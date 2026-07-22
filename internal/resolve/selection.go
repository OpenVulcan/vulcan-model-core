package resolve

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// selectionCandidate contains one catalog profile ranked before mutable credential selection.
// selectionCandidate 包含一个在可变凭据选择前完成排序的目录规格。
type selectionCandidate struct {
	// modelID identifies the provider-scoped logical model.
	// modelID 标识供应商作用域逻辑模型。
	modelID string
	// profileID identifies the exact execution capability shape.
	// profileID 标识精确执行能力形态。
	profileID string
	// preferredModelRank is lower for an explicitly preferred model.
	// preferredModelRank 对显式偏好模型使用更低数值。
	preferredModelRank int
	// preferredCapabilityCount counts satisfied soft requirements.
	// preferredCapabilityCount 统计已满足的软性要求。
	preferredCapabilityCount int
	// defaultProfile reports the provider-authored default shape.
	// defaultProfile 表示供应商编写的默认形态。
	defaultProfile bool
}

// serviceSelectionCandidate contains one special-service profile before mutable credential selection.
// serviceSelectionCandidate 包含一个在可变凭据选择前的特殊服务规格。
type serviceSelectionCandidate struct {
	// serviceID identifies the provider-scoped logical service.
	// serviceID 标识供应商作用域逻辑服务。
	serviceID string
	// offeringID identifies the exact service implementation.
	// offeringID 标识精确服务实现。
	offeringID string
	// profileID identifies the exact executable capability shape.
	// profileID 标识精确可执行能力形态。
	profileID string
	// defaultProfile reports the provider-authored default shape.
	// defaultProfile 表示供应商编写的默认形态。
	defaultProfile bool
}

// Select chooses one currently executable model profile inside the explicitly fixed provider instance.
// Select 在显式固定的供应商实例内选择一个当前可执行模型规格。
func (r *Resolver) Select(ctx context.Context, request vcp.ExecutionSelectionRequest, now time.Time) (vcp.ExecutionSelection, error) {
	if ctx == nil {
		return vcp.ExecutionSelection{}, errors.New("context is required")
	}
	if errContext := ctx.Err(); errContext != nil {
		return vcp.ExecutionSelection{}, errContext
	}
	if errRequest := request.Validate(); errRequest != nil {
		return vcp.ExecutionSelection{}, errRequest
	}
	if now.IsZero() {
		return vcp.ExecutionSelection{}, errors.New("selection evaluation time is required")
	}
	for _, capability := range append(append([]string(nil), request.RequiredCapabilities...), request.PreferredCapabilities...) {
		if !validSelectionCapability(capability) {
			return vcp.ExecutionSelection{}, fmt.Errorf("%w: selection contains unsupported capability %q", vcp.ErrInvalidRequest, capability)
		}
	}
	snapshot, errSnapshot := r.catalogs.Get(ctx, request.ProviderInstanceID)
	if errSnapshot != nil {
		return vcp.ExecutionSelection{}, errSnapshot
	}
	if request.Operation == vcp.OperationSearchWeb {
		return r.selectService(ctx, request, snapshot, now)
	}
	preferredRanks := make(map[string]int, len(request.PreferredModelIDs))
	for index, modelID := range request.PreferredModelIDs {
		preferredRanks[modelID] = index
	}
	candidates := make([]selectionCandidate, 0, len(snapshot.Profiles))
	for _, profile := range snapshot.Profiles {
		if profile.OfferingID == "" || profile.Operation != request.Operation || !capabilitiesSatisfy(profile.Capabilities, request.RequiredCapabilities) || !containsAllStrings(profile.Capabilities.InputModalities, request.RequiredInputModalities) || !containsAllStrings(profile.Capabilities.OutputModalities, request.RequiredOutputModalities) || request.RequiredContextTokens > 0 && (!profile.Capabilities.Tokens.ContextWindow.Known || profile.Capabilities.Tokens.ContextWindow.Value < request.RequiredContextTokens) || request.RequiredMaxOutputTokens > 0 && (!profile.Capabilities.Tokens.MaxOutputTokens.Known || profile.Capabilities.Tokens.MaxOutputTokens.Value < request.RequiredMaxOutputTokens) {
			continue
		}
		offering, exists := findOffering(snapshot.Offerings, profile.OfferingID)
		if !exists {
			continue
		}
		modelRank := len(request.PreferredModelIDs)
		if rank, preferred := preferredRanks[offering.ProviderModelID]; preferred {
			modelRank = rank
		}
		candidates = append(candidates, selectionCandidate{modelID: offering.ProviderModelID, profileID: profile.ID, preferredModelRank: modelRank, preferredCapabilityCount: satisfiedCapabilityCount(profile.Capabilities, request.PreferredCapabilities), defaultProfile: profile.Default})
	}
	sort.Slice(candidates, func(first int, second int) bool {
		left := candidates[first]
		right := candidates[second]
		if left.preferredModelRank != right.preferredModelRank {
			return left.preferredModelRank < right.preferredModelRank
		}
		if left.preferredCapabilityCount != right.preferredCapabilityCount {
			return left.preferredCapabilityCount > right.preferredCapabilityCount
		}
		if left.defaultProfile != right.defaultProfile {
			return left.defaultProfile
		}
		if left.modelID != right.modelID {
			return left.modelID < right.modelID
		}
		return left.profileID < right.profileID
	})
	for _, candidate := range candidates {
		target, _, errResolve := r.Resolve(ctx, Request{ProviderInstanceID: request.ProviderInstanceID, ProviderModelID: candidate.modelID, Operation: request.Operation, ExecutionProfileID: candidate.profileID, RequiredContextTokens: request.RequiredContextTokens, RequiredCapabilities: append([]string(nil), request.RequiredCapabilities...), RequiredRegion: request.RequiredRegion, Now: now})
		if errResolve != nil {
			if isSelectionCandidateRejection(errResolve) {
				continue
			}
			return vcp.ExecutionSelection{}, errResolve
		}
		selection := vcp.ExecutionSelection{RequestID: request.RequestID, Target: vcp.TargetSelection{Model: &vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: target.ProviderInstanceID, ProviderModelID: target.ProviderModelID, ExecutionProfileID: target.ExecutionProfileID, RequiredRegion: request.RequiredRegion}}, Operation: target.Operation, CapabilityRevision: target.CapabilityRevision, CatalogRevision: target.CatalogRevision}
		if target.EffectiveContextWindow.Known {
			value := target.EffectiveContextWindow.Value
			selection.EffectiveContextTokens = &value
		}
		return selection, nil
	}
	return vcp.ExecutionSelection{}, ErrNoEligibleTarget
}

// selectService chooses one currently executable special-service profile inside the fixed provider instance.
// selectService 在固定供应商实例内选择一个当前可执行的特殊服务规格。
func (r *Resolver) selectService(ctx context.Context, request vcp.ExecutionSelectionRequest, snapshot catalog.Snapshot, now time.Time) (vcp.ExecutionSelection, error) {
	candidates := make([]serviceSelectionCandidate, 0, len(snapshot.Profiles))
	for _, service := range snapshot.Services {
		if service.Operation != request.Operation {
			continue
		}
		for _, offering := range snapshot.ServiceOfferings {
			if offering.ProviderServiceID != service.ID {
				continue
			}
			for _, profile := range snapshot.Profiles {
				if profile.ServiceOfferingID == offering.ID && profile.Operation == request.Operation {
					candidates = append(candidates, serviceSelectionCandidate{serviceID: service.ID, offeringID: offering.ID, profileID: profile.ID, defaultProfile: profile.Default})
				}
			}
		}
	}
	sort.Slice(candidates, func(first int, second int) bool {
		left := candidates[first]
		right := candidates[second]
		if left.defaultProfile != right.defaultProfile {
			return left.defaultProfile
		}
		if left.serviceID != right.serviceID {
			return left.serviceID < right.serviceID
		}
		if left.offeringID != right.offeringID {
			return left.offeringID < right.offeringID
		}
		return left.profileID < right.profileID
	})
	for _, candidate := range candidates {
		target, _, errResolve := r.Resolve(ctx, Request{ProviderInstanceID: request.ProviderInstanceID, ProviderServiceID: candidate.serviceID, ServiceOfferingID: candidate.offeringID, Operation: request.Operation, ExecutionProfileID: candidate.profileID, RequiredRegion: request.RequiredRegion, Now: now})
		if errResolve != nil {
			if isSelectionCandidateRejection(errResolve) {
				continue
			}
			return vcp.ExecutionSelection{}, errResolve
		}
		return vcp.ExecutionSelection{RequestID: request.RequestID, Target: vcp.TargetSelection{Service: &vcp.ServiceSelection{ProviderInstanceID: target.ProviderInstanceID, ProviderServiceID: target.ProviderServiceID, ServiceOfferingID: target.ServiceOfferingID, ExecutionProfileID: target.ExecutionProfileID}}, Operation: target.Operation, CapabilityRevision: target.CapabilityRevision, CatalogRevision: target.CatalogRevision}, nil
	}
	return vcp.ExecutionSelection{}, ErrNoEligibleTarget
}

// isSelectionCandidateRejection reports expected candidate ineligibility that permits deterministic evaluation of the next profile.
// isSelectionCandidateRejection 报告允许继续确定性评估下一规格的预期候选不合格错误。
func isSelectionCandidateRejection(errValue error) bool {
	return errors.Is(errValue, ErrInstanceNotExecutable) || errors.Is(errValue, ErrModelDisabled) || errors.Is(errValue, ErrModelNotFound) || errors.Is(errValue, ErrServiceDisabled) || errors.Is(errValue, ErrServiceNotFound) || errors.Is(errValue, ErrProfileNotFound) || errors.Is(errValue, ErrNoEligibleTarget)
}

// containsAllStrings reports whether every required normalized value is present.
// containsAllStrings 报告是否存在全部必需的规范化值。
func containsAllStrings(available []string, required []string) bool {
	for _, requiredValue := range required {
		found := false
		for _, availableValue := range available {
			if availableValue == requiredValue {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// findOffering returns one exact model offering from an already validated snapshot.
// findOffering 从已校验快照返回一个精确模型产品。
func findOffering(offerings []catalog.ModelOffering, offeringID string) (catalog.ModelOffering, bool) {
	for _, offering := range offerings {
		if offering.ID == offeringID {
			return offering, true
		}
	}
	return catalog.ModelOffering{}, false
}

// satisfiedCapabilityCount counts exact callable preferred capabilities.
// satisfiedCapabilityCount 统计精确可调用的偏好能力。
func satisfiedCapabilityCount(capabilities catalog.ModelCapabilities, preferred []string) int {
	count := 0
	for _, capability := range preferred {
		if capabilitiesSatisfy(capabilities, []string{capability}) {
			count++
		}
	}
	return count
}

// validSelectionCapability reports the closed identifiers accepted by execution preselection.
// validSelectionCapability 报告执行前选择接受的封闭能力标识。
func validSelectionCapability(capability string) bool {
	switch capability {
	case "streaming", "tool_calling", "parallel_tool_calls", "streaming_tool_arguments", "strict_json_schema", "reasoning", "image_input", "audio_input", "video_input", "file_input":
		return true
	default:
		return false
	}
}
