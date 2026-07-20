package catalog

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

var (
	// ErrSnapshotNotFound reports a missing provider catalog snapshot.
	// ErrSnapshotNotFound 表示供应商目录快照不存在。
	ErrSnapshotNotFound = errors.New("provider catalog snapshot not found")
)

// Store persists atomic provider-scoped catalog snapshots.
// Store 持久化原子的供应商作用域目录快照。
type Store interface {
	// Save creates or replaces one provider snapshot with a newer revision.
	// Save 使用更高修订号创建或替换一个供应商快照。
	Save(context.Context, Snapshot) error
	// Delete removes one provider snapshot and reports ErrSnapshotNotFound when it does not exist.
	// Delete 删除一个供应商快照，目标不存在时返回 ErrSnapshotNotFound。
	Delete(context.Context, string) error
	// Get returns one mutation-safe provider snapshot.
	// Get 返回一个防止外部修改的供应商快照。
	Get(context.Context, string) (Snapshot, error)
}

// MemoryStore is a thread-safe atomic catalog store for tests and framework bootstrap.
// MemoryStore 是用于测试和框架启动的线程安全原子目录存储。
type MemoryStore struct {
	// mu protects atomic snapshot replacement and reads.
	// mu 保护原子快照替换和读取。
	mu sync.RWMutex
	// snapshots stores one latest catalog per provider instance.
	// snapshots 为每个供应商实例存储一个最新目录。
	snapshots map[string]Snapshot
}

// NewMemoryStore creates an empty atomic provider catalog store.
// NewMemoryStore 创建一个空的原子供应商目录存储。
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{snapshots: make(map[string]Snapshot)}
}

// Save validates and atomically stores a newer provider catalog revision.
// Save 校验并原子存储一个更新的供应商目录修订。
func (s *MemoryStore) Save(ctx context.Context, snapshot Snapshot) error {
	if ctx == nil {
		return errors.New("context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := snapshot.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if current, exists := s.snapshots[snapshot.ProviderInstanceID]; exists && snapshot.Revision <= current.Revision {
		return fmt.Errorf("%w: catalog revision must increase", ErrInvalidCatalog)
	}
	s.snapshots[snapshot.ProviderInstanceID] = cloneSnapshot(snapshot)
	return nil
}

// Delete removes one provider snapshot atomically.
// Delete 原子删除一个供应商快照。
func (s *MemoryStore) Delete(ctx context.Context, providerInstanceID string) error {
	if ctx == nil {
		return errors.New("context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.snapshots[providerInstanceID]; !exists {
		return fmt.Errorf("%w: %s", ErrSnapshotNotFound, providerInstanceID)
	}
	delete(s.snapshots, providerInstanceID)
	return nil
}

// Get returns one mutation-safe atomic provider catalog snapshot.
// Get 返回一个防止外部修改的原子供应商目录快照。
func (s *MemoryStore) Get(ctx context.Context, providerInstanceID string) (Snapshot, error) {
	if ctx == nil {
		return Snapshot{}, errors.New("context is required")
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	snapshot, exists := s.snapshots[providerInstanceID]
	if !exists {
		return Snapshot{}, fmt.Errorf("%w: %s", ErrSnapshotNotFound, providerInstanceID)
	}
	return cloneSnapshot(snapshot), nil
}

// cloneSnapshot returns a deep-enough immutable catalog value for all slice and pointer fields.
// cloneSnapshot 为全部切片和指针字段返回足够深度的不可变目录值。
func cloneSnapshot(snapshot Snapshot) Snapshot {
	snapshot.Models = append([]ProviderModel(nil), snapshot.Models...)
	snapshot.Offerings = append([]ModelOffering(nil), snapshot.Offerings...)
	for index := range snapshot.Offerings {
		snapshot.Offerings[index].Capabilities = cloneCapabilities(snapshot.Offerings[index].Capabilities)
	}
	snapshot.Services = append([]ProviderService(nil), snapshot.Services...)
	snapshot.ServiceOfferings = append([]ServiceOffering(nil), snapshot.ServiceOfferings...)
	for index := range snapshot.ServiceOfferings {
		snapshot.ServiceOfferings[index].Capabilities = cloneServiceCapabilities(snapshot.ServiceOfferings[index].Capabilities)
	}
	snapshot.Profiles = append([]ExecutionProfile(nil), snapshot.Profiles...)
	for index := range snapshot.Profiles {
		snapshot.Profiles[index].Capabilities = cloneCapabilities(snapshot.Profiles[index].Capabilities)
		if snapshot.Profiles[index].ServiceCapabilities != nil {
			capabilities := cloneServiceCapabilities(*snapshot.Profiles[index].ServiceCapabilities)
			snapshot.Profiles[index].ServiceCapabilities = &capabilities
		}
		snapshot.Profiles[index].RequiredEntitlementClasses = append([]string(nil), snapshot.Profiles[index].RequiredEntitlementClasses...)
	}
	snapshot.Entitlements = append([]ModelEntitlement(nil), snapshot.Entitlements...)
	for index := range snapshot.Entitlements {
		snapshot.Entitlements[index].AllowedProfileIDs = append([]string(nil), snapshot.Entitlements[index].AllowedProfileIDs...)
	}
	snapshot.ServiceEntitlements = append([]ServiceEntitlement(nil), snapshot.ServiceEntitlements...)
	for index := range snapshot.ServiceEntitlements {
		snapshot.ServiceEntitlements[index].AllowedProfileIDs = append([]string(nil), snapshot.ServiceEntitlements[index].AllowedProfileIDs...)
	}
	snapshot.Plans = append([]PlanSnapshot(nil), snapshot.Plans...)
	snapshot.Allowances = append([]AllowanceSnapshot(nil), snapshot.Allowances...)
	for index := range snapshot.Allowances {
		snapshot.Allowances[index] = cloneAllowance(snapshot.Allowances[index])
	}
	snapshot.Pools = append([]PoolSummary(nil), snapshot.Pools...)
	for index := range snapshot.Pools {
		snapshot.Pools[index].BlockingAllowanceKinds = append([]AllowanceKind(nil), snapshot.Pools[index].BlockingAllowanceKinds...)
		if snapshot.Pools[index].EarliestResetAt != nil {
			resetAt := *snapshot.Pools[index].EarliestResetAt
			snapshot.Pools[index].EarliestResetAt = &resetAt
		}
	}
	return snapshot
}

// cloneCapabilities returns one mutation-safe model capability value.
// cloneCapabilities 返回一个防止外部修改的模型能力值。
func cloneCapabilities(capabilities ModelCapabilities) ModelCapabilities {
	capabilities.InputModalities = append([]string(nil), capabilities.InputModalities...)
	capabilities.OutputModalities = append([]string(nil), capabilities.OutputModalities...)
	capabilities.MediaInputs = append([]MediaInputCapability(nil), capabilities.MediaInputs...)
	for index := range capabilities.MediaInputs {
		capabilities.MediaInputs[index] = cloneMediaInputCapability(capabilities.MediaInputs[index])
	}
	if capabilities.Embedding != nil {
		embedding := *capabilities.Embedding
		embedding.InputTasks = append([]vcp.EmbeddingInputTask(nil), embedding.InputTasks...)
		embedding.OutputKinds = append([]vcp.EmbeddingVectorKind(nil), embedding.OutputKinds...)
		embedding.Encodings = append([]vcp.EmbeddingEncoding(nil), embedding.Encodings...)
		embedding.Dimensions = append([]int(nil), embedding.Dimensions...)
		embedding.ResourceKinds = append([]vcp.MediaKind(nil), embedding.ResourceKinds...)
		capabilities.Embedding = &embedding
	}
	if capabilities.Rerank != nil {
		rerank := *capabilities.Rerank
		rerank.TruncationPolicies = append([]vcp.RerankTruncation(nil), rerank.TruncationPolicies...)
		rerank.QueryResourceKinds = append([]vcp.MediaKind(nil), rerank.QueryResourceKinds...)
		rerank.CandidateResourceKinds = append([]vcp.MediaKind(nil), rerank.CandidateResourceKinds...)
		capabilities.Rerank = &rerank
	}
	capabilities.MediaOutputs = append([]MediaOutputCapability(nil), capabilities.MediaOutputs...)
	for index := range capabilities.MediaOutputs {
		capabilities.MediaOutputs[index] = cloneMediaOutputCapability(capabilities.MediaOutputs[index])
	}
	capabilities.Parameters = append([]ParameterDescriptor(nil), capabilities.Parameters...)
	for index := range capabilities.Parameters {
		capabilities.Parameters[index] = cloneParameterDescriptor(capabilities.Parameters[index])
	}
	capabilities.ParameterRules = append([]ParameterRule(nil), capabilities.ParameterRules...)
	for index := range capabilities.ParameterRules {
		capabilities.ParameterRules[index].RelatedParameterIDs = append([]string(nil), capabilities.ParameterRules[index].RelatedParameterIDs...)
	}
	capabilities.UsageMetrics = append([]UsageMetricCapability(nil), capabilities.UsageMetrics...)
	return capabilities
}

// CloneModelCapabilities returns one mutation-safe public capability value.
// CloneModelCapabilities 返回一个防止外部修改的公开能力值。
func CloneModelCapabilities(capabilities ModelCapabilities) ModelCapabilities {
	return cloneCapabilities(capabilities)
}

// cloneMediaOutputCapability returns one mutation-safe generated-media capability.
// cloneMediaOutputCapability 返回一个防止外部修改的生成媒体能力。
func cloneMediaOutputCapability(capability MediaOutputCapability) MediaOutputCapability {
	capability.Formats = append([]string(nil), capability.Formats...)
	capability.Common.MIMETypes = append([]string(nil), capability.Common.MIMETypes...)
	if capability.Image != nil {
		image := *capability.Image
		image.AllowedDimensions = append([]ImageDimensions(nil), image.AllowedDimensions...)
		capability.Image = &image
	}
	if capability.Audio != nil {
		audio := *capability.Audio
		audio.Encodings = append([]string(nil), audio.Encodings...)
		capability.Audio = &audio
	}
	if capability.Video != nil {
		video := *capability.Video
		video.Codecs = append([]string(nil), video.Codecs...)
		video.Containers = append([]string(nil), video.Containers...)
		capability.Video = &video
	}
	capability.Evidence = append([]CapabilityEvidence(nil), capability.Evidence...)
	for index := range capability.Evidence {
		if capability.Evidence[index].ExpiresAt != nil {
			expiresAt := *capability.Evidence[index].ExpiresAt
			capability.Evidence[index].ExpiresAt = &expiresAt
		}
	}
	return capability
}

// cloneParameterDescriptor returns one mutation-safe parameter contract.
// cloneParameterDescriptor 返回一个防止外部修改的参数合同。
func cloneParameterDescriptor(parameter ParameterDescriptor) ParameterDescriptor {
	parameter.AllowedValues = append([]string(nil), parameter.AllowedValues...)
	parameter.AllowedResourceRoles = append([]vcp.MediaInputRole(nil), parameter.AllowedResourceRoles...)
	if parameter.IntegerRange != nil {
		value := *parameter.IntegerRange
		value.Minimum = cloneInt64Pointer(value.Minimum)
		value.Maximum = cloneInt64Pointer(value.Maximum)
		parameter.IntegerRange = &value
	}
	if parameter.FloatRange != nil {
		value := *parameter.FloatRange
		if value.Minimum != nil {
			minimum := *value.Minimum
			value.Minimum = &minimum
		}
		if value.Maximum != nil {
			maximum := *value.Maximum
			value.Maximum = &maximum
		}
		parameter.FloatRange = &value
	}
	if parameter.Default != nil {
		value := *parameter.Default
		if value.Boolean != nil {
			boolean := *value.Boolean
			value.Boolean = &boolean
		}
		value.Integer = cloneInt64Pointer(value.Integer)
		if value.Float != nil {
			floatValue := *value.Float
			value.Float = &floatValue
		}
		value.String = cloneStringPointer(value.String)
		if value.ResourceRole != nil {
			role := *value.ResourceRole
			value.ResourceRole = &role
		}
		parameter.Default = &value
	}
	return parameter
}

// cloneInt64Pointer returns one independent integer pointer.
// cloneInt64Pointer 返回一个独立整数指针。
func cloneInt64Pointer(value *int64) *int64 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

// cloneMediaInputCapability returns one mutation-safe media capability value.
// cloneMediaInputCapability 返回一个防止外部修改的媒体能力值。
func cloneMediaInputCapability(capability MediaInputCapability) MediaInputCapability {
	capability.Roles = append([]vcp.MediaInputRole(nil), capability.Roles...)
	capability.InteractionModes = append([]MediaInteractionMode(nil), capability.InteractionModes...)
	capability.AllowedAuthorities = append([]vcp.Authority(nil), capability.AllowedAuthorities...)
	capability.AllowedPlacements = append([]vcp.Placement(nil), capability.AllowedPlacements...)
	capability.ClientWorkflows = append([]ClientResourceWorkflow(nil), capability.ClientWorkflows...)
	capability.MaterializationModes = append([]UpstreamMaterializationMode(nil), capability.MaterializationModes...)
	capability.Common.MIMETypes = append([]string(nil), capability.Common.MIMETypes...)
	if capability.Image != nil {
		image := *capability.Image
		image.AllowedDimensions = append([]ImageDimensions(nil), image.AllowedDimensions...)
		capability.Image = &image
	}
	if capability.Audio != nil {
		audio := *capability.Audio
		audio.Encodings = append([]string(nil), audio.Encodings...)
		capability.Audio = &audio
	}
	if capability.Video != nil {
		video := *capability.Video
		video.Codecs = append([]string(nil), video.Codecs...)
		video.Containers = append([]string(nil), video.Containers...)
		capability.Video = &video
	}
	capability.Evidence = append([]CapabilityEvidence(nil), capability.Evidence...)
	for index := range capability.Evidence {
		if capability.Evidence[index].ExpiresAt != nil {
			expiresAt := *capability.Evidence[index].ExpiresAt
			capability.Evidence[index].ExpiresAt = &expiresAt
		}
	}
	return capability
}

// cloneServiceCapabilities returns one mutation-safe special-service capability value.
// cloneServiceCapabilities 返回一个防止外部修改的特殊服务能力值。
func cloneServiceCapabilities(capabilities ServiceCapabilities) ServiceCapabilities {
	if capabilities.WebSearch == nil {
		return capabilities
	}
	webSearch := *capabilities.WebSearch
	webSearch.OutputModes = append([]vcp.WebSearchOutputMode(nil), webSearch.OutputModes...)
	webSearch.EvidenceKinds = append([]vcp.SearchEvidenceKind(nil), webSearch.EvidenceKinds...)
	webSearch.EvidenceRequirements = append([]vcp.SearchEvidenceRequirement(nil), webSearch.EvidenceRequirements...)
	capabilities.WebSearch = &webSearch
	return capabilities
}

// cloneAllowance returns one mutation-safe allowance value.
// cloneAllowance 返回一个防止外部修改的资源值。
func cloneAllowance(allowance AllowanceSnapshot) AllowanceSnapshot {
	allowance.Limit = cloneStringPointer(allowance.Limit)
	allowance.Used = cloneStringPointer(allowance.Used)
	allowance.Remaining = cloneStringPointer(allowance.Remaining)
	if allowance.RemainingRatio != nil {
		remainingRatio := *allowance.RemainingRatio
		allowance.RemainingRatio = &remainingRatio
	}
	if allowance.Window != nil {
		window := *allowance.Window
		if window.ResetAt != nil {
			resetAt := *window.ResetAt
			window.ResetAt = &resetAt
		}
		allowance.Window = &window
	}
	return allowance
}

// cloneStringPointer copies one optional immutable decimal string.
// cloneStringPointer 复制一个可选的不可变十进制字符串。
func cloneStringPointer(value *string) *string {
	if value == nil {
		return nil
	}
	clonedValue := *value
	return &clonedValue
}
