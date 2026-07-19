package resolve

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/dependency"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
)

// Resolver combines persisted configuration with one atomic provider catalog snapshot.
// Resolver 将持久化配置与一个原子供应商目录快照组合起来。
type Resolver struct {
	// configurations resolves provider instances, credentials, endpoints, and bindings.
	// configurations 解析供应商实例、凭据、端点和访问绑定。
	configurations providerconfig.Store
	// catalogs resolves atomic provider model and allowance snapshots.
	// catalogs 解析原子供应商模型和资源快照。
	catalogs catalog.Store
}

// New creates a provider-scoped target resolver without any protocol implementation.
// New 创建一个不包含任何协议实现的供应商作用域目标解析器。
func New(configurations providerconfig.Store, catalogs catalog.Store) (*Resolver, error) {
	if dependency.IsNil(configurations) || dependency.IsNil(catalogs) {
		return nil, errors.New("provider configuration and catalog stores are required")
	}
	return &Resolver{configurations: configurations, catalogs: catalogs}, nil
}

// SummarizeSnapshot derives client-safe credential pool state for every execution profile.
// SummarizeSnapshot 为每个执行规格派生客户端安全的凭据池状态。
func (r *Resolver) SummarizeSnapshot(ctx context.Context, snapshot catalog.Snapshot, now time.Time, revision uint64) ([]catalog.PoolSummary, error) {
	if ctx == nil {
		return nil, errors.New("context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if now.IsZero() || revision == 0 {
		return nil, errors.New("pool evaluation time and revision are required")
	}
	if err := snapshot.Validate(); err != nil {
		return nil, err
	}
	endpoints, errEndpoints := r.configurations.ListEndpoints(ctx, snapshot.ProviderInstanceID)
	if errEndpoints != nil {
		return nil, errEndpoints
	}
	credentials, errCredentials := r.configurations.ListCredentials(ctx, snapshot.ProviderInstanceID)
	if errCredentials != nil {
		return nil, errCredentials
	}
	bindings, errBindings := r.configurations.ListBindings(ctx, snapshot.ProviderInstanceID)
	if errBindings != nil {
		return nil, errBindings
	}
	endpointByID := make(map[string]providerconfig.Endpoint, len(endpoints))
	for _, endpoint := range endpoints {
		endpointByID[endpoint.ID] = endpoint
	}
	modelsByID := make(map[string]catalog.ProviderModel, len(snapshot.Models))
	for _, model := range snapshot.Models {
		modelsByID[model.ID] = model
	}
	offeringsByID := make(map[string]catalog.ModelOffering, len(snapshot.Offerings))
	for _, offering := range snapshot.Offerings {
		offeringsByID[offering.ID] = offering
	}
	pools := make([]catalog.PoolSummary, 0, len(snapshot.Profiles))
	for _, profile := range snapshot.Profiles {
		offering := offeringsByID[profile.OfferingID]
		model := modelsByID[offering.ProviderModelID]
		entitlements := entitlementsByCredential(snapshot.Entitlements, model.ID)
		blockingKinds := make(map[catalog.AllowanceKind]struct{})
		pool := catalog.PoolSummary{
			ProviderInstanceID:    snapshot.ProviderInstanceID,
			ExecutionProfileID:    profile.ID,
			ConfiguredCredentials: len(credentials),
			Revision:              revision,
			ObservedAt:            now,
		}
		for _, credential := range credentials {
			if !credentialBoundToReadyEndpoint(credential.ID, offering, model.ID, bindings, endpointByID) {
				continue
			}
			entitlement, entitled := entitlementForProfile(model, profile, entitlements[credential.ID], now)
			if !entitled {
				continue
			}
			pool.EntitledCredentials++
			if credential.Status == providerconfig.CredentialCooling && credential.CoolingUntil != nil && credential.CoolingUntil.After(now) {
				pool.CoolingCredentials++
				continue
			}
			if !credential.RuntimeEligibleAt(now) {
				pool.InvalidCredentials++
				continue
			}
			effectiveContext := effectiveContextWindow(profile.Capabilities.Tokens.ContextWindow, entitlement.LimitOverrides.ContextWindow)
			if profile.Capabilities.Tokens.ContextWindow.Known && (!effectiveContext.Known || effectiveContext.Value < profile.Capabilities.Tokens.ContextWindow.Value) {
				continue
			}
			blocked, earliestResetAt := blockedByAllowance(snapshot.Allowances, credential, model.ID, profile.ID, nil)
			if len(blocked) > 0 {
				pool.ExhaustedCredentials++
				for _, allowanceKind := range blocked {
					blockingKinds[allowanceKind] = struct{}{}
				}
				pool.EarliestResetAt = earlierTime(pool.EarliestResetAt, earliestResetAt)
				continue
			}
			pool.ReadyCredentials++
		}
		pool.BlockingAllowanceKinds = sortedAllowanceKinds(blockingKinds)
		pools = append(pools, pool)
	}
	sort.Slice(pools, func(left int, right int) bool {
		return pools[left].ExecutionProfileID < pools[right].ExecutionProfileID
	})
	return pools, nil
}

// credentialBoundToReadyEndpoint reports whether one credential has a usable channel binding.
// credentialBoundToReadyEndpoint 返回一个凭据是否具有可用通道绑定。
func credentialBoundToReadyEndpoint(credentialID string, offering catalog.ModelOffering, modelID string, bindings []providerconfig.AccessBinding, endpoints map[string]providerconfig.Endpoint) bool {
	for _, binding := range bindings {
		if !binding.Enabled || binding.CredentialID != credentialID || binding.ChannelID != offering.ChannelID || !allowsModel(binding.AllowedModelIDs, modelID) {
			continue
		}
		endpoint, exists := endpoints[binding.EndpointID]
		if exists && endpoint.Status == providerconfig.EndpointReady && endpoint.ChannelID == offering.ChannelID {
			return true
		}
	}
	return false
}

// Resolve selects one exact target inside the requested provider instance only.
// Resolve 仅在请求指定的供应商实例内部选择一个精确目标。
func (r *Resolver) Resolve(ctx context.Context, request Request) (Target, Diagnostics, error) {
	if ctx == nil {
		return Target{}, Diagnostics{}, errors.New("context is required")
	}
	if err := ctx.Err(); err != nil {
		return Target{}, Diagnostics{}, err
	}
	if request.ProviderInstanceID == "" || request.ProviderModelID == "" || request.RequiredContextTokens < 0 || request.Now.IsZero() {
		return Target{}, Diagnostics{}, errors.New("provider instance, model, non-negative context requirement, and evaluation time are required")
	}
	instance, errInstance := r.configurations.GetInstance(ctx, request.ProviderInstanceID)
	if errInstance != nil {
		return Target{}, Diagnostics{}, errInstance
	}
	if instance.Status != providerconfig.LifecycleReady && instance.Status != providerconfig.LifecycleDegraded {
		return Target{}, Diagnostics{}, fmt.Errorf("%w: %s", ErrInstanceNotExecutable, instance.Status)
	}
	if modelDisabled(instance.DisabledModelIDs, request.ProviderModelID) {
		return Target{}, Diagnostics{}, fmt.Errorf("%w: %s", ErrModelDisabled, request.ProviderModelID)
	}
	snapshot, errCatalog := r.catalogs.Get(ctx, request.ProviderInstanceID)
	if errCatalog != nil {
		return Target{}, Diagnostics{}, errCatalog
	}
	model, exists := findModel(snapshot.Models, request.ProviderModelID)
	if !exists {
		return Target{}, Diagnostics{}, fmt.Errorf("%w: %s", ErrModelNotFound, request.ProviderModelID)
	}
	profile, offering, errProfile := selectProfile(snapshot, model.ID, request.ExecutionProfileID)
	if errProfile != nil {
		return Target{}, Diagnostics{}, errProfile
	}
	if !capabilitiesSatisfy(profile.Capabilities, request.RequiredCapabilities) {
		return Target{}, Diagnostics{}, fmt.Errorf("%w: execution profile lacks required capabilities", ErrNoEligibleTarget)
	}
	endpoints, errEndpoints := r.configurations.ListEndpoints(ctx, instance.ID)
	if errEndpoints != nil {
		return Target{}, Diagnostics{}, errEndpoints
	}
	credentials, errCredentials := r.configurations.ListCredentials(ctx, instance.ID)
	if errCredentials != nil {
		return Target{}, Diagnostics{}, errCredentials
	}
	bindings, errBindings := r.configurations.ListBindings(ctx, instance.ID)
	if errBindings != nil {
		return Target{}, Diagnostics{}, errBindings
	}
	diagnostics := Diagnostics{ConfiguredCredentials: len(credentials)}
	endpointByID := make(map[string]providerconfig.Endpoint, len(endpoints))
	for _, endpoint := range endpoints {
		endpointByID[endpoint.ID] = endpoint
	}
	credentialByID := make(map[string]providerconfig.Credential, len(credentials))
	for _, credential := range credentials {
		credentialByID[credential.ID] = credential
	}
	entitlements := entitlementsByCredential(snapshot.Entitlements, model.ID)
	blockingKinds := make(map[catalog.AllowanceKind]struct{})
	candidates := make([]candidate, 0, len(bindings))
	for _, binding := range bindings {
		if !binding.Enabled || binding.ChannelID != offering.ChannelID || !allowsModel(binding.AllowedModelIDs, model.ID) {
			continue
		}
		endpoint, endpointExists := endpointByID[binding.EndpointID]
		credential, credentialExists := credentialByID[binding.CredentialID]
		if !endpointExists || !credentialExists || endpoint.ChannelID != offering.ChannelID {
			continue
		}
		diagnostics.BoundCandidates++
		entitlement, entitled := entitlementForProfile(model, profile, entitlements[credential.ID], request.Now)
		if !entitled {
			continue
		}
		diagnostics.EntitledCandidates++
		effectiveContext := effectiveContextWindow(profile.Capabilities.Tokens.ContextWindow, entitlement.LimitOverrides.ContextWindow)
		if request.RequiredContextTokens > 0 && (!effectiveContext.Known || effectiveContext.Value < request.RequiredContextTokens) {
			continue
		}
		diagnostics.CapabilityCandidates++
		blocked, earliestResetAt := blockedByAllowance(snapshot.Allowances, credential, model.ID, profile.ID, request.RequiredCapabilities)
		if len(blocked) > 0 {
			for _, allowanceKind := range blocked {
				blockingKinds[allowanceKind] = struct{}{}
			}
			diagnostics.EarliestResetAt = earlierTime(diagnostics.EarliestResetAt, earliestResetAt)
			continue
		}
		diagnostics.AllowanceCandidates++
		if endpoint.Status != providerconfig.EndpointReady || !credential.RuntimeEligibleAt(request.Now) {
			continue
		}
		diagnostics.ReadyCandidates++
		candidates = append(candidates, candidate{
			binding:           binding,
			endpoint:          endpoint,
			credential:        credential,
			effectiveContext:  effectiveContext,
			selectionCapacity: selectionContextWindow(profile.Capabilities.Tokens.ContextWindow, entitlement.LimitOverrides.ContextWindow),
		})
	}
	diagnostics.BlockingAllowanceKinds = sortedAllowanceKinds(blockingKinds)
	if len(candidates) == 0 {
		return Target{}, diagnostics, ErrNoEligibleTarget
	}
	sortCandidates(candidates, profile.PoolPolicy)
	selected := candidates[0]
	return Target{
		ProviderDefinitionID:   instance.DefinitionID,
		ProviderInstanceID:     instance.ID,
		ChannelID:              offering.ChannelID,
		EndpointID:             selected.endpoint.ID,
		CredentialID:           selected.credential.ID,
		ProviderModelID:        model.ID,
		OfferingID:             offering.ID,
		ExecutionProfileID:     profile.ID,
		UpstreamModelID:        offering.UpstreamModelID,
		EffectiveContextWindow: selected.effectiveContext,
		TokenLimits:            profile.Capabilities.Tokens,
		TokenRecommendations:   profile.Capabilities.Recommendations,
		CapabilityRevision:     profile.CapabilityRevision,
		ProviderConfigRevision: instance.Revision,
		CatalogRevision:        snapshot.Revision,
	}, diagnostics, nil
}

// candidate is one fully eligible same-provider access target before deterministic ordering.
// candidate 是确定性排序前的一个完全合格同供应商访问目标。
type candidate struct {
	// binding is the validated credential-to-endpoint relationship.
	// binding 是经过校验的凭据到端点关系。
	binding providerconfig.AccessBinding
	// endpoint is the concrete upstream destination.
	// endpoint 是具体上游目标。
	endpoint providerconfig.Endpoint
	// credential is the non-secret upstream identity metadata.
	// credential 是非秘密上游身份元数据。
	credential providerconfig.Credential
	// effectiveContext is the smallest authoritative profile and entitlement ceiling.
	// effectiveContext 是规格和授权权威上限中的最小值。
	effectiveContext catalog.OptionalTokenLimit
	// selectionCapacity preserves the account ceiling used to protect scarce high-tier credentials.
	// selectionCapacity 保留用于保护稀缺高等级凭据的账号上限。
	selectionCapacity catalog.OptionalTokenLimit
}

// findModel returns one exact provider model from an atomic snapshot.
// findModel 从原子快照返回一个精确供应商模型。
func findModel(models []catalog.ProviderModel, modelID string) (catalog.ProviderModel, bool) {
	for _, model := range models {
		if model.ID == modelID {
			return model, true
		}
	}
	return catalog.ProviderModel{}, false
}

// selectProfile resolves an explicit profile or one unambiguous default profile for a model.
// selectProfile 为模型解析显式规格或一个无歧义默认规格。
func selectProfile(snapshot catalog.Snapshot, modelID string, profileID string) (catalog.ExecutionProfile, catalog.ModelOffering, error) {
	offerings := make(map[string]catalog.ModelOffering)
	for _, offering := range snapshot.Offerings {
		if offering.ProviderModelID == modelID {
			offerings[offering.ID] = offering
		}
	}
	matches := make([]catalog.ExecutionProfile, 0)
	for _, profile := range snapshot.Profiles {
		if _, exists := offerings[profile.OfferingID]; !exists {
			continue
		}
		if profileID != "" {
			if profile.ID == profileID {
				matches = append(matches, profile)
			}
			continue
		}
		if profile.Default {
			matches = append(matches, profile)
		}
	}
	if len(matches) != 1 {
		return catalog.ExecutionProfile{}, catalog.ModelOffering{}, fmt.Errorf("%w: expected one profile, found %d", ErrProfileNotFound, len(matches))
	}
	return matches[0], offerings[matches[0].OfferingID], nil
}

// entitlementsByCredential indexes model-specific entitlements by credential identifier.
// entitlementsByCredential 按凭据标识索引模型特定授权。
func entitlementsByCredential(entitlements []catalog.ModelEntitlement, modelID string) map[string]catalog.ModelEntitlement {
	indexed := make(map[string]catalog.ModelEntitlement)
	for _, entitlement := range entitlements {
		if entitlement.ProviderModelID == modelID {
			indexed[entitlement.CredentialID] = entitlement
		}
	}
	return indexed
}

// entitlementForProfile resolves whether one credential may use one model profile at a fixed time.
// entitlementForProfile 解析一个凭据在固定时间是否可以使用一个模型规格。
func entitlementForProfile(model catalog.ProviderModel, profile catalog.ExecutionProfile, entitlement catalog.ModelEntitlement, now time.Time) (catalog.ModelEntitlement, bool) {
	if entitlement.ID == "" {
		if model.EntitlementMode == catalog.EntitlementExplicit || len(profile.RequiredEntitlementClasses) > 0 {
			return catalog.ModelEntitlement{}, false
		}
		return catalog.ModelEntitlement{}, true
	}
	if entitlement.Availability != catalog.AvailabilityAllowed || !entitlement.ExpiresAt.After(now) {
		return catalog.ModelEntitlement{}, false
	}
	if len(entitlement.AllowedProfileIDs) > 0 && !contains(entitlement.AllowedProfileIDs, profile.ID) {
		return catalog.ModelEntitlement{}, false
	}
	if len(profile.RequiredEntitlementClasses) > 0 && !contains(profile.RequiredEntitlementClasses, entitlement.EntitlementClass) {
		return catalog.ModelEntitlement{}, false
	}
	return entitlement, true
}

// effectiveContextWindow returns the smallest known profile and account context ceiling.
// effectiveContextWindow 返回规格和账号上下文上限中的最小已知值。
func effectiveContextWindow(profileLimit catalog.OptionalTokenLimit, accountLimit catalog.OptionalTokenLimit) catalog.OptionalTokenLimit {
	if !profileLimit.Known {
		return accountLimit
	}
	if !accountLimit.Known || profileLimit.Value <= accountLimit.Value {
		return profileLimit
	}
	return accountLimit
}

// selectionContextWindow returns the most specific account ceiling for pool ordering.
// selectionContextWindow 返回用于账号池排序的最具体账号上限。
func selectionContextWindow(profileLimit catalog.OptionalTokenLimit, accountLimit catalog.OptionalTokenLimit) catalog.OptionalTokenLimit {
	if accountLimit.Known {
		return accountLimit
	}
	return profileLimit
}

// capabilitiesSatisfy verifies normalized request capability requirements.
// capabilitiesSatisfy 校验规范化的请求能力要求。
func capabilitiesSatisfy(capabilities catalog.ModelCapabilities, required []string) bool {
	for _, capability := range required {
		var level catalog.CapabilityLevel
		switch capability {
		case "tool_calling":
			level = capabilities.ToolCalling
		case "parallel_tool_calls":
			level = capabilities.ParallelToolCalls
		case "streaming_tool_arguments":
			level = capabilities.StreamingToolArguments
		case "strict_json_schema":
			level = capabilities.StrictJSONSchema
		case "reasoning":
			level = capabilities.Reasoning
		default:
			return false
		}
		if level != catalog.CapabilityNative && level != catalog.CapabilityEmulated {
			return false
		}
	}
	return true
}

// blockedByAllowance returns mandatory exhausted resource shapes applicable to one candidate.
// blockedByAllowance 返回适用于一个候选的强制耗尽资源形态。
func blockedByAllowance(allowances []catalog.AllowanceSnapshot, credential providerconfig.Credential, modelID string, profileID string, requiredCapabilities []string) ([]catalog.AllowanceKind, *time.Time) {
	blockedKinds := make(map[catalog.AllowanceKind]struct{})
	var earliestResetAt *time.Time
	for _, allowance := range allowances {
		if !allowance.Mandatory || allowance.Status != catalog.AllowanceExhausted {
			continue
		}
		if !allowanceApplies(allowance, credential, modelID, profileID, requiredCapabilities) {
			continue
		}
		blockedKinds[allowance.Kind] = struct{}{}
		if allowance.Window != nil {
			earliestResetAt = earlierTime(earliestResetAt, allowance.Window.ResetAt)
		}
	}
	return sortedAllowanceKinds(blockedKinds), earliestResetAt
}

// allowanceApplies reports whether one resource scope constrains a candidate.
// allowanceApplies 返回一个资源作用域是否约束候选。
func allowanceApplies(allowance catalog.AllowanceSnapshot, credential providerconfig.Credential, modelID string, profileID string, requiredCapabilities []string) bool {
	switch allowance.Scope {
	case catalog.ScopeCredential:
		return allowance.ScopeID == credential.ID
	case catalog.ScopeProviderModel:
		return allowance.ScopeID == modelID
	case catalog.ScopeExecutionProfile:
		return allowance.ScopeID == profileID
	case catalog.ScopeCapability:
		return contains(requiredCapabilities, allowance.ScopeID)
	case catalog.ScopeSubscription, catalog.ScopeOrganization, catalog.ScopeProject, catalog.ScopeBillingAccount:
		for _, scopeRef := range credential.ScopeRefs {
			if scopeRef.Kind == string(allowance.Scope) && scopeRef.ID == allowance.ScopeID {
				return true
			}
		}
	}
	return false
}

// allowsModel reports whether an access binding permits one provider model.
// allowsModel 返回访问绑定是否允许一个供应商模型。
func allowsModel(allowedModelIDs []string, modelID string) bool {
	return len(allowedModelIDs) == 0 || contains(allowedModelIDs, modelID)
}

// modelDisabled reports whether local management policy explicitly disables one provider model.
// modelDisabled 返回本地管理策略是否显式禁用一个供应商模型。
func modelDisabled(disabledModelIDs []string, modelID string) bool {
	return contains(disabledModelIDs, modelID)
}

// contains reports whether a string slice contains one exact value.
// contains 返回字符串切片是否包含一个精确值。
func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

// earlierTime returns the earliest non-nil time pointer as a copied value.
// earlierTime 将最早的非空时间指针作为复制值返回。
func earlierTime(current *time.Time, candidate *time.Time) *time.Time {
	if candidate == nil {
		return current
	}
	if current == nil || candidate.Before(*current) {
		copiedCandidate := *candidate
		return &copiedCandidate
	}
	return current
}

// sortedAllowanceKinds returns stable unique allowance kinds.
// sortedAllowanceKinds 返回稳定且唯一的资源形态。
func sortedAllowanceKinds(kinds map[catalog.AllowanceKind]struct{}) []catalog.AllowanceKind {
	values := make([]catalog.AllowanceKind, 0, len(kinds))
	for kind := range kinds {
		values = append(values, kind)
	}
	sort.Slice(values, func(left int, right int) bool {
		return values[left] < values[right]
	})
	return values
}

// sortCandidates applies deterministic same-provider pool ordering.
// sortCandidates 应用确定性的同供应商账号池排序。
func sortCandidates(candidates []candidate, policy catalog.PoolPolicy) {
	sort.Slice(candidates, func(left int, right int) bool {
		if policy == catalog.PoolPreferSmallestSufficient {
			leftLimit := candidates[left].selectionCapacity
			rightLimit := candidates[right].selectionCapacity
			if leftLimit.Known != rightLimit.Known {
				return leftLimit.Known
			}
			if leftLimit.Known && leftLimit.Value != rightLimit.Value {
				return leftLimit.Value < rightLimit.Value
			}
		}
		if candidates[left].binding.Priority != candidates[right].binding.Priority {
			return candidates[left].binding.Priority < candidates[right].binding.Priority
		}
		if candidates[left].credential.ID != candidates[right].credential.ID {
			return candidates[left].credential.ID < candidates[right].credential.ID
		}
		return candidates[left].endpoint.ID < candidates[right].endpoint.ID
	})
}
