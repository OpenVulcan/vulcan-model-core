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
	"github.com/OpenVulcan/vulcan-model-core/internal/routing"
	"github.com/OpenVulcan/vulcan-model-core/internal/routingstate"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
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
	// selector applies CLIProxyAPI-derived balanced or first-account scheduling after eligibility filtering.
	// selector 在资格过滤后应用源自 CLIProxyAPI 的均衡或首账号调度。
	selector *routing.Selector
	// runtimeState supplies persistent global policy and credential-model cooldown state when configured.
	// runtimeState 在配置后提供持久化全局策略与凭据模型冷却状态。
	runtimeState routingstate.Store
}

// runtimeScopeIdentity identifies one exact provider-owned runtime availability boundary.
// runtimeScopeIdentity 标识一个精确的供应商所属运行时可用性边界。
type runtimeScopeIdentity struct {
	// scope is the classified runtime resource boundary.
	// scope 是分类后的运行时资源边界。
	scope routingstate.RuntimeScope
	// scopeID is the immutable identifier inside that boundary.
	// scopeID 是该边界内的不可变标识。
	scopeID string
}

// New creates a provider-scoped target resolver without any protocol implementation.
// New 创建一个不包含任何协议实现的供应商作用域目标解析器。
func New(configurations providerconfig.Store, catalogs catalog.Store) (*Resolver, error) {
	return NewWithRuntimeState(configurations, catalogs, nil)
}

// NewWithRuntimeState creates a resolver that applies persistent global routing and model cooldown state.
// NewWithRuntimeState 创建一个应用持久化全局路由与模型冷却状态的解析器。
func NewWithRuntimeState(configurations providerconfig.Store, catalogs catalog.Store, runtimeState routingstate.Store) (*Resolver, error) {
	if dependency.IsNil(configurations) || dependency.IsNil(catalogs) {
		return nil, errors.New("provider configuration and catalog stores are required")
	}
	return &Resolver{configurations: configurations, catalogs: catalogs, selector: routing.NewSelector(), runtimeState: runtimeState}, nil
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
	servicesByID := make(map[string]catalog.ProviderService, len(snapshot.Services))
	for _, service := range snapshot.Services {
		servicesByID[service.ID] = service
	}
	serviceOfferingsByID := make(map[string]catalog.ServiceOffering, len(snapshot.ServiceOfferings))
	for _, offering := range snapshot.ServiceOfferings {
		serviceOfferingsByID[offering.ID] = offering
	}
	pools := make([]catalog.PoolSummary, 0, len(snapshot.Profiles))
	for _, profile := range snapshot.Profiles {
		blockingKinds := make(map[catalog.AllowanceKind]struct{})
		pool := catalog.PoolSummary{
			ProviderInstanceID:    snapshot.ProviderInstanceID,
			ExecutionProfileID:    profile.ID,
			ConfiguredCredentials: len(credentials),
			Revision:              revision,
			ObservedAt:            now,
		}
		if profile.OfferingID != "" {
			offering := offeringsByID[profile.OfferingID]
			model := modelsByID[offering.ProviderModelID]
			entitlements := entitlementsByCredential(snapshot.Entitlements, model.ID)
			for _, credential := range credentials {
				if !credentialBoundToReadyModelEndpoint(credential.ID, offering, model.ID, bindings, endpointByID) {
					continue
				}
				entitlement, entitled := entitlementForProfile(model, profile, entitlements[credential.ID], now)
				if !entitled {
					continue
				}
				pool.EntitledCredentials++
				if !credentialPoolEligible(credential, now, &pool) {
					continue
				}
				effectiveContext := effectiveContextWindow(profile.Capabilities.Tokens.ContextWindow, entitlement.LimitOverrides.ContextWindow)
				if profile.Capabilities.Tokens.ContextWindow.Known && (!effectiveContext.Known || effectiveContext.Value < profile.Capabilities.Tokens.ContextWindow.Value) {
					continue
				}
				if allowanceBlocksPool(snapshot.Allowances, credential, model.ID, profile.ID, blockingKinds, &pool) {
					continue
				}
				pathEligible, errPath := r.modelPoolPathEligible(ctx, snapshot.ProviderInstanceID, credential, offering, model.ID, bindings, endpointByID, now)
				if errPath != nil {
					return nil, errPath
				}
				modelEligible, errModel := r.modelRuntimeEligible(ctx, snapshot.ProviderInstanceID, credential.ID, model.ID, now)
				if errModel != nil {
					return nil, errModel
				}
				if !pathEligible || !modelEligible {
					pool.CoolingCredentials++
					continue
				}
				pool.ReadyCredentials++
			}
		} else {
			offering := serviceOfferingsByID[profile.ServiceOfferingID]
			service := servicesByID[offering.ProviderServiceID]
			entitlements := serviceEntitlementsByCredential(snapshot.ServiceEntitlements, service.ID)
			for _, credential := range credentials {
				if !credentialBoundToReadyServiceEndpoint(credential.ID, offering, service.ID, bindings, endpointByID) || !serviceEntitled(service, profile, entitlements[credential.ID], now) {
					continue
				}
				pool.EntitledCredentials++
				if !credentialPoolEligible(credential, now, &pool) {
					continue
				}
				if allowanceBlocksPool(snapshot.Allowances, credential, service.ID, profile.ID, blockingKinds, &pool) {
					continue
				}
				pathEligible, errPath := r.servicePoolPathEligible(ctx, snapshot.ProviderInstanceID, credential, offering, service.ID, bindings, endpointByID, now)
				if errPath != nil {
					return nil, errPath
				}
				if !pathEligible {
					pool.CoolingCredentials++
					continue
				}
				pool.ReadyCredentials++
			}
		}
		pool.BlockingAllowanceKinds = sortedAllowanceKinds(blockingKinds)
		pools = append(pools, pool)
	}
	sort.Slice(pools, func(left int, right int) bool {
		return pools[left].ExecutionProfileID < pools[right].ExecutionProfileID
	})
	return pools, nil
}

// InspectModelContexts returns every model profile and its exact authorized configured accounts without selecting one target.
// InspectModelContexts 返回每个模型规格及其精确已授权配置账号，且不选择单一目标。
func (r *Resolver) InspectModelContexts(ctx context.Context, instanceID string, modelID string, now time.Time) ([]ModelContextState, error) {
	if ctx == nil {
		return nil, errors.New("context is required")
	}
	if errContext := ctx.Err(); errContext != nil {
		return nil, errContext
	}
	if instanceID == "" || modelID == "" || now.IsZero() {
		return nil, errors.New("provider instance, model, and evaluation time are required")
	}
	instance, errInstance := r.configurations.GetInstance(ctx, instanceID)
	if errInstance != nil {
		return nil, errInstance
	}
	if instance.Status != providerconfig.LifecycleReady && instance.Status != providerconfig.LifecycleDegraded {
		return nil, ErrInstanceNotExecutable
	}
	if modelDisabled(instance.DisabledModelIDs, modelID) {
		return nil, ErrModelDisabled
	}
	snapshot, errSnapshot := r.catalogs.Get(ctx, instanceID)
	if errSnapshot != nil {
		return nil, errSnapshot
	}
	model, modelExists := providerModelByID(snapshot.Models, modelID)
	if !modelExists {
		return nil, ErrModelNotFound
	}
	credentials, errCredentials := r.configurations.ListCredentials(ctx, instanceID)
	if errCredentials != nil {
		return nil, errCredentials
	}
	bindings, errBindings := r.configurations.ListBindings(ctx, instanceID)
	if errBindings != nil {
		return nil, errBindings
	}
	endpoints, errEndpoints := r.configurations.ListEndpoints(ctx, instanceID)
	if errEndpoints != nil {
		return nil, errEndpoints
	}
	endpointByID := make(map[string]providerconfig.Endpoint, len(endpoints))
	for _, endpoint := range endpoints {
		endpointByID[endpoint.ID] = endpoint
	}
	offeringByID := make(map[string]catalog.ModelOffering)
	for _, offering := range snapshot.Offerings {
		if offering.ProviderModelID == model.ID {
			offeringByID[offering.ID] = offering
		}
	}
	entitlements := entitlementsByCredential(snapshot.Entitlements, model.ID)
	contexts := make([]ModelContextState, 0)
	for _, profile := range snapshot.Profiles {
		offering, belongsToModel := offeringByID[profile.OfferingID]
		if !belongsToModel {
			continue
		}
		contextState := ModelContextState{ProfileID: profile.ID, Accounts: make([]ModelContextAccountState, 0)}
		for _, credential := range credentials {
			entitlement, entitled := entitlementForProfile(model, profile, entitlements[credential.ID], now)
			if !entitled {
				continue
			}
			// Explicit provider entitlement proves context ownership even when a local endpoint is currently unavailable; all-bound models still require a configured association.
			// 显式供应商授权即使本地入口当前不可用也能证明上下文归属；全部绑定模型仍要求存在配置关联。
			if entitlement.ID == "" && !credentialBoundToModelEndpoint(credential.ID, offering, model.ID, bindings, endpointByID) {
				continue
			}
			effectiveContext := effectiveContextWindow(profile.Capabilities.Tokens.ContextWindow, entitlement.LimitOverrides.ContextWindow)
			if profile.Capabilities.Tokens.ContextWindow.Known && (!effectiveContext.Known || effectiveContext.Value < profile.Capabilities.Tokens.ContextWindow.Value) {
				continue
			}
			accountState, errState := r.inspectModelContextAccount(ctx, snapshot, credential, offering, model.ID, profile.ID, entitlement.EntitlementClass, effectiveContext, bindings, endpointByID, now)
			if errState != nil {
				return nil, errState
			}
			contextState.Accounts = append(contextState.Accounts, accountState)
		}
		sort.Slice(contextState.Accounts, func(left int, right int) bool {
			if contextState.Accounts[left].Priority != contextState.Accounts[right].Priority {
				return contextState.Accounts[left].Priority < contextState.Accounts[right].Priority
			}
			return contextState.Accounts[left].CredentialID < contextState.Accounts[right].CredentialID
		})
		contexts = append(contexts, contextState)
	}
	sort.Slice(contexts, func(left int, right int) bool { return contexts[left].ProfileID < contexts[right].ProfileID })
	return contexts, nil
}

// inspectModelContextAccount derives one concrete account state using the same eligibility rules as target selection.
// inspectModelContextAccount 使用与目标选择相同的资格规则派生一个具体账号状态。
func (r *Resolver) inspectModelContextAccount(ctx context.Context, snapshot catalog.Snapshot, credential providerconfig.Credential, offering catalog.ModelOffering, modelID string, profileID string, entitlementClass string, effectiveContext catalog.OptionalTokenLimit, bindings []providerconfig.AccessBinding, endpoints map[string]providerconfig.Endpoint, now time.Time) (ModelContextAccountState, error) {
	state := ModelContextAccountState{CredentialID: credential.ID, CredentialStatus: credential.Status, Priority: credential.Priority, EntitlementClass: entitlementClass, EffectiveContextWindow: effectiveContext, RuntimeStatus: ContextAccountUnavailable, CoolingUntil: cloneTimePointer(credential.CoolingUntil)}
	if credential.Status == providerconfig.CredentialCooling && credential.CoolingUntil != nil && credential.CoolingUntil.After(now) {
		state.RuntimeStatus = ContextAccountCooling
		return state, nil
	}
	if !credential.RuntimeEligibleAt(now) {
		state.RuntimeStatus = ContextAccountInvalid
		return state, nil
	}
	blockedKinds, earliestResetAt := blockedByAllowance(snapshot.Allowances, credential, modelID, profileID, nil)
	state.BlockingAllowanceKinds = blockedKinds
	state.EarliestResetAt = cloneTimePointer(earliestResetAt)
	if len(blockedKinds) > 0 {
		state.RuntimeStatus = ContextAccountExhausted
		return state, nil
	}
	if !credentialBoundToReadyModelEndpoint(credential.ID, offering, modelID, bindings, endpoints) {
		state.RuntimeStatus = ContextAccountUnavailable
		return state, nil
	}
	pathEligible, errPath := r.modelPoolPathEligible(ctx, snapshot.ProviderInstanceID, credential, offering, modelID, bindings, endpoints, now)
	if errPath != nil {
		return ModelContextAccountState{}, errPath
	}
	modelEligible, errModel := r.modelRuntimeEligible(ctx, snapshot.ProviderInstanceID, credential.ID, modelID, now)
	if errModel != nil {
		return ModelContextAccountState{}, errModel
	}
	if !pathEligible || !modelEligible {
		state.RuntimeStatus = ContextAccountCooling
		return state, nil
	}
	state.RuntimeStatus = ContextAccountReady
	return state, nil
}

// AllowanceAppliesToModelContext reports exact allowance applicability for one credential, model, profile, and capability set.
// AllowanceAppliesToModelContext 报告额度对一个凭据、模型、规格与能力集合的精确适用性。
func AllowanceAppliesToModelContext(allowance catalog.AllowanceSnapshot, credential providerconfig.Credential, modelID string, profileID string, requiredCapabilities []string) bool {
	return allowanceApplies(allowance, credential, modelID, profileID, requiredCapabilities)
}

// CapabilitiesSatisfy reports whether one model profile supports every normalized capability identifier.
// CapabilitiesSatisfy 报告一个模型规格是否支持全部规范化能力标识。
func CapabilitiesSatisfy(capabilities catalog.ModelCapabilities, required []string) bool {
	return capabilitiesSatisfy(capabilities, required)
}

// credentialBoundToModelEndpoint reports whether one enabled binding associates an account with the model channel.
// credentialBoundToModelEndpoint 报告一个已启用 Binding 是否将账号关联到模型通道。
func credentialBoundToModelEndpoint(credentialID string, offering catalog.ModelOffering, modelID string, bindings []providerconfig.AccessBinding, endpoints map[string]providerconfig.Endpoint) bool {
	for _, binding := range bindings {
		if !binding.Enabled || binding.CredentialID != credentialID || binding.ChannelID != offering.ChannelID || !allowsModel(binding.AllowedModelIDs, modelID) {
			continue
		}
		_, exists := endpoints[binding.EndpointID]
		if exists {
			return true
		}
	}
	return false
}

// providerModelByID resolves one exact model inside an already validated snapshot.
// providerModelByID 在一个已验证快照中解析一个精确模型。
func providerModelByID(models []catalog.ProviderModel, modelID string) (catalog.ProviderModel, bool) {
	for _, model := range models {
		if model.ID == modelID {
			return model, true
		}
	}
	return catalog.ProviderModel{}, false
}

// cloneTimePointer isolates one optional timestamp from mutable persistence state.
// cloneTimePointer 将一个可选时间戳与可变持久化状态隔离。
func cloneTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

// credentialPoolEligible classifies configured credential cooldown and invalid states for one pool.
// credentialPoolEligible 为一个账号池分类已配置凭据的冷却与无效状态。
func credentialPoolEligible(credential providerconfig.Credential, now time.Time, pool *catalog.PoolSummary) bool {
	if credential.Status == providerconfig.CredentialCooling && credential.CoolingUntil != nil && credential.CoolingUntil.After(now) {
		pool.CoolingCredentials++
		return false
	}
	if !credential.RuntimeEligibleAt(now) {
		pool.InvalidCredentials++
		return false
	}
	return true
}

// allowanceBlocksPool records whether mandatory resource exhaustion blocks one pool candidate.
// allowanceBlocksPool 记录强制资源耗尽是否阻塞一个账号池候选项。
func allowanceBlocksPool(allowances []catalog.AllowanceSnapshot, credential providerconfig.Credential, subjectID string, profileID string, blockingKinds map[catalog.AllowanceKind]struct{}, pool *catalog.PoolSummary) bool {
	blocked, earliestResetAt := blockedByAllowance(allowances, credential, subjectID, profileID, nil)
	if len(blocked) == 0 {
		return false
	}
	pool.ExhaustedCredentials++
	for _, allowanceKind := range blocked {
		blockingKinds[allowanceKind] = struct{}{}
	}
	pool.EarliestResetAt = earlierTime(pool.EarliestResetAt, earliestResetAt)
	return true
}

// credentialBoundToReadyModelEndpoint reports whether one credential has a statically usable model channel binding.
// credentialBoundToReadyModelEndpoint 返回一个凭据是否具有静态可用的模型通道绑定。
func credentialBoundToReadyModelEndpoint(credentialID string, offering catalog.ModelOffering, modelID string, bindings []providerconfig.AccessBinding, endpoints map[string]providerconfig.Endpoint) bool {
	for _, binding := range bindings {
		if !binding.Enabled || binding.CredentialID != credentialID || binding.ChannelID != offering.ChannelID || !allowsModel(binding.AllowedModelIDs, modelID) {
			continue
		}
		endpoint, exists := endpoints[binding.EndpointID]
		if exists && endpoint.Status == providerconfig.EndpointReady {
			return true
		}
	}
	return false
}

// credentialBoundToReadyServiceEndpoint reports whether one credential has a statically usable service channel binding.
// credentialBoundToReadyServiceEndpoint 返回一个凭据是否具有静态可用的服务通道绑定。
func credentialBoundToReadyServiceEndpoint(credentialID string, offering catalog.ServiceOffering, serviceID string, bindings []providerconfig.AccessBinding, endpoints map[string]providerconfig.Endpoint) bool {
	for _, binding := range bindings {
		if !binding.Enabled || binding.CredentialID != credentialID || binding.ChannelID != offering.ChannelID || !allowsService(binding.AllowedServiceIDs, serviceID) {
			continue
		}
		endpoint, exists := endpoints[binding.EndpointID]
		if exists && endpoint.Status == providerconfig.EndpointReady {
			return true
		}
	}
	return false
}

// modelPoolPathEligible reports whether at least one bound model endpoint remains runtime eligible.
// modelPoolPathEligible 报告至少一个已绑定模型入口是否仍具备运行时资格。
func (r *Resolver) modelPoolPathEligible(ctx context.Context, instanceID string, credential providerconfig.Credential, offering catalog.ModelOffering, modelID string, bindings []providerconfig.AccessBinding, endpoints map[string]providerconfig.Endpoint, now time.Time) (bool, error) {
	for _, binding := range bindings {
		if !binding.Enabled || binding.CredentialID != credential.ID || binding.ChannelID != offering.ChannelID || !allowsModel(binding.AllowedModelIDs, modelID) {
			continue
		}
		endpoint, exists := endpoints[binding.EndpointID]
		if !exists || endpoint.Status != providerconfig.EndpointReady {
			continue
		}
		eligible, errEligible := r.runtimePathEligible(ctx, instanceID, credential, endpoint.ID, now)
		if errEligible != nil {
			return false, errEligible
		}
		if eligible {
			return true, nil
		}
	}
	return false, nil
}

// servicePoolPathEligible reports whether at least one bound service endpoint remains runtime eligible.
// servicePoolPathEligible 报告至少一个已绑定服务入口是否仍具备运行时资格。
func (r *Resolver) servicePoolPathEligible(ctx context.Context, instanceID string, credential providerconfig.Credential, offering catalog.ServiceOffering, serviceID string, bindings []providerconfig.AccessBinding, endpoints map[string]providerconfig.Endpoint, now time.Time) (bool, error) {
	for _, binding := range bindings {
		if !binding.Enabled || binding.CredentialID != credential.ID || binding.ChannelID != offering.ChannelID || !allowsService(binding.AllowedServiceIDs, serviceID) {
			continue
		}
		endpoint, exists := endpoints[binding.EndpointID]
		if !exists || endpoint.Status != providerconfig.EndpointReady {
			continue
		}
		eligible, errEligible := r.runtimePathEligible(ctx, instanceID, credential, endpoint.ID, now)
		if errEligible != nil {
			return false, errEligible
		}
		if eligible {
			return true, nil
		}
	}
	return false, nil
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
	if request.ProviderInstanceID == "" || request.RequiredContextTokens < 0 || request.Now.IsZero() {
		return Target{}, Diagnostics{}, errors.New("provider instance, non-negative context requirement, and evaluation time are required")
	}
	if (request.ProviderModelID == "") == (request.ProviderServiceID == "") {
		return Target{}, Diagnostics{}, errors.New("exactly one provider model or service is required")
	}
	if request.ProviderServiceID != "" && request.OfferingID != "" {
		return Target{}, Diagnostics{}, errors.New("model offering cannot be selected for a provider service")
	}
	if request.ProviderServiceID != "" {
		return r.resolveService(ctx, request)
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
	profile, offering, errProfile := selectProfile(snapshot, model.ID, request.OfferingID, request.ExecutionProfileID)
	if errProfile != nil {
		return Target{}, Diagnostics{}, errProfile
	}
	if len(snapshot.ModelOperationPolicies) > 0 && !supportedModelOperationPolicy(snapshot.ModelOperationPolicies, model.ID, offering.ID, profile.Operation) {
		return Target{}, Diagnostics{}, fmt.Errorf("%w: model=%s offering=%s operation=%s", ErrProfilePolicyMismatch, model.ID, offering.ID, profile.Operation)
	}
	if profile.Operation != "" && request.Operation != profile.Operation {
		return Target{}, Diagnostics{}, fmt.Errorf("%w: model operation does not match execution profile", ErrNoEligibleTarget)
	}
	if profile.Operation == "" && request.Operation != "" {
		return Target{}, Diagnostics{}, fmt.Errorf("%w: legacy execution profile does not declare operation", ErrNoEligibleTarget)
	}
	actionAuthMethodIDs := []string(nil)
	if profile.ActionBindingID != "" {
		action, errAction := r.resolveDefinitionAction(ctx, instance.DefinitionID, profile.ActionBindingID, profile.Operation, offering.ChannelID)
		if errAction != nil {
			return Target{}, Diagnostics{}, errAction
		}
		actionAuthMethodIDs = action.AuthMethodIDs
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
		if !endpointExists || !credentialExists || (len(actionAuthMethodIDs) > 0 && !containsString(actionAuthMethodIDs, credential.AuthMethodID)) {
			continue
		}
		if request.RequiredCredentialID != "" && credential.ID != request.RequiredCredentialID {
			continue
		}
		if request.RequiredEndpointID != "" && endpoint.ID != request.RequiredEndpointID {
			continue
		}
		if request.RequiredRegion != "" && endpoint.Region != request.RequiredRegion {
			continue
		}
		if containsString(request.ExcludedCredentialIDs, credential.ID) {
			continue
		}
		if containsString(request.ExcludedEndpointIDs, endpoint.ID) {
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
		pathEligible, errPathState := r.runtimePathEligible(ctx, instance.ID, credential, endpoint.ID, request.Now)
		if errPathState != nil {
			return Target{}, diagnostics, errPathState
		}
		if !pathEligible {
			continue
		}
		modelEligible, errRuntimeState := r.modelRuntimeEligible(ctx, instance.ID, credential.ID, model.ID, request.Now)
		if errRuntimeState != nil {
			return Target{}, diagnostics, errRuntimeState
		}
		if !modelEligible {
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
	selected, errSelect := r.selectCandidate(ctx, instance, model.ID+":"+profile.ID, profile.PoolPolicy, candidates)
	if errSelect != nil {
		return Target{}, diagnostics, errSelect
	}
	return Target{
		ProviderDefinitionID:         instance.DefinitionID,
		ProviderInstanceID:           instance.ID,
		ChannelID:                    offering.ChannelID,
		EndpointID:                   selected.endpoint.ID,
		EndpointRegion:               selected.endpoint.Region,
		CredentialID:                 selected.credential.ID,
		SubjectKind:                  ExecutionSubjectModel,
		ProviderModelID:              model.ID,
		OfferingID:                   offering.ID,
		Operation:                    profile.Operation,
		ActionBindingID:              profile.ActionBindingID,
		ProfileDriver:                profile.ProfileDriver,
		ExecutionProfileID:           profile.ID,
		UpstreamModelID:              offering.UpstreamModelID,
		EffectiveContextWindow:       selected.effectiveContext,
		TokenLimits:                  profile.Capabilities.Tokens,
		TokenRecommendations:         profile.Capabilities.Recommendations,
		ModelCapabilities:            catalog.CloneModelCapabilities(profile.Capabilities),
		RequestProjection:            catalog.CloneRequestProjection(offering.RequestProjection),
		ProviderAdditionalParameters: catalog.CloneAdditionalPayloadProjection(snapshot.DefaultAdditionalParameters),
		CapabilityRevision:           profile.CapabilityRevision,
		ProviderConfigRevision:       instance.Revision,
		CatalogRevision:              snapshot.Revision,
	}, diagnostics, nil
}

// supportedModelOperationPolicy verifies one exact model, offering, and operation decision at the final resolution boundary.
// supportedModelOperationPolicy 在最终解析边界校验一个精确模型、Offering 与操作决策。
func supportedModelOperationPolicy(policies []catalog.ModelOperationPolicy, modelID string, offeringID string, operation vcp.OperationKind) bool {
	for _, policy := range policies {
		if policy.ProviderModelID == modelID && policy.OfferingID == offeringID && policy.Operation == operation {
			return policy.Status == catalog.ModelOperationSupported
		}
	}
	return false
}

// resolveService selects one exact same-provider service target without fallback.
// resolveService 选择一个不含降级的精确同供应商服务目标。
func (r *Resolver) resolveService(ctx context.Context, request Request) (Target, Diagnostics, error) {
	if request.ServiceOfferingID == "" || request.ExecutionProfileID == "" || request.Operation == "" {
		return Target{}, Diagnostics{}, errors.New("service offering, execution profile, and operation are required")
	}
	if request.RequiredContextTokens != 0 || len(request.RequiredCapabilities) != 0 {
		return Target{}, Diagnostics{}, errors.New("service resolution does not accept model context or string capability requirements")
	}
	instance, errInstance := r.configurations.GetInstance(ctx, request.ProviderInstanceID)
	if errInstance != nil {
		return Target{}, Diagnostics{}, errInstance
	}
	if instance.Status != providerconfig.LifecycleReady && instance.Status != providerconfig.LifecycleDegraded {
		return Target{}, Diagnostics{}, fmt.Errorf("%w: %s", ErrInstanceNotExecutable, instance.Status)
	}
	if serviceDisabled(instance.DisabledServiceIDs, request.ProviderServiceID) {
		return Target{}, Diagnostics{}, fmt.Errorf("%w: %s", ErrServiceDisabled, request.ProviderServiceID)
	}
	snapshot, errCatalog := r.catalogs.Get(ctx, request.ProviderInstanceID)
	if errCatalog != nil {
		return Target{}, Diagnostics{}, errCatalog
	}
	service, exists := findService(snapshot.Services, request.ProviderServiceID)
	if !exists {
		return Target{}, Diagnostics{}, fmt.Errorf("%w: %s", ErrServiceNotFound, request.ProviderServiceID)
	}
	if service.Operation != request.Operation {
		return Target{}, Diagnostics{}, fmt.Errorf("%w: service operation mismatch", ErrNoEligibleTarget)
	}
	profile, offering, errProfile := selectServiceProfile(snapshot, service.ID, request.ServiceOfferingID, request.ExecutionProfileID)
	if errProfile != nil {
		return Target{}, Diagnostics{}, errProfile
	}
	action, errAction := r.resolveDefinitionAction(ctx, instance.DefinitionID, profile.ActionBindingID, profile.Operation, offering.ChannelID)
	if errAction != nil {
		return Target{}, Diagnostics{}, errAction
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
	entitlements := serviceEntitlementsByCredential(snapshot.ServiceEntitlements, service.ID)
	blockingKinds := make(map[catalog.AllowanceKind]struct{})
	candidates := make([]candidate, 0, len(bindings))
	for _, binding := range bindings {
		if !binding.Enabled || binding.ChannelID != offering.ChannelID || !allowsService(binding.AllowedServiceIDs, service.ID) {
			continue
		}
		endpoint, endpointExists := endpointByID[binding.EndpointID]
		credential, credentialExists := credentialByID[binding.CredentialID]
		if !endpointExists || !credentialExists || (len(action.AuthMethodIDs) > 0 && !containsString(action.AuthMethodIDs, credential.AuthMethodID)) {
			continue
		}
		if request.RequiredCredentialID != "" && credential.ID != request.RequiredCredentialID {
			continue
		}
		if request.RequiredEndpointID != "" && endpoint.ID != request.RequiredEndpointID {
			continue
		}
		if request.RequiredRegion != "" && endpoint.Region != request.RequiredRegion {
			continue
		}
		if containsString(request.ExcludedCredentialIDs, credential.ID) {
			continue
		}
		if containsString(request.ExcludedEndpointIDs, endpoint.ID) {
			continue
		}
		diagnostics.BoundCandidates++
		if !serviceEntitled(service, profile, entitlements[credential.ID], request.Now) {
			continue
		}
		diagnostics.EntitledCandidates++
		diagnostics.CapabilityCandidates++
		blocked, earliestResetAt := blockedByAllowance(snapshot.Allowances, credential, service.ID, profile.ID, nil)
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
		pathEligible, errPathState := r.runtimePathEligible(ctx, instance.ID, credential, endpoint.ID, request.Now)
		if errPathState != nil {
			return Target{}, diagnostics, errPathState
		}
		if !pathEligible {
			continue
		}
		diagnostics.ReadyCandidates++
		candidates = append(candidates, candidate{binding: binding, endpoint: endpoint, credential: credential})
	}
	diagnostics.BlockingAllowanceKinds = sortedAllowanceKinds(blockingKinds)
	if len(candidates) == 0 {
		return Target{}, diagnostics, ErrNoEligibleTarget
	}
	selected, errSelect := r.selectCandidate(ctx, instance, service.ID+":"+profile.ID, profile.PoolPolicy, candidates)
	if errSelect != nil {
		return Target{}, diagnostics, errSelect
	}
	capabilities := cloneServiceCapabilities(*profile.ServiceCapabilities)
	return Target{
		ProviderDefinitionID:   instance.DefinitionID,
		ProviderInstanceID:     instance.ID,
		ChannelID:              offering.ChannelID,
		EndpointID:             selected.endpoint.ID,
		EndpointRegion:         selected.endpoint.Region,
		CredentialID:           selected.credential.ID,
		SubjectKind:            ExecutionSubjectService,
		ProviderServiceID:      service.ID,
		ServiceOfferingID:      offering.ID,
		Operation:              profile.Operation,
		ActionBindingID:        profile.ActionBindingID,
		ExecutionProfileID:     profile.ID,
		UpstreamServiceID:      offering.UpstreamServiceID,
		ServiceCapabilities:    &capabilities,
		CapabilityRevision:     profile.CapabilityRevision,
		ProviderConfigRevision: instance.Revision,
		CatalogRevision:        snapshot.Revision,
	}, diagnostics, nil
}

// resolveDefinitionAction verifies one catalog profile against its exact code-owned provider action.
// resolveDefinitionAction 校验一个目录 Profile 对应其精确代码拥有供应商动作。
func (r *Resolver) resolveDefinitionAction(ctx context.Context, definitionID string, actionBindingID string, operation vcp.OperationKind, channelID string) (providerconfig.ProviderActionBinding, error) {
	definition, errDefinition := r.configurations.GetDefinition(ctx, definitionID)
	if errDefinition != nil {
		return providerconfig.ProviderActionBinding{}, errDefinition
	}
	var resolved providerconfig.ProviderActionBinding
	found := false
	for _, action := range definition.ActionBindings {
		if action.ID != actionBindingID {
			continue
		}
		if found {
			return providerconfig.ProviderActionBinding{}, fmt.Errorf("%w: duplicate provider action binding %q", ErrNoEligibleTarget, actionBindingID)
		}
		resolved = action
		found = true
	}
	if !found || resolved.Operation != operation || resolved.ProtocolProfileID != channelID {
		return providerconfig.ProviderActionBinding{}, fmt.Errorf("%w: profile action does not match provider definition and channel", ErrNoEligibleTarget)
	}
	return resolved, nil
}

// containsString reports whether one exact identifier belongs to a closed configured list.
// containsString 报告一个精确标识是否属于封闭配置列表。
func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
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

// selectCandidate applies account-level routing before deterministic endpoint selection for the chosen credential.
// selectCandidate 在为选中凭据确定性选择入口之前应用账号级路由。
func (r *Resolver) selectCandidate(ctx context.Context, instance providerconfig.ProviderInstance, subjectKey string, policy catalog.PoolPolicy, candidates []candidate) (candidate, error) {
	byCredential := make(map[string][]candidate)
	routingCandidates := make([]routing.Candidate, 0, len(candidates))
	for _, current := range candidates {
		paths := byCredential[current.credential.ID]
		if len(paths) == 0 {
			routingCandidates = append(routingCandidates, routing.Candidate{ID: current.credential.ID, Priority: current.credential.Priority, CapacityKnown: current.selectionCapacity.Known, Capacity: current.selectionCapacity.Value})
		}
		byCredential[current.credential.ID] = append(paths, current)
	}
	strategy := instance.RoutingStrategy
	if strategy == "" {
		strategy = providerconfig.RoutingRoundRobin
		if r.runtimeState != nil {
			settings, errSettings := r.runtimeState.GetSettings(ctx)
			if errSettings != nil {
				return candidate{}, fmt.Errorf("read Router routing settings: %w", errSettings)
			}
			strategy = settings.DefaultRoutingStrategy
		}
	}
	selectedCredential, errSelect := r.selector.Pick(instance.ID+":"+subjectKey, routing.SelectionOptions{Strategy: strategy, PreferSmallestSufficient: policy == catalog.PoolPreferSmallestSufficient}, routingCandidates)
	if errSelect != nil {
		return candidate{}, ErrNoEligibleTarget
	}
	paths := byCredential[selectedCredential.ID]
	sort.Slice(paths, func(left int, right int) bool {
		if paths[left].binding.Priority != paths[right].binding.Priority {
			return paths[left].binding.Priority < paths[right].binding.Priority
		}
		return paths[left].endpoint.ID < paths[right].endpoint.ID
	})
	return paths[0], nil
}

// modelRuntimeEligible applies only exact credential-model runtime state and treats absent state as ready.
// modelRuntimeEligible 仅应用精确凭据模型运行状态，并将缺失状态视为就绪。
func (r *Resolver) modelRuntimeEligible(ctx context.Context, instanceID string, credentialID string, modelID string, now time.Time) (bool, error) {
	if r.runtimeState == nil {
		return true, nil
	}
	state, errState := r.runtimeState.GetCredentialModelState(ctx, instanceID, credentialID, modelID)
	if errors.Is(errState, routingstate.ErrNotFound) {
		return true, nil
	}
	if errState != nil {
		return false, fmt.Errorf("read credential model state: %w", errState)
	}
	return state.EligibleAt(now), nil
}

// runtimePathEligible applies provider, endpoint, credential, subscription, and billing-account state to one exact candidate path.
// runtimePathEligible 将供应商、入口、凭据、订阅与计费账号状态应用到一个精确候选路径。
func (r *Resolver) runtimePathEligible(ctx context.Context, instanceID string, credential providerconfig.Credential, endpointID string, now time.Time) (bool, error) {
	if r.runtimeState == nil {
		return true, nil
	}
	identities := []runtimeScopeIdentity{{routingstate.ScopeProvider, instanceID}, {routingstate.ScopeEndpoint, endpointID}, {routingstate.ScopeCredential, credential.ID}}
	for _, scopeReference := range credential.ScopeRefs {
		switch scopeReference.Kind {
		case string(routingstate.ScopeSubscription):
			identities = append(identities, runtimeScopeIdentity{routingstate.ScopeSubscription, scopeReference.ID})
		case string(routingstate.ScopeBillingAccount):
			identities = append(identities, runtimeScopeIdentity{routingstate.ScopeBillingAccount, scopeReference.ID})
		}
	}
	for _, identity := range identities {
		state, errState := r.runtimeState.GetRuntimeScopeState(ctx, instanceID, identity.scope, identity.scopeID)
		if errors.Is(errState, routingstate.ErrNotFound) {
			continue
		}
		if errState != nil {
			return false, fmt.Errorf("read %s runtime state: %w", identity.scope, errState)
		}
		if !state.EligibleAt(now) {
			return false, nil
		}
	}
	return true, nil
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

// findService returns one exact provider service from an atomic snapshot.
// findService 从原子快照返回一个精确供应商服务。
func findService(services []catalog.ProviderService, serviceID string) (catalog.ProviderService, bool) {
	for _, service := range services {
		if service.ID == serviceID {
			return service, true
		}
	}
	return catalog.ProviderService{}, false
}

// selectServiceProfile resolves one exact service offering and profile.
// selectServiceProfile 解析一个精确服务产品和规格。
func selectServiceProfile(snapshot catalog.Snapshot, serviceID string, offeringID string, profileID string) (catalog.ExecutionProfile, catalog.ServiceOffering, error) {
	var selectedOffering catalog.ServiceOffering
	offeringFound := false
	for _, offering := range snapshot.ServiceOfferings {
		if offering.ID == offeringID && offering.ProviderServiceID == serviceID {
			selectedOffering = offering
			offeringFound = true
			break
		}
	}
	if !offeringFound {
		return catalog.ExecutionProfile{}, catalog.ServiceOffering{}, fmt.Errorf("%w: service offering %q", ErrProfileNotFound, offeringID)
	}
	for _, profile := range snapshot.Profiles {
		if profile.ID == profileID && profile.ServiceOfferingID == selectedOffering.ID {
			return profile, selectedOffering, nil
		}
	}
	return catalog.ExecutionProfile{}, catalog.ServiceOffering{}, fmt.Errorf("%w: service profile %q", ErrProfileNotFound, profileID)
}

// serviceEntitlementsByCredential indexes service-specific entitlements by credential identifier.
// serviceEntitlementsByCredential 按凭据标识索引服务特定授权。
func serviceEntitlementsByCredential(entitlements []catalog.ServiceEntitlement, serviceID string) map[string]catalog.ServiceEntitlement {
	indexed := make(map[string]catalog.ServiceEntitlement)
	for _, entitlement := range entitlements {
		if entitlement.ProviderServiceID == serviceID {
			indexed[entitlement.CredentialID] = entitlement
		}
	}
	return indexed
}

// serviceEntitled reports whether one credential may execute the exact service profile.
// serviceEntitled 报告一个凭据是否可以执行精确服务规格。
func serviceEntitled(service catalog.ProviderService, profile catalog.ExecutionProfile, entitlement catalog.ServiceEntitlement, now time.Time) bool {
	if service.EntitlementMode == catalog.EntitlementAllBoundCredentials {
		return true
	}
	if entitlement.ProviderServiceID != service.ID || entitlement.Availability != catalog.AvailabilityAllowed || !metadataCurrent(entitlement.ObservedAt, entitlement.ExpiresAt, now) {
		return false
	}
	return len(entitlement.AllowedProfileIDs) == 0 || contains(entitlement.AllowedProfileIDs, profile.ID)
}

// cloneServiceCapabilities returns a target-owned service capability snapshot.
// cloneServiceCapabilities 返回一个目标拥有的服务能力快照。
func cloneServiceCapabilities(capabilities catalog.ServiceCapabilities) catalog.ServiceCapabilities {
	if capabilities.WebSearch == nil {
		return capabilities
	}
	search := *capabilities.WebSearch
	search.OutputModes = append([]vcp.WebSearchOutputMode(nil), search.OutputModes...)
	search.EvidenceKinds = append([]vcp.SearchEvidenceKind(nil), search.EvidenceKinds...)
	search.EvidenceRequirements = append([]vcp.SearchEvidenceRequirement(nil), search.EvidenceRequirements...)
	capabilities.WebSearch = &search
	return capabilities
}

// selectProfile resolves one exact offering/profile constraint or one unambiguous default profile for a model.
// selectProfile 为模型解析一个精确产品与规格约束，或一个无歧义默认规格。
func selectProfile(snapshot catalog.Snapshot, modelID string, offeringID string, profileID string) (catalog.ExecutionProfile, catalog.ModelOffering, error) {
	offerings := make(map[string]catalog.ModelOffering)
	for _, offering := range snapshot.Offerings {
		if offering.ProviderModelID == modelID && (offeringID == "" || offering.ID == offeringID) {
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
	// Product-level profiles remain available to every bound credential even when another profile on the same logical model has narrower explicit authorization.
	// 产品级规格对每个已绑定凭据保持可用，即使同一逻辑模型上的其他规格具有更窄的显式授权。
	if model.EntitlementMode == catalog.EntitlementAllBoundCredentials && len(profile.RequiredEntitlementClasses) == 0 {
		return catalog.ModelEntitlement{}, true
	}
	if entitlement.ID == "" {
		if model.EntitlementMode == catalog.EntitlementExplicit || len(profile.RequiredEntitlementClasses) > 0 {
			return catalog.ModelEntitlement{}, false
		}
		return catalog.ModelEntitlement{}, true
	}
	if entitlement.Availability != catalog.AvailabilityAllowed || !metadataCurrent(entitlement.ObservedAt, entitlement.ExpiresAt, now) {
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

// ProfileEntitled reports whether one credential entitlement authorizes an exact execution profile at a fixed time.
// ProfileEntitled 报告一个凭据授权是否在固定时间允许使用精确执行规格。
func ProfileEntitled(model catalog.ProviderModel, profile catalog.ExecutionProfile, entitlement catalog.ModelEntitlement, now time.Time) bool {
	_, entitled := entitlementForProfile(model, profile, entitlement, now)
	return entitled
}

// metadataCurrent reports whether one observed commercial fact is active at the evaluation time.
// metadataCurrent 报告一个已观测商业事实在评估时刻是否有效。
func metadataCurrent(observedAt time.Time, expiresAt time.Time, now time.Time) bool {
	if observedAt.IsZero() || now.Before(observedAt) {
		return false
	}
	return expiresAt.IsZero() || expiresAt.After(now)
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
		case "streaming":
			if capabilities.Delivery.Streaming {
				continue
			}
			return false
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
		case "image_input":
			level = mediaInputLevel(capabilities.MediaInputs, vcp.MediaImage)
		case "audio_input":
			level = mediaInputLevel(capabilities.MediaInputs, vcp.MediaAudio)
		case "video_input":
			level = mediaInputLevel(capabilities.MediaInputs, vcp.MediaVideo)
		case "file_input":
			level = mediaInputLevel(capabilities.MediaInputs, vcp.MediaFile)
		default:
			return false
		}
		if level != catalog.CapabilityNative && level != catalog.CapabilityEmulated {
			return false
		}
	}
	return true
}

// mediaInputLevel returns the declared callable level for one exact media family.
// mediaInputLevel 返回一个精确媒体类别声明的可调用级别。
func mediaInputLevel(inputs []catalog.MediaInputCapability, kind vcp.MediaKind) catalog.CapabilityLevel {
	for _, input := range inputs {
		if input.Kind == kind {
			return input.Level
		}
	}
	return catalog.CapabilityUnsupported
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

// allowsService reports whether an access binding permits one provider service.
// allowsService 报告访问绑定是否允许一个供应商服务。
func allowsService(allowedServiceIDs []string, serviceID string) bool {
	return len(allowedServiceIDs) == 0 || contains(allowedServiceIDs, serviceID)
}

// modelDisabled reports whether local management policy explicitly disables one provider model.
// modelDisabled 返回本地管理策略是否显式禁用一个供应商模型。
func modelDisabled(disabledModelIDs []string, modelID string) bool {
	return contains(disabledModelIDs, modelID)
}

// serviceDisabled reports whether local management policy disables one provider service.
// serviceDisabled 报告本地管理策略是否禁用一个供应商服务。
func serviceDisabled(disabledServiceIDs []string, serviceID string) bool {
	return contains(disabledServiceIDs, serviceID)
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
