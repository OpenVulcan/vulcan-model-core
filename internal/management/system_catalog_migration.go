package management

import (
	"context"
	"errors"
	"fmt"
	"math"
	"reflect"
	"slices"
	"sort"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/bootstrap"
	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/dependency"
	protocolmessages "github.com/OpenVulcan/vulcan-model-core/internal/protocol/anthropic/messages"
	providerkimi "github.com/OpenVulcan/vulcan-model-core/internal/provider/kimi"
	provideropenai "github.com/OpenVulcan/vulcan-model-core/internal/provider/openai"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

const (
	// legacyKimiChatChannelID is the exact Chat channel persisted by the pre-profile Kimi catalog implementation.
	// legacyKimiChatChannelID 是旧版 Kimi 目录实现在引入 Profile 前持久化的精确 Chat 通道标识。
	legacyKimiChatChannelID = "chat"
	// tavilySearchServiceID identifies the code-owned Tavily search service.
	// tavilySearchServiceID 标识代码拥有的 Tavily 搜索服务。
	tavilySearchServiceID = "service_web_search"
	// tavilyExtractServiceID identifies the code-owned Tavily extraction service.
	// tavilyExtractServiceID 标识代码拥有的 Tavily 内容提取服务。
	tavilyExtractServiceID = "service_web_extract"
)

// LoadSystemCatalogs rebuilds every code-owned provider catalog into the runtime store from the current definitions and user-owned access configuration.
// LoadSystemCatalogs 根据当前定义与用户拥有的访问配置，将每个代码拥有的供应商目录重建到运行时存储。
func LoadSystemCatalogs(ctx context.Context, configurations providerconfig.Store, catalogs catalog.Store) (int, error) {
	if ctx == nil {
		return 0, errors.New("context is required")
	}
	if dependency.IsNil(configurations) || dependency.IsNil(catalogs) {
		return 0, errors.New("provider configuration and catalog stores are required")
	}
	instances, errInstances := configurations.ListInstances(ctx, "")
	if errInstances != nil {
		return 0, fmt.Errorf("list provider instances for runtime system catalogs: %w", errInstances)
	}
	targetResolver, errResolver := resolve.New(configurations, catalogs)
	if errResolver != nil {
		return 0, errResolver
	}
	observedAt := time.Now().UTC()
	loaded := 0
	for _, instance := range instances {
		definition, errDefinition := configurations.GetDefinition(ctx, instance.DefinitionID)
		if errDefinition != nil {
			return loaded, fmt.Errorf("get provider definition %s for runtime system catalog: %w", instance.DefinitionID, errDefinition)
		}
		if definition.Kind != providerconfig.DefinitionKindSystem {
			continue
		}
		snapshot, errBuild := buildSystemCatalog(providerconfig.SystemOnboarding{Instance: instance}, definition, observedAt)
		if errBuild != nil {
			return loaded, fmt.Errorf("build runtime system catalog %s: %w", instance.ID, errBuild)
		}
		if definition.ID == bootstrap.KimiCodingDefinitionID {
			credentials, errCredentials := configurations.ListCredentials(ctx, instance.ID)
			if errCredentials != nil {
				return loaded, fmt.Errorf("list Kimi credentials %s for runtime system catalog: %w", instance.ID, errCredentials)
			}
			for _, credential := range credentials {
				if credential.AuthMethodID != "api_key" || credential.DeclaredPlan == nil {
					continue
				}
				var errMembership error
				snapshot, errMembership = providerkimi.ApplyDeclaredMembership(snapshot, credential)
				if errMembership != nil {
					return loaded, fmt.Errorf("apply Kimi declared membership %s: %w", credential.ID, errMembership)
				}
			}
		}
		pools, errPools := targetResolver.SummarizeSnapshot(ctx, snapshot, observedAt, snapshot.Revision)
		if errPools != nil {
			return loaded, fmt.Errorf("summarize runtime system catalog %s: %w", instance.ID, errPools)
		}
		snapshot.Pools = pools
		if errSave := catalogs.Save(ctx, snapshot); errSave != nil {
			return loaded, fmt.Errorf("save runtime system catalog %s: %w", instance.ID, errSave)
		}
		loaded++
	}
	return loaded, nil
}

// ReconcileMiniMaxSharedOrigins collapses historical per-action endpoint copies into one regional Origin per MiniMax instance.
// ReconcileMiniMaxSharedOrigins 将历史上按动作复制的端点收敛为每个 MiniMax 实例的唯一区域 Origin。
func ReconcileMiniMaxSharedOrigins(ctx context.Context, configurations providerconfig.Store) (int, error) {
	if ctx == nil {
		return 0, errors.New("context is required")
	}
	if dependency.IsNil(configurations) {
		return 0, errors.New("provider configuration store is required")
	}
	instances, errInstances := configurations.ListInstances(ctx, "")
	if errInstances != nil {
		return 0, fmt.Errorf("list provider instances for MiniMax Origin reconciliation: %w", errInstances)
	}
	changedInstances := 0
	for _, instance := range instances {
		if instance.DefinitionID != bootstrap.MiniMaxGlobalDefinitionID && instance.DefinitionID != bootstrap.MiniMaxCNDefinitionID {
			continue
		}
		changed, errReconcile := reconcileMiniMaxSharedOrigin(ctx, configurations, instance)
		if errReconcile != nil {
			return changedInstances, fmt.Errorf("reconcile MiniMax Origin %s: %w", instance.ID, errReconcile)
		}
		if changed {
			changedInstances++
		}
	}
	return changedInstances, nil
}

// reconcileMiniMaxSharedOrigin merges only byte-for-byte equivalent network destinations and preserves every action binding.
// reconcileMiniMaxSharedOrigin 仅合并字节级等价的网络目标，并保留每个动作绑定。
func reconcileMiniMaxSharedOrigin(ctx context.Context, configurations providerconfig.Store, instance providerconfig.ProviderInstance) (bool, error) {
	endpoints, errEndpoints := configurations.ListEndpoints(ctx, instance.ID)
	if errEndpoints != nil {
		return false, errEndpoints
	}
	if len(endpoints) <= 1 {
		return false, nil
	}
	bindings, errBindings := configurations.ListBindings(ctx, instance.ID)
	if errBindings != nil {
		return false, errBindings
	}
	definition, errDefinition := configurations.GetDefinition(ctx, instance.DefinitionID)
	if errDefinition != nil {
		return false, errDefinition
	}
	sort.Slice(endpoints, func(left int, right int) bool {
		leftPrimary := endpoints[left].ChannelID == definition.ProtocolProfileID
		rightPrimary := endpoints[right].ChannelID == definition.ProtocolProfileID
		if leftPrimary != rightPrimary {
			return leftPrimary
		}
		return endpoints[left].ID < endpoints[right].ID
	})
	sharedEndpoint := endpoints[0]
	for _, endpoint := range endpoints[1:] {
		if endpoint.BaseURL != sharedEndpoint.BaseURL || endpoint.Region != sharedEndpoint.Region || endpoint.Status != sharedEndpoint.Status || !reflect.DeepEqual(endpoint.Parameters, sharedEndpoint.Parameters) {
			return false, nil
		}
	}
	replacementBindings := append([]providerconfig.AccessBinding(nil), bindings...)
	for index := range replacementBindings {
		if replacementBindings[index].EndpointID == sharedEndpoint.ID {
			continue
		}
		if replacementBindings[index].Revision == math.MaxUint64 {
			return false, fmt.Errorf("MiniMax binding revision is exhausted for %s", replacementBindings[index].ID)
		}
		replacementBindings[index].EndpointID = sharedEndpoint.ID
		replacementBindings[index].Revision++
	}
	replacement := providerconfig.AccessGraphReplacement{ProviderInstanceID: instance.ID, ExpectedEndpoints: endpoints, ExpectedBindings: bindings, Endpoints: []providerconfig.Endpoint{sharedEndpoint}, Bindings: replacementBindings}
	if errReplace := configurations.ReplaceAccessGraph(ctx, replacement); errReplace != nil {
		return false, errReplace
	}
	return true, nil
}

// ReconcileAlibabaSystemCatalogs upgrades every persisted built-in Alibaba catalog to the current complete code-owned baseline while retaining valid operator and account state.
// ReconcileAlibabaSystemCatalogs 将每个已持久化的内置 Alibaba 目录升级到当前完整的代码拥有基线，同时保留有效的操作员与账号状态。
func ReconcileAlibabaSystemCatalogs(ctx context.Context, configurations providerconfig.Store, catalogs catalog.Store) (int, error) {
	if ctx == nil {
		return 0, errors.New("context is required")
	}
	if dependency.IsNil(configurations) || dependency.IsNil(catalogs) {
		return 0, errors.New("provider configuration and catalog stores are required")
	}
	instances, errInstances := configurations.ListInstances(ctx, "")
	if errInstances != nil {
		return 0, fmt.Errorf("list provider instances for Alibaba catalog reconciliation: %w", errInstances)
	}
	targetResolver, errResolver := resolve.New(configurations, catalogs)
	if errResolver != nil {
		return 0, errResolver
	}
	// reconciliationTime gives every catalog upgraded in this startup pass one deterministic evaluation boundary.
	// reconciliationTime 为本次启动过程中升级的每个目录提供同一个确定性评估边界。
	reconciliationTime := time.Now().UTC()
	changedInstances := 0
	for _, instance := range instances {
		if !isAlibabaSystemDefinition(instance.DefinitionID) {
			continue
		}
		definition, errDefinition := configurations.GetDefinition(ctx, instance.DefinitionID)
		if errDefinition != nil {
			return changedInstances, fmt.Errorf("get Alibaba definition %s: %w", instance.DefinitionID, errDefinition)
		}
		accessGraphChanged, errAccessGraph := reconcileAlibabaAccessGraph(ctx, configurations, instance, definition)
		if errAccessGraph != nil {
			return changedInstances, fmt.Errorf("reconcile Alibaba access graph %s: %w", instance.ID, errAccessGraph)
		}
		credentials, errCredentials := configurations.ListCredentials(ctx, instance.ID)
		if errCredentials != nil {
			return changedInstances, fmt.Errorf("list Alibaba credentials %s: %w", instance.ID, errCredentials)
		}
		current, errCurrent := catalogs.Get(ctx, instance.ID)
		if errors.Is(errCurrent, catalog.ErrSnapshotNotFound) {
			created, errCreate := buildSystemCatalog(providerconfig.SystemOnboarding{Instance: instance}, definition, reconciliationTime)
			if errCreate != nil {
				return changedInstances, fmt.Errorf("build missing Alibaba catalog %s: %w", instance.ID, errCreate)
			}
			pools, errPools := targetResolver.SummarizeSnapshot(ctx, created, reconciliationTime, created.Revision)
			if errPools != nil {
				return changedInstances, fmt.Errorf("summarize missing Alibaba catalog %s: %w", instance.ID, errPools)
			}
			created.Pools = pools
			if errSave := catalogs.Save(ctx, created); errSave != nil {
				return changedInstances, fmt.Errorf("save missing Alibaba catalog %s: %w", instance.ID, errSave)
			}
			changedInstances++
			continue
		}
		if errCurrent != nil {
			return changedInstances, fmt.Errorf("get Alibaba catalog %s: %w", instance.ID, errCurrent)
		}
		upgraded, changed, errUpgrade := rebuildAlibabaSystemCatalog(ctx, targetResolver, instance, definition, credentials, current, reconciliationTime)
		if errUpgrade != nil {
			return changedInstances, fmt.Errorf("rebuild Alibaba catalog %s: %w", instance.ID, errUpgrade)
		}
		if !changed {
			if accessGraphChanged {
				changedInstances++
			}
			continue
		}
		if errSave := catalogs.Save(ctx, upgraded); errSave != nil {
			return changedInstances, fmt.Errorf("save upgraded Alibaba catalog %s: %w", instance.ID, errSave)
		}
		changedInstances++
	}
	return changedInstances, nil
}

// reconcileAlibabaAccessGraph migrates the exact historical Anthropic path and adds only definition-owned native action channels to existing account-endpoint relationships.
// reconcileAlibabaAccessGraph 迁移精确的历史 Anthropic 路径，并仅为既有账号入口关系补齐定义拥有的原生操作通道。
func reconcileAlibabaAccessGraph(ctx context.Context, configurations providerconfig.Store, instance providerconfig.ProviderInstance, definition providerconfig.ProviderDefinition) (bool, error) {
	endpoints, errEndpoints := configurations.ListEndpoints(ctx, instance.ID)
	if errEndpoints != nil {
		return false, errEndpoints
	}
	bindings, errBindings := configurations.ListBindings(ctx, instance.ID)
	if errBindings != nil {
		return false, errBindings
	}
	if len(endpoints) == 0 || len(bindings) == 0 {
		return false, nil
	}
	if len(definition.EndpointPresets) != 1 {
		return false, errors.New("Alibaba system definition requires exactly one endpoint preset")
	}
	// replacementEndpoints and replacementBindings preserve caller-owned identifiers and scheduling fields before any atomic replacement.
	// replacementEndpoints 与 replacementBindings 在任何原子替换前保留调用方拥有的标识与调度字段。
	replacementEndpoints := append([]providerconfig.Endpoint(nil), endpoints...)
	replacementBindings := append([]providerconfig.AccessBinding(nil), bindings...)
	preset := definition.EndpointPresets[0]
	changed := false
	for endpointIndex := range replacementEndpoints {
		endpoint := &replacementEndpoints[endpointIndex]
		if endpoint.ChannelID != protocolmessages.ProfileID {
			continue
		}
		if endpoint.Revision == math.MaxUint64 {
			return false, fmt.Errorf("Alibaba endpoint revision is exhausted for %s", endpoint.ID)
		}
		endpoint.ChannelID = definition.ProtocolProfileID
		endpoint.BaseURL = preset.BaseURL
		endpoint.Region = preset.Region
		endpoint.Parameters = nil
		endpoint.Revision++
		changed = true
	}
	for bindingIndex := range replacementBindings {
		binding := &replacementBindings[bindingIndex]
		if binding.ChannelID != protocolmessages.ProfileID {
			continue
		}
		if binding.Revision == math.MaxUint64 {
			return false, fmt.Errorf("Alibaba binding revision is exhausted for %s", binding.ID)
		}
		binding.ChannelID = definition.ProtocolProfileID
		binding.Revision++
		changed = true
	}
	// bindingKey identifies one exact credential, endpoint, and definition-owned channel relation.
	// bindingKey 标识一个精确的凭据、入口与定义拥有通道关系。
	type bindingKey struct {
		// endpointID identifies the exact shared Origin.
		// endpointID 标识精确的共享 Origin。
		endpointID string
		// credentialID identifies the exact account.
		// credentialID 标识精确账号。
		credentialID string
		// channelID identifies the exact executable Wire contract.
		// channelID 标识精确的可执行 Wire 合同。
		channelID string
	}
	existing := make(map[bindingKey]struct{}, len(replacementBindings))
	// primaryBindings are the only proven account-endpoint relationships that may receive newly introduced native action channels.
	// primaryBindings 是唯一已证明且可补充新原生操作通道的账号入口关系。
	primaryBindings := make([]providerconfig.AccessBinding, 0, len(replacementBindings))
	for _, binding := range replacementBindings {
		existing[bindingKey{endpointID: binding.EndpointID, credentialID: binding.CredentialID, channelID: binding.ChannelID}] = struct{}{}
		if binding.ChannelID == definition.ProtocolProfileID {
			primaryBindings = append(primaryBindings, binding)
		}
	}
	for _, primary := range primaryBindings {
		for _, channelID := range definition.ChannelIDs() {
			key := bindingKey{endpointID: primary.EndpointID, credentialID: primary.CredentialID, channelID: channelID}
			if _, exists := existing[key]; exists {
				continue
			}
			bindingID, errBindingID := generateID("bind_")
			if errBindingID != nil {
				return false, errBindingID
			}
			replacementBindings = append(replacementBindings, providerconfig.AccessBinding{
				ID: bindingID, ProviderInstanceID: instance.ID, ChannelID: channelID, EndpointID: primary.EndpointID,
				CredentialID: primary.CredentialID, Priority: primary.Priority, Enabled: primary.Enabled, Revision: 1,
			})
			existing[key] = struct{}{}
			changed = true
		}
	}
	if !changed {
		return false, nil
	}
	replacement := providerconfig.AccessGraphReplacement{
		ProviderInstanceID: instance.ID, ExpectedEndpoints: endpoints, ExpectedBindings: bindings,
		Endpoints: replacementEndpoints, Bindings: replacementBindings,
	}
	if errReplace := configurations.ReplaceAccessGraph(ctx, replacement); errReplace != nil {
		return false, errReplace
	}
	return true, nil
}

// rebuildAlibabaSystemCatalog converges one historical snapshot after the access graph has been reconciled independently.
// rebuildAlibabaSystemCatalog 在访问图已独立完成收敛后重建一份历史快照。
func rebuildAlibabaSystemCatalog(ctx context.Context, targetResolver *resolve.Resolver, instance providerconfig.ProviderInstance, definition providerconfig.ProviderDefinition, credentials []providerconfig.Credential, current catalog.Snapshot, now time.Time) (catalog.Snapshot, bool, error) {
	desired, errDesired := buildSystemCatalog(providerconfig.SystemOnboarding{Instance: instance}, definition, now)
	if errDesired != nil {
		return catalog.Snapshot{}, false, errDesired
	}
	// Operator-authored provider defaults are configuration, not generated catalog evidence, and therefore survive a baseline rebuild.
	// 操作员编写的供应商默认参数属于配置而非生成目录证据，因此在基线重建时必须保留。
	desired.DefaultAdditionalParameters = current.DefaultAdditionalParameters
	preserveAlibabaAccountMetadata(&desired, current, credentials, now)
	// provisionalRevision supports semantic comparison at MaxUint64 without pretending that an unsavable successor exists.
	// provisionalRevision 支持在 MaxUint64 上进行语义比较，而不会假装存在一个无法保存的后继修订。
	provisionalRevision := current.Revision
	if provisionalRevision < math.MaxUint64 {
		provisionalRevision++
	}
	pools, errPools := targetResolver.SummarizeSnapshot(ctx, desired, now, provisionalRevision)
	if errPools != nil {
		return catalog.Snapshot{}, false, errPools
	}
	desired.Pools = pools
	if alibabaCatalogEquivalent(current, desired) {
		return current, false, nil
	}
	if current.Revision == math.MaxUint64 {
		return catalog.Snapshot{}, false, errors.New("Alibaba catalog revision is exhausted")
	}
	desired.Revision = current.Revision + 1
	desired.ObservedAt = now
	if errValidate := desired.Validate(); errValidate != nil {
		return catalog.Snapshot{}, false, errValidate
	}
	return desired, true, nil
}

// preserveAlibabaAccountMetadata keeps only current observations whose exact credential and catalog references remain valid after rebuilding.
// preserveAlibabaAccountMetadata 仅保留重建后精确凭据与目录引用仍然有效的当前观测。
func preserveAlibabaAccountMetadata(desired *catalog.Snapshot, current catalog.Snapshot, credentials []providerconfig.Credential, now time.Time) {
	// credentialIDs and sharedScopeIDs are the only persisted ownership facts allowed to retain credential-scoped observations.
	// credentialIDs 与 sharedScopeIDs 是允许保留凭据作用域观测的唯一持久所有权事实。
	credentialIDs := make(map[string]struct{}, len(credentials))
	sharedScopeIDs := make(map[string]struct{})
	for _, credential := range credentials {
		credentialIDs[credential.ID] = struct{}{}
		for _, scopeReference := range credential.ScopeRefs {
			sharedScopeIDs[scopeReference.Kind+"\x00"+scopeReference.ID] = struct{}{}
		}
	}
	// modelIDs and profileIDs prove allowance references against the rebuilt static baseline.
	// modelIDs 与 profileIDs 用于根据重建后的静态基线证明额度引用。
	modelIDs := make(map[string]struct{}, len(desired.Models))
	profileIDs := make(map[string]struct{}, len(desired.Profiles))
	for _, model := range desired.Models {
		modelIDs[model.ID] = struct{}{}
	}
	for _, profile := range desired.Profiles {
		profileIDs[profile.ID] = struct{}{}
	}
	for _, plan := range current.Plans {
		_, credentialExists := credentialIDs[plan.CredentialID]
		if credentialExists && catalogMetadataCurrent(plan.ObservedAt, plan.ExpiresAt, now) {
			desired.Plans = append(desired.Plans, plan)
		}
	}
	// Historical dynamic entitlement observations are intentionally discarded because every Alibaba catalog now uses static all-bound-credential ownership.
	// 历史动态权益观测会被有意丢弃，因为所有 Alibaba 目录现已使用静态的全部已绑定凭据归属。
	for _, allowance := range current.Allowances {
		if catalogMetadataCurrent(allowance.ObservedAt, allowance.ExpiresAt, now) && alibabaAllowanceReferenceExists(allowance, credentialIDs, sharedScopeIDs, modelIDs, profileIDs) {
			desired.Allowances = append(desired.Allowances, allowance)
		}
	}
	for _, voice := range current.Voices {
		_, credentialExists := credentialIDs[voice.CredentialID]
		if credentialExists && catalogMetadataCurrent(voice.ObservedAt, voice.ExpiresAt, now) {
			desired.Voices = append(desired.Voices, voice)
		}
	}
}

// alibabaAllowanceReferenceExists verifies every catalog-dependent or credential-owned allowance scope without inventing fallback ownership.
// alibabaAllowanceReferenceExists 在不虚构回退所有权的前提下校验每个依赖目录或凭据拥有的额度作用域。
func alibabaAllowanceReferenceExists(allowance catalog.AllowanceSnapshot, credentialIDs map[string]struct{}, sharedScopeIDs map[string]struct{}, modelIDs map[string]struct{}, profileIDs map[string]struct{}) bool {
	switch allowance.Scope {
	case catalog.ScopeCredential:
		_, exists := credentialIDs[allowance.ScopeID]
		return exists
	case catalog.ScopeSubscription, catalog.ScopeOrganization, catalog.ScopeProject, catalog.ScopeBillingAccount:
		_, exists := sharedScopeIDs[string(allowance.Scope)+"\x00"+allowance.ScopeID]
		return exists
	case catalog.ScopeProviderModel:
		_, exists := modelIDs[allowance.ScopeID]
		return exists
	case catalog.ScopeExecutionProfile:
		_, exists := profileIDs[allowance.ScopeID]
		return exists
	case catalog.ScopeCapability:
		// Capability identifiers are provider-owned independent quota dimensions and do not reference a catalog record.
		// 能力标识是供应商拥有的独立额度维度，不引用目录记录。
		return true
	default:
		return false
	}
}

// alibabaCatalogEquivalent compares the complete retained catalog while ignoring only persistence counters and derived observation time.
// alibabaCatalogEquivalent 比较完整的保留目录，同时仅忽略持久化计数器与派生观测时间。
func alibabaCatalogEquivalent(current catalog.Snapshot, desired catalog.Snapshot) bool {
	return reflect.DeepEqual(normalizedAlibabaCatalog(current), normalizedAlibabaCatalog(desired))
}

// normalizedAlibabaCatalog creates a mutation-safe semantic comparison value for every Alibaba snapshot collection.
// normalizedAlibabaCatalog 为 Alibaba 快照的每个集合创建可安全修改的语义比较值。
func normalizedAlibabaCatalog(snapshot catalog.Snapshot) catalog.Snapshot {
	snapshot.Models = append([]catalog.ProviderModel(nil), snapshot.Models...)
	snapshot.Offerings = append([]catalog.ModelOffering(nil), snapshot.Offerings...)
	snapshot.Services = append([]catalog.ProviderService(nil), snapshot.Services...)
	snapshot.ServiceOfferings = append([]catalog.ServiceOffering(nil), snapshot.ServiceOfferings...)
	snapshot.Profiles = append([]catalog.ExecutionProfile(nil), snapshot.Profiles...)
	snapshot.ModelOperationPolicies = append([]catalog.ModelOperationPolicy(nil), snapshot.ModelOperationPolicies...)
	snapshot.Entitlements = append([]catalog.ModelEntitlement(nil), snapshot.Entitlements...)
	snapshot.ServiceEntitlements = append([]catalog.ServiceEntitlement(nil), snapshot.ServiceEntitlements...)
	snapshot.Plans = append([]catalog.PlanSnapshot(nil), snapshot.Plans...)
	snapshot.Allowances = append([]catalog.AllowanceSnapshot(nil), snapshot.Allowances...)
	snapshot.RateLimits = append([]catalog.RateLimitSnapshot(nil), snapshot.RateLimits...)
	snapshot.Voices = append([]catalog.VoiceSnapshot(nil), snapshot.Voices...)
	snapshot.Pools = append([]catalog.PoolSummary(nil), snapshot.Pools...)
	snapshot.Revision = 0
	snapshot.ObservedAt = time.Time{}
	for index := range snapshot.Models {
		snapshot.Models[index].Revision = 0
	}
	for index := range snapshot.Offerings {
		snapshot.Offerings[index].CapabilityRevision = 0
		snapshot.Offerings[index].Revision = 0
	}
	for index := range snapshot.Services {
		snapshot.Services[index].Revision = 0
	}
	for index := range snapshot.ServiceOfferings {
		snapshot.ServiceOfferings[index].CapabilityRevision = 0
		snapshot.ServiceOfferings[index].Revision = 0
	}
	for index := range snapshot.Profiles {
		snapshot.Profiles[index].CapabilityRevision = 0
		snapshot.Profiles[index].Revision = 0
	}
	for index := range snapshot.ModelOperationPolicies {
		snapshot.ModelOperationPolicies[index].Revision = 0
	}
	for index := range snapshot.Entitlements {
		snapshot.Entitlements[index].Revision = 0
	}
	for index := range snapshot.ServiceEntitlements {
		snapshot.ServiceEntitlements[index].Revision = 0
	}
	for index := range snapshot.Plans {
		snapshot.Plans[index].Revision = 0
	}
	for index := range snapshot.Allowances {
		snapshot.Allowances[index].Revision = 0
	}
	for index := range snapshot.RateLimits {
		snapshot.RateLimits[index].Revision = 0
	}
	for index := range snapshot.Voices {
		snapshot.Voices[index].Revision = 0
	}
	for index := range snapshot.Pools {
		snapshot.Pools[index].Revision = 0
		snapshot.Pools[index].ObservedAt = time.Time{}
		if len(snapshot.Pools[index].BlockingAllowanceKinds) == 0 {
			snapshot.Pools[index].BlockingAllowanceKinds = nil
		}
	}
	return snapshot
}

// isAlibabaSystemDefinition reports whether one immutable definition belongs to the seven published Alibaba products.
// isAlibabaSystemDefinition 判断一个不可变定义是否属于七个已发布 Alibaba 产品之一。
func isAlibabaSystemDefinition(definitionID string) bool {
	switch definitionID {
	case bootstrap.AlibabaCodingPlanCNDefinitionID,
		bootstrap.AlibabaCodingPlanGlobalDefinitionID,
		bootstrap.AlibabaTokenPlanPersonalCNDefinitionID,
		bootstrap.AlibabaTokenPlanTeamCNDefinitionID,
		bootstrap.AlibabaTokenPlanTeamGlobalDefinitionID,
		bootstrap.AlibabaModelStudioCNDefinitionID,
		bootstrap.AlibabaModelStudioGlobalDefinitionID:
		return true
	default:
		return false
	}
}

// ReconcileKimiSystemCatalogs migrates persisted Kimi catalogs to the current single Chat protocol contract and returns the changed instance count.
// ReconcileKimiSystemCatalogs 将持久化的 Kimi 目录迁移到当前唯一 Chat 协议合同，并返回发生变更的实例数量。
func ReconcileKimiSystemCatalogs(ctx context.Context, configurations providerconfig.Store, catalogs catalog.Store) (int, error) {
	if ctx == nil {
		return 0, errors.New("context is required")
	}
	if dependency.IsNil(configurations) || dependency.IsNil(catalogs) {
		return 0, errors.New("provider configuration and catalog stores are required")
	}
	instances, errInstances := configurations.ListInstances(ctx, "")
	if errInstances != nil {
		return 0, fmt.Errorf("list provider instances for Kimi catalog reconciliation: %w", errInstances)
	}
	changedInstances := 0
	for _, instance := range instances {
		if !isKimiSystemDefinition(instance.DefinitionID) {
			continue
		}
		definition, errDefinition := configurations.GetDefinition(ctx, instance.DefinitionID)
		if errDefinition != nil {
			return changedInstances, fmt.Errorf("get Kimi definition %s: %w", instance.DefinitionID, errDefinition)
		}
		credentials, errCredentials := configurations.ListCredentials(ctx, instance.ID)
		if errCredentials != nil {
			return changedInstances, fmt.Errorf("list Kimi credentials %s: %w", instance.ID, errCredentials)
		}
		accessGraphChanged, errAccessGraph := reconcileKimiAccessGraph(ctx, configurations, instance, definition, credentials)
		if errAccessGraph != nil {
			return changedInstances, fmt.Errorf("migrate Kimi access graph %s: %w", instance.ID, errAccessGraph)
		}
		current, errCatalog := catalogs.Get(ctx, instance.ID)
		if errors.Is(errCatalog, catalog.ErrSnapshotNotFound) {
			if accessGraphChanged {
				changedInstances++
			}
			continue
		}
		if errCatalog != nil {
			return changedInstances, fmt.Errorf("get Kimi catalog %s: %w", instance.ID, errCatalog)
		}
		migrated, changed, errMigrate := rebuildKimiSystemCatalog(ctx, configurations, catalogs, instance, definition, credentials, current, time.Now().UTC(), accessGraphChanged)
		if errMigrate != nil {
			return changedInstances, fmt.Errorf("migrate Kimi catalog %s: %w", instance.ID, errMigrate)
		}
		if !changed {
			continue
		}
		if errSave := catalogs.Save(ctx, migrated); errSave != nil {
			return changedInstances, fmt.Errorf("save migrated Kimi catalog %s: %w", instance.ID, errSave)
		}
		changedInstances++
	}
	return changedInstances, nil
}

// ReconcileTavilyExtractCatalogs adds the typed Extract service contract to Tavily snapshots created before extraction support existed.
// ReconcileTavilyExtractCatalogs 为内容提取支持出现前创建的 Tavily 快照补充类型化 Extract 服务合同。
func ReconcileTavilyExtractCatalogs(ctx context.Context, configurations providerconfig.Store, catalogs catalog.Store) (int, error) {
	if ctx == nil {
		return 0, errors.New("context is required")
	}
	if dependency.IsNil(configurations) || dependency.IsNil(catalogs) {
		return 0, errors.New("provider configuration and catalog stores are required")
	}
	instances, errInstances := configurations.ListInstances(ctx, bootstrap.TavilySearchDefinitionID)
	if errInstances != nil {
		return 0, fmt.Errorf("list Tavily instances for Extract reconciliation: %w", errInstances)
	}
	targetResolver, errResolver := resolve.New(configurations, catalogs)
	if errResolver != nil {
		return 0, errResolver
	}
	changedInstances := 0
	for _, instance := range instances {
		definition, errDefinition := configurations.GetDefinition(ctx, instance.DefinitionID)
		if errDefinition != nil {
			return changedInstances, fmt.Errorf("get Tavily definition %s: %w", instance.DefinitionID, errDefinition)
		}
		accessGraphChanged, errAccessGraph := reconcileTavilyExtractAccessGraph(ctx, configurations, instance, definition)
		if errAccessGraph != nil {
			return changedInstances, fmt.Errorf("reconcile Tavily Extract access graph %s: %w", instance.ID, errAccessGraph)
		}
		current, errCurrent := catalogs.Get(ctx, instance.ID)
		if errors.Is(errCurrent, catalog.ErrSnapshotNotFound) {
			if accessGraphChanged {
				changedInstances++
			}
			continue
		}
		if errCurrent != nil {
			return changedInstances, fmt.Errorf("get Tavily catalog %s: %w", instance.ID, errCurrent)
		}
		desired, errDesired := buildSystemCatalog(providerconfig.SystemOnboarding{Instance: instance}, definition, time.Now().UTC())
		if errDesired != nil {
			return changedInstances, fmt.Errorf("build Tavily catalog %s: %w", instance.ID, errDesired)
		}
		desiredService, desiredOffering, desiredProfile, desiredExists := tavilyExtractContract(desired)
		if !desiredExists {
			return changedInstances, errors.New("current Tavily definition omitted its Extract service contract")
		}
		currentService, currentOffering, currentProfile, currentExists := tavilyExtractContract(current)
		contractCurrent := currentExists && reflect.DeepEqual(currentService, desiredService) && reflect.DeepEqual(currentOffering, desiredOffering) && reflect.DeepEqual(currentProfile, desiredProfile)
		upgraded := current
		upgraded.Services = removeProviderService(upgraded.Services, desiredService.ID)
		upgraded.ServiceOfferings = removeServiceOffering(upgraded.ServiceOfferings, desiredOffering.ID)
		upgraded.Profiles = removeExecutionProfile(upgraded.Profiles, desiredProfile.ID)
		upgraded.Services = append(upgraded.Services, desiredService)
		upgraded.ServiceOfferings = append(upgraded.ServiceOfferings, desiredOffering)
		upgraded.Profiles = append(upgraded.Profiles, desiredProfile)
		probeObservedAt := time.Now().UTC()
		probePools, errProbePools := targetResolver.SummarizeSnapshot(ctx, upgraded, probeObservedAt, current.Revision)
		if errProbePools != nil {
			return changedInstances, fmt.Errorf("probe upgraded Tavily catalog %s: %w", instance.ID, errProbePools)
		}
		if contractCurrent && !accessGraphChanged && tavilyExtractPoolEquivalent(current.Pools, probePools) {
			continue
		}
		if current.Revision == math.MaxUint64 {
			return changedInstances, errors.New("Tavily catalog revision is exhausted")
		}
		upgraded.Revision++
		upgraded.ObservedAt = probeObservedAt
		pools, errPools := targetResolver.SummarizeSnapshot(ctx, upgraded, upgraded.ObservedAt, upgraded.Revision)
		if errPools != nil {
			return changedInstances, fmt.Errorf("summarize upgraded Tavily catalog %s: %w", instance.ID, errPools)
		}
		upgraded.Pools = pools
		if errValidate := upgraded.Validate(); errValidate != nil {
			return changedInstances, fmt.Errorf("validate upgraded Tavily catalog %s: %w", instance.ID, errValidate)
		}
		if errSave := catalogs.Save(ctx, upgraded); errSave != nil {
			return changedInstances, fmt.Errorf("save upgraded Tavily catalog %s: %w", instance.ID, errSave)
		}
		changedInstances++
	}
	return changedInstances, nil
}

// reconcileTavilyExtractAccessGraph adds one Extract-channel binding for every historical Search-channel binding that does not already own one.
// reconcileTavilyExtractAccessGraph 为每条尚未拥有提取通道的历史搜索通道 Binding 补建一条 Extract 通道 Binding。
func reconcileTavilyExtractAccessGraph(ctx context.Context, configurations providerconfig.Store, instance providerconfig.ProviderInstance, definition providerconfig.ProviderDefinition) (bool, error) {
	searchAction, errSearchAction := definitionActionForOperation(definition, vcp.OperationSearchWeb)
	if errSearchAction != nil {
		return false, errSearchAction
	}
	extractAction, errExtractAction := definitionActionForOperation(definition, vcp.OperationWebExtract)
	if errExtractAction != nil {
		return false, errExtractAction
	}
	if searchAction.ProtocolProfileID == extractAction.ProtocolProfileID {
		return false, nil
	}
	endpoints, errEndpoints := configurations.ListEndpoints(ctx, instance.ID)
	if errEndpoints != nil {
		return false, errEndpoints
	}
	bindings, errBindings := configurations.ListBindings(ctx, instance.ID)
	if errBindings != nil {
		return false, errBindings
	}
	// extractPaths records exact endpoint and credential pairs so an operator-disabled Extract path is preserved instead of duplicated.
	// extractPaths 记录精确的入口与凭据组合，避免重复创建操作员已禁用的 Extract 路径。
	extractPaths := make(map[string]struct{}, len(bindings))
	for _, binding := range bindings {
		if binding.ChannelID == extractAction.ProtocolProfileID {
			extractPaths[tavilyBindingPathKey(binding.EndpointID, binding.CredentialID)] = struct{}{}
		}
	}
	replacementBindings := append([]providerconfig.AccessBinding(nil), bindings...)
	for _, searchBinding := range bindings {
		if searchBinding.ChannelID != searchAction.ProtocolProfileID {
			continue
		}
		pathKey := tavilyBindingPathKey(searchBinding.EndpointID, searchBinding.CredentialID)
		if _, exists := extractPaths[pathKey]; exists {
			continue
		}
		allowedServices := append([]string(nil), searchBinding.AllowedServiceIDs...)
		if len(allowedServices) > 0 {
			searchAllowed := slices.Contains(allowedServices, tavilySearchServiceID)
			extractAllowed := slices.Contains(allowedServices, tavilyExtractServiceID)
			if !searchAllowed && !extractAllowed {
				continue
			}
			if !extractAllowed {
				allowedServices = append(allowedServices, tavilyExtractServiceID)
			}
		}
		bindingID, errBindingID := generateID("bind_")
		if errBindingID != nil {
			return false, errBindingID
		}
		extractBinding := searchBinding
		extractBinding.ID = bindingID
		extractBinding.ChannelID = extractAction.ProtocolProfileID
		extractBinding.AllowedServiceIDs = allowedServices
		extractBinding.Revision = 1
		replacementBindings = append(replacementBindings, extractBinding)
		extractPaths[pathKey] = struct{}{}
	}
	if len(replacementBindings) == len(bindings) {
		return false, nil
	}
	replacement := providerconfig.AccessGraphReplacement{
		ProviderInstanceID: instance.ID,
		ExpectedEndpoints:  endpoints,
		ExpectedBindings:   bindings,
		Endpoints:          endpoints,
		Bindings:           replacementBindings,
	}
	if errReplace := configurations.ReplaceAccessGraph(ctx, replacement); errReplace != nil {
		return false, errReplace
	}
	return true, nil
}

// tavilyBindingPathKey returns one collision-free key for an endpoint and credential pair.
// tavilyBindingPathKey 为入口与凭据组合返回一个无冲突键。
func tavilyBindingPathKey(endpointID string, credentialID string) string {
	return endpointID + "\x00" + credentialID
}

// tavilyExtractPoolEquivalent compares the authoritative Extract pool state while ignoring snapshot revision timestamps.
// tavilyExtractPoolEquivalent 比较权威的 Extract 池状态，同时忽略快照修订号与时间戳。
func tavilyExtractPoolEquivalent(current []catalog.PoolSummary, desired []catalog.PoolSummary) bool {
	currentPool, currentExists := executionProfilePool(current, "profile_tavily_extract")
	desiredPool, desiredExists := executionProfilePool(desired, "profile_tavily_extract")
	if currentExists != desiredExists {
		return false
	}
	if !currentExists {
		return true
	}
	resetEquivalent := currentPool.EarliestResetAt == nil && desiredPool.EarliestResetAt == nil
	if currentPool.EarliestResetAt != nil && desiredPool.EarliestResetAt != nil {
		resetEquivalent = currentPool.EarliestResetAt.Equal(*desiredPool.EarliestResetAt)
	}
	return currentPool.ProviderInstanceID == desiredPool.ProviderInstanceID &&
		currentPool.ExecutionProfileID == desiredPool.ExecutionProfileID &&
		currentPool.ConfiguredCredentials == desiredPool.ConfiguredCredentials &&
		currentPool.EntitledCredentials == desiredPool.EntitledCredentials &&
		currentPool.ReadyCredentials == desiredPool.ReadyCredentials &&
		currentPool.CoolingCredentials == desiredPool.CoolingCredentials &&
		currentPool.ExhaustedCredentials == desiredPool.ExhaustedCredentials &&
		currentPool.InvalidCredentials == desiredPool.InvalidCredentials &&
		slices.Equal(currentPool.BlockingAllowanceKinds, desiredPool.BlockingAllowanceKinds) &&
		resetEquivalent
}

// executionProfilePool returns the one pool owned by an execution profile identifier.
// executionProfilePool 返回指定执行规格标识拥有的唯一池。
func executionProfilePool(pools []catalog.PoolSummary, profileID string) (catalog.PoolSummary, bool) {
	for _, pool := range pools {
		if pool.ExecutionProfileID == profileID {
			return pool, true
		}
	}
	return catalog.PoolSummary{}, false
}

// tavilyExtractContract returns the exact service, offering, and profile that form one executable Extract contract.
// tavilyExtractContract 返回组成一个可执行 Extract 合同的精确服务、供应与规格。
func tavilyExtractContract(snapshot catalog.Snapshot) (catalog.ProviderService, catalog.ServiceOffering, catalog.ExecutionProfile, bool) {
	var service catalog.ProviderService
	var offering catalog.ServiceOffering
	var profile catalog.ExecutionProfile
	serviceFound := false
	offeringFound := false
	profileFound := false
	for _, candidate := range snapshot.Services {
		if candidate.ID == "service_web_extract" {
			service = candidate
			serviceFound = true
			break
		}
	}
	for _, candidate := range snapshot.ServiceOfferings {
		if candidate.ID == "service_offer_tavily_extract" {
			offering = candidate
			offeringFound = true
			break
		}
	}
	for _, candidate := range snapshot.Profiles {
		if candidate.ID == "profile_tavily_extract" {
			profile = candidate
			profileFound = true
			break
		}
	}
	return service, offering, profile, serviceFound && offeringFound && profileFound
}

// removeProviderService removes one exact code-owned service before inserting its current definition.
// removeProviderService 在插入当前定义前删除一个精确的代码拥有服务。
func removeProviderService(services []catalog.ProviderService, serviceID string) []catalog.ProviderService {
	filtered := make([]catalog.ProviderService, 0, len(services))
	for _, service := range services {
		if service.ID != serviceID {
			filtered = append(filtered, service)
		}
	}
	return filtered
}

// removeServiceOffering removes one exact code-owned service offering before inserting its current definition.
// removeServiceOffering 在插入当前定义前删除一个精确的代码拥有服务供应。
func removeServiceOffering(offerings []catalog.ServiceOffering, offeringID string) []catalog.ServiceOffering {
	filtered := make([]catalog.ServiceOffering, 0, len(offerings))
	for _, offering := range offerings {
		if offering.ID != offeringID {
			filtered = append(filtered, offering)
		}
	}
	return filtered
}

// removeExecutionProfile removes one exact code-owned execution profile before inserting its current definition.
// removeExecutionProfile 在插入当前定义前删除一个精确的代码拥有执行规格。
func removeExecutionProfile(profiles []catalog.ExecutionProfile, profileID string) []catalog.ExecutionProfile {
	filtered := make([]catalog.ExecutionProfile, 0, len(profiles))
	for _, profile := range profiles {
		if profile.ID != profileID {
			filtered = append(filtered, profile)
		}
	}
	return filtered
}

// reconcileKimiAccessGraph converges legacy Chat and Anthropic paths to one exact current Chat endpoint and one binding per associated credential.
// reconcileKimiAccessGraph 将旧 Chat 与 Anthropic 路径收敛为唯一精确当前 Chat 入口及每个已关联凭据的唯一 Binding。
func reconcileKimiAccessGraph(ctx context.Context, configurations providerconfig.Store, instance providerconfig.ProviderInstance, definition providerconfig.ProviderDefinition, credentials []providerconfig.Credential) (bool, error) {
	endpoints, errEndpoints := configurations.ListEndpoints(ctx, instance.ID)
	if errEndpoints != nil {
		return false, errEndpoints
	}
	bindings, errBindings := configurations.ListBindings(ctx, instance.ID)
	if errBindings != nil {
		return false, errBindings
	}
	currentChannelID := definition.ProtocolProfileID
	endpointCandidates := make([]providerconfig.Endpoint, 0)
	for _, endpoint := range endpoints {
		if endpoint.ChannelID == currentChannelID || endpoint.ChannelID == legacyKimiChatChannelID {
			endpointCandidates = append(endpointCandidates, endpoint)
		}
	}
	if len(endpointCandidates) == 0 {
		return false, nil
	}
	sort.Slice(endpointCandidates, func(left int, right int) bool {
		leftCurrent := endpointCandidates[left].ChannelID == currentChannelID
		rightCurrent := endpointCandidates[right].ChannelID == currentChannelID
		if leftCurrent != rightCurrent {
			return leftCurrent
		}
		return endpointCandidates[left].ID < endpointCandidates[right].ID
	})
	replacementEndpoint := endpointCandidates[0]
	if replacementEndpoint.ChannelID != currentChannelID {
		if replacementEndpoint.Revision == math.MaxUint64 {
			return false, errors.New("Kimi endpoint revision is exhausted")
		}
		replacementEndpoint.ChannelID = currentChannelID
		replacementEndpoint.Revision++
	}
	credentialByID := make(map[string]providerconfig.Credential, len(credentials))
	for _, credential := range credentials {
		credentialByID[credential.ID] = credential
	}
	bindingCandidates := make(map[string][]providerconfig.AccessBinding)
	for _, binding := range bindings {
		if _, exists := credentialByID[binding.CredentialID]; !exists || (binding.ChannelID != currentChannelID && binding.ChannelID != legacyKimiChatChannelID) {
			continue
		}
		bindingCandidates[binding.CredentialID] = append(bindingCandidates[binding.CredentialID], binding)
	}
	replacementBindings := make([]providerconfig.AccessBinding, 0, len(bindingCandidates))
	for credentialID, candidates := range bindingCandidates {
		sort.Slice(candidates, func(left int, right int) bool {
			leftCurrent := candidates[left].ChannelID == currentChannelID
			rightCurrent := candidates[right].ChannelID == currentChannelID
			if leftCurrent != rightCurrent {
				return leftCurrent
			}
			if candidates[left].Priority != candidates[right].Priority {
				return candidates[left].Priority < candidates[right].Priority
			}
			return candidates[left].ID < candidates[right].ID
		})
		replacementBinding := candidates[0]
		if replacementBinding.ChannelID != currentChannelID || replacementBinding.EndpointID != replacementEndpoint.ID {
			if replacementBinding.Revision == math.MaxUint64 {
				return false, fmt.Errorf("Kimi binding revision is exhausted for credential %s", credentialID)
			}
			replacementBinding.ChannelID = currentChannelID
			replacementBinding.EndpointID = replacementEndpoint.ID
			replacementBinding.Revision++
		}
		replacementBindings = append(replacementBindings, replacementBinding)
	}
	sort.Slice(replacementBindings, func(left int, right int) bool { return replacementBindings[left].ID < replacementBindings[right].ID })
	replacementEndpoints := []providerconfig.Endpoint{replacementEndpoint}
	if accessGraphEquivalent(endpoints, bindings, replacementEndpoints, replacementBindings) {
		return false, nil
	}
	replacement := providerconfig.AccessGraphReplacement{
		ProviderInstanceID: instance.ID,
		ExpectedEndpoints:  endpoints,
		ExpectedBindings:   bindings,
		Endpoints:          replacementEndpoints,
		Bindings:           replacementBindings,
	}
	if errReplace := configurations.ReplaceAccessGraph(ctx, replacement); errReplace != nil {
		return false, errReplace
	}
	return true, nil
}

// accessGraphEquivalent compares complete graph values without relying on persistence ordering.
// accessGraphEquivalent 比较完整图值且不依赖持久化顺序。
func accessGraphEquivalent(leftEndpoints []providerconfig.Endpoint, leftBindings []providerconfig.AccessBinding, rightEndpoints []providerconfig.Endpoint, rightBindings []providerconfig.AccessBinding) bool {
	leftEndpoints = append([]providerconfig.Endpoint(nil), leftEndpoints...)
	rightEndpoints = append([]providerconfig.Endpoint(nil), rightEndpoints...)
	leftBindings = append([]providerconfig.AccessBinding(nil), leftBindings...)
	rightBindings = append([]providerconfig.AccessBinding(nil), rightBindings...)
	sort.Slice(leftEndpoints, func(left int, right int) bool { return leftEndpoints[left].ID < leftEndpoints[right].ID })
	sort.Slice(rightEndpoints, func(left int, right int) bool { return rightEndpoints[left].ID < rightEndpoints[right].ID })
	sort.Slice(leftBindings, func(left int, right int) bool { return leftBindings[left].ID < leftBindings[right].ID })
	sort.Slice(rightBindings, func(left int, right int) bool { return rightBindings[left].ID < rightBindings[right].ID })
	return reflect.DeepEqual(leftEndpoints, rightEndpoints) && reflect.DeepEqual(leftBindings, rightBindings)
}

// ReconcileCodexUnknownPlanEntitlements removes historical privilege-bearing entitlements from missing, expired, or unknown Codex plans.
// ReconcileCodexUnknownPlanEntitlements 删除历史上由缺失、过期或未知 Codex 套餐持有的提权权益。
func ReconcileCodexUnknownPlanEntitlements(ctx context.Context, configurations providerconfig.Store, catalogs catalog.Store) (int, error) {
	if ctx == nil {
		return 0, errors.New("context is required")
	}
	if dependency.IsNil(configurations) || dependency.IsNil(catalogs) {
		return 0, errors.New("provider configuration and catalog stores are required")
	}
	instances, errInstances := configurations.ListInstances(ctx, bootstrap.OpenAICodexDefinitionID)
	if errInstances != nil {
		return 0, errInstances
	}
	targetResolver, errResolver := resolve.New(configurations, catalogs)
	if errResolver != nil {
		return 0, errResolver
	}
	now := time.Now().UTC()
	changedInstances := 0
	for _, instance := range instances {
		current, errCurrent := catalogs.Get(ctx, instance.ID)
		if errors.Is(errCurrent, catalog.ErrSnapshotNotFound) {
			continue
		}
		if errCurrent != nil {
			return changedInstances, errCurrent
		}
		credentials, errCredentials := configurations.ListCredentials(ctx, instance.ID)
		if errCredentials != nil {
			return changedInstances, errCredentials
		}
		knownPlanCredentials := make(map[string]struct{}, len(current.Plans))
		for _, plan := range current.Plans {
			if provideropenai.CodexPlanKnown(plan.PlanCode) && catalogMetadataCurrent(plan.ObservedAt, plan.ExpiresAt, now) {
				knownPlanCredentials[plan.CredentialID] = struct{}{}
			}
		}
		unknownCredentials := make(map[string]struct{}, len(credentials))
		for _, credential := range credentials {
			if _, known := knownPlanCredentials[credential.ID]; !known {
				unknownCredentials[credential.ID] = struct{}{}
			}
		}
		filtered := make([]catalog.ModelEntitlement, 0, len(current.Entitlements))
		for _, entitlement := range current.Entitlements {
			if _, unknown := unknownCredentials[entitlement.CredentialID]; unknown {
				continue
			}
			filtered = append(filtered, entitlement)
		}
		if len(filtered) == len(current.Entitlements) {
			continue
		}
		if current.Revision == math.MaxUint64 {
			return changedInstances, errors.New("Codex catalog revision is exhausted")
		}
		current.Entitlements = filtered
		current.Revision++
		current.ObservedAt = now
		pools, errPools := targetResolver.SummarizeSnapshot(ctx, current, now, current.Revision)
		if errPools != nil {
			return changedInstances, errPools
		}
		current.Pools = pools
		if errSave := catalogs.Save(ctx, current); errSave != nil {
			return changedInstances, errSave
		}
		changedInstances++
	}
	return changedInstances, nil
}

// rebuildKimiSystemCatalog converges historical model, profile, and API-key entitlement data to the current code-owned template.
// rebuildKimiSystemCatalog 将历史模型、规格与 API Key 权益数据收敛到当前代码拥有模板。
func rebuildKimiSystemCatalog(ctx context.Context, configurations providerconfig.Store, catalogs catalog.Store, instance providerconfig.ProviderInstance, definition providerconfig.ProviderDefinition, credentials []providerconfig.Credential, current catalog.Snapshot, now time.Time, force bool) (catalog.Snapshot, bool, error) {
	desired, errDesired := buildSystemCatalog(providerconfig.SystemOnboarding{Instance: instance}, definition, now)
	if errDesired != nil {
		return catalog.Snapshot{}, false, errDesired
	}
	credentialByID := make(map[string]providerconfig.Credential, len(credentials))
	for _, credential := range credentials {
		credentialByID[credential.ID] = credential
		if credential.AuthMethodID == "api_key" && credential.DeclaredPlan != nil && definition.ID == bootstrap.KimiCodingDefinitionID {
			var errApply error
			desired, errApply = providerkimi.ApplyDeclaredMembership(desired, credential)
			if errApply != nil {
				return catalog.Snapshot{}, false, errApply
			}
		}
	}
	if definition.ID == bootstrap.KimiCodingDefinitionID {
		preserveDetectedKimiMetadata(&desired, current, credentialByID, now)
	}
	if current.Revision == math.MaxUint64 {
		return catalog.Snapshot{}, false, errors.New("Kimi catalog revision is exhausted")
	}
	targetResolver, errResolver := resolve.New(configurations, catalogs)
	if errResolver != nil {
		return catalog.Snapshot{}, false, errResolver
	}
	desiredRevision := current.Revision + 1
	pools, errPools := targetResolver.SummarizeSnapshot(ctx, desired, now, desiredRevision)
	if errPools != nil {
		return catalog.Snapshot{}, false, errPools
	}
	desired.Pools = pools
	if !force && kimiCatalogEquivalent(current, desired) {
		return current, false, nil
	}
	desired.Revision = desiredRevision
	desired.ObservedAt = now
	if errValidate := desired.Validate(); errValidate != nil {
		return catalog.Snapshot{}, false, errValidate
	}
	return desired, true, nil
}

// preserveDetectedKimiMetadata retains only current device-flow evidence that still references the rebuilt catalog.
// preserveDetectedKimiMetadata 仅保留仍引用重建目录的当前设备授权证据。
func preserveDetectedKimiMetadata(desired *catalog.Snapshot, current catalog.Snapshot, credentials map[string]providerconfig.Credential, now time.Time) {
	modelIDs := make(map[string]struct{}, len(desired.Models))
	profileIDs := make(map[string]struct{}, len(desired.Profiles))
	for _, model := range desired.Models {
		modelIDs[model.ID] = struct{}{}
	}
	for _, profile := range desired.Profiles {
		profileIDs[profile.ID] = struct{}{}
	}
	for _, plan := range current.Plans {
		credential, exists := credentials[plan.CredentialID]
		if exists && credential.AuthMethodID == "device_flow" && catalogMetadataCurrent(plan.ObservedAt, plan.ExpiresAt, now) {
			desired.Plans = append(desired.Plans, plan)
		}
	}
	for _, entitlement := range current.Entitlements {
		credential, exists := credentials[entitlement.CredentialID]
		_, modelExists := modelIDs[entitlement.ProviderModelID]
		if !exists || credential.AuthMethodID != "device_flow" || !modelExists || !catalogMetadataCurrent(entitlement.ObservedAt, entitlement.ExpiresAt, now) || !allStringsExist(entitlement.AllowedProfileIDs, profileIDs) {
			continue
		}
		desired.Entitlements = append(desired.Entitlements, entitlement)
	}
	for _, allowance := range current.Allowances {
		if !catalogMetadataCurrent(allowance.ObservedAt, allowance.ExpiresAt, now) {
			continue
		}
		credential, directlyOwned := credentials[allowance.ScopeID]
		if allowance.Scope == catalog.ScopeCredential && directlyOwned && credential.AuthMethodID == "device_flow" {
			desired.Allowances = append(desired.Allowances, allowance)
			continue
		}
		if allowance.Scope == catalog.ScopeExecutionProfile {
			if _, exists := profileIDs[allowance.ScopeID]; exists {
				desired.Allowances = append(desired.Allowances, allowance)
			}
		}
	}
}

// allStringsExist reports whether every non-empty profile reference exists in the current template.
// allStringsExist 表示每个非空 Profile 引用是否都存在于当前模板。
func allStringsExist(values []string, existing map[string]struct{}) bool {
	for _, value := range values {
		if _, exists := existing[value]; !exists {
			return false
		}
	}
	return true
}

// catalogMetadataCurrent reports whether one persisted provider or operator observation remains usable.
// catalogMetadataCurrent 表示一个已持久化供应商或操作员观测是否仍可用。
func catalogMetadataCurrent(observedAt time.Time, expiresAt time.Time, now time.Time) bool {
	return !observedAt.IsZero() && !observedAt.After(now) && (expiresAt.IsZero() || expiresAt.After(now))
}

// kimiCatalogEquivalent compares semantic catalog and derived pool data while ignoring persistence counters and observation time.
// kimiCatalogEquivalent 比较语义目录与派生账号池数据，同时忽略持久化计数器与观测时间。
func kimiCatalogEquivalent(current catalog.Snapshot, desired catalog.Snapshot) bool {
	return reflect.DeepEqual(normalizedKimiCatalog(current), normalizedKimiCatalog(desired))
}

// normalizedKimiCatalog removes non-semantic persistence counters from one comparison copy.
// normalizedKimiCatalog 从一个比较副本移除非语义持久化计数。
func normalizedKimiCatalog(snapshot catalog.Snapshot) catalog.Snapshot {
	snapshot.Models = append([]catalog.ProviderModel(nil), snapshot.Models...)
	snapshot.Offerings = append([]catalog.ModelOffering(nil), snapshot.Offerings...)
	snapshot.Profiles = append([]catalog.ExecutionProfile(nil), snapshot.Profiles...)
	snapshot.Plans = append([]catalog.PlanSnapshot(nil), snapshot.Plans...)
	snapshot.Entitlements = append([]catalog.ModelEntitlement(nil), snapshot.Entitlements...)
	snapshot.Allowances = append([]catalog.AllowanceSnapshot(nil), snapshot.Allowances...)
	snapshot.Pools = append([]catalog.PoolSummary(nil), snapshot.Pools...)
	snapshot.Revision = 0
	snapshot.ObservedAt = time.Time{}
	for index := range snapshot.Models {
		snapshot.Models[index].Revision = 0
	}
	for index := range snapshot.Offerings {
		snapshot.Offerings[index].Revision = 0
		snapshot.Offerings[index].CapabilityRevision = 0
	}
	for index := range snapshot.Profiles {
		snapshot.Profiles[index].Revision = 0
		snapshot.Profiles[index].CapabilityRevision = 0
	}
	for index := range snapshot.Plans {
		snapshot.Plans[index].Revision = 0
	}
	for index := range snapshot.Entitlements {
		snapshot.Entitlements[index].Revision = 0
	}
	for index := range snapshot.Allowances {
		snapshot.Allowances[index].Revision = 0
	}
	for index := range snapshot.Pools {
		snapshot.Pools[index].Revision = 0
		snapshot.Pools[index].ObservedAt = time.Time{}
		if len(snapshot.Pools[index].BlockingAllowanceKinds) == 0 {
			snapshot.Pools[index].BlockingAllowanceKinds = nil
		}
	}
	return snapshot
}

// isKimiSystemDefinition reports whether one immutable definition belongs to the three built-in Kimi products.
// isKimiSystemDefinition 判断一个不可变定义是否属于三个内置 Kimi 产品之一。
func isKimiSystemDefinition(definitionID string) bool {
	switch definitionID {
	case bootstrap.KimiCNDefinitionID, bootstrap.KimiGlobalDefinitionID, bootstrap.KimiCodingDefinitionID:
		return true
	default:
		return false
	}
}

// migrateKimiCatalogToChat removes non-Chat products while preserving account metadata that still references the retained Chat profiles.
// migrateKimiCatalogToChat 删除非 Chat 产品，同时保留仍引用保留 Chat Profile 的账号元数据。
func migrateKimiCatalogToChat(current catalog.Snapshot, action providerconfig.ProviderActionBinding) (catalog.Snapshot, bool, error) {
	if action.Operation != vcp.OperationConversationRespond || action.ProtocolProfileID == "" {
		return catalog.Snapshot{}, false, errors.New("Kimi migration requires one concrete Chat conversation action")
	}
	retainedModelIDs := make(map[string]struct{})
	staleOfferingIDs := make(map[string]struct{})
	for _, offering := range current.Offerings {
		if offering.ChannelID == action.ProtocolProfileID || offering.ChannelID == legacyKimiChatChannelID {
			retainedModelIDs[offering.ProviderModelID] = struct{}{}
			continue
		}
		staleOfferingIDs[offering.ID] = struct{}{}
	}
	for _, offering := range current.Offerings {
		if _, stale := staleOfferingIDs[offering.ID]; !stale {
			continue
		}
		if _, retained := retainedModelIDs[offering.ProviderModelID]; !retained {
			return catalog.Snapshot{}, false, fmt.Errorf("model %s has no retained Chat offering", offering.ProviderModelID)
		}
	}
	migrated := current
	migrated.Offerings = make([]catalog.ModelOffering, 0, len(current.Offerings)-len(staleOfferingIDs))
	changed := len(staleOfferingIDs) > 0
	expectedDelivery := catalog.DeliveryCapabilities{Synchronous: action.Delivery.Synchronous, Streaming: action.Delivery.Streaming, Asynchronous: action.Delivery.Asynchronous}
	for _, offering := range current.Offerings {
		if _, stale := staleOfferingIDs[offering.ID]; stale {
			continue
		}
		offeringChanged := false
		if offering.ChannelID == legacyKimiChatChannelID {
			offering.ChannelID = action.ProtocolProfileID
			offeringChanged = true
		}
		if offering.Capabilities.Delivery != expectedDelivery {
			offering.Capabilities.Delivery = expectedDelivery
			offering.CapabilityRevision = incrementCatalogRevision(offering.CapabilityRevision)
			offeringChanged = true
		}
		if offeringChanged {
			offering.Revision = incrementCatalogRevision(offering.Revision)
			changed = true
		}
		migrated.Offerings = append(migrated.Offerings, offering)
	}
	retainedProfileIDs := make(map[string]struct{})
	staleProfileIDs := make(map[string]struct{})
	migrated.Profiles = make([]catalog.ExecutionProfile, 0, len(current.Profiles))
	for _, profile := range current.Profiles {
		if _, stale := staleOfferingIDs[profile.OfferingID]; stale {
			staleProfileIDs[profile.ID] = struct{}{}
			changed = true
			continue
		}
		if profile.OfferingID != "" {
			retainedProfileIDs[profile.ID] = struct{}{}
			profileChanged := false
			if profile.Operation != action.Operation || profile.ActionBindingID != action.ID {
				profile.Operation = action.Operation
				profile.ActionBindingID = action.ID
				profileChanged = true
			}
			if profile.Capabilities.Delivery != expectedDelivery {
				profile.Capabilities.Delivery = expectedDelivery
				profile.CapabilityRevision = incrementCatalogRevision(profile.CapabilityRevision)
				profileChanged = true
			}
			if profileChanged {
				profile.Revision = incrementCatalogRevision(profile.Revision)
				changed = true
			}
		}
		migrated.Profiles = append(migrated.Profiles, profile)
	}
	migrated.Entitlements = make([]catalog.ModelEntitlement, 0, len(current.Entitlements))
	for _, entitlement := range current.Entitlements {
		if len(entitlement.AllowedProfileIDs) == 0 {
			migrated.Entitlements = append(migrated.Entitlements, entitlement)
			continue
		}
		allowedProfileIDs := make([]string, 0, len(entitlement.AllowedProfileIDs))
		for _, profileID := range entitlement.AllowedProfileIDs {
			if _, retained := retainedProfileIDs[profileID]; retained {
				allowedProfileIDs = append(allowedProfileIDs, profileID)
			}
		}
		if len(allowedProfileIDs) == 0 {
			changed = true
			continue
		}
		if len(allowedProfileIDs) != len(entitlement.AllowedProfileIDs) {
			entitlement.AllowedProfileIDs = allowedProfileIDs
			entitlement.Revision = incrementCatalogRevision(entitlement.Revision)
			changed = true
		}
		migrated.Entitlements = append(migrated.Entitlements, entitlement)
	}
	migrated.Allowances = make([]catalog.AllowanceSnapshot, 0, len(current.Allowances))
	for _, allowance := range current.Allowances {
		if allowance.Scope == catalog.ScopeExecutionProfile {
			if _, stale := staleProfileIDs[allowance.ScopeID]; stale {
				changed = true
				continue
			}
		}
		migrated.Allowances = append(migrated.Allowances, allowance)
	}
	migrated.Pools = make([]catalog.PoolSummary, 0, len(current.Pools))
	for _, pool := range current.Pools {
		if _, stale := staleProfileIDs[pool.ExecutionProfileID]; stale {
			changed = true
			continue
		}
		migrated.Pools = append(migrated.Pools, pool)
	}
	if !changed {
		return current, false, nil
	}
	if current.Revision == math.MaxUint64 {
		return catalog.Snapshot{}, false, errors.New("Kimi catalog revision is exhausted")
	}
	migrated.Revision = current.Revision + 1
	if errValidate := migrated.Validate(); errValidate != nil {
		return catalog.Snapshot{}, false, errValidate
	}
	return migrated, true, nil
}

// incrementCatalogRevision advances a record revision while leaving exhaustion to snapshot validation as an explicit invalid state.
// incrementCatalogRevision 推进记录修订号，并将耗尽状态作为显式无效状态交由快照校验处理。
func incrementCatalogRevision(revision uint64) uint64 {
	if revision == math.MaxUint64 {
		return 0
	}
	return revision + 1
}
