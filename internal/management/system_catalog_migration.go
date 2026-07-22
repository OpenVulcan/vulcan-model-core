package management

import (
	"context"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/bootstrap"
	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/dependency"
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
)

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
