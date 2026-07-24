package management

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/bootstrap"
	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	providerkimi "github.com/OpenVulcan/vulcan-model-core/internal/provider/kimi"
	providertavily "github.com/OpenVulcan/vulcan-model-core/internal/provider/tavily"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// alibabaLegacyAccessStore captures one exact legacy access graph replacement while delegating unrelated store methods.
// alibabaLegacyAccessStore 捕获一次精确的历史访问图替换，并将无关存储方法委托给底层实现。
type alibabaLegacyAccessStore struct {
	providerconfig.Store
	// endpoints contain the exact historical endpoint records returned to reconciliation.
	// endpoints 包含返回给收敛逻辑的精确历史入口记录。
	endpoints []providerconfig.Endpoint
	// bindings contain the exact historical binding records returned to reconciliation.
	// bindings 包含返回给收敛逻辑的精确历史 Binding 记录。
	bindings []providerconfig.AccessBinding
	// replacement captures the atomic graph requested by reconciliation.
	// replacement 捕获收敛逻辑请求的原子访问图。
	replacement *providerconfig.AccessGraphReplacement
}

// ListEndpoints returns the exact historical endpoint fixture.
// ListEndpoints 返回精确的历史入口夹具。
func (s *alibabaLegacyAccessStore) ListEndpoints(context.Context, string) ([]providerconfig.Endpoint, error) {
	return append([]providerconfig.Endpoint(nil), s.endpoints...), nil
}

// ListBindings returns the exact historical binding fixture.
// ListBindings 返回精确的历史 Binding 夹具。
func (s *alibabaLegacyAccessStore) ListBindings(context.Context, string) ([]providerconfig.AccessBinding, error) {
	return append([]providerconfig.AccessBinding(nil), s.bindings...), nil
}

// ReplaceAccessGraph captures the compare-and-swap request for exact assertions.
// ReplaceAccessGraph 捕获用于精确断言的比较交换请求。
func (s *alibabaLegacyAccessStore) ReplaceAccessGraph(_ context.Context, replacement providerconfig.AccessGraphReplacement) error {
	s.replacement = &replacement
	return nil
}

// TestReconcileAlibabaAccessGraphMigratesLegacyAnthropicAndAddsNativeActions verifies pre-Chat instances become executable without replacing their credential.
// TestReconcileAlibabaAccessGraphMigratesLegacyAnthropicAndAddsNativeActions 验证旧 Anthropic 实例无需更换凭据即可转为可执行并补齐原生操作。
func TestReconcileAlibabaAccessGraphMigratesLegacyAnthropicAndAddsNativeActions(t *testing.T) {
	ctx := context.Background()
	_, configurations, _ := newKimiOnboardingService(t)
	definition, errDefinition := configurations.GetDefinition(ctx, bootstrap.AlibabaTokenPlanPersonalCNDefinitionID)
	if errDefinition != nil {
		t.Fatalf("get Alibaba definition: %v", errDefinition)
	}
	instance := providerconfig.ProviderInstance{ID: "pvi_alibaba_legacy_access", DefinitionID: definition.ID}
	legacyEndpoint := providerconfig.Endpoint{
		ID: "ep_alibaba_legacy_access", ProviderInstanceID: instance.ID, ChannelID: "anthropic.messages",
		BaseURL: "https://token-plan.cn-beijing.maas.aliyuncs.com/apps/anthropic/v1", Region: "CN",
		Status: providerconfig.EndpointReady, Revision: 1,
	}
	legacyBinding := providerconfig.AccessBinding{
		ID: "bind_alibaba_legacy_access", ProviderInstanceID: instance.ID, ChannelID: "anthropic.messages",
		EndpointID: legacyEndpoint.ID, CredentialID: "cred_alibaba_legacy_access", Priority: 17, Enabled: true, Revision: 1,
	}
	store := &alibabaLegacyAccessStore{Store: configurations, endpoints: []providerconfig.Endpoint{legacyEndpoint}, bindings: []providerconfig.AccessBinding{legacyBinding}}
	changed, errReconcile := reconcileAlibabaAccessGraph(ctx, store, instance, definition)
	if errReconcile != nil || !changed {
		t.Fatalf("reconcileAlibabaAccessGraph() changed=%t error=%v", changed, errReconcile)
	}
	if store.replacement == nil || len(store.replacement.Endpoints) != 1 || len(store.replacement.Bindings) != len(definition.ChannelIDs()) {
		t.Fatalf("replacement = %#v", store.replacement)
	}
	endpoint := store.replacement.Endpoints[0]
	if endpoint.ChannelID != definition.ProtocolProfileID || endpoint.BaseURL != definition.EndpointPresets[0].BaseURL || endpoint.Region != definition.EndpointPresets[0].Region || endpoint.Revision != 2 {
		t.Fatalf("migrated endpoint = %#v", endpoint)
	}
	channels := make(map[string]providerconfig.AccessBinding, len(store.replacement.Bindings))
	for _, binding := range store.replacement.Bindings {
		channels[binding.ChannelID] = binding
	}
	for _, channelID := range definition.ChannelIDs() {
		binding, exists := channels[channelID]
		if !exists || binding.EndpointID != legacyEndpoint.ID || binding.CredentialID != legacyBinding.CredentialID || binding.Priority != legacyBinding.Priority || !binding.Enabled {
			t.Fatalf("channel %q binding = %#v, exists=%t", channelID, binding, exists)
		}
	}
	if channels[definition.ProtocolProfileID].ID != legacyBinding.ID || channels[definition.ProtocolProfileID].Revision != 2 {
		t.Fatalf("migrated primary binding = %#v", channels[definition.ProtocolProfileID])
	}
}

// TestReconcileAlibabaSystemCatalogsRestoresCompleteBaselinePreservesStateAndIsIdempotent verifies the startup migration's complete data boundary.
// TestReconcileAlibabaSystemCatalogsRestoresCompleteBaselinePreservesStateAndIsIdempotent 验证启动迁移的完整数据边界。
func TestReconcileAlibabaSystemCatalogsRestoresCompleteBaselinePreservesStateAndIsIdempotent(t *testing.T) {
	ctx := context.Background()
	service, configurations, _ := newKimiOnboardingService(t)
	onboarding, errOnboard := service.OnboardSystemProvider(ctx, OnboardSystemProviderInput{
		DefinitionID:    bootstrap.AlibabaModelStudioCNDefinitionID,
		Handle:          "legacy-alibaba-model-studio",
		DisplayName:     "Legacy Alibaba Model Studio",
		AuthMethodID:    "api_key",
		CredentialLabel: "Alibaba Primary",
		Secret:          []byte("test-alibaba-key"),
	})
	if errOnboard != nil {
		t.Fatalf("onboard Alibaba provider: %v", errOnboard)
	}
	instanceBefore, errInstance := configurations.GetInstance(ctx, onboarding.Instance.ID)
	endpointsBefore, errEndpoints := configurations.ListEndpoints(ctx, onboarding.Instance.ID)
	credentialsBefore, errCredentials := configurations.ListCredentials(ctx, onboarding.Instance.ID)
	bindingsBefore, errBindings := configurations.ListBindings(ctx, onboarding.Instance.ID)
	if errInstance != nil || errEndpoints != nil || errCredentials != nil || errBindings != nil {
		t.Fatalf("read Alibaba access graph instance=%v endpoints=%v credentials=%v bindings=%v", errInstance, errEndpoints, errCredentials, errBindings)
	}
	current, errCurrent := service.catalogs.Get(ctx, onboarding.Instance.ID)
	if errCurrent != nil {
		t.Fatalf("get current Alibaba catalog: %v", errCurrent)
	}
	completeModelCount := len(current.Models)
	if completeModelCount < 2 || len(current.Profiles) == 0 {
		t.Fatalf("complete Alibaba fixture is unexpectedly small: models=%d profiles=%d", completeModelCount, len(current.Profiles))
	}
	// retainedProfile is one executable model profile used to prove that current account observations survive the rebuild.
	// retainedProfile 是一个可执行模型规格，用于证明当前账号观测会在重建后保留。
	retainedProfile := current.Profiles[0]
	if retainedProfile.OfferingID == "" {
		t.Fatalf("first Alibaba profile is not model-backed: %#v", retainedProfile)
	}
	retainedModelID := ""
	for _, offering := range current.Offerings {
		if offering.ID == retainedProfile.OfferingID {
			retainedModelID = offering.ProviderModelID
			break
		}
	}
	if retainedModelID == "" {
		t.Fatalf("retained Alibaba profile references no offering: %#v", retainedProfile)
	}
	// A persisted disabled-model decision proves the catalog migration never rewrites instance-level operator policy.
	// 持久化的禁用模型决策用于证明目录迁移绝不会改写实例级操作员策略。
	instanceBefore.DisabledModelIDs = []string{retainedModelID}
	instanceBefore.Revision++
	instanceBefore.UpdatedAt = time.Now().UTC()
	if errSaveInstance := configurations.SaveInstance(ctx, instanceBefore); errSaveInstance != nil {
		t.Fatalf("save Alibaba disabled-model policy: %v", errSaveInstance)
	}
	instanceBefore, errInstance = configurations.GetInstance(ctx, onboarding.Instance.ID)
	if errInstance != nil {
		t.Fatalf("reload Alibaba instance policy: %v", errInstance)
	}
	// removedModelID creates an internally valid but incomplete historical baseline with all dependent records removed together.
	// removedModelID 通过同步删除全部依赖记录创建一份内部有效但不完整的历史基线。
	removedModelID := current.Models[len(current.Models)-1].ID
	current.Models = filterAlibabaModelsForMigrationTest(current.Models, removedModelID)
	current.Offerings, current.ModelOperationPolicies, current.Profiles, current.RateLimits = filterAlibabaModelGraphForMigrationTest(current, removedModelID)
	current.Pools = nil
	observedAt := time.Now().UTC()
	expiresAt := observedAt.Add(time.Hour)
	remainingCredits := "42"
	current.DefaultAdditionalParameters = catalog.AdditionalPayloadProjection{Filter: []string{"metadata.debug"}}
	current.Plans = []catalog.PlanSnapshot{{
		ID: "plan_alibaba_api", ProviderInstanceID: onboarding.Instance.ID, CredentialID: onboarding.Credential.ID,
		PlanCode: "api_key", PlanName: "API Key", Status: "active", EvidenceSource: catalog.MetadataEvidenceProviderAPI,
		ObservedAt: observedAt, ExpiresAt: expiresAt, Revision: 3,
	}}
	current.Entitlements = []catalog.ModelEntitlement{{
		ID: "ent_alibaba_retained", ProviderInstanceID: onboarding.Instance.ID, CredentialID: onboarding.Credential.ID, ProviderModelID: retainedModelID,
		Availability: catalog.AvailabilityAllowed, EntitlementClass: "api_key_models_endpoint", AllowedProfileIDs: []string{retainedProfile.ID}, Source: catalog.ModelSourceProviderAPI,
		EvidenceSource: catalog.MetadataEvidenceProviderAPI, ObservedAt: observedAt, ExpiresAt: expiresAt, Revision: 4,
	}}
	current.Allowances = []catalog.AllowanceSnapshot{{
		ID: "allow_alibaba_retained", ProviderInstanceID: onboarding.Instance.ID, Kind: catalog.AllowanceBalance, Scope: catalog.ScopeCredential, ScopeID: onboarding.Credential.ID,
		Metric: "api_credits", Unit: catalog.UnitProviderCredits, Remaining: &remainingCredits, Status: catalog.AllowanceAvailable, Source: catalog.ModelSourceProviderAPI,
		EvidenceSource: catalog.MetadataEvidenceProviderAPI, ObservedAt: observedAt, ExpiresAt: expiresAt, Revision: 5,
	}}
	current.Voices = []catalog.VoiceSnapshot{{
		ID: "voice_alibaba_retained", ProviderInstanceID: onboarding.Instance.ID, CredentialID: onboarding.Credential.ID, VoiceID: "voice-provider-id", DisplayName: "Provider Voice",
		Descriptions: []string{"warm"}, Source: catalog.ModelSourceProviderAPI, ObservedAt: observedAt, ExpiresAt: expiresAt, Revision: 6,
	}}
	for _, profile := range current.Profiles {
		if profile.ServiceOfferingID == "" {
			continue
		}
		for _, offering := range current.ServiceOfferings {
			if offering.ID == profile.ServiceOfferingID {
				current.ServiceEntitlements = []catalog.ServiceEntitlement{{
					ID: "service_ent_alibaba_retained", ProviderInstanceID: onboarding.Instance.ID, CredentialID: onboarding.Credential.ID, ProviderServiceID: offering.ProviderServiceID,
					Availability: catalog.AvailabilityAllowed, AllowedProfileIDs: []string{profile.ID}, Source: catalog.ModelSourceProviderAPI,
					EvidenceSource: catalog.MetadataEvidenceProviderAPI, ObservedAt: observedAt, ExpiresAt: expiresAt, Revision: 7,
				}}
				break
			}
		}
		if len(current.ServiceEntitlements) > 0 {
			break
		}
	}
	if len(current.ServiceEntitlements) != 1 {
		t.Fatal("Alibaba Model Studio fixture omitted its service profile")
	}
	current.Dynamic = &catalog.DynamicCatalogMetadata{Authority: catalog.CatalogAuthorityProvider, SourceRevision: "legacy-models-revision", ETag: "legacy-etag", RefreshedAt: observedAt, ExpiresAt: expiresAt, Status: catalog.CatalogRefreshFresh}
	current.Revision++
	current.ObservedAt = observedAt
	if errValidate := current.Validate(); errValidate != nil {
		t.Fatalf("validate incomplete Alibaba fixture: %v", errValidate)
	}
	if errSave := service.catalogs.Save(ctx, current); errSave != nil {
		t.Fatalf("save incomplete Alibaba catalog: %v", errSave)
	}
	changed, errReconcile := ReconcileAlibabaSystemCatalogs(ctx, configurations, service.catalogs)
	if errReconcile != nil || changed != 1 {
		t.Fatalf("reconcile Alibaba catalogs changed=%d error=%v", changed, errReconcile)
	}
	upgraded, errUpgraded := service.catalogs.Get(ctx, onboarding.Instance.ID)
	if errUpgraded != nil {
		t.Fatalf("get upgraded Alibaba catalog: %v", errUpgraded)
	}
	if len(upgraded.Models) != completeModelCount || len(upgraded.ModelOperationPolicies) == 0 {
		t.Fatalf("upgraded Alibaba baseline models=%d/%d policies=%d", len(upgraded.Models), completeModelCount, len(upgraded.ModelOperationPolicies))
	}
	for _, policy := range upgraded.ModelOperationPolicies {
		if policy.Status == catalog.ModelOperationPendingReview {
			t.Fatalf("upgraded Alibaba policy remains pending: %#v", policy)
		}
	}
	if !reflect.DeepEqual(upgraded.DefaultAdditionalParameters, current.DefaultAdditionalParameters) || !reflect.DeepEqual(upgraded.Plans, current.Plans) || !reflect.DeepEqual(upgraded.Allowances, current.Allowances) || !reflect.DeepEqual(upgraded.Voices, current.Voices) {
		t.Fatal("Alibaba migration discarded valid operator or account metadata")
	}
	if len(upgraded.Entitlements) != 0 || len(upgraded.ServiceEntitlements) != 0 {
		t.Fatalf("Alibaba migration retained historical dynamic entitlements models=%#v services=%#v", upgraded.Entitlements, upgraded.ServiceEntitlements)
	}
	if upgraded.Dynamic != nil {
		t.Fatalf("Alibaba migration retained stale dynamic provenance: %#v", upgraded.Dynamic)
	}
	readyProfiles := 0
	for _, pool := range upgraded.Pools {
		if pool.ReadyCredentials > 0 {
			readyProfiles++
		}
	}
	if readyProfiles == 0 {
		t.Fatal("upgraded Alibaba catalog has no executable credential pool")
	}
	instanceAfter, _ := configurations.GetInstance(ctx, onboarding.Instance.ID)
	endpointsAfter, _ := configurations.ListEndpoints(ctx, onboarding.Instance.ID)
	credentialsAfter, _ := configurations.ListCredentials(ctx, onboarding.Instance.ID)
	bindingsAfter, _ := configurations.ListBindings(ctx, onboarding.Instance.ID)
	if !reflect.DeepEqual(instanceAfter, instanceBefore) || !reflect.DeepEqual(endpointsAfter, endpointsBefore) || !reflect.DeepEqual(credentialsAfter, credentialsBefore) || !reflect.DeepEqual(bindingsAfter, bindingsBefore) {
		t.Fatal("Alibaba catalog migration modified the provider access graph")
	}
	changedAgain, errAgain := ReconcileAlibabaSystemCatalogs(ctx, configurations, service.catalogs)
	if errAgain != nil || changedAgain != 0 {
		t.Fatalf("second Alibaba reconciliation changed=%d error=%v", changedAgain, errAgain)
	}
}

// TestReconcileAlibabaSystemCatalogsRecreatesMissingSnapshot verifies an existing access graph cannot remain stranded without its code-owned catalog.
// TestReconcileAlibabaSystemCatalogsRecreatesMissingSnapshot 验证已有访问图不会在缺少代码拥有目录时保持搁浅。
func TestReconcileAlibabaSystemCatalogsRecreatesMissingSnapshot(t *testing.T) {
	ctx := context.Background()
	service, configurations, _ := newKimiOnboardingService(t)
	onboarding, errOnboard := service.OnboardSystemProvider(ctx, OnboardSystemProviderInput{DefinitionID: bootstrap.AlibabaCodingPlanCNDefinitionID, Handle: "missing-alibaba-catalog", DisplayName: "Missing Alibaba Catalog", AuthMethodID: "api_key", CredentialLabel: "Alibaba", Secret: []byte("test-key")})
	if errOnboard != nil {
		t.Fatalf("onboard Alibaba provider: %v", errOnboard)
	}
	if errDelete := service.catalogs.Delete(ctx, onboarding.Instance.ID); errDelete != nil {
		t.Fatalf("delete Alibaba catalog fixture: %v", errDelete)
	}
	changed, errReconcile := ReconcileAlibabaSystemCatalogs(ctx, configurations, service.catalogs)
	if errReconcile != nil || changed != 1 {
		t.Fatalf("recreate missing Alibaba catalog changed=%d error=%v", changed, errReconcile)
	}
	recreated, errRecreated := service.catalogs.Get(ctx, onboarding.Instance.ID)
	if errRecreated != nil || len(recreated.Models) == 0 || len(recreated.ModelOperationPolicies) == 0 {
		t.Fatalf("recreated Alibaba catalog models=%d policies=%d error=%v", len(recreated.Models), len(recreated.ModelOperationPolicies), errRecreated)
	}
	changedAgain, errAgain := ReconcileAlibabaSystemCatalogs(ctx, configurations, service.catalogs)
	if errAgain != nil || changedAgain != 0 {
		t.Fatalf("second missing-catalog reconciliation changed=%d error=%v", changedAgain, errAgain)
	}
}

// filterAlibabaModelsForMigrationTest removes one exact historical model while preserving all others in order.
// filterAlibabaModelsForMigrationTest 删除一个精确历史模型，同时按原顺序保留其余模型。
func filterAlibabaModelsForMigrationTest(models []catalog.ProviderModel, removedModelID string) []catalog.ProviderModel {
	retained := make([]catalog.ProviderModel, 0, len(models)-1)
	for _, model := range models {
		if model.ID != removedModelID {
			retained = append(retained, model)
		}
	}
	return retained
}

// filterAlibabaModelGraphForMigrationTest removes every offering-owned dependency of one exact historical model.
// filterAlibabaModelGraphForMigrationTest 删除一个精确历史模型拥有的每个 Offering 依赖项。
func filterAlibabaModelGraphForMigrationTest(snapshot catalog.Snapshot, removedModelID string) ([]catalog.ModelOffering, []catalog.ModelOperationPolicy, []catalog.ExecutionProfile, []catalog.RateLimitSnapshot) {
	removedOfferingIDs := make(map[string]struct{})
	offerings := make([]catalog.ModelOffering, 0, len(snapshot.Offerings))
	for _, offering := range snapshot.Offerings {
		if offering.ProviderModelID == removedModelID {
			removedOfferingIDs[offering.ID] = struct{}{}
			continue
		}
		offerings = append(offerings, offering)
	}
	policies := make([]catalog.ModelOperationPolicy, 0, len(snapshot.ModelOperationPolicies))
	for _, policy := range snapshot.ModelOperationPolicies {
		if policy.ProviderModelID != removedModelID {
			policies = append(policies, policy)
		}
	}
	profiles := make([]catalog.ExecutionProfile, 0, len(snapshot.Profiles))
	for _, profile := range snapshot.Profiles {
		if _, removed := removedOfferingIDs[profile.OfferingID]; !removed {
			profiles = append(profiles, profile)
		}
	}
	rateLimits := make([]catalog.RateLimitSnapshot, 0, len(snapshot.RateLimits))
	for _, rateLimit := range snapshot.RateLimits {
		if rateLimit.Scope == catalog.RateLimitScopeOffering {
			if _, removed := removedOfferingIDs[rateLimit.ScopeID]; removed {
				continue
			}
		}
		rateLimits = append(rateLimits, rateLimit)
	}
	return offerings, policies, profiles, rateLimits
}

// TestReconcileTavilyExtractCatalogsUpgradesHistoricalSnapshots verifies old search-only instances gain Extract without losing account metadata.
// TestReconcileTavilyExtractCatalogsUpgradesHistoricalSnapshots 验证旧版仅搜索实例会获得 Extract 且不会丢失账号元数据。
func TestReconcileTavilyExtractCatalogsUpgradesHistoricalSnapshots(t *testing.T) {
	ctx := context.Background()
	service, configurations, _ := newKimiOnboardingService(t)
	onboarding, errOnboard := service.OnboardSystemProvider(ctx, OnboardSystemProviderInput{
		DefinitionID:    bootstrap.TavilySearchDefinitionID,
		Handle:          "legacy-tavily",
		DisplayName:     "Legacy Tavily",
		AuthMethodID:    "api_key",
		CredentialLabel: "Tavily Primary",
		Secret:          []byte("test-tavily-key"),
	})
	if errOnboard != nil {
		t.Fatalf("onboard Tavily provider: %v", errOnboard)
	}
	replaceTavilyBindingsWithSearchOnly(t, ctx, configurations, onboarding)
	current, errCurrent := service.catalogs.Get(ctx, onboarding.Instance.ID)
	if errCurrent != nil {
		t.Fatalf("get current Tavily catalog: %v", errCurrent)
	}
	current.Services = removeProviderService(current.Services, "service_web_extract")
	current.ServiceOfferings = removeServiceOffering(current.ServiceOfferings, "service_offer_tavily_extract")
	current.Profiles = removeExecutionProfile(current.Profiles, "profile_tavily_extract")
	observedAt := current.ObservedAt.Add(time.Second)
	current.Plans = []catalog.PlanSnapshot{{
		ID: "plan_tavily_researcher", ProviderInstanceID: onboarding.Instance.ID, CredentialID: onboarding.Credential.ID,
		PlanCode: "researcher", PlanName: "Researcher", Status: "active", EvidenceSource: catalog.MetadataEvidenceProviderAPI,
		ObservedAt: observedAt, ExpiresAt: observedAt.Add(time.Hour), Revision: 1,
	}}
	current.Revision++
	current.ObservedAt = observedAt
	if errSave := service.catalogs.Save(ctx, current); errSave != nil {
		t.Fatalf("save historical Tavily catalog: %v", errSave)
	}
	changed, errReconcile := ReconcileTavilyExtractCatalogs(ctx, configurations, service.catalogs)
	if errReconcile != nil || changed != 1 {
		t.Fatalf("reconcile Tavily Extract catalogs changed=%d error=%v", changed, errReconcile)
	}
	upgraded, errUpgraded := service.catalogs.Get(ctx, onboarding.Instance.ID)
	if errUpgraded != nil {
		t.Fatalf("get upgraded Tavily catalog: %v", errUpgraded)
	}
	_, _, _, extractExists := tavilyExtractContract(upgraded)
	if !extractExists {
		t.Fatal("upgraded Tavily catalog omitted the Extract contract")
	}
	if len(upgraded.Plans) != 1 || upgraded.Plans[0].PlanName != "Researcher" {
		t.Fatalf("upgraded Tavily account metadata = %#v", upgraded.Plans)
	}
	assertTavilyExtractReady(t, ctx, configurations, upgraded, onboarding)
	changedAgain, errAgain := ReconcileTavilyExtractCatalogs(ctx, configurations, service.catalogs)
	if errAgain != nil || changedAgain != 0 {
		t.Fatalf("second Tavily reconciliation changed=%d error=%v", changedAgain, errAgain)
	}
}

// TestReconcileTavilyExtractCatalogsRepairsCurrentCatalogAccess verifies an already-upgraded catalog still repairs its missing historical Extract binding.
// TestReconcileTavilyExtractCatalogsRepairsCurrentCatalogAccess 验证已经升级的目录仍会修复其缺失的历史 Extract Binding。
func TestReconcileTavilyExtractCatalogsRepairsCurrentCatalogAccess(t *testing.T) {
	ctx := context.Background()
	service, configurations, _ := newKimiOnboardingService(t)
	onboarding, errOnboard := service.OnboardSystemProvider(ctx, OnboardSystemProviderInput{
		DefinitionID:    bootstrap.TavilySearchDefinitionID,
		Handle:          "current-catalog-legacy-tavily",
		DisplayName:     "Current Catalog Legacy Tavily",
		AuthMethodID:    "api_key",
		CredentialLabel: "Tavily Primary",
		Secret:          []byte("test-current-catalog-tavily-key"),
	})
	if errOnboard != nil {
		t.Fatalf("onboard Tavily provider: %v", errOnboard)
	}
	replaceTavilyBindingsWithSearchOnly(t, ctx, configurations, onboarding)
	current, errCurrent := service.catalogs.Get(ctx, onboarding.Instance.ID)
	if errCurrent != nil {
		t.Fatalf("get current Tavily catalog: %v", errCurrent)
	}
	changed, errReconcile := ReconcileTavilyExtractCatalogs(ctx, configurations, service.catalogs)
	if errReconcile != nil || changed != 1 {
		t.Fatalf("reconcile current Tavily catalog changed=%d error=%v", changed, errReconcile)
	}
	upgraded, errUpgraded := service.catalogs.Get(ctx, onboarding.Instance.ID)
	if errUpgraded != nil {
		t.Fatalf("get repaired Tavily catalog: %v", errUpgraded)
	}
	assertTavilyExtractReady(t, ctx, configurations, upgraded, onboarding)
	if upgraded.Revision <= current.Revision {
		t.Fatalf("repaired Tavily catalog revision=%d, want greater than %d", upgraded.Revision, current.Revision)
	}
}

// TestReconcileTavilyExtractCatalogsRepairsStalePool verifies a completed access-graph migration can recover after catalog persistence was interrupted.
// TestReconcileTavilyExtractCatalogsRepairsStalePool 验证访问图迁移完成后即使目录持久化曾中断也可以恢复。
func TestReconcileTavilyExtractCatalogsRepairsStalePool(t *testing.T) {
	ctx := context.Background()
	service, configurations, _ := newKimiOnboardingService(t)
	onboarding, errOnboard := service.OnboardSystemProvider(ctx, OnboardSystemProviderInput{
		DefinitionID:    bootstrap.TavilySearchDefinitionID,
		Handle:          "stale-pool-tavily",
		DisplayName:     "Stale Pool Tavily",
		AuthMethodID:    "api_key",
		CredentialLabel: "Tavily Primary",
		Secret:          []byte("test-stale-pool-tavily-key"),
	})
	if errOnboard != nil {
		t.Fatalf("onboard Tavily provider: %v", errOnboard)
	}
	current, errCurrent := service.catalogs.Get(ctx, onboarding.Instance.ID)
	if errCurrent != nil {
		t.Fatalf("get current Tavily catalog: %v", errCurrent)
	}
	current.Revision++
	current.ObservedAt = current.ObservedAt.Add(time.Second)
	for index := range current.Pools {
		current.Pools[index].Revision = current.Revision
		current.Pools[index].ObservedAt = current.ObservedAt
		if current.Pools[index].ExecutionProfileID == "profile_tavily_extract" {
			current.Pools[index].EntitledCredentials = 0
			current.Pools[index].ReadyCredentials = 0
		}
	}
	if errSave := service.catalogs.Save(ctx, current); errSave != nil {
		t.Fatalf("save stale Tavily pool: %v", errSave)
	}
	changed, errReconcile := ReconcileTavilyExtractCatalogs(ctx, configurations, service.catalogs)
	if errReconcile != nil || changed != 1 {
		t.Fatalf("reconcile stale Tavily pool changed=%d error=%v", changed, errReconcile)
	}
	repaired, errRepaired := service.catalogs.Get(ctx, onboarding.Instance.ID)
	if errRepaired != nil {
		t.Fatalf("get repaired Tavily pool: %v", errRepaired)
	}
	assertTavilyExtractReady(t, ctx, configurations, repaired, onboarding)
}

// replaceTavilyBindingsWithSearchOnly rewrites one current fixture into the exact single-binding graph persisted before Extract support existed.
// replaceTavilyBindingsWithSearchOnly 将一个当前测试夹具改写为 Extract 支持出现前持久化的精确单 Binding 访问图。
func replaceTavilyBindingsWithSearchOnly(t *testing.T, ctx context.Context, configurations providerconfig.Store, onboarding providerconfig.SystemOnboarding) {
	t.Helper()
	endpoints, errEndpoints := configurations.ListEndpoints(ctx, onboarding.Instance.ID)
	bindings, errBindings := configurations.ListBindings(ctx, onboarding.Instance.ID)
	if errEndpoints != nil || errBindings != nil {
		t.Fatalf("list Tavily access graph endpoints=%v bindings=%v", errEndpoints, errBindings)
	}
	searchOnly := make([]providerconfig.AccessBinding, 0, len(bindings))
	for _, binding := range bindings {
		if binding.ChannelID == providertavily.ProtocolProfileID {
			searchOnly = append(searchOnly, binding)
		}
	}
	if len(searchOnly) != 1 || len(bindings) != 2 {
		t.Fatalf("current Tavily bindings=%#v, want one Search and one Extract binding", bindings)
	}
	replacement := providerconfig.AccessGraphReplacement{
		ProviderInstanceID: onboarding.Instance.ID,
		ExpectedEndpoints:  endpoints,
		ExpectedBindings:   bindings,
		Endpoints:          endpoints,
		Bindings:           searchOnly,
	}
	if errReplace := configurations.ReplaceAccessGraph(ctx, replacement); errReplace != nil {
		t.Fatalf("replace Tavily access graph with historical binding: %v", errReplace)
	}
}

// assertTavilyExtractReady verifies migration restored one executable Extract binding and one ready profile pool.
// assertTavilyExtractReady 验证迁移已恢复一条可执行 Extract Binding 与一个就绪规格池。
func assertTavilyExtractReady(t *testing.T, ctx context.Context, configurations providerconfig.Store, snapshot catalog.Snapshot, onboarding providerconfig.SystemOnboarding) {
	t.Helper()
	bindings, errBindings := configurations.ListBindings(ctx, onboarding.Instance.ID)
	if errBindings != nil {
		t.Fatalf("list repaired Tavily bindings: %v", errBindings)
	}
	extractBindings := 0
	for _, binding := range bindings {
		if binding.ChannelID == providertavily.ExtractProtocolProfileID && binding.CredentialID == onboarding.Credential.ID {
			extractBindings++
		}
	}
	if extractBindings != 1 {
		t.Fatalf("repaired Tavily bindings=%#v, want one Extract binding", bindings)
	}
	for _, pool := range snapshot.Pools {
		if pool.ExecutionProfileID == "profile_tavily_extract" {
			if pool.EntitledCredentials != 1 || pool.ReadyCredentials != 1 {
				t.Fatalf("repaired Tavily Extract pool=%+v, want one entitled and ready credential", pool)
			}
			return
		}
	}
	t.Fatal("repaired Tavily catalog omitted its Extract pool")
}

// legacyKimiAccessStore overlays a historical access graph on a complete in-memory provider store.
// legacyKimiAccessStore 在完整内存供应商 Store 上覆盖一份历史访问图。
type legacyKimiAccessStore struct {
	// MemoryStore supplies every configuration operation outside the overlaid access graph.
	// MemoryStore 提供覆盖访问图之外的每个配置操作。
	*providerconfig.MemoryStore
	// endpoints contains the exact historical endpoint snapshot.
	// endpoints 包含精确历史入口快照。
	endpoints []providerconfig.Endpoint
	// bindings contains the exact historical binding snapshot.
	// bindings 包含精确历史 Binding 快照。
	bindings []providerconfig.AccessBinding
	// replacements counts committed atomic graph replacements.
	// replacements 统计已提交原子图替换次数。
	replacements int
}

// TestReconcileMiniMaxSharedOriginsCollapsesEquivalentActionEndpoints verifies persisted multimodal channels retain bindings while sharing one regional Origin.
// TestReconcileMiniMaxSharedOriginsCollapsesEquivalentActionEndpoints 验证持久化多模态通道在保留绑定的同时共享一个区域 Origin。
func TestReconcileMiniMaxSharedOriginsCollapsesEquivalentActionEndpoints(t *testing.T) {
	ctx := context.Background()
	service, configurations, _ := newKimiOnboardingService(t)
	onboarding, errOnboard := service.OnboardSystemProvider(ctx, OnboardSystemProviderInput{DefinitionID: bootstrap.MiniMaxCNDefinitionID, Handle: "minimax-origin", DisplayName: "MiniMax CN", AuthMethodID: "api_key", CredentialLabel: "MiniMax", Secret: []byte("test-key")})
	if errOnboard != nil {
		t.Fatalf("OnboardSystemProvider() error = %v", errOnboard)
	}
	if len(onboarding.Endpoints) != 1 || len(onboarding.Bindings) != 10 {
		t.Fatalf("new MiniMax endpoint/binding counts = %d/%d, want 1/10", len(onboarding.Endpoints), len(onboarding.Bindings))
	}
	legacyEndpoints := make([]providerconfig.Endpoint, 0, len(onboarding.Bindings))
	legacyBindings := append([]providerconfig.AccessBinding(nil), onboarding.Bindings...)
	for index := range legacyBindings {
		endpoint := onboarding.Endpoints[0]
		endpoint.ID = fmt.Sprintf("ep_minimax_legacy_%d", index)
		endpoint.ChannelID = legacyBindings[index].ChannelID
		legacyEndpoints = append(legacyEndpoints, endpoint)
		legacyBindings[index].EndpointID = endpoint.ID
	}
	legacy := providerconfig.AccessGraphReplacement{ProviderInstanceID: onboarding.Instance.ID, ExpectedEndpoints: onboarding.Endpoints, ExpectedBindings: onboarding.Bindings, Endpoints: legacyEndpoints, Bindings: legacyBindings}
	if errReplace := configurations.ReplaceAccessGraph(ctx, legacy); errReplace != nil {
		t.Fatalf("ReplaceAccessGraph() legacy error = %v", errReplace)
	}
	changed, errReconcile := ReconcileMiniMaxSharedOrigins(ctx, configurations)
	if errReconcile != nil || changed != 1 {
		t.Fatalf("ReconcileMiniMaxSharedOrigins() changed=%d error=%v", changed, errReconcile)
	}
	endpoints, errEndpoints := configurations.ListEndpoints(ctx, onboarding.Instance.ID)
	bindings, errBindings := configurations.ListBindings(ctx, onboarding.Instance.ID)
	if errEndpoints != nil || errBindings != nil || len(endpoints) != 1 || len(bindings) != len(onboarding.Bindings) {
		t.Fatalf("reconciled MiniMax graph endpoints=%#v bindings=%#v errors=%v/%v", endpoints, bindings, errEndpoints, errBindings)
	}
	for _, binding := range bindings {
		if binding.EndpointID != endpoints[0].ID {
			t.Fatalf("MiniMax binding %q endpoint = %q, want %q", binding.ID, binding.EndpointID, endpoints[0].ID)
		}
	}
	changedAgain, errAgain := ReconcileMiniMaxSharedOrigins(ctx, configurations)
	if errAgain != nil || changedAgain != 0 {
		t.Fatalf("second reconciliation changed=%d error=%v", changedAgain, errAgain)
	}
}

// ListEndpoints returns the overlaid historical endpoint graph.
// ListEndpoints 返回覆盖的历史入口图。
func (s *legacyKimiAccessStore) ListEndpoints(context.Context, string) ([]providerconfig.Endpoint, error) {
	return append([]providerconfig.Endpoint(nil), s.endpoints...), nil
}

// ListBindings returns the overlaid historical binding graph.
// ListBindings 返回覆盖的历史 Binding 图。
func (s *legacyKimiAccessStore) ListBindings(context.Context, string) ([]providerconfig.AccessBinding, error) {
	return append([]providerconfig.AccessBinding(nil), s.bindings...), nil
}

// ReplaceAccessGraph applies one exact compare-and-swap replacement to the overlaid graph.
// ReplaceAccessGraph 对覆盖图应用一次精确比较并交换替换。
func (s *legacyKimiAccessStore) ReplaceAccessGraph(_ context.Context, replacement providerconfig.AccessGraphReplacement) error {
	if !accessGraphEquivalent(s.endpoints, s.bindings, replacement.ExpectedEndpoints, replacement.ExpectedBindings) {
		return errors.New("historical access graph changed")
	}
	s.endpoints = append([]providerconfig.Endpoint(nil), replacement.Endpoints...)
	s.bindings = append([]providerconfig.AccessBinding(nil), replacement.Bindings...)
	s.replacements++
	return nil
}

// TestReconcileKimiSystemCatalogsRemovesLegacyAnthropicOffering verifies existing Kimi instances converge to one Chat offering without losing valid account metadata.
// TestReconcileKimiSystemCatalogsRemovesLegacyAnthropicOffering 验证已有 Kimi 实例收敛到唯一 Chat 产品且不会丢失有效账号元数据。
func TestReconcileKimiSystemCatalogsRemovesLegacyAnthropicOffering(t *testing.T) {
	ctx := context.Background()
	service, configurations, _ := newKimiOnboardingService(t)
	onboarding, errOnboard := service.OnboardSystemProvider(ctx, OnboardSystemProviderInput{DefinitionID: "system_kimi_coding_plan", Handle: "legacy-kimi", DisplayName: "Legacy Kimi", AuthMethodID: "api_key", CredentialLabel: "Kimi", Secret: []byte("test-key"), PlanOptionID: "kimi_andante"})
	if errOnboard != nil {
		t.Fatalf("OnboardSystemProvider() error = %v", errOnboard)
	}
	currentEndpoints, errEndpoints := configurations.ListEndpoints(ctx, onboarding.Instance.ID)
	if errEndpoints != nil {
		t.Fatalf("ListEndpoints() error = %v", errEndpoints)
	}
	currentBindings, errBindings := configurations.ListBindings(ctx, onboarding.Instance.ID)
	if errBindings != nil {
		t.Fatalf("ListBindings() error = %v", errBindings)
	}
	legacyEndpoint := currentEndpoints[0]
	legacyEndpoint.ChannelID = legacyKimiChatChannelID
	legacyBinding := currentBindings[0]
	legacyBinding.ChannelID = legacyKimiChatChannelID
	legacyAnthropicEndpoint := legacyEndpoint
	legacyAnthropicEndpoint.ID = "ep_legacy_anthropic"
	legacyAnthropicEndpoint.ChannelID = "anthropic"
	legacyAnthropicBinding := legacyBinding
	legacyAnthropicBinding.ID = "bind_legacy_anthropic"
	legacyAnthropicBinding.ChannelID = "anthropic"
	legacyAnthropicBinding.EndpointID = legacyAnthropicEndpoint.ID
	legacyConfigurations := &legacyKimiAccessStore{MemoryStore: configurations, endpoints: []providerconfig.Endpoint{legacyEndpoint, legacyAnthropicEndpoint}, bindings: []providerconfig.AccessBinding{legacyBinding, legacyAnthropicBinding}}
	current, errCurrent := service.catalogs.Get(ctx, onboarding.Instance.ID)
	if errCurrent != nil {
		t.Fatalf("Get() current catalog error = %v", errCurrent)
	}
	chatOffering := current.Offerings[0]
	chatOffering.ChannelID = "chat"
	chatOffering.Capabilities.Delivery = catalog.DeliveryCapabilities{}
	chatProfile := current.Profiles[0]
	chatProfile.Operation = ""
	chatProfile.ActionBindingID = ""
	chatProfile.Capabilities.Delivery = catalog.DeliveryCapabilities{}
	legacyOffering := chatOffering
	legacyOffering.ID = "offer_legacy_anthropic"
	legacyOffering.ChannelID = "anthropic.messages"
	legacyProfile := chatProfile
	legacyProfile.ID = "profile_legacy_anthropic"
	legacyProfile.OfferingID = legacyOffering.ID
	current.Offerings = append(current.Offerings, legacyOffering)
	current.Offerings[0] = chatOffering
	current.Profiles[0] = chatProfile
	current.Profiles = append(current.Profiles, legacyProfile)
	current.Entitlements = nil
	expiresAt := current.ObservedAt.Add(time.Hour)
	current.Entitlements = append(current.Entitlements, catalog.ModelEntitlement{ID: "ent_legacy_kimi", ProviderInstanceID: current.ProviderInstanceID, CredentialID: onboarding.Credential.ID, ProviderModelID: chatOffering.ProviderModelID, Availability: catalog.AvailabilityAllowed, AllowedProfileIDs: []string{chatProfile.ID, legacyProfile.ID}, Source: catalog.ModelSourceRuntimeEvidence, ObservedAt: current.ObservedAt, ExpiresAt: expiresAt, Revision: 1})
	current.Allowances = append(current.Allowances, catalog.AllowanceSnapshot{ID: "allow_legacy_anthropic", ProviderInstanceID: current.ProviderInstanceID, Kind: catalog.AllowanceProviderDefined, Scope: catalog.ScopeExecutionProfile, ScopeID: legacyProfile.ID, Metric: "legacy_calls", Unit: catalog.UnitProviderDefined, Status: catalog.AllowanceAvailable, Source: catalog.ModelSourceRuntimeEvidence, ObservedAt: current.ObservedAt, ExpiresAt: expiresAt, Revision: 1})
	current.Pools = append(current.Pools,
		catalog.PoolSummary{ProviderInstanceID: current.ProviderInstanceID, ExecutionProfileID: chatProfile.ID, ConfiguredCredentials: 1, EntitledCredentials: 1, ReadyCredentials: 1, Revision: 1, ObservedAt: current.ObservedAt},
		catalog.PoolSummary{ProviderInstanceID: current.ProviderInstanceID, ExecutionProfileID: legacyProfile.ID, ConfiguredCredentials: 1, EntitledCredentials: 1, ReadyCredentials: 1, Revision: 1, ObservedAt: current.ObservedAt},
	)
	current.Revision++
	if errSave := service.catalogs.Save(ctx, current); errSave != nil {
		t.Fatalf("Save() legacy catalog error = %v", errSave)
	}
	changed, errReconcile := ReconcileKimiSystemCatalogs(ctx, legacyConfigurations, service.catalogs)
	if errReconcile != nil {
		t.Fatalf("ReconcileKimiSystemCatalogs() error = %v", errReconcile)
	}
	if changed != 1 {
		t.Fatalf("ReconcileKimiSystemCatalogs() changed = %d, want 1", changed)
	}
	if legacyConfigurations.replacements != 1 || len(legacyConfigurations.endpoints) != 1 || legacyConfigurations.endpoints[0].ChannelID != "openai.chat" || len(legacyConfigurations.bindings) != 1 || legacyConfigurations.bindings[0].ChannelID != "openai.chat" {
		t.Fatalf("migrated access graph endpoints=%#v bindings=%#v replacements=%d", legacyConfigurations.endpoints, legacyConfigurations.bindings, legacyConfigurations.replacements)
	}
	migrated, errMigrated := service.catalogs.Get(ctx, onboarding.Instance.ID)
	if errMigrated != nil {
		t.Fatalf("Get() migrated catalog error = %v", errMigrated)
	}
	for _, offering := range migrated.Offerings {
		if offering.ChannelID != "openai.chat" {
			t.Fatalf("migrated offering channel = %q, want openai.chat", offering.ChannelID)
		}
		if !offering.Capabilities.Delivery.Synchronous || !offering.Capabilities.Delivery.Streaming {
			t.Fatalf("migrated offering delivery = %#v", offering.Capabilities.Delivery)
		}
	}
	for _, profile := range migrated.Profiles {
		if profile.Operation != vcp.OperationConversationRespond || profile.ActionBindingID != "action_conversation_respond" {
			t.Fatalf("migrated profile action = %#v", profile)
		}
		if !profile.Capabilities.Delivery.Synchronous || !profile.Capabilities.Delivery.Streaming {
			t.Fatalf("migrated profile delivery = %#v", profile.Capabilities.Delivery)
		}
	}
	allowedEntitlements := 0
	for _, entitlement := range migrated.Entitlements {
		if entitlement.Availability == catalog.AvailabilityAllowed {
			allowedEntitlements++
			if entitlement.ProviderModelID != "model_kimi_for_coding" || len(entitlement.AllowedProfileIDs) != 1 {
				t.Fatalf("unexpected Andante entitlement = %#v", entitlement)
			}
		}
	}
	if len(migrated.Models) != 3 || len(migrated.Entitlements) != 3 || allowedEntitlements != 1 {
		t.Fatalf("migrated entitlements = %#v", migrated.Entitlements)
	}
	if len(migrated.Allowances) != 0 || len(migrated.Pools) != 4 {
		t.Fatalf("migrated account metadata allowances = %#v, pools = %#v", migrated.Allowances, migrated.Pools)
	}
	readyProfiles := 0
	for _, pool := range migrated.Pools {
		if pool.ReadyCredentials > 0 {
			readyProfiles++
		}
	}
	if readyProfiles != 1 {
		t.Fatalf("migrated ready profile count = %d, pools = %#v", readyProfiles, migrated.Pools)
	}
	changedAgain, errAgain := ReconcileKimiSystemCatalogs(ctx, legacyConfigurations, service.catalogs)
	if errAgain != nil || changedAgain != 0 {
		t.Fatalf("second ReconcileKimiSystemCatalogs() changed = %d, error = %v", changedAgain, errAgain)
	}
}

// TestReconcileKimiSystemCatalogsUpgradesPersistedReasoningCapabilities verifies existing K2.7 records receive the current official thinking capability without re-onboarding.
// TestReconcileKimiSystemCatalogsUpgradesPersistedReasoningCapabilities 验证现有 K2.7 记录无需重新录入即可获得当前官方思考能力。
func TestReconcileKimiSystemCatalogsUpgradesPersistedReasoningCapabilities(t *testing.T) {
	ctx := context.Background()
	service, configurations, _ := newKimiOnboardingService(t)
	onboarding, errOnboard := service.OnboardSystemProvider(ctx, OnboardSystemProviderInput{DefinitionID: bootstrap.KimiCodingDefinitionID, Handle: "stale-kimi-reasoning", DisplayName: "Stale Kimi Reasoning", AuthMethodID: "api_key", CredentialLabel: "Kimi", Secret: []byte("test-key"), PlanOptionID: providerkimi.PlanOptionAllegretto})
	if errOnboard != nil {
		t.Fatalf("OnboardSystemProvider() error = %v", errOnboard)
	}
	stale, errStale := service.catalogs.Get(ctx, onboarding.Instance.ID)
	if errStale != nil {
		t.Fatalf("Get() stale catalog error = %v", errStale)
	}
	modelIDs := make(map[string]string, len(stale.Models))
	for _, model := range stale.Models {
		modelIDs[model.ID] = model.UpstreamModelID
	}
	staleOfferingIDs := make(map[string]struct{})
	for index := range stale.Offerings {
		upstreamID := modelIDs[stale.Offerings[index].ProviderModelID]
		if upstreamID != "kimi-for-coding" && upstreamID != "kimi-for-coding-highspeed" {
			continue
		}
		stale.Offerings[index].Capabilities.Reasoning = catalog.CapabilityUnknown
		staleOfferingIDs[stale.Offerings[index].ID] = struct{}{}
	}
	for index := range stale.Profiles {
		if _, exists := staleOfferingIDs[stale.Profiles[index].OfferingID]; exists {
			stale.Profiles[index].Capabilities.Reasoning = catalog.CapabilityUnknown
		}
	}
	stale.Revision++
	if errSave := service.catalogs.Save(ctx, stale); errSave != nil {
		t.Fatalf("Save() stale catalog error = %v", errSave)
	}
	changed, errReconcile := ReconcileKimiSystemCatalogs(ctx, configurations, service.catalogs)
	if errReconcile != nil || changed != 1 {
		t.Fatalf("ReconcileKimiSystemCatalogs() changed=%d error=%v", changed, errReconcile)
	}
	upgraded, errUpgraded := service.catalogs.Get(ctx, onboarding.Instance.ID)
	if errUpgraded != nil {
		t.Fatalf("Get() upgraded catalog error = %v", errUpgraded)
	}
	for _, offering := range upgraded.Offerings {
		upstreamID := modelIDs[offering.ProviderModelID]
		if (upstreamID == "kimi-for-coding" || upstreamID == "kimi-for-coding-highspeed") && offering.Capabilities.Reasoning != catalog.CapabilityNative {
			t.Fatalf("upgraded offering %q reasoning = %q", offering.ID, offering.Capabilities.Reasoning)
		}
	}
	for _, profile := range upgraded.Profiles {
		if _, exists := staleOfferingIDs[profile.OfferingID]; exists && profile.Capabilities.Reasoning != catalog.CapabilityNative {
			t.Fatalf("upgraded profile %q reasoning = %q", profile.ID, profile.Capabilities.Reasoning)
		}
	}
	changedAgain, errAgain := ReconcileKimiSystemCatalogs(ctx, configurations, service.catalogs)
	if errAgain != nil || changedAgain != 0 {
		t.Fatalf("second ReconcileKimiSystemCatalogs() changed=%d error=%v", changedAgain, errAgain)
	}
}

// TestReconcileCodexUnknownPlanEntitlementsRemovesHistoricalPrivilege verifies an unrecognized plan can never retain a prior allowed-model set.
// TestReconcileCodexUnknownPlanEntitlementsRemovesHistoricalPrivilege 验证无法识别的套餐绝不能保留先前允许模型集合。
func TestReconcileCodexUnknownPlanEntitlementsRemovesHistoricalPrivilege(t *testing.T) {
	ctx := context.Background()
	protocols := providerconfig.NewProtocolRegistry()
	if errProtocols := bootstrap.RegisterProtocolProfiles(protocols); errProtocols != nil {
		t.Fatalf("RegisterProtocolProfiles() error = %v", errProtocols)
	}
	systems, errSystems := providerconfig.NewSystemRegistry(protocols)
	if errSystems != nil {
		t.Fatalf("NewSystemRegistry() error = %v", errSystems)
	}
	if errProviders := bootstrap.RegisterSystemProviders(systems); errProviders != nil {
		t.Fatalf("RegisterSystemProviders() error = %v", errProviders)
	}
	configurations, errConfigurations := providerconfig.NewMemoryStore(protocols, systems)
	if errConfigurations != nil {
		t.Fatalf("NewMemoryStore() error = %v", errConfigurations)
	}
	definition, exists := systems.Lookup(bootstrap.OpenAICodexDefinitionID)
	if !exists {
		t.Fatal("Codex definition is missing")
	}
	now := time.Now().UTC()
	onboarding := providerconfig.SystemOnboarding{
		Instance:   providerconfig.ProviderInstance{ID: "pvi_codex_unknown", DefinitionID: definition.ID, Handle: "codex-unknown", DisplayName: "Codex Unknown", Status: providerconfig.LifecycleReady, Revision: 1, DefinitionRevision: definition.Revision, CreatedAt: now, UpdatedAt: now},
		Endpoints:  []providerconfig.Endpoint{{ID: "ep_codex_unknown", ProviderInstanceID: "pvi_codex_unknown", ChannelID: definition.ProtocolProfileID, BaseURL: definition.EndpointPresets[0].BaseURL, Region: definition.EndpointPresets[0].Region, Status: providerconfig.EndpointReady, Revision: 1}},
		Credential: providerconfig.Credential{ID: "cred_codex_unknown", ProviderInstanceID: "pvi_codex_unknown", AuthMethodID: "oauth", Label: "Unknown", SecretRef: "secret-codex", Fingerprint: "fingerprint-codex", Status: providerconfig.CredentialActive, Revision: 1},
		Bindings:   []providerconfig.AccessBinding{{ID: "bind_codex_unknown", ProviderInstanceID: "pvi_codex_unknown", ChannelID: definition.ProtocolProfileID, EndpointID: "ep_codex_unknown", CredentialID: "cred_codex_unknown", Priority: 10, Enabled: true, Revision: 1}},
	}
	if errSave := configurations.SaveSystemOnboarding(ctx, onboarding); errSave != nil {
		t.Fatalf("SaveSystemOnboarding() error = %v", errSave)
	}
	snapshot, errCatalog := buildSystemCatalog(onboarding, definition, now)
	if errCatalog != nil {
		t.Fatalf("buildSystemCatalog() error = %v", errCatalog)
	}
	expiresAt := now.Add(time.Hour)
	snapshot.Plans = []catalog.PlanSnapshot{{ID: "plan_unknown", ProviderInstanceID: onboarding.Instance.ID, CredentialID: onboarding.Credential.ID, PlanCode: "future_enterprise", PlanName: "Future Enterprise", Status: "active", EvidenceSource: catalog.MetadataEvidenceProtectedTokenClaim, ObservedAt: now, ExpiresAt: expiresAt, Revision: 1}}
	snapshot.Entitlements = []catalog.ModelEntitlement{{ID: "ent_stale_pro", ProviderInstanceID: onboarding.Instance.ID, CredentialID: onboarding.Credential.ID, ProviderModelID: snapshot.Models[0].ID, Availability: catalog.AvailabilityAllowed, EntitlementClass: "codex_pro", Source: catalog.ModelSourceProviderAPI, EvidenceSource: catalog.MetadataEvidenceProtectedTokenClaim, ObservedAt: now, ExpiresAt: expiresAt, Revision: 1}}
	catalogs := catalog.NewMemoryStore()
	if errSave := catalogs.Save(ctx, snapshot); errSave != nil {
		t.Fatalf("save stale Codex snapshot: %v", errSave)
	}
	changed, errReconcile := ReconcileCodexUnknownPlanEntitlements(ctx, configurations, catalogs)
	if errReconcile != nil || changed != 1 {
		t.Fatalf("ReconcileCodexUnknownPlanEntitlements() changed=%d error=%v", changed, errReconcile)
	}
	migrated, errMigrated := catalogs.Get(ctx, onboarding.Instance.ID)
	if errMigrated != nil || len(migrated.Entitlements) != 0 || len(migrated.Plans) != 1 {
		t.Fatalf("migrated=%+v error=%v", migrated, errMigrated)
	}
	changedAgain, errAgain := ReconcileCodexUnknownPlanEntitlements(ctx, configurations, catalogs)
	if errAgain != nil || changedAgain != 0 {
		t.Fatalf("second reconciliation changed=%d error=%v", changedAgain, errAgain)
	}
}

// TestMigrateKimiCatalogToChatRejectsRemovingTheOnlyModelOffering verifies migration never silently strands a model when no Chat product exists.
// TestMigrateKimiCatalogToChatRejectsRemovingTheOnlyModelOffering 验证不存在 Chat 产品时迁移绝不会静默留下无产品模型。
func TestMigrateKimiCatalogToChatRejectsRemovingTheOnlyModelOffering(t *testing.T) {
	ctx := context.Background()
	service, _, _ := newKimiOnboardingService(t)
	onboarding, errOnboard := service.OnboardSystemProvider(ctx, OnboardSystemProviderInput{DefinitionID: "system_kimi_coding_plan", Handle: "anthropic-only-kimi", DisplayName: "Anthropic Only Kimi", AuthMethodID: "api_key", CredentialLabel: "Kimi", Secret: []byte("test-key"), PlanOptionID: "kimi_andante"})
	if errOnboard != nil {
		t.Fatalf("OnboardSystemProvider() error = %v", errOnboard)
	}
	snapshot, errSnapshot := service.catalogs.Get(ctx, onboarding.Instance.ID)
	if errSnapshot != nil {
		t.Fatalf("Get() catalog error = %v", errSnapshot)
	}
	for index := range snapshot.Offerings {
		snapshot.Offerings[index].ChannelID = "anthropic.messages"
	}
	_, _, errMigrate := migrateKimiCatalogToChat(snapshot, kimiChatMigrationAction())
	if errMigrate == nil {
		t.Fatal("migrateKimiCatalogToChat() error = nil")
	}
}

// kimiChatMigrationAction returns the exact action contract used by focused migration tests.
// kimiChatMigrationAction 返回迁移聚焦测试使用的精确动作合同。
func kimiChatMigrationAction() providerconfig.ProviderActionBinding {
	return providerconfig.ProviderActionBinding{ID: "action_conversation_respond", Operation: vcp.OperationConversationRespond, ProtocolProfileID: "openai.chat"}
}
