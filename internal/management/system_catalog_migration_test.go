package management

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/bootstrap"
	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	providerkimi "github.com/OpenVulcan/vulcan-model-core/internal/provider/kimi"
	providertavily "github.com/OpenVulcan/vulcan-model-core/internal/provider/tavily"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

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
