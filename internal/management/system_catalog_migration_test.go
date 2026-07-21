package management

import (
	"context"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/bootstrap"
	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestReconcileKimiSystemCatalogsRemovesLegacyAnthropicOffering verifies existing Kimi instances converge to one Chat offering without losing valid account metadata.
// TestReconcileKimiSystemCatalogsRemovesLegacyAnthropicOffering 验证已有 Kimi 实例收敛到唯一 Chat 产品且不会丢失有效账号元数据。
func TestReconcileKimiSystemCatalogsRemovesLegacyAnthropicOffering(t *testing.T) {
	ctx := context.Background()
	service, configurations, _ := newKimiOnboardingService(t)
	onboarding, errOnboard := service.OnboardSystemProvider(ctx, OnboardSystemProviderInput{DefinitionID: "system_kimi_coding_plan", Handle: "legacy-kimi", DisplayName: "Legacy Kimi", AuthMethodID: "api_key", CredentialLabel: "Kimi", Secret: []byte("test-key"), PlanOptionID: "kimi_andante"})
	if errOnboard != nil {
		t.Fatalf("OnboardSystemProvider() error = %v", errOnboard)
	}
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
	changed, errReconcile := ReconcileKimiSystemCatalogs(ctx, configurations, service.catalogs)
	if errReconcile != nil {
		t.Fatalf("ReconcileKimiSystemCatalogs() error = %v", errReconcile)
	}
	if changed != 1 {
		t.Fatalf("ReconcileKimiSystemCatalogs() changed = %d, want 1", changed)
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
	changedAgain, errAgain := ReconcileKimiSystemCatalogs(ctx, configurations, service.catalogs)
	if errAgain != nil || changedAgain != 0 {
		t.Fatalf("second ReconcileKimiSystemCatalogs() changed = %d, error = %v", changedAgain, errAgain)
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
