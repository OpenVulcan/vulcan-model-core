package management

import (
	"context"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestReconcileKimiSystemCatalogsRemovesLegacyAnthropicOffering verifies existing Kimi instances converge to one Chat offering without losing valid account metadata.
// TestReconcileKimiSystemCatalogsRemovesLegacyAnthropicOffering 验证已有 Kimi 实例收敛到唯一 Chat 产品且不会丢失有效账号元数据。
func TestReconcileKimiSystemCatalogsRemovesLegacyAnthropicOffering(t *testing.T) {
	ctx := context.Background()
	service, configurations, _ := newKimiOnboardingService(t)
	onboarding, errOnboard := service.OnboardSystemProvider(ctx, OnboardSystemProviderInput{DefinitionID: "system_kimi_coding_plan", Handle: "legacy-kimi", DisplayName: "Legacy Kimi", AuthMethodID: "api_key", CredentialLabel: "Kimi", Secret: []byte("test-key")})
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
	if len(migrated.Entitlements) != 1 || len(migrated.Entitlements[0].AllowedProfileIDs) != 1 || migrated.Entitlements[0].AllowedProfileIDs[0] != chatProfile.ID {
		t.Fatalf("migrated entitlements = %#v", migrated.Entitlements)
	}
	if len(migrated.Allowances) != 0 || len(migrated.Pools) != 1 || migrated.Pools[0].ExecutionProfileID != chatProfile.ID {
		t.Fatalf("migrated account metadata allowances = %#v, pools = %#v", migrated.Allowances, migrated.Pools)
	}
	changedAgain, errAgain := ReconcileKimiSystemCatalogs(ctx, configurations, service.catalogs)
	if errAgain != nil || changedAgain != 0 {
		t.Fatalf("second ReconcileKimiSystemCatalogs() changed = %d, error = %v", changedAgain, errAgain)
	}
}

// TestMigrateKimiCatalogToChatRejectsRemovingTheOnlyModelOffering verifies migration never silently strands a model when no Chat product exists.
// TestMigrateKimiCatalogToChatRejectsRemovingTheOnlyModelOffering 验证不存在 Chat 产品时迁移绝不会静默留下无产品模型。
func TestMigrateKimiCatalogToChatRejectsRemovingTheOnlyModelOffering(t *testing.T) {
	ctx := context.Background()
	service, _, _ := newKimiOnboardingService(t)
	onboarding, errOnboard := service.OnboardSystemProvider(ctx, OnboardSystemProviderInput{DefinitionID: "system_kimi_coding_plan", Handle: "anthropic-only-kimi", DisplayName: "Anthropic Only Kimi", AuthMethodID: "api_key", CredentialLabel: "Kimi", Secret: []byte("test-key")})
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
