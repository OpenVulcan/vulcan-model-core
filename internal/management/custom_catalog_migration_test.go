package management

import (
	"context"
	"testing"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	protocolchat "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/chat"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestReconcileCustomConversationCatalogsRestoresMissingDelivery verifies startup migration and idempotency for historical custom catalogs.
// TestReconcileCustomConversationCatalogsRestoresMissingDelivery 验证历史自定义目录启动迁移及其幂等性。
func TestReconcileCustomConversationCatalogsRestoresMissingDelivery(t *testing.T) {
	ctx := context.Background()
	_, configurations, secrets := managementTestService(t)
	catalogs := catalog.NewMemoryStore()
	service, errService := NewService(configurations, secrets, catalogs)
	if errService != nil {
		t.Fatalf("NewService() error = %v", errService)
	}
	definition, errDefinition := service.CreateCustomDefinition(ctx, CreateCustomDefinitionInput{
		ID: "custom_delivery_migration", DisplayName: "Custom Delivery Migration", ProtocolProfileID: protocolchat.ProfileID, AuthMethod: providerconfig.AuthMethodBearer,
	})
	if errDefinition != nil {
		t.Fatalf("CreateCustomDefinition() error = %v", errDefinition)
	}
	configured, errConfigure := service.ConfigureProvider(ctx, ConfigureProviderInput{
		DefinitionID: definition.ID, Handle: "custom-delivery-migration", DisplayName: "Custom Delivery Migration", BaseURL: "https://custom.example/v1",
		InitialModel: &InitialProviderModelInput{UpstreamModelID: "custom-model", DisplayName: "Custom Model"},
	})
	if errConfigure != nil {
		t.Fatalf("ConfigureProvider() error = %v", errConfigure)
	}
	legacy := configured.Catalog
	legacy.Revision++
	legacy.Offerings[0].Capabilities.Delivery = catalog.DeliveryCapabilities{}
	legacy.Offerings[0].Revision++
	legacy.Offerings[0].CapabilityRevision++
	legacy.Profiles[0].Capabilities.Delivery = catalog.DeliveryCapabilities{}
	legacy.Profiles[0].Operation = ""
	legacy.Profiles[0].ProfileDriver = false
	legacy.Profiles[0].Revision++
	legacy.Profiles[0].CapabilityRevision++
	if errSave := catalogs.Save(ctx, legacy); errSave != nil {
		t.Fatalf("Save() legacy catalog error = %v", errSave)
	}
	changed, errReconcile := ReconcileCustomConversationCatalogs(ctx, configurations, catalogs)
	if errReconcile != nil || changed != 1 {
		t.Fatalf("ReconcileCustomConversationCatalogs() changed=%d error=%v", changed, errReconcile)
	}
	migrated, errMigrated := catalogs.Get(ctx, configured.Configuration.Instance.ID)
	if errMigrated != nil {
		t.Fatalf("Get() migrated catalog error = %v", errMigrated)
	}
	for _, capabilities := range []catalog.ModelCapabilities{migrated.Offerings[0].Capabilities, migrated.Profiles[0].Capabilities} {
		if !capabilities.Delivery.Synchronous || !capabilities.Delivery.Streaming {
			t.Fatalf("migrated delivery = %#v", capabilities.Delivery)
		}
	}
	if migrated.Profiles[0].Operation != vcp.OperationConversationRespond || !migrated.Profiles[0].ProfileDriver {
		t.Fatalf("migrated operation = %q profile_driver=%t", migrated.Profiles[0].Operation, migrated.Profiles[0].ProfileDriver)
	}
	changedAgain, errAgain := ReconcileCustomConversationCatalogs(ctx, configurations, catalogs)
	if errAgain != nil || changedAgain != 0 {
		t.Fatalf("second ReconcileCustomConversationCatalogs() changed=%d error=%v", changedAgain, errAgain)
	}
}
