package management

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

// managementTestService returns a memory-backed service with one system provider definition.
// managementTestService 返回一个包含系统供应商定义的内存应用服务。
func managementTestService(t *testing.T) (*Service, *providerconfig.MemoryStore, *secret.MemoryStore) {
	t.Helper()
	protocols := providerconfig.NewProtocolRegistry()
	if err := protocols.Register(providerconfig.ProtocolProfile{
		ID:                 "anthropic.messages.v1",
		Version:            "1",
		DisplayName:        "Anthropic Messages",
		UserConfigurable:   true,
		RuntimeReady:       true,
		ModelDiscovery:     providerconfig.SupportUnsupported,
		AllowedAuthMethods: []providerconfig.AuthMethodType{providerconfig.AuthMethodBearer},
	}); err != nil {
		t.Fatalf("register protocol profile: %v", err)
	}
	systems, errSystems := providerconfig.NewSystemRegistry(protocols)
	if errSystems != nil {
		t.Fatalf("create system registry: %v", errSystems)
	}
	if err := systems.Register(providerconfig.ProviderDefinition{
		ID:                  "system_management_test",
		Kind:                providerconfig.DefinitionKindSystem,
		DisplayName:         "Management Test",
		DriverID:            "management-test",
		DriverVersion:       "1.0.0",
		ConfigSchemaVersion: "1",
		Channels: []providerconfig.ProviderChannel{{
			ID:                "anthropic",
			ProtocolProfileID: "anthropic.messages.v1",
			EndpointProfileID: "default",
			AuthMethodIDs:     []string{"oauth"},
			RuntimeReady:      true,
		}},
		AuthMethods: []providerconfig.AuthMethodDefinition{{
			ID:                  "oauth",
			Type:                providerconfig.AuthMethodOAuth,
			Refreshable:         true,
			MultipleCredentials: true,
		}},
		Features: providerconfig.ProviderFeatureSet{
			ModelDiscovery:    providerconfig.SupportUnsupported,
			PlanReader:        providerconfig.SupportUnsupported,
			EntitlementReader: providerconfig.SupportUnsupported,
			AllowanceReader:   providerconfig.SupportUnsupported,
		},
		Revision: 1,
	}); err != nil {
		t.Fatalf("register system definition: %v", err)
	}
	configurations, errConfigurations := providerconfig.NewMemoryStore(protocols, systems)
	if errConfigurations != nil {
		t.Fatalf("create configuration store: %v", errConfigurations)
	}
	secrets := secret.NewMemoryStore()
	service, errService := NewService(configurations, secrets)
	if errService != nil {
		t.Fatalf("create management service: %v", errService)
	}
	return service, configurations, secrets
}

// TestCreateCustomDefinitionConstrainsGenericProvider verifies custom provider ownership defaults.
// TestCreateCustomDefinitionConstrainsGenericProvider 校验自定义供应商所有权默认值。
func TestCreateCustomDefinitionConstrainsGenericProvider(t *testing.T) {
	service, _, _ := managementTestService(t)
	definition, errDefinition := service.CreateCustomDefinition(context.Background(), CreateCustomDefinitionInput{
		ID: "custom_private_gateway", DisplayName: "Private Gateway", ProtocolProfileID: "anthropic.messages.v1", AuthMethod: providerconfig.AuthMethodBearer,
	})
	if errDefinition != nil {
		t.Fatalf("create custom provider definition: %v", errDefinition)
	}
	if definition.Kind != providerconfig.DefinitionKindCustom || len(definition.Channels) != 1 || len(definition.AuthMethods) != 1 {
		t.Fatalf("unexpected custom definition shape: %+v", definition)
	}
	if definition.Features.AllowanceReader != providerconfig.SupportUnsupported {
		t.Fatalf("custom provider allowance support = %s", definition.Features.AllowanceReader)
	}
}

// TestAddCredentialCompensatesSecret verifies failed metadata writes do not orphan secrets.
// TestAddCredentialCompensatesSecret 校验元数据写入失败不会遗留孤立 Secret。
func TestAddCredentialCompensatesSecret(t *testing.T) {
	service, _, secrets := managementTestService(t)
	instance, errInstance := service.CreateInstance(context.Background(), CreateInstanceInput{
		ID: "pvi_compensation", DefinitionID: "system_management_test", Handle: "compensation", DisplayName: "Compensation",
	})
	if errInstance != nil {
		t.Fatalf("create provider instance: %v", errInstance)
	}
	_, errCredential := service.AddCredential(context.Background(), AddCredentialInput{
		ID: "cred_compensation", ProviderInstanceID: instance.ID, AuthMethodID: "oauth", Label: "Invalid",
		PrincipalKey: "account-invalid", Secret: []byte("temporary-secret"),
	})
	if errCredential == nil {
		t.Fatal("expected invalid credential metadata rejection")
	}
	if secrets.Count() != 0 {
		t.Fatalf("orphan secret count = %d, want 0", secrets.Count())
	}
}

// TestActivateInstanceRequiresClosedAccessPath verifies the local lifecycle gate.
// TestActivateInstanceRequiresClosedAccessPath 校验本地生命周期门禁。
func TestActivateInstanceRequiresClosedAccessPath(t *testing.T) {
	ctx := context.Background()
	service, _, _ := managementTestService(t)
	instance, errInstance := service.CreateInstance(ctx, CreateInstanceInput{
		ID: "pvi_activation", DefinitionID: "system_management_test", Handle: "activation", DisplayName: "Activation",
	})
	if errInstance != nil {
		t.Fatalf("create provider instance: %v", errInstance)
	}
	if _, errActivate := service.ActivateInstance(ctx, instance.ID); !errors.Is(errActivate, ErrConfigurationIncomplete) {
		t.Fatalf("expected incomplete configuration, got %v", errActivate)
	}
	endpoint, errEndpoint := service.AddEndpoint(ctx, AddEndpointInput{
		ID: "ep_activation", ProviderInstanceID: instance.ID, ChannelID: "anthropic", BaseURL: "https://activation.example/v1",
	})
	if errEndpoint != nil {
		t.Fatalf("add endpoint: %v", errEndpoint)
	}
	credential, errCredential := service.AddCredential(ctx, AddCredentialInput{
		ID: "cred_activation", ProviderInstanceID: instance.ID, AuthMethodID: "oauth", Label: "Account",
		PrincipalKey: "account-activation", Fingerprint: "fingerprint-activation", Secret: []byte("activation-secret"),
	})
	if errCredential != nil {
		t.Fatalf("add credential: %v", errCredential)
	}
	if _, errActivate := service.ActivateInstance(ctx, instance.ID); !errors.Is(errActivate, ErrConfigurationIncomplete) {
		t.Fatalf("expected missing binding rejection, got %v", errActivate)
	}
	if _, errBinding := service.AddBinding(ctx, AddBindingInput{
		ID: "bind_activation", ProviderInstanceID: instance.ID, ChannelID: "anthropic", EndpointID: endpoint.ID, CredentialID: credential.ID,
	}); errBinding != nil {
		t.Fatalf("add access binding: %v", errBinding)
	}
	activated, errActivate := service.ActivateInstance(ctx, instance.ID)
	if errActivate != nil {
		t.Fatalf("activate provider instance: %v", errActivate)
	}
	if activated.Status != providerconfig.LifecycleReady || activated.Revision != 2 {
		t.Fatalf("activated status=%s revision=%d", activated.Status, activated.Revision)
	}
	disabled, errDisable := service.SetCredentialStatus(ctx, SetCredentialStatusInput{
		ProviderInstanceID: instance.ID, CredentialID: credential.ID, Status: providerconfig.CredentialDisabled,
	})
	if errDisable != nil {
		t.Fatalf("disable credential: %v", errDisable)
	}
	if disabled.Status != providerconfig.CredentialDisabled || disabled.Revision != 2 || disabled.SecretRef != credential.SecretRef {
		t.Fatalf("unexpected disabled credential: %+v", disabled)
	}
}

// TestCustomCatalogServicePersistsUserDeclaredModels verifies custom-provider model configuration.
// TestCustomCatalogServicePersistsUserDeclaredModels 校验自定义供应商模型配置。
func TestCustomCatalogServicePersistsUserDeclaredModels(t *testing.T) {
	ctx := context.Background()
	service, configurations, _ := managementTestService(t)
	definition, errDefinition := service.CreateCustomDefinition(ctx, CreateCustomDefinitionInput{
		ID: "custom_catalog", DisplayName: "Custom Catalog", ProtocolProfileID: "anthropic.messages.v1", AuthMethod: providerconfig.AuthMethodBearer,
	})
	if errDefinition != nil {
		t.Fatalf("create custom provider definition: %v", errDefinition)
	}
	instance, errInstance := service.CreateInstance(ctx, CreateInstanceInput{
		ID: "pvi_custom_catalog", DefinitionID: definition.ID, Handle: "custom-catalog", DisplayName: "Custom Catalog",
	})
	if errInstance != nil {
		t.Fatalf("create custom provider instance: %v", errInstance)
	}
	endpoint, errEndpoint := service.AddEndpoint(ctx, AddEndpointInput{
		ID: "ep_custom_catalog", ProviderInstanceID: instance.ID, ChannelID: "default", BaseURL: "https://custom.example/v1",
	})
	if errEndpoint != nil {
		t.Fatalf("add custom endpoint: %v", errEndpoint)
	}
	credential, errCredential := service.AddCredential(ctx, AddCredentialInput{
		ID: "cred_custom_catalog", ProviderInstanceID: instance.ID, AuthMethodID: "default", Label: "Key",
		Fingerprint: "fingerprint-custom-catalog", Secret: []byte("custom-secret"),
	})
	if errCredential != nil {
		t.Fatalf("add custom credential: %v", errCredential)
	}
	if _, errBinding := service.AddBinding(ctx, AddBindingInput{
		ID: "bind_custom_catalog", ProviderInstanceID: instance.ID, ChannelID: "default", EndpointID: endpoint.ID, CredentialID: credential.ID,
	}); errBinding != nil {
		t.Fatalf("add custom binding: %v", errBinding)
	}
	if _, errActivate := service.ActivateInstance(ctx, instance.ID); errActivate != nil {
		t.Fatalf("activate custom instance: %v", errActivate)
	}
	catalogs := catalog.NewMemoryStore()
	catalogService, errCatalogService := NewCustomCatalogService(configurations, catalogs)
	if errCatalogService != nil {
		t.Fatalf("create custom catalog service: %v", errCatalogService)
	}
	observedAt := time.Date(2026, 7, 17, 16, 0, 0, 0, time.UTC)
	capabilities := catalog.ModelCapabilities{
		Tokens:                 catalog.TokenLimits{ContextWindow: catalog.OptionalTokenLimit{Known: true, Value: 131072}},
		ToolCalling:            catalog.CapabilityNative,
		ParallelToolCalls:      catalog.CapabilityUnsupported,
		StreamingToolArguments: catalog.CapabilityUnsupported,
		StrictJSONSchema:       catalog.CapabilityUnknown,
		Reasoning:              catalog.CapabilityUnsupported,
		InputModalities:        []string{"text"},
		OutputModalities:       []string{"text"},
	}
	snapshot, errSave := catalogService.SaveCustomCatalog(ctx, SaveCustomCatalogInput{
		ProviderInstanceID: instance.ID,
		Models: []catalog.ProviderModel{{
			ID: "model_custom_example", ProviderInstanceID: instance.ID, UpstreamModelID: "custom-model", DisplayName: "Custom Model",
			Source: catalog.ModelSourceUserDeclared, EntitlementMode: catalog.EntitlementAllBoundCredentials, Revision: 1,
		}},
		Offerings: []catalog.ModelOffering{{
			ID: "offer_custom_example", ProviderInstanceID: instance.ID, ProviderModelID: "model_custom_example", ChannelID: "default",
			UpstreamModelID: "custom-model", Capabilities: capabilities, CapabilityRevision: 1, Revision: 1,
		}},
		Profiles: []catalog.ExecutionProfile{{
			ID: "profile_custom_default", ProviderInstanceID: instance.ID, OfferingID: "offer_custom_example", DisplayName: "Default", Default: true,
			Capabilities: capabilities, SwitchPolicy: catalog.ProfileSwitchSeamless, PoolPolicy: catalog.PoolStrictProfile, CapabilityRevision: 1, Revision: 1,
		}},
		ObservedAt: observedAt,
	})
	if errSave != nil {
		t.Fatalf("save custom catalog: %v", errSave)
	}
	if len(snapshot.Models) != 1 || len(snapshot.Pools) != 1 || snapshot.Pools[0].ReadyCredentials != 1 {
		t.Fatalf("unexpected custom catalog snapshot: %+v", snapshot)
	}
}
