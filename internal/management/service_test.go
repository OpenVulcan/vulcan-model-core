package management

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	protocolmessages "github.com/OpenVulcan/vulcan-model-core/internal/protocol/anthropic/messages"
	protocolchat "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/chat"
	protocolresponses "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/responses"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// onboardingDeleteFailureStore simulates a secret compensation failure after a successful write.
// onboardingDeleteFailureStore 模拟秘密写入成功后的补偿删除失败。
type onboardingDeleteFailureStore struct {
	// Store delegates successful writes and reads to the in-memory implementation.
	// Store 将成功写入与读取委托给内存实现。
	secret.Store
	// deleteError is returned for every compensation deletion.
	// deleteError 在每次补偿删除时返回。
	deleteError error
}

// Delete returns the configured compensation failure without removing the secret.
// Delete 返回配置的补偿失败且不删除秘密。
func (s *onboardingDeleteFailureStore) Delete(context.Context, string) error {
	return s.deleteError
}

// managementTestService returns a memory-backed service with one system provider definition.
// managementTestService 返回一个包含系统供应商定义的内存应用服务。
func managementTestService(t *testing.T) (*Service, *providerconfig.MemoryStore, *secret.MemoryStore) {
	t.Helper()
	protocols := providerconfig.NewProtocolRegistry()
	if err := protocols.Register(providerconfig.ProtocolProfile{
		ID:                         protocolchat.ProfileID,
		Version:                    "1",
		DisplayName:                "OpenAI Chat Completions",
		UserConfigurable:           true,
		CustomDefinitionCompatible: true,
		RuntimeReady:               true,
		AllowedAuthMethods:         []providerconfig.AuthMethodType{providerconfig.AuthMethodBearer},
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
		ProtocolProfileID:   protocolchat.ProfileID,
		EndpointProfileID:   "default",
		AuthMethodIDs:       []string{"bearer"},
		RuntimeReady:        true,
		AuthMethods: []providerconfig.AuthMethodDefinition{{
			ID:                  "bearer",
			Type:                providerconfig.AuthMethodBearer,
			MultipleCredentials: true,
		}},
		Features: providerconfig.ProviderFeatureSet{
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
	service, errService := NewService(configurations, secrets, catalog.NewMemoryStore())
	if errService != nil {
		t.Fatalf("create management service: %v", errService)
	}
	return service, configurations, secrets
}

// TestConfigureProviderThenAttachCredentialSeparatesProviderAndAccountLifecycles verifies the new two-stage management workflow.
// TestConfigureProviderThenAttachCredentialSeparatesProviderAndAccountLifecycles 验证新的两阶段管理流程。
func TestConfigureProviderThenAttachCredentialSeparatesProviderAndAccountLifecycles(t *testing.T) {
	ctx := context.Background()
	service, configurations, _ := managementTestService(t)
	definition, errDefinition := service.CreateCustomDefinition(ctx, CreateCustomDefinitionInput{
		ID: "custom_separated_lifecycle", DisplayName: "Separated Lifecycle", ProtocolProfileID: protocolchat.ProfileID, AuthMethod: providerconfig.AuthMethodBearer,
	})
	if errDefinition != nil {
		t.Fatalf("CreateCustomDefinition() error = %v", errDefinition)
	}
	configured, errConfigure := service.ConfigureProvider(ctx, ConfigureProviderInput{
		DefinitionID: definition.ID, Handle: "separated-lifecycle", DisplayName: "Separated Lifecycle", BaseURL: "https://separated.example/v1",
		InitialModel: &InitialProviderModelInput{UpstreamModelID: "separated-model", DisplayName: "Separated Model", ContextWindow: 131072, MaxOutputTokens: 8192, ToolCalling: catalog.CapabilityNative, Reasoning: catalog.CapabilityNative},
	})
	if errConfigure != nil {
		t.Fatalf("ConfigureProvider() error = %v", errConfigure)
	}
	if configured.Configuration.Instance.Status != providerconfig.LifecycleDraft || len(configured.Configuration.Endpoints) != 1 || len(configured.Catalog.Models) != 1 || !configured.Catalog.Offerings[0].Capabilities.Tokens.ContextWindow.Known || configured.Catalog.Offerings[0].Capabilities.Tokens.ContextWindow.Value != 131072 || !configured.Catalog.Offerings[0].Capabilities.Delivery.Synchronous || !configured.Catalog.Offerings[0].Capabilities.Delivery.Streaming || configured.Catalog.Profiles[0].Operation != vcp.OperationConversationRespond || !configured.Catalog.Profiles[0].ProfileDriver || !configured.Catalog.Profiles[0].Capabilities.Delivery.Synchronous || !configured.Catalog.Profiles[0].Capabilities.Delivery.Streaming {
		t.Fatalf("configured provider = %#v catalog=%#v", configured.Configuration, configured.Catalog)
	}
	credentials, errCredentials := configurations.ListCredentials(ctx, configured.Configuration.Instance.ID)
	if errCredentials != nil || len(credentials) != 0 {
		t.Fatalf("credentials before attachment=%#v error=%v", credentials, errCredentials)
	}
	attached, errAttach := service.AttachCredential(ctx, AddCredentialInput{
		ProviderInstanceID: configured.Configuration.Instance.ID, AuthMethodID: "default", Label: "Primary", Secret: []byte("separated-secret"),
	})
	if errAttach != nil {
		t.Fatalf("AttachCredential() error = %v", errAttach)
	}
	if len(attached.Bindings) != 1 || attached.Bindings[0].CredentialID != attached.Credential.ID {
		t.Fatalf("credential attachment = %#v", attached)
	}
	instance, errInstance := configurations.GetInstance(ctx, configured.Configuration.Instance.ID)
	if errInstance != nil || instance.Status != providerconfig.LifecycleReady {
		t.Fatalf("activated instance=%#v error=%v", instance, errInstance)
	}
	deletion, errDelete := service.DeleteCredential(ctx, instance.ID, attached.Credential.ID)
	if errDelete != nil || !deletion.InstanceDrafted {
		t.Fatalf("DeleteCredential() deletion=%#v error=%v", deletion, errDelete)
	}
	retained, errRetained := configurations.GetInstance(ctx, instance.ID)
	if errRetained != nil || retained.Status != providerconfig.LifecycleDraft {
		t.Fatalf("retained provider=%#v error=%v", retained, errRetained)
	}
}

// TestSystemOnboardingReportsBuildCompensationFailure verifies a failed graph build never hides an orphaned secret.
// TestSystemOnboardingReportsBuildCompensationFailure 验证配置图构建失败时绝不隐藏孤立秘密。
func TestSystemOnboardingReportsBuildCompensationFailure(t *testing.T) {
	_, configurations, delegate := managementTestService(t)
	deleteError := errors.New("delete staged secret failed")
	secrets := &onboardingDeleteFailureStore{Store: delegate, deleteError: deleteError}
	service, errService := NewService(configurations, secrets, catalog.NewMemoryStore())
	if errService != nil {
		t.Fatalf("NewService() error = %v", errService)
	}
	_, errOnboard := service.OnboardSystemProvider(context.Background(), OnboardSystemProviderInput{
		DefinitionID: "system_management_test", DisplayName: "Build Failure", AuthMethodID: "bearer", CredentialLabel: "Primary", Secret: []byte("staged-secret"),
	})
	if !errors.Is(errOnboard, deleteError) {
		t.Fatalf("OnboardSystemProvider() error = %v, want compensation failure", errOnboard)
	}
	if delegate.Count() != 1 {
		t.Fatalf("orphaned secret count = %d, want explicit single orphan", delegate.Count())
	}
}

// TestCreateCustomDefinitionConstrainsGenericProvider verifies custom provider ownership defaults.
// TestCreateCustomDefinitionConstrainsGenericProvider 校验自定义供应商所有权默认值。
func TestCreateCustomDefinitionConstrainsGenericProvider(t *testing.T) {
	service, _, _ := managementTestService(t)
	definition, errDefinition := service.CreateCustomDefinition(context.Background(), CreateCustomDefinitionInput{
		ID: "custom_private_gateway", DisplayName: "Private Gateway", ProtocolProfileID: protocolchat.ProfileID, AuthMethod: providerconfig.AuthMethodBearer,
	})
	if errDefinition != nil {
		t.Fatalf("create custom provider definition: %v", errDefinition)
	}
	if definition.Kind != providerconfig.DefinitionKindCustom || definition.ProtocolProfileID != protocolchat.ProfileID || definition.EndpointProfileID != providerconfig.CustomEndpointProfileOpenAICompatibility || len(definition.AuthMethods) != 1 {
		t.Fatalf("unexpected custom definition shape: %+v", definition)
	}
	if definition.Features.AllowanceReader != providerconfig.SupportUnsupported {
		t.Fatalf("custom provider allowance support = %s", definition.Features.AllowanceReader)
	}
}

// TestCustomEndpointProfileIDWhitelistsExecutableCompatibilityShapes verifies unsupported protocols cannot receive a generic endpoint shape.
// TestCustomEndpointProfileIDWhitelistsExecutableCompatibilityShapes 验证不受支持的协议不能获得通用 Endpoint 形态。
func TestCustomEndpointProfileIDWhitelistsExecutableCompatibilityShapes(t *testing.T) {
	for _, testCase := range []struct {
		// protocolProfileID is the exact protocol identifier under test.
		// protocolProfileID 是待测的精确协议标识。
		protocolProfileID string
		// expectedEndpointProfileID is the only permitted execution shape.
		// expectedEndpointProfileID 是唯一允许的执行形态。
		expectedEndpointProfileID string
	}{
		{protocolProfileID: protocolchat.ProfileID, expectedEndpointProfileID: providerconfig.CustomEndpointProfileOpenAICompatibility},
		{protocolProfileID: protocolresponses.ProfileID, expectedEndpointProfileID: providerconfig.CustomEndpointProfileOpenAIResponsesCompatibility},
		{protocolProfileID: protocolmessages.ProfileID, expectedEndpointProfileID: providerconfig.CustomEndpointProfileAnthropicMessagesCompatibility},
		{protocolProfileID: "google.interactions", expectedEndpointProfileID: ""},
	} {
		if actual := customEndpointProfileID(testCase.protocolProfileID); actual != testCase.expectedEndpointProfileID {
			t.Fatalf("customEndpointProfileID(%q) = %q, want %q", testCase.protocolProfileID, actual, testCase.expectedEndpointProfileID)
		}
	}
}

// TestCustomProviderAuthMethodRestrictsNewProvidersToThreeStandardProtocols verifies special provider protocols cannot enter generic onboarding.
// TestCustomProviderAuthMethodRestrictsNewProvidersToThreeStandardProtocols 验证特殊供应商协议无法进入通用录入流程。
func TestCustomProviderAuthMethodRestrictsNewProvidersToThreeStandardProtocols(t *testing.T) {
	for _, testCase := range []struct {
		// protocolProfileID is the exact selectable protocol identifier.
		// protocolProfileID 是精确的可选协议标识。
		protocolProfileID string
		// expectedAuthMethod is the protocol-owned secret carrier.
		// expectedAuthMethod 是协议拥有的 Secret 载体。
		expectedAuthMethod providerconfig.AuthMethodType
	}{
		{protocolProfileID: protocolchat.ProfileID, expectedAuthMethod: providerconfig.AuthMethodBearer},
		{protocolProfileID: protocolresponses.ProfileID, expectedAuthMethod: providerconfig.AuthMethodBearer},
		{protocolProfileID: protocolmessages.ProfileID, expectedAuthMethod: providerconfig.AuthMethodHeaderKey},
	} {
		actualAuthMethod, errAuthMethod := customProviderAuthMethod(testCase.protocolProfileID)
		if errAuthMethod != nil || actualAuthMethod != testCase.expectedAuthMethod {
			t.Fatalf("customProviderAuthMethod(%q) = %q, %v; want %q", testCase.protocolProfileID, actualAuthMethod, errAuthMethod, testCase.expectedAuthMethod)
		}
	}
	if _, errAuthMethod := customProviderAuthMethod("google.aistudio"); errAuthMethod == nil {
		t.Fatal("customProviderAuthMethod(google.aistudio) error = nil")
	}
}

// TestOnboardCustomProviderCommitsOneNameSecretGraphAndCatalog verifies the complete compatibility onboarding boundary.
// TestOnboardCustomProviderCommitsOneNameSecretGraphAndCatalog 验证完整兼容供应商录入边界。
func TestOnboardCustomProviderCommitsOneNameSecretGraphAndCatalog(t *testing.T) {
	ctx := context.Background()
	service, configurations, secrets := managementTestService(t)
	result, errOnboard := service.OnboardCustomProvider(ctx, OnboardCustomProviderInput{
		DisplayName: "Private Gateway", Handle: "private-gateway", ProtocolProfileID: protocolchat.ProfileID,
		BaseURL: "https://gateway.example/openai/v1", Secret: []byte("private-key"), UpstreamModelID: "model-upstream", ModelDisplayName: "Private Model",
	})
	if errOnboard != nil {
		t.Fatalf("OnboardCustomProvider() error = %v", errOnboard)
	}
	configuration := result.Configuration
	if configuration.Definition.EndpointProfileID != providerconfig.CustomEndpointProfileOpenAICompatibility || configuration.Definition.AuthMethods[0].Type != providerconfig.AuthMethodBearer {
		t.Fatalf("unexpected custom definition: %#v", configuration.Definition)
	}
	if configuration.Instance.DisplayName != "Private Gateway" || configuration.Credential.Label != "Private Gateway" || configuration.Endpoint.BaseURL != "https://gateway.example/openai/v1" || !configuration.Binding.Enabled {
		t.Fatalf("unexpected custom access graph: %#v", configuration)
	}
	storedSecret, errSecret := secrets.Get(ctx, configuration.Credential.SecretRef)
	if errSecret != nil || string(storedSecret) != "private-key" {
		t.Fatalf("stored secret = %q, error = %v", storedSecret, errSecret)
	}
	if _, errDefinition := configurations.GetDefinition(ctx, configuration.Definition.ID); errDefinition != nil {
		t.Fatalf("GetDefinition() error = %v", errDefinition)
	}
	if len(result.Catalog.Models) != 1 || result.Catalog.Models[0].UpstreamModelID != "model-upstream" || result.Catalog.Offerings[0].Capabilities.ToolCalling != catalog.CapabilityUnknown || len(result.Catalog.Pools) != 1 || result.Catalog.Pools[0].ReadyCredentials != 1 {
		t.Fatalf("unexpected initial custom catalog: %#v", result.Catalog)
	}
}

// TestOnboardCustomProviderCompensatesCatalogFailure verifies no definition, graph, or secret survives a failed catalog commit.
// TestOnboardCustomProviderCompensatesCatalogFailure 验证目录提交失败后不会遗留 Definition、访问图或 Secret。
func TestOnboardCustomProviderCompensatesCatalogFailure(t *testing.T) {
	ctx := context.Background()
	_, configurations, secrets := managementTestService(t)
	service, errService := NewService(configurations, secrets, failingCatalogStore{})
	if errService != nil {
		t.Fatalf("NewService() error = %v", errService)
	}
	_, errOnboard := service.OnboardCustomProvider(ctx, OnboardCustomProviderInput{
		DisplayName: "Failed Gateway", Handle: "failed-gateway", ProtocolProfileID: protocolchat.ProfileID,
		BaseURL: "https://failed.example/v1", Secret: []byte("temporary-key"), UpstreamModelID: "failed-model",
	})
	if errOnboard == nil {
		t.Fatal("OnboardCustomProvider() error = nil, want catalog failure")
	}
	definitions, errDefinitions := configurations.ListDefinitions(ctx)
	if errDefinitions != nil {
		t.Fatalf("ListDefinitions() error = %v", errDefinitions)
	}
	for _, definition := range definitions {
		if definition.Kind == providerconfig.DefinitionKindCustom {
			t.Fatalf("custom definition survived compensation: %#v", definition)
		}
	}
	instances, errInstances := configurations.ListInstances(ctx, "")
	if errInstances != nil || len(instances) != 0 || secrets.Count() != 0 {
		t.Fatalf("compensation instances=%#v error=%v secrets=%d", instances, errInstances, secrets.Count())
	}
}

// TestUpdateCustomDefinitionMarksExistingInstancesForMigration verifies definition edits cannot leave stale instances executable.
// TestUpdateCustomDefinitionMarksExistingInstancesForMigration 验证定义编辑不会让过期实例继续可执行。
func TestUpdateCustomDefinitionMarksExistingInstancesForMigration(t *testing.T) {
	// ctx fixes the operation scope for the complete configuration transition.
	// ctx 为完整配置转换固定操作范围。
	ctx := context.Background()
	// service and configurations share the same memory-backed configuration state.
	// service 和 configurations 共享同一个内存后端配置状态。
	service, configurations, _ := managementTestService(t)
	definition, errDefinition := service.CreateCustomDefinition(ctx, CreateCustomDefinitionInput{
		ID: "custom_editable", DisplayName: "Before Edit", ProtocolProfileID: protocolchat.ProfileID, AuthMethod: providerconfig.AuthMethodBearer,
	})
	if errDefinition != nil {
		t.Fatalf("create custom provider definition: %v", errDefinition)
	}
	instance, errInstance := service.CreateInstance(ctx, CreateInstanceInput{
		ID: "pvi_editable", DefinitionID: definition.ID, Handle: "before-edit", DisplayName: "Before Edit",
	})
	if errInstance != nil {
		t.Fatalf("create custom provider instance: %v", errInstance)
	}
	updated, errUpdate := service.UpdateCustomDefinition(ctx, UpdateCustomDefinitionInput{
		DefinitionID: definition.ID, DisplayName: "After Edit", ProtocolProfileID: protocolchat.ProfileID, AuthMethod: providerconfig.AuthMethodBearer,
	})
	if errUpdate != nil {
		t.Fatalf("update custom provider definition: %v", errUpdate)
	}
	if updated.Revision != definition.Revision+1 || updated.DisplayName != "After Edit" {
		t.Fatalf("updated definition = %+v", updated)
	}
	storedInstance, errGetInstance := configurations.GetInstance(ctx, instance.ID)
	if errGetInstance != nil {
		t.Fatalf("get migrated provider instance: %v", errGetInstance)
	}
	if storedInstance.Status != providerconfig.LifecycleMigrationRequired || storedInstance.DefinitionRevision != updated.Revision || storedInstance.Revision != instance.Revision+1 {
		t.Fatalf("migrated provider instance = %+v", storedInstance)
	}
	_, errSystemUpdate := service.UpdateCustomDefinition(ctx, UpdateCustomDefinitionInput{
		DefinitionID: "system_management_test", DisplayName: "Forbidden", ProtocolProfileID: protocolchat.ProfileID, AuthMethod: providerconfig.AuthMethodBearer,
	})
	if !errors.Is(errSystemUpdate, ErrSystemDefinitionImmutable) {
		t.Fatalf("system definition update error = %v, want ErrSystemDefinitionImmutable", errSystemUpdate)
	}
}

// TestRotateCredentialSecretReplacesProtectedMaterial verifies rotation deletes prior secret material only after metadata persistence.
// TestRotateCredentialSecretReplacesProtectedMaterial 验证轮换仅在元数据持久化后删除旧 Secret 材料。
func TestRotateCredentialSecretReplacesProtectedMaterial(t *testing.T) {
	// ctx fixes the complete credential lifecycle operation scope.
	// ctx 为完整凭据生命周期操作固定范围。
	ctx := context.Background()
	// service and secrets expose the same memory-backed management state.
	// service 和 secrets 暴露同一个内存后端管理状态。
	service, _, secrets := managementTestService(t)
	instance, errInstance := service.CreateInstance(ctx, CreateInstanceInput{
		ID: "pvi_rotation", DefinitionID: "system_management_test", Handle: "rotation", DisplayName: "Rotation",
	})
	if errInstance != nil {
		t.Fatalf("create provider instance: %v", errInstance)
	}
	credential, errCredential := service.AddCredential(ctx, AddCredentialInput{
		ID: "cred_rotation", ProviderInstanceID: instance.ID, AuthMethodID: "bearer", Label: "Before Rotation",
		PrincipalKey: "rotation-account", Secret: []byte("before-secret"),
	})
	if errCredential != nil {
		t.Fatalf("create credential: %v", errCredential)
	}
	previousReference := credential.SecretRef
	if credential.Fingerprint != credentialFingerprint([]byte("before-secret")) {
		t.Fatalf("initial credential fingerprint = %q", credential.Fingerprint)
	}
	rotated, errRotate := service.RotateCredentialSecret(ctx, RotateCredentialSecretInput{
		ProviderInstanceID: instance.ID, CredentialID: credential.ID, Secret: []byte("after-secret"),
	})
	if errRotate != nil {
		t.Fatalf("rotate credential secret: %v", errRotate)
	}
	if rotated.SecretRef == previousReference || rotated.Revision != credential.Revision+1 || rotated.Fingerprint != credentialFingerprint([]byte("after-secret")) {
		t.Fatalf("rotated credential = %+v", rotated)
	}
	if _, errOldSecret := secrets.Get(ctx, previousReference); !errors.Is(errOldSecret, secret.ErrNotFound) {
		t.Fatalf("old secret lookup error = %v, want ErrNotFound", errOldSecret)
	}
	storedSecret, errNewSecret := secrets.Get(ctx, rotated.SecretRef)
	if errNewSecret != nil {
		t.Fatalf("get rotated secret: %v", errNewSecret)
	}
	if string(storedSecret) != "after-secret" || secrets.Count() != 1 {
		t.Fatalf("rotated secret value=%q count=%d", storedSecret, secrets.Count())
	}
}

// TestCredentialFingerprintIsServerOwnedAndStable verifies duplicate detection cannot be bypassed and metadata edits preserve the derived identity.
// TestCredentialFingerprintIsServerOwnedAndStable 验证重复检测无法被绕过且元数据编辑会保留服务端派生身份。
func TestCredentialFingerprintIsServerOwnedAndStable(t *testing.T) {
	// ctx fixes the complete server-owned fingerprint operation scope.
	// ctx 固定完整的服务端指纹操作范围。
	ctx := context.Background()
	service, _, secrets := managementTestService(t)
	instance, errInstance := service.CreateInstance(ctx, CreateInstanceInput{
		ID: "pvi_fingerprint", DefinitionID: "system_management_test", Handle: "fingerprint", DisplayName: "Fingerprint",
	})
	if errInstance != nil {
		t.Fatalf("create provider instance: %v", errInstance)
	}
	first, errFirst := service.AddCredential(ctx, AddCredentialInput{
		ID: "cred_fingerprint_first", ProviderInstanceID: instance.ID, AuthMethodID: "bearer", Label: "First",
		PrincipalKey: "account-first", Secret: []byte("shared-secret"),
	})
	if errFirst != nil {
		t.Fatalf("create first credential: %v", errFirst)
	}
	// expectedFingerprint proves management derives identity from the exact protected bytes.
	// expectedFingerprint 证明管理层从精确的受保护字节派生身份。
	expectedFingerprint := credentialFingerprint([]byte("shared-secret"))
	if first.Fingerprint != expectedFingerprint {
		t.Fatalf("first fingerprint = %q, want %q", first.Fingerprint, expectedFingerprint)
	}
	updated, errUpdate := service.UpdateCredential(ctx, UpdateCredentialInput{
		ProviderInstanceID: instance.ID, CredentialID: first.ID, Label: "Renamed", PrincipalKey: "account-renamed",
	})
	if errUpdate != nil {
		t.Fatalf("update credential metadata: %v", errUpdate)
	}
	if updated.Fingerprint != expectedFingerprint || updated.SecretRef != first.SecretRef {
		t.Fatalf("metadata update changed protected identity: %+v", updated)
	}
	_, errDuplicate := service.AddCredential(ctx, AddCredentialInput{
		ID: "cred_fingerprint_second", ProviderInstanceID: instance.ID, AuthMethodID: "bearer", Label: "Duplicate",
		PrincipalKey: "account-second", Secret: []byte("shared-secret"),
	})
	if !errors.Is(errDuplicate, providerconfig.ErrAlreadyRegistered) {
		t.Fatalf("duplicate secret error = %v, want ErrAlreadyRegistered", errDuplicate)
	}
	if secrets.Count() != 1 {
		t.Fatalf("protected secret count = %d, want 1", secrets.Count())
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
		ID: "invalid_compensation", ProviderInstanceID: instance.ID, AuthMethodID: "bearer", Label: "Invalid",
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
		ID: "ep_activation", ProviderInstanceID: instance.ID, BaseURL: "https://activation.example/v1",
	})
	if errEndpoint != nil {
		t.Fatalf("add endpoint: %v", errEndpoint)
	}
	credential, errCredential := service.AddCredential(ctx, AddCredentialInput{
		ID: "cred_activation", ProviderInstanceID: instance.ID, AuthMethodID: "bearer", Label: "Account",
		PrincipalKey: "account-activation", Secret: []byte("activation-secret"),
	})
	if errCredential != nil {
		t.Fatalf("add credential: %v", errCredential)
	}
	if _, errActivate := service.ActivateInstance(ctx, instance.ID); !errors.Is(errActivate, ErrConfigurationIncomplete) {
		t.Fatalf("expected missing binding rejection, got %v", errActivate)
	}
	if _, errBinding := service.AddBinding(ctx, AddBindingInput{
		ID: "bind_activation", ProviderInstanceID: instance.ID, EndpointID: endpoint.ID, CredentialID: credential.ID,
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
		ID: "custom_catalog", DisplayName: "Custom Catalog", ProtocolProfileID: protocolchat.ProfileID, AuthMethod: providerconfig.AuthMethodBearer,
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
		ID: "ep_custom_catalog", ProviderInstanceID: instance.ID, BaseURL: "https://custom.example/v1",
	})
	if errEndpoint != nil {
		t.Fatalf("add custom endpoint: %v", errEndpoint)
	}
	credential, errCredential := service.AddCredential(ctx, AddCredentialInput{
		ID: "cred_custom_catalog", ProviderInstanceID: instance.ID, AuthMethodID: "default", Label: "Key",
		Secret: []byte("custom-secret"),
	})
	if errCredential != nil {
		t.Fatalf("add custom credential: %v", errCredential)
	}
	if _, errBinding := service.AddBinding(ctx, AddBindingInput{
		ID: "bind_custom_catalog", ProviderInstanceID: instance.ID, EndpointID: endpoint.ID, CredentialID: credential.ID,
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
			ID: "offer_custom_example", ProviderInstanceID: instance.ID, ProviderModelID: "model_custom_example",
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
	if len(snapshot.Models) != 1 || len(snapshot.Pools) != 1 || snapshot.Pools[0].ReadyCredentials != 1 || snapshot.Offerings[0].ChannelID != definition.ProtocolProfileID {
		t.Fatalf("unexpected custom catalog snapshot: %+v", snapshot)
	}
	secondSnapshot, errSecondSave := catalogService.SaveCustomCatalog(ctx, SaveCustomCatalogInput{
		ProviderInstanceID: instance.ID,
		Models:             snapshot.Models,
		Offerings:          snapshot.Offerings,
		Profiles:           snapshot.Profiles,
		ObservedAt:         observedAt.Add(time.Minute),
	})
	if errSecondSave != nil {
		t.Fatalf("save second custom catalog revision: %v", errSecondSave)
	}
	if secondSnapshot.Revision != snapshot.Revision+1 || secondSnapshot.Models[0].Revision != secondSnapshot.Revision || secondSnapshot.Offerings[0].CapabilityRevision != secondSnapshot.Revision || secondSnapshot.Profiles[0].Revision != secondSnapshot.Revision {
		t.Fatalf("custom catalog did not assign authoritative revisions: %+v", secondSnapshot)
	}
	loaded, errLoad := catalogService.GetCustomCatalog(ctx, instance.ID)
	if errLoad != nil {
		t.Fatalf("get custom catalog: %v", errLoad)
	}
	if loaded.Revision != secondSnapshot.Revision || len(loaded.Offerings) != 1 || len(loaded.Profiles) != 1 {
		t.Fatalf("unexpected loaded custom catalog: %+v", loaded)
	}
}

// TestCustomCatalogServiceRejectsSystemProvider verifies user-declared model metadata cannot mutate system provider ownership.
// TestCustomCatalogServiceRejectsSystemProvider 校验用户声明模型元数据不能修改系统供应商归属。
func TestCustomCatalogServiceRejectsSystemProvider(t *testing.T) {
	// ctx fixes the complete system-instance rejection operation scope.
	// ctx 固定完整系统实例拒绝操作范围。
	ctx := context.Background()
	service, configurations, _ := managementTestService(t)
	instance, errInstance := service.CreateInstance(ctx, CreateInstanceInput{
		ID: "pvi_system_catalog", DefinitionID: "system_management_test", Handle: "system-catalog", DisplayName: "System Catalog",
	})
	if errInstance != nil {
		t.Fatalf("create system provider instance: %v", errInstance)
	}
	catalogService, errCatalogService := NewCustomCatalogService(configurations, catalog.NewMemoryStore())
	if errCatalogService != nil {
		t.Fatalf("create custom catalog service: %v", errCatalogService)
	}
	_, errGet := catalogService.GetCustomCatalog(ctx, instance.ID)
	if !errors.Is(errGet, ErrCustomCatalogRequiresCustomProvider) {
		t.Fatalf("get system custom catalog error = %v, want ErrCustomCatalogRequiresCustomProvider", errGet)
	}
}
