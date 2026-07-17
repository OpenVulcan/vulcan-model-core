package providerconfig

import (
	"context"
	"errors"
	"testing"
	"time"
)

// testProtocolProfile returns one ready user-configurable protocol metadata fixture.
// testProtocolProfile 返回一个就绪且允许用户配置的协议元数据测试夹具。
func testProtocolProfile() ProtocolProfile {
	return ProtocolProfile{
		ID:                 "openai.responses.v1",
		Version:            "1",
		DisplayName:        "OpenAI Responses",
		UserConfigurable:   true,
		RuntimeReady:       true,
		ModelDiscovery:     SupportSupported,
		AllowedAuthMethods: []AuthMethodType{AuthMethodBearer, AuthMethodHeaderKey},
	}
}

// testFeatureSet returns an explicitly unsupported optional feature set.
// testFeatureSet 返回一组显式不支持的可选能力测试夹具。
func testFeatureSet() ProviderFeatureSet {
	return ProviderFeatureSet{
		ModelDiscovery:    SupportUnsupported,
		PlanReader:        SupportUnsupported,
		EntitlementReader: SupportUnsupported,
		AllowanceReader:   SupportUnsupported,
	}
}

// testSystemDefinition returns one immutable code-owned provider fixture.
// testSystemDefinition 返回一个不可变的代码拥有供应商测试夹具。
func testSystemDefinition() ProviderDefinition {
	return ProviderDefinition{
		ID:                  "system_test_provider",
		Kind:                DefinitionKindSystem,
		DisplayName:         "System Test Provider",
		DriverID:            "test_provider_driver",
		DriverVersion:       "1",
		ConfigSchemaVersion: "1",
		Channels: []ProviderChannel{{
			ID:                "responses",
			ProtocolProfileID: "openai.responses.v1",
			EndpointProfileID: "system_fixed",
			AuthMethodIDs:     []string{"oauth", "api_key"},
			RuntimeReady:      true,
		}},
		AuthMethods: []AuthMethodDefinition{
			{ID: "oauth", Type: AuthMethodOAuth, Refreshable: true, MultipleCredentials: true},
			{ID: "api_key", Type: AuthMethodAPIKey, MultipleCredentials: true},
		},
		Features: testFeatureSet(),
		Revision: 1,
	}
}

// testCustomDefinition returns one persisted generic provider fixture.
// testCustomDefinition 返回一个持久化通用供应商测试夹具。
func testCustomDefinition() ProviderDefinition {
	return ProviderDefinition{
		ID:                  "custom_test_provider",
		Kind:                DefinitionKindCustom,
		DisplayName:         "Custom Test Provider",
		ConfigSchemaVersion: "1",
		Channels: []ProviderChannel{{
			ID:                "responses",
			ProtocolProfileID: "openai.responses.v1",
			EndpointProfileID: "custom_base_url",
			AuthMethodIDs:     []string{"bearer"},
			RuntimeReady:      true,
		}},
		AuthMethods: []AuthMethodDefinition{{
			ID:                  "bearer",
			Type:                AuthMethodBearer,
			MultipleCredentials: true,
		}},
		Features: testFeatureSet(),
		Revision: 1,
	}
}

// testConfigurationStore creates initialized registries and one memory store.
// testConfigurationStore 创建初始化后的注册表和一个内存存储。
func testConfigurationStore(t *testing.T) (*MemoryStore, *SystemRegistry) {
	t.Helper()
	protocols := NewProtocolRegistry()
	if err := protocols.Register(testProtocolProfile()); err != nil {
		t.Fatalf("register protocol profile: %v", err)
	}
	systems, errSystems := NewSystemRegistry(protocols)
	if errSystems != nil {
		t.Fatalf("create system registry: %v", errSystems)
	}
	if err := systems.Register(testSystemDefinition()); err != nil {
		t.Fatalf("register system definition: %v", err)
	}
	store, errStore := NewMemoryStore(protocols, systems)
	if errStore != nil {
		t.Fatalf("create memory store: %v", errStore)
	}
	return store, systems
}

// testInstance returns one ready provider instance fixture.
// testInstance 返回一个就绪供应商实例测试夹具。
func testInstance(id string, handle string, definitionID string) ProviderInstance {
	now := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	return ProviderInstance{
		ID:                 id,
		DefinitionID:       definitionID,
		Handle:             handle,
		DisplayName:        handle,
		Status:             LifecycleReady,
		Revision:           1,
		DefinitionRevision: 1,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
}

// TestRegistriesEnforceDefinitionOwnership verifies immutable system and configurable custom boundaries.
// TestRegistriesEnforceDefinitionOwnership 校验不可变系统和可配置自定义边界。
func TestRegistriesEnforceDefinitionOwnership(t *testing.T) {
	protocols := NewProtocolRegistry()
	if err := protocols.Register(testProtocolProfile()); err != nil {
		t.Fatalf("register protocol profile: %v", err)
	}
	systems, errSystems := NewSystemRegistry(protocols)
	if errSystems != nil {
		t.Fatalf("create system registry: %v", errSystems)
	}
	if err := systems.Register(testSystemDefinition()); err != nil {
		t.Fatalf("register system definition: %v", err)
	}
	if err := systems.Register(testSystemDefinition()); !errors.Is(err, ErrAlreadyRegistered) {
		t.Fatalf("expected duplicate system definition error, got %v", err)
	}
	if err := systems.Register(testCustomDefinition()); err == nil {
		t.Fatal("expected system registry to reject custom definition")
	}
	if err := ValidateCustomDefinition(testCustomDefinition(), protocols); err != nil {
		t.Fatalf("validate custom definition: %v", err)
	}
	invalidCustom := testCustomDefinition()
	invalidCustom.AuthMethods[0].Type = AuthMethodOAuth
	if err := ValidateCustomDefinition(invalidCustom, protocols); err == nil {
		t.Fatal("expected custom OAuth definition rejection")
	}
}

// TestMemoryStoreKeepsAccessBindingsProviderScoped verifies that bindings cannot cross instances.
// TestMemoryStoreKeepsAccessBindingsProviderScoped 校验访问绑定不能跨实例。
func TestMemoryStoreKeepsAccessBindingsProviderScoped(t *testing.T) {
	ctx := context.Background()
	store, _ := testConfigurationStore(t)
	firstInstance := testInstance("pvi_first", "first", "system_test_provider")
	secondInstance := testInstance("pvi_second", "second", "system_test_provider")
	if err := store.SaveInstance(ctx, firstInstance); err != nil {
		t.Fatalf("save first instance: %v", err)
	}
	if err := store.SaveInstance(ctx, secondInstance); err != nil {
		t.Fatalf("save second instance: %v", err)
	}
	endpoint := Endpoint{
		ID:                 "ep_first",
		ProviderInstanceID: firstInstance.ID,
		ChannelID:          "responses",
		BaseURL:            "https://example.com/v1",
		Status:             EndpointReady,
		Revision:           1,
	}
	if err := store.SaveEndpoint(ctx, endpoint); err != nil {
		t.Fatalf("save endpoint: %v", err)
	}
	credential := Credential{
		ID:                 "cred_second",
		ProviderInstanceID: secondInstance.ID,
		AuthMethodID:       "api_key",
		Label:              "second account",
		SecretRef:          "secret://second",
		Fingerprint:        "fingerprint-second",
		Status:             CredentialActive,
		Revision:           1,
	}
	if err := store.SaveCredential(ctx, credential); err != nil {
		t.Fatalf("save credential: %v", err)
	}
	binding := AccessBinding{
		ID:                 "bind_cross",
		ProviderInstanceID: firstInstance.ID,
		ChannelID:          "responses",
		EndpointID:         endpoint.ID,
		CredentialID:       credential.ID,
		Enabled:            true,
		Revision:           1,
	}
	if err := store.SaveBinding(ctx, binding); err == nil {
		t.Fatal("expected cross-instance access binding rejection")
	}
}

// TestCustomStoreAllowsMultipleCredentialsAndRejectsDuplicates verifies custom key pool semantics.
// TestCustomStoreAllowsMultipleCredentialsAndRejectsDuplicates 校验自定义 Key 池语义。
func TestCustomStoreAllowsMultipleCredentialsAndRejectsDuplicates(t *testing.T) {
	ctx := context.Background()
	store, _ := testConfigurationStore(t)
	customDefinition := testCustomDefinition()
	if err := store.SaveCustomDefinition(ctx, customDefinition); err != nil {
		t.Fatalf("save custom definition: %v", err)
	}
	instance := testInstance("pvi_custom", "custom", customDefinition.ID)
	if err := store.SaveInstance(ctx, instance); err != nil {
		t.Fatalf("save custom instance: %v", err)
	}
	firstCredential := Credential{
		ID:                 "cred_custom_one",
		ProviderInstanceID: instance.ID,
		AuthMethodID:       "bearer",
		Label:              "key one",
		SecretRef:          "secret://one",
		Fingerprint:        "fingerprint-one",
		Status:             CredentialActive,
		Revision:           1,
	}
	secondCredential := firstCredential
	secondCredential.ID = "cred_custom_two"
	secondCredential.Label = "key two"
	secondCredential.SecretRef = "secret://two"
	secondCredential.Fingerprint = "fingerprint-two"
	if err := store.SaveCredential(ctx, firstCredential); err != nil {
		t.Fatalf("save first credential: %v", err)
	}
	if err := store.SaveCredential(ctx, secondCredential); err != nil {
		t.Fatalf("save second credential: %v", err)
	}
	duplicateCredential := secondCredential
	duplicateCredential.ID = "cred_custom_duplicate"
	duplicateCredential.Fingerprint = firstCredential.Fingerprint
	if err := store.SaveCredential(ctx, duplicateCredential); !errors.Is(err, ErrAlreadyRegistered) {
		t.Fatalf("expected duplicate fingerprint error, got %v", err)
	}
	credentials, errCredentials := store.ListCredentials(ctx, instance.ID)
	if errCredentials != nil {
		t.Fatalf("list credentials: %v", errCredentials)
	}
	if len(credentials) != 2 {
		t.Fatalf("expected two custom credentials, got %d", len(credentials))
	}
}

// TestStoreReturnsMutationSafeDefinitionSnapshots verifies registry and store clone slice fields.
// TestStoreReturnsMutationSafeDefinitionSnapshots 校验注册表和存储会复制切片字段。
func TestStoreReturnsMutationSafeDefinitionSnapshots(t *testing.T) {
	ctx := context.Background()
	store, systems := testConfigurationStore(t)
	definition, exists := systems.Lookup("system_test_provider")
	if !exists {
		t.Fatal("expected system definition")
	}
	definition.Channels[0].AuthMethodIDs[0] = "mutated"
	reloaded, errReloaded := store.GetDefinition(ctx, "system_test_provider")
	if errReloaded != nil {
		t.Fatalf("reload definition: %v", errReloaded)
	}
	if reloaded.Channels[0].AuthMethodIDs[0] != "oauth" {
		t.Fatal("system definition was mutated through a returned snapshot")
	}
}
