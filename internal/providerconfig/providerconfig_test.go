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
		ID:               "openai.responses.v1",
		Version:          "1",
		DisplayName:      "OpenAI Responses",
		UserConfigurable: true,
		RuntimeReady:     true,
		ModelDiscovery:   SupportSupported,
		Capabilities: []ProtocolCapabilityFact{
			{Capability: ProtocolCapabilityStructuredTools, Status: SupportSupported},
			{Capability: ProtocolCapabilityStreamingToolArguments, Status: SupportSupported},
		},
		AllowedAuthMethods: []AuthMethodType{AuthMethodBearer, AuthMethodHeaderKey},
	}
}

// TestDerivedEndpointPresetValidatesAndLocksRegionalOrigins verifies safe template materialization and post-onboarding immutability.
// TestDerivedEndpointPresetValidatesAndLocksRegionalOrigins 校验安全模板实例化与录入后不可变性。
func TestDerivedEndpointPresetValidatesAndLocksRegionalOrigins(t *testing.T) {
	preset := EndpointPreset{
		ID: "default", BaseURL: "https://us-central1-aiplatform.googleapis.com", Region: "us-central1",
		RegionalBaseURLTemplate: "https://{region}-aiplatform.googleapis.com", GlobalBaseURL: "https://aiplatform.googleapis.com",
	}
	if errValidate := preset.Validate(); errValidate != nil {
		t.Fatalf("derived preset Validate() error = %v", errValidate)
	}
	definition := ProviderDefinition{Kind: DefinitionKindSystem, EndpointPresets: []EndpointPreset{preset}}
	regional := Endpoint{ID: "ep_vertex", BaseURL: "https://europe-west1-aiplatform.googleapis.com", Region: "europe-west1"}
	if errMatch := definition.ValidateEndpointPreset(regional); errMatch != nil {
		t.Fatalf("regional endpoint validation error = %v", errMatch)
	}
	global := regional
	global.BaseURL = "https://aiplatform.googleapis.com"
	global.Region = "global"
	if errMatch := definition.ValidateEndpointPreset(global); errMatch != nil {
		t.Fatalf("global endpoint validation error = %v", errMatch)
	}
	unsafe := regional
	unsafe.BaseURL = "https://attacker.example"
	unsafe.Region = "europe-west1.attacker"
	if errUnsafe := definition.ValidateEndpointPreset(unsafe); errUnsafe == nil {
		t.Fatalf("unsafe derived endpoint was accepted")
	}
	changed := regional
	changed.BaseURL = "https://asia-east1-aiplatform.googleapis.com"
	changed.Region = "asia-east1"
	if errMutation := definition.ValidateEndpointMutation(regional, changed); errMutation == nil {
		t.Fatalf("derived endpoint mutation was accepted")
	}
}

// TestProtocolProfileCapabilityFactsRejectInvalidAndRemainIsolated verifies closed capability facts are validated and registry snapshots cannot be mutated externally.
// TestProtocolProfileCapabilityFactsRejectInvalidAndRemainIsolated 验证封闭能力事实会被校验，且注册表快照不能被外部修改。
func TestProtocolProfileCapabilityFactsRejectInvalidAndRemainIsolated(t *testing.T) {
	invalidProfile := testProtocolProfile()
	invalidProfile.Capabilities = append(invalidProfile.Capabilities, ProtocolCapabilityFact{Capability: ProtocolCapability("unknown"), Status: SupportSupported})
	if errValidate := invalidProfile.Validate(); errValidate == nil {
		t.Fatal("ProtocolProfile.Validate() accepted an unknown capability")
	}
	duplicateProfile := testProtocolProfile()
	duplicateProfile.Capabilities = append(duplicateProfile.Capabilities, ProtocolCapabilityFact{Capability: ProtocolCapabilityStructuredTools, Status: SupportUnsupported})
	if errValidate := duplicateProfile.Validate(); errValidate == nil {
		t.Fatal("ProtocolProfile.Validate() accepted a duplicate capability")
	}
	registry := NewProtocolRegistry()
	profile := testProtocolProfile()
	if errRegister := registry.Register(profile); errRegister != nil {
		t.Fatalf("Register() error = %v", errRegister)
	}
	profile.Capabilities[0].Status = SupportUnsupported
	stored, exists := registry.Lookup(profile.ID)
	if !exists || stored.Capabilities[0].Status != SupportSupported {
		t.Fatalf("stored profile = %#v", stored)
	}
	stored.Capabilities[0].Status = SupportUnsupported
	again, existsAgain := registry.Lookup(profile.ID)
	if !existsAgain || again.Capabilities[0].Status != SupportSupported {
		t.Fatalf("isolated profile = %#v", again)
	}
}

// TestConfigurationCollectionsRejectDuplicateIdentifiers verifies collection order cannot hide duplicate domain identifiers.
// TestConfigurationCollectionsRejectDuplicateIdentifiers 验证集合顺序不能掩盖重复领域标识。
func TestConfigurationCollectionsRejectDuplicateIdentifiers(t *testing.T) {
	profile := testProtocolProfile()
	profile.AllowedAuthMethods = []AuthMethodType{AuthMethodBearer, AuthMethodBearer}
	if errValidate := profile.Validate(); errValidate == nil {
		t.Fatal("ProtocolProfile.Validate() accepted a duplicate authentication method")
	}

	definition := testSystemDefinition()
	definition.AuthMethodIDs = []string{"oauth", "oauth"}
	if errValidate := definition.Validate(); errValidate == nil {
		t.Fatal("ProviderDefinition.Validate() accepted a duplicate protocol authentication method")
	}

	binding := AccessBinding{
		ID:                 "bind_test",
		ProviderInstanceID: "pvi_test",
		ChannelID:          "openai.responses.v1",
		EndpointID:         "ep_test",
		CredentialID:       "cred_test",
		AllowedModelIDs:    []string{"model_test", "model_test"},
		Revision:           1,
	}
	if errValidate := binding.Validate(); errValidate == nil {
		t.Fatal("AccessBinding.Validate() accepted a duplicate model identifier")
	}
}

// TestBaseURLsRejectCredentialAndRequestComponents verifies base URLs remain origins or provider-owned paths instead of request templates.
// TestBaseURLsRejectCredentialAndRequestComponents 验证基础 URL 只能表示 Origin 或供应商自有路径而不能充当请求模板。
func TestBaseURLsRejectCredentialAndRequestComponents(t *testing.T) {
	validBaseURL := "https://example.com/coding/v1"
	validPreset := EndpointPreset{ID: "default", BaseURL: validBaseURL, Region: "Global"}
	if errValidate := validPreset.Validate(); errValidate != nil {
		t.Fatalf("EndpointPreset.Validate() rejected provider-owned path: %v", errValidate)
	}
	validEndpoint := Endpoint{
		ID: "ep_test", ProviderInstanceID: "pvi_test", ChannelID: "openai.chat.v1",
		BaseURL: validBaseURL, Status: EndpointReady, Revision: 1,
	}
	if errValidate := validEndpoint.Validate(); errValidate != nil {
		t.Fatalf("Endpoint.Validate() rejected provider-owned path: %v", errValidate)
	}

	// invalidBaseURLs covers every request-specific component forbidden from persisted base addresses.
	// invalidBaseURLs 覆盖持久化基础地址禁止包含的每一种请求专属组件。
	invalidBaseURLs := []string{
		"https://token@example.com/v1",
		"https://example.com/v1?key=value",
		"https://example.com/v1?",
		"https://example.com/v1#fragment",
	}
	for _, invalidBaseURL := range invalidBaseURLs {
		preset := EndpointPreset{ID: "default", BaseURL: invalidBaseURL, Region: "Global"}
		if errValidate := preset.Validate(); errValidate == nil {
			t.Errorf("EndpointPreset.Validate() accepted unsafe base URL %q", invalidBaseURL)
		}
		endpoint := validEndpoint
		endpoint.BaseURL = invalidBaseURL
		if errValidate := endpoint.Validate(); errValidate == nil {
			t.Errorf("Endpoint.Validate() accepted unsafe base URL %q", invalidBaseURL)
		}
	}
}

// TestMutationValidationPreservesRecordOwnership verifies editable fields cannot be used to reassign stable record ownership.
// TestMutationValidationPreservesRecordOwnership 验证可编辑字段不能被用于改派稳定记录所有权。
func TestMutationValidationPreservesRecordOwnership(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	instance := ProviderInstance{ID: "pvi_test", DefinitionID: "system_test", Handle: "test", DisplayName: "Test", Status: LifecycleReady, Revision: 1, DefinitionRevision: 1, CreatedAt: now, UpdatedAt: now}
	mutableInstance := instance
	mutableInstance.DisplayName = "Updated"
	mutableInstance.Revision++
	mutableInstance.UpdatedAt = now.Add(time.Minute)
	if errMutation := instance.ValidateMutation(mutableInstance); errMutation != nil {
		t.Fatalf("ProviderInstance.ValidateMutation() rejected editable fields: %v", errMutation)
	}
	reassignedInstance := mutableInstance
	reassignedInstance.DefinitionID = "system_other"
	if errMutation := instance.ValidateMutation(reassignedInstance); errMutation == nil {
		t.Fatal("ProviderInstance.ValidateMutation() accepted definition reassignment")
	}
	recreatedInstance := mutableInstance
	recreatedInstance.CreatedAt = now.Add(time.Second)
	if errMutation := instance.ValidateMutation(recreatedInstance); errMutation == nil {
		t.Fatal("ProviderInstance.ValidateMutation() accepted creation-time replacement")
	}

	definition := ProviderDefinition{Kind: DefinitionKindCustom}
	endpoint := Endpoint{ID: "ep_test", ProviderInstanceID: "pvi_test", ChannelID: "openai.chat", BaseURL: "https://example.com", Status: EndpointReady, Revision: 1}
	mutableEndpoint := endpoint
	mutableEndpoint.BaseURL = "https://example.com/v1"
	mutableEndpoint.Revision++
	if errMutation := definition.ValidateEndpointMutation(endpoint, mutableEndpoint); errMutation != nil {
		t.Fatalf("ValidateEndpointMutation() rejected editable fields: %v", errMutation)
	}
	reassignedEndpoint := mutableEndpoint
	reassignedEndpoint.ProviderInstanceID = "pvi_other"
	if errMutation := definition.ValidateEndpointMutation(endpoint, reassignedEndpoint); errMutation == nil {
		t.Fatal("ValidateEndpointMutation() accepted provider reassignment")
	}

	credential := Credential{ID: "cred_test", ProviderInstanceID: "pvi_test", AuthMethodID: "api_key"}
	mutableCredential := credential
	mutableCredential.SecretRef = "secret://replacement"
	if errMutation := credential.ValidateMutation(mutableCredential); errMutation != nil {
		t.Fatalf("Credential.ValidateMutation() rejected editable fields: %v", errMutation)
	}
	reassignedCredential := mutableCredential
	reassignedCredential.AuthMethodID = "oauth"
	if errMutation := credential.ValidateMutation(reassignedCredential); errMutation == nil {
		t.Fatal("Credential.ValidateMutation() accepted authentication reassignment")
	}

	binding := AccessBinding{ID: "bind_test", ProviderInstanceID: "pvi_test", ChannelID: "openai.chat", EndpointID: "ep_test", CredentialID: "cred_test"}
	mutableBinding := binding
	mutableBinding.EndpointID = "ep_replacement"
	mutableBinding.CredentialID = "cred_replacement"
	if errMutation := binding.ValidateMutation(mutableBinding); errMutation != nil {
		t.Fatalf("AccessBinding.ValidateMutation() rejected editable references: %v", errMutation)
	}
	reassignedBinding := mutableBinding
	reassignedBinding.ChannelID = "openai.responses"
	if errMutation := binding.ValidateMutation(reassignedBinding); errMutation == nil {
		t.Fatal("AccessBinding.ValidateMutation() accepted channel reassignment")
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
		ProtocolProfileID:   "openai.responses.v1",
		EndpointProfileID:   "system_fixed",
		AuthMethodIDs:       []string{"oauth", "api_key"},
		RuntimeReady:        true,
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
		ProtocolProfileID:   "openai.responses.v1",
		EndpointProfileID:   "custom_base_url",
		AuthMethodIDs:       []string{"bearer"},
		RuntimeReady:        true,
		AuthMethods: []AuthMethodDefinition{{
			ID:                  "bearer",
			Type:                AuthMethodBearer,
			MultipleCredentials: true,
		}},
		Features: testFeatureSet(),
		Revision: 1,
	}
}

// TestProviderDefinitionRequiresProtocolProfileID verifies the data model requires one direct protocol reference.
// TestProviderDefinitionRequiresProtocolProfileID 验证数据模型要求一个直接协议引用。
func TestProviderDefinitionRequiresProtocolProfileID(t *testing.T) {
	definition := testSystemDefinition()
	definition.ProtocolProfileID = ""
	if errValidate := definition.Validate(); errValidate == nil {
		t.Fatal("ProviderDefinition.Validate() accepted an empty protocol profile identifier")
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
	for _, unsupportedAuthMethod := range []AuthMethodType{AuthMethodQueryKey, AuthMethodNone} {
		invalidCustom = testCustomDefinition()
		invalidCustom.AuthMethods[0].Type = unsupportedAuthMethod
		if err := ValidateCustomDefinition(invalidCustom, protocols); err == nil {
			t.Fatalf("expected custom %q definition rejection", unsupportedAuthMethod)
		}
	}
}

// TestSystemProviderGroupsRemainManagementOnly verifies group ownership, definition references, ordering, and snapshot isolation.
// TestSystemProviderGroupsRemainManagementOnly 验证分组归属、定义引用、排序和快照隔离。
func TestSystemProviderGroupsRemainManagementOnly(t *testing.T) {
	protocols := NewProtocolRegistry()
	if errProfile := protocols.Register(testProtocolProfile()); errProfile != nil {
		t.Fatalf("register protocol profile: %v", errProfile)
	}
	systems, errSystems := NewSystemRegistry(protocols)
	if errSystems != nil {
		t.Fatalf("create system registry: %v", errSystems)
	}
	groupedDefinition := testSystemDefinition()
	groupedDefinition.GroupID = "test_group"
	groupedDefinition.VariantName = "Global"
	groupedDefinition.ModelCatalogID = "shared_catalog"
	groupedDefinition.EndpointPresets = []EndpointPreset{{ID: "global", BaseURL: "https://global.example/v1", Region: "Global"}}
	if errUnknownGroup := systems.Register(groupedDefinition); errUnknownGroup == nil {
		t.Fatal("Register() accepted an unknown provider group")
	}
	if errGroup := systems.RegisterGroup(ProviderGroup{ID: "test_group", DisplayName: "Test", SortOrder: 20, Revision: 1}); errGroup != nil {
		t.Fatalf("RegisterGroup() error = %v", errGroup)
	}
	if errEarlierGroup := systems.RegisterGroup(ProviderGroup{ID: "earlier_group", DisplayName: "Earlier", SortOrder: 10, Revision: 1}); errEarlierGroup != nil {
		t.Fatalf("RegisterGroup() earlier error = %v", errEarlierGroup)
	}
	if errDefinition := systems.Register(groupedDefinition); errDefinition != nil {
		t.Fatalf("Register() grouped definition error = %v", errDefinition)
	}
	groups := systems.ListGroups()
	if len(groups) != 2 || groups[0].ID != "earlier_group" || groups[1].ID != "test_group" {
		t.Fatalf("groups = %#v", groups)
	}
	stored, exists := systems.Lookup(groupedDefinition.ID)
	if !exists || stored.GroupID != "test_group" || len(stored.EndpointPresets) != 1 {
		t.Fatalf("stored definition = %#v", stored)
	}
	stored.EndpointPresets[0].BaseURL = "https://mutated.invalid"
	again, existsAgain := systems.Lookup(groupedDefinition.ID)
	if !existsAgain || again.EndpointPresets[0].BaseURL != "https://global.example/v1" {
		t.Fatalf("isolated definition = %#v", again)
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
		ChannelID:          "openai.responses.v1",
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
		ChannelID:          "openai.responses.v1",
		EndpointID:         endpoint.ID,
		CredentialID:       credential.ID,
		Enabled:            true,
		Revision:           1,
	}
	if err := store.SaveBinding(ctx, binding); err == nil {
		t.Fatal("expected cross-instance access binding rejection")
	}
}

// TestMemoryStoreRejectsStableOwnershipReassignment verifies direct store writes cannot move existing identifiers across owners.
// TestMemoryStoreRejectsStableOwnershipReassignment 验证直接存储写入不能跨所有者迁移现有标识。
func TestMemoryStoreRejectsStableOwnershipReassignment(t *testing.T) {
	ctx := context.Background()
	store, systems := testConfigurationStore(t)
	otherDefinition := testSystemDefinition()
	otherDefinition.ID = "system_other_provider"
	if errRegister := systems.Register(otherDefinition); errRegister != nil {
		t.Fatalf("register other system definition: %v", errRegister)
	}
	firstInstance := testInstance("pvi_owner_first", "owner-first", "system_test_provider")
	secondInstance := testInstance("pvi_owner_second", "owner-second", "system_test_provider")
	if errSave := store.SaveInstance(ctx, firstInstance); errSave != nil {
		t.Fatalf("save first instance: %v", errSave)
	}
	if errSave := store.SaveInstance(ctx, secondInstance); errSave != nil {
		t.Fatalf("save second instance: %v", errSave)
	}
	reassignedInstance := firstInstance
	reassignedInstance.DefinitionID = otherDefinition.ID
	reassignedInstance.Revision++
	reassignedInstance.UpdatedAt = reassignedInstance.UpdatedAt.Add(time.Minute)
	if errSave := store.SaveInstance(ctx, reassignedInstance); errSave == nil {
		t.Fatal("SaveInstance() accepted definition ownership reassignment")
	}

	firstEndpoint := Endpoint{ID: "ep_owner_first", ProviderInstanceID: firstInstance.ID, ChannelID: "openai.responses.v1", BaseURL: "https://first.example/v1", Status: EndpointReady, Revision: 1}
	secondEndpoint := Endpoint{ID: "ep_owner_second", ProviderInstanceID: secondInstance.ID, ChannelID: "openai.responses.v1", BaseURL: "https://second.example/v1", Status: EndpointReady, Revision: 1}
	if errSave := store.SaveEndpoint(ctx, firstEndpoint); errSave != nil {
		t.Fatalf("save first endpoint: %v", errSave)
	}
	if errSave := store.SaveEndpoint(ctx, secondEndpoint); errSave != nil {
		t.Fatalf("save second endpoint: %v", errSave)
	}
	reassignedEndpoint := firstEndpoint
	reassignedEndpoint.ProviderInstanceID = secondInstance.ID
	reassignedEndpoint.Revision++
	if errSave := store.SaveEndpoint(ctx, reassignedEndpoint); errSave == nil {
		t.Fatal("SaveEndpoint() accepted provider ownership reassignment")
	}

	firstCredential := Credential{ID: "cred_owner_first", ProviderInstanceID: firstInstance.ID, AuthMethodID: "api_key", Label: "First", SecretRef: "secret://first", Fingerprint: "owner-first", Status: CredentialActive, Revision: 1}
	secondCredential := Credential{ID: "cred_owner_second", ProviderInstanceID: secondInstance.ID, AuthMethodID: "api_key", Label: "Second", SecretRef: "secret://second", Fingerprint: "owner-second", Status: CredentialActive, Revision: 1}
	if errSave := store.SaveCredential(ctx, firstCredential); errSave != nil {
		t.Fatalf("save first credential: %v", errSave)
	}
	if errSave := store.SaveCredential(ctx, secondCredential); errSave != nil {
		t.Fatalf("save second credential: %v", errSave)
	}
	reassignedCredential := firstCredential
	reassignedCredential.ProviderInstanceID = secondInstance.ID
	reassignedCredential.Revision++
	if errSave := store.SaveCredential(ctx, reassignedCredential); errSave == nil {
		t.Fatal("SaveCredential() accepted provider ownership reassignment")
	}
	reassignedAuthMethod := firstCredential
	reassignedAuthMethod.AuthMethodID = "oauth"
	reassignedAuthMethod.Revision++
	if errSave := store.SaveCredential(ctx, reassignedAuthMethod); errSave == nil {
		t.Fatal("SaveCredential() accepted authentication ownership reassignment")
	}

	firstBinding := AccessBinding{ID: "bind_owner_first", ProviderInstanceID: firstInstance.ID, ChannelID: "openai.responses.v1", EndpointID: firstEndpoint.ID, CredentialID: firstCredential.ID, Enabled: true, Revision: 1}
	if errSave := store.SaveBinding(ctx, firstBinding); errSave != nil {
		t.Fatalf("save first binding: %v", errSave)
	}
	reassignedBinding := firstBinding
	reassignedBinding.ProviderInstanceID = secondInstance.ID
	reassignedBinding.EndpointID = secondEndpoint.ID
	reassignedBinding.CredentialID = secondCredential.ID
	reassignedBinding.Revision++
	if errSave := store.SaveBinding(ctx, reassignedBinding); errSave == nil {
		t.Fatal("SaveBinding() accepted provider ownership reassignment")
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

// TestMemoryStoreCustomDefinitionMigrationIsAtomic verifies invalid instance transitions cannot partially replace a definition.
// TestMemoryStoreCustomDefinitionMigrationIsAtomic 验证无效实例转换无法局部替换定义。
func TestMemoryStoreCustomDefinitionMigrationIsAtomic(t *testing.T) {
	ctx := context.Background()
	store, _ := testConfigurationStore(t)
	definition := testCustomDefinition()
	if errSave := store.SaveCustomDefinition(ctx, definition); errSave != nil {
		t.Fatalf("save custom definition: %v", errSave)
	}
	first := testInstance("pvi_migration_first", "migration-first", definition.ID)
	second := testInstance("pvi_migration_second", "migration-second", definition.ID)
	if errSave := store.SaveInstance(ctx, first); errSave != nil {
		t.Fatalf("save first custom instance: %v", errSave)
	}
	if errSave := store.SaveInstance(ctx, second); errSave != nil {
		t.Fatalf("save second custom instance: %v", errSave)
	}
	directReplacement := definition
	directReplacement.DisplayName = "Unsafe direct replacement"
	directReplacement.Revision++
	if errSave := store.SaveCustomDefinition(ctx, directReplacement); !errors.Is(errSave, ErrAlreadyRegistered) {
		t.Fatalf("direct custom definition replacement error = %v, want ErrAlreadyRegistered", errSave)
	}
	storedBeforeMigration, errStoredBeforeMigration := store.GetDefinition(ctx, definition.ID)
	if errStoredBeforeMigration != nil || storedBeforeMigration.Revision != definition.Revision {
		t.Fatalf("definition after direct replacement = %+v, error = %v", storedBeforeMigration, errStoredBeforeMigration)
	}
	updatedDefinition := definition
	updatedDefinition.DisplayName = "Migrated Provider"
	updatedDefinition.Revision++
	migrationTime := first.UpdatedAt.Add(time.Minute)
	migratedFirst := first
	migratedFirst.Status = LifecycleMigrationRequired
	migratedFirst.DefinitionRevision = updatedDefinition.Revision
	migratedFirst.Revision++
	migratedFirst.UpdatedAt = migrationTime
	migratedSecond := second
	migratedSecond.Status = LifecycleMigrationRequired
	migratedSecond.DefinitionRevision = updatedDefinition.Revision
	migratedSecond.UpdatedAt = migrationTime
	if errMigration := store.SaveCustomDefinitionMigration(ctx, CustomDefinitionMigration{
		Definition: updatedDefinition,
		Instances:  []ProviderInstance{migratedFirst, migratedSecond},
	}); errMigration == nil {
		t.Fatal("invalid custom definition migration error = nil")
	}
	storedDefinition, errDefinition := store.GetDefinition(ctx, definition.ID)
	if errDefinition != nil || storedDefinition.Revision != definition.Revision {
		t.Fatalf("definition after rejected migration = %+v, error = %v", storedDefinition, errDefinition)
	}
	storedFirst, errFirst := store.GetInstance(ctx, first.ID)
	storedSecond, errSecond := store.GetInstance(ctx, second.ID)
	if errFirst != nil || errSecond != nil || storedFirst.Revision != first.Revision || storedSecond.Revision != second.Revision || storedFirst.Status != LifecycleReady || storedSecond.Status != LifecycleReady {
		t.Fatalf("instances after rejected migration = %+v / %+v, errors = %v / %v", storedFirst, storedSecond, errFirst, errSecond)
	}
	migratedSecond.Revision++
	if errMigration := store.SaveCustomDefinitionMigration(ctx, CustomDefinitionMigration{
		Definition: updatedDefinition,
		Instances:  []ProviderInstance{migratedFirst, migratedSecond},
	}); errMigration != nil {
		t.Fatalf("save valid custom definition migration: %v", errMigration)
	}
	storedDefinition, errDefinition = store.GetDefinition(ctx, definition.ID)
	storedFirst, errFirst = store.GetInstance(ctx, first.ID)
	storedSecond, errSecond = store.GetInstance(ctx, second.ID)
	if errDefinition != nil || errFirst != nil || errSecond != nil || storedDefinition.Revision != updatedDefinition.Revision || storedFirst.Status != LifecycleMigrationRequired || storedSecond.Status != LifecycleMigrationRequired {
		t.Fatalf("persisted migration definition=%+v instances=%+v/%+v errors=%v/%v/%v", storedDefinition, storedFirst, storedSecond, errDefinition, errFirst, errSecond)
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
	definition.AuthMethodIDs[0] = "mutated"
	reloaded, errReloaded := store.GetDefinition(ctx, "system_test_provider")
	if errReloaded != nil {
		t.Fatalf("reload definition: %v", errReloaded)
	}
	if reloaded.AuthMethodIDs[0] != "oauth" {
		t.Fatal("system definition was mutated through a returned snapshot")
	}
}

// TestCredentialRuntimeEligibilityCoversEveryLifecycleState verifies one shared rule gates execution and metadata refreshes.
// TestCredentialRuntimeEligibilityCoversEveryLifecycleState 验证同一共享规则会约束执行与元数据刷新。
func TestCredentialRuntimeEligibilityCoversEveryLifecycleState(t *testing.T) {
	now := time.Date(2026, 7, 19, 8, 0, 0, 0, time.UTC)
	past := now.Add(-time.Minute)
	future := now.Add(time.Minute)
	testCases := []struct {
		// name identifies the lifecycle boundary under test.
		// name 标识待测试的生命周期边界。
		name string
		// credential contains only fields used by the runtime eligibility rule.
		// credential 仅包含运行资格规则使用的字段。
		credential Credential
		// want is the expected upstream-work eligibility.
		// want 是预期的上游工作资格。
		want bool
	}{
		{name: "active", credential: Credential{Status: CredentialActive}, want: true},
		{name: "active expired", credential: Credential{Status: CredentialActive, ExpiresAt: &past}},
		{name: "active expires now", credential: Credential{Status: CredentialActive, ExpiresAt: &now}},
		{name: "active unexpired", credential: Credential{Status: CredentialActive, ExpiresAt: &future}, want: true},
		{name: "disabled", credential: Credential{Status: CredentialDisabled}},
		{name: "expired state", credential: Credential{Status: CredentialExpired}},
		{name: "invalid", credential: Credential{Status: CredentialInvalid}},
		{name: "cooling without recovery", credential: Credential{Status: CredentialCooling}},
		{name: "cooling before recovery", credential: Credential{Status: CredentialCooling, CoolingUntil: &future}},
		{name: "cooling at recovery", credential: Credential{Status: CredentialCooling, CoolingUntil: &now}, want: true},
		{name: "cooling after recovery", credential: Credential{Status: CredentialCooling, CoolingUntil: &past}, want: true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := testCase.credential.RuntimeEligibleAt(now); got != testCase.want {
				t.Fatalf("RuntimeEligibleAt() = %t, want %t", got, testCase.want)
			}
		})
	}
}
