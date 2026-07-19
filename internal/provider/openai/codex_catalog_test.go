package openai

import (
	"context"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

// TestCodexCatalogDriverDefinitionIsMutationSafe verifies the immutable driver contract across constructor and accessor boundaries.
// TestCodexCatalogDriverDefinitionIsMutationSafe 验证构造器与访问器边界上的不可变 Driver 合同。
func TestCodexCatalogDriverDefinitionIsMutationSafe(t *testing.T) {
	definition := providerconfig.ProviderDefinition{
		ID:              "system_openai_codex",
		AuthMethodIDs:   []string{"oauth"},
		AuthMethods:     []providerconfig.AuthMethodDefinition{{ID: "oauth"}},
		EndpointPresets: []providerconfig.EndpointPreset{{ID: "default", BaseURL: "https://chatgpt.com/backend-api/codex"}},
	}
	driver, errDriver := NewCodexCatalogDriver(definition, secret.NewMemoryStore())
	if errDriver != nil {
		t.Fatalf("NewCodexCatalogDriver() error = %v", errDriver)
	}
	definition.AuthMethodIDs[0] = "mutated"
	definition.AuthMethods[0].ID = "mutated"
	definition.EndpointPresets[0].BaseURL = "https://mutated.example"
	first := driver.Definition()
	if first.AuthMethodIDs[0] != "oauth" || first.AuthMethods[0].ID != "oauth" || first.EndpointPresets[0].BaseURL != "https://chatgpt.com/backend-api/codex" {
		t.Fatalf("driver definition changed through constructor input: %+v", first)
	}
	first.AuthMethodIDs[0] = "mutated-again"
	if second := driver.Definition(); second.AuthMethodIDs[0] != "oauth" {
		t.Fatalf("driver definition changed through accessor result: %+v", second)
	}
}

// TestCodexPlanModelsMatchPinnedCLIProxyCatalog verifies every CLIProxyAPI plan branch and its Pro fallback.
// TestCodexPlanModelsMatchPinnedCLIProxyCatalog 校验 CLIProxyAPI 的每个套餐分支及其 Pro 回退。
func TestCodexPlanModelsMatchPinnedCLIProxyCatalog(t *testing.T) {
	proModels := []string{"gpt-5.3-codex-spark", "gpt-5.4", "gpt-5.4-mini", "gpt-5.5", "gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna", "codex-auto-review"}
	teamModels := []string{"gpt-5.4", "gpt-5.4-mini", "gpt-5.5", "gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna", "codex-auto-review"}
	freeModels := []string{"gpt-5.4-mini", "gpt-5.5", "gpt-5.6-terra", "gpt-5.6-luna", "codex-auto-review"}
	testCases := []struct {
		// plan is the exact provider claim submitted to the copied switch.
		// plan 是提交到复制分支的精确供应商声明。
		plan string
		// entitlementClass is the normalized Vulcan authorization class.
		// entitlementClass 是规范化后的 Vulcan 授权类别。
		entitlementClass string
		// models is the exact expected upstream identifier order.
		// models 是预期的精确上游标识顺序。
		models []string
	}{
		{plan: "free", entitlementClass: "codex_free", models: freeModels},
		{plan: "team", entitlementClass: "codex_team", models: teamModels},
		{plan: "business", entitlementClass: "codex_team", models: teamModels},
		{plan: "go", entitlementClass: "codex_team", models: teamModels},
		{plan: "plus", entitlementClass: "codex_plus", models: proModels},
		{plan: "pro", entitlementClass: "codex_pro", models: proModels},
		{plan: "future-plan", entitlementClass: "codex_pro", models: proModels},
	}
	for _, testCase := range testCases {
		entitlementClass, models := codexPlanModels(testCase.plan)
		if entitlementClass != testCase.entitlementClass || !slices.Equal(models, testCase.models) {
			t.Errorf("codexPlanModels(%q) = %q %#v, want %q %#v", testCase.plan, entitlementClass, models, testCase.entitlementClass, testCase.models)
		}
	}
}

// TestCodexCatalogDriverReadsPlanAndEntitlementsFromProtectedIDToken verifies copied claim parsing and model authorization.
// TestCodexCatalogDriverReadsPlanAndEntitlementsFromProtectedIDToken 验证复制的声明解析与模型授权。
func TestCodexCatalogDriverReadsPlanAndEntitlementsFromProtectedIDToken(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"exp":946684800,"email":"user@example.com","https://api.openai.com/auth":{"chatgpt_account_id":"account-1","chatgpt_plan_type":"team"}}`))
	idToken := "header." + payload + ".signature"
	credentialExpiresAt := time.Unix(4102444800, 0).UTC()
	document, errDocument := MarshalCodexToken(CodexToken{IDToken: idToken, AccessToken: "access-token", RefreshToken: "refresh-token", AccountID: "account-1", Email: "user@example.com", ExpiresAt: credentialExpiresAt, Type: "codex"})
	if errDocument != nil {
		t.Fatalf("MarshalCodexToken() error = %v", errDocument)
	}
	secrets := secret.NewMemoryStore()
	secretReference, errSecret := secrets.Put(context.Background(), document)
	if errSecret != nil {
		t.Fatalf("Put() error = %v", errSecret)
	}
	definition := providerconfig.ProviderDefinition{ID: "system_openai_codex", Kind: providerconfig.DefinitionKindSystem}
	driver, errDriver := NewCodexCatalogDriver(definition, secrets)
	if errDriver != nil {
		t.Fatalf("NewCodexCatalogDriver() error = %v", errDriver)
	}
	instance := providerconfig.ProviderInstance{ID: "pvi_account_1"}
	// credentialID exercises the maximum portable credential length without weakening catalog identifier validation.
	// credentialID 覆盖最大可移植凭据长度，且不弱化目录标识校验。
	credentialID := "cred_" + strings.Repeat("a", 123)
	credential := providerconfig.Credential{ID: credentialID, ProviderInstanceID: instance.ID, SecretRef: secretReference}
	metadata, errMetadata := driver.ReadCredentialMetadata(context.Background(), instance, credential)
	if errMetadata != nil {
		t.Fatalf("ReadCredentialMetadata() error = %v", errMetadata)
	}
	if metadata.Plan == nil || metadata.Plan.PlanCode != "team" || metadata.Plan.Status != "active" || !metadata.Plan.ExpiresAt.Equal(credentialExpiresAt) {
		t.Fatalf("ReadCredentialMetadata() plan = %#v", metadata.Plan)
	}
	if len(metadata.Entitlements) != 7 {
		t.Fatalf("entitlement count = %d, want 7", len(metadata.Entitlements))
	}
	if errPlanValidation := metadata.Plan.Validate(); errPlanValidation != nil {
		t.Fatalf("plan validation error = %v", errPlanValidation)
	}
	for _, entitlement := range metadata.Entitlements {
		if entitlement.EntitlementClass != "codex_team" || entitlement.ProviderModelID == "model_gpt_5_3_codex_spark" {
			t.Fatalf("unexpected team entitlement = %#v", entitlement)
		}
		if errEntitlementValidation := entitlement.Validate(); errEntitlementValidation != nil {
			t.Fatalf("entitlement validation error = %v", errEntitlementValidation)
		}
	}
	// metadataSnapshot exercises the exact atomic snapshot validation path for the maximum-length credential plan.
	// metadataSnapshot 覆盖最大长度凭据套餐的精确原子快照校验路径。
	metadataSnapshot := catalog.Snapshot{ProviderInstanceID: instance.ID, Plans: []catalog.PlanSnapshot{*metadata.Plan}, Revision: 1, ObservedAt: metadata.Plan.ObservedAt}
	if errSnapshotValidation := metadataSnapshot.Validate(); errSnapshotValidation != nil {
		t.Fatalf("plan-only snapshot validation error = %v", errSnapshotValidation)
	}
	projection, errProjection := NewCodexAccessTokenStore(secrets)
	if errProjection != nil {
		t.Fatalf("NewCodexAccessTokenStore() error = %v", errProjection)
	}
	accessToken, errAccessToken := projection.Get(context.Background(), secretReference)
	if errAccessToken != nil || string(accessToken) != "access-token" {
		t.Fatalf("Get() = %q error=%v", accessToken, errAccessToken)
	}
}

// TestCodexCredentialMetadataRejectsExpiredOAuthCredential verifies preserved plan claims cannot outlive the active access credential.
// TestCodexCredentialMetadataRejectsExpiredOAuthCredential 验证保留的套餐声明不能超过当前 Access 凭据的有效期。
func TestCodexCredentialMetadataRejectsExpiredOAuthCredential(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"exp":4102444800,"https://api.openai.com/auth":{"chatgpt_account_id":"account-1","chatgpt_plan_type":"plus"}}`))
	observedAt := time.Unix(2000000000, 0).UTC()
	document, errDocument := MarshalCodexToken(CodexToken{IDToken: "header." + payload + ".signature", AccessToken: "access-token", RefreshToken: "refresh-token", AccountID: "account-1", ExpiresAt: observedAt.Add(-time.Second), Type: "codex"})
	if errDocument != nil {
		t.Fatalf("MarshalCodexToken() error = %v", errDocument)
	}
	_, errMetadata := CodexCredentialMetadataFromToken(document, providerconfig.ProviderInstance{ID: "pvi_account_1"}, providerconfig.Credential{ID: "cred_account_1"}, observedAt)
	if !errors.Is(errMetadata, provider.ErrMetadataAuthentication) {
		t.Fatalf("CodexCredentialMetadataFromToken() error = %v, want ErrMetadataAuthentication", errMetadata)
	}
}

// TestCodexCredentialMetadataRejectsAccountMismatch verifies protected metadata cannot escape its server-derived account scope.
// TestCodexCredentialMetadataRejectsAccountMismatch 验证受保护元数据不能逸出服务端派生的账号作用域。
func TestCodexCredentialMetadataRejectsAccountMismatch(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"exp":4102444800,"https://api.openai.com/auth":{"chatgpt_account_id":"account-2","chatgpt_plan_type":"plus"}}`))
	document, errDocument := MarshalCodexToken(CodexToken{IDToken: "header." + payload + ".signature", AccessToken: "access-token", RefreshToken: "refresh-token", AccountID: "account-1", ExpiresAt: time.Unix(4102444800, 0).UTC(), Type: "codex"})
	if errDocument != nil {
		t.Fatalf("MarshalCodexToken() error = %v", errDocument)
	}
	if _, errMetadata := CodexCredentialMetadataFromToken(document, providerconfig.ProviderInstance{ID: "pvi_account_1"}, providerconfig.Credential{ID: "cred_account_1"}, time.Now().UTC()); errMetadata == nil {
		t.Fatal("CodexCredentialMetadataFromToken() accepted an account mismatch")
	}
}
