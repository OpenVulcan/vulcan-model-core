package runtimeconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// TestLoadHashesInitialManagementSecretAndPersistsIt verifies the CLIProxyAPI-compatible first-run hash transition.
// TestLoadHashesInitialManagementSecretAndPersistsIt 验证与 CLIProxyAPI 兼容的首次运行散列转换。
func TestLoadHashesInitialManagementSecretAndPersistsIt(t *testing.T) {
	// configurationPath is an isolated caller-owned YAML configuration fixture.
	// configurationPath 是一个隔离的调用方拥有 YAML 配置夹具。
	configurationPath := writeConfiguration(t, "management:\n  secret-key: first-management-key\napi:\n  keys:\n    - id: api_initial\n      name: initial\n      key: call-key\n      enabled: true\n")
	store, errLoad := Load(configurationPath)
	if errLoad != nil {
		t.Fatalf("Load() error = %v", errLoad)
	}
	if !store.AuthenticateManagementKey("first-management-key") {
		t.Fatal("AuthenticateManagementKey() did not accept initial plaintext value")
	}
	if store.AuthenticateManagementKey("wrong-management-key") {
		t.Fatal("AuthenticateManagementKey() accepted an incorrect value")
	}
	// persisted contains the rewritten YAML after first-run hashing.
	// persisted 包含首次运行散列后的重写 YAML。
	persisted, errRead := os.ReadFile(configurationPath)
	if errRead != nil {
		t.Fatalf("ReadFile() error = %v", errRead)
	}
	if strings.Contains(string(persisted), "first-management-key") {
		t.Fatalf("persisted configuration retained plaintext management key: %s", persisted)
	}
	// reloaded verifies subsequent process starts accept the persisted bcrypt value.
	// reloaded 验证后续进程启动接受已持久化的 bcrypt 值。
	reloaded, errReload := Load(configurationPath)
	if errReload != nil {
		t.Fatalf("second Load() error = %v", errReload)
	}
	if !reloaded.AuthenticateManagementKey("first-management-key") {
		t.Fatal("reloaded configuration did not accept original management key")
	}
}

// TestLoadRejectsMalformedManagementHash verifies a bcrypt-looking but invalid hash cannot disable authentication silently.
// TestLoadRejectsMalformedManagementHash 验证外观像 bcrypt 但无效的散列不会静默禁用认证。
func TestLoadRejectsMalformedManagementHash(t *testing.T) {
	configurationPath := writeConfiguration(t, "management:\n  secret-key: $2b$not-a-valid-hash\napi:\n  keys: []\n")
	if _, errLoad := Load(configurationPath); errLoad == nil {
		t.Fatal("Load() error = nil, want malformed bcrypt hash error")
	}
}

// TestAPIKeyLifecyclePersistsPlaintextKeys verifies management CRUD and enabled-only call-plane authentication.
// TestAPIKeyLifecyclePersistsPlaintextKeys 验证管理 CRUD 以及仅启用密钥的调用面认证。
func TestAPIKeyLifecyclePersistsPlaintextKeys(t *testing.T) {
	configurationPath := writeConfiguration(t, "management:\n  secret-key: management-key\napi:\n  keys: []\n")
	store, errLoad := Load(configurationPath)
	if errLoad != nil {
		t.Fatalf("Load() error = %v", errLoad)
	}
	created, errCreate := store.CreateAPIKey(APIKeyInput{Name: "Vulcan Code", Key: "call-key-one", Enabled: true})
	if errCreate != nil {
		t.Fatalf("CreateAPIKey() error = %v", errCreate)
	}
	if !store.AuthenticateAPIKey("call-key-one") {
		t.Fatal("AuthenticateAPIKey() rejected enabled created key")
	}
	updated, errUpdate := store.UpdateAPIKey(created.ID, APIKeyInput{Name: "Vulcan Code updated", Key: "call-key-two", Enabled: false})
	if errUpdate != nil {
		t.Fatalf("UpdateAPIKey() error = %v", errUpdate)
	}
	if updated.ID != created.ID || updated.Name != "Vulcan Code updated" {
		t.Fatalf("UpdateAPIKey() = %+v, want preserved identifier and replacement fields", updated)
	}
	if store.AuthenticateAPIKey("call-key-one") || store.AuthenticateAPIKey("call-key-two") {
		t.Fatal("AuthenticateAPIKey() accepted replaced or disabled key")
	}
	if errDelete := store.DeleteAPIKey(created.ID); errDelete != nil {
		t.Fatalf("DeleteAPIKey() error = %v", errDelete)
	}
	if len(store.ListAPIKeys()) != 0 {
		t.Fatalf("ListAPIKeys() length = %d, want 0", len(store.ListAPIKeys()))
	}
	// persisted verifies the call-plane key stays plaintext by the explicitly accepted contract.
	// persisted 验证调用面密钥按明确接受的合同保持明文。
	persisted, errRead := os.ReadFile(configurationPath)
	if errRead != nil {
		t.Fatalf("ReadFile() error = %v", errRead)
	}
	if strings.Contains(string(persisted), "call-key-two") {
		t.Fatalf("persisted configuration retained deleted API key: %s", persisted)
	}
}

// TestLoadAcceptsExistingBcryptHash verifies a pre-hashed management credential remains usable.
// TestLoadAcceptsExistingBcryptHash 验证预先散列的管理凭据仍然可用。
func TestLoadAcceptsExistingBcryptHash(t *testing.T) {
	// hash is generated in the test to exercise the same bcrypt representation persisted by production code.
	// hash 在测试中生成，以覆盖生产代码持久化的同一 bcrypt 表示。
	hash, errHash := bcrypt.GenerateFromPassword([]byte("existing-key"), bcrypt.DefaultCost)
	if errHash != nil {
		t.Fatalf("GenerateFromPassword() error = %v", errHash)
	}
	configurationPath := writeConfiguration(t, "management:\n  secret-key: "+string(hash)+"\napi:\n  keys: []\n")
	store, errLoad := Load(configurationPath)
	if errLoad != nil {
		t.Fatalf("Load() error = %v", errLoad)
	}
	if !store.AuthenticateManagementKey("existing-key") {
		t.Fatal("AuthenticateManagementKey() rejected persisted bcrypt credential")
	}
}

// TestLoadPreservesEnabledOIDCTrustConfiguration verifies API-key rewrites do not drop external identity settings.
// TestLoadPreservesEnabledOIDCTrustConfiguration 验证 API 密钥重写不会丢失外部身份设置。
func TestLoadPreservesEnabledOIDCTrustConfiguration(t *testing.T) {
	configurationPath := writeConfiguration(t, "management:\n  secret-key: management-key\napi:\n  keys: []\n  oidc:\n    enabled: true\n    issuer: https://identity.example.com\n    audience: vulcan-model-router\n    jwks-url: https://identity.example.com/keys\n")
	store, errLoad := Load(configurationPath)
	if errLoad != nil {
		t.Fatalf("Load() error = %v", errLoad)
	}
	configuration := store.OIDCConfiguration()
	if configuration == nil || !configuration.Enabled || configuration.Issuer != "https://identity.example.com" || configuration.Audience != "vulcan-model-router" || configuration.JWKSURL != "https://identity.example.com/keys" {
		t.Fatalf("OIDCConfiguration() = %+v", configuration)
	}
	if _, errCreate := store.CreateAPIKey(APIKeyInput{Name: "caller", Key: "call-key", Enabled: true}); errCreate != nil {
		t.Fatalf("CreateAPIKey() error = %v", errCreate)
	}
	reloaded, errReload := Load(configurationPath)
	if errReload != nil || reloaded.OIDCConfiguration() == nil || !reloaded.OIDCConfiguration().Enabled {
		t.Fatalf("reloaded OIDC configuration = %+v, error = %v", reloaded.OIDCConfiguration(), errReload)
	}
}

// writeConfiguration creates one temporary configuration file and returns its absolute path.
// writeConfiguration 创建一个临时配置文件并返回其绝对路径。
func writeConfiguration(t *testing.T, content string) string {
	t.Helper()
	// configurationPath is unique to the current test and therefore safe for rewrite assertions.
	// configurationPath 对当前测试唯一，因此可安全执行重写断言。
	configurationPath := filepath.Join(t.TempDir(), "vulcan-model-core.yaml")
	if errWrite := os.WriteFile(configurationPath, []byte(content), 0o600); errWrite != nil {
		t.Fatalf("WriteFile() error = %v", errWrite)
	}
	return configurationPath
}
