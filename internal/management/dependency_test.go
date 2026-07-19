package management

import (
	"testing"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

// TestManagementConstructorsRejectTypedNilDependencies verifies application services cannot retain boxed nil stores or clients.
// TestManagementConstructorsRejectTypedNilDependencies 验证应用服务不会保留装箱后的 nil Store 或 Client。
func TestManagementConstructorsRejectTypedNilDependencies(t *testing.T) {
	validService, configurations, secrets := newKimiOnboardingService(t)
	var nilConfigurations *providerconfig.MemoryStore
	var nilSecrets *secret.MemoryStore
	var nilCatalogs *catalog.MemoryStore
	testCases := []struct {
		// name identifies the constructor boundary under test.
		// name 标识待测试的构造器边界。
		name string
		// construct invokes the constructor with one boxed nil dependency.
		// construct 使用一个装箱后的 nil 依赖调用构造器。
		construct func() error
	}{
		{name: "service configuration", construct: func() error { _, err := NewService(nilConfigurations, secrets, validService.catalogs); return err }},
		{name: "service secrets", construct: func() error { _, err := NewService(configurations, nilSecrets, validService.catalogs); return err }},
		{name: "service catalogs", construct: func() error { _, err := NewService(configurations, secrets, nilCatalogs); return err }},
		{name: "query configuration", construct: func() error { _, err := NewQueryService(nilConfigurations, validService.catalogs); return err }},
		{name: "model access catalogs", construct: func() error { _, err := NewModelAccessService(configurations, nilCatalogs); return err }},
		{name: "custom catalog configuration", construct: func() error { _, err := NewCustomCatalogService(nilConfigurations, validService.catalogs); return err }},
		{name: "Kimi token client", construct: func() error {
			_, err := NewKimiTokenService(configurations, secrets, (*staticKimiTokenClient)(nil))
			return err
		}},
		{name: "xAI token client", construct: func() error {
			_, err := NewXAITokenService(configurations, secrets, (*staticXAITokenClient)(nil))
			return err
		}},
		{name: "Codex token client", construct: func() error {
			_, err := NewCodexTokenService(configurations, secrets, (*staticCodexTokenClient)(nil))
			return err
		}},
		{name: "Claude token client", construct: func() error {
			_, err := NewClaudeTokenService(configurations, secrets, (*staticClaudeTokenClient)(nil))
			return err
		}},
		{name: "Antigravity token client", construct: func() error {
			_, err := NewAntigravityTokenService(configurations, secrets, (*staticAntigravityTokenClient)(nil))
			return err
		}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if errConstruct := testCase.construct(); errConstruct == nil {
				t.Fatal("constructor error = nil")
			}
		})
	}
}
