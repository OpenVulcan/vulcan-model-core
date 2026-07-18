package provider

import (
	"testing"

	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
)

// testDriver is a minimum trusted provider library fixture.
// testDriver 是一个最小受信任供应商库测试夹具。
type testDriver struct {
	// definition is the immutable provider metadata exposed by the fixture.
	// definition 是测试夹具暴露的不可变供应商元数据。
	definition providerconfig.ProviderDefinition
}

// Definition returns the fixture's immutable system-provider definition.
// Definition 返回测试夹具的不可变系统供应商定义。
func (d testDriver) Definition() providerconfig.ProviderDefinition {
	return d.definition
}

// ClassifyError reports that the minimum fixture has no provider-specific error rule.
// ClassifyError 表示最小测试夹具没有供应商特定错误规则。
func (d testDriver) ClassifyError(ErrorObservation) (ClassifiedError, bool) {
	return ClassifiedError{}, false
}

// testProviderDefinition returns one valid trusted provider definition.
// testProviderDefinition 返回一个有效的受信任供应商定义。
func testProviderDefinition() providerconfig.ProviderDefinition {
	return providerconfig.ProviderDefinition{
		ID:                  "system_test_provider",
		Kind:                providerconfig.DefinitionKindSystem,
		DisplayName:         "Test Provider",
		DriverID:            "test-provider",
		DriverVersion:       "1.0.0",
		ConfigSchemaVersion: "1",
		ProtocolProfileID:   "anthropic.messages.v1",
		EndpointProfileID:   "default",
		AuthMethodIDs:       []string{"oauth"},
		RuntimeReady:        true,
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
	}
}

// testProviderRegistry returns a registry backed by one executable protocol profile.
// testProviderRegistry 返回一个由可执行协议 Profile 支持的注册表。
func testProviderRegistry(t *testing.T) *Registry {
	t.Helper()
	protocols := providerconfig.NewProtocolRegistry()
	errProfile := protocols.Register(providerconfig.ProtocolProfile{
		ID:                 "anthropic.messages.v1",
		Version:            "1",
		DisplayName:        "Anthropic Messages",
		RuntimeReady:       true,
		ModelDiscovery:     providerconfig.SupportUnsupported,
		AllowedAuthMethods: []providerconfig.AuthMethodType{providerconfig.AuthMethodBearer},
	})
	if errProfile != nil {
		t.Fatalf("register protocol profile: %v", errProfile)
	}
	systems, errSystems := providerconfig.NewSystemRegistry(protocols)
	if errSystems != nil {
		t.Fatalf("create system registry: %v", errSystems)
	}
	registry, errRegistry := NewRegistry(systems)
	if errRegistry != nil {
		t.Fatalf("create provider registry: %v", errRegistry)
	}
	return registry
}

// TestRegistryAcceptsMatchingDriverContract verifies minimum trusted-library registration.
// TestRegistryAcceptsMatchingDriverContract 校验最小受信任库注册。
func TestRegistryAcceptsMatchingDriverContract(t *testing.T) {
	registry := testProviderRegistry(t)
	if err := registry.Register(testDriver{definition: testProviderDefinition()}); err != nil {
		t.Fatalf("register provider driver: %v", err)
	}
	if _, exists := registry.Lookup("system_test_provider"); !exists {
		t.Fatal("registered provider driver was not found")
	}
}

// TestRegistryRejectsUnsupportedFeatureContract verifies metadata cannot overstate implementation.
// TestRegistryRejectsUnsupportedFeatureContract 校验元数据不能夸大实际实现能力。
func TestRegistryRejectsUnsupportedFeatureContract(t *testing.T) {
	registry := testProviderRegistry(t)
	definition := testProviderDefinition()
	definition.Features.ModelDiscovery = providerconfig.SupportSupported
	if err := registry.Register(testDriver{definition: definition}); err == nil {
		t.Fatal("expected missing ModelDiscoverer implementation rejection")
	}
}
