package bootstrap

import (
	"errors"
	"net/http"
	"testing"

	protocolmessages "github.com/OpenVulcan/vulcan-model-core/internal/protocol/anthropic/messages"
	protocolaistudio "github.com/OpenVulcan/vulcan-model-core/internal/protocol/google/aistudio"
	protocolchat "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/chat"
	protocolresponses "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/responses"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

// TestCustomExecutionDriverFactoryBuildsOnlyWhitelistedShapes verifies exact protocol, endpoint, and authentication tuples.
// TestCustomExecutionDriverFactoryBuildsOnlyWhitelistedShapes 验证精确的协议、Endpoint 与认证组合。
func TestCustomExecutionDriverFactoryBuildsOnlyWhitelistedShapes(t *testing.T) {
	factory := newCustomExecutionFactoryFixture(t)
	for _, definition := range []providerconfig.ProviderDefinition{
		customExecutionDefinition("custom-openai", protocolchat.ProfileID, providerconfig.CustomEndpointProfileOpenAICompatibility, providerconfig.AuthMethodBearer),
		customExecutionDefinition("custom-openai-responses", protocolresponses.ProfileID, providerconfig.CustomEndpointProfileOpenAIResponsesCompatibility, providerconfig.AuthMethodBearer),
		customExecutionDefinition("custom-anthropic", protocolmessages.ProfileID, providerconfig.CustomEndpointProfileAnthropicMessagesCompatibility, providerconfig.AuthMethodHeaderKey),
		customExecutionDefinition("custom-vertex", protocolaistudio.ProfileID, providerconfig.CustomEndpointProfileVertexCompatibility, providerconfig.AuthMethodHeaderKey),
	} {
		driver, errDriver := factory.BuildCustomDriver(definition)
		if errDriver != nil {
			t.Fatalf("BuildCustomDriver(%q) error = %v", definition.ID, errDriver)
		}
		if driver.ProviderDefinitionID() != definition.ID || driver.ProtocolProfileID() != definition.ProtocolProfileID {
			t.Fatalf("driver ownership = %q / %q, want %q / %q", driver.ProviderDefinitionID(), driver.ProtocolProfileID(), definition.ID, definition.ProtocolProfileID)
		}
	}
}

// TestCustomExecutionDriverFactoryRejectsShapeDrift verifies no generic fallback can hide unsupported custom configuration.
// TestCustomExecutionDriverFactoryRejectsShapeDrift 验证通用降级不能掩盖不受支持的自定义配置。
func TestCustomExecutionDriverFactoryRejectsShapeDrift(t *testing.T) {
	factory := newCustomExecutionFactoryFixture(t)
	for _, testCase := range []struct {
		// name identifies the exact closed-shape violation.
		// name 标识精确的封闭形态违规项。
		name string
		// definition is the immutable invalid definition snapshot.
		// definition 是不可变的无效 Definition 快照。
		definition providerconfig.ProviderDefinition
	}{
		{name: "system ownership", definition: func() providerconfig.ProviderDefinition {
			definition := customExecutionDefinition("system-openai", protocolchat.ProfileID, providerconfig.CustomEndpointProfileOpenAICompatibility, providerconfig.AuthMethodBearer)
			definition.Kind = providerconfig.DefinitionKindSystem
			return definition
		}()},
		{name: "openai header auth", definition: customExecutionDefinition("custom-openai-header", protocolchat.ProfileID, providerconfig.CustomEndpointProfileOpenAICompatibility, providerconfig.AuthMethodHeaderKey)},
		{name: "responses header auth", definition: customExecutionDefinition("custom-responses-header", protocolresponses.ProfileID, providerconfig.CustomEndpointProfileOpenAIResponsesCompatibility, providerconfig.AuthMethodHeaderKey)},
		{name: "anthropic bearer auth", definition: customExecutionDefinition("custom-anthropic-bearer", protocolmessages.ProfileID, providerconfig.CustomEndpointProfileAnthropicMessagesCompatibility, providerconfig.AuthMethodBearer)},
		{name: "vertex bearer auth", definition: customExecutionDefinition("custom-vertex-bearer", protocolaistudio.ProfileID, providerconfig.CustomEndpointProfileVertexCompatibility, providerconfig.AuthMethodBearer)},
		{name: "endpoint drift", definition: customExecutionDefinition("custom-endpoint-drift", protocolchat.ProfileID, providerconfig.CustomEndpointProfileVertexCompatibility, providerconfig.AuthMethodBearer)},
		{name: "unsupported protocol", definition: customExecutionDefinition("custom-special", "google.interactions", "google-interactions", providerconfig.AuthMethodBearer)},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if _, errDriver := factory.BuildCustomDriver(testCase.definition); !errors.Is(errDriver, ErrInvalidCustomExecutionDefinition) {
				t.Fatalf("BuildCustomDriver() error = %v, want ErrInvalidCustomExecutionDefinition", errDriver)
			}
		})
	}
}

// newCustomExecutionFactoryFixture creates one raw-secret transport factory without performing network traffic.
// newCustomExecutionFactoryFixture 创建一个不会执行网络流量的原始 Secret 传输 Factory。
func newCustomExecutionFactoryFixture(t *testing.T) *customExecutionDriverFactory {
	t.Helper()
	client, errClient := transport.NewClient(http.DefaultClient, secret.NewMemoryStore(), transport.RetryPolicy{})
	if errClient != nil {
		t.Fatalf("NewClient() error = %v", errClient)
	}
	return &customExecutionDriverFactory{client: client}
}

// customExecutionDefinition builds one exact custom definition fixture.
// customExecutionDefinition 构建一个精确的自定义 Definition 夹具。
func customExecutionDefinition(definitionID string, profileID string, endpointProfileID string, authMethodType providerconfig.AuthMethodType) providerconfig.ProviderDefinition {
	return providerconfig.ProviderDefinition{
		ID: definitionID, Kind: providerconfig.DefinitionKindCustom, DisplayName: definitionID, ConfigSchemaVersion: "1",
		ProtocolProfileID: profileID, EndpointProfileID: endpointProfileID, AuthMethodIDs: []string{"default"}, RuntimeReady: true,
		AuthMethods: []providerconfig.AuthMethodDefinition{{ID: "default", Type: authMethodType, MultipleCredentials: true}}, Revision: 1,
	}
}
