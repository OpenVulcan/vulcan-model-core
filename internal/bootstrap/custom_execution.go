package bootstrap

import (
	"errors"
	"fmt"
	"strings"

	protocolmessages "github.com/OpenVulcan/vulcan-model-core/internal/protocol/anthropic/messages"
	protocolaistudio "github.com/OpenVulcan/vulcan-model-core/internal/protocol/google/aistudio"
	protocolchat "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/chat"
	protocolresponses "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/responses"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	provideranthropic "github.com/OpenVulcan/vulcan-model-core/internal/provider/anthropic"
	providergoogle "github.com/OpenVulcan/vulcan-model-core/internal/provider/google"
	provideropenai "github.com/OpenVulcan/vulcan-model-core/internal/provider/openai"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
)

var (
	// ErrInvalidCustomExecutionDefinition reports a persisted custom shape that no approved Driver can execute exactly.
	// ErrInvalidCustomExecutionDefinition 表示已持久化自定义形态无法被任何已批准 Driver 精确执行。
	ErrInvalidCustomExecutionDefinition = errors.New("invalid custom execution definition")
)

// customExecutionDriverFactory owns the exact standard custom-provider runtime whitelist and legacy Vertex compatibility.
// customExecutionDriverFactory 拥有精确的标准自定义供应商运行时白名单与旧版 Vertex 兼容能力。
type customExecutionDriverFactory struct {
	// client owns raw custom-provider secrets and immutable-target HTTP execution.
	// client 管理自定义供应商原始 Secret 与不可变 Target HTTP 执行。
	client *transport.Client
}

// RegisterCustomExecutionDriverFactory installs the sole dynamic custom-provider execution owner.
// RegisterCustomExecutionDriverFactory 安装唯一的动态自定义供应商执行所有者。
func RegisterCustomExecutionDriverFactory(registry *provider.ExecutionRegistry, client *transport.Client) error {
	if registry == nil || client == nil {
		return fmt.Errorf("custom execution registry and transport client are required")
	}
	return registry.RegisterCustomFactory(&customExecutionDriverFactory{client: client})
}

// BuildCustomDriver validates one closed persisted shape and constructs an exact request-scoped Driver.
// BuildCustomDriver 校验一个封闭的已持久化形态，并构造精确的请求作用域 Driver。
func (f *customExecutionDriverFactory) BuildCustomDriver(definition providerconfig.ProviderDefinition) (provider.ExecutionDriver, error) {
	if f == nil || f.client == nil {
		return nil, fmt.Errorf("%w: transport client is required", ErrInvalidCustomExecutionDefinition)
	}
	if errShape := validateCustomExecutionShape(definition); errShape != nil {
		return nil, errShape
	}
	switch definition.ProtocolProfileID {
	case protocolchat.ProfileID:
		driver, errDriver := provideropenai.NewOpenAICompatibilityDriver(definition.ID, f.client, openAICompatibilityCapabilities())
		if errDriver != nil {
			return nil, fmt.Errorf("%w: create OpenAICompatibility driver: %v", ErrInvalidCustomExecutionDefinition, errDriver)
		}
		return driver, nil
	case protocolresponses.ProfileID:
		driver, errDriver := provideropenai.NewOpenAIResponsesCompatibilityDriver(definition.ID, f.client, standardCompatibilityCapabilities())
		if errDriver != nil {
			return nil, fmt.Errorf("%w: create OpenAI Responses compatibility driver: %v", ErrInvalidCustomExecutionDefinition, errDriver)
		}
		return driver, nil
	case protocolmessages.ProfileID:
		driver, errDriver := provideranthropic.NewMessagesDriver(definition.ID, f.client, standardCompatibilityCapabilities())
		if errDriver != nil {
			return nil, fmt.Errorf("%w: create Anthropic Messages compatibility driver: %v", ErrInvalidCustomExecutionDefinition, errDriver)
		}
		return driver, nil
	case protocolaistudio.ProfileID:
		driver, errDriver := providergoogle.NewVertexCompatDriver(definition.ID, f.client, vertexCompatibilityCapabilities())
		if errDriver != nil {
			return nil, fmt.Errorf("%w: create VertexCompat driver: %v", ErrInvalidCustomExecutionDefinition, errDriver)
		}
		return driver, nil
	default:
		return nil, fmt.Errorf("%w: protocol profile %q is not whitelisted", ErrInvalidCustomExecutionDefinition, definition.ProtocolProfileID)
	}
}

// validateCustomExecutionShape enforces the exact definition, endpoint, and authentication tuples implemented by copied Drivers.
// validateCustomExecutionShape 强制执行复制 Driver 所实现的精确 Definition、Endpoint 与认证组合。
func validateCustomExecutionShape(definition providerconfig.ProviderDefinition) error {
	if definition.Kind != providerconfig.DefinitionKindCustom || !definition.RuntimeReady || strings.TrimSpace(definition.ID) == "" || definition.Revision == 0 {
		return fmt.Errorf("%w: custom ownership, runtime readiness, identifier, and revision are required", ErrInvalidCustomExecutionDefinition)
	}
	if len(definition.AuthMethodIDs) != 1 || definition.AuthMethodIDs[0] != "default" || len(definition.AuthMethods) != 1 || definition.AuthMethods[0].ID != "default" {
		return fmt.Errorf("%w: exactly one default authentication method is required", ErrInvalidCustomExecutionDefinition)
	}
	switch definition.ProtocolProfileID {
	case protocolchat.ProfileID:
		if definition.EndpointProfileID != providerconfig.CustomEndpointProfileOpenAICompatibility || definition.AuthMethods[0].Type != providerconfig.AuthMethodBearer {
			return fmt.Errorf("%w: OpenAICompatibility requires endpoint profile %q and bearer authentication", ErrInvalidCustomExecutionDefinition, providerconfig.CustomEndpointProfileOpenAICompatibility)
		}
	case protocolresponses.ProfileID:
		if definition.EndpointProfileID != providerconfig.CustomEndpointProfileOpenAIResponsesCompatibility || definition.AuthMethods[0].Type != providerconfig.AuthMethodBearer {
			return fmt.Errorf("%w: OpenAI Responses compatibility requires endpoint profile %q and bearer authentication", ErrInvalidCustomExecutionDefinition, providerconfig.CustomEndpointProfileOpenAIResponsesCompatibility)
		}
	case protocolmessages.ProfileID:
		if definition.EndpointProfileID != providerconfig.CustomEndpointProfileAnthropicMessagesCompatibility || definition.AuthMethods[0].Type != providerconfig.AuthMethodHeaderKey {
			return fmt.Errorf("%w: Anthropic Messages compatibility requires endpoint profile %q and header API-key authentication", ErrInvalidCustomExecutionDefinition, providerconfig.CustomEndpointProfileAnthropicMessagesCompatibility)
		}
	case protocolaistudio.ProfileID:
		if definition.EndpointProfileID != providerconfig.CustomEndpointProfileVertexCompatibility || definition.AuthMethods[0].Type != providerconfig.AuthMethodHeaderKey {
			return fmt.Errorf("%w: VertexCompat requires endpoint profile %q and header API-key authentication", ErrInvalidCustomExecutionDefinition, providerconfig.CustomEndpointProfileVertexCompatibility)
		}
	default:
		return fmt.Errorf("%w: protocol profile %q is not whitelisted", ErrInvalidCustomExecutionDefinition, definition.ProtocolProfileID)
	}
	return nil
}

// openAICompatibilityCapabilities returns the wire behaviors CLIProxyAPI's OpenAI-compatible executor translates explicitly.
// openAICompatibilityCapabilities 返回 CLIProxyAPI OpenAI 兼容执行器显式转换的 Wire 行为。
func openAICompatibilityCapabilities() protocolchat.ProfileCapabilities {
	return protocolchat.ProfileCapabilities{NativeSystemPreamble: true, NativeInlineSystem: true, StructuredTools: true, ParallelTools: true, StreamingToolArguments: true, StrictJSONSchema: true, Reasoning: true, ReasoningContent: true}
}

// standardCompatibilityCapabilities returns only broadly implemented standard conversation behaviors for custom providers.
// standardCompatibilityCapabilities 仅返回自定义供应商普遍实现的标准会话行为。
func standardCompatibilityCapabilities() protocolresponses.ProfileCapabilities {
	return protocolresponses.ProfileCapabilities{NativeSystemPreamble: true, StructuredTools: true, ParallelTools: true, StreamingToolArguments: true, StrictJSONSchema: true, Reasoning: true}
}

// vertexCompatibilityCapabilities returns the Gemini behaviors CLIProxyAPI's VertexCompat executor translates explicitly.
// vertexCompatibilityCapabilities 返回 CLIProxyAPI VertexCompat 执行器显式转换的 Gemini 行为。
func vertexCompatibilityCapabilities() protocolaistudio.ProfileCapabilities {
	return protocolaistudio.ProfileCapabilities{NativeSystemInstruction: true, StructuredTools: true, ParallelTools: true, StrictJSONSchema: true, NativeReasoning: true, NativeReasoningSummary: true}
}
