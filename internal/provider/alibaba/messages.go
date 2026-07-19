// Package alibaba contains Alibaba Cloud Model Studio provider-specific execution behavior.
// Package alibaba 包含阿里云百炼供应商专属执行行为。
package alibaba

import (
	"fmt"

	protocolmessages "github.com/OpenVulcan/vulcan-model-core/internal/protocol/anthropic/messages"
	openairesponses "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/responses"
	protocolbridge "github.com/OpenVulcan/vulcan-model-core/internal/protocol/translatedresponses"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	translateddriver "github.com/OpenVulcan/vulcan-model-core/internal/provider/translatedresponses"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/tidwall/sjson"
)

// MessagesDriver executes one Alibaba plan definition through its Anthropic-compatible Messages endpoint.
// MessagesDriver 通过阿里云 Anthropic 兼容 Messages 端点执行一个套餐定义。
type MessagesDriver struct {
	// Driver owns the shared translated-response execution mechanics.
	// Driver 管理共享的转换响应执行机制。
	*translateddriver.Driver
}

// NewMessagesDriver constructs an Alibaba Messages driver without Claude-specific headers or endpoint behavior.
// NewMessagesDriver 构造不携带 Claude 专属 Header 或端点行为的阿里云 Messages 驱动。
func NewMessagesDriver(definitionID string, client *transport.Client, capabilities openairesponses.ProfileCapabilities) (*MessagesDriver, error) {
	driver, errDriver := translateddriver.NewDriver(translateddriver.Configuration{
		DefinitionID: definitionID,
		Profile:      protocolmessages.Profile(),
		Client:       client,
		Capabilities: capabilities,
		Path:         "/messages",
		StreamPath:   "/messages",
		Headers: []transport.Header{
			{Name: "Content-Type", Value: "application/json"},
			{Name: "Anthropic-Version", Value: "2023-06-01"},
		},
		Authentication:     transport.Authentication{Mode: transport.AuthenticationHeader, HeaderName: "x-api-key"},
		AllowedAuthMethods: []providerconfig.AuthMethodType{providerconfig.AuthMethodAPIKey},
		StreamInputMode:    translateddriver.StreamInputLine,
		AdaptBody:          adaptMessagesBody,
	})
	if errDriver != nil {
		return nil, errDriver
	}
	return &MessagesDriver{Driver: driver}, nil
}

// adaptMessagesBody applies Alibaba-only token defaults and streaming tool controls after protocol translation.
// adaptMessagesBody 在协议转换后应用阿里云专属 Token 默认值与流式工具控制。
func adaptMessagesBody(execution provider.ExecutionRequest, projected protocolbridge.ProjectedRequest) ([]byte, error) {
	// body preserves the copied translator output while adding only documented Alibaba extensions.
	// body 保留复制翻译器输出，同时仅增加有文档依据的阿里云扩展。
	body := append([]byte(nil), projected.UpstreamJSON...)
	if requestedOutput := execution.Request.GenerationPolicy.MaxOutputTokens; requestedOutput != nil {
		maximumOutput := execution.Binding.Target.TokenLimits.MaxOutputTokens
		if maximumOutput.Known && int64(*requestedOutput) > maximumOutput.Value {
			return nil, fmt.Errorf("Alibaba requested output tokens %d exceed model maximum %d", *requestedOutput, maximumOutput.Value)
		}
	} else if recommendedOutput := execution.Binding.Target.TokenRecommendations.OutputTokens; recommendedOutput.Known {
		var errOutput error
		body, errOutput = setBodyInteger(body, "max_tokens", recommendedOutput.Value)
		if errOutput != nil {
			return nil, errOutput
		}
	}
	if execution.Request.Stream && len(execution.Request.Tools) > 0 && supportsStreamingToolArguments(execution.Binding.Target.UpstreamModelID) {
		var errToolStream error
		body, errToolStream = sjson.SetBytes(body, "tool_stream", true)
		if errToolStream != nil {
			return nil, fmt.Errorf("adapt Alibaba Messages tool_stream: %w", errToolStream)
		}
	}
	return body, nil
}

// supportsStreamingToolArguments reports whether official Alibaba evidence permits tool_stream for one exact model.
// supportsStreamingToolArguments 报告阿里云官方证据是否允许一个精确模型使用 tool_stream。
func supportsStreamingToolArguments(modelID string) bool {
	switch modelID {
	case "qwen3.7-max", "qwen3.7-plus", "qwen3.6-plus", "qwen3.6-flash", "qwen3.5-plus",
		"glm-5.2", "glm-5.1", "glm-5", "glm-4.7":
		return true
	default:
		return false
	}
}

// setBodyInteger writes one provider extension integer without decoding the typed translated envelope.
// setBodyInteger 在不解码类型化转换信封的情况下写入一个供应商扩展整数。
func setBodyInteger(body []byte, path string, value int64) ([]byte, error) {
	updated, errSet := sjson.SetBytes(body, path, value)
	if errSet != nil {
		return nil, fmt.Errorf("adapt Alibaba Messages %s: %w", path, errSet)
	}
	return updated, nil
}
