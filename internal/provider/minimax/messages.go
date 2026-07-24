// Package minimax contains MiniMax provider-specific execution behavior.
// Package minimax 包含 MiniMax 供应商专属执行行为。
package minimax

import (
	"fmt"

	protocolmessages "github.com/OpenVulcan/vulcan-model-core/internal/protocol/anthropic/messages"
	openairesponses "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/responses"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	translateddriver "github.com/OpenVulcan/vulcan-model-core/internal/provider/translatedresponses"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
)

const (
	// ConversationRespondActionBindingID identifies MiniMax's Anthropic-compatible text action.
	// ConversationRespondActionBindingID 标识 MiniMax 的 Anthropic 兼容文本动作。
	ConversationRespondActionBindingID = "action_conversation_respond"
)

// MessagesDriver executes MiniMax text requests through the exact Messages endpoint used by minimax-cli.
// MessagesDriver 通过 minimax-cli 使用的精确 Messages 端点执行 MiniMax 文本请求。
type MessagesDriver struct {
	// Driver owns the copied typed Messages translation and response decoding path.
	// Driver 管理复制的类型化 Messages 转换与响应解码路径。
	*translateddriver.Driver
}

// NewMessagesDriver constructs one region-fixed MiniMax Messages driver.
// NewMessagesDriver 构造一个区域固定的 MiniMax Messages 驱动。
func NewMessagesDriver(definitionID string, client *transport.Client, capabilities openairesponses.ProfileCapabilities, allowedAuthMethods []providerconfig.AuthMethodType) (*MessagesDriver, error) {
	if len(allowedAuthMethods) == 0 {
		return nil, fmt.Errorf("MiniMax Messages driver requires at least one authentication method")
	}
	driver, errDriver := translateddriver.NewDriver(translateddriver.Configuration{
		DefinitionID: definitionID,
		Profile:      protocolmessages.Profile(),
		Client:       client,
		Capabilities: capabilities,
		Path:         "/anthropic/v1/messages",
		StreamPath:   "/anthropic/v1/messages",
		Headers: []transport.Header{
			{Name: "Content-Type", Value: "application/json"},
		},
		Authentication:     transport.Authentication{Mode: transport.AuthenticationHeader, HeaderName: "x-api-key"},
		AllowedAuthMethods: append([]providerconfig.AuthMethodType(nil), allowedAuthMethods...),
		StreamInputMode:    translateddriver.StreamInputLine,
		// ForceTranslationStream preserves the Anthropic translator's SSE contract while the Router still aggregates non-stream callers.
		// ForceTranslationStream 保留 Anthropic 转换器的 SSE 合同，同时 Router 仍为非流式调用方完成聚合。
		ForceTranslationStream: true,
	})
	if errDriver != nil {
		return nil, errDriver
	}
	return &MessagesDriver{Driver: driver}, nil
}

// messagesDriverContract verifies MiniMax Messages satisfies the execution boundary at compile time.
// messagesDriverContract 在编译期验证 MiniMax Messages 满足执行边界。
var _ provider.ExecutionDriver = (*MessagesDriver)(nil)
