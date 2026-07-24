// Package deepseek implements exact official DeepSeek provider adaptations.
// Package deepseek 实现精确的 DeepSeek 官方供应商适配。
package deepseek

import (
	"context"
	"errors"

	chatprofile "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/chat"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
)

var (
	// ErrInvalidChatAdapter reports an incomplete DeepSeek Chat wire adapter.
	// ErrInvalidChatAdapter 表示 DeepSeek Chat Wire 适配器不完整。
	ErrInvalidChatAdapter = errors.New("invalid DeepSeek Chat adapter")
)

// ChatAdapter applies DeepSeek's official thinking.type switch after typed Chat projection.
// ChatAdapter 在类型化 Chat 投影后应用 DeepSeek 官方 thinking.type 开关。
type ChatAdapter struct{}

// NewChatAdapter creates one stateless DeepSeek Chat request adapter.
// NewChatAdapter 创建一个无状态的 DeepSeek Chat 请求适配器。
func NewChatAdapter() *ChatAdapter {
	return &ChatAdapter{}
}

// Adapt maps an explicit VCP reasoning switch without changing DeepSeek's independent reasoning_effort field.
// Adapt 映射显式 VCP 推理开关，同时不改变 DeepSeek 独立的 reasoning_effort 字段。
func (a *ChatAdapter) Adapt(_ context.Context, execution provider.ExecutionRequest, request *chatprofile.Request) ([]transport.Header, error) {
	if a == nil || request == nil {
		return nil, ErrInvalidChatAdapter
	}
	if execution.Request.ReasoningPolicy.Enabled == nil {
		return nil, nil
	}
	thinkingMode := chatprofile.ThinkingDisabled
	if *execution.Request.ReasoningPolicy.Enabled {
		thinkingMode = chatprofile.ThinkingEnabled
	}
	request.Thinking = &chatprofile.ThinkingConfiguration{Type: thinkingMode}
	return nil, nil
}
