package deepseek

import (
	"context"
	"testing"

	chatprofile "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/chat"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestChatAdapterMapsExplicitReasoningSwitch verifies enabled and disabled requests use the official thinking.type contract.
// TestChatAdapterMapsExplicitReasoningSwitch 验证启用与禁用请求使用官方 thinking.type 合同。
func TestChatAdapterMapsExplicitReasoningSwitch(t *testing.T) {
	testCases := []struct {
		// name identifies one explicit VCP switch case.
		// name 标识一个显式 VCP 开关场景。
		name string
		// enabled is the canonical requested reasoning state.
		// enabled 是规范请求的推理状态。
		enabled bool
		// expected is the exact DeepSeek wire value.
		// expected 是精确的 DeepSeek Wire 值。
		expected chatprofile.ThinkingMode
	}{
		{name: "enabled", enabled: true, expected: chatprofile.ThinkingEnabled},
		{name: "disabled", enabled: false, expected: chatprofile.ThinkingDisabled},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			request := chatprofile.Request{ReasoningEffort: "max"}
			execution := provider.ExecutionRequest{Request: vcp.VulcanRequest{ReasoningPolicy: vcp.ReasoningPolicy{Enabled: &testCase.enabled}}}
			if _, errAdapt := NewChatAdapter().Adapt(context.Background(), execution, &request); errAdapt != nil {
				t.Fatalf("Adapt() error = %v", errAdapt)
			}
			if request.Thinking == nil || request.Thinking.Type != testCase.expected {
				t.Fatalf("thinking = %#v, want %q", request.Thinking, testCase.expected)
			}
			if request.ReasoningEffort != "max" {
				t.Fatalf("reasoning_effort = %q, want max", request.ReasoningEffort)
			}
		})
	}
}

// TestChatAdapterPreservesProviderDefaultWhenSwitchIsAbsent verifies omission keeps DeepSeek's documented default behavior.
// TestChatAdapterPreservesProviderDefaultWhenSwitchIsAbsent 验证省略开关时保留 DeepSeek 文档记录的默认行为。
func TestChatAdapterPreservesProviderDefaultWhenSwitchIsAbsent(t *testing.T) {
	request := chatprofile.Request{ReasoningEffort: "high"}
	if _, errAdapt := NewChatAdapter().Adapt(context.Background(), provider.ExecutionRequest{}, &request); errAdapt != nil {
		t.Fatalf("Adapt() error = %v", errAdapt)
	}
	if request.Thinking != nil || request.ReasoningEffort != "high" {
		t.Fatalf("request = %#v", request)
	}
}
