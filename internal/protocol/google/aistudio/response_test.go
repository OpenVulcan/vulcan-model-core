// Response fixtures cover behavior adapted from CLIProxyAPI commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// 响应夹具覆盖改编自 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66 的行为。
// Source path: internal/translator/gemini/claude/gemini_claude_response.go.
// 来源路径：internal/translator/gemini/claude/gemini_claude_response.go。
// The fixtures verify typed AI Studio response reconstruction without importing CLIProxyAPI translator runtime code.
// 夹具验证类型化 AI Studio 响应重建，不导入 CLIProxyAPI Translator 运行时代码。
package aistudio

import (
	"testing"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestDecodeResponseUsesCommonReducer verifies a complete JSON response has the same event and usage semantics as the streaming decoder.
// TestDecodeResponseUsesCommonReducer 验证完整 JSON 响应与流式解码器具有相同的事件和用量语义。
func TestDecodeResponseUsesCommonReducer(t *testing.T) {
	upstream := GenerateContentResponse{
		ResponseID: "upstream-response-4",
		Candidates: []Candidate{{
			Content: &Content{Role: "model", Parts: []Part{{Text: "Hello"}}}, FinishReason: "STOP",
		}},
		UsageMetadata: &UsageMetadata{PromptTokenCount: aiStudioInt64(4), CandidatesTokenCount: aiStudioInt64(2), TotalTokenCount: aiStudioInt64(6)},
	}
	response, events, report, errDecode := DecodeResponse("response-4", upstream, nil, aiStudioNow())
	if errDecode != nil {
		t.Fatalf("DecodeResponse() error = %v", errDecode)
	}
	if response.Status != vcp.ResponseCompleted || len(response.Items) != 1 || response.Items[0].Content[0].Text != "Hello" || response.Usage == nil || response.Usage.InputTokens == nil || *response.Usage.InputTokens != 4 {
		t.Fatalf("response = %#v", response)
	}
	if report.Usage == nil || report.Usage.TotalTokens == nil || *report.Usage.TotalTokens != 6 || len(events) == 0 || events[len(events)-1].Type != vcp.EventResponseCompleted {
		t.Fatalf("events = %#v, report = %#v", events, report)
	}
}

// TestDecodeResponseMapsPromptSafetyToRefusalFailure verifies prompt-level block categories remain explicit without leaking provider text.
// TestDecodeResponseMapsPromptSafetyToRefusalFailure 验证提示词级阻断类别保持显式，且不泄露 Provider 文本。
func TestDecodeResponseMapsPromptSafetyToRefusalFailure(t *testing.T) {
	// testCases contain every documented prompt block category and one unknown value for the safe fallback boundary.
	// testCases 包含每个文档化提示词阻断类别及一个未知值，用于安全兜底边界。
	testCases := []struct {
		// blockReason is the upstream prompt-feedback category.
		// blockReason 是上游提示词反馈类别。
		blockReason string
		// errorCode is the expected VCP-safe diagnostic.
		// errorCode 是预期的 VCP 安全诊断代码。
		errorCode string
	}{
		{blockReason: "SAFETY", errorCode: "google_aistudio.prompt_blocked.safety"},
		{blockReason: "OTHER", errorCode: "google_aistudio.prompt_blocked.other"},
		{blockReason: "BLOCKLIST", errorCode: "google_aistudio.prompt_blocked.blocklist"},
		{blockReason: "PROHIBITED_CONTENT", errorCode: "google_aistudio.prompt_blocked.prohibited_content"},
		{blockReason: "IMAGE_SAFETY", errorCode: "google_aistudio.prompt_blocked.image_safety"},
		{blockReason: "UNRECOGNIZED", errorCode: "google_aistudio.prompt_blocked.unknown"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.blockReason, func(t *testing.T) {
			// upstream carries only safe protocol enum values in the test fixture.
			// upstream 在测试夹具中仅携带安全协议枚举值。
			upstream := GenerateContentResponse{PromptFeedback: &PromptFeedback{BlockReason: testCase.blockReason}, UsageMetadata: &UsageMetadata{PromptTokenCount: aiStudioInt64(3)}}
			response, events, report, errDecode := DecodeResponse("response-5-"+testCase.blockReason, upstream, nil, aiStudioNow())
			if errDecode != nil {
				t.Fatalf("DecodeResponse() error = %v", errDecode)
			}
			if response.Status != vcp.ResponseFailed || response.ErrorCode != testCase.errorCode || len(response.Items) != 1 || response.Items[0].Kind != vcp.ContextRefusal || response.Items[0].Status != vcp.OutputItemCompleted {
				t.Fatalf("response = %#v", response)
			}
			if report.ErrorOrRetryAdvice != testCase.errorCode || len(events) == 0 || events[len(events)-1].Type != vcp.EventResponseFailed {
				t.Fatalf("events = %#v, report = %#v", events, report)
			}
		})
	}
}

// TestDecodeResponseMapsMaxTokensIncomplete verifies the documented truncation reason stays distinguishable from success.
// TestDecodeResponseMapsMaxTokensIncomplete 验证文档化的截断原因仍可与成功状态区分。
func TestDecodeResponseMapsMaxTokensIncomplete(t *testing.T) {
	upstream := GenerateContentResponse{Candidates: []Candidate{{Content: &Content{Role: "model", Parts: []Part{{Text: "Partial"}}}, FinishReason: "MAX_TOKENS"}}}
	response, _, _, errDecode := DecodeResponse("response-6", upstream, nil, aiStudioNow())
	if errDecode != nil {
		t.Fatalf("DecodeResponse() error = %v", errDecode)
	}
	if response.Status != vcp.ResponseIncomplete || response.FinishReason != "max_tokens" || len(response.Items) != 1 || response.Items[0].Status != vcp.OutputItemCompleted {
		t.Fatalf("response = %#v", response)
	}
}
