package chat

import (
	"reflect"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestDecodeResponseMapsContentToolsUsageAndSynthesis verifies non-streaming semantics.
// TestDecodeResponseMapsContentToolsUsageAndSynthesis 校验非流式语义。
func TestDecodeResponseMapsContentToolsUsageAndSynthesis(t *testing.T) {
	promptTokens := int64(4)
	completionTokens := int64(3)
	totalTokens := int64(7)
	upstream := Response{
		ID:      "chatcmpl_1",
		Choices: []Choice{{Index: 0, Message: &AssistantMessage{Content: "Done", ToolCalls: []ToolCall{{Type: "function", Function: FunctionCall{Name: "lookup", Arguments: `{"q":"x"}`}}}}, FinishReason: "tool_calls"}},
		Usage:   &Usage{PromptTokens: &promptTokens, CompletionTokens: &completionTokens, TotalTokens: &totalTokens},
	}
	response, events, report, errDecode := DecodeResponse("resp_1", upstream, time.Unix(40, 0))
	if errDecode != nil {
		t.Fatalf("DecodeResponse() error = %v", errDecode)
	}
	if response.Status != vcp.ResponseCompleted || len(response.Items) != 2 {
		t.Fatalf("response = %#v", response)
	}
	if response.Items[1].ToolCall == nil || !response.Items[1].ToolCall.SynthesizedID || response.Items[1].ToolCall.ToolCallID == "" {
		t.Fatalf("tool call = %#v", response.Items[1].ToolCall)
	}
	if report.Usage == nil || report.Usage.TotalTokens == nil || *report.Usage.TotalTokens != 7 {
		t.Fatalf("usage report = %#v", report.Usage)
	}
	if !reflect.DeepEqual(report.ConversionSummary, []string{"openai_chat.tool_call.id_synthesized"}) {
		t.Fatalf("conversion summary = %#v", report.ConversionSummary)
	}
	assertMonotonicEvents(t, events)
}

// TestDecodeResponseMapsRefusalAndErrors verifies refusal and structured failure paths.
// TestDecodeResponseMapsRefusalAndErrors 校验拒绝和结构化失败路径。
func TestDecodeResponseMapsRefusalAndErrors(t *testing.T) {
	refusal, _, _, errRefusal := DecodeResponse("resp_refusal", Response{Choices: []Choice{{Index: 0, Message: &AssistantMessage{Refusal: "Cannot comply"}, FinishReason: "stop"}}}, time.Unix(41, 0))
	if errRefusal != nil || refusal.Status != vcp.ResponseCompleted || refusal.Items[0].Kind != vcp.ContextRefusal {
		t.Fatalf("refusal = %#v, %v", refusal, errRefusal)
	}
	failed, _, report, errFailed := DecodeResponse("resp_failed", Response{Error: &Error{Code: "rate_limit_error", Message: "sensitive upstream detail"}}, time.Unix(42, 0))
	if errFailed != nil || failed.Status != vcp.ResponseFailed || report.ErrorOrRetryAdvice != "rate_limit_error" {
		t.Fatalf("failed = %#v, report = %#v, err = %v", failed, report, errFailed)
	}
}

// assertMonotonicEvents verifies global sequence and stable event IDs.
// assertMonotonicEvents 校验全局序号和稳定事件 ID。
func assertMonotonicEvents(t *testing.T, events []vcp.Event) {
	t.Helper()
	for index, event := range events {
		if event.Sequence != uint64(index+1) || event.EventID == "" {
			t.Fatalf("event %d = %#v", index, event)
		}
	}
}
