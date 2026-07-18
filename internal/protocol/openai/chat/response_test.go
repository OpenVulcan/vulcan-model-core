// Response fixtures cover behavior adapted from CLIProxyAPI commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// 响应夹具覆盖改编自 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66 的行为。
// Source paths: sdk/api/handlers/openai/openai_handlers.go and internal/runtime/executor/openai_compat_executor.go.
// 来源路径：sdk/api/handlers/openai/openai_handlers.go 和 internal/runtime/executor/openai_compat_executor.go。
// The fixtures verify typed Chat terminal reconstruction without importing CLIProxyAPI runtime code.
// 夹具验证类型化 Chat 终态重建，不导入 CLIProxyAPI 运行时代码。
package chat

import (
	"encoding/json"
	"errors"
	"reflect"
	"slices"
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

// TestDecodeResponseMapsNonSuccessFinishReasons verifies truncation and safety filtering remain distinguishable from successful completion.
// TestDecodeResponseMapsNonSuccessFinishReasons 验证截断和安全过滤始终可与成功完成区分。
func TestDecodeResponseMapsNonSuccessFinishReasons(t *testing.T) {
	truncated, _, _, errTruncated := DecodeResponse("resp_length", Response{Choices: []Choice{{Index: 0, Message: &AssistantMessage{Content: "Partial"}, FinishReason: "length"}}}, time.Unix(43, 0))
	if errTruncated != nil || truncated.Status != vcp.ResponseIncomplete || truncated.FinishReason != "length" {
		t.Fatalf("truncated = %#v, err = %v", truncated, errTruncated)
	}
	filtered, _, report, errFiltered := DecodeResponse("resp_filtered", Response{Choices: []Choice{{Index: 0, Message: &AssistantMessage{}, FinishReason: "content_filter"}}}, time.Unix(44, 0))
	if errFiltered != nil || filtered.Status != vcp.ResponseFailed || filtered.ErrorCode != "openai_chat.content_filter" || report.ErrorOrRetryAdvice != "openai_chat.content_filter" {
		t.Fatalf("filtered = %#v, report = %#v, err = %v", filtered, report, errFiltered)
	}
}

// TestDecodeResponseAuditsDocumentedMetadataAndProjectsLegacyFunctionCall verifies documented non-VCP response fields are auditable while the deprecated function carrier remains usable.
// TestDecodeResponseAuditsDocumentedMetadataAndProjectsLegacyFunctionCall 验证文档化的非 VCP 响应字段可审计，同时已废弃函数载体仍可使用。
func TestDecodeResponseAuditsDocumentedMetadataAndProjectsLegacyFunctionCall(t *testing.T) {
	// upstreamJSON includes each documented metadata group that must not enter canonical output or client-safe reports verbatim.
	// upstreamJSON 包含每组不得原样进入规范输出或客户端安全报告的文档化元数据。
	upstreamJSON := []byte(`{"id":"chatcmpl-metadata","object":"chat.completion","created":7,"model":"actual-model","service_tier":"priority","system_fingerprint":"provider-fingerprint","choices":[{"index":0,"logprobs":{"content":[]},"message":{"role":"assistant","content":"Done","annotations":[{"type":"url_citation","url":"https://example.invalid/private"}],"function_call":{"name":"lookup","arguments":"{}"}},"finish_reason":"function_call"}],"usage":{"prompt_tokens":2,"completion_tokens":3,"total_tokens":5,"cost_in_usd_ticks":17,"num_sources_used":1,"prompt_tokens_details":{"audio_tokens":1,"text_tokens":1,"image_tokens":1},"completion_tokens_details":{"audio_tokens":1,"accepted_prediction_tokens":1,"rejected_prediction_tokens":1}}}`)
	var upstream Response
	if errDecode := json.Unmarshal(upstreamJSON, &upstream); errDecode != nil {
		t.Fatalf("json.Unmarshal() error = %v", errDecode)
	}
	response, _, report, errDecode := DecodeResponse("resp_metadata", upstream, time.Unix(45, 0))
	if errDecode != nil {
		t.Fatalf("DecodeResponse() error = %v", errDecode)
	}
	if response.Status != vcp.ResponseCompleted || len(response.Items) != 2 || response.Items[1].ToolCall == nil || response.Items[1].ToolCall.Name != "lookup" {
		t.Fatalf("response = %#v", response)
	}
	// summaryCodes lists every documented group whose values must be omitted from VCP while leaving an audit-safe fixed code.
	// summaryCodes 列出每个必须从 VCP 省略、但需要留下审计安全固定代码的文档化字段组。
	summaryCodes := []string{
		"openai_chat.response.model.omitted",
		"openai_chat.response.created_at.omitted",
		"openai_chat.response.service_tier.omitted",
		"openai_chat.response.system_fingerprint.omitted",
		"openai_chat.choice.logprobs.omitted",
		"openai_chat.message.annotations.omitted",
		"openai_chat.usage.supplemental_tokens.omitted",
		"openai_chat.usage.cost.omitted",
		"openai_chat.usage.sources.omitted",
		"openai_chat.function_call.deprecated_projected",
	}
	for _, summaryCode := range summaryCodes {
		if !slices.Contains(report.ConversionSummary, summaryCode) {
			t.Fatalf("report = %#v, missing summary %q", report, summaryCode)
		}
	}
}

// TestDecodeResponseRejectsUnsupportedAudioPayload verifies first-phase Chat decoding never silently converts audio payloads into text.
// TestDecodeResponseRejectsUnsupportedAudioPayload 验证第一阶段 Chat 解码绝不会静默将音频载荷转换为文本。
func TestDecodeResponseRejectsUnsupportedAudioPayload(t *testing.T) {
	_, _, _, errDecode := DecodeResponse(
		"resp_audio_payload",
		Response{Choices: []Choice{{Index: 0, Message: &AssistantMessage{Audio: &UnsupportedResponsePayload{}}, FinishReason: "stop"}}},
		time.Unix(46, 0),
	)
	if !errors.Is(errDecode, ErrInvalidUpstreamResponse) {
		t.Fatalf("DecodeResponse() error = %v, want ErrInvalidUpstreamResponse", errDecode)
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
