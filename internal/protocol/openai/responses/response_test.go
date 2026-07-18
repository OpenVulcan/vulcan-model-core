// Response fixtures cover behavior adapted from CLIProxyAPI commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// 响应夹具覆盖改编自 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66 的行为。
// Source path: internal/translator/openai/openai/responses/openai_openai-responses_response.go.
// 来源路径：internal/translator/openai/openai/responses/openai_openai-responses_response.go。
// The fixtures verify typed terminal Responses reconstruction without importing CLIProxyAPI translator runtime code.
// 夹具验证类型化终态 Responses 重建，不导入 CLIProxyAPI Translator 运行时代码。
package responses

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestDecodeResponseConvertsTerminalSnapshot verifies a synchronous completed snapshot emits a closed VCP response.
// TestDecodeResponseConvertsTerminalSnapshot 验证同步完成快照会发出封闭的 VCP 响应。
func TestDecodeResponseConvertsTerminalSnapshot(t *testing.T) {
	upstream := Response{ID: "upstream-response-3", Status: "completed", Output: []OutputItem{{ID: "message-item-1", Type: "message", Content: []OutputContent{{Type: "output_text", Text: "Hello"}}}}}
	response, events, report, errDecode := DecodeResponse("response-vcp-3", upstream, responsesNow())
	if errDecode != nil {
		t.Fatalf("DecodeResponse() error = %v", errDecode)
	}
	if response.Status != vcp.ResponseCompleted || len(response.Items) != 1 || response.Items[0].Content[0].Text != "Hello" {
		t.Fatalf("response = %#v", response)
	}
	if len(events) < 3 || events[0].Type != vcp.EventResponseStarted || events[len(events)-1].Type != vcp.EventResponseCompleted {
		t.Fatalf("events = %#v", events)
	}
	if report.ExecutionID == "" || report.ResponseID != "response-vcp-3" {
		t.Fatalf("report = %#v", report)
	}
}

// TestDecodeResponseReportsOmittedOutputAnnotations verifies annotation presence is explicit in both VCP events and the execution report.
// TestDecodeResponseReportsOmittedOutputAnnotations 验证注释存在会在 VCP 事件和执行报告中显式体现。
func TestDecodeResponseReportsOmittedOutputAnnotations(t *testing.T) {
	upstream := Response{
		ID: "upstream-response-annotation", Status: "completed",
		Output: []OutputItem{{
			ID: "message-item-annotation", Type: "message",
			Content: []OutputContent{{Type: "output_text", Text: "Answer", Annotations: []OutputAnnotation{{Type: "url_citation"}}}},
		}},
	}
	_, events, report, errDecode := DecodeResponse("response-vcp-annotation", upstream, responsesNow())
	if errDecode != nil {
		t.Fatalf("DecodeResponse() error = %v", errDecode)
	}
	warningFound := false
	for _, event := range events {
		if event.Type == vcp.EventWarningRaised && event.WarningCode == "openai_responses.output_annotation_omitted" {
			warningFound = true
		}
	}
	reportFound := false
	for _, code := range report.ConversionSummary {
		if code == "openai_responses.output_annotation_omitted" {
			reportFound = true
		}
	}
	if !warningFound || !reportFound {
		t.Fatalf("events = %#v report = %#v", events, report)
	}
}

// TestDecodeResponseAuditsDocumentedResponseMetadata verifies every documented complete-response field without a VCP carrier is represented by a safe fixed audit code.
// TestDecodeResponseAuditsDocumentedResponseMetadata 验证每个没有 VCP 承载字段的文档化完整响应字段都会由安全固定审计代码表示。
func TestDecodeResponseAuditsDocumentedResponseMetadata(t *testing.T) {
	// upstreamJSON includes documented response metadata while keeping private values out of canonical output and execution reports.
	// upstreamJSON 包含文档化响应元数据，同时要求私有值不进入规范输出和执行报告。
	upstreamJSON := []byte(`{"id":"resp-metadata","object":"response","created_at":1,"completed_at":2,"status":"completed","input":[{"role":"user","content":"private input"}],"instructions":"private instructions","max_output_tokens":128,"model":"actual-model","output":[{"id":"message-1","type":"message","role":"assistant","content":[{"type":"output_text","text":"Safe output","annotations":[{"type":"url_citation","url":"https://example.invalid/private"}],"logprobs":[]}]}],"previous_response_id":"resp-previous","reasoning_effort":"high","store":false,"temperature":0.2,"text":{"format":{"type":"text"}},"tool_choice":"auto","tools":[],"top_p":0.9,"truncation":"disabled","user":"private-user","metadata":{"private":"value"},"service_tier":"priority","parallel_tool_calls":true,"background":false,"frequency_penalty":0.1,"presence_penalty":0.2,"usage":{"input_tokens":1,"output_tokens":2,"total_tokens":3,"cost_in_usd_ticks":17}}`)
	var upstream Response
	if errUnmarshal := json.Unmarshal(upstreamJSON, &upstream); errUnmarshal != nil {
		t.Fatalf("json.Unmarshal() error = %v", errUnmarshal)
	}
	response, _, report, errDecode := DecodeResponse("response-vcp-metadata", upstream, responsesNow())
	if errDecode != nil {
		t.Fatalf("DecodeResponse() error = %v", errDecode)
	}
	if response.Status != vcp.ResponseCompleted || len(response.Items) != 1 || response.Items[0].Content[0].Text != "Safe output" {
		t.Fatalf("response = %#v", response)
	}
	// summaryCodes enumerates all metadata groups present in the fixture that must be auditable without retaining their values.
	// summaryCodes 枚举夹具中所有必须可审计且不得保留其值的元数据组。
	summaryCodes := []string{
		"openai_responses.response.timestamps.omitted",
		"openai_responses.response.model.omitted",
		"openai_responses.response.input.omitted",
		"openai_responses.response.instructions.omitted",
		"openai_responses.response.max_output_tokens.omitted",
		"openai_responses.response.previous_response_id.omitted",
		"openai_responses.response.reasoning_effort.omitted",
		"openai_responses.response.store.omitted",
		"openai_responses.response.sampling.omitted",
		"openai_responses.response.text_configuration.omitted",
		"openai_responses.response.tool_configuration.omitted",
		"openai_responses.response.truncation.omitted",
		"openai_responses.response.user.omitted",
		"openai_responses.response.metadata.omitted",
		"openai_responses.response.service_tier.omitted",
		"openai_responses.response.background.omitted",
		"openai_responses.response.penalties.omitted",
		"openai_responses.usage.cost.omitted",
		"openai_responses.output_annotation_omitted",
		"openai_responses.output_logprobs_omitted",
	}
	for _, summaryCode := range summaryCodes {
		if !slices.Contains(report.ConversionSummary, summaryCode) {
			t.Fatalf("report = %#v, missing summary %q", report, summaryCode)
		}
	}
	if strings.Contains(fmt.Sprintf("%#v", report), "private") {
		t.Fatalf("report leaked private upstream metadata: %#v", report)
	}
}

// TestDecodeResponseAuditsErrorMessageWithoutLeakingIt verifies provider diagnostic text becomes a fixed audit code rather than client-visible report content.
// TestDecodeResponseAuditsErrorMessageWithoutLeakingIt 验证 Provider 诊断文本会成为固定审计代码，而不会成为客户端可见报告内容。
func TestDecodeResponseAuditsErrorMessageWithoutLeakingIt(t *testing.T) {
	_, _, report, errDecode := DecodeResponse(
		"response-vcp-error-message",
		Response{ID: "resp-error-message", Status: "failed", Error: &Error{Code: "server_error", Message: "private upstream diagnostic"}},
		responsesNow(),
	)
	if errDecode != nil {
		t.Fatalf("DecodeResponse() error = %v", errDecode)
	}
	if !slices.Contains(report.ConversionSummary, "openai_responses.error.message.omitted") {
		t.Fatalf("report = %#v", report)
	}
	if strings.Contains(fmt.Sprintf("%#v", report), "private upstream diagnostic") {
		t.Fatalf("report leaked provider diagnostic: %#v", report)
	}
}

// TestDecodeResponseReportsEncryptedStateAlongsideVisibleReasoning verifies opaque reasoning state remains auditable even when visible reasoning content also exists.
// TestDecodeResponseReportsEncryptedStateAlongsideVisibleReasoning 验证即使同时存在可见推理内容，不透明推理状态仍保持可审计。
func TestDecodeResponseReportsEncryptedStateAlongsideVisibleReasoning(t *testing.T) {
	upstream := Response{
		ID: "resp-encrypted-reasoning", Status: "completed",
		Output: []OutputItem{{ID: "reasoning-1", Type: "reasoning", EncryptedContent: "opaque-provider-state", Summary: []ReasoningSummary{{Type: "summary_text", Text: "visible summary"}}}},
	}
	_, _, report, errDecode := DecodeResponse("response-vcp-encrypted-reasoning", upstream, responsesNow())
	if errDecode != nil {
		t.Fatalf("DecodeResponse() error = %v", errDecode)
	}
	if !slices.Contains(report.ConversionSummary, "openai_responses.reasoning.encrypted_state_preserved_by_response_id") {
		t.Fatalf("report = %#v", report)
	}
}

// TestDecodeResponsePreservesIncompleteOutputItemStatus verifies a provider-incomplete item remains incomplete after an incomplete response terminal.
// TestDecodeResponsePreservesIncompleteOutputItemStatus 验证 Provider 不完整项目在不完整响应终态后仍保持不完整。
func TestDecodeResponsePreservesIncompleteOutputItemStatus(t *testing.T) {
	upstream := Response{
		ID: "resp-incomplete-item", Status: "incomplete", IncompleteDetails: &IncompleteDetails{Reason: "max_output_tokens"},
		Output: []OutputItem{{ID: "message-incomplete", Type: "message", Role: "assistant", Status: "incomplete", Content: []OutputContent{{Type: "output_text", Text: "Partial output"}}}},
	}
	response, events, _, errDecode := DecodeResponse("response-vcp-incomplete-item", upstream, responsesNow())
	if errDecode != nil {
		t.Fatalf("DecodeResponse() error = %v", errDecode)
	}
	if response.Status != vcp.ResponseIncomplete || len(response.Items) != 1 || response.Items[0].Status != vcp.OutputItemIncomplete {
		t.Fatalf("response = %#v", response)
	}
	for _, event := range events {
		if event.Type == vcp.EventItemCompleted {
			t.Fatalf("events = %#v, incomplete item must not emit item.completed", events)
		}
	}
}

// TestDecodeResponseRejectsCompletedResponseWithOpenOutputItem verifies a completed response cannot silently finalize an upstream item marked in progress.
// TestDecodeResponseRejectsCompletedResponseWithOpenOutputItem 验证已完成响应不能静默完成上游标记为进行中的项目。
func TestDecodeResponseRejectsCompletedResponseWithOpenOutputItem(t *testing.T) {
	upstream := Response{
		ID: "resp-open-item", Status: "completed",
		Output: []OutputItem{{ID: "message-open", Type: "message", Role: "assistant", Status: "in_progress", Content: []OutputContent{{Type: "output_text", Text: "Unfinished"}}}},
	}
	_, _, _, errDecode := DecodeResponse("response-vcp-open-item", upstream, responsesNow())
	if !errors.Is(errDecode, ErrInvalidUpstreamResponse) {
		t.Fatalf("DecodeResponse() error = %v, want ErrInvalidUpstreamResponse", errDecode)
	}
}

// TestDecodeResponseRejectsNonAssistantOutputRole verifies an unexpected output message role cannot be silently coerced into an assistant response.
// TestDecodeResponseRejectsNonAssistantOutputRole 验证意外输出消息角色不能被静默强制转换为助手响应。
func TestDecodeResponseRejectsNonAssistantOutputRole(t *testing.T) {
	upstream := Response{
		ID: "resp-output-role", Status: "completed",
		Output: []OutputItem{{ID: "message-role", Type: "message", Role: "user", Content: []OutputContent{{Type: "output_text", Text: "Invalid role"}}}},
	}
	_, _, _, errDecode := DecodeResponse("response-vcp-output-role", upstream, responsesNow())
	if !errors.Is(errDecode, ErrInvalidUpstreamResponse) {
		t.Fatalf("DecodeResponse() error = %v, want ErrInvalidUpstreamResponse", errDecode)
	}
}

// TestDecodeResponsePreservesTypedTerminalOutputAndUsage verifies message, refusal, tool, reasoning, and usage fields survive one terminal snapshot.
// TestDecodeResponsePreservesTypedTerminalOutputAndUsage 验证消息、拒绝、工具、推理和用量字段会保留在一个终态快照中。
func TestDecodeResponsePreservesTypedTerminalOutputAndUsage(t *testing.T) {
	inputTokens := int64(11)
	outputTokens := int64(7)
	totalTokens := int64(18)
	reasoningTokens := int64(3)
	upstream := Response{
		ID: "upstream-response-complete", Status: "completed",
		Output: []OutputItem{
			{ID: "message-item", Type: "message", Content: []OutputContent{{Type: "output_text", Text: "Hello"}, {Type: "refusal", Refusal: "Cannot provide more"}}},
			{ID: "function-item", Type: "function_call", CallID: "function-call", Name: "lookup", Arguments: `{"city":"Paris"}`},
			{ID: "custom-item", Type: "custom_tool_call", CallID: "custom-call", Name: "apply_patch", Input: "*** Begin Patch"},
			{ID: "reasoning-item", Type: "reasoning", Summary: []ReasoningSummary{{Type: "summary_text", Text: "Checked forecast"}}},
		},
		Usage: &Usage{InputTokens: &inputTokens, OutputTokens: &outputTokens, TotalTokens: &totalTokens, OutputTokensDetails: &OutputTokensDetails{ReasoningTokens: &reasoningTokens}},
	}
	response, _, report, errDecode := DecodeResponse("response-vcp-complete", upstream, responsesNow())
	if errDecode != nil {
		t.Fatalf("DecodeResponse() error = %v", errDecode)
	}
	if response.Status != vcp.ResponseCompleted || len(response.Items) != 5 {
		t.Fatalf("response = %#v", response)
	}
	messageFound := false
	refusalFound := false
	functionFound := false
	customFound := false
	reasoningFound := false
	for _, item := range response.Items {
		switch item.Kind {
		case vcp.ContextMessage:
			messageFound = len(item.Content) == 1 && item.Content[0].Text == "Hello"
		case vcp.ContextRefusal:
			refusalFound = len(item.Content) == 2 && item.Content[1].Type == vcp.ContentRefusal && item.Content[1].Text == "Cannot provide more"
		case vcp.ContextToolCall:
			if item.ToolCall != nil && item.ToolCall.Name == "lookup" && item.ToolCall.Arguments == `{"city":"Paris"}` && item.ToolCall.UpstreamID == "function-call" {
				functionFound = true
			}
			if item.ToolCall != nil && item.ToolCall.Name == "apply_patch" && item.ToolCall.Arguments == "*** Begin Patch" && item.ToolCall.UpstreamID == "custom-call" {
				customFound = true
			}
		case vcp.ContextReasoning:
			reasoningFound = len(item.Content) == 1 && item.Content[0].Text == "Checked forecast"
		}
	}
	if !messageFound || !refusalFound || !functionFound || !customFound || !reasoningFound {
		t.Fatalf("typed output mapping message=%t refusal=%t function=%t custom=%t reasoning=%t items=%#v", messageFound, refusalFound, functionFound, customFound, reasoningFound, response.Items)
	}
	if response.Usage == nil || response.Usage.TotalTokens == nil || *response.Usage.TotalTokens != 18 || report.Usage == nil || report.Usage.ReasoningTokens == nil || *report.Usage.ReasoningTokens != 3 {
		t.Fatalf("usage response=%#v report=%#v", response.Usage, report.Usage)
	}
}

// TestDecodeResponsePreservesDistinctReasoningSummaryAndContent verifies a completed reasoning item retains both formally separate provider fields.
// TestDecodeResponsePreservesDistinctReasoningSummaryAndContent 验证已完成推理项目会保留两个形式上独立的 Provider 字段。
func TestDecodeResponsePreservesDistinctReasoningSummaryAndContent(t *testing.T) {
	upstream := Response{
		ID: "upstream-reasoning-both", Status: "completed",
		Output: []OutputItem{{
			ID: "rs_both", Type: "reasoning",
			Summary: []ReasoningSummary{{Type: "summary_text", Text: "visible summary"}},
			Content: []OutputContent{{Type: "reasoning_text", Text: "provider reasoning content"}},
		}},
	}
	response, _, _, errDecode := DecodeResponse("response-reasoning-both", upstream, responsesNow())
	if errDecode != nil {
		t.Fatalf("DecodeResponse() error = %v", errDecode)
	}
	if response.Status != vcp.ResponseCompleted || len(response.Items) != 2 {
		t.Fatalf("response = %#v", response)
	}
	if response.Items[0].Kind != vcp.ContextReasoning || response.Items[0].Content[0].Text != "visible summary" {
		t.Fatalf("summary item = %#v", response.Items[0])
	}
	if response.Items[1].Kind != vcp.ContextReasoning || response.Items[1].Content[0].Text != "provider reasoning content" {
		t.Fatalf("content item = %#v", response.Items[1])
	}
}

// TestDecodeResponseMapsSafeNonCompletedTerminals verifies incomplete, failed, and cancelled snapshots preserve only safe terminal diagnostics.
// TestDecodeResponseMapsSafeNonCompletedTerminals 验证不完整、失败和取消快照仅保留安全的终态诊断信息。
func TestDecodeResponseMapsSafeNonCompletedTerminals(t *testing.T) {
	testCases := []struct {
		// name identifies one closed terminal lifecycle fixture.
		// name 标识一个封闭终态生命周期夹具。
		name string
		// upstream contains the provider terminal snapshot under test.
		// upstream 包含待测的 Provider 终态快照。
		upstream Response
		status   vcp.ResponseStatus
		code     string
	}{
		{name: "incomplete", upstream: Response{ID: "upstream-incomplete", Status: "incomplete", IncompleteDetails: &IncompleteDetails{Reason: "max_output"}}, status: vcp.ResponseIncomplete},
		{name: "failed", upstream: Response{ID: "upstream-failed", Status: "failed", Error: &Error{Code: "rate_limited"}}, status: vcp.ResponseFailed, code: "rate_limited"},
		{name: "cancelled", upstream: Response{ID: "upstream-cancelled", Status: "cancelled"}, status: vcp.ResponseCancelled},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			response, events, report, errDecode := DecodeResponse("response-vcp-"+testCase.name, testCase.upstream, responsesNow())
			if errDecode != nil {
				t.Fatalf("DecodeResponse() error = %v", errDecode)
			}
			if response.Status != testCase.status || len(events) == 0 {
				t.Fatalf("response = %#v events = %#v", response, events)
			}
			terminal := events[len(events)-1]
			if testCase.code != "" && (terminal.ErrorCode != testCase.code || report.ErrorOrRetryAdvice != testCase.code) {
				t.Fatalf("terminal = %#v report = %#v", terminal, report)
			}
			if testCase.name == "incomplete" && terminal.FinishReason != "max_output" {
				t.Fatalf("incomplete terminal = %#v", terminal)
			}
			if testCase.name == "cancelled" && terminal.FinishReason != "cancelled" {
				t.Fatalf("cancelled terminal = %#v", terminal)
			}
		})
	}
}

// TestDecodeResponseRejectsNonTerminalStatus verifies an unresolved upstream lifecycle is not silently converted into completion.
// TestDecodeResponseRejectsNonTerminalStatus 验证未解析的上游生命周期不会被静默转换为完成态。
func TestDecodeResponseRejectsNonTerminalStatus(t *testing.T) {
	_, _, _, errDecode := DecodeResponse("response-vcp-4", Response{ID: "upstream-response-4", Status: "in_progress"}, responsesNow())
	if !errors.Is(errDecode, ErrInvalidUpstreamResponse) {
		t.Fatalf("DecodeResponse() error = %v, want ErrInvalidUpstreamResponse", errDecode)
	}
}
