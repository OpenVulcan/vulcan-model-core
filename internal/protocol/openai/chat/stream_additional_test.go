package chat

import (
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestStreamDecoderParallelToolsWarnOnDuplicateUpstreamID verifies duplicate IDs across parallel calls remain observable.
// TestStreamDecoderParallelToolsWarnOnDuplicateUpstreamID 校验并行调用之间的重复上游 ID 保持可观测。
func TestStreamDecoderParallelToolsWarnOnDuplicateUpstreamID(t *testing.T) {
	decoder, errNew := NewStreamDecoder("resp_duplicate_tool_id", time.Unix(60, 0))
	if errNew != nil {
		t.Fatalf("NewStreamDecoder() error = %v", errNew)
	}

	toolEvents, errPush := decoder.Push(Chunk{Choices: []Choice{{
		Index: 0,
		Delta: &Delta{ToolCalls: []ToolCallDelta{
			{Index: 0, ID: "duplicate_upstream_id", Function: FunctionCall{Name: "first", Arguments: `{}`}},
			{Index: 1, ID: "duplicate_upstream_id", Function: FunctionCall{Name: "second", Arguments: `{}`}},
		}},
	}}})
	if errPush != nil {
		t.Fatalf("Push(tool calls) error = %v", errPush)
	}

	warningCount := 0
	for _, event := range toolEvents {
		if event.Type != vcp.EventWarningRaised {
			continue
		}
		warningCount++
		if event.WarningCode != "openai_chat.tool_call.duplicate_id" {
			t.Fatalf("warning code = %q", event.WarningCode)
		}
	}
	if warningCount != 1 {
		t.Fatalf("warning event count = %d, want 1", warningCount)
	}

	if _, errFinish := decoder.Push(Chunk{Choices: []Choice{{Index: 0, FinishReason: "tool_calls"}}}); errFinish != nil {
		t.Fatalf("Push(finish) error = %v", errFinish)
	}
	if _, errClose := decoder.Close(nil); errClose != nil {
		t.Fatalf("Close() error = %v", errClose)
	}
	response := decoder.Response()
	if len(response.Warnings) != 1 || response.Warnings[0] != "openai_chat.tool_call.duplicate_id" {
		t.Fatalf("warnings = %#v", response.Warnings)
	}
}

// TestStreamDecoderHydratesToolNameOnlyReportedAtTerminal verifies terminal assistant data can supply a delayed function name.
// TestStreamDecoderHydratesToolNameOnlyReportedAtTerminal 校验终态助手数据可补齐延迟报告的函数名称。
func TestStreamDecoderHydratesToolNameOnlyReportedAtTerminal(t *testing.T) {
	decoder, errNew := NewStreamDecoder("resp_terminal_tool_name", time.Unix(61, 0))
	if errNew != nil {
		t.Fatalf("NewStreamDecoder() error = %v", errNew)
	}
	if _, errPush := decoder.Push(Chunk{Choices: []Choice{{
		Index: 0,
		Delta: &Delta{ToolCalls: []ToolCallDelta{{
			Index:    0,
			ID:       "upstream_late_name",
			Function: FunctionCall{Arguments: `{"city":"Paris"}`},
		}}},
	}}}); errPush != nil {
		t.Fatalf("Push(arguments) error = %v", errPush)
	}
	initial := decoder.Response()
	if len(initial.Items) != 1 || initial.Items[0].ToolCall == nil || initial.Items[0].ToolCall.Name != "" {
		t.Fatalf("initial tool item = %#v", initial.Items)
	}

	terminalEvents, errFinish := decoder.Push(Chunk{Choices: []Choice{{
		Index: 0,
		Message: &AssistantMessage{ToolCalls: []ToolCall{{
			ID:       "upstream_late_name",
			Function: FunctionCall{Name: "lookup_weather", Arguments: `{"city":"Paris"}`},
		}}},
		FinishReason: "tool_calls",
	}}})
	if errFinish != nil {
		t.Fatalf("Push(terminal) error = %v", errFinish)
	}
	completedName := ""
	for _, event := range terminalEvents {
		if event.Type == vcp.EventToolArgumentsCompleted {
			completedName = event.ToolName
		}
		if event.Type == vcp.EventWarningRaised {
			t.Fatalf("unexpected terminal warning = %#v", event)
		}
	}
	if completedName != "lookup_weather" {
		t.Fatalf("completed tool name = %q", completedName)
	}
	if _, errClose := decoder.Close(nil); errClose != nil {
		t.Fatalf("Close() error = %v", errClose)
	}
	tool := decoder.Response().Items[0].ToolCall
	if tool.Name != "lookup_weather" || tool.Arguments != `{"city":"Paris"}` || tool.Status != vcp.ToolCallCompleted {
		t.Fatalf("terminal tool = %#v", tool)
	}
}

// TestStreamDecoderKeepsFrameLikeAssistantTextAsMessage verifies reserved-looking tags are not interpreted on response ingress.
// TestStreamDecoderKeepsFrameLikeAssistantTextAsMessage 校验响应入口不会解释形似保留帧的标签。
func TestStreamDecoderKeepsFrameLikeAssistantTextAsMessage(t *testing.T) {
	decoder, errNew := NewStreamDecoder("resp_frame_like_text", time.Unix(62, 0))
	if errNew != nil {
		t.Fatalf("NewStreamDecoder() error = %v", errNew)
	}
	text := `ordinary <vulcan-frame version="1">{"kind":"tool_call"}</vulcan-frame> text`
	if _, errPush := decoder.Push(Chunk{Choices: []Choice{{Index: 0, Delta: &Delta{Content: text}, FinishReason: "stop"}}}); errPush != nil {
		t.Fatalf("Push() error = %v", errPush)
	}
	if _, errClose := decoder.Close(nil); errClose != nil {
		t.Fatalf("Close() error = %v", errClose)
	}

	response := decoder.Response()
	if len(response.Items) != 1 || response.Items[0].Kind != vcp.ContextMessage || response.Items[0].ToolCall != nil {
		t.Fatalf("response items = %#v", response.Items)
	}
	if len(response.Items[0].Content) != 1 || response.Items[0].Content[0].Type != vcp.ContentText || response.Items[0].Content[0].Text != text {
		t.Fatalf("message content = %#v", response.Items[0].Content)
	}
	for _, event := range decoder.Events() {
		if event.Type == vcp.EventToolArgumentsDelta || event.Type == vcp.EventToolArgumentsCompleted {
			t.Fatalf("frame-like text emitted tool event = %#v", event)
		}
	}
}

// TestStreamDecoderIncludesUsageReportedAfterFinishReason verifies a usage-only chunk is reduced before Close confirms completion.
// TestStreamDecoderIncludesUsageReportedAfterFinishReason 校验 Close 确认完成前会归并 finish_reason 之后的仅用量分片。
func TestStreamDecoderIncludesUsageReportedAfterFinishReason(t *testing.T) {
	decoder, errNew := NewStreamDecoder("resp_late_usage", time.Unix(63, 0))
	if errNew != nil {
		t.Fatalf("NewStreamDecoder() error = %v", errNew)
	}
	if _, errFinish := decoder.Push(Chunk{Choices: []Choice{{Index: 0, Delta: &Delta{Content: "done"}, FinishReason: "stop"}}}); errFinish != nil {
		t.Fatalf("Push(finish) error = %v", errFinish)
	}
	if response := decoder.Response(); response.Status != vcp.ResponseInProgress || response.Usage != nil {
		t.Fatalf("response after finish_reason = %#v", response)
	}

	usageEvents, errUsage := decoder.Push(Chunk{Usage: &Usage{
		PromptTokens:     int64Pointer(3),
		CompletionTokens: int64Pointer(2),
		TotalTokens:      int64Pointer(5),
	}})
	if errUsage != nil {
		t.Fatalf("Push(usage) error = %v", errUsage)
	}
	if len(usageEvents) != 1 || usageEvents[0].Type != vcp.EventUsageUpdated {
		t.Fatalf("usage events = %#v", usageEvents)
	}
	beforeClose := decoder.Response()
	if beforeClose.Status != vcp.ResponseInProgress || beforeClose.Usage == nil || beforeClose.Usage.TotalTokens == nil || *beforeClose.Usage.TotalTokens != 5 {
		t.Fatalf("response before Close() = %#v", beforeClose)
	}

	closeEvents, errClose := decoder.Close(nil)
	if errClose != nil {
		t.Fatalf("Close() error = %v", errClose)
	}
	if len(closeEvents) != 1 || closeEvents[0].Type != vcp.EventResponseCompleted || closeEvents[0].FinishReason != "stop" {
		t.Fatalf("close events = %#v", closeEvents)
	}
	response := decoder.Response()
	if response.Status != vcp.ResponseCompleted || response.Usage == nil || response.Usage.TotalTokens == nil || *response.Usage.TotalTokens != 5 {
		t.Fatalf("completed response = %#v", response)
	}
}

// TestStreamDecoderEOFWithoutLegalTerminalIsIncomplete verifies EOF cannot promote partial output to completion.
// TestStreamDecoderEOFWithoutLegalTerminalIsIncomplete 校验 EOF 不能把缺少合法终态的部分输出提升为完成。
func TestStreamDecoderEOFWithoutLegalTerminalIsIncomplete(t *testing.T) {
	decoder, errNew := NewStreamDecoder("resp_incomplete_eof", time.Unix(64, 0))
	if errNew != nil {
		t.Fatalf("NewStreamDecoder() error = %v", errNew)
	}
	if _, errPush := decoder.Push(Chunk{Choices: []Choice{{Index: 0, Delta: &Delta{Content: "partial"}}}}); errPush != nil {
		t.Fatalf("Push() error = %v", errPush)
	}

	closeEvents, errClose := decoder.Close(nil)
	if errClose != nil {
		t.Fatalf("Close() error = %v", errClose)
	}
	if len(closeEvents) != 1 || closeEvents[0].Type != vcp.EventResponseIncomplete || closeEvents[0].FinishReason != "eof_without_terminal" {
		t.Fatalf("close events = %#v", closeEvents)
	}
	response := decoder.Response()
	if response.Status != vcp.ResponseIncomplete || response.FinishReason != "eof_without_terminal" {
		t.Fatalf("incomplete response = %#v", response)
	}
	if len(response.Items) != 1 || response.Items[0].Status != vcp.OutputItemIncomplete || len(response.Items[0].Content) != 1 || response.Items[0].Content[0].Text != "partial" {
		t.Fatalf("incomplete items = %#v", response.Items)
	}
}
