// Stream fixtures cover behavior adapted from CLIProxyAPI commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// 流式夹具覆盖改编自 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66 的行为。
// Source paths: sdk/api/handlers/openai/openai_handlers.go and internal/runtime/executor/openai_compat_executor.go.
// 来源路径：sdk/api/handlers/openai/openai_handlers.go 和 internal/runtime/executor/openai_compat_executor.go。
// The fixtures verify typed Chat SSE compatibility without importing CLIProxyAPI runtime code.
// 夹具验证类型化 Chat SSE 兼容行为，不导入 CLIProxyAPI 运行时代码。
package chat

import (
	"errors"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestStreamDecoderInterleavedToolsLateFieldsUsageAndHydration verifies historical stream failures.
// TestStreamDecoderInterleavedToolsLateFieldsUsageAndHydration 校验历史流失败模式。
func TestStreamDecoderInterleavedToolsLateFieldsUsageAndHydration(t *testing.T) {
	decoder, errNew := NewStreamDecoder("resp_stream", time.Unix(50, 0))
	if errNew != nil {
		t.Fatalf("NewStreamDecoder() error = %v", errNew)
	}
	chunks := []Chunk{
		{Choices: []Choice{{
			Index: 0,
			Delta: &Delta{Content: "A", ToolCalls: []ToolCallDelta{
				{Index: 0, Function: FunctionCall{Arguments: `{"a":`}},
				{Index: 1, ID: "up_1", Function: FunctionCall{Name: "second", Arguments: `{"b":`}},
			}},
		}}},
		{Choices: []Choice{{
			Index: 0,
			Delta: &Delta{ToolCalls: []ToolCallDelta{
				{Index: 1, Function: FunctionCall{Arguments: `2}`}},
				{Index: 0, ID: "up_0", Function: FunctionCall{Name: "first", Arguments: `1}`}},
			}},
		}}},
		{Choices: []Choice{{
			Index: 0,
			Message: &AssistantMessage{ToolCalls: []ToolCall{
				{ID: "up_0", Function: FunctionCall{Name: "first", Arguments: `{"a":1}`}},
				{ID: "up_1", Function: FunctionCall{Name: "second", Arguments: `{"b":2}`}},
			}},
			FinishReason: "tool_calls",
		}}},
		{Usage: &Usage{TotalTokens: int64Pointer(9)}},
	}
	for index, chunk := range chunks {
		if _, errPush := decoder.Push(chunk); errPush != nil {
			t.Fatalf("Push(%d) error = %v", index, errPush)
		}
	}
	if _, errClose := decoder.Close(nil); errClose != nil {
		t.Fatalf("Close() error = %v", errClose)
	}
	response := decoder.Response()
	if response.Status != vcp.ResponseCompleted || len(response.Items) != 3 {
		t.Fatalf("response = %#v", response)
	}
	toolItems := response.Items[1:]
	if toolItems[0].ToolCall.Name != "first" || toolItems[0].ToolCall.Arguments != `{"a":1}` || toolItems[0].ToolCall.UpstreamID != "up_0" {
		t.Fatalf("first tool = %#v", toolItems[0].ToolCall)
	}
	if toolItems[1].ToolCall.Name != "second" || toolItems[1].ToolCall.Arguments != `{"b":2}` {
		t.Fatalf("second tool = %#v", toolItems[1].ToolCall)
	}
	if response.Usage == nil || response.Usage.TotalTokens == nil || *response.Usage.TotalTokens != 9 {
		t.Fatalf("usage = %#v", response.Usage)
	}
	assertMonotonicEvents(t, decoder.Events())
	argumentDeltas := 0
	for _, event := range decoder.Events() {
		if event.Type == vcp.EventToolArgumentsDelta {
			argumentDeltas++
		}
	}
	if argumentDeltas != 4 {
		t.Fatalf("argument delta count = %d, want actual four upstream fragments", argumentDeltas)
	}
}

// TestStreamDecoderEOFAndFailureTerminals verifies incomplete and failed reducer paths.
// TestStreamDecoderEOFAndFailureTerminals 校验 incomplete 和 failed reducer 路径。
func TestStreamDecoderEOFAndFailureTerminals(t *testing.T) {
	incomplete, _ := NewStreamDecoder("resp_eof", time.Unix(51, 0))
	if _, errPush := incomplete.Push(Chunk{Choices: []Choice{{Index: 0, Delta: &Delta{Content: "partial"}}}}); errPush != nil {
		t.Fatalf("Push() error = %v", errPush)
	}
	if _, errClose := incomplete.Close(nil); errClose != nil || incomplete.Response().Status != vcp.ResponseIncomplete {
		t.Fatalf("EOF response = %#v, err = %v", incomplete.Response(), errClose)
	}

	failed, _ := NewStreamDecoder("resp_transport", time.Unix(52, 0))
	if _, errClose := failed.Close(errors.New("connection reset")); errClose != nil || failed.Response().Status != vcp.ResponseFailed {
		t.Fatalf("transport response = %#v, err = %v", failed.Response(), errClose)
	}
}

// TestStreamDecoderCompletedIgnoresLaterTransportError verifies terminal immutability.
// TestStreamDecoderCompletedIgnoresLaterTransportError 校验终态不可变性。
func TestStreamDecoderCompletedIgnoresLaterTransportError(t *testing.T) {
	decoder, _ := NewStreamDecoder("resp_done", time.Unix(53, 0))
	if _, errPush := decoder.Push(Chunk{Choices: []Choice{{Index: 0, Delta: &Delta{Content: "done"}, FinishReason: "stop"}}}); errPush != nil {
		t.Fatalf("Push() error = %v", errPush)
	}
	events, errClose := decoder.Close(errors.New("transport closed after finish_reason"))
	if errClose != nil || len(events) != 1 || events[0].Type != vcp.EventResponseCompleted {
		t.Fatalf("first Close() = %#v, %v", events, errClose)
	}
	if laterEvents, errLater := decoder.Close(errors.New("late transport error")); errLater != nil || len(laterEvents) != 0 {
		t.Fatalf("second Close() = %#v, %v", laterEvents, errLater)
	}
	if decoder.Response().Status != vcp.ResponseCompleted {
		t.Fatalf("status = %q", decoder.Response().Status)
	}
}

// TestStreamDecoderMapsNonSuccessFinishReasons verifies deferred stream terminal selection preserves truncation and safety outcomes.
// TestStreamDecoderMapsNonSuccessFinishReasons 验证延迟流终态选择会保留截断和安全结果。
func TestStreamDecoderMapsNonSuccessFinishReasons(t *testing.T) {
	truncated, errNew := NewStreamDecoder("resp_stream_length", time.Unix(54, 0))
	if errNew != nil {
		t.Fatalf("NewStreamDecoder() error = %v", errNew)
	}
	if _, errPush := truncated.Push(Chunk{Choices: []Choice{{Index: 0, FinishReason: "length"}}}); errPush != nil {
		t.Fatalf("truncated Push() error = %v", errPush)
	}
	if _, errClose := truncated.Close(nil); errClose != nil || truncated.Response().Status != vcp.ResponseIncomplete || truncated.Response().FinishReason != "length" {
		t.Fatalf("truncated response = %#v, err = %v", truncated.Response(), errClose)
	}

	filtered, errNew := NewStreamDecoder("resp_stream_filtered", time.Unix(55, 0))
	if errNew != nil {
		t.Fatalf("NewStreamDecoder() error = %v", errNew)
	}
	if _, errPush := filtered.Push(Chunk{Choices: []Choice{{Index: 0, FinishReason: "content_filter"}}}); errPush != nil {
		t.Fatalf("filtered Push() error = %v", errPush)
	}
	if _, errClose := filtered.Close(nil); errClose != nil || filtered.Response().Status != vcp.ResponseFailed || filtered.Response().ErrorCode != "openai_chat.content_filter" {
		t.Fatalf("filtered response = %#v, err = %v", filtered.Response(), errClose)
	}
}

// int64Pointer returns a pointer to one stable fixture value.
// int64Pointer 返回一个稳定夹具数值的指针。
func int64Pointer(value int64) *int64 {
	return &value
}
