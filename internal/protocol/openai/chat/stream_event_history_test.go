package chat

import (
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestStreamDecoderPreservesStartedEventSnapshot verifies later reduction cannot mutate historical replay events.
// TestStreamDecoderPreservesStartedEventSnapshot 校验后续归并不能修改历史回放事件。
func TestStreamDecoderPreservesStartedEventSnapshot(t *testing.T) {
	decoder, errNew := NewStreamDecoder("resp_event_history", time.Unix(70, 0))
	if errNew != nil {
		t.Fatalf("NewStreamDecoder() error = %v", errNew)
	}
	if _, errPush := decoder.Push(Chunk{Choices: []Choice{{Index: 0, Delta: &Delta{ToolCalls: []ToolCallDelta{{Index: 0, Function: FunctionCall{Arguments: `{"city":`}}}}}}}); errPush != nil {
		t.Fatalf("Push(arguments) error = %v", errPush)
	}
	if _, errFinish := decoder.Push(Chunk{Choices: []Choice{{
		Index: 0,
		Message: &AssistantMessage{ToolCalls: []ToolCall{{
			ID:       "call_weather",
			Function: FunctionCall{Name: "weather", Arguments: `{"city":"Paris"}`},
		}}},
		FinishReason: "tool_calls",
	}}}); errFinish != nil {
		t.Fatalf("Push(terminal) error = %v", errFinish)
	}
	if _, errClose := decoder.Close(nil); errClose != nil {
		t.Fatalf("Close() error = %v", errClose)
	}

	var started *vcp.OutputItem
	for _, event := range decoder.Events() {
		if event.Type == vcp.EventItemStarted && event.Item != nil && event.Item.Kind == vcp.ContextToolCall {
			started = event.Item
			break
		}
	}
	if started == nil || started.ToolCall == nil {
		t.Fatalf("missing historical tool item.started event: %#v", decoder.Events())
	}
	if started.ToolCall.Status != vcp.ToolCallPending || started.ToolCall.Name != "" || started.ToolCall.Arguments != "" || started.ToolCall.UpstreamID != "" {
		t.Fatalf("historical item.started was mutated: %#v", started.ToolCall)
	}
	response := decoder.Response()
	if response.Status != vcp.ResponseCompleted || len(response.Items) != 1 || response.Items[0].ToolCall == nil {
		t.Fatalf("completed response = %#v", response)
	}
	toolCall := response.Items[0].ToolCall
	if toolCall.Status != vcp.ToolCallCompleted || toolCall.Name != "weather" || toolCall.Arguments != `{"city":"Paris"}` || toolCall.UpstreamID != "call_weather" {
		t.Fatalf("final tool call = %#v", toolCall)
	}
}
