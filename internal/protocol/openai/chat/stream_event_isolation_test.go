package chat

import (
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestStreamDecoderEventsReturnsDeepIsolatedReplay verifies pointer-backed replay data cannot mutate decoder history.
// TestStreamDecoderEventsReturnsDeepIsolatedReplay 校验含指针的回放数据无法篡改解码器历史记录。
func TestStreamDecoderEventsReturnsDeepIsolatedReplay(t *testing.T) {
	inputTokens := int64(7)
	decoder, errNew := NewStreamDecoder("resp_isolated_replay", time.Unix(80, 0))
	if errNew != nil {
		t.Fatalf("NewStreamDecoder() error = %v", errNew)
	}
	_, errPush := decoder.Push(Chunk{
		Choices: []Choice{{
			Index: 0,
			Delta: &Delta{ToolCalls: []ToolCallDelta{{
				Index:    0,
				ID:       "upstream_call",
				Function: FunctionCall{Name: "lookup", Arguments: `{"query":`},
			}}},
		}},
		Usage: &Usage{PromptTokens: &inputTokens},
	})
	if errPush != nil {
		t.Fatalf("Push(delta) error = %v", errPush)
	}
	_, errTerminal := decoder.Push(Chunk{Choices: []Choice{{
		Index: 0,
		Message: &AssistantMessage{ToolCalls: []ToolCall{{
			ID:       "upstream_call",
			Function: FunctionCall{Name: "lookup", Arguments: `{"query":"vulcan"}`},
		}}},
		FinishReason: "tool_calls",
	}}})
	if errTerminal != nil {
		t.Fatalf("Push(terminal) error = %v", errTerminal)
	}

	events := decoder.Events()
	itemIndex := -1
	usageIndex := -1
	argumentsIndex := -1
	for index := range events {
		switch events[index].Type {
		case vcp.EventItemStarted:
			if events[index].Item != nil && events[index].Item.ToolCall != nil {
				itemIndex = index
			}
		case vcp.EventUsageUpdated:
			if events[index].Usage != nil && events[index].Usage.InputTokens != nil {
				usageIndex = index
			}
		case vcp.EventToolArgumentsCompleted:
			if events[index].FinalArguments != nil {
				argumentsIndex = index
			}
		}
	}
	if itemIndex < 0 || usageIndex < 0 || argumentsIndex < 0 {
		t.Fatalf("Events() missing pointer-backed fixtures: item=%d usage=%d arguments=%d", itemIndex, usageIndex, argumentsIndex)
	}

	originalItemID := events[itemIndex].Item.ItemID
	originalToolCallID := events[itemIndex].Item.ToolCall.ToolCallID
	originalInputTokens := *events[usageIndex].Usage.InputTokens
	originalUsageSource := events[usageIndex].Usage.Source
	originalArguments := *events[argumentsIndex].FinalArguments
	events[itemIndex].Item.ItemID = "mutated_item"
	events[itemIndex].Item.ToolCall.ToolCallID = "mutated_call"
	*events[usageIndex].Usage.InputTokens = 999
	events[usageIndex].Usage.Source = "mutated_source"
	*events[argumentsIndex].FinalArguments = "mutated_arguments"

	replayed := decoder.Events()
	if replayed[itemIndex].Item == events[itemIndex].Item {
		t.Fatal("Events() reused Item pointer across calls")
	}
	if replayed[itemIndex].Item.ToolCall == events[itemIndex].Item.ToolCall {
		t.Fatal("Events() reused ToolCall pointer across calls")
	}
	if replayed[itemIndex].Item.ItemID != originalItemID || replayed[itemIndex].Item.ToolCall.ToolCallID != originalToolCallID {
		t.Fatalf("Events() replay Item was mutated: item_id=%q tool_call_id=%q", replayed[itemIndex].Item.ItemID, replayed[itemIndex].Item.ToolCall.ToolCallID)
	}
	if replayed[usageIndex].Usage == events[usageIndex].Usage || replayed[usageIndex].Usage.InputTokens == events[usageIndex].Usage.InputTokens {
		t.Fatal("Events() reused Usage pointer data across calls")
	}
	if *replayed[usageIndex].Usage.InputTokens != originalInputTokens || replayed[usageIndex].Usage.Source != originalUsageSource {
		t.Fatalf("Events() replay Usage was mutated: input_tokens=%d source=%q", *replayed[usageIndex].Usage.InputTokens, replayed[usageIndex].Usage.Source)
	}
	if replayed[argumentsIndex].FinalArguments == events[argumentsIndex].FinalArguments {
		t.Fatal("Events() reused FinalArguments pointer across calls")
	}
	if *replayed[argumentsIndex].FinalArguments != originalArguments {
		t.Fatalf("Events() replay FinalArguments was mutated: arguments=%q", *replayed[argumentsIndex].FinalArguments)
	}
}
