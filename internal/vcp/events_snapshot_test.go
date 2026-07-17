package vcp

import "testing"

// TestReducerSnapshotDeepIsolation verifies every reference-bearing response field is detached from reducer state.
// TestReducerSnapshotDeepIsolation 校验响应中每个引用型字段均与 reducer 内部状态彻底隔离。
func TestReducerSnapshotDeepIsolation(t *testing.T) {
	inputTokens := int64(11)
	reducer := NewReducer("resp_snapshot")
	applyTestEvent(t, reducer, Event{
		ResponseID: "resp_snapshot",
		EventID:    "evt_message",
		Sequence:   1,
		Type:       EventItemStarted,
		ItemID:     "item_message",
		Item: &OutputItem{
			ItemID:  "item_message",
			Kind:    ContextMessage,
			Content: []ContentBlock{{Type: ContentText, Text: "original content"}},
		},
	})
	applyTestEvent(t, reducer, Event{
		ResponseID: "resp_snapshot",
		EventID:    "evt_tool",
		Sequence:   2,
		Type:       EventItemStarted,
		ItemID:     "item_tool",
		Item: &OutputItem{
			ItemID: "item_tool",
			Kind:   ContextToolCall,
			ToolCall: &ToolCallItem{
				ToolCallID: "call_original",
				Name:       "original_tool",
				Arguments:  `{"value":"original"}`,
				Status:     ToolCallPending,
			},
		},
	})
	applyTestEvent(t, reducer, Event{
		ResponseID:  "resp_snapshot",
		EventID:     "evt_warning",
		Sequence:    3,
		Type:        EventWarningRaised,
		WarningCode: "original_warning",
	})
	applyTestEvent(t, reducer, Event{
		ResponseID: "resp_snapshot",
		EventID:    "evt_usage",
		Sequence:   4,
		Type:       EventUsageUpdated,
		Usage: &UsageObservation{
			InputTokens: &inputTokens,
			Source:      "provider_reported",
			Aggregation: "snapshot",
			Phase:       "terminal",
		},
	})

	snapshot := reducer.Snapshot()
	snapshot.Items[0].Content[0].Text = "mutated content"
	snapshot.Items[1].ToolCall.Name = "mutated_tool"
	snapshot.Items[1].ToolCall.Arguments = `{"value":"mutated"}`
	snapshot.Warnings[0] = "mutated_warning"
	snapshot.Usage.Source = "mutated_source"
	*snapshot.Usage.InputTokens = 99

	isolated := reducer.Snapshot()
	if got := isolated.Items[0].Content[0].Text; got != "original content" {
		t.Errorf("isolated message content = %q, want %q", got, "original content")
	}
	if got := isolated.Items[1].ToolCall.Name; got != "original_tool" {
		t.Errorf("isolated tool name = %q, want %q", got, "original_tool")
	}
	if got := isolated.Items[1].ToolCall.Arguments; got != `{"value":"original"}` {
		t.Errorf("isolated tool arguments = %q, want %q", got, `{"value":"original"}`)
	}
	if got := isolated.Warnings[0]; got != "original_warning" {
		t.Errorf("isolated warning = %q, want %q", got, "original_warning")
	}
	if got := isolated.Usage.Source; got != "provider_reported" {
		t.Errorf("isolated usage source = %q, want %q", got, "provider_reported")
	}
	if got := *isolated.Usage.InputTokens; got != 11 {
		t.Errorf("isolated input tokens = %d, want %d", got, 11)
	}
}
