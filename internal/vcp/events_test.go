package vcp

import (
	"testing"
	"time"
)

// TestReducerTerminalRules verifies completed, failed, and incomplete semantics.
// TestReducerTerminalRules 校验 completed、failed 和 incomplete 语义。
func TestReducerTerminalRules(t *testing.T) {
	now := time.Unix(20, 0)
	completed := NewReducer("resp_completed")
	applyTestEvent(t, completed, Event{ResponseID: "resp_completed", EventID: "evt_1", Sequence: 1, Time: now, Type: EventResponseStarted})
	applyTestEvent(t, completed, Event{ResponseID: "resp_completed", EventID: "evt_2", Sequence: 2, Time: now, Type: EventResponseCompleted})
	applyTestEvent(t, completed, Event{ResponseID: "resp_completed", EventID: "evt_3", Sequence: 3, Time: now, Type: EventResponseFailed, ErrorCode: "transport"})
	if completed.Snapshot().Status != ResponseCompleted {
		t.Fatalf("completed status = %q", completed.Snapshot().Status)
	}

	failed := NewReducer("resp_failed")
	applyTestEvent(t, failed, Event{ResponseID: "resp_failed", EventID: "evt_1", Sequence: 1, Time: now, Type: EventResponseFailed, ErrorCode: "upstream_protocol"})
	if failed.Snapshot().Status != ResponseFailed {
		t.Fatalf("failed status = %q", failed.Snapshot().Status)
	}

	incomplete := NewReducer("resp_incomplete")
	applyTestEvent(t, incomplete, Event{ResponseID: "resp_incomplete", EventID: "evt_1", Sequence: 1, Time: now, Type: EventResponseIncomplete})
	if incomplete.Snapshot().Status != ResponseIncomplete {
		t.Fatalf("incomplete status = %q", incomplete.Snapshot().Status)
	}
}

// applyTestEvent applies one event and fails the test on reducer errors.
// applyTestEvent 应用一个事件并在 reducer 错误时终止测试。
func applyTestEvent(t *testing.T, reducer *Reducer, event Event) {
	t.Helper()
	if errApply := reducer.Apply(event); errApply != nil {
		t.Fatalf("Apply(%s) error = %v", event.Type, errApply)
	}
}
