package minimax

import (
	"fmt"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// textResult converts one provider-confirmed text value into a complete VCP semantic event sequence.
// textResult 将一个供应商确认的文本值转换为完整 VCP 语义事件序列。
func textResult(responseID string, text string, now time.Time, conversionSummary string) (vcp.Response, []vcp.Event, vcp.ExecutionReport, error) {
	if responseID == "" || text == "" || now.IsZero() {
		return vcp.Response{}, nil, vcp.ExecutionReport{}, fmt.Errorf("MiniMax text result requires response identity, content, and time")
	}
	itemID := vcp.DeriveID("itm", responseID, "message")
	events := []vcp.Event{
		{ResponseID: responseID, EventID: vcp.DeriveID("evt", responseID, "1"), Sequence: 1, Time: now, Replayable: true, Type: vcp.EventResponseStarted},
		{ResponseID: responseID, EventID: vcp.DeriveID("evt", responseID, "2"), Sequence: 2, Time: now, Replayable: true, Type: vcp.EventItemStarted, ItemID: itemID, Item: &vcp.OutputItem{ItemID: itemID, Kind: vcp.ContextMessage, Status: vcp.OutputItemInProgress}},
		{ResponseID: responseID, EventID: vcp.DeriveID("evt", responseID, "3"), Sequence: 3, Time: now, Replayable: true, Type: vcp.EventContentDelta, ItemID: itemID, Delta: text},
		{ResponseID: responseID, EventID: vcp.DeriveID("evt", responseID, "4"), Sequence: 4, Time: now, Replayable: true, Type: vcp.EventItemCompleted, ItemID: itemID},
		{ResponseID: responseID, EventID: vcp.DeriveID("evt", responseID, "5"), Sequence: 5, Time: now, Replayable: true, Type: vcp.EventResponseCompleted, FinishReason: "stop"},
	}
	reducer := vcp.NewReducer(responseID)
	for _, event := range events {
		if errApply := reducer.Apply(event); errApply != nil {
			return vcp.Response{}, nil, vcp.ExecutionReport{}, errApply
		}
	}
	report := vcp.ExecutionReport{ResponseID: responseID, ExecutionID: vcp.DeriveID("exec", responseID), ConversionSummary: []string{conversionSummary}}
	return reducer.Snapshot(), events, report, nil
}
