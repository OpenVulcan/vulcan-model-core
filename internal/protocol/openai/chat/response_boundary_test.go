package chat

import (
	"slices"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestDecodeResponseMarksIncompleteChoiceBoundaries verifies malformed terminal choice boundaries remain explicit.
// TestDecodeResponseMarksIncompleteChoiceBoundaries 校验格式错误的终态候选边界保持显式。
func TestDecodeResponseMarksIncompleteChoiceBoundaries(t *testing.T) {
	// boundaryCase defines one malformed first-choice boundary and its safe diagnostic code.
	// boundaryCase 定义一种格式错误的首选项边界及其安全诊断代码。
	type boundaryCase struct {
		name             string
		choice           Choice
		wantFinishReason string
		wantSummaryCode  string
	}

	// testCases covers missing terminal assistant data and missing terminal evidence independently.
	// testCases 分别覆盖缺失终态助手数据与缺失终态证据。
	testCases := []boundaryCase{
		{
			name:             "message missing",
			choice:           Choice{Index: 0, FinishReason: "stop"},
			wantFinishReason: "missing_message",
			wantSummaryCode:  "openai_chat.choice.message_missing",
		},
		{
			name:             "finish reason missing",
			choice:           Choice{Index: 0, Message: &AssistantMessage{Content: "partial"}},
			wantFinishReason: "missing_finish_reason",
			wantSummaryCode:  "openai_chat.response.finish_reason_missing",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// response captures the canonical terminal state derived from malformed upstream data.
			// response 捕获从格式错误的上游数据派生的规范终态。
			response, events, report, errDecode := DecodeResponse(
				"resp_boundary_"+testCase.name,
				Response{Choices: []Choice{testCase.choice}},
				time.Unix(50, 0),
			)
			if errDecode != nil {
				t.Fatalf("DecodeResponse() error = %v", errDecode)
			}
			if response.Status != vcp.ResponseIncomplete || response.FinishReason != testCase.wantFinishReason {
				t.Fatalf("response = %#v, want incomplete with finish reason %q", response, testCase.wantFinishReason)
			}
			if len(events) == 0 || events[len(events)-1].Type != vcp.EventResponseIncomplete {
				t.Fatalf("terminal events = %#v, want response.incomplete", events)
			}
			if !slices.Contains(report.ConversionSummary, testCase.wantSummaryCode) {
				t.Fatalf("conversion summary = %#v, want code %q", report.ConversionSummary, testCase.wantSummaryCode)
			}
		})
	}
}

// TestDecodeResponseCompletesValidEmptyText verifies an explicit stop can complete without output text.
// TestDecodeResponseCompletesValidEmptyText 校验显式 stop 可在没有输出文本时完成。
func TestDecodeResponseCompletesValidEmptyText(t *testing.T) {
	// response captures a valid empty assistant message with explicit terminal evidence.
	// response 捕获带有显式终态证据的合法空助手消息。
	response, events, report, errDecode := DecodeResponse(
		"resp_empty_text",
		Response{Choices: []Choice{{Index: 0, Message: &AssistantMessage{}, FinishReason: "stop"}}},
		time.Unix(51, 0),
	)
	if errDecode != nil {
		t.Fatalf("DecodeResponse() error = %v", errDecode)
	}
	if response.Status != vcp.ResponseCompleted || response.FinishReason != "stop" || len(response.Items) != 0 {
		t.Fatalf("response = %#v, want completed empty output", response)
	}
	if len(events) == 0 || events[len(events)-1].Type != vcp.EventResponseCompleted {
		t.Fatalf("terminal events = %#v, want response.completed", events)
	}
	if len(report.ConversionSummary) != 0 {
		t.Fatalf("conversion summary = %#v, want no conversion warning", report.ConversionSummary)
	}
}
