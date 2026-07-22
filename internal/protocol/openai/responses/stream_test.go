// Stream fixtures cover behavior adapted from CLIProxyAPI commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// 流式夹具覆盖改编自 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66 的行为。
// Source path: sdk/api/handlers/openai/openai_responses_handlers.go.
// 来源路径：sdk/api/handlers/openai/openai_responses_handlers.go。
// The fixtures verify typed SSE framing and completion repair without importing CLIProxyAPI handler runtime code.
// 夹具验证类型化 SSE 分帧和完成修复，不导入 CLIProxyAPI Handler 运行时代码。
package responses

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestStreamDecoderRetainsMultipleReasoningSummaryParts verifies each provider reasoning summary index remains distinct.
// TestStreamDecoderRetainsMultipleReasoningSummaryParts 验证每个 Provider 推理摘要索引都会保持独立。
func TestStreamDecoderRetainsMultipleReasoningSummaryParts(t *testing.T) {
	decoder, errNew := NewStreamDecoder("response-vcp-1", responsesNow())
	if errNew != nil {
		t.Fatalf("NewStreamDecoder() error = %v", errNew)
	}
	outputIndex := 0
	if _, errAdded := decoder.Push(StreamEvent{Type: "response.output_item.added", Item: &OutputItem{ID: "reasoning-item-1", Type: "reasoning"}, OutputIndex: &outputIndex}); errAdded != nil {
		t.Fatalf("Push(added) error = %v", errAdded)
	}
	firstIndex := 0
	if _, errDelta := decoder.Push(StreamEvent{Type: "response.reasoning_summary_text.delta", ItemID: "reasoning-item-1", OutputIndex: &outputIndex, SummaryIndex: &firstIndex, Delta: "first"}); errDelta != nil {
		t.Fatalf("Push(first delta) error = %v", errDelta)
	}
	secondIndex := 1
	if _, errDelta := decoder.Push(StreamEvent{Type: "response.reasoning_summary_text.delta", ItemID: "reasoning-item-1", OutputIndex: &outputIndex, SummaryIndex: &secondIndex, Delta: "second"}); errDelta != nil {
		t.Fatalf("Push(second delta) error = %v", errDelta)
	}
	terminal := Response{ID: "upstream-response-1", Status: "completed", Output: []OutputItem{{ID: "reasoning-item-1", Type: "reasoning", Summary: []ReasoningSummary{{Type: "summary_text", Text: "first"}, {Type: "summary_text", Text: "second"}}}}}
	if _, errCompleted := decoder.Push(StreamEvent{Type: "response.completed", Response: &terminal}); errCompleted != nil {
		t.Fatalf("Push(completed) error = %v", errCompleted)
	}
	response := decoder.Response()
	if response.Status != vcp.ResponseCompleted || len(response.Items) != 2 {
		t.Fatalf("response = %#v", response)
	}
	if response.Items[0].Kind != vcp.ContextReasoning || response.Items[1].Kind != vcp.ContextReasoning {
		t.Fatalf("reasoning items = %#v", response.Items)
	}
	if response.Items[0].Content[0].Text != "first" || response.Items[1].Content[1].Text != "second" {
		t.Fatalf("reasoning content = %#v", response.Items)
	}
}

// TestStreamDecoderProjectsReasoningSummaryPartLifecycle verifies official summary-index SSE events remain a visible VCP reasoning item.
// TestStreamDecoderProjectsReasoningSummaryPartLifecycle 验证官方 summary-index SSE 事件会保持为可见的 VCP 推理项目。
func TestStreamDecoderProjectsReasoningSummaryPartLifecycle(t *testing.T) {
	decoder, errNew := NewStreamDecoder("response-vcp-summary", responsesNow())
	if errNew != nil {
		t.Fatalf("NewStreamDecoder() error = %v", errNew)
	}
	frames := []string{
		`{"type":"response.output_item.added","output_index":0,"item":{"id":"rs_1","type":"reasoning","status":"in_progress"}}`,
		`{"type":"response.reasoning_summary_part.added","item_id":"rs_1","output_index":0,"summary_index":0,"part":{"type":"summary_text","text":""}}`,
		`{"type":"response.reasoning_summary_text.delta","item_id":"rs_1","output_index":0,"summary_index":0,"delta":"visible"}`,
		`{"type":"response.reasoning_summary_text.done","item_id":"rs_1","output_index":0,"summary_index":0,"text":"visible"}`,
		`{"type":"response.reasoning_summary_part.done","item_id":"rs_1","output_index":0,"summary_index":0,"part":{"type":"summary_text","text":"visible"}}`,
		`{"type":"response.completed","response":{"id":"upstream-summary","status":"completed"}}`,
	}
	for frameIndex, frame := range frames {
		if _, errPush := decoder.PushSSE(SSEEnvelope{Data: []byte(frame)}); errPush != nil {
			t.Fatalf("PushSSE(frame %d) error = %v", frameIndex, errPush)
		}
	}
	response := decoder.Response()
	if response.Status != vcp.ResponseCompleted || len(response.Items) != 1 {
		t.Fatalf("response = %#v", response)
	}
	if response.Items[0].Kind != vcp.ContextReasoning || response.Items[0].Content[0].Text != "visible" {
		t.Fatalf("reasoning item = %#v", response.Items[0])
	}
	contentCompleted := 0
	for _, event := range decoder.Events() {
		if event.Type == vcp.EventContentCompleted {
			contentCompleted++
		}
	}
	if contentCompleted != 1 {
		t.Fatalf("content-completed events = %d, want 1", contentCompleted)
	}
}

// TestStreamDecoderDeduplicatesTerminalToolLifecycle verifies argument, output-item, and response snapshots produce one VCP tool completion.
// TestStreamDecoderDeduplicatesTerminalToolLifecycle 验证参数、输出项目与响应快照只产生一个 VCP 工具完成事件。
func TestStreamDecoderDeduplicatesTerminalToolLifecycle(t *testing.T) {
	decoder, errNew := NewStreamDecoder("response-vcp-tool-lifecycle", responsesNow())
	if errNew != nil {
		t.Fatalf("NewStreamDecoder() error = %v", errNew)
	}
	outputIndex := 0
	finalArguments := `{"city":"Paris"}`
	functionCall := OutputItem{ID: "fc_lifecycle", Type: "function_call", CallID: "call_lifecycle", Name: "weather", Arguments: finalArguments}
	events := []StreamEvent{
		{Type: "response.output_item.added", OutputIndex: &outputIndex, Item: &functionCall},
		{Type: "response.function_call_arguments.delta", ItemID: functionCall.ID, OutputIndex: &outputIndex, CallID: functionCall.CallID, Name: functionCall.Name, Delta: finalArguments},
		{Type: "response.function_call_arguments.done", ItemID: functionCall.ID, OutputIndex: &outputIndex, CallID: functionCall.CallID, Name: functionCall.Name, Arguments: finalArguments},
		{Type: "response.output_item.done", OutputIndex: &outputIndex, Item: &functionCall},
		{Type: "response.completed", Response: &Response{ID: "upstream-tool-lifecycle", Status: "completed", Output: []OutputItem{functionCall}}},
	}
	for eventIndex := range events {
		if _, errPush := decoder.Push(events[eventIndex]); errPush != nil {
			t.Fatalf("Push(event %d) error = %v", eventIndex, errPush)
		}
	}
	toolCompleted := 0
	for _, event := range decoder.Events() {
		if event.Type == vcp.EventToolArgumentsCompleted {
			toolCompleted++
		}
	}
	if toolCompleted != 1 {
		t.Fatalf("tool-arguments-completed events = %d, want 1", toolCompleted)
	}
	response := decoder.Response()
	if response.Status != vcp.ResponseCompleted || len(response.Items) != 1 || response.Items[0].ToolCall == nil || response.Items[0].ToolCall.Arguments != finalArguments {
		t.Fatalf("response = %#v", response)
	}
}

// TestStreamDecoderPreservesStreamingCitation verifies annotation-added events become typed citations.
// TestStreamDecoderPreservesStreamingCitation 验证 annotation-added 事件成为类型化引用。
func TestStreamDecoderPreservesStreamingCitation(t *testing.T) {
	decoder, errNew := NewStreamDecoder("response-vcp-annotation-warning", responsesNow())
	if errNew != nil {
		t.Fatalf("NewStreamDecoder() error = %v", errNew)
	}
	contentIndex := 0
	annotationIndex := 0
	start := 0
	end := 4
	annotation := OutputAnnotation{Type: "url_citation", URL: "https://example.com/source", StartIndex: &start, EndIndex: &end}
	if _, errPush := decoder.Push(StreamEvent{Type: "response.output_text.annotation.added", ItemID: "message-citation", ContentIndex: &contentIndex, AnnotationIndex: &annotationIndex, Annotation: &annotation}); errPush != nil {
		t.Fatalf("Push(annotation) error = %v", errPush)
	}
	if len(decoder.Response().Citations) != 1 || decoder.Response().Citations[0].URL != "https://example.com/source" || slices.Contains(decoder.Report().ConversionSummary, "openai_responses.output_annotation_omitted") {
		t.Fatalf("response = %#v report = %#v", decoder.Response(), decoder.Report())
	}
}

// TestStreamDecoderPreservesNativeWebSearchCall verifies lifecycle frames and completed action yield one typed item.
// TestStreamDecoderPreservesNativeWebSearchCall 验证生命周期帧与完成动作生成一个类型化项目。
func TestStreamDecoderPreservesNativeWebSearchCall(t *testing.T) {
	decoder, errNew := NewStreamDecoder("response-vcp-search-stream", responsesNow())
	if errNew != nil {
		t.Fatalf("NewStreamDecoder() error = %v", errNew)
	}
	outputIndex := 0
	added := OutputItem{ID: "search-call-stream", Type: "web_search_call", Status: "in_progress"}
	if _, errPush := decoder.Push(StreamEvent{Type: "response.output_item.added", OutputIndex: &outputIndex, Item: &added}); errPush != nil {
		t.Fatalf("Push(added) error = %v", errPush)
	}
	if _, errPush := decoder.Push(StreamEvent{Type: "response.web_search_call.searching", OutputIndex: &outputIndex, ItemID: added.ID}); errPush != nil {
		t.Fatalf("Push(searching) error = %v", errPush)
	}
	done := OutputItem{ID: added.ID, Type: "web_search_call", Status: "completed", Action: &WebSearchAction{Type: "search", Query: "Vulcan", Sources: []WebSearchSource{{Type: "url", URL: "https://example.com/source"}}}}
	if _, errPush := decoder.Push(StreamEvent{Type: "response.output_item.done", OutputIndex: &outputIndex, Item: &done}); errPush != nil {
		t.Fatalf("Push(done) error = %v", errPush)
	}
	if _, errPush := decoder.Push(StreamEvent{Type: "response.completed", Response: &Response{ID: "upstream-search-stream", Status: "completed"}}); errPush != nil {
		t.Fatalf("Push(completed) error = %v", errPush)
	}
	response := decoder.Response()
	if len(response.Items) != 1 || response.Items[0].SearchCall == nil || response.Items[0].SearchCall.Query != "Vulcan" || response.Items[0].Status != vcp.OutputItemCompleted || slices.Contains(decoder.Report().ConversionSummary, "openai_responses.native_web_search_event_not_exposed") {
		t.Fatalf("response = %#v report = %#v", response, decoder.Report())
	}
}

// TestStreamDecoderRejectsTerminalEventStatusMismatch verifies a terminal wire event cannot falsely upgrade a contradictory response snapshot.
// TestStreamDecoderRejectsTerminalEventStatusMismatch 验证终态 wire 事件不能错误提升与其矛盾的响应快照。
func TestStreamDecoderRejectsTerminalEventStatusMismatch(t *testing.T) {
	testCases := []struct {
		// eventType is the terminal SSE event that declares its expected response status.
		// eventType 是声明其预期响应状态的终态 SSE 事件。
		eventType string
		// status is the conflicting embedded response status.
		// status 是相互冲突的内嵌响应状态。
		status string
	}{
		{eventType: "response.completed", status: "incomplete"},
		{eventType: "response.incomplete", status: "completed"},
		{eventType: "response.failed", status: "cancelled"},
		{eventType: "response.cancelled", status: "failed"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.eventType, func(t *testing.T) {
			decoder, errNew := NewStreamDecoder("response-vcp-terminal-status-"+testCase.eventType, responsesNow())
			if errNew != nil {
				t.Fatalf("NewStreamDecoder() error = %v", errNew)
			}
			if _, errPush := decoder.Push(StreamEvent{Type: testCase.eventType, Response: &Response{ID: "upstream-terminal-status", Status: testCase.status}}); !errors.Is(errPush, ErrInvalidUpstreamResponse) {
				t.Fatalf("Push() error = %v, want ErrInvalidUpstreamResponse", errPush)
			}
		})
	}
}

// TestStreamDecoderAuditsPartLogprobsAndAnnotations verifies streamed part metadata cannot disappear without an explicit VCP warning and report code.
// TestStreamDecoderAuditsPartLogprobsAndAnnotations 验证流式部分元数据不会在没有显式 VCP 警告和报告代码的情况下消失。
func TestStreamDecoderAuditsPartLogprobsAndAnnotations(t *testing.T) {
	decoder, errNew := NewStreamDecoder("response-vcp-part-metadata", responsesNow())
	if errNew != nil {
		t.Fatalf("NewStreamDecoder() error = %v", errNew)
	}
	outputIndex := 0
	if _, errAdded := decoder.Push(StreamEvent{Type: "response.output_item.added", OutputIndex: &outputIndex, Item: &OutputItem{ID: "message-metadata", Type: "message"}}); errAdded != nil {
		t.Fatalf("Push(output item added) error = %v", errAdded)
	}
	start := 0
	end := 4
	part := StreamPart{Type: "output_text", Annotations: []OutputAnnotation{{Type: "url_citation", URL: "https://example.com/source", StartIndex: &start, EndIndex: &end}}, Logprobs: &UnsupportedResponsePayload{}}
	contentIndex := 0
	if _, errPart := decoder.Push(StreamEvent{Type: "response.content_part.added", ItemID: "message-metadata", OutputIndex: &outputIndex, ContentIndex: &contentIndex, Part: &part}); errPart != nil {
		t.Fatalf("Push(content part added) error = %v", errPart)
	}
	if _, errCompleted := decoder.Push(StreamEvent{Type: "response.completed", Response: &Response{ID: "resp-part-metadata", Status: "completed"}}); errCompleted != nil {
		t.Fatalf("Push(completed) error = %v", errCompleted)
	}
	if len(decoder.Response().Citations) != 1 {
		t.Fatalf("response = %#v", decoder.Response())
	}
	for _, summaryCode := range []string{"openai_responses.output_logprobs_omitted"} {
		if !slices.Contains(decoder.Report().ConversionSummary, summaryCode) {
			t.Fatalf("report = %#v, missing summary %q", decoder.Report(), summaryCode)
		}
	}
}

// TestStreamDecoderRejectsNonIncreasingProviderSequence verifies optional upstream sequence numbers detect duplicate or reordered SSE events.
// TestStreamDecoderRejectsNonIncreasingProviderSequence 验证可选上游序列号能够检测重复或乱序 SSE 事件。
func TestStreamDecoderRejectsNonIncreasingProviderSequence(t *testing.T) {
	decoder, errNew := NewStreamDecoder("response-vcp-sequence", responsesNow())
	if errNew != nil {
		t.Fatalf("NewStreamDecoder() error = %v", errNew)
	}
	sequence := int64(1)
	created := Response{ID: "resp-sequence", Status: "in_progress"}
	if _, errCreated := decoder.Push(StreamEvent{Type: "response.created", SequenceNumber: &sequence, Response: &created}); errCreated != nil {
		t.Fatalf("Push(created) error = %v", errCreated)
	}
	if _, errDuplicate := decoder.Push(StreamEvent{Type: "response.in_progress", SequenceNumber: &sequence, Response: &created}); !errors.Is(errDuplicate, ErrInvalidUpstreamResponse) {
		t.Fatalf("Push(duplicate sequence) error = %v, want ErrInvalidUpstreamResponse", errDuplicate)
	}
}

// TestStreamDecoderAcceptsProviderHostedToolTraces verifies provider-owned calls do not abort the final assistant response and remain content-free.
// TestStreamDecoderAcceptsProviderHostedToolTraces 验证供应商拥有调用不会中止最终助手响应且保持不含内容。
func TestStreamDecoderAcceptsProviderHostedToolTraces(t *testing.T) {
	// outputIndex supplies the required stable provider position for the output-item fixture.
	// outputIndex 为输出项目夹具提供必需的稳定 Provider 位置。
	outputIndex := 0
	testCases := []struct {
		// name identifies the independent provider-hosted protocol node.
		// name 标识独立的供应商托管协议节点。
		name string
		// event is the provider event reduced to one safe omission warning.
		// event 是归并为一条安全省略警告的 Provider 事件。
		event StreamEvent
	}{
		{name: "file-search-event", event: StreamEvent{Type: "response.file_search_call.in_progress"}},
		{name: "file-search-output", event: StreamEvent{Type: "response.output_item.added", OutputIndex: &outputIndex, Item: &OutputItem{ID: "fs_1", Type: "file_search_call", Status: "in_progress"}}},
		{name: "code-interpreter-output", event: StreamEvent{Type: "response.output_item.added", OutputIndex: &outputIndex, Item: &OutputItem{ID: "ci_1", Type: "code_interpreter_call", Status: "in_progress"}}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			decoder, errNew := NewStreamDecoder("response-vcp-unsupported-"+testCase.name, responsesNow())
			if errNew != nil {
				t.Fatalf("NewStreamDecoder() error = %v", errNew)
			}
			events, errPush := decoder.Push(testCase.event)
			if errPush != nil || len(events) != 1 || events[0].Type != vcp.EventWarningRaised || events[0].WarningCode == "" {
				t.Fatalf("Push() events = %+v, error = %v", events, errPush)
			}
		})
	}
}

// TestStreamDecoderProjectsComputerCalls verifies both GA batches and legacy preview actions remain executable VCP calls.
// TestStreamDecoderProjectsComputerCalls 验证 GA 批次与旧版预览动作均保持为可执行 VCP 调用。
func TestStreamDecoderProjectsComputerCalls(t *testing.T) {
	// x and y preserve zero-capable pointer coordinates in the wire fixture.
	// x 与 y 在 Wire 夹具中保留可为零的指针坐标。
	x := 405
	y := 157
	testCases := []struct {
		// name identifies the computer wire generation.
		// name 标识计算机 Wire 代际。
		name string
		// item contains one complete upstream computer call.
		// item 包含一个完整上游计算机调用。
		item OutputItem
		// expectedActions is the exact canonical action count.
		// expectedActions 是精确规范动作数量。
		expectedActions int
	}{
		{name: "ga-batch", item: OutputItem{ID: "cu_ga", Type: "computer_call", Status: "completed", CallID: "call_ga", Actions: []OutputAction{{Type: "click", X: &x, Y: &y, Button: "left"}, {Type: "type", Text: "penguin"}}}, expectedActions: 2},
		{name: "preview-single", item: OutputItem{ID: "cu_preview", Type: "computer_call", Status: "completed", CallID: "call_preview", Action: &OutputAction{Type: "screenshot"}}, expectedActions: 1},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			decoder, errNew := NewStreamDecoder("response-vcp-computer-"+testCase.name, responsesNow())
			if errNew != nil {
				t.Fatalf("NewStreamDecoder() error = %v", errNew)
			}
			outputIndex := 0
			events, errPush := decoder.Push(StreamEvent{Type: "response.output_item.done", OutputIndex: &outputIndex, Item: &testCase.item})
			if errPush != nil || len(events) != 2 || events[0].Type != vcp.EventItemStarted || events[1].Type != vcp.EventItemCompleted {
				t.Fatalf("Push() events = %+v, error = %v", events, errPush)
			}
			call := events[0].Item.ToolCall
			if call == nil || call.ToolCallID != testCase.item.CallID || call.UpstreamID != testCase.item.CallID || call.Name != "computer_use" || call.Status != vcp.ToolCallCompleted || len(call.ComputerActions) != testCase.expectedActions {
				t.Fatalf("computer call = %#v", call)
			}
		})
	}
}

// TestStreamDecoderRejectsMixedComputerWireGenerations verifies preview and GA action carriers cannot be merged.
// TestStreamDecoderRejectsMixedComputerWireGenerations 验证预览与 GA 动作载体不能混合。
func TestStreamDecoderRejectsMixedComputerWireGenerations(t *testing.T) {
	decoder, errNew := NewStreamDecoder("response-vcp-computer-mixed", responsesNow())
	if errNew != nil {
		t.Fatalf("NewStreamDecoder() error = %v", errNew)
	}
	outputIndex := 0
	item := OutputItem{ID: "cu_mixed", Type: "computer_call", Status: "completed", CallID: "call_mixed", Action: &OutputAction{Type: "wait"}, Actions: []OutputAction{{Type: "screenshot"}}}
	if _, errPush := decoder.Push(StreamEvent{Type: "response.output_item.done", OutputIndex: &outputIndex, Item: &item}); !errors.Is(errPush, ErrInvalidUpstreamResponse) {
		t.Fatalf("Push() error = %v, want ErrInvalidUpstreamResponse", errPush)
	}
}

// TestStreamDecoderProjectsCompletedContentParts verifies message and reasoning content-part completion events preserve their typed provider slots.
// TestStreamDecoderProjectsCompletedContentParts 验证消息与推理 content-part 完成事件会保留其类型化 Provider 槽位。
func TestStreamDecoderProjectsCompletedContentParts(t *testing.T) {
	decoder, errNew := NewStreamDecoder("response-vcp-content-part", responsesNow())
	if errNew != nil {
		t.Fatalf("NewStreamDecoder() error = %v", errNew)
	}
	frames := []string{
		`{"type":"response.output_item.added","output_index":0,"item":{"id":"msg_1","type":"message","status":"in_progress"}}`,
		`{"type":"response.content_part.added","item_id":"msg_1","output_index":0,"content_index":0,"part":{"type":"output_text","text":""}}`,
		`{"type":"response.output_text.delta","item_id":"msg_1","output_index":0,"content_index":0,"delta":"hello"}`,
		`{"type":"response.content_part.done","item_id":"msg_1","output_index":0,"content_index":0,"part":{"type":"output_text","text":"hello"}}`,
		`{"type":"response.output_item.added","output_index":1,"item":{"id":"rs_2","type":"reasoning","status":"in_progress"}}`,
		`{"type":"response.content_part.added","item_id":"rs_2","output_index":1,"content_index":0,"part":{"type":"reasoning_text","text":""}}`,
		`{"type":"response.reasoning_text.delta","item_id":"rs_2","output_index":1,"content_index":0,"delta":"think"}`,
		`{"type":"response.content_part.done","item_id":"rs_2","output_index":1,"content_index":0,"part":{"type":"reasoning_text","text":"think"}}`,
		`{"type":"response.completed","response":{"id":"upstream-content-part","status":"completed"}}`,
	}
	for frameIndex, frame := range frames {
		if _, errPush := decoder.PushSSE(SSEEnvelope{Data: []byte(frame)}); errPush != nil {
			t.Fatalf("PushSSE(frame %d) error = %v", frameIndex, errPush)
		}
	}
	response := decoder.Response()
	if response.Status != vcp.ResponseCompleted || len(response.Items) != 2 {
		t.Fatalf("response = %#v", response)
	}
	if response.Items[0].Kind != vcp.ContextMessage || response.Items[0].Content[0].Text != "hello" {
		t.Fatalf("message item = %#v", response.Items[0])
	}
	if response.Items[1].Kind != vcp.ContextReasoning || response.Items[1].Content[0].Text != "think" {
		t.Fatalf("reasoning item = %#v", response.Items[1])
	}
}

// TestStreamDecoderSeparatesReasoningSummaryAndContentIndexes verifies coincident provider indexes do not merge distinct reasoning fields.
// TestStreamDecoderSeparatesReasoningSummaryAndContentIndexes 验证重合的 Provider 索引不会合并不同的推理字段。
func TestStreamDecoderSeparatesReasoningSummaryAndContentIndexes(t *testing.T) {
	decoder, errNew := NewStreamDecoder("response-vcp-reasoning-both", responsesNow())
	if errNew != nil {
		t.Fatalf("NewStreamDecoder() error = %v", errNew)
	}
	frames := []string{
		`{"type":"response.output_item.added","output_index":0,"item":{"id":"rs_both","type":"reasoning","status":"in_progress"}}`,
		`{"type":"response.reasoning_summary_part.added","item_id":"rs_both","output_index":0,"summary_index":0,"part":{"type":"summary_text","text":""}}`,
		`{"type":"response.reasoning_summary_text.delta","item_id":"rs_both","output_index":0,"summary_index":0,"delta":"summary"}`,
		`{"type":"response.content_part.added","item_id":"rs_both","output_index":0,"content_index":0,"part":{"type":"reasoning_text","text":""}}`,
		`{"type":"response.reasoning_text.delta","item_id":"rs_both","output_index":0,"content_index":0,"delta":"content"}`,
		`{"type":"response.completed","response":{"id":"upstream-reasoning-both","status":"completed"}}`,
	}
	for frameIndex, frame := range frames {
		if _, errPush := decoder.PushSSE(SSEEnvelope{Data: []byte(frame)}); errPush != nil {
			t.Fatalf("PushSSE(frame %d) error = %v", frameIndex, errPush)
		}
	}
	response := decoder.Response()
	if response.Status != vcp.ResponseCompleted || len(response.Items) != 2 {
		t.Fatalf("response = %#v", response)
	}
	if response.Items[0].Content[0].Text != "summary" || response.Items[1].Content[0].Text != "content" {
		t.Fatalf("reasoning items = %#v", response.Items)
	}
}

// TestStreamDecoderCompletesIdentityOnlyToolSource verifies a response terminal closes sources identified solely by upstream item ID.
// TestStreamDecoderCompletesIdentityOnlyToolSource 验证响应终态会关闭仅由上游项目 ID 标识的来源。
func TestStreamDecoderCompletesIdentityOnlyToolSource(t *testing.T) {
	decoder, errNew := NewStreamDecoder("response-vcp-2", responsesNow())
	if errNew != nil {
		t.Fatalf("NewStreamDecoder() error = %v", errNew)
	}
	item := OutputItem{ID: "tool-item-1", Type: "function_call", CallID: "upstream-call-1", Name: "lookup"}
	if _, errAdded := decoder.Push(StreamEvent{Type: "response.output_item.added", Item: &item}); errAdded != nil {
		t.Fatalf("Push(added) error = %v", errAdded)
	}
	terminal := Response{ID: "upstream-response-2", Status: "completed"}
	if _, errCompleted := decoder.Push(StreamEvent{Type: "response.completed", Response: &terminal}); errCompleted != nil {
		t.Fatalf("Push(completed) error = %v", errCompleted)
	}
	response := decoder.Response()
	if response.Status != vcp.ResponseCompleted || len(response.Items) != 1 || response.Items[0].ToolCall == nil {
		t.Fatalf("response = %#v", response)
	}
	if response.Items[0].Status != vcp.OutputItemCompleted || response.Items[0].ToolCall.Name != "lookup" || response.Items[0].ToolCall.UpstreamID != "upstream-call-1" {
		t.Fatalf("tool item = %#v", response.Items[0])
	}
}

// TestReadSSEJoinsDataLines verifies framing preserves event names and joins protocol data lines exactly once.
// TestReadSSEJoinsDataLines 验证分帧会保留事件名称并恰好一次拼接协议数据行。
func TestReadSSEJoinsDataLines(t *testing.T) {
	stream := "event: response.test\ndata: first\ndata: second\n\n"
	envelopes := make([]SSEEnvelope, 0, 1)
	errRead := ReadSSE(strings.NewReader(stream), func(envelope SSEEnvelope) error {
		envelopes = append(envelopes, envelope)
		return nil
	})
	if errRead != nil {
		t.Fatalf("ReadSSE() error = %v", errRead)
	}
	if len(envelopes) != 1 || envelopes[0].Event != "response.test" || string(envelopes[0].Data) != "first\nsecond" {
		t.Fatalf("envelopes = %#v", envelopes)
	}
}

// TestReadSSERejectsOversizedMultilineFrame verifies individually valid lines cannot create an unbounded aggregate payload.
// TestReadSSERejectsOversizedMultilineFrame 验证单独有效的行不能创建无界聚合载荷。
func TestReadSSERejectsOversizedMultilineFrame(t *testing.T) {
	dataLine := "data: " + strings.Repeat("x", maximumSSELineBytes/2+1) + "\n"
	errRead := ReadSSE(strings.NewReader(dataLine+dataLine+"\n"), func(SSEEnvelope) error { return nil })
	if !errors.Is(errRead, ErrInvalidUpstreamResponse) {
		t.Fatalf("ReadSSE() error = %v, want ErrInvalidUpstreamResponse", errRead)
	}
}
