// Stream fixtures cover behavior adapted from CLIProxyAPI commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// 流式夹具覆盖改编自 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66 的行为。
// Source path: internal/runtime/executor/xai_executor.go.
// 来源路径：internal/runtime/executor/xai_executor.go。
// The fixtures verify typed xAI stream normalization without importing CLIProxyAPI runtime code.
// 夹具验证类型化 xAI 流归一化，不导入 CLIProxyAPI 运行时代码。
package responses

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	openairesponses "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/responses"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestStreamDecoderFiltersInternalXSearchAndCompactsIndexes verifies only documented server-side x_search traces are hidden.
// TestStreamDecoderFiltersInternalXSearchAndCompactsIndexes 验证仅隐藏文档化的服务端 x_search 轨迹。
func TestStreamDecoderFiltersInternalXSearchAndCompactsIndexes(t *testing.T) {
	decoder, errNew := NewStreamDecoder("response-xai-1", xaiNow(), StreamOptions{FilterInternalXSearch: true})
	if errNew != nil {
		t.Fatalf("NewStreamDecoder() error = %v", errNew)
	}
	internalIndex := 0
	internal := OutputItem{ID: "internal-item", Type: "custom_tool_call", CallID: "xs_call_1", Name: "x_keyword_search"}
	if events, errPush := decoder.Push(StreamEvent{Type: "response.output_item.added", Item: &internal, OutputIndex: &internalIndex}); errPush != nil || len(events) != 0 {
		t.Fatalf("Push(internal) events = %#v, error = %v", events, errPush)
	}
	messageIndex := 1
	message := OutputItem{ID: "message-item", Type: "message"}
	if _, errPush := decoder.Push(StreamEvent{Type: "response.output_item.added", Item: &message, OutputIndex: &messageIndex}); errPush != nil {
		t.Fatalf("Push(message added) error = %v", errPush)
	}
	contentIndex := 0
	if _, errPush := decoder.Push(StreamEvent{Type: "response.output_text.delta", ItemID: "message-item", OutputIndex: &messageIndex, ContentIndex: &contentIndex, Delta: "Hello"}); errPush != nil {
		t.Fatalf("Push(message delta) error = %v", errPush)
	}
	terminal := Response{ID: "upstream-xai-1", Status: "completed", Output: []OutputItem{internal, {ID: "message-item", Type: "message", Content: []OutputContent{{Type: "output_text", Text: "Hello"}}}}}
	if _, errPush := decoder.Push(StreamEvent{Type: "response.completed", Response: &terminal}); errPush != nil {
		t.Fatalf("Push(completed) error = %v", errPush)
	}
	response := decoder.Response()
	if response.Status != vcp.ResponseCompleted || len(response.Items) != 1 || response.Items[0].Content[0].Text != "Hello" {
		t.Fatalf("response = %#v", response)
	}
	if !containsSummary(decoder.Report().ConversionSummary, "xai_responses.internal_x_search.filtered") {
		t.Fatalf("report = %#v", decoder.Report())
	}
}

// TestDecodeResponseReportsOmittedOutputAnnotations verifies xAI normalization preserves annotation-presence warnings from the shared Responses profile.
// TestDecodeResponseReportsOmittedOutputAnnotations 验证 xAI 归一化会保留共享 Responses Profile 的注释存在警告。
func TestDecodeResponseReportsOmittedOutputAnnotations(t *testing.T) {
	upstream := Response{
		ID: "upstream-xai-annotation", Status: "completed",
		Output: []OutputItem{{
			ID: "message-xai-annotation", Type: "message",
			Content: []OutputContent{{Type: "output_text", Text: "Answer", Annotations: []openairesponses.OutputAnnotation{{Type: "file_citation"}}}},
		}},
	}
	_, events, report, errDecode := DecodeResponse("response-xai-annotation", upstream, xaiNow(), StreamOptions{})
	if errDecode != nil {
		t.Fatalf("DecodeResponse() error = %v", errDecode)
	}
	warningFound := false
	for _, event := range events {
		if event.Type == vcp.EventWarningRaised && event.WarningCode == "openai_responses.output_annotation_omitted" {
			warningFound = true
		}
	}
	if !warningFound || !containsSummary(report.ConversionSummary, "openai_responses.output_annotation_omitted") {
		t.Fatalf("events = %#v report = %#v", events, report)
	}
}

// TestDecodeResponseAuditsXAISpecificResponseMetadata verifies current xAI response fields without VCP carriers are explicitly audited without retaining values.
// TestDecodeResponseAuditsXAISpecificResponseMetadata 验证当前 xAI 响应中没有 VCP 承载字段的字段会被显式审计且不保留其值。
func TestDecodeResponseAuditsXAISpecificResponseMetadata(t *testing.T) {
	// upstreamJSON includes xAI-specific compatibility, source, safety, citation, and cost metadata alongside one safe text output.
	// upstreamJSON 包含 xAI 特有兼容、来源、安全、引文和成本元数据，以及一个安全文本输出。
	upstreamJSON := []byte(`{"id":"xai-metadata","object":"response","status":"completed","model":"grok-4.5","reasoning":{"effort":"high"},"top_logprobs":0,"prompt_cache_key":"private-cache-key","max_tool_calls":4,"safety_identifier":"private-safety-id","citations":["https://example.invalid/private"],"inline_citations":[{"id":"citation-private"}],"output":[{"id":"message-xai-metadata","type":"message","role":"assistant","status":"completed","content":[{"type":"output_text","text":"Safe output","annotations":[],"logprobs":[]}]}],"usage":{"input_tokens":1,"output_tokens":2,"total_tokens":3,"cost_in_usd_ticks":17,"num_sources_used":2,"num_server_side_tools_used":1}}`)
	var upstream Response
	if errUnmarshal := json.Unmarshal(upstreamJSON, &upstream); errUnmarshal != nil {
		t.Fatalf("json.Unmarshal() error = %v", errUnmarshal)
	}
	response, _, report, errDecode := DecodeResponse("response-xai-metadata", upstream, xaiNow(), StreamOptions{})
	if errDecode != nil {
		t.Fatalf("DecodeResponse() error = %v", errDecode)
	}
	if response.Status != vcp.ResponseCompleted || len(response.Items) != 1 || response.Items[0].Content[0].Text != "Safe output" {
		t.Fatalf("response = %#v", response)
	}
	// summaryCodes lists every xAI-specific metadata group in the fixture that must remain a fixed safe report code.
	// summaryCodes 列出夹具中每个必须保持为固定安全报告代码的 xAI 特有元数据组。
	summaryCodes := []string{
		"openai_responses.response.reasoning_configuration.omitted",
		"openai_responses.response.top_logprobs.omitted",
		"openai_responses.response.prompt_cache_key.omitted",
		"openai_responses.response.max_tool_calls.omitted",
		"openai_responses.response.safety_identifier.omitted",
		"openai_responses.response.citations.omitted",
		"openai_responses.usage.cost.omitted",
		"openai_responses.usage.server_side_tools.omitted",
		"openai_responses.output_logprobs_omitted",
	}
	for _, summaryCode := range summaryCodes {
		if !slices.Contains(report.ConversionSummary, summaryCode) {
			t.Fatalf("report = %#v, missing summary %q", report, summaryCode)
		}
	}
	if strings.Contains(fmt.Sprintf("%#v", report), "private") {
		t.Fatalf("report leaked xAI metadata: %#v", report)
	}
}

// TestStreamDecoderPreservesClientSameNameFunction verifies a client-declared x_search-like function is not filtered by name alone.
// TestStreamDecoderPreservesClientSameNameFunction 验证客户端声明的同名 x_search 风格 function 不会仅因名称被过滤。
func TestStreamDecoderPreservesClientSameNameFunction(t *testing.T) {
	options := StreamOptions{FilterInternalXSearch: true, ToolReferences: []ToolReference{{WireName: "x_keyword_search", Name: "x_keyword_search", Kind: vcp.ToolFunction}}}
	decoder, errNew := NewStreamDecoder("response-xai-2", xaiNow(), options)
	if errNew != nil {
		t.Fatalf("NewStreamDecoder() error = %v", errNew)
	}
	outputIndex := 0
	item := OutputItem{ID: "client-item", Type: "function_call", CallID: "client_call_1", Name: "x_keyword_search"}
	if _, errPush := decoder.Push(StreamEvent{Type: "response.output_item.added", Item: &item, OutputIndex: &outputIndex}); errPush != nil {
		t.Fatalf("Push(added) error = %v", errPush)
	}
	if _, errPush := decoder.Push(StreamEvent{Type: "response.function_call_arguments.done", ItemID: "client-item", OutputIndex: &outputIndex, CallID: "client_call_1", Name: "x_keyword_search", Arguments: `{}`}); errPush != nil {
		t.Fatalf("Push(arguments done) error = %v", errPush)
	}
	terminal := Response{ID: "upstream-xai-2", Status: "completed"}
	if _, errPush := decoder.Push(StreamEvent{Type: "response.completed", Response: &terminal}); errPush != nil {
		t.Fatalf("Push(completed) error = %v", errPush)
	}
	response := decoder.Response()
	if response.Status != vcp.ResponseCompleted || len(response.Items) != 1 || response.Items[0].ToolCall == nil || response.Items[0].ToolCall.Name != "x_keyword_search" {
		t.Fatalf("response = %#v", response)
	}
}

// TestStreamDecoderPreservesClientSameNameCustomTool verifies an xAI-normalized custom declaration remains distinct from an internal x_search trace.
// TestStreamDecoderPreservesClientSameNameCustomTool 验证经 xAI 归一化的 custom 声明仍与内部 x_search 轨迹保持区分。
func TestStreamDecoderPreservesClientSameNameCustomTool(t *testing.T) {
	options := StreamOptions{FilterInternalXSearch: true, ToolReferences: []ToolReference{{WireName: "x_keyword_search", Name: "x_keyword_search", Kind: vcp.ToolCustom}}}
	decoder, errNew := NewStreamDecoder("response-xai-custom-same-name", xaiNow(), options)
	if errNew != nil {
		t.Fatalf("NewStreamDecoder() error = %v", errNew)
	}
	outputIndex := 0
	item := OutputItem{ID: "client-custom-item", Type: "function_call", CallID: "client_call_custom", Name: "x_keyword_search"}
	if _, errPush := decoder.Push(StreamEvent{Type: "response.output_item.added", Item: &item, OutputIndex: &outputIndex}); errPush != nil {
		t.Fatalf("Push(added) error = %v", errPush)
	}
	if _, errPush := decoder.Push(StreamEvent{Type: "response.function_call_arguments.done", ItemID: "client-custom-item", OutputIndex: &outputIndex, CallID: "client_call_custom", Name: "x_keyword_search", Arguments: `{}`}); errPush != nil {
		t.Fatalf("Push(arguments done) error = %v", errPush)
	}
	terminal := Response{ID: "upstream-xai-custom-same-name", Status: "completed"}
	if _, errPush := decoder.Push(StreamEvent{Type: "response.completed", Response: &terminal}); errPush != nil {
		t.Fatalf("Push(completed) error = %v", errPush)
	}
	response := decoder.Response()
	if response.Status != vcp.ResponseCompleted || len(response.Items) != 1 || response.Items[0].ToolCall == nil || response.Items[0].ToolCall.Name != "x_keyword_search" {
		t.Fatalf("response = %#v", response)
	}
}

// TestStreamDecoderRepairsEmptyCompletedOutput verifies terminal output is repaired only from verified item.done snapshots in index order.
// TestStreamDecoderRepairsEmptyCompletedOutput 验证终态输出仅从已验证的 item.done 快照按索引顺序修复。
func TestStreamDecoderRepairsEmptyCompletedOutput(t *testing.T) {
	decoder, errNew := NewStreamDecoder("response-xai-3", xaiNow(), StreamOptions{})
	if errNew != nil {
		t.Fatalf("NewStreamDecoder() error = %v", errNew)
	}
	outputIndex := 0
	item := OutputItem{ID: "message-item", Type: "message", Content: []OutputContent{{Type: "output_text", Text: "Recovered"}}}
	if _, errPush := decoder.Push(StreamEvent{Type: "response.output_item.done", Item: &item, OutputIndex: &outputIndex}); errPush != nil {
		t.Fatalf("Push(item done) error = %v", errPush)
	}
	terminal := Response{ID: "upstream-xai-3", Status: "completed"}
	if _, errPush := decoder.Push(StreamEvent{Type: "response.completed", Response: &terminal}); errPush != nil {
		t.Fatalf("Push(completed) error = %v", errPush)
	}
	response := decoder.Response()
	if response.Status != vcp.ResponseCompleted || len(response.Items) != 1 || response.Items[0].Content[0].Text != "Recovered" {
		t.Fatalf("response = %#v", response)
	}
	if !containsSummary(decoder.Report().ConversionSummary, "xai_responses.completed_output.patched") {
		t.Fatalf("report = %#v", decoder.Report())
	}
}

// TestStreamDecoderNormalizesReasoningText verifies xAI reasoning_text deltas become visible reasoning summaries without plain-text coercion.
// TestStreamDecoderNormalizesReasoningText 验证 xAI reasoning_text 增量会变为可见推理摘要而非普通文本强制转换。
func TestStreamDecoderNormalizesReasoningText(t *testing.T) {
	decoder, errNew := NewStreamDecoder("response-xai-4", xaiNow(), StreamOptions{})
	if errNew != nil {
		t.Fatalf("NewStreamDecoder() error = %v", errNew)
	}
	outputIndex := 0
	reasoning := OutputItem{ID: "reasoning-item", Type: "reasoning"}
	if _, errPush := decoder.Push(StreamEvent{Type: "response.output_item.added", Item: &reasoning, OutputIndex: &outputIndex}); errPush != nil {
		t.Fatalf("Push(reasoning added) error = %v", errPush)
	}
	contentIndex := 0
	if _, errPush := decoder.Push(StreamEvent{Type: "response.reasoning_text.delta", ItemID: "reasoning-item", OutputIndex: &outputIndex, ContentIndex: &contentIndex, Delta: "Reason"}); errPush != nil {
		t.Fatalf("Push(reasoning delta) error = %v", errPush)
	}
	if _, errPush := decoder.Push(StreamEvent{Type: "response.reasoning_text.done", ItemID: "reasoning-item", OutputIndex: &outputIndex, ContentIndex: &contentIndex, Text: "Reason"}); errPush != nil {
		t.Fatalf("Push(reasoning done) error = %v", errPush)
	}
	terminal := Response{ID: "upstream-xai-4", Status: "completed"}
	if _, errPush := decoder.Push(StreamEvent{Type: "response.completed", Response: &terminal}); errPush != nil {
		t.Fatalf("Push(completed) error = %v", errPush)
	}
	response := decoder.Response()
	if response.Status != vcp.ResponseCompleted || len(response.Items) != 1 || response.Items[0].Kind != vcp.ContextReasoning || response.Items[0].Content[0].Text != "Reason" {
		t.Fatalf("response = %#v", response)
	}
}

// TestStreamDecoderNormalizesReasoningPartLifecycle verifies xAI reasoning content lifecycle events retain their summary index during normalization.
// TestStreamDecoderNormalizesReasoningPartLifecycle 验证 xAI 推理内容生命周期事件在归一化时会保留其摘要索引。
func TestStreamDecoderNormalizesReasoningPartLifecycle(t *testing.T) {
	decoder, errNew := NewStreamDecoder("response-xai-lifecycle", xaiNow(), StreamOptions{})
	if errNew != nil {
		t.Fatalf("NewStreamDecoder() error = %v", errNew)
	}
	frames := []string{
		`{"type":"response.output_item.added","output_index":0,"item":{"id":"rs_lifecycle","type":"reasoning","status":"in_progress"}}`,
		`{"type":"response.content_part.added","item_id":"rs_lifecycle","output_index":0,"content_index":0,"part":{"type":"reasoning_text","text":""}}`,
		`{"type":"response.reasoning_text.delta","item_id":"rs_lifecycle","output_index":0,"content_index":0,"delta":"Reason"}`,
		`{"type":"response.reasoning_text.done","item_id":"rs_lifecycle","output_index":0,"content_index":0,"text":"Reason"}`,
		`{"type":"response.content_part.done","item_id":"rs_lifecycle","output_index":0,"content_index":0,"part":{"type":"reasoning_text","text":"Reason"}}`,
		`{"type":"response.completed","response":{"id":"upstream-xai-lifecycle","status":"completed"}}`,
	}
	for frameIndex, frame := range frames {
		if _, errPush := decoder.PushSSE(SSEEnvelope{Data: []byte(frame)}); errPush != nil {
			t.Fatalf("PushSSE(frame %d) error = %v", frameIndex, errPush)
		}
	}
	response := decoder.Response()
	if response.Status != vcp.ResponseCompleted || len(response.Items) != 1 || response.Items[0].Kind != vcp.ContextReasoning || response.Items[0].Content[0].Text != "Reason" {
		t.Fatalf("response = %#v", response)
	}
}

// TestStreamDecoderRestoresNamespace verifies only a declared qualified wire tool is mapped back to the original namespace and name.
// TestStreamDecoderRestoresNamespace 验证仅已声明的限定 wire 工具会映射回原始命名空间和名称。
func TestStreamDecoderRestoresNamespace(t *testing.T) {
	options := StreamOptions{ToolReferences: []ToolReference{{WireName: "weather__lookup", Namespace: "weather", Name: "lookup", Kind: vcp.ToolFunction}}}
	decoder, errNew := NewStreamDecoder("response-xai-5", xaiNow(), options)
	if errNew != nil {
		t.Fatalf("NewStreamDecoder() error = %v", errNew)
	}
	outputIndex := 0
	item := OutputItem{ID: "tool-item", Type: "function_call", CallID: "call-1", Name: "weather__lookup"}
	if _, errPush := decoder.Push(StreamEvent{Type: "response.output_item.added", Item: &item, OutputIndex: &outputIndex}); errPush != nil {
		t.Fatalf("Push(added) error = %v", errPush)
	}
	if _, errPush := decoder.Push(StreamEvent{Type: "response.function_call_arguments.done", ItemID: "tool-item", OutputIndex: &outputIndex, CallID: "call-1", Name: "weather__lookup", Arguments: `{}`}); errPush != nil {
		t.Fatalf("Push(arguments done) error = %v", errPush)
	}
	terminal := Response{ID: "upstream-xai-5", Status: "completed"}
	if _, errPush := decoder.Push(StreamEvent{Type: "response.completed", Response: &terminal}); errPush != nil {
		t.Fatalf("Push(completed) error = %v", errPush)
	}
	response := decoder.Response()
	if len(response.Items) != 1 || response.Items[0].ToolCall == nil || response.Items[0].ToolCall.Namespace != "weather" || response.Items[0].ToolCall.Name != "lookup" {
		t.Fatalf("response = %#v", response)
	}
}

// TestDecodeResponseRetainsCompactionOnlyAsProviderState verifies an xAI compaction item is not fabricated as ordinary output text.
// TestDecodeResponseRetainsCompactionOnlyAsProviderState 验证 xAI 压缩项目不会被伪造为普通输出文本。
func TestDecodeResponseRetainsCompactionOnlyAsProviderState(t *testing.T) {
	upstream := Response{ID: "upstream-xai-6", Status: "completed", Output: []OutputItem{{ID: "compact-item", Type: "compaction"}}}
	response, _, report, errDecode := DecodeResponse("response-xai-6", upstream, xaiNow(), StreamOptions{})
	if errDecode != nil {
		t.Fatalf("DecodeResponse() error = %v", errDecode)
	}
	if response.Status != vcp.ResponseCompleted || len(response.Items) != 0 {
		t.Fatalf("response = %#v", response)
	}
	if !containsSummary(report.ConversionSummary, "xai_responses.compaction.provider_state_retained_by_response_id") {
		t.Fatalf("report = %#v", report)
	}
}
