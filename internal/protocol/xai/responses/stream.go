// Portions of this xAI stream decoder are adapted from CLIProxyAPI commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// 本 xAI 流式解码器的部分逻辑改编自 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66。
// Source path: internal/runtime/executor/xai_executor.go.
// 来源路径：internal/runtime/executor/xai_executor.go。
// The adapted scope is internal x_search filtering, output-index compaction, and completed-output repair.
// 改编范围为内部 x_search 过滤、输出索引紧凑化和已完成输出修复。
package responses

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	openairesponses "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/responses"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// StreamDecoder applies xAI compatibility rules around the typed shared Responses stream decoder.
// StreamDecoder 在类型化共享 Responses 流解码器外围应用 xAI 兼容规则。
type StreamDecoder struct {
	// base decodes the shared closed Responses event semantics.
	// base 解码共享的封闭 Responses 事件语义。
	base *openairesponses.StreamDecoder
	// reducer reduces xAI-normalized output events rather than un-restored shared events.
	// reducer 归并 xAI 归一化输出事件，而不是未恢复的共享事件。
	reducer *vcp.Reducer
	// events stores the xAI-normalized replay log.
	// events 存储 xAI 归一化回放日志。
	events []vcp.Event
	// referencesByWire restores only request-declared qualified tool names.
	// referencesByWire 仅恢复请求已声明的限定工具名称。
	referencesByWire map[string]ToolReference
	// filterInternalXSearch enables evidence-based internal x_search trace filtering.
	// filterInternalXSearch 启用基于证据的内部 x_search 轨迹过滤。
	filterInternalXSearch bool
	// droppedOutputIndexes records only filtered server-side trace positions.
	// droppedOutputIndexes 仅记录已过滤服务端轨迹位置。
	droppedOutputIndexes map[int]struct{}
	// droppedItemIDs records only identifiers proved to belong to filtered traces.
	// droppedItemIDs 仅记录已证实属于已过滤轨迹的标识。
	droppedItemIDs map[string]struct{}
	// completedItemsByIndex holds verified non-filtered item.done snapshots for terminal output repair.
	// completedItemsByIndex 保存用于终态输出修复的已验证非过滤 item.done 快照。
	completedItemsByIndex map[int]OutputItem
	// completedItemFallback holds verified item.done snapshots whose provider position was not reported.
	// completedItemFallback 保存未报告 Provider 位置的已验证 item.done 快照。
	completedItemFallback []OutputItem
	// conversionSummary contains xAI-specific safe conversion codes.
	// conversionSummary 包含 xAI 特定的安全转换代码。
	conversionSummary []string
}

// NewStreamDecoder creates an xAI stream decoder bound to one request-derived set of reversible tool references.
// NewStreamDecoder 创建一个绑定到一组请求派生可逆工具引用的 xAI 流解码器。
func NewStreamDecoder(responseID string, now time.Time, options StreamOptions) (*StreamDecoder, error) {
	base, errBase := openairesponses.NewStreamDecoder(responseID, now)
	if errBase != nil {
		return nil, errBase
	}
	decoder := &StreamDecoder{
		base: base, reducer: vcp.NewReducer(responseID), referencesByWire: make(map[string]ToolReference, len(options.ToolReferences)),
		filterInternalXSearch: options.FilterInternalXSearch, droppedOutputIndexes: make(map[int]struct{}), droppedItemIDs: make(map[string]struct{}),
		completedItemsByIndex: make(map[int]OutputItem),
	}
	for _, reference := range options.ToolReferences {
		if strings.TrimSpace(reference.WireName) == "" {
			return nil, fmt.Errorf("%w: stream tool reference wire name is required", ErrInvalidUpstreamResponse)
		}
		if existing, exists := decoder.referencesByWire[reference.WireName]; exists && (existing.Namespace != reference.Namespace || existing.Name != reference.Name || existing.Kind != reference.Kind) {
			return nil, fmt.Errorf("%w: duplicate stream tool reference %q", ErrInvalidUpstreamResponse, reference.WireName)
		}
		decoder.referencesByWire[reference.WireName] = reference
	}
	if _, errAppend := decoder.appendBaseEvents(base.Events()); errAppend != nil {
		return nil, errAppend
	}
	return decoder, nil
}

// PushSSE decodes one parsed xAI SSE envelope and returns only newly emitted normalized VCP events.
// PushSSE 解码一帧已解析 xAI SSE 信封，并仅返回新发出的归一化 VCP 事件。
func (d *StreamDecoder) PushSSE(envelope SSEEnvelope) ([]vcp.Event, error) {
	if bytes.Equal(bytes.TrimSpace(envelope.Data), []byte("[DONE]")) {
		return nil, nil
	}
	var event StreamEvent
	if errDecode := json.Unmarshal(envelope.Data, &event); errDecode != nil {
		return nil, fmt.Errorf("%w: SSE JSON: %v", ErrInvalidUpstreamResponse, errDecode)
	}
	if event.Type == "" {
		event.Type = envelope.Event
	}
	if event.Type == "" {
		return nil, fmt.Errorf("%w: SSE event type is required", ErrInvalidUpstreamResponse)
	}
	return d.Push(event)
}

// Push normalizes one typed xAI stream event before applying the shared Responses state machine.
// Push 在应用共享 Responses 状态机前归一化一个类型化 xAI 流事件。
func (d *StreamDecoder) Push(event StreamEvent) ([]vcp.Event, error) {
	if d == nil || d.base == nil || d.reducer == nil {
		return nil, fmt.Errorf("%w: decoder is not initialized", ErrInvalidUpstreamResponse)
	}
	normalized, drop, errNormalize := d.normalizeIncomingEvent(event)
	if errNormalize != nil {
		return nil, errNormalize
	}
	if drop {
		return nil, nil
	}
	baseEvents, errPush := d.base.Push(normalized)
	if errPush != nil {
		return nil, errPush
	}
	return d.appendBaseEvents(baseEvents)
}

// Close emits a safe terminal from the shared decoder and returns its xAI-normalized VCP event form.
// Close 从共享解码器发出安全终态并返回其 xAI 归一化 VCP 事件形式。
func (d *StreamDecoder) Close(transportErr error) ([]vcp.Event, error) {
	if d == nil || d.base == nil {
		return nil, fmt.Errorf("%w: decoder is not initialized", ErrInvalidUpstreamResponse)
	}
	baseEvents, errClose := d.base.Close(transportErr)
	if errClose != nil {
		return nil, errClose
	}
	return d.appendBaseEvents(baseEvents)
}

// Response returns the deterministic xAI-normalized VCP reducer snapshot.
// Response 返回确定性的 xAI 归一化 VCP reducer 快照。
func (d *StreamDecoder) Response() vcp.Response {
	if d == nil || d.reducer == nil {
		return vcp.Response{}
	}
	return d.reducer.Snapshot()
}

// Events returns an isolated xAI-normalized replay log.
// Events 返回隔离的 xAI 归一化回放日志。
func (d *StreamDecoder) Events() []vcp.Event {
	if d == nil {
		return nil
	}
	cloned := make([]vcp.Event, len(d.events))
	for index := range d.events {
		cloned[index] = cloneVCPEvent(d.events[index])
	}
	return cloned
}

// Report returns the shared decoder report enriched only with fixed xAI conversion codes.
// Report 返回仅以固定 xAI 转换代码补充的共享解码器报告。
func (d *StreamDecoder) Report() vcp.ExecutionReport {
	if d == nil || d.base == nil {
		return vcp.ExecutionReport{}
	}
	report := d.base.Report()
	for _, code := range d.conversionSummary {
		report.ConversionSummary = appendUniqueString(report.ConversionSummary, code)
	}
	return report
}

// UpstreamResponseID returns the xAI provider response identifier retained for Router-owned continuation persistence.
// UpstreamResponseID 返回为 Router 所有续接持久化保留的 xAI Provider 响应标识。
func (d *StreamDecoder) UpstreamResponseID() string {
	if d == nil || d.base == nil {
		return ""
	}
	return d.base.UpstreamResponseID()
}

// DecodeResponse converts one complete xAI response snapshot through the same filter and namespace restoration path as SSE.
// DecodeResponse 通过与 SSE 相同的过滤和命名空间恢复路径转换一个完整 xAI 响应快照。
func DecodeResponse(responseID string, upstream Response, now time.Time, options StreamOptions) (vcp.Response, []vcp.Event, vcp.ExecutionReport, error) {
	if upstream.ID == "" {
		return vcp.Response{}, nil, vcp.ExecutionReport{}, fmt.Errorf("%w: upstream response id is required", ErrInvalidUpstreamResponse)
	}
	decoder, errNew := NewStreamDecoder(responseID, now, options)
	if errNew != nil {
		return vcp.Response{}, nil, vcp.ExecutionReport{}, errNew
	}
	terminalType, errTerminal := xaiTerminalEventType(upstream.Status)
	if errTerminal != nil {
		return vcp.Response{}, nil, vcp.ExecutionReport{}, errTerminal
	}
	if _, errPush := decoder.Push(StreamEvent{Type: terminalType, Response: &upstream}); errPush != nil {
		return vcp.Response{}, nil, vcp.ExecutionReport{}, errPush
	}
	return decoder.Response(), decoder.Events(), decoder.Report(), nil
}

// ReadSSE parses xAI SSE framing without interpreting the provider JSON event payload.
// ReadSSE 解析 xAI SSE 分帧，但不解释 Provider JSON 事件载荷。
func ReadSSE(reader io.Reader, consume func(SSEEnvelope) error) error {
	return openairesponses.ReadSSE(reader, consume)
}

// normalizeIncomingEvent applies source-evidenced reasoning, x_search, index, and terminal-output rules before shared decoding.
// normalizeIncomingEvent 在共享解码前应用来源证实的推理、x_search、索引和终态输出规则。
func (d *StreamDecoder) normalizeIncomingEvent(event StreamEvent) (StreamEvent, bool, error) {
	normalized := cloneStreamEvent(event)
	dropReasoningPart, errReasoning := d.normalizeReasoningEvent(&normalized)
	if errReasoning != nil {
		return StreamEvent{}, false, errReasoning
	}
	if dropReasoningPart {
		return StreamEvent{}, true, nil
	}
	if normalized.Item != nil {
		if normalized.Item.Type == "compaction" {
			d.appendSummary("xai_responses.compaction.provider_state_retained_by_response_id")
			return StreamEvent{}, true, nil
		}
		if d.isInternalXSearchCall(*normalized.Item) {
			d.recordDroppedItem(normalized)
			d.appendSummary("xai_responses.internal_x_search.filtered")
			return StreamEvent{}, true, nil
		}
		if normalized.Type == "response.output_item.done" {
			d.collectCompletedItem(*normalized.Item, normalized.OutputIndex)
		}
	}
	if d.referencesDroppedItem(normalized) {
		return StreamEvent{}, true, nil
	}
	if normalized.Response != nil {
		if errResponse := d.normalizeTerminalResponse(normalized.Response); errResponse != nil {
			return StreamEvent{}, false, errResponse
		}
	}
	d.compactOutputIndex(&normalized)
	return normalized, false, nil
}

// normalizeReasoningEvent converts only documented xAI reasoning event variants into the shared visible-summary event shape.
// normalizeReasoningEvent 仅将已文档化的 xAI 推理事件变体转换为共享可见摘要事件形态。
func (d *StreamDecoder) normalizeReasoningEvent(event *StreamEvent) (bool, error) {
	if event == nil {
		return false, fmt.Errorf("%w: stream event is required", ErrInvalidUpstreamResponse)
	}
	switch event.Type {
	case "response.reasoning_text.delta":
		if errIndex := normalizeReasoningSummaryIndex(event); errIndex != nil {
			return false, errIndex
		}
		event.Type = "response.reasoning_summary_text.delta"
		d.appendSummary("xai_responses.reasoning_text.normalized")
	case "response.reasoning_text.done":
		if errIndex := normalizeReasoningSummaryIndex(event); errIndex != nil {
			return false, errIndex
		}
		event.Type = "response.reasoning_summary_text.done"
		d.appendSummary("xai_responses.reasoning_text.normalized")
	case "response.content_part.added", "response.content_part.done":
		if event.Part != nil && event.Part.Type == "reasoning_text" {
			if errIndex := normalizeReasoningSummaryIndex(event); errIndex != nil {
				return false, errIndex
			}
			if event.Type == "response.content_part.added" {
				event.Type = "response.reasoning_summary_part.added"
			} else {
				event.Type = "response.reasoning_summary_part.done"
			}
			event.Part.Type = "summary_text"
			d.appendSummary("xai_responses.reasoning_text.normalized")
		}
	}
	if event.Item != nil {
		if errItem := normalizeReasoningOutputItem(event.Item); errItem != nil {
			return false, errItem
		}
	}
	return false, nil
}

// normalizeReasoningSummaryIndex moves a documented xAI reasoning content index into the shared Responses summary index slot.
// normalizeReasoningSummaryIndex 将已文档化的 xAI 推理内容索引移动到共享 Responses 摘要索引槽位。
func normalizeReasoningSummaryIndex(event *StreamEvent) error {
	if event == nil {
		return fmt.Errorf("%w: stream event is required", ErrInvalidUpstreamResponse)
	}
	if event.SummaryIndex == nil {
		if event.ContentIndex == nil {
			return fmt.Errorf("%w: xAI reasoning event requires content_index or summary_index", ErrInvalidUpstreamResponse)
		}
		summaryIndex := *event.ContentIndex
		event.SummaryIndex = &summaryIndex
	}
	event.ContentIndex = nil
	return nil
}

// normalizeTerminalResponse filters terminal output and repairs an empty completed snapshot only from verified item.done records.
// normalizeTerminalResponse 过滤终态输出，并仅从已验证 item.done 记录修复空的完成快照。
func (d *StreamDecoder) normalizeTerminalResponse(response *Response) error {
	if response == nil {
		return fmt.Errorf("%w: terminal response is required", ErrInvalidUpstreamResponse)
	}
	filtered := make([]OutputItem, 0, len(response.Output))
	filteredAny := false
	for index := range response.Output {
		item := cloneOutputItem(response.Output[index])
		if item.Type == "compaction" {
			d.appendSummary("xai_responses.compaction.provider_state_retained_by_response_id")
			continue
		}
		if errItem := normalizeReasoningOutputItem(&item); errItem != nil {
			return errItem
		}
		if d.isInternalXSearchCall(item) {
			filteredAny = true
			continue
		}
		filtered = append(filtered, item)
	}
	if filteredAny {
		d.appendSummary("xai_responses.internal_x_search.filtered")
	}
	response.Output = filtered
	if len(response.Output) == 0 && (len(d.completedItemsByIndex) > 0 || len(d.completedItemFallback) > 0) {
		response.Output = d.completedOutputItems()
		d.appendSummary("xai_responses.completed_output.patched")
	}
	return nil
}

// normalizeReasoningOutputItem converts only evidenced reasoning_text summaries and refuses unexpected reasoning content variants.
// normalizeReasoningOutputItem 仅转换有证据的 reasoning_text 摘要，并拒绝意外的推理内容变体。
func normalizeReasoningOutputItem(item *OutputItem) error {
	if item == nil || item.Type != "reasoning" {
		return nil
	}
	for index := range item.Summary {
		if item.Summary[index].Type == "reasoning_text" {
			item.Summary[index].Type = "summary_text"
		}
	}
	if len(item.Content) == 0 {
		return nil
	}
	for _, content := range item.Content {
		if content.Type != "reasoning_text" {
			return fmt.Errorf("%w: unsupported reasoning content type %q", ErrInvalidUpstreamResponse, content.Type)
		}
		item.Summary = append(item.Summary, ReasoningSummary{Type: "summary_text", Text: content.Text})
	}
	item.Content = nil
	return nil
}

// isInternalXSearchCall identifies only the xAI server-side trace names and identifiers documented by the source fixtures.
// isInternalXSearchCall 仅识别来源夹具文档化的 xAI 服务端轨迹名称和标识。
func (d *StreamDecoder) isInternalXSearchCall(item OutputItem) bool {
	if d == nil || !d.filterInternalXSearch {
		return false
	}
	if item.Type != "function_call" && item.Type != "custom_tool_call" {
		return false
	}
	if !isInternalXSearchName(item.Name) {
		return false
	}
	if strings.HasPrefix(strings.TrimSpace(item.CallID), "xs_call") {
		return true
	}
	if item.Type == "function_call" {
		if reference, exists := d.referencesByWire[item.Name]; exists && (reference.Kind == vcp.ToolFunction || reference.Kind == vcp.ToolCustom) {
			return false
		}
	}
	return true
}

// isInternalXSearchName reports whether a name is one documented xAI server-side x_search subtool.
// isInternalXSearchName 报告一个名称是否为已文档化的 xAI 服务端 x_search 子工具。
func isInternalXSearchName(name string) bool {
	switch strings.TrimSpace(name) {
	case "x_user_search", "x_semantic_search", "x_keyword_search", "x_thread_fetch":
		return true
	default:
		return false
	}
}

// recordDroppedItem records only immutable identifiers carried by a verified internal x_search output item.
// recordDroppedItem 仅记录已验证内部 x_search 输出项目携带的不可变标识。
func (d *StreamDecoder) recordDroppedItem(event StreamEvent) {
	if d == nil || event.Item == nil {
		return
	}
	if event.OutputIndex != nil {
		d.droppedOutputIndexes[*event.OutputIndex] = struct{}{}
	}
	for _, identifier := range []string{event.Item.ID, event.Item.CallID} {
		if strings.TrimSpace(identifier) != "" {
			d.droppedItemIDs[identifier] = struct{}{}
		}
	}
}

// referencesDroppedItem reports whether a nonterminal event belongs to an already filtered x_search trace.
// referencesDroppedItem 报告一个非终态事件是否属于已过滤的 x_search 轨迹。
func (d *StreamDecoder) referencesDroppedItem(event StreamEvent) bool {
	if d == nil || !d.filterInternalXSearch {
		return false
	}
	if event.OutputIndex != nil {
		if _, dropped := d.droppedOutputIndexes[*event.OutputIndex]; dropped {
			return true
		}
	}
	for _, identifier := range []string{event.ItemID, event.CallID} {
		if _, dropped := d.droppedItemIDs[identifier]; identifier != "" && dropped {
			return true
		}
	}
	return false
}

// compactOutputIndex preserves contiguous consumer-visible positions after a verified internal x_search trace is removed.
// compactOutputIndex 在移除已验证内部 x_search 轨迹后保持消费者可见位置连续。
func (d *StreamDecoder) compactOutputIndex(event *StreamEvent) {
	if d == nil || event == nil || event.OutputIndex == nil || !d.filterInternalXSearch {
		return
	}
	removedBefore := 0
	for droppedIndex := range d.droppedOutputIndexes {
		if droppedIndex < *event.OutputIndex {
			removedBefore++
		}
	}
	if removedBefore == 0 {
		return
	}
	compactedIndex := *event.OutputIndex - removedBefore
	event.OutputIndex = &compactedIndex
}

// collectCompletedItem records a non-filtered output-item completion snapshot for a later empty-terminal repair.
// collectCompletedItem 记录一个非过滤输出项目完成快照，用于稍后的空终态修复。
func (d *StreamDecoder) collectCompletedItem(item OutputItem, outputIndex *int) {
	if d == nil {
		return
	}
	cloned := cloneOutputItem(item)
	if outputIndex == nil {
		d.completedItemFallback = append(d.completedItemFallback, cloned)
		return
	}
	d.completedItemsByIndex[*outputIndex] = cloned
}

// completedOutputItems returns recorded item.done snapshots sorted by provider output index followed by no-index fallbacks.
// completedOutputItems 返回按 Provider 输出索引排序的 item.done 快照，随后附加无索引回退项。
func (d *StreamDecoder) completedOutputItems() []OutputItem {
	indexes := make([]int, 0, len(d.completedItemsByIndex))
	for index := range d.completedItemsByIndex {
		indexes = append(indexes, index)
	}
	sort.Ints(indexes)
	items := make([]OutputItem, 0, len(indexes)+len(d.completedItemFallback))
	for _, index := range indexes {
		items = append(items, cloneOutputItem(d.completedItemsByIndex[index]))
	}
	for _, item := range d.completedItemFallback {
		items = append(items, cloneOutputItem(item))
	}
	return items
}

// appendBaseEvents restores declared tool identities and applies the resulting events to the xAI-owned reducer.
// appendBaseEvents 恢复已声明工具身份，并将结果事件应用到 xAI 所有 reducer。
func (d *StreamDecoder) appendBaseEvents(baseEvents []vcp.Event) ([]vcp.Event, error) {
	if d == nil || d.reducer == nil {
		return nil, fmt.Errorf("%w: decoder is not initialized", ErrInvalidUpstreamResponse)
	}
	newEvents := make([]vcp.Event, 0, len(baseEvents))
	for _, baseEvent := range baseEvents {
		normalized := d.normalizeEmittedEvent(baseEvent)
		if errApply := d.reducer.Apply(normalized); errApply != nil {
			return nil, errApply
		}
		d.events = append(d.events, cloneVCPEvent(normalized))
		newEvents = append(newEvents, cloneVCPEvent(normalized))
	}
	return newEvents, nil
}

// normalizeEmittedEvent restores only a request-declared namespace/name pair from a qualified xAI wire name.
// normalizeEmittedEvent 仅从限定 xAI wire 名称恢复请求已声明的命名空间/名称对。
func (d *StreamDecoder) normalizeEmittedEvent(event vcp.Event) vcp.Event {
	normalized := cloneVCPEvent(event)
	if normalized.Item != nil && normalized.Item.ToolCall != nil {
		if reference, exists := d.referencesByWire[normalized.Item.ToolCall.Name]; exists {
			normalized.Item.ToolCall.Name = reference.Name
			normalized.Item.ToolCall.Namespace = reference.Namespace
		}
	}
	if reference, exists := d.referencesByWire[normalized.ToolName]; exists {
		normalized.ToolName = reference.Name
	}
	return normalized
}

// appendSummary appends one safe xAI conversion code at most once.
// appendSummary 至多一次追加一个安全 xAI 转换代码。
func (d *StreamDecoder) appendSummary(code string) {
	d.conversionSummary = appendUniqueString(d.conversionSummary, code)
}

// xaiTerminalEventType maps the closed synchronous xAI response terminal status set to its shared SSE event name.
// xaiTerminalEventType 将封闭的同步 xAI 响应终态集合映射为共享 SSE 事件名称。
func xaiTerminalEventType(status string) (string, error) {
	switch status {
	case "completed":
		return "response.completed", nil
	case "incomplete":
		return "response.incomplete", nil
	case "failed":
		return "response.failed", nil
	case "cancelled":
		return "response.cancelled", nil
	default:
		return "", fmt.Errorf("%w: response status is not a supported terminal status", ErrInvalidUpstreamResponse)
	}
}

// cloneStreamEvent returns an isolated copy before xAI normalization changes pointer-backed fields.
// cloneStreamEvent 在 xAI 归一化修改指针字段前返回一个隔离副本。
func cloneStreamEvent(source StreamEvent) StreamEvent {
	cloned := source
	if source.SequenceNumber != nil {
		sequenceNumber := *source.SequenceNumber
		cloned.SequenceNumber = &sequenceNumber
	}
	if source.Response != nil {
		response := cloneResponse(*source.Response)
		cloned.Response = &response
	}
	if source.Item != nil {
		item := cloneOutputItem(*source.Item)
		cloned.Item = &item
	}
	if source.Part != nil {
		part := *source.Part
		cloned.Part = &part
	}
	if source.OutputIndex != nil {
		outputIndex := *source.OutputIndex
		cloned.OutputIndex = &outputIndex
	}
	if source.ContentIndex != nil {
		contentIndex := *source.ContentIndex
		cloned.ContentIndex = &contentIndex
	}
	if source.SummaryIndex != nil {
		summaryIndex := *source.SummaryIndex
		cloned.SummaryIndex = &summaryIndex
	}
	return cloned
}

// cloneResponse returns an isolated response copy with ordered output items detached from caller-owned slices.
// cloneResponse 返回一个隔离响应副本，其有序输出项目与调用方切片分离。
func cloneResponse(source Response) Response {
	cloned := source
	cloned.Output = make([]OutputItem, len(source.Output))
	for index := range source.Output {
		cloned.Output[index] = cloneOutputItem(source.Output[index])
	}
	return cloned
}

// cloneOutputItem returns an isolated output item copy including its content and reasoning summary slices.
// cloneOutputItem 返回一个隔离输出项目副本，包含其内容与推理摘要切片。
func cloneOutputItem(source OutputItem) OutputItem {
	cloned := source
	cloned.Content = append([]OutputContent(nil), source.Content...)
	for index := range cloned.Content {
		cloned.Content[index].Annotations = append([]openairesponses.OutputAnnotation(nil), source.Content[index].Annotations...)
	}
	cloned.Summary = append([]ReasoningSummary(nil), source.Summary...)
	return cloned
}

// cloneVCPEvent returns an isolated copy of VCP event data altered by namespace restoration.
// cloneVCPEvent 返回会被命名空间恢复改变的 VCP 事件数据的隔离副本。
func cloneVCPEvent(source vcp.Event) vcp.Event {
	cloned := source
	if source.Item != nil {
		item := *source.Item
		item.Content = append([]vcp.ContentBlock(nil), source.Item.Content...)
		for index := range item.Content {
			item.Content[index].Extension = append([]byte(nil), source.Item.Content[index].Extension...)
		}
		if source.Item.ToolCall != nil {
			toolCall := *source.Item.ToolCall
			item.ToolCall = &toolCall
		}
		cloned.Item = &item
	}
	if source.Usage != nil {
		usage := *source.Usage
		cloned.Usage = &usage
	}
	if source.FinalArguments != nil {
		arguments := *source.FinalArguments
		cloned.FinalArguments = &arguments
	}
	return cloned
}
