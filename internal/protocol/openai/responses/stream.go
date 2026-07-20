// Portions of this stream decoder are adapted from CLIProxyAPI commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// 本流式解码器的部分逻辑改编自 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66。
// Source path: sdk/api/handlers/openai/openai_responses_handlers.go.
// 来源路径：sdk/api/handlers/openai/openai_responses_handlers.go。
// The adapted scope is Responses SSE framing, late output repair, and output-item ordering; VCP owns replay semantics.
// 改编范围为 Responses SSE 分帧、晚到输出修复和输出项目顺序；VCP 拥有回放语义。
package responses

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

const (
	// maximumSSELineBytes bounds one upstream SSE line so malformed input cannot allocate without limit.
	// maximumSSELineBytes 限制单条上游 SSE 行，避免格式错误输入无限分配内存。
	maximumSSELineBytes = 4 * 1024 * 1024
)

// StreamDecoder converts typed OpenAI Responses SSE events into deterministic VCP events.
// StreamDecoder 将类型化 OpenAI Responses SSE 事件转换为确定性 VCP 事件。
type StreamDecoder struct {
	// emitter creates stable event identities and sequence numbers.
	// emitter 创建稳定事件身份与序号。
	emitter *eventEmitter
	// reducer validates and reduces emitted semantic events.
	// reducer 校验并归并已发出的语义事件。
	reducer *vcp.Reducer
	// allEvents stores an isolated replay log.
	// allEvents 存储隔离的回放日志。
	allEvents []vcp.Event
	// sourcesByUpstreamID tracks each upstream output item when its identifier is available.
	// sourcesByUpstreamID 在可用时追踪每个上游输出项目标识。
	sourcesByUpstreamID map[string]*streamSource
	// sourcesByOutputIndex tracks each upstream output item when its numeric index is available.
	// sourcesByOutputIndex 在可用时追踪每个上游输出项目索引。
	sourcesByOutputIndex map[int]*streamSource
	// citationIDs deduplicates annotations repeated by delta, part, item, and terminal snapshots.
	// citationIDs 对增量、部分、项目和终态快照重复的注释去重。
	citationIDs map[string]struct{}
	// report stores safe conversion observations accumulated during decoding.
	// report 存储解码期间累积的安全转换观测。
	report vcp.ExecutionReport
	// upstreamResponseID is retained only for Router-owned continuation persistence.
	// upstreamResponseID 仅为 Router 所有续接持久化保留。
	upstreamResponseID string
	// lastUpstreamSequence records the last provider sequence when the upstream exposes one.
	// lastUpstreamSequence 在上游暴露序列号时记录最后一个 Provider 序列。
	lastUpstreamSequence *int64
}

// streamSource groups VCP semantic items derived from one upstream output item.
// streamSource 将一个上游输出项目派生出的 VCP 语义项目分组。
type streamSource struct {
	// upstreamItemID is the provider item identity when reported.
	// upstreamItemID 是上游报告时的 Provider 项目身份。
	upstreamItemID string
	// outputIndex is the provider item position and is -1 only when not reported.
	// outputIndex 是 Provider 项目位置，仅在未报告时为 -1。
	outputIndex int
	// itemType is the closed upstream output item type.
	// itemType 是封闭的上游输出项目类型。
	itemType string
	// itemStatus is the latest verified provider lifecycle status for represented output items.
	// itemStatus 是已表示输出项目的最新已验证 Provider 生命周期状态。
	itemStatus string
	// content maps one upstream content index to its VCP semantic item.
	// content 将一个上游内容索引映射到其 VCP 语义项目。
	content map[int]*streamSemanticItem
	// tool holds the single function or custom tool-call semantic item.
	// tool 保存唯一 function 或 custom tool 调用语义项目。
	tool *streamSemanticItem
	// search holds the single native web-search semantic item.
	// search 保存唯一的原生网页搜索语义项目。
	search *streamSemanticItem
	// reasoningSummaries maps each provider visible reasoning-summary index to its VCP semantic item.
	// reasoningSummaries 将每个 Provider 可见推理摘要索引映射到其 VCP 语义项目。
	reasoningSummaries map[int]*streamSemanticItem
	// reasoningContent maps each provider reasoning-content index to its separate VCP semantic item.
	// reasoningContent 将每个 Provider 推理内容索引映射到其独立 VCP 语义项目。
	reasoningContent map[int]*streamSemanticItem
}

// streamSemanticItem tracks one emitted VCP item and its exact accumulated upstream data.
// streamSemanticItem 跟踪一个已发出 VCP 项目及其精确累积的上游数据。
type streamSemanticItem struct {
	// itemID is the stable VCP output item identifier.
	// itemID 是稳定 VCP 输出项目标识。
	itemID string
	// kind identifies message, refusal, reasoning, or tool-call semantics.
	// kind 标识消息、拒绝、推理或工具调用语义。
	kind vcp.ContextKind
	// contentIndex identifies the original content position for text-like items.
	// contentIndex 标识文本类项目的原始内容位置。
	contentIndex int
	// toolCallID is the stable VCP tool call identifier when kind is a tool call.
	// toolCallID 是 kind 为工具调用时稳定的 VCP 工具调用标识。
	toolCallID string
	// upstreamToolCallID preserves the verified provider tool call identifier when reported.
	// upstreamToolCallID 在报告时保留已验证的 Provider 工具调用标识。
	upstreamToolCallID string
	// toolName preserves the verified provider tool name when reported.
	// toolName 在报告时保留已验证的 Provider 工具名称。
	toolName string
	// content accumulates exact text or refusal deltas.
	// content 累积精确文本或拒绝增量。
	content string
	// contentCompleted reports whether a terminal content-completed event was emitted for this text-like semantic item.
	// contentCompleted 表示此文本类语义项目是否已经发出终态 content-completed 事件。
	contentCompleted bool
	// arguments accumulates exact function arguments or custom freeform input.
	// arguments 累积精确函数参数或 custom 自由格式输入。
	arguments string
	// toolArgumentsCompleted reports whether a terminal tool argument event was emitted.
	// toolArgumentsCompleted 表示是否已发出终态工具参数事件。
	toolArgumentsCompleted bool
	// completed reports whether item.completed has been emitted.
	// completed 表示是否已发出 item.completed。
	completed bool
}

// eventEmitter creates deterministic stable VCP event identities for this profile.
// eventEmitter 为此 Profile 创建确定性稳定 VCP 事件身份。
type eventEmitter struct {
	// responseID identifies every emitted event.
	// responseID 标识每个已发出事件。
	responseID string
	// nextSequence is the next globally monotonic event sequence.
	// nextSequence 是下一个全局单调事件序号。
	nextSequence uint64
	// now fixes deterministic pure-conversion event time.
	// now 固定纯转换的确定性事件时间。
	now time.Time
}

// NewStreamDecoder creates a decoder and emits response.started into its replay log.
// NewStreamDecoder 创建解码器并向回放日志发出 response.started。
func NewStreamDecoder(responseID string, now time.Time) (*StreamDecoder, error) {
	if strings.TrimSpace(responseID) == "" {
		return nil, fmt.Errorf("%w: response_id is required", ErrInvalidUpstreamResponse)
	}
	decoder := &StreamDecoder{
		emitter: eventEmitterFor(responseID, now), reducer: vcp.NewReducer(responseID),
		sourcesByUpstreamID: make(map[string]*streamSource), sourcesByOutputIndex: make(map[int]*streamSource),
		citationIDs: make(map[string]struct{}),
		report:      vcp.ExecutionReport{ResponseID: responseID, ExecutionID: vcp.DeriveID("exec", responseID)},
	}
	if errEmit := decoder.emit(decoder.emitter.event(vcp.EventResponseStarted), nil); errEmit != nil {
		return nil, errEmit
	}
	return decoder, nil
}

// eventEmitterFor creates one deterministic event emitter.
// eventEmitterFor 创建一个确定性事件发射器。
func eventEmitterFor(responseID string, now time.Time) *eventEmitter {
	return &eventEmitter{responseID: responseID, now: now}
}

// event creates one stable response-scoped semantic event.
// event 创建一个稳定的响应作用域语义事件。
func (e *eventEmitter) event(eventType vcp.EventType) vcp.Event {
	e.nextSequence++
	sequenceText := fmt.Sprint(e.nextSequence)
	return vcp.Event{ResponseID: e.responseID, EventID: vcp.DeriveID("evt", e.responseID, sequenceText, string(eventType)), Sequence: e.nextSequence, Time: e.now, Replayable: true, Type: eventType}
}

// itemEvent creates one stable item-scoped semantic event.
// itemEvent 创建一个稳定的项目作用域语义事件。
func (e *eventEmitter) itemEvent(eventType vcp.EventType, itemID string) vcp.Event {
	event := e.event(eventType)
	event.ItemID = itemID
	return event
}

// PushSSE decodes one parsed SSE envelope and returns only newly emitted VCP events.
// PushSSE 解码一帧已解析 SSE 数据，并仅返回新发出的 VCP 事件。
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

// Push converts one typed Responses stream event and returns only newly emitted VCP events.
// Push 转换一个类型化 Responses 流事件，并仅返回新发出的 VCP 事件。
func (d *StreamDecoder) Push(event StreamEvent) ([]vcp.Event, error) {
	if d == nil || d.reducer == nil || d.emitter == nil {
		return nil, fmt.Errorf("%w: decoder is not initialized", ErrInvalidUpstreamResponse)
	}
	if d.reducer.Terminal() {
		return nil, nil
	}
	if errSequence := d.observeUpstreamSequence(event.SequenceNumber); errSequence != nil {
		return nil, errSequence
	}
	newEvents := make([]vcp.Event, 0)
	switch event.Type {
	case "response.created", "response.queued", "response.in_progress":
		if event.Response == nil {
			return nil, fmt.Errorf("%w: %s requires response", ErrInvalidUpstreamResponse, event.Type)
		}
		if errSnapshot := d.observeResponse(*event.Response, false, &newEvents); errSnapshot != nil {
			return nil, errSnapshot
		}
	case "response.output_item.added":
		if event.Item == nil {
			return nil, fmt.Errorf("%w: output item added requires item", ErrInvalidUpstreamResponse)
		}
		if errAdded := d.observeOutputItemAdded(*event.Item, event.OutputIndex, &newEvents); errAdded != nil {
			return nil, errAdded
		}
	case "response.output_item.done":
		if event.Item == nil {
			return nil, fmt.Errorf("%w: output item done requires item", ErrInvalidUpstreamResponse)
		}
		if event.Item.Status != "" && event.Item.Status != "completed" {
			return nil, fmt.Errorf("%w: output item done requires completed status", ErrInvalidUpstreamResponse)
		}
		if errOutput := d.emitOutputItem(*event.Item, event.OutputIndex, &newEvents); errOutput != nil {
			return nil, errOutput
		}
	case "response.content_part.added":
		if event.ItemID == "" || event.OutputIndex == nil || event.ContentIndex == nil || event.Part == nil {
			return nil, fmt.Errorf("%w: content part added requires item_id, output_index, content_index, and part", ErrInvalidUpstreamResponse)
		}
		if errPart := d.observeContentPart(event.ItemID, event.OutputIndex, *event.ContentIndex, *event.Part, &newEvents); errPart != nil {
			return nil, errPart
		}
	case "response.content_part.done":
		if errPart := d.completeContentPart(event, &newEvents); errPart != nil {
			return nil, errPart
		}
	case "response.output_text.delta":
		if errDelta := d.emitTextDelta(event, vcp.ContextMessage, event.ContentIndex, false, &newEvents); errDelta != nil {
			return nil, errDelta
		}
	case "response.output_text.done":
		if errDone := d.emitTextDone(event, vcp.ContextMessage, event.ContentIndex, false, event.Text, &newEvents); errDone != nil {
			return nil, errDone
		}
	case "response.refusal.delta":
		if errDelta := d.emitTextDelta(event, vcp.ContextRefusal, event.ContentIndex, false, &newEvents); errDelta != nil {
			return nil, errDelta
		}
	case "response.refusal.done":
		finalRefusal := event.Refusal
		if finalRefusal == "" {
			finalRefusal = event.Text
		}
		if errDone := d.emitTextDone(event, vcp.ContextRefusal, event.ContentIndex, false, finalRefusal, &newEvents); errDone != nil {
			return nil, errDone
		}
	case "response.function_call_arguments.delta":
		if errArguments := d.emitToolArgumentsDelta(event, false, &newEvents); errArguments != nil {
			return nil, errArguments
		}
	case "response.function_call_arguments.done":
		if errArguments := d.emitToolArgumentsDone(event, false, &newEvents); errArguments != nil {
			return nil, errArguments
		}
	case "response.custom_tool_call_input.delta":
		if errArguments := d.emitToolArgumentsDelta(event, true, &newEvents); errArguments != nil {
			return nil, errArguments
		}
	case "response.custom_tool_call_input.done":
		if errArguments := d.emitToolArgumentsDone(event, true, &newEvents); errArguments != nil {
			return nil, errArguments
		}
	case "response.reasoning_summary_part.added":
		if errPart := d.observeReasoningSummaryPart(event, &newEvents); errPart != nil {
			return nil, errPart
		}
	case "response.reasoning_summary_part.done":
		if errPart := d.completeReasoningSummaryPart(event, &newEvents); errPart != nil {
			return nil, errPart
		}
	case "response.reasoning_summary_text.delta":
		if errDelta := d.emitTextDelta(event, vcp.ContextReasoning, event.SummaryIndex, true, &newEvents); errDelta != nil {
			return nil, errDelta
		}
	case "response.reasoning_text.delta":
		if errDelta := d.emitTextDelta(event, vcp.ContextReasoning, event.ContentIndex, false, &newEvents); errDelta != nil {
			return nil, errDelta
		}
	case "response.reasoning_summary_text.done":
		if errDone := d.emitTextDone(event, vcp.ContextReasoning, event.SummaryIndex, true, event.Text, &newEvents); errDone != nil {
			return nil, errDone
		}
	case "response.reasoning_text.done":
		if errDone := d.emitTextDone(event, vcp.ContextReasoning, event.ContentIndex, false, event.Text, &newEvents); errDone != nil {
			return nil, errDone
		}
	case "response.output_text.annotation.added":
		if event.Annotation == nil || event.AnnotationIndex == nil || event.ContentIndex == nil || event.ItemID == "" {
			return nil, fmt.Errorf("%w: annotation added requires item, content, annotation indexes and payload", ErrInvalidUpstreamResponse)
		}
		if errCitation := d.emitOutputAnnotation(event.ItemID, *event.ContentIndex, *event.AnnotationIndex, *event.Annotation, &newEvents); errCitation != nil {
			return nil, errCitation
		}
	case "response.web_search_call.in_progress", "response.web_search_call.searching", "response.web_search_call.completed":
		// The authoritative action payload is emitted from output_item.added/done; lifecycle-only frames add no facts.
		// 权威动作载荷由 output_item.added/done 发出；仅生命周期帧不增加事实。
	case "response.completed":
		if errTerminal := d.terminate(event.Response, vcp.EventResponseCompleted, &newEvents); errTerminal != nil {
			return nil, errTerminal
		}
	case "response.incomplete":
		if errTerminal := d.terminate(event.Response, vcp.EventResponseIncomplete, &newEvents); errTerminal != nil {
			return nil, errTerminal
		}
	case "response.failed":
		if errTerminal := d.terminate(event.Response, vcp.EventResponseFailed, &newEvents); errTerminal != nil {
			return nil, errTerminal
		}
	case "response.cancelled":
		if errTerminal := d.terminate(event.Response, vcp.EventResponseCancelled, &newEvents); errTerminal != nil {
			return nil, errTerminal
		}
	case "error":
		if errFailed := d.failWithError(event.Error, &newEvents); errFailed != nil {
			return nil, errFailed
		}
	default:
		return nil, fmt.Errorf("%w: unsupported SSE event %q", ErrInvalidUpstreamResponse, event.Type)
	}
	return newEvents, nil
}

// Close emits a safe terminal only when upstream did not confirm one.
// Close 仅在上游未确认终态时发出安全终态。
func (d *StreamDecoder) Close(transportErr error) ([]vcp.Event, error) {
	if d == nil || d.reducer == nil || d.reducer.Terminal() {
		return nil, nil
	}
	newEvents := make([]vcp.Event, 0, 1)
	terminalType := vcp.EventResponseIncomplete
	terminal := d.emitter.event(terminalType)
	if transportErr == nil {
		terminal.FinishReason = "eof_without_terminal"
	} else if errors.Is(transportErr, context.Canceled) {
		terminalType = vcp.EventResponseCancelled
		terminal = d.emitter.event(terminalType)
	} else {
		terminalType = vcp.EventResponseFailed
		terminal = d.emitter.event(terminalType)
		terminal.ErrorCode = "transport"
		d.report.ErrorOrRetryAdvice = terminal.ErrorCode
	}
	if errEmit := d.emit(terminal, &newEvents); errEmit != nil {
		return nil, errEmit
	}
	return newEvents, nil
}

// Response returns the current deterministic VCP reducer snapshot.
// Response 返回当前确定性 VCP reducer 快照。
func (d *StreamDecoder) Response() vcp.Response {
	if d == nil || d.reducer == nil {
		return vcp.Response{}
	}
	return d.reducer.Snapshot()
}

// Events returns an isolated replay log that cannot mutate decoder-owned state.
// Events 返回一个不能修改解码器所有状态的隔离回放日志。
func (d *StreamDecoder) Events() []vcp.Event {
	if d == nil {
		return nil
	}
	events := make([]vcp.Event, len(d.allEvents))
	for index := range d.allEvents {
		events[index] = cloneEvent(d.allEvents[index])
	}
	return events
}

// Report returns an isolated client-safe conversion report snapshot.
// Report 返回一个隔离的客户端安全转换报告快照。
func (d *StreamDecoder) Report() vcp.ExecutionReport {
	if d == nil {
		return vcp.ExecutionReport{}
	}
	report := d.report
	report.CapabilityDecisions = append([]vcp.CapabilityDecision(nil), d.report.CapabilityDecisions...)
	report.ConversionSummary = append([]string(nil), d.report.ConversionSummary...)
	report.Usage = cloneUsage(d.report.Usage)
	return report
}

// UpstreamResponseID returns the provider response identifier for Router-owned continuation persistence.
// UpstreamResponseID 返回供 Router 所有续接持久化使用的 Provider 响应标识。
func (d *StreamDecoder) UpstreamResponseID() string {
	if d == nil {
		return ""
	}
	return d.upstreamResponseID
}

// observeResponse records response identity, usage, and optionally complete output snapshots.
// observeResponse 记录响应身份、用量与可选完整输出快照。
func (d *StreamDecoder) observeResponse(response Response, includeOutput bool, output *[]vcp.Event) error {
	if errMetadata := d.reportUnrepresentedResponseMetadata(response); errMetadata != nil {
		return errMetadata
	}
	if response.ID != "" {
		d.upstreamResponseID = response.ID
		d.report.ExecutionID = vcp.DeriveID("exec", d.emitter.responseID, response.ID)
	}
	if includeOutput {
		for index := range response.Output {
			outputIndex := index
			if errItem := d.emitOutputItem(response.Output[index], &outputIndex, output); errItem != nil {
				return errItem
			}
			if response.Status == "completed" && (response.Output[index].Status == "in_progress" || response.Output[index].Status == "incomplete") {
				return fmt.Errorf("%w: completed response contains output item status %q", ErrInvalidUpstreamResponse, response.Output[index].Status)
			}
		}
	}
	if response.Usage != nil {
		usage := usageObservation(response.Usage, "terminal", includeOutput)
		usageEvent := d.emitter.event(vcp.EventUsageUpdated)
		usageEvent.Usage = &usage
		if errUsage := d.emit(usageEvent, output); errUsage != nil {
			return errUsage
		}
		d.report.Usage = cloneUsage(&usage)
	}
	return nil
}

// observeUpstreamSequence validates the optional documented provider ordering sequence without inventing order when it is absent.
// observeUpstreamSequence 校验可选的文档化 Provider 顺序序列，且在其缺失时不虚构顺序。
func (d *StreamDecoder) observeUpstreamSequence(sequence *int64) error {
	if d == nil || sequence == nil {
		return nil
	}
	if d.lastUpstreamSequence != nil && *sequence <= *d.lastUpstreamSequence {
		return fmt.Errorf("%w: stream sequence is not strictly increasing", ErrInvalidUpstreamResponse)
	}
	observed := *sequence
	d.lastUpstreamSequence = &observed
	return nil
}

// reportUnrepresentedResponseMetadata validates response discriminators and records documented fields that have no VCP response carrier.
// reportUnrepresentedResponseMetadata 校验响应判别字段，并记录没有 VCP 响应承载字段的文档化字段。
func (d *StreamDecoder) reportUnrepresentedResponseMetadata(response Response) error {
	if d == nil {
		return fmt.Errorf("%w: decoder is required", ErrInvalidUpstreamResponse)
	}
	if response.Object != "" && response.Object != "response" {
		return fmt.Errorf("%w: unsupported response object %q", ErrInvalidUpstreamResponse, response.Object)
	}
	if response.CreatedAt != nil || response.CompletedAt != nil {
		d.appendSummary("openai_responses.response.timestamps.omitted")
	}
	if response.Model != "" {
		d.appendSummary("openai_responses.response.model.omitted")
	}
	if response.Input != nil {
		d.appendSummary("openai_responses.response.input.omitted")
	}
	if response.Instructions != nil {
		d.appendSummary("openai_responses.response.instructions.omitted")
	}
	if response.MaxOutputTokens != nil {
		d.appendSummary("openai_responses.response.max_output_tokens.omitted")
	}
	if response.PreviousResponseID != "" {
		d.appendSummary("openai_responses.response.previous_response_id.omitted")
	}
	if response.ReasoningEffort != "" {
		d.appendSummary("openai_responses.response.reasoning_effort.omitted")
	}
	if response.Reasoning != nil {
		d.appendSummary("openai_responses.response.reasoning_configuration.omitted")
	}
	if response.Store != nil {
		d.appendSummary("openai_responses.response.store.omitted")
	}
	if response.Temperature != nil || response.TopP != nil {
		d.appendSummary("openai_responses.response.sampling.omitted")
	}
	if response.Text != nil {
		d.appendSummary("openai_responses.response.text_configuration.omitted")
	}
	if response.ToolChoice != nil || response.Tools != nil || response.ParallelToolCalls != nil {
		d.appendSummary("openai_responses.response.tool_configuration.omitted")
	}
	if response.Truncation != "" {
		d.appendSummary("openai_responses.response.truncation.omitted")
	}
	if response.TopLogprobs != nil {
		d.appendSummary("openai_responses.response.top_logprobs.omitted")
	}
	if response.User != nil {
		d.appendSummary("openai_responses.response.user.omitted")
	}
	if response.Metadata != nil {
		d.appendSummary("openai_responses.response.metadata.omitted")
	}
	if response.ServiceTier != "" {
		d.appendSummary("openai_responses.response.service_tier.omitted")
	}
	if response.Background != nil {
		d.appendSummary("openai_responses.response.background.omitted")
	}
	if response.FrequencyPenalty != nil || response.PresencePenalty != nil {
		d.appendSummary("openai_responses.response.penalties.omitted")
	}
	if response.PromptCacheKey != nil {
		d.appendSummary("openai_responses.response.prompt_cache_key.omitted")
	}
	if response.MaxToolCalls != nil {
		d.appendSummary("openai_responses.response.max_tool_calls.omitted")
	}
	if response.SafetyIdentifier != nil {
		d.appendSummary("openai_responses.response.safety_identifier.omitted")
	}
	if response.Citations != nil || response.InlineCitations != nil {
		d.appendSummary("openai_responses.response.citations.omitted")
	}
	if response.Error != nil && response.Error.Message != "" {
		d.appendSummary("openai_responses.error.message.omitted")
	}
	if response.Usage != nil {
		if response.Usage.CostInUSDTicks != nil {
			d.appendSummary("openai_responses.usage.cost.omitted")
		}
		if response.Usage.NumSourcesUsed != nil || response.Usage.NumServerSideToolsUsed != nil {
			d.appendSummary("openai_responses.usage.server_side_tools.omitted")
		}
	}
	return nil
}

// observeOutputItemAdded records stable source identity and starts non-message semantic items when possible.
// observeOutputItemAdded 记录稳定来源身份，并在可能时启动非消息语义项目。
func (d *StreamDecoder) observeOutputItemAdded(item OutputItem, outputIndex *int, output *[]vcp.Event) error {
	if item.Status != "" && item.Status != "in_progress" {
		return fmt.Errorf("%w: output item added requires in_progress status", ErrInvalidUpstreamResponse)
	}
	source, errSource := d.ensureSource(item.ID, outputIndex, item.Type)
	if errSource != nil {
		return errSource
	}
	if errState := recordOutputItemState(source, item); errState != nil {
		return errState
	}
	switch item.Type {
	case "function_call", "custom_tool_call":
		semantic, errStart := d.ensureTool(source, item.CallID, item.Name, item.Type == "custom_tool_call", output)
		if errStart != nil {
			return errStart
		}
		return d.recordToolFields(semantic, item.CallID, item.Name)
	case "reasoning":
		return nil
	case "web_search_call":
		_, errSearch := d.ensureSearch(source, item, output)
		return errSearch
	case "message":
		return nil
	default:
		return fmt.Errorf("%w: unsupported output item type %q", ErrInvalidUpstreamResponse, item.Type)
	}
}

// observeContentPart starts the exact VCP semantic item declared by one content-part-added event.
// observeContentPart 为一个 content-part-added 事件启动其声明的精确 VCP 语义项目。
func (d *StreamDecoder) observeContentPart(itemID string, outputIndex *int, contentIndex int, part StreamPart, output *[]vcp.Event) error {
	for annotationIndex, annotation := range part.Annotations {
		if errCitation := d.emitOutputAnnotation(itemID, contentIndex, annotationIndex, annotation, output); errCitation != nil {
			return errCitation
		}
	}
	if part.Logprobs != nil {
		if errWarning := d.emitWarning("openai_responses.output_logprobs_omitted", output); errWarning != nil {
			return errWarning
		}
	}
	if part.Type == "reasoning_text" {
		source, errSource := d.ensureSource(itemID, outputIndex, "reasoning")
		if errSource != nil {
			return errSource
		}
		_, errSemantic := d.ensureReasoning(source, contentIndex, false, output)
		return errSemantic
	}
	source, errSource := d.ensureSource(itemID, outputIndex, "message")
	if errSource != nil {
		return errSource
	}
	kind, errKind := contentKind(part.Type)
	if errKind != nil {
		return errKind
	}
	_, errSemantic := d.ensureContent(source, contentIndex, kind, output)
	return errSemantic
}

// completeContentPart finalizes the exact message or reasoning content part declared by one content-part-done event.
// completeContentPart 完成一个 content-part-done 事件声明的精确消息或推理内容部分。
func (d *StreamDecoder) completeContentPart(event StreamEvent, output *[]vcp.Event) error {
	if event.ItemID == "" || event.OutputIndex == nil || event.ContentIndex == nil || event.Part == nil {
		return fmt.Errorf("%w: content part done requires item_id, output_index, content_index, and part", ErrInvalidUpstreamResponse)
	}
	for annotationIndex, annotation := range event.Part.Annotations {
		if errCitation := d.emitOutputAnnotation(event.ItemID, *event.ContentIndex, annotationIndex, annotation, output); errCitation != nil {
			return errCitation
		}
	}
	if event.Part.Logprobs != nil {
		if errWarning := d.emitWarning("openai_responses.output_logprobs_omitted", output); errWarning != nil {
			return errWarning
		}
	}
	switch event.Part.Type {
	case "reasoning_text":
		source, errSource := d.ensureSource(event.ItemID, event.OutputIndex, "reasoning")
		if errSource != nil {
			return errSource
		}
		return d.emitFullReasoning(source, *event.ContentIndex, false, event.Part.Text, output)
	case "output_text":
		source, errSource := d.ensureSource(event.ItemID, event.OutputIndex, "message")
		if errSource != nil {
			return errSource
		}
		return d.emitFullText(source, *event.ContentIndex, vcp.ContextMessage, event.Part.Text, output)
	case "refusal":
		source, errSource := d.ensureSource(event.ItemID, event.OutputIndex, "message")
		if errSource != nil {
			return errSource
		}
		return d.emitFullText(source, *event.ContentIndex, vcp.ContextRefusal, event.Part.Refusal, output)
	default:
		return fmt.Errorf("%w: unsupported completed content part type %q", ErrInvalidUpstreamResponse, event.Part.Type)
	}
}

// observeReasoningSummaryPart starts one visible reasoning summary at its provider-declared summary index.
// observeReasoningSummaryPart 在 Provider 声明的摘要索引处启动一个可见推理摘要。
func (d *StreamDecoder) observeReasoningSummaryPart(event StreamEvent, output *[]vcp.Event) error {
	if event.ItemID == "" || event.OutputIndex == nil || event.SummaryIndex == nil || event.Part == nil {
		return fmt.Errorf("%w: reasoning summary part added requires item_id, output_index, summary_index, and part", ErrInvalidUpstreamResponse)
	}
	if event.Part.Type != "summary_text" {
		return fmt.Errorf("%w: unsupported reasoning summary part type %q", ErrInvalidUpstreamResponse, event.Part.Type)
	}
	source, errSource := d.ensureSource(event.ItemID, event.OutputIndex, "reasoning")
	if errSource != nil {
		return errSource
	}
	_, errSemantic := d.ensureReasoning(source, *event.SummaryIndex, true, output)
	return errSemantic
}

// completeReasoningSummaryPart finalizes one visible reasoning summary at its provider-declared summary index.
// completeReasoningSummaryPart 在 Provider 声明的摘要索引处完成一个可见推理摘要。
func (d *StreamDecoder) completeReasoningSummaryPart(event StreamEvent, output *[]vcp.Event) error {
	if event.ItemID == "" || event.OutputIndex == nil || event.SummaryIndex == nil || event.Part == nil {
		return fmt.Errorf("%w: reasoning summary part done requires item_id, output_index, summary_index, and part", ErrInvalidUpstreamResponse)
	}
	if event.Part.Type != "summary_text" {
		return fmt.Errorf("%w: unsupported completed reasoning summary part type %q", ErrInvalidUpstreamResponse, event.Part.Type)
	}
	source, errSource := d.ensureSource(event.ItemID, event.OutputIndex, "reasoning")
	if errSource != nil {
		return errSource
	}
	return d.emitFullReasoning(source, *event.SummaryIndex, true, event.Part.Text, output)
}

// emitOutputItem converts one complete output item while deduplicating prior streamed deltas.
// emitOutputItem 转换一个完整输出项目，同时对先前流式增量去重。
func (d *StreamDecoder) emitOutputItem(item OutputItem, outputIndex *int, output *[]vcp.Event) error {
	source, errSource := d.ensureSource(item.ID, outputIndex, item.Type)
	if errSource != nil {
		return errSource
	}
	if errState := recordOutputItemState(source, item); errState != nil {
		return errState
	}
	switch item.Type {
	case "message":
		for index := range item.Content {
			part := item.Content[index]
			for annotationIndex, annotation := range part.Annotations {
				if errCitation := d.emitOutputAnnotation(item.ID, index, annotationIndex, annotation, output); errCitation != nil {
					return errCitation
				}
			}
			if part.Logprobs != nil {
				if errWarning := d.emitWarning("openai_responses.output_logprobs_omitted", output); errWarning != nil {
					return errWarning
				}
			}
			kind, errKind := contentKind(part.Type)
			if errKind != nil {
				return errKind
			}
			finalText := part.Text
			if kind == vcp.ContextRefusal {
				finalText = part.Refusal
			}
			if errDone := d.emitFullText(source, index, kind, finalText, output); errDone != nil {
				return errDone
			}
		}
	case "function_call":
		semantic, errTool := d.ensureTool(source, item.CallID, item.Name, false, output)
		if errTool != nil {
			return errTool
		}
		if errDone := d.completeTool(semantic, item.CallID, item.Name, item.Arguments, output); errDone != nil {
			return errDone
		}
	case "custom_tool_call":
		semantic, errTool := d.ensureTool(source, item.CallID, item.Name, true, output)
		if errTool != nil {
			return errTool
		}
		if errDone := d.completeTool(semantic, item.CallID, item.Name, item.Input, output); errDone != nil {
			return errDone
		}
	case "reasoning":
		if item.EncryptedContent != "" {
			d.appendSummary("openai_responses.reasoning.encrypted_state_preserved_by_response_id")
		}
		for index := range item.Summary {
			if item.Summary[index].Type != "summary_text" {
				return fmt.Errorf("%w: unsupported reasoning summary type %q", ErrInvalidUpstreamResponse, item.Summary[index].Type)
			}
			if errDone := d.emitFullReasoning(source, index, true, item.Summary[index].Text, output); errDone != nil {
				return errDone
			}
		}
		for index := range item.Content {
			if item.Content[index].Type != "reasoning_text" {
				return fmt.Errorf("%w: unsupported reasoning content type %q", ErrInvalidUpstreamResponse, item.Content[index].Type)
			}
			if errDone := d.emitFullReasoning(source, index, false, item.Content[index].Text, output); errDone != nil {
				return errDone
			}
		}
	case "web_search_call":
		semantic, errSearch := d.ensureSearch(source, item, output)
		if errSearch != nil {
			return errSearch
		}
		if errComplete := d.completeSearch(semantic, item, output); errComplete != nil {
			return errComplete
		}
	default:
		return fmt.Errorf("%w: unsupported output item type %q", ErrInvalidUpstreamResponse, item.Type)
	}
	if source.itemStatus == "in_progress" || source.itemStatus == "incomplete" {
		return nil
	}
	return d.completeSource(source, output)
}

// emitTextDelta appends one text-like delta at the event-specific content or summary index.
// emitTextDelta 在事件特定的内容或摘要索引处追加一个文本类增量。
func (d *StreamDecoder) emitTextDelta(event StreamEvent, kind vcp.ContextKind, partIndex *int, reasoningSummary bool, output *[]vcp.Event) error {
	if event.ItemID == "" || event.OutputIndex == nil || partIndex == nil {
		return fmt.Errorf("%w: %s requires item_id, output_index, and its declared part index", ErrInvalidUpstreamResponse, event.Type)
	}
	source, errSource := d.ensureSource(event.ItemID, event.OutputIndex, sourceTypeForKind(kind))
	if errSource != nil {
		return errSource
	}
	var semantic *streamSemanticItem
	var errSemantic error
	if kind == vcp.ContextReasoning {
		semantic, errSemantic = d.ensureReasoning(source, *partIndex, reasoningSummary, output)
	} else {
		semantic, errSemantic = d.ensureContent(source, *partIndex, kind, output)
	}
	if errSemantic != nil {
		return errSemantic
	}
	if semantic.contentCompleted {
		return fmt.Errorf("%w: content delta arrived after completion", ErrInvalidUpstreamResponse)
	}
	semantic.content += event.Delta
	delta := d.emitter.itemEvent(vcp.EventContentDelta, semantic.itemID)
	delta.ContentIndex = semantic.contentIndex
	delta.Delta = event.Delta
	return d.emit(delta, output)
}

// emitTextDone completes one text-like stream part at its event-specific content or summary index.
// emitTextDone 在事件特定的内容或摘要索引处完成一个文本类流部分。
func (d *StreamDecoder) emitTextDone(event StreamEvent, kind vcp.ContextKind, partIndex *int, reasoningSummary bool, finalText string, output *[]vcp.Event) error {
	if event.ItemID == "" || event.OutputIndex == nil || partIndex == nil {
		return fmt.Errorf("%w: %s requires item_id, output_index, and its declared part index", ErrInvalidUpstreamResponse, event.Type)
	}
	source, errSource := d.ensureSource(event.ItemID, event.OutputIndex, sourceTypeForKind(kind))
	if errSource != nil {
		return errSource
	}
	if kind == vcp.ContextReasoning {
		return d.emitFullReasoning(source, *partIndex, reasoningSummary, finalText, output)
	}
	return d.emitFullText(source, *partIndex, kind, finalText, output)
}

// emitToolArgumentsDelta appends one function or custom-tool argument delta.
// emitToolArgumentsDelta 追加一个 function 或 custom tool 参数增量。
func (d *StreamDecoder) emitToolArgumentsDelta(event StreamEvent, custom bool, output *[]vcp.Event) error {
	if event.ItemID == "" || event.OutputIndex == nil {
		return fmt.Errorf("%w: %s requires item_id and output_index", ErrInvalidUpstreamResponse, event.Type)
	}
	sourceType := "function_call"
	if custom {
		sourceType = "custom_tool_call"
	}
	source, errSource := d.ensureSource(event.ItemID, event.OutputIndex, sourceType)
	if errSource != nil {
		return errSource
	}
	semantic, errTool := d.ensureTool(source, event.CallID, event.Name, custom, output)
	if errTool != nil {
		return errTool
	}
	if semantic.toolArgumentsCompleted {
		return fmt.Errorf("%w: tool argument delta arrived after completion", ErrInvalidUpstreamResponse)
	}
	semantic.arguments += event.Delta
	delta := d.emitter.itemEvent(vcp.EventToolArgumentsDelta, semantic.itemID)
	delta.ToolCallID = semantic.toolCallID
	delta.Delta = event.Delta
	return d.emit(delta, output)
}

// emitToolArgumentsDone completes one function or custom-tool argument stream.
// emitToolArgumentsDone 完成一个 function 或 custom tool 参数流。
func (d *StreamDecoder) emitToolArgumentsDone(event StreamEvent, custom bool, output *[]vcp.Event) error {
	if event.ItemID == "" || event.OutputIndex == nil {
		return fmt.Errorf("%w: %s requires item_id and output_index", ErrInvalidUpstreamResponse, event.Type)
	}
	sourceType := "function_call"
	if custom {
		sourceType = "custom_tool_call"
	}
	source, errSource := d.ensureSource(event.ItemID, event.OutputIndex, sourceType)
	if errSource != nil {
		return errSource
	}
	semantic, errTool := d.ensureTool(source, event.CallID, event.Name, custom, output)
	if errTool != nil {
		return errTool
	}
	finalArguments := event.Arguments
	if custom {
		finalArguments = event.Input
	}
	return d.completeTool(semantic, event.CallID, event.Name, finalArguments, output)
}

// emitFullText emits only missing suffix bytes and records a completed content part.
// emitFullText 仅发出缺失的后缀字节，并记录已完成的内容部分。
func (d *StreamDecoder) emitFullText(source *streamSource, contentIndex int, kind vcp.ContextKind, finalText string, output *[]vcp.Event) error {
	semantic, errSemantic := d.ensureContent(source, contentIndex, kind, output)
	if errSemantic != nil {
		return errSemantic
	}
	if !strings.HasPrefix(finalText, semantic.content) {
		return fmt.Errorf("%w: final content contradicts streamed delta", ErrInvalidUpstreamResponse)
	}
	if semantic.contentCompleted {
		if finalText != semantic.content {
			return fmt.Errorf("%w: completed content changed", ErrInvalidUpstreamResponse)
		}
		return nil
	}
	missing := strings.TrimPrefix(finalText, semantic.content)
	if missing != "" {
		semantic.content += missing
		delta := d.emitter.itemEvent(vcp.EventContentDelta, semantic.itemID)
		delta.ContentIndex = semantic.contentIndex
		delta.Delta = missing
		if errEmit := d.emit(delta, output); errEmit != nil {
			return errEmit
		}
	}
	completed := d.emitter.itemEvent(vcp.EventContentCompleted, semantic.itemID)
	completed.ContentIndex = semantic.contentIndex
	if errEmit := d.emit(completed, output); errEmit != nil {
		return errEmit
	}
	semantic.contentCompleted = true
	return nil
}

// emitFullReasoning emits only missing summary or reasoning-content bytes and marks the part complete.
// emitFullReasoning 仅发出缺失的摘要或推理内容字节并标记该部分完成。
func (d *StreamDecoder) emitFullReasoning(source *streamSource, contentIndex int, summary bool, finalText string, output *[]vcp.Event) error {
	semantic, errSemantic := d.ensureReasoning(source, contentIndex, summary, output)
	if errSemantic != nil {
		return errSemantic
	}
	if !strings.HasPrefix(finalText, semantic.content) {
		return fmt.Errorf("%w: final reasoning contradicts streamed delta", ErrInvalidUpstreamResponse)
	}
	if semantic.contentCompleted {
		if finalText != semantic.content {
			return fmt.Errorf("%w: completed reasoning changed", ErrInvalidUpstreamResponse)
		}
		return nil
	}
	missing := strings.TrimPrefix(finalText, semantic.content)
	if missing != "" {
		semantic.content += missing
		delta := d.emitter.itemEvent(vcp.EventContentDelta, semantic.itemID)
		delta.ContentIndex = semantic.contentIndex
		delta.Delta = missing
		if errEmit := d.emit(delta, output); errEmit != nil {
			return errEmit
		}
	}
	completed := d.emitter.itemEvent(vcp.EventContentCompleted, semantic.itemID)
	completed.ContentIndex = semantic.contentIndex
	if errEmit := d.emit(completed, output); errEmit != nil {
		return errEmit
	}
	semantic.contentCompleted = true
	return nil
}

// completeTool hydrates final tool fields without inventing a missing name or call identifier.
// completeTool 在不虚构缺失名称或调用标识的前提下水合最终工具字段。
func (d *StreamDecoder) completeTool(semantic *streamSemanticItem, upstreamCallID string, name string, finalArguments string, output *[]vcp.Event) error {
	if semantic == nil {
		return fmt.Errorf("%w: tool item is required", ErrInvalidUpstreamResponse)
	}
	if errFields := d.recordToolFields(semantic, upstreamCallID, name); errFields != nil {
		return errFields
	}
	if semantic.toolArgumentsCompleted {
		if finalArguments != "" && semantic.arguments != finalArguments {
			return fmt.Errorf("%w: completed tool arguments changed", ErrInvalidUpstreamResponse)
		}
		return nil
	}
	if finalArguments != "" || semantic.arguments == "" {
		semantic.arguments = finalArguments
	}
	completed := d.emitter.itemEvent(vcp.EventToolArgumentsCompleted, semantic.itemID)
	completed.ToolCallID = semantic.toolCallID
	completed.ToolName = semantic.toolName
	completed.UpstreamToolCallID = semantic.upstreamToolCallID
	arguments := semantic.arguments
	completed.FinalArguments = &arguments
	if errEmit := d.emit(completed, output); errEmit != nil {
		return errEmit
	}
	semantic.toolArgumentsCompleted = true
	return nil
}

// recordToolFields stores immutable provider tool identity fields and rejects conflicting late values.
// recordToolFields 存储不可变 Provider 工具身份字段并拒绝冲突的迟到值。
func (d *StreamDecoder) recordToolFields(semantic *streamSemanticItem, upstreamCallID string, name string) error {
	if semantic == nil {
		return fmt.Errorf("%w: tool item is required", ErrInvalidUpstreamResponse)
	}
	if upstreamCallID != "" {
		if semantic.upstreamToolCallID != "" && semantic.upstreamToolCallID != upstreamCallID {
			return fmt.Errorf("%w: tool call identifier changed", ErrInvalidUpstreamResponse)
		}
		semantic.upstreamToolCallID = upstreamCallID
	}
	if name != "" {
		if semantic.toolName != "" && semantic.toolName != name {
			return fmt.Errorf("%w: tool name changed", ErrInvalidUpstreamResponse)
		}
		semantic.toolName = name
	}
	return nil
}

// completeSource completes every semantic item that was actually started for one upstream output item.
// completeSource 完成一个上游输出项目中实际已启动的每个语义项目。
func (d *StreamDecoder) completeSource(source *streamSource, output *[]vcp.Event) error {
	if source == nil {
		return nil
	}
	for _, contentIndex := range sortedSemanticIndexes(source.content) {
		semantic := source.content[contentIndex]
		if errComplete := d.completeSemantic(semantic, output); errComplete != nil {
			return errComplete
		}
	}
	if source.tool != nil {
		if !source.tool.toolArgumentsCompleted {
			if errTool := d.completeTool(source.tool, source.tool.upstreamToolCallID, source.tool.toolName, source.tool.arguments, output); errTool != nil {
				return errTool
			}
		}
		if errComplete := d.completeSemantic(source.tool, output); errComplete != nil {
			return errComplete
		}
	}
	for _, reasoningIndex := range sortedSemanticIndexes(source.reasoningSummaries) {
		semantic := source.reasoningSummaries[reasoningIndex]
		if errComplete := d.completeSemantic(semantic, output); errComplete != nil {
			return errComplete
		}
	}
	for _, reasoningIndex := range sortedSemanticIndexes(source.reasoningContent) {
		semantic := source.reasoningContent[reasoningIndex]
		if errComplete := d.completeSemantic(semantic, output); errComplete != nil {
			return errComplete
		}
	}
	return nil
}

// completeAllSources completes every unique source in stable source-identity order.
// completeAllSources 按稳定来源身份顺序完成每个唯一来源。
func (d *StreamDecoder) completeAllSources(output *[]vcp.Event) error {
	for _, source := range d.sortedSources() {
		if errComplete := d.completeSource(source, output); errComplete != nil {
			return errComplete
		}
	}
	return nil
}

// recordOutputItemState validates the closed output role and lifecycle state before it can influence VCP item completion.
// recordOutputItemState 在其影响 VCP 项目完成前校验封闭输出角色与生命周期状态。
func recordOutputItemState(source *streamSource, item OutputItem) error {
	if source == nil {
		return fmt.Errorf("%w: output source is required", ErrInvalidUpstreamResponse)
	}
	if item.Type == "message" && item.Role != "" && item.Role != "assistant" {
		return fmt.Errorf("%w: unsupported output message role %q", ErrInvalidUpstreamResponse, item.Role)
	}
	if item.Type == "web_search_call" || item.Status == "" {
		return nil
	}
	switch item.Status {
	case "in_progress", "completed", "incomplete":
	default:
		return fmt.Errorf("%w: unsupported output item status %q", ErrInvalidUpstreamResponse, item.Status)
	}
	if source.itemStatus == "" {
		source.itemStatus = item.Status
		return nil
	}
	if source.itemStatus == item.Status {
		return nil
	}
	if source.itemStatus == "in_progress" && (item.Status == "completed" || item.Status == "incomplete") {
		source.itemStatus = item.Status
		return nil
	}
	return fmt.Errorf("%w: output item status changed from %q to %q", ErrInvalidUpstreamResponse, source.itemStatus, item.Status)
}

// sortedSources returns unique stream sources in deterministic provider-identity order.
// sortedSources 按确定性 Provider 身份顺序返回唯一流来源。
func (d *StreamDecoder) sortedSources() []*streamSource {
	uniqueSources := make(map[*streamSource]struct{}, len(d.sourcesByUpstreamID)+len(d.sourcesByOutputIndex))
	for _, source := range d.sourcesByUpstreamID {
		uniqueSources[source] = struct{}{}
	}
	for _, source := range d.sourcesByOutputIndex {
		uniqueSources[source] = struct{}{}
	}
	sources := make([]*streamSource, 0, len(uniqueSources))
	for source := range uniqueSources {
		sources = append(sources, source)
	}
	sort.Slice(sources, func(left int, right int) bool {
		leftIdentity := sourceIdentity(sources[left])
		rightIdentity := sourceIdentity(sources[right])
		if leftIdentity == rightIdentity {
			return sources[left].outputIndex < sources[right].outputIndex
		}
		return leftIdentity < rightIdentity
	})
	return sources
}

// sortedSemanticIndexes returns semantic map indexes in ascending provider order.
// sortedSemanticIndexes 按升序 Provider 顺序返回语义映射索引。
func sortedSemanticIndexes(semanticItems map[int]*streamSemanticItem) []int {
	indexes := make([]int, 0, len(semanticItems))
	for index := range semanticItems {
		indexes = append(indexes, index)
	}
	sort.Ints(indexes)
	return indexes
}

// completeSemantic emits item.completed exactly once for a started semantic item.
// completeSemantic 对一个已启动语义项目恰好发出一次 item.completed。
func (d *StreamDecoder) completeSemantic(semantic *streamSemanticItem, output *[]vcp.Event) error {
	if semantic == nil || semantic.completed {
		return nil
	}
	semantic.completed = true
	return d.emit(d.emitter.itemEvent(vcp.EventItemCompleted, semantic.itemID), output)
}

// ensureSource resolves exactly one source by upstream ID or output index and rejects conflicts.
// ensureSource 按上游 ID 或输出索引解析唯一来源并拒绝冲突。
func (d *StreamDecoder) ensureSource(upstreamItemID string, outputIndex *int, itemType string) (*streamSource, error) {
	if outputIndex != nil && *outputIndex < 0 {
		return nil, fmt.Errorf("%w: output_index must not be negative", ErrInvalidUpstreamResponse)
	}
	if upstreamItemID == "" && outputIndex == nil {
		return nil, fmt.Errorf("%w: item_id or output_index is required", ErrInvalidUpstreamResponse)
	}
	byID := d.sourcesByUpstreamID[upstreamItemID]
	var byIndex *streamSource
	if outputIndex != nil {
		byIndex = d.sourcesByOutputIndex[*outputIndex]
	}
	if byID != nil && byIndex != nil && byID != byIndex {
		return nil, fmt.Errorf("%w: item_id and output_index identify different output items", ErrInvalidUpstreamResponse)
	}
	source := byID
	if source == nil {
		source = byIndex
	}
	if source == nil {
		index := -1
		if outputIndex != nil {
			index = *outputIndex
		}
		source = &streamSource{upstreamItemID: upstreamItemID, outputIndex: index, itemType: itemType, content: make(map[int]*streamSemanticItem), reasoningSummaries: make(map[int]*streamSemanticItem), reasoningContent: make(map[int]*streamSemanticItem)}
	}
	if upstreamItemID != "" {
		if source.upstreamItemID != "" && source.upstreamItemID != upstreamItemID {
			return nil, fmt.Errorf("%w: output item identifier changed", ErrInvalidUpstreamResponse)
		}
		source.upstreamItemID = upstreamItemID
		d.sourcesByUpstreamID[upstreamItemID] = source
	}
	if outputIndex != nil {
		if source.outputIndex >= 0 && source.outputIndex != *outputIndex {
			return nil, fmt.Errorf("%w: output item index changed", ErrInvalidUpstreamResponse)
		}
		source.outputIndex = *outputIndex
		d.sourcesByOutputIndex[*outputIndex] = source
	}
	if itemType != "" {
		if source.itemType != "" && source.itemType != itemType {
			return nil, fmt.Errorf("%w: output item type changed from %q to %q", ErrInvalidUpstreamResponse, source.itemType, itemType)
		}
		source.itemType = itemType
	}
	return source, nil
}

// ensureContent starts or returns one content-derived semantic item with a stable VCP identity.
// ensureContent 启动或返回一个具有稳定 VCP 身份的内容派生语义项目。
func (d *StreamDecoder) ensureContent(source *streamSource, contentIndex int, kind vcp.ContextKind, output *[]vcp.Event) (*streamSemanticItem, error) {
	if source == nil || contentIndex < 0 || contentIndex > 1024 {
		return nil, fmt.Errorf("%w: invalid content item identity", ErrInvalidUpstreamResponse)
	}
	if semantic := source.content[contentIndex]; semantic != nil {
		if semantic.kind != kind {
			return nil, fmt.Errorf("%w: content index changed semantic kind", ErrInvalidUpstreamResponse)
		}
		return semantic, nil
	}
	semantic := &streamSemanticItem{itemID: d.semanticItemID(source, kind, contentIndex), kind: kind, contentIndex: contentIndex}
	if errStart := d.startSemantic(semantic, output); errStart != nil {
		return nil, errStart
	}
	source.content[contentIndex] = semantic
	return semantic, nil
}

// ensureTool starts or returns one function or custom tool-call semantic item with all available identity fields.
// ensureTool 使用全部可用身份字段启动或返回一个 function 或 custom tool 调用语义项目。
func (d *StreamDecoder) ensureTool(source *streamSource, upstreamCallID string, name string, custom bool, output *[]vcp.Event) (*streamSemanticItem, error) {
	if source == nil {
		return nil, fmt.Errorf("%w: tool source is required", ErrInvalidUpstreamResponse)
	}
	expectedType := "function_call"
	if custom {
		expectedType = "custom_tool_call"
	}
	if source.itemType != "" && source.itemType != expectedType {
		return nil, fmt.Errorf("%w: tool event conflicts with output item type %q", ErrInvalidUpstreamResponse, source.itemType)
	}
	source.itemType = expectedType
	if source.tool != nil {
		if errFields := d.recordToolFields(source.tool, upstreamCallID, name); errFields != nil {
			return nil, errFields
		}
		return source.tool, nil
	}
	toolCallID := upstreamCallID
	synthesized := false
	if toolCallID == "" {
		toolCallID = vcp.DeriveID("call", d.emitter.responseID, sourceIdentity(source), expectedType)
		synthesized = true
		d.appendSummary("openai_responses.tool_call.id_synthesized")
	}
	semantic := &streamSemanticItem{itemID: d.semanticItemID(source, vcp.ContextToolCall, 0), kind: vcp.ContextToolCall, contentIndex: 0, toolCallID: toolCallID, upstreamToolCallID: upstreamCallID, toolName: name}
	item := vcp.OutputItem{ItemID: semantic.itemID, Kind: vcp.ContextToolCall, Status: vcp.OutputItemInProgress, ToolCall: &vcp.ToolCallItem{ToolCallID: toolCallID, UpstreamID: upstreamCallID, SynthesizedID: synthesized, Name: name, Status: vcp.ToolCallPending}}
	started := d.emitter.itemEvent(vcp.EventItemStarted, semantic.itemID)
	started.Item = &item
	if errEmit := d.emit(started, output); errEmit != nil {
		return nil, errEmit
	}
	source.tool = semantic
	return semantic, nil
}

// ensureSearch starts or returns one provider-observed native web-search item.
// ensureSearch 启动或返回一个供应商观测到的原生网页搜索项目。
func (d *StreamDecoder) ensureSearch(source *streamSource, item OutputItem, output *[]vcp.Event) (*streamSemanticItem, error) {
	if source == nil || source.itemType != "web_search_call" {
		return nil, fmt.Errorf("%w: web search source is required", ErrInvalidUpstreamResponse)
	}
	if source.search != nil {
		return source.search, nil
	}
	searchID := item.ID
	if searchID == "" {
		searchID = vcp.DeriveID("search", d.emitter.responseID, sourceIdentity(source))
		d.appendSummary("openai_responses.web_search_call.id_synthesized")
	}
	semantic := &streamSemanticItem{itemID: d.semanticItemID(source, vcp.ContextSearchCall, 0), kind: vcp.ContextSearchCall, contentIndex: 0}
	searchCall := &vcp.SearchCall{ID: searchID, Status: item.Status}
	started := d.emitter.itemEvent(vcp.EventItemStarted, semantic.itemID)
	started.Item = &vcp.OutputItem{ItemID: semantic.itemID, Kind: vcp.ContextSearchCall, Status: vcp.OutputItemInProgress, SearchCall: searchCall}
	if errEmit := d.emit(started, output); errEmit != nil {
		return nil, errEmit
	}
	source.search = semantic
	return semantic, nil
}

// completeSearch hydrates one completed provider search action without fabricating ranked results.
// completeSearch 水合一个已完成的供应商搜索动作且不虚构排序结果。
func (d *StreamDecoder) completeSearch(semantic *streamSemanticItem, item OutputItem, output *[]vcp.Event) error {
	if semantic == nil || semantic.kind != vcp.ContextSearchCall || item.Action == nil || item.Status != "completed" {
		return fmt.Errorf("%w: completed web search action is required", ErrInvalidUpstreamResponse)
	}
	if item.Action.Type != "search" && item.Action.Type != "open_page" && item.Action.Type != "find_in_page" {
		return fmt.Errorf("%w: unsupported web search action %q", ErrInvalidUpstreamResponse, item.Action.Type)
	}
	searchID := item.ID
	if searchID == "" {
		searchID = vcp.DeriveID("search", d.emitter.responseID, semantic.itemID)
	}
	searchCall := &vcp.SearchCall{ID: searchID, Status: item.Status, ActionType: item.Action.Type, Query: item.Action.Query, URL: item.Action.URL, Pattern: item.Action.Pattern}
	for _, source := range item.Action.Sources {
		if errURL := validateResponseSourceURL(source.URL); errURL != nil {
			return errURL
		}
		searchCall.Sources = append(searchCall.Sources, vcp.SearchSource{Type: source.Type, URL: source.URL})
	}
	completed := d.emitter.itemEvent(vcp.EventItemCompleted, semantic.itemID)
	completed.SearchCall = searchCall
	if errEmit := d.emit(completed, output); errEmit != nil {
		return errEmit
	}
	semantic.completed = true
	return nil
}

// emitOutputAnnotation converts one URL citation and explicitly warns for non-URL annotation variants.
// emitOutputAnnotation 转换一个 URL 引用，并对非 URL 注释变体显式告警。
func (d *StreamDecoder) emitOutputAnnotation(itemID string, contentIndex int, annotationIndex int, annotation OutputAnnotation, output *[]vcp.Event) error {
	if annotation.Type != "url_citation" {
		return d.emitWarning("openai_responses.output_annotation_omitted", output)
	}
	if annotation.StartIndex == nil || annotation.EndIndex == nil || *annotation.StartIndex < 0 || *annotation.EndIndex < *annotation.StartIndex {
		return fmt.Errorf("%w: invalid URL citation offsets", ErrInvalidUpstreamResponse)
	}
	if errURL := validateResponseSourceURL(annotation.URL); errURL != nil {
		return errURL
	}
	citationID := vcp.DeriveID("citation", d.emitter.responseID, itemID, strconv.Itoa(contentIndex), strconv.Itoa(annotationIndex), annotation.URL)
	if _, exists := d.citationIDs[citationID]; exists {
		return nil
	}
	d.citationIDs[citationID] = struct{}{}
	start := *annotation.StartIndex
	end := *annotation.EndIndex
	event := d.emitter.itemEvent(vcp.EventCitationCompleted, itemID)
	event.Citation = &vcp.Citation{ID: citationID, URL: annotation.URL, Title: annotation.Title, Location: vcp.CitationLocation{OutputItemID: itemID, Start: &start, End: &end}}
	return d.emit(event, output)
}

// validateResponseSourceURL requires an absolute HTTPS provider source URL.
// validateResponseSourceURL 要求一个绝对 HTTPS 供应商来源 URL。
func validateResponseSourceURL(value string) error {
	parsed, errParse := url.Parse(value)
	if errParse != nil || parsed.Scheme != "https" || parsed.Hostname() == "" {
		return fmt.Errorf("%w: invalid web search source URL", ErrInvalidUpstreamResponse)
	}
	return nil
}

// ensureReasoning starts or returns one summary or reasoning-content semantic item at its provider-declared index.
// ensureReasoning 在 Provider 声明的索引处启动或返回一个摘要或推理内容语义项目。
func (d *StreamDecoder) ensureReasoning(source *streamSource, contentIndex int, summary bool, output *[]vcp.Event) (*streamSemanticItem, error) {
	if source == nil || contentIndex < 0 || contentIndex > 1024 {
		return nil, fmt.Errorf("%w: invalid reasoning item identity", ErrInvalidUpstreamResponse)
	}
	if source.itemType != "" && source.itemType != "reasoning" {
		return nil, fmt.Errorf("%w: reasoning event conflicts with output item type %q", ErrInvalidUpstreamResponse, source.itemType)
	}
	source.itemType = "reasoning"
	reasoningItems := source.reasoningContent
	if summary {
		reasoningItems = source.reasoningSummaries
	}
	if reasoningItems == nil {
		reasoningItems = make(map[int]*streamSemanticItem)
		if summary {
			source.reasoningSummaries = reasoningItems
		} else {
			source.reasoningContent = reasoningItems
		}
	}
	if semantic := reasoningItems[contentIndex]; semantic != nil {
		return semantic, nil
	}
	semantic := &streamSemanticItem{itemID: d.reasoningSemanticItemID(source, contentIndex, summary), kind: vcp.ContextReasoning, contentIndex: contentIndex}
	if errStart := d.startSemantic(semantic, output); errStart != nil {
		return nil, errStart
	}
	reasoningItems[contentIndex] = semantic
	return semantic, nil
}

// startSemantic emits a correctly typed VCP item.started event.
// startSemantic 发出一个正确类型的 VCP item.started 事件。
func (d *StreamDecoder) startSemantic(semantic *streamSemanticItem, output *[]vcp.Event) error {
	if semantic == nil {
		return fmt.Errorf("%w: semantic item is required", ErrInvalidUpstreamResponse)
	}
	content := make([]vcp.ContentBlock, semantic.contentIndex+1)
	for index := range content {
		content[index] = vcp.ContentBlock{Type: vcp.ContentText}
	}
	if semantic.kind == vcp.ContextRefusal {
		content[semantic.contentIndex] = vcp.ContentBlock{Type: vcp.ContentRefusal}
	}
	item := vcp.OutputItem{ItemID: semantic.itemID, Kind: semantic.kind, Status: vcp.OutputItemInProgress, Content: content}
	started := d.emitter.itemEvent(vcp.EventItemStarted, semantic.itemID)
	started.Item = &item
	return d.emit(started, output)
}

// semanticItemID derives a stable VCP item ID from immutable source identity and semantic slot.
// semanticItemID 从不可变来源身份和语义槽派生稳定 VCP 项目 ID。
func (d *StreamDecoder) semanticItemID(source *streamSource, kind vcp.ContextKind, contentIndex int) string {
	return vcp.DeriveID("itm", d.emitter.responseID, sourceIdentity(source), string(kind), fmt.Sprint(contentIndex))
}

// reasoningSemanticItemID derives a collision-free VCP item identity for one summary or raw reasoning-content slot.
// reasoningSemanticItemID 为一个摘要或原始推理内容槽位派生无冲突的 VCP 项目身份。
func (d *StreamDecoder) reasoningSemanticItemID(source *streamSource, contentIndex int, summary bool) string {
	slot := "content"
	if summary {
		slot = "summary"
	}
	return vcp.DeriveID("itm", d.emitter.responseID, sourceIdentity(source), string(vcp.ContextReasoning), slot, fmt.Sprint(contentIndex))
}

// sourceIdentity returns the provider identifier when available and otherwise the explicitly reported output index.
// sourceIdentity 在可用时返回 Provider 标识，否则返回明确报告的输出索引。
func sourceIdentity(source *streamSource) string {
	if source.upstreamItemID != "" {
		return source.upstreamItemID
	}
	return fmt.Sprintf("output-%d", source.outputIndex)
}

// terminate reduces a provider-confirmed terminal response after applying any complete response snapshot.
// terminate 在应用任意完整响应快照后归并一个 Provider 确认终态。
func (d *StreamDecoder) terminate(response *Response, terminalType vcp.EventType, output *[]vcp.Event) error {
	if response == nil {
		return fmt.Errorf("%w: terminal event requires response", ErrInvalidUpstreamResponse)
	}
	expectedStatus := ""
	switch terminalType {
	case vcp.EventResponseCompleted:
		expectedStatus = "completed"
	case vcp.EventResponseIncomplete:
		expectedStatus = "incomplete"
	case vcp.EventResponseFailed:
		expectedStatus = "failed"
	case vcp.EventResponseCancelled:
		expectedStatus = "cancelled"
	default:
		return fmt.Errorf("%w: unsupported terminal event %q", ErrInvalidUpstreamResponse, terminalType)
	}
	// The wire event name and embedded response status must corroborate each other before VCP records a terminal result.
	// 在 VCP 记录终态结果前，wire 事件名称与内嵌响应状态必须相互印证。
	if response.Status != expectedStatus {
		return fmt.Errorf("%w: terminal event %q conflicts with response status %q", ErrInvalidUpstreamResponse, terminalType, response.Status)
	}
	if errObserve := d.observeResponse(*response, true, output); errObserve != nil {
		return errObserve
	}
	if terminalType == vcp.EventResponseCompleted {
		if errComplete := d.completeAllSources(output); errComplete != nil {
			return errComplete
		}
	}
	terminal := d.emitter.event(terminalType)
	switch terminalType {
	case vcp.EventResponseCompleted:
		terminal.FinishReason = safeDiagnostic(response.Status, "completed")
	case vcp.EventResponseIncomplete:
		reason := "incomplete"
		if response.IncompleteDetails != nil {
			reason = safeDiagnostic(response.IncompleteDetails.Reason, reason)
		}
		terminal.FinishReason = reason
	case vcp.EventResponseFailed:
		terminal.ErrorCode = safeError(response.Error)
		d.report.ErrorOrRetryAdvice = terminal.ErrorCode
	case vcp.EventResponseCancelled:
		terminal.FinishReason = "cancelled"
	}
	return d.emit(terminal, output)
}

// failWithError emits one body-safe failure for a standalone SSE error event.
// failWithError 为独立 SSE error 事件发出一个不携带响应体的安全失败。
func (d *StreamDecoder) failWithError(upstream *Error, output *[]vcp.Event) error {
	if upstream != nil && upstream.Message != "" {
		d.appendSummary("openai_responses.error.message.omitted")
	}
	failed := d.emitter.event(vcp.EventResponseFailed)
	failed.ErrorCode = safeError(upstream)
	d.report.ErrorOrRetryAdvice = failed.ErrorCode
	return d.emit(failed, output)
}

// emitWarning records a fixed safe conversion warning without passing upstream text through VCP.
// emitWarning 记录一个固定安全转换警告，不将上游文本透传到 VCP。
func (d *StreamDecoder) emitWarning(code string, output *[]vcp.Event) error {
	d.appendSummary(code)
	warning := d.emitter.event(vcp.EventWarningRaised)
	warning.WarningCode = code
	return d.emit(warning, output)
}

// emit validates, stores, and optionally returns one semantic event.
// emit 校验、存储并可选返回一个语义事件。
func (d *StreamDecoder) emit(event vcp.Event, output *[]vcp.Event) error {
	if errApply := d.reducer.Apply(event); errApply != nil {
		return errApply
	}
	d.allEvents = append(d.allEvents, cloneEvent(event))
	if output != nil {
		*output = append(*output, cloneEvent(event))
	}
	return nil
}

// appendSummary appends a stable conversion code at most once.
// appendSummary 至多一次追加稳定转换代码。
func (d *StreamDecoder) appendSummary(code string) {
	for _, existing := range d.report.ConversionSummary {
		if existing == code {
			return
		}
	}
	d.report.ConversionSummary = append(d.report.ConversionSummary, code)
}

// contentKind converts the closed Responses content type into its VCP semantic item kind.
// contentKind 将封闭 Responses 内容类型转换为其 VCP 语义项目 Kind。
func contentKind(contentType string) (vcp.ContextKind, error) {
	switch contentType {
	case "output_text", "text":
		return vcp.ContextMessage, nil
	case "refusal":
		return vcp.ContextRefusal, nil
	default:
		return "", fmt.Errorf("%w: unsupported output content type %q", ErrInvalidUpstreamResponse, contentType)
	}
}

// sourceTypeForKind returns the single upstream source type associated with a streamed semantic kind.
// sourceTypeForKind 返回与流式语义 Kind 关联的唯一上游来源类型。
func sourceTypeForKind(kind vcp.ContextKind) string {
	if kind == vcp.ContextReasoning {
		return "reasoning"
	}
	return "message"
}

// usageObservation converts typed Responses usage without replacing unknown values by zero.
// usageObservation 转换类型化 Responses 用量，且不使用零替换未知值。
func usageObservation(usage *Usage, phase string, final bool) vcp.UsageObservation {
	observation := vcp.UsageObservation{Source: "provider", Aggregation: "snapshot", Phase: phase, AccountingBasis: "provider_reported", Final: final}
	if usage == nil {
		return observation
	}
	observation.InputTokens = cloneInt64(usage.InputTokens)
	observation.OutputTokens = cloneInt64(usage.OutputTokens)
	observation.TotalTokens = cloneInt64(usage.TotalTokens)
	if usage.InputTokensDetails != nil {
		observation.CacheReadTokens = cloneInt64(usage.InputTokensDetails.CachedTokens)
	}
	if usage.OutputTokensDetails != nil {
		observation.ReasoningTokens = cloneInt64(usage.OutputTokensDetails.ReasoningTokens)
	}
	return observation
}

// safeError returns a fixed safe error code rather than untrusted upstream message content.
// safeError 返回固定安全错误码，而不是不可信上游消息内容。
func safeError(upstream *Error) string {
	if upstream == nil {
		return "upstream_error"
	}
	if code := safeDiagnostic(upstream.Code, ""); code != "" {
		return code
	}
	if kind := safeDiagnostic(upstream.Type, ""); kind != "" {
		return kind
	}
	return "upstream_error"
}

// safeDiagnostic accepts only registered-safe diagnostic characters and falls back otherwise.
// safeDiagnostic 仅接受已注册安全诊断字符，否则使用回退值。
func safeDiagnostic(value string, fallback string) string {
	if value == "" {
		return fallback
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '.' && character != '_' && character != '-' {
			return fallback
		}
	}
	return value
}

// cloneEvent returns an isolated copy of pointer-backed VCP event data.
// cloneEvent 返回含指针的 VCP 事件数据的隔离副本。
func cloneEvent(source vcp.Event) vcp.Event {
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
	cloned.Usage = cloneUsage(source.Usage)
	if source.FinalArguments != nil {
		arguments := *source.FinalArguments
		cloned.FinalArguments = &arguments
	}
	return cloned
}

// cloneUsage returns an isolated optional usage observation copy.
// cloneUsage 返回一个隔离的可选用量观测副本。
func cloneUsage(source *vcp.UsageObservation) *vcp.UsageObservation {
	if source == nil {
		return nil
	}
	cloned := *source
	cloned.InputTokens = cloneInt64(source.InputTokens)
	cloned.OutputTokens = cloneInt64(source.OutputTokens)
	cloned.ReasoningTokens = cloneInt64(source.ReasoningTokens)
	cloned.CacheReadTokens = cloneInt64(source.CacheReadTokens)
	cloned.CacheCreationTokens = cloneInt64(source.CacheCreationTokens)
	cloned.TotalTokens = cloneInt64(source.TotalTokens)
	return &cloned
}

// cloneInt64 returns an isolated optional integer value.
// cloneInt64 返回一个隔离的可选整数值。
func cloneInt64(source *int64) *int64 {
	if source == nil {
		return nil
	}
	cloned := *source
	return &cloned
}

// ReadSSE parses an SSE byte stream into complete envelopes without interpreting provider JSON.
// ReadSSE 将 SSE 字节流解析为完整信封，但不解释 Provider JSON。
func ReadSSE(reader io.Reader, consume func(SSEEnvelope) error) error {
	if reader == nil || consume == nil {
		return fmt.Errorf("%w: SSE reader and consumer are required", ErrInvalidUpstreamResponse)
	}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), maximumSSELineBytes)
	// eventName and dataLines hold the current SSE frame until its blank-line delimiter.
	// eventName 和 dataLines 在空行分隔符前保存当前 SSE 帧。
	eventName := ""
	dataLines := make([]string, 0)
	// frameBytes bounds the joined data payload across multiple individually valid SSE lines.
	// frameBytes 限制跨多条单独有效 SSE 行连接后的数据载荷。
	frameBytes := 0
	dispatch := func() error {
		if len(dataLines) == 0 {
			eventName = ""
			frameBytes = 0
			return nil
		}
		envelope := SSEEnvelope{Event: eventName, Data: []byte(strings.Join(dataLines, "\n"))}
		eventName = ""
		dataLines = dataLines[:0]
		frameBytes = 0
		return consume(envelope)
	}
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if errDispatch := dispatch(); errDispatch != nil {
				return errDispatch
			}
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		field, value, found := strings.Cut(line, ":")
		if !found {
			return fmt.Errorf("%w: malformed SSE field", ErrInvalidUpstreamResponse)
		}
		value = strings.TrimPrefix(value, " ")
		switch field {
		case "event":
			eventName = value
		case "data":
			if len(dataLines) > 0 {
				if frameBytes >= maximumSSELineBytes {
					return fmt.Errorf("%w: SSE frame exceeds the data limit", ErrInvalidUpstreamResponse)
				}
				frameBytes++
			}
			if len(value) > maximumSSELineBytes-frameBytes {
				return fmt.Errorf("%w: SSE frame exceeds the data limit", ErrInvalidUpstreamResponse)
			}
			frameBytes += len(value)
			dataLines = append(dataLines, value)
		}
	}
	if errScan := scanner.Err(); errScan != nil {
		return errScan
	}
	return dispatch()
}
