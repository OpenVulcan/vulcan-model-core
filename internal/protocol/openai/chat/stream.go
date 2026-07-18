// Portions of this stream decoder are adapted from CLIProxyAPI commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// 本流式解码器的部分逻辑改编自 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66。
// Source paths: sdk/api/handlers/openai/openai_handlers.go and internal/runtime/executor/openai_compat_executor.go.
// 来源路径：sdk/api/handlers/openai/openai_handlers.go 和 internal/runtime/executor/openai_compat_executor.go。
// The adapted scope is Chat SSE tool-delta, usage-only, and terminal compatibility behavior.
// 改编范围是 Chat SSE 工具增量、仅用量和终态兼容行为。
package chat

import (
	"fmt"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// StreamDecoder converts parsed Chat chunks into deterministic VCP semantic events.
// StreamDecoder 将解析后的 Chat 分片转换为确定性 VCP 语义事件。
type StreamDecoder struct {
	// emitter creates globally monotonic stable events.
	// emitter 创建全局单调稳定事件。
	emitter *emitter
	// reducer is the authoritative final response accumulator.
	// reducer 是权威最终响应归并器。
	reducer *vcp.Reducer
	// tools stores parallel and interleaved calls by choice and upstream index.
	// tools 按候选和上游索引存储并行与交错调用。
	tools map[string]*streamTool
	// toolOrder preserves first-observed causal order independently of map iteration.
	// toolOrder 独立于 map 迭代保留首次观察到的因果顺序。
	toolOrder []string
	// texts stores text, refusal, and reasoning item state by choice and semantic kind.
	// texts 按候选和语义类型存储文本、拒绝与推理项目状态。
	texts map[string]*streamText
	// allEvents stores the deterministic replay log.
	// allEvents 存储确定性回放日志。
	allEvents []vcp.Event
	// report stores client-safe warnings, usage, and terminal advice accumulated during stream decoding.
	// report 存储流解码期间累积的客户端安全告警、用量和终态建议。
	report vcp.ExecutionReport
	// pendingFinish records a confirmed finish_reason until usage-only chunks are consumed.
	// pendingFinish 在消费 usage-only 分片前记录已确认的 finish_reason。
	pendingFinish string
	// pendingTerminal records the exact VCP terminal type selected from a confirmed finish reason.
	// pendingTerminal 记录由已确认 finish reason 选定的精确 VCP 终态类型。
	pendingTerminal vcp.EventType
	// pendingErrorCode records the safe failure code selected from a confirmed finish reason.
	// pendingErrorCode 记录由已确认 finish reason 选定的安全失败代码。
	pendingErrorCode string
	// upstreamResponseID records the one provider response identifier observed across stream chunks.
	// upstreamResponseID 记录跨流分片观察到的唯一 Provider 响应标识。
	upstreamResponseID string
}

// streamTool stores one stable tool call across delayed upstream fields.
// streamTool 跨延迟上游字段存储一个稳定工具调用。
type streamTool struct {
	// choiceIndex identifies the owning upstream choice.
	// choiceIndex 标识所属上游候选。
	choiceIndex int
	// toolIndex identifies one call inside the choice.
	// toolIndex 标识候选内的一个调用。
	toolIndex int
	// itemID is stable from the first observed delta.
	// itemID 从首次观察到的增量开始保持稳定。
	itemID string
	// toolCallID is stable even when upstream ID arrives late.
	// toolCallID 即使上游 ID 延迟到达也保持稳定。
	toolCallID string
	// upstreamID records the first non-empty upstream ID.
	// upstreamID 记录首个非空上游 ID。
	upstreamID string
	// name records the first non-empty upstream function name.
	// name 记录首个非空上游函数名称。
	name string
	// arguments contains actual upstream fragments only.
	// arguments 仅包含真实上游片段。
	arguments string
}

// streamText stores one text or refusal item lifecycle.
// streamText 存储一个文本或拒绝项目生命周期。
type streamText struct {
	// choiceIndex identifies the owning upstream choice.
	// choiceIndex 标识所属上游候选。
	choiceIndex int
	// itemID is stable for the choice output.
	// itemID 对候选输出保持稳定。
	itemID string
	// kind identifies message, refusal, or reasoning output.
	// kind 标识消息、拒绝或推理输出。
	kind vcp.ContextKind
	// started reports whether item.started has been emitted.
	// started 表示是否已发出 item.started。
	started bool
}

// NewStreamDecoder creates a decoder and emits response.started into its replay log.
// NewStreamDecoder 创建解码器并向回放日志发出 response.started。
func NewStreamDecoder(responseID string, now time.Time) (*StreamDecoder, error) {
	if responseID == "" {
		return nil, fmt.Errorf("%w: response_id is required", ErrInvalidUpstreamResponse)
	}
	decoder := &StreamDecoder{emitter: newEmitter(responseID, now), reducer: vcp.NewReducer(responseID), tools: make(map[string]*streamTool), texts: make(map[string]*streamText), report: vcp.ExecutionReport{ResponseID: responseID, ExecutionID: vcp.DeriveID("exec", responseID)}}
	if errEmit := decoder.emit(decoder.emitter.event(vcp.EventResponseStarted), nil); errEmit != nil {
		return nil, errEmit
	}
	return decoder, nil
}

// Push converts one parsed chunk and returns only newly emitted events.
// Push 转换一个解析后的分片并仅返回新发出的事件。
func (d *StreamDecoder) Push(chunk Chunk) ([]vcp.Event, error) {
	if d.reducer.Terminal() {
		return nil, nil
	}
	if chunk.ID != "" {
		if d.upstreamResponseID != "" && d.upstreamResponseID != chunk.ID {
			return nil, fmt.Errorf("%w: stream response identifier changed", ErrInvalidUpstreamResponse)
		}
		d.upstreamResponseID = chunk.ID
	}
	if errMetadata := d.observeChunkMetadata(chunk); errMetadata != nil {
		return nil, errMetadata
	}
	newEvents := make([]vcp.Event, 0)
	if chunk.Error != nil && d.pendingTerminal == "" {
		failed := d.emitter.event(vcp.EventResponseFailed)
		failed.ErrorCode = safeErrorCode(chunk.Error)
		if errEmit := d.emit(failed, &newEvents); errEmit != nil {
			return nil, errEmit
		}
		return newEvents, nil
	}
	if chunk.Usage != nil {
		usage := usageObservation(chunk.Usage, "streaming", false)
		usageEvent := d.emitter.event(vcp.EventUsageUpdated)
		usageEvent.Usage = &usage
		if errEmit := d.emit(usageEvent, &newEvents); errEmit != nil {
			return nil, errEmit
		}
	}
	for choiceIndex := range chunk.Choices {
		choice := chunk.Choices[choiceIndex]
		if choice.Delta != nil {
			if choice.Delta.Content != "" {
				if errText := d.emitText(choice.Index, vcp.ContextMessage, choice.Delta.Content, &newEvents); errText != nil {
					return nil, errText
				}
			}
			if choice.Delta.Refusal != "" {
				if errRefusal := d.emitText(choice.Index, vcp.ContextRefusal, choice.Delta.Refusal, &newEvents); errRefusal != nil {
					return nil, errRefusal
				}
			}
			for toolIndex := range choice.Delta.ToolCalls {
				if errTool := d.emitTool(choice.Index, choice.Delta.ToolCalls[toolIndex], &newEvents); errTool != nil {
					return nil, errTool
				}
			}
			if choice.Delta.FunctionCall != nil {
				legacyDelta := ToolCallDelta{Index: 0, Type: "function", Function: *choice.Delta.FunctionCall}
				if errTool := d.emitTool(choice.Index, legacyDelta, &newEvents); errTool != nil {
					return nil, errTool
				}
			}
		}
		if choice.FinishReason != "" {
			if errFinish := d.finishChoice(choice, &newEvents); errFinish != nil {
				return nil, errFinish
			}
		}
	}
	return newEvents, nil
}

// Close emits incomplete or failed only when no legal terminal was confirmed.
// Close 仅在未确认合法终态时发出 incomplete 或 failed。
func (d *StreamDecoder) Close(transportErr error) ([]vcp.Event, error) {
	if d.reducer.Terminal() {
		return nil, nil
	}
	newEvents := make([]vcp.Event, 0, 1)
	terminalType := vcp.EventResponseIncomplete
	if d.pendingTerminal != "" {
		terminalType = d.pendingTerminal
	} else if transportErr != nil {
		terminalType = vcp.EventResponseFailed
	}
	terminal := d.emitter.event(terminalType)
	if d.pendingTerminal != "" {
		terminal.FinishReason = d.pendingFinish
		terminal.ErrorCode = d.pendingErrorCode
		if d.pendingErrorCode != "" {
			d.report.ErrorOrRetryAdvice = d.pendingErrorCode
		}
	} else if transportErr != nil {
		terminal.ErrorCode = "transport"
	} else {
		terminal.FinishReason = "eof_without_terminal"
	}
	if errEmit := d.emit(terminal, &newEvents); errEmit != nil {
		return nil, errEmit
	}
	return newEvents, nil
}

// Response returns the current deterministic reducer snapshot.
// Response 返回当前确定性 reducer 快照。
func (d *StreamDecoder) Response() vcp.Response {
	return d.reducer.Snapshot()
}

// Events returns an isolated deterministic replay log.
// Events 返回隔离的确定性回放日志。
func (d *StreamDecoder) Events() []vcp.Event {
	events := make([]vcp.Event, len(d.allEvents))
	for index := range d.allEvents {
		events[index] = cloneStreamEvent(d.allEvents[index])
	}
	return events
}

// Report returns an isolated client-safe conversion report accumulated from actual stream events.
// Report 返回从真实流事件累积而来的隔离客户端安全转换报告。
func (d *StreamDecoder) Report() vcp.ExecutionReport {
	if d == nil {
		return vcp.ExecutionReport{}
	}
	report := d.report
	report.ConversionSummary = append([]string(nil), d.report.ConversionSummary...)
	report.Usage = cloneStreamUsage(d.report.Usage)
	return report
}

// UpstreamResponseID returns the stable provider response identifier observed in this stream.
// UpstreamResponseID 返回在此流中观察到的稳定 Provider 响应标识。
func (d *StreamDecoder) UpstreamResponseID() string {
	if d == nil {
		return ""
	}
	return d.upstreamResponseID
}

// observeChunkMetadata validates documented Chat chunk discriminators and records metadata with no VCP response carrier.
// observeChunkMetadata 校验文档化 Chat 分片判别字段，并记录没有 VCP 响应承载字段的元数据。
func (d *StreamDecoder) observeChunkMetadata(chunk Chunk) error {
	if d == nil {
		return fmt.Errorf("%w: decoder is required", ErrInvalidUpstreamResponse)
	}
	if chunk.Object != "" && chunk.Object != "chat.completion.chunk" {
		return fmt.Errorf("%w: unsupported stream object %q", ErrInvalidUpstreamResponse, chunk.Object)
	}
	if chunk.Model != "" {
		d.appendReportSummary("openai_chat.response.model.omitted")
	}
	if chunk.Created != nil {
		d.appendReportSummary("openai_chat.response.created_at.omitted")
	}
	if chunk.ServiceTier != "" {
		d.appendReportSummary("openai_chat.response.service_tier.omitted")
	}
	if chunk.SystemFingerprint != "" {
		d.appendReportSummary("openai_chat.response.system_fingerprint.omitted")
	}
	reportUnrepresentedUsageMetadata(&d.report, chunk.Usage)
	for choiceIndex := range chunk.Choices {
		if errChoice := reportChoiceMetadata(&d.report, chunk.Choices[choiceIndex]); errChoice != nil {
			return errChoice
		}
	}
	return nil
}

// cloneStreamEvent returns a deep copy of pointer-backed replay data.
// cloneStreamEvent 返回含指针回放数据的深拷贝。
func cloneStreamEvent(source vcp.Event) vcp.Event {
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
	if source.FinalArguments != nil {
		arguments := *source.FinalArguments
		cloned.FinalArguments = &arguments
	}
	if source.Usage != nil {
		usage := *source.Usage
		usage.InputTokens = cloneStreamInt64(source.Usage.InputTokens)
		usage.OutputTokens = cloneStreamInt64(source.Usage.OutputTokens)
		usage.ReasoningTokens = cloneStreamInt64(source.Usage.ReasoningTokens)
		usage.CacheReadTokens = cloneStreamInt64(source.Usage.CacheReadTokens)
		usage.CacheCreationTokens = cloneStreamInt64(source.Usage.CacheCreationTokens)
		usage.TotalTokens = cloneStreamInt64(source.Usage.TotalTokens)
		cloned.Usage = &usage
	}
	return cloned
}

// cloneStreamInt64 returns an independent optional stream usage value.
// cloneStreamInt64 返回独立的可选流用量值。
func cloneStreamInt64(source *int64) *int64 {
	if source == nil {
		return nil
	}
	cloned := *source
	return &cloned
}

// cloneStreamUsage returns an independent provider usage observation for report snapshots.
// cloneStreamUsage 为报告快照返回独立的 Provider 用量观测。
func cloneStreamUsage(source *vcp.UsageObservation) *vcp.UsageObservation {
	if source == nil {
		return nil
	}
	cloned := *source
	cloned.InputTokens = cloneStreamInt64(source.InputTokens)
	cloned.OutputTokens = cloneStreamInt64(source.OutputTokens)
	cloned.ReasoningTokens = cloneStreamInt64(source.ReasoningTokens)
	cloned.CacheReadTokens = cloneStreamInt64(source.CacheReadTokens)
	cloned.CacheCreationTokens = cloneStreamInt64(source.CacheCreationTokens)
	cloned.TotalTokens = cloneStreamInt64(source.TotalTokens)
	return &cloned
}

// emitText emits one actual text fragment without conflating network chunks and items.
// emitText 发出一个真实文本片段且不混淆网络分片与项目。
func (d *StreamDecoder) emitText(choiceIndex int, kind vcp.ContextKind, fragment string, output *[]vcp.Event) error {
	key := textKey(choiceIndex, kind)
	state, exists := d.texts[key]
	if !exists {
		state = &streamText{choiceIndex: choiceIndex, itemID: vcp.DeriveID("itm", d.emitter.responseID, string(kind), fmt.Sprint(choiceIndex)), kind: kind}
		d.texts[key] = state
	}
	if !state.started {
		item := vcp.OutputItem{ItemID: state.itemID, Kind: kind, Status: vcp.OutputItemInProgress}
		started := d.emitter.itemEvent(vcp.EventItemStarted, state.itemID)
		started.Item = &item
		if errStarted := d.emit(started, output); errStarted != nil {
			return errStarted
		}
		state.started = true
	}
	delta := d.emitter.itemEvent(vcp.EventContentDelta, state.itemID)
	delta.Delta = fragment
	return d.emit(delta, output)
}

// emitTool emits real indexed argument deltas while retaining stable VCP identity.
// emitTool 发出真实索引参数增量并保持稳定 VCP 身份。
func (d *StreamDecoder) emitTool(choiceIndex int, delta ToolCallDelta, output *[]vcp.Event) error {
	if errType := validateChatToolType(delta.Type); errType != nil {
		return errType
	}
	key := toolKey(choiceIndex, delta.Index)
	state, exists := d.tools[key]
	if !exists {
		state = &streamTool{choiceIndex: choiceIndex, toolIndex: delta.Index, itemID: vcp.DeriveID("itm", d.emitter.responseID, "tool", key), toolCallID: vcp.DeriveID("call", d.emitter.responseID, key)}
		d.tools[key] = state
		d.toolOrder = append(d.toolOrder, key)
		item := vcp.OutputItem{ItemID: state.itemID, Kind: vcp.ContextToolCall, Status: vcp.OutputItemInProgress, ToolCall: &vcp.ToolCallItem{ToolCallID: state.toolCallID, SynthesizedID: delta.ID == "", Status: vcp.ToolCallPending}}
		started := d.emitter.itemEvent(vcp.EventItemStarted, state.itemID)
		started.Item = &item
		if errStarted := d.emit(started, output); errStarted != nil {
			return errStarted
		}
	}
	if delta.ID != "" {
		for otherKey, otherState := range d.tools {
			if otherKey != key && otherState.upstreamID == delta.ID {
				warning := d.emitter.itemEvent(vcp.EventWarningRaised, state.itemID)
				warning.WarningCode = "openai_chat.tool_call.duplicate_id"
				if errWarning := d.emit(warning, output); errWarning != nil {
					return errWarning
				}
			}
		}
		if state.upstreamID != "" && state.upstreamID != delta.ID {
			warning := d.emitter.itemEvent(vcp.EventWarningRaised, state.itemID)
			warning.WarningCode = "openai_chat.tool_call.duplicate_id"
			if errWarning := d.emit(warning, output); errWarning != nil {
				return errWarning
			}
		} else {
			state.upstreamID = delta.ID
		}
	}
	if delta.Function.Name != "" {
		if state.name != "" && state.name != delta.Function.Name {
			warning := d.emitter.itemEvent(vcp.EventWarningRaised, state.itemID)
			warning.WarningCode = "openai_chat.tool_call.duplicate_name"
			if errWarning := d.emit(warning, output); errWarning != nil {
				return errWarning
			}
		} else {
			state.name = delta.Function.Name
		}
	}
	if delta.Function.Arguments != "" {
		state.arguments += delta.Function.Arguments
		argumentEvent := d.emitter.itemEvent(vcp.EventToolArgumentsDelta, state.itemID)
		argumentEvent.ToolCallID = state.toolCallID
		argumentEvent.Delta = delta.Function.Arguments
		if errArguments := d.emit(argumentEvent, output); errArguments != nil {
			return errArguments
		}
	}
	return nil
}

// finishChoice preserves complete terminal assistant fields, hydrates prior deltas, and confirms the response terminal.
// finishChoice 保留完整终态助手字段、水合既有增量并确认响应终态。
func (d *StreamDecoder) finishChoice(choice Choice, output *[]vcp.Event) error {
	if errHydrate := d.hydrateTerminalOnlyFields(choice, output); errHydrate != nil {
		return errHydrate
	}
	terminalCalls := make(map[int]ToolCall)
	if choice.Message != nil {
		calls, errCalls := assistantToolCalls(choice.Message)
		if errCalls != nil {
			return errCalls
		}
		for index, call := range calls {
			terminalCalls[index] = call
		}
	}
	keys := make([]string, 0)
	for _, key := range d.toolOrder {
		state := d.tools[key]
		if state.choiceIndex == choice.Index {
			keys = append(keys, key)
		}
	}
	for _, key := range keys {
		state := d.tools[key]
		terminalCall, hydrated := terminalCalls[state.toolIndex]
		name := state.name
		upstreamID := state.upstreamID
		var finalArguments *string
		if hydrated {
			if terminalCall.Function.Name != "" {
				name = terminalCall.Function.Name
			}
			if terminalCall.ID != "" {
				upstreamID = terminalCall.ID
			}
			if terminalCall.Function.Arguments != "" {
				arguments := terminalCall.Function.Arguments
				finalArguments = &arguments
			}
		}
		completed := d.emitter.itemEvent(vcp.EventToolArgumentsCompleted, state.itemID)
		completed.ToolCallID = state.toolCallID
		completed.ToolName = name
		completed.UpstreamToolCallID = upstreamID
		completed.FinalArguments = finalArguments
		if errCompleted := d.emit(completed, output); errCompleted != nil {
			return errCompleted
		}
		if name == "" {
			warning := d.emitter.itemEvent(vcp.EventWarningRaised, state.itemID)
			warning.WarningCode = "openai_chat.tool_call.name_missing"
			if errWarning := d.emit(warning, output); errWarning != nil {
				return errWarning
			}
		}
		if errDone := d.emit(d.emitter.itemEvent(vcp.EventItemCompleted, state.itemID), output); errDone != nil {
			return errDone
		}
	}
	for _, kind := range []vcp.ContextKind{vcp.ContextMessage, vcp.ContextRefusal, vcp.ContextReasoning} {
		if text, exists := d.texts[textKey(choice.Index, kind)]; exists && text.started {
			if errDone := d.emit(d.emitter.itemEvent(vcp.EventItemCompleted, text.itemID), output); errDone != nil {
				return errDone
			}
		}
	}
	if d.pendingTerminal == "" {
		d.pendingTerminal, d.pendingFinish, d.pendingErrorCode = terminalForFinishReason(choice.FinishReason)
	}
	return nil
}

// hydrateTerminalOnlyFields emits complete terminal assistant fields only when the stream did not previously emit their deltas.
// hydrateTerminalOnlyFields 仅在流此前未发出对应增量时发出完整终态助手字段。
func (d *StreamDecoder) hydrateTerminalOnlyFields(choice Choice, output *[]vcp.Event) error {
	if choice.Message == nil {
		return nil
	}
	if choice.Message.Content != "" {
		if _, textExists := d.texts[textKey(choice.Index, vcp.ContextMessage)]; !textExists {
			if errContent := d.emitText(choice.Index, vcp.ContextMessage, choice.Message.Content, output); errContent != nil {
				return errContent
			}
		}
	}
	if choice.Message.Refusal != "" {
		if _, refusalExists := d.texts[textKey(choice.Index, vcp.ContextRefusal)]; !refusalExists {
			if errRefusal := d.emitText(choice.Index, vcp.ContextRefusal, choice.Message.Refusal, output); errRefusal != nil {
				return errRefusal
			}
		}
	}
	calls, errCalls := assistantToolCalls(choice.Message)
	if errCalls != nil {
		return errCalls
	}
	for toolIndex, call := range calls {
		key := toolKey(choice.Index, toolIndex)
		if _, toolExists := d.tools[key]; toolExists {
			continue
		}
		terminalDelta := ToolCallDelta{Index: toolIndex, ID: call.ID, Type: call.Type, Function: call.Function}
		if errTool := d.emitTool(choice.Index, terminalDelta, output); errTool != nil {
			return errTool
		}
	}
	return nil
}

// emit applies and records one semantic event atomically.
// emit 原子应用并记录一个语义事件。
func (d *StreamDecoder) emit(event vcp.Event, output *[]vcp.Event) error {
	if errApply := d.reducer.Apply(event); errApply != nil {
		return errApply
	}
	if event.Type == vcp.EventWarningRaised && event.WarningCode != "" {
		d.appendReportSummary(event.WarningCode)
	}
	if event.Type == vcp.EventUsageUpdated && event.Usage != nil {
		d.report.Usage = cloneStreamUsage(event.Usage)
	}
	if event.Type == vcp.EventResponseFailed && event.ErrorCode != "" {
		d.report.ErrorOrRetryAdvice = event.ErrorCode
	}
	d.allEvents = append(d.allEvents, event)
	if output != nil {
		*output = append(*output, event)
	}
	return nil
}

// appendReportSummary adds one stable conversion code exactly once.
// appendReportSummary 仅追加一次稳定转换代码。
func (d *StreamDecoder) appendReportSummary(code string) {
	for _, existing := range d.report.ConversionSummary {
		if existing == code {
			return
		}
	}
	d.report.ConversionSummary = append(d.report.ConversionSummary, code)
}

// toolKey returns a stable choice-and-index key.
// toolKey 返回稳定的候选与索引组合键。
func toolKey(choiceIndex int, toolIndex int) string {
	return fmt.Sprintf("%d:%d", choiceIndex, toolIndex)
}

// textKey returns a stable choice-and-semantic-kind key.
// textKey 返回稳定的候选与语义类型组合键。
func textKey(choiceIndex int, kind vcp.ContextKind) string {
	return fmt.Sprintf("%d:%s", choiceIndex, kind)
}
