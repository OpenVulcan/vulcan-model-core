package chat

import (
	"fmt"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// DecodeResponse converts one non-streaming Chat response through VCP semantic events.
// DecodeResponse 通过 VCP 语义事件转换一个非流式 Chat 响应。
func DecodeResponse(responseID string, upstream Response, now time.Time) (vcp.Response, []vcp.Event, vcp.ExecutionReport, error) {
	if responseID == "" {
		return vcp.Response{}, nil, vcp.ExecutionReport{}, fmt.Errorf("%w: response_id is required", ErrInvalidUpstreamResponse)
	}
	emitter := newEmitter(responseID, now)
	reducer := vcp.NewReducer(responseID)
	events := make([]vcp.Event, 0)
	appendEvent := func(event vcp.Event) error {
		if errApply := reducer.Apply(event); errApply != nil {
			return errApply
		}
		events = append(events, event)
		return nil
	}
	if errStart := appendEvent(emitter.event(vcp.EventResponseStarted)); errStart != nil {
		return vcp.Response{}, nil, vcp.ExecutionReport{}, errStart
	}
	report := vcp.ExecutionReport{ResponseID: responseID, ExecutionID: vcp.DeriveID("exec", responseID, upstream.ID)}
	if upstream.Error != nil {
		failed := emitter.event(vcp.EventResponseFailed)
		failed.ErrorCode = safeErrorCode(upstream.Error)
		if errFailed := appendEvent(failed); errFailed != nil {
			return vcp.Response{}, nil, report, errFailed
		}
		report.ErrorOrRetryAdvice = failed.ErrorCode
		return reducer.Snapshot(), events, report, nil
	}
	for choiceIndex := range upstream.Choices {
		choice := upstream.Choices[choiceIndex]
		if choice.Message == nil {
			report.ConversionSummary = append(report.ConversionSummary, "openai_chat.choice.message_missing")
			continue
		}
		if choice.Message.Content != "" {
			itemID := vcp.DeriveID("itm", responseID, "message", fmt.Sprint(choice.Index))
			item := vcp.OutputItem{ItemID: itemID, Kind: vcp.ContextMessage, Status: vcp.OutputItemInProgress}
			started := emitter.itemEvent(vcp.EventItemStarted, itemID)
			started.Item = &item
			if errStarted := appendEvent(started); errStarted != nil {
				return vcp.Response{}, nil, report, errStarted
			}
			delta := emitter.itemEvent(vcp.EventContentDelta, itemID)
			delta.Delta = choice.Message.Content
			if errDelta := appendEvent(delta); errDelta != nil {
				return vcp.Response{}, nil, report, errDelta
			}
			if errDone := appendEvent(emitter.itemEvent(vcp.EventItemCompleted, itemID)); errDone != nil {
				return vcp.Response{}, nil, report, errDone
			}
		}
		if choice.Message.Refusal != "" {
			itemID := vcp.DeriveID("itm", responseID, "refusal", fmt.Sprint(choice.Index))
			item := vcp.OutputItem{ItemID: itemID, Kind: vcp.ContextRefusal, Status: vcp.OutputItemInProgress}
			started := emitter.itemEvent(vcp.EventItemStarted, itemID)
			started.Item = &item
			if errStarted := appendEvent(started); errStarted != nil {
				return vcp.Response{}, nil, report, errStarted
			}
			delta := emitter.itemEvent(vcp.EventContentDelta, itemID)
			delta.Delta = choice.Message.Refusal
			if errDelta := appendEvent(delta); errDelta != nil {
				return vcp.Response{}, nil, report, errDelta
			}
			if errDone := appendEvent(emitter.itemEvent(vcp.EventItemCompleted, itemID)); errDone != nil {
				return vcp.Response{}, nil, report, errDone
			}
		}
		for toolIndex := range choice.Message.ToolCalls {
			call := choice.Message.ToolCalls[toolIndex]
			itemID := vcp.DeriveID("itm", responseID, "tool", fmt.Sprint(choice.Index), fmt.Sprint(toolIndex))
			toolCallID := call.ID
			synthesized := false
			if toolCallID == "" {
				toolCallID = vcp.DeriveID("call", responseID, fmt.Sprint(choice.Index), fmt.Sprint(toolIndex))
				synthesized = true
				report.ConversionSummary = append(report.ConversionSummary, "openai_chat.tool_call.id_synthesized")
			}
			status := vcp.ToolCallCompleted
			if call.Function.Name == "" {
				status = vcp.ToolCallIncomplete
				report.ConversionSummary = append(report.ConversionSummary, "openai_chat.tool_call.name_missing")
			}
			item := vcp.OutputItem{ItemID: itemID, Kind: vcp.ContextToolCall, Status: vcp.OutputItemInProgress, ToolCall: &vcp.ToolCallItem{ToolCallID: toolCallID, UpstreamID: call.ID, SynthesizedID: synthesized, Name: call.Function.Name, Arguments: call.Function.Arguments, Status: status}}
			started := emitter.itemEvent(vcp.EventItemStarted, itemID)
			started.Item = &item
			if errStarted := appendEvent(started); errStarted != nil {
				return vcp.Response{}, nil, report, errStarted
			}
			completed := emitter.itemEvent(vcp.EventToolArgumentsCompleted, itemID)
			completed.ToolCallID = toolCallID
			completed.ToolName = call.Function.Name
			completed.UpstreamToolCallID = call.ID
			completed.FinalArguments = &call.Function.Arguments
			if errCompleted := appendEvent(completed); errCompleted != nil {
				return vcp.Response{}, nil, report, errCompleted
			}
			if errDone := appendEvent(emitter.itemEvent(vcp.EventItemCompleted, itemID)); errDone != nil {
				return vcp.Response{}, nil, report, errDone
			}
		}
	}
	if upstream.Usage != nil {
		usage := usageObservation(upstream.Usage, "terminal", true)
		usageEvent := emitter.event(vcp.EventUsageUpdated)
		usageEvent.Usage = &usage
		if errUsage := appendEvent(usageEvent); errUsage != nil {
			return vcp.Response{}, nil, report, errUsage
		}
		report.Usage = &usage
	}
	if len(upstream.Choices) == 0 {
		incomplete := emitter.event(vcp.EventResponseIncomplete)
		incomplete.FinishReason = "missing_choices"
		if errIncomplete := appendEvent(incomplete); errIncomplete != nil {
			return vcp.Response{}, nil, report, errIncomplete
		}
		report.ConversionSummary = append(report.ConversionSummary, "openai_chat.response.choices_missing")
		return reducer.Snapshot(), events, report, nil
	}
	if upstream.Choices[0].Message == nil {
		incomplete := emitter.event(vcp.EventResponseIncomplete)
		incomplete.FinishReason = "missing_message"
		if errIncomplete := appendEvent(incomplete); errIncomplete != nil {
			return vcp.Response{}, nil, report, errIncomplete
		}
		return reducer.Snapshot(), events, report, nil
	}
	if upstream.Choices[0].FinishReason == "" {
		incomplete := emitter.event(vcp.EventResponseIncomplete)
		incomplete.FinishReason = "missing_finish_reason"
		if errIncomplete := appendEvent(incomplete); errIncomplete != nil {
			return vcp.Response{}, nil, report, errIncomplete
		}
		report.ConversionSummary = append(report.ConversionSummary, "openai_chat.response.finish_reason_missing")
		return reducer.Snapshot(), events, report, nil
	}
	terminal := emitter.event(vcp.EventResponseCompleted)
	terminal.FinishReason = safeFinishReason(upstream.Choices[0].FinishReason)
	if errTerminal := appendEvent(terminal); errTerminal != nil {
		return vcp.Response{}, nil, report, errTerminal
	}
	return reducer.Snapshot(), events, report, nil
}

// emitter creates deterministic stable VCP event identities.
// emitter 创建确定性稳定 VCP 事件身份。
type emitter struct {
	// responseID identifies every emitted event.
	// responseID 标识每个已发出事件。
	responseID string
	// nextSequence is the next globally monotonic event sequence.
	// nextSequence 是下一个全局单调事件序号。
	nextSequence uint64
	// now fixes deterministic event time for pure conversion.
	// now 固定纯转换的确定性事件时间。
	now time.Time
}

// newEmitter creates a deterministic event emitter.
// newEmitter 创建确定性事件发射器。
func newEmitter(responseID string, now time.Time) *emitter {
	return &emitter{responseID: responseID, now: now}
}

// event creates one stable semantic event.
// event 创建一个稳定语义事件。
func (e *emitter) event(eventType vcp.EventType) vcp.Event {
	e.nextSequence++
	sequenceText := fmt.Sprint(e.nextSequence)
	return vcp.Event{ResponseID: e.responseID, EventID: vcp.DeriveID("evt", e.responseID, sequenceText, string(eventType)), Sequence: e.nextSequence, Time: e.now, Replayable: true, Type: eventType}
}

// itemEvent creates one stable item-scoped semantic event.
// itemEvent 创建一个稳定的项目作用域语义事件。
func (e *emitter) itemEvent(eventType vcp.EventType, itemID string) vcp.Event {
	event := e.event(eventType)
	event.ItemID = itemID
	return event
}

// usageObservation maps OpenAI usage without replacing unknown values with zero.
// usageObservation 映射 OpenAI 用量且不使用零替代未知值。
func usageObservation(usage *Usage, phase string, final bool) vcp.UsageObservation {
	observation := vcp.UsageObservation{InputTokens: usage.PromptTokens, OutputTokens: usage.CompletionTokens, TotalTokens: usage.TotalTokens, Source: "provider_reported", Aggregation: "snapshot", Phase: phase, AccountingBasis: "input_includes_all_prompt_tokens", Final: final}
	if usage.PromptDetails != nil {
		observation.CacheReadTokens = usage.PromptDetails.CachedTokens
		observation.CacheCreationTokens = usage.PromptDetails.CacheCreationTokens
	}
	if usage.CompletionDetails != nil {
		observation.ReasoningTokens = usage.CompletionDetails.ReasoningTokens
	}
	return observation
}

// safeErrorCode returns an upstream code without copying prompts or provider messages.
// safeErrorCode 返回上游代码且不复制提示词或供应商消息。
func safeErrorCode(upstream *Error) string {
	if safeDiagnosticCode(upstream.Code) {
		return upstream.Code
	}
	if safeDiagnosticCode(upstream.Type) {
		return upstream.Type
	}
	return "upstream_protocol"
}

// safeFinishReason returns a bounded finish identifier suitable for client-visible reports.
// safeFinishReason 返回适合客户端可见报告的有界结束标识。
func safeFinishReason(value string) string {
	if safeDiagnosticCode(value) {
		return value
	}
	return "unknown"
}

// safeDiagnosticCode reports whether an upstream value is a bounded non-sensitive identifier.
// safeDiagnosticCode 报告上游值是否为有界且不敏感的标识符。
func safeDiagnosticCode(value string) bool {
	if value == "" || len(value) > 96 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '_' || character == '-' || character == '.' {
			continue
		}
		return false
	}
	return true
}
