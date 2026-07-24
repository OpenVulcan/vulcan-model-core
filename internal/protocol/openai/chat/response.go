// Portions of this response adapter are adapted from CLIProxyAPI commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// 本响应适配器的部分逻辑改编自 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66。
// Source paths: sdk/api/handlers/openai/openai_handlers.go and internal/runtime/executor/openai_compat_executor.go.
// 来源路径：sdk/api/handlers/openai/openai_handlers.go 和 internal/runtime/executor/openai_compat_executor.go。
// The adapted scope is typed Chat terminal, tool, refusal, and usage behavior without a CLIProxyAPI runtime dependency.
// 改编范围是类型化 Chat 终态、工具、拒绝和用量行为，且不引入 CLIProxyAPI 运行时依赖。
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
	if errMetadata := reportResponseMetadata(&report, upstream); errMetadata != nil {
		return vcp.Response{}, nil, report, errMetadata
	}
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
		if choice.Message.ReasoningContent != "" {
			itemID := vcp.DeriveID("itm", responseID, "reasoning", fmt.Sprint(choice.Index))
			item := vcp.OutputItem{ItemID: itemID, Kind: vcp.ContextReasoning, Status: vcp.OutputItemInProgress}
			started := emitter.itemEvent(vcp.EventItemStarted, itemID)
			started.Item = &item
			if errStarted := appendEvent(started); errStarted != nil {
				return vcp.Response{}, nil, report, errStarted
			}
			delta := emitter.itemEvent(vcp.EventContentDelta, itemID)
			delta.Delta = choice.Message.ReasoningContent
			if errDelta := appendEvent(delta); errDelta != nil {
				return vcp.Response{}, nil, report, errDelta
			}
			if errDone := appendEvent(emitter.itemEvent(vcp.EventItemCompleted, itemID)); errDone != nil {
				return vcp.Response{}, nil, report, errDone
			}
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
		calls, errCalls := assistantToolCalls(choice.Message)
		if errCalls != nil {
			return vcp.Response{}, nil, report, errCalls
		}
		for toolIndex := range calls {
			call := calls[toolIndex]
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
	terminalType, finishReason, errorCode := terminalForFinishReason(upstream.Choices[0].FinishReason)
	terminal := emitter.event(terminalType)
	terminal.FinishReason = finishReason
	terminal.ErrorCode = errorCode
	if errTerminal := appendEvent(terminal); errTerminal != nil {
		return vcp.Response{}, nil, report, errTerminal
	}
	if errorCode != "" {
		report.ErrorOrRetryAdvice = errorCode
	}
	return reducer.Snapshot(), events, report, nil
}

// reportResponseMetadata validates closed response discriminators and records every documented response field that lacks a VCP carrier.
// reportResponseMetadata 校验封闭响应判别字段，并记录每个缺少 VCP 承载字段的文档化响应字段。
func reportResponseMetadata(report *vcp.ExecutionReport, upstream Response) error {
	if report == nil {
		return fmt.Errorf("%w: execution report is required", ErrInvalidUpstreamResponse)
	}
	if upstream.Object != "" && upstream.Object != "chat.completion" {
		return fmt.Errorf("%w: unsupported response object %q", ErrInvalidUpstreamResponse, upstream.Object)
	}
	if upstream.Model != "" {
		appendChatSummary(report, "openai_chat.response.model.omitted")
	}
	if upstream.Created != nil {
		appendChatSummary(report, "openai_chat.response.created_at.omitted")
	}
	if upstream.ServiceTier != "" {
		appendChatSummary(report, "openai_chat.response.service_tier.omitted")
	}
	if upstream.SystemFingerprint != "" {
		appendChatSummary(report, "openai_chat.response.system_fingerprint.omitted")
	}
	reportUnrepresentedUsageMetadata(report, upstream.Usage)
	for choiceIndex := range upstream.Choices {
		if errChoice := reportChoiceMetadata(report, upstream.Choices[choiceIndex], false); errChoice != nil {
			return errChoice
		}
	}
	return nil
}

// reportChoiceMetadata validates closed Chat choice payloads and records safe omissions without retaining provider payload contents.
// reportChoiceMetadata 校验封闭 Chat 候选载荷，并在不保留 Provider 载荷内容的前提下记录安全省略。
func reportChoiceMetadata(report *vcp.ExecutionReport, choice Choice, allowAudio bool) error {
	if report == nil {
		return fmt.Errorf("%w: execution report is required", ErrInvalidUpstreamResponse)
	}
	if choice.Logprobs != nil {
		appendChatSummary(report, "openai_chat.choice.logprobs.omitted")
	}
	if choice.Message != nil {
		if choice.Message.Role != "" && choice.Message.Role != "assistant" {
			return fmt.Errorf("%w: unsupported assistant message role %q", ErrInvalidUpstreamResponse, choice.Message.Role)
		}
		if choice.Message.Audio != nil && !allowAudio {
			return fmt.Errorf("%w: audio output is outside the first-phase Chat profile", ErrInvalidUpstreamResponse)
		}
		if allowAudio {
			reportAudioMetadata(report, choice.Message.Audio)
		}
		if len(choice.Message.Annotations) > 0 {
			appendChatSummary(report, "openai_chat.message.annotations.omitted")
		}
		if choice.Message.FunctionCall != nil {
			appendChatSummary(report, "openai_chat.function_call.deprecated_projected")
		}
		if _, errCalls := assistantToolCalls(choice.Message); errCalls != nil {
			return errCalls
		}
	}
	if choice.Delta != nil {
		if choice.Delta.Role != "" && choice.Delta.Role != "assistant" {
			return fmt.Errorf("%w: unsupported assistant delta role %q", ErrInvalidUpstreamResponse, choice.Delta.Role)
		}
		if choice.Delta.Audio != nil && !allowAudio {
			return fmt.Errorf("%w: audio output is outside the first-phase Chat profile", ErrInvalidUpstreamResponse)
		}
		if allowAudio {
			reportAudioMetadata(report, choice.Delta.Audio)
		}
		if choice.Delta.FunctionCall != nil {
			if len(choice.Delta.ToolCalls) > 0 {
				return fmt.Errorf("%w: deprecated function_call and tool_calls cannot coexist", ErrInvalidUpstreamResponse)
			}
			appendChatSummary(report, "openai_chat.function_call.deprecated_projected")
		}
		for toolIndex := range choice.Delta.ToolCalls {
			if errType := validateChatToolType(choice.Delta.ToolCalls[toolIndex].Type); errType != nil {
				return errType
			}
		}
	}
	return nil
}

// reportAudioMetadata records provider audio identity metadata that has no public VCP carrier.
// reportAudioMetadata 记录没有公开 VCP 承载字段的供应商音频身份元数据。
func reportAudioMetadata(report *vcp.ExecutionReport, audio *AudioOutputDelta) {
	if report == nil || audio == nil {
		return
	}
	if audio.ID != "" {
		appendChatSummary(report, "openai_chat.audio.id.omitted")
	}
	if audio.ExpiresAt != nil {
		appendChatSummary(report, "openai_chat.audio.expires_at.omitted")
	}
}

// reportUnrepresentedUsageMetadata records documented Chat usage details that VCP cannot account for without inventing a token category.
// reportUnrepresentedUsageMetadata 记录 VCP 无法在不虚构 Token 类别的前提下计量的文档化 Chat 用量明细。
func reportUnrepresentedUsageMetadata(report *vcp.ExecutionReport, usage *Usage) {
	if report == nil || usage == nil {
		return
	}
	if (usage.PromptDetails != nil && (usage.PromptDetails.AudioTokens != nil || usage.PromptDetails.TextTokens != nil || usage.PromptDetails.ImageTokens != nil)) || (usage.CompletionDetails != nil && (usage.CompletionDetails.AudioTokens != nil || usage.CompletionDetails.AcceptedPredictionTokens != nil || usage.CompletionDetails.RejectedPredictionTokens != nil)) {
		appendChatSummary(report, "openai_chat.usage.supplemental_tokens.omitted")
	}
	if usage.CostInUSDTicks != nil {
		appendChatSummary(report, "openai_chat.usage.cost.omitted")
	}
	if usage.NumSourcesUsed != nil {
		appendChatSummary(report, "openai_chat.usage.sources.omitted")
	}
}

// appendChatSummary adds one stable client-safe conversion code at most once.
// appendChatSummary 至多一次添加一个稳定且客户端安全的转换代码。
func appendChatSummary(report *vcp.ExecutionReport, code string) {
	if report == nil || code == "" {
		return
	}
	for _, existing := range report.ConversionSummary {
		if existing == code {
			return
		}
	}
	report.ConversionSummary = append(report.ConversionSummary, code)
}

// assistantToolCalls converts the mutually exclusive current and deprecated Chat tool carriers into one closed function-call sequence.
// assistantToolCalls 将互斥的当前与已废弃 Chat 工具载体转换为一个封闭函数调用序列。
func assistantToolCalls(message *AssistantMessage) ([]ToolCall, error) {
	if message == nil {
		return nil, nil
	}
	if message.FunctionCall != nil && len(message.ToolCalls) > 0 {
		return nil, fmt.Errorf("%w: deprecated function_call and tool_calls cannot coexist", ErrInvalidUpstreamResponse)
	}
	calls := append([]ToolCall(nil), message.ToolCalls...)
	if message.FunctionCall != nil {
		calls = append(calls, ToolCall{Type: "function", Function: *message.FunctionCall})
	}
	for callIndex := range calls {
		if errType := validateChatToolType(calls[callIndex].Type); errType != nil {
			return nil, errType
		}
	}
	return calls, nil
}

// validateChatToolType rejects non-function output calls because this profile only declares and restores function tools.
// validateChatToolType 拒绝非 function 输出调用，因为此 Profile 只声明和恢复 function 工具。
func validateChatToolType(toolType string) error {
	if toolType == "" || toolType == "function" {
		return nil
	}
	return fmt.Errorf("%w: unsupported Chat tool call type %q", ErrInvalidUpstreamResponse, toolType)
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

// terminalForFinishReason maps documented Chat terminal causes without reporting truncation or safety filtering as success.
// terminalForFinishReason 映射文档化 Chat 终态原因，绝不把截断或安全过滤报告为成功。
func terminalForFinishReason(value string) (vcp.EventType, string, string) {
	switch value {
	case "stop", "tool_calls", "function_call":
		return vcp.EventResponseCompleted, safeFinishReason(value), ""
	case "length":
		return vcp.EventResponseIncomplete, "length", ""
	case "content_filter":
		return vcp.EventResponseFailed, "", "openai_chat.content_filter"
	default:
		return vcp.EventResponseFailed, "", "openai_chat.unrecognized_finish_reason"
	}
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
