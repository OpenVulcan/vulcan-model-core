package vcp

import (
	"errors"
	"fmt"
	"sort"
	"time"
)

// EventType identifies one VCP semantic lifecycle event.
// EventType 标识一个 VCP 语义生命周期事件。
type EventType string

const (
	// EventResponseStarted begins one logical response.
	// EventResponseStarted 开始一个逻辑响应。
	EventResponseStarted EventType = "response.started"
	// EventRouteResolved reports a safe immutable route summary.
	// EventRouteResolved 报告安全的不可变路由摘要。
	EventRouteResolved EventType = "route.resolved"
	// EventItemStarted begins one output item.
	// EventItemStarted 开始一个输出项目。
	EventItemStarted EventType = "item.started"
	// EventContentStarted begins one content block.
	// EventContentStarted 开始一个内容块。
	EventContentStarted EventType = "content.started"
	// EventContentDelta appends actual upstream content.
	// EventContentDelta 追加真实上游内容。
	EventContentDelta EventType = "content.delta"
	// EventContentCompleted completes one content block.
	// EventContentCompleted 完成一个内容块。
	EventContentCompleted EventType = "content.completed"
	// EventToolArgumentsDelta appends actual upstream tool argument bytes.
	// EventToolArgumentsDelta 追加真实上游工具参数字节。
	EventToolArgumentsDelta EventType = "tool.arguments.delta"
	// EventToolArgumentsCompleted completes and may hydrate one tool call.
	// EventToolArgumentsCompleted 完成并可水合一个工具调用。
	EventToolArgumentsCompleted EventType = "tool.arguments.completed"
	// EventItemCompleted completes one output item.
	// EventItemCompleted 完成一个输出项目。
	EventItemCompleted EventType = "item.completed"
	// EventUsageUpdated reports a usage observation.
	// EventUsageUpdated 报告一个用量观测。
	EventUsageUpdated EventType = "usage.updated"
	// EventWarningRaised reports safe conversion uncertainty.
	// EventWarningRaised 报告安全的转换不确定性。
	EventWarningRaised EventType = "warning.raised"
	// EventResponseCompleted confirms successful terminal state.
	// EventResponseCompleted 确认成功终态。
	EventResponseCompleted EventType = "response.completed"
	// EventResponseIncomplete reports EOF or an incomplete upstream terminal.
	// EventResponseIncomplete 报告 EOF 或不完整上游终态。
	EventResponseIncomplete EventType = "response.incomplete"
	// EventResponseFailed reports structured failure.
	// EventResponseFailed 报告结构化失败。
	EventResponseFailed EventType = "response.failed"
	// EventResponseCancelled reports cancellation.
	// EventResponseCancelled 报告取消。
	EventResponseCancelled EventType = "response.cancelled"
)

// OutputItemStatus identifies the reducer lifecycle state of one output item.
// OutputItemStatus 标识 reducer 中一个输出项目的生命周期状态。
type OutputItemStatus string

const (
	// OutputItemInProgress is still receiving semantic events.
	// OutputItemInProgress 仍在接收语义事件。
	OutputItemInProgress OutputItemStatus = "in_progress"
	// OutputItemCompleted is immutable and complete.
	// OutputItemCompleted 已不可变且完成。
	OutputItemCompleted OutputItemStatus = "completed"
	// OutputItemIncomplete ended without required completion data.
	// OutputItemIncomplete 在缺少必需完成数据时结束。
	OutputItemIncomplete OutputItemStatus = "incomplete"
)

// OutputItem is one reducer-owned VCP output item.
// OutputItem 是一个 reducer 拥有的 VCP 输出项目。
type OutputItem struct {
	// ItemID is stable across all events.
	// ItemID 在所有事件中保持稳定。
	ItemID string `json:"item_id"`
	// Kind identifies message, tool_call, refusal, or reasoning output.
	// Kind 标识消息、工具调用、拒绝或推理输出。
	Kind ContextKind `json:"kind"`
	// Content contains assembled content blocks.
	// Content 包含归并后的内容块。
	Content []ContentBlock `json:"content,omitempty"`
	// ToolCall contains structured invocation state.
	// ToolCall 包含结构化调用状态。
	ToolCall *ToolCallItem `json:"tool_call,omitempty"`
	// Status records in-progress, completed, or incomplete state.
	// Status 记录进行中、已完成或不完整状态。
	Status OutputItemStatus `json:"status"`
}

// ResponseStatus identifies one logical response terminal state.
// ResponseStatus 标识一个逻辑响应终态。
type ResponseStatus string

const (
	// ResponseInProgress is not terminal.
	// ResponseInProgress 尚未终止。
	ResponseInProgress ResponseStatus = "in_progress"
	// ResponseCompleted is a confirmed successful terminal.
	// ResponseCompleted 是已确认成功终态。
	ResponseCompleted ResponseStatus = "completed"
	// ResponseIncomplete is a confirmed incomplete terminal.
	// ResponseIncomplete 是已确认不完整终态。
	ResponseIncomplete ResponseStatus = "incomplete"
	// ResponseFailed is a confirmed failure terminal.
	// ResponseFailed 是已确认失败终态。
	ResponseFailed ResponseStatus = "failed"
	// ResponseCancelled is a confirmed cancellation terminal.
	// ResponseCancelled 是已确认取消终态。
	ResponseCancelled ResponseStatus = "cancelled"
)

// Event contains one typed semantic transition.
// Event 包含一个类型化语义转换。
type Event struct {
	// ResponseID identifies the logical response.
	// ResponseID 标识逻辑响应。
	ResponseID string `json:"response_id"`
	// EventID is stable for replay and deduplication.
	// EventID 对回放和去重保持稳定。
	EventID string `json:"event_id"`
	// Sequence is globally monotonic within the response.
	// Sequence 在响应内全局单调递增。
	Sequence uint64 `json:"sequence"`
	// Time records the semantic event time.
	// Time 记录语义事件时间。
	Time time.Time `json:"time"`
	// Replayable reports whether the event may be replayed by ID.
	// Replayable 表示事件是否可按 ID 回放。
	Replayable bool `json:"replayable"`
	// Type identifies the semantic transition.
	// Type 标识语义转换。
	Type EventType `json:"type"`
	// ItemID identifies the affected output item.
	// ItemID 标识受影响输出项目。
	ItemID string `json:"item_id,omitempty"`
	// ContentIndex identifies the affected content block.
	// ContentIndex 标识受影响内容块。
	ContentIndex int `json:"content_index,omitempty"`
	// ToolCallID identifies the affected stable VCP tool call.
	// ToolCallID 标识受影响的稳定 VCP 工具调用。
	ToolCallID string `json:"tool_call_id,omitempty"`
	// Item supplies initial item state.
	// Item 提供初始项目状态。
	Item *OutputItem `json:"item,omitempty"`
	// Delta contains actual text or argument bytes.
	// Delta 包含真实文本或参数字节。
	Delta string `json:"delta,omitempty"`
	// ToolName hydrates a delayed tool name at completion.
	// ToolName 在完成时水合延迟工具名称。
	ToolName string `json:"tool_name,omitempty"`
	// UpstreamToolCallID hydrates a delayed upstream call identifier.
	// UpstreamToolCallID 水合延迟上游调用标识。
	UpstreamToolCallID string `json:"upstream_tool_call_id,omitempty"`
	// FinalArguments replaces assembled arguments only when explicitly terminal.
	// FinalArguments 仅在显式终态时替换已归并参数。
	FinalArguments *string `json:"final_arguments,omitempty"`
	// Usage contains a usage-only observation when applicable.
	// Usage 在适用时包含仅用量观测。
	Usage *UsageObservation `json:"usage,omitempty"`
	// FinishReason records the safe upstream finish reason.
	// FinishReason 记录安全的上游结束原因。
	FinishReason string `json:"finish_reason,omitempty"`
	// ErrorCode records a safe structured terminal code.
	// ErrorCode 记录安全的结构化终态代码。
	ErrorCode string `json:"error_code,omitempty"`
	// WarningCode records a safe conversion warning.
	// WarningCode 记录安全的转换警告。
	WarningCode string `json:"warning_code,omitempty"`
}

// Response is the deterministic reduction of one legal event sequence.
// Response 是一个合法事件序列的确定性归并结果。
type Response struct {
	// ResponseID identifies the logical response.
	// ResponseID 标识逻辑响应。
	ResponseID string `json:"response_id"`
	// Status records in-progress or terminal state.
	// Status 记录进行中或终态。
	Status ResponseStatus `json:"status"`
	// Items contains output in first-seen causal order.
	// Items 按首次出现的因果顺序包含输出。
	Items []OutputItem `json:"items,omitempty"`
	// Usage contains the latest valid observation.
	// Usage 包含最新有效观测。
	Usage *UsageObservation `json:"usage,omitempty"`
	// FinishReason records the safe upstream finish reason.
	// FinishReason 记录安全的上游结束原因。
	FinishReason string `json:"finish_reason,omitempty"`
	// ErrorCode records a safe terminal failure code.
	// ErrorCode 记录安全终态失败代码。
	ErrorCode string `json:"error_code,omitempty"`
	// Warnings contains stable safe warning codes.
	// Warnings 包含稳定安全警告代码。
	Warnings []string `json:"warnings,omitempty"`
}

// Reducer deterministically reduces validated VCP semantic events.
// Reducer 确定性归并经过校验的 VCP 语义事件。
type Reducer struct {
	// response stores the current deterministic aggregate.
	// response 存储当前确定性聚合结果。
	response Response
	// lastSequence enforces global event monotonicity.
	// lastSequence 强制事件全局单调。
	lastSequence uint64
	// seenEvents deduplicates exact replay events.
	// seenEvents 对精确回放事件去重。
	seenEvents map[string]struct{}
	// itemIndexes maps stable item IDs to response positions.
	// itemIndexes 将稳定项目 ID 映射到响应位置。
	itemIndexes map[string]int
}

// NewReducer creates an empty deterministic reducer.
// NewReducer 创建一个空的确定性 reducer。
func NewReducer(responseID string) *Reducer {
	return &Reducer{response: Response{ResponseID: responseID, Status: ResponseInProgress}, seenEvents: make(map[string]struct{}), itemIndexes: make(map[string]int)}
}

// Apply validates and applies one semantic event.
// Apply 校验并应用一个语义事件。
func (r *Reducer) Apply(event Event) error {
	if event.ResponseID != r.response.ResponseID || event.EventID == "" || event.Sequence == 0 {
		return errors.New("invalid semantic event identity")
	}
	if _, duplicate := r.seenEvents[event.EventID]; duplicate {
		return nil
	}
	if event.Sequence <= r.lastSequence {
		return fmt.Errorf("event sequence %d is not globally monotonic", event.Sequence)
	}
	if r.response.Status != ResponseInProgress {
		return nil
	}
	switch event.Type {
	case EventResponseStarted, EventRouteResolved, EventContentStarted, EventContentCompleted:
	case EventItemStarted:
		if event.Item == nil || event.Item.ItemID == "" || event.Item.ItemID != event.ItemID {
			return errors.New("item.started requires a matching item")
		}
		if _, exists := r.itemIndexes[event.ItemID]; !exists {
			item := cloneOutputItem(*event.Item)
			item.Status = OutputItemInProgress
			r.itemIndexes[item.ItemID] = len(r.response.Items)
			r.response.Items = append(r.response.Items, item)
		}
	case EventContentDelta:
		item, errItem := r.mutableItem(event.ItemID)
		if errItem != nil {
			return errItem
		}
		for len(item.Content) <= event.ContentIndex {
			item.Content = append(item.Content, ContentBlock{Type: ContentText})
		}
		item.Content[event.ContentIndex].Text += event.Delta
	case EventToolArgumentsDelta:
		item, errItem := r.mutableToolItem(event.ItemID)
		if errItem != nil {
			return errItem
		}
		item.ToolCall.Arguments += event.Delta
	case EventToolArgumentsCompleted:
		item, errItem := r.mutableToolItem(event.ItemID)
		if errItem != nil {
			return errItem
		}
		if event.ToolName != "" {
			item.ToolCall.Name = event.ToolName
		}
		if event.UpstreamToolCallID != "" {
			item.ToolCall.UpstreamID = event.UpstreamToolCallID
		}
		if event.FinalArguments != nil {
			item.ToolCall.Arguments = *event.FinalArguments
		}
		if item.ToolCall.Name == "" {
			item.ToolCall.Status = ToolCallIncomplete
		} else {
			item.ToolCall.Status = ToolCallCompleted
		}
	case EventItemCompleted:
		item, errItem := r.mutableItem(event.ItemID)
		if errItem != nil {
			return errItem
		}
		if item.Status != OutputItemCompleted {
			item.Status = OutputItemCompleted
		}
	case EventUsageUpdated:
		if event.Usage == nil {
			return errors.New("usage.updated requires usage")
		}
		usage := *event.Usage
		r.response.Usage = &usage
	case EventWarningRaised:
		if event.WarningCode != "" {
			r.response.Warnings = append(r.response.Warnings, event.WarningCode)
		}
	case EventResponseCompleted:
		r.response.Status = ResponseCompleted
		r.response.FinishReason = event.FinishReason
	case EventResponseIncomplete:
		r.markOpenItemsIncomplete()
		r.response.Status = ResponseIncomplete
		r.response.FinishReason = event.FinishReason
	case EventResponseFailed:
		r.markOpenItemsIncomplete()
		r.response.Status = ResponseFailed
		r.response.ErrorCode = event.ErrorCode
	case EventResponseCancelled:
		r.markOpenItemsIncomplete()
		r.response.Status = ResponseCancelled
	default:
		return fmt.Errorf("unknown semantic event type %q", event.Type)
	}
	r.seenEvents[event.EventID] = struct{}{}
	r.lastSequence = event.Sequence
	return nil
}

// Snapshot returns an isolated deterministic response value.
// Snapshot 返回隔离的确定性响应值。
func (r *Reducer) Snapshot() Response {
	response := r.response
	response.Items = make([]OutputItem, len(r.response.Items))
	for index := range r.response.Items {
		response.Items[index] = cloneOutputItem(r.response.Items[index])
	}
	response.Warnings = append([]string(nil), r.response.Warnings...)
	response.Usage = cloneUsageObservation(r.response.Usage)
	return response
}

// cloneOutputItem returns a deep copy of reducer-owned output state.
// cloneOutputItem 返回 reducer 所有输出状态的深拷贝。
func cloneOutputItem(source OutputItem) OutputItem {
	cloned := source
	cloned.Content = append([]ContentBlock(nil), source.Content...)
	for index := range cloned.Content {
		cloned.Content[index].Extension = append([]byte(nil), source.Content[index].Extension...)
	}
	if source.ToolCall != nil {
		toolCall := *source.ToolCall
		cloned.ToolCall = &toolCall
	}
	return cloned
}

// cloneUsageObservation returns a deep copy of optional token observations.
// cloneUsageObservation 返回可选 Token 观测值的深拷贝。
func cloneUsageObservation(source *UsageObservation) *UsageObservation {
	if source == nil {
		return nil
	}
	cloned := *source
	cloned.InputTokens = cloneInt64Pointer(source.InputTokens)
	cloned.OutputTokens = cloneInt64Pointer(source.OutputTokens)
	cloned.ReasoningTokens = cloneInt64Pointer(source.ReasoningTokens)
	cloned.CacheReadTokens = cloneInt64Pointer(source.CacheReadTokens)
	cloned.CacheCreationTokens = cloneInt64Pointer(source.CacheCreationTokens)
	cloned.TotalTokens = cloneInt64Pointer(source.TotalTokens)
	return &cloned
}

// cloneInt64Pointer returns an independent optional integer.
// cloneInt64Pointer 返回独立的可选整数。
func cloneInt64Pointer(source *int64) *int64 {
	if source == nil {
		return nil
	}
	cloned := *source
	return &cloned
}

// Terminal reports whether a confirmed response terminal has been reduced.
// Terminal 报告是否已归并确认的响应终态。
func (r *Reducer) Terminal() bool {
	return r.response.Status != ResponseInProgress
}

// mutableItem returns the exact reducer-owned item.
// mutableItem 返回精确的 reducer 所有项目。
func (r *Reducer) mutableItem(itemID string) (*OutputItem, error) {
	index, exists := r.itemIndexes[itemID]
	if !exists {
		return nil, fmt.Errorf("item %q has not started", itemID)
	}
	return &r.response.Items[index], nil
}

// mutableToolItem returns an exact structured tool call item.
// mutableToolItem 返回精确的结构化工具调用项目。
func (r *Reducer) mutableToolItem(itemID string) (*OutputItem, error) {
	item, errItem := r.mutableItem(itemID)
	if errItem != nil {
		return nil, errItem
	}
	if item.ToolCall == nil {
		return nil, fmt.Errorf("item %q is not a tool call", itemID)
	}
	return item, nil
}

// markOpenItemsIncomplete closes every non-terminal item without inventing data.
// markOpenItemsIncomplete 在不虚构数据的情况下关闭所有未终止项目。
func (r *Reducer) markOpenItemsIncomplete() {
	for index := range r.response.Items {
		if r.response.Items[index].Status != OutputItemCompleted {
			r.response.Items[index].Status = OutputItemIncomplete
			if r.response.Items[index].ToolCall != nil && r.response.Items[index].ToolCall.Status != ToolCallCompleted {
				r.response.Items[index].ToolCall.Status = ToolCallIncomplete
			}
		}
	}
	sort.Strings(r.response.Warnings)
}
