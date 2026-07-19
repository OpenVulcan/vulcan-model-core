// Portions of this stream decoder are adapted from CLIProxyAPI commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// 本流式解码器的部分逻辑改编自 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66。
// Source path: internal/translator/gemini/claude/gemini_claude_response.go.
// 来源路径：internal/translator/gemini/claude/gemini_claude_response.go。
// The adapted scope is Gemini name-less function argument continuation and terminal usage ordering; VCP owns event semantics.
// 改编范围为 Gemini 无名称函数参数续接和终态用量顺序；VCP 拥有事件语义。
package aistudio

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// StreamDecoder converts typed Gemini response snapshots into one deterministic VCP replay log.
// StreamDecoder 将类型化 Gemini 响应快照转换为一个确定性 VCP 回放日志。
type StreamDecoder struct {
	// emitter assigns monotonic replay identities to every semantic event.
	// emitter 为每个语义事件分配单调回放身份。
	emitter *eventEmitter
	// reducer owns the deterministic VCP response aggregate.
	// reducer 拥有确定性 VCP 响应聚合。
	reducer *vcp.Reducer
	// items stores active output state by one internally stable semantic key.
	// items 按内部稳定语义键存储活跃输出状态。
	items map[string]*streamItem
	// itemOrder preserves first-seen provider output order independently of map iteration.
	// itemOrder 独立于 map 遍历保留 Provider 输出首次出现顺序。
	itemOrder []string
	// lastToolByCandidate records the exact tool that may accept a name-less argument fragment.
	// lastToolByCandidate 记录可接受无名称参数分片的精确工具。
	lastToolByCandidate map[int]string
	// referencesByWire restores only request-declared wire function names.
	// referencesByWire 仅恢复请求已声明的 wire 函数名称。
	referencesByWire map[string]ToolReference
	// allEvents retains the isolated deterministic replay sequence.
	// allEvents 保留隔离的确定性回放序列。
	allEvents []vcp.Event
	// report contains safe upstream conversion observations.
	// report 包含安全的上游转换观测。
	report vcp.ExecutionReport
	// upstreamResponseID stores the latest provider response identifier.
	// upstreamResponseID 存储最新 Provider 响应标识。
	upstreamResponseID string
	// nextToolOrdinal prevents repeated same-part function calls from sharing one synthetic VCP ID.
	// nextToolOrdinal 防止重复的同部分函数调用共享一个合成 VCP ID。
	nextToolOrdinal int
}

// streamItem is one active semantic output carrier awaiting a terminal event.
// streamItem 是一个等待终态事件的活跃语义输出载体。
type streamItem struct {
	// key is the decoder-owned stable identity for this semantic output.
	// key 是此语义输出的 Decoder 所有稳定身份。
	key string
	// itemID is the stable VCP output item identifier.
	// itemID 是稳定 VCP 输出项目标识。
	itemID string
	// kind identifies text, reasoning, tool call, or refusal semantics.
	// kind 标识文本、推理、工具调用或拒绝语义。
	kind vcp.ContextKind
	// toolName is set only for function-call items.
	// toolName 仅为函数调用项目设置。
	toolName string
	// upstreamToolCallID is set only when the provider supplies a correlated call ID.
	// upstreamToolCallID 仅在 Provider 提供关联调用 ID 时设置。
	upstreamToolCallID string
	// arguments preserves exact upstream argument bytes or documented fragments.
	// arguments 保留精确上游参数字节或文档化分片。
	arguments string
	// completed prevents duplicate VCP completion transitions.
	// completed 防止重复的 VCP 完成转换。
	completed bool
}

// eventEmitter creates safe monotonic VCP event identities for one response.
// eventEmitter 为一个响应创建安全且单调的 VCP 事件身份。
type eventEmitter struct {
	// responseID identifies every event emitted by this decoder.
	// responseID 标识此 Decoder 发出的每个事件。
	responseID string
	// now fixes semantic event time for deterministic profile tests.
	// now 为确定性 Profile 测试固定语义事件时间。
	now time.Time
	// sequence is incremented before every emitted event.
	// sequence 在每个事件发出前递增。
	sequence uint64
}

// NewStreamDecoder creates one AI Studio decoder bound to request-declared tool identities.
// NewStreamDecoder 创建一个绑定到请求已声明工具身份的 AI Studio Decoder。
func NewStreamDecoder(responseID string, now time.Time, references []ToolReference) (*StreamDecoder, error) {
	if strings.TrimSpace(responseID) == "" {
		return nil, fmt.Errorf("%w: response_id is required", ErrInvalidUpstreamResponse)
	}
	// referencesByWire validates that output restoration cannot be ambiguous before parsing provider bytes.
	// referencesByWire 在解析 Provider 字节前校验输出恢复不会产生歧义。
	referencesByWire := make(map[string]ToolReference, len(references))
	for _, reference := range references {
		if reference.WireName == "" || reference.Name == "" {
			return nil, fmt.Errorf("%w: invalid tool reference", ErrInvalidUpstreamResponse)
		}
		if _, exists := referencesByWire[reference.WireName]; exists {
			return nil, fmt.Errorf("%w: duplicate tool wire name %q", ErrInvalidUpstreamResponse, reference.WireName)
		}
		referencesByWire[reference.WireName] = reference
	}
	decoder := &StreamDecoder{
		emitter:             &eventEmitter{responseID: responseID, now: now},
		reducer:             vcp.NewReducer(responseID),
		items:               make(map[string]*streamItem),
		lastToolByCandidate: make(map[int]string),
		referencesByWire:    referencesByWire,
		report:              vcp.ExecutionReport{ResponseID: responseID},
	}
	if errEmit := decoder.emit(decoder.emitter.event(vcp.EventResponseStarted)); errEmit != nil {
		return nil, errEmit
	}
	return decoder, nil
}

// event constructs the next deterministic event of one requested type.
// event 构造指定类型的下一个确定性事件。
func (e *eventEmitter) event(eventType vcp.EventType) vcp.Event {
	e.sequence++
	sequenceText := strconv.FormatUint(e.sequence, 10)
	return vcp.Event{ResponseID: e.responseID, EventID: vcp.DeriveID("evt", e.responseID, sequenceText), Sequence: e.sequence, Time: e.now, Replayable: true, Type: eventType}
}

// itemEvent constructs the next deterministic event for one output item.
// itemEvent 为一个输出项目构造下一个确定性事件。
func (e *eventEmitter) itemEvent(eventType vcp.EventType, itemID string) vcp.Event {
	event := e.event(eventType)
	event.ItemID = itemID
	return event
}

// PushSSE decodes one SSE envelope and applies its typed Gemini response snapshot.
// PushSSE 解码一个 SSE 信封并应用其类型化 Gemini 响应快照。
func (d *StreamDecoder) PushSSE(envelope SSEEnvelope) ([]vcp.Event, error) {
	if d == nil {
		return nil, fmt.Errorf("%w: decoder is required", ErrInvalidUpstreamResponse)
	}
	start := len(d.allEvents)
	data := strings.TrimSpace(string(envelope.Data))
	if data == "" {
		return nil, nil
	}
	if data == "[DONE]" {
		if _, errClose := d.Close(nil); errClose != nil {
			return nil, errClose
		}
		return d.eventsFrom(start), nil
	}
	if envelope.Event == "error" {
		if errTerminal := d.terminateFailed("google_aistudio.sse_error"); errTerminal != nil {
			return nil, errTerminal
		}
		return d.eventsFrom(start), nil
	}
	var response GenerateContentResponse
	if errDecode := json.Unmarshal([]byte(data), &response); errDecode != nil {
		return nil, fmt.Errorf("%w: decode SSE data: %v", ErrInvalidUpstreamResponse, errDecode)
	}
	if _, errPush := d.Push(response); errPush != nil {
		return nil, errPush
	}
	return d.eventsFrom(start), nil
}

// Push applies one typed Gemini response chunk or full non-stream response.
// Push 应用一个类型化 Gemini 响应分片或完整非流响应。
func (d *StreamDecoder) Push(response GenerateContentResponse) ([]vcp.Event, error) {
	if d == nil || d.reducer == nil || d.emitter == nil {
		return nil, fmt.Errorf("%w: decoder is required", ErrInvalidUpstreamResponse)
	}
	if d.reducer.Terminal() {
		return nil, nil
	}
	start := len(d.allEvents)
	if response.ResponseID != "" {
		d.upstreamResponseID = response.ResponseID
		d.report.ExecutionID = vcp.DeriveID("exec", d.emitter.responseID, response.ResponseID)
	}
	d.reportUnrepresentedResponseMetadata(response)
	if response.PromptFeedback != nil && len(response.PromptFeedback.SafetyRatings) > 0 {
		d.report.ConversionSummary = appendSafeSummary(d.report.ConversionSummary, "google_aistudio.prompt_safety_ratings.omitted")
	}
	d.reportUnrepresentedUsageMetadata(response.UsageMetadata)
	if response.PromptFeedback != nil && response.PromptFeedback.BlockReason != "" {
		if errUsage := d.emitUsage(response.UsageMetadata, "terminal", true); errUsage != nil {
			return nil, errUsage
		}
		// blockCode retains the documented safe block category without exposing provider diagnostic text.
		// blockCode 保留文档化的安全阻断类别，且不暴露 Provider 诊断文本。
		blockCode := promptBlockCode(response.PromptFeedback.BlockReason)
		if errRefusal := d.emitRefusal(blockCode); errRefusal != nil {
			return nil, errRefusal
		}
		if errTerminal := d.terminateFailed(blockCode); errTerminal != nil {
			return nil, errTerminal
		}
		return d.eventsFrom(start), nil
	}
	if len(response.Candidates) > 1 {
		d.report.ConversionSummary = appendSafeSummary(d.report.ConversionSummary, "google_aistudio.multiple_candidates.emitted_in_order")
	}
	// firstFinish carries only candidates[0].finishReason because the source protocol behavior defines terminal semantics from the first candidate.
	// firstFinish 仅携带 candidates[0].finishReason，因为来源协议行为从第一个候选定义终态语义。
	firstFinish := ""
	for candidatePosition, candidate := range response.Candidates {
		candidateIndex := candidatePosition
		if candidate.Index != nil {
			candidateIndex = *candidate.Index
		}
		if len(candidate.SafetyRatings) > 0 {
			d.report.ConversionSummary = appendSafeSummary(d.report.ConversionSummary, "google_aistudio.candidate_safety_ratings.omitted")
		}
		d.reportUnrepresentedCandidateMetadata(candidate)
		if candidate.Content != nil {
			// Candidate content is model-generated output, so a user role would falsely elevate upstream input into VCP output.
			// Candidate 内容属于模型生成输出，因此 user 角色会把上游输入错误提升为 VCP 输出。
			if candidate.Content.Role != "" && candidate.Content.Role != "model" {
				return nil, fmt.Errorf("%w: candidate content role %q is not model output", ErrInvalidUpstreamResponse, candidate.Content.Role)
			}
			for partIndex, part := range candidate.Content.Parts {
				if errPart := d.pushPart(candidateIndex, partIndex, part); errPart != nil {
					return nil, errPart
				}
			}
		}
		if candidatePosition == 0 && candidate.FinishReason != "" {
			firstFinish = candidate.FinishReason
		}
	}
	usagePhase := "streaming"
	usageFinal := false
	if firstFinish != "" {
		usagePhase = "terminal"
		usageFinal = true
	}
	if errUsage := d.emitUsage(response.UsageMetadata, usagePhase, usageFinal); errUsage != nil {
		return nil, errUsage
	}
	if firstFinish != "" {
		if errTerminal := d.terminateForFinishReason(firstFinish); errTerminal != nil {
			return nil, errTerminal
		}
	}
	return d.eventsFrom(start), nil
}

// reportUnrepresentedResponseMetadata records documented response metadata that cannot be carried by the immutable VCP route or output model.
// reportUnrepresentedResponseMetadata 记录无法由不可变 VCP 路由或输出模型承载的文档化响应元数据。
func (d *StreamDecoder) reportUnrepresentedResponseMetadata(response GenerateContentResponse) {
	if d == nil {
		return
	}
	if response.ModelVersion != "" {
		d.report.ConversionSummary = appendSafeSummary(d.report.ConversionSummary, "google_aistudio.model_version.omitted")
	}
	if response.ModelStatus != nil {
		d.report.ConversionSummary = appendSafeSummary(d.report.ConversionSummary, "google_aistudio.model_status.omitted")
	}
}

// reportUnrepresentedCandidateMetadata records documented candidate metadata that has no lossless first-phase VCP carrier without exposing its contents.
// reportUnrepresentedCandidateMetadata 在不暴露内容的前提下记录没有无损第一阶段 VCP 承载字段的文档化 Candidate 元数据。
func (d *StreamDecoder) reportUnrepresentedCandidateMetadata(candidate Candidate) {
	if d == nil || !candidate.hasUnrepresentedMetadata() {
		return
	}
	if candidate.CitationMetadata != nil {
		d.report.ConversionSummary = appendSafeSummary(d.report.ConversionSummary, "google_aistudio.candidate_citation_metadata.omitted")
	}
	if candidate.TokenCount != nil {
		d.report.ConversionSummary = appendSafeSummary(d.report.ConversionSummary, "google_aistudio.candidate_token_count.omitted")
	}
	if len(candidate.GroundingAttributions) > 0 || candidate.GroundingMetadata != nil {
		d.report.ConversionSummary = appendSafeSummary(d.report.ConversionSummary, "google_aistudio.candidate_grounding_metadata.omitted")
	}
	if candidate.AvgLogprobs != nil || candidate.LogprobsResult != nil {
		d.report.ConversionSummary = appendSafeSummary(d.report.ConversionSummary, "google_aistudio.candidate_logprobs.omitted")
	}
	if candidate.URLContextMetadata != nil {
		d.report.ConversionSummary = appendSafeSummary(d.report.ConversionSummary, "google_aistudio.candidate_url_context_metadata.omitted")
	}
	if candidate.FinishMessage != "" {
		d.report.ConversionSummary = appendSafeSummary(d.report.ConversionSummary, "google_aistudio.candidate_finish_message.omitted")
	}
	if candidate.unrecognized {
		d.report.ConversionSummary = appendSafeSummary(d.report.ConversionSummary, "google_aistudio.candidate_future_metadata.omitted")
	}
}

// reportUnrepresentedUsageMetadata records every documented usage field that has no lossless first-phase VCP accounting carrier.
// reportUnrepresentedUsageMetadata 记录每个没有无损第一阶段 VCP 计量承载字段的文档化用量字段。
func (d *StreamDecoder) reportUnrepresentedUsageMetadata(source *UsageMetadata) {
	if d == nil || source == nil {
		return
	}
	if source.ToolUsePromptTokenCount != nil {
		d.report.ConversionSummary = appendSafeSummary(d.report.ConversionSummary, "google_aistudio.usage.tool_use_prompt_tokens.omitted")
	}
	if len(source.PromptTokensDetails) > 0 || len(source.CacheTokensDetails) > 0 || len(source.CandidatesTokensDetails) > 0 || len(source.ToolUsePromptTokensDetails) > 0 {
		d.report.ConversionSummary = appendSafeSummary(d.report.ConversionSummary, "google_aistudio.usage.modality_details.omitted")
	}
	if source.ServiceTier != "" {
		d.report.ConversionSummary = appendSafeSummary(d.report.ConversionSummary, "google_aistudio.usage.service_tier.omitted")
	}
}

// Close emits a safe terminal only when upstream did not confirm one.
// Close 仅在上游未确认终态时发出安全终态。
func (d *StreamDecoder) Close(transportErr error) ([]vcp.Event, error) {
	if d == nil || d.reducer == nil || d.reducer.Terminal() {
		return nil, nil
	}
	start := len(d.allEvents)
	terminal := d.emitter.event(vcp.EventResponseIncomplete)
	if transportErr == nil {
		terminal.FinishReason = "eof_without_finish_reason"
	} else if errors.Is(transportErr, context.Canceled) {
		terminal = d.emitter.event(vcp.EventResponseCancelled)
	} else {
		terminal = d.emitter.event(vcp.EventResponseFailed)
		terminal.ErrorCode = "google_aistudio.transport"
		d.report.ErrorOrRetryAdvice = terminal.ErrorCode
	}
	if errEmit := d.emit(terminal); errEmit != nil {
		return nil, errEmit
	}
	return d.eventsFrom(start), nil
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
// Events 返回一个不能修改 Decoder 所有状态的隔离回放日志。
func (d *StreamDecoder) Events() []vcp.Event {
	if d == nil {
		return nil
	}
	return d.eventsFrom(0)
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
	report.Usage = cloneUsageObservation(d.report.Usage)
	return report
}

// UpstreamResponseID returns the provider response identifier for Router-owned persistence.
// UpstreamResponseID 返回供 Router 所有持久化使用的 Provider 响应标识。
func (d *StreamDecoder) UpstreamResponseID() string {
	if d == nil {
		return ""
	}
	return d.upstreamResponseID
}

// pushPart maps exactly one Gemini response part without treating provider reasoning as normal text.
// pushPart 映射精确的一条 Gemini 响应部分，且不将 Provider 推理视为普通文本。
func (d *StreamDecoder) pushPart(candidateIndex int, partIndex int, part Part) error {
	if part.hasUnsupportedPayload() {
		return fmt.Errorf("%w: candidate contains a part outside the first-phase text-and-function profile", ErrInvalidUpstreamResponse)
	}
	if part.hasEmptyPayload() {
		return fmt.Errorf("%w: candidate contains an empty part", ErrInvalidUpstreamResponse)
	}
	if part.ThoughtSignature != "" {
		d.report.ConversionSummary = appendSafeSummary(d.report.ConversionSummary, "google_aistudio.thought_signature.provider_state_unavailable")
	}
	// functionResponse is valid only in caller-supplied user history, never in a model candidate.
	// functionResponse 仅能出现在调用方提供的 user 历史中，绝不能出现在模型候选中。
	if part.FunctionResponse != nil {
		return fmt.Errorf("%w: model candidate cannot contain functionResponse", ErrInvalidUpstreamResponse)
	}
	if part.FunctionCall != nil && part.Text != "" {
		return fmt.Errorf("%w: a Gemini part cannot contain both visible text and functionCall", ErrInvalidUpstreamResponse)
	}
	if part.FunctionCall != nil {
		return d.pushFunctionCall(candidateIndex, partIndex, *part.FunctionCall)
	}
	if part.Text == "" {
		return nil
	}
	kind := vcp.ContextMessage
	if part.Thought {
		kind = vcp.ContextReasoning
	}
	item, errItem := d.ensureTextItem(candidateIndex, partIndex, kind)
	if errItem != nil {
		return errItem
	}
	event := d.emitter.itemEvent(vcp.EventContentDelta, item.itemID)
	event.ContentIndex = 0
	event.Delta = part.Text
	return d.emit(event)
}

// pushFunctionCall adapts the source-evidenced named call and name-less argument continuation behavior.
// pushFunctionCall 改编来源有证据的具名调用和无名称参数续接行为。
func (d *StreamDecoder) pushFunctionCall(candidateIndex int, partIndex int, call FunctionCall) error {
	arguments := string(call.Args)
	if call.Name == "" {
		toolKey, exists := d.lastToolByCandidate[candidateIndex]
		if !exists {
			return fmt.Errorf("%w: function argument continuation has no preceding named call", ErrInvalidUpstreamResponse)
		}
		item, exists := d.items[toolKey]
		if !exists || item.completed || item.kind != vcp.ContextToolCall {
			return fmt.Errorf("%w: function argument continuation references no active tool", ErrInvalidUpstreamResponse)
		}
		if arguments == "" {
			return fmt.Errorf("%w: function argument continuation is empty", ErrInvalidUpstreamResponse)
		}
		if call.ID != "" {
			item.upstreamToolCallID = call.ID
		}
		item.arguments += arguments
		event := d.emitter.itemEvent(vcp.EventToolArgumentsDelta, item.itemID)
		event.ToolCallID = item.itemID
		event.Delta = arguments
		return d.emit(event)
	}
	reference, exists := d.referencesByWire[call.Name]
	if !exists {
		return fmt.Errorf("%w: upstream function name %q was not declared by this request", ErrInvalidUpstreamResponse, call.Name)
	}
	if priorKey, exists := d.lastToolByCandidate[candidateIndex]; exists {
		if prior, known := d.items[priorKey]; known && !prior.completed {
			if errComplete := d.completeItem(prior); errComplete != nil {
				return errComplete
			}
		}
	}
	if arguments != "" && !isJSONObject(arguments) {
		return fmt.Errorf("%w: function call %q arguments must be a JSON object", ErrInvalidUpstreamResponse, call.Name)
	}
	ordinal := d.nextToolOrdinal
	d.nextToolOrdinal++
	key := "tool:" + strconv.Itoa(candidateIndex) + ":" + strconv.Itoa(partIndex) + ":" + strconv.Itoa(ordinal)
	itemID := vcp.DeriveID("tool", d.emitter.responseID, strconv.Itoa(candidateIndex), strconv.Itoa(partIndex), strconv.Itoa(ordinal), call.Name, call.ID)
	item := &streamItem{key: key, itemID: itemID, kind: vcp.ContextToolCall, toolName: reference.Name, upstreamToolCallID: call.ID, arguments: arguments}
	// outputToolCall keeps namespace and name separate in the VCP item instead of relying on a flattened tool name.
	// outputToolCall 在 VCP 项目中分离命名空间和名称，而不是依赖扁平化工具名称。
	outputToolCall := &vcp.ToolCallItem{ToolCallID: itemID, UpstreamID: call.ID, Namespace: reference.Namespace, Name: reference.Name, Status: vcp.ToolCallPending}
	start := d.emitter.itemEvent(vcp.EventItemStarted, itemID)
	start.Item = &vcp.OutputItem{ItemID: itemID, Kind: vcp.ContextToolCall, ToolCall: outputToolCall, Status: vcp.OutputItemInProgress}
	if errEmit := d.emit(start); errEmit != nil {
		return errEmit
	}
	d.items[key] = item
	d.itemOrder = append(d.itemOrder, key)
	d.lastToolByCandidate[candidateIndex] = key
	if arguments == "" {
		return nil
	}
	delta := d.emitter.itemEvent(vcp.EventToolArgumentsDelta, itemID)
	delta.ToolCallID = itemID
	delta.Delta = arguments
	return d.emit(delta)
}

// ensureTextItem starts one content carrier the first time a candidate part becomes observable.
// ensureTextItem 在候选部分首次可观察时启动一个内容载体。
func (d *StreamDecoder) ensureTextItem(candidateIndex int, partIndex int, kind vcp.ContextKind) (*streamItem, error) {
	key := "content:" + strconv.Itoa(candidateIndex) + ":" + strconv.Itoa(partIndex) + ":" + string(kind)
	if existing, exists := d.items[key]; exists {
		return existing, nil
	}
	itemID := vcp.DeriveID("out", d.emitter.responseID, key)
	item := &streamItem{key: key, itemID: itemID, kind: kind}
	start := d.emitter.itemEvent(vcp.EventItemStarted, itemID)
	start.Item = &vcp.OutputItem{ItemID: itemID, Kind: kind, Content: []vcp.ContentBlock{{Type: vcp.ContentText}}, Status: vcp.OutputItemInProgress}
	if errEmit := d.emit(start); errEmit != nil {
		return nil, errEmit
	}
	contentStart := d.emitter.itemEvent(vcp.EventContentStarted, itemID)
	contentStart.ContentIndex = 0
	if errEmit := d.emit(contentStart); errEmit != nil {
		return nil, errEmit
	}
	d.items[key] = item
	d.itemOrder = append(d.itemOrder, key)
	return item, nil
}

// emitRefusal emits a typed refusal output item with only a stable safe reason code.
// emitRefusal 使用仅包含稳定安全原因代码的类型化拒绝输出项目。
func (d *StreamDecoder) emitRefusal(code string) error {
	key := "refusal:" + code
	if _, exists := d.items[key]; exists {
		return nil
	}
	itemID := vcp.DeriveID("out", d.emitter.responseID, key)
	item := &streamItem{key: key, itemID: itemID, kind: vcp.ContextRefusal}
	start := d.emitter.itemEvent(vcp.EventItemStarted, itemID)
	start.Item = &vcp.OutputItem{ItemID: itemID, Kind: vcp.ContextRefusal, Content: []vcp.ContentBlock{{Type: vcp.ContentRefusal}}, Status: vcp.OutputItemInProgress}
	if errEmit := d.emit(start); errEmit != nil {
		return errEmit
	}
	d.items[key] = item
	d.itemOrder = append(d.itemOrder, key)
	return d.completeItem(item)
}

// completeAllItems completes every open semantic item in first-seen causal order.
// completeAllItems 按首次出现的因果顺序完成每个开放语义项目。
func (d *StreamDecoder) completeAllItems() error {
	for _, key := range d.itemOrder {
		item := d.items[key]
		if item == nil || item.completed {
			continue
		}
		if errComplete := d.completeItem(item); errComplete != nil {
			return errComplete
		}
	}
	return nil
}

// completeItem emits the exact final events required by one semantic output kind.
// completeItem 为一个语义输出种类发出精确所需的最终事件。
func (d *StreamDecoder) completeItem(item *streamItem) error {
	if item == nil || item.completed {
		return nil
	}
	if item.kind == vcp.ContextToolCall {
		// finalArguments supplies the documented empty-object default only after all name-less fragments have had a chance to arrive.
		// finalArguments 仅在所有无名称分片都有机会到达后才提供文档化的空对象默认值。
		finalArguments := item.arguments
		if finalArguments == "" {
			finalArguments = "{}"
		}
		if !isJSONObject(finalArguments) {
			return fmt.Errorf("%w: completed function call %q has non-object assembled arguments", ErrInvalidUpstreamResponse, item.toolName)
		}
		item.arguments = finalArguments
		argumentsCompleted := d.emitter.itemEvent(vcp.EventToolArgumentsCompleted, item.itemID)
		argumentsCompleted.ToolCallID = item.itemID
		argumentsCompleted.ToolName = item.toolName
		argumentsCompleted.UpstreamToolCallID = item.upstreamToolCallID
		argumentsCompleted.FinalArguments = &finalArguments
		if errEmit := d.emit(argumentsCompleted); errEmit != nil {
			return errEmit
		}
	} else if item.kind == vcp.ContextMessage || item.kind == vcp.ContextReasoning {
		contentCompleted := d.emitter.itemEvent(vcp.EventContentCompleted, item.itemID)
		contentCompleted.ContentIndex = 0
		if errEmit := d.emit(contentCompleted); errEmit != nil {
			return errEmit
		}
	}
	completed := d.emitter.itemEvent(vcp.EventItemCompleted, item.itemID)
	if errEmit := d.emit(completed); errEmit != nil {
		return errEmit
	}
	item.completed = true
	return nil
}

// terminateForFinishReason converts documented Gemini terminal reasons to explicit VCP terminal semantics.
// terminateForFinishReason 将文档化 Gemini 终止原因转换为显式 VCP 终态语义。
func (d *StreamDecoder) terminateForFinishReason(finishReason string) error {
	switch finishReason {
	case "STOP":
		return d.terminate(vcp.EventResponseCompleted, "stop", "")
	case "MAX_TOKENS":
		return d.terminate(vcp.EventResponseIncomplete, "max_tokens", "")
	case "SAFETY", "RECITATION", "LANGUAGE", "BLOCKLIST", "PROHIBITED_CONTENT", "SPII", "IMAGE_SAFETY", "IMAGE_PROHIBITED_CONTENT", "IMAGE_RECITATION":
		if errRefusal := d.emitRefusal("google_aistudio.candidate_blocked"); errRefusal != nil {
			return errRefusal
		}
		return d.terminateFailed("google_aistudio.candidate_blocked")
	case "IMAGE_OTHER":
		return d.terminateFailed("google_aistudio.image_other")
	case "NO_IMAGE":
		return d.terminateFailed("google_aistudio.no_image")
	case "MALFORMED_FUNCTION_CALL":
		return d.terminateFailed("google_aistudio.malformed_function_call")
	case "UNEXPECTED_TOOL_CALL":
		return d.terminateFailed("google_aistudio.unexpected_tool_call")
	case "TOO_MANY_TOOL_CALLS":
		return d.terminateFailed("google_aistudio.too_many_tool_calls")
	case "MISSING_THOUGHT_SIGNATURE":
		return d.terminateFailed("google_aistudio.missing_thought_signature")
	case "MALFORMED_RESPONSE":
		return d.terminateFailed("google_aistudio.malformed_response")
	case "OTHER", "FINISH_REASON_UNSPECIFIED":
		return d.terminateFailed("google_aistudio.unknown_finish_reason")
	default:
		return d.terminateFailed("google_aistudio.unrecognized_finish_reason")
	}
}

// terminateFailed emits one safe explicit failed terminal without exposing untrusted provider text.
// terminateFailed 发出一个安全明确的失败终态，且不暴露不可信 Provider 文本。
func (d *StreamDecoder) terminateFailed(code string) error {
	return d.terminate(vcp.EventResponseFailed, "", code)
}

// promptBlockCode maps documented Gemini prompt block enums to safe stable VCP diagnostics.
// promptBlockCode 将文档化的 Gemini 提示词阻断枚举映射为安全稳定的 VCP 诊断代码。
func promptBlockCode(blockReason string) string {
	switch blockReason {
	case "SAFETY":
		return "google_aistudio.prompt_blocked.safety"
	case "OTHER":
		return "google_aistudio.prompt_blocked.other"
	case "BLOCKLIST":
		return "google_aistudio.prompt_blocked.blocklist"
	case "PROHIBITED_CONTENT":
		return "google_aistudio.prompt_blocked.prohibited_content"
	case "IMAGE_SAFETY":
		return "google_aistudio.prompt_blocked.image_safety"
	default:
		return "google_aistudio.prompt_blocked.unknown"
	}
}

// terminate completes open items before applying one confirmed terminal event.
// terminate 在应用一个已确认终态事件前完成开放项目。
func (d *StreamDecoder) terminate(eventType vcp.EventType, finishReason string, errorCode string) error {
	if d == nil || d.reducer == nil || d.reducer.Terminal() {
		return nil
	}
	if errComplete := d.completeAllItems(); errComplete != nil {
		return errComplete
	}
	terminal := d.emitter.event(eventType)
	terminal.FinishReason = finishReason
	terminal.ErrorCode = errorCode
	if errorCode != "" {
		d.report.ErrorOrRetryAdvice = errorCode
	}
	return d.emit(terminal)
}

// emit applies one validated event and appends an isolated owned event snapshot.
// emit 应用一个已校验事件并追加隔离的所有事件快照。
func (d *StreamDecoder) emit(event vcp.Event) error {
	if errApply := d.reducer.Apply(event); errApply != nil {
		return errApply
	}
	d.allEvents = append(d.allEvents, cloneEvent(event))
	return nil
}

// eventsFrom returns cloned events emitted at or after one known event slice offset.
// eventsFrom 返回从一个已知事件切片偏移处开始发出的克隆事件。
func (d *StreamDecoder) eventsFrom(start int) []vcp.Event {
	if d == nil || start < 0 || start >= len(d.allEvents) {
		if d != nil && start == len(d.allEvents) {
			return []vcp.Event{}
		}
		return nil
	}
	events := make([]vcp.Event, len(d.allEvents)-start)
	for index := range events {
		events[index] = cloneEvent(d.allEvents[start+index])
	}
	return events
}

// emitUsage emits one provider-reported usage observation before any terminal response event.
// emitUsage 在任何终态响应事件之前发出一个 Provider 报告的用量观测。
func (d *StreamDecoder) emitUsage(source *UsageMetadata, phase string, final bool) error {
	usage := usageObservation(source, phase, final)
	if usage == nil {
		return nil
	}
	event := d.emitter.event(vcp.EventUsageUpdated)
	event.Usage = usage
	if errEmit := d.emit(event); errEmit != nil {
		return errEmit
	}
	d.report.Usage = cloneUsageObservation(usage)
	return nil
}

// usageObservation maps only provider-reported values and leaves all unknown token fields nil.
// usageObservation 仅映射 Provider 报告的数值，并将所有未知 Token 字段保留为 nil。
func usageObservation(source *UsageMetadata, phase string, final bool) *vcp.UsageObservation {
	if source == nil {
		return nil
	}
	if source.PromptTokenCount == nil && source.CandidatesTokenCount == nil && source.ThoughtsTokenCount == nil && source.CachedContentTokenCount == nil && source.TotalTokenCount == nil {
		return nil
	}
	return &vcp.UsageObservation{
		InputTokens: source.PromptTokenCount, OutputTokens: source.CandidatesTokenCount, ReasoningTokens: source.ThoughtsTokenCount,
		CacheReadTokens: source.CachedContentTokenCount, TotalTokens: source.TotalTokenCount,
		Source: "provider_reported", Aggregation: "snapshot", Phase: phase, AccountingBasis: "google_aistudio_usage_metadata", Final: final,
	}
}

// cloneEvent returns an isolated VCP event including its nested optional values.
// cloneEvent 返回一个隔离的 VCP 事件，包括其嵌套可选值。
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
	if source.FinalArguments != nil {
		finalArguments := *source.FinalArguments
		cloned.FinalArguments = &finalArguments
	}
	cloned.Usage = cloneUsageObservation(source.Usage)
	return cloned
}

// cloneUsageObservation returns an isolated optional token observation.
// cloneUsageObservation 返回隔离的可选 Token 观测。
func cloneUsageObservation(source *vcp.UsageObservation) *vcp.UsageObservation {
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

// cloneInt64 returns an isolated optional integer.
// cloneInt64 返回一个隔离的可选整数。
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
