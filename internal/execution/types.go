// Package execution owns the durable Vulcan execution lifecycle and replayable semantic event log.
// execution 包拥有持久化 Vulcan 执行生命周期与可回放语义事件日志。
package execution

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

var (
	// ErrInvalidExecution reports an invalid execution record, transition, or event.
	// ErrInvalidExecution 表示无效执行记录、状态转换或事件。
	ErrInvalidExecution = errors.New("invalid execution")
	// ErrExecutionNotFound reports an absent owner-scoped execution.
	// ErrExecutionNotFound 表示所有者作用域内执行不存在。
	ErrExecutionNotFound = errors.New("execution not found")
	// ErrIdempotencyConflict reports reuse of one key with a different canonical request.
	// ErrIdempotencyConflict 表示使用同一键提交了不同的规范请求。
	ErrIdempotencyConflict = errors.New("execution idempotency conflict")
	// ErrRevisionConflict reports a concurrent execution update.
	// ErrRevisionConflict 表示执行发生并发更新冲突。
	ErrRevisionConflict = errors.New("execution revision conflict")
	// ErrInvalidProviderResult reports a provider result that violates the selected immutable capability contract.
	// ErrInvalidProviderResult 表示供应商结果违反选定的不可变能力合同。
	ErrInvalidProviderResult = errors.New("invalid provider execution result")
)

// Status identifies one closed durable execution lifecycle state.
// Status 标识一个封闭的持久化执行生命周期状态。
type Status string

const (
	// StatusAccepted records durable admission before input preparation.
	// StatusAccepted 表示输入准备前已经持久化接收。
	StatusAccepted Status = "accepted"
	// StatusPreparingInputs records deterministic resource materialization.
	// StatusPreparingInputs 表示正在进行确定性资源物化。
	StatusPreparingInputs Status = "preparing_inputs"
	// StatusQueued records a provider task accepted but not yet running.
	// StatusQueued 表示供应商任务已经接收但尚未运行。
	StatusQueued Status = "queued"
	// StatusRunning records active provider execution or polling.
	// StatusRunning 表示供应商正在执行或轮询。
	StatusRunning Status = "running"
	// StatusSucceeded records complete success.
	// StatusSucceeded 表示完整成功。
	StatusSucceeded Status = "succeeded"
	// StatusPartiallySucceeded records a provider-confirmed partial result.
	// StatusPartiallySucceeded 表示供应商确认的部分结果。
	StatusPartiallySucceeded Status = "partially_succeeded"
	// StatusFailed records terminal failure.
	// StatusFailed 表示终态失败。
	StatusFailed Status = "failed"
	// StatusCancelled records confirmed cancellation.
	// StatusCancelled 表示已确认取消。
	StatusCancelled Status = "cancelled"
	// StatusExpired records a task that exceeded its retained execution lifetime.
	// StatusExpired 表示任务超过保留执行生命周期。
	StatusExpired Status = "expired"
)

// IsTerminal reports whether the status can never transition again.
// IsTerminal 表示该状态是否永远不能再次转换。
func (s Status) IsTerminal() bool {
	switch s {
	case StatusSucceeded, StatusPartiallySucceeded, StatusFailed, StatusCancelled, StatusExpired:
		return true
	default:
		return false
	}
}

// ValidateTransition verifies one edge in the closed lifecycle graph.
// ValidateTransition 校验封闭生命周期图中的一条边。
func ValidateTransition(current Status, next Status) error {
	if current == next || current.IsTerminal() {
		return fmt.Errorf("%w: transition %q to %q is forbidden", ErrInvalidExecution, current, next)
	}
	// allowed contains only forward transitions supported by the durable orchestrator.
	// allowed 仅包含持久化编排器支持的前向转换。
	allowed := false
	switch current {
	case StatusAccepted:
		allowed = next == StatusPreparingInputs || next == StatusQueued || next == StatusRunning || next == StatusFailed || next == StatusCancelled || next == StatusExpired
	case StatusPreparingInputs:
		allowed = next == StatusQueued || next == StatusRunning || next == StatusFailed || next == StatusCancelled || next == StatusExpired
	case StatusQueued:
		allowed = next == StatusRunning || next == StatusFailed || next == StatusCancelled || next == StatusExpired
	case StatusRunning:
		allowed = next == StatusSucceeded || next == StatusPartiallySucceeded || next == StatusFailed || next == StatusCancelled || next == StatusExpired
	}
	if !allowed {
		return fmt.Errorf("%w: transition %q to %q is forbidden", ErrInvalidExecution, current, next)
	}
	return nil
}

// Failure contains one stable client-safe terminal failure without secret or prompt content.
// Failure 包含一个不含秘密或提示词内容的稳定客户端安全终态错误。
type Failure struct {
	// Code is a stable machine-readable error code.
	// Code 是稳定的机器可读错误码。
	Code string `json:"code"`
	// Retryable reports only a known safe retry classification.
	// Retryable 仅表示已知且安全的重试分类。
	Retryable bool `json:"retryable"`
}

// ProviderTaskSnapshot freezes the private upstream task affinity needed for restart recovery.
// ProviderTaskSnapshot 冻结重启恢复所需的私有上游任务亲和性。
type ProviderTaskSnapshot struct {
	// ProviderTaskID is the protected upstream task identifier and is never serialized publicly.
	// ProviderTaskID 是受保护的上游任务标识，绝不公开序列化。
	ProviderTaskID string `json:"-"`
	// ProtectedTaskIDRef is the non-secret local-store reference used only by durable repositories.
	// ProtectedTaskIDRef 是仅由持久化 Repository 使用的非秘密本地存储引用。
	ProtectedTaskIDRef string `json:"-"`
	// Target contains the exact provider, endpoint, region, credential, action, and model affinity.
	// Target 包含精确供应商、入口、区域、凭据、动作和模型亲和性。
	Target resolve.Target `json:"-"`
	// Definition is the immutable provider driver definition used when the task was created.
	// Definition 是任务创建时使用的不可变供应商 Driver Definition。
	Definition providerconfig.ProviderDefinition `json:"-"`
	// Endpoint is the immutable network snapshot used when the task was created.
	// Endpoint 是任务创建时使用的不可变网络快照。
	Endpoint providerconfig.Endpoint `json:"-"`
	// Credential is the immutable non-secret credential snapshot used when the task was created.
	// Credential 是任务创建时使用的不可变非秘密凭据快照。
	Credential providerconfig.Credential `json:"-"`
	// PollAfter records the earliest next permitted poll.
	// PollAfter 记录最早允许的下一次轮询时间。
	PollAfter time.Time `json:"poll_after"`
	// PollAttempts records completed bounded polls.
	// PollAttempts 记录已完成的有界轮询次数。
	PollAttempts uint32 `json:"poll_attempts"`
}

// ProviderPreparationSnapshot freezes one private multi-step provider handle and its exact affinity.
// ProviderPreparationSnapshot 冻结一个私有多步骤供应商句柄及其精确亲和性。
type ProviderPreparationSnapshot struct {
	// ProviderHandle is the protected upstream preparation identifier.
	// ProviderHandle 是受保护的上游准备标识。
	ProviderHandle string `json:"-"`
	// ProtectedHandleRef is the non-secret local-store reference used only by durable repositories.
	// ProtectedHandleRef 是仅由持久化 Repository 使用的非秘密本地存储引用。
	ProtectedHandleRef string `json:"-"`
	// Target is the immutable provider affinity that created the handle.
	// Target 是创建此句柄的不可变供应商亲和性。
	Target resolve.Target `json:"-"`
	// ExpiresAt is the provider-confirmed handle expiry.
	// ExpiresAt 是供应商确认的句柄过期时间。
	ExpiresAt time.Time `json:"-"`
}

// Result contains the operation-specific canonical result currently produced by registered drivers.
// Result 包含当前注册 Driver 生成的操作特定规范结果。
type Result struct {
	// Conversation contains a completed conversational response.
	// Conversation 包含已完成的会话响应。
	Conversation *vcp.Response `json:"conversation,omitempty"`
	// Analysis contains a completed media-understanding response.
	// Analysis 包含已完成媒体理解响应。
	Analysis *vcp.Response `json:"analysis,omitempty"`
	// Embeddings contains ordered embedding items.
	// Embeddings 包含有序 Embedding 项。
	Embeddings []vcp.EmbeddingItem `json:"embeddings,omitempty"`
	// Rerank contains ordered rerank results.
	// Rerank 包含有序重排结果。
	Rerank []vcp.RerankResult `json:"rerank,omitempty"`
	// Search contains one unified web-search response.
	// Search 包含一个统一网页搜索响应。
	Search *vcp.WebSearchResponse `json:"search,omitempty"`
	// Transcript contains one complete typed non-realtime recognition result.
	// Transcript 包含一个完整的类型化非实时识别结果。
	Transcript *vcp.Transcript `json:"transcript,omitempty"`
	// MusicCoverPreparation contains one public Router-owned cover preparation result.
	// MusicCoverPreparation 包含一个公开的 Router 所有翻唱准备结果。
	MusicCoverPreparation *vcp.MusicCoverPreparation `json:"music_cover_preparation,omitempty"`
	// Resources contains only completed Router-owned generated resources.
	// Resources 仅包含已完成且由 Router 拥有的生成资源。
	Resources []resource.Resource `json:"resources,omitempty"`
}

// Record is one owner-scoped durable execution and its private recovery snapshot.
// Record 是一个所有者作用域持久化执行及其私有恢复快照。
type Record struct {
	// ID is the Router-owned opaque execution identifier.
	// ID 是 Router 所有的不透明执行标识。
	ID string `json:"id"`
	// OwnerAPIKeyID isolates records between call-plane credentials.
	// OwnerAPIKeyID 在调用面凭据之间隔离记录。
	OwnerAPIKeyID string `json:"-"`
	// RequestHash binds idempotency to exact canonical request bytes.
	// RequestHash 将幂等语义绑定到精确规范请求字节。
	RequestHash string `json:"-"`
	// IdempotencyKey is private request metadata used only for replay lookup.
	// IdempotencyKey 是仅用于重放查找的私有请求元数据。
	IdempotencyKey string `json:"-"`
	// Request is the private immutable VCP request used for recovery.
	// Request 是用于恢复的私有不可变 VCP 请求。
	Request vcp.ExecutionRequest `json:"-"`
	// Target is the private immutable provider target snapshot.
	// Target 是私有不可变供应商 Target 快照。
	Target resolve.Target `json:"-"`
	// Status is the current durable lifecycle state.
	// Status 是当前持久化生命周期状态。
	Status Status `json:"status"`
	// Operation is the safe closed operation identifier.
	// Operation 是安全的封闭操作标识。
	Operation vcp.OperationKind `json:"operation"`
	// Result contains terminal or provider-confirmed partial output.
	// Result 包含终态或供应商确认的部分输出。
	Result *Result `json:"result,omitempty"`
	// Failure contains a safe terminal failure classification.
	// Failure 包含安全终态错误分类。
	Failure *Failure `json:"failure,omitempty"`
	// ProviderTask contains private task recovery affinity when asynchronous.
	// ProviderTask 在异步场景包含私有任务恢复亲和性。
	ProviderTask *ProviderTaskSnapshot `json:"-"`
	// ProviderPreparation contains private prepared-workflow affinity after successful preprocessing.
	// ProviderPreparation 在成功预处理后包含私有准备工作流亲和性。
	ProviderPreparation *ProviderPreparationSnapshot `json:"-"`
	// CreatedAt records durable admission time.
	// CreatedAt 记录持久化接收时间。
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt records the latest committed transition time.
	// UpdatedAt 记录最近提交状态转换时间。
	UpdatedAt time.Time `json:"updated_at"`
	// ExpiresAt records retention expiry.
	// ExpiresAt 记录保留期限。
	ExpiresAt time.Time `json:"expires_at"`
	// Revision supports compare-and-swap updates.
	// Revision 支持比较并交换更新。
	Revision uint64 `json:"revision"`
}

// EventType identifies one execution lifecycle or semantic provider event.
// EventType 标识一种执行生命周期或语义供应商事件。
type EventType string

const (
	// EventExecutionAccepted records durable admission.
	// EventExecutionAccepted 记录持久化接收。
	EventExecutionAccepted EventType = "execution.accepted"
	// EventInputMaterializationStarted records real input preparation.
	// EventInputMaterializationStarted 记录真实输入准备开始。
	EventInputMaterializationStarted EventType = "input.materialization.started"
	// EventInputMaterializationCompleted records completed input preparation.
	// EventInputMaterializationCompleted 记录输入准备完成。
	EventInputMaterializationCompleted EventType = "input.materialization.completed"
	// EventExecutionQueued records provider queue admission.
	// EventExecutionQueued 记录供应商队列接收。
	EventExecutionQueued EventType = "execution.queued"
	// EventExecutionRunning records provider execution start.
	// EventExecutionRunning 记录供应商执行开始。
	EventExecutionRunning EventType = "execution.running"
	// EventProgressUpdated records only provider-reported bounded progress facts.
	// EventProgressUpdated 仅记录供应商报告的有界进度事实。
	EventProgressUpdated EventType = "progress.updated"
	// EventResourcePartial records a provider-native partial resource observation.
	// EventResourcePartial 记录供应商原生部分资源观测。
	EventResourcePartial EventType = "resource.partial"
	// EventResourceCompleted records one completed Router resource result.
	// EventResourceCompleted 记录一个已完成 Router 资源结果。
	EventResourceCompleted EventType = "resource.completed"
	// EventTranscriptSegment records one typed transcript segment.
	// EventTranscriptSegment 记录一个类型化转写片段。
	EventTranscriptSegment EventType = "transcript.segment"
	// EventEmbeddingItemCompleted records one ordered typed embedding result.
	// EventEmbeddingItemCompleted 记录一个有序类型化 Embedding 结果。
	EventEmbeddingItemCompleted EventType = "embedding.item.completed"
	// EventRerankResultCompleted records one ordered typed rerank result.
	// EventRerankResultCompleted 记录一个有序类型化重排结果。
	EventRerankResultCompleted EventType = "rerank.result.completed"
	// EventSearchQueryStarted records an actual upstream search query.
	// EventSearchQueryStarted 记录一个真实上游搜索 Query。
	EventSearchQueryStarted EventType = "search.query.started"
	// EventSearchResultCompleted records one typed search result.
	// EventSearchResultCompleted 记录一个类型化搜索结果。
	EventSearchResultCompleted EventType = "search.result.completed"
	// EventSearchAnswerDelta records actual upstream answer text deltas only.
	// EventSearchAnswerDelta 仅记录真实上游答案文字增量。
	EventSearchAnswerDelta EventType = "search.answer.delta"
	// EventSearchAnswerCompleted records the final typed search answer.
	// EventSearchAnswerCompleted 记录最终类型化搜索答案。
	EventSearchAnswerCompleted EventType = "search.answer.completed"
	// EventCitationCompleted records one typed citation.
	// EventCitationCompleted 记录一个类型化引用。
	EventCitationCompleted EventType = "citation.completed"
	// EventUsageUpdated records one independently observed closed usage metric.
	// EventUsageUpdated 记录一个独立观测的封闭用量指标。
	EventUsageUpdated EventType = "usage.updated"
	// EventExecutionSucceeded records complete success.
	// EventExecutionSucceeded 记录完整成功。
	EventExecutionSucceeded EventType = "execution.succeeded"
	// EventExecutionPartiallySucceeded records provider-confirmed partial success.
	// EventExecutionPartiallySucceeded 记录供应商确认的部分成功。
	EventExecutionPartiallySucceeded EventType = "execution.partially_succeeded"
	// EventExecutionFailed records terminal failure.
	// EventExecutionFailed 记录终态失败。
	EventExecutionFailed EventType = "execution.failed"
	// EventExecutionCancelled records confirmed cancellation.
	// EventExecutionCancelled 记录已确认取消。
	EventExecutionCancelled EventType = "execution.cancelled"
	// EventExecutionExpired records retention or execution expiry.
	// EventExecutionExpired 记录保留或执行期限届满。
	EventExecutionExpired EventType = "execution.expired"
	// EventProviderSemantic wraps one already typed VCP conversation event without flattening its payload.
	// EventProviderSemantic 包装一个已经类型化的 VCP 会话事件且不扁平化其载荷。
	EventProviderSemantic EventType = "provider.semantic"
)

// LifecycleEvent contains an exact status transition payload.
// LifecycleEvent 包含精确状态转换载荷。
type LifecycleEvent struct {
	// Status is the status established by this event.
	// Status 是此事件建立的状态。
	Status Status `json:"status"`
	// Failure contains a safe classification only for failure events.
	// Failure 仅在失败事件中包含安全分类。
	Failure *Failure `json:"failure,omitempty"`
}

// ProgressEvent contains provider-reported progress without fabricating a percentage.
// ProgressEvent 包含供应商报告进度且不虚构百分比。
type ProgressEvent struct {
	// Current is the observed completed unit count when provided.
	// Current 是供应商提供时已完成单位数。
	Current *int64 `json:"current,omitempty"`
	// Total is the observed total unit count when provided.
	// Total 是供应商提供时总单位数。
	Total *int64 `json:"total,omitempty"`
	// Unit is the provider-documented closed progress unit.
	// Unit 是供应商记录的封闭进度单位。
	Unit string `json:"unit,omitempty"`
	// Percent is present only when the provider reports an authoritative percentage.
	// Percent 仅在供应商报告权威百分比时存在。
	Percent *float64 `json:"percent,omitempty"`
}

// ResourceEvent contains one partial byte observation or completed Router resource.
// ResourceEvent 包含一个部分字节观测或已完成 Router 资源。
type ResourceEvent struct {
	// ResourceID is stable across partial and completed observations.
	// ResourceID 在部分与完成观测间保持稳定。
	ResourceID string `json:"resource_id"`
	// PartialBytes is the actual byte count received so far for native partial output.
	// PartialBytes 是原生部分输出目前实际收到的字节数。
	PartialBytes *int64 `json:"partial_bytes,omitempty"`
	// Resource contains safe completed Router metadata.
	// Resource 包含安全已完成 Router 元数据。
	Resource *resource.Resource `json:"resource,omitempty"`
}

// TranscriptWord is the canonical VCP word event payload.
// TranscriptWord 是规范 VCP 词级事件载荷。
type TranscriptWord = vcp.TranscriptWord

// TranscriptSegment is the canonical VCP segment event payload.
// TranscriptSegment 是规范 VCP 分段事件载荷。
type TranscriptSegment = vcp.TranscriptSegment

// SearchQueryEvent contains one actual upstream search query.
// SearchQueryEvent 包含一个真实上游搜索 Query。
type SearchQueryEvent struct {
	// Query is the actual upstream query rather than a Router guess.
	// Query 是真实上游 Query 而不是 Router 猜测。
	Query string `json:"query"`
}

// SearchAnswerEvent contains actual delta or completed answer text.
// SearchAnswerEvent 包含真实增量或完整答案文字。
type SearchAnswerEvent struct {
	// Text contains only bytes actually emitted by the provider.
	// Text 仅包含供应商实际发出的字节。
	Text string `json:"text"`
}

// UsageEvent contains one closed independently observed consumption metric.
// UsageEvent 包含一个封闭独立观测消耗指标。
type UsageEvent struct {
	// Unit is one closed usage dimension.
	// Unit 是一个封闭用量维度。
	Unit string `json:"unit"`
	// Value is the non-negative observed quantity.
	// Value 是非负观测数量。
	Value int64 `json:"value"`
	// Accuracy is exact, estimated, or unknown.
	// Accuracy 是精确、估算或未知。
	Accuracy string `json:"accuracy"`
}

// Event contains one durable strictly typed replay event.
// Event 包含一个持久化严格类型化回放事件。
type Event struct {
	// ExecutionID identifies the owning execution.
	// ExecutionID 标识所属执行。
	ExecutionID string `json:"execution_id"`
	// EventID is stable for SSE replay and deduplication.
	// EventID 对 SSE 回放和去重保持稳定。
	EventID string `json:"event_id"`
	// Sequence is monotonic and gap-free within one execution.
	// Sequence 在单个执行内单调且无间隙。
	Sequence uint64 `json:"sequence"`
	// Time records the committed semantic time.
	// Time 记录提交的语义时间。
	Time time.Time `json:"time"`
	// Type identifies the exact payload variant.
	// Type 标识精确载荷变体。
	Type EventType `json:"type"`
	// Lifecycle contains lifecycle payload for Router-owned events.
	// Lifecycle 包含 Router 所有事件的生命周期载荷。
	Lifecycle *LifecycleEvent `json:"lifecycle,omitempty"`
	// ProviderEvent contains one typed provider conversation event.
	// ProviderEvent 包含一个类型化供应商会话事件。
	ProviderEvent *vcp.Event `json:"provider_event,omitempty"`
	// Progress contains one real provider progress observation.
	// Progress 包含一个真实供应商进度观测。
	Progress *ProgressEvent `json:"progress,omitempty"`
	// Resource contains one partial or completed resource observation.
	// Resource 包含一个部分或完成资源观测。
	Resource *ResourceEvent `json:"resource,omitempty"`
	// Transcript contains one typed transcript segment.
	// Transcript 包含一个类型化转写片段。
	Transcript *TranscriptSegment `json:"transcript,omitempty"`
	// Embedding contains one typed embedding item.
	// Embedding 包含一个类型化 Embedding 项。
	Embedding *vcp.EmbeddingItem `json:"embedding,omitempty"`
	// Rerank contains one typed rerank result.
	// Rerank 包含一个类型化重排结果。
	Rerank *vcp.RerankResult `json:"rerank,omitempty"`
	// SearchQuery contains one actual upstream search query.
	// SearchQuery 包含一个真实上游搜索 Query。
	SearchQuery *SearchQueryEvent `json:"search_query,omitempty"`
	// SearchResult contains one typed web-search result.
	// SearchResult 包含一个类型化网页搜索结果。
	SearchResult *vcp.WebSearchResult `json:"search_result,omitempty"`
	// SearchAnswer contains one actual answer delta or completion.
	// SearchAnswer 包含一个真实答案增量或完成内容。
	SearchAnswer *SearchAnswerEvent `json:"search_answer,omitempty"`
	// Citation contains one typed search citation.
	// Citation 包含一个类型化搜索引用。
	Citation *vcp.Citation `json:"citation,omitempty"`
	// Usage contains one closed consumption metric.
	// Usage 包含一个封闭消耗指标。
	Usage *UsageEvent `json:"usage,omitempty"`
}

// Validate verifies exact-one event payload and stable identity fields.
// Validate 校验唯一事件载荷及稳定身份字段。
func (e Event) Validate() error {
	if strings.TrimSpace(e.ExecutionID) == "" || strings.TrimSpace(e.EventID) == "" || e.Sequence == 0 || e.Time.IsZero() {
		return fmt.Errorf("%w: event identity, sequence, and time are required", ErrInvalidExecution)
	}
	// payloadCount enforces a closed exact-one union across every semantic payload family.
	// payloadCount 在每个语义载荷类别之间强制封闭唯一联合体。
	payloadCount := 0
	for _, present := range []bool{e.Lifecycle != nil, e.ProviderEvent != nil, e.Progress != nil, e.Resource != nil, e.Transcript != nil, e.Embedding != nil, e.Rerank != nil, e.SearchQuery != nil, e.SearchResult != nil, e.SearchAnswer != nil, e.Citation != nil, e.Usage != nil} {
		if present {
			payloadCount++
		}
	}
	if payloadCount != 1 {
		return fmt.Errorf("%w: event requires exactly one typed payload", ErrInvalidExecution)
	}
	if e.Type == EventProviderSemantic {
		if e.ProviderEvent == nil {
			return fmt.Errorf("%w: provider event requires exactly one provider payload", ErrInvalidExecution)
		}
		return nil
	}
	if e.Type == EventProgressUpdated {
		if e.Progress == nil || !validProgress(*e.Progress) {
			return fmt.Errorf("%w: progress payload is invalid", ErrInvalidExecution)
		}
		return nil
	}
	if e.Type == EventResourcePartial || e.Type == EventResourceCompleted {
		if e.Resource == nil || !validResourceEvent(e.Type, *e.Resource) {
			return fmt.Errorf("%w: resource payload is invalid", ErrInvalidExecution)
		}
		return nil
	}
	if e.Type == EventTranscriptSegment {
		if e.Transcript == nil || e.Transcript.Validate() != nil {
			return fmt.Errorf("%w: transcript payload is invalid", ErrInvalidExecution)
		}
		return nil
	}
	if e.Type == EventEmbeddingItemCompleted && e.Embedding != nil || e.Type == EventRerankResultCompleted && e.Rerank != nil || e.Type == EventSearchResultCompleted && e.SearchResult != nil || e.Type == EventCitationCompleted && e.Citation != nil {
		return nil
	}
	if e.Type == EventSearchQueryStarted && e.SearchQuery != nil && strings.TrimSpace(e.SearchQuery.Query) != "" {
		return nil
	}
	if (e.Type == EventSearchAnswerDelta || e.Type == EventSearchAnswerCompleted) && e.SearchAnswer != nil && e.SearchAnswer.Text != "" {
		return nil
	}
	if e.Type == EventUsageUpdated && e.Usage != nil && strings.TrimSpace(e.Usage.Unit) != "" && strings.TrimSpace(e.Usage.Accuracy) != "" && e.Usage.Value >= 0 {
		return nil
	}
	if e.Lifecycle == nil || e.Lifecycle.Status == "" {
		return fmt.Errorf("%w: event type does not match its typed payload", ErrInvalidExecution)
	}
	expectedStatus := Status("")
	switch e.Type {
	case EventExecutionAccepted:
		expectedStatus = StatusAccepted
	case EventInputMaterializationStarted, EventInputMaterializationCompleted:
		expectedStatus = StatusPreparingInputs
	case EventExecutionQueued:
		expectedStatus = StatusQueued
	case EventExecutionRunning:
		expectedStatus = StatusRunning
	case EventExecutionSucceeded:
		expectedStatus = StatusSucceeded
	case EventExecutionPartiallySucceeded:
		expectedStatus = StatusPartiallySucceeded
	case EventExecutionFailed:
		expectedStatus = StatusFailed
	case EventExecutionCancelled:
		expectedStatus = StatusCancelled
	case EventExecutionExpired:
		expectedStatus = StatusExpired
	default:
		return fmt.Errorf("%w: unknown lifecycle event type %q", ErrInvalidExecution, e.Type)
	}
	if e.Lifecycle.Status != expectedStatus {
		return fmt.Errorf("%w: lifecycle event type and status do not match", ErrInvalidExecution)
	}
	if (e.Type == EventExecutionFailed) != (e.Lifecycle.Failure != nil) {
		return fmt.Errorf("%w: failure payload must exist only on execution.failed", ErrInvalidExecution)
	}
	return nil
}

// validProgress verifies only internally consistent provider-reported progress facts.
// validProgress 仅校验内部一致的供应商报告进度事实。
func validProgress(progress ProgressEvent) bool {
	if progress.Current == nil && progress.Total == nil && progress.Percent == nil {
		return false
	}
	if progress.Current != nil && *progress.Current < 0 || progress.Total != nil && *progress.Total < 0 || progress.Current != nil && progress.Total != nil && *progress.Current > *progress.Total {
		return false
	}
	return progress.Percent == nil || (*progress.Percent >= 0 && *progress.Percent <= 100)
}

// validResourceEvent verifies the exact partial or completed resource union.
// validResourceEvent 校验精确部分或完成资源联合体。
func validResourceEvent(eventType EventType, payload ResourceEvent) bool {
	if strings.TrimSpace(payload.ResourceID) == "" {
		return false
	}
	if eventType == EventResourcePartial {
		return payload.PartialBytes != nil && *payload.PartialBytes >= 0 && payload.Resource == nil
	}
	return payload.PartialBytes == nil && payload.Resource != nil && payload.Resource.ID == payload.ResourceID && payload.Resource.State == resource.StateReady
}

// Validate verifies the durable record's private and public invariants.
// Validate 校验持久化记录的私有与公共不变量。
func (r Record) Validate() error {
	if strings.TrimSpace(r.ID) == "" || strings.TrimSpace(r.OwnerAPIKeyID) == "" || strings.TrimSpace(r.RequestHash) == "" || r.Status == "" || r.Operation == "" || r.CreatedAt.IsZero() || r.UpdatedAt.IsZero() || r.ExpiresAt.IsZero() || !r.ExpiresAt.After(r.CreatedAt) || r.Revision == 0 {
		return fmt.Errorf("%w: execution identity, ownership, lifecycle, and retention are required", ErrInvalidExecution)
	}
	if errRequest := r.Request.Validate(); errRequest != nil {
		return fmt.Errorf("%w: private request: %v", ErrInvalidExecution, errRequest)
	}
	if r.Operation != r.Request.Operation || r.Target.Operation != r.Operation || r.Target.ProviderInstanceID == "" || r.Target.ExecutionProfileID == "" {
		return fmt.Errorf("%w: request, operation, and target do not match", ErrInvalidExecution)
	}
	if r.Status == StatusFailed && r.Failure == nil {
		return fmt.Errorf("%w: failed execution requires a safe failure", ErrInvalidExecution)
	}
	if r.Status == StatusSucceeded && r.Result == nil {
		return fmt.Errorf("%w: successful execution requires a result", ErrInvalidExecution)
	}
	if r.ProviderTask != nil {
		task := r.ProviderTask
		if strings.TrimSpace(task.ProviderTaskID) == "" || task.Target.ProviderDefinitionID != r.Target.ProviderDefinitionID || task.Target.ProviderInstanceID != r.Target.ProviderInstanceID || task.Target.EndpointID != r.Target.EndpointID || task.Target.EndpointRegion != r.Target.EndpointRegion || task.Target.CredentialID != r.Target.CredentialID || task.Target.ActionBindingID != r.Target.ActionBindingID || task.Target.ProviderModelID != r.Target.ProviderModelID || task.Target.UpstreamModelID != r.Target.UpstreamModelID || task.Definition.ID != r.Target.ProviderDefinitionID || task.Endpoint.ID != r.Target.EndpointID || task.Endpoint.ProviderInstanceID != r.Target.ProviderInstanceID || task.Credential.ID != r.Target.CredentialID || task.Credential.ProviderInstanceID != r.Target.ProviderInstanceID {
			return fmt.Errorf("%w: provider task affinity does not match the immutable target", ErrInvalidExecution)
		}
	}
	if r.ProviderPreparation != nil {
		preparation := r.ProviderPreparation
		if r.Operation != vcp.OperationMusicCoverPrepare || r.Status != StatusSucceeded || r.Result == nil || r.Result.MusicCoverPreparation == nil || r.Result.MusicCoverPreparation.PreparationID != r.ID || strings.TrimSpace(preparation.ProviderHandle) == "" || preparation.ExpiresAt.IsZero() || preparation.Target.ProviderDefinitionID != r.Target.ProviderDefinitionID || preparation.Target.ProviderInstanceID != r.Target.ProviderInstanceID || preparation.Target.EndpointID != r.Target.EndpointID || preparation.Target.EndpointRegion != r.Target.EndpointRegion || preparation.Target.CredentialID != r.Target.CredentialID || preparation.Target.UpstreamModelID != r.Target.UpstreamModelID {
			return fmt.Errorf("%w: provider preparation affinity does not match the successful cover preparation", ErrInvalidExecution)
		}
	}
	return nil
}
