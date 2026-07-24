// Package execution owns the durable Vulcan execution lifecycle and replayable semantic event log.
// execution 包拥有持久化 Vulcan 执行生命周期与可回放语义事件日志。
package execution

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/routertool"
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
	// ErrExecutionBudgetExceeded reports a caller-owned hard execution ceiling.
	// ErrExecutionBudgetExceeded 表示调用方拥有的执行硬上限。
	ErrExecutionBudgetExceeded = errors.New("execution budget exceeded")
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
	// StatusWaitingRetry records a durable retry that has not reached its scheduled time.
	// StatusWaitingRetry 表示尚未到达计划时间的持久重试。
	StatusWaitingRetry Status = "waiting_retry"
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
		allowed = next == StatusSucceeded || next == StatusPartiallySucceeded || next == StatusWaitingRetry || next == StatusFailed || next == StatusCancelled || next == StatusExpired
	case StatusWaitingRetry:
		allowed = next == StatusPreparingInputs || next == StatusQueued || next == StatusRunning || next == StatusFailed || next == StatusCancelled || next == StatusExpired
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
	// Category is the trusted provider category when the failure reached an upstream boundary.
	// Category 是失败到达上游边界时的可信供应商类别。
	Category string `json:"category,omitempty"`
	// Scope identifies the affected provider-owned resource without exposing its identifier.
	// Scope 标识受影响的供应商拥有资源且不暴露其标识。
	Scope provider.ErrorScope `json:"scope,omitempty"`
	// RetryAction is the final same-provider recovery recommendation.
	// RetryAction 是最终同供应商恢复建议。
	RetryAction provider.RetryAction `json:"retry_action,omitempty"`
	// RetryAfterMilliseconds is the non-negative delay known when the failure became terminal.
	// RetryAfterMilliseconds 是失败进入终态时已知的非负延迟。
	RetryAfterMilliseconds *int64 `json:"retry_after_milliseconds,omitempty"`
	// NextRetryAt is the provider-evidenced recovery time when known.
	// NextRetryAt 是已知时由供应商证据支持的恢复时间。
	NextRetryAt *time.Time `json:"next_retry_at,omitempty"`
	// Attempt is the number of completed provider dispatches.
	// Attempt 是已完成的供应商分派次数。
	Attempt uint32 `json:"attempt"`
	// MaxAttempts is present only for a finite caller policy.
	// MaxAttempts 仅在调用方策略有限时存在。
	MaxAttempts *uint32 `json:"max_attempts,omitempty"`
	// RouterRequestID correlates the failure with the caller request without exposing payloads.
	// RouterRequestID 将失败与调用方请求关联且不暴露载荷。
	RouterRequestID string `json:"router_request_id"`
	// TargetSummary contains only provider instance, model or service, profile, and region.
	// TargetSummary 仅包含供应商实例、模型或服务、规格与区域。
	TargetSummary string `json:"target_summary"`
	// ProviderRequestID contains only a provider-approved request identifier.
	// ProviderRequestID 仅包含供应商批准公开的请求标识。
	ProviderRequestID string `json:"provider_request_id,omitempty"`
}

// Validate verifies the closed client-safe failure shape and provider classification tuple.
// Validate 校验封闭的客户端安全失败结构及供应商分类元组。
func (f Failure) Validate() error {
	if strings.TrimSpace(f.Code) == "" || strings.TrimSpace(f.RouterRequestID) == "" || strings.TrimSpace(f.TargetSummary) == "" {
		return fmt.Errorf("%w: failure code, router request id, and target summary are required", ErrInvalidExecution)
	}
	if f.RetryAfterMilliseconds != nil && *f.RetryAfterMilliseconds < 0 {
		return fmt.Errorf("%w: failure retry delay cannot be negative", ErrInvalidExecution)
	}
	if f.NextRetryAt != nil && f.NextRetryAt.IsZero() {
		return fmt.Errorf("%w: failure next retry time cannot be zero", ErrInvalidExecution)
	}
	if f.MaxAttempts != nil && (*f.MaxAttempts == 0 || f.Attempt > *f.MaxAttempts) {
		return fmt.Errorf("%w: failure attempt exceeds the finite retry policy", ErrInvalidExecution)
	}
	// classifiedFields enforces the exact tuple created only after a trusted provider classifier succeeds.
	// classifiedFields 仅在可信供应商分类器成功后强制其创建的精确元组。
	classifiedFields := []bool{strings.TrimSpace(f.Category) != "", f.Scope != "", f.RetryAction != ""}
	if classifiedFields[0] != classifiedFields[1] || classifiedFields[1] != classifiedFields[2] {
		return fmt.Errorf("%w: failure category, scope, and retry action must appear together", ErrInvalidExecution)
	}
	if classifiedFields[0] {
		if !validFailureScope(f.Scope) || !validFailureRetryAction(f.RetryAction) {
			return fmt.Errorf("%w: failure provider classification is invalid", ErrInvalidExecution)
		}
	} else if f.RetryAfterMilliseconds != nil || f.NextRetryAt != nil || strings.TrimSpace(f.ProviderRequestID) != "" {
		return fmt.Errorf("%w: unclassified failure cannot carry provider retry or request metadata", ErrInvalidExecution)
	}
	return nil
}

// validFailureScope reports whether a scope belongs to the provider error contract.
// validFailureScope 报告作用域是否属于供应商错误契约。
func validFailureScope(scope provider.ErrorScope) bool {
	switch scope {
	case provider.ErrorScopeRequest, provider.ErrorScopeCredential, provider.ErrorScopeSubscription, provider.ErrorScopeBillingAccount, provider.ErrorScopeEndpoint, provider.ErrorScopeModel, provider.ErrorScopeProvider:
		return true
	default:
		return false
	}
}

// validFailureRetryAction reports whether an action belongs to the same-provider recovery contract.
// validFailureRetryAction 报告动作是否属于同供应商恢复契约。
func validFailureRetryAction(action provider.RetryAction) bool {
	switch action {
	case provider.RetryStop, provider.RetrySameTarget, provider.RetryOtherCredential, provider.RetryOtherEndpoint, provider.RetryAfterReset:
		return true
	default:
		return false
	}
}

// RetryState contains client-safe durable scheduling facts for a deferred execution.
// RetryState 包含延迟执行的客户端安全持久调度事实。
type RetryState struct {
	// ConsecutiveFailures counts completed retryable failure cycles.
	// ConsecutiveFailures 统计已经完成的连续可重试失败周期。
	ConsecutiveFailures uint32 `json:"consecutive_failures"`
	// NextRetryAt is the earliest scheduler dispatch time.
	// NextRetryAt 是调度器最早分派时间。
	NextRetryAt time.Time `json:"next_retry_at"`
	// Category is the stable provider-classified failure category.
	// Category 是稳定的供应商分类失败类别。
	Category string `json:"category"`
	// Scope is the provider-owned resource affected by the failure.
	// Scope 是失败影响的供应商拥有资源。
	Scope provider.ErrorScope `json:"scope"`
	// Action is the same-provider recovery action used by the next dispatch.
	// Action 是下一次分派使用的同供应商恢复动作。
	Action provider.RetryAction `json:"action"`
	// MaxAttempts is present only when the caller configured a finite limit.
	// MaxAttempts 仅在调用方配置有限次数时存在。
	MaxAttempts *uint32 `json:"max_attempts,omitempty"`
}

// Attempt records one private exact-target provider dispatch within a logical execution.
// Attempt 记录一个逻辑执行中的一次私有精确 Target 供应商分派。
type Attempt struct {
	// Sequence is the one-based stable attempt order.
	// Sequence 是从一开始的稳定尝试顺序。
	Sequence uint32 `json:"sequence"`
	// Target is the immutable provider affinity used by this attempt.
	// Target 是该尝试使用的不可变供应商亲和性。
	Target resolve.Target `json:"target"`
	// StartedAt records dispatch start.
	// StartedAt 记录分派开始时间。
	StartedAt time.Time `json:"started_at"`
	// EndedAt records provider return time.
	// EndedAt 记录供应商返回时间。
	EndedAt time.Time `json:"ended_at"`
	// Succeeded reports a validated provider result.
	// Succeeded 表示获得经过校验的供应商结果。
	Succeeded bool `json:"succeeded"`
	// FailureCategory is the safe classified category when failed.
	// FailureCategory 是失败时的安全分类类别。
	FailureCategory string `json:"failure_category,omitempty"`
	// RetryAction is the trusted recovery action selected after failure.
	// RetryAction 是失败后选择的可信恢复动作。
	RetryAction provider.RetryAction `json:"retry_action,omitempty"`
	// SemanticOutput reports whether any provider semantic output was observed before failure.
	// SemanticOutput 表示失败前是否已观测到任何供应商语义输出。
	SemanticOutput bool `json:"semantic_output"`
	// Usage contains the terminal provider observation attributable to this exact attempt when one was returned.
	// Usage 包含供应商返回时可归属于该精确尝试的终态用量观测。
	Usage *vcp.UsageObservation `json:"usage,omitempty"`
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
	// CancellationRequestedAt records a durable operator cancellation intent before any upstream cancellation call.
	// CancellationRequestedAt 在任何上游取消调用前记录持久化的操作员取消意图。
	CancellationRequestedAt *time.Time `json:"-"`
	// CancellationAfter records the earliest safe retry time for an unconfirmed upstream cancellation.
	// CancellationAfter 记录尚未确认的上游取消可安全重试的最早时间。
	CancellationAfter time.Time `json:"-"`
	// CancellationAttempts counts completed upstream cancellation requests.
	// CancellationAttempts 统计已完成的上游取消请求次数。
	CancellationAttempts uint32 `json:"-"`
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

// ProviderContinuationSnapshot freezes one protected upstream continuation and its exact provider affinity.
// ProviderContinuationSnapshot 冻结一个受保护的上游续接标识及其精确供应商亲和性。
type ProviderContinuationSnapshot struct {
	// ContinuationID is the Router-owned identifier exposed to the original call-plane owner.
	// ContinuationID 是向原调用面所有者公开的 Router 所有标识。
	ContinuationID string `json:"-"`
	// UpstreamResponseID is the protected provider response identifier and is never serialized publicly.
	// UpstreamResponseID 是受保护的供应商响应标识，绝不公开序列化。
	UpstreamResponseID string `json:"-"`
	// ProtectedResponseIDRef is the durable secret-store reference used only by repositories.
	// ProtectedResponseIDRef 是仅由 Repository 使用的持久 SecretStore 引用。
	ProtectedResponseIDRef string `json:"-"`
	// Target contains the exact provider state ownership boundary.
	// Target 包含精确的供应商状态所有权边界。
	Target resolve.Target `json:"-"`
	// LogicalResponseID identifies the public response that created this continuation.
	// LogicalResponseID 标识创建此续接的公开响应。
	LogicalResponseID string `json:"-"`
	// CreatedAt records when the provider continuation became durable.
	// CreatedAt 记录供应商续接进入持久状态的时间。
	CreatedAt time.Time `json:"-"`
	// LastUsedAt records the latest successful affinity validation before replay.
	// LastUsedAt 记录重放前最近一次成功亲和性校验时间。
	LastUsedAt time.Time `json:"-"`
	// ExpiresAt bounds continuation replay.
	// ExpiresAt 限制续接重放期限。
	ExpiresAt time.Time `json:"-"`
	// InvalidatedAt records an explicit durable revocation time.
	// InvalidatedAt 记录明确的持久失效时间。
	InvalidatedAt time.Time `json:"-"`
	// InvalidationReason is one safe closed reason for rejecting later replay.
	// InvalidationReason 是拒绝后续重放的安全封闭原因。
	InvalidationReason ContinuationInvalidationReason `json:"-"`
}

// ContinuationInvalidationReason identifies one durable safe replay revocation cause.
// ContinuationInvalidationReason 标识一个持久且安全的重放撤销原因。
type ContinuationInvalidationReason string

const (
	// ContinuationInvalidatedExpired marks a continuation whose absolute lifetime ended.
	// ContinuationInvalidatedExpired 标记绝对有效期已经结束的续接。
	ContinuationInvalidatedExpired ContinuationInvalidationReason = "expired"
	// ContinuationInvalidatedTargetUnavailable marks deleted, disabled, or no-longer-eligible exact affinity.
	// ContinuationInvalidatedTargetUnavailable 标记已删除、已禁用或不再可用的精确亲和目标。
	ContinuationInvalidatedTargetUnavailable ContinuationInvalidationReason = "target_unavailable"
	// ContinuationInvalidatedProviderRejected marks an upstream response that explicitly rejected its own continuation state.
	// ContinuationInvalidatedProviderRejected 标记上游明确拒绝其自身续接状态。
	ContinuationInvalidatedProviderRejected ContinuationInvalidationReason = "provider_rejected"
)

// validContinuationInvalidationReason reports membership in the closed durable revocation set.
// validContinuationInvalidationReason 报告是否属于封闭的持久撤销集合。
func validContinuationInvalidationReason(reason ContinuationInvalidationReason) bool {
	return reason == ContinuationInvalidatedExpired || reason == ContinuationInvalidatedTargetUnavailable || reason == ContinuationInvalidatedProviderRejected
}

// ModelToolPlanEntry freezes one requested standard tool and its exact execution backend.
// ModelToolPlanEntry 冻结一个请求的标准工具及其精确执行后端。
type ModelToolPlanEntry struct {
	// Kind identifies the standard model tool.
	// Kind 标识标准模型工具。
	Kind vcp.StandardModelToolKind `json:"kind"`
	// Mode identifies disabled, native, or Router execution.
	// Mode 标识禁用、原生或 Router 执行。
	Mode vcp.ModelToolMode `json:"mode"`
	// RouterBindingID identifies the selected administrator policy without exposing its backend target.
	// RouterBindingID 标识选定的管理员策略且不暴露其后端 Target。
	RouterBindingID string `json:"router_binding_id,omitempty"`
	// RouterBindingRevision identifies the frozen policy revision.
	// RouterBindingRevision 标识冻结的策略修订号。
	RouterBindingRevision uint64 `json:"router_binding_revision,omitempty"`
	// RouterBinding privately contains the immutable Router policy and child target only for router_tool mode.
	// RouterBinding 仅在 router_tool 模式下私有包含不可变 Router 策略与子 Target。
	RouterBinding *routertool.ResolvedBinding `json:"-"`
}

// RouterExtensionPlanEntry freezes one requested Router enhancement and its exact child target.
// RouterExtensionPlanEntry 冻结一个请求的 Router 增强能力及其精确子 Target。
type RouterExtensionPlanEntry struct {
	// ID identifies the closed operation-backed enhancement.
	// ID 标识封闭且由操作支持的增强能力。
	ID vcp.RouterExtensionKind `json:"id"`
	// RouterBindingID identifies the selected administrator binding.
	// RouterBindingID 标识选定的管理员绑定。
	RouterBindingID string `json:"router_binding_id"`
	// RouterBindingRevision freezes the selected binding revision.
	// RouterBindingRevision 冻结选定的绑定修订号。
	RouterBindingRevision uint64 `json:"router_binding_revision"`
	// RouterBinding privately contains the immutable Router policy and child target.
	// RouterBinding 私有包含不可变 Router 策略与子 Target。
	RouterBinding *routertool.ResolvedBinding `json:"-"`
}

// ModelToolPlan freezes all model-tool decisions used by one durable execution.
// ModelToolPlan 冻结一个持久执行使用的全部模型工具决策。
type ModelToolPlan struct {
	// CatalogRevision identifies the parent model catalog snapshot used for planning.
	// CatalogRevision 标识用于规划的父模型目录快照。
	CatalogRevision uint64 `json:"catalog_revision"`
	// Standard contains requested standard tools in canonical request order.
	// Standard 按规范请求顺序包含请求的标准工具。
	Standard []ModelToolPlanEntry `json:"standard,omitempty"`
	// Extra contains exact provider-native extra tool identifiers.
	// Extra 包含精确供应商原生扩展工具标识。
	Extra []string `json:"extra,omitempty"`
	// RouterExtensions contains exact operation-backed Router enhancement identifiers.
	// RouterExtensions 包含精确的操作支持 Router 增强工具标识。
	RouterExtensions []RouterExtensionPlanEntry `json:"router_extensions,omitempty"`
	// Diagnostics contains safe compatibility records produced while canonicalizing the accepted request.
	// Diagnostics 包含规范化已接收请求时生成的安全兼容记录。
	Diagnostics []vcp.ModelToolDiagnostic `json:"diagnostics,omitempty"`
}

// Public returns the non-secret VCP representation of this frozen execution plan.
// Public 返回该冻结执行计划不含秘密的 VCP 表示。
func (p ModelToolPlan) Public() vcp.ModelToolPlan {
	public := vcp.ModelToolPlan{
		CatalogRevision: p.CatalogRevision,
		Extra:           append([]string(nil), p.Extra...),
		Diagnostics:     append([]vcp.ModelToolDiagnostic(nil), p.Diagnostics...),
	}
	public.RouterExtensions = make([]vcp.RouterExtensionPlanEntry, 0, len(p.RouterExtensions))
	for _, entry := range p.RouterExtensions {
		public.RouterExtensions = append(public.RouterExtensions, vcp.RouterExtensionPlanEntry{
			ID:                    entry.ID,
			RouterBindingID:       entry.RouterBindingID,
			RouterBindingRevision: entry.RouterBindingRevision,
		})
	}
	public.Standard = make([]vcp.ModelToolPlanEntry, 0, len(p.Standard))
	for _, entry := range p.Standard {
		public.Standard = append(public.Standard, vcp.ModelToolPlanEntry{
			Kind:                  entry.Kind,
			Mode:                  entry.Mode,
			RouterBindingID:       entry.RouterBindingID,
			RouterBindingRevision: entry.RouterBindingRevision,
		})
	}
	return public
}

// RouterToolLineage identifies one Router-managed child execution.
// RouterToolLineage 标识一个由 Router 管理的子执行。
type RouterToolLineage struct {
	// ParentExecutionID identifies the model execution that requested the tool.
	// ParentExecutionID 标识请求工具的模型执行。
	ParentExecutionID string `json:"parent_execution_id"`
	// ParentToolCallID identifies the exact model-produced tool call.
	// ParentToolCallID 标识模型生成的精确工具调用。
	ParentToolCallID string `json:"parent_tool_call_id"`
	// ParentRound is the positive Router tool loop round.
	// ParentRound 是正数的 Router 工具循环轮次。
	ParentRound uint32 `json:"parent_round"`
	// BindingID identifies the frozen Router tool binding.
	// BindingID 标识冻结的 Router 工具绑定。
	BindingID string `json:"binding_id"`
}

// Validate verifies an immutable model-tool plan against its parent target and accepted request.
// Validate 根据父 Target 与已接收请求校验不可变模型工具计划。
func (p ModelToolPlan) Validate(request vcp.ExecutionRequest, target resolve.Target) error {
	noSelections := request.Operation != vcp.OperationConversationRespond || request.Payload.Conversation == nil || len(request.Payload.Conversation.ModelTools.Standard) == 0 && len(request.Payload.Conversation.ModelTools.Extra) == 0 && len(request.Payload.Conversation.ModelTools.RouterExtensions) == 0
	if p.CatalogRevision == 0 && len(p.Standard) == 0 && len(p.Extra) == 0 && len(p.RouterExtensions) == 0 && len(p.Diagnostics) == 0 && noSelections {
		return nil
	}
	if p.CatalogRevision != target.CatalogRevision {
		return fmt.Errorf("%w: model tool plan catalog revision differs from target", ErrInvalidExecution)
	}
	if request.Operation != vcp.OperationConversationRespond {
		if len(p.Standard) != 0 || len(p.Extra) != 0 || len(p.RouterExtensions) != 0 || len(p.Diagnostics) != 0 {
			return fmt.Errorf("%w: non-conversation execution cannot carry a model tool plan", ErrInvalidExecution)
		}
		return nil
	}
	seenDiagnostics := make(map[vcp.ModelToolDiagnosticCode]struct{}, len(p.Diagnostics))
	for _, diagnostic := range p.Diagnostics {
		if !diagnostic.Code.Valid() {
			return fmt.Errorf("%w: model tool plan contains an invalid diagnostic", ErrInvalidExecution)
		}
		if _, duplicate := seenDiagnostics[diagnostic.Code]; duplicate {
			return fmt.Errorf("%w: model tool plan contains a duplicate diagnostic", ErrInvalidExecution)
		}
		seenDiagnostics[diagnostic.Code] = struct{}{}
	}
	operation := request.Payload.Conversation
	if operation == nil || len(p.Standard) != len(operation.ModelTools.Standard) || len(p.Extra) != len(operation.ModelTools.Extra) || len(p.RouterExtensions) != len(operation.ModelTools.RouterExtensions) {
		return fmt.Errorf("%w: model tool plan differs from accepted selections", ErrInvalidExecution)
	}
	for index, entry := range p.Standard {
		selection := operation.ModelTools.Standard[index]
		if entry.Kind != selection.Kind || entry.Mode != selection.Mode {
			return fmt.Errorf("%w: model tool plan standard selection differs from request", ErrInvalidExecution)
		}
		if entry.Mode == vcp.ModelToolRouter {
			if entry.RouterBinding == nil || entry.RouterBindingID != entry.RouterBinding.Binding.ID || entry.RouterBindingRevision != entry.RouterBinding.Binding.Revision || entry.RouterBinding.Binding.Kind != entry.Kind || entry.RouterBinding.Target.Operation == "" {
				return fmt.Errorf("%w: Router tool plan entry is incomplete", ErrInvalidExecution)
			}
			if errBinding := entry.RouterBinding.Validate(); errBinding != nil {
				return fmt.Errorf("%w: Router tool binding is invalid: %v", ErrInvalidExecution, errBinding)
			}
		} else if entry.RouterBinding != nil || entry.RouterBindingID != "" || entry.RouterBindingRevision != 0 {
			return fmt.Errorf("%w: non-Router tool plan entry contains a Router binding", ErrInvalidExecution)
		}
	}
	for index, id := range p.Extra {
		if id != operation.ModelTools.Extra[index] {
			return fmt.Errorf("%w: model tool plan extra selection differs from request", ErrInvalidExecution)
		}
	}
	for index, entry := range p.RouterExtensions {
		if entry.ID != operation.ModelTools.RouterExtensions[index] {
			return fmt.Errorf("%w: model tool plan Router extension selection differs from request", ErrInvalidExecution)
		}
		if entry.RouterBinding == nil || entry.RouterBindingID != entry.RouterBinding.Binding.ID || entry.RouterBindingRevision != entry.RouterBinding.Binding.Revision || entry.RouterBinding.Binding.Extension != entry.ID || entry.RouterBinding.Target.Operation != entry.ID.Operation() {
			return fmt.Errorf("%w: Router extension plan entry is incomplete", ErrInvalidExecution)
		}
		if errBinding := entry.RouterBinding.Validate(); errBinding != nil {
			return fmt.Errorf("%w: Router extension binding is invalid: %v", ErrInvalidExecution, errBinding)
		}
	}
	return nil
}

// Validate verifies complete Router child lineage without accepting partial parent relationships.
// Validate 校验完整 Router 子执行谱系且不接受部分父级关系。
func (l RouterToolLineage) Validate() error {
	if strings.TrimSpace(l.ParentExecutionID) == "" || strings.TrimSpace(l.ParentToolCallID) == "" || l.ParentRound == 0 || strings.TrimSpace(l.BindingID) == "" {
		return fmt.Errorf("%w: Router tool lineage is incomplete", ErrInvalidExecution)
	}
	return nil
}

// Result contains one closed successful execution result.
// Result 包含一个封闭的成功执行结果。
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
	// Extract contains one unified web-content extraction response.
	// Extract 包含一个统一网页内容提取响应。
	Extract *vcp.WebExtractResponse `json:"extract,omitempty"`
	// Transcript contains one complete typed non-realtime recognition result.
	// Transcript 包含一个完整的类型化非实时识别结果。
	Transcript *vcp.Transcript `json:"transcript,omitempty"`
	// Transcriptions contains ordered resource-owned results for batch recognition.
	// Transcriptions 包含批量识别的有序且归属资源的结果。
	Transcriptions []vcp.TranscriptionResult `json:"transcriptions,omitempty"`
	// MusicCoverPreparation contains one public Router-owned cover preparation result.
	// MusicCoverPreparation 包含一个公开的 Router 所有翻唱准备结果。
	MusicCoverPreparation *vcp.MusicCoverPreparation `json:"music_cover_preparation,omitempty"`
	// Resources contains only completed Router-owned generated resources.
	// Resources 仅包含已完成且由 Router 拥有的生成资源。
	Resources []resource.Resource `json:"resources,omitempty"`
	// Continuation is a client-safe reference to protected provider state.
	// Continuation 是指向受保护供应商状态的客户端安全引用。
	Continuation *vcp.Continuation `json:"continuation,omitempty"`
	// Usage contains the logical execution aggregate of all observed attempt usage without filling unknown dimensions.
	// Usage 包含全部已观测尝试用量的逻辑执行聚合，且不会填充未知维度。
	Usage *vcp.UsageObservation `json:"usage,omitempty"`
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
	// ModelToolPlan is the immutable standard and extra tool plan accepted with the request.
	// ModelToolPlan 是随请求接收的不可变标准及扩展工具计划。
	ModelToolPlan ModelToolPlan `json:"model_tool_plan"`
	// RouterToolLineage is present only for a Router-created child service execution.
	// RouterToolLineage 仅在 Router 创建的子服务执行中存在。
	RouterToolLineage *RouterToolLineage `json:"router_tool_lineage,omitempty"`
	// CompletedRouterToolRounds counts parent model rounds whose child results were durably committed.
	// CompletedRouterToolRounds 统计子结果已经持久提交的父模型工具轮次。
	CompletedRouterToolRounds uint32 `json:"-"`
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
	// Retry contains a safe pending retry state only while status is waiting_retry.
	// Retry 仅在状态为 waiting_retry 时包含安全的待重试状态。
	Retry *RetryState `json:"retry,omitempty"`
	// RetryCycles counts durable retry schedules created for this logical execution.
	// RetryCycles 统计为此逻辑执行创建的持久重试计划次数。
	RetryCycles uint32 `json:"retry_cycles,omitempty"`
	// ProviderTask contains private task recovery affinity when asynchronous.
	// ProviderTask 在异步场景包含私有任务恢复亲和性。
	ProviderTask *ProviderTaskSnapshot `json:"-"`
	// ProviderPreparation contains private prepared-workflow affinity after successful preprocessing.
	// ProviderPreparation 在成功预处理后包含私有准备工作流亲和性。
	ProviderPreparation *ProviderPreparationSnapshot `json:"-"`
	// ProviderContinuation contains private target-bound state produced by a successful conversational execution.
	// ProviderContinuation 包含成功会话执行产生的私有 Target 绑定状态。
	ProviderContinuation *ProviderContinuationSnapshot `json:"-"`
	// Attempts contains private exact-target dispatch audit records.
	// Attempts 包含私有精确 Target 分派审计记录。
	Attempts []Attempt `json:"-"`
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
	// EventExecutionCancellationRequested records durable intent before an upstream task cancellation request.
	// EventExecutionCancellationRequested 在上游任务取消请求前记录持久化意图。
	EventExecutionCancellationRequested EventType = "execution.cancellation.requested"
	// EventExecutionAttemptCompleted records one private provider attempt without exposing its target.
	// EventExecutionAttemptCompleted 记录一次私有供应商尝试且不暴露其 Target。
	EventExecutionAttemptCompleted EventType = "execution.attempt.completed"
	// EventRetryScheduled records one durable provider-safe retry schedule.
	// EventRetryScheduled 记录一次持久且供应商安全的重试计划。
	EventRetryScheduled EventType = "retry.scheduled"
	// EventRetryStarted records dispatch of one previously scheduled retry.
	// EventRetryStarted 记录一次先前已计划重试的分派。
	EventRetryStarted EventType = "retry.started"
	// EventRetrySucceeded records success after at least one scheduled retry.
	// EventRetrySucceeded 记录至少一次计划重试后的成功。
	EventRetrySucceeded EventType = "retry.succeeded"
	// EventRetryAborted records a scheduled retry becoming terminal or cancelled.
	// EventRetryAborted 记录计划重试进入终态或被取消。
	EventRetryAborted EventType = "retry.aborted"
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
	// EventModelToolLifecycle records one safe parent-visible model-tool transition.
	// EventModelToolLifecycle 记录一个父执行可见且安全的模型工具转换。
	EventModelToolLifecycle EventType = "model_tool.lifecycle"
)

// ModelToolEventStage identifies one closed parent execution transition for an enabled model tool.
// ModelToolEventStage 标识一个已启用模型工具在父执行中的封闭转换。
type ModelToolEventStage string

const (
	// ModelToolStageEnabled records that one requested tool passed admission validation.
	// ModelToolStageEnabled 记录一个请求工具已经通过接收校验。
	ModelToolStageEnabled ModelToolEventStage = "enabled"
	// ModelToolStageModeFrozen records the immutable native or Router execution decision.
	// ModelToolStageModeFrozen 记录不可变的原生或 Router 执行决策。
	ModelToolStageModeFrozen ModelToolEventStage = "mode_frozen"
	// ModelToolStageRouterCallStarted records one provider-authored Router tool call before child execution.
	// ModelToolStageRouterCallStarted 记录子执行前一个由供应商生成的 Router 工具调用。
	ModelToolStageRouterCallStarted ModelToolEventStage = "router_call_started"
	// ModelToolStageChildCreated records the opaque child execution relationship.
	// ModelToolStageChildCreated 记录不透明的子执行关系。
	ModelToolStageChildCreated ModelToolEventStage = "child_created"
	// ModelToolStageChildCompleted records successful child completion.
	// ModelToolStageChildCompleted 记录子执行成功完成。
	ModelToolStageChildCompleted ModelToolEventStage = "child_completed"
	// ModelToolStageChildFailed records a failed child attempt without provider-private error text.
	// ModelToolStageChildFailed 记录失败的子执行尝试且不包含供应商私有错误正文。
	ModelToolStageChildFailed ModelToolEventStage = "child_failed"
	// ModelToolStageResultInjected records safe normalized result insertion into the parent context.
	// ModelToolStageResultInjected 记录安全归一结果已经写入父执行上下文。
	ModelToolStageResultInjected ModelToolEventStage = "result_injected"
	// ModelToolStageParentResumed records that the same parent model will continue after a completed Router round.
	// ModelToolStageParentResumed 记录同一个父模型将在 Router 轮次完成后继续执行。
	ModelToolStageParentResumed ModelToolEventStage = "parent_resumed"
)

// ModelToolEvent contains only safe identifiers required to audit one parent tool transition.
// ModelToolEvent 仅包含审计一个父执行工具转换所需的安全标识。
type ModelToolEvent struct {
	// ToolID identifies the public standard, extra, or Router extension tool.
	// ToolID 标识公开标准、额外或 Router 增强工具。
	ToolID string `json:"tool_id"`
	// Stage identifies the closed lifecycle transition.
	// Stage 标识封闭生命周期转换。
	Stage ModelToolEventStage `json:"stage"`
	// Mode identifies the frozen implementation source.
	// Mode 标识冻结的实现来源。
	Mode vcp.ModelToolMode `json:"mode"`
	// ToolCallID identifies one provider-authored call without exposing arguments.
	// ToolCallID 标识一个供应商生成的调用且不暴露参数。
	ToolCallID string `json:"tool_call_id,omitempty"`
	// ChildExecutionID identifies one opaque Router child execution.
	// ChildExecutionID 标识一个不透明 Router 子执行。
	ChildExecutionID string `json:"child_execution_id,omitempty"`
	// Round is the positive Router loop round for call-scoped stages.
	// Round 是调用作用域阶段对应的正数 Router 循环轮次。
	Round uint32 `json:"round,omitempty"`
}

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

// AttemptEvent exposes only the stable ordinal of one completed private provider attempt.
// AttemptEvent 仅公开一次已完成私有供应商尝试的稳定序号。
type AttemptEvent struct {
	// Sequence is the one-based provider attempt order within the logical execution.
	// Sequence 是逻辑执行中从一开始的供应商尝试顺序。
	Sequence uint32 `json:"sequence"`
}

// RetryEvent contains only safe durable scheduler facts.
// RetryEvent 仅包含安全的持久调度事实。
type RetryEvent struct {
	// Attempt is the next one-based provider dispatch ordinal.
	// Attempt 是下一次从一开始的供应商分派序号。
	Attempt uint32 `json:"attempt"`
	// NextRetryAt is present only for retry.scheduled.
	// NextRetryAt 仅用于 retry.scheduled。
	NextRetryAt *time.Time `json:"next_retry_at,omitempty"`
	// Category is the stable provider-classified category when known.
	// Category 是已知时稳定的供应商分类类别。
	Category string `json:"category,omitempty"`
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
	// OutputID is the provider-result-local stable identity shared by partial and completed observations.
	// OutputID 是在部分与完成观测间共享的供应商结果局部稳定身份。
	OutputID string `json:"output_id"`
	// ResourceID is the Router-owned identifier present only after completed ingestion.
	// ResourceID 是仅在完成接收后出现的 Router 所有标识。
	ResourceID string `json:"resource_id,omitempty"`
	// Kind identifies the partial generated media family before Router metadata exists.
	// Kind 在 Router 元数据存在前标识部分生成媒体类别。
	Kind vcp.MediaKind `json:"kind,omitempty"`
	// MIMEType identifies the selected partial output encoding before Router probing completes.
	// MIMEType 在 Router 探测完成前标识选定的部分输出编码。
	MIMEType string `json:"mime_type,omitempty"`
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
	Value float64 `json:"value"`
	// Accuracy is exact, estimated, or unknown.
	// Accuracy 是精确、估算或未知。
	Accuracy string `json:"accuracy"`
	// Source identifies the authoritative origin of this observation.
	// Source 标识该观测的权威来源。
	Source string `json:"source"`
	// Aggregation identifies delta, cumulative, or snapshot semantics.
	// Aggregation 标识增量、累计或快照语义。
	Aggregation string `json:"aggregation"`
	// Phase identifies the execution phase that produced the observation.
	// Phase 标识产生该观测的执行阶段。
	Phase string `json:"phase"`
	// AccountingBasis records the provider or Router counting rule.
	// AccountingBasis 记录供应商或 Router 计量规则。
	AccountingBasis string `json:"accounting_basis"`
	// Final reports whether this metric is terminal.
	// Final 表示该指标是否为终态。
	Final bool `json:"final"`
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
	// Attempt contains a safe completed-attempt ordinal without private target details.
	// Attempt 包含不带私有 Target 详情的安全已完成尝试序号。
	Attempt *AttemptEvent `json:"attempt,omitempty"`
	// Retry contains durable retry scheduling payload.
	// Retry 包含持久重试调度载荷。
	Retry *RetryEvent `json:"retry,omitempty"`
	// ProviderEvent contains one typed provider conversation event.
	// ProviderEvent 包含一个类型化供应商会话事件。
	ProviderEvent *vcp.Event `json:"provider_event,omitempty"`
	// ModelTool contains one safe parent-visible model-tool transition.
	// ModelTool 包含一个父执行可见且安全的模型工具转换。
	ModelTool *ModelToolEvent `json:"model_tool,omitempty"`
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
	for _, present := range []bool{e.Lifecycle != nil, e.Attempt != nil, e.Retry != nil, e.ProviderEvent != nil, e.ModelTool != nil, e.Progress != nil, e.Resource != nil, e.Transcript != nil, e.Embedding != nil, e.Rerank != nil, e.SearchQuery != nil, e.SearchResult != nil, e.SearchAnswer != nil, e.Citation != nil, e.Usage != nil} {
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
		if errProviderEvent := e.ProviderEvent.Validate(); errProviderEvent != nil {
			return fmt.Errorf("%w: provider event is invalid: %v", ErrInvalidExecution, errProviderEvent)
		}
		return nil
	}
	if e.Type == EventModelToolLifecycle {
		if e.ModelTool == nil || !validModelToolEvent(*e.ModelTool) {
			return fmt.Errorf("%w: model tool event is invalid", ErrInvalidExecution)
		}
		return nil
	}
	if e.Type == EventExecutionAttemptCompleted {
		if e.Attempt == nil || e.Attempt.Sequence == 0 {
			return fmt.Errorf("%w: execution attempt payload is invalid", ErrInvalidExecution)
		}
		return nil
	}
	if e.Type == EventExecutionCancellationRequested {
		if e.Lifecycle == nil || e.Lifecycle.Failure != nil || e.Lifecycle.Status != StatusQueued && e.Lifecycle.Status != StatusRunning {
			return fmt.Errorf("%w: cancellation request requires one active task lifecycle", ErrInvalidExecution)
		}
		return nil
	}
	if e.Type == EventRetryScheduled || e.Type == EventRetryStarted || e.Type == EventRetrySucceeded || e.Type == EventRetryAborted {
		if e.Retry == nil || e.Retry.Attempt == 0 {
			return fmt.Errorf("%w: retry event requires a positive attempt", ErrInvalidExecution)
		}
		if (e.Type == EventRetryScheduled) != (e.Retry.NextRetryAt != nil) {
			return fmt.Errorf("%w: only retry.scheduled requires next_retry_at", ErrInvalidExecution)
		}
		return nil
	} else if e.Retry != nil {
		return fmt.Errorf("%w: retry payload requires a retry event type", ErrInvalidExecution)
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
	if e.Type == EventUsageUpdated && e.Usage != nil && strings.TrimSpace(e.Usage.Unit) != "" && strings.TrimSpace(e.Usage.Accuracy) != "" && strings.TrimSpace(e.Usage.Source) != "" && strings.TrimSpace(e.Usage.Aggregation) != "" && strings.TrimSpace(e.Usage.Phase) != "" && strings.TrimSpace(e.Usage.AccountingBasis) != "" && e.Usage.Value >= 0 {
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
	if e.Lifecycle.Failure != nil {
		if errFailure := e.Lifecycle.Failure.Validate(); errFailure != nil {
			return fmt.Errorf("%w: lifecycle failure is invalid: %v", ErrInvalidExecution, errFailure)
		}
	}
	return nil
}

// validModelToolEvent verifies one closed stage without accepting private tool arguments or provider details.
// validModelToolEvent 校验一个封闭阶段且不接受私有工具参数或供应商详情。
func validModelToolEvent(event ModelToolEvent) bool {
	if !vcp.ValidModelToolID(event.ToolID) || !event.Mode.Valid() {
		return false
	}
	callScoped := event.Stage == ModelToolStageRouterCallStarted || event.Stage == ModelToolStageChildCreated || event.Stage == ModelToolStageChildCompleted || event.Stage == ModelToolStageChildFailed || event.Stage == ModelToolStageResultInjected || event.Stage == ModelToolStageParentResumed
	if event.Stage == ModelToolStageEnabled || event.Stage == ModelToolStageModeFrozen {
		return event.ToolCallID == "" && event.ChildExecutionID == "" && event.Round == 0
	}
	if !callScoped || event.Mode != vcp.ModelToolRouter || strings.TrimSpace(event.ToolCallID) == "" || event.Round == 0 {
		return false
	}
	if event.Stage == ModelToolStageRouterCallStarted {
		return event.ChildExecutionID == ""
	}
	if event.Stage == ModelToolStageChildFailed {
		return event.ChildExecutionID == "" || validModelToolChildExecutionID(event.ChildExecutionID)
	}
	return validModelToolChildExecutionID(event.ChildExecutionID)
}

// validModelToolChildExecutionID verifies the opaque Router execution identifier shape published by the event schema.
// validModelToolChildExecutionID 校验事件 Schema 公开的不透明 Router 执行标识格式。
func validModelToolChildExecutionID(value string) bool {
	if len(value) != 36 || !strings.HasPrefix(value, "exe_") {
		return false
	}
	for _, character := range value[4:] {
		if character >= '0' && character <= '9' || character >= 'a' && character <= 'f' {
			continue
		}
		return false
	}
	return true
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
	if strings.TrimSpace(payload.OutputID) == "" {
		return false
	}
	if eventType == EventResourcePartial {
		return payload.ResourceID == "" && payload.PartialBytes != nil && *payload.PartialBytes > 0 && payload.Resource == nil && validGeneratedMediaKind(payload.Kind) && strings.TrimSpace(payload.MIMEType) != ""
	}
	return payload.Kind == "" && payload.MIMEType == "" && payload.PartialBytes == nil && payload.Resource != nil && payload.Resource.ID == payload.ResourceID && payload.Resource.State == resource.StateReady
}

// validGeneratedMediaKind reports whether a progress event belongs to a generated binary family.
// validGeneratedMediaKind 报告进度事件是否属于生成二进制类别。
func validGeneratedMediaKind(kind vcp.MediaKind) bool {
	switch kind {
	case vcp.MediaImage, vcp.MediaAudio, vcp.MediaVideo, vcp.MediaFile:
		return true
	default:
		return false
	}
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
	if errModelTools := r.ModelToolPlan.Validate(r.Request, r.Target); errModelTools != nil {
		return errModelTools
	}
	if r.RouterToolLineage != nil {
		if errLineage := r.RouterToolLineage.Validate(); errLineage != nil {
			return errLineage
		}
	}
	if (r.Status == StatusFailed) != (r.Failure != nil) {
		return fmt.Errorf("%w: safe failure must exist only for failed execution", ErrInvalidExecution)
	}
	if r.Failure != nil {
		if errFailure := r.Failure.Validate(); errFailure != nil {
			return fmt.Errorf("%w: safe failure is invalid: %v", ErrInvalidExecution, errFailure)
		}
	}
	resultRequired := r.Status == StatusSucceeded || r.Status == StatusPartiallySucceeded
	if resultRequired != (r.Result != nil) {
		return fmt.Errorf("%w: result must exist only for successful or partially successful execution", ErrInvalidExecution)
	}
	if (r.Status == StatusWaitingRetry) != (r.Retry != nil) {
		return fmt.Errorf("%w: retry state must exist only while waiting_retry", ErrInvalidExecution)
	}
	if r.Retry != nil {
		if r.Request.DispatchMode != vcp.DispatchDeferred || r.Retry.ConsecutiveFailures == 0 || r.Retry.NextRetryAt.IsZero() || r.Retry.NextRetryAt.Before(r.CreatedAt) || strings.TrimSpace(r.Retry.Category) == "" || r.Retry.Scope == "" || r.Retry.Action == "" {
			return fmt.Errorf("%w: durable retry state is incomplete", ErrInvalidExecution)
		}
		if r.Retry.MaxAttempts != nil && *r.Retry.MaxAttempts <= uint32(len(r.Attempts)) {
			return fmt.Errorf("%w: durable retry exceeds configured attempts", ErrInvalidExecution)
		}
	}
	if r.RetryCycles > uint32(len(r.Attempts)) {
		return fmt.Errorf("%w: retry cycle count exceeds completed attempts", ErrInvalidExecution)
	}
	if r.ProviderTask != nil {
		task := r.ProviderTask
		if strings.TrimSpace(task.ProviderTaskID) == "" || task.Target.ProviderDefinitionID != r.Target.ProviderDefinitionID || task.Target.ProviderInstanceID != r.Target.ProviderInstanceID || task.Target.EndpointID != r.Target.EndpointID || task.Target.EndpointRegion != r.Target.EndpointRegion || task.Target.CredentialID != r.Target.CredentialID || task.Target.ActionBindingID != r.Target.ActionBindingID || task.Target.ProviderModelID != r.Target.ProviderModelID || task.Target.UpstreamModelID != r.Target.UpstreamModelID || task.Definition.ID != r.Target.ProviderDefinitionID || task.Endpoint.ID != r.Target.EndpointID || task.Endpoint.ProviderInstanceID != r.Target.ProviderInstanceID || task.Credential.ID != r.Target.CredentialID || task.Credential.ProviderInstanceID != r.Target.ProviderInstanceID {
			return fmt.Errorf("%w: provider task affinity does not match the immutable target", ErrInvalidExecution)
		}
		if task.CancellationRequestedAt != nil {
			if task.CancellationRequestedAt.IsZero() || task.CancellationRequestedAt.Before(r.CreatedAt) || task.CancellationAfter.IsZero() || task.CancellationAfter.Before(*task.CancellationRequestedAt) {
				return fmt.Errorf("%w: provider task cancellation intent is invalid", ErrInvalidExecution)
			}
		} else if !task.CancellationAfter.IsZero() || task.CancellationAttempts != 0 {
			return fmt.Errorf("%w: provider task cancellation state has no durable intent", ErrInvalidExecution)
		}
	}
	if r.ProviderPreparation != nil {
		preparation := r.ProviderPreparation
		if r.Operation != vcp.OperationMusicCoverPrepare || r.Status != StatusSucceeded || r.Result == nil || r.Result.MusicCoverPreparation == nil || r.Result.MusicCoverPreparation.PreparationID != r.ID || strings.TrimSpace(preparation.ProviderHandle) == "" || preparation.ExpiresAt.IsZero() || preparation.Target.ProviderDefinitionID != r.Target.ProviderDefinitionID || preparation.Target.ProviderInstanceID != r.Target.ProviderInstanceID || preparation.Target.EndpointID != r.Target.EndpointID || preparation.Target.EndpointRegion != r.Target.EndpointRegion || preparation.Target.CredentialID != r.Target.CredentialID || preparation.Target.UpstreamModelID != r.Target.UpstreamModelID {
			return fmt.Errorf("%w: provider preparation affinity does not match the successful cover preparation", ErrInvalidExecution)
		}
	}
	if r.ProviderContinuation != nil {
		continuation := r.ProviderContinuation
		if r.Operation != vcp.OperationConversationRespond || r.Status != StatusSucceeded || r.Result == nil || r.Result.Continuation == nil || r.Result.Continuation.ContinuationID != continuation.ContinuationID || strings.TrimSpace(continuation.ContinuationID) == "" || strings.TrimSpace(continuation.UpstreamResponseID) == "" || strings.TrimSpace(continuation.LogicalResponseID) == "" || continuation.CreatedAt.IsZero() || continuation.CreatedAt.Before(r.CreatedAt) || continuation.CreatedAt.After(r.UpdatedAt) || continuation.ExpiresAt.IsZero() || !continuation.ExpiresAt.After(continuation.CreatedAt) {
			return fmt.Errorf("%w: provider continuation requires one successful timestamped conversational result", ErrInvalidExecution)
		}
		if !continuation.LastUsedAt.IsZero() && (continuation.LastUsedAt.Before(continuation.CreatedAt) || continuation.LastUsedAt.After(r.UpdatedAt)) {
			return fmt.Errorf("%w: provider continuation last-used time is invalid", ErrInvalidExecution)
		}
		if continuation.InvalidatedAt.IsZero() != (continuation.InvalidationReason == "") {
			return fmt.Errorf("%w: provider continuation invalidation requires both time and reason", ErrInvalidExecution)
		}
		if !continuation.InvalidatedAt.IsZero() {
			if continuation.InvalidatedAt.Before(continuation.CreatedAt) || continuation.InvalidatedAt.After(r.UpdatedAt) || !validContinuationInvalidationReason(continuation.InvalidationReason) {
				return fmt.Errorf("%w: provider continuation invalidation is invalid", ErrInvalidExecution)
			}
		} else if !continuation.ExpiresAt.After(r.UpdatedAt) {
			return fmt.Errorf("%w: active provider continuation is expired", ErrInvalidExecution)
		}
		binding := provider.ContinuationBinding{ContinuationID: continuation.ContinuationID, ProviderDefinitionID: continuation.Target.ProviderDefinitionID, ProviderInstanceID: continuation.Target.ProviderInstanceID, ChannelID: continuation.Target.ChannelID, EndpointID: continuation.Target.EndpointID, CredentialID: continuation.Target.CredentialID, ProviderModelID: continuation.Target.ProviderModelID, UpstreamModelID: continuation.Target.UpstreamModelID, ExecutionProfileID: continuation.Target.ExecutionProfileID, UpstreamResponseID: continuation.UpstreamResponseID}
		if errBinding := binding.Validate(r.Target); errBinding != nil {
			return fmt.Errorf("%w: provider continuation affinity does not match the successful target", ErrInvalidExecution)
		}
	}
	for index, attempt := range r.Attempts {
		if attempt.Sequence != uint32(index+1) || attempt.StartedAt.IsZero() || attempt.EndedAt.Before(attempt.StartedAt) || attempt.Target.ProviderDefinitionID != r.Target.ProviderDefinitionID || attempt.Target.ProviderInstanceID != r.Target.ProviderInstanceID || attempt.Target.ProviderModelID != r.Target.ProviderModelID || attempt.Target.ProviderServiceID != r.Target.ProviderServiceID || attempt.Target.ExecutionProfileID != r.Target.ExecutionProfileID || attempt.Target.Operation != r.Operation {
			return fmt.Errorf("%w: provider execution attempt is invalid", ErrInvalidExecution)
		}
		if attempt.Succeeded && (attempt.FailureCategory != "" || attempt.RetryAction != "") {
			return fmt.Errorf("%w: successful provider attempt cannot carry failure classification", ErrInvalidExecution)
		}
		if attempt.Usage != nil {
			if errUsage := validateUsageObservation(*attempt.Usage); errUsage != nil {
				return fmt.Errorf("%w: provider execution attempt contains invalid usage: %v", ErrInvalidExecution, errUsage)
			}
		}
	}
	if r.Result != nil && r.Result.Usage != nil {
		if errUsage := validateUsageObservation(*r.Result.Usage); errUsage != nil {
			return fmt.Errorf("%w: execution result contains invalid usage: %v", ErrInvalidExecution, errUsage)
		}
	}
	return nil
}
