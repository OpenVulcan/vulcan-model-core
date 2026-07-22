package execution

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// staticResolver returns one exact immutable target and records resolution count.
// staticResolver 返回一个精确不可变 Target 并记录解析次数。
type staticResolver struct {
	// target is the exact deterministic destination.
	// target 是精确确定性目的地。
	target resolve.Target
	// calls counts mutable target resolution attempts.
	// calls 统计可变 Target 解析尝试次数。
	calls int
	// last records the exact most recent resolution constraints.
	// last 记录最近一次精确解析约束。
	last resolve.Request
	// err injects one exact target-resolution failure.
	// err 注入一个精确 Target 解析失败。
	err error
}

// Resolve returns the exact configured target.
// Resolve 返回精确配置 Target。
func (r *staticResolver) Resolve(_ context.Context, request resolve.Request) (resolve.Target, resolve.Diagnostics, error) {
	r.calls++
	r.last = request
	if r.err != nil {
		return resolve.Target{}, resolve.Diagnostics{}, r.err
	}
	return r.target, resolve.Diagnostics{ReadyCandidates: 1}, nil
}

// staticConfigurations returns exact endpoint, credential, and definition fixtures.
// staticConfigurations 返回精确 Endpoint、Credential 与 Definition 夹具。
type staticConfigurations struct {
	// definition is the immutable driver owner.
	// definition 是不可变 Driver 所有者。
	definition providerconfig.ProviderDefinition
	// endpoint is the exact ready destination.
	// endpoint 是精确就绪目的地。
	endpoint providerconfig.Endpoint
	// credential is the exact active credential metadata.
	// credential 是精确有效凭据元数据。
	credential providerconfig.Credential
}

// GetDefinition returns the exact definition fixture.
// GetDefinition 返回精确 Definition 夹具。
func (c staticConfigurations) GetDefinition(context.Context, string) (providerconfig.ProviderDefinition, error) {
	return c.definition, nil
}

// ListEndpoints returns the exact endpoint fixture.
// ListEndpoints 返回精确 Endpoint 夹具。
func (c staticConfigurations) ListEndpoints(context.Context, string) ([]providerconfig.Endpoint, error) {
	return []providerconfig.Endpoint{c.endpoint}, nil
}

// ListCredentials returns the exact credential fixture.
// ListCredentials 返回精确 Credential 夹具。
func (c staticConfigurations) ListCredentials(context.Context, string) ([]providerconfig.Credential, error) {
	return []providerconfig.Credential{c.credential}, nil
}

// recordingProviderExecutor records exact dispatch and returns a typed conversation result.
// recordingProviderExecutor 记录精确分派并返回类型化会话结果。
type recordingProviderExecutor struct {
	// calls counts provider side effects.
	// calls 统计供应商副作用次数。
	calls int
	// last records the exact immutable driver request.
	// last 记录精确不可变 Driver 请求。
	last provider.ExecutionRequest
}

// continuationProviderExecutor returns and consumes only an explicit target-bound continuation identifier.
// continuationProviderExecutor 仅返回并消费显式 Target 绑定续接标识。
type continuationProviderExecutor struct {
	// requests records both original and continued provider dispatches.
	// requests 记录原始与续接两次供应商分派。
	requests []provider.ExecutionRequest
	// rejectContinuation injects one explicit provider-owned continuation revocation.
	// rejectContinuation 注入一次明确的供应商续接撤销。
	rejectContinuation bool
}

// Execute creates provider continuation state on the first call and verifies it is resolved on the second call.
// Execute 在首次调用创建供应商续接状态，并在第二次调用校验该状态已解析。
func (e *continuationProviderExecutor) Execute(_ context.Context, request provider.ExecutionRequest) (provider.ExecutionResult, error) {
	e.requests = append(e.requests, request)
	if e.rejectContinuation && request.Continuation != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: fixture", provider.ErrContinuationRejected)
	}
	responseID := "response_original"
	upstreamID := "upstream_original"
	if len(e.requests) == 2 {
		if request.Continuation == nil || request.Continuation.ContinuationID != "exe_11111111111111111111111111111111" || request.Continuation.UpstreamResponseID != "upstream_original" {
			return provider.ExecutionResult{}, errors.New("resolved continuation is missing or changed")
		}
		responseID = "response_continued"
		upstreamID = "upstream_continued"
	}
	return provider.ExecutionResult{Response: vcp.Response{ResponseID: responseID, Status: vcp.ResponseCompleted}, UpstreamResponseID: upstreamID, ContinuationUpstreamResponseID: upstreamID}, nil
}

// blockingStreamingProviderExecutor emits one semantic event before waiting so tests can observe live durability.
// blockingStreamingProviderExecutor 在等待前发送一个语义事件，以便测试实时持久化。
type blockingStreamingProviderExecutor struct {
	// mu protects the provider dispatch count used to detect duplicate recovery side effects.
	// mu 保护用于检测恢复器重复副作用的供应商分派计数。
	mu sync.Mutex
	// calls counts exact provider dispatches.
	// calls 统计精确供应商分派次数。
	calls int
	// started closes after the first event has reached the durable sink.
	// started 在首个事件到达持久 Sink 后关闭。
	started chan struct{}
	// release permits the synthetic upstream stream to finish.
	// release 允许合成上游流结束。
	release chan struct{}
}

// Execute emits one response-start event, blocks, and then returns the complete replay sequence.
// Execute 发送一个响应开始事件、等待，然后返回完整重放序列。
func (e *blockingStreamingProviderExecutor) Execute(ctx context.Context, request provider.ExecutionRequest) (provider.ExecutionResult, error) {
	e.mu.Lock()
	e.calls++
	call := e.calls
	e.mu.Unlock()
	if call != 1 {
		return provider.ExecutionResult{}, errors.New("duplicate provider execution")
	}
	started := vcp.Event{ResponseID: "response_stream", EventID: "provider_stream_started", Sequence: 1, Time: request.Now, Replayable: true, Type: vcp.EventResponseStarted}
	if errEmit := provider.EmitExecutionEvents(ctx, request.EventSink, []vcp.Event{started}); errEmit != nil {
		return provider.ExecutionResult{}, errEmit
	}
	close(e.started)
	select {
	case <-ctx.Done():
		return provider.ExecutionResult{}, ctx.Err()
	case <-e.release:
	}
	completed := vcp.Event{ResponseID: "response_stream", EventID: "provider_stream_completed", Sequence: 2, Time: request.Now, Replayable: true, Type: vcp.EventResponseCompleted}
	return provider.ExecutionResult{Response: vcp.Response{ResponseID: "response_stream", Status: vcp.ResponseCompleted}, Events: []vcp.Event{started, completed}}, nil
}

// callCount returns the synchronized provider dispatch count.
// callCount 返回同步保护的供应商分派计数。
func (e *blockingStreamingProviderExecutor) callCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.calls
}

// testExecutionLease stores exact in-memory lease ownership for multi-service orchestration tests.
// testExecutionLease 为多服务编排测试保存精确的内存租约所有权。
type testExecutionLease struct {
	// ownerID is the current exclusive lease owner.
	// ownerID 是当前独占租约所有者。
	ownerID string
	// expiresAt is the exact takeover boundary.
	// expiresAt 是精确接管边界。
	expiresAt time.Time
}

// testExecutionLeaseStore implements atomic lease ownership for deterministic execution tests.
// testExecutionLeaseStore 为确定性执行测试实现原子租约所有权。
type testExecutionLeaseStore struct {
	// mu protects every lease transition.
	// mu 保护每次租约转换。
	mu sync.Mutex
	// leases maps execution identities to current owners.
	// leases 将执行身份映射到当前所有者。
	leases map[string]testExecutionLease
}

// AcquireLease creates, renews, or takes one expired test lease.
// AcquireLease 创建、续约或接管一个已过期测试租约。
func (s *testExecutionLeaseStore) AcquireLease(_ context.Context, executionID string, ownerID string, now time.Time, expiresAt time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.leases[executionID]
	if exists && current.ownerID != ownerID && current.expiresAt.After(now) {
		return false, nil
	}
	s.leases[executionID] = testExecutionLease{ownerID: ownerID, expiresAt: expiresAt}
	return true, nil
}

// RenewLease extends only one unexpired test lease owned by the exact caller.
// RenewLease 仅延长由精确调用方拥有且尚未过期的测试租约。
func (s *testExecutionLeaseStore) RenewLease(_ context.Context, executionID string, ownerID string, now time.Time, expiresAt time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.leases[executionID]
	if !exists || current.ownerID != ownerID || !current.expiresAt.After(now) {
		return false, nil
	}
	s.leases[executionID] = testExecutionLease{ownerID: ownerID, expiresAt: expiresAt}
	return true, nil
}

// ReleaseLease removes only the exact owner's test lease.
// ReleaseLease 仅删除精确所有者的测试租约。
func (s *testExecutionLeaseStore) ReleaseLease(_ context.Context, executionID string, ownerID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if current, exists := s.leases[executionID]; exists && current.ownerID == ownerID {
		delete(s.leases, executionID)
	}
	return nil
}

// sequenceResolver returns configured targets in order and records every retry constraint.
// sequenceResolver 按顺序返回配置 Target 并记录每个重试约束。
type sequenceResolver struct {
	// targets contains one target for each expected resolution.
	// targets 包含每次预期解析对应的 Target。
	targets []resolve.Target
	// requests records exact resolver inputs.
	// requests 记录精确 Resolver 输入。
	requests []resolve.Request
}

// Resolve returns the next configured same-provider target.
// Resolve 返回下一个已配置的同供应商 Target。
func (r *sequenceResolver) Resolve(_ context.Context, request resolve.Request) (resolve.Target, resolve.Diagnostics, error) {
	r.requests = append(r.requests, request)
	index := len(r.requests) - 1
	if index >= len(r.targets) {
		return resolve.Target{}, resolve.Diagnostics{}, resolve.ErrNoEligibleTarget
	}
	return r.targets[index], resolve.Diagnostics{ReadyCandidates: 1}, nil
}

// multiConfigurations returns exact snapshots for failover targets.
// multiConfigurations 返回故障切换 Target 的精确快照。
type multiConfigurations struct {
	// definition is the shared immutable driver owner.
	// definition 是共享的不可变 Driver 所有者。
	definition providerconfig.ProviderDefinition
	// endpoints contains every eligible same-instance endpoint.
	// endpoints 包含所有合格的同实例入口。
	endpoints []providerconfig.Endpoint
	// credentials contains every eligible same-instance credential.
	// credentials 包含所有合格的同实例凭据。
	credentials []providerconfig.Credential
}

// GetDefinition returns the shared definition.
// GetDefinition 返回共享 Definition。
func (c multiConfigurations) GetDefinition(context.Context, string) (providerconfig.ProviderDefinition, error) {
	return c.definition, nil
}

// ListEndpoints returns copied endpoint snapshots.
// ListEndpoints 返回复制的 Endpoint 快照。
func (c multiConfigurations) ListEndpoints(context.Context, string) ([]providerconfig.Endpoint, error) {
	return append([]providerconfig.Endpoint(nil), c.endpoints...), nil
}

// ListCredentials returns copied credential snapshots.
// ListCredentials 返回复制的 Credential 快照。
func (c multiConfigurations) ListCredentials(context.Context, string) ([]providerconfig.Credential, error) {
	return append([]providerconfig.Credential(nil), c.credentials...), nil
}

// failoverProviderExecutor fails its first dispatch with one trusted classification and then succeeds.
// failoverProviderExecutor 使用可信分类使首次分派失败，随后成功。
type failoverProviderExecutor struct {
	// action controls the exact same-provider retry mode.
	// action 控制精确的同供应商重试模式。
	action provider.RetryAction
	// semanticOnFailure returns provider-accepted state alongside the first failure.
	// semanticOnFailure 在首次失败时同时返回供应商已接收状态。
	semanticOnFailure bool
	// requests records exact dispatch targets.
	// requests 记录精确分派 Target。
	requests []provider.ExecutionRequest
}

// durableRetryProviderExecutor fails one dispatch and then succeeds on the same immutable target.
// durableRetryProviderExecutor 在同一不可变 Target 上使一次分派失败，随后成功。
type durableRetryProviderExecutor struct {
	// requests records every scheduler dispatch.
	// requests 记录每次调度器分派。
	requests []provider.ExecutionRequest
	// failAlways keeps every dispatch in the same classified failure path.
	// failAlways 使每次分派都保持在相同的分类失败路径。
	failAlways bool
}

// Execute returns one pre-semantic transient failure followed by a valid response.
// Execute 返回一次产生语义输出前的瞬态失败，随后返回有效响应。
func (e *durableRetryProviderExecutor) Execute(_ context.Context, request provider.ExecutionRequest) (provider.ExecutionResult, error) {
	e.requests = append(e.requests, request)
	if len(e.requests) == 1 || e.failAlways {
		return provider.ExecutionResult{}, errors.New("transient test failure")
	}
	return provider.ExecutionResult{Response: vcp.Response{ResponseID: "response_retry", Status: vcp.ResponseCompleted}}, nil
}

// TestDeferredExecutionEmitsRetryAbortOnClassifiedTerminalFailure verifies classified exhaustion closes retry event history.
// TestDeferredExecutionEmitsRetryAbortOnClassifiedTerminalFailure 验证分类错误耗尽时会关闭重试事件历史。
func TestDeferredExecutionEmitsRetryAbortOnClassifiedTerminalFailure(t *testing.T) {
	now := time.Date(2026, 7, 21, 16, 30, 0, 0, time.UTC)
	target := resolve.Target{ProviderDefinitionID: "definition_retry_abort", ProviderInstanceID: "pvi_retry_abort", ChannelID: "channel_retry_abort", EndpointID: "endpoint_retry_abort", EndpointRegion: "global", CredentialID: "credential_retry_abort", SubjectKind: resolve.ExecutionSubjectModel, ProviderModelID: "model_retry_abort", OfferingID: "offering_retry_abort", Operation: vcp.OperationConversationRespond, ActionBindingID: "action_retry_abort", ExecutionProfileID: "profile_retry_abort", UpstreamModelID: "upstream_retry_abort", ModelCapabilities: conversationTestCapabilities(true, false), CapabilityRevision: 1, ProviderConfigRevision: 1, CatalogRevision: 1}
	resolver := &staticResolver{target: target}
	configurations := staticConfigurations{definition: providerconfig.ProviderDefinition{ID: target.ProviderDefinitionID}, endpoint: providerconfig.Endpoint{ID: target.EndpointID, ProviderInstanceID: target.ProviderInstanceID, ChannelID: target.ChannelID, BaseURL: "https://provider.example", Region: target.EndpointRegion, Status: providerconfig.EndpointReady, Revision: 1}, credential: providerconfig.Credential{ID: target.CredentialID, ProviderInstanceID: target.ProviderInstanceID, Status: providerconfig.CredentialActive, Revision: 1}}
	executor := &durableRetryProviderExecutor{failAlways: true}
	store := NewMemoryStore()
	service, errService := NewService(store, resolver, configurations, nil, nil, executor, ServiceOptions{NewID: func() (string, error) { return "exe_45454545454545454545454545454545", nil }, Now: func() time.Time { return now }, Retention: time.Hour})
	if errService != nil {
		t.Fatalf("NewService() error = %v", errService)
	}
	maximumAttempts := uint32(2)
	request := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request_retry_abort", DispatchMode: vcp.DispatchDeferred, Target: vcp.TargetSelection{Model: &vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: target.ProviderInstanceID, ProviderModelID: target.ProviderModelID, ExecutionProfileID: target.ExecutionProfileID}}, Operation: vcp.OperationConversationRespond, Payload: vcp.OperationPayload{Conversation: &vcp.ConversationOperation{}}, RetryPolicy: &vcp.RetryPolicy{MaxAttempts: &maximumAttempts}}
	accepted, _, errCreate := service.Create(context.Background(), "owner_retry_abort", request)
	if errCreate != nil {
		t.Fatalf("Create() error = %v", errCreate)
	}
	if errRecover := service.RecoverOnce(context.Background()); errRecover != nil {
		t.Fatalf("first RecoverOnce() error = %v", errRecover)
	}
	now = now.Add(5 * time.Second)
	if errRecover := service.RecoverOnce(context.Background()); errRecover != nil {
		t.Fatalf("second RecoverOnce() error = %v", errRecover)
	}
	failed, errFailed := service.Get(context.Background(), "owner_retry_abort", accepted.ID)
	if errFailed != nil || failed.Status != StatusFailed || failed.Failure == nil || failed.Failure.Category != "transient_upstream" || len(executor.requests) != 2 {
		t.Fatalf("failed record = %+v, requests = %d, error = %v", failed, len(executor.requests), errFailed)
	}
	events, errEvents := service.Events(context.Background(), "owner_retry_abort", accepted.ID, 0)
	if errEvents != nil || !containsExecutionEventType(events, EventRetryScheduled) || !containsExecutionEventType(events, EventRetryStarted) || !containsExecutionEventType(events, EventRetryAborted) {
		t.Fatalf("retry events = %+v, error = %v", events, errEvents)
	}
}

// ClassifyExecutionError returns an exact same-target transient retry classification.
// ClassifyExecutionError 返回精确的相同 Target 瞬态重试分类。
func (e *durableRetryProviderExecutor) ClassifyExecutionError(request provider.ExecutionRequest, _ error) (provider.ClassifiedError, bool) {
	retryAt := request.Now.Add(5 * time.Second)
	return provider.ClassifiedError{Category: "transient_upstream", Scope: provider.ErrorScopeEndpoint, Action: provider.RetrySameTarget, RetryAt: &retryAt, RuleID: "test_durable_retry"}, true
}

// Execute returns one safe first failure and a valid terminal response on the next call.
// Execute 返回一次安全的首次失败，并在下一次调用返回有效终态响应。
func (e *failoverProviderExecutor) Execute(_ context.Context, request provider.ExecutionRequest) (provider.ExecutionResult, error) {
	e.requests = append(e.requests, request)
	if len(e.requests) == 1 {
		result := provider.ExecutionResult{}
		if e.semanticOnFailure {
			result.Response = vcp.Response{ResponseID: "response_partial", Status: vcp.ResponseInProgress}
		}
		return result, errors.New("safe synthetic provider failure")
	}
	return provider.ExecutionResult{Response: vcp.Response{ResponseID: "response_failover", Status: vcp.ResponseCompleted}, Events: []vcp.Event{{ResponseID: "response_failover", EventID: "event_failover", Sequence: 1, Time: request.Now, Replayable: true, Type: vcp.EventResponseCompleted}}}, nil
}

// ClassifyExecutionError returns the exact trusted retry action for the synthetic failure.
// ClassifyExecutionError 为合成失败返回精确的可信重试动作。
func (e *failoverProviderExecutor) ClassifyExecutionError(provider.ExecutionRequest, error) (provider.ClassifiedError, bool) {
	return provider.ClassifiedError{Category: "synthetic_transient", Scope: provider.ErrorScopeCredential, Action: e.action, RuleID: "test_synthetic"}, true
}

// recordingTaskProviderExecutor returns a queued task followed by success and records persisted affinity.
// recordingTaskProviderExecutor 返回先排队后成功的任务并记录持久化亲和性。
type recordingTaskProviderExecutor struct {
	// starts counts upstream task creation.
	// starts 统计上游任务创建次数。
	starts int
	// startRequest records the Router-owned upstream replay identity.
	// startRequest 记录 Router 所有的上游重放身份。
	startRequest provider.ExecutionRequest
	// polls counts upstream task polling.
	// polls 统计上游任务轮询次数。
	polls int
	// queuedPolls returns provider-queued observations before the terminal success fixture.
	// queuedPolls 在终态成功夹具前返回供应商排队观测。
	queuedPolls int
	// pollRequest records the immutable recovered request.
	// pollRequest 记录不可变恢复请求。
	pollRequest provider.ExecutionRequest
	// cancellations counts upstream task cancellation requests.
	// cancellations 统计上游任务取消请求次数。
	cancellations int
	// cancellationRequest records the immutable recovered cancellation request.
	// cancellationRequest 记录不可变的恢复取消请求。
	cancellationRequest provider.ExecutionRequest
}

// blockingCancellationTaskProviderExecutor exposes the exact point at which an upstream cancellation begins.
// blockingCancellationTaskProviderExecutor 暴露上游取消开始的精确时点。
type blockingCancellationTaskProviderExecutor struct {
	// cancellationStarted closes after the Router invokes the upstream cancellation method.
	// cancellationStarted 在 Router 调用上游取消方法后关闭。
	cancellationStarted chan struct{}
	// cancellationRelease allows the test to complete the upstream cancellation response.
	// cancellationRelease 允许测试完成上游取消响应。
	cancellationRelease chan struct{}
}

// Execute reports misuse of the synchronous path.
// Execute 报告同步路径误用。
func (e *blockingCancellationTaskProviderExecutor) Execute(context.Context, provider.ExecutionRequest) (provider.ExecutionResult, error) {
	return provider.ExecutionResult{}, errors.New("synchronous path must not be used")
}

// StartTask returns one queued provider task.
// StartTask 返回一个排队中的供应商任务。
func (e *blockingCancellationTaskProviderExecutor) StartTask(_ context.Context, request provider.ExecutionRequest) (provider.TaskResult, error) {
	return provider.TaskResult{ProviderTaskID: "provider_task_cancel_intent", State: provider.TaskQueued, PollAfter: request.Now.Add(time.Minute)}, nil
}

// PollTask reports misuse while the cancellation test owns the task.
// PollTask 报告取消测试拥有任务期间的轮询误用。
func (e *blockingCancellationTaskProviderExecutor) PollTask(context.Context, provider.ExecutionRequest, string) (provider.TaskResult, error) {
	return provider.TaskResult{}, errors.New("poll must not be used")
}

// CancelTask blocks until the test has inspected the already persisted cancellation intent.
// CancelTask 阻塞到测试检查已经持久化的取消意图为止。
func (e *blockingCancellationTaskProviderExecutor) CancelTask(_ context.Context, _ provider.ExecutionRequest, providerTaskID string) (provider.TaskResult, error) {
	close(e.cancellationStarted)
	<-e.cancellationRelease
	return provider.TaskResult{ProviderTaskID: providerTaskID, State: provider.TaskCancelled}, nil
}

// failoverTaskProviderExecutor fails one task start and records whether accepted provider state was returned.
// failoverTaskProviderExecutor 使一次任务创建失败并记录是否返回供应商已接收状态。
type failoverTaskProviderExecutor struct {
	// acceptedOnFailure includes a provider task identifier with the first error.
	// acceptedOnFailure 在首次错误中包含供应商任务标识。
	acceptedOnFailure bool
	// starts records exact task creation requests.
	// starts 记录精确任务创建请求。
	starts []provider.ExecutionRequest
}

// Execute reports misuse of the synchronous path.
// Execute 报告同步路径误用。
func (e *failoverTaskProviderExecutor) Execute(context.Context, provider.ExecutionRequest) (provider.ExecutionResult, error) {
	return provider.ExecutionResult{}, errors.New("synchronous path must not be used")
}

// StartTask fails first and returns a valid queued task if a safe retry occurs.
// StartTask 首次失败，并在安全重试发生时返回有效排队任务。
func (e *failoverTaskProviderExecutor) StartTask(_ context.Context, request provider.ExecutionRequest) (provider.TaskResult, error) {
	e.starts = append(e.starts, request)
	if len(e.starts) == 1 {
		if e.acceptedOnFailure {
			return provider.TaskResult{ProviderTaskID: "provider_task_already_created", State: provider.TaskQueued, PollAfter: request.Now.Add(time.Second)}, errors.New("task start response interrupted")
		}
		return provider.TaskResult{}, errors.New("task start transport failure")
	}
	return provider.TaskResult{ProviderTaskID: "provider_task_retried", State: provider.TaskQueued, PollAfter: request.Now.Add(time.Second)}, nil
}

// PollTask reports misuse by this start-only test executor.
// PollTask 报告该仅测试创建流程的执行器被误用于轮询。
func (e *failoverTaskProviderExecutor) PollTask(context.Context, provider.ExecutionRequest, string) (provider.TaskResult, error) {
	return provider.TaskResult{}, errors.New("poll must not be used")
}

// CancelTask reports misuse by this start-only test executor.
// CancelTask 报告该仅测试创建流程的执行器被误用于取消。
func (e *failoverTaskProviderExecutor) CancelTask(context.Context, provider.ExecutionRequest, string) (provider.TaskResult, error) {
	return provider.TaskResult{}, errors.New("cancel must not be used")
}

// ClassifyExecutionError permits switching only to another credential in the same provider instance.
// ClassifyExecutionError 仅允许切换到同一供应商实例中的另一凭据。
func (e *failoverTaskProviderExecutor) ClassifyExecutionError(provider.ExecutionRequest, error) (provider.ClassifiedError, bool) {
	return provider.ClassifiedError{Category: "task_start_transient", Scope: provider.ErrorScopeCredential, Action: provider.RetryOtherCredential, RuleID: "test_task_start"}, true
}

// Execute reports misuse of the synchronous path.
// Execute 报告同步路径误用。
func (e *recordingTaskProviderExecutor) Execute(context.Context, provider.ExecutionRequest) (provider.ExecutionResult, error) {
	return provider.ExecutionResult{}, errors.New("synchronous path must not be used")
}

// StartTask returns one provider-confirmed queued task.
// StartTask 返回一个供应商确认排队任务。
func (e *recordingTaskProviderExecutor) StartTask(_ context.Context, request provider.ExecutionRequest) (provider.TaskResult, error) {
	e.starts++
	e.startRequest = request
	return provider.TaskResult{ProviderTaskID: "provider_task_secret", State: provider.TaskQueued, PollAfter: request.Now}, nil
}

// PollTask returns one typed successful result using the same task identifier.
// PollTask 使用同一任务标识返回一个类型化成功结果。
func (e *recordingTaskProviderExecutor) PollTask(_ context.Context, request provider.ExecutionRequest, providerTaskID string) (provider.TaskResult, error) {
	e.polls++
	e.pollRequest = request
	if e.polls <= e.queuedPolls {
		return provider.TaskResult{ProviderTaskID: providerTaskID, State: provider.TaskQueued, PollAfter: request.Now}, nil
	}
	result := provider.ExecutionResult{Response: vcp.Response{ResponseID: "response_async", Status: vcp.ResponseCompleted}}
	return provider.TaskResult{ProviderTaskID: providerTaskID, State: provider.TaskSucceeded, Result: &result}, nil
}

// CancelTask returns one provider-confirmed cancelled task.
// CancelTask 返回一个供应商确认取消任务。
func (e *recordingTaskProviderExecutor) CancelTask(_ context.Context, request provider.ExecutionRequest, providerTaskID string) (provider.TaskResult, error) {
	e.cancellations++
	e.cancellationRequest = request
	return provider.TaskResult{ProviderTaskID: providerTaskID, State: provider.TaskCancelled}, nil
}

// Execute returns one completed conversation response and a real provider semantic event.
// Execute 返回一个已完成会话响应与一个真实供应商语义事件。
func (e *recordingProviderExecutor) Execute(_ context.Context, request provider.ExecutionRequest) (provider.ExecutionResult, error) {
	e.calls++
	e.last = request
	now := request.Now
	return provider.ExecutionResult{
		Response: vcp.Response{ResponseID: "response_test", Status: vcp.ResponseCompleted},
		Events:   []vcp.Event{{ResponseID: "response_test", EventID: "provider_event_test", Sequence: 1, Time: now, Replayable: true, Type: vcp.EventResponseCompleted}},
	}, nil
}

// TestValidateConversationMediaRequiresExplicitMediaOnlyPolicy verifies media-only turns cannot silently inherit a prompt.
// TestValidateConversationMediaRequiresExplicitMediaOnlyPolicy 验证仅媒体轮次不能静默继承提示词。
func TestValidateConversationMediaRequiresExplicitMediaOnlyPolicy(t *testing.T) {
	target := mediaValidationTarget(vcp.OperationConversationRespond)
	operation := &vcp.ConversationOperation{Context: []vcp.ContextItem{{ItemID: "item-image", Sequence: 1, Kind: vcp.ContextMessage, Authority: vcp.AuthorityUser, Actor: vcp.ActorEndUser, Placement: vcp.PlacementTranscript, Activation: vcp.Activation{Mode: vcp.ActivationRequestStart}, Visibility: vcp.VisibilityModel, Content: []vcp.ContentBlock{{Type: vcp.ContentImage, ResourceRef: "resource-image", MediaRole: vcp.MediaRoleUnderstanding}}, Message: &vcp.MessageItem{}}}}
	request := vcp.ExecutionRequest{Operation: vcp.OperationConversationRespond, Payload: vcp.OperationPayload{Conversation: operation}}
	if errValidate := validateRequestAgainstTarget(request, target); !errors.Is(errValidate, vcp.ErrInvalidRequest) {
		t.Fatalf("validateRequestAgainstTarget() error = %v, want ErrInvalidRequest", errValidate)
	}
	operation.MediaOnlyMode = vcp.MediaOnlyConversationUseProfilePolicy
	if errValidate := validateRequestAgainstTarget(request, target); errValidate != nil {
		t.Fatalf("validateRequestAgainstTarget() error = %v", errValidate)
	}
}

// TestValidateMediaAnalyzeRejectsUndeclaredRole verifies dedicated analysis cannot reuse a reference-only semantic role.
// TestValidateMediaAnalyzeRejectsUndeclaredRole 验证专用分析不能复用仅供参考的语义角色。
func TestValidateMediaAnalyzeRejectsUndeclaredRole(t *testing.T) {
	target := mediaValidationTarget(vcp.OperationMediaAnalyze)
	operation := &vcp.MediaAnalyzeOperation{Task: vcp.MediaAnalyzeDescribe, Inputs: []vcp.MediaInput{{ID: "image", Kind: vcp.MediaImage, Role: vcp.MediaRoleReference, Resource: vcp.ResourceReference{ResourceID: "resource-image"}}}}
	request := vcp.ExecutionRequest{Operation: vcp.OperationMediaAnalyze, Payload: vcp.OperationPayload{MediaAnalyze: operation}}
	if errValidate := validateRequestAgainstTarget(request, target); !errors.Is(errValidate, vcp.ErrInvalidRequest) {
		t.Fatalf("validateRequestAgainstTarget() error = %v, want ErrInvalidRequest", errValidate)
	}
}

// mediaValidationTarget returns one valid image-understanding contract for request admission tests.
// mediaValidationTarget 返回一个用于请求接收测试的有效图片理解合同。
func mediaValidationTarget(operation vcp.OperationKind) resolve.Target {
	evidenceTime := time.Date(2026, time.July, 20, 0, 0, 0, 0, time.UTC)
	capability := catalog.MediaInputCapability{Kind: vcp.MediaImage, Roles: []vcp.MediaInputRole{vcp.MediaRoleUnderstanding}, Level: catalog.CapabilityNative, InteractionModes: []catalog.MediaInteractionMode{catalog.MediaInteractionMixedConversation, catalog.MediaInteractionMediaOnlyConversation, catalog.MediaInteractionAnalysis}, MediaOnlyPolicy: catalog.MediaOnlyRouterInstruction, AllowedAuthorities: []vcp.Authority{vcp.AuthorityUser}, AllowedPlacements: []vcp.Placement{vcp.PlacementTranscript}, ClientWorkflows: []catalog.ClientResourceWorkflow{catalog.ClientWorkflowUploadThenReference}, MaterializationModes: []catalog.UpstreamMaterializationMode{catalog.MaterializationInlineBase64}, Image: &catalog.ImageMediaLimits{}, Compatibility: catalog.MediaCompatibility{ToolCalling: catalog.CapabilityNative, Streaming: catalog.CapabilityNative, Reasoning: catalog.CapabilityNative, StructuredOutput: catalog.CapabilityNative}, Evidence: []catalog.CapabilityEvidence{{Source: catalog.ModelSourceSystem, Reference: "test-media-contract", ObservedAt: evidenceTime, Revision: 1}}, EvidenceRevision: 1}
	return resolve.Target{SubjectKind: resolve.ExecutionSubjectModel, Operation: operation, ModelCapabilities: catalog.ModelCapabilities{Delivery: catalog.DeliveryCapabilities{Synchronous: true, Streaming: true}, MediaInputs: []catalog.MediaInputCapability{capability}}}
}

// TestServiceExecutesOnceAndReplaysBeforeMutableResolution verifies durable exactly-once admission semantics.
// TestServiceExecutesOnceAndReplaysBeforeMutableResolution 验证持久化一次性接收语义。
func TestServiceExecutesOnceAndReplaysBeforeMutableResolution(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	target := resolve.Target{ProviderDefinitionID: "definition_test", ProviderInstanceID: "pvi_test", ChannelID: "channel_test", EndpointID: "endpoint_test", EndpointRegion: "region_test", CredentialID: "credential_test", SubjectKind: resolve.ExecutionSubjectModel, ProviderModelID: "model_test", OfferingID: "offering_test", Operation: vcp.OperationConversationRespond, ActionBindingID: "action_test", ExecutionProfileID: "profile_test", UpstreamModelID: "upstream_test", ModelCapabilities: conversationTestCapabilities(true, false), CapabilityRevision: 1, ProviderConfigRevision: 1, CatalogRevision: 1}
	resolver := &staticResolver{target: target}
	configurations := staticConfigurations{
		definition: providerconfig.ProviderDefinition{ID: target.ProviderDefinitionID},
		endpoint:   providerconfig.Endpoint{ID: target.EndpointID, ProviderInstanceID: target.ProviderInstanceID, ChannelID: target.ChannelID, BaseURL: "https://provider.example", Region: target.EndpointRegion, Status: providerconfig.EndpointReady, Revision: 1},
		credential: providerconfig.Credential{ID: target.CredentialID, ProviderInstanceID: target.ProviderInstanceID, Status: providerconfig.CredentialActive, Revision: 1},
	}
	executor := &recordingProviderExecutor{}
	service, errService := NewService(NewMemoryStore(), resolver, configurations, nil, nil, executor, ServiceOptions{NewID: func() (string, error) { return "exe_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil }, Now: func() time.Time { return now }, Retention: time.Hour})
	if errService != nil {
		t.Fatalf("create service: %v", errService)
	}
	request := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request_test", IdempotencyKey: "idem_test", Target: vcp.TargetSelection{Model: &vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: target.ProviderInstanceID, ProviderModelID: target.ProviderModelID, ExecutionProfileID: target.ExecutionProfileID}}, Operation: vcp.OperationConversationRespond, Payload: vcp.OperationPayload{Conversation: &vcp.ConversationOperation{}}}
	created, replayed, errCreate := service.Create(context.Background(), "api_test", request)
	if errCreate != nil || replayed || created.Status != StatusSucceeded || created.Result == nil || created.Result.Conversation == nil {
		t.Fatalf("create record=%+v replayed=%t error=%v", created, replayed, errCreate)
	}
	if executor.calls != 1 || resolver.calls != 1 || executor.last.Binding.Target.CredentialID != target.CredentialID || executor.last.Execution == nil {
		t.Fatalf("dispatch calls=%d resolutions=%d request=%+v", executor.calls, resolver.calls, executor.last)
	}
	replay, replayed, errReplay := service.Create(context.Background(), "api_test", request)
	if errReplay != nil || !replayed || replay.ID != created.ID || executor.calls != 1 || resolver.calls != 1 {
		t.Fatalf("replay=%+v replayed=%t error=%v calls=%d resolutions=%d", replay, replayed, errReplay, executor.calls, resolver.calls)
	}
	events, errEvents := service.Events(context.Background(), "api_test", created.ID, 0)
	if errEvents != nil || len(events) != 4 || events[0].Type != EventExecutionAccepted || events[1].Type != EventExecutionRunning || events[2].Type != EventProviderSemantic || events[3].Type != EventExecutionSucceeded {
		t.Fatalf("events=%+v error=%v", events, errEvents)
	}
	conflicting := request
	conflicting.RequestID = "different_request"
	if _, _, errConflict := service.Create(context.Background(), "api_test", conflicting); !errors.Is(errConflict, ErrIdempotencyConflict) {
		t.Fatalf("conflicting replay error=%v", errConflict)
	}
}

// TestServicePersistsAndResolvesOwnerScopedContinuation verifies public Router identifiers never replace protected upstream state on the wire.
// TestServicePersistsAndResolvesOwnerScopedContinuation 验证公开 Router 标识绝不会在 Wire 上替代受保护上游状态。
func TestServicePersistsAndResolvesOwnerScopedContinuation(t *testing.T) {
	now := time.Date(2026, 7, 21, 13, 0, 0, 0, time.UTC)
	target := resolve.Target{ProviderDefinitionID: "definition_continuation", ProviderInstanceID: "pvi_continuation", ChannelID: "openai.responses", EndpointID: "endpoint_continuation", EndpointRegion: "global", CredentialID: "credential_continuation", SubjectKind: resolve.ExecutionSubjectModel, ProviderModelID: "model_continuation", OfferingID: "offering_continuation", Operation: vcp.OperationConversationRespond, ActionBindingID: "action_continuation", ExecutionProfileID: "profile_continuation", UpstreamModelID: "upstream_model", ModelCapabilities: conversationTestCapabilities(true, false), CapabilityRevision: 1, ProviderConfigRevision: 1, CatalogRevision: 1}
	resolver := &staticResolver{target: target}
	configurations := staticConfigurations{
		definition: providerconfig.ProviderDefinition{ID: target.ProviderDefinitionID},
		endpoint:   providerconfig.Endpoint{ID: target.EndpointID, ProviderInstanceID: target.ProviderInstanceID, ChannelID: target.ChannelID, BaseURL: "https://provider.example", Region: target.EndpointRegion, Status: providerconfig.EndpointReady, Revision: 1},
		credential: providerconfig.Credential{ID: target.CredentialID, ProviderInstanceID: target.ProviderInstanceID, Status: providerconfig.CredentialActive, Revision: 1},
	}
	executor := &continuationProviderExecutor{}
	identifiers := []string{"exe_11111111111111111111111111111111", "exe_22222222222222222222222222222222"}
	store := NewMemoryStore()
	service, errService := NewService(store, resolver, configurations, nil, nil, executor, ServiceOptions{NewID: func() (string, error) {
		identifier := identifiers[0]
		identifiers = identifiers[1:]
		return identifier, nil
	}, Now: func() time.Time { return now }, Retention: time.Hour})
	if errService != nil {
		t.Fatalf("NewService() error = %v", errService)
	}
	selection := &vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: target.ProviderInstanceID, ProviderModelID: target.ProviderModelID, ExecutionProfileID: target.ExecutionProfileID}
	firstRequest := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request_original", Target: vcp.TargetSelection{Model: selection}, Operation: vcp.OperationConversationRespond, Payload: vcp.OperationPayload{Conversation: &vcp.ConversationOperation{}}}
	first, _, errFirst := service.Create(context.Background(), "owner_continuation", firstRequest)
	if errFirst != nil || first.Result == nil || first.Result.Continuation == nil || first.Result.Continuation.ContinuationID != first.ID || first.ProviderContinuation == nil || first.ProviderContinuation.UpstreamResponseID != "upstream_original" {
		t.Fatalf("first execution=%+v error=%v", first, errFirst)
	}
	now = now.Add(time.Minute)
	continuedRequest := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request_continued", Target: vcp.TargetSelection{Model: selection}, Operation: vcp.OperationConversationRespond, Payload: vcp.OperationPayload{Conversation: &vcp.ConversationOperation{ReasoningPolicy: vcp.ReasoningPolicy{ContinuationID: first.ID}}}}
	continued, _, errContinued := service.Create(context.Background(), "owner_continuation", continuedRequest)
	if errContinued != nil || continued.Status != StatusSucceeded || len(executor.requests) != 2 || executor.requests[1].Continuation == nil {
		t.Fatalf("continued execution=%+v requests=%d error=%v", continued, len(executor.requests), errContinued)
	}
	if resolver.last.RequiredCredentialID != target.CredentialID || resolver.last.RequiredEndpointID != target.EndpointID {
		t.Fatalf("continuation resolution constraints=%+v", resolver.last)
	}
	touched, errTouched := store.Get(context.Background(), "owner_continuation", first.ID)
	if errTouched != nil || touched.ProviderContinuation == nil || !touched.ProviderContinuation.LastUsedAt.Equal(now) || touched.Revision != first.Revision+1 {
		t.Fatalf("touched continuation=%+v revision=%d error=%v", touched.ProviderContinuation, touched.Revision, errTouched)
	}
	if _, _, errForeign := service.Create(context.Background(), "foreign_owner", continuedRequest); !errors.Is(errForeign, vcp.ErrInvalidRequest) {
		t.Fatalf("foreign continuation error=%v, want ErrInvalidRequest", errForeign)
	}
	now = first.ExpiresAt
	if _, _, errExpired := service.Create(context.Background(), "owner_continuation", continuedRequest); !errors.Is(errExpired, vcp.ErrInvalidRequest) {
		t.Fatalf("expired continuation error=%v, want ErrInvalidRequest", errExpired)
	}
	invalidated, errInvalidated := store.Get(context.Background(), "owner_continuation", first.ID)
	if errInvalidated != nil || invalidated.ProviderContinuation == nil || invalidated.ProviderContinuation.InvalidationReason != ContinuationInvalidatedExpired || !invalidated.ProviderContinuation.InvalidatedAt.Equal(now) {
		t.Fatalf("invalidated continuation=%+v error=%v", invalidated.ProviderContinuation, errInvalidated)
	}
}

// TestServiceInvalidatesContinuationAfterConfigurationDeletion verifies a deleted exact target permanently closes its continuation.
// TestServiceInvalidatesContinuationAfterConfigurationDeletion 验证删除精确 Target 后会永久关闭其 Continuation。
func TestServiceInvalidatesContinuationAfterConfigurationDeletion(t *testing.T) {
	now := time.Date(2026, 7, 21, 14, 0, 0, 0, time.UTC)
	target := resolve.Target{ProviderDefinitionID: "definition_continuation", ProviderInstanceID: "pvi_continuation", ChannelID: "openai.responses", EndpointID: "endpoint_continuation", EndpointRegion: "global", CredentialID: "credential_continuation", SubjectKind: resolve.ExecutionSubjectModel, ProviderModelID: "model_continuation", OfferingID: "offering_continuation", Operation: vcp.OperationConversationRespond, ActionBindingID: "action_continuation", ExecutionProfileID: "profile_continuation", UpstreamModelID: "upstream_model", ModelCapabilities: conversationTestCapabilities(true, false), CapabilityRevision: 1, ProviderConfigRevision: 1, CatalogRevision: 1}
	resolver := &staticResolver{target: target}
	configurations := staticConfigurations{
		definition: providerconfig.ProviderDefinition{ID: target.ProviderDefinitionID},
		endpoint:   providerconfig.Endpoint{ID: target.EndpointID, ProviderInstanceID: target.ProviderInstanceID, ChannelID: target.ChannelID, BaseURL: "https://provider.example", Region: target.EndpointRegion, Status: providerconfig.EndpointReady, Revision: 1},
		credential: providerconfig.Credential{ID: target.CredentialID, ProviderInstanceID: target.ProviderInstanceID, Status: providerconfig.CredentialActive, Revision: 1},
	}
	executor := &continuationProviderExecutor{}
	store := NewMemoryStore()
	service, errService := NewService(store, resolver, configurations, nil, nil, executor, ServiceOptions{NewID: func() (string, error) { return "exe_11111111111111111111111111111111", nil }, Now: func() time.Time { return now }, Retention: time.Hour})
	if errService != nil {
		t.Fatalf("NewService() error = %v", errService)
	}
	selection := &vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: target.ProviderInstanceID, ProviderModelID: target.ProviderModelID, ExecutionProfileID: target.ExecutionProfileID}
	firstRequest := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request_original", Target: vcp.TargetSelection{Model: selection}, Operation: vcp.OperationConversationRespond, Payload: vcp.OperationPayload{Conversation: &vcp.ConversationOperation{}}}
	first, _, errFirst := service.Create(context.Background(), "owner_continuation", firstRequest)
	if errFirst != nil || first.ProviderContinuation == nil {
		t.Fatalf("first execution=%+v error=%v", first, errFirst)
	}
	now = now.Add(time.Minute)
	resolver.err = providerconfig.ErrNotFound
	continuedRequest := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request_deleted_target", Target: vcp.TargetSelection{Model: selection}, Operation: vcp.OperationConversationRespond, Payload: vcp.OperationPayload{Conversation: &vcp.ConversationOperation{ReasoningPolicy: vcp.ReasoningPolicy{ContinuationID: first.ID}}}}
	if _, _, errContinued := service.Create(context.Background(), "owner_continuation", continuedRequest); !errors.Is(errContinued, providerconfig.ErrNotFound) {
		t.Fatalf("continued error=%v, want providerconfig.ErrNotFound", errContinued)
	}
	invalidated, errInvalidated := store.Get(context.Background(), "owner_continuation", first.ID)
	if errInvalidated != nil || invalidated.ProviderContinuation == nil || invalidated.ProviderContinuation.InvalidationReason != ContinuationInvalidatedTargetUnavailable || !invalidated.ProviderContinuation.InvalidatedAt.Equal(now) || len(executor.requests) != 1 {
		t.Fatalf("invalidated continuation=%+v provider requests=%d error=%v", invalidated.ProviderContinuation, len(executor.requests), errInvalidated)
	}
}

// TestServiceInvalidatesProviderRejectedContinuation verifies one explicit upstream revocation is durable and blocks every later replay.
// TestServiceInvalidatesProviderRejectedContinuation 验证一次明确上游撤销会持久化并阻止全部后续重放。
func TestServiceInvalidatesProviderRejectedContinuation(t *testing.T) {
	now := time.Date(2026, 7, 21, 15, 0, 0, 0, time.UTC)
	target := resolve.Target{ProviderDefinitionID: "definition_continuation", ProviderInstanceID: "pvi_continuation", ChannelID: "openai.responses", EndpointID: "endpoint_continuation", EndpointRegion: "global", CredentialID: "credential_continuation", SubjectKind: resolve.ExecutionSubjectModel, ProviderModelID: "model_continuation", OfferingID: "offering_continuation", Operation: vcp.OperationConversationRespond, ActionBindingID: "action_continuation", ExecutionProfileID: "profile_continuation", UpstreamModelID: "upstream_model", ModelCapabilities: conversationTestCapabilities(true, false), CapabilityRevision: 1, ProviderConfigRevision: 1, CatalogRevision: 1}
	resolver := &staticResolver{target: target}
	configurations := staticConfigurations{
		definition: providerconfig.ProviderDefinition{ID: target.ProviderDefinitionID},
		endpoint:   providerconfig.Endpoint{ID: target.EndpointID, ProviderInstanceID: target.ProviderInstanceID, ChannelID: target.ChannelID, BaseURL: "https://provider.example", Region: target.EndpointRegion, Status: providerconfig.EndpointReady, Revision: 1},
		credential: providerconfig.Credential{ID: target.CredentialID, ProviderInstanceID: target.ProviderInstanceID, Status: providerconfig.CredentialActive, Revision: 1},
	}
	executor := &continuationProviderExecutor{}
	store := NewMemoryStore()
	identifiers := []string{"exe_11111111111111111111111111111111", "exe_22222222222222222222222222222222"}
	service, errService := NewService(store, resolver, configurations, nil, nil, executor, ServiceOptions{NewID: func() (string, error) {
		identifier := identifiers[0]
		identifiers = identifiers[1:]
		return identifier, nil
	}, Now: func() time.Time { return now }, Retention: time.Hour})
	if errService != nil {
		t.Fatalf("NewService() error = %v", errService)
	}
	selection := &vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: target.ProviderInstanceID, ProviderModelID: target.ProviderModelID, ExecutionProfileID: target.ExecutionProfileID}
	firstRequest := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request_original", Target: vcp.TargetSelection{Model: selection}, Operation: vcp.OperationConversationRespond, Payload: vcp.OperationPayload{Conversation: &vcp.ConversationOperation{}}}
	first, _, errFirst := service.Create(context.Background(), "owner_continuation", firstRequest)
	if errFirst != nil || first.ProviderContinuation == nil {
		t.Fatalf("first execution=%+v error=%v", first, errFirst)
	}
	now = now.Add(time.Minute)
	executor.rejectContinuation = true
	continuedRequest := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request_rejected", Target: vcp.TargetSelection{Model: selection}, Operation: vcp.OperationConversationRespond, Payload: vcp.OperationPayload{Conversation: &vcp.ConversationOperation{ReasoningPolicy: vcp.ReasoningPolicy{ContinuationID: first.ID}}}}
	rejected, _, errRejected := service.Create(context.Background(), "owner_continuation", continuedRequest)
	if errRejected != nil || rejected.Status != StatusFailed {
		t.Fatalf("rejected execution=%+v error=%v", rejected, errRejected)
	}
	invalidated, errInvalidated := store.Get(context.Background(), "owner_continuation", first.ID)
	if errInvalidated != nil || invalidated.ProviderContinuation == nil || invalidated.ProviderContinuation.InvalidationReason != ContinuationInvalidatedProviderRejected || !invalidated.ProviderContinuation.InvalidatedAt.Equal(now) {
		t.Fatalf("invalidated continuation=%+v error=%v", invalidated.ProviderContinuation, errInvalidated)
	}
	if _, _, errReplay := service.Create(context.Background(), "owner_continuation", continuedRequest); !errors.Is(errReplay, vcp.ErrInvalidRequest) || len(executor.requests) != 2 {
		t.Fatalf("replay error=%v provider requests=%d", errReplay, len(executor.requests))
	}
}

// TestServicePersistsProviderEventsBeforeStreamingExecutionReturns verifies SSE followers can observe upstream progress immediately.
// TestServicePersistsProviderEventsBeforeStreamingExecutionReturns 验证 SSE 跟随者可以立即观察上游进度。
func TestServicePersistsProviderEventsBeforeStreamingExecutionReturns(t *testing.T) {
	now := time.Date(2026, 7, 21, 10, 0, 0, 0, time.UTC)
	target := resolve.Target{ProviderDefinitionID: "definition_stream", ProviderInstanceID: "pvi_stream", ChannelID: "channel_stream", EndpointID: "endpoint_stream", EndpointRegion: "global", CredentialID: "credential_stream", SubjectKind: resolve.ExecutionSubjectModel, ProviderModelID: "model_stream", OfferingID: "offering_stream", Operation: vcp.OperationConversationRespond, ActionBindingID: "action_stream", ExecutionProfileID: "profile_stream", UpstreamModelID: "upstream_stream", ModelCapabilities: conversationTestCapabilities(true, false), CapabilityRevision: 1, ProviderConfigRevision: 1, CatalogRevision: 1}
	target.ModelCapabilities.Delivery.Streaming = true
	resolver := &staticResolver{target: target}
	configurations := staticConfigurations{
		definition: providerconfig.ProviderDefinition{ID: target.ProviderDefinitionID},
		endpoint:   providerconfig.Endpoint{ID: target.EndpointID, ProviderInstanceID: target.ProviderInstanceID, ChannelID: target.ChannelID, BaseURL: "https://provider.example", Region: target.EndpointRegion, Status: providerconfig.EndpointReady, Revision: 1},
		credential: providerconfig.Credential{ID: target.CredentialID, ProviderInstanceID: target.ProviderInstanceID, Status: providerconfig.CredentialActive, Revision: 1},
	}
	executor := &blockingStreamingProviderExecutor{started: make(chan struct{}), release: make(chan struct{})}
	store := NewMemoryStore()
	service, errService := NewService(store, resolver, configurations, nil, nil, executor, ServiceOptions{NewID: func() (string, error) { return "exe_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", nil }, Now: func() time.Time { return now }, Retention: time.Hour})
	if errService != nil {
		t.Fatalf("create service: %v", errService)
	}
	request := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request_stream", Stream: true, Target: vcp.TargetSelection{Model: &vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: target.ProviderInstanceID, ProviderModelID: target.ProviderModelID, ExecutionProfileID: target.ExecutionProfileID}}, Operation: vcp.OperationConversationRespond, Payload: vcp.OperationPayload{Conversation: &vcp.ConversationOperation{}}}
	type createOutcome struct {
		// record is the completed execution returned by Create.
		// record 是 Create 返回的已完成执行。
		record Record
		// err is the terminal Create error.
		// err 是最终 Create 错误。
		err error
	}
	completed := make(chan createOutcome, 1)
	go func() {
		record, _, errCreate := service.Create(context.Background(), "api_stream", request)
		completed <- createOutcome{record: record, err: errCreate}
	}()
	<-executor.started
	if errRecover := service.RecoverOnce(context.Background()); errRecover != nil {
		t.Fatalf("RecoverOnce() raced active synchronous execution: %v", errRecover)
	}
	if executor.callCount() != 1 {
		t.Fatalf("active synchronous provider dispatches=%d, want 1", executor.callCount())
	}
	events, errEvents := service.Events(context.Background(), "api_stream", "exe_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", 0)
	if errEvents != nil || len(events) != 3 || events[2].Type != EventProviderSemantic || events[2].ProviderEvent == nil || events[2].ProviderEvent.EventID != "provider_stream_started" {
		t.Fatalf("live events=%+v error=%v", events, errEvents)
	}
	close(executor.release)
	outcome := <-completed
	if outcome.err != nil || outcome.record.Status != StatusSucceeded {
		t.Fatalf("completed record=%+v error=%v", outcome.record, outcome.err)
	}
	events, errEvents = service.Events(context.Background(), "api_stream", outcome.record.ID, 0)
	if errEvents != nil || len(events) != 5 || events[3].ProviderEvent == nil || events[3].ProviderEvent.EventID != "provider_stream_completed" || events[4].Type != EventExecutionSucceeded {
		t.Fatalf("terminal events=%+v error=%v", events, errEvents)
	}
}

// TestImmediateExecutionLeaseBlocksAnotherServiceRecovery verifies a second Router cannot replay one in-flight synchronous provider call.
// TestImmediateExecutionLeaseBlocksAnotherServiceRecovery 验证第二个 Router 无法重放正在执行的同步供应商调用。
func TestImmediateExecutionLeaseBlocksAnotherServiceRecovery(t *testing.T) {
	now := time.Date(2026, 7, 22, 13, 0, 0, 0, time.UTC)
	target := resolve.Target{ProviderDefinitionID: "definition_leased", ProviderInstanceID: "pvi_leased", ChannelID: "channel_leased", EndpointID: "endpoint_leased", EndpointRegion: "global", CredentialID: "credential_leased", SubjectKind: resolve.ExecutionSubjectModel, ProviderModelID: "model_leased", OfferingID: "offering_leased", Operation: vcp.OperationConversationRespond, ActionBindingID: "action_leased", ExecutionProfileID: "profile_leased", UpstreamModelID: "upstream_leased", ModelCapabilities: conversationTestCapabilities(true, false), CapabilityRevision: 1, ProviderConfigRevision: 1, CatalogRevision: 1}
	target.ModelCapabilities.Delivery.Streaming = true
	resolver := &staticResolver{target: target}
	configurations := staticConfigurations{definition: providerconfig.ProviderDefinition{ID: target.ProviderDefinitionID}, endpoint: providerconfig.Endpoint{ID: target.EndpointID, ProviderInstanceID: target.ProviderInstanceID, ChannelID: target.ChannelID, BaseURL: "https://provider.example", Region: target.EndpointRegion, Status: providerconfig.EndpointReady, Revision: 1}, credential: providerconfig.Credential{ID: target.CredentialID, ProviderInstanceID: target.ProviderInstanceID, Status: providerconfig.CredentialActive, Revision: 1}}
	executor := &blockingStreamingProviderExecutor{started: make(chan struct{}), release: make(chan struct{})}
	store := NewMemoryStore()
	leases := &testExecutionLeaseStore{leases: make(map[string]testExecutionLease)}
	directService, errDirect := NewService(store, resolver, configurations, nil, nil, executor, ServiceOptions{NewID: func() (string, error) { return "exe_12121212121212121212121212121212", nil }, Now: func() time.Time { return now }, Retention: time.Hour, Leases: leases, WorkerID: "worker_direct", LeaseTTL: 30 * time.Second})
	if errDirect != nil {
		t.Fatalf("create direct execution service: %v", errDirect)
	}
	recoveryService, errRecovery := NewService(store, resolver, configurations, nil, nil, executor, ServiceOptions{NewID: func() (string, error) { return "exe_34343434343434343434343434343434", nil }, Now: func() time.Time { return now.Add(time.Second) }, Retention: time.Hour, Leases: leases, WorkerID: "worker_recovery", LeaseTTL: 30 * time.Second})
	if errRecovery != nil {
		t.Fatalf("create recovery execution service: %v", errRecovery)
	}
	request := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request_leased", Stream: true, Target: vcp.TargetSelection{Model: &vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: target.ProviderInstanceID, ProviderModelID: target.ProviderModelID, ExecutionProfileID: target.ExecutionProfileID}}, Operation: vcp.OperationConversationRespond, Payload: vcp.OperationPayload{Conversation: &vcp.ConversationOperation{}}}
	type createOutcome struct {
		// record is the terminal direct execution.
		// record 是最终即时执行。
		record Record
		// err is the direct execution failure.
		// err 是即时执行失败。
		err error
	}
	completed := make(chan createOutcome, 1)
	go func() {
		record, _, errCreate := directService.Create(context.Background(), "owner_leased", request)
		completed <- createOutcome{record: record, err: errCreate}
	}()
	<-executor.started
	if errRecover := recoveryService.RecoverOnce(context.Background()); errRecover != nil {
		t.Fatalf("competing RecoverOnce() error = %v", errRecover)
	}
	if executor.callCount() != 1 {
		t.Fatalf("leased provider dispatches=%d, want 1", executor.callCount())
	}
	close(executor.release)
	outcome := <-completed
	if outcome.err != nil || outcome.record.Status != StatusSucceeded {
		t.Fatalf("leased direct record=%+v error=%v", outcome.record, outcome.err)
	}
}

// TestDeferredStreamingExecutionCanBeCancelledThroughItsDurableIdentity verifies clients can attach before a synchronous stream starts.
// TestDeferredStreamingExecutionCanBeCancelledThroughItsDurableIdentity 验证客户端可在同步流开始前通过持久身份接入并取消。
func TestDeferredStreamingExecutionCanBeCancelledThroughItsDurableIdentity(t *testing.T) {
	now := time.Date(2026, 7, 21, 15, 0, 0, 0, time.UTC)
	target := resolve.Target{ProviderDefinitionID: "definition_deferred", ProviderInstanceID: "pvi_deferred", ChannelID: "channel_deferred", EndpointID: "endpoint_deferred", EndpointRegion: "global", CredentialID: "credential_deferred", SubjectKind: resolve.ExecutionSubjectModel, ProviderModelID: "model_deferred", OfferingID: "offering_deferred", Operation: vcp.OperationConversationRespond, ActionBindingID: "action_deferred", ExecutionProfileID: "profile_deferred", UpstreamModelID: "upstream_deferred", ModelCapabilities: conversationTestCapabilities(true, false), CapabilityRevision: 1, ProviderConfigRevision: 1, CatalogRevision: 1}
	target.ModelCapabilities.Delivery.Streaming = true
	resolver := &staticResolver{target: target}
	configurations := staticConfigurations{definition: providerconfig.ProviderDefinition{ID: target.ProviderDefinitionID}, endpoint: providerconfig.Endpoint{ID: target.EndpointID, ProviderInstanceID: target.ProviderInstanceID, ChannelID: target.ChannelID, BaseURL: "https://provider.example", Region: target.EndpointRegion, Status: providerconfig.EndpointReady, Revision: 1}, credential: providerconfig.Credential{ID: target.CredentialID, ProviderInstanceID: target.ProviderInstanceID, Status: providerconfig.CredentialActive, Revision: 1}}
	executor := &blockingStreamingProviderExecutor{started: make(chan struct{}), release: make(chan struct{})}
	service, errService := NewService(NewMemoryStore(), resolver, configurations, nil, nil, executor, ServiceOptions{NewID: func() (string, error) { return "exe_33333333333333333333333333333333", nil }, Now: func() time.Time { return now }, Retention: time.Hour})
	if errService != nil {
		t.Fatalf("NewService() error = %v", errService)
	}
	request := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request_deferred", Stream: true, DispatchMode: vcp.DispatchDeferred, Target: vcp.TargetSelection{Model: &vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: target.ProviderInstanceID, ProviderModelID: target.ProviderModelID, ExecutionProfileID: target.ExecutionProfileID}}, Operation: vcp.OperationConversationRespond, Payload: vcp.OperationPayload{Conversation: &vcp.ConversationOperation{}}}
	accepted, replayed, errCreate := service.Create(context.Background(), "owner_deferred", request)
	if errCreate != nil || replayed || accepted.Status != StatusAccepted {
		t.Fatalf("deferred admission=%+v replayed=%t error=%v", accepted, replayed, errCreate)
	}
	recoveryDone := make(chan error, 1)
	go func() { recoveryDone <- service.RecoverOnce(context.Background()) }()
	<-executor.started
	cancelled, errCancel := service.Cancel(context.Background(), "owner_deferred", accepted.ID)
	if errCancel != nil || cancelled.Status != StatusCancelled {
		t.Fatalf("Cancel() record=%+v error=%v", cancelled, errCancel)
	}
	if errRecovery := <-recoveryDone; errRecovery != nil {
		t.Fatalf("RecoverOnce() error = %v", errRecovery)
	}
	terminal, errGet := service.Get(context.Background(), "owner_deferred", accepted.ID)
	if errGet != nil || terminal.Status != StatusCancelled {
		t.Fatalf("terminal record=%+v error=%v", terminal, errGet)
	}
}

// TestDeferredExecutionPersistsAndRecoversScheduledRetry verifies delay, restart-safe state, and scheduler events.
// TestDeferredExecutionPersistsAndRecoversScheduledRetry 验证延迟、可重启状态与调度器事件。
func TestDeferredExecutionPersistsAndRecoversScheduledRetry(t *testing.T) {
	now := time.Date(2026, 7, 21, 16, 0, 0, 0, time.UTC)
	target := resolve.Target{ProviderDefinitionID: "definition_retry", ProviderInstanceID: "pvi_retry", ChannelID: "channel_retry", EndpointID: "endpoint_retry", EndpointRegion: "global", CredentialID: "credential_retry", SubjectKind: resolve.ExecutionSubjectModel, ProviderModelID: "model_retry", OfferingID: "offering_retry", Operation: vcp.OperationConversationRespond, ActionBindingID: "action_retry", ExecutionProfileID: "profile_retry", UpstreamModelID: "upstream_retry", ModelCapabilities: conversationTestCapabilities(true, false), CapabilityRevision: 1, ProviderConfigRevision: 1, CatalogRevision: 1}
	resolver := &staticResolver{target: target}
	configurations := staticConfigurations{definition: providerconfig.ProviderDefinition{ID: target.ProviderDefinitionID}, endpoint: providerconfig.Endpoint{ID: target.EndpointID, ProviderInstanceID: target.ProviderInstanceID, ChannelID: target.ChannelID, BaseURL: "https://provider.example", Region: target.EndpointRegion, Status: providerconfig.EndpointReady, Revision: 1}, credential: providerconfig.Credential{ID: target.CredentialID, ProviderInstanceID: target.ProviderInstanceID, Status: providerconfig.CredentialActive, Revision: 1}}
	executor := &durableRetryProviderExecutor{}
	store := NewMemoryStore()
	service, errService := NewService(store, resolver, configurations, nil, nil, executor, ServiceOptions{NewID: func() (string, error) { return "exe_44444444444444444444444444444444", nil }, Now: func() time.Time { return now }, Retention: time.Hour})
	if errService != nil {
		t.Fatalf("NewService() error = %v", errService)
	}
	request := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request_retry", DispatchMode: vcp.DispatchDeferred, Target: vcp.TargetSelection{Model: &vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: target.ProviderInstanceID, ProviderModelID: target.ProviderModelID, ExecutionProfileID: target.ExecutionProfileID}}, Operation: vcp.OperationConversationRespond, Payload: vcp.OperationPayload{Conversation: &vcp.ConversationOperation{}}}
	accepted, _, errCreate := service.Create(context.Background(), "owner_retry", request)
	if errCreate != nil || accepted.Status != StatusAccepted {
		t.Fatalf("Create() record=%+v error=%v", accepted, errCreate)
	}
	if errRecover := service.RecoverOnce(context.Background()); errRecover != nil {
		t.Fatalf("first RecoverOnce() error = %v", errRecover)
	}
	waiting, errWaiting := service.Get(context.Background(), "owner_retry", accepted.ID)
	if errWaiting != nil || waiting.Status != StatusWaitingRetry || waiting.Retry == nil || waiting.Retry.NextRetryAt != now.Add(5*time.Second) || waiting.RetryCycles != 1 || len(executor.requests) != 1 {
		t.Fatalf("waiting record=%+v requests=%d error=%v", waiting, len(executor.requests), errWaiting)
	}
	if errEarly := service.RecoverOnce(context.Background()); errEarly != nil || len(executor.requests) != 1 {
		t.Fatalf("early recovery requests=%d error=%v", len(executor.requests), errEarly)
	}
	now = now.Add(5 * time.Second)
	if errRecover := service.RecoverOnce(context.Background()); errRecover != nil {
		t.Fatalf("second RecoverOnce() error = %v", errRecover)
	}
	completed, errCompleted := service.Get(context.Background(), "owner_retry", accepted.ID)
	if errCompleted != nil || completed.Status != StatusSucceeded || completed.Retry != nil || completed.RetryCycles != 1 || len(executor.requests) != 2 {
		t.Fatalf("completed record=%+v requests=%d error=%v", completed, len(executor.requests), errCompleted)
	}
	events, errEvents := service.Events(context.Background(), "owner_retry", accepted.ID, 0)
	if errEvents != nil || !containsExecutionEventType(events, EventRetryScheduled) || !containsExecutionEventType(events, EventRetryStarted) || !containsExecutionEventType(events, EventRetrySucceeded) {
		t.Fatalf("retry events=%+v error=%v", events, errEvents)
	}
}

// containsExecutionEventType reports exact membership in an execution event sequence.
// containsExecutionEventType 报告执行事件序列中的精确成员关系。
func containsExecutionEventType(events []Event, target EventType) bool {
	for _, event := range events {
		if event.Type == target {
			return true
		}
	}
	return false
}

// TestServiceRetriesOnlyInsideProviderWithExactClassifierConstraint verifies credential and endpoint retries never widen their affinity.
// TestServiceRetriesOnlyInsideProviderWithExactClassifierConstraint 验证凭据与入口重试绝不会扩大其亲和范围。
func TestServiceRetriesOnlyInsideProviderWithExactClassifierConstraint(t *testing.T) {
	testCases := []struct {
		// name identifies the retry scenario.
		// name 标识重试场景。
		name string
		// action is the provider-classified retry boundary.
		// action 是供应商分类后的重试边界。
		action provider.RetryAction
		// secondCredentialID is the credential selected by the second resolution.
		// secondCredentialID 是第二次解析选中的凭据。
		secondCredentialID string
		// secondEndpointID is the endpoint selected by the second resolution.
		// secondEndpointID 是第二次解析选中的入口。
		secondEndpointID string
		// wantRequiredCredentialID is the exact credential affinity expected on retry.
		// wantRequiredCredentialID 是重试时预期的精确凭据亲和约束。
		wantRequiredCredentialID string
		// wantExcludedCredentialCount is the expected credential exclusion count.
		// wantExcludedCredentialCount 是预期的凭据排除数量。
		wantExcludedCredentialCount int
		// wantExcludedEndpointCount is the expected endpoint exclusion count.
		// wantExcludedEndpointCount 是预期的入口排除数量。
		wantExcludedEndpointCount int
	}{
		{name: "credential", action: provider.RetryOtherCredential, secondCredentialID: "credential_second", secondEndpointID: "endpoint_first", wantExcludedCredentialCount: 1},
		{name: "endpoint", action: provider.RetryOtherEndpoint, secondCredentialID: "credential_first", secondEndpointID: "endpoint_second", wantRequiredCredentialID: "credential_first", wantExcludedEndpointCount: 1},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			now := time.Date(2026, 7, 20, 15, 0, 0, 0, time.UTC)
			first := failoverTestTarget("credential_first", "endpoint_first")
			second := failoverTestTarget(testCase.secondCredentialID, testCase.secondEndpointID)
			resolver := &sequenceResolver{targets: []resolve.Target{first, second}}
			configurations := multiConfigurations{
				definition: providerconfig.ProviderDefinition{ID: first.ProviderDefinitionID},
				endpoints: []providerconfig.Endpoint{
					{ID: "endpoint_first", ProviderInstanceID: first.ProviderInstanceID, ChannelID: first.ChannelID, BaseURL: "https://first.example", Region: "region_test", Status: providerconfig.EndpointReady, Revision: 1},
					{ID: "endpoint_second", ProviderInstanceID: first.ProviderInstanceID, ChannelID: first.ChannelID, BaseURL: "https://second.example", Region: "region_test", Status: providerconfig.EndpointReady, Revision: 1},
				},
				credentials: []providerconfig.Credential{
					{ID: "credential_first", ProviderInstanceID: first.ProviderInstanceID, Status: providerconfig.CredentialActive, Revision: 1},
					{ID: "credential_second", ProviderInstanceID: first.ProviderInstanceID, Status: providerconfig.CredentialActive, Revision: 1},
				},
			}
			executor := &failoverProviderExecutor{action: testCase.action}
			service, errService := NewService(NewMemoryStore(), resolver, configurations, nil, nil, executor, ServiceOptions{NewID: func() (string, error) { return "exe_cccccccccccccccccccccccccccccccc", nil }, Now: func() time.Time { return now }, Retention: time.Hour})
			if errService != nil {
				t.Fatalf("create service: %v", errService)
			}
			created, replayed, errCreate := service.Create(context.Background(), "api_failover", failoverTestRequest(first))
			if errCreate != nil || replayed || created.Status != StatusSucceeded || len(created.Attempts) != 2 || len(executor.requests) != 2 || len(resolver.requests) != 2 {
				t.Fatalf("created=%+v replayed=%t error=%v attempts=%d dispatches=%d resolutions=%d", created, replayed, errCreate, len(created.Attempts), len(executor.requests), len(resolver.requests))
			}
			if created.Target.CredentialID != testCase.secondCredentialID || created.Target.EndpointID != testCase.secondEndpointID || created.Attempts[0].RetryAction != testCase.action || !created.Attempts[1].Succeeded {
				t.Fatalf("unexpected failover audit: target=%+v attempts=%+v", created.Target, created.Attempts)
			}
			retryRequest := resolver.requests[1]
			if retryRequest.RequiredCredentialID != testCase.wantRequiredCredentialID || len(retryRequest.ExcludedCredentialIDs) != testCase.wantExcludedCredentialCount || len(retryRequest.ExcludedEndpointIDs) != testCase.wantExcludedEndpointCount {
				t.Fatalf("retry constraints=%+v", retryRequest)
			}
		})
	}
}

// TestServiceDoesNotRetryAfterProviderSemanticOutput verifies provider-accepted state makes the failed target final.
// TestServiceDoesNotRetryAfterProviderSemanticOutput 验证供应商已接收状态会使失败 Target 成为最终 Target。
func TestServiceDoesNotRetryAfterProviderSemanticOutput(t *testing.T) {
	now := time.Date(2026, 7, 20, 16, 0, 0, 0, time.UTC)
	target := failoverTestTarget("credential_first", "endpoint_first")
	resolver := &sequenceResolver{targets: []resolve.Target{target, failoverTestTarget("credential_second", "endpoint_first")}}
	configurations := multiConfigurations{definition: providerconfig.ProviderDefinition{ID: target.ProviderDefinitionID}, endpoints: []providerconfig.Endpoint{{ID: target.EndpointID, ProviderInstanceID: target.ProviderInstanceID, ChannelID: target.ChannelID, BaseURL: "https://first.example", Region: target.EndpointRegion, Status: providerconfig.EndpointReady, Revision: 1}}, credentials: []providerconfig.Credential{{ID: target.CredentialID, ProviderInstanceID: target.ProviderInstanceID, Status: providerconfig.CredentialActive, Revision: 1}}}
	executor := &failoverProviderExecutor{action: provider.RetryOtherCredential, semanticOnFailure: true}
	service, errService := NewService(NewMemoryStore(), resolver, configurations, nil, nil, executor, ServiceOptions{NewID: func() (string, error) { return "exe_dddddddddddddddddddddddddddddddd", nil }, Now: func() time.Time { return now }, Retention: time.Hour})
	if errService != nil {
		t.Fatalf("create service: %v", errService)
	}
	created, replayed, errCreate := service.Create(context.Background(), "api_semantic", failoverTestRequest(target))
	if errCreate != nil || replayed || created.Status != StatusFailed || len(created.Attempts) != 1 || !created.Attempts[0].SemanticOutput || len(executor.requests) != 1 || len(resolver.requests) != 1 {
		t.Fatalf("created=%+v replayed=%t error=%v dispatches=%d resolutions=%d", created, replayed, errCreate, len(executor.requests), len(resolver.requests))
	}
}

// failoverTestTarget returns one exact target whose account and endpoint may be varied independently.
// failoverTestTarget 返回一个可独立改变账号和入口的精确 Target。
func failoverTestTarget(credentialID string, endpointID string) resolve.Target {
	return resolve.Target{ProviderDefinitionID: "definition_failover", ProviderInstanceID: "pvi_failover", ChannelID: "channel_failover", EndpointID: endpointID, EndpointRegion: "region_test", CredentialID: credentialID, SubjectKind: resolve.ExecutionSubjectModel, ProviderModelID: "model_failover", OfferingID: "offering_failover", Operation: vcp.OperationConversationRespond, ActionBindingID: "action_failover", ExecutionProfileID: "profile_failover", UpstreamModelID: "upstream_failover", ModelCapabilities: conversationTestCapabilities(true, false), CapabilityRevision: 1, ProviderConfigRevision: 1, CatalogRevision: 1}
}

// failoverTestRequest returns one valid exact model request for failover tests.
// failoverTestRequest 返回用于故障切换测试的有效精确模型请求。
func failoverTestRequest(target resolve.Target) vcp.ExecutionRequest {
	return vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request_failover", Target: vcp.TargetSelection{Model: &vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: target.ProviderInstanceID, ProviderModelID: target.ProviderModelID, ExecutionProfileID: target.ExecutionProfileID}}, Operation: vcp.OperationConversationRespond, Payload: vcp.OperationPayload{Conversation: &vcp.ConversationOperation{}}}
}

// TestServiceRetriesTaskStartOnlyBeforeProviderAcceptance verifies task creation affinity freezes as soon as a provider task ID exists.
// TestServiceRetriesTaskStartOnlyBeforeProviderAcceptance 验证供应商任务 ID 一旦存在，任务创建亲和性即被冻结。
func TestServiceRetriesTaskStartOnlyBeforeProviderAcceptance(t *testing.T) {
	testCases := []struct {
		// name identifies the task-start scenario.
		// name 标识任务启动场景。
		name string
		// acceptedOnFailure reports whether the failed response already contains provider acceptance evidence.
		// acceptedOnFailure 表示失败响应是否已包含供应商接收证据。
		acceptedOnFailure bool
		// wantStarts is the expected provider start call count.
		// wantStarts 是预期的供应商启动调用次数。
		wantStarts int
		// wantResolutions is the expected target resolution count.
		// wantResolutions 是预期的目标解析次数。
		wantResolutions int
		// wantStatus is the expected final local task status.
		// wantStatus 是预期的最终本地任务状态。
		wantStatus Status
	}{
		{name: "retry_before_acceptance", wantStarts: 2, wantResolutions: 2, wantStatus: StatusQueued},
		{name: "stop_after_acceptance", acceptedOnFailure: true, wantStarts: 1, wantResolutions: 1, wantStatus: StatusFailed},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			now := time.Date(2026, 7, 20, 17, 0, 0, 0, time.UTC)
			first := failoverTestTarget("credential_first", "endpoint_first")
			first.ModelCapabilities = conversationTestCapabilities(false, true)
			second := failoverTestTarget("credential_second", "endpoint_first")
			second.ModelCapabilities = conversationTestCapabilities(false, true)
			resolver := &sequenceResolver{targets: []resolve.Target{first, second}}
			configurations := multiConfigurations{definition: providerconfig.ProviderDefinition{ID: first.ProviderDefinitionID}, endpoints: []providerconfig.Endpoint{{ID: first.EndpointID, ProviderInstanceID: first.ProviderInstanceID, ChannelID: first.ChannelID, BaseURL: "https://async-failover.example", Region: first.EndpointRegion, Status: providerconfig.EndpointReady, Revision: 1}}, credentials: []providerconfig.Credential{{ID: first.CredentialID, ProviderInstanceID: first.ProviderInstanceID, Status: providerconfig.CredentialActive, Revision: 1}, {ID: second.CredentialID, ProviderInstanceID: second.ProviderInstanceID, Status: providerconfig.CredentialActive, Revision: 1}}}
			executor := &failoverTaskProviderExecutor{acceptedOnFailure: testCase.acceptedOnFailure}
			service, errService := NewService(NewMemoryStore(), resolver, configurations, nil, nil, executor, ServiceOptions{NewID: func() (string, error) { return "exe_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", nil }, Now: func() time.Time { return now }, Retention: time.Hour})
			if errService != nil {
				t.Fatalf("create service: %v", errService)
			}
			created, replayed, errCreate := service.Create(context.Background(), "api_task_failover", failoverTestRequest(first))
			if errCreate != nil || replayed || created.Status != testCase.wantStatus || len(executor.starts) != testCase.wantStarts || len(resolver.requests) != testCase.wantResolutions {
				t.Fatalf("created=%+v replayed=%t error=%v starts=%d resolutions=%d", created, replayed, errCreate, len(executor.starts), len(resolver.requests))
			}
			if len(created.Attempts) != testCase.wantStarts || !testCase.acceptedOnFailure && (created.ProviderTask == nil || created.Target.CredentialID != second.CredentialID) {
				t.Fatalf("unexpected task audit or affinity: %+v", created)
			}
			if testCase.acceptedOnFailure && !created.Attempts[0].SemanticOutput {
				t.Fatalf("provider-accepted failed start was not marked semantic: %+v", created.Attempts)
			}
		})
	}
}

// TestServiceRecoversAsyncTaskWithPersistedAffinity verifies restart polling never re-resolves endpoint or credential.
// TestServiceRecoversAsyncTaskWithPersistedAffinity 验证重启轮询绝不重新解析 Endpoint 或 Credential。
func TestServiceRecoversAsyncTaskWithPersistedAffinity(t *testing.T) {
	now := time.Date(2026, 7, 20, 13, 0, 0, 0, time.UTC)
	target := resolve.Target{ProviderDefinitionID: "definition_async", ProviderInstanceID: "pvi_async", ChannelID: "channel_async", EndpointID: "endpoint_async", EndpointRegion: "region_async", CredentialID: "credential_async", SubjectKind: resolve.ExecutionSubjectModel, ProviderModelID: "model_async", OfferingID: "offering_async", Operation: vcp.OperationConversationRespond, ActionBindingID: "action_async", ExecutionProfileID: "profile_async", UpstreamModelID: "upstream_async", ModelCapabilities: conversationTestCapabilities(false, true), CapabilityRevision: 1, ProviderConfigRevision: 1, CatalogRevision: 1}
	resolver := &staticResolver{target: target}
	configurations := staticConfigurations{definition: providerconfig.ProviderDefinition{ID: target.ProviderDefinitionID}, endpoint: providerconfig.Endpoint{ID: target.EndpointID, ProviderInstanceID: target.ProviderInstanceID, ChannelID: target.ChannelID, BaseURL: "https://async.example", Region: target.EndpointRegion, Status: providerconfig.EndpointReady}, credential: providerconfig.Credential{ID: target.CredentialID, ProviderInstanceID: target.ProviderInstanceID, Status: providerconfig.CredentialActive}}
	executor := &recordingTaskProviderExecutor{}
	store := NewMemoryStore()
	service, errService := NewService(store, resolver, configurations, nil, nil, executor, ServiceOptions{NewID: func() (string, error) { return "exe_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", nil }, Now: func() time.Time { return now }, Retention: time.Hour})
	if errService != nil {
		t.Fatalf("create service: %v", errService)
	}
	request := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request_async", Target: vcp.TargetSelection{Model: &vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: target.ProviderInstanceID, ProviderModelID: target.ProviderModelID, ExecutionProfileID: target.ExecutionProfileID}}, Operation: vcp.OperationConversationRespond, Payload: vcp.OperationPayload{Conversation: &vcp.ConversationOperation{}}}
	queued, replayed, errCreate := service.Create(context.Background(), "api_async", request)
	if errCreate != nil || replayed || queued.Status != StatusQueued || queued.ProviderTask == nil || executor.starts != 1 {
		t.Fatalf("queued=%+v replayed=%t error=%v starts=%d", queued, replayed, errCreate, executor.starts)
	}
	resolver.target.EndpointID = "endpoint_drifted"
	configurations.endpoint.ID = "endpoint_drifted"
	configurations.credential.ID = "credential_drifted"
	if errRecover := service.RecoverOnce(context.Background()); errRecover != nil {
		t.Fatalf("recover once: %v", errRecover)
	}
	completed, errGet := service.Get(context.Background(), "api_async", queued.ID)
	if errGet != nil || completed.Status != StatusSucceeded || executor.polls != 1 {
		t.Fatalf("completed=%+v error=%v polls=%d", completed, errGet, executor.polls)
	}
	if executor.pollRequest.Binding.Target.EndpointID != "endpoint_async" || executor.pollRequest.Binding.Credential.ID != "credential_async" {
		t.Fatalf("poll affinity drifted: %+v", executor.pollRequest.Binding)
	}
}

// TestServiceRecoversAsyncTaskAfterObservationOnlyRevision verifies event ordering remains contiguous after a poll save that emits no semantic event.
// TestServiceRecoversAsyncTaskAfterObservationOnlyRevision 验证仅保存轮询观测且不发语义事件后，事件顺序仍保持连续。
func TestServiceRecoversAsyncTaskAfterObservationOnlyRevision(t *testing.T) {
	now := time.Date(2026, time.July, 20, 13, 15, 0, 0, time.UTC)
	target := resolve.Target{ProviderDefinitionID: "definition_async_sequence", ProviderInstanceID: "pvi_async_sequence", ChannelID: "channel_async_sequence", EndpointID: "endpoint_async_sequence", EndpointRegion: "region_async_sequence", CredentialID: "credential_async_sequence", SubjectKind: resolve.ExecutionSubjectModel, ProviderModelID: "model_async_sequence", OfferingID: "offering_async_sequence", Operation: vcp.OperationConversationRespond, ActionBindingID: "action_async_sequence", ExecutionProfileID: "profile_async_sequence", UpstreamModelID: "upstream_async_sequence", ModelCapabilities: conversationTestCapabilities(false, true), CapabilityRevision: 1, ProviderConfigRevision: 1, CatalogRevision: 1}
	resolver := &staticResolver{target: target}
	configurations := staticConfigurations{definition: providerconfig.ProviderDefinition{ID: target.ProviderDefinitionID}, endpoint: providerconfig.Endpoint{ID: target.EndpointID, ProviderInstanceID: target.ProviderInstanceID, ChannelID: target.ChannelID, BaseURL: "https://async-sequence.example", Region: target.EndpointRegion, Status: providerconfig.EndpointReady}, credential: providerconfig.Credential{ID: target.CredentialID, ProviderInstanceID: target.ProviderInstanceID, Status: providerconfig.CredentialActive}}
	executor := &recordingTaskProviderExecutor{queuedPolls: 1}
	store := NewMemoryStore()
	service, errService := NewService(store, resolver, configurations, nil, nil, executor, ServiceOptions{NewID: func() (string, error) { return "exe_bdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbd", nil }, Now: func() time.Time { return now }, Retention: time.Hour})
	if errService != nil {
		t.Fatalf("NewService() error = %v", errService)
	}
	request := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request_async_sequence", Target: vcp.TargetSelection{Model: &vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: target.ProviderInstanceID, ProviderModelID: target.ProviderModelID, ExecutionProfileID: target.ExecutionProfileID}}, Operation: vcp.OperationConversationRespond, Payload: vcp.OperationPayload{Conversation: &vcp.ConversationOperation{}}}
	queued, _, errCreate := service.Create(context.Background(), "api_async_sequence", request)
	if errCreate != nil || queued.Status != StatusQueued {
		t.Fatalf("Create() record = %+v, error = %v", queued, errCreate)
	}
	if errRecover := service.RecoverOnce(context.Background()); errRecover != nil {
		t.Fatalf("first RecoverOnce() error = %v", errRecover)
	}
	if errRecover := service.RecoverOnce(context.Background()); errRecover != nil {
		t.Fatalf("second RecoverOnce() error = %v", errRecover)
	}
	completed, errGet := service.Get(context.Background(), queued.OwnerAPIKeyID, queued.ID)
	if errGet != nil || completed.Status != StatusSucceeded || executor.polls != 2 || completed.Revision <= 4 {
		t.Fatalf("completed = %+v, polls = %d, error = %v", completed, executor.polls, errGet)
	}
	events, errEvents := service.Events(context.Background(), queued.OwnerAPIKeyID, queued.ID, 0)
	if errEvents != nil || len(events) < 4 {
		t.Fatalf("events = %+v, error = %v", events, errEvents)
	}
	for index, event := range events {
		if event.Sequence != uint64(index+1) {
			t.Fatalf("event[%d] sequence = %d", index, event.Sequence)
		}
	}
}

// TestServicePersistsTaskCancellationIntentBeforeUpstreamCall verifies crash-safe ordering and its public replay event.
// TestServicePersistsTaskCancellationIntentBeforeUpstreamCall 验证可抗崩溃的取消顺序及其公开重放事件。
func TestServicePersistsTaskCancellationIntentBeforeUpstreamCall(t *testing.T) {
	now := time.Date(2026, 7, 20, 13, 30, 0, 0, time.UTC)
	target := resolve.Target{ProviderDefinitionID: "definition_cancel", ProviderInstanceID: "pvi_cancel", ChannelID: "channel_cancel", EndpointID: "endpoint_cancel", EndpointRegion: "region_cancel", CredentialID: "credential_cancel", SubjectKind: resolve.ExecutionSubjectModel, ProviderModelID: "model_cancel", OfferingID: "offering_cancel", Operation: vcp.OperationConversationRespond, ActionBindingID: "action_cancel", ExecutionProfileID: "profile_cancel", UpstreamModelID: "upstream_cancel", ModelCapabilities: conversationTestCapabilities(false, true), CapabilityRevision: 1, ProviderConfigRevision: 1, CatalogRevision: 1}
	resolver := &staticResolver{target: target}
	configurations := staticConfigurations{definition: providerconfig.ProviderDefinition{ID: target.ProviderDefinitionID}, endpoint: providerconfig.Endpoint{ID: target.EndpointID, ProviderInstanceID: target.ProviderInstanceID, ChannelID: target.ChannelID, BaseURL: "https://cancel.example", Region: target.EndpointRegion, Status: providerconfig.EndpointReady}, credential: providerconfig.Credential{ID: target.CredentialID, ProviderInstanceID: target.ProviderInstanceID, Status: providerconfig.CredentialActive}}
	executor := &blockingCancellationTaskProviderExecutor{cancellationStarted: make(chan struct{}), cancellationRelease: make(chan struct{})}
	store := NewMemoryStore()
	service, errService := NewService(store, resolver, configurations, nil, nil, executor, ServiceOptions{NewID: func() (string, error) { return "exe_bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc", nil }, Now: func() time.Time { return now }, Retention: time.Hour})
	if errService != nil {
		t.Fatalf("NewService() error = %v", errService)
	}
	request := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request_cancel_intent", Target: vcp.TargetSelection{Model: &vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: target.ProviderInstanceID, ProviderModelID: target.ProviderModelID, ExecutionProfileID: target.ExecutionProfileID}}, Operation: vcp.OperationConversationRespond, Payload: vcp.OperationPayload{Conversation: &vcp.ConversationOperation{}}}
	queued, _, errCreate := service.Create(context.Background(), "api_cancel", request)
	if errCreate != nil || queued.Status != StatusQueued || queued.ProviderTask == nil {
		t.Fatalf("Create() record = %+v, error = %v", queued, errCreate)
	}
	cancelResult := make(chan error, 1)
	go func() {
		_, errCancel := service.Cancel(context.Background(), "api_cancel", queued.ID)
		cancelResult <- errCancel
	}()
	<-executor.cancellationStarted
	persisted, errPersisted := service.Get(context.Background(), "api_cancel", queued.ID)
	if errPersisted != nil || persisted.Status != StatusQueued || persisted.ProviderTask == nil || persisted.ProviderTask.CancellationRequestedAt == nil || *persisted.ProviderTask.CancellationRequestedAt != now || persisted.ProviderTask.CancellationAttempts != 0 {
		t.Fatalf("persisted cancellation intent = %+v, error = %v", persisted, errPersisted)
	}
	events, errEvents := service.Events(context.Background(), "api_cancel", queued.ID, 0)
	if errEvents != nil || !containsExecutionEventType(events, EventExecutionCancellationRequested) || containsExecutionEventType(events, EventExecutionCancelled) {
		t.Fatalf("pre-confirmation events = %+v, error = %v", events, errEvents)
	}
	close(executor.cancellationRelease)
	if errCancel := <-cancelResult; errCancel != nil {
		t.Fatalf("Cancel() error = %v", errCancel)
	}
	terminal, errTerminal := service.Get(context.Background(), "api_cancel", queued.ID)
	if errTerminal != nil || terminal.Status != StatusCancelled || terminal.ProviderTask != nil {
		t.Fatalf("terminal cancellation = %+v, error = %v", terminal, errTerminal)
	}
}

// TestServiceRecoversPersistedTaskCancellationBeforePolling verifies restart recovery honors durable cancellation intent before normal task polling.
// TestServiceRecoversPersistedTaskCancellationBeforePolling 验证重启恢复会在常规任务轮询前优先履行持久化取消意图。
func TestServiceRecoversPersistedTaskCancellationBeforePolling(t *testing.T) {
	now := time.Date(2026, time.July, 20, 13, 45, 0, 0, time.UTC)
	target := resolve.Target{ProviderDefinitionID: "definition_cancel_recovery", ProviderInstanceID: "pvi_cancel_recovery", ChannelID: "channel_cancel_recovery", EndpointID: "endpoint_cancel_recovery", EndpointRegion: "region_cancel_recovery", CredentialID: "credential_cancel_recovery", SubjectKind: resolve.ExecutionSubjectModel, ProviderModelID: "model_cancel_recovery", OfferingID: "offering_cancel_recovery", Operation: vcp.OperationConversationRespond, ActionBindingID: "action_cancel_recovery", ExecutionProfileID: "profile_cancel_recovery", UpstreamModelID: "upstream_cancel_recovery", ModelCapabilities: conversationTestCapabilities(false, true), CapabilityRevision: 1, ProviderConfigRevision: 1, CatalogRevision: 1}
	resolver := &staticResolver{target: target}
	configurations := staticConfigurations{definition: providerconfig.ProviderDefinition{ID: target.ProviderDefinitionID}, endpoint: providerconfig.Endpoint{ID: target.EndpointID, ProviderInstanceID: target.ProviderInstanceID, ChannelID: target.ChannelID, BaseURL: "https://cancel-recovery.example", Region: target.EndpointRegion, Status: providerconfig.EndpointReady}, credential: providerconfig.Credential{ID: target.CredentialID, ProviderInstanceID: target.ProviderInstanceID, Status: providerconfig.CredentialActive}}
	executor := &recordingTaskProviderExecutor{}
	store := NewMemoryStore()
	service, errService := NewService(store, resolver, configurations, nil, nil, executor, ServiceOptions{NewID: func() (string, error) { return "exe_cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", nil }, Now: func() time.Time { return now }, Retention: time.Hour})
	if errService != nil {
		t.Fatalf("NewService() error = %v", errService)
	}
	request := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request_cancel_recovery", Target: vcp.TargetSelection{Model: &vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: target.ProviderInstanceID, ProviderModelID: target.ProviderModelID, ExecutionProfileID: target.ExecutionProfileID}}, Operation: vcp.OperationConversationRespond, Payload: vcp.OperationPayload{Conversation: &vcp.ConversationOperation{}}}
	queued, _, errCreate := service.Create(context.Background(), "api_cancel_recovery", request)
	if errCreate != nil || queued.ProviderTask == nil || queued.Status != StatusQueued {
		t.Fatalf("Create() record = %+v, error = %v", queued, errCreate)
	}
	cancellationRequestedAt := now
	queued.ProviderTask.CancellationRequestedAt = &cancellationRequestedAt
	queued.ProviderTask.CancellationAfter = now
	expectedRevision := queued.Revision
	queued.Revision++
	queued.UpdatedAt = now
	if errSave := store.Save(context.Background(), queued, expectedRevision, []Event{lifecycleEvent(queued.ID, queued.Revision, now, EventExecutionCancellationRequested, queued.Status, nil)}); errSave != nil {
		t.Fatalf("persist cancellation intent: %v", errSave)
	}
	if errRecover := service.RecoverOnce(context.Background()); errRecover != nil {
		t.Fatalf("RecoverOnce() error = %v", errRecover)
	}
	terminal, errGet := service.Get(context.Background(), queued.OwnerAPIKeyID, queued.ID)
	if errGet != nil || terminal.Status != StatusCancelled || terminal.ProviderTask != nil {
		t.Fatalf("recovered cancellation = %+v, error = %v", terminal, errGet)
	}
	if executor.cancellations != 1 || executor.polls != 0 || executor.cancellationRequest.Binding.Target.EndpointID != target.EndpointID || executor.cancellationRequest.Binding.Credential.ID != target.CredentialID {
		t.Fatalf("cancellations=%d polls=%d request=%+v", executor.cancellations, executor.polls, executor.cancellationRequest.Binding)
	}
}

// TestServiceRecoversAcceptedTaskWithRouterIdempotency verifies the pre-task crash window restarts with one private replay-stable execution identity.
// TestServiceRecoversAcceptedTaskWithRouterIdempotency 验证任务保存前崩溃窗口使用一个私有且重放稳定的执行身份重新启动。
func TestServiceRecoversAcceptedTaskWithRouterIdempotency(t *testing.T) {
	now := time.Date(2026, time.July, 20, 14, 0, 0, 0, time.UTC)
	target := resolve.Target{ProviderDefinitionID: "definition_async", ProviderInstanceID: "pvi_async", ChannelID: "channel_async", EndpointID: "endpoint_async", EndpointRegion: "region_async", CredentialID: "credential_async", SubjectKind: resolve.ExecutionSubjectModel, ProviderModelID: "model_async", OfferingID: "offering_async", Operation: vcp.OperationConversationRespond, ActionBindingID: "action_async", ExecutionProfileID: "profile_async", UpstreamModelID: "upstream_async", ModelCapabilities: conversationTestCapabilities(false, true), CapabilityRevision: 1, ProviderConfigRevision: 1, CatalogRevision: 1}
	resolver := &staticResolver{target: target}
	configurations := staticConfigurations{definition: providerconfig.ProviderDefinition{ID: target.ProviderDefinitionID}, endpoint: providerconfig.Endpoint{ID: target.EndpointID, ProviderInstanceID: target.ProviderInstanceID, ChannelID: target.ChannelID, BaseURL: "https://async.example", Region: target.EndpointRegion, Status: providerconfig.EndpointReady}, credential: providerconfig.Credential{ID: target.CredentialID, ProviderInstanceID: target.ProviderInstanceID, Status: providerconfig.CredentialActive}}
	executor := &recordingTaskProviderExecutor{}
	store := NewMemoryStore()
	service, errService := NewService(store, resolver, configurations, nil, nil, executor, ServiceOptions{Now: func() time.Time { return now }, Retention: time.Hour})
	if errService != nil {
		t.Fatalf("NewService() error = %v", errService)
	}
	request := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request_recover", IdempotencyKey: "caller-local-key", Target: vcp.TargetSelection{Model: &vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: target.ProviderInstanceID, ProviderModelID: target.ProviderModelID, ExecutionProfileID: target.ExecutionProfileID}}, Operation: vcp.OperationConversationRespond, Payload: vcp.OperationPayload{Conversation: &vcp.ConversationOperation{}}}
	record := Record{ID: "exe_cccccccccccccccccccccccccccccccc", OwnerAPIKeyID: "api_async", RequestHash: "request-hash", IdempotencyKey: request.IdempotencyKey, Request: request, Target: target, Status: StatusAccepted, Operation: request.Operation, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour), Revision: 1}
	if _, _, errCreate := store.Create(context.Background(), record, lifecycleEvent(record.ID, 1, now, EventExecutionAccepted, StatusAccepted, nil)); errCreate != nil {
		t.Fatalf("MemoryStore.Create() error = %v", errCreate)
	}
	if errRecover := service.RecoverOnce(context.Background()); errRecover != nil {
		t.Fatalf("RecoverOnce() error = %v", errRecover)
	}
	recovered, errGet := service.Get(context.Background(), record.OwnerAPIKeyID, record.ID)
	if errGet != nil || recovered.Status != StatusQueued || recovered.ProviderTask == nil || executor.starts != 1 {
		t.Fatalf("recovered=%#v starts=%d error=%v", recovered, executor.starts, errGet)
	}
	if executor.startRequest.Execution == nil || executor.startRequest.Execution.IdempotencyKey != record.ID {
		t.Fatalf("upstream idempotency key = %#v, want execution id", executor.startRequest.Execution)
	}
	if recovered.Request.IdempotencyKey != "caller-local-key" {
		t.Fatalf("persisted caller idempotency key = %q", recovered.Request.IdempotencyKey)
	}
}

// TestServiceRecoveryExpiresBeforeRestart verifies retention wins before an accepted execution is restarted.
// TestServiceRecoveryExpiresBeforeRestart 验证保留期限在重新启动已接收执行前生效。
func TestServiceRecoveryExpiresBeforeRestart(t *testing.T) {
	now := time.Date(2026, time.July, 20, 15, 0, 0, 0, time.UTC)
	target := resolve.Target{ProviderDefinitionID: "definition_async", ProviderInstanceID: "pvi_async", ChannelID: "channel_async", EndpointID: "endpoint_async", EndpointRegion: "region_async", CredentialID: "credential_async", SubjectKind: resolve.ExecutionSubjectModel, ProviderModelID: "model_async", OfferingID: "offering_async", Operation: vcp.OperationConversationRespond, ActionBindingID: "action_async", ExecutionProfileID: "profile_async", UpstreamModelID: "upstream_async", ModelCapabilities: conversationTestCapabilities(false, true), CapabilityRevision: 1, ProviderConfigRevision: 1, CatalogRevision: 1}
	resolver := &staticResolver{target: target}
	configurations := staticConfigurations{definition: providerconfig.ProviderDefinition{ID: target.ProviderDefinitionID}, endpoint: providerconfig.Endpoint{ID: target.EndpointID, ProviderInstanceID: target.ProviderInstanceID, ChannelID: target.ChannelID, BaseURL: "https://async.example", Region: target.EndpointRegion, Status: providerconfig.EndpointReady}, credential: providerconfig.Credential{ID: target.CredentialID, ProviderInstanceID: target.ProviderInstanceID, Status: providerconfig.CredentialActive}}
	executor := &recordingTaskProviderExecutor{}
	store := NewMemoryStore()
	service, errService := NewService(store, resolver, configurations, nil, nil, executor, ServiceOptions{Now: func() time.Time { return now }, Retention: time.Hour})
	if errService != nil {
		t.Fatalf("NewService() error = %v", errService)
	}
	request := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request_expired", Target: vcp.TargetSelection{Model: &vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: target.ProviderInstanceID, ProviderModelID: target.ProviderModelID, ExecutionProfileID: target.ExecutionProfileID}}, Operation: vcp.OperationConversationRespond, Payload: vcp.OperationPayload{Conversation: &vcp.ConversationOperation{}}}
	record := Record{ID: "exe_dddddddddddddddddddddddddddddddd", OwnerAPIKeyID: "api_async", RequestHash: "request-hash", Request: request, Target: target, Status: StatusAccepted, Operation: request.Operation, CreatedAt: now.Add(-2 * time.Hour), UpdatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour), Revision: 1}
	if _, _, errCreate := store.Create(context.Background(), record, lifecycleEvent(record.ID, 1, record.CreatedAt, EventExecutionAccepted, StatusAccepted, nil)); errCreate != nil {
		t.Fatalf("MemoryStore.Create() error = %v", errCreate)
	}
	if errRecover := service.RecoverOnce(context.Background()); errRecover != nil {
		t.Fatalf("RecoverOnce() error = %v", errRecover)
	}
	expired, errGet := service.Get(context.Background(), record.OwnerAPIKeyID, record.ID)
	if errGet != nil || expired.Status != StatusExpired || executor.starts != 0 || executor.polls != 0 {
		t.Fatalf("expired=%#v starts=%d polls=%d error=%v", expired, executor.starts, executor.polls, errGet)
	}
}

// conversationTestCapabilities returns one valid minimal conversation profile for service orchestration tests.
// conversationTestCapabilities 为服务编排测试返回一个有效的最小会话 Profile。
func conversationTestCapabilities(synchronous bool, asynchronous bool) catalog.ModelCapabilities {
	return catalog.ModelCapabilities{ToolCalling: catalog.CapabilityUnsupported, ParallelToolCalls: catalog.CapabilityUnsupported, StreamingToolArguments: catalog.CapabilityUnsupported, StrictJSONSchema: catalog.CapabilityUnsupported, Reasoning: catalog.CapabilityUnsupported, InputModalities: []string{"text"}, OutputModalities: []string{"text"}, Delivery: catalog.DeliveryCapabilities{Synchronous: synchronous, Asynchronous: asynchronous}}
}
