package execution

import (
	"context"
	"errors"
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
}

// Resolve returns the exact configured target.
// Resolve 返回精确配置 Target。
func (r *staticResolver) Resolve(context.Context, resolve.Request) (resolve.Target, resolve.Diagnostics, error) {
	r.calls++
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
	// pollRequest records the immutable recovered request.
	// pollRequest 记录不可变恢复请求。
	pollRequest provider.ExecutionRequest
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
	result := provider.ExecutionResult{Response: vcp.Response{ResponseID: "response_async", Status: vcp.ResponseCompleted}}
	return provider.TaskResult{ProviderTaskID: providerTaskID, State: provider.TaskSucceeded, Result: &result}, nil
}

// CancelTask returns one provider-confirmed cancelled task.
// CancelTask 返回一个供应商确认取消任务。
func (e *recordingTaskProviderExecutor) CancelTask(_ context.Context, _ provider.ExecutionRequest, providerTaskID string) (provider.TaskResult, error) {
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
