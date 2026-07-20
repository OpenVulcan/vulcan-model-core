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
