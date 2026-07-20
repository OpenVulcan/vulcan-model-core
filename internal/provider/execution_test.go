package provider

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestExecutionRegistryDispatchesExactDefinitionAndProfile verifies target-owned Driver selection.
// TestExecutionRegistryDispatchesExactDefinitionAndProfile 验证由 Target 所有的精确 Driver 选择。
func TestExecutionRegistryDispatchesExactDefinitionAndProfile(t *testing.T) {
	registry := NewExecutionRegistry()
	driver := &recordingExecutionDriver{definitionID: "definition-1", profileID: "openai.responses"}
	if errRegister := registry.Register(driver); errRegister != nil {
		t.Fatalf("Register() error = %v", errRegister)
	}
	result, errExecute := registry.Execute(context.Background(), validExecutionRequest())
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if !driver.executed || result.UpstreamResponseID != "res-upstream" {
		t.Fatalf("driver execution = %v, result = %#v", driver.executed, result)
	}
}

// TestExecutionRegistryDispatchesExactDefinitionAndAction verifies service execution uses only the immutable action binding.
// TestExecutionRegistryDispatchesExactDefinitionAndAction 验证服务执行只使用不可变动作绑定。
func TestExecutionRegistryDispatchesExactDefinitionAndAction(t *testing.T) {
	registry := NewExecutionRegistry()
	driver := &recordingActionExecutionDriver{definitionID: "definition-search", actionBindingID: "search-web"}
	if errRegister := registry.RegisterAction(driver); errRegister != nil {
		t.Fatalf("RegisterAction() error = %v", errRegister)
	}
	result, errExecute := registry.Execute(context.Background(), validActionExecutionRequest())
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if !driver.executed || result.UpstreamResponseID != "action-upstream" {
		t.Fatalf("driver execution = %v, result = %#v", driver.executed, result)
	}
}

// TestExecutionRegistryRejectsActionTargetDrift verifies canonical service selection cannot cross the resolved target.
// TestExecutionRegistryRejectsActionTargetDrift 验证规范服务选择不能跨越已解析 Target。
func TestExecutionRegistryRejectsActionTargetDrift(t *testing.T) {
	registry := NewExecutionRegistry()
	driver := &recordingActionExecutionDriver{definitionID: "definition-search", actionBindingID: "search-web"}
	if errRegister := registry.RegisterAction(driver); errRegister != nil {
		t.Fatalf("RegisterAction() error = %v", errRegister)
	}
	request := validActionExecutionRequest()
	request.Execution.Target.Service.ProviderServiceID = "service-foreign"
	_, errExecute := registry.Execute(context.Background(), request)
	if !errors.Is(errExecute, ErrExecutionBinding) || driver.executed {
		t.Fatalf("Execute() error = %v, driver executed = %v", errExecute, driver.executed)
	}
}

// TestExecutionRegistryRejectsDuplicateActionOwnership verifies one action has exactly one registered Driver.
// TestExecutionRegistryRejectsDuplicateActionOwnership 验证一个动作只有一个已注册 Driver。
func TestExecutionRegistryRejectsDuplicateActionOwnership(t *testing.T) {
	registry := NewExecutionRegistry()
	driver := &recordingActionExecutionDriver{definitionID: "definition-search", actionBindingID: "search-web"}
	if errRegister := registry.RegisterAction(driver); errRegister != nil {
		t.Fatalf("first RegisterAction() error = %v", errRegister)
	}
	if errRegister := registry.RegisterAction(driver); !errors.Is(errRegister, ErrActionExecutionDriverDuplicate) {
		t.Fatalf("second RegisterAction() error = %v, want ErrActionExecutionDriverDuplicate", errRegister)
	}
}

// TestConversationActionDriverPreservesProvenProfileExecution verifies action migration does not rewrite provider wire ownership.
// TestConversationActionDriverPreservesProvenProfileExecution 验证动作迁移不会改写供应商 wire 归属。
func TestConversationActionDriverPreservesProvenProfileExecution(t *testing.T) {
	registry := NewExecutionRegistry()
	profileDriver := &recordingExecutionDriver{definitionID: "definition-1", profileID: "openai.responses"}
	actionDriver, errAction := NewConversationActionDriver("action_conversation_respond", profileDriver)
	if errAction != nil {
		t.Fatalf("NewConversationActionDriver() error = %v", errAction)
	}
	if errRegister := registry.RegisterAction(actionDriver); errRegister != nil {
		t.Fatalf("RegisterAction() error = %v", errRegister)
	}
	request := validExecutionRequest()
	request.Binding.Target.SubjectKind = resolve.ExecutionSubjectModel
	request.Binding.Target.OfferingID = "offering-1"
	request.Binding.Target.Operation = vcp.OperationConversationRespond
	request.Binding.Target.ActionBindingID = "action_conversation_respond"
	request.Definition.ActionBindings = []providerconfig.ProviderActionBinding{{
		ID: "action_conversation_respond", Operation: vcp.OperationConversationRespond, DriverID: "openai", DriverVersion: "1", ProtocolProfileID: "openai.responses", EndpointProfileID: "responses", AuthMethodIDs: []string{"api-key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true, Streaming: true}, Revision: 1,
	}}
	legacy := request.Request
	request.Request = vcp.VulcanRequest{}
	request.Execution = &vcp.ExecutionRequest{
		ProtocolVersion: legacy.ProtocolVersion, RequestID: legacy.RequestID, Target: vcp.TargetSelection{Model: &legacy.ModelSelection}, Operation: vcp.OperationConversationRespond, Stream: legacy.Stream,
		Payload: vcp.OperationPayload{Conversation: &vcp.ConversationOperation{
			Context: legacy.Context, Tools: legacy.Tools, ToolPolicy: legacy.ToolPolicy, GenerationPolicy: legacy.GenerationPolicy, ReasoningPolicy: legacy.ReasoningPolicy,
			CachePolicy: legacy.CachePolicy, ContextManagementPolicy: legacy.ContextManagementPolicy, RemoteCompaction: legacy.RemoteCompaction, CapabilityPolicy: legacy.CapabilityPolicy, RegisteredExtensions: legacy.RegisteredExtensions,
		}},
	}
	result, errExecute := registry.Execute(context.Background(), request)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if !profileDriver.executed || result.UpstreamResponseID != "res-upstream" {
		t.Fatalf("profile driver execution = %v, result = %#v", profileDriver.executed, result)
	}
}

// TestExecutionRegistryBuildsCustomDriverFromImmutableDefinition verifies dynamic dispatch uses the exact custom definition snapshot.
// TestExecutionRegistryBuildsCustomDriverFromImmutableDefinition 验证动态分派使用精确的自定义 Definition 快照。
func TestExecutionRegistryBuildsCustomDriverFromImmutableDefinition(t *testing.T) {
	registry := NewExecutionRegistry()
	factory := &recordingCustomDriverFactory{}
	if errRegister := registry.RegisterCustomFactory(factory); errRegister != nil {
		t.Fatalf("RegisterCustomFactory() error = %v", errRegister)
	}
	request := validExecutionRequest()
	request.Definition.Kind = providerconfig.DefinitionKindCustom
	request.Definition.Revision = 7
	result, errExecute := registry.Execute(context.Background(), request)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if factory.definition.ID != request.Definition.ID || factory.definition.Revision != 7 || !factory.driver.executed || result.UpstreamResponseID != "res-upstream" {
		t.Fatalf("factory definition = %#v, driver = %#v, result = %#v", factory.definition, factory.driver, result)
	}
}

// TestExecutionRegistryNeverUsesCustomFactoryForSystemDefinition verifies runtime factories cannot capture missing system integrations.
// TestExecutionRegistryNeverUsesCustomFactoryForSystemDefinition 验证运行时 Factory 不能接管缺失的系统集成。
func TestExecutionRegistryNeverUsesCustomFactoryForSystemDefinition(t *testing.T) {
	registry := NewExecutionRegistry()
	factory := &recordingCustomDriverFactory{}
	if errRegister := registry.RegisterCustomFactory(factory); errRegister != nil {
		t.Fatalf("RegisterCustomFactory() error = %v", errRegister)
	}
	_, errExecute := registry.Execute(context.Background(), validExecutionRequest())
	if !errors.Is(errExecute, ErrExecutionDriverNotFound) || factory.called {
		t.Fatalf("Execute() error = %v, factory called = %v", errExecute, factory.called)
	}
}

// TestExecutionRegistryRejectsCustomFactoryOwnershipDrift verifies a factory cannot return a Driver for another definition.
// TestExecutionRegistryRejectsCustomFactoryOwnershipDrift 验证 Factory 不能返回属于其他 Definition 的 Driver。
func TestExecutionRegistryRejectsCustomFactoryOwnershipDrift(t *testing.T) {
	registry := NewExecutionRegistry()
	factory := &recordingCustomDriverFactory{definitionOverride: "definition-foreign"}
	if errRegister := registry.RegisterCustomFactory(factory); errRegister != nil {
		t.Fatalf("RegisterCustomFactory() error = %v", errRegister)
	}
	request := validExecutionRequest()
	request.Definition.Kind = providerconfig.DefinitionKindCustom
	_, errExecute := registry.Execute(context.Background(), request)
	if !errors.Is(errExecute, ErrExecutionBinding) {
		t.Fatalf("Execute() error = %v, want ErrExecutionBinding", errExecute)
	}
}

// TestExecutionRegistryRejectsDuplicateCustomFactory verifies custom runtime ownership remains singular.
// TestExecutionRegistryRejectsDuplicateCustomFactory 验证自定义运行时归属保持唯一。
func TestExecutionRegistryRejectsDuplicateCustomFactory(t *testing.T) {
	registry := NewExecutionRegistry()
	if errRegister := registry.RegisterCustomFactory(&recordingCustomDriverFactory{}); errRegister != nil {
		t.Fatalf("first RegisterCustomFactory() error = %v", errRegister)
	}
	if errRegister := registry.RegisterCustomFactory(&recordingCustomDriverFactory{}); !errors.Is(errRegister, ErrCustomExecutionFactoryDuplicate) {
		t.Fatalf("second RegisterCustomFactory() error = %v, want ErrCustomExecutionFactoryDuplicate", errRegister)
	}
}

// TestExecutionRegistryRejectsTypedNilExtensions verifies nil pointer implementations cannot panic during registration or factory dispatch.
// TestExecutionRegistryRejectsTypedNilExtensions 验证 nil 指针实现不能在注册或 Factory 分派期间触发 panic。
func TestExecutionRegistryRejectsTypedNilExtensions(t *testing.T) {
	registry := NewExecutionRegistry()
	var driver *recordingExecutionDriver
	if errRegister := registry.Register(driver); !errors.Is(errRegister, ErrExecutionDriverRequired) {
		t.Fatalf("Register(typed nil) error = %v, want ErrExecutionDriverRequired", errRegister)
	}
	var factory *recordingCustomDriverFactory
	if errRegister := registry.RegisterCustomFactory(factory); !errors.Is(errRegister, ErrCustomExecutionFactoryRequired) {
		t.Fatalf("RegisterCustomFactory(typed nil) error = %v, want ErrCustomExecutionFactoryRequired", errRegister)
	}
}

// TestExecutionRequestRejectsChannelProfileMismatch verifies a Driver cannot execute another channel profile.
// TestExecutionRequestRejectsChannelProfileMismatch 验证 Driver 不能执行其他 Channel Profile。
func TestExecutionRequestRejectsChannelProfileMismatch(t *testing.T) {
	request := validExecutionRequest()
	_, errValidate := request.ValidateForProfile("google.aistudio")
	if !errors.Is(errValidate, ErrExecutionBinding) {
		t.Fatalf("ValidateForProfile() error = %v, want ErrExecutionBinding", errValidate)
	}
}

// TestExecutionRequestRejectsForeignContinuation verifies continuation affinity is checked before network execution.
// TestExecutionRequestRejectsForeignContinuation 验证会在网络执行前检查续接亲和性。
func TestExecutionRequestRejectsForeignContinuation(t *testing.T) {
	request := validExecutionRequest()
	request.Request.Context = nil
	request.Request.ReasoningPolicy.ContinuationID = "continuation-1"
	request.Continuation = &ContinuationBinding{
		ContinuationID: "continuation-1", ProviderDefinitionID: "definition-foreign", ProviderInstanceID: "instance-1",
		ChannelID: "channel-1", EndpointID: "endpoint-1", CredentialID: "credential-1", ProviderModelID: "model-1", UpstreamModelID: "upstream-model", ExecutionProfileID: "profile-1", UpstreamResponseID: "res-upstream",
	}
	_, errValidate := request.ValidateForProfile("openai.responses")
	if !errors.Is(errValidate, ErrExecutionBinding) {
		t.Fatalf("ValidateForProfile() error = %v, want ErrExecutionBinding", errValidate)
	}
}

// TestExecutionRequestAcceptsRemoteCompactionContinuation verifies explicit remote compaction resolves through the same immutable provider binding.
// TestExecutionRequestAcceptsRemoteCompactionContinuation 验证显式远程压缩通过相同不可变 Provider 绑定解析。
func TestExecutionRequestAcceptsRemoteCompactionContinuation(t *testing.T) {
	request := validExecutionRequest()
	request.Request.RemoteCompaction = &vcp.RemoteCompactionRequest{PreviousResponseID: "continuation-1"}
	request.Continuation = &ContinuationBinding{
		ContinuationID: "continuation-1", ProviderDefinitionID: "definition-1", ProviderInstanceID: "instance-1",
		ChannelID: "channel-1", EndpointID: "endpoint-1", CredentialID: "credential-1", ProviderModelID: "model-1", UpstreamModelID: "upstream-model", ExecutionProfileID: "profile-1", UpstreamResponseID: "res-upstream",
	}
	if _, errValidate := request.ValidateForProfile("openai.responses"); errValidate != nil {
		t.Fatalf("ValidateForProfile() error = %v", errValidate)
	}
}

// TestExecutionRequestRejectsTargetScopedContinuationDrift verifies a sealed response identifier cannot cross an immutable target's network, credential, or wire-model boundary.
// TestExecutionRequestRejectsTargetScopedContinuationDrift 验证密封响应标识不能跨越不可变 Target 的网络、Credential 或 wire 模型边界。
func TestExecutionRequestRejectsTargetScopedContinuationDrift(t *testing.T) {
	for _, testCase := range []struct {
		// name identifies the exact target-bound continuation field under test.
		// name 标识待测的精确 Target 绑定续接字段。
		name string
		// mutate changes one continuation field away from the resolved target value.
		// mutate 将一条续接字段更改为不同于已解析 Target 的值。
		mutate func(*ContinuationBinding)
	}{
		{name: "endpoint", mutate: func(binding *ContinuationBinding) { binding.EndpointID = "endpoint-foreign" }},
		{name: "credential", mutate: func(binding *ContinuationBinding) { binding.CredentialID = "credential-foreign" }},
		{name: "upstream_model", mutate: func(binding *ContinuationBinding) { binding.UpstreamModelID = "upstream-model-foreign" }},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			request := validExecutionRequest()
			request.Request.Context = nil
			request.Request.ReasoningPolicy.ContinuationID = "continuation-1"
			continuation := &ContinuationBinding{
				ContinuationID: "continuation-1", ProviderDefinitionID: "definition-1", ProviderInstanceID: "instance-1", ChannelID: "channel-1",
				EndpointID: "endpoint-1", CredentialID: "credential-1", ProviderModelID: "model-1", UpstreamModelID: "upstream-model", ExecutionProfileID: "profile-1", UpstreamResponseID: "res-upstream",
			}
			testCase.mutate(continuation)
			request.Continuation = continuation
			if _, errValidate := request.ValidateForProfile("openai.responses"); !errors.Is(errValidate, ErrExecutionBinding) {
				t.Fatalf("ValidateForProfile() error = %v, want ErrExecutionBinding", errValidate)
			}
		})
	}
}

// TestExecutionRequestRejectsUndeclaredCredentialAuthMethod verifies a credential cannot select an identifier absent from the immutable definition.
// TestExecutionRequestRejectsUndeclaredCredentialAuthMethod 验证凭据不能选择不可变 Definition 中不存在的认证标识。
func TestExecutionRequestRejectsUndeclaredCredentialAuthMethod(t *testing.T) {
	request := validExecutionRequest()
	request.Definition.AuthMethods = nil
	if _, errValidate := request.ValidateForProfile("openai.responses"); !errors.Is(errValidate, ErrExecutionBinding) {
		t.Fatalf("ValidateForProfile() error = %v, want ErrExecutionBinding", errValidate)
	}
}

// TestExecutionRequestRejectsUnsupportedCredentialAuthType verifies a Driver can reject a declared credential type that its concrete wire carrier cannot encode.
// TestExecutionRequestRejectsUnsupportedCredentialAuthType 验证 Driver 可以拒绝其具体 wire 载体无法编码的已声明凭据类型。
func TestExecutionRequestRejectsUnsupportedCredentialAuthType(t *testing.T) {
	request := validExecutionRequest()
	request.Definition.AuthMethods[0].Type = providerconfig.AuthMethodBearer
	if _, errValidate := request.ValidateForProfile("openai.responses", providerconfig.AuthMethodAPIKey); !errors.Is(errValidate, ErrExecutionBinding) {
		t.Fatalf("ValidateForProfile() error = %v, want ErrExecutionBinding", errValidate)
	}
}

// recordingExecutionDriver records dispatches without performing a network operation.
// recordingExecutionDriver 在不执行网络操作的前提下记录分派。
type recordingExecutionDriver struct {
	// definitionID is the exact provider definition accepted by this test Driver.
	// definitionID 是此测试 Driver 接受的精确供应商 Definition。
	definitionID string
	// profileID is the exact protocol profile accepted by this test Driver.
	// profileID 是此测试 Driver 接受的精确协议 Profile。
	profileID string
	// executed reports whether Execute received a validated request.
	// executed 表示 Execute 是否收到已校验请求。
	executed bool
}

// recordingActionExecutionDriver records exact action dispatches without network traffic.
// recordingActionExecutionDriver 在不产生网络流量的前提下记录精确动作分派。
type recordingActionExecutionDriver struct {
	// definitionID is the exact provider definition accepted by this test Driver.
	// definitionID 是此测试 Driver 接受的精确供应商 Definition。
	definitionID string
	// actionBindingID is the exact provider action accepted by this test Driver.
	// actionBindingID 是此测试 Driver 接受的精确供应商动作。
	actionBindingID string
	// executed reports whether Execute received a validated request.
	// executed 表示 Execute 是否收到已校验请求。
	executed bool
}

// recordingCustomDriverFactory captures immutable custom definition snapshots for registry tests.
// recordingCustomDriverFactory 捕获不可变的自定义 Definition 快照以供注册表测试。
type recordingCustomDriverFactory struct {
	// definition records the exact snapshot supplied by the registry.
	// definition 记录注册表提供的精确快照。
	definition providerconfig.ProviderDefinition
	// definitionOverride optionally forces invalid returned Driver ownership.
	// definitionOverride 可选地强制返回无效的 Driver 归属。
	definitionOverride string
	// driver records execution performed by the factory-created Driver.
	// driver 记录 Factory 创建的 Driver 所执行的调用。
	driver *recordingExecutionDriver
	// called reports whether the registry invoked this Factory.
	// called 表示注册表是否调用了此 Factory。
	called bool
}

// BuildCustomDriver records one custom snapshot and returns an exactly bound test Driver unless ownership drift is requested.
// BuildCustomDriver 记录一个自定义快照，并在未要求归属漂移时返回精确绑定的测试 Driver。
func (f *recordingCustomDriverFactory) BuildCustomDriver(definition providerconfig.ProviderDefinition) (ExecutionDriver, error) {
	f.called = true
	f.definition = definition
	definitionID := definition.ID
	if f.definitionOverride != "" {
		definitionID = f.definitionOverride
	}
	f.driver = &recordingExecutionDriver{definitionID: definitionID, profileID: definition.ProtocolProfileID}
	return f.driver, nil
}

// ProviderDefinitionID returns the test Driver definition ownership.
// ProviderDefinitionID 返回测试 Driver 的 Definition 归属。
func (d *recordingExecutionDriver) ProviderDefinitionID() string {
	return d.definitionID
}

// ProtocolProfileID returns the test Driver protocol ownership.
// ProtocolProfileID 返回测试 Driver 的协议归属。
func (d *recordingExecutionDriver) ProtocolProfileID() string {
	return d.profileID
}

// Execute records a validated request and returns safe mock continuation data.
// Execute 记录已校验请求并返回安全的模拟续接数据。
func (d *recordingExecutionDriver) Execute(_ context.Context, _ ExecutionRequest) (ExecutionResult, error) {
	d.executed = true
	return ExecutionResult{UpstreamResponseID: "res-upstream"}, nil
}

// ProviderDefinitionID returns the test action Driver definition ownership.
// ProviderDefinitionID 返回测试动作 Driver 的 Definition 归属。
func (d *recordingActionExecutionDriver) ProviderDefinitionID() string {
	return d.definitionID
}

// ActionBindingID returns the test action Driver action ownership.
// ActionBindingID 返回测试动作 Driver 的动作归属。
func (d *recordingActionExecutionDriver) ActionBindingID() string {
	return d.actionBindingID
}

// Execute records one validated action request and returns safe mock state.
// Execute 记录一条已校验动作请求并返回安全模拟状态。
func (d *recordingActionExecutionDriver) Execute(_ context.Context, _ ExecutionRequest) (ExecutionResult, error) {
	d.executed = true
	return ExecutionResult{UpstreamResponseID: "action-upstream"}, nil
}

// recordingTaskExecutionDriver records exact asynchronous lifecycle dispatch.
// recordingTaskExecutionDriver 记录精确异步生命周期分派。
type recordingTaskExecutionDriver struct {
	// definitionID is the sole provider owner.
	// definitionID 是唯一供应商所有者。
	definitionID string
	// actionBindingID is the sole action owner.
	// actionBindingID 是唯一动作所有者。
	actionBindingID string
	// started records start dispatch.
	// started 记录创建分派。
	started bool
	// polled records poll dispatch.
	// polled 记录轮询分派。
	polled bool
	// cancelled records cancel dispatch.
	// cancelled 记录取消分派。
	cancelled bool
}

// ProviderDefinitionID returns the sole provider owner.
// ProviderDefinitionID 返回唯一供应商所有者。
func (d *recordingTaskExecutionDriver) ProviderDefinitionID() string { return d.definitionID }

// ActionBindingID returns the sole action owner.
// ActionBindingID 返回唯一动作所有者。
func (d *recordingTaskExecutionDriver) ActionBindingID() string { return d.actionBindingID }

// Start returns one provider-confirmed queued task.
// Start 返回一个供应商确认排队任务。
func (d *recordingTaskExecutionDriver) Start(_ context.Context, request ExecutionRequest) (TaskResult, error) {
	d.started = true
	return TaskResult{ProviderTaskID: "task_test", State: TaskQueued, PollAfter: request.Now.Add(time.Second)}, nil
}

// Poll returns one provider-confirmed successful task.
// Poll 返回一个供应商确认成功任务。
func (d *recordingTaskExecutionDriver) Poll(_ context.Context, _ ExecutionRequest, providerTaskID string) (TaskResult, error) {
	d.polled = true
	result := ExecutionResult{Search: &vcp.WebSearchResponse{Query: "Vulcan"}}
	return TaskResult{ProviderTaskID: providerTaskID, State: TaskSucceeded, Result: &result}, nil
}

// Cancel returns one provider-confirmed cancelled task.
// Cancel 返回一个供应商确认取消任务。
func (d *recordingTaskExecutionDriver) Cancel(_ context.Context, _ ExecutionRequest, providerTaskID string) (TaskResult, error) {
	d.cancelled = true
	return TaskResult{ProviderTaskID: providerTaskID, State: TaskCancelled}, nil
}

// TestExecutionRegistryDispatchesExactAsynchronousTaskLifecycle verifies task affinity and closed state validation.
// TestExecutionRegistryDispatchesExactAsynchronousTaskLifecycle 验证任务亲和性与封闭状态校验。
func TestExecutionRegistryDispatchesExactAsynchronousTaskLifecycle(t *testing.T) {
	registry := NewExecutionRegistry()
	driver := &recordingTaskExecutionDriver{definitionID: "definition-search", actionBindingID: "search-web"}
	if errRegister := registry.RegisterTaskAction(driver); errRegister != nil {
		t.Fatalf("register task driver: %v", errRegister)
	}
	request := validActionExecutionRequest()
	request.Definition.ActionBindings[0].Delivery = providerconfig.ActionDeliveryModes{Asynchronous: true}
	started, errStart := registry.StartTask(context.Background(), request)
	if errStart != nil || !driver.started || started.State != TaskQueued {
		t.Fatalf("start=%+v error=%v called=%t", started, errStart, driver.started)
	}
	polled, errPoll := registry.PollTask(context.Background(), request, started.ProviderTaskID)
	if errPoll != nil || !driver.polled || polled.State != TaskSucceeded {
		t.Fatalf("poll=%+v error=%v called=%t", polled, errPoll, driver.polled)
	}
	cancelled, errCancel := registry.CancelTask(context.Background(), request, started.ProviderTaskID)
	if errCancel != nil || !driver.cancelled || cancelled.State != TaskCancelled {
		t.Fatalf("cancel=%+v error=%v called=%t", cancelled, errCancel, driver.cancelled)
	}
}

// TestTaskResultRejectsProviderControlledFailureCode verifies that arbitrary upstream text cannot become a public failure code.
// TestTaskResultRejectsProviderControlledFailureCode 验证任意上游文本不能成为公开失败码。
func TestTaskResultRejectsProviderControlledFailureCode(t *testing.T) {
	result := TaskResult{ProviderTaskID: "task_test", State: TaskFailed, ErrorCode: "upstream_secret_or_message"}
	if errValidate := result.Validate(); errValidate == nil {
		t.Fatal("TaskResult.Validate() accepted a provider-controlled failure code")
	}

	result.ErrorCode = "provider_task_expired"
	if errValidate := result.Validate(); errValidate != nil {
		t.Fatalf("TaskResult.Validate() safe code error = %v", errValidate)
	}
}

// TestTaskResultRejectsCrossStateFields verifies polling and retry facts cannot leak into incompatible task states.
// TestTaskResultRejectsCrossStateFields 验证轮询与重试事实不能进入不兼容的任务状态。
func TestTaskResultRejectsCrossStateFields(t *testing.T) {
	now := time.Date(2026, time.July, 20, 0, 0, 0, 0, time.UTC)
	result := TaskResult{ProviderTaskID: "task_test", State: TaskQueued, PollAfter: now, Retryable: true}
	if errValidate := result.Validate(); errValidate == nil {
		t.Fatal("TaskResult.Validate() accepted retryability on a queued task")
	}
	completed := ExecutionResult{}
	result = TaskResult{ProviderTaskID: "task_test", State: TaskSucceeded, PollAfter: now, Result: &completed}
	if errValidate := result.Validate(); errValidate == nil {
		t.Fatal("TaskResult.Validate() accepted a poll time on a terminal task")
	}
}

// validExecutionRequest creates a complete executable fixture with exact channel and credential ownership.
// validExecutionRequest 创建具有精确 Channel、Credential 归属的完整可执行夹具。
func validExecutionRequest() ExecutionRequest {
	now := time.Date(2026, time.July, 17, 0, 0, 0, 0, time.UTC)
	return ExecutionRequest{
		Binding: transport.Binding{
			Target: resolve.Target{
				ProviderDefinitionID: "definition-1", ProviderInstanceID: "instance-1", ChannelID: "channel-1", EndpointID: "endpoint-1", CredentialID: "credential-1",
				ProviderModelID: "model-1", OfferingID: "offering-1", ExecutionProfileID: "profile-1", UpstreamModelID: "upstream-model",
			},
			Endpoint:   providerconfig.Endpoint{ID: "endpoint-1", ProviderInstanceID: "instance-1", ChannelID: "channel-1", BaseURL: "https://provider.example", Status: providerconfig.EndpointReady},
			Credential: providerconfig.Credential{ID: "credential-1", ProviderInstanceID: "instance-1", AuthMethodID: "api-key", SecretRef: "secret-1", Status: providerconfig.CredentialActive},
		},
		Definition: providerconfig.ProviderDefinition{
			ID: "definition-1", Kind: providerconfig.DefinitionKindSystem,
			ProtocolProfileID: "openai.responses", AuthMethodIDs: []string{"api-key"}, RuntimeReady: true,
			AuthMethods: []providerconfig.AuthMethodDefinition{{ID: "api-key", Type: providerconfig.AuthMethodAPIKey}},
		},
		Request: vcp.VulcanRequest{
			ProtocolVersion: vcp.ProtocolVersion, RequestID: "request-1",
			ModelSelection: vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: "instance-1", ProviderModelID: "model-1", ExecutionProfileID: "profile-1"},
			Context: []vcp.ContextItem{{
				ItemID: "item-user", Sequence: 1, Kind: vcp.ContextMessage, Authority: vcp.AuthorityUser, Actor: vcp.ActorEndUser,
				Placement: vcp.PlacementTranscript, Activation: vcp.Activation{Mode: vcp.ActivationRequestStart}, Visibility: vcp.VisibilityModel,
				Content: []vcp.ContentBlock{{Type: vcp.ContentText, Text: "Hello"}}, Message: &vcp.MessageItem{},
			}},
			CachePolicy:             vcp.CachePolicy{Strategy: vcp.CacheRegular, OnUnsupported: vcp.CacheUnsupportedReject},
			ContextManagementPolicy: vcp.ContextManagementPolicy{Mode: vcp.ContextManagementRegular},
			CapabilityPolicy:        vcp.CapabilityPolicy{ExecutionMode: vcp.CapabilityMaximize, OptionalOnUnsupported: vcp.OptionalOmit},
		},
		LineageID: "lineage-1", Now: now,
	}
}

// validActionExecutionRequest creates a complete service action fixture with exact ownership.
// validActionExecutionRequest 创建具有精确归属的完整服务动作夹具。
func validActionExecutionRequest() ExecutionRequest {
	now := time.Date(2026, time.July, 20, 0, 0, 0, 0, time.UTC)
	action := providerconfig.ProviderActionBinding{
		ID: "search-web", Operation: vcp.OperationSearchWeb, DriverID: "search-driver", DriverVersion: "1",
		ProtocolProfileID: "search.direct.v1", EndpointProfileID: "search-endpoint", AuthMethodIDs: []string{"api-key"},
		Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, Search: &providerconfig.SearchActionBinding{BackendKind: vcp.SearchBackendDirectAPI}, Revision: 1,
	}
	execution := &vcp.ExecutionRequest{
		ProtocolVersion: vcp.ProtocolVersion,
		RequestID:       "request-search",
		Target: vcp.TargetSelection{Service: &vcp.ServiceSelection{
			ProviderInstanceID: "instance-search", ProviderServiceID: "service-search", ServiceOfferingID: "offering-search", ExecutionProfileID: "profile-search",
		}},
		Operation: vcp.OperationSearchWeb,
		Payload: vcp.OperationPayload{SearchWeb: &vcp.WebSearchOperation{
			Query: "Vulcan", OutputMode: vcp.WebSearchOutputResults, EvidenceRequirement: vcp.SearchEvidenceVerified,
		}},
	}
	return ExecutionRequest{
		Binding: transport.Binding{
			Target: resolve.Target{
				ProviderDefinitionID: "definition-search", ProviderInstanceID: "instance-search", ChannelID: "channel-search", EndpointID: "endpoint-search", CredentialID: "credential-search",
				SubjectKind: resolve.ExecutionSubjectService, ProviderServiceID: "service-search", ServiceOfferingID: "offering-search", Operation: vcp.OperationSearchWeb,
				ActionBindingID: "search-web", ExecutionProfileID: "profile-search", UpstreamServiceID: "search-api",
			},
			Endpoint:   providerconfig.Endpoint{ID: "endpoint-search", ProviderInstanceID: "instance-search", ChannelID: "channel-search", BaseURL: "https://search.example", Status: providerconfig.EndpointReady},
			Credential: providerconfig.Credential{ID: "credential-search", ProviderInstanceID: "instance-search", AuthMethodID: "api-key", SecretRef: "secret-search", Status: providerconfig.CredentialActive},
		},
		Definition: providerconfig.ProviderDefinition{
			ID: "definition-search", Kind: providerconfig.DefinitionKindSystem, RuntimeReady: true,
			AuthMethods: []providerconfig.AuthMethodDefinition{{ID: "api-key", Type: providerconfig.AuthMethodAPIKey}}, ActionBindings: []providerconfig.ProviderActionBinding{action},
		},
		Execution: execution,
		LineageID: "lineage-search", Now: now,
	}
}
