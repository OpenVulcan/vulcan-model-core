package provider

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	dependencycheck "github.com/OpenVulcan/vulcan-model-core/internal/dependency"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

var (
	// ErrExecutionDriverRequired reports an empty provider execution registration.
	// ErrExecutionDriverRequired 表示空的供应商执行 Driver 注册。
	ErrExecutionDriverRequired = errors.New("provider execution driver is required")
	// ErrExecutionDriverDuplicate reports duplicate ownership of one definition and protocol profile pair.
	// ErrExecutionDriverDuplicate 表示同一供应商定义和协议 Profile 对被重复拥有。
	ErrExecutionDriverDuplicate = errors.New("provider execution driver is already registered")
	// ErrExecutionDriverNotFound reports a target with no matching exact execution driver.
	// ErrExecutionDriverNotFound 表示 Target 没有匹配的精确执行 Driver。
	ErrExecutionDriverNotFound = errors.New("provider execution driver is not registered")
	// ErrCustomExecutionFactoryRequired reports a missing custom-provider execution factory registration.
	// ErrCustomExecutionFactoryRequired 表示缺少自定义供应商执行 Factory 注册。
	ErrCustomExecutionFactoryRequired = errors.New("custom provider execution driver factory is required")
	// ErrCustomExecutionFactoryDuplicate reports overlapping ownership of runtime custom-provider execution.
	// ErrCustomExecutionFactoryDuplicate 表示运行时自定义供应商执行归属发生重叠。
	ErrCustomExecutionFactoryDuplicate = errors.New("custom provider execution driver factory is already registered")
	// ErrExecutionBinding reports a definition, channel, target, or continuation mismatch.
	// ErrExecutionBinding 表示 Definition、Channel、Target 或 Continuation 不匹配。
	ErrExecutionBinding = errors.New("invalid provider execution binding")
	// ErrContinuationRejected reports explicit upstream rejection of the exact bound continuation handle.
	// ErrContinuationRejected 表示上游明确拒绝精确绑定的续接句柄。
	ErrContinuationRejected = errors.New("provider continuation rejected")
	// ErrActionExecutionDriverRequired reports an empty action execution registration.
	// ErrActionExecutionDriverRequired 表示空的动作执行 Driver 注册。
	ErrActionExecutionDriverRequired = errors.New("provider action execution driver is required")
	// ErrActionExecutionDriverDuplicate reports duplicate ownership of one definition and action binding pair.
	// ErrActionExecutionDriverDuplicate 表示同一供应商定义和动作绑定对被重复拥有。
	ErrActionExecutionDriverDuplicate = errors.New("provider action execution driver is already registered")
	// ErrTaskExecutionDriverRequired reports an empty asynchronous action driver registration.
	// ErrTaskExecutionDriverRequired 表示空的异步动作 Driver 注册。
	ErrTaskExecutionDriverRequired = errors.New("provider task execution driver is required")
	// ErrTaskExecutionDriverDuplicate reports duplicate asynchronous ownership of one definition and action.
	// ErrTaskExecutionDriverDuplicate 表示同一 Definition 与动作的异步所有权重复。
	ErrTaskExecutionDriverDuplicate = errors.New("provider task execution driver is already registered")
	// ErrExecutionEventSinkClosed reports an event emitted after the durable execution reached a terminal state.
	// ErrExecutionEventSinkClosed 表示持久执行进入终态后仍尝试发送事件。
	ErrExecutionEventSinkClosed = errors.New("provider execution event sink is closed")
	// ErrOutputBudgetExceeded reports a provider stream that crossed the caller's hard output byte ceiling.
	// ErrOutputBudgetExceeded 表示供应商流超过调用方的硬输出字节上限。
	ErrOutputBudgetExceeded = errors.New("provider output budget exceeded")
)

// ExecutionEventSink durably accepts validated provider semantic events while an upstream stream is still active.
// ExecutionEventSink 在上游流仍活跃时持久接收经过校验的供应商语义事件。
type ExecutionEventSink interface {
	// Emit validates and durably publishes one provider semantic event before returning to the upstream reader.
	// Emit 在返回上游读取器前校验并持久发布一个供应商语义事件。
	Emit(context.Context, vcp.Event) error
}

// ResourceProgress contains one provider-confirmed cumulative output byte observation.
// ResourceProgress 包含一个由供应商确认的累计输出字节观测。
type ResourceProgress struct {
	// OutputID is stable within the provider result and matches GeneratedResource.OutputID.
	// OutputID 在供应商结果内保持稳定，并与 GeneratedResource.OutputID 一致。
	OutputID string
	// Kind identifies the generated media family.
	// Kind 标识生成媒体类别。
	Kind vcp.MediaKind
	// MIMEType identifies the exact output encoding selected before streaming starts.
	// MIMEType 标识流式开始前选定的精确输出编码。
	MIMEType string
	// PartialBytes is the cumulative count of provider bytes received so far.
	// PartialBytes 是当前已接收供应商字节的累计数量。
	PartialBytes int64
}

// ExecutionResourceSink durably accepts real provider resource progress while an upstream stream is active.
// ExecutionResourceSink 在上游流活跃时持久接收真实供应商资源进度。
type ExecutionResourceSink interface {
	// EmitResourceProgress publishes one strictly increasing cumulative byte observation.
	// EmitResourceProgress 发布一个严格递增的累计字节观测。
	EmitResourceProgress(context.Context, ResourceProgress) error
}

// EmitExecutionEvents forwards one decoded event batch to the optional real-time sink in causal order.
// EmitExecutionEvents 按因果顺序将一批已解码事件转发到可选实时 Sink。
func EmitExecutionEvents(ctx context.Context, sink ExecutionEventSink, events []vcp.Event) error {
	if sink == nil {
		return nil
	}
	for _, event := range events {
		if errEmit := sink.Emit(ctx, event); errEmit != nil {
			return errEmit
		}
	}
	return nil
}

// ContinuationBinding contains a Router-resolved provider continuation that remains bound to one exact target scope.
// ContinuationBinding 包含 Router 解析的供应商续接状态，并始终绑定到一个精确 Target 作用域。
type ContinuationBinding struct {
	// ContinuationID is the Router-owned opaque continuation identifier requested by the caller.
	// ContinuationID 是调用方请求的 Router 所有不透明续接标识。
	ContinuationID string
	// ProviderDefinitionID fixes the originating provider integration.
	// ProviderDefinitionID 固定来源供应商集成。
	ProviderDefinitionID string
	// ProviderInstanceID fixes the originating provider instance.
	// ProviderInstanceID 固定来源供应商实例。
	ProviderInstanceID string
	// ChannelID fixes the originating provider channel.
	// ChannelID 固定来源供应商通道。
	ChannelID string
	// EndpointID fixes the originating provider endpoint selected by resolution.
	// EndpointID 固定解析阶段选定的来源供应商 Endpoint。
	EndpointID string
	// CredentialID fixes the originating provider credential selected by resolution.
	// CredentialID 固定解析阶段选定的来源供应商 Credential。
	CredentialID string
	// ProviderModelID fixes the originating logical provider model.
	// ProviderModelID 固定来源逻辑供应商模型。
	ProviderModelID string
	// UpstreamModelID fixes the exact wire model identifier that accepted the originating response.
	// UpstreamModelID 固定接受来源响应的精确 wire 模型标识。
	UpstreamModelID string
	// ExecutionProfileID fixes the originating protocol profile shape.
	// ExecutionProfileID 固定来源协议 Profile 形态。
	ExecutionProfileID string
	// UpstreamResponseID is the sealed provider response identifier sent only at the outbound wire boundary.
	// UpstreamResponseID 是仅在出站 wire 边界发送的密封供应商响应标识。
	UpstreamResponseID string
}

// Validate verifies that a continuation cannot cross provider, channel, model, or profile boundaries.
// Validate 校验续接状态不能跨越供应商、通道、模型或 Profile 边界。
func (c ContinuationBinding) Validate(target resolve.Target) error {
	if strings.TrimSpace(c.ContinuationID) == "" || strings.TrimSpace(c.UpstreamResponseID) == "" {
		return fmt.Errorf("%w: continuation identifier and upstream response identifier are required", ErrExecutionBinding)
	}
	if c.ProviderDefinitionID != target.ProviderDefinitionID || c.ProviderInstanceID != target.ProviderInstanceID || c.ChannelID != target.ChannelID || c.EndpointID != target.EndpointID || c.CredentialID != target.CredentialID || c.ProviderModelID != target.ProviderModelID || c.UpstreamModelID != target.UpstreamModelID || c.ExecutionProfileID != target.ExecutionProfileID {
		return fmt.Errorf("%w: continuation differs from immutable target", ErrExecutionBinding)
	}
	return nil
}

// ExecutionRequest joins canonical input, exact configuration snapshots, and optional resolved continuation state.
// ExecutionRequest 组合规范输入、精确配置快照与可选的已解析续接状态。
type ExecutionRequest struct {
	// Binding contains the immutable target and exact endpoint and credential snapshots.
	// Binding 包含不可变 Target 与精确 Endpoint、Credential 快照。
	Binding transport.Binding
	// Definition is the immutable provider definition that owns the selected channel.
	// Definition 是拥有选定 Channel 的不可变供应商 Definition。
	Definition providerconfig.ProviderDefinition
	// Request is the validated VCP request to project and execute.
	// Request 是待投影和执行的已校验 VCP 请求。
	Request vcp.VulcanRequest
	// Execution is the closed multi-operation VCP request used by action-bound drivers.
	// Execution 是动作绑定 Driver 使用的封闭多操作 VCP 请求。
	Execution *vcp.ExecutionRequest
	// MaterializedInputs contains the exact representations frozen by an accepted input plan.
	// MaterializedInputs 包含已接受输入方案冻结的精确表示。
	MaterializedInputs []resource.MaterializedInput
	// LineageID identifies the Router-owned execution lineage for projection and reports.
	// LineageID 标识供投影和报告使用的 Router 所有执行谱系。
	LineageID string
	// Now fixes deterministic projection timestamps.
	// Now 固定确定性的投影时间戳。
	Now time.Time
	// Continuation supplies a target-bound provider response only after Router resolution.
	// Continuation 仅在 Router 解析后提供一个 Target 绑定的供应商响应。
	Continuation *ContinuationBinding
	// PreparedWorkflow contains one Router-resolved provider handle only for an explicit multi-step operation.
	// PreparedWorkflow 仅为显式多步骤操作包含一个由 Router 解析的供应商句柄。
	PreparedWorkflow *PreparedWorkflowBinding
	// EventSink receives validated semantic events immediately for explicitly streaming requests.
	// EventSink 为显式流式请求立即接收经过校验的语义事件。
	EventSink ExecutionEventSink
	// ResourceSink receives native generated-resource byte progress for explicitly streaming requests.
	// ResourceSink 为显式流式请求接收原生生成资源字节进度。
	ResourceSink ExecutionResourceSink
}

// PreparedWorkflowBinding contains one private target-bound provider preparation handle.
// PreparedWorkflowBinding 包含一个私有且绑定 Target 的供应商准备句柄。
type PreparedWorkflowBinding struct {
	// PreparationID is the public Router-owned preparation identifier.
	// PreparationID 是公开的 Router 所有准备标识。
	PreparationID string
	// ProviderHandle is the protected provider value consumed on the wire.
	// ProviderHandle 是在 Wire 上消费的受保护供应商值。
	ProviderHandle string
	// ExpiresAt is the provider-confirmed handle expiry.
	// ExpiresAt 是供应商确认的句柄过期时间。
	ExpiresAt time.Time
}

// ValidateForProfile verifies all invariant facts before a Profile or Driver can emit network traffic; supportedAuthTypes restricts the Driver's closed wire authentication capability when supplied.
// ValidateForProfile 在 Profile 或 Driver 发起网络流量前校验全部不变量事实；提供 supportedAuthTypes 时，它会限制 Driver 的封闭 wire 认证能力。
func (r ExecutionRequest) ValidateForProfile(profileID string, supportedAuthTypes ...providerconfig.AuthMethodType) (string, error) {
	if strings.TrimSpace(profileID) == "" {
		return "", fmt.Errorf("%w: protocol profile identifier is required", ErrExecutionBinding)
	}
	if r.Execution != nil {
		return "", fmt.Errorf("%w: legacy profile execution cannot carry an action request", ErrExecutionBinding)
	}
	if errBinding := r.Binding.Validate(); errBinding != nil {
		return "", errBinding
	}
	if r.Definition.ID != r.Binding.Target.ProviderDefinitionID {
		return "", fmt.Errorf("%w: definition does not match target", ErrExecutionBinding)
	}
	if strings.TrimSpace(r.LineageID) == "" || r.Now.IsZero() {
		return "", fmt.Errorf("%w: lineage identifier and deterministic time are required", ErrExecutionBinding)
	}
	if errRequest := r.Request.Validate(); errRequest != nil {
		return "", errRequest
	}
	if requestedEffort := strings.TrimSpace(r.Request.ReasoningPolicy.Effort); requestedEffort != "" && len(r.Binding.Target.ModelCapabilities.ReasoningEfforts) > 0 && !containsString(r.Binding.Target.ModelCapabilities.ReasoningEfforts, requestedEffort) {
		return "", fmt.Errorf("%w: reasoning effort %q is not configured for the selected model offering", ErrExecutionBinding, requestedEffort)
	}
	if requestedSummary := r.Request.ReasoningPolicy.RequestedSummaryMode(); requestedSummary != "" && len(r.Binding.Target.ModelCapabilities.ReasoningSummaryModes) > 0 && !containsString(r.Binding.Target.ModelCapabilities.ReasoningSummaryModes, requestedSummary) {
		return "", fmt.Errorf("%w: reasoning summary mode %q is not configured for the selected model offering", ErrExecutionBinding, requestedSummary)
	}
	if r.Definition.ProtocolProfileID != profileID || !r.Definition.RuntimeReady {
		return "", fmt.Errorf("%w: provider protocol is not executable for %q", ErrExecutionBinding, profileID)
	}
	if !containsString(r.Definition.AuthMethodIDs, r.Binding.Credential.AuthMethodID) {
		return "", fmt.Errorf("%w: credential authentication method is not allowed by provider protocol", ErrExecutionBinding)
	}
	credentialAuthMethod, errAuthMethod := exactAuthMethod(r.Definition, r.Binding.Credential.AuthMethodID)
	if errAuthMethod != nil {
		return "", errAuthMethod
	}
	if len(supportedAuthTypes) > 0 && !containsAuthMethodType(supportedAuthTypes, credentialAuthMethod.Type) {
		return "", fmt.Errorf("%w: credential authentication type %q cannot be encoded by profile %q", ErrExecutionBinding, credentialAuthMethod.Type, profileID)
	}
	continuationID, continuationRequired, errContinuationID := requiredContinuationID(r.Request)
	if errContinuationID != nil {
		return "", errContinuationID
	}
	if r.Continuation != nil {
		if !continuationRequired || continuationID != r.Continuation.ContinuationID {
			return "", fmt.Errorf("%w: continuation does not match VCP request", ErrExecutionBinding)
		}
		if errContinuation := r.Continuation.Validate(r.Binding.Target); errContinuation != nil {
			return "", errContinuation
		}
	} else if continuationRequired {
		return "", fmt.Errorf("%w: Router-resolved continuation is required", ErrExecutionBinding)
	}
	return r.Definition.ProtocolProfileID, nil
}

// ValidateForAction verifies one exact definition-owned action before its Driver can emit network traffic.
// ValidateForAction 在动作 Driver 发起网络流量前校验一个精确的 Definition 所有动作。
func (r ExecutionRequest) ValidateForAction(actionBindingID string, supportedAuthTypes ...providerconfig.AuthMethodType) (providerconfig.ProviderActionBinding, error) {
	if strings.TrimSpace(actionBindingID) == "" {
		return providerconfig.ProviderActionBinding{}, fmt.Errorf("%w: action binding identifier is required", ErrExecutionBinding)
	}
	if errBinding := r.Binding.Validate(); errBinding != nil {
		return providerconfig.ProviderActionBinding{}, errBinding
	}
	if r.Definition.ID != r.Binding.Target.ProviderDefinitionID || !r.Definition.RuntimeReady {
		return providerconfig.ProviderActionBinding{}, fmt.Errorf("%w: definition does not match an executable target", ErrExecutionBinding)
	}
	if strings.TrimSpace(r.LineageID) == "" || r.Now.IsZero() {
		return providerconfig.ProviderActionBinding{}, fmt.Errorf("%w: lineage identifier and deterministic time are required", ErrExecutionBinding)
	}
	if r.Execution == nil {
		return providerconfig.ProviderActionBinding{}, fmt.Errorf("%w: action execution request is required", ErrExecutionBinding)
	}
	if r.Request.ProtocolVersion != "" {
		return providerconfig.ProviderActionBinding{}, fmt.Errorf("%w: action execution cannot carry a legacy request", ErrExecutionBinding)
	}
	if errExecution := r.Execution.Validate(); errExecution != nil {
		return providerconfig.ProviderActionBinding{}, errExecution
	}
	action, errAction := exactActionBinding(r.Definition, actionBindingID)
	if errAction != nil {
		return providerconfig.ProviderActionBinding{}, errAction
	}
	if action.ID != r.Binding.Target.ActionBindingID || action.Operation != r.Binding.Target.Operation || action.Operation != r.Execution.Operation {
		return providerconfig.ProviderActionBinding{}, fmt.Errorf("%w: action does not match immutable target and VCP operation", ErrExecutionBinding)
	}
	if !containsString(action.AuthMethodIDs, r.Binding.Credential.AuthMethodID) {
		return providerconfig.ProviderActionBinding{}, fmt.Errorf("%w: credential authentication method is not allowed by provider action", ErrExecutionBinding)
	}
	credentialAuthMethod, errAuthMethod := exactAuthMethod(r.Definition, r.Binding.Credential.AuthMethodID)
	if errAuthMethod != nil {
		return providerconfig.ProviderActionBinding{}, errAuthMethod
	}
	if len(supportedAuthTypes) > 0 && !containsAuthMethodType(supportedAuthTypes, credentialAuthMethod.Type) {
		return providerconfig.ProviderActionBinding{}, fmt.Errorf("%w: credential authentication type %q cannot be encoded by action %q", ErrExecutionBinding, credentialAuthMethod.Type, action.ID)
	}
	if errTarget := validateActionTarget(r.Binding.Target, r.Execution.Target); errTarget != nil {
		return providerconfig.ProviderActionBinding{}, errTarget
	}
	continuationID, continuationRequired, errContinuation := requiredActionContinuationID(*r.Execution)
	if errContinuation != nil {
		return providerconfig.ProviderActionBinding{}, errContinuation
	}
	if r.Continuation != nil {
		if !continuationRequired || continuationID != r.Continuation.ContinuationID {
			return providerconfig.ProviderActionBinding{}, fmt.Errorf("%w: continuation does not match VCP action request", ErrExecutionBinding)
		}
		if errValidate := r.Continuation.Validate(r.Binding.Target); errValidate != nil {
			return providerconfig.ProviderActionBinding{}, errValidate
		}
	} else if continuationRequired {
		return providerconfig.ProviderActionBinding{}, fmt.Errorf("%w: Router-resolved continuation is required", ErrExecutionBinding)
	}
	return action, nil
}

// exactActionBinding resolves one definition-owned action by immutable identifier.
// exactActionBinding 按不可变标识解析一个 Definition 所有的动作。
func exactActionBinding(definition providerconfig.ProviderDefinition, actionBindingID string) (providerconfig.ProviderActionBinding, error) {
	var resolved providerconfig.ProviderActionBinding
	found := false
	for _, action := range definition.ActionBindings {
		if action.ID != actionBindingID {
			continue
		}
		if found {
			return providerconfig.ProviderActionBinding{}, fmt.Errorf("%w: definition declares duplicate action binding %q", ErrExecutionBinding, actionBindingID)
		}
		if errValidate := action.Validate(); errValidate != nil {
			return providerconfig.ProviderActionBinding{}, fmt.Errorf("%w: provider action binding is invalid: %v", ErrExecutionBinding, errValidate)
		}
		resolved = action
		found = true
	}
	if !found {
		return providerconfig.ProviderActionBinding{}, fmt.Errorf("%w: action binding %q is not declared by definition", ErrExecutionBinding, actionBindingID)
	}
	return resolved, nil
}

// validateActionTarget verifies that the canonical selection names the exact resolved model or service subject.
// validateActionTarget 校验规范选择指向精确解析的模型或服务主体。
func validateActionTarget(target resolve.Target, selection vcp.TargetSelection) error {
	if target.SubjectKind == resolve.ExecutionSubjectModel {
		if selection.Model == nil || selection.Service != nil || selection.Model.ProviderInstanceID != target.ProviderInstanceID || selection.Model.ProviderModelID != target.ProviderModelID || selection.Model.ExecutionProfileID != target.ExecutionProfileID {
			return fmt.Errorf("%w: VCP model selection differs from immutable target", ErrExecutionBinding)
		}
		return nil
	}
	if target.SubjectKind == resolve.ExecutionSubjectService {
		if selection.Service == nil || selection.Model != nil || selection.Service.ProviderInstanceID != target.ProviderInstanceID || selection.Service.ProviderServiceID != target.ProviderServiceID || selection.Service.ServiceOfferingID != target.ServiceOfferingID || selection.Service.ExecutionProfileID != target.ExecutionProfileID {
			return fmt.Errorf("%w: VCP service selection differs from immutable target", ErrExecutionBinding)
		}
		return nil
	}
	return fmt.Errorf("%w: execution subject kind is invalid", ErrExecutionBinding)
}

// requiredActionContinuationID resolves the sole continuation used by a conversation action.
// requiredActionContinuationID 解析会话动作使用的唯一续接引用。
func requiredActionContinuationID(request vcp.ExecutionRequest) (string, bool, error) {
	if request.Operation != vcp.OperationConversationRespond || request.Payload.Conversation == nil {
		if request.Operation != vcp.OperationConversationRespond && request.Target.Model == nil && request.Target.Service != nil {
			return "", false, nil
		}
		return "", false, nil
	}
	conversation := request.Payload.Conversation
	reasoningID := conversation.ReasoningPolicy.ContinuationID
	compactionID := ""
	if conversation.RemoteCompaction != nil {
		compactionID = conversation.RemoteCompaction.PreviousResponseID
	}
	if reasoningID != "" && compactionID != "" && reasoningID != compactionID {
		return "", false, fmt.Errorf("%w: reasoning and remote compaction require different continuations", ErrExecutionBinding)
	}
	if reasoningID != "" {
		return reasoningID, true, nil
	}
	if compactionID != "" {
		return compactionID, true, nil
	}
	return "", false, nil
}

// exactAuthMethod resolves one definition-owned authentication method by immutable identifier.
// exactAuthMethod 按不可变标识解析一个 Definition 所有的认证方式。
func exactAuthMethod(definition providerconfig.ProviderDefinition, authMethodID string) (providerconfig.AuthMethodDefinition, error) {
	var resolved providerconfig.AuthMethodDefinition
	found := false
	for _, authMethod := range definition.AuthMethods {
		if authMethod.ID != authMethodID {
			continue
		}
		if found {
			return providerconfig.AuthMethodDefinition{}, fmt.Errorf("%w: definition declares duplicate authentication method %q", ErrExecutionBinding, authMethodID)
		}
		if errValidate := authMethod.Validate(); errValidate != nil {
			return providerconfig.AuthMethodDefinition{}, fmt.Errorf("%w: credential authentication method is invalid: %v", ErrExecutionBinding, errValidate)
		}
		resolved = authMethod
		found = true
	}
	if !found {
		return providerconfig.AuthMethodDefinition{}, fmt.Errorf("%w: credential authentication method %q is not declared by definition", ErrExecutionBinding, authMethodID)
	}
	return resolved, nil
}

// containsAuthMethodType reports whether one authentication type belongs to a Driver's closed wire capability set.
// containsAuthMethodType 报告一个认证类型是否属于某个 Driver 的封闭 wire 能力集合。
func containsAuthMethodType(authMethodTypes []providerconfig.AuthMethodType, target providerconfig.AuthMethodType) bool {
	for _, authMethodType := range authMethodTypes {
		if authMethodType == target {
			return true
		}
	}
	return false
}

// requiredContinuationID resolves the sole Router-owned continuation reference required by reasoning or remote compaction.
// requiredContinuationID 解析推理或远程压缩所需的唯一 Router 所有续接引用。
func requiredContinuationID(request vcp.VulcanRequest) (string, bool, error) {
	reasoningID := request.ReasoningPolicy.ContinuationID
	compactionID := ""
	if request.RemoteCompaction != nil {
		compactionID = request.RemoteCompaction.PreviousResponseID
	}
	if reasoningID != "" && compactionID != "" && reasoningID != compactionID {
		return "", false, fmt.Errorf("%w: reasoning and remote compaction require different continuations", ErrExecutionBinding)
	}
	if reasoningID != "" {
		return reasoningID, true, nil
	}
	if compactionID != "" {
		return compactionID, true, nil
	}
	return "", false, nil
}

// containsString reports whether a configured identifier is present without normalizing or guessing aliases.
// containsString 报告配置标识是否存在，且不规范化或猜测别名。
func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// ExecutionResult contains canonical output and optional state that a Router may persist as a new continuation.
// ExecutionResult 包含规范输出及 Router 可持久化为新续接状态的可选状态。
type ExecutionResult struct {
	// Response is the deterministic VCP reduction of returned events.
	// Response 是返回事件的确定性 VCP 归并结果。
	Response vcp.Response
	// Events contains the replayable VCP event sequence.
	// Events 包含可回放的 VCP 事件序列。
	Events []vcp.Event
	// Report contains only client-safe execution and conversion facts.
	// Report 仅包含客户端安全的执行与转换事实。
	Report vcp.ExecutionReport
	// UpstreamResponseID is a provider response identifier for Router-owned continuation persistence.
	// UpstreamResponseID 是供 Router 所有续接持久化使用的供应商响应标识。
	UpstreamResponseID string
	// ContinuationUpstreamResponseID is present only when this exact driver can consume the identifier on a later bound request.
	// ContinuationUpstreamResponseID 仅在此精确 Driver 可于后续绑定请求中消费该标识时存在。
	ContinuationUpstreamResponseID string
	// Embeddings contains ordered typed vector results for embedding actions.
	// Embeddings 包含 Embedding 动作的有序类型化向量结果。
	Embeddings []vcp.EmbeddingItem
	// Rerank contains ordered typed ranking results for rerank actions.
	// Rerank 包含重排动作的有序类型化排序结果。
	Rerank []vcp.RerankResult
	// Search contains one unified typed web-search result.
	// Search 包含一个统一类型化网页搜索结果。
	Search *vcp.WebSearchResponse
	// Transcript contains one complete typed non-realtime recognition result.
	// Transcript 包含一个完整的类型化非实时识别结果。
	Transcript *vcp.Transcript
	// MusicCoverPreparation contains one private provider handle and safe editable cover facts.
	// MusicCoverPreparation 包含一个私有供应商句柄及安全可编辑的翻唱事实。
	MusicCoverPreparation *MusicCoverPreparationResult
	// GeneratedResources contains private provider bytes or temporary URLs that the execution layer must import before publication.
	// GeneratedResources 包含执行层必须在公开前导入的私有供应商字节或临时 URL。
	GeneratedResources []GeneratedResource
}

// MusicCoverPreparationResult contains provider-private state and typed safe preprocessing output.
// MusicCoverPreparationResult 包含供应商私有状态及类型化安全预处理输出。
type MusicCoverPreparationResult struct {
	// ProviderHandle is the upstream cover feature identifier and must never enter public JSON.
	// ProviderHandle 是上游翻唱特征标识且绝不能进入公开 JSON。
	ProviderHandle string
	// FormattedLyrics contains editable provider-extracted lyrics.
	// FormattedLyrics 包含可编辑的供应商提取歌词。
	FormattedLyrics string
	// Structure contains parsed provider-confirmed song sections.
	// Structure 包含已解析且由供应商确认的歌曲段落。
	Structure []vcp.MusicStructureSegment
	// AudioDurationSeconds is the provider-confirmed source duration.
	// AudioDurationSeconds 是供应商确认的来源时长。
	AudioDurationSeconds float64
	// ExpiresAt is the provider-confirmed handle expiry.
	// ExpiresAt 是供应商确认的句柄过期时间。
	ExpiresAt time.Time
}

// GeneratedResource contains one exact provider output acquisition source.
// GeneratedResource 包含一个精确的供应商输出获取来源。
type GeneratedResource struct {
	// OutputID is stable within the provider result and never reused for another output.
	// OutputID 在供应商结果内保持稳定且不会被其他输出复用。
	OutputID string
	// Kind identifies the generated media family.
	// Kind 标识生成媒体类别。
	Kind vcp.MediaKind
	// MIMEType is the provider-declared media type verified by Router content probing.
	// MIMEType 是由 Router 内容探测校验的供应商声明媒体类型。
	MIMEType string
	// Data contains complete generated bytes when the provider returned inline or authenticated content.
	// Data 在供应商返回内联或需认证内容时包含完整生成字节。
	Data []byte
	// DownloadURL contains one temporary public provider URL when no authenticated fetch is required.
	// DownloadURL 在无需认证获取时包含一个临时公网供应商 URL。
	DownloadURL string
}

// ExecutionDriver executes one protocol profile for exactly one provider definition.
// ExecutionDriver 为一个精确供应商 Definition 执行一种协议 Profile。
type ExecutionDriver interface {
	// ProviderDefinitionID returns the sole provider definition owned by this Driver.
	// ProviderDefinitionID 返回该 Driver 唯一拥有的供应商 Definition。
	ProviderDefinitionID() string
	// ProtocolProfileID returns the sole upstream protocol profile implemented by this Driver.
	// ProtocolProfileID 返回该 Driver 实现的唯一上游协议 Profile。
	ProtocolProfileID() string
	// Execute projects and sends one request without changing its target scope.
	// Execute 在不改变 Target 作用域的前提下投影并发送一条请求。
	Execute(context.Context, ExecutionRequest) (ExecutionResult, error)
}

// UsagePreflightResult contains provider-owned side-effect-free input accounting.
// UsagePreflightResult 包含供应商拥有的无副作用输入计量。
type UsagePreflightResult struct {
	// Usage contains only values returned by the provider counting endpoint.
	// Usage 仅包含供应商计量接口返回的数值。
	Usage vcp.UsageObservation
	// Accuracy states whether the provider reported an exact value.
	// Accuracy 声明供应商是否报告了精确值。
	Accuracy vcp.PreflightAccuracy
}

// UsagePreflightDriver counts one request without creating model output or changing target scope.
// UsagePreflightDriver 在不创建模型输出或改变 Target 作用域的情况下计量请求。
type UsagePreflightDriver interface {
	// PreflightUsage returns provider-native input accounting for the exact immutable target.
	// PreflightUsage 返回精确不可变 Target 的供应商原生输入计量。
	PreflightUsage(context.Context, ExecutionRequest) (UsagePreflightResult, error)
}

// ActionExecutionDriver executes one exact definition-owned action binding.
// ActionExecutionDriver 执行一个精确的 Definition 所有动作绑定。
type ActionExecutionDriver interface {
	// ProviderDefinitionID returns the sole provider definition owned by this Driver.
	// ProviderDefinitionID 返回该 Driver 唯一拥有的供应商 Definition。
	ProviderDefinitionID() string
	// ActionBindingID returns the sole provider action binding owned by this Driver.
	// ActionBindingID 返回该 Driver 唯一拥有的供应商动作绑定。
	ActionBindingID() string
	// Execute projects and sends one action without changing its target scope.
	// Execute 在不改变 Target 作用域的前提下投影并发送一个动作。
	Execute(context.Context, ExecutionRequest) (ExecutionResult, error)
}

// TaskState identifies one provider-confirmed asynchronous task state.
// TaskState 标识一种供应商确认的异步任务状态。
type TaskState string

const (
	// TaskQueued is accepted by the provider but not running.
	// TaskQueued 已由供应商接收但尚未运行。
	TaskQueued TaskState = "queued"
	// TaskRunning is actively executing.
	// TaskRunning 正在执行。
	TaskRunning TaskState = "running"
	// TaskSucceeded completed successfully.
	// TaskSucceeded 已成功完成。
	TaskSucceeded TaskState = "succeeded"
	// TaskPartiallySucceeded completed with provider-confirmed partial output.
	// TaskPartiallySucceeded 已完成且具有供应商确认的部分输出。
	TaskPartiallySucceeded TaskState = "partially_succeeded"
	// TaskFailed terminated with a safe provider error code.
	// TaskFailed 已因安全供应商错误码终止。
	TaskFailed TaskState = "failed"
	// TaskCancelled is confirmed cancelled by the provider.
	// TaskCancelled 已由供应商确认取消。
	TaskCancelled TaskState = "cancelled"
)

// TaskResult contains one provider-confirmed asynchronous task observation.
// TaskResult 包含一个供应商确认的异步任务观测。
type TaskResult struct {
	// ProviderTaskID is the exact upstream identifier and must never enter public JSON or logs.
	// ProviderTaskID 是精确上游标识且绝不能进入公开 JSON 或日志。
	ProviderTaskID string
	// State is the provider-confirmed lifecycle state.
	// State 是供应商确认的生命周期状态。
	State TaskState
	// PollAfter is the earliest safe next polling time for non-terminal states.
	// PollAfter 是非终态最早安全下次轮询时间。
	PollAfter time.Time
	// Result contains typed output only for success states.
	// Result 仅在成功状态包含类型化输出。
	Result *ExecutionResult
	// ErrorCode is a client-safe provider classification only for failure.
	// ErrorCode 仅在失败时包含客户端安全供应商分类。
	ErrorCode string
	// Retryable reports a provider-evidenced retry classification.
	// Retryable 表示供应商有证据支持的重试分类。
	Retryable bool
}

// TaskExecutionDriver owns asynchronous start, poll, and cancel for one exact action binding.
// TaskExecutionDriver 为一个精确动作绑定拥有异步创建、轮询与取消。
type TaskExecutionDriver interface {
	// ProviderDefinitionID returns the sole owning provider definition.
	// ProviderDefinitionID 返回唯一拥有供应商 Definition。
	ProviderDefinitionID() string
	// ActionBindingID returns the sole owning action binding.
	// ActionBindingID 返回唯一拥有动作绑定。
	ActionBindingID() string
	// Start creates at most one provider task for one exact idempotently admitted execution.
	// Start 为一个精确幂等接收执行最多创建一个供应商任务。
	Start(context.Context, ExecutionRequest) (TaskResult, error)
	// Poll observes the same provider task without changing target affinity.
	// Poll 在不改变 Target 亲和性的情况下观察同一供应商任务。
	Poll(context.Context, ExecutionRequest, string) (TaskResult, error)
	// Cancel requests cancellation of the same provider task and returns its confirmed state.
	// Cancel 请求取消同一供应商任务并返回其确认状态。
	Cancel(context.Context, ExecutionRequest, string) (TaskResult, error)
}

// CustomExecutionDriverFactory creates one request-scoped Driver from an immutable persisted custom definition snapshot.
// CustomExecutionDriverFactory 根据不可变的已持久化自定义 Definition 快照创建一个请求作用域 Driver。
type CustomExecutionDriverFactory interface {
	// BuildCustomDriver validates the closed custom shape and returns a Driver bound to that exact definition revision.
	// BuildCustomDriver 校验封闭的自定义形态，并返回绑定到该精确 Definition 修订的 Driver。
	BuildCustomDriver(providerconfig.ProviderDefinition) (ExecutionDriver, error)
}

// ExecutionRegistry dispatches to a Driver selected only by target definition and definition-owned channel profile.
// ExecutionRegistry 仅按 Target Definition 和 Definition 拥有的 Channel Profile 分派 Driver。
type ExecutionRegistry struct {
	// mu protects immutable driver registrations and lookups.
	// mu 保护不可变 Driver 注册和查询。
	mu sync.RWMutex
	// drivers maps one exact definition/profile pair to one Driver.
	// drivers 将一个精确 Definition/Profile 对映射到一个 Driver。
	drivers map[string]ExecutionDriver
	// actionDrivers maps one exact definition/action pair to one Driver.
	// actionDrivers 将一个精确 Definition/Action 对映射到一个 Driver。
	actionDrivers map[string]ActionExecutionDriver
	// taskDrivers maps one exact definition/action pair to one asynchronous Driver.
	// taskDrivers 将一个精确 Definition/动作对映射到一个异步 Driver。
	taskDrivers map[string]TaskExecutionDriver
	// customFactory owns the sole protocol-whitelisted runtime path for persisted custom definitions.
	// customFactory 拥有已持久化自定义 Definition 唯一受协议白名单约束的运行时路径。
	customFactory CustomExecutionDriverFactory
}

// NewExecutionRegistry creates an empty provider-scoped execution registry.
// NewExecutionRegistry 创建一个空的供应商作用域执行注册表。
func NewExecutionRegistry() *ExecutionRegistry {
	return &ExecutionRegistry{drivers: make(map[string]ExecutionDriver), actionDrivers: make(map[string]ActionExecutionDriver), taskDrivers: make(map[string]TaskExecutionDriver)}
}

// RegisterTaskAction adds one asynchronous Driver and rejects overlapping ownership.
// RegisterTaskAction 添加一个异步 Driver 并拒绝重叠所有权。
func (r *ExecutionRegistry) RegisterTaskAction(driver TaskExecutionDriver) error {
	if r == nil || isNilExecutionDependency(driver) {
		return ErrTaskExecutionDriverRequired
	}
	definitionID := strings.TrimSpace(driver.ProviderDefinitionID())
	actionBindingID := strings.TrimSpace(driver.ActionBindingID())
	if definitionID == "" || actionBindingID == "" {
		return fmt.Errorf("%w: definition and action binding identifiers are required", ErrExecutionBinding)
	}
	key := executionDriverKey(definitionID, actionBindingID)
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.taskDrivers[key]; exists {
		return fmt.Errorf("%w: %s / %s", ErrTaskExecutionDriverDuplicate, definitionID, actionBindingID)
	}
	r.taskDrivers[key] = driver
	return nil
}

// RegisterAction adds one Driver and rejects overlapping ownership of a definition/action pair.
// RegisterAction 添加一个 Driver 并拒绝重叠拥有同一 Definition/Action 对。
func (r *ExecutionRegistry) RegisterAction(driver ActionExecutionDriver) error {
	if r == nil || isNilExecutionDependency(driver) {
		return ErrActionExecutionDriverRequired
	}
	definitionID := strings.TrimSpace(driver.ProviderDefinitionID())
	actionBindingID := strings.TrimSpace(driver.ActionBindingID())
	if definitionID == "" || actionBindingID == "" {
		return fmt.Errorf("%w: definition and action binding identifiers are required", ErrExecutionBinding)
	}
	key := executionDriverKey(definitionID, actionBindingID)
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.actionDrivers[key]; exists {
		return fmt.Errorf("%w: %s / %s", ErrActionExecutionDriverDuplicate, definitionID, actionBindingID)
	}
	r.actionDrivers[key] = driver
	return nil
}

// Register adds one Driver and rejects overlapping ownership of a definition/profile pair.
// Register 添加一个 Driver 并拒绝重叠拥有同一 Definition/Profile 对。
func (r *ExecutionRegistry) Register(driver ExecutionDriver) error {
	if r == nil || isNilExecutionDependency(driver) {
		return ErrExecutionDriverRequired
	}
	definitionID := strings.TrimSpace(driver.ProviderDefinitionID())
	profileID := strings.TrimSpace(driver.ProtocolProfileID())
	if definitionID == "" || profileID == "" {
		return fmt.Errorf("%w: definition and protocol profile identifiers are required", ErrExecutionBinding)
	}
	key := executionDriverKey(definitionID, profileID)
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.drivers[key]; exists {
		return fmt.Errorf("%w: %s / %s", ErrExecutionDriverDuplicate, definitionID, profileID)
	}
	r.drivers[key] = driver
	return nil
}

// RegisterCustomFactory installs the sole runtime factory for persisted custom definitions.
// RegisterCustomFactory 安装已持久化自定义 Definition 的唯一运行时 Factory。
func (r *ExecutionRegistry) RegisterCustomFactory(factory CustomExecutionDriverFactory) error {
	if r == nil || isNilExecutionDependency(factory) {
		return ErrCustomExecutionFactoryRequired
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.customFactory != nil {
		return ErrCustomExecutionFactoryDuplicate
	}
	r.customFactory = factory
	return nil
}

// ProviderIDs returns stable unique definition identifiers that own at least one registered execution driver.
// ProviderIDs 返回至少拥有一个已注册执行 Driver 的稳定唯一 Definition 标识。
func (r *ExecutionRegistry) ProviderIDs() []string {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	identifiers := make(map[string]struct{}, len(r.drivers)+len(r.actionDrivers)+len(r.taskDrivers))
	for _, driver := range r.drivers {
		identifiers[driver.ProviderDefinitionID()] = struct{}{}
	}
	for _, driver := range r.actionDrivers {
		identifiers[driver.ProviderDefinitionID()] = struct{}{}
	}
	for _, driver := range r.taskDrivers {
		identifiers[driver.ProviderDefinitionID()] = struct{}{}
	}
	r.mu.RUnlock()
	providerIDs := make([]string, 0, len(identifiers))
	for identifier := range identifiers {
		providerIDs = append(providerIDs, identifier)
	}
	sort.Strings(providerIDs)
	return providerIDs
}

// Execute validates the exact binding and dispatches without candidate lists or cross-provider fallback.
// Execute 校验精确绑定并进行分派，不使用候选列表或跨供应商回退。
func (r *ExecutionRegistry) Execute(ctx context.Context, request ExecutionRequest) (ExecutionResult, error) {
	if r == nil {
		return ExecutionResult{}, ErrExecutionDriverNotFound
	}
	if request.Binding.Target.ActionBindingID != "" {
		action, errValidate := request.ValidateForAction(request.Binding.Target.ActionBindingID)
		if errValidate != nil {
			return ExecutionResult{}, errValidate
		}
		key := executionDriverKey(request.Binding.Target.ProviderDefinitionID, action.ID)
		r.mu.RLock()
		driver, exists := r.actionDrivers[key]
		r.mu.RUnlock()
		if !exists {
			return ExecutionResult{}, fmt.Errorf("%w: %s / %s", ErrExecutionDriverNotFound, request.Binding.Target.ProviderDefinitionID, action.ID)
		}
		return driver.Execute(ctx, request)
	}
	if _, errValidate := request.ValidateForProfile(request.Definition.ProtocolProfileID); errValidate != nil {
		return ExecutionResult{}, errValidate
	}
	key := executionDriverKey(request.Binding.Target.ProviderDefinitionID, request.Definition.ProtocolProfileID)
	r.mu.RLock()
	driver, exists := r.drivers[key]
	customFactory := r.customFactory
	r.mu.RUnlock()
	if !exists && request.Definition.Kind == providerconfig.DefinitionKindCustom {
		if customFactory == nil {
			return ExecutionResult{}, fmt.Errorf("%w: %s / %s", ErrCustomExecutionFactoryRequired, request.Binding.Target.ProviderDefinitionID, request.Definition.ProtocolProfileID)
		}
		var errFactory error
		driver, errFactory = customFactory.BuildCustomDriver(request.Definition)
		if errFactory != nil {
			return ExecutionResult{}, errFactory
		}
		if isNilExecutionDependency(driver) || driver.ProviderDefinitionID() != request.Definition.ID || driver.ProtocolProfileID() != request.Definition.ProtocolProfileID {
			return ExecutionResult{}, fmt.Errorf("%w: custom driver ownership differs from immutable definition", ErrExecutionBinding)
		}
		exists = true
	}
	if !exists {
		return ExecutionResult{}, fmt.Errorf("%w: %s / %s", ErrExecutionDriverNotFound, request.Binding.Target.ProviderDefinitionID, request.Definition.ProtocolProfileID)
	}
	return driver.Execute(ctx, request)
}

// PreflightUsage dispatches only to an explicitly registered provider-native counter.
// PreflightUsage 仅分派到显式注册的供应商原生计量器。
func (r *ExecutionRegistry) PreflightUsage(ctx context.Context, request ExecutionRequest) (UsagePreflightResult, error) {
	if r == nil {
		return UsagePreflightResult{}, ErrExecutionDriverNotFound
	}
	if request.Binding.Target.ActionBindingID == "" {
		return UsagePreflightResult{}, fmt.Errorf("%w: usage preflight requires an action-bound target", ErrExecutionBinding)
	}
	action, errValidate := request.ValidateForAction(request.Binding.Target.ActionBindingID)
	if errValidate != nil {
		return UsagePreflightResult{}, errValidate
	}
	key := executionDriverKey(request.Binding.Target.ProviderDefinitionID, action.ID)
	r.mu.RLock()
	driver, exists := r.actionDrivers[key]
	r.mu.RUnlock()
	if !exists {
		return UsagePreflightResult{}, fmt.Errorf("%w: %s / %s", ErrExecutionDriverNotFound, request.Binding.Target.ProviderDefinitionID, action.ID)
	}
	counter, supported := driver.(UsagePreflightDriver)
	if !supported {
		return UsagePreflightResult{}, fmt.Errorf("%w: provider action has no native usage preflight", ErrExecutionDriverNotFound)
	}
	return counter.PreflightUsage(ctx, request)
}

// ClassifyExecutionError converts safe transport failures into closed same-provider retry semantics.
// ClassifyExecutionError 将安全传输失败转换为封闭的同供应商重试语义。
func (r *ExecutionRegistry) ClassifyExecutionError(request ExecutionRequest, executionError error) (ClassifiedError, bool) {
	if executionError == nil || errors.Is(executionError, context.Canceled) || errors.Is(executionError, context.DeadlineExceeded) {
		return ClassifiedError{}, false
	}
	now := request.Now
	if now.IsZero() {
		return ClassifiedError{}, false
	}
	var statusError transport.StatusError
	if errors.As(executionError, &statusError) {
		return classifyHTTPStatus(request.Binding.Target, statusError, now)
	}
	var networkError net.Error
	if errors.As(executionError, &networkError) {
		retryAt := now.Add(time.Minute)
		return ClassifiedError{Category: "network_unavailable", Scope: ErrorScopeEndpoint, Action: RetryOtherEndpoint, RetryAt: &retryAt, RuleID: "transport_network_error"}, true
	}
	return ClassifiedError{}, false
}

// classifyHTTPStatus maps only body-free status evidence and avoids guessing provider message fields.
// classifyHTTPStatus 仅映射不含正文的状态证据并避免猜测供应商消息字段。
func classifyHTTPStatus(target resolve.Target, statusError transport.StatusError, now time.Time) (ClassifiedError, bool) {
	classified := ClassifiedError{}
	switch statusError.StatusCode {
	case 401:
		classified = ClassifiedError{Category: "authentication_rejected", Scope: ErrorScopeCredential, Action: RetryOtherCredential, RuleID: "http_401"}
	case 402, 403:
		classified = ClassifiedError{Category: "payment_required", Scope: ErrorScopeCredential, Action: RetryOtherCredential, RuleID: fmt.Sprintf("http_%d", statusError.StatusCode)}
	case 429:
		scope := ErrorScopeCredential
		if target.ProviderModelID != "" {
			scope = ErrorScopeModel
		}
		classified = ClassifiedError{Category: "quota_exhausted", Scope: scope, Action: RetryOtherCredential, RuleID: "http_429"}
	case 408, 500, 502, 503, 504:
		classified = ClassifiedError{Category: "transient_upstream", Scope: ErrorScopeEndpoint, Action: RetryOtherEndpoint, RuleID: fmt.Sprintf("http_%d", statusError.StatusCode)}
	default:
		return ClassifiedError{}, false
	}
	if statusError.RetryAfter != nil {
		retryAt := now.Add(*statusError.RetryAfter)
		classified.RetryAt = &retryAt
	} else {
		switch classified.Category {
		case "authentication_rejected", "payment_required":
			retryAt := now.Add(30 * time.Minute)
			classified.RetryAt = &retryAt
		case "transient_upstream":
			retryAt := now.Add(time.Minute)
			classified.RetryAt = &retryAt
		}
	}
	return classified, true
}

// StartTask validates exact ownership and starts one asynchronous provider task.
// StartTask 校验精确所有权并创建一个异步供应商任务。
func (r *ExecutionRegistry) StartTask(ctx context.Context, request ExecutionRequest) (TaskResult, error) {
	driver, errDriver := r.taskDriver(request)
	if errDriver != nil {
		return TaskResult{}, errDriver
	}
	result, errStart := driver.Start(ctx, request)
	if errStart != nil {
		return TaskResult{}, errStart
	}
	if errResult := result.Validate(); errResult != nil {
		return TaskResult{}, errResult
	}
	return result, nil
}

// PollTask observes one exact asynchronous provider task without changing affinity.
// PollTask 在不改变亲和性的情况下观察一个精确异步供应商任务。
func (r *ExecutionRegistry) PollTask(ctx context.Context, request ExecutionRequest, providerTaskID string) (TaskResult, error) {
	driver, errDriver := r.taskDriver(request)
	if errDriver != nil {
		return TaskResult{}, errDriver
	}
	if strings.TrimSpace(providerTaskID) == "" {
		return TaskResult{}, fmt.Errorf("%w: provider task identifier is required", ErrExecutionBinding)
	}
	result, errPoll := driver.Poll(ctx, request, providerTaskID)
	if errPoll != nil {
		return TaskResult{}, errPoll
	}
	if errResult := result.Validate(); errResult != nil || result.ProviderTaskID != providerTaskID {
		return TaskResult{}, fmt.Errorf("%w: polled task identity or state is invalid", ErrExecutionBinding)
	}
	return result, nil
}

// CancelTask requests cancellation of one exact asynchronous provider task.
// CancelTask 请求取消一个精确异步供应商任务。
func (r *ExecutionRegistry) CancelTask(ctx context.Context, request ExecutionRequest, providerTaskID string) (TaskResult, error) {
	driver, errDriver := r.taskDriver(request)
	if errDriver != nil {
		return TaskResult{}, errDriver
	}
	if strings.TrimSpace(providerTaskID) == "" {
		return TaskResult{}, fmt.Errorf("%w: provider task identifier is required", ErrExecutionBinding)
	}
	result, errCancel := driver.Cancel(ctx, request, providerTaskID)
	if errCancel != nil {
		return TaskResult{}, errCancel
	}
	if errResult := result.Validate(); errResult != nil || result.ProviderTaskID != providerTaskID {
		return TaskResult{}, fmt.Errorf("%w: cancelled task identity or state is invalid", ErrExecutionBinding)
	}
	return result, nil
}

// taskDriver resolves one exact registered asynchronous action driver.
// taskDriver 解析一个精确注册异步动作 Driver。
func (r *ExecutionRegistry) taskDriver(request ExecutionRequest) (TaskExecutionDriver, error) {
	if r == nil {
		return nil, ErrExecutionDriverNotFound
	}
	action, errValidate := request.ValidateForAction(request.Binding.Target.ActionBindingID)
	if errValidate != nil {
		return nil, errValidate
	}
	if !action.Delivery.Asynchronous {
		return nil, fmt.Errorf("%w: action does not declare asynchronous delivery", ErrExecutionBinding)
	}
	key := executionDriverKey(request.Binding.Target.ProviderDefinitionID, action.ID)
	r.mu.RLock()
	driver, exists := r.taskDrivers[key]
	r.mu.RUnlock()
	if !exists {
		return nil, fmt.Errorf("%w: %s / %s", ErrExecutionDriverNotFound, request.Binding.Target.ProviderDefinitionID, action.ID)
	}
	return driver, nil
}

// Validate verifies one closed provider task observation without accepting invented progress.
// Validate 校验一个封闭供应商任务观测且不接受虚构进度。
func (r TaskResult) Validate() error {
	if strings.TrimSpace(r.ProviderTaskID) == "" {
		return fmt.Errorf("%w: provider task identifier is required", ErrExecutionBinding)
	}
	switch r.State {
	case TaskQueued, TaskRunning:
		if r.PollAfter.IsZero() || r.Result != nil || r.ErrorCode != "" || r.Retryable {
			return fmt.Errorf("%w: non-terminal task requires poll time only", ErrExecutionBinding)
		}
	case TaskSucceeded, TaskPartiallySucceeded:
		if r.Result == nil || r.ErrorCode != "" || !r.PollAfter.IsZero() || r.Retryable {
			return fmt.Errorf("%w: successful task requires typed result", ErrExecutionBinding)
		}
	case TaskFailed:
		if !safeTaskFailureCode(r.ErrorCode) || r.Result != nil || !r.PollAfter.IsZero() {
			return fmt.Errorf("%w: failed task requires a safe error code", ErrExecutionBinding)
		}
	case TaskCancelled:
		if r.Result != nil || r.ErrorCode != "" || !r.PollAfter.IsZero() || r.Retryable {
			return fmt.Errorf("%w: cancelled task cannot carry result or failure", ErrExecutionBinding)
		}
	default:
		return fmt.Errorf("%w: unknown provider task state %q", ErrExecutionBinding, r.State)
	}
	return nil
}

// safeTaskFailureCode reports whether a failure belongs to the closed client-safe task taxonomy.
// safeTaskFailureCode 报告失败是否属于封闭的客户端安全任务分类。
func safeTaskFailureCode(code string) bool {
	switch code {
	case "alibaba_transcription_failed",
		"alibaba_video_generation_failed",
		"google_video_generation_failed",
		"minimax_speech_generation_expired",
		"minimax_speech_generation_failed",
		"minimax_video_generation_failed",
		"openrouter_video_failed",
		"provider_task_expired",
		"xai_video_generation_failed":
		return true
	default:
		return false
	}
}

// isNilExecutionDependency recognizes typed nil implementations before invoking extension-owned interface methods.
// isNilExecutionDependency 在调用扩展所有的接口方法前识别带类型的 nil 实现。
func isNilExecutionDependency(dependency any) bool {
	return dependencycheck.IsNil(dependency)
}

// executionDriverKey creates a collision-free internal key from exact owned identifiers.
// executionDriverKey 根据精确拥有标识创建无冲突的内部键。
func executionDriverKey(definitionID string, profileID string) string {
	return definitionID + "\x00" + profileID
}
