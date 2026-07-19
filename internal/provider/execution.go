package provider

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	dependencycheck "github.com/OpenVulcan/vulcan-model-core/internal/dependency"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
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
)

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
	// LineageID identifies the Router-owned execution lineage for projection and reports.
	// LineageID 标识供投影和报告使用的 Router 所有执行谱系。
	LineageID string
	// Now fixes deterministic projection timestamps.
	// Now 固定确定性的投影时间戳。
	Now time.Time
	// Continuation supplies a target-bound provider response only after Router resolution.
	// Continuation 仅在 Router 解析后提供一个 Target 绑定的供应商响应。
	Continuation *ContinuationBinding
}

// ValidateForProfile verifies all invariant facts before a Profile or Driver can emit network traffic; supportedAuthTypes restricts the Driver's closed wire authentication capability when supplied.
// ValidateForProfile 在 Profile 或 Driver 发起网络流量前校验全部不变量事实；提供 supportedAuthTypes 时，它会限制 Driver 的封闭 wire 认证能力。
func (r ExecutionRequest) ValidateForProfile(profileID string, supportedAuthTypes ...providerconfig.AuthMethodType) (string, error) {
	if strings.TrimSpace(profileID) == "" {
		return "", fmt.Errorf("%w: protocol profile identifier is required", ErrExecutionBinding)
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
	// customFactory owns the sole protocol-whitelisted runtime path for persisted custom definitions.
	// customFactory 拥有已持久化自定义 Definition 唯一受协议白名单约束的运行时路径。
	customFactory CustomExecutionDriverFactory
}

// NewExecutionRegistry creates an empty provider-scoped execution registry.
// NewExecutionRegistry 创建一个空的供应商作用域执行注册表。
func NewExecutionRegistry() *ExecutionRegistry {
	return &ExecutionRegistry{drivers: make(map[string]ExecutionDriver)}
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
	identifiers := make(map[string]struct{}, len(r.drivers))
	for _, driver := range r.drivers {
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
