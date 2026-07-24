package execution

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/inputplan"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/routertool"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

const (
	// maxSameProviderExecutionAttempts bounds credential and endpoint failover for one logical execution.
	// maxSameProviderExecutionAttempts 限制一次逻辑执行中的凭据与入口故障切换次数。
	maxSameProviderExecutionAttempts = 8
	// maximumRouterParentExecutionDuration is the non-overridable wall-clock ceiling for one Router tool parent.
	// maximumRouterParentExecutionDuration 是一次 Router 工具父执行不可覆盖的墙钟上限。
	maximumRouterParentExecutionDuration = 15 * time.Minute
)

// TargetResolver resolves one exact provider-scoped destination.
// TargetResolver 解析一个精确供应商作用域目的地。
type TargetResolver interface {
	// Resolve returns one immutable target or an explicit eligibility error.
	// Resolve 返回一个不可变 Target 或明确资格错误。
	Resolve(context.Context, resolve.Request) (resolve.Target, resolve.Diagnostics, error)
}

// ModelToolResolver resolves one explicit Router standard-tool backend for a parent model.
// ModelToolResolver 为父模型解析一个显式 Router 标准工具后端。
type ModelToolResolver interface {
	// Resolve returns one immutable binding and independently resolved child target.
	// Resolve 返回一个不可变绑定及独立解析的子 Target。
	Resolve(context.Context, resolve.Target, vcp.StandardModelToolKind, time.Time) (routertool.ResolvedBinding, error)
	// ResolveExtension returns one immutable binding for a closed operation-backed Router enhancement.
	// ResolveExtension 为封闭且由操作支持的 Router 增强能力返回一个不可变绑定。
	ResolveExtension(context.Context, resolve.Target, vcp.RouterExtensionKind, time.Time) (routertool.ResolvedBinding, error)
}

// ConfigurationReader loads exact immutable provider snapshots selected by a target.
// ConfigurationReader 加载 Target 选中的精确不可变供应商快照。
type ConfigurationReader interface {
	// GetDefinition returns one system or custom provider definition.
	// GetDefinition 返回一个系统或自定义供应商 Definition。
	GetDefinition(context.Context, string) (providerconfig.ProviderDefinition, error)
	// ListEndpoints returns endpoint snapshots owned by one provider instance.
	// ListEndpoints 返回一个供应商实例拥有的 Endpoint 快照。
	ListEndpoints(context.Context, string) ([]providerconfig.Endpoint, error)
	// ListCredentials returns credential snapshots owned by one provider instance.
	// ListCredentials 返回一个供应商实例拥有的 Credential 快照。
	ListCredentials(context.Context, string) ([]providerconfig.Credential, error)
}

// InputPlanReader revalidates one owner-scoped conditional media plan at execution time.
// InputPlanReader 在执行时重新校验一个所有者作用域条件媒体方案。
type InputPlanReader interface {
	// Revalidate returns the unchanged live plan or capability_changed.
	// Revalidate 返回未变化有效方案或 capability_changed。
	Revalidate(context.Context, string, string) (inputplan.Plan, error)
}

// InputPlanCreator creates one immutable conditional-media plan for a Router child execution.
// InputPlanCreator 为 Router 子执行创建一个不可变条件媒体方案。
type InputPlanCreator interface {
	// CreateInputPlan validates and persists one exact model-scoped media decision.
	// CreateInputPlan 校验并持久化一个精确的模型作用域媒体决策。
	CreateInputPlan(context.Context, inputplan.Request) (inputplan.Plan, error)
}

// InputMaterializer realizes only the representations frozen by an accepted input plan.
// InputMaterializer 仅实现已接受输入方案冻结的表示。
type InputMaterializer interface {
	// Materialize returns ordered exact-one provider representations.
	// Materialize 返回有序且唯一的供应商表示。
	Materialize(context.Context, string, resource.FrozenMaterializationPlan, []resource.ResourceAssignment) ([]resource.MaterializedInput, error)
}

// ProviderExecutor dispatches only to the exact registered definition and action/profile driver.
// ProviderExecutor 仅分派到精确注册的 Definition 与动作/Profile Driver。
type ProviderExecutor interface {
	// Execute performs one provider-bound request without cross-target fallback.
	// Execute 执行一个供应商绑定请求且不进行跨 Target 降级。
	Execute(context.Context, provider.ExecutionRequest) (provider.ExecutionResult, error)
}

// ProviderErrorClassifier exposes trusted body-free same-provider retry semantics.
// ProviderErrorClassifier 暴露可信且不含正文的同供应商重试语义。
type ProviderErrorClassifier interface {
	// ClassifyExecutionError classifies one exact failed provider attempt.
	// ClassifyExecutionError 对一次精确失败的供应商尝试进行分类。
	ClassifyExecutionError(provider.ExecutionRequest, error) (provider.ClassifiedError, bool)
}

// RuntimeFeedback persists classified model state without exposing it to callers.
// RuntimeFeedback 持久化分类后的模型状态且不向调用方暴露。
type RuntimeFeedback interface {
	// RecordFailure applies one classified failure to its exact target scope.
	// RecordFailure 将一个分类失败应用到其精确 Target 作用域。
	RecordFailure(context.Context, provider.ExecutionRequest, provider.ClassifiedError, time.Time) error
	// RecordSuccess clears temporary state for the exact successful target.
	// RecordSuccess 清除精确成功 Target 的临时状态。
	RecordSuccess(context.Context, provider.ExecutionRequest, time.Time) error
}

// ProviderTaskExecutor dispatches exact asynchronous start, poll, and cancel operations.
// ProviderTaskExecutor 分派精确异步创建、轮询与取消操作。
type ProviderTaskExecutor interface {
	// StartTask creates one provider task for the exact immutable request.
	// StartTask 为精确不可变请求创建一个供应商任务。
	StartTask(context.Context, provider.ExecutionRequest) (provider.TaskResult, error)
	// PollTask observes the same exact provider task.
	// PollTask 观察同一个精确供应商任务。
	PollTask(context.Context, provider.ExecutionRequest, string) (provider.TaskResult, error)
	// CancelTask requests cancellation of the same exact provider task.
	// CancelTask 请求取消同一个精确供应商任务。
	CancelTask(context.Context, provider.ExecutionRequest, string) (provider.TaskResult, error)
}

// OutputResourceWriter imports provider output into Router-owned storage before public completion.
// OutputResourceWriter 在公开完成前将供应商输出导入 Router 所有存储。
type OutputResourceWriter interface {
	// CreateGenerated publishes already-acquired provider bytes.
	// CreateGenerated 发布已获取的供应商字节。
	CreateGenerated(context.Context, resource.CreateInput) (resource.Resource, error)
	// ImportGeneratedURL securely fetches one temporary public provider URL.
	// ImportGeneratedURL 安全获取一个临时公网供应商 URL。
	ImportGeneratedURL(context.Context, resource.URLImportInput) (resource.Resource, error)
}

// ServiceOptions configures deterministic identity, time, and retention.
// ServiceOptions 配置确定性身份、时间与保留期。
type ServiceOptions struct {
	// NewID creates a cryptographically opaque execution identifier.
	// NewID 创建一个加密不透明执行标识。
	NewID func() (string, error)
	// Now supplies deterministic UTC time.
	// Now 提供确定性 UTC 时间。
	Now func() time.Time
	// Retention controls terminal and recovery record lifetime.
	// Retention 控制终态与恢复记录生命周期。
	Retention time.Duration
	// OutputResources owns generated media ingestion when media output actions are enabled.
	// OutputResources 在启用媒体输出动作时拥有生成媒体接收。
	OutputResources OutputResourceWriter
	// RuntimeFeedback receives trusted classified execution outcomes.
	// RuntimeFeedback 接收可信的分类执行结果。
	RuntimeFeedback RuntimeFeedback
	// Leases coordinates deferred recovery when multiple Router instances share storage.
	// Leases 在多个 Router 实例共享存储时协调延迟恢复。
	Leases LeaseStore
	// WorkerID is the non-secret unique lease owner identity.
	// WorkerID 是非秘密的唯一租约所有者身份。
	WorkerID string
	// LeaseTTL controls takeover and heartbeat timing.
	// LeaseTTL 控制接管与心跳时间。
	LeaseTTL time.Duration
	// EventDistributor waits for events through a shared-store-safe or deployment-specific distribution mechanism.
	// EventDistributor 通过共享存储安全或部署特定的分发机制等待事件。
	EventDistributor EventDistributor
	// ModelTools resolves administrator-configured Router standard-tool backends.
	// ModelTools 解析管理员配置的 Router 标准工具后端。
	ModelTools ModelToolResolver
}

// Service orchestrates durable admission, exact target execution, replay, and cancellation.
// Service 编排持久化接收、精确 Target 执行、回放与取消。
type Service struct {
	// store owns durable execution and event state.
	// store 拥有持久化执行与事件状态。
	store Store
	// resolver selects one exact current target.
	// resolver 选择一个精确当前 Target。
	resolver TargetResolver
	// configurations supplies immutable endpoint, credential, and definition snapshots.
	// configurations 提供不可变 Endpoint、Credential 与 Definition 快照。
	configurations ConfigurationReader
	// plans revalidates conditional media decisions.
	// plans 重新校验条件媒体决策。
	plans InputPlanReader
	// materializer realizes frozen resource paths when configured.
	// materializer 在已配置时实现冻结资源路径。
	materializer InputMaterializer
	// providers owns exact provider driver dispatch.
	// providers 拥有精确供应商 Driver 分派。
	providers ProviderExecutor
	// options contains validated deterministic runtime configuration.
	// options 包含已校验的确定性运行配置。
	options ServiceOptions
	// activeMu protects process-local cancellation handles for currently running synchronous drivers.
	// activeMu 保护当前运行同步 Driver 的进程内取消句柄。
	activeMu sync.Mutex
	// activeCancels maps execution identities to their exact running context cancellation.
	// activeCancels 将执行身份映射到其精确运行 Context 取消函数。
	activeCancels map[string]context.CancelFunc
	// activeExecutions records immediate executions owned by this process before and during provider dispatch.
	// activeExecutions 记录当前进程在供应商分派前及分派期间拥有的即时执行。
	activeExecutions map[string]struct{}
	// leases coordinates optional multi-instance recovery ownership.
	// leases 协调可选的多实例恢复所有权。
	leases LeaseStore
	// workerID identifies this process in durable leases.
	// workerID 在持久租约中标识当前进程。
	workerID string
	// leaseTTL bounds crash takeover delay.
	// leaseTTL 限制崩溃接管延迟。
	leaseTTL time.Duration
	// eventDistributor observes durable event visibility for local and multi-instance SSE followers.
	// eventDistributor 为本地与多实例 SSE 跟随者观察持久事件可见性。
	eventDistributor EventDistributor
}

// ListDiagnostics returns bounded management-safe execution snapshots when supported by the durable store.
// ListDiagnostics 在持久化存储支持时返回有界且管理安全的执行快照。
func (s *Service) ListDiagnostics(ctx context.Context, limit int) ([]Record, error) {
	store, supported := s.store.(DiagnosticStore)
	if !supported {
		return nil, fmt.Errorf("%w: execution diagnostics are unavailable", ErrInvalidExecution)
	}
	return store.ListDiagnostics(ctx, limit)
}

// NewService creates one complete durable execution orchestrator.
// NewService 创建一个完整持久化执行编排器。
func NewService(store Store, resolver TargetResolver, configurations ConfigurationReader, plans InputPlanReader, materializer InputMaterializer, providers ProviderExecutor, options ServiceOptions) (*Service, error) {
	if store == nil || resolver == nil || configurations == nil || providers == nil {
		return nil, fmt.Errorf("%w: store, resolver, configuration reader, and provider executor are required", ErrInvalidExecution)
	}
	if options.NewID == nil {
		options.NewID = randomExecutionID
	}
	if options.Now == nil {
		options.Now = func() time.Time { return time.Now().UTC() }
	}
	if options.Retention <= 0 {
		options.Retention = 24 * time.Hour
	}
	if options.LeaseTTL <= 0 {
		options.LeaseTTL = 30 * time.Second
	}
	if options.Leases != nil {
		if strings.TrimSpace(options.WorkerID) == "" {
			identity, errIdentity := options.NewID()
			if errIdentity != nil {
				return nil, fmt.Errorf("create execution worker identity: %w", errIdentity)
			}
			options.WorkerID = "worker_" + strings.TrimPrefix(identity, "exe_")
		}
	}
	if options.EventDistributor == nil {
		defaultDistributor, errDistributor := NewPollingEventDistributor(store, 0)
		if errDistributor != nil {
			return nil, errDistributor
		}
		options.EventDistributor = defaultDistributor
	}
	return &Service{store: store, resolver: resolver, configurations: configurations, plans: plans, materializer: materializer, providers: providers, options: options, activeCancels: make(map[string]context.CancelFunc), activeExecutions: make(map[string]struct{}), leases: options.Leases, workerID: options.WorkerID, leaseTTL: options.LeaseTTL, eventDistributor: options.EventDistributor}, nil
}

// Create durably admits and executes one validated VCP request or returns an exact idempotent replay.
// Create 持久接收并执行一个已校验 VCP 请求或返回精确幂等重放。
func (s *Service) Create(ctx context.Context, ownerAPIKeyID string, request vcp.ExecutionRequest) (Record, bool, error) {
	return s.create(ctx, ownerAPIKeyID, request, nil, nil)
}

// create admits a public execution or one Router-owned child with explicit lineage and an optional frozen target.
// create 接收一个公开执行或一个具有显式谱系及可选冻结 Target 的 Router 所有子执行。
func (s *Service) create(ctx context.Context, ownerAPIKeyID string, request vcp.ExecutionRequest, lineage *RouterToolLineage, frozenTarget *resolve.Target) (Record, bool, error) {
	if strings.TrimSpace(ownerAPIKeyID) == "" {
		return Record{}, false, fmt.Errorf("%w: owner API key identifier is required", ErrInvalidExecution)
	}
	if errRequest := request.Validate(); errRequest != nil {
		return Record{}, false, errRequest
	}
	canonicalRequest, compatibilityDiagnostics, errCompatibility := canonicalizeLegacyModelTools(request)
	if errCompatibility != nil {
		return Record{}, false, errCompatibility
	}
	request = canonicalRequest
	requestHash, errHash := canonicalRequestHash(request)
	if errHash != nil {
		return Record{}, false, errHash
	}
	if request.IdempotencyKey != "" {
		existing, found, errLookup := s.store.LookupIdempotency(ctx, ownerAPIKeyID, request.IdempotencyKey, requestHash)
		if errLookup != nil || found {
			return existing, found, errLookup
		}
	}
	// now freezes identity, resolution, events, and retention for deterministic admission.
	// now 为确定性接收冻结身份、解析、事件与保留时间。
	now := s.options.Now().UTC()
	continuation, errContinuation := s.resolveRequestedContinuation(ctx, ownerAPIKeyID, request, now)
	if errContinuation != nil {
		return Record{}, false, errContinuation
	}
	// target remains the immutable execution destination selected at admission.
	// target 保持为接收阶段选定的不可变执行目标。
	var target resolve.Target
	if frozenTarget != nil {
		target = *frozenTarget
	} else {
		resolvedTarget, errTarget := s.resolveTarget(ctx, request, now, continuation)
		if errTarget != nil {
			if continuation != nil && continuationTargetPermanentlyUnavailable(errTarget) {
				if errInvalidate := s.updateContinuationState(ctx, ownerAPIKeyID, continuation.ContinuationID, now, false, ContinuationInvalidatedTargetUnavailable); errInvalidate != nil {
					return Record{}, false, errors.Join(errTarget, fmt.Errorf("invalidate unavailable continuation: %w", errInvalidate))
				}
			}
			return Record{}, false, errTarget
		}
		target = resolvedTarget
	}
	if continuation != nil {
		if errAffinity := continuation.Validate(target); errAffinity != nil {
			if errInvalidate := s.updateContinuationState(ctx, ownerAPIKeyID, continuation.ContinuationID, now, false, ContinuationInvalidatedTargetUnavailable); errInvalidate != nil {
				return Record{}, false, errors.Join(fmt.Errorf("%w: continuation target is no longer available", vcp.ErrInvalidRequest), fmt.Errorf("invalidate mismatched continuation: %w", errInvalidate))
			}
			return Record{}, false, fmt.Errorf("%w: continuation target is no longer available", vcp.ErrInvalidRequest)
		}
		if errTouch := s.updateContinuationState(ctx, ownerAPIKeyID, continuation.ContinuationID, now, true, ""); errTouch != nil {
			return Record{}, false, fmt.Errorf("touch continuation: %w", errTouch)
		}
	}
	if errCapabilities := validateRequestAgainstTarget(request, target); errCapabilities != nil {
		return Record{}, false, errCapabilities
	}
	modelToolPlan, errModelTools := s.resolveModelToolPlan(ctx, request, target, now)
	if errModelTools != nil {
		return Record{}, false, errModelTools
	}
	modelToolPlan.Diagnostics = compatibilityDiagnostics
	executionID, errID := s.options.NewID()
	if errID != nil {
		return Record{}, false, fmt.Errorf("create execution identifier: %w", errID)
	}
	immediate := request.DispatchMode != vcp.DispatchDeferred
	if immediate {
		s.registerActiveExecution(executionID)
		defer s.unregisterActiveExecution(executionID)
	}
	record := Record{ID: executionID, OwnerAPIKeyID: ownerAPIKeyID, RequestHash: requestHash, IdempotencyKey: request.IdempotencyKey, Request: request, Target: target, ModelToolPlan: modelToolPlan, RouterToolLineage: lineage, Status: StatusAccepted, Operation: request.Operation, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(s.options.Retention), Revision: 1}
	accepted := lifecycleEvent(record.ID, 1, now, EventExecutionAccepted, StatusAccepted, nil)
	created, replayed, errCreate := s.store.Create(ctx, record, accepted)
	if errCreate != nil || replayed {
		return created, replayed, errCreate
	}
	initialToolEvents := modelToolAdmissionEvents(created.ModelToolPlan)
	if len(initialToolEvents) > 0 {
		created, errCreate = s.appendModelToolEvents(ctx, created, initialToolEvents)
		if errCreate != nil {
			return Record{}, false, errCreate
		}
	}
	if !immediate {
		return created, false, nil
	}
	return s.executeAdmitted(ctx, created)
}

// canonicalizeLegacyModelTools converts the sole required VCP 1.0 hosted-search compatibility declaration into the authoritative model-tool contract.
// canonicalizeLegacyModelTools 将唯一要求兼容的 VCP 1.0 托管搜索声明转换为权威模型工具合同。
// Parameters: request is an already validated execution request that remains caller-owned.
// 参数：request 是已经校验且仍由调用方拥有的执行请求。
// Returns: a mutation-isolated canonical request, safe diagnostics, and an explicit conflict error.
// 返回：与调用方修改隔离的规范请求、安全诊断以及明确的冲突错误。
func canonicalizeLegacyModelTools(request vcp.ExecutionRequest) (vcp.ExecutionRequest, []vcp.ModelToolDiagnostic, error) {
	if request.Operation != vcp.OperationConversationRespond || request.Payload.Conversation == nil {
		return request, nil, nil
	}
	operation := *request.Payload.Conversation
	operation.Tools = append([]vcp.ToolDefinition(nil), operation.Tools...)
	operation.ModelTools.Standard = append([]vcp.StandardModelToolSelection(nil), operation.ModelTools.Standard...)
	operation.ModelTools.Extra = append([]string(nil), operation.ModelTools.Extra...)
	operation.ModelTools.RouterExtensions = append([]vcp.RouterExtensionKind(nil), operation.ModelTools.RouterExtensions...)
	legacySearch := false
	filteredTools := make([]vcp.ToolDefinition, 0, len(operation.Tools))
	for _, tool := range operation.Tools {
		if tool.Kind == vcp.ToolNativeWebSearch {
			legacySearch = true
			continue
		}
		filteredTools = append(filteredTools, tool)
	}
	if !legacySearch {
		request.Payload.Conversation = &operation
		return request, nil, nil
	}
	selectionFound := false
	for _, selection := range operation.ModelTools.Standard {
		if selection.Kind != vcp.StandardModelToolWebSearch {
			continue
		}
		selectionFound = true
		if selection.Mode != vcp.ModelToolNative {
			return vcp.ExecutionRequest{}, nil, vcp.NewModelToolError(vcp.ModelToolModeNotSupported, string(vcp.StandardModelToolWebSearch), "compatibility", false)
		}
	}
	if !selectionFound {
		operation.ModelTools.Standard = append(operation.ModelTools.Standard, vcp.StandardModelToolSelection{Kind: vcp.StandardModelToolWebSearch, Mode: vcp.ModelToolNative})
	}
	operation.Tools = filteredTools
	request.Payload.Conversation = &operation
	if errValidate := request.Validate(); errValidate != nil {
		return vcp.ExecutionRequest{}, nil, errValidate
	}
	diagnostics := []vcp.ModelToolDiagnostic{{Code: vcp.ModelToolDiagnosticLegacyNativeWebSearchMigrated}}
	return request, diagnostics, nil
}

// resolveModelToolPlan freezes request modes, parent catalog evidence, and exact Router child targets.
// resolveModelToolPlan 冻结请求模式、父目录证据与精确 Router 子 Target。
func (s *Service) resolveModelToolPlan(ctx context.Context, request vcp.ExecutionRequest, target resolve.Target, now time.Time) (ModelToolPlan, error) {
	plan := ModelToolPlan{CatalogRevision: target.CatalogRevision}
	if request.Operation != vcp.OperationConversationRespond || request.Payload.Conversation == nil {
		return plan, nil
	}
	operation := request.Payload.Conversation
	if hasReservedRouterToolCollision(operation.Tools) || hasReservedRouterContextCollision(operation.Context) {
		return ModelToolPlan{}, vcp.NewModelToolError(vcp.ModelToolConflictsWithCallerTools, routerToolNamespace, "planning", false)
	}
	if operation.ToolPolicy.Choice == vcp.ToolChoiceNamed {
		for _, selection := range operation.ModelTools.Standard {
			if string(selection.Kind) == operation.ToolPolicy.NamedTool && selection.Mode != vcp.ModelToolRouter {
				return ModelToolPlan{}, vcp.NewModelToolError(vcp.ModelToolModeNotSupported, string(selection.Kind), "planning", false)
			}
		}
		for _, extraToolID := range operation.ModelTools.Extra {
			if extraToolID == operation.ToolPolicy.NamedTool {
				return ModelToolPlan{}, vcp.NewModelToolError(vcp.ModelToolModeNotSupported, extraToolID, "planning", false)
			}
		}
	}
	if operation.ToolPolicy.Choice == vcp.ToolChoiceRequired && !hasProviderForceableTool(*operation) {
		return ModelToolPlan{}, vcp.NewModelToolError(vcp.ModelToolModeNotSupported, "tool_policy.required", "planning", false)
	}
	plan.Standard = make([]ModelToolPlanEntry, 0, len(operation.ModelTools.Standard))
	for _, selection := range operation.ModelTools.Standard {
		entry := ModelToolPlanEntry{Kind: selection.Kind, Mode: selection.Mode}
		if selection.Mode == vcp.ModelToolRouter {
			if s.options.ModelTools == nil {
				return ModelToolPlan{}, vcp.NewModelToolError(vcp.RouterToolBindingMissing, string(selection.Kind), "planning", false)
			}
			resolved, errResolve := s.options.ModelTools.Resolve(ctx, target, selection.Kind, now)
			if errResolve != nil {
				return ModelToolPlan{}, errors.Join(vcp.NewModelToolError(routerBindingErrorCode(errResolve), string(selection.Kind), "planning", false), errResolve)
			}
			entry.RouterBinding = &resolved
			entry.RouterBindingID = resolved.Binding.ID
			entry.RouterBindingRevision = resolved.Binding.Revision
		}
		plan.Standard = append(plan.Standard, entry)
	}
	plan.Extra = append([]string(nil), operation.ModelTools.Extra...)
	plan.RouterExtensions = make([]RouterExtensionPlanEntry, 0, len(operation.ModelTools.RouterExtensions))
	for _, extension := range operation.ModelTools.RouterExtensions {
		if s.options.ModelTools == nil {
			return ModelToolPlan{}, vcp.NewModelToolError(vcp.RouterToolBindingMissing, string(extension), "planning", false)
		}
		resolved, errResolve := s.options.ModelTools.ResolveExtension(ctx, target, extension, now)
		if errResolve != nil {
			return ModelToolPlan{}, errors.Join(vcp.NewModelToolError(routerBindingErrorCode(errResolve), string(extension), "planning", false), errResolve)
		}
		plan.RouterExtensions = append(plan.RouterExtensions, RouterExtensionPlanEntry{
			ID:                    extension,
			RouterBindingID:       resolved.Binding.ID,
			RouterBindingRevision: resolved.Binding.Revision,
			RouterBinding:         &resolved,
		})
	}
	return plan, nil
}

// hasProviderForceableTool reports whether required choice can be represented by at least one caller or Router function.
// hasProviderForceableTool 报告 required 选择是否能够由至少一个调用方或 Router 函数真实表达。
func hasProviderForceableTool(operation vcp.ConversationOperation) bool {
	for _, tool := range operation.Tools {
		if tool.Kind == vcp.ToolFunction || tool.Kind == vcp.ToolCustom {
			return true
		}
	}
	if len(operation.ModelTools.RouterExtensions) > 0 {
		return true
	}
	for _, selection := range operation.ModelTools.Standard {
		if selection.Mode == vcp.ModelToolRouter {
			return true
		}
	}
	return false
}

// routerBindingErrorCode preserves the stable distinction between absent policy and temporarily unavailable execution state.
// routerBindingErrorCode 保留策略缺失与执行状态暂时不可用之间的稳定区别。
func routerBindingErrorCode(errResolve error) vcp.ModelToolErrorCode {
	if errors.Is(errResolve, routertool.ErrBindingNotFound) {
		return vcp.RouterToolBindingMissing
	}
	return vcp.RouterToolBindingUnavailable
}

// executeAdmitted owns one immediate execution under a distinct durable lease so recovery cannot replay its provider side effect.
// executeAdmitted 通过独立持久租约拥有一次即时执行，防止恢复器重放其供应商副作用。
func (s *Service) executeAdmitted(ctx context.Context, record Record) (Record, bool, error) {
	var executed Record
	var replayed bool
	acquired, errLease := s.withExecutionLease(ctx, record.ID, s.workerID+"_direct", func(leaseContext context.Context) error {
		var errExecute error
		executed, replayed, errExecute = s.execute(leaseContext, record)
		return errExecute
	})
	if errLease != nil {
		return Record{}, false, errLease
	}
	if !acquired {
		return Record{}, false, ErrRevisionConflict
	}
	return executed, replayed, nil
}

// registerActiveExecution reserves an immediate execution locally before its durable admission becomes visible to recovery.
// registerActiveExecution 在即时执行的持久接收对恢复器可见前于本地预留该执行。
func (s *Service) registerActiveExecution(executionID string) {
	s.activeMu.Lock()
	s.activeExecutions[executionID] = struct{}{}
	s.activeMu.Unlock()
}

// unregisterActiveExecution releases one process-local immediate-execution reservation.
// unregisterActiveExecution 释放一个进程内即时执行预留。
func (s *Service) unregisterActiveExecution(executionID string) {
	s.activeMu.Lock()
	delete(s.activeExecutions, executionID)
	s.activeMu.Unlock()
}

// executionActive reports whether this process currently owns immediate dispatch for an execution.
// executionActive 报告当前进程是否正在拥有某次执行的即时分派。
func (s *Service) executionActive(executionID string) bool {
	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	_, exists := s.activeExecutions[executionID]
	return exists
}

// Get returns one owner-scoped execution without private recovery fields.
// Get 返回一个所有者作用域执行且不暴露私有恢复字段。
func (s *Service) Get(ctx context.Context, ownerAPIKeyID string, executionID string) (Record, error) {
	return s.store.Get(ctx, ownerAPIKeyID, executionID)
}

// Events returns durable events strictly after one sequence.
// Events 返回指定序号之后的持久化事件。
func (s *Service) Events(ctx context.Context, ownerAPIKeyID string, executionID string, afterSequence uint64) ([]Event, error) {
	return s.store.ListEvents(ctx, ownerAPIKeyID, executionID, afterSequence)
}

// WaitEvents waits for the next durable event batch through the configured distribution boundary.
// WaitEvents 通过配置的分发边界等待下一批持久事件。
func (s *Service) WaitEvents(ctx context.Context, ownerAPIKeyID string, executionID string, afterSequence uint64, maxWait time.Duration) ([]Event, error) {
	return s.eventDistributor.Wait(ctx, ownerAPIKeyID, executionID, afterSequence, maxWait)
}

// Cancel confirms cancellation only before provider execution starts; running provider tasks require an exact cancel driver.
// Cancel 仅在供应商执行开始前确认取消；运行中的供应商任务需要精确取消 Driver。
func (s *Service) Cancel(ctx context.Context, ownerAPIKeyID string, executionID string) (Record, error) {
	record, errGet := s.store.Get(ctx, ownerAPIKeyID, executionID)
	if errGet != nil {
		return Record{}, errGet
	}
	if record.Status.IsTerminal() {
		return record, nil
	}
	if record.ProviderTask != nil {
		taskExecutor, ok := s.providers.(ProviderTaskExecutor)
		if !ok {
			return Record{}, fmt.Errorf("%w: provider task cancellation is not registered", ErrInvalidExecution)
		}
		if record.ProviderTask.CancellationRequestedAt == nil {
			now := s.options.Now().UTC()
			record.ProviderTask.CancellationRequestedAt = &now
			record.ProviderTask.CancellationAfter = now
			var errIntent error
			record, errIntent = s.appendLifecycle(ctx, record, EventExecutionCancellationRequested)
			if errIntent != nil {
				return Record{}, errIntent
			}
		}
		cancelled, _, errCancel := s.cancelProviderTaskOnce(ctx, record, taskExecutor)
		return cancelled, errCancel
	}
	if record.Status == StatusWaitingRetry {
		var errAborted error
		record, errAborted = s.appendRetryEvent(ctx, record, EventRetryAborted, uint32(len(record.Attempts)+1), nil, record.Retry.Category)
		if errAborted != nil {
			return Record{}, errAborted
		}
		return s.transition(ctx, record, StatusCancelled, EventExecutionCancelled, nil)
	}
	if record.Status == StatusRunning || record.Status == StatusQueued {
		if record.Status == StatusRunning {
			s.activeMu.Lock()
			cancel := s.activeCancels[record.ID]
			s.activeMu.Unlock()
			if cancel != nil {
				now := s.options.Now().UTC()
				expectedRevision := record.Revision
				sequence, errSequence := s.nextEventSequence(ctx, record)
				if errSequence != nil {
					return Record{}, errSequence
				}
				record.Status = StatusCancelled
				record.UpdatedAt = now
				record.Revision++
				event := lifecycleEvent(record.ID, sequence, now, EventExecutionCancelled, StatusCancelled, nil)
				if errSave := s.store.Save(ctx, record, expectedRevision, []Event{event}); errSave != nil {
					return Record{}, errSave
				}
				cancel()
				return record, nil
			}
		}
		return Record{}, fmt.Errorf("%w: running execution has no cancellable provider task or local driver", ErrInvalidExecution)
	}
	now := s.options.Now().UTC()
	expectedRevision := record.Revision
	sequence, errSequence := s.nextEventSequence(ctx, record)
	if errSequence != nil {
		return Record{}, errSequence
	}
	record.Status = StatusCancelled
	record.Retry = nil
	record.UpdatedAt = now
	record.Revision++
	event := lifecycleEvent(record.ID, sequence, now, EventExecutionCancelled, StatusCancelled, nil)
	if errSave := s.store.Save(ctx, record, expectedRevision, []Event{event}); errSave != nil {
		return Record{}, errSave
	}
	return record, nil
}

// execute prepares inputs, loads immutable wire snapshots, dispatches, and commits one terminal reduction.
// execute 准备输入、加载不可变 Wire 快照、分派并提交一个终态归并结果。
func (s *Service) execute(ctx context.Context, record Record) (Record, bool, error) {
	if executionBudgetExpired(record, s.options.Now().UTC()) {
		failed, errFail := s.fail(ctx, record, "execution_time_budget_exceeded", false)
		return failed, false, errFail
	}
	materialized, updated, errInputs := s.prepareInputs(ctx, record)
	if errInputs != nil {
		failed, errFail := s.fail(ctx, updated, stableFailureCode(errInputs), retryableFailure(errInputs))
		if errFail != nil {
			return Record{}, false, errFail
		}
		return failed, false, nil
	}
	record = updated
	if errBudget := validateMaterializedInputBudget(record.Request.Budget, materialized); errBudget != nil {
		failed, errFail := s.fail(ctx, record, stableFailureCode(errBudget), false)
		return failed, false, errFail
	}
	binding, definition, errBinding := s.loadBinding(ctx, record.Target)
	if errBinding != nil {
		failed, errFail := s.fail(ctx, record, stableFailureCode(errBinding), retryableFailure(errBinding))
		if errFail != nil {
			return Record{}, false, errFail
		}
		return failed, false, nil
	}
	preparedWorkflow, errPreparedWorkflow := s.resolvePreparedWorkflow(ctx, record)
	if errPreparedWorkflow != nil {
		failed, errFail := s.fail(ctx, record, stableFailureCode(errPreparedWorkflow), false)
		if errFail != nil {
			return Record{}, false, errFail
		}
		return failed, false, nil
	}
	continuation, errContinuation := s.resolveRequestedContinuation(ctx, record.OwnerAPIKeyID, record.Request, s.options.Now().UTC())
	if errContinuation != nil {
		failed, errFail := s.fail(ctx, record, stableFailureCode(errContinuation), false)
		if errFail != nil {
			return Record{}, false, errFail
		}
		return failed, false, nil
	}
	if requiresProviderTask(record.Target) {
		return s.startTask(ctx, record, binding, definition, materialized)
	}
	executionContext, cancelExecution := executionContextForBudget(ctx, record)
	s.registerActiveCancellation(record.ID, cancelExecution)
	defer func() {
		cancelExecution()
		s.unregisterActiveCancellation(record.ID)
	}()
	running, errRunning := s.transition(executionContext, record, StatusRunning, EventExecutionRunning, nil)
	if errRunning != nil {
		return Record{}, false, errRunning
	}
	return s.executeSynchronous(executionContext, running, binding, definition, materialized, preparedWorkflow, continuation)
}

// registerActiveCancellation installs the sole process-local cancellation handle for a running execution.
// registerActiveCancellation 为一个运行中执行安装唯一进程内取消句柄。
func (s *Service) registerActiveCancellation(executionID string, cancel context.CancelFunc) {
	s.activeMu.Lock()
	s.activeCancels[executionID] = cancel
	s.activeMu.Unlock()
}

// unregisterActiveCancellation removes a completed process-local cancellation handle.
// unregisterActiveCancellation 删除一个已完成的进程内取消句柄。
func (s *Service) unregisterActiveCancellation(executionID string) {
	s.activeMu.Lock()
	delete(s.activeCancels, executionID)
	s.activeMu.Unlock()
}

// executeSynchronous dispatches a bounded sequence of same-provider attempts before any semantic output is committed.
// executeSynchronous 在提交任何语义输出前分派有界的同供应商尝试序列。
func (s *Service) executeSynchronous(ctx context.Context, record Record, binding transport.Binding, definition providerconfig.ProviderDefinition, materialized []resource.MaterializedInput, preparedWorkflow *provider.PreparedWorkflowBinding, continuation *provider.ContinuationBinding) (Record, bool, error) {
	excludedCredentials := make([]string, 0, maxSameProviderExecutionAttempts)
	excludedEndpoints := make([]string, 0, maxSameProviderExecutionAttempts)
	cycleAttempts := maximumSynchronousCycleAttempts(record)
	routerCallsByBinding, seenRouterToolCalls, errHistory := routerToolHistory(record)
	if errHistory != nil {
		failed, errFail := s.fail(ctx, record, string(vcp.RouterToolResultInvalid), false)
		return failed, false, errFail
	}
	if cycleAttempts <= 0 {
		failed, errFail := s.fail(ctx, record, "same_provider_attempt_limit_reached", false)
		return failed, false, errFail
	}
	routerRound := record.CompletedRouterToolRounds
	for attemptIndex := 0; attemptIndex < cycleAttempts; attemptIndex++ {
		providerRequest := providerRequestForRecord(record, binding, definition, materialized, preparedWorkflow, continuation)
		// eventSink is present only for an explicitly streaming request and commits each decoded event before the Driver reads another frame.
		// eventSink 仅用于显式流式请求，并在 Driver 读取下一帧前提交每个已解码事件。
		var eventSink *durableProviderEventSink
		if record.Request.Stream && !hasRouterToolPlan(record.ModelToolPlan) {
			eventSink = newDurableProviderEventSink(s, record)
			providerRequest.EventSink = eventSink
			providerRequest.ResourceSink = eventSink
		}
		startedAt := s.options.Now().UTC()
		providerResult, errExecute := s.providers.Execute(ctx, providerRequest)
		endedAt := s.options.Now().UTC()
		if eventSink != nil {
			refreshed, errRefresh := s.store.Get(context.WithoutCancel(ctx), record.OwnerAPIKeyID, record.ID)
			if errRefresh != nil {
				return Record{}, false, errRefresh
			}
			record = refreshed
		}
		semanticOutput := providerResultHasSemanticOutput(providerResult) || eventSink != nil && eventSink.emittedCount() > 0
		attempt := Attempt{Sequence: uint32(len(record.Attempts) + 1), Target: record.Target, StartedAt: startedAt, EndedAt: endedAt, SemanticOutput: semanticOutput}
		if errExecute != nil {
			continuationRejected := continuation != nil && errors.Is(errExecute, provider.ErrContinuationRejected)
			if errors.Is(errExecute, context.Canceled) {
				cancelled, errCancelled := s.store.Get(context.WithoutCancel(ctx), record.OwnerAPIKeyID, record.ID)
				if errCancelled == nil && cancelled.Status == StatusCancelled {
					return cancelled, false, nil
				}
			}
			classified, classifiedOK := s.classifyAndRecordFailure(ctx, providerRequest, errExecute)
			if classifiedOK {
				attempt.FailureCategory = classified.Category
				attempt.RetryAction = classified.Action
			}
			nextTarget, retry := s.resolveRetryTarget(ctx, record, classified, classifiedOK, semanticOutput, materialized, preparedWorkflow, &excludedCredentials, &excludedEndpoints)
			if retry && attemptIndex+1 < cycleAttempts {
				updated, errPersist := s.persistAttempt(ctx, record, attempt, &nextTarget)
				if errPersist != nil {
					return Record{}, false, errPersist
				}
				binding, definition, errExecute = s.loadBinding(ctx, nextTarget)
				if errExecute != nil {
					failed, errFail := s.fail(ctx, updated, stableFailureCode(errExecute), retryableFailure(errExecute))
					return failed, false, errFail
				}
				record = updated
				continue
			}
			updated, errPersist := s.persistAttempt(ctx, record, attempt, nil)
			if errPersist != nil {
				return Record{}, false, errPersist
			}
			if scheduled, didSchedule, errSchedule := s.scheduleRetry(ctx, updated, classified, classifiedOK, semanticOutput); errSchedule != nil {
				return Record{}, false, errSchedule
			} else if didSchedule {
				return scheduled, false, nil
			}
			failed, errFail := s.failClassified(ctx, updated, stableFailureCode(errExecute), retryableFailure(errExecute) || classifiedRetryable(classified, classifiedOK), classified, classifiedOK)
			if errFail != nil {
				return Record{}, false, errFail
			}
			if continuationRejected {
				if errInvalidate := s.updateContinuationState(context.WithoutCancel(ctx), record.OwnerAPIKeyID, continuation.ContinuationID, endedAt, false, ContinuationInvalidatedProviderRejected); errInvalidate != nil {
					return failed, false, fmt.Errorf("invalidate provider-rejected continuation: %w", errInvalidate)
				}
			}
			return failed, false, nil
		}
		if errResult := validateProviderResult(record.Request, providerResult, true); errResult != nil {
			attempt.FailureCategory = "invalid_provider_result"
			updated, errPersist := s.persistAttempt(ctx, record, attempt, nil)
			if errPersist != nil {
				return Record{}, false, errPersist
			}
			failed, errFail := s.fail(ctx, updated, stableFailureCode(errResult), false)
			if errFail != nil {
				return Record{}, false, errFail
			}
			return failed, false, nil
		}
		routerCalls, errRouterCalls := routerToolCalls(providerResult, record.ModelToolPlan)
		if errRouterCalls != nil {
			attempt.FailureCategory = "invalid_provider_result"
			updated, errPersist := s.persistAttempt(ctx, record, attempt, nil)
			if errPersist != nil {
				return Record{}, false, errPersist
			}
			failed, errFail := s.fail(ctx, updated, stableFailureCode(errRouterCalls), false)
			return failed, false, errFail
		}
		if len(routerCalls) > 0 {
			if len(providerResult.GeneratedResources) > 0 {
				attempt.FailureCategory = "invalid_provider_result"
				updated, errPersist := s.persistAttempt(ctx, record, attempt, nil)
				if errPersist != nil {
					return Record{}, false, errPersist
				}
				failed, errFail := s.fail(ctx, updated, "router_tool_round_returned_generated_resources", false)
				return failed, false, errFail
			}
			attempt.Succeeded = true
			attempt.Usage, _ = usageObservationForResult(providerResult)
			record.Attempts = append(record.Attempts, attempt)
			s.recordSuccessfulRequest(ctx, providerRequest)
			routerRound++
			for _, routerCall := range routerCalls {
				toolCallID := routerCall.Output.ToolCall.ToolCallID
				if _, exists := seenRouterToolCalls[toolCallID]; exists {
					failed, errFail := s.fail(ctx, record, "duplicate_router_tool_call", false)
					return failed, false, errFail
				}
				seenRouterToolCalls[toolCallID] = struct{}{}
				bindingID := routerCall.Plan.RouterBinding.Binding.ID
				routerCallsByBinding[bindingID]++
				if routerCallsByBinding[bindingID] > routerCall.Plan.RouterBinding.Binding.MaximumCalls {
					failed, errFail := s.fail(ctx, record, string(vcp.RouterToolRoundLimitExceeded), false)
					return failed, false, errFail
				}
			}
			startedEvents := make([]ModelToolEvent, 0, len(routerCalls))
			for _, routerCall := range routerCalls {
				startedEvents = append(startedEvents, ModelToolEvent{
					ToolID:     routerCall.Plan.ToolID(),
					Stage:      ModelToolStageRouterCallStarted,
					Mode:       vcp.ModelToolRouter,
					ToolCallID: routerCall.Output.ToolCall.ToolCallID,
					Round:      routerRound,
				})
			}
			record, errRouterCalls = s.appendModelToolEvents(ctx, record, startedEvents)
			if errRouterCalls != nil {
				return Record{}, false, errRouterCalls
			}
			routerResults := s.executeRouterToolCalls(ctx, record, routerCalls, routerRound, record.Request.Payload.Conversation.ToolPolicy.Parallel)
			// candidate isolates all parent-context injections until every parallel child result is valid.
			// candidate 隔离全部父上下文注入，直到每个并行子执行结果均有效。
			candidate := record
			completedEvents := make([]ModelToolEvent, 0, len(routerResults)*2)
			resumedEvents := make([]ModelToolEvent, 0, len(routerResults)*2)
			for index, routerResult := range routerResults {
				routerCall := routerCalls[index]
				if routerResult.Err != nil {
					if routerResult.ChildExecutionID != "" {
						completedEvents = append(completedEvents, ModelToolEvent{
							ToolID:           routerCall.Plan.ToolID(),
							Stage:            ModelToolStageChildCreated,
							Mode:             vcp.ModelToolRouter,
							ToolCallID:       routerCall.Output.ToolCall.ToolCallID,
							ChildExecutionID: routerResult.ChildExecutionID,
							Round:            routerRound,
						})
					}
					completedEvents = append(completedEvents, ModelToolEvent{
						ToolID:           routerCall.Plan.ToolID(),
						Stage:            ModelToolStageChildFailed,
						Mode:             vcp.ModelToolRouter,
						ToolCallID:       routerCall.Output.ToolCall.ToolCallID,
						ChildExecutionID: routerResult.ChildExecutionID,
						Round:            routerRound,
					})
					record, errRouterCalls = s.appendModelToolEvents(ctx, record, completedEvents)
					if errRouterCalls != nil {
						return Record{}, false, errRouterCalls
					}
					failed, errFail := s.fail(ctx, record, stableFailureCode(routerResult.Err), retryableFailure(routerResult.Err))
					return failed, false, errFail
				}
				completedEvents = append(completedEvents,
					ModelToolEvent{ToolID: routerCall.Plan.ToolID(), Stage: ModelToolStageChildCreated, Mode: vcp.ModelToolRouter, ToolCallID: routerCall.Output.ToolCall.ToolCallID, ChildExecutionID: routerResult.ChildExecutionID, Round: routerRound},
					ModelToolEvent{ToolID: routerCall.Plan.ToolID(), Stage: ModelToolStageChildCompleted, Mode: vcp.ModelToolRouter, ToolCallID: routerCall.Output.ToolCall.ToolCallID, ChildExecutionID: routerResult.ChildExecutionID, Round: routerRound},
				)
				if errAppend := appendRouterToolResult(&candidate, routerCall, routerResult.ModelResult, routerResult.ChildExecutionID, routerRound); errAppend != nil {
					record, errRouterCalls = s.appendModelToolEvents(ctx, record, completedEvents)
					if errRouterCalls != nil {
						return Record{}, false, errRouterCalls
					}
					errResult := errors.Join(vcp.NewModelToolError(vcp.RouterToolResultInvalid, routerCall.Plan.ToolID(), "result", false), errAppend)
					failed, errFail := s.fail(ctx, record, stableFailureCode(errResult), false)
					return failed, false, errFail
				}
				resumedEvents = append(resumedEvents,
					ModelToolEvent{ToolID: routerCall.Plan.ToolID(), Stage: ModelToolStageResultInjected, Mode: vcp.ModelToolRouter, ToolCallID: routerCall.Output.ToolCall.ToolCallID, ChildExecutionID: routerResult.ChildExecutionID, Round: routerRound},
					ModelToolEvent{ToolID: routerCall.Plan.ToolID(), Stage: ModelToolStageParentResumed, Mode: vcp.ModelToolRouter, ToolCallID: routerCall.Output.ToolCall.ToolCallID, ChildExecutionID: routerResult.ChildExecutionID, Round: routerRound},
				)
			}
			record = candidate
			completedEvents = append(completedEvents, resumedEvents...)
			if errPersist := s.persistRouterToolRound(ctx, &record, completedEvents); errPersist != nil {
				return Record{}, false, errPersist
			}
			continue
		}
		attempt.Succeeded = true
		attempt.Usage, _ = usageObservationForResult(providerResult)
		record.Attempts = append(record.Attempts, attempt)
		s.recordSuccessfulRequest(ctx, providerRequest)
		generatedResources, errResources := s.ingestGeneratedResources(ctx, record, providerResult.GeneratedResources)
		if errResources != nil {
			failed, errFail := s.fail(ctx, record, stableFailureCode(errResources), retryableFailure(errResources))
			if errFail != nil {
				return Record{}, false, errFail
			}
			return failed, false, nil
		}
		if record.RetryCycles > 0 {
			var errRetrySucceeded error
			record, errRetrySucceeded = s.appendRetryEvent(ctx, record, EventRetrySucceeded, uint32(len(record.Attempts)), nil, "")
			if errRetrySucceeded != nil {
				return Record{}, false, errRetrySucceeded
			}
		}
		if eventSink != nil {
			// Only persistence receives the uncommitted suffix; validation above always proves the complete provider event history.
			// 仅持久化阶段接收尚未提交的后缀；上方校验始终证明完整的供应商事件历史。
			providerResult.Events = eventSink.filterPending(providerResult.Events)
		}
		return s.succeed(ctx, record, providerResult, generatedResources)
	}
	return Record{}, false, fmt.Errorf("%w: same-provider attempt limit reached", ErrInvalidExecution)
}

// resolvePreparedWorkflow resolves one owner-scoped cover preparation without exposing its provider handle.
// resolvePreparedWorkflow 解析一个所有者作用域的翻唱准备结果且不暴露其供应商句柄。
func (s *Service) resolvePreparedWorkflow(ctx context.Context, record Record) (*provider.PreparedWorkflowBinding, error) {
	if record.Operation != vcp.OperationMusicCover {
		return nil, nil
	}
	operation := record.Request.Payload.MusicCover
	if operation != nil && operation.Source != nil {
		return nil, nil
	}
	if operation == nil || strings.TrimSpace(operation.PreparationID) == "" {
		return nil, fmt.Errorf("%w: cover preparation is required", vcp.ErrInvalidRequest)
	}
	prepared, errGet := s.store.Get(ctx, record.OwnerAPIKeyID, operation.PreparationID)
	if errGet != nil {
		return nil, fmt.Errorf("%w: cover preparation is unavailable", vcp.ErrInvalidRequest)
	}
	now := s.options.Now().UTC()
	if prepared.Operation != vcp.OperationMusicCoverPrepare || prepared.Status != StatusSucceeded || prepared.ProviderPreparation == nil || prepared.Result == nil || prepared.Result.MusicCoverPreparation == nil || !prepared.ProviderPreparation.ExpiresAt.After(now) || prepared.Result.MusicCoverPreparation.PreparationID != operation.PreparationID {
		return nil, fmt.Errorf("%w: cover preparation is expired or incomplete", vcp.ErrInvalidRequest)
	}
	preparedTarget := prepared.ProviderPreparation.Target
	if preparedTarget.ProviderDefinitionID != record.Target.ProviderDefinitionID || preparedTarget.ProviderInstanceID != record.Target.ProviderInstanceID || preparedTarget.EndpointID != record.Target.EndpointID || preparedTarget.EndpointRegion != record.Target.EndpointRegion || preparedTarget.CredentialID != record.Target.CredentialID || preparedTarget.UpstreamModelID != record.Target.UpstreamModelID {
		return nil, fmt.Errorf("%w: cover preparation belongs to a different immutable provider target", vcp.ErrInvalidRequest)
	}
	return &provider.PreparedWorkflowBinding{PreparationID: operation.PreparationID, ProviderHandle: prepared.ProviderPreparation.ProviderHandle, ExpiresAt: prepared.ProviderPreparation.ExpiresAt}, nil
}

// ingestGeneratedResources imports every provider output before its temporary source can reach public state.
// ingestGeneratedResources 在任何临时来源进入公开状态前导入每个供应商输出。
func (s *Service) ingestGeneratedResources(ctx context.Context, record Record, outputs []provider.GeneratedResource) ([]resource.Resource, error) {
	if len(outputs) == 0 {
		return nil, nil
	}
	if s.options.OutputResources == nil {
		return nil, fmt.Errorf("%w: generated resource writer is required", ErrInvalidProviderResult)
	}
	resources := make([]resource.Resource, 0, len(outputs))
	seen := make(map[string]struct{}, len(outputs))
	remainingBytes := record.Request.Budget.MaxOutputBytes
	for _, output := range outputs {
		hasData := len(output.Data) > 0
		hasURL := strings.TrimSpace(output.DownloadURL) != ""
		if strings.TrimSpace(output.OutputID) == "" || hasData == hasURL {
			return nil, fmt.Errorf("%w: generated resource requires a unique output identifier and exactly one acquisition source", ErrInvalidProviderResult)
		}
		if _, exists := seen[output.OutputID]; exists {
			return nil, fmt.Errorf("%w: duplicate generated resource output identifier", ErrInvalidProviderResult)
		}
		seen[output.OutputID] = struct{}{}
		generatedBy := generatedResourceProvenance(record)
		if remainingBytes != nil && int64(len(output.Data)) > *remainingBytes {
			return nil, fmt.Errorf("%w: generated output exceeds max_output_bytes", ErrExecutionBudgetExceeded)
		}
		input := resource.CreateInput{OwnerAPIKeyID: record.OwnerAPIKeyID, Kind: output.Kind, DeclaredMIME: output.MIMEType, Retention: resource.RetentionEphemeral, GeneratedBy: &generatedBy, MaxBytes: remainingBytes}
		var (
			created   resource.Resource
			errCreate error
		)
		if len(output.Data) > 0 {
			input.Reader = bytes.NewReader(output.Data)
			created, errCreate = s.options.OutputResources.CreateGenerated(ctx, input)
		} else {
			created, errCreate = s.options.OutputResources.ImportGeneratedURL(ctx, resource.URLImportInput{OwnerAPIKeyID: record.OwnerAPIKeyID, URL: output.DownloadURL, Kind: output.Kind, DeclaredMIME: output.MIMEType, Retention: resource.RetentionEphemeral, GeneratedBy: &generatedBy, MaxBytes: remainingBytes})
		}
		if errCreate != nil {
			return nil, fmt.Errorf("import generated resource: %w", errCreate)
		}
		resources = append(resources, created)
		if remainingBytes != nil {
			updatedRemaining := *remainingBytes - created.SizeBytes
			remainingBytes = &updatedRemaining
		}
	}
	return resources, nil
}

// validateMaterializedInputBudget checks exact Router resource sizes without estimating remote content.
// validateMaterializedInputBudget 使用精确 Router 资源大小进行校验且不估算远程内容。
func validateMaterializedInputBudget(budget vcp.OperationBudget, inputs []resource.MaterializedInput) error {
	if budget.MaxInputBytes == nil {
		return nil
	}
	var total int64
	for _, input := range inputs {
		if input.SizeBytes < 0 || total > *budget.MaxInputBytes-input.SizeBytes {
			return fmt.Errorf("%w: materialized input exceeds max_input_bytes", ErrExecutionBudgetExceeded)
		}
		total += input.SizeBytes
	}
	return nil
}

// executionContextForBudget creates a deadline tied to durable admission rather than retry start time.
// executionContextForBudget 创建绑定持久接收时间而非重试开始时间的截止 Context。
func executionContextForBudget(ctx context.Context, record Record) (context.Context, context.CancelFunc) {
	deadline, bounded := executionDeadline(record)
	if !bounded {
		return context.WithCancel(ctx)
	}
	return context.WithDeadline(ctx, deadline)
}

// executionBudgetExpired reports whether the caller's durable wall-clock ceiling has elapsed.
// executionBudgetExpired 表示调用方的持久墙钟上限是否已经届满。
func executionBudgetExpired(record Record, now time.Time) bool {
	deadline, bounded := executionDeadline(record)
	if !bounded {
		return false
	}
	return !deadline.After(now)
}

// executionDeadline returns the earliest caller budget or hard Router-parent ceiling tied to durable admission.
// executionDeadline 返回绑定持久接收时间的调用方预算或 Router 父执行硬上限中的最早值。
func executionDeadline(record Record) (time.Time, bool) {
	var deadline time.Time
	if record.Request.Budget.MaxExecutionMilliseconds != nil {
		deadline = record.CreatedAt.Add(time.Duration(*record.Request.Budget.MaxExecutionMilliseconds) * time.Millisecond)
	}
	if hasRouterToolPlan(record.ModelToolPlan) {
		routerDeadline := record.CreatedAt.Add(maximumRouterParentExecutionDuration)
		if deadline.IsZero() || routerDeadline.Before(deadline) {
			deadline = routerDeadline
		}
	}
	return deadline, !deadline.IsZero()
}

// generatedResourceProvenance derives safe immutable origin facts from the accepted execution snapshot.
// generatedResourceProvenance 从已接收执行快照派生安全且不可变的来源事实。
func generatedResourceProvenance(record Record) resource.GenerationProvenance {
	return resource.GenerationProvenance{ExecutionID: record.ID, ProviderDefinitionID: record.Target.ProviderDefinitionID, ProviderModelID: record.Target.ProviderModelID, UpstreamModelID: record.Target.UpstreamModelID, ActionBindingID: record.Target.ActionBindingID, Operation: record.Operation}
}

// validateRequestAgainstTarget enforces the selected immutable profile before durable admission or network traffic.
// validateRequestAgainstTarget 在持久接收或网络请求前强制执行选定的不可变 Profile。
func validateRequestAgainstTarget(request vcp.ExecutionRequest, target resolve.Target) error {
	if request.Stream && !target.ModelCapabilities.Delivery.Streaming && target.SubjectKind == resolve.ExecutionSubjectModel {
		return fmt.Errorf("%w: selected profile does not support streaming", vcp.ErrInvalidRequest)
	}
	if !request.Stream && !target.ModelCapabilities.Delivery.Synchronous && !target.ModelCapabilities.Delivery.Asynchronous && target.SubjectKind == resolve.ExecutionSubjectModel {
		return fmt.Errorf("%w: selected profile requires streaming or asynchronous execution", vcp.ErrInvalidRequest)
	}
	if target.SubjectKind != resolve.ExecutionSubjectModel {
		return nil
	}
	if errOperation := target.ModelCapabilities.ValidateOperation(request.Operation); errOperation != nil {
		return fmt.Errorf("%w: selected profile capability contract is invalid: %v", vcp.ErrInvalidRequest, errOperation)
	}
	switch request.Operation {
	case vcp.OperationConversationRespond:
		if errTokens := validateConversationTokenRequest(*request.Payload.Conversation, target); errTokens != nil {
			return errTokens
		}
		requestedOutputs := request.Payload.Conversation.GenerationPolicy.OutputModalities
		if len(requestedOutputs) == 0 {
			requestedOutputs = []string{"text"}
		}
		for _, modality := range requestedOutputs {
			if !containsExecutionString(target.ModelCapabilities.OutputModalities, modality) {
				return fmt.Errorf("%w: selected profile does not support output modality %s", vcp.ErrInvalidRequest, modality)
			}
		}
		if audio := request.Payload.Conversation.GenerationPolicy.AudioOutput; audio != nil && !supportsConversationAudioOutput(target.ModelCapabilities.MediaOutputs, audio.OutputFormat) {
			return fmt.Errorf("%w: selected profile does not support conversational audio format %s", vcp.ErrInvalidRequest, audio.OutputFormat)
		}
		for _, tool := range request.Payload.Conversation.Tools {
			if isProviderHostedTool(tool.Kind) && !containsHostedTool(target.ModelCapabilities, tool.Kind) {
				return fmt.Errorf("%w: selected profile does not support hosted tool %s", vcp.ErrInvalidRequest, tool.Kind)
			}
		}
		if errModelTools := validateModelToolSelectionAgainstTarget(*request.Payload.Conversation, target.ModelCapabilities, request.Stream); errModelTools != nil {
			return errModelTools
		}
		return validateConversationMediaRequest(request, target.ModelCapabilities.MediaInputs)
	case vcp.OperationMediaAnalyze:
		return validateMediaAnalyzeRequest(*request.Payload.MediaAnalyze, target.ModelCapabilities.MediaInputs)
	case vcp.OperationEmbeddingCreate:
		return validateEmbeddingRequest(*request.Payload.EmbeddingCreate, *target.ModelCapabilities.Embedding)
	case vcp.OperationRerankDocuments:
		return validateRerankRequest(*request.Payload.RerankDocuments, *target.ModelCapabilities.Rerank)
	default:
		return nil
	}
}

// validateConversationTokenRequest enforces known output ceilings under the fixed shared-context semantic.
// validateConversationTokenRequest 按固定共享上下文语义强制执行已知输出上限。
func validateConversationTokenRequest(operation vcp.ConversationOperation, target resolve.Target) error {
	if operation.GenerationPolicy.MaxOutputTokens == nil {
		return nil
	}
	requested := int64(*operation.GenerationPolicy.MaxOutputTokens)
	if target.TokenLimits.MaxOutputTokens.Known && requested > target.TokenLimits.MaxOutputTokens.Value {
		return fmt.Errorf("%w: requested max_output_tokens exceeds the selected profile output ceiling", vcp.ErrInvalidRequest)
	}
	if target.EffectiveContextWindow.Known && requested > target.EffectiveContextWindow.Value {
		return fmt.Errorf("%w: requested max_output_tokens exceeds the selected account shared context window", vcp.ErrInvalidRequest)
	}
	return nil
}

// containsExecutionString reports exact membership in one target-owned normalized string set.
// containsExecutionString 报告一个 Target 所有规范化字符串集合中的精确成员关系。
func containsExecutionString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// supportsConversationAudioOutput verifies one callable streaming audio contract and exact file format.
// supportsConversationAudioOutput 校验一个可调用的流式音频合同及精确文件格式。
func supportsConversationAudioOutput(outputs []catalog.MediaOutputCapability, format string) bool {
	for _, output := range outputs {
		if output.Kind != vcp.MediaAudio || output.Level != catalog.CapabilityNative || !output.Delivery.Streaming {
			continue
		}
		if containsExecutionString(output.Formats, format) {
			return true
		}
	}
	return false
}

// isProviderHostedTool reports tool kinds executed by an upstream provider rather than Vulcan Code.
// isProviderHostedTool 表示由上游供应商而非 Vulcan Code 执行的工具类型。
func isProviderHostedTool(kind vcp.ToolKind) bool {
	return kind == vcp.ToolNativeWebSearch || kind == vcp.ToolProviderFileSearch || kind == vcp.ToolProviderCodeInterpreter || kind == vcp.ToolProviderComputerUse
}

// containsHostedTool reports exact legacy membership and the closed standard replacement during migration.
// containsHostedTool 在迁移期间报告精确旧成员关系及其封闭标准替代。
func containsHostedTool(capabilities catalog.ModelCapabilities, target vcp.ToolKind) bool {
	for _, value := range capabilities.HostedTools {
		if value == target {
			return true
		}
	}
	if target == vcp.ToolNativeWebSearch {
		return capabilities.SupportsNativeStandardTool(vcp.StandardModelToolWebSearch)
	}
	return false
}

// validateModelToolSelectionAgainstTarget verifies exact profile support and provider constraints before dispatch.
// validateModelToolSelectionAgainstTarget 在调度前校验精确规格支持与供应商约束。
func validateModelToolSelectionAgainstTarget(operation vcp.ConversationOperation, capabilities catalog.ModelCapabilities, stream bool) error {
	// standardByKind prevents request-time inference from unrelated model capabilities.
	// standardByKind 防止在请求时从无关模型能力推断工具支持。
	standardByKind := make(map[vcp.StandardModelToolKind]catalog.StandardModelToolCapability, len(capabilities.StandardTools))
	for _, capability := range capabilities.StandardTools {
		standardByKind[capability.Kind] = capability
	}
	// enabledStandard records exact dependency satisfaction.
	// enabledStandard 记录精确依赖满足情况。
	enabledStandard := make(map[vcp.StandardModelToolKind]vcp.ModelToolMode, len(operation.ModelTools.Standard))
	for _, selection := range operation.ModelTools.Standard {
		if selection.Mode != vcp.ModelToolDisabled {
			enabledStandard[selection.Kind] = selection.Mode
		}
	}
	for _, selection := range operation.ModelTools.Standard {
		if selection.Mode == vcp.ModelToolDisabled {
			continue
		}
		if selection.Mode == vcp.ModelToolRouter {
			if !callableCapabilityLevel(capabilities.ToolCalling) {
				return vcp.NewModelToolError(vcp.ModelToolModeNotSupported, string(selection.Kind), "validation", false)
			}
			if operation.ToolPolicy.Parallel && !callableCapabilityLevel(capabilities.ParallelToolCalls) {
				return vcp.NewModelToolError(vcp.ModelToolConflictsWithCallerTools, string(selection.Kind), "validation", false)
			}
			continue
		}
		capability, exists := standardByKind[selection.Kind]
		if !exists || !capability.Native {
			return vcp.NewModelToolError(vcp.ModelToolNotSupported, string(selection.Kind), "validation", false)
		}
		for _, requirement := range capability.Requires {
			if enabledStandard[requirement] == vcp.ModelToolDisabled || enabledStandard[requirement] == "" {
				return vcp.NewModelToolError(vcp.ModelToolDependencyMissing, string(selection.Kind), "validation", false)
			}
		}
		if capability.RequiresStreaming && !stream {
			return vcp.NewModelToolError(vcp.ModelToolStreamingRequired, string(selection.Kind), "validation", false)
		}
		if capability.RequiresReasoning && !reasoningEnabled(operation.ReasoningPolicy) {
			return vcp.NewModelToolError(vcp.ModelToolReasoningRequired, string(selection.Kind), "validation", false)
		}
		if !capability.AllowsCallerTools && len(operation.Tools) > 0 {
			return vcp.NewModelToolError(vcp.ModelToolConflictsWithCallerTools, string(selection.Kind), "validation", false)
		}
	}
	// enabledExtra supports exact same-profile dependency validation.
	// enabledExtra 支持精确的同规格依赖校验。
	enabledExtra := make(map[string]struct{}, len(operation.ModelTools.Extra))
	for _, id := range operation.ModelTools.Extra {
		enabledExtra[id] = struct{}{}
	}
	for _, id := range operation.ModelTools.Extra {
		capability, exists := capabilities.ExtraTool(id)
		if !exists {
			return vcp.NewModelToolError(vcp.ModelExtraToolNotSupported, id, "validation", false)
		}
		for _, requirement := range capability.RequiresStandard {
			if enabledStandard[requirement] == vcp.ModelToolDisabled || enabledStandard[requirement] == "" {
				return vcp.NewModelToolError(vcp.ModelToolDependencyMissing, id, "validation", false)
			}
		}
		for _, requirement := range capability.RequiresExtra {
			if _, exists := enabledExtra[requirement]; !exists {
				return vcp.NewModelToolError(vcp.ModelToolDependencyMissing, id, "validation", false)
			}
		}
		if capability.RequiresStreaming && !stream {
			return vcp.NewModelToolError(vcp.ModelToolStreamingRequired, id, "validation", false)
		}
		if capability.RequiresReasoning && !reasoningEnabled(operation.ReasoningPolicy) {
			return vcp.NewModelToolError(vcp.ModelToolReasoningRequired, id, "validation", false)
		}
		if !capability.AllowsCallerTools && len(operation.Tools) > 0 {
			return vcp.NewModelToolError(vcp.ModelToolConflictsWithCallerTools, id, "validation", false)
		}
	}
	for _, extension := range operation.ModelTools.RouterExtensions {
		if !callableCapabilityLevel(capabilities.ToolCalling) {
			return vcp.NewModelToolError(vcp.ModelToolModeNotSupported, string(extension), "validation", false)
		}
		if operation.ToolPolicy.Parallel && !callableCapabilityLevel(capabilities.ParallelToolCalls) {
			return vcp.NewModelToolError(vcp.ModelToolConflictsWithCallerTools, string(extension), "validation", false)
		}
	}
	return nil
}

// reasoningEnabled reports explicit reasoning intent without inferring provider defaults.
// reasoningEnabled 报告显式思考意图且不推断供应商默认值。
func reasoningEnabled(policy vcp.ReasoningPolicy) bool {
	if policy.Enabled != nil {
		return *policy.Enabled
	}
	return policy.Effort != "" && policy.Effort != "none" || policy.BudgetTokens != nil || policy.RequestedSummaryMode() != ""
}

// validateConversationMediaRequest enforces role, placement, interaction mode, and feature-combination declarations for media blocks.
// validateConversationMediaRequest 对媒体块强制执行角色、位置、交互模式与功能组合声明。
func validateConversationMediaRequest(request vcp.ExecutionRequest, capabilities []catalog.MediaInputCapability) error {
	operation := *request.Payload.Conversation
	for _, item := range operation.Context {
		hasText := false
		hasNativeMedia := false
		for _, block := range item.Content {
			if block.Type == vcp.ContentText && strings.TrimSpace(block.Text) != "" {
				hasText = true
			}
			kind, media := mediaKindForContentType(block.Type)
			if !media {
				continue
			}
			if routerExtensionClaimsMedia(operation.ModelTools.RouterExtensions, kind) {
				if item.Kind != vcp.ContextMessage {
					return fmt.Errorf("%w: Router-managed %s input must belong to a message", vcp.ErrInvalidRequest, kind)
				}
				continue
			}
			hasNativeMedia = true
			capability, exists := mediaCapabilityForKind(capabilities, kind)
			if !exists || !callableCapabilityLevel(capability.Level) {
				return fmt.Errorf("%w: selected profile does not support %s input", vcp.ErrInvalidRequest, kind)
			}
			if item.Kind != vcp.ContextMessage || !containsMediaRole(capability.Roles, block.MediaRole) || !containsAuthority(capability.AllowedAuthorities, item.Authority) || !containsPlacement(capability.AllowedPlacements, item.Placement) {
				return fmt.Errorf("%w: %s input role or context location is not supported", vcp.ErrInvalidRequest, kind)
			}
			if errCombination := validateMediaFeatureCombination(operation, request.Stream, capability); errCombination != nil {
				return errCombination
			}
		}
		if !hasNativeMedia {
			continue
		}
		interaction := catalog.MediaInteractionMixedConversation
		if !hasText {
			interaction = catalog.MediaInteractionMediaOnlyConversation
		}
		for _, block := range item.Content {
			kind, media := mediaKindForContentType(block.Type)
			if !media {
				continue
			}
			if routerExtensionClaimsMedia(operation.ModelTools.RouterExtensions, kind) {
				continue
			}
			capability, _ := mediaCapabilityForKind(capabilities, kind)
			if !containsMediaInteraction(capability.InteractionModes, interaction) {
				return fmt.Errorf("%w: selected profile does not support %s", vcp.ErrInvalidRequest, interaction)
			}
			if !hasText && (operation.MediaOnlyMode != vcp.MediaOnlyConversationUseProfilePolicy || capability.MediaOnlyPolicy == catalog.MediaOnlyUnsupported || capability.Compatibility.RequiresText) {
				return fmt.Errorf("%w: media-only conversation requires explicit profile-policy acceptance", vcp.ErrInvalidRequest)
			}
		}
	}
	return nil
}

// routerExtensionClaimsMedia reports whether the request explicitly delegates one media family away from the parent model.
// routerExtensionClaimsMedia 报告请求是否显式将一种媒体类别委托给父模型之外的 Router 增强能力。
func routerExtensionClaimsMedia(extensions []vcp.RouterExtensionKind, kind vcp.MediaKind) bool {
	for _, extension := range extensions {
		if extensionAcceptsMediaKind(extension, kind) {
			return true
		}
	}
	return false
}

// validateMediaAnalyzeRequest enforces the dedicated analysis interaction and declared semantic input roles.
// validateMediaAnalyzeRequest 强制执行专用分析交互与声明的语义输入角色。
func validateMediaAnalyzeRequest(operation vcp.MediaAnalyzeOperation, capabilities []catalog.MediaInputCapability) error {
	for _, input := range operation.Inputs {
		capability, exists := mediaCapabilityForKind(capabilities, input.Kind)
		if !exists || !callableCapabilityLevel(capability.Level) || !containsMediaInteraction(capability.InteractionModes, catalog.MediaInteractionAnalysis) || !containsMediaRole(capability.Roles, input.Role) {
			return fmt.Errorf("%w: selected profile does not support %s analysis with role %s", vcp.ErrInvalidRequest, input.Kind, input.Role)
		}
	}
	return nil
}

// validateMediaFeatureCombination rejects conversation features not declared compatible with one media family.
// validateMediaFeatureCombination 拒绝未声明与某种媒体类别兼容的会话功能。
func validateMediaFeatureCombination(operation vcp.ConversationOperation, stream bool, capability catalog.MediaInputCapability) error {
	if len(operation.Tools) > 0 && !callableCapabilityLevel(capability.Compatibility.ToolCalling) {
		return fmt.Errorf("%w: tool calling is not compatible with selected media input", vcp.ErrInvalidRequest)
	}
	if stream && !callableCapabilityLevel(capability.Compatibility.Streaming) {
		return fmt.Errorf("%w: streaming is not compatible with selected media input", vcp.ErrInvalidRequest)
	}
	// explicitReasoning excludes a pure disable request because disabling cannot invoke a media-incompatible reasoning path.
	// explicitReasoning 排除纯关闭请求，因为关闭推理不会触发与媒体不兼容的推理路径。
	explicitReasoning := operation.ReasoningPolicy.Enabled != nil && *operation.ReasoningPolicy.Enabled || operation.ReasoningPolicy.BudgetTokens != nil || strings.TrimSpace(operation.ReasoningPolicy.Effort) != "" && strings.TrimSpace(operation.ReasoningPolicy.Effort) != "none" || operation.ReasoningPolicy.RequestedSummaryMode() != "" || strings.TrimSpace(operation.ReasoningPolicy.ContinuationID) != ""
	if explicitReasoning && !callableCapabilityLevel(capability.Compatibility.Reasoning) {
		return fmt.Errorf("%w: reasoning is not compatible with selected media input", vcp.ErrInvalidRequest)
	}
	if len(operation.GenerationPolicy.StrictJSONSchema) > 0 && !callableCapabilityLevel(capability.Compatibility.StructuredOutput) {
		return fmt.Errorf("%w: structured output is not compatible with selected media input", vcp.ErrInvalidRequest)
	}
	return nil
}

// mediaKindForContentType maps only registered resource-bearing content variants to their media family.
// mediaKindForContentType 仅将已注册的资源内容变体映射到其媒体类别。
func mediaKindForContentType(contentType vcp.ContentType) (vcp.MediaKind, bool) {
	switch contentType {
	case vcp.ContentImage:
		return vcp.MediaImage, true
	case vcp.ContentAudio:
		return vcp.MediaAudio, true
	case vcp.ContentVideo:
		return vcp.MediaVideo, true
	case vcp.ContentFile:
		return vcp.MediaFile, true
	default:
		return "", false
	}
}

// mediaCapabilityForKind returns the sole validated capability for one media family.
// mediaCapabilityForKind 返回一种媒体类别唯一已验证能力。
func mediaCapabilityForKind(capabilities []catalog.MediaInputCapability, kind vcp.MediaKind) (catalog.MediaInputCapability, bool) {
	for _, capability := range capabilities {
		if capability.Kind == kind {
			return capability, true
		}
	}
	return catalog.MediaInputCapability{}, false
}

// callableCapabilityLevel reports whether a declared combination is executable rather than unknown or unsupported.
// callableCapabilityLevel 报告声明的组合是否可执行而非未知或不支持。
func callableCapabilityLevel(level catalog.CapabilityLevel) bool {
	return level == catalog.CapabilityNative || level == catalog.CapabilityEmulated || level == catalog.CapabilityConditional
}

// containsMediaRole reports exact semantic-role membership.
// containsMediaRole 报告精确语义角色成员关系。
func containsMediaRole(values []vcp.MediaInputRole, target vcp.MediaInputRole) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// containsMediaInteraction reports exact interaction-mode membership.
// containsMediaInteraction 报告精确交互模式成员关系。
func containsMediaInteraction(values []catalog.MediaInteractionMode, target catalog.MediaInteractionMode) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// containsAuthority reports exact VCP authority membership.
// containsAuthority 报告精确 VCP Authority 成员关系。
func containsAuthority(values []vcp.Authority, target vcp.Authority) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// containsPlacement reports exact VCP placement membership.
// containsPlacement 报告精确 VCP Placement 成员关系。
func containsPlacement(values []vcp.Placement, target vcp.Placement) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// validateEmbeddingRequest enforces tasks, representations, dimensions, batch size, and declared media support.
// validateEmbeddingRequest 强制执行任务、表示、维度、批量大小与声明的媒体支持。
func validateEmbeddingRequest(operation vcp.EmbeddingOperation, capabilities catalog.EmbeddingCapabilities) error {
	if !containsEmbeddingTask(capabilities.InputTasks, operation.InputTask) || !containsEmbeddingKind(capabilities.OutputKinds, operation.OutputKind) || !containsEmbeddingEncoding(capabilities.Encodings, operation.Encoding) {
		return fmt.Errorf("%w: embedding task, output kind, or encoding is not supported by the selected profile", vcp.ErrInvalidRequest)
	}
	if capabilities.MaxBatchItems.Known && int64(len(operation.Inputs)) > capabilities.MaxBatchItems.Value {
		return fmt.Errorf("%w: embedding batch exceeds the selected profile limit", vcp.ErrInvalidRequest)
	}
	if operation.Dimensions != nil {
		dimension := *operation.Dimensions
		dimensionAllowed := containsIntValue(capabilities.Dimensions, dimension)
		if capabilities.MinDimensions.Known {
			dimensionAllowed = int64(dimension) >= capabilities.MinDimensions.Value && int64(dimension) <= capabilities.MaxDimensions.Value
		}
		if !dimensionAllowed {
			return fmt.Errorf("%w: embedding dimensions are not selectable by the selected profile", vcp.ErrInvalidRequest)
		}
	}
	for _, input := range operation.Inputs {
		if input.Resource != nil && len(capabilities.ResourceKinds) == 0 {
			return fmt.Errorf("%w: selected embedding profile does not support resource input", vcp.ErrInvalidRequest)
		}
	}
	return nil
}

// validateRerankRequest enforces candidate, truncation, content, and media constraints without rewriting input.
// validateRerankRequest 强制执行候选项、截断、内容与媒体约束且不改写输入。
func validateRerankRequest(operation vcp.RerankOperation, capabilities catalog.RerankCapabilities) error {
	if capabilities.MaxCandidates.Known && int64(len(operation.Candidates)) > capabilities.MaxCandidates.Value {
		return fmt.Errorf("%w: rerank candidates exceed the selected profile limit", vcp.ErrInvalidRequest)
	}
	if !containsRerankTruncation(capabilities.TruncationPolicies, operation.Truncation) || operation.ReturnContent && !capabilities.ReturnContent {
		return fmt.Errorf("%w: rerank truncation or returned content is not supported by the selected profile", vcp.ErrInvalidRequest)
	}
	if operation.Query.Content.Resource != nil && len(capabilities.QueryResourceKinds) == 0 {
		return fmt.Errorf("%w: selected rerank profile does not support resource queries", vcp.ErrInvalidRequest)
	}
	for _, candidate := range operation.Candidates {
		if candidate.Content.Resource != nil && len(capabilities.CandidateResourceKinds) == 0 {
			return fmt.Errorf("%w: selected rerank profile does not support resource candidates", vcp.ErrInvalidRequest)
		}
	}
	return nil
}

// validateProviderResult enforces the operation-specific closed result union before persistence and event emission.
// validateProviderResult 在持久化和事件发出前强制执行操作专属的封闭结果联合体。
func validateProviderResult(request vcp.ExecutionRequest, result provider.ExecutionResult, complete bool) error {
	if _, errUsage := usageObservationForResult(result); errUsage != nil {
		return errUsage
	}
	hasCanonicalResponse := strings.TrimSpace(result.Response.ResponseID) != "" ||
		result.Response.Status != "" ||
		len(result.Response.Items) != 0 ||
		len(result.Response.Citations) != 0 ||
		result.Response.Usage != nil ||
		strings.TrimSpace(result.Response.FinishReason) != "" ||
		strings.TrimSpace(result.Response.ErrorCode) != "" ||
		len(result.Response.Warnings) != 0 ||
		len(result.Events) != 0
	if request.Operation != vcp.OperationConversationRespond && request.Operation != vcp.OperationMediaAnalyze && hasCanonicalResponse {
		return fmt.Errorf("%w: operation returned a foreign canonical response or event history", ErrInvalidProviderResult)
	}
	hasGenerated := len(result.GeneratedResources) > 0
	hasTranscript := result.Transcript != nil
	hasTranscriptions := len(result.Transcriptions) != 0
	hasMusicPreparation := result.MusicCoverPreparation != nil
	hasExtract := result.Extract != nil
	switch request.Operation {
	case vcp.OperationEmbeddingCreate:
		operation := *request.Payload.EmbeddingCreate
		if (complete && len(result.Embeddings) != len(operation.Inputs)) ||
			(!complete && (len(result.Embeddings) == 0 || len(result.Embeddings) > len(operation.Inputs))) ||
			len(result.Rerank) != 0 || result.Search != nil || hasExtract || hasGenerated || hasTranscript || hasTranscriptions || hasMusicPreparation {
			return fmt.Errorf("%w: embedding result union or batch count is invalid", ErrInvalidProviderResult)
		}
		for index, item := range result.Embeddings {
			if item.InputID != operation.Inputs[index].ID || item.Kind != operation.OutputKind || item.Encoding != operation.Encoding {
				return fmt.Errorf("%w: embedding result order or representation differs from the request", ErrInvalidProviderResult)
			}
			if errValidate := item.Validate(); errValidate != nil {
				return fmt.Errorf("%w: %v", ErrInvalidProviderResult, errValidate)
			}
			if operation.Dimensions != nil && item.Dense != nil && item.Dense.Dimensions != *operation.Dimensions {
				return fmt.Errorf("%w: embedding result dimensions differ from the request", ErrInvalidProviderResult)
			}
		}
		return nil
	case vcp.OperationRerankDocuments:
		if len(result.Embeddings) != 0 || result.Search != nil || hasExtract || hasGenerated || hasTranscript || hasTranscriptions || hasMusicPreparation {
			return fmt.Errorf("%w: rerank result union is invalid", ErrInvalidProviderResult)
		}
		if errValidate := request.Payload.RerankDocuments.ValidateResults(result.Rerank); errValidate != nil {
			return fmt.Errorf("%w: %v", ErrInvalidProviderResult, errValidate)
		}
		return nil
	case vcp.OperationSearchWeb:
		if len(result.Embeddings) != 0 || len(result.Rerank) != 0 || result.Search == nil || hasExtract || hasGenerated || hasTranscript || hasTranscriptions || hasMusicPreparation {
			return fmt.Errorf("%w: search result union is invalid", ErrInvalidProviderResult)
		}
		return validateWebSearchResponse(*request.Payload.SearchWeb, *result.Search)
	case vcp.OperationWebExtract:
		if len(result.Embeddings) != 0 || len(result.Rerank) != 0 || result.Search != nil || !hasExtract || hasGenerated || hasTranscript || hasTranscriptions || hasMusicPreparation {
			return fmt.Errorf("%w: web extraction result union is invalid", ErrInvalidProviderResult)
		}
		return validateWebExtractResponse(*result.Extract)
	case vcp.OperationImageGenerate, vcp.OperationImageEdit:
		if !hasGenerated || !generatedKindsAre(result.GeneratedResources, vcp.MediaImage) || len(result.Embeddings) != 0 || len(result.Rerank) != 0 || result.Search != nil || hasExtract || hasTranscript || hasTranscriptions || hasMusicPreparation {
			return fmt.Errorf("%w: image result union is invalid", ErrInvalidProviderResult)
		}
		return validateGeneratedResources(result.GeneratedResources)
	case vcp.OperationVideoGenerate, vcp.OperationVideoEdit, vcp.OperationVideoExtend:
		if len(result.Embeddings) != 0 || len(result.Rerank) != 0 || result.Search != nil || hasTranscript || hasTranscriptions || hasMusicPreparation || hasExtract {
			return fmt.Errorf("%w: video result union is invalid", ErrInvalidProviderResult)
		}
		if complete && (!hasGenerated || !generatedKindsAre(result.GeneratedResources, vcp.MediaVideo)) {
			return fmt.Errorf("%w: completed video result requires video resources", ErrInvalidProviderResult)
		}
		if hasGenerated && !generatedKindsAre(result.GeneratedResources, vcp.MediaVideo) {
			return fmt.Errorf("%w: video result union is invalid", ErrInvalidProviderResult)
		}
		return validateGeneratedResources(result.GeneratedResources)
	case vcp.OperationSpeechSynthesize:
		if !hasGenerated || !generatedSpeechKindsAre(result.GeneratedResources) || len(result.Embeddings) != 0 || len(result.Rerank) != 0 || result.Search != nil || hasTranscript || hasTranscriptions || hasMusicPreparation || hasExtract {
			return fmt.Errorf("%w: speech result union is invalid", ErrInvalidProviderResult)
		}
		return validateGeneratedResources(result.GeneratedResources)
	case vcp.OperationMusicGenerate, vcp.OperationMusicCover:
		if !hasGenerated || !generatedKindsAre(result.GeneratedResources, vcp.MediaAudio) || len(result.Embeddings) != 0 || len(result.Rerank) != 0 || result.Search != nil || hasTranscript || hasTranscriptions || hasMusicPreparation || hasExtract {
			return fmt.Errorf("%w: audio result union is invalid", ErrInvalidProviderResult)
		}
		return validateGeneratedResources(result.GeneratedResources)
	case vcp.OperationMusicCoverPrepare:
		preparation := result.MusicCoverPreparation
		if hasGenerated || hasTranscript || hasTranscriptions || len(result.Embeddings) != 0 || len(result.Rerank) != 0 || result.Search != nil || hasExtract || preparation == nil || strings.TrimSpace(preparation.ProviderHandle) == "" || strings.TrimSpace(preparation.FormattedLyrics) == "" || preparation.AudioDurationSeconds <= 0 || preparation.ExpiresAt.IsZero() || len(preparation.Structure) == 0 {
			return fmt.Errorf("%w: music cover preparation result union is invalid", ErrInvalidProviderResult)
		}
		for _, segment := range preparation.Structure {
			if errSegment := segment.Validate(); errSegment != nil {
				return fmt.Errorf("%w: %v", ErrInvalidProviderResult, errSegment)
			}
		}
		return nil
	case vcp.OperationSpeechTranscribe:
		if hasGenerated || len(result.Embeddings) != 0 || len(result.Rerank) != 0 || result.Search != nil || hasExtract || hasMusicPreparation {
			return fmt.Errorf("%w: speech transcription result union is invalid", ErrInvalidProviderResult)
		}
		return validateTranscriptionResults(*request.Payload.SpeechTranscribe, result)
	case vcp.OperationConversationRespond:
		audioRequested := request.Payload.Conversation.GenerationPolicy.AudioOutput != nil
		if len(result.Embeddings) != 0 || len(result.Rerank) != 0 || result.Search != nil || hasExtract || hasTranscript || hasTranscriptions || hasMusicPreparation || audioRequested != hasGenerated {
			return fmt.Errorf("%w: operation returned a mismatched typed result", ErrInvalidProviderResult)
		}
		if errResponse := validateCanonicalProviderResponse(result.Response, result.Events); errResponse != nil {
			return errResponse
		}
		if hasGenerated {
			if !generatedKindsAre(result.GeneratedResources, vcp.MediaAudio) {
				return fmt.Errorf("%w: conversation audio result union is invalid", ErrInvalidProviderResult)
			}
			return validateGeneratedResources(result.GeneratedResources)
		}
		return nil
	case vcp.OperationMediaAnalyze:
		if hasGenerated || len(result.Embeddings) != 0 || len(result.Rerank) != 0 || result.Search != nil || hasExtract || hasTranscript || hasTranscriptions || hasMusicPreparation {
			return fmt.Errorf("%w: operation returned a mismatched typed result", ErrInvalidProviderResult)
		}
		if errResponse := validateCanonicalProviderResponse(result.Response, result.Events); errResponse != nil {
			return errResponse
		}
		return validateMediaAnalysisResponse(result.Response)
	default:
		if len(result.Embeddings) != 0 || len(result.Rerank) != 0 || result.Search != nil || hasExtract || hasGenerated || hasTranscript || hasTranscriptions || hasMusicPreparation {
			return fmt.Errorf("%w: operation returned a mismatched typed result", ErrInvalidProviderResult)
		}
		return nil
	}
}

// validateCanonicalProviderResponse proves that the published response is the exact deterministic reduction of its semantic events.
// validateCanonicalProviderResponse 证明公开响应正是其语义事件的精确定义性归并结果。
func validateCanonicalProviderResponse(response vcp.Response, events []vcp.Event) error {
	if strings.TrimSpace(response.ResponseID) == "" || len(events) == 0 {
		return fmt.Errorf("%w: canonical response identity or event history is missing", ErrInvalidProviderResult)
	}
	reducer := vcp.NewReducer(response.ResponseID)
	// seenEventIDs rejects replay duplicates inside one provider result while the reducer remains replay-tolerant for external consumers.
	// seenEventIDs 拒绝单次供应商结果内部的重放重复项，同时保留 Reducer 面向外部消费者的重放容错能力。
	seenEventIDs := make(map[string]struct{}, len(events))
	// terminalSeen ensures no semantic fact can appear after the aggregate's successful terminal.
	// terminalSeen 确保聚合结果的成功终态之后不会再出现任何语义事实。
	terminalSeen := false
	for _, event := range events {
		if terminalSeen {
			return fmt.Errorf("%w: canonical response contains an event after its terminal", ErrInvalidProviderResult)
		}
		if _, duplicate := seenEventIDs[event.EventID]; duplicate {
			return fmt.Errorf("%w: canonical response contains a duplicate event identifier", ErrInvalidProviderResult)
		}
		seenEventIDs[event.EventID] = struct{}{}
		if errApply := reducer.Apply(event); errApply != nil {
			return fmt.Errorf("%w: canonical response event history is invalid", ErrInvalidProviderResult)
		}
		terminalSeen = event.Type == vcp.EventResponseCompleted || event.Type == vcp.EventResponseIncomplete
	}
	reduced := reducer.Snapshot()
	if !terminalSeen || reduced.Status != vcp.ResponseCompleted && reduced.Status != vcp.ResponseIncomplete {
		return fmt.Errorf("%w: canonical response is not a successful terminal", ErrInvalidProviderResult)
	}
	reducedJSON, errReduced := json.Marshal(reduced)
	if errReduced != nil {
		return fmt.Errorf("%w: canonical reduced response cannot be encoded", ErrInvalidProviderResult)
	}
	responseJSON, errResponse := json.Marshal(response)
	if errResponse != nil {
		return fmt.Errorf("%w: canonical provider response cannot be encoded", ErrInvalidProviderResult)
	}
	if !bytes.Equal(reducedJSON, responseJSON) {
		return fmt.Errorf("%w: canonical response differs from its semantic event history", ErrInvalidProviderResult)
	}
	return nil
}

// validateWebSearchResponse verifies closed evidence semantics, result identity, ordering, URLs, and request-owned limits.
// validateWebSearchResponse 校验封闭证据语义、结果身份、顺序、URL 与请求方拥有的限制。
func validateWebSearchResponse(operation vcp.WebSearchOperation, response vcp.WebSearchResponse) error {
	if strings.TrimSpace(response.Query) == "" {
		return fmt.Errorf("%w: web search response query is required", ErrInvalidProviderResult)
	}
	if operation.MaxResults != nil && len(response.Results) > *operation.MaxResults {
		return fmt.Errorf("%w: web search returned more results than requested", ErrInvalidProviderResult)
	}
	validKinds := map[vcp.SearchEvidenceKind]struct{}{
		vcp.SearchEvidenceProviderEvent:    {},
		vcp.SearchEvidenceStructuredResult: {},
		vcp.SearchEvidenceCitation:         {},
		vcp.SearchEvidenceProviderContract: {},
	}
	observedKinds := make(map[vcp.SearchEvidenceKind]struct{}, len(response.Evidence.Kinds))
	for _, kind := range response.Evidence.Kinds {
		if _, supported := validKinds[kind]; !supported {
			return fmt.Errorf("%w: web search evidence kind is outside the closed vocabulary", ErrInvalidProviderResult)
		}
		if _, duplicate := observedKinds[kind]; duplicate {
			return fmt.Errorf("%w: web search evidence kinds contain a duplicate", ErrInvalidProviderResult)
		}
		observedKinds[kind] = struct{}{}
	}
	switch response.Evidence.Status {
	case vcp.SearchExecutionConfirmed:
		if len(observedKinds) == 0 {
			return fmt.Errorf("%w: confirmed web search response has no evidence kind", ErrInvalidProviderResult)
		}
	case vcp.SearchExecutionRequestedUnverified, vcp.SearchExecutionNotPerformed:
		if len(observedKinds) != 0 || len(response.Results) != 0 || len(response.Citations) != 0 || len(response.Sources) != 0 {
			return fmt.Errorf("%w: unconfirmed web search response contains observed evidence", ErrInvalidProviderResult)
		}
	default:
		return fmt.Errorf("%w: web search evidence status is outside the closed vocabulary", ErrInvalidProviderResult)
	}
	if operation.EvidenceRequirement == vcp.SearchEvidenceVerified && response.Evidence.Status != vcp.SearchExecutionConfirmed {
		return fmt.Errorf("%w: verified web search request has no confirmed evidence", ErrInvalidProviderResult)
	}
	if len(response.Results) > 0 {
		if _, declared := observedKinds[vcp.SearchEvidenceStructuredResult]; !declared {
			return fmt.Errorf("%w: structured web search results have no matching evidence kind", ErrInvalidProviderResult)
		}
	}
	if len(response.Citations) > 0 || len(response.Sources) > 0 {
		if _, declared := observedKinds[vcp.SearchEvidenceCitation]; !declared {
			return fmt.Errorf("%w: web search citations or sources have no matching evidence kind", ErrInvalidProviderResult)
		}
	}
	for _, query := range response.Queries {
		if strings.TrimSpace(query) == "" {
			return fmt.Errorf("%w: web search response contains an empty observed query", ErrInvalidProviderResult)
		}
	}
	resultIDs := make(map[string]struct{}, len(response.Results))
	for index, result := range response.Results {
		identifier := strings.TrimSpace(result.ID)
		if identifier == "" || result.Rank != index+1 {
			return fmt.Errorf("%w: web search result identity or order is invalid", ErrInvalidProviderResult)
		}
		if _, duplicate := resultIDs[identifier]; duplicate {
			return fmt.Errorf("%w: duplicate web search result identifier", ErrInvalidProviderResult)
		}
		resultIDs[identifier] = struct{}{}
		if _, errURL := transport.ValidateAbsoluteHTTPURL(result.URL); errURL != nil {
			return fmt.Errorf("%w: web search result URL is invalid", ErrInvalidProviderResult)
		}
		if result.ProviderScore != nil && (math.IsNaN(*result.ProviderScore) || math.IsInf(*result.ProviderScore, 0)) {
			return fmt.Errorf("%w: web search provider score is not finite", ErrInvalidProviderResult)
		}
	}
	citationIDs := make(map[string]struct{}, len(response.Citations))
	for _, citation := range response.Citations {
		identifier := strings.TrimSpace(citation.ID)
		if identifier == "" {
			return fmt.Errorf("%w: web search citation identifier is required", ErrInvalidProviderResult)
		}
		if _, duplicate := citationIDs[identifier]; duplicate {
			return fmt.Errorf("%w: duplicate web search citation identifier", ErrInvalidProviderResult)
		}
		citationIDs[identifier] = struct{}{}
		if _, errURL := transport.ValidateAbsoluteHTTPURL(citation.URL); errURL != nil {
			return fmt.Errorf("%w: web search citation URL is invalid", ErrInvalidProviderResult)
		}
		if citation.ResultID != "" {
			if _, exists := resultIDs[citation.ResultID]; !exists {
				return fmt.Errorf("%w: web search citation references an unknown result", ErrInvalidProviderResult)
			}
		}
		hasStart := citation.Location.Start != nil
		hasEnd := citation.Location.End != nil
		if hasStart != hasEnd || (hasStart && (*citation.Location.Start < 0 || *citation.Location.End < *citation.Location.Start)) {
			return fmt.Errorf("%w: web search citation location is invalid", ErrInvalidProviderResult)
		}
	}
	for _, source := range response.Sources {
		if strings.TrimSpace(source.Type) == "" {
			return fmt.Errorf("%w: web search source type is required", ErrInvalidProviderResult)
		}
		if _, errURL := transport.ValidateAbsoluteHTTPURL(source.URL); errURL != nil {
			return fmt.Errorf("%w: web search source URL is invalid", ErrInvalidProviderResult)
		}
	}
	return nil
}

// validateMediaAnalysisResponse verifies that a completed analysis contains model-visible text rather than an empty default response.
// validateMediaAnalysisResponse 校验已完成分析包含模型可见文本而不是空默认响应。
// Parameters: response is the canonical provider conversation reduction used as the analysis result.
// 参数：response 是作为分析结果使用的规范供应商会话归并。
// Returns: nil only for one completed non-empty analysis response.
// 返回：仅对一个已完成且非空的分析响应返回 nil。
func validateMediaAnalysisResponse(response vcp.Response) error {
	if strings.TrimSpace(response.ResponseID) == "" || response.Status != vcp.ResponseCompleted || strings.TrimSpace(response.ErrorCode) != "" || len(response.Items) == 0 {
		return fmt.Errorf("%w: media analysis response is incomplete", ErrInvalidProviderResult)
	}
	for _, item := range response.Items {
		if strings.TrimSpace(item.ItemID) == "" || item.Status != vcp.OutputItemCompleted {
			return fmt.Errorf("%w: media analysis output item is incomplete", ErrInvalidProviderResult)
		}
		for _, block := range item.Content {
			if block.Type == vcp.ContentText && strings.TrimSpace(block.Text) != "" {
				return nil
			}
		}
	}
	return fmt.Errorf("%w: media analysis response contains no text result", ErrInvalidProviderResult)
}

// validateTranscriptionResults enforces the explicit single-result or ordered batch-result contract.
// validateTranscriptionResults 强制执行显式单结果或有序批量结果合同。
func validateTranscriptionResults(operation vcp.SpeechTranscribeOperation, result provider.ExecutionResult) error {
	sources := operation.OrderedSources()
	if len(sources) == 1 {
		if result.Transcript == nil || len(result.Transcriptions) != 0 {
			return fmt.Errorf("%w: single-source transcription requires one transcript", ErrInvalidProviderResult)
		}
		if errTranscript := result.Transcript.Validate(); errTranscript != nil {
			return fmt.Errorf("%w: %v", ErrInvalidProviderResult, errTranscript)
		}
		if operation.CandidateCount > 0 && len(operation.ChannelIDs) <= 1 && len(result.Transcript.Candidates) > operation.CandidateCount {
			return fmt.Errorf("%w: speech transcription returned more candidates than requested", ErrInvalidProviderResult)
		}
		return nil
	}
	if result.Transcript != nil || len(result.Transcriptions) != len(sources) {
		return fmt.Errorf("%w: batch transcription result count differs from the request", ErrInvalidProviderResult)
	}
	for index := range result.Transcriptions {
		item := result.Transcriptions[index]
		if item.InputID != sources[index].ID || item.ResourceID != sources[index].Resource.ResourceID {
			return fmt.Errorf("%w: batch transcription result order or ownership differs from the request", ErrInvalidProviderResult)
		}
		if errValidate := item.Validate(); errValidate != nil {
			return fmt.Errorf("%w: %v", ErrInvalidProviderResult, errValidate)
		}
		if operation.CandidateCount > 0 && len(operation.ChannelIDs) <= 1 && item.Transcript != nil && len(item.Transcript.Candidates) > operation.CandidateCount {
			return fmt.Errorf("%w: batch transcription returned more candidates than requested", ErrInvalidProviderResult)
		}
	}
	return nil
}

// validateWebExtractResponse verifies provider URLs and complete per-item extraction facts.
// validateWebExtractResponse 校验供应商 URL 与完整的逐项提取事实。
func validateWebExtractResponse(response vcp.WebExtractResponse) error {
	if len(response.Results) == 0 && len(response.FailedResults) == 0 {
		return fmt.Errorf("%w: web extraction result is empty", ErrInvalidProviderResult)
	}
	seenURLs := make(map[string]struct{}, len(response.Results)+len(response.FailedResults))
	for _, item := range response.Results {
		operation := vcp.WebExtractOperation{URLs: []string{item.URL}}
		if errURL := operation.Validate(); errURL != nil {
			return fmt.Errorf("%w: web extraction success item is invalid", ErrInvalidProviderResult)
		}
		if _, exists := seenURLs[item.URL]; exists {
			return fmt.Errorf("%w: duplicate web extraction result URL", ErrInvalidProviderResult)
		}
		seenURLs[item.URL] = struct{}{}
	}
	for _, item := range response.FailedResults {
		operation := vcp.WebExtractOperation{URLs: []string{item.URL}}
		if errURL := operation.Validate(); errURL != nil || strings.TrimSpace(item.Error) == "" {
			return fmt.Errorf("%w: web extraction failure item is invalid", ErrInvalidProviderResult)
		}
		if _, exists := seenURLs[item.URL]; exists {
			return fmt.Errorf("%w: duplicate web extraction result URL", ErrInvalidProviderResult)
		}
		seenURLs[item.URL] = struct{}{}
	}
	if response.ResponseTimeSeconds != nil && (math.IsNaN(*response.ResponseTimeSeconds) || math.IsInf(*response.ResponseTimeSeconds, 0) || *response.ResponseTimeSeconds < 0) {
		return fmt.Errorf("%w: web extraction response time is negative", ErrInvalidProviderResult)
	}
	return nil
}

// validateGeneratedResources enforces stable identities and exact-one private acquisition sources before ingestion.
// validateGeneratedResources 在接收前强制执行稳定身份和精确唯一私有获取来源。
func validateGeneratedResources(outputs []provider.GeneratedResource) error {
	seen := make(map[string]struct{}, len(outputs))
	for _, output := range outputs {
		hasData := len(output.Data) > 0
		hasURL := strings.TrimSpace(output.DownloadURL) != ""
		if strings.TrimSpace(output.OutputID) == "" || strings.TrimSpace(output.MIMEType) == "" || hasData == hasURL {
			return fmt.Errorf("%w: generated resource shape is invalid", ErrInvalidProviderResult)
		}
		if _, exists := seen[output.OutputID]; exists {
			return fmt.Errorf("%w: duplicate generated resource output identifier", ErrInvalidProviderResult)
		}
		seen[output.OutputID] = struct{}{}
	}
	return nil
}

// generatedKindsAre reports whether every generated resource has one exact media kind.
// generatedKindsAre 报告每个生成资源是否都具有一个精确媒体类型。
func generatedKindsAre(outputs []provider.GeneratedResource, kind vcp.MediaKind) bool {
	for _, output := range outputs {
		if output.Kind != kind {
			return false
		}
	}
	return true
}

// generatedSpeechKindsAre requires exactly one audio output and permits only optional file artifacts such as subtitles.
// generatedSpeechKindsAre 要求精确一个音频输出，并仅允许字幕等可选文件产物。
func generatedSpeechKindsAre(outputs []provider.GeneratedResource) bool {
	audioCount := 0
	for _, output := range outputs {
		switch output.Kind {
		case vcp.MediaAudio:
			audioCount++
		case vcp.MediaFile:
		default:
			return false
		}
	}
	return audioCount == 1
}

// containsEmbeddingTask reports exact membership in a closed task list.
// containsEmbeddingTask 报告封闭任务列表中的精确成员关系。
func containsEmbeddingTask(values []vcp.EmbeddingInputTask, target vcp.EmbeddingInputTask) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// containsEmbeddingKind reports exact membership in a closed vector-kind list.
// containsEmbeddingKind 报告封闭向量类型列表中的精确成员关系。
func containsEmbeddingKind(values []vcp.EmbeddingVectorKind, target vcp.EmbeddingVectorKind) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// containsEmbeddingEncoding reports exact membership in a closed encoding list.
// containsEmbeddingEncoding 报告封闭编码列表中的精确成员关系。
func containsEmbeddingEncoding(values []vcp.EmbeddingEncoding, target vcp.EmbeddingEncoding) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// containsRerankTruncation reports exact membership in a closed truncation list.
// containsRerankTruncation 报告封闭截断列表中的精确成员关系。
func containsRerankTruncation(values []vcp.RerankTruncation, target vcp.RerankTruncation) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// containsIntValue reports exact membership in an integer list.
// containsIntValue 报告整数列表中的精确成员关系。
func containsIntValue(values []int, target int) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// prepareInputs revalidates and realizes only an explicitly referenced conditional input plan.
// prepareInputs 仅重新校验并实现显式引用的条件输入方案。
func (s *Service) prepareInputs(ctx context.Context, record Record) ([]resource.MaterializedInput, Record, error) {
	if record.Request.InputPlanID == "" {
		return nil, record, nil
	}
	if s.plans == nil || s.materializer == nil {
		return nil, record, fmt.Errorf("%w: input plan execution is unavailable", ErrInvalidExecution)
	}
	preparing := record
	emitCompletedEvent := false
	if record.Status == StatusAccepted || record.Status == StatusWaitingRetry {
		var errTransition error
		preparing, errTransition = s.transition(ctx, record, StatusPreparingInputs, EventInputMaterializationStarted, nil)
		if errTransition != nil {
			return nil, record, errTransition
		}
		emitCompletedEvent = true
	} else if record.Status == StatusPreparingInputs {
		emitCompletedEvent = true
	} else if record.Status != StatusRunning && record.Status != StatusQueued {
		return nil, record, fmt.Errorf("%w: execution status cannot resume input materialization", ErrInvalidExecution)
	}
	plan, errPlan := s.plans.Revalidate(ctx, record.OwnerAPIKeyID, record.Request.InputPlanID)
	if errPlan != nil {
		return nil, preparing, errPlan
	}
	if plan.Operation != record.Operation || !sameTarget(plan.Target, record.Target) {
		return nil, preparing, inputplan.ErrCapabilityChanged
	}
	assignments := make([]resource.ResourceAssignment, len(record.Request.InputPlanResources))
	for index, assignment := range record.Request.InputPlanResources {
		assignments[index] = resource.ResourceAssignment{InputID: assignment.InputID, ResourceID: assignment.ResourceID}
	}
	materialized, errMaterialize := s.materializer.Materialize(ctx, record.OwnerAPIKeyID, plan.FrozenMaterializationPlan(), assignments)
	if errMaterialize != nil {
		return nil, preparing, errMaterialize
	}
	if !emitCompletedEvent {
		return materialized, preparing, nil
	}
	completed, errCompleted := s.appendLifecycle(ctx, preparing, EventInputMaterializationCompleted)
	if errCompleted != nil {
		return nil, preparing, errCompleted
	}
	return materialized, completed, nil
}

// startTask creates one asynchronous provider task and durably freezes its complete affinity.
// startTask 创建一个异步供应商任务并持久冻结其完整亲和性。
func (s *Service) startTask(ctx context.Context, record Record, binding transport.Binding, definition providerconfig.ProviderDefinition, materialized []resource.MaterializedInput) (Record, bool, error) {
	taskExecutor, ok := s.providers.(ProviderTaskExecutor)
	if !ok {
		failed, errFail := s.fail(ctx, record, "provider_task_driver_unavailable", false)
		return failed, false, errFail
	}
	excludedCredentials := make([]string, 0, maxSameProviderExecutionAttempts)
	excludedEndpoints := make([]string, 0, maxSameProviderExecutionAttempts)
	cycleAttempts := maximumCycleAttempts(record)
	if record.Request.Budget.MaxProviderTasks != nil {
		remainingTasks := *record.Request.Budget.MaxProviderTasks - len(record.Attempts)
		if remainingTasks < cycleAttempts {
			cycleAttempts = remainingTasks
		}
	}
	if cycleAttempts <= 0 {
		failed, errFail := s.fail(ctx, record, "provider_task_budget_exceeded", false)
		return failed, false, errFail
	}
	for attemptIndex := 0; attemptIndex < cycleAttempts; attemptIndex++ {
		providerRequest := providerRequestForRecord(record, binding, definition, materialized, nil, nil)
		startedAt := s.options.Now().UTC()
		result, errStart := taskExecutor.StartTask(ctx, providerRequest)
		endedAt := s.options.Now().UTC()
		acceptedByProvider := taskResultHasAcceptedState(result)
		attempt := Attempt{Sequence: uint32(len(record.Attempts) + 1), Target: record.Target, StartedAt: startedAt, EndedAt: endedAt, SemanticOutput: acceptedByProvider}
		if errStart != nil {
			classified, classifiedOK := s.classifyAndRecordFailure(ctx, providerRequest, errStart)
			if classifiedOK {
				attempt.FailureCategory = classified.Category
				attempt.RetryAction = classified.Action
			}
			nextTarget, retry := s.resolveRetryTarget(ctx, record, classified, classifiedOK, acceptedByProvider, materialized, nil, &excludedCredentials, &excludedEndpoints)
			if retry && attemptIndex+1 < cycleAttempts {
				updated, errPersist := s.persistAttempt(ctx, record, attempt, &nextTarget)
				if errPersist != nil {
					return Record{}, false, errPersist
				}
				binding, definition, errStart = s.loadBinding(ctx, nextTarget)
				if errStart != nil {
					failed, errFail := s.fail(ctx, updated, stableFailureCode(errStart), retryableFailure(errStart))
					return failed, false, errFail
				}
				record = updated
				continue
			}
			updated, errPersist := s.persistAttempt(ctx, record, attempt, nil)
			if errPersist != nil {
				return Record{}, false, errPersist
			}
			if scheduled, didSchedule, errSchedule := s.scheduleRetry(ctx, updated, classified, classifiedOK, acceptedByProvider); errSchedule != nil {
				return Record{}, false, errSchedule
			} else if didSchedule {
				return scheduled, false, nil
			}
			failed, errFail := s.failClassified(ctx, updated, stableFailureCode(errStart), retryableFailure(errStart) || classifiedRetryable(classified, classifiedOK), classified, classifiedOK)
			return failed, false, errFail
		}
		if errResult := result.Validate(); errResult != nil {
			attempt.FailureCategory = "invalid_provider_task_result"
			updated, errPersist := s.persistAttempt(ctx, record, attempt, nil)
			if errPersist != nil {
				return Record{}, false, errPersist
			}
			failed, errFail := s.fail(ctx, updated, stableFailureCode(errResult), false)
			return failed, false, errFail
		}
		attempt.Succeeded = true
		record.Attempts = append(record.Attempts, attempt)
		record.ProviderTask = &ProviderTaskSnapshot{ProviderTaskID: result.ProviderTaskID, Target: binding.Target, Definition: definition, Endpoint: binding.Endpoint, Credential: binding.Credential, PollAfter: result.PollAfter}
		updated, errApply := s.applyTaskResult(ctx, record, result)
		return updated, false, errApply
	}
	return Record{}, false, fmt.Errorf("%w: same-provider task-attempt limit reached", ErrInvalidExecution)
}

// taskResultHasAcceptedState reports whether an errored task start already exposed provider-owned state.
// taskResultHasAcceptedState 表示失败的任务创建是否已经暴露供应商拥有状态。
func taskResultHasAcceptedState(result provider.TaskResult) bool {
	return strings.TrimSpace(result.ProviderTaskID) != "" || result.State != "" || !result.PollAfter.IsZero() || result.Result != nil || result.ErrorCode != ""
}

// RunRecovery polls due persisted provider tasks until shutdown without changing their target affinity.
// RunRecovery 在关闭前轮询到期持久化供应商任务且不改变其 Target 亲和性。
func (s *Service) RunRecovery(ctx context.Context, interval time.Duration) error {
	if ctx == nil || interval <= 0 {
		return fmt.Errorf("%w: recovery context and positive interval are required", ErrInvalidExecution)
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if errRecover := s.RecoverOnce(ctx); errRecover != nil && !errors.Is(errRecover, context.Canceled) {
			return errRecover
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// RecoverOnce polls every due provider task once using only its persisted snapshots.
// RecoverOnce 仅使用持久化快照对每个到期供应商任务轮询一次。
func (s *Service) RecoverOnce(ctx context.Context) error {
	records, errList := s.store.ListRecoverable(ctx)
	if errList != nil {
		return errList
	}
	taskExecutor, taskExecutionSupported := s.providers.(ProviderTaskExecutor)
	for _, record := range records {
		now := s.options.Now().UTC()
		if s.executionActive(record.ID) || !recoveryDue(record, now) {
			continue
		}
		_, errRecover := s.withExecutionLease(ctx, record.ID, s.workerID, func(leaseContext context.Context) error {
			return s.recoverRecordOnce(leaseContext, record, taskExecutor, taskExecutionSupported, now)
		})
		if errRecover != nil && !errors.Is(errRecover, ErrRevisionConflict) {
			return errRecover
		}
	}
	return nil
}

// recoveryDue avoids lease traffic for records whose provider or retry schedule is not ready.
// recoveryDue 避免为供应商或重试计划尚未到期的记录产生租约流量。
func recoveryDue(record Record, now time.Time) bool {
	if !record.ExpiresAt.After(now) || executionBudgetExpired(record, now) {
		return true
	}
	if record.Status == StatusWaitingRetry && record.Retry != nil && record.Retry.NextRetryAt.After(now) {
		return false
	}
	if record.ProviderTask != nil && record.ProviderTask.CancellationRequestedAt != nil {
		return !record.ProviderTask.CancellationAfter.After(now)
	}
	return record.ProviderTask == nil || !record.ProviderTask.PollAfter.After(now)
}

// recoverRecordOnce applies one due recovery observation while its caller owns the execution lease.
// recoverRecordOnce 在调用方拥有执行租约时应用一次到期恢复观测。
func (s *Service) recoverRecordOnce(ctx context.Context, record Record, taskExecutor ProviderTaskExecutor, taskExecutionSupported bool, now time.Time) error {
	if !record.ExpiresAt.After(now) {
		if _, errExpire := s.transition(ctx, record, StatusExpired, EventExecutionExpired, nil); errExpire != nil && !errors.Is(errExpire, ErrRevisionConflict) {
			return errExpire
		}
		return nil
	}
	if executionBudgetExpired(record, now) {
		if _, errFail := s.fail(ctx, record, "execution_time_budget_exceeded", false); errFail != nil && !errors.Is(errFail, ErrRevisionConflict) {
			return errFail
		}
		return nil
	}
	if record.Status == StatusWaitingRetry {
		if record.Retry == nil {
			return fmt.Errorf("%w: waiting retry has no durable schedule", ErrInvalidExecution)
		}
		if record.Retry.NextRetryAt.After(now) {
			return nil
		}
		var errStarted error
		record, errStarted = s.appendRetryEvent(ctx, record, EventRetryStarted, uint32(len(record.Attempts)+1), nil, record.Retry.Category)
		if errStarted != nil {
			if errors.Is(errStarted, ErrRevisionConflict) {
				return nil
			}
			return errStarted
		}
	}
	if record.ProviderTask == nil {
		if _, _, errExecute := s.execute(ctx, record); errExecute != nil && !errors.Is(errExecute, ErrRevisionConflict) {
			return errExecute
		}
		return nil
	}
	if !taskExecutionSupported {
		return fmt.Errorf("%w: persisted provider task has no registered task executor", ErrInvalidExecution)
	}
	if record.ProviderTask.CancellationRequestedAt != nil {
		if record.ProviderTask.CancellationAfter.After(now) {
			return nil
		}
		_, deferred, errCancel := s.cancelProviderTaskOnce(ctx, record, taskExecutor)
		if errCancel != nil && !deferred && !errors.Is(errCancel, ErrRevisionConflict) {
			return errCancel
		}
		return nil
	}
	if record.ProviderTask.PollAfter.After(now) {
		return nil
	}
	providerRequest := taskExecutionRequest(record)
	result, errPoll := taskExecutor.PollTask(ctx, providerRequest, record.ProviderTask.ProviderTaskID)
	if errPoll != nil {
		s.classifyAndRecordFailure(ctx, providerRequest, errPoll)
		record.ProviderTask.PollAttempts++
		record.ProviderTask.PollAfter = now.Add(taskPollBackoff(record.ProviderTask.PollAttempts))
		if _, errSave := s.saveTaskObservation(ctx, record); errSave != nil && !errors.Is(errSave, ErrRevisionConflict) {
			return errSave
		}
		return nil
	}
	if _, errApply := s.applyTaskResult(ctx, record, result); errApply != nil && !errors.Is(errApply, ErrRevisionConflict) {
		return errApply
	}
	return nil
}

// cancelProviderTaskOnce performs one upstream cancellation attempt after durable intent and preserves restart backoff on failure.
// cancelProviderTaskOnce 在持久化意图后执行一次上游取消尝试，并在失败时保留可重启退避状态。
func (s *Service) cancelProviderTaskOnce(ctx context.Context, record Record, taskExecutor ProviderTaskExecutor) (Record, bool, error) {
	if record.ProviderTask == nil || record.ProviderTask.CancellationRequestedAt == nil {
		return Record{}, false, fmt.Errorf("%w: provider task cancellation intent is required", ErrInvalidExecution)
	}
	providerRequest := taskExecutionRequest(record)
	record.ProviderTask.CancellationAttempts++
	record.ProviderTask.CancellationAfter = s.options.Now().UTC().Add(taskPollBackoff(record.ProviderTask.CancellationAttempts))
	result, errCancel := taskExecutor.CancelTask(ctx, providerRequest, record.ProviderTask.ProviderTaskID)
	if errCancel != nil {
		s.classifyAndRecordFailure(ctx, providerRequest, errCancel)
		persisted, errSave := s.saveTaskObservation(context.WithoutCancel(ctx), record)
		if errSave != nil {
			return Record{}, false, errSave
		}
		return persisted, true, errCancel
	}
	updated, errApply := s.applyTaskResult(ctx, record, result)
	return updated, false, errApply
}

// withExecutionLease acquires, heartbeats, and releases one optional execution-owner lease.
// withExecutionLease 获取、续约并释放一个可选的执行所有者租约。
func (s *Service) withExecutionLease(ctx context.Context, executionID string, ownerID string, run func(context.Context) error) (bool, error) {
	if s.leases == nil {
		return true, run(ctx)
	}
	now := s.options.Now().UTC()
	acquired, errAcquire := s.leases.AcquireLease(ctx, executionID, ownerID, now, now.Add(s.leaseTTL))
	if errAcquire != nil || !acquired {
		return acquired, errAcquire
	}
	leaseContext, cancelLease := context.WithCancel(ctx)
	heartbeatResult := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(s.leaseTTL / 3)
		defer ticker.Stop()
		for {
			select {
			case <-leaseContext.Done():
				heartbeatResult <- nil
				return
			case <-ticker.C:
				renewedAt := s.options.Now().UTC()
				renewed, errRenew := s.leases.RenewLease(leaseContext, executionID, ownerID, renewedAt, renewedAt.Add(s.leaseTTL))
				if errRenew != nil {
					heartbeatResult <- errRenew
					cancelLease()
					return
				}
				if !renewed {
					heartbeatResult <- fmt.Errorf("%w: execution recovery lease was lost", ErrRevisionConflict)
					cancelLease()
					return
				}
			}
		}
	}()
	errRun := run(leaseContext)
	cancelLease()
	errHeartbeat := <-heartbeatResult
	errRelease := s.leases.ReleaseLease(context.WithoutCancel(ctx), executionID, ownerID)
	if errRun != nil {
		return true, errRun
	}
	if errHeartbeat != nil {
		return true, errHeartbeat
	}
	return true, errRelease
}

// taskPollBackoff returns a bounded deterministic delay after an upstream poll transport failure.
// taskPollBackoff 在上游轮询传输失败后返回一个有界确定性延迟。
func taskPollBackoff(attempts uint32) time.Duration {
	shift := attempts
	if shift > 4 {
		shift = 4
	}
	return time.Duration(1<<shift) * time.Second
}

// applyTaskResult commits one provider-confirmed task observation without inventing progress.
// applyTaskResult 提交一个供应商确认任务观测且不虚构进度。
func (s *Service) applyTaskResult(ctx context.Context, record Record, result provider.TaskResult) (Record, error) {
	if record.ProviderTask == nil || record.ProviderTask.ProviderTaskID != result.ProviderTaskID {
		return Record{}, fmt.Errorf("%w: provider task affinity changed", ErrInvalidExecution)
	}
	record.ProviderTask.PollAttempts++
	record.ProviderTask.PollAfter = result.PollAfter
	switch result.State {
	case provider.TaskQueued:
		if record.Status == StatusQueued {
			return s.saveTaskObservation(ctx, record)
		}
		return s.transition(ctx, record, StatusQueued, EventExecutionQueued, nil)
	case provider.TaskRunning:
		if record.Status == StatusRunning {
			return s.saveTaskObservation(ctx, record)
		}
		return s.transition(ctx, record, StatusRunning, EventExecutionRunning, nil)
	case provider.TaskSucceeded:
		s.recordSuccessfulRequest(ctx, taskExecutionRequest(record))
		if record.Status != StatusRunning {
			var errRunning error
			record, errRunning = s.transition(ctx, record, StatusRunning, EventExecutionRunning, nil)
			if errRunning != nil {
				return Record{}, errRunning
			}
		}
		if errResult := validateProviderResult(record.Request, *result.Result, true); errResult != nil {
			return s.fail(ctx, record, stableFailureCode(errResult), false)
		}
		attachUsageToLastAttempt(&record, *result.Result)
		resources, errResources := s.ingestGeneratedResources(ctx, record, result.Result.GeneratedResources)
		if errResources != nil {
			return s.fail(ctx, record, stableFailureCode(errResources), retryableFailure(errResources))
		}
		completed, _, errSuccess := s.succeedWithStatus(ctx, record, *result.Result, resources, StatusSucceeded, EventExecutionSucceeded)
		return completed, errSuccess
	case provider.TaskPartiallySucceeded:
		s.recordSuccessfulRequest(ctx, taskExecutionRequest(record))
		if record.Status != StatusRunning {
			var errRunning error
			record, errRunning = s.transition(ctx, record, StatusRunning, EventExecutionRunning, nil)
			if errRunning != nil {
				return Record{}, errRunning
			}
		}
		if errResult := validateProviderResult(record.Request, *result.Result, false); errResult != nil {
			return s.fail(ctx, record, stableFailureCode(errResult), false)
		}
		attachUsageToLastAttempt(&record, *result.Result)
		resources, errResources := s.ingestGeneratedResources(ctx, record, result.Result.GeneratedResources)
		if errResources != nil {
			return s.fail(ctx, record, stableFailureCode(errResources), retryableFailure(errResources))
		}
		completed, _, errSuccess := s.succeedWithStatus(ctx, record, *result.Result, resources, StatusPartiallySucceeded, EventExecutionPartiallySucceeded)
		return completed, errSuccess
	case provider.TaskFailed:
		return s.fail(ctx, record, result.ErrorCode, result.Retryable)
	case provider.TaskCancelled:
		return s.transition(ctx, record, StatusCancelled, EventExecutionCancelled, nil)
	default:
		return Record{}, fmt.Errorf("%w: unknown provider task state", ErrInvalidExecution)
	}
}

// attachUsageToLastAttempt associates terminal task usage with the exact accepted provider attempt.
// attachUsageToLastAttempt 将终态任务用量关联到精确的已接受供应商尝试。
func attachUsageToLastAttempt(record *Record, result provider.ExecutionResult) {
	if record == nil || len(record.Attempts) == 0 {
		return
	}
	usage, errUsage := usageObservationForResult(result)
	if errUsage == nil {
		record.Attempts[len(record.Attempts)-1].Usage = usage
	}
}

// saveTaskObservation persists changed polling facts without emitting a false semantic progress event.
// saveTaskObservation 持久化变化的轮询事实且不发布虚假语义进度事件。
func (s *Service) saveTaskObservation(ctx context.Context, record Record) (Record, error) {
	expectedRevision := record.Revision
	record.UpdatedAt = s.options.Now().UTC()
	record.Revision++
	if errSave := s.store.Save(ctx, record, expectedRevision, nil); errSave != nil {
		return Record{}, errSave
	}
	return record, nil
}

// taskExecutionRequest rebuilds a provider request solely from persisted immutable task snapshots.
// taskExecutionRequest 仅从持久化不可变任务快照重建供应商请求。
func taskExecutionRequest(record Record) provider.ExecutionRequest {
	task := record.ProviderTask
	return providerRequestForRecord(record, transport.Binding{Target: task.Target, Endpoint: task.Endpoint, Credential: task.Credential}, task.Definition, nil, nil, nil)
}

// providerRequestForRecord builds one provider request with a Router-owned replay-stable idempotency identity.
// providerRequestForRecord 使用 Router 所有且重放稳定的幂等身份构建供应商请求。
// Parameters: record owns the immutable public request and execution identity; binding, definition, inputs, and workflow freeze the exact upstream target.
// 参数：record 拥有不可变公开请求与执行身份；binding、definition、inputs 与 workflow 冻结精确上游目标。
// Returns: a provider request whose private execution copy never forwards the caller's idempotency key upstream.
// 返回：一个使用私有执行副本且绝不向上游转发调用方幂等键的供应商请求。
func providerRequestForRecord(record Record, binding transport.Binding, definition providerconfig.ProviderDefinition, materialized []resource.MaterializedInput, workflow *provider.PreparedWorkflowBinding, continuation *provider.ContinuationBinding) provider.ExecutionRequest {
	request := providerFacingExecutionRequest(record.Request)
	request.IdempotencyKey = providerDispatchIdempotencyKey(record)
	applyNativeModelToolDefinitions(&request)
	applyRouterToolDefinitions(&request, record.ModelToolPlan)
	applyProviderToolChoice(&request)
	providerInputs := withholdRouterManagedMedia(&request, record.ModelToolPlan, materialized)
	return provider.ExecutionRequest{Binding: binding, Definition: definition, Execution: &request, MaterializedInputs: providerInputs, LineageID: record.ID, Now: record.UpdatedAt, PreparedWorkflow: workflow, Continuation: continuation}
}

// providerDispatchIdempotencyKey returns one replay-stable identity for the current semantic parent round.
// providerDispatchIdempotencyKey 为当前语义父轮次返回一个重放稳定身份。
func providerDispatchIdempotencyKey(record Record) string {
	if record.CompletedRouterToolRounds == 0 {
		return record.ID
	}
	return routerChildIdentifier("parent_round", record.ID, "", record.CompletedRouterToolRounds)
}

// applyProviderToolChoice removes every provider-visible tool when the caller explicitly disables tool use.
// applyProviderToolChoice 在调用方显式关闭工具使用时移除每个供应商可见工具。
func applyProviderToolChoice(request *vcp.ExecutionRequest) {
	if request == nil || request.Payload.Conversation == nil || request.Payload.Conversation.ToolPolicy.Choice != vcp.ToolChoiceNone {
		return
	}
	request.Payload.Conversation.Tools = nil
	request.Payload.Conversation.ModelTools = vcp.ModelToolSelection{}
}

// applyNativeModelToolDefinitions projects authoritative standard-tool selections into the existing provider adapter contract.
// applyNativeModelToolDefinitions 将权威标准工具选择投影到现有供应商适配器合同。
func applyNativeModelToolDefinitions(request *vcp.ExecutionRequest) {
	if request == nil || request.Operation != vcp.OperationConversationRespond || request.Payload.Conversation == nil {
		return
	}
	operation := request.Payload.Conversation
	// webSearchSelection is present only when the new model_tools contract explicitly owns the legacy search projection.
	// webSearchSelection 仅在新的 model_tools 合同明确拥有旧搜索投影时存在。
	var webSearchSelection *vcp.StandardModelToolSelection
	for index := range operation.ModelTools.Standard {
		if operation.ModelTools.Standard[index].Kind == vcp.StandardModelToolWebSearch {
			webSearchSelection = &operation.ModelTools.Standard[index]
			break
		}
	}
	if webSearchSelection == nil {
		return
	}
	filtered := make([]vcp.ToolDefinition, 0, len(operation.Tools)+1)
	for _, tool := range operation.Tools {
		if tool.Kind != vcp.ToolNativeWebSearch {
			filtered = append(filtered, tool)
		}
	}
	if webSearchSelection.Mode == vcp.ModelToolNative {
		filtered = append(filtered, vcp.ToolDefinition{Kind: vcp.ToolNativeWebSearch, Name: "web_search"})
	}
	operation.Tools = filtered
}

// providerFacingExecutionRequest isolates every conversation field mutated only for provider dispatch.
// providerFacingExecutionRequest 隔离仅为供应商分派而修改的全部会话字段。
func providerFacingExecutionRequest(source vcp.ExecutionRequest) vcp.ExecutionRequest {
	cloned := source
	if source.Payload.Conversation == nil {
		return cloned
	}
	conversation := *source.Payload.Conversation
	conversation.Tools = append([]vcp.ToolDefinition(nil), source.Payload.Conversation.Tools...)
	conversation.Context = make([]vcp.ContextItem, len(source.Payload.Conversation.Context))
	for index, item := range source.Payload.Conversation.Context {
		conversation.Context[index] = item
		conversation.Context[index].Content = append([]vcp.ContentBlock(nil), item.Content...)
	}
	cloned.Payload.Conversation = &conversation
	return cloned
}

// requiresProviderTask reports an async-only model execution contract.
// requiresProviderTask 表示仅异步模型执行合同。
func requiresProviderTask(target resolve.Target) bool {
	return target.SubjectKind == resolve.ExecutionSubjectModel && target.ModelCapabilities.Delivery.Asynchronous && !target.ModelCapabilities.Delivery.Synchronous
}

// requestedContinuationID returns the sole Router continuation reference carried by a conversation request.
// requestedContinuationID 返回会话请求携带的唯一 Router 续接引用。
func requestedContinuationID(request vcp.ExecutionRequest) string {
	if request.Operation != vcp.OperationConversationRespond || request.Payload.Conversation == nil {
		return ""
	}
	operation := request.Payload.Conversation
	if operation.ReasoningPolicy.ContinuationID != "" {
		return operation.ReasoningPolicy.ContinuationID
	}
	if operation.RemoteCompaction != nil {
		return operation.RemoteCompaction.PreviousResponseID
	}
	return ""
}

// resolveRequestedContinuation loads one owner-scoped protected response and verifies its complete immutable affinity before dispatch.
// resolveRequestedContinuation 在分派前加载一个所有者作用域受保护响应并校验其完整不可变亲和性。
func (s *Service) resolveRequestedContinuation(ctx context.Context, ownerAPIKeyID string, request vcp.ExecutionRequest, now time.Time) (*provider.ContinuationBinding, error) {
	continuationID := requestedContinuationID(request)
	if continuationID == "" {
		return nil, nil
	}
	if request.Target.Model == nil || request.Target.Model.Target != vcp.ModelTargetExact {
		return nil, fmt.Errorf("%w: continuation replay requires exact model selection", vcp.ErrInvalidRequest)
	}
	source, errSource := s.store.Get(ctx, ownerAPIKeyID, continuationID)
	if errSource != nil {
		return nil, fmt.Errorf("%w: continuation is unavailable", vcp.ErrInvalidRequest)
	}
	continuation := source.ProviderContinuation
	if source.Status != StatusSucceeded || continuation == nil || source.Result == nil || source.Result.Continuation == nil || source.Result.Continuation.ContinuationID != continuationID {
		return nil, fmt.Errorf("%w: continuation is expired or incomplete", vcp.ErrInvalidRequest)
	}
	if !continuation.InvalidatedAt.IsZero() {
		return nil, fmt.Errorf("%w: continuation is invalidated", vcp.ErrInvalidRequest)
	}
	if !continuation.ExpiresAt.After(now) {
		if errInvalidate := s.updateContinuationState(ctx, ownerAPIKeyID, continuationID, now, false, ContinuationInvalidatedExpired); errInvalidate != nil {
			return nil, errors.Join(fmt.Errorf("%w: continuation is expired", vcp.ErrInvalidRequest), fmt.Errorf("record continuation expiry: %w", errInvalidate))
		}
		return nil, fmt.Errorf("%w: continuation is expired", vcp.ErrInvalidRequest)
	}
	selection := request.Target.Model
	if selection.ProviderInstanceID != continuation.Target.ProviderInstanceID || selection.ProviderModelID != continuation.Target.ProviderModelID || selection.ExecutionProfileID != "" && selection.ExecutionProfileID != continuation.Target.ExecutionProfileID {
		return nil, fmt.Errorf("%w: continuation belongs to a different model target", vcp.ErrInvalidRequest)
	}
	binding := &provider.ContinuationBinding{
		ContinuationID:       continuationID,
		ProviderDefinitionID: continuation.Target.ProviderDefinitionID,
		ProviderInstanceID:   continuation.Target.ProviderInstanceID,
		ChannelID:            continuation.Target.ChannelID,
		EndpointID:           continuation.Target.EndpointID,
		CredentialID:         continuation.Target.CredentialID,
		ProviderModelID:      continuation.Target.ProviderModelID,
		UpstreamModelID:      continuation.Target.UpstreamModelID,
		ExecutionProfileID:   continuation.Target.ExecutionProfileID,
		UpstreamResponseID:   continuation.UpstreamResponseID,
	}
	if errBinding := binding.Validate(continuation.Target); errBinding != nil {
		return nil, fmt.Errorf("%w: continuation affinity is invalid", vcp.ErrInvalidRequest)
	}
	return binding, nil
}

// updateContinuationState durably touches or invalidates one owner-scoped continuation through bounded optimistic retries.
// updateContinuationState 通过有界乐观重试持久更新或失效一个所有者作用域续接。
func (s *Service) updateContinuationState(ctx context.Context, ownerAPIKeyID string, continuationID string, observedAt time.Time, markUsed bool, reason ContinuationInvalidationReason) error {
	if markUsed == (reason != "") || observedAt.IsZero() {
		return fmt.Errorf("%w: continuation state update requires exactly one outcome and a time", ErrInvalidExecution)
	}
	for attempt := 0; attempt < maxSameProviderExecutionAttempts; attempt++ {
		source, errSource := s.store.Get(ctx, ownerAPIKeyID, continuationID)
		if errSource != nil {
			return errSource
		}
		if source.ProviderContinuation == nil {
			return fmt.Errorf("%w: continuation state is absent", ErrInvalidExecution)
		}
		continuation := source.ProviderContinuation
		if !continuation.InvalidatedAt.IsZero() {
			if !markUsed && continuation.InvalidationReason == reason {
				return nil
			}
			return fmt.Errorf("%w: continuation is already invalidated", vcp.ErrInvalidRequest)
		}
		effectiveTime := observedAt.UTC()
		if effectiveTime.Before(source.UpdatedAt) {
			effectiveTime = source.UpdatedAt
		}
		if markUsed {
			continuation.LastUsedAt = effectiveTime
		} else {
			continuation.InvalidatedAt = effectiveTime
			continuation.InvalidationReason = reason
		}
		expectedRevision := source.Revision
		source.UpdatedAt = effectiveTime
		source.Revision++
		if errSave := s.store.Save(ctx, source, expectedRevision, nil); errSave != nil {
			if errors.Is(errSave, ErrRevisionConflict) {
				continue
			}
			return errSave
		}
		return nil
	}
	return ErrRevisionConflict
}

// continuationTargetPermanentlyUnavailable reports only explicit catalog or configuration facts that revoke exact affinity.
// continuationTargetPermanentlyUnavailable 仅报告会撤销精确亲和性的明确目录或配置事实。
func continuationTargetPermanentlyUnavailable(errValue error) bool {
	return errors.Is(errValue, providerconfig.ErrNotFound) || errors.Is(errValue, catalog.ErrSnapshotNotFound) || errors.Is(errValue, resolve.ErrInstanceNotExecutable) || errors.Is(errValue, resolve.ErrModelNotFound) || errors.Is(errValue, resolve.ErrModelDisabled) || errors.Is(errValue, resolve.ErrProfileNotFound) || errors.Is(errValue, resolve.ErrNoEligibleTarget)
}

// resolveTarget maps the exact closed target selection into one resolver request.
// resolveTarget 将精确封闭 Target 选择映射为一个解析请求。
func (s *Service) resolveTarget(ctx context.Context, request vcp.ExecutionRequest, now time.Time, continuation *provider.ContinuationBinding, excludedCredentialIDs ...string) (resolve.Target, error) {
	resolution := resolve.Request{Operation: request.Operation, Now: now, ExcludedCredentialIDs: append([]string(nil), excludedCredentialIDs...)}
	if continuation != nil {
		resolution.RequiredCredentialID = continuation.CredentialID
		resolution.RequiredEndpointID = continuation.EndpointID
	}
	return s.resolveTargetWithRequest(ctx, request, resolution)
}

// resolveTargetWithRequest completes one constrained same-provider resolution request from the immutable VCP selection.
// resolveTargetWithRequest 从不可变 VCP 选择补全一次受约束的同供应商解析请求。
func (s *Service) resolveTargetWithRequest(ctx context.Context, request vcp.ExecutionRequest, resolution resolve.Request) (resolve.Target, error) {
	if request.Target.Model != nil {
		resolution.ProviderInstanceID = request.Target.Model.ProviderInstanceID
		resolution.ProviderModelID = request.Target.Model.ProviderModelID
		resolution.ExecutionProfileID = request.Target.Model.ExecutionProfileID
		resolution.RequiredRegion = request.Target.Model.RequiredRegion
	} else {
		resolution.ProviderInstanceID = request.Target.Service.ProviderInstanceID
		resolution.ProviderServiceID = request.Target.Service.ProviderServiceID
		resolution.ServiceOfferingID = request.Target.Service.ServiceOfferingID
		resolution.ExecutionProfileID = request.Target.Service.ExecutionProfileID
	}
	target, _, errResolve := s.resolver.Resolve(ctx, resolution)
	return target, errResolve
}

// resolveRetryTarget chooses another endpoint or credential only within the original provider instance and subject.
// resolveRetryTarget 仅在原始供应商实例与主体内选择另一个入口或凭据。
func (s *Service) resolveRetryTarget(ctx context.Context, record Record, classified provider.ClassifiedError, classifiedOK bool, semanticOutput bool, materialized []resource.MaterializedInput, preparedWorkflow *provider.PreparedWorkflowBinding, excludedCredentials *[]string, excludedEndpoints *[]string) (resolve.Target, bool) {
	if !classifiedOK || semanticOutput || len(materialized) != 0 || preparedWorkflow != nil || requestedContinuationID(record.Request) != "" {
		return resolve.Target{}, false
	}
	request := resolve.Request{Operation: record.Operation, Now: s.options.Now().UTC()}
	switch classified.Action {
	case provider.RetryOtherCredential:
		*excludedCredentials = appendUniqueString(*excludedCredentials, record.Target.CredentialID)
		*excludedEndpoints = (*excludedEndpoints)[:0]
		request.ExcludedCredentialIDs = append([]string(nil), (*excludedCredentials)...)
	case provider.RetryOtherEndpoint:
		*excludedEndpoints = appendUniqueString(*excludedEndpoints, record.Target.EndpointID)
		request.RequiredCredentialID = record.Target.CredentialID
		request.ExcludedEndpointIDs = append([]string(nil), (*excludedEndpoints)...)
	default:
		return resolve.Target{}, false
	}
	target, errResolve := s.resolveTargetWithRequest(ctx, record.Request, request)
	if errResolve != nil || !sameExecutionSubject(record.Target, target) {
		return resolve.Target{}, false
	}
	if errCapabilities := validateRequestAgainstTarget(record.Request, target); errCapabilities != nil {
		return resolve.Target{}, false
	}
	return target, true
}

// persistAttempt atomically records one completed attempt and an optional next same-provider target.
// persistAttempt 原子记录一次已结束尝试以及可选的下一个同供应商 Target。
func (s *Service) persistAttempt(ctx context.Context, record Record, attempt Attempt, nextTarget *resolve.Target) (Record, error) {
	expectedRevision := record.Revision
	sequence, errSequence := s.nextEventSequence(ctx, record)
	if errSequence != nil {
		return Record{}, errSequence
	}
	record.Attempts = append(record.Attempts, attempt)
	if nextTarget != nil {
		record.Target = *nextTarget
	}
	record.UpdatedAt = s.options.Now().UTC()
	record.Revision++
	event := attemptCompletedEvent(record.ID, sequence, record.UpdatedAt, attempt.Sequence)
	if errSave := s.store.Save(ctx, record, expectedRevision, []Event{event}); errSave != nil {
		return Record{}, errSave
	}
	return record, nil
}

// normalizedRetryPolicy contains the bounded defaults used by the durable scheduler.
// normalizedRetryPolicy 包含持久调度器使用的有界默认值。
type normalizedRetryPolicy struct {
	// backoff is the closed delay algorithm.
	// backoff 是封闭的延迟算法。
	backoff vcp.RetryBackoff
	// initial is the first retry delay.
	// initial 是首次重试延迟。
	initial time.Duration
	// maximum is the hard retry-delay ceiling.
	// maximum 是重试延迟硬上限。
	maximum time.Duration
	// multiplier controls exponential growth.
	// multiplier 控制指数增长。
	multiplier float64
	// maxAttempts optionally limits total provider dispatches.
	// maxAttempts 可选地限制供应商分派总次数。
	maxAttempts *uint32
}

// executionRetryPolicy resolves the validated caller policy or the durable deferred defaults.
// executionRetryPolicy 解析已校验的调用方策略或持久延迟执行默认值。
func executionRetryPolicy(request vcp.ExecutionRequest) normalizedRetryPolicy {
	policy := normalizedRetryPolicy{backoff: vcp.RetryBackoffExponential, initial: 5 * time.Second, maximum: 30 * time.Minute, multiplier: 2}
	if request.RetryPolicy == nil {
		return policy
	}
	configured := request.RetryPolicy
	if configured.Backoff != "" {
		policy.backoff = configured.Backoff
	}
	if configured.InitialDelayMilliseconds != nil {
		policy.initial = time.Duration(*configured.InitialDelayMilliseconds) * time.Millisecond
	}
	if configured.MaximumDelayMilliseconds != nil {
		policy.maximum = time.Duration(*configured.MaximumDelayMilliseconds) * time.Millisecond
	}
	if configured.Multiplier != nil {
		policy.multiplier = *configured.Multiplier
	}
	if configured.MaxAttempts != nil {
		maximum := *configured.MaxAttempts
		policy.maxAttempts = &maximum
	}
	return policy
}

// maximumCycleAttempts bounds immediate same-provider failover by the remaining configured total.
// maximumCycleAttempts 使用剩余配置总次数限制即时同供应商故障切换。
func maximumCycleAttempts(record Record) int {
	maximum := maxSameProviderExecutionAttempts
	policy := executionRetryPolicy(record.Request)
	if policy.maxAttempts != nil && int(*policy.maxAttempts) < maximum {
		maximum = int(*policy.maxAttempts)
	}
	completed := len(record.Attempts)
	if completed >= maximum {
		return 0
	}
	return maximum - completed
}

// maximumSynchronousCycleAttempts bounds all remaining parent dispatches across process recovery and Router rounds.
// maximumSynchronousCycleAttempts 跨进程恢复与 Router 轮次限制全部剩余父分派次数。
func maximumSynchronousCycleAttempts(record Record) int {
	maximum := maxSameProviderExecutionAttempts
	policy := executionRetryPolicy(record.Request)
	if policy.maxAttempts != nil && int(*policy.maxAttempts) < maximum {
		maximum = int(*policy.maxAttempts)
	}
	maximum += maximumRouterToolCalls(record.ModelToolPlan)
	if len(record.Attempts) >= maximum {
		return 0
	}
	return maximum - len(record.Attempts)
}

// scheduleRetry persists one future retry only for deferred, classified, pre-semantic transient failures.
// scheduleRetry 仅为延迟、已分类且产生语义输出前的瞬态失败持久化未来重试。
func (s *Service) scheduleRetry(ctx context.Context, record Record, classified provider.ClassifiedError, classifiedOK bool, semanticOutput bool) (Record, bool, error) {
	if record.Request.DispatchMode != vcp.DispatchDeferred || !classifiedOK || semanticOutput {
		return record, false, nil
	}
	switch classified.Category {
	case "network_unavailable", "transient_upstream", "quota_exhausted":
	default:
		return record, false, nil
	}
	policy := executionRetryPolicy(record.Request)
	if policy.maxAttempts != nil && uint32(len(record.Attempts)) >= *policy.maxAttempts {
		return record, false, nil
	}
	failureCycles := uint32((len(record.Attempts) - 1) / maxSameProviderExecutionAttempts)
	delay := policy.initial
	if policy.backoff == vcp.RetryBackoffExponential {
		for cycle := uint32(0); cycle < failureCycles && delay < policy.maximum; cycle++ {
			next := time.Duration(float64(delay) * policy.multiplier)
			if next <= delay || next > policy.maximum {
				delay = policy.maximum
				break
			}
			delay = next
		}
	}
	if delay > policy.maximum {
		delay = policy.maximum
	}
	now := s.options.Now().UTC()
	nextRetryAt := now.Add(delay)
	if classified.RetryAt != nil && classified.RetryAt.After(nextRetryAt) {
		nextRetryAt = classified.RetryAt.UTC()
	}
	if !nextRetryAt.Before(record.ExpiresAt) {
		return record, false, nil
	}
	if deadline, bounded := executionDeadline(record); bounded {
		if !nextRetryAt.Before(deadline) {
			return record, false, nil
		}
	}
	expectedRevision := record.Revision
	sequence, errSequence := s.nextEventSequence(ctx, record)
	if errSequence != nil {
		return Record{}, false, errSequence
	}
	record.Status = StatusWaitingRetry
	record.Failure = nil
	record.RetryCycles++
	record.Retry = &RetryState{ConsecutiveFailures: uint32(len(record.Attempts)), NextRetryAt: nextRetryAt, Category: classified.Category, Scope: classified.Scope, Action: classified.Action, MaxAttempts: policy.maxAttempts}
	record.UpdatedAt = now
	record.Revision++
	event := retryEvent(record.ID, sequence, now, EventRetryScheduled, uint32(len(record.Attempts)+1), &nextRetryAt, classified.Category)
	if errSave := s.store.Save(ctx, record, expectedRevision, []Event{event}); errSave != nil {
		return Record{}, false, errSave
	}
	return record, true, nil
}

// appendRetryEvent persists one scheduler observation without changing lifecycle status.
// appendRetryEvent 持久化一次调度器观测且不改变生命周期状态。
func (s *Service) appendRetryEvent(ctx context.Context, record Record, eventType EventType, attempt uint32, nextRetryAt *time.Time, category string) (Record, error) {
	expectedRevision := record.Revision
	sequence, errSequence := s.nextEventSequence(ctx, record)
	if errSequence != nil {
		return Record{}, errSequence
	}
	now := s.options.Now().UTC()
	record.UpdatedAt = now
	record.Revision++
	event := retryEvent(record.ID, sequence, now, eventType, attempt, nextRetryAt, category)
	if errSave := s.store.Save(ctx, record, expectedRevision, []Event{event}); errSave != nil {
		return Record{}, errSave
	}
	return record, nil
}

// classifyAndRecordFailure returns one trusted classification and persists its runtime-state effect when configured.
// classifyAndRecordFailure 返回可信分类，并在已配置时持久化其运行状态影响。
func (s *Service) classifyAndRecordFailure(ctx context.Context, request provider.ExecutionRequest, executionError error) (provider.ClassifiedError, bool) {
	classifier, supportsClassification := s.providers.(ProviderErrorClassifier)
	if !supportsClassification {
		return provider.ClassifiedError{}, false
	}
	classified, classifiedOK := classifier.ClassifyExecutionError(request, executionError)
	if !classifiedOK {
		return provider.ClassifiedError{}, false
	}
	if s.options.RuntimeFeedback != nil {
		_ = s.options.RuntimeFeedback.RecordFailure(context.WithoutCancel(ctx), request, classified, s.options.Now().UTC())
	}
	return classified, true
}

// classifiedRetryable reports whether a trusted classification recommends a future or alternate-target retry.
// classifiedRetryable 表示可信分类是否建议未来或更换 Target 后重试。
func classifiedRetryable(classified provider.ClassifiedError, classifiedOK bool) bool {
	return classifiedOK && classified.Action != provider.RetryStop
}

// providerResultHasSemanticOutput reports whether an errored dispatch already returned any provider-accepted state or client-visible result.
// providerResultHasSemanticOutput 表示失败分派是否已经返回任何供应商接收状态或客户端可见结果。
func providerResultHasSemanticOutput(result provider.ExecutionResult) bool {
	return result.Response.ResponseID != "" || result.Response.Status != "" || len(result.Response.Items) != 0 || len(result.Response.Citations) != 0 || result.Response.Usage != nil || result.Response.FinishReason != "" || result.Response.ErrorCode != "" || len(result.Response.Warnings) != 0 || len(result.Events) != 0 || result.UpstreamResponseID != "" || result.ContinuationUpstreamResponseID != "" || len(result.Embeddings) != 0 || len(result.Rerank) != 0 || result.Search != nil || result.Extract != nil || result.Transcript != nil || len(result.Transcriptions) != 0 || result.MusicCoverPreparation != nil || len(result.GeneratedResources) != 0 || result.Report.ResponseID != "" || result.Report.ExecutionID != "" || result.Report.Usage != nil
}

// appendUniqueString appends one exact identifier only when it has not already been recorded.
// appendUniqueString 仅在尚未记录时追加一个精确标识。
func appendUniqueString(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

// recordSuccessfulRequest clears temporary exact-target runtime state after provider success.
// recordSuccessfulRequest 在供应商成功后清除精确 Target 的临时运行状态。
func (s *Service) recordSuccessfulRequest(ctx context.Context, request provider.ExecutionRequest) {
	if s.options.RuntimeFeedback == nil {
		return
	}
	_ = s.options.RuntimeFeedback.RecordSuccess(context.WithoutCancel(ctx), request, s.options.Now().UTC())
}

// loadBinding loads exact endpoint, credential, and definition snapshots selected by the target.
// loadBinding 加载 Target 选中的精确 Endpoint、Credential 与 Definition 快照。
func (s *Service) loadBinding(ctx context.Context, target resolve.Target) (transport.Binding, providerconfig.ProviderDefinition, error) {
	definition, errDefinition := s.configurations.GetDefinition(ctx, target.ProviderDefinitionID)
	if errDefinition != nil {
		return transport.Binding{}, providerconfig.ProviderDefinition{}, errDefinition
	}
	endpoints, errEndpoints := s.configurations.ListEndpoints(ctx, target.ProviderInstanceID)
	if errEndpoints != nil {
		return transport.Binding{}, providerconfig.ProviderDefinition{}, errEndpoints
	}
	credentials, errCredentials := s.configurations.ListCredentials(ctx, target.ProviderInstanceID)
	if errCredentials != nil {
		return transport.Binding{}, providerconfig.ProviderDefinition{}, errCredentials
	}
	var endpoint providerconfig.Endpoint
	for _, candidate := range endpoints {
		if candidate.ID == target.EndpointID {
			endpoint = candidate
			break
		}
	}
	var credential providerconfig.Credential
	for _, candidate := range credentials {
		if candidate.ID == target.CredentialID {
			credential = candidate
			break
		}
	}
	binding := transport.Binding{Target: target, Endpoint: endpoint, Credential: credential}
	if errValidate := binding.Validate(); errValidate != nil {
		return transport.Binding{}, providerconfig.ProviderDefinition{}, errValidate
	}
	return binding, definition, nil
}

// transition commits one lifecycle transition and its exact event atomically.
// transition 原子提交一个生命周期转换及其精确事件。
func (s *Service) transition(ctx context.Context, record Record, status Status, eventType EventType, failure *Failure) (Record, error) {
	if record.Status == status {
		return record, nil
	}
	if errTransition := ValidateTransition(record.Status, status); errTransition != nil {
		return Record{}, errTransition
	}
	expectedRevision := record.Revision
	sequence, errSequence := s.nextEventSequence(ctx, record)
	if errSequence != nil {
		return Record{}, errSequence
	}
	now := s.options.Now().UTC()
	record.Status = status
	record.Failure = failure
	if status != StatusWaitingRetry {
		record.Retry = nil
	}
	if status.IsTerminal() {
		// ProviderTask is no longer needed after a confirmed terminal transition, allowing protected-handle cleanup.
		// ProviderTask 在确认进入终态后不再需要，从而允许清理受保护句柄。
		record.ProviderTask = nil
	}
	record.UpdatedAt = now
	record.Revision++
	event := lifecycleEvent(record.ID, sequence, now, eventType, status, failure)
	if errSave := s.store.Save(ctx, record, expectedRevision, []Event{event}); errSave != nil {
		return Record{}, errSave
	}
	return record, nil
}

// appendLifecycle persists one real lifecycle event that does not change the current execution status.
// appendLifecycle 持久化一个不改变当前执行状态的真实生命周期事件。
func (s *Service) appendLifecycle(ctx context.Context, record Record, eventType EventType) (Record, error) {
	expectedRevision := record.Revision
	sequence, errSequence := s.nextEventSequence(ctx, record)
	if errSequence != nil {
		return Record{}, errSequence
	}
	now := s.options.Now().UTC()
	record.UpdatedAt = now
	record.Revision++
	event := lifecycleEvent(record.ID, sequence, now, eventType, record.Status, record.Failure)
	if errSave := s.store.Save(ctx, record, expectedRevision, []Event{event}); errSave != nil {
		return Record{}, errSave
	}
	return record, nil
}

// succeed commits provider semantic events and one successful terminal result in a single CAS update.
// succeed 在单次 CAS 更新中提交供应商语义事件与成功终态结果。
func (s *Service) succeed(ctx context.Context, record Record, providerResult provider.ExecutionResult, resources []resource.Resource) (Record, bool, error) {
	return s.succeedWithStatus(ctx, record, providerResult, resources, StatusSucceeded, EventExecutionSucceeded)
}

// succeedWithStatus commits provider semantic events and one exact successful terminal status.
// succeedWithStatus 提交供应商语义事件与一个精确成功终态。
func (s *Service) succeedWithStatus(ctx context.Context, record Record, providerResult provider.ExecutionResult, resources []resource.Resource, terminalStatus Status, terminalEvent EventType) (Record, bool, error) {
	usage, errUsage := usageObservationForResult(providerResult)
	if errUsage != nil {
		return Record{}, false, errUsage
	}
	result := Result{Embeddings: append([]vcp.EmbeddingItem(nil), providerResult.Embeddings...), Rerank: append([]vcp.RerankResult(nil), providerResult.Rerank...), Search: providerResult.Search, Extract: providerResult.Extract, Transcript: providerResult.Transcript, Transcriptions: append([]vcp.TranscriptionResult(nil), providerResult.Transcriptions...), Resources: append([]resource.Resource(nil), resources...), Usage: usage}
	if providerResult.MusicCoverPreparation != nil {
		preparation := providerResult.MusicCoverPreparation
		publicPreparation := vcp.MusicCoverPreparation{PreparationID: record.ID, FormattedLyrics: preparation.FormattedLyrics, Structure: append([]vcp.MusicStructureSegment(nil), preparation.Structure...), AudioDurationSeconds: preparation.AudioDurationSeconds, ExpiresAt: preparation.ExpiresAt}
		if errPreparation := publicPreparation.Validate(); errPreparation != nil {
			return Record{}, false, fmt.Errorf("%w: %v", ErrInvalidProviderResult, errPreparation)
		}
		result.MusicCoverPreparation = &publicPreparation
		record.ProviderPreparation = &ProviderPreparationSnapshot{ProviderHandle: preparation.ProviderHandle, Target: record.Target, ExpiresAt: preparation.ExpiresAt}
	}
	if record.Operation == vcp.OperationConversationRespond {
		response := providerResult.Response
		result.Conversation = &response
	}
	if record.Operation == vcp.OperationMediaAnalyze {
		response := providerResult.Response
		result.Analysis = &response
	}
	expectedRevision := record.Revision
	sequence, errSequence := s.nextEventSequence(ctx, record)
	if errSequence != nil {
		return Record{}, false, errSequence
	}
	now := s.options.Now().UTC()
	if terminalStatus == StatusSucceeded && record.Operation == vcp.OperationConversationRespond && strings.TrimSpace(providerResult.ContinuationUpstreamResponseID) != "" {
		logicalResponseID := strings.TrimSpace(providerResult.Response.ResponseID)
		if logicalResponseID == "" {
			return Record{}, false, fmt.Errorf("%w: continuation-capable result requires a public response identifier", ErrInvalidProviderResult)
		}
		publicContinuation := &vcp.Continuation{ContinuationID: record.ID, LogicalResponseID: logicalResponseID, AffinitySummary: continuationAffinitySummary(record.Target), ExpiresAt: record.ExpiresAt}
		result.Continuation = publicContinuation
		record.ProviderContinuation = &ProviderContinuationSnapshot{ContinuationID: record.ID, UpstreamResponseID: providerResult.ContinuationUpstreamResponseID, Target: record.Target, LogicalResponseID: logicalResponseID, CreatedAt: now, ExpiresAt: record.ExpiresAt}
	}
	events := make([]Event, 0, len(providerResult.Events)+1)
	for _, providerEvent := range providerResult.Events {
		eventCopy := providerEvent
		events = append(events, Event{ExecutionID: record.ID, EventID: fmt.Sprintf("evt_%s_%d", record.ID[4:], sequence), Sequence: sequence, Time: now, Type: EventProviderSemantic, ProviderEvent: &eventCopy})
		sequence++
	}
	resultEvents := typedResultEvents(record.ID, sequence, now, providerResult, resources)
	events = append(events, resultEvents...)
	sequence += uint64(len(resultEvents))
	events = append(events, lifecycleEvent(record.ID, sequence, now, terminalEvent, terminalStatus, nil))
	record.Status = terminalStatus
	record.Result = &result
	// ProviderTask is no longer needed once the provider result is durably terminal.
	// ProviderTask 在供应商结果持久化进入终态后不再需要。
	record.ProviderTask = nil
	record.UpdatedAt = now
	record.Revision++
	if errSave := s.store.Save(ctx, record, expectedRevision, events); errSave != nil {
		return Record{}, false, errSave
	}
	return record, false, nil
}

// nextEventSequence returns the durable event boundary independently from record revisions that may advance without events.
// nextEventSequence 独立于可能无事件递增的记录修订号返回持久事件边界。
func (s *Service) nextEventSequence(ctx context.Context, record Record) (uint64, error) {
	events, errEvents := s.store.ListEvents(ctx, record.OwnerAPIKeyID, record.ID, 0)
	if errEvents != nil {
		return 0, errEvents
	}
	if len(events) == 0 {
		return 0, fmt.Errorf("%w: execution event log is empty", ErrInvalidExecution)
	}
	return events[len(events)-1].Sequence + 1, nil
}

// modelToolAdmissionEvents returns safe enabled and frozen-mode facts in canonical plan order.
// modelToolAdmissionEvents 按规范计划顺序返回安全的已启用及方式冻结事实。
// Parameters: plan is the immutable accepted model-tool plan.
// 参数：plan 是不可变的已接收模型工具计划。
// Returns: ordered parent execution events without backend or credential details.
// 返回：不含后端或凭据详情的有序父执行事件。
func modelToolAdmissionEvents(plan ModelToolPlan) []ModelToolEvent {
	events := make([]ModelToolEvent, 0, len(plan.Standard)*2+len(plan.Extra)*2+len(plan.RouterExtensions)*2)
	appendAdmission := func(toolID string, mode vcp.ModelToolMode) {
		if mode != vcp.ModelToolDisabled {
			events = append(events, ModelToolEvent{ToolID: toolID, Stage: ModelToolStageEnabled, Mode: mode})
		}
		events = append(events, ModelToolEvent{ToolID: toolID, Stage: ModelToolStageModeFrozen, Mode: mode})
	}
	for _, entry := range plan.Standard {
		appendAdmission(string(entry.Kind), entry.Mode)
	}
	for _, toolID := range plan.Extra {
		appendAdmission(toolID, vcp.ModelToolNative)
	}
	for _, entry := range plan.RouterExtensions {
		appendAdmission(string(entry.ID), vcp.ModelToolRouter)
	}
	return events
}

// appendModelToolEvents durably appends safe parent model-tool transitions without changing execution status.
// appendModelToolEvents 持久追加安全父执行模型工具转换且不改变执行状态。
// Parameters: ctx controls persistence, record is the exact current revision, and payloads are ordered closed events.
// 参数：ctx 控制持久化，record 是精确当前修订，payloads 是有序封闭事件。
// Returns: the revision advanced durable record or an explicit storage error.
// 返回：修订已递增的持久记录或明确存储错误。
func (s *Service) appendModelToolEvents(ctx context.Context, record Record, payloads []ModelToolEvent) (Record, error) {
	if len(payloads) == 0 {
		return record, nil
	}
	sequence, errSequence := s.nextEventSequence(ctx, record)
	if errSequence != nil {
		return Record{}, errSequence
	}
	now := s.options.Now().UTC()
	events := make([]Event, 0, len(payloads))
	for index := range payloads {
		payload := payloads[index]
		event := Event{ExecutionID: record.ID, EventID: fmt.Sprintf("evt_%s_%d", record.ID[4:], sequence), Sequence: sequence, Time: now, Type: EventModelToolLifecycle, ModelTool: &payload}
		if errValidate := event.Validate(); errValidate != nil {
			return Record{}, errValidate
		}
		events = append(events, event)
		sequence++
	}
	expectedRevision := record.Revision
	record.UpdatedAt = now
	record.Revision++
	if errSave := s.store.Save(ctx, record, expectedRevision, events); errSave != nil {
		return Record{}, errSave
	}
	return record, nil
}

// usageObservationForResult returns the sole consistent terminal usage observation carried by a provider result.
// usageObservationForResult 返回供应商结果携带的唯一一致终态用量观测。
func usageObservationForResult(result provider.ExecutionResult) (*vcp.UsageObservation, error) {
	observations := make([]*vcp.UsageObservation, 0, 3)
	if result.Response.Usage != nil {
		observations = append(observations, result.Response.Usage)
	}
	if result.Report.Usage != nil {
		observations = append(observations, result.Report.Usage)
	}
	if result.Search != nil && result.Search.Usage != nil {
		observations = append(observations, result.Search.Usage)
	}
	if result.Extract != nil && result.Extract.Usage != nil {
		observations = append(observations, result.Extract.Usage)
	}
	if len(observations) == 0 {
		return nil, nil
	}
	for _, observation := range observations {
		if errValidate := validateUsageObservation(*observation); errValidate != nil {
			return nil, errValidate
		}
		if !usageObservationsEqual(*observations[0], *observation) {
			return nil, fmt.Errorf("%w: provider result contains conflicting usage observations", ErrInvalidProviderResult)
		}
	}
	copy := *observations[0]
	return &copy, nil
}

// validateUsageObservation enforces explicit provenance and non-negative provider-reported values.
// validateUsageObservation 强制要求显式来源，并校验供应商报告数值非负。
func validateUsageObservation(observation vcp.UsageObservation) error {
	if strings.TrimSpace(observation.Source) == "" || strings.TrimSpace(observation.Aggregation) == "" || strings.TrimSpace(observation.Phase) == "" || strings.TrimSpace(observation.AccountingBasis) == "" {
		return fmt.Errorf("%w: usage observation provenance is incomplete", ErrInvalidProviderResult)
	}
	if !validUsageSource(observation.Source) || !validUsageAggregation(observation.Aggregation) || !validUsagePhase(observation.Phase) {
		return fmt.Errorf("%w: usage observation provenance is outside the closed VCP vocabulary", ErrInvalidProviderResult)
	}
	for _, value := range []*int64{observation.InputTokens, observation.OutputTokens, observation.ReasoningTokens, observation.CacheReadTokens, observation.CacheCreationTokens, observation.TotalTokens} {
		if value != nil && *value < 0 {
			return fmt.Errorf("%w: usage observation contains a negative token value", ErrInvalidProviderResult)
		}
	}
	if observation.ServiceUnits != nil && (*observation.ServiceUnits < 0 || strings.TrimSpace(observation.ServiceUnit) == "") {
		return fmt.Errorf("%w: usage observation service units are invalid", ErrInvalidProviderResult)
	}
	if observation.ServiceUnits == nil && strings.TrimSpace(observation.ServiceUnit) != "" {
		return fmt.Errorf("%w: usage observation service unit has no value", ErrInvalidProviderResult)
	}
	return nil
}

// validUsageSource reports whether provenance belongs to the closed VCP usage vocabulary.
// validUsageSource 报告来源是否属于封闭的 VCP 用量词汇表。
func validUsageSource(source string) bool {
	switch source {
	case "provider_reported", "exact", "estimated", "derived", "unknown":
		return true
	default:
		return false
	}
}

// validUsageAggregation reports whether one observation declares closed aggregation semantics.
// validUsageAggregation 报告观测是否声明了封闭的聚合语义。
func validUsageAggregation(aggregation string) bool {
	switch aggregation {
	case "delta", "cumulative", "snapshot":
		return true
	default:
		return false
	}
}

// validUsagePhase reports whether one observation belongs to a recognized accounting phase.
// validUsagePhase 报告观测是否属于已识别的计量阶段。
func validUsagePhase(phase string) bool {
	switch phase {
	case "preflight", "streaming", "terminal", "billing":
		return true
	default:
		return false
	}
}

// usageObservationsEqual compares every defined usage dimension and its accounting semantics.
// usageObservationsEqual 比较每个已定义用量维度及其计量语义。
func usageObservationsEqual(first vcp.UsageObservation, second vcp.UsageObservation) bool {
	firstJSON, errFirst := json.Marshal(first)
	secondJSON, errSecond := json.Marshal(second)
	return errFirst == nil && errSecond == nil && bytes.Equal(firstJSON, secondJSON)
}

// continuationAffinitySummary returns a stable secret-free description of the exact replay boundary.
// continuationAffinitySummary 返回精确重放边界的稳定无秘密描述。
func continuationAffinitySummary(target resolve.Target) string {
	return fmt.Sprintf("provider=%s;instance=%s;model=%s;profile=%s", target.ProviderDefinitionID, target.ProviderInstanceID, target.ProviderModelID, target.ExecutionProfileID)
}

// typedResultEvents projects only real completed provider results into operation-specific semantic events.
// typedResultEvents 仅将真实已完成供应商结果投影为操作特定语义事件。
func typedResultEvents(executionID string, firstSequence uint64, at time.Time, result provider.ExecutionResult, resources []resource.Resource) []Event {
	events := make([]Event, 0, len(result.Embeddings)+len(result.Rerank)+len(resources))
	sequence := firstSequence
	for _, embedding := range result.Embeddings {
		value := embedding
		events = append(events, Event{ExecutionID: executionID, EventID: fmt.Sprintf("evt_%s_%d", executionID[4:], sequence), Sequence: sequence, Time: at, Type: EventEmbeddingItemCompleted, Embedding: &value})
		sequence++
	}
	for _, rerank := range result.Rerank {
		value := rerank
		events = append(events, Event{ExecutionID: executionID, EventID: fmt.Sprintf("evt_%s_%d", executionID[4:], sequence), Sequence: sequence, Time: at, Type: EventRerankResultCompleted, Rerank: &value})
		sequence++
	}
	if result.Transcript != nil {
		for _, candidate := range result.Transcript.Candidates {
			for _, transcriptSegment := range candidate.Segments {
				value := transcriptSegment
				events = append(events, Event{ExecutionID: executionID, EventID: fmt.Sprintf("evt_%s_%d", executionID[4:], sequence), Sequence: sequence, Time: at, Type: EventTranscriptSegment, Transcript: &value})
				sequence++
			}
		}
	}
	for _, transcription := range result.Transcriptions {
		if transcription.Transcript == nil {
			continue
		}
		for _, candidate := range transcription.Transcript.Candidates {
			for _, transcriptSegment := range candidate.Segments {
				value := transcriptSegment
				events = append(events, Event{ExecutionID: executionID, EventID: fmt.Sprintf("evt_%s_%d", executionID[4:], sequence), Sequence: sequence, Time: at, Type: EventTranscriptSegment, Transcript: &value})
				sequence++
			}
		}
	}
	for resourceIndex, generated := range resources {
		value := generated
		outputID := result.GeneratedResources[resourceIndex].OutputID
		events = append(events, Event{ExecutionID: executionID, EventID: fmt.Sprintf("evt_%s_%d", executionID[4:], sequence), Sequence: sequence, Time: at, Type: EventResourceCompleted, Resource: &ResourceEvent{OutputID: outputID, ResourceID: value.ID, Resource: &value}})
		sequence++
	}
	usage, _ := usageObservationForResult(result)
	for _, usageMetric := range usageEvents(usage) {
		value := usageMetric
		events = append(events, Event{ExecutionID: executionID, EventID: fmt.Sprintf("evt_%s_%d", executionID[4:], sequence), Sequence: sequence, Time: at, Type: EventUsageUpdated, Usage: &value})
		sequence++
	}
	if result.Search == nil {
		return events
	}
	// queries preserves every provider-observed model search instead of collapsing it into one value.
	// queries 保留每个供应商观测到的模型搜索，而不是将其折叠为单个值。
	queries := append([]string(nil), result.Search.Queries...)
	if len(queries) == 0 && result.Search.Query != "" {
		queries = []string{result.Search.Query}
	}
	for _, query := range queries {
		events = append(events, Event{ExecutionID: executionID, EventID: fmt.Sprintf("evt_%s_%d", executionID[4:], sequence), Sequence: sequence, Time: at, Type: EventSearchQueryStarted, SearchQuery: &SearchQueryEvent{Query: query}})
		sequence++
	}
	for _, searchResult := range result.Search.Results {
		value := searchResult
		events = append(events, Event{ExecutionID: executionID, EventID: fmt.Sprintf("evt_%s_%d", executionID[4:], sequence), Sequence: sequence, Time: at, Type: EventSearchResultCompleted, SearchResult: &value})
		sequence++
	}
	if result.Search.Answer != "" {
		events = append(events, Event{ExecutionID: executionID, EventID: fmt.Sprintf("evt_%s_%d", executionID[4:], sequence), Sequence: sequence, Time: at, Type: EventSearchAnswerCompleted, SearchAnswer: &SearchAnswerEvent{Text: result.Search.Answer}})
		sequence++
	}
	for _, citation := range result.Search.Citations {
		value := citation
		events = append(events, Event{ExecutionID: executionID, EventID: fmt.Sprintf("evt_%s_%d", executionID[4:], sequence), Sequence: sequence, Time: at, Type: EventCitationCompleted, Citation: &value})
		sequence++
	}
	return events
}

// usageEvents expands one typed observation into independently replayable closed metrics.
// usageEvents 将一个类型化观测展开为可独立重放的封闭指标。
func usageEvents(observation *vcp.UsageObservation) []UsageEvent {
	if observation == nil {
		return nil
	}
	accuracy := "exact"
	if observation.Source == "estimated" {
		accuracy = "estimated"
	} else if observation.Source == "unknown" {
		accuracy = "unknown"
	}
	metrics := make([]UsageEvent, 0, 7)
	appendMetric := func(unit string, value float64) {
		metrics = append(metrics, UsageEvent{Unit: unit, Value: value, Accuracy: accuracy, Source: observation.Source, Aggregation: observation.Aggregation, Phase: observation.Phase, AccountingBasis: observation.AccountingBasis, Final: observation.Final})
	}
	if observation.ServiceUnits != nil {
		appendMetric(observation.ServiceUnit, *observation.ServiceUnits)
	}
	for _, metric := range []struct {
		// unit identifies the closed VCP accounting dimension.
		// unit 标识封闭的 VCP 计量维度。
		unit string
		// value references the optional measured integer for this dimension.
		// value 引用该维度的可选整数测量值。
		value *int64
	}{{"input_tokens", observation.InputTokens}, {"output_tokens", observation.OutputTokens}, {"reasoning_tokens", observation.ReasoningTokens}, {"cache_read_tokens", observation.CacheReadTokens}, {"cache_creation_tokens", observation.CacheCreationTokens}, {"total_tokens", observation.TotalTokens}} {
		if metric.value != nil {
			appendMetric(metric.unit, float64(*metric.value))
		}
	}
	return metrics
}

// fail commits one safe terminal failure.
// fail 提交一个安全终态失败。
func (s *Service) fail(ctx context.Context, record Record, code string, retryable bool) (Record, error) {
	updated, errAborted := s.appendRetryAbortBeforeTerminalFailure(ctx, record)
	if errAborted != nil {
		return Record{}, errAborted
	}
	record = updated
	failure := failureForRecord(record, code, retryable)
	return s.transition(ctx, record, StatusFailed, EventExecutionFailed, failure)
}

// failClassified commits a terminal failure with trusted provider classification and no response body data.
// failClassified 提交带可信供应商分类且不含响应正文数据的终态失败。
func (s *Service) failClassified(ctx context.Context, record Record, code string, retryable bool, classified provider.ClassifiedError, classifiedOK bool) (Record, error) {
	if !classifiedOK {
		return s.fail(ctx, record, code, retryable)
	}
	updated, errAborted := s.appendRetryAbortBeforeTerminalFailure(ctx, record)
	if errAborted != nil {
		return Record{}, errAborted
	}
	record = updated
	failure := failureForRecord(record, code, retryable)
	failure.Category = classified.Category
	failure.Scope = classified.Scope
	failure.RetryAction = classified.Action
	failure.ProviderRequestID = classified.ProviderRequestID
	if classified.RetryAt != nil {
		nextRetryAt := classified.RetryAt.UTC()
		failure.NextRetryAt = &nextRetryAt
		delay := nextRetryAt.Sub(s.options.Now().UTC()).Milliseconds()
		if delay < 0 {
			delay = 0
		}
		failure.RetryAfterMilliseconds = &delay
	}
	return s.transition(ctx, record, StatusFailed, EventExecutionFailed, failure)
}

// appendRetryAbortBeforeTerminalFailure closes a previously scheduled retry sequence exactly once before failure.
// appendRetryAbortBeforeTerminalFailure 在失败前精确关闭一次先前已计划的重试序列。
func (s *Service) appendRetryAbortBeforeTerminalFailure(ctx context.Context, record Record) (Record, error) {
	if record.RetryCycles == 0 {
		return record, nil
	}
	return s.appendRetryEvent(ctx, record, EventRetryAborted, uint32(len(record.Attempts)+1), nil, "")
}

// failureForRecord creates stable request and redacted target diagnostics.
// failureForRecord 创建稳定请求与脱敏 Target 诊断信息。
func failureForRecord(record Record, code string, retryable bool) *Failure {
	policy := executionRetryPolicy(record.Request)
	return &Failure{Code: code, Retryable: retryable, Attempt: uint32(len(record.Attempts)), MaxAttempts: policy.maxAttempts, RouterRequestID: record.Request.RequestID, TargetSummary: safeTargetSummary(record.Target)}
}

// safeTargetSummary returns only non-secret immutable routing coordinates.
// safeTargetSummary 仅返回非秘密不可变路由坐标。
func safeTargetSummary(target resolve.Target) string {
	subject := target.ProviderModelID
	if subject == "" {
		subject = target.ProviderServiceID
	}
	return fmt.Sprintf("instance=%s;subject=%s;profile=%s;region=%s", target.ProviderInstanceID, subject, target.ExecutionProfileID, target.EndpointRegion)
}

// lifecycleEvent builds one stable Router-owned event.
// lifecycleEvent 构建一个稳定 Router 所有事件。
func lifecycleEvent(executionID string, sequence uint64, at time.Time, eventType EventType, status Status, failure *Failure) Event {
	return Event{ExecutionID: executionID, EventID: fmt.Sprintf("evt_%s_%d", executionID[4:], sequence), Sequence: sequence, Time: at, Type: eventType, Lifecycle: &LifecycleEvent{Status: status, Failure: failure}}
}

// attemptCompletedEvent builds one safe event for a durably audited private provider attempt.
// attemptCompletedEvent 为一次已持久审计的私有供应商尝试构建安全事件。
func attemptCompletedEvent(executionID string, sequence uint64, at time.Time, attemptSequence uint32) Event {
	return Event{ExecutionID: executionID, EventID: fmt.Sprintf("evt_%s_%d", executionID[4:], sequence), Sequence: sequence, Time: at, Type: EventExecutionAttemptCompleted, Attempt: &AttemptEvent{Sequence: attemptSequence}}
}

// retryEvent builds one client-safe durable scheduler event.
// retryEvent 构建一个客户端安全的持久调度器事件。
func retryEvent(executionID string, sequence uint64, at time.Time, eventType EventType, attempt uint32, nextRetryAt *time.Time, category string) Event {
	return Event{ExecutionID: executionID, EventID: fmt.Sprintf("evt_%s_%d", executionID[4:], sequence), Sequence: sequence, Time: at, Type: eventType, Retry: &RetryEvent{Attempt: attempt, NextRetryAt: nextRetryAt, Category: category}}
}

// canonicalRequestHash hashes canonical JSON after removing the transport idempotency key itself.
// canonicalRequestHash 在移除传输幂等键本身后对规范 JSON 计算 Hash。
func canonicalRequestHash(request vcp.ExecutionRequest) (string, error) {
	request.IdempotencyKey = ""
	encoded, errEncode := json.Marshal(request)
	if errEncode != nil {
		return "", fmt.Errorf("%w: encode canonical request: %v", ErrInvalidExecution, errEncode)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

// randomExecutionID returns a 128-bit opaque Router execution identifier.
// randomExecutionID 返回一个 128 位不透明 Router 执行标识。
func randomExecutionID() (string, error) {
	bytes := make([]byte, 16)
	if _, errRead := rand.Read(bytes); errRead != nil {
		return "", errRead
	}
	return "exe_" + hex.EncodeToString(bytes), nil
}

// sameTarget compares every immutable identity that constrains execution and provider asset ownership.
// sameTarget 比较约束执行与供应商资产所有权的每个不可变身份。
func sameTarget(first resolve.Target, second resolve.Target) bool {
	return first.ProviderDefinitionID == second.ProviderDefinitionID && first.ProviderInstanceID == second.ProviderInstanceID && first.ChannelID == second.ChannelID && first.EndpointID == second.EndpointID && first.EndpointRegion == second.EndpointRegion && first.CredentialID == second.CredentialID && first.SubjectKind == second.SubjectKind && first.ProviderModelID == second.ProviderModelID && first.ProviderServiceID == second.ProviderServiceID && first.OfferingID == second.OfferingID && first.ServiceOfferingID == second.ServiceOfferingID && first.Operation == second.Operation && first.ActionBindingID == second.ActionBindingID && first.ExecutionProfileID == second.ExecutionProfileID && first.UpstreamModelID == second.UpstreamModelID && first.UpstreamServiceID == second.UpstreamServiceID && first.CapabilityRevision == second.CapabilityRevision && first.ProviderConfigRevision == second.ProviderConfigRevision && first.CatalogRevision == second.CatalogRevision
}

// sameExecutionSubject verifies that failover changes only endpoint, region, credential, and evidence revisions.
// sameExecutionSubject 校验故障切换只改变入口、区域、凭据和证据修订。
func sameExecutionSubject(first resolve.Target, second resolve.Target) bool {
	return first.ProviderDefinitionID == second.ProviderDefinitionID && first.ProviderInstanceID == second.ProviderInstanceID && first.ChannelID == second.ChannelID && first.SubjectKind == second.SubjectKind && first.ProviderModelID == second.ProviderModelID && first.ProviderServiceID == second.ProviderServiceID && first.OfferingID == second.OfferingID && first.ServiceOfferingID == second.ServiceOfferingID && first.Operation == second.Operation && first.ActionBindingID == second.ActionBindingID && first.ExecutionProfileID == second.ExecutionProfileID && first.UpstreamModelID == second.UpstreamModelID && first.UpstreamServiceID == second.UpstreamServiceID
}

// stableFailureCode maps internal errors to content-safe machine codes.
// stableFailureCode 将内部错误映射为内容安全机器码。
func stableFailureCode(errValue error) string {
	var modelToolError *vcp.ModelToolError
	switch {
	case errors.As(errValue, &modelToolError):
		return string(modelToolError.Code)
	case errors.Is(errValue, inputplan.ErrCapabilityChanged):
		return "capability_changed"
	case errors.Is(errValue, context.Canceled):
		return "cancelled"
	case errors.Is(errValue, context.DeadlineExceeded):
		return "deadline_exceeded"
	case errors.Is(errValue, provider.ErrExecutionDriverNotFound):
		return "provider_action_unavailable"
	case errors.Is(errValue, ErrInvalidProviderResult):
		return "provider_invalid_response"
	case errors.Is(errValue, ErrExecutionBudgetExceeded), errors.Is(errValue, provider.ErrOutputBudgetExceeded):
		return "execution_budget_exceeded"
	default:
		return "provider_execution_failed"
	}
}

// retryableFailure reports only known transient context deadlines; unknown provider errors remain non-retryable.
// retryableFailure 仅将已知瞬态 Context 超时标记为可重试；未知供应商错误保持不可重试。
func retryableFailure(errValue error) bool {
	var modelToolError *vcp.ModelToolError
	if errors.As(errValue, &modelToolError) {
		return modelToolError.Retryable
	}
	return errors.Is(errValue, context.DeadlineExceeded)
}
