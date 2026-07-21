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
	"strings"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/inputplan"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

const (
	// maxSameProviderExecutionAttempts bounds credential and endpoint failover for one logical execution.
	// maxSameProviderExecutionAttempts 限制一次逻辑执行中的凭据与入口故障切换次数。
	maxSameProviderExecutionAttempts = 8
)

// TargetResolver resolves one exact provider-scoped destination.
// TargetResolver 解析一个精确供应商作用域目的地。
type TargetResolver interface {
	// Resolve returns one immutable target or an explicit eligibility error.
	// Resolve 返回一个不可变 Target 或明确资格错误。
	Resolve(context.Context, resolve.Request) (resolve.Target, resolve.Diagnostics, error)
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
	return &Service{store: store, resolver: resolver, configurations: configurations, plans: plans, materializer: materializer, providers: providers, options: options}, nil
}

// Create durably admits and executes one validated VCP request or returns an exact idempotent replay.
// Create 持久接收并执行一个已校验 VCP 请求或返回精确幂等重放。
func (s *Service) Create(ctx context.Context, ownerAPIKeyID string, request vcp.ExecutionRequest) (Record, bool, error) {
	if strings.TrimSpace(ownerAPIKeyID) == "" {
		return Record{}, false, fmt.Errorf("%w: owner API key identifier is required", ErrInvalidExecution)
	}
	if errRequest := request.Validate(); errRequest != nil {
		return Record{}, false, errRequest
	}
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
	target, errTarget := s.resolveTarget(ctx, request, now)
	if errTarget != nil {
		return Record{}, false, errTarget
	}
	if errCapabilities := validateRequestAgainstTarget(request, target); errCapabilities != nil {
		return Record{}, false, errCapabilities
	}
	executionID, errID := s.options.NewID()
	if errID != nil {
		return Record{}, false, fmt.Errorf("create execution identifier: %w", errID)
	}
	record := Record{ID: executionID, OwnerAPIKeyID: ownerAPIKeyID, RequestHash: requestHash, IdempotencyKey: request.IdempotencyKey, Request: request, Target: target, Status: StatusAccepted, Operation: request.Operation, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(s.options.Retention), Revision: 1}
	accepted := lifecycleEvent(record.ID, 1, now, EventExecutionAccepted, StatusAccepted, nil)
	created, replayed, errCreate := s.store.Create(ctx, record, accepted)
	if errCreate != nil || replayed {
		return created, replayed, errCreate
	}
	return s.execute(ctx, created)
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
		providerRequest := taskExecutionRequest(record)
		result, errCancel := taskExecutor.CancelTask(ctx, providerRequest, record.ProviderTask.ProviderTaskID)
		if errCancel != nil {
			s.classifyAndRecordFailure(ctx, providerRequest, errCancel)
			return Record{}, errCancel
		}
		return s.applyTaskResult(ctx, record, result)
	}
	if record.Status == StatusRunning || record.Status == StatusQueued {
		return Record{}, fmt.Errorf("%w: running execution has no cancellable provider task", ErrInvalidExecution)
	}
	now := s.options.Now().UTC()
	expectedRevision := record.Revision
	record.Status = StatusCancelled
	record.UpdatedAt = now
	record.Revision++
	event := lifecycleEvent(record.ID, expectedRevision+1, now, EventExecutionCancelled, StatusCancelled, nil)
	if errSave := s.store.Save(ctx, record, expectedRevision, []Event{event}); errSave != nil {
		return Record{}, errSave
	}
	return record, nil
}

// execute prepares inputs, loads immutable wire snapshots, dispatches, and commits one terminal reduction.
// execute 准备输入、加载不可变 Wire 快照、分派并提交一个终态归并结果。
func (s *Service) execute(ctx context.Context, record Record) (Record, bool, error) {
	materialized, updated, errInputs := s.prepareInputs(ctx, record)
	if errInputs != nil {
		failed, errFail := s.fail(ctx, updated, stableFailureCode(errInputs), retryableFailure(errInputs))
		if errFail != nil {
			return Record{}, false, errFail
		}
		return failed, false, nil
	}
	record = updated
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
	if requiresProviderTask(record.Target) {
		return s.startTask(ctx, record, binding, definition, materialized)
	}
	running, errRunning := s.transition(ctx, record, StatusRunning, EventExecutionRunning, nil)
	if errRunning != nil {
		return Record{}, false, errRunning
	}
	return s.executeSynchronous(ctx, running, binding, definition, materialized, preparedWorkflow)
}

// executeSynchronous dispatches a bounded sequence of same-provider attempts before any semantic output is committed.
// executeSynchronous 在提交任何语义输出前分派有界的同供应商尝试序列。
func (s *Service) executeSynchronous(ctx context.Context, record Record, binding transport.Binding, definition providerconfig.ProviderDefinition, materialized []resource.MaterializedInput, preparedWorkflow *provider.PreparedWorkflowBinding) (Record, bool, error) {
	excludedCredentials := make([]string, 0, maxSameProviderExecutionAttempts)
	excludedEndpoints := make([]string, 0, maxSameProviderExecutionAttempts)
	for attemptIndex := 0; attemptIndex < maxSameProviderExecutionAttempts; attemptIndex++ {
		providerRequest := providerRequestForRecord(record, binding, definition, materialized, preparedWorkflow)
		startedAt := s.options.Now().UTC()
		providerResult, errExecute := s.providers.Execute(ctx, providerRequest)
		endedAt := s.options.Now().UTC()
		semanticOutput := providerResultHasSemanticOutput(providerResult)
		attempt := Attempt{Sequence: uint32(len(record.Attempts) + 1), Target: record.Target, StartedAt: startedAt, EndedAt: endedAt, SemanticOutput: semanticOutput}
		if errExecute != nil {
			classified, classifiedOK := s.classifyAndRecordFailure(ctx, providerRequest, errExecute)
			if classifiedOK {
				attempt.FailureCategory = classified.Category
				attempt.RetryAction = classified.Action
			}
			nextTarget, retry := s.resolveRetryTarget(ctx, record, classified, classifiedOK, semanticOutput, materialized, preparedWorkflow, &excludedCredentials, &excludedEndpoints)
			if retry && attemptIndex+1 < maxSameProviderExecutionAttempts {
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
			failed, errFail := s.fail(ctx, updated, stableFailureCode(errExecute), retryableFailure(errExecute) || classifiedRetryable(classified, classifiedOK))
			if errFail != nil {
				return Record{}, false, errFail
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
		attempt.Succeeded = true
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
		input := resource.CreateInput{OwnerAPIKeyID: record.OwnerAPIKeyID, Kind: output.Kind, DeclaredMIME: output.MIMEType, Retention: resource.RetentionEphemeral, GeneratedBy: &generatedBy}
		var (
			created   resource.Resource
			errCreate error
		)
		if len(output.Data) > 0 {
			input.Reader = bytes.NewReader(output.Data)
			created, errCreate = s.options.OutputResources.CreateGenerated(ctx, input)
		} else {
			created, errCreate = s.options.OutputResources.ImportGeneratedURL(ctx, resource.URLImportInput{OwnerAPIKeyID: record.OwnerAPIKeyID, URL: output.DownloadURL, Kind: output.Kind, DeclaredMIME: output.MIMEType, Retention: resource.RetentionEphemeral, GeneratedBy: &generatedBy})
		}
		if errCreate != nil {
			return nil, fmt.Errorf("import generated resource: %w", errCreate)
		}
		resources = append(resources, created)
	}
	return resources, nil
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
	if target.SubjectKind != resolve.ExecutionSubjectModel {
		return nil
	}
	if errOperation := target.ModelCapabilities.ValidateOperation(request.Operation); errOperation != nil {
		return fmt.Errorf("%w: selected profile capability contract is invalid: %v", vcp.ErrInvalidRequest, errOperation)
	}
	switch request.Operation {
	case vcp.OperationConversationRespond:
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

// validateConversationMediaRequest enforces role, placement, interaction mode, and feature-combination declarations for media blocks.
// validateConversationMediaRequest 对媒体块强制执行角色、位置、交互模式与功能组合声明。
func validateConversationMediaRequest(request vcp.ExecutionRequest, capabilities []catalog.MediaInputCapability) error {
	operation := *request.Payload.Conversation
	for _, item := range operation.Context {
		hasText := false
		hasMedia := false
		for _, block := range item.Content {
			if block.Type == vcp.ContentText && strings.TrimSpace(block.Text) != "" {
				hasText = true
			}
			kind, media := mediaKindForContentType(block.Type)
			if !media {
				continue
			}
			hasMedia = true
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
		if !hasMedia {
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
	if (strings.TrimSpace(operation.ReasoningPolicy.Effort) != "" || operation.ReasoningPolicy.Summary || strings.TrimSpace(operation.ReasoningPolicy.ContinuationID) != "") && !callableCapabilityLevel(capability.Compatibility.Reasoning) {
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
	hasGenerated := len(result.GeneratedResources) > 0
	hasTranscript := result.Transcript != nil
	hasMusicPreparation := result.MusicCoverPreparation != nil
	switch request.Operation {
	case vcp.OperationEmbeddingCreate:
		operation := *request.Payload.EmbeddingCreate
		if (complete && len(result.Embeddings) != len(operation.Inputs)) ||
			(!complete && (len(result.Embeddings) == 0 || len(result.Embeddings) > len(operation.Inputs))) ||
			len(result.Rerank) != 0 || result.Search != nil || hasGenerated || hasTranscript || hasMusicPreparation {
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
		if len(result.Embeddings) != 0 || result.Search != nil || hasGenerated || hasTranscript || hasMusicPreparation {
			return fmt.Errorf("%w: rerank result union is invalid", ErrInvalidProviderResult)
		}
		if errValidate := request.Payload.RerankDocuments.ValidateResults(result.Rerank); errValidate != nil {
			return fmt.Errorf("%w: %v", ErrInvalidProviderResult, errValidate)
		}
		return nil
	case vcp.OperationSearchWeb:
		if len(result.Embeddings) != 0 || len(result.Rerank) != 0 || result.Search == nil || hasGenerated || hasTranscript || hasMusicPreparation {
			return fmt.Errorf("%w: search result union is invalid", ErrInvalidProviderResult)
		}
		return nil
	case vcp.OperationImageGenerate, vcp.OperationImageEdit:
		if !hasGenerated || !generatedKindsAre(result.GeneratedResources, vcp.MediaImage) || len(result.Embeddings) != 0 || len(result.Rerank) != 0 || result.Search != nil || hasTranscript || hasMusicPreparation {
			return fmt.Errorf("%w: image result union is invalid", ErrInvalidProviderResult)
		}
		return validateGeneratedResources(result.GeneratedResources)
	case vcp.OperationVideoGenerate, vcp.OperationVideoEdit, vcp.OperationVideoExtend:
		if hasTranscript || hasMusicPreparation {
			return fmt.Errorf("%w: video result union is invalid", ErrInvalidProviderResult)
		}
		if complete && (!hasGenerated || !generatedKindsAre(result.GeneratedResources, vcp.MediaVideo)) {
			return fmt.Errorf("%w: completed video result requires video resources", ErrInvalidProviderResult)
		}
		if hasGenerated && !generatedKindsAre(result.GeneratedResources, vcp.MediaVideo) {
			return fmt.Errorf("%w: video result union is invalid", ErrInvalidProviderResult)
		}
		return validateGeneratedResources(result.GeneratedResources)
	case vcp.OperationSpeechSynthesize, vcp.OperationMusicGenerate, vcp.OperationMusicCover:
		if !hasGenerated || !generatedKindsAre(result.GeneratedResources, vcp.MediaAudio) || hasTranscript || hasMusicPreparation {
			return fmt.Errorf("%w: audio result union is invalid", ErrInvalidProviderResult)
		}
		return validateGeneratedResources(result.GeneratedResources)
	case vcp.OperationMusicCoverPrepare:
		preparation := result.MusicCoverPreparation
		if hasGenerated || hasTranscript || len(result.Embeddings) != 0 || len(result.Rerank) != 0 || result.Search != nil || preparation == nil || strings.TrimSpace(preparation.ProviderHandle) == "" || strings.TrimSpace(preparation.FormattedLyrics) == "" || preparation.AudioDurationSeconds <= 0 || preparation.ExpiresAt.IsZero() || len(preparation.Structure) == 0 {
			return fmt.Errorf("%w: music cover preparation result union is invalid", ErrInvalidProviderResult)
		}
		for _, segment := range preparation.Structure {
			if errSegment := segment.Validate(); errSegment != nil {
				return fmt.Errorf("%w: %v", ErrInvalidProviderResult, errSegment)
			}
		}
		return nil
	case vcp.OperationSpeechTranscribe:
		if hasGenerated || len(result.Embeddings) != 0 || len(result.Rerank) != 0 || result.Search != nil || !hasTranscript || hasMusicPreparation {
			return fmt.Errorf("%w: speech transcription result union is invalid", ErrInvalidProviderResult)
		}
		if errTranscript := result.Transcript.Validate(); errTranscript != nil {
			return fmt.Errorf("%w: %v", ErrInvalidProviderResult, errTranscript)
		}
		if requested := request.Payload.SpeechTranscribe.CandidateCount; requested > 0 && len(result.Transcript.Candidates) > requested {
			return fmt.Errorf("%w: speech transcription returned more candidates than requested", ErrInvalidProviderResult)
		}
		return nil
	case vcp.OperationConversationRespond, vcp.OperationMediaAnalyze:
		if hasGenerated || len(result.Embeddings) != 0 || len(result.Rerank) != 0 || result.Search != nil || hasTranscript || hasMusicPreparation {
			return fmt.Errorf("%w: operation returned a mismatched typed result", ErrInvalidProviderResult)
		}
		return nil
	default:
		if len(result.Embeddings) != 0 || len(result.Rerank) != 0 || result.Search != nil || hasGenerated || hasTranscript || hasMusicPreparation {
			return fmt.Errorf("%w: operation returned a mismatched typed result", ErrInvalidProviderResult)
		}
		return nil
	}
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
	if record.Status == StatusAccepted {
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
	for attemptIndex := 0; attemptIndex < maxSameProviderExecutionAttempts; attemptIndex++ {
		providerRequest := providerRequestForRecord(record, binding, definition, materialized, nil)
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
			if retry && attemptIndex+1 < maxSameProviderExecutionAttempts {
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
			failed, errFail := s.fail(ctx, updated, stableFailureCode(errStart), retryableFailure(errStart) || classifiedRetryable(classified, classifiedOK))
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
	taskExecutor, ok := s.providers.(ProviderTaskExecutor)
	if !ok {
		return nil
	}
	now := s.options.Now().UTC()
	for _, record := range records {
		if !record.ExpiresAt.After(now) {
			if _, errExpire := s.transition(ctx, record, StatusExpired, EventExecutionExpired, nil); errExpire != nil && !errors.Is(errExpire, ErrRevisionConflict) {
				return errExpire
			}
			continue
		}
		if record.ProviderTask == nil {
			if _, _, errExecute := s.execute(ctx, record); errExecute != nil && !errors.Is(errExecute, ErrRevisionConflict) {
				return errExecute
			}
			continue
		}
		if record.ProviderTask.PollAfter.After(now) {
			continue
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
			continue
		}
		if _, errApply := s.applyTaskResult(ctx, record, result); errApply != nil && !errors.Is(errApply, ErrRevisionConflict) {
			return errApply
		}
	}
	return nil
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
	return providerRequestForRecord(record, transport.Binding{Target: task.Target, Endpoint: task.Endpoint, Credential: task.Credential}, task.Definition, nil, nil)
}

// providerRequestForRecord builds one provider request with a Router-owned replay-stable idempotency identity.
// providerRequestForRecord 使用 Router 所有且重放稳定的幂等身份构建供应商请求。
// Parameters: record owns the immutable public request and execution identity; binding, definition, inputs, and workflow freeze the exact upstream target.
// 参数：record 拥有不可变公开请求与执行身份；binding、definition、inputs 与 workflow 冻结精确上游目标。
// Returns: a provider request whose private execution copy never forwards the caller's idempotency key upstream.
// 返回：一个使用私有执行副本且绝不向上游转发调用方幂等键的供应商请求。
func providerRequestForRecord(record Record, binding transport.Binding, definition providerconfig.ProviderDefinition, materialized []resource.MaterializedInput, workflow *provider.PreparedWorkflowBinding) provider.ExecutionRequest {
	request := record.Request
	request.IdempotencyKey = record.ID
	return provider.ExecutionRequest{Binding: binding, Definition: definition, Execution: &request, MaterializedInputs: materialized, LineageID: record.ID, Now: record.UpdatedAt, PreparedWorkflow: workflow}
}

// requiresProviderTask reports an async-only model execution contract.
// requiresProviderTask 表示仅异步模型执行合同。
func requiresProviderTask(target resolve.Target) bool {
	return target.SubjectKind == resolve.ExecutionSubjectModel && target.ModelCapabilities.Delivery.Asynchronous && !target.ModelCapabilities.Delivery.Synchronous
}

// resolveTarget maps the exact closed target selection into one resolver request.
// resolveTarget 将精确封闭 Target 选择映射为一个解析请求。
func (s *Service) resolveTarget(ctx context.Context, request vcp.ExecutionRequest, now time.Time, excludedCredentialIDs ...string) (resolve.Target, error) {
	resolution := resolve.Request{Operation: request.Operation, Now: now, ExcludedCredentialIDs: append([]string(nil), excludedCredentialIDs...)}
	return s.resolveTargetWithRequest(ctx, request, resolution)
}

// resolveTargetWithRequest completes one constrained same-provider resolution request from the immutable VCP selection.
// resolveTargetWithRequest 从不可变 VCP 选择补全一次受约束的同供应商解析请求。
func (s *Service) resolveTargetWithRequest(ctx context.Context, request vcp.ExecutionRequest, resolution resolve.Request) (resolve.Target, error) {
	if request.Target.Model != nil {
		resolution.ProviderInstanceID = request.Target.Model.ProviderInstanceID
		resolution.ProviderModelID = request.Target.Model.ProviderModelID
		resolution.ExecutionProfileID = request.Target.Model.ExecutionProfileID
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
	if !classifiedOK || semanticOutput || len(materialized) != 0 || preparedWorkflow != nil {
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
	record.Attempts = append(record.Attempts, attempt)
	if nextTarget != nil {
		record.Target = *nextTarget
	}
	record.UpdatedAt = s.options.Now().UTC()
	record.Revision++
	event := attemptCompletedEvent(record.ID, expectedRevision+1, record.UpdatedAt, attempt.Sequence)
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
	return result.Response.ResponseID != "" || result.Response.Status != "" || len(result.Response.Items) != 0 || len(result.Response.Citations) != 0 || result.Response.Usage != nil || result.Response.FinishReason != "" || result.Response.ErrorCode != "" || len(result.Response.Warnings) != 0 || len(result.Events) != 0 || result.UpstreamResponseID != "" || len(result.Embeddings) != 0 || len(result.Rerank) != 0 || result.Search != nil || result.Transcript != nil || result.MusicCoverPreparation != nil || len(result.GeneratedResources) != 0 || result.Report.ResponseID != "" || result.Report.ExecutionID != "" || result.Report.Usage != nil
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
	now := s.options.Now().UTC()
	record.Status = status
	record.Failure = failure
	if status.IsTerminal() {
		// ProviderTask is no longer needed after a confirmed terminal transition, allowing protected-handle cleanup.
		// ProviderTask 在确认进入终态后不再需要，从而允许清理受保护句柄。
		record.ProviderTask = nil
	}
	record.UpdatedAt = now
	record.Revision++
	event := lifecycleEvent(record.ID, expectedRevision+1, now, eventType, status, failure)
	if errSave := s.store.Save(ctx, record, expectedRevision, []Event{event}); errSave != nil {
		return Record{}, errSave
	}
	return record, nil
}

// appendLifecycle persists one real lifecycle event that does not change the current execution status.
// appendLifecycle 持久化一个不改变当前执行状态的真实生命周期事件。
func (s *Service) appendLifecycle(ctx context.Context, record Record, eventType EventType) (Record, error) {
	expectedRevision := record.Revision
	now := s.options.Now().UTC()
	record.UpdatedAt = now
	record.Revision++
	event := lifecycleEvent(record.ID, expectedRevision+1, now, eventType, record.Status, record.Failure)
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
	result := Result{Embeddings: append([]vcp.EmbeddingItem(nil), providerResult.Embeddings...), Rerank: append([]vcp.RerankResult(nil), providerResult.Rerank...), Search: providerResult.Search, Transcript: providerResult.Transcript, Resources: append([]resource.Resource(nil), resources...)}
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
	now := s.options.Now().UTC()
	events := make([]Event, 0, len(providerResult.Events)+1)
	sequence := expectedRevision + 1
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
	for _, generated := range resources {
		value := generated
		events = append(events, Event{ExecutionID: executionID, EventID: fmt.Sprintf("evt_%s_%d", executionID[4:], sequence), Sequence: sequence, Time: at, Type: EventResourceCompleted, Resource: &ResourceEvent{ResourceID: value.ID, Resource: &value}})
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

// fail commits one safe terminal failure.
// fail 提交一个安全终态失败。
func (s *Service) fail(ctx context.Context, record Record, code string, retryable bool) (Record, error) {
	failure := &Failure{Code: code, Retryable: retryable}
	return s.transition(ctx, record, StatusFailed, EventExecutionFailed, failure)
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
	switch {
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
	default:
		return "provider_execution_failed"
	}
}

// retryableFailure reports only known transient context deadlines; unknown provider errors remain non-retryable.
// retryableFailure 仅将已知瞬态 Context 超时标记为可重试；未知供应商错误保持不可重试。
func retryableFailure(errValue error) bool {
	return errors.Is(errValue, context.DeadlineExceeded)
}
