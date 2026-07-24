//! Generated-source boundary for VCP 1.0 consumers.
//! VCP 1.0 消费方的生成源边界。

use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: &str = "1.0";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DispatchMode {
    Inline,
    Deferred,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryBackoff {
    Fixed,
    Exponential,
}

/// One coordinate in an ordered computer drag path.
/// 有序计算机拖动路径中的一个坐标。
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ComputerPoint {
    pub x: i32,
    pub y: i32,
}

/// Closed mouse button set accepted by computer click actions.
/// 计算机点击动作接受的封闭鼠标按钮集合。
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComputerButton {
    Left,
    Right,
    Wheel,
    Back,
    Forward,
}

/// Exact field union for one provider-requested computer action.
/// 一个供应商请求计算机动作的精确字段联合。
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ComputerAction {
    Click {
        x: i32,
        y: i32,
        button: ComputerButton,
        keys: Option<Vec<String>>,
    },
    DoubleClick {
        x: i32,
        y: i32,
        keys: Option<Vec<String>>,
    },
    Drag {
        path: Vec<ComputerPoint>,
        keys: Option<Vec<String>>,
    },
    Move {
        x: i32,
        y: i32,
        keys: Option<Vec<String>>,
    },
    Scroll {
        x: i32,
        y: i32,
        scroll_x: i32,
        scroll_y: i32,
        keys: Option<Vec<String>>,
    },
    Keypress {
        keys: Vec<String>,
    },
    Type {
        text: String,
    },
    Wait,
    Screenshot,
}

/// Router resource returned after executing a provider computer call.
/// 执行供应商计算机调用后返回的 Router 资源。
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ComputerScreenshotResult {
    pub resource_ref: String,
    pub detail: String,
}

/// Golden caller-loop fixture containing one action batch and its screenshot result.
/// 包含一个动作批次及其截图结果的 Golden 调用方循环夹具。
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ComputerLoopFixture {
    pub actions: Vec<ComputerAction>,
    pub result: ComputerScreenshotResult,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RetryPolicy {
    pub backoff: Option<RetryBackoff>,
    pub initial_delay_milliseconds: Option<i64>,
    pub maximum_delay_milliseconds: Option<i64>,
    pub multiplier: Option<f64>,
    pub max_attempts: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperationBudget {
    pub max_input_bytes: Option<i64>,
    pub max_output_bytes: Option<i64>,
    pub max_execution_milliseconds: Option<i64>,
    pub max_provider_tasks: Option<i32>,
}

/// Closed VCP operation discriminator.
/// 封闭的 VCP 操作判别符。
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum OperationKind {
    #[serde(rename = "conversation.respond")]
    ConversationRespond,
    #[serde(rename = "media.analyze")]
    MediaAnalyze,
    #[serde(rename = "image.generate")]
    ImageGenerate,
    #[serde(rename = "image.edit")]
    ImageEdit,
    #[serde(rename = "video.generate")]
    VideoGenerate,
    #[serde(rename = "video.edit")]
    VideoEdit,
    #[serde(rename = "video.extend")]
    VideoExtend,
    #[serde(rename = "speech.synthesize")]
    SpeechSynthesize,
    #[serde(rename = "speech.transcribe")]
    SpeechTranscribe,
    #[serde(rename = "embedding.create")]
    EmbeddingCreate,
    #[serde(rename = "rerank.documents")]
    RerankDocuments,
    #[serde(rename = "search.web")]
    SearchWeb,
    #[serde(rename = "web.extract")]
    WebExtract,
    #[serde(rename = "music.generate")]
    MusicGenerate,
    #[serde(rename = "music.cover.prepare")]
    MusicCoverPrepare,
    #[serde(rename = "music.cover")]
    MusicCover,
}

/// Closed standard model tool understood by every VCP client.
/// 每个 VCP 客户端都能理解的封闭标准模型工具。
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StandardModelToolKind {
    WebSearch,
    WebExtractor,
}

/// Explicit execution source selected for one standard model tool.
/// 为一个标准模型工具显式选择的执行来源。
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelToolMode {
    Disabled,
    Native,
    RouterTool,
}

/// Closed operation-backed Router enhancement identifier.
/// 封闭且由操作支持的 Router 增强能力标识。
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouterExtensionKind {
    ImageUnderstanding,
    AudioUnderstanding,
    VideoUnderstanding,
    ImageGeneration,
    VideoGeneration,
    SpeechGeneration,
    SpeechTranscription,
}

/// One explicit standard model-tool selection.
/// 一项显式标准模型工具选择。
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StandardModelToolSelection {
    pub kind: StandardModelToolKind,
    pub mode: ModelToolMode,
}

/// Complete model-tool selection carried by a conversation operation.
/// 会话操作携带的完整模型工具选择。
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ModelToolSelection {
    pub standard: Option<Vec<StandardModelToolSelection>>,
    pub extra: Option<Vec<String>>,
    pub router_extensions: Option<Vec<RouterExtensionKind>>,
}

/// One frozen standard model-tool execution decision.
/// 一项冻结的标准模型工具执行决策。
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ModelToolPlanEntry {
    pub kind: StandardModelToolKind,
    pub mode: ModelToolMode,
    pub router_binding_id: Option<String>,
    pub router_binding_revision: Option<u64>,
}

/// One frozen operation-backed Router enhancement decision.
/// 一项冻结且由操作支持的 Router 增强决策。
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RouterExtensionPlanEntry {
    pub id: RouterExtensionKind,
    pub router_binding_id: String,
    pub router_binding_revision: u64,
}

/// One safe compatibility or planning diagnostic attached to a frozen model-tool plan.
/// 一个附加到冻结模型工具计划的安全兼容或规划诊断。
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ModelToolDiagnostic {
    pub code: ModelToolDiagnosticCode,
}

/// Closed model-tool diagnostic codes.
/// 封闭的模型工具诊断代码。
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum ModelToolDiagnosticCode {
    #[serde(rename = "legacy_native_web_search_migrated")]
    LegacyNativeWebSearchMigrated,
}

/// Public immutable model-tool plan accepted with one durable execution.
/// 随一个持久执行接收的公开不可变模型工具计划。
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ModelToolPlan {
    pub catalog_revision: u64,
    pub standard: Option<Vec<ModelToolPlanEntry>>,
    pub extra: Option<Vec<String>>,
    pub router_extensions: Option<Vec<RouterExtensionPlanEntry>>,
    pub diagnostics: Option<Vec<ModelToolDiagnostic>>,
}

/// Public parent relationship for one Router-created child execution.
/// 一个 Router 创建子执行的公开父级关系。
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RouterToolLineage {
    pub parent_execution_id: String,
    pub parent_tool_call_id: String,
    pub parent_round: u32,
    pub binding_id: String,
}

/// Exact operation payload member selected by the JSON Schema discriminator.
/// 由 JSON Schema 判别器选择的精确操作载荷成员。
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationPayload<
    TConversation,
    TMediaAnalyze,
    TImageGenerate,
    TImageEdit,
    TVideoGenerate,
    TVideoEdit,
    TVideoExtend,
    TSpeechSynthesize,
    TSpeechTranscribe,
    TEmbeddingCreate,
    TRerankDocuments,
    TSearchWeb,
    TWebExtract,
    TMusicGenerate,
    TMusicCoverPrepare,
    TMusicCover,
> {
    Conversation(TConversation),
    MediaAnalyze(TMediaAnalyze),
    ImageGenerate(TImageGenerate),
    ImageEdit(TImageEdit),
    VideoGenerate(TVideoGenerate),
    VideoEdit(TVideoEdit),
    VideoExtend(TVideoExtend),
    SpeechSynthesize(TSpeechSynthesize),
    SpeechTranscribe(TSpeechTranscribe),
    EmbeddingCreate(TEmbeddingCreate),
    RerankDocuments(TRerankDocuments),
    SearchWeb(TSearchWeb),
    WebExtract(TWebExtract),
    MusicGenerate(TMusicGenerate),
    MusicCoverPrepare(TMusicCoverPrepare),
    MusicCover(TMusicCover),
}

/// Exact model selection without a provider candidate list.
/// 不包含供应商候选列表的精确模型选择。
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ModelTarget {
    pub target: String,
    pub provider_instance_id: Option<String>,
    pub provider_model_id: Option<String>,
    pub execution_profile_id: Option<String>,
    pub required_region: Option<String>,
}

/// Exact service selection owned by one provider instance.
/// 由一个供应商实例拥有的精确服务选择。
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ServiceTarget {
    pub provider_instance_id: String,
    pub provider_service_id: String,
    pub service_offering_id: Option<String>,
    pub execution_profile_id: Option<String>,
}

/// Closed model-or-service target union.
/// 封闭的模型或服务 Target 联合体。
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum TargetSelection {
    Model { model: ModelTarget },
    Service { service: ServiceTarget },
}

/// One Router resource assignment for a previously frozen input plan.
/// 一个先前冻结 Input Plan 的 Router 资源赋值。
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputPlanResourceAssignment {
    pub input_id: String,
    pub resource_id: String,
}

/// Caller-authorized resource projection preferences.
/// 调用方授权的资源投影偏好。
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResourceProjectionPolicy {
    #[serde(default)]
    pub allow_frame_sequence: bool,
    #[serde(default)]
    pub allow_audio_track: bool,
    #[serde(default)]
    pub allow_transcode: bool,
}

/// VCP execution request whose payload type must be generated from operation-payload.schema.json.
/// VCP 执行请求，其载荷类型必须由 operation-payload.schema.json 生成。
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExecutionRequest<TPayload> {
    pub protocol_version: String,
    pub request_id: String,
    pub idempotency_key: Option<String>,
    pub input_plan_id: Option<String>,
    pub input_plan_resources: Option<Vec<InputPlanResourceAssignment>>,
    pub target: TargetSelection,
    pub operation: OperationKind,
    pub stream: bool,
    pub dispatch_mode: Option<DispatchMode>,
    pub payload: TPayload,
    pub projection_policy: ResourceProjectionPolicy,
    pub budget: OperationBudget,
    pub retry_policy: Option<RetryPolicy>,
}

/// Provider-scoped preselection requirements without a cross-provider candidate list.
/// 不包含跨供应商候选列表的供应商作用域预选要求。
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExecutionSelectionRequest {
    pub protocol_version: String,
    pub request_id: String,
    pub provider_instance_id: String,
    pub operation: OperationKind,
    pub required_context_tokens: Option<i64>,
    pub required_max_output_tokens: Option<i64>,
    pub required_input_modalities: Option<Vec<String>>,
    pub required_output_modalities: Option<Vec<String>>,
    pub required_capabilities: Option<Vec<String>>,
    pub preferred_capabilities: Option<Vec<String>>,
    pub preferred_model_ids: Option<Vec<String>>,
    pub required_region: Option<String>,
}

/// Safe exact target selected before mutable endpoint and credential resolution.
/// 在可变入口与凭据解析前选出的安全精确 Target。
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExecutionSelectionResponse {
    pub request_id: String,
    pub target: TargetSelection,
    pub operation: OperationKind,
    pub effective_context_tokens: Option<i64>,
    pub capability_revision: u64,
    pub catalog_revision: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    Accepted,
    PreparingInputs,
    Queued,
    Running,
    WaitingRetry,
    Succeeded,
    PartiallySucceeded,
    Failed,
    Cancelled,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorScope {
    Request,
    Credential,
    Subscription,
    BillingAccount,
    Endpoint,
    Model,
    Provider,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryAction {
    Stop,
    RetrySameTarget,
    RetryOtherCredential,
    RetryOtherEndpoint,
    RetryAfterReset,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RetryState {
    pub consecutive_failures: u32,
    pub next_retry_at: String,
    pub category: String,
    pub scope: ErrorScope,
    pub action: RetryAction,
    pub max_attempts: Option<u32>,
}

/// Safe provider-classified terminal failure.
/// 安全的供应商分类终态失败。
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExecutionFailure {
    pub code: String,
    pub retryable: bool,
    pub category: Option<String>,
    pub scope: Option<ErrorScope>,
    pub retry_action: Option<RetryAction>,
    pub retry_after_milliseconds: Option<i64>,
    pub next_retry_at: Option<String>,
    pub attempt: u32,
    pub max_attempts: Option<u32>,
    pub router_request_id: String,
    pub target_summary: String,
    pub provider_request_id: Option<String>,
}

/// Public durable execution record whose result type is generated from execution-result.schema.json.
/// 公开持久执行记录，其结果类型由 execution-result.schema.json 生成。
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExecutionRecord<TResult> {
    pub id: String,
    pub status: ExecutionStatus,
    pub operation: OperationKind,
    pub model_tool_plan: ModelToolPlan,
    pub router_tool_lineage: Option<RouterToolLineage>,
    pub result: Option<TResult>,
    pub failure: Option<ExecutionFailure>,
    pub retry: Option<RetryState>,
    pub retry_cycles: Option<u32>,
    pub created_at: String,
    pub updated_at: String,
    pub expires_at: String,
    pub revision: u64,
}

/// Shared replay identity flattened into every durable event variant.
/// 扁平化到每个持久事件变体中的共享重放身份。
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExecutionEventIdentity {
    pub execution_id: String,
    pub event_id: String,
    pub sequence: u64,
    pub time: String,
}

/// Lifecycle status and optional terminal failure.
/// 生命周期状态与可选终态失败。
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LifecycleEvent {
    pub status: ExecutionStatus,
    pub failure: Option<ExecutionFailure>,
}

/// Safe ordinal of one completed private provider attempt.
/// 一次已完成私有供应商尝试的安全序号。
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AttemptEvent {
    pub sequence: u32,
}

/// Durable retry scheduler event facts.
/// 持久重试调度器事件事实。
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RetryEvent {
    pub attempt: u32,
    pub next_retry_at: Option<String>,
    pub category: Option<String>,
}

/// Closed parent-visible lifecycle stage for one enabled model tool.
/// 一个已启用模型工具在父执行中可见的封闭生命周期阶段。
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelToolEventStage {
    Enabled,
    ModeFrozen,
    RouterCallStarted,
    ChildCreated,
    ChildCompleted,
    ChildFailed,
    ResultInjected,
    ParentResumed,
}

/// Safe parent model-tool transition without arguments, credentials, or provider-private errors.
/// 不含参数、凭据或供应商私有错误的安全父执行模型工具转换。
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ModelToolEvent {
    pub tool_id: String,
    pub stage: ModelToolEventStage,
    pub mode: ModelToolMode,
    pub tool_call_id: Option<String>,
    pub child_execution_id: Option<String>,
    pub round: Option<u32>,
}

/// Provider-reported progress without fabricated percentages.
/// 不虚构百分比的供应商报告进度。
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProgressEvent {
    pub current: Option<i64>,
    pub total: Option<i64>,
    pub unit: Option<String>,
    pub percent: Option<f64>,
}

/// Partial byte progress or one completed Router resource.
/// 部分字节进度或一个已完成 Router 资源。
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResourceEvent {
    pub output_id: String,
    pub resource_id: Option<String>,
    pub kind: Option<ResourceKind>,
    pub mime_type: Option<String>,
    pub partial_bytes: Option<i64>,
    pub resource: Option<Resource>,
}

/// One actual upstream search query.
/// 一个真实上游搜索查询。
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SearchQueryEvent {
    pub query: String,
}

/// One actual upstream search answer delta or completion.
/// 一个真实上游搜索答案增量或完成值。
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SearchAnswerEvent {
    pub text: String,
}

/// One independently replayable usage metric.
/// 一个可独立重放的用量指标。
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UsageEvent {
    pub unit: String,
    pub value: f64,
    pub accuracy: String,
    pub source: String,
    pub aggregation: String,
    pub phase: String,
    pub accounting_basis: String,
    #[serde(rename = "final")]
    pub final_: bool,
}

/// Closed exact-payload durable event union; generated component types remain explicit generic parameters.
/// 封闭的唯一载荷持久事件联合；生成的组件类型保持为明确泛型参数。
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum ExecutionEvent<TProviderEvent, TTranscript, TEmbedding, TRerank, TSearchResult, TCitation>
{
    #[serde(rename = "execution.accepted")]
    ExecutionAccepted {
        #[serde(flatten)]
        identity: ExecutionEventIdentity,
        lifecycle: LifecycleEvent,
    },
    #[serde(rename = "input.materialization.started")]
    InputMaterializationStarted {
        #[serde(flatten)]
        identity: ExecutionEventIdentity,
        lifecycle: LifecycleEvent,
    },
    #[serde(rename = "input.materialization.completed")]
    InputMaterializationCompleted {
        #[serde(flatten)]
        identity: ExecutionEventIdentity,
        lifecycle: LifecycleEvent,
    },
    #[serde(rename = "execution.queued")]
    ExecutionQueued {
        #[serde(flatten)]
        identity: ExecutionEventIdentity,
        lifecycle: LifecycleEvent,
    },
    #[serde(rename = "execution.running")]
    ExecutionRunning {
        #[serde(flatten)]
        identity: ExecutionEventIdentity,
        lifecycle: LifecycleEvent,
    },
    #[serde(rename = "execution.cancellation.requested")]
    ExecutionCancellationRequested {
        #[serde(flatten)]
        identity: ExecutionEventIdentity,
        lifecycle: LifecycleEvent,
    },
    #[serde(rename = "execution.attempt.completed")]
    ExecutionAttemptCompleted {
        #[serde(flatten)]
        identity: ExecutionEventIdentity,
        attempt: AttemptEvent,
    },
    #[serde(rename = "retry.scheduled")]
    RetryScheduled {
        #[serde(flatten)]
        identity: ExecutionEventIdentity,
        retry: RetryEvent,
    },
    #[serde(rename = "retry.started")]
    RetryStarted {
        #[serde(flatten)]
        identity: ExecutionEventIdentity,
        retry: RetryEvent,
    },
    #[serde(rename = "retry.succeeded")]
    RetrySucceeded {
        #[serde(flatten)]
        identity: ExecutionEventIdentity,
        retry: RetryEvent,
    },
    #[serde(rename = "retry.aborted")]
    RetryAborted {
        #[serde(flatten)]
        identity: ExecutionEventIdentity,
        retry: RetryEvent,
    },
    #[serde(rename = "provider.semantic")]
    ProviderSemantic {
        #[serde(flatten)]
        identity: ExecutionEventIdentity,
        provider_event: TProviderEvent,
    },
    #[serde(rename = "model_tool.lifecycle")]
    ModelToolLifecycle {
        #[serde(flatten)]
        identity: ExecutionEventIdentity,
        model_tool: ModelToolEvent,
    },
    #[serde(rename = "progress.updated")]
    ProgressUpdated {
        #[serde(flatten)]
        identity: ExecutionEventIdentity,
        progress: ProgressEvent,
    },
    #[serde(rename = "resource.partial")]
    ResourcePartial {
        #[serde(flatten)]
        identity: ExecutionEventIdentity,
        resource: ResourceEvent,
    },
    #[serde(rename = "resource.completed")]
    ResourceCompleted {
        #[serde(flatten)]
        identity: ExecutionEventIdentity,
        resource: ResourceEvent,
    },
    #[serde(rename = "transcript.segment")]
    TranscriptSegment {
        #[serde(flatten)]
        identity: ExecutionEventIdentity,
        transcript: TTranscript,
    },
    #[serde(rename = "embedding.item.completed")]
    EmbeddingItemCompleted {
        #[serde(flatten)]
        identity: ExecutionEventIdentity,
        embedding: TEmbedding,
    },
    #[serde(rename = "rerank.result.completed")]
    RerankResultCompleted {
        #[serde(flatten)]
        identity: ExecutionEventIdentity,
        rerank: TRerank,
    },
    #[serde(rename = "search.query.started")]
    SearchQueryStarted {
        #[serde(flatten)]
        identity: ExecutionEventIdentity,
        search_query: SearchQueryEvent,
    },
    #[serde(rename = "search.result.completed")]
    SearchResultCompleted {
        #[serde(flatten)]
        identity: ExecutionEventIdentity,
        search_result: TSearchResult,
    },
    #[serde(rename = "search.answer.delta")]
    SearchAnswerDelta {
        #[serde(flatten)]
        identity: ExecutionEventIdentity,
        search_answer: SearchAnswerEvent,
    },
    #[serde(rename = "search.answer.completed")]
    SearchAnswerCompleted {
        #[serde(flatten)]
        identity: ExecutionEventIdentity,
        search_answer: SearchAnswerEvent,
    },
    #[serde(rename = "citation.completed")]
    CitationCompleted {
        #[serde(flatten)]
        identity: ExecutionEventIdentity,
        citation: TCitation,
    },
    #[serde(rename = "usage.updated")]
    UsageUpdated {
        #[serde(flatten)]
        identity: ExecutionEventIdentity,
        usage: UsageEvent,
    },
    #[serde(rename = "execution.succeeded")]
    ExecutionSucceeded {
        #[serde(flatten)]
        identity: ExecutionEventIdentity,
        lifecycle: LifecycleEvent,
    },
    #[serde(rename = "execution.partially_succeeded")]
    ExecutionPartiallySucceeded {
        #[serde(flatten)]
        identity: ExecutionEventIdentity,
        lifecycle: LifecycleEvent,
    },
    #[serde(rename = "execution.failed")]
    ExecutionFailed {
        #[serde(flatten)]
        identity: ExecutionEventIdentity,
        lifecycle: LifecycleEvent,
    },
    #[serde(rename = "execution.cancelled")]
    ExecutionCancelled {
        #[serde(flatten)]
        identity: ExecutionEventIdentity,
        lifecycle: LifecycleEvent,
    },
    #[serde(rename = "execution.expired")]
    ExecutionExpired {
        #[serde(flatten)]
        identity: ExecutionEventIdentity,
        lifecycle: LifecycleEvent,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Continuation {
    pub continuation_id: String,
    pub logical_response_id: String,
    pub affinity_summary: String,
    pub expires_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UsageObservation {
    pub service_units: Option<f64>,
    pub service_unit: Option<String>,
    pub input_tokens: Option<i64>,
    pub output_tokens: Option<i64>,
    pub reasoning_tokens: Option<i64>,
    pub cache_read_tokens: Option<i64>,
    pub cache_creation_tokens: Option<i64>,
    pub total_tokens: Option<i64>,
    pub source: String,
    pub aggregation: String,
    pub phase: String,
    pub accounting_basis: String,
    #[serde(rename = "final")]
    pub final_: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreflightAccuracy {
    Exact,
    Estimated,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PreflightMetric {
    pub unit: String,
    pub value: Option<f64>,
    pub accuracy: PreflightAccuracy,
    pub accounting_basis: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UsagePreflightResponse<TTarget> {
    pub protocol_version: String,
    pub request_id: String,
    pub target: TTarget,
    pub model_tool_plan: ModelToolPlan,
    pub usage: UsageObservation,
    pub metrics: Vec<PreflightMetric>,
}

/// Closed information projection selector used by POST /vulcan/v1/info.
/// POST /vulcan/v1/info 使用的封闭信息投影选择器。
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InformationKind {
    Instances,
    Models,
    Accounts,
    Services,
    Usage,
    Catalog,
}

/// Strong information request whose selectors are validated against the selected branch.
/// 强类型信息请求，其选择器会根据所选分支进行校验。
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InformationRequest {
    pub get: InformationKind,
    pub provider_instance_id: Option<String>,
    pub provider_model_id: Option<String>,
    pub credential_id: Option<String>,
    pub provider_service_id: Option<String>,
    pub after_revision: Option<u64>,
    pub limit: Option<u32>,
}

/// One authoritative model or service removal from a dynamic replacement snapshot.
/// 动态替换快照中的一条权威模型或服务删除记录。
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CatalogTombstone {
    pub kind: String,
    pub id: String,
    pub removed_at: String,
}

/// One globally ordered catalog invalidation fact.
/// 一条全局有序目录失效事实。
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CatalogChange {
    pub global_revision: u64,
    pub provider_instance_id: String,
    pub provider_revision: u64,
    #[serde(rename = "type")]
    pub change_type: String,
    pub observed_at: String,
    pub source_revision: Option<String>,
    pub etag: Option<String>,
    pub refresh_status: Option<String>,
    pub tombstones: Option<Vec<CatalogTombstone>>,
}

/// One incremental catalog page and the latest committed revision.
/// 一个增量目录页及最新已提交修订。
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CatalogChangePage {
    pub current_revision: u64,
    pub changes: Vec<CatalogChange>,
}

/// Catalog branch of the closed information-response union.
/// 封闭信息响应联合中的目录分支。
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CatalogInformationResponse {
    pub get: InformationKind,
    pub catalog: CatalogChangePage,
}

/// Closed information response whose non-catalog branches are generated from information-response.schema.json.
/// 封闭信息响应，其非目录分支由 information-response.schema.json 生成。
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum InformationResponse<TInstances, TModels, TAccounts, TServices, TUsage> {
    Instances(TInstances),
    Models(TModels),
    Accounts(TAccounts),
    Services(TServices),
    Usage(TUsage),
    Catalog(CatalogInformationResponse),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Image,
    Audio,
    Video,
    File,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Resource {
    pub id: String,
    pub kind: ResourceKind,
    pub mime_type: String,
    pub size_bytes: i64,
    pub sha256: String,
    pub source: String,
    pub state: String,
    pub retention: String,
    pub created_at: String,
    pub updated_at: String,
    pub expires_at: Option<String>,
    pub revision: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VcpError {
    pub error: String,
    pub code: String,
    pub tool_id: Option<String>,
    pub phase: Option<String>,
    pub retryable: Option<bool>,
    pub protocol_minimum: String,
    pub protocol_maximum: String,
}

#[cfg(test)]
mod golden_fixture_tests {
    use super::*;
    use serde_json::Value;

    /// Parses the canonical execution request through the public Rust boundary.
    /// 通过公开 Rust 边界解析规范执行请求。
    #[test]
    fn parses_execution_request_fixture() {
        let request: ExecutionRequest<Value> =
            serde_json::from_str(include_str!("../fixtures/execution-request.json"))
                .expect("execution fixture must match the Rust contract");
        assert_eq!(request.protocol_version, PROTOCOL_VERSION);
        assert!(matches!(
            request.operation,
            OperationKind::ConversationRespond
        ));
    }

    /// Parses the closed durable event union without losing its discriminator.
    /// 解析封闭持久事件联合且不丢失其判别符。
    #[test]
    fn parses_execution_event_fixture() {
        type GoldenEvent = ExecutionEvent<Value, Value, Value, Value, Value, Value>;
        let event: GoldenEvent =
            serde_json::from_str(include_str!("../fixtures/execution-event.json"))
                .expect("event fixture must match the Rust contract");
        assert!(matches!(event, ExecutionEvent::UsageUpdated { .. }));
    }

    /// Parses durable execution, retry, continuation, usage, resource, and error fixtures.
    /// 解析持久执行、重试、续接、用量、资源与错误夹具。
    #[test]
    fn parses_public_state_fixtures() {
        let record: ExecutionRecord<Value> =
            serde_json::from_str(include_str!("../fixtures/execution-record.json"))
                .expect("record fixture must match the Rust contract");
        let retry: RetryState = serde_json::from_str(include_str!("../fixtures/retry-state.json"))
            .expect("retry fixture must match the Rust contract");
        let continuation: Continuation =
            serde_json::from_str(include_str!("../fixtures/continuation.json"))
                .expect("continuation fixture must match the Rust contract");
        let usage: UsageObservation =
            serde_json::from_str(include_str!("../fixtures/usage-observation.json"))
                .expect("usage fixture must match the Rust contract");
        let resource: Resource = serde_json::from_str(include_str!("../fixtures/resource.json"))
            .expect("resource fixture must match the Rust contract");
        let error: VcpError = serde_json::from_str(include_str!("../fixtures/error.json"))
            .expect("error fixture must match the Rust contract");
        assert!(matches!(record.status, ExecutionStatus::Succeeded));
        assert!(retry.consecutive_failures > 0);
        assert!(!continuation.continuation_id.is_empty());
        assert!(usage.final_);
        assert!(resource.size_bytes >= 0);
        assert_eq!(error.protocol_minimum, PROTOCOL_VERSION);
    }

    /// Parses provider-exact or explicitly inexact preflight output used before execution.
    /// 解析执行前使用的供应商精确或显式非精确预检输出。
    #[test]
    fn parses_usage_preflight_fixture() {
        let response: UsagePreflightResponse<Value> =
            serde_json::from_str(include_str!("../fixtures/usage-preflight-response.json"))
                .expect("preflight fixture must match the Rust contract");
        assert_eq!(response.protocol_version, PROTOCOL_VERSION);
        assert!(!response.metrics.is_empty());
    }

    /// Parses both exact model and exact service preselection targets.
    /// 解析精确模型与精确服务两种预选 Target。
    #[test]
    fn parses_selection_fixtures() {
        let request: ExecutionSelectionRequest =
            serde_json::from_str(include_str!("../fixtures/selection-request.json"))
                .expect("selection request fixture must match the Rust contract");
        let model: ExecutionSelectionResponse =
            serde_json::from_str(include_str!("../fixtures/selection-model-response.json"))
                .expect("model selection fixture must match the Rust contract");
        let service: ExecutionSelectionResponse =
            serde_json::from_str(include_str!("../fixtures/selection-service-response.json"))
                .expect("service selection fixture must match the Rust contract");
        assert_eq!(request.protocol_version, PROTOCOL_VERSION);
        assert!(matches!(model.target, TargetSelection::Model { .. }));
        assert!(matches!(service.target, TargetSelection::Service { .. }));
    }

    /// Parses the exact computer action and screenshot caller-loop contract.
    /// 解析精确的计算机动作与截图调用方循环契约。
    #[test]
    fn parses_computer_loop_fixture() {
        let fixture: ComputerLoopFixture =
            serde_json::from_str(include_str!("../fixtures/computer-loop.json"))
                .expect("computer loop fixture must match the Rust contract");
        assert_eq!(fixture.actions.len(), 3);
        assert_eq!(fixture.result.detail, "original");
    }
}
