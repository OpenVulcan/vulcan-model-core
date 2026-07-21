// Package resolve builds immutable provider-scoped execution targets from configuration snapshots.
// Package resolve 从配置快照构建不可变的供应商作用域执行目标。
package resolve

import (
	"errors"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

var (
	// ErrInstanceNotExecutable reports a provider instance that is not ready for resolution.
	// ErrInstanceNotExecutable 表示供应商实例尚未准备好参与解析。
	ErrInstanceNotExecutable = errors.New("provider instance is not executable")
	// ErrModelNotFound reports a provider model outside the selected instance catalog.
	// ErrModelNotFound 表示所选实例目录中不存在供应商模型。
	ErrModelNotFound = errors.New("provider model not found")
	// ErrModelDisabled reports a provider model explicitly disabled by local management policy.
	// ErrModelDisabled 表示供应商模型被本地管理策略显式禁用。
	ErrModelDisabled = errors.New("provider model is disabled")
	// ErrServiceNotFound reports a provider service outside the selected instance catalog.
	// ErrServiceNotFound 表示所选实例目录中不存在供应商服务。
	ErrServiceNotFound = errors.New("provider service not found")
	// ErrServiceDisabled reports a provider service explicitly disabled by local management policy.
	// ErrServiceDisabled 表示供应商服务被本地管理策略显式禁用。
	ErrServiceDisabled = errors.New("provider service is disabled")
	// ErrProfileNotFound reports an absent or ambiguous execution profile.
	// ErrProfileNotFound 表示执行规格不存在或存在歧义。
	ErrProfileNotFound = errors.New("execution profile not found")
	// ErrNoEligibleTarget reports that no same-provider access target satisfies all constraints.
	// ErrNoEligibleTarget 表示没有同供应商访问目标满足全部约束。
	ErrNoEligibleTarget = errors.New("no eligible provider execution target")
)

// Request describes one exact provider-scoped target resolution request.
// Request 描述一次精确的供应商作用域目标解析请求。
type Request struct {
	// ProviderInstanceID fixes the provider boundary for the complete request.
	// ProviderInstanceID 固定整个请求的供应商边界。
	ProviderInstanceID string
	// ProviderModelID identifies one model inside the selected provider instance.
	// ProviderModelID 标识所选供应商实例内的一个模型。
	ProviderModelID string
	// ProviderServiceID identifies one service inside the selected provider instance.
	// ProviderServiceID 标识所选供应商实例内的一个服务。
	ProviderServiceID string
	// ServiceOfferingID selects one exact service implementation.
	// ServiceOfferingID 选择一个精确服务实现。
	ServiceOfferingID string
	// Operation identifies the exact requested VCP operation.
	// Operation 标识精确请求的 VCP 操作。
	Operation vcp.OperationKind
	// ExecutionProfileID optionally selects one client-visible capability shape.
	// ExecutionProfileID 可选地选择一个客户端可见能力形态。
	ExecutionProfileID string
	// RequiredContextTokens is the validated minimum context capacity required by the request.
	// RequiredContextTokens 是请求所需且已经校验的最小上下文容量。
	RequiredContextTokens int64
	// RequiredCapabilities lists normalized capability identifiers needed by the request.
	// RequiredCapabilities 列出请求需要的规范化能力标识。
	RequiredCapabilities []string
	// ExcludedCredentialIDs lists same-instance accounts already attempted by this logical execution.
	// ExcludedCredentialIDs 列出该逻辑执行已经尝试过的同实例账号。
	ExcludedCredentialIDs []string
	// RequiredCredentialID constrains endpoint failover to the credential that owned the failed attempt.
	// RequiredCredentialID 将入口故障切换限制在失败尝试所属的凭据内。
	RequiredCredentialID string
	// ExcludedEndpointIDs lists same-instance endpoints already attempted by this logical execution.
	// ExcludedEndpointIDs 列出该逻辑执行已经尝试过的同实例入口。
	ExcludedEndpointIDs []string
	// Now fixes time-dependent cooldown and snapshot evaluation.
	// Now 固定依赖时间的冷却和快照评估时刻。
	Now time.Time
}

// Diagnostics contains typed candidate counts and allowance blockers for one resolution attempt.
// Diagnostics 包含一次解析尝试的类型化候选数量和资源阻塞信息。
type Diagnostics struct {
	// ConfiguredCredentials is the total credential count in the selected instance.
	// ConfiguredCredentials 是所选实例中的凭据总数。
	ConfiguredCredentials int
	// BoundCandidates is the count with valid access bindings for the selected offering.
	// BoundCandidates 是对所选产品具有有效访问绑定的数量。
	BoundCandidates int
	// EntitledCandidates is the count authorized for the selected model and profile.
	// EntitledCandidates 是获得所选模型和规格授权的数量。
	EntitledCandidates int
	// CapabilityCandidates is the count satisfying context and capability requirements.
	// CapabilityCandidates 是满足上下文和能力要求的数量。
	CapabilityCandidates int
	// AllowanceCandidates is the count not blocked by mandatory consumable resources.
	// AllowanceCandidates 是未被强制可消费资源阻塞的数量。
	AllowanceCandidates int
	// ReadyCandidates is the final immediately executable target count.
	// ReadyCandidates 是最终可以立即执行的目标数量。
	ReadyCandidates int
	// BlockingAllowanceKinds lists unique resource shapes that blocked candidates.
	// BlockingAllowanceKinds 列出阻塞候选的唯一资源形态。
	BlockingAllowanceKinds []catalog.AllowanceKind
	// EarliestResetAt is the earliest known recovery time among blocked candidates.
	// EarliestResetAt 是阻塞候选中最早的已知恢复时间。
	EarliestResetAt *time.Time
}

// ContextAccountRuntimeStatus identifies why one model-context account is or is not immediately executable.
// ContextAccountRuntimeStatus 标识一个模型上下文账号为何能够或不能立即执行。
type ContextAccountRuntimeStatus string

const (
	// ContextAccountReady means the account has an eligible endpoint, authorization, allowance, and runtime state.
	// ContextAccountReady 表示账号具有合格入口、授权、额度与运行时状态。
	ContextAccountReady ContextAccountRuntimeStatus = "ready"
	// ContextAccountCooling means the account or one provider-owned runtime scope is temporarily cooling.
	// ContextAccountCooling 表示账号或某个供应商拥有的运行时作用域正在临时冷却。
	ContextAccountCooling ContextAccountRuntimeStatus = "cooling"
	// ContextAccountExhausted means a mandatory applicable allowance is exhausted.
	// ContextAccountExhausted 表示一个适用的强制额度已经耗尽。
	ContextAccountExhausted ContextAccountRuntimeStatus = "exhausted"
	// ContextAccountInvalid means the credential is disabled, expired, or invalid.
	// ContextAccountInvalid 表示凭据已禁用、过期或无效。
	ContextAccountInvalid ContextAccountRuntimeStatus = "invalid"
	// ContextAccountUnavailable means no currently ready provider-owned path exists.
	// ContextAccountUnavailable 表示当前不存在就绪的供应商所属路径。
	ContextAccountUnavailable ContextAccountRuntimeStatus = "unavailable"
)

// ModelContextAccountState describes one concrete credential authorized for one execution profile.
// ModelContextAccountState 描述一个获得某个执行规格授权的具体凭据。
type ModelContextAccountState struct {
	// CredentialID identifies the concrete local account without exposing secret material.
	// CredentialID 标识具体本地账号且不暴露秘密材料。
	CredentialID string
	// CredentialStatus is the persisted credential lifecycle state.
	// CredentialStatus 是持久化凭据生命周期状态。
	CredentialStatus providerconfig.CredentialStatus
	// Priority is the account scheduling priority; lower values win.
	// Priority 是账号调度优先级；较小值优先。
	Priority int
	// EntitlementClass is the provider-normalized commercial authorization class.
	// EntitlementClass 是供应商规范化商业授权类别。
	EntitlementClass string
	// EffectiveContextWindow is the smallest authoritative profile and account ceiling.
	// EffectiveContextWindow 是规格与账号权威上限中的最小值。
	EffectiveContextWindow catalog.OptionalTokenLimit
	// RuntimeStatus is the exact current execution eligibility class.
	// RuntimeStatus 是精确的当前执行资格类别。
	RuntimeStatus ContextAccountRuntimeStatus
	// CoolingUntil is the known credential recovery time when present.
	// CoolingUntil 是存在时已知的凭据恢复时间。
	CoolingUntil *time.Time
	// BlockingAllowanceKinds lists mandatory exhausted resource shapes.
	// BlockingAllowanceKinds 列出强制且已耗尽的资源形态。
	BlockingAllowanceKinds []catalog.AllowanceKind
	// EarliestResetAt is the earliest known allowance recovery time.
	// EarliestResetAt 是已知最早的额度恢复时间。
	EarliestResetAt *time.Time
}

// ModelContextState binds one exact execution profile to every authorized configured account.
// ModelContextState 将一个精确执行规格绑定到全部已授权配置账号。
type ModelContextState struct {
	// ProfileID identifies the exact client-selectable context shape.
	// ProfileID 标识精确且客户端可选择的上下文形态。
	ProfileID string
	// Accounts contains authorized accounts in deterministic scheduling order.
	// Accounts 包含按确定性调度顺序排列的已授权账号。
	Accounts []ModelContextAccountState
}

// Target is an immutable value snapshot of one exact same-provider execution destination.
// Target 是一个精确同供应商执行目标的不可变值快照。
type Target struct {
	// ProviderDefinitionID identifies the system or custom provider definition.
	// ProviderDefinitionID 标识系统或自定义供应商定义。
	ProviderDefinitionID string
	// ProviderInstanceID fixes the provider instance boundary.
	// ProviderInstanceID 固定供应商实例边界。
	ProviderInstanceID string
	// ChannelID identifies the selected provider channel.
	// ChannelID 标识所选供应商通道。
	ChannelID string
	// EndpointID identifies the selected endpoint.
	// EndpointID 标识所选端点。
	EndpointID string
	// EndpointRegion is the provider-defined region that constrains asset validity.
	// EndpointRegion 是约束资产有效性的供应商定义区域。
	EndpointRegion string
	// CredentialID identifies the selected credential.
	// CredentialID 标识所选凭据。
	CredentialID string
	// SubjectKind identifies whether this target owns a model or a special service.
	// SubjectKind 标识此 Target 拥有模型还是特殊服务。
	SubjectKind ExecutionSubjectKind
	// ProviderModelID identifies the selected logical model.
	// ProviderModelID 标识所选逻辑模型。
	ProviderModelID string
	// ProviderServiceID identifies the selected logical service.
	// ProviderServiceID 标识所选逻辑服务。
	ProviderServiceID string
	// OfferingID identifies the selected channel-specific model offering.
	// OfferingID 标识所选通道特定模型产品。
	OfferingID string
	// ServiceOfferingID identifies the selected channel-specific service offering.
	// ServiceOfferingID 标识所选通道特定服务产品。
	ServiceOfferingID string
	// Operation identifies the exact VCP operation.
	// Operation 标识精确 VCP 操作。
	Operation vcp.OperationKind
	// ActionBindingID identifies the exact code-owned provider action.
	// ActionBindingID 标识精确代码拥有供应商动作。
	ActionBindingID string
	// ExecutionProfileID identifies the selected client-visible capability shape.
	// ExecutionProfileID 标识所选客户端可见能力形态。
	ExecutionProfileID string
	// UpstreamModelID is the exact model identifier sent by a future protocol adapter.
	// UpstreamModelID 是未来协议 Adapter 发送的精确模型标识。
	UpstreamModelID string
	// UpstreamServiceID is the exact safe service, engine, or model handle sent by the adapter.
	// UpstreamServiceID 是 Adapter 发送的精确安全服务、引擎或模型句柄。
	UpstreamServiceID string
	// ServiceCapabilities contains the selected special-service capability ceiling.
	// ServiceCapabilities 包含所选特殊服务能力上限。
	ServiceCapabilities *catalog.ServiceCapabilities
	// EffectiveContextWindow is the smallest authoritative profile and account ceiling.
	// EffectiveContextWindow 是规格和账号权威上限中的最小值。
	EffectiveContextWindow catalog.OptionalTokenLimit
	// TokenLimits contains the selected profile's independently known hard token ceilings.
	// TokenLimits 包含所选规格独立已知的硬 Token 上限。
	TokenLimits catalog.TokenLimits
	// TokenRecommendations contains the selected profile's provider-evidenced defaults.
	// TokenRecommendations 包含所选规格由供应商证据支持的默认值。
	TokenRecommendations catalog.TokenRecommendations
	// ModelCapabilities contains the exact selected execution profile contract.
	// ModelCapabilities 包含精确选定执行规格契约。
	ModelCapabilities catalog.ModelCapabilities
	// RequestProjection contains the selected offering's immutable outbound parameter rules.
	// RequestProjection 包含所选产品不可变的出站参数规则。
	RequestProjection catalog.RequestProjection
	// ProviderAdditionalParameters contains provider-wide request mutations applied before model-specific rules.
	// ProviderAdditionalParameters 包含在模型专属规则前应用的供应商级请求变更。
	ProviderAdditionalParameters catalog.AdditionalPayloadProjection
	// CapabilityRevision records the capability evidence used for resolution.
	// CapabilityRevision 记录解析使用的能力证据修订号。
	CapabilityRevision uint64
	// ProviderConfigRevision records the provider instance configuration revision.
	// ProviderConfigRevision 记录供应商实例配置修订号。
	ProviderConfigRevision uint64
	// CatalogRevision records the atomic catalog revision.
	// CatalogRevision 记录原子目录修订号。
	CatalogRevision uint64
}

// ExecutionSubjectKind identifies the sole catalog subject selected for execution.
// ExecutionSubjectKind 标识为执行选定的唯一目录主体。
type ExecutionSubjectKind string

const (
	// ExecutionSubjectModel selects a provider model and model offering.
	// ExecutionSubjectModel 选择供应商模型及模型产品。
	ExecutionSubjectModel ExecutionSubjectKind = "model"
	// ExecutionSubjectService selects a provider service and service offering.
	// ExecutionSubjectService 选择供应商服务及服务产品。
	ExecutionSubjectService ExecutionSubjectKind = "service"
)
