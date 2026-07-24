// Package catalog defines provider-scoped models, execution profiles, entitlements, and allowances.
// Package catalog 定义供应商作用域的模型、执行规格、授权和可消费资源。
package catalog

import (
	"encoding/json"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// CapabilityLevel describes how one model capability is supported.
// CapabilityLevel 描述一项模型能力的支持方式。
type CapabilityLevel string

const (
	// CapabilityNative means the upstream offering supports the capability directly.
	// CapabilityNative 表示上游产品原生支持该能力。
	CapabilityNative CapabilityLevel = "native"
	// CapabilityEmulated means the core can emulate the capability with declared semantic differences.
	// CapabilityEmulated 表示 Core 可以在声明语义差异后模拟该能力。
	CapabilityEmulated CapabilityLevel = "emulated"
	// CapabilityUnsupported means the capability is explicitly unavailable.
	// CapabilityUnsupported 表示能力明确不可用。
	CapabilityUnsupported CapabilityLevel = "unsupported"
	// CapabilityConditional means availability depends on entitlement or runtime conditions.
	// CapabilityConditional 表示可用性取决于授权或运行时条件。
	CapabilityConditional CapabilityLevel = "conditional"
	// CapabilityUnknown means no reliable evidence is available.
	// CapabilityUnknown 表示没有可靠证据。
	CapabilityUnknown CapabilityLevel = "unknown"
)

// AvailabilityStatus describes entitlement or runtime availability.
// AvailabilityStatus 描述授权或运行时可用性。
type AvailabilityStatus string

const (
	// AvailabilityAllowed means execution is authorized.
	// AvailabilityAllowed 表示执行已获得授权。
	AvailabilityAllowed AvailabilityStatus = "allowed"
	// AvailabilityDenied means execution is explicitly not authorized.
	// AvailabilityDenied 表示执行被明确禁止。
	AvailabilityDenied AvailabilityStatus = "denied"
	// AvailabilityConditional means execution requires additional conditions.
	// AvailabilityConditional 表示执行需要额外条件。
	AvailabilityConditional AvailabilityStatus = "conditional"
	// AvailabilityUnknown means no reliable authorization evidence is available.
	// AvailabilityUnknown 表示没有可靠授权证据。
	AvailabilityUnknown AvailabilityStatus = "unknown"
	// AvailabilityTemporarilyUnavailable means authorization exists but cannot execute now.
	// AvailabilityTemporarilyUnavailable 表示授权存在但当前不可执行。
	AvailabilityTemporarilyUnavailable AvailabilityStatus = "temporarily_unavailable"
)

// ModelSource describes the evidence source for a model or entitlement record.
// ModelSource 描述模型或授权记录的证据来源。
type ModelSource string

const (
	// ModelSourceSystem identifies trusted code-owned model metadata.
	// ModelSourceSystem 标识受信任的代码拥有模型元数据。
	ModelSourceSystem ModelSource = "system"
	// ModelSourceProviderAPI identifies metadata returned by an upstream provider API.
	// ModelSourceProviderAPI 标识上游供应商 API 返回的元数据。
	ModelSourceProviderAPI ModelSource = "provider_api"
	// ModelSourceCredentialDiscovery identifies account-specific model discovery.
	// ModelSourceCredentialDiscovery 标识账号特定的模型发现。
	ModelSourceCredentialDiscovery ModelSource = "credential_discovery"
	// ModelSourceRuntimeEvidence identifies a trusted provider-specific runtime rule.
	// ModelSourceRuntimeEvidence 标识受信任的供应商特定运行时规则。
	ModelSourceRuntimeEvidence ModelSource = "runtime_evidence"
	// ModelSourceUserDeclared identifies custom-provider metadata supplied by a user.
	// ModelSourceUserDeclared 标识用户提供的自定义供应商元数据。
	ModelSourceUserDeclared ModelSource = "user_declared"
)

// MetadataEvidenceSource identifies the authority behind commercial account metadata.
// MetadataEvidenceSource 标识商业账号元数据背后的权威来源。
type MetadataEvidenceSource string

const (
	// MetadataEvidenceProviderAPI identifies a provider account or usage API response.
	// MetadataEvidenceProviderAPI 标识供应商账号或用量 API 响应。
	MetadataEvidenceProviderAPI MetadataEvidenceSource = "provider_api"
	// MetadataEvidenceProtectedTokenClaim identifies a verified claim inside protected credentials.
	// MetadataEvidenceProtectedTokenClaim 标识受保护凭据中的已验证声明。
	MetadataEvidenceProtectedTokenClaim MetadataEvidenceSource = "protected_token_claim"
	// MetadataEvidenceOperatorDeclared identifies one explicit code-constrained operator selection.
	// MetadataEvidenceOperatorDeclared 标识一个受代码约束的显式操作员选择。
	MetadataEvidenceOperatorDeclared MetadataEvidenceSource = "operator_declared"
	// MetadataEvidenceSystemRule identifies immutable product rules maintained by the Router.
	// MetadataEvidenceSystemRule 标识由 Router 维护的不可变产品规则。
	MetadataEvidenceSystemRule MetadataEvidenceSource = "system_rule"
	// MetadataEvidenceRuntimeObservation identifies a trusted classified execution result.
	// MetadataEvidenceRuntimeObservation 标识一个可信的已分类执行结果。
	MetadataEvidenceRuntimeObservation MetadataEvidenceSource = "runtime_observation"
)

// AuthorizationStatus describes provider-evidenced model or service access without collapsing unknown into denial.
// AuthorizationStatus 描述供应商证据支持的模型或服务访问状态，且不会把未知折叠为拒绝。
type AuthorizationStatus string

const (
	// AuthorizationAuthorized means at least one account has current affirmative evidence.
	// AuthorizationAuthorized 表示至少一个账号拥有当前有效的肯定证据。
	AuthorizationAuthorized AuthorizationStatus = "authorized"
	// AuthorizationDenied means current provider evidence explicitly rejects every configured account.
	// AuthorizationDenied 表示当前供应商证据明确拒绝全部已配置账号。
	AuthorizationDenied AuthorizationStatus = "denied"
	// AuthorizationUnknown means no current authoritative evidence proves allowance or denial.
	// AuthorizationUnknown 表示没有当前权威证据证明允许或拒绝。
	AuthorizationUnknown AuthorizationStatus = "unknown"
)

// EntitlementMode describes how credentials become eligible for one provider model.
// EntitlementMode 描述凭据如何获得一个供应商模型的执行资格。
type EntitlementMode string

const (
	// EntitlementAllBoundCredentials allows every otherwise valid access binding.
	// EntitlementAllBoundCredentials 允许全部其他条件有效的访问绑定。
	EntitlementAllBoundCredentials EntitlementMode = "all_bound_credentials"
	// EntitlementExplicit requires an explicit credential model entitlement.
	// EntitlementExplicit 要求存在显式凭据模型授权。
	EntitlementExplicit EntitlementMode = "explicit"
)

// ProfileSwitchPolicy describes whether a conversation can change execution profiles.
// ProfileSwitchPolicy 描述会话是否可以切换执行规格。
type ProfileSwitchPolicy string

const (
	// ProfileSwitchSeamless allows profile changes without replay or session reset.
	// ProfileSwitchSeamless 允许不重放或重置会话地切换规格。
	ProfileSwitchSeamless ProfileSwitchPolicy = "seamless"
	// ProfileSwitchReplayRequired requires a complete stateless history replay.
	// ProfileSwitchReplayRequired 要求完整无状态历史重放。
	ProfileSwitchReplayRequired ProfileSwitchPolicy = "replay_required"
	// ProfileSwitchNewSession requires a new upstream session.
	// ProfileSwitchNewSession 要求创建新的上游会话。
	ProfileSwitchNewSession ProfileSwitchPolicy = "new_session_required"
	// ProfileSwitchUnsupported forbids profile changes for an active conversation.
	// ProfileSwitchUnsupported 禁止活动会话切换规格。
	ProfileSwitchUnsupported ProfileSwitchPolicy = "unsupported"
)

// PoolPolicy describes how credentials with different capability ceilings are selected.
// PoolPolicy 描述如何选择具有不同能力上限的凭据。
type PoolPolicy string

const (
	// PoolPreferSmallestSufficient preserves scarce high-capability credentials.
	// PoolPreferSmallestSufficient 保护稀缺的高能力凭据。
	PoolPreferSmallestSufficient PoolPolicy = "prefer_smallest_sufficient"
	// PoolStrictProfile limits execution to credentials explicitly entitled to the chosen profile.
	// PoolStrictProfile 将执行限制为明确获得所选规格授权的凭据。
	PoolStrictProfile PoolPolicy = "strict_profile"
)

// OptionalTokenLimit represents a known positive limit or an explicitly unknown value.
// OptionalTokenLimit 表示一个已知正数限制或显式未知值。
type OptionalTokenLimit struct {
	// Known reports whether Value is authoritative.
	// Known 表示 Value 是否具有权威性。
	Known bool
	// Value is the positive token limit when Known is true.
	// Value 是 Known 为真时的正数 Token 限制。
	Value int64
}

// TokenLimits describes independently sourced model token ceilings under one fixed shared-window semantic.
// TokenLimits 以固定共享窗口语义描述独立来源的模型 Token 上限。
type TokenLimits struct {
	// ContextWindow is the conservative total ceiling shared by input, reasoning, and generated output.
	// ContextWindow 是输入、推理和生成输出共同占用的保守总上限。
	ContextWindow OptionalTokenLimit
	// MaxInputTokens is the explicit input ceiling when independently known.
	// MaxInputTokens 是独立已知时的明确输入上限。
	MaxInputTokens OptionalTokenLimit
	// MaxOutputTokens is the explicit output ceiling when independently known.
	// MaxOutputTokens 是独立已知时的明确输出上限。
	MaxOutputTokens OptionalTokenLimit
	// MaxReasoningTokens is the explicit reasoning ceiling when independently known.
	// MaxReasoningTokens 是独立已知时的明确推理上限。
	MaxReasoningTokens OptionalTokenLimit
}

// TokenRecommendations describes provider-evidenced defaults that remain subordinate to hard token limits.
// TokenRecommendations 描述由供应商证据支持且始终服从硬 Token 上限的默认值。
type TokenRecommendations struct {
	// OutputTokens is the recommended generated-output budget when the caller omits one.
	// OutputTokens 是调用方未指定时建议采用的生成输出预算。
	OutputTokens OptionalTokenLimit
	// ReasoningTokens is the recommended reasoning budget when the caller omits one.
	// ReasoningTokens 是调用方未指定时建议采用的推理预算。
	ReasoningTokens OptionalTokenLimit
}

// ModelCapabilities describes client-visible capabilities of one offering or profile.
// ModelCapabilities 描述一个产品或规格的客户端可见能力。
type ModelCapabilities struct {
	// Tokens contains independent model token ceilings.
	// Tokens 包含独立的模型 Token 上限。
	Tokens TokenLimits
	// Recommendations contains provider-evidenced defaults and never changes hard ceilings.
	// Recommendations 包含供应商证据支持的默认值，且绝不改变硬上限。
	Recommendations TokenRecommendations
	// ToolCalling describes function or tool call support.
	// ToolCalling 描述函数或工具调用支持。
	ToolCalling CapabilityLevel
	// ParallelToolCalls describes parallel tool call support.
	// ParallelToolCalls 描述并行工具调用支持。
	ParallelToolCalls CapabilityLevel
	// StreamingToolArguments describes incremental tool argument support.
	// StreamingToolArguments 描述增量工具参数支持。
	StreamingToolArguments CapabilityLevel
	// StrictJSONSchema describes strict structured output support.
	// StrictJSONSchema 描述严格结构化输出支持。
	StrictJSONSchema CapabilityLevel
	// Reasoning describes reasoning control and output support.
	// Reasoning 描述推理控制和输出支持。
	Reasoning CapabilityLevel
	// ReasoningEfforts lists exact accepted request effort values when reasoning control is callable.
	// ReasoningEfforts 列出推理控制可调用时接受的精确请求强度值。
	ReasoningEfforts []string
	// ReasoningSummaryModes lists exact visible reasoning summary values accepted by the offering.
	// ReasoningSummaryModes 列出该产品接受的精确可见推理摘要值。
	ReasoningSummaryModes []string
	// InputModalities lists normalized accepted input modality identifiers.
	// InputModalities 列出规范化的输入模态标识。
	InputModalities []string
	// OutputModalities lists normalized produced output modality identifiers.
	// OutputModalities 列出规范化的输出模态标识。
	OutputModalities []string
	// MediaInputs contains typed per-media input contracts.
	// MediaInputs 包含按媒体类型定义的类型化输入合同。
	MediaInputs []MediaInputCapability
	// Delivery declares real synchronous, streaming, asynchronous, and partial delivery.
	// Delivery 声明真实同步、流式、异步和部分结果交付。
	Delivery DeliveryCapabilities
	// Embedding contains vectorization constraints only for embedding profiles.
	// Embedding 仅为 Embedding Profile 包含向量化约束。
	Embedding *EmbeddingCapabilities
	// Rerank contains ranking constraints only for rerank profiles.
	// Rerank 仅为 Rerank Profile 包含排序约束。
	Rerank *RerankCapabilities
	// MediaOutputs contains typed generated-media contracts.
	// MediaOutputs 包含类型化生成媒体合同。
	MediaOutputs []MediaOutputCapability
	// Parameters contains closed operation parameter descriptors.
	// Parameters 包含封闭操作参数描述。
	Parameters []ParameterDescriptor
	// ParameterRules contains typed cross-parameter conditions.
	// ParameterRules 包含类型化跨参数条件。
	ParameterRules []ParameterRule
	// UsageMetrics lists independently observable usage dimensions.
	// UsageMetrics 列出可独立观察的用量维度。
	UsageMetrics []UsageMetricCapability
	// StandardTools lists verified provider-native implementations of closed Vulcan model tools.
	// StandardTools 列出封闭 Vulcan 模型工具经过验证的供应商原生实现。
	StandardTools []StandardModelToolCapability
	// ExtraTools lists profile-scoped non-standard provider or model tools.
	// ExtraTools 列出规格作用域的非标准供应商或模型工具。
	ExtraTools []ModelExtraToolCapability
	// HostedTools lists exact provider-hosted tool kinds supported by this profile.
	// HostedTools 列出此规格支持的精确供应商托管工具类型。
	HostedTools []vcp.ToolKind
}

// PayloadParameter assigns one validated JSON value to an exact upstream JSON path.
// PayloadParameter 将一个已校验 JSON 值赋给精确的上游 JSON 路径。
type PayloadParameter struct {
	// Path is a tidwall/sjson-compatible JSON path owned by configuration.
	// Path 是由配置拥有且兼容 tidwall/sjson 的 JSON 路径。
	Path string `json:"path"`
	// Value is the exact JSON scalar, object, array, or null written at Path.
	// Value 是写入 Path 的精确 JSON 标量、对象、数组或 null。
	Value json.RawMessage `json:"value"`
}

// ReasoningParameterRule maps one canonical reasoning value to exact upstream mutations.
// ReasoningParameterRule 将一个规范推理值映射为精确的上游变更。
type ReasoningParameterRule struct {
	// Value is the canonical effort or summary value selected by the caller.
	// Value 是调用方选择的规范强度或摘要值。
	Value string `json:"value"`
	// Set contains exact assignments applied for this value.
	// Set 包含为此值应用的精确赋值。
	Set []PayloadParameter `json:"set,omitempty"`
	// Delete contains exact paths removed for this value.
	// Delete 包含为此值删除的精确路径。
	Delete []string `json:"delete,omitempty"`
}

// ReasoningRequestProjection describes configurable canonical-to-upstream reasoning mappings.
// ReasoningRequestProjection 描述可配置的规范推理到上游参数映射。
type ReasoningRequestProjection struct {
	// Effort maps each supported canonical effort to its exact upstream representation.
	// Effort 将每个受支持的规范强度映射为精确上游表示。
	Effort []ReasoningParameterRule `json:"effort,omitempty"`
	// Summary maps each supported visible summary mode to its exact upstream representation.
	// Summary 将每个受支持的可见摘要模式映射为精确上游表示。
	Summary []ReasoningParameterRule `json:"summary,omitempty"`
}

// AdditionalPayloadProjection applies explicit CLIProxyAPI-style defaults, overrides, and removals.
// AdditionalPayloadProjection 应用显式的 CLIProxyAPI 风格默认值、覆盖值与删除项。
type AdditionalPayloadProjection struct {
	// Default assigns a value only when the typed protocol projection omitted the path.
	// Default 仅在类型化协议投影未生成该路径时赋值。
	Default []PayloadParameter `json:"default,omitempty"`
	// Override replaces the typed protocol projection at the exact configured path.
	// Override 在精确配置路径覆盖类型化协议投影。
	Override []PayloadParameter `json:"override,omitempty"`
	// Filter removes exact paths after every assignment has completed.
	// Filter 在全部赋值完成后删除精确路径。
	Filter []string `json:"filter,omitempty"`
}

// RequestProjection contains model-offering-specific outbound request customization.
// RequestProjection 包含模型产品专属的出站请求定制。
type RequestProjection struct {
	// Reasoning contains canonical reasoning parameter mappings.
	// Reasoning 包含规范推理参数映射。
	Reasoning ReasoningRequestProjection `json:"reasoning"`
	// Additional contains operator-declared non-core payload parameters.
	// Additional 包含操作员声明的非核心载荷参数。
	Additional AdditionalPayloadProjection `json:"additional"`
}

// ProviderModel describes one logical model within one provider instance.
// ProviderModel 描述一个供应商实例内的逻辑模型。
type ProviderModel struct {
	// ID is the immutable provider-scoped model identifier.
	// ID 是不可变的供应商作用域模型标识。
	ID string
	// ProviderInstanceID owns the model.
	// ProviderInstanceID 是拥有该模型的供应商实例。
	ProviderInstanceID string
	// UpstreamModelID is the exact model identifier used by the provider.
	// UpstreamModelID 是供应商使用的精确模型标识。
	UpstreamModelID string
	// DisplayName is the client-visible model name.
	// DisplayName 是客户端可见的模型名称。
	DisplayName string
	// Source records the model evidence source.
	// Source 记录模型证据来源。
	Source ModelSource
	// EntitlementMode determines whether explicit account authorization is required.
	// EntitlementMode 决定是否要求显式账号授权。
	EntitlementMode EntitlementMode
	// Revision is the immutable model catalog revision.
	// Revision 是不可变的模型目录修订号。
	Revision uint64
}

// ModelOffering binds one provider model to a channel and capability baseline.
// ModelOffering 将一个供应商模型绑定到通道和能力基线。
type ModelOffering struct {
	// ID is the immutable offering identifier.
	// ID 是不可变的产品标识。
	ID string
	// ProviderInstanceID owns the offering.
	// ProviderInstanceID 是拥有该产品的供应商实例。
	ProviderInstanceID string
	// ProviderModelID references one model in the same provider instance.
	// ProviderModelID 引用同一供应商实例中的一个模型。
	ProviderModelID string
	// ChannelID identifies the upstream provider channel.
	// ChannelID 标识上游供应商通道。
	ChannelID string
	// UpstreamModelID overrides the logical model identifier for this channel when necessary.
	// UpstreamModelID 必要时覆盖该通道的逻辑模型标识。
	UpstreamModelID string
	// Capabilities contains the channel-specific model baseline.
	// Capabilities 包含通道特定的模型能力基线。
	Capabilities ModelCapabilities
	// RequestProjection contains provider-channel-specific outbound parameter rules.
	// RequestProjection 包含供应商通道专属的出站参数规则。
	RequestProjection RequestProjection
	// CapabilityRevision identifies the capability evidence revision.
	// CapabilityRevision 标识能力证据修订号。
	CapabilityRevision uint64
	// Revision is the immutable offering catalog revision.
	// Revision 是不可变的产品目录修订号。
	Revision uint64
}

// ExecutionProfile describes one client-selectable capability shape of an offering.
// ExecutionProfile 描述一个产品的客户端可选择能力形态。
type ExecutionProfile struct {
	// ID is the immutable profile identifier.
	// ID 是不可变的规格标识。
	ID string
	// ProviderInstanceID owns the profile.
	// ProviderInstanceID 是拥有该规格的供应商实例。
	ProviderInstanceID string
	// OfferingID references one offering in the same provider instance.
	// OfferingID 引用同一供应商实例中的一个产品。
	OfferingID string
	// ServiceOfferingID references one service offering in the same provider instance.
	// ServiceOfferingID 引用同一供应商实例中的一个服务产品。
	ServiceOfferingID string
	// Operation identifies the exact executable VCP operation.
	// Operation 标识精确可执行 VCP 操作。
	Operation vcp.OperationKind
	// ActionBindingID identifies one code-owned provider action binding.
	// ActionBindingID 标识一个代码拥有的供应商动作绑定。
	ActionBindingID string
	// ProfileDriver declares that this conversation profile executes through the immutable provider definition's primary profile Driver instead of an ActionBinding.
	// ProfileDriver 声明此会话规格通过不可变供应商定义的主 Profile Driver 执行，而不是通过 ActionBinding 执行。
	ProfileDriver bool
	// DisplayName is the client-visible profile name.
	// DisplayName 是客户端可见的规格名称。
	DisplayName string
	// Default reports whether clients may omit an explicit profile selection.
	// Default 表示客户端是否可以省略显式规格选择。
	Default bool
	// Capabilities contains the effective profile capability ceiling.
	// Capabilities 包含该规格的有效能力上限。
	Capabilities ModelCapabilities
	// ServiceCapabilities contains the effective special-service capability ceiling.
	// ServiceCapabilities 包含特殊服务的有效能力上限。
	ServiceCapabilities *ServiceCapabilities
	// RequiredEntitlementClasses lists account classes permitted to use the profile.
	// RequiredEntitlementClasses 列出允许使用该规格的账号授权类别。
	RequiredEntitlementClasses []string
	// SwitchPolicy describes active-conversation profile switching behavior.
	// SwitchPolicy 描述活动会话的规格切换行为。
	SwitchPolicy ProfileSwitchPolicy
	// PoolPolicy describes credential selection within the profile.
	// PoolPolicy 描述规格内部的凭据选择方式。
	PoolPolicy PoolPolicy
	// CapabilityRevision identifies the capability evidence revision.
	// CapabilityRevision 标识能力证据修订号。
	CapabilityRevision uint64
	// Revision is the immutable profile catalog revision.
	// Revision 是不可变的规格目录修订号。
	Revision uint64
}

// ModelOperationSupportStatus identifies whether one exact offering operation is published by the Router.
// ModelOperationSupportStatus 标识 Router 是否发布一个精确 Offering 操作。
type ModelOperationSupportStatus string

const (
	// ModelOperationSupported means the operation is verified, implemented, and eligible for profile publication.
	// ModelOperationSupported 表示该操作已验证、已实现且可发布执行规格。
	ModelOperationSupported ModelOperationSupportStatus = "supported"
	// ModelOperationUnsupported means the operation is retained as catalog evidence but not published.
	// ModelOperationUnsupported 表示该操作作为目录证据保留，但明确不发布。
	ModelOperationUnsupported ModelOperationSupportStatus = "unsupported"
	// ModelOperationPendingReview means evidence exists but is insufficient for a publication decision.
	// ModelOperationPendingReview 表示已有证据但不足以作出发布决策。
	ModelOperationPendingReview ModelOperationSupportStatus = "pending_review"
)

// ModelOperationSupportReason identifies one closed reason behind an operation publication decision.
// ModelOperationSupportReason 标识操作发布决策背后的一个封闭原因。
type ModelOperationSupportReason string

const (
	// SupportReasonRuntimeVerified records a repeatable runtime execution fixture.
	// SupportReasonRuntimeVerified 记录可重复的运行时执行夹具。
	SupportReasonRuntimeVerified ModelOperationSupportReason = "runtime_verified"
	// SupportReasonProviderContractVerified records a verified provider contract without live execution.
	// SupportReasonProviderContractVerified 记录已验证但未实时执行的供应商合同。
	SupportReasonProviderContractVerified ModelOperationSupportReason = "provider_contract_verified"
	// SupportReasonProviderInferenceDisabled records an upstream inference-disabled model.
	// SupportReasonProviderInferenceDisabled 记录上游已禁用推理的模型。
	SupportReasonProviderInferenceDisabled ModelOperationSupportReason = "provider_inference_disabled"
	// SupportReasonOperationNotImplemented records a VCP operation not implemented by the Router.
	// SupportReasonOperationNotImplemented 记录 Router 尚未实现的 VCP 操作。
	SupportReasonOperationNotImplemented ModelOperationSupportReason = "operation_not_implemented"
	// SupportReasonCodingCapabilityInsufficient records a model that fails the verified coding capability boundary.
	// SupportReasonCodingCapabilityInsufficient 记录未通过已验证 Coding 能力边界的模型。
	SupportReasonCodingCapabilityInsufficient ModelOperationSupportReason = "coding_capability_insufficient"
	// SupportReasonDeprecatedOrSuperseded records an explicitly deprecated or superseded model.
	// SupportReasonDeprecatedOrSuperseded 记录已明确弃用或被替代的模型。
	SupportReasonDeprecatedOrSuperseded ModelOperationSupportReason = "deprecated_or_superseded"
	// SupportReasonOutOfScopeRealtime records a realtime operation excluded from the current scope.
	// SupportReasonOutOfScopeRealtime 记录当前范围明确排除的实时操作。
	SupportReasonOutOfScopeRealtime ModelOperationSupportReason = "out_of_scope_realtime"
	// SupportReasonOutOfScopeProduct records an upstream product outside the current scope.
	// SupportReasonOutOfScopeProduct 记录当前范围之外的上游产品。
	SupportReasonOutOfScopeProduct ModelOperationSupportReason = "out_of_scope_product"
	// SupportReasonMissingProtocolEvidence records a missing exact wire-contract mapping.
	// SupportReasonMissingProtocolEvidence 记录缺少精确 Wire 合同映射。
	SupportReasonMissingProtocolEvidence ModelOperationSupportReason = "missing_protocol_evidence"
	// SupportReasonMissingParameterMapping records incomplete request-parameter evidence.
	// SupportReasonMissingParameterMapping 记录不完整的请求参数证据。
	SupportReasonMissingParameterMapping ModelOperationSupportReason = "missing_parameter_mapping"
	// SupportReasonMissingExecutionFixture records a missing repeatable execution fixture.
	// SupportReasonMissingExecutionFixture 记录缺少可重复执行夹具。
	SupportReasonMissingExecutionFixture ModelOperationSupportReason = "missing_execution_fixture"
	// SupportReasonNewCatalogEntry records a newly discovered operation awaiting review.
	// SupportReasonNewCatalogEntry 记录等待审核的新发现操作。
	SupportReasonNewCatalogEntry ModelOperationSupportReason = "new_catalog_entry"
)

// ModelOperationPolicy records the code-owned publication decision for one offering operation.
// ModelOperationPolicy 记录代码拥有的一个 Offering 操作发布决策。
type ModelOperationPolicy struct {
	// ID is the immutable policy identifier.
	// ID 是不可变的策略标识。
	ID string
	// ProviderInstanceID owns the policy.
	// ProviderInstanceID 是拥有该策略的供应商实例。
	ProviderInstanceID string
	// ProviderModelID identifies the classified model.
	// ProviderModelID 标识被分类的模型。
	ProviderModelID string
	// OfferingID identifies the exact provider channel offering.
	// OfferingID 标识精确的供应商通道 Offering。
	OfferingID string
	// Operation identifies the classified VCP operation.
	// Operation 标识被分类的 VCP 操作。
	Operation vcp.OperationKind
	// Status controls whether an execution profile may be published.
	// Status 控制是否可以发布执行规格。
	Status ModelOperationSupportStatus
	// Reason records the closed evidence-backed decision reason.
	// Reason 记录由证据支持的封闭决策原因。
	Reason ModelOperationSupportReason
	// Source records the policy evidence source.
	// Source 记录策略证据来源。
	Source ModelSource
	// EvidenceRevision identifies provider evidence independently from schema changes.
	// EvidenceRevision 独立于 Schema 变更标识供应商证据版本。
	EvidenceRevision uint64
	// Revision is the immutable policy revision.
	// Revision 是不可变的策略修订号。
	Revision uint64
}

// ModelEntitlement describes one credential's model and profile authorization.
// ModelEntitlement 描述一个凭据的模型和规格授权。
type ModelEntitlement struct {
	// ID is the immutable entitlement identifier.
	// ID 是不可变的授权标识。
	ID string
	// ProviderInstanceID owns the entitlement.
	// ProviderInstanceID 是拥有该授权的供应商实例。
	ProviderInstanceID string
	// CredentialID identifies the authorized account or key.
	// CredentialID 标识获得授权的账号或 Key。
	CredentialID string
	// ProviderModelID identifies the authorized model.
	// ProviderModelID 标识获得授权的模型。
	ProviderModelID string
	// Availability is the current authorization state.
	// Availability 是当前授权状态。
	Availability AvailabilityStatus
	// EntitlementClass is the provider-normalized capability class.
	// EntitlementClass 是供应商规范化后的能力类别。
	EntitlementClass string
	// AllowedProfileIDs optionally restricts this credential to explicit profiles.
	// AllowedProfileIDs 可选地将该凭据限制到显式规格。
	AllowedProfileIDs []string
	// LimitOverrides contains account-specific token ceilings.
	// LimitOverrides 包含账号特定的 Token 上限。
	LimitOverrides TokenLimits
	// Source records the authorization evidence source.
	// Source 记录授权证据来源。
	Source ModelSource
	// EvidenceSource identifies how the commercial authorization fact was obtained.
	// EvidenceSource 标识商业授权事实的获取方式。
	EvidenceSource MetadataEvidenceSource
	// ObservedAt records when the authorization evidence was obtained.
	// ObservedAt 记录获得授权证据的时间。
	ObservedAt time.Time
	// ExpiresAt records when the authorization snapshot becomes stale.
	// ExpiresAt 记录授权快照失效时间。
	ExpiresAt time.Time
	// Revision is the immutable entitlement snapshot revision.
	// Revision 是不可变的授权快照修订号。
	Revision uint64
}

// PlanSnapshot describes provider-reported commercial plan metadata for one credential.
// PlanSnapshot 描述供应商为一个凭据报告的商业套餐元数据。
type PlanSnapshot struct {
	// ID is the immutable plan snapshot identifier.
	// ID 是不可变的套餐快照标识。
	ID string
	// ProviderInstanceID owns the snapshot.
	// ProviderInstanceID 是拥有该快照的供应商实例。
	ProviderInstanceID string
	// CredentialID identifies the account whose plan was observed.
	// CredentialID 标识观测到套餐的账号。
	CredentialID string
	// PlanCode is the provider-normalized commercial plan code.
	// PlanCode 是供应商规范化后的商业套餐代码。
	PlanCode string
	// PlanName is the provider-facing display name.
	// PlanName 是供应商显示名称。
	PlanName string
	// Status is the provider-normalized plan lifecycle state.
	// Status 是供应商规范化后的套餐生命周期状态。
	Status string
	// EvidenceSource identifies how this commercial plan was obtained.
	// EvidenceSource 标识该商业套餐的获取方式。
	EvidenceSource MetadataEvidenceSource
	// ObservedAt records when the plan was obtained.
	// ObservedAt 记录获得套餐的时间。
	ObservedAt time.Time
	// ExpiresAt records when the plan snapshot becomes stale.
	// ExpiresAt 记录套餐快照失效时间。
	ExpiresAt time.Time
	// Revision is the immutable plan snapshot revision.
	// Revision 是不可变的套餐快照修订号。
	Revision uint64
}

// AllowanceKind identifies one consumable resource shape.
// AllowanceKind 标识一种可消费资源形态。
type AllowanceKind string

const (
	// AllowanceWindowQuota identifies a time-window quota.
	// AllowanceWindowQuota 标识时间窗口额度。
	AllowanceWindowQuota AllowanceKind = "window_quota"
	// AllowanceBalance identifies a monetary or provider-credit balance.
	// AllowanceBalance 标识货币或供应商 Credit 余额。
	AllowanceBalance AllowanceKind = "balance"
	// AllowanceCreditGrant identifies a credit grant with optional expiry.
	// AllowanceCreditGrant 标识带可选有效期的 Credit Grant。
	AllowanceCreditGrant AllowanceKind = "credit_grant"
	// AllowanceProviderDefined identifies an opaque provider-defined consumable resource.
	// AllowanceProviderDefined 标识不透明的供应商自定义可消费资源。
	AllowanceProviderDefined AllowanceKind = "provider_defined"
)

// AllowanceScope identifies which upstream entity owns a consumable resource.
// AllowanceScope 标识哪个上游实体拥有可消费资源。
type AllowanceScope string

const (
	// ScopeCredential applies an allowance to one credential.
	// ScopeCredential 将资源应用于一个凭据。
	ScopeCredential AllowanceScope = "credential"
	// ScopeSubscription applies an allowance to a shared subscription.
	// ScopeSubscription 将资源应用于共享订阅。
	ScopeSubscription AllowanceScope = "subscription"
	// ScopeOrganization applies an allowance to an organization.
	// ScopeOrganization 将资源应用于组织。
	ScopeOrganization AllowanceScope = "organization"
	// ScopeProject applies an allowance to a project.
	// ScopeProject 将资源应用于项目。
	ScopeProject AllowanceScope = "project"
	// ScopeBillingAccount applies an allowance to a shared billing account.
	// ScopeBillingAccount 将资源应用于共享计费账号。
	ScopeBillingAccount AllowanceScope = "billing_account"
	// ScopeProviderModel applies an allowance to one provider model.
	// ScopeProviderModel 将资源应用于一个供应商模型。
	ScopeProviderModel AllowanceScope = "provider_model"
	// ScopeExecutionProfile applies an allowance to one execution profile.
	// ScopeExecutionProfile 将资源应用于一个执行规格。
	ScopeExecutionProfile AllowanceScope = "execution_profile"
	// ScopeCapability applies an allowance to one provider capability.
	// ScopeCapability 将资源应用于一项供应商能力。
	ScopeCapability AllowanceScope = "capability"
)

// AllowanceStatus describes current resource availability.
// AllowanceStatus 描述当前资源可用性。
type AllowanceStatus string

const (
	// AllowanceAvailable means the resource does not currently block execution.
	// AllowanceAvailable 表示资源当前不阻塞执行。
	AllowanceAvailable AllowanceStatus = "available"
	// AllowanceUnlimited means the provider explicitly reports no finite consumption ceiling.
	// AllowanceUnlimited 表示供应商明确报告不存在有限消费上限。
	AllowanceUnlimited AllowanceStatus = "unlimited"
	// AllowanceLow means the resource remains usable but is close to exhaustion.
	// AllowanceLow 表示资源仍可使用但接近耗尽。
	AllowanceLow AllowanceStatus = "low"
	// AllowanceExhausted means the resource blocks execution.
	// AllowanceExhausted 表示资源阻塞执行。
	AllowanceExhausted AllowanceStatus = "exhausted"
	// AllowanceUnknownSufficiency means the resource amount is known but request sufficiency is unknown.
	// AllowanceUnknownSufficiency 表示资源数量已知但请求是否充足未知。
	AllowanceUnknownSufficiency AllowanceStatus = "unknown_sufficiency"
	// AllowanceUnavailable means the provider could not return current resource state.
	// AllowanceUnavailable 表示供应商无法返回当前资源状态。
	AllowanceUnavailable AllowanceStatus = "unavailable"
	// AllowanceNotIncluded means the provider explicitly reports that the resource is absent from the current plan.
	// AllowanceNotIncluded 表示供应商明确报告当前套餐不包含该资源。
	AllowanceNotIncluded AllowanceStatus = "not_included"
)

// AllowanceUnit identifies the accounting unit of one consumable resource.
// AllowanceUnit 标识一种可消费资源的计量单位。
type AllowanceUnit string

const (
	// UnitTokens identifies token accounting.
	// UnitTokens 标识 Token 计量。
	UnitTokens AllowanceUnit = "tokens"
	// UnitRequests identifies request-count accounting.
	// UnitRequests 标识请求次数计量。
	UnitRequests AllowanceUnit = "requests"
	// UnitWeightedTokens identifies provider-defined weighted token accounting.
	// UnitWeightedTokens 标识供应商定义的加权 Token 计量。
	UnitWeightedTokens AllowanceUnit = "weighted_tokens"
	// UnitProviderCredits identifies provider credits without a known currency conversion.
	// UnitProviderCredits 标识没有已知货币换算关系的供应商 Credit。
	UnitProviderCredits AllowanceUnit = "provider_credits"
	// UnitMinorCurrency identifies integer minor currency units such as cents.
	// UnitMinorCurrency 标识分等货币最小整数单位。
	UnitMinorCurrency AllowanceUnit = "minor_currency_units"
	// UnitPercentage identifies a provider-reported percentage-only resource.
	// UnitPercentage 标识供应商只报告百分比的资源。
	UnitPercentage AllowanceUnit = "percentage"
	// UnitProviderDefined identifies an opaque provider-defined accounting unit.
	// UnitProviderDefined 标识不透明的供应商自定义计量单位。
	UnitProviderDefined AllowanceUnit = "provider_defined"
)

// WindowKind identifies how a quota window advances.
// WindowKind 标识额度窗口如何推进。
type WindowKind string

const (
	// WindowRolling identifies a rolling duration window.
	// WindowRolling 标识滚动时长窗口。
	WindowRolling WindowKind = "rolling"
	// WindowCalendar identifies a provider-defined calendar boundary.
	// WindowCalendar 标识供应商定义的日历边界。
	WindowCalendar WindowKind = "calendar"
	// WindowProviderDefined identifies a provider-specific window.
	// WindowProviderDefined 标识供应商特定窗口。
	WindowProviderDefined WindowKind = "provider_defined"
)

// AllowanceWindow describes a rolling, calendar, or provider-defined quota window.
// AllowanceWindow 描述滚动、日历或供应商定义的额度窗口。
type AllowanceWindow struct {
	// Kind identifies the window advancement rule.
	// Kind 标识窗口推进规则。
	Kind WindowKind
	// Duration is required for rolling windows.
	// Duration 是滚动窗口的必需时长。
	Duration time.Duration
	// CalendarUnit is day, week, month, or another provider-defined unit.
	// CalendarUnit 是日、周、月或其他供应商定义单位。
	CalendarUnit string
	// TimeZone identifies the provider calendar time zone when known.
	// TimeZone 标识已知时的供应商日历时区。
	TimeZone string
	// StartAt is the provider-reported beginning of the active window when known.
	// StartAt 是已知时供应商报告的当前窗口起始时间。
	StartAt *time.Time
	// ResetAt is the next provider-reported recovery time when known.
	// ResetAt 是已知时供应商报告的下次恢复时间。
	ResetAt *time.Time
}

// AllowanceSnapshot describes one independently scoped consumable resource.
// AllowanceSnapshot 描述一个独立作用域的可消费资源。
type AllowanceSnapshot struct {
	// ID is the immutable allowance snapshot identifier.
	// ID 是不可变的资源快照标识。
	ID string
	// ProviderInstanceID owns the snapshot.
	// ProviderInstanceID 是拥有该快照的供应商实例。
	ProviderInstanceID string
	// Kind identifies quota, balance, credit, or provider-defined semantics.
	// Kind 标识额度、余额、Credit 或供应商自定义语义。
	Kind AllowanceKind
	// Scope identifies the upstream owner of the resource.
	// Scope 标识资源的上游所有者。
	Scope AllowanceScope
	// ScopeID identifies the exact credential, account, model, or profile.
	// ScopeID 标识精确凭据、账号、模型或规格。
	ScopeID string
	// Metric is the provider-normalized resource metric identifier.
	// Metric 是供应商规范化后的资源指标标识。
	Metric string
	// Unit identifies the accounting unit.
	// Unit 标识计量单位。
	Unit AllowanceUnit
	// Currency is an ISO currency code only when Unit is minor currency units.
	// Currency 仅在 Unit 为货币最小单位时保存 ISO 货币代码。
	Currency string
	// Limit is a non-negative decimal string when the provider reports a limit.
	// Limit 是供应商报告上限时的非负十进制字符串。
	Limit *string
	// Used is a non-negative decimal string when the provider reports usage.
	// Used 是供应商报告用量时的非负十进制字符串。
	Used *string
	// Remaining is a non-negative decimal string when the provider reports remaining resources.
	// Remaining 是供应商报告剩余资源时的非负十进制字符串。
	Remaining *string
	// RemainingRatio is a value between zero and one when only a ratio is available.
	// RemainingRatio 是只获得比例时位于零到一之间的值。
	RemainingRatio *float64
	// DisplayMultiplierPermille is a provider-reported presentation multiplier without changing the base quota amounts.
	// DisplayMultiplierPermille 是供应商报告的展示倍率，不改变基础额度数值。
	DisplayMultiplierPermille *int64
	// Status is the current normalized resource state.
	// Status 是当前规范化资源状态。
	Status AllowanceStatus
	// Mandatory reports whether exhaustion blocks execution.
	// Mandatory 表示资源耗尽是否阻塞执行。
	Mandatory bool
	// Window describes time reset semantics for window quotas.
	// Window 描述时间窗口额度的重置语义。
	Window *AllowanceWindow
	// Source records the snapshot evidence source.
	// Source 记录快照证据来源。
	Source ModelSource
	// EvidenceSource identifies how the commercial resource fact was obtained.
	// EvidenceSource 标识商业资源事实的获取方式。
	EvidenceSource MetadataEvidenceSource
	// ObservedAt records when the resource was obtained.
	// ObservedAt 记录获得资源状态的时间。
	ObservedAt time.Time
	// ExpiresAt records when the snapshot becomes stale.
	// ExpiresAt 记录快照失效时间。
	ExpiresAt time.Time
	// Revision is the immutable allowance snapshot revision.
	// Revision 是不可变的资源快照修订号。
	Revision uint64
}

// RateLimitScope identifies the exact owner of one provider capacity limit.
// RateLimitScope 标识一项供应商容量限制的精确所有者。
type RateLimitScope string

const (
	// RateLimitScopeProviderInstance applies a limit to one provider instance.
	// RateLimitScopeProviderInstance 将限制应用到一个供应商实例。
	RateLimitScopeProviderInstance RateLimitScope = "provider_instance"
	// RateLimitScopeWorkspace applies a limit to one provider workspace.
	// RateLimitScopeWorkspace 将限制应用到一个供应商 Workspace。
	RateLimitScopeWorkspace RateLimitScope = "workspace"
	// RateLimitScopeCredential applies a limit to one credential.
	// RateLimitScopeCredential 将限制应用到一个凭据。
	RateLimitScopeCredential RateLimitScope = "credential"
	// RateLimitScopeOffering applies a limit to one model offering.
	// RateLimitScopeOffering 将限制应用到一个模型 Offering。
	RateLimitScopeOffering RateLimitScope = "offering"
	// RateLimitScopeExecutionProfile applies a limit to one execution profile.
	// RateLimitScopeExecutionProfile 将限制应用到一个执行规格。
	RateLimitScopeExecutionProfile RateLimitScope = "execution_profile"
)

// RateLimitSnapshot records one provider capacity limit without treating it as consumable allowance.
// RateLimitSnapshot 记录一项供应商容量限制，且不会把它视为可消费额度。
type RateLimitSnapshot struct {
	// ID is the immutable rate-limit snapshot identifier.
	// ID 是不可变的限速快照标识。
	ID string
	// ProviderInstanceID owns the snapshot.
	// ProviderInstanceID 是拥有该快照的供应商实例。
	ProviderInstanceID string
	// Scope identifies the upstream capacity owner.
	// Scope 标识上游容量所有者。
	Scope RateLimitScope
	// ScopeID identifies the exact instance, workspace, credential, offering, or profile.
	// ScopeID 标识精确的实例、Workspace、凭据、Offering 或 Profile。
	ScopeID string
	// TierID preserves the provider tier identifier without inferring precedence.
	// TierID 原样保留供应商 Tier 标识且不推断优先级。
	TierID string
	// CountLimit is the known positive request-count ceiling.
	// CountLimit 是已知的正请求次数上限。
	CountLimit int64
	// CountPeriodSeconds is the exact positive count-window duration.
	// CountPeriodSeconds 是精确的正计数窗口秒数。
	CountPeriodSeconds int64
	// UsageLimit is the optional positive provider usage ceiling.
	// UsageLimit 是可选的正供应商用量上限。
	UsageLimit *int64
	// UsagePeriodSeconds is the optional positive usage-window duration.
	// UsagePeriodSeconds 是可选的正用量窗口秒数。
	UsagePeriodSeconds *int64
	// UsageField identifies the exact provider metric counted by UsageLimit.
	// UsageField 标识 UsageLimit 统计的精确供应商指标。
	UsageField string
	// Source records the snapshot evidence source.
	// Source 记录快照证据来源。
	Source ModelSource
	// ObservedAt records when the capacity fact was obtained.
	// ObservedAt 记录获得容量事实的时间。
	ObservedAt time.Time
	// ExpiresAt records when the capacity snapshot becomes stale.
	// ExpiresAt 记录容量快照何时过期。
	ExpiresAt time.Time
	// Revision is the immutable rate-limit snapshot revision.
	// Revision 是不可变的限速快照修订号。
	Revision uint64
}

// PoolSummary describes aggregated runtime eligibility for one execution profile.
// PoolSummary 描述一个执行规格的聚合运行时资格。
type PoolSummary struct {
	// ProviderInstanceID owns the pool.
	// ProviderInstanceID 是拥有该账号池的供应商实例。
	ProviderInstanceID string
	// ExecutionProfileID identifies the summarized profile.
	// ExecutionProfileID 标识被汇总的执行规格。
	ExecutionProfileID string
	// ConfiguredCredentials is the total configured credential count.
	// ConfiguredCredentials 是已配置凭据总数。
	ConfiguredCredentials int
	// EntitledCredentials is the credential count authorized for the profile.
	// EntitledCredentials 是获得该规格授权的凭据数量。
	EntitledCredentials int
	// ReadyCredentials is the immediately executable credential count.
	// ReadyCredentials 是可以立即执行的凭据数量。
	ReadyCredentials int
	// CoolingCredentials is the known temporary cooldown count.
	// CoolingCredentials 是已知临时冷却凭据数量。
	CoolingCredentials int
	// ExhaustedCredentials is the allowance-blocked credential count.
	// ExhaustedCredentials 是被资源耗尽阻塞的凭据数量。
	ExhaustedCredentials int
	// InvalidCredentials is the invalid or expired credential count.
	// InvalidCredentials 是无效或过期凭据数量。
	InvalidCredentials int
	// BlockingAllowanceKinds lists resource shapes currently blocking candidates.
	// BlockingAllowanceKinds 列出当前阻塞候选的资源形态。
	BlockingAllowanceKinds []AllowanceKind
	// EarliestResetAt is the earliest known candidate recovery time.
	// EarliestResetAt 是最早的已知候选恢复时间。
	EarliestResetAt *time.Time
	// Revision identifies the pool calculation revision.
	// Revision 标识账号池计算修订号。
	Revision uint64
	// ObservedAt records when the pool was calculated.
	// ObservedAt 记录计算账号池的时间。
	ObservedAt time.Time
}

// Snapshot is an atomic provider-scoped model and runtime metadata catalog.
// Snapshot 是原子的供应商作用域模型和运行时元数据目录。
type Snapshot struct {
	// ProviderInstanceID owns every record in the snapshot.
	// ProviderInstanceID 是快照内全部记录的所有者。
	ProviderInstanceID string
	// DefaultAdditionalParameters contains provider-wide non-core request mutations inherited by every model offering.
	// DefaultAdditionalParameters 包含由每个模型产品继承的供应商级非核心请求变更。
	DefaultAdditionalParameters AdditionalPayloadProjection
	// Models contains provider-scoped logical models.
	// Models 包含供应商作用域的逻辑模型。
	Models []ProviderModel
	// Offerings contains channel-specific model products.
	// Offerings 包含通道特定的模型产品。
	Offerings []ModelOffering
	// Services contains provider-scoped logical special services.
	// Services 包含供应商作用域的逻辑特殊服务。
	Services []ProviderService
	// ServiceOfferings contains channel-specific special-service products.
	// ServiceOfferings 包含通道特定的特殊服务产品。
	ServiceOfferings []ServiceOffering
	// Profiles contains client-selectable capability shapes.
	// Profiles 包含客户端可选择的能力形态。
	Profiles []ExecutionProfile
	// ModelOperationPolicies contains code-owned model-operation publication decisions.
	// ModelOperationPolicies 包含代码拥有的模型操作发布决策。
	ModelOperationPolicies []ModelOperationPolicy
	// Entitlements contains credential-specific model authorization.
	// Entitlements 包含凭据特定的模型授权。
	Entitlements []ModelEntitlement
	// ServiceEntitlements contains credential-specific special-service authorization.
	// ServiceEntitlements 包含凭据特定的特殊服务授权。
	ServiceEntitlements []ServiceEntitlement
	// Plans contains provider-reported commercial plan snapshots.
	// Plans 包含供应商报告的商业套餐快照。
	Plans []PlanSnapshot
	// Allowances contains arbitrary quotas, balances, and credits.
	// Allowances 包含任意额度、余额和 Credit。
	Allowances []AllowanceSnapshot
	// RateLimits contains provider capacity ceilings that are not consumable allowances.
	// RateLimits 包含不属于可消费额度的供应商容量上限。
	RateLimits []RateLimitSnapshot
	// Voices contains credential-scoped provider voice catalog observations.
	// Voices 包含凭据作用域的供应商声音目录观测。
	Voices []VoiceSnapshot
	// Pools contains derived client-safe pool summaries.
	// Pools 包含派生的客户端安全账号池摘要。
	Pools []PoolSummary
	// Revision identifies the atomic catalog revision.
	// Revision 标识原子目录修订号。
	Revision uint64
	// ObservedAt records when the atomic catalog was produced.
	// ObservedAt 记录生成原子目录的时间。
	ObservedAt time.Time
	// Dynamic records trusted refresh provenance only for discoverable catalogs.
	// Dynamic 仅为可发现目录记录可信刷新来源。
	Dynamic *DynamicCatalogMetadata
}

// VoiceSnapshot contains one provider-reported voice available to one exact credential.
// VoiceSnapshot 包含供应商报告的、对一个精确凭据可用的声音。
type VoiceSnapshot struct {
	// ID is the stable Router-owned voice observation identifier.
	// ID 是 Router 所有的稳定声音观测标识。
	ID string
	// ProviderInstanceID owns the voice observation.
	// ProviderInstanceID 拥有该声音观测。
	ProviderInstanceID string
	// CredentialID identifies the exact account that exposed the voice.
	// CredentialID 标识公开该声音的精确账号。
	CredentialID string
	// VoiceID is the exact provider request value.
	// VoiceID 是精确的供应商请求值。
	VoiceID string
	// DisplayName is the provider-authored safe voice name.
	// DisplayName 是供应商编写的安全声音名称。
	DisplayName string
	// Descriptions contains ordered provider-authored voice traits.
	// Descriptions 包含供应商编写的有序声音特征。
	Descriptions []string
	// Source identifies the authoritative observation source.
	// Source 标识权威观测来源。
	Source ModelSource
	// ObservedAt records when the provider returned the voice.
	// ObservedAt 记录供应商返回该声音的时间。
	ObservedAt time.Time
	// ExpiresAt bounds cached use of the voice observation.
	// ExpiresAt 限制声音观测的缓存使用时间。
	ExpiresAt time.Time
	// Revision identifies the normalized voice record revision.
	// Revision 标识规范化声音记录修订号。
	Revision uint64
}

// CatalogAuthority identifies who owns one complete snapshot revision.
// CatalogAuthority 标识一个完整快照修订的所有者。
type CatalogAuthority string

const (
	// CatalogAuthorityCode identifies immutable code-owned metadata.
	// CatalogAuthorityCode 标识不可变代码拥有元数据。
	CatalogAuthorityCode CatalogAuthority = "code"
	// CatalogAuthorityProvider identifies a provider discovery API.
	// CatalogAuthorityProvider 标识供应商发现 API。
	CatalogAuthorityProvider CatalogAuthority = "provider"
	// CatalogAuthoritySignedRemote identifies a signature-verified remote catalog.
	// CatalogAuthoritySignedRemote 标识经过签名验证的远程目录。
	CatalogAuthoritySignedRemote CatalogAuthority = "signed_remote"
	// CatalogAuthorityUser identifies explicit local operator metadata.
	// CatalogAuthorityUser 标识明确的本地操作员元数据。
	CatalogAuthorityUser CatalogAuthority = "user"
)

// CatalogRefreshStatus identifies the last attempted dynamic refresh outcome.
// CatalogRefreshStatus 标识最近一次动态刷新结果。
type CatalogRefreshStatus string

const (
	// CatalogRefreshFresh means the current validated payload came from the latest refresh.
	// CatalogRefreshFresh 表示当前已校验载荷来自最近刷新。
	CatalogRefreshFresh CatalogRefreshStatus = "fresh"
	// CatalogRefreshStale means the last-good payload is retained after expiry or refresh failure.
	// CatalogRefreshStale 表示过期或刷新失败后保留最后一次有效载荷。
	CatalogRefreshStale CatalogRefreshStatus = "stale"
)

// CatalogTombstone records a provider identifier removed by a successful authoritative refresh.
// CatalogTombstone 记录被一次成功权威刷新移除的供应商标识。
type CatalogTombstone struct {
	// Kind is model or service.
	// Kind 是模型或服务。
	Kind string
	// ID is the removed provider-scoped identifier.
	// ID 是被移除的供应商作用域标识。
	ID string
	// RemovedAt records the successful refresh time.
	// RemovedAt 记录成功刷新时间。
	RemovedAt time.Time
}

// DynamicCatalogMetadata contains last-good, incremental synchronization, and failure facts.
// DynamicCatalogMetadata 包含最后有效、增量同步与失败事实。
type DynamicCatalogMetadata struct {
	// Authority identifies the trusted source class.
	// Authority 标识可信来源类别。
	Authority CatalogAuthority
	// SourceRevision is the provider, signature manifest, or user revision.
	// SourceRevision 是供应商、签名清单或用户修订。
	SourceRevision string
	// ETag is the opaque conditional-refresh validator when supplied.
	// ETag 是供应商提供时的不透明条件刷新校验值。
	ETag string
	// RefreshedAt records the most recent refresh attempt.
	// RefreshedAt 记录最近一次刷新尝试时间。
	RefreshedAt time.Time
	// ExpiresAt marks when fresh data becomes stale.
	// ExpiresAt 标记新鲜数据何时变为陈旧。
	ExpiresAt time.Time
	// Status reports fresh or retained stale data.
	// Status 报告新鲜数据或保留的陈旧数据。
	Status CatalogRefreshStatus
	// FailureCode is a safe local classification for the latest failed refresh.
	// FailureCode 是最近失败刷新的安全本地分类。
	FailureCode string
	// Tombstones preserve authoritative removals for incremental clients.
	// Tombstones 为增量客户端保留权威删除记录。
	Tombstones []CatalogTombstone
}
