// Package providerconfig defines provider configuration ownership and runtime records.
// Package providerconfig 定义供应商配置所有权和运行时记录。
package providerconfig

import "time"

// DefinitionKind identifies who owns a provider definition.
// DefinitionKind 标识供应商定义的所有者。
type DefinitionKind string

const (
	// DefinitionKindSystem identifies a code-owned immutable provider definition.
	// DefinitionKindSystem 标识由代码拥有的不可变供应商定义。
	DefinitionKindSystem DefinitionKind = "system"
	// DefinitionKindCustom identifies a user-owned persisted provider definition.
	// DefinitionKindCustom 标识由用户拥有并持久化的供应商定义。
	DefinitionKindCustom DefinitionKind = "custom"
)

const (
	// CustomEndpointProfileOpenAICompatibility identifies CLIProxyAPI's base-URL-relative OpenAI Chat compatibility shape.
	// CustomEndpointProfileOpenAICompatibility 标识 CLIProxyAPI 相对于 Base URL 的 OpenAI Chat 兼容形态。
	CustomEndpointProfileOpenAICompatibility = "openai_compatibility"
	// CustomEndpointProfileOpenAIResponsesCompatibility identifies a versioned Base URL using the OpenAI Responses wire contract.
	// CustomEndpointProfileOpenAIResponsesCompatibility 标识使用 OpenAI Responses Wire 合同的带版本 Base URL。
	CustomEndpointProfileOpenAIResponsesCompatibility = "openai_responses_compatibility"
	// CustomEndpointProfileAnthropicMessagesCompatibility identifies an origin Base URL using the Anthropic Messages wire contract.
	// CustomEndpointProfileAnthropicMessagesCompatibility 标识使用 Anthropic Messages Wire 合同的 Origin Base URL。
	CustomEndpointProfileAnthropicMessagesCompatibility = "anthropic_messages_compatibility"
	// CustomEndpointProfileVertexCompatibility identifies CLIProxyAPI's API-key Vertex publisher-path compatibility shape.
	// CustomEndpointProfileVertexCompatibility 标识 CLIProxyAPI 使用 API Key 的 Vertex Publisher 路径兼容形态。
	CustomEndpointProfileVertexCompatibility = "vertex_compatibility"
)

// LifecycleStatus describes the configuration lifecycle of a provider instance.
// LifecycleStatus 描述供应商实例的配置生命周期。
type LifecycleStatus string

const (
	// LifecycleDraft means configuration is incomplete and cannot execute.
	// LifecycleDraft 表示配置尚未完成且不可执行。
	LifecycleDraft LifecycleStatus = "draft"
	// LifecycleValidating means configuration is being validated.
	// LifecycleValidating 表示配置正在校验。
	LifecycleValidating LifecycleStatus = "validating"
	// LifecycleReady means configuration can participate in execution resolution.
	// LifecycleReady 表示配置可以参与执行目标解析。
	LifecycleReady LifecycleStatus = "ready"
	// LifecycleDegraded means configuration remains partly usable with explicit limits.
	// LifecycleDegraded 表示配置仍可部分使用但存在明确限制。
	LifecycleDegraded LifecycleStatus = "degraded"
	// LifecycleDisabled means the operator disabled configuration.
	// LifecycleDisabled 表示操作员已禁用配置。
	LifecycleDisabled LifecycleStatus = "disabled"
	// LifecycleMigrationRequired means the stored configuration requires a schema migration.
	// LifecycleMigrationRequired 表示已存储配置需要进行 Schema 迁移。
	LifecycleMigrationRequired LifecycleStatus = "migration_required"
	// LifecycleDeleting means configuration is being removed after reference checks.
	// LifecycleDeleting 表示配置通过引用检查后正在删除。
	LifecycleDeleting LifecycleStatus = "deleting"
)

// SupportStatus describes whether an optional integration capability is available.
// SupportStatus 描述可选集成能力是否可用。
type SupportStatus string

const (
	// SupportSupported means the capability is implemented and available.
	// SupportSupported 表示能力已经实现且可用。
	SupportSupported SupportStatus = "supported"
	// SupportUnsupported means the capability is intentionally not implemented.
	// SupportUnsupported 表示能力明确未实现。
	SupportUnsupported SupportStatus = "unsupported"
	// SupportTemporarilyUnavailable means the capability exists but is currently unavailable.
	// SupportTemporarilyUnavailable 表示能力存在但当前暂时不可用。
	SupportTemporarilyUnavailable SupportStatus = "temporarily_unavailable"
)

// ProtocolCapability identifies one declarable upstream protocol behavior independent of a concrete provider instance.
// ProtocolCapability 标识独立于具体 Provider Instance 的一个可声明上游协议行为。
type ProtocolCapability string

const (
	// ProtocolCapabilitySystemInstruction identifies a native system-instruction carrier.
	// ProtocolCapabilitySystemInstruction 标识原生系统指令载体。
	ProtocolCapabilitySystemInstruction ProtocolCapability = "system_instruction"
	// ProtocolCapabilityStructuredTools identifies typed function declaration and invocation support.
	// ProtocolCapabilityStructuredTools 标识类型化函数声明和调用支持。
	ProtocolCapabilityStructuredTools ProtocolCapability = "structured_tools"
	// ProtocolCapabilityParallelTools identifies reliable parallel function invocation support.
	// ProtocolCapabilityParallelTools 标识可靠并行函数调用支持。
	ProtocolCapabilityParallelTools ProtocolCapability = "parallel_tools"
	// ProtocolCapabilityStreamingToolArguments identifies real upstream tool-argument deltas.
	// ProtocolCapabilityStreamingToolArguments 标识真实上游工具参数增量。
	ProtocolCapabilityStreamingToolArguments ProtocolCapability = "streaming_tool_arguments"
	// ProtocolCapabilityStrictJSONSchema identifies response-schema enforcement.
	// ProtocolCapabilityStrictJSONSchema 标识响应 Schema 约束支持。
	ProtocolCapabilityStrictJSONSchema ProtocolCapability = "strict_json_schema"
	// ProtocolCapabilityReasoning identifies provider reasoning output or request controls.
	// ProtocolCapabilityReasoning 标识 Provider 推理输出或请求控制。
	ProtocolCapabilityReasoning ProtocolCapability = "reasoning"
	// ProtocolCapabilityReasoningContinuation identifies sealed provider reasoning continuation support.
	// ProtocolCapabilityReasoningContinuation 标识密封 Provider 推理续接支持。
	ProtocolCapabilityReasoningContinuation ProtocolCapability = "reasoning_continuation"
	// ProtocolCapabilityRemoteCompaction identifies a provider-native remote compaction action.
	// ProtocolCapabilityRemoteCompaction 标识 Provider 原生远程压缩动作。
	ProtocolCapabilityRemoteCompaction ProtocolCapability = "remote_compaction"
	// ProtocolCapabilityNativeWebSearch identifies a provider-hosted web-search tool.
	// ProtocolCapabilityNativeWebSearch 标识 Provider 托管网页搜索工具。
	ProtocolCapabilityNativeWebSearch ProtocolCapability = "native_web_search"
	// ProtocolCapabilityTokenCounting identifies a typed upstream token-count action.
	// ProtocolCapabilityTokenCounting 标识类型化上游 Token 统计动作。
	ProtocolCapabilityTokenCounting ProtocolCapability = "token_counting"
)

// ProtocolCapabilityFact declares the verified availability of one closed protocol behavior.
// ProtocolCapabilityFact 声明一个封闭协议行为的经过验证可用性。
type ProtocolCapabilityFact struct {
	// Capability identifies the protocol behavior.
	// Capability 标识协议行为。
	Capability ProtocolCapability
	// Status records whether the behavior is supported without runtime probing.
	// Status 记录该行为是否无需运行时探测即可确认支持。
	Status SupportStatus
}

// AuthMethodType identifies one credential acquisition and application mechanism.
// AuthMethodType 标识一种凭据获取和应用机制。
type AuthMethodType string

const (
	// AuthMethodOAuth identifies a provider-owned OAuth authorization flow.
	// AuthMethodOAuth 标识供应商拥有的 OAuth 授权流程。
	AuthMethodOAuth AuthMethodType = "oauth"
	// AuthMethodDeviceFlow identifies a provider-owned device authorization flow.
	// AuthMethodDeviceFlow 标识供应商拥有的设备授权流程。
	AuthMethodDeviceFlow AuthMethodType = "device_flow"
	// AuthMethodAPIKey identifies a provider-owned API key format.
	// AuthMethodAPIKey 标识供应商拥有的 API Key 格式。
	AuthMethodAPIKey AuthMethodType = "api_key"
	// AuthMethodBearer identifies a generic bearer token.
	// AuthMethodBearer 标识通用 Bearer Token。
	AuthMethodBearer AuthMethodType = "bearer"
	// AuthMethodHeaderKey identifies a generic API key stored in a configured header.
	// AuthMethodHeaderKey 标识存放在指定 Header 中的通用 API Key。
	AuthMethodHeaderKey AuthMethodType = "header_api_key"
	// AuthMethodQueryKey identifies a generic API key stored in a configured query parameter.
	// AuthMethodQueryKey 标识存放在指定 Query 参数中的通用 API Key。
	AuthMethodQueryKey AuthMethodType = "query_api_key"
	// AuthMethodServiceAccount identifies a provider service-account document exchanged for short-lived bearer tokens.
	// AuthMethodServiceAccount 标识用于交换短期 Bearer Token 的供应商服务账号文档。
	AuthMethodServiceAccount AuthMethodType = "service_account"
	// AuthMethodNone identifies an explicitly unauthenticated local service.
	// AuthMethodNone 标识明确无需认证的本地服务。
	AuthMethodNone AuthMethodType = "none"
)

// PlanAcquisitionMode identifies how one authentication method obtains commercial-plan evidence.
// PlanAcquisitionMode 标识一种认证方式如何获得商业套餐证据。
type PlanAcquisitionMode string

const (
	// PlanAcquisitionUnavailable means the authentication method has no trusted plan source.
	// PlanAcquisitionUnavailable 表示该认证方式没有可信套餐来源。
	PlanAcquisitionUnavailable PlanAcquisitionMode = "unavailable"
	// PlanAcquisitionProviderDetected means protected provider evidence determines the plan.
	// PlanAcquisitionProviderDetected 表示由受保护的供应商证据确定套餐。
	PlanAcquisitionProviderDetected PlanAcquisitionMode = "provider_detected"
	// PlanAcquisitionManualRequired requires one code-owned plan choice during credential onboarding.
	// PlanAcquisitionManualRequired 表示录入凭据时必须选择一个代码拥有的套餐。
	PlanAcquisitionManualRequired PlanAcquisitionMode = "manual_required"
	// PlanAcquisitionManualOptional allows an operator choice while preserving unknown when omitted.
	// PlanAcquisitionManualOptional 表示允许操作员选择套餐，省略时保持未知。
	PlanAcquisitionManualOptional PlanAcquisitionMode = "manual_optional"
)

// RoutingStrategy identifies one same-provider credential selection algorithm.
// RoutingStrategy 标识一种同供应商凭据选择算法。
type RoutingStrategy string

const (
	// RoutingRoundRobin balances requests across equally eligible credentials.
	// RoutingRoundRobin 在资格相同的凭据之间均衡分配请求。
	RoutingRoundRobin RoutingStrategy = "round_robin"
	// RoutingFillFirst keeps using the first eligible credential until it becomes unavailable.
	// RoutingFillFirst 持续使用首个合格凭据，直至其不可用。
	RoutingFillFirst RoutingStrategy = "fill_first"
)

// CredentialStatus describes whether one credential can participate in resolution.
// CredentialStatus 描述单个凭据是否可以参与解析。
type CredentialStatus string

const (
	// CredentialActive means the credential is eligible for execution.
	// CredentialActive 表示凭据具备执行资格。
	CredentialActive CredentialStatus = "active"
	// CredentialDisabled means the operator disabled the credential.
	// CredentialDisabled 表示操作员已禁用凭据。
	CredentialDisabled CredentialStatus = "disabled"
	// CredentialExpired means the credential has expired.
	// CredentialExpired 表示凭据已经过期。
	CredentialExpired CredentialStatus = "expired"
	// CredentialInvalid means authentication has been rejected.
	// CredentialInvalid 表示身份认证已被拒绝。
	CredentialInvalid CredentialStatus = "invalid"
	// CredentialCooling means the credential is waiting for a known recovery time.
	// CredentialCooling 表示凭据正在等待已知恢复时间。
	CredentialCooling CredentialStatus = "cooling"
)

// EndpointStatus describes whether one endpoint can participate in resolution.
// EndpointStatus 描述单个端点是否可以参与解析。
type EndpointStatus string

const (
	// EndpointReady means the endpoint can receive requests.
	// EndpointReady 表示端点可以接收请求。
	EndpointReady EndpointStatus = "ready"
	// EndpointUnavailable means the endpoint is temporarily unavailable.
	// EndpointUnavailable 表示端点暂时不可用。
	EndpointUnavailable EndpointStatus = "unavailable"
	// EndpointDisabled means the operator disabled the endpoint.
	// EndpointDisabled 表示操作员已禁用端点。
	EndpointDisabled EndpointStatus = "disabled"
)

// ProtocolProfile describes one versioned upstream protocol without implementing it.
// ProtocolProfile 描述一个版本化上游协议但不实现该协议。
type ProtocolProfile struct {
	// ID is the stable protocol profile identifier.
	// ID 是稳定的协议 Profile 标识。
	ID string
	// Version is the schema and behavior version exposed by the profile.
	// Version 是该 Profile 暴露的 Schema 和行为版本。
	Version string
	// DisplayName is the management-facing protocol name.
	// DisplayName 是管理界面显示的协议名称。
	DisplayName string
	// UserConfigurable reports whether custom providers may select the profile.
	// UserConfigurable 表示自定义供应商是否可以选择该 Profile。
	UserConfigurable bool
	// CustomDefinitionCompatible reports whether persisted custom definitions may continue to reference this executable profile.
	// CustomDefinitionCompatible 表示已持久化自定义定义是否可以继续引用此可执行 Profile。
	CustomDefinitionCompatible bool
	// RuntimeReady reports whether the corresponding adapter is executable.
	// RuntimeReady 表示对应 Adapter 是否已经可以执行。
	RuntimeReady bool
	// Capabilities declares protocol behavior facts available for target-specific capability planning.
	// Capabilities 声明可供 Target 特定能力规划使用的协议行为事实。
	Capabilities []ProtocolCapabilityFact
	// AllowedAuthMethods lists generic authentication methods accepted by custom providers.
	// AllowedAuthMethods 列出自定义供应商可使用的通用认证方式。
	AllowedAuthMethods []AuthMethodType
}

// ProviderGroup describes one code-owned management catalog group that contains related system provider variants.
// ProviderGroup 描述一个由代码拥有的管理目录分组，其中包含相关的系统供应商变体。
type ProviderGroup struct {
	// ID is the immutable group identifier used only by management discovery.
	// ID 是仅供管理发现使用的不可变分组标识。
	ID string
	// DisplayName is the locale-neutral brand name shown by management clients.
	// DisplayName 是管理客户端显示的与区域设置无关的品牌名称。
	DisplayName string
	// Description explains the shared provider brand without selecting an execution target.
	// Description 说明共享供应商品牌，但不选择执行目标。
	Description string
	// DescriptionKey identifies authored client localization without making locale part of provider identity.
	// DescriptionKey 标识客户端编写的本地化文本且不让区域设置成为供应商身份的一部分。
	DescriptionKey string
	// SortOrder is the stable management catalog ordering value.
	// SortOrder 是稳定的管理目录排序值。
	SortOrder int
	// Revision is the immutable group metadata revision.
	// Revision 是不可变的分组元数据修订号。
	Revision uint64
}

// ProviderFeatureSet describes optional system-provider management capabilities.
// ProviderFeatureSet 描述系统供应商可选的管理能力。
type ProviderFeatureSet struct {
	// PlanReader describes commercial plan discovery support.
	// PlanReader 描述商业套餐读取支持。
	PlanReader SupportStatus
	// EntitlementReader describes account-level model entitlement discovery support.
	// EntitlementReader 描述账号级模型授权读取支持。
	EntitlementReader SupportStatus
	// AllowanceReader describes quota and balance discovery support.
	// AllowanceReader 描述额度和余额读取支持。
	AllowanceReader SupportStatus
}

// AuthMethodDefinition describes one provider-supported authentication method.
// AuthMethodDefinition 描述供应商支持的一种认证方式。
type AuthMethodDefinition struct {
	// ID is stable within one provider definition.
	// ID 在一个供应商定义内保持稳定。
	ID string
	// Type identifies how credentials are acquired and applied.
	// Type 标识凭据如何获取和应用。
	Type AuthMethodType
	// Refreshable reports whether the credential can be refreshed.
	// Refreshable 表示凭据是否可以刷新。
	Refreshable bool
	// MultipleCredentials reports whether one instance may store multiple credentials of this method.
	// MultipleCredentials 表示一个实例是否可以存储该认证方式的多个凭据。
	MultipleCredentials bool
	// PlanAcquisition declares the trusted plan source for this exact authentication method.
	// PlanAcquisition 声明该精确认证方式使用的可信套餐来源。
	PlanAcquisition PlanAcquisitionMode
	// ReaderFeatures optionally narrows provider metadata readers for this exact authentication method.
	// ReaderFeatures 可选地为该精确认证方式收窄供应商元数据读取能力。
	ReaderFeatures *ProviderFeatureSet
}

// PlanOptionDefinition describes one immutable commercial plan selectable for declared credentials.
// PlanOptionDefinition 描述一个可供声明式凭据选择的不可变商业套餐。
type PlanOptionDefinition struct {
	// ID is stable within one provider definition.
	// ID 在一个供应商定义内保持稳定。
	ID string
	// DisplayName is the locale-neutral provider plan name.
	// DisplayName 是与区域设置无关的供应商套餐名称。
	DisplayName string
	// DisplayNameKey identifies authored management-client localization.
	// DisplayNameKey 标识管理客户端编写的本地化文本。
	DisplayNameKey string
	// AuthMethodIDs lists exact methods permitted to declare this plan.
	// AuthMethodIDs 列出允许声明此套餐的精确认证方式。
	AuthMethodIDs []string
	// ManuallySelectable reports whether management clients may submit this option.
	// ManuallySelectable 表示管理客户端是否可以提交该选项。
	ManuallySelectable bool
	// ProviderPlanCodes lists exact upstream codes mapped to this plan without fuzzy matching.
	// ProviderPlanCodes 列出精确映射到该套餐且禁止模糊匹配的上游代码。
	ProviderPlanCodes []string
	// SortOrder is the stable management ordering.
	// SortOrder 是稳定的管理排序值。
	SortOrder int
	// Revision identifies the immutable evidence revision.
	// Revision 标识不可变证据修订号。
	Revision uint64
	// EvidenceRevision identifies provider-product evidence independently from schema changes.
	// EvidenceRevision 独立于 Schema 变更标识供应商产品证据版本。
	EvidenceRevision uint64
}

// EndpointParameterKind identifies one closed validation rule for a non-secret endpoint parameter.
// EndpointParameterKind 标识非秘密端点参数的一种封闭校验规则。
type EndpointParameterKind string

const (
	// EndpointParameterHostnameLabel accepts one normalized DNS hostname label.
	// EndpointParameterHostnameLabel 接受一个规范化的 DNS 主机名标签。
	EndpointParameterHostnameLabel EndpointParameterKind = "hostname_label"
)

// EndpointParameterDefinition declares one non-secret parameter required to materialize an endpoint preset.
// EndpointParameterDefinition 声明实例化端点预设所需的一个非秘密参数。
type EndpointParameterDefinition struct {
	// ID is the stable placeholder and request-field identifier.
	// ID 是稳定的占位符与请求字段标识。
	ID string
	// Kind selects the exact validation rule for the parameter value.
	// Kind 选择参数值的精确校验规则。
	Kind EndpointParameterKind
	// Required reports whether onboarding must provide the value.
	// Required 表示录入时是否必须提供该值。
	Required bool
}

// EndpointParameterValue stores one validated non-secret endpoint parameter value.
// EndpointParameterValue 存储一个经过校验的非秘密端点参数值。
type EndpointParameterValue struct {
	// ID identifies the matching endpoint parameter definition.
	// ID 标识匹配的端点参数定义。
	ID string
	// Value is the normalized value materialized into the provider-owned template.
	// Value 是实例化到供应商所有模板中的规范化值。
	Value string
}

// EndpointPreset describes one code-owned default network destination offered during system-provider onboarding.
// EndpointPreset 描述系统供应商录入期间提供的一个由代码拥有的默认网络目标。
type EndpointPreset struct {
	// ID is stable within one provider definition.
	// ID 在一个供应商定义内保持稳定。
	ID string
	// BaseURL is the default absolute upstream base URL.
	// BaseURL 是默认的上游绝对基础 URL。
	BaseURL string
	// Region is the locale-neutral site or region label shown during onboarding.
	// Region 是录入期间显示的与区域设置无关的站点或区域标签。
	Region string
	// UserEditable reports whether management clients may replace this default address.
	// UserEditable 表示管理客户端是否可以替换该默认地址。
	UserEditable bool
	// RegionalBaseURLTemplate derives a provider-owned origin from a normalized region through one {region} placeholder.
	// RegionalBaseURLTemplate 通过唯一 {region} 占位符从规范化区域派生供应商所有 Origin。
	RegionalBaseURLTemplate string
	// GlobalBaseURL overrides the regional template only for the exact global region.
	// GlobalBaseURL 仅对精确的 global 区域覆盖区域模板。
	GlobalBaseURL string
	// BaseURLTemplate materializes a provider-owned origin from declared endpoint parameters.
	// BaseURLTemplate 使用已声明的端点参数实例化供应商所有 Origin。
	BaseURLTemplate string
	// Parameters declares the exact non-secret values accepted by BaseURLTemplate.
	// Parameters 声明 BaseURLTemplate 接受的精确非秘密值。
	Parameters []EndpointParameterDefinition
}

// ProviderDefinition describes either a code-owned system integration or a persisted custom definition.
// ProviderDefinition 描述代码拥有的系统集成或持久化的自定义定义。
type ProviderDefinition struct {
	// ID is the immutable system or custom definition identifier.
	// ID 是不可变的系统或自定义定义标识。
	ID string
	// Kind identifies definition ownership.
	// Kind 标识定义所有权。
	Kind DefinitionKind
	// DisplayName is the management-facing provider name.
	// DisplayName 是管理界面显示的供应商名称。
	DisplayName string
	// GroupID references optional code-owned management grouping metadata.
	// GroupID 引用可选的代码拥有管理分组元数据。
	GroupID string
	// VariantName is the concise locale-neutral label shown inside the owning group.
	// VariantName 是在所属分组内显示的简洁且与区域设置无关的标签。
	VariantName string
	// VariantDescription explains the site, product, or commercial boundary of this definition.
	// VariantDescription 说明此定义的站点、产品或商业边界。
	VariantDescription string
	// VariantDescriptionKey identifies authored client localization for this exact variant.
	// VariantDescriptionKey 标识此精确变体的客户端编写本地化文本。
	VariantDescriptionKey string
	// ModelCatalogID identifies reusable code-owned model metadata shared by compatible definitions.
	// ModelCatalogID 标识可由兼容定义共享的代码拥有模型元数据。
	ModelCatalogID string
	// SortOrder is the stable ordering of this variant inside its management group.
	// SortOrder 是此变体在管理分组内的稳定排序值。
	SortOrder int
	// DriverID identifies the trusted driver used by system definitions.
	// DriverID 标识系统定义使用的受信任 Driver。
	DriverID string
	// DriverVersion records the trusted driver behavior version.
	// DriverVersion 记录受信任 Driver 的行为版本。
	DriverVersion string
	// ConfigSchemaVersion records the definition configuration schema version.
	// ConfigSchemaVersion 记录定义配置 Schema 版本。
	ConfigSchemaVersion string
	// ProtocolProfileID references the one preferred upstream protocol profile.
	// ProtocolProfileID 引用唯一的优势上游协议 Profile。
	ProtocolProfileID string
	// EndpointProfileID identifies provider-owned endpoint behavior for the selected protocol.
	// EndpointProfileID 标识所选协议的供应商自有端点行为。
	EndpointProfileID string
	// AuthMethodIDs lists authentication methods allowed by the selected protocol.
	// AuthMethodIDs 列出所选协议允许的认证方式。
	AuthMethodIDs []string
	// Priority is the stable default binding priority.
	// Priority 是稳定的默认绑定优先级。
	Priority int
	// RuntimeReady reports whether the selected protocol can participate in execution.
	// RuntimeReady 表示所选协议是否可以参与执行。
	RuntimeReady bool
	// ActionBindings contains code-owned operation-specific runtime bindings for system providers.
	// ActionBindings 包含系统供应商由代码拥有的操作特定运行时绑定。
	ActionBindings []ProviderActionBinding
	// EndpointPresets lists code-owned onboarding destinations without changing runtime endpoint ownership.
	// EndpointPresets 列出代码拥有的录入目标，且不改变运行时端点归属。
	EndpointPresets []EndpointPreset
	// AuthMethods lists authentication methods declared by the provider.
	// AuthMethods 列出供应商声明的认证方式。
	AuthMethods []AuthMethodDefinition
	// PlanOptions lists code-owned plans available to manual credential onboarding.
	// PlanOptions 列出人工凭据录入可选择的代码拥有套餐。
	PlanOptions []PlanOptionDefinition
	// Features describes optional system-provider management capabilities.
	// Features 描述系统供应商的可选管理能力。
	Features ProviderFeatureSet
	// Revision is the immutable definition revision.
	// Revision 是不可变的定义修订号。
	Revision uint64
}

// ProviderInstance describes one user or workspace configuration of a provider definition.
// ProviderInstance 描述用户或工作区对供应商定义的一份实际配置。
type ProviderInstance struct {
	// ID is the immutable provider instance identifier.
	// ID 是不可变的供应商实例标识。
	ID string
	// DefinitionID references a system or custom provider definition.
	// DefinitionID 引用系统或自定义供应商定义。
	DefinitionID string
	// Handle is the stable workspace-visible routing alias.
	// Handle 是工作区可见的稳定路由别名。
	Handle string
	// DisplayName is the editable management-facing name.
	// DisplayName 是管理界面可编辑的名称。
	DisplayName string
	// Status describes configuration lifecycle and readiness.
	// Status 描述配置生命周期和就绪状态。
	Status LifecycleStatus
	// ProxyRef references an optional separately managed proxy configuration.
	// ProxyRef 引用可选的独立代理配置。
	ProxyRef string
	// DisabledModelIDs lists provider-scoped models intentionally hidden from call-plane resolution.
	// DisabledModelIDs 列出被有意从调用面解析中隐藏的供应商作用域模型。
	DisabledModelIDs []string
	// DisabledServiceIDs lists provider-scoped services intentionally hidden from call-plane resolution.
	// DisabledServiceIDs 列出被有意从调用面解析中隐藏的供应商作用域服务。
	DisabledServiceIDs []string
	// RoutingStrategy optionally overrides the Router-wide credential selection strategy.
	// RoutingStrategy 可选地覆盖 Router 全局凭据选择策略。
	RoutingStrategy RoutingStrategy
	// Revision is the latest persisted instance revision.
	// Revision 是最新持久化实例修订号。
	Revision uint64
	// DefinitionRevision records the definition revision used for validation.
	// DefinitionRevision 记录校验时使用的定义修订号。
	DefinitionRevision uint64
	// CreatedAt is the immutable creation time.
	// CreatedAt 是不可变的创建时间。
	CreatedAt time.Time
	// UpdatedAt is the latest persisted update time.
	// UpdatedAt 是最新持久化更新时间。
	UpdatedAt time.Time
}

// Endpoint describes one concrete upstream network destination.
// Endpoint 描述一个具体的上游网络目标。
type Endpoint struct {
	// ID is the immutable endpoint identifier.
	// ID 是不可变的端点标识。
	ID string
	// ProviderInstanceID owns the endpoint.
	// ProviderInstanceID 是拥有该端点的供应商实例。
	ProviderInstanceID string
	// ChannelID anchors the endpoint to one definition-owned channel while access bindings may reuse the same Origin for other channels.
	// ChannelID 将端点锚定到一个定义拥有的通道，而访问绑定可对其他通道复用同一 Origin。
	ChannelID string
	// BaseURL is the validated upstream base URL.
	// BaseURL 是经过校验的上游基础 URL。
	BaseURL string
	// Region is an optional provider-defined region label.
	// Region 是可选的供应商定义区域标签。
	Region string
	// Parameters stores the exact validated non-secret values used to derive BaseURL.
	// Parameters 存储用于派生 BaseURL 的精确且经过校验的非秘密值。
	Parameters []EndpointParameterValue
	// Status describes endpoint runtime availability.
	// Status 描述端点运行时可用状态。
	Status EndpointStatus
	// Revision is the latest persisted endpoint revision.
	// Revision 是最新持久化端点修订号。
	Revision uint64
}

// ScopeReference binds a credential to an upstream commercial or organizational scope.
// ScopeReference 将凭据绑定到一个上游商业或组织作用域。
type ScopeReference struct {
	// Kind is a stable scope type such as subscription or billing_account.
	// Kind 是 subscription 或 billing_account 等稳定作用域类型。
	Kind string
	// ID is the provider-scoped stable scope identifier.
	// ID 是供应商作用域内的稳定标识。
	ID string
}

// DeclaredPlanSelection stores one operator-authored choice constrained by a code-owned plan option.
// DeclaredPlanSelection 存储一个受代码拥有套餐选项约束的操作员声明选择。
type DeclaredPlanSelection struct {
	// PlanOptionID references one immutable option on the provider definition.
	// PlanOptionID 引用供应商定义中的一个不可变选项。
	PlanOptionID string `json:"plan_option_id"`
	// DeclaredAt records when the operator confirmed the plan.
	// DeclaredAt 记录操作员确认套餐的时间。
	DeclaredAt time.Time `json:"declared_at"`
	// Revision identifies the latest operator declaration revision.
	// Revision 标识最新的操作员声明修订号。
	Revision uint64 `json:"revision"`
}

// Credential stores non-secret metadata for one OAuth account or API key.
// Credential 存储一个 OAuth 账号或 API Key 的非秘密元数据。
type Credential struct {
	// ID is the immutable credential identifier.
	// ID 是不可变的凭据标识。
	ID string
	// ProviderInstanceID owns the credential.
	// ProviderInstanceID 是拥有该凭据的供应商实例。
	ProviderInstanceID string
	// AuthMethodID identifies the provider authentication method.
	// AuthMethodID 标识供应商认证方式。
	AuthMethodID string
	// Label is the editable management-facing credential name.
	// Label 是管理界面可编辑的凭据名称。
	Label string
	// PrincipalKey is the provider-supplied stable account identity when available.
	// PrincipalKey 是可用时由供应商提供的稳定账号身份。
	PrincipalKey string
	// SecretRef points to encrypted secret storage and never contains the secret itself.
	// SecretRef 指向加密 Secret 存储且绝不包含 Secret 本身。
	SecretRef string
	// Fingerprint is an irreversible duplicate-detection value.
	// Fingerprint 是不可逆的重复检测值。
	Fingerprint string
	// Status describes credential runtime eligibility.
	// Status 描述凭据运行时资格。
	Status CredentialStatus
	// ScopeRefs lists shared subscription, project, organization, or billing scopes.
	// ScopeRefs 列出共享订阅、项目、组织或计费作用域。
	ScopeRefs []ScopeReference
	// ExpiresAt is the provider-reported credential expiry time when known.
	// ExpiresAt 是已知时供应商报告的凭据过期时间。
	ExpiresAt *time.Time
	// CoolingUntil is the earliest known recovery time for a cooling credential.
	// CoolingUntil 是冷却凭据最早的已知恢复时间。
	CoolingUntil *time.Time
	// Priority orders this account before endpoint-specific binding priority; lower values win.
	// Priority 在入口专属 Binding 优先级之前排列账号；较小值优先。
	Priority int
	// DeclaredPlan stores one code-owned manual plan selection when required.
	// DeclaredPlan 在需要时存储一个代码拥有的人工套餐选择。
	DeclaredPlan *DeclaredPlanSelection
	// Revision is the latest persisted credential revision.
	// Revision 是最新持久化凭据修订号。
	Revision uint64
}

// AccessBinding authorizes one credential to use one endpoint and provider channel.
// AccessBinding 授权一个凭据使用一个端点和供应商通道。
type AccessBinding struct {
	// ID is the immutable binding identifier.
	// ID 是不可变的绑定标识。
	ID string
	// ProviderInstanceID owns the binding and all referenced records.
	// ProviderInstanceID 是拥有该绑定及全部引用记录的供应商实例。
	ProviderInstanceID string
	// ChannelID identifies the provider channel.
	// ChannelID 标识供应商通道。
	ChannelID string
	// EndpointID references one endpoint in the same provider instance.
	// EndpointID 引用同一供应商实例中的一个端点。
	EndpointID string
	// CredentialID references one credential in the same provider instance.
	// CredentialID 引用同一供应商实例中的一个凭据。
	CredentialID string
	// AllowedModelIDs restricts the binding to specific provider models when non-empty.
	// AllowedModelIDs 非空时将该绑定限制到指定供应商模型。
	AllowedModelIDs []string
	// AllowedServiceIDs restricts the binding to specific provider services when non-empty.
	// AllowedServiceIDs 非空时将该绑定限制到指定供应商服务。
	AllowedServiceIDs []string
	// Priority is the stable selection order within an eligible pool.
	// Priority 是合格账号池内的稳定选择顺序。
	Priority int
	// Enabled reports whether the binding can participate in resolution.
	// Enabled 表示该绑定是否可以参与解析。
	Enabled bool
	// Revision is the latest persisted binding revision.
	// Revision 是最新持久化绑定修订号。
	Revision uint64
}

// AccessGraphReplacement atomically replaces one instance's complete endpoint and binding graph after exact-state comparison.
// AccessGraphReplacement 在精确状态比对后原子替换一个实例的完整入口与 Binding 图。
type AccessGraphReplacement struct {
	// ProviderInstanceID identifies the sole graph owner.
	// ProviderInstanceID 标识唯一图归属实例。
	ProviderInstanceID string
	// ExpectedEndpoints contains the complete endpoint snapshot that must still be current.
	// ExpectedEndpoints 包含必须仍为当前状态的完整入口快照。
	ExpectedEndpoints []Endpoint
	// ExpectedBindings contains the complete binding snapshot that must still be current.
	// ExpectedBindings 包含必须仍为当前状态的完整 Binding 快照。
	ExpectedBindings []AccessBinding
	// Endpoints contains the complete replacement endpoint graph.
	// Endpoints 包含完整替换入口图。
	Endpoints []Endpoint
	// Bindings contains the complete replacement binding graph.
	// Bindings 包含完整替换 Binding 图。
	Bindings []AccessBinding
}

// ProviderConfiguration contains one provider instance and its complete non-secret endpoint graph.
// ProviderConfiguration 包含一个供应商实例及其完整非秘密入口图。
type ProviderConfiguration struct {
	// Instance is the credential-independent provider configuration root.
	// Instance 是独立于凭据的供应商配置根。
	Instance ProviderInstance
	// Endpoints contains every configured channel destination owned by the instance.
	// Endpoints 包含实例拥有的全部已配置通道目标。
	Endpoints []Endpoint
}

// SystemOnboarding contains one complete new system-provider configuration committed as one unit.
// SystemOnboarding 包含作为一个单元提交的完整新系统供应商配置。
type SystemOnboarding struct {
	// Instance is the exact new provider instance owned by one system definition.
	// Instance 是由一个系统定义拥有的精确新供应商实例。
	Instance ProviderInstance
	// Endpoints contains every code-owned endpoint required by the selected definition.
	// Endpoints 包含所选定义要求的全部代码拥有端点。
	Endpoints []Endpoint
	// Credential contains the protected-secret reference and safe account metadata.
	// Credential 包含受保护秘密引用和安全账号元数据。
	Credential Credential
	// Bindings closes every selected channel path between the credential and its endpoint.
	// Bindings 在凭据与其端点之间闭合每条所选通道路由。
	Bindings []AccessBinding
}

// CustomOnboarding contains one complete new custom-provider definition and executable access graph committed as one unit.
// CustomOnboarding 包含作为一个单元提交的完整新自定义供应商 Definition 与可执行访问图。
type CustomOnboarding struct {
	// Definition is the new user-owned single-protocol provider definition.
	// Definition 是新的用户拥有单协议供应商 Definition。
	Definition ProviderDefinition
	// Instance is the sole initial provider instance owned by the new definition.
	// Instance 是新 Definition 拥有的唯一初始供应商实例。
	Instance ProviderInstance
	// Endpoint is the exact operator-supplied compatibility Base URL.
	// Endpoint 是操作员提供的精确兼容 Base URL。
	Endpoint Endpoint
	// Credential contains the protected-secret reference and one fixed authentication method.
	// Credential 包含受保护 Secret 引用与一种固定认证方式。
	Credential Credential
	// Binding closes the definition's sole protocol channel through the endpoint and credential.
	// Binding 通过 Endpoint 与 Credential 闭合 Definition 的唯一协议 Channel。
	Binding AccessBinding
}

// CustomDefinitionMigration contains one custom definition revision and the complete instance set transitioned with it.
// CustomDefinitionMigration 包含一个自定义定义修订以及与其一同转换的完整实例集合。
type CustomDefinitionMigration struct {
	// Definition is the validated replacement custom provider definition.
	// Definition 是经过校验的替换自定义供应商定义。
	Definition ProviderDefinition
	// Instances contains every existing definition-owned instance in migration-required state.
	// Instances 包含该定义拥有且处于需要迁移状态的全部既有实例。
	Instances []ProviderInstance
}
