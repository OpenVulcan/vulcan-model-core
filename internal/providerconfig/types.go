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
	// RuntimeReady reports whether the corresponding adapter is executable.
	// RuntimeReady 表示对应 Adapter 是否已经可以执行。
	RuntimeReady bool
	// ModelDiscovery describes whether the profile can list upstream models.
	// ModelDiscovery 描述该 Profile 是否可以拉取上游模型。
	ModelDiscovery SupportStatus
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
	// ModelDiscovery describes provider-native model discovery support.
	// ModelDiscovery 描述供应商原生模型发现支持。
	ModelDiscovery SupportStatus
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
	// EndpointPresets lists code-owned onboarding destinations without changing runtime endpoint ownership.
	// EndpointPresets 列出代码拥有的录入目标，且不改变运行时端点归属。
	EndpointPresets []EndpointPreset
	// AuthMethods lists authentication methods declared by the provider.
	// AuthMethods 列出供应商声明的认证方式。
	AuthMethods []AuthMethodDefinition
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
	// ChannelID identifies the provider channel served by the endpoint.
	// ChannelID 标识该端点服务的供应商通道。
	ChannelID string
	// BaseURL is the validated upstream base URL.
	// BaseURL 是经过校验的上游基础 URL。
	BaseURL string
	// Region is an optional provider-defined region label.
	// Region 是可选的供应商定义区域标签。
	Region string
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
