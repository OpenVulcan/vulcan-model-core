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

// ProviderChannel defines one complete upstream access path owned by a provider.
// ProviderChannel 定义供应商拥有的一条完整上游接入路径。
type ProviderChannel struct {
	// ID is stable within one provider definition.
	// ID 在一个供应商定义内保持稳定。
	ID string
	// ProtocolProfileID references the shared upstream protocol profile.
	// ProtocolProfileID 引用共享上游协议 Profile。
	ProtocolProfileID string
	// EndpointProfileID identifies provider-owned endpoint behavior.
	// EndpointProfileID 标识供应商拥有的端点行为。
	EndpointProfileID string
	// AuthMethodIDs lists provider authentication methods allowed on this channel.
	// AuthMethodIDs 列出该通道允许的供应商认证方式。
	AuthMethodIDs []string
	// Priority is the stable default ordering within one provider.
	// Priority 是一个供应商内部的稳定默认顺序。
	Priority int
	// RuntimeReady reports whether the channel can participate in execution.
	// RuntimeReady 表示该通道是否可以参与执行。
	RuntimeReady bool
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
	// DriverID identifies the trusted driver used by system definitions.
	// DriverID 标识系统定义使用的受信任 Driver。
	DriverID string
	// DriverVersion records the trusted driver behavior version.
	// DriverVersion 记录受信任 Driver 的行为版本。
	DriverVersion string
	// ConfigSchemaVersion records the definition configuration schema version.
	// ConfigSchemaVersion 记录定义配置 Schema 版本。
	ConfigSchemaVersion string
	// Channels lists complete provider access paths.
	// Channels 列出完整的供应商接入路径。
	Channels []ProviderChannel
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
