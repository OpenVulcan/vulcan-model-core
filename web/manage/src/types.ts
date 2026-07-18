// ProtocolCapability describes one verified protocol-level behavior fact.
// ProtocolCapability 描述一项经过验证的协议级行为事实。
export interface ProtocolCapability {
  /** Capability is the closed behavior identifier. */
  /** Capability 是封闭行为标识。 */
  capability: string;
  /** Status is the verified availability state. */
  /** Status 是经过验证的可用状态。 */
  status: string;
}

// ProtocolProfile describes one provider protocol that a custom definition may select.
// ProtocolProfile 描述一个自定义定义可以选择的供应商协议。
export interface ProtocolProfile {
  /** ID is the stable protocol profile identifier. */
  /** ID 是稳定协议 Profile 标识。 */
  id: string;
  /** Version is the process-owned behavior version. */
  /** Version 是进程拥有的行为版本。 */
  version: string;
  /** DisplayName is the management-facing label. */
  /** DisplayName 是管理界面显示名称。 */
  display_name: string;
  /** UserConfigurable controls custom definition eligibility. */
  /** UserConfigurable 控制自定义定义资格。 */
  user_configurable: boolean;
  /** RuntimeReady indicates executable local protocol support. */
  /** RuntimeReady 表示可执行的本地协议支持。 */
  runtime_ready: boolean;
  /** ModelDiscovery records upstream model listing support. */
  /** ModelDiscovery 记录上游模型列举支持。 */
  model_discovery: string;
  /** Capabilities contains explicit profile-global facts. */
  /** Capabilities 包含显式 Profile 全局事实。 */
  capabilities: ProtocolCapability[];
  /** AllowedAuthMethods contains generic custom authentication methods. */
  /** AllowedAuthMethods 包含通用自定义认证方式。 */
  allowed_auth_methods: string[];
}

// ProviderChannel describes one configured upstream channel without adapter internals.
// ProviderChannel 描述一个不含 Adapter 内部细节的已配置上游通道。
export interface ProviderChannel {
  /** ID is stable within the provider definition. */
  /** ID 在供应商定义内保持稳定。 */
  id: string;
  /** ProtocolProfileID identifies the selected upstream protocol. */
  /** ProtocolProfileID 标识已选择上游协议。 */
  protocol_profile_id: string;
  /** RuntimeReady reports local implementation readiness. */
  /** RuntimeReady 报告本地实现就绪状态。 */
  runtime_ready: boolean;
}

// ProviderAuthMethod describes one declared authentication method without credential values.
// ProviderAuthMethod 描述一种不含凭据值的已声明认证方式。
export interface ProviderAuthMethod {
  /** ID is stable within the provider definition. */
  /** ID 在供应商定义内保持稳定。 */
  id: string;
  /** Type is the declared authentication mechanism. */
  /** Type 是已声明认证机制。 */
  type: string;
}

// ProviderDefinition describes a system-owned or user-owned provider contract.
// ProviderDefinition 描述系统拥有或用户拥有的供应商合同。
export interface ProviderDefinition {
  /** ID is the immutable provider definition identifier. */
  /** ID 是不可变供应商定义标识。 */
  id: string;
  /** Kind distinguishes system and custom ownership. */
  /** Kind 区分系统和自定义归属。 */
  kind: "system" | "custom";
  /** DisplayName is the management-facing provider name. */
  /** DisplayName 是管理界面供应商名称。 */
  display_name: string;
  /** Channels contains selectable protocol channels. */
  /** Channels 包含可选择的协议通道。 */
  channels: ProviderChannel[];
  /** AuthMethods contains declared authentication mechanisms. */
  /** AuthMethods 包含已声明认证机制。 */
  auth_methods: ProviderAuthMethod[];
  /** Revision is the persisted definition revision. */
  /** Revision 是持久化定义修订号。 */
  revision: number;
}

// ProviderInstance describes one independently enabled provider configuration.
// ProviderInstance 描述一个独立启用的供应商配置。
export interface ProviderInstance {
  /** ID is the immutable provider instance identifier. */
  /** ID 是不可变供应商实例标识。 */
  id: string;
  /** DefinitionID identifies the owning provider definition. */
  /** DefinitionID 标识所属供应商定义。 */
  definition_id: string;
  /** Handle is the workspace-visible routing alias. */
  /** Handle 是工作区可见路由别名。 */
  handle: string;
  /** DisplayName is the management-facing instance label. */
  /** DisplayName 是管理界面实例名称。 */
  display_name: string;
  /** Status is the local lifecycle state. */
  /** Status 是本地生命周期状态。 */
  status: string;
  /** DisabledModelIDs contains local model policy exclusions. */
  /** DisabledModelIDs 包含本地模型策略排除项。 */
  disabled_model_ids: string[];
  /** EndpointCount is the configured endpoint count. */
  /** EndpointCount 是已配置端点数量。 */
  endpoint_count: number;
  /** CredentialCount is the configured credential count. */
  /** CredentialCount 是已配置凭据数量。 */
  credential_count: number;
  /** BindingCount is the configured access binding count. */
  /** BindingCount 是已配置访问绑定数量。 */
  binding_count: number;
  /** Revision is the persisted instance revision. */
  /** Revision 是持久化实例修订号。 */
  revision: number;
}

// Endpoint describes one management-safe upstream endpoint record.
// Endpoint 描述一条管理安全的上游端点记录。
export interface Endpoint {
  /** ID is the immutable endpoint identifier. */
  /** ID 是不可变端点标识。 */
  id: string;
  /** ChannelID identifies the served provider channel. */
  /** ChannelID 标识服务的供应商通道。 */
  channel_id: string;
  /** BaseURL is the validated upstream base URL. */
  /** BaseURL 是已校验上游基础 URL。 */
  base_url: string;
  /** Region is the optional provider-defined region. */
  /** Region 是可选供应商定义区域。 */
  region: string;
  /** Status is the local endpoint availability state. */
  /** Status 是本地端点可用状态。 */
  status: string;
  /** Revision is the persisted endpoint revision. */
  /** Revision 是持久化端点修订号。 */
  revision: number;
}

// Credential describes redacted upstream credential metadata.
// Credential 描述已脱敏的上游凭据元数据。
export interface Credential {
  /** ID is the immutable credential identifier. */
  /** ID 是不可变凭据标识。 */
  id: string;
  /** AuthMethodID identifies the configured authentication method. */
  /** AuthMethodID 标识已配置认证方式。 */
  auth_method_id: string;
  /** Label is the management-facing credential label. */
  /** Label 是管理界面凭据名称。 */
  label: string;
  /** Status is the local credential lifecycle state. */
  /** Status 是本地凭据生命周期状态。 */
  status: string;
  /** CoolingUntil is the optional recovery timestamp. */
  /** CoolingUntil 是可选恢复时间戳。 */
  cooling_until: string | null;
  /** Revision is the persisted credential revision. */
  /** Revision 是持久化凭据修订号。 */
  revision: number;
}

// AccessBinding describes one non-secret credential-to-endpoint relationship.
// AccessBinding 描述一条非秘密的凭据到端点关系。
export interface AccessBinding {
  /** ID is the immutable binding identifier. */
  /** ID 是不可变绑定标识。 */
  id: string;
  /** ChannelID identifies the configured channel. */
  /** ChannelID 标识已配置通道。 */
  channel_id: string;
  /** EndpointID identifies the linked endpoint. */
  /** EndpointID 标识关联端点。 */
  endpoint_id: string;
  /** CredentialID identifies the linked credential. */
  /** CredentialID 标识关联凭据。 */
  credential_id: string;
  /** AllowedModelIDs contains optional model restrictions. */
  /** AllowedModelIDs 包含可选模型限制。 */
  allowed_model_ids: string[];
  /** Priority is deterministic same-pool order. */
  /** Priority 是确定性的同池顺序。 */
  priority: number;
  /** Enabled controls resolution eligibility. */
  /** Enabled 控制解析资格。 */
  enabled: boolean;
  /** Revision is the persisted binding revision. */
  /** Revision 是持久化绑定修订号。 */
  revision: number;
}

// CatalogModel describes one provider-scoped model returned for local control.
// CatalogModel 描述一个为本地控制返回的供应商作用域模型。
export interface CatalogModel {
  /** ID is the stable provider-scoped model identifier. */
  /** ID 是稳定的供应商作用域模型标识。 */
  id: string;
  /** UpstreamModelID is the provider-native model name. */
  /** UpstreamModelID 是供应商原生模型名称。 */
  upstream_model_id: string;
  /** DisplayName is the management-facing model label. */
  /** DisplayName 是管理界面模型名称。 */
  display_name: string;
  /** Enabled reports the local model policy state. */
  /** Enabled 报告本地模型策略状态。 */
  enabled: boolean;
}

// ProviderCatalog describes one client-safe provider catalog snapshot.
// ProviderCatalog 描述一个客户端安全的供应商目录快照。
export interface ProviderCatalog {
  /** ProviderInstanceID identifies the owning instance. */
  /** ProviderInstanceID 标识所属实例。 */
  provider_instance_id: string;
  /** Models contains selectable provider models. */
  /** Models 包含可选择的供应商模型。 */
  models: CatalogModel[];
  /** Revision is the atomic catalog revision. */
  /** Revision 是原子目录修订号。 */
  revision: number;
}

// CustomTokenLimit preserves the explicit distinction between unknown and known positive limits.
// CustomTokenLimit 保留未知限制与已知正数限制之间的显式区别。
export interface CustomTokenLimit {
  /** Known reports whether Value is authoritative. */
  /** Known 表示 Value 是否具有权威性。 */
  known: boolean;
  /** Value is positive only when Known is true. */
  /** Value 仅在 Known 为真时为正数。 */
  value?: number;
}

// CustomModelCapabilities is the complete explicit capability declaration for a custom catalog offering or profile.
// CustomModelCapabilities 是自定义目录产品或规格的完整显式能力声明。
export interface CustomModelCapabilities {
  /** ContextWindow is the total model context ceiling. */
  /** ContextWindow 是模型总上下文上限。 */
  context_window: CustomTokenLimit;
  /** MaxInputTokens is the independent input ceiling. */
  /** MaxInputTokens 是独立输入上限。 */
  max_input_tokens: CustomTokenLimit;
  /** MaxOutputTokens is the independent output ceiling. */
  /** MaxOutputTokens 是独立输出上限。 */
  max_output_tokens: CustomTokenLimit;
  /** MaxReasoningTokens is the independent reasoning ceiling. */
  /** MaxReasoningTokens 是独立推理上限。 */
  max_reasoning_tokens: CustomTokenLimit;
  /** ToolCalling declares tool-call support. */
  /** ToolCalling 声明工具调用支持。 */
  tool_calling: string;
  /** ParallelToolCalls declares parallel tool-call support. */
  /** ParallelToolCalls 声明并行工具调用支持。 */
  parallel_tool_calls: string;
  /** StreamingToolArguments declares incremental tool-argument support. */
  /** StreamingToolArguments 声明增量工具参数支持。 */
  streaming_tool_arguments: string;
  /** StrictJSONSchema declares strict structured-output support. */
  /** StrictJSONSchema 声明严格结构化输出支持。 */
  strict_json_schema: string;
  /** Reasoning declares reasoning-control support. */
  /** Reasoning 声明推理控制支持。 */
  reasoning: string;
  /** InputModalities lists accepted normalized input modalities. */
  /** InputModalities 列出可接受的规范化输入模态。 */
  input_modalities: string[];
  /** OutputModalities lists produced normalized output modalities. */
  /** OutputModalities 列出产生的规范化输出模态。 */
  output_modalities: string[];
}

// CustomCatalogModel declares one logical user-managed custom-provider model.
// CustomCatalogModel 声明一个逻辑的用户管理自定义供应商模型。
export interface CustomCatalogModel {
  /** ID is the stable model_ identifier. */
  /** ID 是稳定的 model_ 标识。 */
  id: string;
  /** UpstreamModelID is the exact upstream model identifier. */
  /** UpstreamModelID 是精确上游模型标识。 */
  upstream_model_id: string;
  /** DisplayName is the management-facing label. */
  /** DisplayName 是管理界面名称。 */
  display_name: string;
}

// CustomCatalogOffering binds one custom model to one configured upstream channel.
// CustomCatalogOffering 将一个自定义模型绑定到一个已配置上游通道。
export interface CustomCatalogOffering {
  /** ID is the stable offer_ identifier. */
  /** ID 是稳定的 offer_ 标识。 */
  id: string;
  /** ProviderModelID references a model in the same document. */
  /** ProviderModelID 引用同一文档内的模型。 */
  provider_model_id: string;
  /** ChannelID selects the exact configured provider channel. */
  /** ChannelID 选择精确已配置供应商通道。 */
  channel_id: string;
  /** UpstreamModelID is the exact model identifier for this channel. */
  /** UpstreamModelID 是此通道的精确模型标识。 */
  upstream_model_id: string;
  /** Capabilities declares the channel baseline. */
  /** Capabilities 声明通道能力基线。 */
  capabilities: CustomModelCapabilities;
}

// CustomCatalogProfile declares one client-selectable capability shape for an offering.
// CustomCatalogProfile 声明一个产品可供客户端选择的能力形态。
export interface CustomCatalogProfile {
  /** ID is the stable profile_ identifier. */
  /** ID 是稳定的 profile_ 标识。 */
  id: string;
  /** OfferingID references an offering in the same document. */
  /** OfferingID 引用同一文档内的产品。 */
  offering_id: string;
  /** DisplayName is the client-visible profile label. */
  /** DisplayName 是客户端可见规格名称。 */
  display_name: string;
  /** Default permits clients to omit profile selection. */
  /** Default 允许客户端省略规格选择。 */
  default: boolean;
  /** Capabilities declares the effective profile ceiling. */
  /** Capabilities 声明有效规格上限。 */
  capabilities: CustomModelCapabilities;
  /** RequiredEntitlementClasses optionally limits eligible credential classes. */
  /** RequiredEntitlementClasses 可选限制有资格的凭据类别。 */
  required_entitlement_classes: string[];
  /** SwitchPolicy defines active-conversation profile switching. */
  /** SwitchPolicy 定义活动会话规格切换。 */
  switch_policy: string;
  /** PoolPolicy defines local credential selection. */
  /** PoolPolicy 定义本地凭据选择。 */
  pool_policy: string;
}

// CustomCatalogDocument is the complete editable non-secret catalog for one custom provider instance.
// CustomCatalogDocument 是一个自定义供应商实例完整可编辑且非秘密的目录。
export interface CustomCatalogDocument {
  /** Models contains logical declared models. */
  /** Models 包含声明的逻辑模型。 */
  models: CustomCatalogModel[];
  /** Offerings contains channel-specific model offerings. */
  /** Offerings 包含通道特定模型产品。 */
  offerings: CustomCatalogOffering[];
  /** Profiles contains client-selectable execution profiles. */
  /** Profiles 包含客户端可选择执行规格。 */
  profiles: CustomCatalogProfile[];
}

// APIKey describes one management-visible plaintext call-plane key record.
// APIKey 描述一条管理面可见的明文调用面密钥记录。
export interface APIKey {
  /** ID is the immutable call-plane key identifier. */
  /** ID 是不可变调用面密钥标识。 */
  id: string;
  /** Name is the management-facing key label. */
  /** Name 是管理界面密钥名称。 */
  name: string;
  /** Key is the plaintext bearer value visible only to management requests. */
  /** Key 是仅对管理请求可见的明文 Bearer 值。 */
  key: string;
  /** Enabled controls call-plane authentication eligibility. */
  /** Enabled 控制调用面认证资格。 */
  enabled: boolean;
}
