import { z } from "zod";

// httpURLSchema accepts only browser-safe HTTP(S) addresses after URL syntax validation.
// httpURLSchema 在 URL 语法校验后仅接受浏览器安全的 HTTP(S) 地址。
const httpURLSchema = z
  .string()
  .url()
  .refine((value) => {
    // protocol is normalized by the URL parser before the closed scheme check.
    // protocol 在封闭 Scheme 校验前由 URL 解析器规范化。
    const protocol = new URL(value).protocol;
    return protocol === "http:" || protocol === "https:";
  }, "URL must use HTTP or HTTPS");

// ProviderEndpointPreset describes one trusted default address returned by the management API.
// ProviderEndpointPreset 描述管理 API 返回的一个受信任默认地址。
export interface ProviderEndpointPreset {
  // id is stable within one provider definition.
  // id 在一个供应商定义内保持稳定。
  id: string;
  // base_url is the trusted fixed upstream address, or empty when parameters materialize the address.
  // base_url 是受信任的固定上游地址；当地址由参数实例化时为空。
  base_url: string;
  // region is the locale-neutral site label.
  // region 是与区域设置无关的站点标签。
  region: string;
  // user_editable reports whether the address may be changed during onboarding.
  // user_editable 表示录入期间是否可以修改地址。
  user_editable: boolean;
  // parameters declares the exact non-secret values required to materialize this endpoint.
  // parameters 声明实例化此端点所需的精确非秘密值。
  parameters: ProviderEndpointParameter[];
}

// ProviderEndpointParameter describes one closed non-secret endpoint input.
// ProviderEndpointParameter 描述一个封闭的非秘密端点输入。
export interface ProviderEndpointParameter {
  // id is the immutable request field identifier.
  // id 是不可变的请求字段标识。
  id: string;
  // kind identifies the server-owned validation rule.
  // kind 标识服务端拥有的校验规则。
  kind: "hostname_label";
  // required reports whether onboarding must supply the value.
  // required 表示录入是否必须提供该值。
  required: boolean;
}

// ProviderDefinition describes one exact selectable site or commercial product.
// ProviderDefinition 描述一个精确可选择的站点或商业产品。
export interface ProviderDefinition {
  // id is the immutable system definition identifier.
  // id 是不可变的系统定义标识。
  id: string;
  // display_name is the complete locale-neutral provider name.
  // display_name 是完整且与区域设置无关的供应商名称。
  display_name: string;
  // group_id identifies the management-only provider family.
  // group_id 标识仅供管理使用的供应商系列。
  group_id: string;
  // variant_name is the concise site or plan label.
  // variant_name 是简洁的站点或套餐标签。
  variant_name: string;
  // variant_description explains the exact product boundary.
  // variant_description 说明精确的产品边界。
  variant_description: string;
  // variant_description_key identifies authored localization for this variant.
  // variant_description_key 标识此变体的编写本地化文本。
  variant_description_key?: string;
  // model_catalog_id identifies shared trusted model metadata.
  // model_catalog_id 标识共享的受信任模型元数据。
  model_catalog_id: string;
  // protocol_profile_id identifies the provider's one preferred protocol.
  // protocol_profile_id 标识供应商唯一的优势协议。
  protocol_profile_id: string;
  // endpoint_presets lists trusted onboarding addresses.
  // endpoint_presets 列出受信任的录入地址。
  endpoint_presets: ProviderEndpointPreset[];
  // auth_methods lists exact credential acquisition mechanisms.
  // auth_methods 列出精确凭据获取机制。
  auth_methods: ProviderAuthMethod[];
  // plan_options lists immutable commercial tiers accepted by manual credential onboarding.
  // plan_options 列出人工凭据录入可选择的不可变商业档位。
  plan_options: ProviderPlanOption[];
  // features reports provider-native management readers implemented by the server.
  // features 报告服务端实现的供应商原生管理读取器。
  features: ProviderFeatures;
}

// ProviderFeatures identifies trusted provider-native metadata readers.
// ProviderFeatures 标识受信任的供应商原生元数据读取器。
export interface ProviderFeatures {
  // model_discovery identifies the provider-native model catalog reader.
  // model_discovery 标识供应商原生模型目录读取器。
  model_discovery: string;
  // plan_reader identifies the provider-native commercial plan reader.
  // plan_reader 标识供应商原生商业套餐读取器。
  plan_reader: string;
  // entitlement_reader identifies the provider-native entitlement reader.
  // entitlement_reader 标识供应商原生权益读取器。
  entitlement_reader: string;
  // allowance_reader identifies the provider-native quota or credit reader.
  // allowance_reader 标识供应商原生额度或积分读取器。
  allowance_reader: string;
}

// ProviderAuthMethod describes one definition-owned authentication mechanism.
// ProviderAuthMethod 描述一种由定义拥有的认证机制。
export interface ProviderAuthMethod {
  // id is the immutable definition-owned authentication method identifier.
  // id 是由 Definition 拥有的不可变认证方式标识。
  id: string;
  // type identifies the credential acquisition mechanism.
  // type 标识凭据获取机制。
  type: string;
  // refreshable reports whether the server can renew this credential.
  // refreshable 表示服务端能否续期此凭据。
  refreshable: boolean;
  // multiple_credentials reports whether one instance accepts an account pool for this method.
  // multiple_credentials 表示一个实例是否接受该认证方式的账号池。
  multiple_credentials: boolean;
  // plan_acquisition identifies how this authentication method obtains plan evidence.
  // plan_acquisition 标识该认证方式如何获得套餐证据。
  plan_acquisition:
    | "provider_detected"
    | "manual_required"
    | "manual_optional"
    | "unavailable";
}

// ProviderPlanOption describes one safe code-owned commercial tier.
// ProviderPlanOption 描述一个安全的代码拥有商业档位。
export interface ProviderPlanOption {
  // id is the stable onboarding request value.
  // id 是稳定的录入请求值。
  id: string;
  // display_name is the provider's locale-neutral plan name.
  // display_name 是供应商与语言环境无关的套餐名称。
  display_name: string;
  // display_name_key identifies optional authored localization.
  // display_name_key 标识可选的客户端编写本地化文本。
  display_name_key?: string;
  // auth_method_ids lists exact authentication methods associated with the tier.
  // auth_method_ids 列出与该档位关联的精确认证方式。
  auth_method_ids: string[];
  // manually_selectable reports whether the browser may submit this option.
  // manually_selectable 表示浏览器是否可以提交该选项。
  manually_selectable: boolean;
  // sort_order is the stable display order.
  // sort_order 是稳定显示顺序。
  sort_order: number;
  // revision is the immutable option revision.
  // revision 是不可变选项修订号。
  revision: number;
}

// ProviderDefinitionIdentity contains the common display and capability contract used by grouped and custom definitions.
// ProviderDefinitionIdentity 包含分组定义与自定义定义共用的显示和能力合同。
export interface ProviderDefinitionIdentity {
  // id is the immutable definition identifier.
  // id 是不可变的 Definition 标识。
  id: string;
  // display_name is the management-facing provider name.
  // display_name 是管理界面显示的供应商名称。
  display_name: string;
  // protocol_profile_id identifies the definition's sole executable protocol.
  // protocol_profile_id 标识 Definition 唯一的可执行协议。
  protocol_profile_id: string;
  // auth_methods lists the exact authentication mechanisms owned by the definition.
  // auth_methods 列出 Definition 拥有的精确认证机制。
  auth_methods: ProviderAuthMethod[];
  // plan_options contains code-owned commercial tiers when applicable.
  // plan_options 在适用时包含代码拥有商业档位。
  plan_options: ProviderPlanOption[];
  // features reports server-verified provider-native metadata readers.
  // features 报告服务端验证的供应商原生元数据读取器。
  features: ProviderFeatures;
}

// ProviderDefinitionSummary describes one system or custom definition returned by the ungrouped management inventory.
// ProviderDefinitionSummary 描述未分组管理清单返回的一个系统或自定义 Definition。
export interface ProviderDefinitionSummary extends ProviderDefinitionIdentity {
  // kind distinguishes code-owned system definitions from user-owned custom definitions.
  // kind 区分代码拥有的系统 Definition 与用户拥有的自定义 Definition。
  kind: "system" | "custom";
}

// ProviderGroup describes one management catalog brand and its selectable variants.
// ProviderGroup 描述一个管理目录品牌及其可选择变体。
export interface ProviderGroup {
  // id is the immutable management group identifier.
  // id 是不可变的管理分组标识。
  id: string;
  // display_name is the locale-neutral brand name.
  // display_name 是与区域设置无关的品牌名称。
  display_name: string;
  // description explains the shared provider family.
  // description 说明共享的供应商系列。
  description: string;
  // description_key identifies authored localization for this provider group.
  // description_key 标识此供应商分组的编写本地化文本。
  description_key?: string;
  // provider_definitions contains exact selectable variants.
  // provider_definitions 包含精确可选择的变体。
  provider_definitions: ProviderDefinition[];
}

// SystemOnboardingInput contains one operator-visible name and the exact API-key acquisition facts.
// SystemOnboardingInput 包含一个操作员可见名称与精确的 API Key 获取事实。
export interface SystemOnboardingInput {
  // provider_definition_id selects the exact system provider variant.
  // provider_definition_id 选择精确的系统供应商变体。
  provider_definition_id: string;
  // name is reused for the instance and credential because API keys expose no provider identity.
  // name 同时用于实例与凭据，因为 API Key 不提供供应商身份。
  name: string;
  // auth_method_id selects one definition-owned authentication mechanism.
  // auth_method_id 选择一种由 Definition 拥有的认证机制。
  auth_method_id: string;
  // secret carries the transient provider credential to the server.
  // secret 将临时供应商凭据传递给服务端。
  secret: string;
  // plan_option_id selects one code-owned tier for manual plan acquisition.
  // plan_option_id 为人工套餐获取选择一个代码拥有档位。
  plan_option_id?: string;
  // endpoint_parameters contains only values declared by the selected endpoint preset.
  // endpoint_parameters 仅包含所选端点预设声明的值。
  endpoint_parameters?: Array<{ id: string; value: string }>;
}

// VertexServiceAccountOnboardingInput contains one transient typed JSON document whose identity is derived server-side.
// VertexServiceAccountOnboardingInput 包含一个临时类型化 JSON 文档，其身份由服务端派生。
export interface VertexServiceAccountOnboardingInput
  extends Partial<CredentialReauthorizationTarget> {
  // provider_definition_id selects the Vertex system definition.
  // provider_definition_id 选择 Vertex 系统 Definition。
  provider_definition_id: string;
  // location selects the exact Vertex regional endpoint.
  // location 选择精确的 Vertex 区域端点。
  location: string;
  // service_account is the transient typed Google service account document.
  // service_account 是临时且类型化的 Google 服务账号文档。
  service_account: Record<string, unknown>;
}

// SystemOnboardingResponse contains only identifiers created by the server-owned transaction.
// SystemOnboardingResponse 仅包含服务端拥有事务创建的标识。
export interface SystemOnboardingResponse {
  // provider_instance_id identifies the committed provider instance.
  // provider_instance_id 标识已提交的供应商实例。
  provider_instance_id: string;
  // credential_id identifies the committed provider credential.
  // credential_id 标识已提交的供应商凭据。
  credential_id: string;
  // endpoint_ids lists the endpoints committed by the transaction.
  // endpoint_ids 列出事务提交的端点。
  endpoint_ids: string[];
  // binding_ids lists the executable access bindings committed by the transaction.
  // binding_ids 列出事务提交的可执行访问绑定。
  binding_ids: string[];
}

// CustomProtocolProfile describes one executable protocol explicitly selectable for a custom provider.
// CustomProtocolProfile 描述一个可供自定义供应商显式选择的可执行协议。
export interface CustomProtocolProfile {
  // id is the immutable wire protocol identifier.
  // id 是不可变的 Wire 协议标识。
  id: string;
  // version is the process-owned behavior version.
  // version 是进程拥有的行为版本。
  version: string;
  // display_name is the management-facing protocol name.
  // display_name 是管理界面显示的协议名称。
  display_name: string;
  // user_configurable confirms that custom definitions may select this profile.
  // user_configurable 确认自定义 Definition 可以选择此 Profile。
  user_configurable: boolean;
  // runtime_ready confirms that an execution factory exists in this process.
  // runtime_ready 确认当前进程存在执行 Factory。
  runtime_ready: boolean;
  // allowed_auth_methods contains the exact fixed secret carrier for this profile.
  // allowed_auth_methods 包含此 Profile 精确且固定的 Secret 载体。
  allowed_auth_methods: Array<"bearer" | "header_api_key">;
}

// CustomProviderOnboardingInput contains the complete one-request custom compatibility configuration.
// CustomProviderOnboardingInput 包含完整的单请求自定义兼容供应商配置。
export interface CustomProviderOnboardingInput {
  // display_name is reused as the provider, instance, and credential label.
  // display_name 同时作为供应商、实例与凭据标签。
  display_name: string;
  // handle is the stable workspace-visible routing identifier.
  // handle 是工作区可见的稳定路由标识。
  handle: string;
  // protocol_profile_id selects one whitelisted execution factory.
  // protocol_profile_id 选择一个白名单执行 Factory。
  protocol_profile_id: string;
  // base_url is the operator-owned versioned compatibility endpoint.
  // base_url 是操作员拥有的带版本兼容 Endpoint。
  base_url: string;
  // secret is transient credential material sent only to the local management API.
  // secret 是仅发送到本地管理 API 的临时凭据材料。
  secret: string;
  // upstream_model_id is the exact model identifier sent on the wire.
  // upstream_model_id 是在 Wire 上发送的精确模型标识。
  upstream_model_id: string;
  // model_display_name is an optional management-facing model label.
  // model_display_name 是可选的管理界面模型标签。
  model_display_name: string;
}

// CustomProviderOnboardingResponse contains only server-allocated identifiers from the committed graph.
// CustomProviderOnboardingResponse 仅包含已提交访问图中由服务端分配的标识。
export interface CustomProviderOnboardingResponse {
  // provider_definition_id identifies the committed user-owned definition.
  // provider_definition_id 标识已提交且由用户拥有的 Definition。
  provider_definition_id: string;
  // provider_instance_id identifies the committed provider instance.
  // provider_instance_id 标识已提交的供应商实例。
  provider_instance_id: string;
  // credential_id identifies the committed non-secret credential metadata.
  // credential_id 标识已提交的非秘密凭据元数据。
  credential_id: string;
  // endpoint_id identifies the committed compatibility endpoint.
  // endpoint_id 标识已提交的兼容 Endpoint。
  endpoint_id: string;
  // binding_id identifies the committed executable access binding.
  // binding_id 标识已提交的可执行访问绑定。
  binding_id: string;
  // provider_model_id identifies the sole initial user-declared model.
  // provider_model_id 标识唯一初始用户声明模型。
  provider_model_id: string;
}

// KimiDeviceFlow contains management-safe verification data without provider secret codes.
// KimiDeviceFlow 包含不带供应商秘密码的管理安全验证数据。
export interface KimiDeviceFlow {
  // id is the opaque server-owned device-flow identifier.
  // id 是由服务端拥有的不透明设备授权流程标识。
  id: string;
  // user_code is the short code displayed to the operator.
  // user_code 是向操作员显示的短验证码。
  user_code: string;
  // verification_uri is the provider verification page.
  // verification_uri 是供应商验证页面。
  verification_uri: string;
  // verification_uri_complete is the provider page with the user code embedded.
  // verification_uri_complete 是已嵌入用户验证码的供应商页面。
  verification_uri_complete: string;
  // expires_at is the server-calculated flow expiration timestamp.
  // expires_at 是服务端计算的流程到期时间。
  expires_at: string;
  // poll_interval_seconds is the minimum provider polling interval.
  // poll_interval_seconds 是供应商允许的最小轮询间隔。
  poll_interval_seconds: number;
}

// XAIDeviceFlow shares the management-safe RFC 8628 projection used by xAI authorization.
// XAIDeviceFlow 共享 xAI 授权使用的管理安全 RFC 8628 投影。
export type XAIDeviceFlow = KimiDeviceFlow;

// CodexDeviceFlow shares the management-safe device projection used by OpenAI Codex authorization.
// CodexDeviceFlow 共享 OpenAI Codex 授权使用的管理安全设备投影。
export type CodexDeviceFlow = KimiDeviceFlow;

// AntigravityOAuthFlow contains the token-free Google consent URL and local callback instructions.
// AntigravityOAuthFlow 包含不带 Token 的 Google 同意授权 URL 与本地回调说明。
export interface AntigravityOAuthFlow {
  // id is the opaque server-owned OAuth flow identifier.
  // id 是由服务端拥有的不透明 OAuth 流程标识。
  id: string;
  // authorization_url is the provider consent URL opened by the operator.
  // authorization_url 是操作员打开的供应商授权同意 URL。
  authorization_url: string;
  // redirect_uri is the exact localhost callback registered for this flow.
  // redirect_uri 是此流程注册的精确 localhost 回调地址。
  redirect_uri: string;
  // expires_at is the server-calculated flow expiration timestamp.
  // expires_at 是服务端计算的流程到期时间。
  expires_at: string;
}

// ClaudeOAuthFlow shares the management-safe browser authorization envelope used by Claude Code.
// ClaudeOAuthFlow 共享 Claude Code 使用的管理安全浏览器授权信封。
export type ClaudeOAuthFlow = AntigravityOAuthFlow;

// CodexOAuthFlow shares the management-safe browser authorization envelope used by OpenAI Codex.
// CodexOAuthFlow 共享 OpenAI Codex 使用的管理安全浏览器授权信封。
export type CodexOAuthFlow = AntigravityOAuthFlow;

// ProviderInstance describes one configured provider without exposing secret material.
// ProviderInstance 描述一个已配置供应商且不暴露秘密材料。
export interface ProviderInstance {
  // id is the immutable provider instance identifier.
  // id 是不可变供应商实例标识。
  id: string;
  // definition_id identifies the exact provider variant.
  // definition_id 标识精确供应商变体。
  definition_id: string;
  // handle is the stable routing alias.
  // handle 是稳定路由别名。
  handle: string;
  // display_name is the management-facing instance name.
  // display_name 是管理界面实例名称。
  display_name: string;
  // status is the current configuration lifecycle state.
  // status 是当前配置生命周期状态。
  status: string;
  // routing_strategy is empty when this instance inherits the Router-wide default.
  // routing_strategy 在该实例继承 Router 全局默认值时为空。
  routing_strategy: "" | "round_robin" | "fill_first";
  // disabled_model_ids lists models disabled by local policy.
  // disabled_model_ids 列出被本地策略禁用的模型。
  disabled_model_ids: string[];
  // endpoint_count is the number of configured endpoints.
  // endpoint_count 是已配置端点数量。
  endpoint_count: number;
  // credential_count is the number of configured credentials.
  // credential_count 是已配置凭据数量。
  credential_count: number;
  // binding_count is the number of configured access bindings.
  // binding_count 是已配置访问绑定数量。
  binding_count: number;
  // revision is the persisted instance revision.
  // revision 是持久化实例修订号。
  revision: number;
}

// ProviderCredential describes one management-safe authorization entry.
// ProviderCredential 描述一个管理安全的授权条目。
export interface ProviderCredential {
  // id is the immutable credential identifier.
  // id 是不可变凭据标识。
  id: string;
  // provider_instance_id identifies the exact owner.
  // provider_instance_id 标识精确所有者。
  provider_instance_id: string;
  // auth_method_id identifies the definition-owned authentication method.
  // auth_method_id 标识定义拥有的认证方式。
  auth_method_id: string;
  // label is the operator-authored API or account name.
  // label 是操作员填写的 API 或账号名称。
  label: string;
  // status is the local credential eligibility state.
  // status 是本地凭据资格状态。
  status: string;
  // expires_at is the provider-reported expiration when known.
  // expires_at 是已知时供应商报告的到期时间。
  expires_at: string | null;
  // cooling_until is the local recovery time when cooling applies.
  // cooling_until 是适用冷却时的本地恢复时间。
  cooling_until: string | null;
  // priority orders this account before endpoint paths.
  // priority 在入口路径之前排列该账号。
  priority: number;
  // declared_plan contains operator-authored plan evidence when present.
  // declared_plan 在存在时包含操作员声明的套餐证据。
  declared_plan?: {
    plan_option_id: string;
    declared_at: string;
    revision: number;
  };
  // revision is the persisted credential revision.
  // revision 是持久化凭据修订号。
  revision: number;
}

// AuthorizedProvider joins one configured instance with its non-secret authorization list.
// AuthorizedProvider 将一个已配置实例与其非秘密授权列表连接起来。
export interface AuthorizedProvider {
  // instance contains the provider identity and lifecycle state.
  // instance 包含供应商身份与生命周期状态。
  instance: ProviderInstance;
  // credentials contains every configured API key or device authorization.
  // credentials 包含每个已配置 API 密钥或设备授权。
  credentials: ProviderCredential[];
}

// CredentialReauthorizationTarget selects an existing local credential for replacement.
// CredentialReauthorizationTarget 选择一个需要替换的既有本地凭据。
export interface CredentialReauthorizationTarget {
  // provider_instance_id owns the credential.
  // provider_instance_id 拥有该凭据。
  provider_instance_id: string;
  // credential_id identifies the exact credential.
  // credential_id 标识精确凭据。
  credential_id: string;
}

// ProviderCatalogModel contains the management-safe identity and local eligibility of one refreshed model.
// ProviderCatalogModel 包含一个已刷新模型的管理安全身份与本地可用性。
export interface ProviderCatalogModel {
  // id is the provider-scoped model identifier selected by VulcanCode.
  // id 是 VulcanCode 选择的供应商作用域模型标识。
  id: string;
  // upstream_model_id is the exact provider model identifier used on the wire.
  // upstream_model_id 是在 Wire 上使用的精确供应商模型标识。
  upstream_model_id: string;
  // display_name is the management-facing model name.
  // display_name 是管理界面显示的模型名称。
  display_name: string;
  // entitlement_mode identifies whether provider-account authorization gates the model.
  // entitlement_mode 标识模型是否受供应商账号授权约束。
  entitlement_mode: "all_bound_credentials" | "explicit";
  // enabled reports whether local policy allows this model.
  // enabled 表示本地策略是否允许此模型。
  enabled: boolean;
  // authorization_status preserves authorized, denied, and unknown evidence.
  // authorization_status 保留已授权、已拒绝与未知证据。
  authorization_status: "authorized" | "denied" | "unknown";
}

// ProviderPlan contains one identity-free commercial plan aggregate.
// ProviderPlan 包含一个不带身份信息的商业套餐聚合。
export interface ProviderPlan {
  // plan_code is the provider-issued stable plan identifier.
  // plan_code 是供应商签发的稳定套餐标识。
  plan_code: string;
  // plan_name is the management-safe commercial plan name.
  // plan_name 是可安全用于管理界面的商业套餐名称。
  plan_name: string;
  // status is the normalized plan lifecycle state.
  // status 是规范化的套餐生命周期状态。
  status: string;
  // credential_count is the number of credentials reporting this aggregate.
  // credential_count 是报告此聚合结果的凭据数量。
  credential_count: number;
  // evidence_source identifies provider-detected or operator-declared plan evidence.
  // evidence_source 标识供应商自动识别或操作员声明的套餐证据。
  evidence_source:
    | "provider_api"
    | "protected_token_claim"
    | "operator_declared"
    | "system_rule"
    | "runtime_observation";
  // observed_at is the newest observation represented by this aggregate.
  // observed_at 是该聚合所代表的最新观测时间。
  observed_at: string;
  // expires_at is the earliest finite expiry when present.
  // expires_at 是存在时最早的有限到期时间。
  expires_at?: string;
}

// ProviderAllowanceWindow preserves provider-authored quota reset semantics without exposing account identity.
// ProviderAllowanceWindow 在不暴露账号身份的情况下保留供应商编写的额度重置语义。
export interface ProviderAllowanceWindow {
  // kind identifies rolling, calendar, or provider-defined advancement semantics.
  // kind 标识滚动、日历或供应商自定义推进语义。
  kind: "rolling" | "calendar" | "provider_defined";
  // duration is the exact base-10 nanosecond length for rolling windows.
  // duration 是滚动窗口精确的十进制纳秒时长。
  duration: string;
  // calendar_unit identifies the provider-authored calendar boundary.
  // calendar_unit 标识供应商编写的日历边界。
  calendar_unit?: string;
  // time_zone identifies the provider calendar time zone when known.
  // time_zone 标识已知时的供应商日历时区。
  time_zone?: string;
  // reset_at is the next provider-reported recovery time when known.
  // reset_at 是已知时供应商报告的下次恢复时间。
  reset_at?: string;
}

// ProviderAllowance contains one redacted provider quota or credit observation.
// ProviderAllowance 包含一个脱敏的供应商额度或积分观测。
export interface ProviderAllowance {
  // credential_id identifies the local credential for credential-scoped usage.
  // credential_id 标识凭据作用域用量对应的本地凭据。
  credential_id?: string;
  // credential_label is the operator-authored local credential name.
  // credential_label 是操作员编写的本地凭据名称。
  credential_label?: string;
  // kind identifies the normalized allowance category.
  // kind 标识规范化的额度类别。
  kind: string;
  // scope identifies the provider resource governed by this allowance.
  // scope 标识此额度约束的供应商资源。
  scope: string;
  // metric identifies the measured provider quantity.
  // metric 标识被测量的供应商数量。
  metric: string;
  // unit identifies the quantity representation.
  // unit 标识数量表示单位。
  unit: string;
  // currency identifies the ISO currency when the allowance is monetary.
  // currency 在额度为金额时标识 ISO 货币。
  currency?: string;
  // limit is the provider-reported maximum quantity.
  // limit 是供应商报告的最大数量。
  limit?: string;
  // used is the provider-reported consumed quantity.
  // used 是供应商报告的已使用数量。
  used?: string;
  // remaining is the provider-reported available quantity.
  // remaining 是供应商报告的可用数量。
  remaining?: string;
  // remaining_ratio is the normalized available fraction when derivable.
  // remaining_ratio 是可推导时规范化的可用比例。
  remaining_ratio?: number;
  // status is the normalized allowance lifecycle state.
  // status 是规范化的额度生命周期状态。
  status: string;
  // mandatory reports whether execution eligibility depends on this allowance.
  // mandatory 表示执行资格是否依赖此额度。
  mandatory: boolean;
  // window preserves reset semantics for window-scoped quotas.
  // window 为窗口额度保留重置语义。
  window?: ProviderAllowanceWindow;
  // observed_at is the server timestamp for this provider observation.
  // observed_at 是此供应商观测的服务端时间戳。
  observed_at: string;
  // expires_at is the provider allowance expiration timestamp.
  // expires_at 是供应商额度到期时间戳。
  expires_at: string;
}

// ProviderCatalogMetadata contains the management-safe portion of one refreshed catalog snapshot.
// ProviderCatalogMetadata 包含一个已刷新目录快照中管理安全的部分。
export interface ProviderCatalogMetadata {
  // provider_instance_id identifies the refreshed provider instance.
  // provider_instance_id 标识已刷新的供应商实例。
  provider_instance_id: string;
  // models contains the refreshed provider model inventory and local eligibility.
  // models 包含已刷新的供应商模型清单与本地可用性。
  models: ProviderCatalogModel[];
  // plans contains normalized identity-free commercial plan aggregates.
  // plans 包含规范化且不带身份信息的商业套餐聚合。
  plans: ProviderPlan[];
  // allowances contains normalized quota and credit observations.
  // allowances 包含规范化的额度与积分观测。
  allowances: ProviderAllowance[];
  // revision is the committed catalog snapshot revision.
  // revision 是已提交目录快照的修订号。
  revision: number;
  // observed_at is the server timestamp for the complete refresh.
  // observed_at 是完整刷新操作的服务端时间戳。
  observed_at: string;
}

// endpointParameterDefinitionSchema validates the server's closed endpoint parameter contract.
// endpointParameterDefinitionSchema 校验服务端封闭的端点参数合同。
const endpointParameterDefinitionSchema = z.object({
  id: z.string().min(1),
  kind: z.literal("hostname_label"),
  required: z.boolean(),
});

// providerEndpointPresetSchema accepts either one fixed URL or one explicitly parameterized endpoint.
// providerEndpointPresetSchema 接受一个固定 URL 或一个显式参数化端点。
const providerEndpointPresetSchema = z
  .object({
    id: z.string().min(1),
    base_url: z.union([z.literal(""), httpURLSchema]),
    region: z.string().min(1),
    user_editable: z.boolean(),
    parameters: z
      .array(endpointParameterDefinitionSchema)
      .optional()
      .default([]),
  })
  .superRefine((preset, context) => {
    const parameterized = preset.parameters.length > 0;
    if ((preset.base_url === "") !== parameterized) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          "endpoint must provide either one fixed base URL or declared parameters",
      });
    }
  });

// providerGroupListResponseSchema validates the complete untrusted management response before UI state owns it.
// providerGroupListResponseSchema 在 UI 状态接管前校验完整的不受信任管理响应。
const providerGroupListResponseSchema = z.object({
  provider_groups: z.array(
    z.object({
      id: z.string().min(1),
      display_name: z.string().min(1),
      description: z.string(),
      description_key: z.string().optional(),
      provider_definitions: z.array(
        z.object({
          id: z.string().min(1),
          display_name: z.string().min(1),
          group_id: z.string().min(1),
          variant_name: z.string().min(1),
          variant_description: z.string(),
          variant_description_key: z.string().optional(),
          model_catalog_id: z.string().min(1),
          protocol_profile_id: z.string().min(1),
          endpoint_presets: z.array(providerEndpointPresetSchema),
          auth_methods: z.array(
            z.object({
              id: z.string().min(1),
              type: z.string().min(1),
              refreshable: z.boolean(),
              multiple_credentials: z.boolean().optional().default(false),
              plan_acquisition: z
                .enum([
                  "provider_detected",
                  "manual_required",
                  "manual_optional",
                  "unavailable",
                ])
                .optional()
                .default("unavailable"),
            }),
          ),
          plan_options: z
            .array(
              z.object({
                id: z.string().min(1),
                display_name: z.string().min(1),
                display_name_key: z.string().optional(),
                auth_method_ids: z.array(z.string().min(1)),
                manually_selectable: z.boolean(),
                sort_order: z.number().int().nonnegative(),
                revision: z.number().int().positive(),
              }),
            )
            .optional()
            .default([]),
          features: z.object({
            model_discovery: z.string(),
            plan_reader: z.string(),
            entitlement_reader: z.string(),
            allowance_reader: z.string(),
          }),
        }),
      ),
    }),
  ),
});

// providerDefinitionSummarySchema validates the common identity required to render authorized custom providers.
// providerDefinitionSummarySchema 校验渲染已授权自定义供应商所需的公共身份。
const providerDefinitionSummarySchema = z.object({
  id: z.string().min(1),
  kind: z.enum(["system", "custom"]),
  display_name: z.string().min(1),
  protocol_profile_id: z.string().min(1),
  auth_methods: z.array(
    z.object({
      id: z.string().min(1),
      type: z.string().min(1),
      refreshable: z.boolean(),
      multiple_credentials: z.boolean().optional().default(false),
      plan_acquisition: z
        .enum([
          "provider_detected",
          "manual_required",
          "manual_optional",
          "unavailable",
        ])
        .optional()
        .default("unavailable"),
    }),
  ),
  plan_options: z
    .array(
      z.object({
        id: z.string().min(1),
        display_name: z.string().min(1),
        display_name_key: z.string().optional(),
        auth_method_ids: z.array(z.string().min(1)),
        manually_selectable: z.boolean(),
        sort_order: z.number().int().nonnegative(),
        revision: z.number().int().positive(),
      }),
    )
    .optional()
    .default([]),
  features: z.object({
    model_discovery: z.string(),
    plan_reader: z.string(),
    entitlement_reader: z.string(),
    allowance_reader: z.string(),
  }),
});

// providerDefinitionListResponseSchema validates the complete system and custom definition inventory.
// providerDefinitionListResponseSchema 校验完整的系统与自定义 Definition 清单。
const providerDefinitionListResponseSchema = z.object({
  provider_definitions: z.array(providerDefinitionSummarySchema),
});

// protocolSupportStatusSchema mirrors the backend's closed support-state contract.
// protocolSupportStatusSchema 镜像后端封闭的支持状态合同。
const protocolSupportStatusSchema = z.enum([
  "supported",
  "unsupported",
  "temporarily_unavailable",
]);

// protocolCapabilitySchema validates every process-owned profile-global behavior fact.
// protocolCapabilitySchema 校验每个由进程拥有的 Profile 全局行为事实。
const protocolCapabilitySchema = z.object({
  capability: z.enum([
    "system_instruction",
    "structured_tools",
    "parallel_tools",
    "streaming_tool_arguments",
    "strict_json_schema",
    "reasoning",
    "reasoning_continuation",
    "remote_compaction",
    "native_web_search",
    "token_counting",
  ]),
  status: protocolSupportStatusSchema,
});

// customProtocolProfileSchema validates the complete registry response before selectable profiles are filtered.
// customProtocolProfileSchema 在过滤可选择 Profile 前校验完整注册表响应。
const customProtocolProfileSchema = z
  .object({
    id: z.string().min(1),
    version: z.string().min(1),
    display_name: z.string().min(1),
    user_configurable: z.boolean(),
    runtime_ready: z.boolean(),
    model_discovery: protocolSupportStatusSchema,
    capabilities: z.array(protocolCapabilitySchema),
    allowed_auth_methods: z
      .array(z.enum(["bearer", "header_api_key"]))
      .nullable()
      .transform((methods) => methods ?? []),
  })
  .superRefine((profile, context) => {
    if (
      profile.user_configurable &&
      profile.runtime_ready &&
      profile.allowed_auth_methods.length !== 1
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          "selectable custom protocol profile requires one authentication method",
      });
    }
  });

// customProtocolProfileListResponseSchema validates process-owned protocol metadata before rendering it.
// customProtocolProfileListResponseSchema 在渲染前校验进程拥有的协议元数据。
const customProtocolProfileListResponseSchema = z.object({
  protocol_profiles: z.array(customProtocolProfileSchema),
});

// systemOnboardingResponseSchema validates identifiers returned after an atomic server commit.
// systemOnboardingResponseSchema 校验服务端原子提交后返回的标识。
const systemOnboardingResponseSchema = z.object({
  provider_instance_id: z.string().min(1),
  credential_id: z.string().min(1),
  endpoint_ids: z.array(z.string().min(1)),
  binding_ids: z.array(z.string().min(1)),
});

// customProviderOnboardingResponseSchema validates every identifier returned after the atomic custom commit.
// customProviderOnboardingResponseSchema 校验自定义原子提交后返回的每个标识。
const customProviderOnboardingResponseSchema = z.object({
  provider_definition_id: z.string().min(1),
  provider_instance_id: z.string().min(1),
  credential_id: z.string().min(1),
  endpoint_id: z.string().min(1),
  binding_id: z.string().min(1),
  provider_model_id: z.string().min(1),
});

// kimiDeviceFlowSchema validates the token-free device verification envelope.
// kimiDeviceFlowSchema 校验不含令牌的设备验证信封。
const kimiDeviceFlowSchema = z.object({
  id: z.string().min(1),
  user_code: z.string().min(1),
  verification_uri: httpURLSchema,
  verification_uri_complete: z.union([z.literal(""), httpURLSchema]),
  expires_at: z.string().datetime({ offset: true }),
  poll_interval_seconds: z.number().int().positive(),
});

// antigravityOAuthFlowSchema validates the token-free browser authorization envelope.
// antigravityOAuthFlowSchema 校验不含 Token 的浏览器授权信封。
const antigravityOAuthFlowSchema = z.object({
  id: z.string().min(1),
  authorization_url: httpURLSchema,
  redirect_uri: httpURLSchema,
  expires_at: z.string().datetime({ offset: true }),
});

// exactNonNegativeDecimalPattern matches the backend catalog's JSON-compatible exact amount contract.
// exactNonNegativeDecimalPattern 匹配后端目录与 JSON 兼容的精确数量合同。
const exactNonNegativeDecimalPattern =
  /^(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$/;

// exactNonNegativeIntegerPattern preserves nanosecond durations beyond JavaScript's safe integer range.
// exactNonNegativeIntegerPattern 保留超过 JavaScript 安全整数范围的纳秒时长。
const exactNonNegativeIntegerPattern = /^(0|[1-9][0-9]*)$/;

// providerCatalogMetadataSchema validates provider-native plan and allowance observations before rendering.
// providerCatalogMetadataSchema 在渲染前校验供应商原生套餐与额度观测。
const providerCatalogMetadataSchema = z.object({
  provider_instance_id: z.string().min(1),
  models: z.array(
    z.object({
      id: z.string().min(1),
      upstream_model_id: z.string().min(1),
      display_name: z.string().min(1),
      entitlement_mode: z.enum(["all_bound_credentials", "explicit"]),
      enabled: z.boolean(),
      authorization_status: z.enum(["authorized", "denied", "unknown"]),
    }),
  ),
  plans: z.array(
    z.object({
      plan_code: z.string().min(1),
      plan_name: z.string().min(1),
      status: z.string().min(1),
      credential_count: z.number().int().nonnegative(),
      evidence_source: z
        .enum([
          "provider_api",
          "protected_token_claim",
          "operator_declared",
          "system_rule",
          "runtime_observation",
        ])
        .optional()
        .default("provider_api"),
      observed_at: z.string().datetime({ offset: true }).optional().default("1970-01-01T00:00:00Z"),
      expires_at: z.string().datetime({ offset: true }).optional(),
    }),
  ),
  allowances: z.array(
    z.object({
      credential_id: z.string().min(1).optional(),
      credential_label: z.string().optional(),
      kind: z.enum([
        "window_quota",
        "balance",
        "credit_grant",
        "provider_defined",
      ]),
      scope: z.enum([
        "credential",
        "subscription",
        "organization",
        "project",
        "billing_account",
        "provider_model",
        "execution_profile",
        "capability",
      ]),
      metric: z.string().min(1),
      unit: z.enum([
        "tokens",
        "requests",
        "weighted_tokens",
        "provider_credits",
        "minor_currency_units",
        "percentage",
        "provider_defined",
      ]),
      currency: z
        .string()
        .regex(/^[A-Z]{3}$/)
        .optional(),
      limit: z.string().regex(exactNonNegativeDecimalPattern).optional(),
      used: z.string().regex(exactNonNegativeDecimalPattern).optional(),
      remaining: z.string().regex(exactNonNegativeDecimalPattern).optional(),
      remaining_ratio: z.number().finite().min(0).max(1).optional(),
      status: z.enum([
        "available",
        "low",
        "exhausted",
        "unknown_sufficiency",
        "unavailable",
      ]),
      mandatory: z.boolean(),
      window: z
        .object({
          kind: z.enum(["rolling", "calendar", "provider_defined"]),
          duration: z.string().regex(exactNonNegativeIntegerPattern),
          calendar_unit: z.string().min(1).optional(),
          time_zone: z.string().min(1).optional(),
          reset_at: z.string().datetime({ offset: true }).optional(),
        })
        .optional(),
      observed_at: z.string().datetime({ offset: true }),
      expires_at: z.string().datetime({ offset: true }),
    }),
  ),
  revision: z.number().int().positive(),
  observed_at: z.string().datetime({ offset: true }),
});

// controlErrorResponseSchema validates the stable non-sensitive error envelope returned by management APIs.
// controlErrorResponseSchema 校验管理 API 返回的稳定且不敏感错误信封。
const controlErrorResponseSchema = z.object({ error: z.string().min(1) });

// ProviderMetadataRefreshError preserves the server-authored failure category for localized account refresh feedback.
// ProviderMetadataRefreshError 为本地化账号刷新反馈保留服务端给出的失败分类。
export class ProviderMetadataRefreshError extends Error {
  // code is the stable management error identifier.
  // code 是稳定的管理错误标识。
  readonly code: string;
  // status is the HTTP status returned by the management endpoint.
  // status 是管理入口返回的 HTTP 状态。
  readonly status: number;

  // constructor creates one typed metadata refresh failure without retaining response bodies.
  // constructor 创建一个不保留响应正文的强类型元数据刷新失败。
  constructor(code: string, status: number) {
    super(`Provider metadata refresh failed with status ${status}`);
    this.name = "ProviderMetadataRefreshError";
    this.code = code;
    this.status = status;
  }
}

// ProviderCredentialRefreshError preserves the server-authored authentication category without retaining provider response bodies.
// ProviderCredentialRefreshError 保留服务端给出的认证分类，且不保留供应商响应正文。
export class ProviderCredentialRefreshError extends Error {
  // code is the stable management error identifier.
  // code 是稳定的管理错误标识。
  readonly code: string;
  // status is the HTTP status returned by the management endpoint.
  // status 是管理入口返回的 HTTP 状态。
  readonly status: number;

  // constructor creates one typed credential refresh failure for safe localized feedback.
  // constructor 创建一个用于安全本地化反馈的强类型凭据刷新失败。
  constructor(code: string, status: number) {
    super(`Provider credential refresh failed with status ${status}`);
    this.name = "ProviderCredentialRefreshError";
    this.code = code;
    this.status = status;
  }
}

// providerInstanceSchema validates one management-safe configured provider.
// providerInstanceSchema 校验一个管理安全的已配置供应商。
const providerInstanceSchema = z.object({
  id: z.string().min(1),
  definition_id: z.string().min(1),
  handle: z.string().min(1),
  display_name: z.string().min(1),
  status: z.string().min(1),
  routing_strategy: z
    .enum(["", "round_robin", "fill_first"])
    .optional()
    .default(""),
  // The running management API historically serialized an unset slice as null; normalize that exact shape at the boundary.
  // 当前运行中的管理 API 历史上会将未设置切片序列化为 null；在边界处规范化这一精确结构。
  disabled_model_ids: z
    .array(z.string())
    .nullable()
    .transform((modelIDs) => modelIDs ?? []),
  endpoint_count: z.number().int().nonnegative(),
  credential_count: z.number().int().nonnegative(),
  binding_count: z.number().int().nonnegative(),
  revision: z.number().int().positive(),
});

// providerCredentialSchema validates one redacted authorization entry.
// providerCredentialSchema 校验一个已脱敏授权条目。
const providerCredentialSchema = z.object({
  id: z.string().min(1),
  provider_instance_id: z.string().min(1),
  auth_method_id: z.string().min(1),
  label: z.string().min(1),
  status: z.string().min(1),
  expires_at: z.string().datetime({ offset: true }).nullable(),
  cooling_until: z.string().datetime({ offset: true }).nullable(),
  priority: z.number().int().nonnegative().optional().default(0),
  declared_plan: z
    .object({
      plan_option_id: z.string().min(1),
      declared_at: z.string().datetime({ offset: true }),
      revision: z.number().int().positive(),
    })
    .optional(),
  revision: z.number().int().positive(),
});

// providerInstanceListResponseSchema validates the complete configured-provider envelope.
// providerInstanceListResponseSchema 校验完整的已配置供应商响应信封。
const providerInstanceListResponseSchema = z.object({
  provider_instances: z.array(providerInstanceSchema),
});

// providerCredentialListResponseSchema validates one instance authorization envelope.
// providerCredentialListResponseSchema 校验一个实例授权响应信封。
const providerCredentialListResponseSchema = z.object({
  credentials: z.array(providerCredentialSchema),
});

// routingSettingsSchema validates the persisted global scheduling strategy.
// routingSettingsSchema 校验持久化全局调度策略。
const routingSettingsSchema = z.object({
  strategy: z.enum(["round_robin", "fill_first"]),
  revision: z.number().int().positive(),
  updated_at: z.string().datetime({ offset: true }),
});

// RoutingSettings contains the Router-wide account scheduling default.
// RoutingSettings 包含 Router 全局账号调度默认值。
export type RoutingSettings = z.infer<typeof routingSettingsSchema>;

// fetchProviderDefinitions loads the common identity contract for both system and user-owned custom definitions.
// fetchProviderDefinitions 加载系统与用户拥有自定义 Definition 共用的身份合同。
export async function fetchProviderDefinitions(
  managementAuthToken: string,
  signal?: AbortSignal,
): Promise<ProviderDefinitionSummary[]> {
  const response = await fetch("/vulcan/manage/provider-definitions", {
    method: "GET",
    headers: { Authorization: `Bearer ${managementAuthToken}` },
    signal,
  });
  if (!response.ok) {
    throw new Error(
      `provider definitions request failed with status ${response.status}`,
    );
  }
  const payload = providerDefinitionListResponseSchema.parse(
    await response.json(),
  );
  return payload.provider_definitions;
}

// fetchCustomProtocolProfiles loads only executable profiles that the server permits custom providers to select.
// fetchCustomProtocolProfiles 仅加载服务端允许自定义供应商选择的可执行 Profile。
export async function fetchCustomProtocolProfiles(
  managementAuthToken: string,
  signal?: AbortSignal,
): Promise<CustomProtocolProfile[]> {
  const response = await fetch("/vulcan/manage/protocol-profiles", {
    method: "GET",
    headers: { Authorization: `Bearer ${managementAuthToken}` },
    signal,
  });
  if (!response.ok) {
    throw new Error(
      `protocol profiles request failed with status ${response.status}`,
    );
  }
  const payload = customProtocolProfileListResponseSchema.parse(
    await response.json(),
  );
  return payload.protocol_profiles.filter(
    (profile) => profile.user_configurable && profile.runtime_ready,
  );
}

// fetchProviderGroups loads grouped system providers using the active in-memory management credential.
// fetchProviderGroups 使用当前内存管理凭证加载已分组系统供应商。
export async function fetchProviderGroups(
  managementAuthToken: string,
  signal?: AbortSignal,
): Promise<ProviderGroup[]> {
  const response = await fetch("/vulcan/manage/provider-groups", {
    method: "GET",
    headers: { Authorization: `Bearer ${managementAuthToken}` },
    signal,
  });
  if (!response.ok) {
    throw new Error(
      `provider groups request failed with status ${response.status}`,
    );
  }
  const payload = providerGroupListResponseSchema.parse(await response.json());
  return payload.provider_groups;
}

// fetchAuthorizedProviders loads configured instances and their redacted credentials, excluding incomplete instances without authorization.
// fetchAuthorizedProviders 加载已配置实例及其脱敏凭据，并排除没有授权的不完整实例。
export async function fetchAuthorizedProviders(
  managementAuthToken: string,
  signal?: AbortSignal,
): Promise<AuthorizedProvider[]> {
  const headers = { Authorization: `Bearer ${managementAuthToken}` };
  const response = await fetch("/vulcan/manage/provider-instances", {
    method: "GET",
    headers,
    signal,
  });
  if (!response.ok) {
    throw new Error(
      `provider instances request failed with status ${response.status}`,
    );
  }
  const payload = providerInstanceListResponseSchema.parse(
    await response.json(),
  );
  const providers = await Promise.all(
    payload.provider_instances.map(async (instance) => {
      const credentialResponse = await fetch(
        `/vulcan/manage/provider-instances/${encodeURIComponent(instance.id)}/credentials`,
        { method: "GET", headers, signal },
      );
      if (!credentialResponse.ok) {
        throw new Error(
          `provider credentials request failed with status ${credentialResponse.status}`,
        );
      }
      const credentialPayload = providerCredentialListResponseSchema.parse(
        await credentialResponse.json(),
      );
      if (
        credentialPayload.credentials.some(
          (credential) => credential.provider_instance_id !== instance.id,
        )
      ) {
        throw new Error(
          "provider credential response contains a mismatched owner",
        );
      }
      return { instance, credentials: credentialPayload.credentials };
    }),
  );
  return providers.filter((provider) => provider.credentials.length > 0);
}

// onboardSystemProvider submits one API-key variant to the server-owned atomic onboarding command.
// onboardSystemProvider 将一个 API Key 变体提交到服务端拥有的原子录入命令。
export async function onboardSystemProvider(
  managementAuthToken: string,
  input: SystemOnboardingInput,
): Promise<SystemOnboardingResponse> {
  const response = await fetch("/vulcan/manage/provider-instances/onboard", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${managementAuthToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(input),
  });
  if (!response.ok) {
    throw new Error(
      `provider onboarding failed with status ${response.status}`,
    );
  }
  return systemOnboardingResponseSchema.parse(await response.json());
}

// fetchRoutingSettings loads the persisted Router-wide account scheduling default.
// fetchRoutingSettings 加载持久化 Router 全局账号调度默认值。
export async function fetchRoutingSettings(
  managementAuthToken: string,
  signal?: AbortSignal,
): Promise<RoutingSettings> {
  const response = await fetch("/vulcan/manage/settings/routing", {
    headers: { Authorization: `Bearer ${managementAuthToken}` },
    signal,
  });
  if (!response.ok) {
    throw new Error(`routing settings request failed with status ${response.status}`);
  }
  return routingSettingsSchema.parse(await response.json());
}

// updateRoutingSettings persists one closed Router-wide account scheduling strategy.
// updateRoutingSettings 持久化一个封闭的 Router 全局账号调度策略。
export async function updateRoutingSettings(
  managementAuthToken: string,
  strategy: "round_robin" | "fill_first",
): Promise<RoutingSettings> {
  const response = await fetch("/vulcan/manage/settings/routing", {
    method: "PUT",
    headers: {
      Authorization: `Bearer ${managementAuthToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ strategy }),
  });
  if (!response.ok) {
    throw new Error(`routing settings update failed with status ${response.status}`);
  }
  return routingSettingsSchema.parse(await response.json());
}

// updateProviderRoutingStrategy sets or clears one provider-instance override.
// updateProviderRoutingStrategy 设置或清除一个供应商实例覆盖策略。
export async function updateProviderRoutingStrategy(
  managementAuthToken: string,
  providerInstanceID: string,
  strategy: "" | "round_robin" | "fill_first",
): Promise<void> {
  const response = await fetch(
    `/vulcan/manage/provider-instances/${encodeURIComponent(providerInstanceID)}/routing`,
    {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${managementAuthToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ strategy }),
    },
  );
  if (!response.ok) {
    throw new Error(`provider routing update failed with status ${response.status}`);
  }
}

// updateProviderCredentialPriority persists one nonnegative account priority.
// updateProviderCredentialPriority 持久化一个非负账号优先级。
export async function updateProviderCredentialPriority(
  managementAuthToken: string,
  providerInstanceID: string,
  credentialID: string,
  priority: number,
): Promise<void> {
  const response = await fetch(
    `/vulcan/manage/provider-instances/${encodeURIComponent(providerInstanceID)}/credentials/${encodeURIComponent(credentialID)}/priority`,
    {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${managementAuthToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ priority }),
    },
  );
  if (!response.ok) {
    throw new Error(`credential priority update failed with status ${response.status}`);
  }
}

// updateProviderCredentialPlan replaces one code-owned manual plan selection.
// updateProviderCredentialPlan 替换一个代码拥有人工套餐选择。
export async function updateProviderCredentialPlan(
  managementAuthToken: string,
  providerInstanceID: string,
  credentialID: string,
  planOptionID: string,
): Promise<void> {
  const response = await fetch(
    `/vulcan/manage/provider-instances/${encodeURIComponent(providerInstanceID)}/credentials/${encodeURIComponent(credentialID)}/plan`,
    {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${managementAuthToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ plan_option_id: planOptionID }),
    },
  );
  if (!response.ok) {
    throw new Error(`credential plan update failed with status ${response.status}`);
  }
}

// rotateProviderCredentialSecret replaces one operator-managed credential without changing its local identity.
// rotateProviderCredentialSecret 替换一个操作员管理的凭据且不改变其本地身份。
export async function rotateProviderCredentialSecret(
  managementAuthToken: string,
  providerInstanceID: string,
  credentialID: string,
  secret: string,
): Promise<void> {
  const response = await fetch(
    `/vulcan/manage/provider-instances/${encodeURIComponent(providerInstanceID)}/credentials/${encodeURIComponent(credentialID)}/secret`,
    {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${managementAuthToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ secret }),
    },
  );
  if (!response.ok)
    throw new Error(
      `provider credential replacement failed with status ${response.status}`,
    );
}

// deleteProviderCredential permanently removes one credential and its local access bindings.
// deleteProviderCredential 永久删除一个凭据及其本地访问绑定。
export async function deleteProviderCredential(
  managementAuthToken: string,
  providerInstanceID: string,
  credentialID: string,
): Promise<void> {
  const response = await fetch(
    `/vulcan/manage/provider-instances/${encodeURIComponent(providerInstanceID)}/credentials/${encodeURIComponent(credentialID)}`,
    {
      method: "DELETE",
      headers: { Authorization: `Bearer ${managementAuthToken}` },
    },
  );
  if (!response.ok)
    throw new Error(
      `provider credential deletion failed with status ${response.status}`,
    );
}

// onboardCustomProvider submits the complete compatibility definition and initial model through one atomic management command.
// onboardCustomProvider 通过一个原子管理命令提交完整兼容 Definition 与初始模型。
export async function onboardCustomProvider(
  managementAuthToken: string,
  input: CustomProviderOnboardingInput,
): Promise<CustomProviderOnboardingResponse> {
  const response = await fetch("/vulcan/manage/custom-providers/onboard", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${managementAuthToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(input),
  });
  if (!response.ok) {
    throw new Error(
      `custom provider onboarding failed with status ${response.status}`,
    );
  }
  return customProviderOnboardingResponseSchema.parse(await response.json());
}

// onboardVertexServiceAccount submits one parsed service-account object to the dedicated server validation boundary.
// onboardVertexServiceAccount 将一个已解析服务账号对象提交到专属服务端校验边界。
export async function onboardVertexServiceAccount(
  managementAuthToken: string,
  input: VertexServiceAccountOnboardingInput,
): Promise<SystemOnboardingResponse> {
  const response = await fetch(
    "/vulcan/manage/vertex/service-accounts/onboard",
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${managementAuthToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(input),
    },
  );
  if (!response.ok) {
    throw new Error(
      `Vertex service-account onboarding failed with status ${response.status}`,
    );
  }
  return systemOnboardingResponseSchema.parse(await response.json());
}

// startKimiDeviceFlow starts one token-confidential Coding Plan authorization session.
// startKimiDeviceFlow 启动一个令牌保密的 Coding Plan 授权会话。
export async function startKimiDeviceFlow(
  managementAuthToken: string,
): Promise<KimiDeviceFlow> {
  const response = await fetch("/vulcan/manage/kimi/device-flows", {
    method: "POST",
    headers: { Authorization: `Bearer ${managementAuthToken}` },
  });
  if (!response.ok) {
    throw new Error(`Kimi device flow failed with status ${response.status}`);
  }
  return kimiDeviceFlowSchema.parse(await response.json());
}

// onboardKimiDeviceFlow polls once and atomically stores a completed Coding Plan authorization.
// onboardKimiDeviceFlow 轮询一次并原子存储已完成的 Coding Plan 授权。
export async function onboardKimiDeviceFlow(
  managementAuthToken: string,
  flowID: string,
  input: Pick<SystemOnboardingInput, "provider_definition_id" | "name"> &
    Partial<CredentialReauthorizationTarget>,
): Promise<SystemOnboardingResponse | null> {
  const response = await fetch(
    `/vulcan/manage/kimi/device-flows/${encodeURIComponent(flowID)}/onboard`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${managementAuthToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(input),
    },
  );
  if (response.status === 202) {
    return null;
  }
  if (!response.ok) {
    throw new Error(
      `Kimi device onboarding failed with status ${response.status}`,
    );
  }
  return systemOnboardingResponseSchema.parse(await response.json());
}

// cancelKimiDeviceFlow releases one incomplete server-owned authorization session.
// cancelKimiDeviceFlow 释放一个尚未完成且由服务端拥有的授权会话。
export async function cancelKimiDeviceFlow(
  managementAuthToken: string,
  flowID: string,
): Promise<void> {
  const response = await fetch(
    `/vulcan/manage/kimi/device-flows/${encodeURIComponent(flowID)}`,
    {
      method: "DELETE",
      headers: { Authorization: `Bearer ${managementAuthToken}` },
    },
  );
  if (!response.ok) {
    throw new Error(
      `Kimi device flow cancellation failed with status ${response.status}`,
    );
  }
}

// startXAIDeviceFlow starts one token-confidential xAI account authorization session.
// startXAIDeviceFlow 启动一个令牌保密的 xAI 账号授权会话。
export async function startXAIDeviceFlow(
  managementAuthToken: string,
): Promise<XAIDeviceFlow> {
  const response = await fetch("/vulcan/manage/xai/device-flows", {
    method: "POST",
    headers: { Authorization: `Bearer ${managementAuthToken}` },
  });
  if (!response.ok) {
    throw new Error(`xAI device flow failed with status ${response.status}`);
  }
  return kimiDeviceFlowSchema.parse(await response.json());
}

// onboardXAIDeviceFlow polls once and atomically stores a completed xAI authorization.
// onboardXAIDeviceFlow 轮询一次并原子存储已完成的 xAI 授权。
export async function onboardXAIDeviceFlow(
  managementAuthToken: string,
  flowID: string,
  input: Pick<SystemOnboardingInput, "provider_definition_id" | "name"> &
    Partial<CredentialReauthorizationTarget>,
): Promise<SystemOnboardingResponse | null> {
  const response = await fetch(
    `/vulcan/manage/xai/device-flows/${encodeURIComponent(flowID)}/onboard`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${managementAuthToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(input),
    },
  );
  if (response.status === 202) {
    return null;
  }
  if (!response.ok) {
    throw new Error(
      `xAI device onboarding failed with status ${response.status}`,
    );
  }
  return systemOnboardingResponseSchema.parse(await response.json());
}

// cancelXAIDeviceFlow releases one incomplete server-owned xAI authorization session.
// cancelXAIDeviceFlow 释放一个尚未完成且由服务端拥有的 xAI 授权会话。
export async function cancelXAIDeviceFlow(
  managementAuthToken: string,
  flowID: string,
): Promise<void> {
  const response = await fetch(
    `/vulcan/manage/xai/device-flows/${encodeURIComponent(flowID)}`,
    {
      method: "DELETE",
      headers: { Authorization: `Bearer ${managementAuthToken}` },
    },
  );
  if (!response.ok && response.status !== 404) {
    throw new Error(
      `xAI device flow cancellation failed with status ${response.status}`,
    );
  }
}

// startCodexDeviceFlow starts one token-confidential OpenAI Codex authorization session.
// startCodexDeviceFlow 启动一个令牌保密的 OpenAI Codex 授权会话。
export async function startCodexDeviceFlow(
  managementAuthToken: string,
): Promise<CodexDeviceFlow> {
  const response = await fetch("/vulcan/manage/codex/device-flows", {
    method: "POST",
    headers: { Authorization: `Bearer ${managementAuthToken}` },
  });
  if (!response.ok) {
    throw new Error(`Codex device flow failed with status ${response.status}`);
  }
  return kimiDeviceFlowSchema.parse(await response.json());
}

// onboardCodexDeviceFlow polls once and atomically stores a completed Codex authorization.
// onboardCodexDeviceFlow 轮询一次并原子存储已完成的 Codex 授权。
export async function onboardCodexDeviceFlow(
  managementAuthToken: string,
  flowID: string,
  input: Pick<SystemOnboardingInput, "provider_definition_id" | "name"> &
    Partial<CredentialReauthorizationTarget>,
): Promise<SystemOnboardingResponse | null> {
  const response = await fetch(
    `/vulcan/manage/codex/device-flows/${encodeURIComponent(flowID)}/onboard`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${managementAuthToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(input),
    },
  );
  if (response.status === 202) {
    return null;
  }
  if (!response.ok) {
    throw new Error(
      `Codex device onboarding failed with status ${response.status}`,
    );
  }
  return systemOnboardingResponseSchema.parse(await response.json());
}

// cancelCodexDeviceFlow releases one incomplete server-owned Codex authorization session.
// cancelCodexDeviceFlow 释放一个尚未完成且由服务端拥有的 Codex 授权会话。
export async function cancelCodexDeviceFlow(
  managementAuthToken: string,
  flowID: string,
): Promise<void> {
  const response = await fetch(
    `/vulcan/manage/codex/device-flows/${encodeURIComponent(flowID)}`,
    {
      method: "DELETE",
      headers: { Authorization: `Bearer ${managementAuthToken}` },
    },
  );
  if (!response.ok && response.status !== 404) {
    throw new Error(
      `Codex device flow cancellation failed with status ${response.status}`,
    );
  }
}

// startCodexOAuthFlow starts one server-owned OpenAI browser PKCE authorization session.
// startCodexOAuthFlow 启动一个服务端拥有的 OpenAI 浏览器 PKCE 授权会话。
export async function startCodexOAuthFlow(
  managementAuthToken: string,
): Promise<CodexOAuthFlow> {
  const response = await fetch("/vulcan/manage/codex/oauth-flows", {
    method: "POST",
    headers: { Authorization: `Bearer ${managementAuthToken}` },
  });
  if (!response.ok) {
    throw new Error(`Codex OAuth flow failed with status ${response.status}`);
  }
  return antigravityOAuthFlowSchema.parse(await response.json());
}

// onboardCodexOAuthFlow completes one pasted localhost callback and atomically stores the account.
// onboardCodexOAuthFlow 完成一个粘贴的 localhost 回调并原子存储账号。
export async function onboardCodexOAuthFlow(
  managementAuthToken: string,
  flowID: string,
  input: {
    // provider_definition_id selects the exact Codex account definition.
    // provider_definition_id 选择精确的 Codex 账号 Definition。
    provider_definition_id: string;
    // callback_url is the exact pasted localhost callback returned by OpenAI.
    // callback_url 是 OpenAI 返回且由操作员粘贴的精确 localhost 回调地址。
    callback_url: string;
  } & Partial<CredentialReauthorizationTarget>,
): Promise<SystemOnboardingResponse> {
  const response = await fetch(
    `/vulcan/manage/codex/oauth-flows/${encodeURIComponent(flowID)}/onboard`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${managementAuthToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(input),
    },
  );
  if (!response.ok) {
    throw new Error(
      `Codex OAuth onboarding failed with status ${response.status}`,
    );
  }
  return systemOnboardingResponseSchema.parse(await response.json());
}

// cancelCodexOAuthFlow releases one local server-owned Codex browser authorization session.
// cancelCodexOAuthFlow 释放一个本地且由服务端拥有的 Codex 浏览器授权会话。
export async function cancelCodexOAuthFlow(
  managementAuthToken: string,
  flowID: string,
): Promise<void> {
  const response = await fetch(
    `/vulcan/manage/codex/oauth-flows/${encodeURIComponent(flowID)}`,
    {
      method: "DELETE",
      headers: { Authorization: `Bearer ${managementAuthToken}` },
    },
  );
  if (!response.ok && response.status !== 404) {
    throw new Error(
      `Codex OAuth cancellation failed with status ${response.status}`,
    );
  }
}

// startClaudeOAuthFlow starts one server-owned Claude Code PKCE authorization session.
// startClaudeOAuthFlow 启动一个服务端拥有的 Claude Code PKCE 授权会话。
export async function startClaudeOAuthFlow(
  managementAuthToken: string,
): Promise<ClaudeOAuthFlow> {
  const response = await fetch("/vulcan/manage/claude/oauth-flows", {
    method: "POST",
    headers: { Authorization: `Bearer ${managementAuthToken}` },
  });
  if (!response.ok) {
    throw new Error(`Claude OAuth flow failed with status ${response.status}`);
  }
  return antigravityOAuthFlowSchema.parse(await response.json());
}

// onboardClaudeOAuthFlow completes one pasted callback or code#state value and atomically stores the account.
// onboardClaudeOAuthFlow 完成一个粘贴回调或 code#state 值并原子存储账号。
export async function onboardClaudeOAuthFlow(
  managementAuthToken: string,
  flowID: string,
  input: {
    // provider_definition_id selects the exact Claude Code definition.
    // provider_definition_id 选择精确的 Claude Code Definition。
    provider_definition_id: string;
    // callback_url is the exact callback or code#state value returned by Anthropic.
    // callback_url 是 Anthropic 返回的精确回调或 code#state 值。
    callback_url: string;
  } & Partial<CredentialReauthorizationTarget>,
): Promise<SystemOnboardingResponse> {
  const response = await fetch(
    `/vulcan/manage/claude/oauth-flows/${encodeURIComponent(flowID)}/onboard`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${managementAuthToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(input),
    },
  );
  if (!response.ok) {
    throw new Error(
      `Claude OAuth onboarding failed with status ${response.status}`,
    );
  }
  return systemOnboardingResponseSchema.parse(await response.json());
}

// cancelClaudeOAuthFlow releases one incomplete server-owned Claude authorization session.
// cancelClaudeOAuthFlow 释放一个尚未完成且由服务端拥有的 Claude 授权会话。
export async function cancelClaudeOAuthFlow(
  managementAuthToken: string,
  flowID: string,
): Promise<void> {
  const response = await fetch(
    `/vulcan/manage/claude/oauth-flows/${encodeURIComponent(flowID)}`,
    {
      method: "DELETE",
      headers: { Authorization: `Bearer ${managementAuthToken}` },
    },
  );
  if (!response.ok && response.status !== 404) {
    throw new Error(
      `Claude OAuth cancellation failed with status ${response.status}`,
    );
  }
}

// startAntigravityOAuthFlow starts one server-owned Google consent session.
// startAntigravityOAuthFlow 启动一个服务端拥有的 Google 同意授权会话。
export async function startAntigravityOAuthFlow(
  managementAuthToken: string,
): Promise<AntigravityOAuthFlow> {
  const response = await fetch("/vulcan/manage/antigravity/oauth-flows", {
    method: "POST",
    headers: { Authorization: `Bearer ${managementAuthToken}` },
  });
  if (!response.ok) {
    throw new Error(
      `Antigravity OAuth flow failed with status ${response.status}`,
    );
  }
  return antigravityOAuthFlowSchema.parse(await response.json());
}

// onboardAntigravityOAuthFlow completes one pasted callback and atomically stores the account authorization.
// onboardAntigravityOAuthFlow 完成一个粘贴回调并原子存储账号授权。
export async function onboardAntigravityOAuthFlow(
  managementAuthToken: string,
  flowID: string,
  input: {
    // provider_definition_id selects the exact Antigravity account definition.
    // provider_definition_id 选择精确的 Antigravity 账号 Definition。
    provider_definition_id: string;
    // callback_url is the exact pasted localhost callback returned by Google.
    // callback_url 是 Google 返回且由操作员粘贴的精确 localhost 回调地址。
    callback_url: string;
  } & Partial<CredentialReauthorizationTarget>,
): Promise<SystemOnboardingResponse> {
  const response = await fetch(
    `/vulcan/manage/antigravity/oauth-flows/${encodeURIComponent(flowID)}/onboard`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${managementAuthToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(input),
    },
  );
  if (!response.ok) {
    throw new Error(
      `Antigravity OAuth onboarding failed with status ${response.status}`,
    );
  }
  return systemOnboardingResponseSchema.parse(await response.json());
}

// cancelAntigravityOAuthFlow releases one incomplete server-owned Google consent session.
// cancelAntigravityOAuthFlow 释放一个尚未完成且由服务端拥有的 Google 同意授权会话。
export async function cancelAntigravityOAuthFlow(
  managementAuthToken: string,
  flowID: string,
): Promise<void> {
  const response = await fetch(
    `/vulcan/manage/antigravity/oauth-flows/${encodeURIComponent(flowID)}`,
    {
      method: "DELETE",
      headers: { Authorization: `Bearer ${managementAuthToken}` },
    },
  );
  if (!response.ok && response.status !== 404) {
    throw new Error(
      `Antigravity OAuth cancellation failed with status ${response.status}`,
    );
  }
}

// refreshProviderMetadata requests one provider-native catalog refresh and returns only redacted metadata.
// refreshProviderMetadata 请求一次供应商原生目录刷新并仅返回脱敏元数据。
export async function refreshProviderMetadata(
  managementAuthToken: string,
  providerInstanceID: string,
): Promise<ProviderCatalogMetadata> {
  const response = await fetch(
    `/vulcan/manage/provider-instances/${encodeURIComponent(providerInstanceID)}/catalog/refresh`,
    {
      method: "POST",
      headers: { Authorization: `Bearer ${managementAuthToken}` },
    },
  );
  // payload is parsed once so malformed success and failure envelopes share an explicit invalid-response category.
  // payload 只解析一次，使格式错误的成功与失败信封共用显式无效响应分类。
  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    throw new ProviderMetadataRefreshError(
      "provider_metadata_invalid_response",
      response.status,
    );
  }
  if (!response.ok) {
    const errorPayload = controlErrorResponseSchema.safeParse(payload);
    throw new ProviderMetadataRefreshError(
      errorPayload.success
        ? errorPayload.data.error
        : "provider_metadata_invalid_response",
      response.status,
    );
  }
  const metadata = providerCatalogMetadataSchema.safeParse(payload);
  if (!metadata.success) {
    throw new ProviderMetadataRefreshError(
      "provider_metadata_invalid_response",
      response.status,
    );
  }
  if (metadata.data.provider_instance_id !== providerInstanceID) {
    throw new ProviderMetadataRefreshError(
      "provider_metadata_invalid_response",
      response.status,
    );
  }
  return metadata.data;
}

// refreshProviderCredential requests one explicit provider-token refresh and validates the returned credential identity.
// refreshProviderCredential 请求一次显式供应商 Token 刷新并校验返回的凭据身份。
export async function refreshProviderCredential(
  managementAuthToken: string,
  providerInstanceID: string,
  credentialID: string,
): Promise<string> {
  const response = await fetch(
    `/vulcan/manage/provider-instances/${encodeURIComponent(providerInstanceID)}/credentials/${encodeURIComponent(credentialID)}/refresh`,
    {
      method: "POST",
      headers: { Authorization: `Bearer ${managementAuthToken}` },
    },
  );
  // payload is parsed once so malformed success and failure envelopes share the same explicit invalid-response category.
  // payload 只解析一次，使格式错误的成功与失败信封共用同一个显式无效响应分类。
  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    throw new ProviderCredentialRefreshError(
      "provider_authentication_invalid_response",
      response.status,
    );
  }
  if (!response.ok) {
    const errorPayload = controlErrorResponseSchema.safeParse(payload);
    throw new ProviderCredentialRefreshError(
      errorPayload.success
        ? errorPayload.data.error
        : "provider_authentication_invalid_response",
      response.status,
    );
  }
  const result = z.object({ id: z.string().min(1) }).safeParse(payload);
  if (!result.success || result.data.id !== credentialID) {
    throw new ProviderCredentialRefreshError(
      "provider_authentication_invalid_response",
      response.status,
    );
  }
  return result.data.id;
}
