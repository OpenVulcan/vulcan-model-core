import { z } from "zod"

// ProviderEndpointPreset describes one trusted default address returned by the management API.
// ProviderEndpointPreset 描述管理 API 返回的一个受信任默认地址。
export interface ProviderEndpointPreset {
  // id is stable within one provider definition.
  // id 在一个供应商定义内保持稳定。
  id: string
  // base_url is the trusted upstream base address.
  // base_url 是受信任的上游基础地址。
  base_url: string
  // region is the locale-neutral site label.
  // region 是与区域设置无关的站点标签。
  region: string
  // user_editable reports whether the address may be changed during onboarding.
  // user_editable 表示录入期间是否可以修改地址。
  user_editable: boolean
}

// ProviderDefinition describes one exact selectable site or commercial product.
// ProviderDefinition 描述一个精确可选择的站点或商业产品。
export interface ProviderDefinition {
  // id is the immutable system definition identifier.
  // id 是不可变的系统定义标识。
  id: string
  // display_name is the complete locale-neutral provider name.
  // display_name 是完整且与区域设置无关的供应商名称。
  display_name: string
  // group_id identifies the management-only provider family.
  // group_id 标识仅供管理使用的供应商系列。
  group_id: string
  // variant_name is the concise site or plan label.
  // variant_name 是简洁的站点或套餐标签。
  variant_name: string
  // variant_description explains the exact product boundary.
  // variant_description 说明精确的产品边界。
  variant_description: string
  // variant_description_key identifies authored localization for this variant.
  // variant_description_key 标识此变体的编写本地化文本。
  variant_description_key?: string
  // model_catalog_id identifies shared trusted model metadata.
  // model_catalog_id 标识共享的受信任模型元数据。
  model_catalog_id: string
  // protocol_profile_id identifies the provider's one preferred protocol.
  // protocol_profile_id 标识供应商唯一的优势协议。
  protocol_profile_id: string
  // endpoint_presets lists trusted onboarding addresses.
  // endpoint_presets 列出受信任的录入地址。
  endpoint_presets: ProviderEndpointPreset[]
  // auth_methods lists exact credential acquisition mechanisms.
  // auth_methods 列出精确凭据获取机制。
  auth_methods: ProviderAuthMethod[]
}

// ProviderAuthMethod describes one definition-owned authentication mechanism.
// ProviderAuthMethod 描述一种由定义拥有的认证机制。
export interface ProviderAuthMethod {
  id: string
  type: string
  refreshable: boolean
}

// ProviderGroup describes one management catalog brand and its selectable variants.
// ProviderGroup 描述一个管理目录品牌及其可选择变体。
export interface ProviderGroup {
  // id is the immutable management group identifier.
  // id 是不可变的管理分组标识。
  id: string
  // display_name is the locale-neutral brand name.
  // display_name 是与区域设置无关的品牌名称。
  display_name: string
  // description explains the shared provider family.
  // description 说明共享的供应商系列。
  description: string
  // description_key identifies authored localization for this provider group.
  // description_key 标识此供应商分组的编写本地化文本。
  description_key?: string
  // provider_definitions contains exact selectable variants.
  // provider_definitions 包含精确可选择的变体。
  provider_definitions: ProviderDefinition[]
}

// SystemOnboardingInput contains operator-authored fields for atomic API-key onboarding.
// SystemOnboardingInput 包含原子 API Key 录入的操作员填写字段。
export interface SystemOnboardingInput {
  provider_definition_id: string
  handle: string
  display_name: string
  auth_method_id: string
  credential_label: string
  principal_key: string
  secret: string
}

// SystemOnboardingResponse contains only identifiers created by the server-owned transaction.
// SystemOnboardingResponse 仅包含服务端拥有事务创建的标识。
export interface SystemOnboardingResponse {
  provider_instance_id: string
  credential_id: string
  endpoint_ids: string[]
  binding_ids: string[]
}

// KimiDeviceFlow contains management-safe verification data without provider secret codes.
// KimiDeviceFlow 包含不带供应商秘密码的管理安全验证数据。
export interface KimiDeviceFlow {
  id: string
  user_code: string
  verification_uri: string
  verification_uri_complete: string
  expires_at: string
  poll_interval_seconds: number
}

// ProviderInstance describes one configured provider without exposing secret material.
// ProviderInstance 描述一个已配置供应商且不暴露秘密材料。
export interface ProviderInstance {
  // id is the immutable provider instance identifier.
  // id 是不可变供应商实例标识。
  id: string
  // definition_id identifies the exact provider variant.
  // definition_id 标识精确供应商变体。
  definition_id: string
  // handle is the stable routing alias.
  // handle 是稳定路由别名。
  handle: string
  // display_name is the management-facing instance name.
  // display_name 是管理界面实例名称。
  display_name: string
  // status is the current configuration lifecycle state.
  // status 是当前配置生命周期状态。
  status: string
  // disabled_model_ids lists models disabled by local policy.
  // disabled_model_ids 列出被本地策略禁用的模型。
  disabled_model_ids: string[]
  // endpoint_count is the number of configured endpoints.
  // endpoint_count 是已配置端点数量。
  endpoint_count: number
  // credential_count is the number of configured credentials.
  // credential_count 是已配置凭据数量。
  credential_count: number
  // binding_count is the number of configured access bindings.
  // binding_count 是已配置访问绑定数量。
  binding_count: number
  // revision is the persisted instance revision.
  // revision 是持久化实例修订号。
  revision: number
}

// ProviderCredential describes one management-safe authorization entry.
// ProviderCredential 描述一个管理安全的授权条目。
export interface ProviderCredential {
  // id is the immutable credential identifier.
  // id 是不可变凭据标识。
  id: string
  // provider_instance_id identifies the exact owner.
  // provider_instance_id 标识精确所有者。
  provider_instance_id: string
  // auth_method_id identifies the definition-owned authentication method.
  // auth_method_id 标识定义拥有的认证方式。
  auth_method_id: string
  // label is the operator-authored API or account name.
  // label 是操作员填写的 API 或账号名称。
  label: string
  // status is the local credential eligibility state.
  // status 是本地凭据资格状态。
  status: string
  // expires_at is the provider-reported expiration when known.
  // expires_at 是已知时供应商报告的到期时间。
  expires_at: string | null
  // cooling_until is the local recovery time when cooling applies.
  // cooling_until 是适用冷却时的本地恢复时间。
  cooling_until: string | null
  // revision is the persisted credential revision.
  // revision 是持久化凭据修订号。
  revision: number
}

// AuthorizedProvider joins one configured instance with its non-secret authorization list.
// AuthorizedProvider 将一个已配置实例与其非秘密授权列表连接起来。
export interface AuthorizedProvider {
  // instance contains the provider identity and lifecycle state.
  // instance 包含供应商身份与生命周期状态。
  instance: ProviderInstance
  // credentials contains every configured API key or device authorization.
  // credentials 包含每个已配置 API 密钥或设备授权。
  credentials: ProviderCredential[]
}

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
          endpoint_presets: z.array(
            z.object({
              id: z.string().min(1),
              base_url: z.string().url(),
              region: z.string().min(1),
              user_editable: z.boolean(),
            }),
          ),
          auth_methods: z.array(
            z.object({
              id: z.string().min(1),
              type: z.string().min(1),
              refreshable: z.boolean(),
            }),
          ),
        }),
      ),
    }),
  ),
})

// systemOnboardingResponseSchema validates identifiers returned after an atomic server commit.
// systemOnboardingResponseSchema 校验服务端原子提交后返回的标识。
const systemOnboardingResponseSchema = z.object({
  provider_instance_id: z.string().min(1),
  credential_id: z.string().min(1),
  endpoint_ids: z.array(z.string().min(1)),
  binding_ids: z.array(z.string().min(1)),
})

// kimiDeviceFlowSchema validates the token-free device verification envelope.
// kimiDeviceFlowSchema 校验不含令牌的设备验证信封。
const kimiDeviceFlowSchema = z.object({
  id: z.string().min(1),
  user_code: z.string().min(1),
  verification_uri: z.string().url(),
  verification_uri_complete: z.union([z.literal(""), z.string().url()]),
  expires_at: z.string().datetime({ offset: true }),
  poll_interval_seconds: z.number().int().positive(),
})

// providerInstanceSchema validates one management-safe configured provider.
// providerInstanceSchema 校验一个管理安全的已配置供应商。
const providerInstanceSchema = z.object({
  id: z.string().min(1),
  definition_id: z.string().min(1),
  handle: z.string().min(1),
  display_name: z.string().min(1),
  status: z.string().min(1),
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
})

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
  revision: z.number().int().positive(),
})

// providerInstanceListResponseSchema validates the complete configured-provider envelope.
// providerInstanceListResponseSchema 校验完整的已配置供应商响应信封。
const providerInstanceListResponseSchema = z.object({
  provider_instances: z.array(providerInstanceSchema),
})

// providerCredentialListResponseSchema validates one instance authorization envelope.
// providerCredentialListResponseSchema 校验一个实例授权响应信封。
const providerCredentialListResponseSchema = z.object({
  credentials: z.array(providerCredentialSchema),
})

// fetchProviderGroups loads grouped system providers using the active in-memory management credential.
// fetchProviderGroups 使用当前内存管理凭证加载已分组系统供应商。
export async function fetchProviderGroups(managementAuthToken: string, signal?: AbortSignal): Promise<ProviderGroup[]> {
  const response = await fetch("/vulcan/manage/provider-groups", {
    method: "GET",
    headers: { Authorization: `Bearer ${managementAuthToken}` },
    signal,
  })
  if (!response.ok) {
    throw new Error(`provider groups request failed with status ${response.status}`)
  }
  const payload = providerGroupListResponseSchema.parse(await response.json())
  return payload.provider_groups
}

// fetchAuthorizedProviders loads configured instances and their redacted credentials, excluding incomplete instances without authorization.
// fetchAuthorizedProviders 加载已配置实例及其脱敏凭据，并排除没有授权的不完整实例。
export async function fetchAuthorizedProviders(
  managementAuthToken: string,
  signal?: AbortSignal,
): Promise<AuthorizedProvider[]> {
  const headers = { Authorization: `Bearer ${managementAuthToken}` }
  const response = await fetch("/vulcan/manage/provider-instances", {
    method: "GET",
    headers,
    signal,
  })
  if (!response.ok) {
    throw new Error(`provider instances request failed with status ${response.status}`)
  }
  const payload = providerInstanceListResponseSchema.parse(await response.json())
  const providers = await Promise.all(
    payload.provider_instances.map(async (instance) => {
      const credentialResponse = await fetch(
        `/vulcan/manage/provider-instances/${encodeURIComponent(instance.id)}/credentials`,
        { method: "GET", headers, signal },
      )
      if (!credentialResponse.ok) {
        throw new Error(`provider credentials request failed with status ${credentialResponse.status}`)
      }
      const credentialPayload = providerCredentialListResponseSchema.parse(await credentialResponse.json())
      if (credentialPayload.credentials.some((credential) => credential.provider_instance_id !== instance.id)) {
        throw new Error("provider credential response contains a mismatched owner")
      }
      return { instance, credentials: credentialPayload.credentials }
    }),
  )
  return providers.filter((provider) => provider.credentials.length > 0)
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
  })
  if (!response.ok) {
    throw new Error(`provider onboarding failed with status ${response.status}`)
  }
  return systemOnboardingResponseSchema.parse(await response.json())
}

// startKimiDeviceFlow starts one token-confidential Coding Plan authorization session.
// startKimiDeviceFlow 启动一个令牌保密的 Coding Plan 授权会话。
export async function startKimiDeviceFlow(managementAuthToken: string): Promise<KimiDeviceFlow> {
  const response = await fetch("/vulcan/manage/kimi/device-flows", {
    method: "POST",
    headers: { Authorization: `Bearer ${managementAuthToken}` },
  })
  if (!response.ok) {
    throw new Error(`Kimi device flow failed with status ${response.status}`)
  }
  return kimiDeviceFlowSchema.parse(await response.json())
}

// onboardKimiDeviceFlow polls once and atomically stores a completed Coding Plan authorization.
// onboardKimiDeviceFlow 轮询一次并原子存储已完成的 Coding Plan 授权。
export async function onboardKimiDeviceFlow(
  managementAuthToken: string,
  flowID: string,
  input: Omit<SystemOnboardingInput, "auth_method_id" | "secret">,
): Promise<SystemOnboardingResponse | null> {
  const response = await fetch(`/vulcan/manage/kimi/device-flows/${encodeURIComponent(flowID)}/onboard`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${managementAuthToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(input),
  })
  if (response.status === 202) {
    return null
  }
  if (!response.ok) {
    throw new Error(`Kimi device onboarding failed with status ${response.status}`)
  }
  return systemOnboardingResponseSchema.parse(await response.json())
}

// cancelKimiDeviceFlow releases one incomplete server-owned authorization session.
// cancelKimiDeviceFlow 释放一个尚未完成且由服务端拥有的授权会话。
export async function cancelKimiDeviceFlow(managementAuthToken: string, flowID: string): Promise<void> {
  const response = await fetch(`/vulcan/manage/kimi/device-flows/${encodeURIComponent(flowID)}`, {
    method: "DELETE",
    headers: { Authorization: `Bearer ${managementAuthToken}` },
  })
  if (!response.ok) {
    throw new Error(`Kimi device flow cancellation failed with status ${response.status}`)
  }
}
