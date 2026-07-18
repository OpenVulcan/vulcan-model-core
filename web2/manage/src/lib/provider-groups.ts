import { z } from "zod"

// ProviderEndpointPreset describes one trusted default address returned by the management API.
// ProviderEndpointPreset 描述管理 API 返回的一个受信任默认地址。
export interface ProviderEndpointPreset {
  // id is stable within one provider definition.
  // id 在一个供应商定义内保持稳定。
  id: string
  // channel_id identifies the exact protocol channel served by this address.
  // channel_id 标识此地址服务的精确协议通道。
  channel_id: string
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

// ProviderChannel describes one executable protocol option owned by a definition.
// ProviderChannel 描述一个供应商定义拥有的可执行协议选项。
export interface ProviderChannel {
  // id is stable within the provider definition.
  // id 在供应商定义内保持稳定。
  id: string
  // protocol_profile_id identifies the exact internal protocol contract.
  // protocol_profile_id 标识精确的内部协议合同。
  protocol_profile_id: string
  // runtime_ready reports whether the local adapter is implemented.
  // runtime_ready 表示本地适配器是否已实现。
  runtime_ready: boolean
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
  // channels lists explicit protocol choices without fallback semantics.
  // channels 列出不带降级语义的显式协议选项。
  channels: ProviderChannel[]
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

// providerGroupListResponseSchema validates the complete untrusted management response before UI state owns it.
// providerGroupListResponseSchema 在 UI 状态接管前校验完整的不受信任管理响应。
const providerGroupListResponseSchema = z.object({
  provider_groups: z.array(z.object({
    id: z.string().min(1),
    display_name: z.string().min(1),
    description: z.string(),
    description_key: z.string().optional(),
    provider_definitions: z.array(z.object({
      id: z.string().min(1),
      display_name: z.string().min(1),
      group_id: z.string().min(1),
      variant_name: z.string().min(1),
      variant_description: z.string(),
      variant_description_key: z.string().optional(),
      model_catalog_id: z.string().min(1),
      channels: z.array(z.object({ id: z.string().min(1), protocol_profile_id: z.string().min(1), runtime_ready: z.boolean() })),
      endpoint_presets: z.array(z.object({ id: z.string().min(1), channel_id: z.string().min(1), base_url: z.string().url(), region: z.string().min(1), user_editable: z.boolean() })),
      auth_methods: z.array(z.object({ id: z.string().min(1), type: z.string().min(1), refreshable: z.boolean() })),
    })),
  })),
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

// fetchProviderGroups loads grouped system providers using the active in-memory management credential.
// fetchProviderGroups 使用当前内存管理凭证加载已分组系统供应商。
export async function fetchProviderGroups(
  managementAuthToken: string,
  signal?: AbortSignal
): Promise<ProviderGroup[]> {
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

// onboardSystemProvider submits one API-key variant to the server-owned atomic onboarding command.
// onboardSystemProvider 将一个 API Key 变体提交到服务端拥有的原子录入命令。
export async function onboardSystemProvider(managementAuthToken: string, input: SystemOnboardingInput): Promise<SystemOnboardingResponse> {
  const response = await fetch("/vulcan/manage/provider-instances/onboard", {
    method: "POST",
    headers: { Authorization: `Bearer ${managementAuthToken}`, "Content-Type": "application/json" },
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
  const response = await fetch("/vulcan/manage/kimi/device-flows", { method: "POST", headers: { Authorization: `Bearer ${managementAuthToken}` } })
  if (!response.ok) {
    throw new Error(`Kimi device flow failed with status ${response.status}`)
  }
  return kimiDeviceFlowSchema.parse(await response.json())
}

// onboardKimiDeviceFlow polls once and atomically stores a completed Coding Plan authorization.
// onboardKimiDeviceFlow 轮询一次并原子存储已完成的 Coding Plan 授权。
export async function onboardKimiDeviceFlow(managementAuthToken: string, flowID: string, input: Omit<SystemOnboardingInput, "auth_method_id" | "secret">): Promise<SystemOnboardingResponse | null> {
  const response = await fetch(`/vulcan/manage/kimi/device-flows/${encodeURIComponent(flowID)}/onboard`, {
    method: "POST",
    headers: { Authorization: `Bearer ${managementAuthToken}`, "Content-Type": "application/json" },
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
