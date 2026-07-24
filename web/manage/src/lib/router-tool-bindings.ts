import { z } from "zod"

// standardToolKindSchema validates the complete closed Router standard-tool set.
// standardToolKindSchema 校验完整封闭的 Router 标准工具集合。
export const standardToolKindSchema = z.enum(["web_search", "web_extractor"])

// routerExtensionKindSchema validates the complete closed operation-backed enhancement set.
// routerExtensionKindSchema 校验完整封闭且由操作支持的增强能力集合。
export const routerExtensionKindSchema = z.enum([
  "image_understanding",
  "audio_understanding",
  "video_understanding",
  "image_generation",
  "video_generation",
  "speech_generation",
  "speech_transcription",
])

// routerToolBindingSchema validates one complete management-safe Router binding.
// routerToolBindingSchema 校验一个完整且管理安全的 Router 绑定。
const routerToolBindingSchema = z.object({
  id: z.string().min(1),
  kind: standardToolKindSchema.optional(),
  extension: routerExtensionKindSchema.optional(),
  provider_instance_id: z.string().min(1),
  provider_service_id: z.string().min(1).optional(),
  service_offering_id: z.string().min(1).optional(),
  provider_model_id: z.string().min(1).optional(),
  offering_id: z.string().min(1).optional(),
  execution_profile_id: z.string().min(1),
  priority: z.number().int().nonnegative(),
  enabled: z.boolean(),
  allowed_provider_instance_ids: z.array(z.string().min(1)).nullish().transform((values) => values ?? []),
  allowed_provider_model_ids: z.array(z.string().min(1)).nullish().transform((values) => values ?? []),
  allowed_execution_profile_ids: z.array(z.string().min(1)).nullish().transform((values) => values ?? []),
  timeout_milliseconds: z.number().int().positive(),
  maximum_calls: z.number().int().positive(),
  maximum_results: z.number().int().nonnegative(),
  maximum_urls: z.number().int().nonnegative(),
  maximum_result_bytes: z.number().int().positive(),
  safety_policy: z.literal("public_https_only"),
  revision: z.number().int().positive(),
  created_at: z.string().datetime({ offset: true }),
  updated_at: z.string().datetime({ offset: true }),
}).superRefine((binding, context) => {
  const standard = binding.kind !== undefined
  const extension = binding.extension !== undefined
  const serviceTarget = binding.provider_service_id !== undefined && binding.service_offering_id !== undefined
  const modelTarget = binding.provider_model_id !== undefined && binding.offering_id !== undefined
  if (standard === extension || serviceTarget === modelTarget || standard !== serviceTarget || extension !== modelTarget) {
    context.addIssue({ code: z.ZodIssueCode.custom, message: "binding tool and target families must match" })
  }
})

// routerToolBindingListSchema validates the complete binding collection response.
// routerToolBindingListSchema 校验完整绑定集合响应。
const routerToolBindingListSchema = z.object({
  router_tool_bindings: z.array(routerToolBindingSchema),
})

// routerToolBindingProbeSchema validates one exact management binding readiness test.
// routerToolBindingProbeSchema 校验一个精确管理绑定就绪测试。
const routerToolBindingProbeSchema = z.object({
  binding_id: z.string().min(1),
  revision: z.number().int().positive(),
  tool_id: z.string().min(1),
  operation: z.string().min(1),
  ready: z.boolean(),
  unavailable_reason: z.enum([
    "router_binding_disabled",
    "router_binding_unavailable",
  ]).optional(),
}).superRefine((probe, context) => {
  if (probe.ready === (probe.unavailable_reason !== undefined)) {
    context.addIssue({ code: z.ZodIssueCode.custom, message: "binding test readiness and reason are inconsistent" })
  }
})

// modelToolAvailabilitySchema validates management-safe effective tool readiness.
// modelToolAvailabilitySchema 校验管理安全的有效工具就绪状态。
const modelToolAvailabilitySchema = z.object({
  models: z.array(z.object({
    provider_instance_id: z.string().min(1),
    provider_handle: z.string().min(1),
    provider_definition_id: z.string().min(1),
    model: z.object({
      id: z.string().min(1),
      display_name: z.string().min(1),
      upstream_model_id: z.string().min(1),
    }).passthrough(),
    model_tools: z.array(z.object({
      offering_id: z.string().min(1),
      execution_profile_id: z.string().min(1),
      standard: z.array(z.object({
        kind: standardToolKindSchema,
        native_supported: z.boolean(),
        native_ready: z.boolean(),
        router_tool_supported: z.boolean(),
        router_tool_ready: z.boolean(),
        available_modes: z.array(z.enum(["disabled", "native", "router_tool"])),
        requires: z.array(standardToolKindSchema).nullish().transform((values) => values ?? []),
        native_unavailable_reason: z.literal("parent_target_unavailable").optional(),
        router_tool_unavailable_reason: z.enum([
          "parent_target_unavailable",
          "router_binding_missing",
          "router_binding_disabled",
          "router_binding_unavailable",
        ]).optional(),
      })),
      extra: z.array(z.object({
        capability: z.object({
          id: z.string().min(1),
          display_name: z.string().min(1),
          description: z.string().min(1),
        }).passthrough(),
        ready: z.boolean(),
        unavailable_reason: z.string().optional(),
      })),
      router_extensions: z.array(z.object({
        id: routerExtensionKindSchema,
        display_name: z.string().min(1),
        supported: z.boolean(),
        ready: z.boolean(),
        unavailable_reason: z.string().optional(),
      })),
    })),
  })),
})

// RouterToolBinding is one validated Router standard-tool or extension backend selection.
// RouterToolBinding 是一个经过校验的 Router 标准工具或增强能力后端选择。
export type RouterToolBinding = z.infer<typeof routerToolBindingSchema>

// RouterToolBindingProbe is one validated exact-backend readiness test.
// RouterToolBindingProbe 是一个经过校验的精确后端就绪测试。
export type RouterToolBindingProbe = z.infer<typeof routerToolBindingProbeSchema>

// ModelToolAvailability is the validated effective model-tool discovery response.
// ModelToolAvailability 是经过校验的有效模型工具发现响应。
export type ModelToolAvailability = z.infer<typeof modelToolAvailabilitySchema>

// RouterToolBindingInput contains every operator-authored binding field.
// RouterToolBindingInput 包含操作员编写的全部绑定字段。
export interface RouterToolBindingInput {
  // kind selects one standard tool semantic when this is a service binding.
  // kind 在当前为服务绑定时选择一种标准工具语义。
  kind?: z.infer<typeof standardToolKindSchema>
  // extension selects one operation-backed enhancement when this is a model binding.
  // extension 在当前为模型绑定时选择一种由操作支持的增强能力。
  extension?: z.infer<typeof routerExtensionKindSchema>
  // providerInstanceID fixes the backend provider instance.
  // providerInstanceID 固定后端供应商实例。
  providerInstanceID: string
  // providerServiceID fixes the backend logical service.
  // providerServiceID 固定后端逻辑服务。
  providerServiceID?: string
  // serviceOfferingID fixes the backend service offering.
  // serviceOfferingID 固定后端服务产品。
  serviceOfferingID?: string
  // providerModelID fixes the backend logical model for one Router enhancement.
  // providerModelID 为一个 Router 增强能力固定后端逻辑模型。
  providerModelID?: string
  // offeringID fixes the backend model offering for one Router enhancement.
  // offeringID 为一个 Router 增强能力固定后端模型产品。
  offeringID?: string
  // executionProfileID fixes the backend execution profile.
  // executionProfileID 固定后端执行规格。
  executionProfileID: string
  // priority orders matching bindings in ascending order.
  // priority 按升序排列匹配绑定。
  priority: number
  // enabled controls immediate selection eligibility.
  // enabled 控制立即选择资格。
  enabled: boolean
  // timeoutMilliseconds is the hard child-execution ceiling.
  // timeoutMilliseconds 是子执行硬超时上限。
  timeoutMilliseconds: number
  // maximumCalls limits calls per parent execution.
  // maximumCalls 限制每个父执行的调用次数。
  maximumCalls: number
  // maximumResults limits normalized search results.
  // maximumResults 限制规范化搜索结果数。
  maximumResults: number
  // maximumURLs limits extraction URLs.
  // maximumURLs 限制抓取 URL 数。
  maximumURLs: number
  // maximumResultBytes limits the result returned to the parent model.
  // maximumResultBytes 限制回填父模型的结果大小。
  maximumResultBytes: number
  // allowedProviderInstanceIDs optionally scopes parent provider instances.
  // allowedProviderInstanceIDs 可选限制父供应商实例。
  allowedProviderInstanceIDs?: string[]
  // allowedProviderModelIDs optionally scopes parent models.
  // allowedProviderModelIDs 可选限制父模型。
  allowedProviderModelIDs?: string[]
  // allowedExecutionProfileIDs optionally scopes parent profiles.
  // allowedExecutionProfileIDs 可选限制父执行规格。
  allowedExecutionProfileIDs?: string[]
}

// managementHeaders returns the exact protected management request headers.
// managementHeaders 返回精确的受保护管理请求头。
function managementHeaders(managementAuthToken: string): HeadersInit {
  return {
    Authorization: `Bearer ${managementAuthToken}`,
    "Content-Type": "application/json",
  }
}

// bindingPayload converts the UI input into the exact management contract.
// bindingPayload 将界面输入转换为精确管理合同。
function bindingPayload(input: RouterToolBindingInput, revision?: number): Record<string, unknown> {
  return {
    kind: input.kind,
    extension: input.extension,
    provider_instance_id: input.providerInstanceID,
    provider_service_id: input.providerServiceID,
    service_offering_id: input.serviceOfferingID,
    provider_model_id: input.providerModelID,
    offering_id: input.offeringID,
    execution_profile_id: input.executionProfileID,
    priority: input.priority,
    enabled: input.enabled,
    allowed_provider_instance_ids: input.allowedProviderInstanceIDs ?? [],
    allowed_provider_model_ids: input.allowedProviderModelIDs ?? [],
    allowed_execution_profile_ids: input.allowedExecutionProfileIDs ?? [],
    timeout_milliseconds: input.timeoutMilliseconds,
    maximum_calls: input.maximumCalls,
    maximum_results: input.maximumResults,
    maximum_urls: input.maximumURLs,
    maximum_result_bytes: input.maximumResultBytes,
    safety_policy: "public_https_only",
    revision,
  }
}

// responseFailure reads a stable server error without treating arbitrary response data as trusted text.
// responseFailure 读取稳定服务端错误且不把任意响应数据当作可信文本。
async function responseFailure(response: Response, fallback: string): Promise<Error> {
  const parsed = z.object({ error: z.string().min(1) }).safeParse(await response.json().catch(() => null))
  return new Error(parsed.success ? parsed.data.error : `${fallback}: ${response.status}`)
}

// fetchRouterToolBindings loads every explicit Router tool binding.
// fetchRouterToolBindings 加载全部显式 Router 工具绑定。
export async function fetchRouterToolBindings(managementAuthToken: string, signal?: AbortSignal): Promise<RouterToolBinding[]> {
  const response = await fetch("/vulcan/manage/router-tool-bindings", {
    method: "GET",
    headers: managementHeaders(managementAuthToken),
    signal,
  })
  if (!response.ok) throw await responseFailure(response, "router tool bindings request failed")
  return routerToolBindingListSchema.parse(await response.json()).router_tool_bindings
}

// fetchModelToolAvailability loads effective native, extra, and Router readiness.
// fetchModelToolAvailability 加载有效原生、额外及 Router 就绪状态。
export async function fetchModelToolAvailability(managementAuthToken: string, signal?: AbortSignal): Promise<ModelToolAvailability> {
  const response = await fetch("/vulcan/manage/model-tool-availability", {
    method: "GET",
    headers: managementHeaders(managementAuthToken),
    signal,
  })
  if (!response.ok) throw await responseFailure(response, "model tool availability request failed")
  return modelToolAvailabilitySchema.parse(await response.json())
}

// probeRouterToolBinding tests current exact-target resolution without exposing credentials.
// probeRouterToolBinding 测试当前精确 Target 解析且不暴露凭据。
export async function probeRouterToolBinding(managementAuthToken: string, bindingID: string): Promise<RouterToolBindingProbe> {
  const response = await fetch(`/vulcan/manage/router-tool-bindings/${encodeURIComponent(bindingID)}/test`, {
    method: "POST",
    headers: managementHeaders(managementAuthToken),
  })
  if (!response.ok) throw await responseFailure(response, "router tool binding test failed")
  return routerToolBindingProbeSchema.parse(await response.json())
}

// createRouterToolBinding creates one validated Router binding.
// createRouterToolBinding 创建一个经过校验的 Router 绑定。
export async function createRouterToolBinding(managementAuthToken: string, input: RouterToolBindingInput): Promise<RouterToolBinding> {
  const response = await fetch("/vulcan/manage/router-tool-bindings", {
    method: "POST",
    headers: managementHeaders(managementAuthToken),
    body: JSON.stringify(bindingPayload(input)),
  })
  if (!response.ok) throw await responseFailure(response, "router tool binding creation failed")
  return routerToolBindingSchema.parse(await response.json())
}

// updateRouterToolBinding replaces one exact binding with optimistic concurrency.
// updateRouterToolBinding 使用乐观并发替换一个精确绑定。
export async function updateRouterToolBinding(managementAuthToken: string, bindingID: string, revision: number, input: RouterToolBindingInput): Promise<RouterToolBinding> {
  const response = await fetch(`/vulcan/manage/router-tool-bindings/${encodeURIComponent(bindingID)}`, {
    method: "PUT",
    headers: managementHeaders(managementAuthToken),
    body: JSON.stringify(bindingPayload(input, revision)),
  })
  if (!response.ok) throw await responseFailure(response, "router tool binding update failed")
  return routerToolBindingSchema.parse(await response.json())
}

// deleteRouterToolBinding removes one exact Router binding.
// deleteRouterToolBinding 删除一个精确 Router 绑定。
export async function deleteRouterToolBinding(managementAuthToken: string, bindingID: string): Promise<void> {
  const response = await fetch(`/vulcan/manage/router-tool-bindings/${encodeURIComponent(bindingID)}`, {
    method: "DELETE",
    headers: managementHeaders(managementAuthToken),
  })
  if (!response.ok) throw await responseFailure(response, "router tool binding deletion failed")
}
