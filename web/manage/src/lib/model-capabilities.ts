import { z } from "zod"

import { fetchAuthorizedProviders, type AuthorizedProvider } from "@/lib/provider-groups"

// capabilityLevelSchema validates the complete support vocabulary returned by the Router.
// capabilityLevelSchema 校验 Router 返回的完整支持级别词汇。
export const capabilityLevelSchema = z.enum(["native", "emulated", "conditional", "unsupported", "unknown"])

// optionalLimitSchema accepts both HTTP token-limit omission and catalog zero-value encoding, then normalizes unknown limits.
// optionalLimitSchema 同时接受 HTTP Token 限制省略与目录零值编码，再规范化未知限制。
const optionalLimitSchema = z
  .object({
    known: z.boolean(),
    value: z.number().int().nonnegative().optional(),
  })
  .superRefine((limit, context) => {
    if (
      (limit.known && limit.value === undefined) ||
      (!limit.known && limit.value !== undefined && limit.value !== 0)
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: "optional limit known flag and value are inconsistent",
      })
    }
  })
  .transform((limit) =>
    limit.known
      ? { known: true as const, value: limit.value as number }
      : { known: false as const },
  )

// stringArraySchema normalizes Go nil slices and omitted optional lists to one explicit empty list.
// stringArraySchema 将 Go nil Slice 与省略的可选列表规范化为显式空列表。
const stringArraySchema = z
  .array(z.string())
  .nullish()
  .transform((values) => values ?? [])

// optionalBoolSchema preserves an explicit unknown boolean without treating its Go zero value as evidence.
// optionalBoolSchema 保留显式未知布尔值，且不把 Go 零值当作能力证据。
const optionalBoolSchema = z
  .object({ known: z.boolean(), value: z.boolean() })
  .transform((value) =>
    value.known
      ? { known: true as const, value: value.value }
      : { known: false as const },
  )

// deliverySchema validates every execution delivery mode displayed by management diagnostics.
// deliverySchema 校验管理诊断显示的每种执行交付方式。
const deliverySchema = z.object({
  synchronous: z.boolean(),
  streaming: z.boolean(),
  asynchronous: z.boolean(),
  polling: z.boolean(),
  cancellation: z.boolean(),
  partial_results: z.boolean(),
}).passthrough()

// evidenceSchema validates one auditable provider capability source.
// evidenceSchema 校验一个可审计的供应商能力来源。
const evidenceSchema = z.object({ source: z.string().min(1), reference: z.string().min(1), observed_at: z.string().min(1), expires_at: z.string().optional(), revision: z.number().int().positive() })

// mediaCapabilitySchema validates the shared diagnostic fields of media input and output contracts.
// mediaCapabilitySchema 校验媒体输入与输出合同的共享诊断字段。
const mediaCapabilitySchema = z.object({
  kind: z.enum(["image", "audio", "video", "file"]),
  level: capabilityLevelSchema,
  roles: stringArraySchema,
  interaction_modes: stringArraySchema,
  media_only_policy: z.string().optional(),
  client_workflows: stringArraySchema,
  materialization_modes: stringArraySchema,
  formats: stringArraySchema,
  max_outputs: optionalLimitSchema.optional(),
  common: z.object({ mime_types: stringArraySchema, max_item_bytes: optionalLimitSchema.optional(), max_total_bytes: optionalLimitSchema.optional(), max_items: optionalLimitSchema.optional(), allows_remote_url: optionalBoolSchema.optional() }).passthrough().optional(),
  delivery: deliverySchema.optional(),
  evidence: z.array(evidenceSchema),
  evidence_revision: z.number().int().positive(),
}).passthrough()

// mediaCapabilityArraySchema normalizes an omitted extended capability family to an explicit empty list.
// mediaCapabilityArraySchema 将省略的扩展能力类别规范化为显式空列表。
const mediaCapabilityArraySchema = z
  .array(mediaCapabilitySchema)
  .nullish()
  .transform((values) => values ?? [])

// parameterSchema validates one closed operation parameter descriptor.
// parameterSchema 校验一个封闭操作参数描述符。
const parameterSchema = z.object({ id: z.string().min(1), kind: z.string().min(1), required: z.boolean(), allowed_values: z.array(z.string()).optional(), integer_range: z.object({ minimum: z.number().optional(), maximum: z.number().optional(), multiple_of: z.number().optional() }).optional(), float_range: z.object({ minimum: z.number().optional(), maximum: z.number().optional() }).optional(), string_range: z.object({ minimum_length: z.number().optional(), maximum_length: z.number().optional() }).optional() }).passthrough()

// poolSchema validates aggregate readiness and exact non-secret reasons for an unavailable profile.
// poolSchema 校验聚合就绪状态及规格不可用的精确非秘密原因。
const poolSchema = z.object({ configured_credentials: z.number().int().nonnegative(), entitled_credentials: z.number().int().nonnegative(), ready_credentials: z.number().int().nonnegative(), cooling_credentials: z.number().int().nonnegative(), exhausted_credentials: z.number().int().nonnegative(), invalid_credentials: z.number().int().nonnegative(), blocking_allowance_kinds: stringArraySchema, earliest_reset_at: z.string().optional() })

// embeddingSchema mirrors the current closed VCP embedding capability contract.
// embeddingSchema 镜像当前封闭的 VCP Embedding 能力合同。
const embeddingSchema = z.object({
  input_tasks: z.array(z.enum(["provider_default", "query", "document", "semantic_similarity", "classification", "clustering", "code_retrieval"])),
  output_kinds: z.array(z.enum(["dense", "sparse", "multi_vector"])),
  encodings: z.array(z.enum(["float", "base64"])),
  dimensions: z.array(z.number().int().positive()).nullish().transform((values) => values ?? []),
  default_dimensions: optionalLimitSchema,
  min_dimensions: optionalLimitSchema,
  max_dimensions: optionalLimitSchema,
  max_batch_items: optionalLimitSchema,
  resource_kinds: z.array(z.enum(["image", "audio", "video", "file"])).nullish().transform((values) => values ?? []),
  normalized: optionalBoolSchema,
}).passthrough()

// rerankSchema mirrors the current closed VCP rerank capability contract.
// rerankSchema 镜像当前封闭的 VCP Rerank 能力合同。
const rerankSchema = z.object({
  max_candidates: optionalLimitSchema,
  truncation_policies: stringArraySchema,
  query_resource_kinds: z.array(z.enum(["image", "audio", "video", "file"])).nullish().transform((values) => values ?? []),
  candidate_resource_kinds: z.array(z.enum(["image", "audio", "video", "file"])).nullish().transform((values) => values ?? []),
  return_content: z.boolean(),
  score_semantics: z.string().min(1),
}).passthrough()

// modelCapabilitiesSchema validates every capability family rendered by the model page.
// modelCapabilitiesSchema 校验模型页面渲染的每个能力类别。
export const modelCapabilitiesSchema = z.object({
  context_window: optionalLimitSchema,
  max_input_tokens: optionalLimitSchema,
  max_output_tokens: optionalLimitSchema,
  max_reasoning_tokens: optionalLimitSchema,
  recommended_output_tokens: optionalLimitSchema,
  recommended_reasoning_tokens: optionalLimitSchema,
  tool_calling: capabilityLevelSchema,
  parallel_tool_calls: capabilityLevelSchema,
  streaming_tool_arguments: capabilityLevelSchema,
  strict_json_schema: capabilityLevelSchema,
  reasoning: capabilityLevelSchema,
  input_modalities: stringArraySchema,
  output_modalities: stringArraySchema,
  delivery: deliverySchema,
  embedding: embeddingSchema.optional(),
  rerank: rerankSchema.optional(),
  media_inputs: mediaCapabilityArraySchema,
  media_outputs: mediaCapabilityArraySchema,
  parameters: z.array(parameterSchema).nullish().transform((values) => values ?? []),
  parameter_rules: z.array(z.object({ kind: z.string(), parameter_id: z.string(), related_parameter_ids: stringArraySchema, enum_value: z.string().optional() })).nullish().transform((values) => values ?? []),
  usage_metrics: z.array(z.object({ unit: z.string(), accuracy: z.enum(["exact", "estimated", "unknown"]) })).nullish().transform((values) => values ?? []),
}).passthrough()

// modelCatalogSchema validates one complete provider-scoped management catalog.
// modelCatalogSchema 校验一个完整的供应商作用域管理目录。
export const modelCatalogSchema = z.object({
  provider_instance_id: z.string().min(1),
  models: z.array(z.object({ id: z.string().min(1), upstream_model_id: z.string().min(1), display_name: z.string().min(1), entitlement_mode: z.string(), enabled: z.boolean(), authorization_status: z.enum(["authorized", "denied", "unknown"]), offerings: z.array(z.object({ id: z.string().min(1), upstream_model_id: z.string().min(1), profiles: z.array(z.object({ id: z.string().min(1), display_name: z.string().min(1), default: z.boolean(), operation: z.string().min(1).optional().default(""), action_binding_id: z.string().min(1).optional().default(""), capabilities: modelCapabilitiesSchema, pool: poolSchema.nullable().optional() }).passthrough()) }).passthrough()) }).passthrough()),
  services: z.array(z.object({ id: z.string().min(1), display_name: z.string().min(1), operation: z.string().min(1), enabled: z.boolean(), authorization_status: z.enum(["authorized", "denied", "unknown"]), offerings: z.array(z.object({ id: z.string().min(1), upstream_service_id: z.string().min(1), capabilities: z.object({ web_search: z.object({ backend_kind: z.string().min(1), invocation_mode: z.string().min(1), output_modes: z.array(z.string()), evidence_kinds: z.array(z.string()), evidence_requirements: z.array(z.string()) }).passthrough().optional() }).passthrough(), profiles: z.array(z.object({ id: z.string().min(1), display_name: z.string().min(1), operation: z.string().min(1), action_binding_id: z.string().min(1), capabilities: z.object({ web_search: z.object({ backend_kind: z.string().min(1), invocation_mode: z.string().min(1), output_modes: z.array(z.string()), evidence_kinds: z.array(z.string()), evidence_requirements: z.array(z.string()) }).passthrough().optional() }).passthrough(), pool: poolSchema.nullable().optional() }).passthrough()) }).passthrough()) }).passthrough()),
  revision: z.number().int().positive(),
  observed_at: z.string().min(1),
}).passthrough()

// ProviderCapabilityCatalog binds one authorized provider identity to its parsed catalog.
// ProviderCapabilityCatalog 将一个已授权供应商身份绑定到已解析目录。
export interface ProviderCapabilityCatalog {
  // provider is the configured redacted provider identity.
  // provider 是已配置且脱敏的供应商身份。
  provider: AuthorizedProvider
  // catalog is the complete typed management catalog.
  // catalog 是完整的类型化管理目录。
  catalog: z.infer<typeof modelCatalogSchema>
}

// fetchCapabilityCatalogs loads every authorized provider and parses each complete catalog independently.
// fetchCapabilityCatalogs 加载每个已授权供应商并独立解析其完整目录。
export async function fetchCapabilityCatalogs(managementAuthToken: string, signal?: AbortSignal): Promise<ProviderCapabilityCatalog[]> {
  const providers = await fetchAuthorizedProviders(managementAuthToken, signal)
  const headers = { Authorization: `Bearer ${managementAuthToken}` }
  return Promise.all(providers.map(async (provider) => {
    const response = await fetch(`/vulcan/manage/provider-instances/${encodeURIComponent(provider.instance.id)}/catalog`, { method: "GET", headers, signal })
    if (!response.ok) throw new Error(`provider catalog request failed with status ${response.status}`)
    const catalog = modelCatalogSchema.parse(await response.json())
    if (catalog.provider_instance_id !== provider.instance.id) throw new Error("provider catalog response contains a mismatched owner")
    return { provider, catalog }
  }))
}

// formatKnownLimit renders unknown limits honestly instead of substituting an assumed value.
// formatKnownLimit 诚实渲染未知限制，而不是替换为假定值。
export function formatKnownLimit(limit: z.infer<typeof optionalLimitSchema>, unknownLabel: string): string {
  return limit.known ? String(limit.value) : unknownLabel
}
