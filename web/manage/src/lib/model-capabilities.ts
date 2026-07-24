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

// standardModelToolSchema validates one closed provider-native standard tool contract.
// standardModelToolSchema 校验一项封闭的供应商原生标准工具合同。
const standardModelToolSchema = z.object({
  kind: z.enum(["web_search", "web_extractor"]),
  native: z.boolean(),
  requires: z.array(z.enum(["web_search", "web_extractor"])).nullish().transform((values) => values ?? []),
  requires_reasoning: z.boolean().optional().default(false),
  requires_streaming: z.boolean().optional().default(false),
  allows_caller_tools: z.boolean().optional().default(false),
})

// extraModelToolSchema validates one profile-owned non-standard model tool.
// extraModelToolSchema 校验一项规格拥有的非标准模型工具。
const extraModelToolSchema = z.object({
  id: z.string().regex(/^[a-z][a-z0-9_]*$/),
  display_name: z.string().min(1),
  description: z.string().min(1),
  input_modalities: stringArraySchema,
  output_modalities: stringArraySchema,
  requires_standard: z.array(z.enum(["web_search", "web_extractor"])).nullish().transform((values) => values ?? []),
  requires_extra: stringArraySchema,
  requires_reasoning: z.boolean().optional().default(false),
  requires_streaming: z.boolean().optional().default(false),
  allows_caller_tools: z.boolean().optional().default(false),
})

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
  standard_tools: z.array(standardModelToolSchema).nullish().transform((values) => values ?? []),
  extra_tools: z.array(extraModelToolSchema).nullish().transform((values) => values ?? []),
  hosted_tools: z.array(z.enum(["native_web_search", "provider_file_search", "provider_code_interpreter", "provider_computer_use"])).nullish().transform((values) => values ?? []),
}).passthrough()

// modelCatalogSchema validates one complete provider-scoped management catalog.
// modelCatalogSchema 校验一个完整的供应商作用域管理目录。
const webSearchCapabilitiesSchema = z.object({ backend_kind: z.string().min(1), invocation_mode: z.string().min(1), output_modes: z.array(z.string()), evidence_kinds: z.array(z.string()), evidence_requirements: z.array(z.string()) }).passthrough()

// webExtractCapabilitiesSchema validates one exact direct content-extraction contract.
// webExtractCapabilitiesSchema 校验一个精确的直接内容提取合同。
const webExtractCapabilitiesSchema = z.object({
  max_urls: z.number().int().positive(),
  depths: z.array(z.enum(["basic", "advanced"])).min(1),
  formats: z.array(z.enum(["markdown", "text"])).min(1),
  query_relevance: z.boolean(),
  minimum_chunks_per_source: z.number().int().nonnegative(),
  maximum_chunks_per_source: z.number().int().nonnegative(),
  include_images: z.boolean(),
  include_favicon: z.boolean(),
  minimum_timeout_seconds: z.number().positive(),
  maximum_timeout_seconds: z.number().positive(),
}).passthrough()

// serviceCapabilitiesSchema validates the closed special-service capability union.
// serviceCapabilitiesSchema 校验封闭的特殊服务能力联合体。
const serviceCapabilitiesSchema = z.object({
  web_search: webSearchCapabilitiesSchema.optional(),
  web_extract: webExtractCapabilitiesSchema.optional(),
}).passthrough()

// catalogRateLimitSchema validates one provider capacity ceiling and its exact ownership scope.
// catalogRateLimitSchema 校验一项供应商容量上限及其精确所有权作用域。
const catalogRateLimitSchema = z.object({
  id: z.string().min(1),
  scope: z.enum(["provider_instance", "workspace", "credential", "offering", "execution_profile"]),
  scope_id: z.string().min(1),
  tier_id: z.string().min(1),
  count_limit: z.number().int().positive(),
  count_period_seconds: z.number().int().positive(),
  usage_limit: z.number().int().positive().optional(),
  usage_period_seconds: z.number().int().positive().optional(),
  usage_field: z.string().min(1).optional(),
  observed_at: z.string().datetime({ offset: true }),
  expires_at: z.string().datetime({ offset: true }),
}).superRefine((limit, context) => {
  // usageTupleSize counts the provider metric tuple members so partial capacity facts cannot be rendered as complete limits.
  // usageTupleSize 统计供应商指标元组成员，避免把不完整容量事实渲染为完整限制。
  const usageTupleSize = [limit.usage_limit, limit.usage_period_seconds, limit.usage_field]
    .filter((value) => value !== undefined).length
  if (usageTupleSize !== 0 && usageTupleSize !== 3) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "rate-limit usage fields must be all present or all absent",
    })
  }
})

// CatalogRateLimit is one typed provider capacity ceiling displayed by management diagnostics.
// CatalogRateLimit 是由管理诊断展示的一项类型化供应商容量上限。
export type CatalogRateLimit = z.infer<typeof catalogRateLimitSchema>

export const modelCatalogSchema = z.object({
  provider_instance_id: z.string().min(1),
  models: z.array(z.object({ id: z.string().min(1), upstream_model_id: z.string().min(1), display_name: z.string().min(1), entitlement_mode: z.string(), enabled: z.boolean(), authorization_status: z.enum(["authorized", "denied", "unknown"]), offerings: z.array(z.object({ id: z.string().min(1), upstream_model_id: z.string().min(1), profiles: z.array(z.object({ id: z.string().min(1), display_name: z.string().min(1), default: z.boolean(), operation: z.string().min(1).optional().default(""), action_binding_id: z.string().min(1).optional().default(""), capabilities: modelCapabilitiesSchema, pool: poolSchema.nullable().optional() }).passthrough()) }).passthrough()) }).passthrough()),
  services: z.array(z.object({ id: z.string().min(1), display_name: z.string().min(1), operation: z.string().min(1), enabled: z.boolean(), authorization_status: z.enum(["authorized", "denied", "unknown"]), offerings: z.array(z.object({ id: z.string().min(1), upstream_service_id: z.string().min(1), capabilities: serviceCapabilitiesSchema, profiles: z.array(z.object({ id: z.string().min(1), display_name: z.string().min(1), operation: z.string().min(1), action_binding_id: z.string().min(1), capabilities: serviceCapabilitiesSchema, pool: poolSchema.nullable().optional() }).passthrough()) }).passthrough()) }).passthrough()),
  rate_limits: z.array(catalogRateLimitSchema).nullish().transform((values) => values ?? []),
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

// selectProfileRateLimits returns only capacity facts whose owner can be proven to affect the exact rendered profile.
// selectProfileRateLimits 仅返回可证实影响当前精确渲染规格的容量事实。
// providerInstanceID, offeringID, and executionProfileID are immutable owner identifiers; the return value preserves source order.
// providerInstanceID、offeringID 与 executionProfileID 是不可变所有者标识；返回值保留来源顺序。
export function selectProfileRateLimits(
  rateLimits: CatalogRateLimit[],
  providerInstanceID: string,
  offeringID: string,
  executionProfileID: string,
): CatalogRateLimit[] {
  return rateLimits.filter((limit) => {
    switch (limit.scope) {
      case "provider_instance":
        return limit.scope_id === providerInstanceID
      case "offering":
        return limit.scope_id === offeringID
      case "execution_profile":
        return limit.scope_id === executionProfileID
      case "workspace":
      case "credential":
        return false
    }
  })
}

// isCatalogRateLimitExpired reports whether one capacity fact is stale at an explicit comparison time.
// isCatalogRateLimitExpired 返回一项容量事实是否在显式比较时间点已经过期。
// nowMilliseconds is supplied by the caller for deterministic testing; invalid timestamps are rejected by the catalog schema before this function.
// nowMilliseconds 由调用方提供以支持确定性测试；无效时间戳会在进入此函数前被目录 Schema 拒绝。
export function isCatalogRateLimitExpired(
  rateLimit: CatalogRateLimit,
  nowMilliseconds: number,
): boolean {
  return Date.parse(rateLimit.expires_at) <= nowMilliseconds
}

// webSearchResultSchema validates one provider-returned ranked search item.
// webSearchResultSchema 校验一个供应商返回的排序搜索项。
const webSearchResultSchema = z.object({
  id: z.string().min(1),
  rank: z.number().int().positive(),
  title: z.string().optional(),
  url: z.string().url(),
  source_domain: z.string().optional(),
  snippet: z.string().optional(),
  published_at: z.string().optional(),
  updated_at: z.string().optional(),
  author: z.string().optional(),
  provider_score: z.number().finite().optional(),
})

// webSearchCitationSchema validates one provider-returned answer citation.
// webSearchCitationSchema 校验一个供应商返回的答案引用。
const webSearchCitationSchema = z.object({
  id: z.string().min(1),
  result_id: z.string().optional(),
  url: z.string().url(),
  title: z.string().optional(),
  location: z.object({
    output_item_id: z.string().optional(),
    start: z.number().int().nonnegative().optional(),
    end: z.number().int().nonnegative().optional(),
  }),
})

// managementSearchTestResponseSchema validates the real unified search result returned by the management diagnostic endpoint.
// managementSearchTestResponseSchema 校验管理诊断端点返回的真实统一搜索结果。
const managementSearchTestResponseSchema = z.object({
  execution_id: z.string().min(1),
  search: z.object({
    query: z.string(),
    queries: stringArraySchema,
    evidence: z.object({
      status: z.enum(["confirmed", "requested_unverified", "not_performed"]),
      kinds: stringArraySchema,
    }),
    results: z.array(webSearchResultSchema).nullish().transform((values) => values ?? []),
    answer: z.string().optional(),
    citations: z.array(webSearchCitationSchema).nullish().transform((values) => values ?? []),
    sources: z.array(z.object({ type: z.string().min(1), url: z.string().url() })).nullish().transform((values) => values ?? []),
    usage: z.record(z.string(), z.unknown()).optional(),
  }),
})

// SearchServiceTestInput selects one exact typed profile and query.
// SearchServiceTestInput 选择一个精确类型化规格及查询。
export interface SearchServiceTestInput {
  // providerInstanceID fixes the configured provider owner.
  // providerInstanceID 固定已配置供应商所有者。
  providerInstanceID: string
  // providerServiceID fixes the logical search service.
  // providerServiceID 固定逻辑搜索服务。
  providerServiceID: string
  // serviceOfferingID fixes the concrete provider channel.
  // serviceOfferingID 固定具体供应商通道。
  serviceOfferingID: string
  // executionProfileID fixes the typed execution shape.
  // executionProfileID 固定类型化执行形态。
  executionProfileID: string
  // query is the operator-entered search text.
  // query 是操作员输入的搜索文本。
  query: string
  // outputMode is selected from the profile-authored capability list.
  // outputMode 从规格编写的能力列表中选择。
  outputMode: string
  // evidenceRequirement is selected from the profile-authored policy list.
  // evidenceRequirement 从规格编写的策略列表中选择。
  evidenceRequirement: string
}

// SearchServiceTestResult is the validated management search diagnostic response.
// SearchServiceTestResult 是经过校验的管理搜索诊断响应。
export type SearchServiceTestResult = z.infer<typeof managementSearchTestResponseSchema>

// testSearchService executes one real provider search through the management diagnostic boundary.
// testSearchService 通过管理诊断边界执行一次真实供应商搜索。
export async function testSearchService(managementAuthToken: string, input: SearchServiceTestInput): Promise<SearchServiceTestResult> {
  const response = await fetch(`/vulcan/manage/provider-instances/${encodeURIComponent(input.providerInstanceID)}/services/${encodeURIComponent(input.providerServiceID)}/search-test`, {
    method: "POST",
    headers: { Authorization: `Bearer ${managementAuthToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      query: input.query,
      service_offering_id: input.serviceOfferingID,
      execution_profile_id: input.executionProfileID,
      output_mode: input.outputMode,
      evidence_requirement: input.evidenceRequirement,
    }),
  })
  if (!response.ok) {
    const failure = z.object({ error: z.string().min(1) }).safeParse(await response.json().catch(() => null))
    throw new Error(failure.success ? failure.data.error : `search test failed with status ${response.status}`)
  }
  return managementSearchTestResponseSchema.parse(await response.json())
}

// managementExtractTestResponseSchema validates one real provider extraction diagnostic.
// managementExtractTestResponseSchema 校验一次真实供应商内容提取诊断。
const managementExtractTestResponseSchema = z.object({
  execution_id: z.string().min(1),
  extract: z.object({
    results: z.array(z.object({ url: z.string().url(), raw_content: z.string(), images: z.array(z.string()).nullish().transform((values) => values ?? []), favicon: z.string().optional() })),
    failed_results: z.array(z.object({ url: z.string().url(), error: z.string().min(1) })).nullish().transform((values) => values ?? []),
    provider_request_id: z.string().optional(),
    response_time_seconds: z.number().nonnegative().optional(),
    usage: z.record(z.string(), z.unknown()).optional(),
  }),
})

// ExtractServiceTestInput selects one exact typed profile and bounded extraction request.
// ExtractServiceTestInput 选择一个精确类型化规格及有界内容提取请求。
export interface ExtractServiceTestInput {
  providerInstanceID: string
  providerServiceID: string
  serviceOfferingID: string
  executionProfileID: string
  urls: string[]
  query: string
  chunksPerSource?: number
  depth: "basic" | "advanced"
  format: "markdown" | "text"
  includeImages: boolean
  includeFavicon: boolean
  timeoutSeconds?: number
}

// ExtractServiceTestResult is the validated management extraction diagnostic response.
// ExtractServiceTestResult 是经过校验的管理内容提取诊断响应。
export type ExtractServiceTestResult = z.infer<typeof managementExtractTestResponseSchema>

// testExtractService executes one real provider extraction through the management diagnostic boundary.
// testExtractService 通过管理诊断边界执行一次真实供应商内容提取。
export async function testExtractService(managementAuthToken: string, input: ExtractServiceTestInput): Promise<ExtractServiceTestResult> {
  const response = await fetch(`/vulcan/manage/provider-instances/${encodeURIComponent(input.providerInstanceID)}/services/${encodeURIComponent(input.providerServiceID)}/extract-test`, {
    method: "POST",
    headers: { Authorization: `Bearer ${managementAuthToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      service_offering_id: input.serviceOfferingID,
      execution_profile_id: input.executionProfileID,
      urls: input.urls,
      query: input.query || undefined,
      chunks_per_source: input.chunksPerSource,
      depth: input.depth,
      format: input.format,
      include_images: input.includeImages,
      include_favicon: input.includeFavicon,
      timeout_seconds: input.timeoutSeconds,
    }),
  })
  if (!response.ok) {
    const failure = z.object({ error: z.string().min(1) }).safeParse(await response.json().catch(() => null))
    throw new Error(failure.success ? failure.data.error : `extraction test failed with status ${response.status}`)
  }
  return managementExtractTestResponseSchema.parse(await response.json())
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
