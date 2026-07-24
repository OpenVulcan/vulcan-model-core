import { useEffect, useState } from "react"

import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { RouterToolBindingsPanel } from "@/components/router-tool-bindings-panel"
import { useI18n } from "@/i18n"
import {
  fetchCapabilityCatalogs,
  formatKnownLimit,
  isCatalogRateLimitExpired,
  selectProfileRateLimits,
  type CatalogRateLimit,
  type ProviderCapabilityCatalog,
} from "@/lib/model-capabilities"
import {
  fetchModelToolAvailability,
  type ModelToolAvailability,
} from "@/lib/router-tool-bindings"

// ModelCapabilitiesPageProps defines the credential needed to read provider capability catalogs.
// ModelCapabilitiesPageProps 定义读取供应商能力目录所需的凭证。
interface ModelCapabilitiesPageProps {
  // managementAuthToken authorizes read-only management catalog requests.
  // managementAuthToken 授权只读管理目录请求。
  managementAuthToken: string
}

// formatCapabilityLevel renders one explicit support level without collapsing unknown or conditional states.
// formatCapabilityLevel 渲染一个明确支持级别，且不会折叠未知或条件支持状态。
function formatCapabilityLevel(level: string): string {
  return level.replaceAll("_", " ")
}

// joinValues renders a closed value list while preserving an explicit empty state.
// joinValues 渲染封闭值列表，同时保留明确的空状态。
function joinValues(values: string[], emptyLabel: string): string {
  return values.length > 0 ? values.join(", ") : emptyLabel
}

// formatRateLimit renders one complete capacity tuple without changing provider-authored tier or metric names.
// formatRateLimit 渲染一项完整容量元组，且不会改写供应商编写的档位或指标名称。
// The localized labels describe request counts and time windows; the return value is presentation-only text.
// 本地化标签描述请求次数与时间窗口；返回值仅用于展示文本。
function formatRateLimit(
  limit: CatalogRateLimit,
  requestsLabel: string,
  secondsLabel: string,
): string {
  // segments preserves the independent request-count and optional usage ceilings in one compact line.
  // segments 在一条紧凑文本中保留独立的请求计数与可选用量上限。
  const segments = [
    `${limit.count_limit} ${requestsLabel} / ${limit.count_period_seconds} ${secondsLabel}`,
  ]
  if (
    limit.usage_limit !== undefined &&
    limit.usage_period_seconds !== undefined &&
    limit.usage_field !== undefined
  ) {
    segments.push(
      `${limit.usage_field}: ${limit.usage_limit} / ${limit.usage_period_seconds} ${secondsLabel}`,
    )
  }
  return `${limit.tier_id} · ${segments.join(" · ")}`
}

// ModelCapabilitiesPage renders provider-scoped model contracts and their auditable limits.
// ModelCapabilitiesPage 渲染供应商作用域模型合同及其可审计限制。
export function ModelCapabilitiesPage({ managementAuthToken }: ModelCapabilitiesPageProps) {
  // catalogs contains independently parsed catalogs for every configured provider.
  // catalogs 包含每个已配置供应商独立解析后的目录。
  const [catalogs, setCatalogs] = useState<ProviderCapabilityCatalog[]>([])
  // loading distinguishes the initial request from a valid empty provider list.
  // loading 区分初始请求与有效的空供应商列表。
  const [loading, setLoading] = useState(true)
  // failed reports a complete catalog read failure without inventing partial capability data.
  // failed 报告完整目录读取失败，且不会虚构部分能力数据。
  const [failed, setFailed] = useState(false)
  // toolAvailability contains effective native, extra, and Router readiness from exact target resolution.
  // toolAvailability 包含通过精确 Target 解析得到的有效原生、额外及 Router 就绪状态。
  const [toolAvailability, setToolAvailability] = useState<ModelToolAvailability | null>(null)
  // toolAvailabilityRevision requests a fresh view after binding mutations.
  // toolAvailabilityRevision 在绑定变更后请求刷新视图。
  const [toolAvailabilityRevision, setToolAvailabilityRevision] = useState(0)
  // t resolves all authored page chrome into the active interface language.
  // t 将页面中所有编写的界面文案解析为当前语言。
  const { t } = useI18n()
  // renderedAtMilliseconds keeps every freshness decision internally consistent for this render.
  // renderedAtMilliseconds 让本次渲染内的所有新鲜度判断保持一致。
  const renderedAtMilliseconds = Date.now()

  useEffect(() => {
    const controller = new AbortController()
    setLoading(true)
    setFailed(false)
    fetchCapabilityCatalogs(managementAuthToken, controller.signal)
      .then(setCatalogs)
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === "AbortError") return
        setFailed(true)
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false)
      })
    return () => controller.abort()
  }, [managementAuthToken])

  useEffect(() => {
    const controller = new AbortController()
    fetchModelToolAvailability(managementAuthToken, controller.signal)
      .then(setToolAvailability)
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === "AbortError") return
        setToolAvailability(null)
      })
    return () => controller.abort()
  }, [managementAuthToken, toolAvailabilityRevision])

  if (loading) {
    return <div className="grid gap-4 px-4 lg:px-6"><Skeleton className="h-36 w-full" /><Skeleton className="h-56 w-full" /></div>
  }

  if (failed) {
    return <Card className="mx-4 lg:mx-6"><CardHeader><CardTitle>{t("capabilities.loadFailed")}</CardTitle><CardDescription>{t("capabilities.loadFailedDescription")}</CardDescription></CardHeader></Card>
  }

  if (catalogs.every(({ catalog }) => catalog.models.length === 0)) {
    return <Card className="mx-4 lg:mx-6"><CardHeader><CardTitle>{t("capabilities.noModels")}</CardTitle><CardDescription>{t("capabilities.noModelsDescription")}</CardDescription></CardHeader></Card>
  }

  return (
    <div className="grid gap-4 px-4 lg:px-6">
      <RouterToolBindingsPanel
        managementAuthToken={managementAuthToken}
        catalogs={catalogs}
        onBindingsChanged={() => setToolAvailabilityRevision((revision) => revision + 1)}
      />
      {catalogs.flatMap(({ provider, catalog }) => catalog.models.map((model) => (
        <Card key={`${provider.instance.id}:${model.id}`}>
          <CardHeader className="gap-2">
            <div className="flex flex-wrap items-center gap-2">
              <CardTitle>{model.display_name}</CardTitle>
              <Badge variant="outline">{provider.instance.display_name}</Badge>
              <Badge variant={model.enabled ? "default" : "secondary"}>{model.enabled ? t("capabilities.enabled") : t("capabilities.disabled")}</Badge>
              <Badge variant={model.authorization_status === "authorized" ? "default" : model.authorization_status === "denied" ? "destructive" : "secondary"}>{model.authorization_status === "authorized" ? t("capabilities.authorized") : model.authorization_status === "denied" ? t("capabilities.unauthorized") : t("capabilities.unknown")}</Badge>
            </div>
            <CardDescription>{model.upstream_model_id}</CardDescription>
          </CardHeader>
          <CardContent className="grid gap-3">
            {model.offerings.flatMap((offering) => offering.profiles.map((profile) => {
              const capabilities = profile.capabilities
              // effectiveTools is the runtime-aware view for this exact provider, model, offering, and profile.
              // effectiveTools 是此精确供应商、模型、产品及规格的运行时感知视图。
              const effectiveTools = toolAvailability?.models
                .find((candidate) =>
                  candidate.provider_instance_id === provider.instance.id
                  && candidate.model.id === model.id
                )
                ?.model_tools.find((candidate) =>
                  candidate.offering_id === offering.id
                  && candidate.execution_profile_id === profile.id
                )
              // profileRateLimits contains only instance-, Offering-, or profile-owned limits that can be attributed exactly.
              // profileRateLimits 仅包含可精确归属的实例、Offering 或规格级限制。
              const profileRateLimits = selectProfileRateLimits(
                catalog.rate_limits,
                catalog.provider_instance_id,
                offering.id,
                profile.id,
              )
              const limits = [
                [t("capabilities.contextWindow"), formatKnownLimit(capabilities.context_window, t("capabilities.unknown"))],
                [t("capabilities.maxInput"), formatKnownLimit(capabilities.max_input_tokens, t("capabilities.unknown"))],
                [t("capabilities.maxOutput"), formatKnownLimit(capabilities.max_output_tokens, t("capabilities.unknown"))],
                [t("capabilities.recommendedOutput"), formatKnownLimit(capabilities.recommended_output_tokens, t("capabilities.unknown"))],
              ]
              const featureLevels = [
                [t("capabilities.toolCalling"), capabilities.tool_calling],
                [t("capabilities.parallelTools"), capabilities.parallel_tool_calls],
                [t("capabilities.streamingToolArguments"), capabilities.streaming_tool_arguments],
                [t("capabilities.strictJSON"), capabilities.strict_json_schema],
                [t("capabilities.reasoning"), capabilities.reasoning],
              ]
              return (
                <section key={profile.id} className="rounded-lg border p-4">
                  <div className="mb-3 flex flex-wrap items-center gap-2">
                    <h3 className="font-semibold">{profile.display_name}</h3>
                    <Badge variant="outline">{profile.operation || t("capabilities.legacyConversation")}</Badge>
                    <Badge variant="secondary">{t("capabilities.readyCredentials")}: {profile.pool?.ready_credentials ?? 0}</Badge>
                    {profile.pool && profile.pool.ready_credentials === 0 && <Badge variant="destructive">{t("capabilities.unavailable")}</Badge>}
                  </div>
                  <div className="grid gap-4 xl:grid-cols-2">
                    <div className="grid gap-2 text-sm">
                      <p><span className="font-medium">{t("capabilities.inputModalities")}:</span> {joinValues(capabilities.input_modalities, t("capabilities.none"))}</p>
                      <p><span className="font-medium">{t("capabilities.outputModalities")}:</span> {joinValues(capabilities.output_modalities, t("capabilities.none"))}</p>
                      <p><span className="font-medium">{t("capabilities.delivery")}:</span> {Object.entries(capabilities.delivery).filter(([, supported]) => supported).map(([mode]) => mode).join(", ") || t("capabilities.none")}</p>
                      <div className="flex flex-wrap gap-2">
                        {featureLevels.map(([label, level]) => <Badge key={label} variant="outline">{label}: {formatCapabilityLevel(level)}</Badge>)}
                      </div>
                    </div>
                    <div className="grid grid-cols-2 gap-2 text-sm sm:grid-cols-4">
                      {limits.map(([label, value]) => <div key={label} className="rounded-md bg-muted p-2"><p className="text-muted-foreground">{label}</p><p className="font-medium">{value}</p></div>)}
                    </div>
                  </div>
                  {profileRateLimits.length > 0 && (
                    <div className="mt-4 text-sm">
                      <p className="mb-2 font-medium">{t("capabilities.rateLimits")}</p>
                      <div className="flex flex-wrap gap-2">
                        {profileRateLimits.map((limit) => {
                          // expired preserves the fact's staleness consistently across styling and text in this render.
                          // expired 在本次渲染的样式与文本间一致保留该事实的过期状态。
                          const expired = isCatalogRateLimitExpired(limit, renderedAtMilliseconds)
                          return (
                            <Badge key={limit.id} variant={expired ? "destructive" : "outline"}>
                              {formatRateLimit(
                                limit,
                                t("capabilities.requests"),
                                t("capabilities.seconds"),
                              )}
                              {expired ? ` · ${t("capabilities.expired")}` : ""}
                            </Badge>
                          )
                        })}
                      </div>
                    </div>
                  )}
                  {(capabilities.media_inputs.length > 0 || capabilities.media_outputs.length > 0) && (
                    <div className="mt-4 grid gap-2 text-sm md:grid-cols-2">
                      <div><p className="mb-1 font-medium">{t("capabilities.mediaInputs")}</p>{capabilities.media_inputs.map((media) => <p key={`${media.kind}:${media.roles?.join(":")}`}>{media.kind} · {formatCapabilityLevel(media.level)} · {joinValues(media.client_workflows ?? [], t("capabilities.none"))}</p>)}</div>
                      <div><p className="mb-1 font-medium">{t("capabilities.mediaOutputs")}</p>{capabilities.media_outputs.map((media) => <p key={`${media.kind}:${media.formats?.join(":")}`}>{media.kind} · {formatCapabilityLevel(media.level)} · {joinValues(media.materialization_modes ?? [], t("capabilities.none"))}</p>)}</div>
                    </div>
                  )}
                  {(capabilities.embedding || capabilities.rerank) && (
                    <div className="mt-4 flex flex-wrap gap-2">
                      {capabilities.embedding && <Badge variant="outline">embedding · {joinValues(capabilities.embedding.output_kinds, t("capabilities.unknown"))} · {capabilities.embedding.dimensions.join(", ") || t("capabilities.unknown")}</Badge>}
                      {capabilities.rerank && <Badge variant="outline">rerank · {capabilities.rerank.score_semantics}</Badge>}
                    </div>
                  )}
                  {(effectiveTools?.standard.length ?? capabilities.standard_tools.length) > 0 && (
                    <div className="mt-4 text-sm">
                      <p className="mb-2 font-medium">{t("capabilities.standardTools")}</p>
                      <div className="grid gap-2 md:grid-cols-2">
                        {(effectiveTools?.standard ?? capabilities.standard_tools.map((tool) => ({
                          kind: tool.kind,
                          native_supported: tool.native,
                          native_ready: tool.native,
                          router_tool_supported: false,
                          router_tool_ready: false,
                          available_modes: tool.native ? ["disabled", "native"] : ["disabled"],
                          requires: tool.requires,
                          native_unavailable_reason: undefined,
                          router_tool_unavailable_reason: "router_binding_missing",
                        }))).map((tool) => (
                          <div key={tool.kind} className="rounded-md border p-3">
                            <div className="flex flex-wrap items-center gap-2">
                              <span className="font-medium">{t(`capabilities.${tool.kind}`)}</span>
                              <Badge variant={tool.native_ready ? "default" : "secondary"}>
                                {t("capabilities.native")}: {tool.native_ready ? t("capabilities.ready") : tool.native_supported ? t("capabilities.unavailable") : t("capabilities.unsupported")}
                              </Badge>
                              <Badge variant={tool.router_tool_ready ? "default" : "secondary"}>
                                Router: {tool.router_tool_ready ? t("capabilities.ready") : tool.router_tool_supported ? t("capabilities.unavailable") : t("capabilities.unconfigured")}
                              </Badge>
                            </div>
                            <p className="mt-1 text-xs text-muted-foreground">
                              {t("capabilities.dependencies")}: {joinValues(tool.requires, t("capabilities.none"))}
                              {" · "}{t("capabilities.availableModes")}: {tool.available_modes.join(", ")}
                              {tool.native_unavailable_reason ? ` · ${t("capabilities.native")}: ${t(`capabilities.${tool.native_unavailable_reason}`)}` : ""}
                              {tool.router_tool_unavailable_reason ? ` · Router: ${t(`capabilities.${tool.router_tool_unavailable_reason}`)}` : ""}
                            </p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {(effectiveTools?.extra.length ?? capabilities.extra_tools.length) > 0 && (
                    <div className="mt-4 text-sm">
                      <p className="mb-2 font-medium">{t("capabilities.extraTools")}</p>
                      <div className="grid gap-2 md:grid-cols-2">
                        {(effectiveTools?.extra ?? capabilities.extra_tools.map((capability) => ({ capability, ready: true }))).map((toolView) => {
                          const tool = toolView.capability
                          return (
                          <div key={tool.id} className="rounded-md border p-3">
                            <div className="flex flex-wrap items-center gap-2">
                              <span className="font-medium">{tool.display_name}</span>
                              <Badge variant="outline">{tool.id}</Badge>
                              <Badge variant="secondary">{t("capabilities.defaultDisabled")}</Badge>
                              <Badge variant={toolView.ready ? "default" : "destructive"}>{toolView.ready ? t("capabilities.ready") : t("capabilities.unavailable")}</Badge>
                            </div>
                            <p className="mt-1 text-muted-foreground">{tool.description}</p>
                          </div>
                          )
                        })}
                      </div>
                    </div>
                  )}
                  {effectiveTools && effectiveTools.router_extensions.length > 0 && (
                    <div className="mt-4 text-sm">
                      <p className="mb-2 font-medium">{t("capabilities.routerExtensions")}</p>
                      <div className="grid gap-2 md:grid-cols-2">
                        {effectiveTools.router_extensions.map((tool) => (
                          <div key={tool.id} className="rounded-md border p-3">
                            <div className="flex flex-wrap items-center gap-2">
                              <span className="font-medium">{t(`capabilities.${tool.id}`)}</span>
                              <Badge variant="outline">{tool.id}</Badge>
                              <Badge variant={tool.ready ? "default" : tool.supported ? "destructive" : "secondary"}>
                                {tool.ready ? t("capabilities.ready") : tool.supported ? t("capabilities.unavailable") : t("capabilities.unconfigured")}
                              </Badge>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {profile.pool && (
                    <div className="mt-4 grid grid-cols-2 gap-2 text-sm sm:grid-cols-4 lg:grid-cols-6">
                      <p>{t("capabilities.configured")}: {profile.pool.configured_credentials}</p>
                      <p>{t("capabilities.entitled")}: {profile.pool.entitled_credentials}</p>
                      <p>{t("capabilities.cooling")}: {profile.pool.cooling_credentials}</p>
                      <p>{t("capabilities.exhausted")}: {profile.pool.exhausted_credentials}</p>
                      <p>{t("capabilities.invalid")}: {profile.pool.invalid_credentials}</p>
                      <p>{t("capabilities.blockedBy")}: {profile.pool.blocking_allowance_kinds.join(", ") || t("capabilities.none")}</p>
                    </div>
                  )}
                  {[...capabilities.media_inputs, ...capabilities.media_outputs].some((media) => media.evidence.length > 0) && (
                    <div className="mt-4 text-xs text-muted-foreground">
                      <p className="font-medium">{t("capabilities.evidence")}</p>
                      {[...capabilities.media_inputs, ...capabilities.media_outputs].flatMap((media) => media.evidence.map((item) => <p key={`${media.kind}:${item.source}:${item.reference}`}>{media.kind} · {item.source} · {item.reference} · rev {item.revision}</p>))}
                    </div>
                  )}
                </section>
              )
            }))}
          </CardContent>
        </Card>
      )))}
    </div>
  )
}
