import { useEffect, useState } from "react"

import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { useI18n } from "@/i18n"
import {
  fetchCapabilityCatalogs,
  formatKnownLimit,
  type ProviderCapabilityCatalog,
} from "@/lib/model-capabilities"

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
  // t resolves all authored page chrome into the active interface language.
  // t 将页面中所有编写的界面文案解析为当前语言。
  const { t } = useI18n()

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
