import { useEffect, useState } from "react"

import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { useI18n } from "@/i18n"
import { fetchCapabilityCatalogs, type ProviderCapabilityCatalog } from "@/lib/model-capabilities"

// ServiceCapabilitiesPageProps defines the credential needed to read special-service contracts.
// ServiceCapabilitiesPageProps 定义读取特殊服务合同所需的凭证。
interface ServiceCapabilitiesPageProps {
  // managementAuthToken authorizes read-only management catalog requests.
  // managementAuthToken 授权只读管理目录请求。
  managementAuthToken: string
}

// ServiceCapabilitiesPage renders web-search and future provider service contracts separately from models.
// ServiceCapabilitiesPage 将联网搜索及未来供应商服务合同与模型分开渲染。
export function ServiceCapabilitiesPage({ managementAuthToken }: ServiceCapabilitiesPageProps) {
  // catalogs contains independently validated service catalogs.
  // catalogs 包含独立校验后的服务目录。
  const [catalogs, setCatalogs] = useState<ProviderCapabilityCatalog[]>([])
  // loading distinguishes the initial request from an empty service catalog.
  // loading 区分初始请求与空服务目录。
  const [loading, setLoading] = useState(true)
  // failed reports that the complete service view cannot be trusted.
  // failed 报告完整服务视图无法被信任。
  const [failed, setFailed] = useState(false)
  // t resolves authored service-page chrome into the active language.
  // t 将编写的服务页面文案解析为当前语言。
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

  if (loading) return <div className="grid gap-4 px-4 lg:px-6"><Skeleton className="h-40 w-full" /></div>
  if (failed) return <Card className="mx-4 lg:mx-6"><CardHeader><CardTitle>{t("capabilities.loadFailed")}</CardTitle><CardDescription>{t("capabilities.loadFailedDescription")}</CardDescription></CardHeader></Card>
  if (catalogs.every(({ catalog }) => catalog.services.length === 0)) return <Card className="mx-4 lg:mx-6"><CardHeader><CardTitle>{t("capabilities.noServices")}</CardTitle><CardDescription>{t("capabilities.noServicesDescription")}</CardDescription></CardHeader></Card>

  return (
    <div className="grid gap-4 px-4 lg:px-6">
      {catalogs.flatMap(({ provider, catalog }) => catalog.services.map((service) => (
        <Card key={`${provider.instance.id}:${service.id}`}>
          <CardHeader>
            <div className="flex flex-wrap items-center gap-2"><CardTitle>{service.display_name}</CardTitle><Badge variant="outline">{provider.instance.display_name}</Badge><Badge variant="outline">{service.operation}</Badge><Badge variant={service.enabled ? "default" : "secondary"}>{service.enabled ? t("capabilities.enabled") : t("capabilities.disabled")}</Badge><Badge variant={service.authorization_status === "authorized" ? "default" : service.authorization_status === "denied" ? "destructive" : "secondary"}>{service.authorization_status === "authorized" ? t("capabilities.authorized") : service.authorization_status === "denied" ? t("capabilities.unauthorized") : t("capabilities.unknown")}</Badge></div>
            <CardDescription>{service.id}</CardDescription>
          </CardHeader>
          <CardContent className="grid gap-3">
            {service.offerings.flatMap((offering) => offering.profiles.map((profile) => {
              const search = profile.capabilities.web_search
              return (
                <section key={profile.id} className="grid gap-3 rounded-lg border p-4">
                  <div className="flex flex-wrap items-center gap-2"><h3 className="font-semibold">{profile.display_name}</h3><Badge variant="secondary">{t("capabilities.readyCredentials")}: {profile.pool?.ready_credentials ?? 0}</Badge>{profile.pool && profile.pool.ready_credentials === 0 && <Badge variant="destructive">{t("capabilities.unavailable")}</Badge>}</div>
                  {search ? <div className="grid gap-2 text-sm md:grid-cols-2"><p><span className="font-medium">{t("services.backendKind")}:</span> {search.backend_kind}</p><p><span className="font-medium">{t("services.invocationMode")}:</span> {search.invocation_mode}</p><p><span className="font-medium">{t("services.outputModes")}:</span> {search.output_modes.join(", ")}</p><p><span className="font-medium">{t("services.evidenceKinds")}:</span> {search.evidence_kinds.join(", ")}</p><p className="md:col-span-2"><span className="font-medium">{t("services.evidenceRequirements")}:</span> {search.evidence_requirements.join(", ")}</p></div> : <p className="text-sm text-muted-foreground">{t("services.noTypedContract")}</p>}
                  {profile.pool && <p className="text-xs text-muted-foreground">{t("capabilities.configured")}: {profile.pool.configured_credentials} · {t("capabilities.entitled")}: {profile.pool.entitled_credentials} · {t("capabilities.cooling")}: {profile.pool.cooling_credentials} · {t("capabilities.exhausted")}: {profile.pool.exhausted_credentials} · {t("capabilities.invalid")}: {profile.pool.invalid_credentials} · {t("capabilities.blockedBy")}: {profile.pool.blocking_allowance_kinds.join(", ") || t("capabilities.none")}</p>}
                </section>
              )
            }))}
          </CardContent>
        </Card>
      )))}
    </div>
  )
}
