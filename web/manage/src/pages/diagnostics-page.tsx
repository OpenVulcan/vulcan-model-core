import { useEffect, useState } from "react"

import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { useI18n } from "@/i18n"
import {
  fetchExecutionDiagnostics,
  fetchAccessDiagnostics,
  fetchResourceDiagnostics,
  type AccessDiagnostic,
  type ExecutionDiagnostic,
  type ResourceDiagnostic,
} from "@/lib/diagnostics"

// DiagnosticsPageProps defines one metadata-only diagnostic view and its management credential.
// DiagnosticsPageProps 定义一个仅元数据诊断视图及其管理凭证。
interface DiagnosticsPageProps {
  // kind selects the bounded resource or execution history endpoint.
  // kind 选择有界资源或执行历史端点。
  kind: "resources" | "executions" | "access"
  // managementAuthToken authorizes management-only diagnostic reads.
  // managementAuthToken 授权仅管理端可用的诊断读取。
  managementAuthToken: string
}

// formatTimestamp renders one persisted timestamp using the active browser locale.
// formatTimestamp 使用当前浏览器区域设置渲染一个持久化时间戳。
function formatTimestamp(value: string): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "medium" }).format(new Date(value))
}

// ResourceRowsProps defines the safe Router resource rows rendered by the table-like list.
// ResourceRowsProps 定义由类表格列表渲染的安全 Router 资源行。
interface ResourceRowsProps {
  // rows contains metadata-only resources without content, locations, or owners.
  // rows 包含不带内容、位置或所有者的仅元数据资源。
  rows: ResourceDiagnostic[]
}

// ResourceRows renders resource lifecycle metadata without exposing protected material.
// ResourceRows 渲染资源生命周期元数据且不暴露受保护材料。
function ResourceRows({ rows }: ResourceRowsProps) {
  const { t } = useI18n()
  return <div className="grid gap-2">{rows.map((row) => <div key={row.id} className="grid gap-2 rounded-lg border p-3 text-sm lg:grid-cols-[minmax(10rem,1.5fr)_repeat(4,minmax(7rem,1fr))]"><div className="min-w-0"><p className="truncate font-medium">{row.id}</p><p className="truncate text-muted-foreground">{row.mime_type || t("diagnostics.unknownMime")}</p></div><div><p className="text-muted-foreground">{t("diagnostics.kind")}</p><p>{row.kind}</p></div><div><p className="text-muted-foreground">{t("diagnostics.source")}</p><p>{row.source}</p></div><div><p className="text-muted-foreground">{t("diagnostics.size")}</p><p>{row.size_bytes.toLocaleString()} B</p></div><div><p className="text-muted-foreground">{t("diagnostics.updated")}</p><p>{formatTimestamp(row.updated_at)}</p></div><div className="lg:col-span-5 flex flex-wrap gap-2"><Badge variant="outline">{row.state}</Badge><Badge variant="secondary">rev {row.revision}</Badge>{row.error_code && <Badge variant="destructive">{row.error_code}</Badge>}</div></div>)}</div>
}

// ExecutionRowsProps defines the public execution lifecycle rows rendered by diagnostics.
// ExecutionRowsProps 定义由诊断页面渲染的公开执行生命周期行。
interface ExecutionRowsProps {
  // rows contains public status and failure metadata without provider-private handles.
  // rows 包含不带供应商私有句柄的公开状态与失败元数据。
  rows: ExecutionDiagnostic[]
}

// ExecutionRows renders public execution lifecycle metadata without provider task or preparation state.
// ExecutionRows 渲染公开执行生命周期元数据且不包含供应商任务或准备状态。
function ExecutionRows({ rows }: ExecutionRowsProps) {
  const { t } = useI18n()
  return <div className="grid gap-2">{rows.map((row) => <div key={row.id} className="grid gap-2 rounded-lg border p-3 text-sm lg:grid-cols-[minmax(10rem,1.5fr)_repeat(3,minmax(8rem,1fr))]"><div className="min-w-0"><p className="truncate font-medium">{row.id}</p><p className="truncate text-muted-foreground">{row.operation}</p></div><div><p className="text-muted-foreground">{t("diagnostics.status")}</p><Badge variant="outline">{row.status}</Badge></div><div><p className="text-muted-foreground">{t("diagnostics.updated")}</p><p>{formatTimestamp(row.updated_at)}</p></div><div><p className="text-muted-foreground">{t("diagnostics.expires")}</p><p>{formatTimestamp(row.expires_at)}</p></div>{row.failure && <div className="rounded-md bg-destructive/10 p-2 text-destructive lg:col-span-4"><span className="font-medium">{row.failure.code}</span>{row.failure.category ? ` · ${row.failure.category}` : ""}</div>}<div className="lg:col-span-4"><Badge variant="secondary">rev {row.revision}</Badge></div></div>)}</div>
}

// AccessViewProps defines one redacted access observability snapshot.
// AccessViewProps 定义一个脱敏访问可观测快照。
interface AccessViewProps {
  // value contains bounded audit rows and aggregate counters.
  // value 包含受限审计行与聚合计数器。
  value: AccessDiagnostic
}

// AccessView renders aggregate traffic and redacted route audit without request content.
// AccessView 渲染聚合流量与脱敏路由审计且不包含请求内容。
function AccessView({ value }: AccessViewProps) {
  const { t } = useI18n()
  return <div className="grid gap-4">
    <div className="grid gap-3 sm:grid-cols-3">
      <div className="rounded-lg border p-3"><p className="text-sm text-muted-foreground">{t("diagnostics.requests")}</p><p className="text-2xl font-semibold">{value.metrics.requests.toLocaleString()}</p></div>
      <div className="rounded-lg border p-3"><p className="text-sm text-muted-foreground">{t("diagnostics.failures")}</p><p className="text-2xl font-semibold">{value.metrics.failures.toLocaleString()}</p></div>
      <div className="rounded-lg border p-3"><p className="text-sm text-muted-foreground">{t("diagnostics.totalDuration")}</p><p className="text-2xl font-semibold">{(value.metrics.total_duration_nanoseconds / 1_000_000).toLocaleString()} ms</p></div>
    </div>
    <div className="grid gap-2">{value.audit.map((event, index) => <div key={`${event.time}-${event.path}-${index}`} className="grid gap-2 rounded-lg border p-3 text-sm lg:grid-cols-[minmax(10rem,1.2fr)_minmax(8rem,1fr)_minmax(12rem,2fr)_auto]">
      <div>{event.principal ? <><p className="font-medium">{event.principal.subject_id}</p><p className="text-muted-foreground">{event.principal.tenant_id} / {event.principal.project_id}</p></> : <p className="font-medium text-muted-foreground">{t("diagnostics.unauthenticated")}</p>}</div>
      <div><Badge variant="outline">{t(`diagnostics.outcome.${event.outcome}`)}</Badge><p className="mt-1 text-muted-foreground">{event.permission} · {event.method}</p></div>
      <p className="break-all">{event.path}</p>
      <div className="text-right"><Badge variant={event.status_code >= 400 ? "destructive" : "secondary"}>{event.status_code}</Badge><p className="mt-1 text-muted-foreground">{formatTimestamp(event.time)}</p></div>
    </div>)}</div>
  </div>
}

// DiagnosticsPage loads and renders one bounded management-safe diagnostic history.
// DiagnosticsPage 加载并渲染一个有界且管理安全的诊断历史。
export function DiagnosticsPage({ kind, managementAuthToken }: DiagnosticsPageProps) {
  // resourceRows contains metadata-only resource history when selected.
  // resourceRows 在选中资源视图时包含仅元数据资源历史。
  const [resourceRows, setResourceRows] = useState<ResourceDiagnostic[]>([])
  // executionRows contains public execution lifecycle history when selected.
  // executionRows 在选中执行视图时包含公开执行生命周期历史。
  const [executionRows, setExecutionRows] = useState<ExecutionDiagnostic[]>([])
  // accessSnapshot contains redacted audit and aggregate metrics when selected.
  // accessSnapshot 在选中访问视图时包含脱敏审计与聚合指标。
  const [accessSnapshot, setAccessSnapshot] = useState<AccessDiagnostic | null>(null)
  // loading distinguishes an active request from an empty diagnostic history.
  // loading 区分活动请求与空诊断历史。
  const [loading, setLoading] = useState(true)
  // failed reports an authenticated diagnostic request or schema failure.
  // failed 报告已认证诊断请求或结构校验失败。
  const [failed, setFailed] = useState(false)
  const { t } = useI18n()

  useEffect(() => {
    const controller = new AbortController()
    setLoading(true)
    setFailed(false)
    const request = kind === "resources" ? fetchResourceDiagnostics(managementAuthToken, controller.signal).then(setResourceRows) : kind === "executions" ? fetchExecutionDiagnostics(managementAuthToken, controller.signal).then(setExecutionRows) : fetchAccessDiagnostics(managementAuthToken, controller.signal).then(setAccessSnapshot)
    request.catch((error: unknown) => {
      if (error instanceof DOMException && error.name === "AbortError") return
      setFailed(true)
    }).finally(() => {
      if (!controller.signal.aborted) setLoading(false)
    })
    return () => controller.abort()
  }, [kind, managementAuthToken])

  const rowsEmpty = kind === "resources" ? resourceRows.length === 0 : kind === "executions" ? executionRows.length === 0 : accessSnapshot === null || accessSnapshot.audit.length === 0 && accessSnapshot.metrics.requests === 0
  if (loading) return <div className="grid gap-3 px-4 lg:px-6"><Skeleton className="h-28 w-full" /><Skeleton className="h-28 w-full" /></div>

  const title = kind === "resources" ? t("diagnostics.resourcesTitle") : kind === "executions" ? t("diagnostics.executionsTitle") : t("diagnostics.accessTitle")
  const description = kind === "resources" ? t("diagnostics.resourcesDescription") : kind === "executions" ? t("diagnostics.executionsDescription") : t("diagnostics.accessDescription")
  return <Card className="mx-4 lg:mx-6"><CardHeader><CardTitle>{title}</CardTitle><CardDescription>{description}</CardDescription></CardHeader><CardContent>{failed ? <p className="text-sm text-destructive">{t("diagnostics.loadFailed")}</p> : rowsEmpty ? <p className="text-sm text-muted-foreground">{t("diagnostics.empty")}</p> : kind === "resources" ? <ResourceRows rows={resourceRows} /> : kind === "executions" ? <ExecutionRows rows={executionRows} /> : accessSnapshot && <AccessView value={accessSnapshot} />}</CardContent></Card>
}
