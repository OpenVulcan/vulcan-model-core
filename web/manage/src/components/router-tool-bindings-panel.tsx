"use client"

import { useEffect, useMemo, useState } from "react"
import { Activity, Pencil, Plus, Trash2 } from "lucide-react"

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { ReadonlyCombobox } from "@/components/ui/readonly-combobox"
import { useI18n } from "@/i18n"
import type { ProviderCapabilityCatalog } from "@/lib/model-capabilities"
import {
  createRouterToolBinding,
  deleteRouterToolBinding,
  fetchRouterToolBindings,
  probeRouterToolBinding,
  type RouterToolBinding,
  type RouterToolBindingInput,
  type RouterToolBindingProbe,
  updateRouterToolBinding,
} from "@/lib/router-tool-bindings"

// RouterToolBindingsPanelProps supplies management authentication and exact service catalogs.
// RouterToolBindingsPanelProps 提供管理认证与精确服务目录。
interface RouterToolBindingsPanelProps {
  // managementAuthToken authorizes Router binding mutations.
  // managementAuthToken 授权 Router 绑定变更。
  managementAuthToken: string
  // catalogs contains every configured provider service path.
  // catalogs 包含每个已配置供应商服务路径。
  catalogs: ProviderCapabilityCatalog[]
  // onBindingsChanged requests a fresh effective model-tool view.
  // onBindingsChanged 请求刷新有效模型工具视图。
  onBindingsChanged: () => void
}

// RouterToolID is the complete closed standard and operation-backed binding set.
// RouterToolID 是完整封闭的标准工具与操作支持增强绑定集合。
type RouterToolID =
  | "web_search"
  | "web_extractor"
  | "image_understanding"
  | "audio_understanding"
  | "video_understanding"
  | "image_generation"
  | "video_generation"
  | "speech_generation"
  | "speech_transcription"

// StandardToolID is the service-backed subset of RouterToolID.
// StandardToolID 是 RouterToolID 中由服务支持的子集。
type StandardToolID = "web_search" | "web_extractor"

// RouterExtensionID is the model-backed subset of RouterToolID.
// RouterExtensionID 是 RouterToolID 中由模型支持的子集。
type RouterExtensionID = Exclude<RouterToolID, StandardToolID>

// BackendOption binds one stable UI option to an exact catalog service or model path.
// BackendOption 将一个稳定界面选项绑定到一条精确目录服务或模型路径。
interface BackendOption {
  // value is a local presentation identifier and is never submitted.
  // value 是本地展示标识且绝不提交。
  value: string
  // label is the human-readable provider and service path.
  // label 是供用户阅读的供应商与服务路径。
  label: string
  // toolID is the closed capability provided by this profile.
  // toolID 是该规格提供的封闭能力。
  toolID: RouterToolID
  // providerInstanceID fixes the backend provider owner.
  // providerInstanceID 固定后端供应商所有者。
  providerInstanceID: string
  // providerServiceID fixes the logical service.
  // providerServiceID 固定逻辑服务。
  providerServiceID?: string
  // serviceOfferingID fixes the service offering.
  // serviceOfferingID 固定服务产品。
  serviceOfferingID?: string
  // providerModelID fixes the logical model for an operation-backed enhancement.
  // providerModelID 为操作支持增强能力固定逻辑模型。
  providerModelID?: string
  // offeringID fixes the model offering for an operation-backed enhancement.
  // offeringID 为操作支持增强能力固定模型产品。
  offeringID?: string
  // executionProfileID fixes the executable profile.
  // executionProfileID 固定可执行规格。
  executionProfileID: string
}

// BindingDraft contains the complete editable form state.
// BindingDraft 包含完整可编辑表单状态。
interface BindingDraft {
  // toolID selects one standard tool or operation-backed enhancement.
  // toolID 选择一个标准工具或操作支持增强能力。
  toolID: RouterToolID
  // backendValue selects one exact catalog path.
  // backendValue 选择一条精确目录路径。
  backendValue: string
  // priority orders matching bindings.
  // priority 排列匹配绑定顺序。
  priority: string
  // enabled controls selection eligibility.
  // enabled 控制选择资格。
  enabled: boolean
  // timeoutMilliseconds is the child timeout.
  // timeoutMilliseconds 是子执行超时。
  timeoutMilliseconds: string
  // maximumCalls limits calls per parent.
  // maximumCalls 限制每个父执行调用次数。
  maximumCalls: string
  // maximumResults limits search results.
  // maximumResults 限制搜索结果数。
  maximumResults: string
  // maximumURLs limits extraction URLs.
  // maximumURLs 限制抓取 URL 数。
  maximumURLs: string
  // maximumResultBytes limits model-visible serialized output.
  // maximumResultBytes 限制模型可见序列化输出。
  maximumResultBytes: string
  // allowedProviderInstanceIDs is a comma-separated exact parent-instance allowlist.
  // allowedProviderInstanceIDs 是逗号分隔的精确父实例允许列表。
  allowedProviderInstanceIDs: string
  // allowedProviderModelIDs is a comma-separated exact parent-model allowlist.
  // allowedProviderModelIDs 是逗号分隔的精确父模型允许列表。
  allowedProviderModelIDs: string
  // allowedExecutionProfileIDs is a comma-separated exact parent-profile allowlist.
  // allowedExecutionProfileIDs 是逗号分隔的精确父规格允许列表。
  allowedExecutionProfileIDs: string
}

// defaultDraft returns safe bounded defaults for one selected Router capability.
// defaultDraft 返回一个已选 Router 能力的安全有界默认值。
function defaultDraft(toolID: RouterToolID): BindingDraft {
  return {
    toolID,
    backendValue: "",
    priority: "0",
    enabled: true,
    timeoutMilliseconds: "30000",
    maximumCalls: "4",
    maximumResults: toolID === "web_search" ? "8" : "0",
    maximumURLs: toolID === "web_extractor" ? "8" : "0",
    maximumResultBytes: "65536",
    allowedProviderInstanceIDs: "",
    allowedProviderModelIDs: "",
    allowedExecutionProfileIDs: "",
  }
}

// exactBackendValue returns the local option that owns one persisted binding path.
// exactBackendValue 返回拥有一条持久绑定路径的本地选项。
function exactBackendValue(options: BackendOption[], binding: RouterToolBinding): string {
  const toolID = binding.kind ?? binding.extension
  return options.find((option) =>
    option.toolID === toolID
    && option.providerInstanceID === binding.provider_instance_id
    && option.providerServiceID === binding.provider_service_id
    && option.serviceOfferingID === binding.service_offering_id
    && option.providerModelID === binding.provider_model_id
    && option.offeringID === binding.offering_id
    && option.executionProfileID === binding.execution_profile_id
  )?.value ?? ""
}

// draftFromBinding converts a persisted binding into editable form state.
// draftFromBinding 将持久绑定转换为可编辑表单状态。
function draftFromBinding(options: BackendOption[], binding: RouterToolBinding): BindingDraft {
  return {
    toolID: (binding.kind ?? binding.extension) as RouterToolID,
    backendValue: exactBackendValue(options, binding),
    priority: String(binding.priority),
    enabled: binding.enabled,
    timeoutMilliseconds: String(binding.timeout_milliseconds),
    maximumCalls: String(binding.maximum_calls),
    maximumResults: String(binding.maximum_results),
    maximumURLs: String(binding.maximum_urls),
    maximumResultBytes: String(binding.maximum_result_bytes),
    allowedProviderInstanceIDs: binding.allowed_provider_instance_ids.join(", "),
    allowedProviderModelIDs: binding.allowed_provider_model_ids.join(", "),
    allowedExecutionProfileIDs: binding.allowed_execution_profile_ids.join(", "),
  }
}

// positiveInteger converts a form value into one validated positive integer.
// positiveInteger 将表单值转换为一个经过校验的正整数。
function positiveInteger(value: string): number | null {
  const parsed = Number(value)
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : null
}

// nonnegativeInteger converts a form value into one validated nonnegative integer.
// nonnegativeInteger 将表单值转换为一个经过校验的非负整数。
function nonnegativeInteger(value: string): number | null {
  const parsed = Number(value)
  return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : null
}

// parseScopeIDs validates one comma-separated exact allowlist without silently merging duplicates.
// parseScopeIDs 校验一个逗号分隔的精确允许列表且不静默合并重复项。
function parseScopeIDs(value: string): string[] | null {
  if (value.trim() === "") return []
  const identifiers = value.split(",").map((identifier) => identifier.trim())
  if (identifiers.some((identifier) => identifier === "") || new Set(identifiers).size !== identifiers.length) return null
  return identifiers
}

// extensionsForProfile returns every Router enhancement proven by one exact model profile.
// extensionsForProfile 返回由一个精确模型规格证实的全部 Router 增强能力。
function extensionsForProfile(operation: string, mediaKinds: string[]): RouterExtensionID[] {
  switch (operation) {
    case "media.analyze":
      return [
        ...(mediaKinds.includes("image") ? ["image_understanding" as const] : []),
        ...(mediaKinds.includes("audio") ? ["audio_understanding" as const] : []),
        ...(mediaKinds.includes("video") ? ["video_understanding" as const] : []),
      ]
    case "image.generate":
      return ["image_generation"]
    case "video.generate":
      return ["video_generation"]
    case "speech.synthesize":
      return ["speech_generation"]
    case "speech.transcribe":
      return ["speech_transcription"]
    default:
      return []
  }
}

// RouterToolBindingsPanel renders complete CRUD for explicit standard-tool and extension backends.
// RouterToolBindingsPanel 渲染显式标准工具与增强能力后端的完整增删改查。
export function RouterToolBindingsPanel({
  managementAuthToken,
  catalogs,
  onBindingsChanged,
}: RouterToolBindingsPanelProps) {
  const { t } = useI18n()
  const [bindings, setBindings] = useState<RouterToolBinding[]>([])
  const [loading, setLoading] = useState(true)
  const [failure, setFailure] = useState("")
  const [dialogOpen, setDialogOpen] = useState(false)
  const [editing, setEditing] = useState<RouterToolBinding | null>(null)
  const [draft, setDraft] = useState<BindingDraft>(() => defaultDraft("web_search"))
  const [saving, setSaving] = useState(false)
  const [probes, setProbes] = useState<Record<string, RouterToolBindingProbe>>({})
  const [probingBindingID, setProbingBindingID] = useState("")

  // backendOptions contains only catalog paths with exact service or operation evidence.
  // backendOptions 仅包含具有精确服务或操作证据的目录路径。
  const backendOptions = useMemo<BackendOption[]>(() => {
    const options: BackendOption[] = []
    for (const { provider, catalog } of catalogs) {
      for (const service of catalog.services) {
        for (const offering of service.offerings) {
          for (const profile of offering.profiles) {
            const supportsSearch = profile.capabilities.web_search !== undefined
            const supportsExtract = profile.capabilities.web_extract !== undefined
            if (!supportsSearch && !supportsExtract) continue
            const base = {
              label: `${provider.instance.display_name} · ${service.display_name} · ${profile.display_name}`,
              providerInstanceID: catalog.provider_instance_id,
              providerServiceID: service.id,
              serviceOfferingID: offering.id,
              executionProfileID: profile.id,
            }
            if (supportsSearch) options.push({ ...base, value: `backend-${options.length}`, toolID: "web_search" })
            if (supportsExtract) options.push({ ...base, value: `backend-${options.length}`, toolID: "web_extractor" })
          }
        }
      }
      for (const model of catalog.models) {
        for (const offering of model.offerings) {
          for (const profile of offering.profiles) {
            const mediaKinds = profile.capabilities.media_inputs.map((capability) => capability.kind)
            for (const toolID of extensionsForProfile(profile.operation, mediaKinds)) {
              options.push({
                value: `backend-${options.length}`,
                label: `${provider.instance.display_name} · ${model.display_name} · ${profile.display_name}`,
                toolID,
                providerInstanceID: catalog.provider_instance_id,
                providerModelID: model.id,
                offeringID: offering.id,
                executionProfileID: profile.id,
              })
            }
          }
        }
      }
    }
    return options
  }, [catalogs])

  // loadBindings refreshes only the non-secret binding collection.
  // loadBindings 仅刷新不含秘密的绑定集合。
  async function loadBindings(signal?: AbortSignal): Promise<void> {
    setLoading(true)
    setFailure("")
    setProbes({})
    try {
      setBindings(await fetchRouterToolBindings(managementAuthToken, signal))
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") return
      setFailure(error instanceof Error ? error.message : t("capabilities.routerBindingsLoadFailed"))
    } finally {
      if (!signal?.aborted) setLoading(false)
    }
  }

  useEffect(() => {
    const controller = new AbortController()
    void loadBindings(controller.signal)
    return () => controller.abort()
  }, [managementAuthToken])

  // openCreate initializes a new binding with the first compatible backend.
  // openCreate 使用第一个兼容后端初始化新绑定。
  function openCreate(): void {
    const next = defaultDraft("web_search")
    next.backendValue = backendOptions.find((option) => option.toolID === next.toolID)?.value ?? ""
    setEditing(null)
    setDraft(next)
    setFailure("")
    setDialogOpen(true)
  }

  // openEdit preserves every persisted safety limit and exact backend.
  // openEdit 保留全部持久安全限制与精确后端。
  function openEdit(binding: RouterToolBinding): void {
    setEditing(binding)
    setDraft(draftFromBinding(backendOptions, binding))
    setFailure("")
    setDialogOpen(true)
  }

  // changeTool resets the backend to one compatible exact service or model path.
  // changeTool 将后端重置为一条兼容的精确服务或模型路径。
  function changeTool(toolID: RouterToolID): void {
    setDraft((current) => ({
      ...current,
      toolID,
      backendValue: backendOptions.find((option) => option.toolID === toolID)?.value ?? "",
      maximumResults: toolID === "web_search" ? (current.maximumResults === "0" ? "8" : current.maximumResults) : "0",
      maximumURLs: toolID === "web_extractor" ? (current.maximumURLs === "0" ? "8" : current.maximumURLs) : "0",
    }))
  }

  // submit validates numeric limits and persists one exact binding.
  // submit 校验数值限制并持久化一个精确绑定。
  async function submit(): Promise<void> {
    const backend = backendOptions.find((option) => option.value === draft.backendValue && option.toolID === draft.toolID)
    const priority = nonnegativeInteger(draft.priority)
    const timeoutMilliseconds = positiveInteger(draft.timeoutMilliseconds)
    const maximumCalls = positiveInteger(draft.maximumCalls)
    const maximumResults = nonnegativeInteger(draft.maximumResults)
    const maximumURLs = nonnegativeInteger(draft.maximumURLs)
    const maximumResultBytes = positiveInteger(draft.maximumResultBytes)
    const allowedProviderInstanceIDs = parseScopeIDs(draft.allowedProviderInstanceIDs)
    const allowedProviderModelIDs = parseScopeIDs(draft.allowedProviderModelIDs)
    const allowedExecutionProfileIDs = parseScopeIDs(draft.allowedExecutionProfileIDs)
    if (!backend || priority === null || timeoutMilliseconds === null || maximumCalls === null || maximumResults === null || maximumURLs === null || maximumResultBytes === null || allowedProviderInstanceIDs === null || allowedProviderModelIDs === null || allowedExecutionProfileIDs === null) {
      setFailure(t("capabilities.routerBindingInvalid"))
      return
    }
    if (draft.toolID === "web_search" && maximumResults === 0 || draft.toolID === "web_extractor" && maximumURLs === 0) {
      setFailure(t("capabilities.routerBindingInvalid"))
      return
    }
    const standard = draft.toolID === "web_search" || draft.toolID === "web_extractor"
    const toolSelection = standard
      ? { kind: draft.toolID as StandardToolID }
      : { extension: draft.toolID as RouterExtensionID }
    const input: RouterToolBindingInput = {
      ...toolSelection,
      providerInstanceID: backend.providerInstanceID,
      providerServiceID: backend.providerServiceID,
      serviceOfferingID: backend.serviceOfferingID,
      providerModelID: backend.providerModelID,
      offeringID: backend.offeringID,
      executionProfileID: backend.executionProfileID,
      priority,
      enabled: draft.enabled,
      timeoutMilliseconds,
      maximumCalls,
      maximumResults,
      maximumURLs,
      maximumResultBytes,
      allowedProviderInstanceIDs,
      allowedProviderModelIDs,
      allowedExecutionProfileIDs,
    }
    setSaving(true)
    setFailure("")
    try {
      if (editing) {
        await updateRouterToolBinding(managementAuthToken, editing.id, editing.revision, input)
      } else {
        await createRouterToolBinding(managementAuthToken, input)
      }
      setDialogOpen(false)
      await loadBindings()
      onBindingsChanged()
    } catch (error) {
      setFailure(error instanceof Error ? error.message : t("capabilities.routerBindingSaveFailed"))
    } finally {
      setSaving(false)
    }
  }

  // remove deletes one exact binding only after explicit confirmation.
  // remove 仅在显式确认后删除一个精确绑定。
  async function remove(bindingID: string): Promise<void> {
    setFailure("")
    try {
      await deleteRouterToolBinding(managementAuthToken, bindingID)
      await loadBindings()
      onBindingsChanged()
    } catch (error) {
      setFailure(error instanceof Error ? error.message : t("capabilities.routerBindingDeleteFailed"))
    }
  }

  // probe verifies one persisted binding through current exact-target resolution.
  // probe 通过当前精确 Target 解析验证一个持久化绑定。
  async function probe(bindingID: string): Promise<void> {
    setFailure("")
    setProbingBindingID(bindingID)
    try {
      const result = await probeRouterToolBinding(managementAuthToken, bindingID)
      setProbes((current) => ({ ...current, [bindingID]: result }))
    } catch (error) {
      setFailure(error instanceof Error ? error.message : t("capabilities.routerBindingProbeFailed"))
    } finally {
      setProbingBindingID("")
    }
  }

  const compatibleBackends = backendOptions.filter((option) => option.toolID === draft.toolID)

  return (
    <section className="rounded-lg border p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="font-semibold">{t("capabilities.routerBindings")}</h2>
          <p className="text-sm text-muted-foreground">{t("capabilities.routerBindingsDescription")}</p>
        </div>
        <Button size="sm" onClick={openCreate} disabled={backendOptions.length === 0}>
          <Plus className="size-4" />{t("capabilities.addRouterBinding")}
        </Button>
      </div>
      {failure ? <p className="mt-3 text-sm text-destructive">{failure}</p> : null}
      {loading ? <p className="mt-3 text-sm text-muted-foreground">{t("common.loading")}</p> : null}
      {!loading && bindings.length === 0 ? <p className="mt-3 text-sm text-muted-foreground">{t("capabilities.noRouterBindings")}</p> : null}
      <div className="mt-3 grid gap-2">
        {bindings.map((binding) => {
          const backend = backendOptions.find((option) => exactBackendValue([option], binding) !== "")
          const toolID = (binding.kind ?? binding.extension) as RouterToolID
          const probeResult = probes[binding.id]
          return (
            <div key={binding.id} className="flex flex-wrap items-center justify-between gap-3 rounded-md border p-3">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium">{t(`capabilities.${toolID}`)}</span>
                  <Badge variant={binding.enabled ? "default" : "secondary"}>
                    {binding.enabled ? t("capabilities.enabled") : t("capabilities.disabled")}
                  </Badge>
                  {probeResult ? (
                    <Badge variant={probeResult.ready ? "default" : "destructive"}>
                      {probeResult.ready ? t("capabilities.ready") : t(`capabilities.${probeResult.unavailable_reason!}`)}
                    </Badge>
                  ) : null}
                  <Badge variant="outline">{t("capabilities.priority")}: {binding.priority}</Badge>
                </div>
                <p className="mt-1 truncate text-sm text-muted-foreground">{backend?.label ?? binding.provider_service_id ?? binding.provider_model_id}</p>
              </div>
              <div className="flex items-center gap-2">
                <Button size="sm" variant="outline" disabled={probingBindingID === binding.id} onClick={() => void probe(binding.id)}>
                  <Activity className="size-4" />{probingBindingID === binding.id ? t("capabilities.testingRouterBinding") : t("capabilities.testRouterBinding")}
                </Button>
                <Button size="sm" variant="outline" onClick={() => openEdit(binding)}>
                  <Pencil className="size-4" />{t("common.edit")}
                </Button>
                <AlertDialog>
                  <AlertDialogTrigger render={<Button size="icon-sm" variant="ghost" aria-label={t("common.delete")} />}>
                    <Trash2 className="size-4 text-destructive" />
                  </AlertDialogTrigger>
                  <AlertDialogContent>
                    <AlertDialogHeader>
                      <AlertDialogTitle>{t("capabilities.deleteRouterBindingTitle")}</AlertDialogTitle>
                      <AlertDialogDescription>{t("capabilities.deleteRouterBindingDescription")}</AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                      <AlertDialogCancel>{t("common.cancel")}</AlertDialogCancel>
                      <AlertDialogAction onClick={() => void remove(binding.id)}>{t("common.delete")}</AlertDialogAction>
                    </AlertDialogFooter>
                  </AlertDialogContent>
                </AlertDialog>
              </div>
            </div>
          )
        })}
      </div>

      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="max-h-[80vh] max-w-2xl overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{editing ? t("capabilities.editRouterBinding") : t("capabilities.addRouterBinding")}</DialogTitle>
            <DialogDescription>{t("capabilities.routerBindingDialogDescription")}</DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 py-2">
            <div className="grid gap-2 sm:grid-cols-2">
              <div className="grid gap-2">
                <Label>{t("capabilities.routerCapability")}</Label>
                <ReadonlyCombobox
                  value={draft.toolID}
                  onValueChange={(value) => changeTool(value as RouterToolID)}
                  options={[
                    { value: "web_search", label: t("capabilities.web_search") },
                    { value: "web_extractor", label: t("capabilities.web_extractor") },
                    { value: "image_understanding", label: t("capabilities.image_understanding") },
                    { value: "audio_understanding", label: t("capabilities.audio_understanding") },
                    { value: "video_understanding", label: t("capabilities.video_understanding") },
                    { value: "image_generation", label: t("capabilities.image_generation") },
                    { value: "video_generation", label: t("capabilities.video_generation") },
                    { value: "speech_generation", label: t("capabilities.speech_generation") },
                    { value: "speech_transcription", label: t("capabilities.speech_transcription") },
                  ]}
                />
              </div>
              <div className="grid gap-2">
                <Label>{t("capabilities.backendService")}</Label>
                <ReadonlyCombobox
                  value={draft.backendValue}
                  onValueChange={(backendValue) => setDraft((current) => ({ ...current, backendValue }))}
                  options={compatibleBackends}
                  placeholder={t("capabilities.selectBackendService")}
                  emptyText={t("capabilities.noCompatibleBackend")}
                />
              </div>
            </div>
            <div className="grid gap-3 sm:grid-cols-3">
              <div className="grid gap-2"><Label>{t("capabilities.priority")}</Label><Input type="number" min={0} value={draft.priority} onChange={(event) => setDraft((current) => ({ ...current, priority: event.target.value }))} /></div>
              <div className="grid gap-2"><Label>{t("capabilities.timeoutMilliseconds")}</Label><Input type="number" min={1} max={300000} value={draft.timeoutMilliseconds} onChange={(event) => setDraft((current) => ({ ...current, timeoutMilliseconds: event.target.value }))} /></div>
              <div className="grid gap-2"><Label>{t("capabilities.maximumCalls")}</Label><Input type="number" min={1} max={32} value={draft.maximumCalls} onChange={(event) => setDraft((current) => ({ ...current, maximumCalls: event.target.value }))} /></div>
              <div className="grid gap-2"><Label>{t("capabilities.maximumResults")}</Label><Input type="number" min={0} max={100} disabled={draft.toolID !== "web_search"} value={draft.maximumResults} onChange={(event) => setDraft((current) => ({ ...current, maximumResults: event.target.value }))} /></div>
              <div className="grid gap-2"><Label>{t("capabilities.maximumURLs")}</Label><Input type="number" min={0} max={20} disabled={draft.toolID !== "web_extractor"} value={draft.maximumURLs} onChange={(event) => setDraft((current) => ({ ...current, maximumURLs: event.target.value }))} /></div>
              <div className="grid gap-2"><Label>{t("capabilities.maximumResultBytes")}</Label><Input type="number" min={1} max={1048576} value={draft.maximumResultBytes} onChange={(event) => setDraft((current) => ({ ...current, maximumResultBytes: event.target.value }))} /></div>
            </div>
            <div className="grid gap-3">
              <p className="text-sm font-medium">{t("capabilities.bindingScope")}</p>
              <p className="text-xs text-muted-foreground">{t("capabilities.bindingScopeDescription")}</p>
              <div className="grid gap-3 sm:grid-cols-3">
                <div className="grid gap-2"><Label>{t("capabilities.allowedProviderInstances")}</Label><Input value={draft.allowedProviderInstanceIDs} onChange={(event) => setDraft((current) => ({ ...current, allowedProviderInstanceIDs: event.target.value }))} placeholder={t("capabilities.commaSeparatedIDs")} /></div>
                <div className="grid gap-2"><Label>{t("capabilities.allowedProviderModels")}</Label><Input value={draft.allowedProviderModelIDs} onChange={(event) => setDraft((current) => ({ ...current, allowedProviderModelIDs: event.target.value }))} placeholder={t("capabilities.commaSeparatedIDs")} /></div>
                <div className="grid gap-2"><Label>{t("capabilities.allowedExecutionProfiles")}</Label><Input value={draft.allowedExecutionProfileIDs} onChange={(event) => setDraft((current) => ({ ...current, allowedExecutionProfileIDs: event.target.value }))} placeholder={t("capabilities.commaSeparatedIDs")} /></div>
              </div>
            </div>
            <label className="flex items-center gap-2 text-sm">
              <Checkbox checked={draft.enabled} onCheckedChange={(enabled) => setDraft((current) => ({ ...current, enabled }))} />
              {t("capabilities.bindingEnabled")}
            </label>
            {failure ? <p className="text-sm text-destructive">{failure}</p> : null}
          </div>
          <div className="flex justify-end gap-2">
            <Button variant="outline" onClick={() => setDialogOpen(false)}>{t("common.cancel")}</Button>
            <Button disabled={saving} onClick={() => void submit()}>{saving ? t("common.saving") : t("common.save")}</Button>
          </div>
        </DialogContent>
      </Dialog>
    </section>
  )
}
