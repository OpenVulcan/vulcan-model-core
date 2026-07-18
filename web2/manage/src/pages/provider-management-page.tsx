import { type FormEvent, useEffect, useRef, useState } from "react"
import { CheckIcon, Globe2Icon, ServerIcon } from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { type TranslationKey, useI18n } from "@/i18n"
import {
  cancelKimiDeviceFlow,
  fetchProviderGroups,
  onboardKimiDeviceFlow,
  onboardSystemProvider,
  startKimiDeviceFlow,
  type KimiDeviceFlow,
  type ProviderDefinition,
  type ProviderGroup,
} from "@/lib/provider-groups"

// ProviderManagementPageProps defines the authenticated management credential used only for API reads.
// ProviderManagementPageProps 定义仅用于 API 读取的已认证管理凭证。
interface ProviderManagementPageProps {
  // managementAuthToken is the active in-memory management credential.
  // managementAuthToken 是当前内存管理凭证。
  managementAuthToken: string
}

// ProviderManagementPage renders grouped system providers and exact site or plan selection.
// ProviderManagementPage 渲染已分组系统供应商及精确站点或套餐选择。
export function ProviderManagementPage({
  managementAuthToken,
}: ProviderManagementPageProps) {
  const { t } = useI18n()
  // groups contains the authenticated management catalog returned by the core service.
  // groups 包含核心服务返回的已认证管理目录。
  const [groups, setGroups] = useState<ProviderGroup[]>([])
  // selectedGroupID identifies the brand whose exact definitions are currently visible.
  // selectedGroupID 标识当前显示精确定义的品牌。
  const [selectedGroupID, setSelectedGroupID] = useState("")
  // selectedDefinitionID identifies the exact site or product selected for subsequent onboarding.
  // selectedDefinitionID 标识为后续录入选择的精确站点或产品。
  const [selectedDefinitionID, setSelectedDefinitionID] = useState("")
  // loading reports whether the first authenticated catalog request is pending.
  // loading 表示首次已认证目录请求是否仍在等待。
  const [loading, setLoading] = useState(true)
  // loadFailed reports a safe localized catalog-loading failure without exposing server details.
  // loadFailed 报告安全的本地化目录加载失败且不暴露服务端细节。
  const [loadFailed, setLoadFailed] = useState(false)

  useEffect(() => {
    // controller cancels only this page-owned catalog request when the route unmounts.
    // controller 仅在路由卸载时取消此页面拥有的目录请求。
    const controller = new AbortController()
    setLoading(true)
    setLoadFailed(false)
    fetchProviderGroups(managementAuthToken, controller.signal)
      .then((providerGroups) => {
        setGroups(providerGroups)
        if (providerGroups.length === 1) {
          setSelectedGroupID(providerGroups[0].id)
        }
      })
      .catch((error: unknown) => {
        if (controller.signal.aborted || (error instanceof DOMException && error.name === "AbortError")) {
          return
        }
        setLoadFailed(true)
      })
      .finally(() => {
        if (!controller.signal.aborted) {
          setLoading(false)
        }
      })
    return () => controller.abort()
  }, [managementAuthToken])

  // selectedGroup is the exact group chosen by its immutable identifier.
  // selectedGroup 是按不可变标识选择的精确分组。
  const selectedGroup = groups.find((group) => group.id === selectedGroupID)
  // selectedDefinition is the exact immutable variant passed to the onboarding command.
  // selectedDefinition 是传递给录入命令的精确不可变变体。
  const selectedDefinition = selectedGroup?.provider_definitions.find((definition) => definition.id === selectedDefinitionID)

  return (
    <div className="flex flex-col gap-6 p-4 lg:p-6">
      <div>
        <h2 className="text-2xl font-semibold tracking-tight">
          {t("providers.title")}
        </h2>
        <p className="text-muted-foreground mt-1 text-sm">
          {t("providers.description")}
        </p>
      </div>

      {loading ? (
        <p className="text-muted-foreground text-sm">{t("providers.loading")}</p>
      ) : null}
      {loadFailed ? (
        <p className="text-destructive text-sm">{t("providers.loadFailed")}</p>
      ) : null}

      {!loading && !loadFailed ? (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {groups.map((group) => (
            <Button
              key={group.id}
              variant={selectedGroupID === group.id ? "default" : "outline"}
              className="h-auto justify-start gap-3 px-4 py-4 text-left"
              onClick={() => {
                setSelectedGroupID(group.id)
                setSelectedDefinitionID("")
              }}
            >
              <ServerIcon className="size-5" />
              <span>
                <span className="block font-semibold">{group.display_name}</span>
                <span className="block text-xs opacity-75">
                  {group.provider_definitions.length} {t("providers.variants")}
                </span>
              </span>
            </Button>
          ))}
        </div>
      ) : null}

      {selectedGroup ? (
        <section className="space-y-4" aria-label={selectedGroup.display_name}>
          <div>
            <h3 className="text-lg font-semibold">{selectedGroup.display_name}</h3>
            <p className="text-muted-foreground text-sm">{localizedDescription(t, selectedGroup.description_key, selectedGroup.description)}</p>
          </div>
          <div className="grid gap-4 lg:grid-cols-3">
            {selectedGroup.provider_definitions.map((definition) => (
              <ProviderVariantCard
                key={definition.id}
                definition={definition}
                selected={selectedDefinitionID === definition.id}
                onSelect={setSelectedDefinitionID}
              />
            ))}
          </div>
          {selectedDefinition ? (
            <ProviderOnboardingPanel key={selectedDefinition.id} definition={selectedDefinition} managementAuthToken={managementAuthToken} />
          ) : null}
        </section>
      ) : null}
    </div>
  )
}

// ProviderVariantCardProps defines one exact selectable provider variant card.
// ProviderVariantCardProps 定义一个精确可选择的供应商变体卡片。
interface ProviderVariantCardProps {
  // definition contains one exact site or commercial product.
  // definition 包含一个精确站点或商业产品。
  definition: ProviderDefinition
  // selected reports whether this definition is the current onboarding choice.
  // selected 表示此定义是否为当前录入选择。
  selected: boolean
  // onSelect records the immutable definition identifier without creating a runtime fallback.
  // onSelect 记录不可变定义标识且不创建运行时降级。
  onSelect: (definitionID: string) => void
}

// ProviderVariantCard renders one Kimi site or plan with explicit protocols and endpoints.
// ProviderVariantCard 使用显式协议和端点渲染一个 Kimi 站点或套餐。
function ProviderVariantCard({
  definition,
  selected,
  onSelect,
}: ProviderVariantCardProps) {
  const { t } = useI18n()
  return (
    <Card className={selected ? "border-primary ring-primary/20 ring-2" : ""}>
      <CardHeader>
        <div className="flex items-start justify-between gap-3">
          <div>
            <CardTitle>{definition.variant_name}</CardTitle>
            <CardDescription className="mt-1">
              {localizedDescription(t, definition.variant_description_key, definition.variant_description)}
            </CardDescription>
          </div>
          {selected ? <CheckIcon className="text-primary size-5" /> : null}
        </div>
      </CardHeader>
      <CardContent className="flex flex-1 flex-col gap-4">
        <div className="flex flex-wrap gap-2">
          {definition.channels.map((channel) => (
            <Badge key={channel.id} variant="secondary">
              {channel.protocol_profile_id}
            </Badge>
          ))}
        </div>
        <div className="space-y-2">
          {definition.endpoint_presets.map((preset) => (
            <div key={preset.id} className="flex items-start gap-2 text-xs">
              <Globe2Icon className="text-muted-foreground mt-0.5 size-3.5 shrink-0" />
              <span className="break-all">{preset.base_url}</span>
            </div>
          ))}
        </div>
        <Button
          className="mt-auto w-full"
          variant={selected ? "secondary" : "default"}
          onClick={() => onSelect(definition.id)}
        >
          {selected ? t("providers.selected") : t("providers.select")}
        </Button>
      </CardContent>
    </Card>
  )
}

// localizedDescription resolves only server-authored localization keys and preserves a safe English fallback.
// localizedDescription 仅解析服务端编写的本地化键并保留安全英文回退。
function localizedDescription(t: (key: TranslationKey) => string, key: string | undefined, fallback: string): string {
  switch (key) {
    case "providers.kimi.description":
    case "providers.kimi.cnDescription":
    case "providers.kimi.globalDescription":
    case "providers.kimi.codingDescription":
      return t(key)
    default:
      return fallback
  }
}

// ProviderOnboardingPanelProps binds one exact definition and active management credential to its real workflow.
// ProviderOnboardingPanelProps 将一个精确定义和当前管理凭证绑定到真实工作流。
interface ProviderOnboardingPanelProps {
  definition: ProviderDefinition
  managementAuthToken: string
}

// ProviderOnboardingPanel performs API-key or server-confidential device-flow onboarding.
// ProviderOnboardingPanel 执行 API Key 或服务端保密设备授权录入。
function ProviderOnboardingPanel({ definition, managementAuthToken }: ProviderOnboardingPanelProps) {
  const { t } = useI18n()
  const [authMethodID, setAuthMethodID] = useState(definition.auth_methods[0]?.id ?? "")
  const authMethod = definition.auth_methods.find((method) => method.id === authMethodID)
  const isDeviceFlow = authMethod?.type === "device_flow"
  const [handle, setHandle] = useState(definition.id.replace(/^system_/, ""))
  const [displayName, setDisplayName] = useState(definition.display_name)
  const [credentialLabel, setCredentialLabel] = useState(isDeviceFlow ? "Kimi User" : "Primary")
  const [secret, setSecret] = useState("")
  const [deviceFlow, setDeviceFlow] = useState<KimiDeviceFlow | null>(null)
  // deviceFlowRef retains the exact unfinished session for unmount cleanup without duplicating completed cancellation.
  // deviceFlowRef 保留精确的未完成会话用于卸载清理，且不会重复取消已完成会话。
  const deviceFlowRef = useRef<KimiDeviceFlow | null>(null)
  const [pending, setPending] = useState(false)
  const [messageKey, setMessageKey] = useState<TranslationKey | null>(null)

  useEffect(() => {
    // cleanup releases the exact unfinished server session when this definition panel unmounts.
    // cleanup 在此定义面板卸载时释放精确的未完成服务端会话。
    return () => {
      if (deviceFlowRef.current) {
        void cancelKimiDeviceFlow(managementAuthToken, deviceFlowRef.current.id).catch(() => undefined)
      }
    }
  }, [managementAuthToken])

  // submitAPIKey sends one plaintext key only to the authenticated atomic onboarding endpoint.
  // submitAPIKey 仅将一个明文密钥发送到经过认证的原子录入端点。
  async function submitAPIKey(event: FormEvent) {
    event.preventDefault()
    if (!authMethod || authMethod.type !== "api_key") {
      setMessageKey("providers.unsupportedAuthentication")
      return
    }
    setPending(true)
    setMessageKey(null)
    try {
      await onboardSystemProvider(managementAuthToken, {
        provider_definition_id: definition.id, handle, display_name: displayName,
        auth_method_id: authMethodID, credential_label: credentialLabel, principal_key: "", secret,
      })
      setSecret("")
      setMessageKey("providers.onboardingComplete")
    } catch {
      setMessageKey("providers.onboardingFailed")
    } finally {
      setPending(false)
    }
  }

  // beginDeviceFlow requests management-safe verification data from the server-owned Kimi client.
  // beginDeviceFlow 从服务端拥有的 Kimi 客户端请求管理安全验证数据。
  async function beginDeviceFlow() {
    if (!authMethod || authMethod.type !== "device_flow") {
      setMessageKey("providers.unsupportedAuthentication")
      return
    }
    setPending(true)
    setMessageKey(null)
    try {
      const flow = await startKimiDeviceFlow(managementAuthToken)
      deviceFlowRef.current = flow
      setDeviceFlow(flow)
    } catch {
      setMessageKey("providers.onboardingFailed")
    } finally {
      setPending(false)
    }
  }

  // checkDeviceFlow performs one provider-safe poll and commits only a completed authorization.
  // checkDeviceFlow 执行一次供应商安全轮询且仅提交已完成授权。
  async function checkDeviceFlow() {
    if (!deviceFlow) return
    setPending(true)
    setMessageKey(null)
    try {
      const result = await onboardKimiDeviceFlow(managementAuthToken, deviceFlow.id, {
        provider_definition_id: definition.id, handle, display_name: displayName,
        credential_label: credentialLabel, principal_key: "",
      })
      if (result === null) {
        setMessageKey("providers.authorizationPending")
      } else {
        deviceFlowRef.current = null
        setDeviceFlow(null)
        setMessageKey("providers.onboardingComplete")
      }
    } catch {
      setMessageKey("providers.onboardingFailed")
    } finally {
      setPending(false)
    }
  }

  // cancelDeviceFlow releases the page-owned authorization session immediately.
  // cancelDeviceFlow 立即释放页面拥有的授权会话。
  async function cancelDeviceFlow() {
    if (!deviceFlow) return
    setPending(true)
    setMessageKey(null)
    try {
      await cancelKimiDeviceFlow(managementAuthToken, deviceFlow.id)
      deviceFlowRef.current = null
      setDeviceFlow(null)
    } catch {
      setMessageKey("providers.onboardingFailed")
    } finally {
      setPending(false)
    }
  }

  // selectAuthMethod releases any unfinished flow before changing the exact credential acquisition method.
  // selectAuthMethod 在切换精确凭据获取方式前释放任何未完成授权流程。
  function selectAuthMethod(methodID: string) {
    if (deviceFlowRef.current) {
      void cancelKimiDeviceFlow(managementAuthToken, deviceFlowRef.current.id).catch(() => undefined)
    }
    deviceFlowRef.current = null
    setAuthMethodID(methodID)
    setDeviceFlow(null)
    setSecret("")
    setMessageKey(null)
  }

  if (!authMethod || (authMethod.type !== "api_key" && authMethod.type !== "device_flow")) {
    return <p className="text-destructive text-sm" role="alert">{t("providers.unsupportedAuthentication")}</p>
  }

  return (
    <Card>
      <CardHeader><CardTitle>{definition.display_name}</CardTitle><CardDescription>{localizedDescription(t, definition.variant_description_key, definition.variant_description)}</CardDescription></CardHeader>
      <CardContent>
        <form className="grid gap-4 md:grid-cols-2" onSubmit={isDeviceFlow ? (event) => event.preventDefault() : submitAPIKey}>
          {definition.auth_methods.length > 1 ? <div className="flex gap-2 md:col-span-2">{definition.auth_methods.map((method) => <Button key={method.id} type="button" variant={authMethodID === method.id ? "default" : "outline"} onClick={() => selectAuthMethod(method.id)}>{method.type === "device_flow" ? t("providers.deviceFlow") : t("providers.apiKey")}</Button>)}</div> : null}
          <div className="space-y-2"><Label htmlFor="provider-handle">{t("providers.handle")}</Label><Input id="provider-handle" value={handle} onChange={(event) => setHandle(event.target.value)} required /></div>
          <div className="space-y-2"><Label htmlFor="provider-name">{t("providers.displayName")}</Label><Input id="provider-name" value={displayName} onChange={(event) => setDisplayName(event.target.value)} required /></div>
          <div className="space-y-2"><Label htmlFor="credential-label">{t("providers.credentialLabel")}</Label><Input id="credential-label" value={credentialLabel} onChange={(event) => setCredentialLabel(event.target.value)} required /></div>
          {!isDeviceFlow ? <div className="space-y-2"><Label htmlFor="provider-secret">{t("providers.apiKey")}</Label><Input id="provider-secret" type="password" value={secret} onChange={(event) => setSecret(event.target.value)} required autoComplete="off" /></div> : null}
          <div className="md:col-span-2">
            {!isDeviceFlow ? <Button type="submit" disabled={pending}>{t("providers.onboard")}</Button> : deviceFlow ? (
              <div className="space-y-3"><p className="text-sm">{t("providers.authorizationCode")}: <strong>{deviceFlow.user_code}</strong></p><a className="text-primary text-sm underline" href={deviceFlow.verification_uri_complete || deviceFlow.verification_uri} target="_blank" rel="noreferrer">{deviceFlow.verification_uri}</a><div className="flex gap-2"><Button type="button" disabled={pending} onClick={checkDeviceFlow}>{t("providers.checkAuthorization")}</Button><Button type="button" variant="outline" disabled={pending} onClick={cancelDeviceFlow}>{t("providers.cancelAuthorization")}</Button></div></div>
            ) : <Button type="button" disabled={pending} onClick={beginDeviceFlow}>{t("providers.startAuthorization")}</Button>}
          </div>
          {messageKey ? <p className="md:col-span-2 text-sm" role="status">{t(messageKey)}</p> : null}
        </form>
      </CardContent>
    </Card>
  )
}
