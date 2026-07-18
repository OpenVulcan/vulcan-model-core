import { type FormEvent, useEffect, useRef, useState } from "react"
import {
  ArrowLeftIcon,
  ChevronDownIcon,
  ChevronRightIcon,
  KeyRoundIcon,
  PlusIcon,
  SearchIcon,
  ServerIcon,
  ShieldCheckIcon,
  XIcon,
} from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { type TranslationKey, useI18n } from "@/i18n"
import {
  cancelKimiDeviceFlow,
  fetchAuthorizedProviders,
  fetchProviderGroups,
  onboardKimiDeviceFlow,
  onboardSystemProvider,
  startKimiDeviceFlow,
  type AuthorizedProvider,
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
export function ProviderManagementPage({ managementAuthToken }: ProviderManagementPageProps) {
  const { t } = useI18n()
  // groups contains the authenticated management catalog returned by the core service.
  // groups 包含核心服务返回的已认证管理目录。
  const [groups, setGroups] = useState<ProviderGroup[]>([])
  // authorizedProviders contains only configured instances with at least one redacted credential.
  // authorizedProviders 仅包含至少拥有一个脱敏凭据的已配置实例。
  const [authorizedProviders, setAuthorizedProviders] = useState<AuthorizedProvider[]>([])
  // adding reports whether the explicit two-level provider creation workflow is open.
  // adding 表示显式的两级供应商新增流程是否打开。
  const [adding, setAdding] = useState(false)
  // searchQuery filters provider groups and exact variants during creation.
  // searchQuery 在新增期间过滤供应商分组与精确变体。
  const [searchQuery, setSearchQuery] = useState("")
  // expandedGroupID identifies the provider card whose exact variants are expanded in place.
  // expandedGroupID 标识在原位展开精确变体的供应商卡片。
  const [expandedGroupID, setExpandedGroupID] = useState("")
  // selectedDefinitionID identifies the exact site or product selected for subsequent onboarding.
  // selectedDefinitionID 标识为后续录入选择的精确站点或产品。
  const [selectedDefinitionID, setSelectedDefinitionID] = useState("")
  // loading reports whether the first authenticated catalog request is pending.
  // loading 表示首次已认证目录请求是否仍在等待。
  const [loading, setLoading] = useState(true)
  // catalogFailed reports whether provider creation metadata could not be loaded.
  // catalogFailed 表示供应商新增元数据是否加载失败。
  const [catalogFailed, setCatalogFailed] = useState(false)
  // authorizedFailed reports whether the configured authorization list could not be loaded.
  // authorizedFailed 表示已配置授权列表是否加载失败。
  const [authorizedFailed, setAuthorizedFailed] = useState(false)
  // refreshRevision invalidates the authorized list only after a successful onboarding commit.
  // refreshRevision 仅在录入提交成功后使已授权列表失效并重新加载。
  const [refreshRevision, setRefreshRevision] = useState(0)

  useEffect(() => {
    // controller cancels only this page-owned catalog request when the route unmounts.
    // controller 仅在路由卸载时取消此页面拥有的目录请求。
    const controller = new AbortController()
    setLoading(true)
    setCatalogFailed(false)
    setAuthorizedFailed(false)
    Promise.allSettled([
      fetchProviderGroups(managementAuthToken, controller.signal),
      fetchAuthorizedProviders(managementAuthToken, controller.signal),
    ]).then(([providerGroupsResult, configuredProvidersResult]) => {
      if (controller.signal.aborted) return
      if (providerGroupsResult.status === "fulfilled") {
        setGroups(providerGroupsResult.value)
      } else {
        setCatalogFailed(true)
      }
      if (configuredProvidersResult.status === "fulfilled") {
        setAuthorizedProviders(configuredProvidersResult.value)
      } else {
        setAuthorizedFailed(true)
      }
      setLoading(false)
    })
    return () => controller.abort()
  }, [managementAuthToken, refreshRevision])

  // selectedDefinition is the exact immutable variant passed to the onboarding command.
  // selectedDefinition 是传递给录入命令的精确不可变变体。
  const selectedDefinition = groups
    .flatMap((group) => group.provider_definitions)
    .find((definition) => definition.id === selectedDefinitionID)
  // normalizedSearch is compared only with locale-neutral provider identifiers and authored names.
  // normalizedSearch 仅与区域无关的供应商标识和编写名称比较。
  const normalizedSearch = searchQuery.trim().toLocaleLowerCase()
  // filteredGroups is the first-level creation list and retains groups with any matching variant.
  // filteredGroups 是第一级新增列表，并保留包含任一匹配变体的分组。
  const filteredGroups = groups.filter((group) => providerGroupMatches(group, normalizedSearch))
  // closeCreation resets every creation-only selection and safely unmounts any device flow.
  // closeCreation 重置所有仅用于新增的选择，并安全卸载任何设备授权流程。
  function closeCreation() {
    setAdding(false)
    setSearchQuery("")
    setExpandedGroupID("")
    setSelectedDefinitionID("")
  }

  // returnToProviderCatalog leaves configuration while preserving the expanded parent provider card.
  // returnToProviderCatalog 离开配置页面，同时保留已展开的上级供应商卡片。
  function returnToProviderCatalog() {
    setSelectedDefinitionID("")
  }

  // completeOnboarding returns to the authorized list and reloads committed server state.
  // completeOnboarding 返回已授权列表并重新加载已提交的服务端状态。
  function completeOnboarding() {
    closeCreation()
    setRefreshRevision((revision) => revision + 1)
  }

  return (
    <div className="flex flex-col gap-6 p-4 lg:p-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h2 className="text-2xl font-semibold tracking-tight">{t("providers.title")}</h2>
          <p className="text-muted-foreground mt-1 text-sm">{t("providers.authorizedDescription")}</p>
        </div>
        {!adding && !loading && !catalogFailed ? (
          <Button onClick={() => setAdding(true)}>
            <PlusIcon className="size-4" />
            {t("providers.add")}
          </Button>
        ) : null}
      </div>

      {loading ? <p className="text-muted-foreground text-sm">{t("providers.loading")}</p> : null}
      {!loading && catalogFailed ? (
        <p className="text-destructive text-sm">{t("providers.catalogLoadFailed")}</p>
      ) : null}
      {!loading && authorizedFailed ? (
        <p className="text-destructive text-sm">{t("providers.authorizedLoadFailed")}</p>
      ) : null}

      {!loading && !authorizedFailed ? (
        authorizedProviders.length > 0 ? (
          <div className="grid gap-4 lg:grid-cols-2">
            {authorizedProviders.map((provider) => (
              <AuthorizedProviderCard key={provider.instance.id} provider={provider} groups={groups} />
            ))}
          </div>
        ) : (
          <Card>
            <CardContent className="flex flex-col items-center gap-2 py-12 text-center">
              <ShieldCheckIcon className="text-muted-foreground size-8" />
              <p className="font-medium">{t("providers.noAuthorized")}</p>
            </CardContent>
          </Card>
        )
      ) : null}

      <Dialog
        open={adding}
        onOpenChange={(open) => {
          if (open) setAdding(true)
          else closeCreation()
        }}
      >
        {!catalogFailed ? (
          <DialogContent className="h-[min(80vh,600px)] max-h-[min(80vh,600px)] grid-rows-[auto_minmax(0,1fr)] overflow-hidden">
            <DialogHeader>
              {selectedDefinition ? (
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  aria-label={t("providers.backToProviders")}
                  onClick={returnToProviderCatalog}
                >
                  <ArrowLeftIcon className="size-4" />
                </Button>
              ) : null}
              <div className="min-w-0 flex-1">
                <DialogTitle>{selectedDefinition ? t("providers.configureProvider") : t("providers.add")}</DialogTitle>
                <DialogDescription>
                  {selectedDefinition ? selectedDefinition.display_name : t("providers.description")}
                </DialogDescription>
              </div>
              <DialogClose
                aria-label={t("providers.cancelAdd")}
                render={<Button type="button" variant="ghost" size="icon" />}
              >
                <XIcon className="size-4" />
              </DialogClose>
            </DialogHeader>

            {!selectedDefinition ? (
              <div className="grid min-h-0 grid-rows-[auto_minmax(0,1fr)] gap-5 pr-1">
                <div className="relative">
                  <SearchIcon className="text-muted-foreground absolute left-3 top-1/2 size-4 -translate-y-1/2" />
                  <Label className="sr-only" htmlFor="provider-filter">
                    {t("providers.search")}
                  </Label>
                  <Input
                    id="provider-filter"
                    className="pl-9"
                    value={searchQuery}
                    onChange={(event) => setSearchQuery(event.target.value)}
                    placeholder={t("providers.searchPlaceholder")}
                  />
                </div>
                <div className="min-h-0 overflow-y-auto border p-2">
                  {filteredGroups.length > 0 ? (
                    <div className="grid gap-2">
                      {filteredGroups.map((group) => (
                        <ProviderGroupSelectionCard
                          key={group.id}
                          group={group}
                          expanded={expandedGroupID === group.id}
                          normalizedSearch={normalizedSearch}
                          onToggle={() => setExpandedGroupID(expandedGroupID === group.id ? "" : group.id)}
                          onSelect={setSelectedDefinitionID}
                        />
                      ))}
                    </div>
                  ) : (
                    <p className="text-muted-foreground text-sm">{t("providers.noMatches")}</p>
                  )}
                </div>
              </div>
            ) : (
              <div className="min-h-0 overflow-y-auto pr-1">
                <ProviderOnboardingPanel
                  key={selectedDefinition.id}
                  definition={selectedDefinition}
                  managementAuthToken={managementAuthToken}
                  onComplete={completeOnboarding}
                />
              </div>
            )}
          </DialogContent>
        ) : null}
      </Dialog>
    </div>
  )
}

// providerIdentityMatches applies one normalized filter to a closed list of locale-neutral values.
// providerIdentityMatches 将一个规范化过滤条件应用到封闭的区域无关值列表。
function providerIdentityMatches(values: string[], normalizedSearch: string): boolean {
  return normalizedSearch === "" || values.some((value) => value.toLocaleLowerCase().includes(normalizedSearch))
}

// providerDefinitionMatches reports whether one exact site or plan matches the creation filter.
// providerDefinitionMatches 表示一个精确站点或套餐是否匹配新增过滤条件。
function providerDefinitionMatches(definition: ProviderDefinition, normalizedSearch: string): boolean {
  return providerIdentityMatches([definition.id, definition.display_name, definition.variant_name], normalizedSearch)
}

// providerGroupMatches retains a group when its identity or any exact variant matches the filter.
// providerGroupMatches 在分组身份或任一精确变体匹配过滤条件时保留该分组。
function providerGroupMatches(group: ProviderGroup, normalizedSearch: string): boolean {
  return (
    providerIdentityMatches([group.id, group.display_name], normalizedSearch) ||
    group.provider_definitions.some((definition) => providerDefinitionMatches(definition, normalizedSearch))
  )
}

// ProviderGroupSelectionCardProps defines inline expansion and exact-definition selection for one provider family.
// ProviderGroupSelectionCardProps 定义一个供应商系列的原位展开与精确定义选择行为。
interface ProviderGroupSelectionCardProps {
  // group contains the provider family and its exact selectable definitions.
  // group 包含供应商系列及其精确可选定义。
  group: ProviderGroup
  // expanded reports whether multiple variants are currently visible inside this card.
  // expanded 表示当前是否在此卡片内显示多个变体。
  expanded: boolean
  // normalizedSearch filters variants without changing their server-owned identities.
  // normalizedSearch 过滤变体且不改变其服务端拥有的身份。
  normalizedSearch: string
  // onToggle expands or collapses a provider that owns multiple variants.
  // onToggle 展开或折叠拥有多个变体的供应商。
  onToggle: () => void
  // onSelect opens configuration for one exact definition.
  // onSelect 为一个精确定义打开配置页面。
  onSelect: (definitionID: string) => void
}

// ProviderGroupSelectionCard directly configures a single-definition provider or expands multiple variants in place.
// ProviderGroupSelectionCard 直接配置单定义供应商，或在原位展开多个变体。
function ProviderGroupSelectionCard({
  group,
  expanded,
  normalizedSearch,
  onToggle,
  onSelect,
}: ProviderGroupSelectionCardProps) {
  // hasVariants distinguishes an actual choice from a provider with one directly configurable definition.
  // hasVariants 区分真实选择与只有一个可直接配置定义的供应商。
  const hasVariants = group.provider_definitions.length > 1
  // groupIdentityMatches keeps every variant visible when the filter matched the provider family itself.
  // groupIdentityMatches 在过滤条件匹配供应商系列本身时保留所有变体可见。
  const groupIdentityMatches = providerIdentityMatches([group.id, group.display_name], normalizedSearch)
  // visibleDefinitions retains only exact variant matches when the filter did not match the parent provider.
  // visibleDefinitions 在过滤条件未匹配上级供应商时仅保留精确变体匹配项。
  const visibleDefinitions = group.provider_definitions.filter(
    (definition) => groupIdentityMatches || providerDefinitionMatches(definition, normalizedSearch),
  )

  // activateProvider follows the exact definition count instead of inventing a separate provider mode.
  // activateProvider 按精确定义数量执行，不虚构额外供应商模式。
  function activateProvider() {
    if (group.provider_definitions.length === 1) {
      onSelect(group.provider_definitions[0].id)
      return
    }
    if (hasVariants) onToggle()
  }

  return (
    <Card className="gap-0 rounded-lg border py-0 shadow-none ring-0" data-provider-selection-card={group.id}>
      <CardHeader className="p-0">
        <button
          type="button"
          className="group flex min-h-16 w-full items-center gap-3 px-4 py-3 text-left outline-none transition-colors hover:bg-muted/50 focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50"
          disabled={group.provider_definitions.length === 0}
          aria-expanded={hasVariants ? expanded : undefined}
          onClick={activateProvider}
        >
          <span className="flex size-10 shrink-0 items-center justify-center rounded-lg bg-muted">
            <ServerIcon className="size-5" />
          </span>
          <span className="min-w-0 flex-1">
            <span className="block font-semibold">{group.display_name}</span>
            <span className="mt-1 flex flex-wrap gap-1.5">
              {group.provider_definitions.map((definition) => (
                <Badge key={definition.id} variant="default" className="rounded-sm">
                  {definition.variant_name}
                </Badge>
              ))}
            </span>
          </span>
          {hasVariants ? (
            expanded ? (
              <ChevronDownIcon className="text-muted-foreground size-4 transition-colors group-hover:text-foreground group-focus-visible:text-foreground" />
            ) : (
              <ChevronRightIcon className="text-muted-foreground size-4 transition-colors group-hover:text-foreground group-focus-visible:text-foreground" />
            )
          ) : (
            <ChevronRightIcon className="text-muted-foreground size-4 transition-colors group-hover:text-foreground group-focus-visible:text-foreground" />
          )}
        </button>
      </CardHeader>
      {hasVariants && expanded ? (
        <CardContent className="border-t p-0">
          <div className="grid">
            {visibleDefinitions.map((definition) => (
              <ProviderVariantRow key={definition.id} definition={definition} onSelect={onSelect} />
            ))}
          </div>
        </CardContent>
      ) : null}
    </Card>
  )
}

// AuthorizedProviderCardProps defines the data required by one configured-provider card.
// AuthorizedProviderCardProps 定义一个已配置供应商卡片所需的数据。
interface AuthorizedProviderCardProps {
  // provider joins the configured instance with its server-redacted credentials.
  // provider 将已配置实例与服务端脱敏凭据连接起来。
  provider: AuthorizedProvider
  // groups supplies exact definition-owned authentication metadata for display.
  // groups 提供用于显示的精确定义认证元数据。
  groups: ProviderGroup[]
}

// AuthorizedProviderCard renders one configured provider and its complete redacted authorization list.
// AuthorizedProviderCard 渲染一个已配置供应商及其完整脱敏授权列表。
function AuthorizedProviderCard({ provider, groups }: AuthorizedProviderCardProps) {
  const { t } = useI18n()
  const definition = groups
    .flatMap((group) => group.provider_definitions)
    .find((candidate) => candidate.id === provider.instance.definition_id)
  return (
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between gap-3">
          <div>
            <CardTitle>{provider.instance.display_name}</CardTitle>
            <CardDescription className="mt-1">
              {definition?.display_name ?? provider.instance.definition_id}
            </CardDescription>
          </div>
          <Badge variant="secondary">{providerStatusLabel(t, provider.instance.status)}</Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="text-muted-foreground text-xs">
          {t("providers.instanceHandle")}: <span className="text-foreground font-mono">{provider.instance.handle}</span>
        </div>
        <div>
          <h4 className="mb-2 text-sm font-medium">{t("providers.authorizations")}</h4>
          <ul className="divide-y rounded-md border">
            {provider.credentials.map((credential) => {
              const authMethod = definition?.auth_methods.find((method) => method.id === credential.auth_method_id)
              return (
                <li key={credential.id} className="flex items-center justify-between gap-3 px-3 py-3">
                  <div className="flex min-w-0 items-center gap-3">
                    {authMethod?.type === "device_flow" ? (
                      <ShieldCheckIcon className="text-muted-foreground size-4 shrink-0" />
                    ) : authMethod?.type === "api_key" ? (
                      <KeyRoundIcon className="text-muted-foreground size-4 shrink-0" />
                    ) : (
                      <ServerIcon className="text-muted-foreground size-4 shrink-0" />
                    )}
                    <div className="min-w-0">
                      <p className="truncate text-sm font-medium">{credential.label}</p>
                      <p className="text-muted-foreground text-xs">
                        {authorizationTypeLabel(t, authMethod?.type, credential.auth_method_id)}
                      </p>
                    </div>
                  </div>
                  <Badge variant="outline">{providerStatusLabel(t, credential.status)}</Badge>
                </li>
              )
            })}
          </ul>
        </div>
      </CardContent>
    </Card>
  )
}

// authorizationTypeLabel maps only definition-owned authentication types and otherwise preserves the exact method identifier.
// authorizationTypeLabel 仅映射定义拥有的认证类型，否则保留精确认证方式标识。
function authorizationTypeLabel(
  t: (key: TranslationKey) => string,
  authType: string | undefined,
  authMethodID: string,
): string {
  if (authType === "api_key") return t("providers.apiKey")
  if (authType === "device_flow") return t("providers.deviceFlow")
  return authMethodID
}

// providerStatusLabel localizes the complete lifecycle and credential status sets defined by providerconfig.
// providerStatusLabel 本地化 providerconfig 定义的完整生命周期与凭据状态集合。
function providerStatusLabel(t: (key: TranslationKey) => string, status: string): string {
  switch (status) {
    case "draft":
      return t("providers.status.draft")
    case "validating":
      return t("providers.status.validating")
    case "ready":
      return t("providers.status.ready")
    case "degraded":
      return t("providers.status.degraded")
    case "disabled":
      return t("providers.status.disabled")
    case "migration_required":
      return t("providers.status.migrationRequired")
    case "deleting":
      return t("providers.status.deleting")
    case "active":
      return t("providers.status.active")
    case "expired":
      return t("providers.status.expired")
    case "invalid":
      return t("providers.status.invalid")
    case "cooling":
      return t("providers.status.cooling")
    default:
      return status
  }
}

// ProviderVariantRowProps defines one exact selectable provider variant row.
// ProviderVariantRowProps 定义一个精确可选择的供应商变体行。
interface ProviderVariantRowProps {
  // definition contains one exact site or commercial product.
  // definition 包含一个精确站点或商业产品。
  definition: ProviderDefinition
  // onSelect records the immutable definition identifier without creating a runtime fallback.
  // onSelect 记录不可变定义标识且不创建运行时降级。
  onSelect: (definitionID: string) => void
}

// ProviderVariantRow renders one compact selectable row with description, base protocols, and a centered arrow.
// ProviderVariantRow 使用介绍、基础协议与居中箭头渲染一个紧凑的可选择行。
function ProviderVariantRow({ definition, onSelect }: ProviderVariantRowProps) {
  const { t } = useI18n()
  return (
    <button
      type="button"
      className="group grid w-full items-center gap-2 border-b bg-background px-3 py-2 text-left outline-none transition-colors last:border-b-0 hover:bg-muted/50 focus-visible:z-10 focus-visible:ring-2 focus-visible:ring-ring sm:grid-cols-[6.5rem_minmax(0,1fr)_auto]"
      aria-label={`${t("providers.select")} ${definition.variant_name}`}
      onClick={() => onSelect(definition.id)}
      data-provider-variant-row={definition.id}
    >
      <div className="font-semibold">{definition.variant_name}</div>
      <div className="min-w-0 space-y-1">
        <p className="text-sm leading-tight">
          {localizedDescription(t, definition.variant_description_key, definition.variant_description)}
        </p>
        <Badge variant="secondary" className="h-5 px-2 text-xs">
          {definition.protocol_profile_id}
        </Badge>
      </div>
      <ChevronRightIcon className="text-muted-foreground size-4 shrink-0 justify-self-end transition-colors group-hover:text-foreground group-focus-visible:text-foreground" />
    </button>
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
  // definition is the exact selected site or commercial plan.
  // definition 是精确选择的站点或商业套餐。
  definition: ProviderDefinition
  // managementAuthToken authenticates only the management-plane workflow.
  // managementAuthToken 仅认证管理面工作流。
  managementAuthToken: string
  // onComplete reloads the authorized list after the server commits onboarding.
  // onComplete 在服务端提交录入后重新加载已授权列表。
  onComplete: () => void
}

// ProviderOnboardingPanel performs API-key or server-confidential device-flow onboarding.
// ProviderOnboardingPanel 执行 API Key 或服务端保密设备授权录入。
function ProviderOnboardingPanel({ definition, managementAuthToken, onComplete }: ProviderOnboardingPanelProps) {
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
        provider_definition_id: definition.id,
        handle,
        display_name: displayName,
        auth_method_id: authMethodID,
        credential_label: credentialLabel,
        principal_key: "",
        secret,
      })
      setSecret("")
      onComplete()
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
        provider_definition_id: definition.id,
        handle,
        display_name: displayName,
        credential_label: credentialLabel,
        principal_key: "",
      })
      if (result === null) {
        setMessageKey("providers.authorizationPending")
      } else {
        deviceFlowRef.current = null
        setDeviceFlow(null)
        onComplete()
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
    // selectedAuthMethod comes from the exact definition-owned button and controls the default credential name.
    // selectedAuthMethod 来自精确定义拥有的按钮，并控制默认凭据名称。
    const selectedAuthMethod = definition.auth_methods.find((method) => method.id === methodID)
    if (!selectedAuthMethod) {
      setMessageKey("providers.unsupportedAuthentication")
      return
    }
    if (deviceFlowRef.current) {
      void cancelKimiDeviceFlow(managementAuthToken, deviceFlowRef.current.id).catch(() => undefined)
    }
    deviceFlowRef.current = null
    setAuthMethodID(methodID)
    setCredentialLabel(selectedAuthMethod.type === "device_flow" ? "Kimi User" : "Primary")
    setDeviceFlow(null)
    setSecret("")
    setMessageKey(null)
  }

  if (!authMethod || (authMethod.type !== "api_key" && authMethod.type !== "device_flow")) {
    return (
      <p className="text-destructive text-sm" role="alert">
        {t("providers.unsupportedAuthentication")}
      </p>
    )
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>{definition.display_name}</CardTitle>
        <CardDescription>
          {localizedDescription(t, definition.variant_description_key, definition.variant_description)}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form
          className="grid gap-4 md:grid-cols-2"
          onSubmit={isDeviceFlow ? (event) => event.preventDefault() : submitAPIKey}
        >
          {definition.auth_methods.length > 1 ? (
            <div className="flex gap-2 md:col-span-2">
              {definition.auth_methods.map((method) => (
                <Button
                  key={method.id}
                  type="button"
                  variant={authMethodID === method.id ? "default" : "outline"}
                  onClick={() => selectAuthMethod(method.id)}
                >
                  {method.type === "device_flow" ? t("providers.deviceFlow") : t("providers.apiKey")}
                </Button>
              ))}
            </div>
          ) : null}
          <div className="space-y-2">
            <Label htmlFor="provider-handle">{t("providers.handle")}</Label>
            <Input id="provider-handle" value={handle} onChange={(event) => setHandle(event.target.value)} required />
          </div>
          <div className="space-y-2">
            <Label htmlFor="provider-name">{t("providers.displayName")}</Label>
            <Input
              id="provider-name"
              value={displayName}
              onChange={(event) => setDisplayName(event.target.value)}
              required
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="credential-label">{t("providers.credentialLabel")}</Label>
            <Input
              id="credential-label"
              value={credentialLabel}
              onChange={(event) => setCredentialLabel(event.target.value)}
              required
            />
          </div>
          {!isDeviceFlow ? (
            <div className="space-y-2">
              <Label htmlFor="provider-secret">{t("providers.apiKey")}</Label>
              <Input
                id="provider-secret"
                type="password"
                value={secret}
                onChange={(event) => setSecret(event.target.value)}
                required
                autoComplete="off"
              />
            </div>
          ) : null}
          <div className="md:col-span-2">
            {!isDeviceFlow ? (
              <Button type="submit" disabled={pending}>
                {t("providers.onboard")}
              </Button>
            ) : deviceFlow ? (
              <div className="space-y-3">
                <p className="text-sm">
                  {t("providers.authorizationCode")}: <strong>{deviceFlow.user_code}</strong>
                </p>
                <a
                  className="text-primary text-sm underline"
                  href={deviceFlow.verification_uri_complete || deviceFlow.verification_uri}
                  target="_blank"
                  rel="noreferrer"
                >
                  {deviceFlow.verification_uri}
                </a>
                <div className="flex gap-2">
                  <Button type="button" disabled={pending} onClick={checkDeviceFlow}>
                    {t("providers.checkAuthorization")}
                  </Button>
                  <Button type="button" variant="outline" disabled={pending} onClick={cancelDeviceFlow}>
                    {t("providers.cancelAuthorization")}
                  </Button>
                </div>
              </div>
            ) : (
              <Button type="button" disabled={pending} onClick={beginDeviceFlow}>
                {t("providers.startAuthorization")}
              </Button>
            )}
          </div>
          {messageKey ? (
            <p className="md:col-span-2 text-sm" role="status">
              {t(messageKey)}
            </p>
          ) : null}
        </form>
      </CardContent>
    </Card>
  )
}
