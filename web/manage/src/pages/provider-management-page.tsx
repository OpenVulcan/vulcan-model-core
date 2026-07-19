import { type FormEvent, useEffect, useRef, useState } from "react";
import {
  ArrowLeftIcon,
  CableIcon,
  ChevronDownIcon,
  ChevronRightIcon,
  Globe2Icon,
  KeyRoundIcon,
  PlusIcon,
  RefreshCwIcon,
  SearchIcon,
  ServerIcon,
  ShieldCheckIcon,
  XIcon,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { type TranslationKey, useI18n } from "@/i18n";
import {
  cancelAntigravityOAuthFlow,
  cancelClaudeOAuthFlow,
  cancelCodexOAuthFlow,
  cancelKimiDeviceFlow,
  cancelCodexDeviceFlow,
  cancelXAIDeviceFlow,
  fetchAuthorizedProviders,
  fetchCustomProtocolProfiles,
  fetchProviderDefinitions,
  fetchProviderGroups,
  onboardAntigravityOAuthFlow,
  onboardClaudeOAuthFlow,
  onboardCodexOAuthFlow,
  onboardKimiDeviceFlow,
  onboardCodexDeviceFlow,
  onboardXAIDeviceFlow,
  onboardCustomProvider,
  onboardSystemProvider,
  onboardVertexServiceAccount,
  refreshProviderCredential,
  refreshProviderMetadata,
  startAntigravityOAuthFlow,
  startClaudeOAuthFlow,
  startCodexOAuthFlow,
  startKimiDeviceFlow,
  startCodexDeviceFlow,
  startXAIDeviceFlow,
  type AuthorizedProvider,
  type AntigravityOAuthFlow,
  type ClaudeOAuthFlow,
  type CodexOAuthFlow,
  type CustomProtocolProfile,
  type KimiDeviceFlow,
  type ProviderDefinitionIdentity,
  type ProviderDefinitionSummary,
  type ProviderDefinition,
  type ProviderAllowance,
  type ProviderAllowanceWindow,
  type ProviderCatalogMetadata,
  type ProviderGroup,
  ProviderCredentialRefreshError,
  ProviderMetadataRefreshError,
} from "@/lib/provider-groups";

// ProviderManagementPageProps defines the authenticated management credential used only for API reads.
// ProviderManagementPageProps 定义仅用于 API 读取的已认证管理凭证。
interface ProviderManagementPageProps {
  // managementAuthToken is the active in-memory management credential.
  // managementAuthToken 是当前内存管理凭证。
  managementAuthToken: string;
}

// ProviderManagementPage renders grouped system providers and exact site or plan selection.
// ProviderManagementPage 渲染已分组系统供应商及精确站点或套餐选择。
export function ProviderManagementPage({
  managementAuthToken,
}: ProviderManagementPageProps) {
  const { t } = useI18n();
  // groups contains the authenticated management catalog returned by the core service.
  // groups 包含核心服务返回的已认证管理目录。
  const [groups, setGroups] = useState<ProviderGroup[]>([]);
  // definitions contains the ungrouped identity inventory required to render user-owned custom providers.
  // definitions 包含渲染用户拥有自定义供应商所需的未分组身份清单。
  const [definitions, setDefinitions] = useState<ProviderDefinitionSummary[]>(
    [],
  );
  // customProtocolProfiles contains only server-whitelisted and runtime-ready compatibility factories.
  // customProtocolProfiles 仅包含服务端白名单且运行时就绪的兼容执行 Factory。
  const [customProtocolProfiles, setCustomProtocolProfiles] = useState<
    CustomProtocolProfile[]
  >([]);
  // authorizedProviders contains only configured instances with at least one redacted credential.
  // authorizedProviders 仅包含至少拥有一个脱敏凭据的已配置实例。
  const [authorizedProviders, setAuthorizedProviders] = useState<
    AuthorizedProvider[]
  >([]);
  // adding reports whether the explicit two-level provider creation workflow is open.
  // adding 表示显式的两级供应商新增流程是否打开。
  const [adding, setAdding] = useState(false);
  // searchQuery filters provider groups and exact variants during creation.
  // searchQuery 在新增期间过滤供应商分组与精确变体。
  const [searchQuery, setSearchQuery] = useState("");
  // expandedGroupID identifies the provider card whose exact variants are expanded in place.
  // expandedGroupID 标识在原位展开精确变体的供应商卡片。
  const [expandedGroupID, setExpandedGroupID] = useState("");
  // selectedDefinitionID identifies the exact site or product selected for subsequent onboarding.
  // selectedDefinitionID 标识为后续录入选择的精确站点或产品。
  const [selectedDefinitionID, setSelectedDefinitionID] = useState("");
  // configuringCustom reports whether the dialog is showing the dedicated custom-provider configuration step.
  // configuringCustom 表示 Dialog 是否正在显示专属自定义供应商配置步骤。
  const [configuringCustom, setConfiguringCustom] = useState(false);
  // loading reports whether the first authenticated catalog request is pending.
  // loading 表示首次已认证目录请求是否仍在等待。
  const [loading, setLoading] = useState(true);
  // catalogFailed reports whether provider creation metadata could not be loaded.
  // catalogFailed 表示供应商新增元数据是否加载失败。
  const [catalogFailed, setCatalogFailed] = useState(false);
  // customProtocolsFailed reports whether custom execution profile metadata could not be loaded.
  // customProtocolsFailed 表示自定义执行 Profile 元数据是否加载失败。
  const [customProtocolsFailed, setCustomProtocolsFailed] = useState(false);
  // authorizedFailed reports whether the configured authorization list could not be loaded.
  // authorizedFailed 表示已配置授权列表是否加载失败。
  const [authorizedFailed, setAuthorizedFailed] = useState(false);
  // refreshRevision invalidates the authorized list only after a successful onboarding commit.
  // refreshRevision 仅在录入提交成功后使已授权列表失效并重新加载。
  const [refreshRevision, setRefreshRevision] = useState(0);
  // providerMetadata stores only explicitly refreshed, management-safe account snapshots by instance.
  // providerMetadata 仅按实例存储显式刷新的管理安全账号快照。
  const [providerMetadata, setProviderMetadata] = useState<
    Record<string, ProviderCatalogMetadata>
  >({});
  // refreshingMetadataIDs identifies instances with an active provider-native metadata request.
  // refreshingMetadataIDs 标识正在执行供应商原生元数据请求的实例。
  const [refreshingMetadataIDs, setRefreshingMetadataIDs] = useState<
    Set<string>
  >(new Set());
  // metadataErrors stores the exact safe failure category from each instance's latest explicit refresh.
  // metadataErrors 存储每个实例最近一次显式刷新的精确安全失败分类。
  const [metadataErrors, setMetadataErrors] = useState<Record<string, string>>(
    {},
  );
  // refreshingCredentialIDs identifies account credentials with an active explicit token refresh.
  // refreshingCredentialIDs 标识正在执行显式 Token 刷新的账号凭据。
  const [refreshingCredentialIDs, setRefreshingCredentialIDs] = useState<
    Set<string>
  >(new Set());
  // credentialRefreshErrors records only safe local failure categories by immutable credential identifier.
  // credentialRefreshErrors 仅按不可变凭据标识记录安全的本地失败分类。
  const [credentialRefreshErrors, setCredentialRefreshErrors] = useState<
    Record<string, string>
  >({});

  useEffect(() => {
    // controller cancels only this page-owned catalog request when the route unmounts.
    // controller 仅在路由卸载时取消此页面拥有的目录请求。
    const controller = new AbortController();
    setLoading(true);
    setCatalogFailed(false);
    setAuthorizedFailed(false);
    setCustomProtocolsFailed(false);
    Promise.allSettled([
      fetchProviderGroups(managementAuthToken, controller.signal),
      fetchAuthorizedProviders(managementAuthToken, controller.signal),
      fetchProviderDefinitions(managementAuthToken, controller.signal),
      fetchCustomProtocolProfiles(managementAuthToken, controller.signal),
    ]).then(
      ([
        providerGroupsResult,
        configuredProvidersResult,
        providerDefinitionsResult,
        customProtocolProfilesResult,
      ]) => {
        if (controller.signal.aborted) return;
        if (providerGroupsResult.status === "fulfilled") {
          setGroups(providerGroupsResult.value);
        } else {
          setCatalogFailed(true);
        }
        if (configuredProvidersResult.status === "fulfilled") {
          setAuthorizedProviders(configuredProvidersResult.value);
        } else {
          setAuthorizedFailed(true);
        }
        if (providerDefinitionsResult.status === "fulfilled") {
          setDefinitions(providerDefinitionsResult.value);
        } else {
          setDefinitions([]);
          if (
            configuredProvidersResult.status === "fulfilled" &&
            configuredProvidersResult.value.some((provider) =>
              provider.instance.definition_id.startsWith("custom_"),
            )
          ) {
            setAuthorizedFailed(true);
          }
        }
        if (customProtocolProfilesResult.status === "fulfilled") {
          setCustomProtocolProfiles(customProtocolProfilesResult.value);
        } else {
          setCustomProtocolProfiles([]);
          setCustomProtocolsFailed(true);
        }
        setLoading(false);
      },
    );
    return () => controller.abort();
  }, [managementAuthToken, refreshRevision]);

  // selectedDefinition is the exact immutable variant passed to the onboarding command.
  // selectedDefinition 是传递给录入命令的精确不可变变体。
  const selectedDefinition = groups
    .flatMap((group) => group.provider_definitions)
    .find((definition) => definition.id === selectedDefinitionID);
  // normalizedSearch is compared only with locale-neutral provider identifiers and authored names.
  // normalizedSearch 仅与区域无关的供应商标识和编写名称比较。
  const normalizedSearch = searchQuery.trim().toLocaleLowerCase();
  // filteredGroups is the first-level creation list and retains groups with any matching variant.
  // filteredGroups 是第一级新增列表，并保留包含任一匹配变体的分组。
  const filteredGroups = groups.filter((group) =>
    providerGroupMatches(group, normalizedSearch),
  );
  // customProviderMatches keeps the dedicated custom entry inside the same provider filter semantics.
  // customProviderMatches 使专属自定义入口遵循相同的供应商过滤语义。
  const customProviderMatches = providerIdentityMatches(
    [
      "custom",
      "custom provider",
      t("providers.customProvider"),
      "openai chat",
      "vertex compatibility",
    ],
    normalizedSearch,
  );
  // closeCreation resets every creation-only selection and safely unmounts any device flow.
  // closeCreation 重置所有仅用于新增的选择，并安全卸载任何设备授权流程。
  function closeCreation() {
    setAdding(false);
    setSearchQuery("");
    setExpandedGroupID("");
    setSelectedDefinitionID("");
    setConfiguringCustom(false);
  }

  // returnToProviderCatalog leaves configuration while preserving the expanded parent provider card.
  // returnToProviderCatalog 离开配置页面，同时保留已展开的上级供应商卡片。
  function returnToProviderCatalog() {
    setSelectedDefinitionID("");
    setConfiguringCustom(false);
  }

  // completeOnboarding returns to the authorized list and reloads committed server state.
  // completeOnboarding 返回已授权列表并重新加载已提交的服务端状态。
  function completeOnboarding() {
    closeCreation();
    setRefreshRevision((revision) => revision + 1);
  }

  // refreshAccountMetadata reads provider-native plan and allowance data without exposing account secrets.
  // refreshAccountMetadata 读取供应商原生套餐与额度数据，且不暴露账号秘密。
  async function refreshAccountMetadata(providerInstanceID: string) {
    setRefreshingMetadataIDs((current) =>
      new Set(current).add(providerInstanceID),
    );
    setMetadataErrors((current) => {
      const next = { ...current };
      delete next[providerInstanceID];
      return next;
    });
    try {
      const metadata = await refreshProviderMetadata(
        managementAuthToken,
        providerInstanceID,
      );
      setProviderMetadata((current) => ({
        ...current,
        [providerInstanceID]: metadata,
      }));
    } catch (error) {
      const errorCode =
        error instanceof ProviderMetadataRefreshError
          ? error.code
          : "provider_metadata_network_failed";
      setMetadataErrors((current) => ({
        ...current,
        [providerInstanceID]: errorCode,
      }));
    } finally {
      setRefreshingMetadataIDs((current) => {
        const next = new Set(current);
        next.delete(providerInstanceID);
        return next;
      });
    }
  }

  // refreshAccountCredential explicitly rotates one refreshable provider token and reloads its redacted persisted metadata.
  // refreshAccountCredential 显式轮换一个可刷新的供应商 Token，并重新加载其脱敏持久化元数据。
  async function refreshAccountCredential(
    providerInstanceID: string,
    credentialID: string,
  ) {
    setRefreshingCredentialIDs((current) => new Set(current).add(credentialID));
    setCredentialRefreshErrors((current) => {
      const next = { ...current };
      delete next[credentialID];
      return next;
    });
    try {
      await refreshProviderCredential(
        managementAuthToken,
        providerInstanceID,
        credentialID,
      );
      setProviderMetadata((current) => {
        const next = { ...current };
        delete next[providerInstanceID];
        return next;
      });
      setRefreshRevision((revision) => revision + 1);
    } catch (error) {
      const errorCode =
        error instanceof ProviderCredentialRefreshError
          ? error.code
          : "provider_authentication_network_failed";
      setCredentialRefreshErrors((current) => ({
        ...current,
        [credentialID]: errorCode,
      }));
    } finally {
      setRefreshingCredentialIDs((current) => {
        const next = new Set(current);
        next.delete(credentialID);
        return next;
      });
    }
  }

  return (
    <div className="flex flex-col gap-6 p-4 lg:p-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h2 className="text-2xl font-semibold tracking-tight">
            {t("providers.title")}
          </h2>
          <p className="text-muted-foreground mt-1 text-sm">
            {t("providers.authorizedDescription")}
          </p>
        </div>
        {!adding && !loading && !catalogFailed ? (
          <Button onClick={() => setAdding(true)}>
            <PlusIcon className="size-4" />
            {t("providers.add")}
          </Button>
        ) : null}
      </div>

      {loading ? (
        <p className="text-muted-foreground text-sm">
          {t("providers.loading")}
        </p>
      ) : null}
      {!loading && catalogFailed ? (
        <p className="text-destructive text-sm">
          {t("providers.catalogLoadFailed")}
        </p>
      ) : null}
      {!loading && authorizedFailed ? (
        <p className="text-destructive text-sm">
          {t("providers.authorizedLoadFailed")}
        </p>
      ) : null}

      {!loading && !authorizedFailed ? (
        authorizedProviders.length > 0 ? (
          <div className="grid gap-4 lg:grid-cols-2">
            {authorizedProviders.map((provider) => (
              <AuthorizedProviderCard
                key={provider.instance.id}
                provider={provider}
                definition={
                  definitions.find(
                    (candidate) =>
                      candidate.id === provider.instance.definition_id,
                  ) ??
                  groups
                    .flatMap((group) => group.provider_definitions)
                    .find(
                      (candidate) =>
                        candidate.id === provider.instance.definition_id,
                    )
                }
                metadata={providerMetadata[provider.instance.id]}
                refreshingMetadata={refreshingMetadataIDs.has(
                  provider.instance.id,
                )}
                metadataErrorCode={metadataErrors[provider.instance.id]}
                onRefreshMetadata={refreshAccountMetadata}
                refreshingCredentialIDs={refreshingCredentialIDs}
                credentialRefreshErrors={credentialRefreshErrors}
                onRefreshCredential={refreshAccountCredential}
              />
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
          if (open) setAdding(true);
          else closeCreation();
        }}
      >
        {!catalogFailed ? (
          <DialogContent className="h-[min(80vh,600px)] max-h-[min(80vh,600px)] grid-rows-[auto_minmax(0,1fr)] overflow-hidden">
            <DialogHeader>
              {selectedDefinition || configuringCustom ? (
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
                <DialogTitle>
                  {selectedDefinition || configuringCustom
                    ? t("providers.configureProvider")
                    : t("providers.add")}
                </DialogTitle>
                <DialogDescription>
                  {selectedDefinition
                    ? selectedDefinition.display_name
                    : configuringCustom
                      ? t("providers.customDescription")
                      : t("providers.description")}
                </DialogDescription>
              </div>
              <DialogClose
                aria-label={t("providers.cancelAdd")}
                render={<Button type="button" variant="ghost" size="icon" />}
              >
                <XIcon className="size-4" />
              </DialogClose>
            </DialogHeader>

            {!selectedDefinition && !configuringCustom ? (
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
                  {customProviderMatches || filteredGroups.length > 0 ? (
                    <div className="grid gap-2">
                      {customProviderMatches ? (
                        <CustomProviderSelectionCard
                          onSelect={() => setConfiguringCustom(true)}
                        />
                      ) : null}
                      {filteredGroups.map((group) => (
                        <ProviderGroupSelectionCard
                          key={group.id}
                          group={group}
                          expanded={expandedGroupID === group.id}
                          normalizedSearch={normalizedSearch}
                          onToggle={() =>
                            setExpandedGroupID(
                              expandedGroupID === group.id ? "" : group.id,
                            )
                          }
                          onSelect={setSelectedDefinitionID}
                        />
                      ))}
                    </div>
                  ) : (
                    <p className="text-muted-foreground text-sm">
                      {t("providers.noMatches")}
                    </p>
                  )}
                </div>
              </div>
            ) : (
              <div className="min-h-0 overflow-y-auto pr-1">
                {configuringCustom ? (
                  <CustomProviderOnboardingPanel
                    managementAuthToken={managementAuthToken}
                    profiles={customProtocolProfiles}
                    profilesFailed={customProtocolsFailed}
                    onComplete={completeOnboarding}
                  />
                ) : selectedDefinition ? (
                  <ProviderOnboardingPanel
                    key={selectedDefinition.id}
                    definition={selectedDefinition}
                    managementAuthToken={managementAuthToken}
                    onComplete={completeOnboarding}
                  />
                ) : null}
              </div>
            )}
          </DialogContent>
        ) : null}
      </Dialog>
    </div>
  );
}

// providerIdentityMatches applies one normalized filter to a closed list of locale-neutral values.
// providerIdentityMatches 将一个规范化过滤条件应用到封闭的区域无关值列表。
function providerIdentityMatches(
  values: string[],
  normalizedSearch: string,
): boolean {
  return (
    normalizedSearch === "" ||
    values.some((value) => value.toLocaleLowerCase().includes(normalizedSearch))
  );
}

// providerDefinitionMatches reports whether one exact site or plan matches the creation filter.
// providerDefinitionMatches 表示一个精确站点或套餐是否匹配新增过滤条件。
function providerDefinitionMatches(
  definition: ProviderDefinition,
  normalizedSearch: string,
): boolean {
  return providerIdentityMatches(
    [definition.id, definition.display_name, definition.variant_name],
    normalizedSearch,
  );
}

// providerGroupMatches retains a group when its identity or any exact variant matches the filter.
// providerGroupMatches 在分组身份或任一精确变体匹配过滤条件时保留该分组。
function providerGroupMatches(
  group: ProviderGroup,
  normalizedSearch: string,
): boolean {
  return (
    providerIdentityMatches([group.id, group.display_name], normalizedSearch) ||
    group.provider_definitions.some((definition) =>
      providerDefinitionMatches(definition, normalizedSearch),
    )
  );
}

// CustomProviderSelectionCardProps defines the direct custom-provider entry inside the shared catalog dialog.
// CustomProviderSelectionCardProps 定义共享目录 Dialog 内的直接自定义供应商入口。
interface CustomProviderSelectionCardProps {
  // onSelect opens the dedicated custom compatibility configuration step.
  // onSelect 打开专属自定义兼容配置步骤。
  onSelect: () => void;
}

// CustomProviderSelectionCard renders one compact full-width action for user-owned compatibility endpoints.
// CustomProviderSelectionCard 为用户拥有的兼容 Endpoint 渲染一个紧凑全宽操作项。
function CustomProviderSelectionCard({
  onSelect,
}: CustomProviderSelectionCardProps) {
  const { t } = useI18n();
  return (
    <Card
      className="gap-0 rounded-lg border py-0 shadow-none ring-0"
      data-provider-selection-card="custom"
    >
      <CardHeader className="p-0">
        <button
          type="button"
          className="group flex min-h-16 w-full items-center gap-3 px-4 py-3 text-left outline-none transition-colors hover:bg-muted/50 focus-visible:ring-2 focus-visible:ring-ring"
          onClick={onSelect}
        >
          <span className="flex size-10 shrink-0 items-center justify-center rounded-lg bg-muted">
            <CableIcon className="size-5" />
          </span>
          <span className="min-w-0 flex-1">
            <span className="block font-semibold">
              {t("providers.customProvider")}
            </span>
            <span className="text-muted-foreground mt-0.5 block text-xs">
              {t("providers.customCardDescription")}
            </span>
          </span>
          <ChevronRightIcon className="text-muted-foreground size-4 transition-colors group-hover:text-foreground group-focus-visible:text-foreground" />
        </button>
      </CardHeader>
    </Card>
  );
}

// ProviderGroupSelectionCardProps defines inline expansion and exact-definition selection for one provider family.
// ProviderGroupSelectionCardProps 定义一个供应商系列的原位展开与精确定义选择行为。
interface ProviderGroupSelectionCardProps {
  // group contains the provider family and its exact selectable definitions.
  // group 包含供应商系列及其精确可选定义。
  group: ProviderGroup;
  // expanded reports whether multiple variants are currently visible inside this card.
  // expanded 表示当前是否在此卡片内显示多个变体。
  expanded: boolean;
  // normalizedSearch filters variants without changing their server-owned identities.
  // normalizedSearch 过滤变体且不改变其服务端拥有的身份。
  normalizedSearch: string;
  // onToggle expands or collapses a provider that owns multiple variants.
  // onToggle 展开或折叠拥有多个变体的供应商。
  onToggle: () => void;
  // onSelect opens configuration for one exact definition.
  // onSelect 为一个精确定义打开配置页面。
  onSelect: (definitionID: string) => void;
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
  const hasVariants = group.provider_definitions.length > 1;
  // groupIdentityMatches keeps every variant visible when the filter matched the provider family itself.
  // groupIdentityMatches 在过滤条件匹配供应商系列本身时保留所有变体可见。
  const groupIdentityMatches = providerIdentityMatches(
    [group.id, group.display_name],
    normalizedSearch,
  );
  // visibleDefinitions retains only exact variant matches when the filter did not match the parent provider.
  // visibleDefinitions 在过滤条件未匹配上级供应商时仅保留精确变体匹配项。
  const visibleDefinitions = group.provider_definitions.filter(
    (definition) =>
      groupIdentityMatches ||
      providerDefinitionMatches(definition, normalizedSearch),
  );
  // badges condenses commercial-plan families without hiding the exact choices shown after expansion.
  // badges 在不隐藏展开后精确选项的前提下压缩商业套餐系列标签。
  const badges = providerGroupBadges(group);

  // activateProvider follows the exact definition count instead of inventing a separate provider mode.
  // activateProvider 按精确定义数量执行，不虚构额外供应商模式。
  function activateProvider() {
    if (group.provider_definitions.length === 1) {
      onSelect(group.provider_definitions[0].id);
      return;
    }
    if (hasVariants) onToggle();
  }

  return (
    <Card
      className="gap-0 rounded-lg border py-0 shadow-none ring-0"
      data-provider-selection-card={group.id}
    >
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
              {badges.map((badge) => (
                <Badge
                  key={badge}
                  variant="default"
                  className="rounded-sm"
                >
                  {badge}
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
              <ProviderVariantRow
                key={definition.id}
                definition={definition}
                onSelect={onSelect}
              />
            ))}
          </div>
        </CardContent>
      ) : null}
    </Card>
  );
}

// providerGroupBadges returns concise family badges while preserving generic variant labels for every other provider.
// providerGroupBadges 为 Alibaba 返回简洁系列标签，并为其他供应商保留通用变体标签。
function providerGroupBadges(group: ProviderGroup): string[] {
  if (group.id === "alibaba") return ["Coding Plan", "Token Plan"];
  return group.provider_definitions.map((definition) => definition.variant_name);
}

// AuthorizedProviderCardProps defines the data required by one configured-provider card.
// AuthorizedProviderCardProps 定义一个已配置供应商卡片所需的数据。
interface AuthorizedProviderCardProps {
  // provider joins the configured instance with its server-redacted credentials.
  // provider 将已配置实例与服务端脱敏凭据连接起来。
  provider: AuthorizedProvider;
  // definition supplies exact system or custom authentication metadata when the inventory contains the instance owner.
  // definition 在清单包含实例所有者时提供精确系统或自定义认证元数据。
  definition?: ProviderDefinitionIdentity;
  // metadata is the latest explicit provider-native account snapshot.
  // metadata 是最近一次显式获取的供应商原生账号快照。
  metadata?: ProviderCatalogMetadata;
  // refreshingMetadata reports an active metadata refresh for this exact instance.
  // refreshingMetadata 表示此精确实例正在刷新元数据。
  refreshingMetadata: boolean;
  // metadataErrorCode is the latest server-authored or browser-network failure category.
  // metadataErrorCode 是最近一次服务端给出或浏览器网络失败的分类。
  metadataErrorCode?: string;
  // onRefreshMetadata requests metadata only for the immutable instance identifier.
  // onRefreshMetadata 仅针对不可变实例标识请求元数据。
  onRefreshMetadata: (providerInstanceID: string) => void;
  // refreshingCredentialIDs identifies exact credentials currently refreshing.
  // refreshingCredentialIDs 标识当前正在刷新的精确凭据。
  refreshingCredentialIDs: ReadonlySet<string>;
  // credentialRefreshErrors contains safe failures keyed by credential identifier.
  // credentialRefreshErrors 包含按凭据标识索引的安全失败。
  credentialRefreshErrors: Readonly<Record<string, string>>;
  // onRefreshCredential requests one exact credential refresh within its immutable provider instance.
  // onRefreshCredential 在不可变供应商实例内请求一个精确凭据刷新。
  onRefreshCredential: (
    providerInstanceID: string,
    credentialID: string,
  ) => void;
}

// AuthorizedProviderCard renders one configured provider and its complete redacted authorization list.
// AuthorizedProviderCard 渲染一个已配置供应商及其完整脱敏授权列表。
function AuthorizedProviderCard({
  provider,
  definition,
  metadata,
  refreshingMetadata,
  metadataErrorCode,
  onRefreshMetadata,
  refreshingCredentialIDs,
  credentialRefreshErrors,
  onRefreshCredential,
}: AuthorizedProviderCardProps) {
  const { t } = useI18n();
  // accountMetadataStatuses is the complete server-authored capability state set relevant to account refresh.
  // accountMetadataStatuses 是与账号刷新相关的完整服务端能力状态集合。
  const accountMetadataStatuses = [
    definition?.features.model_discovery,
    definition?.features.plan_reader,
    definition?.features.entitlement_reader,
    definition?.features.allowance_reader,
  ];
  // supportsAccountMetadata follows only the server-authored feature contract for this definition.
  // supportsAccountMetadata 仅遵循此定义的服务端编写功能合同。
  const supportsAccountMetadata = accountMetadataStatuses.includes("supported");
  // accountMetadataTemporarilyUnavailable distinguishes an implemented but unavailable reader from explicit non-support.
  // accountMetadataTemporarilyUnavailable 区分已实现但暂不可用的读取器与明确不支持。
  const accountMetadataTemporarilyUnavailable =
    !supportsAccountMetadata &&
    accountMetadataStatuses.includes("temporarily_unavailable");
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
          <Badge variant="secondary">
            {providerStatusLabel(t, provider.instance.status)}
          </Badge>
          {supportsAccountMetadata ? (
            <Button
              type="button"
              variant="outline"
              size="sm"
              disabled={refreshingMetadata}
              onClick={() => onRefreshMetadata(provider.instance.id)}
            >
              <RefreshCwIcon
                className={`size-3.5 ${refreshingMetadata ? "animate-spin" : ""}`}
              />
              {refreshingMetadata
                ? t("providers.refreshingMetadata")
                : t("providers.refreshMetadata")}
            </Button>
          ) : null}
        </div>
        {!supportsAccountMetadata ? (
          <p className="text-muted-foreground text-xs">
            {t(
              accountMetadataTemporarilyUnavailable
                ? "providers.metadataTemporarilyUnavailable"
                : "providers.metadataUnsupported",
            )}
          </p>
        ) : null}
        {metadataErrorCode ? (
          <p className="text-destructive text-sm" role="status">
            {metadataRefreshErrorLabel(t, metadataErrorCode)}
          </p>
        ) : null}
        {metadata?.models.length ? (
          <div>
            <h4 className="mb-2 text-sm font-medium">
              {t("providers.models")}
            </h4>
            <ul className="divide-y rounded-md border">
              {metadata.models.map((model) => (
                <li
                  key={model.id}
                  className="flex items-center justify-between gap-3 px-3 py-2 text-sm"
                >
                  <div className="min-w-0">
                    <p className="truncate font-medium">{model.display_name}</p>
                    <p className="text-muted-foreground truncate font-mono text-xs">
                      {model.upstream_model_id}
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    {model.entitlement_mode === "explicit" ? (
                      <Badge variant="outline">
                        {model.provider_authorized
                          ? t("providers.modelAuthorized")
                          : t("providers.modelUnauthorized")}
                      </Badge>
                    ) : null}
                    <Badge variant="outline">
                      {model.enabled
                        ? t("providers.modelEnabled")
                        : t("providers.modelDisabled")}
                    </Badge>
                  </div>
                </li>
              ))}
            </ul>
          </div>
        ) : null}
        {metadata?.plans.length ? (
          <div>
            <h4 className="mb-2 text-sm font-medium">{t("providers.plans")}</h4>
            <ul className="divide-y rounded-md border">
              {metadata.plans.map((plan) => (
                <li
                  key={`${plan.plan_code}\u0000${plan.plan_name}\u0000${plan.status}`}
                  className="flex items-center justify-between gap-3 px-3 py-2 text-sm"
                >
                  <span>{plan.plan_name || plan.plan_code}</span>
                  <Badge variant="outline">{plan.status}</Badge>
                </li>
              ))}
            </ul>
          </div>
        ) : null}
        {metadata?.allowances.length ? (
          <div>
            <h4 className="mb-2 text-sm font-medium">
              {t("providers.allowances")}
            </h4>
            <ul className="divide-y rounded-md border">
              {metadata.allowances.map((allowance, allowanceIndex) => (
                <li
                  key={`${allowance.kind}\u0000${allowance.metric}\u0000${allowance.scope}\u0000${allowanceIndex}`}
                  className="space-y-1 px-3 py-2 text-sm"
                >
                  <div className="flex items-center justify-between gap-3">
                    <span className="font-medium">{allowance.metric}</span>
                    <Badge variant="outline">{allowance.status}</Badge>
                  </div>
                  <p className="text-muted-foreground text-xs">
                    {allowance.remaining !== undefined
                      ? `${t("providers.remaining")}: ${allowance.remaining} ${allowanceDisplayUnit(allowance)}`
                      : null}
                    {allowance.remaining === undefined &&
                    allowance.remaining_ratio !== undefined
                      ? `${t("providers.remainingRatio")}: ${allowance.remaining_ratio * 100}%`
                      : null}
                    {allowance.used !== undefined
                      ? ` · ${t("providers.used")}: ${allowance.used}`
                      : null}
                    {allowance.limit !== undefined
                      ? ` · ${t("providers.limit")}: ${allowance.limit}`
                      : null}
                  </p>
                  {allowance.window ? (
                    <p className="text-muted-foreground text-xs">
                      {t("providers.window")}:{" "}
                      {allowanceWindowLabel(allowance.window)}
                      {allowance.window.reset_at
                        ? ` · ${t("providers.resetAt")}: ${allowance.window.reset_at}`
                        : null}
                    </p>
                  ) : null}
                </li>
              ))}
            </ul>
          </div>
        ) : null}
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="text-muted-foreground text-xs">
          {t("providers.instanceHandle")}:{" "}
          <span className="text-foreground font-mono">
            {provider.instance.handle}
          </span>
        </div>
        <div>
          <h4 className="mb-2 text-sm font-medium">
            {t("providers.authorizations")}
          </h4>
          <ul className="divide-y rounded-md border">
            {provider.credentials.map((credential) => {
              const authMethod = definition?.auth_methods.find(
                (method) => method.id === credential.auth_method_id,
              );
              return (
                <li key={credential.id} className="space-y-2 px-3 py-3">
                  <div className="flex items-center justify-between gap-3">
                    <div className="flex min-w-0 items-center gap-3">
                      {authMethod?.type === "device_flow" ? (
                        <ShieldCheckIcon className="text-muted-foreground size-4 shrink-0" />
                      ) : authMethod?.type === "api_key" ||
                        authMethod?.type === "bearer" ||
                        authMethod?.type === "header_api_key" ? (
                        <KeyRoundIcon className="text-muted-foreground size-4 shrink-0" />
                      ) : (
                        <ServerIcon className="text-muted-foreground size-4 shrink-0" />
                      )}
                      <div className="min-w-0">
                        <p className="truncate text-sm font-medium">
                          {credential.label}
                        </p>
                        <p className="text-muted-foreground text-xs">
                          {authorizationTypeLabel(
                            t,
                            authMethod?.type,
                            credential.auth_method_id,
                          )}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {authMethod?.refreshable ? (
                        <Button
                          type="button"
                          variant="outline"
                          size="sm"
                          disabled={refreshingCredentialIDs.has(credential.id)}
                          onClick={() =>
                            onRefreshCredential(
                              provider.instance.id,
                              credential.id,
                            )
                          }
                        >
                          <RefreshCwIcon
                            className={`size-3.5 ${refreshingCredentialIDs.has(credential.id) ? "animate-spin" : ""}`}
                          />
                          {refreshingCredentialIDs.has(credential.id)
                            ? t("providers.refreshingCredential")
                            : t("providers.refreshCredential")}
                        </Button>
                      ) : null}
                      <Badge variant="outline">
                        {providerStatusLabel(t, credential.status)}
                      </Badge>
                    </div>
                  </div>
                  {credentialRefreshErrors[credential.id] ? (
                    <p className="text-destructive text-xs" role="status">
                      {credentialRefreshErrorLabel(
                        t,
                        credentialRefreshErrors[credential.id],
                      )}
                    </p>
                  ) : null}
                </li>
              );
            })}
          </ul>
        </div>
      </CardContent>
    </Card>
  );
}

// authorizationTypeLabel maps only definition-owned authentication types and otherwise preserves the exact method identifier.
// authorizationTypeLabel 仅映射定义拥有的认证类型，否则保留精确认证方式标识。
function authorizationTypeLabel(
  t: (key: TranslationKey) => string,
  authType: string | undefined,
  authMethodID: string,
): string {
  if (authType === "api_key") return t("providers.apiKey");
  if (authType === "bearer") return "Bearer";
  if (authType === "header_api_key") return "x-goog-api-key";
  if (authType === "device_flow") return t("providers.deviceFlow");
  if (authType === "oauth") return t("providers.oauth");
  if (authType === "service_account") return t("providers.serviceAccount");
  return authMethodID;
}

// allowanceDisplayUnit returns the exact ISO currency for monetary values and otherwise preserves the normalized accounting unit.
// allowanceDisplayUnit 为金额返回精确 ISO 货币，否则保留规范化计量单位。
function allowanceDisplayUnit(allowance: ProviderAllowance): string {
  return allowance.currency ?? allowance.unit;
}

// allowanceWindowLabel preserves provider-authored window kind, duration, calendar unit, and time zone in one compact label.
// allowanceWindowLabel 在一个紧凑标签中保留供应商编写的窗口类型、时长、日历单位和时区。
function allowanceWindowLabel(window: ProviderAllowanceWindow): string {
  // parts retains only window nodes that are present in the validated management response.
  // parts 仅保留已校验管理响应中实际存在的窗口节点。
  const parts = [window.kind];
  if (window.duration !== "0") parts.push(`${window.duration} ns`);
  if (window.calendar_unit) parts.push(window.calendar_unit);
  if (window.time_zone) parts.push(window.time_zone);
  return parts.join(" · ");
}

// metadataRefreshErrorLabel maps stable metadata failure categories to actionable localized feedback.
// metadataRefreshErrorLabel 将稳定的元数据失败分类映射为可操作的本地化反馈。
function metadataRefreshErrorLabel(
  t: (key: TranslationKey) => string,
  errorCode: string,
): string {
  switch (errorCode) {
    case "provider_metadata_authentication_failed":
      return t("providers.metadataAuthenticationFailed");
    case "provider_metadata_unavailable":
    case "provider_metadata_network_failed":
      return t("providers.metadataUnavailable");
    case "provider_metadata_invalid_response":
      return t("providers.metadataInvalidResponse");
    default:
      return t("providers.metadataRefreshFailed");
  }
}

// credentialRefreshErrorLabel maps stable authentication failures to retry-safe localized guidance.
// credentialRefreshErrorLabel 将稳定认证失败映射为可安全重试的本地化指引。
function credentialRefreshErrorLabel(
  t: (key: TranslationKey) => string,
  errorCode: string,
): string {
  switch (errorCode) {
    case "provider_authentication_rejected":
      return t("providers.credentialAuthenticationRejected");
    case "provider_authentication_unavailable":
    case "provider_authentication_network_failed":
      return t("providers.credentialAuthenticationUnavailable");
    case "provider_authentication_invalid_response":
      return t("providers.credentialAuthenticationInvalidResponse");
    default:
      return t("providers.credentialRefreshFailed");
  }
}

// providerStatusLabel localizes the complete lifecycle and credential status sets defined by providerconfig.
// providerStatusLabel 本地化 providerconfig 定义的完整生命周期与凭据状态集合。
function providerStatusLabel(
  t: (key: TranslationKey) => string,
  status: string,
): string {
  switch (status) {
    case "draft":
      return t("providers.status.draft");
    case "validating":
      return t("providers.status.validating");
    case "ready":
      return t("providers.status.ready");
    case "degraded":
      return t("providers.status.degraded");
    case "disabled":
      return t("providers.status.disabled");
    case "migration_required":
      return t("providers.status.migrationRequired");
    case "deleting":
      return t("providers.status.deleting");
    case "active":
      return t("providers.status.active");
    case "expired":
      return t("providers.status.expired");
    case "invalid":
      return t("providers.status.invalid");
    case "cooling":
      return t("providers.status.cooling");
    default:
      return status;
  }
}

// ProviderVariantRowProps defines one exact selectable provider variant row.
// ProviderVariantRowProps 定义一个精确可选择的供应商变体行。
interface ProviderVariantRowProps {
  // definition contains one exact site or commercial product.
  // definition 包含一个精确站点或商业产品。
  definition: ProviderDefinition;
  // onSelect records the immutable definition identifier without creating a runtime fallback.
  // onSelect 记录不可变定义标识且不创建运行时降级。
  onSelect: (definitionID: string) => void;
}

// ProviderVariantRow renders one compact selectable row with its direct protocol, endpoint addresses, and centered arrow.
// ProviderVariantRow 使用直接协议、端点地址与居中箭头渲染一个紧凑的可选择行。
function ProviderVariantRow({ definition, onSelect }: ProviderVariantRowProps) {
  const { t } = useI18n();
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
          {localizedDescription(
            t,
            definition.variant_description_key,
            definition.variant_description,
          )}
        </p>
        <div className="text-muted-foreground flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1 text-xs">
          <span className="flex items-center gap-1.5">
            <CableIcon className="size-3.5 shrink-0" aria-hidden="true" />
            <Badge variant="secondary" className="h-5 px-2 text-xs">
              {definition.protocol_profile_id}
            </Badge>
          </span>
          {definition.endpoint_presets.map((endpoint) => (
            <span
              key={endpoint.id}
              className="flex min-w-0 items-center gap-1.5"
              data-provider-endpoint={endpoint.id}
            >
              <Globe2Icon className="size-3.5 shrink-0" aria-hidden="true" />
              <span className="truncate">{endpoint.base_url}</span>
            </span>
          ))}
        </div>
      </div>
      <ChevronRightIcon className="text-muted-foreground size-4 shrink-0 justify-self-end transition-colors group-hover:text-foreground group-focus-visible:text-foreground" />
    </button>
  );
}

// localizedDescription resolves only server-authored localization keys and preserves a safe English fallback.
// localizedDescription 仅解析服务端编写的本地化键并保留安全英文回退。
function localizedDescription(
  t: (key: TranslationKey) => string,
  key: string | undefined,
  fallback: string,
): string {
  switch (key) {
    case "providers.kimi.description":
    case "providers.kimi.cnDescription":
    case "providers.kimi.globalDescription":
    case "providers.kimi.codingDescription":
    case "providers.alibaba.description":
    case "providers.alibaba.codingPlanCNDescription":
    case "providers.alibaba.codingPlanGlobalDescription":
    case "providers.alibaba.tokenPlanPersonalCNDescription":
    case "providers.alibaba.tokenPlanTeamCNDescription":
    case "providers.alibaba.tokenPlanTeamGlobalDescription":
    case "providers.openai.description":
    case "providers.openai.apiDescription":
    case "providers.openai.codexDescription":
    case "providers.openai.codexAPIKeyDescription":
    case "providers.anthropic.description":
    case "providers.anthropic.apiDescription":
    case "providers.anthropic.claudeCodeDescription":
    case "providers.google.description":
    case "providers.google.aiStudioDescription":
    case "providers.google.interactionsDescription":
    case "providers.google.vertexDescription":
    case "providers.google.antigravityDescription":
    case "providers.xai.description":
    case "providers.xai.apiDescription":
    case "providers.xai.oauthDescription":
      return t(key);
    default:
      return fallback;
  }
}

// CustomProviderOnboardingPanelProps binds the server whitelist and active management credential to one atomic custom workflow.
// CustomProviderOnboardingPanelProps 将服务端白名单与当前管理凭证绑定到一个原子自定义工作流。
interface CustomProviderOnboardingPanelProps {
  // managementAuthToken authenticates only the management-plane custom onboarding request.
  // managementAuthToken 仅认证管理面的自定义录入请求。
  managementAuthToken: string;
  // profiles contains the exact custom execution factories returned by the server.
  // profiles 包含服务端返回的精确自定义执行 Factory。
  profiles: CustomProtocolProfile[];
  // profilesFailed reports that the profile inventory could not be loaded.
  // profilesFailed 表示 Profile 清单无法加载。
  profilesFailed: boolean;
  // onComplete closes the dialog and reloads committed provider state.
  // onComplete 关闭 Dialog 并重新加载已提交供应商状态。
  onComplete: () => void;
}

// CustomProviderOnboardingPanel creates one compatibility provider, access graph, protected secret, and initial model in one request.
// CustomProviderOnboardingPanel 通过一个请求创建兼容供应商、访问图、受保护 Secret 与初始模型。
function CustomProviderOnboardingPanel({
  managementAuthToken,
  profiles,
  profilesFailed,
  onComplete,
}: CustomProviderOnboardingPanelProps) {
  const { t } = useI18n();
  const [displayName, setDisplayName] = useState("");
  const [handle, setHandle] = useState("");
  const [protocolProfileID, setProtocolProfileID] = useState(
    profiles[0]?.id ?? "",
  );
  const [baseURL, setBaseURL] = useState("");
  const [secret, setSecret] = useState("");
  const [upstreamModelID, setUpstreamModelID] = useState("");
  const [modelDisplayName, setModelDisplayName] = useState("");
  const [pending, setPending] = useState(false);
  const [failed, setFailed] = useState(false);
  // selectedProfile is the immutable server-owned execution profile selected by its exact identifier.
  // selectedProfile 是通过精确标识选择的不可变服务端拥有执行 Profile。
  const selectedProfile = profiles.find(
    (profile) => profile.id === protocolProfileID,
  );

  // submitCustomProvider sends transient secret material only after browser validation accepts every required field.
  // submitCustomProvider 仅在浏览器校验全部必填字段后发送临时 Secret 材料。
  async function submitCustomProvider(event: FormEvent) {
    event.preventDefault();
    if (!selectedProfile) {
      setFailed(true);
      return;
    }
    setPending(true);
    setFailed(false);
    try {
      await onboardCustomProvider(managementAuthToken, {
        display_name: displayName.trim(),
        handle: handle.trim(),
        protocol_profile_id: selectedProfile.id,
        base_url: baseURL.trim(),
        secret,
        upstream_model_id: upstreamModelID.trim(),
        model_display_name: modelDisplayName.trim(),
      });
      onComplete();
    } catch {
      setFailed(true);
    } finally {
      setPending(false);
    }
  }

  if (profilesFailed || profiles.length === 0) {
    return (
      <p className="text-destructive text-sm" role="status">
        {t("providers.customProfilesFailed")}
      </p>
    );
  }

  return (
    <form className="grid gap-4" onSubmit={submitCustomProvider}>
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="grid gap-2">
          <Label htmlFor="custom-provider-name">
            {t("providers.customName")}
          </Label>
          <Input
            id="custom-provider-name"
            value={displayName}
            onChange={(event) => setDisplayName(event.target.value)}
            autoComplete="off"
            required
          />
        </div>
        <div className="grid gap-2">
          <Label htmlFor="custom-provider-handle">
            {t("providers.handle")}
          </Label>
          <Input
            id="custom-provider-handle"
            value={handle}
            onChange={(event) => setHandle(event.target.value)}
            autoComplete="off"
            required
          />
        </div>
      </div>
      <div className="grid gap-2">
        <Label
          className="flex items-center gap-1.5"
          htmlFor="custom-provider-protocol"
        >
          <CableIcon className="size-3.5" aria-hidden="true" />
          {t("providers.protocol")}
        </Label>
        <Select
          value={protocolProfileID}
          onValueChange={(value) => {
            if (value !== null) setProtocolProfileID(value);
          }}
        >
          <SelectTrigger id="custom-provider-protocol" className="w-full">
            <SelectValue placeholder={t("providers.selectProtocol")} />
          </SelectTrigger>
          <SelectContent>
            {profiles.map((profile) => (
              <SelectItem key={profile.id} value={profile.id}>
                {profile.display_name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {selectedProfile ? (
          <p className="text-muted-foreground text-xs">
            {t("providers.authentication")}:{" "}
            {selectedProfile.allowed_auth_methods[0] === "bearer"
              ? "Bearer"
              : "x-goog-api-key"}
          </p>
        ) : null}
      </div>
      <div className="grid gap-2">
        <Label
          className="flex items-center gap-1.5"
          htmlFor="custom-provider-base-url"
        >
          <Globe2Icon className="size-3.5" aria-hidden="true" />
          {t("providers.baseURL")}
        </Label>
        <Input
          id="custom-provider-base-url"
          type="url"
          value={baseURL}
          onChange={(event) => setBaseURL(event.target.value)}
          placeholder="https://api.example.com/v1"
          autoComplete="url"
          required
        />
      </div>
      <div className="grid gap-2">
        <Label
          className="flex items-center gap-1.5"
          htmlFor="custom-provider-secret"
        >
          <KeyRoundIcon className="size-3.5" aria-hidden="true" />
          {t("providers.apiKey")}
        </Label>
        <Input
          id="custom-provider-secret"
          type="password"
          value={secret}
          onChange={(event) => setSecret(event.target.value)}
          autoComplete="new-password"
          required
        />
      </div>
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="grid gap-2">
          <Label htmlFor="custom-provider-model-id">
            {t("providers.upstreamModelID")}
          </Label>
          <Input
            id="custom-provider-model-id"
            value={upstreamModelID}
            onChange={(event) => setUpstreamModelID(event.target.value)}
            autoComplete="off"
            required
          />
        </div>
        <div className="grid gap-2">
          <Label htmlFor="custom-provider-model-name">
            {t("providers.modelDisplayName")}
          </Label>
          <Input
            id="custom-provider-model-name"
            value={modelDisplayName}
            onChange={(event) => setModelDisplayName(event.target.value)}
            autoComplete="off"
          />
        </div>
      </div>
      {failed ? (
        <p className="text-destructive text-sm" role="status">
          {t("providers.onboardingFailed")}
        </p>
      ) : null}
      <Button type="submit" disabled={pending}>
        {pending ? t("providers.creating") : t("providers.onboard")}
      </Button>
    </form>
  );
}

// ProviderOnboardingPanelProps binds one exact definition and active management credential to its real workflow.
// ProviderOnboardingPanelProps 将一个精确定义和当前管理凭证绑定到真实工作流。
interface ProviderOnboardingPanelProps {
  // definition is the exact selected site or commercial plan.
  // definition 是精确选择的站点或商业套餐。
  definition: ProviderDefinition;
  // managementAuthToken authenticates only the management-plane workflow.
  // managementAuthToken 仅认证管理面工作流。
  managementAuthToken: string;
  // onComplete reloads the authorized list after the server commits onboarding.
  // onComplete 在服务端提交录入后重新加载已授权列表。
  onComplete: () => void;
}

// ProviderOnboardingPanel performs API-key, service-account, or server-confidential interactive onboarding.
// ProviderOnboardingPanel 执行 API Key、服务账号或服务端保密交互授权录入。
function ProviderOnboardingPanel({
  definition,
  managementAuthToken,
  onComplete,
}: ProviderOnboardingPanelProps) {
  const { t } = useI18n();
  const [authMethodID, setAuthMethodID] = useState(
    definition.auth_methods[0]?.id ?? "",
  );
  const authMethod = definition.auth_methods.find(
    (method) => method.id === authMethodID,
  );
  const isDeviceFlow = authMethod?.type === "device_flow";
  const isAntigravityOAuth =
    authMethod?.type === "oauth" &&
    definition.id === "system_google_antigravity";
  const isClaudeOAuth =
    authMethod?.type === "oauth" &&
    definition.id === "system_anthropic_claude_code";
  const isCodexOAuth =
    authMethod?.type === "oauth" && definition.id === "system_openai_codex";
  // isBrowserOAuth identifies the exact providers using server-owned callback completion.
  // isBrowserOAuth 标识使用服务端拥有回调完成流程的精确供应商。
  const isBrowserOAuth = isAntigravityOAuth || isClaudeOAuth || isCodexOAuth;
  const isVertexServiceAccount =
    authMethod?.type === "service_account" &&
    definition.id === "system_google_vertex";
  const isXAIDeviceFlow = definition.id === "system_xai_oauth";
  const isCodexDeviceFlow =
    isDeviceFlow && definition.id === "system_openai_codex";
  // requiresOperatorName is true only when the selected credential carries no provider-issued display identity.
  // requiresOperatorName 仅在所选凭据不携带供应商签发的显示身份时为 true。
  const requiresOperatorName =
    authMethod?.type === "api_key" ||
    (isDeviceFlow &&
      (definition.id === "system_kimi_coding_plan" || isXAIDeviceFlow));
  // name is the sole operator-authored label and is reused by the server for the instance and credential.
  // name 是唯一由操作员填写的标签，并由服务端同时用于实例与凭据。
  const [name, setName] = useState(definition.display_name);
  const [secret, setSecret] = useState("");
  // vertexLocation starts from the code-owned default and remains a normalized provider location string.
  // vertexLocation 从代码拥有的默认值开始，并始终表示规范化供应商区域字符串。
  const [vertexLocation, setVertexLocation] = useState(
    definition.endpoint_presets[0]?.region ?? "us-central1",
  );
  const [deviceFlow, setDeviceFlow] = useState<KimiDeviceFlow | null>(null);
  // deviceFlowRef retains the exact unfinished session for unmount cleanup without duplicating completed cancellation.
  // deviceFlowRef 保留精确的未完成会话用于卸载清理，且不会重复取消已完成会话。
  const deviceFlowRef = useRef<KimiDeviceFlow | null>(null);
  // oauthFlow contains the token-free provider consent session displayed to the administrator.
  // oauthFlow 包含向管理员展示且不含令牌的供应商同意授权会话。
  const [oauthFlow, setOAuthFlow] = useState<
    AntigravityOAuthFlow | ClaudeOAuthFlow | CodexOAuthFlow | null
  >(null);
  // oauthFlowRef retains the exact unfinished OAuth session for unmount cleanup.
  // oauthFlowRef 保留精确的未完成 OAuth 会话用于卸载清理。
  const oauthFlowRef = useRef<
    AntigravityOAuthFlow | ClaudeOAuthFlow | CodexOAuthFlow | null
  >(null);
  // flowRequestRevision invalidates authorization-start responses that arrive after a method change or panel unmount.
  // flowRequestRevision 使认证方式切换或面板卸载后到达的授权启动响应失效。
  const flowRequestRevision = useRef(0);
  // oauthCallbackURL is the exact localhost callback copied from the browser address bar.
  // oauthCallbackURL 是从浏览器地址栏复制的精确 localhost 回调地址。
  const [oauthCallbackURL, setOAuthCallbackURL] = useState("");
  const [pending, setPending] = useState(false);
  const [messageKey, setMessageKey] = useState<TranslationKey | null>(null);

  useEffect(() => {
    // cleanup releases the exact unfinished server session when this definition panel unmounts.
    // cleanup 在此定义面板卸载时释放精确的未完成服务端会话。
    return () => {
      flowRequestRevision.current += 1;
      // unfinishedDeviceFlow is captured before clearing the shared ref so later effects cannot cancel it through the wrong provider route.
      // unfinishedDeviceFlow 在清空共享引用前被捕获，避免后续 Effect 通过错误供应商路由取消它。
      const unfinishedDeviceFlow = deviceFlowRef.current;
      deviceFlowRef.current = null;
      if (unfinishedDeviceFlow) {
        const cancelFlow = isXAIDeviceFlow
          ? cancelXAIDeviceFlow
          : isCodexDeviceFlow
            ? cancelCodexDeviceFlow
            : cancelKimiDeviceFlow;
        void cancelFlow(managementAuthToken, unfinishedDeviceFlow.id).catch(
          () => undefined,
        );
      }
      // unfinishedOAuthFlow is captured with the provider classification owned by this effect revision.
      // unfinishedOAuthFlow 与此 Effect 修订拥有的供应商分类一同被捕获。
      const unfinishedOAuthFlow = oauthFlowRef.current;
      oauthFlowRef.current = null;
      if (unfinishedOAuthFlow) {
        const cancelProviderOAuthFlow = isClaudeOAuth
          ? cancelClaudeOAuthFlow
          : isCodexOAuth
            ? cancelCodexOAuthFlow
            : cancelAntigravityOAuthFlow;
        void cancelProviderOAuthFlow(
          managementAuthToken,
          unfinishedOAuthFlow.id,
        ).catch(() => undefined);
      }
    };
  }, [
    isClaudeOAuth,
    isCodexDeviceFlow,
    isCodexOAuth,
    isXAIDeviceFlow,
    managementAuthToken,
  ]);

  // beginOAuthFlow requests one provider-specific server-owned authorization URL without exposing OAuth secrets.
  // beginOAuthFlow 请求一个供应商专属且由服务端拥有的授权地址，且不暴露 OAuth 秘密。
  async function beginOAuthFlow() {
    if (!isBrowserOAuth) {
      setMessageKey("providers.unsupportedAuthentication");
      return;
    }
    setPending(true);
    setMessageKey(null);
    // requestRevision binds a late start response to the exact panel and authentication method that initiated it.
    // requestRevision 将延迟到达的启动响应绑定到发起它的精确面板与认证方式。
    const requestRevision = flowRequestRevision.current;
    try {
      const startProviderOAuthFlow = isClaudeOAuth
        ? startClaudeOAuthFlow
        : isCodexOAuth
          ? startCodexOAuthFlow
          : startAntigravityOAuthFlow;
      const cancelProviderOAuthFlow = isClaudeOAuth
        ? cancelClaudeOAuthFlow
        : isCodexOAuth
          ? cancelCodexOAuthFlow
          : cancelAntigravityOAuthFlow;
      const flow = await startProviderOAuthFlow(managementAuthToken);
      if (flowRequestRevision.current !== requestRevision) {
        await cancelProviderOAuthFlow(managementAuthToken, flow.id).catch(
          () => undefined,
        );
        return;
      }
      oauthFlowRef.current = flow;
      setOAuthFlow(flow);
      setOAuthCallbackURL("");
    } catch {
      setMessageKey("providers.onboardingFailed");
    } finally {
      if (flowRequestRevision.current === requestRevision) setPending(false);
    }
  }

  // completeOAuthFlow exchanges the exact pasted callback and persists the resulting provider atomically.
  // completeOAuthFlow 交换精确粘贴的回调并原子持久化生成的供应商。
  async function completeOAuthFlow() {
    if (!oauthFlow || !oauthCallbackURL.trim()) return;
    setPending(true);
    setMessageKey(null);
    try {
      const onboardProviderOAuthFlow = isClaudeOAuth
        ? onboardClaudeOAuthFlow
        : isCodexOAuth
          ? onboardCodexOAuthFlow
          : onboardAntigravityOAuthFlow;
      await onboardProviderOAuthFlow(managementAuthToken, oauthFlow.id, {
        provider_definition_id: definition.id,
        callback_url: oauthCallbackURL.trim(),
      });
      oauthFlowRef.current = null;
      setOAuthFlow(null);
      setOAuthCallbackURL("");
      onComplete();
    } catch {
      setMessageKey("providers.onboardingFailed");
    } finally {
      setPending(false);
    }
  }

  // cancelOAuthFlow releases one incomplete provider consent session immediately.
  // cancelOAuthFlow 立即释放一个未完成的供应商同意授权会话。
  async function cancelOAuthFlow() {
    if (!oauthFlow) return;
    setPending(true);
    setMessageKey(null);
    try {
      const cancelProviderOAuthFlow = isClaudeOAuth
        ? cancelClaudeOAuthFlow
        : isCodexOAuth
          ? cancelCodexOAuthFlow
          : cancelAntigravityOAuthFlow;
      await cancelProviderOAuthFlow(managementAuthToken, oauthFlow.id);
      oauthFlowRef.current = null;
      setOAuthFlow(null);
      setOAuthCallbackURL("");
    } catch {
      setMessageKey("providers.onboardingFailed");
    } finally {
      setPending(false);
    }
  }

  // submitAPIKey sends one plaintext key only to the authenticated atomic onboarding endpoint.
  // submitAPIKey 仅将一个明文密钥发送到经过认证的原子录入端点。
  async function submitAPIKey(event: FormEvent) {
    event.preventDefault();
    if (!authMethod || authMethod.type !== "api_key") {
      setMessageKey("providers.unsupportedAuthentication");
      return;
    }
    setPending(true);
    setMessageKey(null);
    try {
      await onboardSystemProvider(managementAuthToken, {
        provider_definition_id: definition.id,
        name: name.trim(),
        auth_method_id: authMethodID,
        secret,
      });
      setSecret("");
      onComplete();
    } catch {
      setMessageKey("providers.onboardingFailed");
    } finally {
      setPending(false);
    }
  }

  // submitVertexServiceAccount parses one JSON object locally before sending it to the dedicated protected onboarding endpoint.
  // submitVertexServiceAccount 在发送到专属受保护录入入口前于本地解析一个 JSON 对象。
  async function submitVertexServiceAccount(event: FormEvent) {
    event.preventDefault();
    if (!isVertexServiceAccount) {
      setMessageKey("providers.unsupportedAuthentication");
      return;
    }
    let serviceAccount: unknown;
    try {
      serviceAccount = JSON.parse(secret);
    } catch {
      setMessageKey("providers.invalidServiceAccountJSON");
      return;
    }
    if (
      serviceAccount === null ||
      Array.isArray(serviceAccount) ||
      typeof serviceAccount !== "object"
    ) {
      setMessageKey("providers.invalidServiceAccountJSON");
      return;
    }
    setPending(true);
    setMessageKey(null);
    try {
      await onboardVertexServiceAccount(managementAuthToken, {
        provider_definition_id: definition.id,
        location: vertexLocation.trim(),
        service_account: serviceAccount as Record<string, unknown>,
      });
      setSecret("");
      onComplete();
    } catch {
      setMessageKey("providers.onboardingFailed");
    } finally {
      setPending(false);
    }
  }

  // beginDeviceFlow requests management-safe verification data from the server-owned Kimi client.
  // beginDeviceFlow 从服务端拥有的 Kimi 客户端请求管理安全验证数据。
  async function beginDeviceFlow() {
    if (!authMethod || authMethod.type !== "device_flow") {
      setMessageKey("providers.unsupportedAuthentication");
      return;
    }
    setPending(true);
    setMessageKey(null);
    // requestRevision binds a late device response to the provider route selected when the request started.
    // requestRevision 将延迟到达的设备响应绑定到请求发起时选择的供应商路由。
    const requestRevision = flowRequestRevision.current;
    try {
      const startFlow = isXAIDeviceFlow
        ? startXAIDeviceFlow
        : isCodexDeviceFlow
          ? startCodexDeviceFlow
          : startKimiDeviceFlow;
      const cancelFlow = isXAIDeviceFlow
        ? cancelXAIDeviceFlow
        : isCodexDeviceFlow
          ? cancelCodexDeviceFlow
          : cancelKimiDeviceFlow;
      const flow = await startFlow(managementAuthToken);
      if (flowRequestRevision.current !== requestRevision) {
        await cancelFlow(managementAuthToken, flow.id).catch(() => undefined);
        return;
      }
      deviceFlowRef.current = flow;
      setDeviceFlow(flow);
    } catch {
      setMessageKey("providers.onboardingFailed");
    } finally {
      if (flowRequestRevision.current === requestRevision) setPending(false);
    }
  }

  // checkDeviceFlow performs one provider-safe poll and commits only a completed authorization.
  // checkDeviceFlow 执行一次供应商安全轮询且仅提交已完成授权。
  async function checkDeviceFlow() {
    if (!deviceFlow) return;
    setPending(true);
    setMessageKey(null);
    try {
      const onboardFlow = isXAIDeviceFlow
        ? onboardXAIDeviceFlow
        : isCodexDeviceFlow
          ? onboardCodexDeviceFlow
          : onboardKimiDeviceFlow;
      const result = await onboardFlow(managementAuthToken, deviceFlow.id, {
        provider_definition_id: definition.id,
        name: requiresOperatorName ? name.trim() : "",
      });
      if (result === null) {
        setMessageKey("providers.authorizationPending");
      } else {
        deviceFlowRef.current = null;
        setDeviceFlow(null);
        onComplete();
      }
    } catch {
      setMessageKey("providers.onboardingFailed");
    } finally {
      setPending(false);
    }
  }

  // cancelDeviceFlow releases the page-owned authorization session immediately.
  // cancelDeviceFlow 立即释放页面拥有的授权会话。
  async function cancelDeviceFlow() {
    if (!deviceFlow) return;
    setPending(true);
    setMessageKey(null);
    try {
      const cancelFlow = isXAIDeviceFlow
        ? cancelXAIDeviceFlow
        : isCodexDeviceFlow
          ? cancelCodexDeviceFlow
          : cancelKimiDeviceFlow;
      await cancelFlow(managementAuthToken, deviceFlow.id);
      deviceFlowRef.current = null;
      setDeviceFlow(null);
    } catch {
      setMessageKey("providers.onboardingFailed");
    } finally {
      setPending(false);
    }
  }

  // selectAuthMethod releases any unfinished flow before changing the exact credential acquisition method.
  // selectAuthMethod 在切换精确凭据获取方式前释放任何未完成授权流程。
  function selectAuthMethod(methodID: string) {
    // selectedAuthMethod comes from the exact definition-owned button and prevents forged acquisition methods.
    // selectedAuthMethod 来自精确定义拥有的按钮，并阻止伪造凭据获取方式。
    const selectedAuthMethod = definition.auth_methods.find(
      (method) => method.id === methodID,
    );
    if (!selectedAuthMethod) {
      setMessageKey("providers.unsupportedAuthentication");
      return;
    }
    flowRequestRevision.current += 1;
    setPending(false);
    if (deviceFlowRef.current) {
      const cancelFlow = isXAIDeviceFlow
        ? cancelXAIDeviceFlow
        : isCodexDeviceFlow
          ? cancelCodexDeviceFlow
          : cancelKimiDeviceFlow;
      void cancelFlow(managementAuthToken, deviceFlowRef.current.id).catch(
        () => undefined,
      );
    }
    if (oauthFlowRef.current) {
      const cancelProviderOAuthFlow =
        definition.id === "system_anthropic_claude_code"
          ? cancelClaudeOAuthFlow
          : definition.id === "system_openai_codex"
            ? cancelCodexOAuthFlow
            : cancelAntigravityOAuthFlow;
      void cancelProviderOAuthFlow(
        managementAuthToken,
        oauthFlowRef.current.id,
      ).catch(() => undefined);
    }
    deviceFlowRef.current = null;
    setAuthMethodID(methodID);
    setDeviceFlow(null);
    oauthFlowRef.current = null;
    setOAuthFlow(null);
    setOAuthCallbackURL("");
    setSecret("");
    setVertexLocation(definition.endpoint_presets[0]?.region ?? "us-central1");
    setMessageKey(null);
  }

  if (
    !authMethod ||
    (authMethod.type !== "api_key" &&
      authMethod.type !== "device_flow" &&
      !isBrowserOAuth &&
      !isVertexServiceAccount)
  ) {
    return (
      <p className="text-destructive text-sm" role="alert">
        {t("providers.unsupportedAuthentication")}
      </p>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>{definition.display_name}</CardTitle>
        <CardDescription>
          {localizedDescription(
            t,
            definition.variant_description_key,
            definition.variant_description,
          )}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form
          className="grid gap-4 md:grid-cols-2"
          onSubmit={
            isDeviceFlow || isBrowserOAuth
              ? (event) => event.preventDefault()
              : isVertexServiceAccount
                ? submitVertexServiceAccount
                : submitAPIKey
          }
        >
          {definition.auth_methods.length > 1 ? (
            <div className="flex gap-2 md:col-span-2">
              {definition.auth_methods.map((method) => (
                <Button
                  key={method.id}
                  type="button"
                  variant={authMethodID === method.id ? "default" : "outline"}
                  disabled={pending}
                  onClick={() => selectAuthMethod(method.id)}
                >
                  {method.type === "device_flow"
                    ? t("providers.deviceFlow")
                    : method.type === "oauth"
                      ? t("providers.oauth")
                      : method.type === "service_account"
                        ? t("providers.serviceAccount")
                        : t("providers.apiKey")}
                </Button>
              ))}
            </div>
          ) : null}
          {requiresOperatorName ? (
            <div className="space-y-2">
              <Label htmlFor="provider-name">{t("providers.name")}</Label>
              <Input
                id="provider-name"
                value={name}
                onChange={(event) => setName(event.target.value)}
                required
              />
            </div>
          ) : null}
          {isVertexServiceAccount ? (
            <>
              <div className="space-y-2">
                <Label htmlFor="vertex-location">
                  {t("providers.vertexLocation")}
                </Label>
                <Input
                  id="vertex-location"
                  value={vertexLocation}
                  onChange={(event) => setVertexLocation(event.target.value)}
                  required
                  autoComplete="off"
                />
              </div>
              <div className="space-y-2 md:col-span-2">
                <Label htmlFor="provider-secret">
                  {t("providers.serviceAccountJSON")}
                </Label>
                <textarea
                  id="provider-secret"
                  className="border-input bg-transparent placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-ring/50 min-h-40 w-full rounded-md border px-3 py-2 font-mono text-sm shadow-xs outline-none focus-visible:ring-[3px]"
                  value={secret}
                  onChange={(event) => setSecret(event.target.value)}
                  placeholder='{ "type": "service_account", ... }'
                  required
                  autoComplete="off"
                  spellCheck={false}
                />
                <p className="text-muted-foreground text-xs">
                  {t("providers.serviceAccountHelp")}
                </p>
              </div>
            </>
          ) : !isDeviceFlow && !isBrowserOAuth ? (
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
            {!isDeviceFlow && !isBrowserOAuth ? (
              <Button type="submit" disabled={pending}>
                {t("providers.onboard")}
              </Button>
            ) : isDeviceFlow && deviceFlow ? (
              <div className="space-y-3">
                <p className="text-sm">
                  {t("providers.authorizationCode")}:{" "}
                  <strong>{deviceFlow.user_code}</strong>
                </p>
                <a
                  className="text-primary text-sm underline"
                  href={
                    deviceFlow.verification_uri_complete ||
                    deviceFlow.verification_uri
                  }
                  target="_blank"
                  rel="noreferrer"
                >
                  {deviceFlow.verification_uri}
                </a>
                <div className="flex gap-2">
                  <Button
                    type="button"
                    disabled={pending}
                    onClick={checkDeviceFlow}
                  >
                    {t("providers.checkAuthorization")}
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    disabled={pending}
                    onClick={cancelDeviceFlow}
                  >
                    {t("providers.cancelAuthorization")}
                  </Button>
                </div>
              </div>
            ) : isDeviceFlow ? (
              <Button
                type="button"
                disabled={pending}
                onClick={beginDeviceFlow}
              >
                {t("providers.startAuthorization")}
              </Button>
            ) : oauthFlow ? (
              <div className="space-y-3">
                <a
                  className="text-primary inline-flex text-sm underline"
                  href={oauthFlow.authorization_url}
                  target="_blank"
                  rel="noreferrer"
                >
                  {t("providers.openAuthorization")}
                </a>
                <div className="space-y-2">
                  <Label htmlFor="oauth-callback-url">
                    {t("providers.callbackURL")}
                  </Label>
                  <Input
                    id="oauth-callback-url"
                    type={isClaudeOAuth ? "text" : "url"}
                    value={oauthCallbackURL}
                    onChange={(event) =>
                      setOAuthCallbackURL(event.target.value)
                    }
                    placeholder={oauthFlow.redirect_uri}
                    required
                    autoComplete="off"
                  />
                  <p className="text-muted-foreground text-xs">
                    {t(
                      isClaudeOAuth
                        ? "providers.claudeCallbackHelp"
                        : "providers.callbackHelp",
                    )}
                  </p>
                </div>
                <div className="flex gap-2">
                  <Button
                    type="button"
                    disabled={pending || !oauthCallbackURL.trim()}
                    onClick={completeOAuthFlow}
                  >
                    {t("providers.completeAuthorization")}
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    disabled={pending}
                    onClick={cancelOAuthFlow}
                  >
                    {t("providers.cancelAuthorization")}
                  </Button>
                </div>
              </div>
            ) : (
              <Button type="button" disabled={pending} onClick={beginOAuthFlow}>
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
  );
}
