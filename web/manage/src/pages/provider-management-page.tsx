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
  Trash2Icon,
  XIcon,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
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
} from "@/components/ui/alert-dialog";
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
  deleteProviderCredential,
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
  rotateProviderCredentialSecret,
  startAntigravityOAuthFlow,
  startClaudeOAuthFlow,
  startCodexOAuthFlow,
  startKimiDeviceFlow,
  startCodexDeviceFlow,
  startXAIDeviceFlow,
  updateProviderCredentialPlan,
  updateProviderCredentialPriority,
  updateProviderRoutingStrategy,
  type AuthorizedProvider,
  type AntigravityOAuthFlow,
  type ClaudeOAuthFlow,
  type CodexOAuthFlow,
  type CustomProtocolProfile,
  type KimiDeviceFlow,
  type ProviderDefinitionIdentity,
  type ProviderDefinitionSummary,
  type ProviderDefinition,
  type ProviderCredential,
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

// CredentialReauthorizationSelection binds one local credential to its immutable provider definition.
// CredentialReauthorizationSelection 将一个本地凭据绑定到其不可变供应商定义。
interface CredentialReauthorizationSelection {
  // providerInstanceID owns the credential.
  // providerInstanceID 拥有该凭据。
  providerInstanceID: string;
  // credential is the exact management-safe credential.
  // credential 是精确的管理端安全凭据。
  credential: ProviderCredential;
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
  // reauthorizationTarget identifies an existing credential being replaced through the creation dialog shell.
  // reauthorizationTarget 标识通过新增 Dialog 外壳进行替换的既有凭据。
  const [reauthorizationTarget, setReauthorizationTarget] =
    useState<CredentialReauthorizationSelection | null>(null);
  // deletingCredentialIDs prevents duplicate destructive requests.
  // deletingCredentialIDs 防止重复的破坏性请求。
  const [deletingCredentialIDs, setDeletingCredentialIDs] = useState<
    Set<string>
  >(new Set());

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
    .find((definition) => definition.id === selectedDefinitionID) ??
    definitions.find((definition) => definition.id === selectedDefinitionID);
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
    setReauthorizationTarget(null);
  }

  // beginCredentialReauthorization opens the exact provider workflow for one existing credential.
  // beginCredentialReauthorization 为一个既有凭据打开精确供应商工作流。
  function beginCredentialReauthorization(
    providerInstanceID: string,
    definitionID: string,
    credential: ProviderCredential,
  ) {
    setReauthorizationTarget({ providerInstanceID, credential });
    setSelectedDefinitionID(definitionID);
    setAdding(true);
  }

  // deleteCredential removes one confirmed credential and reloads authoritative provider state.
  // deleteCredential 删除一个已确认凭据并重新加载权威供应商状态。
  async function deleteCredential(
    providerInstanceID: string,
    credentialID: string,
  ) {
    setDeletingCredentialIDs((current) => new Set(current).add(credentialID));
    try {
      await deleteProviderCredential(
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
    } catch {
      setCredentialRefreshErrors((current) => ({
        ...current,
        [credentialID]: "provider_credential_delete_failed",
      }));
      // A cleanup-stage server error can occur after configuration deletion, so always reload authoritative state.
      // 服务端清理阶段错误可能发生在配置已删除之后，因此始终重新加载权威状态。
      setRefreshRevision((revision) => revision + 1);
    } finally {
      setDeletingCredentialIDs((current) => {
        const next = new Set(current);
        next.delete(credentialID);
        return next;
      });
    }
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

  // changeProviderRouting persists one instance override and reloads the authoritative provider list.
  // changeProviderRouting 持久化一个实例覆盖策略并重新加载权威供应商列表。
  async function changeProviderRouting(
    providerInstanceID: string,
    strategy: "" | "round_robin" | "fill_first",
  ) {
    await updateProviderRoutingStrategy(
      managementAuthToken,
      providerInstanceID,
      strategy,
    );
    setRefreshRevision((revision) => revision + 1);
  }

  // changeCredentialPriority persists account ordering and reloads redacted credential metadata.
  // changeCredentialPriority 持久化账号顺序并重新加载脱敏凭据元数据。
  async function changeCredentialPriority(
    providerInstanceID: string,
    credentialID: string,
    priority: number,
  ) {
    await updateProviderCredentialPriority(
      managementAuthToken,
      providerInstanceID,
      credentialID,
      priority,
    );
    setRefreshRevision((revision) => revision + 1);
  }

  // changeCredentialPlan replaces one manual plan and discards the stale browser catalog projection.
  // changeCredentialPlan 替换一个人工套餐并丢弃浏览器中的过期目录投影。
  async function changeCredentialPlan(
    providerInstanceID: string,
    credentialID: string,
    planOptionID: string,
  ) {
    await updateProviderCredentialPlan(
      managementAuthToken,
      providerInstanceID,
      credentialID,
      planOptionID,
    );
    setProviderMetadata((current) => {
      const next = { ...current };
      delete next[providerInstanceID];
      return next;
    });
    setRefreshRevision((revision) => revision + 1);
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
                onChangeRouting={changeProviderRouting}
                onChangeCredentialPriority={changeCredentialPriority}
                onChangeCredentialPlan={changeCredentialPlan}
                onReauthorizeCredential={beginCredentialReauthorization}
                onDeleteCredential={deleteCredential}
                deletingCredentialIDs={deletingCredentialIDs}
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
                  {reauthorizationTarget
                    ? t("providers.reauthorizeCredential")
                    : selectedDefinition || configuringCustom
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
                    key={`${selectedDefinition.id}:${reauthorizationTarget?.credential.id ?? "new"}`}
                    definition={selectedDefinition}
                    managementAuthToken={managementAuthToken}
                    onComplete={completeOnboarding}
                    reauthorizationTarget={reauthorizationTarget}
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
  // onChangeRouting persists one instance scheduling override.
  // onChangeRouting 持久化一个实例调度覆盖值。
  onChangeRouting: (
    providerInstanceID: string,
    strategy: "" | "round_robin" | "fill_first",
  ) => Promise<void>;
  // onChangeCredentialPriority persists one nonnegative account priority.
  // onChangeCredentialPriority 持久化一个非负账号优先级。
  onChangeCredentialPriority: (
    providerInstanceID: string,
    credentialID: string,
    priority: number,
  ) => Promise<void>;
  // onChangeCredentialPlan replaces one manual code-owned plan.
  // onChangeCredentialPlan 替换一个人工代码拥有套餐。
  onChangeCredentialPlan: (
    providerInstanceID: string,
    credentialID: string,
    planOptionID: string,
  ) => Promise<void>;
  // onReauthorizeCredential opens the exact credential acquisition workflow.
  // onReauthorizeCredential 打开精确的凭据获取流程。
  onReauthorizeCredential: (
    providerInstanceID: string,
    definitionID: string,
    credential: ProviderCredential,
  ) => void;
  // onDeleteCredential deletes one confirmed credential.
  // onDeleteCredential 删除一个已确认凭据。
  onDeleteCredential: (
    providerInstanceID: string,
    credentialID: string,
  ) => Promise<void>;
  // deletingCredentialIDs identifies credentials with an active delete request.
  // deletingCredentialIDs 标识正在执行删除请求的凭据。
  deletingCredentialIDs: ReadonlySet<string>;
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
  onChangeRouting,
  onChangeCredentialPriority,
  onChangeCredentialPlan,
  onReauthorizeCredential,
  onDeleteCredential,
  deletingCredentialIDs,
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
  const [routingMutationPending, setRoutingMutationPending] = useState(false);
  const [routingMutationFailed, setRoutingMutationFailed] = useState(false);
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
                        {model.authorization_status === "authorized"
                          ? t("providers.modelAuthorized")
                          : model.authorization_status === "denied"
                            ? t("providers.modelUnauthorized")
                            : t("providers.modelAuthorizationUnknown")}
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
                  <Badge variant="secondary">
                    {plan.evidence_source === "operator_declared"
                      ? t("providers.operatorDeclared")
                      : t("providers.providerDetected")}
                  </Badge>
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
                <AllowanceDisplay
                  key={`${allowance.kind}\u0000${allowance.metric}\u0000${allowance.scope}\u0000${allowanceIndex}`}
                  allowance={allowance}
                  t={t}
                />
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
        <div className="grid gap-2 sm:grid-cols-[minmax(0,1fr)_minmax(12rem,16rem)] sm:items-center">
          <div>
            <p className="text-sm font-medium">{t("providers.routingStrategy")}</p>
            <p className="text-muted-foreground text-xs">
              {t("providers.routingStrategyHelp")}
            </p>
          </div>
          <Select
            value={provider.instance.routing_strategy || "inherit"}
            disabled={routingMutationPending}
            onValueChange={(value) => {
              if (
                value !== "inherit" &&
                value !== "round_robin" &&
                value !== "fill_first"
              )
                return;
              setRoutingMutationPending(true);
              setRoutingMutationFailed(false);
              void onChangeRouting(
                provider.instance.id,
                value === "inherit" ? "" : value,
              )
                .catch(() => setRoutingMutationFailed(true))
                .finally(() => setRoutingMutationPending(false));
            }}
          >
            <SelectTrigger className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="inherit">{t("providers.routingInherit")}</SelectItem>
              <SelectItem value="round_robin">{t("settings.roundRobin")}</SelectItem>
              <SelectItem value="fill_first">{t("settings.fillFirst")}</SelectItem>
            </SelectContent>
          </Select>
        </div>
        {routingMutationFailed ? (
          <p className="text-destructive text-xs" role="alert">
            {t("providers.routingUpdateFailed")}
          </p>
        ) : null}
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
                        <p className="text-muted-foreground text-xs">
                          {t("providers.priority")}: {credential.priority}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {definition &&
                      (authMethod?.type === "api_key" ||
                        authMethod?.type === "bearer" ||
                        authMethod?.type === "header_api_key" ||
                        authMethod?.type === "device_flow" ||
                        authMethod?.type === "oauth" ||
                        authMethod?.type === "service_account") ? (
                        <Button
                          type="button"
                          variant="outline"
                          size="sm"
                          onClick={() =>
                            onReauthorizeCredential(
                              provider.instance.id,
                              provider.instance.definition_id,
                              credential,
                            )
                          }
                        >
                          <KeyRoundIcon className="size-3.5" />
                          {authMethod.type === "api_key" ||
                          authMethod.type === "bearer" ||
                          authMethod.type === "header_api_key" ||
                          authMethod.type === "service_account"
                            ? t("providers.replaceCredential")
                            : t("providers.reauthorizeCredential")}
                        </Button>
                      ) : null}
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
                      <AlertDialog>
                        <AlertDialogTrigger
                          render={
                            <Button
                              type="button"
                              variant="ghost"
                              size="icon-sm"
                              aria-label={t("providers.deleteCredential")}
                              disabled={deletingCredentialIDs.has(credential.id)}
                            />
                          }
                        >
                          <Trash2Icon className="text-destructive size-3.5" />
                        </AlertDialogTrigger>
                        <AlertDialogContent>
                          <AlertDialogHeader>
                            <AlertDialogTitle>
                              {t("providers.deleteCredentialTitle")}
                            </AlertDialogTitle>
                            <AlertDialogDescription>
                              {t("providers.deleteCredentialDescription")}
                            </AlertDialogDescription>
                          </AlertDialogHeader>
                          <AlertDialogFooter>
                            <AlertDialogCancel>
                              {t("providers.cancel")}
                            </AlertDialogCancel>
                            <AlertDialogAction
                              onClick={() =>
                                void onDeleteCredential(
                                  provider.instance.id,
                                  credential.id,
                                )
                              }
                            >
                              {t("providers.deleteCredential")}
                            </AlertDialogAction>
                          </AlertDialogFooter>
                        </AlertDialogContent>
                      </AlertDialog>
                    </div>
                  </div>
                  <div className="grid gap-2 sm:grid-cols-2">
                    <div className="space-y-1">
                      <Label htmlFor={`credential-priority-${credential.id}`}>
                        {t("providers.priority")}
                      </Label>
                      <Input
                        id={`credential-priority-${credential.id}`}
                        type="number"
                        min={0}
                        defaultValue={credential.priority}
                        onBlur={(event) => {
                          const priority = Number.parseInt(event.currentTarget.value, 10);
                          if (
                            Number.isInteger(priority) &&
                            priority >= 0 &&
                            priority !== credential.priority
                          ) {
                            void onChangeCredentialPriority(
                              provider.instance.id,
                              credential.id,
                              priority,
                            );
                          }
                        }}
                      />
                    </div>
                    {authMethod?.plan_acquisition === "manual_required" ? (
                      <div className="space-y-1">
                        <Label>{t("providers.membershipPlan")}</Label>
                        <Select
                          value={credential.declared_plan?.plan_option_id ?? ""}
                          onValueChange={(value) => {
                            if (value !== null && value !== credential.declared_plan?.plan_option_id) {
                              void onChangeCredentialPlan(
                                provider.instance.id,
                                credential.id,
                                value,
                              );
                            }
                          }}
                        >
                          <SelectTrigger className="w-full">
                            <SelectValue placeholder={t("providers.selectMembershipPlan")} />
                          </SelectTrigger>
                          <SelectContent>
                            {(definition?.plan_options ?? [])
                              .filter(
                                (option) =>
                                  option.manually_selectable &&
                                  option.auth_method_ids.includes(credential.auth_method_id),
                              )
                              .map((option) => (
                                <SelectItem key={option.id} value={option.id}>
                                  {option.display_name}
                                </SelectItem>
                              ))}
                          </SelectContent>
                        </Select>
                      </div>
                    ) : null}
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

// AllowanceDisplay renders window quotas, monetary balances, credits, and provider-defined values with distinct visual modes.
// AllowanceDisplay 使用不同视觉模式渲染窗口额度、货币余额、积分与供应商自定义值。
function AllowanceDisplay({
  allowance,
  t,
}: {
  // allowance is one validated management-safe resource observation.
  // allowance 是一条经过校验且管理端安全的资源观测。
  allowance: ProviderAllowance;
  // t resolves the current simplified-Chinese or English label.
  // t 解析当前简体中文或英文标签。
  t: (key: TranslationKey) => string;
}) {
  const ratio = allowance.remaining_ratio;
  const progress =
    ratio === undefined ? undefined : Math.max(0, Math.min(100, ratio * 100));
  const isMoney = allowance.unit === "minor_currency_units";
  const displayValue = (value: string | undefined) =>
    isMoney
      ? formatMinorCurrency(value, allowance.currency)
      : value === undefined
        ? undefined
        : `${value} ${allowanceDisplayUnit(allowance)}`;
  const remaining = displayValue(allowance.remaining);
  const used = displayValue(allowance.used);
  const limit = displayValue(allowance.limit);

  if (allowance.kind === "window_quota") {
    return (
      <li className="space-y-2 px-3 py-3 text-sm">
        <div className="flex items-center justify-between gap-3">
          <span className="flex min-w-0 items-center gap-2">
            <span className="truncate font-medium">
              {allowanceMetricLabel(t, allowance.metric)}
            </span>
            <AllowanceCredentialBadge allowance={allowance} />
          </span>
          <Badge variant="outline">
            {allowanceStatusLabel(t, allowance.status)}
          </Badge>
        </div>
        {progress !== undefined ? (
          <div className="space-y-1">
            <div
              className="bg-muted h-2 overflow-hidden rounded-full"
              role="progressbar"
              aria-label={allowanceMetricLabel(t, allowance.metric)}
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={Math.round(progress)}
            >
              <div
                className={`h-full rounded-full transition-[width] ${progress <= 10 ? "bg-destructive" : progress <= 30 ? "bg-amber-500" : "bg-emerald-500"}`}
                style={{ width: `${progress}%` }}
              />
            </div>
            <div className="text-muted-foreground flex justify-between gap-3 text-xs">
              <span>
                {t("providers.remaining")}:{" "}
                {remaining ?? `${progress.toFixed(0)}%`}
              </span>
              {used !== undefined && limit !== undefined ? (
                <span>
                  {used} / {limit}
                </span>
              ) : null}
            </div>
          </div>
        ) : (
          <AllowanceValueSummary allowance={allowance} t={t} />
        )}
        {allowance.window ? (
          <p className="text-muted-foreground text-xs">
            {t("providers.window")}: {allowanceWindowLabel(allowance.window)}
            {allowance.window.reset_at
              ? ` · ${t("providers.resetAt")}: ${formatAllowanceTime(allowance.window.reset_at)}`
              : null}
          </p>
        ) : null}
      </li>
    );
  }

  if (allowance.kind === "balance") {
    return (
      <li className="grid gap-2 px-3 py-3 text-sm sm:grid-cols-[minmax(0,1fr)_auto] sm:items-center">
        <div>
          <div className="flex items-center gap-2">
            <span className="font-medium">
              {allowanceMetricLabel(t, allowance.metric)}
            </span>
            <AllowanceCredentialBadge allowance={allowance} />
            <Badge variant="outline">
              {allowanceStatusLabel(t, allowance.status)}
            </Badge>
          </div>
          {used !== undefined ? (
            <p className="text-muted-foreground mt-1 text-xs">
              {t("providers.used")}: {used}
            </p>
          ) : null}
        </div>
        <div className="sm:text-right">
          <p className="text-base font-semibold tabular-nums">
            {remaining ?? t("providers.unknownAmount")}
          </p>
          {limit !== undefined ? (
            <p className="text-muted-foreground text-xs">
              {t("providers.limit")}: {limit}
            </p>
          ) : null}
        </div>
      </li>
    );
  }

  return (
    <li className="flex items-center justify-between gap-4 px-3 py-3 text-sm">
      <div>
        <p className="font-medium">
          {allowanceMetricLabel(t, allowance.metric)}
        </p>
        <AllowanceCredentialBadge allowance={allowance} />
        <AllowanceValueSummary allowance={allowance} t={t} />
      </div>
      <Badge
        variant={allowance.kind === "credit_grant" ? "secondary" : "outline"}
      >
        {remaining ?? limit ?? allowanceStatusLabel(t, allowance.status)}
      </Badge>
    </li>
  );
}

// AllowanceCredentialBadge identifies one local credential without exposing upstream account identity.
// AllowanceCredentialBadge 标识一个本地凭据且不暴露上游账号身份。
function AllowanceCredentialBadge({
  allowance,
}: {
  // allowance supplies the optional management-safe credential reference.
  // allowance 提供可选的管理端安全凭据引用。
  allowance: ProviderAllowance;
}) {
  const label = allowance.credential_label || allowance.credential_id;
  return label ? (
    <Badge variant="secondary" className="max-w-48 truncate">
      {label}
    </Badge>
  ) : null;
}

// AllowanceValueSummary renders compact exact values for modes without a progress representation.
// AllowanceValueSummary 为没有进度表示的模式渲染紧凑精确数值。
function AllowanceValueSummary({
  allowance,
  t,
}: {
  // allowance supplies exact optional quantities.
  // allowance 提供精确的可选数量。
  allowance: ProviderAllowance;
  // t resolves localized field labels.
  // t 解析本地化字段标签。
  t: (key: TranslationKey) => string;
}) {
  const parts: string[] = [];
  if (allowance.remaining !== undefined)
    parts.push(`${t("providers.remaining")}: ${allowance.remaining}`);
  if (allowance.used !== undefined)
    parts.push(`${t("providers.used")}: ${allowance.used}`);
  if (allowance.limit !== undefined)
    parts.push(`${t("providers.limit")}: ${allowance.limit}`);
  return parts.length ? (
    <p className="text-muted-foreground mt-1 text-xs">{parts.join(" · ")}</p>
  ) : null;
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

// formatMinorCurrency converts exact minor units to a localized major-currency label.
// formatMinorCurrency 将精确货币最小单位转换为本地化主要货币标签。
function formatMinorCurrency(
  value: string | undefined,
  currency: string | undefined,
): string | undefined {
  if (value === undefined || currency === undefined) return undefined;
  const amount = Number(value);
  if (!Number.isFinite(amount)) return undefined;
  return new Intl.NumberFormat(undefined, {
    style: "currency",
    currency,
  }).format(amount / 100);
}

// allowanceMetricLabel maps known provider metrics and safely humanizes dynamic provider labels.
// allowanceMetricLabel 映射已知供应商指标并安全地将动态供应商标签转为可读形式。
function allowanceMetricLabel(
  t: (key: TranslationKey) => string,
  metric: string,
): string {
  const known: Partial<Record<string, TranslationKey>> = {
    codex_primary: "providers.allowanceMetrics.codexPrimary",
    codex_secondary: "providers.allowanceMetrics.codexSecondary",
    code_review_primary: "providers.allowanceMetrics.codeReviewPrimary",
    code_review_secondary: "providers.allowanceMetrics.codeReviewSecondary",
    rate_limit_reset_credits: "providers.allowanceMetrics.resetCredits",
    five_hour: "providers.allowanceMetrics.fiveHour",
    seven_day: "providers.allowanceMetrics.sevenDay",
    seven_day_oauth_apps: "providers.allowanceMetrics.sevenDayOAuthApps",
    seven_day_opus: "providers.allowanceMetrics.sevenDayOpus",
    seven_day_sonnet: "providers.allowanceMetrics.sevenDaySonnet",
    seven_day_cowork: "providers.allowanceMetrics.sevenDayCowork",
    iguana_necktie: "providers.allowanceMetrics.providerSpecial",
    extra_usage: "providers.allowanceMetrics.extraUsage",
    weekly_usage: "providers.allowanceMetrics.weeklyUsage",
    monthly_budget: "providers.allowanceMetrics.monthlyBudget",
    on_demand_cap: "providers.allowanceMetrics.onDemandCap",
    GOOGLE_ONE_AI: "providers.allowanceMetrics.googleOneAI",
  };
  const translationKey = known[metric];
  if (translationKey) return t(translationKey);
  return metric
    .split("_")
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

// allowanceStatusLabel localizes the complete canonical allowance status set.
// allowanceStatusLabel 本地化完整的规范额度状态集合。
function allowanceStatusLabel(
  t: (key: TranslationKey) => string,
  status: string,
): string {
  switch (status) {
    case "available":
      return t("providers.allowanceStatus.available");
    case "low":
      return t("providers.allowanceStatus.low");
    case "exhausted":
      return t("providers.allowanceStatus.exhausted");
    case "unknown_sufficiency":
      return t("providers.allowanceStatus.unknown");
    case "unavailable":
      return t("providers.allowanceStatus.unavailable");
    default:
      return status;
  }
}

// allowanceWindowLabel preserves provider-authored window kind, duration, calendar unit, and time zone in one compact label.
// allowanceWindowLabel 在一个紧凑标签中保留供应商编写的窗口类型、时长、日历单位和时区。
function allowanceWindowLabel(window: ProviderAllowanceWindow): string {
  // parts retains only window nodes that are present in the validated management response.
  // parts 仅保留已校验管理响应中实际存在的窗口节点。
  const parts = [window.kind];
  if (window.duration !== "0") parts.push(formatAllowanceDuration(window.duration));
  if (window.calendar_unit) parts.push(window.calendar_unit);
  if (window.time_zone) parts.push(window.time_zone);
  return parts.join(" · ");
}

// formatAllowanceDuration converts an exact nanosecond string to the largest exact-friendly human unit.
// formatAllowanceDuration 将精确纳秒字符串转换为最大的易读时间单位。
function formatAllowanceDuration(duration: string): string {
  const nanoseconds = BigInt(duration);
  const units = [
    { label: "d", value: 86_400_000_000_000n },
    { label: "h", value: 3_600_000_000_000n },
    { label: "m", value: 60_000_000_000n },
    { label: "s", value: 1_000_000_000n },
  ];
  for (const unit of units) {
    if (nanoseconds >= unit.value && nanoseconds % unit.value === 0n)
      return `${nanoseconds / unit.value}${unit.label}`;
  }
  return `${duration} ns`;
}

// formatAllowanceTime renders one server-validated timestamp in the browser locale.
// formatAllowanceTime 使用浏览器区域设置渲染一个服务端已校验时间戳。
function formatAllowanceTime(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
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
    case "provider_credential_delete_failed":
      return t("providers.credentialDeleteFailed");
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
              <span className="truncate">
                {endpoint.base_url ||
                  endpoint.parameters
                    .map((parameter) => `{${parameter.id}}`)
                    .join(" · ")}
              </span>
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
    case "providers.alibaba.modelStudioCNDescription":
    case "providers.alibaba.modelStudioGlobalDescription":
    case "providers.alibaba.modelStudioWorkspaceGlobalDescription":
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
  // reauthorizationTarget selects an existing credential instead of creating an instance.
  // reauthorizationTarget 选择一个既有凭据而不是创建实例。
  reauthorizationTarget?: CredentialReauthorizationSelection | null;
}

// ProviderOnboardingPanel performs API-key, service-account, or server-confidential interactive onboarding.
// ProviderOnboardingPanel 执行 API Key、服务账号或服务端保密交互授权录入。
function ProviderOnboardingPanel({
  definition,
  managementAuthToken,
  onComplete,
  reauthorizationTarget,
}: ProviderOnboardingPanelProps) {
  const { t } = useI18n();
  const [authMethodID, setAuthMethodID] = useState(
    reauthorizationTarget?.credential.auth_method_id ??
      definition.auth_methods[0]?.id ??
      "",
  );
  const authMethod = definition.auth_methods.find(
    (method) => method.id === authMethodID,
  );
  // selectablePlanOptions contains only server-authored plans valid for the selected manual authentication method.
  // selectablePlanOptions 仅包含适用于所选人工认证方式且由服务端编写的套餐。
  const selectablePlanOptions = definition.plan_options
    .filter(
      (option) =>
        option.manually_selectable &&
        option.auth_method_ids.includes(authMethodID),
    )
    .sort((left, right) => left.sort_order - right.sort_order);
  // planOptionID is submitted only for authentication methods whose contract permits manual plan evidence.
  // planOptionID 仅在认证方式合同允许人工套餐证据时提交。
  const [planOptionID, setPlanOptionID] = useState(
    definition.plan_options.find(
      (option) =>
        option.manually_selectable &&
        option.auth_method_ids.includes(definition.auth_methods[0]?.id ?? ""),
    )?.id ?? "",
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
  // isDirectSecretAuth identifies credential bytes that an administrator may replace directly.
  // isDirectSecretAuth 标识管理员可以直接替换的凭据字节。
  const isDirectSecretAuth =
    authMethod?.type === "api_key" ||
    authMethod?.type === "bearer" ||
    authMethod?.type === "header_api_key";
  const isXAIDeviceFlow = definition.id === "system_xai_oauth";
  const isCodexDeviceFlow =
    isDeviceFlow && definition.id === "system_openai_codex";
  // requiresOperatorName is true only when the selected credential carries no provider-issued display identity.
  // requiresOperatorName 仅在所选凭据不携带供应商签发的显示身份时为 true。
  const requiresOperatorName =
    !reauthorizationTarget &&
    (authMethod?.type === "api_key" ||
      (isDeviceFlow &&
        (definition.id === "system_kimi_coding_plan" || isXAIDeviceFlow)));
  // name is the sole operator-authored label and is reused by the server for the instance and credential.
  // name 是唯一由操作员填写的标签，并由服务端同时用于实例与凭据。
  const [name, setName] = useState(
    reauthorizationTarget?.credential.label ?? definition.display_name,
  );
  const [secret, setSecret] = useState("");
  // endpointPreset is the exact code-owned destination selected by this definition.
  // endpointPreset 是此 Definition 选择的精确代码拥有目标。
  const endpointPreset = definition.endpoint_presets[0];
  // endpointParameterValues stores only declared non-secret values keyed by their immutable identifiers.
  // endpointParameterValues 仅按不可变标识存储已声明的非秘密值。
  const [endpointParameterValues, setEndpointParameterValues] = useState<
    Record<string, string>
  >(() =>
    Object.fromEntries(
      (endpointPreset?.parameters ?? []).map((parameter) => [parameter.id, ""]),
    ),
  );
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
  // credentialWorkflowFailureKey distinguishes replacement failures from new-provider creation failures.
  // credentialWorkflowFailureKey 区分凭据替换失败与新增供应商失败。
  const credentialWorkflowFailureKey: TranslationKey = reauthorizationTarget
    ? "providers.reauthorizationFailed"
    : "providers.onboardingFailed";

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
      setMessageKey(credentialWorkflowFailureKey);
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
        ...(reauthorizationTarget
          ? {
              provider_instance_id: reauthorizationTarget.providerInstanceID,
              credential_id: reauthorizationTarget.credential.id,
            }
          : {}),
      });
      oauthFlowRef.current = null;
      setOAuthFlow(null);
      setOAuthCallbackURL("");
      onComplete();
    } catch {
      setMessageKey(credentialWorkflowFailureKey);
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
      setMessageKey(credentialWorkflowFailureKey);
    } finally {
      setPending(false);
    }
  }

  // submitAPIKey sends one plaintext key only to the authenticated atomic onboarding endpoint.
  // submitAPIKey 仅将一个明文密钥发送到经过认证的原子录入端点。
  async function submitAPIKey(event: FormEvent) {
    event.preventDefault();
    if (!authMethod || !isDirectSecretAuth) {
      setMessageKey("providers.unsupportedAuthentication");
      return;
    }
    if (authMethod.plan_acquisition === "manual_required" && !planOptionID) {
      setMessageKey("providers.selectMembershipPlan");
      return;
    }
    setPending(true);
    setMessageKey(null);
    try {
      // endpointParameters serializes only the exact fields declared by the selected code-owned preset.
      // endpointParameters 仅序列化所选代码拥有预设声明的精确字段。
      const endpointParameters = (endpointPreset?.parameters ?? []).map(
        (parameter) => ({
          id: parameter.id,
          value: endpointParameterValues[parameter.id].trim(),
        }),
      );
      if (reauthorizationTarget) {
        await rotateProviderCredentialSecret(
          managementAuthToken,
          reauthorizationTarget.providerInstanceID,
          reauthorizationTarget.credential.id,
          secret,
        );
      } else {
        await onboardSystemProvider(managementAuthToken, {
          provider_definition_id: definition.id,
          name: name.trim(),
          auth_method_id: authMethodID,
          secret,
          ...(planOptionID &&
          (authMethod.plan_acquisition === "manual_required" ||
            authMethod.plan_acquisition === "manual_optional")
            ? { plan_option_id: planOptionID }
            : {}),
          ...(endpointParameters.length > 0
            ? { endpoint_parameters: endpointParameters }
            : {}),
        });
      }
      setSecret("");
      onComplete();
    } catch {
      setMessageKey(credentialWorkflowFailureKey);
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
        ...(reauthorizationTarget
          ? {
              provider_instance_id: reauthorizationTarget.providerInstanceID,
              credential_id: reauthorizationTarget.credential.id,
            }
          : {}),
      });
      setSecret("");
      onComplete();
    } catch {
      setMessageKey(credentialWorkflowFailureKey);
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
      setMessageKey(credentialWorkflowFailureKey);
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
        ...(reauthorizationTarget
          ? {
              provider_instance_id: reauthorizationTarget.providerInstanceID,
              credential_id: reauthorizationTarget.credential.id,
            }
          : {}),
      });
      if (result === null) {
        setMessageKey("providers.authorizationPending");
      } else {
        deviceFlowRef.current = null;
        setDeviceFlow(null);
        onComplete();
      }
    } catch {
      setMessageKey(credentialWorkflowFailureKey);
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
      setMessageKey(credentialWorkflowFailureKey);
    } finally {
      setPending(false);
    }
  }

  // selectAuthMethod releases any unfinished flow before changing the exact credential acquisition method.
  // selectAuthMethod 在切换精确凭据获取方式前释放任何未完成授权流程。
  function selectAuthMethod(methodID: string) {
    if (reauthorizationTarget) return;
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
    setPlanOptionID(
      definition.plan_options.find(
        (option) =>
          option.manually_selectable &&
          option.auth_method_ids.includes(methodID),
      )?.id ?? "",
    );
    setDeviceFlow(null);
    oauthFlowRef.current = null;
    setOAuthFlow(null);
    setOAuthCallbackURL("");
    setSecret("");
    setEndpointParameterValues(
      Object.fromEntries(
        (endpointPreset?.parameters ?? []).map((parameter) => [
          parameter.id,
          "",
        ]),
      ),
    );
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
          {!reauthorizationTarget && definition.auth_methods.length > 1 ? (
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
              {!reauthorizationTarget ? (
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
              ) : null}
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
          {authMethod?.type === "api_key" && !reauthorizationTarget
            ? (endpointPreset?.parameters ?? []).map((parameter) => (
                <div className="space-y-2" key={parameter.id}>
                  <Label htmlFor={`endpoint-parameter-${parameter.id}`}>
                    {parameter.id === "workspace_id"
                      ? t("providers.workspaceID")
                      : parameter.id}
                  </Label>
                  <Input
                    id={`endpoint-parameter-${parameter.id}`}
                    value={endpointParameterValues[parameter.id]}
                    onChange={(event) =>
                      setEndpointParameterValues((current) => ({
                        ...current,
                        [parameter.id]: event.target.value,
                      }))
                    }
                    required={parameter.required}
                    maxLength={63}
                    pattern="[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
                    title={t("providers.workspaceIDHelp")}
                    autoComplete="off"
                    spellCheck={false}
                  />
                  <p className="text-muted-foreground text-xs">
                    {t("providers.workspaceIDHelp")}
                  </p>
                </div>
              ))
            : null}
          {authMethod?.type === "api_key" &&
          !reauthorizationTarget &&
          (authMethod.plan_acquisition === "manual_required" ||
            authMethod.plan_acquisition === "manual_optional") ? (
            <div className="space-y-2">
              <Label htmlFor="provider-membership-plan">
                {t("providers.membershipPlan")}
              </Label>
              <Select
                value={planOptionID}
                onValueChange={(value) => {
                  if (value !== null) setPlanOptionID(value);
                }}
              >
                <SelectTrigger id="provider-membership-plan" className="w-full">
                  <SelectValue
                    placeholder={t("providers.selectMembershipPlan")}
                  />
                </SelectTrigger>
                <SelectContent>
                  {selectablePlanOptions.map((option) => (
                    <SelectItem key={option.id} value={option.id}>
                      {option.display_name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-muted-foreground text-xs">
                {t("providers.membershipPlanHelp")}
              </p>
            </div>
          ) : null}
          <div className="md:col-span-2">
            {!isDeviceFlow && !isBrowserOAuth ? (
              <Button
                type="submit"
                disabled={
                  pending ||
                  (!reauthorizationTarget &&
                    authMethod.plan_acquisition === "manual_required" &&
                    !planOptionID)
                }
              >
                {reauthorizationTarget
                  ? t("providers.replaceCredential")
                  : t("providers.onboard")}
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
