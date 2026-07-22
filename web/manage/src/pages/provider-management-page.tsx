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
import type { SearchServiceTestTarget } from "@/components/search-service-test-dialog";
import type { ExtractServiceTestTarget } from "@/components/extract-service-test-dialog";
import {
  ServiceTestDialog,
  type ServiceTestTarget,
} from "@/components/service-test-dialog";
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
import { ReadonlyCombobox } from "@/components/ui/readonly-combobox";
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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { type TranslationKey, useI18n } from "@/i18n";
import { ProviderIcon } from "@/lib/provider-icons";
import {
  cancelAntigravityOAuthFlow,
  cancelClaudeOAuthFlow,
  cancelCodexOAuthFlow,
  cancelKimiDeviceFlow,
  cancelMiniMaxDeviceFlow,
  cancelCodexDeviceFlow,
  cancelXAIDeviceFlow,
  attachProviderCredential,
  deleteProviderCredential,
  fetchAuthorizedProviders,
  fetchProviderBindings,
  fetchCustomProtocolProfiles,
  fetchProviderCatalog,
  fetchProviderDefinitions,
  fetchProviderEndpoints,
  fetchProviderFiles,
  fetchProviderGroups,
  onboardAntigravityOAuthFlow,
  onboardClaudeOAuthFlow,
  onboardCodexOAuthFlow,
  onboardKimiDeviceFlow,
  onboardMiniMaxDeviceFlow,
  onboardCodexDeviceFlow,
  onboardXAIDeviceFlow,
  onboardCustomProvider,
  onboardSystemProvider,
  onboardVertexServiceAccount,
  providerCatalogHasModels,
  refreshProviderCredential,
  refreshProviderMetadata,
  rotateProviderCredentialSecret,
  startAntigravityOAuthFlow,
  startClaudeOAuthFlow,
  startCodexOAuthFlow,
  startKimiDeviceFlow,
  startMiniMaxDeviceFlow,
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
  type ProviderEndpoint,
  type ProviderFileDiagnostic,
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
  // mode preserves the legacy onboarding-catalog test surface while the credential route selects the separated workspace.
  // mode 保留旧录入目录测试表面，同时允许凭据路由选择拆分后的工作区。
  mode?: "provider" | "credential";
}

// CredentialProviderDefinition joins every selectable provider definition with its ownership kind.
// CredentialProviderDefinition 将每个可选择供应商 Definition 与其所有权类型组合起来。
interface CredentialProviderDefinition extends ProviderDefinitionIdentity {
  // kind distinguishes code-owned providers from user-owned custom providers.
  // kind 区分代码拥有供应商与用户拥有的自定义供应商。
  kind: "system" | "custom";
  // endpoint_presets preserves code-owned endpoint parameters required during first credential onboarding.
  // endpoint_presets 保留首次凭据录入期间所需的代码拥有入口参数。
  endpoint_presets?: ProviderDefinition["endpoint_presets"];
  // variant_name is the category-local site or product label authored by native provider groups.
  // variant_name 是原生供应商分组编写的分类内站点或产品标签。
  variant_name?: string;
  // variant_description explains the exact site or product when authored by the server catalog.
  // variant_description 在服务端目录提供时说明精确站点或产品。
  variant_description?: string;
  // variant_description_key identifies the localized description for one native subtype.
  // variant_description_key 标识一个原生子类的本地化说明。
  variant_description_key?: string;
}

// CredentialProviderCategory represents one top-level provider family in credential navigation.
// CredentialProviderCategory 表示凭据导航中的一个顶层供应商大类。
interface CredentialProviderCategory {
  // id is the frontend-stable category identity derived from an authoritative group or custom definition.
  // id 是从权威分组或自定义 Definition 派生的前端稳定分类标识。
  id: string;
  // display_name is the top-level provider name shown in the left directory.
  // display_name 是左侧目录显示的顶层供应商名称。
  display_name: string;
  // kind distinguishes native grouped providers from user-owned custom providers.
  // kind 区分原生分组供应商与用户拥有的自定义供应商。
  kind: "system" | "custom";
  // group_id binds native category icons without leaking presentation ownership into the backend.
  // group_id 绑定原生分类图标，且不将展示职责泄漏到后端。
  group_id?: string;
  // definitions contains the exact subtypes selected only during credential creation.
  // definitions 包含仅在创建凭据时选择的精确子类。
  definitions: CredentialProviderDefinition[];
}

// CredentialReauthorizationSelection binds one local credential to its immutable provider definition.
// CredentialReauthorizationSelection 将一个本地凭据绑定到其不可变供应商定义。
export interface CredentialReauthorizationSelection {
  // providerInstanceID owns the credential.
  // providerInstanceID 拥有该凭据。
  providerInstanceID: string;
  // credential is the exact management-safe credential.
  // credential 是精确的管理端安全凭据。
  credential: ProviderCredential;
}

// CredentialAttachmentSelection identifies an existing provider configuration receiving a new credential.
// CredentialAttachmentSelection 标识接收新凭据的既有供应商配置。
export interface CredentialAttachmentSelection {
  // providerInstanceID is the credential-independent provider configuration root.
  // providerInstanceID 是独立于凭据的供应商配置根。
  providerInstanceID: string;
}

// ProviderManagementPage renders grouped system providers and exact site or plan selection.
// ProviderManagementPage 渲染已分组系统供应商及精确站点或套餐选择。
export function ProviderManagementPage({
  managementAuthToken,
  mode = "provider",
}: ProviderManagementPageProps) {
  const { t } = useI18n();
  // credentialMode enables the separated provider-tree and credential-card workspace.
  // credentialMode 启用拆分后的供应商树与凭据卡片工作区。
  const credentialMode = mode === "credential";
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
  // authorizedProviders contains every configured instance and its redacted credential list.
  // authorizedProviders 包含每个已配置实例及其脱敏凭据列表。
  const [authorizedProviders, setAuthorizedProviders] = useState<
    AuthorizedProvider[]
  >([]);
  // selectedCredentialCategoryID identifies the top-level provider family selected in the credential directory.
  // selectedCredentialCategoryID 标识凭据目录中选中的顶层供应商大类。
  const [selectedCredentialCategoryID, setSelectedCredentialCategoryID] =
    useState("");
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
  // attachmentTarget identifies an existing provider configuration receiving a new credential.
  // attachmentTarget 标识接收新凭据的既有供应商配置。
  const [attachmentTarget, setAttachmentTarget] =
    useState<CredentialAttachmentSelection | null>(null);
  // credentialIntent reports that credential creation must also create the first system-provider instance.
  // credentialIntent 表示新增凭据还必须创建首个系统供应商实例。
  const [credentialIntent, setCredentialIntent] = useState(false);
  // credentialCreationCategoryID preserves the selected top-level category while its subtype is chosen in the dialog.
  // credentialCreationCategoryID 在 Dialog 中选择子类期间保留所选顶层分类。
  const [credentialCreationCategoryID, setCredentialCreationCategoryID] =
    useState("");
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

  useEffect(() => {
    // controller cancels only local cached-catalog reads when the provider inventory changes or the page unmounts.
    // controller 仅在供应商清单变化或页面卸载时取消本地缓存目录读取。
    const controller = new AbortController();
    if (authorizedProviders.length === 0) {
      setProviderMetadata({});
      return () => controller.abort();
    }
    // activeProviderIDs prevents removed provider snapshots from surviving a refreshed authorization inventory.
    // activeProviderIDs 防止已删除供应商的快照残留在刷新的授权清单中。
    const activeProviderIDs = new Set(
      authorizedProviders.map((provider) => provider.instance.id),
    );
    Promise.all(
      authorizedProviders.map(async (provider) => {
        try {
          // metadata is loaded from the persisted local catalog and never invokes an upstream provider.
          // metadata 从持久化本地目录读取，绝不调用上游供应商。
          const metadata = await fetchProviderCatalog(
            managementAuthToken,
            provider.instance.id,
            controller.signal,
          );
          return [provider.instance.id, metadata] as const;
        } catch {
          return null;
        }
      }),
    ).then((entries) => {
      if (controller.signal.aborted) return;
      setProviderMetadata((current) => {
        // next retains only active instances and never replaces a newer explicit refresh with an older cached response.
        // next 仅保留活跃实例，且绝不使用更旧缓存响应覆盖更新的显式刷新。
        const next: Record<string, ProviderCatalogMetadata> = {};
        for (const [providerInstanceID, metadata] of Object.entries(current)) {
          if (activeProviderIDs.has(providerInstanceID)) {
            next[providerInstanceID] = metadata;
          }
        }
        for (const entry of entries) {
          if (!entry) continue;
          const [providerInstanceID, metadata] = entry;
          if (
            !next[providerInstanceID] ||
            metadata.revision >= next[providerInstanceID].revision
          ) {
            next[providerInstanceID] = metadata;
          }
        }
        return next;
      });
    });
    return () => controller.abort();
  }, [authorizedProviders, managementAuthToken]);

  // credentialCategories is the custom-first top-level directory followed by native provider families.
  // credentialCategories 是自定义供应商优先、随后为原生供应商大类的顶层目录。
  const credentialCategories = buildCredentialProviderCategories(
    definitions,
    groups,
  );
  // defaultCredentialCategory is the first category with configured account data, otherwise the first supported category.
  // defaultCredentialCategory 是首个拥有已配置账号数据的分类，否则为首个受支持分类。
  const defaultCredentialCategory =
    credentialCategories.find((category) =>
      category.definitions.some((definition) =>
        authorizedProviders.some(
          (provider) => provider.instance.definition_id === definition.id,
        ),
      ),
    ) ?? credentialCategories[0];
  // activeCredentialCategoryID avoids an empty intermediate workspace while asynchronous inventories settle.
  // activeCredentialCategoryID 在异步清单稳定期间避免出现空白的中间工作区。
  const activeCredentialCategoryID = credentialCategories.some(
    (category) => category.id === selectedCredentialCategoryID,
  )
    ? selectedCredentialCategoryID
    : (defaultCredentialCategory?.id ?? "");

  useEffect(() => {
    if (!credentialMode) return;
    setSelectedCredentialCategoryID((current) => {
      if (credentialCategories.some((category) => category.id === current)) {
        return current;
      }
      return defaultCredentialCategory?.id ?? "";
    });
  }, [authorizedProviders, credentialMode, definitions, groups]);

  // selectedDefinition is the exact immutable variant passed to the onboarding command.
  // selectedDefinition 是传递给录入命令的精确不可变变体。
  const selectedDefinition =
    groups
      .flatMap((group) => group.provider_definitions)
      .find((definition) => definition.id === selectedDefinitionID) ??
    definitions.find((definition) => definition.id === selectedDefinitionID);
  // selectedCredentialCategory is the top-level native family or custom provider selected in the directory.
  // selectedCredentialCategory 是目录中选中的顶层原生系列或自定义供应商。
  const selectedCredentialCategory = credentialCategories.find(
    (category) => category.id === activeCredentialCategoryID,
  );
  // selectedCredentialProviders contains every configured subtype instance owned by the selected category.
  // selectedCredentialProviders 包含所选大类拥有的每个已配置子类实例。
  const selectedCredentialProviders = authorizedProviders.filter((provider) =>
    selectedCredentialCategory?.definitions.some(
      (definition) => definition.id === provider.instance.definition_id,
    ),
  );
  // credentialCreationCategory is the top-level category whose subtype chooser is active in the dialog.
  // credentialCreationCategory 是其子类选择器当前显示在 Dialog 中的顶层分类。
  const credentialCreationCategory = credentialCategories.find(
    (category) => category.id === credentialCreationCategoryID,
  );
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
    setAttachmentTarget(null);
    setCredentialIntent(false);
    setCredentialCreationCategoryID("");
  }

  // beginCredentialAttachment opens the authorization workflow for the selected existing provider configuration.
  // beginCredentialAttachment 为所选既有供应商配置打开授权流程。
  function beginCredentialAttachment(provider: AuthorizedProvider): void {
    setAttachmentTarget({
      providerInstanceID: provider.instance.id,
    });
    setCredentialIntent(false);
    setCredentialCreationCategoryID("");
    setSelectedDefinitionID(provider.instance.definition_id);
    setAdding(true);
  }

  // beginSelectedCredentialCreation opens subtype selection for native families or direct attachment for one custom instance.
  // beginSelectedCredentialCreation 为原生大类打开子类选择，或为一个自定义实例直接打开凭据附加流程。
  function beginSelectedCredentialCreation(): void {
    if (!selectedCredentialCategory) return;
    if (
      selectedCredentialCategory.kind === "custom" &&
      selectedCredentialProviders.length === 1
    ) {
      beginCredentialAttachment(selectedCredentialProviders[0]);
      return;
    }
    if (selectedCredentialCategory.kind === "system") {
      setAttachmentTarget(null);
      setReauthorizationTarget(null);
      setCredentialIntent(false);
      setSelectedDefinitionID("");
      setCredentialCreationCategoryID(selectedCredentialCategory.id);
      setAdding(true);
    }
  }

  // selectCredentialSubtype resolves one native subtype to its existing instance or first-onboarding workflow.
  // selectCredentialSubtype 将一个原生子类解析到其既有实例或首次录入流程。
  function selectCredentialSubtype(definitionID: string): void {
    if (!credentialCreationCategory) return;
    // definition is selected only from the active category's authoritative subtype set.
    // definition 仅从当前分类的权威子类集合中选择。
    const definition = credentialCreationCategory.definitions.find(
      (candidate) => candidate.id === definitionID,
    );
    if (!definition) return;
    // configuredProviders identifies the exact existing subtype configuration, if present.
    // configuredProviders 标识该精确子类已有的配置（如存在）。
    const configuredProviders = authorizedProviders.filter(
      (provider) => provider.instance.definition_id === definition.id,
    );
    if (configuredProviders.length === 1) {
      setAttachmentTarget({
        providerInstanceID: configuredProviders[0].instance.id,
      });
      setCredentialIntent(false);
    } else if (configuredProviders.length === 0) {
      setAttachmentTarget(null);
      setCredentialIntent(true);
    } else {
      return;
    }
    setSelectedDefinitionID(definition.id);
  }

  // beginCredentialReauthorization opens the exact provider workflow for one existing credential.
  // beginCredentialReauthorization 为一个既有凭据打开精确供应商工作流。
  function beginCredentialReauthorization(
    providerInstanceID: string,
    definitionID: string,
    credential: ProviderCredential,
  ) {
    setReauthorizationTarget({ providerInstanceID, credential });
    setAttachmentTarget(null);
    setCredentialCreationCategoryID("");
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

  // returnToCredentialSubtypeSelection leaves authorization while preserving the selected native provider category.
  // returnToCredentialSubtypeSelection 离开授权步骤，同时保留选中的原生供应商大类。
  function returnToCredentialSubtypeSelection(): void {
    setSelectedDefinitionID("");
    setAttachmentTarget(null);
    setCredentialIntent(false);
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

  // renderAuthorizedProviderCard binds one exact provider instance to shared credential operations.
  // renderAuthorizedProviderCard 将一个精确供应商实例绑定到共用凭据操作。
  function renderAuthorizedProviderCard(provider: AuthorizedProvider) {
    // definition is the authoritative product metadata associated with this configured instance.
    // definition 是与此已配置实例关联的权威产品元数据。
    const definition = findProviderDefinition(
      definitions,
      groups,
      provider.instance.definition_id,
    );
    return (
      <AuthorizedProviderCard
        key={provider.instance.id}
        provider={provider}
        definition={definition}
        metadata={providerMetadata[provider.instance.id]}
        refreshingMetadata={refreshingMetadataIDs.has(provider.instance.id)}
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
        onAddCredential={
          credentialMode && selectedCredentialProviders.length > 1
            ? () => beginCredentialAttachment(provider)
            : undefined
        }
      />
    );
  }

  return (
    <div className="flex flex-col gap-6 p-4 lg:p-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h2 className="text-2xl font-semibold tracking-tight">
            {t(credentialMode ? "credentials.title" : "providers.title")}
          </h2>
          <p className="text-muted-foreground mt-1 text-sm">
            {t(
              credentialMode
                ? "credentials.description"
                : "providers.authorizedDescription",
            )}
          </p>
        </div>
        {!adding &&
        !loading &&
        !catalogFailed &&
        (!credentialMode ||
          (selectedCredentialCategory &&
            ((selectedCredentialCategory.kind === "system" &&
              selectedCredentialCategory.definitions.length > 0) ||
              (selectedCredentialCategory.kind === "custom" &&
                selectedCredentialProviders.length === 1)))) ? (
          <Button
            onClick={
              credentialMode
                ? beginSelectedCredentialCreation
                : () => setAdding(true)
            }
          >
            <PlusIcon className="size-4" />
            {t(credentialMode ? "providers.addCredential" : "providers.add")}
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
        credentialMode ? (
          credentialCategories.length > 0 ? (
            <div className="grid min-h-[32rem] overflow-hidden rounded-xl border lg:grid-cols-[16rem_minmax(0,1fr)]">
              <aside className="border-b bg-muted/20 p-2 lg:border-b-0 lg:border-r">
                <div
                  className="space-y-1"
                  role="tree"
                  aria-label={t("credentials.title")}
                >
                  {credentialCategories.map((category) => {
                    // configuredProviders contains every configured subtype owned by this top-level category.
                    // configuredProviders 包含此顶层大类拥有的每个已配置子类。
                    const configuredProviders = authorizedProviders.filter(
                      (provider) =>
                        category.definitions.some(
                          (definition) =>
                            definition.id === provider.instance.definition_id,
                        ),
                    );
                    // credentialCount summarizes every account attached across all category subtypes.
                    // credentialCount 汇总此大类所有子类附加的账号。
                    const credentialCount = configuredProviders.reduce(
                      (count, provider) => count + provider.credentials.length,
                      0,
                    );
                    const selected = category.id === activeCredentialCategoryID;
                    return (
                      <button
                        key={category.id}
                        type="button"
                        role="treeitem"
                        aria-selected={selected}
                        className={`flex w-full items-center justify-between gap-2 rounded-md px-3 py-2 text-left text-sm transition-colors ${selected ? "bg-muted/80 text-foreground ring-1 ring-inset ring-border" : "hover:bg-muted"}`}
                        onClick={() =>
                          setSelectedCredentialCategoryID(category.id)
                        }
                      >
                        <span className="flex min-w-0 items-center gap-2.5">
                          <ProviderIcon
                            definitionID={category.definitions[0]?.id}
                            groupID={category.group_id}
                            className="size-[26px]"
                          />
                          <span className="min-w-0 truncate font-medium">
                            {category.display_name}
                          </span>
                        </span>
                        <Badge variant="secondary">{credentialCount}</Badge>
                      </button>
                    );
                  })}
                </div>
              </aside>
              <main className="min-w-0 p-3 lg:p-4">
                {selectedCredentialProviders.length > 0 ? (
                  <CredentialManagementTable
                    providers={selectedCredentialProviders}
                    definitions={definitions}
                    groups={groups}
                    metadataByProviderID={providerMetadata}
                    managementAuthToken={managementAuthToken}
                    refreshingMetadataIDs={refreshingMetadataIDs}
                    metadataErrors={metadataErrors}
                    refreshingCredentialIDs={refreshingCredentialIDs}
                    credentialRefreshErrors={credentialRefreshErrors}
                    deletingCredentialIDs={deletingCredentialIDs}
                    onRefreshMetadata={refreshAccountMetadata}
                    onRefreshCredential={refreshAccountCredential}
                    onChangeCredentialPriority={changeCredentialPriority}
                    onChangeCredentialPlan={changeCredentialPlan}
                    onReauthorizeCredential={beginCredentialReauthorization}
                    onDeleteCredential={deleteCredential}
                    onAddCredential={beginCredentialAttachment}
                  />
                ) : selectedCredentialCategory ? (
                  <Card>
                    <CardContent className="flex flex-col items-center gap-3 py-12 text-center">
                      <ProviderIcon
                        definitionID={
                          selectedCredentialCategory.definitions[0]?.id
                        }
                        groupID={selectedCredentialCategory.group_id}
                        className="size-8"
                      />
                      <div>
                        <p className="font-medium">
                          {selectedCredentialCategory.display_name}
                        </p>
                        <p className="text-muted-foreground mt-1 text-sm">
                          {t(
                            selectedCredentialCategory.kind === "custom"
                              ? "credentials.configureCustomFirst"
                              : "providers.noCredentialsForProvider",
                          )}
                        </p>
                      </div>
                    </CardContent>
                  </Card>
                ) : null}
              </main>
            </div>
          ) : (
            <Card>
              <CardContent className="flex flex-col items-center gap-2 py-12 text-center">
                <ShieldCheckIcon className="text-muted-foreground size-8" />
                <p className="font-medium">{t("credentials.noProviders")}</p>
              </CardContent>
            </Card>
          )
        ) : authorizedProviders.length > 0 ? (
          <div className="grid gap-4 lg:grid-cols-2">
            {authorizedProviders.map(renderAuthorizedProviderCard)}
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
          <DialogContent
            className={
              credentialMode
                ? "max-h-[min(80vh,600px)] grid-rows-[auto_minmax(0,1fr)] overflow-hidden"
                : "h-[min(80vh,600px)] max-h-[min(80vh,600px)] grid-rows-[auto_minmax(0,1fr)] overflow-hidden"
            }
          >
            <DialogHeader>
              {(credentialCreationCategory && selectedDefinition) ||
              ((selectedDefinition || configuringCustom) &&
                !attachmentTarget &&
                !reauthorizationTarget &&
                !credentialIntent) ? (
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  aria-label={t("providers.backToProviders")}
                  onClick={
                    credentialCreationCategory
                      ? returnToCredentialSubtypeSelection
                      : returnToProviderCatalog
                  }
                >
                  <ArrowLeftIcon className="size-4" />
                </Button>
              ) : null}
              <div className="min-w-0 flex-1">
                <DialogTitle>
                  {reauthorizationTarget
                    ? t("providers.reauthorizeCredential")
                    : attachmentTarget ||
                        credentialIntent ||
                        credentialCreationCategory
                      ? t("providers.addCredential")
                      : selectedDefinition || configuringCustom
                        ? t("providers.configureProvider")
                        : t("providers.add")}
                </DialogTitle>
                <DialogDescription>
                  {selectedDefinition
                    ? selectedDefinition.display_name
                    : credentialCreationCategory
                      ? credentialCreationCategory.display_name
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

            {!selectedDefinition && credentialCreationCategory ? (
              <div className="min-h-0 overflow-y-auto">
                <div className="grid overflow-hidden rounded-lg border">
                  {credentialCreationCategory.definitions.map((definition) => (
                    <CredentialSubtypeSelectionRow
                      key={definition.id}
                      definition={definition}
                      onSelect={selectCredentialSubtype}
                    />
                  ))}
                </div>
              </div>
            ) : !selectedDefinition && !configuringCustom ? (
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
                    attachmentTarget={attachmentTarget}
                    credentialIntent={credentialIntent}
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

// findProviderDefinition resolves one configured instance to the exact server-authored definition used for icon and credential presentation.
// findProviderDefinition 将一个已配置实例解析到用于图标与凭据展示的精确服务端 Definition。
function findProviderDefinition(
  definitions: ProviderDefinitionSummary[],
  groups: ProviderGroup[],
  definitionID: string,
): ProviderDefinitionIdentity | undefined {
  return (
    definitions.find((definition) => definition.id === definitionID) ??
    groups
      .flatMap((group) => group.provider_definitions)
      .find((definition) => definition.id === definitionID)
  );
}

// buildCredentialProviderCategories returns custom providers and native families as top-level credential navigation entries.
// buildCredentialProviderCategories 将自定义供应商与原生供应商大类作为顶层凭据导航项返回。
function buildCredentialProviderCategories(
  definitions: ProviderDefinitionSummary[],
  groups: ProviderGroup[],
): CredentialProviderCategory[] {
  // categories preserves custom-first presentation while retaining server-authored native group order.
  // categories 保持自定义供应商优先展示，同时保留服务端编写的原生分组顺序。
  const categories: CredentialProviderCategory[] = [];
  // seenDefinitionIDs prevents grouped and ungrouped inventories from duplicating one native subtype.
  // seenDefinitionIDs 防止分组与未分组清单重复展示同一个原生子类。
  const seenDefinitionIDs = new Set<string>();

  for (const definition of definitions) {
    if (definition.kind !== "custom") continue;
    seenDefinitionIDs.add(definition.id);
    categories.push({
      id: `custom:${definition.id}`,
      display_name: definition.display_name,
      kind: "custom",
      group_id: definition.group_id,
      definitions: [definition],
    });
  }
  for (const group of groups) {
    // groupDefinitions contains the exact native subtypes owned by this server-authored provider family.
    // groupDefinitions 包含此服务端编写供应商大类拥有的精确原生子类。
    const groupDefinitions = group.provider_definitions.map((definition) => {
      seenDefinitionIDs.add(definition.id);
      return { ...definition, kind: "system" as const };
    });
    if (groupDefinitions.length > 0) {
      categories.push({
        id: `system-group:${group.id}`,
        display_name: group.display_name,
        kind: "system",
        group_id: group.id,
        definitions: groupDefinitions,
      });
    }
  }
  for (const definition of definitions) {
    if (definition.kind !== "system" || seenDefinitionIDs.has(definition.id)) {
      continue;
    }
    seenDefinitionIDs.add(definition.id);
    categories.push({
      id: `system-definition:${definition.id}`,
      display_name: definition.display_name,
      kind: "system",
      group_id: definition.group_id,
      definitions: [definition],
    });
  }
  return categories;
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
            <ProviderIcon className="size-[26px]" />
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
            <ProviderIcon groupID={group.id} className="size-[26px]" />
          </span>
          <span className="min-w-0 flex-1">
            <span className="block font-semibold">{group.display_name}</span>
            <span className="mt-1 flex flex-wrap gap-1.5">
              {badges.map((badge) => (
                <Badge key={badge} variant="default" className="rounded-sm">
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
  return group.provider_definitions.map(
    (definition) => definition.variant_name,
  );
}

// CredentialManagementTableProps defines the compact credential-only workspace contract.
// CredentialManagementTableProps 定义紧凑凭据专用工作区的契约。
interface CredentialManagementTableProps {
  // providers contains configured instances belonging to the selected credential category.
  // providers 包含属于当前所选凭据分类的已配置实例。
  providers: AuthorizedProvider[];
  // definitions resolves each configured instance to server-owned authentication and plan metadata.
  // definitions 将每个已配置实例解析为服务端拥有的认证与套餐元数据。
  definitions: ProviderDefinitionSummary[];
  // groups supplies native definition metadata that is not repeated in the ungrouped inventory.
  // groups 提供未在未分组清单中重复的原生定义元数据。
  groups: ProviderGroup[];
  // metadataByProviderID stores the latest management-safe provider catalog snapshot by immutable instance identifier.
  // metadataByProviderID 按不可变实例标识保存最新的管理安全供应商目录快照。
  metadataByProviderID: Readonly<Record<string, ProviderCatalogMetadata>>;
  // managementAuthToken authorizes protected resource metadata reads without retaining it in dialog state.
  // managementAuthToken 授权受保护资源元数据读取，且不会将其保留在对话框状态中。
  managementAuthToken: string;
  // refreshingMetadataIDs identifies instances with an active provider-native metadata refresh.
  // refreshingMetadataIDs 标识正在执行供应商原生元数据刷新的实例。
  refreshingMetadataIDs: ReadonlySet<string>;
  // metadataErrors contains safe per-instance metadata refresh failures.
  // metadataErrors 包含安全的按实例划分的元数据刷新失败。
  metadataErrors: Readonly<Record<string, string>>;
  // refreshingCredentialIDs identifies credentials with an active refresh request.
  // refreshingCredentialIDs 标识正在执行刷新请求的凭据。
  refreshingCredentialIDs: ReadonlySet<string>;
  // credentialRefreshErrors contains safe per-credential refresh failures.
  // credentialRefreshErrors 包含安全的按凭据划分的刷新失败。
  credentialRefreshErrors: Readonly<Record<string, string>>;
  // deletingCredentialIDs identifies credentials pending confirmed deletion.
  // deletingCredentialIDs 标识正在等待确认删除完成的凭据。
  deletingCredentialIDs: ReadonlySet<string>;
  // onRefreshMetadata refreshes one exact provider-native catalog snapshot.
  // onRefreshMetadata 刷新一个精确供应商原生目录快照。
  onRefreshMetadata: (providerInstanceID: string) => Promise<void>;
  // onRefreshCredential refreshes one exact local provider credential.
  // onRefreshCredential 刷新一个精确的本地供应商凭据。
  onRefreshCredential: (
    providerInstanceID: string,
    credentialID: string,
  ) => void;
  // onChangeCredentialPriority persists one confirmed nonnegative credential ordering value.
  // onChangeCredentialPriority 持久化一个已确认的非负凭据排序值。
  onChangeCredentialPriority: (
    providerInstanceID: string,
    credentialID: string,
    priority: number,
  ) => Promise<void>;
  // onChangeCredentialPlan persists one definition-owned manual plan selection.
  // onChangeCredentialPlan 持久化一个由定义拥有的人工套餐选择。
  onChangeCredentialPlan: (
    providerInstanceID: string,
    credentialID: string,
    planOptionID: string,
  ) => Promise<void>;
  // onReauthorizeCredential opens the exact existing credential acquisition workflow.
  // onReauthorizeCredential 打开精确既有凭据的获取工作流。
  onReauthorizeCredential: (
    providerInstanceID: string,
    definitionID: string,
    credential: ProviderCredential,
  ) => void;
  // onDeleteCredential deletes one confirmed credential.
  // onDeleteCredential 删除一个已确认的凭据。
  onDeleteCredential: (
    providerInstanceID: string,
    credentialID: string,
  ) => Promise<void>;
  // onAddCredential opens attachment for an existing provider instance.
  // onAddCredential 为既有供应商实例打开凭据附加流程。
  onAddCredential: (provider: AuthorizedProvider) => void;
}

// CredentialPriorityEditTarget identifies the only credential permitted to receive the currently open priority update.
// CredentialPriorityEditTarget 标识当前打开的优先级更新唯一允许作用的凭据。
interface CredentialPriorityEditTarget {
  // providerInstanceID owns the exact local credential.
  // providerInstanceID 拥有精确的本地凭据。
  providerInstanceID: string;
  // credential is the management-safe credential shown by the table row.
  // credential 是由表格行展示的管理安全凭据。
  credential: ProviderCredential;
}

// CredentialResourceDialogTarget scopes a resource dialog to one provider credential and its exact definition.
// CredentialResourceDialogTarget 将资源对话框限定到一个供应商凭据及其精确定义。
interface CredentialResourceDialogTarget {
  // provider owns the selected credential.
  // provider 拥有已选凭据。
  provider: AuthorizedProvider;
  // definition authoritatively describes provider-specific resource support when available.
  // definition 在可用时权威描述供应商专用资源支持。
  definition?: ProviderDefinitionIdentity;
  // credential is the selected account whose resources may be listed.
  // credential 是可以列出资源的已选账号。
  credential: ProviderCredential;
}

// ProviderResourceFileGroup keeps provider files separate by their exact configured endpoint.
// ProviderResourceFileGroup 按其精确配置端点分离供应商文件。
interface ProviderResourceFileGroup {
  // endpoint is the management-safe configured upstream target that produced the listing.
  // endpoint 是产生该列表的管理安全已配置上游目标。
  endpoint: ProviderEndpoint;
  // files contains only redacted file metadata and never file content.
  // files 仅包含脱敏文件元数据，绝不包含文件内容。
  files: ProviderFileDiagnostic[];
}

// CredentialManagementTable renders credential rows with only account-facing controls and on-demand detail dialogs.
// CredentialManagementTable 渲染仅包含账号侧控件的凭据行，并按需打开详情对话框。
function CredentialManagementTable({
  providers,
  definitions,
  groups,
  metadataByProviderID,
  managementAuthToken,
  refreshingMetadataIDs,
  metadataErrors,
  refreshingCredentialIDs,
  credentialRefreshErrors,
  deletingCredentialIDs,
  onRefreshMetadata,
  onRefreshCredential,
  onChangeCredentialPriority,
  onChangeCredentialPlan,
  onReauthorizeCredential,
  onDeleteCredential,
  onAddCredential,
}: CredentialManagementTableProps) {
  const { t } = useI18n();
  // modelProviderInstanceID opens one provider-scoped supported-model dialog without duplicating model details in the table.
  // modelProviderInstanceID 打开一个供应商作用域的支持模型对话框，而不在表格中重复模型详情。
  const [modelProviderInstanceID, setModelProviderInstanceID] = useState("");
  // serviceTestTarget opens one provider-scoped selector for every typed diagnostic supported by that provider.
  // serviceTestTarget 打开一个供应商作用域选择器，包含该供应商支持的全部类型化诊断。
  const [serviceTestTarget, setServiceTestTarget] =
    useState<ServiceTestTarget | null>(null);
  // resourceTarget constrains the resource dialog to one exact local credential.
  // resourceTarget 将资源对话框限定到一个精确的本地凭据。
  const [resourceTarget, setResourceTarget] =
    useState<CredentialResourceDialogTarget | null>(null);
  // resourceFileGroups preserves the endpoint boundary when MiniMax returns file metadata.
  // resourceFileGroups 在 MiniMax 返回文件元数据时保留端点边界。
  const [resourceFileGroups, setResourceFileGroups] = useState<
    ProviderResourceFileGroup[]
  >([]);
  // resourceFilesLoading reports the explicit on-demand provider file read.
  // resourceFilesLoading 表示显式按需的供应商文件读取。
  const [resourceFilesLoading, setResourceFilesLoading] = useState(false);
  // resourceFilesFailed records a safe generic failure without retaining provider response content.
  // resourceFilesFailed 记录安全的通用失败，而不保留供应商响应内容。
  const [resourceFilesFailed, setResourceFilesFailed] = useState(false);
  // priorityEditTarget identifies the only credential receiving a confirmed priority change.
  // priorityEditTarget 标识唯一接收已确认优先级变更的凭据。
  const [priorityEditTarget, setPriorityEditTarget] =
    useState<CredentialPriorityEditTarget | null>(null);
  // priorityDraft is deliberately dialog-local so a table row never edits priority on blur.
  // priorityDraft 被刻意限定在对话框内，因此表格行绝不会在失焦时编辑优先级。
  const [priorityDraft, setPriorityDraft] = useState("");
  // priorityUpdatePending prevents duplicate confirmed updates for one credential.
  // priorityUpdatePending 防止同一凭据重复提交已确认的更新。
  const [priorityUpdatePending, setPriorityUpdatePending] = useState(false);
  // priorityUpdateError distinguishes invalid local input from a failed persisted update.
  // priorityUpdateError 区分无效的本地输入与失败的持久化更新。
  const [priorityUpdateError, setPriorityUpdateError] = useState<
    "invalid" | "failed" | null
  >(null);
  // modelProvider resolves the live row target after inventory reloads while its dialog remains open.
  // modelProvider 在目录重载后解析仍处于打开状态的实时行目标。
  const modelProvider = providers.find(
    (provider) => provider.instance.id === modelProviderInstanceID,
  );
  // modelDefinition supplies the exact provider capability contract for the selected model dialog.
  // modelDefinition 为已选模型对话框提供精确的供应商能力契约。
  const modelDefinition = modelProvider
    ? findProviderDefinition(
        definitions,
        groups,
        modelProvider.instance.definition_id,
      )
    : undefined;
  // modelMetadata always follows the latest parent-owned snapshot instead of keeping a stale dialog copy.
  // modelMetadata 始终跟随最新的父级快照，而不保留过期的对话框副本。
  const modelMetadata = modelProvider
    ? metadataByProviderID[modelProvider.instance.id]
    : undefined;
  // resourceMetadata always follows the latest parent-owned snapshot for the selected credential.
  // resourceMetadata 始终跟随已选凭据的最新父级快照。
  const resourceMetadata = resourceTarget
    ? metadataByProviderID[resourceTarget.provider.instance.id]
    : undefined;
  // resourceVoices retains only entries owned by the selected credential and never mixes accounts.
  // resourceVoices 仅保留由已选凭据拥有的条目，绝不混合账号。
  const resourceVoices = resourceTarget
    ? (resourceMetadata?.voices ?? []).filter(
        (voice) => voice.credential_id === resourceTarget.credential.id,
      )
    : [];
  // resourceUsesProviderFiles is true only for the exact MiniMax definitions implemented by the protected file endpoint.
  // resourceUsesProviderFiles 仅在受保护文件端点已实现的精确 MiniMax 定义下为真。
  const resourceUsesProviderFiles = supportsMiniMaxProviderFileList(
    resourceTarget?.definition?.id,
  );
  // resourceHasFiles avoids presenting an empty detail section as a loaded resource list.
  // resourceHasFiles 避免将空详情区展示为已加载的资源列表。
  const resourceHasFiles = resourceFileGroups.some(
    (group) => group.files.length > 0,
  );

  useEffect(() => {
    if (!resourceTarget || !resourceUsesProviderFiles) {
      setResourceFileGroups([]);
      setResourceFilesLoading(false);
      setResourceFilesFailed(false);
      return;
    }
    // controller cancels the dialog-owned diagnostic reads when the user closes or switches the resource target.
    // controller 在用户关闭或切换资源目标时取消由对话框拥有的诊断读取。
    const controller = new AbortController();
    setResourceFileGroups([]);
    setResourceFilesLoading(true);
    setResourceFilesFailed(false);
    void (async () => {
      try {
        const [endpoints, bindings] = await Promise.all([
          fetchProviderEndpoints(
            managementAuthToken,
            resourceTarget.provider.instance.id,
            controller.signal,
          ),
          fetchProviderBindings(
            managementAuthToken,
            resourceTarget.provider.instance.id,
            controller.signal,
          ),
        ]);
        // boundEndpointIDs selects only endpoints that the exact credential is enabled to use.
        // boundEndpointIDs 仅选择精确凭据已启用使用权的端点。
        const boundEndpointIDs = new Set(
          bindings
            .filter(
              (binding) =>
                binding.credential_id === resourceTarget.credential.id &&
                binding.enabled,
            )
            .map((binding) => binding.endpoint_id),
        );
        // boundEndpoints prevents a diagnostic request from probing unrelated or disabled credential paths.
        // boundEndpoints 防止诊断请求探测无关或已禁用的凭据路径。
        const boundEndpoints = endpoints.filter((endpoint) =>
          boundEndpointIDs.has(endpoint.id),
        );
        const fileGroups = await Promise.all(
          boundEndpoints.map(async (endpoint) => ({
            endpoint,
            files: await fetchProviderFiles(
              managementAuthToken,
              resourceTarget.provider.instance.id,
              endpoint.id,
              resourceTarget.credential.id,
              controller.signal,
            ),
          })),
        );
        if (controller.signal.aborted) return;
        setResourceFileGroups(fileGroups);
      } catch {
        if (controller.signal.aborted) return;
        setResourceFilesFailed(true);
      } finally {
        if (!controller.signal.aborted) setResourceFilesLoading(false);
      }
    })();
    return () => controller.abort();
  }, [managementAuthToken, resourceTarget, resourceUsesProviderFiles]);

  // openModelCatalog starts one explicit account refresh and opens the compact model-only detail dialog.
  // openModelCatalog 启动一次显式账号刷新，并打开紧凑的仅模型详情对话框。
  function openModelCatalog(
    provider: AuthorizedProvider,
    definition: ProviderDefinitionIdentity | undefined,
  ): void {
    setModelProviderInstanceID(provider.instance.id);
    if (providerSupportsAccountMetadata(definition)) {
      void onRefreshMetadata(provider.instance.id);
    }
  }

  // openResourceCatalog starts any supported metadata refresh before showing credential-scoped resources.
  // openResourceCatalog 在展示凭据作用域资源前启动任何受支持的元数据刷新。
  function openResourceCatalog(
    provider: AuthorizedProvider,
    definition: ProviderDefinitionIdentity | undefined,
    credential: ProviderCredential,
  ): void {
    setResourceTarget({ provider, definition, credential });
    if (providerSupportsAccountMetadata(definition)) {
      void onRefreshMetadata(provider.instance.id);
    }
  }

  // openPriorityEditor copies the current persisted priority into an explicit confirmation dialog.
  // openPriorityEditor 将当前持久化优先级复制到显式确认对话框中。
  function openPriorityEditor(
    providerInstanceID: string,
    credential: ProviderCredential,
  ): void {
    setPriorityEditTarget({ providerInstanceID, credential });
    setPriorityDraft(String(credential.priority));
    setPriorityUpdateError(null);
  }

  // closePriorityEditor discards an unconfirmed priority draft.
  // closePriorityEditor 丢弃未确认的优先级草稿。
  function closePriorityEditor(): void {
    if (priorityUpdatePending) return;
    setPriorityEditTarget(null);
    setPriorityDraft("");
    setPriorityUpdateError(null);
  }

  // savePriority commits only one syntactically valid nonnegative safe integer after explicit confirmation.
  // savePriority 仅在显式确认后提交一个语法有效的非负安全整数。
  async function savePriority(): Promise<void> {
    if (!priorityEditTarget) return;
    const normalizedPriority = priorityDraft.trim();
    if (!/^(0|[1-9][0-9]*)$/.test(normalizedPriority)) {
      setPriorityUpdateError("invalid");
      return;
    }
    const priority = Number(normalizedPriority);
    if (!Number.isSafeInteger(priority)) {
      setPriorityUpdateError("invalid");
      return;
    }
    setPriorityUpdatePending(true);
    setPriorityUpdateError(null);
    try {
      await onChangeCredentialPriority(
        priorityEditTarget.providerInstanceID,
        priorityEditTarget.credential.id,
        priority,
      );
      setPriorityEditTarget(null);
      setPriorityDraft("");
    } catch {
      setPriorityUpdateError("failed");
    } finally {
      setPriorityUpdatePending(false);
    }
  }

  return (
    <>
      <div className="overflow-hidden rounded-xl border">
        <Table>
          <TableHeader className="bg-muted/40">
            <TableRow>
              <TableHead className="min-w-52">
                {t("providerConfig.provider")}
              </TableHead>
              <TableHead className="min-w-48">
                {t("providers.authorizations")}
              </TableHead>
              <TableHead className="min-w-40">
                {t("providers.membershipPlan")}
              </TableHead>
              <TableHead className="min-w-48">{t("providers.usage")}</TableHead>
              <TableHead className="w-24 text-center">
                {t("providers.priority")}
              </TableHead>
              <TableHead className="w-24 text-center">
                {t("providerConfig.status")}
              </TableHead>
              <TableHead className="min-w-80 text-right">
                {t("providerConfig.actions")}
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {providers.flatMap((provider) => {
              // definition is resolved once per provider so every credential row obeys the same server-authored contract.
              // definition 每个供应商仅解析一次，因此每个凭据行都遵循相同的服务端编写契约。
              const definition = findProviderDefinition(
                definitions,
                groups,
                provider.instance.definition_id,
              );
              // metadata is the latest local catalog snapshot shared by the provider's credential rows.
              // metadata 是由该供应商凭据行共享的最新本地目录快照。
              const metadata = metadataByProviderID[provider.instance.id];
              const supportsMetadata =
                providerSupportsAccountMetadata(definition);
              // searchAction exists only when the catalog declares one typed search.web service profile.
              // searchAction 仅在目录声明一个类型化 search.web 服务规格时存在。
              const searchAction = providerSearchTestAction(provider, metadata);
              // extractAction exists only when the catalog declares one typed web.extract service profile.
              // extractAction 仅在目录声明一个类型化 web.extract 服务规格时存在。
              const extractAction = providerExtractTestAction(provider, metadata);
              // hasModelCatalog prevents search-only providers from displaying a model discovery action.
              // hasModelCatalog 防止仅搜索供应商显示模型发现操作。
              const hasModelCatalog = providerCatalogHasModels(metadata);
              if (provider.credentials.length === 0) {
                  return [
                    <TableRow key={provider.instance.id}>
                      <TableCell className="whitespace-normal py-3 align-top">
                        <div className="flex items-center gap-3">
                          <ProviderIcon
                            definitionID={provider.instance.definition_id}
                            groupID={definition?.group_id}
                            className="size-[26px]"
                          />
                          <div className="min-w-0">
                            <p className="font-medium">
                              {provider.instance.display_name}
                            </p>
                            <p className="text-muted-foreground mt-1 text-xs">
                              {definition?.display_name ??
                                provider.instance.definition_id}
                            </p>
                          </div>
                        </div>
                      </TableCell>
                    <TableCell
                      colSpan={6}
                      className="whitespace-normal py-3 align-middle"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-3">
                        <span className="text-muted-foreground text-sm">
                          {t("providers.noCredentialsForProvider")}
                        </span>
                        <Button
                          type="button"
                          variant="outline"
                          size="sm"
                          aria-label={`${t("providers.addCredential")} ${provider.instance.display_name}`}
                          onClick={() => onAddCredential(provider)}
                        >
                          <PlusIcon className="size-3.5" />
                          {t("providers.addCredential")}
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>,
                ];
              }
              return provider.credentials.map((credential, credentialIndex) => {
                // authMethod is resolved only from the owning definition and never inferred from a credential value.
                // authMethod 仅从所属定义解析，绝不从凭据值推断。
                const authMethod = definition?.auth_methods.find(
                  (method) => method.id === credential.auth_method_id,
                );
                const canListResources = supportsCredentialResourceList(
                  definition?.id,
                  metadata,
                );
                return (
                  <TableRow key={credential.id}>
                    <TableCell className="whitespace-normal py-3 align-top">
                      <div className="flex items-center gap-3">
                        <ProviderIcon
                          definitionID={provider.instance.definition_id}
                          groupID={definition?.group_id}
                          className="size-[26px]"
                        />
                        <div className="min-w-0">
                          <p className="font-medium">
                            {provider.instance.display_name}
                          </p>
                          <p className="text-muted-foreground mt-1 text-xs">
                            {definition?.display_name ??
                              provider.instance.definition_id}
                          </p>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell className="whitespace-normal py-3 align-top">
                      <p className="font-medium">{credential.label}</p>
                      <p className="text-muted-foreground mt-1 text-xs">
                        {authorizationTypeLabel(
                          t,
                          authMethod?.type,
                          credential.auth_method_id,
                        )}
                      </p>
                    </TableCell>
                    <TableCell className="whitespace-normal py-3 align-middle">
                      {authMethod?.plan_acquisition === "manual_required" ? (
                        <ReadonlyCombobox
                          value={credential.declared_plan?.plan_option_id ?? ""}
                          onValueChange={(value) => {
                            if (
                              value !== credential.declared_plan?.plan_option_id
                            ) {
                              void onChangeCredentialPlan(
                                provider.instance.id,
                                credential.id,
                                value,
                              );
                            }
                          }}
                          options={(definition?.plan_options ?? [])
                            .filter(
                              (option) =>
                                option.manually_selectable &&
                                option.auth_method_ids.includes(
                                  credential.auth_method_id,
                                ),
                            )
                            .map((option) => ({
                              value: option.id,
                              label: option.display_name,
                            }))}
                          placeholder={t("providers.selectMembershipPlan")}
                          className="w-full min-w-36"
                        />
                      ) : (
                        <span className="text-muted-foreground text-sm">
                          {credentialPlanLabel(
                            definition,
                            credential,
                          ) ?? "—"}
                        </span>
                      )}
                    </TableCell>
                    <TableCell className="whitespace-normal py-3 align-top">
                      <CompactAllowanceSummary
                        allowances={metadata?.allowances ?? []}
                        credentialID={credential.id}
                        includeSharedAllowances={credentialIndex === 0}
                        t={t}
                      />
                    </TableCell>
                    <TableCell className="py-3 text-center align-middle">
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        aria-label={`${t("providers.editPriority")} ${credential.label}`}
                        onClick={() =>
                          openPriorityEditor(provider.instance.id, credential)
                        }
                      >
                        {credential.priority}
                      </Button>
                    </TableCell>
                    <TableCell className="py-3 text-center align-middle">
                      <Badge variant="outline">
                        {providerStatusLabel(t, credential.status)}
                      </Badge>
                    </TableCell>
                    <TableCell className="whitespace-normal py-3 text-right align-middle">
                      <div className="flex flex-wrap justify-end gap-2">
                        {supportsMetadata ? (
                          <Button
                            type="button"
                            variant="outline"
                            size="icon-sm"
                            aria-label={t("providers.refreshMetadata")}
                            disabled={refreshingMetadataIDs.has(
                              provider.instance.id,
                            )}
                            onClick={() =>
                              void onRefreshMetadata(provider.instance.id)
                            }
                          >
                            <RefreshCwIcon
                              className={`size-3.5 ${refreshingMetadataIDs.has(provider.instance.id) ? "animate-spin" : ""}`}
                            />
                          </Button>
                        ) : null}
                        {hasModelCatalog ? (
                          <Button
                            type="button"
                            variant="outline"
                            size="sm"
                            onClick={() =>
                              openModelCatalog(provider, definition)
                            }
                          >
                            {t("providers.getSupportedModels")}
                          </Button>
                        ) : null}
                        {searchAction || extractAction ? (
                          <Button
                            type="button"
                            variant="outline"
                            size="sm"
                            disabled={
                              !searchAction?.ready && !extractAction?.ready
                            }
                            onClick={() =>
                              setServiceTestTarget({
                                providerName: provider.instance.display_name,
                                search: searchAction ?? undefined,
                                extract: extractAction ?? undefined,
                              })
                            }
                          >
                            {t("services.test")}
                          </Button>
                        ) : null}
                        {canListResources ? (
                          <Button
                            type="button"
                            variant="outline"
                            size="sm"
                            onClick={() =>
                              openResourceCatalog(
                                provider,
                                definition,
                                credential,
                              )
                            }
                          >
                            {t("providers.resources")}
                          </Button>
                        ) : null}
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
                            disabled={refreshingCredentialIDs.has(
                              credential.id,
                            )}
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
                        <AlertDialog>
                          <AlertDialogTrigger
                            render={
                              <Button
                                type="button"
                                variant="ghost"
                                size="icon-sm"
                                aria-label={t("providers.deleteCredential")}
                                disabled={deletingCredentialIDs.has(
                                  credential.id,
                                )}
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
                      {metadataErrors[provider.instance.id] ? (
                        <p
                          className="text-destructive mt-2 text-left text-xs"
                          role="status"
                        >
                          {metadataRefreshErrorLabel(
                            t,
                            metadataErrors[provider.instance.id],
                          )}
                        </p>
                      ) : null}
                      {credentialRefreshErrors[credential.id] ? (
                        <p
                          className="text-destructive mt-2 text-left text-xs"
                          role="status"
                        >
                          {credentialRefreshErrorLabel(
                            t,
                            credentialRefreshErrors[credential.id],
                          )}
                        </p>
                      ) : null}
                    </TableCell>
                  </TableRow>
                );
              });
            })}
          </TableBody>
        </Table>
      </div>

      <Dialog
        open={modelProviderInstanceID !== ""}
        onOpenChange={(open) => {
          if (!open) setModelProviderInstanceID("");
        }}
      >
        <DialogContent className="grid max-h-[min(80vh,680px)] grid-rows-[auto_minmax(0,1fr)] overflow-hidden">
          <DialogHeader>
            <div className="min-w-0 flex-1">
              <DialogTitle>{t("providers.modelCatalogTitle")}</DialogTitle>
              <DialogDescription>
                {modelProvider?.instance.display_name ??
                  t("providers.modelCatalogDescription")}
              </DialogDescription>
            </div>
            <DialogClose
              aria-label={t("providers.cancel")}
              render={<Button type="button" variant="ghost" size="icon" />}
            >
              <XIcon className="size-4" />
            </DialogClose>
          </DialogHeader>
          <div className="min-h-0 overflow-y-auto pr-1">
            {modelProvider && modelDefinition ? (
              <div className="mb-3 flex justify-end">
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  disabled={refreshingMetadataIDs.has(
                    modelProvider.instance.id,
                  )}
                  onClick={() =>
                    void onRefreshMetadata(modelProvider.instance.id)
                  }
                >
                  <RefreshCwIcon
                    className={`size-3.5 ${refreshingMetadataIDs.has(modelProvider.instance.id) ? "animate-spin" : ""}`}
                  />
                  {refreshingMetadataIDs.has(modelProvider.instance.id)
                    ? t("providers.refreshingMetadata")
                    : t("providers.refreshMetadata")}
                </Button>
              </div>
            ) : null}
            {modelMetadata?.models.length ? (
              <div className="overflow-hidden rounded-lg border">
                <Table>
                  <TableHeader className="bg-muted/40">
                    <TableRow>
                      <TableHead>{t("providers.models")}</TableHead>
                      <TableHead>{t("providers.upstreamModelID")}</TableHead>
                      <TableHead className="w-36 text-center">
                        {t("providers.authorizations")}
                      </TableHead>
                      <TableHead className="w-24 text-center">
                        {t("providerConfig.status")}
                      </TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {modelMetadata.models.map((model) => (
                      <TableRow key={model.id}>
                        <TableCell className="whitespace-normal py-3">
                          {model.display_name}
                        </TableCell>
                        <TableCell className="py-3 font-mono text-xs">
                          {model.upstream_model_id}
                        </TableCell>
                        <TableCell className="py-3 text-center">
                          {model.entitlement_mode === "explicit" ? (
                            <Badge variant="outline">
                              {model.authorization_status === "authorized"
                                ? t("providers.modelAuthorized")
                                : model.authorization_status === "denied"
                                  ? t("providers.modelUnauthorized")
                                  : t("providers.modelAuthorizationUnknown")}
                            </Badge>
                          ) : (
                            <span className="text-muted-foreground">—</span>
                          )}
                        </TableCell>
                        <TableCell className="py-3 text-center">
                          <Badge variant="outline">
                            {model.enabled
                              ? t("providers.modelEnabled")
                              : t("providers.modelDisabled")}
                          </Badge>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            ) : (
              <p className="text-muted-foreground text-sm">
                {refreshingMetadataIDs.has(modelProviderInstanceID)
                  ? t("providers.refreshingMetadata")
                  : t("providers.noSupportedModels")}
              </p>
            )}
          </div>
        </DialogContent>
      </Dialog>

      <Dialog
        open={resourceTarget !== null}
        onOpenChange={(open) => {
          if (!open) setResourceTarget(null);
        }}
      >
        <DialogContent className="grid max-h-[min(80vh,720px)] grid-rows-[auto_minmax(0,1fr)] overflow-hidden">
          <DialogHeader>
            <div className="min-w-0 flex-1">
              <DialogTitle>{t("providers.resourceList")}</DialogTitle>
              <DialogDescription>
                {resourceTarget
                  ? `${resourceTarget.provider.instance.display_name} · ${resourceTarget.credential.label}`
                  : t("providers.resourceListDescription")}
              </DialogDescription>
            </div>
            <DialogClose
              aria-label={t("providers.cancel")}
              render={<Button type="button" variant="ghost" size="icon" />}
            >
              <XIcon className="size-4" />
            </DialogClose>
          </DialogHeader>
          <div className="min-h-0 space-y-5 overflow-y-auto pr-1">
            {resourceVoices.length ? (
              <section className="space-y-2">
                <h4 className="text-sm font-medium">
                  {t("providers.voiceResources")}
                </h4>
                <div className="overflow-hidden rounded-lg border">
                  <Table>
                    <TableHeader className="bg-muted/40">
                      <TableRow>
                        <TableHead>{t("providers.voices")}</TableHead>
                        <TableHead>{t("providers.voiceIdentifier")}</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {resourceVoices.map((voice) => (
                        <TableRow key={voice.voice_id}>
                          <TableCell className="whitespace-normal py-3">
                            <p className="font-medium">{voice.display_name}</p>
                            {voice.descriptions.length ? (
                              <p className="text-muted-foreground mt-1 text-xs">
                                {voice.descriptions.join(" · ")}
                              </p>
                            ) : null}
                          </TableCell>
                          <TableCell className="py-3 font-mono text-xs">
                            {voice.voice_id}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </section>
            ) : null}

            {resourceUsesProviderFiles ? (
              <section className="space-y-2">
                <h4 className="text-sm font-medium">
                  {t("providers.fileResources")}
                </h4>
                {resourceFilesLoading ? (
                  <p className="text-muted-foreground text-sm">
                    {t("providers.loadingResourceFiles")}
                  </p>
                ) : resourceFilesFailed ? (
                  <p className="text-destructive text-sm" role="status">
                    {t("providers.resourceLoadFailed")}
                  </p>
                ) : resourceFileGroups.length ? (
                  <div className="space-y-3">
                    {resourceFileGroups.map((group) => (
                      <div key={group.endpoint.id} className="space-y-2">
                        {resourceFileGroups.length > 1 ? (
                          <p className="text-muted-foreground text-xs">
                            {group.endpoint.region || group.endpoint.id}
                          </p>
                        ) : null}
                        {group.files.length ? (
                          <div className="overflow-hidden rounded-lg border">
                            <Table>
                              <TableHeader className="bg-muted/40">
                                <TableRow>
                                  <TableHead>
                                    {t("providers.fileName")}
                                  </TableHead>
                                  <TableHead>
                                    {t("providers.resourcePurpose")}
                                  </TableHead>
                                  <TableHead className="w-24 text-right">
                                    {t("providers.resourceSize")}
                                  </TableHead>
                                  <TableHead className="w-44">
                                    {t("providers.resourceCreatedAt")}
                                  </TableHead>
                                </TableRow>
                              </TableHeader>
                              <TableBody>
                                {group.files.map((file) => (
                                  <TableRow key={file.file_id}>
                                    <TableCell className="whitespace-normal py-3">
                                      <p className="font-medium">
                                        {file.filename}
                                      </p>
                                      <p className="text-muted-foreground mt-1 font-mono text-xs">
                                        {file.file_id}
                                      </p>
                                    </TableCell>
                                    <TableCell className="py-3">
                                      {file.purpose}
                                    </TableCell>
                                    <TableCell className="py-3 text-right tabular-nums">
                                      {formatResourceBytes(file.size_bytes)}
                                    </TableCell>
                                    <TableCell className="py-3 text-xs">
                                      {formatAllowanceTime(file.created_at)}
                                    </TableCell>
                                  </TableRow>
                                ))}
                              </TableBody>
                            </Table>
                          </div>
                        ) : (
                          <p className="text-muted-foreground text-sm">
                            {t("providers.noFileResources")}
                          </p>
                        )}
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-muted-foreground text-sm">
                    {t("providers.noFileResources")}
                  </p>
                )}
              </section>
            ) : null}

            {!resourceFilesLoading &&
            !resourceFilesFailed &&
            resourceVoices.length === 0 &&
            (!resourceUsesProviderFiles || !resourceHasFiles) ? (
              <p className="text-muted-foreground text-sm">
                {t("providers.noResources")}
              </p>
            ) : null}
          </div>
        </DialogContent>
      </Dialog>

      <Dialog
        open={priorityEditTarget !== null}
        onOpenChange={(open) => {
          if (!open) closePriorityEditor();
        }}
      >
        <DialogContent className="max-w-md">
          <DialogHeader>
            <div className="min-w-0 flex-1">
              <DialogTitle>{t("providers.editPriority")}</DialogTitle>
              <DialogDescription>
                {priorityEditTarget?.credential.label ??
                  t("providers.priorityEditDescription")}
              </DialogDescription>
            </div>
            <DialogClose
              aria-label={t("providers.cancel")}
              render={<Button type="button" variant="ghost" size="icon" />}
            >
              <XIcon className="size-4" />
            </DialogClose>
          </DialogHeader>
          <div className="space-y-2">
            <Label htmlFor="credential-priority-dialog">
              {t("providers.priority")}
            </Label>
            <Input
              id="credential-priority-dialog"
              type="number"
              min={0}
              inputMode="numeric"
              value={priorityDraft}
              disabled={priorityUpdatePending}
              onChange={(event) => {
                setPriorityDraft(event.target.value);
                setPriorityUpdateError(null);
              }}
            />
            {priorityUpdateError ? (
              <p className="text-destructive text-xs" role="alert">
                {t(
                  priorityUpdateError === "invalid"
                    ? "providers.priorityInvalid"
                    : "providers.priorityUpdateFailed",
                )}
              </p>
            ) : null}
          </div>
          <div className="flex justify-end gap-2">
            <Button
              type="button"
              variant="outline"
              disabled={priorityUpdatePending}
              onClick={closePriorityEditor}
            >
              {t("providers.cancel")}
            </Button>
            <Button
              type="button"
              disabled={priorityUpdatePending}
              onClick={() => void savePriority()}
            >
              {priorityUpdatePending
                ? t("providers.updatingPriority")
                : t("providers.updatePriority")}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
      <ServiceTestDialog
        managementAuthToken={managementAuthToken}
        target={serviceTestTarget}
        onClose={() => setServiceTestTarget(null)}
      />
    </>
  );
}

// ProviderSearchTestAction binds a catalog-authored search target to its current aggregate readiness.
// ProviderSearchTestAction 将目录编写的搜索目标绑定到其当前聚合就绪状态。
interface ProviderSearchTestAction {
  // target contains the exact service, offering, profile, and declared policies.
  // target 包含精确的服务、供应、规格及声明策略。
  target: SearchServiceTestTarget;
  // ready reports whether the current pool can execute the diagnostic immediately.
  // ready 表示当前凭据池是否能够立即执行诊断。
  ready: boolean;
}

// providerSearchTestAction selects one ready typed search profile, or the first declared profile when credentials are unavailable.
// providerSearchTestAction 选择一个就绪的类型化搜索规格；凭据不可用时返回首个已声明规格。
function providerSearchTestAction(
  provider: AuthorizedProvider,
  metadata: ProviderCatalogMetadata | undefined,
): ProviderSearchTestAction | null {
  // candidates preserve the authoritative catalog order while excluding non-search and incomplete contracts.
  // candidates 保留权威目录顺序，同时排除非搜索及不完整合同。
  const candidates = (metadata?.services ?? []).flatMap((service) => {
    if (service.operation !== "search.web") return [];
    return service.offerings.flatMap((offering) =>
      offering.profiles.flatMap((profile) => {
        const search = profile.capabilities.web_search;
        if (
          profile.operation !== "search.web" ||
          !search ||
          search.output_modes.length === 0 ||
          search.evidence_requirements.length === 0
        ) {
          return [];
        }
        return [
          {
            target: {
              providerInstanceID: provider.instance.id,
              providerName: provider.instance.display_name,
              providerServiceID: service.id,
              serviceName: service.display_name,
              serviceOfferingID: offering.id,
              executionProfileID: profile.id,
              outputMode: search.output_modes[0],
              evidenceRequirement: search.evidence_requirements[0],
            },
            ready:
              service.enabled && (profile.pool?.ready_credentials ?? 0) > 0,
          },
        ];
      }),
    );
  });
  // selected prefers an executable profile while retaining a disabled action for a configured search service without ready credentials.
  // selected 优先选择可执行规格，同时为暂无就绪凭据的已配置搜索服务保留禁用操作。
  const selected =
    candidates.find((candidate) => candidate.ready) ?? candidates[0];
  return selected ?? null;
}

// ProviderExtractTestAction binds a catalog-authored extraction target to its current aggregate readiness.
// ProviderExtractTestAction 将目录编写的内容提取目标绑定到其当前聚合就绪状态。
interface ProviderExtractTestAction {
  target: ExtractServiceTestTarget;
  ready: boolean;
}

// providerExtractTestAction selects one ready typed extraction profile, or the first declared profile when credentials are unavailable.
// providerExtractTestAction 选择一个就绪的类型化内容提取规格；凭据不可用时返回首个已声明规格。
function providerExtractTestAction(provider: AuthorizedProvider, metadata: ProviderCatalogMetadata | undefined): ProviderExtractTestAction | null {
  const candidates = (metadata?.services ?? []).flatMap((service) => {
    if (service.operation !== "web.extract") return [];
    return service.offerings.flatMap((offering) => offering.profiles.flatMap((profile) => {
      const extract = profile.capabilities.web_extract;
      if (profile.operation !== "web.extract" || !extract || extract.depths.length === 0 || extract.formats.length === 0) return [];
      return [{
        target: {
          providerInstanceID: provider.instance.id,
          providerName: provider.instance.display_name,
          providerServiceID: service.id,
          serviceName: service.display_name,
          serviceOfferingID: offering.id,
          executionProfileID: profile.id,
          maxURLs: extract.max_urls,
          depths: extract.depths,
          formats: extract.formats,
          queryRelevance: extract.query_relevance,
          minimumChunksPerSource: extract.minimum_chunks_per_source,
          maximumChunksPerSource: extract.maximum_chunks_per_source,
          includeImages: extract.include_images,
          includeFavicon: extract.include_favicon,
          minimumTimeoutSeconds: extract.minimum_timeout_seconds,
          maximumTimeoutSeconds: extract.maximum_timeout_seconds,
        },
        ready: service.enabled && (profile.pool?.ready_credentials ?? 0) > 0,
      }];
    }));
  });
  return candidates.find((candidate) => candidate.ready) ?? candidates[0] ?? null;
}

// providerSupportsAccountMetadata follows only the server-authored native reader capability contract.
// providerSupportsAccountMetadata 仅遵循服务端编写的原生读取器能力契约。
function providerSupportsAccountMetadata(
  definition: ProviderDefinitionIdentity | undefined,
): boolean {
  // statuses contains every account metadata capability represented by the provider definition.
  // statuses 包含供应商定义表示的每个账号元数据能力。
  const statuses = [
    definition?.features.model_discovery,
    definition?.features.plan_reader,
    definition?.features.entitlement_reader,
    definition?.features.allowance_reader,
  ];
  return statuses.includes("supported");
}

// supportsMiniMaxProviderFileList follows the exact two MiniMax definitions implemented by the protected file listing endpoint.
// supportsMiniMaxProviderFileList 遵循受保护文件列表端点实现的两个精确 MiniMax 定义。
function supportsMiniMaxProviderFileList(
  definitionID: string | undefined,
): boolean {
  return (
    definitionID === "system_minimax_api" ||
    definitionID === "system_minimax_cn"
  );
}

// supportsCredentialResourceList exposes a resource action only for proven MiniMax file support or cached credential-scoped voices.
// supportsCredentialResourceList 仅为已证实的 MiniMax 文件支持或缓存的凭据作用域声音暴露资源操作。
function supportsCredentialResourceList(
  definitionID: string | undefined,
  metadata: ProviderCatalogMetadata | undefined,
): boolean {
  return (
    supportsMiniMaxProviderFileList(definitionID) ||
    (metadata?.voices.length ?? 0) > 0
  );
}

// credentialPlanLabel returns the exact manual selection or provider-detected plan bound to this local credential.
// credentialPlanLabel 返回绑定到此本地凭据的精确人工选择或供应商自动识别套餐。
export function credentialPlanLabel(
  definition: Pick<ProviderDefinitionIdentity, "plan_options"> | undefined,
  credential: Pick<ProviderCredential, "declared_plan" | "detected_plan">,
): string | undefined {
  const planOptionID = credential.declared_plan?.plan_option_id;
  if (planOptionID) {
    return (
      definition?.plan_options.find((option) => option.id === planOptionID)
        ?.display_name ?? planOptionID
    );
  }
  return credential.detected_plan?.plan_name || credential.detected_plan?.plan_code;
}

// CompactAllowanceSummaryProps defines the limited quota visualization placed inside one credential table field.
// CompactAllowanceSummaryProps 定义放置在一个凭据表格字段内的有限额度可视化。
interface CompactAllowanceSummaryProps {
  // allowances contains one provider's latest normalized quota observations.
  // allowances 包含一个供应商最新的规范化额度观测。
  allowances: ProviderAllowance[];
  // credentialID selects exact credential-scoped observations.
  // credentialID 选择精确的凭据作用域观测。
  credentialID: string;
  // includeSharedAllowances renders unscoped provider usage once without assigning it to every credential.
  // includeSharedAllowances 仅渲染一次无作用域供应商用量，而不将其分配给每个凭据。
  includeSharedAllowances: boolean;
  // t resolves current localized field labels.
  // t 解析当前本地化字段标签。
  t: (key: TranslationKey) => string;
}

// MiniMaxAllowanceRow joins the provider's current and weekly windows for one Token Plan resource bucket.
// MiniMaxAllowanceRow 将供应商针对一个 Token Plan 资源桶的当前周期与周窗口连接起来。
interface MiniMaxAllowanceRow {
  // name is the exact provider-owned resource bucket name.
  // name 是供应商拥有的精确资源桶名称。
  name: string;
  // current is the short provider-defined interval when reported.
  // current 是报告时的短供应商定义周期。
  current?: ProviderAllowance;
  // weekly is the calendar-week interval when reported.
  // weekly 是报告时的日历周周期。
  weekly?: ProviderAllowance;
}

// TavilyAllowanceSummaryData selects the dynamic account plan fact appropriate for the compact credential table.
// TavilyAllowanceSummaryData 选择适合凭据紧凑表格的动态账号套餐事实。
interface TavilyAllowanceSummaryData {
  // accountPlan is the account plan usage and plan limit.
  // accountPlan 是账号套餐用量及套餐上限。
  accountPlan?: ProviderAllowance;
}

// tavilyAllowanceSummary recognizes Tavily metadata while projecting only compact account-level facts; detailed counters remain in the catalog.
// tavilyAllowanceSummary 识别 Tavily 元数据但只投影紧凑的账号级事实；详细计数器仍保留在目录中。
function tavilyAllowanceSummary(
  allowances: ProviderAllowance[],
): TavilyAllowanceSummaryData | undefined {
  const metrics = new Map(
    allowances
      .filter((allowance) => allowance.metric.startsWith("tavily."))
      .map((allowance) => [allowance.metric, allowance]),
  );
  if (metrics.size === 0) return undefined;
  return {
    accountPlan: metrics.get("tavily.account.plan"),
  };
}

// tavilyCounterValue renders provider-reported usage and its optional limit without substituting remaining credits.
// tavilyCounterValue 渲染供应商报告的已用量及其可选上限，且不以剩余积分替代已用量。
function tavilyCounterValue(allowance: ProviderAllowance | undefined): string {
  if (!allowance || allowance.used === undefined) return "—";
  return allowance.limit === undefined
    ? allowance.used
    : `${allowance.used} / ${allowance.limit}`;
}

// TavilyAllowanceSummary renders only dynamic plan consumption while the catalog retains PAYGO configuration and detailed counters.
// TavilyAllowanceSummary 仅渲染动态套餐消费，同时目录保留 PAYGO 配置与全部详细计数器。
export function TavilyAllowanceSummary({
  summary,
  t,
}: {
  summary: TavilyAllowanceSummaryData;
  t: (key: TranslationKey) => string;
}) {
  const planRatio = allowanceDisplayRatio(summary.accountPlan);
  return (
    <div className="w-72 max-w-full space-y-1 text-[11px]">
      <div className="space-y-0.5">
        <div className="flex items-center justify-between gap-2">
          <span className="font-medium">
            {t("providers.allowanceMetrics.tavilyPlan")}
          </span>
          <span className="tabular-nums">
            {t("providers.used")} {tavilyCounterValue(summary.accountPlan)}
          </span>
        </div>
        {planRatio !== undefined ? (
          <div
            aria-label={`${t("providers.allowanceMetrics.tavilyPlan")}: ${Math.round(planRatio * 100)}%`}
            aria-valuemax={100}
            aria-valuemin={0}
            aria-valuenow={Math.round(planRatio * 100)}
            className="bg-muted h-1.5 overflow-hidden rounded-full"
            role="progressbar"
          >
            <div
              className={`h-full rounded-full ${planRatio <= 0.1 ? "bg-destructive" : planRatio <= 0.3 ? "bg-amber-500" : "bg-emerald-500"}`}
              style={{ width: `${Math.min(1, planRatio) * 100}%` }}
            />
          </div>
        ) : null}
      </div>
    </div>
  );
}

// miniMaxAllowanceRows recognizes only the exact metric namespace emitted by the MiniMax allowance driver.
// miniMaxAllowanceRows 仅识别 MiniMax 额度 Driver 发出的精确指标命名空间。
function miniMaxAllowanceRows(
  allowances: ProviderAllowance[],
): MiniMaxAllowanceRow[] {
  const rows = new Map<string, MiniMaxAllowanceRow>();
  for (const allowance of allowances) {
    const match = /^minimax\.(.+)\.(current_interval|weekly)$/.exec(
      allowance.metric,
    );
    if (!match) continue;
    const name = match[1];
    const row = rows.get(name) ?? { name };
    if (match[2] === "current_interval") row.current = allowance;
    else row.weekly = allowance;
    rows.set(name, row);
  }
  return [...rows.values()].sort((left, right) => {
    const order = (name: string) =>
      name === "general" ? 0 : name === "video" ? 1 : 2;
    return (
      order(left.name) - order(right.name) ||
      left.name.localeCompare(right.name)
    );
  });
}

// MiniMaxAllowanceSummary renders the Token Plan's paired resource windows inside one credential field.
// MiniMaxAllowanceSummary 在一个凭据字段内渲染 Token Plan 成对的资源窗口。
function MiniMaxAllowanceSummary({
  rows,
  t,
}: {
  rows: MiniMaxAllowanceRow[];
  t: (key: TranslationKey) => string;
}) {
  const weeklyWindow = rows.find(
    (row) => row.weekly?.window?.start_at && row.weekly.window.reset_at,
  )?.weekly?.window;
  return (
    <div className="w-[22rem] max-w-full space-y-1.5">
      {weeklyWindow?.start_at && weeklyWindow.reset_at ? (
        <div className="text-muted-foreground text-right text-[10px] leading-none">
          {t("providers.period")}: {miniMaxPeriodDate(weeklyWindow.start_at)} –{" "}
          {miniMaxPeriodDate(weeklyWindow.reset_at)}
        </div>
      ) : null}
      {rows.map((row) => {
        const label =
          row.name === "general"
            ? t("providers.allowanceMetrics.minimaxGeneral")
            : row.name === "video"
              ? t("providers.allowanceMetrics.minimaxVideo")
              : row.name;
        const resetAt = row.current?.window?.reset_at;
        return (
          <div
            key={row.name}
            className="grid grid-cols-[2.75rem_minmax(0,1fr)_minmax(0,1fr)_auto] items-center gap-2 text-[11px]"
          >
            <span className="font-medium">{label}</span>
            <MiniMaxAllowanceMetric
              label={t("providers.allowanceMetrics.minimaxCurrent")}
              allowance={row.current}
              t={t}
            />
            <MiniMaxAllowanceMetric
              label={t("providers.allowanceMetrics.minimaxWeekly")}
              allowance={row.weekly}
              t={t}
            />
            <span className="text-muted-foreground whitespace-nowrap tabular-nums">
              {t("providers.resetsIn")} {miniMaxResetDuration(resetAt)}
            </span>
          </div>
        );
      })}
    </div>
  );
}

// MiniMaxAllowanceMetric renders one exact remaining amount and its compact progress indicator.
// MiniMaxAllowanceMetric 渲染一个精确剩余量及其紧凑进度指示器。
function MiniMaxAllowanceMetric({
  label,
  allowance,
  t,
}: {
  label: string;
  allowance?: ProviderAllowance;
  t: (key: TranslationKey) => string;
}) {
  const ratio = allowanceDisplayRatio(allowance);
  const visualRatio = ratio === undefined ? 0 : Math.min(1, ratio);
  // displayValue keeps the visible amount and accessible progress name on the same normalized contract.
  // displayValue 使可见额度与无障碍进度名称保持同一规范合同。
  const displayValue = miniMaxAllowanceValue(allowance, ratio, t);
  return (
    <div className="min-w-0 space-y-0.5">
      <div className="flex items-center justify-between gap-1">
        <span className="text-muted-foreground truncate">{label}</span>
        <span className="shrink-0 tabular-nums">{displayValue}</span>
      </div>
      <div
        aria-label={`${label}: ${displayValue}`}
        aria-valuemax={100}
        aria-valuemin={0}
        aria-valuenow={Math.round(visualRatio * 100)}
        className="bg-muted h-1.5 overflow-hidden rounded-full"
        role="progressbar"
      >
        <div
          className={`h-full rounded-full ${visualRatio <= 0.1 ? "bg-destructive" : visualRatio <= 0.3 ? "bg-amber-500" : "bg-emerald-500"}`}
          style={{ width: `${visualRatio * 100}%` }}
        />
      </div>
    </div>
  );
}

// isMiniMaxAllowanceUnlimited recognizes the canonical state and the exact legacy MiniMax management representation.
// isMiniMaxAllowanceUnlimited 识别规范状态及精确的旧版 MiniMax 管理表示。
function isMiniMaxAllowanceUnlimited(
  allowance: ProviderAllowance | undefined,
): boolean {
  if (!allowance) return false;
  if (allowance.status === "unlimited") return true;
  return (
    /^minimax\.(.+)\.(current_interval|weekly)$/.test(allowance.metric) &&
    allowance.status === "available" &&
    allowance.limit === undefined &&
    allowance.remaining === undefined &&
    allowance.remaining_ratio === undefined
  );
}

// allowanceDisplayRatio applies explicit unlimited availability or the provider-authored visual multiplier without changing exact accounting counts.
// allowanceDisplayRatio 应用明确的无限可用性或供应商编写的视觉倍率，且不改变精确计量数。
function allowanceDisplayRatio(
  allowance: ProviderAllowance | undefined,
): number | undefined {
  if (!allowance) return undefined;
  if (isMiniMaxAllowanceUnlimited(allowance)) return 1;
  let ratio = allowance.remaining_ratio;
  if (ratio === undefined && allowance.limit && allowance.remaining) {
    const limit = Number(allowance.limit);
    const remaining = Number(allowance.remaining);
    if (Number.isFinite(limit) && limit > 0 && Number.isFinite(remaining)) {
      ratio = remaining / limit;
    }
  }
  if (ratio === undefined) return undefined;
  return ratio * ((allowance.display_multiplier_permille ?? 1000) / 1000);
}

// miniMaxAllowanceValue follows minimax-cli's count, percentage, unlimited, and unavailable display contract.
// miniMaxAllowanceValue 遵循 minimax-cli 的次数、百分比、无限与不可用展示合同。
function miniMaxAllowanceValue(
  allowance: ProviderAllowance | undefined,
  ratio: number | undefined,
  t: (key: TranslationKey) => string,
): string {
  if (!allowance) return t("providers.unknownAmount");
  if (allowance.status === "not_included") return t("providers.notInPlan");
  // The legacy management response encoded MiniMax unlimited windows as available with every finite amount omitted.
  // 旧版管理响应将 MiniMax 无限窗口编码为可用且省略全部有限数值。
  if (isMiniMaxAllowanceUnlimited(allowance)) return t("providers.unlimited");
  if (allowance.limit !== undefined && Number(allowance.limit) > 0) {
    return `${allowance.remaining ?? "0"} / ${allowance.limit}`;
  }
  return ratio === undefined
    ? t("providers.unknownAmount")
    : `${Math.round(ratio * 100)}%`;
}

// miniMaxResetDuration renders the current interval reset countdown used by minimax-cli.
// miniMaxResetDuration 渲染 minimax-cli 使用的当前周期重置倒计时。
function miniMaxResetDuration(resetAt: string | undefined): string {
  if (!resetAt) return "—";
  const remainingMilliseconds = Math.max(
    0,
    new Date(resetAt).getTime() - Date.now(),
  );
  const hours = Math.floor(remainingMilliseconds / 3_600_000);
  const minutes = Math.floor((remainingMilliseconds % 3_600_000) / 60_000);
  return hours > 0 ? `${hours}h ${minutes}m` : `${minutes}m`;
}

// miniMaxPeriodDate renders the calendar date portion used by the Token Plan period header.
// miniMaxPeriodDate 渲染 Token Plan 周期标题使用的日历日期部分。
function miniMaxPeriodDate(value: string): string {
  return new Date(value).toISOString().slice(0, 10);
}

// CompactAllowanceSummary renders up to three miniature usage indicators in one table field.
// CompactAllowanceSummary 在一个表格字段内渲染最多三个微型用量指示器。
function CompactAllowanceSummary({
  allowances,
  credentialID,
  includeSharedAllowances,
  t,
}: CompactAllowanceSummaryProps) {
  // credentialAllowances keeps ownership exact and never treats shared usage as credential-specific.
  // credentialAllowances 保持归属精确，绝不将共享用量视为凭据专属。
  const credentialAllowances = allowances.filter(
    (allowance) => allowance.credential_id === credentialID,
  );
  // sharedAllowances is rendered only once to avoid duplicating provider-level usage across account rows.
  // sharedAllowances 仅渲染一次，以避免跨账号行重复供应商级用量。
  const sharedAllowances = includeSharedAllowances
    ? allowances.filter((allowance) => allowance.credential_id === undefined)
    : [];
  const scopedAllowances = [...credentialAllowances, ...sharedAllowances];
  const miniMaxRows = miniMaxAllowanceRows(scopedAllowances);
  if (miniMaxRows.length > 0) {
    return <MiniMaxAllowanceSummary rows={miniMaxRows} t={t} />;
  }
  const tavilySummary = tavilyAllowanceSummary(scopedAllowances);
  if (tavilySummary) {
    return <TavilyAllowanceSummary summary={tavilySummary} t={t} />;
  }
  // visibleAllowances caps table density while retaining the full detailed contract in the model and resource dialogs.
  // visibleAllowances 限制表格密度，同时在模型与资源对话框中保留完整详情契约。
  const visibleAllowances = scopedAllowances.slice(0, 3);
  const hiddenAllowanceCount =
    credentialAllowances.length +
    sharedAllowances.length -
    visibleAllowances.length;
  if (visibleAllowances.length === 0) {
    return (
      <span className="text-muted-foreground text-xs">
        {t("providers.noUsage")}
      </span>
    );
  }
  return (
    <div className="w-48 space-y-1.5">
      {visibleAllowances.map((allowance, index) => {
        // progress is used only when the canonical catalog supplied a normalized remaining ratio.
        // progress 仅在规范目录提供了规范化剩余比例时使用。
        const progress =
          allowance.remaining_ratio === undefined
            ? undefined
            : Math.round(allowance.remaining_ratio * 100);
        const shared = allowance.credential_id === undefined;
        return (
          <div
            key={`${allowance.kind}\u0000${allowance.metric}\u0000${allowance.scope}\u0000${index}`}
            className="space-y-0.5"
          >
            <div className="flex items-center justify-between gap-2 text-[11px] leading-none">
              <span
                className="min-w-0 truncate"
                title={allowanceMetricLabel(
                  t,
                  allowance.metric,
                  allowance.window,
                )}
              >
                {allowanceMetricLabel(t, allowance.metric, allowance.window)}
                {shared ? ` · ${t("providers.sharedUsage")}` : ""}
              </span>
              <span className="text-muted-foreground shrink-0 tabular-nums">
                {progress === undefined
                  ? compactAllowanceValue(allowance, t)
                  : `${progress}%`}
              </span>
            </div>
            {progress !== undefined ? (
              <div
                className="bg-muted h-1.5 overflow-hidden rounded-full"
                role="progressbar"
                aria-label={allowanceMetricLabel(
                  t,
                  allowance.metric,
                  allowance.window,
                )}
                aria-valuemin={0}
                aria-valuemax={100}
                aria-valuenow={progress}
              >
                <div
                  className={`h-full rounded-full ${progress <= 10 ? "bg-destructive" : progress <= 30 ? "bg-amber-500" : "bg-emerald-500"}`}
                  style={{ width: `${progress}%` }}
                />
              </div>
            ) : null}
          </div>
        );
      })}
      {hiddenAllowanceCount > 0 ? (
        <p className="text-muted-foreground text-[11px] leading-none">
          +{hiddenAllowanceCount}
        </p>
      ) : null}
    </div>
  );
}

// compactAllowanceValue renders the exact available amount for observations that do not provide a progress ratio.
// compactAllowanceValue 为未提供进度比例的观测渲染精确可用数量。
function compactAllowanceValue(
  allowance: ProviderAllowance,
  t: (key: TranslationKey) => string,
): string {
  if (allowance.status === "unlimited") return t("providers.unlimited");
  const value = allowance.remaining ?? allowance.limit ?? allowance.used;
  if (value === undefined) return t("providers.unknownAmount");
  if (allowance.unit === "minor_currency_units") {
    return formatMinorCurrency(value, allowance.currency) ?? value;
  }
  return `${value} ${allowanceDisplayUnit(allowance)}`;
}

// formatResourceBytes renders provider-reported byte counts without exposing file content.
// formatResourceBytes 渲染供应商报告的字节数，而不暴露文件内容。
function formatResourceBytes(sizeBytes: number): string {
  if (sizeBytes < 1024) return `${sizeBytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = sizeBytes / 1024;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }
  return `${value.toLocaleString(undefined, {
    maximumFractionDigits: 1,
  })} ${units[unitIndex]}`;
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
  // onAddCredential opens credential acquisition for this exact configured instance when supplied.
  // onAddCredential 在提供时为此精确已配置实例打开凭据获取流程。
  onAddCredential?: () => void;
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
  onAddCredential,
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
          <div className="flex min-w-0 items-center gap-3">
            <ProviderIcon
              definitionID={provider.instance.definition_id}
              groupID={definition?.group_id}
              className="size-[26px]"
            />
            <div className="min-w-0">
              <CardTitle>{provider.instance.display_name}</CardTitle>
              <CardDescription className="mt-1">
                {definition?.display_name ?? provider.instance.definition_id}
              </CardDescription>
            </div>
          </div>
          <div className="flex flex-wrap items-center justify-end gap-2">
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
            {onAddCredential ? (
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={onAddCredential}
              >
                <PlusIcon className="size-3.5" />
                {t("providers.addCredential")}
              </Button>
            ) : null}
          </div>
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
        {metadata?.voices.length ? (
          <div>
            <h4 className="mb-2 text-sm font-medium">
              {t("providers.voices")}
            </h4>
            <ul className="divide-y rounded-md border">
              {metadata.voices.map((voice) => (
                <li
                  key={`${voice.voice_id}\u0000${voice.credential_id}`}
                  className="flex items-center justify-between gap-3 px-3 py-2 text-sm"
                >
                  <div className="min-w-0">
                    <p className="truncate font-medium">{voice.display_name}</p>
                    <p className="text-muted-foreground truncate font-mono text-xs">
                      {t("providers.voiceIdentifier")}: {voice.voice_id}
                    </p>
                    {voice.descriptions.length ? (
                      <p className="text-muted-foreground line-clamp-2 text-xs">
                        {voice.descriptions.join(" · ")}
                      </p>
                    ) : null}
                  </div>
                  <Badge variant="outline" className="shrink-0">
                    {t("providers.voiceAccount")}: {voice.credential_label}
                  </Badge>
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
        <div className="grid gap-2 sm:grid-cols-[minmax(0,1fr)_minmax(12rem,16rem)] sm:items-center">
          <div>
            <p className="text-sm font-medium">
              {t("providers.routingStrategy")}
            </p>
            <p className="text-muted-foreground text-xs">
              {t("providers.routingStrategyHelp")}
            </p>
          </div>
          <ReadonlyCombobox
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
            options={[
              { value: "inherit", label: t("providers.routingInherit") },
              { value: "round_robin", label: t("settings.roundRobin") },
              { value: "fill_first", label: t("settings.fillFirst") },
            ]}
            className="w-full"
          />
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
          {provider.credentials.length === 0 ? (
            <div className="rounded-md border border-dashed px-3 py-6 text-center text-sm text-muted-foreground">
              {t("providers.noCredentialsForProvider")}
            </div>
          ) : (
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
                            disabled={refreshingCredentialIDs.has(
                              credential.id,
                            )}
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
                                disabled={deletingCredentialIDs.has(
                                  credential.id,
                                )}
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
                            const priority = Number.parseInt(
                              event.currentTarget.value,
                              10,
                            );
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
                          <ReadonlyCombobox
                            value={
                              credential.declared_plan?.plan_option_id ?? ""
                            }
                            onValueChange={(value) => {
                              if (
                                value !==
                                credential.declared_plan?.plan_option_id
                              ) {
                                void onChangeCredentialPlan(
                                  provider.instance.id,
                                  credential.id,
                                  value,
                                );
                              }
                            }}
                            options={(definition?.plan_options ?? [])
                              .filter(
                                (option) =>
                                  option.manually_selectable &&
                                  option.auth_method_ids.includes(
                                    credential.auth_method_id,
                                  ),
                              )
                              .map((option) => ({
                                value: option.id,
                                label: option.display_name,
                              }))}
                            placeholder={t("providers.selectMembershipPlan")}
                            className="w-full"
                          />
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
          )}
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
  // ratio treats explicit unlimited resources as fully available without fabricating a finite remaining amount.
  // ratio 将明确无限的资源视为完全可用，但不虚构有限剩余量。
  const ratio =
    allowance.status === "unlimited" ? 1 : allowance.remaining_ratio;
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
              {allowanceMetricLabel(t, allowance.metric, allowance.window)}
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
              aria-label={allowanceMetricLabel(
                t,
                allowance.metric,
                allowance.window,
              )}
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
              {allowanceMetricLabel(t, allowance.metric, allowance.window)}
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
          {allowanceMetricLabel(t, allowance.metric, allowance.window)}
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
  window?: ProviderAllowanceWindow,
): string {
  const known: Partial<Record<string, TranslationKey>> = {
    codex_primary: "providers.allowanceMetrics.codexPrimary",
    codex_secondary: "providers.allowanceMetrics.codexSecondary",
    code_review_primary: "providers.allowanceMetrics.codeReviewPrimary",
    code_review_secondary: "providers.allowanceMetrics.codeReviewSecondary",
    rate_limit_reset_credits: "providers.allowanceMetrics.resetCredits",
    "tavily.key.total": "providers.allowanceMetrics.tavilyKeyTotal",
    "tavily.account.plan": "providers.allowanceMetrics.tavilyAccountPlan",
    "tavily.account.paygo": "providers.allowanceMetrics.tavilyAccountPaygo",
    "tavily.key.search": "providers.allowanceMetrics.tavilyKeySearch",
    "tavily.key.extract": "providers.allowanceMetrics.tavilyKeyExtract",
    "tavily.account.search": "providers.allowanceMetrics.tavilyAccountSearch",
    "tavily.account.extract": "providers.allowanceMetrics.tavilyAccountExtract",
    five_hour: "providers.allowanceMetrics.fiveHour",
    five_hour_usage: "providers.allowanceMetrics.fiveHour",
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
  // An unnamed Kimi limit is identified by its explicit five-hour rolling duration, matching already persisted snapshots.
  // 未命名 Kimi 限额通过其显式五小时滚动时长识别，从而兼容已经持久化的快照。
  if (
    /^limit_\d+$/.test(metric) &&
    window?.kind === "rolling" &&
    window.duration === "18000000000000"
  ) {
    return t("providers.allowanceMetrics.fiveHour");
  }
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
    case "unlimited":
      return t("providers.unlimited");
    case "low":
      return t("providers.allowanceStatus.low");
    case "exhausted":
      return t("providers.allowanceStatus.exhausted");
    case "unknown_sufficiency":
      return t("providers.allowanceStatus.unknown");
    case "unavailable":
      return t("providers.allowanceStatus.unavailable");
    case "not_included":
      return t("providers.notInPlan");
    default:
      return status;
  }
}

// allowanceWindowLabel preserves provider-authored window kind, duration, calendar unit, and time zone in one compact label.
// allowanceWindowLabel 在一个紧凑标签中保留供应商编写的窗口类型、时长、日历单位和时区。
function allowanceWindowLabel(window: ProviderAllowanceWindow): string {
  // parts retains only window nodes that are present in the validated management response.
  // parts 仅保留已校验管理响应中实际存在的窗口节点。
  const parts: string[] = [window.kind];
  if (window.duration !== "0")
    parts.push(formatAllowanceDuration(window.duration));
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
export function providerStatusLabel(
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

// CredentialSubtypeSelectionRowProps defines one exact native subtype selected after its top-level provider category.
// CredentialSubtypeSelectionRowProps 定义在顶层供应商大类之后选择的一个精确原生子类。
interface CredentialSubtypeSelectionRowProps {
  // definition contains the exact site, account product, or commercial plan.
  // definition 包含精确站点、账号产品或商业套餐。
  definition: CredentialProviderDefinition;
  // onSelect advances credential creation with the immutable definition identifier.
  // onSelect 使用不可变 Definition 标识推进凭据创建。
  onSelect: (definitionID: string) => void;
}

// CredentialSubtypeSelectionRow renders one compact subtype choice without flattening it into the left provider directory.
// CredentialSubtypeSelectionRow 渲染一个紧凑子类选项，且不将其平铺到左侧供应商目录。
function CredentialSubtypeSelectionRow({
  definition,
  onSelect,
}: CredentialSubtypeSelectionRowProps) {
  const { t } = useI18n();
  // subtypeName prefers the category-local variant label and retains the authoritative definition name as fallback.
  // subtypeName 优先使用分类内变体标签，并以权威 Definition 名称作为回退。
  const subtypeName = definition.variant_name ?? definition.display_name;
  return (
    <button
      type="button"
      className="group grid w-full items-center gap-2 border-b bg-background px-3 py-2 text-left outline-none transition-colors last:border-b-0 hover:bg-muted/50 focus-visible:z-10 focus-visible:ring-2 focus-visible:ring-ring sm:grid-cols-[8rem_minmax(0,1fr)_auto]"
      aria-label={`${t("providers.select")} ${subtypeName}`}
      onClick={() => onSelect(definition.id)}
      data-credential-subtype={definition.id}
    >
      <div className="font-semibold">{subtypeName}</div>
      <div className="min-w-0 space-y-1">
        {definition.variant_description ? (
          <p className="text-sm leading-tight">
            {localizedDescription(
              t,
              definition.variant_description_key,
              definition.variant_description,
            )}
          </p>
        ) : null}
        <div className="text-muted-foreground flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1 text-xs">
          <span className="flex items-center gap-1.5">
            <CableIcon className="size-3.5 shrink-0" aria-hidden="true" />
            <Badge variant="secondary" className="h-5 px-2 text-xs">
              {definition.protocol_profile_id}
            </Badge>
          </span>
          {(definition.endpoint_presets ?? []).map((endpoint) => (
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
        <ReadonlyCombobox
          value={protocolProfileID}
          onValueChange={(value) => {
            setProtocolProfileID(value);
          }}
          options={profiles.map((profile) => ({
            value: profile.id,
            label: profile.display_name,
          }))}
          id="custom-provider-protocol"
          className="w-full"
          placeholder={t("providers.selectProtocol")}
        />
        {selectedProfile ? (
          <p className="text-muted-foreground text-xs">
            {t("providers.authentication")}:{" "}
            {selectedProfile.allowed_auth_methods[0] === "bearer"
              ? "Bearer"
              : "x-api-key"}
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
          placeholder={
            protocolProfileID === "anthropic.messages"
              ? "https://api.example.com"
              : "https://api.example.com/v1"
          }
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

// ProviderWorkflowDefinition contains the common credential contract and optional system-only presentation metadata.
// ProviderWorkflowDefinition 包含共用凭据合同与可选的仅系统展示元数据。
export type ProviderWorkflowDefinition = ProviderDefinitionIdentity &
  Partial<
    Pick<
      ProviderDefinition,
      "variant_description" | "variant_description_key" | "endpoint_presets"
    >
  >;

// ProviderOnboardingPanelProps binds one exact definition and active management credential to its real workflow.
// ProviderOnboardingPanelProps 将一个精确定义和当前管理凭证绑定到真实工作流。
export interface ProviderOnboardingPanelProps {
  // definition is the exact selected site or commercial plan.
  // definition 是精确选择的站点或商业套餐。
  definition: ProviderWorkflowDefinition;
  // managementAuthToken authenticates only the management-plane workflow.
  // managementAuthToken 仅认证管理面工作流。
  managementAuthToken: string;
  // onComplete reloads the authorized list after the server commits onboarding.
  // onComplete 在服务端提交录入后重新加载已授权列表。
  onComplete: () => void;
  // reauthorizationTarget selects an existing credential instead of creating an instance.
  // reauthorizationTarget 选择一个既有凭据而不是创建实例。
  reauthorizationTarget?: CredentialReauthorizationSelection | null;
  // attachmentTarget selects an existing provider configuration for a new credential.
  // attachmentTarget 为新凭据选择一个既有供应商配置。
  attachmentTarget?: CredentialAttachmentSelection | null;
  // credentialIntent keeps labels credential-focused when first authorization must also create the configuration.
  // credentialIntent 在首次授权必须同时创建配置时仍保持以凭据为中心的界面文案。
  credentialIntent?: boolean;
}

// ProviderOnboardingPanel performs API-key, service-account, or server-confidential interactive onboarding.
// ProviderOnboardingPanel 执行 API Key、服务账号或服务端保密交互授权录入。
export function ProviderOnboardingPanel({
  definition,
  managementAuthToken,
  onComplete,
  reauthorizationTarget,
  attachmentTarget,
  credentialIntent = false,
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
  // isMiniMaxDeviceFlow identifies the two explicit regional MiniMax definitions.
  // isMiniMaxDeviceFlow 标识两个显式区域 MiniMax Definition。
  const isMiniMaxDeviceFlow =
    isDeviceFlow &&
    (definition.id === "system_minimax_api" ||
      definition.id === "system_minimax_cn");
  // requiresOperatorName is true only when the selected credential carries no provider-issued display identity.
  // requiresOperatorName 仅在所选凭据不携带供应商签发的显示身份时为 true。
  const requiresOperatorName =
    !reauthorizationTarget &&
    (authMethod?.type === "api_key" ||
      (isDeviceFlow &&
        (definition.id === "system_kimi_coding_plan" ||
          isXAIDeviceFlow ||
          isMiniMaxDeviceFlow)));
  // name is the sole operator-authored label and is reused by the server for the instance and credential.
  // name 是唯一由操作员填写的标签，并由服务端同时用于实例与凭据。
  const [name, setName] = useState(
    reauthorizationTarget?.credential.label ?? definition.display_name,
  );
  const [secret, setSecret] = useState("");
  // endpointPreset is the exact code-owned destination selected by this definition.
  // endpointPreset 是此 Definition 选择的精确代码拥有目标。
  const endpointPreset = definition.endpoint_presets?.[0];
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
    definition.endpoint_presets?.[0]?.region ?? "us-central1",
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
  // authorizationTargetPayload distinguishes new-instance, existing-instance attachment, and exact credential replacement.
  // authorizationTargetPayload 区分新实例、既有实例附加与精确凭据替换。
  const authorizationTargetPayload = reauthorizationTarget
    ? {
        provider_instance_id: reauthorizationTarget.providerInstanceID,
        credential_id: reauthorizationTarget.credential.id,
      }
    : attachmentTarget
      ? { provider_instance_id: attachmentTarget.providerInstanceID }
      : {};

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
        const cancelFlow = isMiniMaxDeviceFlow
          ? cancelMiniMaxDeviceFlow
          : isXAIDeviceFlow
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
    isMiniMaxDeviceFlow,
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
        ...authorizationTargetPayload,
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
      } else if (attachmentTarget) {
        await attachProviderCredential(
          managementAuthToken,
          attachmentTarget.providerInstanceID,
          {
            auth_method_id: authMethodID,
            label: name.trim(),
            secret,
            ...(planOptionID &&
            (authMethod.plan_acquisition === "manual_required" ||
              authMethod.plan_acquisition === "manual_optional")
              ? { plan_option_id: planOptionID }
              : {}),
          },
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
        ...authorizationTargetPayload,
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
      const cancelFlow = isMiniMaxDeviceFlow
        ? cancelMiniMaxDeviceFlow
        : isXAIDeviceFlow
          ? cancelXAIDeviceFlow
          : isCodexDeviceFlow
            ? cancelCodexDeviceFlow
            : cancelKimiDeviceFlow;
      const flow = isMiniMaxDeviceFlow
        ? await startMiniMaxDeviceFlow(
            managementAuthToken,
            definition.id === "system_minimax_cn" ? "cn" : "global",
          )
        : isXAIDeviceFlow
          ? await startXAIDeviceFlow(managementAuthToken)
          : isCodexDeviceFlow
            ? await startCodexDeviceFlow(managementAuthToken)
            : await startKimiDeviceFlow(managementAuthToken);
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
      const onboardFlow = isMiniMaxDeviceFlow
        ? onboardMiniMaxDeviceFlow
        : isXAIDeviceFlow
          ? onboardXAIDeviceFlow
          : isCodexDeviceFlow
            ? onboardCodexDeviceFlow
            : onboardKimiDeviceFlow;
      const result = await onboardFlow(managementAuthToken, deviceFlow.id, {
        provider_definition_id: definition.id,
        name: requiresOperatorName ? name.trim() : "",
        ...authorizationTargetPayload,
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
      const cancelFlow = isMiniMaxDeviceFlow
        ? cancelMiniMaxDeviceFlow
        : isXAIDeviceFlow
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
      const cancelFlow = isMiniMaxDeviceFlow
        ? cancelMiniMaxDeviceFlow
        : isXAIDeviceFlow
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
    setVertexLocation(
      definition.endpoint_presets?.[0]?.region ?? "us-central1",
    );
    setMessageKey(null);
  }

  if (
    !authMethod ||
    (!isDirectSecretAuth &&
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
        <div className="flex items-center gap-3">
          <ProviderIcon
            definitionID={definition.id}
            groupID={definition.group_id}
            className="size-[26px]"
          />
          <div className="min-w-0">
            <CardTitle>{definition.display_name}</CardTitle>
            <CardDescription className="mt-1">
              {localizedDescription(
                t,
                definition.variant_description_key,
                definition.variant_description ?? definition.display_name,
              )}
            </CardDescription>
          </div>
        </div>
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
              <Label htmlFor="provider-name">
                {t(
                  attachmentTarget || credentialIntent
                    ? "providers.credentialName"
                    : "providers.name",
                )}
              </Label>
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
          {authMethod?.type === "api_key" &&
          !reauthorizationTarget &&
          !attachmentTarget
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
              <ReadonlyCombobox
                value={planOptionID}
                onValueChange={(value) => {
                  setPlanOptionID(value);
                }}
                options={selectablePlanOptions.map((option) => ({
                  value: option.id,
                  label: option.display_name,
                }))}
                id="provider-membership-plan"
                className="w-full"
                placeholder={t("providers.selectMembershipPlan")}
              />
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
                  : attachmentTarget || credentialIntent
                    ? t("providers.addCredential")
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
