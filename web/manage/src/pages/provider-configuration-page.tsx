import { type FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import {
  BoxesIcon,
  CableIcon,
  KeyRoundIcon,
  LoaderCircleIcon,
  LockKeyholeIcon,
  PlusIcon,
  PencilIcon,
  RefreshCwIcon,
  ServerCogIcon,
  Settings2Icon,
  Trash2Icon,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ReadonlyCombobox } from "@/components/ui/readonly-combobox";
import { useI18n } from "@/i18n";
import {
  configureProvider,
  createCustomProviderDefinition,
  discoverCustomProviderModels,
  fetchCustomProtocolProfiles,
  fetchProviderCatalog,
  fetchProviderDefinitions,
  fetchProviderEndpoints,
  fetchProviderCredentials,
  fetchProviderGroups,
  fetchProviderInstances,
  saveCustomProviderModels,
  updateProviderInstance,
  type CustomProtocolProfile,
  type ProviderCatalogMetadata,
  type ProviderDefinitionSummary,
  type ProviderEndpoint,
  type ProviderCredential,
  type ProviderGroup,
  type ProviderInstance,
  type SimpleCustomModelInput,
} from "@/lib/provider-groups";

// ProviderConfigurationPageProps identifies the authenticated management session used for provider-only requests.
// ProviderConfigurationPageProps 标识用于仅供应商请求的已认证管理会话。
interface ProviderConfigurationPageProps {
  // managementAuthToken authorizes management API requests without browser persistence.
  // managementAuthToken 授权管理 API 请求且不进行浏览器持久化。
  managementAuthToken: string;
}

// ProviderInventoryItem joins one provider instance with its non-secret definition, endpoints, and catalog.
// ProviderInventoryItem 将一个供应商实例与其非秘密定义、入口及目录连接起来。
interface ProviderInventoryItem {
  // instance is the credential-independent configuration root.
  // instance 是独立于凭据的配置根。
  instance: ProviderInstance;
  // definition is the exact system or custom integration definition.
  // definition 是精确的系统或自定义集成定义。
  definition: ProviderDefinitionSummary;
  // endpoints contains every configured upstream destination.
  // endpoints 包含全部已配置上游目标。
  endpoints: ProviderEndpoint[];
  // catalog is present only when the management-safe model snapshot loaded successfully.
  // catalog 仅在管理安全模型快照成功加载时存在。
  catalog: ProviderCatalogMetadata | null;
  // credentials contains redacted choices only for explicit custom model discovery.
  // credentials 仅包含用于显式自定义模型发现的脱敏选择项。
  credentials: ProviderCredential[];
}

// ProviderCreationForm contains the exact non-secret values submitted by the provider dialog.
// ProviderCreationForm 包含供应商对话框提交的精确非秘密值。
interface ProviderCreationForm {
  // displayName is the management-facing instance name.
  // displayName 是管理界面显示的实例名称。
  displayName: string;
  // handle is the stable call-plane routing identifier.
  // handle 是稳定的调用面路由标识。
  handle: string;
  // baseURL is the operator-owned endpoint for the selected compatibility protocol.
  // baseURL 是操作员为所选兼容协议拥有的入口。
  baseURL: string;
  // protocolProfileID selects one executable custom-provider protocol.
  // protocolProfileID 选择一个可执行自定义供应商协议。
  protocolProfileID: string;
}

// defaultCustomProtocolProfileID selects OpenAI Chat for every fresh provider draft.
// defaultCustomProtocolProfileID 为每个全新的供应商草稿选择 OpenAI Chat。
const defaultCustomProtocolProfileID = "openai.chat";

// emptyProviderCreationForm returns a fresh provider dialog state without retaining prior operator input.
// emptyProviderCreationForm 返回全新的供应商对话框状态且不保留之前的操作员输入。
function emptyProviderCreationForm(): ProviderCreationForm {
  return {
    displayName: "",
    handle: "",
    baseURL: "",
    protocolProfileID: defaultCustomProtocolProfileID,
  };
}

// supportsStandardModelDiscovery reports whether one custom protocol shares the standard OpenAI-compatible GET /models contract.
// supportsStandardModelDiscovery 表示一个自定义协议是否共享标准 OpenAI 兼容 GET /models 合同。
function supportsStandardModelDiscovery(protocolProfileID: string): boolean {
  return protocolProfileID === "openai.chat" || protocolProfileID === "openai.responses";
}

// ProviderConfigurationPage renders immutable native integrations and credential-independent configured providers.
// ProviderConfigurationPage 渲染不可变原生集成与独立于凭据的已配置供应商。
export function ProviderConfigurationPage({
  managementAuthToken,
}: ProviderConfigurationPageProps) {
  const { t } = useI18n();
  // groups contains code-owned native provider families and exact variants.
  // groups 包含代码拥有的原生供应商系列与精确变体。
  const [groups, setGroups] = useState<ProviderGroup[]>([]);
  // customProtocols contains only server-approved executable custom protocols.
  // customProtocols 仅包含服务端批准的可执行自定义协议。
  const [customProtocols, setCustomProtocols] = useState<CustomProtocolProfile[]>([]);
  // inventory contains provider configurations without credential material.
  // inventory 包含不带凭据材料的供应商配置。
  const [inventory, setInventory] = useState<ProviderInventoryItem[]>([]);
  // loading reports whether the authoritative provider inventory is being loaded.
  // loading 表示是否正在加载权威供应商清单。
  const [loading, setLoading] = useState(true);
  // loadError stores one explicit provider inventory failure.
  // loadError 存储一个显式供应商清单加载失败。
  const [loadError, setLoadError] = useState<string | null>(null);
  // dialogOpen controls the provider-only creation workflow.
  // dialogOpen 控制仅供应商创建流程。
  const [dialogOpen, setDialogOpen] = useState(false);
  // form contains the current non-secret provider configuration draft.
  // form 包含当前非秘密供应商配置草稿。
  const [form, setForm] = useState<ProviderCreationForm>(emptyProviderCreationForm);
  // submitting prevents duplicate provider configuration writes.
  // submitting 防止重复写入供应商配置。
  const [submitting, setSubmitting] = useState(false);
  // submitError reports one explicit provider creation failure.
  // submitError 报告一个显式供应商创建失败。
  const [submitError, setSubmitError] = useState<string | null>(null);
  // discoveryCredentialIDs stores one explicit credential selection per custom provider instance.
  // discoveryCredentialIDs 为每个自定义供应商实例存储一个显式凭据选择。
  const [discoveryCredentialIDs, setDiscoveryCredentialIDs] = useState<Record<string, string>>({});
  // discoveringInstanceIDs identifies custom providers with an active model-list request.
  // discoveringInstanceIDs 标识正在执行模型清单请求的自定义供应商。
  const [discoveringInstanceIDs, setDiscoveringInstanceIDs] = useState<Set<string>>(new Set());
  // discoveryErrors stores explicit discovery failures by provider instance.
  // discoveryErrors 按供应商实例存储显式发现失败。
  const [discoveryErrors, setDiscoveryErrors] = useState<Record<string, string>>({});
  // editingModelsInstanceID identifies the custom provider whose complete simplified model set is being edited.
  // editingModelsInstanceID 标识正在编辑完整简化模型集合的自定义供应商。
  const [editingModelsInstanceID, setEditingModelsInstanceID] = useState("");
  // modelDrafts contains the exact desired model set submitted by the editor.
  // modelDrafts 包含模型编辑器提交的精确期望模型集合。
  const [modelDrafts, setModelDrafts] = useState<SimpleCustomModelInput[]>([]);
  // savingModels prevents duplicate custom model replacement requests.
  // savingModels 防止重复提交自定义模型替换请求。
  const [savingModels, setSavingModels] = useState(false);
  // modelEditorError reports one explicit custom model replacement failure.
  // modelEditorError 报告一个显式自定义模型替换失败。
  const [modelEditorError, setModelEditorError] = useState<string | null>(null);
  // editingProvider identifies one custom provider whose editable local identity is being changed.
  // editingProvider 标识正在修改可编辑本地身份的自定义供应商。
  const [editingProvider, setEditingProvider] = useState<ProviderInventoryItem | null>(null);
  // editDisplayName is the custom provider's replacement management-facing name.
  // editDisplayName 是自定义供应商替换后的管理界面名称。
  const [editDisplayName, setEditDisplayName] = useState("");
  // editHandle is the custom provider's replacement stable routing identifier.
  // editHandle 是自定义供应商替换后的稳定路由标识。
  const [editHandle, setEditHandle] = useState("");
  // savingProviderIdentity prevents duplicate custom provider identity writes.
  // savingProviderIdentity 防止重复写入自定义供应商身份。
  const [savingProviderIdentity, setSavingProviderIdentity] = useState(false);
  // providerIdentityError reports one explicit custom provider identity update failure.
  // providerIdentityError 报告一个显式自定义供应商身份更新失败。
  const [providerIdentityError, setProviderIdentityError] = useState<string | null>(null);

  // systemDefinitions flattens grouped native variants into their exact definition identities.
  // systemDefinitions 将分组原生变体展开为精确定义身份。
  const systemDefinitions = useMemo(
    () => groups.flatMap((group) => group.provider_definitions),
    [groups],
  );
  // selectedCustomProtocol resolves the exact executable profile for new custom definitions.
  // selectedCustomProtocol 为新自定义定义解析精确可执行 Profile。
  const selectedCustomProtocol = useMemo(
    () =>
      customProtocols.find(
        (profile) => profile.id === form.protocolProfileID,
      ) ?? null,
    [customProtocols, form.protocolProfileID],
  );

  // loadInventory reads each management source and joins only records with exact definition ownership.
  // loadInventory 读取每个管理来源，并仅连接具有精确定义归属的记录。
  const loadInventory = useCallback(
    async (signal?: AbortSignal) => {
      setLoading(true);
      setLoadError(null);
      try {
        const [loadedGroups, loadedDefinitions, loadedProtocols, instances] =
          await Promise.all([
            fetchProviderGroups(managementAuthToken, signal),
            fetchProviderDefinitions(managementAuthToken, signal),
            fetchCustomProtocolProfiles(managementAuthToken, signal),
            fetchProviderInstances(managementAuthToken, signal),
          ]);
        const definitionByID = new Map(
          loadedDefinitions.map((definition) => [definition.id, definition]),
        );
        const items = await Promise.all(
          instances.map(async (instance): Promise<ProviderInventoryItem> => {
            const definition = definitionByID.get(instance.definition_id);
            if (!definition) {
              throw new Error("provider instance references an unknown definition");
            }
            const endpoints = await fetchProviderEndpoints(
              managementAuthToken,
              instance.id,
              signal,
            );
            const credentials =
              definition.kind === "custom"
                ? await fetchProviderCredentials(
                    managementAuthToken,
                    instance.id,
                    signal,
                  )
                : [];
            let providerCatalog: ProviderCatalogMetadata | null = null;
            try {
              providerCatalog = await fetchProviderCatalog(
                managementAuthToken,
                instance.id,
                signal,
              );
            } catch {
              providerCatalog = null;
            }
            return { instance, definition, endpoints, catalog: providerCatalog, credentials };
          }),
        );
        setGroups(loadedGroups);
        setCustomProtocols(loadedProtocols);
        setInventory(items);
      } catch (error) {
        if (signal?.aborted) {
          return;
        }
        setLoadError(
          error instanceof Error ? error.message : t("providerConfig.loadFailed"),
        );
      } finally {
        if (!signal?.aborted) {
          setLoading(false);
        }
      }
    },
    [managementAuthToken, t],
  );

  useEffect(() => {
    const controller = new AbortController();
    void loadInventory(controller.signal);
    return () => controller.abort();
  }, [loadInventory]);

  // closeDialog resets all transient provider inputs after the controlled dialog closes.
  // closeDialog 在受控对话框关闭后重置全部临时供应商输入。
  function closeDialog(): void {
    setDialogOpen(false);
    setForm(emptyProviderCreationForm());
    setSubmitError(null);
  }

  // submitProviderConfiguration creates one standard-compatible custom definition and its credential-independent instance.
  // submitProviderConfiguration 创建一个标准兼容自定义定义及其独立于凭据的实例。
  async function submitProviderConfiguration(event: FormEvent): Promise<void> {
    event.preventDefault();
    setSubmitting(true);
    setSubmitError(null);
    try {
      if (!selectedCustomProtocol) {
        throw new Error(t("providerConfig.protocolRequired"));
      }
      const authMethod = selectedCustomProtocol.allowed_auth_methods[0];
      if (!authMethod) {
        throw new Error(t("providerConfig.protocolRequired"));
      }
      const definitionID = await createCustomProviderDefinition(
        managementAuthToken,
        {
          display_name: form.displayName.trim(),
          protocol_profile_id: selectedCustomProtocol.id,
          auth_method: authMethod,
        },
      );
      await configureProvider(managementAuthToken, {
        provider_definition_id: definitionID,
        display_name: form.displayName.trim(),
        handle: form.handle.trim(),
        base_url: form.baseURL.trim(),
      });
      closeDialog();
      await loadInventory();
    } catch (error) {
      setSubmitError(
        error instanceof Error ? error.message : t("providerConfig.createFailed"),
      );
    } finally {
      setSubmitting(false);
    }
  }

  // discoverModels refreshes one custom model catalog with the exact credential selected by the operator.
  // discoverModels 使用操作员精确选择的凭据刷新一个自定义模型目录。
  async function discoverModels(providerInstanceID: string): Promise<void> {
    const credentialID = discoveryCredentialIDs[providerInstanceID];
    if (!credentialID) return;
    setDiscoveringInstanceIDs((current) => new Set(current).add(providerInstanceID));
    setDiscoveryErrors((current) => {
      const next = { ...current };
      delete next[providerInstanceID];
      return next;
    });
    try {
      await discoverCustomProviderModels(
        managementAuthToken,
        providerInstanceID,
        credentialID,
      );
      await loadInventory();
    } catch (error) {
      setDiscoveryErrors((current) => ({
        ...current,
        [providerInstanceID]:
          error instanceof Error ? error.message : t("providerConfig.discoveryFailed"),
      }));
    } finally {
      setDiscoveringInstanceIDs((current) => {
        const next = new Set(current);
        next.delete(providerInstanceID);
        return next;
      });
    }
  }

  // openModelEditor converts the current catalog into an explicit simplified model replacement draft.
  // openModelEditor 将当前目录转换为显式的简化模型替换草稿。
  function openModelEditor(item: ProviderInventoryItem): void {
    setEditingModelsInstanceID(item.instance.id);
    setModelEditorError(null);
    setModelDrafts(
      (item.catalog?.models ?? []).map((model) => {
        const profile =
          model.offerings
            ?.flatMap((offering) => offering.profiles)
            .find((candidate) => candidate.default) ??
          model.offerings?.[0]?.profiles[0];
        const toolCalling = profile?.capabilities.tool_calling;
        const reasoning = profile?.capabilities.reasoning;
        return {
          upstream_model_id: model.upstream_model_id,
          display_name: model.display_name,
          context_window: profile?.capabilities.context_window.known
            ? profile.capabilities.context_window.value
            : undefined,
          max_output_tokens: profile?.capabilities.max_output_tokens.known
            ? profile.capabilities.max_output_tokens.value
            : undefined,
          tool_calling:
            toolCalling === "native" || toolCalling === "unsupported"
              ? toolCalling
              : "unknown",
          reasoning:
            reasoning === "native" || reasoning === "unsupported"
              ? reasoning
              : "unknown",
        };
      }),
    );
  }

  // saveModelDrafts atomically replaces the custom provider's complete simplified model set.
  // saveModelDrafts 原子替换自定义供应商的完整简化模型集合。
  async function saveModelDrafts(): Promise<void> {
    if (!editingModelsInstanceID) return;
    setSavingModels(true);
    setModelEditorError(null);
    try {
      await saveCustomProviderModels(
        managementAuthToken,
        editingModelsInstanceID,
        modelDrafts,
      );
      setEditingModelsInstanceID("");
      setModelDrafts([]);
      await loadInventory();
    } catch (error) {
      setModelEditorError(
        error instanceof Error ? error.message : t("providerConfig.modelSaveFailed"),
      );
    } finally {
      setSavingModels(false);
    }
  }

  // openProviderEditor opens editable local identity fields only for one user-owned custom provider.
  // openProviderEditor 仅为一个用户拥有的自定义供应商打开可编辑本地身份字段。
  function openProviderEditor(item: ProviderInventoryItem): void {
    setEditingProvider(item);
    setEditDisplayName(item.instance.display_name);
    setEditHandle(item.instance.handle);
    setProviderIdentityError(null);
  }

  // saveProviderIdentity persists custom provider identity without changing its protocol, endpoints, models, or credentials.
  // saveProviderIdentity 持久化自定义供应商身份且不改变其协议、入口、模型或凭据。
  async function saveProviderIdentity(): Promise<void> {
    if (!editingProvider) return;
    setSavingProviderIdentity(true);
    setProviderIdentityError(null);
    try {
      await updateProviderInstance(
        managementAuthToken,
        editingProvider.instance.id,
        { display_name: editDisplayName.trim(), handle: editHandle.trim() },
      );
      setEditingProvider(null);
      await loadInventory();
    } catch (error) {
      setProviderIdentityError(
        error instanceof Error ? error.message : t("providerConfig.identitySaveFailed"),
      );
    } finally {
      setSavingProviderIdentity(false);
    }
  }

  return (
    <div className="space-y-6 px-4 lg:px-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-xl font-semibold">{t("providerConfig.title")}</h2>
          <p className="text-sm text-muted-foreground">
            {t("providerConfig.description")}
          </p>
        </div>
        <Button onClick={() => setDialogOpen(true)}>
          <PlusIcon className="size-4" />
          {t("providerConfig.addProvider")}
        </Button>
      </div>

      {loadError ? (
        <Card className="border-destructive/40">
          <CardHeader>
            <CardTitle>{t("providerConfig.loadFailed")}</CardTitle>
            <CardDescription>{loadError}</CardDescription>
          </CardHeader>
        </Card>
      ) : null}

      <section className="space-y-3">
        <div className="flex items-center gap-2">
          <LockKeyholeIcon className="size-4" />
          <h3 className="font-medium">{t("providerConfig.nativeProviders")}</h3>
          <Badge variant="secondary">{systemDefinitions.length}</Badge>
        </div>
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {groups.map((group) => (
            <Card key={group.id}>
              <CardHeader className="gap-2">
                <CardTitle className="text-base">{group.display_name}</CardTitle>
                <CardDescription>{group.description}</CardDescription>
              </CardHeader>
              <CardContent className="flex flex-wrap gap-1.5">
                {group.provider_definitions.map((definition) => (
                  <Badge key={definition.id} variant="outline">
                    {definition.variant_name}
                  </Badge>
                ))}
              </CardContent>
            </Card>
          ))}
        </div>
      </section>

      <section className="space-y-3">
        <div className="flex items-center gap-2">
          <ServerCogIcon className="size-4" />
          <h3 className="font-medium">{t("providerConfig.configuredProviders")}</h3>
          <Badge variant="secondary">{inventory.length}</Badge>
        </div>
        {loading ? (
          <div className="flex items-center gap-2 rounded-lg border p-4 text-sm text-muted-foreground">
            <LoaderCircleIcon className="size-4 animate-spin" />
            {t("providerConfig.loading")}
          </div>
        ) : inventory.length === 0 ? (
          <div className="rounded-lg border border-dashed p-8 text-center text-sm text-muted-foreground">
            {t("providerConfig.empty")}
          </div>
        ) : (
          <div className="grid gap-4 xl:grid-cols-2">
            {inventory.map(({ instance, definition, endpoints, catalog, credentials }) => (
              <Card key={instance.id}>
                <CardHeader className="gap-2">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <CardTitle className="text-base">{instance.display_name}</CardTitle>
                    <div className="flex gap-1.5">
                      <Badge variant="outline">{definition.kind}</Badge>
                      <Badge>{instance.status}</Badge>
                      {definition.kind === "custom" ? (
                        <Button
                          type="button"
                          variant="ghost"
                          size="icon-sm"
                          aria-label={t("providerConfig.editSettings")}
                          onClick={() => openProviderEditor({ instance, definition, endpoints, catalog, credentials })}
                        >
                          <Settings2Icon className="size-4" />
                        </Button>
                      ) : null}
                    </div>
                  </div>
                  <CardDescription>{instance.handle}</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4 text-sm">
                  <div className="flex flex-wrap gap-2">
                    <Badge variant="secondary">
                      <CableIcon className="mr-1 size-3" />
                      {definition.protocol_profile_id}
                    </Badge>
                    <Badge variant="secondary">
                      <BoxesIcon className="mr-1 size-3" />
                      {catalog?.models.length ?? 0} {t("providerConfig.models")}
                    </Badge>
                    <Badge variant="secondary">
                      <KeyRoundIcon className="mr-1 size-3" />
                      {instance.credential_count} {t("providerConfig.credentials")}
                    </Badge>
                  </div>
                  <div className="space-y-2">
                    {endpoints.map((endpoint) => (
                      <div key={endpoint.id} className="rounded-md bg-muted/50 px-3 py-2">
                        <div className="break-all font-mono text-xs">{endpoint.base_url}</div>
                        <div className="mt-1 text-xs text-muted-foreground">
                          {endpoint.region || t("providerConfig.globalEndpoint")} · {endpoint.status}
                        </div>
                      </div>
                    ))}
                  </div>
                  {catalog ? (
                    <div className="space-y-2">
                      {catalog.models.slice(0, 8).map((model) => {
                        const profile =
                          model.offerings
                            ?.flatMap((offering) => offering.profiles)
                            .find((candidate) => candidate.default) ??
                          model.offerings?.[0]?.profiles[0];
                        return (
                          <div key={model.id} className="rounded-md border px-3 py-2">
                            <div className="flex flex-wrap items-center justify-between gap-2">
                              <span className="font-medium">{model.display_name}</span>
                              <span className="font-mono text-xs text-muted-foreground">{model.upstream_model_id}</span>
                            </div>
                            {profile ? (
                              <div className="mt-2 flex flex-wrap gap-1.5">
                                <Badge variant="outline">
                                  {t("providerConfig.contextWindow")}: {profile.capabilities.context_window.known ? profile.capabilities.context_window.value : t("providerConfig.unknown")}
                                </Badge>
                                <Badge variant="outline">
                                  {t("providerConfig.maxOutputTokens")}: {profile.capabilities.max_output_tokens.known ? profile.capabilities.max_output_tokens.value : t("providerConfig.unknown")}
                                </Badge>
                                <Badge variant="outline">{t("providerConfig.toolCalling")}: {profile.capabilities.tool_calling}</Badge>
                                <Badge variant="outline">{t("providerConfig.reasoning")}: {profile.capabilities.reasoning}</Badge>
                                <Badge variant="outline">{profile.capabilities.input_modalities.join(", ")} → {profile.capabilities.output_modalities.join(", ")}</Badge>
                              </div>
                            ) : null}
                          </div>
                        );
                      })}
                      {catalog.models.length > 8 ? (
                        <Badge variant="outline">+{catalog.models.length - 8}</Badge>
                      ) : null}
                    </div>
                  ) : (
                    <p className="text-xs text-destructive">
                      {t("providerConfig.catalogUnavailable")}
                    </p>
                  )}
                  {definition.kind === "custom" ? (
                    <div className="grid gap-2 rounded-md border p-3 sm:grid-cols-[minmax(0,1fr)_auto_auto] sm:items-end">
                      {supportsStandardModelDiscovery(definition.protocol_profile_id) ? (
                        <>
                          <div className="space-y-1.5">
                            <Label>{t("providerConfig.discoveryCredential")}</Label>
                            <ReadonlyCombobox
                              value={discoveryCredentialIDs[instance.id] ?? ""}
                              onValueChange={(value) =>
                                setDiscoveryCredentialIDs((current) => ({
                                  ...current,
                                  [instance.id]: value,
                                }))
                              }
                              options={credentials.map((credential) => ({
                                value: credential.id,
                                label: credential.label,
                              }))}
                              placeholder={t("providerConfig.selectCredential")}
                              className="w-full"
                            />
                          </div>
                          <Button
                            type="button"
                            variant="outline"
                            disabled={
                              !discoveryCredentialIDs[instance.id] ||
                              discoveringInstanceIDs.has(instance.id)
                            }
                            onClick={() => void discoverModels(instance.id)}
                          >
                            <RefreshCwIcon className={discoveringInstanceIDs.has(instance.id) ? "size-4 animate-spin" : "size-4"} />
                            {t("providerConfig.discoverModels")}
                          </Button>
                        </>
                      ) : null}
                      <Button type="button" variant="outline" onClick={() => openModelEditor({ instance, definition, endpoints, catalog, credentials })}>
                        <PencilIcon className="size-4" />
                        {t("providerConfig.editModels")}
                      </Button>
                      {supportsStandardModelDiscovery(definition.protocol_profile_id) && discoveryErrors[instance.id] ? (
                        <p className="text-xs text-destructive sm:col-span-3">{discoveryErrors[instance.id]}</p>
                      ) : null}
                    </div>
                  ) : null}
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </section>

      <Dialog open={dialogOpen} onOpenChange={(open) => (open ? setDialogOpen(true) : closeDialog())}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <div>
              <DialogTitle>{t("providerConfig.addProvider")}</DialogTitle>
              <DialogDescription>{t("providerConfig.addDescription")}</DialogDescription>
            </div>
          </DialogHeader>
          <form className="space-y-4" onSubmit={submitProviderConfiguration}>
            <div className="space-y-2">
              <Label>{t("providerConfig.protocol")}</Label>
              <ReadonlyCombobox
                value={form.protocolProfileID}
                onValueChange={(value) =>
                  setForm((current) => ({ ...current, protocolProfileID: value }))
                }
                options={customProtocols.map((profile) => ({
                  value: profile.id,
                  label: profile.display_name,
                }))}
                placeholder={t("providerConfig.selectProtocol")}
                className="w-full"
              />
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="provider-display-name">{t("providerConfig.displayName")}</Label>
                <Input
                  id="provider-display-name"
                  value={form.displayName}
                  onChange={(event) =>
                    setForm((current) => ({ ...current, displayName: event.target.value }))
                  }
                  placeholder={t("providerConfig.displayNamePlaceholder")}
                  required
                />
                <p className="text-muted-foreground text-xs">
                  {t("providerConfig.displayNameHelp")}
                </p>
              </div>
              <div className="space-y-2">
                <Label htmlFor="provider-handle">{t("providerConfig.handle")}</Label>
                <Input
                  id="provider-handle"
                  value={form.handle}
                  onChange={(event) =>
                    setForm((current) => ({ ...current, handle: event.target.value }))
                  }
                  pattern="[a-z][a-z0-9_.-]{0,127}"
                  maxLength={128}
                  placeholder="deepseek"
                  required
                />
                <p className="text-muted-foreground text-xs">
                  {t("providerConfig.handleHelp")}
                </p>
              </div>
            </div>
            <div className="space-y-2">
              <Label htmlFor="provider-base-url">{t("providerConfig.baseURL")}</Label>
              <Input
                id="provider-base-url"
                type="url"
                value={form.baseURL}
                onChange={(event) =>
                  setForm((current) => ({ ...current, baseURL: event.target.value }))
                }
                placeholder={
                  form.protocolProfileID === "anthropic.messages"
                    ? "https://api.example.com"
                    : "https://api.example.com/v1"
                }
                required
              />
            </div>
            {submitError ? <p className="text-sm text-destructive">{submitError}</p> : null}
            <div className="flex justify-end gap-2">
              <Button type="button" variant="outline" onClick={closeDialog}>
                {t("providerConfig.cancel")}
              </Button>
              <Button
                type="submit"
                disabled={
                  submitting ||
                  !form.displayName.trim() ||
                  !form.handle.trim() ||
                  !form.baseURL.trim() ||
                  !form.protocolProfileID
                }
              >
                {submitting ? <LoaderCircleIcon className="size-4 animate-spin" /> : null}
                {submitting ? t("providerConfig.creating") : t("providerConfig.create")}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      <Dialog
        open={editingModelsInstanceID !== ""}
        onOpenChange={(open) => {
          if (!open) {
            setEditingModelsInstanceID("");
            setModelDrafts([]);
            setModelEditorError(null);
          }
        }}
      >
        <DialogContent className="max-w-4xl">
          <DialogHeader>
            <div>
              <DialogTitle>{t("providerConfig.editModels")}</DialogTitle>
              <DialogDescription>{t("providerConfig.editModelsDescription")}</DialogDescription>
            </div>
          </DialogHeader>
          <div className="space-y-3">
            {modelDrafts.map((model, index) => (
              <div key={index} className="space-y-3 rounded-lg border p-3">
                <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-[minmax(12rem,1fr)_minmax(12rem,1fr)_10rem_10rem_auto]">
                  <div className="space-y-1.5">
                    <Label htmlFor={`model-upstream-id-${index}`}>
                      {t("providerConfig.upstreamModelID")}
                      <span className="text-destructive" aria-hidden="true"> *</span>
                    </Label>
                    <Input
                      id={`model-upstream-id-${index}`}
                      value={model.upstream_model_id}
                      placeholder={t("providerConfig.upstreamModelIDPlaceholder")}
                      onChange={(event) =>
                        setModelDrafts((current) => current.map((candidate, candidateIndex) => candidateIndex === index ? { ...candidate, upstream_model_id: event.target.value } : candidate))
                      }
                      required
                    />
                  </div>
                  <div className="space-y-1.5">
                    <Label htmlFor={`model-display-name-${index}`}>
                      {t("providerConfig.modelDisplayName")}
                      <span className="text-muted-foreground font-normal"> ({t("providerConfig.optional")})</span>
                    </Label>
                    <Input
                      id={`model-display-name-${index}`}
                      value={model.display_name}
                      placeholder={t("providerConfig.modelDisplayNamePlaceholder")}
                      onChange={(event) =>
                        setModelDrafts((current) => current.map((candidate, candidateIndex) => candidateIndex === index ? { ...candidate, display_name: event.target.value } : candidate))
                      }
                    />
                  </div>
                  <div className="space-y-1.5">
                    <Label htmlFor={`model-context-window-${index}`}>
                      {t("providerConfig.contextWindow")}
                      <span className="text-muted-foreground font-normal"> ({t("providerConfig.optional")})</span>
                    </Label>
                    <Input
                      id={`model-context-window-${index}`}
                      type="number"
                      min={1}
                      value={model.context_window ?? ""}
                      placeholder="128000"
                      onChange={(event) =>
                        setModelDrafts((current) => current.map((candidate, candidateIndex) => candidateIndex === index ? { ...candidate, context_window: event.target.value ? Number.parseInt(event.target.value, 10) : undefined } : candidate))
                      }
                    />
                  </div>
                  <div className="space-y-1.5">
                    <Label htmlFor={`model-max-output-${index}`}>
                      {t("providerConfig.maxOutputTokens")}
                      <span className="text-muted-foreground font-normal"> ({t("providerConfig.optional")})</span>
                    </Label>
                    <Input
                      id={`model-max-output-${index}`}
                      type="number"
                      min={1}
                      value={model.max_output_tokens ?? ""}
                      placeholder="8192"
                      onChange={(event) =>
                        setModelDrafts((current) => current.map((candidate, candidateIndex) => candidateIndex === index ? { ...candidate, max_output_tokens: event.target.value ? Number.parseInt(event.target.value, 10) : undefined } : candidate))
                      }
                    />
                  </div>
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="self-end"
                    aria-label={t("providerConfig.removeModel")}
                    onClick={() => setModelDrafts((current) => current.filter((_, candidateIndex) => candidateIndex !== index))}
                  >
                    <Trash2Icon className="size-4 text-destructive" />
                  </Button>
                </div>
                <div className="grid gap-3 sm:grid-cols-2">
                  <ReadonlyCombobox
                    value={model.tool_calling}
                    onValueChange={(value) => {
                      if (value === "native" || value === "unsupported" || value === "unknown") {
                        setModelDrafts((current) => current.map((candidate, candidateIndex) => candidateIndex === index ? { ...candidate, tool_calling: value } : candidate));
                      }
                    }}
                    options={[
                      { value: "unknown", label: `${t("providerConfig.toolCalling")}: ${t("providerConfig.unknown")}` },
                      { value: "native", label: `${t("providerConfig.toolCalling")}: ${t("providerConfig.native")}` },
                      { value: "unsupported", label: `${t("providerConfig.toolCalling")}: ${t("providerConfig.unsupported")}` },
                    ]}
                    className="w-full"
                  />
                  <ReadonlyCombobox
                    value={model.reasoning}
                    onValueChange={(value) => {
                      if (value === "native" || value === "unsupported" || value === "unknown") {
                        setModelDrafts((current) => current.map((candidate, candidateIndex) => candidateIndex === index ? { ...candidate, reasoning: value } : candidate));
                      }
                    }}
                    options={[
                      { value: "unknown", label: `${t("providerConfig.reasoning")}: ${t("providerConfig.unknown")}` },
                      { value: "native", label: `${t("providerConfig.reasoning")}: ${t("providerConfig.native")}` },
                      { value: "unsupported", label: `${t("providerConfig.reasoning")}: ${t("providerConfig.unsupported")}` },
                    ]}
                    className="w-full"
                  />
                </div>
              </div>
            ))}
            <Button
              type="button"
              variant="outline"
              onClick={() =>
                setModelDrafts((current) => [
                  ...current,
                  { upstream_model_id: "", display_name: "", tool_calling: "unknown", reasoning: "unknown" },
                ])
              }
            >
              <PlusIcon className="size-4" />
              {t("providerConfig.addModel")}
            </Button>
            {modelEditorError ? <p className="text-sm text-destructive">{modelEditorError}</p> : null}
            <div className="flex justify-end gap-2">
              <Button type="button" variant="outline" onClick={() => setEditingModelsInstanceID("")}>
                {t("providerConfig.cancel")}
              </Button>
              <Button
                type="button"
                disabled={savingModels || modelDrafts.some((model) => !model.upstream_model_id.trim())}
                onClick={() => void saveModelDrafts()}
              >
                {savingModels ? <LoaderCircleIcon className="size-4 animate-spin" /> : null}
                {t("providerConfig.saveModels")}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      <Dialog
        open={editingProvider !== null}
        onOpenChange={(open) => {
          if (!open) {
            setEditingProvider(null);
            setProviderIdentityError(null);
          }
        }}
      >
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <div>
              <DialogTitle>{t("providerConfig.editSettings")}</DialogTitle>
              <DialogDescription>{t("providerConfig.editSettingsDescription")}</DialogDescription>
            </div>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="edit-provider-name">{t("providerConfig.displayName")}</Label>
              <Input id="edit-provider-name" value={editDisplayName} onChange={(event) => setEditDisplayName(event.target.value)} />
            </div>
            <div className="space-y-2">
              <Label htmlFor="edit-provider-handle">{t("providerConfig.handle")}</Label>
              <Input id="edit-provider-handle" value={editHandle} onChange={(event) => setEditHandle(event.target.value)} />
            </div>
            {providerIdentityError ? <p className="text-sm text-destructive">{providerIdentityError}</p> : null}
            <div className="flex justify-end gap-2">
              <Button type="button" variant="outline" onClick={() => setEditingProvider(null)}>{t("providerConfig.cancel")}</Button>
              <Button
                type="button"
                disabled={savingProviderIdentity || !editDisplayName.trim() || !editHandle.trim()}
                onClick={() => void saveProviderIdentity()}
              >
                {savingProviderIdentity ? <LoaderCircleIcon className="size-4 animate-spin" /> : null}
                {t("providerConfig.saveSettings")}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
