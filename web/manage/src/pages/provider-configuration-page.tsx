import { type FormEvent, type ReactElement, useCallback, useEffect, useMemo, useState } from "react";
import {
  CircleQuestionMarkIcon,
  KeyRoundIcon,
  LoaderCircleIcon,
  LockKeyholeIcon,
  PlusIcon,
  PencilIcon,
  RefreshCwIcon,
  ServerCogIcon,
  Settings2Icon,
  ShieldCheckIcon,
  SlidersHorizontalIcon,
  Trash2Icon,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
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
import { Textarea } from "@/components/ui/textarea";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { useI18n } from "@/i18n";
import { ProviderIcon } from "@/lib/provider-icons";
import { ProviderOnboardingPanel, providerStatusLabel } from "@/pages/provider-management-page";
import {
  configureProvider,
  attachProviderCredential,
  createCustomProviderDefinition,
  discoverCustomProviderModels,
  fetchProtocolProfiles,
  filterCustomProtocolProfiles,
  fetchProviderCatalog,
  fetchProviderDefinitions,
  fetchProviderEndpoints,
  fetchProviderCredentials,
  fetchProviderGroups,
  fetchProviderInstances,
  parseAdditionalPayloadProjectionJSON,
  parseRequestProjectionJSON,
  saveCustomProviderAdditionalParameters,
  saveCustomProviderModels,
  updateProviderEndpoint,
  updateProviderInstance,
  type CustomProtocolProfile,
  type ProviderCatalogMetadata,
  type ProviderDefinitionSummary,
  type ProviderEndpoint,
  type ProviderCredential,
  type ProviderGroup,
  type ProviderInstance,
  type SimpleCustomModelInput,
  type RequestProjection,
  type AdditionalPayloadProjection,
} from "@/lib/provider-groups";

// emptyRequestProjection creates an explicit rule document with no runtime mutations.
// emptyRequestProjection 创建一份不含运行时变更的显式规则文档。
function emptyRequestProjection(): RequestProjection {
  return { reasoning: {}, additional: {} };
}

// defaultRequestProjection returns the same protocol-owned baseline used by the management service.
// defaultRequestProjection 返回与管理服务相同的协议默认配置。
function defaultRequestProjection(protocolProfileID: string): RequestProjection {
  const efforts = ["none", "minimal", "low", "medium", "high", "xhigh", "max"];
  if (protocolProfileID === "openai.responses") {
    return {
      reasoning: {
        effort: efforts.map((value) => ({ value, set: [{ path: "reasoning.effort", value }] })),
        summary: ["auto", "concise", "detailed"].map((value) => ({ value, set: [{ path: "reasoning.summary", value }] })),
      },
      additional: {},
    };
  }
  if (protocolProfileID === "anthropic.messages") {
    const budgets: Record<string, number> = { minimal: 512, low: 1024, medium: 8192, high: 24576, xhigh: 32768, max: 128000 };
    return {
      reasoning: {
        effort: [
          { value: "none", set: [{ path: "thinking.type", value: "disabled" }], delete: ["thinking.budget_tokens", "output_config.effort"] },
          { value: "auto", set: [{ path: "thinking.type", value: "enabled" }], delete: ["thinking.budget_tokens", "output_config.effort"] },
          ...Object.entries(budgets).map(([value, budget]) => ({ value, set: [{ path: "thinking.type", value: "enabled" }, { path: "thinking.budget_tokens", value: budget }], delete: ["output_config.effort"] })),
        ],
      },
      additional: {},
    };
  }
  return {
    reasoning: { effort: efforts.map((value) => ({ value, set: [{ path: "reasoning_effort", value }] })) },
    additional: {},
  };
}

// formatReasoningProjection renders only the model-owned reasoning rule object.
// formatReasoningProjection 仅渲染模型拥有的推理规则对象。
function formatReasoningProjection(projection: RequestProjection["reasoning"]): string {
  return JSON.stringify(projection, null, 2);
}

// formatAdditionalProjection renders one provider- or model-level non-reasoning rule object.
// formatAdditionalProjection 渲染一个供应商级或模型级非推理规则对象。
function formatAdditionalProjection(projection: AdditionalPayloadProjection): string {
  return JSON.stringify(projection, null, 2);
}

// parseModelProjection combines independently edited reasoning and additional documents for authoritative validation.
// parseModelProjection 合并独立编辑的推理与附加文档并执行权威校验。
function parseModelProjection(reasoningValue: string, additionalValue: string, protocolProfileID: string): RequestProjection {
  const reasoning = JSON.parse(reasoningValue) as RequestProjection["reasoning"];
  const additional = parseAdditionalPayloadProjectionJSON(additionalValue);
  return parseRequestProjectionJSON(JSON.stringify({ reasoning, additional }), protocolProfileID);
}

// HelpLabel renders one form label with an accessible shadcn tooltip trigger.
// HelpLabel 渲染一个带有可访问 shadcn Tooltip 触发器的表单标签。
function HelpLabel({ htmlFor, label, help }: { htmlFor: string; label: string; help: string }): ReactElement {
  return (
    <div className="flex items-center gap-1.5">
      <Label htmlFor={htmlFor}>{label}</Label>
      <Tooltip>
        <TooltipTrigger
          render={(
            <button
              type="button"
              className="inline-flex size-4 items-center justify-center rounded-full text-muted-foreground outline-none hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring"
              aria-label={`${label}: ${help}`}
            >
              <CircleQuestionMarkIcon className="size-3.5" />
            </button>
          )}
        />
        <TooltipContent side="top">{help}</TooltipContent>
      </Tooltip>
    </div>
  );
}

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

// ProviderCreationForm contains provider configuration fields and one optional transient API secret.
// ProviderCreationForm 包含供应商配置字段与一个可选的临时 API 密钥。
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
  // secret optionally creates the first direct API credential after provider configuration.
  // secret 可选地在供应商配置完成后创建首个直接 API 凭据。
  secret: string;
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
    secret: "",
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
  // protocolProfiles contains the complete server-owned display catalog for configured and native interfaces.
  // protocolProfiles 包含用于已配置及原生接口的完整服务端显示目录。
  const [protocolProfiles, setProtocolProfiles] = useState<CustomProtocolProfile[]>([]);
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
  // addingSystemGroupID identifies the native provider family selected from the system-provider table.
  // addingSystemGroupID 标识从系统供应商表格中选择的原生供应商系列。
  const [addingSystemGroupID, setAddingSystemGroupID] = useState("");
  // systemDefinitionID selects one exact native interface within the active provider family.
  // systemDefinitionID 在当前供应商系列中选择一个精确原生接口。
  const [systemDefinitionID, setSystemDefinitionID] = useState("");
  // systemCredentialInstanceID selects an existing configuration that receives the new native credential.
  // systemCredentialInstanceID 选择接收新原生凭据的既有配置。
  const [systemCredentialInstanceID, setSystemCredentialInstanceID] = useState("");
  // configuringProviderInstanceID identifies the configured-provider row opened in the details dialog.
  // configuringProviderInstanceID 标识在详情对话框中打开的已配置供应商行。
  const [configuringProviderInstanceID, setConfiguringProviderInstanceID] = useState("");
  // configurationParentInstanceID preserves the provider configuration opened before a second-level editor.
  // configurationParentInstanceID 保留进入二级编辑器前打开的供应商配置。
  const [configurationParentInstanceID, setConfigurationParentInstanceID] = useState("");
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
  // modelReasoningDrafts preserves independently edited model reasoning JSON.
  // modelReasoningDrafts 保留独立编辑的模型推理 JSON。
  const [modelReasoningDrafts, setModelReasoningDrafts] = useState<string[]>([]);
  // modelAdditionalDrafts preserves optional per-model exceptions to provider defaults.
  // modelAdditionalDrafts 保留供应商默认规则的可选模型级例外。
  const [modelAdditionalDrafts, setModelAdditionalDrafts] = useState<string[]>([]);
  // editingModelsProtocolID identifies the protocol whose default projection and examples are displayed.
  // editingModelsProtocolID 标识用于显示默认投影与示例的协议。
  const [editingModelsProtocolID, setEditingModelsProtocolID] = useState("");
  // validatedProjectionIndexes records models whose current JSON passed local validation.
  // validatedProjectionIndexes 记录当前 JSON 已通过本地校验的模型。
  const [validatedProjectionIndexes, setValidatedProjectionIndexes] = useState<Set<number>>(new Set());
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
  // editBaseURL is the replacement custom-provider API destination.
  // editBaseURL 是自定义供应商替换后的 API 目标地址。
  const [editBaseURL, setEditBaseURL] = useState("");
  // savingProviderSettings prevents duplicate custom provider identity and API writes.
  // savingProviderSettings 防止重复写入自定义供应商身份与 API 设置。
  const [savingProviderSettings, setSavingProviderSettings] = useState(false);
  // providerSettingsError reports one explicit custom provider settings update failure.
  // providerSettingsError 报告一个显式自定义供应商设置更新失败。
  const [providerSettingsError, setProviderSettingsError] = useState<string | null>(null);
  // editingAdditionalProvider identifies the custom provider whose inherited additional rules are being edited.
  // editingAdditionalProvider 标识正在编辑继承附加规则的自定义供应商。
  const [editingAdditionalProvider, setEditingAdditionalProvider] = useState<ProviderInventoryItem | null>(null);
  // providerAdditionalDraft preserves invalid provider-level JSON until explicit validation or save.
  // providerAdditionalDraft 保留无效的供应商级 JSON，直到显式验证或保存。
  const [providerAdditionalDraft, setProviderAdditionalDraft] = useState("{}");
  // providerAdditionalValidated reports whether the current provider-level draft passed local validation.
  // providerAdditionalValidated 报告当前供应商级草稿是否通过本地校验。
  const [providerAdditionalValidated, setProviderAdditionalValidated] = useState(false);
  // savingProviderAdditional prevents duplicate provider-level rule writes.
  // savingProviderAdditional 防止重复写入供应商级规则。
  const [savingProviderAdditional, setSavingProviderAdditional] = useState(false);
  // providerAdditionalError reports one explicit provider-level rule failure.
  // providerAdditionalError 报告一个明确的供应商级规则失败。
  const [providerAdditionalError, setProviderAdditionalError] = useState<string | null>(null);

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
  // protocolDisplayNameByID resolves internal interface identifiers to server-owned human-readable names.
  // protocolDisplayNameByID 将内部接口标识解析为服务端拥有的易读名称。
  const protocolDisplayNameByID = useMemo(
    () => new Map(protocolProfiles.map((profile) => [profile.id, profile.display_name])),
    [protocolProfiles],
  );
  // protocolDisplayName returns a human-readable interface label or an explicit unavailable state.
  // protocolDisplayName 返回易读接口名称，或返回明确的不可用状态。
  function protocolDisplayName(protocolProfileID: string): string {
    return protocolDisplayNameByID.get(protocolProfileID) ?? t("providerConfig.interfaceUnavailable");
  }
  // addingSystemGroup resolves the exact native family selected by the table action.
  // addingSystemGroup 解析表格操作选择的精确原生系列。
  const addingSystemGroup = useMemo(
    () => groups.find((group) => group.id === addingSystemGroupID) ?? null,
    [groups, addingSystemGroupID],
  );
  // selectedSystemDefinition resolves the exact native interface submitted to the server.
  // selectedSystemDefinition 解析提交到服务端的精确原生接口。
  const selectedSystemDefinition = useMemo(
    () => addingSystemGroup?.provider_definitions.find((definition) => definition.id === systemDefinitionID) ?? null,
    [addingSystemGroup, systemDefinitionID],
  );
  // selectedSystemProviderInstances contains only existing configurations owned by the selected native interface.
  // selectedSystemProviderInstances 仅包含所选原生接口拥有的既有配置。
  const selectedSystemProviderInstances = useMemo(
    () => inventory.filter((item) => item.instance.definition_id === systemDefinitionID),
    [inventory, systemDefinitionID],
  );
  // configuringProvider always resolves from the latest loaded inventory after model discovery or settings changes.
  // configuringProvider 在拉取模型或修改设置后始终从最新清单解析。
  const configuringProvider = useMemo(
    () => inventory.find((item) => item.instance.id === configuringProviderInstanceID) ?? null,
    [inventory, configuringProviderInstanceID],
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
            fetchProtocolProfiles(managementAuthToken, signal),
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
        setProtocolProfiles(loadedProtocols);
        setCustomProtocols(filterCustomProtocolProfiles(loadedProtocols));
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

  // openSystemProviderDialog starts a group-scoped native credential workflow without cloning a provider configuration.
  // openSystemProviderDialog 启动限定在供应商系列内且不会克隆供应商配置的原生凭据流程。
  function openSystemProviderDialog(group: ProviderGroup): void {
    const firstDefinition = group.provider_definitions[0];
    if (!firstDefinition) return;
    setAddingSystemGroupID(group.id);
    setSystemDefinitionID(firstDefinition.id);
    const existingInstance = inventory.find((item) => item.instance.definition_id === firstDefinition.id);
    setSystemCredentialInstanceID(existingInstance ? existingInstance.instance.id : "");
  }

  // closeSystemProviderDialog clears every transient native credential selection.
  // closeSystemProviderDialog 清除全部临时原生凭据选择。
  function closeSystemProviderDialog(): void {
    setAddingSystemGroupID("");
    setSystemDefinitionID("");
    setSystemCredentialInstanceID("");
  }

  // selectSystemDefinition switches credential onboarding to one exact interface and its existing configuration.
  // selectSystemDefinition 将凭据录入切换到一个精确接口及其既有配置。
  function selectSystemDefinition(definitionID: string): void {
    const definition = addingSystemGroup?.provider_definitions.find((candidate) => candidate.id === definitionID);
    if (!definition) return;
    setSystemDefinitionID(definition.id);
    const existingInstance = inventory.find((item) => item.instance.definition_id === definition.id);
    setSystemCredentialInstanceID(existingInstance ? existingInstance.instance.id : "");
  }

  // completeSystemCredential closes onboarding and reloads the provider and credential counts.
  // completeSystemCredential 关闭凭据录入并重新加载供应商与凭据数量。
  function completeSystemCredential(): void {
    closeSystemProviderDialog();
    void loadInventory();
  }

  // submitProviderConfiguration creates one standard-compatible provider and optionally attaches its first protected credential.
  // submitProviderConfiguration 创建一个标准兼容供应商，并可选地附加其首个受保护凭据。
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
      const configuration = await configureProvider(managementAuthToken, {
        provider_definition_id: definitionID,
        display_name: form.displayName.trim(),
        handle: form.handle.trim(),
        base_url: form.baseURL.trim(),
      });
      let attachedCredentialID = "";
      if (form.secret.length > 0) {
        const attachment = await attachProviderCredential(
          managementAuthToken,
          configuration.provider_instance_id,
          {
            auth_method_id: "default",
            label: form.displayName.trim(),
            secret: form.secret,
          },
        );
        attachedCredentialID = attachment.credential_id;
      }
      closeDialog();
      await loadInventory();
      if (attachedCredentialID) {
        setDiscoveryCredentialIDs((current) => ({
          ...current,
          [configuration.provider_instance_id]: attachedCredentialID,
        }));
      }
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

  // enterConfigurationChild records the exact parent and closes its dialog before opening a second-level editor.
  // enterConfigurationChild 记录精确上级，并在打开二级编辑器前关闭其对话框。
  function enterConfigurationChild(providerInstanceID: string): void {
    setConfigurationParentInstanceID(providerInstanceID);
    setConfiguringProviderInstanceID("");
  }

  // restoreConfigurationParent returns from a second-level editor to its originating provider configuration.
  // restoreConfigurationParent 从二级编辑器返回其来源供应商配置。
  function restoreConfigurationParent(): void {
    setConfiguringProviderInstanceID(configurationParentInstanceID);
    setConfigurationParentInstanceID("");
  }

  // closeModelEditor clears model drafts and returns to the originating provider configuration.
  // closeModelEditor 清除模型草稿并返回来源供应商配置。
  function closeModelEditor(): void {
    setEditingModelsInstanceID("");
    setModelDrafts([]);
    setModelReasoningDrafts([]);
    setModelAdditionalDrafts([]);
    setEditingModelsProtocolID("");
    setValidatedProjectionIndexes(new Set());
    setModelEditorError(null);
    restoreConfigurationParent();
  }

  // closeProviderAdditionalEditor clears provider-wide parameter state and returns to the parent configuration.
  // closeProviderAdditionalEditor 清除供应商级参数状态并返回上级配置。
  function closeProviderAdditionalEditor(): void {
    setEditingAdditionalProvider(null);
    setProviderAdditionalValidated(false);
    setProviderAdditionalError(null);
    restoreConfigurationParent();
  }

  // closeProviderEditor clears editable provider settings and returns to the parent configuration.
  // closeProviderEditor 清除可编辑供应商设置并返回上级配置。
  function closeProviderEditor(): void {
    setEditingProvider(null);
    setProviderSettingsError(null);
    restoreConfigurationParent();
  }

  // openModelEditor converts the current catalog into an explicit simplified model replacement draft.
  // openModelEditor 将当前目录转换为显式的简化模型替换草稿。
  function openModelEditor(item: ProviderInventoryItem): void {
    enterConfigurationChild(item.instance.id);
    setEditingModelsInstanceID(item.instance.id);
    setEditingModelsProtocolID(item.definition.protocol_profile_id);
    setModelEditorError(null);
    setValidatedProjectionIndexes(new Set());
    const catalogModels = item.catalog?.models ?? [];
    setModelDrafts(
      catalogModels.map((model) => {
        const offering = model.offerings?.[0];
        const profile = offering?.profiles.find((candidate) => candidate.default) ?? offering?.profiles[0];
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
              : "native",
          reasoning:
            reasoning === "native" || reasoning === "unsupported"
              ? reasoning
              : "native",
        };
      }),
    );
    const projections = catalogModels.map((model) => {
      const profile = model.offerings?.[0]?.profiles.find((candidate) => candidate.default) ?? model.offerings?.[0]?.profiles[0];
      const saved = model.offerings?.[0]?.request_projection;
      const projection = saved && ((saved.reasoning.effort?.length ?? 0) > 0 || (saved.reasoning.summary?.length ?? 0) > 0 || (saved.additional.default?.length ?? 0) > 0 || (saved.additional.override?.length ?? 0) > 0 || (saved.additional.filter?.length ?? 0) > 0)
        ? saved
        : profile?.capabilities.reasoning === "unsupported"
          ? emptyRequestProjection()
          : defaultRequestProjection(item.definition.protocol_profile_id);
      return projection;
    });
    setModelReasoningDrafts(projections.map((projection) => formatReasoningProjection(projection.reasoning)));
    setModelAdditionalDrafts(projections.map((projection) => formatAdditionalProjection(projection.additional)));
  }

  // saveModelDrafts atomically replaces the custom provider's complete simplified model set.
  // saveModelDrafts 原子替换自定义供应商的完整简化模型集合。
  async function saveModelDrafts(): Promise<void> {
    if (!editingModelsInstanceID) return;
    const parsedModels: SimpleCustomModelInput[] = [];
    try {
      for (const [index, model] of modelDrafts.entries()) {
        const projection = parseModelProjection(modelReasoningDrafts[index] ?? "", modelAdditionalDrafts[index] ?? "", editingModelsProtocolID);
        if (model.reasoning === "native" && (projection.reasoning.effort?.length ?? 0) === 0) {
          throw new Error(t("providerConfig.projectionEffortRequired"));
        }
        if (model.reasoning === "unsupported" && ((projection.reasoning.effort?.length ?? 0) > 0 || (projection.reasoning.summary?.length ?? 0) > 0)) {
          throw new Error(t("providerConfig.projectionReasoningUnsupported"));
        }
        parsedModels.push({
          ...model,
          request_projection: projection,
        });
      }
    } catch (error) {
      setModelEditorError(error instanceof Error ? error.message : t("providerConfig.projectionInvalid"));
      return;
    }
    setSavingModels(true);
    setModelEditorError(null);
    try {
      await saveCustomProviderModels(
        managementAuthToken,
        editingModelsInstanceID,
        parsedModels,
      );
      closeModelEditor();
      await loadInventory();
    } catch (error) {
      setModelEditorError(
        error instanceof Error ? error.message : t("providerConfig.modelSaveFailed"),
      );
    } finally {
      setSavingModels(false);
    }
  }

  // validateProjectionDraft validates and normalizes one model's advanced JSON without saving it.
  // validateProjectionDraft 校验并规范化一个模型的高级 JSON，但不进行保存。
  function validateProjectionDraft(index: number): void {
    try {
      const parsed = parseModelProjection(modelReasoningDrafts[index] ?? "", modelAdditionalDrafts[index] ?? "", editingModelsProtocolID);
      if (modelDrafts[index]?.reasoning === "native" && (parsed.reasoning.effort?.length ?? 0) === 0) throw new Error(t("providerConfig.projectionEffortRequired"));
      if (modelDrafts[index]?.reasoning === "unsupported" && ((parsed.reasoning.effort?.length ?? 0) > 0 || (parsed.reasoning.summary?.length ?? 0) > 0)) throw new Error(t("providerConfig.projectionReasoningUnsupported"));
      setModelReasoningDrafts((current) => current.map((value, candidateIndex) => candidateIndex === index ? formatReasoningProjection(parsed.reasoning) : value));
      setModelAdditionalDrafts((current) => current.map((value, candidateIndex) => candidateIndex === index ? formatAdditionalProjection(parsed.additional) : value));
      setValidatedProjectionIndexes((current) => new Set(current).add(index));
      setModelEditorError(null);
    } catch (error) {
      setValidatedProjectionIndexes((current) => {
        const next = new Set(current);
        next.delete(index);
        return next;
      });
      setModelEditorError(error instanceof Error ? error.message : t("providerConfig.projectionInvalid"));
    }
  }

  // openProviderEditor opens editable local identity fields only for one user-owned custom provider.
  // openProviderEditor 仅为一个用户拥有的自定义供应商打开可编辑本地身份字段。
  function openProviderEditor(item: ProviderInventoryItem): void {
    enterConfigurationChild(item.instance.id);
    setEditingProvider(item);
    setEditDisplayName(item.instance.display_name);
    setEditHandle(item.instance.handle);
    setEditBaseURL(item.endpoints[0]?.base_url ?? "");
    setProviderSettingsError(null);
  }

  // saveProviderSettings persists custom provider identity and API destination without changing protocol, models, or credentials.
  // saveProviderSettings 持久化自定义供应商身份与 API 目标，且不改变协议、模型或凭据。
  async function saveProviderSettings(): Promise<void> {
    if (!editingProvider) return;
    if (editingProvider.endpoints.length !== 1) {
      setProviderSettingsError(t("providerConfig.endpointRequired"));
      return;
    }
    const endpoint = editingProvider.endpoints[0];
    setSavingProviderSettings(true);
    setProviderSettingsError(null);
    try {
      if (endpoint.base_url !== editBaseURL.trim()) {
        await updateProviderEndpoint(
          managementAuthToken,
          editingProvider.instance.id,
          { id: endpoint.id, base_url: editBaseURL.trim(), region: endpoint.region, status: endpoint.status },
        );
      }
      await updateProviderInstance(
        managementAuthToken,
        editingProvider.instance.id,
        { display_name: editDisplayName.trim(), handle: editHandle.trim() },
      );
      closeProviderEditor();
      await loadInventory();
    } catch (error) {
      setProviderSettingsError(
        error instanceof Error ? error.message : t("providerConfig.identitySaveFailed"),
      );
    } finally {
      setSavingProviderSettings(false);
    }
  }

  // openProviderAdditionalEditor opens the provider-wide inherited rule document.
  // openProviderAdditionalEditor 打开供应商级继承规则文档。
  function openProviderAdditionalEditor(item: ProviderInventoryItem): void {
    enterConfigurationChild(item.instance.id);
    setEditingAdditionalProvider(item);
    setProviderAdditionalDraft(formatAdditionalProjection(item.catalog?.default_additional_parameters ?? {}));
    setProviderAdditionalValidated(false);
    setProviderAdditionalError(null);
  }

  // validateProviderAdditionalDraft validates and normalizes provider-wide non-reasoning rules locally.
  // validateProviderAdditionalDraft 在本地校验并规范化供应商级非推理规则。
  function validateProviderAdditionalDraft(): void {
    try {
      const parsed = parseAdditionalPayloadProjectionJSON(providerAdditionalDraft);
      setProviderAdditionalDraft(formatAdditionalProjection(parsed));
      setProviderAdditionalValidated(true);
      setProviderAdditionalError(null);
    } catch (error) {
      setProviderAdditionalValidated(false);
      setProviderAdditionalError(error instanceof Error ? error.message : t("providerConfig.additionalParametersInvalid"));
    }
  }

  // saveProviderAdditionalDraft persists provider-wide defaults without changing model-specific exceptions.
  // saveProviderAdditionalDraft 持久化供应商级默认规则，且不改变模型专属例外。
  async function saveProviderAdditionalDraft(): Promise<void> {
    if (!editingAdditionalProvider) return;
    let parsed: AdditionalPayloadProjection;
    try {
      parsed = parseAdditionalPayloadProjectionJSON(providerAdditionalDraft);
    } catch (error) {
      setProviderAdditionalValidated(false);
      setProviderAdditionalError(error instanceof Error ? error.message : t("providerConfig.additionalParametersInvalid"));
      return;
    }
    setSavingProviderAdditional(true);
    setProviderAdditionalError(null);
    try {
      await saveCustomProviderAdditionalParameters(managementAuthToken, editingAdditionalProvider.instance.id, parsed);
      closeProviderAdditionalEditor();
      await loadInventory();
    } catch (error) {
      setProviderAdditionalError(error instanceof Error ? error.message : t("providerConfig.additionalParametersSaveFailed"));
    } finally {
      setSavingProviderAdditional(false);
    }
  }

  return (
    <div className="space-y-6 px-4 lg:px-6">
      <div>
        <div>
          <h2 className="text-xl font-semibold">{t("providerConfig.title")}</h2>
          <p className="text-sm text-muted-foreground">
            {t("providerConfig.description")}
          </p>
        </div>
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
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <ServerCogIcon className="size-4" />
            <h3 className="font-medium">{t("providerConfig.configuredProviders")}</h3>
            <Badge variant="secondary">{inventory.length}</Badge>
          </div>
          <Button
            type="button"
            size="sm"
            className="inline-flex items-center gap-1.5 leading-none"
            onClick={() => setDialogOpen(true)}
          >
            <PlusIcon className="size-4" />
            <span className="leading-none">{t("providerConfig.addProvider")}</span>
          </Button>
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
          <div className="overflow-hidden rounded-xl border">
            <Table>
              <TableHeader className="bg-muted/40">
                <TableRow>
                  <TableHead className="w-[18rem]">{t("providerConfig.provider")}</TableHead>
                  <TableHead className="w-24 text-center">{t("providerConfig.kind")}</TableHead>
                  <TableHead>{t("providerConfig.interface")}</TableHead>
                  <TableHead className="w-32">{t("providerConfig.resourceCounts")}</TableHead>
                  <TableHead className="w-28 text-center">{t("providerConfig.status")}</TableHead>
                  <TableHead className="w-24 text-right">{t("providerConfig.actions")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {inventory.map((item) => (
                  <TableRow key={item.instance.id}>
                    <TableCell className="whitespace-normal py-3 align-top">
                      <div className="flex items-center gap-3">
                        <ProviderIcon
                          definitionID={item.definition.id}
                          groupID={item.definition.group_id}
                          className="size-[26px]"
                        />
                        <div className="min-w-0">
                          <div className="font-medium">{item.instance.display_name}</div>
                          <div className="mt-1 truncate font-mono text-xs text-muted-foreground">{item.instance.handle}</div>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell className="whitespace-normal py-3 text-center align-middle">
                      <Badge variant="outline">
                        {t(item.definition.kind === "system" ? "providerConfig.kindSystem" : "providerConfig.kindCustom")}
                      </Badge>
                    </TableCell>
                    <TableCell className="whitespace-normal py-3 align-top">
                      <div className="font-medium">{protocolDisplayName(item.definition.protocol_profile_id)}</div>
                      <div className="mt-1 space-y-1 text-xs text-muted-foreground">
                        {item.endpoints.map((endpoint) => (
                          <div key={endpoint.id} className="break-all font-mono">{endpoint.base_url}</div>
                        ))}
                      </div>
                    </TableCell>
                    <TableCell className="whitespace-normal py-3 align-top">
                      <div>{t("providerConfig.modelCount")}: {item.catalog?.models.length ?? 0}</div>
                      <div className="mt-1 text-muted-foreground">{t("providerConfig.credentialCount")}: {item.instance.credential_count}</div>
                    </TableCell>
                    <TableCell className="whitespace-normal py-3 text-center align-middle">
                      <Badge variant={item.instance.status === "ready" ? "default" : "outline"}>
                        {providerStatusLabel(t, item.instance.status)}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right align-middle">
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        aria-label={`${t("providerConfig.configure")} ${item.instance.display_name}`}
                        onClick={() => setConfiguringProviderInstanceID(item.instance.id)}
                      >
                        <Settings2Icon className="size-4" />
                        {t("providerConfig.configure")}
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </section>

      <section className="space-y-3">
        <div className="flex items-center gap-2">
          <LockKeyholeIcon className="size-4" />
          <h3 className="font-medium">{t("providerConfig.nativeProviders")}</h3>
          <Badge variant="secondary">{systemDefinitions.length}</Badge>
        </div>
        <div className="overflow-hidden rounded-xl border">
          <Table>
            <TableHeader className="bg-muted/40">
              <TableRow>
                <TableHead className="w-[18rem]">{t("providerConfig.provider")}</TableHead>
                <TableHead>{t("providerConfig.details")}</TableHead>
                <TableHead className="w-32 text-right">{t("providerConfig.actions")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {groups.map((group) => (
                <TableRow key={group.id}>
                  <TableCell className="whitespace-normal align-top py-3">
                    <div className="flex items-center gap-3">
                      <ProviderIcon groupID={group.id} className="size-[26px]" />
                      <div className="font-medium">{group.display_name}</div>
                    </div>
                  </TableCell>
                  <TableCell className="whitespace-normal py-3">
                    <div className="space-y-2">
                      <p className="text-sm text-muted-foreground">{group.description}</p>
                      <div className="flex flex-wrap gap-1.5">
                        {group.provider_definitions.map((definition) => (
                          <Badge key={definition.id} variant="outline">
                            {definition.variant_name} · {protocolDisplayName(definition.protocol_profile_id)}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  </TableCell>
                  <TableCell className="text-right align-middle">
                    <Button
                      type="button"
                      size="sm"
                      className="inline-flex items-center gap-1.5 leading-none"
                      aria-label={`${t("providerConfig.newCredential")} ${group.display_name}`}
                      onClick={() => openSystemProviderDialog(group)}
                    >
                      <KeyRoundIcon className="size-4" />
                      <span className="leading-none">{t("providerConfig.newCredential")}</span>
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </section>

      <Dialog
        open={addingSystemGroup !== null}
        onOpenChange={(open) => {
          if (!open) closeSystemProviderDialog();
        }}
      >
        <DialogContent className="grid max-h-[min(80vh,760px)] w-[calc(100vw-2rem)] max-w-2xl grid-rows-[auto_minmax(0,1fr)] overflow-hidden">
          <DialogHeader>
            <div>
              <DialogTitle>{t("providerConfig.addSystemProvider")}</DialogTitle>
              <DialogDescription>
                {addingSystemGroup?.display_name} · {t("providerConfig.addSystemDescription")}
              </DialogDescription>
            </div>
          </DialogHeader>
          {addingSystemGroup && selectedSystemDefinition ? (
            <div className="min-h-0 space-y-4 overflow-y-auto pr-1">
              <div className="space-y-2">
                <Label>{t("providerConfig.interface")}</Label>
                <ReadonlyCombobox
                  value={selectedSystemDefinition.id}
                  onValueChange={selectSystemDefinition}
                  options={addingSystemGroup.provider_definitions.map((definition) => ({
                    value: definition.id,
                    label: definition.variant_name,
                  }))}
                  className="w-full"
                />
                <div className="space-y-1 rounded-md bg-muted/40 p-3 text-sm">
                  <p>{selectedSystemDefinition.variant_description}</p>
                  <div className="flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
                    <Badge variant="secondary">{protocolDisplayName(selectedSystemDefinition.protocol_profile_id)}</Badge>
                    {selectedSystemDefinition.endpoint_presets.map((endpoint) => (
                      <span key={endpoint.id} className="break-all font-mono">
                        {endpoint.base_url || endpoint.parameters.map((parameter) => `{${parameter.id}}`).join(" · ")}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
              {selectedSystemProviderInstances.length > 0 ? (
                <div className="space-y-2">
                  <Label>{t("providerConfig.credentialTarget")}</Label>
                  <ReadonlyCombobox
                    value={systemCredentialInstanceID}
                    onValueChange={setSystemCredentialInstanceID}
                    options={selectedSystemProviderInstances.map((item) => ({
                      value: item.instance.id,
                      label: `${item.instance.display_name} · ${item.instance.handle}`,
                    }))}
                    className="w-full"
                  />
                  <p className="text-xs text-muted-foreground">{t("providerConfig.credentialTargetHelp")}</p>
                </div>
              ) : (
                <div className="rounded-md border border-dashed px-3 py-2 text-xs text-muted-foreground">
                  {t("providerConfig.firstCredentialCreatesConfiguration")}
                </div>
              )}
              <ProviderOnboardingPanel
                key={`${selectedSystemDefinition.id}:${systemCredentialInstanceID || "first"}`}
                definition={selectedSystemDefinition}
                managementAuthToken={managementAuthToken}
                attachmentTarget={systemCredentialInstanceID ? { providerInstanceID: systemCredentialInstanceID } : null}
                credentialIntent
                onComplete={completeSystemCredential}
              />
            </div>
          ) : null}
        </DialogContent>
      </Dialog>

      <Dialog
        open={configuringProvider !== null}
        onOpenChange={(open) => {
          if (!open) setConfiguringProviderInstanceID("");
        }}
      >
        <DialogContent className="grid max-h-[min(80vh,760px)] w-[calc(100vw-2rem)] max-w-4xl grid-rows-[auto_minmax(0,1fr)] overflow-hidden">
          <DialogHeader>
            <div>
              <DialogTitle>{configuringProvider?.instance.display_name}</DialogTitle>
              <DialogDescription>{t("providerConfig.configurationDescription")}</DialogDescription>
            </div>
          </DialogHeader>
          {configuringProvider ? (
            <div className="min-h-0 space-y-4 overflow-y-auto pr-1 text-sm">
              <div className="flex flex-wrap gap-2">
                <Badge variant="outline">{configuringProvider.definition.kind}</Badge>
                <Badge>{configuringProvider.instance.status}</Badge>
                <Badge variant="secondary">{protocolDisplayName(configuringProvider.definition.protocol_profile_id)}</Badge>
                <Badge variant="secondary">{configuringProvider.catalog?.models.length ?? 0} {t("providerConfig.models")}</Badge>
                <Badge variant="secondary">{configuringProvider.instance.credential_count} {t("providerConfig.credentials")}</Badge>
              </div>
              <div className="space-y-2">
                {configuringProvider.endpoints.map((endpoint) => (
                  <div key={endpoint.id} className="rounded-md bg-muted/50 px-3 py-2">
                    <div className="break-all font-mono text-xs">{endpoint.base_url}</div>
                    <div className="mt-1 text-xs text-muted-foreground">
                      {endpoint.region || t("providerConfig.globalEndpoint")} · {endpoint.status}
                    </div>
                  </div>
                ))}
              </div>
              {configuringProvider.catalog ? (
                <div className="space-y-2">
                  {configuringProvider.catalog.models.map((model) => {
                    const profile =
                      model.offerings?.flatMap((offering) => offering.profiles).find((candidate) => candidate.default) ??
                      model.offerings?.[0]?.profiles[0];
                    return (
                      <div key={model.id} className="rounded-md border px-3 py-2">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <span className="font-medium">{model.display_name}</span>
                          <span className="font-mono text-xs text-muted-foreground">{model.upstream_model_id}</span>
                        </div>
                        {profile ? (
                          <div className="mt-2 flex flex-wrap gap-1.5">
                            <Badge variant="outline">{t("providerConfig.contextWindow")}: {profile.capabilities.context_window.known ? profile.capabilities.context_window.value : t("providerConfig.unknown")}</Badge>
                            <Badge variant="outline">{t("providerConfig.maxOutputTokens")}: {profile.capabilities.max_output_tokens.known ? profile.capabilities.max_output_tokens.value : t("providerConfig.unknown")}</Badge>
                            <Badge variant="outline">{t("providerConfig.toolCalling")}: {profile.capabilities.tool_calling}</Badge>
                            <Badge variant="outline">{t("providerConfig.reasoning")}: {profile.capabilities.reasoning}</Badge>
                            <Badge variant="outline">{profile.capabilities.input_modalities.join(", ")} → {profile.capabilities.output_modalities.join(", ")}</Badge>
                          </div>
                        ) : null}
                      </div>
                    );
                  })}
                </div>
              ) : (
                <p className="text-xs text-destructive">{t("providerConfig.catalogUnavailable")}</p>
              )}
              {configuringProvider.definition.kind === "custom" ? (
                <div className="grid gap-2 rounded-md border p-3 sm:grid-cols-[minmax(0,1fr)_auto_auto_auto_auto] sm:items-end">
                  {supportsStandardModelDiscovery(configuringProvider.definition.protocol_profile_id) ? (
                    <>
                      <div className="space-y-1.5">
                        <Label>{t("providerConfig.discoveryCredential")}</Label>
                        <ReadonlyCombobox
                          value={discoveryCredentialIDs[configuringProvider.instance.id] ?? ""}
                          onValueChange={(value) =>
                            setDiscoveryCredentialIDs((current) => ({
                              ...current,
                              [configuringProvider.instance.id]: value,
                            }))
                          }
                          options={configuringProvider.credentials.map((credential) => ({
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
                        disabled={!discoveryCredentialIDs[configuringProvider.instance.id] || discoveringInstanceIDs.has(configuringProvider.instance.id)}
                        onClick={() => void discoverModels(configuringProvider.instance.id)}
                      >
                        <RefreshCwIcon className={discoveringInstanceIDs.has(configuringProvider.instance.id) ? "size-4 animate-spin" : "size-4"} />
                        {t("providerConfig.discoverModels")}
                      </Button>
                    </>
                  ) : null}
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => {
                      openProviderEditor(configuringProvider);
                      setConfiguringProviderInstanceID("");
                    }}
                  >
                    <Settings2Icon className="size-4" />
                    {t("providerConfig.editSettings")}
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    disabled={configuringProvider.catalog === null}
                    onClick={() => {
                      openProviderAdditionalEditor(configuringProvider);
                      setConfiguringProviderInstanceID("");
                    }}
                  >
                    <SlidersHorizontalIcon className="size-4" />
                    {t("providerConfig.additionalParameters")}
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => {
                      openModelEditor(configuringProvider);
                      setConfiguringProviderInstanceID("");
                    }}
                  >
                    <PencilIcon className="size-4" />
                    {t("providerConfig.editModels")}
                  </Button>
                  {supportsStandardModelDiscovery(configuringProvider.definition.protocol_profile_id) && discoveryErrors[configuringProvider.instance.id] ? (
                    <p className="text-xs text-destructive sm:col-span-5">{discoveryErrors[configuringProvider.instance.id]}</p>
                  ) : null}
                </div>
              ) : null}
            </div>
          ) : null}
        </DialogContent>
      </Dialog>

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
                <HelpLabel htmlFor="provider-display-name" label={t("providerConfig.displayName")} help={t("providerConfig.displayNameHelp")} />
                <Input
                  id="provider-display-name"
                  value={form.displayName}
                  onChange={(event) =>
                    setForm((current) => ({ ...current, displayName: event.target.value }))
                  }
                  placeholder={t("providerConfig.displayNamePlaceholder")}
                  required
                />
              </div>
              <div className="space-y-2">
                <HelpLabel htmlFor="provider-handle" label={t("providerConfig.handle")} help={t("providerConfig.handleHelp")} />
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
            <div className="space-y-2">
              <Label htmlFor="provider-api-key">
                {t("providerConfig.apiKey")}
                <span className="text-muted-foreground font-normal"> ({t("providerConfig.optional")})</span>
              </Label>
              <Input
                id="provider-api-key"
                type="password"
                autoComplete="new-password"
                value={form.secret}
                onChange={(event) =>
                  setForm((current) => ({ ...current, secret: event.target.value }))
                }
                placeholder={t("providerConfig.apiKeyPlaceholder")}
              />
              <p className="text-xs text-muted-foreground">{t("providerConfig.apiKeyHelp")}</p>
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
            closeModelEditor();
          }
        }}
      >
        <DialogContent className="w-[calc(100vw-2rem)] min-w-0 max-w-4xl overflow-x-hidden">
          <DialogHeader className="min-w-0">
            <div className="min-w-0">
              <DialogTitle>{t("providerConfig.editModels")}</DialogTitle>
              <DialogDescription>{t("providerConfig.editModelsDescription")}</DialogDescription>
            </div>
          </DialogHeader>
          <div className="min-w-0 space-y-3">
            {modelDrafts.map((model, index) => (
              <div key={index} className="min-w-0 space-y-3 overflow-hidden rounded-lg border p-3">
                <div className="grid min-w-0 gap-3 sm:grid-cols-2 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_10rem_10rem_auto] [&>*]:min-w-0">
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
                    onClick={() => {
                      setModelDrafts((current) => current.filter((_, candidateIndex) => candidateIndex !== index));
                      setModelReasoningDrafts((current) => current.filter((_, candidateIndex) => candidateIndex !== index));
                      setModelAdditionalDrafts((current) => current.filter((_, candidateIndex) => candidateIndex !== index));
                      setValidatedProjectionIndexes(new Set());
                    }}
                  >
                    <Trash2Icon className="size-4 text-destructive" />
                  </Button>
                </div>
                <div className="grid min-w-0 gap-3 sm:grid-cols-2 [&>*]:min-w-0">
                  <ReadonlyCombobox
                    value={model.tool_calling}
                    onValueChange={(value) => {
                      if (value === "native" || value === "unsupported") {
                        setModelDrafts((current) => current.map((candidate, candidateIndex) => candidateIndex === index ? { ...candidate, tool_calling: value } : candidate));
                      }
                    }}
                    options={[
                      { value: "native", label: `${t("providerConfig.toolCalling")}: ${t("providerConfig.native")}` },
                      { value: "unsupported", label: `${t("providerConfig.toolCalling")}: ${t("providerConfig.unsupported")}` },
                    ]}
                    className="w-full"
                  />
                  <ReadonlyCombobox
                    value={model.reasoning}
                    onValueChange={(value) => {
                      if (value === "native" || value === "unsupported") {
                        setModelDrafts((current) => current.map((candidate, candidateIndex) => candidateIndex === index ? { ...candidate, reasoning: value } : candidate));
                        setModelReasoningDrafts((current) => current.map((candidate, candidateIndex) => candidateIndex === index ? formatReasoningProjection(value === "native" ? defaultRequestProjection(editingModelsProtocolID).reasoning : {}) : candidate));
                        setValidatedProjectionIndexes((current) => {
                          const next = new Set(current);
                          next.delete(index);
                          return next;
                        });
                      }
                    }}
                    options={[
                      { value: "native", label: `${t("providerConfig.reasoning")}: ${t("providerConfig.native")}` },
                      { value: "unsupported", label: `${t("providerConfig.reasoning")}: ${t("providerConfig.unsupported")}` },
                    ]}
                    className="w-full"
                  />
                </div>
                <details className="min-w-0 overflow-hidden rounded-md border bg-muted/20 p-3">
                  <summary className="cursor-pointer select-none text-sm font-medium">{t("providerConfig.reasoningRules")}</summary>
                  <div className="mt-3 min-w-0 space-y-3">
                    <p className="break-words text-xs leading-relaxed text-muted-foreground [overflow-wrap:anywhere]">{t("providerConfig.reasoningRulesHelp")}</p>
                    <pre className="block max-w-full overflow-x-auto rounded-md bg-muted p-3 text-xs">{t("providerConfig.projectionExample")}</pre>
                    <Textarea
                      aria-label={t("providerConfig.reasoningRulesJSON")}
                      className="field-sizing-fixed h-56 min-h-56 w-full min-w-0 max-w-full resize-y overflow-auto whitespace-pre font-mono text-xs"
                      spellCheck={false}
                      value={modelReasoningDrafts[index] ?? ""}
                      onChange={(event) => {
                        const nextValue = event.target.value;
                        setModelReasoningDrafts((current) => current.map((candidate, candidateIndex) => candidateIndex === index ? nextValue : candidate));
                        setValidatedProjectionIndexes((current) => {
                          const next = new Set(current);
                          next.delete(index);
                          return next;
                        });
                      }}
                    />
                  </div>
                </details>
                <details className="min-w-0 overflow-hidden rounded-md border bg-muted/20 p-3">
                  <summary className="cursor-pointer select-none text-sm font-medium">{t("providerConfig.modelAdditionalParameters")}</summary>
                  <div className="mt-3 min-w-0 space-y-3">
                    <p className="break-words text-xs leading-relaxed text-muted-foreground [overflow-wrap:anywhere]">{t("providerConfig.modelAdditionalParametersHelp")}</p>
                    <Textarea
                      aria-label={t("providerConfig.additionalParametersJSON")}
                      className="field-sizing-fixed h-48 min-h-48 w-full min-w-0 max-w-full resize-y overflow-auto whitespace-pre font-mono text-xs"
                      spellCheck={false}
                      value={modelAdditionalDrafts[index] ?? ""}
                      onChange={(event) => {
                        const nextValue = event.target.value;
                        setModelAdditionalDrafts((current) => current.map((candidate, candidateIndex) => candidateIndex === index ? nextValue : candidate));
                        setValidatedProjectionIndexes((current) => {
                          const next = new Set(current);
                          next.delete(index);
                          return next;
                        });
                      }}
                    />
                  </div>
                </details>
                <div className="flex items-center gap-2">
                  <Button type="button" variant="outline" size="sm" onClick={() => validateProjectionDraft(index)}>
                    <ShieldCheckIcon className="size-4" />
                    {t("providerConfig.validateProjection")}
                  </Button>
                  {validatedProjectionIndexes.has(index) ? <span className="text-xs text-emerald-600">{t("providerConfig.projectionValid")}</span> : null}
                </div>
              </div>
            ))}
            <Button
              type="button"
              variant="outline"
              onClick={() =>
                {
                  setModelDrafts((current) => [
                    ...current,
                    { upstream_model_id: "", display_name: "", tool_calling: "native", reasoning: "native" },
                  ]);
                  const projection = defaultRequestProjection(editingModelsProtocolID);
                  setModelReasoningDrafts((current) => [...current, formatReasoningProjection(projection.reasoning)]);
                  setModelAdditionalDrafts((current) => [...current, formatAdditionalProjection({})]);
                  setValidatedProjectionIndexes(new Set());
                }
              }
            >
              <PlusIcon className="size-4" />
              {t("providerConfig.addModel")}
            </Button>
            {modelEditorError ? <p className="text-sm text-destructive">{modelEditorError}</p> : null}
            <div className="flex justify-end gap-2">
              <Button type="button" variant="outline" onClick={closeModelEditor}>
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
        open={editingAdditionalProvider !== null}
        onOpenChange={(open) => {
          if (!open) {
            closeProviderAdditionalEditor();
          }
        }}
      >
        <DialogContent className="w-[calc(100vw-2rem)] min-w-0 max-w-3xl overflow-x-hidden">
          <DialogHeader className="min-w-0">
            <div className="min-w-0">
              <DialogTitle>{t("providerConfig.additionalParameters")}</DialogTitle>
              <DialogDescription>{t("providerConfig.additionalParametersDescription")}</DialogDescription>
            </div>
          </DialogHeader>
          <div className="min-w-0 space-y-3">
            <p className="break-words text-xs leading-relaxed text-muted-foreground [overflow-wrap:anywhere]">{t("providerConfig.additionalParametersHelp")}</p>
            <pre className="block max-w-full overflow-x-auto rounded-md bg-muted p-3 text-xs">{t("providerConfig.additionalParametersExample")}</pre>
            <Textarea
              aria-label={t("providerConfig.additionalParametersJSON")}
              className="field-sizing-fixed h-72 min-h-72 w-full min-w-0 max-w-full resize-y overflow-auto whitespace-pre font-mono text-xs"
              spellCheck={false}
              value={providerAdditionalDraft}
              onChange={(event) => {
                setProviderAdditionalDraft(event.target.value);
                setProviderAdditionalValidated(false);
              }}
            />
            {providerAdditionalError ? <p className="text-sm text-destructive">{providerAdditionalError}</p> : null}
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <Button type="button" variant="outline" size="sm" onClick={validateProviderAdditionalDraft}>
                  <ShieldCheckIcon className="size-4" />
                  {t("providerConfig.validateProjection")}
                </Button>
                {providerAdditionalValidated ? <span className="text-xs text-emerald-600">{t("providerConfig.projectionValid")}</span> : null}
              </div>
              <div className="flex gap-2">
                <Button type="button" variant="outline" onClick={closeProviderAdditionalEditor}>{t("providerConfig.cancel")}</Button>
                <Button type="button" disabled={savingProviderAdditional} onClick={() => void saveProviderAdditionalDraft()}>
                  {savingProviderAdditional ? <LoaderCircleIcon className="size-4 animate-spin" /> : null}
                  {t("providerConfig.saveAdditionalParameters")}
                </Button>
              </div>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      <Dialog
        open={editingProvider !== null}
        onOpenChange={(open) => {
          if (!open) {
            closeProviderEditor();
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
              <HelpLabel htmlFor="edit-provider-name" label={t("providerConfig.displayName")} help={t("providerConfig.displayNameHelp")} />
              <Input id="edit-provider-name" value={editDisplayName} onChange={(event) => setEditDisplayName(event.target.value)} />
            </div>
            <div className="space-y-2">
              <HelpLabel htmlFor="edit-provider-handle" label={t("providerConfig.handle")} help={t("providerConfig.handleHelp")} />
              <Input id="edit-provider-handle" value={editHandle} onChange={(event) => setEditHandle(event.target.value)} />
            </div>
            <div className="space-y-2">
              <Label htmlFor="edit-provider-base-url">{t("providerConfig.baseURL")}</Label>
              <Input
                id="edit-provider-base-url"
                type="url"
                value={editBaseURL}
                onChange={(event) => setEditBaseURL(event.target.value)}
                placeholder="https://api.example.com/v1"
                required
              />
              <p className="text-xs text-muted-foreground">{t("providerConfig.editBaseURLHelp")}</p>
            </div>
            {providerSettingsError ? <p className="text-sm text-destructive">{providerSettingsError}</p> : null}
            <div className="flex justify-end gap-2">
              <Button type="button" variant="outline" onClick={closeProviderEditor}>{t("providerConfig.cancel")}</Button>
              <Button
                type="button"
                disabled={savingProviderSettings || !editDisplayName.trim() || !editHandle.trim() || !editBaseURL.trim()}
                onClick={() => void saveProviderSettings()}
              >
                {savingProviderSettings ? <LoaderCircleIcon className="size-4 animate-spin" /> : null}
                {t("providerConfig.saveSettings")}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
