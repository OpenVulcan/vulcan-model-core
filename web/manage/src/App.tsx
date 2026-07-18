import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";

import {
  ControlPlaneRequestError,
  ManagementClient,
  splitModelIDs,
  type APIKeyRequest,
  type BindingRequest,
  type CreateDefinitionRequest,
  type CreateInstanceRequest,
  type CredentialMetadataRequest,
  type CredentialRequest,
  type EndpointRequest
} from "./api";
import type { APIKey, AccessBinding, Credential, CustomCatalogDocument, Endpoint, ProviderCatalog, ProviderDefinition, ProviderInstance, ProtocolProfile } from "./types";

// DefinitionDraft contains form-owned custom provider definition fields.
// DefinitionDraft 包含表单拥有的自定义供应商定义字段。
interface DefinitionDraft extends CreateDefinitionRequest {}

// InstanceDraft contains form-owned provider instance fields.
// InstanceDraft 包含表单拥有的供应商实例字段。
interface InstanceDraft extends CreateInstanceRequest {}

// EndpointDraft contains form-owned endpoint fields and its optional editing identifier.
// EndpointDraft 包含表单拥有的端点字段及其可选编辑标识。
interface EndpointDraft extends EndpointRequest {
  /** EditingID identifies the endpoint being edited when present. */
  /** EditingID 存在时标识正在编辑的端点。 */
  editing_id: string;
}

// CredentialDraft contains form-owned credential metadata and transient secret fields.
// CredentialDraft 包含表单拥有的凭据元数据和临时 Secret 字段。
interface CredentialDraft {
  /** EditingID identifies the credential being edited when present. */
  /** EditingID 存在时标识正在编辑的凭据。 */
  editing_id: string;
  /** ID optionally supplies a stable credential identifier on creation. */
  /** ID 创建时可选提供稳定凭据标识。 */
  id: string;
  /** AuthMethodID selects the declared authentication method. */
  /** AuthMethodID 选择已声明认证方式。 */
  auth_method_id: string;
  /** Label is the management-facing credential label. */
  /** Label 是管理界面凭据名称。 */
  label: string;
  /** PrincipalKey is optional operator-supplied upstream identity metadata. */
  /** PrincipalKey 是可选操作员提供的上游身份元数据。 */
  principal_key: string;
  /** Fingerprint is the irreversible duplicate-detection value. */
  /** Fingerprint 是不可逆排重值。 */
  fingerprint: string;
  /** Secret is used only during create or explicit rotation. */
  /** Secret 仅在创建或显式轮换时使用。 */
  secret: string;
  /** Status is the requested local lifecycle state. */
  /** Status 是请求的本地生命周期状态。 */
  status: string;
  /** CoolingUntil is an optional local ISO-compatible form timestamp. */
  /** CoolingUntil 是可选的本地 ISO 兼容表单时间戳。 */
  cooling_until: string;
}

// BindingDraft contains form-owned access binding fields and its optional editing identifier.
// BindingDraft 包含表单拥有的访问绑定字段及其可选编辑标识。
interface BindingDraft extends BindingRequest {
  /** EditingID identifies the binding being edited when present. */
  /** EditingID 存在时标识正在编辑的绑定。 */
  editing_id: string;
  /** AllowedModelsText is a comma-separated form representation. */
  /** AllowedModelsText 是逗号分隔的表单表示。 */
  allowed_models_text: string;
}

// APIKeyDraft contains form-owned call-plane key fields and its optional editing identifier.
// APIKeyDraft 包含表单拥有的调用面密钥字段及其可选编辑标识。
interface APIKeyDraft extends APIKeyRequest {
  /** EditingID identifies the key being edited when present. */
  /** EditingID 存在时标识正在编辑的密钥。 */
  editing_id: string;
}

// emptyDefinitionDraft is the initial custom provider definition form state.
// emptyDefinitionDraft 是初始自定义供应商定义表单状态。
const emptyDefinitionDraft: DefinitionDraft = {
  id: "",
  display_name: "",
  protocol_profile_id: "",
  auth_method: "bearer"
};

// emptyInstanceDraft is the initial provider instance form state.
// emptyInstanceDraft 是初始供应商实例表单状态。
const emptyInstanceDraft: InstanceDraft = {
  id: "",
  definition_id: "",
  handle: "",
  display_name: ""
};

// emptyEndpointDraft is the initial endpoint form state.
// emptyEndpointDraft 是初始端点表单状态。
const emptyEndpointDraft: EndpointDraft = {
  editing_id: "",
  id: "",
  channel_id: "default",
  base_url: "",
  region: "",
  status: "ready"
};

// emptyCredentialDraft is the initial credential form state.
// emptyCredentialDraft 是初始凭据表单状态。
const emptyCredentialDraft: CredentialDraft = {
  editing_id: "",
  id: "",
  auth_method_id: "default",
  label: "",
  principal_key: "",
  fingerprint: "",
  secret: "",
  status: "active",
  cooling_until: ""
};

// emptyBindingDraft is the initial access binding form state.
// emptyBindingDraft 是初始访问绑定表单状态。
const emptyBindingDraft: BindingDraft = {
  editing_id: "",
  id: "",
  channel_id: "default",
  endpoint_id: "",
  credential_id: "",
  allowed_model_ids: [],
  allowed_models_text: "",
  priority: 0,
  enabled: true
};

// emptyAPIKeyDraft is the initial call-plane key form state.
// emptyAPIKeyDraft 是初始调用面密钥表单状态。
const emptyAPIKeyDraft: APIKeyDraft = {
  editing_id: "",
  name: "",
  key: "",
  enabled: true
};

// emptyCustomCatalogDocument creates an editable empty custom-provider catalog document.
// emptyCustomCatalogDocument 创建一个可编辑的空自定义供应商目录文档。
function emptyCustomCatalogDocument(): CustomCatalogDocument {
  return { models: [], offerings: [], profiles: [] };
}

// customCatalogTemplate creates one unsaved example that documents every required custom catalog relationship.
// customCatalogTemplate 创建一个未保存示例，用于说明每个必填自定义目录关系。
function customCatalogTemplate(channelID: string): CustomCatalogDocument {
  // capabilities declares every capability explicitly so the server never infers omitted facts.
  // capabilities 显式声明每项能力，确保服务端绝不推导缺失事实。
  const capabilities = {
    context_window: { known: true, value: 128000 },
    max_input_tokens: { known: false },
    max_output_tokens: { known: true, value: 4096 },
    max_reasoning_tokens: { known: false },
    tool_calling: "unknown",
    parallel_tool_calls: "unknown",
    streaming_tool_arguments: "unknown",
    strict_json_schema: "unknown",
    reasoning: "unknown",
    input_modalities: ["text"],
    output_modalities: ["text"]
  };
  return {
    models: [{ id: "model_example", upstream_model_id: "example-model", display_name: "Example Model" }],
    offerings: [{ id: "offer_example", provider_model_id: "model_example", channel_id: channelID, upstream_model_id: "example-model", capabilities }],
    profiles: [{
      id: "profile_example_default",
      offering_id: "offer_example",
      display_name: "Default",
      default: true,
      capabilities,
      required_entitlement_classes: [],
      switch_policy: "seamless",
      pool_policy: "strict_profile"
    }]
  };
}

// formatCustomCatalogDocument serializes a typed document for the operator-facing JSON editor.
// formatCustomCatalogDocument 将类型化文档序列化为面向操作员的 JSON 编辑器内容。
function formatCustomCatalogDocument(document: CustomCatalogDocument): string {
  return JSON.stringify(document, null, 2);
}

// parseCustomCatalogDocument checks the JSON document envelope before strict server-side semantic validation.
// parseCustomCatalogDocument 在严格服务端语义校验前检查 JSON 文档外层结构。
function parseCustomCatalogDocument(value: string): CustomCatalogDocument {
  // parsed preserves untrusted operator input until the narrow document envelope has been checked.
  // parsed 在检查狭窄文档外层前保留不可信操作员输入。
  const parsed: unknown = JSON.parse(value);
  if (parsed === null || typeof parsed !== "object") {
    throw new Error("模型目录必须是 JSON 对象。");
  }
  // document checks only the collection envelope; the control plane validates every identifier, relationship, capability, and policy.
  // document 仅检查集合外层；控制面会校验每个标识、关系、能力和策略。
  const document = parsed as Record<string, unknown>;
  if (!Array.isArray(document.models) || !Array.isArray(document.offerings) || !Array.isArray(document.profiles)) {
    throw new Error("模型目录必须包含 models、offerings 与 profiles 数组。");
  }
  return parsed as CustomCatalogDocument;
}

// errorMessage converts an unknown asynchronous failure into a safe user-visible message.
// errorMessage 将未知异步失败转换为安全的用户可见消息。
function errorMessage(error: unknown): string {
  if (error instanceof ControlPlaneRequestError) {
    if (error.status === 401) {
      return "管理密钥无效，或核心服务未在 127.0.0.1:13514 运行。";
    }
    if (error.status === 404) {
      return "目标资源或模型目录尚不存在。";
    }
  }
  if (error instanceof Error) {
    return error.message;
  }
  return "管理操作失败。";
}

// App renders a memory-only management-key login boundary and the local control workspace.
// App 渲染仅内存管理密钥登录边界和本地控制工作区。
export default function App() {
  // managementKey retains the management credential only for the active browser session.
  // managementKey 仅在活动浏览器会话中保留管理凭据。
  const [managementKey, setManagementKey] = useState("");

  if (managementKey === "") {
    return <LoginPanel onConnect={setManagementKey} />;
  }
  return <ManagementWorkspace managementKey={managementKey} onDisconnect={() => setManagementKey("")} />;
}

// LoginPanelProps defines the memory-only credential handoff contract.
// LoginPanelProps 定义仅内存凭据交接合同。
interface LoginPanelProps {
  /** OnConnect receives the non-empty management key for this browser session. */
  /** OnConnect 接收此浏览器会话的非空管理密钥。 */
  onConnect: (managementKey: string) => void;
}

// LoginPanel requests the management key without writing it to browser storage.
// LoginPanel 请求管理密钥且不将其写入浏览器存储。
function LoginPanel({ onConnect }: LoginPanelProps) {
  // inputKey is held only in the controlled password input until connection.
  // inputKey 仅在受控密码输入框中保留直到连接。
  const [inputKey, setInputKey] = useState("");
  // validationMessage reports a local input error before any API request occurs.
  // validationMessage 在任何 API 请求前报告本地输入错误。
  const [validationMessage, setValidationMessage] = useState("");

  // submit validates the key locally before entering the management workspace.
  // submit 在进入管理工作区前于本地校验密钥。
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const normalizedKey = inputKey.trim();
    if (normalizedKey === "") {
      setValidationMessage("请输入管理密钥。");
      return;
    }
    setValidationMessage("");
    onConnect(normalizedKey);
  };

  return (
    <main className="login-shell">
      <section className="login-card" aria-labelledby="login-title">
        <p className="eyebrow">VULCAN MODEL CORE</p>
        <h1 id="login-title">本地管理控制台</h1>
        <p>连接到 <code>127.0.0.1:13514</code> 的 <code>/vulcan/manage</code>。管理密钥只保存在当前页面内存中。</p>
        <form onSubmit={submit}>
          <label htmlFor="management-key">管理密钥</label>
          <input
            id="management-key"
            name="management-key"
            type="password"
            autoComplete="current-password"
            value={inputKey}
            onChange={(event) => setInputKey(event.target.value)}
            placeholder="输入配置文件中的初始管理密钥"
          />
          {validationMessage !== "" ? <p className="error" role="alert">{validationMessage}</p> : null}
          <button type="submit">进入管理端</button>
        </form>
      </section>
    </main>
  );
}

// ManagementWorkspaceProps defines the authenticated workspace inputs.
// ManagementWorkspaceProps 定义认证工作区输入。
interface ManagementWorkspaceProps {
  /** ManagementKey is retained in browser memory by the parent login boundary. */
  /** ManagementKey 由父级登录边界保留在浏览器内存中。 */
  managementKey: string;
  /** OnDisconnect removes the management key from browser memory. */
  /** OnDisconnect 从浏览器内存移除管理密钥。 */
  onDisconnect: () => void;
}

// ManagementWorkspace exposes every current management node through the dedicated local API namespace.
// ManagementWorkspace 通过专用本地 API 命名空间暴露每个当前管理节点。
function ManagementWorkspace({ managementKey, onDisconnect }: ManagementWorkspaceProps) {
  // client owns requests authenticated with the management-only bearer value.
  // client 管理使用仅管理 Bearer 值认证的请求。
  const client = useMemo(() => new ManagementClient(managementKey), [managementKey]);
  // protocolProfiles contains process-owned custom-provider protocol choices.
  // protocolProfiles 包含进程拥有的自定义供应商协议选项。
  const [protocolProfiles, setProtocolProfiles] = useState<ProtocolProfile[]>([]);
  // definitions contains system and custom provider contracts.
  // definitions 包含系统和自定义供应商合同。
  const [definitions, setDefinitions] = useState<ProviderDefinition[]>([]);
  // instances contains all provider instance summaries.
  // instances 包含全部供应商实例摘要。
  const [instances, setInstances] = useState<ProviderInstance[]>([]);
  // apiKeys contains management-authorized plaintext call-plane key records.
  // apiKeys 包含经管理授权的明文调用面密钥记录。
  const [apiKeys, setAPIKeys] = useState<APIKey[]>([]);
  // selectedInstanceID identifies the instance whose child resources are currently managed.
  // selectedInstanceID 标识当前管理其子资源的实例。
  const [selectedInstanceID, setSelectedInstanceID] = useState("");
  // endpoints contains endpoints owned by the selected provider instance.
  // endpoints 包含所选供应商实例拥有的端点。
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  // credentials contains redacted credentials owned by the selected provider instance.
  // credentials 包含所选供应商实例拥有的已脱敏凭据。
  const [credentials, setCredentials] = useState<Credential[]>([]);
  // bindings contains selected-instance credential-to-endpoint relationships.
  // bindings 包含所选实例的凭据到端点关系。
  const [bindings, setBindings] = useState<AccessBinding[]>([]);
  // catalog contains the selected-instance model catalog when one has been published.
  // catalog 包含已发布时所选实例的模型目录。
  const [catalog, setCatalog] = useState<ProviderCatalog | null>(null);
  // definitionDraft owns editable custom provider definition form values.
  // definitionDraft 管理可编辑自定义供应商定义表单值。
  const [definitionDraft, setDefinitionDraft] = useState<DefinitionDraft>(emptyDefinitionDraft);
  // editingDefinitionID identifies a custom definition currently being replaced.
  // editingDefinitionID 标识当前正在替换的自定义定义。
  const [editingDefinitionID, setEditingDefinitionID] = useState("");
  // instanceDraft owns editable provider instance form values.
  // instanceDraft 管理可编辑供应商实例表单值。
  const [instanceDraft, setInstanceDraft] = useState<InstanceDraft>(emptyInstanceDraft);
  // editingInstanceID identifies a provider instance currently being edited.
  // editingInstanceID 标识当前正在编辑的供应商实例。
  const [editingInstanceID, setEditingInstanceID] = useState("");
  // endpointDraft owns editable endpoint form values.
  // endpointDraft 管理可编辑端点表单值。
  const [endpointDraft, setEndpointDraft] = useState<EndpointDraft>(emptyEndpointDraft);
  // credentialDraft owns editable credential form values and never receives a server-side secret value.
  // credentialDraft 管理可编辑凭据表单值且永不接收服务端 Secret 值。
  const [credentialDraft, setCredentialDraft] = useState<CredentialDraft>(emptyCredentialDraft);
  // bindingDraft owns editable access binding form values.
  // bindingDraft 管理可编辑访问绑定表单值。
  const [bindingDraft, setBindingDraft] = useState<BindingDraft>(emptyBindingDraft);
  // apiKeyDraft owns editable call-plane API key form values.
  // apiKeyDraft 管理可编辑调用面 API 密钥表单值。
  const [apiKeyDraft, setAPIKeyDraft] = useState<APIKeyDraft>(emptyAPIKeyDraft);
  // customCatalogText holds the selected custom provider's editable non-secret catalog document.
  // customCatalogText 保存所选自定义供应商可编辑的非秘密目录文档。
  const [customCatalogText, setCustomCatalogText] = useState(formatCustomCatalogDocument(emptyCustomCatalogDocument()));
  // notice reports the latest successful operation without including credentials or secrets.
  // notice 报告最新成功操作且不包含凭据或 Secret。
  const [notice, setNotice] = useState("");
  // failure reports the latest local-safe operation error.
  // failure 报告最新本地安全操作错误。
  const [failure, setFailure] = useState("");
  // loading reports an in-flight initial or explicit refresh.
  // loading 报告正在进行的初始或显式刷新。
  const [loading, setLoading] = useState(false);

  // refreshCore reloads resource summaries that are independent of one selected provider instance.
  // refreshCore 重新加载独立于所选供应商实例的资源摘要。
  const refreshCore = useCallback(async () => {
    const [loadedProfiles, loadedDefinitions, loadedInstances, loadedAPIKeys] = await Promise.all([
      client.listProtocolProfiles(),
      client.listDefinitions(),
      client.listInstances(),
      client.listAPIKeys()
    ]);
    setProtocolProfiles(loadedProfiles);
    setDefinitions(loadedDefinitions);
    setInstances(loadedInstances);
    setAPIKeys(loadedAPIKeys);
    setSelectedInstanceID((currentID) => loadedInstances.some((instance) => instance.id === currentID) ? currentID : loadedInstances[0]?.id ?? "");
  }, [client]);

  // refreshSelectedInstance reloads child resources and treats an unpublished catalog as an empty model section.
  // refreshSelectedInstance 重新加载子资源，并将未发布目录视为一个空模型区块。
  const refreshSelectedInstance = useCallback(async (instanceID: string) => {
    if (instanceID === "") {
      setEndpoints([]);
      setCredentials([]);
      setBindings([]);
      setCatalog(null);
      return;
    }
    const [loadedEndpoints, loadedCredentials, loadedBindings] = await Promise.all([
      client.listEndpoints(instanceID),
      client.listCredentials(instanceID),
      client.listBindings(instanceID)
    ]);
    setEndpoints(loadedEndpoints);
    setCredentials(loadedCredentials);
    setBindings(loadedBindings);
    try {
      setCatalog(await client.getCatalog(instanceID));
    } catch (error) {
      if (error instanceof ControlPlaneRequestError && error.status === 404) {
        setCatalog(null);
        return;
      }
      throw error;
    }
  }, [client]);

  // reload performs one complete safe data refresh and reports a user-visible failure when needed.
  // reload 执行一次完整安全数据刷新并在需要时报告用户可见失败。
  const reload = useCallback(async () => {
    setLoading(true);
    setFailure("");
    try {
      await refreshCore();
      await refreshSelectedInstance(selectedInstanceID);
    } catch (error) {
      setFailure(errorMessage(error));
    } finally {
      setLoading(false);
    }
  }, [refreshCore, refreshSelectedInstance, selectedInstanceID]);

  useEffect(() => {
    void reload();
  }, [reload]);

  useEffect(() => {
    void refreshSelectedInstance(selectedInstanceID).catch((error) => setFailure(errorMessage(error)));
  }, [refreshSelectedInstance, selectedInstanceID]);

  useEffect(() => {
    // selectedInstance resolves the exact current owner before requesting custom-only catalog configuration.
    // selectedInstance 在请求仅自定义目录配置前解析精确当前所有者。
    const selectedInstance = instances.find((instance) => instance.id === selectedInstanceID);
    const selectedDefinition = definitions.find((definition) => definition.id === selectedInstance?.definition_id);
    if (selectedInstance === undefined || selectedDefinition?.kind !== "custom") {
      setCustomCatalogText(formatCustomCatalogDocument(emptyCustomCatalogDocument()));
      return;
    }
    // active prevents a slower previous selection request from overwriting the current editor.
    // active 防止较慢的先前选择请求覆盖当前编辑器。
    let active = true;
    void client.getCustomCatalog(selectedInstance.id)
      .then((document) => {
        if (active) {
          setCustomCatalogText(formatCustomCatalogDocument(document));
        }
      })
      .catch((error) => {
        if (!active) {
          return;
        }
        if (error instanceof ControlPlaneRequestError && error.status === 404) {
          setCustomCatalogText(formatCustomCatalogDocument(emptyCustomCatalogDocument()));
          return;
        }
        setFailure(errorMessage(error));
      });
    return () => {
      active = false;
    };
  }, [client, definitions, instances, selectedInstanceID]);

  // runAction applies a typed management mutation and refreshes all observable state afterwards.
  // runAction 应用类型化管理变更并在之后刷新全部可观察状态。
  const runAction = async (successMessage: string, action: () => Promise<void>) => {
    setFailure("");
    setNotice("");
    try {
      await action();
      await refreshCore();
      await refreshSelectedInstance(selectedInstanceID);
      setNotice(successMessage);
    } catch (error) {
      setFailure(errorMessage(error));
    }
  };

  // submitDefinition creates or replaces one custom provider definition.
  // submitDefinition 创建或替换一个自定义供应商定义。
  const submitDefinition = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    void runAction(editingDefinitionID === "" ? "已创建自定义供应商定义。" : "已更新自定义供应商定义；关联实例已标记为待迁移。", async () => {
      if (editingDefinitionID === "") {
        await client.createDefinition(definitionDraft);
      } else {
        await client.updateDefinition(editingDefinitionID, {
          display_name: definitionDraft.display_name,
          protocol_profile_id: definitionDraft.protocol_profile_id,
          auth_method: definitionDraft.auth_method
        });
      }
      setDefinitionDraft(emptyDefinitionDraft);
      setEditingDefinitionID("");
    });
  };

  // beginDefinitionEdit copies a custom definition into the edit form and preserves system definition immutability.
  // beginDefinitionEdit 将自定义定义复制到编辑表单并保持系统定义不可变性。
  const beginDefinitionEdit = (definition: ProviderDefinition) => {
    if (definition.kind !== "custom") {
      return;
    }
    const channel = definition.channels[0];
    setEditingDefinitionID(definition.id);
    setDefinitionDraft({
      id: definition.id,
      display_name: definition.display_name,
      protocol_profile_id: channel?.protocol_profile_id ?? "",
      auth_method: definition.auth_methods[0]?.type ?? "bearer"
    });
  };

  // submitInstance creates or replaces editable identity fields of one provider instance.
  // submitInstance 创建或替换一个供应商实例的可编辑身份字段。
  const submitInstance = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    void runAction(editingInstanceID === "" ? "已创建供应商实例。" : "已更新供应商实例。", async () => {
      if (editingInstanceID === "") {
        const createdID = await client.createInstance(instanceDraft);
        setSelectedInstanceID(createdID);
      } else {
        await client.updateInstance(editingInstanceID, instanceDraft.handle, instanceDraft.display_name);
      }
      setInstanceDraft(emptyInstanceDraft);
      setEditingInstanceID("");
    });
  };

  // beginInstanceEdit copies one instance into the editable identity form.
  // beginInstanceEdit 将一个实例复制到可编辑身份表单。
  const beginInstanceEdit = (instance: ProviderInstance) => {
    setEditingInstanceID(instance.id);
    setInstanceDraft({ id: instance.id, definition_id: instance.definition_id, handle: instance.handle, display_name: instance.display_name });
  };

  // submitEndpoint creates or replaces one upstream endpoint under the selected instance.
  // submitEndpoint 在所选实例下创建或替换一个上游端点。
  const submitEndpoint = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (selectedInstanceID === "") {
      setFailure("请先创建并选择供应商实例。");
      return;
    }
    void runAction(endpointDraft.editing_id === "" ? "已创建上游端点。" : "已更新上游端点。", async () => {
      if (endpointDraft.editing_id === "") {
        await client.createEndpoint(selectedInstanceID, endpointDraft);
      } else {
        await client.updateEndpoint(selectedInstanceID, endpointDraft.editing_id, endpointDraft);
      }
      setEndpointDraft(emptyEndpointDraft);
    });
  };

  // beginEndpointEdit copies one endpoint into the selected-instance edit form.
  // beginEndpointEdit 将一个端点复制到所选实例编辑表单。
  const beginEndpointEdit = (endpoint: Endpoint) => {
    setEndpointDraft({ editing_id: endpoint.id, id: endpoint.id, channel_id: endpoint.channel_id, base_url: endpoint.base_url, region: endpoint.region, status: endpoint.status });
  };

  // submitCredential creates or replaces credential metadata without ever requesting a stored secret from the server.
  // submitCredential 创建或替换凭据元数据且绝不从服务端请求已存储 Secret。
  const submitCredential = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (selectedInstanceID === "") {
      setFailure("请先创建并选择供应商实例。");
      return;
    }
    void runAction(credentialDraft.editing_id === "" ? "已添加上游凭据。" : "已更新上游凭据元数据。", async () => {
      if (credentialDraft.editing_id === "") {
        const payload: CredentialRequest = {
          id: credentialDraft.id,
          auth_method_id: credentialDraft.auth_method_id,
          label: credentialDraft.label,
          principal_key: credentialDraft.principal_key,
          fingerprint: credentialDraft.fingerprint,
          scope_refs: [],
          secret: credentialDraft.secret
        };
        await client.createCredential(selectedInstanceID, payload);
      } else {
        const payload: CredentialMetadataRequest = {
          label: credentialDraft.label,
          principal_key: credentialDraft.principal_key,
          fingerprint: credentialDraft.fingerprint,
          scope_refs: []
        };
        await client.updateCredential(selectedInstanceID, credentialDraft.editing_id, payload);
      }
      setCredentialDraft(emptyCredentialDraft);
    });
  };

  // beginCredentialEdit copies only redacted metadata into the form and leaves sensitive fields empty for explicit operator replacement.
  // beginCredentialEdit 仅将脱敏元数据复制到表单，并将敏感字段留空供操作员显式替换。
  const beginCredentialEdit = (credential: Credential) => {
    setCredentialDraft({
      ...emptyCredentialDraft,
      editing_id: credential.id,
      id: credential.id,
      auth_method_id: credential.auth_method_id,
      label: credential.label,
      status: credential.status,
      cooling_until: credential.cooling_until === null ? "" : credential.cooling_until.slice(0, 16)
    });
  };

  // rotateCredential sends a replacement secret only when an operator explicitly provides it.
  // rotateCredential 仅在操作员显式提供时发送替换 Secret。
  const rotateCredential = () => {
    if (selectedInstanceID === "" || credentialDraft.editing_id === "") {
      setFailure("请先选择要轮换的凭据。");
      return;
    }
    if (credentialDraft.secret === "" || credentialDraft.fingerprint === "") {
      setFailure("轮换 Secret 时必须提供新 Secret 和新指纹。" );
      return;
    }
    void runAction("已轮换上游凭据 Secret。", async () => {
      await client.rotateCredentialSecret(selectedInstanceID, credentialDraft.editing_id, credentialDraft.secret, credentialDraft.fingerprint);
      setCredentialDraft(emptyCredentialDraft);
    });
  };

  // updateCredentialStatus applies the selected credential lifecycle state.
  // updateCredentialStatus 应用所选凭据生命周期状态。
  const updateCredentialStatus = () => {
    if (selectedInstanceID === "" || credentialDraft.editing_id === "") {
      setFailure("请先选择要调整状态的凭据。");
      return;
    }
    void runAction("已更新凭据状态。", async () => {
      await client.setCredentialStatus(selectedInstanceID, credentialDraft.editing_id, credentialDraft.status, credentialDraft.cooling_until);
    });
  };

  // submitBinding creates or replaces one same-instance endpoint-to-credential relationship.
  // submitBinding 创建或替换一个同实例端点到凭据关系。
  const submitBinding = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (selectedInstanceID === "") {
      setFailure("请先创建并选择供应商实例。");
      return;
    }
    const payload: BindingRequest = {
      id: bindingDraft.id,
      channel_id: bindingDraft.channel_id,
      endpoint_id: bindingDraft.endpoint_id,
      credential_id: bindingDraft.credential_id,
      allowed_model_ids: splitModelIDs(bindingDraft.allowed_models_text),
      priority: bindingDraft.priority,
      enabled: bindingDraft.enabled
    };
    void runAction(bindingDraft.editing_id === "" ? "已创建访问绑定。" : "已更新访问绑定。", async () => {
      if (bindingDraft.editing_id === "") {
        await client.createBinding(selectedInstanceID, payload);
      } else {
        await client.updateBinding(selectedInstanceID, bindingDraft.editing_id, payload);
      }
      setBindingDraft(emptyBindingDraft);
    });
  };

  // beginBindingEdit copies one binding into the selected-instance edit form.
  // beginBindingEdit 将一个绑定复制到所选实例编辑表单。
  const beginBindingEdit = (binding: AccessBinding) => {
    setBindingDraft({
      editing_id: binding.id,
      id: binding.id,
      channel_id: binding.channel_id,
      endpoint_id: binding.endpoint_id,
      credential_id: binding.credential_id,
      allowed_model_ids: binding.allowed_model_ids,
      allowed_models_text: binding.allowed_model_ids.join(", "),
      priority: binding.priority,
      enabled: binding.enabled
    });
  };

  // loadCustomCatalog replaces the editor with the latest saved document for the selected custom provider.
  // loadCustomCatalog 使用所选自定义供应商的最新已保存文档替换编辑器内容。
  const loadCustomCatalog = () => {
    if (selectedInstanceID === "") {
      setFailure("请先选择自定义供应商实例。");
      return;
    }
    setFailure("");
    void client.getCustomCatalog(selectedInstanceID)
      .then((document) => {
        setCustomCatalogText(formatCustomCatalogDocument(document));
        setNotice("已加载自定义模型目录。");
      })
      .catch((error) => {
        if (error instanceof ControlPlaneRequestError && error.status === 404) {
          setCustomCatalogText(formatCustomCatalogDocument(emptyCustomCatalogDocument()));
          setNotice("该自定义供应商尚未保存模型目录。");
          return;
        }
        setFailure(errorMessage(error));
      });
  };

  // writeCustomCatalogTemplate puts an unsaved complete schema example into the editor for the exact custom default channel.
  // writeCustomCatalogTemplate 将一个未保存的完整模式示例写入该自定义默认通道的编辑器。
  const writeCustomCatalogTemplate = () => {
    setCustomCatalogText(formatCustomCatalogDocument(customCatalogTemplate("default")));
    setNotice("已写入示例，请替换模型与能力事实后再保存。");
  };

  // saveCustomCatalog parses only JSON syntax locally and delegates strict semantic validation to the typed management API.
  // saveCustomCatalog 仅在本地解析 JSON 语法，并将严格语义校验委托给类型化管理 API。
  const saveCustomCatalog = () => {
    if (selectedInstanceID === "") {
      setFailure("请先选择自定义供应商实例。");
      return;
    }
    // document is retained only after the editor envelope has passed local syntax validation.
    // document 仅在编辑器外层通过本地语法校验后保留。
    let document: CustomCatalogDocument;
    try {
      document = parseCustomCatalogDocument(customCatalogText);
    } catch (error) {
      setFailure(errorMessage(error));
      return;
    }
    void runAction("已保存自定义模型目录。", async () => {
      const saved = await client.saveCustomCatalog(selectedInstanceID, document);
      setCustomCatalogText(formatCustomCatalogDocument(saved));
    });
  };

  // submitAPIKey creates or replaces one management-visible call-plane key.
  // submitAPIKey 创建或替换一个管理面可见调用面密钥。
  const submitAPIKey = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const payload: APIKeyRequest = { name: apiKeyDraft.name, key: apiKeyDraft.key, enabled: apiKeyDraft.enabled };
    void runAction(apiKeyDraft.editing_id === "" ? "已创建调用 API 密钥。" : "已更新调用 API 密钥。", async () => {
      if (apiKeyDraft.editing_id === "") {
        await client.createAPIKey(payload);
      } else {
        await client.updateAPIKey(apiKeyDraft.editing_id, payload);
      }
      setAPIKeyDraft(emptyAPIKeyDraft);
    });
  };

  // beginAPIKeyEdit copies one plaintext key into the management-authorized edit form.
  // beginAPIKeyEdit 将一个明文密钥复制到管理授权编辑表单。
  const beginAPIKeyEdit = (apiKey: APIKey) => {
    setAPIKeyDraft({ editing_id: apiKey.id, name: apiKey.name, key: apiKey.key, enabled: apiKey.enabled });
  };

  // selectedDefinitionProfile is the profile selected by the definition form when available.
  // selectedDefinitionProfile 是定义表单当前选择的 Profile（如存在）。
  const selectedDefinitionProfile = protocolProfiles.find((profile) => profile.id === definitionDraft.protocol_profile_id);
  // selectedInstanceDefinition is the exact definition that owns the resource panel's current instance.
  // selectedInstanceDefinition 是拥有资源面板当前实例的精确定义。
  const selectedInstanceDefinition = definitions.find((definition) => definition.id === instances.find((instance) => instance.id === selectedInstanceID)?.definition_id);
  // selectedDefinitionChannels contains the channels declared by the selected instance definition.
  // selectedDefinitionChannels 包含所选实例定义声明的通道。
  const selectedDefinitionChannels = selectedInstanceDefinition?.channels ?? [];
  // selectedInstanceIsCustom reports whether user-declared catalog editing is allowed for the selected instance.
  // selectedInstanceIsCustom 报告所选实例是否允许用户声明目录编辑。
  const selectedInstanceIsCustom = selectedInstanceDefinition?.kind === "custom";

  return (
    <main className="workspace-shell">
      <header className="workspace-header">
        <div>
          <p className="eyebrow">LOCAL CONTROL PLANE</p>
          <h1>Vulcan 管理控制台</h1>
          <p>核心：<code>127.0.0.1:13514</code>　管理页面：<code>127.0.0.1:13520</code></p>
        </div>
        <div className="header-actions">
          <button type="button" className="secondary" onClick={() => void reload()} disabled={loading}>{loading ? "刷新中…" : "刷新"}</button>
          <button type="button" className="secondary" onClick={onDisconnect}>退出并清除内存密钥</button>
        </div>
      </header>
      {notice !== "" ? <p className="notice" role="status">{notice}</p> : null}
      {failure !== "" ? <p className="error" role="alert">{failure}</p> : null}

      <section className="panel" aria-labelledby="protocol-title">
        <div className="section-title">
          <div>
            <p className="eyebrow">1. PROTOCOLS</p>
            <h2 id="protocol-title">可配置上游协议</h2>
          </div>
          <p>仅展示内部出站 Profile；不会新增公开兼容端点。</p>
        </div>
        <div className="chip-list">
          {protocolProfiles.filter((profile) => profile.user_configurable).map((profile) => (
            <span className="chip" key={profile.id}>{profile.display_name} · <code>{profile.id}</code> · {profile.allowed_auth_methods.join(" / ")}</span>
          ))}
        </div>
      </section>

      <section className="two-column">
        <section className="panel" aria-labelledby="definition-title">
          <div className="section-title">
            <div>
              <p className="eyebrow">2. PROVIDER DEFINITIONS</p>
              <h2 id="definition-title">供应商定义</h2>
            </div>
            <p>系统定义只读；可创建和编辑自定义定义。</p>
          </div>
          <div className="resource-list">
            {definitions.map((definition) => (
              <article className="resource-row" key={definition.id}>
                <div>
                  <strong>{definition.display_name}</strong>
                  <span><code>{definition.id}</code> · {definition.kind} · {definition.channels.map((channel) => channel.protocol_profile_id).join(", ")}</span>
                </div>
                {definition.kind === "custom" ? <button type="button" className="secondary" onClick={() => beginDefinitionEdit(definition)}>编辑</button> : <span className="readonly">系统定义</span>}
              </article>
            ))}
          </div>
          <form className="form-grid" onSubmit={submitDefinition}>
            <h3>{editingDefinitionID === "" ? "新增自定义供应商" : `编辑 ${editingDefinitionID}`}</h3>
            <label>定义 ID（custom_ 前缀）<input value={definitionDraft.id} disabled={editingDefinitionID !== ""} onChange={(event) => setDefinitionDraft({ ...definitionDraft, id: event.target.value })} placeholder="custom_private_gateway" /></label>
            <label>显示名称<input value={definitionDraft.display_name} onChange={(event) => setDefinitionDraft({ ...definitionDraft, display_name: event.target.value })} required /></label>
            <label>协议 Profile
              <select value={definitionDraft.protocol_profile_id} onChange={(event) => {
                const profile = protocolProfiles.find((candidate) => candidate.id === event.target.value);
                setDefinitionDraft({ ...definitionDraft, protocol_profile_id: event.target.value, auth_method: profile?.allowed_auth_methods[0] ?? "bearer" });
              }} required>
                <option value="">选择协议</option>
                {protocolProfiles.filter((profile) => profile.user_configurable && profile.runtime_ready).map((profile) => <option key={profile.id} value={profile.id}>{profile.display_name} ({profile.id})</option>)}
              </select>
            </label>
            <label>认证方式
              <select value={definitionDraft.auth_method} onChange={(event) => setDefinitionDraft({ ...definitionDraft, auth_method: event.target.value })} required>
                {(selectedDefinitionProfile?.allowed_auth_methods ?? []).map((method) => <option key={method} value={method}>{method}</option>)}
              </select>
            </label>
            <div className="form-actions"><button type="submit">{editingDefinitionID === "" ? "创建定义" : "保存定义"}</button><button type="button" className="secondary" onClick={() => { setDefinitionDraft(emptyDefinitionDraft); setEditingDefinitionID(""); }}>清空</button></div>
          </form>
        </section>

        <section className="panel" aria-labelledby="instance-title">
          <div className="section-title">
            <div>
              <p className="eyebrow">3. PROVIDER INSTANCES</p>
              <h2 id="instance-title">供应商实例</h2>
            </div>
            <p>启用时会验证端点、凭据与绑定闭环。</p>
          </div>
          <div className="resource-list">
            {instances.map((instance) => (
              <article className={`resource-row ${instance.id === selectedInstanceID ? "selected" : ""}`} key={instance.id}>
                <button type="button" className="row-select" onClick={() => setSelectedInstanceID(instance.id)}>
                  <strong>{instance.display_name}</strong>
                  <span><code>{instance.handle}</code> · {instance.status} · 端点 {instance.endpoint_count} / 凭据 {instance.credential_count} / 绑定 {instance.binding_count}</span>
                </button>
                <div className="row-actions">
                  <button type="button" className="secondary" onClick={() => beginInstanceEdit(instance)}>编辑</button>
                  <button type="button" className="secondary" onClick={() => void runAction(instance.status === "disabled" ? "已请求启用实例。" : "已禁用实例。", async () => client.setInstanceEnabled(instance.id, instance.status === "disabled"))}>{instance.status === "disabled" ? "启用" : "禁用"}</button>
                </div>
              </article>
            ))}
          </div>
          <form className="form-grid" onSubmit={submitInstance}>
            <h3>{editingInstanceID === "" ? "新增实例" : `编辑 ${editingInstanceID}`}</h3>
            <label>实例 ID（pvi_ 前缀）<input value={instanceDraft.id} disabled={editingInstanceID !== ""} onChange={(event) => setInstanceDraft({ ...instanceDraft, id: event.target.value })} placeholder="pvi_gateway" /></label>
            <label>供应商定义
              <select value={instanceDraft.definition_id} disabled={editingInstanceID !== ""} onChange={(event) => setInstanceDraft({ ...instanceDraft, definition_id: event.target.value })} required>
                <option value="">选择定义</option>
                {definitions.map((definition) => <option key={definition.id} value={definition.id}>{definition.display_name} ({definition.id})</option>)}
              </select>
            </label>
            <label>路由 Handle<input value={instanceDraft.handle} onChange={(event) => setInstanceDraft({ ...instanceDraft, handle: event.target.value })} required /></label>
            <label>显示名称<input value={instanceDraft.display_name} onChange={(event) => setInstanceDraft({ ...instanceDraft, display_name: event.target.value })} required /></label>
            <div className="form-actions"><button type="submit">{editingInstanceID === "" ? "创建实例" : "保存实例"}</button><button type="button" className="secondary" onClick={() => { setInstanceDraft(emptyInstanceDraft); setEditingInstanceID(""); }}>清空</button></div>
          </form>
        </section>
      </section>

      <section className="panel" aria-labelledby="resources-title">
        <div className="section-title">
          <div>
            <p className="eyebrow">4. SELECTED INSTANCE</p>
            <h2 id="resources-title">端点、凭据、绑定与模型控制</h2>
          </div>
          <label className="instance-picker">当前实例
            <select value={selectedInstanceID} onChange={(event) => setSelectedInstanceID(event.target.value)}>
              <option value="">选择实例</option>
              {instances.map((instance) => <option key={instance.id} value={instance.id}>{instance.display_name} ({instance.handle})</option>)}
            </select>
          </label>
        </div>
        {selectedInstanceID === "" ? <p className="empty-state">请选择或创建一个供应商实例后配置其资源。</p> : (
          <div className="resource-grid">
            <section className="subpanel">
              <h3>上游端点</h3>
              <div className="resource-list compact">
                {endpoints.map((endpoint) => <article className="resource-row" key={endpoint.id}><div><strong>{endpoint.base_url}</strong><span><code>{endpoint.id}</code> · {endpoint.channel_id} · {endpoint.status}</span></div><button type="button" className="secondary" onClick={() => beginEndpointEdit(endpoint)}>编辑</button></article>)}
              </div>
              <form className="form-grid compact" onSubmit={submitEndpoint}>
                <label>端点 ID<input value={endpointDraft.id ?? ""} disabled={endpointDraft.editing_id !== ""} onChange={(event) => setEndpointDraft({ ...endpointDraft, id: event.target.value })} placeholder="ep_gateway" /></label>
                <label>通道
                  <select value={endpointDraft.channel_id} onChange={(event) => setEndpointDraft({ ...endpointDraft, channel_id: event.target.value })} required>
                    {(selectedDefinitionChannels.length === 0 ? [{ id: "default" }] : selectedDefinitionChannels).map((channel) => <option key={channel.id} value={channel.id}>{channel.id}</option>)}
                  </select>
                </label>
                <label>Base URL<input type="url" value={endpointDraft.base_url} onChange={(event) => setEndpointDraft({ ...endpointDraft, base_url: event.target.value })} placeholder="https://gateway.example/v1" required /></label>
                <label>区域<input value={endpointDraft.region} onChange={(event) => setEndpointDraft({ ...endpointDraft, region: event.target.value })} /></label>
                <label>状态<select value={endpointDraft.status ?? "ready"} onChange={(event) => setEndpointDraft({ ...endpointDraft, status: event.target.value })}><option value="ready">ready</option><option value="unavailable">unavailable</option><option value="disabled">disabled</option></select></label>
                <div className="form-actions"><button type="submit">{endpointDraft.editing_id === "" ? "添加端点" : "保存端点"}</button><button type="button" className="secondary" onClick={() => setEndpointDraft(emptyEndpointDraft)}>清空</button></div>
              </form>
            </section>

            <section className="subpanel">
              <h3>上游凭据</h3>
              <p className="hint">服务器不会返回 Secret、指纹或账号身份；编辑时请仅在需要替换时重新输入。</p>
              <div className="resource-list compact">
                {credentials.map((credential) => <article className="resource-row" key={credential.id}><div><strong>{credential.label}</strong><span><code>{credential.id}</code> · {credential.auth_method_id} · {credential.status}</span></div><button type="button" className="secondary" onClick={() => beginCredentialEdit(credential)}>编辑</button></article>)}
              </div>
              <form className="form-grid compact" onSubmit={submitCredential}>
                <label>凭据 ID<input value={credentialDraft.id} disabled={credentialDraft.editing_id !== ""} onChange={(event) => setCredentialDraft({ ...credentialDraft, id: event.target.value })} placeholder="cred_gateway" /></label>
                <label>认证方式 ID<input value={credentialDraft.auth_method_id} disabled={credentialDraft.editing_id !== ""} onChange={(event) => setCredentialDraft({ ...credentialDraft, auth_method_id: event.target.value })} required /></label>
                <label>显示名称<input value={credentialDraft.label} onChange={(event) => setCredentialDraft({ ...credentialDraft, label: event.target.value })} required /></label>
                <label>账号标识（可选）<input value={credentialDraft.principal_key} onChange={(event) => setCredentialDraft({ ...credentialDraft, principal_key: event.target.value })} /></label>
                <label>指纹<input value={credentialDraft.fingerprint} onChange={(event) => setCredentialDraft({ ...credentialDraft, fingerprint: event.target.value })} required /></label>
                <label>Secret{credentialDraft.editing_id === "" ? <textarea value={credentialDraft.secret} onChange={(event) => setCredentialDraft({ ...credentialDraft, secret: event.target.value })} required /> : <textarea value={credentialDraft.secret} onChange={(event) => setCredentialDraft({ ...credentialDraft, secret: event.target.value })} placeholder="仅轮换时填写" />}</label>
                <div className="form-actions"><button type="submit">{credentialDraft.editing_id === "" ? "添加凭据" : "保存元数据"}</button>{credentialDraft.editing_id !== "" ? <button type="button" className="secondary" onClick={rotateCredential}>轮换 Secret</button> : null}<button type="button" className="secondary" onClick={() => setCredentialDraft(emptyCredentialDraft)}>清空</button></div>
              </form>
              {credentialDraft.editing_id !== "" ? <div className="inline-controls"><label>状态<select value={credentialDraft.status} onChange={(event) => setCredentialDraft({ ...credentialDraft, status: event.target.value })}><option value="active">active</option><option value="disabled">disabled</option><option value="expired">expired</option><option value="invalid">invalid</option><option value="cooling">cooling</option></select></label><label>冷却至<input type="datetime-local" value={credentialDraft.cooling_until} onChange={(event) => setCredentialDraft({ ...credentialDraft, cooling_until: event.target.value })} /></label><button type="button" className="secondary" onClick={updateCredentialStatus}>更新状态</button></div> : null}
            </section>

            <section className="subpanel">
              <h3>访问绑定</h3>
              <div className="resource-list compact">
                {bindings.map((binding) => <article className="resource-row" key={binding.id}><div><strong>{binding.enabled ? "已启用" : "已禁用"}</strong><span><code>{binding.id}</code> · {binding.endpoint_id} → {binding.credential_id} · 优先级 {binding.priority}</span></div><button type="button" className="secondary" onClick={() => beginBindingEdit(binding)}>编辑</button></article>)}
              </div>
              <form className="form-grid compact" onSubmit={submitBinding}>
                <label>绑定 ID<input value={bindingDraft.id ?? ""} disabled={bindingDraft.editing_id !== ""} onChange={(event) => setBindingDraft({ ...bindingDraft, id: event.target.value })} placeholder="bind_gateway" /></label>
                <label>通道<select value={bindingDraft.channel_id} onChange={(event) => setBindingDraft({ ...bindingDraft, channel_id: event.target.value })}>{(selectedDefinitionChannels.length === 0 ? [{ id: "default" }] : selectedDefinitionChannels).map((channel) => <option key={channel.id} value={channel.id}>{channel.id}</option>)}</select></label>
                <label>端点<select value={bindingDraft.endpoint_id} onChange={(event) => setBindingDraft({ ...bindingDraft, endpoint_id: event.target.value })} required><option value="">选择端点</option>{endpoints.map((endpoint) => <option key={endpoint.id} value={endpoint.id}>{endpoint.base_url}</option>)}</select></label>
                <label>凭据<select value={bindingDraft.credential_id} onChange={(event) => setBindingDraft({ ...bindingDraft, credential_id: event.target.value })} required><option value="">选择凭据</option>{credentials.map((credential) => <option key={credential.id} value={credential.id}>{credential.label}</option>)}</select></label>
                <label>模型限制（逗号分隔）<input value={bindingDraft.allowed_models_text} onChange={(event) => setBindingDraft({ ...bindingDraft, allowed_models_text: event.target.value })} placeholder="model_a, model_b" /></label>
                <label>优先级<input type="number" value={bindingDraft.priority} onChange={(event) => setBindingDraft({ ...bindingDraft, priority: Number(event.target.value) })} /></label>
                <label className="checkbox-label"><input type="checkbox" checked={bindingDraft.enabled ?? true} onChange={(event) => setBindingDraft({ ...bindingDraft, enabled: event.target.checked })} />启用绑定</label>
                <div className="form-actions"><button type="submit">{bindingDraft.editing_id === "" ? "添加绑定" : "保存绑定"}</button><button type="button" className="secondary" onClick={() => setBindingDraft(emptyBindingDraft)}>清空</button></div>
              </form>
            </section>

            <section className="subpanel">
              <h3>自定义模型目录</h3>
              {!selectedInstanceIsCustom ? <p className="empty-state">系统供应商目录由对应 Adapter 维护，不能从此处编辑。</p> : <>
                <p className="hint">完整替换当前自定义模型、通道产品与执行规格。服务端会严格校验 ID、通道、能力与关联关系；此处不包含任何 Secret。</p>
                <label>目录 JSON
                  <textarea className="catalog-editor" value={customCatalogText} onChange={(event) => setCustomCatalogText(event.target.value)} spellCheck={false} aria-label="自定义模型目录 JSON" />
                </label>
                <div className="form-actions"><button type="button" onClick={saveCustomCatalog}>保存目录</button><button type="button" className="secondary" onClick={loadCustomCatalog}>加载已保存目录</button><button type="button" className="secondary" onClick={writeCustomCatalogTemplate}>写入示例</button><button type="button" className="secondary" onClick={() => setCustomCatalogText(formatCustomCatalogDocument(emptyCustomCatalogDocument()))}>清空编辑器</button></div>
              </>}
            </section>

            <section className="subpanel">
              <h3>模型本地启停</h3>
              {catalog === null ? <p className="empty-state">尚未发布该实例的模型目录。</p> : <div className="resource-list compact">{catalog.models.map((model) => <article className="resource-row" key={model.id}><div><strong>{model.display_name}</strong><span><code>{model.id}</code> · {model.upstream_model_id} · {model.enabled ? "已启用" : "已禁用"}</span></div><button type="button" className="secondary" onClick={() => void runAction(model.enabled ? "已禁用模型。" : "已启用模型。", async () => client.setModelEnabled(selectedInstanceID, model, !model.enabled))}>{model.enabled ? "禁用" : "启用"}</button></article>)}</div>}
            </section>
          </div>
        )}
      </section>

      <section className="panel" aria-labelledby="api-key-title">
        <div className="section-title">
          <div>
            <p className="eyebrow">5. CALL-PLANE KEYS</p>
            <h2 id="api-key-title">调用 API 密钥</h2>
          </div>
          <p>仅管理接口可查看；调用端使用 <code>Authorization: Bearer &lt;key&gt;</code> 访问 <code>/vulcan/v1</code>。</p>
        </div>
        <div className="resource-list">
          {apiKeys.map((apiKey) => <article className="resource-row" key={apiKey.id}><div><strong>{apiKey.name}</strong><span><code>{apiKey.id}</code> · {apiKey.enabled ? "已启用" : "已禁用"} · <code>{apiKey.key}</code></span></div><div className="row-actions"><button type="button" className="secondary" onClick={() => beginAPIKeyEdit(apiKey)}>编辑</button><button type="button" className="danger" onClick={() => void runAction("已删除调用 API 密钥。", async () => client.deleteAPIKey(apiKey.id))}>删除</button></div></article>)}
        </div>
        <form className="form-grid" onSubmit={submitAPIKey}>
          <h3>{apiKeyDraft.editing_id === "" ? "新增调用 API 密钥" : `编辑 ${apiKeyDraft.editing_id}`}</h3>
          <label>名称<input value={apiKeyDraft.name} onChange={(event) => setAPIKeyDraft({ ...apiKeyDraft, name: event.target.value })} required /></label>
          <label>明文密钥<input type="text" value={apiKeyDraft.key} onChange={(event) => setAPIKeyDraft({ ...apiKeyDraft, key: event.target.value })} required /></label>
          <label className="checkbox-label"><input type="checkbox" checked={apiKeyDraft.enabled} onChange={(event) => setAPIKeyDraft({ ...apiKeyDraft, enabled: event.target.checked })} />立即启用</label>
          <div className="form-actions"><button type="submit">{apiKeyDraft.editing_id === "" ? "创建调用密钥" : "保存调用密钥"}</button><button type="button" className="secondary" onClick={() => setAPIKeyDraft(emptyAPIKeyDraft)}>清空</button></div>
        </form>
      </section>
    </main>
  );
}
