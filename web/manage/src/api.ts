import type {
  AccessBinding,
  APIKey,
  CatalogModel,
  Credential,
	CustomCatalogDocument,
  Endpoint,
  ProtocolProfile,
  ProviderCatalog,
  ProviderDefinition,
  ProviderInstance
} from "./types";

// IdentifierResponse is the non-secret result returned after a management resource is created or changed.
// IdentifierResponse 是管理资源创建或变更后返回的非秘密结果。
interface IdentifierResponse {
  /** ID is the immutable resource identifier. */
  /** ID 是不可变资源标识。 */
  id: string;
}

// ProtocolProfileListResponse is the wire envelope for registered protocol metadata.
// ProtocolProfileListResponse 是已注册协议元数据的 Wire 包装。
interface ProtocolProfileListResponse {
  /** ProtocolProfiles contains immutable process-owned profiles. */
  /** ProtocolProfiles 包含不可变的进程拥有 Profile。 */
  protocol_profiles: ProtocolProfile[];
}

// ProviderDefinitionListResponse is the wire envelope for provider definitions.
// ProviderDefinitionListResponse 是供应商定义的 Wire 包装。
interface ProviderDefinitionListResponse {
  /** ProviderDefinitions contains system and custom definition views. */
  /** ProviderDefinitions 包含系统和自定义定义视图。 */
  provider_definitions: ProviderDefinition[];
}

// ProviderInstanceListResponse is the wire envelope for provider instances.
// ProviderInstanceListResponse 是供应商实例的 Wire 包装。
interface ProviderInstanceListResponse {
  /** ProviderInstances contains management-safe instance views. */
  /** ProviderInstances 包含管理安全实例视图。 */
  provider_instances: ProviderInstance[];
}

// EndpointListResponse is the wire envelope for upstream endpoints.
// EndpointListResponse 是上游端点的 Wire 包装。
interface EndpointListResponse {
  /** Endpoints contains management-safe endpoint views. */
  /** Endpoints 包含管理安全端点视图。 */
  endpoints: Endpoint[];
}

// CredentialListResponse is the wire envelope for redacted credential metadata.
// CredentialListResponse 是已脱敏凭据元数据的 Wire 包装。
interface CredentialListResponse {
  /** Credentials contains no upstream secret material. */
  /** Credentials 不包含上游 Secret 材料。 */
  credentials: Credential[];
}

// BindingListResponse is the wire envelope for access bindings.
// BindingListResponse 是访问绑定的 Wire 包装。
interface BindingListResponse {
  /** Bindings contains credential-to-endpoint relationships. */
  /** Bindings 包含凭据到端点关系。 */
  bindings: AccessBinding[];
}

// APIKeyListResponse is the management-only wire envelope for call-plane keys.
// APIKeyListResponse 是调用面密钥的仅管理面 Wire 包装。
interface APIKeyListResponse {
  /** APIKeys contains plaintext key values after management authorization. */
  /** APIKeys 在管理授权后包含明文密钥值。 */
  api_keys: APIKey[];
}

// CreateDefinitionRequest is the explicit custom provider definition creation payload.
// CreateDefinitionRequest 是显式自定义供应商定义创建载荷。
export interface CreateDefinitionRequest {
  /** ID optionally supplies a stable custom_ identifier. */
  /** ID 可选提供稳定的 custom_ 标识。 */
  id: string;
  /** DisplayName is the management-facing provider name. */
  /** DisplayName 是管理界面供应商名称。 */
  display_name: string;
  /** ProtocolProfileID selects an allowed protocol profile. */
  /** ProtocolProfileID 选择允许的协议 Profile。 */
  protocol_profile_id: string;
  /** AuthMethod selects an allowed generic authentication mechanism. */
  /** AuthMethod 选择允许的通用认证机制。 */
  auth_method: string;
}

// CreateInstanceRequest is the explicit provider instance creation payload.
// CreateInstanceRequest 是显式供应商实例创建载荷。
export interface CreateInstanceRequest {
  /** ID optionally supplies a stable pvi_ identifier. */
  /** ID 可选提供稳定的 pvi_ 标识。 */
  id: string;
  /** DefinitionID selects the owning provider definition. */
  /** DefinitionID 选择所属供应商定义。 */
  definition_id: string;
  /** Handle is the workspace-visible routing alias. */
  /** Handle 是工作区可见路由别名。 */
  handle: string;
  /** DisplayName is the management-facing instance label. */
  /** DisplayName 是管理界面实例名称。 */
  display_name: string;
}

// EndpointRequest is the complete upstream endpoint create or edit payload.
// EndpointRequest 是完整上游端点创建或编辑载荷。
export interface EndpointRequest {
  /** ID is used only during endpoint creation. */
  /** ID 仅在端点创建时使用。 */
  id?: string;
  /** ChannelID selects the exact provider channel. */
  /** ChannelID 选择精确供应商通道。 */
  channel_id: string;
  /** BaseURL is the validated upstream base URL. */
  /** BaseURL 是已校验上游基础 URL。 */
  base_url: string;
  /** Region is an optional provider-defined location label. */
  /** Region 是可选供应商定义位置标签。 */
  region: string;
  /** Status is required only while editing an existing endpoint. */
  /** Status 仅在编辑既有端点时必填。 */
  status?: string;
}

// CredentialRequest is the non-secret metadata and transient secret payload for credential creation.
// CredentialRequest 是凭据创建所需的非秘密元数据和临时 Secret 载荷。
export interface CredentialRequest {
  /** ID optionally supplies a stable cred_ identifier. */
  /** ID 可选提供稳定的 cred_ 标识。 */
  id?: string;
  /** AuthMethodID selects the declared provider authentication method. */
  /** AuthMethodID 选择已声明供应商认证方式。 */
  auth_method_id: string;
  /** Label is the management-facing credential label. */
  /** Label 是管理界面凭据名称。 */
  label: string;
  /** PrincipalKey is optional upstream account metadata. */
  /** PrincipalKey 是可选上游账号元数据。 */
  principal_key: string;
  /** Fingerprint is the irreversible duplicate-detection value. */
  /** Fingerprint 是不可逆排重值。 */
  fingerprint: string;
  /** ScopeRefs contains optional typed commercial scope references. */
  /** ScopeRefs 包含可选的类型化商业范围引用。 */
  scope_refs: never[];
  /** Secret contains transient upstream credential bytes. */
  /** Secret 包含临时上游凭据字节。 */
  secret: string;
}

// CredentialMetadataRequest is the editable non-secret credential payload.
// CredentialMetadataRequest 是可编辑的非秘密凭据载荷。
export interface CredentialMetadataRequest {
  /** Label is the replacement management-facing credential label. */
  /** Label 是替换后的管理界面凭据名称。 */
  label: string;
  /** PrincipalKey is the replacement optional upstream account metadata. */
  /** PrincipalKey 是替换后的可选上游账号元数据。 */
  principal_key: string;
  /** Fingerprint is the replacement duplicate-detection value. */
  /** Fingerprint 是替换后的排重值。 */
  fingerprint: string;
  /** ScopeRefs contains replacement typed commercial scope references. */
  /** ScopeRefs 包含替换后的类型化商业范围引用。 */
  scope_refs: never[];
}

// BindingRequest is the complete access-binding create or edit payload.
// BindingRequest 是完整访问绑定创建或编辑载荷。
export interface BindingRequest {
  /** ID is used only during binding creation. */
  /** ID 仅在绑定创建时使用。 */
  id?: string;
  /** ChannelID selects the exact provider channel. */
  /** ChannelID 选择精确供应商通道。 */
  channel_id: string;
  /** EndpointID identifies the linked same-instance endpoint. */
  /** EndpointID 标识关联的同实例端点。 */
  endpoint_id: string;
  /** CredentialID identifies the linked same-instance credential. */
  /** CredentialID 标识关联的同实例凭据。 */
  credential_id: string;
  /** AllowedModelIDs supplies explicit restrictions when non-empty. */
  /** AllowedModelIDs 非空时提供显式限制。 */
  allowed_model_ids: string[];
  /** Priority controls deterministic same-pool selection order. */
  /** Priority 控制确定性的同池选择顺序。 */
  priority: number;
  /** Enabled is required only while editing an existing binding. */
  /** Enabled 仅在编辑既有绑定时必填。 */
  enabled?: boolean;
}

// APIKeyRequest is the explicit plaintext call-plane key create or edit payload.
// APIKeyRequest 是显式明文调用面密钥创建或编辑载荷。
export interface APIKeyRequest {
  /** Name is the management-facing key label. */
  /** Name 是管理界面密钥名称。 */
  name: string;
  /** Key is the plaintext call-plane bearer value. */
  /** Key 是明文调用面 Bearer 值。 */
  key: string;
  /** Enabled controls immediate call-plane availability. */
  /** Enabled 控制即时调用面可用性。 */
  enabled: boolean;
}

// ControlPlaneRequestError reports a non-success management response without exposing an upstream response body.
// ControlPlaneRequestError 报告非成功管理响应且不暴露上游响应正文。
export class ControlPlaneRequestError extends Error {
  /** Status is the HTTP status returned by the local core. */
  /** Status 是本地核心返回的 HTTP 状态。 */
  readonly status: number;

  // constructor creates one non-sensitive request error.
  // constructor 创建一个非敏感请求错误。
  constructor(status: number) {
    super(`管理接口请求失败（HTTP ${status}）`);
    this.name = "ControlPlaneRequestError";
    this.status = status;
  }
}

// ManagementClient owns authenticated browser calls to the local management API only.
// ManagementClient 仅管理浏览器到本地管理 API 的认证调用。
export class ManagementClient {
  /** managementKey is held only in memory for the lifetime of this client. */
  /** managementKey 仅在此客户端生命周期内保存在内存中。 */
  private readonly managementKey: string;

  // constructor creates one memory-only management API client.
  // constructor 创建一个仅内存管理 API 客户端。
  constructor(managementKey: string) {
    this.managementKey = managementKey;
  }

  // listProtocolProfiles returns immutable protocol metadata available to custom providers.
  // listProtocolProfiles 返回自定义供应商可用的不可变协议元数据。
  async listProtocolProfiles(): Promise<ProtocolProfile[]> {
    const response = await this.request<ProtocolProfileListResponse>("/vulcan/manage/protocol-profiles");
    return response.protocol_profiles;
  }

  // listDefinitions returns system and custom provider definitions.
  // listDefinitions 返回系统和自定义供应商定义。
  async listDefinitions(): Promise<ProviderDefinition[]> {
    const response = await this.request<ProviderDefinitionListResponse>("/vulcan/manage/provider-definitions");
    return response.provider_definitions;
  }

  // createDefinition persists one typed custom provider definition.
  // createDefinition 持久化一个类型化自定义供应商定义。
  async createDefinition(payload: CreateDefinitionRequest): Promise<string> {
    const response = await this.request<IdentifierResponse>("/vulcan/manage/provider-definitions", "POST", payload);
    return response.id;
  }

  // updateDefinition replaces one editable custom provider definition.
  // updateDefinition 替换一个可编辑自定义供应商定义。
  async updateDefinition(definitionID: string, payload: Omit<CreateDefinitionRequest, "id">): Promise<void> {
    await this.request<IdentifierResponse>(`/vulcan/manage/provider-definitions/${encodeURIComponent(definitionID)}`, "PUT", payload);
  }

  // listInstances returns all management-safe provider instance views.
  // listInstances 返回全部管理安全供应商实例视图。
  async listInstances(): Promise<ProviderInstance[]> {
    const response = await this.request<ProviderInstanceListResponse>("/vulcan/manage/provider-instances");
    return response.provider_instances;
  }

  // createInstance persists one provider instance in draft state.
  // createInstance 以草稿状态持久化一个供应商实例。
  async createInstance(payload: CreateInstanceRequest): Promise<string> {
    const response = await this.request<IdentifierResponse>("/vulcan/manage/provider-instances", "POST", payload);
    return response.id;
  }

  // updateInstance replaces editable provider instance identity fields.
  // updateInstance 替换可编辑供应商实例身份字段。
  async updateInstance(instanceID: string, handle: string, displayName: string): Promise<void> {
    await this.request<IdentifierResponse>(`/vulcan/manage/provider-instances/${encodeURIComponent(instanceID)}`, "PUT", {
      handle,
      display_name: displayName
    });
  }

  // setInstanceEnabled validates or disables one provider instance.
  // setInstanceEnabled 校验后启用或禁用一个供应商实例。
  async setInstanceEnabled(instanceID: string, enabled: boolean): Promise<void> {
    await this.request<IdentifierResponse>(`/vulcan/manage/provider-instances/${encodeURIComponent(instanceID)}/enabled`, "PUT", { enabled });
  }

  // getCatalog returns one instance-scoped safe model catalog.
  // getCatalog 返回一个实例作用域安全模型目录。
  async getCatalog(instanceID: string): Promise<ProviderCatalog> {
    return this.request<ProviderCatalog>(`/vulcan/manage/provider-instances/${encodeURIComponent(instanceID)}/catalog`);
  }

  // getCustomCatalog returns the full editable catalog document for one custom provider instance.
  // getCustomCatalog 返回一个自定义供应商实例完整可编辑的目录文档。
  async getCustomCatalog(instanceID: string): Promise<CustomCatalogDocument> {
    return this.request<CustomCatalogDocument>(`/vulcan/manage/provider-instances/${encodeURIComponent(instanceID)}/custom-catalog`);
  }

  // saveCustomCatalog atomically replaces the complete custom-provider catalog document.
  // saveCustomCatalog 原子替换完整的自定义供应商目录文档。
  async saveCustomCatalog(instanceID: string, document: CustomCatalogDocument): Promise<CustomCatalogDocument> {
    return this.request<CustomCatalogDocument>(`/vulcan/manage/provider-instances/${encodeURIComponent(instanceID)}/custom-catalog`, "PUT", document);
  }

  // setModelEnabled changes one exact local model policy.
  // setModelEnabled 更改一个精确本地模型策略。
  async setModelEnabled(instanceID: string, model: CatalogModel, enabled: boolean): Promise<void> {
    await this.request<IdentifierResponse>(`/vulcan/manage/provider-instances/${encodeURIComponent(instanceID)}/models/${encodeURIComponent(model.id)}/enabled`, "PUT", { enabled });
  }

  // listEndpoints returns endpoints owned by one exact provider instance.
  // listEndpoints 返回一个精确供应商实例拥有的端点。
  async listEndpoints(instanceID: string): Promise<Endpoint[]> {
    const response = await this.request<EndpointListResponse>(`/vulcan/manage/provider-instances/${encodeURIComponent(instanceID)}/endpoints`);
    return response.endpoints;
  }

  // createEndpoint persists one upstream endpoint.
  // createEndpoint 持久化一个上游端点。
  async createEndpoint(instanceID: string, payload: EndpointRequest): Promise<string> {
    const createPayload = {
      id: payload.id ?? "",
      channel_id: payload.channel_id,
      base_url: payload.base_url,
      region: payload.region
    };
    const response = await this.request<IdentifierResponse>(`/vulcan/manage/provider-instances/${encodeURIComponent(instanceID)}/endpoints`, "POST", createPayload);
    return response.id;
  }

  // updateEndpoint replaces every editable endpoint field.
  // updateEndpoint 替换全部可编辑端点字段。
  async updateEndpoint(instanceID: string, endpointID: string, payload: EndpointRequest): Promise<void> {
    const updatePayload = {
      channel_id: payload.channel_id,
      base_url: payload.base_url,
      region: payload.region,
      status: payload.status ?? "ready"
    };
    await this.request<IdentifierResponse>(`/vulcan/manage/provider-instances/${encodeURIComponent(instanceID)}/endpoints/${encodeURIComponent(endpointID)}`, "PUT", updatePayload);
  }

  // listCredentials returns redacted credential metadata owned by one instance.
  // listCredentials 返回一个实例拥有的已脱敏凭据元数据。
  async listCredentials(instanceID: string): Promise<Credential[]> {
    const response = await this.request<CredentialListResponse>(`/vulcan/manage/provider-instances/${encodeURIComponent(instanceID)}/credentials`);
    return response.credentials;
  }

  // createCredential persists metadata and transient upstream secret bytes.
  // createCredential 持久化元数据和临时上游 Secret 字节。
  async createCredential(instanceID: string, payload: CredentialRequest): Promise<string> {
    const response = await this.request<IdentifierResponse>(`/vulcan/manage/provider-instances/${encodeURIComponent(instanceID)}/credentials`, "POST", payload);
    return response.id;
  }

  // updateCredential replaces non-secret credential metadata.
  // updateCredential 替换非秘密凭据元数据。
  async updateCredential(instanceID: string, credentialID: string, payload: CredentialMetadataRequest): Promise<void> {
    await this.request<IdentifierResponse>(`/vulcan/manage/provider-instances/${encodeURIComponent(instanceID)}/credentials/${encodeURIComponent(credentialID)}`, "PUT", payload);
  }

  // rotateCredentialSecret replaces one protected upstream credential secret.
  // rotateCredentialSecret 替换一个受保护上游凭据 Secret。
  async rotateCredentialSecret(instanceID: string, credentialID: string, secret: string, fingerprint: string): Promise<void> {
    await this.request<IdentifierResponse>(`/vulcan/manage/provider-instances/${encodeURIComponent(instanceID)}/credentials/${encodeURIComponent(credentialID)}/secret`, "PUT", { secret, fingerprint });
  }

  // setCredentialStatus changes one credential lifecycle status.
  // setCredentialStatus 更改一个凭据生命周期状态。
  async setCredentialStatus(instanceID: string, credentialID: string, status: string, coolingUntil: string): Promise<void> {
    const cooling_until = coolingUntil === "" ? null : new Date(coolingUntil).toISOString();
    await this.request<IdentifierResponse>(`/vulcan/manage/provider-instances/${encodeURIComponent(instanceID)}/credentials/${encodeURIComponent(credentialID)}/status`, "PUT", {
      status,
      cooling_until
    });
  }

  // listBindings returns access bindings owned by one instance.
  // listBindings 返回一个实例拥有的访问绑定。
  async listBindings(instanceID: string): Promise<AccessBinding[]> {
    const response = await this.request<BindingListResponse>(`/vulcan/manage/provider-instances/${encodeURIComponent(instanceID)}/bindings`);
    return response.bindings;
  }

  // createBinding persists one credential-to-endpoint binding.
  // createBinding 持久化一条凭据到端点绑定。
  async createBinding(instanceID: string, payload: BindingRequest): Promise<string> {
    const createPayload = {
      id: payload.id ?? "",
      channel_id: payload.channel_id,
      endpoint_id: payload.endpoint_id,
      credential_id: payload.credential_id,
      allowed_model_ids: payload.allowed_model_ids,
      priority: payload.priority
    };
    const response = await this.request<IdentifierResponse>(`/vulcan/manage/provider-instances/${encodeURIComponent(instanceID)}/bindings`, "POST", createPayload);
    return response.id;
  }

  // updateBinding replaces every editable binding field.
  // updateBinding 替换全部可编辑绑定字段。
  async updateBinding(instanceID: string, bindingID: string, payload: BindingRequest): Promise<void> {
    const updatePayload = {
      channel_id: payload.channel_id,
      endpoint_id: payload.endpoint_id,
      credential_id: payload.credential_id,
      allowed_model_ids: payload.allowed_model_ids,
      priority: payload.priority,
      enabled: payload.enabled ?? true
    };
    await this.request<IdentifierResponse>(`/vulcan/manage/provider-instances/${encodeURIComponent(instanceID)}/bindings/${encodeURIComponent(bindingID)}`, "PUT", updatePayload);
  }

  // listAPIKeys returns management-authorized plaintext call-plane keys.
  // listAPIKeys 返回经管理授权的明文调用面密钥。
  async listAPIKeys(): Promise<APIKey[]> {
    const response = await this.request<APIKeyListResponse>("/vulcan/manage/api-keys");
    return response.api_keys;
  }

  // createAPIKey persists one explicit plaintext call-plane key.
  // createAPIKey 持久化一个显式明文调用面密钥。
  async createAPIKey(payload: APIKeyRequest): Promise<APIKey> {
    return this.request<APIKey>("/vulcan/manage/api-keys", "POST", payload);
  }

  // updateAPIKey replaces one existing call-plane key.
  // updateAPIKey 替换一个既有调用面密钥。
  async updateAPIKey(identifier: string, payload: APIKeyRequest): Promise<APIKey> {
    return this.request<APIKey>(`/vulcan/manage/api-keys/${encodeURIComponent(identifier)}`, "PUT", payload);
  }

  // deleteAPIKey removes one existing call-plane key.
  // deleteAPIKey 删除一个既有调用面密钥。
  async deleteAPIKey(identifier: string): Promise<void> {
    await this.request<void>(`/vulcan/manage/api-keys/${encodeURIComponent(identifier)}`, "DELETE");
  }

  // request sends one strict JSON request with only the management Bearer credential namespace.
  // request 仅使用管理 Bearer 凭据命名空间发送一条严格 JSON 请求。
  private async request<Response>(path: string, method = "GET", body?: object): Promise<Response> {
    const response = await fetch(path, {
      method,
      headers: {
        Authorization: `Bearer ${this.managementKey}`,
        ...(body === undefined ? {} : { "Content-Type": "application/json" })
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) })
    });
    if (!response.ok) {
      throw new ControlPlaneRequestError(response.status);
    }
    if (response.status === 204) {
      return undefined as Response;
    }
    return (await response.json()) as Response;
  }
}

// splitModelIDs converts a comma-separated form value into exact non-empty model identifiers.
// splitModelIDs 将逗号分隔表单值转换为精确的非空模型标识。
export function splitModelIDs(value: string): string[] {
  return value
    .split(",")
    .map((candidate) => candidate.trim())
    .filter((candidate) => candidate !== "");
}
