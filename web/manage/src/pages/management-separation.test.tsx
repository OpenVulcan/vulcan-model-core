import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { I18nProvider } from "@/i18n";
import { CredentialManagementPage } from "@/pages/credential-management-page";
import { ProviderConfigurationPage } from "@/pages/provider-configuration-page";

// unavailableFeatures supplies one explicit no-reader contract for the test provider.
// unavailableFeatures 为测试供应商提供一个显式无读取器合同。
const unavailableFeatures = {
  model_discovery: "unsupported",
  plan_reader: "unsupported",
  entitlement_reader: "unsupported",
  allowance_reader: "unsupported",
};

// definition is the exact native provider metadata shared by both separated-page tests.
// definition 是两个拆分页面测试共用的精确原生供应商元数据。
const definition = {
  id: "system_test_provider",
  display_name: "Test Provider",
  group_id: "test",
  variant_name: "Global",
  variant_description: "Global test endpoint.",
  model_catalog_id: "test_catalog",
  protocol_profile_id: "openai.chat",
  endpoint_presets: [
    {
      id: "global",
      base_url: "https://provider.example/v1",
      region: "Global",
      user_editable: false,
      parameters: [],
    },
  ],
  auth_methods: [
    {
      id: "api_key",
      type: "api_key",
      refreshable: false,
      multiple_credentials: true,
      plan_acquisition: "unavailable",
    },
  ],
  plan_options: [],
  features: unavailableFeatures,
};

// instance is one credential-independent provider configuration fixture.
// instance 是一个独立于凭据的供应商配置夹具。
const instance = {
  id: "pvi_test_provider",
  definition_id: definition.id,
  handle: "test-provider",
  display_name: "Test Production",
  status: "ready",
  routing_strategy: "",
  disabled_model_ids: [],
  endpoint_count: 1,
  credential_count: 1,
  binding_count: 1,
  revision: 2,
};

// jsonResponse creates one deterministic JSON management response.
// jsonResponse 创建一个确定性的 JSON 管理响应。
function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

// commonReadResponse returns the exact management payload for a known read route.
// commonReadResponse 为一个已知读取路由返回精确管理 Payload。
function commonReadResponse(url: string): Response | null {
  if (url.endsWith("/provider-groups")) {
    return jsonResponse({
      provider_groups: [
        {
          id: "test",
          display_name: "Test",
          description: "Native test providers.",
          provider_definitions: [definition],
        },
      ],
    });
  }
  if (url.endsWith("/provider-definitions")) {
    return jsonResponse({
      provider_definitions: [
        {
          id: definition.id,
          kind: "system",
          display_name: definition.display_name,
          protocol_profile_id: definition.protocol_profile_id,
          auth_methods: definition.auth_methods,
          plan_options: [],
          features: unavailableFeatures,
        },
      ],
    });
  }
  if (url.endsWith("/protocol-profiles")) {
    return jsonResponse({
      protocol_profiles: [{
        id: "openai.chat",
        version: "1",
        display_name: "OpenAI Chat Completions",
        user_configurable: true,
        runtime_ready: true,
        model_discovery: "unsupported",
        capabilities: [],
        allowed_auth_methods: ["bearer"],
      }],
    });
  }
  if (url.endsWith("/provider-instances")) {
    return jsonResponse({ provider_instances: [instance] });
  }
  return null;
}

describe("separated provider and credential management", () => {
  afterEach(() => vi.unstubAllGlobals());

  // This test verifies provider creation exposes protocols rather than native system definitions.
  // 此测试验证供应商创建公开协议而不是原生系统定义。
  it("offers exactly three standard protocols when adding a provider", async () => {
    // fetchMock serves the inventory and records the exact provider-only creation payload.
    // fetchMock 提供供应商清单并记录精确的仅供应商创建载荷。
    const fetchMock = vi.fn().mockImplementation(
      (input: string | URL | Request, init?: RequestInit) => {
        const url = String(input);
        const method = init?.method ?? (input instanceof Request ? input.method : "GET");
        if (url.endsWith("/provider-groups")) {
          return Promise.resolve(jsonResponse({
            provider_groups: [{
              id: "test",
              display_name: "Test",
              description: "Native test providers.",
              provider_definitions: [definition],
            }],
          }));
        }
        if (url.endsWith("/provider-definitions")) {
          if (method === "POST") {
            return Promise.resolve(jsonResponse({ id: "custom_deepseek" }, 201));
          }
          return Promise.resolve(jsonResponse({ provider_definitions: [] }));
        }
        if (url.endsWith("/provider-configurations") && method === "POST") {
          return Promise.resolve(jsonResponse({
            provider_instance_id: "pvi_deepseek",
            endpoint_ids: ["ep_deepseek"],
          }, 201));
        }
        if (
          url.endsWith("/provider-instances/pvi_deepseek/credentials/attach") &&
          method === "POST"
        ) {
          return Promise.resolve(jsonResponse({
            provider_instance_id: "pvi_deepseek",
            credential_id: "cred_deepseek",
            endpoint_ids: [],
            binding_ids: ["bind_deepseek"],
          }, 201));
        }
        if (url.endsWith("/provider-instances")) {
          return Promise.resolve(jsonResponse({ provider_instances: [] }));
        }
        if (url.endsWith("/protocol-profiles")) {
          return Promise.resolve(jsonResponse({
            protocol_profiles: [
              { id: "openai.chat", version: "1", display_name: "OpenAI Chat Completions", user_configurable: true, runtime_ready: true, model_discovery: "unsupported", capabilities: [], allowed_auth_methods: ["bearer"] },
              { id: "openai.responses", version: "1", display_name: "OpenAI Responses", user_configurable: true, runtime_ready: true, model_discovery: "unsupported", capabilities: [], allowed_auth_methods: ["bearer"] },
              { id: "anthropic.messages", version: "1", display_name: "Anthropic Messages", user_configurable: true, runtime_ready: true, model_discovery: "unsupported", capabilities: [], allowed_auth_methods: ["header_api_key"] },
              { id: "google.aistudio", version: "1", display_name: "Google AI Studio", user_configurable: true, runtime_ready: true, model_discovery: "unsupported", capabilities: [], allowed_auth_methods: ["header_api_key"] },
            ],
          }));
        }
        return Promise.resolve(jsonResponse({ error: "not_found" }, 404));
      },
    );
    vi.stubGlobal("fetch", fetchMock);
    render(
      <I18nProvider>
        <ProviderConfigurationPage managementAuthToken="management-token" />
      </I18nProvider>,
    );

    await screen.findByText("Native providers");
    fireEvent.click(screen.getByRole("button", { name: "Add provider" }));
    // protocolCombobox must start from the product-default OpenAI Chat profile.
    // protocolCombobox 必须从产品默认的 OpenAI Chat Profile 开始。
    const protocolCombobox = screen.getAllByRole("combobox")[0];

    expect(protocolCombobox).toHaveValue("OpenAI Chat Completions");
    expect(screen.queryByLabelText("Upstream model ID")).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Model display name")).not.toBeInTheDocument();

    fireEvent.click(protocolCombobox);

    expect(screen.getAllByRole("option")).toHaveLength(3);
    expect(screen.getByRole("option", { name: "OpenAI Chat Completions" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "OpenAI Responses" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "Anthropic Messages" })).toBeInTheDocument();
    expect(screen.queryByRole("option", { name: "Google AI Studio" })).not.toBeInTheDocument();
    expect(screen.queryByRole("option", { name: /Test Provider/ })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("option", { name: "OpenAI Chat Completions" }));
    fireEvent.change(screen.getByLabelText("Provider name"), {
      target: { value: "DeepSeek" },
    });
    fireEvent.change(screen.getByLabelText("Provider handle"), {
      target: { value: "deepseek" },
    });
    fireEvent.change(screen.getByLabelText("API endpoint URL"), {
      target: { value: "https://api.deepseek.com/v1" },
    });
    fireEvent.change(screen.getByLabelText("API key (optional)"), {
      target: { value: "sk-deepseek-test" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Create provider" }));

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        "/vulcan/manage/provider-configurations",
        expect.objectContaining({ method: "POST" }),
      );
    });

    // configurationCall contains the credential-independent first-level provider payload.
    // configurationCall 包含独立于凭据的供应商一级创建载荷。
    const configurationCall = fetchMock.mock.calls.find(
      ([input, init]) =>
        String(input).endsWith("/provider-configurations") && init?.method === "POST",
    );
    // configurationPayload must not create any model-level state during provider creation.
    // configurationPayload 在供应商创建阶段不得创建任何模型级状态。
    const configurationPayload = JSON.parse(String(configurationCall?.[1]?.body));

    expect(configurationPayload).toEqual({
      provider_definition_id: "custom_deepseek",
      display_name: "DeepSeek",
      handle: "deepseek",
      base_url: "https://api.deepseek.com/v1",
    });
    expect(configurationPayload).not.toHaveProperty("initial_model");
    expect(configurationPayload).not.toHaveProperty("secret");
    expect(fetchMock).toHaveBeenCalledWith(
      "/vulcan/manage/provider-instances/pvi_deepseek/credentials/attach",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({
          auth_method_id: "default",
          label: "DeepSeek",
          secret: "sk-deepseek-test",
        }),
      }),
    );
  });

  // This test verifies provider management renders only definitions, endpoints, catalogs, and credential counts.
  // 此测试验证供应商管理仅渲染定义、入口、目录与凭据计数。
  it("renders the provider-only inventory", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation((input: string | URL | Request) => {
        const url = String(input);
        if (url.endsWith("/provider-definitions")) {
          return Promise.resolve(jsonResponse({
            provider_definitions: [{
              id: definition.id,
              kind: "custom",
              display_name: definition.display_name,
              protocol_profile_id: definition.protocol_profile_id,
              auth_methods: definition.auth_methods,
              plan_options: [],
              features: unavailableFeatures,
            }],
          }));
        }
        const common = commonReadResponse(url);
        if (common) return Promise.resolve(common);
        if (url.endsWith(`/provider-instances/${instance.id}/credentials`)) {
          return Promise.resolve(jsonResponse({ credentials: [] }));
        }
        if (url.endsWith(`/provider-instances/${instance.id}/endpoints`)) {
          return Promise.resolve(
            jsonResponse({
              endpoints: [
                {
                  id: "ep_test_provider",
                  provider_instance_id: instance.id,
                  base_url: "https://provider.example/v1",
                  region: "Global",
                  parameters: [],
                  status: "ready",
                  revision: 1,
                },
              ],
            }),
          );
        }
        if (url.endsWith(`/provider-instances/${instance.id}/catalog`)) {
          return Promise.resolve(
            jsonResponse({
              provider_instance_id: instance.id,
              models: [
                {
                  id: "model_test",
                  upstream_model_id: "test-model",
                  display_name: "Test Model",
                  entitlement_mode: "all_bound_credentials",
                  enabled: true,
                  authorization_status: "authorized",
                },
              ],
              plans: [],
              allowances: [],
              revision: 1,
              observed_at: "2026-07-21T07:00:00Z",
            }),
          );
        }
        return Promise.resolve(jsonResponse({ error: "not_found" }, 404));
      }),
    );
    render(
      <I18nProvider>
        <ProviderConfigurationPage managementAuthToken="management-token" />
      </I18nProvider>,
    );

    expect(await screen.findByText("Native providers")).toBeInTheDocument();
    expect(await screen.findByText("Test Production")).toBeInTheDocument();
    expect(screen.getByText("https://provider.example/v1")).toBeInTheDocument();
    const configuredRow = screen.getByText("Test Production").closest("tr");
    expect(configuredRow).not.toBeNull();
    const configuredRowQueries = within(configuredRow as HTMLTableRowElement);
    expect(configuredRowQueries.getByText("Custom")).toHaveAttribute("data-slot", "badge");
    expect(configuredRowQueries.getByText("OpenAI Chat Completions")).toBeInTheDocument();
    expect(configuredRowQueries.getByText("Models: 1")).toBeInTheDocument();
    expect(configuredRowQueries.getByText("Credentials: 1")).toBeInTheDocument();
    expect(configuredRowQueries.getByText("Ready")).toHaveAttribute("data-slot", "badge");
    expect(screen.queryByText("Test Model")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Configure Test Production" }));
    expect(screen.getByText("Test Model")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Edit models" }));
    expect(screen.getByRole("heading", { name: "Edit models" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.getByRole("heading", { name: "Test Production" })).toBeInTheDocument();
    expect(screen.queryByText("Authorizations")).not.toBeInTheDocument();
  });

  // This test verifies a native provider row attaches a credential to its existing configuration instead of cloning the provider.
  // 此测试验证原生供应商行将凭据附加到既有配置，而不是克隆供应商。
  it("attaches a credential to the existing native provider configuration", async () => {
    const fetchMock = vi.fn().mockImplementation(
      (input: string | URL | Request, init?: RequestInit) => {
        const url = String(input);
        const method = init?.method ?? (input instanceof Request ? input.method : "GET");
        if (url.endsWith("/provider-instances")) {
          return Promise.resolve(jsonResponse({ provider_instances: [instance] }));
        }
        if (url.endsWith(`/provider-instances/${instance.id}/endpoints`)) {
          return Promise.resolve(jsonResponse({
            endpoints: [{
              id: "ep_test_provider",
              provider_instance_id: instance.id,
              base_url: "https://provider.example/v1",
              region: "Global",
              parameters: [],
              status: "ready",
              revision: 1,
            }],
          }));
        }
        if (url.endsWith(`/provider-instances/${instance.id}/credentials/attach`) && method === "POST") {
          return Promise.resolve(jsonResponse({
            provider_instance_id: instance.id,
            credential_id: "cred_native_test",
            endpoint_ids: [],
            binding_ids: ["bind_native_test"],
          }, 201));
        }
        const common = commonReadResponse(url);
        if (common) return Promise.resolve(common);
        return Promise.resolve(jsonResponse({ error: "not_found" }, 404));
      },
    );
    vi.stubGlobal("fetch", fetchMock);
    render(
      <I18nProvider>
        <ProviderConfigurationPage managementAuthToken="management-token" />
      </I18nProvider>,
    );

    await screen.findByText("Native providers");
    fireEvent.click(screen.getByRole("button", { name: "New credential Test" }));
    expect(screen.getByRole("heading", { name: "Add provider credential" })).toBeInTheDocument();
    expect(screen.getAllByRole("combobox")[0]).toHaveValue("Global");
    expect(screen.getAllByRole("combobox")[1]).toHaveValue("Test Production · test-provider");
    fireEvent.change(screen.getByLabelText("Credential name"), {
      target: { value: "Primary test key" },
    });
    fireEvent.change(screen.getByLabelText("API key"), {
      target: { value: "test-native-secret" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add credential" }));

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        `/vulcan/manage/provider-instances/${instance.id}/credentials/attach`,
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({
            auth_method_id: "api_key",
            label: "Primary test key",
            secret: "test-native-secret",
          }),
        }),
      );
    });
    expect(fetchMock.mock.calls.some(([input]) => String(input).endsWith("/provider-configurations"))).toBe(false);
    expect(fetchMock.mock.calls.some(([input]) => String(input).endsWith("/provider-instances/onboard"))).toBe(false);
  });

  // This test verifies credential management selects an existing provider and uses the attachment endpoint.
  // 此测试验证凭据管理选择既有供应商并使用附加接口。
  it("attaches a credential to the selected provider instance", async () => {
    const fetchMock = vi.fn().mockImplementation(
      (input: string | URL | Request, init?: RequestInit) => {
        const url = String(input);
        const common = commonReadResponse(url);
        if (common) return Promise.resolve(common);
        if (url.endsWith(`/provider-instances/${instance.id}/credentials`)) {
          return Promise.resolve(jsonResponse({ credentials: [] }));
        }
        if (
          url.endsWith(
            `/provider-instances/${instance.id}/credentials/attach`,
          ) && init?.method === "POST"
        ) {
          return Promise.resolve(
            jsonResponse(
              {
                provider_instance_id: instance.id,
                credential_id: "cred_attached",
                endpoint_ids: [],
                binding_ids: ["bind_attached"],
              },
              201,
            ),
          );
        }
        return Promise.resolve(jsonResponse({ error: "not_found" }, 404));
      },
    );
    vi.stubGlobal("fetch", fetchMock);
    render(
      <I18nProvider>
        <CredentialManagementPage managementAuthToken="management-token" />
      </I18nProvider>,
    );

    expect(await screen.findByRole("tree", { name: "Credential Management" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Add credential" }));
    fireEvent.click(screen.getByRole("button", { name: "Select Global" }));
    fireEvent.change(screen.getByLabelText("Credential name"), {
      target: { value: "Primary key" },
    });
    fireEvent.change(screen.getByLabelText("API key"), {
      target: { value: "test-secret" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add credential" }));

    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        `/vulcan/manage/provider-instances/${instance.id}/credentials/attach`,
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({
            auth_method_id: "api_key",
            label: "Primary key",
            secret: "test-secret",
          }),
        }),
      ),
    );
  });

  // This test verifies credential management keeps the table compact while opening models, resources, and priority editing on demand.
  // 此测试验证凭据管理保持表格紧凑，并按需打开模型、资源和优先级编辑。
  it("opens credential model, resource, and priority details on demand", async () => {
    // miniMaxDefinition matches the exact native definition that owns the protected file-list integration.
    // miniMaxDefinition 匹配拥有受保护文件列表集成的精确原生定义。
    const miniMaxDefinition = {
      id: "system_minimax_api",
      display_name: "MiniMax API",
      group_id: "minimax",
      variant_name: "Global",
      variant_description: "MiniMax global API endpoint.",
      model_catalog_id: "minimax",
      protocol_profile_id: "openai.chat",
      endpoint_presets: [
        {
          id: "global",
          base_url: "https://api.minimax.io",
          region: "global",
          user_editable: false,
          parameters: [],
        },
      ],
      auth_methods: [
        {
          id: "api_key",
          type: "api_key",
          refreshable: false,
          multiple_credentials: true,
          plan_acquisition: "unavailable",
        },
      ],
      plan_options: [],
      features: {
        model_discovery: "supported",
        plan_reader: "supported",
        entitlement_reader: "supported",
        allowance_reader: "supported",
      },
    };
    // miniMaxInstance owns the single credential rendered by this focused management interaction test.
    // miniMaxInstance 拥有此聚焦管理交互测试渲染的单个凭据。
    const miniMaxInstance = {
      id: "pvi_minimax",
      definition_id: miniMaxDefinition.id,
      handle: "minimax",
      display_name: "MiniMax Production",
      status: "ready",
      routing_strategy: "",
      disabled_model_ids: [],
      endpoint_count: 1,
      credential_count: 1,
      binding_count: 1,
      revision: 1,
    };
    // miniMaxCatalog mirrors persisted management-safe models, quota, voices, and excludes all secret material.
    // miniMaxCatalog 镜像持久化的管理安全模型、额度和声音，并排除所有秘密材料。
    const miniMaxCatalog = {
      provider_instance_id: miniMaxInstance.id,
      models: [
        {
          id: "model_minimax_m25",
          upstream_model_id: "MiniMax-M2.5",
          display_name: "MiniMax M2.5",
          entitlement_mode: "all_bound_credentials",
          enabled: true,
          authorization_status: "authorized",
        },
      ],
      plans: [],
      allowances: [
        {
          credential_id: "cred_minimax",
          credential_label: "MiniMax Primary",
          kind: "window_quota",
          scope: "credential",
          metric: "minimax.general.current_interval",
          unit: "requests",
          remaining_ratio: 0.23,
          status: "available",
          mandatory: false,
          window: {
            kind: "provider_defined",
            duration: "0",
            reset_at: "2026-07-22T06:34:00Z",
          },
          observed_at: "2026-07-22T04:00:00Z",
          expires_at: "2026-07-22T04:30:00Z",
        },
        {
          credential_id: "cred_minimax",
          credential_label: "MiniMax Primary",
          kind: "window_quota",
          scope: "credential",
          metric: "minimax.general.weekly",
          unit: "requests",
          status: "available",
          mandatory: false,
          window: { kind: "calendar", duration: "0", calendar_unit: "week", start_at: "2026-07-19T00:00:00Z", reset_at: "2026-07-26T00:00:00Z" },
          observed_at: "2026-07-22T04:00:00Z",
          expires_at: "2026-07-22T04:30:00Z",
        },
        {
          credential_id: "cred_minimax",
          credential_label: "MiniMax Primary",
          kind: "window_quota",
          scope: "credential",
          metric: "minimax.video.current_interval",
          unit: "requests",
          limit: "3",
          remaining: "0",
          remaining_ratio: 0,
          status: "exhausted",
          mandatory: false,
          window: { kind: "provider_defined", duration: "0", reset_at: "2026-07-22T10:34:00Z" },
          observed_at: "2026-07-22T04:00:00Z",
          expires_at: "2026-07-22T04:30:00Z",
        },
        {
          credential_id: "cred_minimax",
          credential_label: "MiniMax Primary",
          kind: "window_quota",
          scope: "credential",
          metric: "minimax.video.weekly",
          unit: "requests",
          limit: "21",
          remaining: "0",
          remaining_ratio: 0,
          display_multiplier_permille: 1500,
          status: "exhausted",
          mandatory: false,
          window: { kind: "calendar", duration: "0", calendar_unit: "week", start_at: "2026-07-19T00:00:00Z", reset_at: "2026-07-26T00:00:00Z" },
          observed_at: "2026-07-22T04:00:00Z",
          expires_at: "2026-07-22T04:30:00Z",
        },
      ],
      voices: [
        {
          voice_id: "male-qn-qingse",
          display_name: "Qingse",
          descriptions: ["male", "warm"],
          credential_id: "cred_minimax",
          credential_label: "MiniMax Primary",
          observed_at: "2026-07-22T04:00:00Z",
          expires_at: "2026-07-22T04:30:00Z",
        },
      ],
      revision: 1,
      observed_at: "2026-07-22T04:00:00Z",
    };
    // fetchMock serves only the exact protected management paths exercised by the compact credential table.
    // fetchMock 仅提供紧凑凭据表所调用的精确受保护管理路径。
    const fetchMock = vi.fn().mockImplementation(
      (input: string | URL | Request, init?: RequestInit) => {
        const url = String(input);
        const method =
          init?.method ?? (input instanceof Request ? input.method : "GET");
        if (url.endsWith("/provider-groups")) {
          return Promise.resolve(
            jsonResponse({
              provider_groups: [
                {
                  id: "minimax",
                  display_name: "MiniMax",
                  description: "MiniMax native providers.",
                  provider_definitions: [miniMaxDefinition],
                },
              ],
            }),
          );
        }
        if (url.endsWith("/provider-definitions")) {
          return Promise.resolve(
            jsonResponse({
              provider_definitions: [
                {
                  id: miniMaxDefinition.id,
                  kind: "system",
                  display_name: miniMaxDefinition.display_name,
                  group_id: miniMaxDefinition.group_id,
                  protocol_profile_id: miniMaxDefinition.protocol_profile_id,
                  auth_methods: miniMaxDefinition.auth_methods,
                  plan_options: miniMaxDefinition.plan_options,
                  features: miniMaxDefinition.features,
                },
              ],
            }),
          );
        }
        if (url.endsWith("/protocol-profiles")) {
          return Promise.resolve(
            jsonResponse({
              protocol_profiles: [
                {
                  id: "openai.chat",
                  version: "1",
                  display_name: "OpenAI Chat Completions",
                  user_configurable: true,
                  runtime_ready: true,
                  model_discovery: "supported",
                  capabilities: [],
                  allowed_auth_methods: ["bearer"],
                },
              ],
            }),
          );
        }
        if (url.endsWith("/provider-instances")) {
          return Promise.resolve(
            jsonResponse({ provider_instances: [miniMaxInstance] }),
          );
        }
        if (
          url.endsWith(
            `/provider-instances/${miniMaxInstance.id}/credentials`,
          )
        ) {
          return Promise.resolve(
            jsonResponse({
              credentials: [
                {
                  id: "cred_minimax",
                  provider_instance_id: miniMaxInstance.id,
                  auth_method_id: "api_key",
                  label: "MiniMax Primary",
                  status: "active",
                  expires_at: null,
                  cooling_until: null,
                  priority: 2,
                  revision: 1,
                },
              ],
            }),
          );
        }
        if (
          url.endsWith(
            `/provider-instances/${miniMaxInstance.id}/catalog/refresh`,
          ) && method === "POST"
        ) {
          return Promise.resolve(jsonResponse(miniMaxCatalog));
        }
        if (
          url.endsWith(`/provider-instances/${miniMaxInstance.id}/catalog`) &&
          method === "GET"
        ) {
          return Promise.resolve(jsonResponse(miniMaxCatalog));
        }
        if (
          url.endsWith(`/provider-instances/${miniMaxInstance.id}/endpoints`)
        ) {
          return Promise.resolve(
            jsonResponse({
              endpoints: [
                {
                  id: "endpoint_minimax",
                  provider_instance_id: miniMaxInstance.id,
                  base_url: "https://api.minimax.io",
                  region: "global",
                  parameters: [],
                  status: "ready",
                  revision: 1,
                },
              ],
            }),
          );
        }
        if (
          url.endsWith(`/provider-instances/${miniMaxInstance.id}/bindings`)
        ) {
          return Promise.resolve(
            jsonResponse({
              bindings: [
                {
                  id: "binding_minimax",
                  provider_instance_id: miniMaxInstance.id,
                  endpoint_id: "endpoint_minimax",
                  credential_id: "cred_minimax",
                  allowed_model_ids: [],
                  allowed_service_ids: [],
                  priority: 0,
                  enabled: true,
                  revision: 1,
                },
              ],
            }),
          );
        }
        if (
          url ===
            `/vulcan/manage/provider-instances/${miniMaxInstance.id}/credentials/cred_minimax/files?endpoint_id=endpoint_minimax` &&
          method === "GET"
        ) {
          return Promise.resolve(
            jsonResponse({
              files: [
                {
                  file_id: "file_minimax_reference",
                  filename: "reference.png",
                  purpose: "vision",
                  size_bytes: 2048,
                  created_at: "2026-07-22T04:00:00Z",
                  download_available: false,
                },
              ],
            }),
          );
        }
        if (
          url.endsWith(
            `/provider-instances/${miniMaxInstance.id}/credentials/cred_minimax/priority`,
          ) && method === "PUT"
        ) {
          return Promise.resolve(jsonResponse({}));
        }
        return Promise.resolve(jsonResponse({ error: "not_found" }, 404));
      },
    );
    vi.stubGlobal("fetch", fetchMock);
    render(
      <I18nProvider>
        <CredentialManagementPage managementAuthToken="management-token" />
      </I18nProvider>,
    );

    expect(await screen.findByText("MiniMax Primary")).toBeInTheDocument();
    expect(await screen.findByText("General")).toBeInTheDocument();
    expect(screen.getByText("23%")).toBeInTheDocument();
    expect(screen.getByText("Unlimited")).toBeInTheDocument();
    expect(
      screen.getByRole("progressbar", { name: "Wk left: Unlimited" }),
    ).toHaveAttribute("aria-valuenow", "100");
    expect(
      screen
        .getByRole("progressbar", { name: "Wk left: Unlimited" })
        .firstElementChild,
    ).toHaveStyle({ width: "100%" });
    expect(screen.getByText("Video")).toBeInTheDocument();
    expect(screen.getByText("0 / 3")).toBeInTheDocument();
    expect(screen.getByText("0 / 21")).toBeInTheDocument();
    expect(screen.getByText(/Period:/)).toHaveTextContent("2026-07-19");
    expect(screen.getByText(/Period:/)).toHaveTextContent("2026-07-26");
    expect(screen.queryByText("MiniMax M2.5")).not.toBeInTheDocument();

    fireEvent.click(
      screen.getByRole("button", { name: "Get supported models" }),
    );
    expect(
      await screen.findByRole("heading", { name: "Supported models" }),
    ).toBeInTheDocument();
    expect(screen.getByText("MiniMax M2.5")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));

    fireEvent.click(screen.getByRole("button", { name: "Resources" }));
    expect(
      await screen.findByRole("heading", { name: "Resource list" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Qingse")).toBeInTheDocument();
    expect(await screen.findByText("reference.png")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));

    fireEvent.click(
      screen.getByRole("button", { name: "Edit priority MiniMax Primary" }),
    );
    expect(
      screen.getByRole("heading", { name: "Edit priority" }),
    ).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Priority"), {
      target: { value: "7" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Update priority" }));
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        `/vulcan/manage/provider-instances/${miniMaxInstance.id}/credentials/cred_minimax/priority`,
        expect.objectContaining({
          method: "PUT",
          body: JSON.stringify({ priority: 7 }),
        }),
      ),
    );
  });

  // This test verifies credential navigation shows provider categories while native subtypes remain in the creation dialog.
  // 此测试验证凭据导航显示供应商大类，而原生子类仅保留在创建 Dialog 中。
  it("groups native subtypes and lists custom providers in credential navigation", async () => {
    // unconfiguredDefinition is one supported native provider with no local instance or credential.
    // unconfiguredDefinition 是一个尚无本地实例或凭据的受支持原生供应商。
    const unconfiguredDefinition = {
      ...definition,
      id: "system_unconfigured_provider",
      display_name: "Unconfigured Native",
      variant_name: "Unconfigured",
    };
    // customDefinition is one user-owned provider definition returned by the complete definition inventory.
    // customDefinition 是完整 Definition 清单返回的一个用户拥有供应商定义。
    const customDefinition = {
      id: "custom_deepseek",
      kind: "custom",
      display_name: "DeepSeek",
      protocol_profile_id: "openai.chat",
      auth_methods: [
        {
          id: "default",
          type: "bearer",
          refreshable: false,
          multiple_credentials: true,
          plan_acquisition: "unavailable",
        },
      ],
      plan_options: [],
      features: unavailableFeatures,
    };
    // fetchMock serves one configured instance while retaining two additional supported definitions.
    // fetchMock 提供一个已配置实例，同时保留另外两个受支持 Definition。
    const fetchMock = vi.fn().mockImplementation(
      (input: string | URL | Request, init?: RequestInit) => {
        const url = String(input);
        const method =
          init?.method ?? (input instanceof Request ? input.method : "GET");
        if (url.endsWith("/provider-groups")) {
          return Promise.resolve(
            jsonResponse({
              provider_groups: [
                {
                  id: "test",
                  display_name: "Test",
                  description: "Native test providers.",
                  provider_definitions: [definition, unconfiguredDefinition],
                },
              ],
            }),
          );
        }
        if (url.endsWith("/provider-definitions")) {
          return Promise.resolve(
            jsonResponse({
              provider_definitions: [
                {
                  id: definition.id,
                  kind: "system",
                  display_name: definition.display_name,
                  group_id: definition.group_id,
                  protocol_profile_id: definition.protocol_profile_id,
                  auth_methods: definition.auth_methods,
                  plan_options: [],
                  features: unavailableFeatures,
                },
                {
                  id: unconfiguredDefinition.id,
                  kind: "system",
                  display_name: unconfiguredDefinition.display_name,
                  group_id: unconfiguredDefinition.group_id,
                  protocol_profile_id:
                    unconfiguredDefinition.protocol_profile_id,
                  auth_methods: unconfiguredDefinition.auth_methods,
                  plan_options: [],
                  features: unavailableFeatures,
                },
                customDefinition,
              ],
            }),
          );
        }
        if (url.endsWith("/provider-instances")) {
          return Promise.resolve(
            jsonResponse({ provider_instances: [instance] }),
          );
        }
        if (url.endsWith(`/provider-instances/${instance.id}/credentials`)) {
          return Promise.resolve(jsonResponse({ credentials: [] }));
        }
        if (
          url.endsWith("/provider-instances/onboard") &&
          method === "POST"
        ) {
          return Promise.resolve(
            jsonResponse(
              {
                provider_instance_id: "pvi_unconfigured",
                credential_id: "cred_unconfigured",
                endpoint_ids: ["ep_unconfigured"],
                binding_ids: ["bind_unconfigured"],
              },
              201,
            ),
          );
        }
        if (url.endsWith("/protocol-profiles")) {
          return Promise.resolve(jsonResponse({ protocol_profiles: [] }));
        }
        return Promise.resolve(jsonResponse({ error: "not_found" }, 404));
      },
    );
    vi.stubGlobal("fetch", fetchMock);
    render(
      <I18nProvider>
        <CredentialManagementPage managementAuthToken="management-token" />
      </I18nProvider>,
    );

    // providerTree is the complete definition-backed navigation directory.
    // providerTree 是由完整 Definition 驱动的导航目录。
    const providerTree = await screen.findByRole("tree", {
      name: "Credential Management",
    });
    expect(within(providerTree).getByText("Test")).toBeInTheDocument();
    expect(within(providerTree).queryByText("Test Provider")).not.toBeInTheDocument();
    expect(within(providerTree).queryByText("Unconfigured Native")).not.toBeInTheDocument();
    expect(within(providerTree).getByText("DeepSeek")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Add credential" }));
    expect(screen.getByRole("button", { name: "Select Global" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Select Unconfigured" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Select Unconfigured" }));
    expect(screen.getByRole("heading", { name: "Add credential" })).toBeInTheDocument();
    expect(screen.getByLabelText("Credential name")).toHaveValue(
      "Unconfigured Native",
    );
  });
});
