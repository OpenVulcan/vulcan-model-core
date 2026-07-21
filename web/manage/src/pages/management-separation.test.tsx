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
});
