import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { I18nProvider } from "@/i18n";
import {
  credentialPlanLabel,
  ProviderManagementPage,
} from "@/pages/provider-management-page";

// unavailableFeatures is the exact management feature contract for API-key-only test definitions.
// unavailableFeatures 是仅 API Key 测试定义的精确管理功能合同。
const unavailableFeatures = {
  model_discovery: "unsupported",
  plan_reader: "unsupported",
  entitlement_reader: "unsupported",
  allowance_reader: "unsupported",
};

// kimiGroupResponse is the exact management envelope used to verify grouped provider selection.
// kimiGroupResponse 是用于验证分组供应商选择的精确管理响应信封。
const kimiGroupResponse = {
  provider_groups: [
    {
      id: "kimi",
      display_name: "Kimi",
      description: "Kimi provider family.",
      provider_definitions: [
        {
          id: "system_kimi_cn",
          display_name: "Kimi CN",
          group_id: "kimi",
          variant_name: "CN",
          variant_description: "CN API site.",
          model_catalog_id: "kimi_open_platform",
          auth_methods: [
            { id: "api_key", type: "api_key", refreshable: false },
          ],
          features: unavailableFeatures,
          protocol_profile_id: "openai.chat",
          endpoint_presets: [
            {
              id: "cn_chat",
              base_url: "https://api.moonshot.cn",
              region: "CN",
              user_editable: false,
            },
          ],
        },
        {
          id: "system_kimi_global",
          display_name: "Kimi Global",
          group_id: "kimi",
          variant_name: "Global",
          variant_description: "Global API site.",
          model_catalog_id: "kimi_open_platform",
          auth_methods: [
            { id: "api_key", type: "api_key", refreshable: false },
          ],
          features: unavailableFeatures,
          protocol_profile_id: "openai.chat",
          endpoint_presets: [
            {
              id: "global_chat",
              base_url: "https://api.moonshot.ai",
              region: "Global",
              user_editable: false,
            },
          ],
        },
        {
          id: "system_kimi_coding_plan",
          display_name: "Kimi Coding Plan",
          group_id: "kimi",
          variant_name: "Coding Plan",
          variant_description: "Coding membership.",
          model_catalog_id: "kimi_coding",
          auth_methods: [
            { id: "api_key", type: "api_key", refreshable: false },
            { id: "device_flow", type: "device_flow", refreshable: true },
          ],
          features: unavailableFeatures,
          protocol_profile_id: "openai.chat",
          endpoint_presets: [
            {
              id: "coding_chat",
              base_url: "https://api.kimi.com/coding/v1",
              region: "Coding Plan",
              user_editable: false,
            },
          ],
        },
      ],
    },
  ],
};

// alibabaDefinition creates one exact Alibaba test variant from immutable identity and endpoint facts.
// alibabaDefinition 根据不可变身份与端点事实创建一个精确 Alibaba 测试变体。
function alibabaDefinition(
  id: string,
  variantName: string,
  catalogID: string,
  endpointID: string,
  baseURL: string,
  region: string,
  descriptionKey: string,
) {
  return {
    id,
    display_name: `Alibaba ${variantName}`,
    group_id: "alibaba",
    variant_name: variantName,
    variant_description: `${variantName} subscription.`,
    variant_description_key: descriptionKey,
    model_catalog_id: catalogID,
    auth_methods: [{ id: "api_key", type: "api_key", refreshable: false }],
    features: unavailableFeatures,
    protocol_profile_id: "anthropic.messages",
    endpoint_presets: [
      { id: endpointID, base_url: baseURL, region, user_editable: false },
    ],
  };
}

// alibabaGroupResponse exposes all five regional commercial products through one grouped card.
// alibabaGroupResponse 通过一个分组卡片暴露全部五个区域商业产品。
const alibabaGroupResponse = {
  provider_groups: [
    {
      id: "alibaba",
      display_name: "Alibaba Cloud Model Studio",
      description: "Alibaba coding subscriptions.",
      description_key: "providers.alibaba.description",
      provider_definitions: [
        alibabaDefinition("system_alibaba_coding_plan_cn", "Coding Plan CN", "alibaba_coding_plan_cn", "coding_plan_cn", "https://coding.dashscope.aliyuncs.com/apps/anthropic/v1", "CN", "providers.alibaba.codingPlanCNDescription"),
        alibabaDefinition("system_alibaba_coding_plan_global", "Coding Plan Global", "alibaba_coding_plan_global", "coding_plan_global", "https://coding-intl.dashscope.aliyuncs.com/apps/anthropic/v1", "Global", "providers.alibaba.codingPlanGlobalDescription"),
        alibabaDefinition("system_alibaba_token_plan_personal_cn", "Token Plan Personal CN", "alibaba_token_plan_personal_cn", "token_plan_personal_cn", "https://token-plan.cn-beijing.maas.aliyuncs.com/apps/anthropic/v1", "CN", "providers.alibaba.tokenPlanPersonalCNDescription"),
        alibabaDefinition("system_alibaba_token_plan_team_cn", "Token Plan Team CN", "alibaba_token_plan_team_cn", "token_plan_team_cn", "https://token-plan.cn-beijing.maas.aliyuncs.com/apps/anthropic/v1", "CN", "providers.alibaba.tokenPlanTeamCNDescription"),
        alibabaDefinition("system_alibaba_token_plan_team_global", "Token Plan Team Global", "alibaba_token_plan_team_global", "token_plan_team_global", "https://token-plan.ap-southeast-1.maas.aliyuncs.com/apps/anthropic/v1", "Global", "providers.alibaba.tokenPlanTeamGlobalDescription"),
      ],
    },
  ],
};

// alibabaWorkspaceGroupResponse reproduces the parameterized endpoint returned by the real Alibaba catalog.
// alibabaWorkspaceGroupResponse 复现真实 Alibaba 目录返回的参数化端点。
const alibabaWorkspaceGroupResponse = {
  provider_groups: [
    {
      id: "alibaba",
      display_name: "Alibaba Cloud Model Studio",
      description: "Alibaba Model Studio products.",
      description_key: "providers.alibaba.description",
      provider_definitions: [
        {
          id: "system_alibaba_model_studio_workspace_global",
          display_name: "Alibaba Model Studio Workspace Global",
          group_id: "alibaba",
          variant_name: "Model Studio Workspace Global",
          variant_description:
            "Alibaba Model Studio API hosted in Singapore and isolated by workspace ID.",
          variant_description_key:
            "providers.alibaba.modelStudioWorkspaceGlobalDescription",
          model_catalog_id: "alibaba_model_studio_workspace_global",
          auth_methods: [
            { id: "api_key", type: "api_key", refreshable: false },
          ],
          features: unavailableFeatures,
          protocol_profile_id: "alibaba.embedding",
          endpoint_presets: [
            {
              id: "model_studio_workspace_global",
              base_url: "",
              region: "Global",
              user_editable: false,
              parameters: [
                {
                  id: "workspace_id",
                  kind: "hostname_label",
                  required: true,
                },
              ],
            },
          ],
        },
      ],
    },
  ],
};

// mixedProviderGroupResponse adds one single-definition provider to exercise direct configuration.
// mixedProviderGroupResponse 增加一个单定义供应商，用于验证直接配置流程。
const mixedProviderGroupResponse = {
  provider_groups: [
    ...kimiGroupResponse.provider_groups,
    {
      id: "openai",
      display_name: "OpenAI",
      description: "OpenAI API service.",
      provider_definitions: [
        {
          id: "system_openai",
          display_name: "OpenAI",
          group_id: "openai",
          variant_name: "Default",
          variant_description: "OpenAI API service.",
          model_catalog_id: "openai",
          auth_methods: [
            { id: "api_key", type: "api_key", refreshable: false },
          ],
          features: unavailableFeatures,
          protocol_profile_id: "openai.responses",
          endpoint_presets: [
            {
              id: "openai_responses",
              base_url: "https://api.openai.com/v1",
              region: "Global",
              user_editable: false,
            },
          ],
        },
      ],
    },
  ],
};

// antigravityGroupResponse exposes the exact single-definition browser OAuth product.
// antigravityGroupResponse 暴露精确的单定义浏览器 OAuth 产品。
const antigravityGroupResponse = {
  provider_groups: [
    {
      id: "google",
      display_name: "Google",
      description: "Google account products.",
      provider_definitions: [
        {
          id: "system_google_antigravity",
          display_name: "Google Antigravity",
          group_id: "google",
          variant_name: "Antigravity",
          variant_description:
            "Google account-scoped Antigravity agent backend.",
          model_catalog_id: "google_antigravity",
          auth_methods: [{ id: "oauth", type: "oauth", refreshable: true }],
          features: {
            model_discovery: "supported",
            plan_reader: "supported",
            entitlement_reader: "unsupported",
            allowance_reader: "supported",
          },
          protocol_profile_id: "google.antigravity",
          endpoint_presets: [
            {
              id: "google_antigravity",
              base_url: "https://cloudcode-pa.googleapis.com",
              region: "Global",
              user_editable: false,
            },
          ],
        },
      ],
    },
  ],
};

// claudeGroupResponse exposes the exact single-definition Claude Code OAuth product.
// claudeGroupResponse 暴露精确的单定义 Claude Code OAuth 产品。
const claudeGroupResponse = {
  provider_groups: [
    {
      id: "anthropic",
      display_name: "Anthropic",
      description: "Anthropic account products.",
      provider_definitions: [
        {
          id: "system_anthropic_claude_code",
          display_name: "Claude Code",
          group_id: "anthropic",
          variant_name: "Claude Code",
          variant_description:
            "Anthropic account-scoped Claude Code subscription.",
          model_catalog_id: "anthropic_claude_code",
          auth_methods: [{ id: "oauth", type: "oauth", refreshable: true }],
          features: unavailableFeatures,
          protocol_profile_id: "anthropic.messages",
          endpoint_presets: [
            {
              id: "claude_code_messages",
              base_url: "https://api.anthropic.com",
              region: "Global",
              user_editable: false,
            },
          ],
        },
      ],
    },
  ],
};

// codexGroupResponse exposes both CLIProxyAPI-supported Codex account authorization methods with browser OAuth as the default.
// codexGroupResponse 暴露 CLIProxyAPI 支持的两种 Codex 账号授权方式，并以浏览器 OAuth 作为默认方式。
const codexGroupResponse = {
  provider_groups: [
    {
      id: "openai",
      display_name: "OpenAI",
      description: "OpenAI account products.",
      provider_definitions: [
        {
          id: "system_openai_codex",
          display_name: "OpenAI Codex",
          group_id: "openai",
          variant_name: "Codex",
          variant_description: "OpenAI account-scoped Codex subscription.",
          model_catalog_id: "openai_codex",
          auth_methods: [
            { id: "oauth", type: "oauth", refreshable: true },
            { id: "device_flow", type: "device_flow", refreshable: true },
          ],
          features: unavailableFeatures,
          protocol_profile_id: "openai.responses",
          endpoint_presets: [
            {
              id: "codex_responses",
              base_url: "https://chatgpt.com/backend-api/codex",
              region: "Global",
              user_editable: false,
            },
          ],
        },
      ],
    },
  ],
};

// vertexGroupResponse exposes the exact single-definition service-account product.
// vertexGroupResponse 暴露精确的单定义服务账号产品。
const vertexGroupResponse = {
  provider_groups: [
    {
      id: "google",
      display_name: "Google",
      description: "Google cloud products.",
      provider_definitions: [
        {
          id: "system_google_vertex",
          display_name: "Google Vertex AI",
          group_id: "google",
          variant_name: "Vertex AI",
          variant_description:
            "Google Cloud Vertex AI using one project-scoped service account.",
          variant_description_key: "providers.google.vertexDescription",
          model_catalog_id: "google_vertex",
          auth_methods: [
            {
              id: "service_account",
              type: "service_account",
              refreshable: false,
            },
          ],
          features: unavailableFeatures,
          protocol_profile_id: "google.aistudio",
          endpoint_presets: [
            {
              id: "default",
              base_url: "https://us-central1-aiplatform.googleapis.com",
              region: "us-central1",
              user_editable: false,
            },
          ],
        },
      ],
    },
  ],
};

// authorizedVertexInstanceResponse exposes one configured Vertex instance for credential replacement tests.
// authorizedVertexInstanceResponse 暴露一个已配置 Vertex 实例用于凭据替换测试。
const authorizedVertexInstanceResponse = {
  provider_instances: [
    {
      id: "pvi_vertex",
      definition_id: "system_google_vertex",
      handle: "google_vertex",
      display_name: "vertex@vertex-project.iam.gserviceaccount.com",
      status: "ready",
      disabled_model_ids: [],
      endpoint_count: 1,
      credential_count: 1,
      binding_count: 1,
      revision: 1,
    },
  ],
};

// authorizedVertexCredentialsResponse exposes the service-account metadata without protected bytes.
// authorizedVertexCredentialsResponse 暴露不含受保护字节的服务账号元数据。
const authorizedVertexCredentialsResponse = {
  credentials: [
    {
      id: "cred_vertex",
      provider_instance_id: "pvi_vertex",
      auth_method_id: "service_account",
      label: "vertex@vertex-project.iam.gserviceaccount.com",
      principal_key: "vertex@vertex-project.iam.gserviceaccount.com",
      status: "active",
      expires_at: null,
      cooling_until: null,
      priority: 0,
      revision: 1,
      scope_refs: [{ kind: "project", id: "vertex-project" }],
    },
  ],
};

// emptyProviderInstancesResponse represents a management account with no completed authorization.
// emptyProviderInstancesResponse 表示尚无已完成授权的管理账户。
const emptyProviderInstancesResponse = { provider_instances: [] };

// authorizedCNInstanceResponse is the configured instance returned after successful API-key onboarding.
// authorizedCNInstanceResponse 是 API Key 录入成功后返回的已配置实例。
const authorizedCNInstanceResponse = {
  provider_instances: [
    {
      id: "pvi_kimi_cn",
      definition_id: "system_kimi_cn",
      handle: "kimi_cn",
      display_name: "Kimi CN Production",
      status: "ready",
      disabled_model_ids: null,
      endpoint_count: 1,
      credential_count: 1,
      binding_count: 1,
      revision: 1,
    },
  ],
};

// authorizedCNCredentialsResponse is the redacted API authorization list for the configured CN instance.
// authorizedCNCredentialsResponse 是已配置 CN 实例的脱敏 API 授权列表。
const authorizedCNCredentialsResponse = {
  credentials: [
    {
      id: "cred_kimi_cn",
      provider_instance_id: "pvi_kimi_cn",
      auth_method_id: "api_key",
      label: "Kimi CN Production",
      status: "active",
      expires_at: null,
      cooling_until: null,
      revision: 1,
    },
  ],
};

// authorizedCodingInstanceResponse is the configured instance returned after completed device authorization.
// authorizedCodingInstanceResponse 是设备授权完成后返回的已配置实例。
const authorizedCodingInstanceResponse = {
  provider_instances: [
    {
      id: "pvi_kimi_coding",
      definition_id: "system_kimi_coding_plan",
      handle: "kimi_coding_plan",
      display_name: "Kimi Coding Account",
      status: "ready",
      disabled_model_ids: [],
      endpoint_count: 2,
      credential_count: 1,
      binding_count: 2,
      revision: 1,
    },
  ],
};

// authorizedCodingCredentialsResponse is the redacted device authorization list for the Coding Plan instance.
// authorizedCodingCredentialsResponse 是 Coding Plan 实例的脱敏设备授权列表。
const authorizedCodingCredentialsResponse = {
  credentials: [
    {
      id: "cred_kimi_coding",
      provider_instance_id: "pvi_kimi_coding",
      auth_method_id: "device_flow",
      label: "Kimi Coding Account",
      status: "active",
      expires_at: "2026-07-18T13:00:00Z",
      cooling_until: null,
      revision: 1,
    },
  ],
};

// authorizedAntigravityResponse is one configured Google account instance with metadata readers.
// authorizedAntigravityResponse 是一个已配置且拥有元数据读取器的 Google 账号实例。
const authorizedAntigravityResponse = {
  provider_instances: [
    {
      id: "pvi_antigravity",
      definition_id: "system_google_antigravity",
      handle: "google_antigravity",
      display_name: "Google Antigravity",
      status: "ready",
      disabled_model_ids: [],
      endpoint_count: 1,
      credential_count: 1,
      binding_count: 1,
      revision: 1,
    },
  ],
};

// authorizedAntigravityCredentialsResponse is the redacted Google OAuth credential list.
// authorizedAntigravityCredentialsResponse 是脱敏的 Google OAuth 凭据列表。
const authorizedAntigravityCredentialsResponse = {
  credentials: [
    {
      id: "cred_antigravity",
      provider_instance_id: "pvi_antigravity",
      auth_method_id: "oauth",
      label: "Google Account",
      status: "active",
      expires_at: "2026-07-19T13:00:00Z",
      cooling_until: null,
      revision: 1,
    },
  ],
};

// credentialRefreshFailureCases covers every actionable refresh failure rendered by the provider page.
// credentialRefreshFailureCases 覆盖供应商页面渲染的每种可操作刷新失败。
const credentialRefreshFailureCases = [
  {
    name: "rejected",
    status: 424,
    code: "provider_authentication_rejected",
    message: "The saved credential was rejected. Reauthorize this provider.",
  },
  {
    name: "temporarily unavailable",
    status: 503,
    code: "provider_authentication_unavailable",
    message:
      "The provider is temporarily unreachable. Your saved credential was not changed.",
  },
  {
    name: "invalid provider response",
    status: 502,
    code: "provider_authentication_invalid_response",
    message:
      "The provider returned an unreadable authentication response. Your saved credential was not changed.",
  },
  {
    name: "browser network failure",
    status: null,
    code: "",
    message:
      "The provider is temporarily unreachable. Your saved credential was not changed.",
  },
] as const;

// jsonResponse creates one JSON response with a stable content type for route-aware mocks.
// jsonResponse 为按路由模拟创建一个内容类型稳定的 JSON 响应。
function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

// renderPage mounts the provider page with one authenticated management credential.
// renderPage 使用一个已认证管理凭证挂载供应商页面。
function renderPage() {
  render(
    <I18nProvider>
      <ProviderManagementPage managementAuthToken="management-token" />
    </I18nProvider>,
  );
}

describe("ProviderManagementPage", () => {
  afterEach(() => vi.unstubAllGlobals());

  // This test verifies an automatically detected plan is joined only to the credential that reported it.
  // 此测试验证自动识别套餐只会关联到报告该套餐的凭据。
  it("resolves a provider-detected membership plan by exact credential ownership", () => {
    // detectedPlanLabel is the membership label resolved from provider metadata for the matching credential.
    // detectedPlanLabel 是根据匹配凭据的供应商元数据解析出的会员套餐标签。
    const detectedPlanLabel = credentialPlanLabel(
      undefined,
      {
        detected_plan: {
          plan_code: "researcher",
          plan_name: "Researcher",
          status: "active",
          evidence_source: "provider_api",
          observed_at: "2026-07-22T04:00:00Z",
        },
      },
    );
    expect(detectedPlanLabel).toBe("Researcher");
    expect(credentialPlanLabel(undefined, {})).toBeUndefined();
  });

  // This test verifies the authorized list is primary and provider filtering precedes exact variant selection.
  // 此测试验证已授权列表是主视图，且供应商过滤先于精确变体选择。
  it("lists authorized providers before opening the filterable two-level creation flow", async () => {
    const fetchMock = vi
      .fn()
      .mockImplementation((input: string | URL | Request) => {
        const url = String(input);
        if (url === "/vulcan/manage/provider-groups")
          return Promise.resolve(jsonResponse(kimiGroupResponse));
        if (url === "/vulcan/manage/provider-instances")
          return Promise.resolve(jsonResponse(authorizedCNInstanceResponse));
        if (url === "/vulcan/manage/provider-instances/pvi_kimi_cn/credentials")
          return Promise.resolve(jsonResponse(authorizedCNCredentialsResponse));
        return Promise.resolve(new Response(null, { status: 404 }));
      });
    vi.stubGlobal("fetch", fetchMock);

    renderPage();

    expect(
      (await screen.findAllByText("Kimi CN Production")).length,
    ).toBeGreaterThan(1);
    expect(screen.getByText("API key")).toBeInTheDocument();
    expect(
      screen.getByText(
        "This provider does not expose account, plan, or allowance data.",
      ),
    ).toBeInTheDocument();
    expect(screen.queryByText("Coding Plan")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Add provider" }));
    fireEvent.change(screen.getByLabelText("Filter providers"), {
      target: { value: "Global" },
    });
    fireEvent.click(screen.getByRole("button", { name: /Kimi/ }));

    // providerOptionRows excludes the always-visible summary badges from filtered option assertions.
    // providerOptionRows 在筛选后的选项断言中排除始终显示的摘要标签。
    const providerOptionRows = document.querySelectorAll(
      "[data-provider-variant-row]",
    );
    expect(providerOptionRows).toHaveLength(1);
    expect(providerOptionRows[0]).toHaveTextContent("Global");
    expect(providerOptionRows[0]).not.toHaveTextContent("CN");
    expect(providerOptionRows[0]).not.toHaveTextContent("Coding Plan");
    expect(fetchMock).toHaveBeenCalledWith(
      "/vulcan/manage/provider-groups",
      expect.objectContaining({
        headers: { Authorization: "Bearer management-token" },
      }),
    );
  });

  // This test verifies an API key is replaced through the credential-specific route without creating another provider.
  // 此测试验证 API Key 通过凭据专属入口替换且不会创建另一个供应商。
  it("replaces one existing API-key credential", async () => {
    const fetchMock = vi
      .fn()
      .mockImplementation(
        (input: string | URL | Request, init?: RequestInit) => {
          const url = String(input);
          if (url === "/vulcan/manage/provider-groups")
            return Promise.resolve(jsonResponse(kimiGroupResponse));
          if (url === "/vulcan/manage/provider-instances")
            return Promise.resolve(jsonResponse(authorizedCNInstanceResponse));
          if (
            url === "/vulcan/manage/provider-instances/pvi_kimi_cn/credentials"
          )
            return Promise.resolve(
              jsonResponse(authorizedCNCredentialsResponse),
            );
          if (
            url ===
              "/vulcan/manage/provider-instances/pvi_kimi_cn/credentials/cred_kimi_cn/secret" &&
            init?.method === "PUT"
          )
            return Promise.resolve(jsonResponse({ id: "cred_kimi_cn" }));
          return Promise.resolve(new Response(null, { status: 404 }));
        },
      );
    vi.stubGlobal("fetch", fetchMock);
    renderPage();

    await screen.findByText("API key");
    fireEvent.click(
      screen.getByRole("button", { name: "Replace credential" }),
    );
    expect(screen.queryByLabelText("Name")).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("API key"), {
      target: { value: "replacement-kimi-key" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Replace credential" }),
    );
    await waitFor(() => {
      const replacementCall = fetchMock.mock.calls.find(
        ([url, init]) =>
          String(url).endsWith("/cred_kimi_cn/secret") &&
          init?.method === "PUT",
      );
      expect(replacementCall?.[1]?.body).toBe(
        JSON.stringify({ secret: "replacement-kimi-key" }),
      );
    });
    expect(
      fetchMock.mock.calls.some(
        ([url, init]) =>
          String(url) === "/vulcan/manage/provider-instances/onboard" &&
          init?.method === "POST",
      ),
    ).toBe(false);
  });

  // This test verifies Alibaba uses concise plan-family badges and keeps all exact variants inside the existing dialog workflow.
  // 此测试验证 Alibaba 使用简洁套餐系列标签，并在现有 Dialog 流程中保留全部精确变体。
  it("renders Alibaba plan families and configures one exact variant", async () => {
    const fetchMock = vi
      .fn()
      .mockImplementation((input: string | URL | Request) => {
        const url = String(input);
        if (url === "/vulcan/manage/provider-groups")
          return Promise.resolve(jsonResponse(alibabaGroupResponse));
        if (url === "/vulcan/manage/provider-instances")
          return Promise.resolve(jsonResponse(emptyProviderInstancesResponse));
        return Promise.resolve(new Response(null, { status: 404 }));
      });
    vi.stubGlobal("fetch", fetchMock);
    renderPage();

    expect(
      await screen.findByText("No authorized providers yet."),
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Add provider" }));
    expect(screen.getByText("Coding Plan")).toBeInTheDocument();
    expect(screen.getByText("Token Plan")).toBeInTheDocument();
    expect(screen.queryByText("Coding Plan CN")).not.toBeInTheDocument();

    fireEvent.click(
      screen.getByRole("button", { name: /Alibaba Cloud Model Studio/ }),
    );
    expect(
      document.querySelectorAll("[data-provider-variant-row]"),
    ).toHaveLength(5);
    expect(screen.getAllByText("anthropic.messages")).toHaveLength(5);
    expect(
      screen.getByText(
        "https://token-plan.ap-southeast-1.maas.aliyuncs.com/apps/anthropic/v1",
      ),
    ).toBeInTheDocument();

    fireEvent.click(
      screen.getByRole("button", { name: "Select Coding Plan CN" }),
    );
    expect(screen.getByText("Configure provider")).toBeInTheDocument();
    expect(screen.getByLabelText("Name")).toBeInTheDocument();
    expect(screen.getByLabelText("API key")).toHaveAttribute("type", "password");
  });

  // This test verifies a parameterized Alibaba endpoint loads and submits its declared workspace value.
  // 此测试验证参数化 Alibaba 端点能够加载并提交其声明的 Workspace 值。
  it("loads and onboards the Alibaba workspace endpoint", async () => {
    const fetchMock = vi
      .fn()
      .mockImplementation(
        (input: string | URL | Request, init?: RequestInit) => {
          const url = String(input);
          if (url === "/vulcan/manage/provider-groups")
            return Promise.resolve(
              jsonResponse(alibabaWorkspaceGroupResponse),
            );
          if (url === "/vulcan/manage/provider-instances")
            return Promise.resolve(
              jsonResponse(emptyProviderInstancesResponse),
            );
          if (
            url === "/vulcan/manage/provider-instances/onboard" &&
            init?.method === "POST"
          )
            return Promise.resolve(
              jsonResponse(
                {
                  provider_instance_id: "pvi_alibaba_workspace",
                  credential_id: "cred_alibaba_workspace",
                  endpoint_ids: ["endpoint_alibaba_workspace"],
                  binding_ids: ["binding_alibaba_workspace"],
                },
                201,
              ),
            );
          return Promise.resolve(new Response(null, { status: 404 }));
        },
      );
    vi.stubGlobal("fetch", fetchMock);
    renderPage();

    expect(
      await screen.findByText("No authorized providers yet."),
    ).toBeInTheDocument();
    expect(
      screen.queryByText(
        "Unable to load the provider catalog. Adding providers is temporarily unavailable.",
      ),
    ).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Add provider" }));
    fireEvent.click(
      screen.getByRole("button", { name: /Alibaba Cloud Model Studio/ }),
    );
    fireEvent.change(screen.getByLabelText("Name"), {
      target: { value: "Alibaba Workspace" },
    });
    fireEvent.change(screen.getByLabelText("API key"), {
      target: { value: "test-api-key" },
    });
    fireEvent.change(screen.getByLabelText("Workspace ID"), {
      target: { value: "workspace-one" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Create provider" }));

    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/vulcan/manage/provider-instances/onboard",
        expect.objectContaining({ method: "POST" }),
      ),
    );
    const onboardingCall = fetchMock.mock.calls.find(
      ([url, init]) =>
        String(url) === "/vulcan/manage/provider-instances/onboard" &&
        init?.method === "POST",
    );
    expect(JSON.parse(String(onboardingCall?.[1]?.body))).toEqual({
      provider_definition_id:
        "system_alibaba_model_studio_workspace_global",
      name: "Alibaba Workspace",
      auth_method_id: "api_key",
      secret: "test-api-key",
      endpoint_parameters: [
        { id: "workspace_id", value: "workspace-one" },
      ],
    });
  });

  // This test verifies an authorized-list failure cannot leave the still-available creation workflow blank.
  // 此测试验证已授权列表失败时，仍可用的新增流程不会出现空白。
  it("keeps provider creation usable when only the authorized list fails", async () => {
    const fetchMock = vi
      .fn()
      .mockImplementation((input: string | URL | Request) => {
        const url = String(input);
        if (url === "/vulcan/manage/provider-groups")
          return Promise.resolve(jsonResponse(kimiGroupResponse));
        if (url === "/vulcan/manage/provider-instances")
          return Promise.resolve(jsonResponse({ error: "temporary" }, 500));
        return Promise.resolve(new Response(null, { status: 404 }));
      });
    vi.stubGlobal("fetch", fetchMock);
    renderPage();

    expect(
      await screen.findByText("Unable to load the authorized provider list."),
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Add provider" }));

    expect(screen.getByRole("button", { name: /Kimi/ })).toBeInTheDocument();
    expect(screen.getByLabelText("Filter providers")).toBeInTheDocument();
  });

  // This test verifies custom authorization cards never render without their server-owned definition metadata.
  // 此测试验证自定义授权卡片绝不会在缺少服务端拥有的 Definition 元数据时渲染。
  it("fails the authorized view when custom definition metadata is unavailable", async () => {
    const fetchMock = vi
      .fn()
      .mockImplementation((input: string | URL | Request) => {
        const url = String(input);
        if (url === "/vulcan/manage/provider-groups")
          return Promise.resolve(jsonResponse({ provider_groups: [] }));
        if (url === "/vulcan/manage/provider-instances")
          return Promise.resolve(
            jsonResponse({
              provider_instances: [
                {
                  id: "pvi_custom",
                  definition_id: "custom_missing_metadata",
                  handle: "custom-gateway",
                  display_name: "Custom Gateway",
                  status: "ready",
                  disabled_model_ids: [],
                  endpoint_count: 1,
                  credential_count: 1,
                  binding_count: 1,
                  revision: 1,
                },
              ],
            }),
          );
        if (url === "/vulcan/manage/provider-instances/pvi_custom/credentials")
          return Promise.resolve(
            jsonResponse({
              credentials: [
                {
                  id: "cred_custom",
                  provider_instance_id: "pvi_custom",
                  auth_method_id: "default",
                  label: "Custom Gateway",
                  status: "active",
                  expires_at: null,
                  cooling_until: null,
                  revision: 1,
                },
              ],
            }),
          );
        if (url === "/vulcan/manage/provider-definitions")
          return Promise.resolve(jsonResponse({ error: "temporary" }, 500));
        if (url === "/vulcan/manage/protocol-profiles")
          return Promise.resolve(jsonResponse({ protocol_profiles: [] }));
        return Promise.resolve(new Response(null, { status: 404 }));
      });
    vi.stubGlobal("fetch", fetchMock);
    renderPage();

    expect(
      await screen.findByText("Unable to load the authorized provider list."),
    ).toBeInTheDocument();
    expect(
      screen.queryByText("custom_missing_metadata"),
    ).not.toBeInTheDocument();
  });

  // This test verifies the custom card, server-owned protocol whitelist, atomic submission, and authorized-list refresh as one dialog workflow.
  // 此测试验证自定义卡片、服务端拥有协议白名单、原子提交与已授权列表刷新构成同一 Dialog 工作流。
  it("creates a custom compatibility provider through the atomic dialog workflow", async () => {
    let created = false;
    let submittedBody: Record<string, unknown> | null = null;
    const customDefinition = {
      id: "custom_acme",
      kind: "custom",
      display_name: "Acme Gateway",
      protocol_profile_id: "openai.chat",
      auth_methods: [
        { id: "default", type: "bearer", refreshable: false },
      ],
      features: unavailableFeatures,
    };
    const customInstanceResponse = {
      provider_instances: [
        {
          id: "pvi_acme",
          definition_id: "custom_acme",
          handle: "custom-acme",
          display_name: "Acme Gateway",
          status: "ready",
          disabled_model_ids: [],
          endpoint_count: 1,
          credential_count: 1,
          binding_count: 1,
          revision: 1,
        },
      ],
    };
    const customCredentialsResponse = {
      credentials: [
        {
          id: "cred_acme",
          provider_instance_id: "pvi_acme",
          auth_method_id: "default",
          label: "Acme Gateway",
          status: "active",
          expires_at: null,
          cooling_until: null,
          revision: 1,
        },
      ],
    };
    const protocolProfileResponse = {
      protocol_profiles: [
        {
          id: "google.aistudio",
          version: "1",
          display_name: "Gemini GenerateContent (Vertex-compatible)",
          user_configurable: true,
          runtime_ready: true,
          model_discovery: "unsupported",
          capabilities: [],
          allowed_auth_methods: ["header_api_key"],
        },
        {
          id: "openai.chat",
          version: "1",
          display_name: "OpenAI Chat Completions",
          user_configurable: true,
          runtime_ready: true,
          model_discovery: "unsupported",
          capabilities: [],
          allowed_auth_methods: ["bearer"],
        },
        {
          id: "openai.responses",
          version: "1",
          display_name: "OpenAI Responses",
          user_configurable: true,
          runtime_ready: true,
          model_discovery: "unsupported",
          capabilities: [],
          allowed_auth_methods: ["bearer"],
        },
        {
          id: "anthropic.messages",
          version: "1",
          display_name: "Anthropic Messages",
          user_configurable: true,
          runtime_ready: true,
          model_discovery: "unsupported",
          capabilities: [],
          allowed_auth_methods: ["header_api_key"],
        },
      ],
    };
    const fetchMock = vi
      .fn()
      .mockImplementation(
        (input: string | URL | Request, init?: RequestInit) => {
          const url = String(input);
          if (url === "/vulcan/manage/provider-groups") {
            return Promise.resolve(jsonResponse({ provider_groups: [] }));
          }
          if (url === "/vulcan/manage/protocol-profiles") {
            return Promise.resolve(jsonResponse(protocolProfileResponse));
          }
          if (url === "/vulcan/manage/provider-definitions") {
            return Promise.resolve(
              jsonResponse({
                provider_definitions: created ? [customDefinition] : [],
              }),
            );
          }
          if (url === "/vulcan/manage/provider-instances") {
            return Promise.resolve(
              jsonResponse(
                created
                  ? customInstanceResponse
                  : emptyProviderInstancesResponse,
              ),
            );
          }
          if (
            url === "/vulcan/manage/provider-instances/pvi_acme/credentials"
          ) {
            return Promise.resolve(jsonResponse(customCredentialsResponse));
          }
          if (
            url === "/vulcan/manage/custom-providers/onboard" &&
            init?.method === "POST"
          ) {
            submittedBody = JSON.parse(String(init.body)) as Record<
              string,
              unknown
            >;
            created = true;
            return Promise.resolve(
              jsonResponse(
                {
                  provider_definition_id: "custom_acme",
                  provider_instance_id: "pvi_acme",
                  credential_id: "cred_acme",
                  endpoint_id: "ep_acme",
                  binding_id: "bind_acme",
                  provider_model_id: "model_acme",
                },
                201,
              ),
            );
          }
          return Promise.resolve(new Response(null, { status: 404 }));
        },
      );
    vi.stubGlobal("fetch", fetchMock);

    renderPage();
    expect(
      await screen.findByText("No authorized providers yet."),
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Add provider" }));
    fireEvent.click(screen.getByRole("button", { name: /Custom provider/ }));

    expect(screen.getByText(/Authentication: Bearer/)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Provider name"), {
      target: { value: "Acme Gateway" },
    });
    fireEvent.change(screen.getByLabelText("Instance handle"), {
      target: { value: "custom-acme" },
    });
    fireEvent.change(screen.getByLabelText("Base URL"), {
      target: { value: "https://acme.example/v1" },
    });
    fireEvent.change(screen.getByLabelText("API key"), {
      target: { value: "acme-private-token" },
    });
    fireEvent.change(screen.getByLabelText("Upstream model ID"), {
      target: { value: "acme-model" },
    });
    fireEvent.change(screen.getByLabelText("Model display name (optional)"), {
      target: { value: "Acme Model" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Create provider" }));

    await waitFor(() => {
      expect(submittedBody).toEqual({
        display_name: "Acme Gateway",
        handle: "custom-acme",
        protocol_profile_id: "openai.chat",
        base_url: "https://acme.example/v1",
        secret: "acme-private-token",
        upstream_model_id: "acme-model",
        model_display_name: "Acme Model",
      });
    });
    expect(await screen.findByText("custom-acme")).toBeInTheDocument();
    expect(screen.getByText("Bearer")).toBeInTheDocument();
    expect(screen.queryByText("acme-private-token")).not.toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith(
      "/vulcan/manage/protocol-profiles",
      expect.objectContaining({
        headers: { Authorization: "Bearer management-token" },
      }),
    );
  });

  // This test verifies the dialog preserves the main list, expands variants in place, and returns from configuration.
  // 此测试验证 Dialog 保留主列表、原位展开变体并可从配置返回。
  it("keeps all provider selection and configuration levels inside the dialog", async () => {
    const fetchMock = vi
      .fn()
      .mockImplementation((input: string | URL | Request) => {
        const url = String(input);
        if (url === "/vulcan/manage/provider-groups")
          return Promise.resolve(jsonResponse(mixedProviderGroupResponse));
        if (url === "/vulcan/manage/provider-instances")
          return Promise.resolve(jsonResponse(emptyProviderInstancesResponse));
        return Promise.resolve(new Response(null, { status: 404 }));
      });
    vi.stubGlobal("fetch", fetchMock);
    renderPage();

    expect(
      await screen.findByText("No authorized providers yet."),
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Add provider" }));

    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(
      screen.getByText("No authorized providers yet."),
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Kimi/ }));
    expect(screen.getAllByText("CN")).toHaveLength(2);
    expect(screen.getAllByText("Global")).toHaveLength(2);
    expect(screen.getAllByText("Coding Plan")).toHaveLength(2);
    expect(
      document.querySelectorAll("[data-provider-variant-row]"),
    ).toHaveLength(3);
    expect(screen.getAllByText("openai.chat")).toHaveLength(3);
    expect(screen.getByText("https://api.moonshot.cn")).toBeInTheDocument();
    expect(screen.getByText("https://api.moonshot.ai")).toBeInTheDocument();
    expect(
      screen.getByText("https://api.kimi.com/coding/v1"),
    ).toBeInTheDocument();
    expect(screen.getByText("Add provider")).toBeInTheDocument();

    fireEvent.click(screen.getAllByRole("button", { name: /^Select / })[0]);
    expect(screen.getByText("Configure provider")).toBeInTheDocument();
    expect(screen.getAllByText("Kimi CN").length).toBeGreaterThan(0);
    // backButton must remain in the dialog title bar rather than inside the configuration form.
    // backButton 必须位于 Dialog 标题栏，而不是配置表单内部。
    const backButton = screen.getByRole("button", {
      name: "Back to providers",
    });
    expect(backButton.closest('[data-slot="dialog-header"]')).not.toBeNull();
    fireEvent.click(backButton);
    expect(screen.getByText("Add provider")).toBeInTheDocument();
    expect(screen.getAllByText("CN")).toHaveLength(2);

    fireEvent.click(screen.getByRole("button", { name: /OpenAI/ }));
    expect(screen.getByText("Configure provider")).toBeInTheDocument();
    expect(screen.getAllByText("OpenAI").length).toBeGreaterThan(0);
  });

  // This test verifies API-key onboarding refreshes the authorized list only after the atomic server commit.
  // 此测试验证仅在服务端原子提交后，API Key 录入才刷新已授权列表。
  it("refreshes the authorized list after API-key onboarding", async () => {
    let onboarded = false;
    const fetchMock = vi
      .fn()
      .mockImplementation(
        (input: string | URL | Request, init?: RequestInit) => {
          const url = String(input);
          if (url === "/vulcan/manage/provider-groups")
            return Promise.resolve(jsonResponse(kimiGroupResponse));
          if (url === "/vulcan/manage/provider-instances")
            return Promise.resolve(
              jsonResponse(
                onboarded
                  ? authorizedCNInstanceResponse
                  : emptyProviderInstancesResponse,
              ),
            );
          if (
            url === "/vulcan/manage/provider-instances/pvi_kimi_cn/credentials"
          )
            return Promise.resolve(
              jsonResponse(authorizedCNCredentialsResponse),
            );
          if (
            url === "/vulcan/manage/provider-instances/onboard" &&
            init?.method === "POST"
          ) {
            onboarded = true;
            return Promise.resolve(
              jsonResponse(
                {
                  provider_instance_id: "pvi_kimi_cn",
                  credential_id: "cred_kimi_cn",
                  endpoint_ids: ["ep_created"],
                  binding_ids: ["bind_created"],
                },
                201,
              ),
            );
          }
          return Promise.resolve(new Response(null, { status: 404 }));
        },
      );
    vi.stubGlobal("fetch", fetchMock);
    renderPage();

    expect(
      await screen.findByText("No authorized providers yet."),
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Add provider" }));
    fireEvent.click(screen.getByRole("button", { name: /Kimi/ }));
    fireEvent.click(screen.getAllByRole("button", { name: /^Select / })[0]);
    fireEvent.change(screen.getByLabelText("Name"), {
      target: { value: "Kimi CN Production" },
    });
    fireEvent.change(screen.getByLabelText("API key"), {
      target: { value: "private-kimi-key" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Create provider" }));

    expect(
      (await screen.findAllByText("Kimi CN Production")).length,
    ).toBeGreaterThan(1);
    expect(screen.queryByLabelText("Filter providers")).not.toBeInTheDocument();
    const onboardingCall = fetchMock.mock.calls.find(
      ([url]) => String(url) === "/vulcan/manage/provider-instances/onboard",
    );
    // requestBody proves the browser sends only the current single-name public contract.
    // requestBody 证明浏览器只发送当前单名称公开合同。
    const requestBody = JSON.parse(String(onboardingCall?.[1]?.body));
    expect(requestBody).toEqual({
      provider_definition_id: "system_kimi_cn",
      name: "Kimi CN Production",
      auth_method_id: "api_key",
      secret: "private-kimi-key",
    });
    expect(requestBody).not.toHaveProperty("handle");
    expect(requestBody).not.toHaveProperty("display_name");
    expect(requestBody).not.toHaveProperty("credential_label");
    expect(requestBody).not.toHaveProperty("principal_key");
    expect(onboardingCall?.[1]?.headers).toEqual(
      expect.objectContaining({ Authorization: "Bearer management-token" }),
    );
  });

  // This test verifies Vertex uses one visible name and sends parsed JSON only to its specialized endpoint.
  // 此测试验证 Vertex 仅使用一个可见名称，并只向专属入口发送已解析 JSON。
  it("onboards a Vertex service account through the dedicated protected workflow", async () => {
    const fetchMock = vi
      .fn()
      .mockImplementation(
        (input: string | URL | Request, init?: RequestInit) => {
          const url = String(input);
          if (url === "/vulcan/manage/provider-groups")
            return Promise.resolve(jsonResponse(vertexGroupResponse));
          if (url === "/vulcan/manage/provider-instances")
            return Promise.resolve(
              jsonResponse(emptyProviderInstancesResponse),
            );
          if (
            url === "/vulcan/manage/vertex/service-accounts/onboard" &&
            init?.method === "POST"
          )
            return Promise.resolve(
              jsonResponse(
                {
                  provider_instance_id: "pvi_vertex",
                  credential_id: "cred_vertex",
                  endpoint_ids: ["ep_vertex"],
                  binding_ids: ["bind_vertex"],
                },
                201,
              ),
            );
          return Promise.resolve(new Response(null, { status: 404 }));
        },
      );
    vi.stubGlobal("fetch", fetchMock);
    renderPage();

    await screen.findByText("No authorized providers yet.");
    fireEvent.click(screen.getByRole("button", { name: "Add provider" }));
    fireEvent.click(screen.getByRole("button", { name: /Google/ }));
    expect(screen.queryByLabelText("Name")).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Vertex location"), {
      target: { value: "europe-west1" },
    });
    fireEvent.change(screen.getByLabelText("Service account JSON"), {
      target: { value: "not-json" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Create provider" }));
    expect(
      await screen.findByText(
        "Enter a valid Google service account JSON object.",
      ),
    ).toBeInTheDocument();
    expect(
      fetchMock.mock.calls.some(
        ([url]) =>
          String(url) === "/vulcan/manage/vertex/service-accounts/onboard",
      ),
    ).toBe(false);

    const serviceAccount = {
      type: "service_account",
      project_id: "vertex-project",
      private_key: "private-key",
      client_email: "vertex@example.com",
      token_uri: "https://oauth2.googleapis.com/token",
    };
    fireEvent.change(screen.getByLabelText("Service account JSON"), {
      target: { value: JSON.stringify(serviceAccount) },
    });
    fireEvent.click(screen.getByRole("button", { name: "Create provider" }));
    await waitFor(() =>
      expect(
        screen.queryByLabelText("Service account JSON"),
      ).not.toBeInTheDocument(),
    );
    const onboardingCall = fetchMock.mock.calls.find(
      ([url]) =>
        String(url) === "/vulcan/manage/vertex/service-accounts/onboard",
    );
    const requestBody = JSON.parse(String(onboardingCall?.[1]?.body));
    expect(requestBody).toEqual(
      expect.objectContaining({
        location: "europe-west1",
        service_account: serviceAccount,
      }),
    );
    expect(requestBody).not.toHaveProperty("handle");
    expect(requestBody).not.toHaveProperty("display_name");
    expect(requestBody).not.toHaveProperty("credential_label");
    expect(onboardingCall?.[1]?.headers).toEqual(
      expect.objectContaining({ Authorization: "Bearer management-token" }),
    );
  });

  // This test verifies Vertex service-account replacement targets the existing credential instead of creating another instance.
  // 此测试验证 Vertex 服务账号替换指向既有凭据而不是创建另一个实例。
  it("replaces one existing Vertex service-account credential", async () => {
    const fetchMock = vi
      .fn()
      .mockImplementation(
        (input: string | URL | Request, init?: RequestInit) => {
          const url = String(input);
          if (url === "/vulcan/manage/provider-groups")
            return Promise.resolve(jsonResponse(vertexGroupResponse));
          if (url === "/vulcan/manage/provider-instances")
            return Promise.resolve(jsonResponse(authorizedVertexInstanceResponse));
          if (
            url === "/vulcan/manage/provider-instances/pvi_vertex/credentials"
          )
            return Promise.resolve(
              jsonResponse(authorizedVertexCredentialsResponse),
            );
          if (
            url === "/vulcan/manage/vertex/service-accounts/onboard" &&
            init?.method === "POST"
          )
            return Promise.resolve(
              jsonResponse({
                provider_instance_id: "pvi_vertex",
                credential_id: "cred_vertex",
                endpoint_ids: [],
                binding_ids: [],
              }),
            );
          return Promise.resolve(new Response(null, { status: 404 }));
        },
      );
    vi.stubGlobal("fetch", fetchMock);
    renderPage();

    expect(
      (
        await screen.findAllByText(
          "vertex@vertex-project.iam.gserviceaccount.com",
        )
      ).length,
    ).toBeGreaterThan(1);
    fireEvent.click(
      screen.getByRole("button", { name: "Replace credential" }),
    );
    expect(screen.queryByLabelText("Vertex location")).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Service account JSON"), {
      target: {
        value: JSON.stringify({
          type: "service_account",
          project_id: "vertex-project",
          private_key: "replacement-private-key",
          client_email: "vertex@vertex-project.iam.gserviceaccount.com",
          token_uri: "https://oauth2.googleapis.com/token",
        }),
      },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Replace credential" }),
    );
    await waitFor(() => {
      const replacementCall = fetchMock.mock.calls.find(
        ([url, init]) =>
          String(url) ===
            "/vulcan/manage/vertex/service-accounts/onboard" &&
          init?.method === "POST",
      );
      expect(replacementCall?.[1]?.body).toContain(
        '"provider_instance_id":"pvi_vertex"',
      );
      expect(replacementCall?.[1]?.body).toContain(
        '"credential_id":"cred_vertex"',
      );
    });
  });

  // This test verifies completed device authorization refreshes the list without exposing provider tokens to the browser.
  // 此测试验证完成的设备授权会刷新列表，且不会向浏览器暴露供应商令牌。
  it("refreshes the authorized list after server-confidential device authorization", async () => {
    let onboarded = false;
    const fetchMock = vi
      .fn()
      .mockImplementation(
        (input: string | URL | Request, init?: RequestInit) => {
          const url = String(input);
          if (url === "/vulcan/manage/provider-groups")
            return Promise.resolve(jsonResponse(kimiGroupResponse));
          if (url === "/vulcan/manage/provider-instances")
            return Promise.resolve(
              jsonResponse(
                onboarded
                  ? authorizedCodingInstanceResponse
                  : emptyProviderInstancesResponse,
              ),
            );
          if (
            url ===
            "/vulcan/manage/provider-instances/pvi_kimi_coding/credentials"
          )
            return Promise.resolve(
              jsonResponse(authorizedCodingCredentialsResponse),
            );
          if (
            url === "/vulcan/manage/kimi/device-flows" &&
            init?.method === "POST"
          )
            return Promise.resolve(
              jsonResponse(
                {
                  id: "flow-test",
                  user_code: "ABCD-EFGH",
                  verification_uri: "https://auth.example/verify",
                  verification_uri_complete:
                    "https://auth.example/verify?code=ABCD-EFGH",
                  expires_at: "2026-07-18T12:00:00Z",
                  poll_interval_seconds: 5,
                },
                201,
              ),
            );
          if (
            url === "/vulcan/manage/kimi/device-flows/flow-test/onboard" &&
            init?.method === "POST"
          ) {
            onboarded = true;
            return Promise.resolve(
              jsonResponse(
                {
                  provider_instance_id: "pvi_kimi_coding",
                  credential_id: "cred_kimi_coding",
                  endpoint_ids: ["ep_chat", "ep_anthropic"],
                  binding_ids: ["bind_chat", "bind_anthropic"],
                },
                201,
              ),
            );
          }
          return Promise.resolve(new Response(null, { status: 404 }));
        },
      );
    vi.stubGlobal("fetch", fetchMock);
    renderPage();

    await screen.findByText("No authorized providers yet.");
    fireEvent.click(screen.getByRole("button", { name: "Add provider" }));
    fireEvent.click(screen.getByRole("button", { name: /Kimi/ }));
    fireEvent.click(screen.getAllByRole("button", { name: /^Select / })[2]);
    fireEvent.change(screen.getByLabelText("Name"), {
      target: { value: "Kimi Coding Account" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Device authorization" }),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Start authorization" }),
    );
    expect(await screen.findByText("ABCD-EFGH")).toBeInTheDocument();
    fireEvent.click(
      screen.getByRole("button", { name: "Check authorization" }),
    );

    expect(
      (await screen.findAllByText("Kimi Coding Account")).length,
    ).toBeGreaterThan(1);
    expect(screen.getByText("Device authorization")).toBeInTheDocument();
    // deviceOnboardingCall captures the exact server-confidential completion request.
    // deviceOnboardingCall 捕获精确的服务端保密授权完成请求。
    const deviceOnboardingCall = fetchMock.mock.calls.find(([url]) =>
      String(url).endsWith("/device-flows/flow-test/onboard"),
    );
    expect(deviceOnboardingCall?.[1]?.body).toContain(
      '"name":"Kimi Coding Account"',
    );
    expect(deviceOnboardingCall?.[1]?.body).not.toContain("credential_label");
    expect(JSON.stringify(fetchMock.mock.calls)).not.toContain(
      "device-access-secret",
    );
  });

  // This test verifies Antigravity authorization exchanges only the pasted callback through the management API.
  // 此测试验证 Antigravity 授权仅通过管理 API 交换粘贴的回调地址。
  it("completes server-confidential Antigravity browser authorization", async () => {
    const fetchMock = vi
      .fn()
      .mockImplementation(
        (input: string | URL | Request, init?: RequestInit) => {
          const url = String(input);
          if (url === "/vulcan/manage/provider-groups")
            return Promise.resolve(jsonResponse(antigravityGroupResponse));
          if (url === "/vulcan/manage/provider-instances")
            return Promise.resolve(
              jsonResponse(emptyProviderInstancesResponse),
            );
          if (
            url === "/vulcan/manage/antigravity/oauth-flows" &&
            init?.method === "POST"
          )
            return Promise.resolve(
              jsonResponse(
                {
                  id: "oauth-flow-test",
                  authorization_url:
                    "https://accounts.google.com/o/oauth2/v2/auth?state=state-test",
                  redirect_uri: "http://localhost:51121/oauth-callback",
                  expires_at: "2026-07-19T12:00:00Z",
                },
                201,
              ),
            );
          if (
            url ===
              "/vulcan/manage/antigravity/oauth-flows/oauth-flow-test/onboard" &&
            init?.method === "POST"
          )
            return Promise.resolve(
              jsonResponse(
                {
                  provider_instance_id: "pvi_antigravity",
                  credential_id: "cred_antigravity",
                  endpoint_ids: ["ep_antigravity"],
                  binding_ids: ["bind_antigravity"],
                },
                201,
              ),
            );
          return Promise.resolve(new Response(null, { status: 404 }));
        },
      );
    vi.stubGlobal("fetch", fetchMock);
    renderPage();

    await screen.findByText("No authorized providers yet.");
    fireEvent.click(screen.getByRole("button", { name: "Add provider" }));
    fireEvent.click(screen.getByRole("button", { name: /Google/ }));
    fireEvent.click(
      screen.getByRole("button", { name: "Start authorization" }),
    );
    expect(
      await screen.findByRole("link", { name: "Open authorization page" }),
    ).toHaveAttribute(
      "href",
      "https://accounts.google.com/o/oauth2/v2/auth?state=state-test",
    );
    const callbackURL =
      "http://localhost:51121/oauth-callback?code=code-test&state=state-test";
    fireEvent.change(screen.getByLabelText("Callback URL"), {
      target: { value: callbackURL },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Complete authorization" }),
    );
    await waitFor(() =>
      expect(screen.queryByLabelText("Callback URL")).not.toBeInTheDocument(),
    );
    const onboardingCall = fetchMock.mock.calls.find(([url]) =>
      String(url).endsWith("/oauth-flows/oauth-flow-test/onboard"),
    );
    expect(onboardingCall?.[1]?.body).toContain(
      `"callback_url":"${callbackURL}"`,
    );
    expect(onboardingCall?.[1]?.body).not.toContain("access_token");
  });

  // This test verifies Claude Code uses the server-owned PKCE flow and accepts CLIProxyAPI's code#state form.
  // 此测试验证 Claude Code 使用服务端拥有的 PKCE 流程并接受 CLIProxyAPI 的 code#state 形式。
  it("completes server-confidential Claude Code browser authorization", async () => {
    const fetchMock = vi
      .fn()
      .mockImplementation(
        (input: string | URL | Request, init?: RequestInit) => {
          const url = String(input);
          if (url === "/vulcan/manage/provider-groups")
            return Promise.resolve(jsonResponse(claudeGroupResponse));
          if (url === "/vulcan/manage/provider-instances")
            return Promise.resolve(
              jsonResponse(emptyProviderInstancesResponse),
            );
          if (
            url === "/vulcan/manage/claude/oauth-flows" &&
            init?.method === "POST"
          )
            return Promise.resolve(
              jsonResponse(
                {
                  id: "claude-flow-test",
                  authorization_url:
                    "https://claude.ai/oauth/authorize?state=state-test",
                  redirect_uri: "http://localhost:54545/callback",
                  expires_at: "2026-07-19T12:00:00Z",
                },
                201,
              ),
            );
          if (
            url ===
              "/vulcan/manage/claude/oauth-flows/claude-flow-test/onboard" &&
            init?.method === "POST"
          )
            return Promise.resolve(
              jsonResponse(
                {
                  provider_instance_id: "pvi_claude",
                  credential_id: "cred_claude",
                  endpoint_ids: ["ep_claude"],
                  binding_ids: ["bind_claude"],
                },
                201,
              ),
            );
          return Promise.resolve(new Response(null, { status: 404 }));
        },
      );
    vi.stubGlobal("fetch", fetchMock);
    renderPage();

    await screen.findByText("No authorized providers yet.");
    fireEvent.click(screen.getByRole("button", { name: "Add provider" }));
    fireEvent.click(screen.getByRole("button", { name: /Anthropic/ }));
    expect(screen.queryByLabelText("Credential name")).not.toBeInTheDocument();
    fireEvent.click(
      screen.getByRole("button", { name: "Start authorization" }),
    );
    expect(
      await screen.findByRole("link", { name: "Open authorization page" }),
    ).toHaveAttribute(
      "href",
      "https://claude.ai/oauth/authorize?state=state-test",
    );
    expect(
      screen.getByText(
        /complete localhost callback URL or the displayed code#state/,
      ),
    ).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Callback URL"), {
      target: { value: "code-test#state-test" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Complete authorization" }),
    );
    await waitFor(() =>
      expect(screen.queryByLabelText("Callback URL")).not.toBeInTheDocument(),
    );
    const onboardingCall = fetchMock.mock.calls.find(([url]) =>
      String(url).endsWith("/oauth-flows/claude-flow-test/onboard"),
    );
    expect(onboardingCall?.[1]?.body).toContain(
      '"callback_url":"code-test#state-test"',
    );
    expect(onboardingCall?.[1]?.body).not.toContain("credential_label");
    expect(onboardingCall?.[1]?.body).not.toContain("display_name");
    expect(onboardingCall?.[1]?.body).not.toContain("handle");
    expect(onboardingCall?.[1]?.body).not.toContain("access_token");
  });

  // This test verifies Codex defaults to browser OAuth while retaining the explicit CLIProxyAPI device-flow alternative.
  // 此测试验证 Codex 默认使用浏览器 OAuth，同时保留 CLIProxyAPI 的显式设备授权备选方式。
  it("completes default Codex browser authorization and exposes device authorization", async () => {
    const fetchMock = vi
      .fn()
      .mockImplementation(
        (input: string | URL | Request, init?: RequestInit) => {
          const url = String(input);
          if (url === "/vulcan/manage/provider-groups")
            return Promise.resolve(jsonResponse(codexGroupResponse));
          if (url === "/vulcan/manage/provider-instances")
            return Promise.resolve(
              jsonResponse(emptyProviderInstancesResponse),
            );
          if (
            url === "/vulcan/manage/codex/oauth-flows" &&
            init?.method === "POST"
          )
            return Promise.resolve(
              jsonResponse(
                {
                  id: "codex-oauth-flow-test",
                  authorization_url:
                    "https://auth.openai.com/oauth/authorize?state=state-test",
                  redirect_uri: "http://localhost:1455/auth/callback",
                  expires_at: "2026-07-19T12:00:00Z",
                },
                201,
              ),
            );
          if (
            url ===
              "/vulcan/manage/codex/oauth-flows/codex-oauth-flow-test/onboard" &&
            init?.method === "POST"
          )
            return Promise.resolve(
              jsonResponse(
                {
                  provider_instance_id: "pvi_codex",
                  credential_id: "cred_codex",
                  endpoint_ids: ["ep_codex"],
                  binding_ids: ["bind_codex"],
                },
                201,
              ),
            );
          return Promise.resolve(new Response(null, { status: 404 }));
        },
      );
    vi.stubGlobal("fetch", fetchMock);
    renderPage();

    await screen.findByText("No authorized providers yet.");
    fireEvent.click(screen.getByRole("button", { name: "Add provider" }));
    fireEvent.click(screen.getByRole("button", { name: /OpenAI/ }));
    expect(
      screen.getByRole("button", { name: "Device authorization" }),
    ).toBeInTheDocument();
    expect(screen.queryByLabelText("Credential name")).not.toBeInTheDocument();
    fireEvent.click(
      screen.getByRole("button", { name: "Start authorization" }),
    );
    expect(
      await screen.findByRole("link", { name: "Open authorization page" }),
    ).toHaveAttribute(
      "href",
      "https://auth.openai.com/oauth/authorize?state=state-test",
    );
    const callbackURL =
      "http://localhost:1455/auth/callback?code=code-test&state=state-test";
    fireEvent.change(screen.getByLabelText("Callback URL"), {
      target: { value: callbackURL },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Complete authorization" }),
    );
    await waitFor(() =>
      expect(screen.queryByLabelText("Callback URL")).not.toBeInTheDocument(),
    );
    const onboardingCall = fetchMock.mock.calls.find(([url]) =>
      String(url).endsWith("/codex/oauth-flows/codex-oauth-flow-test/onboard"),
    );
    expect(onboardingCall?.[1]?.body).toContain(
      `"callback_url":"${callbackURL}"`,
    );
    expect(onboardingCall?.[1]?.body).not.toContain("credential_label");
    expect(onboardingCall?.[1]?.body).not.toContain("display_name");
    expect(onboardingCall?.[1]?.body).not.toContain("handle");
    expect(onboardingCall?.[1]?.body).not.toContain("access_token");
  });

  // This test verifies a Codex start response arriving after dialog close is reclaimed through its original OAuth route.
  // 此测试验证 Dialog 关闭后才到达的 Codex 启动响应会通过其原始 OAuth 路由回收。
  it("reclaims a late Codex authorization session after dialog close", async () => {
    // resolveAuthorizationStart releases the deliberately delayed server response after the panel has unmounted.
    // resolveAuthorizationStart 在面板卸载后释放刻意延迟的服务端响应。
    let resolveAuthorizationStart: ((response: Response) => void) | undefined;
    // authorizationStartResponse models a start request that outlives the creation dialog.
    // authorizationStartResponse 模拟生命周期长于新增 Dialog 的启动请求。
    const authorizationStartResponse = new Promise<Response>((resolve) => {
      resolveAuthorizationStart = resolve;
    });
    const fetchMock = vi
      .fn()
      .mockImplementation(
        (input: string | URL | Request, init?: RequestInit) => {
          const url = String(input);
          if (url === "/vulcan/manage/provider-groups")
            return Promise.resolve(jsonResponse(codexGroupResponse));
          if (url === "/vulcan/manage/provider-instances")
            return Promise.resolve(
              jsonResponse(emptyProviderInstancesResponse),
            );
          if (
            url === "/vulcan/manage/codex/oauth-flows" &&
            init?.method === "POST"
          )
            return authorizationStartResponse;
          if (
            url === "/vulcan/manage/codex/oauth-flows/codex-late-flow-test" &&
            init?.method === "DELETE"
          )
            return Promise.resolve(new Response(null, { status: 204 }));
          return Promise.resolve(new Response(null, { status: 404 }));
        },
      );
    vi.stubGlobal("fetch", fetchMock);
    renderPage();

    await screen.findByText("No authorized providers yet.");
    fireEvent.click(screen.getByRole("button", { name: "Add provider" }));
    fireEvent.click(screen.getByRole("button", { name: /OpenAI/ }));
    fireEvent.click(
      screen.getByRole("button", { name: "Start authorization" }),
    );
    expect(
      screen.getByRole("button", { name: "Device authorization" }),
    ).toBeDisabled();
    fireEvent.click(
      screen.getByRole("button", { name: "Close provider creation" }),
    );
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();

    resolveAuthorizationStart?.(
      jsonResponse(
        {
          id: "codex-late-flow-test",
          authorization_url:
            "https://auth.openai.com/oauth/authorize?state=late-state",
          redirect_uri: "http://localhost:1455/auth/callback",
          expires_at: "2026-07-19T12:00:00Z",
        },
        201,
      ),
    );
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/vulcan/manage/codex/oauth-flows/codex-late-flow-test",
        expect.objectContaining({ method: "DELETE" }),
      ),
    );
  });

  // This test verifies persisted plan, credit, and reset-window data loads locally before any explicit upstream refresh.
  // 此测试验证已持久化的套餐、积分与重置窗口数据会在任何显式上游刷新前从本地加载。
  it("loads cached account metadata and still permits an explicit refresh", async () => {
    // cachedMetadata is the redacted database snapshot returned by both local reads and a later explicit refresh.
    // cachedMetadata 是本地读取与后续显式刷新返回的脱敏数据库快照。
    const cachedMetadata = {
      provider_instance_id: "pvi_antigravity",
      models: [
        {
          id: "model_gemini_3_pro",
          upstream_model_id: "gemini-3-pro-preview",
          display_name: "Gemini 3 Pro",
          entitlement_mode: "all_bound_credentials",
          enabled: true,
          authorization_status: "authorized",
          offerings: [],
        },
      ],
      plans: [
        {
          plan_code: "pro",
          plan_name: "Google AI Pro",
          status: "active",
          credential_count: 1,
        },
      ],
      allowances: [
        {
          credential_id: "cred_antigravity",
          credential_label: "Google Account",
          kind: "balance",
          scope: "credential",
          metric: "GOOGLE_ONE_AI",
          unit: "provider_credits",
          limit: "1000",
          used: "250",
          remaining: "750",
          status: "available",
          mandatory: false,
          observed_at: "2026-07-19T12:00:00Z",
          expires_at: "2026-07-19T12:10:00Z",
        },
        {
          kind: "window_quota",
          scope: "credential",
          metric: "monthly_requests",
          unit: "requests",
          remaining_ratio: 0.5,
          status: "low",
          mandatory: true,
          window: {
            kind: "calendar",
            duration: "0",
            calendar_unit: "month",
            time_zone: "Asia/Shanghai",
            reset_at: "2026-08-01T00:00:00+08:00",
          },
          observed_at: "2026-07-19T12:00:00Z",
          expires_at: "2026-07-19T12:10:00Z",
        },
        {
          kind: "window_quota",
          scope: "credential",
          metric: "limit_1",
          unit: "provider_defined",
          limit: "100",
          used: "0",
          remaining: "100",
          remaining_ratio: 1,
          status: "available",
          mandatory: false,
          window: {
            kind: "rolling",
            duration: "18000000000000",
            reset_at: "2026-07-19T17:00:00Z",
          },
          observed_at: "2026-07-19T12:00:00Z",
          expires_at: "2026-07-19T12:10:00Z",
        },
      ],
      revision: 2,
      observed_at: "2026-07-19T12:00:00Z",
    };
    const fetchMock = vi
      .fn()
      .mockImplementation(
        (input: string | URL | Request, init?: RequestInit) => {
          const url = String(input);
          if (url === "/vulcan/manage/provider-groups")
            return Promise.resolve(jsonResponse(antigravityGroupResponse));
          if (url === "/vulcan/manage/provider-instances")
            return Promise.resolve(jsonResponse(authorizedAntigravityResponse));
          if (
            url ===
            "/vulcan/manage/provider-instances/pvi_antigravity/credentials"
          )
            return Promise.resolve(
              jsonResponse(authorizedAntigravityCredentialsResponse),
            );
          if (
            url ===
              "/vulcan/manage/provider-instances/pvi_antigravity/catalog" &&
            init?.method === "GET"
          )
            return Promise.resolve(jsonResponse(cachedMetadata));
          if (
            url ===
              "/vulcan/manage/provider-instances/pvi_antigravity/catalog/refresh" &&
            init?.method === "POST"
          )
            return Promise.resolve(jsonResponse(cachedMetadata));
          return Promise.resolve(new Response(null, { status: 404 }));
        },
      );
    vi.stubGlobal("fetch", fetchMock);
    renderPage();

    await screen.findAllByText("Google Account");
    expect(await screen.findByText("Google AI Pro")).toBeInTheDocument();
    expect(await screen.findByText("5-hour usage window")).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith(
      "/vulcan/manage/provider-instances/pvi_antigravity/catalog",
      expect.objectContaining({ method: "GET" }),
    );
    expect(fetchMock).not.toHaveBeenCalledWith(
      "/vulcan/manage/provider-instances/pvi_antigravity/catalog/refresh",
      expect.anything(),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Refresh account data" }),
    );
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/vulcan/manage/provider-instances/pvi_antigravity/catalog/refresh",
        expect.objectContaining({ method: "POST" }),
      ),
    );
    expect(screen.getByText("Gemini 3 Pro")).toBeInTheDocument();
    expect(screen.getByText("gemini-3-pro-preview")).toBeInTheDocument();
    expect(screen.getByText("Google One AI credits")).toBeInTheDocument();
    expect(screen.getAllByText("Google Account").length).toBeGreaterThan(1);
    expect(screen.getByText("750 provider_credits")).toBeInTheDocument();
    expect(screen.getByText(/Remaining: 50%/)).toBeInTheDocument();
    expect(
      screen.getByText(/Window: calendar · month · Asia\/Shanghai/),
    ).toBeInTheDocument();
    expect(screen.getAllByText(/Resets at:/).length).toBeGreaterThanOrEqual(2);
  });

  // This test verifies one refreshable account credential is rotated only through its exact protected management route.
  // 此测试验证一个可刷新账号凭据仅通过其精确的受保护管理路由进行轮换。
  it("refreshes one exact provider credential", async () => {
    const fetchMock = vi
      .fn()
      .mockImplementation(
        (input: string | URL | Request, init?: RequestInit) => {
          const url = String(input);
          if (url === "/vulcan/manage/provider-groups")
            return Promise.resolve(jsonResponse(antigravityGroupResponse));
          if (url === "/vulcan/manage/provider-instances")
            return Promise.resolve(jsonResponse(authorizedAntigravityResponse));
          if (
            url ===
            "/vulcan/manage/provider-instances/pvi_antigravity/credentials"
          )
            return Promise.resolve(
              jsonResponse(authorizedAntigravityCredentialsResponse),
            );
          if (
            url ===
              "/vulcan/manage/provider-instances/pvi_antigravity/credentials/cred_antigravity/refresh" &&
            init?.method === "POST"
          )
            return Promise.resolve(jsonResponse({ id: "cred_antigravity" }));
          return Promise.resolve(new Response(null, { status: 404 }));
        },
      );
    vi.stubGlobal("fetch", fetchMock);
    renderPage();

    expect(await screen.findByText("Google Account")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Refresh credential" }));
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/vulcan/manage/provider-instances/pvi_antigravity/credentials/cred_antigravity/refresh",
        expect.objectContaining({
          method: "POST",
          headers: { Authorization: "Bearer management-token" },
        }),
      ),
    );
    expect(
      screen.queryByText(/Unable to refresh this credential/),
    ).not.toBeInTheDocument();
  });

  // This test verifies reauthorization reuses the exact OAuth workflow and targets the existing credential.
  // 此测试验证重新授权复用精确 OAuth 流程并指向既有凭据。
  it("reauthorizes one existing provider credential", async () => {
    const fetchMock = vi
      .fn()
      .mockImplementation(
        (input: string | URL | Request, init?: RequestInit) => {
          const url = String(input);
          if (url === "/vulcan/manage/provider-groups")
            return Promise.resolve(jsonResponse(antigravityGroupResponse));
          if (url === "/vulcan/manage/provider-instances")
            return Promise.resolve(jsonResponse(authorizedAntigravityResponse));
          if (
            url ===
            "/vulcan/manage/provider-instances/pvi_antigravity/credentials"
          )
            return Promise.resolve(
              jsonResponse(authorizedAntigravityCredentialsResponse),
            );
          if (
            url === "/vulcan/manage/antigravity/oauth-flows" &&
            init?.method === "POST"
          )
            return Promise.resolve(
              jsonResponse(
                {
                  id: "reauthorize-flow",
                  authorization_url: "https://accounts.google.com/authorize",
                  redirect_uri: "http://localhost:51121/oauth-callback",
                  expires_at: "2026-07-21T02:00:00Z",
                },
                201,
              ),
            );
          if (
            url ===
              "/vulcan/manage/antigravity/oauth-flows/reauthorize-flow/onboard" &&
            init?.method === "POST"
          )
            return Promise.resolve(
              jsonResponse({
                provider_instance_id: "pvi_antigravity",
                credential_id: "cred_antigravity",
                endpoint_ids: [],
                binding_ids: [],
              }),
            );
          return Promise.resolve(new Response(null, { status: 404 }));
        },
      );
    vi.stubGlobal("fetch", fetchMock);
    renderPage();

    expect(await screen.findByText("Google Account")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Reauthorize" }));
    fireEvent.click(screen.getByRole("button", { name: "Start authorization" }));
    await screen.findByRole("link", { name: "Open authorization page" });
    fireEvent.change(screen.getByLabelText("Callback URL"), {
      target: { value: "http://localhost:51121/oauth-callback?code=test" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Complete authorization" }),
    );
    await waitFor(() => {
      const call = fetchMock.mock.calls.find(
        ([url, init]) =>
          String(url).endsWith("/reauthorize-flow/onboard") &&
          init?.method === "POST",
      );
      expect(call).toBeDefined();
      expect(call?.[1]?.body).toContain(
        '"provider_instance_id":"pvi_antigravity"',
      );
      expect(call?.[1]?.body).toContain(
        '"credential_id":"cred_antigravity"',
      );
    });
  });

  // This test verifies credential deletion is gated by confirmation and uses the exact local target.
  // 此测试验证凭据删除受确认保护并使用精确本地目标。
  it("confirms and deletes one provider credential", async () => {
    const fetchMock = vi
      .fn()
      .mockImplementation(
        (input: string | URL | Request, init?: RequestInit) => {
          const url = String(input);
          if (url === "/vulcan/manage/provider-groups")
            return Promise.resolve(jsonResponse(antigravityGroupResponse));
          if (url === "/vulcan/manage/provider-instances")
            return Promise.resolve(jsonResponse(authorizedAntigravityResponse));
          if (
            url ===
            "/vulcan/manage/provider-instances/pvi_antigravity/credentials"
          )
            return Promise.resolve(
              jsonResponse(authorizedAntigravityCredentialsResponse),
            );
          if (
            url ===
              "/vulcan/manage/provider-instances/pvi_antigravity/credentials/cred_antigravity" &&
            init?.method === "DELETE"
          )
            return Promise.resolve(new Response(null, { status: 204 }));
          return Promise.resolve(new Response(null, { status: 404 }));
        },
      );
    vi.stubGlobal("fetch", fetchMock);
    renderPage();

    expect(await screen.findByText("Google Account")).toBeInTheDocument();
    fireEvent.click(
      screen.getByRole("button", { name: "Delete credential" }),
    );
    expect(await screen.findByText("Delete this credential?")).toBeInTheDocument();
    const deleteButtons = screen.getAllByRole("button", {
      name: "Delete credential",
    });
    fireEvent.click(deleteButtons[deleteButtons.length - 1]);
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/vulcan/manage/provider-instances/pvi_antigravity/credentials/cred_antigravity",
        expect.objectContaining({ method: "DELETE" }),
      ),
    );
  });

  // This test verifies every credential refresh failure category produces exact retry-safe guidance.
  // 此测试验证每种凭据刷新失败分类都会生成精确且可安全重试的指引。
  it.each(credentialRefreshFailureCases)(
    "renders $name credential refresh guidance",
    async (failure) => {
      const fetchMock = vi
        .fn()
        .mockImplementation(
          (input: string | URL | Request, init?: RequestInit) => {
            const url = String(input);
            if (url === "/vulcan/manage/provider-groups")
              return Promise.resolve(jsonResponse(antigravityGroupResponse));
            if (url === "/vulcan/manage/provider-instances")
              return Promise.resolve(
                jsonResponse(authorizedAntigravityResponse),
              );
            if (
              url ===
              "/vulcan/manage/provider-instances/pvi_antigravity/credentials"
            )
              return Promise.resolve(
                jsonResponse(authorizedAntigravityCredentialsResponse),
              );
            if (
              url ===
                "/vulcan/manage/provider-instances/pvi_antigravity/credentials/cred_antigravity/refresh" &&
              init?.method === "POST"
            ) {
              if (failure.status === null) {
                return Promise.reject(new TypeError("network unavailable"));
              }
              return Promise.resolve(
                jsonResponse({ error: failure.code }, failure.status),
              );
            }
            return Promise.resolve(new Response(null, { status: 404 }));
          },
        );
      vi.stubGlobal("fetch", fetchMock);
      renderPage();

      expect(await screen.findByText("Google Account")).toBeInTheDocument();
      fireEvent.click(
        screen.getByRole("button", { name: "Refresh credential" }),
      );
      expect(await screen.findByText(failure.message)).toBeInTheDocument();
    },
  );

  // This test verifies a rejected saved credential is distinguished from a temporary provider outage.
  // 此测试验证已保存凭据被拒绝时能够与供应商临时不可用明确区分。
  it("renders an actionable metadata authentication failure", async () => {
    const fetchMock = vi
      .fn()
      .mockImplementation(
        (input: string | URL | Request, init?: RequestInit) => {
          const url = String(input);
          if (url === "/vulcan/manage/provider-groups")
            return Promise.resolve(jsonResponse(antigravityGroupResponse));
          if (url === "/vulcan/manage/provider-instances")
            return Promise.resolve(jsonResponse(authorizedAntigravityResponse));
          if (
            url ===
            "/vulcan/manage/provider-instances/pvi_antigravity/credentials"
          )
            return Promise.resolve(
              jsonResponse(authorizedAntigravityCredentialsResponse),
            );
          if (
            url ===
              "/vulcan/manage/provider-instances/pvi_antigravity/catalog/refresh" &&
            init?.method === "POST"
          )
            return Promise.resolve(
              jsonResponse(
                { error: "provider_metadata_authentication_failed" },
                424,
              ),
            );
          return Promise.resolve(new Response(null, { status: 404 }));
        },
      );
    vi.stubGlobal("fetch", fetchMock);
    renderPage();

    expect(await screen.findByText("Google Account")).toBeInTheDocument();
    fireEvent.click(
      screen.getByRole("button", { name: "Refresh account data" }),
    );
    expect(
      await screen.findByText(
        "The saved credential was rejected. Reauthorize this provider.",
      ),
    ).toBeInTheDocument();
  });

  // This test verifies an unfinished server-owned device authorization can be explicitly released.
  // 此测试验证未完成且由服务端拥有的设备授权可以被显式释放。
  it("cancels an unfinished server-owned device authorization", async () => {
    const fetchMock = vi
      .fn()
      .mockImplementation(
        (input: string | URL | Request, init?: RequestInit) => {
          const url = String(input);
          if (url === "/vulcan/manage/provider-groups")
            return Promise.resolve(jsonResponse(kimiGroupResponse));
          if (url === "/vulcan/manage/provider-instances")
            return Promise.resolve(
              jsonResponse(emptyProviderInstancesResponse),
            );
          if (
            url === "/vulcan/manage/kimi/device-flows" &&
            init?.method === "POST"
          )
            return Promise.resolve(
              jsonResponse(
                {
                  id: "flow-cancel",
                  user_code: "CANCEL-ME",
                  verification_uri: "https://auth.example/verify",
                  verification_uri_complete:
                    "https://auth.example/verify?code=CANCEL-ME",
                  expires_at: "2026-07-18T12:00:00Z",
                  poll_interval_seconds: 5,
                },
                201,
              ),
            );
          if (
            url === "/vulcan/manage/kimi/device-flows/flow-cancel" &&
            init?.method === "DELETE"
          )
            return Promise.resolve(new Response(null, { status: 204 }));
          return Promise.resolve(new Response(null, { status: 404 }));
        },
      );
    vi.stubGlobal("fetch", fetchMock);
    renderPage();

    await screen.findByText("No authorized providers yet.");
    fireEvent.click(screen.getByRole("button", { name: "Add provider" }));
    fireEvent.click(screen.getByRole("button", { name: /Kimi/ }));
    fireEvent.click(screen.getAllByRole("button", { name: /^Select / })[2]);
    fireEvent.click(
      screen.getByRole("button", { name: "Device authorization" }),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Start authorization" }),
    );
    expect(await screen.findByText("CANCEL-ME")).toBeInTheDocument();
    fireEvent.click(
      screen.getByRole("button", { name: "Cancel authorization" }),
    );

    await waitFor(() =>
      expect(screen.queryByText("CANCEL-ME")).not.toBeInTheDocument(),
    );
    expect(fetchMock).toHaveBeenCalledWith(
      "/vulcan/manage/kimi/device-flows/flow-cancel",
      expect.objectContaining({
        method: "DELETE",
        headers: { Authorization: "Bearer management-token" },
      }),
    );
  });
});
