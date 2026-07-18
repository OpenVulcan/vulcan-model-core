import { fireEvent, render, screen, waitFor } from "@testing-library/react"
import { afterEach, describe, expect, it, vi } from "vitest"

import { I18nProvider } from "@/i18n"
import { ProviderManagementPage } from "@/pages/provider-management-page"

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
          auth_methods: [{ id: "api_key", type: "api_key", refreshable: false }],
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
          auth_methods: [{ id: "api_key", type: "api_key", refreshable: false }],
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
}

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
          auth_methods: [{ id: "api_key", type: "api_key", refreshable: false }],
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
}

// emptyProviderInstancesResponse represents a management account with no completed authorization.
// emptyProviderInstancesResponse 表示尚无已完成授权的管理账户。
const emptyProviderInstancesResponse = { provider_instances: [] }

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
}

// authorizedCNCredentialsResponse is the redacted API authorization list for the configured CN instance.
// authorizedCNCredentialsResponse 是已配置 CN 实例的脱敏 API 授权列表。
const authorizedCNCredentialsResponse = {
  credentials: [
    {
      id: "cred_kimi_cn",
      provider_instance_id: "pvi_kimi_cn",
      auth_method_id: "api_key",
      label: "Production API",
      status: "active",
      expires_at: null,
      cooling_until: null,
      revision: 1,
    },
  ],
}

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
}

// authorizedCodingCredentialsResponse is the redacted device authorization list for the Coding Plan instance.
// authorizedCodingCredentialsResponse 是 Coding Plan 实例的脱敏设备授权列表。
const authorizedCodingCredentialsResponse = {
  credentials: [
    {
      id: "cred_kimi_coding",
      provider_instance_id: "pvi_kimi_coding",
      auth_method_id: "device_flow",
      label: "Kimi User",
      status: "active",
      expires_at: "2026-07-18T13:00:00Z",
      cooling_until: null,
      revision: 1,
    },
  ],
}

// jsonResponse creates one JSON response with a stable content type for route-aware mocks.
// jsonResponse 为按路由模拟创建一个内容类型稳定的 JSON 响应。
function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "Content-Type": "application/json" },
  })
}

// renderPage mounts the provider page with one authenticated management credential.
// renderPage 使用一个已认证管理凭证挂载供应商页面。
function renderPage() {
  render(
    <I18nProvider>
      <ProviderManagementPage managementAuthToken="management-token" />
    </I18nProvider>,
  )
}

describe("ProviderManagementPage", () => {
  afterEach(() => vi.unstubAllGlobals())

  // This test verifies the authorized list is primary and provider filtering precedes exact variant selection.
  // 此测试验证已授权列表是主视图，且供应商过滤先于精确变体选择。
  it("lists authorized providers before opening the filterable two-level creation flow", async () => {
    const fetchMock = vi.fn().mockImplementation((input: string | URL | Request) => {
      const url = String(input)
      if (url === "/vulcan/manage/provider-groups") return Promise.resolve(jsonResponse(kimiGroupResponse))
      if (url === "/vulcan/manage/provider-instances")
        return Promise.resolve(jsonResponse(authorizedCNInstanceResponse))
      if (url === "/vulcan/manage/provider-instances/pvi_kimi_cn/credentials")
        return Promise.resolve(jsonResponse(authorizedCNCredentialsResponse))
      return Promise.resolve(new Response(null, { status: 404 }))
    })
    vi.stubGlobal("fetch", fetchMock)

    renderPage()

    expect(await screen.findByText("Kimi CN Production")).toBeInTheDocument()
    expect(screen.getByText("Production API")).toBeInTheDocument()
    expect(screen.getByText("API key")).toBeInTheDocument()
    expect(screen.queryByText("Coding Plan")).not.toBeInTheDocument()

    fireEvent.click(screen.getByRole("button", { name: "Add provider" }))
    fireEvent.change(screen.getByLabelText("Filter providers"), {
      target: { value: "Global" },
    })
    fireEvent.click(screen.getByRole("button", { name: /Kimi/ }))

    // providerOptionRows excludes the always-visible summary badges from filtered option assertions.
    // providerOptionRows 在筛选后的选项断言中排除始终显示的摘要标签。
    const providerOptionRows = document.querySelectorAll("[data-provider-variant-row]")
    expect(providerOptionRows).toHaveLength(1)
    expect(providerOptionRows[0]).toHaveTextContent("Global")
    expect(providerOptionRows[0]).not.toHaveTextContent("CN")
    expect(providerOptionRows[0]).not.toHaveTextContent("Coding Plan")
    expect(fetchMock).toHaveBeenCalledWith(
      "/vulcan/manage/provider-groups",
      expect.objectContaining({
        headers: { Authorization: "Bearer management-token" },
      }),
    )
  })

  // This test verifies an authorized-list failure cannot leave the still-available creation workflow blank.
  // 此测试验证已授权列表失败时，仍可用的新增流程不会出现空白。
  it("keeps provider creation usable when only the authorized list fails", async () => {
    const fetchMock = vi.fn().mockImplementation((input: string | URL | Request) => {
      const url = String(input)
      if (url === "/vulcan/manage/provider-groups") return Promise.resolve(jsonResponse(kimiGroupResponse))
      if (url === "/vulcan/manage/provider-instances") return Promise.resolve(jsonResponse({ error: "temporary" }, 500))
      return Promise.resolve(new Response(null, { status: 404 }))
    })
    vi.stubGlobal("fetch", fetchMock)
    renderPage()

    expect(await screen.findByText("Unable to load the authorized provider list.")).toBeInTheDocument()
    fireEvent.click(screen.getByRole("button", { name: "Add provider" }))

    expect(screen.getByRole("button", { name: /Kimi/ })).toBeInTheDocument()
    expect(screen.getByLabelText("Filter providers")).toBeInTheDocument()
  })

  // This test verifies the dialog preserves the main list, expands variants in place, and returns from configuration.
  // 此测试验证 Dialog 保留主列表、原位展开变体并可从配置返回。
  it("keeps all provider selection and configuration levels inside the dialog", async () => {
    const fetchMock = vi.fn().mockImplementation((input: string | URL | Request) => {
      const url = String(input)
      if (url === "/vulcan/manage/provider-groups") return Promise.resolve(jsonResponse(mixedProviderGroupResponse))
      if (url === "/vulcan/manage/provider-instances")
        return Promise.resolve(jsonResponse(emptyProviderInstancesResponse))
      return Promise.resolve(new Response(null, { status: 404 }))
    })
    vi.stubGlobal("fetch", fetchMock)
    renderPage()

    expect(await screen.findByText("No authorized providers yet.")).toBeInTheDocument()
    fireEvent.click(screen.getByRole("button", { name: "Add provider" }))

    expect(screen.getByRole("dialog")).toBeInTheDocument()
    expect(screen.getByText("No authorized providers yet.")).toBeInTheDocument()
    fireEvent.click(screen.getByRole("button", { name: /Kimi/ }))
    expect(screen.getAllByText("CN")).toHaveLength(2)
    expect(screen.getAllByText("Global")).toHaveLength(2)
    expect(screen.getAllByText("Coding Plan")).toHaveLength(2)
    expect(document.querySelectorAll("[data-provider-variant-row]")).toHaveLength(3)
    expect(screen.getAllByText("openai.chat")).toHaveLength(3)
    expect(screen.queryByText("https://api.moonshot.cn")).not.toBeInTheDocument()
    expect(screen.getByText("Add provider")).toBeInTheDocument()

    fireEvent.click(screen.getAllByRole("button", { name: /^Select / })[0])
    expect(screen.getByText("Configure provider")).toBeInTheDocument()
    expect(screen.getAllByText("Kimi CN").length).toBeGreaterThan(0)
    // backButton must remain in the dialog title bar rather than inside the configuration form.
    // backButton 必须位于 Dialog 标题栏，而不是配置表单内部。
    const backButton = screen.getByRole("button", { name: "Back to providers" })
    expect(backButton.closest('[data-slot="dialog-header"]')).not.toBeNull()
    fireEvent.click(backButton)
    expect(screen.getByText("Add provider")).toBeInTheDocument()
    expect(screen.getAllByText("CN")).toHaveLength(2)

    fireEvent.click(screen.getByRole("button", { name: /OpenAI/ }))
    expect(screen.getByText("Configure provider")).toBeInTheDocument()
    expect(screen.getAllByText("OpenAI").length).toBeGreaterThan(0)
  })

  // This test verifies API-key onboarding refreshes the authorized list only after the atomic server commit.
  // 此测试验证仅在服务端原子提交后，API Key 录入才刷新已授权列表。
  it("refreshes the authorized list after API-key onboarding", async () => {
    let onboarded = false
    const fetchMock = vi.fn().mockImplementation((input: string | URL | Request, init?: RequestInit) => {
      const url = String(input)
      if (url === "/vulcan/manage/provider-groups") return Promise.resolve(jsonResponse(kimiGroupResponse))
      if (url === "/vulcan/manage/provider-instances")
        return Promise.resolve(jsonResponse(onboarded ? authorizedCNInstanceResponse : emptyProviderInstancesResponse))
      if (url === "/vulcan/manage/provider-instances/pvi_kimi_cn/credentials")
        return Promise.resolve(jsonResponse(authorizedCNCredentialsResponse))
      if (url === "/vulcan/manage/provider-instances/onboard" && init?.method === "POST") {
        onboarded = true
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
        )
      }
      return Promise.resolve(new Response(null, { status: 404 }))
    })
    vi.stubGlobal("fetch", fetchMock)
    renderPage()

    expect(await screen.findByText("No authorized providers yet.")).toBeInTheDocument()
    fireEvent.click(screen.getByRole("button", { name: "Add provider" }))
    fireEvent.click(screen.getByRole("button", { name: /Kimi/ }))
    fireEvent.click(screen.getAllByRole("button", { name: /^Select / })[0])
    fireEvent.change(screen.getByLabelText("Display name"), {
      target: { value: "Kimi CN Production" },
    })
    fireEvent.change(screen.getByLabelText("Credential label"), {
      target: { value: "Production API" },
    })
    fireEvent.change(screen.getByLabelText("API key"), {
      target: { value: "private-kimi-key" },
    })
    fireEvent.click(screen.getByRole("button", { name: "Create provider" }))

    expect(await screen.findByText("Kimi CN Production")).toBeInTheDocument()
    expect(screen.getByText("Production API")).toBeInTheDocument()
    expect(screen.queryByLabelText("Filter providers")).not.toBeInTheDocument()
    const onboardingCall = fetchMock.mock.calls.find(
      ([url]) => String(url) === "/vulcan/manage/provider-instances/onboard",
    )
    expect(onboardingCall?.[1]?.body).toContain('"secret":"private-kimi-key"')
    expect(onboardingCall?.[1]?.headers).toEqual(expect.objectContaining({ Authorization: "Bearer management-token" }))
  })

  // This test verifies completed device authorization refreshes the list without exposing provider tokens to the browser.
  // 此测试验证完成的设备授权会刷新列表，且不会向浏览器暴露供应商令牌。
  it("refreshes the authorized list after server-confidential device authorization", async () => {
    let onboarded = false
    const fetchMock = vi.fn().mockImplementation((input: string | URL | Request, init?: RequestInit) => {
      const url = String(input)
      if (url === "/vulcan/manage/provider-groups") return Promise.resolve(jsonResponse(kimiGroupResponse))
      if (url === "/vulcan/manage/provider-instances")
        return Promise.resolve(
          jsonResponse(onboarded ? authorizedCodingInstanceResponse : emptyProviderInstancesResponse),
        )
      if (url === "/vulcan/manage/provider-instances/pvi_kimi_coding/credentials")
        return Promise.resolve(jsonResponse(authorizedCodingCredentialsResponse))
      if (url === "/vulcan/manage/kimi/device-flows" && init?.method === "POST")
        return Promise.resolve(
          jsonResponse(
            {
              id: "flow-test",
              user_code: "ABCD-EFGH",
              verification_uri: "https://auth.example/verify",
              verification_uri_complete: "https://auth.example/verify?code=ABCD-EFGH",
              expires_at: "2026-07-18T12:00:00Z",
              poll_interval_seconds: 5,
            },
            201,
          ),
        )
      if (url === "/vulcan/manage/kimi/device-flows/flow-test/onboard" && init?.method === "POST") {
        onboarded = true
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
        )
      }
      return Promise.resolve(new Response(null, { status: 404 }))
    })
    vi.stubGlobal("fetch", fetchMock)
    renderPage()

    await screen.findByText("No authorized providers yet.")
    fireEvent.click(screen.getByRole("button", { name: "Add provider" }))
    fireEvent.click(screen.getByRole("button", { name: /Kimi/ }))
    fireEvent.click(screen.getAllByRole("button", { name: /^Select / })[2])
    fireEvent.click(screen.getByRole("button", { name: "Device authorization" }))
    fireEvent.click(screen.getByRole("button", { name: "Start Kimi authorization" }))
    expect(await screen.findByText("ABCD-EFGH")).toBeInTheDocument()
    fireEvent.click(screen.getByRole("button", { name: "Check authorization" }))

    expect(await screen.findByText("Kimi Coding Account")).toBeInTheDocument()
    expect(screen.getByText("Kimi User")).toBeInTheDocument()
    expect(screen.getByText("Device authorization")).toBeInTheDocument()
    // deviceOnboardingCall captures the exact server-confidential completion request.
    // deviceOnboardingCall 捕获精确的服务端保密授权完成请求。
    const deviceOnboardingCall = fetchMock.mock.calls.find(([url]) =>
      String(url).endsWith("/device-flows/flow-test/onboard"),
    )
    expect(deviceOnboardingCall?.[1]?.body).toContain('"credential_label":"Kimi User"')
    expect(JSON.stringify(fetchMock.mock.calls)).not.toContain("device-access-secret")
  })

  // This test verifies an unfinished server-owned device authorization can be explicitly released.
  // 此测试验证未完成且由服务端拥有的设备授权可以被显式释放。
  it("cancels an unfinished server-owned device authorization", async () => {
    const fetchMock = vi.fn().mockImplementation((input: string | URL | Request, init?: RequestInit) => {
      const url = String(input)
      if (url === "/vulcan/manage/provider-groups") return Promise.resolve(jsonResponse(kimiGroupResponse))
      if (url === "/vulcan/manage/provider-instances")
        return Promise.resolve(jsonResponse(emptyProviderInstancesResponse))
      if (url === "/vulcan/manage/kimi/device-flows" && init?.method === "POST")
        return Promise.resolve(
          jsonResponse(
            {
              id: "flow-cancel",
              user_code: "CANCEL-ME",
              verification_uri: "https://auth.example/verify",
              verification_uri_complete: "https://auth.example/verify?code=CANCEL-ME",
              expires_at: "2026-07-18T12:00:00Z",
              poll_interval_seconds: 5,
            },
            201,
          ),
        )
      if (url === "/vulcan/manage/kimi/device-flows/flow-cancel" && init?.method === "DELETE")
        return Promise.resolve(new Response(null, { status: 204 }))
      return Promise.resolve(new Response(null, { status: 404 }))
    })
    vi.stubGlobal("fetch", fetchMock)
    renderPage()

    await screen.findByText("No authorized providers yet.")
    fireEvent.click(screen.getByRole("button", { name: "Add provider" }))
    fireEvent.click(screen.getByRole("button", { name: /Kimi/ }))
    fireEvent.click(screen.getAllByRole("button", { name: /^Select / })[2])
    fireEvent.click(screen.getByRole("button", { name: "Device authorization" }))
    fireEvent.click(screen.getByRole("button", { name: "Start Kimi authorization" }))
    expect(await screen.findByText("CANCEL-ME")).toBeInTheDocument()
    fireEvent.click(screen.getByRole("button", { name: "Cancel authorization" }))

    await waitFor(() => expect(screen.queryByText("CANCEL-ME")).not.toBeInTheDocument())
    expect(fetchMock).toHaveBeenCalledWith(
      "/vulcan/manage/kimi/device-flows/flow-cancel",
      expect.objectContaining({
        method: "DELETE",
        headers: { Authorization: "Bearer management-token" },
      }),
    )
  })
})
