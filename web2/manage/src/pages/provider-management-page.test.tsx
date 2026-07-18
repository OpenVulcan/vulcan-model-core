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
          channels: [{ id: "chat", protocol_profile_id: "openai.chat", runtime_ready: true }],
          endpoint_presets: [{ id: "cn_chat", channel_id: "chat", base_url: "https://api.moonshot.cn", region: "CN", user_editable: false }],
        },
        {
          id: "system_kimi_global",
          display_name: "Kimi Global",
          group_id: "kimi",
          variant_name: "Global",
          variant_description: "Global API site.",
          model_catalog_id: "kimi_open_platform",
          auth_methods: [{ id: "api_key", type: "api_key", refreshable: false }],
          channels: [{ id: "chat", protocol_profile_id: "openai.chat", runtime_ready: true }],
          endpoint_presets: [{ id: "global_chat", channel_id: "chat", base_url: "https://api.moonshot.ai", region: "Global", user_editable: false }],
        },
        {
          id: "system_kimi_coding_plan",
          display_name: "Kimi Coding Plan",
          group_id: "kimi",
          variant_name: "Coding Plan",
          variant_description: "Coding membership.",
          model_catalog_id: "kimi_coding",
          auth_methods: [{ id: "api_key", type: "api_key", refreshable: false }, { id: "device_flow", type: "device_flow", refreshable: true }],
          channels: [
            { id: "chat", protocol_profile_id: "openai.chat", runtime_ready: true },
            { id: "anthropic", protocol_profile_id: "anthropic.messages", runtime_ready: true },
          ],
          endpoint_presets: [{ id: "coding_chat", channel_id: "chat", base_url: "https://api.kimi.com/coding/v1", region: "Coding Plan", user_editable: false }],
        },
      ],
    },
  ],
}

describe("ProviderManagementPage", () => {
  afterEach(() => vi.unstubAllGlobals())

  // This test verifies authenticated group loading and exact CN, Global, and Coding Plan selection.
  // 此测试验证已认证分组加载以及精确的 CN、Global 和 Coding Plan 选择。
  it("loads the Kimi group and selects one exact variant", async () => {
    // fetchMock records the active management credential while returning the isolated group fixture.
    // fetchMock 在返回隔离分组夹具时记录当前管理凭证。
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(kimiGroupResponse), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      })
    )
    vi.stubGlobal("fetch", fetchMock)

    render(
      <I18nProvider>
        <ProviderManagementPage managementAuthToken="management-token" />
      </I18nProvider>
    )

    expect(await screen.findByRole("heading", { name: "Kimi" })).toBeInTheDocument()
    expect(screen.getByText("CN")).toBeInTheDocument()
    expect(screen.getByText("Global")).toBeInTheDocument()
    expect(screen.getByText("Coding Plan")).toBeInTheDocument()
    fireEvent.click(screen.getAllByRole("button", { name: "Select variant" })[1])
    expect(screen.getByRole("button", { name: "Selected" })).toBeInTheDocument()
    expect(fetchMock).toHaveBeenCalledWith(
      "/vulcan/manage/provider-groups",
      expect.objectContaining({
        headers: { Authorization: "Bearer management-token" },
      })
    )
  })

  // This test verifies the API key remains transient and reaches the atomic onboarding route only after submission.
  // 此测试验证 API Key 保持临时状态且仅在提交后到达原子录入路由。
  it("submits one selected API-key variant to atomic onboarding", async () => {
    const fetchMock = vi.fn().mockImplementation((input: string | URL | Request) => {
      const url = String(input)
      if (url === "/vulcan/manage/provider-groups") {
        return Promise.resolve(new Response(JSON.stringify(kimiGroupResponse), { status: 200, headers: { "Content-Type": "application/json" } }))
      }
      return Promise.resolve(new Response(JSON.stringify({ provider_instance_id: "pvi_created", credential_id: "cred_created", endpoint_ids: ["ep_created"], binding_ids: ["bind_created"] }), { status: 201, headers: { "Content-Type": "application/json" } }))
    })
    vi.stubGlobal("fetch", fetchMock)
    render(<I18nProvider><ProviderManagementPage managementAuthToken="management-token" /></I18nProvider>)
    await screen.findByRole("heading", { name: "Kimi" })
    fireEvent.click(screen.getAllByRole("button", { name: "Select variant" })[0])
    fireEvent.change(screen.getByLabelText("API key"), { target: { value: "private-kimi-key" } })
    fireEvent.click(screen.getByRole("button", { name: "Create provider" }))
    expect(await screen.findByText("Provider configuration created successfully.")).toBeInTheDocument()
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2))
    const request = fetchMock.mock.calls[1][1] as RequestInit
    expect(request.body).toContain('"secret":"private-kimi-key"')
    expect(request.headers).toEqual(expect.objectContaining({ Authorization: "Bearer management-token" }))
  })

  // This test verifies Coding Plan authorization data never includes provider tokens in the browser flow.
  // 此测试验证 Coding Plan 授权数据在浏览器流程中绝不包含供应商令牌。
  it("starts and completes server-confidential Coding Plan authorization", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(kimiGroupResponse), { status: 200, headers: { "Content-Type": "application/json" } }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ id: "flow-test", user_code: "ABCD-EFGH", verification_uri: "https://auth.example/verify", verification_uri_complete: "https://auth.example/verify?code=ABCD-EFGH", expires_at: "2026-07-18T12:00:00Z", poll_interval_seconds: 5 }), { status: 201, headers: { "Content-Type": "application/json" } }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ provider_instance_id: "pvi_coding", credential_id: "cred_coding", endpoint_ids: ["ep_chat", "ep_anthropic"], binding_ids: ["bind_chat", "bind_anthropic"] }), { status: 201, headers: { "Content-Type": "application/json" } }))
    vi.stubGlobal("fetch", fetchMock)
    render(<I18nProvider><ProviderManagementPage managementAuthToken="management-token" /></I18nProvider>)
    await screen.findByRole("heading", { name: "Kimi" })
    fireEvent.click(screen.getAllByRole("button", { name: "Select variant" })[2])
    fireEvent.click(screen.getByRole("button", { name: "Device authorization" }))
    fireEvent.click(screen.getByRole("button", { name: "Start Kimi authorization" }))
    expect(await screen.findByText("ABCD-EFGH")).toBeInTheDocument()
    fireEvent.click(screen.getByRole("button", { name: "Check authorization" }))
    expect(await screen.findByText("Provider configuration created successfully.")).toBeInTheDocument()
    expect(JSON.stringify(fetchMock.mock.calls)).not.toContain("device-access-secret")
  })

  // This test verifies an unfinished Coding Plan authorization can be explicitly released without exposing its provider code.
  // 此测试验证未完成的 Coding Plan 授权可以被显式释放且不会暴露供应商秘密码。
  it("cancels an unfinished server-owned Coding Plan authorization", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(kimiGroupResponse), { status: 200, headers: { "Content-Type": "application/json" } }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ id: "flow-cancel", user_code: "CANCEL-ME", verification_uri: "https://auth.example/verify", verification_uri_complete: "https://auth.example/verify?code=CANCEL-ME", expires_at: "2026-07-18T12:00:00Z", poll_interval_seconds: 5 }), { status: 201, headers: { "Content-Type": "application/json" } }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
    vi.stubGlobal("fetch", fetchMock)
    render(<I18nProvider><ProviderManagementPage managementAuthToken="management-token" /></I18nProvider>)
    await screen.findByRole("heading", { name: "Kimi" })
    fireEvent.click(screen.getAllByRole("button", { name: "Select variant" })[2])
    fireEvent.click(screen.getByRole("button", { name: "Device authorization" }))
    fireEvent.click(screen.getByRole("button", { name: "Start Kimi authorization" }))
    expect(await screen.findByText("CANCEL-ME")).toBeInTheDocument()
    fireEvent.click(screen.getByRole("button", { name: "Cancel authorization" }))
    await waitFor(() => expect(screen.queryByText("CANCEL-ME")).not.toBeInTheDocument())
    expect(fetchMock).toHaveBeenLastCalledWith(
      "/vulcan/manage/kimi/device-flows/flow-cancel",
      expect.objectContaining({ method: "DELETE", headers: { Authorization: "Bearer management-token" } })
    )
  })
})
