import { fireEvent, render, screen, waitFor } from "@testing-library/react"
import { beforeEach, describe, expect, it, vi } from "vitest"

import { LoginForm } from "@/components/login-form"
import {
  readStoredManagementCredential,
  saveRememberedManagementCredential,
} from "@/lib/management-credential-storage"

// LoginForm authentication-suite verifies the protected management route gates browser-session entry.
// LoginForm 认证测试套件验证受保护的管理路由会控制浏览器会话进入。
describe("LoginForm", () => {
  // resetCredentialStorage keeps each persistence scenario independent from previous login behavior.
  // resetCredentialStorage 使每个持久化场景都不受先前登录行为影响。
  beforeEach(() => {
    window.localStorage.clear()
  })

  // The accepted-token test verifies the exact Bearer request before a login callback can run.
  // 已接受令牌测试验证精确 Bearer 请求会先于登录回调执行。
  it("enters the application only after the management API accepts the auth token", async () => {
    // onAuthenticated records the verified in-memory token handoff.
    // onAuthenticated 记录已验证令牌的内存交接。
    const onAuthenticated = vi.fn()
    // fetchMock returns the successful response shape needed by the read-only validation route.
    // fetchMock 返回只读验证路由所需的成功响应结构。
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200 })
    vi.stubGlobal("fetch", fetchMock)

    try {
      render(<LoginForm onAuthenticated={onAuthenticated} />)
      fireEvent.change(screen.getByLabelText("Auth token"), {
        target: { value: "valid-management-token" },
      })
      fireEvent.click(screen.getByRole("button", { name: "Login" }))

      await waitFor(() => {
        expect(fetchMock).toHaveBeenCalledWith(
          "/vulcan/manage/protocol-profiles",
          {
            headers: {
              Authorization: "Bearer valid-management-token",
            },
          },
        )
      })
      expect(onAuthenticated).toHaveBeenCalledWith("valid-management-token")
    } finally {
      vi.unstubAllGlobals()
    }
  })

  // The rejected-token test verifies a 401 response remains on the login surface and reports no secret.
  // 被拒绝令牌测试验证 401 响应会保持在登录界面且不报告任何密钥内容。
  it("rejects an invalid management auth token", async () => {
    // onAuthenticated must not run for an unauthenticated server response.
    // onAuthenticated 不得在未认证的服务端响应下运行。
    const onAuthenticated = vi.fn()
    // fetchMock represents the credential-agnostic 401 response from the management route.
    // fetchMock 表示管理路由返回的凭据无关 401 响应。
    const fetchMock = vi.fn().mockResolvedValue({ ok: false, status: 401 })
    vi.stubGlobal("fetch", fetchMock)

    try {
      render(<LoginForm onAuthenticated={onAuthenticated} />)
      fireEvent.change(screen.getByLabelText("Auth token"), {
        target: { value: "invalid-management-token" },
      })
      fireEvent.click(screen.getByRole("button", { name: "Login" }))

      expect(
        await screen.findByRole("alert"),
      ).toHaveTextContent("The auth token is invalid.")
      expect(onAuthenticated).not.toHaveBeenCalled()
    } finally {
      vi.unstubAllGlobals()
    }
  })

  // Remembered-credential test verifies warning visibility and success-gated token persistence.
  // 记忆凭证测试验证安全提示可见性与仅成功后保存令牌。
  it("stores an opted-in credential only after successful validation", async () => {
    // onAuthenticated records the verified in-memory handoff after persistence succeeds.
    // onAuthenticated 记录持久化成功后的已验证内存交接。
    const onAuthenticated = vi.fn()
    // fetchMock accepts the credential so the successful persistence branch can complete.
    // fetchMock 接受凭证，使成功持久化分支能够完成。
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200 })
    vi.stubGlobal("fetch", fetchMock)

    try {
      // orphanedCredential represents an old token without an active remember preference.
      // orphanedCredential 表示没有启用保存偏好的旧令牌。
      window.localStorage.setItem(
        "vulcan-model-router.management.auth-token",
        "orphaned-management-token",
      )
      render(<LoginForm onAuthenticated={onAuthenticated} />)
      fireEvent.click(
        screen.getByRole("checkbox", { name: "Remember credential" }),
      )

      expect(screen.getByRole("note")).toHaveTextContent(
        "stored in plaintext in this browser's localStorage",
      )
      expect(readStoredManagementCredential()).toEqual({
        rememberCredential: true,
        authToken: "",
      })

      fireEvent.change(screen.getByLabelText("Auth token"), {
        target: { value: "remembered-management-token" },
      })
      fireEvent.click(screen.getByRole("button", { name: "Login" }))

      await waitFor(() => {
        expect(readStoredManagementCredential()).toEqual({
          rememberCredential: true,
          authToken: "remembered-management-token",
        })
      })
      expect(onAuthenticated).toHaveBeenCalledWith(
        "remembered-management-token",
      )
    } finally {
      vi.unstubAllGlobals()
    }
  })

  // Automatic-login test verifies a previously accepted credential is validated immediately on page load.
  // 自动登录测试验证此前已接受凭证会在页面加载时立即验证。
  it("automatically validates a remembered credential", async () => {
    saveRememberedManagementCredential("saved-management-token")
    // onAuthenticated records successful automatic entry into the management workspace.
    // onAuthenticated 记录成功自动进入管理工作区的行为。
    const onAuthenticated = vi.fn()
    // fetchMock accepts the saved credential during automatic validation.
    // fetchMock 在自动验证期间接受已保存凭证。
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200 })
    vi.stubGlobal("fetch", fetchMock)

    try {
      render(<LoginForm onAuthenticated={onAuthenticated} />)

      await waitFor(() => {
        expect(fetchMock).toHaveBeenCalledWith(
          "/vulcan/manage/protocol-profiles",
          {
            headers: {
              Authorization: "Bearer saved-management-token",
            },
          },
        )
      })
      expect(onAuthenticated).toHaveBeenCalledWith("saved-management-token")
    } finally {
      vi.unstubAllGlobals()
    }
  })

  // Invalid-saved-credential test removes only the bad token and keeps the checkbox preference enabled.
  // 无效已保存凭证测试仅删除错误令牌，并保持勾选偏好启用。
  it("clears an invalid saved credential while retaining the checked preference", async () => {
    saveRememberedManagementCredential("expired-management-token")
    // onAuthenticated must remain untouched when automatic credential validation returns 401.
    // onAuthenticated 在自动凭证验证返回 401 时不得执行。
    const onAuthenticated = vi.fn()
    // fetchMock represents the management API's definitive invalid-credential response.
    // fetchMock 表示管理 API 明确返回的无效凭证响应。
    const fetchMock = vi.fn().mockResolvedValue({ ok: false, status: 401 })
    vi.stubGlobal("fetch", fetchMock)

    try {
      render(<LoginForm onAuthenticated={onAuthenticated} />)

      expect(
        await screen.findByText("The auth token is invalid."),
      ).toBeInTheDocument()
      expect(readStoredManagementCredential()).toEqual({
        rememberCredential: true,
        authToken: "",
      })
      expect(screen.getByLabelText("Auth token")).toHaveValue("")
      expect(
        screen.getByRole("checkbox", { name: "Remember credential" }),
      ).toBeChecked()
      expect(onAuthenticated).not.toHaveBeenCalled()
    } finally {
      vi.unstubAllGlobals()
    }
  })

  // Network-failure test retains the saved credential because the server did not reject its validity.
  // 网络失败测试保留已保存凭证，因为服务端并未否定其有效性。
  it("retains a saved credential when automatic validation cannot reach the API", async () => {
    saveRememberedManagementCredential("offline-management-token")
    // onAuthenticated must remain untouched while the management API is unreachable.
    // onAuthenticated 在管理 API 无法连接时不得执行。
    const onAuthenticated = vi.fn()
    // fetchMock represents a transport failure without an authentication verdict.
    // fetchMock 表示没有认证结论的传输失败。
    const fetchMock = vi.fn().mockRejectedValue(new TypeError("Network error"))
    vi.stubGlobal("fetch", fetchMock)

    try {
      render(<LoginForm onAuthenticated={onAuthenticated} />)

      expect(
        await screen.findByText("Unable to reach the local management API."),
      ).toBeInTheDocument()
      expect(readStoredManagementCredential()).toEqual({
        rememberCredential: true,
        authToken: "offline-management-token",
      })
      expect(screen.getByLabelText("Auth token")).toHaveValue(
        "offline-management-token",
      )
      expect(onAuthenticated).not.toHaveBeenCalled()
    } finally {
      vi.unstubAllGlobals()
    }
  })
})
