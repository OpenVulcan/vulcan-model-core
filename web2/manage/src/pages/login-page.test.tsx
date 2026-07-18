import { render, screen } from "@testing-library/react"
import { describe, expect, it } from "vitest"

import { LoginPage } from "@/pages/login-page"

// LoginPage auth-token suite protects the single-token administrator login surface from template regressions.
// LoginPage Auth token 测试套件保护单令牌管理员登录界面不受模板回归影响。
describe("LoginPage", () => {
  // The administrator sign-in test verifies one required token field and excludes account-provider links.
  // 管理员登录测试验证单一必填令牌字段，并排除账号提供商链接。
  it("renders only the administrator auth token form", () => {
    // onAuthenticated is intentionally inert because this test covers static form shape only.
    // onAuthenticated 有意保持空操作，因为此测试仅覆盖静态表单结构。
    const onAuthenticated = () => undefined

    render(<LoginPage onAuthenticated={onAuthenticated} />)

    expect(
      screen.getByRole("heading", { name: "Sign in to Model Router" }),
    ).toBeInTheDocument()
    // authTokenInput is the sole credential control and receives initial keyboard focus.
    // authTokenInput 是唯一的凭据控件，并在初始渲染时接收键盘焦点。
    const authTokenInput = screen.getByLabelText("Auth token")
    expect(authTokenInput).toBeRequired()
    expect(authTokenInput).toHaveFocus()
    expect(authTokenInput).toHaveAttribute(
      "type",
      "password",
    )
    expect(screen.queryByLabelText("Email")).not.toBeInTheDocument()
    expect(screen.queryByLabelText("Password")).not.toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Login" })).toBeInTheDocument()
    expect(screen.queryByRole("link")).not.toBeInTheDocument()
    expect(screen.queryByText(/GitHub/i)).not.toBeInTheDocument()
  })
})
