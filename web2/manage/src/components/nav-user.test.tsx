import { fireEvent, render, screen } from "@testing-library/react"
import { describe, expect, it, vi } from "vitest"

import { NavUser } from "@/components/nav-user"
import { SidebarProvider } from "@/components/ui/sidebar"

// routerUser supplies the stable identity used by the sidebar logout test.
// routerUser 提供侧栏退出登录测试使用的稳定身份信息。
const routerUser = {
  name: "Administrator",
  email: "local@vulcan.router",
}

// NavUser logout-suite verifies direct confirmation-based logout without the former overflow menu.
// NavUser 退出登录测试套件验证直接确认式退出，不再使用原有的溢出菜单。
describe("NavUser", () => {
  // The logout confirmation test checks cancellation and explicit confirmation independently.
  // 退出登录确认测试分别检查取消与显式确认行为。
  it("requires confirmation before invoking the logout operation", () => {
    // onLogout records only confirmed logout actions for this isolated component test.
    // onLogout 仅记录此隔离组件测试中已确认的退出登录操作。
    const onLogout = vi.fn()

    render(
      <SidebarProvider>
        <NavUser user={routerUser} onLogout={onLogout} />
      </SidebarProvider>,
    )

    expect(
      screen.getByRole("img", { name: "VulcanCode" }),
    ).toBeInTheDocument()
    fireEvent.click(screen.getByRole("button", { name: "Log out" }))
    expect(
      screen.getByText("Log out of VulcanModelRouter?"),
    ).toBeInTheDocument()

    fireEvent.click(screen.getByRole("button", { name: "Cancel" }))
    expect(onLogout).not.toHaveBeenCalled()

    fireEvent.click(screen.getByRole("button", { name: "Log out" }))
    fireEvent.click(screen.getByRole("button", { name: "Log out now" }))
    expect(onLogout).toHaveBeenCalledTimes(1)
  })
})
