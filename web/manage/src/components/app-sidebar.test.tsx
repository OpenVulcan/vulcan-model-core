import { fireEvent, render, screen } from "@testing-library/react"
import { describe, expect, it, vi } from "vitest"

import { AppSidebar } from "@/components/app-sidebar"
import { SidebarProvider } from "@/components/ui/sidebar"
import { I18nProvider } from "@/i18n"

// AppSidebar navigation-suite verifies removed template nodes and route-owned selection styling.
// AppSidebar 导航测试套件验证已移除的模板节点与路由拥有的选中样式。
describe("AppSidebar", () => {
  // This test proves every real route can expose one unambiguous current-page node.
  // 此测试证明每个真实路由都可以公开一个明确的当前页面节点。
  it("removes unused top nodes and selects the current route", () => {
    // onNavigate records client-side navigation without requiring a browser router in this component test.
    // onNavigate 在组件测试中记录客户端导航，无需引入浏览器 Router。
    const onNavigate = vi.fn()

    render(
      <I18nProvider>
        <SidebarProvider>
          <AppSidebar
            currentPath="/providers"
            onNavigate={onNavigate}
            onLogout={vi.fn()}
          />
        </SidebarProvider>
      </I18nProvider>,
    )

    expect(screen.queryByText("Lifecycle")).not.toBeInTheDocument()
    expect(screen.queryByText("Analytics")).not.toBeInTheDocument()
    expect(screen.queryByText("Projects")).not.toBeInTheDocument()
    expect(screen.queryByText("Team")).not.toBeInTheDocument()

    const selectedProvider = screen.getByRole("link", {
      name: "Provider Management",
    })
    expect(selectedProvider).toHaveAttribute("aria-current", "page")
    expect(selectedProvider).toHaveAttribute("data-active")
    expect(screen.getByRole("link", { name: "Dashboard" })).not.toHaveAttribute(
      "data-active",
    )

    fireEvent.click(screen.getByRole("link", { name: "Settings" }))
    expect(onNavigate).toHaveBeenCalledWith("/settings")
  })
})
