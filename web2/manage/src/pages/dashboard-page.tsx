import type { CSSProperties } from "react"

import { AppSidebar } from "@/components/app-sidebar"
import { DataTable } from "@/components/data-table"
import { SectionCards } from "@/components/section-cards"
import { SiteHeader } from "@/components/site-header"
import { ProviderManagementPage } from "@/pages/provider-management-page"
import { SidebarInset, SidebarProvider } from "@/components/ui/sidebar"

import data from "@/app/dashboard/data.json"

// DashboardPageProps defines dashboard actions owned by the application route shell.
// DashboardPageProps 定义由应用路由外壳拥有的仪表盘操作。
interface DashboardPageProps {
	// currentPath identifies the authenticated page selected by the application route shell.
	// currentPath 标识应用路由外壳选择的已认证页面。
	currentPath: string
	// managementAuthToken authorizes management API requests without persistent page storage.
	// managementAuthToken 授权管理 API 请求且不进行页面持久化存储。
	managementAuthToken: string
	// onNavigate changes authenticated routes without a browser reload.
	// onNavigate 在不重新加载浏览器的情况下切换已认证路由。
	onNavigate: (path: string) => void
  // onLogout ends the active browser management session after confirmation.
  // onLogout 会在确认后结束当前浏览器管理会话。
  onLogout: () => void
}

// DashboardPage renders the shadcn dashboard-01 block as the application home page.
// DashboardPage 将 shadcn dashboard-01 区块渲染为应用首页。
export function DashboardPage({ currentPath, managementAuthToken, onNavigate, onLogout }: DashboardPageProps) {
  // sidebarStyle preserves the dashboard-01 layout dimensions in the Vite entry point.
  // sidebarStyle 在 Vite 入口中保持 dashboard-01 的布局尺寸。
  const sidebarStyle = {
    "--sidebar-width": "calc(var(--spacing) * 72)",
    "--header-height": "calc(var(--spacing) * 12)"
  } as CSSProperties

  return (
    <SidebarProvider style={sidebarStyle}>
      <AppSidebar variant="inset" onNavigate={onNavigate} onLogout={onLogout} />
      <SidebarInset>
        <SiteHeader titleKey={currentPath === "/providers" ? "providers.title" : "dashboard.overview"} />
        <div className="flex flex-1 flex-col">
          <div className="@container/main flex flex-1 flex-col gap-2">
            <div className="flex flex-col gap-4 py-4 md:gap-6 md:py-6">
              {currentPath === "/providers" ? (
                <ProviderManagementPage managementAuthToken={managementAuthToken} />
              ) : (
                <>
                  <SectionCards />
                  <DataTable data={data} />
                </>
              )}
            </div>
          </div>
        </div>
      </SidebarInset>
    </SidebarProvider>
  )
}
