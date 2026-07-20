import type { CSSProperties } from "react"

import { AppSidebar } from "@/components/app-sidebar"
import { DataTable } from "@/components/data-table"
import { SectionCards } from "@/components/section-cards"
import { SiteHeader } from "@/components/site-header"
import { DiagnosticsPage } from "@/pages/diagnostics-page"
import { ModelCapabilitiesPage } from "@/pages/model-capabilities-page"
import { ProviderManagementPage } from "@/pages/provider-management-page"
import { ServiceCapabilitiesPage } from "@/pages/service-capabilities-page"
import type { TranslationKey } from "@/i18n"
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

// resolvePageTitleKey maps every authenticated management route to its exact localized header.
// resolvePageTitleKey 将每个已认证管理路由映射到其精确的本地化标题。
function resolvePageTitleKey(currentPath: string): TranslationKey {
  switch (currentPath) {
    case "/providers":
      return "providers.title"
    case "/capabilities/models":
      return "capabilities.modelsTitle"
    case "/capabilities/services":
      return "capabilities.servicesTitle"
    case "/diagnostics/resources":
      return "diagnostics.resourcesTitle"
    case "/diagnostics/executions":
      return "diagnostics.executionsTitle"
    default:
      return "dashboard.overview"
  }
}

// renderAuthenticatedPage selects one exact management page without broad route fallbacks.
// renderAuthenticatedPage 选择一个精确管理页面且不使用宽泛路由回退。
function renderAuthenticatedPage(currentPath: string, managementAuthToken: string) {
  switch (currentPath) {
    case "/providers":
      return <ProviderManagementPage managementAuthToken={managementAuthToken} />
    case "/capabilities/models":
      return <ModelCapabilitiesPage managementAuthToken={managementAuthToken} />
    case "/capabilities/services":
      return <ServiceCapabilitiesPage managementAuthToken={managementAuthToken} />
    case "/diagnostics/resources":
      return <DiagnosticsPage kind="resources" managementAuthToken={managementAuthToken} />
    case "/diagnostics/executions":
      return <DiagnosticsPage kind="executions" managementAuthToken={managementAuthToken} />
    default:
      return <><SectionCards /><DataTable data={data} /></>
  }
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
        <SiteHeader titleKey={resolvePageTitleKey(currentPath)} />
        <div className="flex flex-1 flex-col">
          <div className="@container/main flex flex-1 flex-col gap-2">
            <div className="flex flex-col gap-4 py-4 md:gap-6 md:py-6">
              {renderAuthenticatedPage(currentPath, managementAuthToken)}
            </div>
          </div>
        </div>
      </SidebarInset>
    </SidebarProvider>
  )
}
