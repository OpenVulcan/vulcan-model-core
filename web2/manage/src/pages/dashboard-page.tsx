import type { CSSProperties } from "react"

import { AppSidebar } from "@/components/app-sidebar"
import { DataTable } from "@/components/data-table"
import { SectionCards } from "@/components/section-cards"
import { SiteHeader } from "@/components/site-header"
import { SidebarInset, SidebarProvider } from "@/components/ui/sidebar"

import data from "@/app/dashboard/data.json"

// DashboardPageProps defines dashboard actions owned by the application route shell.
// DashboardPageProps 定义由应用路由外壳拥有的仪表盘操作。
interface DashboardPageProps {
  // onLogout ends the active browser management session after confirmation.
  // onLogout 会在确认后结束当前浏览器管理会话。
  onLogout: () => void
}

// DashboardPage renders the shadcn dashboard-01 block as the application home page.
// DashboardPage 将 shadcn dashboard-01 区块渲染为应用首页。
export function DashboardPage({ onLogout }: DashboardPageProps) {
  // sidebarStyle preserves the dashboard-01 layout dimensions in the Vite entry point.
  // sidebarStyle 在 Vite 入口中保持 dashboard-01 的布局尺寸。
  const sidebarStyle = {
    "--sidebar-width": "calc(var(--spacing) * 72)",
    "--header-height": "calc(var(--spacing) * 12)"
  } as CSSProperties

  return (
    <SidebarProvider style={sidebarStyle}>
      <AppSidebar variant="inset" onLogout={onLogout} />
      <SidebarInset>
        <SiteHeader />
        <div className="flex flex-1 flex-col">
          <div className="@container/main flex flex-1 flex-col gap-2">
            <div className="flex flex-col gap-4 py-4 md:gap-6 md:py-6">
              <SectionCards />
              <DataTable data={data} />
            </div>
          </div>
        </div>
      </SidebarInset>
    </SidebarProvider>
  )
}
