import { LanguageToggle } from "@/components/language-toggle"
import { Separator } from "@/components/ui/separator"
import { SidebarTrigger } from "@/components/ui/sidebar"
import { useI18n } from "@/i18n"

// SiteHeader renders the dashboard-01 header for the router overview workspace.
// SiteHeader 为 Router 概览工作区渲染 dashboard-01 页头。
export function SiteHeader() {
  const { t } = useI18n()
  return (
    <header className="flex h-(--header-height) shrink-0 items-center gap-2 border-b transition-[width,height] ease-linear group-has-data-[collapsible=icon]/sidebar-wrapper:h-(--header-height)">
      <div className="flex w-full items-center gap-1 px-4 lg:gap-2 lg:px-6">
        <SidebarTrigger className="-ml-1" />
        <Separator
          orientation="vertical"
          className="mx-2 h-4 data-vertical:self-auto"
        />
        <h1 className="text-base font-medium">{t("dashboard.overview")}</h1>
        <LanguageToggle className="ml-auto" />
      </div>
    </header>
  )
}
