import type { ReactNode } from "react"

import { Button } from "@/components/ui/button"
import {
  SidebarGroup,
  SidebarGroupContent,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar"
import { useI18n } from "@/i18n"
import { CirclePlusIcon, MailIcon } from "lucide-react"

// NavMainProps defines the localized primary navigation items rendered in the dashboard sidebar.
// NavMainProps 定义仪表盘侧栏中渲染的本地化主导航项。
interface NavMainProps {
	// currentPath identifies the primary destination selected by the route shell.
	// currentPath 标识路由外壳选择的主导航目标。
	currentPath: string
	// onNavigate changes one authenticated route without reloading the application.
	// onNavigate 在不重新加载应用的情况下切换一个已认证路由。
	onNavigate: (path: string) => void
  // items contains primary navigation destinations with already-resolved display titles.
  // items 包含已解析显示标题的主导航目标。
  items: {
    // title is the visible localized navigation label.
    // title 是可见的本地化导航标签。
    title: string
    // url is the navigation destination.
    // url 是导航目标地址。
    url: string
    // icon is the optional visual marker for the navigation destination.
    // icon 是导航目标的可选视觉标记。
    icon?: ReactNode
  }[]
}

// NavMain renders localized primary navigation controls for the management sidebar.
// NavMain 为管理侧栏渲染本地化的主导航控件。
export function NavMain({
  items,
  currentPath,
  onNavigate,
}: NavMainProps) {
  // t resolves authored static sidebar actions into the current interface language.
  // t 将已编写的静态侧栏操作解析为当前界面语言。
  const { t } = useI18n()

  return (
    <SidebarGroup>
      <SidebarGroupContent className="flex flex-col gap-2">
        <SidebarMenu>
          <SidebarMenuItem className="flex items-center gap-2">
            <SidebarMenuButton
              tooltip={t("sidebar.quickCreate")}
              className="min-w-8 bg-primary text-primary-foreground duration-200 ease-linear hover:bg-primary/90 hover:text-primary-foreground active:bg-primary/90 active:text-primary-foreground"
            >
              <CirclePlusIcon
              />
              <span>{t("sidebar.quickCreate")}</span>
            </SidebarMenuButton>
            <Button
              size="icon"
              className="size-8 group-data-[collapsible=icon]:opacity-0"
              variant="outline"
            >
              <MailIcon
              />
              <span className="sr-only">{t("sidebar.inbox")}</span>
            </Button>
          </SidebarMenuItem>
        </SidebarMenu>
        <SidebarMenu>
          {items.map((item) => (
            <SidebarMenuItem key={item.title}>
              <SidebarMenuButton
                tooltip={item.title}
                isActive={currentPath === item.url}
                className="data-active:bg-primary data-active:text-primary-foreground data-active:font-semibold data-active:hover:bg-primary data-active:hover:text-primary-foreground"
                render={
                  <a
                    href={item.url}
                    aria-current={currentPath === item.url ? "page" : undefined}
                    onClick={(event) => {
                      event.preventDefault()
                      onNavigate(item.url)
                    }}
                  />
                }
              >
                {item.icon}
                <span>{item.title}</span>
              </SidebarMenuButton>
            </SidebarMenuItem>
          ))}
        </SidebarMenu>
      </SidebarGroupContent>
    </SidebarGroup>
  )
}
