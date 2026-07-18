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
              <SidebarMenuButton tooltip={item.title}>
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
