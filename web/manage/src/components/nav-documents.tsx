"use client"

import type { ReactNode } from "react"

import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import {
  SidebarGroup,
  SidebarGroupLabel,
  SidebarMenu,
  SidebarMenuAction,
  SidebarMenuButton,
  SidebarMenuItem,
  useSidebar,
} from "@/components/ui/sidebar"
import { useI18n } from "@/i18n"
import { MoreHorizontalIcon, FolderIcon, ShareIcon, Trash2Icon } from "lucide-react"

// NavDocumentsProps defines localized document shortcuts rendered in the management sidebar.
// NavDocumentsProps 定义管理侧栏中渲染的本地化文档快捷方式。
interface NavDocumentsProps {
	// currentPath identifies the document destination selected by the route shell.
	// currentPath 标识路由外壳选择的文档目标。
	currentPath: string
	// onNavigate changes one authenticated route without reloading the application.
	// onNavigate 在不重新加载应用的情况下切换一个已认证路由。
	onNavigate: (path: string) => void
  // items contains document shortcuts with already-resolved visible names.
  // items 包含已解析可见名称的文档快捷方式。
  items: {
    // name is the visible localized document name.
    // name 是可见的本地化文档名称。
    name: string
    // url is the document shortcut target.
    // url 是文档快捷方式目标。
    url: string
    // icon is the visual marker for the document shortcut.
    // icon 是文档快捷方式的视觉标记。
    icon: ReactNode
  }[]
}

// NavDocuments renders localized document shortcuts and their contextual menu controls.
// NavDocuments 渲染本地化文档快捷方式及其上下文菜单控件。
export function NavDocuments({
  items,
  currentPath,
  onNavigate,
}: NavDocumentsProps) {
  // isMobile selects the menu placement prescribed by the responsive sidebar primitive.
  // isMobile 选择响应式侧栏基础组件规定的菜单位置。
  const { isMobile } = useSidebar()
  // t resolves authored document chrome into the current interface language.
  // t 将已编写的文档界面元素解析为当前界面语言。
  const { t } = useI18n()

  return (
    <SidebarGroup className="group-data-[collapsible=icon]:hidden">
      <SidebarGroupLabel>{t("sidebar.documents")}</SidebarGroupLabel>
      <SidebarMenu>
        {items.map((item) => (
          <SidebarMenuItem key={item.name}>
            <SidebarMenuButton
              isActive={currentPath === item.url}
              className="data-active:bg-primary data-active:text-primary-foreground data-active:font-semibold data-active:hover:bg-primary data-active:hover:text-primary-foreground"
              render={
                <a
                  href={item.url}
                  aria-current={currentPath === item.url ? "page" : undefined}
                  onClick={(event) => {
                    if (item.url === "#") {
                      return
                    }
                    event.preventDefault()
                    onNavigate(item.url)
                  }}
                />
              }
            >
              {item.icon}
              <span>{item.name}</span>
            </SidebarMenuButton>
            <DropdownMenu>
              <DropdownMenuTrigger
                render={
                  <SidebarMenuAction
                    showOnHover
                    className="aria-expanded:bg-muted"
                  />
                }
              >
                <MoreHorizontalIcon
                />
                <span className="sr-only">{t("sidebar.more")}</span>
              </DropdownMenuTrigger>
              <DropdownMenuContent
                className="w-24"
                side={isMobile ? "bottom" : "right"}
                align={isMobile ? "end" : "start"}
              >
                <DropdownMenuItem>
                  <FolderIcon
                  />
                  <span>{t("sidebar.open")}</span>
                </DropdownMenuItem>
                <DropdownMenuItem>
                  <ShareIcon
                  />
                  <span>{t("sidebar.share")}</span>
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem variant="destructive">
                  <Trash2Icon
                  />
                  <span>{t("sidebar.delete")}</span>
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </SidebarMenuItem>
        ))}
        <SidebarMenuItem>
          <SidebarMenuButton className="text-sidebar-foreground/70">
            <MoreHorizontalIcon className="text-sidebar-foreground/70" />
            <span>{t("sidebar.more")}</span>
          </SidebarMenuButton>
        </SidebarMenuItem>
      </SidebarMenu>
    </SidebarGroup>
  )
}
