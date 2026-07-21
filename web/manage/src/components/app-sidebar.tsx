import * as React from "react"

import { BrandMark } from "@/components/brand-mark"
import { NavDocuments } from "@/components/nav-documents"
import { NavMain } from "@/components/nav-main"
import { NavSecondary } from "@/components/nav-secondary"
import { NavUser } from "@/components/nav-user"
import { type TranslationKey, useI18n } from "@/i18n"
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar"
import {
  CircleHelpIcon,
  CpuIcon,
  DatabaseIcon,
  FileClockIcon,
  LayoutDashboardIcon,
  KeyRoundIcon,
  SearchIcon,
  ServerCogIcon,
  SparklesIcon,
  Settings2Icon,
} from "lucide-react"

// SidebarUserData defines the non-secret identity shown in the management sidebar footer.
// SidebarUserData 定义管理侧栏底部显示的非敏感身份信息。
interface SidebarUserData {
  // nameKey identifies the localized administrator display name.
  // nameKey 标识本地化的管理员显示名称。
  nameKey: TranslationKey
  // email provides the fixed local router account descriptor.
  // email 提供固定的本地 Router 账户描述。
  email: string
}

// SidebarNavigationEntry defines one localized primary or secondary navigation destination.
// SidebarNavigationEntry 定义一个本地化的主导航或次级导航目标。
interface SidebarNavigationEntry {
  // titleKey identifies the visible localized navigation label.
  // titleKey 标识可见的本地化导航标签。
  titleKey: TranslationKey
  // url identifies the current navigation target.
  // url 标识当前导航目标。
  url: string
  // icon provides the visual navigation marker.
  // icon 提供视觉导航标记。
  icon: React.ReactNode
}

// SidebarDocumentEntry defines one localized document shortcut displayed in the sidebar.
// SidebarDocumentEntry 定义侧栏中显示的一个本地化文档快捷方式。
interface SidebarDocumentEntry {
  // nameKey identifies the visible localized document label.
  // nameKey 标识可见的本地化文档标签。
  nameKey: TranslationKey
  // url identifies the document shortcut target.
  // url 标识文档快捷方式目标。
  url: string
  // icon provides the visual document marker.
  // icon 提供视觉文档标记。
  icon: React.ReactNode
}

// SidebarData groups the static, non-localized sidebar metadata used by the management workspace.
// SidebarData 汇集管理工作区使用的静态非本地化侧栏元数据。
interface SidebarData {
  // user contains the footer administrator metadata.
  // user 包含底部管理员元数据。
  user: SidebarUserData
  // navMain contains primary navigation entries.
  // navMain 包含主导航项。
  navMain: SidebarNavigationEntry[]
  // navSecondary contains secondary navigation entries.
  // navSecondary 包含次级导航项。
  navSecondary: SidebarNavigationEntry[]
  // documents contains document shortcut entries.
  // documents 包含文档快捷方式项。
  documents: SidebarDocumentEntry[]
}

// data supplies static dashboard navigation metadata while deferring visible labels to the translation catalog.
// data 为仪表盘提供静态导航元数据，并将可见标签延后至翻译目录解析。
const data: SidebarData = {
  user: {
    nameKey: "sidebar.administrator",
    email: "local@vulcan.router",
  },
  navMain: [
    {
      titleKey: "sidebar.dashboard",
      url: "/",
      icon: (
        <LayoutDashboardIcon
        />
      ),
    },
  ],
  navSecondary: [
    {
      titleKey: "sidebar.settings",
      url: "/settings",
      icon: (
        <Settings2Icon
        />
      ),
    },
    {
      titleKey: "sidebar.getHelp",
      url: "#",
      icon: (
        <CircleHelpIcon
        />
      ),
    },
    {
      titleKey: "sidebar.search",
      url: "#",
      icon: (
        <SearchIcon
        />
      ),
    },
  ],
  documents: [
    {
      nameKey: "sidebar.providerManagement",
      url: "/providers",
      icon: (
        <ServerCogIcon
        />
      ),
    },
    {
      nameKey: "sidebar.credentialManagement",
      url: "/credentials",
      icon: (
        <KeyRoundIcon
        />
      ),
    },
    {
      nameKey: "sidebar.modelCapabilities",
      url: "/capabilities/models",
      icon: (
        <CpuIcon
        />
      ),
    },
    {
      nameKey: "sidebar.serviceCapabilities",
      url: "/capabilities/services",
      icon: (
        <SparklesIcon
        />
      ),
    },
    {
      nameKey: "sidebar.resourceDiagnostics",
      url: "/diagnostics/resources",
      icon: (
        <DatabaseIcon
        />
      ),
    },
    {
      nameKey: "sidebar.executionDiagnostics",
      url: "/diagnostics/executions",
      icon: (
        <FileClockIcon
        />
      ),
    },
  ],
}

// localizeNavigationEntries converts translation-keyed navigation metadata into the label contract used by sidebar controls.
// localizeNavigationEntries 将带翻译键的导航元数据转换为侧栏控件使用的标签契约。
// entries contains the static navigation metadata to display.
// entries 包含待显示的静态导航元数据。
// t resolves one visible translation key into the active language.
// t 将一个可见翻译键解析为当前语言。
// Returns navigation items with exact localized title strings.
// 返回带有精确本地化标题字符串的导航项。
function localizeNavigationEntries(
  entries: SidebarNavigationEntry[],
  t: (key: TranslationKey) => string,
) {
  return entries.map(({ titleKey, ...entry }) => ({
    ...entry,
    title: t(titleKey),
  }))
}
// AppSidebarProps extends the sidebar primitives with the application logout operation.
// AppSidebarProps 在侧栏基础属性上扩展应用退出登录操作。
interface AppSidebarProps extends React.ComponentProps<typeof Sidebar> {
	// currentPath identifies the route whose sidebar node receives the selected state.
	// currentPath 标识应获得选中状态的侧栏节点路由。
	currentPath: string
	// onNavigate changes authenticated routes without reloading the Vite application.
	// onNavigate 在不重新加载 Vite 应用的情况下切换已认证路由。
	onNavigate: (path: string) => void
  // onLogout is forwarded to the footer confirmation action.
  // onLogout 会传递到侧栏底部的确认操作。
  onLogout: () => void
}

// AppSidebar renders the dashboard-01 sidebar with the VulcanModelRouter brand mark.
// AppSidebar 使用 VulcanModelRouter 品牌标识渲染 dashboard-01 侧栏。
export function AppSidebar({ currentPath, onNavigate, onLogout, ...props }: AppSidebarProps) {
  // t resolves all authored sidebar chrome into the current interface language.
  // t 将所有已编写侧栏界面元素解析为当前界面语言。
  const { t } = useI18n()
  // localizedMainItems contains primary navigation entries with visible translated titles.
  // localizedMainItems 包含带可见翻译标题的主导航项。
  const localizedMainItems = localizeNavigationEntries(data.navMain, t)
  // localizedSecondaryItems contains secondary navigation entries with visible translated titles.
  // localizedSecondaryItems 包含带可见翻译标题的次级导航项。
  const localizedSecondaryItems = localizeNavigationEntries(data.navSecondary, t)
  // localizedDocumentItems contains document shortcuts with visible translated names.
  // localizedDocumentItems 包含带可见翻译名称的文档快捷方式。
  const localizedDocumentItems = data.documents.map(({ nameKey, ...item }) => ({
    ...item,
    name: t(nameKey),
  }))
  // localizedUser contains footer administrator metadata with a visible translated display name.
  // localizedUser 包含带可见翻译显示名称的底部管理员元数据。
  const { nameKey, ...userMetadata } = data.user
  const localizedUser = {
    ...userMetadata,
    name: t(nameKey),
  }

  return (
    <Sidebar collapsible="offcanvas" {...props}>
      <SidebarHeader>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton
              className="data-[slot=sidebar-menu-button]:p-1.5!"
              render={<a href="/" />}
            >
              <BrandMark />
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>
      <SidebarContent>
        <NavMain items={localizedMainItems} currentPath={currentPath} onNavigate={onNavigate} />
        <NavDocuments items={localizedDocumentItems} currentPath={currentPath} onNavigate={onNavigate} />
        <NavSecondary items={localizedSecondaryItems} currentPath={currentPath} onNavigate={onNavigate} className="mt-auto" />
      </SidebarContent>
      <SidebarFooter>
        <NavUser user={localizedUser} onLogout={onLogout} />
      </SidebarFooter>
    </Sidebar>
  )
}
