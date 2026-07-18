import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react"

// Locale identifies each supported user-interface language.
// Locale 标识每种受支持的用户界面语言。
export type Locale = "en" | "zh"

// englishMessages defines the canonical key set and English fallback strings for authored router pages.
// englishMessages 定义已编写 Router 页面所使用的规范键集合与英文回退文案。
const englishMessages = {
  "language.switchToChinese": "Switch to Chinese",
  "language.switchToEnglish": "Switch to English",
  "login.title": "Sign in to Model Router",
  "login.description": "Enter your management auth token to continue",
  "login.authToken": "Auth token",
  "login.placeholder": "Enter your auth token",
  "login.rememberCredential": "Remember credential",
  "login.rememberCredentialWarning":
    "The management credential will be stored in plaintext in this browser's localStorage. Use only on a trusted device.",
  "login.submit": "Login",
  "login.verifying": "Verifying…",
  "login.error.empty": "Enter a management auth token.",
  "login.error.invalid": "The auth token is invalid.",
  "login.error.unavailable": "Unable to reach the local management API.",
  "login.error.validation": "The local management API could not validate the auth token.",
  "brand.platform": "VulcanCode Platform",
  "brand.controlPlane": "Local AI Control Plane",
  "brand.description": "Route local model access through one focused management surface.",
  "dashboard.overview": "Model Router overview",
  "providers.title": "Provider Management",
  "providers.authorizedDescription": "Manage configured providers and their authorized API or device credentials.",
  "providers.description": "Choose a provider, then select the exact site or plan to authorize.",
  "providers.add": "Add provider",
  "providers.cancelAdd": "Close provider creation",
  "providers.search": "Filter providers",
  "providers.searchPlaceholder": "Filter by provider, site, or plan…",
  "providers.chooseProvider": "Choose a provider",
  "providers.chooseVariant": "Choose a site or plan",
  "providers.configureProvider": "Configure provider",
  "providers.directConfiguration": "Configure directly",
  "providers.backToProviders": "Back to providers",
  "providers.noMatches": "No providers match this filter.",
  "providers.noAuthorized": "No authorized providers yet.",
  "providers.authorizations": "Authorizations",
  "providers.instanceHandle": "Instance handle",
  "providers.loading": "Loading provider data…",
  "providers.catalogLoadFailed": "Unable to load the provider catalog. Adding providers is temporarily unavailable.",
  "providers.authorizedLoadFailed": "Unable to load the authorized provider list.",
  "providers.variants": "options",
  "providers.select": "Select",
  "providers.selected": "Selected",
  "providers.kimi.description":
    "Moonshot AI services across regional Open Platform sites and the separate Coding Plan.",
  "providers.kimi.cnDescription": "Kimi Open Platform service hosted at the CN API site.",
  "providers.kimi.globalDescription": "Kimi Open Platform service hosted at the Global API site.",
  "providers.kimi.codingDescription": "Membership-based coding service with dedicated models and credentials.",
  "providers.handle": "Instance handle",
  "providers.displayName": "Display name",
  "providers.credentialLabel": "Credential label",
  "providers.apiKey": "API key",
  "providers.deviceFlow": "Device authorization",
  "providers.onboard": "Create provider",
  "providers.startAuthorization": "Start Kimi authorization",
  "providers.checkAuthorization": "Check authorization",
  "providers.cancelAuthorization": "Cancel authorization",
  "providers.authorizationCode": "Authorization code",
  "providers.status.draft": "Draft",
  "providers.status.validating": "Validating",
  "providers.status.ready": "Ready",
  "providers.status.degraded": "Degraded",
  "providers.status.disabled": "Disabled",
  "providers.status.migrationRequired": "Migration required",
  "providers.status.deleting": "Deleting",
  "providers.status.active": "Active",
  "providers.status.expired": "Expired",
  "providers.status.invalid": "Invalid",
  "providers.status.cooling": "Cooling down",
  "providers.authorizationPending": "Authorization is still pending.",
  "providers.unsupportedAuthentication": "This provider does not expose a supported authentication method.",
  "providers.onboardingFailed": "Unable to create the provider configuration.",
  "providers.onboardingComplete": "Provider configuration created successfully.",
  "sidebar.dashboard": "Dashboard",
  "sidebar.lifecycle": "Lifecycle",
  "sidebar.analytics": "Analytics",
  "sidebar.projects": "Projects",
  "sidebar.team": "Team",
  "sidebar.documents": "Providers",
  "sidebar.providerManagement": "Provider Management",
  "sidebar.dataLibrary": "Data Library",
  "sidebar.reports": "Reports",
  "sidebar.wordAssistant": "Word Assistant",
  "sidebar.settings": "Settings",
  "sidebar.getHelp": "Get Help",
  "sidebar.search": "Search",
  "sidebar.quickCreate": "Quick Create",
  "sidebar.inbox": "Inbox",
  "sidebar.more": "More",
  "sidebar.open": "Open",
  "sidebar.share": "Share",
  "sidebar.delete": "Delete",
  "sidebar.administrator": "Administrator",
  "logout.label": "Log out",
  "logout.title": "Log out of VulcanModelRouter?",
  "logout.description": "You will return to the administrator login page.",
  "logout.cancel": "Cancel",
  "logout.confirm": "Log out now",
} as const

// TranslationKey restricts translation reads to strings defined by the canonical message catalog.
// TranslationKey 将翻译读取限制为规范消息目录中定义的字符串。
export type TranslationKey = keyof typeof englishMessages

// Messages represents one complete translation catalog for all authored router-page strings.
// Messages 表示已编写 Router 页面全部字符串的一个完整翻译目录。
type Messages = Record<TranslationKey, string>

// chineseMessages supplies simplified Chinese copy for every Chinese browser variant and manual Chinese selection.
// chineseMessages 为所有中文浏览器变体和手动中文选择提供简体中文文案。
const chineseMessages: Messages = {
  "language.switchToChinese": "切换到中文",
  "language.switchToEnglish": "切换到英文",
  "login.title": "登录到 Model Router",
  "login.description": "输入管理认证令牌以继续",
  "login.authToken": "认证令牌",
  "login.placeholder": "输入认证令牌",
  "login.rememberCredential": "保存凭证",
  "login.rememberCredentialWarning": "管理凭证将以明文保存在此浏览器的 localStorage 中，请仅在受信任设备上使用。",
  "login.submit": "登录",
  "login.verifying": "正在验证…",
  "login.error.empty": "请输入管理认证令牌。",
  "login.error.invalid": "认证令牌无效。",
  "login.error.unavailable": "无法连接本地管理 API。",
  "login.error.validation": "本地管理 API 无法验证认证令牌。",
  "brand.platform": "VulcanCode 平台",
  "brand.controlPlane": "本地 AI 控制平面",
  "brand.description": "通过一个专用管理界面统一路由本地模型访问。",
  "dashboard.overview": "模型路由概览",
  "providers.title": "供应商管理",
  "providers.authorizedDescription": "管理已配置供应商及其 API 或设备授权凭据。",
  "providers.description": "选择供应商，然后选择需要授权的精确站点或套餐。",
  "providers.add": "新增供应商",
  "providers.cancelAdd": "关闭供应商新增",
  "providers.search": "过滤供应商",
  "providers.searchPlaceholder": "按供应商、站点或套餐过滤…",
  "providers.chooseProvider": "选择供应商",
  "providers.chooseVariant": "选择站点或套餐",
  "providers.configureProvider": "配置供应商",
  "providers.directConfiguration": "直接配置",
  "providers.backToProviders": "返回供应商列表",
  "providers.noMatches": "没有符合过滤条件的供应商。",
  "providers.noAuthorized": "暂无已授权供应商。",
  "providers.authorizations": "授权列表",
  "providers.instanceHandle": "实例标识",
  "providers.loading": "正在加载供应商数据…",
  "providers.catalogLoadFailed": "无法加载供应商目录，暂时不能新增供应商。",
  "providers.authorizedLoadFailed": "无法加载已授权供应商列表。",
  "providers.variants": "个选项",
  "providers.select": "选择",
  "providers.selected": "已选择",
  "providers.kimi.description": "Moonshot AI 在不同区域的开放平台站点以及独立的 Coding Plan 服务。",
  "providers.kimi.cnDescription": "托管于 CN API 站点的 Kimi 开放平台服务。",
  "providers.kimi.globalDescription": "托管于 Global API 站点的 Kimi 开放平台服务。",
  "providers.kimi.codingDescription": "提供专用模型与凭据的订阅制编程服务。",
  "providers.handle": "实例标识",
  "providers.displayName": "显示名称",
  "providers.credentialLabel": "凭据名称",
  "providers.apiKey": "API 密钥",
  "providers.deviceFlow": "设备授权",
  "providers.onboard": "创建供应商",
  "providers.startAuthorization": "开始 Kimi 授权",
  "providers.checkAuthorization": "检查授权状态",
  "providers.cancelAuthorization": "取消授权",
  "providers.authorizationCode": "授权码",
  "providers.status.draft": "草稿",
  "providers.status.validating": "验证中",
  "providers.status.ready": "就绪",
  "providers.status.degraded": "服务降级",
  "providers.status.disabled": "已停用",
  "providers.status.migrationRequired": "需要迁移",
  "providers.status.deleting": "删除中",
  "providers.status.active": "可用",
  "providers.status.expired": "已过期",
  "providers.status.invalid": "无效",
  "providers.status.cooling": "冷却中",
  "providers.authorizationPending": "授权尚未完成。",
  "providers.unsupportedAuthentication": "该供应商没有提供受支持的认证方式。",
  "providers.onboardingFailed": "无法创建供应商配置。",
  "providers.onboardingComplete": "供应商配置创建成功。",
  "sidebar.dashboard": "仪表盘",
  "sidebar.lifecycle": "生命周期",
  "sidebar.analytics": "分析",
  "sidebar.projects": "项目",
  "sidebar.team": "团队",
  "sidebar.documents": "供应商",
  "sidebar.providerManagement": "供应商管理",
  "sidebar.dataLibrary": "数据资料库",
  "sidebar.reports": "报告",
  "sidebar.wordAssistant": "文档助手",
  "sidebar.settings": "设置",
  "sidebar.getHelp": "获取帮助",
  "sidebar.search": "搜索",
  "sidebar.quickCreate": "快速创建",
  "sidebar.inbox": "收件箱",
  "sidebar.more": "更多",
  "sidebar.open": "打开",
  "sidebar.share": "共享",
  "sidebar.delete": "删除",
  "sidebar.administrator": "管理员",
  "logout.label": "退出登录",
  "logout.title": "退出 VulcanModelRouter？",
  "logout.description": "你将返回管理员登录页。",
  "logout.cancel": "取消",
  "logout.confirm": "立即退出",
}

// messageCatalogs maps each supported locale to its complete authored-page translation catalog.
// messageCatalogs 将每个受支持语言映射到其完整的已编写页面翻译目录。
const messageCatalogs: Record<Locale, Messages> = {
  en: englishMessages,
  zh: chineseMessages,
}

// I18nContextValue exposes the current locale, exact string lookup, and a manual two-language toggle.
// I18nContextValue 暴露当前语言、精确字符串查询和手动双语切换。
interface I18nContextValue {
  // locale is the active user-interface language.
  // locale 是当前生效的用户界面语言。
  locale: Locale
  // t returns the active translation for one authored-page message key.
  // t 返回一个已编写页面消息键在当前语言下的翻译。
  t: (key: TranslationKey) => string
  // toggleLocale swaps English and Chinese for the current browser page.
  // toggleLocale 会为当前浏览器页面在英文与中文之间切换。
  toggleLocale: () => void
}

// englishFallbackContext keeps isolated component tests deterministic without requiring a provider wrapper.
// englishFallbackContext 使隔离组件测试无需 Provider 包装也能保持确定性的英文行为。
const englishFallbackContext: I18nContextValue = {
  locale: "en",
  t: (key) => englishMessages[key],
  toggleLocale: () => undefined,
}

// I18nContext carries page-scoped locale state without coupling it to management authentication state.
// I18nContext 传递页面级语言状态，但不与管理认证状态耦合。
const I18nContext = createContext<I18nContextValue>(englishFallbackContext)

// I18nProviderProps defines the React subtree that receives browser-aware translation state.
// I18nProviderProps 定义接收浏览器感知翻译状态的 React 子树。
interface I18nProviderProps {
  // children is the complete management application subtree.
  // children 是完整的管理应用子树。
  children: ReactNode
}

// isChineseLanguageTag recognizes every standard Chinese language tag, including zh-Hans and zh-Hant variants.
// isChineseLanguageTag 识别所有标准中文语言标签，包括 zh-Hans 与 zh-Hant 变体。
export function isChineseLanguageTag(languageTag: string): boolean {
  return languageTag.trim().toLowerCase().startsWith("zh")
}

// detectBrowserLocale selects simplified Chinese for every primary Chinese browser language tag and otherwise uses English.
// detectBrowserLocale 会为所有主浏览器语言为中文的标签选择简体中文，否则使用英文。
export function detectBrowserLocale(): Locale {
  if (typeof navigator === "undefined") {
    return "en"
  }

  return isChineseLanguageTag(navigator.language) ? "zh" : "en"
}

// I18nProvider initializes browser-aware language state and updates the document language declaration.
// I18nProvider 初始化浏览器感知语言状态，并更新文档语言声明。
export function I18nProvider({ children }: I18nProviderProps) {
  // locale is initialized only once from the browser and can then be switched manually.
  // locale 只会从浏览器初始化一次，随后可由用户手动切换。
  const [locale, setLocale] = useState<Locale>(detectBrowserLocale)

  // synchronizeDocumentLanguage keeps assistive technologies aligned with the selected content language.
  // synchronizeDocumentLanguage 使辅助技术与所选内容语言保持一致。
  useEffect(() => {
    document.documentElement.lang = locale === "zh" ? "zh-CN" : "en"
  }, [locale])

  // contextValue groups the active catalog lookup with the page-local manual language switch.
  // contextValue 将当前目录查询与页面级手动语言切换组合在一起。
  const contextValue = useMemo<I18nContextValue>(
    () => ({
      locale,
      t: (key) => messageCatalogs[locale][key],
      toggleLocale: () => {
        setLocale((currentLocale) => (currentLocale === "zh" ? "en" : "zh"))
      },
    }),
    [locale],
  )

  return <I18nContext.Provider value={contextValue}>{children}</I18nContext.Provider>
}

// useI18n returns the page language state, using the deterministic English fallback outside the provider.
// useI18n 返回页面语言状态，并在 Provider 外使用确定性的英文回退。
export function useI18n(): I18nContextValue {
  return useContext(I18nContext)
}
