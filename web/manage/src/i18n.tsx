import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

// Locale identifies each supported user-interface language.
// Locale 标识每种受支持的用户界面语言。
export type Locale = "en" | "zh";

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
  "login.error.validation":
    "The local management API could not validate the auth token.",
  "brand.platform": "VulcanCode Platform",
  "brand.controlPlane": "Local AI Control Plane",
  "brand.description":
    "Route local model access through one focused management surface.",
  "dashboard.overview": "Model Router overview",
  "capabilities.modelsTitle": "Model Capabilities",
  "capabilities.servicesTitle": "Special Service Capabilities",
  "capabilities.loadFailed": "Unable to load capability catalogs",
  "capabilities.loadFailedDescription": "One or more provider catalogs failed validation. No assumed capability data is shown.",
  "capabilities.noModels": "No models configured",
  "capabilities.noModelsDescription": "Add and authorize a provider before inspecting model capabilities.",
  "capabilities.noServices": "No special services configured",
  "capabilities.noServicesDescription": "Configured providers do not currently expose a typed special-service contract.",
  "capabilities.enabled": "Enabled",
  "capabilities.disabled": "Disabled",
  "capabilities.authorized": "Authorized",
  "capabilities.unauthorized": "Not authorized",
  "capabilities.readyCredentials": "Ready credentials",
  "capabilities.unavailable": "Unavailable",
  "capabilities.configured": "Configured",
  "capabilities.entitled": "Entitled",
  "capabilities.cooling": "Cooling",
  "capabilities.exhausted": "Exhausted",
  "capabilities.invalid": "Invalid",
  "capabilities.blockedBy": "Blocked by",
  "capabilities.evidence": "Evidence",
  "capabilities.legacyConversation": "Legacy conversation",
  "capabilities.contextWindow": "Context window",
  "capabilities.maxInput": "Max input",
  "capabilities.maxOutput": "Max output",
  "capabilities.recommendedOutput": "Recommended output",
  "capabilities.unknown": "Unknown",
  "capabilities.none": "None",
  "capabilities.inputModalities": "Input modalities",
  "capabilities.outputModalities": "Output modalities",
  "capabilities.delivery": "Delivery",
  "capabilities.toolCalling": "Tool calling",
  "capabilities.parallelTools": "Parallel tools",
  "capabilities.streamingToolArguments": "Streaming tool arguments",
  "capabilities.strictJSON": "Strict JSON schema",
  "capabilities.reasoning": "Reasoning",
  "capabilities.mediaInputs": "Media input contracts",
  "capabilities.mediaOutputs": "Media output contracts",
  "services.backendKind": "Backend kind",
  "services.invocationMode": "Invocation mode",
  "services.outputModes": "Output modes",
  "services.evidenceKinds": "Evidence kinds",
  "services.evidenceRequirements": "Evidence requirements",
  "services.noTypedContract": "This service profile has no typed capability contract.",
  "diagnostics.resourcesTitle": "Resource Diagnostics",
  "diagnostics.executionsTitle": "Execution Diagnostics",
  "diagnostics.resourcesDescription": "Metadata-only Router resource lifecycle history. Content, object locations, source URLs, and owners are excluded.",
  "diagnostics.executionsDescription": "Public execution lifecycle history. Requests, provider task handles, and preparation handles are excluded.",
  "diagnostics.loadFailed": "Unable to load management diagnostics.",
  "diagnostics.empty": "No diagnostic records are available.",
  "diagnostics.unknownMime": "Unknown MIME type",
  "diagnostics.kind": "Kind",
  "diagnostics.source": "Source",
  "diagnostics.size": "Size",
  "diagnostics.updated": "Updated",
  "diagnostics.status": "Status",
  "diagnostics.expires": "Expires",
  "providers.title": "Provider Management",
  "providers.authorizedDescription":
    "Manage configured providers and their authorized API or device credentials.",
  "providers.description":
    "Choose a provider, then select the exact site or plan to authorize.",
  "providers.add": "Add provider",
  "providers.addCredential": "Add credential",
  "providers.noCredentialsForProvider": "No credentials have been added to this provider.",
  "providers.cancelAdd": "Close provider creation",
  "providers.search": "Filter providers",
  "providers.searchPlaceholder": "Filter by provider, site, or plan…",
  "providers.chooseProvider": "Choose a provider",
  "providers.chooseVariant": "Choose a site or plan",
  "providers.configureProvider": "Configure provider",
  "providers.directConfiguration": "Configure directly",
  "providers.backToProviders": "Back to providers",
  "providers.customProvider": "Custom provider",
  "providers.customCardDescription":
    "Connect a compatible API endpoint through one preferred protocol.",
  "providers.customDescription":
    "Configure an OpenAI Chat or Vertex-compatible endpoint and its initial model.",
  "providers.customProfilesFailed":
    "Unable to load the custom protocol profiles.",
  "providers.customName": "Provider name",
  "providers.protocol": "Protocol",
  "providers.selectProtocol": "Select a protocol",
  "providers.authentication": "Authentication",
  "providers.baseURL": "Base URL",
  "providers.upstreamModelID": "Upstream model ID",
  "providers.modelDisplayName": "Model display name (optional)",
  "providers.creating": "Creating…",
  "providers.noMatches": "No providers match this filter.",
  "providers.noAuthorized": "No authorized providers yet.",
  "providers.authorizations": "Authorizations",
  "providers.instanceHandle": "Instance handle",
  "providers.loading": "Loading provider data…",
  "providers.catalogLoadFailed":
    "Unable to load the provider catalog. Adding providers is temporarily unavailable.",
  "providers.authorizedLoadFailed":
    "Unable to load the authorized provider list.",
  "providers.variants": "options",
  "providers.select": "Select",
  "providers.selected": "Selected",
  "providers.kimi.description":
    "Moonshot AI services across regional Open Platform sites and the separate Coding Plan.",
  "providers.kimi.cnDescription":
    "Kimi Open Platform service hosted at the CN API site.",
  "providers.kimi.globalDescription":
    "Kimi Open Platform service hosted at the Global API site.",
  "providers.kimi.codingDescription":
    "Membership-based coding service with dedicated models and credentials.",
  "providers.alibaba.description":
    "Alibaba Cloud Model Studio APIs and coding subscriptions across CN and Global sites.",
  "providers.alibaba.modelStudioCNDescription":
    "Model Studio APIs hosted at the CN site.",
  "providers.alibaba.modelStudioGlobalDescription":
    "Model Studio APIs hosted at the Global site.",
  "providers.alibaba.modelStudioWorkspaceGlobalDescription":
    "Workspace-isolated Model Studio APIs hosted in Singapore.",
  "providers.alibaba.codingPlanCNDescription":
    "Coding Plan subscription hosted at the CN site.",
  "providers.alibaba.codingPlanGlobalDescription":
    "Coding Plan subscription hosted at the Global site.",
  "providers.alibaba.tokenPlanPersonalCNDescription":
    "Personal Token Plan subscription hosted at the CN site.",
  "providers.alibaba.tokenPlanTeamCNDescription":
    "Team Token Plan subscription hosted at the CN site.",
  "providers.alibaba.tokenPlanTeamGlobalDescription":
    "Team Token Plan subscription hosted at the Global site.",
  "providers.openai.description":
    "OpenAI API and account-scoped Codex products.",
  "providers.openai.apiDescription":
    "Public OpenAI API using the Responses protocol.",
  "providers.openai.codexDescription": "ChatGPT account-scoped Codex service.",
  "providers.openai.codexAPIKeyDescription":
    "Codex Responses service configured with a standalone bearer API key.",
  "providers.anthropic.description":
    "Anthropic API and Claude Code subscription products.",
  "providers.anthropic.apiDescription": "Public Anthropic API using Messages.",
  "providers.anthropic.claudeCodeDescription":
    "Anthropic account-scoped Claude Code subscription.",
  "providers.google.description":
    "Google AI Studio, Interactions, Vertex AI, and Antigravity products.",
  "providers.google.aiStudioDescription":
    "Google AI Studio GenerateContent API.",
  "providers.google.interactionsDescription": "Google native Interactions API.",
  "providers.google.vertexDescription":
    "Google Cloud Vertex AI using one project-scoped service account.",
  "providers.google.antigravityDescription":
    "Google account-scoped Antigravity agent backend.",
  "providers.xai.description": "xAI API and account-authorized products.",
  "providers.xai.apiDescription": "Public xAI API using xAI Responses.",
  "providers.xai.oauthDescription":
    "Grok CLI account authorization using xAI Responses.",
  "providers.handle": "Instance handle",
  "providers.name": "Name",
  "providers.credentialName": "Credential name",
  "providers.apiKey": "API key",
  "providers.workspaceID": "Workspace ID",
  "providers.workspaceIDHelp":
    "Enter the lowercase Workspace hostname label without a domain name.",
  "providers.deviceFlow": "Device authorization",
  "providers.oauth": "Browser authorization",
  "providers.serviceAccount": "Service account",
  "providers.vertexLocation": "Vertex location",
  "providers.serviceAccountJSON": "Service account JSON",
  "providers.serviceAccountHelp":
    "The private key is sent only to the local management API, normalized, and stored in protected credential storage.",
  "providers.invalidServiceAccountJSON":
    "Enter a valid Google service account JSON object.",
  "providers.onboard": "Create provider",
  "providers.startAuthorization": "Start authorization",
  "providers.openAuthorization": "Open authorization page",
  "providers.callbackURL": "Callback URL",
  "providers.callbackHelp":
    "After Google redirects to localhost, paste the complete URL from the browser address bar here.",
  "providers.claudeCallbackHelp":
    "After Claude authorization, paste the complete localhost callback URL or the displayed code#state value here.",
  "providers.completeAuthorization": "Complete authorization",
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
  "providers.unsupportedAuthentication":
    "This provider does not expose a supported authentication method.",
  "providers.onboardingFailed": "Unable to create the provider configuration.",
  "providers.reauthorizationFailed":
    "Unable to replace or reauthorize this credential.",
  "providers.onboardingComplete":
    "Provider configuration created successfully.",
  "providers.refreshMetadata": "Refresh account data",
  "providers.refreshingMetadata": "Refreshing account data…",
  "providers.metadataUnsupported":
    "This provider does not expose account, plan, or allowance data.",
  "providers.metadataTemporarilyUnavailable":
    "Provider account data is temporarily unavailable.",
  "providers.refreshCredential": "Refresh credential",
  "providers.replaceCredential": "Replace credential",
  "providers.reauthorizeCredential": "Reauthorize",
  "providers.deleteCredential": "Delete credential",
  "providers.deleteCredentialTitle": "Delete this credential?",
  "providers.deleteCredentialDescription":
    "This permanently removes the credential and its access bindings. The provider configuration and model catalog are retained.",
  "providers.credentialDeleteFailed": "Unable to delete this credential.",
  "providers.cancel": "Cancel",
  "providers.refreshingCredential": "Refreshing credential…",
  "providers.credentialRefreshFailed":
    "Unable to refresh this credential. Reauthorize it if the provider rejected the refresh token.",
  "providers.credentialAuthenticationRejected":
    "The saved credential was rejected. Reauthorize this provider.",
  "providers.credentialAuthenticationUnavailable":
    "The provider is temporarily unreachable. Your saved credential was not changed.",
  "providers.credentialAuthenticationInvalidResponse":
    "The provider returned an unreadable authentication response. Your saved credential was not changed.",
  "providers.metadataRefreshFailed": "Unable to refresh provider account data.",
  "providers.metadataAuthenticationFailed":
    "The saved credential was rejected. Reauthorize this provider.",
  "providers.metadataUnavailable":
    "The provider is temporarily unreachable. Your saved credential was not changed.",
  "providers.metadataInvalidResponse":
    "The provider returned account data that could not be read.",
  "providers.models": "Models",
  "providers.modelEnabled": "Enabled",
  "providers.modelDisabled": "Disabled",
  "providers.modelAuthorized": "Authorized",
  "providers.modelUnauthorized": "Not authorized",
  "providers.modelAuthorizationUnknown": "Authorization unknown",
  "providers.operatorDeclared": "Operator declared",
  "providers.providerDetected": "Provider detected",
  "providers.routingStrategy": "Account scheduling",
  "providers.routingStrategyHelp": "Override the global account routing strategy for this provider.",
  "providers.routingInherit": "Use global default",
  "providers.routingUpdateFailed": "Unable to update provider account scheduling.",
  "providers.priority": "Priority",
  "providers.plans": "Plans",
  "providers.membershipPlan": "Membership plan",
  "providers.selectMembershipPlan": "Select a membership plan",
  "providers.membershipPlanHelp":
    "Choose the plan attached to this API key. The selection is saved only after onboarding succeeds.",
  "providers.allowances": "Allowances and credits",
  "providers.remaining": "Remaining",
  "providers.remainingRatio": "Remaining ratio",
  "providers.used": "Used",
  "providers.limit": "Limit",
  "providers.window": "Window",
  "providers.resetAt": "Resets at",
  "providers.unknownAmount": "Amount unavailable",
  "providers.allowanceStatus.available": "Available",
  "providers.allowanceStatus.low": "Low",
  "providers.allowanceStatus.exhausted": "Exhausted",
  "providers.allowanceStatus.unknown": "Unknown",
  "providers.allowanceStatus.unavailable": "Unavailable",
  "providers.allowanceMetrics.codexPrimary": "Codex short window",
  "providers.allowanceMetrics.codexSecondary": "Codex long window",
  "providers.allowanceMetrics.codeReviewPrimary": "Code review short window",
  "providers.allowanceMetrics.codeReviewSecondary": "Code review long window",
  "providers.allowanceMetrics.resetCredits": "Rate-limit reset credits",
  "providers.allowanceMetrics.fiveHour": "5-hour window",
  "providers.allowanceMetrics.sevenDay": "7-day window",
  "providers.allowanceMetrics.sevenDayOAuthApps": "OAuth apps · 7-day window",
  "providers.allowanceMetrics.sevenDayOpus": "Opus · 7-day window",
  "providers.allowanceMetrics.sevenDaySonnet": "Sonnet · 7-day window",
  "providers.allowanceMetrics.sevenDayCowork": "Cowork · 7-day window",
  "providers.allowanceMetrics.providerSpecial": "Provider special window",
  "providers.allowanceMetrics.extraUsage": "Extra usage",
  "providers.allowanceMetrics.weeklyUsage": "Weekly usage",
  "providers.allowanceMetrics.monthlyBudget": "Monthly budget",
  "providers.allowanceMetrics.onDemandCap": "Pay-as-you-go cap",
  "providers.allowanceMetrics.googleOneAI": "Google One AI credits",
  "sidebar.dashboard": "Dashboard",
  "sidebar.lifecycle": "Lifecycle",
  "sidebar.analytics": "Analytics",
  "sidebar.projects": "Projects",
  "sidebar.team": "Team",
  "sidebar.documents": "Providers",
  "sidebar.providerManagement": "Provider Management",
  "sidebar.credentialManagement": "Credential Management",
  "credentials.title": "Credential Management",
  "providerConfig.title": "Provider Management",
  "providerConfig.description":
    "Manage provider definitions, endpoints, model catalogs, and capabilities independently from account credentials.",
  "providerConfig.addProvider": "Add provider",
  "providerConfig.addDescription":
    "Configure the protocol, provider identity, and service endpoint first. Add models from provider settings and credentials from Credential Management afterward.",
  "providerConfig.nativeProviders": "Native providers",
  "providerConfig.configuredProviders": "Configured providers",
  "providerConfig.loading": "Loading provider inventory…",
  "providerConfig.empty": "No provider configuration has been created yet.",
  "providerConfig.loadFailed": "Unable to load provider inventory.",
  "providerConfig.createFailed": "Unable to create provider configuration.",
  "providerConfig.catalogUnavailable": "The model catalog for this provider could not be loaded.",
  "providerConfig.definition": "Provider definition",
  "providerConfig.selectDefinition": "Select a native provider or custom integration",
  "providerConfig.customProvider": "New custom provider",
  "providerConfig.displayName": "Provider name",
  "providerConfig.displayNamePlaceholder": "DeepSeek",
  "providerConfig.displayNameHelp":
    "The human-readable name shown in management pages. It can be changed later.",
  "providerConfig.handle": "Provider handle",
  "providerConfig.handleHelp":
    "A unique, stable workspace alias used by VulcanCode, such as deepseek or deepseek-cn. Use lowercase letters, digits, periods, underscores, or hyphens, and avoid changing it after use.",
  "providerConfig.protocol": "Protocol",
  "providerConfig.selectProtocol": "Select an executable protocol",
  "providerConfig.protocolRequired": "Select an executable custom-provider protocol.",
  "providerConfig.baseURL": "Base URL",
  "providerConfig.region": "Region",
  "providerConfig.upstreamModelID": "Upstream model ID",
  "providerConfig.upstreamModelIDPlaceholder": "deepseek-chat",
  "providerConfig.modelDisplayName": "Model display name",
  "providerConfig.modelDisplayNamePlaceholder": "DeepSeek Chat",
  "providerConfig.optional": "optional",
  "providerConfig.contextWindow": "Context window",
  "providerConfig.maxOutputTokens": "Maximum output tokens",
  "providerConfig.toolCalling": "Tool calling",
  "providerConfig.reasoning": "Reasoning",
  "providerConfig.unknown": "Unknown",
  "providerConfig.native": "Native",
  "providerConfig.unsupported": "Unsupported",
  "providerConfig.discoveryCredential": "Credential for /models",
  "providerConfig.selectCredential": "Select an existing credential",
  "providerConfig.discoverModels": "Discover models",
  "providerConfig.discoveryFailed": "Unable to discover provider models.",
  "providerConfig.editModels": "Edit models",
  "providerConfig.editModelsDescription":
    "Add, update, or remove models and declare only capability limits you have verified.",
  "providerConfig.addModel": "Add model",
  "providerConfig.removeModel": "Remove model",
  "providerConfig.saveModels": "Save models",
  "providerConfig.modelSaveFailed": "Unable to save the custom model catalog.",
  "providerConfig.editSettings": "Edit provider settings",
  "providerConfig.editSettingsDescription":
    "Change the local display name and stable handle. Protocol, endpoints, models, and credentials remain unchanged.",
  "providerConfig.saveSettings": "Save settings",
  "providerConfig.identitySaveFailed": "Unable to save provider settings.",
  "providerConfig.models": "models",
  "providerConfig.credentials": "credentials",
  "providerConfig.globalEndpoint": "Global",
  "providerConfig.cancel": "Cancel",
  "providerConfig.create": "Create provider",
  "providerConfig.creating": "Creating…",
  "sidebar.modelCapabilities": "Model Capabilities",
  "sidebar.serviceCapabilities": "Special Services",
  "sidebar.resourceDiagnostics": "Resource Diagnostics",
  "sidebar.executionDiagnostics": "Execution Diagnostics",
  "sidebar.dataLibrary": "Data Library",
  "sidebar.reports": "Reports",
  "sidebar.wordAssistant": "Word Assistant",
  "sidebar.settings": "Settings",
  "settings.accountRouting": "Account routing",
  "settings.accountRoutingHelp":
    "Choose how eligible accounts are selected by default. Providers may override this setting.",
  "settings.defaultStrategy": "Default strategy",
  "settings.roundRobin": "Balanced usage",
  "settings.fillFirst": "Preferred account",
  "settings.roundRobinHelp":
    "Balances requests across equally eligible accounts.",
  "settings.fillFirstHelp":
    "Uses the highest-priority eligible account until it becomes unavailable.",
  "settings.ineligibleSkipped":
    "Accounts without entitlement, cooling down, exhausted, disabled, or invalid are always skipped.",
  "settings.revision": "Settings revision",
  "settings.save": "Save",
  "settings.saving": "Saving…",
  "settings.saveFailed": "Unable to save account routing settings.",
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
} as const;

// TranslationKey restricts translation reads to strings defined by the canonical message catalog.
// TranslationKey 将翻译读取限制为规范消息目录中定义的字符串。
export type TranslationKey = keyof typeof englishMessages;

// Messages represents one complete translation catalog for all authored router-page strings.
// Messages 表示已编写 Router 页面全部字符串的一个完整翻译目录。
type Messages = Record<TranslationKey, string>;

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
  "login.rememberCredentialWarning":
    "管理凭证将以明文保存在此浏览器的 localStorage 中，请仅在受信任设备上使用。",
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
  "capabilities.modelsTitle": "模型能力",
  "capabilities.servicesTitle": "特殊服务能力",
  "capabilities.loadFailed": "无法加载能力目录",
  "capabilities.loadFailedDescription": "一个或多个供应商目录校验失败，页面不会显示推测的能力数据。",
  "capabilities.noModels": "尚未配置模型",
  "capabilities.noModelsDescription": "请先新增并授权供应商，再检查模型能力。",
  "capabilities.noServices": "尚未配置特殊服务",
  "capabilities.noServicesDescription": "当前已配置供应商没有提供类型化特殊服务合同。",
  "capabilities.enabled": "已启用",
  "capabilities.disabled": "已停用",
  "capabilities.authorized": "已授权",
  "capabilities.unauthorized": "未授权",
  "capabilities.readyCredentials": "就绪凭据",
  "capabilities.unavailable": "不可用",
  "capabilities.configured": "已配置",
  "capabilities.entitled": "已授权",
  "capabilities.cooling": "冷却中",
  "capabilities.exhausted": "额度耗尽",
  "capabilities.invalid": "无效",
  "capabilities.blockedBy": "阻塞原因",
  "capabilities.evidence": "能力证据",
  "capabilities.legacyConversation": "旧版会话",
  "capabilities.contextWindow": "上下文窗口",
  "capabilities.maxInput": "最大输入",
  "capabilities.maxOutput": "最大输出",
  "capabilities.recommendedOutput": "推荐输出",
  "capabilities.unknown": "未知",
  "capabilities.none": "无",
  "capabilities.inputModalities": "输入模态",
  "capabilities.outputModalities": "输出模态",
  "capabilities.delivery": "交付方式",
  "capabilities.toolCalling": "工具调用",
  "capabilities.parallelTools": "并行工具",
  "capabilities.streamingToolArguments": "流式工具参数",
  "capabilities.strictJSON": "严格 JSON Schema",
  "capabilities.reasoning": "推理",
  "capabilities.mediaInputs": "媒体输入合同",
  "capabilities.mediaOutputs": "媒体输出合同",
  "services.backendKind": "后端类型",
  "services.invocationMode": "调用模式",
  "services.outputModes": "输出模式",
  "services.evidenceKinds": "证据类型",
  "services.evidenceRequirements": "证据要求",
  "services.noTypedContract": "该服务配置没有类型化能力合同。",
  "diagnostics.resourcesTitle": "资源诊断",
  "diagnostics.executionsTitle": "执行诊断",
  "diagnostics.resourcesDescription": "仅显示 Router 资源生命周期元数据，不包含内容、对象位置、来源 URL 与所有者。",
  "diagnostics.executionsDescription": "显示公开执行生命周期，不包含请求、供应商任务句柄与准备句柄。",
  "diagnostics.loadFailed": "无法加载管理诊断数据。",
  "diagnostics.empty": "暂无诊断记录。",
  "diagnostics.unknownMime": "未知 MIME 类型",
  "diagnostics.kind": "类型",
  "diagnostics.source": "来源",
  "diagnostics.size": "大小",
  "diagnostics.updated": "更新时间",
  "diagnostics.status": "状态",
  "diagnostics.expires": "过期时间",
  "providers.title": "供应商管理",
  "providers.authorizedDescription":
    "管理已配置供应商及其 API 或设备授权凭据。",
  "providers.description": "选择供应商，然后选择需要授权的精确站点或套餐。",
  "providers.add": "新增供应商",
  "providers.addCredential": "新增凭据",
  "providers.noCredentialsForProvider": "该供应商尚未添加凭据。",
  "providers.cancelAdd": "关闭供应商新增",
  "providers.search": "过滤供应商",
  "providers.searchPlaceholder": "按供应商、站点或套餐过滤…",
  "providers.chooseProvider": "选择供应商",
  "providers.chooseVariant": "选择站点或套餐",
  "providers.configureProvider": "配置供应商",
  "providers.directConfiguration": "直接配置",
  "providers.backToProviders": "返回供应商列表",
  "providers.customProvider": "自定义供应商",
  "providers.customCardDescription": "连接采用单一优势协议的兼容 API 端点。",
  "providers.customDescription":
    "配置 OpenAI Chat 或 Vertex 兼容端点及其初始模型。",
  "providers.customProfilesFailed": "无法加载自定义协议列表。",
  "providers.customName": "供应商名称",
  "providers.protocol": "协议",
  "providers.selectProtocol": "选择协议",
  "providers.authentication": "认证方式",
  "providers.baseURL": "基础 URL",
  "providers.upstreamModelID": "上游模型 ID",
  "providers.modelDisplayName": "模型显示名称（可选）",
  "providers.creating": "正在创建…",
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
  "providers.kimi.description":
    "Moonshot AI 在不同区域的开放平台站点以及独立的 Coding Plan 服务。",
  "providers.kimi.cnDescription": "托管于 CN API 站点的 Kimi 开放平台服务。",
  "providers.kimi.globalDescription":
    "托管于 Global API 站点的 Kimi 开放平台服务。",
  "providers.kimi.codingDescription": "提供专用模型与凭据的订阅制编程服务。",
  "providers.alibaba.description":
    "Alibaba Cloud Model Studio 在 CN 与 Global 站点提供的 API 与编程订阅服务。",
  "providers.alibaba.modelStudioCNDescription":
    "托管于 CN 站点的 Model Studio API。",
  "providers.alibaba.modelStudioGlobalDescription":
    "托管于 Global 站点的 Model Studio API。",
  "providers.alibaba.modelStudioWorkspaceGlobalDescription":
    "托管于新加坡并按 Workspace 隔离的 Model Studio API。",
  "providers.alibaba.codingPlanCNDescription":
    "托管于 CN 站点的 Coding Plan 订阅服务。",
  "providers.alibaba.codingPlanGlobalDescription":
    "托管于 Global 站点的 Coding Plan 订阅服务。",
  "providers.alibaba.tokenPlanPersonalCNDescription":
    "托管于 CN 站点的 Personal Token Plan 订阅服务。",
  "providers.alibaba.tokenPlanTeamCNDescription":
    "托管于 CN 站点的 Team Token Plan 订阅服务。",
  "providers.alibaba.tokenPlanTeamGlobalDescription":
    "托管于 Global 站点的 Team Token Plan 订阅服务。",
  "providers.openai.description": "OpenAI API 与账号授权的 Codex 产品。",
  "providers.openai.apiDescription": "使用 Responses 协议的 OpenAI 公共 API。",
  "providers.openai.codexDescription": "通过 ChatGPT 账号授权的 Codex 服务。",
  "providers.openai.codexAPIKeyDescription":
    "使用独立 Bearer API Key 配置的 Codex Responses 服务。",
  "providers.anthropic.description": "Anthropic API 与 Claude Code 订阅产品。",
  "providers.anthropic.apiDescription":
    "使用 Messages 协议的 Anthropic 公共 API。",
  "providers.anthropic.claudeCodeDescription":
    "通过 Anthropic 账号授权的 Claude Code 订阅服务。",
  "providers.google.description":
    "Google AI Studio、Interactions、Vertex AI 与 Antigravity 产品。",
  "providers.google.aiStudioDescription":
    "Google AI Studio GenerateContent API。",
  "providers.google.interactionsDescription": "Google 原生 Interactions API。",
  "providers.google.vertexDescription":
    "使用项目作用域服务账号的 Google Cloud Vertex AI。",
  "providers.google.antigravityDescription":
    "通过 Google 账号授权的 Antigravity 智能体后端。",
  "providers.xai.description": "xAI API 与账号授权产品。",
  "providers.xai.apiDescription": "使用 xAI Responses 协议的 xAI 公共 API。",
  "providers.xai.oauthDescription":
    "通过 Grok CLI 账号授权的 xAI Responses 服务。",
  "providers.handle": "实例标识",
  "providers.name": "名称",
  "providers.credentialName": "凭据名称",
  "providers.apiKey": "API 密钥",
  "providers.workspaceID": "Workspace ID",
  "providers.workspaceIDHelp":
    "请输入小写 Workspace 主机标签，不要包含域名。",
  "providers.deviceFlow": "设备授权",
  "providers.oauth": "浏览器授权",
  "providers.serviceAccount": "服务账号",
  "providers.vertexLocation": "Vertex 区域",
  "providers.serviceAccountJSON": "服务账号 JSON",
  "providers.serviceAccountHelp":
    "私钥仅发送到本地管理 API，经规范化后保存到受保护的凭据存储中。",
  "providers.invalidServiceAccountJSON":
    "请输入有效的 Google 服务账号 JSON 对象。",
  "providers.onboard": "创建供应商",
  "providers.startAuthorization": "开始授权",
  "providers.openAuthorization": "打开授权页面",
  "providers.callbackURL": "回调 URL",
  "providers.callbackHelp":
    "Google 跳转到 localhost 后，请将浏览器地址栏中的完整 URL 粘贴到这里。",
  "providers.claudeCallbackHelp":
    "完成 Claude 授权后，请在此粘贴完整的 localhost 回调 URL，或页面显示的 code#state 值。",
  "providers.completeAuthorization": "完成授权",
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
  "providers.reauthorizationFailed": "无法更换或重新授权此凭据。",
  "providers.onboardingComplete": "供应商配置创建成功。",
  "providers.refreshMetadata": "刷新账号数据",
  "providers.refreshingMetadata": "正在刷新账号数据…",
  "providers.metadataUnsupported": "该供应商不提供账号、套餐或额度数据。",
  "providers.metadataTemporarilyUnavailable": "供应商账号数据暂时不可用。",
  "providers.refreshCredential": "刷新凭据",
  "providers.replaceCredential": "更换凭据",
  "providers.reauthorizeCredential": "重新授权",
  "providers.deleteCredential": "删除凭据",
  "providers.deleteCredentialTitle": "删除这个凭据？",
  "providers.deleteCredentialDescription":
    "这会永久删除该凭据及其访问绑定；供应商配置与模型目录会继续保留。",
  "providers.credentialDeleteFailed": "无法删除该凭据。",
  "providers.cancel": "取消",
  "providers.refreshingCredential": "正在刷新凭据…",
  "providers.credentialRefreshFailed":
    "无法刷新该凭据；如果供应商拒绝了刷新令牌，请重新授权。",
  "providers.credentialAuthenticationRejected":
    "已保存的凭据被供应商拒绝，请重新授权此供应商。",
  "providers.credentialAuthenticationUnavailable":
    "暂时无法连接供应商，已保存的凭据不会被更改。",
  "providers.credentialAuthenticationInvalidResponse":
    "供应商返回的认证响应无法解析，已保存的凭据不会被更改。",
  "providers.metadataRefreshFailed": "无法刷新供应商账号数据。",
  "providers.metadataAuthenticationFailed":
    "已保存的凭据被供应商拒绝，请重新授权此供应商。",
  "providers.metadataUnavailable":
    "暂时无法连接供应商，已保存的凭据不会被更改。",
  "providers.metadataInvalidResponse": "供应商返回的账号数据无法解析。",
  "providers.models": "模型",
  "providers.modelEnabled": "已启用",
  "providers.modelDisabled": "已停用",
  "providers.modelAuthorized": "已授权",
  "providers.modelUnauthorized": "未授权",
  "providers.modelAuthorizationUnknown": "授权未知",
  "providers.operatorDeclared": "管理员声明",
  "providers.providerDetected": "供应商识别",
  "providers.routingStrategy": "账号调度",
  "providers.routingStrategyHelp": "为该供应商覆盖全局账号调度策略。",
  "providers.routingInherit": "使用全局默认值",
  "providers.routingUpdateFailed": "无法更新供应商账号调度策略。",
  "providers.priority": "优先级",
  "providers.plans": "套餐",
  "providers.membershipPlan": "会员套餐",
  "providers.selectMembershipPlan": "请选择会员套餐",
  "providers.membershipPlanHelp":
    "请选择该 API 密钥所属套餐；仅在录入成功后保存此选择。",
  "providers.allowances": "额度与积分",
  "providers.remaining": "剩余",
  "providers.remainingRatio": "剩余比例",
  "providers.used": "已用",
  "providers.limit": "总额",
  "providers.window": "额度周期",
  "providers.resetAt": "重置时间",
  "providers.unknownAmount": "金额未知",
  "providers.allowanceStatus.available": "可用",
  "providers.allowanceStatus.low": "即将用尽",
  "providers.allowanceStatus.exhausted": "已用尽",
  "providers.allowanceStatus.unknown": "状态未知",
  "providers.allowanceStatus.unavailable": "暂不可用",
  "providers.allowanceMetrics.codexPrimary": "Codex 短周期",
  "providers.allowanceMetrics.codexSecondary": "Codex 长周期",
  "providers.allowanceMetrics.codeReviewPrimary": "代码审查短周期",
  "providers.allowanceMetrics.codeReviewSecondary": "代码审查长周期",
  "providers.allowanceMetrics.resetCredits": "限额重置次数",
  "providers.allowanceMetrics.fiveHour": "5 小时周期",
  "providers.allowanceMetrics.sevenDay": "7 天周期",
  "providers.allowanceMetrics.sevenDayOAuthApps": "OAuth 应用 · 7 天周期",
  "providers.allowanceMetrics.sevenDayOpus": "Opus · 7 天周期",
  "providers.allowanceMetrics.sevenDaySonnet": "Sonnet · 7 天周期",
  "providers.allowanceMetrics.sevenDayCowork": "Cowork · 7 天周期",
  "providers.allowanceMetrics.providerSpecial": "供应商特殊周期",
  "providers.allowanceMetrics.extraUsage": "额外用量",
  "providers.allowanceMetrics.weeklyUsage": "每周用量",
  "providers.allowanceMetrics.monthlyBudget": "月度额度",
  "providers.allowanceMetrics.onDemandCap": "按量付费上限",
  "providers.allowanceMetrics.googleOneAI": "Google One AI 积分",
  "sidebar.dashboard": "仪表盘",
  "sidebar.lifecycle": "生命周期",
  "sidebar.analytics": "分析",
  "sidebar.projects": "项目",
  "sidebar.team": "团队",
  "sidebar.documents": "供应商",
  "sidebar.providerManagement": "供应商管理",
  "sidebar.credentialManagement": "凭据管理",
  "credentials.title": "凭据管理",
  "providerConfig.title": "供应商管理",
  "providerConfig.description":
    "独立管理供应商定义、入口、模型目录与能力，不在此处管理账号凭据。",
  "providerConfig.addProvider": "新增供应商",
  "providerConfig.addDescription":
    "先配置协议、供应商身份与服务地址；模型随后在供应商设置中添加，凭据在凭据管理中添加。",
  "providerConfig.nativeProviders": "原生供应商",
  "providerConfig.configuredProviders": "已配置供应商",
  "providerConfig.loading": "正在加载供应商清单…",
  "providerConfig.empty": "尚未创建供应商配置。",
  "providerConfig.loadFailed": "无法加载供应商清单。",
  "providerConfig.createFailed": "无法创建供应商配置。",
  "providerConfig.catalogUnavailable": "无法加载该供应商的模型目录。",
  "providerConfig.definition": "供应商定义",
  "providerConfig.selectDefinition": "选择原生供应商或自定义集成",
  "providerConfig.customProvider": "新建自定义供应商",
  "providerConfig.displayName": "供应商名称",
  "providerConfig.displayNamePlaceholder": "DeepSeek",
  "providerConfig.displayNameHelp":
    "显示在管理页面中的易读名称，后续可以修改。",
  "providerConfig.handle": "供应商标识",
  "providerConfig.handleHelp":
    "VulcanCode 使用的工作区唯一稳定别名，例如 deepseek 或 deepseek-cn；仅使用小写字母、数字、点、下划线或连字符，投入使用后应避免修改。",
  "providerConfig.protocol": "协议",
  "providerConfig.selectProtocol": "选择可执行协议",
  "providerConfig.protocolRequired": "请选择可执行的自定义供应商协议。",
  "providerConfig.baseURL": "基础地址",
  "providerConfig.region": "区域",
  "providerConfig.upstreamModelID": "上游模型 ID",
  "providerConfig.upstreamModelIDPlaceholder": "deepseek-chat",
  "providerConfig.modelDisplayName": "模型显示名称",
  "providerConfig.modelDisplayNamePlaceholder": "DeepSeek Chat",
  "providerConfig.optional": "可选",
  "providerConfig.contextWindow": "上下文窗口",
  "providerConfig.maxOutputTokens": "最大输出 Token",
  "providerConfig.toolCalling": "工具调用",
  "providerConfig.reasoning": "推理",
  "providerConfig.unknown": "未知",
  "providerConfig.native": "原生支持",
  "providerConfig.unsupported": "不支持",
  "providerConfig.discoveryCredential": "/models 使用的凭据",
  "providerConfig.selectCredential": "选择一个既有凭据",
  "providerConfig.discoverModels": "拉取模型",
  "providerConfig.discoveryFailed": "无法拉取供应商模型。",
  "providerConfig.editModels": "编辑模型",
  "providerConfig.editModelsDescription":
    "新增、更新或删除模型，并且只声明已经确认的能力限制。",
  "providerConfig.addModel": "新增模型",
  "providerConfig.removeModel": "删除模型",
  "providerConfig.saveModels": "保存模型",
  "providerConfig.modelSaveFailed": "无法保存自定义模型目录。",
  "providerConfig.editSettings": "编辑供应商设置",
  "providerConfig.editSettingsDescription":
    "修改本地显示名称与稳定标识；协议、入口、模型及凭据保持不变。",
  "providerConfig.saveSettings": "保存设置",
  "providerConfig.identitySaveFailed": "无法保存供应商设置。",
  "providerConfig.models": "个模型",
  "providerConfig.credentials": "个凭据",
  "providerConfig.globalEndpoint": "Global",
  "providerConfig.cancel": "取消",
  "providerConfig.create": "创建供应商",
  "providerConfig.creating": "正在创建…",
  "sidebar.modelCapabilities": "模型能力",
  "sidebar.serviceCapabilities": "特殊服务",
  "sidebar.resourceDiagnostics": "资源诊断",
  "sidebar.executionDiagnostics": "执行诊断",
  "sidebar.dataLibrary": "数据资料库",
  "sidebar.reports": "报告",
  "sidebar.wordAssistant": "文档助手",
  "sidebar.settings": "设置",
  "settings.accountRouting": "账号调度",
  "settings.accountRoutingHelp":
    "选择合格账号的默认调度方式；供应商实例可以覆盖此设置。",
  "settings.defaultStrategy": "默认策略",
  "settings.roundRobin": "均衡使用",
  "settings.fillFirst": "优先账号",
  "settings.roundRobinHelp": "在资格相同的账号之间均衡分配请求。",
  "settings.fillFirstHelp": "优先使用排序最高的合格账号，直至该账号不可用。",
  "settings.ineligibleSkipped":
    "无权益、冷却中、额度耗尽、已停用或无效的账号始终会被自动跳过。",
  "settings.revision": "设置修订号",
  "settings.save": "保存",
  "settings.saving": "正在保存…",
  "settings.saveFailed": "无法保存账号调度设置。",
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
};

// messageCatalogs maps each supported locale to its complete authored-page translation catalog.
// messageCatalogs 将每个受支持语言映射到其完整的已编写页面翻译目录。
const messageCatalogs: Record<Locale, Messages> = {
  en: englishMessages,
  zh: chineseMessages,
};

// I18nContextValue exposes the current locale, exact string lookup, and a manual two-language toggle.
// I18nContextValue 暴露当前语言、精确字符串查询和手动双语切换。
interface I18nContextValue {
  // locale is the active user-interface language.
  // locale 是当前生效的用户界面语言。
  locale: Locale;
  // t returns the active translation for one authored-page message key.
  // t 返回一个已编写页面消息键在当前语言下的翻译。
  t: (key: TranslationKey) => string;
  // toggleLocale swaps English and Chinese for the current browser page.
  // toggleLocale 会为当前浏览器页面在英文与中文之间切换。
  toggleLocale: () => void;
}

// englishFallbackContext keeps isolated component tests deterministic without requiring a provider wrapper.
// englishFallbackContext 使隔离组件测试无需 Provider 包装也能保持确定性的英文行为。
const englishFallbackContext: I18nContextValue = {
  locale: "en",
  t: (key) => englishMessages[key],
  toggleLocale: () => undefined,
};

// I18nContext carries page-scoped locale state without coupling it to management authentication state.
// I18nContext 传递页面级语言状态，但不与管理认证状态耦合。
const I18nContext = createContext<I18nContextValue>(englishFallbackContext);

// I18nProviderProps defines the React subtree that receives browser-aware translation state.
// I18nProviderProps 定义接收浏览器感知翻译状态的 React 子树。
interface I18nProviderProps {
  // children is the complete management application subtree.
  // children 是完整的管理应用子树。
  children: ReactNode;
}

// isChineseLanguageTag recognizes every standard Chinese language tag, including zh-Hans and zh-Hant variants.
// isChineseLanguageTag 识别所有标准中文语言标签，包括 zh-Hans 与 zh-Hant 变体。
export function isChineseLanguageTag(languageTag: string): boolean {
  return languageTag.trim().toLowerCase().startsWith("zh");
}

// detectBrowserLocale selects simplified Chinese for every primary Chinese browser language tag and otherwise uses English.
// detectBrowserLocale 会为所有主浏览器语言为中文的标签选择简体中文，否则使用英文。
export function detectBrowserLocale(): Locale {
  if (typeof navigator === "undefined") {
    return "en";
  }

  return isChineseLanguageTag(navigator.language) ? "zh" : "en";
}

// I18nProvider initializes browser-aware language state and updates the document language declaration.
// I18nProvider 初始化浏览器感知语言状态，并更新文档语言声明。
export function I18nProvider({ children }: I18nProviderProps) {
  // locale is initialized only once from the browser and can then be switched manually.
  // locale 只会从浏览器初始化一次，随后可由用户手动切换。
  const [locale, setLocale] = useState<Locale>(detectBrowserLocale);

  // synchronizeDocumentLanguage keeps assistive technologies aligned with the selected content language.
  // synchronizeDocumentLanguage 使辅助技术与所选内容语言保持一致。
  useEffect(() => {
    document.documentElement.lang = locale === "zh" ? "zh-CN" : "en";
  }, [locale]);

  // contextValue groups the active catalog lookup with the page-local manual language switch.
  // contextValue 将当前目录查询与页面级手动语言切换组合在一起。
  const contextValue = useMemo<I18nContextValue>(
    () => ({
      locale,
      t: (key) => messageCatalogs[locale][key],
      toggleLocale: () => {
        setLocale((currentLocale) => (currentLocale === "zh" ? "en" : "zh"));
      },
    }),
    [locale],
  );

  return (
    <I18nContext.Provider value={contextValue}>{children}</I18nContext.Provider>
  );
}

// useI18n returns the page language state, using the deterministic English fallback outside the provider.
// useI18n 返回页面语言状态，并在 Provider 外使用确定性的英文回退。
export function useI18n(): I18nContextValue {
  return useContext(I18nContext);
}
