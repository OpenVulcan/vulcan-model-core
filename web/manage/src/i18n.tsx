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
  "capabilities.loadFailedDescription":
    "One or more provider catalogs failed validation. No assumed capability data is shown.",
  "capabilities.noModels": "No models configured",
  "capabilities.noModelsDescription":
    "Add and authorize a provider before inspecting model capabilities.",
  "capabilities.noServices": "No special services configured",
  "capabilities.noServicesDescription":
    "Configured providers do not currently expose a typed special-service contract.",
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
  "capabilities.contextWindow": "Total context (includes output)",
  "capabilities.maxInput": "Max input",
  "capabilities.maxOutput": "Max output",
  "capabilities.recommendedOutput": "Recommended output",
  "capabilities.rateLimits": "Rate limits",
  "capabilities.requests": "requests",
  "capabilities.seconds": "seconds",
  "capabilities.expired": "Expired",
  "capabilities.unknown": "Unknown",
  "capabilities.native": "Native",
  "capabilities.emulated": "Emulated",
  "capabilities.conditional": "Conditional",
  "capabilities.unsupported": "Unsupported",
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
  "capabilities.standardTools": "Standard tools",
  "capabilities.extraTools": "Model extra tools",
  "capabilities.dependencies": "Dependencies",
  "capabilities.requiresStreaming": "Requires streaming",
  "capabilities.requiresReasoning": "Requires reasoning",
  "capabilities.defaultDisabled": "Off by default",
  "capabilities.ready": "Ready",
  "capabilities.unconfigured": "Not configured",
  "capabilities.availableModes": "Available modes",
  "capabilities.web_search": "Web search",
  "capabilities.web_extractor": "Web extraction",
  "capabilities.image_understanding": "Image understanding",
  "capabilities.audio_understanding": "Audio understanding",
  "capabilities.video_understanding": "Video understanding",
  "capabilities.image_generation": "Image generation",
  "capabilities.video_generation": "Video generation",
  "capabilities.speech_generation": "Speech generation",
  "capabilities.speech_transcription": "Speech transcription",
  "capabilities.router_binding_missing": "Router binding is not configured",
  "capabilities.parent_target_unavailable": "Parent model target is currently unavailable",
  "capabilities.router_binding_disabled": "Router binding is disabled",
  "capabilities.router_binding_unavailable": "Router backend is unavailable",
  "capabilities.routerExtensions": "Router enhancements",
  "capabilities.routerBindings": "Router tool bindings",
  "capabilities.routerBindingsDescription":
    "Bind a standard tool to one exact service profile, or a Router enhancement to one exact model profile. Bindings are never selected implicitly across providers.",
  "capabilities.addRouterBinding": "Add binding",
  "capabilities.editRouterBinding": "Edit binding",
  "capabilities.noRouterBindings": "No Router tool or enhancement bindings are configured.",
  "capabilities.routerBindingsLoadFailed": "Unable to load Router tool bindings.",
  "capabilities.routerBindingInvalid": "Select a compatible backend and enter valid positive safety limits.",
  "capabilities.routerBindingSaveFailed": "Unable to save the Router tool binding.",
  "capabilities.routerBindingDeleteFailed": "Unable to delete the Router tool binding.",
  "capabilities.routerBindingProbeFailed": "Unable to test the Router tool binding.",
  "capabilities.testRouterBinding": "Test",
  "capabilities.testingRouterBinding": "Testing…",
  "capabilities.routerBindingDialogDescription":
    "Select one exact backend and bounded execution limits. Empty parent scopes apply this binding to every compatible model.",
  "capabilities.deleteRouterBindingTitle": "Delete Router tool binding?",
  "capabilities.deleteRouterBindingDescription":
    "Models using this binding will lose the corresponding router_tool mode until another ready binding applies.",
  "capabilities.standardTool": "Standard tool",
  "capabilities.routerCapability": "Router capability",
  "capabilities.backendService": "Backend service",
  "capabilities.selectBackendService": "Select a compatible backend",
  "capabilities.noCompatibleBackend": "No compatible service or model profile is configured.",
  "capabilities.priority": "Priority",
  "capabilities.timeoutMilliseconds": "Timeout (milliseconds)",
  "capabilities.maximumCalls": "Maximum calls",
  "capabilities.maximumResults": "Maximum results",
  "capabilities.maximumURLs": "Maximum URLs",
  "capabilities.maximumResultBytes": "Maximum result bytes",
  "capabilities.bindingEnabled": "Enable this binding",
  "capabilities.bindingScope": "Parent model scope",
  "capabilities.bindingScopeDescription": "Leave all fields empty to apply globally. Enter exact IDs separated by commas to restrict this binding.",
  "capabilities.allowedProviderInstances": "Provider instance IDs",
  "capabilities.allowedProviderModels": "Provider model IDs",
  "capabilities.allowedExecutionProfiles": "Execution profile IDs",
  "capabilities.commaSeparatedIDs": "id_a, id_b",
  "common.loading": "Loading…",
  "common.edit": "Edit",
  "common.delete": "Delete",
  "common.cancel": "Cancel",
  "common.save": "Save",
  "common.saving": "Saving…",
  "services.backendKind": "Backend kind",
  "services.invocationMode": "Invocation mode",
  "services.outputModes": "Output modes",
  "services.evidenceKinds": "Evidence kinds",
  "services.evidenceRequirements": "Evidence requirements",
  "services.noTypedContract":
    "This service profile has no typed capability contract.",
  "services.test": "Test",
  "services.testTitle": "Service test",
  "services.testDescription":
    "Choose a capability to test with the configured provider:",
  "services.closeTest": "Close test",
  "services.search": "Search",
  "services.extract": "Extract",
  "services.searchTest": "Test search",
  "services.searchTestTitle": "Search test",
  "services.searchTestDescription":
    "Enter a query to run a real search with this configured provider credential.",
  "services.searchQuery": "Search query",
  "services.searchQueryPlaceholder": "Enter text to search…",
  "services.searching": "Searching…",
  "services.searchFailed": "Search test failed.",
  "services.searchResults": "Search results",
  "services.searchAnswer": "Answer",
  "services.searchCitations": "Citations",
  "services.searchSources": "Consulted sources",
  "services.searchNoResults":
    "The provider returned no displayable search results.",
  "services.searchConsumesQuota":
    "This test sends the query to the provider and may consume search quota.",
  "services.extractTest": "Test extraction",
  "services.extractTestTitle": "Content extraction test",
  "services.extractTestDescription":
    "Enter one HTTPS URL per line to run a real Tavily Extract request with the configured credential.",
  "services.extractURLs": "HTTPS URLs",
  "services.extractURLsPlaceholder":
    "https://example.com/page\nhttps://example.com/another-page",
  "services.extractURLLimit": "Maximum URLs",
  "services.extractQuery": "Relevance query (optional)",
  "services.extractChunks": "Chunks per source",
  "services.extractDepth": "Extraction depth",
  "services.extractDepthBasic": "Basic",
  "services.extractDepthAdvanced": "Advanced",
  "services.extractFormat": "Content format",
  "services.extractFormatMarkdown": "Markdown",
  "services.extractFormatText": "Plain text",
  "services.extractTimeout": "Timeout seconds (optional)",
  "services.extractIncludeImages": "Include image URLs",
  "services.extractIncludeFavicon": "Include favicon",
  "services.extractConsumesQuota":
    "This test sends URLs to the provider and consumes Extract credits for successful URLs.",
  "services.extracting": "Extracting…",
  "services.extractFailed": "Content extraction test failed.",
  "services.extractResults": "Extraction results",
  "services.extractSucceeded": "succeeded",
  "services.extractFailedCount": "failed",
  "services.providerRequestID": "Provider request ID",
  "diagnostics.resourcesTitle": "Resource Diagnostics",
  "diagnostics.executionsTitle": "Execution Diagnostics",
  "diagnostics.accessTitle": "Access Diagnostics",
  "diagnostics.resourcesDescription":
    "Metadata-only Router resource lifecycle history. Content, object locations, source URLs, and owners are excluded.",
  "diagnostics.executionsDescription":
    "Public execution lifecycle history. Requests, provider task handles, and preparation handles are excluded.",
  "diagnostics.accessDescription":
    "Redacted route audit and aggregate traffic metrics. Tokens, bodies, prompts, and provider content are excluded.",
  "diagnostics.requests": "Requests",
  "diagnostics.failures": "Failures",
  "diagnostics.totalDuration": "Total duration",
  "diagnostics.unauthenticated": "Unauthenticated request",
  "diagnostics.outcome.authorized": "Authorized",
  "diagnostics.outcome.unauthenticated": "Unauthenticated",
  "diagnostics.outcome.forbidden": "Forbidden",
  "diagnostics.outcome.rate_limited": "Rate limited",
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
  "providers.noCredentialsForProvider":
    "No credentials have been added to this provider.",
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
  "credentials.description":
    "Select a supported native or custom provider category, then manage its credentials.",
  "credentials.noProviders": "No supported providers are available.",
  "credentials.configureCustomFirst":
    "Configure this custom provider's API endpoint in Provider Management before adding credentials.",
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
    "Alibaba Cloud Model Studio APIs and coding subscriptions across CN, Singapore, US, and Global sites.",
  "providers.alibaba.modelStudioCNDescription":
    "Model Studio APIs hosted at the CN site.",
  "providers.alibaba.modelStudioSingaporeDescription":
    "Model Studio APIs hosted in Singapore and visible from the domestic console site.",
  "providers.alibaba.modelStudioUSDescription":
    "Model Studio APIs hosted in the United States; model capabilities remain unpublished until independently verified.",
  "providers.alibaba.modelStudioWorkspaceSingaporeDescription":
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
  "providers.deepseek.description":
    "Official DeepSeek API with dual thinking modes and account balance queries.",
  "providers.deepseek.apiDescription":
    "Official DeepSeek API using OpenAI Chat Completions and provider-native balance queries.",
  "providers.handle": "Instance handle",
  "providers.name": "Name",
  "providers.credentialName": "Credential name",
  "providers.apiKey": "API key",
  "providers.newAPIKey": "New API key",
  "providers.newAPIKeyPlaceholder": "Enter the replacement API key",
  "providers.replaceCredentialHelp":
    "The saved credential remains active until the new API key is accepted and stored successfully.",
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
  "providers.refreshEntitlements": "Refresh access",
  "providers.refreshUsage": "Refresh usage",
  "providers.usageUnsupported": "Usage queries are not supported",
  "providers.catalogAudit": "Catalog audit",
  "providers.catalogAuditTitle": "Complete catalog audit",
  "providers.catalogAuditDescription":
    "Collected models and every explicit publication decision.",
  "providers.catalogAuditFilter":
    "Filter models, channels, operations, or reasons…",
  "providers.catalogAuditAll": "All decisions",
  "providers.catalogPolicySupported": "Supported",
  "providers.catalogPolicyUnsupported": "Unsupported",
  "providers.catalogPolicyPending": "Pending review",
  "providers.catalogPolicyReason.runtimeVerified": "Runtime verified",
  "providers.catalogPolicyReason.providerContractVerified":
    "Provider contract verified",
  "providers.catalogPolicyReason.providerInferenceDisabled":
    "Provider inference disabled",
  "providers.catalogPolicyReason.operationNotImplemented":
    "Operation not implemented",
  "providers.catalogPolicyReason.codingCapabilityInsufficient":
    "Coding capability insufficient",
  "providers.catalogPolicyReason.deprecatedOrSuperseded":
    "Deprecated or superseded",
  "providers.catalogPolicyReason.outOfScopeRealtime":
    "Realtime operation is out of scope",
  "providers.catalogPolicyReason.outOfScopeProduct": "Product is out of scope",
  "providers.catalogPolicyReason.missingProtocolEvidence":
    "Missing protocol evidence",
  "providers.catalogPolicyReason.missingParameterMapping":
    "Missing parameter mapping",
  "providers.catalogPolicyReason.missingExecutionFixture":
    "Missing execution fixture",
  "providers.catalogPolicyReason.newCatalogEntry": "New catalog entry",
  "providers.catalogEvidenceRevision": "Evidence revision",
  "providers.catalogUnclassified": "No classified operation",
  "providers.catalogLegacyPublication": "Published by execution profiles",
  "providers.refreshCatalogAudit": "Refresh audit",
  "providers.catalogAuditFailed": "Unable to load the complete catalog audit.",
  "providers.catalogProduct": "Product",
  "providers.catalogRegions": "Regions",
  "providers.catalogChannels": "Channels",
  "providers.catalogCapabilities": "Channels and capabilities",
  "providers.catalogCapabilityRevision": "Capability revision",
  "providers.catalogCapabilityDetails": "Complete capability evidence",
  "providers.catalogRevision": "Source revision",
  "providers.catalogStale": "Stale",
  "providers.catalogDecisions": "Publication decisions",
  "providers.catalogPolicyMissing": "Missing explicit policy",
  "providers.catalogAuditCount": "Visible models",
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
    "The provider returned catalog data that could not be read.",
  "providers.models": "Models",
  "providers.getSupportedModels": "View models",
  "providers.modelCatalogTitle": "Supported models",
  "providers.modelCatalogDescription":
    "Models available to the selected provider account.",
  "providers.noSupportedModels":
    "No supported model data is available. Refresh account data and try again.",
  "providers.modelEnabled": "Enabled",
  "providers.modelDisabled": "Disabled",
  "providers.modelAuthorized": "Authorized",
  "providers.modelUnauthorized": "Not authorized",
  "providers.modelAuthorizationUnknown": "Authorization unknown",
  "providers.operatorDeclared": "Operator declared",
  "providers.providerDetected": "Provider detected",
  "providers.routingStrategy": "Account scheduling",
  "providers.routingStrategyHelp":
    "Override the global account routing strategy for this provider.",
  "providers.routingInherit": "Use global default",
  "providers.routingUpdateFailed":
    "Unable to update provider account scheduling.",
  "providers.priority": "Priority",
  "providers.editPriority": "Edit priority",
  "providers.priorityEditDescription":
    "Set a non-negative account preference. Lower values are selected first.",
  "providers.priorityInvalid": "Enter a non-negative whole number.",
  "providers.priorityUpdateFailed": "Unable to update credential priority.",
  "providers.updatingPriority": "Updating priority…",
  "providers.updatePriority": "Update priority",
  "providers.plans": "Plans",
  "providers.membershipPlan": "Membership plan",
  "providers.billingUsage": "Pay as you go",
  "providers.billingSubscription": "Plan",
  "providers.selectMembershipPlan": "Select a membership plan",
  "providers.membershipPlanHelp":
    "Choose the plan attached to this API key. The selection is saved only after onboarding succeeds.",
  "providers.allowances": "Allowances and credits",
  "providers.usage": "Usage",
  "providers.balance": "Balance",
  "providers.noUsage": "No usage data",
  "providers.sharedUsage": "Shared",
  "providers.resources": "Resources",
  "providers.resourceList": "Resource list",
  "providers.resourceListDescription":
    "Resources available to the selected credential.",
  "providers.noResources": "No resources are available for this credential.",
  "providers.resourceLoadFailed": "Unable to load the provider resource list.",
  "providers.loadingResourceFiles": "Loading file resources…",
  "providers.noFileResources": "No file resources are available.",
  "providers.voiceResources": "Voice resources",
  "providers.fileResources": "File resources",
  "providers.fileName": "File name",
  "providers.resourcePurpose": "Purpose",
  "providers.resourceSize": "Size",
  "providers.resourceCreatedAt": "Created",
  "providers.voices": "Voices",
  "providers.voiceAccount": "Account",
  "providers.voiceIdentifier": "Voice ID",
  "providers.remaining": "Remaining",
  "providers.remainingRatio": "Remaining ratio",
  "providers.used": "Used",
  "providers.limit": "Limit",
  "providers.window": "Window",
  "providers.resetAt": "Resets at",
  "providers.unknownAmount": "Amount unavailable",
  "providers.unlimited": "Unlimited",
  "providers.notInPlan": "Not in plan",
  "providers.resetsIn": "Reset",
  "providers.period": "Period",
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
  "providers.allowanceMetrics.tavilyKeyTotal": "API key total credits",
  "providers.allowanceMetrics.tavilyAccountPlan": "Account plan credits",
  "providers.allowanceMetrics.tavilyAccountPaygo":
    "Account pay-as-you-go credits",
  "providers.allowanceMetrics.tavilyKeySearch": "API key search usage",
  "providers.allowanceMetrics.tavilyKeyExtract": "API key extract usage",
  "providers.allowanceMetrics.tavilyAccountSearch": "Account search usage",
  "providers.allowanceMetrics.tavilyAccountExtract": "Account extract usage",
  "providers.allowanceMetrics.deepseekTotal": "Available balance",
  "providers.allowanceMetrics.deepseekGranted": "Granted balance",
  "providers.allowanceMetrics.deepseekToppedUp": "Topped-up balance",
  "providers.allowanceMetrics.tavilyPlan": "Plan",
  "providers.allowanceMetrics.tavilyPaygo": "Pay-as-you-go",
  "providers.allowanceMetrics.fiveHour": "5-hour usage window",
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
  "providers.allowanceMetrics.minimaxGeneral": "General",
  "providers.allowanceMetrics.minimaxVideo": "Video",
  "providers.allowanceMetrics.minimaxCurrent": "Left",
  "providers.allowanceMetrics.minimaxWeekly": "Wk left",
  "sidebar.dashboard": "Dashboard",
  "sidebar.lifecycle": "Lifecycle",
  "sidebar.analytics": "Analytics",
  "sidebar.projects": "Projects",
  "sidebar.team": "Team",
  "sidebar.documents": "Providers",
  "sidebar.providerManagement": "Provider Management",
  "sidebar.credentialManagement": "Credential Management",
  "credentials.title": "Credential Management",
  "credentials.all": "All",
  "providerConfig.title": "Provider Management",
  "providerConfig.description":
    "Manage provider definitions, endpoints, model catalogs, and capabilities independently from account credentials.",
  "providerConfig.addProvider": "Add provider",
  "providerConfig.addDescription":
    "Configure the protocol, provider identity, and API endpoint. You can optionally add the first API key now and then discover models directly.",
  "providerConfig.nativeProviders": "Native providers",
  "providerConfig.configuredProviders": "Configured providers",
  "providerConfig.customProviders": "Custom providers",
  "providerConfig.provider": "Provider",
  "providerConfig.details": "Description and interfaces",
  "providerConfig.actions": "Actions",
  "providerConfig.kind": "Type",
  "providerConfig.kindSystem": "System",
  "providerConfig.kindCustom": "Custom",
  "providerConfig.resourceCounts": "Resources",
  "providerConfig.status": "Status",
  "providerConfig.modelCount": "Models",
  "providerConfig.credentialCount": "Credentials",
  "providerConfig.interfaceUnavailable": "Interface information unavailable",
  "providerConfig.add": "Add",
  "providerConfig.newCredential": "New credential",
  "providerConfig.configure": "Configure",
  "providerConfig.unconfigured": "Unconfigured",
  "providerConfig.deleteProvider": "Delete provider",
  "providerConfig.deleteFailed": "Unable to delete the custom provider.",
  "providerConfig.deleteWithCredentialsTitle":
    "Delete this provider and all credentials?",
  "providerConfig.deleteWithCredentialsDescription":
    "This custom provider still owns credentials. Continuing permanently deletes every credential, endpoint, model configuration, and provider definition owned by it.",
  "providerConfig.deleteProviderAndCredentials":
    "Delete provider and credentials",
  "providerConfig.interface": "Provider interface",
  "providerConfig.addSystemProvider": "Add provider credential",
  "providerConfig.addSystemDescription":
    "Select the exact provider interface, then add a credential through its native authorization workflow.",
  "providerConfig.credentialTarget": "Target provider configuration",
  "providerConfig.credentialTargetHelp":
    "The new credential is added to this existing provider configuration; no provider is cloned.",
  "providerConfig.firstCredentialCreatesConfiguration":
    "This interface has not been configured yet. Its first successful authorization creates the provider configuration and first credential together.",
  "providerConfig.configurationDescription":
    "Review endpoints and models, then open the relevant provider configuration tool.",
  "providerConfig.loading": "Loading provider inventory…",
  "providerConfig.empty": "No custom provider has been defined yet.",
  "providerConfig.loadFailed": "Unable to load provider inventory.",
  "providerConfig.createFailed": "Unable to create provider configuration.",
  "providerConfig.catalogUnavailable":
    "The model catalog for this provider could not be loaded.",
  "providerConfig.definition": "Provider definition",
  "providerConfig.selectDefinition":
    "Select a native provider or custom integration",
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
  "providerConfig.protocolRequired":
    "Select an executable custom-provider protocol.",
  "providerConfig.baseURL": "API endpoint URL",
  "providerConfig.apiKey": "API key",
  "providerConfig.apiKeyPlaceholder": "Enter an API key",
  "providerConfig.apiKeyHelp":
    "Optional. When provided, the key is stored as this provider's first protected credential and automatically selected for model discovery.",
  "providerConfig.region": "Region",
  "providerConfig.upstreamModelID": "Upstream model ID",
  "providerConfig.upstreamModelIDPlaceholder": "deepseek-chat",
  "providerConfig.modelDisplayName": "Model display name",
  "providerConfig.modelDisplayNamePlaceholder": "DeepSeek Chat",
  "providerConfig.optional": "optional",
  "providerConfig.contextWindow": "Total context (includes output)",
  "providerConfig.maxOutputTokens": "Maximum output tokens",
  "providerConfig.toolCalling": "Tool calling",
  "providerConfig.reasoning": "Reasoning",
  "providerConfig.reasoningRules": "Reasoning parameter rules",
  "providerConfig.reasoningRulesJSON": "Reasoning rule JSON",
  "providerConfig.reasoningRulesHelp":
    "Map each caller-visible effort or summary value to exact upstream set/delete mutations. If the caller omits a value, the upstream default remains unchanged.",
  "providerConfig.additionalParameters": "Additional parameters",
  "providerConfig.additionalParametersDescription":
    "Configure provider-wide non-core request parameters inherited by every model.",
  "providerConfig.additionalParametersHelp":
    "Provider rules are applied first: default fills missing values, override replaces values, and filter removes fields. A model normally needs no additional configuration; its optional model-level rules run afterward and can replace provider defaults. Protocol-owned model, messages/input, tools, stream, instructions, and authentication paths are rejected.",
  "providerConfig.additionalParametersExample":
    'Example:\n{\n  "default": [{ "path": "temperature", "value": 0.7 }],\n  "override": [{ "path": "provider_options.route", "value": "fast" }],\n  "filter": ["unsupported_parameter"]\n}',
  "providerConfig.additionalParametersJSON": "Additional parameter JSON",
  "providerConfig.additionalParametersInvalid":
    "Additional parameter rules are invalid.",
  "providerConfig.additionalParametersSaveFailed":
    "Unable to save provider additional parameters.",
  "providerConfig.saveAdditionalParameters": "Save additional parameters",
  "providerConfig.modelAdditionalParameters":
    "Model additional parameter overrides",
  "providerConfig.modelAdditionalParametersHelp":
    "Leave this empty object for normal models. Configure only model-specific exceptions; these rules run after provider-wide rules and therefore take precedence.",
  "providerConfig.advancedRequestParameters": "Advanced request parameters",
  "providerConfig.projectionJSON": "Request projection JSON",
  "providerConfig.projectionRulesHelp":
    "Each effort or summary value must contain at least one set/delete mutation. If the caller omits effort, no effort rule is applied and the upstream default remains. additional.default writes only missing values, override replaces values, and filter removes values last. Additional parameters remain available when reasoning is unsupported. Protocol-owned model, messages/input, tools, stream, instructions, and authentication paths are rejected. Saving performs the same authoritative validation on the server.",
  "providerConfig.projectionExample":
    'DeepSeek effort rules example:\n"effort": [\n  { "value": "none", "set": [{ "path": "thinking.type", "value": "disabled" }], "delete": ["reasoning_effort"] },\n  { "value": "high", "set": [{ "path": "thinking.type", "value": "enabled" }, { "path": "reasoning_effort", "value": "high" }] }\n]',
  "providerConfig.validateProjection": "Validate rules",
  "providerConfig.projectionValid": "Rules are valid",
  "providerConfig.projectionInvalid": "Request projection rules are invalid.",
  "providerConfig.projectionEffortRequired":
    "Supported reasoning requires at least one effort rule.",
  "providerConfig.projectionReasoningUnsupported":
    "A model without reasoning support cannot define effort or summary rules; additional parameters remain available.",
  "providerConfig.unknown": "Unknown",
  "providerConfig.native": "Native",
  "providerConfig.unsupported": "Unsupported",
  "providerConfig.editModels": "Edit models",
  "providerConfig.editModelsDescription":
    "Add, update, or remove models and declare only capability limits you have verified.",
  "providerConfig.addModel": "Add model",
  "providerConfig.removeModel": "Remove model",
  "providerConfig.saveModels": "Save models",
  "providerConfig.modelSaveFailed": "Unable to save the custom model catalog.",
  "providerConfig.editSettings": "Edit provider settings",
  "providerConfig.editSettingsDescription":
    "Change the local display name, stable handle, and custom provider API base URL. Protocol, models, and credentials remain unchanged.",
  "providerConfig.editBaseURLHelp":
    "The complete upstream API base URL, including a required version path such as /v1 when the provider expects it.",
  "providerConfig.endpointRequired":
    "This provider does not have an editable API endpoint.",
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
  "sidebar.accessDiagnostics": "Access Diagnostics",
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
  "capabilities.loadFailedDescription":
    "一个或多个供应商目录校验失败，页面不会显示推测的能力数据。",
  "capabilities.noModels": "尚未配置模型",
  "capabilities.noModelsDescription": "请先新增并授权供应商，再检查模型能力。",
  "capabilities.noServices": "尚未配置特殊服务",
  "capabilities.noServicesDescription":
    "当前已配置供应商没有提供类型化特殊服务合同。",
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
  "capabilities.contextWindow": "总上下文（含输出）",
  "capabilities.maxInput": "最大输入",
  "capabilities.maxOutput": "最大输出",
  "capabilities.recommendedOutput": "推荐输出",
  "capabilities.rateLimits": "速率限制",
  "capabilities.requests": "次请求",
  "capabilities.seconds": "秒",
  "capabilities.expired": "已过期",
  "capabilities.unknown": "未知",
  "capabilities.native": "原生支持",
  "capabilities.emulated": "模拟支持",
  "capabilities.conditional": "条件支持",
  "capabilities.unsupported": "不支持",
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
  "capabilities.standardTools": "标准工具",
  "capabilities.extraTools": "模型额外工具",
  "capabilities.dependencies": "依赖",
  "capabilities.requiresStreaming": "要求流式输出",
  "capabilities.requiresReasoning": "要求开启推理",
  "capabilities.defaultDisabled": "默认关闭",
  "capabilities.ready": "就绪",
  "capabilities.unconfigured": "未配置",
  "capabilities.availableModes": "可用方式",
  "capabilities.web_search": "联网搜索",
  "capabilities.web_extractor": "网页抓取",
  "capabilities.image_understanding": "图片理解",
  "capabilities.audio_understanding": "音频理解",
  "capabilities.video_understanding": "视频理解",
  "capabilities.image_generation": "图片生成",
  "capabilities.video_generation": "视频生成",
  "capabilities.speech_generation": "语音生成",
  "capabilities.speech_transcription": "语音转写",
  "capabilities.router_binding_missing": "尚未配置 Router 绑定",
  "capabilities.parent_target_unavailable": "父模型目标当前不可用",
  "capabilities.router_binding_disabled": "Router 绑定已停用",
  "capabilities.router_binding_unavailable": "Router 后端当前不可用",
  "capabilities.routerExtensions": "Router 增强能力",
  "capabilities.routerBindings": "Router 工具绑定",
  "capabilities.routerBindingsDescription":
    "将标准工具绑定到一个精确服务规格，或将 Router 增强能力绑定到一个精确模型规格。绑定绝不会在供应商之间隐式切换。",
  "capabilities.addRouterBinding": "新增绑定",
  "capabilities.editRouterBinding": "编辑绑定",
  "capabilities.noRouterBindings": "尚未配置 Router 工具或增强能力绑定。",
  "capabilities.routerBindingsLoadFailed": "无法加载 Router 工具绑定。",
  "capabilities.routerBindingInvalid": "请选择兼容后端并填写有效的正数安全限制。",
  "capabilities.routerBindingSaveFailed": "无法保存 Router 工具绑定。",
  "capabilities.routerBindingDeleteFailed": "无法删除 Router 工具绑定。",
  "capabilities.routerBindingProbeFailed": "无法测试 Router 工具绑定。",
  "capabilities.testRouterBinding": "测试",
  "capabilities.testingRouterBinding": "测试中…",
  "capabilities.routerBindingDialogDescription":
    "请选择一个精确后端和有界执行限制。父级范围为空时，该绑定适用于全部兼容模型。",
  "capabilities.deleteRouterBindingTitle": "删除 Router 工具绑定？",
  "capabilities.deleteRouterBindingDescription":
    "使用此绑定的模型将失去对应 router_tool 方式，直到存在另一个适用且就绪的绑定。",
  "capabilities.standardTool": "标准工具",
  "capabilities.routerCapability": "Router 能力",
  "capabilities.backendService": "后端服务",
  "capabilities.selectBackendService": "选择兼容后端",
  "capabilities.noCompatibleBackend": "尚未配置兼容的服务或模型规格。",
  "capabilities.priority": "优先级",
  "capabilities.timeoutMilliseconds": "超时（毫秒）",
  "capabilities.maximumCalls": "最大调用次数",
  "capabilities.maximumResults": "最大结果数",
  "capabilities.maximumURLs": "最大 URL 数",
  "capabilities.maximumResultBytes": "最大结果字节数",
  "capabilities.bindingEnabled": "启用此绑定",
  "capabilities.bindingScope": "父模型作用域",
  "capabilities.bindingScopeDescription": "全部留空表示全局适用；如需限制，请填写以逗号分隔的精确 ID。",
  "capabilities.allowedProviderInstances": "供应商实例 ID",
  "capabilities.allowedProviderModels": "供应商模型 ID",
  "capabilities.allowedExecutionProfiles": "执行规格 ID",
  "capabilities.commaSeparatedIDs": "id_a, id_b",
  "common.loading": "加载中…",
  "common.edit": "编辑",
  "common.delete": "删除",
  "common.cancel": "取消",
  "common.save": "保存",
  "common.saving": "保存中…",
  "services.backendKind": "后端类型",
  "services.invocationMode": "调用模式",
  "services.outputModes": "输出模式",
  "services.evidenceKinds": "证据类型",
  "services.evidenceRequirements": "证据要求",
  "services.noTypedContract": "该服务配置没有类型化能力合同。",
  "services.test": "测试",
  "services.testTitle": "能力测试",
  "services.testDescription": "选择要使用当前供应商测试的能力：",
  "services.closeTest": "关闭测试",
  "services.search": "搜索",
  "services.extract": "提取",
  "services.searchTest": "测试搜索",
  "services.searchTestTitle": "搜索测试",
  "services.searchTestDescription":
    "输入查询文本，使用该供应商已经配置的凭据执行一次真实搜索。",
  "services.searchQuery": "搜索文本",
  "services.searchQueryPlaceholder": "输入需要搜索的文本…",
  "services.searching": "正在搜索…",
  "services.searchFailed": "搜索测试失败。",
  "services.searchResults": "搜索结果",
  "services.searchAnswer": "搜索回答",
  "services.searchCitations": "引用",
  "services.searchSources": "已查询来源",
  "services.searchNoResults": "供应商没有返回可展示的搜索结果。",
  "services.searchConsumesQuota":
    "该测试会把查询发送给供应商，并可能消耗搜索额度。",
  "services.extractTest": "测试提取",
  "services.extractTestTitle": "内容提取测试",
  "services.extractTestDescription":
    "每行输入一个 HTTPS URL，使用已配置凭据执行一次真实 Tavily Extract 请求。",
  "services.extractURLs": "HTTPS URL",
  "services.extractURLsPlaceholder":
    "https://example.com/page\nhttps://example.com/another-page",
  "services.extractURLLimit": "最大 URL 数",
  "services.extractQuery": "相关性查询（可选）",
  "services.extractChunks": "每个来源片段数",
  "services.extractDepth": "提取深度",
  "services.extractDepthBasic": "基础",
  "services.extractDepthAdvanced": "高级",
  "services.extractFormat": "内容格式",
  "services.extractFormatMarkdown": "Markdown",
  "services.extractFormatText": "纯文本",
  "services.extractTimeout": "超时秒数（可选）",
  "services.extractIncludeImages": "包含图片 URL",
  "services.extractIncludeFavicon": "包含站点图标",
  "services.extractConsumesQuota":
    "该测试会把 URL 发送给供应商，并按成功提取的 URL 消耗 Extract Credit。",
  "services.extracting": "正在提取…",
  "services.extractFailed": "内容提取测试失败。",
  "services.extractResults": "提取结果",
  "services.extractSucceeded": "成功",
  "services.extractFailedCount": "失败",
  "services.providerRequestID": "供应商请求 ID",
  "diagnostics.resourcesTitle": "资源诊断",
  "diagnostics.executionsTitle": "执行诊断",
  "diagnostics.accessTitle": "访问诊断",
  "diagnostics.resourcesDescription":
    "仅显示 Router 资源生命周期元数据，不包含内容、对象位置、来源 URL 与所有者。",
  "diagnostics.executionsDescription":
    "显示公开执行生命周期，不包含请求、供应商任务句柄与准备句柄。",
  "diagnostics.accessDescription":
    "显示脱敏路由审计与聚合流量指标，不包含令牌、请求正文、提示词或供应商内容。",
  "diagnostics.requests": "请求数",
  "diagnostics.failures": "失败数",
  "diagnostics.totalDuration": "总耗时",
  "diagnostics.unauthenticated": "未认证请求",
  "diagnostics.outcome.authorized": "已授权",
  "diagnostics.outcome.unauthenticated": "未认证",
  "diagnostics.outcome.forbidden": "无权限",
  "diagnostics.outcome.rate_limited": "已限流",
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
  "credentials.description":
    "选择受支持的原生或自定义供应商大类，然后管理其凭据。",
  "credentials.noProviders": "暂无可用的受支持供应商。",
  "credentials.configureCustomFirst":
    "请先在供应商管理中配置此自定义供应商的 API 接口，再添加凭据。",
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
    "Alibaba Cloud Model Studio 在 CN、新加坡、美国与 Global 站点提供的 API 与编程订阅服务。",
  "providers.alibaba.modelStudioCNDescription":
    "托管于 CN 站点的 Model Studio API。",
  "providers.alibaba.modelStudioSingaporeDescription":
    "托管于新加坡、并可从国内控制台查看的 Model Studio API。",
  "providers.alibaba.modelStudioUSDescription":
    "托管于美国区域的 Model Studio API；模型能力在独立验证前不会发布。",
  "providers.alibaba.modelStudioWorkspaceSingaporeDescription":
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
  "providers.deepseek.description":
    "支持双重思考模式与账号余额查询的 DeepSeek 官方 API。",
  "providers.deepseek.apiDescription":
    "使用 OpenAI Chat Completions 协议并支持原生余额查询的 DeepSeek 官方 API。",
  "providers.handle": "实例标识",
  "providers.name": "名称",
  "providers.credentialName": "凭据名称",
  "providers.apiKey": "API 密钥",
  "providers.newAPIKey": "新 API 密钥",
  "providers.newAPIKeyPlaceholder": "输入用于替换的新 API 密钥",
  "providers.replaceCredentialHelp":
    "只有新 API 密钥成功保存后才会替换现有凭据；提交失败不会改动已保存凭据。",
  "providers.workspaceID": "Workspace ID",
  "providers.workspaceIDHelp": "请输入小写 Workspace 主机标签，不要包含域名。",
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
  "providers.refreshEntitlements": "刷新权益",
  "providers.refreshUsage": "刷新用量",
  "providers.usageUnsupported": "不支持查询用量",
  "providers.catalogAudit": "目录审核",
  "providers.catalogAuditTitle": "完整目录审核",
  "providers.catalogAuditDescription": "已采集模型及全部显式发布决策。",
  "providers.catalogAuditFilter": "过滤模型、通道、操作或原因…",
  "providers.catalogAuditAll": "全部决策",
  "providers.catalogPolicySupported": "支持",
  "providers.catalogPolicyUnsupported": "不支持",
  "providers.catalogPolicyPending": "待审核",
  "providers.catalogPolicyReason.runtimeVerified": "运行时验证通过",
  "providers.catalogPolicyReason.providerContractVerified": "供应商合同已验证",
  "providers.catalogPolicyReason.providerInferenceDisabled": "供应商未启用推理",
  "providers.catalogPolicyReason.operationNotImplemented": "操作尚未实现",
  "providers.catalogPolicyReason.codingCapabilityInsufficient": "编码能力不足",
  "providers.catalogPolicyReason.deprecatedOrSuperseded": "已弃用或已被替代",
  "providers.catalogPolicyReason.outOfScopeRealtime": "实时操作不在当前范围",
  "providers.catalogPolicyReason.outOfScopeProduct": "产品不在当前范围",
  "providers.catalogPolicyReason.missingProtocolEvidence": "缺少协议证据",
  "providers.catalogPolicyReason.missingParameterMapping": "缺少参数映射",
  "providers.catalogPolicyReason.missingExecutionFixture": "缺少执行夹具",
  "providers.catalogPolicyReason.newCatalogEntry": "新目录条目",
  "providers.catalogEvidenceRevision": "证据修订",
  "providers.catalogUnclassified": "暂无已分类操作",
  "providers.catalogLegacyPublication": "由执行规格发布",
  "providers.refreshCatalogAudit": "刷新审核数据",
  "providers.catalogAuditFailed": "无法加载完整目录审核数据。",
  "providers.catalogProduct": "产品",
  "providers.catalogRegions": "区域",
  "providers.catalogChannels": "通道",
  "providers.catalogCapabilities": "通道与能力",
  "providers.catalogCapabilityRevision": "能力修订",
  "providers.catalogCapabilityDetails": "完整能力证据",
  "providers.catalogRevision": "来源修订",
  "providers.catalogStale": "已过期",
  "providers.catalogDecisions": "发布决策",
  "providers.catalogPolicyMissing": "缺少显式策略",
  "providers.catalogAuditCount": "当前显示模型",
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
  "providers.metadataInvalidResponse": "供应商返回的目录数据无法解析。",
  "providers.models": "模型",
  "providers.getSupportedModels": "查看模型",
  "providers.modelCatalogTitle": "支持的模型",
  "providers.modelCatalogDescription": "当前供应商账号可用的模型。",
  "providers.noSupportedModels": "暂无可用模型数据，请刷新账号数据后重试。",
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
  "providers.editPriority": "编辑优先级",
  "providers.priorityEditDescription": "设置非负账号优先级，数值越小越优先。",
  "providers.priorityInvalid": "请输入非负整数。",
  "providers.priorityUpdateFailed": "无法更新凭据优先级。",
  "providers.updatingPriority": "正在更新优先级…",
  "providers.updatePriority": "确认更新",
  "providers.plans": "套餐",
  "providers.membershipPlan": "会员套餐",
  "providers.billingUsage": "按量",
  "providers.billingSubscription": "套餐",
  "providers.selectMembershipPlan": "请选择会员套餐",
  "providers.membershipPlanHelp":
    "请选择该 API 密钥所属套餐；仅在录入成功后保存此选择。",
  "providers.allowances": "额度与积分",
  "providers.usage": "用量",
  "providers.balance": "余额",
  "providers.noUsage": "暂无用量数据",
  "providers.sharedUsage": "共享",
  "providers.resources": "资源",
  "providers.resourceList": "资源列表",
  "providers.resourceListDescription": "当前凭据可用的资源。",
  "providers.noResources": "当前凭据暂无可用资源。",
  "providers.resourceLoadFailed": "无法加载供应商资源列表。",
  "providers.loadingResourceFiles": "正在加载文件资源…",
  "providers.noFileResources": "暂无文件资源。",
  "providers.voiceResources": "声音资源",
  "providers.fileResources": "文件资源",
  "providers.fileName": "文件名",
  "providers.resourcePurpose": "用途",
  "providers.resourceSize": "大小",
  "providers.resourceCreatedAt": "创建时间",
  "providers.voices": "声音目录",
  "providers.voiceAccount": "账号",
  "providers.voiceIdentifier": "声音 ID",
  "providers.remaining": "剩余",
  "providers.remainingRatio": "剩余比例",
  "providers.used": "已用",
  "providers.limit": "总额",
  "providers.window": "额度周期",
  "providers.resetAt": "重置时间",
  "providers.unknownAmount": "金额未知",
  "providers.unlimited": "无限",
  "providers.notInPlan": "不在当前套餐中",
  "providers.resetsIn": "重置",
  "providers.period": "周期",
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
  "providers.allowanceMetrics.tavilyKeyTotal": "API 密钥总积分",
  "providers.allowanceMetrics.tavilyAccountPlan": "账号套餐积分",
  "providers.allowanceMetrics.tavilyAccountPaygo": "账号按量付费积分",
  "providers.allowanceMetrics.tavilyKeySearch": "API 密钥搜索用量",
  "providers.allowanceMetrics.tavilyKeyExtract": "API 密钥提取用量",
  "providers.allowanceMetrics.tavilyAccountSearch": "账号搜索用量",
  "providers.allowanceMetrics.tavilyAccountExtract": "账号提取用量",
  "providers.allowanceMetrics.deepseekTotal": "可用余额",
  "providers.allowanceMetrics.deepseekGranted": "赠送余额",
  "providers.allowanceMetrics.deepseekToppedUp": "充值余额",
  "providers.allowanceMetrics.tavilyPlan": "套餐",
  "providers.allowanceMetrics.tavilyPaygo": "按量付费",
  "providers.allowanceMetrics.fiveHour": "5 小时用量窗口",
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
  "providers.allowanceMetrics.minimaxGeneral": "通用",
  "providers.allowanceMetrics.minimaxVideo": "视频",
  "providers.allowanceMetrics.minimaxCurrent": "剩余",
  "providers.allowanceMetrics.minimaxWeekly": "周剩余",
  "sidebar.dashboard": "仪表盘",
  "sidebar.lifecycle": "生命周期",
  "sidebar.analytics": "分析",
  "sidebar.projects": "项目",
  "sidebar.team": "团队",
  "sidebar.documents": "供应商",
  "sidebar.providerManagement": "供应商管理",
  "sidebar.credentialManagement": "凭据管理",
  "credentials.title": "凭据管理",
  "credentials.all": "全部",
  "providerConfig.title": "供应商管理",
  "providerConfig.description":
    "独立管理供应商定义、入口、模型目录与能力，不在此处管理账号凭据。",
  "providerConfig.addProvider": "新增供应商",
  "providerConfig.addDescription":
    "配置协议、供应商身份与接口地址；可以同时填写首个 API 密钥，创建后直接拉取模型。",
  "providerConfig.nativeProviders": "原生供应商",
  "providerConfig.configuredProviders": "已配置供应商",
  "providerConfig.customProviders": "自定义供应商",
  "providerConfig.provider": "供应商",
  "providerConfig.details": "说明与接口",
  "providerConfig.actions": "操作",
  "providerConfig.kind": "类型",
  "providerConfig.kindSystem": "系统",
  "providerConfig.kindCustom": "自定义",
  "providerConfig.resourceCounts": "资源数量",
  "providerConfig.status": "状态",
  "providerConfig.modelCount": "模型数",
  "providerConfig.credentialCount": "凭据数",
  "providerConfig.interfaceUnavailable": "接口信息不可用",
  "providerConfig.add": "新增",
  "providerConfig.newCredential": "新建凭据",
  "providerConfig.configure": "配置",
  "providerConfig.unconfigured": "未配置",
  "providerConfig.deleteProvider": "删除供应商",
  "providerConfig.deleteFailed": "无法删除自定义供应商。",
  "providerConfig.deleteWithCredentialsTitle": "删除该供应商及其全部凭据？",
  "providerConfig.deleteWithCredentialsDescription":
    "该自定义供应商仍然拥有凭据。继续操作将永久删除其全部凭据、接口、模型配置与供应商定义。",
  "providerConfig.deleteProviderAndCredentials": "删除供应商及凭据",
  "providerConfig.interface": "供应商接口",
  "providerConfig.addSystemProvider": "新增供应商凭据",
  "providerConfig.addSystemDescription":
    "选择精确的供应商接口，然后通过其原生授权流程新增凭据。",
  "providerConfig.credentialTarget": "目标供应商配置",
  "providerConfig.credentialTargetHelp":
    "新凭据会加入该既有供应商配置，不会克隆供应商。",
  "providerConfig.firstCredentialCreatesConfiguration":
    "该接口尚未配置；首次授权成功时会同时创建供应商配置与首个凭据。",
  "providerConfig.configurationDescription":
    "查看入口与模型，并进入对应的供应商配置功能。",
  "providerConfig.loading": "正在加载供应商清单…",
  "providerConfig.empty": "尚未定义自定义供应商。",
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
  "providerConfig.baseURL": "接口地址",
  "providerConfig.apiKey": "API 密钥",
  "providerConfig.apiKeyPlaceholder": "输入 API 密钥",
  "providerConfig.apiKeyHelp":
    "可选。填写后会作为该供应商的首个受保护凭据保存，并自动选中用于拉取模型。",
  "providerConfig.region": "区域",
  "providerConfig.upstreamModelID": "上游模型 ID",
  "providerConfig.upstreamModelIDPlaceholder": "deepseek-chat",
  "providerConfig.modelDisplayName": "模型显示名称",
  "providerConfig.modelDisplayNamePlaceholder": "DeepSeek Chat",
  "providerConfig.optional": "可选",
  "providerConfig.contextWindow": "总上下文（含输出）",
  "providerConfig.maxOutputTokens": "最大输出 Token",
  "providerConfig.toolCalling": "工具调用",
  "providerConfig.reasoning": "推理",
  "providerConfig.reasoningRules": "推理参数规则",
  "providerConfig.reasoningRulesJSON": "推理规则 JSON",
  "providerConfig.reasoningRulesHelp":
    "将调用方可见的每个推理强度或摘要值映射为精确的上游 set/delete 变更。调用方未指定值时保持上游默认行为。",
  "providerConfig.additionalParameters": "附加参数",
  "providerConfig.additionalParametersDescription":
    "配置由所有模型继承的供应商级非核心请求参数。",
  "providerConfig.additionalParametersHelp":
    "先执行供应商规则：default 补充缺失值，override 覆盖已有值，filter 删除字段。一般模型无需额外配置；个别模型可在模型层声明例外，模型规则后执行并拥有更高优先级。模型、messages/input、工具、流式、指令及认证等协议拥有路径会被拒绝。",
  "providerConfig.additionalParametersExample":
    '示例：\n{\n  "default": [{ "path": "temperature", "value": 0.7 }],\n  "override": [{ "path": "provider_options.route", "value": "fast" }],\n  "filter": ["unsupported_parameter"]\n}',
  "providerConfig.additionalParametersJSON": "附加参数 JSON",
  "providerConfig.additionalParametersInvalid": "附加参数规则无效。",
  "providerConfig.additionalParametersSaveFailed": "无法保存供应商附加参数。",
  "providerConfig.saveAdditionalParameters": "保存附加参数",
  "providerConfig.modelAdditionalParameters": "模型附加参数覆盖",
  "providerConfig.modelAdditionalParametersHelp":
    "普通模型保持空对象即可。仅为个别模型配置例外；模型规则在供应商规则之后执行，因此拥有更高优先级。",
  "providerConfig.advancedRequestParameters": "高级请求参数",
  "providerConfig.projectionJSON": "请求投影 JSON",
  "providerConfig.projectionRulesHelp":
    "每个推理强度或摘要值必须至少包含一项 set/delete 变更。调用方未指定强度时不会应用强度规则，保持上游默认行为。additional.default 只补充缺失值，override 覆盖已有值，filter 最后删除字段；模型不支持推理时仍可使用额外参数。模型、messages/input、工具、流式、指令及认证等协议拥有路径会被拒绝；保存时服务端还会执行同一套权威校验。",
  "providerConfig.projectionExample":
    'DeepSeek 强度规则示例：\n"effort": [\n  { "value": "none", "set": [{ "path": "thinking.type", "value": "disabled" }], "delete": ["reasoning_effort"] },\n  { "value": "high", "set": [{ "path": "thinking.type", "value": "enabled" }, { "path": "reasoning_effort", "value": "high" }] }\n]',
  "providerConfig.validateProjection": "验证规则",
  "providerConfig.projectionValid": "规则有效",
  "providerConfig.projectionInvalid": "请求投影规则无效。",
  "providerConfig.projectionEffortRequired":
    "启用推理时至少需要一条推理强度规则。",
  "providerConfig.projectionReasoningUnsupported":
    "模型不支持推理时不能定义强度或摘要规则；仍可配置额外参数。",
  "providerConfig.unknown": "未知",
  "providerConfig.native": "原生支持",
  "providerConfig.unsupported": "不支持",
  "providerConfig.editModels": "编辑模型",
  "providerConfig.editModelsDescription":
    "新增、更新或删除模型，并且只声明已经确认的能力限制。",
  "providerConfig.addModel": "新增模型",
  "providerConfig.removeModel": "删除模型",
  "providerConfig.saveModels": "保存模型",
  "providerConfig.modelSaveFailed": "无法保存自定义模型目录。",
  "providerConfig.editSettings": "编辑供应商设置",
  "providerConfig.editSettingsDescription":
    "修改本地显示名称、稳定标识与自定义供应商 API 基础地址；协议、模型及凭据保持不变。",
  "providerConfig.editBaseURLHelp":
    "填写完整的上游 API 基础地址；如果供应商要求版本路径，需要包含类似 /v1 的路径。",
  "providerConfig.endpointRequired": "该供应商不存在可编辑的 API 入口。",
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
  "sidebar.accessDiagnostics": "访问诊断",
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
