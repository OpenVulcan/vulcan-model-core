package management

import (
	"fmt"
	"strings"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	provideropenai "github.com/OpenVulcan/vulcan-model-core/internal/provider/openai"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
)

// systemModelTemplate contains code-owned facts shared across instance-isolated catalog records.
// systemModelTemplate 包含在实例隔离目录记录之间共享的代码拥有事实。
type systemModelTemplate struct {
	// upstreamID is the exact provider model identifier.
	// upstreamID 是精确的供应商模型标识。
	upstreamID string
	// displayName is the operator-facing model name.
	// displayName 是面向操作员的模型名称。
	displayName string
	// contextWindow is the verified maximum input and output context size.
	// contextWindow 是已验证的最大输入输出上下文大小。
	contextWindow int64
	// maxOutputTokens is the provider-declared maximum completion size when known.
	// maxOutputTokens 是已知时由供应商声明的最大补全大小。
	maxOutputTokens int64
	// maxReasoningTokens is the provider-declared reasoning budget ceiling when known.
	// maxReasoningTokens 是已知时由供应商声明的推理预算上限。
	maxReasoningTokens int64
	// inputModalities lists the exact accepted resource kinds.
	// inputModalities 列出精确接受的资源类型。
	inputModalities []string
	// reasoning records the verified reasoning capability level.
	// reasoning 记录已验证的推理能力等级。
	reasoning catalog.CapabilityLevel
	// toolCalling records the verified tool-call capability level.
	// toolCalling 记录已验证的工具调用能力等级。
	toolCalling catalog.CapabilityLevel
	// parallelTools records verified parallel tool-call support.
	// parallelTools 记录已验证的并行工具调用支持。
	parallelTools catalog.CapabilityLevel
	// streamingTools records verified streamed tool-call support.
	// streamingTools 记录已验证的流式工具调用支持。
	streamingTools catalog.CapabilityLevel
	// strictSchema records verified strict JSON Schema support.
	// strictSchema 记录已验证的严格 JSON Schema 支持。
	strictSchema catalog.CapabilityLevel
	// entitlementMode determines how access is verified for the model.
	// entitlementMode 决定模型访问权的验证方式。
	entitlementMode catalog.EntitlementMode
}

// buildSystemCatalog materializes one immutable template into records owned only by the new instance.
// buildSystemCatalog 将一个不可变模板实例化为仅由新实例拥有的记录。
func buildSystemCatalog(onboarding providerconfig.SystemOnboarding, definition providerconfig.ProviderDefinition, observedAt time.Time) (catalog.Snapshot, error) {
	templates, errTemplates := systemModelTemplates(definition.ModelCatalogID)
	if errTemplates != nil {
		return catalog.Snapshot{}, errTemplates
	}
	snapshot := catalog.Snapshot{ProviderInstanceID: onboarding.Instance.ID, Revision: 1, ObservedAt: observedAt}
	for _, template := range templates {
		modelSuffix := catalogIdentifier(template.upstreamID)
		modelID := "model_" + modelSuffix
		snapshot.Models = append(snapshot.Models, catalog.ProviderModel{ID: modelID, ProviderInstanceID: onboarding.Instance.ID, UpstreamModelID: template.upstreamID, DisplayName: template.displayName, Source: catalog.ModelSourceSystem, EntitlementMode: template.entitlementMode, Revision: 1})
		protocolSuffix := catalogIdentifier(definition.ProtocolProfileID)
		offeringID := "offer_" + modelSuffix + "_" + protocolSuffix
		capabilities := systemModelCapabilities(template)
		snapshot.Offerings = append(snapshot.Offerings, catalog.ModelOffering{ID: offeringID, ProviderInstanceID: onboarding.Instance.ID, ProviderModelID: modelID, ChannelID: definition.ProtocolProfileID, UpstreamModelID: template.upstreamID, Capabilities: capabilities, CapabilityRevision: 1, Revision: 1})
		snapshot.Profiles = append(snapshot.Profiles, catalog.ExecutionProfile{ID: "profile_" + modelSuffix + "_" + protocolSuffix, ProviderInstanceID: onboarding.Instance.ID, OfferingID: offeringID, DisplayName: template.displayName, Default: true, Capabilities: capabilities, SwitchPolicy: catalog.ProfileSwitchReplayRequired, PoolPolicy: catalog.PoolPreferSmallestSufficient, CapabilityRevision: 1, Revision: 1})
	}
	if errValidate := snapshot.Validate(); errValidate != nil {
		return catalog.Snapshot{}, fmt.Errorf("validate system provider catalog: %w", errValidate)
	}
	return snapshot, nil
}

// systemModelTemplates returns the exact current code-owned model set for one registered catalog identifier.
// systemModelTemplates 返回一个已注册目录标识的精确当前代码拥有模型集合。
func systemModelTemplates(catalogID string) ([]systemModelTemplate, error) {
	switch catalogID {
	case "kimi_open_platform":
		return kimiOpenPlatformModels(), nil
	case "kimi_coding":
		return kimiCodingModels(), nil
	case "openai_api":
		// CLIProxyAPI does not own a static public OpenAI API model list; the empty catalog avoids inventing one.
		// CLIProxyAPI 不拥有静态公开 OpenAI API 模型列表；空目录避免虚构模型。
		return []systemModelTemplate{}, nil
	case "openai_codex_api_key":
		return codexSystemModels(catalog.EntitlementAllBoundCredentials), nil
	case "openai_codex_account":
		return codexSystemModels(catalog.EntitlementExplicit), nil
	case "anthropic_api", "anthropic_claude_code":
		return copiedTextModels("claude", []systemModelIdentity{{"claude-haiku-4-5-20251001", "Claude 4.5 Haiku", 200000}, {"claude-sonnet-4-5-20250929", "Claude 4.5 Sonnet", 200000}, {"claude-sonnet-4-6", "Claude 4.6 Sonnet", 200000}, {"claude-opus-4-6", "Claude 4.6 Opus", 1000000}, {"claude-opus-4-7", "Claude Opus 4.7", 1000000}, {"claude-opus-4-8", "Claude Opus 4.8", 1000000}, {"claude-sonnet-5", "Claude Sonnet 5", 1000000}, {"claude-fable-5", "Claude Fable 5", 1000000}, {"claude-opus-4-5-20251101", "Claude 4.5 Opus", 200000}, {"claude-opus-4-1-20250805", "Claude 4.1 Opus", 200000}, {"claude-opus-4-20250514", "Claude 4 Opus", 200000}, {"claude-sonnet-4-20250514", "Claude 4 Sonnet", 200000}, {"claude-3-7-sonnet-20250219", "Claude 3.7 Sonnet", 128000}, {"claude-3-5-haiku-20241022", "Claude 3.5 Haiku", 128000}}), nil
	case "google_ai_studio":
		return geminiAPITextModels(), nil
	case "google_interactions":
		return geminiAPITextModels(), nil
	case "google_vertex":
		// VCP 1.0 has no durable Router-owned output resource store, so media-output Imagen and Gemini Image products are not advertised as executable text models.
		// VCP 1.0 尚无持久 Router 所有输出资源存储，因此不将媒体输出 Imagen 与 Gemini Image 产品声明为可执行文本模型。
		return copiedTextModels("vertex", []systemModelIdentity{{"gemini-2.5-pro", "Gemini 2.5 Pro", 0}, {"gemini-2.5-flash", "Gemini 2.5 Flash", 0}, {"gemini-2.5-flash-lite", "Gemini 2.5 Flash Lite", 0}, {"gemini-3-pro-preview", "Gemini 3 Pro Preview", 0}, {"gemini-3-flash-preview", "Gemini 3 Flash Preview", 0}, {"gemini-3.1-pro-preview", "Gemini 3.1 Pro Preview", 0}, {"gemini-3.1-flash-lite", "Gemini 3.1 Flash Lite", 0}, {"gemini-3.5-flash", "Gemini 3.5 Flash", 0}}), nil
	case "google_antigravity":
		return copiedTextModels("antigravity", []systemModelIdentity{{"claude-opus-4-6-thinking", "Claude Opus 4.6 (Thinking)", 200000}, {"claude-sonnet-4-6", "Claude Sonnet 4.6 (Thinking)", 200000}, {"gemini-3-flash", "Gemini 3 Flash", 1048576}, {"gemini-3-flash-agent", "Gemini 3.5 Flash (High)", 1048576}, {"gemini-pro-agent", "Gemini 3.1 Pro (High)", 1048576}, {"gemini-3.1-pro-low", "Gemini 3.1 Pro (Low)", 1048576}, {"gpt-oss-120b-medium", "GPT-OSS 120B (Medium)", 114000}, {"gemini-3.1-flash-lite", "Gemini 3.1 Flash Lite", 1048576}, {"gemini-3.5-flash-low", "Gemini 3.5 Flash (Medium)", 1048576}, {"gemini-3.5-flash-extra-low", "Gemini 3.5 Flash (Low)", 1048576}}), nil
	case "xai_api", "xai_account":
		return copiedTextModels("xai", []systemModelIdentity{{"grok-build-0.1", "Grok Build 0.1", 256000}, {"grok-4.5", "Grok 4.5", 500000}, {"grok-4.3", "Grok 4.3", 1000000}, {"grok-4.20-0309-reasoning", "Grok 4.20 0309 Reasoning", 2000000}, {"grok-4.20-0309-non-reasoning", "Grok 4.20 0309 Non Reasoning", 2000000}, {"grok-4.20-multi-agent-0309", "Grok 4.20 Multi Agent 0309", 2000000}, {"grok-3-mini", "Grok 3 Mini", 131072}, {"grok-3-mini-fast", "Grok 3 Mini Fast", 131072}, {"grok-composer-2.5-fast", "Composer 2.5 Fast", 200000}}), nil
	default:
		return nil, fmt.Errorf("system provider model catalog %q is not registered", catalogID)
	}
}

// codexSystemModels maps the shared CLIProxyAPI Codex catalog to one product-specific entitlement boundary.
// codexSystemModels 将共享 CLIProxyAPI Codex 目录映射到一个产品特定授权边界。
func codexSystemModels(entitlementMode catalog.EntitlementMode) []systemModelTemplate {
	models := provideropenai.CodexCatalogModels()
	templates := make([]systemModelTemplate, 0, len(models))
	for _, model := range models {
		templates = append(templates, systemModelTemplate{upstreamID: model.UpstreamID, displayName: model.DisplayName, contextWindow: model.ContextWindow, maxOutputTokens: model.MaxOutputTokens, inputModalities: []string{"text"}, reasoning: model.Reasoning, toolCalling: model.ToolCalling, parallelTools: catalog.CapabilityUnknown, streamingTools: catalog.CapabilityUnknown, strictSchema: catalog.CapabilityUnknown, entitlementMode: entitlementMode})
	}
	return templates
}

// systemModelIdentity contains the exact identity and context facts copied from CLIProxyAPI's models.json.
// systemModelIdentity 包含从 CLIProxyAPI models.json 精确复制的身份与上下文事实。
type systemModelIdentity struct {
	// upstreamID is the provider model identifier.
	// upstreamID 是供应商模型标识。
	upstreamID string
	// displayName is the copied user-facing model name.
	// displayName 是复制的用户可见模型名称。
	displayName string
	// contextWindow is the copied context limit, or zero when CLIProxyAPI does not declare one.
	// contextWindow 是复制的上下文限制；CLIProxyAPI 未声明时为零。
	contextWindow int64
}

// copiedTextModels converts copied CLIProxyAPI identities and structured model evidence into conservative templates.
// copiedTextModels 将复制的 CLIProxyAPI 身份与结构化模型证据转换为保守模板。
func copiedTextModels(sourceCatalogID string, identities []systemModelIdentity) []systemModelTemplate {
	templates := make([]systemModelTemplate, 0, len(identities))
	for _, identity := range identities {
		evidence := copiedModelEvidenceFor(sourceCatalogID, identity.upstreamID)
		templates = append(templates, systemModelTemplate{upstreamID: identity.upstreamID, displayName: identity.displayName, contextWindow: identity.contextWindow, maxOutputTokens: evidence.maxOutputTokens, maxReasoningTokens: evidence.maxReasoningTokens, inputModalities: []string{"text"}, reasoning: evidence.reasoning, toolCalling: evidence.toolCalling, parallelTools: catalog.CapabilityUnknown, streamingTools: catalog.CapabilityUnknown, strictSchema: catalog.CapabilityUnknown, entitlementMode: catalog.EntitlementAllBoundCredentials})
	}
	return templates
}

// geminiAPITextModels returns CLIProxyAPI's official Gemini API-key catalog while excluding image-output products that VCP cannot persist yet.
// geminiAPITextModels 返回 CLIProxyAPI 官方 Gemini API Key 目录，并排除 VCP 当前尚不能持久化的图像输出产品。
func geminiAPITextModels() []systemModelTemplate {
	return copiedTextModels("gemini", []systemModelIdentity{{"gemini-2.5-pro", "Gemini 2.5 Pro", 0}, {"gemini-2.5-flash", "Gemini 2.5 Flash", 0}, {"gemini-2.5-flash-lite", "Gemini 2.5 Flash Lite", 0}, {"gemini-3-pro-preview", "Gemini 3 Pro Preview", 0}, {"gemini-3.1-pro-preview", "Gemini 3.1 Pro Preview", 0}, {"gemini-3-flash-preview", "Gemini 3 Flash Preview", 0}, {"gemini-3.1-flash-lite-preview", "Gemini 3.1 Flash Lite Preview", 0}, {"gemini-3.5-flash", "Gemini 3.5 Flash", 0}})
}

// kimiOpenPlatformModels returns current non-retired models documented by the Kimi API Open Platform.
// kimiOpenPlatformModels 返回 Kimi API 开放平台当前记录且未退役的模型。
func kimiOpenPlatformModels() []systemModelTemplate {
	allBound := catalog.EntitlementAllBoundCredentials
	return []systemModelTemplate{
		{upstreamID: "kimi-k3", displayName: "Kimi K3", contextWindow: 1048576, inputModalities: []string{"text", "image", "video"}, reasoning: catalog.CapabilityNative, toolCalling: catalog.CapabilityNative, parallelTools: catalog.CapabilityNative, streamingTools: catalog.CapabilityNative, strictSchema: catalog.CapabilityNative, entitlementMode: allBound},
		{upstreamID: "kimi-k2.7-code", displayName: "Kimi K2.7 Code", contextWindow: 262144, inputModalities: []string{"text", "image", "video"}, reasoning: catalog.CapabilityUnknown, toolCalling: catalog.CapabilityNative, parallelTools: catalog.CapabilityNative, streamingTools: catalog.CapabilityNative, strictSchema: catalog.CapabilityUnknown, entitlementMode: allBound},
		{upstreamID: "kimi-k2.7-code-highspeed", displayName: "Kimi K2.7 Code HighSpeed", contextWindow: 262144, inputModalities: []string{"text", "image", "video"}, reasoning: catalog.CapabilityUnknown, toolCalling: catalog.CapabilityNative, parallelTools: catalog.CapabilityNative, streamingTools: catalog.CapabilityNative, strictSchema: catalog.CapabilityUnknown, entitlementMode: allBound},
		{upstreamID: "kimi-k2.6", displayName: "Kimi K2.6", contextWindow: 262144, inputModalities: []string{"text", "image"}, reasoning: catalog.CapabilityUnknown, toolCalling: catalog.CapabilityNative, parallelTools: catalog.CapabilityNative, streamingTools: catalog.CapabilityNative, strictSchema: catalog.CapabilityUnknown, entitlementMode: allBound},
		{upstreamID: "kimi-k2.5", displayName: "Kimi K2.5", contextWindow: 262144, inputModalities: []string{"text", "image"}, reasoning: catalog.CapabilityUnknown, toolCalling: catalog.CapabilityNative, parallelTools: catalog.CapabilityNative, streamingTools: catalog.CapabilityNative, strictSchema: catalog.CapabilityUnknown, entitlementMode: catalog.EntitlementExplicit},
		{upstreamID: "moonshot-v1-8k", displayName: "Moonshot V1 8K", contextWindow: 8192, inputModalities: []string{"text"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnknown, parallelTools: catalog.CapabilityUnknown, streamingTools: catalog.CapabilityUnknown, strictSchema: catalog.CapabilityUnknown, entitlementMode: catalog.EntitlementExplicit},
		{upstreamID: "moonshot-v1-32k", displayName: "Moonshot V1 32K", contextWindow: 32768, inputModalities: []string{"text"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnknown, parallelTools: catalog.CapabilityUnknown, streamingTools: catalog.CapabilityUnknown, strictSchema: catalog.CapabilityUnknown, entitlementMode: catalog.EntitlementExplicit},
		{upstreamID: "moonshot-v1-128k", displayName: "Moonshot V1 128K", contextWindow: 131072, inputModalities: []string{"text"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnknown, parallelTools: catalog.CapabilityUnknown, streamingTools: catalog.CapabilityUnknown, strictSchema: catalog.CapabilityUnknown, entitlementMode: catalog.EntitlementExplicit},
		{upstreamID: "moonshot-v1-8k-vision-preview", displayName: "Moonshot V1 8K Vision", contextWindow: 8192, inputModalities: []string{"text", "image"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnknown, parallelTools: catalog.CapabilityUnknown, streamingTools: catalog.CapabilityUnknown, strictSchema: catalog.CapabilityUnknown, entitlementMode: catalog.EntitlementExplicit},
		{upstreamID: "moonshot-v1-32k-vision-preview", displayName: "Moonshot V1 32K Vision", contextWindow: 32768, inputModalities: []string{"text", "image"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnknown, parallelTools: catalog.CapabilityUnknown, streamingTools: catalog.CapabilityUnknown, strictSchema: catalog.CapabilityUnknown, entitlementMode: catalog.EntitlementExplicit},
		{upstreamID: "moonshot-v1-128k-vision-preview", displayName: "Moonshot V1 128K Vision", contextWindow: 131072, inputModalities: []string{"text", "image"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnknown, parallelTools: catalog.CapabilityUnknown, streamingTools: catalog.CapabilityUnknown, strictSchema: catalog.CapabilityUnknown, entitlementMode: catalog.EntitlementExplicit},
	}
}

// kimiCodingModels returns CLIProxyAPI's exact Kimi executor model set at the pinned source baseline.
// kimiCodingModels 返回 CLIProxyAPI 在固定源码基线上的精确 Kimi Executor 模型集合。
func kimiCodingModels() []systemModelTemplate {
	return copiedTextModels("kimi", []systemModelIdentity{{"kimi-k2", "Kimi K2", 131072}, {"kimi-k2-thinking", "Kimi K2 Thinking", 131072}, {"kimi-k2.5", "Kimi K2.5", 262144}, {"kimi-k2.6", "Kimi K2.6", 262144}, {"kimi-k2.7-code", "Kimi K2.7 Code", 262144}, {"kimi-k2.7-code-highspeed", "Kimi K2.7 Code HighSpeed", 262144}, {"kimi-k3", "Kimi K3", 1048576}})
}

// systemModelCapabilities constructs one closed capability set without inferring undocumented output limits.
// systemModelCapabilities 构建一组封闭能力且不推断未记录输出限制。
func systemModelCapabilities(template systemModelTemplate) catalog.ModelCapabilities {
	contextWindow := catalog.OptionalTokenLimit{}
	if template.contextWindow > 0 {
		contextWindow = catalog.OptionalTokenLimit{Known: true, Value: template.contextWindow}
	}
	maxOutputTokens := catalog.OptionalTokenLimit{}
	if template.maxOutputTokens > 0 {
		maxOutputTokens = catalog.OptionalTokenLimit{Known: true, Value: template.maxOutputTokens}
	}
	maxReasoningTokens := catalog.OptionalTokenLimit{}
	if template.maxReasoningTokens > 0 {
		maxReasoningTokens = catalog.OptionalTokenLimit{Known: true, Value: template.maxReasoningTokens}
	}
	return catalog.ModelCapabilities{Tokens: catalog.TokenLimits{ContextWindow: contextWindow, MaxOutputTokens: maxOutputTokens, MaxReasoningTokens: maxReasoningTokens}, ToolCalling: template.toolCalling, ParallelToolCalls: template.parallelTools, StreamingToolArguments: template.streamingTools, StrictJSONSchema: template.strictSchema, Reasoning: template.reasoning, InputModalities: append([]string(nil), template.inputModalities...), OutputModalities: []string{"text"}}
}

// catalogIdentifier converts one trusted upstream model identifier to the portable catalog identifier alphabet.
// catalogIdentifier 将一个受信任上游模型标识转换为可移植目录标识字母表。
func catalogIdentifier(value string) string {
	return strings.NewReplacer("-", "_", ".", "_").Replace(value)
}
