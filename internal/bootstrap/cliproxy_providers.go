package bootstrap

import (
	"fmt"

	protocolmessages "github.com/OpenVulcan/vulcan-model-core/internal/protocol/anthropic/messages"
	protocolaistudio "github.com/OpenVulcan/vulcan-model-core/internal/protocol/google/aistudio"
	protocolantigravity "github.com/OpenVulcan/vulcan-model-core/internal/protocol/google/antigravity"
	protocolinteractions "github.com/OpenVulcan/vulcan-model-core/internal/protocol/google/interactions"
	protocolcodex "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/codex"
	protocolresponses "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/responses"
	protocolxai "github.com/OpenVulcan/vulcan-model-core/internal/protocol/xai/responses"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	provideranthropic "github.com/OpenVulcan/vulcan-model-core/internal/provider/anthropic"
	providergoogle "github.com/OpenVulcan/vulcan-model-core/internal/provider/google"
	provideropenai "github.com/OpenVulcan/vulcan-model-core/internal/provider/openai"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	providerxai "github.com/OpenVulcan/vulcan-model-core/internal/provider/xai"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
)

const (
	// OpenAIGroupID identifies the OpenAI provider family.
	// OpenAIGroupID 标识 OpenAI 供应商系列。
	OpenAIGroupID = "openai"
	// OpenAIAPIDefinitionID identifies the public OpenAI API product.
	// OpenAIAPIDefinitionID 标识公开 OpenAI API 产品。
	OpenAIAPIDefinitionID = "system_openai_api"
	// OpenAICodexDefinitionID identifies the ChatGPT Codex product.
	// OpenAICodexDefinitionID 标识 ChatGPT Codex 产品。
	OpenAICodexDefinitionID = "system_openai_codex"
	// OpenAICodexAPIKeyDefinitionID identifies CLIProxyAPI's independently configured Codex API-key product.
	// OpenAICodexAPIKeyDefinitionID 标识 CLIProxyAPI 独立配置的 Codex API Key 产品。
	OpenAICodexAPIKeyDefinitionID = "system_openai_codex_api_key"
	// AnthropicGroupID identifies the Anthropic provider family.
	// AnthropicGroupID 标识 Anthropic 供应商系列。
	AnthropicGroupID = "anthropic"
	// AnthropicAPIDefinitionID identifies the public Anthropic API product.
	// AnthropicAPIDefinitionID 标识公开 Anthropic API 产品。
	AnthropicAPIDefinitionID = "system_anthropic_api"
	// AnthropicClaudeCodeDefinitionID identifies the Claude Code subscription product.
	// AnthropicClaudeCodeDefinitionID 标识 Claude Code 订阅产品。
	AnthropicClaudeCodeDefinitionID = "system_anthropic_claude_code"
	// GoogleGroupID identifies the Google model provider family.
	// GoogleGroupID 标识 Google 模型供应商系列。
	GoogleGroupID = "google"
	// GoogleAIStudioDefinitionID identifies Google AI Studio.
	// GoogleAIStudioDefinitionID 标识 Google AI Studio。
	GoogleAIStudioDefinitionID = "system_google_ai_studio"
	// GoogleInteractionsDefinitionID identifies the Google Interactions API.
	// GoogleInteractionsDefinitionID 标识 Google Interactions API。
	GoogleInteractionsDefinitionID = "system_google_interactions"
	// GoogleVertexDefinitionID identifies Google Vertex AI.
	// GoogleVertexDefinitionID 标识 Google Vertex AI。
	GoogleVertexDefinitionID = "system_google_vertex"
	// GoogleAntigravityDefinitionID identifies Google Antigravity.
	// GoogleAntigravityDefinitionID 标识 Google Antigravity。
	GoogleAntigravityDefinitionID = "system_google_antigravity"
	// XAIGroupID identifies the xAI provider family.
	// XAIGroupID 标识 xAI 供应商系列。
	XAIGroupID = "xai"
	// XAIAPIDefinitionID identifies the public xAI API product.
	// XAIAPIDefinitionID 标识公开 xAI API 产品。
	XAIAPIDefinitionID = "system_xai_api"
	// XAIOAuthDefinitionID identifies xAI account authorization.
	// XAIOAuthDefinitionID 标识 xAI 账号授权产品。
	XAIOAuthDefinitionID = "system_xai_oauth"
)

// registerCLIProxyProviderCatalog registers adapted system products evidenced by CLIProxyAPI's built-in executors and configuration types.
// registerCLIProxyProviderCatalog 注册由 CLIProxyAPI 内置执行器和配置类型验证、且已完成适配的系统产品。
func registerCLIProxyProviderCatalog(registry *providerconfig.SystemRegistry) error {
	// groups preserves CLIProxyAPI brand ownership while variants select one exact product and protocol.
	// groups 保留 CLIProxyAPI 的品牌归属，同时由变体选择一个精确产品和协议。
	groups := []providerconfig.ProviderGroup{
		{ID: OpenAIGroupID, DisplayName: "OpenAI", Description: "OpenAI API and account-scoped Codex products.", DescriptionKey: "providers.openai.description", SortOrder: 20, Revision: 1},
		{ID: AnthropicGroupID, DisplayName: "Anthropic", Description: "Anthropic API and Claude Code subscription products.", DescriptionKey: "providers.anthropic.description", SortOrder: 30, Revision: 1},
		{ID: GoogleGroupID, DisplayName: "Google", Description: "Google AI Studio, Interactions, Vertex AI, and Antigravity products.", DescriptionKey: "providers.google.description", SortOrder: 40, Revision: 1},
		{ID: XAIGroupID, DisplayName: "xAI", Description: "xAI API and account-authorized products.", DescriptionKey: "providers.xai.description", SortOrder: 50, Revision: 1},
	}
	for _, group := range groups {
		if errRegister := registry.RegisterGroup(group); errRegister != nil {
			return fmt.Errorf("register provider group %s: %w", group.ID, errRegister)
		}
	}
	for _, definition := range cliProxyProviderDefinitions() {
		if errRegister := registry.Register(definition); errRegister != nil {
			return fmt.Errorf("register provider definition %s: %w", definition.ID, errRegister)
		}
	}
	return nil
}

// RegisterCLIProxyExecutionDrivers binds every runtime-ready non-Kimi CLIProxyAPI provider product to one driver.
// RegisterCLIProxyExecutionDrivers 将每个运行时就绪的非 Kimi CLIProxyAPI 供应商产品绑定到唯一 Driver。
func RegisterCLIProxyExecutionDrivers(registry *provider.ExecutionRegistry, client *transport.Client, codexClient *transport.Client, claudeClient *transport.Client, xaiOAuthClient *transport.Client, antigravityClient *transport.Client, vertexClient *transport.Client) error {
	if registry == nil || client == nil || codexClient == nil || claudeClient == nil || xaiOAuthClient == nil || antigravityClient == nil || vertexClient == nil {
		return fmt.Errorf("CLIProxyAPI execution registry and transport client are required")
	}
	// drivers are created from copied, provider-specific protocol implementations already present in this repository.
	// drivers 由仓库中已有的、复制并适配后的供应商专属协议实现创建。
	drivers := make([]provider.ExecutionDriver, 0, 11)
	openAIAPI, errOpenAIAPI := provideropenai.NewResponsesDriver(OpenAIAPIDefinitionID, client, responsesCapabilities())
	if errOpenAIAPI != nil {
		return fmt.Errorf("create OpenAI API driver: %w", errOpenAIAPI)
	}
	drivers = append(drivers, openAIAPI)
	openAICodexAPIKey, errOpenAICodexAPIKey := provideropenai.NewCodexDriver(OpenAICodexAPIKeyDefinitionID, client, responsesCapabilities())
	if errOpenAICodexAPIKey != nil {
		return fmt.Errorf("create OpenAI Codex API-key driver: %w", errOpenAICodexAPIKey)
	}
	drivers = append(drivers, openAICodexAPIKey)
	openAICodex, errOpenAICodex := provideropenai.NewCodexDriver(OpenAICodexDefinitionID, codexClient, responsesCapabilities())
	if errOpenAICodex != nil {
		return fmt.Errorf("create OpenAI Codex driver: %w", errOpenAICodex)
	}
	drivers = append(drivers, openAICodex)
	anthropicAPI, errAnthropicAPI := provideranthropic.NewMessagesDriver(AnthropicAPIDefinitionID, client, responsesCapabilities())
	if errAnthropicAPI != nil {
		return fmt.Errorf("create Anthropic API driver: %w", errAnthropicAPI)
	}
	drivers = append(drivers, anthropicAPI)
	claudeCode, errClaudeCode := provideranthropic.NewBearerMessagesDriver(AnthropicClaudeCodeDefinitionID, claudeClient, responsesCapabilities(), []providerconfig.AuthMethodType{providerconfig.AuthMethodOAuth})
	if errClaudeCode != nil {
		return fmt.Errorf("create Claude Code driver: %w", errClaudeCode)
	}
	drivers = append(drivers, claudeCode)
	aiStudio, errAIStudio := providergoogle.NewAIStudioDriver(GoogleAIStudioDefinitionID, client, aiStudioCapabilities())
	if errAIStudio != nil {
		return fmt.Errorf("create Google AI Studio driver: %w", errAIStudio)
	}
	drivers = append(drivers, aiStudio)
	interactions, errInteractions := providergoogle.NewInteractionsDriver(GoogleInteractionsDefinitionID, client, responsesCapabilities())
	if errInteractions != nil {
		return fmt.Errorf("create Google Interactions driver: %w", errInteractions)
	}
	drivers = append(drivers, interactions)
	vertex, errVertex := providergoogle.NewVertexDriver(GoogleVertexDefinitionID, vertexClient, aiStudioCapabilities())
	if errVertex != nil {
		return fmt.Errorf("create Google Vertex AI driver: %w", errVertex)
	}
	drivers = append(drivers, vertex)
	antigravity, errAntigravity := providergoogle.NewAntigravityDriver(GoogleAntigravityDefinitionID, antigravityClient, responsesCapabilities())
	if errAntigravity != nil {
		return fmt.Errorf("create Google Antigravity driver: %w", errAntigravity)
	}
	drivers = append(drivers, antigravity)
	xaiAPI, errXAIAPI := providerxai.NewResponsesDriver(XAIAPIDefinitionID, client, xaiAPIResponsesCapabilities())
	if errXAIAPI != nil {
		return fmt.Errorf("create xAI API driver: %w", errXAIAPI)
	}
	drivers = append(drivers, xaiAPI)
	xaiOAuth, errXAIOAuth := providerxai.NewBearerResponsesDriver(XAIOAuthDefinitionID, xaiOAuthClient, xaiAccountResponsesCapabilities(), []providerconfig.AuthMethodType{providerconfig.AuthMethodDeviceFlow})
	if errXAIOAuth != nil {
		return fmt.Errorf("create xAI OAuth driver: %w", errXAIOAuth)
	}
	drivers = append(drivers, xaiOAuth)
	for _, driver := range drivers {
		if errRegister := registry.Register(driver); errRegister != nil {
			return fmt.Errorf("register execution driver %s: %w", driver.ProviderDefinitionID(), errRegister)
		}
	}
	return nil
}

// responsesCapabilities returns the common verified Responses translation feature set copied from CLIProxyAPI.
// responsesCapabilities 返回从 CLIProxyAPI 复制并验证的通用 Responses 转换能力集合。
func responsesCapabilities() protocolresponses.ProfileCapabilities {
	return protocolresponses.ProfileCapabilities{NativeSystemPreamble: true, NativeDeveloper: true, StructuredTools: true, ParallelTools: true, StreamingToolArguments: true, StrictJSONSchema: true, Reasoning: true, ReasoningContinuation: true}
}

// aiStudioCapabilities returns the verified Gemini GenerateContent feature set.
// aiStudioCapabilities 返回已验证的 Gemini GenerateContent 能力集合。
func aiStudioCapabilities() protocolaistudio.ProfileCapabilities {
	return protocolaistudio.ProfileCapabilities{NativeSystemInstruction: true, StructuredTools: true, ParallelTools: true, StrictJSONSchema: true, NativeReasoning: true, NativeReasoningSummary: true}
}

// xaiAPIResponsesCapabilities returns the verified official xAI API feature set, including its compact endpoint.
// xaiAPIResponsesCapabilities 返回已验证的官方 xAI API 能力集合，包括 Compact 入口。
func xaiAPIResponsesCapabilities() protocolxai.ProfileCapabilities {
	return protocolxai.ProfileCapabilities{NativeSystemPreamble: true, NativeDeveloper: true, StructuredTools: true, ParallelTools: true, StreamingToolArguments: true, StrictJSONSchema: true, Reasoning: true, ReasoningEffort: true, ReasoningContinuation: true, NativeXSearch: true, NativeRemoteCompaction: true}
}

// xaiAccountResponsesCapabilities excludes compact because the immutable account chat endpoint does not implement it.
// xaiAccountResponsesCapabilities 排除 Compact，因为不可变账号聊天入口没有实现该能力。
func xaiAccountResponsesCapabilities() protocolxai.ProfileCapabilities {
	return protocolxai.ProfileCapabilities{NativeSystemPreamble: true, NativeDeveloper: true, StructuredTools: true, ParallelTools: true, StreamingToolArguments: true, StrictJSONSchema: true, Reasoning: true, ReasoningEffort: true, ReasoningContinuation: true, NativeXSearch: true}
}

// cliProxyProviderDefinitions returns immutable single-protocol system products supported by copied CLIProxyAPI evidence and Vulcan drivers.
// cliProxyProviderDefinitions 返回由已复制的 CLIProxyAPI 证据与 Vulcan Driver 共同支撑的不可变单协议系统产品。
func cliProxyProviderDefinitions() []providerconfig.ProviderDefinition {
	// apiKey represents manually issued provider API keys.
	// apiKey 表示供应商手动签发的 API Key。
	apiKey := providerconfig.AuthMethodDefinition{ID: "api_key", Type: providerconfig.AuthMethodAPIKey, MultipleCredentials: true}
	// oauth represents refreshable account authorization whose acquisition remains provider-specific.
	// oauth 表示可刷新的账号授权，其获取流程仍由供应商专属实现负责。
	oauth := providerconfig.AuthMethodDefinition{ID: "oauth", Type: providerconfig.AuthMethodOAuth, Refreshable: true, MultipleCredentials: true}
	// deviceFlow represents refreshable RFC 8628 account authorization.
	// deviceFlow 表示可刷新的 RFC 8628 账号授权。
	deviceFlow := providerconfig.AuthMethodDefinition{ID: "device_flow", Type: providerconfig.AuthMethodDeviceFlow, Refreshable: true, MultipleCredentials: true}
	// serviceAccount represents one uploaded Google-owned RSA service-account document.
	// serviceAccount 表示一个上传的 Google 所有 RSA 服务账号文档。
	serviceAccount := providerconfig.AuthMethodDefinition{ID: "service_account", Type: providerconfig.AuthMethodServiceAccount, MultipleCredentials: true}
	// unavailable records capabilities that CLIProxyAPI does not expose as provider catalog readers.
	// unavailable 记录 CLIProxyAPI 未作为供应商目录读取器暴露的能力。
	unavailable := providerconfig.ProviderFeatureSet{ModelDiscovery: providerconfig.SupportUnsupported, PlanReader: providerconfig.SupportUnsupported, EntitlementReader: providerconfig.SupportUnsupported, AllowanceReader: providerconfig.SupportUnsupported}
	// codexFeatures reflect plan metadata and its exact allowed-model set embedded in the provider-issued Codex identity token.
	// codexFeatures 反映供应商签发 Codex 身份令牌中携带的套餐元数据及其精确允许模型集合。
	codexFeatures := unavailable
	codexFeatures.PlanReader = providerconfig.SupportSupported
	codexFeatures.EntitlementReader = providerconfig.SupportSupported
	// antigravityFeatures reflect loadCodeAssist tier and GOOGLE_ONE_AI credit data.
	// antigravityFeatures 反映 loadCodeAssist 返回的套餐层级与 GOOGLE_ONE_AI 积分数据。
	antigravityFeatures := unavailable
	antigravityFeatures.PlanReader = providerconfig.SupportSupported
	antigravityFeatures.AllowanceReader = providerconfig.SupportSupported
	return []providerconfig.ProviderDefinition{
		providerDefinition(OpenAIAPIDefinitionID, "OpenAI API", OpenAIGroupID, "API", "Public OpenAI API using the Responses protocol.", "providers.openai.apiDescription", "openai_api", 10, "openai", protocolresponses.ProfileID, "openai_responses", "https://api.openai.com", true, []providerconfig.AuthMethodDefinition{apiKey}, unavailable),
		providerDefinition(OpenAICodexAPIKeyDefinitionID, "OpenAI Codex API Key", OpenAIGroupID, "Codex API Key", "Codex Responses service configured with a standalone bearer API key.", "providers.openai.codexAPIKeyDescription", "openai_codex_api_key", 20, "codex", protocolcodex.ProfileID, "openai_codex_api_key", "https://chatgpt.com/backend-api/codex", true, []providerconfig.AuthMethodDefinition{apiKey}, unavailable),
		providerDefinition(OpenAICodexDefinitionID, "OpenAI Codex Account", OpenAIGroupID, "Codex Account", "ChatGPT account-scoped Codex service.", "providers.openai.codexDescription", "openai_codex_account", 30, "codex", protocolcodex.ProfileID, "openai_codex", "https://chatgpt.com/backend-api/codex", true, []providerconfig.AuthMethodDefinition{oauth, deviceFlow}, codexFeatures),
		providerDefinition(AnthropicAPIDefinitionID, "Anthropic API", AnthropicGroupID, "API", "Public Anthropic API using Messages.", "providers.anthropic.apiDescription", "anthropic_api", 10, "anthropic", protocolmessages.ProfileID, "anthropic_messages", "https://api.anthropic.com", true, []providerconfig.AuthMethodDefinition{apiKey}, unavailable),
		providerDefinition(AnthropicClaudeCodeDefinitionID, "Claude Code", AnthropicGroupID, "Claude Code", "Anthropic account-scoped Claude Code subscription.", "providers.anthropic.claudeCodeDescription", "anthropic_claude_code", 20, "claude", protocolmessages.ProfileID, "claude_code_messages", "https://api.anthropic.com", true, []providerconfig.AuthMethodDefinition{oauth}, unavailable),
		providerDefinition(GoogleAIStudioDefinitionID, "Google AI Studio", GoogleGroupID, "AI Studio", "Google AI Studio GenerateContent API.", "providers.google.aiStudioDescription", "google_ai_studio", 10, "aistudio", protocolaistudio.ProfileID, "google_ai_studio", "https://generativelanguage.googleapis.com", true, []providerconfig.AuthMethodDefinition{apiKey}, unavailable),
		providerDefinition(GoogleInteractionsDefinitionID, "Google Interactions", GoogleGroupID, "Interactions", "Google native Interactions API.", "providers.google.interactionsDescription", "google_interactions", 20, "interactions", protocolinteractions.ProfileID, "google_interactions", "https://generativelanguage.googleapis.com", true, []providerconfig.AuthMethodDefinition{apiKey}, unavailable),
		vertexProviderDefinition(serviceAccount, unavailable),
		providerDefinition(GoogleAntigravityDefinitionID, "Google Antigravity", GoogleGroupID, "Antigravity", "Google account-scoped Antigravity agent backend.", "providers.google.antigravityDescription", "google_antigravity", 40, "antigravity", protocolantigravity.ProfileID, "google_antigravity", "https://cloudcode-pa.googleapis.com", true, []providerconfig.AuthMethodDefinition{oauth}, antigravityFeatures),
		providerDefinition(XAIAPIDefinitionID, "xAI API", XAIGroupID, "API", "Public xAI API using xAI Responses.", "providers.xai.apiDescription", "xai_api", 10, "xai", protocolxai.ProfileID, "xai_responses", "https://api.x.ai/v1", true, []providerconfig.AuthMethodDefinition{apiKey}, unavailable),
		providerDefinition(XAIOAuthDefinitionID, "xAI Account", XAIGroupID, "Account", "Grok CLI account authorization using xAI Responses.", "providers.xai.oauthDescription", "xai_account", 20, "xai", protocolxai.ProfileID, "xai_oauth_responses", "https://cli-chat-proxy.grok.com/v1", true, []providerconfig.AuthMethodDefinition{deviceFlow}, unavailable),
	}
}

// vertexProviderDefinition builds the regional service-account product without exposing an editable endpoint.
// vertexProviderDefinition 构建区域服务账号产品且不暴露可编辑入口。
func vertexProviderDefinition(serviceAccount providerconfig.AuthMethodDefinition, features providerconfig.ProviderFeatureSet) providerconfig.ProviderDefinition {
	definition := providerDefinition(GoogleVertexDefinitionID, "Google Vertex AI", GoogleGroupID, "Vertex AI", "Google Cloud Vertex AI using one project-scoped service account.", "providers.google.vertexDescription", "google_vertex", 30, "vertex", protocolaistudio.ProfileID, "google_vertex", "https://us-central1-aiplatform.googleapis.com", true, []providerconfig.AuthMethodDefinition{serviceAccount}, features)
	definition.EndpointPresets[0].Region = "us-central1"
	definition.EndpointPresets[0].RegionalBaseURLTemplate = "https://{region}-aiplatform.googleapis.com"
	definition.EndpointPresets[0].GlobalBaseURL = "https://aiplatform.googleapis.com"
	return definition
}

// providerDefinition constructs one exact system product with one protocol and endpoint.
// providerDefinition 构造具有唯一协议与入口的精确系统产品。
func providerDefinition(id string, displayName string, groupID string, variantName string, description string, descriptionKey string, catalogID string, sortOrder int, driverID string, protocolProfileID string, endpointProfileID string, baseURL string, runtimeReady bool, authMethods []providerconfig.AuthMethodDefinition, features providerconfig.ProviderFeatureSet) providerconfig.ProviderDefinition {
	// authMethodIDs mirrors the declared methods without introducing a second source of truth.
	// authMethodIDs 镜像已声明认证方式且不引入第二事实源。
	authMethodIDs := make([]string, 0, len(authMethods))
	for _, authMethod := range authMethods {
		authMethodIDs = append(authMethodIDs, authMethod.ID)
	}
	return providerconfig.ProviderDefinition{
		ID: id, Kind: providerconfig.DefinitionKindSystem, DisplayName: displayName, GroupID: groupID, VariantName: variantName,
		VariantDescription: description, VariantDescriptionKey: descriptionKey, ModelCatalogID: catalogID, SortOrder: sortOrder,
		DriverID: driverID, DriverVersion: "1", ConfigSchemaVersion: "1", ProtocolProfileID: protocolProfileID, EndpointProfileID: endpointProfileID,
		AuthMethodIDs: authMethodIDs, Priority: 10, RuntimeReady: runtimeReady, AuthMethods: authMethods,
		EndpointPresets: []providerconfig.EndpointPreset{{ID: "default", BaseURL: baseURL, Region: "Global", UserEditable: false}}, Features: features, Revision: 1,
	}
}
