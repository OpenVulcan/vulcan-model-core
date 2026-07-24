package bootstrap

import (
	"fmt"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/dependency"
	protocolchat "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/chat"
	protocolresponses "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/responses"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	provideralibaba "github.com/OpenVulcan/vulcan-model-core/internal/provider/alibaba"
	provideropenai "github.com/OpenVulcan/vulcan-model-core/internal/provider/openai"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

const (
	// AlibabaGroupID identifies the Alibaba Cloud Model Studio provider family.
	// AlibabaGroupID 标识 Alibaba Cloud Model Studio 供应商系列。
	AlibabaGroupID = "alibaba"
	// AlibabaCodingPlanCNDefinitionID identifies the China Coding Plan product.
	// AlibabaCodingPlanCNDefinitionID 标识中国站 Coding Plan 产品。
	AlibabaCodingPlanCNDefinitionID = "system_alibaba_coding_plan_cn"
	// AlibabaCodingPlanGlobalDefinitionID identifies the global Coding Plan product.
	// AlibabaCodingPlanGlobalDefinitionID 标识国际站 Coding Plan 产品。
	AlibabaCodingPlanGlobalDefinitionID = "system_alibaba_coding_plan_global"
	// AlibabaTokenPlanPersonalCNDefinitionID identifies the China Token Plan Personal product.
	// AlibabaTokenPlanPersonalCNDefinitionID 标识中国站 Token Plan Personal 产品。
	AlibabaTokenPlanPersonalCNDefinitionID = "system_alibaba_token_plan_personal_cn"
	// AlibabaTokenPlanPersonalGlobalDefinitionID reserves the unpublished Global Personal product boundary.
	// AlibabaTokenPlanPersonalGlobalDefinitionID 保留尚未发布的国际站个人版产品边界。
	AlibabaTokenPlanPersonalGlobalDefinitionID = "system_alibaba_token_plan_personal_global"
	// AlibabaTokenPlanTeamCNDefinitionID identifies the China Token Plan Team product.
	// AlibabaTokenPlanTeamCNDefinitionID 标识中国站 Token Plan Team 产品。
	AlibabaTokenPlanTeamCNDefinitionID = "system_alibaba_token_plan_team_cn"
	// AlibabaTokenPlanTeamGlobalDefinitionID identifies the global Token Plan Team product.
	// AlibabaTokenPlanTeamGlobalDefinitionID 标识国际站 Token Plan Team 产品。
	AlibabaTokenPlanTeamGlobalDefinitionID = "system_alibaba_token_plan_team_global"
	// AlibabaModelStudioCNDefinitionID identifies the fixed China Model Studio compatible API.
	// AlibabaModelStudioCNDefinitionID 标识固定的中国站百炼兼容 API。
	AlibabaModelStudioCNDefinitionID = "system_alibaba_model_studio_cn"
	// AlibabaModelStudioGlobalDefinitionID identifies the fixed Global Model Studio compatible API.
	// AlibabaModelStudioGlobalDefinitionID 标识固定的国际站百炼兼容 API。
	AlibabaModelStudioGlobalDefinitionID = "system_alibaba_model_studio_global"
	// AlibabaModelStudioUSDefinitionID identifies the fixed United States Model Studio compatible API.
	// AlibabaModelStudioUSDefinitionID 标识固定的美国区域百炼兼容 API。
	AlibabaModelStudioUSDefinitionID = "system_alibaba_model_studio_us"
	// AlibabaModelStudioWorkspaceGlobalDefinitionID identifies the Singapore workspace-scoped Model Studio API.
	// AlibabaModelStudioWorkspaceGlobalDefinitionID 标识新加坡工作空间作用域的百炼 API。
	AlibabaModelStudioWorkspaceGlobalDefinitionID = "system_alibaba_model_studio_workspace_global"
	// alibabaStandardChatPath is the documented Coding Plan OpenAI-compatible path.
	// alibabaStandardChatPath 是有文档依据的 Coding Plan OpenAI 兼容路径。
	alibabaStandardChatPath = "/v1/chat/completions"
	// alibabaCompatibleChatPath is the Model Studio and Token Plan OpenAI-compatible path.
	// alibabaCompatibleChatPath 是 Model Studio 与 Token Plan 的 OpenAI 兼容路径。
	alibabaCompatibleChatPath = "/compatible-mode/v1/chat/completions"
	// alibabaTokenPlanHarnessResponsesPath is the exact provider-hosted tool side-request path used by Qwen Code.
	// alibabaTokenPlanHarnessResponsesPath 是 Qwen Code 使用的精确供应商托管工具旁路请求路径。
	alibabaTokenPlanHarnessResponsesPath = "/compatible-mode/v1/responses"
)

// registerAlibabaProviderCatalog registers Alibaba's immutable plan products and exact regional boundaries.
// registerAlibabaProviderCatalog 注册阿里云不可变套餐产品及精确区域边界。
func registerAlibabaProviderCatalog(registry *providerconfig.SystemRegistry) error {
	if errGroup := registry.RegisterGroup(providerconfig.ProviderGroup{
		ID:             AlibabaGroupID,
		DisplayName:    "Alibaba Cloud Model Studio",
		Description:    "Alibaba Cloud Model Studio APIs and coding subscriptions across CN, Singapore, US, and Global sites.",
		DescriptionKey: "providers.alibaba.description",
		SortOrder:      60,
		Revision:       1,
	}); errGroup != nil {
		return fmt.Errorf("register Alibaba provider group: %w", errGroup)
	}
	for _, definition := range alibabaProviderDefinitions() {
		if errRegister := registry.Register(definition); errRegister != nil {
			return fmt.Errorf("register Alibaba provider definition %s: %w", definition.ID, errRegister)
		}
	}
	return nil
}

// RegisterAlibabaExecutionDrivers binds every Alibaba product to its exact conversation, action, and task drivers.
// RegisterAlibabaExecutionDrivers 将每个阿里云产品绑定到其精确的会话、动作及任务驱动。
func RegisterAlibabaExecutionDrivers(registry *provider.ExecutionRegistry, client *transport.Client, resultFetcher resource.PublicDocumentFetcher) error {
	if registry == nil || client == nil || dependency.IsNil(resultFetcher) {
		return fmt.Errorf("Alibaba execution registry, transport client, and result fetcher are required")
	}
	// chatAdapter owns Alibaba's documented thinking defaults for every OpenAI-compatible product path.
	// chatAdapter 为所有 OpenAI 兼容产品路径管理 Alibaba 文档化的思考默认值。
	chatAdapter := provideralibaba.NewChatAdapter()
	for _, definitionID := range []string{
		AlibabaCodingPlanCNDefinitionID,
		AlibabaCodingPlanGlobalDefinitionID,
	} {
		driver, errDriver := provideropenai.NewBearerChatDriverAtPathWithRequestAdapter(definitionID, protocolchat.ProfileID, client, alibabaChatCapabilities(), []providerconfig.AuthMethodType{providerconfig.AuthMethodAPIKey}, alibabaStandardChatPath, chatAdapter)
		if errDriver != nil {
			return fmt.Errorf("create Alibaba Coding Plan Chat driver %s: %w", definitionID, errDriver)
		}
		if errRegister := registerConversationDriver(registry, driver); errRegister != nil {
			return fmt.Errorf("register Alibaba Coding Plan Chat driver %s: %w", definitionID, errRegister)
		}
	}
	for _, definitionID := range []string{AlibabaTokenPlanPersonalCNDefinitionID, AlibabaTokenPlanTeamCNDefinitionID, AlibabaTokenPlanTeamGlobalDefinitionID, AlibabaModelStudioCNDefinitionID, AlibabaModelStudioGlobalDefinitionID} {
		driver, errDriver := provideropenai.NewBearerChatDriverAtPathWithRequestAdapter(definitionID, protocolchat.ProfileID, client, alibabaChatCapabilities(), []providerconfig.AuthMethodType{providerconfig.AuthMethodAPIKey}, alibabaCompatibleChatPath, chatAdapter)
		if errDriver != nil {
			return fmt.Errorf("create Alibaba compatible Chat driver %s: %w", definitionID, errDriver)
		}
		if errRegister := registerConversationDriver(registry, driver); errRegister != nil {
			return fmt.Errorf("register Alibaba compatible Chat driver %s: %w", definitionID, errRegister)
		}
		if definitionID == AlibabaModelStudioCNDefinitionID || definitionID == AlibabaModelStudioGlobalDefinitionID {
			mediaDriver, errMediaDriver := provideralibaba.NewMediaAnalyzeActionDriver(definitionID, driver)
			if errMediaDriver != nil {
				return fmt.Errorf("create Alibaba Qwen Omni media-analysis driver %s: %w", definitionID, errMediaDriver)
			}
			if errRegister := registry.RegisterAction(mediaDriver); errRegister != nil {
				return fmt.Errorf("register Alibaba Qwen Omni media-analysis driver %s: %w", definitionID, errRegister)
			}
		}
	}
	for _, definitionID := range []string{AlibabaTokenPlanPersonalCNDefinitionID, AlibabaTokenPlanTeamCNDefinitionID, AlibabaTokenPlanTeamGlobalDefinitionID} {
		responsesDriver, errResponsesDriver := provideropenai.NewBearerResponsesDriverAtPathWithRequestAdapter(definitionID, client, alibabaTokenPlanHarnessResponsesCapabilities(), []providerconfig.AuthMethodType{providerconfig.AuthMethodAPIKey}, alibabaTokenPlanHarnessResponsesPath, provideralibaba.NewTokenPlanHarnessResponsesAdapter())
		if errResponsesDriver != nil {
			return fmt.Errorf("create Alibaba Token Plan Harness Responses driver %s: %w", definitionID, errResponsesDriver)
		}
		if errRegister := registry.Register(responsesDriver); errRegister != nil {
			return fmt.Errorf("register Alibaba Token Plan Harness Responses profile driver %s: %w", definitionID, errRegister)
		}
		actionDriver, errActionDriver := provider.NewConversationActionDriver(provideralibaba.TokenPlanHarnessConversationActionBindingID, responsesDriver)
		if errActionDriver != nil {
			return fmt.Errorf("create Alibaba Token Plan Harness conversation action %s: %w", definitionID, errActionDriver)
		}
		if errRegister := registry.RegisterAction(actionDriver); errRegister != nil {
			return fmt.Errorf("register Alibaba Token Plan Harness conversation action %s: %w", definitionID, errRegister)
		}
	}
	for _, definitionID := range []string{AlibabaModelStudioCNDefinitionID, AlibabaModelStudioGlobalDefinitionID} {
		driver, errDriver := provideralibaba.NewEmbeddingDriver(definitionID, client)
		if errDriver != nil {
			return fmt.Errorf("create Alibaba embedding driver %s: %w", definitionID, errDriver)
		}
		if errRegister := registry.RegisterAction(driver); errRegister != nil {
			return fmt.Errorf("register Alibaba embedding driver %s: %w", definitionID, errRegister)
		}
		rerankDriver, errRerankDriver := provideralibaba.NewRerankActionDriver(definitionID, client)
		if errRerankDriver != nil {
			return fmt.Errorf("create Alibaba rerank driver %s: %w", definitionID, errRerankDriver)
		}
		if errRegister := registry.RegisterAction(rerankDriver); errRegister != nil {
			return fmt.Errorf("register Alibaba rerank driver %s: %w", definitionID, errRegister)
		}
		searchDriver, errSearchDriver := provideralibaba.NewWebSearchActionDriver(definitionID, client)
		if errSearchDriver != nil {
			return fmt.Errorf("create Alibaba WebSearch MCP driver %s: %w", definitionID, errSearchDriver)
		}
		if errRegister := registry.RegisterAction(searchDriver); errRegister != nil {
			return fmt.Errorf("register Alibaba WebSearch MCP driver %s: %w", definitionID, errRegister)
		}
		cosyVoiceDriver, errCosyVoiceDriver := provideralibaba.NewCosyVoiceActionDriver(definitionID, client)
		if errCosyVoiceDriver != nil {
			return fmt.Errorf("create Alibaba CosyVoice driver %s: %w", definitionID, errCosyVoiceDriver)
		}
		if errRegister := registry.RegisterAction(cosyVoiceDriver); errRegister != nil {
			return fmt.Errorf("register Alibaba CosyVoice driver %s: %w", definitionID, errRegister)
		}
		for _, actionBindingID := range []string{provideralibaba.SpeechSynthesizeActionBindingID, provideralibaba.SpeechTranscribeActionBindingID} {
			speechDriver, errSpeechDriver := provideralibaba.NewSpeechActionDriver(definitionID, actionBindingID, client)
			if errSpeechDriver != nil {
				return fmt.Errorf("create Alibaba speech driver %s/%s: %w", definitionID, actionBindingID, errSpeechDriver)
			}
			if errRegister := registry.RegisterAction(speechDriver); errRegister != nil {
				return fmt.Errorf("register Alibaba speech driver %s/%s: %w", definitionID, actionBindingID, errRegister)
			}
		}
		speechTaskDriver, errSpeechTaskDriver := provideralibaba.NewSpeechTaskDriver(definitionID, client, resultFetcher)
		if errSpeechTaskDriver != nil {
			return fmt.Errorf("create Alibaba asynchronous speech driver %s: %w", definitionID, errSpeechTaskDriver)
		}
		if errRegister := registry.RegisterTaskAction(speechTaskDriver); errRegister != nil {
			return fmt.Errorf("register Alibaba asynchronous speech driver %s: %w", definitionID, errRegister)
		}
		for _, actionBindingID := range []string{provideralibaba.ImageGenerateActionBindingID, provideralibaba.ImageEditActionBindingID} {
			imageDriver, errImageDriver := provideralibaba.NewImageActionDriver(definitionID, actionBindingID, client)
			if errImageDriver != nil {
				return fmt.Errorf("create Alibaba image driver %s/%s: %w", definitionID, actionBindingID, errImageDriver)
			}
			if errRegister := registry.RegisterAction(imageDriver); errRegister != nil {
				return fmt.Errorf("register Alibaba image driver %s/%s: %w", definitionID, actionBindingID, errRegister)
			}
		}
	}
	for _, binding := range []struct {
		// definitionID identifies the provider product that owns this native action.
		// definitionID 标识拥有该原生操作的供应商产品。
		definitionID string
		// actionBindingID identifies the exact native action wire contract.
		// actionBindingID 标识精确的原生操作 Wire 合同。
		actionBindingID string
	}{
		{definitionID: AlibabaTokenPlanPersonalCNDefinitionID, actionBindingID: provideralibaba.HappyHorseVideoGenerateActionBindingID},
		{definitionID: AlibabaTokenPlanTeamCNDefinitionID, actionBindingID: provideralibaba.HappyHorseVideoGenerateActionBindingID},
		{definitionID: AlibabaModelStudioCNDefinitionID, actionBindingID: provideralibaba.HappyHorseVideoGenerateActionBindingID},
		{definitionID: AlibabaModelStudioCNDefinitionID, actionBindingID: provideralibaba.HappyHorseVideoEditActionBindingID},
	} {
		happyHorseDriver, errHappyHorseDriver := provideralibaba.NewHappyHorseVideoTaskDriver(binding.definitionID, binding.actionBindingID, client)
		if errHappyHorseDriver != nil {
			return fmt.Errorf("create Alibaba HappyHorse driver %s/%s: %w", binding.definitionID, binding.actionBindingID, errHappyHorseDriver)
		}
		if errRegister := registry.RegisterTaskAction(happyHorseDriver); errRegister != nil {
			return fmt.Errorf("register Alibaba HappyHorse driver %s/%s: %w", binding.definitionID, binding.actionBindingID, errRegister)
		}
	}
	for _, definitionID := range []string{AlibabaTokenPlanPersonalCNDefinitionID, AlibabaTokenPlanTeamCNDefinitionID, AlibabaTokenPlanTeamGlobalDefinitionID} {
		wanTokenPlanDriver, errWanTokenPlanDriver := provideralibaba.NewWanImageActionDriver(definitionID, provideralibaba.WanImageGenerateActionBindingID, client)
		if errWanTokenPlanDriver != nil {
			return fmt.Errorf("create Alibaba Token Plan Wan image driver %s: %w", definitionID, errWanTokenPlanDriver)
		}
		if errRegister := registry.RegisterAction(wanTokenPlanDriver); errRegister != nil {
			return fmt.Errorf("register Alibaba Token Plan Wan image driver %s: %w", definitionID, errRegister)
		}
	}
	for _, definitionID := range []string{AlibabaTokenPlanTeamCNDefinitionID, AlibabaTokenPlanTeamGlobalDefinitionID} {
		imageDriver, errImageDriver := provideralibaba.NewImageActionDriver(definitionID, provideralibaba.ImageGenerateActionBindingID, client)
		if errImageDriver != nil {
			return fmt.Errorf("create Alibaba Token Plan Qwen image driver %s: %w", definitionID, errImageDriver)
		}
		if errRegister := registry.RegisterAction(imageDriver); errRegister != nil {
			return fmt.Errorf("register Alibaba Token Plan Qwen image driver %s: %w", definitionID, errRegister)
		}
	}
	return nil
}

// alibabaChatCapabilities returns provider-documented Chat transport features; model-level publication remains catalog-owned.
// alibabaChatCapabilities 返回供应商文档记录的 Chat 传输能力；模型级发布仍由目录拥有。
func alibabaChatCapabilities() protocolchat.ProfileCapabilities {
	return protocolchat.ProfileCapabilities{NativeSystemPreamble: true, StructuredTools: true, ParallelTools: true, StreamingToolArguments: true, StrictJSONSchema: true, Reasoning: true, ProviderReasoningSwitchAdapter: true, ProviderReasoningBudgetAdapter: true, ReasoningContent: true, StreamUsage: true, NativeWebSearch: true, MixedAudioOutput: true, InputAudioURICarrier: true, InputAudioFormats: []string{"wav", "mp3", "amr", "aac", "ogg", "3gpp"}, MediaInputKinds: []vcp.MediaKind{vcp.MediaImage, vcp.MediaVideo, vcp.MediaAudio}, MediaMaterializations: []catalog.UpstreamMaterializationMode{catalog.MaterializationInlineBase64, catalog.MaterializationDirectRemoteURL, catalog.MaterializationProviderObjectURI}}
}

// alibabaTokenPlanHarnessResponsesCapabilities returns only the two provider-hosted tools proven on the exact Responses side request.
// alibabaTokenPlanHarnessResponsesCapabilities 仅返回在精确 Responses 旁路请求上证实的两个供应商托管工具。
func alibabaTokenPlanHarnessResponsesCapabilities() protocolresponses.ProfileCapabilities {
	return protocolresponses.ProfileCapabilities{NativeSystemPreamble: true, NativeWebSearch: true, NativeWebExtractor: true}
}

// alibabaProviderDefinitions returns only the seven independently verified executable Alibaba products.
// alibabaProviderDefinitions 仅返回七个经过独立验证且可执行的 Alibaba 产品。
func alibabaProviderDefinitions() []providerconfig.ProviderDefinition {
	// staticCatalogFeatures disable metadata readers until the same execution key has a verified stable reader contract.
	// staticCatalogFeatures 在同一调用密钥拥有已验证稳定读取合同前禁用元数据读取器。
	staticCatalogFeatures := providerconfig.ProviderFeatureSet{
		PlanReader:        providerconfig.SupportUnsupported,
		EntitlementReader: providerconfig.SupportUnsupported,
		AllowanceReader:   providerconfig.SupportUnsupported,
	}
	// subscriptionAPIKey is the sole executable credential for Alibaba Coding Plan and Token Plan products.
	// subscriptionAPIKey 是 Alibaba Coding Plan 与 Token Plan 产品唯一的可执行凭据。
	subscriptionAPIKey := providerconfig.AuthMethodDefinition{ID: "api_key", Type: providerconfig.AuthMethodAPIKey, MultipleCredentials: true, BillingMode: providerconfig.BillingModeSubscription, ReaderFeatures: &staticCatalogFeatures}
	// usageAPIKey is the metered credential for Alibaba Cloud Model Studio products.
	// usageAPIKey 是 Alibaba Cloud Model Studio 产品的按量计费凭据。
	usageAPIKey := providerconfig.AuthMethodDefinition{ID: "api_key", Type: providerconfig.AuthMethodAPIKey, MultipleCredentials: true, BillingMode: providerconfig.BillingModeUsage, ReaderFeatures: &staticCatalogFeatures}
	definitions := []providerconfig.ProviderDefinition{
		alibabaProviderDefinition(AlibabaCodingPlanCNDefinitionID, "Alibaba Coding Plan CN", "Coding Plan CN", "Alibaba Coding Plan service hosted at the CN site.", "providers.alibaba.codingPlanCNDescription", "alibaba_coding_plan_cn", "coding_plan_cn", "https://coding.dashscope.aliyuncs.com", "CN", 10, subscriptionAPIKey, staticCatalogFeatures),
		alibabaProviderDefinition(AlibabaCodingPlanGlobalDefinitionID, "Alibaba Coding Plan Global", "Coding Plan Global", "Alibaba Coding Plan service hosted at the Global site.", "providers.alibaba.codingPlanGlobalDescription", "alibaba_coding_plan_global", "coding_plan_global", "https://coding-intl.dashscope.aliyuncs.com", "Global", 20, subscriptionAPIKey, staticCatalogFeatures),
		alibabaProviderDefinition(AlibabaTokenPlanPersonalCNDefinitionID, "Alibaba Token Plan Personal CN", "Token Plan Personal CN", "Personal Token Plan service hosted at the CN site.", "providers.alibaba.tokenPlanPersonalCNDescription", "alibaba_token_plan_personal_cn", "token_plan_personal_cn", "https://token-plan.cn-beijing.maas.aliyuncs.com", "CN", 30, subscriptionAPIKey, staticCatalogFeatures),
		alibabaProviderDefinition(AlibabaTokenPlanTeamCNDefinitionID, "Alibaba Token Plan Team CN", "Token Plan Team CN", "Team Token Plan service hosted at the CN site.", "providers.alibaba.tokenPlanTeamCNDescription", "alibaba_token_plan_team_cn", "token_plan_team_cn", "https://token-plan.cn-beijing.maas.aliyuncs.com", "CN", 40, subscriptionAPIKey, staticCatalogFeatures),
		alibabaProviderDefinition(AlibabaTokenPlanTeamGlobalDefinitionID, "Alibaba Token Plan Team Global", "Token Plan Team Global", "Team Token Plan service hosted at the Global site.", "providers.alibaba.tokenPlanTeamGlobalDescription", "alibaba_token_plan_team_global", "token_plan_team_global", "https://token-plan.ap-southeast-1.maas.aliyuncs.com", "Global", 50, subscriptionAPIKey, staticCatalogFeatures),
	}
	for definitionIndex := range definitions {
		switch definitions[definitionIndex].ID {
		case AlibabaTokenPlanPersonalCNDefinitionID:
			definitions[definitionIndex].ActionBindings = append(definitions[definitionIndex].ActionBindings,
				alibabaTokenPlanHarnessActionBinding(),
				alibabaWanImageGenerateActionBinding(),
			)
			definitions[definitionIndex].ActionBindings = append(definitions[definitionIndex].ActionBindings, alibabaHappyHorsePlanActionBindings()...)
		case AlibabaTokenPlanTeamCNDefinitionID:
			definitions[definitionIndex].ActionBindings = append(definitions[definitionIndex].ActionBindings,
				alibabaTokenPlanHarnessActionBinding(),
				alibabaQwenImageGenerateActionBinding(),
				alibabaWanImageGenerateActionBinding(),
			)
			definitions[definitionIndex].ActionBindings = append(definitions[definitionIndex].ActionBindings, alibabaHappyHorsePlanActionBindings()...)
		case AlibabaTokenPlanTeamGlobalDefinitionID:
			definitions[definitionIndex].ActionBindings = append(definitions[definitionIndex].ActionBindings,
				alibabaTokenPlanHarnessActionBinding(),
				alibabaQwenImageGenerateActionBinding(),
				alibabaWanImageGenerateActionBinding(),
			)
		}
	}
	definitions = append(definitions,
		alibabaEmbeddingProviderDefinition(AlibabaModelStudioCNDefinitionID, "Alibaba Cloud Model Studio CN", "Model Studio CN", "Alibaba Cloud Model Studio compatible embedding API hosted at the CN site.", "providers.alibaba.modelStudioCNDescription", "alibaba_model_studio_cn", providerconfig.EndpointPreset{ID: "model_studio_cn", BaseURL: "https://dashscope.aliyuncs.com", Region: "CN"}, 60, usageAPIKey, staticCatalogFeatures),
		alibabaEmbeddingProviderDefinition(AlibabaModelStudioGlobalDefinitionID, "Alibaba Cloud Model Studio Singapore", "Model Studio Singapore", "Alibaba Cloud Model Studio API hosted in Singapore and visible from the domestic console site.", "providers.alibaba.modelStudioSingaporeDescription", "alibaba_model_studio_sg_domestic", providerconfig.EndpointPreset{ID: "model_studio_singapore", BaseURL: "https://dashscope-intl.aliyuncs.com", Region: "Singapore"}, 70, usageAPIKey, staticCatalogFeatures),
	)
	return definitions
}

// alibabaTokenPlanHarnessActionBinding returns the streaming-only Responses side request proven by the official Qwen Code source.
// alibabaTokenPlanHarnessActionBinding 返回官方 Qwen Code 源码证实的仅流式 Responses 旁路请求。
func alibabaTokenPlanHarnessActionBinding() providerconfig.ProviderActionBinding {
	return providerconfig.ProviderActionBinding{
		ID: provideralibaba.TokenPlanHarnessConversationActionBindingID, Operation: vcp.OperationConversationRespond,
		DriverID: "alibaba", DriverVersion: "1", ProtocolProfileID: protocolresponses.ProfileID, EndpointProfileID: "alibaba_token_plan_harness",
		AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Streaming: true}, Revision: 1,
	}
}

// alibabaEmbeddingProviderDefinition builds one fixed regional Chat definition with native model actions.
// alibabaEmbeddingProviderDefinition 构建一个带原生模型动作的固定区域 Chat 定义。
func alibabaEmbeddingProviderDefinition(definitionID string, displayName string, variantName string, description string, descriptionKey string, catalogID string, endpoint providerconfig.EndpointPreset, sortOrder int, apiKey providerconfig.AuthMethodDefinition, features providerconfig.ProviderFeatureSet) providerconfig.ProviderDefinition {
	// inputMaterializations preserve the globally verified inline and direct URL paths.
	// inputMaterializations 保留全球已验证的内联与直连 URL 路径。
	inputMaterializations := []providerconfig.ResourceMaterializationMode{providerconfig.ResourceMaterializationInline, providerconfig.ResourceMaterializationDirectURL}
	// asynchronousInputMaterializations preserve the globally verified direct URL path.
	// asynchronousInputMaterializations 保留全球已验证的直连 URL 路径。
	asynchronousInputMaterializations := []providerconfig.ResourceMaterializationMode{providerconfig.ResourceMaterializationDirectURL}
	if definitionID == AlibabaModelStudioCNDefinitionID {
		inputMaterializations = append(inputMaterializations, providerconfig.ResourceMaterializationObjectURI)
		asynchronousInputMaterializations = append(asynchronousInputMaterializations, providerconfig.ResourceMaterializationObjectURI)
	}
	definition := providerconfig.ProviderDefinition{
		ID: definitionID, Kind: providerconfig.DefinitionKindSystem, DisplayName: displayName,
		GroupID: AlibabaGroupID, VariantName: variantName, VariantDescription: description, VariantDescriptionKey: descriptionKey, ModelCatalogID: catalogID, SortOrder: sortOrder,
		DriverID: "alibaba", DriverVersion: "1", ConfigSchemaVersion: "1", ProtocolProfileID: protocolchat.ProfileID, EndpointProfileID: "alibaba_chat", AuthMethodIDs: []string{"api_key"}, Priority: 10, RuntimeReady: true,
		AuthMethods: []providerconfig.AuthMethodDefinition{apiKey}, EndpointPresets: []providerconfig.EndpointPreset{endpoint}, Features: features, Revision: 1,
	}
	definition.ActionBindings = []providerconfig.ProviderActionBinding{
		{ID: ConversationActionBindingID, Operation: vcp.OperationConversationRespond, DriverID: "alibaba", DriverVersion: "1", ProtocolProfileID: protocolchat.ProfileID, EndpointProfileID: "alibaba_chat", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true, Streaming: true}, Revision: 1},
		{ID: provideralibaba.EmbeddingActionBindingID, Operation: vcp.OperationEmbeddingCreate, DriverID: "alibaba", DriverVersion: "1", ProtocolProfileID: provideralibaba.EmbeddingProtocolProfileID, EndpointProfileID: "alibaba_model_studio_embeddings", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, Revision: 1},
		{ID: provideralibaba.RerankActionBindingID, Operation: vcp.OperationRerankDocuments, DriverID: "alibaba", DriverVersion: "1", ProtocolProfileID: provideralibaba.RerankProtocolProfileID, EndpointProfileID: "alibaba_model_studio_rerank", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, Revision: 1},
		{ID: provideralibaba.SearchWebActionBindingID, Operation: vcp.OperationSearchWeb, DriverID: "alibaba", DriverVersion: "1", ProtocolProfileID: provideralibaba.SearchWebProtocolProfileID, EndpointProfileID: "alibaba_web_search_mcp", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, Search: &providerconfig.SearchActionBinding{BackendKind: vcp.SearchBackendDirectAPI}, Revision: 1},
		{ID: provideralibaba.CosyVoiceSynthesizeActionBindingID, Operation: vcp.OperationSpeechSynthesize, DriverID: "alibaba", DriverVersion: "1", ProtocolProfileID: provideralibaba.CosyVoiceSynthesizeProtocolProfileID, EndpointProfileID: "alibaba_cosyvoice", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true, Streaming: true}, Revision: 1},
		{ID: provideralibaba.SpeechSynthesizeActionBindingID, Operation: vcp.OperationSpeechSynthesize, DriverID: "alibaba", DriverVersion: "1", ProtocolProfileID: provideralibaba.SpeechSynthesizeProtocolProfileID, EndpointProfileID: "alibaba_qwen3_tts", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, Revision: 1},
		{ID: provideralibaba.SpeechTranscribeActionBindingID, Operation: vcp.OperationSpeechTranscribe, DriverID: "alibaba", DriverVersion: "1", ProtocolProfileID: provideralibaba.SpeechTranscribeProtocolProfileID, EndpointProfileID: "alibaba_qwen3_asr", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, ResourceMaterialization: append([]providerconfig.ResourceMaterializationMode(nil), inputMaterializations...), Revision: 1},
		{ID: provideralibaba.SpeechTranscribeAsyncActionBindingID, Operation: vcp.OperationSpeechTranscribe, DriverID: "alibaba", DriverVersion: "1", ProtocolProfileID: provideralibaba.SpeechTranscribeAsyncProtocolProfileID, EndpointProfileID: "alibaba_fun_asr", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Asynchronous: true, Polling: true}, ResourceMaterialization: append([]providerconfig.ResourceMaterializationMode(nil), asynchronousInputMaterializations...), Revision: 1},
		{ID: provideralibaba.ImageGenerateActionBindingID, Operation: vcp.OperationImageGenerate, DriverID: "alibaba", DriverVersion: "1", ProtocolProfileID: provideralibaba.ImageGenerateProtocolProfileID, EndpointProfileID: "alibaba_qwen_image", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, Revision: 1},
		{ID: provideralibaba.ImageEditActionBindingID, Operation: vcp.OperationImageEdit, DriverID: "alibaba", DriverVersion: "1", ProtocolProfileID: provideralibaba.ImageEditProtocolProfileID, EndpointProfileID: "alibaba_qwen_image", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, ResourceMaterialization: append([]providerconfig.ResourceMaterializationMode(nil), inputMaterializations...), Revision: 1},
	}
	if definitionID == AlibabaModelStudioCNDefinitionID || definitionID == AlibabaModelStudioGlobalDefinitionID {
		definition.ActionBindings = append(definition.ActionBindings, providerconfig.ProviderActionBinding{
			ID: provideralibaba.MediaAnalyzeActionBindingID, Operation: vcp.OperationMediaAnalyze, DriverID: "alibaba", DriverVersion: "1",
			ProtocolProfileID: provideralibaba.MediaAnalyzeProtocolProfileID, EndpointProfileID: "alibaba_chat", AuthMethodIDs: []string{"api_key"},
			Delivery: providerconfig.ActionDeliveryModes{Streaming: true}, ResourceMaterialization: append([]providerconfig.ResourceMaterializationMode(nil), inputMaterializations...), Revision: 1,
		})
	}
	if definitionID == AlibabaModelStudioCNDefinitionID {
		definition.ActionBindings = append(definition.ActionBindings, alibabaHappyHorseActionBindings()...)
	}
	return definition
}

// alibabaHappyHorseActionBindings returns the two CN-only video actions proven by Bailian CLI and Token Plan dry-runs.
// alibabaHappyHorseActionBindings 返回由百炼 CLI 与 Token Plan Dry-run 证明的两个仅 CN 视频动作。
func alibabaHappyHorseActionBindings() []providerconfig.ProviderActionBinding {
	materializations := []providerconfig.ResourceMaterializationMode{providerconfig.ResourceMaterializationInline, providerconfig.ResourceMaterializationDirectURL, providerconfig.ResourceMaterializationObjectURI}
	return []providerconfig.ProviderActionBinding{
		{ID: provideralibaba.HappyHorseVideoGenerateActionBindingID, Operation: vcp.OperationVideoGenerate, DriverID: "alibaba", DriverVersion: "1", ProtocolProfileID: provideralibaba.HappyHorseVideoGenerateProtocolProfileID, EndpointProfileID: "alibaba_happyhorse_video", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Asynchronous: true, Polling: true, Cancellation: true}, ResourceMaterialization: append([]providerconfig.ResourceMaterializationMode(nil), materializations...), Revision: 1},
		{ID: provideralibaba.HappyHorseVideoEditActionBindingID, Operation: vcp.OperationVideoEdit, DriverID: "alibaba", DriverVersion: "1", ProtocolProfileID: provideralibaba.HappyHorseVideoEditProtocolProfileID, EndpointProfileID: "alibaba_happyhorse_video", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Asynchronous: true, Polling: true, Cancellation: true}, ResourceMaterialization: append([]providerconfig.ResourceMaterializationMode(nil), materializations...), Revision: 1},
	}
}

// alibabaHappyHorsePlanActionBindings returns the generation-only HappyHorse action owned by CN Token Plans.
// alibabaHappyHorsePlanActionBindings 返回中国站 Token Plan 拥有的仅生成 HappyHorse 动作。
func alibabaHappyHorsePlanActionBindings() []providerconfig.ProviderActionBinding {
	return alibabaHappyHorseActionBindings()[:1]
}

// alibabaQwenImageGenerateActionBinding returns the Qwen Image generation action published by Team Token Plans.
// alibabaQwenImageGenerateActionBinding 返回团队 Token Plan 发布的 Qwen Image 生成动作。
func alibabaQwenImageGenerateActionBinding() providerconfig.ProviderActionBinding {
	return providerconfig.ProviderActionBinding{
		ID: provideralibaba.ImageGenerateActionBindingID, Operation: vcp.OperationImageGenerate,
		DriverID: "alibaba", DriverVersion: "1", ProtocolProfileID: provideralibaba.ImageGenerateProtocolProfileID, EndpointProfileID: "alibaba_qwen_image",
		AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, Revision: 1,
	}
}

// alibabaWanImageGenerateActionBinding returns the Wan image generation action published by Token Plans.
// alibabaWanImageGenerateActionBinding 返回 Token Plan 发布的 Wan 图像生成动作。
func alibabaWanImageGenerateActionBinding() providerconfig.ProviderActionBinding {
	return providerconfig.ProviderActionBinding{
		ID: provideralibaba.WanImageGenerateActionBindingID, Operation: vcp.OperationImageGenerate,
		DriverID: "alibaba", DriverVersion: "1", ProtocolProfileID: provideralibaba.WanImageGenerateProtocolProfileID, EndpointProfileID: "alibaba_wan_image",
		AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true},
		ResourceMaterialization: []providerconfig.ResourceMaterializationMode{providerconfig.ResourceMaterializationInline, providerconfig.ResourceMaterializationDirectURL}, Revision: 1,
	}
}

// alibabaProviderDefinition builds one closed single-protocol system definition from explicit product facts.
// alibabaProviderDefinition 根据明确产品事实构建一个封闭的单协议系统定义。
func alibabaProviderDefinition(definitionID string, displayName string, variantName string, description string, descriptionKey string, catalogID string, endpointID string, baseURL string, region string, sortOrder int, apiKey providerconfig.AuthMethodDefinition, features providerconfig.ProviderFeatureSet) providerconfig.ProviderDefinition {
	definition := providerconfig.ProviderDefinition{
		ID: definitionID, Kind: providerconfig.DefinitionKindSystem, DisplayName: displayName,
		GroupID: AlibabaGroupID, VariantName: variantName, VariantDescription: description, VariantDescriptionKey: descriptionKey, ModelCatalogID: catalogID, SortOrder: sortOrder,
		DriverID: "alibaba", DriverVersion: "1", ConfigSchemaVersion: "1", ProtocolProfileID: protocolchat.ProfileID, EndpointProfileID: "alibaba_chat", AuthMethodIDs: []string{"api_key"}, Priority: 10, RuntimeReady: true,
		AuthMethods:     []providerconfig.AuthMethodDefinition{apiKey},
		EndpointPresets: []providerconfig.EndpointPreset{{ID: endpointID, BaseURL: baseURL, Region: region, UserEditable: false}},
		Features:        features, Revision: 1,
	}
	definition.ActionBindings = []providerconfig.ProviderActionBinding{{
		ID: ConversationActionBindingID, Operation: vcp.OperationConversationRespond,
		DriverID: definition.DriverID, DriverVersion: definition.DriverVersion, ProtocolProfileID: definition.ProtocolProfileID, EndpointProfileID: definition.EndpointProfileID,
		AuthMethodIDs: append([]string(nil), definition.AuthMethodIDs...), Delivery: providerconfig.ActionDeliveryModes{Synchronous: true, Streaming: true}, Revision: definition.Revision,
	}}
	return definition
}
