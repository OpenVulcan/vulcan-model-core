package bootstrap

import (
	"fmt"

	"github.com/OpenVulcan/vulcan-model-core/internal/dependency"
	protocolmessages "github.com/OpenVulcan/vulcan-model-core/internal/protocol/anthropic/messages"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	provideralibaba "github.com/OpenVulcan/vulcan-model-core/internal/provider/alibaba"
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
	// AlibabaModelStudioWorkspaceGlobalDefinitionID identifies the Singapore workspace-scoped Model Studio API.
	// AlibabaModelStudioWorkspaceGlobalDefinitionID 标识新加坡工作空间作用域的百炼 API。
	AlibabaModelStudioWorkspaceGlobalDefinitionID = "system_alibaba_model_studio_workspace_global"
)

// registerAlibabaProviderCatalog registers Alibaba's immutable plan products and exact regional boundaries.
// registerAlibabaProviderCatalog 注册阿里云不可变套餐产品及精确区域边界。
func registerAlibabaProviderCatalog(registry *providerconfig.SystemRegistry) error {
	if errGroup := registry.RegisterGroup(providerconfig.ProviderGroup{
		ID:             AlibabaGroupID,
		DisplayName:    "Alibaba Cloud Model Studio",
		Description:    "Alibaba Cloud Model Studio coding subscriptions across CN and Global sites.",
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
	for _, definitionID := range []string{
		AlibabaCodingPlanCNDefinitionID,
		AlibabaCodingPlanGlobalDefinitionID,
		AlibabaTokenPlanPersonalCNDefinitionID,
		AlibabaTokenPlanTeamCNDefinitionID,
		AlibabaTokenPlanTeamGlobalDefinitionID,
	} {
		driver, errDriver := provideralibaba.NewMessagesDriver(definitionID, client, responsesCapabilities())
		if errDriver != nil {
			return fmt.Errorf("create Alibaba Messages driver %s: %w", definitionID, errDriver)
		}
		if errRegister := registerConversationDriver(registry, driver); errRegister != nil {
			return fmt.Errorf("register Alibaba Messages driver %s: %w", definitionID, errRegister)
		}
	}
	for _, definitionID := range []string{AlibabaModelStudioCNDefinitionID, AlibabaModelStudioGlobalDefinitionID, AlibabaModelStudioWorkspaceGlobalDefinitionID} {
		driver, errDriver := provideralibaba.NewEmbeddingDriver(definitionID, client)
		if errDriver != nil {
			return fmt.Errorf("create Alibaba embedding driver %s: %w", definitionID, errDriver)
		}
		if errRegister := registry.RegisterAction(driver); errRegister != nil {
			return fmt.Errorf("register Alibaba embedding driver %s: %w", definitionID, errRegister)
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
		if definitionID == AlibabaModelStudioWorkspaceGlobalDefinitionID {
			for _, actionBindingID := range []string{provideralibaba.WanImageGenerateActionBindingID, provideralibaba.WanImageEditActionBindingID} {
				wanDriver, errWanDriver := provideralibaba.NewWanImageActionDriver(definitionID, actionBindingID, client)
				if errWanDriver != nil {
					return fmt.Errorf("create Alibaba Wan image driver %s/%s: %w", definitionID, actionBindingID, errWanDriver)
				}
				if errRegister := registry.RegisterAction(wanDriver); errRegister != nil {
					return fmt.Errorf("register Alibaba Wan image driver %s/%s: %w", definitionID, actionBindingID, errRegister)
				}
			}
			videoDriver, errVideoDriver := provideralibaba.NewWanVideoTaskDriver(definitionID, client)
			if errVideoDriver != nil {
				return fmt.Errorf("create Alibaba Wan video driver %s: %w", definitionID, errVideoDriver)
			}
			if errRegister := registry.RegisterTaskAction(videoDriver); errRegister != nil {
				return fmt.Errorf("register Alibaba Wan video driver %s: %w", definitionID, errRegister)
			}
		}
	}
	return nil
}

// alibabaProviderDefinitions returns five immutable subscription and region boundaries.
// alibabaProviderDefinitions 返回五个不可变订阅产品及区域边界。
func alibabaProviderDefinitions() []providerconfig.ProviderDefinition {
	// apiKey is the only documented credential mechanism for Alibaba coding plans.
	// apiKey 是阿里云编码套餐唯一有文档依据的凭据机制。
	apiKey := providerconfig.AuthMethodDefinition{ID: "api_key", Type: providerconfig.AuthMethodAPIKey, MultipleCredentials: true}
	// unsupportedFeatures prevents unimplemented console-only metadata from appearing available.
	// unsupportedFeatures 防止尚未实现的控制台专属元数据被声明为可用。
	unsupportedFeatures := providerconfig.ProviderFeatureSet{
		ModelDiscovery:    providerconfig.SupportUnsupported,
		PlanReader:        providerconfig.SupportUnsupported,
		EntitlementReader: providerconfig.SupportUnsupported,
		AllowanceReader:   providerconfig.SupportUnsupported,
	}
	definitions := []providerconfig.ProviderDefinition{
		alibabaProviderDefinition(AlibabaCodingPlanCNDefinitionID, "Alibaba Coding Plan CN", "Coding Plan CN", "Alibaba Coding Plan service hosted at the CN site.", "providers.alibaba.codingPlanCNDescription", "alibaba_coding_plan_cn", "coding_plan_cn", "https://coding.dashscope.aliyuncs.com/apps/anthropic/v1", "CN", 10, apiKey, unsupportedFeatures),
		alibabaProviderDefinition(AlibabaCodingPlanGlobalDefinitionID, "Alibaba Coding Plan Global", "Coding Plan Global", "Alibaba Coding Plan service hosted at the Global site.", "providers.alibaba.codingPlanGlobalDescription", "alibaba_coding_plan_global", "coding_plan_global", "https://coding-intl.dashscope.aliyuncs.com/apps/anthropic/v1", "Global", 20, apiKey, unsupportedFeatures),
		alibabaProviderDefinition(AlibabaTokenPlanPersonalCNDefinitionID, "Alibaba Token Plan Personal CN", "Token Plan Personal CN", "Personal Token Plan service hosted at the CN site.", "providers.alibaba.tokenPlanPersonalCNDescription", "alibaba_token_plan_personal_cn", "token_plan_personal_cn", "https://token-plan.cn-beijing.maas.aliyuncs.com/apps/anthropic/v1", "CN", 30, apiKey, unsupportedFeatures),
		alibabaProviderDefinition(AlibabaTokenPlanTeamCNDefinitionID, "Alibaba Token Plan Team CN", "Token Plan Team CN", "Team Token Plan service hosted at the CN site.", "providers.alibaba.tokenPlanTeamCNDescription", "alibaba_token_plan_team_cn", "token_plan_team_cn", "https://token-plan.cn-beijing.maas.aliyuncs.com/apps/anthropic/v1", "CN", 40, apiKey, unsupportedFeatures),
		alibabaProviderDefinition(AlibabaTokenPlanTeamGlobalDefinitionID, "Alibaba Token Plan Team Global", "Token Plan Team Global", "Team Token Plan service hosted at the Global site.", "providers.alibaba.tokenPlanTeamGlobalDescription", "alibaba_token_plan_team_global", "token_plan_team_global", "https://token-plan.ap-southeast-1.maas.aliyuncs.com/apps/anthropic/v1", "Global", 50, apiKey, unsupportedFeatures),
	}
	definitions = append(definitions,
		alibabaEmbeddingProviderDefinition(AlibabaModelStudioCNDefinitionID, "Alibaba Model Studio CN", "Model Studio CN", "Alibaba Model Studio compatible embedding API hosted at the CN site.", "providers.alibaba.modelStudioCNDescription", "alibaba_model_studio_cn", providerconfig.EndpointPreset{ID: "model_studio_cn", BaseURL: "https://dashscope.aliyuncs.com", Region: "CN"}, 60, apiKey, unsupportedFeatures),
		alibabaEmbeddingProviderDefinition(AlibabaModelStudioGlobalDefinitionID, "Alibaba Model Studio Global", "Model Studio Global", "Alibaba Model Studio compatible embedding API hosted at the Global site.", "providers.alibaba.modelStudioGlobalDescription", "alibaba_model_studio_global", providerconfig.EndpointPreset{ID: "model_studio_global", BaseURL: "https://dashscope-intl.aliyuncs.com", Region: "Global"}, 70, apiKey, unsupportedFeatures),
		alibabaEmbeddingProviderDefinition(AlibabaModelStudioWorkspaceGlobalDefinitionID, "Alibaba Model Studio Workspace Global", "Model Studio Workspace Global", "Alibaba Model Studio API hosted in Singapore and isolated by workspace ID.", "providers.alibaba.modelStudioWorkspaceGlobalDescription", "alibaba_model_studio_workspace_global", providerconfig.EndpointPreset{ID: "model_studio_workspace_global", Region: "Global", BaseURLTemplate: "https://{workspace_id}.ap-southeast-1.maas.aliyuncs.com", Parameters: []providerconfig.EndpointParameterDefinition{{ID: "workspace_id", Kind: providerconfig.EndpointParameterHostnameLabel, Required: true}}}, 80, apiKey, unsupportedFeatures),
	)
	return definitions
}

// alibabaEmbeddingProviderDefinition builds one fixed regional compatible embedding definition.
// alibabaEmbeddingProviderDefinition 构建一个固定区域兼容 Embedding 定义。
func alibabaEmbeddingProviderDefinition(definitionID string, displayName string, variantName string, description string, descriptionKey string, catalogID string, endpoint providerconfig.EndpointPreset, sortOrder int, apiKey providerconfig.AuthMethodDefinition, features providerconfig.ProviderFeatureSet) providerconfig.ProviderDefinition {
	definition := providerconfig.ProviderDefinition{
		ID: definitionID, Kind: providerconfig.DefinitionKindSystem, DisplayName: displayName,
		GroupID: AlibabaGroupID, VariantName: variantName, VariantDescription: description, VariantDescriptionKey: descriptionKey, ModelCatalogID: catalogID, SortOrder: sortOrder,
		DriverID: "alibaba", DriverVersion: "1", ConfigSchemaVersion: "1", ProtocolProfileID: provideralibaba.EmbeddingProtocolProfileID, EndpointProfileID: "alibaba_model_studio_embeddings", AuthMethodIDs: []string{"api_key"}, Priority: 10, RuntimeReady: true,
		AuthMethods: []providerconfig.AuthMethodDefinition{apiKey}, EndpointPresets: []providerconfig.EndpointPreset{endpoint}, Features: features, Revision: 1,
	}
	definition.ActionBindings = []providerconfig.ProviderActionBinding{
		{ID: provideralibaba.EmbeddingActionBindingID, Operation: vcp.OperationEmbeddingCreate, DriverID: "alibaba", DriverVersion: "1", ProtocolProfileID: provideralibaba.EmbeddingProtocolProfileID, EndpointProfileID: "alibaba_model_studio_embeddings", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, Revision: 1},
		{ID: provideralibaba.SpeechSynthesizeActionBindingID, Operation: vcp.OperationSpeechSynthesize, DriverID: "alibaba", DriverVersion: "1", ProtocolProfileID: provideralibaba.SpeechSynthesizeProtocolProfileID, EndpointProfileID: "alibaba_qwen3_tts", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, Revision: 1},
		{ID: provideralibaba.SpeechTranscribeActionBindingID, Operation: vcp.OperationSpeechTranscribe, DriverID: "alibaba", DriverVersion: "1", ProtocolProfileID: provideralibaba.SpeechTranscribeProtocolProfileID, EndpointProfileID: "alibaba_qwen3_asr", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, ResourceMaterialization: []providerconfig.ResourceMaterializationMode{providerconfig.ResourceMaterializationInline, providerconfig.ResourceMaterializationDirectURL}, Revision: 1},
		{ID: provideralibaba.SpeechTranscribeAsyncActionBindingID, Operation: vcp.OperationSpeechTranscribe, DriverID: "alibaba", DriverVersion: "1", ProtocolProfileID: provideralibaba.SpeechTranscribeAsyncProtocolProfileID, EndpointProfileID: "alibaba_fun_asr", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Asynchronous: true, Polling: true}, ResourceMaterialization: []providerconfig.ResourceMaterializationMode{providerconfig.ResourceMaterializationDirectURL}, Revision: 1},
		{ID: provideralibaba.ImageGenerateActionBindingID, Operation: vcp.OperationImageGenerate, DriverID: "alibaba", DriverVersion: "1", ProtocolProfileID: provideralibaba.ImageGenerateProtocolProfileID, EndpointProfileID: "alibaba_qwen_image", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, Revision: 1},
		{ID: provideralibaba.ImageEditActionBindingID, Operation: vcp.OperationImageEdit, DriverID: "alibaba", DriverVersion: "1", ProtocolProfileID: provideralibaba.ImageEditProtocolProfileID, EndpointProfileID: "alibaba_qwen_image", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, ResourceMaterialization: []providerconfig.ResourceMaterializationMode{providerconfig.ResourceMaterializationInline, providerconfig.ResourceMaterializationDirectURL}, Revision: 1},
	}
	if definitionID == AlibabaModelStudioWorkspaceGlobalDefinitionID {
		definition.ActionBindings = append(definition.ActionBindings,
			providerconfig.ProviderActionBinding{ID: provideralibaba.WanImageGenerateActionBindingID, Operation: vcp.OperationImageGenerate, DriverID: "alibaba", DriverVersion: "1", ProtocolProfileID: provideralibaba.WanImageGenerateProtocolProfileID, EndpointProfileID: "alibaba_wan_image", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, ResourceMaterialization: []providerconfig.ResourceMaterializationMode{providerconfig.ResourceMaterializationInline, providerconfig.ResourceMaterializationDirectURL}, Revision: 1},
			providerconfig.ProviderActionBinding{ID: provideralibaba.WanImageEditActionBindingID, Operation: vcp.OperationImageEdit, DriverID: "alibaba", DriverVersion: "1", ProtocolProfileID: provideralibaba.WanImageEditProtocolProfileID, EndpointProfileID: "alibaba_wan_image", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, ResourceMaterialization: []providerconfig.ResourceMaterializationMode{providerconfig.ResourceMaterializationInline, providerconfig.ResourceMaterializationDirectURL}, Revision: 1},
			providerconfig.ProviderActionBinding{ID: provideralibaba.WanVideoGenerateActionBindingID, Operation: vcp.OperationVideoGenerate, DriverID: "alibaba", DriverVersion: "1", ProtocolProfileID: provideralibaba.WanVideoGenerateProtocolProfileID, EndpointProfileID: "alibaba_wan_video", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Asynchronous: true, Polling: true, Cancellation: true}, ResourceMaterialization: []providerconfig.ResourceMaterializationMode{providerconfig.ResourceMaterializationInline, providerconfig.ResourceMaterializationDirectURL}, Revision: 1},
		)
	}
	return definition
}

// alibabaProviderDefinition builds one closed single-protocol system definition from explicit product facts.
// alibabaProviderDefinition 根据明确产品事实构建一个封闭的单协议系统定义。
func alibabaProviderDefinition(definitionID string, displayName string, variantName string, description string, descriptionKey string, catalogID string, endpointID string, baseURL string, region string, sortOrder int, apiKey providerconfig.AuthMethodDefinition, features providerconfig.ProviderFeatureSet) providerconfig.ProviderDefinition {
	definition := providerconfig.ProviderDefinition{
		ID: definitionID, Kind: providerconfig.DefinitionKindSystem, DisplayName: displayName,
		GroupID: AlibabaGroupID, VariantName: variantName, VariantDescription: description, VariantDescriptionKey: descriptionKey, ModelCatalogID: catalogID, SortOrder: sortOrder,
		DriverID: "alibaba", DriverVersion: "1", ConfigSchemaVersion: "1", ProtocolProfileID: protocolmessages.ProfileID, EndpointProfileID: "alibaba_messages", AuthMethodIDs: []string{"api_key"}, Priority: 10, RuntimeReady: true,
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
