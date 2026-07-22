package bootstrap

import (
	"fmt"

	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	providerminimax "github.com/OpenVulcan/vulcan-model-core/internal/provider/minimax"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

const (
	// MiniMaxGroupID identifies the MiniMax provider family.
	// MiniMaxGroupID 标识 MiniMax 供应商系列。
	MiniMaxGroupID = "minimax"
	// MiniMaxAPIDefinitionID identifies the global MiniMax API product.
	// MiniMaxAPIDefinitionID 标识全球 MiniMax API 产品。
	MiniMaxAPIDefinitionID = MiniMaxGlobalDefinitionID
	// MiniMaxGlobalDefinitionID identifies the explicit MiniMax Global API variant while preserving the historical identifier.
	// MiniMaxGlobalDefinitionID 标识显式 MiniMax Global API 变体，同时保留历史标识。
	MiniMaxGlobalDefinitionID = "system_minimax_api"
	// MiniMaxCNDefinitionID identifies the explicit MiniMax CN API variant.
	// MiniMaxCNDefinitionID 标识显式 MiniMax CN API 变体。
	MiniMaxCNDefinitionID = "system_minimax_cn"
)

// registerMiniMaxProviderCatalog registers explicit Global and CN MiniMax products without API-key region probing.
// registerMiniMaxProviderCatalog 注册显式 Global 与 CN MiniMax 产品且不探测 API Key 区域。
func registerMiniMaxProviderCatalog(registry *providerconfig.SystemRegistry) error {
	if errGroup := registry.RegisterGroup(providerconfig.ProviderGroup{ID: MiniMaxGroupID, DisplayName: "MiniMax", Description: "MiniMax multimodal API services across explicit Global and CN sites.", DescriptionKey: "providers.minimax.description", SortOrder: 80, Revision: 2}); errGroup != nil {
		return fmt.Errorf("register MiniMax provider group: %w", errGroup)
	}
	// auth describes raw API keys that remain bound to the operator-selected regional variant.
	// auth 描述始终绑定到操作员所选区域变体的原始 API Key。
	auth := providerconfig.AuthMethodDefinition{ID: "api_key", Type: providerconfig.AuthMethodAPIKey, MultipleCredentials: true, PlanAcquisition: providerconfig.PlanAcquisitionUnavailable}
	// deviceFlow is region-specific and obtains quota from the same selected API Origin without region probing.
	// deviceFlow 按区域区分，并从同一个所选 API Origin 获取额度且不探测区域。
	deviceFlow := providerconfig.AuthMethodDefinition{ID: "device_flow", Type: providerconfig.AuthMethodDeviceFlow, Refreshable: true, MultipleCredentials: true, PlanAcquisition: providerconfig.PlanAcquisitionUnavailable}
	features := providerconfig.ProviderFeatureSet{ModelDiscovery: providerconfig.SupportUnsupported, PlanReader: providerconfig.SupportUnsupported, EntitlementReader: providerconfig.SupportUnsupported, AllowanceReader: providerconfig.SupportSupported}
	definitions := []providerconfig.ProviderDefinition{
		miniMaxProviderDefinition(MiniMaxGlobalDefinitionID, "MiniMax Global", "Global", "MiniMax Global multimodal API services.", "providers.minimax.globalDescription", 10, "https://api.minimax.io", "Global", []providerconfig.AuthMethodDefinition{auth, deviceFlow}, features),
		miniMaxProviderDefinition(MiniMaxCNDefinitionID, "MiniMax CN", "CN", "MiniMax CN multimodal API services.", "providers.minimax.cnDescription", 20, "https://api.minimaxi.com", "CN", []providerconfig.AuthMethodDefinition{auth, deviceFlow}, features),
	}
	for _, definition := range definitions {
		if errRegister := registry.Register(definition); errRegister != nil {
			return fmt.Errorf("register MiniMax provider definition %s: %w", definition.ID, errRegister)
		}
	}
	return nil
}

// miniMaxProviderDefinition constructs one region-fixed MiniMax system definition with the current native action set.
// miniMaxProviderDefinition 构造一个区域固定且包含当前原生动作集合的 MiniMax 系统定义。
func miniMaxProviderDefinition(definitionID string, displayName string, variantName string, description string, descriptionKey string, sortOrder int, baseURL string, region string, authMethods []providerconfig.AuthMethodDefinition, features providerconfig.ProviderFeatureSet) providerconfig.ProviderDefinition {
	definition := providerDefinition(definitionID, displayName, MiniMaxGroupID, variantName, description, descriptionKey, "minimax_api", sortOrder, "minimax", providerminimax.ImageGenerateProtocolProfileID, "minimax_image", baseURL, true, authMethods, features)
	definition.EndpointPresets[0].Region = region
	definition.ActionBindings = miniMaxActionBindings([]string{"api_key", "device_flow"})
	definition.Revision = 2
	return definition
}

// miniMaxActionBindings returns copied action declarations for one exact Definition auth set.
// miniMaxActionBindings 为一个精确 Definition 认证集合返回复制后的动作声明。
func miniMaxActionBindings(authMethodIDs []string) []providerconfig.ProviderActionBinding {
	return []providerconfig.ProviderActionBinding{
		{ID: providerminimax.ConversationRespondActionBindingID, Operation: vcp.OperationConversationRespond, DriverID: "minimax", DriverVersion: "1", ProtocolProfileID: "anthropic.messages", EndpointProfileID: "minimax_messages", AuthMethodIDs: append([]string(nil), authMethodIDs...), Delivery: providerconfig.ActionDeliveryModes{Synchronous: true, Streaming: true}, Revision: 1},
		{ID: providerminimax.MediaAnalyzeActionBindingID, Operation: vcp.OperationMediaAnalyze, DriverID: "minimax", DriverVersion: "1", ProtocolProfileID: providerminimax.MediaAnalyzeProtocolProfileID, EndpointProfileID: "minimax_vlm", AuthMethodIDs: append([]string(nil), authMethodIDs...), Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, ResourceMaterialization: []providerconfig.ResourceMaterializationMode{providerconfig.ResourceMaterializationInline}, Revision: 1},
		{ID: providerminimax.SearchWebActionBindingID, Operation: vcp.OperationSearchWeb, DriverID: "minimax", DriverVersion: "1", ProtocolProfileID: providerminimax.SearchWebProtocolProfileID, EndpointProfileID: "minimax_search", AuthMethodIDs: append([]string(nil), authMethodIDs...), Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, Search: &providerconfig.SearchActionBinding{BackendKind: vcp.SearchBackendDirectAPI}, Revision: 1},
		{ID: providerminimax.ImageGenerateActionBindingID, Operation: vcp.OperationImageGenerate, DriverID: "minimax", DriverVersion: "1", ProtocolProfileID: providerminimax.ImageGenerateProtocolProfileID, EndpointProfileID: "minimax_image", AuthMethodIDs: append([]string(nil), authMethodIDs...), Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, ResourceMaterialization: []providerconfig.ResourceMaterializationMode{providerconfig.ResourceMaterializationInline, providerconfig.ResourceMaterializationDirectURL}, Revision: 1},
		{ID: providerminimax.VideoGenerateActionBindingID, Operation: vcp.OperationVideoGenerate, DriverID: "minimax", DriverVersion: "1", ProtocolProfileID: providerminimax.VideoGenerateProtocolProfileID, EndpointProfileID: "minimax_video", AuthMethodIDs: append([]string(nil), authMethodIDs...), Delivery: providerconfig.ActionDeliveryModes{Asynchronous: true, Polling: true}, ResourceMaterialization: []providerconfig.ResourceMaterializationMode{providerconfig.ResourceMaterializationInline, providerconfig.ResourceMaterializationDirectURL}, Revision: 1},
		{ID: providerminimax.SpeechSynthesizeActionBindingID, Operation: vcp.OperationSpeechSynthesize, DriverID: "minimax", DriverVersion: "1", ProtocolProfileID: providerminimax.SpeechSynthesizeProtocolProfileID, EndpointProfileID: "minimax_speech", AuthMethodIDs: append([]string(nil), authMethodIDs...), Delivery: providerconfig.ActionDeliveryModes{Synchronous: true, Streaming: true}, Revision: 1},
		{ID: providerminimax.SpeechSynthesizeAsyncActionBindingID, Operation: vcp.OperationSpeechSynthesize, DriverID: "minimax", DriverVersion: "1", ProtocolProfileID: providerminimax.SpeechSynthesizeAsyncProtocolProfileID, EndpointProfileID: "minimax_speech_async", AuthMethodIDs: append([]string(nil), authMethodIDs...), Delivery: providerconfig.ActionDeliveryModes{Asynchronous: true, Polling: true}, Revision: 1},
		{ID: providerminimax.MusicGenerateActionBindingID, Operation: vcp.OperationMusicGenerate, DriverID: "minimax", DriverVersion: "1", ProtocolProfileID: providerminimax.MusicGenerateProtocolProfileID, EndpointProfileID: "minimax_music", AuthMethodIDs: append([]string(nil), authMethodIDs...), Delivery: providerconfig.ActionDeliveryModes{Synchronous: true, Streaming: true}, Revision: 1},
		{ID: providerminimax.MusicCoverPrepareActionBindingID, Operation: vcp.OperationMusicCoverPrepare, DriverID: "minimax", DriverVersion: "1", ProtocolProfileID: providerminimax.MusicCoverPrepareProtocolProfileID, EndpointProfileID: "minimax_music", AuthMethodIDs: append([]string(nil), authMethodIDs...), Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, ResourceMaterialization: []providerconfig.ResourceMaterializationMode{providerconfig.ResourceMaterializationInline, providerconfig.ResourceMaterializationDirectURL}, Revision: 1},
		{ID: providerminimax.MusicCoverActionBindingID, Operation: vcp.OperationMusicCover, DriverID: "minimax", DriverVersion: "1", ProtocolProfileID: providerminimax.MusicCoverProtocolProfileID, EndpointProfileID: "minimax_music", AuthMethodIDs: append([]string(nil), authMethodIDs...), Delivery: providerconfig.ActionDeliveryModes{Synchronous: true, Streaming: true}, Revision: 1},
	}
}

// RegisterMiniMaxExecutionDrivers binds every implemented MiniMax action independently to both fixed regional definitions.
// RegisterMiniMaxExecutionDrivers 将每个已实现 MiniMax 动作独立绑定到两个固定区域 Definition。
func RegisterMiniMaxExecutionDrivers(registry *provider.ExecutionRegistry, client *transport.Client) error {
	if registry == nil || client == nil {
		return fmt.Errorf("MiniMax execution registry and transport client are required")
	}
	for _, definitionID := range []string{MiniMaxGlobalDefinitionID, MiniMaxCNDefinitionID} {
		if errRegister := registerMiniMaxDefinitionDrivers(registry, client, definitionID); errRegister != nil {
			return errRegister
		}
	}
	return nil
}

// registerMiniMaxDefinitionDrivers binds all current MiniMax native actions to one exact region-fixed Definition.
// registerMiniMaxDefinitionDrivers 将全部当前 MiniMax 原生动作绑定到一个精确且区域固定的 Definition。
func registerMiniMaxDefinitionDrivers(registry *provider.ExecutionRegistry, client *transport.Client, definitionID string) error {
	messagesDriver, errMessagesDriver := providerminimax.NewMessagesDriver(definitionID, client, anthropicMessagesCapabilities(), []providerconfig.AuthMethodType{providerconfig.AuthMethodAPIKey, providerconfig.AuthMethodDeviceFlow})
	if errMessagesDriver != nil {
		return fmt.Errorf("create MiniMax Messages driver: %w", errMessagesDriver)
	}
	if errRegister := registerConversationDriver(registry, messagesDriver); errRegister != nil {
		return fmt.Errorf("register MiniMax Messages driver: %w", errRegister)
	}
	visionDriver, errVisionDriver := providerminimax.NewVisionDriver(definitionID, client)
	if errVisionDriver != nil {
		return fmt.Errorf("create MiniMax VLM driver: %w", errVisionDriver)
	}
	if errRegister := registry.RegisterAction(visionDriver); errRegister != nil {
		return fmt.Errorf("register MiniMax VLM driver: %w", errRegister)
	}
	searchDriver, errSearchDriver := providerminimax.NewSearchDriver(definitionID, client)
	if errSearchDriver != nil {
		return fmt.Errorf("create MiniMax search driver: %w", errSearchDriver)
	}
	if errRegister := registry.RegisterAction(searchDriver); errRegister != nil {
		return fmt.Errorf("register MiniMax search driver: %w", errRegister)
	}
	driver, errDriver := providerminimax.NewImageActionDriver(definitionID, client)
	if errDriver != nil {
		return fmt.Errorf("create MiniMax image driver: %w", errDriver)
	}
	if errRegister := registry.RegisterAction(driver); errRegister != nil {
		return fmt.Errorf("register MiniMax image driver: %w", errRegister)
	}
	videoDriver, errVideoDriver := providerminimax.NewVideoTaskDriver(definitionID, client)
	if errVideoDriver != nil {
		return fmt.Errorf("create MiniMax video driver: %w", errVideoDriver)
	}
	if errRegister := registry.RegisterTaskAction(videoDriver); errRegister != nil {
		return fmt.Errorf("register MiniMax video driver: %w", errRegister)
	}
	speechDriver, errSpeechDriver := providerminimax.NewSpeechActionDriver(definitionID, client)
	if errSpeechDriver != nil {
		return fmt.Errorf("create MiniMax speech driver: %w", errSpeechDriver)
	}
	if errRegister := registry.RegisterAction(speechDriver); errRegister != nil {
		return fmt.Errorf("register MiniMax speech driver: %w", errRegister)
	}
	speechTaskDriver, errSpeechTaskDriver := providerminimax.NewSpeechTaskDriver(definitionID, client)
	if errSpeechTaskDriver != nil {
		return fmt.Errorf("create MiniMax asynchronous speech driver: %w", errSpeechTaskDriver)
	}
	if errRegister := registry.RegisterTaskAction(speechTaskDriver); errRegister != nil {
		return fmt.Errorf("register MiniMax asynchronous speech driver: %w", errRegister)
	}
	for _, bindingID := range []string{providerminimax.MusicGenerateActionBindingID, providerminimax.MusicCoverPrepareActionBindingID, providerminimax.MusicCoverActionBindingID} {
		musicDriver, errMusicDriver := providerminimax.NewMusicActionDriver(definitionID, bindingID, client)
		if errMusicDriver != nil {
			return fmt.Errorf("create MiniMax music driver %q: %w", bindingID, errMusicDriver)
		}
		if errRegister := registry.RegisterAction(musicDriver); errRegister != nil {
			return fmt.Errorf("register MiniMax music driver %q: %w", bindingID, errRegister)
		}
	}
	return nil
}
