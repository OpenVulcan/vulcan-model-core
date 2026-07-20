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
	MiniMaxAPIDefinitionID = "system_minimax_api"
)

// registerMiniMaxProviderCatalog registers the official global MiniMax image, video, speech, and music product.
// registerMiniMaxProviderCatalog 注册官方全球 MiniMax 图片、视频、语音与音乐产品。
func registerMiniMaxProviderCatalog(registry *providerconfig.SystemRegistry) error {
	if errGroup := registry.RegisterGroup(providerconfig.ProviderGroup{ID: MiniMaxGroupID, DisplayName: "MiniMax", Description: "MiniMax global multimodal API services.", DescriptionKey: "providers.minimax.description", SortOrder: 80, Revision: 1}); errGroup != nil {
		return fmt.Errorf("register MiniMax provider group: %w", errGroup)
	}
	auth := providerconfig.AuthMethodDefinition{ID: "api_key", Type: providerconfig.AuthMethodAPIKey, MultipleCredentials: true}
	features := providerconfig.ProviderFeatureSet{ModelDiscovery: providerconfig.SupportUnsupported, PlanReader: providerconfig.SupportUnsupported, EntitlementReader: providerconfig.SupportUnsupported, AllowanceReader: providerconfig.SupportUnsupported}
	definition := providerDefinition(MiniMaxAPIDefinitionID, "MiniMax API", MiniMaxGroupID, "Global API", "MiniMax global API with native image, video, music, and non-realtime speech generation.", "providers.minimax.apiDescription", "minimax_api", 10, "minimax", providerminimax.ImageGenerateProtocolProfileID, "minimax_image", "https://api.minimax.io", true, []providerconfig.AuthMethodDefinition{auth}, features)
	definition.ActionBindings = []providerconfig.ProviderActionBinding{
		{ID: providerminimax.ImageGenerateActionBindingID, Operation: vcp.OperationImageGenerate, DriverID: "minimax", DriverVersion: "1", ProtocolProfileID: providerminimax.ImageGenerateProtocolProfileID, EndpointProfileID: "minimax_image", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, ResourceMaterialization: []providerconfig.ResourceMaterializationMode{providerconfig.ResourceMaterializationDirectURL}, Revision: 1},
		{ID: providerminimax.VideoGenerateActionBindingID, Operation: vcp.OperationVideoGenerate, DriverID: "minimax", DriverVersion: "1", ProtocolProfileID: providerminimax.VideoGenerateProtocolProfileID, EndpointProfileID: "minimax_video", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Asynchronous: true, Polling: true}, ResourceMaterialization: []providerconfig.ResourceMaterializationMode{providerconfig.ResourceMaterializationInline, providerconfig.ResourceMaterializationDirectURL}, Revision: 1},
		{ID: providerminimax.SpeechSynthesizeActionBindingID, Operation: vcp.OperationSpeechSynthesize, DriverID: "minimax", DriverVersion: "1", ProtocolProfileID: providerminimax.SpeechSynthesizeProtocolProfileID, EndpointProfileID: "minimax_speech", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, Revision: 1},
		{ID: providerminimax.SpeechSynthesizeAsyncActionBindingID, Operation: vcp.OperationSpeechSynthesize, DriverID: "minimax", DriverVersion: "1", ProtocolProfileID: providerminimax.SpeechSynthesizeAsyncProtocolProfileID, EndpointProfileID: "minimax_speech_async", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Asynchronous: true, Polling: true}, Revision: 1},
		{ID: providerminimax.MusicGenerateActionBindingID, Operation: vcp.OperationMusicGenerate, DriverID: "minimax", DriverVersion: "1", ProtocolProfileID: providerminimax.MusicGenerateProtocolProfileID, EndpointProfileID: "minimax_music", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, Revision: 1},
		{ID: providerminimax.MusicCoverPrepareActionBindingID, Operation: vcp.OperationMusicCoverPrepare, DriverID: "minimax", DriverVersion: "1", ProtocolProfileID: providerminimax.MusicCoverPrepareProtocolProfileID, EndpointProfileID: "minimax_music", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, ResourceMaterialization: []providerconfig.ResourceMaterializationMode{providerconfig.ResourceMaterializationInline, providerconfig.ResourceMaterializationDirectURL}, Revision: 1},
		{ID: providerminimax.MusicCoverActionBindingID, Operation: vcp.OperationMusicCover, DriverID: "minimax", DriverVersion: "1", ProtocolProfileID: providerminimax.MusicCoverProtocolProfileID, EndpointProfileID: "minimax_music", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, Revision: 1},
	}
	if errRegister := registry.Register(definition); errRegister != nil {
		return fmt.Errorf("register MiniMax provider definition: %w", errRegister)
	}
	return nil
}

// RegisterMiniMaxExecutionDrivers binds every implemented MiniMax image, video, speech, music, and cover action to its exact definition.
// RegisterMiniMaxExecutionDrivers 将每个已实现的 MiniMax 图片、视频、语音、音乐与翻唱动作绑定到其精确 Definition。
func RegisterMiniMaxExecutionDrivers(registry *provider.ExecutionRegistry, client *transport.Client) error {
	if registry == nil || client == nil {
		return fmt.Errorf("MiniMax execution registry and transport client are required")
	}
	driver, errDriver := providerminimax.NewImageActionDriver(MiniMaxAPIDefinitionID, client)
	if errDriver != nil {
		return fmt.Errorf("create MiniMax image driver: %w", errDriver)
	}
	if errRegister := registry.RegisterAction(driver); errRegister != nil {
		return fmt.Errorf("register MiniMax image driver: %w", errRegister)
	}
	videoDriver, errVideoDriver := providerminimax.NewVideoTaskDriver(MiniMaxAPIDefinitionID, client)
	if errVideoDriver != nil {
		return fmt.Errorf("create MiniMax video driver: %w", errVideoDriver)
	}
	if errRegister := registry.RegisterTaskAction(videoDriver); errRegister != nil {
		return fmt.Errorf("register MiniMax video driver: %w", errRegister)
	}
	speechDriver, errSpeechDriver := providerminimax.NewSpeechActionDriver(MiniMaxAPIDefinitionID, client)
	if errSpeechDriver != nil {
		return fmt.Errorf("create MiniMax speech driver: %w", errSpeechDriver)
	}
	if errRegister := registry.RegisterAction(speechDriver); errRegister != nil {
		return fmt.Errorf("register MiniMax speech driver: %w", errRegister)
	}
	speechTaskDriver, errSpeechTaskDriver := providerminimax.NewSpeechTaskDriver(MiniMaxAPIDefinitionID, client)
	if errSpeechTaskDriver != nil {
		return fmt.Errorf("create MiniMax asynchronous speech driver: %w", errSpeechTaskDriver)
	}
	if errRegister := registry.RegisterTaskAction(speechTaskDriver); errRegister != nil {
		return fmt.Errorf("register MiniMax asynchronous speech driver: %w", errRegister)
	}
	for _, bindingID := range []string{providerminimax.MusicGenerateActionBindingID, providerminimax.MusicCoverPrepareActionBindingID, providerminimax.MusicCoverActionBindingID} {
		musicDriver, errMusicDriver := providerminimax.NewMusicActionDriver(MiniMaxAPIDefinitionID, bindingID, client)
		if errMusicDriver != nil {
			return fmt.Errorf("create MiniMax music driver %q: %w", bindingID, errMusicDriver)
		}
		if errRegister := registry.RegisterAction(musicDriver); errRegister != nil {
			return fmt.Errorf("register MiniMax music driver %q: %w", bindingID, errRegister)
		}
	}
	return nil
}
