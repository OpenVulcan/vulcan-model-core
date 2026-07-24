package bootstrap

import (
	"fmt"

	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	provideropenrouter "github.com/OpenVulcan/vulcan-model-core/internal/provider/openrouter"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

const (
	// OpenRouterGroupID identifies the OpenRouter provider family.
	// OpenRouterGroupID 标识 OpenRouter 供应商系列。
	OpenRouterGroupID = "openrouter"
	// OpenRouterAPIDefinitionID identifies the public OpenRouter API product.
	// OpenRouterAPIDefinitionID 标识公开 OpenRouter API 产品。
	OpenRouterAPIDefinitionID = "system_openrouter_api"
)

// registerOpenRouterProviderCatalog registers OpenRouter with exact native model actions.
// registerOpenRouterProviderCatalog 注册具有精确原生模型动作的 OpenRouter。
func registerOpenRouterProviderCatalog(registry *providerconfig.SystemRegistry) error {
	if errGroup := registry.RegisterGroup(providerconfig.ProviderGroup{ID: OpenRouterGroupID, DisplayName: "OpenRouter", Description: "OpenRouter model routing API with typed native capability actions.", DescriptionKey: "providers.openrouter.description", SortOrder: 70, Revision: 1}); errGroup != nil {
		return fmt.Errorf("register OpenRouter provider group: %w", errGroup)
	}
	auth := providerconfig.AuthMethodDefinition{ID: "api_key", Type: providerconfig.AuthMethodAPIKey, MultipleCredentials: true}
	features := providerconfig.ProviderFeatureSet{PlanReader: providerconfig.SupportUnsupported, EntitlementReader: providerconfig.SupportUnsupported, AllowanceReader: providerconfig.SupportUnsupported}
	definition := providerDefinition(OpenRouterAPIDefinitionID, "OpenRouter API", OpenRouterGroupID, "API", "OpenRouter API with typed image, video, non-realtime speech, embedding, and rerank execution.", "providers.openrouter.apiDescription", "openrouter_api", 10, "openrouter", provideropenrouter.EmbeddingProtocolProfileID, "openrouter_embeddings", "https://openrouter.ai/api", true, []providerconfig.AuthMethodDefinition{auth}, features)
	definition.ActionBindings = []providerconfig.ProviderActionBinding{
		{ID: provideropenrouter.EmbeddingActionBindingID, Operation: vcp.OperationEmbeddingCreate, DriverID: "openrouter", DriverVersion: "1", ProtocolProfileID: provideropenrouter.EmbeddingProtocolProfileID, EndpointProfileID: "openrouter_embeddings", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, Revision: 1},
		{ID: provideropenrouter.RerankActionBindingID, Operation: vcp.OperationRerankDocuments, DriverID: "openrouter", DriverVersion: "1", ProtocolProfileID: provideropenrouter.RerankProtocolProfileID, EndpointProfileID: "openrouter_rerank", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, Revision: 1},
		{ID: provideropenrouter.ImageGenerateActionBindingID, Operation: vcp.OperationImageGenerate, DriverID: "openrouter", DriverVersion: "1", ProtocolProfileID: provideropenrouter.ImageGenerateProtocolProfileID, EndpointProfileID: "openrouter_images_openai", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, ResourceMaterialization: []providerconfig.ResourceMaterializationMode{providerconfig.ResourceMaterializationInline, providerconfig.ResourceMaterializationDirectURL}, Revision: 1},
		{ID: provideropenrouter.VideoGenerateActionBindingID, Operation: vcp.OperationVideoGenerate, DriverID: "openrouter", DriverVersion: "1", ProtocolProfileID: provideropenrouter.VideoGenerateProtocolProfileID, EndpointProfileID: "openrouter_videos", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Asynchronous: true, Polling: true}, ResourceMaterialization: []providerconfig.ResourceMaterializationMode{providerconfig.ResourceMaterializationInline, providerconfig.ResourceMaterializationDirectURL}, Revision: 1},
		{ID: provideropenrouter.SpeechSynthesizeActionBindingID, Operation: vcp.OperationSpeechSynthesize, DriverID: "openrouter", DriverVersion: "1", ProtocolProfileID: provideropenrouter.SpeechSynthesizeProtocolProfileID, EndpointProfileID: "openrouter_audio_speech", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, Revision: 1},
		{ID: provideropenrouter.SpeechTranscribeActionBindingID, Operation: vcp.OperationSpeechTranscribe, DriverID: "openrouter", DriverVersion: "1", ProtocolProfileID: provideropenrouter.SpeechTranscribeProtocolProfileID, EndpointProfileID: "openrouter_audio_transcriptions", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, ResourceMaterialization: []providerconfig.ResourceMaterializationMode{providerconfig.ResourceMaterializationInline}, Revision: 1},
	}
	if errRegister := registry.Register(definition); errRegister != nil {
		return fmt.Errorf("register OpenRouter provider definition: %w", errRegister)
	}
	return nil
}

// RegisterOpenRouterExecutionDrivers binds OpenRouter native actions to one exact provider definition.
// RegisterOpenRouterExecutionDrivers 将 OpenRouter 原生动作绑定到一个精确供应商 Definition。
func RegisterOpenRouterExecutionDrivers(registry *provider.ExecutionRegistry, client *transport.Client) error {
	if registry == nil || client == nil {
		return fmt.Errorf("OpenRouter execution registry and transport client are required")
	}
	embedding, errEmbedding := provideropenrouter.NewEmbeddingDriver(OpenRouterAPIDefinitionID, client)
	if errEmbedding != nil {
		return fmt.Errorf("create OpenRouter embedding driver: %w", errEmbedding)
	}
	if errRegister := registry.RegisterAction(embedding); errRegister != nil {
		return fmt.Errorf("register OpenRouter embedding driver: %w", errRegister)
	}
	rerank, errRerank := provideropenrouter.NewRerankDriver(OpenRouterAPIDefinitionID, client)
	if errRerank != nil {
		return fmt.Errorf("create OpenRouter rerank driver: %w", errRerank)
	}
	if errRegister := registry.RegisterAction(rerank); errRegister != nil {
		return fmt.Errorf("register OpenRouter rerank driver: %w", errRegister)
	}
	image, errImage := provideropenrouter.NewImageDriver(OpenRouterAPIDefinitionID, client)
	if errImage != nil {
		return fmt.Errorf("create OpenRouter image driver: %w", errImage)
	}
	if errRegister := registry.RegisterAction(image); errRegister != nil {
		return fmt.Errorf("register OpenRouter image driver: %w", errRegister)
	}
	video, errVideo := provideropenrouter.NewVideoTaskDriver(OpenRouterAPIDefinitionID, client)
	if errVideo != nil {
		return fmt.Errorf("create OpenRouter video driver: %w", errVideo)
	}
	if errRegister := registry.RegisterTaskAction(video); errRegister != nil {
		return fmt.Errorf("register OpenRouter video driver: %w", errRegister)
	}
	for _, actionBindingID := range []string{provideropenrouter.SpeechSynthesizeActionBindingID, provideropenrouter.SpeechTranscribeActionBindingID} {
		audio, errAudio := provideropenrouter.NewAudioDriver(OpenRouterAPIDefinitionID, actionBindingID, client)
		if errAudio != nil {
			return fmt.Errorf("create OpenRouter audio driver %s: %w", actionBindingID, errAudio)
		}
		if errRegister := registry.RegisterAction(audio); errRegister != nil {
			return fmt.Errorf("register OpenRouter audio driver %s: %w", actionBindingID, errRegister)
		}
	}
	return nil
}
