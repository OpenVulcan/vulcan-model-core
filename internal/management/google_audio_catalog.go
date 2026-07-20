package management

import (
	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	providergoogle "github.com/OpenVulcan/vulcan-model-core/internal/provider/google"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// googleInteractionsSpeechModels returns the current non-realtime Gemini TTS inventory.
// googleInteractionsSpeechModels 返回当前非实时 Gemini TTS 模型清单。
func googleInteractionsSpeechModels() []systemModelTemplate {
	models := make([]systemModelTemplate, 0, 3)
	for _, identity := range []systemModelIdentity{{upstreamID: "gemini-3.1-flash-tts-preview", displayName: "Gemini 3.1 Flash TTS Preview"}, {upstreamID: "gemini-2.5-flash-preview-tts", displayName: "Gemini 2.5 Flash Preview TTS"}, {upstreamID: "gemini-2.5-pro-preview-tts", displayName: "Gemini 2.5 Pro Preview TTS"}} {
		models = append(models, googleInteractionsSpeechTemplate(identity))
	}
	return models
}

// googleInteractionsSpeechTemplate builds one closed single- or two-speaker TTS profile.
// googleInteractionsSpeechTemplate 构建一个封闭的单说话人或双说话人 TTS 配置。
func googleInteractionsSpeechTemplate(identity systemModelIdentity) systemModelTemplate {
	return systemModelTemplate{
		upstreamID: identity.upstreamID, displayName: identity.displayName, contextWindow: 32768, inputModalities: []string{"text"},
		reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnsupported, parallelTools: catalog.CapabilityUnsupported, streamingTools: catalog.CapabilityUnsupported, strictSchema: catalog.CapabilityUnsupported, entitlementMode: catalog.EntitlementAllBoundCredentials,
		operation: vcp.OperationSpeechSynthesize, actionBindingID: providergoogle.SpeechSynthesizeActionBindingID,
		mediaOutputs: []catalog.MediaOutputCapability{{Kind: vcp.MediaAudio, Level: catalog.CapabilityNative, Formats: []string{"mp3", "wav"}, MaxOutputs: catalog.OptionalLimit{Known: true, Value: 1}, Audio: &catalog.AudioMediaLimits{MaxSampleRateHz: catalog.OptionalLimit{Known: true, Value: 24000}, MaxChannels: catalog.OptionalLimit{Known: true, Value: 1}, Encodings: []string{"mp3", "pcm"}}, Delivery: catalog.DeliveryCapabilities{Synchronous: true}, Evidence: []catalog.CapabilityEvidence{{Source: catalog.ModelSourceProviderAPI, Reference: "https://ai.google.dev/gemini-api/docs/speech-generation", ObservedAt: mediaEvidenceObservedAt(), Revision: 1}}, EvidenceRevision: 1}},
		parameters: []catalog.ParameterDescriptor{
			{ID: "text", Kind: catalog.ParameterString, Required: true, StringRange: &catalog.StringRange{MinimumLength: catalogInt64(1)}},
			{ID: "voice_id", Kind: catalog.ParameterEnum, Required: true, AllowedValues: googleInteractionsVoices()},
			{ID: "style", Kind: catalog.ParameterString, StringRange: &catalog.StringRange{}},
			{ID: "sample_rate", Kind: catalog.ParameterEnum, AllowedValues: []string{"24000"}},
			{ID: "channels", Kind: catalog.ParameterEnum, AllowedValues: []string{"1"}},
			{ID: "output_format", Kind: catalog.ParameterFormat, AllowedValues: []string{"mp3", "wav"}},
		},
	}
}

// googleInteractionsVoices returns the current thirty prebuilt Gemini TTS voices.
// googleInteractionsVoices 返回当前三十个 Gemini TTS 预设声音。
func googleInteractionsVoices() []string {
	return []string{"Zephyr", "Puck", "Charon", "Kore", "Fenrir", "Leda", "Orus", "Aoede", "Callirrhoe", "Autonoe", "Enceladus", "Iapetus", "Umbriel", "Algieba", "Despina", "Erinome", "Algenib", "Rasalgethi", "Laomedeia", "Achernar", "Alnilam", "Schedar", "Gacrux", "Pulcherrima", "Achird", "Zubenelgenubi", "Vindemiatrix", "Sadachbia", "Sadaltager", "Sulafat"}
}
