package management

import (
	"math"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	providerminimax "github.com/OpenVulcan/vulcan-model-core/internal/provider/minimax"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// miniMaxSpeechModels returns synchronous and long-text profiles for current Speech 2.8 models.
// miniMaxSpeechModels 返回当前 Speech 2.8 模型的同步与长文本配置。
func miniMaxSpeechModels() []systemModelTemplate {
	models := make([]systemModelTemplate, 0, 6)
	for _, identity := range []systemModelIdentity{{upstreamID: "speech-2.8-hd", displayName: "MiniMax Speech 2.8 HD"}, {upstreamID: "speech-2.8-turbo", displayName: "MiniMax Speech 2.8 Turbo"}} {
		models = append(models, miniMaxSpeechTemplate(identity, false), miniMaxSpeechTemplate(identity, true))
	}
	models = append(models,
		miniMaxSpeechTemplate(systemModelIdentity{upstreamID: "speech-2.6", displayName: "MiniMax Speech 2.6"}, false),
		miniMaxSpeechTemplate(systemModelIdentity{upstreamID: "speech-02", displayName: "MiniMax Speech 02"}, false),
	)
	return models
}

// miniMaxSpeechTemplate builds one execution-mode-specific MiniMax T2A contract.
// miniMaxSpeechTemplate 构建一个执行模式专属的 MiniMax T2A 合同。
func miniMaxSpeechTemplate(identity systemModelIdentity, asynchronous bool) systemModelTemplate {
	actionBindingID := providerminimax.SpeechSynthesizeActionBindingID
	delivery := catalog.DeliveryCapabilities{Synchronous: true, Streaming: true, PartialResults: true, Cancellation: true}
	maximumCharacters := int64(9999)
	if asynchronous {
		actionBindingID = providerminimax.SpeechSynthesizeAsyncActionBindingID
		delivery = catalog.DeliveryCapabilities{Asynchronous: true, Polling: true}
		maximumCharacters = 50000
	}
	outputFormats := []string{"mp3", "pcm", "flac", "wav", "pcmu_raw", "pcmu_wav", "opus"}
	outputEncodings := append([]string(nil), outputFormats...)
	if asynchronous {
		outputFormats = []string{"mp3", "wav"}
		outputEncodings = []string{"mp3", "wav"}
	}
	minimumSpeed, maximumSpeed, defaultSpeed := 0.5, 2.0, 1.0
	minimumVolume, maximumVolume, defaultVolume := math.SmallestNonzeroFloat64, 10.0, 1.0
	minimumPitch, maximumPitch, defaultPitch := int64(-12), int64(12), int64(0)
	return systemModelTemplate{
		upstreamID: identity.upstreamID, displayName: identity.displayName, inputModalities: []string{"text"},
		reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnsupported, parallelTools: catalog.CapabilityUnsupported, streamingTools: catalog.CapabilityUnsupported, strictSchema: catalog.CapabilityUnsupported, entitlementMode: catalog.EntitlementAllBoundCredentials,
		operation: vcp.OperationSpeechSynthesize, actionBindingID: actionBindingID,
		mediaOutputs: []catalog.MediaOutputCapability{{Kind: vcp.MediaAudio, Level: catalog.CapabilityNative, Formats: outputFormats, MaxOutputs: catalog.OptionalLimit{Known: true, Value: 1}, Audio: &catalog.AudioMediaLimits{Encodings: outputEncodings}, Delivery: delivery, Evidence: []catalog.CapabilityEvidence{{Source: catalog.ModelSourceProviderAPI, Reference: miniMaxSpeechEvidenceURL(asynchronous), ObservedAt: mediaEvidenceObservedAt(), Revision: 1}}, EvidenceRevision: 1}},
		parameters: []catalog.ParameterDescriptor{
			{ID: "text", Kind: catalog.ParameterString, Required: true, StringRange: &catalog.StringRange{MinimumLength: catalogInt64(1), MaximumLength: &maximumCharacters}},
			{ID: "voice_id", Kind: catalog.ParameterString, Required: true, StringRange: &catalog.StringRange{}},
			{ID: "language", Kind: catalog.ParameterEnum, AllowedValues: miniMaxSpeechLanguages()},
			{ID: "speed", Kind: catalog.ParameterFloat, FloatRange: &catalog.FloatRange{Minimum: &minimumSpeed, Maximum: &maximumSpeed}, Default: &catalog.ParameterDefault{Source: catalog.ParameterDefaultProvider, Float: &defaultSpeed}},
			{ID: "volume", Kind: catalog.ParameterFloat, FloatRange: &catalog.FloatRange{Minimum: &minimumVolume, Maximum: &maximumVolume}, Default: &catalog.ParameterDefault{Source: catalog.ParameterDefaultProvider, Float: &defaultVolume}},
			{ID: "pitch", Kind: catalog.ParameterInteger, IntegerRange: &catalog.IntegerRange{Minimum: &minimumPitch, Maximum: &maximumPitch}, Default: &catalog.ParameterDefault{Source: catalog.ParameterDefaultProvider, Integer: &defaultPitch}},
			{ID: "sample_rate", Kind: catalog.ParameterEnum, AllowedValues: []string{"8000", "16000", "22050", "24000", "32000", "44100"}},
			{ID: "bitrate", Kind: catalog.ParameterEnum, AllowedValues: []string{"32000", "64000", "128000", "256000"}},
			{ID: "channels", Kind: catalog.ParameterEnum, AllowedValues: []string{"1", "2"}},
			{ID: "output_format", Kind: catalog.ParameterFormat, AllowedValues: outputFormats},
			{ID: "timestamps", Kind: catalog.ParameterBoolean},
			{ID: "pronunciations", Kind: catalog.ParameterStringList, StringRange: &catalog.StringRange{}},
		},
	}
}

// miniMaxSpeechEvidenceURL returns the exact official endpoint reference for one execution mode.
// miniMaxSpeechEvidenceURL 返回一个执行模式对应的精确官方端点参考。
func miniMaxSpeechEvidenceURL(asynchronous bool) string {
	if asynchronous {
		return "https://platform.minimax.io/docs/api-reference/speech-t2a-async-create"
	}
	return "https://platform.minimax.io/docs/api-reference/speech-t2a-http"
}

// miniMaxSpeechLanguages returns the closed current language_boost enumeration.
// miniMaxSpeechLanguages 返回当前封闭的 language_boost 枚举。
func miniMaxSpeechLanguages() []string {
	return []string{"Chinese", "Chinese,Yue", "English", "Arabic", "Russian", "Spanish", "French", "Portuguese", "German", "Turkish", "Dutch", "Ukrainian", "Vietnamese", "Indonesian", "Japanese", "Italian", "Korean", "Thai", "Polish", "Romanian", "Greek", "Czech", "Finnish", "Hindi", "Bulgarian", "Danish", "Hebrew", "Malay", "Persian", "Slovak", "Swedish", "Croatian", "Filipino", "Hungarian", "Norwegian", "Slovenian", "Catalan", "Nynorsk", "Tamil", "Afrikaans", "auto"}
}
