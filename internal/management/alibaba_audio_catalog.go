package management

import (
	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	provideralibaba "github.com/OpenVulcan/vulcan-model-core/internal/provider/alibaba"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// alibabaAudioModels returns current non-realtime Qwen3-TTS, synchronous Qwen3-ASR, and asynchronous Fun-ASR contracts.
// alibabaAudioModels 返回当前非实时 Qwen3-TTS、同步 Qwen3-ASR 与异步 Fun-ASR 合同。
func alibabaAudioModels() []systemModelTemplate {
	return []systemModelTemplate{
		alibabaQwen3TTSModel("qwen3-tts-flash", "Qwen3 TTS Flash", false),
		alibabaQwen3TTSModel("qwen3-tts-instruct-flash", "Qwen3 TTS Instruct Flash", true),
		alibabaQwen3ASRModel(),
		alibabaFunASRModel(),
	}
}

// alibabaQwen3TTSModel builds one system-voice-only non-streaming synthesis contract.
// alibabaQwen3TTSModel 构建一个仅使用系统声音的非流式合成合同。
func alibabaQwen3TTSModel(upstreamID string, displayName string, instructions bool) systemModelTemplate {
	maximumCharacters := int64(600)
	parameters := []catalog.ParameterDescriptor{
		{ID: "text", Kind: catalog.ParameterString, Required: true, StringRange: &catalog.StringRange{MinimumLength: catalogInt64(1), MaximumLength: &maximumCharacters}},
		{ID: "voice_id", Kind: catalog.ParameterEnum, Required: true, AllowedValues: alibabaQwen3TTSVoices()},
		{ID: "language", Kind: catalog.ParameterEnum, AllowedValues: []string{"Auto", "Chinese", "English", "German", "Italian", "Portuguese", "Spanish", "Japanese", "Korean", "French", "Russian"}},
		{ID: "output_format", Kind: catalog.ParameterFormat, AllowedValues: []string{"wav"}},
	}
	if instructions {
		parameters = append(parameters, catalog.ParameterDescriptor{ID: "style", Kind: catalog.ParameterString, StringRange: &catalog.StringRange{}})
	}
	return systemModelTemplate{
		upstreamID: upstreamID, displayName: displayName, inputModalities: []string{"text"},
		reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnsupported, parallelTools: catalog.CapabilityUnsupported, streamingTools: catalog.CapabilityUnsupported, strictSchema: catalog.CapabilityUnsupported, entitlementMode: catalog.EntitlementAllBoundCredentials,
		operation: vcp.OperationSpeechSynthesize, actionBindingID: provideralibaba.SpeechSynthesizeActionBindingID,
		mediaOutputs: []catalog.MediaOutputCapability{{Kind: vcp.MediaAudio, Level: catalog.CapabilityNative, Formats: []string{"wav"}, MaxOutputs: catalog.OptionalLimit{Known: true, Value: 1}, Audio: &catalog.AudioMediaLimits{Encodings: []string{"pcm"}}, Delivery: catalog.DeliveryCapabilities{Synchronous: true}, Evidence: []catalog.CapabilityEvidence{{Source: catalog.ModelSourceProviderAPI, Reference: "https://www.alibabacloud.com/help/en/model-studio/qwen-tts-api", ObservedAt: mediaEvidenceObservedAt(), Revision: 1}}, EvidenceRevision: 1}},
		parameters:   parameters,
	}
}

// alibabaQwen3ASRModel builds the short-audio synchronous recognition contract without invented timing fields.
// alibabaQwen3ASRModel 构建不虚构时间字段的短音频同步识别合同。
func alibabaQwen3ASRModel() systemModelTemplate {
	return systemModelTemplate{
		upstreamID: "qwen3-asr-flash", displayName: "Qwen3 ASR Flash", inputModalities: []string{"audio"},
		reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnsupported, parallelTools: catalog.CapabilityUnsupported, streamingTools: catalog.CapabilityUnsupported, strictSchema: catalog.CapabilityUnsupported, entitlementMode: catalog.EntitlementAllBoundCredentials,
		operation: vcp.OperationSpeechTranscribe, actionBindingID: provideralibaba.SpeechTranscribeActionBindingID,
		mediaInputs: []catalog.MediaInputCapability{{
			Kind: vcp.MediaAudio, Roles: []vcp.MediaInputRole{vcp.MediaRoleTranscriptionSource}, Level: catalog.CapabilityNative, InteractionModes: []catalog.MediaInteractionMode{catalog.MediaInteractionOperationInput}, MediaOnlyPolicy: catalog.MediaOnlyNative,
			ClientWorkflows: []catalog.ClientResourceWorkflow{catalog.ClientWorkflowUploadThenReference, catalog.ClientWorkflowImportURLThenReference, catalog.ClientWorkflowImportBase64ThenReference, catalog.ClientWorkflowResolveInputPlan}, MaterializationModes: []catalog.UpstreamMaterializationMode{catalog.MaterializationInlineBase64, catalog.MaterializationDirectRemoteURL},
			Common: catalog.CommonMediaLimits{MIMETypes: []string{"audio/mpeg", "audio/wav", "audio/mp4", "audio/aac", "audio/ogg", "audio/flac", "audio/webm"}, MaxItemBytes: catalog.OptionalLimit{Known: true, Value: 10 << 20}, MaxItems: catalog.OptionalLimit{Known: true, Value: 1}}, Audio: &catalog.AudioMediaLimits{MaxDurationMilliseconds: catalog.OptionalLimit{Known: true, Value: 5 * 60 * 1000}},
			Compatibility: catalog.MediaCompatibility{ToolCalling: catalog.CapabilityUnsupported, Streaming: catalog.CapabilityUnsupported, Reasoning: catalog.CapabilityUnsupported, StructuredOutput: catalog.CapabilityUnsupported}, Evidence: []catalog.CapabilityEvidence{{Source: catalog.ModelSourceProviderAPI, Reference: "https://www.alibabacloud.com/help/en/model-studio/qwen-asr-api-reference", ObservedAt: mediaEvidenceObservedAt(), Revision: 1}}, EvidenceRevision: 1,
		}},
		parameters: []catalog.ParameterDescriptor{
			{ID: "language", Kind: catalog.ParameterEnum, AllowedValues: alibabaQwen3ASRLanguages()},
			{ID: "candidate_count", Kind: catalog.ParameterCount, IntegerRange: &catalog.IntegerRange{Maximum: catalogInt64(1)}},
		},
	}
}

// alibabaFunASRModel builds the URL-only asynchronous audio and video transcription contract.
// alibabaFunASRModel 构建仅接受 URL 的异步音频与视频转写合同。
func alibabaFunASRModel() systemModelTemplate {
	// evidence pins every declared input fact to the current official offline guide.
	// evidence 将每项输入声明固定到当前官方离线指南。
	evidence := []catalog.CapabilityEvidence{{Source: catalog.ModelSourceProviderAPI, Reference: "https://www.alibabacloud.com/help/en/model-studio/non-realtime-speech-recognition-user-guide", ObservedAt: mediaEvidenceObservedAt(), Revision: 1}}
	// common contains the provider-wide single-file public URL limits.
	// common 包含供应商范围的单文件公网 URL 限制。
	common := catalog.CommonMediaLimits{MaxItemBytes: catalog.OptionalLimit{Known: true, Value: 2 << 30}, MaxItems: catalog.OptionalLimit{Known: true, Value: 1}, AllowsRemoteURL: catalog.OptionalBool{Known: true, Value: true}}
	// compatibility closes unsupported conversation-only features for this standalone operation.
	// compatibility 为此独立操作封闭不受支持的会话专属特性。
	compatibility := catalog.MediaCompatibility{ToolCalling: catalog.CapabilityUnsupported, Streaming: catalog.CapabilityUnsupported, Reasoning: catalog.CapabilityUnsupported, StructuredOutput: catalog.CapabilityUnsupported}
	return systemModelTemplate{
		upstreamID: "fun-asr", displayName: "Fun-ASR", inputModalities: []string{"audio", "video"},
		reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnsupported, parallelTools: catalog.CapabilityUnsupported, streamingTools: catalog.CapabilityUnsupported, strictSchema: catalog.CapabilityUnsupported, entitlementMode: catalog.EntitlementAllBoundCredentials,
		operation: vcp.OperationSpeechTranscribe, actionBindingID: provideralibaba.SpeechTranscribeAsyncActionBindingID,
		mediaInputs: []catalog.MediaInputCapability{
			{Kind: vcp.MediaAudio, Roles: []vcp.MediaInputRole{vcp.MediaRoleTranscriptionSource}, Level: catalog.CapabilityNative, InteractionModes: []catalog.MediaInteractionMode{catalog.MediaInteractionOperationInput}, MediaOnlyPolicy: catalog.MediaOnlyNative, ClientWorkflows: []catalog.ClientResourceWorkflow{catalog.ClientWorkflowImportURLThenReference, catalog.ClientWorkflowResolveInputPlan}, MaterializationModes: []catalog.UpstreamMaterializationMode{catalog.MaterializationDirectRemoteURL}, Common: catalog.CommonMediaLimits{MIMETypes: []string{"audio/aac", "audio/amr", "audio/flac", "audio/mp4", "audio/mpeg", "audio/ogg", "audio/opus", "audio/wav", "audio/x-ms-wma"}, MaxItemBytes: common.MaxItemBytes, MaxItems: common.MaxItems, AllowsRemoteURL: common.AllowsRemoteURL}, Audio: &catalog.AudioMediaLimits{MaxDurationMilliseconds: catalog.OptionalLimit{Known: true, Value: 12 * 60 * 60 * 1000}}, Compatibility: compatibility, Evidence: evidence, EvidenceRevision: 1},
			{Kind: vcp.MediaVideo, Roles: []vcp.MediaInputRole{vcp.MediaRoleTranscriptionSource}, Level: catalog.CapabilityNative, InteractionModes: []catalog.MediaInteractionMode{catalog.MediaInteractionOperationInput}, MediaOnlyPolicy: catalog.MediaOnlyNative, ClientWorkflows: []catalog.ClientResourceWorkflow{catalog.ClientWorkflowImportURLThenReference, catalog.ClientWorkflowResolveInputPlan}, MaterializationModes: []catalog.UpstreamMaterializationMode{catalog.MaterializationDirectRemoteURL}, Common: catalog.CommonMediaLimits{MIMETypes: []string{"video/mp4", "video/mpeg", "video/quicktime", "video/webm", "video/x-flv", "video/x-matroska", "video/x-ms-wmv", "video/x-msvideo"}, MaxItemBytes: common.MaxItemBytes, MaxItems: common.MaxItems, AllowsRemoteURL: common.AllowsRemoteURL}, Video: &catalog.VideoMediaLimits{MaxDurationMilliseconds: catalog.OptionalLimit{Known: true, Value: 12 * 60 * 60 * 1000}, EmbeddedAudio: catalog.OptionalBool{Known: true, Value: true}}, Compatibility: compatibility, Evidence: evidence, EvidenceRevision: 1},
		},
		parameters: []catalog.ParameterDescriptor{
			{ID: "language", Kind: catalog.ParameterEnum, AllowedValues: alibabaFunASRLanguages()},
			{ID: "diarization", Kind: catalog.ParameterBoolean},
			{ID: "segment_timestamps", Kind: catalog.ParameterBoolean},
			{ID: "word_timestamps", Kind: catalog.ParameterBoolean},
			{ID: "candidate_count", Kind: catalog.ParameterCount, IntegerRange: &catalog.IntegerRange{Maximum: catalogInt64(1)}},
		},
	}
}

// alibabaQwen3TTSVoices returns the closed non-realtime system voice set shared by the current aliases.
// alibabaQwen3TTSVoices 返回当前别名共享的封闭非实时系统声音集合。
func alibabaQwen3TTSVoices() []string {
	return []string{"Cherry", "Serena", "Ethan", "Chelsie", "Momo", "Vivian", "Moon", "Maia", "Kai", "Nofish", "Bella", "Jennifer", "Ryan", "Katerina", "Aiden", "Eldric Sage", "Mia", "Mochi", "Bellona", "Vincent", "Bunny", "Neil", "Elias", "Arthur", "Nini", "Seren", "Pip", "Stella", "Bodega", "Sonrisa", "Alek", "Dolce", "Sohee", "Ono Anna", "Lenn"}
}

// alibabaQwen3ASRLanguages returns the documented synchronous source-language codes.
// alibabaQwen3ASRLanguages 返回文档规定的同步源语言代码。
func alibabaQwen3ASRLanguages() []string {
	return []string{"zh", "yue", "en", "ja", "de", "ko", "ru", "fr", "pt", "ar", "it", "es", "hi", "id", "th", "tr", "uk", "vi", "cs", "da", "fil", "fi", "is", "ms", "no", "pl", "sv"}
}

// alibabaFunASRLanguages returns the current stable offline language-hint set.
// alibabaFunASRLanguages 返回当前稳定版离线语言提示集合。
func alibabaFunASRLanguages() []string {
	return []string{"zh", "en", "ja", "ko", "vi", "th", "id", "ms", "tl", "hi", "ar", "fr", "de", "es", "pt", "ru", "it", "nl", "sv", "da", "fi", "no", "el", "pl", "cs", "hu", "ro", "bg", "hr", "sk"}
}
