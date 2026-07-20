package management

import (
	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	provideropenai "github.com/OpenVulcan/vulcan-model-core/internal/provider/openai"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// openAIAudioModels returns current non-realtime OpenAI TTS and STT model contracts.
// openAIAudioModels 返回当前 OpenAI 非实时 TTS 与 STT 模型合同。
func openAIAudioModels() []systemModelTemplate {
	models := []systemModelTemplate{
		openAITTSModel("tts-1", "TTS-1"),
		openAITTSModel("tts-1-hd", "TTS-1 HD"),
		openAISTTModel("gpt-4o-transcribe", "GPT-4o Transcribe"),
		openAISTTModel("gpt-4o-mini-transcribe", "GPT-4o Mini Transcribe"),
		openAISTTModel("gpt-4o-transcribe-diarize", "GPT-4o Transcribe Diarize"),
		openAISTTModel("whisper-1", "Whisper"),
	}
	return models
}

// openAITTSModel builds one fixed single-voice synthesis profile.
// openAITTSModel 构建一个固定的单声音语音合成 Profile。
func openAITTSModel(upstreamID string, displayName string) systemModelTemplate {
	minimumSpeed, maximumSpeed, defaultSpeed := 0.25, 4.0, 1.0
	return systemModelTemplate{
		upstreamID: upstreamID, displayName: displayName, inputModalities: []string{"text"},
		reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnsupported, parallelTools: catalog.CapabilityUnsupported, streamingTools: catalog.CapabilityUnsupported, strictSchema: catalog.CapabilityUnsupported, entitlementMode: catalog.EntitlementAllBoundCredentials,
		operation: vcp.OperationSpeechSynthesize, actionBindingID: provideropenai.SpeechSynthesizeActionBindingID,
		mediaOutputs: []catalog.MediaOutputCapability{openAITTSOutputCapability()},
		parameters: []catalog.ParameterDescriptor{
			{ID: "voice_id", Kind: catalog.ParameterEnum, AllowedValues: []string{"alloy", "ash", "ballad", "coral", "echo", "fable", "onyx", "nova", "sage", "shimmer", "verse", "marin", "cedar"}},
			{ID: "speed", Kind: catalog.ParameterFloat, FloatRange: &catalog.FloatRange{Minimum: &minimumSpeed, Maximum: &maximumSpeed}, Default: &catalog.ParameterDefault{Source: catalog.ParameterDefaultProvider, Float: &defaultSpeed}},
			{ID: "output_format", Kind: catalog.ParameterFormat, AllowedValues: []string{"mp3", "wav"}},
		},
	}
}

// openAISTTModel builds one transcription profile with model-specific optional controls.
// openAISTTModel 构建一个具有模型特定可选控制项的转写 Profile。
func openAISTTModel(upstreamID string, displayName string) systemModelTemplate {
	parameters := []catalog.ParameterDescriptor{{ID: "candidate_count", Kind: catalog.ParameterCount, IntegerRange: &catalog.IntegerRange{Maximum: catalogInt64(1)}}}
	if upstreamID == "whisper-1" {
		parameters = append(parameters,
			catalog.ParameterDescriptor{ID: "segment_timestamps", Kind: catalog.ParameterBoolean},
			catalog.ParameterDescriptor{ID: "word_timestamps", Kind: catalog.ParameterBoolean},
		)
	}
	if upstreamID == "gpt-4o-transcribe-diarize" {
		parameters = append(parameters,
			catalog.ParameterDescriptor{ID: "diarization", Kind: catalog.ParameterBoolean},
			catalog.ParameterDescriptor{ID: "segment_timestamps", Kind: catalog.ParameterBoolean},
		)
	}
	return systemModelTemplate{
		upstreamID: upstreamID, displayName: displayName, inputModalities: []string{"audio", "video"},
		reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnsupported, parallelTools: catalog.CapabilityUnsupported, streamingTools: catalog.CapabilityUnsupported, strictSchema: catalog.CapabilityUnsupported, entitlementMode: catalog.EntitlementAllBoundCredentials,
		operation: vcp.OperationSpeechTranscribe, actionBindingID: provideropenai.SpeechTranscribeActionBindingID,
		mediaInputs: openAISTTInputCapabilities(), parameters: parameters,
	}
}

// openAITTSOutputCapability publishes only audio formats the Router can inspect authoritatively.
// openAITTSOutputCapability 仅发布 Router 能够权威检查的音频格式。
func openAITTSOutputCapability() catalog.MediaOutputCapability {
	return catalog.MediaOutputCapability{
		Kind: vcp.MediaAudio, Level: catalog.CapabilityNative, Formats: []string{"mp3", "wav"}, MaxOutputs: catalog.OptionalLimit{Known: true, Value: 1}, Audio: &catalog.AudioMediaLimits{Encodings: []string{"mp3", "pcm"}}, Delivery: catalog.DeliveryCapabilities{Synchronous: true},
		Evidence: []catalog.CapabilityEvidence{{Source: catalog.ModelSourceProviderAPI, Reference: "https://platform.openai.com/docs/api-reference/audio/createSpeech", ObservedAt: mediaEvidenceObservedAt(), Revision: 1}}, EvidenceRevision: 1,
	}
}

// openAISTTInputCapabilities returns separate audio and video upload contracts for transcription.
// openAISTTInputCapabilities 返回转写所需的独立音频与视频上传合同。
func openAISTTInputCapabilities() []catalog.MediaInputCapability {
	evidence := []catalog.CapabilityEvidence{{Source: catalog.ModelSourceProviderAPI, Reference: "https://platform.openai.com/docs/api-reference/audio/createTranscription", ObservedAt: mediaEvidenceObservedAt(), Revision: 1}}
	common := catalog.MediaInputCapability{
		Roles: []vcp.MediaInputRole{vcp.MediaRoleTranscriptionSource}, Level: catalog.CapabilityNative, InteractionModes: []catalog.MediaInteractionMode{catalog.MediaInteractionOperationInput}, MediaOnlyPolicy: catalog.MediaOnlyNative,
		ClientWorkflows: []catalog.ClientResourceWorkflow{catalog.ClientWorkflowUploadThenReference, catalog.ClientWorkflowImportURLThenReference, catalog.ClientWorkflowImportBase64ThenReference, catalog.ClientWorkflowResolveInputPlan}, MaterializationModes: []catalog.UpstreamMaterializationMode{catalog.MaterializationInlineBase64},
		Compatibility: catalog.MediaCompatibility{ToolCalling: catalog.CapabilityUnsupported, Streaming: catalog.CapabilityUnsupported, Reasoning: catalog.CapabilityUnsupported, StructuredOutput: catalog.CapabilityUnsupported}, Evidence: evidence, EvidenceRevision: 1,
	}
	audio := common
	audio.Kind = vcp.MediaAudio
	audio.Common = catalog.CommonMediaLimits{MIMETypes: []string{"audio/mpeg", "audio/wav"}, MaxItemBytes: catalog.OptionalLimit{Known: true, Value: 25 << 20}, MaxItems: catalog.OptionalLimit{Known: true, Value: 1}}
	audio.Audio = &catalog.AudioMediaLimits{Encodings: []string{"mp3", "pcm"}}
	video := common
	video.Kind = vcp.MediaVideo
	video.Common = catalog.CommonMediaLimits{MIMETypes: []string{"video/mp4", "video/webm"}, MaxItemBytes: catalog.OptionalLimit{Known: true, Value: 25 << 20}, MaxItems: catalog.OptionalLimit{Known: true, Value: 1}}
	video.Video = &catalog.VideoMediaLimits{Containers: []string{"mp4", "webm"}, EmbeddedAudio: catalog.OptionalBool{Known: true, Value: true}}
	return []catalog.MediaInputCapability{audio, video}
}

// catalogInt64 returns a stable pointer for a catalog integer boundary.
// catalogInt64 为目录整数边界返回稳定指针。
func catalogInt64(value int64) *int64 {
	return &value
}
