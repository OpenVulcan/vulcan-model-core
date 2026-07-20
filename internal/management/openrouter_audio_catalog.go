package management

import (
	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	provideropenrouter "github.com/OpenVulcan/vulcan-model-core/internal/provider/openrouter"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// openRouterAudioModels returns the endpoint-specific speech and transcription baseline.
// openRouterAudioModels 返回端点专属的语音与转写基线。
func openRouterAudioModels() []systemModelTemplate {
	minimumSpeed, maximumSpeed, defaultSpeed := 0.25, 4.0, 1.0
	evidenceTTS := []catalog.CapabilityEvidence{{Source: catalog.ModelSourceProviderAPI, Reference: "https://openrouter.ai/docs/guides/overview/multimodal/tts", ObservedAt: mediaEvidenceObservedAt(), Revision: 1}}
	evidenceSTT := []catalog.CapabilityEvidence{{Source: catalog.ModelSourceProviderAPI, Reference: "https://openrouter.ai/openai/whisper-large-v3/api", ObservedAt: mediaEvidenceObservedAt(), Revision: 1}}
	return []systemModelTemplate{
		{
			upstreamID: "openai/gpt-4o-mini-tts-2025-12-15", displayName: "OpenAI GPT-4o Mini TTS via OpenRouter", inputModalities: []string{"text"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnsupported, parallelTools: catalog.CapabilityUnsupported, streamingTools: catalog.CapabilityUnsupported, strictSchema: catalog.CapabilityUnsupported, entitlementMode: catalog.EntitlementAllBoundCredentials,
			operation: vcp.OperationSpeechSynthesize, actionBindingID: provideropenrouter.SpeechSynthesizeActionBindingID,
			mediaOutputs: []catalog.MediaOutputCapability{{Kind: vcp.MediaAudio, Level: catalog.CapabilityNative, Formats: []string{"mp3"}, MaxOutputs: catalog.OptionalLimit{Known: true, Value: 1}, Audio: &catalog.AudioMediaLimits{Encodings: []string{"mp3"}}, Delivery: catalog.DeliveryCapabilities{Synchronous: true}, Evidence: evidenceTTS, EvidenceRevision: 1}},
			parameters:   []catalog.ParameterDescriptor{{ID: "voice_id", Kind: catalog.ParameterEnum, AllowedValues: []string{"alloy", "ash", "ballad", "coral", "echo", "fable", "onyx", "nova", "sage", "shimmer", "verse", "marin", "cedar"}}, {ID: "speed", Kind: catalog.ParameterFloat, FloatRange: &catalog.FloatRange{Minimum: &minimumSpeed, Maximum: &maximumSpeed}, Default: &catalog.ParameterDefault{Source: catalog.ParameterDefaultProvider, Float: &defaultSpeed}}, {ID: "output_format", Kind: catalog.ParameterFormat, AllowedValues: []string{"mp3"}}},
		},
		{
			upstreamID: "openai/whisper-large-v3", displayName: "OpenAI Whisper Large V3 via OpenRouter", inputModalities: []string{"audio"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnsupported, parallelTools: catalog.CapabilityUnsupported, streamingTools: catalog.CapabilityUnsupported, strictSchema: catalog.CapabilityUnsupported, entitlementMode: catalog.EntitlementAllBoundCredentials,
			operation: vcp.OperationSpeechTranscribe, actionBindingID: provideropenrouter.SpeechTranscribeActionBindingID,
			mediaInputs: []catalog.MediaInputCapability{{Kind: vcp.MediaAudio, Roles: []vcp.MediaInputRole{vcp.MediaRoleTranscriptionSource}, Level: catalog.CapabilityNative, InteractionModes: []catalog.MediaInteractionMode{catalog.MediaInteractionOperationInput}, MediaOnlyPolicy: catalog.MediaOnlyNative, ClientWorkflows: []catalog.ClientResourceWorkflow{catalog.ClientWorkflowUploadThenReference, catalog.ClientWorkflowImportURLThenReference, catalog.ClientWorkflowImportBase64ThenReference, catalog.ClientWorkflowResolveInputPlan}, MaterializationModes: []catalog.UpstreamMaterializationMode{catalog.MaterializationInlineBase64}, Common: catalog.CommonMediaLimits{MIMETypes: []string{"audio/wav"}, MaxItems: catalog.OptionalLimit{Known: true, Value: 1}}, Audio: &catalog.AudioMediaLimits{Encodings: []string{"pcm"}}, Compatibility: catalog.MediaCompatibility{ToolCalling: catalog.CapabilityUnsupported, Streaming: catalog.CapabilityUnsupported, Reasoning: catalog.CapabilityUnsupported, StructuredOutput: catalog.CapabilityUnsupported}, Evidence: evidenceSTT, EvidenceRevision: 1}},
			parameters:  []catalog.ParameterDescriptor{{ID: "candidate_count", Kind: catalog.ParameterCount, IntegerRange: &catalog.IntegerRange{Maximum: catalogInt64(1)}}},
		},
	}
}
