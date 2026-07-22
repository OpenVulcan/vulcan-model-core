package management

import (
	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	providerminimax "github.com/OpenVulcan/vulcan-model-core/internal/provider/minimax"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// miniMaxMusicModels returns current text-to-music and two-step cover profiles.
// miniMaxMusicModels 返回当前文本生成音乐与两阶段翻唱配置。
func miniMaxMusicModels() []systemModelTemplate {
	return []systemModelTemplate{
		miniMaxMusicGenerationTemplate(systemModelIdentity{upstreamID: "music-3.0", displayName: "MiniMax Music 3.0"}),
		miniMaxMusicGenerationTemplate(systemModelIdentity{upstreamID: "music-2.6", displayName: "MiniMax Music 2.6"}),
		miniMaxMusicGenerationTemplate(systemModelIdentity{upstreamID: "music-2.6-free", displayName: "MiniMax Music 2.6 Free"}),
		miniMaxMusicGenerationTemplate(systemModelIdentity{upstreamID: "music-2.5+", displayName: "MiniMax Music 2.5 Plus"}),
		miniMaxMusicGenerationTemplate(systemModelIdentity{upstreamID: "music-2.5", displayName: "MiniMax Music 2.5"}),
		miniMaxMusicCoverPreparationTemplate(),
		miniMaxMusicCoverTemplate(),
		miniMaxMusicCoverTemplateForIdentity(systemModelIdentity{upstreamID: "music-cover-free", displayName: "MiniMax Music Cover Free"}),
	}
}

// miniMaxMusicGenerationTemplate builds one closed text-to-music contract.
// miniMaxMusicGenerationTemplate 构建一个封闭的文本生成音乐合同。
func miniMaxMusicGenerationTemplate(identity systemModelIdentity) systemModelTemplate {
	maximumPrompt, maximumLyrics := int64(2000), int64(3500)
	evidence := miniMaxMusicEvidence()
	return systemModelTemplate{
		upstreamID: identity.upstreamID, displayName: identity.displayName, inputModalities: []string{"text"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnsupported, parallelTools: catalog.CapabilityUnsupported, streamingTools: catalog.CapabilityUnsupported, strictSchema: catalog.CapabilityUnsupported, entitlementMode: catalog.EntitlementAllBoundCredentials,
		operation: vcp.OperationMusicGenerate, actionBindingID: providerminimax.MusicGenerateActionBindingID,
		mediaOutputs: []catalog.MediaOutputCapability{miniMaxMusicOutputCapability(evidence)},
		parameters: []catalog.ParameterDescriptor{
			{ID: "prompt", Kind: catalog.ParameterString, StringRange: &catalog.StringRange{MaximumLength: &maximumPrompt}},
			{ID: "lyrics", Kind: catalog.ParameterString, StringRange: &catalog.StringRange{MaximumLength: &maximumLyrics}},
			{ID: "instrumental", Kind: catalog.ParameterBoolean},
			{ID: "lyrics_optimizer", Kind: catalog.ParameterBoolean},
			{ID: "sample_rate", Kind: catalog.ParameterInteger, IntegerRange: &catalog.IntegerRange{Minimum: catalogInt64(1)}},
			{ID: "bitrate", Kind: catalog.ParameterInteger, IntegerRange: &catalog.IntegerRange{Minimum: catalogInt64(1)}},
			{ID: "channels", Kind: catalog.ParameterInteger, IntegerRange: &catalog.IntegerRange{Minimum: catalogInt64(1), Maximum: catalogInt64(2)}},
			{ID: "seed", Kind: catalog.ParameterInteger, IntegerRange: &catalog.IntegerRange{}},
			{ID: "watermark", Kind: catalog.ParameterBoolean},
			{ID: "output_format", Kind: catalog.ParameterFormat, AllowedValues: []string{"mp3", "wav", "pcm"}},
			{ID: "count", Kind: catalog.ParameterCount, IntegerRange: &catalog.IntegerRange{Minimum: catalogInt64(1), Maximum: catalogInt64(1)}},
		},
		parameterRules: []catalog.ParameterRule{{Kind: catalog.ParameterRuleForbids, ParameterID: "instrumental", RelatedParameterIDs: []string{"lyrics"}}},
		usageMetrics:   []catalog.UsageMetricCapability{{Unit: catalog.UsageUnitAudioMilliseconds, Accuracy: catalog.UsageExact}},
	}
}

// miniMaxMusicCoverPreparationTemplate builds the audio-to-private-feature preprocessing contract.
// miniMaxMusicCoverPreparationTemplate 构建音频到私有特征的预处理合同。
func miniMaxMusicCoverPreparationTemplate() systemModelTemplate {
	evidence := miniMaxMusicCoverPreparationEvidence()
	return systemModelTemplate{
		upstreamID: "music-cover", displayName: "MiniMax Music Cover Preparation", inputModalities: []string{"audio"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnsupported, parallelTools: catalog.CapabilityUnsupported, streamingTools: catalog.CapabilityUnsupported, strictSchema: catalog.CapabilityUnsupported, entitlementMode: catalog.EntitlementAllBoundCredentials,
		operation: vcp.OperationMusicCoverPrepare, actionBindingID: providerminimax.MusicCoverPrepareActionBindingID,
		mediaInputs:  []catalog.MediaInputCapability{{Kind: vcp.MediaAudio, Roles: []vcp.MediaInputRole{vcp.MediaRoleCoverReference}, Level: catalog.CapabilityNative, InteractionModes: []catalog.MediaInteractionMode{catalog.MediaInteractionOperationInput}, MediaOnlyPolicy: catalog.MediaOnlyNative, ClientWorkflows: []catalog.ClientResourceWorkflow{catalog.ClientWorkflowUploadThenReference, catalog.ClientWorkflowImportURLThenReference, catalog.ClientWorkflowImportBase64ThenReference, catalog.ClientWorkflowResolveInputPlan}, MaterializationModes: []catalog.UpstreamMaterializationMode{catalog.MaterializationInlineBase64, catalog.MaterializationDirectRemoteURL}, Common: catalog.CommonMediaLimits{MIMETypes: []string{"audio/mpeg", "audio/wav", "audio/flac"}, MaxItemBytes: catalog.OptionalLimit{Known: true, Value: 50 << 20}, MaxItems: catalog.OptionalLimit{Known: true, Value: 1}, AllowsRemoteURL: catalog.OptionalBool{Known: true, Value: true}}, Audio: &catalog.AudioMediaLimits{MaxDurationMilliseconds: catalog.OptionalLimit{Known: true, Value: 360000}, Encodings: []string{"mp3", "wav", "flac"}}, Compatibility: catalog.MediaCompatibility{ToolCalling: catalog.CapabilityUnsupported, Streaming: catalog.CapabilityUnsupported, Reasoning: catalog.CapabilityUnsupported, StructuredOutput: catalog.CapabilityUnsupported, RequiresText: false}, Evidence: evidence, EvidenceRevision: 1}},
		usageMetrics: []catalog.UsageMetricCapability{{Unit: catalog.UsageUnitAudioMilliseconds, Accuracy: catalog.UsageExact}},
	}
}

// miniMaxMusicCoverTemplate builds the prepared-feature-to-audio cover contract.
// miniMaxMusicCoverTemplate 构建已准备特征到音频的翻唱合同。
func miniMaxMusicCoverTemplate() systemModelTemplate {
	return miniMaxMusicCoverTemplateForIdentity(systemModelIdentity{upstreamID: "music-cover", displayName: "MiniMax Music Cover"})
}

// miniMaxMusicCoverTemplateForIdentity builds one exact prepared-feature cover model contract.
// miniMaxMusicCoverTemplateForIdentity 构建一个精确的已准备特征翻唱模型合同。
func miniMaxMusicCoverTemplateForIdentity(identity systemModelIdentity) systemModelTemplate {
	minimumPrompt, maximumPrompt := int64(10), int64(300)
	minimumLyrics, maximumLyrics := int64(10), int64(1000)
	evidence := miniMaxMusicEvidence()
	return systemModelTemplate{
		upstreamID: identity.upstreamID, displayName: identity.displayName, inputModalities: []string{"text", "audio"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnsupported, parallelTools: catalog.CapabilityUnsupported, streamingTools: catalog.CapabilityUnsupported, strictSchema: catalog.CapabilityUnsupported, entitlementMode: catalog.EntitlementAllBoundCredentials,
		operation: vcp.OperationMusicCover, actionBindingID: providerminimax.MusicCoverActionBindingID,
		mediaInputs:  []catalog.MediaInputCapability{{Kind: vcp.MediaAudio, Roles: []vcp.MediaInputRole{vcp.MediaRoleCoverReference}, Level: catalog.CapabilityNative, InteractionModes: []catalog.MediaInteractionMode{catalog.MediaInteractionOperationInput}, MediaOnlyPolicy: catalog.MediaOnlyUnsupported, ClientWorkflows: []catalog.ClientResourceWorkflow{catalog.ClientWorkflowUploadThenReference, catalog.ClientWorkflowImportURLThenReference, catalog.ClientWorkflowImportBase64ThenReference, catalog.ClientWorkflowResolveInputPlan}, MaterializationModes: []catalog.UpstreamMaterializationMode{catalog.MaterializationInlineBase64, catalog.MaterializationDirectRemoteURL}, Common: catalog.CommonMediaLimits{MIMETypes: []string{"audio/mpeg", "audio/wav", "audio/flac"}, MaxItemBytes: catalog.OptionalLimit{Known: true, Value: 50 << 20}, MaxItems: catalog.OptionalLimit{Known: true, Value: 1}, AllowsRemoteURL: catalog.OptionalBool{Known: true, Value: true}}, Audio: &catalog.AudioMediaLimits{MaxDurationMilliseconds: catalog.OptionalLimit{Known: true, Value: 360000}, Encodings: []string{"mp3", "wav", "flac"}}, Compatibility: catalog.MediaCompatibility{ToolCalling: catalog.CapabilityUnsupported, Streaming: catalog.CapabilityNative, Reasoning: catalog.CapabilityUnsupported, StructuredOutput: catalog.CapabilityUnsupported, RequiresText: true}, Evidence: evidence, EvidenceRevision: 1}},
		mediaOutputs: []catalog.MediaOutputCapability{miniMaxMusicOutputCapability(evidence)},
		parameters: []catalog.ParameterDescriptor{
			{ID: "preparation_id", Kind: catalog.ParameterString, StringRange: &catalog.StringRange{}},
			{ID: "prompt", Kind: catalog.ParameterString, Required: true, StringRange: &catalog.StringRange{MinimumLength: &minimumPrompt, MaximumLength: &maximumPrompt}},
			{ID: "lyrics", Kind: catalog.ParameterString, StringRange: &catalog.StringRange{MinimumLength: &minimumLyrics, MaximumLength: &maximumLyrics}},
			{ID: "output_format", Kind: catalog.ParameterFormat, AllowedValues: []string{"mp3", "wav", "pcm"}},
			{ID: "sample_rate", Kind: catalog.ParameterInteger, IntegerRange: &catalog.IntegerRange{Minimum: catalogInt64(1)}},
			{ID: "bitrate", Kind: catalog.ParameterInteger, IntegerRange: &catalog.IntegerRange{Minimum: catalogInt64(1)}},
			{ID: "channels", Kind: catalog.ParameterInteger, IntegerRange: &catalog.IntegerRange{Minimum: catalogInt64(1), Maximum: catalogInt64(2)}},
			{ID: "seed", Kind: catalog.ParameterInteger, IntegerRange: &catalog.IntegerRange{}},
			{ID: "watermark", Kind: catalog.ParameterBoolean},
		},
		parameterRules: []catalog.ParameterRule{{Kind: catalog.ParameterRuleRequires, ParameterID: "preparation_id", RelatedParameterIDs: []string{"lyrics"}}, {Kind: catalog.ParameterRuleRequires, ParameterID: "lyrics", RelatedParameterIDs: []string{"preparation_id"}}},
		usageMetrics:   []catalog.UsageMetricCapability{{Unit: catalog.UsageUnitAudioMilliseconds, Accuracy: catalog.UsageExact}},
	}
}

// miniMaxMusicOutputCapability returns the synchronous single-audio output contract.
// miniMaxMusicOutputCapability 返回同步单音频输出合同。
func miniMaxMusicOutputCapability(evidence []catalog.CapabilityEvidence) catalog.MediaOutputCapability {
	return catalog.MediaOutputCapability{Kind: vcp.MediaAudio, Level: catalog.CapabilityNative, Formats: []string{"mp3", "wav", "pcm"}, MaxOutputs: catalog.OptionalLimit{Known: true, Value: 1}, Audio: &catalog.AudioMediaLimits{MaxSampleRateHz: catalog.OptionalLimit{Known: true, Value: 44100}, MaxChannels: catalog.OptionalLimit{Known: true, Value: 2}, Encodings: []string{"mp3", "wav", "pcm"}}, Delivery: catalog.DeliveryCapabilities{Synchronous: true, Streaming: true, PartialResults: true, Cancellation: true}, Evidence: evidence, EvidenceRevision: 1}
}

// miniMaxMusicEvidence returns the official generation contract evidence.
// miniMaxMusicEvidence 返回官方生成合同证据。
func miniMaxMusicEvidence() []catalog.CapabilityEvidence {
	return []catalog.CapabilityEvidence{{Source: catalog.ModelSourceProviderAPI, Reference: "https://platform.minimax.io/docs/api-reference/music-generation", ObservedAt: mediaEvidenceObservedAt(), Revision: 1}}
}

// miniMaxMusicCoverPreparationEvidence returns the official preprocessing contract evidence.
// miniMaxMusicCoverPreparationEvidence 返回官方预处理合同证据。
func miniMaxMusicCoverPreparationEvidence() []catalog.CapabilityEvidence {
	return []catalog.CapabilityEvidence{{Source: catalog.ModelSourceProviderAPI, Reference: "https://platform.minimax.io/docs/api-reference/music-cover-preprocess", ObservedAt: mediaEvidenceObservedAt(), Revision: 1}}
}
