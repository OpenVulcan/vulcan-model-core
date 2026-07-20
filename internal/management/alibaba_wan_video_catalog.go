package management

import (
	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	provideralibaba "github.com/OpenVulcan/vulcan-model-core/internal/provider/alibaba"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// alibabaWanVideoModels returns workspace-only Wan 2.7 text-to-video and image-to-video templates.
// alibabaWanVideoModels 返回仅工作空间可用的 Wan 2.7 文生视频与图生视频模板。
func alibabaWanVideoModels() []systemModelTemplate {
	minimumDuration, maximumDuration, defaultDuration := 2.0, 15.0, 5.0
	minimumSeed, maximumSeed := int64(0), int64(2147483647)
	evidence := []catalog.CapabilityEvidence{{Source: catalog.ModelSourceProviderAPI, Reference: "https://help.aliyun.com/en/model-studio/text-to-video-api-reference", ObservedAt: mediaEvidenceObservedAt(), Revision: 1}}
	models := []systemModelTemplate{{
		upstreamID: "wan2.7-t2v", displayName: "Wan 2.7 Text to Video", inputModalities: []string{"text", "audio"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnsupported, parallelTools: catalog.CapabilityUnsupported, streamingTools: catalog.CapabilityUnsupported, strictSchema: catalog.CapabilityUnsupported, entitlementMode: catalog.EntitlementAllBoundCredentials,
		operation: vcp.OperationVideoGenerate, actionBindingID: provideralibaba.WanVideoGenerateActionBindingID,
		mediaInputs:  []catalog.MediaInputCapability{{Kind: vcp.MediaAudio, Roles: []vcp.MediaInputRole{vcp.MediaRoleAudioTrack}, Level: catalog.CapabilityNative, InteractionModes: []catalog.MediaInteractionMode{catalog.MediaInteractionOperationInput}, MediaOnlyPolicy: catalog.MediaOnlyUnsupported, ClientWorkflows: []catalog.ClientResourceWorkflow{catalog.ClientWorkflowImportURLThenReference, catalog.ClientWorkflowResolveInputPlan}, MaterializationModes: []catalog.UpstreamMaterializationMode{catalog.MaterializationDirectRemoteURL}, Common: catalog.CommonMediaLimits{MIMETypes: []string{"audio/mpeg", "audio/wav"}, MaxItemBytes: catalog.OptionalLimit{Known: true, Value: 15 << 20}, MaxItems: catalog.OptionalLimit{Known: true, Value: 1}, AllowsRemoteURL: catalog.OptionalBool{Known: true, Value: true}}, Audio: &catalog.AudioMediaLimits{MaxDurationMilliseconds: catalog.OptionalLimit{Known: true, Value: 30000}}, Compatibility: catalog.MediaCompatibility{ToolCalling: catalog.CapabilityUnsupported, Streaming: catalog.CapabilityUnsupported, Reasoning: catalog.CapabilityUnsupported, StructuredOutput: catalog.CapabilityUnsupported, RequiresText: true}, Evidence: evidence, EvidenceRevision: 1}},
		mediaOutputs: []catalog.MediaOutputCapability{{Kind: vcp.MediaVideo, Level: catalog.CapabilityNative, Formats: []string{"mp4"}, MaxOutputs: catalog.OptionalLimit{Known: true, Value: 1}, Video: &catalog.VideoMediaLimits{MaxDurationMilliseconds: catalog.OptionalLimit{Known: true, Value: 15000}, MaxWidth: catalog.OptionalLimit{Known: true, Value: 1920}, MaxHeight: catalog.OptionalLimit{Known: true, Value: 1920}, MaxFPS: catalog.OptionalLimit{Known: true, Value: 30}, Containers: []string{"mp4"}, Codecs: []string{"h264"}, EmbeddedAudio: catalog.OptionalBool{Known: true, Value: true}}, Delivery: catalog.DeliveryCapabilities{Asynchronous: true, Polling: true, Cancellation: true}, Evidence: evidence, EvidenceRevision: 1}},
		parameters: []catalog.ParameterDescriptor{
			{ID: "duration_seconds", Kind: catalog.ParameterDuration, FloatRange: &catalog.FloatRange{Minimum: &minimumDuration, Maximum: &maximumDuration}, Default: &catalog.ParameterDefault{Source: catalog.ParameterDefaultProvider, Float: &defaultDuration}},
			{ID: "resolution", Kind: catalog.ParameterEnum, AllowedValues: []string{"720P", "1080P"}},
			{ID: "aspect_ratio", Kind: catalog.ParameterEnum, AllowedValues: []string{"16:9", "9:16", "1:1", "4:3", "3:4"}},
			{ID: "seed", Kind: catalog.ParameterInteger, IntegerRange: &catalog.IntegerRange{Minimum: &minimumSeed, Maximum: &maximumSeed}},
			{ID: "watermark", Kind: catalog.ParameterBoolean},
			{ID: "prompt_extend", Kind: catalog.ParameterBoolean},
		},
		usageMetrics: []catalog.UsageMetricCapability{{Unit: catalog.UsageUnitVideoMilliseconds, Accuracy: catalog.UsageExact}},
	}}
	imageVideoEvidence := []catalog.CapabilityEvidence{{Source: catalog.ModelSourceProviderAPI, Reference: "https://www.alibabacloud.com/help/en/model-studio/image-to-video-general-api-reference", ObservedAt: mediaEvidenceObservedAt(), Revision: 1}}
	models = append(models, systemModelTemplate{
		upstreamID: "wan2.7-i2v", displayName: "Wan 2.7 Image to Video", inputModalities: []string{"text", "image", "audio"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnsupported, parallelTools: catalog.CapabilityUnsupported, streamingTools: catalog.CapabilityUnsupported, strictSchema: catalog.CapabilityUnsupported, entitlementMode: catalog.EntitlementAllBoundCredentials,
		operation: vcp.OperationVideoGenerate, actionBindingID: provideralibaba.WanVideoGenerateActionBindingID,
		mediaInputs: []catalog.MediaInputCapability{
			{Kind: vcp.MediaImage, Roles: []vcp.MediaInputRole{vcp.MediaRoleFirstFrame, vcp.MediaRoleLastFrame}, Level: catalog.CapabilityNative, InteractionModes: []catalog.MediaInteractionMode{catalog.MediaInteractionOperationInput}, MediaOnlyPolicy: catalog.MediaOnlyNative, ClientWorkflows: []catalog.ClientResourceWorkflow{catalog.ClientWorkflowUploadThenReference, catalog.ClientWorkflowImportURLThenReference, catalog.ClientWorkflowResolveInputPlan}, MaterializationModes: []catalog.UpstreamMaterializationMode{catalog.MaterializationInlineBase64, catalog.MaterializationDirectRemoteURL}, Common: catalog.CommonMediaLimits{MIMETypes: []string{"image/jpeg", "image/png", "image/bmp", "image/webp"}, MaxItemBytes: catalog.OptionalLimit{Known: true, Value: 20 << 20}, MaxItems: catalog.OptionalLimit{Known: true, Value: 2}, AllowsRemoteURL: catalog.OptionalBool{Known: true, Value: true}}, Image: &catalog.ImageMediaLimits{MinWidth: catalog.OptionalLimit{Known: true, Value: 240}, MinHeight: catalog.OptionalLimit{Known: true, Value: 240}, MaxWidth: catalog.OptionalLimit{Known: true, Value: 8000}, MaxHeight: catalog.OptionalLimit{Known: true, Value: 8000}}, Compatibility: catalog.MediaCompatibility{ToolCalling: catalog.CapabilityUnsupported, Streaming: catalog.CapabilityUnsupported, Reasoning: catalog.CapabilityUnsupported, StructuredOutput: catalog.CapabilityUnsupported}, Evidence: imageVideoEvidence, EvidenceRevision: 1},
			{Kind: vcp.MediaAudio, Roles: []vcp.MediaInputRole{vcp.MediaRoleAudioTrack}, Level: catalog.CapabilityNative, InteractionModes: []catalog.MediaInteractionMode{catalog.MediaInteractionOperationInput}, MediaOnlyPolicy: catalog.MediaOnlyUnsupported, ClientWorkflows: []catalog.ClientResourceWorkflow{catalog.ClientWorkflowImportURLThenReference, catalog.ClientWorkflowResolveInputPlan}, MaterializationModes: []catalog.UpstreamMaterializationMode{catalog.MaterializationDirectRemoteURL}, Common: catalog.CommonMediaLimits{MIMETypes: []string{"audio/mpeg", "audio/wav"}, MaxItemBytes: catalog.OptionalLimit{Known: true, Value: 15 << 20}, MaxItems: catalog.OptionalLimit{Known: true, Value: 1}, AllowsRemoteURL: catalog.OptionalBool{Known: true, Value: true}}, Audio: &catalog.AudioMediaLimits{MaxDurationMilliseconds: catalog.OptionalLimit{Known: true, Value: 30000}}, Compatibility: catalog.MediaCompatibility{ToolCalling: catalog.CapabilityUnsupported, Streaming: catalog.CapabilityUnsupported, Reasoning: catalog.CapabilityUnsupported, StructuredOutput: catalog.CapabilityUnsupported}, Evidence: imageVideoEvidence, EvidenceRevision: 1},
		},
		mediaOutputs: []catalog.MediaOutputCapability{{Kind: vcp.MediaVideo, Level: catalog.CapabilityNative, Formats: []string{"mp4"}, MaxOutputs: catalog.OptionalLimit{Known: true, Value: 1}, Video: &catalog.VideoMediaLimits{MaxDurationMilliseconds: catalog.OptionalLimit{Known: true, Value: 15000}, MaxWidth: catalog.OptionalLimit{Known: true, Value: 8000}, MaxHeight: catalog.OptionalLimit{Known: true, Value: 8000}, Containers: []string{"mp4"}, EmbeddedAudio: catalog.OptionalBool{Known: true, Value: true}}, Delivery: catalog.DeliveryCapabilities{Asynchronous: true, Polling: true, Cancellation: true}, Evidence: imageVideoEvidence, EvidenceRevision: 1}},
		parameters: []catalog.ParameterDescriptor{
			{ID: "duration_seconds", Kind: catalog.ParameterDuration, FloatRange: &catalog.FloatRange{Minimum: &minimumDuration, Maximum: &maximumDuration}, Default: &catalog.ParameterDefault{Source: catalog.ParameterDefaultProvider, Float: &defaultDuration}},
			{ID: "resolution", Kind: catalog.ParameterEnum, AllowedValues: []string{"720P", "1080P"}},
			{ID: "seed", Kind: catalog.ParameterInteger, IntegerRange: &catalog.IntegerRange{Minimum: &minimumSeed, Maximum: &maximumSeed}},
			{ID: "watermark", Kind: catalog.ParameterBoolean},
			{ID: "prompt_extend", Kind: catalog.ParameterBoolean},
		},
		usageMetrics: []catalog.UsageMetricCapability{{Unit: catalog.UsageUnitVideoMilliseconds, Accuracy: catalog.UsageExact}},
	})
	return models
}
