package management

import (
	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	provideralibaba "github.com/OpenVulcan/vulcan-model-core/internal/provider/alibaba"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// alibabaHappyHorseModels returns the four CN-native HappyHorse operations copied from Bailian CLI.
// alibabaHappyHorseModels 返回从百炼 CLI 复制的四个 CN 原生 HappyHorse 操作。
func alibabaHappyHorseModels() []systemModelTemplate {
	// evidence records the upstream implementation and catalog facts used to close these profiles.
	// evidence 记录用于封闭这些 Profile 的上游实现与目录事实。
	evidence := []catalog.CapabilityEvidence{{Source: catalog.ModelSourceProviderAPI, Reference: "https://help.aliyun.com/zh/model-studio/video-generation-api-reference", ObservedAt: mediaEvidenceObservedAt(), Revision: 1}}
	// output is the shared asynchronous MP4 delivery contract.
	// output 是共享的异步 MP4 交付合同。
	output := catalog.MediaOutputCapability{Kind: vcp.MediaVideo, Level: catalog.CapabilityNative, Formats: []string{"mp4"}, MaxOutputs: catalog.OptionalLimit{Known: true, Value: 1}, Video: &catalog.VideoMediaLimits{Containers: []string{"mp4"}}, Delivery: catalog.DeliveryCapabilities{Asynchronous: true, Polling: true, Cancellation: true}, Evidence: evidence, EvidenceRevision: 1}
	// commonParameters contains only generation controls present in the copied wire request.
	// commonParameters 仅包含复制 Wire 请求中存在的生成控制项。
	minimumGenerationDuration, defaultDuration := 1.0, 5.0
	commonParameters := append(happyHorseCommonParameters(), catalog.ParameterDescriptor{ID: "duration_seconds", Kind: catalog.ParameterDuration, FloatRange: &catalog.FloatRange{Minimum: &minimumGenerationDuration}, Default: &catalog.ParameterDefault{Source: catalog.ParameterDefaultProvider, Float: &defaultDuration}})
	common := systemModelTemplate{reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnsupported, parallelTools: catalog.CapabilityUnsupported, streamingTools: catalog.CapabilityUnsupported, strictSchema: catalog.CapabilityUnsupported, entitlementMode: catalog.EntitlementAllBoundCredentials, operation: vcp.OperationVideoGenerate, actionBindingID: provideralibaba.HappyHorseVideoGenerateActionBindingID, mediaOutputs: []catalog.MediaOutputCapability{output}, parameters: commonParameters, usageMetrics: []catalog.UsageMetricCapability{{Unit: catalog.UsageUnitVideoMilliseconds, Accuracy: catalog.UsageExact}}}

	t2v := common
	t2v.upstreamID = "happyhorse-1.1-t2v"
	t2v.displayName = "HappyHorse 1.1 Text to Video"
	t2v.inputModalities = []string{"text"}

	i2v := common
	i2v.upstreamID = "happyhorse-1.1-i2v"
	i2v.displayName = "HappyHorse 1.1 Image to Video"
	i2v.inputModalities = []string{"text", "image"}
	i2v.mediaInputs = []catalog.MediaInputCapability{happyHorseImageInput([]vcp.MediaInputRole{vcp.MediaRoleFirstFrame}, 1, evidence)}

	r2v := common
	r2v.upstreamID = "happyhorse-1.1-r2v"
	r2v.displayName = "HappyHorse 1.1 Reference to Video"
	r2v.inputModalities = []string{"text", "image", "video", "audio"}
	r2v.mediaInputs = []catalog.MediaInputCapability{
		happyHorseImageInput([]vcp.MediaInputRole{vcp.MediaRoleReference}, 9, evidence),
		happyHorseRemoteInput(vcp.MediaVideo, []vcp.MediaInputRole{vcp.MediaRoleReference}, []string{"video/mp4", "video/quicktime"}, evidence),
		happyHorseRemoteInput(vcp.MediaAudio, []vcp.MediaInputRole{vcp.MediaRoleReferenceVoice}, []string{"audio/mpeg", "audio/wav", "audio/mp4", "audio/aac", "audio/flac"}, evidence),
	}

	edit := common
	edit.upstreamID = "happyhorse-1.0-video-edit"
	edit.displayName = "HappyHorse 1.0 Video Edit"
	edit.inputModalities = []string{"text", "video", "image"}
	edit.operation = vcp.OperationVideoEdit
	edit.actionBindingID = provideralibaba.HappyHorseVideoEditActionBindingID
	edit.mediaInputs = []catalog.MediaInputCapability{
		happyHorseRemoteInput(vcp.MediaVideo, []vcp.MediaInputRole{vcp.MediaRoleEditSource}, []string{"video/mp4", "video/quicktime"}, evidence),
		happyHorseImageInput([]vcp.MediaInputRole{vcp.MediaRoleReference}, 4, evidence),
	}
	minimumDuration, maximumDuration := 2.0, 10.0
	edit.parameters = append(happyHorseCommonParameters(),
		catalog.ParameterDescriptor{ID: "duration_seconds", Kind: catalog.ParameterDuration, FloatRange: &catalog.FloatRange{Minimum: &minimumDuration, Maximum: &maximumDuration}},
		catalog.ParameterDescriptor{ID: "audio_mode", Kind: catalog.ParameterEnum, AllowedValues: []string{string(vcp.VideoAudioAuto), string(vcp.VideoAudioOrigin)}},
	)
	edit.mediaOutputs = []catalog.MediaOutputCapability{output}
	edit.mediaOutputs[0].Video = &catalog.VideoMediaLimits{MaxDurationMilliseconds: catalog.OptionalLimit{Known: true, Value: 10000}, Containers: []string{"mp4"}}
	return []systemModelTemplate{t2v, i2v, r2v, edit}
}

// alibabaHappyHorsePlanModels returns only the three HappyHorse 1.1 generation models explicitly included by CN Token Plans.
// alibabaHappyHorsePlanModels 仅返回中国站 Token Plan 明确包含的三个 HappyHorse 1.1 生成模型。
func alibabaHappyHorsePlanModels() []systemModelTemplate {
	allModels := alibabaHappyHorseModels()
	planModels := make([]systemModelTemplate, 0, 3)
	for _, model := range allModels {
		if model.operation == vcp.OperationVideoGenerate && model.upstreamID != "happyhorse-1.0-video-edit" {
			planModels = append(planModels, model)
		}
	}
	return planModels
}

// happyHorseCommonParameters returns fields shared by generation and editing except duration and audio mode.
// happyHorseCommonParameters 返回生成与编辑共享且不含时长和音频模式的字段。
func happyHorseCommonParameters() []catalog.ParameterDescriptor {
	minimumSeed := int64(0)
	return []catalog.ParameterDescriptor{
		{ID: "negative_prompt", Kind: catalog.ParameterString, StringRange: &catalog.StringRange{}},
		{ID: "resolution", Kind: catalog.ParameterEnum, AllowedValues: []string{"720P", "1080P"}},
		{ID: "aspect_ratio", Kind: catalog.ParameterEnum, AllowedValues: []string{"16:9", "9:16", "1:1", "4:3", "3:4"}},
		{ID: "seed", Kind: catalog.ParameterInteger, IntegerRange: &catalog.IntegerRange{Minimum: &minimumSeed}},
		{ID: "prompt_extend", Kind: catalog.ParameterBoolean},
		{ID: "watermark", Kind: catalog.ParameterBoolean},
	}
}

// happyHorseImageInput returns one exact image role with CN inline, URL, and temporary OSS paths.
// happyHorseImageInput 返回一个具有 CN 内联、URL 与临时 OSS 路径的精确图片角色。
func happyHorseImageInput(roles []vcp.MediaInputRole, maximumItems int64, evidence []catalog.CapabilityEvidence) catalog.MediaInputCapability {
	maximum := catalog.OptionalLimit{}
	if maximumItems > 0 {
		maximum = catalog.OptionalLimit{Known: true, Value: maximumItems}
	}
	return catalog.MediaInputCapability{Kind: vcp.MediaImage, Roles: append([]vcp.MediaInputRole(nil), roles...), Level: catalog.CapabilityNative, InteractionModes: []catalog.MediaInteractionMode{catalog.MediaInteractionOperationInput}, MediaOnlyPolicy: catalog.MediaOnlyNative, ClientWorkflows: []catalog.ClientResourceWorkflow{catalog.ClientWorkflowUploadThenReference, catalog.ClientWorkflowImportURLThenReference, catalog.ClientWorkflowImportBase64ThenReference, catalog.ClientWorkflowResolveInputPlan}, MaterializationModes: []catalog.UpstreamMaterializationMode{catalog.MaterializationInlineBase64, catalog.MaterializationDirectRemoteURL, catalog.MaterializationProviderObjectURI}, Common: catalog.CommonMediaLimits{MIMETypes: []string{"image/jpeg", "image/png", "image/webp"}, MaxItems: maximum, AllowsRemoteURL: catalog.OptionalBool{Known: true, Value: true}}, Image: &catalog.ImageMediaLimits{}, Compatibility: happyHorseMediaCompatibility(), Evidence: append([]catalog.CapabilityEvidence(nil), evidence...), EvidenceRevision: 1}
}

// happyHorseRemoteInput returns one URL-or-OSS video or audio role.
// happyHorseRemoteInput 返回一个 URL 或 OSS 视频、音频角色。
func happyHorseRemoteInput(kind vcp.MediaKind, roles []vcp.MediaInputRole, mimeTypes []string, evidence []catalog.CapabilityEvidence) catalog.MediaInputCapability {
	input := catalog.MediaInputCapability{Kind: kind, Roles: append([]vcp.MediaInputRole(nil), roles...), Level: catalog.CapabilityNative, InteractionModes: []catalog.MediaInteractionMode{catalog.MediaInteractionOperationInput}, MediaOnlyPolicy: catalog.MediaOnlyNative, ClientWorkflows: []catalog.ClientResourceWorkflow{catalog.ClientWorkflowUploadThenReference, catalog.ClientWorkflowImportURLThenReference, catalog.ClientWorkflowResolveInputPlan}, MaterializationModes: []catalog.UpstreamMaterializationMode{catalog.MaterializationDirectRemoteURL, catalog.MaterializationProviderObjectURI}, Common: catalog.CommonMediaLimits{MIMETypes: append([]string(nil), mimeTypes...), AllowsRemoteURL: catalog.OptionalBool{Known: true, Value: true}}, Compatibility: happyHorseMediaCompatibility(), Evidence: append([]catalog.CapabilityEvidence(nil), evidence...), EvidenceRevision: 1}
	if kind == vcp.MediaVideo {
		input.Video = &catalog.VideoMediaLimits{Containers: []string{"mp4", "mov"}, EmbeddedAudio: catalog.OptionalBool{Known: true, Value: true}}
	} else {
		input.Audio = &catalog.AudioMediaLimits{}
	}
	return input
}

// happyHorseMediaCompatibility closes conversation-only features for standalone video tasks.
// happyHorseMediaCompatibility 为独立视频任务封闭会话专属特性。
func happyHorseMediaCompatibility() catalog.MediaCompatibility {
	return catalog.MediaCompatibility{ToolCalling: catalog.CapabilityUnsupported, Streaming: catalog.CapabilityUnsupported, Reasoning: catalog.CapabilityUnsupported, StructuredOutput: catalog.CapabilityUnsupported}
}
