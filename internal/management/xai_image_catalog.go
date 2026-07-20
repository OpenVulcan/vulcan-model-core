package management

import (
	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	providerxai "github.com/OpenVulcan/vulcan-model-core/internal/provider/xai"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// xaiAPIModels returns the copied text catalog plus current Imagine image and video actions.
// xaiAPIModels 返回复制的文本目录及当前 Imagine 图片和视频动作。
func xaiAPIModels() []systemModelTemplate {
	models := copiedTextModels("xai", []systemModelIdentity{{"grok-build-0.1", "Grok Build 0.1", 256000}, {"grok-4.5", "Grok 4.5", 500000}, {"grok-4.3", "Grok 4.3", 1000000}, {"grok-4.20-0309-reasoning", "Grok 4.20 0309 Reasoning", 2000000}, {"grok-4.20-0309-non-reasoning", "Grok 4.20 0309 Non Reasoning", 2000000}, {"grok-4.20-multi-agent-0309", "Grok 4.20 Multi Agent 0309", 2000000}, {"grok-3-mini", "Grok 3 Mini", 131072}, {"grok-3-mini-fast", "Grok 3 Mini Fast", 131072}, {"grok-composer-2.5-fast", "Composer 2.5 Fast", 200000}})
	for _, identity := range []systemModelIdentity{{"grok-imagine-image", "Grok Imagine Image", 0}, {"grok-imagine-image-quality", "Grok Imagine Image Quality", 0}} {
		models = append(models,
			xaiImageTemplate(identity, vcp.OperationImageGenerate),
			xaiImageTemplate(identity, vcp.OperationImageEdit),
		)
	}
	models = append(models,
		xaiVideoTemplate(vcp.OperationVideoGenerate),
		xaiVideoTemplate(vcp.OperationVideoEdit),
		xaiVideoTemplate(vcp.OperationVideoExtend),
	)
	return models
}

// xaiVideoTemplate creates one operation-specific Imagine video template.
// xaiVideoTemplate 创建一个操作专属 Imagine 视频模板。
func xaiVideoTemplate(operation vcp.OperationKind) systemModelTemplate {
	template := systemModelTemplate{upstreamID: "grok-imagine-video", displayName: "Grok Imagine Video", inputModalities: []string{"text"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnsupported, parallelTools: catalog.CapabilityUnsupported, streamingTools: catalog.CapabilityUnsupported, strictSchema: catalog.CapabilityUnsupported, entitlementMode: catalog.EntitlementAllBoundCredentials, operation: operation, mediaOutputs: []catalog.MediaOutputCapability{xaiVideoOutputCapability()}, parameters: xaiVideoParameters(operation), usageMetrics: []catalog.UsageMetricCapability{{Unit: catalog.UsageUnitVideoMilliseconds, Accuracy: catalog.UsageExact}}}
	switch operation {
	case vcp.OperationVideoGenerate:
		template.actionBindingID = providerxai.VideoGenerateActionBindingID
		template.inputModalities = []string{"text", "image"}
		template.mediaInputs = []catalog.MediaInputCapability{xaiVideoInputCapability(vcp.MediaImage, []vcp.MediaInputRole{vcp.MediaRoleFirstFrame, vcp.MediaRoleReference}, 7, 0)}
	case vcp.OperationVideoEdit:
		template.actionBindingID = providerxai.VideoEditActionBindingID
		template.inputModalities = []string{"text", "video"}
		template.mediaInputs = []catalog.MediaInputCapability{xaiVideoInputCapability(vcp.MediaVideo, []vcp.MediaInputRole{vcp.MediaRoleEditSource}, 1, 8700)}
	case vcp.OperationVideoExtend:
		template.actionBindingID = providerxai.VideoExtendActionBindingID
		template.inputModalities = []string{"text", "video"}
		template.mediaInputs = []catalog.MediaInputCapability{xaiVideoInputCapability(vcp.MediaVideo, []vcp.MediaInputRole{vcp.MediaRoleEditSource}, 1, 15000)}
	}
	return template
}

// xaiVideoInputCapability returns one exact xAI inline, URL, or Files API input contract.
// xaiVideoInputCapability 返回一个精确的 xAI 内联、URL 或 Files API 输入合同。
func xaiVideoInputCapability(kind vcp.MediaKind, roles []vcp.MediaInputRole, maxItems int64, maxDurationMilliseconds int64) catalog.MediaInputCapability {
	capability := catalog.MediaInputCapability{Kind: kind, Roles: roles, Level: catalog.CapabilityNative, InteractionModes: []catalog.MediaInteractionMode{catalog.MediaInteractionOperationInput}, MediaOnlyPolicy: catalog.MediaOnlyUnsupported, ClientWorkflows: []catalog.ClientResourceWorkflow{catalog.ClientWorkflowUploadThenReference, catalog.ClientWorkflowImportURLThenReference, catalog.ClientWorkflowImportBase64ThenReference, catalog.ClientWorkflowResolveInputPlan}, MaterializationModes: []catalog.UpstreamMaterializationMode{catalog.MaterializationInlineBase64, catalog.MaterializationDirectRemoteURL, catalog.MaterializationProviderFileID}, Common: catalog.CommonMediaLimits{MaxItems: catalog.OptionalLimit{Known: true, Value: maxItems}, AllowsRemoteURL: catalog.OptionalBool{Known: true, Value: true}}, Compatibility: catalog.MediaCompatibility{ToolCalling: catalog.CapabilityUnsupported, Streaming: catalog.CapabilityUnsupported, Reasoning: catalog.CapabilityUnsupported, StructuredOutput: catalog.CapabilityUnsupported, RequiresText: true}, Evidence: []catalog.CapabilityEvidence{{Source: catalog.ModelSourceProviderAPI, Reference: "https://docs.x.ai/developers/model-capabilities/video/generation", ObservedAt: mediaEvidenceObservedAt(), Revision: 1}}, EvidenceRevision: 1}
	if kind == vcp.MediaImage {
		capability.Common.MIMETypes = []string{"image/png", "image/jpeg", "image/webp"}
		capability.Image = &catalog.ImageMediaLimits{}
	} else {
		capability.Common.MIMETypes = []string{"video/mp4"}
		capability.Video = &catalog.VideoMediaLimits{MaxDurationMilliseconds: catalog.OptionalLimit{Known: true, Value: maxDurationMilliseconds}, Containers: []string{"mp4"}, EmbeddedAudio: catalog.OptionalBool{Known: true, Value: true}}
	}
	return capability
}

// xaiVideoOutputCapability returns the asynchronous MP4 Imagine output contract.
// xaiVideoOutputCapability 返回异步 MP4 Imagine 输出合同。
func xaiVideoOutputCapability() catalog.MediaOutputCapability {
	return catalog.MediaOutputCapability{Kind: vcp.MediaVideo, Level: catalog.CapabilityNative, Formats: []string{"mp4"}, MaxOutputs: catalog.OptionalLimit{Known: true, Value: 1}, Video: &catalog.VideoMediaLimits{MaxDurationMilliseconds: catalog.OptionalLimit{Known: true, Value: 25000}, MaxWidth: catalog.OptionalLimit{Known: true, Value: 1920}, MaxHeight: catalog.OptionalLimit{Known: true, Value: 1920}, Containers: []string{"mp4"}, EmbeddedAudio: catalog.OptionalBool{Known: false}}, Delivery: catalog.DeliveryCapabilities{Asynchronous: true, Polling: true}, Evidence: []catalog.CapabilityEvidence{{Source: catalog.ModelSourceProviderAPI, Reference: "https://docs.x.ai/developers/model-capabilities/video/generation", ObservedAt: mediaEvidenceObservedAt(), Revision: 1}}, EvidenceRevision: 1}
}

// xaiVideoParameters returns only documented controls represented by VCP for each operation.
// xaiVideoParameters 为每个操作仅返回 VCP 可表示且文档明确的控制项。
func xaiVideoParameters(operation vcp.OperationKind) []catalog.ParameterDescriptor {
	minimumDuration, maximumDuration := float64(1), float64(15)
	parameters := []catalog.ParameterDescriptor{{ID: "duration_seconds", Kind: catalog.ParameterDuration, FloatRange: &catalog.FloatRange{Minimum: &minimumDuration, Maximum: &maximumDuration}}, {ID: "aspect_ratio", Kind: catalog.ParameterEnum, AllowedValues: []string{"1:1", "16:9", "9:16", "4:3", "3:4", "3:2", "2:3"}}, {ID: "resolution", Kind: catalog.ParameterEnum, AllowedValues: []string{"480p", "720p"}}, {ID: "output_format", Kind: catalog.ParameterFormat, AllowedValues: []string{"mp4"}}}
	if operation == vcp.OperationVideoEdit {
		return []catalog.ParameterDescriptor{{ID: "output_format", Kind: catalog.ParameterFormat, AllowedValues: []string{"mp4"}}}
	}
	if operation == vcp.OperationVideoExtend {
		minimumDuration, maximumDuration = 2, 10
		return []catalog.ParameterDescriptor{{ID: "additional_duration_seconds", Kind: catalog.ParameterDuration, FloatRange: &catalog.FloatRange{Minimum: &minimumDuration, Maximum: &maximumDuration}}, {ID: "output_format", Kind: catalog.ParameterFormat, AllowedValues: []string{"mp4"}}}
	}
	return parameters
}

// xaiImageTemplate creates one operation-specific Imagine image template.
// xaiImageTemplate 创建一个操作专属 Imagine 图片模板。
func xaiImageTemplate(identity systemModelIdentity, operation vcp.OperationKind) systemModelTemplate {
	template := systemModelTemplate{upstreamID: identity.upstreamID, displayName: identity.displayName, inputModalities: []string{"text"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnsupported, parallelTools: catalog.CapabilityUnsupported, streamingTools: catalog.CapabilityUnsupported, strictSchema: catalog.CapabilityUnsupported, entitlementMode: catalog.EntitlementAllBoundCredentials, operation: operation, mediaOutputs: []catalog.MediaOutputCapability{xaiImageOutputCapability()}, parameters: xaiImageParameters(operation), usageMetrics: []catalog.UsageMetricCapability{{Unit: catalog.UsageUnitImages, Accuracy: catalog.UsageExact}}}
	if operation == vcp.OperationImageEdit {
		template.displayName += " Edit"
		template.inputModalities = []string{"text", "image"}
		template.mediaInputs = []catalog.MediaInputCapability{xaiImageEditCapability()}
	}
	return template
}

// xaiImageEditCapability returns the documented one-to-three image edit contract.
// xaiImageEditCapability 返回文档明确的一至三张图片编辑合同。
func xaiImageEditCapability() catalog.MediaInputCapability {
	return catalog.MediaInputCapability{Kind: vcp.MediaImage, Roles: []vcp.MediaInputRole{vcp.MediaRoleEditSource}, Level: catalog.CapabilityNative, InteractionModes: []catalog.MediaInteractionMode{catalog.MediaInteractionOperationInput}, MediaOnlyPolicy: catalog.MediaOnlyUnsupported, ClientWorkflows: []catalog.ClientResourceWorkflow{catalog.ClientWorkflowUploadThenReference, catalog.ClientWorkflowImportURLThenReference, catalog.ClientWorkflowImportBase64ThenReference, catalog.ClientWorkflowResolveInputPlan}, MaterializationModes: []catalog.UpstreamMaterializationMode{catalog.MaterializationInlineBase64, catalog.MaterializationDirectRemoteURL}, Common: catalog.CommonMediaLimits{MIMETypes: []string{"image/png", "image/jpeg"}, MaxItems: catalog.OptionalLimit{Known: true, Value: 3}, AllowsRemoteURL: catalog.OptionalBool{Known: true, Value: true}}, Image: &catalog.ImageMediaLimits{}, Compatibility: catalog.MediaCompatibility{ToolCalling: catalog.CapabilityUnsupported, Streaming: catalog.CapabilityUnsupported, Reasoning: catalog.CapabilityUnsupported, StructuredOutput: catalog.CapabilityUnsupported, RequiresText: true}, Evidence: []catalog.CapabilityEvidence{{Source: catalog.ModelSourceProviderAPI, Reference: "https://docs.x.ai/developers/model-capabilities/images/multi-image-editing", ObservedAt: mediaEvidenceObservedAt(), Revision: 1}}, EvidenceRevision: 1}
}

// xaiImageOutputCapability returns the synchronous JPEG Imagine output contract.
// xaiImageOutputCapability 返回同步 JPEG Imagine 输出合同。
func xaiImageOutputCapability() catalog.MediaOutputCapability {
	return catalog.MediaOutputCapability{Kind: vcp.MediaImage, Level: catalog.CapabilityNative, Formats: []string{"jpeg"}, Image: &catalog.ImageMediaLimits{}, Delivery: catalog.DeliveryCapabilities{Synchronous: true}, Evidence: []catalog.CapabilityEvidence{{Source: catalog.ModelSourceProviderAPI, Reference: "https://docs.x.ai/developers/rest-api-reference/inference/images", ObservedAt: mediaEvidenceObservedAt(), Revision: 1}}, EvidenceRevision: 1}
}

// xaiImageParameters returns only documented controls represented by VCP.
// xaiImageParameters 仅返回 VCP 可表示且文档明确的控制项。
func xaiImageParameters(operation vcp.OperationKind) []catalog.ParameterDescriptor {
	minimumCount, defaultCount := int64(1), int64(1)
	parameters := []catalog.ParameterDescriptor{{ID: "count", Kind: catalog.ParameterCount, IntegerRange: &catalog.IntegerRange{Minimum: &minimumCount}, Default: &catalog.ParameterDefault{Source: catalog.ParameterDefaultProvider, Integer: &defaultCount}}, {ID: "aspect_ratio", Kind: catalog.ParameterEnum, AllowedValues: []string{"auto", "1:1", "16:9", "9:16", "4:3", "3:4", "3:2", "2:3", "2:1", "1:2", "19.5:9", "9:19.5", "20:9", "9:20"}}, {ID: "resolution", Kind: catalog.ParameterEnum, AllowedValues: []string{"1k", "2k"}}, {ID: "output_format", Kind: catalog.ParameterFormat, AllowedValues: []string{"jpeg"}}}
	if operation == vcp.OperationImageEdit {
		maximumCount := int64(1)
		parameters[0].IntegerRange.Maximum = &maximumCount
	}
	return parameters
}
