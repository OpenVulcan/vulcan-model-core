package management

import (
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// openAIImageUnderstandingCapability returns the official Responses image-input contract used by the fixed OpenAI model.
// openAIImageUnderstandingCapability 返回固定 OpenAI 模型使用的官方 Responses 图片输入合同。
func openAIImageUnderstandingCapability() catalog.MediaInputCapability {
	return catalog.MediaInputCapability{
		Kind: vcp.MediaImage, Roles: []vcp.MediaInputRole{vcp.MediaRoleUnderstanding}, Level: catalog.CapabilityNative,
		InteractionModes: []catalog.MediaInteractionMode{catalog.MediaInteractionMixedConversation, catalog.MediaInteractionMediaOnlyConversation}, MediaOnlyPolicy: catalog.MediaOnlyRouterInstruction,
		AllowedAuthorities: []vcp.Authority{vcp.AuthorityUser}, AllowedPlacements: []vcp.Placement{vcp.PlacementTranscript},
		ClientWorkflows:      []catalog.ClientResourceWorkflow{catalog.ClientWorkflowUploadThenReference, catalog.ClientWorkflowImportURLThenReference, catalog.ClientWorkflowImportBase64ThenReference, catalog.ClientWorkflowResolveInputPlan},
		MaterializationModes: []catalog.UpstreamMaterializationMode{catalog.MaterializationInlineBase64, catalog.MaterializationProviderFileID},
		Common:               catalog.CommonMediaLimits{MIMETypes: []string{"image/jpeg", "image/png", "image/gif", "image/webp"}}, Image: &catalog.ImageMediaLimits{},
		Compatibility: catalog.MediaCompatibility{ToolCalling: catalog.CapabilityNative, Streaming: catalog.CapabilityNative, Reasoning: catalog.CapabilityNative, StructuredOutput: catalog.CapabilityNative},
		Evidence:      []catalog.CapabilityEvidence{{Source: catalog.ModelSourceProviderAPI, Reference: "https://platform.openai.com/docs/guides/images-vision", ObservedAt: mediaEvidenceObservedAt(), Revision: 1}}, EvidenceRevision: 1,
	}
}

// openAIImageEditCapabilities returns separate source and mask contracts with exact cross-role requirements.
// openAIImageEditCapabilities 返回具有精确跨角色要求的独立来源与遮罩合同。
func openAIImageEditCapabilities() []catalog.MediaInputCapability {
	common := catalog.MediaInputCapability{
		Kind: vcp.MediaImage, Level: catalog.CapabilityNative, InteractionModes: []catalog.MediaInteractionMode{catalog.MediaInteractionOperationInput}, MediaOnlyPolicy: catalog.MediaOnlyUnsupported,
		ClientWorkflows: []catalog.ClientResourceWorkflow{catalog.ClientWorkflowUploadThenReference, catalog.ClientWorkflowImportURLThenReference, catalog.ClientWorkflowImportBase64ThenReference, catalog.ClientWorkflowResolveInputPlan}, MaterializationModes: []catalog.UpstreamMaterializationMode{catalog.MaterializationInlineBase64},
		Compatibility: catalog.MediaCompatibility{ToolCalling: catalog.CapabilityUnsupported, Streaming: catalog.CapabilityUnsupported, Reasoning: catalog.CapabilityUnsupported, StructuredOutput: catalog.CapabilityUnsupported},
		Evidence:      []catalog.CapabilityEvidence{{Source: catalog.ModelSourceProviderAPI, Reference: "https://developers.openai.com/api/docs/guides/image-generation", ObservedAt: mediaEvidenceObservedAt(), Revision: 1}}, EvidenceRevision: 1,
	}
	source := common
	source.Roles = []vcp.MediaInputRole{vcp.MediaRoleEditSource}
	source.Common = catalog.CommonMediaLimits{MIMETypes: []string{"image/png", "image/jpeg", "image/webp"}, MaxItemBytes: catalog.OptionalLimit{Known: true, Value: 50 << 20}}
	source.Image = &catalog.ImageMediaLimits{}
	mask := common
	mask.Roles = []vcp.MediaInputRole{vcp.MediaRoleMask}
	mask.Common = catalog.CommonMediaLimits{MIMETypes: []string{"image/png", "image/webp"}, MaxItemBytes: catalog.OptionalLimit{Known: true, Value: 50 << 20}, MaxItems: catalog.OptionalLimit{Known: true, Value: 1}}
	mask.Image = &catalog.ImageMediaLimits{RequiresAlpha: true, MustMatchFormatAndDimensionsOfRole: vcp.MediaRoleEditSource}
	return []catalog.MediaInputCapability{source, mask}
}

// openAIImageOutputCapability returns the official GPT Image output formats and dimensions.
// openAIImageOutputCapability 返回官方 GPT Image 输出格式与尺寸。
func openAIImageOutputCapability() catalog.MediaOutputCapability {
	return catalog.MediaOutputCapability{
		Kind: vcp.MediaImage, Level: catalog.CapabilityNative, Formats: []string{"png", "jpeg", "webp"}, MaxOutputs: catalog.OptionalLimit{Known: true, Value: 10},
		Image: &catalog.ImageMediaLimits{MaxWidth: catalog.OptionalLimit{Known: true, Value: 3840}, MaxHeight: catalog.OptionalLimit{Known: true, Value: 3840}, WidthMultipleOf: catalog.OptionalLimit{Known: true, Value: 16}, HeightMultipleOf: catalog.OptionalLimit{Known: true, Value: 16}, MinPixels: catalog.OptionalLimit{Known: true, Value: 655360}, MaxPixels: catalog.OptionalLimit{Known: true, Value: 8294400}, MaxLongToShortRatio: catalog.ImageAspectRatioLimit{Known: true, LongEdge: 3, ShortEdge: 1}}, Delivery: catalog.DeliveryCapabilities{Synchronous: true},
		Evidence: []catalog.CapabilityEvidence{{Source: catalog.ModelSourceProviderAPI, Reference: "https://platform.openai.com/docs/api-reference/images/create", ObservedAt: mediaEvidenceObservedAt(), Revision: 1}}, EvidenceRevision: 1,
	}
}

// openAIImageParameters returns the closed GPT Image generation or edit controls.
// openAIImageParameters 返回封闭的 GPT Image 生成或编辑控制项。
func openAIImageParameters(includeBackground bool) []catalog.ParameterDescriptor {
	minimumCount, maximumCount, defaultCount := int64(1), int64(10), int64(1)
	maximumEdge, edgeMultiple := int64(3840), int64(16)
	parameters := []catalog.ParameterDescriptor{{ID: "count", Kind: catalog.ParameterCount, IntegerRange: &catalog.IntegerRange{Minimum: &minimumCount, Maximum: &maximumCount}, Default: &catalog.ParameterDefault{Source: catalog.ParameterDefaultProvider, Integer: &defaultCount}}, {ID: "width", Kind: catalog.ParameterInteger, IntegerRange: &catalog.IntegerRange{Maximum: &maximumEdge, MultipleOf: &edgeMultiple}}, {ID: "height", Kind: catalog.ParameterInteger, IntegerRange: &catalog.IntegerRange{Maximum: &maximumEdge, MultipleOf: &edgeMultiple}}, {ID: "quality", Kind: catalog.ParameterEnum, AllowedValues: []string{"auto", "low", "medium", "high"}}, {ID: "output_format", Kind: catalog.ParameterFormat, AllowedValues: []string{"png", "jpeg", "webp"}}}
	if includeBackground {
		parameters = append(parameters, catalog.ParameterDescriptor{ID: "background", Kind: catalog.ParameterEnum, AllowedValues: []string{"auto", "opaque"}})
	}
	return parameters
}

// openAIImageSizeRules returns the exact paired-dimension contract.
// openAIImageSizeRules 返回精确的成对尺寸合同。
func openAIImageSizeRules() []catalog.ParameterRule {
	return []catalog.ParameterRule{{Kind: catalog.ParameterRuleRequires, ParameterID: "width", RelatedParameterIDs: []string{"height"}}, {Kind: catalog.ParameterRuleRequires, ParameterID: "height", RelatedParameterIDs: []string{"width"}}}
}

// openRouterImageReferenceCapability returns the pinned OpenAI endpoint reference-image contract.
// openRouterImageReferenceCapability 返回固定 OpenAI 端点的参考图片合同。
func openRouterImageReferenceCapability() catalog.MediaInputCapability {
	return catalog.MediaInputCapability{
		Kind: vcp.MediaImage, Roles: []vcp.MediaInputRole{vcp.MediaRoleReference}, Level: catalog.CapabilityNative, InteractionModes: []catalog.MediaInteractionMode{catalog.MediaInteractionOperationInput}, MediaOnlyPolicy: catalog.MediaOnlyUnsupported,
		ClientWorkflows: []catalog.ClientResourceWorkflow{catalog.ClientWorkflowUploadThenReference, catalog.ClientWorkflowImportURLThenReference, catalog.ClientWorkflowImportBase64ThenReference, catalog.ClientWorkflowResolveInputPlan}, MaterializationModes: []catalog.UpstreamMaterializationMode{catalog.MaterializationInlineBase64, catalog.MaterializationDirectRemoteURL},
		Common: catalog.CommonMediaLimits{MIMETypes: []string{"image/png", "image/jpeg", "image/webp"}}, Image: &catalog.ImageMediaLimits{}, Compatibility: catalog.MediaCompatibility{ToolCalling: catalog.CapabilityUnsupported, Streaming: catalog.CapabilityUnsupported, Reasoning: catalog.CapabilityUnsupported, StructuredOutput: catalog.CapabilityUnsupported},
		Evidence: []catalog.CapabilityEvidence{{Source: catalog.ModelSourceProviderAPI, Reference: "https://openrouter.ai/docs/guides/overview/multimodal/image-generation", ObservedAt: mediaEvidenceObservedAt(), Revision: 1}}, EvidenceRevision: 1,
	}
}

// openRouterImageOutputCapability returns the dedicated Image API output contract.
// openRouterImageOutputCapability 返回专用 Image API 输出合同。
func openRouterImageOutputCapability() catalog.MediaOutputCapability {
	return catalog.MediaOutputCapability{
		Kind: vcp.MediaImage, Level: catalog.CapabilityNative, Formats: []string{"png", "jpeg", "webp", "svg"}, MaxOutputs: catalog.OptionalLimit{Known: true, Value: 10}, Image: &catalog.ImageMediaLimits{}, Delivery: catalog.DeliveryCapabilities{Synchronous: true},
		Evidence: []catalog.CapabilityEvidence{{Source: catalog.ModelSourceProviderAPI, Reference: "https://openrouter.ai/docs/guides/overview/multimodal/image-generation", ObservedAt: mediaEvidenceObservedAt(), Revision: 1}}, EvidenceRevision: 1,
	}
}

// anthropicUnderstandingCapabilities returns only image and PDF contracts preserved by the copied Responses-to-Claude translator.
// anthropicUnderstandingCapabilities 仅返回复制 Responses-to-Claude 转换器能保留的图片与 PDF 合同。
func anthropicUnderstandingCapabilities() []catalog.MediaInputCapability {
	// common creates one provider-evidenced user-transcript understanding capability.
	// common 创建一个由供应商证据支持的用户会话理解能力。
	common := func(kind vcp.MediaKind, mimeTypes []string, reference string) catalog.MediaInputCapability {
		return catalog.MediaInputCapability{
			Kind: kind, Roles: []vcp.MediaInputRole{vcp.MediaRoleUnderstanding}, Level: catalog.CapabilityNative,
			InteractionModes: []catalog.MediaInteractionMode{catalog.MediaInteractionMixedConversation, catalog.MediaInteractionMediaOnlyConversation}, MediaOnlyPolicy: catalog.MediaOnlyRouterInstruction,
			AllowedAuthorities: []vcp.Authority{vcp.AuthorityUser}, AllowedPlacements: []vcp.Placement{vcp.PlacementTranscript},
			ClientWorkflows:      []catalog.ClientResourceWorkflow{catalog.ClientWorkflowUploadThenReference, catalog.ClientWorkflowImportURLThenReference, catalog.ClientWorkflowImportBase64ThenReference, catalog.ClientWorkflowResolveInputPlan},
			MaterializationModes: []catalog.UpstreamMaterializationMode{catalog.MaterializationInlineBase64}, Common: catalog.CommonMediaLimits{MIMETypes: mimeTypes},
			Compatibility: catalog.MediaCompatibility{ToolCalling: catalog.CapabilityNative, Streaming: catalog.CapabilityNative, Reasoning: catalog.CapabilityNative, StructuredOutput: catalog.CapabilityNative},
			Evidence:      []catalog.CapabilityEvidence{{Source: catalog.ModelSourceProviderAPI, Reference: reference, ObservedAt: mediaEvidenceObservedAt(), Revision: 1}}, EvidenceRevision: 1,
		}
	}
	image := common(vcp.MediaImage, []string{"image/jpeg", "image/png", "image/gif", "image/webp"}, "https://docs.anthropic.com/en/docs/build-with-claude/vision")
	image.Image = &catalog.ImageMediaLimits{}
	file := common(vcp.MediaFile, []string{"application/pdf"}, "https://docs.anthropic.com/en/docs/build-with-claude/pdf-support")
	return []catalog.MediaInputCapability{image, file}
}

// anthropicModels overlays official media contracts without changing copied CLIProxyAPI model facts.
// anthropicModels 在不改变复制 CLIProxyAPI 模型事实的前提下叠加官方媒体合同。
func anthropicModels() []systemModelTemplate {
	models := copiedTextModels("claude", []systemModelIdentity{{"claude-haiku-4-5-20251001", "Claude 4.5 Haiku", 200000}, {"claude-sonnet-4-5-20250929", "Claude 4.5 Sonnet", 200000}, {"claude-sonnet-4-6", "Claude 4.6 Sonnet", 200000}, {"claude-opus-4-6", "Claude 4.6 Opus", 1000000}, {"claude-opus-4-7", "Claude Opus 4.7", 1000000}, {"claude-opus-4-8", "Claude Opus 4.8", 1000000}, {"claude-sonnet-5", "Claude Sonnet 5", 1000000}, {"claude-fable-5", "Claude Fable 5", 1000000}, {"claude-opus-4-5-20251101", "Claude 4.5 Opus", 200000}, {"claude-opus-4-1-20250805", "Claude 4.1 Opus", 200000}, {"claude-opus-4-20250514", "Claude 4 Opus", 200000}, {"claude-sonnet-4-20250514", "Claude 4 Sonnet", 200000}, {"claude-3-7-sonnet-20250219", "Claude 3.7 Sonnet", 128000}, {"claude-3-5-haiku-20241022", "Claude 3.5 Haiku", 128000}})
	for index := range models {
		models[index].inputModalities = []string{"text", "image", "file"}
		models[index].mediaInputs = anthropicUnderstandingCapabilities()
	}
	return models
}

// mediaEvidenceObservedAt freezes the official-document verification date for code-owned catalogs.
// mediaEvidenceObservedAt 固定代码拥有目录的官方文档核验日期。
func mediaEvidenceObservedAt() time.Time {
	return time.Date(2026, time.July, 20, 0, 0, 0, 0, time.UTC)
}
