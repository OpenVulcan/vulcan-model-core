package management

import (
	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	provideralibaba "github.com/OpenVulcan/vulcan-model-core/internal/provider/alibaba"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// alibabaModelStudioModels returns the evidence-closed regional native-action catalog without copying unverified products across endpoint families.
// alibabaModelStudioModels 返回证据封闭的区域原生动作目录，且不会在未经验证的入口家族间复制产品。
func alibabaModelStudioModels(includeOmniModels bool, includeWanWorkspaceModels bool) []systemModelTemplate {
	models := alibabaModelStudioEmbeddingModels()
	models = append(models, alibabaAudioModels()...)
	if includeOmniModels {
		models = append(models, alibabaOmniModels()...)
	}
	models = append(models,
		systemModelTemplate{
			upstreamID: "qwen-image-2.0-pro", displayName: "Qwen Image 2.0 Pro", inputModalities: []string{"text"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnsupported, parallelTools: catalog.CapabilityUnsupported, streamingTools: catalog.CapabilityUnsupported, strictSchema: catalog.CapabilityUnsupported, entitlementMode: catalog.EntitlementAllBoundCredentials,
			operation: vcp.OperationImageGenerate, actionBindingID: provideralibaba.ImageGenerateActionBindingID, mediaOutputs: []catalog.MediaOutputCapability{alibabaQwenImageOutputCapability()}, parameters: alibabaQwenImageParameters(true), parameterRules: alibabaQwenImageParameterRules(true), usageMetrics: []catalog.UsageMetricCapability{{Unit: catalog.UsageUnitImages, Accuracy: catalog.UsageExact}, {Unit: catalog.UsageUnitPixels, Accuracy: catalog.UsageExact}},
		},
		systemModelTemplate{
			upstreamID: "qwen-image-2.0-pro", displayName: "Qwen Image 2.0 Pro Edit", inputModalities: []string{"text", "image"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnsupported, parallelTools: catalog.CapabilityUnsupported, streamingTools: catalog.CapabilityUnsupported, strictSchema: catalog.CapabilityUnsupported, entitlementMode: catalog.EntitlementAllBoundCredentials,
			operation: vcp.OperationImageEdit, actionBindingID: provideralibaba.ImageEditActionBindingID, mediaInputs: []catalog.MediaInputCapability{alibabaQwenImageEditCapability()}, mediaOutputs: []catalog.MediaOutputCapability{alibabaQwenImageOutputCapability()}, parameters: alibabaQwenImageParameters(false), usageMetrics: []catalog.UsageMetricCapability{{Unit: catalog.UsageUnitImages, Accuracy: catalog.UsageExact}, {Unit: catalog.UsageUnitPixels, Accuracy: catalog.UsageExact}},
		},
	)
	if includeWanWorkspaceModels {
		models = append(models, alibabaWanImageModels()...)
		models = append(models, alibabaWanVideoModels()...)
	}
	return models
}

// alibabaTokenPlanQwenImageModels returns the two exact Qwen Image generation models published by Team plans.
// alibabaTokenPlanQwenImageModels 返回团队套餐发布的两个精确 Qwen 图片生成模型。
func alibabaTokenPlanQwenImageModels() []systemModelTemplate {
	return []systemModelTemplate{
		alibabaQwenImageGenerationTemplate("qwen-image-2.0", "Qwen Image 2.0"),
		alibabaQwenImageGenerationTemplate("qwen-image-2.0-pro", "Qwen Image 2.0 Pro"),
	}
}

// alibabaQwenImageGenerationTemplate builds one synchronous Qwen Image generation operation without adding edit support.
// alibabaQwenImageGenerationTemplate 构建一个同步 Qwen 图片生成操作，且不会附带图片编辑支持。
func alibabaQwenImageGenerationTemplate(upstreamID string, displayName string) systemModelTemplate {
	return systemModelTemplate{
		upstreamID: upstreamID, displayName: displayName, inputModalities: []string{"text"},
		reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnsupported, parallelTools: catalog.CapabilityUnsupported,
		streamingTools: catalog.CapabilityUnsupported, strictSchema: catalog.CapabilityUnsupported, entitlementMode: catalog.EntitlementAllBoundCredentials,
		operation: vcp.OperationImageGenerate, actionBindingID: provideralibaba.ImageGenerateActionBindingID,
		mediaOutputs: []catalog.MediaOutputCapability{alibabaQwenImageOutputCapability()},
		parameters:   alibabaQwenImageParameters(true), parameterRules: alibabaQwenImageParameterRules(true),
		usageMetrics: []catalog.UsageMetricCapability{{Unit: catalog.UsageUnitImages, Accuracy: catalog.UsageExact}, {Unit: catalog.UsageUnitPixels, Accuracy: catalog.UsageExact}},
	}
}

// alibabaQwenImageEditCapability returns the official one-to-three image editing input contract.
// alibabaQwenImageEditCapability 返回官方的一至三张图片编辑输入合同。
func alibabaQwenImageEditCapability() catalog.MediaInputCapability {
	return catalog.MediaInputCapability{
		Kind: vcp.MediaImage, Roles: []vcp.MediaInputRole{vcp.MediaRoleEditSource}, Level: catalog.CapabilityNative, InteractionModes: []catalog.MediaInteractionMode{catalog.MediaInteractionOperationInput}, MediaOnlyPolicy: catalog.MediaOnlyUnsupported,
		ClientWorkflows: []catalog.ClientResourceWorkflow{catalog.ClientWorkflowUploadThenReference, catalog.ClientWorkflowImportURLThenReference, catalog.ClientWorkflowImportBase64ThenReference, catalog.ClientWorkflowResolveInputPlan}, MaterializationModes: []catalog.UpstreamMaterializationMode{catalog.MaterializationInlineBase64, catalog.MaterializationDirectRemoteURL},
		Common: catalog.CommonMediaLimits{MIMETypes: []string{"image/jpeg", "image/png", "image/bmp", "image/webp", "image/gif"}, MaxItemBytes: catalog.OptionalLimit{Known: true, Value: 10 << 20}, MaxItems: catalog.OptionalLimit{Known: true, Value: 3}, AllowsRemoteURL: catalog.OptionalBool{Known: true, Value: true}}, Image: &catalog.ImageMediaLimits{Animated: catalog.OptionalBool{Known: true, Value: false}}, Compatibility: catalog.MediaCompatibility{ToolCalling: catalog.CapabilityUnsupported, Streaming: catalog.CapabilityUnsupported, Reasoning: catalog.CapabilityUnsupported, StructuredOutput: catalog.CapabilityUnsupported, RequiresText: true},
		Evidence: []catalog.CapabilityEvidence{{Source: catalog.ModelSourceProviderAPI, Reference: "https://www.alibabacloud.com/help/en/model-studio/qwen-image-edit-api", ObservedAt: mediaEvidenceObservedAt(), Revision: 1}}, EvidenceRevision: 1,
	}
}

// alibabaQwenImageOutputCapability returns the official Qwen Image 2.0 PNG output contract.
// alibabaQwenImageOutputCapability 返回官方 Qwen Image 2.0 PNG 输出合同。
func alibabaQwenImageOutputCapability() catalog.MediaOutputCapability {
	return catalog.MediaOutputCapability{
		Kind: vcp.MediaImage, Level: catalog.CapabilityNative, Formats: []string{"png"}, MaxOutputs: catalog.OptionalLimit{Known: true, Value: 6}, Image: &catalog.ImageMediaLimits{MaxPixels: catalog.OptionalLimit{Known: true, Value: 2048 * 2048}}, Delivery: catalog.DeliveryCapabilities{Synchronous: true},
		Evidence: []catalog.CapabilityEvidence{{Source: catalog.ModelSourceProviderAPI, Reference: "https://www.alibabacloud.com/help/en/model-studio/qwen-image-api", ObservedAt: mediaEvidenceObservedAt(), Revision: 1}}, EvidenceRevision: 1,
	}
}

// alibabaQwenImageParameters returns closed VCP parameter facts and optionally exposes exact generation dimensions.
// alibabaQwenImageParameters 返回封闭 VCP 参数事实，并可选公开精确生成尺寸。
func alibabaQwenImageParameters(includeSize bool) []catalog.ParameterDescriptor {
	minimumCount, maximumCount, defaultCount := int64(1), int64(6), int64(1)
	maximumNegativePromptLength := int64(500)
	minimumSeed, maximumSeed := int64(0), int64(2147483647)
	parameters := []catalog.ParameterDescriptor{
		{ID: "count", Kind: catalog.ParameterCount, IntegerRange: &catalog.IntegerRange{Minimum: &minimumCount, Maximum: &maximumCount}, Default: &catalog.ParameterDefault{Source: catalog.ParameterDefaultProvider, Integer: &defaultCount}},
		{ID: "output_format", Kind: catalog.ParameterFormat, AllowedValues: []string{"png"}},
		{ID: "negative_prompt", Kind: catalog.ParameterString, StringRange: &catalog.StringRange{MaximumLength: &maximumNegativePromptLength}},
		{ID: "prompt_extend", Kind: catalog.ParameterBoolean},
		{ID: "watermark", Kind: catalog.ParameterBoolean},
		{ID: "seed", Kind: catalog.ParameterInteger, IntegerRange: &catalog.IntegerRange{Minimum: &minimumSeed, Maximum: &maximumSeed}},
	}
	if includeSize {
		minimumDimension := int64(1)
		parameters = append(parameters,
			catalog.ParameterDescriptor{ID: "width", Kind: catalog.ParameterInteger, IntegerRange: &catalog.IntegerRange{Minimum: &minimumDimension}},
			catalog.ParameterDescriptor{ID: "height", Kind: catalog.ParameterInteger, IntegerRange: &catalog.IntegerRange{Minimum: &minimumDimension}},
		)
	}
	return parameters
}

// alibabaQwenImageParameterRules returns the exact width and height co-presence contract.
// alibabaQwenImageParameterRules 返回精确的宽高共同出现合同。
func alibabaQwenImageParameterRules(includeSize bool) []catalog.ParameterRule {
	if !includeSize {
		return nil
	}
	return []catalog.ParameterRule{
		{Kind: catalog.ParameterRuleRequires, ParameterID: "width", RelatedParameterIDs: []string{"height"}},
		{Kind: catalog.ParameterRuleRequires, ParameterID: "height", RelatedParameterIDs: []string{"width"}},
	}
}
