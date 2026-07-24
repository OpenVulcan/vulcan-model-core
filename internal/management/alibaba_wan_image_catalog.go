package management

import (
	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	provideralibaba "github.com/OpenVulcan/vulcan-model-core/internal/provider/alibaba"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// alibabaWanImageModels returns the complete synchronous Wan 2.7 generation and editing templates proven for workspace APIs.
// alibabaWanImageModels 返回已为工作空间 API 证实的完整同步 Wan 2.7 图片生成与编辑模板。
func alibabaWanImageModels() []systemModelTemplate {
	models := make([]systemModelTemplate, 0, 4)
	for _, identity := range []systemModelIdentity{{upstreamID: "wan2.7-image-pro", displayName: "Wan 2.7 Image Pro"}, {upstreamID: "wan2.7-image", displayName: "Wan 2.7 Image"}} {
		models = append(models,
			alibabaWanImageTemplate(identity, vcp.OperationImageGenerate),
			alibabaWanImageTemplate(identity, vcp.OperationImageEdit),
		)
	}
	return models
}

// alibabaTokenPlanWanImageModels returns only the synchronous generation operations proven for Personal CN Token Plan.
// alibabaTokenPlanWanImageModels 仅返回已为中国站个人 Token Plan 证实的同步生成操作。
func alibabaTokenPlanWanImageModels() []systemModelTemplate {
	models := make([]systemModelTemplate, 0, 2)
	for _, identity := range []systemModelIdentity{{upstreamID: "wan2.7-image-pro", displayName: "Wan 2.7 Image Pro"}, {upstreamID: "wan2.7-image", displayName: "Wan 2.7 Image"}} {
		models = append(models, alibabaWanImageTemplate(identity, vcp.OperationImageGenerate))
	}
	return models
}

// alibabaWanImageTemplate builds one operation-specific Wan 2.7 template.
// alibabaWanImageTemplate 构建一个操作专属 Wan 2.7 模板。
func alibabaWanImageTemplate(identity systemModelIdentity, operation vcp.OperationKind) systemModelTemplate {
	template := systemModelTemplate{
		upstreamID: identity.upstreamID, displayName: identity.displayName, inputModalities: []string{"text", "image"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnsupported, parallelTools: catalog.CapabilityUnsupported, streamingTools: catalog.CapabilityUnsupported, strictSchema: catalog.CapabilityUnsupported, entitlementMode: catalog.EntitlementAllBoundCredentials,
		operation: operation, mediaOutputs: []catalog.MediaOutputCapability{alibabaWanImageOutputCapability()}, parameters: alibabaWanImageParameters(identity.upstreamID, operation), usageMetrics: []catalog.UsageMetricCapability{{Unit: catalog.UsageUnitImages, Accuracy: catalog.UsageExact}, {Unit: catalog.UsageUnitPixels, Accuracy: catalog.UsageExact}},
	}
	if operation == vcp.OperationImageGenerate {
		template.actionBindingID = provideralibaba.WanImageGenerateActionBindingID
		template.mediaInputs = []catalog.MediaInputCapability{alibabaWanImageInputCapability(vcp.MediaRoleReference)}
		return template
	}
	template.displayName += " Edit"
	template.actionBindingID = provideralibaba.WanImageEditActionBindingID
	template.mediaInputs = []catalog.MediaInputCapability{alibabaWanImageInputCapability(vcp.MediaRoleEditSource)}
	return template
}

// alibabaWanImageInputCapability returns the exact synchronous Wan image materialization contract.
// alibabaWanImageInputCapability 返回精确的同步 Wan 图片物化合同。
func alibabaWanImageInputCapability(role vcp.MediaInputRole) catalog.MediaInputCapability {
	return catalog.MediaInputCapability{
		Kind: vcp.MediaImage, Roles: []vcp.MediaInputRole{role}, Level: catalog.CapabilityNative, InteractionModes: []catalog.MediaInteractionMode{catalog.MediaInteractionOperationInput}, MediaOnlyPolicy: catalog.MediaOnlyUnsupported,
		ClientWorkflows: []catalog.ClientResourceWorkflow{catalog.ClientWorkflowUploadThenReference, catalog.ClientWorkflowImportURLThenReference, catalog.ClientWorkflowImportBase64ThenReference, catalog.ClientWorkflowResolveInputPlan}, MaterializationModes: []catalog.UpstreamMaterializationMode{catalog.MaterializationInlineBase64, catalog.MaterializationDirectRemoteURL},
		Common: catalog.CommonMediaLimits{MIMETypes: []string{"image/jpeg", "image/png", "image/bmp", "image/webp"}, MaxItemBytes: catalog.OptionalLimit{Known: true, Value: 20 << 20}, MaxItems: catalog.OptionalLimit{Known: true, Value: 9}, AllowsRemoteURL: catalog.OptionalBool{Known: true, Value: true}}, Image: &catalog.ImageMediaLimits{MaxWidth: catalog.OptionalLimit{Known: true, Value: 8000}, MaxHeight: catalog.OptionalLimit{Known: true, Value: 8000}, Transparency: catalog.OptionalBool{Known: true, Value: false}}, Compatibility: catalog.MediaCompatibility{ToolCalling: catalog.CapabilityUnsupported, Streaming: catalog.CapabilityUnsupported, Reasoning: catalog.CapabilityUnsupported, StructuredOutput: catalog.CapabilityUnsupported, RequiresText: true},
		Evidence: []catalog.CapabilityEvidence{{Source: catalog.ModelSourceProviderAPI, Reference: "https://www.alibabacloud.com/help/en/model-studio/wan-image-generation-and-editing-api-reference", ObservedAt: mediaEvidenceObservedAt(), Revision: 1}}, EvidenceRevision: 1,
	}
}

// alibabaWanImageOutputCapability returns the synchronous private PNG output contract.
// alibabaWanImageOutputCapability 返回同步私有 PNG 输出合同。
func alibabaWanImageOutputCapability() catalog.MediaOutputCapability {
	return catalog.MediaOutputCapability{
		Kind: vcp.MediaImage, Level: catalog.CapabilityNative, Formats: []string{"png"}, MaxOutputs: catalog.OptionalLimit{Known: true, Value: 4}, Image: &catalog.ImageMediaLimits{MaxWidth: catalog.OptionalLimit{Known: true, Value: 4096}, MaxHeight: catalog.OptionalLimit{Known: true, Value: 4096}, Transparency: catalog.OptionalBool{Known: true, Value: false}}, Delivery: catalog.DeliveryCapabilities{Synchronous: true},
		Evidence: []catalog.CapabilityEvidence{{Source: catalog.ModelSourceProviderAPI, Reference: "https://www.alibabacloud.com/help/en/model-studio/wan-image-generation-and-editing-api-reference", ObservedAt: mediaEvidenceObservedAt(), Revision: 1}}, EvidenceRevision: 1,
	}
}

// alibabaWanImageParameters returns only VCP controls with direct synchronous Wan carriers.
// alibabaWanImageParameters 仅返回具有同步 Wan 直接载体的 VCP 控制项。
func alibabaWanImageParameters(model string, operation vcp.OperationKind) []catalog.ParameterDescriptor {
	minimumCount, maximumCount, defaultCount := int64(1), int64(4), int64(1)
	minimumSeed, maximumSeed := int64(0), int64(2147483647)
	resolutions := []string{"1k", "2k"}
	if model == "wan2.7-image-pro" && operation == vcp.OperationImageGenerate {
		resolutions = append(resolutions, "4k")
	}
	parameters := []catalog.ParameterDescriptor{
		{ID: "count", Kind: catalog.ParameterCount, IntegerRange: &catalog.IntegerRange{Minimum: &minimumCount, Maximum: &maximumCount}, Default: &catalog.ParameterDefault{Source: catalog.ParameterDefaultProvider, Integer: &defaultCount}},
		{ID: "resolution", Kind: catalog.ParameterEnum, AllowedValues: resolutions},
		{ID: "output_format", Kind: catalog.ParameterFormat, AllowedValues: []string{"png"}},
		{ID: "negative_prompt", Kind: catalog.ParameterString, StringRange: &catalog.StringRange{}},
		{ID: "prompt_extend", Kind: catalog.ParameterBoolean},
		{ID: "watermark", Kind: catalog.ParameterBoolean},
		{ID: "seed", Kind: catalog.ParameterInteger, IntegerRange: &catalog.IntegerRange{Minimum: &minimumSeed, Maximum: &maximumSeed}},
	}
	return parameters
}
