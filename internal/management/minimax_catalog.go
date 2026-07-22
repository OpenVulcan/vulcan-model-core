package management

import (
	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// miniMaxImageModels returns the verified image-01 generation template.
// miniMaxImageModels 返回已验证的 image-01 生成模板。
func miniMaxImageModels() []systemModelTemplate {
	return []systemModelTemplate{{upstreamID: "image-01", displayName: "MiniMax Image 01", inputModalities: []string{"text", "image"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnsupported, parallelTools: catalog.CapabilityUnsupported, streamingTools: catalog.CapabilityUnsupported, strictSchema: catalog.CapabilityUnsupported, entitlementMode: catalog.EntitlementAllBoundCredentials, operation: vcp.OperationImageGenerate, mediaInputs: []catalog.MediaInputCapability{miniMaxSubjectReferenceCapability()}, mediaOutputs: []catalog.MediaOutputCapability{miniMaxImageOutputCapability()}, parameters: miniMaxImageParameters(), parameterRules: []catalog.ParameterRule{{Kind: catalog.ParameterRuleRequires, ParameterID: "width", RelatedParameterIDs: []string{"height"}}, {Kind: catalog.ParameterRuleRequires, ParameterID: "height", RelatedParameterIDs: []string{"width"}}, {Kind: catalog.ParameterRuleMutuallyExclusive, ParameterID: "width", RelatedParameterIDs: []string{"aspect_ratio"}}, {Kind: catalog.ParameterRuleMutuallyExclusive, ParameterID: "height", RelatedParameterIDs: []string{"aspect_ratio"}}}, usageMetrics: []catalog.UsageMetricCapability{{Unit: catalog.UsageUnitImages, Accuracy: catalog.UsageExact}, {Unit: catalog.UsageUnitPixels, Accuracy: catalog.UsageExact}}}}
}

// miniMaxSubjectReferenceCapability returns the inline-or-public-URL character reference contract.
// miniMaxSubjectReferenceCapability 返回内联或公网 URL 的角色参考合同。
func miniMaxSubjectReferenceCapability() catalog.MediaInputCapability {
	return catalog.MediaInputCapability{Kind: vcp.MediaImage, Roles: []vcp.MediaInputRole{vcp.MediaRoleReference}, Level: catalog.CapabilityNative, InteractionModes: []catalog.MediaInteractionMode{catalog.MediaInteractionOperationInput}, MediaOnlyPolicy: catalog.MediaOnlyUnsupported, ClientWorkflows: []catalog.ClientResourceWorkflow{catalog.ClientWorkflowUploadThenReference, catalog.ClientWorkflowImportURLThenReference, catalog.ClientWorkflowImportBase64ThenReference, catalog.ClientWorkflowResolveInputPlan}, MaterializationModes: []catalog.UpstreamMaterializationMode{catalog.MaterializationInlineBase64, catalog.MaterializationDirectRemoteURL}, Common: catalog.CommonMediaLimits{MIMETypes: []string{"image/jpeg", "image/png", "image/webp"}, MaxItems: catalog.OptionalLimit{Known: true, Value: 1}, AllowsRemoteURL: catalog.OptionalBool{Known: true, Value: true}}, Image: &catalog.ImageMediaLimits{}, Compatibility: catalog.MediaCompatibility{ToolCalling: catalog.CapabilityUnsupported, Streaming: catalog.CapabilityUnsupported, Reasoning: catalog.CapabilityUnsupported, StructuredOutput: catalog.CapabilityUnsupported, RequiresText: true}, Evidence: []catalog.CapabilityEvidence{{Source: catalog.ModelSourceProviderAPI, Reference: "https://platform.minimax.io/docs/api-reference/image-generation-i2i", ObservedAt: mediaEvidenceObservedAt(), Revision: 1}}, EvidenceRevision: 1}
}

// miniMaxImageOutputCapability returns the synchronous JPEG output contract.
// miniMaxImageOutputCapability 返回同步 JPEG 输出合同。
func miniMaxImageOutputCapability() catalog.MediaOutputCapability {
	return catalog.MediaOutputCapability{Kind: vcp.MediaImage, Level: catalog.CapabilityNative, Formats: []string{"jpeg"}, MaxOutputs: catalog.OptionalLimit{Known: true, Value: 9}, Image: &catalog.ImageMediaLimits{MaxWidth: catalog.OptionalLimit{Known: true, Value: 2048}, MaxHeight: catalog.OptionalLimit{Known: true, Value: 2048}}, Delivery: catalog.DeliveryCapabilities{Synchronous: true}, Evidence: []catalog.CapabilityEvidence{{Source: catalog.ModelSourceProviderAPI, Reference: "https://platform.minimax.io/docs/api-reference/image-generation-t2i", ObservedAt: mediaEvidenceObservedAt(), Revision: 1}}, EvidenceRevision: 1}
}

// miniMaxImageParameters returns the closed image-01 control set.
// miniMaxImageParameters 返回封闭的 image-01 控制集合。
func miniMaxImageParameters() []catalog.ParameterDescriptor {
	minimumCount, maximumCount, defaultCount := int64(1), int64(9), int64(1)
	minimumDimension, maximumDimension, dimensionStep := int64(512), int64(2048), int64(8)
	return []catalog.ParameterDescriptor{{ID: "count", Kind: catalog.ParameterCount, IntegerRange: &catalog.IntegerRange{Minimum: &minimumCount, Maximum: &maximumCount}, Default: &catalog.ParameterDefault{Source: catalog.ParameterDefaultProvider, Integer: &defaultCount}}, {ID: "aspect_ratio", Kind: catalog.ParameterEnum, AllowedValues: []string{"1:1", "16:9", "4:3", "3:2", "2:3", "3:4", "9:16", "21:9"}}, {ID: "width", Kind: catalog.ParameterInteger, IntegerRange: &catalog.IntegerRange{Minimum: &minimumDimension, Maximum: &maximumDimension, MultipleOf: &dimensionStep}}, {ID: "height", Kind: catalog.ParameterInteger, IntegerRange: &catalog.IntegerRange{Minimum: &minimumDimension, Maximum: &maximumDimension, MultipleOf: &dimensionStep}}, {ID: "seed", Kind: catalog.ParameterInteger, IntegerRange: &catalog.IntegerRange{}}, {ID: "prompt_extend", Kind: catalog.ParameterBoolean}, {ID: "watermark", Kind: catalog.ParameterBoolean}, {ID: "output_format", Kind: catalog.ParameterFormat, AllowedValues: []string{"jpeg"}}}
}
