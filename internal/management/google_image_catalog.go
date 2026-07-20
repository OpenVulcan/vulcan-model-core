package management

import (
	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// googleInteractionsImageModels returns the verified Gemini 3.1 Flash Image action templates.
// googleInteractionsImageModels 返回已验证的 Gemini 3.1 Flash Image 动作模板。
func googleInteractionsImageModels() []systemModelTemplate {
	return []systemModelTemplate{
		{
			upstreamID: "gemini-3.1-flash-image", displayName: "Gemini 3.1 Flash Image", contextWindow: 131072, maxInputTokens: 131072, maxOutputTokens: 32768, inputModalities: []string{"text"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnsupported, parallelTools: catalog.CapabilityUnsupported, streamingTools: catalog.CapabilityUnsupported, strictSchema: catalog.CapabilityUnsupported, entitlementMode: catalog.EntitlementAllBoundCredentials,
			operation: vcp.OperationImageGenerate, mediaOutputs: []catalog.MediaOutputCapability{googleInteractionsImageOutputCapability()}, parameters: googleInteractionsImageParameters(true), usageMetrics: []catalog.UsageMetricCapability{{Unit: catalog.UsageUnitImages, Accuracy: catalog.UsageExact}},
		},
		{
			upstreamID: "gemini-3.1-flash-image", displayName: "Gemini 3.1 Flash Image Edit", contextWindow: 131072, maxInputTokens: 131072, maxOutputTokens: 32768, inputModalities: []string{"text", "image"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnsupported, parallelTools: catalog.CapabilityUnsupported, streamingTools: catalog.CapabilityUnsupported, strictSchema: catalog.CapabilityUnsupported, entitlementMode: catalog.EntitlementAllBoundCredentials,
			operation: vcp.OperationImageEdit, mediaInputs: []catalog.MediaInputCapability{googleInteractionsImageEditCapability()}, mediaOutputs: []catalog.MediaOutputCapability{googleInteractionsImageOutputCapability()}, parameters: googleInteractionsImageParameters(true), usageMetrics: []catalog.UsageMetricCapability{{Unit: catalog.UsageUnitImages, Accuracy: catalog.UsageExact}},
		},
	}
}

// googleInteractionsImageEditCapability returns the current Interactions image input contract.
// googleInteractionsImageEditCapability 返回当前 Interactions 图片输入合同。
func googleInteractionsImageEditCapability() catalog.MediaInputCapability {
	return catalog.MediaInputCapability{
		Kind: vcp.MediaImage, Roles: []vcp.MediaInputRole{vcp.MediaRoleEditSource}, Level: catalog.CapabilityNative, InteractionModes: []catalog.MediaInteractionMode{catalog.MediaInteractionOperationInput}, MediaOnlyPolicy: catalog.MediaOnlyUnsupported,
		ClientWorkflows: []catalog.ClientResourceWorkflow{catalog.ClientWorkflowUploadThenReference, catalog.ClientWorkflowImportURLThenReference, catalog.ClientWorkflowImportBase64ThenReference, catalog.ClientWorkflowResolveInputPlan}, MaterializationModes: []catalog.UpstreamMaterializationMode{catalog.MaterializationInlineBase64, catalog.MaterializationDirectRemoteURL},
		Common: catalog.CommonMediaLimits{MIMETypes: []string{"image/png", "image/jpeg", "image/webp", "image/gif"}, MaxItems: catalog.OptionalLimit{Known: true, Value: 14}, AllowsRemoteURL: catalog.OptionalBool{Known: true, Value: true}}, Image: &catalog.ImageMediaLimits{}, Compatibility: catalog.MediaCompatibility{ToolCalling: catalog.CapabilityUnsupported, Streaming: catalog.CapabilityUnsupported, Reasoning: catalog.CapabilityUnsupported, StructuredOutput: catalog.CapabilityUnsupported, RequiresText: true},
		Evidence: []catalog.CapabilityEvidence{{Source: catalog.ModelSourceProviderAPI, Reference: "https://ai.google.dev/gemini-api/docs/image-generation", ObservedAt: mediaEvidenceObservedAt(), Revision: 1}}, EvidenceRevision: 1,
	}
}

// googleInteractionsImageOutputCapability returns the current synchronous image output contract.
// googleInteractionsImageOutputCapability 返回当前同步图片输出合同。
func googleInteractionsImageOutputCapability() catalog.MediaOutputCapability {
	return catalog.MediaOutputCapability{
		Kind: vcp.MediaImage, Level: catalog.CapabilityNative, Formats: []string{"png", "jpeg"}, MaxOutputs: catalog.OptionalLimit{Known: true, Value: 1}, Image: &catalog.ImageMediaLimits{}, Delivery: catalog.DeliveryCapabilities{Synchronous: true},
		Evidence: []catalog.CapabilityEvidence{{Source: catalog.ModelSourceProviderAPI, Reference: "https://ai.google.dev/gemini-api/docs/image-generation", ObservedAt: mediaEvidenceObservedAt(), Revision: 1}}, EvidenceRevision: 1,
	}
}

// googleInteractionsImageParameters returns only controls with direct current REST carriers.
// googleInteractionsImageParameters 仅返回当前 REST 可直接承载的控制项。
func googleInteractionsImageParameters(includeAspectRatio bool) []catalog.ParameterDescriptor {
	minimumCount, maximumCount, defaultCount := int64(1), int64(1), int64(1)
	parameters := []catalog.ParameterDescriptor{
		{ID: "count", Kind: catalog.ParameterCount, IntegerRange: &catalog.IntegerRange{Minimum: &minimumCount, Maximum: &maximumCount}, Default: &catalog.ParameterDefault{Source: catalog.ParameterDefaultProvider, Integer: &defaultCount}},
		{ID: "output_format", Kind: catalog.ParameterFormat, AllowedValues: []string{"png", "jpeg"}},
	}
	if includeAspectRatio {
		parameters = append(parameters,
			catalog.ParameterDescriptor{ID: "aspect_ratio", Kind: catalog.ParameterEnum, AllowedValues: []string{"1:1", "1:4", "1:8", "2:3", "3:2", "3:4", "4:1", "4:3", "4:5", "5:4", "8:1", "9:16", "16:9", "21:9"}},
			catalog.ParameterDescriptor{ID: "resolution", Kind: catalog.ParameterEnum, AllowedValues: []string{"512", "1k", "2k", "4k"}},
		)
	}
	return parameters
}
