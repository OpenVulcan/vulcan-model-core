package management

import (
	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	providergoogle "github.com/OpenVulcan/vulcan-model-core/internal/provider/google"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// googleVeoModels returns operation-specific current Veo 3.1 preview templates.
// googleVeoModels 返回操作专属的当前 Veo 3.1 预览模板。
func googleVeoModels() []systemModelTemplate {
	models := make([]systemModelTemplate, 0, 5)
	for _, identity := range []systemModelIdentity{{upstreamID: "veo-3.1-generate-preview", displayName: "Veo 3.1 Preview"}, {upstreamID: "veo-3.1-fast-generate-preview", displayName: "Veo 3.1 Fast Preview"}, {upstreamID: "veo-3.1-lite-generate-preview", displayName: "Veo 3.1 Lite Preview"}} {
		models = append(models, googleVeoTemplate(identity, vcp.OperationVideoGenerate))
		if identity.upstreamID != "veo-3.1-lite-generate-preview" {
			models = append(models, googleVeoTemplate(identity, vcp.OperationVideoExtend))
		}
	}
	return models
}

// googleVeoTemplate builds one closed Veo operation contract.
// googleVeoTemplate 构建一个封闭 Veo 操作合同。
func googleVeoTemplate(identity systemModelIdentity, operation vcp.OperationKind) systemModelTemplate {
	minimumDuration, maximumDuration := 4.0, 8.0
	evidence := []catalog.CapabilityEvidence{{Source: catalog.ModelSourceProviderAPI, Reference: "https://ai.google.dev/gemini-api/docs/veo", ObservedAt: mediaEvidenceObservedAt(), Revision: 1}}
	template := systemModelTemplate{
		upstreamID: identity.upstreamID, displayName: identity.displayName, inputModalities: []string{"text", "image"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnsupported, parallelTools: catalog.CapabilityUnsupported, streamingTools: catalog.CapabilityUnsupported, strictSchema: catalog.CapabilityUnsupported, entitlementMode: catalog.EntitlementAllBoundCredentials,
		operation: operation, mediaOutputs: []catalog.MediaOutputCapability{{Kind: vcp.MediaVideo, Level: catalog.CapabilityNative, Formats: []string{"mp4"}, MaxOutputs: catalog.OptionalLimit{Known: true, Value: 1}, Video: &catalog.VideoMediaLimits{MaxDurationMilliseconds: catalog.OptionalLimit{Known: true, Value: 8000}, MaxWidth: catalog.OptionalLimit{Known: true, Value: 3840}, MaxHeight: catalog.OptionalLimit{Known: true, Value: 3840}, MaxFPS: catalog.OptionalLimit{Known: true, Value: 24}, Containers: []string{"mp4"}, EmbeddedAudio: catalog.OptionalBool{Known: true, Value: true}}, Delivery: catalog.DeliveryCapabilities{Asynchronous: true, Polling: true}, Evidence: evidence, EvidenceRevision: 1}}, usageMetrics: []catalog.UsageMetricCapability{{Unit: catalog.UsageUnitVideoMilliseconds, Accuracy: catalog.UsageExact}},
	}
	if operation == vcp.OperationVideoExtend {
		template.actionBindingID = providergoogle.VideoExtendActionBindingID
		template.displayName += " Extension"
		template.inputModalities = []string{"video", "text"}
		template.mediaInputs = []catalog.MediaInputCapability{{Kind: vcp.MediaVideo, Roles: []vcp.MediaInputRole{vcp.MediaRoleEditSource}, Level: catalog.CapabilityNative, InteractionModes: []catalog.MediaInteractionMode{catalog.MediaInteractionOperationInput}, MediaOnlyPolicy: catalog.MediaOnlyUnsupported, ClientWorkflows: []catalog.ClientResourceWorkflow{catalog.ClientWorkflowResolveInputPlan}, MaterializationModes: []catalog.UpstreamMaterializationMode{catalog.MaterializationInlineBase64}, GeneratedSource: &catalog.GeneratedSourceRequirement{Required: true, SameProviderDefinition: true, AllowedOperations: []vcp.OperationKind{vcp.OperationVideoGenerate, vcp.OperationVideoExtend}, AllowedUpstreamModels: []string{"veo-3.1-generate-preview", "veo-3.1-fast-generate-preview"}}, Common: catalog.CommonMediaLimits{MIMETypes: []string{"video/mp4"}, MaxItems: catalog.OptionalLimit{Known: true, Value: 1}}, Video: &catalog.VideoMediaLimits{MaxDurationMilliseconds: catalog.OptionalLimit{Known: true, Value: 141000}, MaxWidth: catalog.OptionalLimit{Known: true, Value: 1280}, MaxHeight: catalog.OptionalLimit{Known: true, Value: 1280}, Containers: []string{"mp4"}}, Compatibility: catalog.MediaCompatibility{ToolCalling: catalog.CapabilityUnsupported, Streaming: catalog.CapabilityUnsupported, Reasoning: catalog.CapabilityUnsupported, StructuredOutput: catalog.CapabilityUnsupported}, Evidence: evidence, EvidenceRevision: 1}}
		return template
	}
	template.actionBindingID = providergoogle.VideoGenerateActionBindingID
	roles := []vcp.MediaInputRole{vcp.MediaRoleFirstFrame, vcp.MediaRoleLastFrame}
	if identity.upstreamID != "veo-3.1-lite-generate-preview" {
		roles = append(roles, vcp.MediaRoleReference)
	}
	template.mediaInputs = []catalog.MediaInputCapability{{Kind: vcp.MediaImage, Roles: roles, Level: catalog.CapabilityNative, InteractionModes: []catalog.MediaInteractionMode{catalog.MediaInteractionOperationInput}, MediaOnlyPolicy: catalog.MediaOnlyUnsupported, ClientWorkflows: []catalog.ClientResourceWorkflow{catalog.ClientWorkflowUploadThenReference, catalog.ClientWorkflowImportURLThenReference, catalog.ClientWorkflowImportBase64ThenReference, catalog.ClientWorkflowResolveInputPlan}, MaterializationModes: []catalog.UpstreamMaterializationMode{catalog.MaterializationInlineBase64}, Common: catalog.CommonMediaLimits{MIMETypes: []string{"image/jpeg", "image/png"}, MaxItems: catalog.OptionalLimit{Known: true, Value: 3}}, Image: &catalog.ImageMediaLimits{}, Compatibility: catalog.MediaCompatibility{ToolCalling: catalog.CapabilityUnsupported, Streaming: catalog.CapabilityUnsupported, Reasoning: catalog.CapabilityUnsupported, StructuredOutput: catalog.CapabilityUnsupported, RequiresText: true}, Evidence: evidence, EvidenceRevision: 1}}
	resolutions := []string{"720p", "1080p", "4k"}
	if identity.upstreamID == "veo-3.1-lite-generate-preview" {
		resolutions = []string{"720p", "1080p"}
	}
	template.parameters = []catalog.ParameterDescriptor{{ID: "duration_seconds", Kind: catalog.ParameterDuration, FloatRange: &catalog.FloatRange{Minimum: &minimumDuration, Maximum: &maximumDuration}}, {ID: "resolution", Kind: catalog.ParameterEnum, AllowedValues: resolutions}, {ID: "aspect_ratio", Kind: catalog.ParameterEnum, AllowedValues: []string{"16:9", "9:16"}}, {ID: "output_format", Kind: catalog.ParameterFormat, AllowedValues: []string{"mp4"}}}
	return template
}
