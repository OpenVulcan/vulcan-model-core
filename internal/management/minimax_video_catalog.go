package management

import (
	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	providerminimax "github.com/OpenVulcan/vulcan-model-core/internal/provider/minimax"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// miniMaxModels returns the complete evidence-backed MiniMax native catalog.
// miniMaxModels 返回完整且有证据支持的 MiniMax 原生目录。
func miniMaxModels() []systemModelTemplate {
	models := miniMaxTextModels()
	models = append(models, miniMaxVisionModels()...)
	models = append(models, miniMaxImageModels()...)
	models = append(models, miniMaxVideoModels()...)
	models = append(models, miniMaxSpeechModels()...)
	models = append(models, miniMaxMusicModels()...)
	return models
}

// miniMaxVisionModels returns the model-like catalog handle for MiniMax's model-free VLM endpoint.
// miniMaxVisionModels 返回 MiniMax 无模型参数 VLM 端点的模型式目录句柄。
func miniMaxVisionModels() []systemModelTemplate {
	evidence := []catalog.CapabilityEvidence{{Source: catalog.ModelSourceProviderAPI, Reference: "minimax-cli/src/commands/vision/describe.ts", ObservedAt: mediaEvidenceObservedAt(), Revision: 1}}
	return []systemModelTemplate{{
		upstreamID: "minimax-vlm", displayName: "MiniMax VLM", inputModalities: []string{"image"}, reasoning: catalog.CapabilityUnsupported,
		toolCalling: catalog.CapabilityUnsupported, parallelTools: catalog.CapabilityUnsupported, streamingTools: catalog.CapabilityUnsupported,
		strictSchema: catalog.CapabilityUnsupported, entitlementMode: catalog.EntitlementAllBoundCredentials, operation: vcp.OperationMediaAnalyze,
		actionBindingID: providerminimax.MediaAnalyzeActionBindingID,
		mediaInputs:     []catalog.MediaInputCapability{{Kind: vcp.MediaImage, Roles: []vcp.MediaInputRole{vcp.MediaRoleUnderstanding}, Level: catalog.CapabilityNative, InteractionModes: []catalog.MediaInteractionMode{catalog.MediaInteractionAnalysis, catalog.MediaInteractionOperationInput}, MediaOnlyPolicy: catalog.MediaOnlyNative, ClientWorkflows: []catalog.ClientResourceWorkflow{catalog.ClientWorkflowUploadThenReference, catalog.ClientWorkflowImportURLThenReference, catalog.ClientWorkflowImportBase64ThenReference, catalog.ClientWorkflowResolveInputPlan}, MaterializationModes: []catalog.UpstreamMaterializationMode{catalog.MaterializationInlineBase64}, Common: catalog.CommonMediaLimits{MIMETypes: []string{"image/jpeg", "image/png", "image/webp"}, MaxItemBytes: catalog.OptionalLimit{Known: true, Value: 50 << 20}, MaxItems: catalog.OptionalLimit{Known: true, Value: 1}}, Image: &catalog.ImageMediaLimits{}, Compatibility: catalog.MediaCompatibility{ToolCalling: catalog.CapabilityUnsupported, Streaming: catalog.CapabilityUnsupported, Reasoning: catalog.CapabilityUnsupported, StructuredOutput: catalog.CapabilityUnsupported, RequiresText: false}, Evidence: evidence, EvidenceRevision: 1}},
	}}
}

// miniMaxTextModels returns the exact default text model proved by the pinned minimax-cli source.
// miniMaxTextModels 返回固定 minimax-cli 源码证明的精确默认文本模型。
func miniMaxTextModels() []systemModelTemplate {
	return []systemModelTemplate{{
		upstreamID: "MiniMax-M3", displayName: "MiniMax M3", contextWindow: 1048576, maxInputTokens: 1048576, maxOutputTokens: 32768, inputModalities: []string{"text"},
		reasoning: catalog.CapabilityNative, toolCalling: catalog.CapabilityNative, parallelTools: catalog.CapabilityUnknown,
		streamingTools: catalog.CapabilityNative, strictSchema: catalog.CapabilityUnknown, entitlementMode: catalog.EntitlementAllBoundCredentials,
		operation: vcp.OperationConversationRespond, actionBindingID: providerminimax.ConversationRespondActionBindingID,
	}}
}

// miniMaxVideoModels returns operation-specific Hailuo video templates.
// miniMaxVideoModels 返回操作专属 Hailuo 视频模板。
func miniMaxVideoModels() []systemModelTemplate {
	models := make([]systemModelTemplate, 0, 4)
	for _, identity := range []systemModelIdentity{{upstreamID: "MiniMax-Hailuo-2.3", displayName: "MiniMax Hailuo 2.3"}, {upstreamID: "MiniMax-Hailuo-2.3-Fast", displayName: "MiniMax Hailuo 2.3 Fast"}, {upstreamID: "MiniMax-Hailuo-02", displayName: "MiniMax Hailuo 02"}, {upstreamID: "S2V-01", displayName: "MiniMax S2V 01"}} {
		models = append(models, miniMaxVideoTemplate(identity))
	}
	return models
}

// miniMaxVideoTemplate builds one closed model-specific video generation contract.
// miniMaxVideoTemplate 构建一个封闭且模型专属的视频生成合同。
func miniMaxVideoTemplate(identity systemModelIdentity) systemModelTemplate {
	minimumDuration, maximumDuration, defaultDuration := 6.0, 10.0, 6.0
	evidence := []catalog.CapabilityEvidence{{Source: catalog.ModelSourceProviderAPI, Reference: "https://platform.minimax.io/docs/api-reference/video-generation-i2v", ObservedAt: mediaEvidenceObservedAt(), Revision: 1}}
	roles := []vcp.MediaInputRole{vcp.MediaRoleFirstFrame}
	if identity.upstreamID == "MiniMax-Hailuo-02" {
		roles = append(roles, vcp.MediaRoleLastFrame)
	}
	if identity.upstreamID == "S2V-01" {
		roles = []vcp.MediaInputRole{vcp.MediaRoleSubjectReference}
	}
	inputModalities := []string{"text", "image"}
	if identity.upstreamID == "MiniMax-Hailuo-2.3-Fast" {
		inputModalities = []string{"image", "text"}
	}
	return systemModelTemplate{
		upstreamID: identity.upstreamID, displayName: identity.displayName, inputModalities: inputModalities, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnsupported, parallelTools: catalog.CapabilityUnsupported, streamingTools: catalog.CapabilityUnsupported, strictSchema: catalog.CapabilityUnsupported, entitlementMode: catalog.EntitlementAllBoundCredentials,
		operation: vcp.OperationVideoGenerate, actionBindingID: providerminimax.VideoGenerateActionBindingID,
		mediaInputs:  []catalog.MediaInputCapability{{Kind: vcp.MediaImage, Roles: roles, Level: catalog.CapabilityNative, InteractionModes: []catalog.MediaInteractionMode{catalog.MediaInteractionOperationInput}, MediaOnlyPolicy: catalog.MediaOnlyUnsupported, ClientWorkflows: []catalog.ClientResourceWorkflow{catalog.ClientWorkflowUploadThenReference, catalog.ClientWorkflowImportURLThenReference, catalog.ClientWorkflowImportBase64ThenReference, catalog.ClientWorkflowResolveInputPlan}, MaterializationModes: []catalog.UpstreamMaterializationMode{catalog.MaterializationInlineBase64, catalog.MaterializationDirectRemoteURL}, Common: catalog.CommonMediaLimits{MIMETypes: []string{"image/jpeg", "image/png", "image/webp"}, MaxItemBytes: catalog.OptionalLimit{Known: true, Value: 20 << 20}, MaxItems: catalog.OptionalLimit{Known: true, Value: int64(len(roles))}, AllowsRemoteURL: catalog.OptionalBool{Known: true, Value: true}}, Image: &catalog.ImageMediaLimits{}, Compatibility: catalog.MediaCompatibility{ToolCalling: catalog.CapabilityUnsupported, Streaming: catalog.CapabilityUnsupported, Reasoning: catalog.CapabilityUnsupported, StructuredOutput: catalog.CapabilityUnsupported, RequiresText: true}, Evidence: evidence, EvidenceRevision: 1}},
		mediaOutputs: []catalog.MediaOutputCapability{{Kind: vcp.MediaVideo, Level: catalog.CapabilityNative, Formats: []string{"mp4"}, MaxOutputs: catalog.OptionalLimit{Known: true, Value: 1}, Video: &catalog.VideoMediaLimits{MaxDurationMilliseconds: catalog.OptionalLimit{Known: true, Value: 10000}, MaxWidth: catalog.OptionalLimit{Known: true, Value: 1920}, MaxHeight: catalog.OptionalLimit{Known: true, Value: 1920}, Containers: []string{"mp4"}}, Delivery: catalog.DeliveryCapabilities{Asynchronous: true, Polling: true}, Evidence: evidence, EvidenceRevision: 1}},
		parameters:   []catalog.ParameterDescriptor{{ID: "duration_seconds", Kind: catalog.ParameterDuration, FloatRange: &catalog.FloatRange{Minimum: &minimumDuration, Maximum: &maximumDuration}, Default: &catalog.ParameterDefault{Source: catalog.ParameterDefaultProvider, Float: &defaultDuration}}, {ID: "resolution", Kind: catalog.ParameterEnum, AllowedValues: miniMaxVideoResolutions(identity.upstreamID)}, {ID: "prompt_extend", Kind: catalog.ParameterBoolean}},
		usageMetrics: []catalog.UsageMetricCapability{{Unit: catalog.UsageUnitVideoMilliseconds, Accuracy: catalog.UsageExact}},
	}
}

// miniMaxVideoResolutions returns the exact model-scoped resolution set.
// miniMaxVideoResolutions 返回精确的模型作用域分辨率集合。
func miniMaxVideoResolutions(model string) []string {
	if model == "MiniMax-Hailuo-02" || model == "S2V-01" {
		return []string{"512P", "768P", "1080P"}
	}
	return []string{"768P", "1080P"}
}
