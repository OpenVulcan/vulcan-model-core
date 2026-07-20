package management

import (
	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	provideropenrouter "github.com/OpenVulcan/vulcan-model-core/internal/provider/openrouter"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// openRouterNativeModels returns the evidence-closed initial OpenRouter embedding and rerank catalog.
// openRouterNativeModels 返回证据封闭的初始 OpenRouter Embedding 与 Rerank 目录。
func openRouterNativeModels() []systemModelTemplate {
	models := []systemModelTemplate{
		{
			upstreamID: "openai/text-embedding-3-small", displayName: "OpenAI Text Embedding 3 Small", contextWindow: 8192,
			inputModalities: []string{"text"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnsupported, parallelTools: catalog.CapabilityUnsupported, streamingTools: catalog.CapabilityUnsupported, strictSchema: catalog.CapabilityUnsupported, entitlementMode: catalog.EntitlementAllBoundCredentials,
			operation: vcp.OperationEmbeddingCreate,
			embedding: &catalog.EmbeddingCapabilities{
				InputTasks: []vcp.EmbeddingInputTask{vcp.EmbeddingTaskProviderDefault}, OutputKinds: []vcp.EmbeddingVectorKind{vcp.EmbeddingVectorDense}, Encodings: []vcp.EmbeddingEncoding{vcp.EmbeddingEncodingFloat},
			},
		},
		{
			upstreamID: "cohere/rerank-v3.5", displayName: "Cohere Rerank 3.5",
			inputModalities: []string{"text"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnsupported, parallelTools: catalog.CapabilityUnsupported, streamingTools: catalog.CapabilityUnsupported, strictSchema: catalog.CapabilityUnsupported, entitlementMode: catalog.EntitlementAllBoundCredentials,
			operation: vcp.OperationRerankDocuments,
			rerank:    &catalog.RerankCapabilities{TruncationPolicies: []vcp.RerankTruncation{vcp.RerankTruncationNone}, ReturnContent: true, ScoreSemantics: "openrouter.relevance_score"},
		},
		{
			upstreamID: "openai/gpt-image-1", displayName: "OpenAI GPT Image 1 via OpenRouter", inputModalities: []string{"text", "image"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnsupported, parallelTools: catalog.CapabilityUnsupported, streamingTools: catalog.CapabilityUnsupported, strictSchema: catalog.CapabilityUnsupported, entitlementMode: catalog.EntitlementAllBoundCredentials,
			operation: vcp.OperationImageGenerate, mediaInputs: []catalog.MediaInputCapability{openRouterImageReferenceCapability()}, mediaOutputs: []catalog.MediaOutputCapability{openRouterImageOutputCapability()}, usageMetrics: []catalog.UsageMetricCapability{{Unit: catalog.UsageUnitImages, Accuracy: catalog.UsageExact}},
		},
		{
			upstreamID: "google/veo-3.1", displayName: "Google Veo 3.1 via OpenRouter", inputModalities: []string{"text", "image"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnsupported, parallelTools: catalog.CapabilityUnsupported, streamingTools: catalog.CapabilityUnsupported, strictSchema: catalog.CapabilityUnsupported, entitlementMode: catalog.EntitlementAllBoundCredentials,
			operation: vcp.OperationVideoGenerate, actionBindingID: provideropenrouter.VideoGenerateActionBindingID, mediaInputs: []catalog.MediaInputCapability{openRouterVideoFrameCapability()}, mediaOutputs: []catalog.MediaOutputCapability{openRouterVideoOutputCapability()}, parameters: openRouterVideoParameters(), usageMetrics: []catalog.UsageMetricCapability{{Unit: catalog.UsageUnitVideoMilliseconds, Accuracy: catalog.UsageExact}},
		},
	}
	return append(models, openRouterAudioModels()...)
}

// openRouterVideoFrameCapability returns the observed Veo 3.1 first-and-last-frame contract.
// openRouterVideoFrameCapability 返回已观测的 Veo 3.1 首尾帧合同。
func openRouterVideoFrameCapability() catalog.MediaInputCapability {
	return catalog.MediaInputCapability{Kind: vcp.MediaImage, Roles: []vcp.MediaInputRole{vcp.MediaRoleFirstFrame, vcp.MediaRoleLastFrame}, Level: catalog.CapabilityNative, InteractionModes: []catalog.MediaInteractionMode{catalog.MediaInteractionOperationInput}, MediaOnlyPolicy: catalog.MediaOnlyUnsupported, ClientWorkflows: []catalog.ClientResourceWorkflow{catalog.ClientWorkflowUploadThenReference, catalog.ClientWorkflowImportURLThenReference, catalog.ClientWorkflowImportBase64ThenReference, catalog.ClientWorkflowResolveInputPlan}, MaterializationModes: []catalog.UpstreamMaterializationMode{catalog.MaterializationInlineBase64, catalog.MaterializationDirectRemoteURL}, Common: catalog.CommonMediaLimits{MIMETypes: []string{"image/png", "image/jpeg", "image/webp"}, MaxItems: catalog.OptionalLimit{Known: true, Value: 2}, AllowsRemoteURL: catalog.OptionalBool{Known: true, Value: true}}, Image: &catalog.ImageMediaLimits{}, Compatibility: catalog.MediaCompatibility{ToolCalling: catalog.CapabilityUnsupported, Streaming: catalog.CapabilityUnsupported, Reasoning: catalog.CapabilityUnsupported, StructuredOutput: catalog.CapabilityUnsupported, RequiresText: true}, Evidence: []catalog.CapabilityEvidence{{Source: catalog.ModelSourceProviderAPI, Reference: "https://openrouter.ai/docs/api/api-reference/video-generation/list-videos-models", ObservedAt: mediaEvidenceObservedAt(), Revision: 1}}, EvidenceRevision: 1}
}

// openRouterVideoOutputCapability returns the observed asynchronous Veo 3.1 MP4 contract.
// openRouterVideoOutputCapability 返回已观测的异步 Veo 3.1 MP4 合同。
func openRouterVideoOutputCapability() catalog.MediaOutputCapability {
	return catalog.MediaOutputCapability{Kind: vcp.MediaVideo, Level: catalog.CapabilityNative, Formats: []string{"mp4"}, MaxOutputs: catalog.OptionalLimit{Known: true, Value: 1}, Video: &catalog.VideoMediaLimits{MaxDurationMilliseconds: catalog.OptionalLimit{Known: true, Value: 8000}, MaxWidth: catalog.OptionalLimit{Known: true, Value: 1280}, MaxHeight: catalog.OptionalLimit{Known: true, Value: 1280}, Containers: []string{"mp4"}, EmbeddedAudio: catalog.OptionalBool{Known: true, Value: true}}, Delivery: catalog.DeliveryCapabilities{Asynchronous: true, Polling: true}, Evidence: []catalog.CapabilityEvidence{{Source: catalog.ModelSourceProviderAPI, Reference: "https://openrouter.ai/docs/api/api-reference/video-generation/list-videos-models", ObservedAt: mediaEvidenceObservedAt(), Revision: 1}}, EvidenceRevision: 1}
}

// openRouterVideoParameters returns the observed Veo 3.1 endpoint-specific controls.
// openRouterVideoParameters 返回已观测的 Veo 3.1 端点专属控制项。
func openRouterVideoParameters() []catalog.ParameterDescriptor {
	minimumDuration, maximumDuration := float64(5), float64(8)
	return []catalog.ParameterDescriptor{{ID: "duration_seconds", Kind: catalog.ParameterDuration, FloatRange: &catalog.FloatRange{Minimum: &minimumDuration, Maximum: &maximumDuration}}, {ID: "aspect_ratio", Kind: catalog.ParameterEnum, AllowedValues: []string{"16:9"}}, {ID: "resolution", Kind: catalog.ParameterEnum, AllowedValues: []string{"720p"}}, {ID: "output_format", Kind: catalog.ParameterFormat, AllowedValues: []string{"mp4"}}}
}
