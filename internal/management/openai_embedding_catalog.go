package management

import (
	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	provideropenai "github.com/OpenVulcan/vulcan-model-core/internal/provider/openai"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// openAIAPIModels returns the fixed grounded-search model and official embedding models with exact limits.
// openAIAPIModels 返回固定联网搜索模型及具有精确限制的官方 Embedding 模型。
func openAIAPIModels() []systemModelTemplate {
	models := []systemModelTemplate{
		{
			upstreamID: provideropenai.SearchBackingModelID, displayName: "GPT-5.4 Nano 2026-03-17", contextWindow: 400000, maxOutputTokens: 128000,
			inputModalities: []string{"text", "image"}, reasoning: catalog.CapabilityNative, toolCalling: catalog.CapabilityNative, parallelTools: catalog.CapabilityNative, streamingTools: catalog.CapabilityNative, strictSchema: catalog.CapabilityNative, entitlementMode: catalog.EntitlementAllBoundCredentials,
		},
		{
			upstreamID: "text-embedding-3-small", displayName: "Text Embedding 3 Small", contextWindow: 8192, maxInputTokens: 8192,
			inputModalities: []string{"text"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnsupported, parallelTools: catalog.CapabilityUnsupported, streamingTools: catalog.CapabilityUnsupported, strictSchema: catalog.CapabilityUnsupported, entitlementMode: catalog.EntitlementAllBoundCredentials,
			operation: vcp.OperationEmbeddingCreate,
			embedding: &catalog.EmbeddingCapabilities{
				InputTasks: []vcp.EmbeddingInputTask{vcp.EmbeddingTaskProviderDefault}, OutputKinds: []vcp.EmbeddingVectorKind{vcp.EmbeddingVectorDense}, Encodings: []vcp.EmbeddingEncoding{vcp.EmbeddingEncodingFloat}, MaxBatchItems: catalog.OptionalLimit{Known: true, Value: 2048},
			},
		},
		{
			upstreamID: "text-embedding-3-large", displayName: "Text Embedding 3 Large", contextWindow: 8192, maxInputTokens: 8192,
			inputModalities: []string{"text"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnsupported, parallelTools: catalog.CapabilityUnsupported, streamingTools: catalog.CapabilityUnsupported, strictSchema: catalog.CapabilityUnsupported, entitlementMode: catalog.EntitlementAllBoundCredentials,
			operation: vcp.OperationEmbeddingCreate,
			embedding: &catalog.EmbeddingCapabilities{
				InputTasks: []vcp.EmbeddingInputTask{vcp.EmbeddingTaskProviderDefault}, OutputKinds: []vcp.EmbeddingVectorKind{vcp.EmbeddingVectorDense}, Encodings: []vcp.EmbeddingEncoding{vcp.EmbeddingEncodingFloat}, MaxBatchItems: catalog.OptionalLimit{Known: true, Value: 2048},
			},
		},
		{
			upstreamID: "gpt-image-2", displayName: "GPT Image 2", inputModalities: []string{"text"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnsupported, parallelTools: catalog.CapabilityUnsupported, streamingTools: catalog.CapabilityUnsupported, strictSchema: catalog.CapabilityUnsupported, entitlementMode: catalog.EntitlementAllBoundCredentials,
			operation: vcp.OperationImageGenerate, mediaOutputs: []catalog.MediaOutputCapability{openAIImageOutputCapability()}, parameters: openAIImageParameters(true), parameterRules: openAIImageSizeRules(), usageMetrics: []catalog.UsageMetricCapability{{Unit: catalog.UsageUnitImages, Accuracy: catalog.UsageExact}},
		},
		{
			upstreamID: "gpt-image-2", displayName: "GPT Image 2 Edit", inputModalities: []string{"text", "image"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnsupported, parallelTools: catalog.CapabilityUnsupported, streamingTools: catalog.CapabilityUnsupported, strictSchema: catalog.CapabilityUnsupported, entitlementMode: catalog.EntitlementAllBoundCredentials,
			operation: vcp.OperationImageEdit, mediaInputs: openAIImageEditCapabilities(), mediaOutputs: []catalog.MediaOutputCapability{openAIImageOutputCapability()}, parameters: openAIImageParameters(false), parameterRules: openAIImageSizeRules(), usageMetrics: []catalog.UsageMetricCapability{{Unit: catalog.UsageUnitImages, Accuracy: catalog.UsageExact}},
		},
	}
	models[0].mediaInputs = []catalog.MediaInputCapability{openAIImageUnderstandingCapability()}
	return append(models, openAIAudioModels()...)
}
