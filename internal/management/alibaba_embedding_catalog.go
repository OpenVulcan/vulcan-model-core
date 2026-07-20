package management

import (
	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// alibabaModelStudioEmbeddingModels returns the evidence-closed compatible text embedding catalog.
// alibabaModelStudioEmbeddingModels 返回证据封闭的兼容文本 Embedding 目录。
func alibabaModelStudioEmbeddingModels() []systemModelTemplate {
	return []systemModelTemplate{{
		upstreamID: "text-embedding-v4", displayName: "Text Embedding V4", contextWindow: 8192, maxInputTokens: 8192,
		inputModalities: []string{"text"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnsupported, parallelTools: catalog.CapabilityUnsupported, streamingTools: catalog.CapabilityUnsupported, strictSchema: catalog.CapabilityUnsupported, entitlementMode: catalog.EntitlementAllBoundCredentials,
		operation: vcp.OperationEmbeddingCreate,
		embedding: &catalog.EmbeddingCapabilities{
			InputTasks:        []vcp.EmbeddingInputTask{vcp.EmbeddingTaskProviderDefault},
			OutputKinds:       []vcp.EmbeddingVectorKind{vcp.EmbeddingVectorDense},
			Encodings:         []vcp.EmbeddingEncoding{vcp.EmbeddingEncodingFloat},
			Dimensions:        []int{64, 128, 256, 512, 768, 1024, 1536, 2048},
			DefaultDimensions: catalog.OptionalLimit{Known: true, Value: 1024},
			MinDimensions:     catalog.OptionalLimit{Known: true, Value: 64},
			MaxDimensions:     catalog.OptionalLimit{Known: true, Value: 2048},
			MaxBatchItems:     catalog.OptionalLimit{Known: true, Value: 10},
		},
	}}
}
