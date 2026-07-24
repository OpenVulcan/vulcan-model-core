package management

import (
	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	provideralibaba "github.com/OpenVulcan/vulcan-model-core/internal/provider/alibaba"
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
	}, {
		upstreamID: "qwen3-rerank", displayName: "Qwen3 Rerank", contextWindow: 120000, maxInputTokens: 120000,
		inputModalities: []string{"text"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnsupported, parallelTools: catalog.CapabilityUnsupported, streamingTools: catalog.CapabilityUnsupported, strictSchema: catalog.CapabilityUnsupported, entitlementMode: catalog.EntitlementAllBoundCredentials,
		operation: vcp.OperationRerankDocuments, actionBindingID: provideralibaba.RerankActionBindingID,
		rerank: &catalog.RerankCapabilities{MaxCandidates: catalog.OptionalLimit{Known: true, Value: 500}, TruncationPolicies: []vcp.RerankTruncation{vcp.RerankTruncationProvider}, ReturnContent: true, ScoreSemantics: "alibaba.request_relative_relevance_score"},
	}}
}

// alibabaModelStudioCNEmbeddingModels returns China-only embedding models with an executable compatible dense-vector contract.
// alibabaModelStudioCNEmbeddingModels 返回具有可执行兼容稠密向量合同的中国站专属 Embedding 模型。
func alibabaModelStudioCNEmbeddingModels() []systemModelTemplate {
	return []systemModelTemplate{{
		upstreamID: "qwen3.7-text-embedding", displayName: "Qwen3.7 Text Embedding", contextWindow: 131_072, maxInputTokens: 128_000,
		inputModalities: []string{"text"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnsupported, parallelTools: catalog.CapabilityUnsupported, streamingTools: catalog.CapabilityUnsupported, strictSchema: catalog.CapabilityUnsupported, entitlementMode: catalog.EntitlementAllBoundCredentials,
		operation: vcp.OperationEmbeddingCreate,
		embedding: &catalog.EmbeddingCapabilities{
			InputTasks:        []vcp.EmbeddingInputTask{vcp.EmbeddingTaskProviderDefault},
			OutputKinds:       []vcp.EmbeddingVectorKind{vcp.EmbeddingVectorDense},
			Encodings:         []vcp.EmbeddingEncoding{vcp.EmbeddingEncodingFloat},
			Dimensions:        []int{256, 512, 768, 1024, 1536, 2048, 2560},
			DefaultDimensions: catalog.OptionalLimit{Known: true, Value: 1024},
			MinDimensions:     catalog.OptionalLimit{Known: true, Value: 256},
			MaxDimensions:     catalog.OptionalLimit{Known: true, Value: 2560},
			MaxBatchItems:     catalog.OptionalLimit{Known: true, Value: 20},
		},
	}}
}
