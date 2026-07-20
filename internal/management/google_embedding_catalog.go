package management

import (
	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// geminiAIStudioModels combines existing conversation models with the evidence-closed Gemini Embedding 2 Profile.
// geminiAIStudioModels 将既有会话模型与证据封闭的 Gemini Embedding 2 Profile 组合。
func geminiAIStudioModels() []systemModelTemplate {
	models := geminiAPITextModels()
	// mediaAnalyzeTemplate preserves the independently addressable action while sharing one provider model identity.
	// mediaAnalyzeTemplate 保留可独立寻址的动作，同时共享同一个供应商模型身份。
	var mediaAnalyzeTemplate systemModelTemplate
	for index := range models {
		if models[index].upstreamID == "gemini-2.5-flash" {
			models[index].contextWindow = 1048576
			models[index].maxInputTokens = 1048576
			models[index].maxOutputTokens = 65536
			models[index].inputModalities = []string{"text", "image", "audio", "video"}
			models[index].mediaInputs = gemini25FlashMediaInputs()
			mediaAnalyzeTemplate = models[index]
			mediaAnalyzeTemplate.operation = vcp.OperationMediaAnalyze
		}
	}
	models = append(models, systemModelTemplate{
		upstreamID: "gemini-embedding-2", displayName: "Gemini Embedding 2", contextWindow: 8192, maxInputTokens: 8192,
		inputModalities: []string{"text"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnsupported, parallelTools: catalog.CapabilityUnsupported, streamingTools: catalog.CapabilityUnsupported, strictSchema: catalog.CapabilityUnsupported, entitlementMode: catalog.EntitlementAllBoundCredentials,
		operation: vcp.OperationEmbeddingCreate,
		embedding: &catalog.EmbeddingCapabilities{
			InputTasks: []vcp.EmbeddingInputTask{vcp.EmbeddingTaskProviderDefault}, OutputKinds: []vcp.EmbeddingVectorKind{vcp.EmbeddingVectorDense}, Encodings: []vcp.EmbeddingEncoding{vcp.EmbeddingEncodingFloat},
			DefaultDimensions: catalog.OptionalLimit{Known: true, Value: 3072}, MinDimensions: catalog.OptionalLimit{Known: true, Value: 128}, MaxDimensions: catalog.OptionalLimit{Known: true, Value: 3072}, Normalized: catalog.OptionalBool{Known: true, Value: true},
		},
	})
	models = append(models, mediaAnalyzeTemplate)
	models = append(models, googleVeoModels()...)
	return models
}
