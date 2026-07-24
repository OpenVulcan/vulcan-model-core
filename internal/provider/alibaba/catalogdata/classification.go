package catalogdata

import (
	"slices"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// ClassifiedOperations returns every operation independently established by provider capability codes and exact model exceptions.
// ClassifiedOperations 返回由供应商能力代码与精确模型例外独立证实的全部操作。
func ClassifiedOperations(fact ModelFact) []vcp.OperationKind {
	capabilities := make(map[string]struct{}, len(fact.Capabilities))
	for _, capability := range fact.Capabilities {
		capabilities[capability] = struct{}{}
	}
	// operations follows one fixed order so snapshots and policy files remain reproducible.
	// operations 使用固定顺序，确保快照与策略文件保持可复现。
	operations := make([]vcp.OperationKind, 0, 8)
	if _, exists := capabilities["TTS"]; exists {
		operations = append(operations, vcp.OperationSpeechSynthesize)
	}
	if _, exists := capabilities["ASR"]; exists {
		operations = append(operations, vcp.OperationSpeechTranscribe)
	}
	if _, exists := capabilities["VG"]; exists {
		operations = append(operations, vcp.OperationVideoGenerate)
	}
	if _, exists := capabilities["IG"]; exists {
		operations = append(operations, vcp.OperationImageGenerate)
	}
	if _, exists := capabilities["ME"]; exists {
		operations = append(operations, vcp.OperationEmbeddingCreate)
	}
	if _, exists := capabilities["TR"]; exists {
		switch fact.ModelID {
		case "gte-rerank-v2", "qwen3-rerank", "qwen3-vl-rerank":
			operations = append(operations, vcp.OperationRerankDocuments)
		case "qwen3.7-text-embedding", "text-embedding-async-v1", "text-embedding-async-v2", "text-embedding-v1", "text-embedding-v2", "text-embedding-v3", "text-embedding-v4":
			if !slices.Contains(operations, vcp.OperationEmbeddingCreate) {
				operations = append(operations, vcp.OperationEmbeddingCreate)
			}
		}
	}
	_, textGeneration := capabilities["TG"]
	_, omni := capabilities["Multimodal-Omni"]
	if textGeneration || omni {
		operations = append(operations, vcp.OperationConversationRespond)
	}
	_, visualUnderstanding := capabilities["VU"]
	if visualUnderstanding || omni {
		operations = append(operations, vcp.OperationMediaAnalyze)
	}
	return operations
}
