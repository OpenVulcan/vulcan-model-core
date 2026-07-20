package google

import (
	"errors"
	"testing"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestGeminiEmbeddingProjectionDisablesTruncationAndPreservesOrder verifies the official batch contract.
// TestGeminiEmbeddingProjectionDisablesTruncationAndPreservesOrder 验证官方批量合同。
func TestGeminiEmbeddingProjectionDisablesTruncationAndPreservesOrder(t *testing.T) {
	first := "query"
	second := "document"
	dimensions := 2
	operation := vcp.EmbeddingOperation{Inputs: []vcp.EmbeddingInput{{ID: "first", Text: &first}, {ID: "second", Text: &second}}, InputTask: vcp.EmbeddingTaskProviderDefault, OutputKind: vcp.EmbeddingVectorDense, Encoding: vcp.EmbeddingEncodingFloat, Dimensions: &dimensions}
	request, modelName, errProject := projectGeminiEmbeddingRequest("gemini-embedding-2", operation)
	if errProject != nil || modelName != "gemini-embedding-2" || len(request.Requests) != 2 || request.Requests[0].Config.AutoTruncate || request.Requests[0].Config.OutputDimensionality == nil || *request.Requests[0].Config.OutputDimensionality != dimensions {
		t.Fatalf("request=%+v model=%q error=%v", request, modelName, errProject)
	}
	result, errMap := mapGeminiEmbeddingResponse(operation, geminiBatchEmbeddingResponse{Embeddings: []geminiContentEmbedding{{Values: []float64{1, 2}}, {Values: []float64{3, 4}}}})
	if errMap != nil || len(result.Embeddings) != 2 || result.Embeddings[0].InputID != "first" || result.Embeddings[1].InputID != "second" {
		t.Fatalf("result=%+v error=%v", result, errMap)
	}
}

// TestGeminiEmbeddingRejectsTaskRewriteAndDimensionMismatch verifies no hidden prompt or truncation fallback.
// TestGeminiEmbeddingRejectsTaskRewriteAndDimensionMismatch 验证不存在隐藏提示词或截断回退。
func TestGeminiEmbeddingRejectsTaskRewriteAndDimensionMismatch(t *testing.T) {
	text := "query"
	dimensions := 2
	operation := vcp.EmbeddingOperation{Inputs: []vcp.EmbeddingInput{{ID: "first", Text: &text}}, InputTask: vcp.EmbeddingTaskQuery, OutputKind: vcp.EmbeddingVectorDense, Encoding: vcp.EmbeddingEncodingFloat, Dimensions: &dimensions}
	if _, _, errProject := projectGeminiEmbeddingRequest("gemini-embedding-2", operation); !errors.Is(errProject, ErrUnsupportedEmbeddingInput) {
		t.Fatalf("project error=%v", errProject)
	}
	operation.InputTask = vcp.EmbeddingTaskProviderDefault
	_, errMap := mapGeminiEmbeddingResponse(operation, geminiBatchEmbeddingResponse{Embeddings: []geminiContentEmbedding{{Values: []float64{1}}}})
	if !errors.Is(errMap, ErrInvalidEmbeddingResponse) {
		t.Fatalf("map error=%v", errMap)
	}
}
