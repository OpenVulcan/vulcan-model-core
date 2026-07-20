package openai

import (
	"errors"
	"testing"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestCompatibleEmbeddingProjectionAndMappingPreserveOrderedIdentity verifies documented fields and reordered indexes.
// TestCompatibleEmbeddingProjectionAndMappingPreserveOrderedIdentity 验证文档字段与重排索引保留有序身份。
func TestCompatibleEmbeddingProjectionAndMappingPreserveOrderedIdentity(t *testing.T) {
	first := "first"
	second := "second"
	operation := vcp.EmbeddingOperation{Inputs: []vcp.EmbeddingInput{{ID: "input-first", Text: &first}, {ID: "input-second", Text: &second}}, InputTask: vcp.EmbeddingTaskProviderDefault, OutputKind: vcp.EmbeddingVectorDense, Encoding: vcp.EmbeddingEncodingFloat}
	request, errProject := projectCompatibleEmbeddingRequest("text-embedding-3-small", operation)
	if errProject != nil || request.Model != "text-embedding-3-small" || request.EncodingFormat != "float" || len(request.Input) != 2 || request.Input[1] != second {
		t.Fatalf("request=%+v error=%v", request, errProject)
	}
	response := compatibleEmbeddingResponse{ID: "embed-1", Model: "text-embedding-3-small", Data: []compatibleEmbeddingData{{Index: 1, Embedding: compatibleEmbeddingValue{Values: []float64{3, 4}}}, {Index: 0, Embedding: compatibleEmbeddingValue{Values: []float64{1, 2}}}}}
	result, errMap := mapCompatibleEmbeddingResponse("text-embedding-3-small", operation, response)
	if errMap != nil || result.UpstreamResponseID != "embed-1" || len(result.Embeddings) != 2 || result.Embeddings[0].InputID != "input-first" || result.Embeddings[1].Dense.Values[0] != 3 {
		t.Fatalf("result=%+v error=%v", result, errMap)
	}
}

// TestCompatibleEmbeddingRejectsUnprovenBase64DimensionsAndModelDrift verifies conservative provider boundaries.
// TestCompatibleEmbeddingRejectsUnprovenBase64DimensionsAndModelDrift 验证保守供应商边界。
func TestCompatibleEmbeddingRejectsUnprovenBase64DimensionsAndModelDrift(t *testing.T) {
	text := "input"
	operation := vcp.EmbeddingOperation{Inputs: []vcp.EmbeddingInput{{ID: "input-1", Text: &text}}, InputTask: vcp.EmbeddingTaskProviderDefault, OutputKind: vcp.EmbeddingVectorDense, Encoding: vcp.EmbeddingEncodingBase64}
	if _, errProject := projectCompatibleEmbeddingRequest("text-embedding-3-small", operation); !errors.Is(errProject, ErrUnsupportedEmbeddingInput) {
		t.Fatalf("project error=%v", errProject)
	}
	operation.Encoding = vcp.EmbeddingEncodingFloat
	_, errMap := mapCompatibleEmbeddingResponse("text-embedding-3-small", operation, compatibleEmbeddingResponse{Model: "different-model", Data: []compatibleEmbeddingData{{Index: 0, Embedding: compatibleEmbeddingValue{Values: []float64{1}}}}})
	if !errors.Is(errMap, ErrInvalidEmbeddingResponse) {
		t.Fatalf("map error=%v", errMap)
	}
}
