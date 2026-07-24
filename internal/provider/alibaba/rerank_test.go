package alibaba

import (
	"errors"
	"testing"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestProjectQwenRerankRequestPreservesOrder verifies the exact compatible request and provider-truncation boundary.
// TestProjectQwenRerankRequestPreservesOrder 验证精确兼容请求与供应商截断边界。
func TestProjectQwenRerankRequestPreservesOrder(t *testing.T) {
	query := "query"
	first := "first"
	second := "second"
	topN := 1
	operation := vcp.RerankOperation{Query: vcp.RerankQuery{ID: "query", Content: vcp.RerankContent{Text: &query}}, Candidates: []vcp.RerankCandidate{{ID: "first", Content: vcp.RerankContent{Text: &first}}, {ID: "second", Content: vcp.RerankContent{Text: &second}}}, TopN: &topN, Truncation: vcp.RerankTruncationProvider}
	request, errProject := projectQwenRerankRequest("qwen3-rerank", operation)
	if errProject != nil {
		t.Fatalf("projectQwenRerankRequest() error = %v", errProject)
	}
	if request.Model != "qwen3-rerank" || request.Query != query || len(request.Documents) != 2 || request.Documents[0] != first || request.Documents[1] != second || request.TopN == nil || *request.TopN != topN {
		t.Fatalf("request = %#v", request)
	}
	operation.Truncation = vcp.RerankTruncationNone
	if _, errProject := projectQwenRerankRequest("qwen3-rerank", operation); !errors.Is(errProject, ErrInvalidRerankDriver) {
		t.Fatalf("no-truncation error = %v", errProject)
	}
}

// TestDecodeQwenRerankResponsePreservesProviderScore verifies result identity, rank, content, and raw score semantics.
// TestDecodeQwenRerankResponsePreservesProviderScore 验证结果身份、排名、内容及原始分数语义。
func TestDecodeQwenRerankResponsePreservesProviderScore(t *testing.T) {
	query := "query"
	first := "first"
	second := "second"
	operation := vcp.RerankOperation{Query: vcp.RerankQuery{ID: "query", Content: vcp.RerankContent{Text: &query}}, Candidates: []vcp.RerankCandidate{{ID: "first", Content: vcp.RerankContent{Text: &first}}, {ID: "second", Content: vcp.RerankContent{Text: &second}}}, ReturnContent: true, Truncation: vcp.RerankTruncationProvider}
	result, errDecode := decodeQwenRerankResponse("qwen3-rerank", operation, qwenRerankResponse{Object: "list", Model: "qwen3-rerank", ID: "request-1", Results: []qwenRerankResult{{Index: 1, RelevanceScore: 0.75}, {Index: 0, RelevanceScore: 0.25}}})
	if errDecode != nil {
		t.Fatalf("decodeQwenRerankResponse() error = %v", errDecode)
	}
	if len(result.Rerank) != 2 || result.Rerank[0].CandidateID != "second" || result.Rerank[0].Rank != 1 || result.Rerank[0].ProviderScore != 0.75 || result.Rerank[0].ScoreSemantics != rerankScoreSemantics || result.Rerank[0].Content == nil || result.UpstreamResponseID != "request-1" {
		t.Fatalf("result = %#v", result)
	}
}

// TestDecodeQwenRerankResponseRejectsDuplicateIndexes verifies provider result corruption is never accepted.
// TestDecodeQwenRerankResponseRejectsDuplicateIndexes 验证供应商结果损坏绝不会被接受。
func TestDecodeQwenRerankResponseRejectsDuplicateIndexes(t *testing.T) {
	query := "query"
	document := "document"
	operation := vcp.RerankOperation{Query: vcp.RerankQuery{ID: "query", Content: vcp.RerankContent{Text: &query}}, Candidates: []vcp.RerankCandidate{{ID: "document", Content: vcp.RerankContent{Text: &document}}}, Truncation: vcp.RerankTruncationProvider}
	_, errDecode := decodeQwenRerankResponse("qwen3-rerank", operation, qwenRerankResponse{Object: "list", Model: "qwen3-rerank", ID: "request-1", Results: []qwenRerankResult{{Index: 0, RelevanceScore: 0.8}, {Index: 0, RelevanceScore: 0.7}}})
	if !errors.Is(errDecode, ErrInvalidRerankResponse) {
		t.Fatalf("duplicate result error = %v", errDecode)
	}
}
