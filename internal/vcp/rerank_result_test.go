package vcp

import "testing"

// TestRerankOperationValidateResultsPreservesStableIdentity verifies rank order maps exactly to original candidates.
// TestRerankOperationValidateResultsPreservesStableIdentity 验证排序结果精确映射到原始候选项。
func TestRerankOperationValidateResultsPreservesStableIdentity(t *testing.T) {
	query := "query"
	first := "first"
	second := "second"
	operation := RerankOperation{Query: RerankQuery{ID: "query-1", Content: RerankContent{Text: &query}}, Candidates: []RerankCandidate{{ID: "candidate-1", Content: RerankContent{Text: &first}}, {ID: "candidate-2", Content: RerankContent{Text: &second}}}, Truncation: RerankTruncationNone}
	results := []RerankResult{{CandidateID: "candidate-2", OriginalIndex: 1, Rank: 1, ProviderScore: 0.9, ScoreSemantics: "provider_relevance"}, {CandidateID: "candidate-1", OriginalIndex: 0, Rank: 2, ProviderScore: 0.4, ScoreSemantics: "provider_relevance"}}
	if errValidate := operation.ValidateResults(results); errValidate != nil {
		t.Fatalf("ValidateResults() error = %v", errValidate)
	}
	results[1].Rank = 1
	if errValidate := operation.ValidateResults(results); errValidate == nil {
		t.Fatal("ValidateResults() error = nil, want unstable rank rejection")
	}
}
