package openai

import (
	"errors"
	"testing"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestGroundedSearchProjectionPinsToolVersionAndPrompt verifies immutable model-search activation.
// TestGroundedSearchProjectionPinsToolVersionAndPrompt 验证不可变模型搜索启用方式。
func TestGroundedSearchProjectionPinsToolVersionAndPrompt(t *testing.T) {
	operation := vcp.WebSearchOperation{Query: "Vulcan", Domains: vcp.DomainFilter{Allow: []string{"example.com"}}, Location: vcp.SearchLocation{Country: "US", City: "Seattle"}, OutputMode: vcp.WebSearchOutputAnswerWithCitations, EvidenceRequirement: vcp.SearchEvidenceVerified}
	request, errProject := projectGroundedSearchRequest(SearchBackingModelID, operation)
	if errProject != nil {
		t.Fatalf("projectGroundedSearchRequest() error = %v", errProject)
	}
	if request.Model != SearchBackingModelID || request.Instructions != searchPrompt || len(request.Tools) != 1 || request.Tools[0].Type != "web_search_2025_08_26" || request.Tools[0].Filters == nil || request.Tools[0].Filters.AllowedDomains[0] != "example.com" || request.Tools[0].UserLocation == nil || request.Tools[0].UserLocation.Type != "approximate" || len(request.Include) != 1 || request.Include[0] != "web_search_call.action.sources" {
		t.Fatalf("request = %#v", request)
	}
}

// TestGroundedSearchResponsePreservesQueriesSourcesAndCitations verifies no observed search evidence is collapsed.
// TestGroundedSearchResponsePreservesQueriesSourcesAndCitations 验证观测到的搜索证据不会被折叠。
func TestGroundedSearchResponsePreservesQueriesSourcesAndCitations(t *testing.T) {
	inputTokens := int64(10)
	response := groundedSearchResponse{ID: "resp-search", Status: "completed", Usage: &groundedSearchUsage{InputTokens: &inputTokens}, Output: []groundedSearchOutput{
		{ID: "search-1", Type: "web_search_call", Status: "completed", Action: &groundedSearchAction{Type: "search", Query: "Vulcan Router", Sources: []groundedSearchSource{{Type: "url", URL: "https://example.com/source"}}}},
		{ID: "message-1", Type: "message", Status: "completed", Content: []groundedSearchContent{{Type: "output_text", Text: "Answer", Annotations: []groundedSearchAnnotation{{Type: "url_citation", URL: "https://example.com/source", Title: "Source", StartIndex: 0, EndIndex: 6}}}}},
	}}
	result, errMap := mapGroundedSearchResponse(vcp.WebSearchOperation{Query: "Vulcan", EvidenceRequirement: vcp.SearchEvidenceVerified}, response)
	if errMap != nil {
		t.Fatalf("mapGroundedSearchResponse() error = %v", errMap)
	}
	if result.Search == nil || len(result.Search.Queries) != 1 || result.Search.Queries[0] != "Vulcan Router" || len(result.Search.Sources) != 1 || result.Search.Sources[0].URL != "https://example.com/source" || result.Search.Answer != "Answer" || len(result.Search.Citations) != 1 || result.Search.Citations[0].Location.End == nil || *result.Search.Citations[0].Location.End != 6 || result.Search.Usage == nil || result.Search.Usage.InputTokens == nil || *result.Search.Usage.InputTokens != 10 {
		t.Fatalf("result = %#v", result)
	}
}

// TestGroundedSearchVerifiedRequestRejectsMissingSearchCall verifies an ordinary model answer is never mislabeled as web search.
// TestGroundedSearchVerifiedRequestRejectsMissingSearchCall 验证普通模型答案绝不会被错误标记为网页搜索。
func TestGroundedSearchVerifiedRequestRejectsMissingSearchCall(t *testing.T) {
	response := groundedSearchResponse{ID: "resp-no-search", Status: "completed", Output: []groundedSearchOutput{{ID: "message-1", Type: "message", Status: "completed", Content: []groundedSearchContent{{Type: "output_text", Text: "Answer"}}}}}
	_, errMap := mapGroundedSearchResponse(vcp.WebSearchOperation{Query: "Vulcan", EvidenceRequirement: vcp.SearchEvidenceVerified}, response)
	if !errors.Is(errMap, ErrSearchNotObserved) {
		t.Fatalf("mapGroundedSearchResponse() error = %v, want ErrSearchNotObserved", errMap)
	}
}
