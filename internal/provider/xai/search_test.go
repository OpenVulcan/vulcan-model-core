package xai

import (
	"errors"
	"testing"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestXAISearchMapsSourcesAndInlineCitationsSeparately verifies the documented Responses shapes.
// TestXAISearchMapsSourcesAndInlineCitationsSeparately 验证文档记录的 Responses 结构。
func TestXAISearchMapsSourcesAndInlineCitationsSeparately(t *testing.T) {
	operation := vcp.WebSearchOperation{Query: "Vulcan", OutputMode: vcp.WebSearchOutputAnswerWithCitations, EvidenceRequirement: vcp.SearchEvidenceVerified, Domains: vcp.DomainFilter{Allow: []string{"example.com"}}}
	tool, errTool := projectXAISearchTool(operation)
	if errTool != nil || tool.Type != "web_search" || len(tool.AllowedDomains) != 1 {
		t.Fatalf("tool=%+v error=%v", tool, errTool)
	}
	response := xaiSearchResponse{ID: "response-1", Citations: []string{"https://example.com/source"}, Output: []xaiSearchOutput{{Type: "message", Content: []xaiSearchContent{{Type: "output_text", Text: "Answer", Annotations: []xaiSearchAnnotation{{Type: "url_citation", URL: "https://example.com/source", Title: "Source", StartIndex: 0, EndIndex: 6}}}}}}}
	mapped, errMap := mapXAISearchResponse(operation, response)
	if errMap != nil || mapped.Search == nil || mapped.Search.Evidence.Status != vcp.SearchExecutionConfirmed || len(mapped.Search.Sources) != 1 || len(mapped.Search.Citations) != 1 || mapped.UpstreamResponseID != "response-1" {
		t.Fatalf("mapped=%+v error=%v", mapped, errMap)
	}
}

// TestXAIVerifiedSearchRejectsUnobservedAndConflictingDomains verifies evidence and filter boundaries.
// TestXAIVerifiedSearchRejectsUnobservedAndConflictingDomains 验证证据与过滤边界。
func TestXAIVerifiedSearchRejectsUnobservedAndConflictingDomains(t *testing.T) {
	operation := vcp.WebSearchOperation{Query: "Vulcan", OutputMode: vcp.WebSearchOutputAnswerWithCitations, EvidenceRequirement: vcp.SearchEvidenceVerified}
	if _, errMap := mapXAISearchResponse(operation, xaiSearchResponse{}); !errors.Is(errMap, ErrSearchNotObserved) {
		t.Fatalf("map error=%v", errMap)
	}
	operation.Domains = vcp.DomainFilter{Allow: []string{"example.com"}, Block: []string{"blocked.example"}}
	if _, errTool := projectXAISearchTool(operation); !errors.Is(errTool, ErrUnsupportedSearchInput) {
		t.Fatalf("tool error=%v", errTool)
	}
}
