package google

import (
	"errors"
	"testing"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestGoogleSearchMapsProviderQueriesAndCitationSpans verifies observable Interactions grounding.
// TestGoogleSearchMapsProviderQueriesAndCitationSpans 验证可观察 Interactions 联网证据。
func TestGoogleSearchMapsProviderQueriesAndCitationSpans(t *testing.T) {
	operation := vcp.WebSearchOperation{Query: "Vulcan", OutputMode: vcp.WebSearchOutputAnswerWithCitations, EvidenceRequirement: vcp.SearchEvidenceVerified}
	if errPolicy := validateGoogleSearchPolicy(operation); errPolicy != nil {
		t.Fatalf("validate policy: %v", errPolicy)
	}
	response := googleSearchResponse{ID: "interaction-1", Steps: []googleSearchStep{{Type: "google_search_call", Arguments: googleSearchArguments{Queries: []string{"Vulcan Router"}}}, {Type: "model_output", Content: []googleSearchContent{{Type: "text", Text: "Answer", Annotations: []googleSearchAnnotation{{Type: "url_citation", URL: "https://example.com", Title: "Example", StartIndex: 0, EndIndex: 6}}}}}}}
	mapped, errMap := mapGoogleSearchResponse(operation, response)
	if errMap != nil || mapped.Search == nil || mapped.Search.Evidence.Status != vcp.SearchExecutionConfirmed || len(mapped.Search.Queries) != 1 || len(mapped.Search.Citations) != 1 || mapped.UpstreamResponseID != "interaction-1" {
		t.Fatalf("mapped=%+v error=%v", mapped, errMap)
	}
}

// TestGoogleVerifiedSearchRejectsUnobservedAndUnsupportedFilters verifies exact capability publication.
// TestGoogleVerifiedSearchRejectsUnobservedAndUnsupportedFilters 验证精确能力发布。
func TestGoogleVerifiedSearchRejectsUnobservedAndUnsupportedFilters(t *testing.T) {
	operation := vcp.WebSearchOperation{Query: "Vulcan", OutputMode: vcp.WebSearchOutputAnswerWithCitations, EvidenceRequirement: vcp.SearchEvidenceVerified}
	if _, errMap := mapGoogleSearchResponse(operation, googleSearchResponse{}); !errors.Is(errMap, ErrSearchNotObserved) {
		t.Fatalf("map error=%v", errMap)
	}
	operation.Domains.Allow = []string{"example.com"}
	if errPolicy := validateGoogleSearchPolicy(operation); !errors.Is(errPolicy, ErrUnsupportedSearchInput) {
		t.Fatalf("policy error=%v", errPolicy)
	}
}
