package anthropic

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestAnthropicSearchMapsServerToolResultsCitationsAndUsage verifies every observable official response node.
// TestAnthropicSearchMapsServerToolResultsCitationsAndUsage 验证每个可观察官方响应节点。
func TestAnthropicSearchMapsServerToolResultsCitationsAndUsage(t *testing.T) {
	operation := vcp.WebSearchOperation{Query: "Vulcan", OutputMode: vcp.WebSearchOutputResultsAndAnswer, EvidenceRequirement: vcp.SearchEvidenceVerified, Domains: vcp.DomainFilter{Allow: []string{"example.com"}}, Location: vcp.SearchLocation{Country: "US", City: "Seattle"}}
	tool, errTool := projectAnthropicSearchTool(operation)
	if errTool != nil || tool.Type != "web_search_20250305" || tool.Name != "web_search" || tool.UserLocation == nil || tool.UserLocation.City != "Seattle" || len(tool.AllowedDomains) != 1 {
		t.Fatalf("tool=%+v error=%v", tool, errTool)
	}
	results, _ := json.Marshal([]anthropicSearchResult{{Type: "web_search_result", URL: "https://example.com/result", Title: "Result"}})
	response := anthropicSearchResponse{ID: "msg-search", Content: []anthropicSearchBlock{{Type: "server_tool_use", Name: "web_search", Input: anthropicSearchInput{Query: "Vulcan Router"}}, {Type: "web_search_tool_result", Content: results}, {Type: "text", Text: "Answer", Citations: []anthropicSearchCitation{{Type: "web_search_result_location", URL: "https://example.com/result", Title: "Result"}}}}, Usage: anthropicSearchUsage{InputTokens: 10, OutputTokens: 5, ServerToolUse: anthropicServerToolUsage{WebSearchRequests: 1}}}
	mapped, errMap := mapAnthropicSearchResponse(operation, response)
	if errMap != nil || mapped.Search == nil || mapped.Search.Evidence.Status != vcp.SearchExecutionConfirmed || len(mapped.Search.Results) != 1 || len(mapped.Search.Citations) != 1 || mapped.Search.Usage == nil || mapped.Search.Usage.ServiceUnits == nil || *mapped.Search.Usage.ServiceUnits != 1 {
		t.Fatalf("mapped=%+v error=%v", mapped, errMap)
	}
}

// TestAnthropicVerifiedSearchRejectsUnobservedToolUse verifies prompt-only answers are not mislabeled.
// TestAnthropicVerifiedSearchRejectsUnobservedToolUse 验证仅提示词答案不会被错误标记。
func TestAnthropicVerifiedSearchRejectsUnobservedToolUse(t *testing.T) {
	operation := vcp.WebSearchOperation{Query: "Vulcan", OutputMode: vcp.WebSearchOutputAnswerWithCitations, EvidenceRequirement: vcp.SearchEvidenceVerified}
	_, errMap := mapAnthropicSearchResponse(operation, anthropicSearchResponse{Content: []anthropicSearchBlock{{Type: "text", Text: "memory-only answer"}}})
	if !errors.Is(errMap, ErrSearchNotObserved) {
		t.Fatalf("map error=%v", errMap)
	}
}
