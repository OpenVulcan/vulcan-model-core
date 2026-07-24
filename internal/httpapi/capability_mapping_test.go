package httpapi

import (
	"testing"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestCapabilityMappingRoundTripPreservesRecommendations verifies the custom-catalog HTTP boundary does not fuse defaults with hard token limits.
// TestCapabilityMappingRoundTripPreservesRecommendations 验证自定义目录 HTTP 边界不会把默认值与 Token 硬上限融合。
func TestCapabilityMappingRoundTripPreservesRecommendations(t *testing.T) {
	capabilities := catalog.ModelCapabilities{
		Tokens: catalog.TokenLimits{
			ContextWindow:      catalog.OptionalTokenLimit{Known: true, Value: 1_000_000},
			MaxOutputTokens:    catalog.OptionalTokenLimit{Known: true, Value: 131_072},
			MaxReasoningTokens: catalog.OptionalTokenLimit{Known: true, Value: 262_144},
		},
		Recommendations: catalog.TokenRecommendations{
			OutputTokens:    catalog.OptionalTokenLimit{Known: true, Value: 32_768},
			ReasoningTokens: catalog.OptionalTokenLimit{Known: true, Value: 8_192},
		},
		InputModalities:  []string{"text"},
		OutputModalities: []string{"text"},
		HostedTools:      []vcp.ToolKind{vcp.ToolNativeWebSearch},
	}
	roundTrip := capabilityFromView(capabilityView(capabilities))
	if roundTrip.Tokens != capabilities.Tokens || roundTrip.Recommendations != capabilities.Recommendations || len(roundTrip.HostedTools) != 1 || roundTrip.HostedTools[0] != vcp.ToolNativeWebSearch {
		t.Fatalf("round-trip token facts = limits %#v recommendations %#v", roundTrip.Tokens, roundTrip.Recommendations)
	}
}
