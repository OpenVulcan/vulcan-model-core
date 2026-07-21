package xai

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
)

// TestXAIBillingSupportsWrappedSnakeCaseValues verifies every source-router billing shape.
// TestXAIBillingSupportsWrappedSnakeCaseValues 验证来源路由项目支持的全部计费形态。
func TestXAIBillingSupportsWrappedSnakeCaseValues(t *testing.T) {
	var payload xaiBillingResponse
	if errDecode := json.Unmarshal([]byte(`{"config":{"monthly_limit":{"val":"15000"},"used":{"val":3000},"on_demand_cap":"5000","billing_period_end":"2026-08-01T00:00:00Z"}}`), &payload); errDecode != nil {
		t.Fatalf("decode xAI billing fixture: %v", errDecode)
	}
	allowances, errAllowances := xaiBillingAllowances(*payload.Config, providerconfig.ProviderInstance{ID: "pvi_xai"}, providerconfig.Credential{ID: "cred_xai"}, time.Date(2026, 7, 21, 0, 0, 0, 0, time.UTC))
	if errAllowances != nil || len(allowances) != 2 {
		t.Fatalf("xAI allowances = %#v error=%v", allowances, errAllowances)
	}
	if allowances[0].Kind != catalog.AllowanceWindowQuota || allowances[0].Remaining == nil || *allowances[0].Remaining != "12000" || allowances[0].RemainingRatio == nil || *allowances[0].RemainingRatio != 0.8 || allowances[0].Window == nil || allowances[0].Window.ResetAt == nil {
		t.Fatalf("xAI monthly allowance = %#v", allowances[0])
	}
	if allowances[1].Kind != catalog.AllowanceProviderDefined || allowances[1].Limit == nil || *allowances[1].Limit != "5000" {
		t.Fatalf("xAI on-demand allowance = %#v", allowances[1])
	}
	for _, allowance := range allowances {
		if errValidate := allowance.Validate(); errValidate != nil {
			t.Fatalf("xAI allowance validation error = %v", errValidate)
		}
	}
}
