package anthropic

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
)

// TestClaudeAllowanceSeparatesPercentageWindowAndMoneyBalance verifies the two Claude display modes.
// TestClaudeAllowanceSeparatesPercentageWindowAndMoneyBalance 验证 Claude 的两种显示模式。
func TestClaudeAllowanceSeparatesPercentageWindowAndMoneyBalance(t *testing.T) {
	var payload claudeUsageResponse
	if errDecode := json.Unmarshal([]byte(`{"five_hour":{"utilization":25,"resets_at":"2026-07-21T05:00:00Z"},"extra_usage":{"is_enabled":true,"monthly_limit":2000,"used_credits":500,"utilization":25}}`), &payload); errDecode != nil {
		t.Fatalf("decode Claude usage fixture: %v", errDecode)
	}
	instance := providerconfig.ProviderInstance{ID: "pvi_claude"}
	credential := providerconfig.Credential{ID: "cred_claude"}
	observedAt := time.Date(2026, 7, 21, 0, 0, 0, 0, time.UTC)
	window, errWindow := claudeWindowAllowance("five_hour", *payload.FiveHour, instance, credential, observedAt)
	if errWindow != nil || window.Kind != catalog.AllowanceWindowQuota || window.RemainingRatio == nil || *window.RemainingRatio != 0.75 {
		t.Fatalf("Claude window = %#v error=%v", window, errWindow)
	}
	balance, present, errBalance := claudeExtraUsageAllowance(*payload.ExtraUsage, instance, credential, observedAt)
	if errBalance != nil || !present || balance.Kind != catalog.AllowanceBalance || balance.Currency != "USD" || balance.Remaining == nil || *balance.Remaining != "1500" {
		t.Fatalf("Claude balance = %#v present=%v error=%v", balance, present, errBalance)
	}
	if errValidate := window.Validate(); errValidate != nil {
		t.Fatalf("Claude window validation error = %v", errValidate)
	}
	if errValidate := balance.Validate(); errValidate != nil {
		t.Fatalf("Claude balance validation error = %v", errValidate)
	}
}
