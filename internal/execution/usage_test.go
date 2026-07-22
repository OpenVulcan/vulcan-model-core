package execution

import (
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestUsageObservationForResultRejectsConflictingSources verifies duplicate usage carriers cannot silently disagree.
// TestUsageObservationForResultRejectsConflictingSources 验证重复用量载体不能静默产生冲突。
func TestUsageObservationForResultRejectsConflictingSources(t *testing.T) {
	firstTotal := int64(10)
	secondTotal := int64(11)
	first := &vcp.UsageObservation{TotalTokens: &firstTotal, Source: "provider_reported", Aggregation: "snapshot", Phase: "terminal", AccountingBasis: "test", Final: true}
	second := &vcp.UsageObservation{TotalTokens: &secondTotal, Source: "provider_reported", Aggregation: "snapshot", Phase: "terminal", AccountingBasis: "test", Final: true}
	result := provider.ExecutionResult{Response: vcp.Response{Usage: first}, Report: vcp.ExecutionReport{Usage: second}}
	if _, errUsage := usageObservationForResult(result); errUsage == nil {
		t.Fatal("expected conflicting usage observations to be rejected")
	}
}

// TestTypedResultEventsPreserveFractionalServiceUsage verifies durable usage events preserve provider credit precision and provenance.
// TestTypedResultEventsPreserveFractionalServiceUsage 验证持久用量事件保留供应商积分精度与来源。
func TestTypedResultEventsPreserveFractionalServiceUsage(t *testing.T) {
	credits := 0.25
	usage := &vcp.UsageObservation{ServiceUnits: &credits, ServiceUnit: "credits", Source: "provider_reported", Aggregation: "snapshot", Phase: "terminal", AccountingBasis: "test_credits", Final: true}
	result := provider.ExecutionResult{Search: &vcp.WebSearchResponse{Usage: usage}}
	events := typedResultEvents("exe_0123456789abcdef0123456789abcdef", 1, time.Date(2026, 7, 21, 0, 0, 0, 0, time.UTC), result, nil)
	if len(events) != 1 || events[0].Usage == nil || events[0].Usage.Value != 0.25 || events[0].Usage.Unit != "credits" || events[0].Usage.AccountingBasis != "test_credits" {
		t.Fatalf("unexpected usage events: %#v", events)
	}
	if errValidate := events[0].Validate(); errValidate != nil {
		t.Fatalf("validate usage event: %v", errValidate)
	}
}
