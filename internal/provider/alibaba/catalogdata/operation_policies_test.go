package catalogdata

import (
	"strings"
	"testing"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
)

// TestEmbeddedOperationPoliciesCloseEveryClassifiedOperation verifies the release baseline is complete, source-bound, and free of pending decisions.
// TestEmbeddedOperationPoliciesCloseEveryClassifiedOperation 验证发布基线完整、绑定来源且不含待审核决策。
func TestEmbeddedOperationPoliciesCloseEveryClassifiedOperation(t *testing.T) {
	policies, errPolicies := LoadOperationPolicies()
	if errPolicies != nil {
		t.Fatalf("LoadOperationPolicies() error = %v", errPolicies)
	}
	if errStable := policies.ValidateStableDecisions(); errStable != nil {
		t.Fatalf("ValidateStableDecisions() error = %v", errStable)
	}
	supported := 0
	unsupported := 0
	for _, entry := range policies.Entries {
		switch entry.Status {
		case catalog.ModelOperationSupported:
			supported++
		case catalog.ModelOperationUnsupported:
			unsupported++
		default:
			t.Fatalf("release entry %q has status %q", entry.Key(), entry.Status)
		}
	}
	if supported == 0 || unsupported == 0 {
		t.Fatalf("policy distribution supported=%d unsupported=%d", supported, unsupported)
	}
}

// TestOperationPolicyCoverageRejectsMissingAndStaleDecisions verifies additions and refreshed snapshots cannot silently inherit publication status.
// TestOperationPolicyCoverageRejectsMissingAndStaleDecisions 验证新增操作与刷新快照不能静默继承发布状态。
func TestOperationPolicyCoverageRejectsMissingAndStaleDecisions(t *testing.T) {
	policies, errPolicies := LoadOperationPolicies()
	if errPolicies != nil {
		t.Fatal(errPolicies)
	}
	missing := policies
	missing.Entries = append([]OperationPolicyEntry(nil), policies.Entries[1:]...)
	if errMissing := missing.ValidateEmbeddedCoverage(); errMissing == nil || !strings.Contains(errMissing.Error(), "no explicit policy") {
		t.Fatalf("missing policy error = %v", errMissing)
	}
	stale := policies
	stale.Entries = append([]OperationPolicyEntry(nil), policies.Entries...)
	stale.Entries[0].SourceRevision = strings.Repeat("0", 64)
	if errStale := stale.ValidateEmbeddedCoverage(); errStale == nil || !strings.Contains(errStale.Error(), "stale source revision") {
		t.Fatalf("stale policy error = %v", errStale)
	}
}

// TestOperationPolicyDecisionRejectsUnsupportedMissingFixture verifies missing evidence remains a review state and cannot masquerade as a stable unsupported decision.
// TestOperationPolicyDecisionRejectsUnsupportedMissingFixture 验证缺失证据始终属于审核状态，不能伪装成稳定的不支持决策。
func TestOperationPolicyDecisionRejectsUnsupportedMissingFixture(t *testing.T) {
	entry := OperationPolicyEntry{CatalogID: "catalog", ModelID: "model", Operation: "conversation.respond", Status: catalog.ModelOperationUnsupported, Reason: catalog.SupportReasonMissingExecutionFixture, EvidenceRevision: 1, SourceRevision: strings.Repeat("a", 64), Evidence: "reviewed fixture boundary"}
	if errValidate := entry.Validate(); errValidate == nil {
		t.Fatal("Validate() accepted an unsupported decision with a pending-review reason")
	}
}

// TestOperationPolicyRejectsNonCanonicalAndNonHexEvidence verifies policy keys and revisions cannot create visually identical evidence identities.
// TestOperationPolicyRejectsNonCanonicalAndNonHexEvidence 验证策略键与修订不能创建视觉相同的证据身份。
func TestOperationPolicyRejectsNonCanonicalAndNonHexEvidence(t *testing.T) {
	valid := OperationPolicyEntry{CatalogID: "catalog", ModelID: "model", Operation: "conversation.respond", Status: catalog.ModelOperationSupported, Reason: catalog.SupportReasonRuntimeVerified, EvidenceRevision: 1, SourceRevision: strings.Repeat("a", 64), Evidence: "verified runtime fixture"}
	for name, mutate := range map[string]func(*OperationPolicyEntry){
		"catalog whitespace": func(entry *OperationPolicyEntry) { entry.CatalogID += " " },
		"model whitespace":   func(entry *OperationPolicyEntry) { entry.ModelID += " " },
		"evidence whitespace": func(entry *OperationPolicyEntry) {
			entry.Evidence += " "
		},
		"non hexadecimal revision": func(entry *OperationPolicyEntry) { entry.SourceRevision = strings.Repeat("z", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			entry := valid
			mutate(&entry)
			if errValidate := entry.Validate(); errValidate == nil {
				t.Fatal("Validate() accepted a non-canonical operation policy")
			}
		})
	}
}
