package catalog

import (
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestModelOperationPoliciesSeparateInternalFactsFromPublishedProfiles verifies unsupported models remain valid catalog facts without becoming executable.
// TestModelOperationPoliciesSeparateInternalFactsFromPublishedProfiles 验证不支持模型仍是有效目录事实但不会变成可执行对象。
func TestModelOperationPoliciesSeparateInternalFactsFromPublishedProfiles(t *testing.T) {
	// snapshot is the smallest policy-controlled catalog containing one published and one retained model.
	// snapshot 是包含一个已发布模型和一个保留模型的最小策略控制目录。
	snapshot := policyControlledSnapshot()
	if errValidate := snapshot.Validate(); errValidate != nil {
		t.Fatalf("validate policy-controlled snapshot: %v", errValidate)
	}

	// invalidProfile publishes the explicitly unsupported operation and must be rejected.
	// invalidProfile 发布了明确不支持的操作，必须被拒绝。
	invalidProfile := snapshot.Profiles[0]
	invalidProfile.ID = "profile_retained_chat"
	invalidProfile.OfferingID = "offer_retained_chat"
	invalidProfile.Default = false
	snapshot.Profiles = append(snapshot.Profiles, invalidProfile)
	if errValidate := snapshot.Validate(); errValidate == nil {
		t.Fatal("unsupported operation unexpectedly accepted an execution profile")
	}
}

// TestModelOperationPoliciesRequireExhaustiveOfferingDecisions verifies policy-enabled snapshots cannot omit one offering decision.
// TestModelOperationPoliciesRequireExhaustiveOfferingDecisions 验证启用策略的快照不能遗漏一个 Offering 决策。
func TestModelOperationPoliciesRequireExhaustiveOfferingDecisions(t *testing.T) {
	// snapshot drops the retained model policy while preserving its internal offering.
	// snapshot 删除保留模型策略但保留其内部 Offering。
	snapshot := policyControlledSnapshot()
	snapshot.ModelOperationPolicies = snapshot.ModelOperationPolicies[:1]
	if errValidate := snapshot.Validate(); errValidate == nil {
		t.Fatal("policy-controlled snapshot unexpectedly accepted an offering without a decision")
	}
}

// TestModelOperationPoliciesRejectUnknownAndServiceOperations verifies publication decisions cannot escape the closed model-operation union.
// TestModelOperationPoliciesRejectUnknownAndServiceOperations 验证发布决策不能逃逸封闭的模型操作联合类型。
func TestModelOperationPoliciesRejectUnknownAndServiceOperations(t *testing.T) {
	for _, operation := range []vcp.OperationKind{"future.operation", vcp.OperationSearchWeb} {
		snapshot := policyControlledSnapshot()
		snapshot.ModelOperationPolicies[1].Operation = operation
		if errValidate := snapshot.Validate(); errValidate == nil {
			t.Fatalf("model operation policy accepted %q", operation)
		}
	}
}

// TestRateLimitSnapshotPreservesCapacityWithoutAllowanceSemantics verifies exact provider capacity windows and scope references.
// TestRateLimitSnapshotPreservesCapacityWithoutAllowanceSemantics 验证精确供应商容量窗口和作用域引用。
func TestRateLimitSnapshotPreservesCapacityWithoutAllowanceSemantics(t *testing.T) {
	// snapshot supplies one offering-scoped count and usage capacity limit.
	// snapshot 提供一个 Offering 作用域的计数与用量容量限制。
	snapshot := policyControlledSnapshot()
	// usageLimit is the exact provider usage ceiling used by the fixture.
	// usageLimit 是夹具使用的精确供应商用量上限。
	usageLimit := int64(1_000_000)
	// usagePeriod is the exact provider usage window used by the fixture.
	// usagePeriod 是夹具使用的精确供应商用量窗口。
	usagePeriod := int64(60)
	snapshot.RateLimits = []RateLimitSnapshot{{
		ID: "rate_published_default", ProviderInstanceID: snapshot.ProviderInstanceID,
		Scope: RateLimitScopeOffering, ScopeID: "offer_published_chat", TierID: "model-default",
		CountLimit: 120, CountPeriodSeconds: 60, UsageLimit: &usageLimit, UsagePeriodSeconds: &usagePeriod, UsageField: "tokens",
		Source: ModelSourceProviderAPI, ObservedAt: snapshot.ObservedAt, ExpiresAt: snapshot.ObservedAt.Add(time.Hour), Revision: 1,
	}}
	if errValidate := snapshot.Validate(); errValidate != nil {
		t.Fatalf("validate rate-limit snapshot: %v", errValidate)
	}

	// partialUsageLimit proves incomplete optional usage tuples are rejected.
	// partialUsageLimit 证明不完整的可选用量元组会被拒绝。
	partialUsageLimit := snapshot
	partialUsageLimit.RateLimits = append([]RateLimitSnapshot(nil), snapshot.RateLimits...)
	partialUsageLimit.RateLimits[0].UsagePeriodSeconds = nil
	if errValidate := partialUsageLimit.Validate(); errValidate == nil {
		t.Fatal("partial usage rate-limit tuple was unexpectedly accepted")
	}
}

// policyControlledSnapshot returns a complete catalog with supported and intentionally unpublished model operations.
// policyControlledSnapshot 返回包含已支持和明确不发布模型操作的完整目录。
func policyControlledSnapshot() Snapshot {
	// observedAt fixes deterministic evidence and cache timestamps.
	// observedAt 固定确定性的证据与缓存时间戳。
	observedAt := time.Date(2026, 7, 23, 0, 0, 0, 0, time.UTC)
	// capabilities are the verified common Chat contract shared by both classified offerings.
	// capabilities 是两个已分类 Offering 共享的已验证 Chat 合同。
	capabilities := testCapabilities(262_144)
	capabilities.Delivery = DeliveryCapabilities{Synchronous: true, Streaming: true}
	return Snapshot{
		ProviderInstanceID: "pvi_policy_test",
		Models: []ProviderModel{
			{ID: "model_published", ProviderInstanceID: "pvi_policy_test", UpstreamModelID: "published", DisplayName: "Published", Source: ModelSourceSystem, EntitlementMode: EntitlementAllBoundCredentials, Revision: 1},
			{ID: "model_retained", ProviderInstanceID: "pvi_policy_test", UpstreamModelID: "retained", DisplayName: "Retained", Source: ModelSourceProviderAPI, EntitlementMode: EntitlementAllBoundCredentials, Revision: 1},
		},
		Offerings: []ModelOffering{
			{ID: "offer_published_chat", ProviderInstanceID: "pvi_policy_test", ProviderModelID: "model_published", ChannelID: "openai_chat", UpstreamModelID: "published", Capabilities: capabilities, CapabilityRevision: 1, Revision: 1},
			{ID: "offer_retained_chat", ProviderInstanceID: "pvi_policy_test", ProviderModelID: "model_retained", ChannelID: "openai_chat", UpstreamModelID: "retained", Capabilities: capabilities, CapabilityRevision: 1, Revision: 1},
		},
		Profiles: []ExecutionProfile{{
			ID: "profile_published_chat", ProviderInstanceID: "pvi_policy_test", OfferingID: "offer_published_chat",
			Operation: vcp.OperationConversationRespond, ActionBindingID: "action_policy_chat", DisplayName: "Published Chat", Default: true,
			Capabilities: capabilities, SwitchPolicy: ProfileSwitchReplayRequired, PoolPolicy: PoolPreferSmallestSufficient, CapabilityRevision: 1, Revision: 1,
		}},
		ModelOperationPolicies: []ModelOperationPolicy{
			{ID: "policy_published_chat", ProviderInstanceID: "pvi_policy_test", ProviderModelID: "model_published", OfferingID: "offer_published_chat", Operation: vcp.OperationConversationRespond, Status: ModelOperationSupported, Reason: SupportReasonRuntimeVerified, Source: ModelSourceRuntimeEvidence, EvidenceRevision: 1, Revision: 1},
			{ID: "policy_retained_chat", ProviderInstanceID: "pvi_policy_test", ProviderModelID: "model_retained", OfferingID: "offer_retained_chat", Operation: vcp.OperationConversationRespond, Status: ModelOperationUnsupported, Reason: SupportReasonCodingCapabilityInsufficient, Source: ModelSourceSystem, EvidenceRevision: 1, Revision: 1},
		},
		Revision: 1, ObservedAt: observedAt,
	}
}
