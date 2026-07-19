package catalog

import (
	"context"
	"math"
	"testing"
	"time"
)

// testCapabilities returns one explicit model capability fixture with a known context ceiling.
// testCapabilities 返回一个具有已知上下文上限的显式模型能力测试夹具。
func testCapabilities(contextWindow int64) ModelCapabilities {
	return ModelCapabilities{
		Tokens:                 TokenLimits{ContextWindow: OptionalTokenLimit{Known: true, Value: contextWindow}},
		ToolCalling:            CapabilityNative,
		ParallelToolCalls:      CapabilityNative,
		StreamingToolArguments: CapabilityNative,
		StrictJSONSchema:       CapabilityConditional,
		Reasoning:              CapabilityNative,
		InputModalities:        []string{"text"},
		OutputModalities:       []string{"text"},
	}
}

// testCatalogSnapshot returns one K3-style two-profile catalog fixture.
// testCatalogSnapshot 返回一个 K3 风格双规格目录测试夹具。
func testCatalogSnapshot() Snapshot {
	now := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	resetAt := now.Add(5 * time.Hour)
	remaining := "80"
	return Snapshot{
		ProviderInstanceID: "pvi_kimi",
		Models: []ProviderModel{{
			ID:                 "model_kimi_k3",
			ProviderInstanceID: "pvi_kimi",
			UpstreamModelID:    "kimi-k3",
			DisplayName:        "Kimi K3",
			Source:             ModelSourceSystem,
			EntitlementMode:    EntitlementExplicit,
			Revision:           1,
		}},
		Offerings: []ModelOffering{{
			ID:                 "offer_kimi_k3",
			ProviderInstanceID: "pvi_kimi",
			ProviderModelID:    "model_kimi_k3",
			ChannelID:          "anthropic",
			UpstreamModelID:    "kimi-k3",
			Capabilities:       testCapabilities(1048576),
			CapabilityRevision: 1,
			Revision:           1,
		}},
		Profiles: []ExecutionProfile{
			{
				ID:                         "profile_kimi_k3_256k",
				ProviderInstanceID:         "pvi_kimi",
				OfferingID:                 "offer_kimi_k3",
				DisplayName:                "256K",
				Default:                    true,
				Capabilities:               testCapabilities(262144),
				RequiredEntitlementClasses: []string{"kimi_256k", "kimi_1m"},
				SwitchPolicy:               ProfileSwitchReplayRequired,
				PoolPolicy:                 PoolPreferSmallestSufficient,
				CapabilityRevision:         1,
				Revision:                   1,
			},
			{
				ID:                         "profile_kimi_k3_1m",
				ProviderInstanceID:         "pvi_kimi",
				OfferingID:                 "offer_kimi_k3",
				DisplayName:                "1M",
				Capabilities:               testCapabilities(1048576),
				RequiredEntitlementClasses: []string{"kimi_1m"},
				SwitchPolicy:               ProfileSwitchReplayRequired,
				PoolPolicy:                 PoolStrictProfile,
				CapabilityRevision:         1,
				Revision:                   1,
			},
		},
		Entitlements: []ModelEntitlement{{
			ID:                 "ent_kimi_account",
			ProviderInstanceID: "pvi_kimi",
			CredentialID:       "cred_kimi_account",
			ProviderModelID:    "model_kimi_k3",
			Availability:       AvailabilityAllowed,
			EntitlementClass:   "kimi_1m",
			AllowedProfileIDs:  []string{"profile_kimi_k3_256k", "profile_kimi_k3_1m"},
			LimitOverrides:     TokenLimits{ContextWindow: OptionalTokenLimit{Known: true, Value: 1048576}},
			Source:             ModelSourceProviderAPI,
			ObservedAt:         now,
			ExpiresAt:          now.Add(time.Hour),
			Revision:           1,
		}},
		Allowances: []AllowanceSnapshot{
			{
				ID:                 "allow_kimi_five_hour",
				ProviderInstanceID: "pvi_kimi",
				Kind:               AllowanceWindowQuota,
				Scope:              ScopeCredential,
				ScopeID:            "cred_kimi_account",
				Metric:             "five_hour_usage",
				Unit:               UnitPercentage,
				Remaining:          &remaining,
				Status:             AllowanceAvailable,
				Mandatory:          true,
				Window:             &AllowanceWindow{Kind: WindowRolling, Duration: 5 * time.Hour, ResetAt: &resetAt},
				Source:             ModelSourceProviderAPI,
				ObservedAt:         now,
				ExpiresAt:          now.Add(5 * time.Minute),
				Revision:           1,
			},
			{
				ID:                 "allow_kimi_balance",
				ProviderInstanceID: "pvi_kimi",
				Kind:               AllowanceBalance,
				Scope:              ScopeBillingAccount,
				ScopeID:            "billing-kimi",
				Metric:             "prepaid_balance",
				Unit:               UnitMinorCurrency,
				Currency:           "CNY",
				Remaining:          &remaining,
				Status:             AllowanceUnknownSufficiency,
				Mandatory:          true,
				Source:             ModelSourceProviderAPI,
				ObservedAt:         now,
				ExpiresAt:          now.Add(5 * time.Minute),
				Revision:           1,
			},
		},
		Pools: []PoolSummary{{
			ProviderInstanceID:    "pvi_kimi",
			ExecutionProfileID:    "profile_kimi_k3_256k",
			ConfiguredCredentials: 1,
			EntitledCredentials:   1,
			ReadyCredentials:      1,
			Revision:              1,
			ObservedAt:            now,
		}},
		Revision:   1,
		ObservedAt: now,
	}
}

// TestSnapshotSupportsMultipleProfilesAndAllowanceShapes verifies the complete K3-style structure.
// TestSnapshotSupportsMultipleProfilesAndAllowanceShapes 校验完整的 K3 风格结构。
func TestSnapshotSupportsMultipleProfilesAndAllowanceShapes(t *testing.T) {
	snapshot := testCatalogSnapshot()
	if err := snapshot.Validate(); err != nil {
		t.Fatalf("validate catalog snapshot: %v", err)
	}
	if len(snapshot.Profiles) != 2 || len(snapshot.Allowances) != 2 {
		t.Fatalf("expected two profiles and two allowance shapes")
	}
}

// TestSnapshotRejectsNonDecimalAllowanceAmounts verifies exact amount fields cannot smuggle fraction or non-decimal notation.
// TestSnapshotRejectsNonDecimalAllowanceAmounts 验证精确金额字段不能混入分数或非十进制表示法。
func TestSnapshotRejectsNonDecimalAllowanceAmounts(t *testing.T) {
	// invalidAmounts enumerates lexical forms accepted by math/big.Rat but forbidden by the catalog decimal contract.
	// invalidAmounts 枚举 math/big.Rat 会接受但目录十进制合同禁止的词法形式。
	invalidAmounts := []string{"1/2", "0x10", "01", "+1"}
	for _, invalidAmount := range invalidAmounts {
		// snapshot isolates each invalid exact amount in the same otherwise valid catalog fixture.
		// snapshot 在同一个其他字段均有效的目录夹具中隔离每个无效精确金额。
		snapshot := testCatalogSnapshot()
		snapshot.Allowances[0].Remaining = &invalidAmount
		if err := snapshot.Validate(); err == nil {
			t.Fatalf("expected invalid allowance amount %q to be rejected", invalidAmount)
		}
	}
}

// TestSnapshotRejectsNaNAllowanceRatio verifies a non-finite ratio cannot bypass range comparisons.
// TestSnapshotRejectsNaNAllowanceRatio 验证非有限比例不能绕过范围比较。
func TestSnapshotRejectsNaNAllowanceRatio(t *testing.T) {
	// invalidRatio represents the IEEE value for which both ordered range comparisons are false.
	// invalidRatio 表示两个有序范围比较结果都为假的 IEEE 数值。
	invalidRatio := math.NaN()
	// snapshot carries the invalid ratio through the complete catalog validator.
	// snapshot 通过完整目录校验器承载无效比例。
	snapshot := testCatalogSnapshot()
	snapshot.Allowances[0].RemainingRatio = &invalidRatio
	if err := snapshot.Validate(); err == nil {
		t.Fatal("expected NaN allowance ratio to be rejected")
	}
}

// TestSnapshotRejectsMultipleDefaultProfiles verifies unambiguous client profile selection.
// TestSnapshotRejectsMultipleDefaultProfiles 校验客户端规格选择无歧义。
func TestSnapshotRejectsMultipleDefaultProfiles(t *testing.T) {
	snapshot := testCatalogSnapshot()
	snapshot.Profiles[1].Default = true
	if err := snapshot.Validate(); err == nil {
		t.Fatal("expected duplicate default profile rejection")
	}
}

// TestSnapshotRejectsDuplicateCredentialModelEntitlements verifies resolver indexing is unambiguous.
// TestSnapshotRejectsDuplicateCredentialModelEntitlements 校验解析器索引没有歧义。
func TestSnapshotRejectsDuplicateCredentialModelEntitlements(t *testing.T) {
	snapshot := testCatalogSnapshot()
	duplicate := snapshot.Entitlements[0]
	duplicate.ID = "ent_kimi_account_duplicate"
	snapshot.Entitlements = append(snapshot.Entitlements, duplicate)
	if err := snapshot.Validate(); err == nil {
		t.Fatal("expected duplicate credential-model entitlement rejection")
	}
}

// TestSnapshotRejectsMultiplePlansForOneCredential verifies the current-plan contract cannot double-count one account.
// TestSnapshotRejectsMultiplePlansForOneCredential 验证当前套餐合同不能重复计算同一个账号。
func TestSnapshotRejectsMultiplePlansForOneCredential(t *testing.T) {
	snapshot := testCatalogSnapshot()
	// firstPlan is the first otherwise valid current plan for the shared credential.
	// firstPlan 是共享凭据的第一条其他字段均有效的当前套餐。
	firstPlan := PlanSnapshot{ID: "plan_kimi_first", ProviderInstanceID: snapshot.ProviderInstanceID, CredentialID: "cred_kimi_account", PlanCode: "first", PlanName: "First", Status: "active", ObservedAt: snapshot.ObservedAt, ExpiresAt: snapshot.ObservedAt.Add(time.Hour), Revision: 1}
	// secondPlan changes identity and provider tier while retaining the forbidden duplicate credential subject.
	// secondPlan 更改标识与供应商等级，同时保留被禁止的重复凭据主体。
	secondPlan := firstPlan
	secondPlan.ID = "plan_kimi_second"
	secondPlan.PlanCode = "second"
	secondPlan.PlanName = "Second"
	snapshot.Plans = []PlanSnapshot{firstPlan, secondPlan}
	if err := snapshot.Validate(); err == nil {
		t.Fatal("expected duplicate credential plan rejection")
	}
}

// TestPoolSummaryRejectsImpossibleCredentialClassifications verifies disjoint runtime categories cannot exceed the entitled pool.
// TestPoolSummaryRejectsImpossibleCredentialClassifications 验证互斥运行时分类不能超过已授权账号池。
func TestPoolSummaryRejectsImpossibleCredentialClassifications(t *testing.T) {
	// pool starts from a valid ready-only summary before each isolated corruption.
	// pool 在每项隔离破坏前从有效的仅就绪摘要开始。
	pool := testCatalogSnapshot().Pools[0]
	pool.CoolingCredentials = 1
	if err := pool.Validate(); err == nil {
		t.Fatal("expected overlapping ready and cooling credential counts to be rejected")
	}
	pool = testCatalogSnapshot().Pools[0]
	pool.ReadyCredentials = 0
	pool.BlockingAllowanceKinds = []AllowanceKind{AllowanceBalance}
	if err := pool.Validate(); err == nil {
		t.Fatal("expected blocking allowance without exhausted credentials to be rejected")
	}
}

// TestCredentialAllowanceRequiresCredentialIdentifier verifies credential-scoped resources cannot use an unrelated provider subject.
// TestCredentialAllowanceRequiresCredentialIdentifier 验证凭据作用域资源不能使用无关供应商主体。
func TestCredentialAllowanceRequiresCredentialIdentifier(t *testing.T) {
	// allowance starts from one valid credential-scoped resource observation.
	// allowance 从一条有效的凭据作用域资源观测开始。
	allowance := testCatalogSnapshot().Allowances[0]
	allowance.ScopeID = "account-upstream"
	if err := allowance.Validate(); err == nil {
		t.Fatal("expected malformed credential allowance scope rejection")
	}
}

// TestSnapshotRejectsEntitlementProfileFromAnotherModel verifies model-profile ownership.
// TestSnapshotRejectsEntitlementProfileFromAnotherModel 校验模型与规格的所有权。
func TestSnapshotRejectsEntitlementProfileFromAnotherModel(t *testing.T) {
	snapshot := testCatalogSnapshot()
	snapshot.Models = append(snapshot.Models, ProviderModel{
		ID:                 "model_kimi_other",
		ProviderInstanceID: snapshot.ProviderInstanceID,
		UpstreamModelID:    "kimi-other",
		DisplayName:        "Kimi Other",
		Source:             ModelSourceSystem,
		EntitlementMode:    EntitlementExplicit,
		Revision:           1,
	})
	snapshot.Offerings = append(snapshot.Offerings, ModelOffering{
		ID:                 "offer_kimi_other",
		ProviderInstanceID: snapshot.ProviderInstanceID,
		ProviderModelID:    "model_kimi_other",
		ChannelID:          "anthropic",
		UpstreamModelID:    "kimi-other",
		Capabilities:       testCapabilities(262144),
		CapabilityRevision: 1,
		Revision:           1,
	})
	snapshot.Profiles = append(snapshot.Profiles, ExecutionProfile{
		ID:                 "profile_kimi_other_default",
		ProviderInstanceID: snapshot.ProviderInstanceID,
		OfferingID:         "offer_kimi_other",
		DisplayName:        "Default",
		Default:            true,
		Capabilities:       testCapabilities(262144),
		SwitchPolicy:       ProfileSwitchSeamless,
		PoolPolicy:         PoolStrictProfile,
		CapabilityRevision: 1,
		Revision:           1,
	})
	snapshot.Entitlements[0].AllowedProfileIDs = []string{"profile_kimi_other_default"}
	if err := snapshot.Validate(); err == nil {
		t.Fatal("expected cross-model entitlement profile rejection")
	}
}

// TestUnknownTokenLimitCannotCarryValue verifies that unknown is not encoded as a hidden limit.
// TestUnknownTokenLimitCannotCarryValue 校验未知值不能携带隐藏限制。
func TestUnknownTokenLimitCannotCarryValue(t *testing.T) {
	limits := TokenLimits{ContextWindow: OptionalTokenLimit{Known: false, Value: 1048576}}
	if err := limits.Validate(); err == nil {
		t.Fatal("expected unknown token limit value rejection")
	}
}

// TestCatalogStoreReturnsMutationSafeSnapshots verifies atomic snapshot ownership.
// TestCatalogStoreReturnsMutationSafeSnapshots 校验原子快照所有权。
func TestCatalogStoreReturnsMutationSafeSnapshots(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	snapshot := testCatalogSnapshot()
	if err := store.Save(ctx, snapshot); err != nil {
		t.Fatalf("save catalog snapshot: %v", err)
	}
	loaded, errLoaded := store.Get(ctx, snapshot.ProviderInstanceID)
	if errLoaded != nil {
		t.Fatalf("load catalog snapshot: %v", errLoaded)
	}
	loaded.Profiles[0].RequiredEntitlementClasses[0] = "mutated"
	loaded.Allowances[0].Window.Duration = time.Minute
	reloaded, errReloaded := store.Get(ctx, snapshot.ProviderInstanceID)
	if errReloaded != nil {
		t.Fatalf("reload catalog snapshot: %v", errReloaded)
	}
	if reloaded.Profiles[0].RequiredEntitlementClasses[0] != "kimi_256k" {
		t.Fatal("profile entitlement classes were mutated through a returned snapshot")
	}
	if reloaded.Allowances[0].Window.Duration != 5*time.Hour {
		t.Fatal("allowance window was mutated through a returned snapshot")
	}
}
