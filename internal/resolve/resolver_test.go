package resolve

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
)

// resolverFixture contains one K3-style provider instance with two account tiers.
// resolverFixture 包含一个具有两个账号等级的 K3 风格供应商实例。
type resolverFixture struct {
	// resolver selects targets from the configured provider and catalog stores.
	// resolver 从已配置的供应商和目录存储中选择目标。
	resolver *Resolver
	// configurations exposes the provider configuration store for local policy mutation tests.
	// configurations 为本地策略变更测试暴露供应商配置存储。
	configurations *providerconfig.MemoryStore
	// catalogs exposes the atomic snapshot store for allowance replacement tests.
	// catalogs 为资源替换测试暴露原子快照存储。
	catalogs *catalog.MemoryStore
	// snapshot is the initial valid provider catalog.
	// snapshot 是初始有效供应商目录。
	snapshot catalog.Snapshot
	// now is the fixed evaluation time used by every test.
	// now 是每个测试使用的固定评估时间。
	now time.Time
}

// resolverCapabilities returns explicit capabilities with a known context ceiling.
// resolverCapabilities 返回具有已知上下文上限的显式能力。
func resolverCapabilities(contextWindow int64) catalog.ModelCapabilities {
	return catalog.ModelCapabilities{
		Tokens:                 catalog.TokenLimits{ContextWindow: catalog.OptionalTokenLimit{Known: true, Value: contextWindow}},
		ToolCalling:            catalog.CapabilityNative,
		ParallelToolCalls:      catalog.CapabilityNative,
		StreamingToolArguments: catalog.CapabilityNative,
		StrictJSONSchema:       catalog.CapabilityConditional,
		Reasoning:              catalog.CapabilityNative,
		InputModalities:        []string{"text"},
		OutputModalities:       []string{"text"},
	}
}

// newResolverFixture creates one fully linked provider configuration and catalog.
// newResolverFixture 创建一套完整关联的供应商配置与目录。
func newResolverFixture(t *testing.T) resolverFixture {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	protocols := providerconfig.NewProtocolRegistry()
	if err := protocols.Register(providerconfig.ProtocolProfile{
		ID:                 "openai.chat",
		Version:            "1",
		DisplayName:        "OpenAI Chat",
		RuntimeReady:       true,
		ModelDiscovery:     providerconfig.SupportUnsupported,
		AllowedAuthMethods: []providerconfig.AuthMethodType{providerconfig.AuthMethodBearer},
	}); err != nil {
		t.Fatalf("register protocol profile: %v", err)
	}
	systems, errSystems := providerconfig.NewSystemRegistry(protocols)
	if errSystems != nil {
		t.Fatalf("create system registry: %v", errSystems)
	}
	definition := providerconfig.ProviderDefinition{
		ID:                  "system_kimi_coding_plan",
		Kind:                providerconfig.DefinitionKindSystem,
		DisplayName:         "Kimi Coding Plan",
		DriverID:            "kimi-coding-plan",
		DriverVersion:       "1.0.0",
		ConfigSchemaVersion: "1",
		ProtocolProfileID:   "openai.chat",
		EndpointProfileID:   "kimi-coding",
		AuthMethodIDs:       []string{"oauth"},
		RuntimeReady:        true,
		AuthMethods: []providerconfig.AuthMethodDefinition{{
			ID:                  "oauth",
			Type:                providerconfig.AuthMethodOAuth,
			Refreshable:         true,
			MultipleCredentials: true,
		}},
		Features: providerconfig.ProviderFeatureSet{
			ModelDiscovery:    providerconfig.SupportSupported,
			PlanReader:        providerconfig.SupportSupported,
			EntitlementReader: providerconfig.SupportSupported,
			AllowanceReader:   providerconfig.SupportSupported,
		},
		Revision: 1,
	}
	if err := systems.Register(definition); err != nil {
		t.Fatalf("register system definition: %v", err)
	}
	configurations, errConfigurations := providerconfig.NewMemoryStore(protocols, systems)
	if errConfigurations != nil {
		t.Fatalf("create provider configuration store: %v", errConfigurations)
	}
	instance := providerconfig.ProviderInstance{
		ID:                 "pvi_kimi",
		DefinitionID:       definition.ID,
		Handle:             "kimi",
		DisplayName:        "Kimi",
		Status:             providerconfig.LifecycleReady,
		Revision:           1,
		DefinitionRevision: 1,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	if err := configurations.SaveInstance(ctx, instance); err != nil {
		t.Fatalf("save provider instance: %v", err)
	}
	endpoint := providerconfig.Endpoint{
		ID:                 "ep_kimi",
		ProviderInstanceID: instance.ID,
		ChannelID:          "openai.chat",
		BaseURL:            "https://api.kimi.example/v1",
		Status:             providerconfig.EndpointReady,
		Revision:           1,
	}
	if err := configurations.SaveEndpoint(ctx, endpoint); err != nil {
		t.Fatalf("save endpoint: %v", err)
	}
	credentials := []providerconfig.Credential{
		{
			ID:                 "cred_kimi_256k",
			ProviderInstanceID: instance.ID,
			AuthMethodID:       "oauth",
			Label:              "256K account",
			PrincipalKey:       "account-256k",
			SecretRef:          "secret://kimi/256k",
			Fingerprint:        "fingerprint-256k",
			Status:             providerconfig.CredentialActive,
			ScopeRefs:          []providerconfig.ScopeReference{{Kind: "billing_account", ID: "billing-256k"}},
			Revision:           1,
		},
		{
			ID:                 "cred_kimi_1m",
			ProviderInstanceID: instance.ID,
			AuthMethodID:       "oauth",
			Label:              "1M account",
			PrincipalKey:       "account-1m",
			SecretRef:          "secret://kimi/1m",
			Fingerprint:        "fingerprint-1m",
			Status:             providerconfig.CredentialActive,
			ScopeRefs:          []providerconfig.ScopeReference{{Kind: "billing_account", ID: "billing-1m"}},
			Revision:           1,
		},
	}
	for _, credential := range credentials {
		if err := configurations.SaveCredential(ctx, credential); err != nil {
			t.Fatalf("save credential %s: %v", credential.ID, err)
		}
	}
	bindings := []providerconfig.AccessBinding{
		{ID: "bind_kimi_256k", ProviderInstanceID: instance.ID, ChannelID: "openai.chat", EndpointID: endpoint.ID, CredentialID: "cred_kimi_256k", Priority: 10, Enabled: true, Revision: 1},
		{ID: "bind_kimi_1m", ProviderInstanceID: instance.ID, ChannelID: "openai.chat", EndpointID: endpoint.ID, CredentialID: "cred_kimi_1m", Priority: 1, Enabled: true, Revision: 1},
	}
	for _, binding := range bindings {
		if err := configurations.SaveBinding(ctx, binding); err != nil {
			t.Fatalf("save access binding %s: %v", binding.ID, err)
		}
	}
	snapshot := catalog.Snapshot{
		ProviderInstanceID: instance.ID,
		Models: []catalog.ProviderModel{{
			ID:                 "model_kimi_k3",
			ProviderInstanceID: instance.ID,
			UpstreamModelID:    "kimi-k3",
			DisplayName:        "Kimi K3",
			Source:             catalog.ModelSourceSystem,
			EntitlementMode:    catalog.EntitlementExplicit,
			Revision:           1,
		}},
		Offerings: []catalog.ModelOffering{{
			ID:                 "offer_kimi_k3",
			ProviderInstanceID: instance.ID,
			ProviderModelID:    "model_kimi_k3",
			ChannelID:          "openai.chat",
			UpstreamModelID:    "kimi-k3",
			Capabilities:       resolverCapabilities(1048576),
			CapabilityRevision: 1,
			Revision:           1,
		}},
		Profiles: []catalog.ExecutionProfile{
			{
				ID:                         "profile_kimi_k3_256k",
				ProviderInstanceID:         instance.ID,
				OfferingID:                 "offer_kimi_k3",
				DisplayName:                "256K",
				Default:                    true,
				Capabilities:               resolverCapabilities(262144),
				RequiredEntitlementClasses: []string{"kimi_256k", "kimi_1m"},
				SwitchPolicy:               catalog.ProfileSwitchReplayRequired,
				PoolPolicy:                 catalog.PoolPreferSmallestSufficient,
				CapabilityRevision:         1,
				Revision:                   1,
			},
			{
				ID:                         "profile_kimi_k3_1m",
				ProviderInstanceID:         instance.ID,
				OfferingID:                 "offer_kimi_k3",
				DisplayName:                "1M",
				Capabilities:               resolverCapabilities(1048576),
				RequiredEntitlementClasses: []string{"kimi_1m"},
				SwitchPolicy:               catalog.ProfileSwitchReplayRequired,
				PoolPolicy:                 catalog.PoolStrictProfile,
				CapabilityRevision:         1,
				Revision:                   1,
			},
		},
		Entitlements: []catalog.ModelEntitlement{
			{
				ID:                 "ent_kimi_256k",
				ProviderInstanceID: instance.ID,
				CredentialID:       "cred_kimi_256k",
				ProviderModelID:    "model_kimi_k3",
				Availability:       catalog.AvailabilityAllowed,
				EntitlementClass:   "kimi_256k",
				AllowedProfileIDs:  []string{"profile_kimi_k3_256k"},
				LimitOverrides:     catalog.TokenLimits{ContextWindow: catalog.OptionalTokenLimit{Known: true, Value: 262144}},
				Source:             catalog.ModelSourceProviderAPI,
				ObservedAt:         now,
				ExpiresAt:          now.Add(time.Hour),
				Revision:           1,
			},
			{
				ID:                 "ent_kimi_1m",
				ProviderInstanceID: instance.ID,
				CredentialID:       "cred_kimi_1m",
				ProviderModelID:    "model_kimi_k3",
				Availability:       catalog.AvailabilityAllowed,
				EntitlementClass:   "kimi_1m",
				AllowedProfileIDs:  []string{"profile_kimi_k3_256k", "profile_kimi_k3_1m"},
				LimitOverrides:     catalog.TokenLimits{ContextWindow: catalog.OptionalTokenLimit{Known: true, Value: 1048576}},
				Source:             catalog.ModelSourceProviderAPI,
				ObservedAt:         now,
				ExpiresAt:          now.Add(time.Hour),
				Revision:           1,
			},
		},
		Revision:   1,
		ObservedAt: now,
	}
	catalogs := catalog.NewMemoryStore()
	if err := catalogs.Save(ctx, snapshot); err != nil {
		t.Fatalf("save catalog snapshot: %v", err)
	}
	resolver, errResolver := New(configurations, catalogs)
	if errResolver != nil {
		t.Fatalf("create resolver: %v", errResolver)
	}
	return resolverFixture{resolver: resolver, configurations: configurations, catalogs: catalogs, snapshot: snapshot, now: now}
}

// TestResolverRejectsLocallyDisabledModel verifies call routing cannot bypass management-disabled model policy.
// TestResolverRejectsLocallyDisabledModel 验证调用路由无法绕过管理面禁用的模型策略。
func TestResolverRejectsLocallyDisabledModel(t *testing.T) {
	// fixture contains a ready provider instance with a normally resolvable model.
	// fixture 包含具有通常可解析模型的就绪供应商实例。
	fixture := newResolverFixture(t)
	// ctx fixes the configuration read and write scope.
	// ctx 固定配置读写范围。
	ctx := context.Background()
	instance, errInstance := fixture.configurations.GetInstance(ctx, "pvi_kimi")
	if errInstance != nil {
		t.Fatalf("get provider instance: %v", errInstance)
	}
	instance.DisabledModelIDs = []string{"model_kimi_k3"}
	instance.Revision++
	if errSave := fixture.configurations.SaveInstance(ctx, instance); errSave != nil {
		t.Fatalf("save disabled-model policy: %v", errSave)
	}
	_, _, errResolve := fixture.resolver.Resolve(ctx, Request{
		ProviderInstanceID: "pvi_kimi", ProviderModelID: "model_kimi_k3", ExecutionProfileID: "profile_kimi_k3_256k", Now: fixture.now,
	})
	if !errors.Is(errResolve, ErrModelDisabled) {
		t.Fatalf("disabled model resolution error = %v, want ErrModelDisabled", errResolve)
	}
}

// TestResolverPreservesHighTierCredential verifies smallest-sufficient account selection.
// TestResolverPreservesHighTierCredential 校验优先选择满足条件的最低等级账号。
func TestResolverPreservesHighTierCredential(t *testing.T) {
	fixture := newResolverFixture(t)
	target, _, errResolve := fixture.resolver.Resolve(context.Background(), Request{
		ProviderInstanceID:    "pvi_kimi",
		ProviderModelID:       "model_kimi_k3",
		ExecutionProfileID:    "profile_kimi_k3_256k",
		RequiredContextTokens: 200000,
		Now:                   fixture.now,
	})
	if errResolve != nil {
		t.Fatalf("resolve 256K profile: %v", errResolve)
	}
	if target.CredentialID != "cred_kimi_256k" {
		t.Fatalf("expected smallest sufficient credential, got %s", target.CredentialID)
	}
}

// TestResolverRequiresHighTierEntitlement verifies a 1M profile excludes lower-tier accounts.
// TestResolverRequiresHighTierEntitlement 校验 1M 规格排除低等级账号。
func TestResolverRequiresHighTierEntitlement(t *testing.T) {
	fixture := newResolverFixture(t)
	target, diagnostics, errResolve := fixture.resolver.Resolve(context.Background(), Request{
		ProviderInstanceID:    "pvi_kimi",
		ProviderModelID:       "model_kimi_k3",
		ExecutionProfileID:    "profile_kimi_k3_1m",
		RequiredContextTokens: 800000,
		Now:                   fixture.now,
	})
	if errResolve != nil {
		t.Fatalf("resolve 1M profile: %v", errResolve)
	}
	if target.CredentialID != "cred_kimi_1m" || diagnostics.EntitledCandidates != 1 {
		t.Fatalf("expected only the 1M credential, target=%s entitled=%d", target.CredentialID, diagnostics.EntitledCandidates)
	}
}

// TestResolverBlocksSharedExhaustedBalance verifies billing-scope resource enforcement.
// TestResolverBlocksSharedExhaustedBalance 校验计费作用域资源耗尽阻断。
func TestResolverBlocksSharedExhaustedBalance(t *testing.T) {
	fixture := newResolverFixture(t)
	remaining := "0"
	fixture.snapshot.Allowances = []catalog.AllowanceSnapshot{{
		ID:                 "allow_kimi_1m_balance",
		ProviderInstanceID: "pvi_kimi",
		Kind:               catalog.AllowanceBalance,
		Scope:              catalog.ScopeBillingAccount,
		ScopeID:            "billing-1m",
		Metric:             "prepaid_balance",
		Unit:               catalog.UnitMinorCurrency,
		Currency:           "CNY",
		Remaining:          &remaining,
		Status:             catalog.AllowanceExhausted,
		Mandatory:          true,
		Source:             catalog.ModelSourceProviderAPI,
		ObservedAt:         fixture.now,
		ExpiresAt:          fixture.now.Add(time.Minute),
		Revision:           1,
	}}
	fixture.snapshot.Revision = 2
	if err := fixture.catalogs.Save(context.Background(), fixture.snapshot); err != nil {
		t.Fatalf("replace catalog snapshot: %v", err)
	}
	_, diagnostics, errResolve := fixture.resolver.Resolve(context.Background(), Request{
		ProviderInstanceID:    "pvi_kimi",
		ProviderModelID:       "model_kimi_k3",
		ExecutionProfileID:    "profile_kimi_k3_1m",
		RequiredContextTokens: 800000,
		Now:                   fixture.now,
	})
	if !errors.Is(errResolve, ErrNoEligibleTarget) {
		t.Fatalf("expected exhausted balance rejection, got %v", errResolve)
	}
	if len(diagnostics.BlockingAllowanceKinds) != 1 || diagnostics.BlockingAllowanceKinds[0] != catalog.AllowanceBalance {
		t.Fatalf("expected balance blocker diagnostics, got %v", diagnostics.BlockingAllowanceKinds)
	}
}
