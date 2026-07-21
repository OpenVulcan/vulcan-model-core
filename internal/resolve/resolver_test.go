package resolve

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/routingstate"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestResolveSelectsExactModelGroundedSearchService verifies service target immutability.
// TestResolveSelectsExactModelGroundedSearchService 校验服务目标不可变性。
func TestResolveSelectsExactModelGroundedSearchService(t *testing.T) {
	fixture := newResolverFixture(t)
	capabilities := resolverSearchCapabilities()
	fixture.snapshot.Services = []catalog.ProviderService{{
		ID:                 "service_web_search",
		ProviderInstanceID: "pvi_kimi",
		DisplayName:        "Web Search",
		Operation:          vcp.OperationSearchWeb,
		Source:             catalog.ModelSourceSystem,
		EntitlementMode:    catalog.EntitlementAllBoundCredentials,
		Revision:           1,
	}}
	fixture.snapshot.ServiceOfferings = []catalog.ServiceOffering{{
		ID:                 "service_offer_web_search",
		ProviderInstanceID: "pvi_kimi",
		ProviderServiceID:  "service_web_search",
		ChannelID:          "openai.chat",
		UpstreamServiceID:  "kimi-k3-search",
		Capabilities:       capabilities,
		CapabilityRevision: 1,
		Revision:           1,
	}}
	fixture.snapshot.Profiles = append(fixture.snapshot.Profiles, catalog.ExecutionProfile{
		ID:                  "profile_web_search",
		ProviderInstanceID:  "pvi_kimi",
		ServiceOfferingID:   "service_offer_web_search",
		Operation:           vcp.OperationSearchWeb,
		ActionBindingID:     "action_web_search",
		DisplayName:         "Web Search",
		Default:             true,
		ServiceCapabilities: &capabilities,
		SwitchPolicy:        catalog.ProfileSwitchUnsupported,
		PoolPolicy:          catalog.PoolStrictProfile,
		CapabilityRevision:  1,
		Revision:            1,
	})
	fixture.snapshot.Revision++
	fixture.snapshot.ObservedAt = fixture.snapshot.ObservedAt.Add(time.Second)
	if errSave := fixture.catalogs.Save(context.Background(), fixture.snapshot); errSave != nil {
		t.Fatalf("save search service snapshot: %v", errSave)
	}
	pools, errPools := fixture.resolver.SummarizeSnapshot(context.Background(), fixture.snapshot, fixture.now, fixture.snapshot.Revision)
	if errPools != nil {
		t.Fatalf("summarize search service snapshot: %v", errPools)
	}
	var searchPool catalog.PoolSummary
	for _, pool := range pools {
		if pool.ExecutionProfileID == "profile_web_search" {
			searchPool = pool
			break
		}
	}
	if searchPool.EntitledCredentials != 2 || searchPool.ReadyCredentials != 2 {
		t.Fatalf("search service pool=%+v, want two ready credentials", searchPool)
	}

	target, diagnostics, errResolve := fixture.resolver.Resolve(context.Background(), Request{
		ProviderInstanceID: "pvi_kimi",
		ProviderServiceID:  "service_web_search",
		ServiceOfferingID:  "service_offer_web_search",
		ExecutionProfileID: "profile_web_search",
		Operation:          vcp.OperationSearchWeb,
		Now:                fixture.now,
	})
	if errResolve != nil {
		t.Fatalf("resolve search service: %v", errResolve)
	}
	if target.ProviderServiceID != "service_web_search" || target.ServiceOfferingID != "service_offer_web_search" || target.ActionBindingID != "action_web_search" {
		t.Fatalf("unexpected search target: %+v", target)
	}
	if target.ProviderModelID != "" || target.OfferingID != "" || target.ServiceCapabilities == nil {
		t.Fatalf("service target leaked model subject fields: %+v", target)
	}
	if diagnostics.ReadyCandidates != 2 || target.CredentialID != "cred_kimi_1m" {
		t.Fatalf("search service selection diagnostics=%+v target=%+v", diagnostics, target)
	}
}

// resolverSearchCapabilities returns one model-grounded unified-search contract.
// resolverSearchCapabilities 返回一个模型型统一搜索契约。
func resolverSearchCapabilities() catalog.ServiceCapabilities {
	return catalog.ServiceCapabilities{WebSearch: &catalog.WebSearchCapabilities{
		BackendKind:            vcp.SearchBackendGroundedModel,
		InvocationMode:         catalog.SearchInvocationPrompt,
		BackingModelOfferingID: "offer_kimi_k3",
		PromptTemplateID:       "search_prompt",
		PromptTemplateRevision: 1,
		OutputModes:            []vcp.WebSearchOutputMode{vcp.WebSearchOutputAnswerWithCitations},
		EvidenceKinds:          []vcp.SearchEvidenceKind{vcp.SearchEvidenceCitation},
		EvidenceRequirements:   []vcp.SearchEvidenceRequirement{vcp.SearchEvidenceBestEffort, vcp.SearchEvidenceVerified},
		Filters: catalog.SearchFilterCapabilities{
			DomainAllow:     catalog.CapabilityUnsupported,
			DomainBlock:     catalog.CapabilityUnsupported,
			PublicationTime: catalog.CapabilityUnsupported,
			Language:        catalog.CapabilityUnsupported,
			Region:          catalog.CapabilityUnsupported,
			Location:        catalog.CapabilityUnsupported,
			SafeSearch:      catalog.CapabilityUnsupported,
		},
		MaxResults: catalog.OptionalCountLimit{},
	}}
}

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
		Tokens:                 catalog.TokenLimits{ContextWindow: catalog.OptionalTokenLimit{Known: true, Value: contextWindow}, MaxOutputTokens: catalog.OptionalTokenLimit{Known: true, Value: 16_384}},
		Recommendations:        catalog.TokenRecommendations{OutputTokens: catalog.OptionalTokenLimit{Known: true, Value: 8_192}},
		ToolCalling:            catalog.CapabilityNative,
		ParallelToolCalls:      catalog.CapabilityNative,
		StreamingToolArguments: catalog.CapabilityNative,
		StrictJSONSchema:       catalog.CapabilityConditional,
		Reasoning:              catalog.CapabilityNative,
		InputModalities:        []string{"text"},
		OutputModalities:       []string{"text"},
		Delivery:               catalog.DeliveryCapabilities{Synchronous: true, Streaming: true},
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
		ActionBindings: []providerconfig.ProviderActionBinding{
			{ID: "action_conversation", Operation: vcp.OperationConversationRespond, DriverID: "kimi-coding-plan", DriverVersion: "1.0.0", ProtocolProfileID: "openai.chat", EndpointProfileID: "kimi-coding", AuthMethodIDs: []string{"oauth"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true, Streaming: true}, Revision: 1},
			{ID: "action_web_search", Operation: vcp.OperationSearchWeb, DriverID: "kimi-coding-plan", DriverVersion: "1.0.0", ProtocolProfileID: "openai.chat", EndpointProfileID: "kimi-coding", AuthMethodIDs: []string{"oauth"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true, Streaming: true}, Search: &providerconfig.SearchActionBinding{BackendKind: vcp.SearchBackendGroundedModel, BackingModelOfferingID: "offer_kimi_k3", PromptTemplateID: "search_prompt", PromptTemplateRevision: 1}, Revision: 1},
		},
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
				Operation:                  vcp.OperationConversationRespond,
				ActionBindingID:            "action_conversation",
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
				Operation:                  vcp.OperationConversationRespond,
				ActionBindingID:            "action_conversation",
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

// TestResolverSkipsCoolingCredentialModelState verifies a model failure does not globally disable the account.
// TestResolverSkipsCoolingCredentialModelState 验证模型失败不会全局禁用账号。
func TestResolverSkipsCoolingCredentialModelState(t *testing.T) {
	fixture := newResolverFixture(t)
	states := routingstate.NewMemoryStore(fixture.now)
	coolingUntil := fixture.now.Add(time.Minute)
	if errState := states.SaveCredentialModelState(context.Background(), routingstate.CredentialModelState{ProviderInstanceID: "pvi_kimi", CredentialID: "cred_kimi_256k", ProviderModelID: "model_kimi_k3", Status: routingstate.ModelCooling, CoolingUntil: &coolingUntil, LastFailureAt: &fixture.now, Revision: 1}); errState != nil {
		t.Fatalf("SaveCredentialModelState() error = %v", errState)
	}
	resolver, errResolver := NewWithRuntimeState(fixture.configurations, fixture.catalogs, states)
	if errResolver != nil {
		t.Fatalf("NewWithRuntimeState() error = %v", errResolver)
	}
	target, _, errResolve := resolver.Resolve(context.Background(), Request{ProviderInstanceID: "pvi_kimi", ProviderModelID: "model_kimi_k3", ExecutionProfileID: "profile_kimi_k3_256k", Operation: vcp.OperationConversationRespond, Now: fixture.now})
	if errResolve != nil || target.CredentialID != "cred_kimi_1m" {
		t.Fatalf("resolved target = %#v, error = %v", target, errResolve)
	}
	if !fixture.snapshot.Entitlements[0].LimitOverrides.ContextWindow.Known {
		t.Fatal("fixture unexpectedly mutated the cooling credential entitlement")
	}
}

// TestResolverAppliesCredentialEndpointAndSharedRuntimeScopes verifies every classified non-model boundary filters the exact candidate set.
// TestResolverAppliesCredentialEndpointAndSharedRuntimeScopes 验证每个分类非模型边界都会过滤精确候选集合。
func TestResolverAppliesCredentialEndpointAndSharedRuntimeScopes(t *testing.T) {
	testCases := []struct {
		// name identifies the runtime scope scenario.
		// name 标识运行时作用域场景。
		name string
		// scope is the persisted runtime resource boundary.
		// scope 是持久化的运行时资源边界。
		scope routingstate.RuntimeScope
		// scopeID is the exact resource identifier to cool down.
		// scopeID 是需要冷却的精确资源标识。
		scopeID string
		// wantCredentialID is the eligible alternative credential.
		// wantCredentialID 是可用的替代凭据。
		wantCredentialID string
		// wantNoTarget reports whether the scope blocks every candidate.
		// wantNoTarget 表示该作用域是否阻断所有候选项。
		wantNoTarget bool
	}{
		{name: "credential", scope: routingstate.ScopeCredential, scopeID: "cred_kimi_256k", wantCredentialID: "cred_kimi_1m"},
		{name: "billing_account", scope: routingstate.ScopeBillingAccount, scopeID: "billing-1m", wantCredentialID: "cred_kimi_256k"},
		{name: "endpoint", scope: routingstate.ScopeEndpoint, scopeID: "ep_kimi", wantNoTarget: true},
		{name: "provider", scope: routingstate.ScopeProvider, scopeID: "pvi_kimi", wantNoTarget: true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newResolverFixture(t)
			states := routingstate.NewMemoryStore(fixture.now)
			coolingUntil := fixture.now.Add(time.Minute)
			state := routingstate.RuntimeScopeState{ProviderInstanceID: "pvi_kimi", Scope: testCase.scope, ScopeID: testCase.scopeID, Status: routingstate.ModelCooling, CoolingUntil: &coolingUntil, LastFailureAt: &fixture.now, Revision: 1}
			if errState := states.SaveRuntimeScopeState(context.Background(), state); errState != nil {
				t.Fatalf("SaveRuntimeScopeState() error = %v", errState)
			}
			resolver, errResolver := NewWithRuntimeState(fixture.configurations, fixture.catalogs, states)
			if errResolver != nil {
				t.Fatalf("NewWithRuntimeState() error = %v", errResolver)
			}
			target, _, errResolve := resolver.Resolve(context.Background(), Request{ProviderInstanceID: "pvi_kimi", ProviderModelID: "model_kimi_k3", ExecutionProfileID: "profile_kimi_k3_256k", Operation: vcp.OperationConversationRespond, Now: fixture.now})
			if testCase.wantNoTarget {
				if !errors.Is(errResolve, ErrNoEligibleTarget) {
					t.Fatalf("target=%+v error=%v, want ErrNoEligibleTarget", target, errResolve)
				}
				return
			}
			if errResolve != nil || target.CredentialID != testCase.wantCredentialID {
				t.Fatalf("target=%+v error=%v", target, errResolve)
			}
		})
	}
}

// TestSummarizeSnapshotAppliesLiveRuntimeState verifies management pool summaries match execution-time cooldown filtering.
// TestSummarizeSnapshotAppliesLiveRuntimeState 验证管理账号池摘要与执行时冷却过滤保持一致。
func TestSummarizeSnapshotAppliesLiveRuntimeState(t *testing.T) {
	fixture := newResolverFixture(t)
	states := routingstate.NewMemoryStore(fixture.now)
	coolingUntil := fixture.now.Add(time.Minute)
	state := routingstate.RuntimeScopeState{ProviderInstanceID: "pvi_kimi", Scope: routingstate.ScopeCredential, ScopeID: "cred_kimi_1m", Status: routingstate.ModelCooling, CoolingUntil: &coolingUntil, LastFailureAt: &fixture.now, Revision: 1}
	if errState := states.SaveRuntimeScopeState(context.Background(), state); errState != nil {
		t.Fatalf("SaveRuntimeScopeState() error = %v", errState)
	}
	resolver, errResolver := NewWithRuntimeState(fixture.configurations, fixture.catalogs, states)
	if errResolver != nil {
		t.Fatalf("NewWithRuntimeState() error = %v", errResolver)
	}
	pools, errPools := resolver.SummarizeSnapshot(context.Background(), fixture.snapshot, fixture.now, fixture.snapshot.Revision)
	if errPools != nil {
		t.Fatalf("SummarizeSnapshot() error = %v", errPools)
	}
	for _, pool := range pools {
		if pool.ExecutionProfileID != "profile_kimi_k3_1m" {
			continue
		}
		if pool.EntitledCredentials != 1 || pool.ReadyCredentials != 0 || pool.CoolingCredentials != 1 {
			t.Fatalf("pool=%+v, want one entitled cooling credential", pool)
		}
		return
	}
	t.Fatal("profile_kimi_k3_1m pool was not summarized")
}

// TestResolverUsesGlobalFillFirstAndExcludedCredentials verifies inherited strategy and one-execution retry exclusion.
// TestResolverUsesGlobalFillFirstAndExcludedCredentials 验证继承策略与单次执行重试排除。
func TestResolverUsesGlobalFillFirstAndExcludedCredentials(t *testing.T) {
	fixture := newResolverFixture(t)
	states := routingstate.NewMemoryStore(fixture.now)
	if errSettings := states.SaveSettings(context.Background(), routingstate.Settings{DefaultRoutingStrategy: providerconfig.RoutingFillFirst, Revision: 2, UpdatedAt: fixture.now.Add(time.Second)}); errSettings != nil {
		t.Fatalf("SaveSettings() error = %v", errSettings)
	}
	resolver, _ := NewWithRuntimeState(fixture.configurations, fixture.catalogs, states)
	request := Request{ProviderInstanceID: "pvi_kimi", ProviderModelID: "model_kimi_k3", ExecutionProfileID: "profile_kimi_k3_256k", Operation: vcp.OperationConversationRespond, Now: fixture.now}
	first, _, errFirst := resolver.Resolve(context.Background(), request)
	second, _, errSecond := resolver.Resolve(context.Background(), request)
	if errFirst != nil || errSecond != nil || first.CredentialID != second.CredentialID {
		t.Fatalf("fill-first targets first=%#v second=%#v errors=%v/%v", first, second, errFirst, errSecond)
	}
	request.ExcludedCredentialIDs = []string{first.CredentialID}
	fallback, _, errFallback := resolver.Resolve(context.Background(), request)
	if errFallback != nil || fallback.CredentialID == first.CredentialID {
		t.Fatalf("excluded fallback = %#v, error = %v", fallback, errFallback)
	}
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
		ProviderInstanceID: "pvi_kimi", ProviderModelID: "model_kimi_k3", ExecutionProfileID: "profile_kimi_k3_256k", Operation: vcp.OperationConversationRespond, Now: fixture.now,
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
		Operation:             vcp.OperationConversationRespond,
		RequiredContextTokens: 200000,
		Now:                   fixture.now,
	})
	if errResolve != nil {
		t.Fatalf("resolve 256K profile: %v", errResolve)
	}
	if target.CredentialID != "cred_kimi_256k" {
		t.Fatalf("expected smallest sufficient credential, got %s", target.CredentialID)
	}
	if target.SubjectKind != ExecutionSubjectModel || target.Operation != vcp.OperationConversationRespond || target.ActionBindingID != "action_conversation" {
		t.Fatalf("resolved typed model target = %#v", target)
	}
	if !target.TokenLimits.MaxOutputTokens.Known || target.TokenLimits.MaxOutputTokens.Value != 16_384 || !target.TokenRecommendations.OutputTokens.Known || target.TokenRecommendations.OutputTokens.Value != 8_192 {
		t.Fatalf("resolved token facts = limits %#v recommendations %#v", target.TokenLimits, target.TokenRecommendations)
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
		Operation:             vcp.OperationConversationRespond,
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

// TestInspectModelContextsListsExactAuthorizedAccounts verifies context-to-account mapping without selecting or hiding non-default profiles.
// TestInspectModelContextsListsExactAuthorizedAccounts 验证上下文到账号的精确映射，且不选择账号或隐藏非默认规格。
func TestInspectModelContextsListsExactAuthorizedAccounts(t *testing.T) {
	fixture := newResolverFixture(t)
	contexts, errContexts := fixture.resolver.InspectModelContexts(context.Background(), "pvi_kimi", "model_kimi_k3", fixture.now)
	if errContexts != nil {
		t.Fatalf("InspectModelContexts() error = %v", errContexts)
	}
	if len(contexts) != 2 || contexts[0].ProfileID != "profile_kimi_k3_1m" || contexts[1].ProfileID != "profile_kimi_k3_256k" {
		t.Fatalf("model contexts = %#v", contexts)
	}
	if len(contexts[0].Accounts) != 1 || contexts[0].Accounts[0].CredentialID != "cred_kimi_1m" || contexts[0].Accounts[0].RuntimeStatus != ContextAccountReady || contexts[0].Accounts[0].EffectiveContextWindow.Value != 1048576 {
		t.Fatalf("1M context accounts = %#v", contexts[0].Accounts)
	}
	if len(contexts[1].Accounts) != 2 || contexts[1].Accounts[0].CredentialID != "cred_kimi_1m" || contexts[1].Accounts[1].CredentialID != "cred_kimi_256k" {
		t.Fatalf("256K context accounts = %#v", contexts[1].Accounts)
	}
}

// TestInspectModelContextsKeepsExplicitEntitlementWhenPathIsUnavailable verifies authorization ownership is not erased by local endpoint state.
// TestInspectModelContextsKeepsExplicitEntitlementWhenPathIsUnavailable 验证授权归属不会被本地入口状态抹除。
func TestInspectModelContextsKeepsExplicitEntitlementWhenPathIsUnavailable(t *testing.T) {
	fixture := newResolverFixture(t)
	bindings, errBindings := fixture.configurations.ListBindings(context.Background(), "pvi_kimi")
	if errBindings != nil {
		t.Fatalf("ListBindings() error = %v", errBindings)
	}
	for _, binding := range bindings {
		binding.Enabled = false
		binding.Revision++
		if errSave := fixture.configurations.SaveBinding(context.Background(), binding); errSave != nil {
			t.Fatalf("SaveBinding() error = %v", errSave)
		}
	}
	contexts, errContexts := fixture.resolver.InspectModelContexts(context.Background(), "pvi_kimi", "model_kimi_k3", fixture.now)
	if errContexts != nil {
		t.Fatalf("InspectModelContexts() error = %v", errContexts)
	}
	if len(contexts) != 2 || len(contexts[0].Accounts) != 1 || contexts[0].Accounts[0].RuntimeStatus != ContextAccountUnavailable || len(contexts[1].Accounts) != 2 {
		t.Fatalf("unavailable explicit context accounts = %#v", contexts)
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
		Operation:             vcp.OperationConversationRespond,
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
