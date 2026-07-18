package refresh

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/management"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

// fakeKimiDriver provides deterministic provider-native metadata without network access.
// fakeKimiDriver 提供不访问网络的确定性供应商原生元数据。
type fakeKimiDriver struct {
	// definition is the immutable system provider definition.
	// definition 是不可变系统供应商定义。
	definition providerconfig.ProviderDefinition
	// observedAt fixes every provider metadata timestamp.
	// observedAt 固定全部供应商元数据时间戳。
	observedAt time.Time
}

// Definition returns the immutable fake Kimi integration definition.
// Definition 返回不可变 Fake Kimi 集成定义。
func (d fakeKimiDriver) Definition() providerconfig.ProviderDefinition {
	return d.definition
}

// ClassifyError reports no runtime error rules for the metadata-only fake.
// ClassifyError 表示仅元数据 Fake 没有运行时错误规则。
func (d fakeKimiDriver) ClassifyError(provider.ErrorObservation) (provider.ClassifiedError, bool) {
	return provider.ClassifiedError{}, false
}

// DiscoverModels returns one K3 offering with 256K and 1M execution profiles.
// DiscoverModels 返回一个具有 256K 与 1M 执行规格的 K3 产品。
func (d fakeKimiDriver) DiscoverModels(_ context.Context, request provider.DiscoveryRequest) (provider.ModelDiscoveryResult, error) {
	instanceID := request.ProviderInstance.ID
	return provider.ModelDiscoveryResult{
		Models: []catalog.ProviderModel{{
			ID:                 "model_kimi_k3",
			ProviderInstanceID: instanceID,
			UpstreamModelID:    "kimi-k3",
			DisplayName:        "Kimi K3",
			Source:             catalog.ModelSourceSystem,
			EntitlementMode:    catalog.EntitlementExplicit,
			Revision:           1,
		}},
		Offerings: []catalog.ModelOffering{{
			ID:                 "offer_kimi_k3",
			ProviderInstanceID: instanceID,
			ProviderModelID:    "model_kimi_k3",
			ChannelID:          "anthropic",
			UpstreamModelID:    "kimi-k3",
			Capabilities:       fakeKimiCapabilities(1048576),
			CapabilityRevision: 1,
			Revision:           1,
		}},
		Profiles: []catalog.ExecutionProfile{
			{
				ID:                         "profile_kimi_k3_256k",
				ProviderInstanceID:         instanceID,
				OfferingID:                 "offer_kimi_k3",
				DisplayName:                "256K",
				Default:                    true,
				Capabilities:               fakeKimiCapabilities(262144),
				RequiredEntitlementClasses: []string{"kimi_256k", "kimi_1m"},
				SwitchPolicy:               catalog.ProfileSwitchReplayRequired,
				PoolPolicy:                 catalog.PoolPreferSmallestSufficient,
				CapabilityRevision:         1,
				Revision:                   1,
			},
			{
				ID:                         "profile_kimi_k3_1m",
				ProviderInstanceID:         instanceID,
				OfferingID:                 "offer_kimi_k3",
				DisplayName:                "1M",
				Capabilities:               fakeKimiCapabilities(1048576),
				RequiredEntitlementClasses: []string{"kimi_1m"},
				SwitchPolicy:               catalog.ProfileSwitchReplayRequired,
				PoolPolicy:                 catalog.PoolStrictProfile,
				CapabilityRevision:         1,
				Revision:                   1,
			},
		},
		ObservedAt: d.observedAt,
	}, nil
}

// ReadPlan returns one account-specific commercial plan snapshot.
// ReadPlan 返回一个账号特定商业套餐快照。
func (d fakeKimiDriver) ReadPlan(_ context.Context, instance providerconfig.ProviderInstance, credential providerconfig.Credential) (catalog.PlanSnapshot, error) {
	planCode := "coding_256k"
	planName := "Coding 256K"
	if credential.ID == "cred_kimi_1m" {
		planCode = "coding_1m"
		planName = "Coding 1M"
	}
	return catalog.PlanSnapshot{
		ID:                 "plan_" + credential.ID,
		ProviderInstanceID: instance.ID,
		CredentialID:       credential.ID,
		PlanCode:           planCode,
		PlanName:           planName,
		Status:             "active",
		ObservedAt:         d.observedAt,
		ExpiresAt:          d.observedAt.Add(time.Hour),
		Revision:           1,
	}, nil
}

// ReadEntitlements returns the exact account-specific K3 context authorization.
// ReadEntitlements 返回精确账号特定 K3 上下文授权。
func (d fakeKimiDriver) ReadEntitlements(_ context.Context, instance providerconfig.ProviderInstance, credential providerconfig.Credential) ([]catalog.ModelEntitlement, error) {
	entitlementClass := "kimi_256k"
	allowedProfiles := []string{"profile_kimi_k3_256k"}
	contextWindow := int64(262144)
	if credential.ID == "cred_kimi_1m" {
		entitlementClass = "kimi_1m"
		allowedProfiles = []string{"profile_kimi_k3_256k", "profile_kimi_k3_1m"}
		contextWindow = 1048576
	}
	return []catalog.ModelEntitlement{{
		ID:                 "ent_" + credential.ID,
		ProviderInstanceID: instance.ID,
		CredentialID:       credential.ID,
		ProviderModelID:    "model_kimi_k3",
		Availability:       catalog.AvailabilityAllowed,
		EntitlementClass:   entitlementClass,
		AllowedProfileIDs:  allowedProfiles,
		LimitOverrides:     catalog.TokenLimits{ContextWindow: catalog.OptionalTokenLimit{Known: true, Value: contextWindow}},
		Source:             catalog.ModelSourceProviderAPI,
		ObservedAt:         d.observedAt,
		ExpiresAt:          d.observedAt.Add(time.Hour),
		Revision:           1,
	}}, nil
}

// ReadAllowances returns an available weekly quota or an exhausted 1M billing balance.
// ReadAllowances 返回可用周额度或已经耗尽的 1M 计费余额。
func (d fakeKimiDriver) ReadAllowances(_ context.Context, instance providerconfig.ProviderInstance, credential providerconfig.Credential) ([]catalog.AllowanceSnapshot, error) {
	remaining := "50"
	if credential.ID == "cred_kimi_256k" {
		resetAt := d.observedAt.Add(7 * 24 * time.Hour)
		return []catalog.AllowanceSnapshot{{
			ID:                 "allow_kimi_256k_week",
			ProviderInstanceID: instance.ID,
			Kind:               catalog.AllowanceWindowQuota,
			Scope:              catalog.ScopeBillingAccount,
			ScopeID:            "billing-256k",
			Metric:             "weekly_usage",
			Unit:               catalog.UnitPercentage,
			Remaining:          &remaining,
			Status:             catalog.AllowanceAvailable,
			Mandatory:          true,
			Window:             &catalog.AllowanceWindow{Kind: catalog.WindowCalendar, CalendarUnit: "week", ResetAt: &resetAt},
			Source:             catalog.ModelSourceProviderAPI,
			ObservedAt:         d.observedAt,
			ExpiresAt:          d.observedAt.Add(5 * time.Minute),
			Revision:           1,
		}}, nil
	}
	remaining = "0"
	return []catalog.AllowanceSnapshot{{
		ID:                 "allow_kimi_1m_balance",
		ProviderInstanceID: instance.ID,
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
		ObservedAt:         d.observedAt,
		ExpiresAt:          d.observedAt.Add(5 * time.Minute),
		Revision:           1,
	}}, nil
}

// fakeKimiCapabilities returns explicit text capabilities for one context shape.
// fakeKimiCapabilities 返回一个上下文形态的显式文本能力。
func fakeKimiCapabilities(contextWindow int64) catalog.ModelCapabilities {
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

// TestFakeKimiRefreshBuildsProfilesPoolsAndSafeQuery verifies the complete metadata loop.
// TestFakeKimiRefreshBuildsProfilesPoolsAndSafeQuery 校验完整元数据闭环。
func TestFakeKimiRefreshBuildsProfilesPoolsAndSafeQuery(t *testing.T) {
	ctx := context.Background()
	observedAt := time.Date(2026, 7, 17, 15, 0, 0, 0, time.UTC)
	protocols := providerconfig.NewProtocolRegistry()
	if err := protocols.Register(providerconfig.ProtocolProfile{
		ID: "anthropic.messages.v1", Version: "1", DisplayName: "Anthropic Messages", RuntimeReady: true,
		ModelDiscovery: providerconfig.SupportUnsupported, AllowedAuthMethods: []providerconfig.AuthMethodType{providerconfig.AuthMethodBearer},
	}); err != nil {
		t.Fatalf("register protocol profile: %v", err)
	}
	systems, errSystems := providerconfig.NewSystemRegistry(protocols)
	if errSystems != nil {
		t.Fatalf("create system registry: %v", errSystems)
	}
	driver := fakeKimiDriver{definition: providerconfig.ProviderDefinition{
		ID: "system_kimi_coding_plan", Kind: providerconfig.DefinitionKindSystem, DisplayName: "Kimi Coding Plan",
		DriverID: "kimi-coding-plan", DriverVersion: "1.0.0", ConfigSchemaVersion: "1",
		Channels: []providerconfig.ProviderChannel{{
			ID: "anthropic", ProtocolProfileID: "anthropic.messages.v1", EndpointProfileID: "kimi", AuthMethodIDs: []string{"bearer"}, RuntimeReady: true,
		}},
		AuthMethods: []providerconfig.AuthMethodDefinition{{
			ID: "bearer", Type: providerconfig.AuthMethodBearer, MultipleCredentials: true,
		}},
		Features: providerconfig.ProviderFeatureSet{
			ModelDiscovery: providerconfig.SupportSupported, PlanReader: providerconfig.SupportSupported,
			EntitlementReader: providerconfig.SupportSupported, AllowanceReader: providerconfig.SupportSupported,
		},
		Revision: 1,
	}, observedAt: observedAt}
	drivers, errDrivers := provider.NewRegistry(systems)
	if errDrivers != nil {
		t.Fatalf("create provider registry: %v", errDrivers)
	}
	if err := drivers.Register(driver); err != nil {
		t.Fatalf("register fake Kimi driver: %v", err)
	}
	configurations, errConfigurations := providerconfig.NewMemoryStore(protocols, systems)
	if errConfigurations != nil {
		t.Fatalf("create configuration store: %v", errConfigurations)
	}
	catalogs := catalog.NewMemoryStore()
	configurationService, errConfigurationService := management.NewService(configurations, secret.NewMemoryStore(), catalogs)
	if errConfigurationService != nil {
		t.Fatalf("create configuration service: %v", errConfigurationService)
	}
	instance, errInstance := configurationService.CreateInstance(ctx, management.CreateInstanceInput{
		ID: "pvi_kimi", DefinitionID: driver.definition.ID, Handle: "kimi", DisplayName: "Kimi",
	})
	if errInstance != nil {
		t.Fatalf("create Kimi instance: %v", errInstance)
	}
	endpoint, errEndpoint := configurationService.AddEndpoint(ctx, management.AddEndpointInput{
		ID: "ep_kimi", ProviderInstanceID: instance.ID, ChannelID: "anthropic", BaseURL: "https://api.kimi.example/v1",
	})
	if errEndpoint != nil {
		t.Fatalf("add Kimi endpoint: %v", errEndpoint)
	}
	credentialInputs := []management.AddCredentialInput{
		{ID: "cred_kimi_256k", ProviderInstanceID: instance.ID, AuthMethodID: "bearer", Label: "256K", PrincipalKey: "account-256k", Fingerprint: "fingerprint-256k", ScopeRefs: []providerconfig.ScopeReference{{Kind: "billing_account", ID: "billing-256k"}}, Secret: []byte("secret-256k")},
		{ID: "cred_kimi_1m", ProviderInstanceID: instance.ID, AuthMethodID: "bearer", Label: "1M", PrincipalKey: "account-1m", Fingerprint: "fingerprint-1m", ScopeRefs: []providerconfig.ScopeReference{{Kind: "billing_account", ID: "billing-1m"}}, Secret: []byte("secret-1m")},
	}
	for index, input := range credentialInputs {
		credential, errCredential := configurationService.AddCredential(ctx, input)
		if errCredential != nil {
			t.Fatalf("add Kimi credential %s: %v", input.ID, errCredential)
		}
		if _, errBinding := configurationService.AddBinding(ctx, management.AddBindingInput{
			ID: "bind_" + strings.TrimPrefix(credential.ID, "cred_"), ProviderInstanceID: instance.ID,
			ChannelID: "anthropic", EndpointID: endpoint.ID, CredentialID: credential.ID, Priority: index,
		}); errBinding != nil {
			t.Fatalf("bind Kimi credential %s: %v", credential.ID, errBinding)
		}
	}
	if _, errActivate := configurationService.ActivateInstance(ctx, instance.ID); errActivate != nil {
		t.Fatalf("activate Kimi instance: %v", errActivate)
	}
	refreshService, errRefreshService := NewService(configurations, catalogs, drivers)
	if errRefreshService != nil {
		t.Fatalf("create refresh service: %v", errRefreshService)
	}
	snapshot, errRefresh := refreshService.Refresh(ctx, instance.ID, observedAt)
	if errRefresh != nil {
		t.Fatalf("refresh fake Kimi catalog: %v", errRefresh)
	}
	if len(snapshot.Profiles) != 2 || len(snapshot.Pools) != 2 || len(snapshot.Plans) != 2 {
		t.Fatalf("profiles=%d pools=%d plans=%d", len(snapshot.Profiles), len(snapshot.Pools), len(snapshot.Plans))
	}
	queryService, errQueryService := management.NewQueryService(configurations, catalogs)
	if errQueryService != nil {
		t.Fatalf("create query service: %v", errQueryService)
	}
	view, errView := queryService.GetCatalog(ctx, instance.ID)
	if errView != nil {
		t.Fatalf("query Kimi catalog: %v", errView)
	}
	profiles := view.Models[0].Offerings[0].Profiles
	if len(profiles) != 2 || profiles[0].Capabilities.ContextWindow.Value != 262144 || profiles[1].Capabilities.ContextWindow.Value != 1048576 {
		t.Fatalf("unexpected sorted Kimi profile views: %+v", profiles)
	}
	if len(view.Plans) != 2 || view.Plans[0].CredentialCount != 1 || view.Plans[1].CredentialCount != 1 {
		t.Fatalf("unexpected safe Kimi plan aggregates: %+v", view.Plans)
	}
	encodedView, errEncode := json.Marshal(view)
	if errEncode != nil {
		t.Fatalf("encode safe catalog view: %v", errEncode)
	}
	for _, forbidden := range []string{"cred_kimi_256k", "cred_kimi_1m", "billing-256k", "billing-1m", "secret-256k", "secret-1m"} {
		if strings.Contains(string(encodedView), forbidden) {
			t.Fatalf("safe catalog view leaked %s", forbidden)
		}
	}
	targetResolver, errResolver := resolve.New(configurations, catalogs)
	if errResolver != nil {
		t.Fatalf("create target resolver: %v", errResolver)
	}
	target, _, errResolve256K := targetResolver.Resolve(ctx, resolve.Request{
		ProviderInstanceID: instance.ID, ProviderModelID: "model_kimi_k3", ExecutionProfileID: "profile_kimi_k3_256k",
		RequiredContextTokens: 200000, Now: observedAt,
	})
	if errResolve256K != nil || target.CredentialID != "cred_kimi_256k" {
		t.Fatalf("resolve 256K target=%s error=%v", target.CredentialID, errResolve256K)
	}
	_, diagnostics, errResolve1M := targetResolver.Resolve(ctx, resolve.Request{
		ProviderInstanceID: instance.ID, ProviderModelID: "model_kimi_k3", ExecutionProfileID: "profile_kimi_k3_1m",
		RequiredContextTokens: 800000, Now: observedAt,
	})
	if !errors.Is(errResolve1M, resolve.ErrNoEligibleTarget) || len(diagnostics.BlockingAllowanceKinds) != 1 || diagnostics.BlockingAllowanceKinds[0] != catalog.AllowanceBalance {
		t.Fatalf("expected exhausted 1M balance, error=%v diagnostics=%+v", errResolve1M, diagnostics)
	}
}
