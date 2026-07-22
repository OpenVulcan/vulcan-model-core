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
	// metadataReads counts complete per-credential observations performed by the aggregate contract.
	// metadataReads 统计聚合合同执行的完整逐凭据观测次数。
	metadataReads *int
	// failCredentialID optionally injects one isolated account metadata failure.
	// failCredentialID 可选注入一个隔离账号元数据失败。
	failCredentialID *string
}

// separateKimiDriver exposes independent metadata readers and can fail one entitlement read.
// separateKimiDriver 暴露独立元数据读取器，并可使一次权益读取失败。
type separateKimiDriver struct {
	// base owns deterministic metadata values and model discovery.
	// base 管理确定性元数据值与模型发现。
	base fakeKimiDriver
	// failCredentialID identifies the account whose entitlement read fails.
	// failCredentialID 标识权益读取失败的账号。
	failCredentialID string
}

// Definition returns the immutable integration definition.
// Definition 返回不可变集成 Definition。
func (d separateKimiDriver) Definition() providerconfig.ProviderDefinition {
	return d.base.Definition()
}

// ClassifyError reports no runtime error classification.
// ClassifyError 表示没有运行时错误分类。
func (d separateKimiDriver) ClassifyError(observation provider.ErrorObservation) (provider.ClassifiedError, bool) {
	return d.base.ClassifyError(observation)
}

// DiscoverModels forwards deterministic model discovery.
// DiscoverModels 转发确定性模型发现。
func (d separateKimiDriver) DiscoverModels(ctx context.Context, request provider.DiscoveryRequest) (provider.ModelDiscoveryResult, error) {
	return d.base.DiscoverModels(ctx, request)
}

// ReadPlan forwards one independent plan read.
// ReadPlan 转发一次独立套餐读取。
func (d separateKimiDriver) ReadPlan(ctx context.Context, instance providerconfig.ProviderInstance, credential providerconfig.Credential) (catalog.PlanSnapshot, error) {
	return d.base.ReadPlan(ctx, instance, credential)
}

// ReadEntitlements fails only the configured account and forwards every other read.
// ReadEntitlements 仅使已配置账号失败，并转发其他读取。
func (d separateKimiDriver) ReadEntitlements(ctx context.Context, instance providerconfig.ProviderInstance, credential providerconfig.Credential) ([]catalog.ModelEntitlement, error) {
	if credential.ID == d.failCredentialID {
		return nil, errors.New("injected separate entitlement failure")
	}
	return d.base.ReadEntitlements(ctx, instance, credential)
}

// ReadAllowances forwards one independent allowance read.
// ReadAllowances 转发一次独立额度读取。
func (d separateKimiDriver) ReadAllowances(ctx context.Context, instance providerconfig.ProviderInstance, credential providerconfig.Credential) ([]catalog.AllowanceSnapshot, error) {
	return d.base.ReadAllowances(ctx, instance, credential)
}

// metadataReaderlessDriver declares metadata capabilities without implementing any reader.
// metadataReaderlessDriver 声明元数据能力但不实现任何读取器。
type metadataReaderlessDriver struct {
	// definition contains the intentionally inconsistent feature contract.
	// definition 包含故意不一致的功能合同。
	definition providerconfig.ProviderDefinition
}

// fakeCredentialRefresher records exact refresh ownership and returns one configured replacement.
// fakeCredentialRefresher 记录精确刷新归属并返回一个已配置的替换凭据。
type fakeCredentialRefresher struct {
	// calls records the exact provider-instance and credential pairs requested by the service.
	// calls 记录服务请求的精确供应商实例与凭据组合。
	calls []string
	// replacement is the persisted credential metadata returned after protected token replacement.
	// replacement 是受保护令牌替换后返回的已持久化凭据元数据。
	replacement providerconfig.Credential
	// err injects one protected refresh failure.
	// err 注入一次受保护刷新失败。
	err error
}

// failingCatalogStore delegates reads and fails every attempted replacement.
// failingCatalogStore 委托读取并使每次替换尝试失败。
type failingCatalogStore struct {
	// Store supplies the previously committed last-good snapshot.
	// Store 提供先前已提交的最后有效快照。
	catalog.Store
	// err is the exact durable persistence failure.
	// err 是精确的持久化失败。
	err error
}

// Save injects the configured durable persistence failure.
// Save 注入配置的持久化失败。
func (s failingCatalogStore) Save(context.Context, catalog.Snapshot) error {
	return s.err
}

// RefreshCredential records one exact refresh request and returns the configured result.
// RefreshCredential 记录一次精确刷新请求并返回已配置结果。
func (r *fakeCredentialRefresher) RefreshCredential(_ context.Context, instanceID string, credentialID string) (providerconfig.Credential, error) {
	r.calls = append(r.calls, instanceID+"\x00"+credentialID)
	return r.replacement, r.err
}

// Definition returns the intentionally inconsistent test definition.
// Definition 返回故意不一致的测试 Definition。
func (d metadataReaderlessDriver) Definition() providerconfig.ProviderDefinition {
	return d.definition
}

// ClassifyError reports no runtime classification for the metadata-only test double.
// ClassifyError 表示仅元数据测试替身没有运行时错误分类。
func (d metadataReaderlessDriver) ClassifyError(provider.ErrorObservation) (provider.ClassifiedError, bool) {
	return provider.ClassifiedError{}, false
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
			ChannelID:          "openai.chat",
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
		ObservedAt:     d.observedAt,
		ExpiresAt:      d.observedAt.Add(time.Hour),
		SourceRevision: "fake-kimi-1",
		ETag:           "fake-kimi-etag-1",
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

// ReadCredentialMetadata returns every fake account fact from one aggregate provider observation.
// ReadCredentialMetadata 从一次聚合供应商观测返回全部 Fake 账号事实。
func (d fakeKimiDriver) ReadCredentialMetadata(ctx context.Context, instance providerconfig.ProviderInstance, credential providerconfig.Credential) (provider.CredentialMetadataResult, error) {
	if d.metadataReads != nil {
		(*d.metadataReads)++
	}
	if d.failCredentialID != nil && credential.ID == *d.failCredentialID {
		return provider.CredentialMetadataResult{}, errors.New("injected account metadata failure")
	}
	plan, errPlan := d.ReadPlan(ctx, instance, credential)
	if errPlan != nil {
		return provider.CredentialMetadataResult{}, errPlan
	}
	entitlements, errEntitlements := d.ReadEntitlements(ctx, instance, credential)
	if errEntitlements != nil {
		return provider.CredentialMetadataResult{}, errEntitlements
	}
	allowances, errAllowances := d.ReadAllowances(ctx, instance, credential)
	if errAllowances != nil {
		return provider.CredentialMetadataResult{}, errAllowances
	}
	return provider.CredentialMetadataResult{Plan: &plan, Entitlements: entitlements, Allowances: allowances}, nil
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
		ID: "openai.chat", Version: "1", DisplayName: "OpenAI Chat", RuntimeReady: true,
		ModelDiscovery: providerconfig.SupportUnsupported, AllowedAuthMethods: []providerconfig.AuthMethodType{providerconfig.AuthMethodBearer},
	}); err != nil {
		t.Fatalf("register protocol profile: %v", err)
	}
	systems, errSystems := providerconfig.NewSystemRegistry(protocols)
	if errSystems != nil {
		t.Fatalf("create system registry: %v", errSystems)
	}
	// metadataReads proves the coordinator chooses one aggregate observation per credential.
	// metadataReads 证明协调器为每个凭据选择一次聚合观测。
	metadataReads := 0
	failingCredentialID := ""
	driver := fakeKimiDriver{definition: providerconfig.ProviderDefinition{
		ID: "system_kimi_coding_plan", Kind: providerconfig.DefinitionKindSystem, DisplayName: "Kimi Coding Plan",
		DriverID: "kimi-coding-plan", DriverVersion: "1.0.0", ConfigSchemaVersion: "1",
		ProtocolProfileID: "openai.chat", EndpointProfileID: "kimi", AuthMethodIDs: []string{"bearer"}, RuntimeReady: true,
		AuthMethods: []providerconfig.AuthMethodDefinition{{
			ID: "bearer", Type: providerconfig.AuthMethodBearer, MultipleCredentials: true,
		}},
		Features: providerconfig.ProviderFeatureSet{
			ModelDiscovery: providerconfig.SupportSupported, PlanReader: providerconfig.SupportSupported,
			EntitlementReader: providerconfig.SupportSupported, AllowanceReader: providerconfig.SupportSupported,
		},
		Revision: 1,
	}, observedAt: observedAt, metadataReads: &metadataReads, failCredentialID: &failingCredentialID}
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
		ID: "ep_kimi", ProviderInstanceID: instance.ID, BaseURL: "https://api.kimi.example/v1",
	})
	if errEndpoint != nil {
		t.Fatalf("add Kimi endpoint: %v", errEndpoint)
	}
	credentialInputs := []management.AddCredentialInput{
		{ID: "cred_kimi_256k", ProviderInstanceID: instance.ID, AuthMethodID: "bearer", Label: "256K", PrincipalKey: "account-256k", ScopeRefs: []providerconfig.ScopeReference{{Kind: "billing_account", ID: "billing-256k"}}, Secret: []byte("secret-256k")},
		{ID: "cred_kimi_1m", ProviderInstanceID: instance.ID, AuthMethodID: "bearer", Label: "1M", PrincipalKey: "account-1m", ScopeRefs: []providerconfig.ScopeReference{{Kind: "billing_account", ID: "billing-1m"}}, Secret: []byte("secret-1m")},
	}
	for index, input := range credentialInputs {
		credential, errCredential := configurationService.AddCredential(ctx, input)
		if errCredential != nil {
			t.Fatalf("add Kimi credential %s: %v", input.ID, errCredential)
		}
		if _, errBinding := configurationService.AddBinding(ctx, management.AddBindingInput{
			ID: "bind_" + strings.TrimPrefix(credential.ID, "cred_"), ProviderInstanceID: instance.ID,
			EndpointID: endpoint.ID, CredentialID: credential.ID, Priority: index,
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
	if metadataReads != len(credentialInputs) {
		t.Fatalf("aggregate metadata reads=%d, want %d", metadataReads, len(credentialInputs))
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
	if _, errDisable := configurationService.SetCredentialStatus(ctx, management.SetCredentialStatusInput{
		ProviderInstanceID: instance.ID,
		CredentialID:       "cred_kimi_1m",
		Status:             providerconfig.CredentialDisabled,
	}); errDisable != nil {
		t.Fatalf("disable Kimi credential: %v", errDisable)
	}
	metadataReads = 0
	disabledSnapshot, errDisabledRefresh := refreshService.Refresh(ctx, instance.ID, observedAt.Add(time.Minute))
	if errDisabledRefresh != nil {
		t.Fatalf("refresh with disabled credential: %v", errDisabledRefresh)
	}
	if metadataReads != 1 || len(disabledSnapshot.Plans) != 2 {
		t.Fatalf("disabled refresh reads=%d plans=%+v", metadataReads, disabledSnapshot.Plans)
	}
	if _, errEnable := configurationService.SetCredentialStatus(ctx, management.SetCredentialStatusInput{ProviderInstanceID: instance.ID, CredentialID: "cred_kimi_1m", Status: providerconfig.CredentialActive}); errEnable != nil {
		t.Fatalf("enable Kimi credential: %v", errEnable)
	}
	failingCredentialID = "cred_kimi_1m"
	metadataReads = 0
	partialSnapshot, errPartialRefresh := refreshService.Refresh(ctx, instance.ID, observedAt.Add(2*time.Minute))
	if errPartialRefresh != nil {
		t.Fatalf("partial account refresh: %v", errPartialRefresh)
	}
	if metadataReads != 2 || len(partialSnapshot.Plans) != 2 || len(partialSnapshot.Entitlements) != 2 || len(partialSnapshot.Allowances) != 2 {
		t.Fatalf("partial refresh reads=%d plans=%d entitlements=%d allowances=%d", metadataReads, len(partialSnapshot.Plans), len(partialSnapshot.Entitlements), len(partialSnapshot.Allowances))
	}
	separateDrivers, errSeparateDrivers := provider.NewRegistry(systems)
	if errSeparateDrivers != nil {
		t.Fatalf("create separate-reader registry: %v", errSeparateDrivers)
	}
	separateDriver := separateKimiDriver{base: fakeKimiDriver{definition: driver.definition, observedAt: observedAt}, failCredentialID: "cred_kimi_1m"}
	if errRegisterSeparate := separateDrivers.Register(separateDriver); errRegisterSeparate != nil {
		t.Fatalf("register separate-reader driver: %v", errRegisterSeparate)
	}
	separateRefreshService, errSeparateService := NewService(configurations, catalogs, separateDrivers)
	if errSeparateService != nil {
		t.Fatalf("create separate-reader refresh service: %v", errSeparateService)
	}
	separateSnapshot, errSeparateRefresh := separateRefreshService.Refresh(ctx, instance.ID, observedAt.Add(3*time.Minute))
	if errSeparateRefresh != nil {
		t.Fatalf("separate-reader partial account refresh: %v", errSeparateRefresh)
	}
	if len(separateSnapshot.Plans) != 2 || len(separateSnapshot.Entitlements) != 2 || len(separateSnapshot.Allowances) != 2 {
		t.Fatalf("separate-reader partial refresh plans=%d entitlements=%d allowances=%d", len(separateSnapshot.Plans), len(separateSnapshot.Entitlements), len(separateSnapshot.Allowances))
	}
}

// TestValidateDeclaredMetadataReadersRejectsMissingImplementations verifies supported metadata cannot silently become empty output.
// TestValidateDeclaredMetadataReadersRejectsMissingImplementations 验证已支持元数据不能静默变为空输出。
func TestValidateDeclaredMetadataReadersRejectsMissingImplementations(t *testing.T) {
	testCases := []struct {
		// name labels the isolated feature declaration.
		// name 标记隔离的功能声明。
		name string
		// features contains the exact inconsistent contract under test.
		// features 包含待测试的精确不一致合同。
		features providerconfig.ProviderFeatureSet
	}{
		{name: "plan", features: providerconfig.ProviderFeatureSet{PlanReader: providerconfig.SupportSupported}},
		{name: "entitlement", features: providerconfig.ProviderFeatureSet{EntitlementReader: providerconfig.SupportSupported}},
		{name: "allowance", features: providerconfig.ProviderFeatureSet{AllowanceReader: providerconfig.SupportSupported}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			driver := metadataReaderlessDriver{definition: providerconfig.ProviderDefinition{Features: testCase.features}}
			if errValidate := validateDeclaredMetadataReaders(driver, driver.definition); errValidate == nil {
				t.Fatal("validateDeclaredMetadataReaders() error = nil")
			}
		})
	}
}

// TestRemoveCredentialServiceEntitlementsAppliesAuthoritativeEmptyObservation verifies a successful empty service observation revokes only the observed account.
// TestRemoveCredentialServiceEntitlementsAppliesAuthoritativeEmptyObservation 验证成功的空服务观测仅撤销被观测账号的授权。
func TestRemoveCredentialServiceEntitlementsAppliesAuthoritativeEmptyObservation(t *testing.T) {
	current := []catalog.ServiceEntitlement{
		{ID: "service_ent_first", CredentialID: "cred_first"},
		{ID: "service_ent_second", CredentialID: "cred_second"},
	}
	indexed := map[string]catalog.ServiceEntitlement{
		"service_ent_first":  current[0],
		"service_ent_second": current[1],
	}
	filtered := removeCredentialServiceEntitlements(current, indexed, "cred_first")
	if len(filtered) != 1 || filtered[0].CredentialID != "cred_second" {
		t.Fatalf("filtered service entitlements=%+v", filtered)
	}
	if _, exists := indexed["service_ent_first"]; exists {
		t.Fatal("revoked service entitlement remained indexed")
	}
	if _, exists := indexed["service_ent_second"]; !exists {
		t.Fatal("unrelated service entitlement was removed")
	}
}

// TestMetadataCurrentRejectsExpiredEvidence verifies last-known-good preservation cannot retain stale service authorization.
// TestMetadataCurrentRejectsExpiredEvidence 验证最后可信数据保留不会留下过期服务授权。
func TestMetadataCurrentRejectsExpiredEvidence(t *testing.T) {
	observedAt := time.Date(2026, 7, 20, 20, 0, 0, 0, time.UTC)
	if metadataCurrent(observedAt, observedAt.Add(time.Minute), observedAt.Add(2*time.Minute)) {
		t.Fatal("expired metadata was reported current")
	}
	if !metadataCurrent(observedAt, time.Time{}, observedAt.Add(2*time.Minute)) {
		t.Fatal("non-expiring operator or system metadata was reported stale")
	}
}

// TestNewServiceRejectsTypedNilDependencies verifies refresh orchestration cannot retain boxed nil stores or registries.
// TestNewServiceRejectsTypedNilDependencies 验证刷新编排不会保留装箱后的 nil Store 或 Registry。
func TestNewServiceRejectsTypedNilDependencies(t *testing.T) {
	var configurations *providerconfig.MemoryStore
	var drivers *provider.Registry
	if _, errService := NewService(configurations, catalog.NewMemoryStore(), drivers); errService == nil {
		t.Fatal("NewService() error = nil")
	}
}

// TestRecordDiscoveryFailureJoinsPersistenceFailure verifies last-good failure recording can never hide a storage outage.
// TestRecordDiscoveryFailureJoinsPersistenceFailure 验证最后有效快照的失败记录绝不会隐藏存储故障。
func TestRecordDiscoveryFailureJoinsPersistenceFailure(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.July, 21, 6, 0, 0, 0, time.UTC)
	store := catalog.NewMemoryStore()
	snapshot := catalog.Snapshot{ProviderInstanceID: "pvi_dynamic", Revision: 1, ObservedAt: now.Add(-time.Minute), Dynamic: &catalog.DynamicCatalogMetadata{Authority: catalog.CatalogAuthorityProvider, SourceRevision: "source-1", RefreshedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Status: catalog.CatalogRefreshFresh}}
	if errSave := store.Save(ctx, snapshot); errSave != nil {
		t.Fatalf("Save() error = %v", errSave)
	}
	discoveryErr := errors.New("injected discovery failure")
	persistenceErr := errors.New("injected persistence failure")
	errRecord := recordDiscoveryFailure(ctx, failingCatalogStore{Store: store, err: persistenceErr}, snapshot, nil, snapshot.ProviderInstanceID, now, discoveryErr)
	if !errors.Is(errRecord, discoveryErr) || !errors.Is(errRecord, persistenceErr) {
		t.Fatalf("recordDiscoveryFailure() error = %v, want both causes", errRecord)
	}
}

// TestPrepareCredentialRefreshesOnlyEligibleExpiringTokens verifies metadata refresh cannot strand a refreshable account at token expiry.
// TestPrepareCredentialRefreshesOnlyEligibleExpiringTokens 验证元数据刷新不会在令牌到期时搁置可刷新账号。
func TestPrepareCredentialRefreshesOnlyEligibleExpiringTokens(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	expiresSoon := now.Add(30 * time.Second)
	refreshedExpiry := now.Add(time.Hour)
	credential := providerconfig.Credential{
		ID:                 "cred_refreshable",
		ProviderInstanceID: "pvi_refreshable",
		AuthMethodID:       "device_flow",
		Status:             providerconfig.CredentialActive,
		ExpiresAt:          &expiresSoon,
		Revision:           1,
	}
	replacement := credential
	replacement.ExpiresAt = &refreshedExpiry
	replacement.Revision = 2
	refresher := &fakeCredentialRefresher{replacement: replacement}
	service := &Service{credentialRefreshers: map[string]CredentialRefresher{"system_refreshable": refresher}}
	definition := providerconfig.ProviderDefinition{
		ID: "system_refreshable",
		AuthMethods: []providerconfig.AuthMethodDefinition{{
			ID:          "device_flow",
			Type:        providerconfig.AuthMethodDeviceFlow,
			Refreshable: true,
		}},
	}

	prepared, errPrepare := service.prepareCredential(context.Background(), definition, credential, now)
	if errPrepare != nil {
		t.Fatalf("prepareCredential() error = %v", errPrepare)
	}
	if len(refresher.calls) != 1 || refresher.calls[0] != "pvi_refreshable\x00cred_refreshable" {
		t.Fatalf("refresh calls = %#v", refresher.calls)
	}
	if prepared.Revision != 2 || prepared.ExpiresAt == nil || !prepared.ExpiresAt.Equal(refreshedExpiry) {
		t.Fatalf("prepared credential = %+v", prepared)
	}

	refresher.calls = nil
	notExpiring := credential
	laterExpiry := now.Add(2 * credentialRefreshLeadTime)
	notExpiring.ExpiresAt = &laterExpiry
	prepared, errPrepare = service.prepareCredential(context.Background(), definition, notExpiring, now)
	if errPrepare != nil {
		t.Fatalf("prepareCredential() non-expiring error = %v", errPrepare)
	}
	if len(refresher.calls) != 0 || prepared.Revision != notExpiring.Revision {
		t.Fatalf("non-expiring credential unexpectedly refreshed: calls=%#v credential=%+v", refresher.calls, prepared)
	}
}

// TestPrepareCredentialRejectsRefresherOwnershipChanges verifies protected refresh cannot reassign an account.
// TestPrepareCredentialRejectsRefresherOwnershipChanges 验证受保护刷新不能重新分配账号归属。
func TestPrepareCredentialRejectsRefresherOwnershipChanges(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	expiredAt := now.Add(-time.Second)
	credential := providerconfig.Credential{
		ID:                 "cred_owner",
		ProviderInstanceID: "pvi_owner",
		AuthMethodID:       "oauth",
		Status:             providerconfig.CredentialActive,
		ExpiresAt:          &expiredAt,
	}
	replacement := credential
	replacement.ProviderInstanceID = "pvi_foreign"
	replacementExpiry := now.Add(time.Hour)
	replacement.ExpiresAt = &replacementExpiry
	refresher := &fakeCredentialRefresher{replacement: replacement}
	service := &Service{credentialRefreshers: map[string]CredentialRefresher{"system_owner": refresher}}
	definition := providerconfig.ProviderDefinition{
		ID:          "system_owner",
		AuthMethods: []providerconfig.AuthMethodDefinition{{ID: "oauth", Type: providerconfig.AuthMethodOAuth, Refreshable: true}},
	}

	if _, errPrepare := service.prepareCredential(context.Background(), definition, credential, now); errPrepare == nil {
		t.Fatal("prepareCredential() accepted changed credential ownership")
	}
}

// TestValidateCredentialMetadataOwnershipRejectsForeignRecords verifies every credential-specific and shared-scope boundary.
// TestValidateCredentialMetadataOwnershipRejectsForeignRecords 验证全部凭据特定与共享作用域边界。
func TestValidateCredentialMetadataOwnershipRejectsForeignRecords(t *testing.T) {
	credential := providerconfig.Credential{
		ID:                 "cred_owner",
		ProviderInstanceID: "pvi_owner",
		ScopeRefs:          []providerconfig.ScopeReference{{Kind: "organization", ID: "organization-owner"}},
	}
	plan := catalog.PlanSnapshot{ID: "plan_owner", ProviderInstanceID: credential.ProviderInstanceID, CredentialID: credential.ID}
	entitlement := catalog.ModelEntitlement{ID: "ent_owner", ProviderInstanceID: credential.ProviderInstanceID, CredentialID: credential.ID}
	credentialAllowance := catalog.AllowanceSnapshot{ID: "allow_owner", ProviderInstanceID: credential.ProviderInstanceID, Scope: catalog.ScopeCredential, ScopeID: credential.ID}
	sharedAllowance := catalog.AllowanceSnapshot{ID: "allow_shared", ProviderInstanceID: credential.ProviderInstanceID, Scope: catalog.ScopeOrganization, ScopeID: "organization-owner"}
	if errValid := validateCredentialMetadataOwnership(credential, &plan, []catalog.ModelEntitlement{entitlement}, nil, []catalog.AllowanceSnapshot{credentialAllowance, sharedAllowance}); errValid != nil {
		t.Fatalf("validateCredentialMetadataOwnership() valid metadata error = %v", errValid)
	}
	testCases := []struct {
		// name identifies the exact ownership boundary under test.
		// name 标识待测试的精确所有权边界。
		name string
		// plan is the optional plan record supplied by the fake reader.
		// plan 是 Fake 读取器提供的可选套餐记录。
		plan *catalog.PlanSnapshot
		// entitlements are the model authorization records supplied by the fake reader.
		// entitlements 是 Fake 读取器提供的模型授权记录。
		entitlements []catalog.ModelEntitlement
		// allowances are the resource records supplied by the fake reader.
		// allowances 是 Fake 读取器提供的资源记录。
		allowances []catalog.AllowanceSnapshot
	}{
		{name: "foreign plan credential", plan: &catalog.PlanSnapshot{ID: "plan_foreign", ProviderInstanceID: credential.ProviderInstanceID, CredentialID: "cred_foreign"}},
		{name: "foreign entitlement credential", entitlements: []catalog.ModelEntitlement{{ID: "ent_foreign", ProviderInstanceID: credential.ProviderInstanceID, CredentialID: "cred_foreign"}}},
		{name: "foreign credential allowance", allowances: []catalog.AllowanceSnapshot{{ID: "allow_foreign", ProviderInstanceID: credential.ProviderInstanceID, Scope: catalog.ScopeCredential, ScopeID: "cred_foreign"}}},
		{name: "unbound shared allowance", allowances: []catalog.AllowanceSnapshot{{ID: "allow_unbound", ProviderInstanceID: credential.ProviderInstanceID, Scope: catalog.ScopeOrganization, ScopeID: "organization-foreign"}}},
		{name: "foreign provider instance", allowances: []catalog.AllowanceSnapshot{{ID: "allow_foreign_instance", ProviderInstanceID: "pvi_foreign", Scope: catalog.ScopeCredential, ScopeID: credential.ID}}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if errOwnership := validateCredentialMetadataOwnership(credential, testCase.plan, testCase.entitlements, nil, testCase.allowances); errOwnership == nil {
				t.Fatal("validateCredentialMetadataOwnership() error = nil")
			}
		})
	}
}
