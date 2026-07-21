package management

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/bootstrap"
	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	providerkimi "github.com/OpenVulcan/vulcan-model-core/internal/provider/kimi"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestQueryServiceReturnsModelContextsAndAccountUsage verifies the public discovery graph preserves exact model-profile-account ownership.
// TestQueryServiceReturnsModelContextsAndAccountUsage 验证公开发现图保留精确模型规格账号归属关系。
func TestQueryServiceReturnsModelContextsAndAccountUsage(t *testing.T) {
	ctx := context.Background()
	service, configurations, _ := newKimiOnboardingService(t)
	onboarding, errOnboard := service.OnboardSystemProvider(ctx, OnboardSystemProviderInput{DefinitionID: bootstrap.KimiCodingDefinitionID, DisplayName: "Kimi Coding", AuthMethodID: "api_key", CredentialLabel: "Allegretto Account", Secret: []byte("test-kimi-key"), PlanOptionID: providerkimi.PlanOptionAllegretto})
	if errOnboard != nil {
		t.Fatalf("OnboardSystemProvider() error = %v", errOnboard)
	}
	snapshot, errSnapshot := service.catalogs.Get(ctx, onboarding.Instance.ID)
	if errSnapshot != nil {
		t.Fatalf("Get() catalog error = %v", errSnapshot)
	}
	observedAt := time.Now().UTC()
	remaining := "75"
	snapshot.Allowances = append(snapshot.Allowances, catalog.AllowanceSnapshot{ID: "allow_kimi_weekly", ProviderInstanceID: onboarding.Instance.ID, Kind: catalog.AllowanceWindowQuota, Scope: catalog.ScopeCredential, ScopeID: onboarding.Credential.ID, Metric: "weekly_usage", Unit: catalog.UnitProviderDefined, Remaining: &remaining, Status: catalog.AllowanceAvailable, Window: &catalog.AllowanceWindow{Kind: catalog.WindowProviderDefined}, Source: catalog.ModelSourceProviderAPI, ObservedAt: observedAt, ExpiresAt: observedAt.Add(time.Hour), Revision: 1})
	snapshot.Revision++
	snapshot.ObservedAt = observedAt
	if errSave := service.catalogs.Save(ctx, snapshot); errSave != nil {
		t.Fatalf("Save() catalog error = %v", errSave)
	}
	queries, errQueries := NewQueryService(configurations, service.catalogs)
	if errQueries != nil {
		t.Fatalf("NewQueryService() error = %v", errQueries)
	}
	contexts, errContexts := queries.GetModelContexts(ctx, onboarding.Instance.ID, providerkimi.ModelK3ID)
	if errContexts != nil {
		t.Fatalf("GetModelContexts() error = %v", errContexts)
	}
	if len(contexts.ContextProfiles) != 2 || contexts.ContextProfiles[0].ID != providerkimi.ProfileK3256KID || contexts.ContextProfiles[1].ID != providerkimi.ProfileK31MID {
		t.Fatalf("Kimi context profiles = %#v", contexts.ContextProfiles)
	}
	for _, profile := range contexts.ContextProfiles {
		if len(profile.Accounts) != 1 || profile.Accounts[0].CredentialID != onboarding.Credential.ID || profile.Accounts[0].RuntimeStatus != "ready" || !profile.Accounts[0].UsageAvailable {
			t.Fatalf("Kimi profile accounts = %#v", profile.Accounts)
		}
	}
	encodedContexts, errEncodeContexts := json.Marshal(contexts)
	if errEncodeContexts != nil {
		t.Fatalf("encode model contexts: %v", errEncodeContexts)
	}
	if strings.Contains(string(encodedContexts), "test-kimi-key") || strings.Contains(string(encodedContexts), "secret_ref") || strings.Contains(string(encodedContexts), "principal_key") {
		t.Fatalf("model contexts leaked protected data: %s", encodedContexts)
	}
	usage, errUsage := queries.GetModelCredentialUsage(ctx, onboarding.Instance.ID, providerkimi.ModelK3ID, onboarding.Credential.ID)
	if errUsage != nil {
		t.Fatalf("GetModelCredentialUsage() error = %v", errUsage)
	}
	if usage.PlanCode != providerkimi.PlanOptionAllegretto || len(usage.SupportedContextProfileIDs) != 2 || len(usage.Allowances) != 1 || usage.Allowances[0].Usage.Metric != "weekly_usage" || len(usage.Allowances[0].ContextProfileIDs) != 2 {
		t.Fatalf("Kimi model credential usage = %#v", usage)
	}
	encodedUsage, errEncode := json.Marshal(usage)
	if errEncode != nil {
		t.Fatalf("encode model credential usage: %v", errEncode)
	}
	if strings.Contains(string(encodedUsage), "test-kimi-key") || strings.Contains(string(encodedUsage), "scope_id") {
		t.Fatalf("model credential usage leaked protected data: %s", encodedUsage)
	}
	_, errMissing := queries.GetModelCredentialUsage(ctx, onboarding.Instance.ID, providerkimi.ModelK3ID, "cred_missing")
	if !errors.Is(errMissing, providerconfig.ErrNotFound) {
		t.Fatalf("missing model account error = %v", errMissing)
	}
}

// TestQueryServiceRedactsCredentialSecretMetadata verifies every management query view excludes secret references and identity correlation fields.
// TestQueryServiceRedactsCredentialSecretMetadata 验证每个管理查询视图均排除 Secret 引用和身份关联字段。
func TestQueryServiceRedactsCredentialSecretMetadata(t *testing.T) {
	// ctx fixes one shared configuration operation scope.
	// ctx 固定一个共享配置操作范围。
	ctx := context.Background()
	// commands and configurations share the memory-backed provider configuration state.
	// commands 和 configurations 共享内存后端供应商配置状态。
	commands, configurations, _ := managementTestService(t)
	instance, errInstance := commands.CreateInstance(ctx, CreateInstanceInput{
		ID: "pvi_query_redaction", DefinitionID: "system_management_test", Handle: "query-redaction", DisplayName: "Query Redaction",
	})
	if errInstance != nil {
		t.Fatalf("create provider instance: %v", errInstance)
	}
	endpoint, errEndpoint := commands.AddEndpoint(ctx, AddEndpointInput{
		ID: "ep_query_redaction", ProviderInstanceID: instance.ID, BaseURL: "https://query-redaction.example/v1",
	})
	if errEndpoint != nil {
		t.Fatalf("create endpoint: %v", errEndpoint)
	}
	credential, errCredential := commands.AddCredential(ctx, AddCredentialInput{
		ID: "cred_query_redaction", ProviderInstanceID: instance.ID, AuthMethodID: "bearer", Label: "Safe Label",
		PrincipalKey: "sensitive-principal", Secret: []byte("sensitive-secret"),
	})
	if errCredential != nil {
		t.Fatalf("create credential: %v", errCredential)
	}
	if _, errBinding := commands.AddBinding(ctx, AddBindingInput{
		ID: "bind_query_redaction", ProviderInstanceID: instance.ID, EndpointID: endpoint.ID, CredentialID: credential.ID,
	}); errBinding != nil {
		t.Fatalf("create binding: %v", errBinding)
	}
	// queries uses a catalog store even though these configuration-only routes do not read a snapshot.
	// queries 使用目录存储，即使这些仅配置路由不读取快照。
	queries, errQueries := NewQueryService(configurations, catalog.NewMemoryStore())
	if errQueries != nil {
		t.Fatalf("create query service: %v", errQueries)
	}
	instanceViews, errInstances := queries.ListInstances(ctx)
	if errInstances != nil || len(instanceViews) != 1 {
		t.Fatalf("instance views = %+v, error = %v", instanceViews, errInstances)
	}
	// encodedInstances verifies an unset internal slice remains a stable public JSON array.
	// encodedInstances 验证未设置的内部切片仍保持为稳定的公共 JSON 数组。
	encodedInstances, errEncodeInstances := json.Marshal(instanceViews)
	if errEncodeInstances != nil {
		t.Fatalf("encode instance views: %v", errEncodeInstances)
	}
	if strings.Contains(string(encodedInstances), `"disabled_model_ids":null`) || !strings.Contains(string(encodedInstances), `"disabled_model_ids":[]`) {
		t.Fatalf("disabled model IDs did not encode as an array: %s", encodedInstances)
	}
	credentialViews, errCredentials := queries.ListCredentials(ctx, instance.ID)
	if errCredentials != nil {
		t.Fatalf("list credential views: %v", errCredentials)
	}
	if len(credentialViews) != 1 || credentialViews[0].ID != credential.ID || credentialViews[0].Label != "Safe Label" {
		t.Fatalf("credential views = %+v", credentialViews)
	}
	encodedViews, errEncode := json.Marshal(credentialViews)
	if errEncode != nil {
		t.Fatalf("encode credential views: %v", errEncode)
	}
	// encodedText is checked as an external caller would observe the management response.
	// encodedText 按外部调用方可观察的管理响应进行检查。
	encodedText := strings.ToLower(string(encodedViews))
	for _, forbidden := range []string{"secret_ref", "sensitive-secret", "sensitive-principal", "sensitive-fingerprint", "principal_key", "fingerprint"} {
		if strings.Contains(encodedText, forbidden) {
			t.Fatalf("credential query leaked %q in %s", forbidden, encodedViews)
		}
	}
	endpointViews, errEndpoints := queries.ListEndpoints(ctx, instance.ID)
	if errEndpoints != nil || len(endpointViews) != 1 || endpointViews[0].ID != endpoint.ID {
		t.Fatalf("endpoint views = %+v, error = %v", endpointViews, errEndpoints)
	}
	bindingViews, errBindings := queries.ListBindings(ctx, instance.ID)
	if errBindings != nil || len(bindingViews) != 1 || bindingViews[0].CredentialID != credential.ID {
		t.Fatalf("binding views = %+v, error = %v", bindingViews, errBindings)
	}
}

// TestListProviderGroupsReturnsExactKimiVariants verifies grouped discovery preserves definition boundaries and stable ordering.
// TestListProviderGroupsReturnsExactKimiVariants 验证分组发现保留定义边界和稳定排序。
func TestListProviderGroupsReturnsExactKimiVariants(t *testing.T) {
	protocols := providerconfig.NewProtocolRegistry()
	if errProfiles := bootstrap.RegisterProtocolProfiles(protocols); errProfiles != nil {
		t.Fatalf("RegisterProtocolProfiles() error = %v", errProfiles)
	}
	systems, errSystems := providerconfig.NewSystemRegistry(protocols)
	if errSystems != nil {
		t.Fatalf("NewSystemRegistry() error = %v", errSystems)
	}
	if errProviders := bootstrap.RegisterSystemProviders(systems); errProviders != nil {
		t.Fatalf("RegisterSystemProviders() error = %v", errProviders)
	}
	configurations, errConfigurations := providerconfig.NewMemoryStore(protocols, systems)
	if errConfigurations != nil {
		t.Fatalf("NewMemoryStore() error = %v", errConfigurations)
	}
	queries, errQueries := NewQueryService(configurations, catalog.NewMemoryStore())
	if errQueries != nil {
		t.Fatalf("NewQueryService() error = %v", errQueries)
	}
	groups, errGroups := queries.ListProviderGroups(context.Background())
	if errGroups != nil {
		t.Fatalf("ListProviderGroups() error = %v", errGroups)
	}
	if len(groups) != 9 || groups[0].ID != bootstrap.KimiGroupID || len(groups[0].ProviderDefinitions) != 3 || groups[5].ID != bootstrap.AlibabaGroupID || len(groups[5].ProviderDefinitions) != 8 || groups[6].ID != bootstrap.OpenRouterGroupID || groups[7].ID != bootstrap.MiniMaxGroupID || groups[8].ID != bootstrap.TavilyGroupID {
		t.Fatalf("groups = %#v", groups)
	}
	variants := groups[0].ProviderDefinitions
	if variants[0].VariantName != "CN" || variants[1].VariantName != "Global" || variants[2].VariantName != "Coding Plan" {
		t.Fatalf("variants = %#v", variants)
	}
	if variants[0].ModelCatalogID != variants[1].ModelCatalogID || variants[2].ModelCatalogID == variants[0].ModelCatalogID {
		t.Fatalf("catalog ownership = %#v", variants)
	}
}

// TestCapabilityViewPreservesTokenRecommendations verifies management projections distinguish recommended defaults from hard limits.
// TestCapabilityViewPreservesTokenRecommendations 验证管理投影将推荐默认值与硬上限严格区分。
func TestCapabilityViewPreservesTokenRecommendations(t *testing.T) {
	capabilities := catalog.ModelCapabilities{
		Tokens: catalog.TokenLimits{
			MaxOutputTokens:    catalog.OptionalTokenLimit{Known: true, Value: 16_384},
			MaxReasoningTokens: catalog.OptionalTokenLimit{Known: true, Value: 8_192},
		},
		Recommendations: catalog.TokenRecommendations{
			OutputTokens:    catalog.OptionalTokenLimit{Known: true, Value: 4_096},
			ReasoningTokens: catalog.OptionalTokenLimit{Known: true, Value: 1_024},
		},
		Delivery: catalog.DeliveryCapabilities{Synchronous: true},
		Embedding: &catalog.EmbeddingCapabilities{
			InputTasks: []vcp.EmbeddingInputTask{vcp.EmbeddingTaskQuery}, OutputKinds: []vcp.EmbeddingVectorKind{vcp.EmbeddingVectorDense}, Encodings: []vcp.EmbeddingEncoding{vcp.EmbeddingEncodingFloat}, Dimensions: []int{1024},
		},
		UsageMetrics: []catalog.UsageMetricCapability{{Unit: catalog.UsageUnitEmbeddingInputs, Accuracy: catalog.UsageExact}},
	}
	view := capabilityView(capabilities)
	if !view.MaxOutputTokens.Known || view.MaxOutputTokens.Value != 16_384 || !view.MaxReasoningTokens.Known || view.MaxReasoningTokens.Value != 8_192 || !view.RecommendedOutputTokens.Known || view.RecommendedOutputTokens.Value != 4_096 || !view.RecommendedReasoningTokens.Known || view.RecommendedReasoningTokens.Value != 1_024 || view.Embedding == nil || len(view.Embedding.Dimensions) != 1 || view.Embedding.Dimensions[0] != 1024 || len(view.UsageMetrics) != 1 {
		t.Fatalf("capability view = %#v", view)
	}
}

// TestCatalogViewPreservesAllowanceWindowSemantics verifies reset context and local credential labels without upstream scope identity.
// TestCatalogViewPreservesAllowanceWindowSemantics 验证重置上下文与本地凭据名称且不暴露上游作用域身份。
func TestCatalogViewPreservesAllowanceWindowSemantics(t *testing.T) {
	// resetAt fixes the provider-reported recovery boundary serialized to management clients.
	// resetAt 固定序列化给管理客户端的供应商报告恢复边界。
	resetAt := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	// rollingDuration exceeds JavaScript's safe integer range and proves the HTTP boundary remains exact.
	// rollingDuration 超过 JavaScript 安全整数范围，用于证明 HTTP 边界仍保持精确。
	rollingDuration := 365 * 24 * time.Hour
	// snapshot contains calendar and rolling allowance nodes needed to verify the identity-safe projection.
	// snapshot 包含验证身份安全投影所需的日历与滚动额度节点。
	snapshot := catalog.Snapshot{
		ProviderInstanceID: "pvi_window_projection",
		Allowances: []catalog.AllowanceSnapshot{
			{
				Kind:    catalog.AllowanceWindowQuota,
				Scope:   catalog.ScopeCredential,
				ScopeID: "cred_sensitive_scope",
				Window: &catalog.AllowanceWindow{
					Kind:         catalog.WindowCalendar,
					CalendarUnit: "month",
					TimeZone:     "Asia/Shanghai",
					ResetAt:      &resetAt,
				},
			},
			{
				Kind:    catalog.AllowanceWindowQuota,
				Scope:   catalog.ScopeCredential,
				ScopeID: "cred_sensitive_rolling_scope",
				Window: &catalog.AllowanceWindow{
					Kind:     catalog.WindowRolling,
					Duration: rollingDuration,
				},
			},
		},
	}
	// view is the exact DTO returned by management catalog endpoints.
	// view 是管理目录端点返回的精确 DTO。
	view := catalogView(snapshot, nil, nil, []string{"cred_sensitive_scope", "cred_sensitive_rolling_scope"}, map[string]string{"cred_sensitive_scope": "Primary", "cred_sensitive_rolling_scope": "Backup"}, time.Now().UTC())
	if len(view.Allowances) != 2 || view.Allowances[0].Window == nil || view.Allowances[1].Window == nil {
		t.Fatalf("allowance projection = %#v", view.Allowances)
	}
	if view.Allowances[0].Window.TimeZone != "Asia/Shanghai" || view.Allowances[0].Window.CalendarUnit != "month" {
		t.Fatalf("allowance window projection = %#v", view.Allowances[0].Window)
	}
	if view.Allowances[1].Window.Duration != "31536000000000000" {
		t.Fatalf("rolling allowance duration = %q", view.Allowances[1].Window.Duration)
	}
	if view.Allowances[0].CredentialID != "cred_sensitive_scope" || view.Allowances[0].CredentialLabel != "Primary" {
		t.Fatalf("allowance credential projection = %#v", view.Allowances[0])
	}
	// encodedView proves the HTTP JSON contract retains the newly audited node name.
	// encodedView 证明 HTTP JSON 合同保留了本轮审核补齐的节点名称。
	encodedView, errEncode := json.Marshal(view)
	if errEncode != nil {
		t.Fatalf("encode catalog view: %v", errEncode)
	}
	if !strings.Contains(string(encodedView), `"time_zone":"Asia/Shanghai"`) || !strings.Contains(string(encodedView), `"duration":"31536000000000000"`) || !strings.Contains(string(encodedView), `"credential_label":"Primary"`) || strings.Contains(string(encodedView), "scope_id") {
		t.Fatalf("catalog view did not preserve safe window semantics: %s", encodedView)
	}
}

// TestCatalogViewReportsThreeStateModelAuthorization verifies explicit entitlements are not confused with unknown evidence or local policy.
// TestCatalogViewReportsThreeStateModelAuthorization 验证显式权益不会与未知证据或本地策略混淆。
func TestCatalogViewReportsThreeStateModelAuthorization(t *testing.T) {
	// snapshot combines all-bound, explicitly allowed, and explicitly unproven model cases.
	// snapshot 组合全部绑定、显式允许与未获得显式证明的模型场景。
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	snapshot := catalog.Snapshot{
		Models: []catalog.ProviderModel{
			{ID: "model_all_bound", EntitlementMode: catalog.EntitlementAllBoundCredentials},
			{ID: "model_explicit_allowed", EntitlementMode: catalog.EntitlementExplicit},
			{ID: "model_explicit_missing", EntitlementMode: catalog.EntitlementExplicit},
		},
		Entitlements: []catalog.ModelEntitlement{{CredentialID: "cred_allowed", ProviderModelID: "model_explicit_allowed", Availability: catalog.AvailabilityAllowed, ObservedAt: now}},
	}
	// view disables the explicitly allowed model locally to prove the two states remain independent.
	// view 在本地停用显式允许模型，以证明两种状态保持独立。
	view := catalogView(snapshot, []string{"model_explicit_allowed"}, nil, []string{"cred_allowed"}, map[string]string{"cred_allowed": "Primary account"}, now)
	if len(view.Models) != 3 {
		t.Fatalf("model view count = %d, want 3", len(view.Models))
	}
	// modelsByID makes each expected authorization state independent of presentation sorting.
	// modelsByID 使每个预期授权状态不依赖展示排序。
	modelsByID := make(map[string]ModelView, len(view.Models))
	for _, model := range view.Models {
		modelsByID[model.ID] = model
	}
	if modelsByID["model_all_bound"].AuthorizationStatus != catalog.AuthorizationAuthorized || modelsByID["model_explicit_allowed"].AuthorizationStatus != catalog.AuthorizationAuthorized || modelsByID["model_explicit_missing"].AuthorizationStatus != catalog.AuthorizationUnknown {
		t.Fatalf("provider authorization projection = %#v", modelsByID)
	}
	if modelsByID["model_explicit_allowed"].Enabled {
		t.Fatal("provider authorization incorrectly overrode local disabled policy")
	}
}

// TestCatalogViewSortsPlansByEveryIdentityField verifies map aggregation cannot randomize equal-code plan names.
// TestCatalogViewSortsPlansByEveryIdentityField 验证 map 聚合不会随机排列代码相同但名称不同的套餐。
func TestCatalogViewSortsPlansByEveryIdentityField(t *testing.T) {
	// snapshot contains equal-code plans whose names and statuses exercise the complete deterministic order.
	// snapshot 包含代码相同的套餐，其名称与状态用于覆盖完整确定性顺序。
	snapshot := catalog.Snapshot{Plans: []catalog.PlanSnapshot{
		{PlanCode: "pro", PlanName: "Zulu", Status: "active"},
		{PlanCode: "pro", PlanName: "Alpha", Status: "inactive"},
		{PlanCode: "pro", PlanName: "Alpha", Status: "active"},
	}}
	// plans is the redacted and aggregated management projection under test.
	// plans 是待测的脱敏聚合管理投影。
	plans := catalogView(snapshot, nil, nil, nil, nil, time.Now().UTC()).Plans
	if len(plans) != 3 {
		t.Fatalf("plan view count = %d, want 3", len(plans))
	}
	if plans[0].PlanName != "Alpha" || plans[0].Status != "active" || plans[1].PlanName != "Alpha" || plans[1].Status != "inactive" || plans[2].PlanName != "Zulu" {
		t.Fatalf("plan ordering = %#v", plans)
	}
}
