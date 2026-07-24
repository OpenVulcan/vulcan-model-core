package management

import (
	"bytes"
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

// TestAllowanceViewFromPreservesProviderPresentationWindow verifies management output retains MiniMax period and boost facts.
// TestAllowanceViewFromPreservesProviderPresentationWindow 验证管理输出保留 MiniMax 周期与展示倍率事实。
func TestAllowanceViewFromPreservesProviderPresentationWindow(t *testing.T) {
	startAt := time.Date(2026, time.July, 19, 0, 0, 0, 0, time.UTC)
	resetAt := time.Date(2026, time.July, 26, 0, 0, 0, 0, time.UTC)
	multiplier := int64(1500)
	view := allowanceViewFrom(catalog.AllowanceSnapshot{DisplayMultiplierPermille: &multiplier, Window: &catalog.AllowanceWindow{Kind: catalog.WindowCalendar, CalendarUnit: "week", StartAt: &startAt, ResetAt: &resetAt}}, nil)
	if view.DisplayMultiplierPermille == nil || *view.DisplayMultiplierPermille != multiplier || view.Window == nil || view.Window.StartAt == nil || !view.Window.StartAt.Equal(startAt) || view.Window.ResetAt == nil || !view.Window.ResetAt.Equal(resetAt) {
		t.Fatalf("allowance view = %#v", view)
	}
}

// TestModelAuthorizationStatusUsesProfileEntitlements verifies a public catalog model is not called authorized until one exact published profile is entitled.
// TestModelAuthorizationStatusUsesProfileEntitlements 验证公开目录模型只有在精确已发布规格获得授权后才会被标记为已授权。
func TestModelAuthorizationStatusUsesProfileEntitlements(t *testing.T) {
	now := time.Date(2026, time.July, 23, 0, 0, 0, 0, time.UTC)
	model := catalog.ProviderModel{ID: "model_qwen", EntitlementMode: catalog.EntitlementAllBoundCredentials}
	compatibleProfile := catalog.ExecutionProfile{ID: "profile_chat", RequiredEntitlementClasses: []string{"api_key_models_endpoint"}}
	if got := modelAuthorizationStatus(model, []catalog.ExecutionProfile{compatibleProfile}, nil, []string{"cred_api"}, now); got != catalog.AuthorizationUnknown {
		t.Fatalf("modelAuthorizationStatus() = %q, want unknown before /models evidence", got)
	}
	entitlement := catalog.ModelEntitlement{
		ID: "entitlement_chat", ProviderModelID: model.ID, CredentialID: "cred_api", Availability: catalog.AvailabilityAllowed,
		EntitlementClass: "api_key_models_endpoint", AllowedProfileIDs: []string{compatibleProfile.ID}, ObservedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute),
	}
	if got := modelAuthorizationStatus(model, []catalog.ExecutionProfile{compatibleProfile}, []catalog.ModelEntitlement{entitlement}, []string{"cred_api"}, now); got != catalog.AuthorizationAuthorized {
		t.Fatalf("modelAuthorizationStatus() = %q, want authorized with exact /models evidence", got)
	}
	nativeProfile := catalog.ExecutionProfile{ID: "profile_native"}
	if got := modelAuthorizationStatus(model, []catalog.ExecutionProfile{nativeProfile}, nil, []string{"cred_api"}, now); got != catalog.AuthorizationAuthorized {
		t.Fatalf("modelAuthorizationStatus() = %q, want authorized for product-level native profile", got)
	}
}

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
	// catalogs stores one provider-detected plan so the exact credential management row can expose it safely.
	// catalogs 存储一个供应商自动识别套餐，使精确凭据管理行可以安全暴露该套餐。
	catalogs := catalog.NewMemoryStore()
	observedAt := time.Date(2026, time.July, 22, 4, 0, 0, 0, time.UTC)
	if errSave := catalogs.Save(ctx, catalog.Snapshot{
		ProviderInstanceID: instance.ID,
		Plans: []catalog.PlanSnapshot{{
			ID: "plan_query_researcher", ProviderInstanceID: instance.ID, CredentialID: credential.ID,
			PlanCode: "researcher", PlanName: "Researcher", Status: "active",
			EvidenceSource: catalog.MetadataEvidenceProviderAPI, ObservedAt: observedAt, ExpiresAt: observedAt.Add(time.Hour), Revision: 1,
		}},
		Revision: 1, ObservedAt: observedAt,
	}); errSave != nil {
		t.Fatalf("save detected credential plan: %v", errSave)
	}
	queries, errQueries := NewQueryService(configurations, catalogs)
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
	if len(credentialViews) != 1 || credentialViews[0].ID != credential.ID || credentialViews[0].Label != "Safe Label" || credentialViews[0].DetectedPlan == nil || credentialViews[0].DetectedPlan.PlanName != "Researcher" {
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
	if len(groups) != 9 || groups[0].ID != bootstrap.KimiGroupID || len(groups[0].ProviderDefinitions) != 3 || groups[5].ID != bootstrap.AlibabaGroupID || len(groups[5].ProviderDefinitions) != 7 || groups[6].ID != bootstrap.OpenRouterGroupID || groups[7].ID != bootstrap.MiniMaxGroupID || groups[8].ID != bootstrap.TavilyGroupID {
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
		HostedTools:  []vcp.ToolKind{vcp.ToolNativeWebSearch},
	}
	view := capabilityView(capabilities)
	if !view.MaxOutputTokens.Known || view.MaxOutputTokens.Value != 16_384 || !view.MaxReasoningTokens.Known || view.MaxReasoningTokens.Value != 8_192 || !view.RecommendedOutputTokens.Known || view.RecommendedOutputTokens.Value != 4_096 || !view.RecommendedReasoningTokens.Known || view.RecommendedReasoningTokens.Value != 1_024 || view.Embedding == nil || len(view.Embedding.Dimensions) != 1 || view.Embedding.Dimensions[0] != 1024 || len(view.UsageMetrics) != 1 || len(view.HostedTools) != 1 || view.HostedTools[0] != vcp.ToolNativeWebSearch {
		t.Fatalf("capability view = %#v", view)
	}
}

// TestGetCatalogAuditPreservesOfferingCapabilities verifies the full audit boundary does not discard collected capability classifications or their evidence revision.
// TestGetCatalogAuditPreservesOfferingCapabilities 验证完整审核边界不会丢弃已采集能力分类及其证据修订。
func TestGetCatalogAuditPreservesOfferingCapabilities(t *testing.T) {
	// ctx fixes one complete management read scope.
	// ctx 固定一个完整管理读取作用域。
	ctx := context.Background()
	// commands and configurations share the exact provider ownership graph queried by the audit service.
	// commands 与 configurations 共享审核服务查询的精确供应商所有权图。
	commands, configurations, _ := managementTestService(t)
	instance, errInstance := commands.CreateInstance(ctx, CreateInstanceInput{
		ID: "pvi_catalog_audit_capabilities", DefinitionID: "system_management_test", Handle: "catalog-audit-capabilities", DisplayName: "Catalog Audit Capabilities",
	})
	if errInstance != nil {
		t.Fatalf("create audit provider instance: %v", errInstance)
	}
	// capabilities contain independently testable modality, token, tool, and reasoning classifications.
	// capabilities 包含可独立测试的模态、Token、工具与推理分类。
	capabilities := catalog.ModelCapabilities{
		Tokens:                 catalog.TokenLimits{ContextWindow: catalog.OptionalTokenLimit{Known: true, Value: 131_072}, MaxOutputTokens: catalog.OptionalTokenLimit{Known: true, Value: 8_192}},
		ToolCalling:            catalog.CapabilityNative,
		ParallelToolCalls:      catalog.CapabilityConditional,
		StreamingToolArguments: catalog.CapabilityUnknown,
		StrictJSONSchema:       catalog.CapabilityUnsupported,
		Reasoning:              catalog.CapabilityNative,
		ReasoningEfforts:       []string{"high"},
		InputModalities:        []string{"text", "image"},
		OutputModalities:       []string{"text"},
		Delivery:               catalog.DeliveryCapabilities{Synchronous: true},
	}
	// observedAt anchors every catalog fact in one deterministic snapshot.
	// observedAt 将每项目录事实锚定在同一个确定性快照中。
	observedAt := time.Date(2026, time.July, 23, 6, 0, 0, 0, time.UTC)
	if errSave := commands.catalogs.Save(ctx, catalog.Snapshot{
		ProviderInstanceID: instance.ID,
		Models: []catalog.ProviderModel{{
			ID: "model_catalog_audit", ProviderInstanceID: instance.ID, UpstreamModelID: "audit-model", DisplayName: "Audit Model", Source: catalog.ModelSourceSystem, EntitlementMode: catalog.EntitlementAllBoundCredentials, Revision: 7,
		}},
		Offerings: []catalog.ModelOffering{{
			ID: "offer_catalog_audit", ProviderInstanceID: instance.ID, ProviderModelID: "model_catalog_audit", ChannelID: "openai.chat", UpstreamModelID: "audit-model", Capabilities: capabilities, CapabilityRevision: 7, Revision: 7,
		}},
		Profiles: []catalog.ExecutionProfile{{
			ID: "profile_catalog_audit", ProviderInstanceID: instance.ID, OfferingID: "offer_catalog_audit", DisplayName: "Default", Default: true, Capabilities: capabilities, SwitchPolicy: catalog.ProfileSwitchSeamless, PoolPolicy: catalog.PoolStrictProfile, CapabilityRevision: 7, Revision: 7,
		}},
		Revision: 7, ObservedAt: observedAt,
	}); errSave != nil {
		t.Fatalf("save audit catalog: %v", errSave)
	}
	queries, errQueries := NewQueryService(configurations, commands.catalogs)
	if errQueries != nil {
		t.Fatalf("create audit query service: %v", errQueries)
	}
	audit, errAudit := queries.GetCatalogAudit(ctx, instance.ID)
	if errAudit != nil {
		t.Fatalf("GetCatalogAudit() error = %v", errAudit)
	}
	if len(audit.Offerings) != 1 {
		t.Fatalf("audit offerings = %#v", audit.Offerings)
	}
	offering := audit.Offerings[0]
	if offering.CapabilityRevision != 7 || !offering.Capabilities.ContextWindow.Known || offering.Capabilities.ContextWindow.Value != 131_072 || offering.Capabilities.ToolCalling != catalog.CapabilityNative || offering.Capabilities.Reasoning != catalog.CapabilityNative || len(offering.Capabilities.InputModalities) != 2 {
		t.Fatalf("audit offering capabilities = %#v", offering)
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
		{CredentialID: "cred_zulu", PlanCode: "pro", PlanName: "Zulu", Status: "active"},
		{CredentialID: "cred_alpha_inactive", PlanCode: "pro", PlanName: "Alpha", Status: "inactive"},
		{CredentialID: "cred_alpha_two", PlanCode: "pro", PlanName: "Alpha", Status: "active"},
		{CredentialID: "cred_alpha_one", PlanCode: "pro", PlanName: "Alpha", Status: "active"},
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
	if plans[0].CredentialCount != 2 {
		t.Fatalf("aggregated plan credential count = %#v", plans[0])
	}
}

// TestCatalogViewSerializesEmptyVoiceDescriptionsAsArray verifies a legal empty provider trait list cannot invalidate the management response.
// TestCatalogViewSerializesEmptyVoiceDescriptionsAsArray 验证合法的空供应商特征列表不会使管理响应失效。
func TestCatalogViewSerializesEmptyVoiceDescriptionsAsArray(t *testing.T) {
	// observedAt fixes both voice timestamps so the encoded contract remains deterministic.
	// observedAt 固定两个声音时间戳，使编码合同保持确定性。
	observedAt := time.Date(2026, time.July, 22, 1, 0, 0, 0, time.UTC)
	// snapshot mirrors a MiniMax system voice whose documented description array is empty.
	// snapshot 镜像说明数组为空的 MiniMax 系统声音。
	snapshot := catalog.Snapshot{Voices: []catalog.VoiceSnapshot{{VoiceID: "voice-empty-description", DisplayName: "Voice", CredentialID: "cred_minimax", Descriptions: []string{}, ObservedAt: observedAt, ExpiresAt: observedAt.Add(time.Hour)}}}
	// view is the exact management response projection under test.
	// view 是待测的精确管理响应投影。
	view := catalogView(snapshot, nil, nil, nil, map[string]string{"cred_minimax": "MiniMax"}, observedAt)
	// encoded is the public JSON representation consumed by the management Web application.
	// encoded 是管理 Web 应用消费的公共 JSON 表示。
	encoded, errEncode := json.Marshal(view)
	if errEncode != nil {
		t.Fatalf("marshal catalog view: %v", errEncode)
	}
	if !bytes.Contains(encoded, []byte(`"descriptions":[]`)) || bytes.Contains(encoded, []byte(`"descriptions":null`)) {
		t.Fatalf("empty voice descriptions JSON = %s", encoded)
	}
}
