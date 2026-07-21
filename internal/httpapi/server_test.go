package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/execution"
	"github.com/OpenVulcan/vulcan-model-core/internal/inputplan"
	"github.com/OpenVulcan/vulcan-model-core/internal/management"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/runtimeconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// staticCatalog provides immutable provider identifiers for HTTP tests.
// staticCatalog 为 HTTP 测试提供不可变的供应商标识。
type staticCatalog struct {
	// providerIDs is the provider snapshot returned to the server.
	// providerIDs 是返回给服务的供应商快照。
	providerIDs []string
}

// staticManagementQuery provides deterministic safe discovery views for HTTP tests.
// staticManagementQuery 为 HTTP 测试提供确定性安全发现视图。
type staticManagementQuery struct{}

// ListProviderGroups returns one Kimi group for authenticated management discovery tests.
// ListProviderGroups 为已认证管理发现测试返回一个 Kimi 分组。
func (staticManagementQuery) ListProviderGroups(context.Context) ([]management.ProviderGroupView, error) {
	return []management.ProviderGroupView{{
		ID: "kimi", DisplayName: "Kimi", ProviderDefinitions: []management.ProviderDefinitionView{
			{ID: "system_kimi_cn", Kind: providerconfig.DefinitionKindSystem, DisplayName: "Kimi CN", GroupID: "kimi", VariantName: "CN", Revision: 1},
		}, Revision: 1,
	}}, nil
}

// staticProtocolProfiles provides immutable protocol metadata for authenticated route tests.
// staticProtocolProfiles 为认证路由测试提供不可变协议元数据。
type staticProtocolProfiles struct{}

// List returns one selectable standard profile and one hidden special profile.
// List 返回一个可选标准 Profile 与一个隐藏特殊 Profile。
func (staticProtocolProfiles) List() []providerconfig.ProtocolProfile {
	return []providerconfig.ProtocolProfile{
		{
			ID: "openai.responses", Version: "1", DisplayName: "OpenAI Responses",
			UserConfigurable: true, CustomDefinitionCompatible: true, RuntimeReady: true,
			ModelDiscovery: providerconfig.SupportUnsupported, AllowedAuthMethods: []providerconfig.AuthMethodType{providerconfig.AuthMethodBearer},
		},
		{
			ID: "google.interactions", Version: "1", DisplayName: "Google Interactions",
			UserConfigurable: false, RuntimeReady: true, ModelDiscovery: providerconfig.SupportUnsupported,
		},
	}
}

// TestHandleProtocolProfilesReturnsOnlySelectableStandardProtocols verifies special native protocols never enter generic-provider selection data.
// TestHandleProtocolProfilesReturnsOnlySelectableStandardProtocols 验证特殊原生协议不会进入通用供应商选择数据。
func TestHandleProtocolProfilesReturnsOnlySelectableStandardProtocols(t *testing.T) {
	server := &Server{control: &ControlPlane{Protocols: staticProtocolProfiles{}}}
	recorder := httptest.NewRecorder()
	server.handleProtocolProfiles(recorder, httptest.NewRequest(http.MethodGet, "/vulcan/manage/protocol-profiles", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	var payload protocolProfileListResponse
	if errDecode := json.NewDecoder(recorder.Body).Decode(&payload); errDecode != nil {
		t.Fatalf("decode response: %v", errDecode)
	}
	if len(payload.ProtocolProfiles) != 1 || payload.ProtocolProfiles[0].ID != "openai.responses" {
		t.Fatalf("protocol profiles = %#v", payload.ProtocolProfiles)
	}
}

// ListDefinitions returns one system provider definition view.
// ListDefinitions 返回一个系统供应商定义视图。
func (staticManagementQuery) ListDefinitions(context.Context) ([]management.ProviderDefinitionView, error) {
	return []management.ProviderDefinitionView{{ID: "system_test", Kind: providerconfig.DefinitionKindSystem, DisplayName: "Test", Revision: 1}}, nil
}

// ListInstances returns one ready provider instance aggregate.
// ListInstances 返回一个 Ready 供应商实例聚合。
func (staticManagementQuery) ListInstances(context.Context) ([]management.ProviderInstanceView, error) {
	return []management.ProviderInstanceView{{ID: "pvi_test", DefinitionID: "system_test", Handle: "test", DisplayName: "Test", Status: providerconfig.LifecycleReady, CredentialCount: 2, Revision: 2}}, nil
}

// GetInstance returns one ready provider instance aggregate.
// GetInstance 返回一个 Ready 供应商实例聚合。
func (staticManagementQuery) GetInstance(context.Context, string) (management.ProviderInstanceView, error) {
	return management.ProviderInstanceView{ID: "pvi_test", DefinitionID: "system_test", Handle: "test", DisplayName: "Test", Status: providerconfig.LifecycleReady, CredentialCount: 2, Revision: 2}, nil
}

// GetCatalog returns one model with two safe execution profiles.
// GetCatalog 返回一个具有两个安全执行规格的模型。
func (staticManagementQuery) GetCatalog(context.Context, string) (management.CatalogView, error) {
	// resetAt fixes the client-visible provider recovery boundary.
	// resetAt 固定客户端可见的供应商恢复边界。
	resetAt := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	return management.CatalogView{
		ProviderInstanceID: "pvi_test",
		Models: []management.ModelView{{
			ID: "model_test", UpstreamModelID: "test", DisplayName: "Test", EntitlementMode: catalog.EntitlementExplicit, Enabled: true, AuthorizationStatus: catalog.AuthorizationAuthorized,
			Offerings: []management.OfferingView{{ID: "offer_test", UpstreamModelID: "test", Profiles: []management.ExecutionProfileView{
				{ID: "profile_test_256k", DisplayName: "256K", Default: true, Capabilities: management.CapabilityView{
					ContextWindow: management.TokenLimitView{Known: true, Value: 262144},
					MediaInputs:   []catalog.MediaInputCapability{{Kind: vcp.MediaImage, Common: catalog.CommonMediaLimits{MaxItemBytes: catalog.OptionalLimit{Known: true, Value: 1024}}}},
				}, Pool: &management.PoolView{ReadyCredentials: 1}},
				{ID: "profile_test_1m", DisplayName: "1M", Capabilities: management.CapabilityView{ContextWindow: management.TokenLimitView{Known: true, Value: 1048576}}, Pool: &management.PoolView{ReadyCredentials: 1}},
			}}},
		}},
		Services: []management.ServiceView{{
			ID: "service_search", DisplayName: "Search", Operation: vcp.OperationSearchWeb, EntitlementMode: catalog.EntitlementAllBoundCredentials, Enabled: true, AuthorizationStatus: catalog.AuthorizationAuthorized,
			Offerings: []management.ServiceOfferingView{{
				ID: "service_offer_search", UpstreamServiceID: "search",
				Capabilities: catalog.ServiceCapabilities{WebSearch: &catalog.WebSearchCapabilities{BackendKind: vcp.SearchBackendDirectAPI, InvocationMode: catalog.SearchInvocationDirectRequest, OutputModes: []vcp.WebSearchOutputMode{vcp.WebSearchOutputResults}}},
				Profiles:     []management.ServiceExecutionProfileView{{ID: "profile_search", DisplayName: "Search", Default: true, Operation: vcp.OperationSearchWeb, ActionBindingID: "action_search", Pool: &management.PoolView{ReadyCredentials: 1}}},
			}},
		}},
		Allowances: []management.AllowanceView{{
			Kind: catalog.AllowanceWindowQuota, Scope: catalog.ScopeCredential, Metric: "monthly_requests", Unit: catalog.UnitRequests, Status: catalog.AllowanceAvailable, Mandatory: true,
			Window:     &management.AllowanceWindowView{Kind: catalog.WindowCalendar, CalendarUnit: "month", TimeZone: "Asia/Shanghai", ResetAt: &resetAt},
			ObservedAt: resetAt.Add(-time.Hour), ExpiresAt: resetAt,
		}},
		Revision: 1,
	}, nil
}

// GetModelContexts returns two exact context profiles with concrete account membership.
// GetModelContexts 返回两个具有具体账号成员关系的精确上下文规格。
func (staticManagementQuery) GetModelContexts(context.Context, string, string) (management.ModelContextsView, error) {
	return management.ModelContextsView{ProviderInstanceID: "pvi_test", ProviderModelID: "model_test", UpstreamModelID: "test", DisplayName: "Test", ContextProfiles: []management.ModelContextProfileView{
		{ID: "profile_test_256k", DisplayName: "256K", Default: true, Capabilities: management.CapabilityView{ContextWindow: management.TokenLimitView{Known: true, Value: 262144}}, Accounts: []management.ModelContextAccountView{{CredentialID: "cred_test", Label: "Primary", CredentialStatus: providerconfig.CredentialActive, RuntimeStatus: resolve.ContextAccountReady, UsageAvailable: true}}},
		{ID: "profile_test_1m", DisplayName: "1M", Capabilities: management.CapabilityView{ContextWindow: management.TokenLimitView{Known: true, Value: 1048576}}, Accounts: []management.ModelContextAccountView{{CredentialID: "cred_test_high", Label: "High", CredentialStatus: providerconfig.CredentialActive, RuntimeStatus: resolve.ContextAccountReady}}},
	}, CatalogRevision: 1, ObservedAt: time.Date(2026, 7, 21, 0, 0, 0, 0, time.UTC)}, nil
}

// GetModelCredentialUsage returns one exact account-scoped usage observation.
// GetModelCredentialUsage 返回一条精确账号作用域用量观测。
func (staticManagementQuery) GetModelCredentialUsage(context.Context, string, string, string) (management.ModelCredentialUsageView, error) {
	remaining := "75"
	return management.ModelCredentialUsageView{ProviderInstanceID: "pvi_test", ProviderModelID: "model_test", CredentialID: "cred_test", CredentialLabel: "Primary", CredentialStatus: providerconfig.CredentialActive, SupportedContextProfileIDs: []string{"profile_test_256k"}, Allowances: []management.ModelUsageAllowanceView{{Usage: management.AllowanceView{Kind: catalog.AllowanceWindowQuota, Scope: catalog.ScopeCredential, Metric: "weekly_usage", Unit: catalog.UnitProviderDefined, Remaining: &remaining, Status: catalog.AllowanceAvailable}, ContextProfileIDs: []string{"profile_test_256k"}}}, CatalogRevision: 1}, nil
}

// ListEndpoints returns no endpoint details for the focused route fixture.
// ListEndpoints 为聚焦路由夹具返回空端点详情。
func (staticManagementQuery) ListEndpoints(context.Context, string) ([]management.EndpointView, error) {
	return []management.EndpointView{}, nil
}

// ListCredentials returns no credential details for the focused route fixture.
// ListCredentials 为聚焦路由夹具返回空凭据详情。
func (staticManagementQuery) ListCredentials(context.Context, string) ([]management.CredentialView, error) {
	return []management.CredentialView{}, nil
}

// ListBindings returns no binding details for the focused route fixture.
// ListBindings 为聚焦路由夹具返回空绑定详情。
func (staticManagementQuery) ListBindings(context.Context, string) ([]management.BindingView, error) {
	return []management.BindingView{}, nil
}

// staticManagementCommands satisfies mutation dependencies while route tests focus on authentication and redaction.
// staticManagementCommands 满足变更依赖，而路由测试聚焦认证和脱敏。
type staticManagementCommands struct{}

// staticMetadataRefresh records the exact provider instance requested by authenticated route tests.
// staticMetadataRefresh 记录认证路由测试请求的精确供应商实例。
type staticMetadataRefresh struct {
	// providerInstanceID is the last exact refresh target.
	// providerInstanceID 是最后一次精确刷新目标。
	providerInstanceID string
}

// Refresh records one explicit refresh request and returns a non-sensitive snapshot identity.
// Refresh 记录一次显式刷新请求并返回不敏感的快照身份。
func (r *staticMetadataRefresh) Refresh(_ context.Context, providerInstanceID string, observedAt time.Time) (catalog.Snapshot, error) {
	r.providerInstanceID = providerInstanceID
	return catalog.Snapshot{ProviderInstanceID: providerInstanceID, Revision: 1, ObservedAt: observedAt}, nil
}

// OnboardSystemProvider returns an empty onboarding result for route-table tests.
// OnboardSystemProvider 为路由表测试返回空录入结果。
func (staticManagementCommands) OnboardSystemProvider(context.Context, management.OnboardSystemProviderInput) (providerconfig.SystemOnboarding, error) {
	return providerconfig.SystemOnboarding{}, nil
}

// OnboardKimiDeviceProvider returns an empty onboarding result for route-table tests.
// OnboardKimiDeviceProvider 为路由表测试返回空录入结果。
func (staticManagementCommands) OnboardKimiDeviceProvider(context.Context, management.OnboardSystemProviderInput) (providerconfig.SystemOnboarding, error) {
	return providerconfig.SystemOnboarding{}, nil
}

// OnboardXAIDeviceProvider returns an empty onboarding result for route-table tests.
// OnboardXAIDeviceProvider 为路由表测试返回空录入结果。
func (staticManagementCommands) OnboardXAIDeviceProvider(context.Context, management.OnboardSystemProviderInput) (providerconfig.SystemOnboarding, error) {
	return providerconfig.SystemOnboarding{}, nil
}

// OnboardCodexDeviceProvider returns an empty onboarding result for route-table tests.
// OnboardCodexDeviceProvider 为路由表测试返回空录入结果。
func (staticManagementCommands) OnboardCodexDeviceProvider(context.Context, management.OnboardSystemProviderInput) (providerconfig.SystemOnboarding, error) {
	return providerconfig.SystemOnboarding{}, nil
}

// OnboardCodexOAuthProvider returns an empty onboarding result for route-table tests.
// OnboardCodexOAuthProvider 为路由表测试返回空录入结果。
func (staticManagementCommands) OnboardCodexOAuthProvider(context.Context, management.OnboardSystemProviderInput) (providerconfig.SystemOnboarding, error) {
	return providerconfig.SystemOnboarding{}, nil
}

// OnboardClaudeOAuthProvider returns an empty onboarding result for route-table tests.
// OnboardClaudeOAuthProvider 为路由表测试返回空录入结果。
func (staticManagementCommands) OnboardClaudeOAuthProvider(context.Context, management.OnboardSystemProviderInput) (providerconfig.SystemOnboarding, error) {
	return providerconfig.SystemOnboarding{}, nil
}

// OnboardAntigravityOAuthProvider returns an empty onboarding result for route-table tests.
// OnboardAntigravityOAuthProvider 为路由表测试返回空录入结果。
func (staticManagementCommands) OnboardAntigravityOAuthProvider(context.Context, management.OnboardSystemProviderInput) (providerconfig.SystemOnboarding, error) {
	return providerconfig.SystemOnboarding{}, nil
}

// OnboardVertexServiceAccountProvider satisfies the management command contract for route tests.
// OnboardVertexServiceAccountProvider 为路由测试实现管理命令合同。
func (staticManagementCommands) OnboardVertexServiceAccountProvider(context.Context, management.OnboardSystemProviderInput, string) (providerconfig.SystemOnboarding, error) {
	return providerconfig.SystemOnboarding{}, nil
}

// OnboardCustomProvider reports that the static fixture does not execute custom onboarding flows.
// OnboardCustomProvider 报告静态夹具不执行自定义录入流程。
func (staticManagementCommands) OnboardCustomProvider(context.Context, management.OnboardCustomProviderInput) (management.CustomProviderOnboardingResult, error) {
	return management.CustomProviderOnboardingResult{}, errors.New("static command fixture")
}

// CreateCustomDefinition reports that the static fixture does not execute mutation flows.
// CreateCustomDefinition 报告静态夹具不执行变更流程。
func (staticManagementCommands) CreateCustomDefinition(context.Context, management.CreateCustomDefinitionInput) (providerconfig.ProviderDefinition, error) {
	return providerconfig.ProviderDefinition{}, errors.New("static command fixture")
}

// UpdateCustomDefinition reports that the static fixture does not execute mutation flows.
// UpdateCustomDefinition 报告静态夹具不执行变更流程。
func (staticManagementCommands) UpdateCustomDefinition(context.Context, management.UpdateCustomDefinitionInput) (providerconfig.ProviderDefinition, error) {
	return providerconfig.ProviderDefinition{}, errors.New("static command fixture")
}

// ConfigureProvider reports that the static fixture does not execute provider configuration flows.
// ConfigureProvider 报告静态夹具不执行供应商配置流程。
func (staticManagementCommands) ConfigureProvider(context.Context, management.ConfigureProviderInput) (management.ProviderConfigurationResult, error) {
	return management.ProviderConfigurationResult{}, errors.New("static command fixture")
}

// DeleteProviderConfiguration reports that the static fixture does not execute provider deletion flows.
// DeleteProviderConfiguration 报告静态夹具不执行供应商删除流程。
func (staticManagementCommands) DeleteProviderConfiguration(context.Context, string) error {
	return errors.New("static command fixture")
}

// DiscoverCustomProviderModels reports that the static fixture does not execute custom discovery flows.
// DiscoverCustomProviderModels 报告静态夹具不执行自定义发现流程。
func (staticManagementCommands) DiscoverCustomProviderModels(context.Context, string, string) (catalog.Snapshot, error) {
	return catalog.Snapshot{}, errors.New("static command fixture")
}

// SaveCustomProviderModels reports that the static fixture does not execute custom model editing flows.
// SaveCustomProviderModels 报告静态夹具不执行自定义模型编辑流程。
func (staticManagementCommands) SaveCustomProviderModels(context.Context, string, []management.InitialProviderModelInput) (catalog.Snapshot, error) {
	return catalog.Snapshot{}, errors.New("static command fixture")
}

// SaveCustomProviderAdditionalParameters reports that the static fixture does not execute provider parameter editing flows.
// SaveCustomProviderAdditionalParameters 报告静态夹具不执行供应商参数编辑流程。
func (staticManagementCommands) SaveCustomProviderAdditionalParameters(context.Context, string, catalog.AdditionalPayloadProjection) (catalog.Snapshot, error) {
	return catalog.Snapshot{}, errors.New("static command fixture")
}

// CreateInstance reports that the static fixture does not execute mutation flows.
// CreateInstance 报告静态夹具不执行变更流程。
func (staticManagementCommands) CreateInstance(context.Context, management.CreateInstanceInput) (providerconfig.ProviderInstance, error) {
	return providerconfig.ProviderInstance{}, errors.New("static command fixture")
}

// UpdateInstance reports that the static fixture does not execute mutation flows.
// UpdateInstance 报告静态夹具不执行变更流程。
func (staticManagementCommands) UpdateInstance(context.Context, management.UpdateInstanceInput) (providerconfig.ProviderInstance, error) {
	return providerconfig.ProviderInstance{}, errors.New("static command fixture")
}

// SetInstanceEnabled reports that the static fixture does not execute mutation flows.
// SetInstanceEnabled 报告静态夹具不执行变更流程。
func (staticManagementCommands) SetInstanceEnabled(context.Context, string, bool) (providerconfig.ProviderInstance, error) {
	return providerconfig.ProviderInstance{}, errors.New("static command fixture")
}

// AddEndpoint reports that the static fixture does not execute mutation flows.
// AddEndpoint 报告静态夹具不执行变更流程。
func (staticManagementCommands) AddEndpoint(context.Context, management.AddEndpointInput) (providerconfig.Endpoint, error) {
	return providerconfig.Endpoint{}, errors.New("static command fixture")
}

// UpdateEndpoint reports that the static fixture does not execute mutation flows.
// UpdateEndpoint 报告静态夹具不执行变更流程。
func (staticManagementCommands) UpdateEndpoint(context.Context, management.UpdateEndpointInput) (providerconfig.Endpoint, error) {
	return providerconfig.Endpoint{}, errors.New("static command fixture")
}

// AddCredential reports that the static fixture does not execute mutation flows.
// AddCredential 报告静态夹具不执行变更流程。
func (staticManagementCommands) AddCredential(context.Context, management.AddCredentialInput) (providerconfig.Credential, error) {
	return providerconfig.Credential{}, errors.New("static command fixture")
}

// AttachCredential reports that the static fixture does not execute attachment flows.
// AttachCredential 报告静态夹具不执行凭据附加流程。
func (staticManagementCommands) AttachCredential(context.Context, management.AddCredentialInput) (management.CredentialAttachment, error) {
	return management.CredentialAttachment{}, errors.New("static command fixture")
}

// AttachAcquiredCredential reports that the static fixture does not execute provider-owned attachment flows.
// AttachAcquiredCredential 报告静态夹具不执行供应商拥有的凭据附加流程。
func (staticManagementCommands) AttachAcquiredCredential(context.Context, management.AttachAcquiredCredentialInput) (management.CredentialAttachment, error) {
	return management.CredentialAttachment{}, errors.New("static command fixture")
}

// UpdateCredential reports that the static fixture does not execute mutation flows.
// UpdateCredential 报告静态夹具不执行变更流程。
func (staticManagementCommands) UpdateCredential(context.Context, management.UpdateCredentialInput) (providerconfig.Credential, error) {
	return providerconfig.Credential{}, errors.New("static command fixture")
}

// RotateCredentialSecret reports that the static fixture does not execute mutation flows.
// RotateCredentialSecret 报告静态夹具不执行变更流程。
func (staticManagementCommands) RotateCredentialSecret(context.Context, management.RotateCredentialSecretInput) (providerconfig.Credential, error) {
	return providerconfig.Credential{}, errors.New("static command fixture")
}

// ReauthorizeCredential reports that the static fixture does not execute mutation flows.
// ReauthorizeCredential 报告静态夹具不执行变更流程。
func (staticManagementCommands) ReauthorizeCredential(context.Context, management.ReauthorizeCredentialInput) (providerconfig.Credential, error) {
	return providerconfig.Credential{}, errors.New("static command fixture")
}

// DeleteCredential reports that the static fixture does not execute mutation flows.
// DeleteCredential 报告静态夹具不执行变更流程。
func (staticManagementCommands) DeleteCredential(context.Context, string, string) (providerconfig.CredentialDeletion, error) {
	return providerconfig.CredentialDeletion{}, errors.New("static command fixture")
}

// SetCredentialStatus reports that the static fixture does not execute mutation flows.
// SetCredentialStatus 报告静态夹具不执行变更流程。
func (staticManagementCommands) SetCredentialStatus(context.Context, management.SetCredentialStatusInput) (providerconfig.Credential, error) {
	return providerconfig.Credential{}, errors.New("static command fixture")
}

// AddBinding reports that the static fixture does not execute mutation flows.
// AddBinding 报告静态夹具不执行变更流程。
func (staticManagementCommands) AddBinding(context.Context, management.AddBindingInput) (providerconfig.AccessBinding, error) {
	return providerconfig.AccessBinding{}, errors.New("static command fixture")
}

// UpdateBinding reports that the static fixture does not execute mutation flows.
// UpdateBinding 报告静态夹具不执行变更流程。
func (staticManagementCommands) UpdateBinding(context.Context, management.UpdateBindingInput) (providerconfig.AccessBinding, error) {
	return providerconfig.AccessBinding{}, errors.New("static command fixture")
}

// staticModelAccessCommands satisfies model policy dependencies for static HTTP route tests.
// staticModelAccessCommands 为静态 HTTP 路由测试满足模型策略依赖。
type staticModelAccessCommands struct{}

// SetModelEnabled reports that the static fixture does not execute mutation flows.
// SetModelEnabled 报告静态夹具不执行变更流程。
func (staticModelAccessCommands) SetModelEnabled(context.Context, management.SetModelEnabledInput) (providerconfig.ProviderInstance, error) {
	return providerconfig.ProviderInstance{}, errors.New("static model access fixture")
}

// staticCustomCatalogOperations satisfies custom catalog dependencies for static HTTP route tests.
// staticCustomCatalogOperations 为静态 HTTP 路由测试满足自定义目录依赖。
type staticCustomCatalogOperations struct{}

// GetCustomCatalog returns an empty deterministic editable catalog fixture.
// GetCustomCatalog 返回一个空的确定性可编辑目录夹具。
func (staticCustomCatalogOperations) GetCustomCatalog(context.Context, string) (catalog.Snapshot, error) {
	return catalog.Snapshot{ProviderInstanceID: "pvi_test", Revision: 1}, nil
}

// SaveCustomCatalog reports that the static fixture does not execute mutation flows.
// SaveCustomCatalog 报告静态夹具不执行变更流程。
func (staticCustomCatalogOperations) SaveCustomCatalog(context.Context, management.SaveCustomCatalogInput) (catalog.Snapshot, error) {
	return catalog.Snapshot{}, errors.New("static custom catalog fixture")
}

// staticControlAccess provides deterministic distinct management and call-plane credentials.
// staticControlAccess 提供确定性的独立管理和调用面凭据。
type staticControlAccess struct{}

// staticExecutionAccess provides an inert durable execution dependency for unrelated route tests.
// staticExecutionAccess 为无关路由测试提供一个惰性持久化执行依赖。
type staticExecutionAccess struct{}

// Create reports that the inert fixture does not execute provider calls.
// Create 报告惰性夹具不执行供应商调用。
func (staticExecutionAccess) Create(context.Context, string, vcp.ExecutionRequest) (execution.Record, bool, error) {
	return execution.Record{}, false, execution.ErrInvalidExecution
}

// Get reports no owner-scoped execution.
// Get 报告不存在所有者作用域执行。
func (staticExecutionAccess) Get(context.Context, string, string) (execution.Record, error) {
	return execution.Record{}, execution.ErrExecutionNotFound
}

// Events reports no owner-scoped execution event log.
// Events 报告不存在所有者作用域执行事件日志。
func (staticExecutionAccess) Events(context.Context, string, string, uint64) ([]execution.Event, error) {
	return nil, execution.ErrExecutionNotFound
}

// Cancel reports no owner-scoped execution.
// Cancel 报告不存在所有者作用域执行。
func (staticExecutionAccess) Cancel(context.Context, string, string) (execution.Record, error) {
	return execution.Record{}, execution.ErrExecutionNotFound
}

// AuthenticateManagementKey accepts only the management fixture key.
// AuthenticateManagementKey 仅接受管理夹具密钥。
func (staticControlAccess) AuthenticateManagementKey(value string) bool {
	return value == "manage-key"
}

// AuthenticateAPIKey accepts only the call-plane fixture key.
// AuthenticateAPIKey 仅接受调用面夹具密钥。
func (staticControlAccess) AuthenticateAPIKey(value string) bool {
	return value == "call-key"
}

// AuthenticateAPIKeyID returns the deterministic non-secret owner identifier for the call fixture.
// AuthenticateAPIKeyID 为调用夹具返回确定性的非秘密所有者标识。
func (staticControlAccess) AuthenticateAPIKeyID(value string) (string, bool) {
	if value != "call-key" {
		return "", false
	}
	return "api_test", true
}

// MaximumObjectBytes returns a deterministic resource request ceiling.
// MaximumObjectBytes 返回确定性资源请求上限。
func (staticControlAccess) MaximumObjectBytes() int64 { return 1 << 20 }

// Create reports that static route fixtures do not ingest content.
// Create 报告静态路由夹具不接收内容。
func (staticControlAccess) Create(context.Context, resource.CreateInput) (resource.Resource, error) {
	return resource.Resource{}, errors.New("static resource fixture")
}

// ImportURL reports that static route fixtures do not perform network imports.
// ImportURL 报告静态路由夹具不执行网络导入。
func (staticControlAccess) ImportURL(context.Context, resource.URLImportInput) (resource.Resource, error) {
	return resource.Resource{}, errors.New("static resource fixture")
}

// ImportBase64 reports that static route fixtures do not perform Base64 imports.
// ImportBase64 报告静态路由夹具不执行 Base64 导入。
func (staticControlAccess) ImportBase64(context.Context, resource.Base64ImportInput) (resource.Resource, error) {
	return resource.Resource{}, errors.New("static resource fixture")
}

// Get reports that static route fixtures contain no resources.
// Get 报告静态路由夹具不包含资源。
func (staticControlAccess) Get(context.Context, string, string) (resource.Resource, error) {
	return resource.Resource{}, resource.ErrResourceNotFound
}

// OpenContent reports that static route fixtures contain no resource content.
// OpenContent 报告静态路由夹具不包含资源正文。
func (staticControlAccess) OpenContent(context.Context, string, string) (resource.Resource, io.ReadCloser, error) {
	return resource.Resource{}, nil, resource.ErrResourceNotFound
}

// Delete reports that static route fixtures contain no resources.
// Delete 报告静态路由夹具不包含资源。
func (staticControlAccess) Delete(context.Context, string, string) error {
	return resource.ErrResourceNotFound
}

// Create reports that static route fixtures do not resolve input plans.
// Create 报告静态路由夹具不解析输入方案。
func (staticControlAccess) CreateInputPlan(context.Context, inputplan.Request) (inputplan.Plan, error) {
	return inputplan.Plan{}, errors.New("static input plan fixture")
}

// Resolve returns one deterministic exact target for discovery route fixtures.
// Resolve 为发现路由夹具返回一个确定性精确 Target。
func (staticControlAccess) Resolve(_ context.Context, request resolve.Request) (resolve.Target, resolve.Diagnostics, error) {
	return resolve.Target{ProviderInstanceID: request.ProviderInstanceID, ProviderModelID: request.ProviderModelID, ProviderServiceID: request.ProviderServiceID, ServiceOfferingID: request.ServiceOfferingID, ExecutionProfileID: request.ExecutionProfileID, Operation: request.Operation}, resolve.Diagnostics{ReadyCandidates: 1}, nil
}

// ListAPIKeys returns one management-visible fixture API key.
// ListAPIKeys 返回一个管理面可见夹具 API 密钥。
func (staticControlAccess) ListAPIKeys() []runtimeconfig.APIKey {
	return []runtimeconfig.APIKey{{ID: "api_test", Name: "Test", Key: "call-key", Enabled: true}}
}

// CreateAPIKey returns one deterministic fixture API key.
// CreateAPIKey 返回一个确定性夹具 API 密钥。
func (staticControlAccess) CreateAPIKey(input runtimeconfig.APIKeyInput) (runtimeconfig.APIKey, error) {
	return runtimeconfig.APIKey{ID: "api_created", Name: input.Name, Key: input.Key, Enabled: input.Enabled}, nil
}

// UpdateAPIKey returns one deterministic replacement fixture API key.
// UpdateAPIKey 返回一个确定性替换夹具 API 密钥。
func (staticControlAccess) UpdateAPIKey(identifier string, input runtimeconfig.APIKeyInput) (runtimeconfig.APIKey, error) {
	return runtimeconfig.APIKey{ID: identifier, Name: input.Name, Key: input.Key, Enabled: input.Enabled}, nil
}

// DeleteAPIKey accepts the deterministic fixture key identifier only.
// DeleteAPIKey 仅接受确定性夹具密钥标识。
func (staticControlAccess) DeleteAPIKey(identifier string) error {
	if identifier != "api_test" {
		return runtimeconfig.ErrAPIKeyNotFound
	}
	return nil
}

// ProviderIDs returns an isolated provider identifier snapshot.
// ProviderIDs 返回隔离后的供应商标识快照。
func (c staticCatalog) ProviderIDs() []string {
	return append([]string(nil), c.providerIDs...)
}

// TestHealthEndpointIsAlwaysLive verifies process liveness semantics.
// TestHealthEndpointIsAlwaysLive 验证进程存活语义。
func TestHealthEndpointIsAlwaysLive(t *testing.T) {
	// server has no providers but must still report process liveness.
	// server 没有供应商但仍必须报告进程存活。
	server, errServer := New(staticCatalog{})
	if errServer != nil {
		t.Fatalf("create server: %v", errServer)
	}
	// request targets the liveness endpoint.
	// request 指向存活端点。
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	// recorder captures the HTTP response.
	// recorder 捕获 HTTP 响应。
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
}

// TestReadyEndpointRequiresProvider verifies executable readiness semantics.
// TestReadyEndpointRequiresProvider 验证可执行就绪语义。
func TestReadyEndpointRequiresProvider(t *testing.T) {
	// cases cover empty and executable provider catalogs.
	// cases 覆盖空目录和可执行供应商目录。
	cases := []struct {
		// name labels the isolated readiness case.
		// name 标记隔离的就绪检查用例。
		name string
		// providerIDs supplies the executable provider snapshot.
		// providerIDs 提供可执行供应商快照。
		providerIDs []string
		// wantStatus is the expected readiness HTTP status.
		// wantStatus 是预期的就绪 HTTP 状态。
		wantStatus int
	}{
		{name: "empty", wantStatus: http.StatusServiceUnavailable},
		{name: "registered", providerIDs: []string{"anthropic"}, wantStatus: http.StatusOK},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			// server uses the provider snapshot defined by the test case.
			// server 使用测试用例定义的供应商快照。
			server, errServer := New(staticCatalog{providerIDs: testCase.providerIDs})
			if errServer != nil {
				t.Fatalf("create server: %v", errServer)
			}
			// request targets the readiness endpoint.
			// request 指向就绪端点。
			request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
			// recorder captures the HTTP response.
			// recorder 捕获 HTTP 响应。
			recorder := httptest.NewRecorder()
			server.Handler().ServeHTTP(recorder, request)
			if recorder.Code != testCase.wantStatus {
				t.Fatalf("status = %d, want %d", recorder.Code, testCase.wantStatus)
			}
		})
	}
}

// TestServerConstructionRejectsTypedNilDependencies verifies dependency interfaces cannot defer nil panics into request handling.
// TestServerConstructionRejectsTypedNilDependencies 验证依赖接口不会把 nil panic 延迟到请求处理阶段。
func TestServerConstructionRejectsTypedNilDependencies(t *testing.T) {
	// nilCatalog is a typed nil that still satisfies ProviderCatalog when stored in an interface.
	// nilCatalog 是存入接口后仍满足 ProviderCatalog 的带类型 nil。
	var nilCatalog *staticCatalog
	if _, errServer := New(nilCatalog); !errors.Is(errServer, ErrProviderCatalogRequired) {
		t.Fatalf("typed nil catalog error = %v, want ErrProviderCatalogRequired", errServer)
	}
	// access supplies both required key-management interfaces for complete control-plane fixtures.
	// access 为完整控制面夹具提供两个必需的密钥管理接口。
	access := staticControlAccess{}
	// nilQuery proves one required interface cannot hide a typed nil pointer.
	// nilQuery 证明必需接口不能隐藏一个带类型 nil 指针。
	var nilQuery *staticManagementQuery
	_, errRequired := NewWithControlPlane(staticCatalog{}, ControlPlane{
		Query: nilQuery, Commands: staticManagementCommands{}, ModelAccess: staticModelAccessCommands{}, CustomCatalogs: staticCustomCatalogOperations{}, Protocols: staticProtocolProfiles{}, APIKeys: access, Auth: access, Resources: access, InputPlans: access, Executions: staticExecutionAccess{}, Targets: access,
	})
	if errRequired == nil {
		t.Fatal("typed nil required control dependency was accepted")
	}
	// nilMetadataRefresh proves an optional typed nil is rejected instead of registering a panic-prone route.
	// nilMetadataRefresh 证明可选的带类型 nil 会被拒绝，而不是注册一个可能 panic 的路由。
	var nilMetadataRefresh *staticMetadataRefresh
	_, errOptional := NewWithControlPlane(staticCatalog{}, ControlPlane{
		Query: staticManagementQuery{}, Commands: staticManagementCommands{}, ModelAccess: staticModelAccessCommands{}, CustomCatalogs: staticCustomCatalogOperations{}, MetadataRefresh: nilMetadataRefresh, Protocols: staticProtocolProfiles{}, APIKeys: access, Auth: access, Resources: access, InputPlans: access, Executions: staticExecutionAccess{}, Targets: access,
	})
	if errOptional == nil {
		t.Fatal("typed nil optional control dependency was accepted")
	}
}

// TestServerDoesNotExposeLegacyProtocolRoutes verifies the Vulcan-only surface.
// TestServerDoesNotExposeLegacyProtocolRoutes 验证仅暴露 Vulcan 接口面。
func TestServerDoesNotExposeLegacyProtocolRoutes(t *testing.T) {
	// server contains only framework routes.
	// server 仅包含框架路由。
	server, errServer := New(staticCatalog{})
	if errServer != nil {
		t.Fatalf("create server: %v", errServer)
	}
	// legacyPaths lists protocol compatibility routes that must remain absent.
	// legacyPaths 列出必须保持缺失的协议兼容路由。
	legacyPaths := []string{
		"/v1/chat/completions",
		"/v1/messages",
		"/v1/responses",
		"/v1beta/models/test:generateContent",
		"/backend-api/codex/responses",
		"/openai/v1/videos",
	}
	for _, legacyPath := range legacyPaths {
		// request probes one forbidden compatibility route.
		// request 探测一个禁止的兼容路由。
		request := httptest.NewRequest(http.MethodPost, legacyPath, nil)
		// recorder captures the route lookup result.
		// recorder 捕获路由查找结果。
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("path %s status = %d, want %d", legacyPath, recorder.Code, http.StatusNotFound)
		}
	}
}

// TestControlPlaneSeparatesManagementAndCallCredentials verifies route-scoped authentication and safe query views.
// TestControlPlaneSeparatesManagementAndCallCredentials 校验路由作用域认证和安全查询视图。
func TestControlPlaneSeparatesManagementAndCallCredentials(t *testing.T) {
	// access owns the same deterministic fixture for management and call-plane interfaces.
	// access 为管理和调用面接口拥有同一确定性夹具。
	access := staticControlAccess{}
	// metadataRefresh records only an authenticated explicit account-data refresh.
	// metadataRefresh 仅记录经过认证的显式账号数据刷新。
	metadataRefresh := &staticMetadataRefresh{}
	server, errServer := NewWithControlPlane(staticCatalog{}, ControlPlane{
		Query: staticManagementQuery{}, Commands: staticManagementCommands{}, ModelAccess: staticModelAccessCommands{}, CustomCatalogs: staticCustomCatalogOperations{}, MetadataRefresh: metadataRefresh, Protocols: staticProtocolProfiles{}, APIKeys: access, Auth: access, Resources: access, InputPlans: access, Executions: staticExecutionAccess{}, Targets: access,
	})
	if errServer != nil {
		t.Fatalf("create control-plane server: %v", errServer)
	}
	managementPaths := []string{
		"/vulcan/manage/protocol-profiles",
		"/vulcan/manage/provider-groups",
		"/vulcan/manage/provider-definitions",
		"/vulcan/manage/provider-instances",
		"/vulcan/manage/provider-instances/pvi_test",
		"/vulcan/manage/provider-instances/pvi_test/catalog",
		"/vulcan/manage/provider-instances/pvi_test/custom-catalog",
		"/vulcan/manage/api-keys",
	}
	for _, path := range managementPaths {
		// missingRequest proves management routes never inherit call-plane or loopback trust.
		// missingRequest 证明管理路由绝不继承调用面或环回信任。
		missingRequest := httptest.NewRequest(http.MethodGet, path, nil)
		missingRecorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(missingRecorder, missingRequest)
		if missingRecorder.Code != http.StatusUnauthorized {
			t.Fatalf("unauthenticated path %s status=%d, want %d", path, missingRecorder.Code, http.StatusUnauthorized)
		}
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Header.Set("Authorization", "Bearer manage-key")
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("path %s status=%d body=%s", path, recorder.Code, recorder.Body.String())
		}
		var payload any
		if errDecode := json.Unmarshal(recorder.Body.Bytes(), &payload); errDecode != nil {
			t.Fatalf("path %s returned invalid JSON: %v", path, errDecode)
		}
		for _, forbidden := range []string{"secret_ref", "fingerprint", "principal_key", "access_token", "refresh_token"} {
			if strings.Contains(strings.ToLower(recorder.Body.String()), forbidden) {
				t.Fatalf("path %s leaked forbidden field %s", path, forbidden)
			}
		}
	}
	// ambiguousManagementRequest proves duplicate Authorization values cannot be interpreted differently by a proxy and the management server.
	// ambiguousManagementRequest 证明重复 Authorization 值不会被代理与管理服务端作出不同解释。
	ambiguousManagementRequest := httptest.NewRequest(http.MethodGet, "/vulcan/manage/provider-groups", nil)
	ambiguousManagementRequest.Header.Add("Authorization", "Bearer manage-key")
	ambiguousManagementRequest.Header.Add("Authorization", "Bearer conflicting-key")
	ambiguousManagementRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(ambiguousManagementRecorder, ambiguousManagementRequest)
	if ambiguousManagementRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("duplicate management authorization status=%d, want %d", ambiguousManagementRecorder.Code, http.StatusUnauthorized)
	}
	// unauthenticatedRefresh proves a state-changing metadata read never inherits loopback trust.
	// unauthenticatedRefresh 证明会触发状态变更的元数据读取绝不继承环回信任。
	unauthenticatedRefresh := httptest.NewRequest(http.MethodPost, "/vulcan/manage/provider-instances/pvi_test/catalog/refresh", nil)
	unauthenticatedRefreshRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(unauthenticatedRefreshRecorder, unauthenticatedRefresh)
	if unauthenticatedRefreshRecorder.Code != http.StatusUnauthorized || metadataRefresh.providerInstanceID != "" {
		t.Fatalf("unauthenticated metadata refresh status=%d target=%q", unauthenticatedRefreshRecorder.Code, metadataRefresh.providerInstanceID)
	}
	// authenticatedRefresh exercises the exact protected refresh route and safe catalog projection.
	// authenticatedRefresh 执行精确受保护刷新路由与安全目录投影。
	authenticatedRefresh := httptest.NewRequest(http.MethodPost, "/vulcan/manage/provider-instances/pvi_test/catalog/refresh", nil)
	authenticatedRefresh.Header.Set("Authorization", "Bearer manage-key")
	authenticatedRefreshRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(authenticatedRefreshRecorder, authenticatedRefresh)
	if authenticatedRefreshRecorder.Code != http.StatusOK || metadataRefresh.providerInstanceID != "pvi_test" {
		t.Fatalf("authenticated metadata refresh status=%d target=%q body=%s", authenticatedRefreshRecorder.Code, metadataRefresh.providerInstanceID, authenticatedRefreshRecorder.Body.String())
	}
	if !strings.Contains(authenticatedRefreshRecorder.Body.String(), `"time_zone":"Asia/Shanghai"`) || strings.Contains(authenticatedRefreshRecorder.Body.String(), "scope_id") {
		t.Fatalf("metadata refresh response lost safe window semantics or leaked scope identity: %s", authenticatedRefreshRecorder.Body.String())
	}
	// callRequest proves a management credential cannot authorize the call plane.
	// callRequest 证明管理凭据不能授权调用面。
	callRequest := httptest.NewRequest(http.MethodPost, "/vulcan/v1/info", strings.NewReader(`{"get":"models"}`))
	callRequest.Header.Set("Authorization", "Bearer manage-key")
	callRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(callRecorder, callRequest)
	if callRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("management credential call-plane status=%d, want %d", callRecorder.Code, http.StatusUnauthorized)
	}
	callRequest = httptest.NewRequest(http.MethodPost, "/vulcan/v1/info", strings.NewReader(`{"get":"models"}`))
	callRequest.Header.Set("Authorization", "Bearer call-key")
	callRecorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(callRecorder, callRequest)
	if callRecorder.Code != http.StatusOK {
		t.Fatalf("call-plane status=%d body=%s", callRecorder.Code, callRecorder.Body.String())
	}
	if !strings.Contains(callRecorder.Body.String(), `"get":"models"`) || !strings.Contains(callRecorder.Body.String(), `"max_item_bytes":{"known":true,"value":1024}`) || strings.Contains(callRecorder.Body.String(), `"MaxItemBytes"`) {
		t.Fatalf("model discovery did not preserve the snake-case capability contract: %s", callRecorder.Body.String())
	}
	// instancesRequest verifies another information shape uses the same authenticated protocol entry.
	// instancesRequest 验证另一种信息形态使用相同的已认证协议入口。
	instancesRequest := httptest.NewRequest(http.MethodPost, "/vulcan/v1/info", strings.NewReader(`{"get":"instances"}`))
	instancesRequest.Header.Set("Authorization", "Bearer call-key")
	instancesRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(instancesRecorder, instancesRequest)
	if instancesRecorder.Code != http.StatusOK || !strings.Contains(instancesRecorder.Body.String(), `"get":"instances"`) || !strings.Contains(instancesRecorder.Body.String(), `"instances"`) {
		t.Fatalf("instances information status=%d body=%s", instancesRecorder.Code, instancesRecorder.Body.String())
	}
	contextRequest := httptest.NewRequest(http.MethodPost, "/vulcan/v1/info", strings.NewReader(`{"get":"accounts","provider_instance_id":"pvi_test","provider_model_id":"model_test"}`))
	contextRequest.Header.Set("Authorization", "Bearer call-key")
	contextRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(contextRecorder, contextRequest)
	if contextRecorder.Code != http.StatusOK || !strings.Contains(contextRecorder.Body.String(), `"context_profiles"`) || !strings.Contains(contextRecorder.Body.String(), `"credential_id":"cred_test"`) || !strings.Contains(contextRecorder.Body.String(), `"runtime_status":"ready"`) {
		t.Fatalf("model contexts status=%d body=%s", contextRecorder.Code, contextRecorder.Body.String())
	}
	usageRequest := httptest.NewRequest(http.MethodPost, "/vulcan/v1/info", strings.NewReader(`{"get":"usage","provider_instance_id":"pvi_test","provider_model_id":"model_test","credential_id":"cred_test"}`))
	usageRequest.Header.Set("Authorization", "Bearer call-key")
	usageRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(usageRecorder, usageRequest)
	if usageRecorder.Code != http.StatusOK || !strings.Contains(usageRecorder.Body.String(), `"metric":"weekly_usage"`) || !strings.Contains(usageRecorder.Body.String(), `"remaining":"75"`) || !strings.Contains(usageRecorder.Body.String(), `"context_profile_ids":["profile_test_256k"]`) {
		t.Fatalf("model account usage status=%d body=%s", usageRecorder.Code, usageRecorder.Body.String())
	}
	serviceRequest := httptest.NewRequest(http.MethodPost, "/vulcan/v1/info", strings.NewReader(`{"get":"services"}`))
	serviceRequest.Header.Set("Authorization", "Bearer call-key")
	serviceRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(serviceRecorder, serviceRequest)
	if serviceRecorder.Code != http.StatusOK || !strings.Contains(serviceRecorder.Body.String(), `"backend_kind":"direct_search_api"`) || strings.Contains(serviceRecorder.Body.String(), `"Models"`) || strings.Contains(serviceRecorder.Body.String(), `"BackendKind"`) {
		t.Fatalf("service discovery status=%d body=%s", serviceRecorder.Code, serviceRecorder.Body.String())
	}
	// ambiguousCallRequest proves the same duplicate-header rejection protects the call plane.
	// ambiguousCallRequest 证明相同的重复请求头拒绝规则也保护调用面。
	ambiguousCallRequest := httptest.NewRequest(http.MethodPost, "/vulcan/v1/info", strings.NewReader(`{"get":"models"}`))
	ambiguousCallRequest.Header.Add("Authorization", "Bearer call-key")
	ambiguousCallRequest.Header.Add("Authorization", "Bearer conflicting-key")
	ambiguousCallRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(ambiguousCallRecorder, ambiguousCallRequest)
	if ambiguousCallRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("duplicate call authorization status=%d, want %d", ambiguousCallRecorder.Code, http.StatusUnauthorized)
	}
	// invalidInformationRequest verifies selectors cannot cross the closed information branches.
	// invalidInformationRequest 验证选择器不能跨越封闭信息分支。
	invalidInformationRequest := httptest.NewRequest(http.MethodPost, "/vulcan/v1/info", strings.NewReader(`{"get":"accounts","provider_instance_id":"pvi_test"}`))
	invalidInformationRequest.Header.Set("Authorization", "Bearer call-key")
	invalidInformationRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(invalidInformationRecorder, invalidInformationRequest)
	if invalidInformationRecorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid information status=%d body=%s", invalidInformationRecorder.Code, invalidInformationRecorder.Body.String())
	}
	// legacyInformationRequest verifies the replaced REST-style discovery route is not retained as an alias.
	// legacyInformationRequest 验证被替换的 REST 风格发现路由不会作为别名保留。
	legacyInformationPaths := []string{
		"/vulcan/v1/models",
		"/vulcan/v1/services",
		"/vulcan/v1/provider-instances/pvi_test/models/model_test/contexts",
		"/vulcan/v1/provider-instances/pvi_test/models/model_test/accounts/cred_test/usage",
	}
	for _, legacyInformationPath := range legacyInformationPaths {
		legacyInformationRequest := httptest.NewRequest(http.MethodGet, legacyInformationPath, nil)
		legacyInformationRequest.Header.Set("Authorization", "Bearer call-key")
		legacyInformationRecorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(legacyInformationRecorder, legacyInformationRequest)
		if legacyInformationRecorder.Code != http.StatusNotFound {
			t.Fatalf("legacy information route %s status=%d, want %d", legacyInformationPath, legacyInformationRecorder.Code, http.StatusNotFound)
		}
	}
	// legacyRequest verifies the old read-only management namespace is not exposed beside the authenticated surface.
	// legacyRequest 验证旧只读管理命名空间不会与认证接口面并存。
	legacyRequest := httptest.NewRequest(http.MethodGet, "/vulcan/management/provider-definitions", nil)
	legacyRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(legacyRecorder, legacyRequest)
	if legacyRecorder.Code != http.StatusNotFound {
		t.Fatalf("legacy management route status=%d, want %d", legacyRecorder.Code, http.StatusNotFound)
	}
}
