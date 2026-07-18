package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/management"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/runtimeconfig"
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

// List returns one custom-provider-selectable protocol profile.
// List 返回一个可供自定义供应商选择的协议 Profile。
func (staticProtocolProfiles) List() []providerconfig.ProtocolProfile {
	return []providerconfig.ProtocolProfile{{
		ID:                 "openai.responses",
		Version:            "1",
		DisplayName:        "OpenAI Responses",
		UserConfigurable:   true,
		RuntimeReady:       true,
		ModelDiscovery:     providerconfig.SupportUnsupported,
		AllowedAuthMethods: []providerconfig.AuthMethodType{providerconfig.AuthMethodAPIKey},
	}}
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
	return management.CatalogView{
		ProviderInstanceID: "pvi_test",
		Models: []management.ModelView{{
			ID: "model_test", UpstreamModelID: "test", DisplayName: "Test", EntitlementMode: catalog.EntitlementExplicit, Enabled: true,
			Offerings: []management.OfferingView{{ID: "offer_test", UpstreamModelID: "test", Profiles: []management.ExecutionProfileView{
				{ID: "profile_test_256k", DisplayName: "256K", Default: true, Capabilities: management.CapabilityView{ContextWindow: management.TokenLimitView{Known: true, Value: 262144}}},
				{ID: "profile_test_1m", DisplayName: "1M", Capabilities: management.CapabilityView{ContextWindow: management.TokenLimitView{Known: true, Value: 1048576}}},
			}}},
		}},
		Revision: 1,
	}, nil
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
		name        string
		providerIDs []string
		wantStatus  int
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
	server, errServer := NewWithControlPlane(staticCatalog{}, ControlPlane{
		Query: staticManagementQuery{}, Commands: staticManagementCommands{}, ModelAccess: staticModelAccessCommands{}, CustomCatalogs: staticCustomCatalogOperations{}, Protocols: staticProtocolProfiles{}, APIKeys: access, Auth: access,
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
	// callRequest proves a management credential cannot authorize the call plane.
	// callRequest 证明管理凭据不能授权调用面。
	callRequest := httptest.NewRequest(http.MethodGet, "/vulcan/v1/models", nil)
	callRequest.Header.Set("Authorization", "Bearer manage-key")
	callRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(callRecorder, callRequest)
	if callRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("management credential call-plane status=%d, want %d", callRecorder.Code, http.StatusUnauthorized)
	}
	callRequest.Header.Set("Authorization", "Bearer call-key")
	callRecorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(callRecorder, callRequest)
	if callRecorder.Code != http.StatusOK {
		t.Fatalf("call-plane status=%d body=%s", callRecorder.Code, callRecorder.Body.String())
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
