package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/management"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
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
			ID: "model_test", UpstreamModelID: "test", DisplayName: "Test", EntitlementMode: catalog.EntitlementExplicit,
			Offerings: []management.OfferingView{{ID: "offer_test", ChannelID: "anthropic", UpstreamModelID: "test", Profiles: []management.ExecutionProfileView{
				{ID: "profile_test_256k", DisplayName: "256K", Default: true, Capabilities: management.CapabilityView{ContextWindow: management.TokenLimitView{Known: true, Value: 262144}}},
				{ID: "profile_test_1m", DisplayName: "1M", Capabilities: management.CapabilityView{ContextWindow: management.TokenLimitView{Known: true, Value: 1048576}}},
			}}},
		}},
		Revision: 1,
	}, nil
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

// TestManagementRoutesExposeOnlySafeVulcanViews verifies read-only discovery routing and JSON shape.
// TestManagementRoutesExposeOnlySafeVulcanViews 校验只读发现路由与 JSON 形态。
func TestManagementRoutesExposeOnlySafeVulcanViews(t *testing.T) {
	server, errServer := NewWithManagement(staticCatalog{}, staticManagementQuery{})
	if errServer != nil {
		t.Fatalf("create management server: %v", errServer)
	}
	paths := []string{
		"/vulcan/management/provider-definitions",
		"/vulcan/management/provider-instances",
		"/vulcan/management/provider-instances/pvi_test",
		"/vulcan/catalog/provider-instances/pvi_test",
	}
	for _, path := range paths {
		request := httptest.NewRequest(http.MethodGet, path, nil)
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
}
