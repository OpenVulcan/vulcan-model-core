package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/bootstrap"
	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/management"
	providerkimi "github.com/OpenVulcan/vulcan-model-core/internal/provider/kimi"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/runtimeconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

// TestWriteControlErrorMapsKimiDeviceFlowStates verifies stable non-secret HTTP semantics for every local authorization state.
// TestWriteControlErrorMapsKimiDeviceFlowStates 验证每个本地授权状态具有稳定且不泄密的 HTTP 语义。
func TestWriteControlErrorMapsKimiDeviceFlowStates(t *testing.T) {
	testCases := []struct {
		name       string
		err        error
		statusCode int
		errorCode  string
	}{
		{name: "not found", err: providerkimi.ErrFlowNotFound, statusCode: http.StatusNotFound, errorCode: "device_flow_not_found"},
		{name: "expired", err: providerkimi.ErrAuthorizationExpired, statusCode: http.StatusGone, errorCode: "device_flow_expired"},
		{name: "denied", err: providerkimi.ErrAuthorizationDenied, statusCode: http.StatusForbidden, errorCode: "device_flow_denied"},
		{name: "pending", err: providerkimi.ErrAuthorizationPending, statusCode: http.StatusConflict, errorCode: "device_flow_pending"},
		{name: "bounded", err: providerkimi.ErrFlowLimitReached, statusCode: http.StatusTooManyRequests, errorCode: "device_flow_limit_reached"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			writeControlError(recorder, testCase.err)
			if recorder.Code != testCase.statusCode {
				t.Fatalf("status = %d, want %d", recorder.Code, testCase.statusCode)
			}
			var response errorResponse
			if errDecode := json.NewDecoder(recorder.Body).Decode(&response); errDecode != nil {
				t.Fatalf("decode error response: %v", errDecode)
			}
			if response.Error != testCase.errorCode {
				t.Fatalf("error = %q, want %q", response.Error, testCase.errorCode)
			}
		})
	}
}

// newControlPlaneIntegrationServer creates an authenticated server backed by real control-plane services and isolated test storage.
// newControlPlaneIntegrationServer 创建一个由真实控制面服务和隔离测试存储支撑的认证服务器。
func newControlPlaneIntegrationServer(t *testing.T) *Server {
	return newControlPlaneIntegrationServerWithFlows(t, nil)
}

// newControlPlaneIntegrationServerWithFlows creates the real control plane with an optional deterministic device-flow boundary.
// newControlPlaneIntegrationServerWithFlows 创建具有可选确定性设备授权边界的真实控制面。
func newControlPlaneIntegrationServerWithFlows(t *testing.T, deviceFlows KimiDeviceFlows) *Server {
	t.Helper()
	// protocols owns the exact custom-provider protocol vocabulary used by management commands.
	// protocols 管理控制命令使用的精确自定义供应商协议词汇。
	protocols := providerconfig.NewProtocolRegistry()
	if errRegister := bootstrap.RegisterProtocolProfiles(protocols); errRegister != nil {
		t.Fatalf("register protocol profiles: %v", errRegister)
	}
	// systems owns the same built-in provider definitions used by the production process.
	// systems 管理与生产进程相同的内置供应商定义。
	systems, errSystems := providerconfig.NewSystemRegistry(protocols)
	if errSystems != nil {
		t.Fatalf("create system registry: %v", errSystems)
	}
	if errProviders := bootstrap.RegisterSystemProviders(systems); errProviders != nil {
		t.Fatalf("register system providers: %v", errProviders)
	}
	configurations, errConfigurations := providerconfig.NewMemoryStore(protocols, systems)
	if errConfigurations != nil {
		t.Fatalf("create configuration store: %v", errConfigurations)
	}
	catalogs := catalog.NewMemoryStore()
	queries, errQueries := management.NewQueryService(configurations, catalogs)
	if errQueries != nil {
		t.Fatalf("create management query service: %v", errQueries)
	}
	commands, errCommands := management.NewService(configurations, secret.NewMemoryStore(), catalogs)
	if errCommands != nil {
		t.Fatalf("create management command service: %v", errCommands)
	}
	modelAccess, errModelAccess := management.NewModelAccessService(configurations, catalogs)
	if errModelAccess != nil {
		t.Fatalf("create model access service: %v", errModelAccess)
	}
	// customCatalogs persists complete user-declared model metadata through the same catalog store queried by the control plane.
	// customCatalogs 通过控制面查询使用的同一目录存储持久化完整用户声明模型元数据。
	customCatalogs, errCustomCatalogs := management.NewCustomCatalogService(configurations, catalogs)
	if errCustomCatalogs != nil {
		t.Fatalf("create custom catalog service: %v", errCustomCatalogs)
	}
	// configurationPath stores a deliberately plaintext initial management key so Load verifies automatic bcrypt replacement.
	// configurationPath 存储一个有意明文的初始管理密钥，以便 Load 校验自动 bcrypt 替换。
	configurationPath := filepath.Join(t.TempDir(), "control-plane.yaml")
	if errWrite := os.WriteFile(configurationPath, []byte("management:\n  secret-key: admin-control-key\napi:\n  keys: []\n"), 0o600); errWrite != nil {
		t.Fatalf("write control-plane configuration: %v", errWrite)
	}
	configuration, errConfiguration := runtimeconfig.Load(configurationPath)
	if errConfiguration != nil {
		t.Fatalf("load control-plane configuration: %v", errConfiguration)
	}
	// server exposes the same dependencies the process entry point owns, without opening a network listener.
	// server 暴露与进程入口相同的依赖，但不打开网络监听器。
	server, errServer := NewWithControlPlane(staticCatalog{}, ControlPlane{
		Query:           queries,
		Commands:        commands,
		ModelAccess:     modelAccess,
		CustomCatalogs:  customCatalogs,
		Protocols:       protocols,
		APIKeys:         configuration,
		Auth:            configuration,
		KimiDeviceFlows: deviceFlows,
	})
	if errServer != nil {
		t.Fatalf("create control-plane server: %v", errServer)
	}
	return server
}

// TestSystemProviderOnboardingHTTPCommitsFixedKimiCatalog verifies the authenticated atomic API-key route end to end.
// TestSystemProviderOnboardingHTTPCommitsFixedKimiCatalog 端到端验证经过认证的原子 API Key 路由。
func TestSystemProviderOnboardingHTTPCommitsFixedKimiCatalog(t *testing.T) {
	server := newControlPlaneIntegrationServer(t)
	onboarding := serveControlRequest(server, http.MethodPost, "/vulcan/manage/provider-instances/onboard", "admin-control-key", `{"provider_definition_id":"system_kimi_cn","handle":"kimi-cn-http","display_name":"Kimi CN","auth_method_id":"api_key","credential_label":"Primary","principal_key":"","secret":"private-kimi-key"}`)
	if onboarding.Code != http.StatusCreated || strings.Contains(onboarding.Body.String(), "private-kimi-key") {
		t.Fatalf("onboarding status=%d body=%s", onboarding.Code, onboarding.Body.String())
	}
	var created onboardSystemProviderResponse
	if errDecode := json.Unmarshal(onboarding.Body.Bytes(), &created); errDecode != nil {
		t.Fatalf("decode onboarding response: %v", errDecode)
	}
	if created.ProviderInstanceID == "" || len(created.EndpointIDs) != 1 || len(created.BindingIDs) != 1 {
		t.Fatalf("onboarding response = %#v", created)
	}
	catalogResponse := serveControlRequest(server, http.MethodGet, "/vulcan/manage/provider-instances/"+created.ProviderInstanceID+"/catalog", "admin-control-key", "")
	if catalogResponse.Code != http.StatusOK || !strings.Contains(catalogResponse.Body.String(), "kimi-k2.6") || !strings.Contains(catalogResponse.Body.String(), "moonshot-v1-128k") {
		t.Fatalf("catalog status=%d body=%s", catalogResponse.Code, catalogResponse.Body.String())
	}
	endpoints := serveControlRequest(server, http.MethodGet, "/vulcan/manage/provider-instances/"+created.ProviderInstanceID+"/endpoints", "admin-control-key", "")
	if endpoints.Code != http.StatusOK || !strings.Contains(endpoints.Body.String(), "https://api.moonshot.cn") || strings.Contains(endpoints.Body.String(), "private-kimi-key") {
		t.Fatalf("endpoints status=%d body=%s", endpoints.Code, endpoints.Body.String())
	}
}

// TestSystemProviderOnboardingHTTPRejectsDeviceCredentialInjection verifies device credentials are accepted only through the server-owned flow route.
// TestSystemProviderOnboardingHTTPRejectsDeviceCredentialInjection 验证设备凭据仅能通过服务端拥有的授权流程路由录入。
func TestSystemProviderOnboardingHTTPRejectsDeviceCredentialInjection(t *testing.T) {
	server := newControlPlaneIntegrationServer(t)
	response := serveControlRequest(server, http.MethodPost, "/vulcan/manage/provider-instances/onboard", "admin-control-key", `{"provider_definition_id":"system_kimi_coding_plan","handle":"forged-device-flow","display_name":"Forged Device Flow","auth_method_id":"device_flow","credential_label":"Untrusted","principal_key":"","secret":"vulcan-kimi-token-v1:{\"access_token\":\"forged\"}"}`)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("device credential injection status=%d body=%s", response.Code, response.Body.String())
	}
}

// serveControlRequest sends one JSON management or call-plane request with the selected bearer namespace value.
// serveControlRequest 使用选定 Bearer 命名空间值发送一个 JSON 管理面或调用面请求。
func serveControlRequest(server *Server, method string, path string, bearer string, body string) *httptest.ResponseRecorder {
	// request contains only test fixture data and the route-scoped Authorization header.
	// request 仅包含测试夹具数据和路由作用域 Authorization 头。
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+bearer)
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	// recorder captures the complete response for status and leakage assertions.
	// recorder 捕获完整响应以执行状态和泄露断言。
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	return recorder
}

// customCatalogPayload is one complete valid user-declared catalog document for HTTP integration coverage.
// customCatalogPayload 是用于 HTTP 集成覆盖的一份完整有效用户声明目录文档。
const customCatalogPayload = `{"models":[{"id":"model_control","upstream_model_id":"control-model","display_name":"Control Model"}],"offerings":[{"id":"offer_control","provider_model_id":"model_control","upstream_model_id":"control-model","capabilities":{"context_window":{"known":true,"value":128000},"max_input_tokens":{"known":false},"max_output_tokens":{"known":true,"value":4096},"max_reasoning_tokens":{"known":false},"tool_calling":"native","parallel_tool_calls":"native","streaming_tool_arguments":"unsupported","strict_json_schema":"unknown","reasoning":"unsupported","input_modalities":["text"],"output_modalities":["text"]}}],"profiles":[{"id":"profile_control_default","offering_id":"offer_control","display_name":"Default","default":true,"capabilities":{"context_window":{"known":true,"value":128000},"max_input_tokens":{"known":false},"max_output_tokens":{"known":true,"value":4096},"max_reasoning_tokens":{"known":false},"tool_calling":"native","parallel_tool_calls":"native","streaming_tool_arguments":"unsupported","strict_json_schema":"unknown","reasoning":"unsupported","input_modalities":["text"],"output_modalities":["text"]},"required_entitlement_classes":[],"switch_policy":"seamless","pool_policy":"strict_profile"}]}`

// TestControlPlaneHTTPMutationsKeepSecretsScopedAndCallKeysSeparate verifies real management mutations, redaction, and route-scoped authorization.
// TestControlPlaneHTTPMutationsKeepSecretsScopedAndCallKeysSeparate 验证真实管理变更、脱敏和路由作用域授权。
func TestControlPlaneHTTPMutationsKeepSecretsScopedAndCallKeysSeparate(t *testing.T) {
	// server is a fully wired in-memory control plane without external side effects.
	// server 是没有外部副作用的完整内存控制面。
	server := newControlPlaneIntegrationServer(t)
	// unauthorized proves the call-plane key namespace cannot be inferred from a missing management credential.
	// unauthorized 证明调用面密钥命名空间无法从缺失管理凭据中推断。
	unauthorized := serveControlRequest(server, http.MethodGet, "/vulcan/manage/protocol-profiles", "call-control-key", "")
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("management route with call key status = %d, want %d", unauthorized.Code, http.StatusUnauthorized)
	}
	customCatalogUnauthorized := serveControlRequest(server, http.MethodPut, "/vulcan/manage/provider-instances/pvi_control/custom-catalog", "call-control-key", customCatalogPayload)
	if customCatalogUnauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("custom catalog route with call key status = %d, want %d", customCatalogUnauthorized.Code, http.StatusUnauthorized)
	}
	protocolProfiles := serveControlRequest(server, http.MethodGet, "/vulcan/manage/protocol-profiles", "admin-control-key", "")
	if protocolProfiles.Code != http.StatusOK || !strings.Contains(protocolProfiles.Body.String(), "openai.responses") {
		t.Fatalf("protocol profile list status=%d body=%s", protocolProfiles.Code, protocolProfiles.Body.String())
	}
	definition := serveControlRequest(server, http.MethodPost, "/vulcan/manage/provider-definitions", "admin-control-key", `{"id":"custom_control","display_name":"Control Gateway","protocol_profile_id":"openai.responses","auth_method":"bearer"}`)
	if definition.Code != http.StatusCreated || !strings.Contains(definition.Body.String(), "custom_control") {
		t.Fatalf("create definition status=%d body=%s", definition.Code, definition.Body.String())
	}
	instance := serveControlRequest(server, http.MethodPost, "/vulcan/manage/provider-instances", "admin-control-key", `{"id":"pvi_control","definition_id":"custom_control","handle":"control","display_name":"Control Instance"}`)
	if instance.Code != http.StatusCreated || !strings.Contains(instance.Body.String(), "pvi_control") {
		t.Fatalf("create instance status=%d body=%s", instance.Code, instance.Body.String())
	}
	endpoint := serveControlRequest(server, http.MethodPost, "/vulcan/manage/provider-instances/pvi_control/endpoints", "admin-control-key", `{"id":"ep_control","base_url":"https://control.example/v1","region":"local"}`)
	if endpoint.Code != http.StatusCreated || !strings.Contains(endpoint.Body.String(), "ep_control") {
		t.Fatalf("create endpoint status=%d body=%s", endpoint.Code, endpoint.Body.String())
	}
	credential := serveControlRequest(server, http.MethodPost, "/vulcan/manage/provider-instances/pvi_control/credentials", "admin-control-key", `{"id":"cred_control","auth_method_id":"default","label":"Control Credential","principal_key":"private-principal","fingerprint":"private-fingerprint","secret":"private-upstream-secret"}`)
	if credential.Code != http.StatusCreated || !strings.Contains(credential.Body.String(), "cred_control") {
		t.Fatalf("create credential status=%d body=%s", credential.Code, credential.Body.String())
	}
	if strings.Contains(credential.Body.String(), "private-upstream-secret") || strings.Contains(strings.ToLower(credential.Body.String()), "secret_ref") {
		t.Fatalf("credential creation leaked secret material: %s", credential.Body.String())
	}
	customCatalog := serveControlRequest(server, http.MethodPut, "/vulcan/manage/provider-instances/pvi_control/custom-catalog", "admin-control-key", customCatalogPayload)
	if customCatalog.Code != http.StatusOK || !strings.Contains(customCatalog.Body.String(), "profile_control_default") {
		t.Fatalf("save custom catalog status=%d body=%s", customCatalog.Code, customCatalog.Body.String())
	}
	loadedCustomCatalog := serveControlRequest(server, http.MethodGet, "/vulcan/manage/provider-instances/pvi_control/custom-catalog", "admin-control-key", "")
	if loadedCustomCatalog.Code != http.StatusOK || !strings.Contains(loadedCustomCatalog.Body.String(), "offer_control") || strings.Contains(strings.ToLower(loadedCustomCatalog.Body.String()), "secret") {
		t.Fatalf("load custom catalog status=%d body=%s", loadedCustomCatalog.Code, loadedCustomCatalog.Body.String())
	}
	unknownCustomCatalogField := serveControlRequest(server, http.MethodPut, "/vulcan/manage/provider-instances/pvi_control/custom-catalog", "admin-control-key", `{"models":[],"offerings":[],"profiles":[],"undeclared":true}`)
	if unknownCustomCatalogField.Code != http.StatusBadRequest {
		t.Fatalf("unknown custom catalog field status=%d body=%s", unknownCustomCatalogField.Code, unknownCustomCatalogField.Body.String())
	}
	binding := serveControlRequest(server, http.MethodPost, "/vulcan/manage/provider-instances/pvi_control/bindings", "admin-control-key", `{"id":"bind_control","endpoint_id":"ep_control","credential_id":"cred_control","allowed_model_ids":["model_control"],"priority":1}`)
	if binding.Code != http.StatusCreated || !strings.Contains(binding.Body.String(), "bind_control") {
		t.Fatalf("create binding status=%d body=%s", binding.Code, binding.Body.String())
	}
	activation := serveControlRequest(server, http.MethodPut, "/vulcan/manage/provider-instances/pvi_control/enabled", "admin-control-key", `{"enabled":true}`)
	if activation.Code != http.StatusOK || !strings.Contains(activation.Body.String(), "pvi_control") {
		t.Fatalf("activate instance status=%d body=%s", activation.Code, activation.Body.String())
	}
	credentialViews := serveControlRequest(server, http.MethodGet, "/vulcan/manage/provider-instances/pvi_control/credentials", "admin-control-key", "")
	if credentialViews.Code != http.StatusOK {
		t.Fatalf("list credentials status=%d body=%s", credentialViews.Code, credentialViews.Body.String())
	}
	for _, forbidden := range []string{"private-upstream-secret", "private-principal", "private-fingerprint", "secret_ref", "principal_key", "fingerprint"} {
		if strings.Contains(strings.ToLower(credentialViews.Body.String()), strings.ToLower(forbidden)) {
			t.Fatalf("credential views leaked %q: %s", forbidden, credentialViews.Body.String())
		}
	}
	apiKey := serveControlRequest(server, http.MethodPost, "/vulcan/manage/api-keys", "admin-control-key", `{"name":"Vulcan Code","key":"call-control-key","enabled":true}`)
	if apiKey.Code != http.StatusCreated || !strings.Contains(apiKey.Body.String(), "call-control-key") {
		t.Fatalf("create call-plane key status=%d body=%s", apiKey.Code, apiKey.Body.String())
	}
	managementCall := serveControlRequest(server, http.MethodGet, "/vulcan/v1/models", "admin-control-key", "")
	if managementCall.Code != http.StatusUnauthorized {
		t.Fatalf("call route with management key status=%d, want %d", managementCall.Code, http.StatusUnauthorized)
	}
	callModels := serveControlRequest(server, http.MethodGet, "/vulcan/v1/models", "call-control-key", "")
	if callModels.Code != http.StatusOK || !strings.Contains(callModels.Body.String(), "model_control") {
		t.Fatalf("call model list status=%d body=%s", callModels.Code, callModels.Body.String())
	}
	disableModel := serveControlRequest(server, http.MethodPut, "/vulcan/manage/provider-instances/pvi_control/models/model_control/enabled", "admin-control-key", `{"enabled":false}`)
	if disableModel.Code != http.StatusOK {
		t.Fatalf("disable model status=%d body=%s", disableModel.Code, disableModel.Body.String())
	}
	callModels = serveControlRequest(server, http.MethodGet, "/vulcan/v1/models", "call-control-key", "")
	if callModels.Code != http.StatusOK || strings.Contains(callModels.Body.String(), "model_control") {
		t.Fatalf("disabled call model list status=%d body=%s", callModels.Code, callModels.Body.String())
	}
}

// TestKimiDeviceFlowHTTPKeepsTokensServerSideAndOnboardsCoding verifies the token-confidential route sequence.
// TestKimiDeviceFlowHTTPKeepsTokensServerSideAndOnboardsCoding 验证令牌保密的路由序列。
func TestKimiDeviceFlowHTTPKeepsTokensServerSideAndOnboardsCoding(t *testing.T) {
	flows := &staticKimiDeviceFlows{token: providerkimi.Token{AccessToken: "device-access-secret", RefreshToken: "device-refresh-secret", TokenType: "Bearer", DeviceID: "device-id", Type: "kimi"}}
	server := newControlPlaneIntegrationServerWithFlows(t, flows)
	started := serveControlRequest(server, http.MethodPost, "/vulcan/manage/kimi/device-flows", "admin-control-key", "")
	if started.Code != http.StatusCreated || !strings.Contains(started.Body.String(), "ABCD-EFGH") || strings.Contains(started.Body.String(), "device-access-secret") {
		t.Fatalf("start flow status=%d body=%s", started.Code, started.Body.String())
	}
	onboarded := serveControlRequest(server, http.MethodPost, "/vulcan/manage/kimi/device-flows/flow-test/onboard", "admin-control-key", `{"provider_definition_id":"system_kimi_coding_plan","handle":"kimi-coding-http","display_name":"Kimi Coding Plan","credential_label":"Kimi User","principal_key":"account"}`)
	if onboarded.Code != http.StatusCreated || strings.Contains(onboarded.Body.String(), "device-access-secret") || strings.Contains(onboarded.Body.String(), "device-refresh-secret") {
		t.Fatalf("device onboarding status=%d body=%s", onboarded.Code, onboarded.Body.String())
	}
	if !flows.wasCancelled("flow-test") {
		t.Fatal("completed device flow was not consumed")
	}
}

// staticKimiDeviceFlows returns deterministic safe verification data and one completed token.
// staticKimiDeviceFlows 返回确定性的安全验证数据和一个已完成令牌。
type staticKimiDeviceFlows struct {
	mu        sync.Mutex
	token     providerkimi.Token
	cancelled map[string]bool
}

// Start returns management-safe verification data.
// Start 返回管理安全验证数据。
func (f *staticKimiDeviceFlows) Start(context.Context) (providerkimi.Flow, error) {
	return providerkimi.Flow{ID: "flow-test", UserCode: "ABCD-EFGH", VerificationURI: "https://auth.example/verify", VerificationURIComplete: "https://auth.example/verify?code=ABCD-EFGH", ExpiresAt: time.Now().Add(time.Minute), PollIntervalSeconds: 5}, nil
}

// Poll returns the configured completed token.
// Poll 返回配置的已完成令牌。
func (f *staticKimiDeviceFlows) Poll(context.Context, string) (providerkimi.Token, error) {
	return f.token, nil
}

// Cancel records one consumed flow identifier.
// Cancel 记录一个已消费授权流程标识。
func (f *staticKimiDeviceFlows) Cancel(flowID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cancelled == nil {
		f.cancelled = make(map[string]bool)
	}
	f.cancelled[flowID] = true
}

// wasCancelled reports whether one flow was consumed.
// wasCancelled 报告一个授权流程是否已消费。
func (f *staticKimiDeviceFlows) wasCancelled(flowID string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cancelled[flowID]
}
