package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
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
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	provideranthropic "github.com/OpenVulcan/vulcan-model-core/internal/provider/anthropic"
	providergoogle "github.com/OpenVulcan/vulcan-model-core/internal/provider/google"
	providerkimi "github.com/OpenVulcan/vulcan-model-core/internal/provider/kimi"
	provideropenai "github.com/OpenVulcan/vulcan-model-core/internal/provider/openai"
	providerxai "github.com/OpenVulcan/vulcan-model-core/internal/provider/xai"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/routertool"
	"github.com/OpenVulcan/vulcan-model-core/internal/routingstate"
	"github.com/OpenVulcan/vulcan-model-core/internal/runtimeconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// codexHTTPTestIDToken creates one structurally valid Codex identity token for control-plane integration tests.
// codexHTTPTestIDToken 为控制面集成测试创建一份结构有效的 Codex 身份令牌。
func codexHTTPTestIDToken(t *testing.T, accountID string, planType string, email string) string {
	t.Helper()
	claims, errClaims := json.Marshal(map[string]any{"exp": int64(4102444800), "email": email, "https://api.openai.com/auth": map[string]string{"chatgpt_account_id": accountID, "chatgpt_plan_type": planType}})
	if errClaims != nil {
		t.Fatalf("marshal Codex claims: %v", errClaims)
	}
	return "header." + base64.RawURLEncoding.EncodeToString(claims) + ".signature"
}

// TestWriteControlErrorMapsKimiDeviceFlowStates verifies stable non-secret HTTP semantics for every local authorization state.
// TestWriteControlErrorMapsKimiDeviceFlowStates 验证每个本地授权状态具有稳定且不泄密的 HTTP 语义。
func TestWriteControlErrorMapsKimiDeviceFlowStates(t *testing.T) {
	testCases := []struct {
		// name labels the isolated error mapping case.
		// name 标记隔离的错误映射用例。
		name string
		// err is the provider or flow state presented to the HTTP boundary.
		// err 是提交到 HTTP 边界的供应商或流程状态。
		err error
		// statusCode is the expected stable HTTP status.
		// statusCode 是预期的稳定 HTTP 状态。
		statusCode int
		// errorCode is the expected client-safe Vulcan error code.
		// errorCode 是预期的客户端安全 Vulcan 错误码。
		errorCode string
	}{
		{name: "not found", err: providerkimi.ErrFlowNotFound, statusCode: http.StatusNotFound, errorCode: "device_flow_not_found"},
		{name: "expired", err: providerkimi.ErrAuthorizationExpired, statusCode: http.StatusGone, errorCode: "device_flow_expired"},
		{name: "denied", err: providerkimi.ErrAuthorizationDenied, statusCode: http.StatusForbidden, errorCode: "device_flow_denied"},
		{name: "pending", err: providerkimi.ErrAuthorizationPending, statusCode: http.StatusConflict, errorCode: "device_flow_pending"},
		{name: "bounded", err: providerkimi.ErrFlowLimitReached, statusCode: http.StatusTooManyRequests, errorCode: "device_flow_limit_reached"},
		{name: "xAI pending", err: providerxai.ErrAuthorizationPending, statusCode: http.StatusConflict, errorCode: "device_flow_pending"},
		{name: "xAI denied", err: providerxai.ErrAuthorizationDenied, statusCode: http.StatusForbidden, errorCode: "device_flow_denied"},
		{name: "Antigravity missing", err: providergoogle.ErrAntigravityFlowNotFound, statusCode: http.StatusNotFound, errorCode: "oauth_flow_not_found"},
		{name: "Antigravity completing", err: providergoogle.ErrAntigravityFlowInProgress, statusCode: http.StatusConflict, errorCode: "oauth_flow_in_progress"},
		{name: "Antigravity bounded", err: providergoogle.ErrAntigravityFlowLimitReached, statusCode: http.StatusTooManyRequests, errorCode: "oauth_flow_limit_reached"},
		{name: "Claude missing", err: provideranthropic.ErrClaudeOAuthFlowNotFound, statusCode: http.StatusNotFound, errorCode: "oauth_flow_not_found"},
		{name: "Claude completing", err: provideranthropic.ErrClaudeOAuthFlowInProgress, statusCode: http.StatusConflict, errorCode: "oauth_flow_in_progress"},
		{name: "Claude bounded", err: provideranthropic.ErrClaudeOAuthFlowLimitReached, statusCode: http.StatusTooManyRequests, errorCode: "oauth_flow_limit_reached"},
		{name: "Codex OAuth missing", err: provideropenai.ErrCodexOAuthFlowNotFound, statusCode: http.StatusNotFound, errorCode: "oauth_flow_not_found"},
		{name: "Codex OAuth completing", err: provideropenai.ErrCodexOAuthFlowInProgress, statusCode: http.StatusConflict, errorCode: "oauth_flow_in_progress"},
		{name: "Codex OAuth bounded", err: provideropenai.ErrCodexOAuthFlowLimitReached, statusCode: http.StatusTooManyRequests, errorCode: "oauth_flow_limit_reached"},
		{name: "authentication rejected", err: provider.ErrAuthenticationRejected, statusCode: http.StatusFailedDependency, errorCode: "provider_authentication_rejected"},
		{name: "authentication unavailable", err: provider.ErrAuthenticationUnavailable, statusCode: http.StatusServiceUnavailable, errorCode: "provider_authentication_unavailable"},
		{name: "authentication invalid response", err: provider.ErrAuthenticationResponseInvalid, statusCode: http.StatusBadGateway, errorCode: "provider_authentication_invalid_response"},
		{name: "metadata authentication", err: provider.ErrMetadataAuthentication, statusCode: http.StatusFailedDependency, errorCode: "provider_metadata_authentication_failed"},
		{name: "metadata unavailable", err: provider.ErrMetadataUnavailable, statusCode: http.StatusServiceUnavailable, errorCode: "provider_metadata_unavailable"},
		{name: "metadata invalid response", err: provider.ErrMetadataResponseInvalid, statusCode: http.StatusBadGateway, errorCode: "provider_metadata_invalid_response"},
		{name: "custom provider owns credentials", err: management.ErrCustomDefinitionHasCredentials, statusCode: http.StatusConflict, errorCode: "custom_provider_has_credentials"},
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
	return newControlPlaneIntegrationServerWithProviderFlows(t, deviceFlows, nil, nil, nil, nil, nil)
}

// newControlPlaneIntegrationServerWithProviderFlows creates the real control plane with exact optional provider flow boundaries.
// newControlPlaneIntegrationServerWithProviderFlows 创建具有精确可选供应商授权边界的真实控制面。
func newControlPlaneIntegrationServerWithProviderFlows(t *testing.T, kimiFlows KimiDeviceFlows, xaiFlows XAIDeviceFlows, codexDeviceFlows CodexDeviceFlows, codexOAuthFlows CodexOAuthFlows, claudeFlows ClaudeOAuthFlows, antigravityFlows AntigravityOAuthFlows) *Server {
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
	routingStates := routingstate.NewMemoryStore(time.Now().UTC())
	targets, errTargets := resolve.NewWithRuntimeState(configurations, catalogs, routingStates)
	if errTargets != nil {
		t.Fatalf("create target resolver: %v", errTargets)
	}
	// routerToolBindings owns isolated administrator-authored standard-tool policies for this server.
	// routerToolBindings 为该服务器管理隔离的管理员标准工具策略。
	routerToolBindings := routertool.NewMemoryStore()
	routerToolResolver, errRouterToolResolver := routertool.NewResolver(routerToolBindings, targets)
	if errRouterToolResolver != nil {
		t.Fatalf("create Router tool resolver: %v", errRouterToolResolver)
	}
	queries, errQueries := management.NewQueryService(configurations, catalogs)
	if errQueries != nil {
		t.Fatalf("create management query service: %v", errQueries)
	}
	commands, errCommands := management.NewService(configurations, secret.NewMemoryStore(), catalogs)
	if errCommands != nil {
		t.Fatalf("create management command service: %v", errCommands)
	}
	routingManagement, errRoutingManagement := management.NewRoutingService(configurations, catalogs, routingStates)
	if errRoutingManagement != nil {
		t.Fatalf("create routing management service: %v", errRoutingManagement)
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
		Query:                 queries,
		Commands:              commands,
		ModelAccess:           modelAccess,
		CustomCatalogs:        customCatalogs,
		Protocols:             protocols,
		APIKeys:               configuration,
		Auth:                  configuration,
		Resources:             staticControlAccess{},
		InputPlans:            staticControlAccess{},
		Executions:            staticExecutionAccess{},
		Targets:               targets,
		Routing:               routingManagement,
		RouterTools:           routerToolBindings,
		ModelToolAvailability: routerToolResolver,
		KimiDeviceFlows:       kimiFlows,
		XAIDeviceFlows:        xaiFlows,
		CodexDeviceFlows:      codexDeviceFlows,
		CodexOAuthFlows:       codexOAuthFlows,
		ClaudeOAuthFlows:      claudeFlows,
		AntigravityOAuthFlows: antigravityFlows,
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
	onboarding := serveControlRequest(server, http.MethodPost, "/vulcan/manage/provider-instances/onboard", "admin-control-key", `{"provider_definition_id":"system_kimi_cn","name":"Kimi CN","auth_method_id":"api_key","secret":"private-kimi-key"}`)
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
	secondOnboarding := serveControlRequest(server, http.MethodPost, "/vulcan/manage/provider-instances/onboard", "admin-control-key", `{"provider_definition_id":"system_kimi_cn","name":"Kimi CN","auth_method_id":"api_key","secret":"second-private-kimi-key"}`)
	if secondOnboarding.Code != http.StatusCreated {
		t.Fatalf("second onboarding status=%d body=%s", secondOnboarding.Code, secondOnboarding.Body.String())
	}
	var secondCreated onboardSystemProviderResponse
	if errDecode := json.Unmarshal(secondOnboarding.Body.Bytes(), &secondCreated); errDecode != nil {
		t.Fatalf("decode second onboarding response: %v", errDecode)
	}
	if secondCreated.ProviderInstanceID == "" || secondCreated.ProviderInstanceID == created.ProviderInstanceID {
		t.Fatalf("second onboarding response = %#v, first = %#v", secondCreated, created)
	}
	firstInstanceResponse := serveControlRequest(server, http.MethodGet, "/vulcan/manage/provider-instances/"+created.ProviderInstanceID, "admin-control-key", "")
	secondInstanceResponse := serveControlRequest(server, http.MethodGet, "/vulcan/manage/provider-instances/"+secondCreated.ProviderInstanceID, "admin-control-key", "")
	var firstInstance management.ProviderInstanceView
	var secondInstance management.ProviderInstanceView
	if errDecode := json.Unmarshal(firstInstanceResponse.Body.Bytes(), &firstInstance); errDecode != nil {
		t.Fatalf("decode first provider instance: %v", errDecode)
	}
	if errDecode := json.Unmarshal(secondInstanceResponse.Body.Bytes(), &secondInstance); errDecode != nil {
		t.Fatalf("decode second provider instance: %v", errDecode)
	}
	if firstInstance.Handle == "" || secondInstance.Handle == "" || firstInstance.Handle == secondInstance.Handle {
		t.Fatalf("server-generated handles first=%q second=%q", firstInstance.Handle, secondInstance.Handle)
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

// TestRouterToolBindingHTTPRoundTripPublishesEffectiveReadiness verifies CRUD and management-safe model discovery end to end.
// TestRouterToolBindingHTTPRoundTripPublishesEffectiveReadiness 端到端验证绑定增删改查与管理安全模型发现。
func TestRouterToolBindingHTTPRoundTripPublishesEffectiveReadiness(t *testing.T) {
	server := newControlPlaneIntegrationServer(t)
	kimiOnboarding := serveControlRequest(server, http.MethodPost, "/vulcan/manage/provider-instances/onboard", "admin-control-key", `{"provider_definition_id":"system_kimi_cn","name":"Kimi CN","auth_method_id":"api_key","secret":"test-kimi-key"}`)
	if kimiOnboarding.Code != http.StatusCreated {
		t.Fatalf("Kimi onboarding status=%d body=%s", kimiOnboarding.Code, kimiOnboarding.Body.String())
	}
	tavilyOnboarding := serveControlRequest(server, http.MethodPost, "/vulcan/manage/provider-instances/onboard", "admin-control-key", `{"provider_definition_id":"system_tavily_search_api","name":"Tavily","auth_method_id":"api_key","secret":"test-tavily-key"}`)
	if tavilyOnboarding.Code != http.StatusCreated {
		t.Fatalf("Tavily onboarding status=%d body=%s", tavilyOnboarding.Code, tavilyOnboarding.Body.String())
	}
	var tavilyCreated onboardSystemProviderResponse
	if errDecode := json.Unmarshal(tavilyOnboarding.Body.Bytes(), &tavilyCreated); errDecode != nil {
		t.Fatalf("decode Tavily onboarding: %v", errDecode)
	}
	if tavilyCreated.ProviderInstanceID == "" || tavilyCreated.CredentialID == "" {
		t.Fatalf("Tavily onboarding response = %#v", tavilyCreated)
	}
	createBody := `{"kind":"web_search","provider_instance_id":"` + tavilyCreated.ProviderInstanceID + `","provider_service_id":"service_web_search","service_offering_id":"service_offer_tavily_search","execution_profile_id":"profile_tavily_search","priority":0,"enabled":true,"allowed_provider_instance_ids":[],"allowed_provider_model_ids":[],"allowed_execution_profile_ids":[],"timeout_milliseconds":30000,"maximum_calls":4,"maximum_results":8,"maximum_urls":0,"maximum_result_bytes":65536,"safety_policy":"public_https_only"}`
	createdResponse := serveControlRequest(server, http.MethodPost, "/vulcan/manage/router-tool-bindings", "admin-control-key", createBody)
	if createdResponse.Code != http.StatusCreated || strings.Contains(createdResponse.Body.String(), "test-tavily-key") {
		t.Fatalf("binding creation status=%d body=%s", createdResponse.Code, createdResponse.Body.String())
	}
	var created routertool.Binding
	if errDecode := json.Unmarshal(createdResponse.Body.Bytes(), &created); errDecode != nil {
		t.Fatalf("decode binding creation: %v", errDecode)
	}
	if created.ID == "" || created.Revision != 1 {
		t.Fatalf("created binding = %#v", created)
	}
	mismatchedBody := `{"kind":"web_extractor","provider_instance_id":"` + tavilyCreated.ProviderInstanceID + `","provider_service_id":"service_web_search","service_offering_id":"service_offer_tavily_search","execution_profile_id":"profile_tavily_search","priority":0,"enabled":true,"allowed_provider_instance_ids":[],"allowed_provider_model_ids":[],"allowed_execution_profile_ids":[],"timeout_milliseconds":30000,"maximum_calls":4,"maximum_results":0,"maximum_urls":8,"maximum_result_bytes":65536,"safety_policy":"public_https_only"}`
	mismatchedResponse := serveControlRequest(server, http.MethodPost, "/vulcan/manage/router-tool-bindings", "admin-control-key", mismatchedBody)
	if mismatchedResponse.Code != http.StatusBadRequest {
		t.Fatalf("mismatched standard binding status=%d body=%s", mismatchedResponse.Code, mismatchedResponse.Body.String())
	}
	listResponse := serveControlRequest(server, http.MethodGet, "/vulcan/manage/router-tool-bindings", "admin-control-key", "")
	if listResponse.Code != http.StatusOK || !strings.Contains(listResponse.Body.String(), created.ID) {
		t.Fatalf("binding list status=%d body=%s", listResponse.Code, listResponse.Body.String())
	}
	probeResponse := serveControlRequest(server, http.MethodPost, "/vulcan/manage/router-tool-bindings/"+created.ID+"/test", "admin-control-key", "")
	if probeResponse.Code != http.StatusOK || !strings.Contains(probeResponse.Body.String(), `"ready":true`) || !strings.Contains(probeResponse.Body.String(), `"operation":"search.web"`) || strings.Contains(probeResponse.Body.String(), tavilyCreated.CredentialID) {
		t.Fatalf("binding probe status=%d body=%s", probeResponse.Code, probeResponse.Body.String())
	}
	availabilityResponse := serveControlRequest(server, http.MethodGet, "/vulcan/manage/model-tool-availability", "admin-control-key", "")
	if availabilityResponse.Code != http.StatusOK || !strings.Contains(availabilityResponse.Body.String(), `"router_tool_ready":true`) || strings.Contains(availabilityResponse.Body.String(), tavilyCreated.CredentialID) {
		t.Fatalf("availability status=%d body=%s", availabilityResponse.Code, availabilityResponse.Body.String())
	}
	updateBody := `{"kind":"web_search","provider_instance_id":"` + tavilyCreated.ProviderInstanceID + `","provider_service_id":"service_web_search","service_offering_id":"service_offer_tavily_search","execution_profile_id":"profile_tavily_search","priority":1,"enabled":false,"allowed_provider_instance_ids":[],"allowed_provider_model_ids":[],"allowed_execution_profile_ids":[],"timeout_milliseconds":30000,"maximum_calls":4,"maximum_results":8,"maximum_urls":0,"maximum_result_bytes":65536,"safety_policy":"public_https_only","revision":1}`
	updatedResponse := serveControlRequest(server, http.MethodPut, "/vulcan/manage/router-tool-bindings/"+created.ID, "admin-control-key", updateBody)
	if updatedResponse.Code != http.StatusOK || !strings.Contains(updatedResponse.Body.String(), `"revision":2`) || !strings.Contains(updatedResponse.Body.String(), `"enabled":false`) {
		t.Fatalf("binding update status=%d body=%s", updatedResponse.Code, updatedResponse.Body.String())
	}
	deleteResponse := serveControlRequest(server, http.MethodDelete, "/vulcan/manage/router-tool-bindings/"+created.ID, "admin-control-key", "")
	if deleteResponse.Code != http.StatusNoContent {
		t.Fatalf("binding delete status=%d body=%s", deleteResponse.Code, deleteResponse.Body.String())
	}

	minimaxOnboarding := serveControlRequest(server, http.MethodPost, "/vulcan/manage/provider-instances/onboard", "admin-control-key", `{"provider_definition_id":"system_minimax_cn","name":"MiniMax CN","auth_method_id":"api_key","secret":"test-minimax-key"}`)
	if minimaxOnboarding.Code != http.StatusCreated {
		t.Fatalf("MiniMax onboarding status=%d body=%s", minimaxOnboarding.Code, minimaxOnboarding.Body.String())
	}
	var minimaxCreated onboardSystemProviderResponse
	if errDecode := json.Unmarshal(minimaxOnboarding.Body.Bytes(), &minimaxCreated); errDecode != nil {
		t.Fatalf("decode MiniMax onboarding: %v", errDecode)
	}
	catalogResponse := serveControlRequest(server, http.MethodGet, "/vulcan/manage/provider-instances/"+minimaxCreated.ProviderInstanceID+"/catalog", "admin-control-key", "")
	if catalogResponse.Code != http.StatusOK {
		t.Fatalf("MiniMax catalog status=%d body=%s", catalogResponse.Code, catalogResponse.Body.String())
	}
	var catalogView management.CatalogView
	if errDecode := json.Unmarshal(catalogResponse.Body.Bytes(), &catalogView); errDecode != nil {
		t.Fatalf("decode MiniMax catalog: %v", errDecode)
	}
	// extensionModelTarget captures the exact code-owned image-generation profile exposed by the MiniMax catalog.
	// extensionModelTarget 捕获 MiniMax 目录公开的精确代码拥有图片生成规格。
	var extensionModelID, extensionOfferingID, extensionProfileID string
	for _, model := range catalogView.Models {
		for _, offering := range model.Offerings {
			for _, profile := range offering.Profiles {
				if profile.Operation == vcp.OperationImageGenerate {
					extensionModelID = model.ID
					extensionOfferingID = offering.ID
					extensionProfileID = profile.ID
					break
				}
			}
		}
	}
	if extensionModelID == "" || extensionOfferingID == "" || extensionProfileID == "" {
		t.Fatalf("MiniMax catalog has no image-generation profile: %+v", catalogView.Models)
	}
	extensionPayload, errEncode := json.Marshal(map[string]any{
		"extension":                     vcp.RouterExtensionImageGeneration,
		"provider_instance_id":          minimaxCreated.ProviderInstanceID,
		"provider_model_id":             extensionModelID,
		"offering_id":                   extensionOfferingID,
		"execution_profile_id":          extensionProfileID,
		"priority":                      0,
		"enabled":                       true,
		"allowed_provider_instance_ids": []string{},
		"allowed_provider_model_ids":    []string{},
		"allowed_execution_profile_ids": []string{},
		"timeout_milliseconds":          30000,
		"maximum_calls":                 2,
		"maximum_results":               0,
		"maximum_urls":                  0,
		"maximum_result_bytes":          65536,
		"safety_policy":                 routertool.SafetyPublicHTTPSOnly,
	})
	if errEncode != nil {
		t.Fatalf("encode Router extension binding: %v", errEncode)
	}
	extensionResponse := serveControlRequest(server, http.MethodPost, "/vulcan/manage/router-tool-bindings", "admin-control-key", string(extensionPayload))
	if extensionResponse.Code != http.StatusCreated || !strings.Contains(extensionResponse.Body.String(), `"extension":"image_generation"`) || !strings.Contains(extensionResponse.Body.String(), `"provider_model_id":"`+extensionModelID+`"`) || strings.Contains(extensionResponse.Body.String(), "test-minimax-key") {
		t.Fatalf("extension binding creation status=%d body=%s", extensionResponse.Code, extensionResponse.Body.String())
	}
	extensionAvailability := serveControlRequest(server, http.MethodGet, "/vulcan/manage/model-tool-availability", "admin-control-key", "")
	if extensionAvailability.Code != http.StatusOK || !strings.Contains(extensionAvailability.Body.String(), `"id":"image_generation"`) || !strings.Contains(extensionAvailability.Body.String(), `"supported":true`) {
		t.Fatalf("extension availability status=%d body=%s", extensionAvailability.Code, extensionAvailability.Body.String())
	}
}

// TestKimiManualPlanAndRoutingHTTPRoundTrip verifies plan selection, account priority, and scheduling settings through authenticated routes.
// TestKimiManualPlanAndRoutingHTTPRoundTrip 通过认证路由验证套餐选择、账号优先级与调度设置。
func TestKimiManualPlanAndRoutingHTTPRoundTrip(t *testing.T) {
	server := newControlPlaneIntegrationServer(t)
	groups := serveControlRequest(server, http.MethodGet, "/vulcan/manage/provider-groups", "admin-control-key", "")
	if groups.Code != http.StatusOK || !strings.Contains(groups.Body.String(), `"plan_acquisition":"manual_required"`) || !strings.Contains(groups.Body.String(), `"id":"kimi_allegro"`) {
		t.Fatalf("Kimi plan discovery status=%d body=%s", groups.Code, groups.Body.String())
	}
	missingPlan := serveControlRequest(server, http.MethodPost, "/vulcan/manage/provider-instances/onboard", "admin-control-key", `{"provider_definition_id":"system_kimi_coding_plan","name":"Kimi Plan","auth_method_id":"api_key","secret":"private-kimi-plan-key"}`)
	if missingPlan.Code != http.StatusBadRequest {
		t.Fatalf("missing Kimi plan status=%d body=%s", missingPlan.Code, missingPlan.Body.String())
	}
	onboarding := serveControlRequest(server, http.MethodPost, "/vulcan/manage/provider-instances/onboard", "admin-control-key", `{"provider_definition_id":"system_kimi_coding_plan","name":"Kimi Plan","auth_method_id":"api_key","secret":"private-kimi-plan-key","plan_option_id":"kimi_allegro"}`)
	if onboarding.Code != http.StatusCreated || strings.Contains(onboarding.Body.String(), "private-kimi-plan-key") {
		t.Fatalf("Kimi plan onboarding status=%d body=%s", onboarding.Code, onboarding.Body.String())
	}
	var created onboardSystemProviderResponse
	if errDecode := json.Unmarshal(onboarding.Body.Bytes(), &created); errDecode != nil {
		t.Fatalf("decode Kimi plan onboarding: %v", errDecode)
	}
	settings := serveControlRequest(server, http.MethodPut, "/vulcan/manage/settings/routing", "admin-control-key", `{"strategy":"fill_first"}`)
	if settings.Code != http.StatusOK || !strings.Contains(settings.Body.String(), `"strategy":"fill_first"`) {
		t.Fatalf("routing settings status=%d body=%s", settings.Code, settings.Body.String())
	}
	priority := serveControlRequest(server, http.MethodPut, "/vulcan/manage/provider-instances/"+created.ProviderInstanceID+"/credentials/"+created.CredentialID+"/priority", "admin-control-key", `{"priority":4}`)
	if priority.Code != http.StatusOK || !strings.Contains(priority.Body.String(), `"priority":4`) {
		t.Fatalf("credential priority status=%d body=%s", priority.Code, priority.Body.String())
	}
	plan := serveControlRequest(server, http.MethodPut, "/vulcan/manage/provider-instances/"+created.ProviderInstanceID+"/credentials/"+created.CredentialID+"/plan", "admin-control-key", `{"plan_option_id":"kimi_andante"}`)
	if plan.Code != http.StatusOK || !strings.Contains(plan.Body.String(), `"plan_option_id":"kimi_andante"`) {
		t.Fatalf("credential plan status=%d body=%s", plan.Code, plan.Body.String())
	}
	catalogResponse := serveControlRequest(server, http.MethodGet, "/vulcan/manage/provider-instances/"+created.ProviderInstanceID+"/catalog", "admin-control-key", "")
	if catalogResponse.Code != http.StatusOK || !strings.Contains(catalogResponse.Body.String(), `"plan_code":"kimi_andante"`) || !strings.Contains(catalogResponse.Body.String(), `"authorization_status":"denied"`) || !strings.Contains(catalogResponse.Body.String(), `"reasoning_efforts":["low","high","max"]`) {
		t.Fatalf("updated Kimi catalog status=%d body=%s", catalogResponse.Code, catalogResponse.Body.String())
	}
}

// TestAlibabaSystemOnboardingCommitsFixedEndpointAndCatalog verifies the selected plan owns its endpoint, isolated model set, and recommendation metadata.
// TestAlibabaSystemOnboardingCommitsFixedEndpointAndCatalog 验证所选套餐拥有其端点、隔离模型集合和推荐元数据。
func TestAlibabaSystemOnboardingCommitsFixedEndpointAndCatalog(t *testing.T) {
	server := newControlPlaneIntegrationServer(t)
	forged := serveControlRequest(server, http.MethodPost, "/vulcan/manage/provider-instances/onboard", "admin-control-key", `{"provider_definition_id":"system_alibaba_token_plan_team_global","name":"Alibaba Global","auth_method_id":"api_key","secret":"invalid-test-key","base_url":"https://attacker.invalid"}`)
	if forged.Code != http.StatusBadRequest {
		t.Fatalf("forged endpoint status=%d body=%s", forged.Code, forged.Body.String())
	}
	onboarding := serveControlRequest(server, http.MethodPost, "/vulcan/manage/provider-instances/onboard", "admin-control-key", `{"provider_definition_id":"system_alibaba_token_plan_team_global","name":"Alibaba Global","auth_method_id":"api_key","secret":"invalid-test-key"}`)
	if onboarding.Code != http.StatusCreated || strings.Contains(onboarding.Body.String(), "invalid-test-key") {
		t.Fatalf("onboarding status=%d body=%s", onboarding.Code, onboarding.Body.String())
	}
	var created onboardSystemProviderResponse
	if errDecode := json.Unmarshal(onboarding.Body.Bytes(), &created); errDecode != nil {
		t.Fatalf("decode onboarding response: %v", errDecode)
	}
	catalogResponse := serveControlRequest(server, http.MethodGet, "/vulcan/manage/provider-instances/"+created.ProviderInstanceID+"/catalog", "admin-control-key", "")
	if catalogResponse.Code != http.StatusOK || !strings.Contains(catalogResponse.Body.String(), "qwen3.7-max") || !strings.Contains(catalogResponse.Body.String(), "MiniMax-M2.5") || strings.Contains(catalogResponse.Body.String(), "qwen3.8-max-preview") || !strings.Contains(catalogResponse.Body.String(), `"recommended_reasoning_tokens":{"known":true,"value":4000}`) {
		t.Fatalf("catalog status=%d body=%s", catalogResponse.Code, catalogResponse.Body.String())
	}
	endpoints := serveControlRequest(server, http.MethodGet, "/vulcan/manage/provider-instances/"+created.ProviderInstanceID+"/endpoints", "admin-control-key", "")
	if endpoints.Code != http.StatusOK || !strings.Contains(endpoints.Body.String(), "https://token-plan.ap-southeast-1.maas.aliyuncs.com") || strings.Contains(endpoints.Body.String(), "/apps/anthropic/v1") || strings.Contains(endpoints.Body.String(), "invalid-test-key") {
		t.Fatalf("endpoints status=%d body=%s", endpoints.Code, endpoints.Body.String())
	}
}

// TestAlibabaUnverifiedProductsCannotBeOnboarded verifies evidence-only boundaries never become configurable runtime products.
// TestAlibabaUnverifiedProductsCannotBeOnboarded 验证仅有证据边界的产品绝不会变成可配置运行时产品。
func TestAlibabaUnverifiedProductsCannotBeOnboarded(t *testing.T) {
	server := newControlPlaneIntegrationServer(t)
	for _, definitionID := range []string{"system_alibaba_model_studio_workspace_global", "system_alibaba_model_studio_us", "system_alibaba_token_plan_personal_global"} {
		onboarding := serveControlRequest(server, http.MethodPost, "/vulcan/manage/provider-instances/onboard", "admin-control-key", `{"provider_definition_id":"`+definitionID+`","name":"Unverified Alibaba","auth_method_id":"api_key","secret":"private-unverified-key"}`)
		if onboarding.Code != http.StatusNotFound || strings.Contains(onboarding.Body.String(), "private-unverified-key") {
			t.Fatalf("unverified onboarding %q status=%d body=%s", definitionID, onboarding.Code, onboarding.Body.String())
		}
	}
}

// TestCustomProviderOnboardingHTTPCommitsCompleteSecretSafeGraph verifies the one-request custom compatibility workflow end to end.
// TestCustomProviderOnboardingHTTPCommitsCompleteSecretSafeGraph 端到端验证单请求自定义兼容供应商工作流。
func TestCustomProviderOnboardingHTTPCommitsCompleteSecretSafeGraph(t *testing.T) {
	server := newControlPlaneIntegrationServer(t)
	// unauthorized proves the custom onboarding entry remains management-key scoped.
	// unauthorized 证明自定义录入入口仍仅限管理密钥访问。
	unauthorized := serveControlRequest(server, http.MethodPost, "/vulcan/manage/custom-providers/onboard", "call-control-key", `{"display_name":"Acme","handle":"acme","protocol_profile_id":"openai.chat","base_url":"https://acme.example/v1","secret":"acme-private-token","upstream_model_id":"acme-model"}`)
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("custom onboarding with call key status=%d, want %d", unauthorized.Code, http.StatusUnauthorized)
	}
	// onboarding creates the definition, graph, protected secret, and initial model without returning credential material.
	// onboarding 创建 Definition、访问图、受保护 Secret 与初始模型，且不返回凭据材料。
	onboarding := serveControlRequest(server, http.MethodPost, "/vulcan/manage/custom-providers/onboard", "admin-control-key", `{"display_name":"Acme","handle":"acme","protocol_profile_id":"openai.chat","base_url":"https://acme.example/v1","secret":"acme-private-token","upstream_model_id":"acme-model","model_display_name":"Acme Model"}`)
	if onboarding.Code != http.StatusCreated || strings.Contains(onboarding.Body.String(), "acme-private-token") {
		t.Fatalf("custom onboarding status=%d body=%s", onboarding.Code, onboarding.Body.String())
	}
	var created customProviderOnboardingResponse
	if errDecode := json.Unmarshal(onboarding.Body.Bytes(), &created); errDecode != nil {
		t.Fatalf("decode custom onboarding response: %v", errDecode)
	}
	if created.ProviderDefinitionID == "" || created.ProviderInstanceID == "" || created.CredentialID == "" || created.EndpointID == "" || created.BindingID == "" || created.ProviderModelID == "" {
		t.Fatalf("custom onboarding response = %#v", created)
	}
	// persistedViews exercises each independently readable node to catch partial-commit regressions.
	// persistedViews 读取每个可独立查询的节点，以捕获部分提交回归。
	persistedViews := []string{
		"/vulcan/manage/provider-definitions",
		"/vulcan/manage/provider-instances/" + created.ProviderInstanceID,
		"/vulcan/manage/provider-instances/" + created.ProviderInstanceID + "/endpoints",
		"/vulcan/manage/provider-instances/" + created.ProviderInstanceID + "/credentials",
		"/vulcan/manage/provider-instances/" + created.ProviderInstanceID + "/bindings",
		"/vulcan/manage/provider-instances/" + created.ProviderInstanceID + "/custom-catalog",
	}
	for _, path := range persistedViews {
		response := serveControlRequest(server, http.MethodGet, path, "admin-control-key", "")
		if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "acme-private-token") || strings.Contains(strings.ToLower(response.Body.String()), "secret_ref") {
			t.Fatalf("persisted custom view %s status=%d body=%s", path, response.Code, response.Body.String())
		}
	}
	catalogResponse := serveControlRequest(server, http.MethodGet, "/vulcan/manage/provider-instances/"+created.ProviderInstanceID+"/custom-catalog", "admin-control-key", "")
	if !strings.Contains(catalogResponse.Body.String(), created.ProviderModelID) || !strings.Contains(catalogResponse.Body.String(), "acme-model") {
		t.Fatalf("custom catalog body=%s", catalogResponse.Body.String())
	}
	// unconfirmedDeletion proves credential-bearing custom providers cannot be removed by one accidental request.
	// unconfirmedDeletion 证明带凭据的自定义供应商不会被一次误操作请求删除。
	unconfirmedDeletion := serveControlRequest(server, http.MethodDelete, "/vulcan/manage/provider-definitions/"+created.ProviderDefinitionID, "admin-control-key", "")
	if unconfirmedDeletion.Code != http.StatusConflict || !strings.Contains(unconfirmedDeletion.Body.String(), "custom_provider_has_credentials") {
		t.Fatalf("unconfirmed custom deletion status=%d body=%s", unconfirmedDeletion.Code, unconfirmedDeletion.Body.String())
	}
	// confirmedDeletion explicitly removes credentials, protected secrets, catalogs, instances, and the custom definition.
	// confirmedDeletion 显式删除凭据、受保护秘密、目录、实例与自定义定义。
	confirmedDeletion := serveControlRequest(server, http.MethodDelete, "/vulcan/manage/provider-definitions/"+created.ProviderDefinitionID+"?delete_credentials=true", "admin-control-key", "")
	if confirmedDeletion.Code != http.StatusNoContent {
		t.Fatalf("confirmed custom deletion status=%d body=%s", confirmedDeletion.Code, confirmedDeletion.Body.String())
	}
	deletedInstance := serveControlRequest(server, http.MethodGet, "/vulcan/manage/provider-instances/"+created.ProviderInstanceID, "admin-control-key", "")
	if deletedInstance.Code != http.StatusNotFound {
		t.Fatalf("deleted custom instance status=%d body=%s", deletedInstance.Code, deletedInstance.Body.String())
	}
	remainingDefinitions := serveControlRequest(server, http.MethodGet, "/vulcan/manage/provider-definitions", "admin-control-key", "")
	if remainingDefinitions.Code != http.StatusOK || strings.Contains(remainingDefinitions.Body.String(), created.ProviderDefinitionID) {
		t.Fatalf("remaining custom definitions status=%d body=%s", remainingDefinitions.Code, remainingDefinitions.Body.String())
	}
}

// TestSystemProviderOnboardingHTTPRejectsDeviceCredentialInjection verifies device credentials are accepted only through the server-owned flow route.
// TestSystemProviderOnboardingHTTPRejectsDeviceCredentialInjection 验证设备凭据仅能通过服务端拥有的授权流程路由录入。
func TestSystemProviderOnboardingHTTPRejectsDeviceCredentialInjection(t *testing.T) {
	server := newControlPlaneIntegrationServer(t)
	response := serveControlRequest(server, http.MethodPost, "/vulcan/manage/provider-instances/onboard", "admin-control-key", `{"provider_definition_id":"system_kimi_coding_plan","name":"Forged Device Flow","auth_method_id":"device_flow","secret":"vulcan-kimi-token-v1:{\"access_token\":\"forged\"}"}`)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("device credential injection status=%d body=%s", response.Code, response.Body.String())
	}
}

// TestProviderOnboardingRoutesRejectMalformedJSON verifies every provider-specific onboarding boundary returns one explicit client error.
// TestProviderOnboardingRoutesRejectMalformedJSON 验证每个供应商专属录入边界都会对畸形 JSON 返回明确客户端错误。
func TestProviderOnboardingRoutesRejectMalformedJSON(t *testing.T) {
	server := newControlPlaneIntegrationServerWithProviderFlows(
		t,
		&staticKimiDeviceFlows{},
		&staticXAIDeviceFlows{},
		&staticCodexDeviceFlows{},
		&staticCodexOAuthFlows{},
		&staticClaudeOAuthFlows{},
		&staticAntigravityOAuthFlows{},
	)
	// routes contains every onboarding handler that decodes one provider-specific request body.
	// routes 包含每个解码供应商专属请求正文的录入 Handler。
	routes := []string{
		"/vulcan/manage/provider-instances/onboard",
		"/vulcan/manage/vertex/service-accounts/onboard",
		"/vulcan/manage/kimi/device-flows/flow-kimi/onboard",
		"/vulcan/manage/xai/device-flows/flow-xai/onboard",
		"/vulcan/manage/codex/device-flows/flow-codex/onboard",
		"/vulcan/manage/codex/oauth-flows/flow-codex-oauth/onboard",
		"/vulcan/manage/claude/oauth-flows/flow-claude/onboard",
		"/vulcan/manage/antigravity/oauth-flows/flow-antigravity/onboard",
	}
	for _, route := range routes {
		t.Run(route, func(t *testing.T) {
			response := serveControlRequest(server, http.MethodPost, route, "admin-control-key", "{")
			if response.Code != http.StatusBadRequest {
				t.Fatalf("route %s malformed JSON status=%d body=%s", route, response.Code, response.Body.String())
			}
			var payload errorResponse
			if errDecode := json.Unmarshal(response.Body.Bytes(), &payload); errDecode != nil {
				t.Fatalf("route %s decode error response: %v", route, errDecode)
			}
			if payload.Error != "invalid_request" {
				t.Fatalf("route %s error=%q, want invalid_request", route, payload.Error)
			}
		})
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
	definition := serveControlRequest(server, http.MethodPost, "/vulcan/manage/provider-definitions", "admin-control-key", `{"id":"custom_control","display_name":"Control Gateway","protocol_profile_id":"openai.chat","auth_method":"bearer"}`)
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
	unknownFingerprint := serveControlRequest(server, http.MethodPost, "/vulcan/manage/provider-instances/pvi_control/credentials", "admin-control-key", `{"id":"cred_control","auth_method_id":"default","label":"Control Credential","principal_key":"private-principal","fingerprint":"private-fingerprint","secret":"private-upstream-secret"}`)
	if unknownFingerprint.Code != http.StatusBadRequest {
		t.Fatalf("client fingerprint status=%d body=%s", unknownFingerprint.Code, unknownFingerprint.Body.String())
	}
	credential := serveControlRequest(server, http.MethodPost, "/vulcan/manage/provider-instances/pvi_control/credentials", "admin-control-key", `{"id":"cred_control","auth_method_id":"default","label":"Control Credential","principal_key":"private-principal","secret":"private-upstream-secret"}`)
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
	managementCall := serveControlRequest(server, http.MethodPost, "/vulcan/v1/info", "admin-control-key", `{"get":"models"}`)
	if managementCall.Code != http.StatusUnauthorized {
		t.Fatalf("call route with management key status=%d, want %d", managementCall.Code, http.StatusUnauthorized)
	}
	callModels := serveControlRequest(server, http.MethodPost, "/vulcan/v1/info", "call-control-key", `{"get":"models"}`)
	if callModels.Code != http.StatusOK || !strings.Contains(callModels.Body.String(), "model_control") {
		t.Fatalf("call model list status=%d body=%s", callModels.Code, callModels.Body.String())
	}
	disableModel := serveControlRequest(server, http.MethodPut, "/vulcan/manage/provider-instances/pvi_control/models/model_control/enabled", "admin-control-key", `{"enabled":false}`)
	if disableModel.Code != http.StatusOK {
		t.Fatalf("disable model status=%d body=%s", disableModel.Code, disableModel.Body.String())
	}
	callModels = serveControlRequest(server, http.MethodPost, "/vulcan/v1/info", "call-control-key", `{"get":"models"}`)
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
	onboarded := serveControlRequest(server, http.MethodPost, "/vulcan/manage/kimi/device-flows/flow-test/onboard", "admin-control-key", `{"provider_definition_id":"system_kimi_coding_plan","name":"Kimi User"}`)
	if onboarded.Code != http.StatusCreated || strings.Contains(onboarded.Body.String(), "device-access-secret") || strings.Contains(onboarded.Body.String(), "device-refresh-secret") {
		t.Fatalf("device onboarding status=%d body=%s", onboarded.Code, onboarded.Body.String())
	}
	if !flows.wasCancelled("flow-test") {
		t.Fatal("completed device flow was not consumed")
	}
}

// TestKimiDeviceFlowHTTPReauthorizesExistingCredential verifies target identifiers replace one credential instead of creating a duplicate instance.
// TestKimiDeviceFlowHTTPReauthorizesExistingCredential 验证目标标识会替换一个凭据而不是创建重复实例。
func TestKimiDeviceFlowHTTPReauthorizesExistingCredential(t *testing.T) {
	flows := &staticKimiDeviceFlows{token: providerkimi.Token{AccessToken: "device-access-before", RefreshToken: "device-refresh-before", TokenType: "Bearer", DeviceID: "device-id", Type: "kimi"}}
	server := newControlPlaneIntegrationServerWithFlows(t, flows)
	onboarded := serveControlRequest(server, http.MethodPost, "/vulcan/manage/kimi/device-flows/flow-test/onboard", "admin-control-key", `{"provider_definition_id":"system_kimi_coding_plan","name":"Kimi Account"}`)
	if onboarded.Code != http.StatusCreated {
		t.Fatalf("initial Kimi onboarding status=%d body=%s", onboarded.Code, onboarded.Body.String())
	}
	var created onboardSystemProviderResponse
	if errDecode := json.NewDecoder(onboarded.Body).Decode(&created); errDecode != nil {
		t.Fatalf("decode initial Kimi onboarding: %v", errDecode)
	}
	flows.token = providerkimi.Token{AccessToken: "device-access-after", RefreshToken: "device-refresh-after", TokenType: "Bearer", DeviceID: "device-id", Type: "kimi"}
	reauthorizationBody, errBody := json.Marshal(map[string]string{
		"provider_definition_id": "system_kimi_coding_plan",
		"name":                   "",
		"provider_instance_id":   created.ProviderInstanceID,
		"credential_id":          created.CredentialID,
	})
	if errBody != nil {
		t.Fatalf("encode Kimi reauthorization body: %v", errBody)
	}
	reauthorized := serveControlRequest(server, http.MethodPost, "/vulcan/manage/kimi/device-flows/flow-test/onboard", "admin-control-key", string(reauthorizationBody))
	if reauthorized.Code != http.StatusOK || strings.Contains(reauthorized.Body.String(), "device-access-after") || strings.Contains(reauthorized.Body.String(), "device-refresh-after") {
		t.Fatalf("Kimi reauthorization status=%d body=%s", reauthorized.Code, reauthorized.Body.String())
	}
	var replaced onboardSystemProviderResponse
	if errDecode := json.NewDecoder(reauthorized.Body).Decode(&replaced); errDecode != nil {
		t.Fatalf("decode Kimi reauthorization: %v", errDecode)
	}
	if replaced.ProviderInstanceID != created.ProviderInstanceID || replaced.CredentialID != created.CredentialID || replaced.EndpointIDs == nil || replaced.BindingIDs == nil || len(replaced.EndpointIDs) != 0 || len(replaced.BindingIDs) != 0 {
		t.Fatalf("Kimi reauthorization response=%#v", replaced)
	}
	instancesResponse := serveControlRequest(server, http.MethodGet, "/vulcan/manage/provider-instances", "admin-control-key", "")
	var instances providerInstanceListResponse
	if errDecode := json.NewDecoder(instancesResponse.Body).Decode(&instances); errDecode != nil || len(instances.ProviderInstances) != 1 {
		t.Fatalf("provider instances after reauthorization=%#v error=%v", instances, errDecode)
	}
	credentialsResponse := serveControlRequest(server, http.MethodGet, "/vulcan/manage/provider-instances/"+created.ProviderInstanceID+"/credentials", "admin-control-key", "")
	var credentials credentialListResponse
	if errDecode := json.NewDecoder(credentialsResponse.Body).Decode(&credentials); errDecode != nil || len(credentials.Credentials) != 1 || credentials.Credentials[0].ID != created.CredentialID || credentials.Credentials[0].Revision != 2 {
		t.Fatalf("Kimi credentials after reauthorization=%#v error=%v", credentials, errDecode)
	}
}

// TestProviderCredentialRefreshHTTPDispatchesExactCredential verifies the protected refresh route binds one immutable instance and credential pair.
// TestProviderCredentialRefreshHTTPDispatchesExactCredential 验证受保护刷新路由绑定一个不可变实例与凭据组合。
func TestProviderCredentialRefreshHTTPDispatchesExactCredential(t *testing.T) {
	flows := &staticKimiDeviceFlows{token: providerkimi.Token{AccessToken: "device-access-secret", RefreshToken: "device-refresh-secret", TokenType: "Bearer", DeviceID: "device-id", Type: "kimi"}}
	server := newControlPlaneIntegrationServerWithFlows(t, flows)
	onboarded := serveControlRequest(server, http.MethodPost, "/vulcan/manage/kimi/device-flows/flow-test/onboard", "admin-control-key", `{"provider_definition_id":"system_kimi_coding_plan","name":"Kimi Account"}`)
	if onboarded.Code != http.StatusCreated {
		t.Fatalf("device onboarding status=%d body=%s", onboarded.Code, onboarded.Body.String())
	}
	var created onboardSystemProviderResponse
	if errDecode := json.NewDecoder(onboarded.Body).Decode(&created); errDecode != nil {
		t.Fatalf("decode onboarding response: %v", errDecode)
	}
	commands := &staticKimiTokenCommands{}
	recovery := &staticCredentialRefreshRecovery{}
	server.control.KimiTokens = commands
	server.control.CredentialRefreshRecovery = recovery
	refresherServer, errServer := newServer(server.catalog, server.control)
	if errServer != nil {
		t.Fatalf("rebuild route table with credential refresh: %v", errServer)
	}
	server = refresherServer
	refreshed := serveControlRequest(server, http.MethodPost, "/vulcan/manage/provider-instances/"+created.ProviderInstanceID+"/credentials/"+created.CredentialID+"/refresh", "admin-control-key", "")
	if refreshed.Code != http.StatusOK || !strings.Contains(refreshed.Body.String(), created.CredentialID) {
		t.Fatalf("credential refresh status=%d body=%s", refreshed.Code, refreshed.Body.String())
	}
	if !commands.calledWith(created.ProviderInstanceID, created.CredentialID) {
		t.Fatalf("credential refresh dispatched instance=%q credential=%q", commands.instanceID, commands.credentialID)
	}
	if !recovery.calledWith(created.ProviderInstanceID, created.CredentialID) {
		t.Fatalf("credential recovery dispatched instance=%q credential=%q", recovery.instanceID, recovery.credentialID)
	}
}

// TestXAIDeviceFlowHTTPKeepsTokensServerSideAndOnboardsAccount verifies the complete authenticated xAI device route.
// TestXAIDeviceFlowHTTPKeepsTokensServerSideAndOnboardsAccount 验证完整的已认证 xAI 设备授权路由。
func TestXAIDeviceFlowHTTPKeepsTokensServerSideAndOnboardsAccount(t *testing.T) {
	flows := &staticXAIDeviceFlows{token: providerxai.Token{AccessToken: "xai-access-secret", RefreshToken: "xai-refresh-secret", TokenEndpoint: "https://auth.x.ai/oauth/token", Type: "xai"}}
	server := newControlPlaneIntegrationServerWithProviderFlows(t, nil, flows, nil, nil, nil, nil)
	started := serveControlRequest(server, http.MethodPost, "/vulcan/manage/xai/device-flows", "admin-control-key", "")
	if started.Code != http.StatusCreated || strings.Contains(started.Body.String(), "xai-access-secret") {
		t.Fatalf("start status=%d body=%s", started.Code, started.Body.String())
	}
	onboarded := serveControlRequest(server, http.MethodPost, "/vulcan/manage/xai/device-flows/flow-xai/onboard", "admin-control-key", `{"provider_definition_id":"system_xai_oauth","name":"xAI Account"}`)
	if onboarded.Code != http.StatusCreated || strings.Contains(onboarded.Body.String(), "xai-access-secret") || strings.Contains(onboarded.Body.String(), "xai-refresh-secret") {
		t.Fatalf("onboard status=%d body=%s", onboarded.Code, onboarded.Body.String())
	}
	if !flows.wasCancelled("flow-xai") {
		t.Fatal("completed xAI flow was not consumed")
	}
}

// TestCodexDeviceFlowHTTPKeepsTokensServerSideAndOnboardsAccount verifies the complete authenticated Codex device route.
// TestCodexDeviceFlowHTTPKeepsTokensServerSideAndOnboardsAccount 验证完整的已认证 Codex 设备授权路由。
func TestCodexDeviceFlowHTTPKeepsTokensServerSideAndOnboardsAccount(t *testing.T) {
	idToken := codexHTTPTestIDToken(t, "account-one", "plus", "codex@example.com")
	flows := &staticCodexDeviceFlows{token: provideropenai.CodexToken{IDToken: idToken, AccessToken: "codex-access-secret", RefreshToken: "codex-refresh-secret", AccountID: "account-one", Email: "codex@example.com", ExpiresAt: time.Now().UTC().Add(time.Hour), Type: "codex"}}
	server := newControlPlaneIntegrationServerWithProviderFlows(t, nil, nil, flows, nil, nil, nil)
	started := serveControlRequest(server, http.MethodPost, "/vulcan/manage/codex/device-flows", "admin-control-key", "")
	if started.Code != http.StatusCreated || strings.Contains(started.Body.String(), "codex-access-secret") {
		t.Fatalf("start status=%d body=%s", started.Code, started.Body.String())
	}
	onboarded := serveControlRequest(server, http.MethodPost, "/vulcan/manage/codex/device-flows/flow-codex/onboard", "admin-control-key", `{"provider_definition_id":"system_openai_codex","name":""}`)
	if onboarded.Code != http.StatusCreated || strings.Contains(onboarded.Body.String(), "codex-access-secret") || strings.Contains(onboarded.Body.String(), "codex-refresh-secret") {
		t.Fatalf("onboard status=%d body=%s", onboarded.Code, onboarded.Body.String())
	}
	if !flows.wasCancelled("flow-codex") {
		t.Fatal("completed Codex flow was not consumed")
	}
}

// TestCodexOAuthHTTPKeepsTokensServerSideAndOnboardsAccount verifies the default browser PKCE onboarding boundary.
// TestCodexOAuthHTTPKeepsTokensServerSideAndOnboardsAccount 验证默认浏览器 PKCE 录入边界。
func TestCodexOAuthHTTPKeepsTokensServerSideAndOnboardsAccount(t *testing.T) {
	flows := &staticCodexOAuthFlows{token: provideropenai.CodexToken{IDToken: codexHTTPTestIDToken(t, "account-one", "plus", "user@example.com"), AccessToken: "codex-private-access", RefreshToken: "codex-private-refresh", AccountID: "account-one", Email: "user@example.com", ExpiresAt: time.Now().UTC().Add(time.Hour), Type: "codex"}}
	server := newControlPlaneIntegrationServerWithProviderFlows(t, nil, nil, nil, flows, nil, nil)
	started := serveControlRequest(server, http.MethodPost, "/vulcan/manage/codex/oauth-flows", "admin-control-key", "")
	if started.Code != http.StatusCreated || !strings.Contains(started.Body.String(), "auth.openai.com") || strings.Contains(started.Body.String(), "codex-private") {
		t.Fatalf("Codex OAuth start status=%d body=%s", started.Code, started.Body.String())
	}
	onboarded := serveControlRequest(server, http.MethodPost, "/vulcan/manage/codex/oauth-flows/flow-codex-oauth/onboard", "admin-control-key", `{"provider_definition_id":"system_openai_codex","callback_url":"http://localhost:1455/auth/callback?code=code&state=state"}`)
	if onboarded.Code != http.StatusCreated || strings.Contains(onboarded.Body.String(), "codex-private") || strings.Contains(onboarded.Body.String(), "account-one") || strings.Contains(onboarded.Body.String(), "user@example.com") {
		t.Fatalf("Codex OAuth onboarding status=%d body=%s", onboarded.Code, onboarded.Body.String())
	}
	if !flows.wasCancelled("flow-codex-oauth") {
		t.Fatal("completed Codex OAuth flow was not consumed")
	}
	var created onboardSystemProviderResponse
	if errDecode := json.NewDecoder(onboarded.Body).Decode(&created); errDecode != nil {
		t.Fatalf("decode Codex OAuth onboarding response: %v", errDecode)
	}
	credentials := serveControlRequest(server, http.MethodGet, "/vulcan/manage/provider-instances/"+created.ProviderInstanceID+"/credentials", "admin-control-key", "")
	if credentials.Code != http.StatusOK || strings.Contains(credentials.Body.String(), "codex-private") || strings.Contains(credentials.Body.String(), "account-one") || !strings.Contains(credentials.Body.String(), "user@example.com") || !strings.Contains(credentials.Body.String(), "expires_at") {
		t.Fatalf("Codex OAuth credential view status=%d body=%s", credentials.Code, credentials.Body.String())
	}
}

// TestClaudeOAuthHTTPKeepsTokensServerSideAndOnboardsAccount verifies the complete pasted-callback workflow.
// TestClaudeOAuthHTTPKeepsTokensServerSideAndOnboardsAccount 验证完整的粘贴回调授权工作流。
func TestClaudeOAuthHTTPKeepsTokensServerSideAndOnboardsAccount(t *testing.T) {
	now := time.Now().UTC()
	flows := &staticClaudeOAuthFlows{token: provideranthropic.ClaudeToken{AccessToken: "claude-private-access", RefreshToken: "claude-private-refresh", TokenType: "Bearer", ExpiresAt: now.Add(time.Hour).Unix(), LastRefreshAt: now.Unix(), Email: "user@example.com", AccountID: "account-one", OrganizationID: "org-one", Type: "claude"}}
	server := newControlPlaneIntegrationServerWithProviderFlows(t, nil, nil, nil, nil, flows, nil)
	started := serveControlRequest(server, http.MethodPost, "/vulcan/manage/claude/oauth-flows", "admin-control-key", "")
	if started.Code != http.StatusCreated || strings.Contains(started.Body.String(), "claude-private") {
		t.Fatalf("Claude start status=%d body=%s", started.Code, started.Body.String())
	}
	onboarded := serveControlRequest(server, http.MethodPost, "/vulcan/manage/claude/oauth-flows/flow-claude/onboard", "admin-control-key", `{"provider_definition_id":"system_anthropic_claude_code","callback_url":"http://localhost:54545/callback?code=code&state=state"}`)
	if onboarded.Code != http.StatusCreated || strings.Contains(onboarded.Body.String(), "claude-private") {
		t.Fatalf("Claude onboarding status=%d body=%s", onboarded.Code, onboarded.Body.String())
	}
	if !flows.wasCancelled("flow-claude") {
		t.Fatal("completed Claude flow was not consumed")
	}
	var created onboardSystemProviderResponse
	if errDecode := json.NewDecoder(onboarded.Body).Decode(&created); errDecode != nil {
		t.Fatalf("decode Claude onboarding response: %v", errDecode)
	}
	credentials := serveControlRequest(server, http.MethodGet, "/vulcan/manage/provider-instances/"+created.ProviderInstanceID+"/credentials", "admin-control-key", "")
	if credentials.Code != http.StatusOK || strings.Contains(credentials.Body.String(), "claude-private") || strings.Contains(credentials.Body.String(), "account-one") || !strings.Contains(credentials.Body.String(), "user@example.com") || !strings.Contains(credentials.Body.String(), "expires_at") {
		t.Fatalf("Claude credential view status=%d body=%s", credentials.Code, credentials.Body.String())
	}
}

// TestAntigravityOAuthHTTPKeepsTokensServerSideAndOnboardsProject verifies the complete pasted-callback route.
// TestAntigravityOAuthHTTPKeepsTokensServerSideAndOnboardsProject 验证完整的粘贴回调授权路由。
func TestAntigravityOAuthHTTPKeepsTokensServerSideAndOnboardsProject(t *testing.T) {
	flows := &staticAntigravityOAuthFlows{token: providergoogle.AntigravityToken{AccessToken: "google-access-secret", RefreshToken: "google-refresh-secret", TokenType: "Bearer", Email: "user@example.com", ProjectID: "project-one", ExpiresAt: time.Now().Add(time.Hour).Unix(), Type: "antigravity"}}
	server := newControlPlaneIntegrationServerWithProviderFlows(t, nil, nil, nil, nil, nil, flows)
	started := serveControlRequest(server, http.MethodPost, "/vulcan/manage/antigravity/oauth-flows", "admin-control-key", "")
	if started.Code != http.StatusCreated || !strings.Contains(started.Body.String(), "accounts.google.com") || strings.Contains(started.Body.String(), "google-access-secret") {
		t.Fatalf("start status=%d body=%s", started.Code, started.Body.String())
	}
	onboarded := serveControlRequest(server, http.MethodPost, "/vulcan/manage/antigravity/oauth-flows/flow-antigravity/onboard", "admin-control-key", `{"provider_definition_id":"system_google_antigravity","callback_url":"http://localhost:51121/oauth-callback?code=code&state=state"}`)
	if onboarded.Code != http.StatusCreated || strings.Contains(onboarded.Body.String(), "google-access-secret") || strings.Contains(onboarded.Body.String(), "google-refresh-secret") || strings.Contains(onboarded.Body.String(), "user@example.com") || strings.Contains(onboarded.Body.String(), "project-one") {
		t.Fatalf("onboard status=%d body=%s", onboarded.Code, onboarded.Body.String())
	}
	if !flows.wasCancelled("flow-antigravity") {
		t.Fatal("completed Antigravity OAuth flow was not consumed")
	}
}

// flowLeaseObservation exposes exact delivery-lease transitions for HTTP boundary tests.
// flowLeaseObservation 为 HTTP 边界测试暴露精确的交付租约状态变化。
type flowLeaseObservation interface {
	// wasReleased reports whether downstream failure returned the completed result.
	// wasReleased 报告下游失败是否归还已完成结果。
	wasReleased(string) bool
	// wasCancelled reports whether downstream success consumed the session.
	// wasCancelled 报告下游成功是否消费会话。
	wasCancelled(string) bool
}

// assertFailedOnboardingReleasesFlow verifies a failed atomic commit returns rather than consumes one completed authorization lease.
// assertFailedOnboardingReleasesFlow 验证原子提交失败时归还而不是消费一个已完成授权租约。
func assertFailedOnboardingReleasesFlow(t *testing.T, server *Server, path string, body string, flowID string, observation flowLeaseObservation) {
	t.Helper()
	response := serveControlRequest(server, http.MethodPost, path, "admin-control-key", body)
	if response.Code == http.StatusCreated {
		t.Fatalf("failed onboarding unexpectedly succeeded: %s", response.Body.String())
	}
	if !observation.wasReleased(flowID) {
		t.Fatalf("failed onboarding did not release flow %q", flowID)
	}
	if observation.wasCancelled(flowID) {
		t.Fatalf("failed onboarding consumed flow %q", flowID)
	}
}

// TestAuthorizationHTTPReleasesCompletedLeaseWhenOnboardingFails verifies all confidential authorization routes remain retryable without duplicate delivery.
// TestAuthorizationHTTPReleasesCompletedLeaseWhenOnboardingFails 验证全部保密授权路由在避免重复交付的同时仍可失败重试。
func TestAuthorizationHTTPReleasesCompletedLeaseWhenOnboardingFails(t *testing.T) {
	t.Run("Kimi device", func(t *testing.T) {
		flows := &staticKimiDeviceFlows{token: providerkimi.Token{AccessToken: "kimi-access", RefreshToken: "kimi-refresh", TokenType: "Bearer", DeviceID: "device-id", Type: "kimi"}}
		server := newControlPlaneIntegrationServerWithProviderFlows(t, flows, nil, nil, nil, nil, nil)
		assertFailedOnboardingReleasesFlow(t, server, "/vulcan/manage/kimi/device-flows/flow-test/onboard", `{"provider_definition_id":"missing_definition","name":"Kimi"}`, "flow-test", flows)
	})
	t.Run("xAI device", func(t *testing.T) {
		flows := &staticXAIDeviceFlows{token: providerxai.Token{AccessToken: "xai-access", RefreshToken: "xai-refresh", TokenEndpoint: "https://auth.x.ai/oauth/token", Type: "xai"}}
		server := newControlPlaneIntegrationServerWithProviderFlows(t, nil, flows, nil, nil, nil, nil)
		assertFailedOnboardingReleasesFlow(t, server, "/vulcan/manage/xai/device-flows/flow-xai/onboard", `{"provider_definition_id":"missing_definition","name":"xAI"}`, "flow-xai", flows)
	})
	t.Run("Codex device", func(t *testing.T) {
		flows := &staticCodexDeviceFlows{token: provideropenai.CodexToken{IDToken: codexHTTPTestIDToken(t, "account-one", "plus", "user@example.com"), AccessToken: "codex-access", RefreshToken: "codex-refresh", AccountID: "account-one", Email: "user@example.com", ExpiresAt: time.Now().UTC().Add(time.Hour), Type: "codex"}}
		server := newControlPlaneIntegrationServerWithProviderFlows(t, nil, nil, flows, nil, nil, nil)
		assertFailedOnboardingReleasesFlow(t, server, "/vulcan/manage/codex/device-flows/flow-codex/onboard", `{"provider_definition_id":"missing_definition","name":"Codex"}`, "flow-codex", flows)
	})
	t.Run("Codex OAuth", func(t *testing.T) {
		flows := &staticCodexOAuthFlows{token: provideropenai.CodexToken{IDToken: codexHTTPTestIDToken(t, "account-one", "plus", "user@example.com"), AccessToken: "codex-access", RefreshToken: "codex-refresh", AccountID: "account-one", Email: "user@example.com", ExpiresAt: time.Now().UTC().Add(time.Hour), Type: "codex"}}
		server := newControlPlaneIntegrationServerWithProviderFlows(t, nil, nil, nil, flows, nil, nil)
		assertFailedOnboardingReleasesFlow(t, server, "/vulcan/manage/codex/oauth-flows/flow-codex-oauth/onboard", `{"provider_definition_id":"missing_definition","callback_url":"http://localhost:1455/auth/callback?code=code&state=state"}`, "flow-codex-oauth", flows)
	})
	t.Run("Claude OAuth", func(t *testing.T) {
		now := time.Now().UTC()
		flows := &staticClaudeOAuthFlows{token: provideranthropic.ClaudeToken{AccessToken: "claude-access", RefreshToken: "claude-refresh", TokenType: "Bearer", ExpiresAt: now.Add(time.Hour).Unix(), LastRefreshAt: now.Unix(), Email: "user@example.com", AccountID: "account-one", OrganizationID: "org-one", Type: "claude"}}
		server := newControlPlaneIntegrationServerWithProviderFlows(t, nil, nil, nil, nil, flows, nil)
		assertFailedOnboardingReleasesFlow(t, server, "/vulcan/manage/claude/oauth-flows/flow-claude/onboard", `{"provider_definition_id":"missing_definition","callback_url":"http://localhost:54545/callback?code=code&state=state"}`, "flow-claude", flows)
	})
	t.Run("Antigravity OAuth", func(t *testing.T) {
		flows := &staticAntigravityOAuthFlows{token: providergoogle.AntigravityToken{AccessToken: "google-access", RefreshToken: "google-refresh", TokenType: "Bearer", Email: "user@example.com", ProjectID: "project-one", ExpiresAt: time.Now().UTC().Add(time.Hour).Unix(), Type: "antigravity"}}
		server := newControlPlaneIntegrationServerWithProviderFlows(t, nil, nil, nil, nil, nil, flows)
		assertFailedOnboardingReleasesFlow(t, server, "/vulcan/manage/antigravity/oauth-flows/flow-antigravity/onboard", `{"provider_definition_id":"missing_definition","callback_url":"http://localhost:51121/oauth-callback?code=code&state=state"}`, "flow-antigravity", flows)
	})
}

// TestVertexServiceAccountHTTPNormalizesAndKeepsPrivateKeyServerSide verifies the dedicated management upload boundary end to end.
// TestVertexServiceAccountHTTPNormalizesAndKeepsPrivateKeyServerSide 端到端校验专属管理上传边界的规范化与私钥保密。
func TestVertexServiceAccountHTTPNormalizesAndKeepsPrivateKeyServerSide(t *testing.T) {
	server := newControlPlaneIntegrationServer(t)
	serviceAccount := vertexHTTPServiceAccountFixture(t)
	payload, errPayload := json.Marshal(map[string]any{
		"provider_definition_id": bootstrap.GoogleVertexDefinitionID,
		"location":               "europe-west1",
		"service_account":        serviceAccount,
	})
	if errPayload != nil {
		t.Fatalf("marshal Vertex onboarding request: %v", errPayload)
	}
	onboarded := serveControlRequest(server, http.MethodPost, "/vulcan/manage/vertex/service-accounts/onboard", "admin-control-key", string(payload))
	if onboarded.Code != http.StatusCreated {
		t.Fatalf("Vertex onboarding status=%d body=%s", onboarded.Code, onboarded.Body.String())
	}
	if strings.Contains(onboarded.Body.String(), serviceAccount["private_key"]) || strings.Contains(onboarded.Body.String(), serviceAccount["client_email"]) {
		t.Fatalf("Vertex onboarding response leaked service-account material: %s", onboarded.Body.String())
	}
	var response onboardSystemProviderResponse
	if errDecode := json.NewDecoder(onboarded.Body).Decode(&response); errDecode != nil {
		t.Fatalf("decode Vertex onboarding response: %v", errDecode)
	}
	endpoints := serveControlRequest(server, http.MethodGet, "/vulcan/manage/provider-instances/"+response.ProviderInstanceID+"/endpoints", "admin-control-key", "")
	if endpoints.Code != http.StatusOK || !strings.Contains(endpoints.Body.String(), "https://europe-west1-aiplatform.googleapis.com") || !strings.Contains(endpoints.Body.String(), "europe-west1") {
		t.Fatalf("Vertex endpoint response status=%d body=%s", endpoints.Code, endpoints.Body.String())
	}
	credentials := serveControlRequest(server, http.MethodGet, "/vulcan/manage/provider-instances/"+response.ProviderInstanceID+"/credentials", "admin-control-key", "")
	if credentials.Code != http.StatusOK || strings.Contains(credentials.Body.String(), serviceAccount["private_key"]) || !strings.Contains(credentials.Body.String(), serviceAccount["client_email"]) {
		t.Fatalf("Vertex credential response did not preserve only safe service-account identity: %s", credentials.Body.String())
	}
}

// vertexHTTPServiceAccountFixture creates one valid generated service-account JSON object for HTTP boundary tests.
// vertexHTTPServiceAccountFixture 为 HTTP 边界测试创建一个有效的动态服务账号 JSON 对象。
func vertexHTTPServiceAccountFixture(t *testing.T) map[string]string {
	t.Helper()
	privateKey, errKey := rsa.GenerateKey(rand.Reader, 2048)
	if errKey != nil {
		t.Fatalf("generate Vertex HTTP RSA key: %v", errKey)
	}
	return map[string]string{
		"type": "service_account", "project_id": "vertex-http-project", "private_key_id": "http-key-id",
		"private_key":  string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})),
		"client_email": "vertex@vertex-http-project.iam.gserviceaccount.com", "token_uri": "https://oauth2.googleapis.com/token",
	}
}

// staticCodexOAuthFlows provides deterministic management-safe Codex browser authorization for HTTP integration tests.
// staticCodexOAuthFlows 为 HTTP 集成测试提供确定性的管理安全 Codex 浏览器授权。
type staticCodexOAuthFlows struct {
	// token is the protected OpenAI result returned only to the server handler.
	// token 是仅返回给服务端 Handler 的受保护 OpenAI 结果。
	token provideropenai.CodexToken
	// cancelled records consumed flow identifiers.
	// cancelled 记录已消费流程标识。
	cancelled sync.Map
	// released records leases returned after failed onboarding.
	// released 记录录入失败后归还的租约。
	released sync.Map
}

// Start returns a public OpenAI consent URL without token, state, or PKCE material.
// Start 返回不含 Token、State 或 PKCE 材料的 OpenAI 公共同意授权地址。
func (f *staticCodexOAuthFlows) Start(context.Context) (provideropenai.CodexOAuthFlow, error) {
	return provideropenai.CodexOAuthFlow{ID: "flow-codex-oauth", AuthorizationURL: "https://auth.openai.com/oauth/authorize?redacted=true", RedirectURI: "http://localhost:1455/auth/callback", ExpiresAt: time.Now().Add(time.Minute)}, nil
}

// Complete returns the configured protected Codex token.
// Complete 返回配置的受保护 Codex Token。
func (f *staticCodexOAuthFlows) Complete(context.Context, string, string) (provideropenai.CodexToken, error) {
	return f.token, nil
}

// Release records one returned Codex OAuth lease.
// Release 记录一个已归还的 Codex OAuth 租约。
func (f *staticCodexOAuthFlows) Release(flowID string) {
	f.released.Store(flowID, struct{}{})
}

// Cancel records exact Codex OAuth flow consumption.
// Cancel 记录精确 Codex OAuth 流程消费。
func (f *staticCodexOAuthFlows) Cancel(flowID string) {
	f.cancelled.Store(flowID, struct{}{})
}

// wasCancelled reports whether the exact Codex OAuth flow was consumed.
// wasCancelled 报告精确 Codex OAuth 流程是否已消费。
func (f *staticCodexOAuthFlows) wasCancelled(flowID string) bool {
	_, found := f.cancelled.Load(flowID)
	return found
}

// wasReleased reports whether one Codex OAuth lease was returned.
// wasReleased 报告一个 Codex OAuth 租约是否已归还。
func (f *staticCodexOAuthFlows) wasReleased(flowID string) bool {
	_, found := f.released.Load(flowID)
	return found
}

// staticClaudeOAuthFlows provides deterministic management-safe Claude authorization for HTTP integration tests.
// staticClaudeOAuthFlows 为 HTTP 集成测试提供确定性的管理安全 Claude 授权。
type staticClaudeOAuthFlows struct {
	// token is the protected provider result returned only to the server handler.
	// token 是仅返回给服务端 Handler 的受保护供应商结果。
	token provideranthropic.ClaudeToken
	// cancelled records consumed flow identifiers.
	// cancelled 记录已消费流程标识。
	cancelled sync.Map
	// released records leases returned after failed onboarding.
	// released 记录录入失败后归还的租约。
	released sync.Map
}

// Start returns a public Claude authorization URL without Token, State, or PKCE material.
// Start 返回不含 Token、State 或 PKCE 材料的公开 Claude 授权地址。
func (f *staticClaudeOAuthFlows) Start(context.Context) (provideranthropic.ClaudeOAuthFlow, error) {
	return provideranthropic.ClaudeOAuthFlow{ID: "flow-claude", AuthorizationURL: "https://claude.ai/oauth/authorize?redacted=true", RedirectURI: "http://localhost:54545/callback", ExpiresAt: time.Now().Add(time.Minute)}, nil
}

// Complete returns the configured protected Claude token.
// Complete 返回配置的受保护 Claude Token。
func (f *staticClaudeOAuthFlows) Complete(context.Context, string, string) (provideranthropic.ClaudeToken, error) {
	return f.token, nil
}

// Release records one returned Claude OAuth lease.
// Release 记录一个已归还的 Claude OAuth 租约。
func (f *staticClaudeOAuthFlows) Release(flowID string) {
	f.released.Store(flowID, struct{}{})
}

// Cancel records exact Claude flow consumption.
// Cancel 记录精确 Claude 流程消费。
func (f *staticClaudeOAuthFlows) Cancel(flowID string) {
	f.cancelled.Store(flowID, struct{}{})
}

// wasCancelled reports whether the exact Claude flow was consumed.
// wasCancelled 报告精确 Claude 流程是否已消费。
func (f *staticClaudeOAuthFlows) wasCancelled(flowID string) bool {
	_, found := f.cancelled.Load(flowID)
	return found
}

// wasReleased reports whether one Claude OAuth lease was returned.
// wasReleased 报告一个 Claude OAuth 租约是否已归还。
func (f *staticClaudeOAuthFlows) wasReleased(flowID string) bool {
	_, found := f.released.Load(flowID)
	return found
}

// staticAntigravityOAuthFlows provides deterministic management-safe Google authorization for HTTP integration tests.
// staticAntigravityOAuthFlows 为 HTTP 集成测试提供确定性的管理安全 Google 授权。
type staticAntigravityOAuthFlows struct {
	// token is returned only across the in-process server boundary.
	// token 仅在进程内服务边界返回。
	token providergoogle.AntigravityToken
	// cancelled records exact local flow consumption.
	// cancelled 记录精确的本地流程消费。
	cancelled sync.Map
	// released records leases returned after failed onboarding.
	// released 记录录入失败后归还的租约。
	released sync.Map
}

// Start returns a public Google authorization URL without token or CSRF material.
// Start 返回不含 Token 或 CSRF 材料的 Google 公共授权地址。
func (f *staticAntigravityOAuthFlows) Start(context.Context) (providergoogle.AntigravityOAuthFlow, error) {
	return providergoogle.AntigravityOAuthFlow{ID: "flow-antigravity", AuthorizationURL: "https://accounts.google.com/o/oauth2/v2/auth?state=state", RedirectURI: "http://localhost:51121/oauth-callback", ExpiresAt: time.Now().Add(time.Minute)}, nil
}

// Complete returns the configured protected Antigravity token.
// Complete 返回配置的受保护 Antigravity Token。
func (f *staticAntigravityOAuthFlows) Complete(context.Context, string, string) (providergoogle.AntigravityToken, error) {
	return f.token, nil
}

// Release records one returned Antigravity OAuth lease.
// Release 记录一个已归还的 Antigravity OAuth 租约。
func (f *staticAntigravityOAuthFlows) Release(flowID string) {
	f.released.Store(flowID, struct{}{})
}

// Cancel records exact Antigravity flow consumption.
// Cancel 记录精确的 Antigravity 流程消费。
func (f *staticAntigravityOAuthFlows) Cancel(flowID string) {
	f.cancelled.Store(flowID, true)
}

// wasCancelled reports whether the exact Antigravity flow was consumed.
// wasCancelled 报告精确 Antigravity 流程是否已消费。
func (f *staticAntigravityOAuthFlows) wasCancelled(flowID string) bool {
	_, found := f.cancelled.Load(flowID)
	return found
}

// wasReleased reports whether one Antigravity OAuth lease was returned.
// wasReleased 报告一个 Antigravity OAuth 租约是否已归还。
func (f *staticAntigravityOAuthFlows) wasReleased(flowID string) bool {
	_, found := f.released.Load(flowID)
	return found
}

// staticKimiDeviceFlows returns deterministic safe verification data and one completed token.
// staticKimiDeviceFlows 返回确定性的安全验证数据和一个已完成令牌。
type staticKimiDeviceFlows struct {
	// mu protects deterministic cancellation observations.
	// mu 保护确定性的取消观察结果。
	mu sync.Mutex
	// token is returned only across the in-process server boundary.
	// token 仅在进程内服务边界返回。
	token providerkimi.Token
	// cancelled records exact local flow consumption.
	// cancelled 记录精确的本地流程消费。
	cancelled map[string]bool
	// released records leases returned after failed onboarding.
	// released 记录录入失败后归还的租约。
	released map[string]bool
}

// staticXAIDeviceFlows provides deterministic management-safe xAI authorization for HTTP integration tests.
// staticXAIDeviceFlows 为 HTTP 集成测试提供确定性的管理安全 xAI 授权。
type staticXAIDeviceFlows struct {
	// token is returned only across the in-process server boundary.
	// token 仅在进程内服务边界返回。
	token providerxai.Token
	// cancelled records exact local flow consumption.
	// cancelled 记录精确的本地流程消费。
	cancelled sync.Map
	// released records leases returned after failed onboarding.
	// released 记录录入失败后归还的租约。
	released sync.Map
}

// staticCodexDeviceFlows provides deterministic management-safe Codex authorization for HTTP integration tests.
// staticCodexDeviceFlows 为 HTTP 集成测试提供确定性的管理安全 Codex 授权。
type staticCodexDeviceFlows struct {
	// token is returned only across the in-process server boundary.
	// token 仅在进程内服务边界返回。
	token provideropenai.CodexToken
	// cancelled records exact local flow consumption.
	// cancelled 记录精确的本地流程消费。
	cancelled sync.Map
	// released records leases returned after failed onboarding.
	// released 记录录入失败后归还的租约。
	released sync.Map
}

// Start returns public Codex verification data without token material.
// Start 返回不含 Token 材料的 Codex 公共验证数据。
func (f *staticCodexDeviceFlows) Start(context.Context) (provideropenai.CodexDeviceFlow, error) {
	return provideropenai.CodexDeviceFlow{ID: "flow-codex", UserCode: "CODEX-CODE", VerificationURI: "https://auth.openai.com/codex/device", ExpiresAt: time.Now().Add(time.Minute), PollIntervalSeconds: 1}, nil
}

// Poll returns the configured protected Codex token.
// Poll 返回配置的受保护 Codex Token。
func (f *staticCodexDeviceFlows) Poll(context.Context, string) (provideropenai.CodexToken, error) {
	return f.token, nil
}

// Release records one returned Codex device lease.
// Release 记录一个已归还的 Codex 设备租约。
func (f *staticCodexDeviceFlows) Release(flowID string) {
	f.released.Store(flowID, struct{}{})
}

// Cancel records exact Codex flow consumption.
// Cancel 记录精确的 Codex 流程消费。
func (f *staticCodexDeviceFlows) Cancel(flowID string) {
	f.cancelled.Store(flowID, true)
}

// wasCancelled reports whether the exact Codex flow was consumed.
// wasCancelled 报告精确 Codex 流程是否已消费。
func (f *staticCodexDeviceFlows) wasCancelled(flowID string) bool {
	_, found := f.cancelled.Load(flowID)
	return found
}

// wasReleased reports whether one Codex device lease was returned.
// wasReleased 报告一个 Codex 设备租约是否已归还。
func (f *staticCodexDeviceFlows) wasReleased(flowID string) bool {
	_, found := f.released.Load(flowID)
	return found
}

// Start returns public xAI verification data without token material.
// Start 返回不含 Token 材料的 xAI 公共验证数据。
func (f *staticXAIDeviceFlows) Start(context.Context) (providerxai.Flow, error) {
	return providerxai.Flow{ID: "flow-xai", UserCode: "XAI-CODE", VerificationURI: "https://auth.x.ai/device", ExpiresAt: time.Now().Add(time.Minute), PollIntervalSeconds: 1}, nil
}

// Poll returns the configured protected xAI token.
// Poll 返回配置的受保护 xAI Token。
func (f *staticXAIDeviceFlows) Poll(context.Context, string) (providerxai.Token, error) {
	return f.token, nil
}

// Release records one returned xAI device lease.
// Release 记录一个已归还的 xAI 设备租约。
func (f *staticXAIDeviceFlows) Release(flowID string) {
	f.released.Store(flowID, struct{}{})
}

// Cancel records exact xAI flow consumption.
// Cancel 记录精确的 xAI 流程消费。
func (f *staticXAIDeviceFlows) Cancel(flowID string) {
	f.cancelled.Store(flowID, true)
}

// wasCancelled reports whether the exact xAI flow was consumed.
// wasCancelled 报告精确 xAI 流程是否已消费。
func (f *staticXAIDeviceFlows) wasCancelled(flowID string) bool {
	_, found := f.cancelled.Load(flowID)
	return found
}

// wasReleased reports whether one xAI device lease was returned.
// wasReleased 报告一个 xAI 设备租约是否已归还。
func (f *staticXAIDeviceFlows) wasReleased(flowID string) bool {
	_, found := f.released.Load(flowID)
	return found
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

// Release records one returned Kimi device lease.
// Release 记录一个已归还的 Kimi 设备租约。
func (f *staticKimiDeviceFlows) Release(flowID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.released == nil {
		f.released = make(map[string]bool)
	}
	f.released[flowID] = true
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

// wasReleased reports whether one Kimi device lease was returned.
// wasReleased 报告一个 Kimi 设备租约是否已归还。
func (f *staticKimiDeviceFlows) wasReleased(flowID string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.released[flowID]
}

// staticKimiTokenCommands records one exact management credential refresh dispatch.
// staticKimiTokenCommands 记录一次精确的管理凭据刷新分派。
type staticKimiTokenCommands struct {
	// mu protects the observed immutable identifiers.
	// mu 保护已观察到的不可变标识。
	mu sync.Mutex
	// instanceID is the exact provider instance passed by the route.
	// instanceID 是路由传入的精确供应商实例。
	instanceID string
	// credentialID is the exact credential passed by the route.
	// credentialID 是路由传入的精确凭据。
	credentialID string
}

// RefreshCredential records the exact route binding and returns only safe credential metadata.
// RefreshCredential 记录精确路由绑定并仅返回安全凭据元数据。
func (c *staticKimiTokenCommands) RefreshCredential(_ context.Context, instanceID string, credentialID string) (providerconfig.Credential, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.instanceID = instanceID
	c.credentialID = credentialID
	return providerconfig.Credential{ID: credentialID}, nil
}

// calledWith reports whether the route dispatched the expected immutable pair.
// calledWith 报告路由是否分派了预期的不可变组合。
func (c *staticKimiTokenCommands) calledWith(instanceID string, credentialID string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.instanceID == instanceID && c.credentialID == credentialID
}

// staticCredentialRefreshRecovery records one exact post-refresh runtime recovery dispatch.
// staticCredentialRefreshRecovery 记录一次精确的刷新后运行时恢复分派。
type staticCredentialRefreshRecovery struct {
	// mu protects the observed immutable identifiers.
	// mu 保护已观察到的不可变标识。
	mu sync.Mutex
	// instanceID is the exact provider instance proven by refresh.
	// instanceID 是由刷新证明的精确供应商实例。
	instanceID string
	// credentialID is the exact refreshed credential.
	// credentialID 是精确的已刷新凭据。
	credentialID string
}

// RecordCredentialRefreshSuccess records the exact recovered credential boundary.
// RecordCredentialRefreshSuccess 记录精确的已恢复凭据边界。
func (r *staticCredentialRefreshRecovery) RecordCredentialRefreshSuccess(_ context.Context, instanceID string, credentialID string, _ time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.instanceID = instanceID
	r.credentialID = credentialID
	return nil
}

// calledWith reports whether recovery received the expected immutable pair.
// calledWith 报告恢复逻辑是否收到预期的不可变组合。
func (r *staticCredentialRefreshRecovery) calledWith(instanceID string, credentialID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.instanceID == instanceID && r.credentialID == credentialID
}
