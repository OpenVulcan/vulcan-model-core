package google

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	coreprovider "github.com/OpenVulcan/vulcan-model-core/internal/provider"
)

// TestAntigravityOAuthClientRefusesRedirectsWithoutMutatingCaller verifies OAuth credentials and access tokens remain on selected origins.
// TestAntigravityOAuthClientRefusesRedirectsWithoutMutatingCaller 验证 OAuth 凭据与 Access Token 保持在选定源站。
func TestAntigravityOAuthClientRefusesRedirectsWithoutMutatingCaller(t *testing.T) {
	callerRedirectError := errors.New("caller redirect policy")
	caller := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return callerRedirectError }}
	client, errClient := NewAntigravityOAuthClientWithEndpoints(caller, "https://oauth.example/token", "https://oauth.example/user", "https://api.example", "https://daily.example")
	if errClient != nil {
		t.Fatalf("NewAntigravityOAuthClientWithEndpoints() error = %v", errClient)
	}
	if client.httpClient == caller {
		t.Fatal("Antigravity OAuth client retained the caller-owned HTTP client")
	}
	if errRedirect := client.httpClient.CheckRedirect(nil, nil); !errors.Is(errRedirect, http.ErrUseLastResponse) {
		t.Fatalf("Antigravity OAuth redirect error = %v, want http.ErrUseLastResponse", errRedirect)
	}
	if errRedirect := caller.CheckRedirect(nil, nil); !errors.Is(errRedirect, callerRedirectError) {
		t.Fatalf("caller redirect error = %v, want original policy", errRedirect)
	}
}

// TestAntigravityOAuthCopiesExactConsentExchangeAndRefresh verifies the complete copied account flow.
// TestAntigravityOAuthCopiesExactConsentExchangeAndRefresh 验证完整复制的账号授权流程。
func TestAntigravityOAuthCopiesExactConsentExchangeAndRefresh(t *testing.T) {
	var tokenCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/token":
			if errParse := request.ParseForm(); errParse != nil {
				t.Errorf("ParseForm() error = %v", errParse)
			}
			if request.Form.Get("client_id") != antigravityOAuthClientID || request.Form.Get("client_secret") != antigravityOAuthClientSecret {
				t.Errorf("token form = %#v", request.Form)
			}
			if tokenCalls.Add(1) == 1 {
				if request.Form.Get("grant_type") != "authorization_code" || request.Form.Get("redirect_uri") != antigravityRedirectURI || request.Form.Get("code") != "authorization-code" {
					t.Errorf("exchange form = %#v", request.Form)
				}
				_ = json.NewEncoder(writer).Encode(map[string]any{"access_token": "access-before", "refresh_token": "refresh-before", "token_type": "Bearer", "expires_in": 3600})
				return
			}
			if request.Form.Get("grant_type") != "refresh_token" || request.Form.Get("refresh_token") != "refresh-before" {
				t.Errorf("refresh form = %#v", request.Form)
			}
			if request.UserAgent() != "Go-http-client/2.0" {
				t.Errorf("refresh User-Agent = %q", request.UserAgent())
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{"access_token": "access-after", "token_type": "Bearer", "expires_in": 3600})
		case "/userinfo":
			if request.Header.Get("Authorization") != "Bearer access-before" || request.Header.Get("User-Agent") != AntigravityRequestUserAgent("") {
				t.Errorf("userinfo headers = %#v", request.Header)
			}
			_ = json.NewEncoder(writer).Encode(map[string]string{"email": "user@example.com"})
		case "/v1internal:loadCodeAssist":
			if request.Header.Get("Authorization") != "Bearer access-before" || request.Header.Get("User-Agent") != AntigravityLoadCodeAssistUserAgent("") {
				t.Errorf("loadCodeAssist headers = %#v", request.Header)
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{"cloudaicompanionProject": map[string]string{"id": "project-one"}})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	client, errClient := NewAntigravityOAuthClientWithEndpoints(server.Client(), server.URL+"/token", server.URL+"/userinfo", server.URL, server.URL)
	if errClient != nil {
		t.Fatalf("NewAntigravityOAuthClientWithEndpoints() error = %v", errClient)
	}
	authorizationURL, errURL := url.Parse(client.AuthorizationURL("state-one"))
	if errURL != nil {
		t.Fatalf("url.Parse() error = %v", errURL)
	}
	query := authorizationURL.Query()
	if query.Get("access_type") != "offline" || query.Get("prompt") != "consent" || query.Get("redirect_uri") != antigravityRedirectURI || query.Get("scope") != strings.Join(antigravityScopes, " ") {
		t.Fatalf("authorization query = %#v", query)
	}
	callback := antigravityRedirectURI + "?code=authorization-code&state=state-one"
	token, errExchange := client.ExchangeCallback(context.Background(), callback, "state-one")
	if errExchange != nil || token.Email != "user@example.com" || token.ProjectID != "project-one" || token.Type != "antigravity" {
		t.Fatalf("ExchangeCallback() token=%#v error=%v", token, errExchange)
	}
	refreshed, errRefresh := client.Refresh(context.Background(), token)
	if errRefresh != nil || refreshed.AccessToken != "access-after" || refreshed.RefreshToken != "refresh-before" || refreshed.ProjectID != "project-one" {
		t.Fatalf("Refresh() token=%#v error=%v", refreshed, errRefresh)
	}
}

// TestAntigravityRefreshClassifiesAuthenticationFailures verifies the management-safe Google refresh taxonomy.
// TestAntigravityRefreshClassifiesAuthenticationFailures 验证管理安全的 Google 刷新错误分类。
func TestAntigravityRefreshClassifiesAuthenticationFailures(t *testing.T) {
	tests := []struct {
		// name labels the isolated provider response.
		// name 标记隔离的供应商响应。
		name string
		// statusCode is the provider HTTP status.
		// statusCode 是供应商 HTTP 状态码。
		statusCode int
		// body is the exact provider response body.
		// body 是精确的供应商响应正文。
		body string
		// expectedError is the stable authentication category.
		// expectedError 是稳定的认证错误分类。
		expectedError error
	}{
		{name: "rejected", statusCode: http.StatusUnauthorized, body: `{"error":"invalid_grant"}`, expectedError: coreprovider.ErrAuthenticationRejected},
		{name: "request timeout", statusCode: http.StatusRequestTimeout, body: `{}`, expectedError: coreprovider.ErrAuthenticationUnavailable},
		{name: "unavailable", statusCode: http.StatusServiceUnavailable, body: `{}`, expectedError: coreprovider.ErrAuthenticationUnavailable},
		{name: "invalid response", statusCode: http.StatusOK, body: `{}`, expectedError: coreprovider.ErrAuthenticationResponseInvalid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(test.statusCode)
				_, _ = writer.Write([]byte(test.body))
			}))
			defer server.Close()
			client, errClient := NewAntigravityOAuthClientWithEndpoints(server.Client(), server.URL+"/token", server.URL+"/userinfo", server.URL, server.URL)
			if errClient != nil {
				t.Fatalf("NewAntigravityOAuthClientWithEndpoints() error = %v", errClient)
			}
			_, errRefresh := client.Refresh(context.Background(), AntigravityToken{AccessToken: "access-before", RefreshToken: "refresh-before", Email: "user@example.com", ProjectID: "project-one", Type: "antigravity"})
			if !errors.Is(errRefresh, test.expectedError) {
				t.Fatalf("Refresh() error = %v, want category %v", errRefresh, test.expectedError)
			}
		})
	}
}

// TestAntigravityProjectLookupCopiesOnboardFallback verifies default-tier selection and completed project provisioning.
// TestAntigravityProjectLookupCopiesOnboardFallback 验证默认套餐选择与已完成项目配置。
func TestAntigravityProjectLookupCopiesOnboardFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1internal:loadCodeAssist":
			_ = json.NewEncoder(writer).Encode(map[string]any{"allowedTiers": []any{map[string]any{"id": "paid-tier", "isDefault": true}}})
		case "/v1internal:onboardUser":
			if request.Header.Get("User-Agent") != AntigravityOnboardUserUserAgent("") || request.Header.Get("X-Goog-Api-Client") != antigravityGoogAPIClientUA {
				t.Errorf("onboard headers = %#v", request.Header)
			}
			var payload map[string]any
			_ = json.NewDecoder(request.Body).Decode(&payload)
			if payload["tier_id"] != "paid-tier" {
				t.Errorf("onboard payload = %#v", payload)
			}
			metadata, hasMetadata := payload["metadata"].(map[string]any)
			if !hasMetadata || metadata["ide_version"] != AntigravityLatestVersion() {
				t.Errorf("onboard metadata = %#v", payload["metadata"])
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{"done": true, "response": map[string]any{"projectId": "project-onboarded"}})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client, errClient := NewAntigravityOAuthClientWithEndpoints(server.Client(), server.URL+"/token", server.URL+"/userinfo", server.URL, server.URL)
	if errClient != nil {
		t.Fatalf("NewAntigravityOAuthClientWithEndpoints() error = %v", errClient)
	}
	projectID, errProject := client.fetchProjectID(context.Background(), "access")
	if errProject != nil || projectID != "project-onboarded" {
		t.Fatalf("fetchProjectID() = %q, %v", projectID, errProject)
	}
}

// TestAntigravityOAuthRejectsOversizedResponse verifies the shared strict response boundary.
// TestAntigravityOAuthRejectsOversizedResponse 验证共享的严格响应边界。
func TestAntigravityOAuthRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(strings.Repeat("x", antigravityControlResponseLimit+1)))
	}))
	defer server.Close()
	client, errClient := NewAntigravityOAuthClientWithEndpoints(server.Client(), server.URL, server.URL, server.URL, server.URL)
	if errClient != nil {
		t.Fatalf("NewAntigravityOAuthClientWithEndpoints() error = %v", errClient)
	}
	if _, errToken := client.requestToken(context.Background(), url.Values{}); errToken == nil || !strings.Contains(errToken.Error(), "exceeds the response limit") {
		t.Fatalf("requestToken() error = %v", errToken)
	}
}

// TestAntigravityTokenExpiryRejectsOverflow verifies hostile provider lifetime rejection.
// TestAntigravityTokenExpiryRejectsOverflow 验证拒绝恶意供应商有效期。
func TestAntigravityTokenExpiryRejectsOverflow(t *testing.T) {
	if _, errExpiry := antigravityTokenExpiry(math.MaxInt64); errExpiry == nil {
		t.Fatal("antigravityTokenExpiry() unexpectedly accepted overflow")
	}
}

// TestParseAntigravityCallbackRejectsWrongRedirectAndState verifies the server-owned CSRF boundary.
// TestParseAntigravityCallbackRejectsWrongRedirectAndState 验证服务端拥有的 CSRF 边界。
func TestParseAntigravityCallbackRejectsWrongRedirectAndState(t *testing.T) {
	for _, callback := range []string{"https://localhost:51121/oauth-callback?code=x&state=s", "http://localhost:51121/wrong?code=x&state=s", "http://localhost:51121/oauth-callback?code=x&state=wrong", "http://localhost:51121/oauth-callback?code=x&code=y&state=s", "http://localhost:51121/oauth-callback?code=x&state=s#fragment"} {
		if _, errCallback := parseAntigravityCallback(callback, "s"); errCallback == nil {
			t.Fatalf("parseAntigravityCallback(%q) unexpectedly succeeded", callback)
		}
	}
}

// TestAntigravityFlowManagerKeepsSuccessUntilExplicitConsumption verifies retry-safe token retention after OAuth completion.
// TestAntigravityFlowManagerKeepsSuccessUntilExplicitConsumption 验证 OAuth 完成后可安全重试的 Token 保留行为。
func TestAntigravityFlowManagerKeepsSuccessUntilExplicitConsumption(t *testing.T) {
	var exchanges atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/token":
			exchanges.Add(1)
			_ = json.NewEncoder(writer).Encode(map[string]any{"access_token": "access", "refresh_token": "refresh", "token_type": "Bearer", "expires_in": 3600})
		case "/userinfo":
			_ = json.NewEncoder(writer).Encode(map[string]string{"email": "user@example.com"})
		case "/v1internal:loadCodeAssist":
			_ = json.NewEncoder(writer).Encode(map[string]any{"cloudaicompanionProject": map[string]string{"id": "project-one"}})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client, errClient := NewAntigravityOAuthClientWithEndpoints(server.Client(), server.URL+"/token", server.URL+"/userinfo", server.URL, server.URL)
	if errClient != nil {
		t.Fatalf("NewAntigravityOAuthClientWithEndpoints() error = %v", errClient)
	}
	manager, errManager := NewAntigravityFlowManager(client)
	if errManager != nil {
		t.Fatalf("NewAntigravityFlowManager() error = %v", errManager)
	}
	flow, errStart := manager.Start(context.Background())
	if errStart != nil {
		t.Fatalf("Start() error = %v", errStart)
	}
	authorizationURL, errURL := url.Parse(flow.AuthorizationURL)
	if errURL != nil {
		t.Fatalf("url.Parse() error = %v", errURL)
	}
	callback := antigravityRedirectURI + "?code=authorization-code&state=" + url.QueryEscape(authorizationURL.Query().Get("state"))
	token, errComplete := manager.Complete(context.Background(), flow.ID, callback)
	if errComplete != nil || token.AccessToken != "access" {
		t.Fatalf("Complete() token=%#v error=%v", token, errComplete)
	}
	if _, errLeased := manager.Complete(context.Background(), flow.ID, callback); errLeased != ErrAntigravityFlowInProgress {
		t.Fatalf("leased Complete() error = %v, want ErrAntigravityFlowInProgress", errLeased)
	}
	manager.Release(flow.ID)
	cached, errCached := manager.Complete(context.Background(), flow.ID, callback)
	if errCached != nil || cached.AccessToken != "access" || exchanges.Load() != 1 {
		t.Fatalf("released cached Complete() token=%#v error=%v exchanges=%d", cached, errCached, exchanges.Load())
	}
	manager.Cancel(flow.ID)
	if _, errMissing := manager.Complete(context.Background(), flow.ID, callback); errMissing != ErrAntigravityFlowNotFound {
		t.Fatalf("cancelled Complete() error = %v, want ErrAntigravityFlowNotFound", errMissing)
	}
}

// TestAntigravityFlowManagerRejectsDuplicateAndDoesNotRestoreCancelledExchange verifies concurrent completion ownership.
// TestAntigravityFlowManagerRejectsDuplicateAndDoesNotRestoreCancelledExchange 验证并发完成请求的所有权边界。
func TestAntigravityFlowManagerRejectsDuplicateAndDoesNotRestoreCancelledExchange(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/token":
			close(started)
			<-release
			_ = json.NewEncoder(writer).Encode(map[string]any{"access_token": "access", "refresh_token": "refresh", "token_type": "Bearer", "expires_in": 3600})
		case "/userinfo":
			_ = json.NewEncoder(writer).Encode(map[string]string{"email": "user@example.com"})
		case "/v1internal:loadCodeAssist":
			_ = json.NewEncoder(writer).Encode(map[string]any{"cloudaicompanionProject": map[string]string{"id": "project-one"}})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client, errClient := NewAntigravityOAuthClientWithEndpoints(server.Client(), server.URL+"/token", server.URL+"/userinfo", server.URL, server.URL)
	if errClient != nil {
		t.Fatalf("NewAntigravityOAuthClientWithEndpoints() error = %v", errClient)
	}
	manager, errManager := NewAntigravityFlowManager(client)
	if errManager != nil {
		t.Fatalf("NewAntigravityFlowManager() error = %v", errManager)
	}
	flow, errStart := manager.Start(context.Background())
	if errStart != nil {
		t.Fatalf("Start() error = %v", errStart)
	}
	authorizationURL, errURL := url.Parse(flow.AuthorizationURL)
	if errURL != nil {
		t.Fatalf("url.Parse() error = %v", errURL)
	}
	callback := antigravityRedirectURI + "?code=authorization-code&state=" + url.QueryEscape(authorizationURL.Query().Get("state"))
	result := make(chan error, 1)
	go func() {
		_, errComplete := manager.Complete(context.Background(), flow.ID, callback)
		result <- errComplete
	}()
	<-started
	if _, errDuplicate := manager.Complete(context.Background(), flow.ID, callback); errDuplicate != ErrAntigravityFlowInProgress {
		t.Fatalf("duplicate Complete() error = %v, want ErrAntigravityFlowInProgress", errDuplicate)
	}
	manager.Cancel(flow.ID)
	close(release)
	if errComplete := <-result; errComplete != ErrAntigravityFlowNotFound {
		t.Fatalf("cancelled in-flight Complete() error = %v, want ErrAntigravityFlowNotFound", errComplete)
	}
}
