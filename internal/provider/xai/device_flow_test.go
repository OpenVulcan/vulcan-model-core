package xai

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	coreprovider "github.com/OpenVulcan/vulcan-model-core/internal/provider"
)

// TestDeviceFlowClientRefusesRedirectsWithoutMutatingCaller verifies OAuth discovery and token forms stay on their selected origins.
// TestDeviceFlowClientRefusesRedirectsWithoutMutatingCaller 验证 OAuth 发现与 Token 表单停留在其选定源站。
func TestDeviceFlowClientRefusesRedirectsWithoutMutatingCaller(t *testing.T) {
	callerRedirectError := errors.New("caller redirect policy")
	caller := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return callerRedirectError }}
	client, errClient := NewDeviceFlowClientWithEndpoints(caller, "https://device.example/code", "https://device.example/token")
	if errClient != nil {
		t.Fatalf("NewDeviceFlowClientWithEndpoints() error = %v", errClient)
	}
	if client.httpClient == caller {
		t.Fatal("device-flow client retained the caller-owned HTTP client")
	}
	if errRedirect := client.httpClient.CheckRedirect(nil, nil); !errors.Is(errRedirect, http.ErrUseLastResponse) {
		t.Fatalf("device-flow redirect error = %v, want http.ErrUseLastResponse", errRedirect)
	}
	if errRedirect := caller.CheckRedirect(nil, nil); !errors.Is(errRedirect, callerRedirectError) {
		t.Fatalf("caller redirect error = %v, want original policy", errRedirect)
	}
}

// TestXAIFlowLifetimeClampsOversizedProviderValue verifies integer overflow cannot expire a new authorization session.
// TestXAIFlowLifetimeClampsOversizedProviderValue 验证整数溢出不能让新授权会话立即过期。
func TestXAIFlowLifetimeClampsOversizedProviderValue(t *testing.T) {
	if lifetime := xaiFlowLifetime(int(^uint(0) >> 1)); lifetime != maximumFlowLifetime {
		t.Fatalf("xaiFlowLifetime() = %s, want %s", lifetime, maximumFlowLifetime)
	}
}

// TestDeviceFlowClientUsesExactGrokCLIForms verifies the copied public client, scope, and RFC 8628 grants.
// TestDeviceFlowClientUsesExactGrokCLIForms 验证复制的公开客户端、Scope 与 RFC 8628 Grant。
func TestDeviceFlowClientUsesExactGrokCLIForms(t *testing.T) {
	var tokenCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if errParse := request.ParseForm(); errParse != nil {
			t.Fatalf("ParseForm() error = %v", errParse)
		}
		switch request.URL.Path {
		case "/device":
			if request.Form.Get("client_id") != oauthClientID || request.Form.Get("scope") != oauthScope {
				t.Errorf("device form = %#v", request.Form)
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{"device_code": "provider-secret", "user_code": "ABCD-EFGH", "verification_uri_complete": "https://auth.x.ai/device?user_code=ABCD-EFGH", "interval": 5})
		case "/token":
			call := tokenCalls.Add(1)
			if request.Form.Get("client_id") != oauthClientID {
				t.Errorf("token client_id = %q", request.Form.Get("client_id"))
			}
			if call == 1 {
				if request.Form.Get("grant_type") != deviceCodeGrantType || request.Form.Get("device_code") != "provider-secret" {
					t.Errorf("exchange form = %#v", request.Form)
				}
				_ = json.NewEncoder(writer).Encode(map[string]any{"access_token": "access-before", "refresh_token": "refresh-before", "id_token": "identity-before", "token_type": "Bearer", "expires_in": 3600})
				return
			}
			if request.Form.Get("grant_type") != "refresh_token" || request.Form.Get("refresh_token") != "refresh-before" {
				t.Errorf("refresh form = %#v", request.Form)
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{"access_token": "access-after", "token_type": "Bearer", "expires_in": 3600})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	client, errClient := NewDeviceFlowClientWithEndpoints(server.Client(), server.URL+"/device", server.URL+"/token")
	if errClient != nil {
		t.Fatalf("NewDeviceFlowClientWithEndpoints() error = %v", errClient)
	}
	code, errStart := client.Start(context.Background())
	if errStart != nil || code.TokenEndpoint != server.URL+"/token" || code.VerificationURI != "https://auth.x.ai/device?user_code=ABCD-EFGH" || code.ExpiresIn != 0 {
		t.Fatalf("Start() code=%#v error=%v", code, errStart)
	}
	token, errExchange := client.Exchange(context.Background(), code)
	if errExchange != nil || token.AccessToken != "access-before" || token.Type != "xai" {
		t.Fatalf("Exchange() token=%#v error=%v", token, errExchange)
	}
	refreshed, errRefresh := client.Refresh(context.Background(), token)
	if errRefresh != nil || refreshed.AccessToken != "access-after" || refreshed.RefreshToken != "refresh-before" || refreshed.IDToken != "identity-before" {
		t.Fatalf("Refresh() token=%#v error=%v", refreshed, errRefresh)
	}
}

// TestDeviceFlowClientMapsRFC8628Errors verifies the terminal and retryable provider states.
// TestDeviceFlowClientMapsRFC8628Errors 验证终止态与可重试供应商状态。
func TestDeviceFlowClientMapsRFC8628Errors(t *testing.T) {
	tests := []struct {
		// name labels the isolated RFC 8628 state.
		// name 标记隔离的 RFC 8628 状态。
		name string
		// code is the provider error code.
		// code 是供应商错误码。
		code string
		// expected is the stable Vulcan flow error.
		// expected 是稳定的 Vulcan 流程错误。
		expected error
	}{{"pending", "authorization_pending", ErrAuthorizationPending}, {"slow down", "slow_down", ErrAuthorizationPending}, {"expired", "expired_token", ErrAuthorizationExpired}, {"denied", "access_denied", ErrAuthorizationDenied}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(writer).Encode(map[string]string{"error": test.code})
			}))
			defer server.Close()
			client, errClient := NewDeviceFlowClientWithEndpoints(server.Client(), server.URL+"/device", server.URL+"/token")
			if errClient != nil {
				t.Fatalf("NewDeviceFlowClientWithEndpoints() error = %v", errClient)
			}
			_, errExchange := client.Exchange(context.Background(), DeviceCode{DeviceCode: "secret", TokenEndpoint: server.URL + "/token"})
			if !errors.Is(errExchange, test.expected) {
				t.Fatalf("Exchange() error = %v, want %v", errExchange, test.expected)
			}
		})
	}
}

// TestDeviceFlowClientAcceptsAccessOnlyToken verifies CLIProxyAPI-compatible device responses do not require a refresh token.
// TestDeviceFlowClientAcceptsAccessOnlyToken 验证兼容 CLIProxyAPI 的设备授权响应不强制要求 Refresh Token。
func TestDeviceFlowClientAcceptsAccessOnlyToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(writer).Encode(map[string]any{"access_token": "access-only", "token_type": "Bearer", "expires_in": 3600})
	}))
	defer server.Close()
	client, errClient := NewDeviceFlowClientWithEndpoints(server.Client(), server.URL+"/device", server.URL+"/token")
	if errClient != nil {
		t.Fatalf("NewDeviceFlowClientWithEndpoints() error = %v", errClient)
	}
	token, errExchange := client.Exchange(context.Background(), DeviceCode{DeviceCode: "provider-secret", TokenEndpoint: server.URL + "/token"})
	if errExchange != nil || token.AccessToken != "access-only" || token.RefreshToken != "" {
		t.Fatalf("Exchange() token=%#v error=%v", token, errExchange)
	}
	token.TokenEndpoint = "https://auth.x.ai/oauth/token"
	if _, errMarshal := MarshalToken(token); errMarshal != nil {
		t.Fatalf("MarshalToken() error = %v", errMarshal)
	}
	token.TokenEndpoint = server.URL + "/token"
	if _, errRefresh := client.Refresh(context.Background(), token); !errors.Is(errRefresh, coreprovider.ErrAuthenticationRejected) {
		t.Fatalf("Refresh() error = %v, want ErrAuthenticationRejected", errRefresh)
	}
}

// TestProtectedTokenRejectsUntrustedEndpoint verifies persisted refresh credentials cannot target arbitrary hosts.
// TestProtectedTokenRejectsUntrustedEndpoint 验证持久化刷新凭据不能指向任意主机。
func TestProtectedTokenRejectsUntrustedEndpoint(t *testing.T) {
	token := Token{AccessToken: "access", RefreshToken: "refresh", TokenEndpoint: "https://example.com/oauth/token", Type: "xai"}
	if _, errMarshal := MarshalToken(token); errMarshal == nil {
		t.Fatal("MarshalToken() unexpectedly accepted an untrusted token endpoint")
	}
	document, errDocument := json.Marshal(token)
	if errDocument != nil {
		t.Fatalf("json.Marshal() error = %v", errDocument)
	}
	if _, errUnmarshal := UnmarshalToken(document); errUnmarshal == nil {
		t.Fatal("UnmarshalToken() unexpectedly accepted an untrusted token endpoint")
	}
}

// TestDeviceFlowClientRejectsMismatchedFixedRefreshEndpoint verifies test isolation cannot be bypassed by token data.
// TestDeviceFlowClientRejectsMismatchedFixedRefreshEndpoint 验证 Token 数据不能绕过测试隔离入口。
func TestDeviceFlowClientRejectsMismatchedFixedRefreshEndpoint(t *testing.T) {
	client, errClient := NewDeviceFlowClientWithEndpoints(http.DefaultClient, "http://127.0.0.1/device", "http://127.0.0.1/token")
	if errClient != nil {
		t.Fatalf("NewDeviceFlowClientWithEndpoints() error = %v", errClient)
	}
	_, errRefresh := client.Refresh(context.Background(), Token{AccessToken: "access", RefreshToken: "refresh", TokenEndpoint: "http://127.0.0.1/other", Type: "xai"})
	if !errors.Is(errRefresh, coreprovider.ErrAuthenticationResponseInvalid) {
		t.Fatalf("Refresh() error = %v, want ErrAuthenticationResponseInvalid", errRefresh)
	}
}

// TestDeviceFlowClientRefreshClassifiesAuthenticationFailures verifies the management-safe xAI refresh taxonomy.
// TestDeviceFlowClientRefreshClassifiesAuthenticationFailures 验证管理安全的 xAI 刷新错误分类。
func TestDeviceFlowClientRefreshClassifiesAuthenticationFailures(t *testing.T) {
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
			client, errClient := NewDeviceFlowClientWithEndpoints(server.Client(), server.URL+"/device", server.URL+"/token")
			if errClient != nil {
				t.Fatalf("NewDeviceFlowClientWithEndpoints() error = %v", errClient)
			}
			_, errRefresh := client.Refresh(context.Background(), Token{AccessToken: "access-before", RefreshToken: "refresh-before", TokenEndpoint: server.URL + "/token", Type: "xai"})
			if !errors.Is(errRefresh, test.expectedError) {
				t.Fatalf("Refresh() error = %v, want category %v", errRefresh, test.expectedError)
			}
		})
	}
}

// TestDeviceFlowClientRejectsOversizedTokenResponse verifies provider data cannot bypass the bounded decoder.
// TestDeviceFlowClientRejectsOversizedTokenResponse 验证供应商数据不能绕过有界解码器。
func TestDeviceFlowClientRejectsOversizedTokenResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(strings.Repeat("x", maximumOAuthResponseBytes+1)))
	}))
	defer server.Close()
	client, errClient := NewDeviceFlowClientWithEndpoints(server.Client(), server.URL+"/device", server.URL+"/token")
	if errClient != nil {
		t.Fatalf("NewDeviceFlowClientWithEndpoints() error = %v", errClient)
	}
	_, errExchange := client.Exchange(context.Background(), DeviceCode{DeviceCode: "secret", TokenEndpoint: server.URL + "/token"})
	if errExchange == nil || !strings.Contains(errExchange.Error(), "exceeds the allowed size") {
		t.Fatalf("Exchange() error = %v", errExchange)
	}
}

// TestTokenExpiryRejectsDurationOverflow verifies malicious expiry values are rejected instead of silently becoming valid tokens.
// TestTokenExpiryRejectsDurationOverflow 验证恶意过期值会被拒绝，而不会静默变成有效 Token。
func TestTokenExpiryRejectsDurationOverflow(t *testing.T) {
	if strconv.IntSize < 64 {
		t.Skip("duration-overflow input does not fit in a 32-bit int")
	}
	maximumDurationSeconds := int64(time.Duration(1<<63-1) / time.Second)
	if _, errExpiry := tokenExpiry(int(maximumDurationSeconds + 1)); errExpiry == nil {
		t.Fatal("tokenExpiry() unexpectedly accepted a duration-overflow value")
	}
}

// TestValidateOAuthEndpointConfinesDiscovery verifies that discovery cannot redirect credentials outside x.ai HTTPS hosts.
// TestValidateOAuthEndpointConfinesDiscovery 验证发现过程不能将凭据重定向到 x.ai HTTPS 主机之外。
func TestValidateOAuthEndpointConfinesDiscovery(t *testing.T) {
	valid, errValid := validateOAuthEndpoint("https://auth.x.ai/oauth/token")
	if errValid != nil || valid != "https://auth.x.ai/oauth/token" {
		t.Fatalf("validateOAuthEndpoint(valid) = %q, %v", valid, errValid)
	}
	for _, candidate := range []string{"http://auth.x.ai/oauth/token", "https://x.ai.attacker.example/token", "https://example.com/token"} {
		if _, errInvalid := validateOAuthEndpoint(candidate); errInvalid == nil {
			t.Fatalf("validateOAuthEndpoint(%q) unexpectedly succeeded", candidate)
		}
	}
}

// TestFlowManagerKeepsSuccessUntilExplicitConsumption verifies retry-safe token retention after provider completion.
// TestFlowManagerKeepsSuccessUntilExplicitConsumption 验证供应商完成后可安全重试的 Token 保留行为。
func TestFlowManagerKeepsSuccessUntilExplicitConsumption(t *testing.T) {
	var exchanges atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/device":
			_ = json.NewEncoder(writer).Encode(map[string]any{"device_code": "provider-secret", "user_code": "ABCD-EFGH", "verification_uri": "https://auth.x.ai/device", "expires_in": 600, "interval": 5})
		case "/token":
			exchanges.Add(1)
			_ = json.NewEncoder(writer).Encode(map[string]any{"access_token": "access", "refresh_token": "refresh", "token_type": "Bearer", "expires_in": 3600})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client, errClient := NewDeviceFlowClientWithEndpoints(server.Client(), server.URL+"/device", server.URL+"/token")
	if errClient != nil {
		t.Fatalf("NewDeviceFlowClientWithEndpoints() error = %v", errClient)
	}
	manager, errManager := NewFlowManager(client)
	if errManager != nil {
		t.Fatalf("NewFlowManager() error = %v", errManager)
	}
	now := time.Date(2026, 7, 19, 10, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }
	flow, errStart := manager.Start(context.Background())
	if errStart != nil {
		t.Fatalf("Start() error = %v", errStart)
	}
	token, errPoll := manager.Poll(context.Background(), flow.ID)
	if errPoll != nil || token.AccessToken != "access" {
		t.Fatalf("Poll() token=%#v error=%v", token, errPoll)
	}
	if _, errLeased := manager.Poll(context.Background(), flow.ID); !errors.Is(errLeased, ErrAuthorizationPending) {
		t.Fatalf("leased Poll() error = %v, want ErrAuthorizationPending", errLeased)
	}
	manager.Release(flow.ID)
	cached, errCached := manager.Poll(context.Background(), flow.ID)
	if errCached != nil || cached.AccessToken != "access" || exchanges.Load() != 1 {
		t.Fatalf("released cached Poll() token=%#v error=%v exchanges=%d", cached, errCached, exchanges.Load())
	}
	manager.Cancel(flow.ID)
	if _, errConsumed := manager.Poll(context.Background(), flow.ID); !errors.Is(errConsumed, ErrFlowNotFound) {
		t.Fatalf("cancelled Poll() error = %v, want ErrFlowNotFound", errConsumed)
	}
}

// TestFlowManagerRejectsOverlappingProviderExchanges verifies elapsed polling cadence cannot start a second request while the first remains active.
// TestFlowManagerRejectsOverlappingProviderExchanges 验证轮询间隔已过也不能在首个请求仍活动时启动第二个请求。
func TestFlowManagerRejectsOverlappingProviderExchanges(t *testing.T) {
	var exchanges atomic.Int32
	exchangeStarted := make(chan struct{})
	releaseExchange := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/device":
			_ = json.NewEncoder(writer).Encode(map[string]any{"device_code": "provider-secret", "user_code": "ABCD-EFGH", "verification_uri": "https://auth.x.ai/device", "expires_in": 600, "interval": 5})
		case "/token":
			if exchanges.Add(1) == 1 {
				close(exchangeStarted)
			}
			<-releaseExchange
			_ = json.NewEncoder(writer).Encode(map[string]any{"access_token": "access", "refresh_token": "refresh", "token_type": "Bearer", "expires_in": 3600})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client, errClient := NewDeviceFlowClientWithEndpoints(server.Client(), server.URL+"/device", server.URL+"/token")
	if errClient != nil {
		t.Fatalf("NewDeviceFlowClientWithEndpoints() error = %v", errClient)
	}
	manager, errManager := NewFlowManager(client)
	if errManager != nil {
		t.Fatalf("NewFlowManager() error = %v", errManager)
	}
	now := time.Date(2026, 7, 19, 11, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }
	flow, errStart := manager.Start(context.Background())
	if errStart != nil {
		t.Fatalf("Start() error = %v", errStart)
	}
	pollResult := make(chan error, 1)
	go func() {
		_, errPoll := manager.Poll(context.Background(), flow.ID)
		pollResult <- errPoll
	}()
	<-exchangeStarted
	now = now.Add(5 * time.Second)
	overlapContext, cancelOverlap := context.WithTimeout(context.Background(), 100*time.Millisecond)
	_, errOverlap := manager.Poll(overlapContext, flow.ID)
	cancelOverlap()
	close(releaseExchange)
	if !errors.Is(errOverlap, ErrAuthorizationPending) || exchanges.Load() != 1 {
		t.Fatalf("overlapping Poll() error = %v exchanges = %d", errOverlap, exchanges.Load())
	}
	if errPoll := <-pollResult; errPoll != nil {
		t.Fatalf("first Poll() error = %v", errPoll)
	}
}

// TestFlowManagerCopiesMinimumIntervalAndSlowDown verifies CLIProxyAPI's RFC 8628 scheduling behavior.
// TestFlowManagerCopiesMinimumIntervalAndSlowDown 验证 CLIProxyAPI 的 RFC 8628 调度行为。
func TestFlowManagerCopiesMinimumIntervalAndSlowDown(t *testing.T) {
	var exchanges atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/device":
			_ = json.NewEncoder(writer).Encode(map[string]any{"device_code": "provider-secret", "user_code": "ABCD-EFGH", "verification_uri": "https://auth.x.ai/device", "expires_in": 600})
		case "/token":
			exchanges.Add(1)
			_ = json.NewEncoder(writer).Encode(map[string]string{"error": "slow_down"})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client, errClient := NewDeviceFlowClientWithEndpoints(server.Client(), server.URL+"/device", server.URL+"/token")
	if errClient != nil {
		t.Fatalf("NewDeviceFlowClientWithEndpoints() error = %v", errClient)
	}
	manager, errManager := NewFlowManager(client)
	if errManager != nil {
		t.Fatalf("NewFlowManager() error = %v", errManager)
	}
	now := time.Date(2026, 7, 19, 10, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }
	flow, errStart := manager.Start(context.Background())
	if errStart != nil || flow.PollIntervalSeconds != 5 {
		t.Fatalf("Start() flow=%#v error=%v", flow, errStart)
	}
	if _, errPoll := manager.Poll(context.Background(), flow.ID); !errors.Is(errPoll, ErrAuthorizationPending) {
		t.Fatalf("Poll() error = %v, want ErrAuthorizationPending", errPoll)
	}
	now = now.Add(5 * time.Second)
	if _, errEarly := manager.Poll(context.Background(), flow.ID); !errors.Is(errEarly, ErrAuthorizationPending) || exchanges.Load() != 1 {
		t.Fatalf("early Poll() error=%v exchanges=%d", errEarly, exchanges.Load())
	}
	manager.mu.Lock()
	stored := manager.sessions[flow.ID]
	manager.mu.Unlock()
	if stored.flow.PollIntervalSeconds != 10 {
		t.Fatalf("slow_down interval = %d, want 10", stored.flow.PollIntervalSeconds)
	}
}

// TestXAIIntervalsClampOversizedProviderValues verifies polling conversion and slow-down increments cannot overflow.
// TestXAIIntervalsClampOversizedProviderValues 验证轮询转换与减速增量不会溢出。
func TestXAIIntervalsClampOversizedProviderValues(t *testing.T) {
	maximumSeconds := int(maximumFlowLifetime / time.Second)
	if interval := xaiPollInterval(int(^uint(0) >> 1)); interval != maximumFlowLifetime {
		t.Fatalf("xaiPollInterval() = %s, want %s", interval, maximumFlowLifetime)
	}
	if interval := xaiPollInterval(1); interval != defaultPollInterval {
		t.Fatalf("xaiPollInterval() minimum = %s, want %s", interval, defaultPollInterval)
	}
	if interval := xaiSlowDownInterval(maximumSeconds); interval != maximumSeconds {
		t.Fatalf("xaiSlowDownInterval() = %d, want %d", interval, maximumSeconds)
	}
}

// TestTokenRequestFormEncodingIsStable documents the URL encoding used for copied OAuth values.
// TestTokenRequestFormEncodingIsStable 记录复制 OAuth 值所使用的 URL 编码。
func TestTokenRequestFormEncodingIsStable(t *testing.T) {
	encoded := url.Values{"scope": {oauthScope}}.Encode()
	if !strings.Contains(encoded, "grok-cli%3Aaccess") || !strings.Contains(encoded, "api%3Aaccess") {
		t.Fatalf("encoded scope = %q", encoded)
	}
}

// TestParseJWTIdentityCopiesCLIProxyAccountFields verifies the exact email and subject claim projection.
// TestParseJWTIdentityCopiesCLIProxyAccountFields 验证精确的邮箱与 Subject 声明投影。
func TestParseJWTIdentityCopiesCLIProxyAccountFields(t *testing.T) {
	payload, errPayload := json.Marshal(map[string]string{"email": " user@x.ai ", "sub": " subject-one "})
	if errPayload != nil {
		t.Fatalf("json.Marshal() error = %v", errPayload)
	}
	idToken := "header." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
	email, subject := parseJWTIdentity(idToken)
	if email != "user@x.ai" || subject != "subject-one" {
		t.Fatalf("parseJWTIdentity() = %q, %q", email, subject)
	}
	expiresAt, errExpiry := tokenExpiry(0)
	if errExpiry != nil || expiresAt != 0 {
		t.Fatalf("tokenExpiry(0) = %d, %v; want 0, nil", expiresAt, errExpiry)
	}
}
