package openai

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	coreprovider "github.com/OpenVulcan/vulcan-model-core/internal/provider"
)

// TestParseCodexPollIntervalClampsOversizedValues verifies string and integer provider forms cannot wrap the local schedule.
// TestParseCodexPollIntervalClampsOversizedValues 验证供应商字符串与整数形式不能使本地轮询计划回绕。
func TestParseCodexPollIntervalClampsOversizedValues(t *testing.T) {
	for _, raw := range []json.RawMessage{json.RawMessage(`"9223372036854775807"`), json.RawMessage(`9223372036854775807`)} {
		if interval := parseCodexPollInterval(raw); interval != codexDeviceLifetime {
			t.Fatalf("parseCodexPollInterval(%s) = %s, want %s", raw, interval, codexDeviceLifetime)
		}
	}
	if interval := parseCodexPollInterval(json.RawMessage(`0`)); interval != codexDefaultPollInterval {
		t.Fatalf("parseCodexPollInterval(0) = %s, want %s", interval, codexDefaultPollInterval)
	}
}

// TestCodexDeviceFlowClientRefusesRedirectsWithoutMutatingCaller verifies device and refresh forms cannot leave their configured origins.
// TestCodexDeviceFlowClientRefusesRedirectsWithoutMutatingCaller 验证设备与刷新表单不能离开其配置源站。
func TestCodexDeviceFlowClientRefusesRedirectsWithoutMutatingCaller(t *testing.T) {
	callerRedirectError := errors.New("caller redirect policy")
	caller := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return callerRedirectError }}
	client, errClient := NewCodexDeviceFlowClientWithEndpoints(caller, "https://device.example/user", "https://device.example/token", "https://oauth.example/token")
	if errClient != nil {
		t.Fatalf("NewCodexDeviceFlowClientWithEndpoints() error = %v", errClient)
	}
	if client.httpClient == caller {
		t.Fatal("Codex device-flow client retained the caller-owned HTTP client")
	}
	if errRedirect := client.httpClient.CheckRedirect(nil, nil); !errors.Is(errRedirect, http.ErrUseLastResponse) {
		t.Fatalf("Codex device-flow redirect error = %v, want http.ErrUseLastResponse", errRedirect)
	}
	if errRedirect := caller.CheckRedirect(nil, nil); !errors.Is(errRedirect, callerRedirectError) {
		t.Fatalf("caller redirect error = %v, want original policy", errRedirect)
	}
}

// TestCodexDeviceFlowCopiesExactRequestsAndRefresh verifies the CLIProxyAPI device, exchange, and refresh forms.
// TestCodexDeviceFlowCopiesExactRequestsAndRefresh 验证 CLIProxyAPI 设备、交换与刷新表单。
func TestCodexDeviceFlowCopiesExactRequestsAndRefresh(t *testing.T) {
	var devicePolls atomic.Int32
	var tokenCalls atomic.Int32
	idToken := codexTestIDToken(t, "account-one", "user@example.com")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/usercode":
			var payload map[string]string
			if errDecode := json.NewDecoder(request.Body).Decode(&payload); errDecode != nil {
				t.Errorf("decode user-code request: %v", errDecode)
			}
			if payload["client_id"] != codexOAuthClientID {
				t.Errorf("user-code request = %#v", payload)
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{"device_auth_id": "device-secret", "usercode": "ABCD-EFGH", "interval": "5"})
		case "/device-token":
			var payload map[string]string
			_ = json.NewDecoder(request.Body).Decode(&payload)
			if payload["device_auth_id"] != "device-secret" || payload["user_code"] != "ABCD-EFGH" {
				t.Errorf("device-token request = %#v", payload)
			}
			if devicePolls.Add(1) == 1 {
				writer.WriteHeader(http.StatusForbidden)
				return
			}
			_ = json.NewEncoder(writer).Encode(map[string]string{"authorization_code": "authorization-code", "code_verifier": "verifier", "code_challenge": "challenge"})
		case "/oauth-token":
			if errParse := request.ParseForm(); errParse != nil {
				t.Errorf("ParseForm() error = %v", errParse)
			}
			if request.Form.Get("client_id") != codexOAuthClientID {
				t.Errorf("OAuth form = %#v", request.Form)
			}
			if tokenCalls.Add(1) == 1 {
				if request.Form.Get("grant_type") != "authorization_code" || request.Form.Get("redirect_uri") != codexDeviceRedirectURI || request.Form.Get("code_verifier") != "verifier" {
					t.Errorf("exchange form = %#v", request.Form)
				}
				_ = json.NewEncoder(writer).Encode(map[string]any{"access_token": "access-before", "refresh_token": "refresh-before", "id_token": idToken, "expires_in": 3600})
				return
			}
			if request.Form.Get("grant_type") != "refresh_token" || request.Form.Get("refresh_token") != "refresh-before" || request.Form.Get("scope") != "openid profile email" {
				t.Errorf("refresh form = %#v", request.Form)
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{"access_token": "access-after", "expires_in": 7200})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	client, errClient := NewCodexDeviceFlowClientWithEndpoints(server.Client(), server.URL+"/usercode", server.URL+"/device-token", server.URL+"/oauth-token")
	if errClient != nil {
		t.Fatalf("NewCodexDeviceFlowClientWithEndpoints() error = %v", errClient)
	}
	// fixedNow makes provider-relative expires_in assertions deterministic.
	// fixedNow 使供应商相对 expires_in 断言具有确定性。
	fixedNow := time.Date(2026, 7, 19, 4, 0, 0, 0, time.UTC)
	client.now = func() time.Time { return fixedNow }
	session, errStart := client.Start(context.Background())
	if errStart != nil || session.userCode != "ABCD-EFGH" || session.flow.VerificationURI != codexDeviceVerificationURL {
		t.Fatalf("Start() session=%#v error=%v", session, errStart)
	}
	if _, errPending := client.Exchange(context.Background(), session); errPending != ErrCodexAuthorizationPending {
		t.Fatalf("first Exchange() error = %v", errPending)
	}
	token, errExchange := client.Exchange(context.Background(), session)
	if errExchange != nil || token.AccountID != "account-one" || token.Email != "user@example.com" || token.ExpiresAt != fixedNow.Add(time.Hour) || token.Type != "codex" {
		t.Fatalf("Exchange() token=%#v error=%v", token, errExchange)
	}
	refreshed, errRefresh := client.Refresh(context.Background(), token)
	if errRefresh != nil || refreshed.AccessToken != "access-after" || refreshed.RefreshToken != "refresh-before" || refreshed.IDToken != token.IDToken || refreshed.AccountID != "account-one" || refreshed.Email != "user@example.com" || refreshed.ExpiresAt != fixedNow.Add(2*time.Hour) {
		t.Fatalf("Refresh() token=%#v error=%v", refreshed, errRefresh)
	}
}

// TestCodexFlowManagerKeepsSuccessUntilExplicitConsumption verifies retry-safe token retention after provider completion.
// TestCodexFlowManagerKeepsSuccessUntilExplicitConsumption 验证供应商完成后可安全重试的 Token 保留行为。
func TestCodexFlowManagerKeepsSuccessUntilExplicitConsumption(t *testing.T) {
	var exchanges atomic.Int32
	idToken := codexTestIDToken(t, "account-one", "user@example.com")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/usercode":
			_ = json.NewEncoder(writer).Encode(map[string]any{"device_auth_id": "device-secret", "user_code": "ABCD-EFGH", "interval": 5})
		case "/device-token":
			_ = json.NewEncoder(writer).Encode(map[string]string{"authorization_code": "authorization-code", "code_verifier": "verifier", "code_challenge": "challenge"})
		case "/oauth-token":
			exchanges.Add(1)
			_ = json.NewEncoder(writer).Encode(map[string]any{"access_token": "access", "refresh_token": "refresh", "id_token": idToken, "expires_in": 3600})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client, errClient := NewCodexDeviceFlowClientWithEndpoints(server.Client(), server.URL+"/usercode", server.URL+"/device-token", server.URL+"/oauth-token")
	if errClient != nil {
		t.Fatalf("NewCodexDeviceFlowClientWithEndpoints() error = %v", errClient)
	}
	manager, errManager := NewCodexFlowManager(client)
	if errManager != nil {
		t.Fatalf("NewCodexFlowManager() error = %v", errManager)
	}
	flow, errStart := manager.Start(context.Background())
	if errStart != nil {
		t.Fatalf("Start() error = %v", errStart)
	}
	token, errPoll := manager.Poll(context.Background(), flow.ID)
	if errPoll != nil || token.AccessToken != "access" {
		t.Fatalf("Poll() token=%#v error=%v", token, errPoll)
	}
	if _, errLeased := manager.Poll(context.Background(), flow.ID); errLeased != ErrCodexAuthorizationPending {
		t.Fatalf("leased Poll() error = %v, want ErrCodexAuthorizationPending", errLeased)
	}
	manager.Release(flow.ID)
	cached, errCached := manager.Poll(context.Background(), flow.ID)
	if errCached != nil || cached.AccessToken != "access" || exchanges.Load() != 1 {
		t.Fatalf("released cached Poll() token=%#v error=%v exchanges=%d", cached, errCached, exchanges.Load())
	}
	manager.Cancel(flow.ID)
	if _, errMissing := manager.Poll(context.Background(), flow.ID); errMissing != ErrCodexFlowNotFound {
		t.Fatalf("cancelled Poll() error = %v, want ErrCodexFlowNotFound", errMissing)
	}
}

// TestCodexFlowManagerRejectsOverlappingProviderExchanges verifies a slow device-token request remains single-flight after the interval elapses.
// TestCodexFlowManagerRejectsOverlappingProviderExchanges 验证缓慢的设备 Token 请求在间隔结束后仍保持单飞。
func TestCodexFlowManagerRejectsOverlappingProviderExchanges(t *testing.T) {
	var exchanges atomic.Int32
	exchangeStarted := make(chan struct{})
	releaseExchange := make(chan struct{})
	idToken := codexTestIDToken(t, "account-one", "user@example.com")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/usercode":
			_ = json.NewEncoder(writer).Encode(map[string]any{"device_auth_id": "device-secret", "user_code": "ABCD-EFGH", "interval": 5})
		case "/device-token":
			if exchanges.Add(1) == 1 {
				close(exchangeStarted)
			}
			<-releaseExchange
			_ = json.NewEncoder(writer).Encode(map[string]string{"authorization_code": "authorization-code", "code_verifier": "verifier", "code_challenge": "challenge"})
		case "/oauth-token":
			_ = json.NewEncoder(writer).Encode(map[string]any{"access_token": "access", "refresh_token": "refresh", "id_token": idToken, "expires_in": 3600})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client, errClient := NewCodexDeviceFlowClientWithEndpoints(server.Client(), server.URL+"/usercode", server.URL+"/device-token", server.URL+"/oauth-token")
	if errClient != nil {
		t.Fatalf("NewCodexDeviceFlowClientWithEndpoints() error = %v", errClient)
	}
	manager, errManager := NewCodexFlowManager(client)
	if errManager != nil {
		t.Fatalf("NewCodexFlowManager() error = %v", errManager)
	}
	now := time.Date(2026, 7, 19, 11, 30, 0, 0, time.UTC)
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
	if !errors.Is(errOverlap, ErrCodexAuthorizationPending) || exchanges.Load() != 1 {
		t.Fatalf("overlapping Poll() error = %v exchanges = %d", errOverlap, exchanges.Load())
	}
	if errPoll := <-pollResult; errPoll != nil {
		t.Fatalf("first Poll() error = %v", errPoll)
	}
}

// TestCodexDeviceFlowRejectsOversizedResponse verifies strict provider response truncation detection.
// TestCodexDeviceFlowRejectsOversizedResponse 验证严格的供应商响应截断检测。
func TestCodexDeviceFlowRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(strings.Repeat("x", maximumCodexDeviceResponseBytes+1)))
	}))
	defer server.Close()
	client, errClient := NewCodexDeviceFlowClientWithEndpoints(server.Client(), server.URL, server.URL, server.URL)
	if errClient != nil {
		t.Fatalf("NewCodexDeviceFlowClientWithEndpoints() error = %v", errClient)
	}
	if _, errStart := client.Start(context.Background()); errStart == nil || !strings.Contains(errStart.Error(), "exceeds the response limit") {
		t.Fatalf("Start() error = %v", errStart)
	}
}

// TestCodexRefreshRetriesTransientErrorsAndStopsOnReuse verifies CLIProxyAPI's exact refresh retry policy.
// TestCodexRefreshRetriesTransientErrorsAndStopsOnReuse 验证 CLIProxyAPI 的精确刷新重试策略。
func TestCodexRefreshRetriesTransientErrorsAndStopsOnReuse(t *testing.T) {
	idToken := codexTestIDToken(t, "account-one", "user@example.com")
	var transientCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/transient":
			if transientCalls.Add(1) < codexRefreshAttempts {
				writer.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(writer).Encode(map[string]string{"error": "temporarily_unavailable"})
				return
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{"access_token": "access-after", "refresh_token": "refresh-after", "id_token": idToken, "expires_in": 3600})
		case "/reused":
			writer.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(writer).Encode(map[string]string{"error": "invalid_grant", "code": "refresh_token_reused"})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	token := CodexToken{IDToken: idToken, AccessToken: "access-before", RefreshToken: "refresh-before", AccountID: "account-one", Email: "user@example.com", ExpiresAt: time.Now().Add(time.Hour), Type: "codex"}
	client, errClient := NewCodexDeviceFlowClientWithEndpoints(server.Client(), server.URL+"/usercode", server.URL+"/device-token", server.URL+"/transient")
	if errClient != nil {
		t.Fatalf("NewCodexDeviceFlowClientWithEndpoints() error = %v", errClient)
	}
	client.retryDelay = func(int) time.Duration { return 0 }
	if _, errRefresh := client.Refresh(context.Background(), token); errRefresh != nil || transientCalls.Load() != codexRefreshAttempts {
		t.Fatalf("transient Refresh() calls=%d error=%v", transientCalls.Load(), errRefresh)
	}
	client.tokenURL = server.URL + "/reused"
	var reuseCalls atomic.Int32
	client.httpClient.Transport = roundTripCounter{delegate: http.DefaultTransport, calls: &reuseCalls}
	if _, errRefresh := client.Refresh(context.Background(), token); errRefresh == nil || !strings.Contains(errRefresh.Error(), "refresh_token_reused") || reuseCalls.Load() != 1 {
		t.Fatalf("reused Refresh() calls=%d error=%v", reuseCalls.Load(), errRefresh)
	}
}

// TestCodexRefreshClassifiesAuthenticationFailures verifies the management-safe Codex refresh taxonomy.
// TestCodexRefreshClassifiesAuthenticationFailures 验证管理安全的 Codex 刷新错误分类。
func TestCodexRefreshClassifiesAuthenticationFailures(t *testing.T) {
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
			client, errClient := NewCodexDeviceFlowClientWithEndpoints(server.Client(), server.URL+"/usercode", server.URL+"/device-token", server.URL+"/oauth-token")
			if errClient != nil {
				t.Fatalf("NewCodexDeviceFlowClientWithEndpoints() error = %v", errClient)
			}
			client.retryDelay = func(int) time.Duration { return 0 }
			_, errRefresh := client.Refresh(context.Background(), CodexToken{IDToken: "identity-before", AccessToken: "access-before", RefreshToken: "refresh-before", ExpiresAt: time.Now().UTC().Add(time.Hour), Type: "codex"})
			if !errors.Is(errRefresh, test.expectedError) {
				t.Fatalf("Refresh() error = %v, want category %v", errRefresh, test.expectedError)
			}
		})
	}
}

// TestCodexRefreshClassifiesAccessOnlyTokenAsRejected verifies an access-only Codex token requests reauthorization.
// TestCodexRefreshClassifiesAccessOnlyTokenAsRejected 验证仅含 Access Token 的 Codex Token 会请求重新授权。
func TestCodexRefreshClassifiesAccessOnlyTokenAsRejected(t *testing.T) {
	client, errClient := NewCodexDeviceFlowClientWithEndpoints(&http.Client{}, "https://device.example/user", "https://device.example/token", "https://oauth.example/token")
	if errClient != nil {
		t.Fatalf("NewCodexDeviceFlowClientWithEndpoints() error = %v", errClient)
	}
	_, errRefresh := client.Refresh(context.Background(), CodexToken{IDToken: codexTestIDToken(t, "account", "user@example.com"), AccessToken: "access", AccountID: "account", ExpiresAt: time.Now().UTC().Add(time.Hour), Type: "codex"})
	if !errors.Is(errRefresh, coreprovider.ErrAuthenticationRejected) {
		t.Fatalf("Refresh() error = %v, want ErrAuthenticationRejected", errRefresh)
	}
}

// roundTripCounter counts outbound requests while delegating exact HTTP behavior.
// roundTripCounter 统计出站请求并委托精确 HTTP 行为。
type roundTripCounter struct {
	// delegate performs the actual request.
	// delegate 执行实际请求。
	delegate http.RoundTripper
	// calls receives the request count.
	// calls 接收请求计数。
	calls *atomic.Int32
}

// RoundTrip counts and delegates one HTTP request.
// RoundTrip 统计并委托一个 HTTP 请求。
func (c roundTripCounter) RoundTrip(request *http.Request) (*http.Response, error) {
	c.calls.Add(1)
	return c.delegate.RoundTrip(request)
}

// codexTestIDToken creates a structurally valid test ID token with the exact copied claim paths.
// codexTestIDToken 使用精确复制的声明路径创建结构有效的测试 ID Token。
func codexTestIDToken(t *testing.T, accountID string, email string) string {
	t.Helper()
	payload, errPayload := json.Marshal(map[string]any{"email": email, "https://api.openai.com/auth": map[string]string{"chatgpt_account_id": accountID, "chatgpt_plan_type": "plus"}})
	if errPayload != nil {
		t.Fatalf("json.Marshal() error = %v", errPayload)
	}
	return strings.Join([]string{"header", base64.RawURLEncoding.EncodeToString(payload), "signature"}, ".")
}
