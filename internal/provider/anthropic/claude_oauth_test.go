package anthropic

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	coreprovider "github.com/OpenVulcan/vulcan-model-core/internal/provider"
)

// claudeTestRoundTripper adapts one deterministic function to http.RoundTripper.
// claudeTestRoundTripper 将一个确定性函数适配为 http.RoundTripper。
type claudeTestRoundTripper func(*http.Request) (*http.Response, error)

// RoundTrip executes the configured deterministic test function.
// RoundTrip 执行配置的确定性测试函数。
func (f claudeTestRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

// TestClaudeAuthorizationURLCopiesCLIProxyContract verifies every copied authorization parameter.
// TestClaudeAuthorizationURLCopiesCLIProxyContract 验证每一个复制的授权参数。
func TestClaudeAuthorizationURLCopiesCLIProxyContract(t *testing.T) {
	client, errClient := newClaudeOAuthClient(&http.Client{}, "https://example.invalid/token")
	if errClient != nil {
		t.Fatalf("newClaudeOAuthClient() error = %v", errClient)
	}
	pkce := claudePKCECodes{CodeVerifier: "verifier", CodeChallenge: "challenge"}
	authorizationURL, errAuthorizationURL := client.AuthorizationURL("state-value", pkce)
	if errAuthorizationURL != nil {
		t.Fatalf("AuthorizationURL() error = %v", errAuthorizationURL)
	}
	parsed, errParse := url.Parse(authorizationURL)
	if errParse != nil {
		t.Fatalf("parse authorization URL: %v", errParse)
	}
	if parsed.Scheme+"://"+parsed.Host+parsed.Path != claudeAuthorizationEndpoint {
		t.Fatalf("authorization endpoint = %q", parsed.String())
	}
	want := map[string]string{
		"code": "true", "client_id": claudeOAuthClientID, "response_type": "code",
		"redirect_uri": claudeOAuthRedirectURI, "scope": claudeOAuthScope,
		"code_challenge": "challenge", "code_challenge_method": "S256", "state": "state-value",
	}
	if len(parsed.Query()) != len(want) {
		t.Fatalf("authorization parameter count = %d, want %d", len(parsed.Query()), len(want))
	}
	for name, value := range want {
		if parsed.Query().Get(name) != value {
			t.Fatalf("authorization parameter %s = %q, want %q", name, parsed.Query().Get(name), value)
		}
	}
}

// TestGenerateClaudePKCECodesUsesCopiedVerifierShape verifies the 96-byte verifier and S256 challenge.
// TestGenerateClaudePKCECodesUsesCopiedVerifierShape 验证 96 字节 Verifier 与 S256 Challenge。
func TestGenerateClaudePKCECodesUsesCopiedVerifierShape(t *testing.T) {
	pkce, errPKCE := generateClaudePKCECodes()
	if errPKCE != nil {
		t.Fatalf("generateClaudePKCECodes() error = %v", errPKCE)
	}
	if len(pkce.CodeVerifier) != 128 {
		t.Fatalf("verifier length = %d, want 128", len(pkce.CodeVerifier))
	}
	digest := sha256.Sum256([]byte(pkce.CodeVerifier))
	if pkce.CodeChallenge != base64.RawURLEncoding.EncodeToString(digest[:]) {
		t.Fatalf("challenge does not match S256 verifier digest")
	}
}

// TestClaudeOAuthExchangePreservesTypedAccountFields verifies callback validation and the copied JSON body.
// TestClaudeOAuthExchangePreservesTypedAccountFields 验证回调校验与复制的 JSON 正文。
func TestClaudeOAuthExchangePreservesTypedAccountFields(t *testing.T) {
	var received claudeAuthorizationCodeRequest
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.Header.Get("Content-Type") != "application/json" || request.Header.Get("Accept") != "application/json" {
			t.Errorf("token request boundary = %s %#v", request.Method, request.Header)
		}
		if errDecode := json.NewDecoder(request.Body).Decode(&received); errDecode != nil {
			t.Errorf("decode token request: %v", errDecode)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"access_token":"access","refresh_token":"refresh","token_type":"Bearer","expires_in":3600,"organization":{"uuid":"org-one","name":"Example"},"account":{"uuid":"account-one","email_address":"user@example.com"}}`)
	}))
	defer server.Close()
	client, errClient := newClaudeOAuthClient(server.Client(), server.URL)
	if errClient != nil {
		t.Fatalf("newClaudeOAuthClient() error = %v", errClient)
	}
	fixedNow := time.Unix(1_800_000_000, 0).UTC()
	client.now = func() time.Time { return fixedNow }
	token, errExchange := client.ExchangeCallback(context.Background(), "http://localhost:54545/callback?code=authorization-code%23state-value&state=state-value", "state-value", claudePKCECodes{CodeVerifier: "verifier", CodeChallenge: "challenge"})
	if errExchange != nil {
		t.Fatalf("ExchangeCallback() error = %v", errExchange)
	}
	if received != (claudeAuthorizationCodeRequest{Code: "authorization-code", State: "state-value", GrantType: "authorization_code", ClientID: claudeOAuthClientID, RedirectURI: claudeOAuthRedirectURI, CodeVerifier: "verifier"}) {
		t.Fatalf("token request = %#v", received)
	}
	if token.AccountID != "account-one" || token.OrganizationID != "org-one" || token.Email != "user@example.com" || token.ExpiresAt != fixedNow.Unix()+3600 {
		t.Fatalf("Claude token = %#v", token)
	}
}

// TestParseClaudeAuthorizationInputAcceptsCodeStateAndRejectsWrongState verifies CLIProxyAPI's manual form safely.
// TestParseClaudeAuthorizationInputAcceptsCodeStateAndRejectsWrongState 安全验证 CLIProxyAPI 的手动形式。
func TestParseClaudeAuthorizationInputAcceptsCodeStateAndRejectsWrongState(t *testing.T) {
	code, errCode := parseClaudeAuthorizationInput("authorization-code#expected", "expected")
	if errCode != nil || code != "authorization-code" {
		t.Fatalf("parse code#state = %q, %v", code, errCode)
	}
	if _, errWrong := parseClaudeAuthorizationInput("authorization-code#wrong", "expected"); errWrong == nil {
		t.Fatalf("wrong State was accepted")
	}
}

// TestClaudeRefresh429BlocksImmediateReplay copies CLIProxyAPI's historical rate-limit regression test.
// TestClaudeRefresh429BlocksImmediateReplay 复制 CLIProxyAPI 的历史限流回归测试。
func TestClaudeRefresh429BlocksImmediateReplay(t *testing.T) {
	var calls atomic.Int32
	fixedNow := time.Unix(1_800_000_000, 0).UTC()
	httpClient := &http.Client{Transport: claudeTestRoundTripper(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: http.StatusTooManyRequests, Body: io.NopCloser(strings.NewReader(`{"error":"rate_limited"}`)), Header: http.Header{"Retry-After": []string{"60"}}, Request: request}, nil
	})}
	client, errClient := newClaudeOAuthClient(httpClient, "https://api.anthropic.com/v1/oauth/token")
	if errClient != nil {
		t.Fatalf("newClaudeOAuthClient() error = %v", errClient)
	}
	client.now = func() time.Time { return fixedNow }
	client.wait = func(context.Context, time.Duration) error { return nil }
	token := claudeTokenFixture(fixedNow)
	if _, errRefresh := client.Refresh(context.Background(), token); errRefresh == nil || !strings.Contains(errRefresh.Error(), "status 429") {
		t.Fatalf("first Refresh() error = %v", errRefresh)
	}
	if _, errRefresh := client.Refresh(context.Background(), token); errRefresh == nil || !strings.Contains(errRefresh.Error(), "status 429") {
		t.Fatalf("blocked Refresh() error = %v", errRefresh)
	}
	if calls.Load() != 1 {
		t.Fatalf("refresh calls = %d, want 1", calls.Load())
	}
}

// TestClaudeRefreshPrunesExpiredReplayBlocks verifies abandoned rate-limit entries cannot accumulate indefinitely.
// TestClaudeRefreshPrunesExpiredReplayBlocks 验证废弃的限流记录不能无限累积。
func TestClaudeRefreshPrunesExpiredReplayBlocks(t *testing.T) {
	client, errClient := newClaudeOAuthClient(http.DefaultClient, "https://api.anthropic.com/v1/oauth/token")
	if errClient != nil {
		t.Fatalf("newClaudeOAuthClient() error = %v", errClient)
	}
	now := time.Date(2026, 7, 19, 7, 0, 0, 0, time.UTC)
	expiredKey := sha256.Sum256([]byte("expired-refresh-token"))
	activeKey := sha256.Sum256([]byte("active-refresh-token"))
	client.blockedUntil[expiredKey] = now.Add(-time.Second)
	client.blockedUntil[activeKey] = now.Add(time.Minute)
	client.refreshMu.Lock()
	client.pruneExpiredRefreshBlocksLocked(now)
	client.refreshMu.Unlock()
	if _, exists := client.blockedUntil[expiredKey]; exists {
		t.Fatal("expired replay block was not pruned")
	}
	if _, exists := client.blockedUntil[activeKey]; !exists {
		t.Fatal("active replay block was pruned")
	}
}

// TestClaudeRefreshDeduplicatesConcurrentExchange copies CLIProxyAPI's historical single-flight regression test.
// TestClaudeRefreshDeduplicatesConcurrentExchange 复制 CLIProxyAPI 的历史单飞回归测试。
func TestClaudeRefreshDeduplicatesConcurrentExchange(t *testing.T) {
	var calls atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	var startedOnce sync.Once
	fixedNow := time.Unix(1_800_000_000, 0).UTC()
	httpClient := &http.Client{Transport: claudeTestRoundTripper(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		startedOnce.Do(func() { close(started) })
		<-release
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"access_token":"new-access","refresh_token":"new-refresh","token_type":"Bearer","expires_in":3600,"account":{"uuid":"account-one","email_address":"user@example.com"}}`)), Header: make(http.Header), Request: request}, nil
	})}
	client, errClient := newClaudeOAuthClient(httpClient, "https://api.anthropic.com/v1/oauth/token")
	if errClient != nil {
		t.Fatalf("newClaudeOAuthClient() error = %v", errClient)
	}
	client.now = func() time.Time { return fixedNow }
	results := make(chan ClaudeToken, 2)
	errors := make(chan error, 2)
	refresh := func() {
		token, errRefresh := client.Refresh(context.Background(), claudeTokenFixture(fixedNow))
		results <- token
		errors <- errRefresh
	}
	go refresh()
	go refresh()
	<-started
	time.Sleep(20 * time.Millisecond)
	if calls.Load() != 1 {
		t.Fatalf("concurrent upstream calls before release = %d, want 1", calls.Load())
	}
	close(release)
	for index := 0; index < 2; index++ {
		if errRefresh := <-errors; errRefresh != nil {
			t.Fatalf("Refresh() error = %v", errRefresh)
		}
		if token := <-results; token.AccessToken != "new-access" {
			t.Fatalf("refreshed token = %#v", token)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("concurrent upstream calls = %d, want 1", calls.Load())
	}
}

// TestClaudeRefreshClassifiesAuthenticationFailures verifies the management-safe Claude refresh taxonomy.
// TestClaudeRefreshClassifiesAuthenticationFailures 验证管理安全的 Claude 刷新错误分类。
func TestClaudeRefreshClassifiesAuthenticationFailures(t *testing.T) {
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
			client, errClient := newClaudeOAuthClient(server.Client(), server.URL)
			if errClient != nil {
				t.Fatalf("newClaudeOAuthClient() error = %v", errClient)
			}
			client.wait = func(context.Context, time.Duration) error { return nil }
			_, errRefresh := client.Refresh(context.Background(), claudeTokenFixture(time.Now().UTC()))
			if !errors.Is(errRefresh, test.expectedError) {
				t.Fatalf("Refresh() error = %v, want category %v", errRefresh, test.expectedError)
			}
		})
	}
}

// TestClaudeFlowManagerRetainsSuccessUntilConsumption verifies idempotent completion and explicit cancellation.
// TestClaudeFlowManagerRetainsSuccessUntilConsumption 验证幂等完成与显式取消。
func TestClaudeFlowManagerRetainsSuccessUntilConsumption(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, `{"access_token":"access","refresh_token":"refresh","token_type":"Bearer","expires_in":3600,"account":{"uuid":"account-one","email_address":"user@example.com"}}`)
	}))
	defer server.Close()
	client, errClient := newClaudeOAuthClient(server.Client(), server.URL)
	if errClient != nil {
		t.Fatalf("newClaudeOAuthClient() error = %v", errClient)
	}
	client.now = func() time.Time { return time.Unix(1_800_000_000, 0).UTC() }
	manager, errManager := NewClaudeFlowManager(client)
	if errManager != nil {
		t.Fatalf("NewClaudeFlowManager() error = %v", errManager)
	}
	manager.now = client.now
	flow, errStart := manager.Start(context.Background())
	if errStart != nil {
		t.Fatalf("Start() error = %v", errStart)
	}
	parsedAuthorization, _ := url.Parse(flow.AuthorizationURL)
	state := parsedAuthorization.Query().Get("state")
	callback := "http://localhost:54545/callback?code=authorization-code&state=" + url.QueryEscape(state)
	first, errFirst := manager.Complete(context.Background(), flow.ID, callback)
	if errFirst != nil {
		t.Fatalf("first Complete() error = %v", errFirst)
	}
	if _, errLeased := manager.Complete(context.Background(), flow.ID, callback); errLeased != ErrClaudeOAuthFlowInProgress {
		t.Fatalf("leased Complete() error = %v, want ErrClaudeOAuthFlowInProgress", errLeased)
	}
	manager.Release(flow.ID)
	second, errSecond := manager.Complete(context.Background(), flow.ID, callback)
	if errSecond != nil || second.AccessToken != first.AccessToken {
		t.Fatalf("released idempotent Complete() = %#v, %v", second, errSecond)
	}
	manager.Cancel(flow.ID)
	if _, errMissing := manager.Complete(context.Background(), flow.ID, callback); errMissing != ErrClaudeOAuthFlowNotFound {
		t.Fatalf("cancelled Complete() error = %v", errMissing)
	}
}

// claudeTokenFixture creates one complete protected token for refresh tests.
// claudeTokenFixture 为刷新测试创建一个完整受保护 Token。
func claudeTokenFixture(now time.Time) ClaudeToken {
	return ClaudeToken{AccessToken: "old-access", RefreshToken: "shared-refresh", TokenType: "Bearer", ExpiresAt: now.Add(time.Hour).Unix(), LastRefreshAt: now.Unix(), Email: "user@example.com", AccountID: "account-one", Type: claudeTokenDocumentType}
}
