package openai

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestCodexOAuthClientRefusesRedirectsWithoutMutatingCaller verifies browser OAuth exchanges retain their configured token origin.
// TestCodexOAuthClientRefusesRedirectsWithoutMutatingCaller 验证浏览器 OAuth 交换保持在配置的 Token 源站。
func TestCodexOAuthClientRefusesRedirectsWithoutMutatingCaller(t *testing.T) {
	callerRedirectError := errors.New("caller redirect policy")
	caller := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return callerRedirectError }}
	client, errClient := NewCodexOAuthClientWithEndpoints(caller, "https://oauth.example/authorize", "https://oauth.example/token")
	if errClient != nil {
		t.Fatalf("NewCodexOAuthClientWithEndpoints() error = %v", errClient)
	}
	if client.httpClient == caller {
		t.Fatal("Codex OAuth client retained the caller-owned HTTP client")
	}
	if errRedirect := client.httpClient.CheckRedirect(nil, nil); !errors.Is(errRedirect, http.ErrUseLastResponse) {
		t.Fatalf("Codex OAuth redirect error = %v, want http.ErrUseLastResponse", errRedirect)
	}
	if errRedirect := caller.CheckRedirect(nil, nil); !errors.Is(errRedirect, callerRedirectError) {
		t.Fatalf("caller redirect error = %v, want original policy", errRedirect)
	}
}

// TestCodexOAuthCopiesExactConsentAndExchange verifies CLIProxyAPI's browser query, PKCE form, identity, and retry-safe result retention.
// TestCodexOAuthCopiesExactConsentAndExchange 验证 CLIProxyAPI 的浏览器查询、PKCE 表单、身份与重试安全结果保留。
func TestCodexOAuthCopiesExactConsentAndExchange(t *testing.T) {
	var tokenCalls atomic.Int32
	idToken := codexTestIDToken(t, "account-one", "user@example.com")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/token" {
			http.NotFound(writer, request)
			return
		}
		tokenCalls.Add(1)
		if errParse := request.ParseForm(); errParse != nil {
			t.Fatalf("ParseForm() error = %v", errParse)
		}
		if request.Form.Get("grant_type") != "authorization_code" || request.Form.Get("client_id") != codexOAuthClientID || request.Form.Get("redirect_uri") != codexBrowserRedirectURI || request.Form.Get("code") != "authorization-code" || len(request.Form.Get("code_verifier")) != 128 {
			t.Errorf("token form = %#v", request.Form)
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{"access_token": "access", "refresh_token": "refresh", "id_token": idToken, "expires_in": 3600})
	}))
	defer server.Close()
	client, errClient := NewCodexOAuthClientWithEndpoints(server.Client(), server.URL+"/authorize", server.URL+"/token")
	if errClient != nil {
		t.Fatalf("NewCodexOAuthClientWithEndpoints() error = %v", errClient)
	}
	fixedNow := time.Date(2026, 7, 19, 5, 0, 0, 0, time.UTC)
	client.now = func() time.Time { return fixedNow }
	manager, errManager := NewCodexOAuthManager(client)
	if errManager != nil {
		t.Fatalf("NewCodexOAuthManager() error = %v", errManager)
	}
	manager.now = func() time.Time { return fixedNow }
	flow, errStart := manager.Start(context.Background())
	if errStart != nil {
		t.Fatalf("Start() error = %v", errStart)
	}
	authorizationURL, errAuthorizationURL := url.Parse(flow.AuthorizationURL)
	if errAuthorizationURL != nil {
		t.Fatalf("url.Parse() error = %v", errAuthorizationURL)
	}
	query := authorizationURL.Query()
	if query.Get("client_id") != codexOAuthClientID || query.Get("redirect_uri") != codexBrowserRedirectURI || query.Get("scope") != codexBrowserScope || query.Get("response_type") != "code" || query.Get("code_challenge_method") != "S256" || query.Get("prompt") != "login" || query.Get("id_token_add_organizations") != "true" || query.Get("codex_cli_simplified_flow") != "true" || len(query.Get("code_challenge")) != 43 {
		t.Fatalf("authorization query = %#v", query)
	}
	callbackURL := codexBrowserRedirectURI + "?code=authorization-code&state=" + url.QueryEscape(query.Get("state"))
	token, errComplete := manager.Complete(context.Background(), flow.ID, callbackURL)
	if errComplete != nil || token.AccountID != "account-one" || token.Email != "user@example.com" || !token.ExpiresAt.Equal(fixedNow.Add(time.Hour)) {
		t.Fatalf("Complete() token=%#v error=%v", token, errComplete)
	}
	if _, errLeased := manager.Complete(context.Background(), flow.ID, callbackURL); errLeased != ErrCodexOAuthFlowInProgress {
		t.Fatalf("leased Complete() error = %v, want ErrCodexOAuthFlowInProgress", errLeased)
	}
	manager.Release(flow.ID)
	cached, errCached := manager.Complete(context.Background(), flow.ID, callbackURL)
	if errCached != nil || cached.AccessToken != "access" || tokenCalls.Load() != 1 {
		t.Fatalf("released cached Complete() token=%#v error=%v calls=%d", cached, errCached, tokenCalls.Load())
	}
	manager.Cancel(flow.ID)
	if _, errMissing := manager.Complete(context.Background(), flow.ID, callbackURL); errMissing != ErrCodexOAuthFlowNotFound {
		t.Fatalf("cancelled Complete() error = %v, want ErrCodexOAuthFlowNotFound", errMissing)
	}
}

// TestCodexOAuthRejectsCallbackMismatchWithoutConsumingFlow verifies CSRF and redirect validation remain retry-safe.
// TestCodexOAuthRejectsCallbackMismatchWithoutConsumingFlow 验证 CSRF 与重定向校验保持重试安全。
func TestCodexOAuthRejectsCallbackMismatchWithoutConsumingFlow(t *testing.T) {
	client, errClient := NewCodexOAuthClientWithEndpoints(http.DefaultClient, "https://auth.openai.com/oauth/authorize", "https://auth.openai.com/oauth/token")
	if errClient != nil {
		t.Fatalf("NewCodexOAuthClientWithEndpoints() error = %v", errClient)
	}
	manager, errManager := NewCodexOAuthManager(client)
	if errManager != nil {
		t.Fatalf("NewCodexOAuthManager() error = %v", errManager)
	}
	flow, errStart := manager.Start(context.Background())
	if errStart != nil {
		t.Fatalf("Start() error = %v", errStart)
	}
	if _, errComplete := manager.Complete(context.Background(), flow.ID, codexBrowserRedirectURI+"?code=authorization-code&state=wrong"); errComplete == nil {
		t.Fatal("Complete() accepted a mismatched state")
	}
	manager.mu.Lock()
	session, exists := manager.sessions[flow.ID]
	manager.mu.Unlock()
	if !exists || session.completing || session.token != nil {
		t.Fatalf("flow after rejected callback = %#v, exists=%t", session, exists)
	}
}

// TestCodexOAuthRejectsTokenCompletingAfterFlowExpiry verifies a slow provider exchange cannot revive an expired browser session.
// TestCodexOAuthRejectsTokenCompletingAfterFlowExpiry 验证缓慢的供应商交换不能复活已过期的浏览器会话。
func TestCodexOAuthRejectsTokenCompletingAfterFlowExpiry(t *testing.T) {
	fixedNow := time.Date(2026, 7, 19, 6, 0, 0, 0, time.UTC)
	managerNow := fixedNow
	var clockMu sync.Mutex
	idToken := codexTestIDToken(t, "account-one", "user@example.com")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		clockMu.Lock()
		managerNow = fixedNow.Add(codexOAuthFlowLifetime)
		clockMu.Unlock()
		_ = json.NewEncoder(writer).Encode(map[string]any{"access_token": "access", "refresh_token": "refresh", "id_token": idToken, "expires_in": 3600})
	}))
	defer server.Close()
	client, errClient := NewCodexOAuthClientWithEndpoints(server.Client(), server.URL+"/authorize", server.URL)
	if errClient != nil {
		t.Fatalf("NewCodexOAuthClientWithEndpoints() error = %v", errClient)
	}
	client.now = func() time.Time { return fixedNow }
	manager, errManager := NewCodexOAuthManager(client)
	if errManager != nil {
		t.Fatalf("NewCodexOAuthManager() error = %v", errManager)
	}
	manager.now = func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return managerNow
	}
	flow, errStart := manager.Start(context.Background())
	if errStart != nil {
		t.Fatalf("Start() error = %v", errStart)
	}
	authorizationURL, errAuthorizationURL := url.Parse(flow.AuthorizationURL)
	if errAuthorizationURL != nil {
		t.Fatalf("url.Parse() error = %v", errAuthorizationURL)
	}
	callbackURL := codexBrowserRedirectURI + "?code=authorization-code&state=" + url.QueryEscape(authorizationURL.Query().Get("state"))
	if _, errComplete := manager.Complete(context.Background(), flow.ID, callbackURL); !errors.Is(errComplete, ErrCodexOAuthFlowNotFound) {
		t.Fatalf("Complete() error = %v, want ErrCodexOAuthFlowNotFound", errComplete)
	}
}

// TestCodexOAuthRejectsAmbiguousCallbackParameters verifies duplicate callback values cannot alter CSRF interpretation.
// TestCodexOAuthRejectsAmbiguousCallbackParameters 验证重复回调值不能改变 CSRF 解释。
func TestCodexOAuthRejectsAmbiguousCallbackParameters(t *testing.T) {
	callbackURL := codexBrowserRedirectURI + "?code=first&code=second&state=expected"
	if _, errCallback := parseCodexOAuthCallback(callbackURL, "expected"); errCallback == nil {
		t.Fatal("parseCodexOAuthCallback() unexpectedly accepted duplicate code parameters")
	}
}
