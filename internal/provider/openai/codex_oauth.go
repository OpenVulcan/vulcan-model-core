package openai

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	providertransport "github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
)

const (
	// codexAuthorizationURL is CLIProxyAPI's exact OpenAI account authorization endpoint.
	// codexAuthorizationURL 是 CLIProxyAPI 使用的精确 OpenAI 账号授权入口。
	codexAuthorizationURL = "https://auth.openai.com/oauth/authorize"
	// codexBrowserRedirectURI is the provider-registered localhost callback copied from CLIProxyAPI.
	// codexBrowserRedirectURI 是从 CLIProxyAPI 复制的供应商注册 localhost 回调地址。
	codexBrowserRedirectURI = "http://localhost:1455/auth/callback"
	// codexBrowserScope is CLIProxyAPI's exact browser OAuth scope set.
	// codexBrowserScope 是 CLIProxyAPI 使用的精确浏览器 OAuth Scope 集合。
	codexBrowserScope = "openid email profile offline_access"
	// codexOAuthFlowLifetime matches CLIProxyAPI's five-minute callback window.
	// codexOAuthFlowLifetime 与 CLIProxyAPI 的五分钟回调窗口一致。
	codexOAuthFlowLifetime = 5 * time.Minute
	// maximumCodexOAuthFlows bounds retained PKCE and CSRF state.
	// maximumCodexOAuthFlows 限制保留的 PKCE 与 CSRF 状态数量。
	maximumCodexOAuthFlows = 32
	// maximumCodexOAuthResponseBytes bounds token responses before decoding.
	// maximumCodexOAuthResponseBytes 在解码前限制 Token 响应大小。
	maximumCodexOAuthResponseBytes = 64 << 10
)

var (
	// ErrCodexOAuthFlowNotFound reports an unknown, expired, or consumed browser flow.
	// ErrCodexOAuthFlowNotFound 表示未知、过期或已消费的浏览器授权流程。
	ErrCodexOAuthFlowNotFound = errors.New("Codex OAuth flow not found")
	// ErrCodexOAuthFlowInProgress reports a duplicate token exchange for one immutable flow.
	// ErrCodexOAuthFlowInProgress 表示对同一不可变流程发起重复 Token 交换。
	ErrCodexOAuthFlowInProgress = errors.New("Codex OAuth flow is already completing")
	// ErrCodexOAuthFlowLimitReached reports bounded in-memory flow exhaustion.
	// ErrCodexOAuthFlowLimitReached 表示有界内存授权流程已耗尽。
	ErrCodexOAuthFlowLimitReached = errors.New("Codex OAuth flow limit reached")
)

// codexPKCECodes stores the RFC 7636 verifier and S256 challenge only inside the server process.
// codexPKCECodes 仅在服务进程内存中存储 RFC 7636 Verifier 与 S256 Challenge。
type codexPKCECodes struct {
	// verifier is the 128-character URL-safe secret copied from CLIProxyAPI behavior.
	// verifier 是从 CLIProxyAPI 行为复制的 128 字符 URL 安全秘密。
	verifier string
	// challenge is the unpadded base64url SHA-256 digest.
	// challenge 是无填充 base64url SHA-256 摘要。
	challenge string
}

// CodexOAuthFlow is the management-safe projection of one server-owned browser authorization session.
// CodexOAuthFlow 是一个服务端拥有的浏览器授权会话的管理安全投影。
type CodexOAuthFlow struct {
	// ID identifies the in-memory flow without revealing State or PKCE material.
	// ID 标识内存流程且不暴露 State 或 PKCE 材料。
	ID string `json:"id"`
	// AuthorizationURL is the exact OpenAI consent URL.
	// AuthorizationURL 是精确的 OpenAI 同意授权地址。
	AuthorizationURL string `json:"authorization_url"`
	// RedirectURI tells the administrator which failed localhost callback to copy.
	// RedirectURI 告知管理员应复制哪个失败的 localhost 回调地址。
	RedirectURI string `json:"redirect_uri"`
	// ExpiresAt bounds retention of PKCE and State.
	// ExpiresAt 限制 PKCE 与 State 的保留时间。
	ExpiresAt time.Time `json:"expires_at"`
}

// codexOAuthSession retains sensitive flow material and an idempotent successful result server-side.
// codexOAuthSession 在服务端保留敏感流程材料与幂等成功结果。
type codexOAuthSession struct {
	// flow is the management-safe projection.
	// flow 是管理安全投影。
	flow CodexOAuthFlow
	// state is the exact CSRF value sent to OpenAI.
	// state 是发送给 OpenAI 的精确 CSRF 值。
	state string
	// pkce contains the verifier never exposed to the browser UI.
	// pkce 包含绝不向浏览器界面暴露的 Verifier。
	pkce codexPKCECodes
	// completing leases the provider exchange or completed result to one downstream onboarding request.
	// completing 将供应商交换或已完成结果租给一个下游录入请求。
	completing bool
	// token retains one completed result until onboarding consumes the flow.
	// token 保留一个已完成结果，直至录入流程消费它。
	token *CodexToken
}

// codexOAuthTokenResponse mirrors CLIProxyAPI's typed OpenAI token response.
// codexOAuthTokenResponse 镜像 CLIProxyAPI 的类型化 OpenAI Token 响应。
type codexOAuthTokenResponse struct {
	// AccessToken authenticates Codex requests.
	// AccessToken 授权 Codex 请求。
	AccessToken string `json:"access_token"`
	// RefreshToken obtains future access tokens.
	// RefreshToken 用于获取后续 Access Token。
	RefreshToken string `json:"refresh_token"`
	// IDToken contains account and plan claims.
	// IDToken 包含账号与套餐声明。
	IDToken string `json:"id_token"`
	// ExpiresIn is the access-token lifetime in seconds.
	// ExpiresIn 是 Access Token 有效期秒数。
	ExpiresIn int64 `json:"expires_in"`
}

// CodexOAuthClient performs CLIProxyAPI's exact browser authorization-code exchange.
// CodexOAuthClient 执行 CLIProxyAPI 的精确浏览器授权码交换。
type CodexOAuthClient struct {
	// httpClient executes bounded provider requests.
	// httpClient 执行有界供应商请求。
	httpClient *http.Client
	// authorizationEndpoint is the production endpoint or an explicit test endpoint.
	// authorizationEndpoint 是生产入口或显式测试入口。
	authorizationEndpoint string
	// tokenEndpoint is the production endpoint or an explicit test endpoint.
	// tokenEndpoint 是生产入口或显式测试入口。
	tokenEndpoint string
	// now supplies deterministic token expiry in focused tests.
	// now 在聚焦测试中提供确定性 Token 过期时间。
	now func() time.Time
}

// CodexOAuthManager owns bounded browser PKCE sessions without exposing provider tokens.
// CodexOAuthManager 管理有界浏览器 PKCE 会话且不暴露供应商 Token。
type CodexOAuthManager struct {
	// client performs provider token exchanges.
	// client 执行供应商 Token 交换。
	client *CodexOAuthClient
	// now supplies the flow clock.
	// now 提供授权流程时钟。
	now func() time.Time
	// mu protects all sessions.
	// mu 保护全部会话。
	mu sync.Mutex
	// sessions owns incomplete or not-yet-consumed authorization state.
	// sessions 管理未完成或尚未消费的授权状态。
	sessions map[string]codexOAuthSession
}

// NewCodexOAuthClient creates a production browser OAuth client.
// NewCodexOAuthClient 创建生产浏览器 OAuth 客户端。
func NewCodexOAuthClient(httpClient *http.Client) (*CodexOAuthClient, error) {
	return NewCodexOAuthClientWithEndpoints(httpClient, codexAuthorizationURL, codexTokenURL)
}

// NewCodexOAuthClientWithEndpoints creates an isolated OAuth client for deterministic tests.
// NewCodexOAuthClientWithEndpoints 为确定性测试创建隔离 OAuth 客户端。
func NewCodexOAuthClientWithEndpoints(httpClient *http.Client, authorizationEndpoint string, tokenEndpoint string) (*CodexOAuthClient, error) {
	if httpClient == nil || strings.TrimSpace(authorizationEndpoint) == "" || strings.TrimSpace(tokenEndpoint) == "" {
		return nil, errors.New("Codex OAuth HTTP client and endpoints are required")
	}
	return &CodexOAuthClient{httpClient: providertransport.CloneHTTPClientWithoutRedirects(httpClient), authorizationEndpoint: strings.TrimSpace(authorizationEndpoint), tokenEndpoint: strings.TrimSpace(tokenEndpoint), now: time.Now}, nil
}

// NewCodexOAuthManager creates an empty bounded browser authorization manager.
// NewCodexOAuthManager 创建空的有界浏览器授权管理器。
func NewCodexOAuthManager(client *CodexOAuthClient) (*CodexOAuthManager, error) {
	if client == nil {
		return nil, errors.New("Codex OAuth client is required")
	}
	return &CodexOAuthManager{client: client, now: time.Now, sessions: make(map[string]codexOAuthSession)}, nil
}

// Start creates one server-owned CSRF and PKCE session and returns only its consent URL.
// Start 创建一个服务端拥有的 CSRF 与 PKCE 会话，并仅返回其同意授权 URL。
func (m *CodexOAuthManager) Start(_ context.Context) (CodexOAuthFlow, error) {
	now := m.now().UTC()
	flowID, errFlowID := randomCodexIdentifier(16)
	if errFlowID != nil {
		return CodexOAuthFlow{}, errFlowID
	}
	state, errState := randomCodexIdentifier(32)
	if errState != nil {
		return CodexOAuthFlow{}, errState
	}
	pkce, errPKCE := generateCodexPKCE()
	if errPKCE != nil {
		return CodexOAuthFlow{}, errPKCE
	}
	authorizationURL, errAuthorizationURL := m.client.authorizationURL(state, pkce)
	if errAuthorizationURL != nil {
		return CodexOAuthFlow{}, errAuthorizationURL
	}
	flow := CodexOAuthFlow{ID: flowID, AuthorizationURL: authorizationURL, RedirectURI: codexBrowserRedirectURI, ExpiresAt: now.Add(codexOAuthFlowLifetime)}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneExpiredLocked(now)
	if len(m.sessions) >= maximumCodexOAuthFlows {
		return CodexOAuthFlow{}, ErrCodexOAuthFlowLimitReached
	}
	m.sessions[flowID] = codexOAuthSession{flow: flow, state: state, pkce: pkce}
	return flow, nil
}

// Complete validates one pasted localhost callback and performs at most one provider token exchange.
// Complete 校验一个粘贴的 localhost 回调，并最多执行一次供应商 Token 交换。
func (m *CodexOAuthManager) Complete(ctx context.Context, flowID string, callbackURL string) (CodexToken, error) {
	now := m.now().UTC()
	m.mu.Lock()
	m.pruneExpiredLocked(now)
	session, exists := m.sessions[flowID]
	if !exists {
		m.mu.Unlock()
		return CodexToken{}, ErrCodexOAuthFlowNotFound
	}
	if session.completing {
		m.mu.Unlock()
		return CodexToken{}, ErrCodexOAuthFlowInProgress
	}
	if session.token != nil {
		token := *session.token
		session.completing = true
		m.sessions[flowID] = session
		m.mu.Unlock()
		return token, nil
	}
	session.completing = true
	m.sessions[flowID] = session
	m.mu.Unlock()

	token, errExchange := m.client.ExchangeCallback(ctx, callbackURL, session.state, session.pkce)
	if errExchange != nil {
		m.mu.Lock()
		current, stillExists := m.sessions[flowID]
		if stillExists && current.token == nil {
			current.completing = false
			m.sessions[flowID] = current
		}
		m.mu.Unlock()
		return CodexToken{}, errExchange
	}
	m.mu.Lock()
	current, stillExists := m.sessions[flowID]
	if !stillExists {
		m.mu.Unlock()
		return CodexToken{}, ErrCodexOAuthFlowNotFound
	}
	if !current.flow.ExpiresAt.After(m.now().UTC()) {
		delete(m.sessions, flowID)
		m.mu.Unlock()
		return CodexToken{}, ErrCodexOAuthFlowNotFound
	}
	current.token = &token
	m.sessions[flowID] = current
	m.mu.Unlock()
	return token, nil
}

// Release returns one delivered completed token to the session after downstream onboarding fails.
// Release 在下游录入失败后将一个已交付的完成 Token 归还会话。
func (m *CodexOAuthManager) Release(flowID string) {
	m.mu.Lock()
	session, exists := m.sessions[flowID]
	if exists && session.token != nil {
		session.completing = false
		m.sessions[flowID] = session
	}
	m.mu.Unlock()
}

// Cancel removes one incomplete or completed local authorization session.
// Cancel 删除一个未完成或已完成的本地授权会话。
func (m *CodexOAuthManager) Cancel(flowID string) {
	m.mu.Lock()
	delete(m.sessions, flowID)
	m.mu.Unlock()
}

// pruneExpiredLocked removes expired sessions while the caller owns the manager lock.
// pruneExpiredLocked 在调用方持有管理器锁时删除过期会话。
func (m *CodexOAuthManager) pruneExpiredLocked(now time.Time) {
	for flowID, session := range m.sessions {
		if !session.flow.ExpiresAt.After(now) {
			delete(m.sessions, flowID)
		}
	}
}

// authorizationURL builds CLIProxyAPI's exact OpenAI account consent query.
// authorizationURL 构建 CLIProxyAPI 的精确 OpenAI 账号同意授权查询。
func (c *CodexOAuthClient) authorizationURL(state string, pkce codexPKCECodes) (string, error) {
	endpoint, errEndpoint := url.Parse(c.authorizationEndpoint)
	if errEndpoint != nil {
		return "", fmt.Errorf("parse Codex authorization endpoint: %w", errEndpoint)
	}
	query := endpoint.Query()
	query.Set("client_id", codexOAuthClientID)
	query.Set("response_type", "code")
	query.Set("redirect_uri", codexBrowserRedirectURI)
	query.Set("scope", codexBrowserScope)
	query.Set("state", state)
	query.Set("code_challenge", pkce.challenge)
	query.Set("code_challenge_method", "S256")
	query.Set("prompt", "login")
	query.Set("id_token_add_organizations", "true")
	query.Set("codex_cli_simplified_flow", "true")
	endpoint.RawQuery = query.Encode()
	return endpoint.String(), nil
}

// ExchangeCallback validates the exact localhost callback and exchanges its authorization code.
// ExchangeCallback 校验精确 localhost 回调并交换其中的授权码。
func (c *CodexOAuthClient) ExchangeCallback(ctx context.Context, callbackURL string, expectedState string, pkce codexPKCECodes) (CodexToken, error) {
	code, errCallback := parseCodexOAuthCallback(callbackURL, expectedState)
	if errCallback != nil {
		return CodexToken{}, errCallback
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {codexOAuthClientID},
		"code":          {code},
		"redirect_uri":  {codexBrowserRedirectURI},
		"code_verifier": {pkce.verifier},
	}
	encodedForm := []byte(form.Encode())
	defer clear(encodedForm)
	request, errRequest := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenEndpoint, bytes.NewReader(encodedForm))
	if errRequest != nil {
		return CodexToken{}, fmt.Errorf("create Codex OAuth token request: %w", errRequest)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	response, errResponse := c.httpClient.Do(request)
	if errResponse != nil {
		return CodexToken{}, fmt.Errorf("request Codex OAuth token: %w", errResponse)
	}
	defer response.Body.Close()
	body, errBody := io.ReadAll(io.LimitReader(response.Body, maximumCodexOAuthResponseBytes+1))
	if errBody != nil {
		return CodexToken{}, fmt.Errorf("read Codex OAuth token response: %w", errBody)
	}
	defer clear(body)
	if len(body) > maximumCodexOAuthResponseBytes {
		return CodexToken{}, errors.New("Codex OAuth token response exceeds the allowed size")
	}
	if response.StatusCode != http.StatusOK {
		return CodexToken{}, fmt.Errorf("Codex OAuth token request returned status %d", response.StatusCode)
	}
	var payload codexOAuthTokenResponse
	if errDecode := json.Unmarshal(body, &payload); errDecode != nil {
		return CodexToken{}, fmt.Errorf("decode Codex OAuth token response: %w", errDecode)
	}
	if payload.ExpiresIn <= 0 || payload.ExpiresIn > int64(time.Duration(1<<63-1)/time.Second) {
		return CodexToken{}, errors.New("Codex OAuth token response expiry is invalid")
	}
	claims, errClaims := parseCodexJWT(payload.IDToken)
	if errClaims != nil {
		return CodexToken{}, errClaims
	}
	token := CodexToken{
		IDToken: payload.IDToken, AccessToken: payload.AccessToken, RefreshToken: payload.RefreshToken,
		AccountID: claims.Auth.AccountID, Email: claims.Email,
		ExpiresAt: c.now().UTC().Add(time.Duration(payload.ExpiresIn) * time.Second), Type: "codex",
	}
	if errValidate := validateCodexToken(token); errValidate != nil {
		return CodexToken{}, errValidate
	}
	if strings.TrimSpace(token.AccountID) == "" && strings.TrimSpace(token.Email) == "" {
		return CodexToken{}, errors.New("Codex OAuth token response omitted account identity")
	}
	return token, nil
}

// parseCodexOAuthCallback accepts only the exact provider-registered localhost redirect and matching State.
// parseCodexOAuthCallback 仅接受精确的供应商注册 localhost 重定向与匹配 State。
func parseCodexOAuthCallback(callbackURL string, expectedState string) (string, error) {
	parsed, errParse := url.Parse(strings.TrimSpace(callbackURL))
	if errParse != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.Fragment != "" || !strings.EqualFold(parsed.Hostname(), "localhost") || parsed.Port() != "1455" || parsed.EscapedPath() != "/auth/callback" {
		return "", errors.New("Codex OAuth callback must use the registered localhost redirect")
	}
	query := parsed.Query()
	if len(query["error"]) > 1 || len(query["state"]) != 1 {
		return "", errors.New("Codex OAuth callback must contain one state")
	}
	if providerError := strings.TrimSpace(query.Get("error")); providerError != "" {
		return "", fmt.Errorf("Codex OAuth callback returned error %s", providerError)
	}
	if len(query["code"]) != 1 {
		return "", errors.New("Codex OAuth callback must contain one authorization code")
	}
	if query.Get("state") != expectedState {
		return "", errors.New("Codex OAuth callback state mismatch")
	}
	code := strings.TrimSpace(query.Get("code"))
	if code == "" {
		return "", errors.New("Codex OAuth callback omitted authorization code")
	}
	return code, nil
}

// generateCodexPKCE copies CLIProxyAPI's 96-byte verifier and S256 challenge construction.
// generateCodexPKCE 复制 CLIProxyAPI 的 96 字节 Verifier 与 S256 Challenge 构造方式。
func generateCodexPKCE() (codexPKCECodes, error) {
	buffer := make([]byte, 96)
	if _, errRead := rand.Read(buffer); errRead != nil {
		return codexPKCECodes{}, fmt.Errorf("generate Codex PKCE verifier: %w", errRead)
	}
	verifier := base64.RawURLEncoding.EncodeToString(buffer)
	clear(buffer)
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	return codexPKCECodes{verifier: verifier, challenge: challenge}, nil
}
