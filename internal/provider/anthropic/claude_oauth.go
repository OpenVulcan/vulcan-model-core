package anthropic

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
)

const (
	// claudeAuthorizationEndpoint is CLIProxyAPI's fixed Claude authorization endpoint.
	// claudeAuthorizationEndpoint 是 CLIProxyAPI 固定的 Claude 授权端点。
	claudeAuthorizationEndpoint = "https://claude.ai/oauth/authorize"
	// claudeTokenEndpoint is CLIProxyAPI's fixed Anthropic OAuth token endpoint.
	// claudeTokenEndpoint 是 CLIProxyAPI 固定的 Anthropic OAuth Token 端点。
	claudeTokenEndpoint = "https://api.anthropic.com/v1/oauth/token"
	// claudeOAuthClientID is the public Claude Code OAuth client identifier copied from CLIProxyAPI.
	// claudeOAuthClientID 是从 CLIProxyAPI 复制的公开 Claude Code OAuth 客户端标识。
	claudeOAuthClientID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
	// claudeOAuthRedirectURI is the provider-registered Claude Code localhost callback.
	// claudeOAuthRedirectURI 是供应商注册的 Claude Code 本地回调地址。
	claudeOAuthRedirectURI = "http://localhost:54545/callback"
	// claudeOAuthScope preserves CLIProxyAPI's complete account, inference, session, MCP, and upload scope set.
	// claudeOAuthScope 保留 CLIProxyAPI 完整的账号、推理、会话、MCP 与上传 Scope 集合。
	claudeOAuthScope = "user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload"
	// claudeOAuthFlowLifetime matches CLIProxyAPI's five-minute callback window.
	// claudeOAuthFlowLifetime 与 CLIProxyAPI 的五分钟回调窗口一致。
	claudeOAuthFlowLifetime = 5 * time.Minute
	// maximumClaudeOAuthFlows bounds retained PKCE and CSRF state.
	// maximumClaudeOAuthFlows 限制保留的 PKCE 与 CSRF 状态数量。
	maximumClaudeOAuthFlows = 32
	// maximumClaudeOAuthResponseBytes bounds provider token responses before decoding.
	// maximumClaudeOAuthResponseBytes 在解码前限制供应商 Token 响应大小。
	maximumClaudeOAuthResponseBytes = 64 << 10
	// claudeRefreshMinBackoff is CLIProxyAPI's minimum 429 replay block.
	// claudeRefreshMinBackoff 是 CLIProxyAPI 的最小 429 重放阻断时间。
	claudeRefreshMinBackoff = 5 * time.Second
	// claudeRefreshMaxBackoff is CLIProxyAPI's maximum 429 replay block.
	// claudeRefreshMaxBackoff 是 CLIProxyAPI 的最大 429 重放阻断时间。
	claudeRefreshMaxBackoff = 5 * time.Minute
	// claudeRefreshAttempts preserves CLIProxyAPI's three-attempt refresh behavior.
	// claudeRefreshAttempts 保留 CLIProxyAPI 的三次刷新尝试行为。
	claudeRefreshAttempts = 3
)

var (
	// ErrClaudeOAuthFlowNotFound reports an unknown, expired, or consumed server-owned flow.
	// ErrClaudeOAuthFlowNotFound 表示未知、过期或已消费的服务端授权流程。
	ErrClaudeOAuthFlowNotFound = errors.New("Claude OAuth flow not found")
	// ErrClaudeOAuthFlowInProgress reports a duplicate exchange for one immutable flow.
	// ErrClaudeOAuthFlowInProgress 表示对同一不可变流程发起了重复交换。
	ErrClaudeOAuthFlowInProgress = errors.New("Claude OAuth flow is already completing")
	// ErrClaudeOAuthFlowLimitReached reports bounded in-memory flow exhaustion.
	// ErrClaudeOAuthFlowLimitReached 表示有界内存授权流程已耗尽。
	ErrClaudeOAuthFlowLimitReached = errors.New("Claude OAuth flow limit reached")
)

// claudePKCECodes stores the RFC 7636 verifier and S256 challenge only inside the server process.
// claudePKCECodes 仅在服务进程内存中存储 RFC 7636 Verifier 与 S256 Challenge。
type claudePKCECodes struct {
	// CodeVerifier is the 128-character URL-safe verifier copied from CLIProxyAPI behavior.
	// CodeVerifier 是从 CLIProxyAPI 行为复制的 128 字符 URL 安全 Verifier。
	CodeVerifier string
	// CodeChallenge is the unpadded base64url SHA-256 digest.
	// CodeChallenge 是无填充 base64url SHA-256 摘要。
	CodeChallenge string
}

// ClaudeOAuthFlow is the management-safe projection of one server-owned Claude authorization session.
// ClaudeOAuthFlow 是一个服务端拥有的 Claude 授权会话的管理安全投影。
type ClaudeOAuthFlow struct {
	// ID identifies the in-memory flow without revealing State or PKCE material.
	// ID 标识内存流程且不暴露 State 或 PKCE 材料。
	ID string `json:"id"`
	// AuthorizationURL is the exact provider consent URL.
	// AuthorizationURL 是精确的供应商同意授权地址。
	AuthorizationURL string `json:"authorization_url"`
	// RedirectURI tells the administrator which failed localhost callback to copy.
	// RedirectURI 告知管理员应复制哪个可能失败的本地回调地址。
	RedirectURI string `json:"redirect_uri"`
	// ExpiresAt bounds retention of PKCE and State.
	// ExpiresAt 限制 PKCE 与 State 的保留时间。
	ExpiresAt time.Time `json:"expires_at"`
}

// claudeOAuthSession retains sensitive flow material and an idempotent successful result server-side.
// claudeOAuthSession 在服务端保留敏感流程材料与幂等成功结果。
type claudeOAuthSession struct {
	// flow is the management-safe projection.
	// flow 是管理安全投影。
	flow ClaudeOAuthFlow
	// state is the exact CSRF value sent to Anthropic.
	// state 是发送给 Anthropic 的精确 CSRF 值。
	state string
	// pkce contains the verifier never exposed to the browser UI.
	// pkce 包含绝不向浏览器界面暴露的 Verifier。
	pkce claudePKCECodes
	// completing leases the provider exchange or completed result to one downstream onboarding request.
	// completing 将供应商交换或已完成结果租给一个下游录入请求。
	completing bool
	// token retains one completed result until onboarding consumes the flow.
	// token 保留一个已完成结果，直至录入流程消费它。
	token *ClaudeToken
}

// ClaudeFlowManager owns transient Claude PKCE and State without exposing provider tokens.
// ClaudeFlowManager 管理临时 Claude PKCE 与 State，且不暴露供应商 Token。
type ClaudeFlowManager struct {
	// client performs the exact OAuth token exchanges.
	// client 执行精确 OAuth Token 交换。
	client *ClaudeOAuthClient
	// now supplies the flow clock and is replaceable by focused package tests.
	// now 提供流程时钟，并可由聚焦包测试替换。
	now func() time.Time
	// mu protects all sessions.
	// mu 保护全部会话。
	mu sync.Mutex
	// sessions owns incomplete or not-yet-consumed authorization state.
	// sessions 管理未完成或尚未消费的授权状态。
	sessions map[string]claudeOAuthSession
}

// claudeOAuthOrganization is the organization projection returned by Anthropic's token endpoint.
// claudeOAuthOrganization 是 Anthropic Token 端点返回的组织投影。
type claudeOAuthOrganization struct {
	// UUID is the stable organization identifier.
	// UUID 是稳定组织标识。
	UUID string `json:"uuid"`
	// Name is the provider-reported organization name.
	// Name 是供应商报告的组织名称。
	Name string `json:"name"`
}

// claudeOAuthAccount is the account projection returned by Anthropic's token endpoint.
// claudeOAuthAccount 是 Anthropic Token 端点返回的账号投影。
type claudeOAuthAccount struct {
	// UUID is the stable Anthropic account identifier.
	// UUID 是稳定 Anthropic 账号标识。
	UUID string `json:"uuid"`
	// EmailAddress is the provider-reported account email.
	// EmailAddress 是供应商报告的账号邮箱。
	EmailAddress string `json:"email_address"`
}

// claudeOAuthTokenResponse mirrors CLIProxyAPI's typed Anthropic token response.
// claudeOAuthTokenResponse 镜像 CLIProxyAPI 的类型化 Anthropic Token 响应。
type claudeOAuthTokenResponse struct {
	// AccessToken authorizes Claude requests.
	// AccessToken 授权 Claude 请求。
	AccessToken string `json:"access_token"`
	// RefreshToken obtains future access tokens.
	// RefreshToken 用于获取后续 Access Token。
	RefreshToken string `json:"refresh_token"`
	// TokenType is the provider-issued authorization scheme.
	// TokenType 是供应商签发的授权方案。
	TokenType string `json:"token_type"`
	// ExpiresIn is the access-token lifetime in seconds.
	// ExpiresIn 是 Access Token 有效期秒数。
	ExpiresIn int64 `json:"expires_in"`
	// Organization contains the provider-reported organization identity.
	// Organization 包含供应商报告的组织身份。
	Organization claudeOAuthOrganization `json:"organization"`
	// Account contains the provider-reported account identity.
	// Account 包含供应商报告的账号身份。
	Account claudeOAuthAccount `json:"account"`
}

// claudeTokenRequest seals the only two OAuth request documents accepted by the Anthropic token endpoint.
// claudeTokenRequest 封闭 Anthropic Token 入口仅接受的两种 OAuth 请求文档。
type claudeTokenRequest interface {
	// isClaudeTokenRequest prevents arbitrary payload shapes from entering the OAuth exchange boundary.
	// isClaudeTokenRequest 阻止任意正文形状进入 OAuth 交换边界。
	isClaudeTokenRequest()
}

// claudeAuthorizationCodeRequest mirrors CLIProxyAPI's JSON authorization-code exchange body.
// claudeAuthorizationCodeRequest 镜像 CLIProxyAPI 的 JSON 授权码交换正文。
type claudeAuthorizationCodeRequest struct {
	// Code is the callback authorization code without an appended State fragment.
	// Code 是移除追加 State 片段后的回调授权码。
	Code string `json:"code"`
	// State is the exact server-owned CSRF value.
	// State 是精确的服务端拥有 CSRF 值。
	State string `json:"state"`
	// GrantType fixes the OAuth authorization-code grant.
	// GrantType 固定 OAuth 授权码 Grant。
	GrantType string `json:"grant_type"`
	// ClientID is the public Claude Code client identifier.
	// ClientID 是公开 Claude Code 客户端标识。
	ClientID string `json:"client_id"`
	// RedirectURI is the provider-registered localhost callback.
	// RedirectURI 是供应商注册的本地回调地址。
	RedirectURI string `json:"redirect_uri"`
	// CodeVerifier proves possession of the server-owned PKCE secret.
	// CodeVerifier 证明持有服务端拥有的 PKCE Secret。
	CodeVerifier string `json:"code_verifier"`
}

// isClaudeTokenRequest marks the authorization-code exchange as an allowed Claude token request.
// isClaudeTokenRequest 将授权码交换标记为允许的 Claude Token 请求。
func (claudeAuthorizationCodeRequest) isClaudeTokenRequest() {}

// claudeRefreshTokenRequest mirrors CLIProxyAPI's JSON refresh exchange body.
// claudeRefreshTokenRequest 镜像 CLIProxyAPI 的 JSON 刷新交换正文。
type claudeRefreshTokenRequest struct {
	// ClientID is the public Claude Code client identifier.
	// ClientID 是公开 Claude Code 客户端标识。
	ClientID string `json:"client_id"`
	// GrantType fixes the OAuth refresh-token grant.
	// GrantType 固定 OAuth Refresh Token Grant。
	GrantType string `json:"grant_type"`
	// RefreshToken is the protected provider token being exchanged.
	// RefreshToken 是正在交换的受保护供应商 Token。
	RefreshToken string `json:"refresh_token"`
}

// isClaudeTokenRequest marks the refresh exchange as an allowed Claude token request.
// isClaudeTokenRequest 将刷新交换标记为允许的 Claude Token 请求。
func (claudeRefreshTokenRequest) isClaudeTokenRequest() {}

// claudeRefreshHTTPError carries retry classification without retaining a provider response body.
// claudeRefreshHTTPError 携带重试分类且不保留供应商响应正文。
type claudeRefreshHTTPError struct {
	// status is the upstream HTTP status.
	// status 是上游 HTTP 状态码。
	status int
	// retryable permits only transient 5xx retries.
	// retryable 仅允许瞬时 5xx 重试。
	retryable bool
}

// Error returns one credential-free Claude refresh failure.
// Error 返回一个不含凭据的 Claude 刷新失败。
func (e *claudeRefreshHTTPError) Error() string {
	return fmt.Sprintf("Claude token refresh failed with status %d", e.status)
}

// Retryable reports whether CLIProxyAPI permits another attempt.
// Retryable 报告 CLIProxyAPI 是否允许再次尝试。
func (e *claudeRefreshHTTPError) Retryable() bool {
	return e != nil && e.retryable
}

// claudeOAuthRefreshCall shares one provider exchange between concurrent callers.
// claudeOAuthRefreshCall 在并发调用方之间共享一次供应商交换。
type claudeOAuthRefreshCall struct {
	// done closes after token and err become immutable.
	// done 在 token 与 err 不可变后关闭。
	done chan struct{}
	// token is the complete refreshed protected document.
	// token 是完整的已刷新受保护文档。
	token ClaudeToken
	// err is the shared exchange result.
	// err 是共享交换结果。
	err error
}

// ClaudeOAuthClient performs copied Claude Code authorization and refresh exchanges through uTLS.
// ClaudeOAuthClient 通过 uTLS 执行复制的 Claude Code 授权与刷新交换。
type ClaudeOAuthClient struct {
	// httpClient owns the Chrome-uTLS transport and bounded timeout.
	// httpClient 管理 Chrome-uTLS 传输与有界超时。
	httpClient *http.Client
	// tokenEndpoint is production-fixed and replaceable only by same-package tests.
	// tokenEndpoint 在生产中固定，且仅可由同包测试替换。
	tokenEndpoint string
	// now supplies exchange and backoff timestamps.
	// now 提供交换与退避时间戳。
	now func() time.Time
	// wait applies CLIProxyAPI's retry delay and is replaceable by focused tests.
	// wait 应用 CLIProxyAPI 的重试延迟，并可由聚焦测试替换。
	wait func(context.Context, time.Duration) error
	// refreshMu protects calls and blockedUntil.
	// refreshMu 保护 calls 与 blockedUntil。
	refreshMu sync.Mutex
	// calls deduplicates exchanges by a non-reversible refresh-token digest.
	// calls 按不可逆 Refresh Token 摘要去重交换。
	calls map[[sha256.Size]byte]*claudeOAuthRefreshCall
	// blockedUntil retains one 429 replay boundary per refresh-token digest.
	// blockedUntil 按 Refresh Token 摘要保留一个 429 重放边界。
	blockedUntil map[[sha256.Size]byte]time.Time
}

// NewClaudeOAuthClient creates one production-fixed Claude OAuth client.
// NewClaudeOAuthClient 创建一个生产端点固定的 Claude OAuth 客户端。
func NewClaudeOAuthClient(httpClient *http.Client) (*ClaudeOAuthClient, error) {
	return newClaudeOAuthClient(httpClient, claudeTokenEndpoint)
}

// newClaudeOAuthClient creates one Claude OAuth client with an explicit code-owned test endpoint.
// newClaudeOAuthClient 使用显式代码拥有的测试端点创建 Claude OAuth 客户端。
func newClaudeOAuthClient(httpClient *http.Client, tokenEndpoint string) (*ClaudeOAuthClient, error) {
	if httpClient == nil {
		return nil, errors.New("Claude OAuth HTTP client is required")
	}
	parsedEndpoint, errEndpoint := url.Parse(tokenEndpoint)
	if errEndpoint != nil || parsedEndpoint.Scheme == "" || parsedEndpoint.Host == "" || parsedEndpoint.User != nil || parsedEndpoint.Fragment != "" {
		return nil, errors.New("Claude OAuth token endpoint must be one absolute credential-free URL")
	}
	if parsedEndpoint.Scheme != "https" && parsedEndpoint.Scheme != "http" {
		return nil, errors.New("Claude OAuth token endpoint scheme is unsupported")
	}
	clonedHTTPClient := *httpClient
	clonedHTTPClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &ClaudeOAuthClient{
		httpClient:    &clonedHTTPClient,
		tokenEndpoint: parsedEndpoint.String(),
		now:           time.Now,
		wait:          waitForClaudeRefresh,
		calls:         make(map[[sha256.Size]byte]*claudeOAuthRefreshCall),
		blockedUntil:  make(map[[sha256.Size]byte]time.Time),
	}, nil
}

// AuthorizationURL builds the exact CLIProxyAPI Claude Code consent URL.
// AuthorizationURL 构建精确的 CLIProxyAPI Claude Code 同意授权地址。
func (c *ClaudeOAuthClient) AuthorizationURL(state string, pkce claudePKCECodes) (string, error) {
	if strings.TrimSpace(state) == "" || strings.TrimSpace(pkce.CodeChallenge) == "" || strings.TrimSpace(pkce.CodeVerifier) == "" {
		return "", errors.New("Claude OAuth State and PKCE codes are required")
	}
	parameters := url.Values{
		"code":                  {"true"},
		"client_id":             {claudeOAuthClientID},
		"response_type":         {"code"},
		"redirect_uri":          {claudeOAuthRedirectURI},
		"scope":                 {claudeOAuthScope},
		"code_challenge":        {pkce.CodeChallenge},
		"code_challenge_method": {"S256"},
		"state":                 {state},
	}
	return claudeAuthorizationEndpoint + "?" + parameters.Encode(), nil
}

// ExchangeCallback validates one pasted localhost callback and exchanges its code through the copied JSON contract.
// ExchangeCallback 校验一个粘贴的本地回调，并通过复制的 JSON 合同交换其中授权码。
func (c *ClaudeOAuthClient) ExchangeCallback(ctx context.Context, callback string, expectedState string, pkce claudePKCECodes) (ClaudeToken, error) {
	code, errCallback := parseClaudeAuthorizationInput(callback, expectedState)
	if errCallback != nil {
		return ClaudeToken{}, errCallback
	}
	payload := claudeAuthorizationCodeRequest{
		Code: code, State: expectedState, GrantType: "authorization_code", ClientID: claudeOAuthClientID,
		RedirectURI: claudeOAuthRedirectURI, CodeVerifier: pkce.CodeVerifier,
	}
	response, statusCode, _, errRequest := c.requestToken(ctx, payload)
	if errRequest != nil {
		return ClaudeToken{}, errRequest
	}
	if statusCode != http.StatusOK {
		return ClaudeToken{}, fmt.Errorf("Claude token exchange failed with status %d", statusCode)
	}
	return c.tokenFromResponse(response, nil)
}

// Refresh applies CLIProxyAPI's per-token single-flight, 429 block, and three-attempt retry behavior.
// Refresh 应用 CLIProxyAPI 的按 Token 单飞、429 阻断与三次尝试刷新行为。
func (c *ClaudeOAuthClient) Refresh(ctx context.Context, token ClaudeToken) (ClaudeToken, error) {
	if errContext := ctx.Err(); errContext != nil {
		return ClaudeToken{}, errContext
	}
	if errToken := validateClaudeToken(token); errToken != nil {
		return ClaudeToken{}, errToken
	}
	refreshKey := sha256.Sum256([]byte(token.RefreshToken))
	c.refreshMu.Lock()
	now := c.now().UTC()
	c.pruneExpiredRefreshBlocksLocked(now)
	if blocked := c.blockedUntil[refreshKey]; blocked.After(now) {
		c.refreshMu.Unlock()
		return ClaudeToken{}, classifyClaudeRefreshError(&claudeRefreshHTTPError{status: http.StatusTooManyRequests, retryable: false})
	}
	if existing, exists := c.calls[refreshKey]; exists {
		c.refreshMu.Unlock()
		select {
		case <-existing.done:
			return existing.token, existing.err
		case <-ctx.Done():
			return ClaudeToken{}, ctx.Err()
		}
	}
	call := &claudeOAuthRefreshCall{done: make(chan struct{})}
	c.calls[refreshKey] = call
	c.refreshMu.Unlock()

	call.token, call.err = c.refreshWithRetry(context.WithoutCancel(ctx), token, refreshKey, claudeRefreshAttempts)
	call.err = classifyClaudeRefreshError(call.err)
	c.refreshMu.Lock()
	delete(c.calls, refreshKey)
	close(call.done)
	c.refreshMu.Unlock()
	return call.token, call.err
}

// pruneExpiredRefreshBlocksLocked removes obsolete 429 replay boundaries while the caller owns refreshMu.
// pruneExpiredRefreshBlocksLocked 在调用方持有 refreshMu 时移除过期的 429 重放边界。
func (c *ClaudeOAuthClient) pruneExpiredRefreshBlocksLocked(now time.Time) {
	for refreshKey, blockedUntil := range c.blockedUntil {
		if !blockedUntil.After(now) {
			delete(c.blockedUntil, refreshKey)
		}
	}
}

// refreshWithRetry preserves CLIProxyAPI's linear one-second-per-attempt delay and retry classification.
// refreshWithRetry 保留 CLIProxyAPI 的逐次增加一秒延迟与重试分类。
func (c *ClaudeOAuthClient) refreshWithRetry(ctx context.Context, token ClaudeToken, refreshKey [sha256.Size]byte, maximumAttempts int) (ClaudeToken, error) {
	var lastErr error
	for attempt := 0; attempt < maximumAttempts; attempt++ {
		if attempt > 0 {
			if errWait := c.wait(ctx, time.Duration(attempt)*time.Second); errWait != nil {
				return ClaudeToken{}, errWait
			}
		}
		refreshed, errRefresh := c.refreshOnce(ctx, token, refreshKey)
		if errRefresh == nil {
			return refreshed, nil
		}
		lastErr = errRefresh
		if !isClaudeRefreshRetryable(errRefresh) {
			break
		}
	}
	return ClaudeToken{}, fmt.Errorf("Claude token refresh failed after %d attempts: %w", maximumAttempts, lastErr)
}

// classifyClaudeRefreshError preserves CLIProxyAPI retry behavior while exposing one stable management-safe failure category.
// classifyClaudeRefreshError 保留 CLIProxyAPI 重试行为，同时暴露一个稳定且管理安全的失败分类。
func classifyClaudeRefreshError(errRefresh error) error {
	if errRefresh == nil || errors.Is(errRefresh, context.Canceled) || errors.Is(errRefresh, context.DeadlineExceeded) {
		return errRefresh
	}
	if errors.Is(errRefresh, provider.ErrAuthenticationRejected) || errors.Is(errRefresh, provider.ErrAuthenticationUnavailable) || errors.Is(errRefresh, provider.ErrAuthenticationResponseInvalid) {
		return errRefresh
	}
	var statusError *claudeRefreshHTTPError
	if errors.As(errRefresh, &statusError) {
		switch {
		case statusError.status == http.StatusBadRequest || statusError.status == http.StatusUnauthorized || statusError.status == http.StatusForbidden:
			return fmt.Errorf("%w: %w", provider.ErrAuthenticationRejected, errRefresh)
		case statusError.status == http.StatusRequestTimeout || statusError.status == http.StatusTooManyRequests || statusError.status >= http.StatusInternalServerError:
			return fmt.Errorf("%w: %w", provider.ErrAuthenticationUnavailable, errRefresh)
		default:
			return fmt.Errorf("%w: %w", provider.ErrAuthenticationResponseInvalid, errRefresh)
		}
	}
	return fmt.Errorf("%w: %w", provider.ErrAuthenticationResponseInvalid, errRefresh)
}

// refreshOnce performs one exact JSON refresh exchange and updates the replay block.
// refreshOnce 执行一次精确 JSON 刷新交换并更新重放阻断状态。
func (c *ClaudeOAuthClient) refreshOnce(ctx context.Context, token ClaudeToken, refreshKey [sha256.Size]byte) (ClaudeToken, error) {
	c.refreshMu.Lock()
	if blocked := c.blockedUntil[refreshKey]; blocked.After(c.now().UTC()) {
		c.refreshMu.Unlock()
		return ClaudeToken{}, &claudeRefreshHTTPError{status: http.StatusTooManyRequests, retryable: false}
	}
	c.refreshMu.Unlock()
	payload := claudeRefreshTokenRequest{ClientID: claudeOAuthClientID, GrantType: "refresh_token", RefreshToken: token.RefreshToken}
	response, statusCode, headers, errRequest := c.requestToken(ctx, payload)
	if errRequest != nil {
		return ClaudeToken{}, errRequest
	}
	if statusCode != http.StatusOK {
		if statusCode == http.StatusTooManyRequests {
			blockedUntil := c.now().UTC().Add(parseClaudeRetryAfter(headers, c.now().UTC()))
			c.refreshMu.Lock()
			c.blockedUntil[refreshKey] = blockedUntil
			c.refreshMu.Unlock()
			return ClaudeToken{}, &claudeRefreshHTTPError{status: statusCode, retryable: false}
		}
		return ClaudeToken{}, &claudeRefreshHTTPError{status: statusCode, retryable: statusCode >= http.StatusInternalServerError}
	}
	refreshed, errToken := c.tokenFromResponse(response, &token)
	if errToken != nil {
		return ClaudeToken{}, errToken
	}
	c.refreshMu.Lock()
	delete(c.blockedUntil, refreshKey)
	c.refreshMu.Unlock()
	return refreshed, nil
}

// requestToken sends one bounded JSON token request and never retains an unsuccessful response body.
// requestToken 发送一条有界 JSON Token 请求，且绝不保留失败响应正文。
func (c *ClaudeOAuthClient) requestToken(ctx context.Context, payload claudeTokenRequest) (claudeOAuthTokenResponse, int, http.Header, error) {
	encoded, errEncode := json.Marshal(payload)
	if errEncode != nil {
		return claudeOAuthTokenResponse{}, 0, nil, fmt.Errorf("encode Claude token request: %w", errEncode)
	}
	request, errRequest := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenEndpoint, bytes.NewReader(encoded))
	if errRequest != nil {
		clear(encoded)
		return claudeOAuthTokenResponse{}, 0, nil, fmt.Errorf("create Claude token request: %w", errRequest)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, errDo := c.httpClient.Do(request)
	clear(encoded)
	if errDo != nil {
		return claudeOAuthTokenResponse{}, 0, nil, fmt.Errorf("%w: send Claude token request: %w", provider.ErrAuthenticationUnavailable, errDo)
	}
	defer response.Body.Close()
	body, errBody := io.ReadAll(io.LimitReader(response.Body, maximumClaudeOAuthResponseBytes+1))
	if errBody != nil {
		return claudeOAuthTokenResponse{}, 0, nil, fmt.Errorf("%w: read Claude token response: %w", provider.ErrAuthenticationUnavailable, errBody)
	}
	defer clear(body)
	if len(body) > maximumClaudeOAuthResponseBytes {
		return claudeOAuthTokenResponse{}, 0, nil, fmt.Errorf("%w: Claude token response exceeds the allowed size", provider.ErrAuthenticationResponseInvalid)
	}
	if response.StatusCode != http.StatusOK {
		return claudeOAuthTokenResponse{}, response.StatusCode, response.Header.Clone(), nil
	}
	var decoded claudeOAuthTokenResponse
	if errDecode := json.Unmarshal(body, &decoded); errDecode != nil {
		return claudeOAuthTokenResponse{}, 0, nil, fmt.Errorf("%w: decode Claude token response: %w", provider.ErrAuthenticationResponseInvalid, errDecode)
	}
	return decoded, response.StatusCode, response.Header.Clone(), nil
}

// tokenFromResponse validates one provider response and preserves identity fields omitted during refresh.
// tokenFromResponse 校验一个供应商响应，并保留刷新时省略的身份字段。
func (c *ClaudeOAuthClient) tokenFromResponse(response claudeOAuthTokenResponse, previous *ClaudeToken) (ClaudeToken, error) {
	now := c.now().UTC().Unix()
	if response.ExpiresIn <= 0 || response.ExpiresIn > math.MaxInt64-now {
		return ClaudeToken{}, errors.New("Claude token response expiry is invalid")
	}
	token := ClaudeToken{
		AccessToken: response.AccessToken, RefreshToken: response.RefreshToken, TokenType: response.TokenType,
		ExpiresAt: now + response.ExpiresIn, LastRefreshAt: now, Email: response.Account.EmailAddress,
		AccountID: response.Account.UUID, OrganizationID: response.Organization.UUID,
		OrganizationName: response.Organization.Name, Type: claudeTokenDocumentType,
	}
	if previous != nil {
		if token.RefreshToken == "" {
			token.RefreshToken = previous.RefreshToken
		}
		if token.TokenType == "" {
			token.TokenType = previous.TokenType
		}
		if token.Email == "" {
			token.Email = previous.Email
		}
		if token.AccountID == "" {
			token.AccountID = previous.AccountID
		}
		if token.OrganizationID == "" {
			token.OrganizationID = previous.OrganizationID
		}
		if token.OrganizationName == "" {
			token.OrganizationName = previous.OrganizationName
		}
	}
	if errValidate := validateClaudeToken(token); errValidate != nil {
		return ClaudeToken{}, errValidate
	}
	return token, nil
}

// NewClaudeFlowManager creates one bounded server-owned Claude authorization manager.
// NewClaudeFlowManager 创建一个有界且由服务端拥有的 Claude 授权管理器。
func NewClaudeFlowManager(client *ClaudeOAuthClient) (*ClaudeFlowManager, error) {
	if client == nil {
		return nil, errors.New("Claude OAuth client is required")
	}
	return &ClaudeFlowManager{client: client, now: time.Now, sessions: make(map[string]claudeOAuthSession)}, nil
}

// Start creates one exact authorization URL while retaining State and PKCE only in memory.
// Start 创建一个精确授权地址，同时仅在内存中保留 State 与 PKCE。
func (m *ClaudeFlowManager) Start(ctx context.Context) (ClaudeOAuthFlow, error) {
	if errContext := ctx.Err(); errContext != nil {
		return ClaudeOAuthFlow{}, errContext
	}
	flowID, errFlowID := randomClaudeHex(16)
	if errFlowID != nil {
		return ClaudeOAuthFlow{}, errFlowID
	}
	state, errState := randomClaudeHex(16)
	if errState != nil {
		return ClaudeOAuthFlow{}, errState
	}
	pkce, errPKCE := generateClaudePKCECodes()
	if errPKCE != nil {
		return ClaudeOAuthFlow{}, errPKCE
	}
	authorizationURL, errAuthorizationURL := m.client.AuthorizationURL(state, pkce)
	if errAuthorizationURL != nil {
		return ClaudeOAuthFlow{}, errAuthorizationURL
	}
	now := m.now().UTC()
	flow := ClaudeOAuthFlow{ID: flowID, AuthorizationURL: authorizationURL, RedirectURI: claudeOAuthRedirectURI, ExpiresAt: now.Add(claudeOAuthFlowLifetime)}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneExpiredLocked(now)
	if len(m.sessions) >= maximumClaudeOAuthFlows {
		return ClaudeOAuthFlow{}, ErrClaudeOAuthFlowLimitReached
	}
	m.sessions[flowID] = claudeOAuthSession{flow: flow, state: state, pkce: pkce}
	return flow, nil
}

// Complete validates one callback, deduplicates exchange, and retains success until explicit consumption.
// Complete 校验一个回调、去重交换，并保留成功结果直至显式消费。
func (m *ClaudeFlowManager) Complete(ctx context.Context, flowID string, callback string) (ClaudeToken, error) {
	now := m.now().UTC()
	m.mu.Lock()
	m.pruneExpiredLocked(now)
	session, exists := m.sessions[flowID]
	if !exists {
		m.mu.Unlock()
		return ClaudeToken{}, ErrClaudeOAuthFlowNotFound
	}
	if session.completing {
		m.mu.Unlock()
		return ClaudeToken{}, ErrClaudeOAuthFlowInProgress
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

	token, errToken := m.client.ExchangeCallback(ctx, callback, session.state, session.pkce)
	if errToken != nil {
		m.mu.Lock()
		current, stillExists := m.sessions[flowID]
		if stillExists {
			current.completing = false
			m.sessions[flowID] = current
		}
		m.mu.Unlock()
		return ClaudeToken{}, errToken
	}
	m.mu.Lock()
	current, stillExists := m.sessions[flowID]
	if !stillExists || !m.now().UTC().Before(current.flow.ExpiresAt) {
		delete(m.sessions, flowID)
		m.mu.Unlock()
		return ClaudeToken{}, ErrClaudeOAuthFlowNotFound
	}
	current.token = &token
	m.sessions[flowID] = current
	m.mu.Unlock()
	return token, nil
}

// Release returns one delivered completed token to the session after downstream onboarding fails.
// Release 在下游录入失败后将一个已交付的完成 Token 归还会话。
func (m *ClaudeFlowManager) Release(flowID string) {
	m.mu.Lock()
	session, exists := m.sessions[flowID]
	if exists && session.token != nil {
		session.completing = false
		m.sessions[flowID] = session
	}
	m.mu.Unlock()
}

// Cancel consumes one exact incomplete or completed local authorization session.
// Cancel 消费一个精确的未完成或已完成本地授权会话。
func (m *ClaudeFlowManager) Cancel(flowID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, flowID)
}

// pruneExpiredLocked removes sessions whose provider callback window has elapsed.
// pruneExpiredLocked 移除供应商回调窗口已过期的会话。
func (m *ClaudeFlowManager) pruneExpiredLocked(now time.Time) {
	for flowID, session := range m.sessions {
		if !now.Before(session.flow.ExpiresAt) {
			delete(m.sessions, flowID)
		}
	}
}

// generateClaudePKCECodes copies CLIProxyAPI's 96-byte verifier and S256 challenge generation.
// generateClaudePKCECodes 复制 CLIProxyAPI 的 96 字节 Verifier 与 S256 Challenge 生成逻辑。
func generateClaudePKCECodes() (claudePKCECodes, error) {
	randomBytes := make([]byte, 96)
	if _, errRandom := rand.Read(randomBytes); errRandom != nil {
		return claudePKCECodes{}, fmt.Errorf("generate Claude PKCE verifier: %w", errRandom)
	}
	verifier := base64.RawURLEncoding.EncodeToString(randomBytes)
	clear(randomBytes)
	digest := sha256.Sum256([]byte(verifier))
	return claudePKCECodes{CodeVerifier: verifier, CodeChallenge: base64.RawURLEncoding.EncodeToString(digest[:])}, nil
}

// randomClaudeHex returns the exact hex-encoded cryptographic State shape used by CLIProxyAPI.
// randomClaudeHex 返回 CLIProxyAPI 使用的精确十六进制加密 State 形态。
func randomClaudeHex(size int) (string, error) {
	value := make([]byte, size)
	if _, errRandom := rand.Read(value); errRandom != nil {
		return "", fmt.Errorf("generate Claude OAuth identifier: %w", errRandom)
	}
	encoded := hex.EncodeToString(value)
	clear(value)
	return encoded, nil
}

// parseClaudeAuthorizationInput accepts one exact localhost callback or CLIProxyAPI's code#state form.
// parseClaudeAuthorizationInput 接受一个精确本地回调或 CLIProxyAPI 的 code#state 形式。
func parseClaudeAuthorizationInput(raw string, expectedState string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || strings.TrimSpace(expectedState) == "" {
		return "", errors.New("Claude OAuth callback and expected State are required")
	}
	parsed, errParse := url.Parse(trimmed)
	if errParse == nil && parsed.IsAbs() {
		if parsed.Scheme != "http" || parsed.Hostname() != "localhost" || parsed.Port() != "54545" || parsed.EscapedPath() != "/callback" || parsed.User != nil {
			return "", errors.New("Claude OAuth callback origin or path is invalid")
		}
		query := parsed.Query()
		if query.Get("error") != "" {
			return "", errors.New("Claude OAuth provider rejected authorization")
		}
		codes, codeExists := query["code"]
		states, stateExists := query["state"]
		if !codeExists || len(codes) != 1 || strings.TrimSpace(codes[0]) == "" {
			return "", errors.New("Claude OAuth callback requires exactly one authorization code")
		}
		callbackState := ""
		if stateExists {
			if len(states) != 1 {
				return "", errors.New("Claude OAuth callback requires exactly one State")
			}
			callbackState = states[0]
		}
		if parsed.Fragment != "" {
			if callbackState != "" && callbackState != parsed.Fragment {
				return "", errors.New("Claude OAuth callback contains conflicting State values")
			}
			callbackState = parsed.Fragment
		}
		if callbackState != expectedState {
			return "", errors.New("Claude OAuth callback State is invalid")
		}
		code, embeddedState := splitClaudeCodeAndState(codes[0])
		if embeddedState != "" && embeddedState != expectedState {
			return "", errors.New("Claude OAuth authorization code State is invalid")
		}
		if code == "" {
			return "", errors.New("Claude OAuth authorization code is empty")
		}
		return code, nil
	}
	code, state := splitClaudeCodeAndState(trimmed)
	if code == "" || state != expectedState {
		return "", errors.New("Claude OAuth code#state value is invalid")
	}
	return code, nil
}

// splitClaudeCodeAndState preserves CLIProxyAPI's first-fragment code parsing behavior.
// splitClaudeCodeAndState 保留 CLIProxyAPI 的首个片段授权码解析行为。
func splitClaudeCodeAndState(value string) (string, string) {
	parts := strings.Split(value, "#")
	code := strings.TrimSpace(parts[0])
	if len(parts) < 2 {
		return code, ""
	}
	return code, strings.TrimSpace(parts[1])
}

// parseClaudeRetryAfter copies CLIProxyAPI's Retry-After seconds/date and Retry-After-Ms precedence.
// parseClaudeRetryAfter 复制 CLIProxyAPI 的 Retry-After 秒数/日期与 Retry-After-Ms 优先级。
func parseClaudeRetryAfter(headers http.Header, now time.Time) time.Duration {
	if raw := strings.TrimSpace(headers.Get("Retry-After")); raw != "" {
		if seconds, errDuration := time.ParseDuration(raw + "s"); errDuration == nil {
			return clampClaudeRefreshBackoff(seconds)
		}
		if retryAt, errTime := http.ParseTime(raw); errTime == nil {
			return clampClaudeRefreshBackoff(retryAt.Sub(now))
		}
	}
	if raw := strings.TrimSpace(headers.Get("Retry-After-Ms")); raw != "" {
		if milliseconds, errDuration := time.ParseDuration(raw + "ms"); errDuration == nil {
			return clampClaudeRefreshBackoff(milliseconds)
		}
	}
	return claudeRefreshMinBackoff
}

// clampClaudeRefreshBackoff applies CLIProxyAPI's five-second to five-minute bounds.
// clampClaudeRefreshBackoff 应用 CLIProxyAPI 的五秒至五分钟边界。
func clampClaudeRefreshBackoff(delay time.Duration) time.Duration {
	if delay < claudeRefreshMinBackoff {
		return claudeRefreshMinBackoff
	}
	if delay > claudeRefreshMaxBackoff {
		return claudeRefreshMaxBackoff
	}
	return delay
}

// isClaudeRefreshRetryable preserves CLIProxyAPI's retry rule for network, decode, and 5xx failures.
// isClaudeRefreshRetryable 保留 CLIProxyAPI 对网络、解码与 5xx 失败的重试规则。
func isClaudeRefreshRetryable(err error) bool {
	var httpError *claudeRefreshHTTPError
	if errors.As(err, &httpError) {
		return httpError.Retryable()
	}
	return true
}

// waitForClaudeRefresh waits without ignoring cancellation or leaking a timer.
// waitForClaudeRefresh 在不忽略取消信号或泄漏计时器的前提下等待。
func waitForClaudeRefresh(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
