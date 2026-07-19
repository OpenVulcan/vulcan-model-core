package openai

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	providertransport "github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
)

const (
	// codexOAuthClientID is the exact public Codex CLI client copied from CLIProxyAPI.
	// codexOAuthClientID 是从 CLIProxyAPI 精确复制的公开 Codex CLI 客户端。
	codexOAuthClientID = "app_EMoamEEZ73f0CkXaXp7hrann"
	// codexDeviceUserCodeURL creates Codex device sessions.
	// codexDeviceUserCodeURL 创建 Codex 设备会话。
	codexDeviceUserCodeURL = "https://auth.openai.com/api/accounts/deviceauth/usercode"
	// codexDeviceTokenURL polls Codex device sessions.
	// codexDeviceTokenURL 轮询 Codex 设备会话。
	codexDeviceTokenURL = "https://auth.openai.com/api/accounts/deviceauth/token"
	// codexDeviceVerificationURL is the exact user authorization page.
	// codexDeviceVerificationURL 是精确的用户授权页面。
	codexDeviceVerificationURL = "https://auth.openai.com/codex/device"
	// codexTokenURL exchanges and refreshes OAuth tokens.
	// codexTokenURL 交换并刷新 OAuth Token。
	codexTokenURL = "https://auth.openai.com/oauth/token"
	// codexDeviceRedirectURI is registered for the OpenAI device exchange.
	// codexDeviceRedirectURI 是为 OpenAI 设备交换注册的重定向地址。
	codexDeviceRedirectURI = "https://auth.openai.com/deviceauth/callback"
	// codexDeviceLifetime matches CLIProxyAPI's fifteen-minute timeout.
	// codexDeviceLifetime 与 CLIProxyAPI 的十五分钟超时保持一致。
	codexDeviceLifetime = 15 * time.Minute
	// codexDefaultPollInterval is used when OpenAI omits or corrupts the interval.
	// codexDefaultPollInterval 在 OpenAI 缺失或损坏轮询间隔时使用。
	codexDefaultPollInterval = 5 * time.Second
	// maximumCodexFlowSessions bounds incomplete management authorization state.
	// maximumCodexFlowSessions 限制未完成管理授权状态数量。
	maximumCodexFlowSessions = 64
	// maximumCodexDeviceResponseBytes bounds every device and token response.
	// maximumCodexDeviceResponseBytes 限制每个设备与 Token 响应大小。
	maximumCodexDeviceResponseBytes = 1 << 20
	// codexRefreshAttempts matches CLIProxyAPI's executor refresh retry count.
	// codexRefreshAttempts 与 CLIProxyAPI 执行器的刷新重试次数一致。
	codexRefreshAttempts = 3
)

var (
	// ErrCodexAuthorizationPending reports an incomplete OpenAI authorization.
	// ErrCodexAuthorizationPending 表示 OpenAI 授权尚未完成。
	ErrCodexAuthorizationPending = errors.New("Codex authorization is pending")
	// ErrCodexFlowNotFound reports an unknown local Codex flow.
	// ErrCodexFlowNotFound 表示本地 Codex 授权流程不存在。
	ErrCodexFlowNotFound = errors.New("Codex device flow not found")
	// ErrCodexFlowLimitReached reports excessive incomplete Codex flows.
	// ErrCodexFlowLimitReached 表示未完成 Codex 授权流程过多。
	ErrCodexFlowLimitReached = errors.New("Codex device flow limit reached")
)

// CodexDeviceFlow contains public verification data while secrets remain in process memory.
// CodexDeviceFlow 包含公共验证数据，同时秘密仅保留在进程内存中。
type CodexDeviceFlow struct {
	// ID is the local opaque flow identifier.
	// ID 是本地不透明流程标识。
	ID string `json:"id"`
	// UserCode is the short OpenAI verification code.
	// UserCode 是 OpenAI 短验证代码。
	UserCode string `json:"user_code"`
	// VerificationURI is the OpenAI Codex device page.
	// VerificationURI 是 OpenAI Codex 设备页面。
	VerificationURI string `json:"verification_uri"`
	// ExpiresAt is the bounded local expiry.
	// ExpiresAt 是有界的本地过期时间。
	ExpiresAt time.Time `json:"expires_at"`
	// PollIntervalSeconds is the minimum OpenAI polling delay in seconds.
	// PollIntervalSeconds 是以秒为单位的 OpenAI 最小轮询间隔。
	PollIntervalSeconds int `json:"poll_interval_seconds"`
}

// codexDeviceSession contains the provider-owned secret identifiers.
// codexDeviceSession 包含供应商拥有的秘密标识。
type codexDeviceSession struct {
	// deviceAuthID identifies the provider session.
	// deviceAuthID 标识供应商会话。
	deviceAuthID string
	// userCode is required by the provider poll request.
	// userCode 是供应商轮询请求所需的用户码。
	userCode string
	// flow is the management-safe projection.
	// flow 是管理安全投影。
	flow CodexDeviceFlow
	// nextPollAt enforces the provider interval locally.
	// nextPollAt 在本地强制供应商轮询间隔。
	nextPollAt time.Time
	// polling leases the provider exchange or completed result to one downstream onboarding request.
	// polling 将供应商交换或已完成结果租给一个下游录入请求。
	polling bool
	// token retains a completed provider result until atomic onboarding succeeds or the session expires.
	// token 在原子录入成功或会话过期前保留已完成的供应商结果。
	token *CodexToken
}

// CodexDeviceFlowClient performs the exact CLIProxyAPI Codex device and token exchanges.
// CodexDeviceFlowClient 执行精确的 CLIProxyAPI Codex 设备与 Token 交换。
type CodexDeviceFlowClient struct {
	// httpClient performs bounded provider requests.
	// httpClient 执行有界供应商请求。
	httpClient *http.Client
	// userCodeURL is the production endpoint or an explicit test endpoint.
	// userCodeURL 是生产入口或显式测试入口。
	userCodeURL string
	// deviceTokenURL is the production polling endpoint or an explicit test endpoint.
	// deviceTokenURL 是生产轮询入口或显式测试入口。
	deviceTokenURL string
	// tokenURL is the production OAuth token endpoint or an explicit test endpoint.
	// tokenURL 是生产 OAuth Token 入口或显式测试入口。
	tokenURL string
	// now returns the authoritative timestamp used to materialize OAuth expires_in values.
	// now 返回用于具体化 OAuth expires_in 值的权威时间戳。
	now func() time.Time
	// retryDelay returns CLIProxyAPI's attempt-indexed refresh backoff.
	// retryDelay 返回 CLIProxyAPI 按尝试序号计算的刷新退避时长。
	retryDelay func(int) time.Duration
}

// codexOAuthErrorResponse contains the exact stable error fields used by CLIProxyAPI's non-retryable refresh rule.
// codexOAuthErrorResponse 包含 CLIProxyAPI 不可重试刷新规则使用的精确稳定错误字段。
type codexOAuthErrorResponse struct {
	// Error is the OAuth error category.
	// Error 是 OAuth 错误类别。
	Error string `json:"error"`
	// Code is the provider-specific error code.
	// Code 是供应商专属错误码。
	Code string `json:"code"`
}

// NewCodexDeviceFlowClient creates a production Codex device-flow client.
// NewCodexDeviceFlowClient 创建生产 Codex 设备授权客户端。
func NewCodexDeviceFlowClient(httpClient *http.Client) (*CodexDeviceFlowClient, error) {
	return NewCodexDeviceFlowClientWithEndpoints(httpClient, codexDeviceUserCodeURL, codexDeviceTokenURL, codexTokenURL)
}

// NewCodexDeviceFlowClientWithEndpoints creates an isolated client for deterministic tests.
// NewCodexDeviceFlowClientWithEndpoints 为确定性测试创建隔离客户端。
func NewCodexDeviceFlowClientWithEndpoints(httpClient *http.Client, userCodeURL string, deviceTokenURL string, tokenURL string) (*CodexDeviceFlowClient, error) {
	if httpClient == nil || strings.TrimSpace(userCodeURL) == "" || strings.TrimSpace(deviceTokenURL) == "" || strings.TrimSpace(tokenURL) == "" {
		return nil, errors.New("Codex device-flow HTTP client and endpoints are required")
	}
	return &CodexDeviceFlowClient{
		httpClient: providertransport.CloneHTTPClientWithoutRedirects(httpClient), userCodeURL: userCodeURL, deviceTokenURL: deviceTokenURL, tokenURL: tokenURL, now: time.Now,
		retryDelay: func(attempt int) time.Duration { return time.Duration(attempt) * time.Second },
	}, nil
}

// Start requests one Codex user code using the copied public client identifier.
// Start 使用复制的公开客户端标识请求一个 Codex 用户码。
func (c *CodexDeviceFlowClient) Start(ctx context.Context) (codexDeviceSession, error) {
	body, errBody := json.Marshal(struct {
		// ClientID is the public Codex CLI OAuth client.
		// ClientID 是公开 Codex CLI OAuth 客户端。
		ClientID string `json:"client_id"`
	}{ClientID: codexOAuthClientID})
	if errBody != nil {
		return codexDeviceSession{}, fmt.Errorf("encode Codex device request: %w", errBody)
	}
	defer clear(body)
	request, errRequest := http.NewRequestWithContext(ctx, http.MethodPost, c.userCodeURL, bytes.NewReader(body))
	if errRequest != nil {
		return codexDeviceSession{}, fmt.Errorf("create Codex device request: %w", errRequest)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	responseBody, statusCode, errDo := c.do(request)
	if errDo != nil {
		return codexDeviceSession{}, errDo
	}
	defer clear(responseBody)
	if statusCode < http.StatusOK || statusCode >= http.StatusMultipleChoices {
		return codexDeviceSession{}, fmt.Errorf("Codex device code request returned status %d", statusCode)
	}
	var payload struct {
		// DeviceAuthID identifies the secret provider session.
		// DeviceAuthID 标识秘密供应商会话。
		DeviceAuthID string `json:"device_auth_id"`
		// UserCode is the canonical response field.
		// UserCode 是规范响应字段。
		UserCode string `json:"user_code"`
		// UserCodeAlt is CLIProxyAPI's observed alternate field.
		// UserCodeAlt 是 CLIProxyAPI 观察到的备用字段。
		UserCodeAlt string `json:"usercode"`
		// Interval accepts provider string or number forms.
		// Interval 接受供应商字符串或数字形式。
		Interval json.RawMessage `json:"interval"`
	}
	if errDecode := json.Unmarshal(responseBody, &payload); errDecode != nil {
		return codexDeviceSession{}, fmt.Errorf("decode Codex device response: %w", errDecode)
	}
	userCode := strings.TrimSpace(payload.UserCode)
	if userCode == "" {
		userCode = strings.TrimSpace(payload.UserCodeAlt)
	}
	if strings.TrimSpace(payload.DeviceAuthID) == "" || userCode == "" {
		return codexDeviceSession{}, errors.New("Codex device flow did not return required fields")
	}
	now := time.Now().UTC()
	interval := parseCodexPollInterval(payload.Interval)
	flow := CodexDeviceFlow{UserCode: userCode, VerificationURI: codexDeviceVerificationURL, ExpiresAt: now.Add(codexDeviceLifetime), PollIntervalSeconds: int(interval / time.Second)}
	return codexDeviceSession{deviceAuthID: strings.TrimSpace(payload.DeviceAuthID), userCode: userCode, flow: flow, nextPollAt: now}, nil
}

// Exchange performs one non-blocking device poll and exchanges a completed authorization code.
// Exchange 执行一次非阻塞设备轮询并交换已完成的授权码。
func (c *CodexDeviceFlowClient) Exchange(ctx context.Context, session codexDeviceSession) (CodexToken, error) {
	body, errBody := json.Marshal(struct {
		// DeviceAuthID identifies the provider session.
		// DeviceAuthID 标识供应商会话。
		DeviceAuthID string `json:"device_auth_id"`
		// UserCode confirms the displayed code.
		// UserCode 确认已显示的用户码。
		UserCode string `json:"user_code"`
	}{DeviceAuthID: session.deviceAuthID, UserCode: session.userCode})
	if errBody != nil {
		return CodexToken{}, fmt.Errorf("encode Codex device poll: %w", errBody)
	}
	defer clear(body)
	request, errRequest := http.NewRequestWithContext(ctx, http.MethodPost, c.deviceTokenURL, bytes.NewReader(body))
	if errRequest != nil {
		return CodexToken{}, fmt.Errorf("create Codex device poll: %w", errRequest)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	responseBody, statusCode, errDo := c.do(request)
	if errDo != nil {
		return CodexToken{}, errDo
	}
	defer clear(responseBody)
	if statusCode == http.StatusForbidden || statusCode == http.StatusNotFound {
		return CodexToken{}, ErrCodexAuthorizationPending
	}
	if statusCode < http.StatusOK || statusCode >= http.StatusMultipleChoices {
		return CodexToken{}, fmt.Errorf("Codex device poll returned status %d", statusCode)
	}
	var payload struct {
		// AuthorizationCode is exchanged at the OAuth token endpoint.
		// AuthorizationCode 在 OAuth Token 入口交换。
		AuthorizationCode string `json:"authorization_code"`
		// CodeVerifier completes PKCE verification.
		// CodeVerifier 完成 PKCE 校验。
		CodeVerifier string `json:"code_verifier"`
		// CodeChallenge must be present because CLIProxyAPI rejects incomplete responses.
		// CodeChallenge 必须存在，因为 CLIProxyAPI 拒绝不完整响应。
		CodeChallenge string `json:"code_challenge"`
	}
	if errDecode := json.Unmarshal(responseBody, &payload); errDecode != nil {
		return CodexToken{}, fmt.Errorf("decode Codex device poll: %w", errDecode)
	}
	if strings.TrimSpace(payload.AuthorizationCode) == "" || strings.TrimSpace(payload.CodeVerifier) == "" || strings.TrimSpace(payload.CodeChallenge) == "" {
		return CodexToken{}, errors.New("Codex device token response is incomplete")
	}
	return c.exchangeAuthorizationCode(ctx, payload.AuthorizationCode, payload.CodeVerifier)
}

// Refresh exchanges one protected Codex refresh token.
// Refresh 交换一个受保护 Codex Refresh Token。
func (c *CodexDeviceFlowClient) Refresh(ctx context.Context, token CodexToken) (CodexToken, error) {
	if errValidate := validateCodexToken(token); errValidate != nil {
		return CodexToken{}, fmt.Errorf("%w: %w", provider.ErrAuthenticationResponseInvalid, errValidate)
	}
	if strings.TrimSpace(token.RefreshToken) == "" {
		return CodexToken{}, fmt.Errorf("%w: Codex credential does not contain a refresh token", provider.ErrAuthenticationRejected)
	}
	form := url.Values{"client_id": {codexOAuthClientID}, "grant_type": {"refresh_token"}, "refresh_token": {token.RefreshToken}, "scope": {"openid profile email"}}
	refreshed, errRefresh := c.refreshOAuthTokenWithRetry(ctx, form)
	if errRefresh != nil {
		return CodexToken{}, errRefresh
	}
	if refreshed.RefreshToken == "" {
		refreshed.RefreshToken = token.RefreshToken
	}
	if refreshed.IDToken == "" {
		refreshed.IDToken = token.IDToken
		refreshed.AccountID = token.AccountID
		refreshed.Email = token.Email
	}
	if errValidate := validateCodexToken(refreshed); errValidate != nil {
		return CodexToken{}, fmt.Errorf("%w: %w", provider.ErrAuthenticationResponseInvalid, errValidate)
	}
	return refreshed, nil
}

// refreshOAuthTokenWithRetry copies CLIProxyAPI's three-attempt refresh policy and refresh-token reuse stop condition.
// refreshOAuthTokenWithRetry 复制 CLIProxyAPI 的三次刷新策略与 Refresh Token 重用立即停止条件。
func (c *CodexDeviceFlowClient) refreshOAuthTokenWithRetry(ctx context.Context, form url.Values) (CodexToken, error) {
	var lastError error
	for attempt := 0; attempt < codexRefreshAttempts; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(c.retryDelay(attempt))
			select {
			case <-ctx.Done():
				timer.Stop()
				return CodexToken{}, ctx.Err()
			case <-timer.C:
			}
		}
		refreshed, errRefresh := c.requestOAuthToken(ctx, form)
		if errRefresh == nil {
			return refreshed, nil
		}
		if isNonRetryableCodexRefreshError(errRefresh) {
			return CodexToken{}, errRefresh
		}
		lastError = errRefresh
	}
	return CodexToken{}, fmt.Errorf("Codex token refresh failed after %d attempts: %w", codexRefreshAttempts, lastError)
}

// isNonRetryableCodexRefreshError identifies CLIProxyAPI's exact refresh-token reuse terminal code.
// isNonRetryableCodexRefreshError 识别 CLIProxyAPI 使用的精确 Refresh Token 重用终止错误码。
func isNonRetryableCodexRefreshError(errRefresh error) bool {
	return errRefresh != nil && strings.Contains(strings.ToLower(errRefresh.Error()), "refresh_token_reused")
}

// exchangeAuthorizationCode completes the copied device callback exchange.
// exchangeAuthorizationCode 完成复制的设备回调交换。
func (c *CodexDeviceFlowClient) exchangeAuthorizationCode(ctx context.Context, code string, verifier string) (CodexToken, error) {
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {codexOAuthClientID}, "code": {strings.TrimSpace(code)}, "redirect_uri": {codexDeviceRedirectURI}, "code_verifier": {strings.TrimSpace(verifier)}}
	token, errToken := c.requestOAuthToken(ctx, form)
	if errToken != nil {
		return CodexToken{}, errToken
	}
	if errValidate := validateCodexToken(token); errValidate != nil {
		return CodexToken{}, errValidate
	}
	return token, nil
}

// requestOAuthToken submits one exact Codex OAuth form and builds the protected document.
// requestOAuthToken 提交一个精确 Codex OAuth 表单并构建受保护文档。
func (c *CodexDeviceFlowClient) requestOAuthToken(ctx context.Context, form url.Values) (CodexToken, error) {
	// refreshRequest isolates refresh-specific error classification from browser and device authorization exchanges.
	// refreshRequest 将刷新专属错误分类与浏览器及设备授权交换隔离。
	refreshRequest := form.Get("grant_type") == "refresh_token"
	encodedForm := []byte(form.Encode())
	defer clear(encodedForm)
	request, errRequest := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, bytes.NewReader(encodedForm))
	if errRequest != nil {
		return CodexToken{}, fmt.Errorf("create Codex token request: %w", errRequest)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	responseBody, statusCode, errDo := c.do(request)
	if errDo != nil {
		return CodexToken{}, errDo
	}
	defer clear(responseBody)
	if statusCode != http.StatusOK {
		detail := codexOAuthErrorDetail(responseBody)
		if refreshRequest {
			switch {
			case statusCode == http.StatusRequestTimeout || statusCode == http.StatusTooManyRequests || statusCode >= http.StatusInternalServerError:
				return CodexToken{}, codexRefreshStatusError(provider.ErrAuthenticationUnavailable, statusCode, detail)
			case statusCode == http.StatusBadRequest || statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden:
				return CodexToken{}, codexRefreshStatusError(provider.ErrAuthenticationRejected, statusCode, detail)
			default:
				return CodexToken{}, fmt.Errorf("%w: Codex token refresh returned unexpected status %d", provider.ErrAuthenticationResponseInvalid, statusCode)
			}
		}
		if detail != "" {
			return CodexToken{}, fmt.Errorf("Codex token request returned status %d: %s", statusCode, detail)
		}
		return CodexToken{}, fmt.Errorf("Codex token request returned status %d", statusCode)
	}
	var payload struct {
		// IDToken contains identity and plan claims.
		// IDToken 包含身份与套餐声明。
		IDToken string `json:"id_token"`
		// AccessToken authenticates execution.
		// AccessToken 用于认证执行。
		AccessToken string `json:"access_token"`
		// RefreshToken refreshes provider access.
		// RefreshToken 用于刷新供应商访问权。
		RefreshToken string `json:"refresh_token"`
		// ExpiresIn is the provider-reported access-token lifetime in seconds.
		// ExpiresIn 是供应商报告的 Access Token 有效秒数。
		ExpiresIn int `json:"expires_in"`
	}
	if errDecode := json.Unmarshal(responseBody, &payload); errDecode != nil {
		if refreshRequest {
			return CodexToken{}, fmt.Errorf("%w: decode Codex token response: %w", provider.ErrAuthenticationResponseInvalid, errDecode)
		}
		return CodexToken{}, fmt.Errorf("decode Codex token response: %w", errDecode)
	}
	if payload.ExpiresIn <= 0 || int64(payload.ExpiresIn) > int64(time.Duration(1<<63-1)/time.Second) {
		if refreshRequest {
			return CodexToken{}, fmt.Errorf("%w: Codex token response omitted a positive expires_in value", provider.ErrAuthenticationResponseInvalid)
		}
		return CodexToken{}, errors.New("Codex token response omitted a positive expires_in value")
	}
	// claims stays empty only for refresh responses that legitimately omit a replacement ID token.
	// claims 仅在刷新响应合法省略替代 ID Token 时保持为空。
	var claims codexJWTClaims
	if strings.TrimSpace(payload.IDToken) != "" {
		parsedClaims, errClaims := parseCodexJWT(payload.IDToken)
		if errClaims != nil {
			if refreshRequest {
				return CodexToken{}, fmt.Errorf("%w: %w", provider.ErrAuthenticationResponseInvalid, errClaims)
			}
			return CodexToken{}, errClaims
		}
		claims = parsedClaims
	}
	token := CodexToken{IDToken: payload.IDToken, AccessToken: payload.AccessToken, RefreshToken: payload.RefreshToken, AccountID: claims.Auth.AccountID, Email: claims.Email, ExpiresAt: c.now().UTC().Add(time.Duration(payload.ExpiresIn) * time.Second), Type: "codex"}
	if strings.TrimSpace(token.AccessToken) == "" {
		if refreshRequest {
			return CodexToken{}, fmt.Errorf("%w: Codex token response is incomplete", provider.ErrAuthenticationResponseInvalid)
		}
		return CodexToken{}, errors.New("Codex token response is incomplete")
	}
	return token, nil
}

// codexRefreshStatusError builds a stable refresh error without appending an empty provider detail suffix.
// codexRefreshStatusError 构建稳定刷新错误，且不会追加空的供应商详情后缀。
func codexRefreshStatusError(category error, statusCode int, detail string) error {
	if detail != "" {
		return fmt.Errorf("%w: Codex token refresh returned status %d: %s", category, statusCode, detail)
	}
	return fmt.Errorf("%w: Codex token refresh returned status %d", category, statusCode)
}

// codexOAuthErrorDetail projects only stable OAuth error fields so provider bodies cannot leak through errors or logs.
// codexOAuthErrorDetail 仅投影稳定 OAuth 错误字段，避免供应商响应体经错误或日志泄漏。
func codexOAuthErrorDetail(body []byte) string {
	var response codexOAuthErrorResponse
	if json.Unmarshal(body, &response) != nil {
		return ""
	}
	code := strings.TrimSpace(response.Code)
	category := strings.TrimSpace(response.Error)
	if code != "" && category != "" {
		return category + ": " + code
	}
	if code != "" {
		return code
	}
	return category
}

// do executes one bounded Codex auth request and returns its status and body.
// do 执行一个有界 Codex 认证请求并返回状态与响应体。
func (c *CodexDeviceFlowClient) do(request *http.Request) ([]byte, int, error) {
	response, errResponse := c.httpClient.Do(request)
	if errResponse != nil {
		return nil, 0, fmt.Errorf("%w: request Codex auth endpoint: %w", provider.ErrAuthenticationUnavailable, errResponse)
	}
	defer response.Body.Close()
	body, errBody := io.ReadAll(io.LimitReader(response.Body, maximumCodexDeviceResponseBytes+1))
	if errBody != nil {
		return nil, 0, fmt.Errorf("%w: read Codex auth response: %w", provider.ErrAuthenticationUnavailable, errBody)
	}
	if len(body) > maximumCodexDeviceResponseBytes {
		clear(body)
		return nil, 0, fmt.Errorf("%w: Codex auth response exceeds the response limit", provider.ErrAuthenticationResponseInvalid)
	}
	return body, response.StatusCode, nil
}

// parseCodexPollInterval preserves CLIProxyAPI's string, integer, and default behavior.
// parseCodexPollInterval 保留 CLIProxyAPI 的字符串、整数与默认行为。
func parseCodexPollInterval(raw json.RawMessage) time.Duration {
	var asString string
	if len(raw) > 0 && json.Unmarshal(raw, &asString) == nil {
		if seconds, errSeconds := strconv.ParseInt(strings.TrimSpace(asString), 10, 64); errSeconds == nil {
			return boundedCodexPollInterval(seconds)
		}
	}
	var asInteger int64
	if len(raw) > 0 && json.Unmarshal(raw, &asInteger) == nil {
		return boundedCodexPollInterval(asInteger)
	}
	return codexDefaultPollInterval
}

// boundedCodexPollInterval preserves positive provider intervals without allowing duration conversion to wrap past the local flow lifetime.
// boundedCodexPollInterval 保留供应商正轮询间隔，同时防止 Duration 转换回绕并超过本地流程生命周期。
func boundedCodexPollInterval(seconds int64) time.Duration {
	if seconds <= 0 {
		return codexDefaultPollInterval
	}
	if seconds >= int64(codexDeviceLifetime/time.Second) {
		return codexDeviceLifetime
	}
	return time.Duration(seconds) * time.Second
}

// CodexFlowManager owns bounded in-memory Codex device sessions.
// CodexFlowManager 管理有界的内存 Codex 设备授权会话。
type CodexFlowManager struct {
	// client performs provider exchanges.
	// client 执行供应商交换。
	client *CodexDeviceFlowClient
	// now provides deterministic expiry and polling checks.
	// now 提供可确定的过期与轮询检查。
	now func() time.Time
	// mu protects sessions.
	// mu 保护会话。
	mu sync.Mutex
	// sessions stores incomplete flows by local ID.
	// sessions 按本地 ID 存储未完成流程。
	sessions map[string]codexDeviceSession
}

// NewCodexFlowManager creates an empty Codex flow manager.
// NewCodexFlowManager 创建空 Codex 授权流程管理器。
func NewCodexFlowManager(client *CodexDeviceFlowClient) (*CodexFlowManager, error) {
	if client == nil {
		return nil, errors.New("Codex device-flow client is required")
	}
	return &CodexFlowManager{client: client, now: time.Now, sessions: make(map[string]codexDeviceSession)}, nil
}

// Start creates one provider flow and retains its secrets only in memory.
// Start 创建一个供应商流程并仅在内存保留其秘密。
func (m *CodexFlowManager) Start(ctx context.Context) (CodexDeviceFlow, error) {
	session, errStart := m.client.Start(ctx)
	if errStart != nil {
		return CodexDeviceFlow{}, errStart
	}
	flowID, errID := randomCodexIdentifier(16)
	if errID != nil {
		return CodexDeviceFlow{}, errID
	}
	now := m.now().UTC()
	session.flow.ID = flowID
	session.flow.ExpiresAt = now.Add(codexDeviceLifetime)
	session.nextPollAt = now
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneExpiredLocked(now)
	if len(m.sessions) >= maximumCodexFlowSessions {
		return CodexDeviceFlow{}, ErrCodexFlowLimitReached
	}
	m.sessions[flowID] = session
	return session.flow, nil
}

// Poll performs at most one provider request and retains successful results until explicit consumption.
// Poll 最多执行一次供应商请求，并在显式消费前保留成功结果。
func (m *CodexFlowManager) Poll(ctx context.Context, flowID string) (CodexToken, error) {
	now := m.now().UTC()
	m.mu.Lock()
	m.pruneExpiredLocked(now)
	session, exists := m.sessions[flowID]
	if !exists {
		m.mu.Unlock()
		return CodexToken{}, ErrCodexFlowNotFound
	}
	if session.polling {
		m.mu.Unlock()
		return CodexToken{}, ErrCodexAuthorizationPending
	}
	if session.token != nil {
		token := *session.token
		session.polling = true
		m.sessions[flowID] = session
		m.mu.Unlock()
		return token, nil
	}
	if now.Before(session.nextPollAt) {
		m.mu.Unlock()
		return CodexToken{}, ErrCodexAuthorizationPending
	}
	session.polling = true
	session.nextPollAt = now.Add(time.Duration(session.flow.PollIntervalSeconds) * time.Second)
	m.sessions[flowID] = session
	m.mu.Unlock()
	token, errToken := m.client.Exchange(ctx, session)
	if errToken != nil {
		m.mu.Lock()
		current, stillExists := m.sessions[flowID]
		if stillExists && current.token == nil {
			current.polling = false
			m.sessions[flowID] = current
		}
		m.mu.Unlock()
		return CodexToken{}, errToken
	}
	m.mu.Lock()
	current, stillExists := m.sessions[flowID]
	if !stillExists {
		m.mu.Unlock()
		return CodexToken{}, ErrCodexFlowNotFound
	}
	if !m.now().UTC().Before(current.flow.ExpiresAt) {
		delete(m.sessions, flowID)
		m.mu.Unlock()
		return CodexToken{}, ErrCodexFlowNotFound
	}
	current.token = &token
	m.sessions[flowID] = current
	m.mu.Unlock()
	return token, nil
}

// Release returns one delivered completed token to the session after downstream onboarding fails.
// Release 在下游录入失败后将一个已交付的完成 Token 归还会话。
func (m *CodexFlowManager) Release(flowID string) {
	m.mu.Lock()
	session, exists := m.sessions[flowID]
	if exists && session.token != nil {
		session.polling = false
		m.sessions[flowID] = session
	}
	m.mu.Unlock()
}

// Cancel consumes one incomplete or completed local Codex authorization session.
// Cancel 消费一个未完成或已完成的本地 Codex 授权会话。
func (m *CodexFlowManager) Cancel(flowID string) {
	m.mu.Lock()
	delete(m.sessions, flowID)
	m.mu.Unlock()
}

// pruneExpiredLocked removes expired sessions while the caller owns the lock.
// pruneExpiredLocked 在调用方持锁时删除已过期会话。
func (m *CodexFlowManager) pruneExpiredLocked(now time.Time) {
	for flowID, session := range m.sessions {
		if !session.flow.ExpiresAt.After(now) {
			delete(m.sessions, flowID)
		}
	}
}

// randomCodexIdentifier generates an opaque identifier using operating-system entropy.
// randomCodexIdentifier 使用操作系统熵生成不透明标识。
func randomCodexIdentifier(size int) (string, error) {
	buffer := make([]byte, size)
	if _, errRead := rand.Read(buffer); errRead != nil {
		return "", fmt.Errorf("generate Codex flow identifier: %w", errRead)
	}
	return hex.EncodeToString(buffer), nil
}
