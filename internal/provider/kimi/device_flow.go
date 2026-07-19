// Package kimi implements Kimi Coding Plan device authorization without exposing tokens to management clients.
// Package kimi 实现 Kimi Coding Plan 设备授权且不向管理客户端暴露令牌。
package kimi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	providertransport "github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
)

const (
	// codingClientID is the proven Kimi Code OAuth client identifier.
	// codingClientID 是已验证的 Kimi Code OAuth 客户端标识。
	codingClientID = "17e5f671-d194-4dfb-9706-5516cb48c098"
	// deviceAuthorizationURL is the Kimi device authorization endpoint.
	// deviceAuthorizationURL 是 Kimi 设备授权端点。
	deviceAuthorizationURL = "https://auth.kimi.com/api/oauth/device_authorization"
	// tokenURL is the Kimi OAuth token endpoint.
	// tokenURL 是 Kimi OAuth 令牌端点。
	tokenURL = "https://auth.kimi.com/api/oauth/token"
	// defaultPollInterval prevents clients from polling faster than the provider-safe interval.
	// defaultPollInterval 防止客户端以高于供应商安全间隔的频率轮询。
	defaultPollInterval = 5 * time.Second
	// maximumFlowLifetime bounds every in-memory authorization session.
	// maximumFlowLifetime 限制每个内存授权会话的最长生命周期。
	maximumFlowLifetime = 15 * time.Minute
	// maximumFlowSessions bounds authenticated management requests that have not completed authorization.
	// maximumFlowSessions 限制尚未完成授权的管理请求数量。
	maximumFlowSessions = 64
	// maximumOAuthResponseBytes bounds each Kimi authentication response before JSON decoding.
	// maximumOAuthResponseBytes 在 JSON 解码前限制每个 Kimi 认证响应大小。
	maximumOAuthResponseBytes = 1 << 20
	// devicePlatform preserves CLIProxyAPI's provider-observed platform identity.
	// devicePlatform 保留 CLIProxyAPI 已被供应商验证的平台身份。
	devicePlatform = "CLIProxyAPI"
	// deviceVersion preserves CLIProxyAPI's local-build default version value.
	// deviceVersion 保留 CLIProxyAPI 本地构建的默认版本值。
	deviceVersion = "dev"
	// tokenDocumentPrefix distinguishes protected refreshable token documents from arbitrary Coding Plan API keys.
	// tokenDocumentPrefix 将受保护的可刷新令牌文档与任意 Coding Plan API Key 精确区分。
	tokenDocumentPrefix = "vulcan-kimi-token-v1:"
)

var (
	// ErrAuthorizationPending reports that the user has not completed verification yet.
	// ErrAuthorizationPending 表示用户尚未完成验证。
	ErrAuthorizationPending = errors.New("kimi authorization is pending")
	// ErrAuthorizationExpired reports that the provider or local session expired.
	// ErrAuthorizationExpired 表示供应商或本地会话已过期。
	ErrAuthorizationExpired = errors.New("kimi authorization expired")
	// ErrAuthorizationDenied reports an explicit user denial.
	// ErrAuthorizationDenied 表示用户明确拒绝授权。
	ErrAuthorizationDenied = errors.New("kimi authorization denied")
	// ErrFlowNotFound reports an unknown or already-consumed local session.
	// ErrFlowNotFound 表示未知或已消费的本地会话。
	ErrFlowNotFound = errors.New("kimi device flow not found")
	// ErrFlowLimitReached reports that the bounded local session capacity is exhausted.
	// ErrFlowLimitReached 表示有界本地会话容量已经耗尽。
	ErrFlowLimitReached = errors.New("kimi device flow limit reached")
)

// oauthTokenResponse mirrors CLIProxyAPI's shared device-exchange and refresh response shape.
// oauthTokenResponse 镜像 CLIProxyAPI 共用的设备交换与刷新响应形状。
type oauthTokenResponse struct {
	// Error is the provider OAuth error code.
	// Error 是供应商 OAuth 错误码。
	Error string `json:"error"`
	// ErrorDescription is the provider OAuth error detail retained only for typed decoding.
	// ErrorDescription 是仅为类型化解码保留的供应商 OAuth 错误详情。
	ErrorDescription string `json:"error_description"`
	// AccessToken authenticates Coding Plan requests.
	// AccessToken 用于认证 Coding Plan 请求。
	AccessToken string `json:"access_token"`
	// RefreshToken obtains replacement access tokens.
	// RefreshToken 用于获取替代 Access Token。
	RefreshToken string `json:"refresh_token"`
	// TokenType is the OAuth token type.
	// TokenType 是 OAuth Token 类型。
	TokenType string `json:"token_type"`
	// ExpiresIn is the provider lifetime in seconds and preserves CLIProxyAPI's floating-point field type.
	// ExpiresIn 是供应商返回的有效秒数，并保留 CLIProxyAPI 的浮点字段类型。
	ExpiresIn float64 `json:"expires_in"`
	// Scope is the granted OAuth scope string.
	// Scope 是已授予的 OAuth Scope 字符串。
	Scope string `json:"scope"`
}

// DeviceCode contains provider-issued verification data plus the local device identity.
// DeviceCode 包含供应商签发的验证数据及本地设备身份。
type DeviceCode struct {
	// DeviceCode is the provider secret retained only in local flow memory.
	// DeviceCode 是仅保留在本地流程内存中的供应商秘密。
	DeviceCode string `json:"device_code"`
	// UserCode is the short verification code shown to the administrator.
	// UserCode 是向管理员展示的短验证码。
	UserCode string `json:"user_code"`
	// VerificationURI is the provider verification page.
	// VerificationURI 是供应商验证页面。
	VerificationURI string `json:"verification_uri"`
	// VerificationURIComplete is the optional verification page with the code prefilled.
	// VerificationURIComplete 是可选的预填验证码验证页面。
	VerificationURIComplete string `json:"verification_uri_complete"`
	// ExpiresIn is the provider-reported device-code lifetime in seconds.
	// ExpiresIn 是供应商报告的设备码有效秒数。
	ExpiresIn int `json:"expires_in"`
	// Interval is the provider-reported minimum polling interval in seconds.
	// Interval 是供应商报告的最小轮询间隔秒数。
	Interval int `json:"interval"`
	// DeviceID is the local provider-visible identity retained outside JSON responses.
	// DeviceID 是不进入 JSON 响应的本地供应商可见设备身份。
	DeviceID string `json:"-"`
}

// Token contains the complete refreshable secret stored only behind the secret-store boundary.
// Token 包含仅存储在秘密存储边界后的完整可刷新秘密。
type Token struct {
	// AccessToken authenticates Kimi Coding Plan requests.
	// AccessToken 用于认证 Kimi Coding Plan 请求。
	AccessToken string `json:"access_token"`
	// RefreshToken obtains a replacement access token.
	// RefreshToken 用于获取替代 Access Token。
	RefreshToken string `json:"refresh_token"`
	// TokenType is the OAuth token type.
	// TokenType 是 OAuth Token 类型。
	TokenType string `json:"token_type"`
	// Scope is the provider-granted OAuth scope.
	// Scope 是供应商授予的 OAuth Scope。
	Scope string `json:"scope,omitempty"`
	// DeviceID preserves the exact identity required by refresh and execution requests.
	// DeviceID 保留刷新与执行请求所需的精确设备身份。
	DeviceID string `json:"device_id"`
	// ExpiresAt is the access-token Unix expiry when reported.
	// ExpiresAt 是供应商报告时的 Access Token Unix 过期时间。
	ExpiresAt int64 `json:"expires_at,omitempty"`
	// Type distinguishes the protected document from arbitrary API keys.
	// Type 将受保护文档与任意 API Key 区分。
	Type string `json:"type"`
}

// DeviceFlowClient performs one provider exchange at a time so the management layer owns polling cadence.
// DeviceFlowClient 每次只执行一次供应商交换，使管理层拥有轮询节奏。
type DeviceFlowClient struct {
	// httpClient owns bounded provider request execution.
	// httpClient 管理有界供应商请求执行。
	httpClient *http.Client
	// deviceURL is the production device endpoint or an explicit test endpoint.
	// deviceURL 是生产设备入口或显式测试入口。
	deviceURL string
	// tokenURL is the production token endpoint or an explicit test endpoint.
	// tokenURL 是生产 Token 入口或显式测试入口。
	tokenURL string
}

// NewDeviceFlowClient creates a production Kimi device-flow client with bounded network timeouts.
// NewDeviceFlowClient 创建具有有界网络超时的生产 Kimi 设备授权客户端。
func NewDeviceFlowClient(httpClient *http.Client) (*DeviceFlowClient, error) {
	if httpClient == nil {
		return nil, errors.New("Kimi device-flow HTTP client is required")
	}
	return &DeviceFlowClient{httpClient: providertransport.CloneHTTPClientWithoutRedirects(httpClient), deviceURL: deviceAuthorizationURL, tokenURL: tokenURL}, nil
}

// NewDeviceFlowClientWithEndpoints creates an isolated client for deterministic integration tests.
// NewDeviceFlowClientWithEndpoints 为确定性集成测试创建隔离客户端。
func NewDeviceFlowClientWithEndpoints(httpClient *http.Client, deviceURL string, exchangeURL string) (*DeviceFlowClient, error) {
	if httpClient == nil || strings.TrimSpace(deviceURL) == "" || strings.TrimSpace(exchangeURL) == "" {
		return nil, errors.New("Kimi device-flow HTTP client and endpoints are required")
	}
	return &DeviceFlowClient{httpClient: providertransport.CloneHTTPClientWithoutRedirects(httpClient), deviceURL: deviceURL, tokenURL: exchangeURL}, nil
}

// Start requests one provider device code using a newly generated device identity.
// Start 使用新生成的设备身份请求一个供应商设备码。
func (c *DeviceFlowClient) Start(ctx context.Context) (DeviceCode, error) {
	deviceID, errDeviceID := randomDeviceID()
	if errDeviceID != nil {
		return DeviceCode{}, errDeviceID
	}
	values := url.Values{"client_id": {codingClientID}}
	encodedValues := []byte(values.Encode())
	defer clear(encodedValues)
	request, errRequest := http.NewRequestWithContext(ctx, http.MethodPost, c.deviceURL, bytes.NewReader(encodedValues))
	if errRequest != nil {
		return DeviceCode{}, fmt.Errorf("create Kimi device-code request: %w", errRequest)
	}
	applyDeviceHeaders(request, deviceID)
	response, errResponse := c.httpClient.Do(request)
	if errResponse != nil {
		return DeviceCode{}, fmt.Errorf("request Kimi device code: %w", errResponse)
	}
	defer response.Body.Close()
	body, errBody := io.ReadAll(io.LimitReader(response.Body, maximumOAuthResponseBytes+1))
	if errBody != nil {
		return DeviceCode{}, fmt.Errorf("read Kimi device-code response: %w", errBody)
	}
	defer clear(body)
	if len(body) > maximumOAuthResponseBytes {
		return DeviceCode{}, errors.New("Kimi device-code response exceeds the allowed size")
	}
	if response.StatusCode != http.StatusOK {
		return DeviceCode{}, fmt.Errorf("Kimi device-code request returned status %d", response.StatusCode)
	}
	var code DeviceCode
	if errDecode := json.Unmarshal(body, &code); errDecode != nil {
		return DeviceCode{}, fmt.Errorf("decode Kimi device-code response: %w", errDecode)
	}
	if strings.TrimSpace(code.VerificationURI) == "" {
		code.VerificationURI = strings.TrimSpace(code.VerificationURIComplete)
	}
	if strings.TrimSpace(code.DeviceCode) == "" || strings.TrimSpace(code.UserCode) == "" || strings.TrimSpace(code.VerificationURI) == "" {
		return DeviceCode{}, errors.New("Kimi device-code response is incomplete")
	}
	// verificationURI is the normalized primary browser link safe to expose through management APIs.
	// verificationURI 是可安全通过管理 API 暴露的规范化主浏览器链接。
	verificationURI, errVerificationURI := providertransport.ValidateAbsoluteHTTPURL(code.VerificationURI)
	if errVerificationURI != nil {
		return DeviceCode{}, fmt.Errorf("validate Kimi verification URI: %w", errVerificationURI)
	}
	code.VerificationURI = verificationURI
	if strings.TrimSpace(code.VerificationURIComplete) != "" {
		// verificationURIComplete is the optional normalized prefilled browser link.
		// verificationURIComplete 是可选的规范化预填浏览器链接。
		verificationURIComplete, errVerificationURIComplete := providertransport.ValidateAbsoluteHTTPURL(code.VerificationURIComplete)
		if errVerificationURIComplete != nil {
			return DeviceCode{}, fmt.Errorf("validate Kimi complete verification URI: %w", errVerificationURIComplete)
		}
		code.VerificationURIComplete = verificationURIComplete
	}
	code.DeviceID = deviceID
	return code, nil
}

// Exchange performs one RFC 8628 device-code token exchange.
// Exchange 执行一次 RFC 8628 设备码令牌交换。
func (c *DeviceFlowClient) Exchange(ctx context.Context, code DeviceCode) (Token, error) {
	values := url.Values{"client_id": {codingClientID}, "device_code": {code.DeviceCode}, "grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}}
	encodedValues := []byte(values.Encode())
	defer clear(encodedValues)
	request, errRequest := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, bytes.NewReader(encodedValues))
	if errRequest != nil {
		return Token{}, fmt.Errorf("create Kimi token request: %w", errRequest)
	}
	applyDeviceHeaders(request, code.DeviceID)
	response, errResponse := c.httpClient.Do(request)
	if errResponse != nil {
		return Token{}, fmt.Errorf("request Kimi token: %w", errResponse)
	}
	defer response.Body.Close()
	body, errBody := io.ReadAll(io.LimitReader(response.Body, maximumOAuthResponseBytes+1))
	if errBody != nil {
		return Token{}, fmt.Errorf("read Kimi token response: %w", errBody)
	}
	defer clear(body)
	if len(body) > maximumOAuthResponseBytes {
		return Token{}, errors.New("Kimi token response exceeds the allowed size")
	}
	var payload oauthTokenResponse
	if errDecode := json.Unmarshal(body, &payload); errDecode != nil {
		return Token{}, fmt.Errorf("decode Kimi token response: %w", errDecode)
	}
	switch payload.Error {
	case "authorization_pending", "slow_down":
		return Token{}, ErrAuthorizationPending
	case "expired_token":
		return Token{}, ErrAuthorizationExpired
	case "access_denied":
		return Token{}, ErrAuthorizationDenied
	case "":
	default:
		return Token{}, fmt.Errorf("Kimi OAuth error %q", payload.Error)
	}
	if response.StatusCode != http.StatusOK || strings.TrimSpace(payload.AccessToken) == "" {
		return Token{}, fmt.Errorf("Kimi token request returned an invalid response")
	}
	expiresAt, errExpiry := kimiTokenExpiry(payload.ExpiresIn)
	if errExpiry != nil {
		return Token{}, errExpiry
	}
	return Token{AccessToken: payload.AccessToken, RefreshToken: payload.RefreshToken, TokenType: payload.TokenType, Scope: payload.Scope, DeviceID: code.DeviceID, ExpiresAt: expiresAt, Type: "kimi"}, nil
}

// Refresh exchanges one protected refresh token without exposing it outside the provider client.
// Refresh 在不向供应商客户端之外暴露令牌的情况下交换一个受保护 Refresh Token。
func (c *DeviceFlowClient) Refresh(ctx context.Context, token Token) (Token, error) {
	if errValidate := validateToken(token); errValidate != nil {
		return Token{}, fmt.Errorf("%w: %w", provider.ErrAuthenticationResponseInvalid, errValidate)
	}
	if strings.TrimSpace(token.RefreshToken) == "" {
		return Token{}, fmt.Errorf("%w: Kimi credential does not contain a refresh token", provider.ErrAuthenticationRejected)
	}
	values := url.Values{"client_id": {codingClientID}, "refresh_token": {token.RefreshToken}, "grant_type": {"refresh_token"}}
	encodedValues := []byte(values.Encode())
	defer clear(encodedValues)
	request, errRequest := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, bytes.NewReader(encodedValues))
	if errRequest != nil {
		return Token{}, fmt.Errorf("create Kimi refresh request: %w", errRequest)
	}
	applyDeviceHeaders(request, token.DeviceID)
	response, errResponse := c.httpClient.Do(request)
	if errResponse != nil {
		return Token{}, fmt.Errorf("%w: request Kimi token refresh: %w", provider.ErrAuthenticationUnavailable, errResponse)
	}
	defer response.Body.Close()
	body, errBody := io.ReadAll(io.LimitReader(response.Body, maximumOAuthResponseBytes+1))
	if errBody != nil {
		return Token{}, fmt.Errorf("%w: read Kimi refresh response: %w", provider.ErrAuthenticationUnavailable, errBody)
	}
	defer clear(body)
	if len(body) > maximumOAuthResponseBytes {
		return Token{}, fmt.Errorf("%w: Kimi refresh response exceeds the allowed size", provider.ErrAuthenticationResponseInvalid)
	}
	if response.StatusCode == http.StatusRequestTimeout || response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= http.StatusInternalServerError {
		return Token{}, fmt.Errorf("%w: Kimi token refresh returned status %d", provider.ErrAuthenticationUnavailable, response.StatusCode)
	}
	if response.StatusCode == http.StatusBadRequest || response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return Token{}, fmt.Errorf("%w: Kimi token refresh returned status %d", provider.ErrAuthenticationRejected, response.StatusCode)
	}
	if response.StatusCode != http.StatusOK {
		return Token{}, fmt.Errorf("%w: Kimi token refresh returned unexpected status %d", provider.ErrAuthenticationResponseInvalid, response.StatusCode)
	}
	var payload oauthTokenResponse
	if errDecode := json.Unmarshal(body, &payload); errDecode != nil {
		return Token{}, fmt.Errorf("%w: decode Kimi refresh response: %w", provider.ErrAuthenticationResponseInvalid, errDecode)
	}
	if payload.Error != "" {
		return Token{}, fmt.Errorf("%w: Kimi token refresh was rejected", provider.ErrAuthenticationRejected)
	}
	if strings.TrimSpace(payload.AccessToken) == "" {
		return Token{}, fmt.Errorf("%w: Kimi token refresh response omitted its access token", provider.ErrAuthenticationResponseInvalid)
	}
	if payload.RefreshToken == "" {
		payload.RefreshToken = token.RefreshToken
	}
	expiresAt, errExpiry := kimiTokenExpiry(payload.ExpiresIn)
	if errExpiry != nil {
		return Token{}, fmt.Errorf("%w: %w", provider.ErrAuthenticationResponseInvalid, errExpiry)
	}
	return Token{AccessToken: payload.AccessToken, RefreshToken: payload.RefreshToken, TokenType: payload.TokenType, Scope: payload.Scope, DeviceID: token.DeviceID, ExpiresAt: expiresAt, Type: "kimi"}, nil
}

// kimiTokenExpiry preserves CLIProxyAPI's fractional-second truncation while rejecting Unix overflow.
// kimiTokenExpiry 保留 CLIProxyAPI 的小数秒截断行为，同时拒绝 Unix 时间溢出。
func kimiTokenExpiry(expiresIn float64) (int64, error) {
	if expiresIn <= 0 {
		return 0, nil
	}
	now := time.Now().Unix()
	if expiresIn > float64(math.MaxInt64-now) {
		return 0, errors.New("Kimi token response expiry is invalid")
	}
	return now + int64(expiresIn), nil
}

// Flow describes one management-safe device authorization session.
// Flow 描述一个管理安全的设备授权会话。
type Flow struct {
	// ID is the server-owned opaque flow identifier.
	// ID 是服务端拥有的不透明流程标识。
	ID string `json:"id"`
	// UserCode is the provider-issued short verification code.
	// UserCode 是供应商签发的短验证码。
	UserCode string `json:"user_code"`
	// VerificationURI is the provider verification page.
	// VerificationURI 是供应商验证页面。
	VerificationURI string `json:"verification_uri"`
	// VerificationURIComplete is the provider-composed verification URL when available.
	// VerificationURIComplete 是供应商可用时组合的完整验证地址。
	VerificationURIComplete string `json:"verification_uri_complete"`
	// ExpiresAt bounds retention of provider device secrets.
	// ExpiresAt 限制供应商设备秘密的保留时间。
	ExpiresAt time.Time `json:"expires_at"`
	// PollIntervalSeconds is the enforced minimum polling interval.
	// PollIntervalSeconds 是强制执行的最小轮询秒数。
	PollIntervalSeconds int `json:"poll_interval_seconds"`
}

// flowSession owns the provider secret code and polling schedule for one local flow.
// flowSession 拥有一个本地授权流程的供应商秘密码和轮询计划。
type flowSession struct {
	// code retains the provider secret device code only in memory.
	// code 仅在内存中保留供应商秘密设备码。
	code DeviceCode
	// flow is the management-safe public projection.
	// flow 是管理安全的公共投影。
	flow Flow
	// nextPollAt enforces provider polling cadence locally.
	// nextPollAt 在本地强制供应商轮询节奏。
	nextPollAt time.Time
	// polling leases the provider exchange or completed result to one downstream onboarding request.
	// polling 将供应商交换或已完成结果租给一个下游录入请求。
	polling bool
	// token retains a completed provider result only until atomic onboarding succeeds or the session expires.
	// token 仅在原子录入成功或会话过期前保留已完成的供应商结果。
	token *Token
}

// FlowManager owns bounded in-memory device sessions and never persists incomplete authorization state.
// FlowManager 管理有界内存设备会话且绝不持久化未完成授权状态。
type FlowManager struct {
	// mu protects every in-memory authorization session.
	// mu 保护每个内存授权会话。
	mu sync.Mutex
	// client performs the exact provider device exchanges.
	// client 执行精确的供应商设备交换。
	client *DeviceFlowClient
	// now supplies deterministic flow timestamps in tests.
	// now 在测试中提供确定性的流程时间戳。
	now func() time.Time
	// sessions owns incomplete or not-yet-consumed flow state.
	// sessions 管理未完成或尚未消费的流程状态。
	sessions map[string]flowSession
}

// NewFlowManager creates an empty device-flow session manager.
// NewFlowManager 创建一个空设备授权会话管理器。
func NewFlowManager(client *DeviceFlowClient) (*FlowManager, error) {
	if client == nil {
		return nil, errors.New("Kimi device-flow client is required")
	}
	return &FlowManager{client: client, now: time.Now, sessions: make(map[string]flowSession)}, nil
}

// Start creates one provider code and retains only its secret portion in memory.
// Start 创建一个供应商设备码并仅在内存中保留其秘密部分。
func (m *FlowManager) Start(ctx context.Context) (Flow, error) {
	code, errCode := m.client.Start(ctx)
	if errCode != nil {
		return Flow{}, errCode
	}
	flowID, errID := randomIdentifier(16)
	if errID != nil {
		return Flow{}, errID
	}
	interval := kimiPollInterval(code.Interval)
	lifetime := kimiFlowLifetime(code.ExpiresIn)
	now := m.now().UTC()
	flow := Flow{ID: flowID, UserCode: code.UserCode, VerificationURI: code.VerificationURI, VerificationURIComplete: code.VerificationURIComplete, ExpiresAt: now.Add(lifetime), PollIntervalSeconds: int(interval / time.Second)}
	m.mu.Lock()
	m.pruneExpiredLocked(now)
	if len(m.sessions) >= maximumFlowSessions {
		m.mu.Unlock()
		return Flow{}, ErrFlowLimitReached
	}
	m.sessions[flowID] = flowSession{code: code, flow: flow, nextPollAt: now.Add(interval)}
	m.mu.Unlock()
	return flow, nil
}

// kimiFlowLifetime bounds provider seconds before duration conversion so oversized values cannot wrap into an expired session.
// kimiFlowLifetime 在转换为 Duration 前限制供应商秒数，避免超大值回绕成已过期会话。
func kimiFlowLifetime(expiresIn int) time.Duration {
	if expiresIn <= 0 || int64(expiresIn) >= int64(maximumFlowLifetime/time.Second) {
		return maximumFlowLifetime
	}
	return time.Duration(expiresIn) * time.Second
}

// kimiPollInterval preserves the provider minimum while bounding integer conversion to the local session lifetime.
// kimiPollInterval 保留供应商最小轮询间隔，同时将整数转换限制在本地会话生命周期内。
func kimiPollInterval(intervalSeconds int) time.Duration {
	if intervalSeconds <= int(defaultPollInterval/time.Second) {
		return defaultPollInterval
	}
	if int64(intervalSeconds) >= int64(maximumFlowLifetime/time.Second) {
		return maximumFlowLifetime
	}
	return time.Duration(intervalSeconds) * time.Second
}

// Poll performs at most one provider exchange and leases a successful result until explicit consumption or release.
// Poll 最多执行一次供应商交换，并租出成功结果直至显式消费或归还。
func (m *FlowManager) Poll(ctx context.Context, flowID string) (Token, error) {
	m.mu.Lock()
	session, exists := m.sessions[flowID]
	if !exists {
		m.mu.Unlock()
		return Token{}, ErrFlowNotFound
	}
	now := m.now().UTC()
	if !now.Before(session.flow.ExpiresAt) {
		delete(m.sessions, flowID)
		m.mu.Unlock()
		return Token{}, ErrAuthorizationExpired
	}
	if session.polling {
		m.mu.Unlock()
		return Token{}, ErrAuthorizationPending
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
		return Token{}, ErrAuthorizationPending
	}
	session.polling = true
	session.nextPollAt = now.Add(time.Duration(session.flow.PollIntervalSeconds) * time.Second)
	m.sessions[flowID] = session
	m.mu.Unlock()
	token, errExchange := m.client.Exchange(ctx, session.code)
	if errExchange != nil {
		if errors.Is(errExchange, ErrAuthorizationExpired) || errors.Is(errExchange, ErrAuthorizationDenied) {
			m.Cancel(flowID)
		} else {
			m.mu.Lock()
			current, stillExists := m.sessions[flowID]
			if stillExists && current.token == nil {
				current.polling = false
				m.sessions[flowID] = current
			}
			m.mu.Unlock()
		}
		return Token{}, errExchange
	}
	m.mu.Lock()
	current, stillExists := m.sessions[flowID]
	if !stillExists {
		m.mu.Unlock()
		return Token{}, ErrFlowNotFound
	}
	if !m.now().UTC().Before(current.flow.ExpiresAt) {
		delete(m.sessions, flowID)
		m.mu.Unlock()
		return Token{}, ErrAuthorizationExpired
	}
	current.token = &token
	m.sessions[flowID] = current
	m.mu.Unlock()
	return token, nil
}

// Release returns one delivered completed token to the session after downstream onboarding fails.
// Release 在下游录入失败后将一个已交付的完成 Token 归还会话。
func (m *FlowManager) Release(flowID string) {
	m.mu.Lock()
	session, exists := m.sessions[flowID]
	if exists && session.token != nil {
		session.polling = false
		m.sessions[flowID] = session
	}
	m.mu.Unlock()
}

// Cancel consumes one incomplete or completed local session and remains idempotent for cleanup paths.
// Cancel 消费一个未完成或已完成的本地会话，并保持幂等以支持清理路径。
func (m *FlowManager) Cancel(flowID string) {
	m.mu.Lock()
	delete(m.sessions, flowID)
	m.mu.Unlock()
}

// pruneExpiredLocked removes expired sessions while the caller owns m.mu.
// pruneExpiredLocked 在调用方持有 m.mu 时移除过期会话。
func (m *FlowManager) pruneExpiredLocked(now time.Time) {
	for flowID, session := range m.sessions {
		if !now.Before(session.flow.ExpiresAt) {
			delete(m.sessions, flowID)
		}
	}
}

// MarshalToken encodes one completed token for protected opaque storage.
// MarshalToken 编码一个已完成令牌以存入受保护不透明存储。
func MarshalToken(token Token) ([]byte, error) {
	if errValidate := validateToken(token); errValidate != nil {
		return nil, errValidate
	}
	payload, errMarshal := json.Marshal(token)
	if errMarshal != nil {
		return nil, errMarshal
	}
	return append([]byte(tokenDocumentPrefix), payload...), nil
}

// UnmarshalToken decodes one protected token document and permits provider-issued access-only credentials.
// UnmarshalToken 解码一个受保护令牌文档并允许供应商签发仅含 Access Token 的凭据。
func UnmarshalToken(value []byte) (Token, error) {
	if !bytes.HasPrefix(value, []byte(tokenDocumentPrefix)) {
		return Token{}, errors.New("protected Kimi token document has an unknown format")
	}
	var token Token
	if errDecode := json.Unmarshal(value[len(tokenDocumentPrefix):], &token); errDecode != nil {
		return Token{}, errors.New("protected Kimi token document is invalid")
	}
	if errValidate := validateToken(token); errValidate != nil {
		return Token{}, errValidate
	}
	return token, nil
}

// validateToken enforces the usable Kimi credential boundary while treating refresh support as optional.
// validateToken 强制执行可用 Kimi 凭据边界，同时将刷新能力视为可选项。
func validateToken(token Token) error {
	if strings.TrimSpace(token.AccessToken) == "" || strings.TrimSpace(token.DeviceID) == "" || token.Type != "kimi" {
		return errors.New("protected Kimi token document is incomplete")
	}
	return nil
}

// applyDeviceHeaders applies the stable provider-required device identity headers.
// applyDeviceHeaders 应用稳定的供应商必需设备身份请求头。
func applyDeviceHeaders(request *http.Request, deviceID string) {
	hostname, errHostname := os.Hostname()
	if errHostname != nil {
		hostname = "unknown"
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-Msh-Platform", devicePlatform)
	request.Header.Set("X-Msh-Version", deviceVersion)
	request.Header.Set("X-Msh-Device-Name", hostname)
	request.Header.Set("X-Msh-Device-Model", kimiDeviceModel())
	request.Header.Set("X-Msh-Device-Id", deviceID)
}

// kimiDeviceModel preserves CLIProxyAPI's provider-observed operating-system labels.
// kimiDeviceModel 保留 CLIProxyAPI 已被供应商验证的操作系统标签。
func kimiDeviceModel() string {
	switch runtime.GOOS {
	case "darwin":
		return "macOS " + runtime.GOARCH
	case "windows":
		return "Windows " + runtime.GOARCH
	case "linux":
		return "Linux " + runtime.GOARCH
	default:
		return runtime.GOOS + " " + runtime.GOARCH
	}
}

// randomDeviceID creates the RFC 4122 version-4 UUID shape used by CLIProxyAPI's proven Kimi flow.
// randomDeviceID 创建 CLIProxyAPI 已验证 Kimi 流程使用的 RFC 4122 第 4 版 UUID 形状。
func randomDeviceID() (string, error) {
	buffer := make([]byte, 16)
	if _, errRead := rand.Read(buffer); errRead != nil {
		return "", fmt.Errorf("generate Kimi device identifier: %w", errRead)
	}
	buffer[6] = (buffer[6] & 0x0f) | 0x40
	buffer[8] = (buffer[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(buffer)
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32], nil
}

// randomIdentifier generates an opaque lowercase identifier using operating-system entropy.
// randomIdentifier 使用操作系统熵生成一个不透明小写标识。
func randomIdentifier(size int) (string, error) {
	value := make([]byte, size)
	if _, errRead := rand.Read(value); errRead != nil {
		return "", fmt.Errorf("generate Kimi device-flow identifier: %w", errRead)
	}
	return hex.EncodeToString(value), nil
}
