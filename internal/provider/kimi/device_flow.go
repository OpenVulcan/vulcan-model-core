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
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
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

// DeviceCode contains provider-issued verification data plus the local device identity.
// DeviceCode 包含供应商签发的验证数据及本地设备身份。
type DeviceCode struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
	DeviceID                string `json:"-"`
}

// Token contains the complete refreshable secret stored only behind the secret-store boundary.
// Token 包含仅存储在秘密存储边界后的完整可刷新秘密。
type Token struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope,omitempty"`
	DeviceID     string `json:"device_id"`
	ExpiresAt    int64  `json:"expires_at,omitempty"`
	Type         string `json:"type"`
}

// DeviceFlowClient performs one provider exchange at a time so the management layer owns polling cadence.
// DeviceFlowClient 每次只执行一次供应商交换，使管理层拥有轮询节奏。
type DeviceFlowClient struct {
	httpClient *http.Client
	deviceURL  string
	tokenURL   string
}

// NewDeviceFlowClient creates a production Kimi device-flow client with bounded network timeouts.
// NewDeviceFlowClient 创建具有有界网络超时的生产 Kimi 设备授权客户端。
func NewDeviceFlowClient(httpClient *http.Client) (*DeviceFlowClient, error) {
	if httpClient == nil {
		return nil, errors.New("Kimi device-flow HTTP client is required")
	}
	return &DeviceFlowClient{httpClient: httpClient, deviceURL: deviceAuthorizationURL, tokenURL: tokenURL}, nil
}

// NewDeviceFlowClientWithEndpoints creates an isolated client for deterministic integration tests.
// NewDeviceFlowClientWithEndpoints 为确定性集成测试创建隔离客户端。
func NewDeviceFlowClientWithEndpoints(httpClient *http.Client, deviceURL string, exchangeURL string) (*DeviceFlowClient, error) {
	if httpClient == nil || strings.TrimSpace(deviceURL) == "" || strings.TrimSpace(exchangeURL) == "" {
		return nil, errors.New("Kimi device-flow HTTP client and endpoints are required")
	}
	return &DeviceFlowClient{httpClient: httpClient, deviceURL: deviceURL, tokenURL: exchangeURL}, nil
}

// Start requests one provider device code using a newly generated device identity.
// Start 使用新生成的设备身份请求一个供应商设备码。
func (c *DeviceFlowClient) Start(ctx context.Context) (DeviceCode, error) {
	deviceID, errDeviceID := randomIdentifier(16)
	if errDeviceID != nil {
		return DeviceCode{}, errDeviceID
	}
	values := url.Values{"client_id": {codingClientID}}
	request, errRequest := http.NewRequestWithContext(ctx, http.MethodPost, c.deviceURL, strings.NewReader(values.Encode()))
	if errRequest != nil {
		return DeviceCode{}, fmt.Errorf("create Kimi device-code request: %w", errRequest)
	}
	applyDeviceHeaders(request, deviceID)
	response, errResponse := c.httpClient.Do(request)
	if errResponse != nil {
		return DeviceCode{}, fmt.Errorf("request Kimi device code: %w", errResponse)
	}
	defer response.Body.Close()
	body, errBody := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if errBody != nil {
		return DeviceCode{}, fmt.Errorf("read Kimi device-code response: %w", errBody)
	}
	if response.StatusCode != http.StatusOK {
		return DeviceCode{}, fmt.Errorf("Kimi device-code request returned status %d", response.StatusCode)
	}
	var code DeviceCode
	if errDecode := json.Unmarshal(body, &code); errDecode != nil {
		return DeviceCode{}, fmt.Errorf("decode Kimi device-code response: %w", errDecode)
	}
	if strings.TrimSpace(code.DeviceCode) == "" || strings.TrimSpace(code.UserCode) == "" || strings.TrimSpace(code.VerificationURI) == "" {
		return DeviceCode{}, errors.New("Kimi device-code response is incomplete")
	}
	code.DeviceID = deviceID
	return code, nil
}

// Exchange performs one RFC 8628 device-code token exchange.
// Exchange 执行一次 RFC 8628 设备码令牌交换。
func (c *DeviceFlowClient) Exchange(ctx context.Context, code DeviceCode) (Token, error) {
	values := url.Values{"client_id": {codingClientID}, "device_code": {code.DeviceCode}, "grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}}
	request, errRequest := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(values.Encode()))
	if errRequest != nil {
		return Token{}, fmt.Errorf("create Kimi token request: %w", errRequest)
	}
	applyDeviceHeaders(request, code.DeviceID)
	response, errResponse := c.httpClient.Do(request)
	if errResponse != nil {
		return Token{}, fmt.Errorf("request Kimi token: %w", errResponse)
	}
	defer response.Body.Close()
	body, errBody := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if errBody != nil {
		return Token{}, fmt.Errorf("read Kimi token response: %w", errBody)
	}
	var payload struct {
		Error        string  `json:"error"`
		AccessToken  string  `json:"access_token"`
		RefreshToken string  `json:"refresh_token"`
		TokenType    string  `json:"token_type"`
		ExpiresIn    float64 `json:"expires_in"`
		Scope        string  `json:"scope"`
	}
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
	if response.StatusCode != http.StatusOK || strings.TrimSpace(payload.AccessToken) == "" || strings.TrimSpace(payload.RefreshToken) == "" {
		return Token{}, fmt.Errorf("Kimi token request returned an invalid response")
	}
	expiresAt := int64(0)
	if payload.ExpiresIn > 0 {
		expiresAt = time.Now().Unix() + int64(payload.ExpiresIn)
	}
	return Token{AccessToken: payload.AccessToken, RefreshToken: payload.RefreshToken, TokenType: payload.TokenType, Scope: payload.Scope, DeviceID: code.DeviceID, ExpiresAt: expiresAt, Type: "kimi"}, nil
}

// Refresh exchanges one protected refresh token without exposing it outside the provider client.
// Refresh 在不向供应商客户端之外暴露令牌的情况下交换一个受保护 Refresh Token。
func (c *DeviceFlowClient) Refresh(ctx context.Context, token Token) (Token, error) {
	if strings.TrimSpace(token.RefreshToken) == "" || strings.TrimSpace(token.DeviceID) == "" {
		return Token{}, errors.New("Kimi refresh token and device identity are required")
	}
	values := url.Values{"client_id": {codingClientID}, "refresh_token": {token.RefreshToken}, "grant_type": {"refresh_token"}}
	request, errRequest := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(values.Encode()))
	if errRequest != nil {
		return Token{}, fmt.Errorf("create Kimi refresh request: %w", errRequest)
	}
	applyDeviceHeaders(request, token.DeviceID)
	response, errResponse := c.httpClient.Do(request)
	if errResponse != nil {
		return Token{}, fmt.Errorf("request Kimi token refresh: %w", errResponse)
	}
	defer response.Body.Close()
	body, errBody := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if errBody != nil {
		return Token{}, fmt.Errorf("read Kimi refresh response: %w", errBody)
	}
	var payload struct {
		AccessToken  string  `json:"access_token"`
		RefreshToken string  `json:"refresh_token"`
		TokenType    string  `json:"token_type"`
		ExpiresIn    float64 `json:"expires_in"`
		Scope        string  `json:"scope"`
		Error        string  `json:"error"`
	}
	if errDecode := json.Unmarshal(body, &payload); errDecode != nil {
		return Token{}, fmt.Errorf("decode Kimi refresh response: %w", errDecode)
	}
	if response.StatusCode != http.StatusOK || payload.Error != "" || strings.TrimSpace(payload.AccessToken) == "" {
		return Token{}, errors.New("Kimi token refresh was rejected")
	}
	if payload.RefreshToken == "" {
		payload.RefreshToken = token.RefreshToken
	}
	expiresAt := int64(0)
	if payload.ExpiresIn > 0 {
		expiresAt = time.Now().Unix() + int64(payload.ExpiresIn)
	}
	return Token{AccessToken: payload.AccessToken, RefreshToken: payload.RefreshToken, TokenType: payload.TokenType, Scope: payload.Scope, DeviceID: token.DeviceID, ExpiresAt: expiresAt, Type: "kimi"}, nil
}

// Flow describes one management-safe device authorization session.
// Flow 描述一个管理安全的设备授权会话。
type Flow struct {
	ID                      string    `json:"id"`
	UserCode                string    `json:"user_code"`
	VerificationURI         string    `json:"verification_uri"`
	VerificationURIComplete string    `json:"verification_uri_complete"`
	ExpiresAt               time.Time `json:"expires_at"`
	PollIntervalSeconds     int       `json:"poll_interval_seconds"`
}

// flowSession owns the provider secret code and polling schedule for one local flow.
// flowSession 拥有一个本地授权流程的供应商秘密码和轮询计划。
type flowSession struct {
	code       DeviceCode
	flow       Flow
	nextPollAt time.Time
	// token retains a completed provider result only until atomic onboarding succeeds or the session expires.
	// token 仅在原子录入成功或会话过期前保留已完成的供应商结果。
	token *Token
}

// FlowManager owns bounded in-memory device sessions and never persists incomplete authorization state.
// FlowManager 管理有界内存设备会话且绝不持久化未完成授权状态。
type FlowManager struct {
	mu       sync.Mutex
	client   *DeviceFlowClient
	now      func() time.Time
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
	interval := time.Duration(code.Interval) * time.Second
	if interval < defaultPollInterval {
		interval = defaultPollInterval
	}
	lifetime := maximumFlowLifetime
	if code.ExpiresIn > 0 && time.Duration(code.ExpiresIn)*time.Second < lifetime {
		lifetime = time.Duration(code.ExpiresIn) * time.Second
	}
	now := m.now().UTC()
	flow := Flow{ID: flowID, UserCode: code.UserCode, VerificationURI: code.VerificationURI, VerificationURIComplete: code.VerificationURIComplete, ExpiresAt: now.Add(lifetime), PollIntervalSeconds: int(interval / time.Second)}
	m.mu.Lock()
	m.pruneExpiredLocked(now)
	if len(m.sessions) >= maximumFlowSessions {
		m.mu.Unlock()
		return Flow{}, ErrFlowLimitReached
	}
	m.sessions[flowID] = flowSession{code: code, flow: flow, nextPollAt: now}
	m.mu.Unlock()
	return flow, nil
}

// Poll performs at most one provider exchange and consumes a successful or terminal session.
// Poll 最多执行一次供应商交换并消费成功或终止的会话。
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
	if session.token != nil {
		token := *session.token
		m.mu.Unlock()
		return token, nil
	}
	if now.Before(session.nextPollAt) {
		m.mu.Unlock()
		return Token{}, ErrAuthorizationPending
	}
	session.nextPollAt = now.Add(time.Duration(session.flow.PollIntervalSeconds) * time.Second)
	m.sessions[flowID] = session
	m.mu.Unlock()
	token, errExchange := m.client.Exchange(ctx, session.code)
	if errExchange != nil {
		if errors.Is(errExchange, ErrAuthorizationExpired) || errors.Is(errExchange, ErrAuthorizationDenied) {
			m.Cancel(flowID)
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

// Cancel deletes one local session and is idempotent to support cleanup paths.
// Cancel 删除一个本地会话且保持幂等以支持清理路径。
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

// UnmarshalToken decodes one protected token document without accepting an empty access or refresh boundary.
// UnmarshalToken 解码一个受保护令牌文档且不接受空 Access 或 Refresh 边界。
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

// validateToken enforces the complete refreshable Kimi credential boundary.
// validateToken 强制执行完整的可刷新 Kimi 凭据边界。
func validateToken(token Token) error {
	if strings.TrimSpace(token.AccessToken) == "" || strings.TrimSpace(token.RefreshToken) == "" || strings.TrimSpace(token.DeviceID) == "" || token.Type != "kimi" {
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
	request.Header.Set("X-Msh-Platform", "VulcanModelRouter")
	request.Header.Set("X-Msh-Version", "1")
	request.Header.Set("X-Msh-Device-Name", hostname)
	request.Header.Set("X-Msh-Device-Model", runtime.GOOS+" "+runtime.GOARCH)
	request.Header.Set("X-Msh-Device-Id", deviceID)
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
