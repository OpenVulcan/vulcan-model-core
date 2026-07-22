package minimax

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

	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
)

const (
	// oauthClientID is copied from minimax-cli's released device flow.
	// oauthClientID 从 minimax-cli 已发布的设备授权流程复制而来。
	oauthClientID = "659cf4c1-615c-45f6-a5f6-4bf15eb476e5"
	// oauthScope is the exact scope sequence used by minimax-cli.
	// oauthScope 是 minimax-cli 使用的精确 Scope 顺序。
	oauthScope = "openid profile coding_plan"
	// maximumOAuthResponseBytes bounds authentication responses before decoding.
	// maximumOAuthResponseBytes 在解码前限制认证响应大小。
	maximumOAuthResponseBytes = 1 << 20
	// maximumOAuthFlowLifetime bounds retained PKCE state.
	// maximumOAuthFlowLifetime 限制保留的 PKCE 状态时长。
	maximumOAuthFlowLifetime = 15 * time.Minute
	// maximumOAuthFlows bounds unfinished management sessions.
	// maximumOAuthFlows 限制未完成的管理会话数量。
	maximumOAuthFlows = 64
	// defaultOAuthPollInterval is minimax-cli's fallback interval.
	// defaultOAuthPollInterval 是 minimax-cli 的默认轮询间隔。
	defaultOAuthPollInterval = 3 * time.Second
)

var (
	// ErrAuthorizationPending reports an incomplete MiniMax user authorization.
	// ErrAuthorizationPending 表示 MiniMax 用户授权尚未完成。
	ErrAuthorizationPending = errors.New("MiniMax authorization is pending")
	// ErrAuthorizationExpired reports an expired provider or local flow.
	// ErrAuthorizationExpired 表示供应商或本地流程已过期。
	ErrAuthorizationExpired = errors.New("MiniMax authorization expired")
	// ErrAuthorizationDenied reports a terminal provider denial.
	// ErrAuthorizationDenied 表示供应商终止拒绝授权。
	ErrAuthorizationDenied = errors.New("MiniMax authorization denied")
	// ErrFlowNotFound reports an unknown or consumed flow.
	// ErrFlowNotFound 表示流程未知或已消费。
	ErrFlowNotFound = errors.New("MiniMax device flow not found")
	// ErrFlowLimitReached reports bounded session exhaustion.
	// ErrFlowLimitReached 表示有界会话容量耗尽。
	ErrFlowLimitReached = errors.New("MiniMax device flow limit reached")
)

// OAuthRegion fixes all authorization and API Origins for one selected MiniMax variant.
// OAuthRegion 固定一个所选 MiniMax 变体的全部授权与 API Origin。
type OAuthRegion struct {
	// ID is exactly global or cn.
	// ID 必须精确为 global 或 cn。
	ID string
	// AccountBaseURL is the selected OAuth Origin.
	// AccountBaseURL 是所选 OAuth Origin。
	AccountBaseURL string
	// APIBaseURL is the only accepted resource Origin.
	// APIBaseURL 是唯一接受的资源 Origin。
	APIBaseURL string
}

// GlobalOAuthRegion returns the immutable MiniMax Global OAuth boundary.
// GlobalOAuthRegion 返回不可变的 MiniMax Global OAuth 边界。
func GlobalOAuthRegion() OAuthRegion {
	return OAuthRegion{ID: "global", AccountBaseURL: "https://account.minimax.io", APIBaseURL: "https://api.minimax.io"}
}

// CNOAuthRegion returns the immutable MiniMax CN OAuth boundary.
// CNOAuthRegion 返回不可变的 MiniMax CN OAuth 边界。
func CNOAuthRegion() OAuthRegion {
	return OAuthRegion{ID: "cn", AccountBaseURL: "https://account.minimaxi.com", APIBaseURL: "https://api.minimaxi.com"}
}

// DeviceCode contains public verification facts and private PKCE state.
// DeviceCode 包含公开验证事实和私有 PKCE 状态。
type DeviceCode struct {
	// UserCode is shown to the administrator.
	// UserCode 向管理员展示。
	UserCode string `json:"user_code"`
	// VerificationURI is the provider browser page.
	// VerificationURI 是供应商浏览器页面。
	VerificationURI string `json:"verification_uri"`
	// ExpiresAt is the provider-returned absolute expiry.
	// ExpiresAt 是供应商返回的绝对过期时刻。
	ExpiresAt time.Time `json:"expires_at"`
	// PollInterval is the provider minimum poll cadence.
	// PollInterval 是供应商最小轮询间隔。
	PollInterval time.Duration `json:"-"`
	// CodeVerifier is retained only in local flow memory.
	// CodeVerifier 仅保留在本地流程内存中。
	CodeVerifier string `json:"-"`
}

// Flow is the management-safe MiniMax authorization session.
// Flow 是管理安全的 MiniMax 授权会话。
type Flow struct {
	// ID is the Router-owned opaque session identifier.
	// ID 是 Router 拥有的不透明会话标识。
	ID string `json:"id"`
	// UserCode is the provider-issued short code.
	// UserCode 是供应商签发的短码。
	UserCode string `json:"user_code"`
	// VerificationURI is the validated provider browser link.
	// VerificationURI 是经过校验的供应商浏览器链接。
	VerificationURI string `json:"verification_uri"`
	// VerificationURIComplete remains empty because MiniMax returns a separate user code.
	// VerificationURIComplete 保持为空，因为 MiniMax 返回独立的用户码。
	VerificationURIComplete string `json:"verification_uri_complete"`
	// ExpiresAt bounds session retention.
	// ExpiresAt 限制会话保留时间。
	ExpiresAt time.Time `json:"expires_at"`
	// PollIntervalSeconds is the minimum management polling cadence.
	// PollIntervalSeconds 是管理面最小轮询间隔秒数。
	PollIntervalSeconds int `json:"poll_interval_seconds"`
}

// deviceCodeResponse mirrors minimax-cli's exact OAuth response names.
// deviceCodeResponse 镜像 minimax-cli 的精确 OAuth 响应字段名。
type deviceCodeResponse struct {
	// UserCode is the provider device user code.
	// UserCode 是供应商设备用户码。
	UserCode string `json:"user_code"`
	// VerificationURI is the browser verification location.
	// VerificationURI 是浏览器验证地址。
	VerificationURI string `json:"verification_uri"`
	// ExpiredIn is an absolute Unix millisecond timestamp despite its name.
	// ExpiredIn 尽管名称如此，实际是绝对 Unix 毫秒时间戳。
	ExpiredIn int64 `json:"expired_in"`
	// Interval is a poll interval in milliseconds.
	// Interval 是毫秒轮询间隔。
	Interval int64 `json:"interval"`
	// State must exactly echo the request state.
	// State 必须精确回显请求 State。
	State string `json:"state"`
}

// oauthTokenResponse mirrors device exchange and refresh responses.
// oauthTokenResponse 镜像设备交换与刷新响应。
type oauthTokenResponse struct {
	// Status is pending or success during device exchange.
	// Status 在设备交换时为 pending 或 success。
	Status string `json:"status"`
	// AccessToken authenticates API requests.
	// AccessToken 用于认证 API 请求。
	AccessToken string `json:"access_token"`
	// RefreshToken obtains replacement access tokens.
	// RefreshToken 用于获取替代 Access Token。
	RefreshToken string `json:"refresh_token"`
	// ExpiredIn is an absolute Unix millisecond timestamp.
	// ExpiredIn 是绝对 Unix 毫秒时间戳。
	ExpiredIn int64 `json:"expired_in"`
	// ResourceURL is a provider-selected API URL that must remain within the selected region Origin.
	// ResourceURL 是供应商选择的 API URL，必须保持在所选区域 Origin 内。
	ResourceURL string `json:"resource_url"`
}

// DeviceFlowClient performs one region-fixed MiniMax OAuth exchange at a time.
// DeviceFlowClient 每次执行一次区域固定的 MiniMax OAuth 交换。
type DeviceFlowClient struct {
	// client performs bounded requests without redirects.
	// client 执行有界且不跟随重定向的请求。
	client *http.Client
	// region fixes OAuth and API origins.
	// region 固定 OAuth 与 API Origin。
	region OAuthRegion
	// deviceURL is the exact device-code endpoint.
	// deviceURL 是精确设备码端点。
	deviceURL string
	// tokenURL is the exact exchange and refresh endpoint.
	// tokenURL 是精确交换与刷新端点。
	tokenURL string
	// now supplies deterministic expiry validation.
	// now 提供确定性过期校验时间。
	now func() time.Time
}

// NewDeviceFlowClient creates one production region-fixed client.
// NewDeviceFlowClient 创建一个生产环境区域固定客户端。
func NewDeviceFlowClient(client *http.Client, region OAuthRegion) (*DeviceFlowClient, error) {
	if client == nil || !validOAuthRegion(region) {
		return nil, errors.New("MiniMax device-flow client and valid region are required")
	}
	accountBase := strings.TrimRight(region.AccountBaseURL, "/")
	return &DeviceFlowClient{client: transport.CloneHTTPClientWithoutRedirects(client), region: region, deviceURL: accountBase + "/oauth2/device/code", tokenURL: accountBase + "/oauth2/token", now: time.Now}, nil
}

// NewDeviceFlowClientWithEndpoints creates an isolated test client while preserving one region's resource Origin.
// NewDeviceFlowClientWithEndpoints 创建隔离测试客户端，同时保留一个区域的资源 Origin。
func NewDeviceFlowClientWithEndpoints(client *http.Client, region OAuthRegion, deviceURL string, tokenURL string) (*DeviceFlowClient, error) {
	flow, errFlow := NewDeviceFlowClient(client, region)
	if errFlow != nil || strings.TrimSpace(deviceURL) == "" || strings.TrimSpace(tokenURL) == "" {
		return nil, errors.New("MiniMax test device-flow client requires endpoints")
	}
	flow.deviceURL, flow.tokenURL = deviceURL, tokenURL
	return flow, nil
}

// Start requests one device code with fresh PKCE and CSRF state.
// Start 使用全新 PKCE 与 CSRF State 请求一个设备码。
func (c *DeviceFlowClient) Start(ctx context.Context) (DeviceCode, error) {
	verifier, errVerifier := randomBase64URL(32)
	if errVerifier != nil {
		return DeviceCode{}, errVerifier
	}
	state, errState := randomBase64URL(16)
	if errState != nil {
		return DeviceCode{}, errState
	}
	challengeDigest := sha256.Sum256([]byte(verifier))
	values := url.Values{"client_id": {oauthClientID}, "scope": {oauthScope}, "code_challenge": {base64.RawURLEncoding.EncodeToString(challengeDigest[:])}, "code_challenge_method": {"S256"}, "state": {state}}
	var response deviceCodeResponse
	if errRequest := c.postForm(ctx, c.deviceURL, values, &response); errRequest != nil {
		return DeviceCode{}, errRequest
	}
	if response.State != state || strings.TrimSpace(response.UserCode) == "" || response.ExpiredIn <= 0 {
		return DeviceCode{}, fmt.Errorf("%w: MiniMax device-code response is incomplete", provider.ErrAuthenticationResponseInvalid)
	}
	verificationURI, errURI := transport.ValidateAbsoluteHTTPURL(response.VerificationURI)
	if errURI != nil {
		return DeviceCode{}, fmt.Errorf("%w: MiniMax verification URI is invalid", provider.ErrAuthenticationResponseInvalid)
	}
	expiresAt := time.UnixMilli(response.ExpiredIn).UTC()
	if !expiresAt.After(c.now().UTC()) {
		return DeviceCode{}, fmt.Errorf("%w: MiniMax device code is already expired", provider.ErrAuthenticationResponseInvalid)
	}
	interval := time.Duration(response.Interval) * time.Millisecond
	if interval <= 0 {
		interval = defaultOAuthPollInterval
	}
	return DeviceCode{UserCode: response.UserCode, VerificationURI: verificationURI, ExpiresAt: expiresAt, PollInterval: interval, CodeVerifier: verifier}, nil
}

// Exchange performs one device token poll without internally sleeping.
// Exchange 执行一次设备 Token 轮询且不在内部休眠。
func (c *DeviceFlowClient) Exchange(ctx context.Context, code DeviceCode) (Token, error) {
	values := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "client_id": {oauthClientID}, "user_code": {code.UserCode}, "code_verifier": {code.CodeVerifier}}
	var response oauthTokenResponse
	if errRequest := c.postForm(ctx, c.tokenURL, values, &response); errRequest != nil {
		return Token{}, errRequest
	}
	switch response.Status {
	case "pending":
		return Token{}, ErrAuthorizationPending
	case "success":
	default:
		return Token{}, ErrAuthorizationDenied
	}
	return c.tokenFromResponse(response, "")
}

// Refresh exchanges one refresh token using minimax-cli's bounded three-attempt policy.
// Refresh 使用 minimax-cli 的有界三次尝试策略交换一个 Refresh Token。
func (c *DeviceFlowClient) Refresh(ctx context.Context, token Token) (Token, error) {
	if errValidate := validateToken(token); errValidate != nil || token.Region != c.region.ID {
		return Token{}, fmt.Errorf("%w: MiniMax token does not belong to selected region", provider.ErrAuthenticationResponseInvalid)
	}
	var lastError error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return Token{}, ctx.Err()
			case <-time.After(time.Duration(attempt) * 500 * time.Millisecond):
			}
		}
		attemptContext, cancel := context.WithTimeout(ctx, 10*time.Second)
		values := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token.RefreshToken}, "client_id": {oauthClientID}}
		var response oauthTokenResponse
		status, errRequest := c.postFormStatus(attemptContext, c.tokenURL, values, &response)
		cancel()
		if errRequest == nil {
			return c.tokenFromResponse(response, token.RefreshToken)
		}
		if status >= http.StatusBadRequest && status < http.StatusInternalServerError {
			return Token{}, fmt.Errorf("%w: MiniMax OAuth refresh was rejected", provider.ErrAuthenticationRejected)
		}
		lastError = errRequest
	}
	return Token{}, fmt.Errorf("%w: MiniMax OAuth refresh failed after three attempts: %v", provider.ErrAuthenticationUnavailable, lastError)
}

// tokenFromResponse validates token material and same-region resource ownership.
// tokenFromResponse 校验 Token 材料及同区域资源归属。
func (c *DeviceFlowClient) tokenFromResponse(response oauthTokenResponse, retainedRefreshToken string) (Token, error) {
	if response.Status != "success" || strings.TrimSpace(response.AccessToken) == "" || response.ExpiredIn <= 0 {
		return Token{}, fmt.Errorf("%w: MiniMax OAuth response is incomplete", provider.ErrAuthenticationResponseInvalid)
	}
	refreshToken := response.RefreshToken
	if refreshToken == "" {
		refreshToken = retainedRefreshToken
	}
	resourceURL, errResource := validateResourceURL(response.ResourceURL, c.region.APIBaseURL)
	if errResource != nil {
		return Token{}, fmt.Errorf("%w: %v", provider.ErrAuthenticationResponseInvalid, errResource)
	}
	token := Token{AccessToken: response.AccessToken, RefreshToken: refreshToken, ExpiresAt: time.UnixMilli(response.ExpiredIn).UTC(), Region: c.region.ID, ResourceURL: resourceURL, Type: "minimax"}
	if errValidate := validateToken(token); errValidate != nil || !token.ExpiresAt.After(c.now().UTC()) {
		return Token{}, fmt.Errorf("%w: MiniMax OAuth token is invalid", provider.ErrAuthenticationResponseInvalid)
	}
	return token, nil
}

// postForm posts and decodes one successful OAuth form response.
// postForm 提交并解码一个成功 OAuth 表单响应。
func (c *DeviceFlowClient) postForm(ctx context.Context, endpoint string, values url.Values, destination any) error {
	_, errRequest := c.postFormStatus(ctx, endpoint, values, destination)
	return errRequest
}

// postFormStatus preserves HTTP status for refresh retry classification.
// postFormStatus 为刷新重试分类保留 HTTP 状态。
func (c *DeviceFlowClient) postFormStatus(ctx context.Context, endpoint string, values url.Values, destination any) (int, error) {
	body := []byte(values.Encode())
	defer clear(body)
	request, errRequest := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if errRequest != nil {
		return 0, errRequest
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, errResponse := c.client.Do(request)
	if errResponse != nil {
		return 0, errResponse
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return response.StatusCode, fmt.Errorf("MiniMax OAuth endpoint returned status %d", response.StatusCode)
	}
	reader := io.LimitReader(response.Body, maximumOAuthResponseBytes+1)
	encoded, errRead := io.ReadAll(reader)
	if errRead != nil || len(encoded) > maximumOAuthResponseBytes {
		return response.StatusCode, fmt.Errorf("%w: MiniMax OAuth response exceeds the allowed size", provider.ErrAuthenticationResponseInvalid)
	}
	defer clear(encoded)
	if errDecode := json.Unmarshal(encoded, destination); errDecode != nil {
		return response.StatusCode, fmt.Errorf("%w: MiniMax OAuth response is invalid", provider.ErrAuthenticationResponseInvalid)
	}
	return response.StatusCode, nil
}

// flowSession retains one private device code and an optional leased token.
// flowSession 保留一个私有设备码和可选租借 Token。
type flowSession struct {
	// code contains private PKCE material.
	// code 包含私有 PKCE 材料。
	code DeviceCode
	// flow contains client-safe metadata.
	// flow 包含客户端安全元数据。
	flow Flow
	// nextPollAt enforces provider cadence.
	// nextPollAt 强制执行供应商轮询节奏。
	nextPollAt time.Time
	// polling prevents concurrent exchange and leases a successful token.
	// polling 防止并发交换并租借成功 Token。
	polling bool
	// token retains completed authorization until consumption.
	// token 保留完成的授权直至消费。
	token *Token
}

// FlowManager owns bounded in-memory MiniMax device authorization state.
// FlowManager 管理有界的内存 MiniMax 设备授权状态。
type FlowManager struct {
	// mu protects sessions.
	// mu 保护会话。
	mu sync.Mutex
	// client performs provider exchanges.
	// client 执行供应商交换。
	client *DeviceFlowClient
	// now supplies deterministic time.
	// now 提供确定性时间。
	now func() time.Time
	// sessions owns incomplete or leased flows.
	// sessions 管理未完成或已租借流程。
	sessions map[string]flowSession
}

// NewFlowManager creates an empty MiniMax flow manager.
// NewFlowManager 创建一个空 MiniMax 流程管理器。
func NewFlowManager(client *DeviceFlowClient) (*FlowManager, error) {
	if client == nil {
		return nil, errors.New("MiniMax device-flow client is required")
	}
	return &FlowManager{client: client, now: time.Now, sessions: make(map[string]flowSession)}, nil
}

// Start creates one provider code and retains private PKCE state locally.
// Start 创建一个供应商设备码并在本地保留私有 PKCE 状态。
func (m *FlowManager) Start(ctx context.Context) (Flow, error) {
	code, errCode := m.client.Start(ctx)
	if errCode != nil {
		return Flow{}, errCode
	}
	flowID, errID := randomBase64URL(16)
	if errID != nil {
		return Flow{}, errID
	}
	now := m.now().UTC()
	expiresAt := code.ExpiresAt
	if expiresAt.After(now.Add(maximumOAuthFlowLifetime)) {
		expiresAt = now.Add(maximumOAuthFlowLifetime)
	}
	flow := Flow{ID: flowID, UserCode: code.UserCode, VerificationURI: code.VerificationURI, ExpiresAt: expiresAt, PollIntervalSeconds: max(1, int(code.PollInterval/time.Second))}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneExpiredLocked(now)
	if len(m.sessions) >= maximumOAuthFlows {
		return Flow{}, ErrFlowLimitReached
	}
	m.sessions[flowID] = flowSession{code: code, flow: flow, nextPollAt: now.Add(code.PollInterval)}
	return flow, nil
}

// Poll performs at most one provider exchange and leases completed material.
// Poll 最多执行一次供应商交换并租借已完成材料。
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
		session.polling = true
		m.sessions[flowID] = session
		token := *session.token
		m.mu.Unlock()
		return token, nil
	}
	if now.Before(session.nextPollAt) {
		m.mu.Unlock()
		return Token{}, ErrAuthorizationPending
	}
	session.polling = true
	session.nextPollAt = now.Add(session.code.PollInterval)
	m.sessions[flowID] = session
	m.mu.Unlock()
	token, errExchange := m.client.Exchange(ctx, session.code)
	if errExchange != nil {
		m.mu.Lock()
		current, found := m.sessions[flowID]
		if found {
			current.polling = false
			m.sessions[flowID] = current
		}
		m.mu.Unlock()
		if errors.Is(errExchange, ErrAuthorizationDenied) || errors.Is(errExchange, ErrAuthorizationExpired) {
			m.Cancel(flowID)
		}
		return Token{}, errExchange
	}
	m.mu.Lock()
	current, found := m.sessions[flowID]
	if !found {
		m.mu.Unlock()
		return Token{}, ErrFlowNotFound
	}
	current.token = &token
	m.sessions[flowID] = current
	m.mu.Unlock()
	return token, nil
}

// Release returns a delivered token lease after downstream failure.
// Release 在下游失败后归还已交付 Token 租约。
func (m *FlowManager) Release(flowID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	session, exists := m.sessions[flowID]
	if exists && session.token != nil {
		session.polling = false
		m.sessions[flowID] = session
	}
}

// Cancel idempotently consumes one local flow.
// Cancel 幂等消费一个本地流程。
func (m *FlowManager) Cancel(flowID string) {
	m.mu.Lock()
	delete(m.sessions, flowID)
	m.mu.Unlock()
}

// pruneExpiredLocked removes expired sessions while the caller owns the lock.
// pruneExpiredLocked 在调用方持锁时移除过期会话。
func (m *FlowManager) pruneExpiredLocked(now time.Time) {
	for flowID, session := range m.sessions {
		if !now.Before(session.flow.ExpiresAt) {
			delete(m.sessions, flowID)
		}
	}
}

// RegionalFlowManager dispatches MiniMax device flows only to an explicitly selected regional manager.
// RegionalFlowManager 仅将 MiniMax 设备授权流程分派到显式选择的区域管理器。
type RegionalFlowManager struct {
	// global owns Global-site transient authorization state.
	// global 管理 Global 站点的临时授权状态。
	global *FlowManager
	// cn owns CN-site transient authorization state.
	// cn 管理 CN 站点的临时授权状态。
	cn *FlowManager
}

// NewRegionalFlowManager creates one strict two-region MiniMax authorization dispatcher.
// NewRegionalFlowManager 创建一个严格的 MiniMax 双区域授权分派器。
func NewRegionalFlowManager(global *FlowManager, cn *FlowManager) (*RegionalFlowManager, error) {
	if global == nil || cn == nil {
		return nil, errors.New("MiniMax Global and CN flow managers are required")
	}
	return &RegionalFlowManager{global: global, cn: cn}, nil
}

// Start creates a flow in exactly the requested region and returns an opaque region-bound identifier.
// Start 仅在请求的精确区域创建流程，并返回一个不透明且绑定区域的标识。
func (m *RegionalFlowManager) Start(ctx context.Context, region string) (Flow, error) {
	manager, errRegion := m.manager(region)
	if errRegion != nil {
		return Flow{}, errRegion
	}
	flow, errStart := manager.Start(ctx)
	if errStart != nil {
		return Flow{}, errStart
	}
	flow.ID = region + "." + flow.ID
	return flow, nil
}

// Poll performs one exchange against the manager encoded by the opaque flow identifier.
// Poll 针对不透明流程标识编码的管理器执行一次交换。
func (m *RegionalFlowManager) Poll(ctx context.Context, flowID string) (Token, error) {
	manager, localID, errFlow := m.resolve(flowID)
	if errFlow != nil {
		return Token{}, errFlow
	}
	return manager.Poll(ctx, localID)
}

// Release returns one completed token lease to its exact regional manager.
// Release 将一个已完成 Token 租约归还给其精确区域管理器。
func (m *RegionalFlowManager) Release(flowID string) {
	manager, localID, errFlow := m.resolve(flowID)
	if errFlow == nil {
		manager.Release(localID)
	}
}

// Cancel removes one flow from its exact regional manager.
// Cancel 从其精确区域管理器中删除一个流程。
func (m *RegionalFlowManager) Cancel(flowID string) {
	manager, localID, errFlow := m.resolve(flowID)
	if errFlow == nil {
		manager.Cancel(localID)
	}
}

// manager selects one closed MiniMax region without inspecting credential material.
// manager 在不检查凭据材料的情况下选择一个封闭的 MiniMax 区域。
func (m *RegionalFlowManager) manager(region string) (*FlowManager, error) {
	switch region {
	case "global":
		return m.global, nil
	case "cn":
		return m.cn, nil
	default:
		return nil, errors.New("MiniMax device authorization region must be global or cn")
	}
}

// resolve decodes only identifiers produced by Start and rejects ambiguous values.
// resolve 仅解码由 Start 生成的标识，并拒绝含糊值。
func (m *RegionalFlowManager) resolve(flowID string) (*FlowManager, string, error) {
	region, localID, found := strings.Cut(flowID, ".")
	if !found || strings.TrimSpace(localID) == "" || strings.Contains(localID, ".") {
		return nil, "", ErrFlowNotFound
	}
	manager, errRegion := m.manager(region)
	if errRegion != nil {
		return nil, "", ErrFlowNotFound
	}
	return manager, localID, nil
}

// RegionalTokenClient refreshes one token only through its document-declared regional OAuth client.
// RegionalTokenClient 仅通过 Token 文档声明的区域 OAuth 客户端刷新该 Token。
type RegionalTokenClient struct {
	// global exchanges Global-site refresh tokens.
	// global 交换 Global 站点 Refresh Token。
	global *DeviceFlowClient
	// cn exchanges CN-site refresh tokens.
	// cn 交换 CN 站点 Refresh Token。
	cn *DeviceFlowClient
}

// NewRegionalTokenClient creates a strict region-bound MiniMax refresh dispatcher.
// NewRegionalTokenClient 创建一个严格绑定区域的 MiniMax 刷新分派器。
func NewRegionalTokenClient(global *DeviceFlowClient, cn *DeviceFlowClient) (*RegionalTokenClient, error) {
	if global == nil || cn == nil {
		return nil, errors.New("MiniMax Global and CN token clients are required")
	}
	return &RegionalTokenClient{global: global, cn: cn}, nil
}

// Refresh selects the OAuth Origin exclusively from the validated protected token region.
// Refresh 仅根据已校验受保护 Token 的区域选择 OAuth Origin。
func (c *RegionalTokenClient) Refresh(ctx context.Context, token Token) (Token, error) {
	switch token.Region {
	case "global":
		return c.global.Refresh(ctx, token)
	case "cn":
		return c.cn.Refresh(ctx, token)
	default:
		return Token{}, fmt.Errorf("%w: MiniMax token has an invalid region", provider.ErrAuthenticationResponseInvalid)
	}
}

// randomBase64URL creates one unpadded URL-safe random value.
// randomBase64URL 创建一个无填充且 URL 安全的随机值。
func randomBase64URL(size int) (string, error) {
	value := make([]byte, size)
	if _, errRead := rand.Read(value); errRead != nil {
		return "", errRead
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

// validOAuthRegion verifies one exact supported region tuple.
// validOAuthRegion 校验一个精确受支持区域元组。
func validOAuthRegion(region OAuthRegion) bool {
	return region == GlobalOAuthRegion() || region == CNOAuthRegion()
}

// validateResourceURL accepts only URLs whose Origin equals the selected region API Origin.
// validateResourceURL 仅接受 Origin 与所选区域 API Origin 相同的 URL。
func validateResourceURL(resourceURL string, expectedBaseURL string) (string, error) {
	if strings.TrimSpace(resourceURL) == "" {
		return strings.TrimRight(expectedBaseURL, "/"), nil
	}
	validated, errValidate := transport.ValidateAbsoluteHTTPURL(resourceURL)
	if errValidate != nil {
		return "", errors.New("MiniMax resource URL is invalid")
	}
	actual, _ := url.Parse(validated)
	expected, _ := url.Parse(expectedBaseURL)
	if !strings.EqualFold(actual.Scheme, expected.Scheme) || !strings.EqualFold(actual.Host, expected.Host) {
		return "", errors.New("MiniMax resource URL crosses the selected regional Origin")
	}
	return validated, nil
}
