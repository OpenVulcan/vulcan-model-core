package xai

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
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
	providertransport "github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
)

const (
	// oauthDiscoveryURL is xAI's OIDC discovery document copied from CLIProxyAPI.
	// oauthDiscoveryURL 是从 CLIProxyAPI 复制的 xAI OIDC 发现文档地址。
	oauthDiscoveryURL = "https://auth.x.ai/.well-known/openid-configuration"
	// oauthClientID is the public Grok CLI OAuth client identifier.
	// oauthClientID 是公开 Grok CLI OAuth 客户端标识。
	oauthClientID = "b1a00492-073a-47ea-816f-4c329264a828"
	// oauthScope is the exact Grok CLI scope set.
	// oauthScope 是精确 Grok CLI Scope 集合。
	oauthScope = "openid profile email offline_access grok-cli:access api:access"
	// deviceCodeGrantType is the RFC 8628 device-code grant.
	// deviceCodeGrantType 是 RFC 8628 设备码 Grant。
	deviceCodeGrantType = "urn:ietf:params:oauth:grant-type:device_code"
	// maximumFlowLifetime bounds incomplete authorization state.
	// maximumFlowLifetime 限制未完成授权状态的最长生命周期。
	maximumFlowLifetime = 30 * time.Minute
	// maximumFlowSessions bounds concurrent incomplete management flows.
	// maximumFlowSessions 限制并发未完成管理授权流程数量。
	maximumFlowSessions = 64
	// defaultPollInterval matches CLIProxyAPI's minimum RFC 8628 polling interval.
	// defaultPollInterval 与 CLIProxyAPI 的最小 RFC 8628 轮询间隔一致。
	defaultPollInterval = 5 * time.Second
	// maximumOAuthResponseBytes bounds every xAI discovery and token response before JSON decoding.
	// maximumOAuthResponseBytes 在 JSON 解码前限制每个 xAI 发现与 Token 响应大小。
	maximumOAuthResponseBytes = 1 << 20
)

// xaiJSONResponse seals the two response shapes accepted by the discovery request boundary.
// xaiJSONResponse 封闭发现请求边界允许的两种响应形状。
type xaiJSONResponse interface {
	// isXAIJSONResponse prevents arbitrary destination objects from entering the OAuth decoder.
	// isXAIJSONResponse 阻止任意目标对象进入 OAuth 解码器。
	isXAIJSONResponse()
}

// xaiDeviceCodeResponse mirrors CLIProxyAPI's exact RFC 8628 device response.
// xaiDeviceCodeResponse 镜像 CLIProxyAPI 的精确 RFC 8628 设备响应。
type xaiDeviceCodeResponse struct {
	// DeviceCode is the provider secret retained only in process memory.
	// DeviceCode 是仅保留在进程内存中的供应商秘密。
	DeviceCode string `json:"device_code"`
	// UserCode is the short code shown to the user.
	// UserCode 是向用户显示的短码。
	UserCode string `json:"user_code"`
	// VerificationURI is the provider authorization page.
	// VerificationURI 是供应商授权页面。
	VerificationURI string `json:"verification_uri"`
	// VerificationURIComplete is the optional prefilled provider authorization page.
	// VerificationURIComplete 是可选的预填供应商授权页面。
	VerificationURIComplete string `json:"verification_uri_complete"`
	// ExpiresIn is the provider lifetime in seconds.
	// ExpiresIn 是供应商返回的有效秒数。
	ExpiresIn int `json:"expires_in"`
	// Interval is the provider polling interval in seconds.
	// Interval 是供应商返回的轮询秒数。
	Interval int `json:"interval"`
}

// isXAIJSONResponse marks the exact xAI device response as decoder-safe.
// isXAIJSONResponse 将精确 xAI 设备响应标记为可安全解码。
func (*xaiDeviceCodeResponse) isXAIJSONResponse() {}

// xaiDiscoveryResponse contains only the two OAuth endpoints consumed from OIDC discovery.
// xaiDiscoveryResponse 仅包含从 OIDC 发现文档消费的两个 OAuth 入口。
type xaiDiscoveryResponse struct {
	// DeviceAuthorizationEndpoint is the discovered device endpoint.
	// DeviceAuthorizationEndpoint 是发现得到的设备入口。
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	// TokenEndpoint is the discovered token endpoint.
	// TokenEndpoint 是发现得到的 Token 入口。
	TokenEndpoint string `json:"token_endpoint"`
}

// isXAIJSONResponse marks the exact xAI discovery response as decoder-safe.
// isXAIJSONResponse 将精确 xAI 发现响应标记为可安全解码。
func (*xaiDiscoveryResponse) isXAIJSONResponse() {}

// xaiTokenResponse mirrors CLIProxyAPI's token and RFC 8628 error response fields.
// xaiTokenResponse 镜像 CLIProxyAPI 的 Token 与 RFC 8628 错误响应字段。
type xaiTokenResponse struct {
	// AccessToken authenticates provider requests.
	// AccessToken 用于认证供应商请求。
	AccessToken string `json:"access_token"`
	// RefreshToken refreshes provider access.
	// RefreshToken 用于刷新供应商访问权。
	RefreshToken string `json:"refresh_token"`
	// IDToken contains identity claims.
	// IDToken 包含身份声明。
	IDToken string `json:"id_token"`
	// TokenType is the OAuth token type.
	// TokenType 是 OAuth Token 类型。
	TokenType string `json:"token_type"`
	// ExpiresIn is the access-token lifetime.
	// ExpiresIn 是 Access Token 有效秒数。
	ExpiresIn int `json:"expires_in"`
	// Error is the RFC 8628 error code.
	// Error 是 RFC 8628 错误码。
	Error string `json:"error"`
	// ErrorDescription is the optional provider explanation attached to an OAuth error.
	// ErrorDescription 是 OAuth 错误附带的可选供应商说明。
	ErrorDescription string `json:"error_description"`
}

var (
	// ErrAuthorizationPending reports an incomplete provider authorization.
	// ErrAuthorizationPending 表示供应商授权尚未完成。
	ErrAuthorizationPending = errors.New("xAI authorization is pending")
	// ErrAuthorizationExpired reports an expired provider code.
	// ErrAuthorizationExpired 表示供应商设备码已过期。
	ErrAuthorizationExpired = errors.New("xAI authorization expired")
	// ErrAuthorizationDenied reports an explicit provider denial.
	// ErrAuthorizationDenied 表示供应商明确拒绝授权。
	ErrAuthorizationDenied = errors.New("xAI authorization denied")
	// ErrFlowNotFound reports an unknown local flow.
	// ErrFlowNotFound 表示本地授权流程不存在。
	ErrFlowNotFound = errors.New("xAI device flow not found")
	// ErrFlowLimitReached reports excessive incomplete flows.
	// ErrFlowLimitReached 表示未完成授权流程过多。
	ErrFlowLimitReached = errors.New("xAI device flow limit reached")
	// errAuthorizationSlowDown preserves RFC 8628 slow_down while remaining compatible with pending callers.
	// errAuthorizationSlowDown 保留 RFC 8628 slow_down 语义，同时兼容待授权调用方。
	errAuthorizationSlowDown = fmt.Errorf("%w: slow down", ErrAuthorizationPending)
)

// DeviceCode contains xAI's public verification data and the discovered token endpoint.
// DeviceCode 包含 xAI 的公开验证数据与发现得到的 Token 入口。
type DeviceCode struct {
	// DeviceCode is the provider secret retained only in process memory.
	// DeviceCode 是仅保留在进程内存中的供应商秘密。
	DeviceCode string `json:"-"`
	// UserCode is the short code shown to the user.
	// UserCode 是向用户显示的短码。
	UserCode string `json:"user_code"`
	// VerificationURI is the provider authorization page.
	// VerificationURI 是供应商授权页面。
	VerificationURI string `json:"verification_uri"`
	// VerificationURIComplete is the prefilled provider authorization page.
	// VerificationURIComplete 是预填设备码的供应商授权页面。
	VerificationURIComplete string `json:"verification_uri_complete"`
	// ExpiresIn is the provider lifetime in seconds.
	// ExpiresIn 是供应商返回的有效秒数。
	ExpiresIn int `json:"expires_in"`
	// Interval is the provider polling interval in seconds.
	// Interval 是供应商返回的轮询秒数。
	Interval int `json:"interval"`
	// TokenEndpoint is the validated OIDC token endpoint.
	// TokenEndpoint 是经过校验的 OIDC Token 入口。
	TokenEndpoint string `json:"-"`
}

// Token contains one usable xAI credential whose refresh token is provider-optional.
// Token 包含一个可用的 xAI 凭据，其中 Refresh Token 是否存在由供应商决定。
type Token struct {
	// AccessToken authenticates xAI requests.
	// AccessToken 用于认证 xAI 请求。
	AccessToken string `json:"access_token"`
	// RefreshToken refreshes the access token.
	// RefreshToken 用于刷新 Access Token。
	RefreshToken string `json:"refresh_token"`
	// IDToken contains optional identity claims.
	// IDToken 包含可选身份声明。
	IDToken string `json:"id_token,omitempty"`
	// TokenType is the OAuth token type.
	// TokenType 是 OAuth Token 类型。
	TokenType string `json:"token_type,omitempty"`
	// ExpiresAt is the access-token Unix expiry.
	// ExpiresAt 是 Access Token 的 Unix 过期时间。
	ExpiresAt int64 `json:"expires_at"`
	// TokenEndpoint is the validated refresh endpoint.
	// TokenEndpoint 是经过校验的刷新入口。
	TokenEndpoint string `json:"token_endpoint"`
	// Email is the optional account identity copied from the xAI ID token.
	// Email 是从 xAI ID Token 复制的可选账号身份。
	Email string `json:"email,omitempty"`
	// Subject is the optional stable account subject copied from the xAI ID token.
	// Subject 是从 xAI ID Token 复制的可选稳定账号 Subject。
	Subject string `json:"subject,omitempty"`
	// Type distinguishes the protected document.
	// Type 用于区分受保护文档。
	Type string `json:"type"`
}

// DeviceFlowClient performs xAI discovery, device exchange, and refresh calls.
// DeviceFlowClient 执行 xAI 发现、设备交换与刷新调用。
type DeviceFlowClient struct {
	// httpClient owns bounded network execution.
	// httpClient 管理有界网络执行。
	httpClient *http.Client
	// discoveryURL is the production discovery address or an explicit test address.
	// discoveryURL 是生产发现地址或显式测试地址。
	discoveryURL string
	// fixedDeviceURL bypasses discovery only for deterministic tests.
	// fixedDeviceURL 仅为确定性测试绕过发现。
	fixedDeviceURL string
	// fixedTokenURL bypasses discovery only for deterministic tests.
	// fixedTokenURL 仅为确定性测试绕过发现。
	fixedTokenURL string
}

// NewDeviceFlowClient creates a production xAI device-flow client.
// NewDeviceFlowClient 创建生产 xAI 设备授权客户端。
func NewDeviceFlowClient(httpClient *http.Client) (*DeviceFlowClient, error) {
	if httpClient == nil {
		return nil, errors.New("xAI device-flow HTTP client is required")
	}
	return &DeviceFlowClient{httpClient: providertransport.CloneHTTPClientWithoutRedirects(httpClient), discoveryURL: oauthDiscoveryURL}, nil
}

// NewDeviceFlowClientWithEndpoints creates an isolated client for deterministic tests.
// NewDeviceFlowClientWithEndpoints 为确定性测试创建隔离客户端。
func NewDeviceFlowClientWithEndpoints(httpClient *http.Client, deviceURL string, tokenURL string) (*DeviceFlowClient, error) {
	if httpClient == nil || strings.TrimSpace(deviceURL) == "" || strings.TrimSpace(tokenURL) == "" {
		return nil, errors.New("xAI device-flow HTTP client and endpoints are required")
	}
	return &DeviceFlowClient{httpClient: providertransport.CloneHTTPClientWithoutRedirects(httpClient), fixedDeviceURL: deviceURL, fixedTokenURL: tokenURL}, nil
}

// Start discovers trusted endpoints and requests one xAI device code.
// Start 发现受信任入口并请求一个 xAI 设备码。
func (c *DeviceFlowClient) Start(ctx context.Context) (DeviceCode, error) {
	deviceEndpoint, tokenEndpoint, errEndpoints := c.endpoints(ctx)
	if errEndpoints != nil {
		return DeviceCode{}, errEndpoints
	}
	form := url.Values{"client_id": {oauthClientID}, "scope": {oauthScope}}
	encodedForm := []byte(form.Encode())
	defer clear(encodedForm)
	request, errRequest := http.NewRequestWithContext(ctx, http.MethodPost, deviceEndpoint, bytes.NewReader(encodedForm))
	if errRequest != nil {
		return DeviceCode{}, fmt.Errorf("create xAI device-code request: %w", errRequest)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	var payload xaiDeviceCodeResponse
	if errDo := c.doJSON(request, &payload); errDo != nil {
		return DeviceCode{}, errDo
	}
	code := DeviceCode{DeviceCode: payload.DeviceCode, UserCode: payload.UserCode, VerificationURI: payload.VerificationURI, VerificationURIComplete: payload.VerificationURIComplete, ExpiresIn: payload.ExpiresIn, Interval: payload.Interval}
	if strings.TrimSpace(code.VerificationURI) == "" {
		code.VerificationURI = strings.TrimSpace(code.VerificationURIComplete)
	}
	if code.DeviceCode == "" || code.UserCode == "" || code.VerificationURI == "" {
		return DeviceCode{}, errors.New("xAI device-code response is incomplete")
	}
	// verificationURI is the normalized primary browser link safe to expose through management APIs.
	// verificationURI 是可安全通过管理 API 暴露的规范化主浏览器链接。
	verificationURI, errVerificationURI := providertransport.ValidateAbsoluteHTTPURL(code.VerificationURI)
	if errVerificationURI != nil {
		return DeviceCode{}, fmt.Errorf("validate xAI verification URI: %w", errVerificationURI)
	}
	code.VerificationURI = verificationURI
	if strings.TrimSpace(code.VerificationURIComplete) != "" {
		// verificationURIComplete is the optional normalized prefilled browser link.
		// verificationURIComplete 是可选的规范化预填浏览器链接。
		verificationURIComplete, errVerificationURIComplete := providertransport.ValidateAbsoluteHTTPURL(code.VerificationURIComplete)
		if errVerificationURIComplete != nil {
			return DeviceCode{}, fmt.Errorf("validate xAI complete verification URI: %w", errVerificationURIComplete)
		}
		code.VerificationURIComplete = verificationURIComplete
	}
	if code.Interval <= 0 {
		code.Interval = 5
	}
	code.TokenEndpoint = tokenEndpoint
	return code, nil
}

// Exchange performs one RFC 8628 token poll without blocking the management request.
// Exchange 执行一次 RFC 8628 Token 轮询且不阻塞管理请求。
func (c *DeviceFlowClient) Exchange(ctx context.Context, code DeviceCode) (Token, error) {
	form := url.Values{"grant_type": {deviceCodeGrantType}, "client_id": {oauthClientID}, "device_code": {code.DeviceCode}}
	token, errToken := c.requestToken(ctx, code.TokenEndpoint, form)
	if errToken != nil {
		return Token{}, errToken
	}
	return token, nil
}

// Refresh exchanges one protected refresh token at the discovered trusted endpoint.
// Refresh 在发现的受信任入口交换一个受保护 Refresh Token。
func (c *DeviceFlowClient) Refresh(ctx context.Context, token Token) (Token, error) {
	if errValidate := c.validateRefreshToken(token); errValidate != nil {
		return Token{}, fmt.Errorf("%w: %w", provider.ErrAuthenticationResponseInvalid, errValidate)
	}
	if strings.TrimSpace(token.RefreshToken) == "" {
		return Token{}, fmt.Errorf("%w: xAI credential does not contain a refresh token", provider.ErrAuthenticationRejected)
	}
	form := url.Values{"grant_type": {"refresh_token"}, "client_id": {oauthClientID}, "refresh_token": {token.RefreshToken}}
	refreshed, errRefresh := c.requestToken(ctx, token.TokenEndpoint, form)
	if errRefresh != nil {
		return Token{}, errRefresh
	}
	if refreshed.RefreshToken == "" {
		refreshed.RefreshToken = token.RefreshToken
	}
	if refreshed.IDToken == "" {
		refreshed.IDToken = token.IDToken
	}
	if refreshed.Email == "" {
		refreshed.Email = token.Email
	}
	if refreshed.Subject == "" {
		refreshed.Subject = token.Subject
	}
	if errValidate := c.validateRefreshToken(refreshed); errValidate != nil {
		return Token{}, fmt.Errorf("%w: %w", provider.ErrAuthenticationResponseInvalid, errValidate)
	}
	return refreshed, nil
}

// validateRefreshToken binds refresh requests to the production trust boundary or the exact isolated test endpoint.
// validateRefreshToken 将刷新请求绑定到生产信任边界或精确的隔离测试入口。
func (c *DeviceFlowClient) validateRefreshToken(token Token) error {
	if errValidate := validateTokenFields(token); errValidate != nil {
		return errValidate
	}
	if c.fixedTokenURL != "" {
		if token.TokenEndpoint != c.fixedTokenURL {
			return errors.New("protected xAI token endpoint does not match the configured test endpoint")
		}
		return nil
	}
	_, errEndpoint := validateOAuthEndpoint(token.TokenEndpoint)
	return errEndpoint
}

// endpoints resolves and validates xAI's OIDC endpoints.
// endpoints 解析并校验 xAI 的 OIDC 入口。
func (c *DeviceFlowClient) endpoints(ctx context.Context) (string, string, error) {
	if c.fixedDeviceURL != "" {
		return c.fixedDeviceURL, c.fixedTokenURL, nil
	}
	request, errRequest := http.NewRequestWithContext(ctx, http.MethodGet, c.discoveryURL, nil)
	if errRequest != nil {
		return "", "", fmt.Errorf("create xAI discovery request: %w", errRequest)
	}
	request.Header.Set("Accept", "application/json")
	var discovery xaiDiscoveryResponse
	if errDo := c.doJSON(request, &discovery); errDo != nil {
		return "", "", errDo
	}
	deviceEndpoint, errDevice := validateOAuthEndpoint(discovery.DeviceAuthorizationEndpoint)
	if errDevice != nil {
		return "", "", errDevice
	}
	tokenEndpoint, errToken := validateOAuthEndpoint(discovery.TokenEndpoint)
	if errToken != nil {
		return "", "", errToken
	}
	return deviceEndpoint, tokenEndpoint, nil
}

// requestToken submits one token form and maps RFC 8628 terminal states.
// requestToken 提交一个 Token 表单并映射 RFC 8628 终止状态。
func (c *DeviceFlowClient) requestToken(ctx context.Context, endpoint string, form url.Values) (Token, error) {
	// refreshRequest distinguishes management credential refresh from the RFC 8628 polling path that has its own terminal errors.
	// refreshRequest 区分管理凭据刷新与拥有独立终止错误的 RFC 8628 轮询路径。
	refreshRequest := form.Get("grant_type") == "refresh_token"
	encodedForm := []byte(form.Encode())
	defer clear(encodedForm)
	request, errRequest := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(encodedForm))
	if errRequest != nil {
		return Token{}, fmt.Errorf("create xAI token request: %w", errRequest)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	response, errResponse := c.httpClient.Do(request)
	if errResponse != nil {
		if refreshRequest {
			return Token{}, fmt.Errorf("%w: request xAI token: %w", provider.ErrAuthenticationUnavailable, errResponse)
		}
		return Token{}, fmt.Errorf("request xAI token: %w", errResponse)
	}
	defer response.Body.Close()
	body, errBody := io.ReadAll(io.LimitReader(response.Body, maximumOAuthResponseBytes+1))
	if errBody != nil {
		if refreshRequest {
			return Token{}, fmt.Errorf("%w: read xAI token response: %w", provider.ErrAuthenticationUnavailable, errBody)
		}
		return Token{}, fmt.Errorf("read xAI token response: %w", errBody)
	}
	defer clear(body)
	if len(body) > maximumOAuthResponseBytes {
		if refreshRequest {
			return Token{}, fmt.Errorf("%w: xAI token response exceeds the allowed size", provider.ErrAuthenticationResponseInvalid)
		}
		return Token{}, errors.New("xAI token response exceeds the allowed size")
	}
	if refreshRequest {
		switch {
		case response.StatusCode == http.StatusRequestTimeout || response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= http.StatusInternalServerError:
			return Token{}, fmt.Errorf("%w: xAI token refresh returned status %d", provider.ErrAuthenticationUnavailable, response.StatusCode)
		case response.StatusCode == http.StatusBadRequest || response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden:
			return Token{}, fmt.Errorf("%w: xAI token refresh returned status %d", provider.ErrAuthenticationRejected, response.StatusCode)
		case response.StatusCode != http.StatusOK:
			return Token{}, fmt.Errorf("%w: xAI token refresh returned unexpected status %d", provider.ErrAuthenticationResponseInvalid, response.StatusCode)
		}
	}
	var payload xaiTokenResponse
	if errDecode := json.Unmarshal(body, &payload); errDecode != nil {
		if refreshRequest {
			return Token{}, fmt.Errorf("%w: decode xAI token response: %w", provider.ErrAuthenticationResponseInvalid, errDecode)
		}
		return Token{}, fmt.Errorf("decode xAI token response: %w", errDecode)
	}
	switch payload.Error {
	case "authorization_pending":
		return Token{}, ErrAuthorizationPending
	case "slow_down":
		return Token{}, errAuthorizationSlowDown
	case "expired_token":
		return Token{}, ErrAuthorizationExpired
	case "access_denied":
		return Token{}, ErrAuthorizationDenied
	case "":
	default:
		if refreshRequest {
			return Token{}, fmt.Errorf("%w: xAI OAuth error %s", provider.ErrAuthenticationRejected, payload.Error)
		}
		if strings.TrimSpace(payload.ErrorDescription) != "" {
			return Token{}, fmt.Errorf("xAI OAuth error %s: %s", payload.Error, strings.TrimSpace(payload.ErrorDescription))
		}
		return Token{}, fmt.Errorf("xAI OAuth error %s", payload.Error)
	}
	if response.StatusCode != http.StatusOK || payload.AccessToken == "" {
		if refreshRequest {
			return Token{}, fmt.Errorf("%w: xAI token refresh response omitted its access token", provider.ErrAuthenticationResponseInvalid)
		}
		return Token{}, fmt.Errorf("xAI token request returned status %d", response.StatusCode)
	}
	email, subject := parseJWTIdentity(payload.IDToken)
	expiresAt, errExpiry := tokenExpiry(payload.ExpiresIn)
	if errExpiry != nil {
		if refreshRequest {
			return Token{}, fmt.Errorf("%w: %w", provider.ErrAuthenticationResponseInvalid, errExpiry)
		}
		return Token{}, errExpiry
	}
	return Token{AccessToken: payload.AccessToken, RefreshToken: payload.RefreshToken, IDToken: payload.IDToken, TokenType: payload.TokenType, ExpiresAt: expiresAt, TokenEndpoint: endpoint, Email: email, Subject: subject, Type: "xai"}, nil
}

// parseJWTIdentity copies CLIProxyAPI's unverified display-identity extraction from an already trusted OAuth response.
// parseJWTIdentity 从已受信任 OAuth 响应中复制 CLIProxyAPI 的未验证显示身份提取逻辑。
func parseJWTIdentity(token string) (string, string) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return "", ""
	}
	payload := parts[1] + strings.Repeat("=", (4-len(parts[1])%4)%4)
	raw, errDecode := base64.URLEncoding.DecodeString(payload)
	if errDecode != nil {
		return "", ""
	}
	defer clear(raw)
	var claims struct {
		// Email is the optional account email.
		// Email 是可选账号邮箱。
		Email string `json:"email"`
		// Subject is the optional stable OAuth subject.
		// Subject 是可选稳定 OAuth Subject。
		Subject string `json:"sub"`
	}
	if json.Unmarshal(raw, &claims) != nil {
		return "", ""
	}
	return strings.TrimSpace(claims.Email), strings.TrimSpace(claims.Subject)
}

// tokenExpiry returns zero when xAI omits expiry and rejects values that overflow time.Duration.
// tokenExpiry 在 xAI 省略有效期时返回零，并拒绝会溢出 time.Duration 的值。
func tokenExpiry(expiresIn int) (int64, error) {
	if expiresIn <= 0 {
		return 0, nil
	}
	if int64(expiresIn) > int64(time.Duration(1<<63-1)/time.Second) {
		return 0, errors.New("xAI token response expiry is invalid")
	}
	return time.Now().Add(time.Duration(expiresIn) * time.Second).Unix(), nil
}

// doJSON executes one bounded JSON request and rejects non-success responses.
// doJSON 执行一个有界 JSON 请求并拒绝非成功响应。
func (c *DeviceFlowClient) doJSON(request *http.Request, destination xaiJSONResponse) error {
	response, errResponse := c.httpClient.Do(request)
	if errResponse != nil {
		return fmt.Errorf("request xAI OAuth endpoint: %w", errResponse)
	}
	defer response.Body.Close()
	body, errBody := io.ReadAll(io.LimitReader(response.Body, maximumOAuthResponseBytes+1))
	if errBody != nil {
		return fmt.Errorf("read xAI OAuth response: %w", errBody)
	}
	defer clear(body)
	if len(body) > maximumOAuthResponseBytes {
		return errors.New("xAI OAuth response exceeds the allowed size")
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("xAI OAuth endpoint returned status %d", response.StatusCode)
	}
	if errDecode := json.Unmarshal(body, destination); errDecode != nil {
		return fmt.Errorf("decode xAI OAuth response: %w", errDecode)
	}
	return nil
}

// validateOAuthEndpoint confines discovery results to trusted HTTPS x.ai hosts.
// validateOAuthEndpoint 将发现结果限制在受信任的 HTTPS x.ai 主机。
func validateOAuthEndpoint(raw string) (string, error) {
	parsed, errParse := url.Parse(strings.TrimSpace(raw))
	if errParse != nil || parsed.Scheme != "https" {
		return "", errors.New("xAI discovery endpoint must be a valid HTTPS URL")
	}
	host := strings.ToLower(parsed.Hostname())
	if host != "x.ai" && !strings.HasSuffix(host, ".x.ai") {
		return "", errors.New("xAI discovery endpoint must use an x.ai host")
	}
	return parsed.String(), nil
}

// Flow describes one management-safe xAI authorization session.
// Flow 描述一个管理安全的 xAI 授权会话。
type Flow struct {
	// ID is the local opaque flow identifier.
	// ID 是本地不透明流程标识。
	ID string `json:"id"`
	// UserCode is the provider display code.
	// UserCode 是供应商显示码。
	UserCode string `json:"user_code"`
	// VerificationURI is the provider authorization page.
	// VerificationURI 是供应商授权页面。
	VerificationURI string `json:"verification_uri"`
	// VerificationURIComplete is the optional prefilled page.
	// VerificationURIComplete 是可选预填页面。
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	// ExpiresAt is the local flow expiry.
	// ExpiresAt 是本地流程过期时间。
	ExpiresAt time.Time `json:"expires_at"`
	// PollIntervalSeconds is the minimum provider polling delay in seconds.
	// PollIntervalSeconds 是以秒为单位的供应商最小轮询间隔。
	PollIntervalSeconds int `json:"poll_interval_seconds"`
}

// flowSession owns the provider secret code and polling schedule.
// flowSession 管理供应商秘密码与轮询计划。
type flowSession struct {
	// code is the complete provider device code.
	// code 是完整供应商设备码。
	code DeviceCode
	// flow is the management-safe projection.
	// flow 是管理安全投影。
	flow Flow
	// nextPollAt prevents callers from violating the provider interval.
	// nextPollAt 防止调用方违反供应商轮询间隔。
	nextPollAt time.Time
	// polling leases the provider exchange or completed result to one downstream onboarding request.
	// polling 将供应商交换或已完成结果租给一个下游录入请求。
	polling bool
	// token retains a completed provider result until atomic onboarding succeeds or the session expires.
	// token 在原子录入成功或会话过期前保留已完成的供应商结果。
	token *Token
}

// FlowManager owns bounded in-memory xAI device sessions.
// FlowManager 管理有界的内存 xAI 设备授权会话。
type FlowManager struct {
	// client performs provider exchanges.
	// client 执行供应商交换。
	client *DeviceFlowClient
	// now provides a deterministic clock for expiry and polling checks.
	// now 为过期与轮询检查提供可确定的时钟。
	now func() time.Time
	// mu protects sessions.
	// mu 保护会话。
	mu sync.Mutex
	// sessions stores incomplete flows by local ID.
	// sessions 按本地 ID 存储未完成流程。
	sessions map[string]flowSession
}

// NewFlowManager creates an empty xAI flow manager.
// NewFlowManager 创建空 xAI 授权流程管理器。
func NewFlowManager(client *DeviceFlowClient) (*FlowManager, error) {
	if client == nil {
		return nil, errors.New("xAI device-flow client is required")
	}
	return &FlowManager{client: client, now: time.Now, sessions: make(map[string]flowSession)}, nil
}

// Start creates one provider flow and retains its secret only in memory.
// Start 创建一个供应商流程并仅在内存保留其秘密。
func (m *FlowManager) Start(ctx context.Context) (Flow, error) {
	code, errCode := m.client.Start(ctx)
	if errCode != nil {
		return Flow{}, errCode
	}
	flowID, errID := randomIdentifier(16)
	if errID != nil {
		return Flow{}, errID
	}
	now := m.now().UTC()
	interval := xaiPollInterval(code.Interval)
	lifetime := xaiFlowLifetime(code.ExpiresIn)
	expiresAt := now.Add(lifetime)
	flow := Flow{ID: flowID, UserCode: code.UserCode, VerificationURI: code.VerificationURI, VerificationURIComplete: code.VerificationURIComplete, ExpiresAt: expiresAt, PollIntervalSeconds: int(interval / time.Second)}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneExpiredLocked(now)
	if len(m.sessions) >= maximumFlowSessions {
		return Flow{}, ErrFlowLimitReached
	}
	m.sessions[flowID] = flowSession{code: code, flow: flow, nextPollAt: now}
	return flow, nil
}

// xaiFlowLifetime bounds provider seconds before duration conversion so oversized values cannot wrap into an expired session.
// xaiFlowLifetime 在转换为 Duration 前限制供应商秒数，避免超大值回绕成已过期会话。
func xaiFlowLifetime(expiresIn int) time.Duration {
	if expiresIn <= 0 || int64(expiresIn) >= int64(maximumFlowLifetime/time.Second) {
		return maximumFlowLifetime
	}
	return time.Duration(expiresIn) * time.Second
}

// xaiPollInterval preserves the provider minimum while bounding integer conversion to the local session lifetime.
// xaiPollInterval 保留供应商最小轮询间隔，同时将整数转换限制在本地会话生命周期内。
func xaiPollInterval(intervalSeconds int) time.Duration {
	if intervalSeconds <= int(defaultPollInterval/time.Second) {
		return defaultPollInterval
	}
	if int64(intervalSeconds) >= int64(maximumFlowLifetime/time.Second) {
		return maximumFlowLifetime
	}
	return time.Duration(intervalSeconds) * time.Second
}

// Poll performs at most one provider exchange and retains successful results until explicit consumption.
// Poll 最多执行一次供应商交换，并在显式消费前保留成功结果。
func (m *FlowManager) Poll(ctx context.Context, flowID string) (Token, error) {
	now := m.now().UTC()
	m.mu.Lock()
	m.pruneExpiredLocked(now)
	session, exists := m.sessions[flowID]
	if !exists {
		m.mu.Unlock()
		return Token{}, ErrFlowNotFound
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
	token, errToken := m.client.Exchange(ctx, session.code)
	if errToken != nil {
		if errors.Is(errToken, errAuthorizationSlowDown) {
			m.mu.Lock()
			current, stillExists := m.sessions[flowID]
			if stillExists {
				current.polling = false
				current.flow.PollIntervalSeconds = xaiSlowDownInterval(current.flow.PollIntervalSeconds)
				current.nextPollAt = m.now().UTC().Add(time.Duration(current.flow.PollIntervalSeconds) * time.Second)
				m.sessions[flowID] = current
			}
			m.mu.Unlock()
		}
		if errors.Is(errToken, ErrAuthorizationExpired) || errors.Is(errToken, ErrAuthorizationDenied) {
			m.Cancel(flowID)
		} else if !errors.Is(errToken, errAuthorizationSlowDown) {
			m.mu.Lock()
			current, stillExists := m.sessions[flowID]
			if stillExists && current.token == nil {
				current.polling = false
				m.sessions[flowID] = current
			}
			m.mu.Unlock()
		}
		return Token{}, errToken
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

// xaiSlowDownInterval applies RFC 8628 slow-down increments without exceeding the bounded flow lifetime.
// xaiSlowDownInterval 应用 RFC 8628 减速增量且不超过有界流程生命周期。
func xaiSlowDownInterval(currentSeconds int) int {
	maximumSeconds := int(maximumFlowLifetime / time.Second)
	incrementSeconds := int(defaultPollInterval / time.Second)
	if currentSeconds >= maximumSeconds-incrementSeconds {
		return maximumSeconds
	}
	return currentSeconds + incrementSeconds
}

// Cancel consumes one incomplete or completed local xAI authorization session.
// Cancel 消费一个未完成或已完成的本地 xAI 授权会话。
func (m *FlowManager) Cancel(flowID string) {
	m.mu.Lock()
	delete(m.sessions, flowID)
	m.mu.Unlock()
}

// pruneExpiredLocked removes expired sessions while the caller owns the lock.
// pruneExpiredLocked 在调用方持锁时删除已过期会话。
func (m *FlowManager) pruneExpiredLocked(now time.Time) {
	for flowID, session := range m.sessions {
		if !session.flow.ExpiresAt.After(now) {
			delete(m.sessions, flowID)
		}
	}
}

// MarshalToken serializes one validated protected xAI token document.
// MarshalToken 序列化一个经过校验的受保护 xAI Token 文档。
func MarshalToken(token Token) ([]byte, error) {
	if errValidate := validateToken(token); errValidate != nil {
		return nil, errValidate
	}
	return json.Marshal(token)
}

// UnmarshalToken parses one protected xAI token document.
// UnmarshalToken 解析一个受保护 xAI Token 文档。
func UnmarshalToken(value []byte) (Token, error) {
	var token Token
	if errDecode := json.Unmarshal(value, &token); errDecode != nil {
		return Token{}, errors.New("protected xAI credential is not a token document")
	}
	if errValidate := validateToken(token); errValidate != nil {
		return Token{}, errValidate
	}
	return token, nil
}

// validateToken enforces the usable xAI credential boundary while treating refresh support as optional.
// validateToken 强制执行可用 xAI 凭据边界，同时将刷新能力视为可选项。
func validateToken(token Token) error {
	if errValidate := validateTokenFields(token); errValidate != nil {
		return errValidate
	}
	if _, errEndpoint := validateOAuthEndpoint(token.TokenEndpoint); errEndpoint != nil {
		return fmt.Errorf("protected xAI token endpoint is invalid: %w", errEndpoint)
	}
	return nil
}

// validateTokenFields enforces provider identity and required secret fields independently from endpoint ownership.
// validateTokenFields 独立于入口归属强制执行供应商身份与必需秘密字段。
func validateTokenFields(token Token) error {
	if strings.TrimSpace(token.AccessToken) == "" || strings.TrimSpace(token.TokenEndpoint) == "" || token.Type != "xai" {
		return errors.New("protected xAI token document is incomplete")
	}
	return nil
}

// randomIdentifier generates an opaque identifier using operating-system entropy.
// randomIdentifier 使用操作系统熵生成不透明标识。
func randomIdentifier(size int) (string, error) {
	buffer := make([]byte, size)
	if _, errRead := rand.Read(buffer); errRead != nil {
		return "", fmt.Errorf("generate xAI flow identifier: %w", errRead)
	}
	return hex.EncodeToString(buffer), nil
}
