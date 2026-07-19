package google

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
	"strings"
	"sync"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	providertransport "github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
)

const (
	// antigravityOAuthClientID is copied from CLIProxyAPI's Antigravity authenticator.
	// antigravityOAuthClientID 从 CLIProxyAPI Antigravity 认证器复制。
	antigravityOAuthClientID = "1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com"
	// antigravityOAuthClientSecret is the public installed-application secret copied from CLIProxyAPI.
	// antigravityOAuthClientSecret 是从 CLIProxyAPI 复制的公开已安装应用 Secret。
	antigravityOAuthClientSecret = "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"
	// antigravityAuthEndpoint is Google's authorization endpoint.
	// antigravityAuthEndpoint 是 Google 授权入口。
	antigravityAuthEndpoint = "https://accounts.google.com/o/oauth2/v2/auth"
	// antigravityTokenEndpoint is Google's token endpoint.
	// antigravityTokenEndpoint 是 Google Token 入口。
	antigravityTokenEndpoint = "https://oauth2.googleapis.com/token"
	// antigravityUserInfoEndpoint returns the authenticated email.
	// antigravityUserInfoEndpoint 返回已认证邮箱。
	antigravityUserInfoEndpoint = "https://www.googleapis.com/oauth2/v2/userinfo?alt=json"
	// antigravityRedirectURI is the exact registered desktop callback copied from CLIProxyAPI.
	// antigravityRedirectURI 是从 CLIProxyAPI 复制的精确已注册桌面回调。
	antigravityRedirectURI = "http://localhost:51121/oauth-callback"
	// antigravityAPIEndpoint serves loadCodeAssist.
	// antigravityAPIEndpoint 提供 loadCodeAssist。
	antigravityAPIEndpoint = "https://cloudcode-pa.googleapis.com"
	// antigravityDailyAPIEndpoint serves onboardUser.
	// antigravityDailyAPIEndpoint 提供 onboardUser。
	antigravityDailyAPIEndpoint = "https://daily-cloudcode-pa.googleapis.com"
	// antigravityFlowLifetime bounds incomplete browser authorization state.
	// antigravityFlowLifetime 限制未完成浏览器授权状态生命周期。
	antigravityFlowLifetime = 10 * time.Minute
	// maximumAntigravityFlows bounds concurrent incomplete browser flows.
	// maximumAntigravityFlows 限制并发未完成浏览器授权流程数量。
	maximumAntigravityFlows = 64
)

var (
	// antigravityScopes preserves CLIProxyAPI's exact ordered Google consent scope set.
	// antigravityScopes 保留 CLIProxyAPI 精确且有序的 Google 同意授权 Scope 集合。
	antigravityScopes = []string{
		"https://www.googleapis.com/auth/cloud-platform",
		"https://www.googleapis.com/auth/userinfo.email",
		"https://www.googleapis.com/auth/userinfo.profile",
		"https://www.googleapis.com/auth/cclog",
		"https://www.googleapis.com/auth/experimentsandconfigs",
	}
)

var (
	// ErrAntigravityFlowNotFound reports an unknown or expired local OAuth flow.
	// ErrAntigravityFlowNotFound 表示本地 OAuth 流程不存在或已过期。
	ErrAntigravityFlowNotFound = errors.New("Antigravity OAuth flow not found")
	// ErrAntigravityFlowLimitReached reports excessive incomplete OAuth flows.
	// ErrAntigravityFlowLimitReached 表示未完成 OAuth 流程过多。
	ErrAntigravityFlowLimitReached = errors.New("Antigravity OAuth flow limit reached")
	// ErrAntigravityFlowInProgress reports a duplicate completion request while the provider exchange is active.
	// ErrAntigravityFlowInProgress 表示供应商交换进行中收到重复完成请求。
	ErrAntigravityFlowInProgress = errors.New("Antigravity OAuth flow completion is in progress")
)

// AntigravityOAuthFlow contains the public authorization URL and local opaque identifier.
// AntigravityOAuthFlow 包含公共授权 URL 与本地不透明标识。
type AntigravityOAuthFlow struct {
	// ID identifies the server-owned state document.
	// ID 标识服务端拥有的状态文档。
	ID string `json:"id"`
	// AuthorizationURL opens Google's consent flow.
	// AuthorizationURL 打开 Google 同意授权流程。
	AuthorizationURL string `json:"authorization_url"`
	// RedirectURI tells the user which failed local callback URL must be pasted when no callback listener exists.
	// RedirectURI 告知用户在没有回调监听器时需要粘贴哪个失败的本地回调 URL。
	RedirectURI string `json:"redirect_uri"`
	// ExpiresAt is the local authorization expiry.
	// ExpiresAt 是本地授权过期时间。
	ExpiresAt time.Time `json:"expires_at"`
}

// antigravityOAuthSession owns the CSRF state hidden from management clients.
// antigravityOAuthSession 管理对管理客户端隐藏的 CSRF State。
type antigravityOAuthSession struct {
	// flow is the management-safe projection.
	// flow 是管理安全投影。
	flow AntigravityOAuthFlow
	// state is the exact CSRF value sent to Google.
	// state 是发送给 Google 的精确 CSRF 值。
	state string
	// token retains a completed provider result until atomic onboarding succeeds or the session expires.
	// token 在原子录入成功或会话过期前保留已完成的供应商结果。
	token *AntigravityToken
	// completing leases the provider exchange or completed result to one downstream onboarding request.
	// completing 将供应商交换或已完成结果租给一个下游录入请求。
	completing bool
}

// AntigravityOAuthClient performs Google OAuth, identity, and project provisioning calls.
// AntigravityOAuthClient 执行 Google OAuth、身份与项目配置调用。
type AntigravityOAuthClient struct {
	// httpClient executes bounded upstream calls.
	// httpClient 执行有界上游调用。
	httpClient *http.Client
	// tokenEndpoint is the production endpoint or an explicit test endpoint.
	// tokenEndpoint 是生产入口或显式测试入口。
	tokenEndpoint string
	// userInfoEndpoint is the production endpoint or an explicit test endpoint.
	// userInfoEndpoint 是生产入口或显式测试入口。
	userInfoEndpoint string
	// apiEndpoint is the production Cloud Code base or an explicit test base.
	// apiEndpoint 是生产 Cloud Code 基础地址或显式测试基础地址。
	apiEndpoint string
	// dailyAPIEndpoint is the production onboarding base or an explicit test base.
	// dailyAPIEndpoint 是生产录入基础地址或显式测试基础地址。
	dailyAPIEndpoint string
}

// NewAntigravityOAuthClient creates a production Antigravity OAuth client.
// NewAntigravityOAuthClient 创建生产 Antigravity OAuth 客户端。
func NewAntigravityOAuthClient(httpClient *http.Client) (*AntigravityOAuthClient, error) {
	return NewAntigravityOAuthClientWithEndpoints(httpClient, antigravityTokenEndpoint, antigravityUserInfoEndpoint, antigravityAPIEndpoint, antigravityDailyAPIEndpoint)
}

// NewAntigravityOAuthClientWithEndpoints creates an isolated client for deterministic tests.
// NewAntigravityOAuthClientWithEndpoints 为确定性测试创建隔离客户端。
func NewAntigravityOAuthClientWithEndpoints(httpClient *http.Client, tokenEndpoint string, userInfoEndpoint string, apiEndpoint string, dailyAPIEndpoint string) (*AntigravityOAuthClient, error) {
	if httpClient == nil || strings.TrimSpace(tokenEndpoint) == "" || strings.TrimSpace(userInfoEndpoint) == "" || strings.TrimSpace(apiEndpoint) == "" || strings.TrimSpace(dailyAPIEndpoint) == "" {
		return nil, errors.New("Antigravity OAuth HTTP client and endpoints are required")
	}
	return &AntigravityOAuthClient{httpClient: providertransport.CloneHTTPClientWithoutRedirects(httpClient), tokenEndpoint: tokenEndpoint, userInfoEndpoint: userInfoEndpoint, apiEndpoint: strings.TrimRight(apiEndpoint, "/"), dailyAPIEndpoint: strings.TrimRight(dailyAPIEndpoint, "/")}, nil
}

// AuthorizationURL builds the exact offline-consent URL copied from CLIProxyAPI.
// AuthorizationURL 构建从 CLIProxyAPI 复制的精确离线同意授权 URL。
func (c *AntigravityOAuthClient) AuthorizationURL(state string) string {
	parameters := url.Values{"access_type": {"offline"}, "client_id": {antigravityOAuthClientID}, "prompt": {"consent"}, "redirect_uri": {antigravityRedirectURI}, "response_type": {"code"}, "scope": {strings.Join(antigravityScopes, " ")}, "state": {state}}
	return antigravityAuthEndpoint + "?" + parameters.Encode()
}

// ExchangeCallback validates one pasted local callback and constructs the complete protected token document.
// ExchangeCallback 校验一个粘贴的本地回调并构建完整受保护 Token 文档。
func (c *AntigravityOAuthClient) ExchangeCallback(ctx context.Context, callbackURL string, expectedState string) (AntigravityToken, error) {
	code, errCallback := parseAntigravityCallback(callbackURL, expectedState)
	if errCallback != nil {
		return AntigravityToken{}, errCallback
	}
	tokenResponse, errToken := c.requestToken(ctx, url.Values{"code": {code}, "client_id": {antigravityOAuthClientID}, "client_secret": {antigravityOAuthClientSecret}, "redirect_uri": {antigravityRedirectURI}, "grant_type": {"authorization_code"}})
	if errToken != nil {
		return AntigravityToken{}, errToken
	}
	if strings.TrimSpace(tokenResponse.RefreshToken) == "" {
		return AntigravityToken{}, errors.New("Antigravity OAuth response did not include a refresh token")
	}
	email, errEmail := c.fetchUserInfo(ctx, tokenResponse.AccessToken)
	if errEmail != nil {
		return AntigravityToken{}, errEmail
	}
	projectID, errProject := c.fetchProjectID(ctx, tokenResponse.AccessToken)
	if errProject != nil {
		return AntigravityToken{}, errProject
	}
	expiresAt, errExpiry := antigravityTokenExpiry(tokenResponse.ExpiresIn)
	if errExpiry != nil {
		return AntigravityToken{}, errExpiry
	}
	token := AntigravityToken{AccessToken: tokenResponse.AccessToken, RefreshToken: tokenResponse.RefreshToken, TokenType: tokenResponse.TokenType, Email: email, ProjectID: projectID, ExpiresAt: expiresAt, Type: "antigravity"}
	if errValidate := validateAntigravityToken(token); errValidate != nil {
		return AntigravityToken{}, errValidate
	}
	return token, nil
}

// Refresh exchanges one protected Google refresh token while preserving identity and project scope.
// Refresh 交换一个受保护 Google Refresh Token，同时保留身份与项目作用域。
func (c *AntigravityOAuthClient) Refresh(ctx context.Context, token AntigravityToken) (AntigravityToken, error) {
	if errValidate := validateAntigravityToken(token); errValidate != nil {
		return AntigravityToken{}, errValidate
	}
	response, errRefresh := c.requestToken(ctx, url.Values{"client_id": {antigravityOAuthClientID}, "client_secret": {antigravityOAuthClientSecret}, "grant_type": {"refresh_token"}, "refresh_token": {token.RefreshToken}})
	if errRefresh != nil {
		return AntigravityToken{}, errRefresh
	}
	expiresAt, errExpiry := antigravityTokenExpiry(response.ExpiresIn)
	if errExpiry != nil {
		return AntigravityToken{}, fmt.Errorf("%w: %w", provider.ErrAuthenticationResponseInvalid, errExpiry)
	}
	refreshed := AntigravityToken{AccessToken: response.AccessToken, RefreshToken: response.RefreshToken, TokenType: response.TokenType, Email: token.Email, ProjectID: token.ProjectID, ExpiresAt: expiresAt, Type: "antigravity"}
	if refreshed.RefreshToken == "" {
		refreshed.RefreshToken = token.RefreshToken
	}
	if errValidate := validateAntigravityToken(refreshed); errValidate != nil {
		return AntigravityToken{}, fmt.Errorf("%w: %w", provider.ErrAuthenticationResponseInvalid, errValidate)
	}
	return refreshed, nil
}

// antigravityTokenResponse is Google's exact OAuth response subset.
// antigravityTokenResponse 是 Google OAuth 响应的精确字段子集。
type antigravityTokenResponse struct {
	// AccessToken authenticates provider calls.
	// AccessToken 用于认证供应商调用。
	AccessToken string `json:"access_token"`
	// RefreshToken refreshes provider access.
	// RefreshToken 用于刷新供应商访问权。
	RefreshToken string `json:"refresh_token"`
	// ExpiresIn is the access-token lifetime.
	// ExpiresIn 是 Access Token 有效期。
	ExpiresIn int64 `json:"expires_in"`
	// TokenType is Google's token type.
	// TokenType 是 Google Token 类型。
	TokenType string `json:"token_type"`
}

// requestToken submits one exact Google OAuth form.
// requestToken 提交一个精确 Google OAuth 表单。
func (c *AntigravityOAuthClient) requestToken(ctx context.Context, form url.Values) (antigravityTokenResponse, error) {
	// refreshRequest confines management error classification to the exact refresh-token grant.
	// refreshRequest 将管理错误分类限制在精确的 Refresh Token Grant。
	refreshRequest := form.Get("grant_type") == "refresh_token"
	// encodedForm is mutable so authorization codes and refresh tokens can be cleared after request construction.
	// encodedForm 可变，因此授权码与 Refresh Token 可在请求构造后清除。
	encodedForm := []byte(form.Encode())
	defer clear(encodedForm)
	request, errRequest := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenEndpoint, bytes.NewReader(encodedForm))
	if errRequest != nil {
		return antigravityTokenResponse{}, fmt.Errorf("create Antigravity token request: %w", errRequest)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if form.Get("grant_type") == "refresh_token" {
		// Google refresh calls copy Antigravity's explicit OAuth host and Go HTTP/2 user-agent fingerprint.
		// Google 刷新调用复制 Antigravity 显式 OAuth Host 与 Go HTTP/2 User-Agent 指纹。
		request.Header.Set("Host", "oauth2.googleapis.com")
		request.Header.Set("User-Agent", "Go-http-client/2.0")
	}
	response, errResponse := c.httpClient.Do(request)
	if errResponse != nil {
		if refreshRequest {
			return antigravityTokenResponse{}, fmt.Errorf("%w: execute Antigravity token request: %w", provider.ErrAuthenticationUnavailable, errResponse)
		}
		return antigravityTokenResponse{}, fmt.Errorf("execute Antigravity token request: %w", errResponse)
	}
	body, _, errBody := readAndCloseAntigravityResponse(response)
	if errBody != nil {
		if refreshRequest {
			return antigravityTokenResponse{}, fmt.Errorf("%w: read Antigravity token response: %w", provider.ErrAuthenticationUnavailable, errBody)
		}
		return antigravityTokenResponse{}, fmt.Errorf("read Antigravity token response: %w", errBody)
	}
	defer clear(body)
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		if refreshRequest {
			switch {
			case response.StatusCode == http.StatusRequestTimeout || response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= http.StatusInternalServerError:
				return antigravityTokenResponse{}, fmt.Errorf("%w: Antigravity token refresh returned status %d", provider.ErrAuthenticationUnavailable, response.StatusCode)
			case response.StatusCode == http.StatusBadRequest || response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden:
				return antigravityTokenResponse{}, fmt.Errorf("%w: Antigravity token refresh returned status %d", provider.ErrAuthenticationRejected, response.StatusCode)
			default:
				return antigravityTokenResponse{}, fmt.Errorf("%w: Antigravity token refresh returned unexpected status %d", provider.ErrAuthenticationResponseInvalid, response.StatusCode)
			}
		}
		return antigravityTokenResponse{}, fmt.Errorf("Antigravity token request returned status %d", response.StatusCode)
	}
	var token antigravityTokenResponse
	if errDecode := json.Unmarshal(body, &token); errDecode != nil {
		if refreshRequest {
			return antigravityTokenResponse{}, fmt.Errorf("%w: decode Antigravity token response: %w", provider.ErrAuthenticationResponseInvalid, errDecode)
		}
		return antigravityTokenResponse{}, fmt.Errorf("decode Antigravity token response: %w", errDecode)
	}
	if strings.TrimSpace(token.AccessToken) == "" {
		if refreshRequest {
			return antigravityTokenResponse{}, fmt.Errorf("%w: Antigravity token response is incomplete", provider.ErrAuthenticationResponseInvalid)
		}
		return antigravityTokenResponse{}, errors.New("Antigravity token response is incomplete")
	}
	return token, nil
}

// fetchUserInfo retrieves the authenticated Google email copied by CLIProxyAPI.
// fetchUserInfo 获取 CLIProxyAPI 复制的已认证 Google 邮箱。
func (c *AntigravityOAuthClient) fetchUserInfo(ctx context.Context, accessToken string) (string, error) {
	request, errRequest := http.NewRequestWithContext(ctx, http.MethodGet, c.userInfoEndpoint, nil)
	if errRequest != nil {
		return "", fmt.Errorf("create Antigravity userinfo request: %w", errRequest)
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.Header.Set("User-Agent", AntigravityRequestUserAgent(""))
	response, errResponse := c.httpClient.Do(request)
	if errResponse != nil {
		return "", fmt.Errorf("execute Antigravity userinfo request: %w", errResponse)
	}
	body, statusCode, errBody := readAndCloseAntigravityResponse(response)
	if errBody != nil {
		return "", fmt.Errorf("read Antigravity userinfo response: %w", errBody)
	}
	defer clear(body)
	if statusCode < http.StatusOK || statusCode >= http.StatusMultipleChoices {
		return "", fmt.Errorf("Antigravity userinfo returned status %d", statusCode)
	}
	var payload struct {
		// Email is the verified Google account email.
		// Email 是已验证 Google 账号邮箱。
		Email string `json:"email"`
	}
	if errDecode := json.Unmarshal(body, &payload); errDecode != nil {
		return "", fmt.Errorf("decode Antigravity userinfo response: %w", errDecode)
	}
	if strings.TrimSpace(payload.Email) == "" {
		return "", errors.New("Antigravity userinfo response did not include email")
	}
	return strings.TrimSpace(payload.Email), nil
}

// fetchProjectID copies CLIProxyAPI's loadCodeAssist lookup and onboardUser fallback.
// fetchProjectID 复制 CLIProxyAPI 的 loadCodeAssist 查询与 onboardUser 回退。
func (c *AntigravityOAuthClient) fetchProjectID(ctx context.Context, accessToken string) (string, error) {
	requestBody, errBody := json.Marshal(map[string]any{"metadata": map[string]string{"ideType": "ANTIGRAVITY"}})
	if errBody != nil {
		return "", fmt.Errorf("marshal Antigravity loadCodeAssist request: %w", errBody)
	}
	request, errRequest := http.NewRequestWithContext(ctx, http.MethodPost, c.apiEndpoint+"/v1internal:loadCodeAssist", bytes.NewReader(requestBody))
	if errRequest != nil {
		return "", fmt.Errorf("create Antigravity loadCodeAssist request: %w", errRequest)
	}
	setAntigravityControlHeaders(request, accessToken, AntigravityLoadCodeAssistUserAgent(""))
	response, errResponse := c.httpClient.Do(request)
	if errResponse != nil {
		return "", fmt.Errorf("execute Antigravity loadCodeAssist request: %w", errResponse)
	}
	body, statusCode, errRead := readAndCloseAntigravityResponse(response)
	if errRead != nil {
		return "", errRead
	}
	if statusCode < http.StatusOK || statusCode >= http.StatusMultipleChoices {
		return "", fmt.Errorf("Antigravity loadCodeAssist returned status %d", statusCode)
	}
	var payload map[string]any
	if errDecode := json.Unmarshal(body, &payload); errDecode != nil {
		return "", fmt.Errorf("decode Antigravity loadCodeAssist response: %w", errDecode)
	}
	if projectID := extractAntigravityProject(payload); projectID != "" {
		return projectID, nil
	}
	return c.onboardUser(ctx, accessToken, defaultAntigravityTier(payload))
}

// onboardUser copies CLIProxyAPI's five-attempt project provisioning poll.
// onboardUser 复制 CLIProxyAPI 的五次项目配置轮询。
func (c *AntigravityOAuthClient) onboardUser(ctx context.Context, accessToken string, tierID string) (string, error) {
	userAgent := AntigravityOnboardUserUserAgent("")
	requestBody, errBody := json.Marshal(map[string]any{"tier_id": tierID, "metadata": map[string]string{"ide_type": "ANTIGRAVITY", "ide_version": AntigravityVersionFromUserAgent(userAgent), "ide_name": "antigravity"}})
	if errBody != nil {
		return "", fmt.Errorf("marshal Antigravity onboardUser request: %w", errBody)
	}
	for attempt := 1; attempt <= 5; attempt++ {
		requestContext, cancel := context.WithTimeout(ctx, 30*time.Second)
		request, errRequest := http.NewRequestWithContext(requestContext, http.MethodPost, c.dailyAPIEndpoint+"/v1internal:onboardUser", bytes.NewReader(requestBody))
		if errRequest != nil {
			cancel()
			return "", fmt.Errorf("create Antigravity onboardUser request: %w", errRequest)
		}
		setAntigravityControlHeaders(request, accessToken, userAgent)
		request.Header.Set("X-Goog-Api-Client", antigravityGoogAPIClientUA)
		response, errResponse := c.httpClient.Do(request)
		if errResponse != nil {
			cancel()
			return "", fmt.Errorf("execute Antigravity onboardUser request: %w", errResponse)
		}
		body, statusCode, errRead := readAndCloseAntigravityResponse(response)
		cancel()
		if errRead != nil {
			return "", errRead
		}
		if statusCode != http.StatusOK {
			return "", fmt.Errorf("Antigravity onboardUser returned status %d", statusCode)
		}
		var payload map[string]any
		if errDecode := json.Unmarshal(body, &payload); errDecode != nil {
			return "", fmt.Errorf("decode Antigravity onboardUser response: %w", errDecode)
		}
		if done, isDone := payload["done"].(bool); isDone && done {
			responsePayload, hasResponse := payload["response"].(map[string]any)
			if !hasResponse {
				return "", errors.New("Antigravity onboardUser response is missing the completed payload")
			}
			projectID := extractAntigravityProject(responsePayload)
			if projectID == "" {
				return "", errors.New("Antigravity onboardUser response did not include project id")
			}
			return projectID, nil
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return "", errors.New("Antigravity onboardUser did not complete after 5 attempts")
}

// setAntigravityControlHeaders applies the copied control-plane headers.
// setAntigravityControlHeaders 应用复制的控制面请求头。
func setAntigravityControlHeaders(request *http.Request, accessToken string, userAgent string) {
	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.Header.Set("Accept", "*/*")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", userAgent)
}

// readAndCloseAntigravityResponse bounds and closes one provider response.
// readAndCloseAntigravityResponse 限制并关闭一个供应商响应。
func readAndCloseAntigravityResponse(response *http.Response) ([]byte, int, error) {
	defer response.Body.Close()
	body, errBody := io.ReadAll(io.LimitReader(response.Body, antigravityControlResponseLimit+1))
	if errBody != nil {
		return nil, 0, fmt.Errorf("read Antigravity response: %w", errBody)
	}
	if len(body) > antigravityControlResponseLimit {
		clear(body)
		return nil, 0, errors.New("Antigravity response exceeds the response limit")
	}
	return body, response.StatusCode, nil
}

// extractAntigravityProject preserves CLIProxyAPI's three documented project response shapes.
// extractAntigravityProject 保留 CLIProxyAPI 记录的三种项目响应形态。
func extractAntigravityProject(payload map[string]any) string {
	for _, key := range []string{"cloudaicompanionProject", "projectId", "project"} {
		switch value := payload[key].(type) {
		case string:
			if trimmed := strings.TrimSpace(value); trimmed != "" {
				return trimmed
			}
		case map[string]any:
			if identifier, exists := value["id"].(string); exists && strings.TrimSpace(identifier) != "" {
				return strings.TrimSpace(identifier)
			}
		}
	}
	return ""
}

// defaultAntigravityTier preserves CLIProxyAPI's default-tier selection order.
// defaultAntigravityTier 保留 CLIProxyAPI 的默认套餐选择顺序。
func defaultAntigravityTier(payload map[string]any) string {
	if tiers, exists := payload["allowedTiers"].([]any); exists {
		for _, rawTier := range tiers {
			tier, validTier := rawTier.(map[string]any)
			if !validTier {
				continue
			}
			isDefault, validDefault := tier["isDefault"].(bool)
			identifier, validIdentifier := tier["id"].(string)
			if validDefault && isDefault && validIdentifier && strings.TrimSpace(identifier) != "" {
				return strings.TrimSpace(identifier)
			}
		}
	}
	if currentTier, exists := payload["currentTier"].(map[string]any); exists {
		if identifier, validIdentifier := currentTier["id"].(string); validIdentifier && strings.TrimSpace(identifier) != "" {
			return strings.TrimSpace(identifier)
		}
	}
	return "free-tier"
}

// parseAntigravityCallback validates the exact registered redirect, CSRF state, and authorization result.
// parseAntigravityCallback 校验精确已注册重定向、CSRF State 与授权结果。
func parseAntigravityCallback(rawCallback string, expectedState string) (string, error) {
	parsed, errParse := url.Parse(strings.TrimSpace(rawCallback))
	if errParse != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.Fragment != "" || !strings.EqualFold(parsed.Hostname(), "localhost") || parsed.Port() != "51121" || parsed.EscapedPath() != "/oauth-callback" {
		return "", errors.New("Antigravity callback must use the registered localhost redirect URI")
	}
	query := parsed.Query()
	if len(query["error"]) > 1 || len(query["state"]) != 1 {
		return "", errors.New("Antigravity callback must contain one state")
	}
	if providerError := strings.TrimSpace(query.Get("error")); providerError != "" {
		return "", fmt.Errorf("Antigravity OAuth returned %s", providerError)
	}
	if query.Get("state") != expectedState {
		return "", errors.New("Antigravity OAuth state mismatch")
	}
	if len(query["code"]) != 1 {
		return "", errors.New("Antigravity callback must contain one authorization code")
	}
	code := strings.TrimSpace(query.Get("code"))
	if code == "" {
		return "", errors.New("Antigravity callback did not include an authorization code")
	}
	return code, nil
}

// AntigravityFlowManager owns bounded server-side OAuth state documents.
// AntigravityFlowManager 管理有界的服务端 OAuth 状态文档。
type AntigravityFlowManager struct {
	// client builds URLs and completes provider exchanges.
	// client 构建 URL 并完成供应商交换。
	client *AntigravityOAuthClient
	// now provides deterministic expiry checks.
	// now 提供可确定的过期检查。
	now func() time.Time
	// mu protects sessions.
	// mu 保护会话。
	mu sync.Mutex
	// sessions stores incomplete flows by opaque ID.
	// sessions 按不透明 ID 存储未完成流程。
	sessions map[string]antigravityOAuthSession
}

// NewAntigravityFlowManager creates an empty Antigravity OAuth manager.
// NewAntigravityFlowManager 创建空 Antigravity OAuth 管理器。
func NewAntigravityFlowManager(client *AntigravityOAuthClient) (*AntigravityFlowManager, error) {
	if client == nil {
		return nil, errors.New("Antigravity OAuth client is required")
	}
	return &AntigravityFlowManager{client: client, now: time.Now, sessions: make(map[string]antigravityOAuthSession)}, nil
}

// Start creates one authorization URL and retains the CSRF state only in memory.
// Start 创建一个授权 URL 并仅在内存保留 CSRF State。
func (m *AntigravityFlowManager) Start(ctx context.Context) (AntigravityOAuthFlow, error) {
	if errContext := ctx.Err(); errContext != nil {
		return AntigravityOAuthFlow{}, errContext
	}
	flowID, errFlowID := randomAntigravityIdentifier(16)
	if errFlowID != nil {
		return AntigravityOAuthFlow{}, errFlowID
	}
	state, errState := randomAntigravityIdentifier(32)
	if errState != nil {
		return AntigravityOAuthFlow{}, errState
	}
	now := m.now().UTC()
	flow := AntigravityOAuthFlow{ID: flowID, AuthorizationURL: m.client.AuthorizationURL(state), RedirectURI: antigravityRedirectURI, ExpiresAt: now.Add(antigravityFlowLifetime)}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneExpiredLocked(now)
	if len(m.sessions) >= maximumAntigravityFlows {
		return AntigravityOAuthFlow{}, ErrAntigravityFlowLimitReached
	}
	m.sessions[flowID] = antigravityOAuthSession{flow: flow, state: state}
	return flow, nil
}

// Complete validates one callback and retains the result until explicit onboarding consumption.
// Complete 校验一个回调，并在录入流程显式消费前保留结果。
func (m *AntigravityFlowManager) Complete(ctx context.Context, flowID string, callbackURL string) (AntigravityToken, error) {
	now := m.now().UTC()
	m.mu.Lock()
	m.pruneExpiredLocked(now)
	session, exists := m.sessions[flowID]
	if !exists {
		m.mu.Unlock()
		return AntigravityToken{}, ErrAntigravityFlowNotFound
	}
	if session.completing {
		m.mu.Unlock()
		return AntigravityToken{}, ErrAntigravityFlowInProgress
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
	token, errToken := m.client.ExchangeCallback(ctx, callbackURL, session.state)
	if errToken != nil {
		m.mu.Lock()
		current, stillExists := m.sessions[flowID]
		if stillExists {
			current.completing = false
			m.sessions[flowID] = current
		}
		m.mu.Unlock()
		return AntigravityToken{}, errToken
	}
	m.mu.Lock()
	current, stillExists := m.sessions[flowID]
	if !stillExists {
		m.mu.Unlock()
		return AntigravityToken{}, ErrAntigravityFlowNotFound
	}
	if !m.now().UTC().Before(current.flow.ExpiresAt) {
		delete(m.sessions, flowID)
		m.mu.Unlock()
		return AntigravityToken{}, ErrAntigravityFlowNotFound
	}
	current.token = &token
	m.sessions[flowID] = current
	m.mu.Unlock()
	return token, nil
}

// Release returns one delivered completed token to the session after downstream onboarding fails.
// Release 在下游录入失败后将一个已交付的完成 Token 归还会话。
func (m *AntigravityFlowManager) Release(flowID string) {
	m.mu.Lock()
	session, exists := m.sessions[flowID]
	if exists && session.token != nil {
		session.completing = false
		m.sessions[flowID] = session
	}
	m.mu.Unlock()
}

// Cancel consumes one incomplete or completed Antigravity OAuth flow.
// Cancel 消费一个未完成或已完成的 Antigravity OAuth 流程。
func (m *AntigravityFlowManager) Cancel(flowID string) {
	m.mu.Lock()
	delete(m.sessions, flowID)
	m.mu.Unlock()
}

// pruneExpiredLocked removes expired sessions while the caller owns the lock.
// pruneExpiredLocked 在调用方持锁时删除已过期会话。
func (m *AntigravityFlowManager) pruneExpiredLocked(now time.Time) {
	for flowID, session := range m.sessions {
		if !session.flow.ExpiresAt.After(now) {
			delete(m.sessions, flowID)
		}
	}
}

// randomAntigravityIdentifier generates an opaque identifier using operating-system entropy.
// randomAntigravityIdentifier 使用操作系统熵生成不透明标识。
func randomAntigravityIdentifier(size int) (string, error) {
	buffer := make([]byte, size)
	if _, errRead := rand.Read(buffer); errRead != nil {
		return "", fmt.Errorf("generate Antigravity identifier: %w", errRead)
	}
	return hex.EncodeToString(buffer), nil
}
