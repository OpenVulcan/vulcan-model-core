package openai

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/dependency"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

// CodexToken stores the exact OAuth fields required for execution and plan inspection, with provider-optional refresh support.
// CodexToken 存储执行与套餐检查所需的精确 OAuth 字段，并允许供应商选择性提供刷新能力。
type CodexToken struct {
	// IDToken contains account and subscription claims.
	// IDToken 包含账号与订阅声明。
	IDToken string `json:"id_token"`
	// AccessToken authenticates Codex API requests.
	// AccessToken 用于认证 Codex API 请求。
	AccessToken string `json:"access_token"`
	// RefreshToken obtains replacement access tokens.
	// RefreshToken 用于获取替代 Access Token。
	RefreshToken string `json:"refresh_token"`
	// AccountID scopes requests to the exact ChatGPT account.
	// AccountID 将请求限定到精确 ChatGPT 账号。
	AccountID string `json:"account_id"`
	// Email is the account email returned by OpenAI authentication.
	// Email 是 OpenAI 认证返回的账号邮箱。
	Email string `json:"email"`
	// ExpiresAt is the provider-reported access-token expiration timestamp.
	// ExpiresAt 是供应商报告的 Access Token 过期时间戳。
	ExpiresAt time.Time `json:"expires_at"`
	// Type distinguishes this protected document from arbitrary bearer strings.
	// Type 将此受保护文档与任意 Bearer 字符串区分。
	Type string `json:"type"`
}

// codexJWTClaims contains the decoded identity and plan claim subset copied from CLIProxyAPI.
// codexJWTClaims 包含从 CLIProxyAPI 复制的已解码身份与套餐声明子集。
type codexJWTClaims struct {
	// Exp is the JWT expiration Unix timestamp.
	// Exp 是 JWT 过期 Unix 时间戳。
	Exp int64 `json:"exp"`
	// Email is the authenticated account email.
	// Email 是已认证账号邮箱。
	Email string `json:"email"`
	// Auth contains OpenAI-specific account claims.
	// Auth 包含 OpenAI 专属账号声明。
	Auth codexAuthClaims `json:"https://api.openai.com/auth"`
}

// codexAuthClaims contains the ChatGPT account and plan fields used by CLIProxyAPI.
// codexAuthClaims 包含 CLIProxyAPI 使用的 ChatGPT 账号与套餐字段。
type codexAuthClaims struct {
	// AccountID is the ChatGPT account identifier.
	// AccountID 是 ChatGPT 账号标识。
	AccountID string `json:"chatgpt_account_id"`
	// PlanType is the ChatGPT commercial plan code.
	// PlanType 是 ChatGPT 商业套餐代码。
	PlanType string `json:"chatgpt_plan_type"`
}

// CodexAccessTokenStore projects protected Codex documents to access tokens only during execution.
// CodexAccessTokenStore 仅在执行期间将受保护 Codex 文档投影为 Access Token。
type CodexAccessTokenStore struct {
	// delegate owns encrypted token documents.
	// delegate 管理加密 Token 文档。
	delegate secret.Store
}

// NewCodexAccessTokenStore creates a projection over the protected secret store.
// NewCodexAccessTokenStore 在受保护 Secret Store 上创建投影。
func NewCodexAccessTokenStore(delegate secret.Store) (*CodexAccessTokenStore, error) {
	if dependency.IsNil(delegate) {
		return nil, errors.New("Codex token delegate store is required")
	}
	return &CodexAccessTokenStore{delegate: delegate}, nil
}

// Put delegates protected token persistence unchanged.
// Put 原样委托受保护 Token 持久化。
func (s *CodexAccessTokenStore) Put(ctx context.Context, value []byte) (string, error) {
	return s.delegate.Put(ctx, value)
}

// Get returns only the access token from a versioned Codex document.
// Get 仅返回版本化 Codex 文档中的 Access Token。
func (s *CodexAccessTokenStore) Get(ctx context.Context, reference string) ([]byte, error) {
	value, errValue := s.delegate.Get(ctx, reference)
	if errValue != nil {
		return nil, errValue
	}
	token, errToken := UnmarshalCodexToken(value)
	clear(value)
	if errToken != nil {
		return nil, errToken
	}
	return []byte(token.AccessToken), nil
}

// Delete delegates exact token deletion.
// Delete 委托精确 Token 删除。
func (s *CodexAccessTokenStore) Delete(ctx context.Context, reference string) error {
	return s.delegate.Delete(ctx, reference)
}

// MarshalCodexToken serializes a structurally validated protected Codex token document.
// MarshalCodexToken 序列化经过结构校验的受保护 Codex Token 文档。
func MarshalCodexToken(token CodexToken) ([]byte, error) {
	if errValidate := validateCodexToken(token); errValidate != nil {
		return nil, errValidate
	}
	return json.Marshal(token)
}

// UnmarshalCodexToken parses and validates one protected Codex token document.
// UnmarshalCodexToken 解析并校验一个受保护 Codex Token 文档。
func UnmarshalCodexToken(value []byte) (CodexToken, error) {
	var token CodexToken
	if errDecode := json.Unmarshal(value, &token); errDecode != nil {
		return CodexToken{}, errors.New("protected Codex credential is not a token document")
	}
	if errValidate := validateCodexToken(token); errValidate != nil {
		return CodexToken{}, errValidate
	}
	return token, nil
}

// validateCodexToken enforces a usable OAuth document while treating refresh support as optional.
// validateCodexToken 强制执行可用 OAuth 文档边界，同时将刷新能力视为可选项。
func validateCodexToken(token CodexToken) error {
	if strings.TrimSpace(token.IDToken) == "" || strings.TrimSpace(token.AccessToken) == "" || token.ExpiresAt.IsZero() || token.Type != "codex" {
		return errors.New("protected Codex token document is incomplete")
	}
	return nil
}

// parseCodexJWT decodes claims from an ID token obtained directly from the provider OAuth token endpoint.
// parseCodexJWT 从供应商 OAuth Token 入口直接获取的 ID Token 中解码声明。
func parseCodexJWT(token string) (codexJWTClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return codexJWTClaims{}, errors.New("Codex ID token must contain three JWT segments")
	}
	payload, errPayload := base64.RawURLEncoding.DecodeString(parts[1])
	if errPayload != nil {
		return codexJWTClaims{}, fmt.Errorf("decode Codex ID token claims: %w", errPayload)
	}
	var claims codexJWTClaims
	if errDecode := json.Unmarshal(payload, &claims); errDecode != nil {
		return codexJWTClaims{}, fmt.Errorf("decode Codex ID token claim document: %w", errDecode)
	}
	return claims, nil
}
