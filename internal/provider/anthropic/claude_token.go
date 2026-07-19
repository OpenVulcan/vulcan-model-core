package anthropic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/OpenVulcan/vulcan-model-core/internal/dependency"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

const (
	// claudeTokenDocumentType identifies one protected Claude Code OAuth document.
	// claudeTokenDocumentType 标识一个受保护的 Claude Code OAuth 文档。
	claudeTokenDocumentType = "claude"
)

// ClaudeToken stores the complete refreshable Claude Code OAuth identity behind the secret boundary.
// ClaudeToken 在 Secret 边界后存储完整且可刷新的 Claude Code OAuth 身份。
type ClaudeToken struct {
	// AccessToken authorizes one Claude API request.
	// AccessToken 授权一条 Claude API 请求。
	AccessToken string `json:"access_token"`
	// RefreshToken obtains a replacement access token.
	// RefreshToken 用于获取替代 Access Token。
	RefreshToken string `json:"refresh_token"`
	// TokenType records the provider-issued authorization scheme.
	// TokenType 记录供应商签发的授权方案。
	TokenType string `json:"token_type"`
	// ExpiresAt is the access-token expiry as a Unix timestamp.
	// ExpiresAt 是 Access Token 过期时间的 Unix 时间戳。
	ExpiresAt int64 `json:"expires_at"`
	// LastRefreshAt records the most recent successful token exchange as a Unix timestamp.
	// LastRefreshAt 以 Unix 时间戳记录最近一次成功 Token 交换。
	LastRefreshAt int64 `json:"last_refresh_at"`
	// Email is the provider-reported Anthropic account email.
	// Email 是供应商报告的 Anthropic 账号邮箱。
	Email string `json:"email"`
	// AccountID is the provider-reported stable Anthropic account UUID.
	// AccountID 是供应商报告的稳定 Anthropic 账号 UUID。
	AccountID string `json:"account_id"`
	// OrganizationID is the provider-reported Anthropic organization UUID.
	// OrganizationID 是供应商报告的 Anthropic 组织 UUID。
	OrganizationID string `json:"organization_id"`
	// OrganizationName is the provider-reported Anthropic organization name.
	// OrganizationName 是供应商报告的 Anthropic 组织名称。
	OrganizationName string `json:"organization_name"`
	// Type fixes the protected document schema to Claude Code OAuth.
	// Type 将受保护文档 Schema 固定为 Claude Code OAuth。
	Type string `json:"type"`
}

// ClaudeAccessTokenStore projects protected Claude OAuth documents to access tokens only during execution.
// ClaudeAccessTokenStore 仅在执行期间将受保护 Claude OAuth 文档投影为 Access Token。
type ClaudeAccessTokenStore struct {
	// delegate owns encrypted-at-rest protected documents.
	// delegate 管理静态加密的受保护文档。
	delegate secret.Store
}

// NewClaudeAccessTokenStore creates one Claude access-token projection.
// NewClaudeAccessTokenStore 创建一个 Claude Access Token 投影。
func NewClaudeAccessTokenStore(delegate secret.Store) (*ClaudeAccessTokenStore, error) {
	if dependency.IsNil(delegate) {
		return nil, errors.New("Claude access-token store requires a secret store")
	}
	return &ClaudeAccessTokenStore{delegate: delegate}, nil
}

// Put delegates protected Claude token persistence unchanged.
// Put 原样委托受保护 Claude Token 持久化。
func (s *ClaudeAccessTokenStore) Put(ctx context.Context, value []byte) (string, error) {
	return s.delegate.Put(ctx, value)
}

// Get returns only the access token from one protected Claude token document.
// Get 仅返回一个受保护 Claude Token 文档中的 Access Token。
func (s *ClaudeAccessTokenStore) Get(ctx context.Context, reference string) ([]byte, error) {
	value, errValue := s.delegate.Get(ctx, reference)
	if errValue != nil {
		return nil, errValue
	}
	token, errToken := UnmarshalClaudeToken(value)
	clear(value)
	if errToken != nil {
		return nil, errToken
	}
	return []byte(token.AccessToken), nil
}

// Delete delegates exact protected Claude token deletion.
// Delete 委托精确删除受保护 Claude Token。
func (s *ClaudeAccessTokenStore) Delete(ctx context.Context, reference string) error {
	return s.delegate.Delete(ctx, reference)
}

// MarshalClaudeToken serializes one validated protected Claude OAuth document.
// MarshalClaudeToken 序列化一个经过校验的受保护 Claude OAuth 文档。
func MarshalClaudeToken(token ClaudeToken) ([]byte, error) {
	if errValidate := validateClaudeToken(token); errValidate != nil {
		return nil, errValidate
	}
	encoded, errEncode := json.Marshal(token)
	if errEncode != nil {
		return nil, fmt.Errorf("marshal Claude OAuth token: %w", errEncode)
	}
	return encoded, nil
}

// UnmarshalClaudeToken parses one protected Claude OAuth document.
// UnmarshalClaudeToken 解析一个受保护 Claude OAuth 文档。
func UnmarshalClaudeToken(value []byte) (ClaudeToken, error) {
	var token ClaudeToken
	if errDecode := json.Unmarshal(value, &token); errDecode != nil {
		return ClaudeToken{}, fmt.Errorf("decode Claude OAuth token: %w", errDecode)
	}
	if errValidate := validateClaudeToken(token); errValidate != nil {
		return ClaudeToken{}, errValidate
	}
	return token, nil
}

// validateClaudeToken enforces the complete refreshable Claude account boundary.
// validateClaudeToken 强制执行完整且可刷新的 Claude 账号边界。
func validateClaudeToken(token ClaudeToken) error {
	if token.Type != claudeTokenDocumentType {
		return errors.New("Claude OAuth token document type is invalid")
	}
	if strings.TrimSpace(token.AccessToken) == "" || strings.TrimSpace(token.RefreshToken) == "" {
		return errors.New("Claude OAuth access and refresh tokens are required")
	}
	if !strings.EqualFold(strings.TrimSpace(token.TokenType), "Bearer") {
		return errors.New("Claude OAuth token type must be Bearer")
	}
	if token.ExpiresAt <= 0 || token.LastRefreshAt <= 0 {
		return errors.New("Claude OAuth expiry and refresh timestamps are required")
	}
	if strings.TrimSpace(token.AccountID) == "" && strings.TrimSpace(token.Email) == "" {
		return errors.New("Claude OAuth account identity is required")
	}
	return nil
}
