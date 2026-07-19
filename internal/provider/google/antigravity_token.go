package google

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/dependency"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

// AntigravityToken stores the exact OAuth, identity, and project fields required by execution and refresh.
// AntigravityToken 存储执行与刷新所需的精确 OAuth、身份与项目字段。
type AntigravityToken struct {
	// AccessToken authenticates Google control-plane and execution requests.
	// AccessToken 用于认证 Google 控制面与执行请求。
	AccessToken string `json:"access_token"`
	// RefreshToken obtains replacement access tokens.
	// RefreshToken 用于获取替代 Access Token。
	RefreshToken string `json:"refresh_token"`
	// TokenType is Google's OAuth token type.
	// TokenType 是 Google OAuth Token 类型。
	TokenType string `json:"token_type,omitempty"`
	// Email is the verified Google user identity.
	// Email 是已验证 Google 用户身份。
	Email string `json:"email"`
	// ProjectID scopes Antigravity requests to the provisioned Cloud AI Companion project.
	// ProjectID 将 Antigravity 请求限定到已配置的 Cloud AI Companion 项目。
	ProjectID string `json:"project_id"`
	// ExpiresAt is the access-token Unix expiry.
	// ExpiresAt 是 Access Token 的 Unix 过期时间。
	ExpiresAt int64 `json:"expires_at"`
	// Type distinguishes this protected document from arbitrary bearer strings.
	// Type 将此受保护文档与任意 Bearer 字符串区分。
	Type string `json:"type"`
}

// AntigravityAccessTokenStore projects protected documents to access tokens only during execution.
// AntigravityAccessTokenStore 仅在执行期间将受保护文档投影为 Access Token。
type AntigravityAccessTokenStore struct {
	// delegate owns encrypted token documents.
	// delegate 管理加密 Token 文档。
	delegate secret.Store
}

// NewAntigravityAccessTokenStore creates an Antigravity access-token projection.
// NewAntigravityAccessTokenStore 创建 Antigravity Access Token 投影。
func NewAntigravityAccessTokenStore(delegate secret.Store) (*AntigravityAccessTokenStore, error) {
	if dependency.IsNil(delegate) {
		return nil, errors.New("Antigravity token delegate store is required")
	}
	return &AntigravityAccessTokenStore{delegate: delegate}, nil
}

// Put delegates protected token persistence unchanged.
// Put 原样委托受保护 Token 持久化。
func (s *AntigravityAccessTokenStore) Put(ctx context.Context, value []byte) (string, error) {
	return s.delegate.Put(ctx, value)
}

// Get returns only the access token from a protected Antigravity document.
// Get 仅返回受保护 Antigravity 文档中的 Access Token。
func (s *AntigravityAccessTokenStore) Get(ctx context.Context, reference string) ([]byte, error) {
	value, errValue := s.delegate.Get(ctx, reference)
	if errValue != nil {
		return nil, errValue
	}
	token, errToken := UnmarshalAntigravityToken(value)
	clear(value)
	if errToken != nil {
		return nil, errToken
	}
	return []byte(token.AccessToken), nil
}

// Delete delegates exact token deletion.
// Delete 委托精确 Token 删除。
func (s *AntigravityAccessTokenStore) Delete(ctx context.Context, reference string) error {
	return s.delegate.Delete(ctx, reference)
}

// MarshalAntigravityToken serializes one validated protected Antigravity token document.
// MarshalAntigravityToken 序列化一个经过校验的受保护 Antigravity Token 文档。
func MarshalAntigravityToken(token AntigravityToken) ([]byte, error) {
	if errValidate := validateAntigravityToken(token); errValidate != nil {
		return nil, errValidate
	}
	return json.Marshal(token)
}

// UnmarshalAntigravityToken parses one protected Antigravity token document.
// UnmarshalAntigravityToken 解析一个受保护 Antigravity Token 文档。
func UnmarshalAntigravityToken(value []byte) (AntigravityToken, error) {
	var token AntigravityToken
	if errDecode := json.Unmarshal(value, &token); errDecode != nil {
		return AntigravityToken{}, errors.New("protected Antigravity credential is not a token document")
	}
	if errValidate := validateAntigravityToken(token); errValidate != nil {
		return AntigravityToken{}, errValidate
	}
	return token, nil
}

// validateAntigravityToken enforces the complete refreshable account and project boundary.
// validateAntigravityToken 强制执行完整可刷新账号与项目边界。
func validateAntigravityToken(token AntigravityToken) error {
	if strings.TrimSpace(token.AccessToken) == "" || strings.TrimSpace(token.RefreshToken) == "" || strings.TrimSpace(token.Email) == "" || strings.TrimSpace(token.ProjectID) == "" || token.Type != "antigravity" {
		return errors.New("protected Antigravity token document is incomplete")
	}
	return nil
}

// antigravityTokenExpiry converts Google's lifetime to one stable Unix expiry while rejecting overflow.
// antigravityTokenExpiry 将 Google 有效期转换为稳定 Unix 过期时间，同时拒绝溢出。
func antigravityTokenExpiry(expiresIn int64) (int64, error) {
	if expiresIn <= 0 {
		return 0, nil
	}
	now := time.Now().Unix()
	if expiresIn > math.MaxInt64-now {
		return 0, errors.New("Antigravity token response expiry is invalid")
	}
	return now + expiresIn, nil
}
