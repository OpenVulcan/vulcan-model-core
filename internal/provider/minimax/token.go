package minimax

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/dependency"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

const (
	// tokenDocumentPrefix distinguishes protected MiniMax OAuth documents from arbitrary API keys.
	// tokenDocumentPrefix 将受保护 MiniMax OAuth 文档与任意 API Key 精确区分。
	tokenDocumentPrefix = "vulcan-minimax-token-v1:"
)

// Token contains the complete region-bound refreshable MiniMax OAuth secret.
// Token 包含完整且绑定区域的可刷新 MiniMax OAuth 秘密。
type Token struct {
	// AccessToken authenticates MiniMax API requests.
	// AccessToken 用于认证 MiniMax API 请求。
	AccessToken string `json:"access_token"`
	// RefreshToken obtains a replacement access token.
	// RefreshToken 用于获取替代 Access Token。
	RefreshToken string `json:"refresh_token"`
	// ExpiresAt is the provider-returned absolute expiry instant.
	// ExpiresAt 是供应商返回的绝对过期时刻。
	ExpiresAt time.Time `json:"expires_at"`
	// Region is exactly global or cn and must match the selected Definition.
	// Region 必须精确为 global 或 cn，并与所选 Definition 一致。
	Region string `json:"region"`
	// ResourceURL preserves the provider-returned same-region API Origin for audit.
	// ResourceURL 保留供应商返回的同区域 API Origin 供审计。
	ResourceURL string `json:"resource_url,omitempty"`
	// Type distinguishes the protected document from raw API keys.
	// Type 将受保护文档与原始 API Key 区分。
	Type string `json:"type"`
}

// AccessTokenStore projects protected MiniMax OAuth documents while passing raw API keys unchanged.
// AccessTokenStore 投影受保护 MiniMax OAuth 文档，同时原样传递原始 API Key。
type AccessTokenStore struct {
	// delegate owns encrypted complete credential persistence.
	// delegate 管理加密的完整凭据持久化。
	delegate secret.Store
}

// NewAccessTokenStore creates one MiniMax credential projection store.
// NewAccessTokenStore 创建一个 MiniMax 凭据投影存储。
func NewAccessTokenStore(delegate secret.Store) (*AccessTokenStore, error) {
	if dependency.IsNil(delegate) {
		return nil, errors.New("MiniMax token delegate store is required")
	}
	return &AccessTokenStore{delegate: delegate}, nil
}

// Put delegates complete credential persistence unchanged.
// Put 原样委托完整凭据持久化。
func (s *AccessTokenStore) Put(ctx context.Context, value []byte) (string, error) {
	return s.delegate.Put(ctx, value)
}

// Get returns a raw API key or only the access token from a versioned OAuth document.
// Get 返回原始 API Key，或仅返回版本化 OAuth 文档中的 Access Token。
func (s *AccessTokenStore) Get(ctx context.Context, reference string) ([]byte, error) {
	value, errGet := s.delegate.Get(ctx, reference)
	if errGet != nil {
		return nil, errGet
	}
	if !bytes.HasPrefix(value, []byte(tokenDocumentPrefix)) {
		return value, nil
	}
	defer clear(value)
	token, errToken := UnmarshalToken(value)
	if errToken != nil {
		return nil, errToken
	}
	return []byte(token.AccessToken), nil
}

// Delete delegates exact credential deletion.
// Delete 委托精确凭据删除。
func (s *AccessTokenStore) Delete(ctx context.Context, reference string) error {
	return s.delegate.Delete(ctx, reference)
}

// MarshalToken encodes one validated MiniMax token for protected storage.
// MarshalToken 编码一个已校验 MiniMax Token 以存入受保护存储。
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

// UnmarshalToken decodes one versioned protected MiniMax token document.
// UnmarshalToken 解码一个版本化受保护 MiniMax Token 文档。
func UnmarshalToken(value []byte) (Token, error) {
	if !bytes.HasPrefix(value, []byte(tokenDocumentPrefix)) {
		return Token{}, errors.New("protected MiniMax token document has an unknown format")
	}
	var token Token
	if errDecode := json.Unmarshal(value[len(tokenDocumentPrefix):], &token); errDecode != nil {
		return Token{}, errors.New("protected MiniMax token document is invalid")
	}
	if errValidate := validateToken(token); errValidate != nil {
		return Token{}, errValidate
	}
	return token, nil
}

// validateToken enforces region and expiry facts without accepting cross-region fallbacks.
// validateToken 强制执行区域与过期事实，且不接受跨区域降级。
func validateToken(token Token) error {
	if strings.TrimSpace(token.AccessToken) == "" || strings.TrimSpace(token.RefreshToken) == "" || token.ExpiresAt.IsZero() || token.Type != "minimax" {
		return errors.New("protected MiniMax token document is incomplete")
	}
	if token.Region != "global" && token.Region != "cn" {
		return errors.New("protected MiniMax token document has an invalid region")
	}
	return nil
}
