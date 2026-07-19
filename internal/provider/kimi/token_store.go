package kimi

import (
	"bytes"
	"context"
	"errors"

	"github.com/OpenVulcan/vulcan-model-core/internal/dependency"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

// AccessTokenStore projects a protected Kimi token document to its bearer access token only during transport execution.
// AccessTokenStore 仅在传输执行期间将受保护 Kimi 令牌文档投影为 Bearer Access Token。
type AccessTokenStore struct {
	// delegate owns encrypted persistence and deletion of the complete refreshable token.
	// delegate 管理完整可刷新令牌的加密持久化和删除。
	delegate secret.Store
}

// NewAccessTokenStore creates a provider-specific secret projection without duplicating protected storage.
// NewAccessTokenStore 创建供应商专用秘密投影且不复制受保护存储。
func NewAccessTokenStore(delegate secret.Store) (*AccessTokenStore, error) {
	if dependency.IsNil(delegate) {
		return nil, errors.New("Kimi token delegate store is required")
	}
	return &AccessTokenStore{delegate: delegate}, nil
}

// Put delegates complete token persistence unchanged.
// Put 原样委托完整令牌持久化。
func (s *AccessTokenStore) Put(ctx context.Context, value []byte) (string, error) {
	return s.delegate.Put(ctx, value)
}

// Get returns only the access token required by an outbound Bearer header.
// Get 仅返回出站 Bearer 请求头需要的 Access Token。
func (s *AccessTokenStore) Get(ctx context.Context, reference string) ([]byte, error) {
	value, errGet := s.delegate.Get(ctx, reference)
	if errGet != nil {
		return nil, errGet
	}
	// Only the versioned document prefix denotes device-flow material; every other byte sequence remains an API key.
	// 仅版本化文档前缀表示设备授权材料；其他任意字节序列都保持为 API Key。
	if !bytes.HasPrefix(value, []byte(tokenDocumentPrefix)) {
		return value, nil
	}
	// The complete refreshable document is no longer needed after the access-token projection is copied.
	// 完整的可刷新文档在复制 Access Token 投影后不再需要。
	defer clear(value)
	token, errToken := UnmarshalToken(value)
	if errToken != nil {
		return nil, errToken
	}
	return []byte(token.AccessToken), nil
}

// Delete delegates complete token deletion unchanged.
// Delete 原样委托完整令牌删除。
func (s *AccessTokenStore) Delete(ctx context.Context, reference string) error {
	return s.delegate.Delete(ctx, reference)
}
