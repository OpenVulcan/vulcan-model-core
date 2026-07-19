package xai

import (
	"context"
	"errors"

	"github.com/OpenVulcan/vulcan-model-core/internal/dependency"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

// AccessTokenStore projects protected xAI token documents to bearer tokens only during execution.
// AccessTokenStore 仅在执行期间将受保护 xAI Token 文档投影为 Bearer Token。
type AccessTokenStore struct {
	// delegate owns encrypted token documents.
	// delegate 管理加密 Token 文档。
	delegate secret.Store
}

// NewAccessTokenStore creates an xAI access-token projection.
// NewAccessTokenStore 创建 xAI Access Token 投影。
func NewAccessTokenStore(delegate secret.Store) (*AccessTokenStore, error) {
	if dependency.IsNil(delegate) {
		return nil, errors.New("xAI token delegate store is required")
	}
	return &AccessTokenStore{delegate: delegate}, nil
}

// Put delegates protected token persistence unchanged.
// Put 原样委托受保护 Token 持久化。
func (s *AccessTokenStore) Put(ctx context.Context, value []byte) (string, error) {
	return s.delegate.Put(ctx, value)
}

// Get returns only the access token from a protected xAI document.
// Get 仅返回受保护 xAI 文档中的 Access Token。
func (s *AccessTokenStore) Get(ctx context.Context, reference string) ([]byte, error) {
	value, errValue := s.delegate.Get(ctx, reference)
	if errValue != nil {
		return nil, errValue
	}
	token, errToken := UnmarshalToken(value)
	clear(value)
	if errToken != nil {
		return nil, errToken
	}
	return []byte(token.AccessToken), nil
}

// Delete delegates exact token deletion.
// Delete 委托精确 Token 删除。
func (s *AccessTokenStore) Delete(ctx context.Context, reference string) error {
	return s.delegate.Delete(ctx, reference)
}
