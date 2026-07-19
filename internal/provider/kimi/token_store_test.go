package kimi

import (
	"bytes"
	"context"
	"testing"

	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

// TestAccessTokenStoreDistinguishesArbitraryAPIKeysFromVersionedTokens verifies that JSON-shaped API keys are never parsed speculatively.
// TestAccessTokenStoreDistinguishesArbitraryAPIKeysFromVersionedTokens 验证类似 JSON 的 API Key 绝不会被投机解析。
func TestAccessTokenStoreDistinguishesArbitraryAPIKeysFromVersionedTokens(t *testing.T) {
	ctx := context.Background()
	delegate := secret.NewMemoryStore()
	store, errStore := NewAccessTokenStore(delegate)
	if errStore != nil {
		t.Fatalf("NewAccessTokenStore() error = %v", errStore)
	}
	apiKey := []byte(`{"access_token":"this-is-still-an-api-key"}`)
	apiKeyReference, errAPIKey := delegate.Put(ctx, apiKey)
	if errAPIKey != nil {
		t.Fatalf("Put(API key) error = %v", errAPIKey)
	}
	resolvedAPIKey, errResolveAPIKey := store.Get(ctx, apiKeyReference)
	if errResolveAPIKey != nil || !bytes.Equal(resolvedAPIKey, apiKey) {
		t.Fatalf("Get(API key) value=%q error=%v", resolvedAPIKey, errResolveAPIKey)
	}
	encodedToken, errToken := MarshalToken(Token{AccessToken: "access-only", RefreshToken: "refresh-secret", DeviceID: "device-one", Type: "kimi"})
	if errToken != nil {
		t.Fatalf("MarshalToken() error = %v", errToken)
	}
	tokenReference, errPutToken := delegate.Put(ctx, encodedToken)
	if errPutToken != nil {
		t.Fatalf("Put(token) error = %v", errPutToken)
	}
	resolvedToken, errResolveToken := store.Get(ctx, tokenReference)
	if errResolveToken != nil || string(resolvedToken) != "access-only" {
		t.Fatalf("Get(token) value=%q error=%v", resolvedToken, errResolveToken)
	}
}

// TestAccessTokenStoreClearsDecodedDeviceDocument verifies the projection clears the complete decrypted refreshable document after copying its access token.
// TestAccessTokenStoreClearsDecodedDeviceDocument 验证投影层复制 Access Token 后会清零完整的已解密可刷新文档。
func TestAccessTokenStoreClearsDecodedDeviceDocument(t *testing.T) {
	encodedToken, errToken := MarshalToken(Token{AccessToken: "access-secret", RefreshToken: "refresh-secret", DeviceID: "device-one", Type: "kimi"})
	if errToken != nil {
		t.Fatalf("MarshalToken() error = %v", errToken)
	}
	delegate := &retainingKimiSecretStore{value: append([]byte(nil), encodedToken...)}
	store, errStore := NewAccessTokenStore(delegate)
	if errStore != nil {
		t.Fatalf("NewAccessTokenStore() error = %v", errStore)
	}
	accessToken, errGet := store.Get(context.Background(), "secret://retained/kimi")
	if errGet != nil || string(accessToken) != "access-secret" {
		t.Fatalf("Get() value=%q error=%v", accessToken, errGet)
	}
	for _, item := range delegate.value {
		if item != 0 {
			t.Fatalf("Get() retained decrypted token document: %q", delegate.value)
		}
	}
}

// retainingKimiSecretStore returns one owned backing buffer so tests can observe projection-layer clearing.
// retainingKimiSecretStore 返回一个自有底层缓冲区，以便测试观察投影层清零行为。
type retainingKimiSecretStore struct {
	// value is the exact decrypted buffer returned by Get.
	// value 是 Get 返回的精确已解密缓冲区。
	value []byte
}

// Put replaces the retained test buffer.
// Put 替换被保留的测试缓冲区。
func (s *retainingKimiSecretStore) Put(_ context.Context, value []byte) (string, error) {
	s.value = append([]byte(nil), value...)
	return "secret://retained/kimi", nil
}

// Get returns the exact retained buffer rather than an isolated copy.
// Get 返回精确的被保留缓冲区，而不是隔离副本。
func (s *retainingKimiSecretStore) Get(context.Context, string) ([]byte, error) {
	return s.value, nil
}

// Delete clears and removes the retained test buffer.
// Delete 清零并移除被保留的测试缓冲区。
func (s *retainingKimiSecretStore) Delete(context.Context, string) error {
	clear(s.value)
	s.value = nil
	return nil
}
