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
