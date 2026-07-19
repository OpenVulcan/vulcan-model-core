package xai

import (
	"bytes"
	"context"
	"testing"

	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

// TestAccessTokenStoreProjectsOnlyValidatedXAITokens verifies that execution never receives refresh or identity tokens.
// TestAccessTokenStoreProjectsOnlyValidatedXAITokens 验证执行阶段绝不会收到 Refresh Token 或身份 Token。
func TestAccessTokenStoreProjectsOnlyValidatedXAITokens(t *testing.T) {
	ctx := context.Background()
	delegate := secret.NewMemoryStore()
	store, errStore := NewAccessTokenStore(delegate)
	if errStore != nil {
		t.Fatalf("NewAccessTokenStore() error = %v", errStore)
	}
	document, errDocument := MarshalToken(Token{AccessToken: "access", RefreshToken: "refresh", IDToken: "identity", TokenEndpoint: "https://auth.x.ai/token", Type: "xai"})
	if errDocument != nil {
		t.Fatalf("MarshalToken() error = %v", errDocument)
	}
	reference, errPut := store.Put(ctx, document)
	if errPut != nil {
		t.Fatalf("Put() error = %v", errPut)
	}
	projected, errGet := store.Get(ctx, reference)
	if errGet != nil || !bytes.Equal(projected, []byte("access")) {
		t.Fatalf("Get() = %q, %v", projected, errGet)
	}
	invalidReference, errInvalidPut := delegate.Put(ctx, []byte("ordinary-api-key"))
	if errInvalidPut != nil {
		t.Fatalf("delegate.Put() error = %v", errInvalidPut)
	}
	if _, errInvalidGet := store.Get(ctx, invalidReference); errInvalidGet == nil {
		t.Fatal("Get() accepted an untyped secret as an xAI token document")
	}
}
