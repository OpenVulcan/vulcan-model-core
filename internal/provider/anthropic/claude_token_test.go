package anthropic

import (
	"context"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

// TestClaudeAccessTokenStoreProjectsOnlyAccessToken verifies the execution secret boundary.
// TestClaudeAccessTokenStoreProjectsOnlyAccessToken 验证执行 Secret 边界。
func TestClaudeAccessTokenStoreProjectsOnlyAccessToken(t *testing.T) {
	ctx := context.Background()
	delegate := secret.NewMemoryStore()
	store, errStore := NewClaudeAccessTokenStore(delegate)
	if errStore != nil {
		t.Fatalf("NewClaudeAccessTokenStore() error = %v", errStore)
	}
	token := claudeTokenFixture(time.Unix(1_800_000_000, 0).UTC())
	encoded, errEncode := MarshalClaudeToken(token)
	if errEncode != nil {
		t.Fatalf("MarshalClaudeToken() error = %v", errEncode)
	}
	reference, errPut := store.Put(ctx, encoded)
	if errPut != nil {
		t.Fatalf("Put() error = %v", errPut)
	}
	projected, errGet := store.Get(ctx, reference)
	if errGet != nil {
		t.Fatalf("Get() error = %v", errGet)
	}
	if string(projected) != token.AccessToken {
		t.Fatalf("projected secret = %q, want access token", string(projected))
	}
}

// TestUnmarshalClaudeTokenRejectsIncompleteProtectedDocument verifies refresh material cannot be omitted.
// TestUnmarshalClaudeTokenRejectsIncompleteProtectedDocument 验证不可省略刷新材料。
func TestUnmarshalClaudeTokenRejectsIncompleteProtectedDocument(t *testing.T) {
	if _, errToken := UnmarshalClaudeToken([]byte(`{"access_token":"access","token_type":"Bearer","expires_at":1,"last_refresh_at":1,"email":"user@example.com","type":"claude"}`)); errToken == nil {
		t.Fatalf("UnmarshalClaudeToken() accepted a document without refresh token")
	}
}
