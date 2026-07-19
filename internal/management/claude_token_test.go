package management

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/bootstrap"
	coreprovider "github.com/OpenVulcan/vulcan-model-core/internal/provider"
	provideranthropic "github.com/OpenVulcan/vulcan-model-core/internal/provider/anthropic"
)

// staticClaudeTokenClient returns one deterministic refreshed Claude OAuth document.
// staticClaudeTokenClient 返回一个确定性的已刷新 Claude OAuth 文档。
type staticClaudeTokenClient struct {
	// token is the deterministic refresh result.
	// token 是确定性的刷新结果。
	token provideranthropic.ClaudeToken
}

// Refresh returns the configured Claude token.
// Refresh 返回配置的 Claude Token。
func (c staticClaudeTokenClient) Refresh(context.Context, provideranthropic.ClaudeToken) (provideranthropic.ClaudeToken, error) {
	return c.token, nil
}

// TestClaudeOAuthOnboardingAndRefreshPreserveAccount verifies the specialized acquisition and replacement boundary.
// TestClaudeOAuthOnboardingAndRefreshPreserveAccount 验证专属获取与替换边界。
func TestClaudeOAuthOnboardingAndRefreshPreserveAccount(t *testing.T) {
	ctx := context.Background()
	service, configurations, secrets := newKimiOnboardingService(t)
	now := time.Now().UTC().Truncate(time.Second)
	initial := provideranthropic.ClaudeToken{AccessToken: "before", RefreshToken: "refresh-before", TokenType: "Bearer", ExpiresAt: now.Add(time.Hour).Unix(), LastRefreshAt: now.Unix(), Email: "user@example.com", AccountID: "account-one", OrganizationID: "org-one", OrganizationName: "Example", Type: "claude"}
	encoded, errEncode := provideranthropic.MarshalClaudeToken(initial)
	if errEncode != nil {
		t.Fatalf("MarshalClaudeToken() error = %v", errEncode)
	}
	input := OnboardSystemProviderInput{DefinitionID: bootstrap.AnthropicClaudeCodeDefinitionID, Handle: "claude-code", DisplayName: "Claude Code", AuthMethodID: "oauth", Secret: encoded}
	if _, errGeneric := service.OnboardSystemProvider(ctx, input); errGeneric == nil {
		t.Fatalf("generic onboarding accepted an injected Claude OAuth token")
	}
	onboarding, errOnboard := service.OnboardClaudeOAuthProvider(ctx, input)
	if errOnboard != nil {
		t.Fatalf("OnboardClaudeOAuthProvider() error = %v", errOnboard)
	}
	if onboarding.Credential.PrincipalKey != "account-one" || onboarding.Credential.Label != "user@example.com" || onboarding.Credential.ExpiresAt == nil || !onboarding.Credential.ExpiresAt.Equal(time.Unix(initial.ExpiresAt, 0).UTC()) {
		t.Fatalf("Claude credential metadata = %#v", onboarding.Credential)
	}
	oldReference := onboarding.Credential.SecretRef
	refreshedToken := initial
	refreshedToken.AccessToken = "after"
	refreshedToken.RefreshToken = "refresh-after"
	refreshedToken.ExpiresAt = now.Add(2 * time.Hour).Unix()
	refreshedToken.LastRefreshAt = now.Add(time.Minute).Unix()
	refresher, errRefresher := NewClaudeTokenService(configurations, secrets, staticClaudeTokenClient{token: refreshedToken})
	if errRefresher != nil {
		t.Fatalf("NewClaudeTokenService() error = %v", errRefresher)
	}
	credential, errRefresh := refresher.RefreshCredential(ctx, onboarding.Instance.ID, onboarding.Credential.ID)
	if errRefresh != nil {
		t.Fatalf("RefreshCredential() error = %v", errRefresh)
	}
	if credential.Revision != 2 || credential.SecretRef == oldReference || credential.ExpiresAt == nil || credential.ExpiresAt.Unix() != refreshedToken.ExpiresAt {
		t.Fatalf("refreshed Claude credential = %#v", credential)
	}
	if _, errOld := secrets.Get(ctx, oldReference); errOld == nil {
		t.Fatalf("superseded Claude token still exists")
	}
	protected, errProtected := secrets.Get(ctx, credential.SecretRef)
	if errProtected != nil {
		t.Fatalf("read refreshed Claude token: %v", errProtected)
	}
	stored, errStored := provideranthropic.UnmarshalClaudeToken(protected)
	if errStored != nil || stored.AccessToken != "after" || stored.AccountID != "account-one" {
		t.Fatalf("stored Claude token = %#v, %v", stored, errStored)
	}
}

// TestClaudeTokenRefreshRejectsAccountChange verifies a refresh cannot silently cross provider identity.
// TestClaudeTokenRefreshRejectsAccountChange 验证刷新不能静默跨越供应商身份。
func TestClaudeTokenRefreshRejectsAccountChange(t *testing.T) {
	ctx := context.Background()
	service, configurations, secrets := newKimiOnboardingService(t)
	now := time.Now().UTC().Truncate(time.Second)
	initial := provideranthropic.ClaudeToken{AccessToken: "before", RefreshToken: "refresh-before", TokenType: "Bearer", ExpiresAt: now.Add(time.Hour).Unix(), LastRefreshAt: now.Unix(), Email: "user@example.com", AccountID: "account-one", Type: "claude"}
	encoded, _ := provideranthropic.MarshalClaudeToken(initial)
	onboarding, errOnboard := service.OnboardClaudeOAuthProvider(ctx, OnboardSystemProviderInput{DefinitionID: bootstrap.AnthropicClaudeCodeDefinitionID, Handle: "claude-mismatch", DisplayName: "Claude", AuthMethodID: "oauth", Secret: encoded})
	if errOnboard != nil {
		t.Fatalf("OnboardClaudeOAuthProvider() error = %v", errOnboard)
	}
	mismatch := initial
	mismatch.AccountID = "account-two"
	refresher, _ := NewClaudeTokenService(configurations, secrets, staticClaudeTokenClient{token: mismatch})
	if _, errRefresh := refresher.RefreshCredential(ctx, onboarding.Instance.ID, onboarding.Credential.ID); !errors.Is(errRefresh, coreprovider.ErrAuthenticationResponseInvalid) {
		t.Fatalf("RefreshCredential() error = %v, want invalid authentication response", errRefresh)
	}
}

// TestClaudeTokenRefreshRejectsOrganizationChange verifies refresh cannot cross the provider-owned organization boundary.
// TestClaudeTokenRefreshRejectsOrganizationChange 验证刷新不能跨越供应商拥有的组织边界。
func TestClaudeTokenRefreshRejectsOrganizationChange(t *testing.T) {
	ctx := context.Background()
	service, configurations, secrets := newKimiOnboardingService(t)
	now := time.Now().UTC().Truncate(time.Second)
	initial := provideranthropic.ClaudeToken{AccessToken: "before", RefreshToken: "refresh-before", TokenType: "Bearer", ExpiresAt: now.Add(time.Hour).Unix(), LastRefreshAt: now.Unix(), Email: "user@example.com", AccountID: "account-one", OrganizationID: "org-one", OrganizationName: "Example", Type: "claude"}
	encoded, errEncode := provideranthropic.MarshalClaudeToken(initial)
	if errEncode != nil {
		t.Fatalf("MarshalClaudeToken() error = %v", errEncode)
	}
	onboarding, errOnboard := service.OnboardClaudeOAuthProvider(ctx, OnboardSystemProviderInput{DefinitionID: bootstrap.AnthropicClaudeCodeDefinitionID, Handle: "claude-org-mismatch", DisplayName: "Claude", AuthMethodID: "oauth", Secret: encoded})
	if errOnboard != nil {
		t.Fatalf("OnboardClaudeOAuthProvider() error = %v", errOnboard)
	}
	mismatch := initial
	mismatch.OrganizationID = "org-two"
	refresher, errRefresher := NewClaudeTokenService(configurations, secrets, staticClaudeTokenClient{token: mismatch})
	if errRefresher != nil {
		t.Fatalf("NewClaudeTokenService() error = %v", errRefresher)
	}
	if _, errRefresh := refresher.RefreshCredential(ctx, onboarding.Instance.ID, onboarding.Credential.ID); !errors.Is(errRefresh, coreprovider.ErrAuthenticationResponseInvalid) {
		t.Fatalf("RefreshCredential() error = %v, want invalid authentication response", errRefresh)
	}
}
