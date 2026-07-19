package management

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/bootstrap"
	coreprovider "github.com/OpenVulcan/vulcan-model-core/internal/provider"
	provideranthropic "github.com/OpenVulcan/vulcan-model-core/internal/provider/anthropic"
	providergoogle "github.com/OpenVulcan/vulcan-model-core/internal/provider/google"
	providerkimi "github.com/OpenVulcan/vulcan-model-core/internal/provider/kimi"
	providerxai "github.com/OpenVulcan/vulcan-model-core/internal/provider/xai"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

// TestProviderOwnedOnboardingDerivesIdentityAndScopes verifies callers cannot inject provider-owned credential identity fields.
// TestProviderOwnedOnboardingDerivesIdentityAndScopes 验证调用方不能注入供应商拥有的凭据身份字段。
func TestProviderOwnedOnboardingDerivesIdentityAndScopes(t *testing.T) {
	t.Run("Kimi clears unverifiable identity", func(t *testing.T) {
		service, _, _ := newKimiOnboardingService(t)
		token, errToken := providerkimi.MarshalToken(providerkimi.Token{AccessToken: "access", RefreshToken: "refresh", TokenType: "Bearer", DeviceID: "device-one", Type: "kimi"})
		if errToken != nil {
			t.Fatalf("MarshalToken() error = %v", errToken)
		}
		onboarding, errOnboard := service.OnboardKimiDeviceProvider(context.Background(), OnboardSystemProviderInput{DefinitionID: bootstrap.KimiCodingDefinitionID, Handle: "kimi-derived-identity", DisplayName: "Kimi", AuthMethodID: "device_flow", PrincipalKey: "forged-account", ScopeRefs: []providerconfig.ScopeReference{{Kind: "organization", ID: "forged-scope"}}, Secret: token})
		if errOnboard != nil {
			t.Fatalf("OnboardKimiDeviceProvider() error = %v", errOnboard)
		}
		if onboarding.Credential.PrincipalKey != "" || len(onboarding.Credential.ScopeRefs) != 0 {
			t.Fatalf("Kimi credential identity = %#v", onboarding.Credential)
		}
	})

	t.Run("xAI keeps only provider account identity", func(t *testing.T) {
		service, _, _ := newKimiOnboardingService(t)
		token, errToken := providerxai.MarshalToken(providerxai.Token{AccessToken: "access", RefreshToken: "refresh", TokenEndpoint: "https://auth.x.ai/oauth/token", Email: "user@x.ai", Subject: "subject-one", Type: "xai"})
		if errToken != nil {
			t.Fatalf("MarshalToken() error = %v", errToken)
		}
		onboarding, errOnboard := service.OnboardXAIDeviceProvider(context.Background(), OnboardSystemProviderInput{DefinitionID: bootstrap.XAIOAuthDefinitionID, Handle: "xai-derived-identity", DisplayName: "xAI", AuthMethodID: "device_flow", PrincipalKey: "forged-account", ScopeRefs: []providerconfig.ScopeReference{{Kind: "organization", ID: "forged-scope"}}, Secret: token})
		if errOnboard != nil {
			t.Fatalf("OnboardXAIDeviceProvider() error = %v", errOnboard)
		}
		if onboarding.Credential.PrincipalKey != "subject-one" || len(onboarding.Credential.ScopeRefs) != 0 {
			t.Fatalf("xAI credential identity = %#v", onboarding.Credential)
		}
	})

	t.Run("Claude keeps exact provider organization", func(t *testing.T) {
		service, _, _ := newKimiOnboardingService(t)
		now := time.Date(2026, 7, 19, 4, 0, 0, 0, time.UTC)
		token, errToken := provideranthropic.MarshalClaudeToken(provideranthropic.ClaudeToken{AccessToken: "access", RefreshToken: "refresh", TokenType: "Bearer", ExpiresAt: now.Add(time.Hour).Unix(), LastRefreshAt: now.Unix(), Email: "user@example.com", AccountID: "account-one", OrganizationID: "org-one", OrganizationName: "Example", Type: "claude"})
		if errToken != nil {
			t.Fatalf("MarshalClaudeToken() error = %v", errToken)
		}
		onboarding, errOnboard := service.OnboardClaudeOAuthProvider(context.Background(), OnboardSystemProviderInput{DefinitionID: bootstrap.AnthropicClaudeCodeDefinitionID, Handle: "claude-derived-identity", DisplayName: "Claude", AuthMethodID: "oauth", PrincipalKey: "forged-account", ScopeRefs: []providerconfig.ScopeReference{{Kind: "organization", ID: "forged-scope"}}, Secret: token})
		if errOnboard != nil {
			t.Fatalf("OnboardClaudeOAuthProvider() error = %v", errOnboard)
		}
		expectedScope := providerconfig.ScopeReference{Kind: "organization", ID: "org-one"}
		if onboarding.Credential.PrincipalKey != "account-one" || len(onboarding.Credential.ScopeRefs) != 1 || onboarding.Credential.ScopeRefs[0] != expectedScope {
			t.Fatalf("Claude credential identity = %#v", onboarding.Credential)
		}
	})

	t.Run("Claude clears absent organization", func(t *testing.T) {
		service, _, _ := newKimiOnboardingService(t)
		now := time.Date(2026, 7, 19, 4, 0, 0, 0, time.UTC)
		token, errToken := provideranthropic.MarshalClaudeToken(provideranthropic.ClaudeToken{AccessToken: "access", RefreshToken: "refresh", TokenType: "Bearer", ExpiresAt: now.Add(time.Hour).Unix(), LastRefreshAt: now.Unix(), Email: "user@example.com", AccountID: "account-one", Type: "claude"})
		if errToken != nil {
			t.Fatalf("MarshalClaudeToken() error = %v", errToken)
		}
		onboarding, errOnboard := service.OnboardClaudeOAuthProvider(context.Background(), OnboardSystemProviderInput{DefinitionID: bootstrap.AnthropicClaudeCodeDefinitionID, Handle: "claude-no-organization", DisplayName: "Claude", AuthMethodID: "oauth", ScopeRefs: []providerconfig.ScopeReference{{Kind: "organization", ID: "forged-scope"}}, Secret: token})
		if errOnboard != nil {
			t.Fatalf("OnboardClaudeOAuthProvider() error = %v", errOnboard)
		}
		if len(onboarding.Credential.ScopeRefs) != 0 {
			t.Fatalf("Claude credential scopes = %#v", onboarding.Credential.ScopeRefs)
		}
	})
}

// TestXAITokenRefreshRejectsSubjectChange verifies the stable OAuth subject cannot change during refresh.
// TestXAITokenRefreshRejectsSubjectChange 验证稳定 OAuth Subject 不能在刷新期间变化。
func TestXAITokenRefreshRejectsSubjectChange(t *testing.T) {
	ctx := context.Background()
	service, configurations, secrets := newKimiOnboardingService(t)
	initial := providerxai.Token{AccessToken: "before", RefreshToken: "refresh-before", TokenEndpoint: "https://auth.x.ai/oauth/token", Email: "user@x.ai", Subject: "subject-one", Type: "xai"}
	encoded, errEncode := providerxai.MarshalToken(initial)
	if errEncode != nil {
		t.Fatalf("MarshalToken() error = %v", errEncode)
	}
	onboarding, errOnboard := service.OnboardXAIDeviceProvider(ctx, OnboardSystemProviderInput{DefinitionID: bootstrap.XAIOAuthDefinitionID, Handle: "xai-subject-mismatch", DisplayName: "xAI Account", AuthMethodID: "device_flow", CredentialLabel: "xAI Account", Secret: encoded})
	if errOnboard != nil {
		t.Fatalf("OnboardXAIDeviceProvider() error = %v", errOnboard)
	}
	mismatch := initial
	mismatch.Subject = "subject-two"
	refresher, errRefresher := NewXAITokenService(configurations, secrets, staticXAITokenClient{token: mismatch})
	if errRefresher != nil {
		t.Fatalf("NewXAITokenService() error = %v", errRefresher)
	}
	if _, errRefresh := refresher.RefreshCredential(ctx, onboarding.Instance.ID, onboarding.Credential.ID); !errors.Is(errRefresh, coreprovider.ErrAuthenticationResponseInvalid) {
		t.Fatalf("RefreshCredential() error = %v, want invalid authentication response", errRefresh)
	}
	assertOriginalSecretPreserved(t, secrets, onboarding.Credential.SecretRef)
}

// TestXAITokenRefreshRejectsFallbackEmailChange verifies email ownership when the provider omits a stable subject.
// TestXAITokenRefreshRejectsFallbackEmailChange 验证供应商缺少稳定 Subject 时的邮箱所有权。
func TestXAITokenRefreshRejectsFallbackEmailChange(t *testing.T) {
	ctx := context.Background()
	service, configurations, secrets := newKimiOnboardingService(t)
	initial := providerxai.Token{AccessToken: "before", RefreshToken: "refresh-before", TokenEndpoint: "https://auth.x.ai/oauth/token", Email: "user@x.ai", Type: "xai"}
	encoded, errEncode := providerxai.MarshalToken(initial)
	if errEncode != nil {
		t.Fatalf("MarshalToken() error = %v", errEncode)
	}
	onboarding, errOnboard := service.OnboardXAIDeviceProvider(ctx, OnboardSystemProviderInput{DefinitionID: bootstrap.XAIOAuthDefinitionID, Handle: "xai-email-mismatch", DisplayName: "xAI Account", AuthMethodID: "device_flow", CredentialLabel: "xAI Account", Secret: encoded})
	if errOnboard != nil {
		t.Fatalf("OnboardXAIDeviceProvider() error = %v", errOnboard)
	}
	mismatch := initial
	mismatch.Email = "other@x.ai"
	refresher, errRefresher := NewXAITokenService(configurations, secrets, staticXAITokenClient{token: mismatch})
	if errRefresher != nil {
		t.Fatalf("NewXAITokenService() error = %v", errRefresher)
	}
	if _, errRefresh := refresher.RefreshCredential(ctx, onboarding.Instance.ID, onboarding.Credential.ID); !errors.Is(errRefresh, coreprovider.ErrAuthenticationResponseInvalid) {
		t.Fatalf("RefreshCredential() error = %v, want invalid authentication response", errRefresh)
	}
	assertOriginalSecretPreserved(t, secrets, onboarding.Credential.SecretRef)
}

// TestAntigravityTokenRefreshRejectsProjectChange verifies refresh cannot escape the onboarded Google project.
// TestAntigravityTokenRefreshRejectsProjectChange 验证刷新不能逃逸已录入的 Google Project。
func TestAntigravityTokenRefreshRejectsProjectChange(t *testing.T) {
	ctx := context.Background()
	service, configurations, secrets := newKimiOnboardingService(t)
	initial := providergoogle.AntigravityToken{AccessToken: "before", RefreshToken: "refresh-before", TokenType: "Bearer", Email: "user@example.com", ProjectID: "project-one", Type: "antigravity"}
	encoded, errEncode := providergoogle.MarshalAntigravityToken(initial)
	if errEncode != nil {
		t.Fatalf("MarshalAntigravityToken() error = %v", errEncode)
	}
	onboarding, errOnboard := service.OnboardAntigravityOAuthProvider(ctx, OnboardSystemProviderInput{DefinitionID: bootstrap.GoogleAntigravityDefinitionID, Handle: "antigravity-project-mismatch", DisplayName: "Google Antigravity", AuthMethodID: "oauth", Secret: encoded})
	if errOnboard != nil {
		t.Fatalf("OnboardAntigravityOAuthProvider() error = %v", errOnboard)
	}
	mismatch := initial
	mismatch.ProjectID = "project-two"
	refresher, errRefresher := NewAntigravityTokenService(configurations, secrets, staticAntigravityTokenClient{token: mismatch})
	if errRefresher != nil {
		t.Fatalf("NewAntigravityTokenService() error = %v", errRefresher)
	}
	if _, errRefresh := refresher.RefreshCredential(ctx, onboarding.Instance.ID, onboarding.Credential.ID); !errors.Is(errRefresh, coreprovider.ErrAuthenticationResponseInvalid) {
		t.Fatalf("RefreshCredential() error = %v, want invalid authentication response", errRefresh)
	}
	assertOriginalSecretPreserved(t, secrets, onboarding.Credential.SecretRef)
}

// TestClaudeTokenRefreshRejectsFallbackEmailChange verifies account email ownership when no UUID is available.
// TestClaudeTokenRefreshRejectsFallbackEmailChange 验证缺少 UUID 时的账号邮箱所有权。
func TestClaudeTokenRefreshRejectsFallbackEmailChange(t *testing.T) {
	ctx := context.Background()
	service, configurations, secrets := newKimiOnboardingService(t)
	now := time.Date(2026, 7, 19, 4, 0, 0, 0, time.UTC)
	initial := provideranthropic.ClaudeToken{AccessToken: "before", RefreshToken: "refresh-before", TokenType: "Bearer", ExpiresAt: now.Add(time.Hour).Unix(), LastRefreshAt: now.Unix(), Email: "user@example.com", Type: "claude"}
	encoded, errEncode := provideranthropic.MarshalClaudeToken(initial)
	if errEncode != nil {
		t.Fatalf("MarshalClaudeToken() error = %v", errEncode)
	}
	onboarding, errOnboard := service.OnboardClaudeOAuthProvider(ctx, OnboardSystemProviderInput{DefinitionID: bootstrap.AnthropicClaudeCodeDefinitionID, Handle: "claude-email-mismatch", DisplayName: "Claude Code", AuthMethodID: "oauth", Secret: encoded})
	if errOnboard != nil {
		t.Fatalf("OnboardClaudeOAuthProvider() error = %v", errOnboard)
	}
	mismatch := initial
	mismatch.Email = "other@example.com"
	mismatch.ExpiresAt = now.Add(2 * time.Hour).Unix()
	refresher, errRefresher := NewClaudeTokenService(configurations, secrets, staticClaudeTokenClient{token: mismatch})
	if errRefresher != nil {
		t.Fatalf("NewClaudeTokenService() error = %v", errRefresher)
	}
	if _, errRefresh := refresher.RefreshCredential(ctx, onboarding.Instance.ID, onboarding.Credential.ID); !errors.Is(errRefresh, coreprovider.ErrAuthenticationResponseInvalid) {
		t.Fatalf("RefreshCredential() error = %v, want invalid authentication response", errRefresh)
	}
	assertOriginalSecretPreserved(t, secrets, onboarding.Credential.SecretRef)
}

// assertOriginalSecretPreserved verifies a rejected refresh leaves the exact protected credential untouched.
// assertOriginalSecretPreserved 验证被拒绝的刷新保持精确的受保护凭据不变。
func assertOriginalSecretPreserved(t *testing.T, secrets *secret.MemoryStore, reference string) {
	t.Helper()
	if _, errSecret := secrets.Get(context.Background(), reference); errSecret != nil {
		t.Fatalf("original token was not preserved: %v", errSecret)
	}
	if secrets.Count() != 1 {
		t.Fatalf("secret count = %d, want 1", secrets.Count())
	}
}
