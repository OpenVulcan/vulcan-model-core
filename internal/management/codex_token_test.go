package management

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/bootstrap"
	coreprovider "github.com/OpenVulcan/vulcan-model-core/internal/provider"
	provideropenai "github.com/OpenVulcan/vulcan-model-core/internal/provider/openai"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

// codexManagementTestIDToken creates one structurally valid provider-issued identity document for management tests.
// codexManagementTestIDToken 为管理测试创建一份结构有效的供应商签发身份文档。
func codexManagementTestIDToken(accountID string, planType string) string {
	payload := fmt.Sprintf(`{"exp":4102444800,"email":"user@example.com","https://api.openai.com/auth":{"chatgpt_account_id":%q,"chatgpt_plan_type":%q}}`, accountID, planType)
	return "header." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
}

// staticCodexTokenClient returns one deterministic refreshed Codex document.
// staticCodexTokenClient 返回一个确定性的已刷新 Codex 文档。
type staticCodexTokenClient struct {
	// token is the deterministic refresh result.
	// token 是确定性的刷新结果。
	token provideropenai.CodexToken
}

// blockingCodexTokenClient exposes the refresh context lifetime to one focused cancellation test.
// blockingCodexTokenClient 向一个聚焦取消测试暴露刷新 Context 生命周期。
type blockingCodexTokenClient struct {
	// started closes after the shared refresh leader enters the provider client.
	// started 在共享刷新主请求进入供应商客户端后关闭。
	started chan struct{}
	// release unblocks the deterministic provider response.
	// release 解除确定性供应商响应的阻塞。
	release chan struct{}
	// token is the deterministic provider result.
	// token 是确定性的供应商结果。
	token provideropenai.CodexToken
}

// Refresh returns the configured Codex token.
// Refresh 返回配置的 Codex Token。
func (c staticCodexTokenClient) Refresh(context.Context, provideropenai.CodexToken) (provideropenai.CodexToken, error) {
	return c.token, nil
}

// Refresh verifies the shared leader has no caller cancellation channel and waits for release.
// Refresh 验证共享主请求没有调用方取消通道并等待解除阻塞。
func (c blockingCodexTokenClient) Refresh(ctx context.Context, _ provideropenai.CodexToken) (provideropenai.CodexToken, error) {
	close(c.started)
	if ctx.Done() != nil {
		return provideropenai.CodexToken{}, errors.New("shared Codex refresh inherited caller cancellation")
	}
	<-c.release
	return c.token, nil
}

// TestCodexTokenRefreshPreservesAccountAndExpiry verifies protected replacement and provider expiry propagation.
// TestCodexTokenRefreshPreservesAccountAndExpiry 验证受保护替换与供应商过期时间传播。
func TestCodexTokenRefreshPreservesAccountAndExpiry(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 19, 4, 0, 0, 0, time.UTC)
	service, configurations, secrets := newKimiOnboardingService(t)
	service.now = func() time.Time { return now }
	initial := provideropenai.CodexToken{IDToken: codexManagementTestIDToken("account-one", "plus"), AccessToken: "before", RefreshToken: "refresh-before", AccountID: "account-one", Email: "user@example.com", ExpiresAt: now.Add(time.Hour), Type: "codex"}
	encoded, errEncode := provideropenai.MarshalCodexToken(initial)
	if errEncode != nil {
		t.Fatalf("MarshalCodexToken() error = %v", errEncode)
	}
	onboarding, errOnboard := service.OnboardCodexDeviceProvider(ctx, OnboardSystemProviderInput{DefinitionID: bootstrap.OpenAICodexDefinitionID, Handle: "codex-refresh", DisplayName: "OpenAI Codex", AuthMethodID: "device_flow", CredentialLabel: "OpenAI Account", Secret: encoded})
	if errOnboard != nil {
		t.Fatalf("OnboardCodexDeviceProvider() error = %v", errOnboard)
	}
	oldReference := onboarding.Credential.SecretRef
	refreshedToken := provideropenai.CodexToken{IDToken: codexManagementTestIDToken("account-one", "plus"), AccessToken: "after", RefreshToken: "refresh-after", AccountID: "account-one", Email: "user@example.com", ExpiresAt: now.Add(2 * time.Hour), Type: "codex"}
	refresher, errRefresher := NewCodexTokenService(configurations, secrets, staticCodexTokenClient{token: refreshedToken})
	if errRefresher != nil {
		t.Fatalf("NewCodexTokenService() error = %v", errRefresher)
	}
	credential, errRefresh := refresher.RefreshCredential(ctx, onboarding.Instance.ID, onboarding.Credential.ID)
	if errRefresh != nil {
		t.Fatalf("RefreshCredential() error = %v", errRefresh)
	}
	if credential.Revision != 2 || credential.SecretRef == oldReference || credential.ExpiresAt == nil || !credential.ExpiresAt.Equal(refreshedToken.ExpiresAt) || len(credential.ScopeRefs) != 1 || credential.ScopeRefs[0].Kind != "account" || credential.ScopeRefs[0].ID != "account-one" {
		t.Fatalf("refreshed Codex credential = %#v", credential)
	}
	if _, errOld := secrets.Get(ctx, oldReference); !errors.Is(errOld, secret.ErrNotFound) {
		t.Fatalf("old secret error = %v, want ErrNotFound", errOld)
	}
	protected, errProtected := secrets.Get(ctx, credential.SecretRef)
	if errProtected != nil {
		t.Fatalf("read refreshed Codex token: %v", errProtected)
	}
	stored, errStored := provideropenai.UnmarshalCodexToken(protected)
	if errStored != nil || stored.AccessToken != "after" || stored.AccountID != "account-one" || !stored.ExpiresAt.Equal(refreshedToken.ExpiresAt) {
		t.Fatalf("stored Codex token = %#v, %v", stored, errStored)
	}
}

// TestCodexTokenRefreshRejectsAccountChange verifies a refresh cannot silently cross ChatGPT account ownership.
// TestCodexTokenRefreshRejectsAccountChange 验证刷新不能静默跨越 ChatGPT 账号所有权。
func TestCodexTokenRefreshRejectsAccountChange(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 19, 4, 0, 0, 0, time.UTC)
	service, configurations, secrets := newKimiOnboardingService(t)
	service.now = func() time.Time { return now }
	initial := provideropenai.CodexToken{IDToken: codexManagementTestIDToken("account-one", "plus"), AccessToken: "before", RefreshToken: "refresh-before", AccountID: "account-one", Email: "user@example.com", ExpiresAt: now.Add(time.Hour), Type: "codex"}
	encoded, errEncode := provideropenai.MarshalCodexToken(initial)
	if errEncode != nil {
		t.Fatalf("MarshalCodexToken() error = %v", errEncode)
	}
	onboarding, errOnboard := service.OnboardCodexDeviceProvider(ctx, OnboardSystemProviderInput{DefinitionID: bootstrap.OpenAICodexDefinitionID, Handle: "codex-mismatch", DisplayName: "OpenAI Codex", AuthMethodID: "device_flow", CredentialLabel: "OpenAI Account", Secret: encoded})
	if errOnboard != nil {
		t.Fatalf("OnboardCodexDeviceProvider() error = %v", errOnboard)
	}
	mismatch := initial
	mismatch.AccountID = "account-two"
	mismatch.IDToken = codexManagementTestIDToken("account-two", "plus")
	mismatch.ExpiresAt = now.Add(2 * time.Hour)
	refresher, errRefresher := NewCodexTokenService(configurations, secrets, staticCodexTokenClient{token: mismatch})
	if errRefresher != nil {
		t.Fatalf("NewCodexTokenService() error = %v", errRefresher)
	}
	if _, errRefresh := refresher.RefreshCredential(ctx, onboarding.Instance.ID, onboarding.Credential.ID); !errors.Is(errRefresh, coreprovider.ErrAuthenticationResponseInvalid) {
		t.Fatalf("RefreshCredential() error = %v, want invalid authentication response", errRefresh)
	}
	if _, errOld := secrets.Get(ctx, onboarding.Credential.SecretRef); errOld != nil {
		t.Fatalf("original Codex token was not preserved: %v", errOld)
	}
	if secrets.Count() != 1 {
		t.Fatalf("secret count = %d, want 1", secrets.Count())
	}
}

// TestCodexTokenRefreshLeaderOutlivesCallerCancellation verifies CLIProxyAPI's shared refresh lifetime.
// TestCodexTokenRefreshLeaderOutlivesCallerCancellation 验证 CLIProxyAPI 的共享刷新生命周期。
func TestCodexTokenRefreshLeaderOutlivesCallerCancellation(t *testing.T) {
	now := time.Date(2026, 7, 19, 4, 0, 0, 0, time.UTC)
	service, configurations, secrets := newKimiOnboardingService(t)
	service.now = func() time.Time { return now }
	initial := provideropenai.CodexToken{IDToken: codexManagementTestIDToken("account-one", "plus"), AccessToken: "before", RefreshToken: "refresh-before", AccountID: "account-one", Email: "user@example.com", ExpiresAt: now.Add(time.Hour), Type: "codex"}
	encoded, errEncode := provideropenai.MarshalCodexToken(initial)
	if errEncode != nil {
		t.Fatalf("MarshalCodexToken() error = %v", errEncode)
	}
	onboarding, errOnboard := service.OnboardCodexOAuthProvider(context.Background(), OnboardSystemProviderInput{DefinitionID: bootstrap.OpenAICodexDefinitionID, Handle: "codex-cancel", DisplayName: "OpenAI Codex", AuthMethodID: "oauth", CredentialLabel: "OpenAI Account", Secret: encoded})
	if errOnboard != nil {
		t.Fatalf("OnboardCodexOAuthProvider() error = %v", errOnboard)
	}
	providerClient := blockingCodexTokenClient{started: make(chan struct{}), release: make(chan struct{}), token: provideropenai.CodexToken{IDToken: initial.IDToken, AccessToken: "after", RefreshToken: "refresh-after", AccountID: initial.AccountID, Email: initial.Email, ExpiresAt: now.Add(2 * time.Hour), Type: "codex"}}
	refresher, errRefresher := NewCodexTokenService(configurations, secrets, providerClient)
	if errRefresher != nil {
		t.Fatalf("NewCodexTokenService() error = %v", errRefresher)
	}
	callerContext, cancelCaller := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, errRefresh := refresher.RefreshCredential(callerContext, onboarding.Instance.ID, onboarding.Credential.ID)
		result <- errRefresh
	}()
	<-providerClient.started
	cancelCaller()
	close(providerClient.release)
	if errRefresh := <-result; errRefresh != nil {
		t.Fatalf("RefreshCredential() error after caller cancellation = %v", errRefresh)
	}
}
