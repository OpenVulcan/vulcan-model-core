package management

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/bootstrap"
	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	coreprovider "github.com/OpenVulcan/vulcan-model-core/internal/provider"
	providergoogle "github.com/OpenVulcan/vulcan-model-core/internal/provider/google"
	providerkimi "github.com/OpenVulcan/vulcan-model-core/internal/provider/kimi"
	provideropenai "github.com/OpenVulcan/vulcan-model-core/internal/provider/openai"
	provideropenrouter "github.com/OpenVulcan/vulcan-model-core/internal/provider/openrouter"
	providerxai "github.com/OpenVulcan/vulcan-model-core/internal/provider/xai"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

// TestOnboardSystemProviderCommitsClosedKimiConfiguration verifies fixed endpoints, bindings, and secret compensation.
// TestOnboardSystemProviderCommitsClosedKimiConfiguration 验证固定端点、绑定和秘密补偿。
func TestOnboardSystemProviderCommitsClosedKimiConfiguration(t *testing.T) {
	ctx := context.Background()
	service, configurations, secrets := newKimiOnboardingService(t)
	onboarding, errOnboard := service.OnboardSystemProvider(ctx, OnboardSystemProviderInput{
		DefinitionID:    bootstrap.KimiCNDefinitionID,
		Handle:          "kimi-cn",
		DisplayName:     "Kimi CN",
		AuthMethodID:    "api_key",
		CredentialLabel: "Primary",
		Secret:          []byte("moonshot-secret"),
	})
	if errOnboard != nil {
		t.Fatalf("OnboardSystemProvider() error = %v", errOnboard)
	}
	if onboarding.Instance.Status != providerconfig.LifecycleReady || len(onboarding.Endpoints) != 1 || len(onboarding.Bindings) != 1 || onboarding.Endpoints[0].BaseURL != "https://api.moonshot.cn" {
		t.Fatalf("onboarding = %#v", onboarding)
	}
	modifiedEndpoint := onboarding.Endpoints[0]
	modifiedEndpoint.BaseURL = "https://api.moonshot.ai"
	modifiedEndpoint.Revision++
	if errEndpoint := configurations.SaveEndpoint(ctx, modifiedEndpoint); errEndpoint == nil {
		t.Fatal("SaveEndpoint() error = nil, want fixed-preset rejection")
	}
	_, errDuplicate := service.OnboardSystemProvider(ctx, OnboardSystemProviderInput{
		DefinitionID:    bootstrap.KimiCNDefinitionID,
		Handle:          "kimi-cn",
		DisplayName:     "Duplicate",
		AuthMethodID:    "api_key",
		CredentialLabel: "Duplicate",
		Secret:          []byte("temporary-secret"),
	})
	if errDuplicate == nil {
		t.Fatal("duplicate OnboardSystemProvider() error = nil")
	}
	if secrets.Count() != 1 {
		t.Fatalf("secret count = %d, want compensated count 1", secrets.Count())
	}
}

// TestOnboardSystemProviderCreatesEveryOpenRouterActionChannel verifies that native actions share one Origin through independently resolvable bindings.
// TestOnboardSystemProviderCreatesEveryOpenRouterActionChannel 验证原生动作通过独立可解析绑定共享一个 Origin。
func TestOnboardSystemProviderCreatesEveryOpenRouterActionChannel(t *testing.T) {
	ctx := context.Background()
	service, _, _ := newKimiOnboardingService(t)
	onboarding, errOnboard := service.OnboardSystemProvider(ctx, OnboardSystemProviderInput{
		DefinitionID: bootstrap.OpenRouterAPIDefinitionID, Handle: "openrouter-native", DisplayName: "OpenRouter Native",
		AuthMethodID: "api_key", CredentialLabel: "Primary", Secret: []byte("openrouter-secret"),
	})
	if errOnboard != nil {
		t.Fatalf("OnboardSystemProvider() error = %v", errOnboard)
	}
	if len(onboarding.Endpoints) != 1 || len(onboarding.Bindings) != 6 {
		t.Fatalf("OpenRouter endpoint/binding counts = %d/%d, want 1/6", len(onboarding.Endpoints), len(onboarding.Bindings))
	}
	channels := make(map[string]struct{}, len(onboarding.Bindings))
	for _, endpoint := range onboarding.Endpoints {
		if endpoint.BaseURL != "https://openrouter.ai/api" {
			t.Fatalf("OpenRouter endpoint base URL = %q", endpoint.BaseURL)
		}
	}
	for _, binding := range onboarding.Bindings {
		if binding.EndpointID != onboarding.Endpoints[0].ID {
			t.Fatalf("OpenRouter binding endpoint = %q, want shared endpoint %q", binding.EndpointID, onboarding.Endpoints[0].ID)
		}
		channels[binding.ChannelID] = struct{}{}
	}
	for _, channelID := range []string{"openrouter.embeddings.v1", provideropenrouter.ImageGenerateProtocolProfileID, "openrouter.rerank.v1", provideropenrouter.SpeechSynthesizeProtocolProfileID, provideropenrouter.SpeechTranscribeProtocolProfileID} {
		if _, exists := channels[channelID]; !exists {
			t.Fatalf("OpenRouter channel %q is missing from %#v", channelID, channels)
		}
	}
}

// TestOnboardSystemProviderRejectsInteractiveCredentialInjection verifies the generic secret boundary cannot impersonate device authorization.
// TestOnboardSystemProviderRejectsInteractiveCredentialInjection 验证通用秘密边界无法冒充设备授权。
func TestOnboardSystemProviderRejectsInteractiveCredentialInjection(t *testing.T) {
	ctx := context.Background()
	service, configurations, secrets := newKimiOnboardingService(t)
	deviceToken, errMarshal := providerkimi.MarshalToken(providerkimi.Token{AccessToken: "access", RefreshToken: "refresh", TokenType: "Bearer", DeviceID: "device", Type: "kimi"})
	if errMarshal != nil {
		t.Fatalf("MarshalToken() error = %v", errMarshal)
	}
	_, errOnboard := service.OnboardSystemProvider(ctx, OnboardSystemProviderInput{
		DefinitionID:    bootstrap.KimiCodingDefinitionID,
		Handle:          "forged-device-flow",
		DisplayName:     "Forged Device Flow",
		AuthMethodID:    "device_flow",
		CredentialLabel: "Untrusted",
		Secret:          deviceToken,
	})
	if errOnboard == nil {
		t.Fatal("OnboardSystemProvider() error = nil, want interactive-credential rejection")
	}
	if secrets.Count() != 0 {
		t.Fatalf("secret count = %d, want 0", secrets.Count())
	}
	instances, errInstances := configurations.ListInstances(ctx, bootstrap.KimiCodingDefinitionID)
	if errInstances != nil {
		t.Fatalf("ListInstances() error = %v", errInstances)
	}
	if len(instances) != 0 {
		t.Fatalf("instance count = %d, want 0", len(instances))
	}
}

// TestGenericCredentialMutationsRejectInteractiveSecretInjection verifies alternate credential routes cannot bypass the server-owned device flow.
// TestGenericCredentialMutationsRejectInteractiveSecretInjection 验证其他凭据路由无法绕过服务端拥有的设备授权流程。
func TestGenericCredentialMutationsRejectInteractiveSecretInjection(t *testing.T) {
	ctx := context.Background()
	service, _, secrets := newKimiOnboardingService(t)
	instance, errInstance := service.CreateInstance(ctx, CreateInstanceInput{DefinitionID: bootstrap.KimiCodingDefinitionID, Handle: "kimi-generic", DisplayName: "Kimi Generic"})
	if errInstance != nil {
		t.Fatalf("CreateInstance() error = %v", errInstance)
	}
	if _, errAdd := service.AddCredential(ctx, AddCredentialInput{ProviderInstanceID: instance.ID, AuthMethodID: "device_flow", Label: "Forged", Secret: []byte("forged")}); errAdd == nil {
		t.Fatal("AddCredential() error = nil, want interactive-credential rejection")
	}
	if secrets.Count() != 0 {
		t.Fatalf("secret count after AddCredential() = %d, want 0", secrets.Count())
	}

	deviceToken, errMarshal := providerkimi.MarshalToken(providerkimi.Token{AccessToken: "access", RefreshToken: "refresh", TokenType: "Bearer", DeviceID: "device", Type: "kimi"})
	if errMarshal != nil {
		t.Fatalf("MarshalToken() error = %v", errMarshal)
	}
	onboarding, errOnboard := service.OnboardKimiDeviceProvider(ctx, OnboardSystemProviderInput{DefinitionID: bootstrap.KimiCodingDefinitionID, Handle: "kimi-trusted", DisplayName: "Kimi Trusted", AuthMethodID: "device_flow", CredentialLabel: "Trusted", Secret: deviceToken})
	if errOnboard != nil {
		t.Fatalf("OnboardKimiDeviceProvider() error = %v", errOnboard)
	}
	if _, errRotate := service.RotateCredentialSecret(ctx, RotateCredentialSecretInput{ProviderInstanceID: onboarding.Instance.ID, CredentialID: onboarding.Credential.ID, Secret: []byte("forged replacement")}); errRotate == nil {
		t.Fatal("RotateCredentialSecret() error = nil, want interactive-credential rejection")
	}
	if secrets.Count() != 1 {
		t.Fatalf("secret count after RotateCredentialSecret() = %d, want 1", secrets.Count())
	}
}

// TestKimiTokenServiceRefreshesProtectedCredential verifies token replacement, metadata revision, and old-secret cleanup.
// TestKimiTokenServiceRefreshesProtectedCredential 验证令牌替换、元数据修订和旧秘密清理。
func TestKimiTokenServiceRefreshesProtectedCredential(t *testing.T) {
	ctx := context.Background()
	service, configurations, secrets := newKimiOnboardingService(t)
	initialToken, errToken := providerkimi.MarshalToken(providerkimi.Token{AccessToken: "before", RefreshToken: "refresh-before", TokenType: "Bearer", DeviceID: "device", Type: "kimi"})
	if errToken != nil {
		t.Fatalf("MarshalToken() error = %v", errToken)
	}
	onboarding, errOnboard := service.OnboardKimiDeviceProvider(ctx, OnboardSystemProviderInput{DefinitionID: bootstrap.KimiCodingDefinitionID, Handle: "kimi-refresh", DisplayName: "Kimi Coding", AuthMethodID: "device_flow", CredentialLabel: "Kimi User", Secret: initialToken})
	if errOnboard != nil {
		t.Fatalf("OnboardKimiDeviceProvider() error = %v", errOnboard)
	}
	oldReference := onboarding.Credential.SecretRef
	refresher, errRefresher := NewKimiTokenService(configurations, secrets, staticKimiTokenClient{token: providerkimi.Token{AccessToken: "after", RefreshToken: "refresh-after", TokenType: "Bearer", DeviceID: "device", ExpiresAt: time.Now().Add(time.Hour).Unix(), Type: "kimi"}})
	if errRefresher != nil {
		t.Fatalf("NewKimiTokenService() error = %v", errRefresher)
	}
	credential, errRefresh := refresher.RefreshCredential(ctx, onboarding.Instance.ID, onboarding.Credential.ID)
	if errRefresh != nil {
		t.Fatalf("RefreshCredential() error = %v", errRefresh)
	}
	if credential.Revision != 2 || credential.SecretRef == oldReference || credential.ExpiresAt == nil {
		t.Fatalf("refreshed credential = %#v", credential)
	}
	if _, errOld := secrets.Get(ctx, oldReference); !errors.Is(errOld, secret.ErrNotFound) {
		t.Fatalf("old secret error = %v, want ErrNotFound", errOld)
	}
	stored, errStored := secrets.Get(ctx, credential.SecretRef)
	if errStored != nil {
		t.Fatalf("new secret error = %v", errStored)
	}
	token, errDecode := providerkimi.UnmarshalToken(stored)
	if errDecode != nil || token.AccessToken != "after" {
		t.Fatalf("stored token=%#v error=%v", token, errDecode)
	}
}

// TestKimiTokenServiceRejectsDeviceIdentityChange verifies refresh cannot replace the provider-bound device identity.
// TestKimiTokenServiceRejectsDeviceIdentityChange 验证刷新不能替换供应商绑定的设备身份。
func TestKimiTokenServiceRejectsDeviceIdentityChange(t *testing.T) {
	ctx := context.Background()
	service, configurations, secrets := newKimiOnboardingService(t)
	initialToken, errToken := providerkimi.MarshalToken(providerkimi.Token{AccessToken: "before", RefreshToken: "refresh-before", TokenType: "Bearer", DeviceID: "device-one", Type: "kimi"})
	if errToken != nil {
		t.Fatalf("MarshalToken() error = %v", errToken)
	}
	onboarding, errOnboard := service.OnboardKimiDeviceProvider(ctx, OnboardSystemProviderInput{DefinitionID: bootstrap.KimiCodingDefinitionID, Handle: "kimi-device-mismatch", DisplayName: "Kimi Coding", AuthMethodID: "device_flow", Secret: initialToken})
	if errOnboard != nil {
		t.Fatalf("OnboardKimiDeviceProvider() error = %v", errOnboard)
	}
	refreshedToken := providerkimi.Token{AccessToken: "after", RefreshToken: "refresh-after", TokenType: "Bearer", DeviceID: "device-two", ExpiresAt: time.Now().Add(time.Hour).Unix(), Type: "kimi"}
	refresher, errRefresher := NewKimiTokenService(configurations, secrets, staticKimiTokenClient{token: refreshedToken})
	if errRefresher != nil {
		t.Fatalf("NewKimiTokenService() error = %v", errRefresher)
	}
	if _, errRefresh := refresher.RefreshCredential(ctx, onboarding.Instance.ID, onboarding.Credential.ID); !errors.Is(errRefresh, coreprovider.ErrAuthenticationResponseInvalid) {
		t.Fatalf("RefreshCredential() error = %v, want invalid authentication response", errRefresh)
	}
}

// TestKimiTokenServiceRejectsNonKimiDefinition verifies provider-specific refresh cannot be selected by user-owned metadata.
// TestKimiTokenServiceRejectsNonKimiDefinition 验证用户拥有的元数据无法选择供应商专用刷新器。
func TestKimiTokenServiceRejectsNonKimiDefinition(t *testing.T) {
	ctx := context.Background()
	service, configurations, secrets := newKimiOnboardingService(t)
	definition, errDefinition := service.CreateCustomDefinition(ctx, CreateCustomDefinitionInput{ID: "custom_refresh_target", DisplayName: "Custom Refresh Target", ProtocolProfileID: "openai.chat", AuthMethod: providerconfig.AuthMethodBearer})
	if errDefinition != nil {
		t.Fatalf("CreateCustomDefinition() error = %v", errDefinition)
	}
	instance, errInstance := service.CreateInstance(ctx, CreateInstanceInput{DefinitionID: definition.ID, Handle: "custom-device-flow", DisplayName: "Custom Device Flow"})
	if errInstance != nil {
		t.Fatalf("CreateInstance() error = %v", errInstance)
	}
	refresher, errRefresher := NewKimiTokenService(configurations, secrets, staticKimiTokenClient{})
	if errRefresher != nil {
		t.Fatalf("NewKimiTokenService() error = %v", errRefresher)
	}
	if _, errRefresh := refresher.RefreshCredential(ctx, instance.ID, "cred_missing"); errRefresh == nil {
		t.Fatal("RefreshCredential() error = nil, want exact-definition rejection")
	}
}

// staticKimiTokenClient returns one deterministic replacement token.
// staticKimiTokenClient 返回一个确定性的替换令牌。
type staticKimiTokenClient struct {
	// token is the deterministic replacement returned by Refresh.
	// token 是 Refresh 返回的确定性替换令牌。
	token providerkimi.Token
}

// Refresh returns the configured replacement without network access.
// Refresh 在不访问网络的情况下返回配置的替换令牌。
func (c staticKimiTokenClient) Refresh(context.Context, providerkimi.Token) (providerkimi.Token, error) {
	return c.token, nil
}

// blockingKimiTokenClient counts and blocks refresh calls so concurrent service coordination is observable.
// blockingKimiTokenClient 统计并阻塞刷新调用，以便观察服务并发协调行为。
type blockingKimiTokenClient struct {
	// mu protects the upstream call count.
	// mu 保护上游调用计数。
	mu sync.Mutex
	// calls records provider refresh exchanges.
	// calls 记录供应商刷新交换次数。
	calls int
	// started closes when the first exchange reaches the client.
	// started 在第一次交换到达客户端时关闭。
	started chan struct{}
	// release unblocks deterministic refresh completion.
	// release 解除确定性刷新完成的阻塞。
	release chan struct{}
	// token is the deterministic shared refresh result.
	// token 是确定性的共享刷新结果。
	token providerkimi.Token
}

// Refresh records one upstream exchange and waits until the test releases it.
// Refresh 记录一次上游交换并等待测试释放。
func (c *blockingKimiTokenClient) Refresh(context.Context, providerkimi.Token) (providerkimi.Token, error) {
	c.mu.Lock()
	c.calls++
	if c.calls == 1 {
		close(c.started)
	}
	c.mu.Unlock()
	<-c.release
	return c.token, nil
}

// callCount returns the synchronized number of upstream refresh exchanges.
// callCount 返回同步后的上游刷新交换次数。
func (c *blockingKimiTokenClient) callCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// TestKimiTokenServiceCoalescesConcurrentRefreshes verifies one credential cannot rotate the same refresh token twice concurrently.
// TestKimiTokenServiceCoalescesConcurrentRefreshes 验证同一凭据不能并发轮换同一个 Refresh Token 两次。
func TestKimiTokenServiceCoalescesConcurrentRefreshes(t *testing.T) {
	ctx := context.Background()
	service, configurations, secrets := newKimiOnboardingService(t)
	initialToken, errToken := providerkimi.MarshalToken(providerkimi.Token{AccessToken: "before", RefreshToken: "refresh-before", TokenType: "Bearer", DeviceID: "device", Type: "kimi"})
	if errToken != nil {
		t.Fatalf("MarshalToken() error = %v", errToken)
	}
	onboarding, errOnboard := service.OnboardKimiDeviceProvider(ctx, OnboardSystemProviderInput{DefinitionID: bootstrap.KimiCodingDefinitionID, Handle: "kimi-concurrent-refresh", DisplayName: "Kimi Concurrent Refresh", AuthMethodID: "device_flow", CredentialLabel: "Kimi User", Secret: initialToken})
	if errOnboard != nil {
		t.Fatalf("OnboardKimiDeviceProvider() error = %v", errOnboard)
	}
	client := &blockingKimiTokenClient{started: make(chan struct{}), release: make(chan struct{}), token: providerkimi.Token{AccessToken: "after", RefreshToken: "refresh-after", TokenType: "Bearer", DeviceID: "device", Type: "kimi"}}
	refresher, errRefresher := NewKimiTokenService(configurations, secrets, client)
	if errRefresher != nil {
		t.Fatalf("NewKimiTokenService() error = %v", errRefresher)
	}
	// results collects both callers without relying on scheduling order.
	// results 收集两个调用方的结果且不依赖调度顺序。
	results := make(chan providerconfig.Credential, 2)
	errorsChannel := make(chan error, 2)
	refresh := func() {
		credential, errRefresh := refresher.RefreshCredential(ctx, onboarding.Instance.ID, onboarding.Credential.ID)
		results <- credential
		errorsChannel <- errRefresh
	}
	go refresh()
	<-client.started
	go refresh()
	refreshKey := onboarding.Instance.ID + "\x00" + onboarding.Credential.ID
	joinDeadline := time.Now().Add(time.Second)
	for {
		refresher.refreshMu.Lock()
		call := refresher.refreshCalls[refreshKey]
		joined := call != nil && call.waiters == 1
		refresher.refreshMu.Unlock()
		if joined {
			break
		}
		if time.Now().After(joinDeadline) {
			t.Fatal("second refresh did not join the in-flight operation")
		}
		runtime.Gosched()
	}
	close(client.release)
	first, second := <-results, <-results
	firstError, secondError := <-errorsChannel, <-errorsChannel
	if firstError != nil || secondError != nil {
		t.Fatalf("refresh errors = %v, %v", firstError, secondError)
	}
	if client.callCount() != 1 || first.SecretRef != second.SecretRef || first.Revision != 2 || second.Revision != 2 {
		t.Fatalf("calls=%d first=%#v second=%#v", client.callCount(), first, second)
	}
}

// TestOnboardKimiCodingPlanUsesDeviceFlowWithPreferredProtocol verifies one refreshed token closes the sole preferred protocol.
// TestOnboardKimiCodingPlanUsesDeviceFlowWithPreferredProtocol 验证一个刷新令牌闭合唯一的优势协议。
func TestOnboardKimiCodingPlanUsesDeviceFlowWithPreferredProtocol(t *testing.T) {
	service, _, _ := newKimiOnboardingService(t)
	deviceToken, errMarshal := providerkimi.MarshalToken(providerkimi.Token{AccessToken: "access", RefreshToken: "refresh", TokenType: "Bearer", DeviceID: "device", Type: "kimi"})
	if errMarshal != nil {
		t.Fatalf("MarshalToken() error = %v", errMarshal)
	}
	onboarding, errOnboard := service.OnboardKimiDeviceProvider(context.Background(), OnboardSystemProviderInput{
		DefinitionID:    bootstrap.KimiCodingDefinitionID,
		Handle:          "kimi-coding",
		DisplayName:     "Kimi Coding Plan",
		AuthMethodID:    "device_flow",
		CredentialLabel: "Kimi User",
		PrincipalKey:    "kimi-user",
		Secret:          deviceToken,
	})
	if errOnboard != nil {
		t.Fatalf("OnboardKimiDeviceProvider() error = %v", errOnboard)
	}
	if len(onboarding.Endpoints) != 1 || len(onboarding.Bindings) != 1 || onboarding.Credential.AuthMethodID != "device_flow" {
		t.Fatalf("Coding onboarding = %#v", onboarding)
	}
}

// TestXAIAccountOnboardingAndRefreshPreserveProtectedTokens verifies the server-owned xAI flow and durable replacement boundary.
// TestXAIAccountOnboardingAndRefreshPreserveProtectedTokens 验证服务端拥有的 xAI 流程与持久替换边界。
func TestXAIAccountOnboardingAndRefreshPreserveProtectedTokens(t *testing.T) {
	ctx := context.Background()
	service, configurations, secrets := newKimiOnboardingService(t)
	initialToken, errToken := providerxai.MarshalToken(providerxai.Token{AccessToken: "before", RefreshToken: "refresh-before", IDToken: "identity", TokenEndpoint: "https://auth.x.ai/oauth/token", Email: "user@x.ai", Subject: "subject-one", Type: "xai"})
	if errToken != nil {
		t.Fatalf("MarshalToken() error = %v", errToken)
	}
	if _, errGeneric := service.OnboardSystemProvider(ctx, OnboardSystemProviderInput{DefinitionID: bootstrap.XAIOAuthDefinitionID, Handle: "xai-forged", DisplayName: "xAI Forged", AuthMethodID: "device_flow", CredentialLabel: "xAI", Secret: initialToken}); errGeneric == nil {
		t.Fatal("OnboardSystemProvider() accepted an injected xAI device token")
	}
	onboarding, errOnboard := service.OnboardXAIDeviceProvider(ctx, OnboardSystemProviderInput{DefinitionID: bootstrap.XAIOAuthDefinitionID, Handle: "xai-account", DisplayName: "xAI Account", AuthMethodID: "device_flow", CredentialLabel: "xAI", PrincipalKey: "forged", Secret: initialToken})
	if errOnboard != nil {
		t.Fatalf("OnboardXAIDeviceProvider() error = %v", errOnboard)
	}
	if onboarding.Credential.PrincipalKey != "subject-one" {
		t.Fatalf("xAI principal = %q, want subject-one", onboarding.Credential.PrincipalKey)
	}
	oldReference := onboarding.Credential.SecretRef
	refresher, errRefresher := NewXAITokenService(configurations, secrets, staticXAITokenClient{token: providerxai.Token{AccessToken: "after", RefreshToken: "refresh-after", IDToken: "identity", ExpiresAt: time.Now().Add(time.Hour).Unix(), TokenEndpoint: "https://auth.x.ai/oauth/token", Email: "user@x.ai", Subject: "subject-one", Type: "xai"}})
	if errRefresher != nil {
		t.Fatalf("NewXAITokenService() error = %v", errRefresher)
	}
	credential, errRefresh := refresher.RefreshCredential(ctx, onboarding.Instance.ID, onboarding.Credential.ID)
	if errRefresh != nil {
		t.Fatalf("RefreshCredential() error = %v", errRefresh)
	}
	if credential.Revision != 2 || credential.SecretRef == oldReference || credential.ExpiresAt == nil {
		t.Fatalf("refreshed credential = %#v", credential)
	}
	if _, errOld := secrets.Get(ctx, oldReference); !errors.Is(errOld, secret.ErrNotFound) {
		t.Fatalf("old secret error = %v, want ErrNotFound", errOld)
	}
	stored, errStored := secrets.Get(ctx, credential.SecretRef)
	if errStored != nil {
		t.Fatalf("new secret error = %v", errStored)
	}
	token, errDecode := providerxai.UnmarshalToken(stored)
	if errDecode != nil || token.AccessToken != "after" {
		t.Fatalf("stored token=%#v error=%v", token, errDecode)
	}
}

// staticXAITokenClient returns one deterministic refreshed xAI document.
// staticXAITokenClient 返回一个确定性的已刷新 xAI 文档。
type staticXAITokenClient struct {
	// token is the deterministic refresh result.
	// token 是确定性的刷新结果。
	token providerxai.Token
}

// Refresh returns the configured xAI token.
// Refresh 返回配置的 xAI Token。
func (c staticXAITokenClient) Refresh(context.Context, providerxai.Token) (providerxai.Token, error) {
	return c.token, nil
}

// TestCodexOnboardingDerivesPrincipalFromProtectedToken verifies operator input cannot forge account ownership.
// TestCodexOnboardingDerivesPrincipalFromProtectedToken 验证操作员输入不能伪造账号所有权。
func TestCodexOnboardingDerivesPrincipalFromProtectedToken(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	service, _, _ := newKimiOnboardingService(t)
	service.now = func() time.Time { return now }
	encoded, errEncode := provideropenai.MarshalCodexToken(provideropenai.CodexToken{IDToken: codexManagementTestIDToken("account-one", "team"), AccessToken: "access", RefreshToken: "refresh", AccountID: "account-one", Email: "user@example.com", ExpiresAt: now.Add(time.Hour), Type: "codex"})
	if errEncode != nil {
		t.Fatalf("MarshalCodexToken() error = %v", errEncode)
	}
	onboarding, errOnboard := service.OnboardCodexDeviceProvider(context.Background(), OnboardSystemProviderInput{DefinitionID: bootstrap.OpenAICodexDefinitionID, Handle: "openai-codex", DisplayName: "OpenAI Codex", AuthMethodID: "device_flow", CredentialLabel: "OpenAI Account", PrincipalKey: "forged", Secret: encoded})
	if errOnboard != nil {
		t.Fatalf("OnboardCodexDeviceProvider() error = %v", errOnboard)
	}
	if onboarding.Credential.PrincipalKey != "account-one" || len(onboarding.Credential.ScopeRefs) != 1 || onboarding.Credential.ScopeRefs[0] != (providerconfig.ScopeReference{Kind: "account", ID: "account-one"}) {
		t.Fatalf("Codex credential identity = %#v", onboarding.Credential)
	}
	snapshot, errSnapshot := service.catalogs.Get(context.Background(), onboarding.Instance.ID)
	if errSnapshot != nil {
		t.Fatalf("read initial Codex catalog: %v", errSnapshot)
	}
	if len(snapshot.Plans) != 1 || snapshot.Plans[0].PlanCode != "team" || len(snapshot.Entitlements) != 7 {
		t.Fatalf("initial Codex metadata = plans %#v entitlements %#v", snapshot.Plans, snapshot.Entitlements)
	}
	for _, entitlement := range snapshot.Entitlements {
		if entitlement.ProviderModelID == "model_gpt_5_3_codex_spark" {
			t.Fatal("team account received the Plus/Pro-only Codex Spark entitlement")
		}
	}
}

// TestCodexOnboardingRejectsMissingAccountScope verifies an email-only token cannot create an execution path that lacks the required ChatGPT account header.
// TestCodexOnboardingRejectsMissingAccountScope 验证仅含邮箱的 Token 不能创建缺少必要 ChatGPT 账号请求头的执行路径。
func TestCodexOnboardingRejectsMissingAccountScope(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	service, _, _ := newKimiOnboardingService(t)
	service.now = func() time.Time { return now }
	encoded, errEncode := provideropenai.MarshalCodexToken(provideropenai.CodexToken{IDToken: codexManagementTestIDToken("account-one", "team"), AccessToken: "access", RefreshToken: "refresh", Email: "user@example.com", ExpiresAt: now.Add(time.Hour), Type: "codex"})
	if errEncode != nil {
		t.Fatalf("MarshalCodexToken() error = %v", errEncode)
	}
	if _, errOnboard := service.OnboardCodexOAuthProvider(context.Background(), OnboardSystemProviderInput{DefinitionID: bootstrap.OpenAICodexDefinitionID, Handle: "openai-codex-email-only", DisplayName: "OpenAI Codex", AuthMethodID: "oauth", Secret: encoded}); errOnboard == nil {
		t.Fatal("OnboardCodexOAuthProvider() accepted a token without ChatGPT account scope")
	}
}

// TestAntigravityOnboardingAndRefreshPreserveProjectScope verifies protected OAuth storage and immutable project ownership.
// TestAntigravityOnboardingAndRefreshPreserveProjectScope 验证受保护 OAuth 存储与不可变项目所有权。
func TestAntigravityOnboardingAndRefreshPreserveProjectScope(t *testing.T) {
	ctx := context.Background()
	service, configurations, secrets := newKimiOnboardingService(t)
	initialToken, errToken := providergoogle.MarshalAntigravityToken(providergoogle.AntigravityToken{AccessToken: "before", RefreshToken: "refresh-before", TokenType: "Bearer", Email: "user@example.com", ProjectID: "project-one", ExpiresAt: time.Now().Add(time.Hour).Unix(), Type: "antigravity"})
	if errToken != nil {
		t.Fatalf("MarshalAntigravityToken() error = %v", errToken)
	}
	input := OnboardSystemProviderInput{DefinitionID: bootstrap.GoogleAntigravityDefinitionID, Handle: "google-antigravity", DisplayName: "Google Antigravity", AuthMethodID: "oauth", CredentialLabel: "Google Account", PrincipalKey: "forged", Secret: initialToken, ScopeRefs: []providerconfig.ScopeReference{{Kind: "project", ID: "forged"}}}
	if _, errGeneric := service.OnboardSystemProvider(ctx, input); errGeneric == nil {
		t.Fatal("OnboardSystemProvider() accepted an injected Antigravity OAuth token")
	}
	onboarding, errOnboard := service.OnboardAntigravityOAuthProvider(ctx, input)
	if errOnboard != nil {
		t.Fatalf("OnboardAntigravityOAuthProvider() error = %v", errOnboard)
	}
	if len(onboarding.Credential.ScopeRefs) != 1 || onboarding.Credential.ScopeRefs[0] != (providerconfig.ScopeReference{Kind: "project", ID: "project-one"}) {
		t.Fatalf("project scopes = %#v", onboarding.Credential.ScopeRefs)
	}
	if onboarding.Credential.PrincipalKey != "user@example.com" {
		t.Fatalf("Antigravity principal = %q, want user@example.com", onboarding.Credential.PrincipalKey)
	}
	oldReference := onboarding.Credential.SecretRef
	refresher, errRefresher := NewAntigravityTokenService(configurations, secrets, staticAntigravityTokenClient{token: providergoogle.AntigravityToken{AccessToken: "after", RefreshToken: "refresh-after", TokenType: "Bearer", Email: "user@example.com", ProjectID: "project-one", ExpiresAt: time.Now().Add(2 * time.Hour).Unix(), Type: "antigravity"}})
	if errRefresher != nil {
		t.Fatalf("NewAntigravityTokenService() error = %v", errRefresher)
	}
	credential, errRefresh := refresher.RefreshCredential(ctx, onboarding.Instance.ID, onboarding.Credential.ID)
	if errRefresh != nil {
		t.Fatalf("RefreshCredential() error = %v", errRefresh)
	}
	if credential.Revision != 2 || credential.SecretRef == oldReference || len(credential.ScopeRefs) != 1 || credential.ScopeRefs[0].ID != "project-one" {
		t.Fatalf("refreshed credential = %#v", credential)
	}
	if _, errOld := secrets.Get(ctx, oldReference); !errors.Is(errOld, secret.ErrNotFound) {
		t.Fatalf("old secret error = %v, want ErrNotFound", errOld)
	}
	stored, errStored := secrets.Get(ctx, credential.SecretRef)
	if errStored != nil {
		t.Fatalf("new secret error = %v", errStored)
	}
	token, errDecode := providergoogle.UnmarshalAntigravityToken(stored)
	if errDecode != nil || token.AccessToken != "after" || token.ProjectID != "project-one" {
		t.Fatalf("stored token=%#v error=%v", token, errDecode)
	}
}

// TestVertexOnboardingDerivesAndLocksServiceAccountScope verifies protected normalization and immutable regional ownership.
// TestVertexOnboardingDerivesAndLocksServiceAccountScope 校验受保护规范化与不可变区域所有权。
func TestVertexOnboardingDerivesAndLocksServiceAccountScope(t *testing.T) {
	ctx := context.Background()
	service, configurations, secrets := newKimiOnboardingService(t)
	rawCredential := vertexServiceAccountFixture(t)
	genericCredential := append([]byte(nil), rawCredential...)
	input := OnboardSystemProviderInput{
		DefinitionID: bootstrap.GoogleVertexDefinitionID, Handle: "google-vertex", DisplayName: "Vertex Production",
		AuthMethodID: "service_account", PrincipalKey: "forged@example.com", Secret: genericCredential,
		ScopeRefs: []providerconfig.ScopeReference{{Kind: "project", ID: "forged-project"}},
	}
	if _, errGeneric := service.OnboardSystemProvider(ctx, input); errGeneric == nil {
		t.Fatalf("generic onboarding accepted an injected Vertex service account")
	}
	input.Secret = rawCredential
	onboarding, errOnboard := service.OnboardVertexServiceAccountProvider(ctx, input, "europe-west1")
	if errOnboard != nil {
		t.Fatalf("OnboardVertexServiceAccountProvider() error = %v", errOnboard)
	}
	if onboarding.Credential.PrincipalKey != "vertex@vertex-project.iam.gserviceaccount.com" || onboarding.Credential.Label != "vertex@vertex-project.iam.gserviceaccount.com" {
		t.Fatalf("derived Vertex credential metadata = %#v", onboarding.Credential)
	}
	if len(onboarding.Credential.ScopeRefs) != 1 || onboarding.Credential.ScopeRefs[0] != (providerconfig.ScopeReference{Kind: "project", ID: "vertex-project"}) {
		t.Fatalf("derived Vertex project scope = %#v", onboarding.Credential.ScopeRefs)
	}
	if len(onboarding.Endpoints) != 1 || onboarding.Endpoints[0].Region != "europe-west1" || onboarding.Endpoints[0].BaseURL != "https://europe-west1-aiplatform.googleapis.com" {
		t.Fatalf("derived Vertex endpoint = %#v", onboarding.Endpoints)
	}
	if _, errAdd := service.AddCredential(ctx, AddCredentialInput{ProviderInstanceID: onboarding.Instance.ID, AuthMethodID: "service_account", Label: "Forged", Secret: []byte("forged")}); errAdd == nil {
		t.Fatal("AddCredential() accepted a generic Vertex service-account secret")
	}
	if _, errRotate := service.RotateCredentialSecret(ctx, RotateCredentialSecretInput{ProviderInstanceID: onboarding.Instance.ID, CredentialID: onboarding.Credential.ID, Secret: []byte("forged replacement")}); errRotate == nil {
		t.Fatal("RotateCredentialSecret() accepted a generic Vertex service-account secret")
	}
	if secrets.Count() != 1 {
		t.Fatalf("secret count after generic Vertex mutations = %d, want 1", secrets.Count())
	}
	if _, errUpdate := service.UpdateCredential(ctx, UpdateCredentialInput{ProviderInstanceID: onboarding.Instance.ID, CredentialID: onboarding.Credential.ID, Label: "Forged", PrincipalKey: "forged@example.com", ScopeRefs: []providerconfig.ScopeReference{{Kind: "project", ID: "forged-project"}}}); errUpdate == nil {
		t.Fatal("UpdateCredential() accepted forged Vertex identity metadata")
	}
	renamed, errRename := service.UpdateCredential(ctx, UpdateCredentialInput{ProviderInstanceID: onboarding.Instance.ID, CredentialID: onboarding.Credential.ID, Label: "Vertex Renamed"})
	if errRename != nil {
		t.Fatalf("UpdateCredential() label-only error = %v", errRename)
	}
	if renamed.Label != "Vertex Renamed" || renamed.PrincipalKey != onboarding.Credential.PrincipalKey || !slices.Equal(renamed.ScopeRefs, onboarding.Credential.ScopeRefs) {
		t.Fatalf("label-only Vertex update changed provider-owned metadata = %#v", renamed)
	}
	for index, value := range rawCredential {
		if value != 0 {
			t.Fatalf("raw service-account upload was not cleared at byte %d", index)
		}
	}
	protected, errProtected := secrets.Get(ctx, onboarding.Credential.SecretRef)
	if errProtected != nil {
		t.Fatalf("read protected Vertex credential: %v", errProtected)
	}
	credential, errCredential := providergoogle.UnmarshalVertexCredential(protected)
	if errCredential != nil || credential.ProjectID != "vertex-project" || credential.Location != "europe-west1" {
		t.Fatalf("stored Vertex credential = %#v error=%v", credential, errCredential)
	}
	changedEndpoint := onboarding.Endpoints[0]
	changedEndpoint.Region = "asia-east1"
	changedEndpoint.BaseURL = "https://asia-east1-aiplatform.googleapis.com"
	changedEndpoint.Revision++
	if errSave := configurations.SaveEndpoint(ctx, changedEndpoint); errSave == nil {
		t.Fatalf("provider-derived Vertex endpoint changed after onboarding")
	}
}

// vertexServiceAccountFixture creates one valid generated Google service-account upload.
// vertexServiceAccountFixture 创建一个有效的动态 Google 服务账号上传 Fixture。
func vertexServiceAccountFixture(t *testing.T) []byte {
	t.Helper()
	privateKey, errKey := rsa.GenerateKey(rand.Reader, 2048)
	if errKey != nil {
		t.Fatalf("generate Vertex RSA key: %v", errKey)
	}
	payload := map[string]string{
		"type": "service_account", "project_id": "vertex-project", "private_key_id": "key-id",
		"private_key":  string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})),
		"client_email": "vertex@vertex-project.iam.gserviceaccount.com", "token_uri": "https://oauth2.googleapis.com/token",
	}
	raw, errMarshal := json.Marshal(payload)
	if errMarshal != nil {
		t.Fatalf("marshal Vertex service-account fixture: %v", errMarshal)
	}
	return raw
}

// staticAntigravityTokenClient returns one deterministic refreshed Google OAuth document.
// staticAntigravityTokenClient 返回一个确定性的已刷新 Google OAuth 文档。
type staticAntigravityTokenClient struct {
	// token is the deterministic refresh result.
	// token 是确定性的刷新结果。
	token providergoogle.AntigravityToken
}

// Refresh returns the configured Antigravity token.
// Refresh 返回配置的 Antigravity Token。
func (c staticAntigravityTokenClient) Refresh(context.Context, providergoogle.AntigravityToken) (providergoogle.AntigravityToken, error) {
	return c.token, nil
}

// newKimiOnboardingService creates an isolated real registry and in-memory persistence graph.
// newKimiOnboardingService 创建隔离的真实注册表和内存持久化图。
func newKimiOnboardingService(t *testing.T) (*Service, *providerconfig.MemoryStore, *secret.MemoryStore) {
	t.Helper()
	protocols := providerconfig.NewProtocolRegistry()
	if errProtocols := bootstrap.RegisterProtocolProfiles(protocols); errProtocols != nil {
		t.Fatalf("RegisterProtocolProfiles() error = %v", errProtocols)
	}
	systems, errSystems := providerconfig.NewSystemRegistry(protocols)
	if errSystems != nil {
		t.Fatalf("NewSystemRegistry() error = %v", errSystems)
	}
	if errProviders := bootstrap.RegisterSystemProviders(systems); errProviders != nil {
		t.Fatalf("RegisterSystemProviders() error = %v", errProviders)
	}
	configurations, errConfigurations := providerconfig.NewMemoryStore(protocols, systems)
	if errConfigurations != nil {
		t.Fatalf("NewMemoryStore() error = %v", errConfigurations)
	}
	secrets := secret.NewMemoryStore()
	service, errService := NewService(configurations, secrets, catalog.NewMemoryStore())
	if errService != nil {
		t.Fatalf("NewService() error = %v", errService)
	}
	return service, configurations, secrets
}
