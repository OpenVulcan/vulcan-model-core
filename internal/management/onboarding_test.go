package management

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/bootstrap"
	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	providerkimi "github.com/OpenVulcan/vulcan-model-core/internal/provider/kimi"
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
	mu      sync.Mutex
	calls   int
	started chan struct{}
	release chan struct{}
	token   providerkimi.Token
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
