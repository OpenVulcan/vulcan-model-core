package kimi

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	coreprovider "github.com/OpenVulcan/vulcan-model-core/internal/provider"
)

// TestDeviceFlowClientRefusesRedirectsWithoutMutatingCaller verifies credential-bearing forms cannot cross redirect boundaries.
// TestDeviceFlowClientRefusesRedirectsWithoutMutatingCaller 验证携带凭据的表单不能跨越重定向边界。
func TestDeviceFlowClientRefusesRedirectsWithoutMutatingCaller(t *testing.T) {
	callerRedirectError := errors.New("caller redirect policy")
	caller := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return callerRedirectError }}
	client, errClient := NewDeviceFlowClientWithEndpoints(caller, "https://device.example/code", "https://device.example/token")
	if errClient != nil {
		t.Fatalf("NewDeviceFlowClientWithEndpoints() error = %v", errClient)
	}
	if client.httpClient == caller {
		t.Fatal("device-flow client retained the caller-owned HTTP client")
	}
	if errRedirect := client.httpClient.CheckRedirect(nil, nil); !errors.Is(errRedirect, http.ErrUseLastResponse) {
		t.Fatalf("device-flow redirect error = %v, want http.ErrUseLastResponse", errRedirect)
	}
	if errRedirect := caller.CheckRedirect(nil, nil); !errors.Is(errRedirect, callerRedirectError) {
		t.Fatalf("caller redirect error = %v, want original policy", errRedirect)
	}
}

// TestKimiFlowLifetimeClampsOversizedProviderValue verifies integer overflow cannot expire a new authorization session.
// TestKimiFlowLifetimeClampsOversizedProviderValue 验证整数溢出不能让新授权会话立即过期。
func TestKimiFlowLifetimeClampsOversizedProviderValue(t *testing.T) {
	if lifetime := kimiFlowLifetime(int(^uint(0) >> 1)); lifetime != maximumFlowLifetime {
		t.Fatalf("kimiFlowLifetime() = %s, want %s", lifetime, maximumFlowLifetime)
	}
}

// TestKimiPollIntervalClampsOversizedProviderValue verifies provider integers cannot wrap the polling schedule.
// TestKimiPollIntervalClampsOversizedProviderValue 验证供应商整数不能使轮询计划发生回绕。
func TestKimiPollIntervalClampsOversizedProviderValue(t *testing.T) {
	if interval := kimiPollInterval(int(^uint(0) >> 1)); interval != maximumFlowLifetime {
		t.Fatalf("kimiPollInterval() = %s, want %s", interval, maximumFlowLifetime)
	}
	if interval := kimiPollInterval(1); interval != defaultPollInterval {
		t.Fatalf("kimiPollInterval() minimum = %s, want %s", interval, defaultPollInterval)
	}
}

// TestFlowManagerKeepsCompletedTokenUntilExplicitConsumption verifies pending, completion, retry, and cancellation semantics.
// TestFlowManagerKeepsCompletedTokenUntilExplicitConsumption 验证等待、完成、重试和取消语义。
func TestFlowManagerKeepsCompletedTokenUntilExplicitConsumption(t *testing.T) {
	var exchanges atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		deviceID := request.Header.Get("X-Msh-Device-Id")
		if len(deviceID) != 36 || strings.Count(deviceID, "-") != 4 || request.Header.Get("X-Msh-Platform") != devicePlatform || request.Header.Get("X-Msh-Version") != deviceVersion {
			t.Errorf("device headers = %#v", request.Header)
		}
		switch request.URL.Path {
		case "/device":
			_ = json.NewEncoder(writer).Encode(map[string]any{"device_code": "provider-secret", "user_code": "ABCD-EFGH", "verification_uri_complete": "https://auth.example/verify?code=ABCD-EFGH", "expires_in": 600, "interval": 5})
		case "/token":
			body := make([]byte, request.ContentLength)
			_, _ = request.Body.Read(body)
			if !strings.Contains(string(body), "device_code=provider-secret") {
				t.Errorf("token request body = %q", body)
			}
			if exchanges.Add(1) == 1 {
				_ = json.NewEncoder(writer).Encode(map[string]string{"error": "authorization_pending"})
				return
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{"access_token": "access", "refresh_token": "refresh", "token_type": "Bearer", "expires_in": 3600})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client, errClient := NewDeviceFlowClientWithEndpoints(server.Client(), server.URL+"/device", server.URL+"/token")
	if errClient != nil {
		t.Fatalf("NewDeviceFlowClientWithEndpoints() error = %v", errClient)
	}
	manager, errManager := NewFlowManager(client)
	if errManager != nil {
		t.Fatalf("NewFlowManager() error = %v", errManager)
	}
	now := time.Date(2026, 7, 18, 10, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }
	flow, errStart := manager.Start(context.Background())
	if errStart != nil {
		t.Fatalf("Start() error = %v", errStart)
	}
	if flow.VerificationURI != "https://auth.example/verify?code=ABCD-EFGH" {
		t.Fatalf("Start() verification URI = %q", flow.VerificationURI)
	}
	if _, errPending := manager.Poll(context.Background(), flow.ID); errPending != ErrAuthorizationPending {
		t.Fatalf("first Poll() error = %v, want ErrAuthorizationPending", errPending)
	}
	if exchanges.Load() != 0 {
		t.Fatalf("first Poll() exchanges = %d, want 0 before the provider interval", exchanges.Load())
	}
	now = now.Add(5 * time.Second)
	if _, errPending := manager.Poll(context.Background(), flow.ID); errPending != ErrAuthorizationPending {
		t.Fatalf("provider-pending Poll() error = %v, want ErrAuthorizationPending", errPending)
	}
	now = now.Add(5 * time.Second)
	token, errPoll := manager.Poll(context.Background(), flow.ID)
	if errPoll != nil || token.AccessToken != "access" || token.DeviceID == "" {
		t.Fatalf("completed Poll() token=%#v error=%v", token, errPoll)
	}
	if _, errLeased := manager.Poll(context.Background(), flow.ID); errLeased != ErrAuthorizationPending {
		t.Fatalf("leased Poll() error = %v, want ErrAuthorizationPending", errLeased)
	}
	manager.Release(flow.ID)
	cached, errCached := manager.Poll(context.Background(), flow.ID)
	if errCached != nil || cached.AccessToken != token.AccessToken || exchanges.Load() != 2 {
		t.Fatalf("released cached Poll() token=%#v error=%v exchanges=%d", cached, errCached, exchanges.Load())
	}
	manager.Cancel(flow.ID)
	if _, errMissing := manager.Poll(context.Background(), flow.ID); errMissing != ErrFlowNotFound {
		t.Fatalf("cancelled Poll() error = %v, want ErrFlowNotFound", errMissing)
	}
}

// TestDeviceFlowClientAcceptsAccessOnlyToken verifies CLIProxyAPI-compatible device responses do not require a refresh token.
// TestDeviceFlowClientAcceptsAccessOnlyToken 验证兼容 CLIProxyAPI 的设备授权响应不强制要求 Refresh Token。
func TestDeviceFlowClientAcceptsAccessOnlyToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/token" {
			http.NotFound(writer, request)
			return
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{"access_token": "access-only", "token_type": "Bearer", "expires_in": 3600})
	}))
	defer server.Close()
	client, errClient := NewDeviceFlowClientWithEndpoints(server.Client(), server.URL+"/device", server.URL+"/token")
	if errClient != nil {
		t.Fatalf("NewDeviceFlowClientWithEndpoints() error = %v", errClient)
	}
	token, errExchange := client.Exchange(context.Background(), DeviceCode{DeviceCode: "provider-secret", DeviceID: "device-one"})
	if errExchange != nil || token.AccessToken != "access-only" || token.RefreshToken != "" {
		t.Fatalf("Exchange() token=%#v error=%v", token, errExchange)
	}
	encoded, errMarshal := MarshalToken(token)
	if errMarshal != nil || len(encoded) == 0 {
		t.Fatalf("MarshalToken() bytes=%q error=%v", encoded, errMarshal)
	}
}

// TestDeviceFlowClientRejectsOversizedTokenResponse verifies provider data cannot bypass the bounded decoder.
// TestDeviceFlowClientRejectsOversizedTokenResponse 验证供应商数据不能绕过有界解码器。
func TestDeviceFlowClientRejectsOversizedTokenResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(strings.Repeat("x", maximumOAuthResponseBytes+1)))
	}))
	defer server.Close()
	client, errClient := NewDeviceFlowClientWithEndpoints(server.Client(), server.URL+"/device", server.URL+"/token")
	if errClient != nil {
		t.Fatalf("NewDeviceFlowClientWithEndpoints() error = %v", errClient)
	}
	_, errExchange := client.Exchange(context.Background(), DeviceCode{DeviceCode: "provider-secret", DeviceID: "device-one"})
	if errExchange == nil || !strings.Contains(errExchange.Error(), "exceeds the allowed size") {
		t.Fatalf("Exchange() error = %v", errExchange)
	}
}

// TestKimiTokenExpiryRejectsUnixOverflow verifies malicious provider lifetimes cannot wrap credential expiry.
// TestKimiTokenExpiryRejectsUnixOverflow 验证恶意供应商有效期不能使凭据过期时间回绕。
func TestKimiTokenExpiryRejectsUnixOverflow(t *testing.T) {
	if _, errExpiry := kimiTokenExpiry(math.MaxFloat64); errExpiry == nil {
		t.Fatal("kimiTokenExpiry() unexpectedly accepted an overflowing lifetime")
	}
}

// TestFlowManagerBoundsSessionsAndPrunesExpiredEntries verifies bounded memory ownership without blocking new flows after expiry.
// TestFlowManagerBoundsSessionsAndPrunesExpiredEntries 验证有界内存所有权且过期后不会阻止新授权流程。
func TestFlowManagerBoundsSessionsAndPrunesExpiredEntries(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/device" {
			http.NotFound(writer, request)
			return
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{"device_code": "provider-secret", "user_code": "ABCD-EFGH", "verification_uri": "https://auth.example/verify", "expires_in": 60, "interval": 5})
	}))
	defer server.Close()
	client, errClient := NewDeviceFlowClientWithEndpoints(server.Client(), server.URL+"/device", server.URL+"/token")
	if errClient != nil {
		t.Fatalf("NewDeviceFlowClientWithEndpoints() error = %v", errClient)
	}
	manager, errManager := NewFlowManager(client)
	if errManager != nil {
		t.Fatalf("NewFlowManager() error = %v", errManager)
	}
	now := time.Date(2026, 7, 18, 10, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }
	for index := 0; index < maximumFlowSessions; index++ {
		if _, errStart := manager.Start(context.Background()); errStart != nil {
			t.Fatalf("Start(%d) error = %v", index, errStart)
		}
	}
	if _, errLimit := manager.Start(context.Background()); errLimit != ErrFlowLimitReached {
		t.Fatalf("bounded Start() error = %v, want ErrFlowLimitReached", errLimit)
	}
	now = now.Add(61 * time.Second)
	if _, errPruned := manager.Start(context.Background()); errPruned != nil {
		t.Fatalf("Start() after expiry error = %v", errPruned)
	}
}

// TestDeviceFlowClientRefreshPreservesRefreshToken verifies the exact refresh grant and non-rotating refresh-token behavior.
// TestDeviceFlowClientRefreshPreservesRefreshToken 验证精确刷新授权及不轮换 Refresh Token 的行为。
func TestDeviceFlowClientRefreshPreservesRefreshToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body := make([]byte, request.ContentLength)
		_, _ = request.Body.Read(body)
		if !strings.Contains(string(body), "grant_type=refresh_token") || !strings.Contains(string(body), "refresh_token=refresh-before") {
			t.Errorf("refresh request body = %q", body)
		}
		if request.Header.Get("X-Msh-Device-Id") != "device-one" {
			t.Errorf("device header = %q", request.Header.Get("X-Msh-Device-Id"))
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{"access_token": "access-after", "token_type": "Bearer", "expires_in": 3600})
	}))
	defer server.Close()
	client, errClient := NewDeviceFlowClientWithEndpoints(server.Client(), server.URL+"/device", server.URL+"/token")
	if errClient != nil {
		t.Fatalf("NewDeviceFlowClientWithEndpoints() error = %v", errClient)
	}
	token, errRefresh := client.Refresh(context.Background(), Token{AccessToken: "access-before", RefreshToken: "refresh-before", DeviceID: "device-one", Type: "kimi"})
	if errRefresh != nil || token.AccessToken != "access-after" || token.RefreshToken != "refresh-before" || token.DeviceID != "device-one" {
		t.Fatalf("Refresh() token=%#v error=%v", token, errRefresh)
	}
}

// TestDeviceFlowClientRefreshClassifiesAuthenticationFailures verifies the management-safe Kimi refresh taxonomy.
// TestDeviceFlowClientRefreshClassifiesAuthenticationFailures 验证管理安全的 Kimi 刷新错误分类。
func TestDeviceFlowClientRefreshClassifiesAuthenticationFailures(t *testing.T) {
	tests := []struct {
		// name labels the isolated provider response.
		// name 标记隔离的供应商响应。
		name string
		// statusCode is the provider HTTP status.
		// statusCode 是供应商 HTTP 状态码。
		statusCode int
		// body is the exact provider response body.
		// body 是精确的供应商响应正文。
		body string
		// expectedError is the stable authentication category.
		// expectedError 是稳定的认证错误分类。
		expectedError error
	}{
		{name: "rejected", statusCode: http.StatusUnauthorized, body: `{"error":"invalid_grant"}`, expectedError: coreprovider.ErrAuthenticationRejected},
		{name: "request timeout", statusCode: http.StatusRequestTimeout, body: `{}`, expectedError: coreprovider.ErrAuthenticationUnavailable},
		{name: "unavailable", statusCode: http.StatusServiceUnavailable, body: `{}`, expectedError: coreprovider.ErrAuthenticationUnavailable},
		{name: "invalid response", statusCode: http.StatusOK, body: `{}`, expectedError: coreprovider.ErrAuthenticationResponseInvalid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(test.statusCode)
				_, _ = writer.Write([]byte(test.body))
			}))
			defer server.Close()
			client, errClient := NewDeviceFlowClientWithEndpoints(server.Client(), server.URL+"/device", server.URL+"/token")
			if errClient != nil {
				t.Fatalf("NewDeviceFlowClientWithEndpoints() error = %v", errClient)
			}
			_, errRefresh := client.Refresh(context.Background(), Token{AccessToken: "access-before", RefreshToken: "refresh-before", DeviceID: "device-one", Type: "kimi"})
			if !errors.Is(errRefresh, test.expectedError) {
				t.Fatalf("Refresh() error = %v, want category %v", errRefresh, test.expectedError)
			}
		})
	}
}

// TestDeviceFlowClientClassifiesAccessOnlyRefreshAsRejected verifies access-only credentials request reauthorization through the stable taxonomy.
// TestDeviceFlowClientClassifiesAccessOnlyRefreshAsRejected 验证仅含 Access Token 的凭据通过稳定分类请求重新授权。
func TestDeviceFlowClientClassifiesAccessOnlyRefreshAsRejected(t *testing.T) {
	client, errClient := NewDeviceFlowClientWithEndpoints(&http.Client{}, "https://device.example/code", "https://device.example/token")
	if errClient != nil {
		t.Fatalf("NewDeviceFlowClientWithEndpoints() error = %v", errClient)
	}
	_, errRefresh := client.Refresh(context.Background(), Token{AccessToken: "access", DeviceID: "device", Type: "kimi"})
	if !errors.Is(errRefresh, coreprovider.ErrAuthenticationRejected) {
		t.Fatalf("Refresh() error = %v, want ErrAuthenticationRejected", errRefresh)
	}
}

// TestFlowManagerDoesNotRestoreCancelledInFlightSession verifies a slow successful exchange cannot resurrect a cancelled flow.
// TestFlowManagerDoesNotRestoreCancelledInFlightSession 验证缓慢成功的交换不能复活已取消授权流程。
func TestFlowManagerDoesNotRestoreCancelledInFlightSession(t *testing.T) {
	var exchanges atomic.Int32
	exchangeStarted := make(chan struct{})
	releaseExchange := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/device":
			_ = json.NewEncoder(writer).Encode(map[string]any{"device_code": "provider-secret", "user_code": "ABCD-EFGH", "verification_uri": "https://auth.example/verify", "expires_in": 600, "interval": 5})
		case "/token":
			if exchanges.Add(1) == 1 {
				close(exchangeStarted)
			}
			<-releaseExchange
			_ = json.NewEncoder(writer).Encode(map[string]any{"access_token": "access", "refresh_token": "refresh", "token_type": "Bearer", "expires_in": 3600})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client, errClient := NewDeviceFlowClientWithEndpoints(server.Client(), server.URL+"/device", server.URL+"/token")
	if errClient != nil {
		t.Fatalf("NewDeviceFlowClientWithEndpoints() error = %v", errClient)
	}
	manager, errManager := NewFlowManager(client)
	if errManager != nil {
		t.Fatalf("NewFlowManager() error = %v", errManager)
	}
	now := time.Date(2026, 7, 18, 10, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }
	flow, errStart := manager.Start(context.Background())
	if errStart != nil {
		t.Fatalf("Start() error = %v", errStart)
	}
	now = now.Add(5 * time.Second)
	pollResult := make(chan error, 1)
	go func() {
		_, errPoll := manager.Poll(context.Background(), flow.ID)
		pollResult <- errPoll
	}()
	<-exchangeStarted
	now = now.Add(5 * time.Second)
	overlapContext, cancelOverlap := context.WithTimeout(context.Background(), 100*time.Millisecond)
	_, errOverlap := manager.Poll(overlapContext, flow.ID)
	cancelOverlap()
	manager.Cancel(flow.ID)
	close(releaseExchange)
	if !errors.Is(errOverlap, ErrAuthorizationPending) || exchanges.Load() != 1 {
		t.Fatalf("overlapping Poll() error = %v exchanges = %d", errOverlap, exchanges.Load())
	}
	if errPoll := <-pollResult; errPoll != ErrFlowNotFound {
		t.Fatalf("in-flight Poll() error = %v, want ErrFlowNotFound", errPoll)
	}
	if _, errMissing := manager.Poll(context.Background(), flow.ID); errMissing != ErrFlowNotFound {
		t.Fatalf("post-cancel Poll() error = %v, want ErrFlowNotFound", errMissing)
	}
}
