package kimi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestFlowManagerKeepsCompletedTokenUntilExplicitConsumption verifies pending, completion, retry, and cancellation semantics.
// TestFlowManagerKeepsCompletedTokenUntilExplicitConsumption 验证等待、完成、重试和取消语义。
func TestFlowManagerKeepsCompletedTokenUntilExplicitConsumption(t *testing.T) {
	var exchanges atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("X-Msh-Device-Id") == "" || request.Header.Get("X-Msh-Platform") != "VulcanModelRouter" {
			t.Errorf("device headers = %#v", request.Header)
		}
		switch request.URL.Path {
		case "/device":
			_ = json.NewEncoder(writer).Encode(map[string]any{"device_code": "provider-secret", "user_code": "ABCD-EFGH", "verification_uri": "https://auth.example/verify", "verification_uri_complete": "https://auth.example/verify?code=ABCD-EFGH", "expires_in": 600, "interval": 5})
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
	if _, errPending := manager.Poll(context.Background(), flow.ID); errPending != ErrAuthorizationPending {
		t.Fatalf("first Poll() error = %v, want ErrAuthorizationPending", errPending)
	}
	now = now.Add(5 * time.Second)
	token, errPoll := manager.Poll(context.Background(), flow.ID)
	if errPoll != nil || token.AccessToken != "access" || token.DeviceID == "" {
		t.Fatalf("completed Poll() token=%#v error=%v", token, errPoll)
	}
	cached, errCached := manager.Poll(context.Background(), flow.ID)
	if errCached != nil || cached.AccessToken != token.AccessToken || exchanges.Load() != 2 {
		t.Fatalf("cached Poll() token=%#v error=%v exchanges=%d", cached, errCached, exchanges.Load())
	}
	manager.Cancel(flow.ID)
	if _, errMissing := manager.Poll(context.Background(), flow.ID); errMissing != ErrFlowNotFound {
		t.Fatalf("cancelled Poll() error = %v, want ErrFlowNotFound", errMissing)
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

// TestFlowManagerDoesNotRestoreCancelledInFlightSession verifies a slow successful exchange cannot resurrect a cancelled flow.
// TestFlowManagerDoesNotRestoreCancelledInFlightSession 验证缓慢成功的交换不能复活已取消授权流程。
func TestFlowManagerDoesNotRestoreCancelledInFlightSession(t *testing.T) {
	exchangeStarted := make(chan struct{})
	releaseExchange := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/device":
			_ = json.NewEncoder(writer).Encode(map[string]any{"device_code": "provider-secret", "user_code": "ABCD-EFGH", "verification_uri": "https://auth.example/verify", "expires_in": 600, "interval": 5})
		case "/token":
			close(exchangeStarted)
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
	flow, errStart := manager.Start(context.Background())
	if errStart != nil {
		t.Fatalf("Start() error = %v", errStart)
	}
	pollResult := make(chan error, 1)
	go func() {
		_, errPoll := manager.Poll(context.Background(), flow.ID)
		pollResult <- errPoll
	}()
	<-exchangeStarted
	manager.Cancel(flow.ID)
	close(releaseExchange)
	if errPoll := <-pollResult; errPoll != ErrFlowNotFound {
		t.Fatalf("in-flight Poll() error = %v, want ErrFlowNotFound", errPoll)
	}
	if _, errMissing := manager.Poll(context.Background(), flow.ID); errMissing != ErrFlowNotFound {
		t.Fatalf("post-cancel Poll() error = %v, want ErrFlowNotFound", errMissing)
	}
}
