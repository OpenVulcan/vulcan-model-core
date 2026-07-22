package minimax

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

// TestRegionalFlowManagerKeepsGlobalAndCNOriginsSeparate verifies explicit region selection owns every device exchange.
// TestRegionalFlowManagerKeepsGlobalAndCNOriginsSeparate 验证显式区域选择拥有每一次设备交换。
func TestRegionalFlowManagerKeepsGlobalAndCNOriginsSeparate(t *testing.T) {
	// globalCalls counts requests received by the isolated Global fixture.
	// globalCalls 统计隔离 Global 夹具接收的请求。
	var globalCalls atomic.Int32
	// cnCalls counts requests received by the isolated CN fixture.
	// cnCalls 统计隔离 CN 夹具接收的请求。
	var cnCalls atomic.Int32
	globalServer := newMiniMaxOAuthFixture(t, "GLOBAL", &globalCalls)
	defer globalServer.Close()
	cnServer := newMiniMaxOAuthFixture(t, "CN", &cnCalls)
	defer cnServer.Close()

	globalClient, errGlobalClient := NewDeviceFlowClientWithEndpoints(globalServer.Client(), GlobalOAuthRegion(), globalServer.URL+"/oauth2/device/code", globalServer.URL+"/oauth2/token")
	if errGlobalClient != nil {
		t.Fatalf("create Global client: %v", errGlobalClient)
	}
	cnClient, errCNClient := NewDeviceFlowClientWithEndpoints(cnServer.Client(), CNOAuthRegion(), cnServer.URL+"/oauth2/device/code", cnServer.URL+"/oauth2/token")
	if errCNClient != nil {
		t.Fatalf("create CN client: %v", errCNClient)
	}
	globalManager, _ := NewFlowManager(globalClient)
	cnManager, _ := NewFlowManager(cnClient)
	managerNow := time.Now().UTC()
	globalManager.now = func() time.Time { return managerNow }
	cnManager.now = func() time.Time { return managerNow }
	regional, errRegional := NewRegionalFlowManager(globalManager, cnManager)
	if errRegional != nil {
		t.Fatalf("create regional manager: %v", errRegional)
	}

	flow, errStart := regional.Start(context.Background(), "cn")
	if errStart != nil {
		t.Fatalf("start CN flow: %v", errStart)
	}
	if !strings.HasPrefix(flow.ID, "cn.") || flow.UserCode != "CN-CODE" {
		t.Fatalf("CN flow = %#v", flow)
	}
	// managerNow advances deterministically beyond the provider-declared one-millisecond cadence.
	// managerNow 以确定方式推进到供应商声明的一毫秒轮询间隔之后。
	managerNow = managerNow.Add(2 * time.Millisecond)
	token, errPoll := regional.Poll(context.Background(), flow.ID)
	if errPoll != nil {
		t.Fatalf("poll CN flow: %v", errPoll)
	}
	if token.Region != "cn" || token.AccessToken != "CN-ACCESS" || globalCalls.Load() != 0 || cnCalls.Load() != 2 {
		t.Fatalf("regional exchange token=%#v global=%d cn=%d", token, globalCalls.Load(), cnCalls.Load())
	}
	regional.Cancel(flow.ID)
	if _, errPollAgain := regional.Poll(context.Background(), flow.ID); errPollAgain != ErrFlowNotFound {
		t.Fatalf("poll consumed flow error = %v", errPollAgain)
	}
}

// TestRegionalFlowManagerRejectsImplicitRegion verifies no credential or fallback logic can choose an Origin.
// TestRegionalFlowManagerRejectsImplicitRegion 验证任何凭据或降级逻辑都不能选择 Origin。
func TestRegionalFlowManagerRejectsImplicitRegion(t *testing.T) {
	server := newMiniMaxOAuthFixture(t, "TEST", &atomic.Int32{})
	defer server.Close()
	client, _ := NewDeviceFlowClientWithEndpoints(server.Client(), GlobalOAuthRegion(), server.URL+"/oauth2/device/code", server.URL+"/oauth2/token")
	manager, _ := NewFlowManager(client)
	regional, _ := NewRegionalFlowManager(manager, manager)
	if _, errStart := regional.Start(context.Background(), ""); errStart == nil {
		t.Fatal("empty MiniMax region unexpectedly started a flow")
	}
	if _, errPoll := regional.Poll(context.Background(), "unknown.flow"); errPoll != ErrFlowNotFound {
		t.Fatalf("unknown regional flow error = %v", errPoll)
	}
}

// newMiniMaxOAuthFixture creates one strict device-code and token fixture for a single test region.
// newMiniMaxOAuthFixture 为单个测试区域创建一个严格的设备码与 Token 夹具。
func newMiniMaxOAuthFixture(t *testing.T, label string, calls *atomic.Int32) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		if errForm := request.ParseForm(); errForm != nil {
			t.Errorf("parse OAuth form: %v", errForm)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/oauth2/device/code":
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"user_code":        label + "-CODE",
				"verification_uri": "https://account.example/authorize",
				"expired_in":       time.Now().Add(time.Minute).UnixMilli(),
				"interval":         1,
				"state":            request.Form.Get("state"),
			})
		case "/oauth2/token":
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"status":        "success",
				"access_token":  label + "-ACCESS",
				"refresh_token": label + "-REFRESH",
				"expired_in":    time.Now().Add(time.Hour).UnixMilli(),
			})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	return server
}
