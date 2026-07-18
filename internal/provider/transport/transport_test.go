// Transport fixtures cover behavior adapted from CLIProxyAPI executor evidence at commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// 传输夹具覆盖改编自 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66 的 Executor 证据行为。
// Source paths: internal/runtime/executor/openai_compat_executor.go, xai_executor.go, and aistudio_executor.go.
// 来源路径：internal/runtime/executor/openai_compat_executor.go、xai_executor.go 和 aistudio_executor.go。
// The fixtures verify provider-scoped transport boundaries without importing CLIProxyAPI runtime code.
// 夹具验证 Provider 作用域传输边界，不导入 CLIProxyAPI 运行时代码。
package transport

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

// TestClientDoInjectsBoundBearerCredential verifies exact-target authentication and JSON request construction.
// TestClientDoInjectsBoundBearerCredential 验证精确 Target 认证与 JSON 请求构建。
func TestClientDoInjectsBoundBearerCredential(t *testing.T) {
	secretStore := secret.NewMemoryStore()
	secretRef, errPut := secretStore.Put(context.Background(), []byte("credential-value"))
	if errPut != nil {
		t.Fatalf("Put() error = %v", errPut)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/responses" {
			t.Errorf("request = %s %s", request.Method, request.URL.Path)
		}
		if authorization := request.Header.Get("Authorization"); authorization != "Bearer credential-value" {
			t.Errorf("Authorization = %q", authorization)
		}
		if contentType := request.Header.Get("Content-Type"); contentType != "application/json" {
			t.Errorf("Content-Type = %q", contentType)
		}
		body, errRead := io.ReadAll(request.Body)
		if errRead != nil || string(body) != `{"model":"model-a"}` {
			t.Errorf("body = %q, %v", body, errRead)
		}
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()
	client, errClient := NewClient(server.Client(), secretStore, RetryPolicy{})
	if errClient != nil {
		t.Fatalf("NewClient() error = %v", errClient)
	}
	response, errDo := client.Do(context.Background(), testRequest(server.URL, secretRef))
	if errDo != nil {
		t.Fatalf("Do() error = %v", errDo)
	}
	defer DrainAndClose(response)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
}

// TestClientRejectsMismatchedTargetBeforeNetwork verifies that a driver cannot swap selected endpoint identity.
// TestClientRejectsMismatchedTargetBeforeNetwork 验证 Driver 不能替换已选 Endpoint 身份。
func TestClientRejectsMismatchedTargetBeforeNetwork(t *testing.T) {
	secretStore := secret.NewMemoryStore()
	secretRef, errPut := secretStore.Put(context.Background(), []byte("credential-value"))
	if errPut != nil {
		t.Fatalf("Put() error = %v", errPut)
	}
	var received atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		received.Add(1)
	}))
	defer server.Close()
	client, errClient := NewClient(server.Client(), secretStore, RetryPolicy{})
	if errClient != nil {
		t.Fatalf("NewClient() error = %v", errClient)
	}
	request := testRequest(server.URL, secretRef)
	request.Binding.Endpoint.ID = "endpoint-other"
	_, errDo := client.Do(context.Background(), request)
	if !errors.Is(errDo, ErrInvalidBinding) {
		t.Fatalf("Do() error = %v, want ErrInvalidBinding", errDo)
	}
	if count := received.Load(); count != 0 {
		t.Fatalf("network requests = %d, want 0", count)
	}
}

// TestNewClientRejectsStandardClientRedirectBeforeSecondTarget verifies all standard HTTP clients preserve the selected endpoint boundary, not only NewDefaultClient.
// TestNewClientRejectsStandardClientRedirectBeforeSecondTarget 验证所有标准 HTTP 客户端都保持选定 Endpoint 边界，而非仅 NewDefaultClient。
func TestNewClientRejectsStandardClientRedirectBeforeSecondTarget(t *testing.T) {
	secretStore := secret.NewMemoryStore()
	secretRef, errPut := secretStore.Put(context.Background(), []byte("credential-value"))
	if errPut != nil {
		t.Fatalf("Put() error = %v", errPut)
	}
	var secondTargetRequests atomic.Int32
	secondTarget := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		secondTargetRequests.Add(1)
		writer.WriteHeader(http.StatusOK)
	}))
	defer secondTarget.Close()
	firstTarget := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Location", secondTarget.URL+"/v1/responses")
		writer.WriteHeader(http.StatusFound)
	}))
	defer firstTarget.Close()

	client, errClient := NewClient(http.DefaultClient, secretStore, RetryPolicy{})
	if errClient != nil {
		t.Fatalf("NewClient() error = %v", errClient)
	}
	_, errDo := client.Do(context.Background(), testRequest(firstTarget.URL, secretRef))
	var statusError StatusError
	if !errors.As(errDo, &statusError) || statusError.StatusCode != http.StatusFound {
		t.Fatalf("Do() error = %v, want safe 302 StatusError", errDo)
	}
	if count := secondTargetRequests.Load(); count != 0 {
		t.Fatalf("second target requests = %d, want 0", count)
	}
}

// TestClientRetriesOnlyWithIdempotencyKey verifies that a transient same-target retry needs explicit replay protection.
// TestClientRetriesOnlyWithIdempotencyKey 验证瞬态同 Target 重试需要明确的重放保护。
func TestClientRetriesOnlyWithIdempotencyKey(t *testing.T) {
	secretStore := secret.NewMemoryStore()
	secretRef, errPut := secretStore.Put(context.Background(), []byte("credential-value"))
	if errPut != nil {
		t.Fatalf("Put() error = %v", errPut)
	}
	var received atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if idempotencyKey := request.Header.Get("Idempotency-Key"); idempotencyKey != "request-1" {
			t.Errorf("Idempotency-Key = %q", idempotencyKey)
		}
		if received.Add(1) == 1 {
			writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client, errClient := NewClient(server.Client(), secretStore, RetryPolicy{MaxAttempts: 2, InitialBackoff: time.Millisecond})
	if errClient != nil {
		t.Fatalf("NewClient() error = %v", errClient)
	}
	request := testRequest(server.URL, secretRef)
	request.IdempotencyKey = "request-1"
	response, errDo := client.Do(context.Background(), request)
	if errDo != nil {
		t.Fatalf("Do() error = %v", errDo)
	}
	defer DrainAndClose(response)
	if count := received.Load(); count != 2 {
		t.Fatalf("network requests = %d, want 2", count)
	}
}

// TestClientDoesNotRetryWithoutIdempotencyKey verifies that POST failures are not replayed by default.
// TestClientDoesNotRetryWithoutIdempotencyKey 验证默认不会重放失败的 POST 请求。
func TestClientDoesNotRetryWithoutIdempotencyKey(t *testing.T) {
	secretStore := secret.NewMemoryStore()
	secretRef, errPut := secretStore.Put(context.Background(), []byte("credential-value"))
	if errPut != nil {
		t.Fatalf("Put() error = %v", errPut)
	}
	var received atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		received.Add(1)
		writer.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	client, errClient := NewClient(server.Client(), secretStore, RetryPolicy{MaxAttempts: 2})
	if errClient != nil {
		t.Fatalf("NewClient() error = %v", errClient)
	}
	_, errDo := client.Do(context.Background(), testRequest(server.URL, secretRef))
	var statusError StatusError
	if !errors.As(errDo, &statusError) || statusError.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("Do() error = %v, want safe 503 StatusError", errDo)
	}
	if count := received.Load(); count != 1 {
		t.Fatalf("network requests = %d, want 1", count)
	}
}

// TestClientDoStreamSetsEventAccept verifies that SSE requests remain HTTP requests with explicit content negotiation.
// TestClientDoStreamSetsEventAccept 验证 SSE 请求仍是带明确内容协商的 HTTP 请求。
func TestClientDoStreamSetsEventAccept(t *testing.T) {
	secretStore := secret.NewMemoryStore()
	secretRef, errPut := secretStore.Put(context.Background(), []byte("credential-value"))
	if errPut != nil {
		t.Fatalf("Put() error = %v", errPut)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if accept := request.Header.Get("Accept"); accept != "text/event-stream" {
			t.Errorf("Accept = %q", accept)
		}
		writer.Header().Set("Content-Type", "text/event-stream")
		_, _ = writer.Write([]byte("data: {}\n\n"))
	}))
	defer server.Close()
	client, errClient := NewClient(server.Client(), secretStore, RetryPolicy{})
	if errClient != nil {
		t.Fatalf("NewClient() error = %v", errClient)
	}
	response, errDo := client.DoStream(context.Background(), testRequest(server.URL, secretRef))
	if errDo != nil {
		t.Fatalf("DoStream() error = %v", errDo)
	}
	defer DrainAndClose(response)
}

// testRequest creates one complete provider-scoped request fixture.
// testRequest 创建一个完整的供应商作用域请求夹具。
func testRequest(baseURL string, secretRef string) Request {
	return Request{
		Binding: Binding{
			Target:     resolveTarget(),
			Endpoint:   providerconfig.Endpoint{ID: "endpoint-1", ProviderInstanceID: "instance-1", ChannelID: "channel-1", BaseURL: baseURL, Status: providerconfig.EndpointReady},
			Credential: providerconfig.Credential{ID: "credential-1", ProviderInstanceID: "instance-1", SecretRef: secretRef, Status: providerconfig.CredentialActive},
		},
		Method: http.MethodPost, Path: "/v1/responses", Body: []byte(`{"model":"model-a"}`), Authentication: Authentication{Mode: AuthenticationBearer},
	}
}

// resolveTarget creates the immutable target matching testRequest endpoint and credential fixtures.
// resolveTarget 创建与 testRequest Endpoint、Credential 夹具匹配的不可变 Target。
func resolveTarget() resolve.Target {
	return resolve.Target{
		ProviderDefinitionID: "definition-1", ProviderInstanceID: "instance-1", ChannelID: "channel-1", EndpointID: "endpoint-1", CredentialID: "credential-1",
		ProviderModelID: "model-1", OfferingID: "offering-1", ExecutionProfileID: "profile-1", UpstreamModelID: "model-a",
	}
}
