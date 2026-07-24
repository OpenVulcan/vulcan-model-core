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
	"strings"
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

// TestNewClientRejectsTypedNilDependencies verifies boxed nil transports and secret stores cannot survive construction.
// TestNewClientRejectsTypedNilDependencies 验证装箱后的 nil Transport 与 Secret Store 无法通过构造。
func TestNewClientRejectsTypedNilDependencies(t *testing.T) {
	var httpClient *http.Client
	if _, errClient := NewClient(httpClient, secret.NewMemoryStore(), RetryPolicy{}); !errors.Is(errClient, ErrHTTPClientRequired) {
		t.Fatalf("typed nil HTTP client error = %v, want ErrHTTPClientRequired", errClient)
	}
	var secretStore *secret.MemoryStore
	if _, errClient := NewClient(http.DefaultClient, secretStore, RetryPolicy{}); !errors.Is(errClient, ErrSecretStoreRequired) {
		t.Fatalf("typed nil secret store error = %v, want ErrSecretStoreRequired", errClient)
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

// TestClientExtractsOnlySafeStructuredErrorIdentity verifies provider codes can drive trusted rules without leaking free-form text.
// TestClientExtractsOnlySafeStructuredErrorIdentity 验证供应商代码可驱动受信任规则且不会泄露自由文本。
func TestClientExtractsOnlySafeStructuredErrorIdentity(t *testing.T) {
	secretStore := secret.NewMemoryStore()
	secretRef, errPut := secretStore.Put(context.Background(), []byte("credential-value"))
	if errPut != nil {
		t.Fatalf("Put() error = %v", errPut)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusForbidden)
		_, _ = writer.Write([]byte(`{"error":{"code":"quota_exhausted","type":"access_terminated_error","message":"private provider detail must not escape"}}`))
	}))
	defer server.Close()
	client, errClient := NewClient(server.Client(), secretStore, RetryPolicy{})
	if errClient != nil {
		t.Fatalf("NewClient() error = %v", errClient)
	}
	_, errDo := client.Do(context.Background(), testRequest(server.URL, secretRef))
	var statusError StatusError
	if !errors.As(errDo, &statusError) {
		t.Fatalf("Do() error = %v, want StatusError", errDo)
	}
	if statusError.ProviderCode != "quota_exhausted" || statusError.ProviderType != "access_terminated_error" {
		t.Fatalf("structured identity = code=%q type=%q", statusError.ProviderCode, statusError.ProviderType)
	}
	if strings.Contains(errDo.Error(), "private provider detail") || strings.Contains(errDo.Error(), statusError.ProviderCode) || strings.Contains(errDo.Error(), statusError.ProviderType) {
		t.Fatalf("safe error leaked provider body identity: %v", errDo)
	}
}

// TestStructuredErrorIdentityRejectsFreeFormAndOversizedTokens verifies untrusted text cannot enter classifier fields.
// TestStructuredErrorIdentityRejectsFreeFormAndOversizedTokens 验证不可信文本不能进入分类器字段。
func TestStructuredErrorIdentityRejectsFreeFormAndOversizedTokens(t *testing.T) {
	oversized := strings.Repeat("a", maximumStructuredErrorTokenBytes+1)
	body := strings.NewReader(`{"code":"contains spaces","type":"` + oversized + `"}`)
	code, errorType := readStructuredErrorIdentity(body)
	if code != "" || errorType != "" {
		t.Fatalf("unsafe structured identity = code=%q type=%q", code, errorType)
	}
}

// TestRetryPolicyBoundsProviderDelayAndDefaultCap verifies untrusted Retry-After values cannot exceed configured backoff bounds.
// TestRetryPolicyBoundsProviderDelayAndDefaultCap 验证不受信任的 Retry-After 值不能超过已配置的退避边界。
func TestRetryPolicyBoundsProviderDelayAndDefaultCap(t *testing.T) {
	// providerDelay simulates an upstream attempt to suspend one retry for an hour.
	// providerDelay 模拟上游试图将一次重试暂停一小时。
	providerDelay := time.Hour
	if delay := (RetryPolicy{InitialBackoff: 2 * time.Second}).delay(3, nil); delay != 2*time.Second {
		t.Fatalf("default maximum backoff delay = %s, want 2s", delay)
	}
	if delay := (RetryPolicy{InitialBackoff: 2 * time.Second, MaxBackoff: 5 * time.Second}).delay(3, nil); delay != 5*time.Second {
		t.Fatalf("exponential capped delay = %s, want 5s", delay)
	}
	if delay := (RetryPolicy{InitialBackoff: time.Second, MaxBackoff: 5 * time.Second}).delay(1, &providerDelay); delay != 5*time.Second {
		t.Fatalf("provider capped delay = %s, want 5s", delay)
	}
	if delay := (RetryPolicy{InitialBackoff: time.Duration(1 << 62), MaxBackoff: time.Duration(1<<63 - 1)}).delay(2, nil); delay != time.Duration(1<<63-1) {
		t.Fatalf("overflow-safe capped delay = %s, want maximum time.Duration", delay)
	}
	if delay := (RetryPolicy{}).delay(1, &providerDelay); delay != 0 {
		t.Fatalf("zero-backoff provider delay = %s, want immediate retry", delay)
	}
}

// TestRetryAfterRejectsTrailingAndOverflowValues verifies seconds parsing is exact and cannot wrap time.Duration.
// TestRetryAfterRejectsTrailingAndOverflowValues 验证秒数解析保持精确且不能使 time.Duration 回绕。
func TestRetryAfterRejectsTrailingAndOverflowValues(t *testing.T) {
	for _, invalidValue := range []string{"10 trailing", "9223372036854775807", "-1"} {
		if delay := parseRetryAfter(invalidValue, time.Now()); delay != nil {
			t.Fatalf("parseRetryAfter(%q) = %s, want nil", invalidValue, *delay)
		}
	}
	if delay := parseRetryAfter("10", time.Now()); delay == nil || *delay != 10*time.Second {
		t.Fatalf("parseRetryAfter(10) = %v, want 10s", delay)
	}
}

// TestRetryPolicyRejectsNegativeBackoffWithDefaultAttempts verifies default single-attempt mode does not hide invalid configuration.
// TestRetryPolicyRejectsNegativeBackoffWithDefaultAttempts 验证默认单次尝试模式不会掩盖无效配置。
func TestRetryPolicyRejectsNegativeBackoffWithDefaultAttempts(t *testing.T) {
	if _, errAttempts := (RetryPolicy{InitialBackoff: -time.Second}).attempts(); !errors.Is(errAttempts, ErrInvalidRequest) {
		t.Fatalf("RetryPolicy.attempts() error = %v, want ErrInvalidRequest", errAttempts)
	}
}

// TestRequestRejectsInvalidHTTPHeaderMetadata verifies every caller-owned header channel is sanitized before a custom HTTPDoer can observe it.
// TestRequestRejectsInvalidHTTPHeaderMetadata 验证每个调用方拥有的 Header 通道都会在自定义 HTTPDoer 观察前完成净化。
func TestRequestRejectsInvalidHTTPHeaderMetadata(t *testing.T) {
	// cases contains isolated malformed header channels over the same otherwise-valid binding.
	// cases 包含基于同一其他字段有效绑定的独立异常 Header 通道。
	cases := []struct {
		// name identifies the rejected transport boundary.
		// name 标识被拒绝的传输边界。
		name string
		// mutate injects one invalid header fact.
		// mutate 注入一个无效 Header 事实。
		mutate func(*Request)
	}{
		{name: "field name", mutate: func(request *Request) { request.Headers = []Header{{Name: "X-Test\r\nInjected", Value: "value"}} }},
		{name: "field value", mutate: func(request *Request) { request.Headers = []Header{{Name: "X-Test", Value: "value\r\nInjected: yes"}} }},
		{name: "host override", mutate: func(request *Request) { request.Headers = []Header{{Name: "Host", Value: "other.example"}} }},
		{name: "idempotency key", mutate: func(request *Request) { request.IdempotencyKey = "key\r\nInjected: yes" }},
		{name: "authentication field", mutate: func(request *Request) {
			request.Authentication = Authentication{Mode: AuthenticationHeader, HeaderName: "Bad Header"}
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			request := testRequest("https://provider.example", "secret-reference")
			testCase.mutate(&request)
			if errValidate := request.Validate(); errValidate == nil {
				t.Fatal("Request.Validate() error = nil, want invalid header rejection")
			}
		})
	}
}

// TestApplyAuthenticationRejectsCredentialHeaderInjection verifies protected credential bytes cannot escape into another HTTP field.
// TestApplyAuthenticationRejectsCredentialHeaderInjection 验证受保护凭据字节不能逸出到另一个 HTTP 字段。
func TestApplyAuthenticationRejectsCredentialHeaderInjection(t *testing.T) {
	request, errRequest := http.NewRequest(http.MethodPost, "https://provider.example/v1/responses", nil)
	if errRequest != nil {
		t.Fatalf("http.NewRequest() error = %v", errRequest)
	}
	if errApply := applyAuthentication(request, Authentication{Mode: AuthenticationBearer}, []byte("token\r\nInjected: yes")); !errors.Is(errApply, ErrInvalidBinding) {
		t.Fatalf("applyAuthentication() error = %v, want ErrInvalidBinding", errApply)
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

// TestBoundedResponseReaderDistinguishesExactEOFAndOverflow verifies response limits never masquerade truncation as success.
// TestBoundedResponseReaderDistinguishesExactEOFAndOverflow 验证响应限制绝不会把截断伪装成成功。
func TestBoundedResponseReaderDistinguishesExactEOFAndOverflow(t *testing.T) {
	exact, errExact := NewBoundedResponseReader(strings.NewReader("1234"), 4)
	if errExact != nil {
		t.Fatalf("create exact bounded reader: %v", errExact)
	}
	exactBody, errReadExact := io.ReadAll(exact)
	if errReadExact != nil || string(exactBody) != "1234" {
		t.Fatalf("exact body=%q error=%v", exactBody, errReadExact)
	}
	overflow, errOverflow := NewBoundedResponseReader(strings.NewReader("12345"), 4)
	if errOverflow != nil {
		t.Fatalf("create overflow bounded reader: %v", errOverflow)
	}
	overflowBody, errReadOverflow := io.ReadAll(overflow)
	if !errors.Is(errReadOverflow, ErrResponseTooLarge) || string(overflowBody) != "1234" {
		t.Fatalf("overflow body=%q error=%v", overflowBody, errReadOverflow)
	}
}

// TestDrainAndCloseBoundsCleanupAndAlwaysCloses verifies cleanup neither consumes an unbounded body nor leaks one that returns a read error.
// TestDrainAndCloseBoundsCleanupAndAlwaysCloses 验证清理既不会消费无界正文，也不会泄漏返回读取错误的正文。
func TestDrainAndCloseBoundsCleanupAndAlwaysCloses(t *testing.T) {
	t.Run("bounded", func(t *testing.T) {
		body := &trackingReadCloser{reader: strings.NewReader(strings.Repeat("x", int(maximumResponseDrainBytes*2)))}
		if errClose := DrainAndClose(&http.Response{Body: body}); errClose != nil {
			t.Fatalf("DrainAndClose() error = %v", errClose)
		}
		if !body.closed || body.readBytes != maximumResponseDrainBytes {
			t.Fatalf("closed=%v read=%d, want closed with %d-byte drain", body.closed, body.readBytes, maximumResponseDrainBytes)
		}
	})
	t.Run("read error", func(t *testing.T) {
		body := &trackingReadCloser{reader: failingReader{}}
		if errClose := DrainAndClose(&http.Response{Body: body}); !errors.Is(errClose, io.ErrUnexpectedEOF) {
			t.Fatalf("DrainAndClose() error = %v, want io.ErrUnexpectedEOF", errClose)
		}
		if !body.closed {
			t.Fatal("response body was not closed after read error")
		}
	})
}

// trackingReadCloser records the exact cleanup read budget and close state.
// trackingReadCloser 记录精确的清理读取预算与关闭状态。
type trackingReadCloser struct {
	// reader supplies the controlled response body bytes.
	// reader 提供受控响应正文字节。
	reader io.Reader
	// readBytes records bytes consumed by cleanup.
	// readBytes 记录清理消费的字节数。
	readBytes int64
	// closed records whether cleanup released the body.
	// closed 记录清理是否释放了正文。
	closed bool
}

// Read delegates to the controlled reader and records consumed bytes.
// Read 委托给受控 Reader 并记录已消费字节。
func (r *trackingReadCloser) Read(destination []byte) (int, error) {
	read, errRead := r.reader.Read(destination)
	r.readBytes += int64(read)
	return read, errRead
}

// Close records deterministic response-body release.
// Close 记录确定性的响应正文释放。
func (r *trackingReadCloser) Close() error {
	r.closed = true
	return nil
}

// failingReader returns one deterministic body-read failure.
// failingReader 返回一个确定性的正文读取失败。
type failingReader struct{}

// Read returns io.ErrUnexpectedEOF without producing bytes.
// Read 在不产生字节的情况下返回 io.ErrUnexpectedEOF。
func (failingReader) Read([]byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

// TestValidateAbsoluteHTTPURLRejectsUnsafeProviderLinks verifies management-visible links cannot carry credentials or executable schemes.
// TestValidateAbsoluteHTTPURLRejectsUnsafeProviderLinks 验证管理可见链接不能携带凭据或可执行 Scheme。
func TestValidateAbsoluteHTTPURLRejectsUnsafeProviderLinks(t *testing.T) {
	for _, rawURL := range []string{"javascript:alert(1)", "file:///tmp/token", "https://user:secret@auth.example/verify", "/relative/verify"} {
		if _, errValidate := ValidateAbsoluteHTTPURL(rawURL); errValidate == nil {
			t.Errorf("ValidateAbsoluteHTTPURL(%q) unexpectedly succeeded", rawURL)
		}
	}
	// normalizedURL is the exact credential-free link returned after surrounding whitespace is removed.
	// normalizedURL 是移除首尾空白后返回的精确无凭据链接。
	normalizedURL, errValidate := ValidateAbsoluteHTTPURL("  https://auth.example/verify?code=ABCD  ")
	if errValidate != nil || normalizedURL != "https://auth.example/verify?code=ABCD" {
		t.Fatalf("ValidateAbsoluteHTTPURL() = %q, %v", normalizedURL, errValidate)
	}
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
