package google

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// antigravityRoundTripFunc adapts one test function to http.RoundTripper.
// antigravityRoundTripFunc 将一个测试函数适配为 http.RoundTripper。
type antigravityRoundTripFunc func(*http.Request) (*http.Response, error)

// RoundTrip delegates one test request to the wrapped assertion function.
// RoundTrip 将一条测试请求委托给封装的断言函数。
func (f antigravityRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

// TestNewAntigravityHTTPClient verifies the copied HTTP/1.1 negotiation and redirect boundaries.
// TestNewAntigravityHTTPClient 校验复制的 HTTP/1.1 协商与重定向边界。
func TestNewAntigravityHTTPClient(t *testing.T) {
	t.Parallel()

	timeout := 37 * time.Second
	client := NewAntigravityHTTPClient(timeout)
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", client.Transport)
	}
	if client.Timeout != timeout {
		t.Fatalf("timeout = %s, want %s", client.Timeout, timeout)
	}
	if transport.ForceAttemptHTTP2 {
		t.Fatal("ForceAttemptHTTP2 = true, want false")
	}
	if transport.TLSNextProto == nil || len(transport.TLSNextProto) != 0 {
		t.Fatalf("TLSNextProto = %#v, want a non-nil empty map", transport.TLSNextProto)
	}
	if transport.TLSClientConfig == nil || len(transport.TLSClientConfig.NextProtos) != 1 || transport.TLSClientConfig.NextProtos[0] != "http/1.1" {
		t.Fatalf("TLS NextProtos = %#v, want [http/1.1]", transport.TLSClientConfig)
	}
	if secondTransport := NewAntigravityHTTPClient(time.Second).Transport; secondTransport != transport {
		t.Fatal("Antigravity clients do not share the singleton HTTP/1.1 transport")
	}
	if client.CheckRedirect == nil {
		t.Fatal("CheckRedirect is nil")
	}
	if errRedirect := client.CheckRedirect(nil, nil); !errors.Is(errRedirect, http.ErrUseLastResponse) {
		t.Fatalf("CheckRedirect error = %v, want http.ErrUseLastResponse", errRedirect)
	}
}

// TestAntigravityCloseRoundTripper verifies that only the cloned execution request is marked connection-closing.
// TestAntigravityCloseRoundTripper 校验仅克隆后的执行请求会被标记为关闭连接。
func TestAntigravityCloseRoundTripper(t *testing.T) {
	t.Parallel()

	var observedClose bool
	roundTripper := antigravityCloseRoundTripper{next: antigravityRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		observedClose = request.Close
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("{}")), Request: request}, nil
	})}
	request, errRequest := http.NewRequest(http.MethodPost, "https://cloudcode-pa.googleapis.com/v1internal:generateContent", strings.NewReader("{}"))
	if errRequest != nil {
		t.Fatalf("create request: %v", errRequest)
	}
	response, errRoundTrip := roundTripper.RoundTrip(request)
	if errRoundTrip != nil {
		t.Fatalf("round trip: %v", errRoundTrip)
	}
	response.Body.Close()
	if !observedClose {
		t.Fatal("execution request Close = false, want true")
	}
	if request.Close {
		t.Fatal("source request was mutated")
	}
}
