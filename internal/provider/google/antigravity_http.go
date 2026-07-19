package google

import (
	"crypto/tls"
	"net/http"
	"sync"
	"time"
)

var (
	// antigravityHTTPTransportOnce initializes the shared HTTP/1.1 connection pool exactly once.
	// antigravityHTTPTransportOnce 仅初始化一次共享 HTTP/1.1 连接池。
	antigravityHTTPTransportOnce sync.Once
	// antigravityHTTPTransport is the provider-scoped transport copied from CLIProxyAPI's Antigravity executor boundary.
	// antigravityHTTPTransport 是从 CLIProxyAPI Antigravity Executor 边界复制的供应商作用域传输层。
	antigravityHTTPTransport *http.Transport
)

// antigravityCloseRoundTripper marks only execution requests as connection-closing while preserving the shared HTTP/1.1 transport.
// antigravityCloseRoundTripper 仅将执行请求标记为关闭连接，同时保留共享 HTTP/1.1 传输层。
type antigravityCloseRoundTripper struct {
	// next performs the provider-scoped HTTP/1.1 round trip.
	// next 执行供应商作用域 HTTP/1.1 往返。
	next http.RoundTripper
}

// RoundTrip clones one execution request and sets Request.Close exactly as CLIProxyAPI does before sending it.
// RoundTrip 克隆一条执行请求，并在发送前完全按照 CLIProxyAPI 设置 Request.Close。
func (r antigravityCloseRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	outbound := request.Clone(request.Context())
	outbound.Close = true
	return r.next.RoundTrip(outbound)
}

// NewAntigravityHTTPClient creates a control-plane client that shares CLIProxyAPI's HTTP/1.1-only transport.
// NewAntigravityHTTPClient 创建共享 CLIProxyAPI 仅 HTTP/1.1 传输层的控制面客户端。
//
// Parameters:
//   - timeout: maximum duration for one complete provider request; zero keeps the standard no-timeout behavior.
//
// 参数：
//   - timeout：一条完整供应商请求的最长持续时间；零值保留标准库不超时行为。
//
// Returns:
//   - *http.Client: a redirect-refusing Antigravity HTTP/1.1 client.
//
// 返回值：
//   - *http.Client：拒绝重定向的 Antigravity HTTP/1.1 客户端。
func NewAntigravityHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Transport: sharedAntigravityHTTPTransport(),
		Timeout:   timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// NewAntigravityExecutionHTTPClient creates the execution client and closes every model-request connection like CLIProxyAPI.
// NewAntigravityExecutionHTTPClient 创建执行客户端，并像 CLIProxyAPI 一样关闭每条模型请求的连接。
//
// Parameters:
//   - timeout: maximum duration for one complete model request.
//
// 参数：
//   - timeout：一条完整模型请求的最长持续时间。
//
// Returns:
//   - *http.Client: an HTTP/1.1-only client whose execution requests carry Connection: close semantics.
//
// 返回值：
//   - *http.Client：仅使用 HTTP/1.1 且执行请求携带 Connection: close 语义的客户端。
func NewAntigravityExecutionHTTPClient(timeout time.Duration) *http.Client {
	client := NewAntigravityHTTPClient(timeout)
	client.Transport = antigravityCloseRoundTripper{next: client.Transport}
	return client
}

// sharedAntigravityHTTPTransport returns the singleton transport that disables every implicit HTTP/2 negotiation path.
// sharedAntigravityHTTPTransport 返回禁用全部隐式 HTTP/2 协商路径的单例传输层。
func sharedAntigravityHTTPTransport() *http.Transport {
	antigravityHTTPTransportOnce.Do(func() {
		base, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			base = &http.Transport{}
		}
		cloned := base.Clone()
		cloned.ForceAttemptHTTP2 = false
		cloned.TLSNextProto = make(map[string]func(string, *tls.Conn) http.RoundTripper)
		if cloned.TLSClientConfig == nil {
			cloned.TLSClientConfig = &tls.Config{}
		} else {
			cloned.TLSClientConfig = cloned.TLSClientConfig.Clone()
		}
		cloned.TLSClientConfig.NextProtos = []string{"http/1.1"}
		antigravityHTTPTransport = cloned
	})
	return antigravityHTTPTransport
}
