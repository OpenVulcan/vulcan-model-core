package anthropic

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	proxyutil "github.com/OpenVulcan/vulcan-model-core/internal/thirdparty/cliproxyapi/sdk/proxyutil"
	tls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
)

// claudeUTLSRoundTripper implements the copied CLIProxyAPI Chrome-uTLS and HTTP/2 connection behavior.
// claudeUTLSRoundTripper 实现从 CLIProxyAPI 复制的 Chrome-uTLS 与 HTTP/2 连接行为。
type claudeUTLSRoundTripper struct {
	// mu protects connections and pending connection conditions.
	// mu 保护连接与待建连接条件变量。
	mu sync.Mutex
	// connections caches one reusable HTTP/2 client connection per TLS hostname.
	// connections 按 TLS 主机名缓存一个可复用 HTTP/2 客户端连接。
	connections map[string]*http2.ClientConn
	// pending serializes concurrent connection creation for one TLS hostname.
	// pending 按 TLS 主机名串行化并发建连。
	pending map[string]*sync.Cond
	// dialer creates direct or explicitly proxied TCP connections.
	// dialer 创建直连或显式代理的 TCP 连接。
	dialer proxy.Dialer
}

// NewClaudeHTTPClient creates the exact Chrome-uTLS HTTP/2 client required by Claude Code endpoints.
// NewClaudeHTTPClient 创建 Claude Code 端点所需的精确 Chrome-uTLS HTTP/2 客户端。
func NewClaudeHTTPClient(proxyURL string, timeout time.Duration) (*http.Client, error) {
	if timeout <= 0 {
		return nil, errors.New("Claude HTTP client timeout must be positive")
	}
	// dialer defaults to direct because CLIProxyAPI's uTLS transport treats an unspecified proxy as direct.
	// dialer 默认为直连，因为 CLIProxyAPI 的 uTLS 传输将未指定代理视为直连。
	var dialer proxy.Dialer = proxy.Direct
	configuredDialer, mode, errDialer := proxyutil.BuildDialer(proxyURL)
	if errDialer != nil {
		return nil, fmt.Errorf("configure Claude proxy dialer: %w", errDialer)
	}
	if mode != proxyutil.ModeInherit && configuredDialer != nil {
		dialer = configuredDialer
	}
	roundTripper := &claudeUTLSRoundTripper{
		connections: make(map[string]*http2.ClientConn),
		pending:     make(map[string]*sync.Cond),
		dialer:      dialer,
	}
	return &http.Client{
		Transport: roundTripper,
		Timeout:   timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

// getOrCreateConnection returns one reusable connection or serializes creation for the same host.
// getOrCreateConnection 返回一个可复用连接，或串行化同一主机的建连过程。
func (t *claudeUTLSRoundTripper) getOrCreateConnection(host string, address string) (*http2.ClientConn, error) {
	t.mu.Lock()
	if connection, exists := t.connections[host]; exists && connection.CanTakeNewRequest() {
		t.mu.Unlock()
		return connection, nil
	}
	if condition, exists := t.pending[host]; exists {
		condition.Wait()
		if connection, ready := t.connections[host]; ready && connection.CanTakeNewRequest() {
			t.mu.Unlock()
			return connection, nil
		}
	}
	condition := sync.NewCond(&t.mu)
	t.pending[host] = condition
	t.mu.Unlock()

	connection, errConnection := t.createConnection(host, address)

	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.pending, host)
	condition.Broadcast()
	if errConnection != nil {
		return nil, errConnection
	}
	t.connections[host] = connection
	return connection, nil
}

// createConnection copies CLIProxyAPI's Chrome ClientHello and HTTP/2 client-connection construction.
// createConnection 复制 CLIProxyAPI 的 Chrome ClientHello 与 HTTP/2 客户端连接构造。
func (t *claudeUTLSRoundTripper) createConnection(host string, address string) (*http2.ClientConn, error) {
	connection, errDial := t.dialer.Dial("tcp", address)
	if errDial != nil {
		return nil, fmt.Errorf("dial Claude endpoint: %w", errDial)
	}
	// tlsConnection intentionally uses HelloChrome_Auto because this fingerprint is the upstream-proven Claude Code compatibility boundary.
	// tlsConnection 有意使用 HelloChrome_Auto，因为该指纹是上游验证过的 Claude Code 兼容边界。
	tlsConnection := tls.UClient(connection, &tls.Config{ServerName: host}, tls.HelloChrome_Auto)
	if errHandshake := tlsConnection.Handshake(); errHandshake != nil {
		_ = connection.Close()
		return nil, fmt.Errorf("handshake with Claude endpoint: %w", errHandshake)
	}
	http2Transport := &http2.Transport{}
	http2Connection, errHTTP2 := http2Transport.NewClientConn(tlsConnection)
	if errHTTP2 != nil {
		_ = tlsConnection.Close()
		return nil, fmt.Errorf("create Claude HTTP/2 connection: %w", errHTTP2)
	}
	return http2Connection, nil
}

// RoundTrip sends one HTTPS request through the host-scoped Chrome-uTLS HTTP/2 connection.
// RoundTrip 通过主机作用域的 Chrome-uTLS HTTP/2 连接发送一条 HTTPS 请求。
func (t *claudeUTLSRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	if request == nil || request.URL == nil || request.URL.Scheme != "https" || request.URL.Hostname() == "" {
		return nil, errors.New("Claude uTLS transport requires one absolute HTTPS request")
	}
	address := request.URL.Host
	if !strings.Contains(address, ":") {
		address += ":443"
	}
	hostname := request.URL.Hostname()
	connection, errConnection := t.getOrCreateConnection(hostname, address)
	if errConnection != nil {
		return nil, errConnection
	}
	response, errRoundTrip := connection.RoundTrip(request)
	if errRoundTrip != nil {
		t.mu.Lock()
		if cached, exists := t.connections[hostname]; exists && cached == connection {
			delete(t.connections, hostname)
		}
		t.mu.Unlock()
		return nil, errRoundTrip
	}
	return response, nil
}
