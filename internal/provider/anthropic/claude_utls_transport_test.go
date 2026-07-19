package anthropic

import (
	"net/http"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

// TestNewClaudeHTTPClientUsesCopiedUTLSDirectTransport verifies the exact private transport and direct default.
// TestNewClaudeHTTPClientUsesCopiedUTLSDirectTransport 验证精确私有传输与直连默认值。
func TestNewClaudeHTTPClientUsesCopiedUTLSDirectTransport(t *testing.T) {
	client, errClient := NewClaudeHTTPClient("", time.Second)
	if errClient != nil {
		t.Fatalf("NewClaudeHTTPClient() error = %v", errClient)
	}
	transport, ok := client.Transport.(*claudeUTLSRoundTripper)
	if !ok || transport == nil {
		t.Fatalf("Claude transport = %T", client.Transport)
	}
	if transport.dialer != proxy.Direct {
		t.Fatalf("Claude direct dialer = %T", transport.dialer)
	}
	if client.CheckRedirect == nil {
		t.Fatalf("Claude client permits default redirect following")
	}
}

// TestNewClaudeHTTPClientAppliesExplicitProxy verifies copied proxy-dialer integration.
// TestNewClaudeHTTPClientAppliesExplicitProxy 验证复制的代理 Dialer 集成。
func TestNewClaudeHTTPClientAppliesExplicitProxy(t *testing.T) {
	client, errClient := NewClaudeHTTPClient("socks5://proxy.example.com:1080", time.Second)
	if errClient != nil {
		t.Fatalf("NewClaudeHTTPClient() error = %v", errClient)
	}
	transport := client.Transport.(*claudeUTLSRoundTripper)
	if transport.dialer == proxy.Direct {
		t.Fatalf("explicit proxy retained direct dialer")
	}
}

// TestClaudeUTLSTransportRejectsPlainHTTP verifies credentials cannot leave the TLS boundary.
// TestClaudeUTLSTransportRejectsPlainHTTP 验证凭据不能离开 TLS 边界。
func TestClaudeUTLSTransportRejectsPlainHTTP(t *testing.T) {
	client, errClient := NewClaudeHTTPClient("", time.Second)
	if errClient != nil {
		t.Fatalf("NewClaudeHTTPClient() error = %v", errClient)
	}
	request, errRequest := http.NewRequest(http.MethodPost, "http://api.anthropic.com/v1/oauth/token", nil)
	if errRequest != nil {
		t.Fatalf("create request: %v", errRequest)
	}
	if _, errRoundTrip := client.Transport.RoundTrip(request); errRoundTrip == nil {
		t.Fatalf("RoundTrip() accepted plain HTTP")
	}
}
