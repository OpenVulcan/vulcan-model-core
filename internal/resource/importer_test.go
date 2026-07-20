package resource

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestResolvePublicAddressesRejectsPrivateAndMixedDNS verifies one unsafe answer rejects the entire host.
// TestResolvePublicAddressesRejectsPrivateAndMixedDNS 验证一个不安全结果会拒绝整个 Host。
func TestResolvePublicAddressesRejectsPrivateAndMixedDNS(t *testing.T) {
	resolver := staticDNSResolver{addresses: []netip.Addr{netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("127.0.0.1")}}
	if _, errResolve := resolvePublicAddresses(context.Background(), resolver, "example.test"); !errors.Is(errResolve, ErrUnsafeImportURL) {
		t.Fatalf("mixed DNS error = %v, want ErrUnsafeImportURL", errResolve)
	}
	for _, literal := range []string{"127.0.0.1", "10.0.0.1", "169.254.1.1", "192.0.2.1", "::1", "fc00::1", "2001:db8::1"} {
		if _, errResolve := resolvePublicAddresses(context.Background(), resolver, literal); !errors.Is(errResolve, ErrUnsafeImportURL) {
			t.Errorf("literal %s error = %v, want ErrUnsafeImportURL", literal, errResolve)
		}
	}
}

// TestSecureDialUsesValidatedLiteralIP verifies DNS names never reach the underlying dialer.
// TestSecureDialUsesValidatedLiteralIP 验证 DNS 名称绝不会到达底层拨号器。
func TestSecureDialUsesValidatedLiteralIP(t *testing.T) {
	resolver := staticDNSResolver{addresses: []netip.Addr{netip.MustParseAddr("93.184.216.34")}}
	dialedAddress := ""
	dial := secureDialContext(resolver, func(_ context.Context, _ string, address string) (net.Conn, error) {
		dialedAddress = address
		return nil, errors.New("stop after address verification")
	})
	_, errDial := dial(context.Background(), "tcp", "example.test:443")
	if errDial == nil || dialedAddress != "93.184.216.34:443" {
		t.Fatalf("dialed address = %q, error = %v", dialedAddress, errDial)
	}
}

// TestImporterBase64PublishesVerifiedResource verifies typed decoding flows through the same magic and storage boundary.
// TestImporterBase64PublishesVerifiedResource 验证类型化解码经过相同魔数与存储边界。
func TestImporterBase64PublishesVerifiedResource(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, time.July, 20, 14, 0, 0, 0, time.UTC)
	resources := newTestService(t, store, &now, "res_dddddddddddddddddddddddddddddddd", nil, 1<<20)
	importer, errImporter := NewImporter(resources, ImporterOptions{Resolver: staticDNSResolver{}, RequestTimeout: time.Second, ResponseHeaderTimeout: time.Second, MaxRedirects: 2})
	if errImporter != nil {
		t.Fatalf("NewImporter() error = %v", errImporter)
	}
	encoded := base64.StdEncoding.EncodeToString(testPNG(t, 2, 1))
	created, errCreate := importer.ImportBase64(context.Background(), Base64ImportInput{
		OwnerAPIKeyID: "key_owner", Data: encoded, Encoding: Base64Standard, Kind: vcp.MediaImage, DeclaredMIME: "image/png", Retention: RetentionEphemeral,
	})
	if errCreate != nil || created.State != StateReady || created.Source != SourceBase64Import || created.Metadata.Image == nil || created.Metadata.Image.Width != 2 {
		t.Fatalf("created Base64 resource = %#v, error = %v", created, errCreate)
	}
}

// TestImporterRevalidatesRedirectBeforeSecondRequest verifies a private redirect is rejected before transport sees it.
// TestImporterRevalidatesRedirectBeforeSecondRequest 验证私网重定向在 Transport 看到第二次请求前被拒绝。
func TestImporterRevalidatesRedirectBeforeSecondRequest(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, time.July, 20, 14, 0, 0, 0, time.UTC)
	resources := newTestService(t, store, &now, "res_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", nil, 1<<20)
	resolver := staticDNSResolver{addresses: []netip.Addr{netip.MustParseAddr("93.184.216.34")}}
	importer, errImporter := NewImporter(resources, ImporterOptions{Resolver: resolver, RequestTimeout: time.Second, ResponseHeaderTimeout: time.Second, MaxRedirects: 2})
	if errImporter != nil {
		t.Fatalf("NewImporter() error = %v", errImporter)
	}
	requests := 0
	importer.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"http://127.0.0.1/private"}}, Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
	})
	_, errImport := importer.ImportURL(context.Background(), URLImportInput{OwnerAPIKeyID: "key_owner", URL: "https://example.test/public", Kind: vcp.MediaImage, Retention: RetentionEphemeral})
	if !errors.Is(errImport, ErrUnsafeImportURL) || requests != 1 {
		t.Fatalf("ImportURL() error = %v, transport requests = %d", errImport, requests)
	}
}

// TestFetchPublicDocumentUsesBoundedCredentialFreeJSONRequest verifies secure sidecar acquisition without persistence or authorization.
// TestFetchPublicDocumentUsesBoundedCredentialFreeJSONRequest 验证不持久化且不携带授权的安全有界 Sidecar 获取。
func TestFetchPublicDocumentUsesBoundedCredentialFreeJSONRequest(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, time.July, 20, 14, 0, 0, 0, time.UTC)
	resources := newTestService(t, store, &now, "res_ffffffffffffffffffffffffffffffff", nil, 1<<20)
	resolver := staticDNSResolver{addresses: []netip.Addr{netip.MustParseAddr("93.184.216.34")}}
	importer, errImporter := NewImporter(resources, ImporterOptions{Resolver: resolver, RequestTimeout: time.Second, ResponseHeaderTimeout: time.Second, MaxRedirects: 2})
	if errImporter != nil {
		t.Fatalf("NewImporter() error = %v", errImporter)
	}
	importer.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.String() != "https://results.example/transcript.json" || request.Header.Get("Accept") != "application/json" || request.Header.Get("Authorization") != "" {
			t.Errorf("request = %s %s headers=%#v", request.Method, request.URL.String(), request.Header)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"result":"ok"}`)), ContentLength: -1, Request: request}, nil
	})
	content, errFetch := importer.FetchPublicDocument(context.Background(), "https://results.example/transcript.json", 64)
	if errFetch != nil || string(content) != `{"result":"ok"}` {
		t.Fatalf("FetchPublicDocument() content = %q, error = %v", content, errFetch)
	}
}

// TestFetchPublicDocumentRejectsOversizedAndUnsafeResponses verifies both streaming size enforcement and SSRF rejection.
// TestFetchPublicDocumentRejectsOversizedAndUnsafeResponses 验证流式大小限制与 SSRF 拒绝。
func TestFetchPublicDocumentRejectsOversizedAndUnsafeResponses(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, time.July, 20, 14, 0, 0, 0, time.UTC)
	resources := newTestService(t, store, &now, "res_11111111111111111111111111111111", nil, 1<<20)
	resolver := staticDNSResolver{addresses: []netip.Addr{netip.MustParseAddr("93.184.216.34")}}
	importer, errImporter := NewImporter(resources, ImporterOptions{Resolver: resolver, RequestTimeout: time.Second, ResponseHeaderTimeout: time.Second, MaxRedirects: 2})
	if errImporter != nil {
		t.Fatalf("NewImporter() error = %v", errImporter)
	}
	importer.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("12345")), ContentLength: -1, Request: request}, nil
	})
	if _, errFetch := importer.FetchPublicDocument(context.Background(), "https://results.example/transcript.json", 4); !errors.Is(errFetch, ErrImportResponse) {
		t.Fatalf("oversized FetchPublicDocument() error = %v", errFetch)
	}
	if _, errFetch := importer.FetchPublicDocument(context.Background(), "http://127.0.0.1/private", 64); !errors.Is(errFetch, ErrUnsafeImportURL) {
		t.Fatalf("unsafe FetchPublicDocument() error = %v", errFetch)
	}
}

// staticDNSResolver returns one deterministic DNS answer set.
// staticDNSResolver 返回一个确定性 DNS 结果集合。
type staticDNSResolver struct {
	// addresses contains the exact returned addresses.
	// addresses 包含精确返回地址。
	addresses []netip.Addr
	// err is the controlled lookup failure.
	// err 是受控查询失败。
	err error
}

// LookupNetIP returns the configured immutable address slice.
// LookupNetIP 返回已配置不可变地址 Slice。
func (r staticDNSResolver) LookupNetIP(_ context.Context, _ string, _ string) ([]netip.Addr, error) {
	return append([]netip.Addr(nil), r.addresses...), r.err
}

// roundTripFunc adapts one test function to http.RoundTripper.
// roundTripFunc 将一个测试函数适配到 http.RoundTripper。
type roundTripFunc func(*http.Request) (*http.Response, error)

// RoundTrip invokes the controlled test transport function.
// RoundTrip 调用受控测试 Transport 函数。
func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
