package resource

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/dependency"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

var (
	// ErrUnsafeImportURL reports a URL, host, DNS answer, or redirect that may access a non-public network.
	// ErrUnsafeImportURL 表示 URL、Host、DNS 结果或重定向可能访问非公网网络。
	ErrUnsafeImportURL = errors.New("unsafe resource import URL")
	// ErrImportResponse reports a non-successful or malformed public download response.
	// ErrImportResponse 表示非成功或格式错误的公网下载响应。
	ErrImportResponse = errors.New("invalid resource import response")
)

// DNSResolver is the exact hostname resolution dependency used before every network connection.
// DNSResolver 是每次网络连接前使用的精确主机名解析依赖。
type DNSResolver interface {
	// LookupNetIP resolves one hostname for the requested IP network.
	// LookupNetIP 为请求的 IP 网络解析一个主机名。
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

// DialContextFunc dials one already validated literal public address.
// DialContextFunc 拨号一个已经校验的字面公网地址。
type DialContextFunc func(context.Context, string, string) (net.Conn, error)

// ImporterOptions configures secure URL and Base64 ingestion.
// ImporterOptions 配置安全 URL 与 Base64 接收。
type ImporterOptions struct {
	// Resolver performs fresh DNS resolution for every connection.
	// Resolver 为每次连接执行新的 DNS 解析。
	Resolver DNSResolver
	// DialContext connects only to a validated literal IP and defaults to net.Dialer.
	// DialContext 仅连接已校验字面 IP 且默认使用 net.Dialer。
	DialContext DialContextFunc
	// RequestTimeout bounds the complete URL import.
	// RequestTimeout 限制完整 URL 导入时间。
	RequestTimeout time.Duration
	// ResponseHeaderTimeout bounds response header wait.
	// ResponseHeaderTimeout 限制响应 Header 等待时间。
	ResponseHeaderTimeout time.Duration
	// MaxRedirects limits revalidated redirect hops.
	// MaxRedirects 限制重新校验的重定向跳数。
	MaxRedirects int
}

// Importer acquires external bytes and delegates verified object publication to Service.
// Importer 获取外部字节并委派给 Service 完成已校验对象发布。
type Importer struct {
	// resources owns bounded hashing, probing, storage, and metadata.
	// resources 拥有受限 Hash、探测、存储和元数据。
	resources *Service
	// client is isolated from environment proxies and caller headers.
	// client 与环境代理及调用方 Header 隔离。
	client *http.Client
	// resolver is retained for deterministic host validation tests and dial behavior.
	// resolver 为确定性 Host 校验测试和拨号行为保留。
	resolver DNSResolver
}

// URLImportInput contains one typed public URL acquisition request.
// URLImportInput 包含一个类型化公网 URL 获取请求。
type URLImportInput struct {
	// OwnerAPIKeyID is the authenticated non-secret call-key identifier.
	// OwnerAPIKeyID 是已认证非秘密调用密钥标识。
	OwnerAPIKeyID string
	// URL is the exact caller-authorized public HTTP or HTTPS location.
	// URL 是调用方授权的精确公网 HTTP 或 HTTPS 位置。
	URL string
	// Kind is verified against downloaded magic.
	// Kind 将与下载内容魔数核对。
	Kind vcp.MediaKind
	// DeclaredMIME optionally adds a strict caller expectation.
	// DeclaredMIME 可选地增加严格调用方预期。
	DeclaredMIME string
	// Retention controls Router object expiry.
	// Retention 控制 Router 对象过期。
	Retention RetentionPolicy
	// ExpiresAt is used only by explicit expiry retention.
	// ExpiresAt 仅由明确过期保留策略使用。
	ExpiresAt *time.Time
	// GeneratedBy records safe execution provenance for provider-generated URL acquisition.
	// GeneratedBy 为供应商生成 URL 获取记录安全执行来源。
	GeneratedBy *GenerationProvenance
}

// PublicDocumentFetcher securely downloads a bounded public sidecar document without persisting it as media.
// PublicDocumentFetcher 安全下载一个受限公网 Sidecar 文档且不将其持久化为媒体。
type PublicDocumentFetcher interface {
	// FetchPublicDocument downloads one public URL after the same SSRF and redirect validation used by resource imports.
	// FetchPublicDocument 使用与资源导入相同的 SSRF 与重定向校验下载一个公网 URL。
	FetchPublicDocument(context.Context, string, int64) ([]byte, error)
}

// Base64Encoding identifies one closed accepted Base64 alphabet.
// Base64Encoding 标识一种封闭且接受的 Base64 字母表。
type Base64Encoding string

const (
	// Base64Standard uses RFC 4648 padded standard encoding.
	// Base64Standard 使用 RFC 4648 带填充标准编码。
	Base64Standard Base64Encoding = "standard"
	// Base64URLSafe uses RFC 4648 padded URL-safe encoding.
	// Base64URLSafe 使用 RFC 4648 带填充 URL 安全编码。
	Base64URLSafe Base64Encoding = "url_safe"
)

// Base64ImportInput contains one typed bounded Base64 acquisition request.
// Base64ImportInput 包含一个类型化受限 Base64 获取请求。
type Base64ImportInput struct {
	// OwnerAPIKeyID is the authenticated non-secret call-key identifier.
	// OwnerAPIKeyID 是已认证非秘密调用密钥标识。
	OwnerAPIKeyID string
	// Data contains encoded bytes only at this call boundary.
	// Data 仅在此调用边界包含编码字节。
	Data string
	// Encoding identifies the exact alphabet.
	// Encoding 标识精确字母表。
	Encoding Base64Encoding
	// Kind is verified against decoded magic.
	// Kind 将与解码内容魔数核对。
	Kind vcp.MediaKind
	// DeclaredMIME optionally adds a strict caller expectation.
	// DeclaredMIME 可选地增加严格调用方预期。
	DeclaredMIME string
	// Retention controls Router object expiry.
	// Retention 控制 Router 对象过期。
	Retention RetentionPolicy
	// ExpiresAt is used only by explicit expiry retention.
	// ExpiresAt 仅由明确过期保留策略使用。
	ExpiresAt *time.Time
}

// NewImporter creates one proxy-free HTTP client with fresh public-IP validation on every dial.
// NewImporter 创建一个无代理 HTTP 客户端并在每次拨号时重新校验公网 IP。
func NewImporter(resources *Service, options ImporterOptions) (*Importer, error) {
	if resources == nil || options.RequestTimeout <= 0 || options.ResponseHeaderTimeout <= 0 || options.MaxRedirects < 0 {
		return nil, fmt.Errorf("%w: resource service, timeouts, and redirect limit are required", ErrInvalidResource)
	}
	if dependency.IsNil(options.Resolver) {
		options.Resolver = net.DefaultResolver
	}
	if options.DialContext == nil {
		dialer := &net.Dialer{Timeout: options.ResponseHeaderTimeout, KeepAlive: 30 * time.Second}
		options.DialContext = dialer.DialContext
	}
	secureDial := secureDialContext(options.Resolver, options.DialContext)
	transport := &http.Transport{
		Proxy: nil, DialContext: secureDial, ForceAttemptHTTP2: true,
		TLSHandshakeTimeout: options.ResponseHeaderTimeout, ResponseHeaderTimeout: options.ResponseHeaderTimeout,
	}
	client := &http.Client{Transport: transport, Timeout: options.RequestTimeout}
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) > options.MaxRedirects {
			return fmt.Errorf("%w: redirect limit exceeded", ErrUnsafeImportURL)
		}
		return validateImportTarget(request.Context(), options.Resolver, request.URL)
	}
	return &Importer{resources: resources, client: client, resolver: options.Resolver}, nil
}

// ImportURL fetches one public object without forwarding caller credentials or trusting response MIME.
// ImportURL 获取一个公网对象且不转发调用方凭据或信任响应 MIME。
func (i *Importer) ImportURL(ctx context.Context, input URLImportInput) (Resource, error) {
	return i.importURL(ctx, input, SourceURLImport)
}

// ImportGeneratedURL securely fetches one provider-generated public object without retaining its temporary URL.
// ImportGeneratedURL 安全获取一个供应商生成的公网对象且不保留其临时 URL。
func (i *Importer) ImportGeneratedURL(ctx context.Context, input URLImportInput) (Resource, error) {
	return i.importURL(ctx, input, SourceGenerated)
}

// FetchPublicDocument securely downloads one bounded provider sidecar without retaining its URL or bytes.
// FetchPublicDocument 安全下载一个受限供应商 Sidecar，且不保留其 URL 或字节。
func (i *Importer) FetchPublicDocument(ctx context.Context, rawURL string, maximumBytes int64) ([]byte, error) {
	if i == nil || maximumBytes <= 0 {
		return nil, fmt.Errorf("%w: document byte ceiling is required", ErrImportResponse)
	}
	parsed, errParse := url.Parse(rawURL)
	if errParse != nil {
		return nil, fmt.Errorf("%w: parse document URL", ErrUnsafeImportURL)
	}
	if errValidate := validateImportTarget(ctx, i.resolver, parsed); errValidate != nil {
		return nil, errValidate
	}
	request, errRequest := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if errRequest != nil {
		return nil, fmt.Errorf("create public document request: %w", errRequest)
	}
	request.Header.Set("Accept", "application/json")
	response, errDo := i.client.Do(request)
	if errDo != nil {
		return nil, fmt.Errorf("download public document: %w", errDo)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("%w: document upstream status %d", ErrImportResponse, response.StatusCode)
	}
	if response.ContentLength > maximumBytes {
		return nil, fmt.Errorf("%w: document exceeds byte ceiling", ErrImportResponse)
	}
	bounded := io.LimitReader(response.Body, maximumBytes+1)
	content, errRead := io.ReadAll(bounded)
	if errRead != nil {
		return nil, fmt.Errorf("read public document: %w", errRead)
	}
	if int64(len(content)) > maximumBytes {
		return nil, fmt.Errorf("%w: document exceeds byte ceiling", ErrImportResponse)
	}
	return content, nil
}

// importURL securely fetches one public object for the exact authorized ingestion source.
// importURL 为精确授权接收来源安全获取一个公网对象。
func (i *Importer) importURL(ctx context.Context, input URLImportInput, source Source) (Resource, error) {
	parsed, errParse := url.Parse(input.URL)
	if errParse != nil {
		return Resource{}, fmt.Errorf("%w: parse URL: %v", ErrUnsafeImportURL, errParse)
	}
	if errValidate := validateImportTarget(ctx, i.resolver, parsed); errValidate != nil {
		return Resource{}, errValidate
	}
	request, errRequest := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if errRequest != nil {
		return Resource{}, fmt.Errorf("create resource import request: %w", errRequest)
	}
	request.Header.Set("Accept", "*/*")
	response, errDo := i.client.Do(request)
	if errDo != nil {
		return Resource{}, fmt.Errorf("download resource URL: %w", errDo)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return Resource{}, fmt.Errorf("%w: upstream status %d", ErrImportResponse, response.StatusCode)
	}
	if response.ContentLength > i.resources.options.MaxObjectBytes {
		return Resource{}, ErrResourceQuotaExceeded
	}
	finalURL := ""
	if source == SourceURLImport {
		finalURL = response.Request.URL.String()
	}
	return i.resources.Create(ctx, CreateInput{
		OwnerAPIKeyID: input.OwnerAPIKeyID, Kind: input.Kind, DeclaredMIME: input.DeclaredMIME, Source: source, SourceURL: finalURL,
		Retention: input.Retention, ExpiresAt: input.ExpiresAt, GeneratedBy: input.GeneratedBy, Reader: response.Body,
	})
}

// ImportBase64 decodes one explicit alphabet as a stream into bounded resource ingestion.
// ImportBase64 将一个明确字母表作为流解码到受限资源接收。
func (i *Importer) ImportBase64(ctx context.Context, input Base64ImportInput) (Resource, error) {
	var encoding *base64.Encoding
	switch input.Encoding {
	case Base64Standard:
		encoding = base64.StdEncoding.Strict()
	case Base64URLSafe:
		encoding = base64.URLEncoding.Strict()
	default:
		return Resource{}, fmt.Errorf("%w: invalid Base64 encoding %q", ErrInvalidResource, input.Encoding)
	}
	maximumLength, errMaximumLength := maximumBase64Length(i.resources.options.MaxObjectBytes)
	if errMaximumLength != nil {
		return Resource{}, errMaximumLength
	}
	if input.Data == "" || int64(len(input.Data)) > maximumLength {
		return Resource{}, ErrResourceQuotaExceeded
	}
	decoder := base64.NewDecoder(encoding, strings.NewReader(input.Data))
	return i.resources.Create(ctx, CreateInput{
		OwnerAPIKeyID: input.OwnerAPIKeyID, Kind: input.Kind, DeclaredMIME: input.DeclaredMIME, Source: SourceBase64Import,
		Retention: input.Retention, ExpiresAt: input.ExpiresAt, Reader: decoder,
	})
}

// maximumBase64Length returns the largest encoded length without native-int conversion or overflow.
// maximumBase64Length 在不转换为原生 int 且不溢出的前提下返回最大编码长度。
func maximumBase64Length(decodedBytes int64) (int64, error) {
	if decodedBytes <= 0 || decodedBytes > (math.MaxInt64/4)*3-2 {
		return 0, fmt.Errorf("%w: invalid Base64 byte ceiling", ErrInvalidResource)
	}
	return ((decodedBytes + 2) / 3) * 4, nil
}

// secureDialContext resolves, validates, and connects only to literal public IP addresses.
// secureDialContext 解析、校验并仅连接字面公网 IP 地址。
func secureDialContext(resolver DNSResolver, dial DialContextFunc) DialContextFunc {
	return func(ctx context.Context, network string, address string) (net.Conn, error) {
		host, port, errSplit := net.SplitHostPort(address)
		if errSplit != nil {
			return nil, fmt.Errorf("%w: invalid dial address", ErrUnsafeImportURL)
		}
		addresses, errResolve := resolvePublicAddresses(ctx, resolver, host)
		if errResolve != nil {
			return nil, errResolve
		}
		var lastError error
		for _, candidate := range addresses {
			connection, errDial := dial(ctx, network, net.JoinHostPort(candidate.String(), port))
			if errDial == nil {
				return connection, nil
			}
			lastError = errDial
		}
		return nil, fmt.Errorf("dial validated public address: %w", lastError)
	}
}

// resolvePublicAddresses resolves one host and rejects the complete answer if any address is non-public.
// resolvePublicAddresses 解析一个 Host 且在任一地址非公网时拒绝完整结果。
func resolvePublicAddresses(ctx context.Context, resolver DNSResolver, host string) ([]netip.Addr, error) {
	if literal, errParse := netip.ParseAddr(host); errParse == nil {
		literal = literal.Unmap()
		if !isPublicAddress(literal) {
			return nil, fmt.Errorf("%w: non-public literal address", ErrUnsafeImportURL)
		}
		return []netip.Addr{literal}, nil
	}
	addresses, errLookup := resolver.LookupNetIP(ctx, "ip", host)
	if errLookup != nil {
		return nil, fmt.Errorf("resolve import host: %w", errLookup)
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("%w: host has no addresses", ErrUnsafeImportURL)
	}
	validated := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if !isPublicAddress(address) {
			return nil, fmt.Errorf("%w: host resolves to non-public address", ErrUnsafeImportURL)
		}
		validated = append(validated, address)
	}
	return validated, nil
}

// validateImportURL verifies scheme and authority before any request or redirect is sent.
// validateImportURL 在发送任何请求或重定向前校验 Scheme 和 Authority。
func validateImportURL(target *url.URL) error {
	if target == nil || (target.Scheme != "http" && target.Scheme != "https") || target.Hostname() == "" || target.User != nil {
		return fmt.Errorf("%w: only credential-free HTTP and HTTPS URLs are allowed", ErrUnsafeImportURL)
	}
	if target.Port() != "" {
		port, errPort := strconv.ParseUint(target.Port(), 10, 16)
		if errPort != nil || port == 0 {
			return fmt.Errorf("%w: invalid URL port", ErrUnsafeImportURL)
		}
	}
	return nil
}

// validateImportTarget verifies URL syntax and current DNS answers before one request or redirect proceeds.
// validateImportTarget 在一次请求或重定向继续前校验 URL 语法及当前 DNS 结果。
func validateImportTarget(ctx context.Context, resolver DNSResolver, target *url.URL) error {
	if errURL := validateImportURL(target); errURL != nil {
		return errURL
	}
	_, errAddresses := resolvePublicAddresses(ctx, resolver, target.Hostname())
	return errAddresses
}

// isPublicAddress rejects local, private, link, multicast, documentation, benchmark, and reserved ranges.
// isPublicAddress 拒绝本地、私网、链路、多播、文档、基准测试及保留地址范围。
func isPublicAddress(address netip.Addr) bool {
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsLoopback() || address.IsPrivate() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range blockedPublicImportPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

// blockedPublicImportPrefixes contains globally routed but non-destination or documentation networks.
// blockedPublicImportPrefixes 包含全局路由但不可作为目标或用于文档的网络。
var blockedPublicImportPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001:db8::/32"),
}
