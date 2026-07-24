// Package transport provides provider-scoped HTTP and SSE transport primitives.
// Package transport 提供供应商作用域 HTTP 与 SSE 传输基础能力。
//
// Portions of the request-boundary behavior are adapted from CLIProxyAPI executor implementations at commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// 部分请求边界行为改编自 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66 的 Executor 实现。
// Source paths include internal/runtime/executor/openai_compat_executor.go, xai_executor.go, and aistudio_executor.go.
// 来源路径包括 internal/runtime/executor/openai_compat_executor.go、xai_executor.go 和 aistudio_executor.go。
// The adapted scope is same-target HTTP/SSE request behavior and safe status handling; all binding and secret ownership are native VCP design.
// 改编范围为同 Target HTTP/SSE 请求行为和安全状态处理；所有绑定和 Secret 所有权均为原生 VCP 设计。
package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/dependency"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

var (
	// ErrHTTPClientRequired reports construction without an HTTP execution dependency.
	// ErrHTTPClientRequired 表示构造时缺少 HTTP 执行依赖。
	ErrHTTPClientRequired = errors.New("HTTP client is required")
	// ErrSecretStoreRequired reports construction without protected credential storage.
	// ErrSecretStoreRequired 表示构造时缺少受保护的凭据存储。
	ErrSecretStoreRequired = errors.New("secret store is required")
	// ErrInvalidBinding reports a target, endpoint, or credential that does not share one immutable scope.
	// ErrInvalidBinding 表示 Target、Endpoint 或 Credential 不属于同一不可变作用域。
	ErrInvalidBinding = errors.New("invalid provider execution binding")
	// ErrInvalidRequest reports a malformed outbound HTTP request description.
	// ErrInvalidRequest 表示出站 HTTP 请求描述格式错误。
	ErrInvalidRequest = errors.New("invalid provider transport request")
	// ErrUnsupportedAuthentication reports an unregistered credential injection mode.
	// ErrUnsupportedAuthentication 表示未注册的凭据注入模式。
	ErrUnsupportedAuthentication = errors.New("unsupported credential injection")
	// ErrResponseTooLarge reports a successful upstream response that exceeded the bounded non-streaming decode budget.
	// ErrResponseTooLarge 表示成功的上游响应超过非流式解码的有界预算。
	ErrResponseTooLarge = errors.New("upstream response exceeds the non-streaming response limit")
)

const (
	// MaximumNonStreamingResponseBytes matches CLIProxyAPI's reviewed 50 MiB executor scanner boundary.
	// MaximumNonStreamingResponseBytes 与 CLIProxyAPI 已审核的 50 MiB Executor 扫描边界一致。
	MaximumNonStreamingResponseBytes int64 = 52_428_800
	// maximumResponseDrainBytes permits small connection-reuse cleanup without consuming an unbounded upstream body.
	// maximumResponseDrainBytes 允许为连接复用清理小型正文，同时避免消费无界上游正文。
	maximumResponseDrainBytes int64 = 64 * 1024
	// maximumStructuredErrorBytes bounds the untrusted JSON inspected only for closed error code and type tokens.
	// maximumStructuredErrorBytes 限制仅为封闭错误代码与类型 Token 检查的不可信 JSON 大小。
	maximumStructuredErrorBytes int64 = 64 * 1024
	// maximumStructuredErrorTokenBytes bounds one provider error code or type before it can enter trusted classification.
	// maximumStructuredErrorTokenBytes 限制进入受信任分类前的单个供应商错误代码或类型长度。
	maximumStructuredErrorTokenBytes = 128
)

// boundedResponseReader turns a byte budget into an explicit overflow error instead of a silent truncated EOF.
// boundedResponseReader 将字节预算转换为显式溢出错误，而不是静默截断的 EOF。
type boundedResponseReader struct {
	// source is the exact successful upstream response body.
	// source 是精确的成功上游响应体。
	source io.Reader
	// remaining is the number of bytes still available to the decoder.
	// remaining 是解码器仍可读取的字节数。
	remaining int64
	// overflowed keeps every read after the first excess byte deterministic.
	// overflowed 使检测到首个超额字节后的每次读取保持确定性。
	overflowed bool
}

// NewBoundedResponseReader creates a reader that returns ErrResponseTooLarge after the exact byte budget is exhausted.
// NewBoundedResponseReader 创建一个在精确字节预算耗尽后返回 ErrResponseTooLarge 的读取器。
func NewBoundedResponseReader(source io.Reader, maximumBytes int64) (io.Reader, error) {
	if source == nil || maximumBytes <= 0 {
		return nil, fmt.Errorf("%w: response reader and positive byte limit are required", ErrInvalidRequest)
	}
	return &boundedResponseReader{source: source, remaining: maximumBytes}, nil
}

// Read implements io.Reader while probing one byte beyond the budget solely to distinguish EOF from overflow.
// Read 实现 io.Reader，并仅探测预算外一个字节以区分 EOF 与溢出。
func (r *boundedResponseReader) Read(destination []byte) (int, error) {
	if len(destination) == 0 {
		return 0, nil
	}
	if r.overflowed {
		return 0, ErrResponseTooLarge
	}
	if r.remaining > 0 {
		if int64(len(destination)) > r.remaining {
			destination = destination[:r.remaining]
		}
		read, errRead := r.source.Read(destination)
		r.remaining -= int64(read)
		return read, errRead
	}
	var probe [1]byte
	read, errRead := r.source.Read(probe[:])
	if read > 0 {
		r.overflowed = true
		return 0, ErrResponseTooLarge
	}
	if errRead == nil {
		return 0, io.ErrNoProgress
	}
	return 0, errRead
}

// HTTPDoer is the minimal standard-library HTTP execution contract used by the transport.
// HTTPDoer 是传输层使用的最小标准库 HTTP 执行合同。
type HTTPDoer interface {
	// Do sends one fully prepared HTTP request.
	// Do 发送一个已完整准备的 HTTP 请求。
	Do(*http.Request) (*http.Response, error)
}

// AuthenticationMode identifies how a resolved secret is injected into one outbound request.
// AuthenticationMode 标识如何将已解析 Secret 注入一条出站请求。
type AuthenticationMode string

const (
	// AuthenticationNone sends no secret and is reserved for explicitly unauthenticated local services.
	// AuthenticationNone 不发送 Secret，保留给明确无需认证的本地服务。
	AuthenticationNone AuthenticationMode = "none"
	// AuthenticationBearer sends the secret as an Authorization Bearer value.
	// AuthenticationBearer 将 Secret 作为 Authorization Bearer 值发送。
	AuthenticationBearer AuthenticationMode = "bearer"
	// AuthenticationHeader sends the secret as the exact value of one named header.
	// AuthenticationHeader 将 Secret 作为指定 Header 的精确值发送。
	AuthenticationHeader AuthenticationMode = "header"
)

// Authentication specifies one closed credential injection shape without storing a secret.
// Authentication 指定一种不存储 Secret 的封闭凭据注入形态。
type Authentication struct {
	// Mode identifies bearer, header, or explicitly unauthenticated behavior.
	// Mode 标识 Bearer、Header 或明确无需认证的行为。
	Mode AuthenticationMode
	// HeaderName identifies the target header only when Mode is AuthenticationHeader.
	// HeaderName 仅在 Mode 为 AuthenticationHeader 时标识目标 Header。
	HeaderName string
}

// Header is one typed non-secret HTTP header at the outbound wire boundary.
// Header 是出站 wire 边界上的一个类型化非秘密 HTTP Header。
type Header struct {
	// Name is the HTTP header field name.
	// Name 是 HTTP Header 字段名称。
	Name string
	// Value is the non-secret field value.
	// Value 是非秘密字段值。
	Value string
}

// Binding groups the exact resolved target and its selected endpoint and credential snapshots.
// Binding 将精确解析的 Target 与选定的 Endpoint、Credential 快照组合在一起。
type Binding struct {
	// Target fixes all provider-scoped routing identifiers for this execution.
	// Target 固定本次执行的全部供应商作用域路由标识。
	Target resolve.Target
	// Endpoint is the exact network destination selected by resolution.
	// Endpoint 是解析阶段选定的精确网络目标。
	Endpoint providerconfig.Endpoint
	// Credential is the exact credential selected by resolution.
	// Credential 是解析阶段选定的精确凭据。
	Credential providerconfig.Credential
}

// Validate verifies that all endpoint and credential facts belong to the immutable target.
// Validate 校验所有 Endpoint 与 Credential 事实都属于不可变 Target。
func (b Binding) Validate() error {
	if strings.TrimSpace(b.Target.ProviderDefinitionID) == "" || strings.TrimSpace(b.Target.ProviderInstanceID) == "" || strings.TrimSpace(b.Target.ChannelID) == "" || strings.TrimSpace(b.Target.EndpointID) == "" || strings.TrimSpace(b.Target.CredentialID) == "" || strings.TrimSpace(b.Target.ExecutionProfileID) == "" {
		return fmt.Errorf("%w: target must contain exact provider, channel, endpoint, credential, and profile identifiers", ErrInvalidBinding)
	}
	// legacyModelExecution is the historical untyped profile-driver shape retained only for persisted compatibility.
	// legacyModelExecution 是仅为持久化兼容保留的历史无类型 Profile Driver 形态。
	legacyModelExecution := b.Target.Operation == "" && b.Target.ActionBindingID == "" && !b.Target.ProfileDriver
	// actionModelExecution is a typed model operation owned by one immutable ActionBinding.
	// actionModelExecution 是由一个不可变 ActionBinding 拥有的类型化模型操作。
	actionModelExecution := b.Target.Operation != "" && b.Target.ActionBindingID != "" && !b.Target.ProfileDriver
	// profileModelExecution is the explicit typed conversation path for a provider definition's primary profile Driver.
	// profileModelExecution 是供应商定义主 Profile Driver 的显式类型化会话路径。
	profileModelExecution := b.Target.Operation == vcp.OperationConversationRespond && b.Target.ActionBindingID == "" && b.Target.ProfileDriver
	modelTarget := b.Target.SubjectKind == resolve.ExecutionSubjectModel && strings.TrimSpace(b.Target.ProviderModelID) != "" && strings.TrimSpace(b.Target.OfferingID) != "" && strings.TrimSpace(b.Target.UpstreamModelID) != "" && (legacyModelExecution || actionModelExecution || profileModelExecution)
	// legacyModelTarget preserves the current conversation-driver boundary until every system model profile is migrated to an ActionBinding.
	// legacyModelTarget 在所有系统模型 Profile 迁移到 ActionBinding 前保留当前会话 Driver 边界。
	legacyModelTarget := b.Target.SubjectKind == "" && strings.TrimSpace(b.Target.ProviderModelID) != "" && strings.TrimSpace(b.Target.UpstreamModelID) != ""
	serviceTarget := b.Target.SubjectKind == resolve.ExecutionSubjectService && strings.TrimSpace(b.Target.ProviderServiceID) != "" && strings.TrimSpace(b.Target.ServiceOfferingID) != "" && strings.TrimSpace(string(b.Target.Operation)) != "" && strings.TrimSpace(b.Target.ActionBindingID) != "" && strings.TrimSpace(b.Target.UpstreamServiceID) != ""
	if (modelTarget || legacyModelTarget) == serviceTarget {
		return fmt.Errorf("%w: target must contain exactly one complete model or service subject", ErrInvalidBinding)
	}
	if (modelTarget || legacyModelTarget) && (b.Target.ProviderServiceID != "" || b.Target.ServiceOfferingID != "" || b.Target.UpstreamServiceID != "" || b.Target.ServiceCapabilities != nil) {
		return fmt.Errorf("%w: model target cannot contain service facts", ErrInvalidBinding)
	}
	if serviceTarget && (b.Target.ProviderModelID != "" || b.Target.OfferingID != "" || b.Target.UpstreamModelID != "") {
		return fmt.Errorf("%w: service target cannot contain model facts", ErrInvalidBinding)
	}
	if b.Endpoint.ID != b.Target.EndpointID || b.Endpoint.ProviderInstanceID != b.Target.ProviderInstanceID {
		return fmt.Errorf("%w: endpoint does not match target", ErrInvalidBinding)
	}
	if b.Credential.ID != b.Target.CredentialID || b.Credential.ProviderInstanceID != b.Target.ProviderInstanceID {
		return fmt.Errorf("%w: credential does not match target", ErrInvalidBinding)
	}
	if b.Endpoint.Status != providerconfig.EndpointReady {
		return fmt.Errorf("%w: endpoint is not ready", ErrInvalidBinding)
	}
	if b.Credential.Status != providerconfig.CredentialActive {
		return fmt.Errorf("%w: credential is not active", ErrInvalidBinding)
	}
	if strings.TrimSpace(b.Endpoint.BaseURL) == "" {
		return fmt.Errorf("%w: endpoint base URL is required", ErrInvalidBinding)
	}
	return nil
}

// Request is one typed outbound HTTP or SSE request after Profile projection.
// Request 是 Profile 投影后的一条类型化 HTTP 或 SSE 出站请求。
type Request struct {
	// Binding fixes the exact provider target and credential scope.
	// Binding 固定精确的供应商 Target 与凭据作用域。
	Binding Binding
	// Method is the explicit HTTP method.
	// Method 是明确的 HTTP 方法。
	Method string
	// Path is a relative endpoint path and optional query, never an absolute URL.
	// Path 是相对端点路径及可选查询，绝不允许为绝对 URL。
	Path string
	// Body contains encoded profile wire bytes only at the transport boundary.
	// Body 仅在传输边界包含已编码的 Profile wire 字节。
	Body []byte
	// Headers contains non-secret protocol headers.
	// Headers 包含非秘密协议 Header。
	Headers []Header
	// Authentication defines the closed secret injection strategy.
	// Authentication 定义封闭的 Secret 注入策略。
	Authentication Authentication
	// Stream requests an SSE response and controls the Accept header.
	// Stream 请求 SSE 响应并控制 Accept Header。
	Stream bool
	// IdempotencyKey permits same-target automatic retry only when non-empty.
	// IdempotencyKey 仅在非空时允许对同一 Target 自动重试。
	IdempotencyKey string
}

// Validate verifies that Request can be sent without escaping the selected provider scope.
// Validate 校验 Request 可以在不逸出选定供应商作用域的前提下发送。
func (r Request) Validate() error {
	if errBinding := r.Binding.Validate(); errBinding != nil {
		return errBinding
	}
	if strings.TrimSpace(r.Method) == "" {
		return fmt.Errorf("%w: method is required", ErrInvalidRequest)
	}
	if strings.TrimSpace(r.Path) == "" {
		return fmt.Errorf("%w: path is required", ErrInvalidRequest)
	}
	if errAuthentication := r.Authentication.validate(); errAuthentication != nil {
		return errAuthentication
	}
	for _, header := range r.Headers {
		if !validHTTPHeaderName(header.Name) {
			return fmt.Errorf("%w: header name is invalid", ErrInvalidRequest)
		}
		if !validHTTPHeaderValue(header.Value) {
			return fmt.Errorf("%w: header %q contains invalid bytes", ErrInvalidRequest, header.Name)
		}
		if strings.EqualFold(header.Name, "Authorization") || strings.EqualFold(header.Name, "Idempotency-Key") || strings.EqualFold(header.Name, "X-Goog-Api-Key") || strings.EqualFold(header.Name, "Host") {
			return fmt.Errorf("%w: reserved header %q must be owned by transport or driver policy", ErrInvalidRequest, header.Name)
		}
	}
	if r.IdempotencyKey != "" && (strings.TrimSpace(r.IdempotencyKey) == "" || !validHTTPHeaderValue(r.IdempotencyKey)) {
		return fmt.Errorf("%w: idempotency key contains invalid HTTP header bytes", ErrInvalidRequest)
	}
	return nil
}

// validate verifies that Authentication is one registered and complete injection shape.
// validate 校验 Authentication 是一种已注册且完整的注入形态。
func (a Authentication) validate() error {
	switch a.Mode {
	case AuthenticationNone, AuthenticationBearer:
		if a.HeaderName != "" {
			return fmt.Errorf("%w: header name is not valid for mode %q", ErrUnsupportedAuthentication, a.Mode)
		}
	case AuthenticationHeader:
		if !validHTTPHeaderName(a.HeaderName) || strings.EqualFold(a.HeaderName, "Host") {
			return fmt.Errorf("%w: header mode requires a valid non-Host header name", ErrUnsupportedAuthentication)
		}
	default:
		return fmt.Errorf("%w: mode %q", ErrUnsupportedAuthentication, a.Mode)
	}
	return nil
}

// validHTTPHeaderName reports whether one field name is an RFC token accepted at the immutable transport boundary.
// validHTTPHeaderName 报告一个字段名是否为不可变传输边界接受的 RFC Token。
func validHTTPHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for index := 0; index < len(name); index++ {
		character := name[index]
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') {
			continue
		}
		switch character {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		default:
			return false
		}
	}
	return true
}

// validHTTPHeaderValue rejects control bytes that could create another field or alter the HTTP message boundary.
// validHTTPHeaderValue 拒绝可能创建其他字段或改变 HTTP 消息边界的控制字节。
func validHTTPHeaderValue(value string) bool {
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character == '\t' || (character >= 0x20 && character != 0x7f) {
			continue
		}
		return false
	}
	return true
}

// RetryPolicy bounds safe retry attempts for an idempotency-protected immutable target.
// RetryPolicy 限制受幂等键保护的不可变 Target 的安全重试次数。
type RetryPolicy struct {
	// MaxAttempts includes the initial attempt and defaults to one.
	// MaxAttempts 包含首次尝试，默认值为一。
	MaxAttempts int
	// InitialBackoff is the first retry delay and defaults to zero.
	// InitialBackoff 是首次重试延迟，默认值为零。
	InitialBackoff time.Duration
	// MaxBackoff caps exponential retry delays and defaults to InitialBackoff.
	// MaxBackoff 限制指数重试延迟，默认值为 InitialBackoff。
	MaxBackoff time.Duration
}

// attempts returns the validated bounded attempt count.
// attempts 返回经过校验且有上限的尝试次数。
func (p RetryPolicy) attempts() (int, error) {
	if p.InitialBackoff < 0 || p.MaxBackoff < 0 {
		return 0, fmt.Errorf("%w: retry backoff must not be negative", ErrInvalidRequest)
	}
	if p.MaxAttempts == 0 {
		return 1, nil
	}
	if p.MaxAttempts < 1 || p.MaxAttempts > 3 {
		return 0, fmt.Errorf("%w: max attempts must be between 1 and 3", ErrInvalidRequest)
	}
	return p.MaxAttempts, nil
}

// Client executes provider-scoped outbound HTTP and SSE requests without logging sensitive payloads.
// Client 在不记录敏感载荷的前提下执行供应商作用域 HTTP 与 SSE 请求。
type Client struct {
	// doer owns actual network execution.
	// doer 负责实际网络执行。
	doer HTTPDoer
	// secrets resolves the selected credential only while building a request.
	// secrets 仅在构建请求期间解析选定凭据。
	secrets secret.Store
	// retry bounds same-target recovery attempts.
	// retry 限制同一 Target 的恢复尝试次数。
	retry RetryPolicy
}

// NewClient creates a transport client with explicit dependency and retry boundaries.
// NewClient 使用明确依赖和重试边界创建传输客户端。
func NewClient(doer HTTPDoer, secrets secret.Store, retry RetryPolicy) (*Client, error) {
	if dependency.IsNil(doer) {
		return nil, ErrHTTPClientRequired
	}
	if dependency.IsNil(secrets) {
		return nil, ErrSecretStoreRequired
	}
	if _, errAttempts := retry.attempts(); errAttempts != nil {
		return nil, errAttempts
	}
	return &Client{doer: refuseRedirects(doer), secrets: secrets, retry: retry}, nil
}

// refuseRedirects clones a standard HTTP client with redirect following disabled while preserving its caller-owned transport settings.
// refuseRedirects 在保留调用方 Transport 设置的同时，复制标准 HTTP 客户端并禁用重定向跟随。
func refuseRedirects(doer HTTPDoer) HTTPDoer {
	standardClient, isStandardClient := doer.(*http.Client)
	if !isStandardClient {
		return doer
	}
	return CloneHTTPClientWithoutRedirects(standardClient)
}

// CloneHTTPClientWithoutRedirects preserves caller-owned transport settings while refusing credential-bearing redirects.
// CloneHTTPClientWithoutRedirects 保留调用方拥有的传输设置，同时拒绝携带凭据的重定向。
func CloneHTTPClientWithoutRedirects(client *http.Client) *http.Client {
	if client == nil {
		return nil
	}
	clonedClient := *client
	clonedClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &clonedClient
}

// NewDefaultClient creates a standard-library client that refuses redirects before credentials can cross origins.
// NewDefaultClient 创建一个会在凭据跨域前拒绝重定向的标准库客户端。
func NewDefaultClient(secrets secret.Store, retry RetryPolicy) (*Client, error) {
	// httpClient intentionally retains the upstream response instead of following redirects with credentials.
	// httpClient 有意保留上游响应，而不携带凭据继续跟随重定向。
	httpClient := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	return NewClient(httpClient, secrets, retry)
}

// Do sends one non-streaming request and returns an open successful upstream response body.
// Do 发送一条非流式请求并返回打开的成功上游响应体。
func (c *Client) Do(ctx context.Context, request Request) (*http.Response, error) {
	return c.do(ctx, request, false)
}

// DoStream sends one SSE request and returns an open successful upstream response body.
// DoStream 发送一条 SSE 请求并返回打开的成功上游响应体。
func (c *Client) DoStream(ctx context.Context, request Request) (*http.Response, error) {
	request.Stream = true
	return c.do(ctx, request, true)
}

// do prepares credentials once per attempt and executes only against the exact immutable target.
// do 每次尝试仅针对精确不可变 Target 准备凭据并执行请求。
func (c *Client) do(ctx context.Context, request Request, stream bool) (*http.Response, error) {
	if c == nil || c.doer == nil || c.secrets == nil {
		return nil, ErrHTTPClientRequired
	}
	if ctx == nil {
		return nil, fmt.Errorf("%w: context is required", ErrInvalidRequest)
	}
	if errRequest := request.Validate(); errRequest != nil {
		return nil, errRequest
	}
	if stream != request.Stream {
		return nil, fmt.Errorf("%w: stream method and request stream flag differ", ErrInvalidRequest)
	}
	// endpointURL is the resolved URL constrained to the selected endpoint base URL.
	// endpointURL 是被限制在选定 Endpoint 基础 URL 内的解析 URL。
	endpointURL, errURL := buildURL(request.Binding.Endpoint.BaseURL, request.Path)
	if errURL != nil {
		return nil, errURL
	}
	// secretValue exists only while request headers are constructed and is never logged or returned.
	// secretValue 仅在构建请求 Header 期间存在，绝不记录日志或返回。
	secretValue, errSecret := c.resolveSecret(ctx, request)
	if errSecret != nil {
		return nil, errSecret
	}
	defer clearBytes(secretValue)

	attempts, errAttempts := c.retry.attempts()
	if errAttempts != nil {
		return nil, errAttempts
	}
	if strings.TrimSpace(request.IdempotencyKey) == "" {
		attempts = 1
	}
	for attempt := 1; attempt <= attempts; attempt++ {
		// upstreamRequest is rebuilt for every retry because HTTP request bodies are single-use.
		// upstreamRequest 会为每次重试重新构建，因为 HTTP 请求体只能使用一次。
		upstreamRequest, errBuild := buildHTTPRequest(ctx, endpointURL, request, secretValue)
		if errBuild != nil {
			return nil, errBuild
		}
		upstreamResponse, errDo := c.doer.Do(upstreamRequest)
		if errDo != nil {
			if attempt < attempts && retryableNetworkError(errDo) {
				if errWait := waitForRetry(ctx, c.retry.delay(attempt, nil)); errWait != nil {
					return nil, errWait
				}
				continue
			}
			return nil, errDo
		}
		if upstreamResponse == nil {
			return nil, fmt.Errorf("%w: HTTP client returned nil response", ErrInvalidRequest)
		}
		if upstreamResponse.Body == nil {
			return nil, fmt.Errorf("%w: HTTP client returned response without a body", ErrInvalidRequest)
		}
		if upstreamResponse.StatusCode >= http.StatusOK && upstreamResponse.StatusCode < http.StatusMultipleChoices {
			return upstreamResponse, nil
		}
		// statusError is intentionally body-free so untrusted upstream text cannot escape as a client error.
		// statusError 有意不携带响应体，防止不可信上游文本作为客户端错误泄露。
		statusError := newStatusError(upstreamResponse)
		if errClose := upstreamResponse.Body.Close(); errClose != nil {
			return nil, errClose
		}
		if attempt < attempts && retryableStatus(upstreamResponse.StatusCode) {
			if errWait := waitForRetry(ctx, c.retry.delay(attempt, statusError.RetryAfter)); errWait != nil {
				return nil, errWait
			}
			continue
		}
		return nil, statusError
	}
	return nil, fmt.Errorf("%w: retry attempts exhausted", ErrInvalidRequest)
}

// resolveSecret obtains the selected credential only for authentication modes that require it.
// resolveSecret 仅为需要认证的模式获取选定凭据。
func (c *Client) resolveSecret(ctx context.Context, request Request) ([]byte, error) {
	if request.Authentication.Mode == AuthenticationNone {
		return nil, nil
	}
	if strings.TrimSpace(request.Binding.Credential.SecretRef) == "" {
		return nil, fmt.Errorf("%w: credential secret reference is required", ErrInvalidBinding)
	}
	secretValue, errSecret := c.secrets.Get(ctx, request.Binding.Credential.SecretRef)
	if errSecret != nil {
		return nil, fmt.Errorf("%w: credential secret is unavailable", ErrInvalidBinding)
	}
	if len(secretValue) == 0 {
		return nil, fmt.Errorf("%w: credential secret is empty", ErrInvalidBinding)
	}
	return secretValue, nil
}

// ValidateAbsoluteHTTPURL validates one provider-returned browser or API link and returns its normalized HTTP(S) form.
// ValidateAbsoluteHTTPURL 校验一个供应商返回的浏览器或 API 链接，并返回其规范化 HTTP(S) 形式。
// The rawURL parameter may contain surrounding whitespace; credentials, missing hosts, and non-HTTP schemes are rejected.
// rawURL 参数可以包含首尾空白；携带凭据、缺少 Host 或使用非 HTTP Scheme 的地址会被拒绝。
func ValidateAbsoluteHTTPURL(rawURL string) (string, error) {
	parsedURL, errParse := url.Parse(strings.TrimSpace(rawURL))
	if errParse != nil || !parsedURL.IsAbs() || parsedURL.Host == "" || parsedURL.User != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		return "", errors.New("provider link must be an absolute credential-free HTTP URL")
	}
	return parsedURL.String(), nil
}

// buildURL joins a relative protocol path to one selected endpoint without accepting another origin.
// buildURL 将相对协议路径拼接到选定 Endpoint，且不接受其他来源。
func buildURL(baseURL string, relativePath string) (*url.URL, error) {
	parsedBase, errBase := url.Parse(strings.TrimSpace(baseURL))
	if errBase != nil || parsedBase.Scheme == "" || parsedBase.Host == "" || (parsedBase.Scheme != "http" && parsedBase.Scheme != "https") || parsedBase.User != nil {
		return nil, fmt.Errorf("%w: endpoint base URL must be an absolute HTTP URL", ErrInvalidBinding)
	}
	parsedPath, errPath := url.Parse(relativePath)
	if errPath != nil || parsedPath.IsAbs() || parsedPath.Host != "" || !strings.HasPrefix(parsedPath.Path, "/") {
		return nil, fmt.Errorf("%w: path must be an origin-relative URL", ErrInvalidRequest)
	}
	if strings.Contains(parsedPath.Path, "../") || strings.HasSuffix(parsedPath.Path, "/..") {
		return nil, fmt.Errorf("%w: path traversal is not allowed", ErrInvalidRequest)
	}
	// endpointURL is a copy so shared configuration is never mutated during execution.
	// endpointURL 是副本，确保执行期间不会修改共享配置。
	endpointURL := *parsedBase
	endpointURL.Path = strings.TrimRight(parsedBase.Path, "/") + "/" + strings.TrimLeft(parsedPath.Path, "/")
	endpointURL.RawPath = ""
	endpointURL.RawQuery = parsedPath.RawQuery
	endpointURL.Fragment = ""
	return &endpointURL, nil
}

// buildHTTPRequest creates one body-replayable standard-library request with transport-owned headers.
// buildHTTPRequest 使用传输层拥有的 Header 创建一条可重放的标准库请求。
func buildHTTPRequest(ctx context.Context, endpointURL *url.URL, request Request, secretValue []byte) (*http.Request, error) {
	// bodyReader is recreated on every attempt to keep retries deterministic.
	// bodyReader 会在每次尝试中重建，以保持重试的确定性。
	bodyReader := bytes.NewReader(request.Body)
	upstreamRequest, errRequest := http.NewRequestWithContext(ctx, request.Method, endpointURL.String(), bodyReader)
	if errRequest != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRequest, errRequest)
	}
	if len(request.Body) > 0 {
		upstreamRequest.Header.Set("Content-Type", "application/json")
	}
	if request.Stream {
		upstreamRequest.Header.Set("Accept", "text/event-stream")
	} else {
		upstreamRequest.Header.Set("Accept", "application/json")
	}
	for _, header := range request.Headers {
		upstreamRequest.Header.Set(header.Name, header.Value)
	}
	if request.IdempotencyKey != "" {
		upstreamRequest.Header.Set("Idempotency-Key", request.IdempotencyKey)
	}
	if errAuthentication := applyAuthentication(upstreamRequest, request.Authentication, secretValue); errAuthentication != nil {
		return nil, errAuthentication
	}
	return upstreamRequest, nil
}

// applyAuthentication injects one secret without ever returning or logging its value.
// applyAuthentication 在绝不返回或记录 Secret 值的前提下注入凭据。
func applyAuthentication(request *http.Request, authentication Authentication, secretValue []byte) error {
	if request == nil {
		return fmt.Errorf("%w: HTTP request is required", ErrInvalidRequest)
	}
	switch authentication.Mode {
	case AuthenticationNone:
		return nil
	case AuthenticationBearer:
		// credentialValue is the sole string projection required by the standard HTTP header map.
		// credentialValue 是标准 HTTP Header Map 所需的唯一字符串投影。
		credentialValue := string(secretValue)
		if !validHTTPHeaderValue(credentialValue) {
			return fmt.Errorf("%w: credential contains invalid HTTP header bytes", ErrInvalidBinding)
		}
		request.Header.Set("Authorization", "Bearer "+credentialValue)
	case AuthenticationHeader:
		// credentialValue is the sole string projection required by the standard HTTP header map.
		// credentialValue 是标准 HTTP Header Map 所需的唯一字符串投影。
		credentialValue := string(secretValue)
		if !validHTTPHeaderValue(credentialValue) {
			return fmt.Errorf("%w: credential contains invalid HTTP header bytes", ErrInvalidBinding)
		}
		request.Header.Set(authentication.HeaderName, credentialValue)
	default:
		return fmt.Errorf("%w: mode %q", ErrUnsupportedAuthentication, authentication.Mode)
	}
	return nil
}

// StatusError is a safe, body-free upstream HTTP failure observation.
// StatusError 是一个安全且不携带响应体的上游 HTTP 失败观测。
type StatusError struct {
	// StatusCode is the upstream HTTP status.
	// StatusCode 是上游 HTTP 状态码。
	StatusCode int
	// RetryAfter is the parsed retry delay when the server supplied one.
	// RetryAfter 是服务端提供时解析出的重试延迟。
	RetryAfter *time.Duration
	// ProviderCode is a bounded structured provider error code containing only safe token characters.
	// ProviderCode 是仅包含安全 Token 字符的有界结构化供应商错误代码。
	ProviderCode string
	// ProviderType is a bounded structured provider error type containing only safe token characters.
	// ProviderType 是仅包含安全 Token 字符的有界结构化供应商错误类型。
	ProviderType string
}

// Error returns a client-safe error string without upstream body content.
// Error 返回不含上游响应体内容的客户端安全错误字符串。
func (e StatusError) Error() string {
	return fmt.Sprintf("upstream HTTP status %d", e.StatusCode)
}

// newStatusError converts one non-success response into body-free retry metadata.
// newStatusError 将一个非成功响应转换为不含响应体的重试元数据。
func newStatusError(response *http.Response) StatusError {
	if response == nil {
		return StatusError{}
	}
	code, errorType := readStructuredErrorIdentity(response.Body)
	return StatusError{StatusCode: response.StatusCode, RetryAfter: parseRetryAfter(response.Header.Get("Retry-After"), time.Now()), ProviderCode: code, ProviderType: errorType}
}

// readStructuredErrorIdentity extracts only bounded token-shaped code and type fields from one untrusted JSON error body.
// readStructuredErrorIdentity 仅从一个不可信 JSON 错误正文中提取有界且呈 Token 形态的代码与类型字段。
func readStructuredErrorIdentity(body io.Reader) (string, string) {
	if body == nil {
		return "", ""
	}
	encoded, errRead := io.ReadAll(io.LimitReader(body, maximumStructuredErrorBytes+1))
	if errRead != nil || int64(len(encoded)) > maximumStructuredErrorBytes {
		return "", ""
	}
	var document map[string]json.RawMessage
	if errDecode := json.Unmarshal(encoded, &document); errDecode != nil {
		return "", ""
	}
	code := safeStructuredErrorToken(document["code"])
	errorType := safeStructuredErrorToken(document["type"])
	var nested map[string]json.RawMessage
	if encodedError, exists := document["error"]; exists && json.Unmarshal(encodedError, &nested) == nil {
		if code == "" {
			code = safeStructuredErrorToken(nested["code"])
		}
		if errorType == "" {
			errorType = safeStructuredErrorToken(nested["type"])
		}
	}
	return code, errorType
}

// safeStructuredErrorToken accepts only short ASCII identifiers and rejects free-form provider text.
// safeStructuredErrorToken 仅接受短 ASCII 标识符并拒绝供应商自由文本。
func safeStructuredErrorToken(encoded json.RawMessage) string {
	var value string
	if len(encoded) == 0 || json.Unmarshal(encoded, &value) != nil {
		return ""
	}
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maximumStructuredErrorTokenBytes {
		return ""
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '_' || character == '-' || character == '.' || character == ':' {
			continue
		}
		return ""
	}
	return value
}

// parseRetryAfter parses standard Retry-After seconds or HTTP-date values.
// parseRetryAfter 解析标准 Retry-After 秒数或 HTTP 日期值。
func parseRetryAfter(value string, now time.Time) *time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if retryAt, errDate := http.ParseTime(value); errDate == nil {
		delay := retryAt.Sub(now)
		if delay < 0 {
			delay = 0
		}
		return &delay
	}
	seconds, errSeconds := strconv.ParseInt(value, 10, 64)
	// maximumRetryAfterSeconds prevents the conversion to time.Duration from wrapping into an immediate negative retry.
	// maximumRetryAfterSeconds 防止转换为 time.Duration 时回绕为立即执行的负重试时间。
	maximumRetryAfterSeconds := int64((time.Duration(1<<63 - 1)) / time.Second)
	if errSeconds != nil || seconds < 0 || seconds > maximumRetryAfterSeconds {
		return nil
	}
	delay := time.Duration(seconds) * time.Second
	return &delay
}

// delay calculates a bounded exponential retry wait, preferring a valid provider delay.
// delay 计算有上限的指数重试等待，优先使用有效的供应商延迟。
func (p RetryPolicy) delay(attempt int, retryAfter *time.Duration) time.Duration {
	// maximumBackoff applies the documented InitialBackoff default and bounds provider-authored Retry-After values.
	// maximumBackoff 应用文档约定的 InitialBackoff 默认值，并限制供应商编写的 Retry-After 值。
	maximumBackoff := p.MaxBackoff
	if maximumBackoff <= 0 {
		maximumBackoff = p.InitialBackoff
	}
	if retryAfter != nil {
		if maximumBackoff <= 0 {
			return 0
		}
		if *retryAfter > maximumBackoff {
			return maximumBackoff
		}
		return *retryAfter
	}
	if p.InitialBackoff <= 0 {
		return 0
	}
	delay := p.InitialBackoff
	for index := 1; index < attempt; index++ {
		if maximumBackoff > 0 && delay >= maximumBackoff {
			return maximumBackoff
		}
		if maximumBackoff > 0 && delay > maximumBackoff/2 {
			return maximumBackoff
		}
		delay *= 2
	}
	if maximumBackoff > 0 && delay > maximumBackoff {
		return maximumBackoff
	}
	return delay
}

// waitForRetry waits without ignoring cancellation or deadline signals.
// waitForRetry 在不忽略取消或截止时间信号的前提下等待重试。
func waitForRetry(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	// timer is stopped on cancellation to release its runtime resources promptly.
	// timer 会在取消时停止，以便及时释放运行时资源。
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// retryableStatus restricts automatic recovery to transient standard HTTP failures.
// retryableStatus 将自动恢复限制为瞬态标准 HTTP 失败。
func retryableStatus(statusCode int) bool {
	return statusCode == http.StatusRequestTimeout || statusCode == http.StatusTooManyRequests || statusCode >= http.StatusInternalServerError
}

// retryableNetworkError permits only timeout or temporary network errors to retry.
// retryableNetworkError 仅允许超时或临时网络错误进入重试。
func retryableNetworkError(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	// networkError is checked structurally so wrapped standard-library errors remain safe to classify.
	// networkError 以结构方式检查，使包装后的标准库错误仍可被安全分类。
	var networkError net.Error
	return errors.As(err, &networkError) && (networkError.Timeout() || networkError.Temporary())
}

// clearBytes overwrites a mutable credential buffer after request construction work completes.
// clearBytes 在请求构建完成后覆盖可变凭据缓冲区。
func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

// DrainAndClose closes a response after discarding at most a bounded amount of unread sensitive content.
// DrainAndClose 在最多丢弃有界数量的未读敏感内容后关闭响应。
func DrainAndClose(response *http.Response) error {
	if response == nil || response.Body == nil {
		return nil
	}
	_, errDrain := io.Copy(io.Discard, io.LimitReader(response.Body, maximumResponseDrainBytes))
	errClose := response.Body.Close()
	return errors.Join(errDrain, errClose)
}
