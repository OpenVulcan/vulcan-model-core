// Portions of this driver are adapted from CLIProxyAPI internal/runtime/executor/openai_compat_executor.go at commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// 本 Driver 的部分逻辑改编自 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66 中的 internal/runtime/executor/openai_compat_executor.go。
// Source path: internal/runtime/executor/openai_compat_executor.go.
// 来源路径：internal/runtime/executor/openai_compat_executor.go。
// The adapted scope is target-bound OpenAI-compatible Chat HTTP/SSE execution without CLIProxyAPI configuration, logs, or runtime dependencies.
// 改编范围为 Target 绑定的 OpenAI 兼容 Chat HTTP/SSE 执行，不引入 CLIProxyAPI 配置、日志或运行时依赖。
package openai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/dependency"
	chatprofile "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/chat"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
)

var (
	// ErrInvalidChatDriver reports an unconfigured OpenAI Chat execution driver.
	// ErrInvalidChatDriver 表示未配置的 OpenAI Chat 执行 Driver。
	ErrInvalidChatDriver = errors.New("invalid OpenAI Chat execution driver")
)

const (
	// openAIChatEndpointPath is the system-provider path appended to an origin-only endpoint.
	// openAIChatEndpointPath 是追加到仅含 Origin 的系统供应商 Endpoint 的路径。
	openAIChatEndpointPath = "/v1/chat/completions"
	// openAICompatibilityEndpointPath is CLIProxyAPI's exact path appended to a versioned compatibility Base URL.
	// openAICompatibilityEndpointPath 是 CLIProxyAPI 追加到带版本兼容 Base URL 的精确路径。
	openAICompatibilityEndpointPath = "/chat/completions"
)

// ChatDriver executes one explicitly registered OpenAI Chat protocol profile for one immutable provider definition.
// ChatDriver 为一个不可变 Provider Definition 执行一个显式注册的 OpenAI Chat 协议 Profile。
type ChatDriver struct {
	// definitionID is the sole provider definition permitted to use this driver.
	// definitionID 是允许使用此 Driver 的唯一 Provider Definition。
	definitionID string
	// profileID is the exact configured Chat protocol profile owned by this driver.
	// profileID 是由此 Driver 拥有的精确已配置 Chat 协议 Profile。
	profileID string
	// client owns provider-scoped HTTP and SSE execution.
	// client 负责供应商作用域的 HTTP 与 SSE 执行。
	client *transport.Client
	// capabilities records the verified protocol behavior selected for this driver instance.
	// capabilities 记录为此 Driver 实例选定的已验证协议行为。
	capabilities chatprofile.ProfileCapabilities
	// allowedAuthMethods is the closed set of credential acquisition types that this Bearer wire adapter may encode.
	// allowedAuthMethods 是此 Bearer 线路适配器可以编码的封闭凭据获取类型集合。
	allowedAuthMethods []providerconfig.AuthMethodType
	// endpointPath is the immutable profile-specific path appended to the selected endpoint Base URL.
	// endpointPath 是追加到选定 Endpoint Base URL 的不可变 Profile 特定路径。
	endpointPath string
	// requestAdapter applies one explicitly registered provider-specific wire adjustment after typed projection.
	// requestAdapter 在类型化投影后应用一个显式注册的供应商专用 wire 调整。
	requestAdapter ChatRequestAdapter
}

// ChatRequestAdapter applies provider-specific wire behavior without weakening the typed Chat protocol boundary.
// ChatRequestAdapter 在不削弱类型化 Chat 协议边界的前提下应用供应商专用 wire 行为。
type ChatRequestAdapter interface {
	// Adapt mutates only the projected request copy and returns non-secret headers for the immutable execution target.
	// Adapt 仅修改投影请求副本，并为不可变执行 Target 返回非秘密请求头。
	Adapt(context.Context, provider.ExecutionRequest, *chatprofile.Request) ([]transport.Header, error)
}

// NewChatDriver creates a driver permanently bound to one provider definition, registered Chat profile, and transport client.
// NewChatDriver 创建一个永久绑定到一个 Provider Definition、已注册 Chat Profile 与传输客户端的 Driver。
func NewChatDriver(definitionID string, profileID string, client *transport.Client, capabilities chatprofile.ProfileCapabilities) (*ChatDriver, error) {
	return NewBearerChatDriver(definitionID, profileID, client, capabilities, []providerconfig.AuthMethodType{providerconfig.AuthMethodAPIKey})
}

// NewBearerChatDriver creates a Chat driver with an explicit closed set of Bearer-compatible credential types.
// NewBearerChatDriver 使用显式封闭的 Bearer 兼容凭据类型集合创建 Chat Driver。
func NewBearerChatDriver(definitionID string, profileID string, client *transport.Client, capabilities chatprofile.ProfileCapabilities, allowedAuthMethods []providerconfig.AuthMethodType) (*ChatDriver, error) {
	return newBearerChatDriver(definitionID, profileID, client, capabilities, allowedAuthMethods, openAIChatEndpointPath, nil)
}

// NewBearerChatDriverWithRequestAdapter creates a Bearer Chat driver with one required provider-specific wire adapter.
// NewBearerChatDriverWithRequestAdapter 使用一个必需的供应商专用 wire 适配器创建 Bearer Chat Driver。
func NewBearerChatDriverWithRequestAdapter(definitionID string, profileID string, client *transport.Client, capabilities chatprofile.ProfileCapabilities, allowedAuthMethods []providerconfig.AuthMethodType, requestAdapter ChatRequestAdapter) (*ChatDriver, error) {
	if dependency.IsNil(requestAdapter) {
		return nil, ErrInvalidChatDriver
	}
	return newBearerChatDriver(definitionID, profileID, client, capabilities, allowedAuthMethods, openAIChatEndpointPath, requestAdapter)
}

// NewOpenAICompatibilityDriver creates CLIProxyAPI's exact OpenAICompatibility Chat driver with Bearer authentication.
// NewOpenAICompatibilityDriver 使用 Bearer 认证创建 CLIProxyAPI 的精确 OpenAICompatibility Chat Driver。
func NewOpenAICompatibilityDriver(definitionID string, client *transport.Client, capabilities chatprofile.ProfileCapabilities) (*ChatDriver, error) {
	return newBearerChatDriver(definitionID, chatprofile.ProfileID, client, capabilities, []providerconfig.AuthMethodType{providerconfig.AuthMethodBearer}, openAICompatibilityEndpointPath, nil)
}

// newBearerChatDriver validates and copies one closed Bearer-compatible Chat execution shape.
// newBearerChatDriver 校验并复制一个封闭的 Bearer 兼容 Chat 执行形态。
func newBearerChatDriver(definitionID string, profileID string, client *transport.Client, capabilities chatprofile.ProfileCapabilities, allowedAuthMethods []providerconfig.AuthMethodType, endpointPath string, requestAdapter ChatRequestAdapter) (*ChatDriver, error) {
	if strings.TrimSpace(definitionID) == "" || strings.TrimSpace(profileID) == "" || client == nil {
		return nil, ErrInvalidChatDriver
	}
	if endpointPath != openAIChatEndpointPath && endpointPath != openAICompatibilityEndpointPath {
		return nil, ErrInvalidChatDriver
	}
	if len(allowedAuthMethods) == 0 {
		return nil, ErrInvalidChatDriver
	}
	for _, authMethod := range allowedAuthMethods {
		switch authMethod {
		case providerconfig.AuthMethodAPIKey, providerconfig.AuthMethodBearer, providerconfig.AuthMethodOAuth, providerconfig.AuthMethodDeviceFlow:
		default:
			return nil, fmt.Errorf("%w: authentication type %q cannot use a Bearer header", ErrInvalidChatDriver, authMethod)
		}
	}
	return &ChatDriver{definitionID: definitionID, profileID: profileID, client: client, capabilities: capabilities, allowedAuthMethods: append([]providerconfig.AuthMethodType(nil), allowedAuthMethods...), endpointPath: endpointPath, requestAdapter: requestAdapter}, nil
}

// ProviderDefinitionID returns the exact definition that owns this Chat driver.
// ProviderDefinitionID 返回拥有此 Chat Driver 的精确 Definition。
func (d *ChatDriver) ProviderDefinitionID() string {
	if d == nil {
		return ""
	}
	return d.definitionID
}

// ProtocolProfileID returns the one explicitly registered Chat protocol profile implemented by this driver.
// ProtocolProfileID 返回此 Driver 实现的唯一显式注册 Chat 协议 Profile。
func (d *ChatDriver) ProtocolProfileID() string {
	if d == nil {
		return ""
	}
	return d.profileID
}

// Execute projects one VCP request, sends it only to the immutable target, and decodes exactly that OpenAI Chat response.
// Execute 投影一条 VCP 请求，仅将其发送到不可变 Target，并解码该 OpenAI Chat 的精确响应。
func (d *ChatDriver) Execute(ctx context.Context, execution provider.ExecutionRequest) (provider.ExecutionResult, error) {
	if d == nil || d.client == nil {
		return provider.ExecutionResult{}, ErrInvalidChatDriver
	}
	if execution.Binding.Target.ProviderDefinitionID != d.definitionID {
		return provider.ExecutionResult{}, fmt.Errorf("%w: target definition does not belong to this driver", provider.ErrExecutionBinding)
	}
	if _, errValidate := execution.ValidateForProfile(d.profileID, d.allowedAuthMethods...); errValidate != nil {
		return provider.ExecutionResult{}, errValidate
	}
	projected, errProject := chatprofile.ProjectRequest(execution.Request, execution.Binding.Target, d.capabilities, execution.LineageID, execution.Now)
	if errProject != nil {
		return provider.ExecutionResult{}, errProject
	}
	// headers begins with the profile-owned content type before an explicit provider adapter appends non-secret wire identity.
	// headers 以 Profile 所有的内容类型开始，随后由显式供应商适配器追加非秘密 wire 身份。
	headers := []transport.Header{{Name: "Content-Type", Value: "application/json"}}
	if d.requestAdapter != nil {
		adaptedHeaders, errAdapt := d.requestAdapter.Adapt(ctx, execution, &projected.Upstream)
		if errAdapt != nil {
			return provider.ExecutionResult{}, errAdapt
		}
		headers = append(headers, adaptedHeaders...)
	}
	encodedRequest, errMarshal := json.Marshal(projected.Upstream)
	if errMarshal != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: encode request: %v", ErrInvalidChatDriver, errMarshal)
	}
	outbound := transport.Request{
		Binding: execution.Binding, Method: http.MethodPost, Path: d.endpointPath, Body: encodedRequest,
		Headers:        headers,
		Authentication: transport.Authentication{Mode: transport.AuthenticationBearer},
		Stream:         projected.Upstream.Stream, IdempotencyKey: execution.Request.IdempotencyKey,
	}
	if projected.Upstream.Stream {
		return d.executeStream(ctx, outbound, projected, execution.Now)
	}
	return d.executeResponse(ctx, outbound, projected, execution.Now)
}

// executeResponse executes one non-streaming Chat request and rejects trailing untyped JSON values.
// executeResponse 执行一条非流式 Chat 请求并拒绝尾随的未类型化 JSON 值。
func (d *ChatDriver) executeResponse(ctx context.Context, outbound transport.Request, projected chatprofile.ProjectedRequest, now time.Time) (provider.ExecutionResult, error) {
	upstreamResponse, errRequest := d.client.Do(ctx, outbound)
	if errRequest != nil {
		return provider.ExecutionResult{}, errRequest
	}
	defer func() {
		_ = transport.DrainAndClose(upstreamResponse)
	}()
	boundedBody, errBound := transport.NewBoundedResponseReader(upstreamResponse.Body, transport.MaximumNonStreamingResponseBytes)
	if errBound != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: bound response: %v", chatprofile.ErrInvalidUpstreamResponse, errBound)
	}
	var upstream chatprofile.Response
	decoder := json.NewDecoder(boundedBody)
	if errDecode := decoder.Decode(&upstream); errDecode != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: decode response: %v", chatprofile.ErrInvalidUpstreamResponse, errDecode)
	}
	if errTrailing := rejectTrailingChatJSON(decoder); errTrailing != nil {
		return provider.ExecutionResult{}, errTrailing
	}
	response, events, decodedReport, errDecode := chatprofile.DecodeResponse(projected.Report.ResponseID, upstream, now)
	if errDecode != nil {
		return provider.ExecutionResult{}, errDecode
	}
	return provider.ExecutionResult{Response: response, Events: events, Report: mergeReports(projected.Report, decodedReport), UpstreamResponseID: upstream.ID}, nil
}

// executeStream executes one Chat SSE request and converts each syntactically complete upstream frame into VCP replay events.
// executeStream 执行一条 Chat SSE 请求，并将每个语法完整的上游帧转换为 VCP 回放事件。
func (d *ChatDriver) executeStream(ctx context.Context, outbound transport.Request, projected chatprofile.ProjectedRequest, now time.Time) (provider.ExecutionResult, error) {
	upstreamResponse, errRequest := d.client.DoStream(ctx, outbound)
	if errRequest != nil {
		return provider.ExecutionResult{}, errRequest
	}
	defer func() {
		_ = transport.DrainAndClose(upstreamResponse)
	}()
	decoder, errNew := chatprofile.NewStreamDecoder(projected.Report.ResponseID, now)
	if errNew != nil {
		return provider.ExecutionResult{}, errNew
	}
	errRead := chatprofile.ReadSSE(upstreamResponse.Body, func(envelope chatprofile.SSEEnvelope) error {
		if bytes.Equal(bytes.TrimSpace(envelope.Data), []byte("[DONE]")) {
			return nil
		}
		var chunk chatprofile.Chunk
		if errDecode := json.Unmarshal(envelope.Data, &chunk); errDecode != nil {
			return fmt.Errorf("%w: SSE JSON: %v", chatprofile.ErrInvalidUpstreamResponse, errDecode)
		}
		_, errPush := decoder.Push(chunk)
		return errPush
	})
	if errRead != nil {
		_, _ = decoder.Close(errRead)
		return provider.ExecutionResult{}, errRead
	}
	if _, errClose := decoder.Close(nil); errClose != nil {
		return provider.ExecutionResult{}, errClose
	}
	return provider.ExecutionResult{Response: decoder.Response(), Events: decoder.Events(), Report: mergeReports(projected.Report, decoder.Report()), UpstreamResponseID: decoder.UpstreamResponseID()}, nil
}

// rejectTrailingChatJSON rejects a second JSON value so the typed response decoder never silently accepts an ambiguous payload.
// rejectTrailingChatJSON 拒绝第二个 JSON 值，确保类型化响应解码器不会静默接受含糊载荷。
func rejectTrailingChatJSON(decoder *json.Decoder) error {
	var trailing json.RawMessage
	if errTrailing := decoder.Decode(&trailing); !errors.Is(errTrailing, io.EOF) {
		if errTrailing == nil {
			return fmt.Errorf("%w: response contains trailing JSON value", chatprofile.ErrInvalidUpstreamResponse)
		}
		return fmt.Errorf("%w: decode trailing response data: %v", chatprofile.ErrInvalidUpstreamResponse, errTrailing)
	}
	return nil
}
