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
	"path"
	"strings"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/dependency"
	chatprofile "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/chat"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
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

// ChatErrorClassifier maps one safe structured Chat transport failure into provider-specific routing semantics.
// ChatErrorClassifier 将一个安全的结构化 Chat 传输故障映射为供应商专属路由语义。
type ChatErrorClassifier interface {
	// ClassifyChatError returns one closed classification only for provider-proven error identities.
	// ClassifyChatError 仅为供应商已验证的错误身份返回一个封闭分类。
	ClassifyChatError(transport.StatusError, resolve.Target, time.Time) (provider.ClassifiedError, bool)
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

// NewBearerChatDriverAtPath creates a Bearer Chat driver for one explicit provider-owned compatible endpoint path.
// NewBearerChatDriverAtPath 为一个显式供应商拥有的兼容入口路径创建 Bearer Chat Driver。
func NewBearerChatDriverAtPath(definitionID string, profileID string, client *transport.Client, capabilities chatprofile.ProfileCapabilities, allowedAuthMethods []providerconfig.AuthMethodType, endpointPath string) (*ChatDriver, error) {
	return newBearerChatDriver(definitionID, profileID, client, capabilities, allowedAuthMethods, endpointPath, nil)
}

// NewBearerChatDriverAtPathWithRequestAdapter creates a path-bound Bearer Chat driver with one required provider wire adapter.
// NewBearerChatDriverAtPathWithRequestAdapter 创建一个绑定路径且带必需供应商 wire 适配器的 Bearer Chat Driver。
func NewBearerChatDriverAtPathWithRequestAdapter(definitionID string, profileID string, client *transport.Client, capabilities chatprofile.ProfileCapabilities, allowedAuthMethods []providerconfig.AuthMethodType, endpointPath string, requestAdapter ChatRequestAdapter) (*ChatDriver, error) {
	if dependency.IsNil(requestAdapter) {
		return nil, ErrInvalidChatDriver
	}
	return newBearerChatDriver(definitionID, profileID, client, capabilities, allowedAuthMethods, endpointPath, requestAdapter)
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
	if (capabilities.ProviderReasoningSwitchAdapter || capabilities.ProviderReasoningBudgetAdapter) && dependency.IsNil(requestAdapter) {
		return nil, fmt.Errorf("%w: provider reasoning adapter capability requires a request adapter", ErrInvalidChatDriver)
	}
	if !validChatEndpointPath(endpointPath) {
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
	capabilities.MediaInputKinds = append([]vcp.MediaKind(nil), capabilities.MediaInputKinds...)
	capabilities.MediaMaterializations = append([]catalog.UpstreamMaterializationMode(nil), capabilities.MediaMaterializations...)
	capabilities.InputAudioFormats = append([]string(nil), capabilities.InputAudioFormats...)
	return &ChatDriver{definitionID: definitionID, profileID: profileID, client: client, capabilities: capabilities, allowedAuthMethods: append([]providerconfig.AuthMethodType(nil), allowedAuthMethods...), endpointPath: endpointPath, requestAdapter: requestAdapter}, nil
}

// validChatEndpointPath reports whether one immutable compatibility path is normalized and ends at Chat Completions.
// validChatEndpointPath 返回一个不可变兼容路径是否规范化并终止于 Chat Completions。
func validChatEndpointPath(endpointPath string) bool {
	return strings.HasPrefix(endpointPath, "/") &&
		!strings.ContainsAny(endpointPath, "?#\\") &&
		path.Clean(endpointPath) == endpointPath &&
		strings.HasSuffix(endpointPath, "/chat/completions")
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
	projected, errProject := chatprofile.ProjectRequestWithInputs(execution.Request, execution.Binding.Target, d.capabilities, execution.LineageID, execution.Now, execution.MaterializedInputs)
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
	if !provider.AdditionalPayloadProjectionIsEmpty(execution.Binding.Target.ProviderAdditionalParameters) || !provider.RequestProjectionIsEmpty(execution.Binding.Target.RequestProjection) {
		encodedRequest, errMarshal = provider.ApplyRequestProjections(encodedRequest, execution.Binding.Target.ProviderAdditionalParameters, execution.Binding.Target.RequestProjection, execution.Request.ReasoningPolicy)
		if errMarshal != nil {
			return provider.ExecutionResult{}, errMarshal
		}
	}
	outbound := transport.Request{
		Binding: execution.Binding, Method: http.MethodPost, Path: d.endpointPath, Body: encodedRequest,
		Headers:        headers,
		Authentication: transport.Authentication{Mode: transport.AuthenticationBearer},
		Stream:         projected.Upstream.Stream, IdempotencyKey: execution.Request.IdempotencyKey,
	}
	if projected.Upstream.Stream {
		return d.executeStream(ctx, execution, outbound, projected, execution.Now)
	}
	return d.executeResponse(ctx, outbound, projected, execution.Now)
}

// executeResponse executes one non-streaming Chat request and rejects trailing untyped JSON values.
// executeResponse 执行一条非流式 Chat 请求并拒绝尾随的未类型化 JSON 值。
func (d *ChatDriver) executeResponse(ctx context.Context, outbound transport.Request, projected chatprofile.ProjectedRequest, now time.Time) (provider.ExecutionResult, error) {
	upstreamResponse, errRequest := d.client.Do(ctx, outbound)
	if errRequest != nil {
		return provider.ExecutionResult{}, d.classifyChatError(outbound.Binding.Target, errRequest, now)
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
func (d *ChatDriver) executeStream(ctx context.Context, execution provider.ExecutionRequest, outbound transport.Request, projected chatprofile.ProjectedRequest, now time.Time) (provider.ExecutionResult, error) {
	upstreamResponse, errRequest := d.client.DoStream(ctx, outbound)
	if errRequest != nil {
		return provider.ExecutionResult{}, d.classifyChatError(outbound.Binding.Target, errRequest, now)
	}
	defer func() {
		_ = transport.DrainAndClose(upstreamResponse)
	}()
	var decoder *chatprofile.StreamDecoder
	var errNew error
	var audioAccumulator *chatAudioAccumulator
	if projected.Upstream.Audio != nil {
		decoder, errNew = chatprofile.NewAudioStreamDecoder(projected.Report.ResponseID, now)
		if errNew == nil {
			audioAccumulator, errNew = newChatAudioAccumulator(execution.Request.Budget.MaxOutputBytes, execution.ResourceSink)
		}
	} else {
		decoder, errNew = chatprofile.NewStreamDecoder(projected.Report.ResponseID, now)
	}
	if errNew != nil {
		return provider.ExecutionResult{}, errNew
	}
	// The decoder creates response.started before reading upstream bytes, so persist that initial causal boundary before any chunk-derived event.
	// 解码器会在读取上游字节前创建 response.started，因此必须在任何分片事件前持久化该初始因果边界。
	if errEmit := provider.EmitExecutionEvents(ctx, execution.EventSink, decoder.Events()); errEmit != nil {
		return provider.ExecutionResult{}, errEmit
	}
	errRead := chatprofile.ReadSSE(upstreamResponse.Body, func(envelope chatprofile.SSEEnvelope) error {
		if bytes.Equal(bytes.TrimSpace(envelope.Data), []byte("[DONE]")) {
			return nil
		}
		var chunk chatprofile.Chunk
		if errDecode := json.Unmarshal(envelope.Data, &chunk); errDecode != nil {
			return fmt.Errorf("%w: SSE JSON: %v", chatprofile.ErrInvalidUpstreamResponse, errDecode)
		}
		events, errPush := decoder.Push(chunk)
		if errPush != nil {
			return errPush
		}
		if errAudio := pushChatChoiceAudio(ctx, audioAccumulator, chunk.Choices); errAudio != nil {
			return errAudio
		}
		return provider.EmitExecutionEvents(ctx, execution.EventSink, events)
	})
	if errRead != nil {
		closingEvents, _ := decoder.Close(errRead)
		_ = provider.EmitExecutionEvents(context.WithoutCancel(ctx), execution.EventSink, closingEvents)
		return provider.ExecutionResult{}, errRead
	}
	generatedResources := make([]provider.GeneratedResource, 0, 1)
	if audioAccumulator != nil {
		audio, errAudio := audioAccumulator.Finalize(ctx)
		if errAudio != nil {
			closingEvents, _ := decoder.Close(errAudio)
			_ = provider.EmitExecutionEvents(context.WithoutCancel(ctx), execution.EventSink, closingEvents)
			return provider.ExecutionResult{}, errAudio
		}
		generatedResources = append(generatedResources, audio)
	}
	closingEvents, errClose := decoder.Close(nil)
	if errClose != nil {
		return provider.ExecutionResult{}, errClose
	}
	if errEmit := provider.EmitExecutionEvents(ctx, execution.EventSink, closingEvents); errEmit != nil {
		return provider.ExecutionResult{}, errEmit
	}
	return provider.ExecutionResult{Response: decoder.Response(), Events: decoder.Events(), Report: mergeReports(projected.Report, decoder.Report()), UpstreamResponseID: decoder.UpstreamResponseID(), GeneratedResources: generatedResources}, nil
}

// classifyChatError delegates only safe structured status evidence to the explicitly registered provider adapter.
// classifyChatError 仅将安全的结构化状态证据委托给显式注册的供应商适配器。
func (d *ChatDriver) classifyChatError(target resolve.Target, executionError error, now time.Time) error {
	classifier, supportsClassification := d.requestAdapter.(ChatErrorClassifier)
	if !supportsClassification {
		return executionError
	}
	var statusError transport.StatusError
	if !errors.As(executionError, &statusError) {
		return executionError
	}
	classification, classified := classifier.ClassifyChatError(statusError, target, now)
	if !classified {
		return executionError
	}
	return provider.WrapClassifiedExecutionError(classification, executionError)
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
