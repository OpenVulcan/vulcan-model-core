// Package openai contains provider-scoped OpenAI execution drivers.
// Package openai 包含供应商作用域的 OpenAI 执行 Driver。
//
// Portions of this driver are adapted from CLIProxyAPI internal/runtime/executor/openai_compat_executor.go at commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// 本 Driver 的部分逻辑改编自 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66 中的 internal/runtime/executor/openai_compat_executor.go。
// Source path: internal/runtime/executor/openai_compat_executor.go.
// 来源路径：internal/runtime/executor/openai_compat_executor.go。
// The adapted scope is provider-bound HTTP/SSE action execution without CLIProxyAPI configuration, logs, or runtime dependencies.
// 改编范围为 Provider 绑定 HTTP/SSE 动作执行，不引入 CLIProxyAPI 配置、日志或运行时依赖。
package openai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	responsesprofile "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/responses"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

var (
	// ErrInvalidResponsesDriver reports an unconfigured OpenAI Responses execution driver.
	// ErrInvalidResponsesDriver 表示未配置的 OpenAI Responses 执行 Driver。
	ErrInvalidResponsesDriver = errors.New("invalid OpenAI Responses execution driver")
)

const (
	// openAIResponsesEndpointPath is appended to an origin-only system-provider endpoint.
	// openAIResponsesEndpointPath 追加到仅含 Origin 的系统供应商 Endpoint。
	openAIResponsesEndpointPath = "/v1/responses"
	// openAIResponsesCompatibilityEndpointPath is appended to a versioned OpenAI-compatible Base URL.
	// openAIResponsesCompatibilityEndpointPath 追加到带版本的 OpenAI 兼容 Base URL。
	openAIResponsesCompatibilityEndpointPath = "/responses"
)

// ResponsesDriver executes the one registered OpenAI Responses profile for one immutable provider definition.
// ResponsesDriver 为一个不可变 Provider Definition 执行唯一已注册的 OpenAI Responses Profile。
type ResponsesDriver struct {
	// definitionID is the sole provider definition permitted to use this driver.
	// definitionID 是允许使用此 Driver 的唯一 Provider Definition。
	definitionID string
	// client owns provider-scoped HTTP and SSE execution.
	// client 负责供应商作用域的 HTTP 与 SSE 执行。
	client *transport.Client
	// capabilities records the verified protocol behavior selected for this driver instance.
	// capabilities 记录为此 Driver 实例选定的已验证协议行为。
	capabilities responsesprofile.ProfileCapabilities
	// allowedAuthMethods is the closed credential-type set accepted by this Bearer wire contract.
	// allowedAuthMethods 是此 Bearer Wire 合同接受的封闭凭据类型集合。
	allowedAuthMethods []providerconfig.AuthMethodType
	// endpointPath is the immutable Responses path appended to the configured Base URL.
	// endpointPath 是追加到已配置 Base URL 的不可变 Responses 路径。
	endpointPath string
}

// NewResponsesDriver creates a driver that remains permanently bound to one provider definition and transport client.
// NewResponsesDriver 创建一个永久绑定到一个 Provider Definition 与传输客户端的 Driver。
func NewResponsesDriver(definitionID string, client *transport.Client, capabilities responsesprofile.ProfileCapabilities) (*ResponsesDriver, error) {
	return newResponsesDriver(definitionID, client, capabilities, []providerconfig.AuthMethodType{providerconfig.AuthMethodAPIKey}, openAIResponsesEndpointPath)
}

// NewOpenAIResponsesCompatibilityDriver creates a custom-provider Responses driver over a versioned Base URL and Bearer credential.
// NewOpenAIResponsesCompatibilityDriver 基于带版本 Base URL 与 Bearer 凭据创建自定义供应商 Responses Driver。
func NewOpenAIResponsesCompatibilityDriver(definitionID string, client *transport.Client, capabilities responsesprofile.ProfileCapabilities) (*ResponsesDriver, error) {
	return newResponsesDriver(definitionID, client, capabilities, []providerconfig.AuthMethodType{providerconfig.AuthMethodBearer}, openAIResponsesCompatibilityEndpointPath)
}

// newResponsesDriver validates and copies one exact Responses endpoint and authentication shape.
// newResponsesDriver 校验并复制一个精确的 Responses Endpoint 与认证形态。
func newResponsesDriver(definitionID string, client *transport.Client, capabilities responsesprofile.ProfileCapabilities, allowedAuthMethods []providerconfig.AuthMethodType, endpointPath string) (*ResponsesDriver, error) {
	if strings.TrimSpace(definitionID) == "" || client == nil {
		return nil, ErrInvalidResponsesDriver
	}
	if endpointPath != openAIResponsesEndpointPath && endpointPath != openAIResponsesCompatibilityEndpointPath {
		return nil, ErrInvalidResponsesDriver
	}
	if len(allowedAuthMethods) != 1 || (allowedAuthMethods[0] != providerconfig.AuthMethodAPIKey && allowedAuthMethods[0] != providerconfig.AuthMethodBearer) {
		return nil, ErrInvalidResponsesDriver
	}
	copiedCapabilities := capabilities
	copiedCapabilities.MediaInputKinds = append([]vcp.MediaKind(nil), capabilities.MediaInputKinds...)
	copiedCapabilities.MediaMaterializations = append([]catalog.UpstreamMaterializationMode(nil), capabilities.MediaMaterializations...)
	return &ResponsesDriver{definitionID: definitionID, client: client, capabilities: copiedCapabilities, allowedAuthMethods: append([]providerconfig.AuthMethodType(nil), allowedAuthMethods...), endpointPath: endpointPath}, nil
}

// ProviderDefinitionID returns the exact definition that owns this Responses driver.
// ProviderDefinitionID 返回拥有此 Responses Driver 的精确 Definition。
func (d *ResponsesDriver) ProviderDefinitionID() string {
	if d == nil {
		return ""
	}
	return d.definitionID
}

// ProtocolProfileID returns the one OpenAI Responses protocol profile implemented by this driver.
// ProtocolProfileID 返回此 Driver 实现的唯一 OpenAI Responses 协议 Profile。
func (d *ResponsesDriver) ProtocolProfileID() string {
	return responsesprofile.ProfileID
}

// Execute projects one VCP request, sends it to the immutable target, and decodes exactly that provider response.
// Execute 投影一条 VCP 请求，将其发送到不可变 Target，并解码该 Provider 的精确响应。
func (d *ResponsesDriver) Execute(ctx context.Context, execution provider.ExecutionRequest) (provider.ExecutionResult, error) {
	if d == nil || d.client == nil {
		return provider.ExecutionResult{}, ErrInvalidResponsesDriver
	}
	if execution.Binding.Target.ProviderDefinitionID != d.definitionID {
		return provider.ExecutionResult{}, fmt.Errorf("%w: target definition does not belong to this driver", provider.ErrExecutionBinding)
	}
	if _, errValidate := execution.ValidateForProfile(responsesprofile.ProfileID, d.allowedAuthMethods...); errValidate != nil {
		return provider.ExecutionResult{}, errValidate
	}
	previousResponseID := ""
	if execution.Continuation != nil {
		previousResponseID = execution.Continuation.UpstreamResponseID
	}
	projected, errProject := responsesprofile.ProjectRequestWithInputs(execution.Request, execution.Binding.Target, d.capabilities, execution.LineageID, previousResponseID, execution.Now, execution.MaterializedInputs)
	if errProject != nil {
		return provider.ExecutionResult{}, errProject
	}
	encodedRequest, errMarshal := json.Marshal(projected.Upstream)
	if errMarshal != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: encode request: %v", ErrInvalidResponsesDriver, errMarshal)
	}
	outbound := transport.Request{
		Binding: execution.Binding, Method: http.MethodPost, Path: d.endpointPath, Body: encodedRequest,
		Headers:        []transport.Header{{Name: "Content-Type", Value: "application/json"}},
		Authentication: transport.Authentication{Mode: transport.AuthenticationBearer},
		Stream:         projected.Upstream.Stream, IdempotencyKey: execution.Request.IdempotencyKey,
	}
	if projected.Upstream.Stream {
		return d.executeStream(ctx, outbound, projected, execution.Now)
	}
	return d.executeResponse(ctx, outbound, projected, execution.Now)
}

// executeResponse executes one non-streaming response request and rejects trailing untyped payload data.
// executeResponse 执行一条非流式响应请求并拒绝尾随的未类型化载荷数据。
func (d *ResponsesDriver) executeResponse(ctx context.Context, outbound transport.Request, projected responsesprofile.ProjectedRequest, now time.Time) (provider.ExecutionResult, error) {
	upstreamResponse, errRequest := d.client.Do(ctx, outbound)
	if errRequest != nil {
		return provider.ExecutionResult{}, errRequest
	}
	defer func() {
		_ = transport.DrainAndClose(upstreamResponse)
	}()
	boundedBody, errBound := transport.NewBoundedResponseReader(upstreamResponse.Body, transport.MaximumNonStreamingResponseBytes)
	if errBound != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: bound response: %v", responsesprofile.ErrInvalidUpstreamResponse, errBound)
	}
	var upstream responsesprofile.Response
	decoder := json.NewDecoder(boundedBody)
	if errDecode := decoder.Decode(&upstream); errDecode != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: decode response: %v", responsesprofile.ErrInvalidUpstreamResponse, errDecode)
	}
	var trailing json.RawMessage
	if errTrailing := decoder.Decode(&trailing); !errors.Is(errTrailing, io.EOF) {
		if errTrailing == nil {
			return provider.ExecutionResult{}, fmt.Errorf("%w: response contains trailing JSON value", responsesprofile.ErrInvalidUpstreamResponse)
		}
		return provider.ExecutionResult{}, fmt.Errorf("%w: decode trailing response data: %v", responsesprofile.ErrInvalidUpstreamResponse, errTrailing)
	}
	response, events, decodedReport, errDecode := responsesprofile.DecodeResponse(projected.Report.ResponseID, upstream, now)
	if errDecode != nil {
		return provider.ExecutionResult{}, errDecode
	}
	return provider.ExecutionResult{Response: response, Events: events, Report: mergeReports(projected.Report, decodedReport), UpstreamResponseID: upstream.ID}, nil
}

// executeStream executes one SSE response request and converts every parsed upstream frame into the same VCP replay log.
// executeStream 执行一条 SSE 响应请求并将每个已解析上游帧转换为同一 VCP 回放日志。
func (d *ResponsesDriver) executeStream(ctx context.Context, outbound transport.Request, projected responsesprofile.ProjectedRequest, now time.Time) (provider.ExecutionResult, error) {
	upstreamResponse, errRequest := d.client.DoStream(ctx, outbound)
	if errRequest != nil {
		return provider.ExecutionResult{}, errRequest
	}
	defer func() {
		_ = transport.DrainAndClose(upstreamResponse)
	}()
	decoder, errNew := responsesprofile.NewStreamDecoder(projected.Report.ResponseID, now)
	if errNew != nil {
		return provider.ExecutionResult{}, errNew
	}
	errRead := responsesprofile.ReadSSE(upstreamResponse.Body, func(envelope responsesprofile.SSEEnvelope) error {
		_, errPush := decoder.PushSSE(envelope)
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

// mergeReports combines projection-owned routing facts with decoder-owned provider observations without replacing unknown values.
// mergeReports 组合投影拥有的路由事实与解码器拥有的 Provider 观测，且不替换未知值。
func mergeReports(projected vcp.ExecutionReport, decoded vcp.ExecutionReport) vcp.ExecutionReport {
	merged := projected
	if decoded.Usage != nil {
		usage := *decoded.Usage
		merged.Usage = &usage
	}
	if decoded.ErrorOrRetryAdvice != "" {
		merged.ErrorOrRetryAdvice = decoded.ErrorOrRetryAdvice
	}
	for _, code := range decoded.ConversionSummary {
		if !containsConversionCode(merged.ConversionSummary, code) {
			merged.ConversionSummary = append(merged.ConversionSummary, code)
		}
	}
	return merged
}

// containsConversionCode reports whether a stable conversion code has already been recorded.
// containsConversionCode 报告是否已经记录了一个稳定转换代码。
func containsConversionCode(codes []string, target string) bool {
	for _, code := range codes {
		if code == target {
			return true
		}
	}
	return false
}
