// Package google contains provider-scoped Google execution drivers.
// Package google 包含供应商作用域的 Google 执行 Driver。
//
// Portions of this driver are adapted from CLIProxyAPI internal/runtime/executor/aistudio_executor.go at commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// 本 Driver 的部分逻辑改编自 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66 中的 internal/runtime/executor/aistudio_executor.go。
// Source path: internal/runtime/executor/aistudio_executor.go.
// 来源路径：internal/runtime/executor/aistudio_executor.go。
// The adapted scope is action routing and endpoint construction, without CLIProxyAPI configuration, logging, or runtime dependencies.
// 改编范围为动作路由和端点构造，不引入 CLIProxyAPI 配置、日志或运行时依赖。
package google

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	aistudio "github.com/OpenVulcan/vulcan-model-core/internal/protocol/google/aistudio"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

var (
	// ErrInvalidAIStudioDriver reports an unconfigured Google AI Studio execution driver.
	// ErrInvalidAIStudioDriver 表示未配置的 Google AI Studio 执行 Driver。
	ErrInvalidAIStudioDriver = errors.New("invalid Google AI Studio execution driver")
)

// AIStudioDriver executes the one registered Google AI Studio profile for one immutable provider definition.
// AIStudioDriver 为一个不可变 Provider Definition 执行唯一已注册的 Google AI Studio Profile。
type AIStudioDriver struct {
	// definitionID is the sole provider definition permitted to use this driver.
	// definitionID 是允许使用此 Driver 的唯一 Provider Definition。
	definitionID string
	// client owns provider-scoped HTTP and SSE execution.
	// client 负责供应商作用域的 HTTP 与 SSE 执行。
	client *transport.Client
	// capabilities records the verified protocol behavior selected for this driver instance.
	// capabilities 记录为此 Driver 实例选定的已验证协议行为。
	capabilities aistudio.ProfileCapabilities
}

// NewAIStudioDriver creates a driver permanently bound to one provider definition and transport client.
// NewAIStudioDriver 创建一个永久绑定到一个 Provider Definition 与传输客户端的 Driver。
func NewAIStudioDriver(definitionID string, client *transport.Client, capabilities aistudio.ProfileCapabilities) (*AIStudioDriver, error) {
	if strings.TrimSpace(definitionID) == "" || client == nil {
		return nil, ErrInvalidAIStudioDriver
	}
	// copiedCapabilities prevents caller-owned slices from changing verified driver facts after construction.
	// copiedCapabilities 防止调用方持有的切片在构造后修改已验证的 Driver 能力事实。
	copiedCapabilities := capabilities
	copiedCapabilities.ThinkingLevels = append([]string(nil), capabilities.ThinkingLevels...)
	copiedCapabilities.MediaInputKinds = append([]vcp.MediaKind(nil), capabilities.MediaInputKinds...)
	return &AIStudioDriver{definitionID: definitionID, client: client, capabilities: copiedCapabilities}, nil
}

// ProviderDefinitionID returns the exact definition that owns this AI Studio driver.
// ProviderDefinitionID 返回拥有此 AI Studio Driver 的精确 Definition。
func (d *AIStudioDriver) ProviderDefinitionID() string {
	if d == nil {
		return ""
	}
	return d.definitionID
}

// ProtocolProfileID returns the one Google AI Studio protocol profile implemented by this driver.
// ProtocolProfileID 返回此 Driver 实现的唯一 Google AI Studio 协议 Profile。
func (d *AIStudioDriver) ProtocolProfileID() string {
	return aistudio.ProfileID
}

// Execute projects one VCP request, sends it to the immutable target, and decodes exactly that AI Studio response.
// Execute 投影一条 VCP 请求，将其发送到不可变 Target，并解码该 AI Studio 的精确响应。
func (d *AIStudioDriver) Execute(ctx context.Context, execution provider.ExecutionRequest) (provider.ExecutionResult, error) {
	if d == nil || d.client == nil {
		return provider.ExecutionResult{}, ErrInvalidAIStudioDriver
	}
	if execution.Binding.Target.ProviderDefinitionID != d.definitionID {
		return provider.ExecutionResult{}, fmt.Errorf("%w: target definition does not belong to this driver", provider.ErrExecutionBinding)
	}
	if _, errValidate := execution.ValidateForProfile(aistudio.ProfileID, providerconfig.AuthMethodAPIKey); errValidate != nil {
		return provider.ExecutionResult{}, errValidate
	}
	projected, errProject := aistudio.ProjectRequestWithInputs(execution.Request, execution.Binding.Target, d.capabilities, execution.LineageID, execution.Now, execution.MaterializedInputs)
	if errProject != nil {
		return provider.ExecutionResult{}, errProject
	}
	encodedRequest, errMarshal := json.Marshal(projected.Upstream)
	if errMarshal != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: encode request: %v", ErrInvalidAIStudioDriver, errMarshal)
	}
	action := "generateContent"
	if execution.Request.Stream {
		action = "streamGenerateContent"
	}
	path, errPath := aiStudioEndpointPath(execution.Binding.Target.UpstreamModelID, action, execution.Request.Stream)
	if errPath != nil {
		return provider.ExecutionResult{}, errPath
	}
	outbound := transport.Request{
		Binding: execution.Binding, Method: http.MethodPost, Path: path, Body: encodedRequest,
		Headers:        []transport.Header{{Name: "Content-Type", Value: "application/json"}},
		Authentication: transport.Authentication{Mode: transport.AuthenticationHeader, HeaderName: "X-Goog-Api-Key"},
		Stream:         execution.Request.Stream, IdempotencyKey: execution.Request.IdempotencyKey,
	}
	if execution.Request.Stream {
		return d.executeStream(ctx, execution, outbound, projected, execution.Now)
	}
	return d.executeResponse(ctx, outbound, projected, execution.Now)
}

// CountTokens executes the typed Google AI Studio countTokens action for the same immutable provider target.
// CountTokens 为同一不可变 Provider Target 执行类型化 Google AI Studio countTokens 动作。
func (d *AIStudioDriver) CountTokens(ctx context.Context, execution provider.ExecutionRequest) (aistudio.CountTokensResult, error) {
	if d == nil || d.client == nil {
		return aistudio.CountTokensResult{}, ErrInvalidAIStudioDriver
	}
	if execution.Binding.Target.ProviderDefinitionID != d.definitionID {
		return aistudio.CountTokensResult{}, fmt.Errorf("%w: target definition does not belong to this driver", provider.ErrExecutionBinding)
	}
	if _, errValidate := execution.ValidateForProfile(aistudio.ProfileID, providerconfig.AuthMethodAPIKey); errValidate != nil {
		return aistudio.CountTokensResult{}, errValidate
	}
	projected, countRequest, errProject := aistudio.ProjectCountTokensRequest(execution.Request, execution.Binding.Target, d.capabilities, execution.LineageID, execution.Now)
	if errProject != nil {
		return aistudio.CountTokensResult{}, errProject
	}
	encodedRequest, errMarshal := json.Marshal(countRequest)
	if errMarshal != nil {
		return aistudio.CountTokensResult{}, fmt.Errorf("%w: encode countTokens request: %v", ErrInvalidAIStudioDriver, errMarshal)
	}
	path, errPath := aiStudioEndpointPath(execution.Binding.Target.UpstreamModelID, "countTokens", false)
	if errPath != nil {
		return aistudio.CountTokensResult{}, errPath
	}
	outbound := transport.Request{
		Binding: execution.Binding, Method: http.MethodPost, Path: path, Body: encodedRequest,
		Headers:        []transport.Header{{Name: "Content-Type", Value: "application/json"}},
		Authentication: transport.Authentication{Mode: transport.AuthenticationHeader, HeaderName: "X-Goog-Api-Key"},
		IdempotencyKey: execution.Request.IdempotencyKey,
	}
	upstreamResponse, errRequest := d.client.Do(ctx, outbound)
	if errRequest != nil {
		return aistudio.CountTokensResult{}, errRequest
	}
	defer func() {
		_ = transport.DrainAndClose(upstreamResponse)
	}()
	boundedBody, errBound := transport.NewBoundedResponseReader(upstreamResponse.Body, transport.MaximumNonStreamingResponseBytes)
	if errBound != nil {
		return aistudio.CountTokensResult{}, fmt.Errorf("%w: bound countTokens response: %v", aistudio.ErrInvalidUpstreamResponse, errBound)
	}
	var upstream aistudio.CountTokensResponse
	decoder := json.NewDecoder(boundedBody)
	if errDecode := decoder.Decode(&upstream); errDecode != nil {
		return aistudio.CountTokensResult{}, fmt.Errorf("%w: decode countTokens response: %v", aistudio.ErrInvalidUpstreamResponse, errDecode)
	}
	if errTrailing := rejectTrailingJSON(decoder); errTrailing != nil {
		return aistudio.CountTokensResult{}, errTrailing
	}
	if upstream.TotalTokens == nil {
		return aistudio.CountTokensResult{}, fmt.Errorf("%w: countTokens response omits totalTokens", aistudio.ErrInvalidUpstreamResponse)
	}
	usage := vcp.UsageObservation{
		InputTokens: upstream.TotalTokens, CacheReadTokens: upstream.CachedContentTokenCount, TotalTokens: upstream.TotalTokens,
		Source: "provider_reported", Aggregation: "snapshot", Phase: "preflight", AccountingBasis: "google_aistudio_count_tokens", Final: true,
	}
	report := aistudio.CountTokensReport(projected.Report, usage, upstream)
	return aistudio.CountTokensResult{TotalTokens: upstream.TotalTokens, Usage: usage, Report: report, Projected: projected}, nil
}

// PreflightUsage exposes AI Studio countTokens through the provider-neutral preflight contract.
// PreflightUsage 通过供应商无关预检合同公开 AI Studio countTokens。
func (d *AIStudioDriver) PreflightUsage(ctx context.Context, execution provider.ExecutionRequest) (provider.UsagePreflightResult, error) {
	result, errCount := d.CountTokens(ctx, execution)
	if errCount != nil {
		return provider.UsagePreflightResult{}, errCount
	}
	return provider.UsagePreflightResult{Usage: result.Usage, Accuracy: vcp.PreflightExact}, nil
}

// executeResponse executes one non-streaming AI Studio request and rejects trailing untyped payload data.
// executeResponse 执行一条非流式 AI Studio 请求并拒绝尾随的未类型化载荷数据。
func (d *AIStudioDriver) executeResponse(ctx context.Context, outbound transport.Request, projected aistudio.ProjectedRequest, now time.Time) (provider.ExecutionResult, error) {
	return executeAIStudioResponse(ctx, d.client, outbound, projected, now)
}

// executeAIStudioResponse performs the shared bounded decode for conversation and action-bound generateContent calls.
// executeAIStudioResponse 为会话与动作绑定的 generateContent 调用执行共享的有界解码。
func executeAIStudioResponse(ctx context.Context, client *transport.Client, outbound transport.Request, projected aistudio.ProjectedRequest, now time.Time) (provider.ExecutionResult, error) {
	upstreamResponse, errRequest := client.Do(ctx, outbound)
	if errRequest != nil {
		return provider.ExecutionResult{}, errRequest
	}
	defer func() {
		_ = transport.DrainAndClose(upstreamResponse)
	}()
	boundedBody, errBound := transport.NewBoundedResponseReader(upstreamResponse.Body, transport.MaximumNonStreamingResponseBytes)
	if errBound != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: bound response: %v", aistudio.ErrInvalidUpstreamResponse, errBound)
	}
	var upstream aistudio.GenerateContentResponse
	decoder := json.NewDecoder(boundedBody)
	if errDecode := decoder.Decode(&upstream); errDecode != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: decode response: %v", aistudio.ErrInvalidUpstreamResponse, errDecode)
	}
	if errTrailing := rejectTrailingJSON(decoder); errTrailing != nil {
		return provider.ExecutionResult{}, errTrailing
	}
	response, events, decodedReport, errDecode := aistudio.DecodeResponse(projected.Report.ResponseID, upstream, projected.ToolReferences, now)
	if errDecode != nil {
		return provider.ExecutionResult{}, errDecode
	}
	return provider.ExecutionResult{Response: response, Events: events, Report: mergeAIStudioReports(projected.Report, decodedReport), UpstreamResponseID: upstream.ResponseID}, nil
}

// executeStream executes one AI Studio SSE request and converts every parsed upstream frame into one VCP replay log.
// executeStream 执行一条 AI Studio SSE 请求并将每个已解析上游帧转换为一个 VCP 回放日志。
func (d *AIStudioDriver) executeStream(ctx context.Context, execution provider.ExecutionRequest, outbound transport.Request, projected aistudio.ProjectedRequest, now time.Time) (provider.ExecutionResult, error) {
	upstreamResponse, errRequest := d.client.DoStream(ctx, outbound)
	if errRequest != nil {
		return provider.ExecutionResult{}, errRequest
	}
	defer func() {
		_ = transport.DrainAndClose(upstreamResponse)
	}()
	decoder, errNew := aistudio.NewStreamDecoder(projected.Report.ResponseID, now, projected.ToolReferences)
	if errNew != nil {
		return provider.ExecutionResult{}, errNew
	}
	errRead := aistudio.ReadSSE(upstreamResponse.Body, func(envelope aistudio.SSEEnvelope) error {
		events, errPush := decoder.PushSSE(envelope)
		if errPush != nil {
			return errPush
		}
		return provider.EmitExecutionEvents(ctx, execution.EventSink, events)
	})
	if errRead != nil {
		closingEvents, _ := decoder.Close(errRead)
		_ = provider.EmitExecutionEvents(context.WithoutCancel(ctx), execution.EventSink, closingEvents)
		return provider.ExecutionResult{}, errRead
	}
	closingEvents, errClose := decoder.Close(nil)
	if errClose != nil {
		return provider.ExecutionResult{}, errClose
	}
	if errEmit := provider.EmitExecutionEvents(ctx, execution.EventSink, closingEvents); errEmit != nil {
		return provider.ExecutionResult{}, errEmit
	}
	return provider.ExecutionResult{Response: decoder.Response(), Events: decoder.Events(), Report: mergeAIStudioReports(projected.Report, decoder.Report()), UpstreamResponseID: decoder.UpstreamResponseID()}, nil
}

// aiStudioEndpointPath builds the exact Google AI Studio v1beta action path inside the selected endpoint origin.
// aiStudioEndpointPath 在选定 Endpoint Origin 内构建精确 Google AI Studio v1beta 动作路径。
func aiStudioEndpointPath(upstreamModelID string, action string, stream bool) (string, error) {
	modelName, errModel := aiStudioModelName(upstreamModelID)
	if errModel != nil {
		return "", errModel
	}
	switch action {
	case "generateContent", "streamGenerateContent", "countTokens":
	default:
		return "", fmt.Errorf("%w: unsupported AI Studio action %q", ErrInvalidAIStudioDriver, action)
	}
	if stream != (action == "streamGenerateContent") {
		return "", fmt.Errorf("%w: stream flag does not match AI Studio action", ErrInvalidAIStudioDriver)
	}
	path := "/v1beta/models/" + url.PathEscape(modelName) + ":" + action
	if stream {
		path += "?alt=sse"
	}
	return path, nil
}

// aiStudioModelName accepts the documented models/{id} resource form and the configured bare model ID form.
// aiStudioModelName 接受文档化的 models/{id} 资源形式和配置的裸模型 ID 形式。
func aiStudioModelName(upstreamModelID string) (string, error) {
	modelName := strings.TrimSpace(upstreamModelID)
	if strings.HasPrefix(modelName, "models/") {
		modelName = strings.TrimPrefix(modelName, "models/")
	}
	if modelName == "" || strings.Contains(modelName, "/") || strings.Contains(modelName, ":") {
		return "", fmt.Errorf("%w: upstream model must be one AI Studio model identifier", ErrInvalidAIStudioDriver)
	}
	return modelName, nil
}

// rejectTrailingJSON rejects a second JSON value or malformed trailing bytes after one typed response object.
// rejectTrailingJSON 拒绝一个类型化响应对象之后的第二个 JSON 值或格式错误尾随字节。
func rejectTrailingJSON(decoder *json.Decoder) error {
	var trailing json.RawMessage
	if errTrailing := decoder.Decode(&trailing); !errors.Is(errTrailing, io.EOF) {
		if errTrailing == nil {
			return fmt.Errorf("%w: response contains trailing JSON value", aistudio.ErrInvalidUpstreamResponse)
		}
		return fmt.Errorf("%w: decode trailing response data: %v", aistudio.ErrInvalidUpstreamResponse, errTrailing)
	}
	return nil
}

// mergeAIStudioReports combines projection-owned routing facts with decoder-owned provider observations.
// mergeAIStudioReports 组合投影拥有的路由事实与 Decoder 拥有的 Provider 观测。
func mergeAIStudioReports(projected vcp.ExecutionReport, decoded vcp.ExecutionReport) vcp.ExecutionReport {
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

// containsConversionCode reports whether one stable conversion code is already present.
// containsConversionCode 报告一个稳定转换代码是否已经存在。
func containsConversionCode(codes []string, target string) bool {
	for _, code := range codes {
		if code == target {
			return true
		}
	}
	return false
}
