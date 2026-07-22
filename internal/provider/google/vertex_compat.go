// Portions of this driver are copied and architecture-adapted from CLIProxyAPI internal/runtime/executor/gemini_vertex_executor.go at commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// 本 Driver 的部分逻辑复制并架构适配自 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66 中的 internal/runtime/executor/gemini_vertex_executor.go。
package google

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	aistudio "github.com/OpenVulcan/vulcan-model-core/internal/protocol/google/aistudio"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

var (
	// ErrInvalidVertexCompatDriver reports an unconfigured or shape-inconsistent Vertex-compatible execution driver.
	// ErrInvalidVertexCompatDriver 表示未配置或形态不一致的 Vertex 兼容执行 Driver。
	ErrInvalidVertexCompatDriver = errors.New("invalid Vertex-compatible execution driver")
)

// VertexCompatDriver executes CLIProxyAPI's API-key Vertex publisher-path shape for one immutable custom definition.
// VertexCompatDriver 为一个不可变自定义 Definition 执行 CLIProxyAPI 的 API Key Vertex Publisher 路径形态。
type VertexCompatDriver struct {
	// definitionID is the sole custom provider definition permitted to use this Driver.
	// definitionID 是允许使用此 Driver 的唯一自定义供应商 Definition。
	definitionID string
	// client owns provider-scoped HTTP and SSE execution with raw header API keys.
	// client 使用原始 Header API Key 管理供应商作用域 HTTP 与 SSE 执行。
	client *transport.Client
	// capabilities records the conservative Gemini GenerateContent behavior exposed by compatibility endpoints.
	// capabilities 记录兼容 Endpoint 暴露的保守 Gemini GenerateContent 行为。
	capabilities aistudio.ProfileCapabilities
	// decoder reuses the copied AI Studio typed response and SSE reduction boundary.
	// decoder 复用复制的 AI Studio 类型化响应与 SSE 归并边界。
	decoder *AIStudioDriver
}

// NewVertexCompatDriver creates a Driver permanently bound to one custom definition and raw-secret transport.
// NewVertexCompatDriver 创建一个永久绑定到一个自定义 Definition 与原始 Secret 传输的 Driver。
func NewVertexCompatDriver(definitionID string, client *transport.Client, capabilities aistudio.ProfileCapabilities) (*VertexCompatDriver, error) {
	decoder, errDecoder := NewAIStudioDriver(definitionID, client, capabilities)
	if errDecoder != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidVertexCompatDriver, errDecoder)
	}
	copiedCapabilities := capabilities
	copiedCapabilities.ThinkingLevels = append([]string(nil), capabilities.ThinkingLevels...)
	copiedCapabilities.MediaInputKinds = append([]vcp.MediaKind(nil), capabilities.MediaInputKinds...)
	return &VertexCompatDriver{definitionID: strings.TrimSpace(definitionID), client: client, capabilities: copiedCapabilities, decoder: decoder}, nil
}

// ProviderDefinitionID returns the exact custom definition that owns this Driver.
// ProviderDefinitionID 返回拥有此 Driver 的精确自定义 Definition。
func (d *VertexCompatDriver) ProviderDefinitionID() string {
	if d == nil {
		return ""
	}
	return d.definitionID
}

// ProtocolProfileID returns the typed Gemini GenerateContent profile used by Vertex-compatible endpoints.
// ProtocolProfileID 返回 Vertex 兼容 Endpoint 使用的类型化 Gemini GenerateContent Profile。
func (d *VertexCompatDriver) ProtocolProfileID() string {
	return aistudio.ProfileID
}

// Execute projects one VCP request to CLIProxyAPI's exact publisher, model, and action path.
// Execute 将一条 VCP 请求投影到 CLIProxyAPI 精确的 Publisher、Model 与 Action 路径。
func (d *VertexCompatDriver) Execute(ctx context.Context, execution provider.ExecutionRequest) (provider.ExecutionResult, error) {
	if d == nil || d.client == nil || d.decoder == nil {
		return provider.ExecutionResult{}, ErrInvalidVertexCompatDriver
	}
	if execution.Binding.Target.ProviderDefinitionID != d.definitionID {
		return provider.ExecutionResult{}, fmt.Errorf("%w: target definition does not belong to this Vertex-compatible driver", provider.ErrExecutionBinding)
	}
	if _, errValidate := execution.ValidateForProfile(aistudio.ProfileID, providerconfig.AuthMethodHeaderKey); errValidate != nil {
		return provider.ExecutionResult{}, errValidate
	}
	modelName, errModel := aiStudioModelName(execution.Binding.Target.UpstreamModelID)
	if errModel != nil {
		return provider.ExecutionResult{}, errModel
	}
	if isVertexImageGenerationModel(modelName) {
		return provider.ExecutionResult{}, fmt.Errorf("%w: image-generation model %q requires the future VCP resource-output profile", ErrInvalidVertexCompatDriver, modelName)
	}
	projected, errProject := aistudio.ProjectRequest(execution.Request, execution.Binding.Target, d.capabilities, execution.LineageID, execution.Now)
	if errProject != nil {
		return provider.ExecutionResult{}, errProject
	}
	encodedRequest, errMarshal := json.Marshal(projected.Upstream)
	if errMarshal != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: encode Vertex-compatible request: %v", ErrInvalidVertexCompatDriver, errMarshal)
	}
	action := "generateContent"
	if execution.Request.Stream {
		action = "streamGenerateContent"
	}
	outbound := transport.Request{
		Binding: execution.Binding, Method: http.MethodPost,
		Path: vertexCompatEndpointPath(modelName, action, execution.Request.Stream), Body: encodedRequest,
		Headers:        []transport.Header{{Name: "Content-Type", Value: "application/json"}},
		Authentication: transport.Authentication{Mode: transport.AuthenticationHeader, HeaderName: "X-Goog-Api-Key"},
		Stream:         execution.Request.Stream, IdempotencyKey: execution.Request.IdempotencyKey,
	}
	if execution.Request.Stream {
		return d.decoder.executeStream(ctx, execution, outbound, projected, execution.Now)
	}
	return d.decoder.executeResponse(ctx, outbound, projected, execution.Now)
}

// CountTokens executes CLIProxyAPI's Vertex-compatible countTokens action against the same immutable target.
// CountTokens 对同一不可变 Target 执行 CLIProxyAPI 的 Vertex 兼容 countTokens 动作。
func (d *VertexCompatDriver) CountTokens(ctx context.Context, execution provider.ExecutionRequest) (aistudio.CountTokensResult, error) {
	if d == nil || d.client == nil {
		return aistudio.CountTokensResult{}, ErrInvalidVertexCompatDriver
	}
	if execution.Binding.Target.ProviderDefinitionID != d.definitionID {
		return aistudio.CountTokensResult{}, fmt.Errorf("%w: target definition does not belong to this Vertex-compatible driver", provider.ErrExecutionBinding)
	}
	if _, errValidate := execution.ValidateForProfile(aistudio.ProfileID, providerconfig.AuthMethodHeaderKey); errValidate != nil {
		return aistudio.CountTokensResult{}, errValidate
	}
	modelName, errModel := aiStudioModelName(execution.Binding.Target.UpstreamModelID)
	if errModel != nil {
		return aistudio.CountTokensResult{}, errModel
	}
	if isVertexImageGenerationModel(modelName) {
		return aistudio.CountTokensResult{}, fmt.Errorf("%w: image-generation models do not support this countTokens profile", ErrInvalidVertexCompatDriver)
	}
	projected, _, errProject := aistudio.ProjectCountTokensRequest(execution.Request, execution.Binding.Target, d.capabilities, execution.LineageID, execution.Now)
	if errProject != nil {
		return aistudio.CountTokensResult{}, errProject
	}
	// encodedRequest follows CLIProxyAPI by sending the GenerateContent body directly without an AI Studio wrapper.
	// encodedRequest 遵循 CLIProxyAPI，直接发送 GenerateContent Body 而不使用 AI Studio 包装。
	encodedRequest, errMarshal := json.Marshal(projected.Upstream)
	if errMarshal != nil {
		return aistudio.CountTokensResult{}, fmt.Errorf("%w: encode Vertex-compatible countTokens request: %v", ErrInvalidVertexCompatDriver, errMarshal)
	}
	outbound := transport.Request{
		Binding: execution.Binding, Method: http.MethodPost,
		Path: vertexCompatEndpointPath(modelName, "countTokens", false), Body: encodedRequest,
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
		return aistudio.CountTokensResult{}, fmt.Errorf("%w: bound Vertex compatibility countTokens response: %v", aistudio.ErrInvalidUpstreamResponse, errBound)
	}
	var upstream aistudio.CountTokensResponse
	decoder := json.NewDecoder(boundedBody)
	if errDecode := decoder.Decode(&upstream); errDecode != nil {
		return aistudio.CountTokensResult{}, fmt.Errorf("%w: decode Vertex-compatible countTokens response: %v", aistudio.ErrInvalidUpstreamResponse, errDecode)
	}
	if errTrailing := rejectTrailingJSON(decoder); errTrailing != nil {
		return aistudio.CountTokensResult{}, errTrailing
	}
	if upstream.TotalTokens == nil {
		return aistudio.CountTokensResult{}, fmt.Errorf("%w: countTokens response omits totalTokens", aistudio.ErrInvalidUpstreamResponse)
	}
	usage := vcp.UsageObservation{
		InputTokens: upstream.TotalTokens, CacheReadTokens: upstream.CachedContentTokenCount, TotalTokens: upstream.TotalTokens,
		Source: "provider_reported", Aggregation: "snapshot", Phase: "preflight", AccountingBasis: "vertex_compat_count_tokens", Final: true,
	}
	report := aistudio.CountTokensReport(projected.Report, usage, upstream)
	return aistudio.CountTokensResult{TotalTokens: upstream.TotalTokens, Usage: usage, Report: report, Projected: projected}, nil
}

// PreflightUsage exposes Vertex-compatible countTokens through the provider-neutral preflight contract.
// PreflightUsage 通过供应商无关预检合同公开 Vertex 兼容 countTokens。
func (d *VertexCompatDriver) PreflightUsage(ctx context.Context, execution provider.ExecutionRequest) (provider.UsagePreflightResult, error) {
	result, errCount := d.CountTokens(ctx, execution)
	if errCount != nil {
		return provider.UsagePreflightResult{}, errCount
	}
	return provider.UsagePreflightResult{Usage: result.Usage, Accuracy: vcp.PreflightExact}, nil
}

// vertexCompatEndpointPath builds CLIProxyAPI's exact v1 publisher, model, and action path.
// vertexCompatEndpointPath 构建 CLIProxyAPI 精确的 v1 Publisher、Model 与 Action 路径。
func vertexCompatEndpointPath(modelName string, action string, stream bool) string {
	path := "/" + vertexAPIVersion + "/publishers/google/models/" + url.PathEscape(modelName) + ":" + action
	if stream {
		path += "?alt=sse"
	}
	return path
}
