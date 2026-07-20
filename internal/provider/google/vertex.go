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

const (
	// vertexAPIVersion is CLIProxyAPI's exact public Vertex Generative AI API version.
	// vertexAPIVersion 是 CLIProxyAPI 使用的精确公开 Vertex Generative AI API 版本。
	vertexAPIVersion = "v1"
)

var (
	// ErrInvalidVertexDriver reports an unconfigured or scope-inconsistent Vertex execution driver.
	// ErrInvalidVertexDriver 表示未配置或作用域不一致的 Vertex 执行 Driver。
	ErrInvalidVertexDriver = errors.New("invalid Google Vertex AI execution driver")
)

// VertexDriver executes one immutable Google Vertex AI system definition with service-account credentials.
// VertexDriver 使用服务账号凭据执行一个不可变的 Google Vertex AI 系统定义。
type VertexDriver struct {
	// definitionID is the sole provider definition permitted to use this driver.
	// definitionID 是允许使用此 Driver 的唯一供应商定义。
	definitionID string
	// client owns provider-scoped HTTP and SSE execution with projected Google access tokens.
	// client 使用投影后的 Google Access Token 管理供应商作用域 HTTP 与 SSE 执行。
	client *transport.Client
	// capabilities records the verified Gemini GenerateContent behavior selected for Vertex.
	// capabilities 记录为 Vertex 选定的已验证 Gemini GenerateContent 行为。
	capabilities aistudio.ProfileCapabilities
	// decoder reuses the copied AI Studio typed response and SSE reduction boundary.
	// decoder 复用复制的 AI Studio 类型化响应与 SSE 归并边界。
	decoder *AIStudioDriver
}

// NewVertexDriver creates a driver permanently bound to one Vertex definition and access-token transport.
// NewVertexDriver 创建一个永久绑定到 Vertex 定义与 Access Token 传输的 Driver。
func NewVertexDriver(definitionID string, client *transport.Client, capabilities aistudio.ProfileCapabilities) (*VertexDriver, error) {
	decoder, errDecoder := NewAIStudioDriver(definitionID, client, capabilities)
	if errDecoder != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidVertexDriver, errDecoder)
	}
	copiedCapabilities := capabilities
	copiedCapabilities.ThinkingLevels = append([]string(nil), capabilities.ThinkingLevels...)
	copiedCapabilities.MediaInputKinds = append([]vcp.MediaKind(nil), capabilities.MediaInputKinds...)
	return &VertexDriver{definitionID: strings.TrimSpace(definitionID), client: client, capabilities: copiedCapabilities, decoder: decoder}, nil
}

// ProviderDefinitionID returns the exact system definition that owns this Vertex driver.
// ProviderDefinitionID 返回拥有此 Vertex Driver 的精确系统定义。
func (d *VertexDriver) ProviderDefinitionID() string {
	if d == nil {
		return ""
	}
	return d.definitionID
}

// ProtocolProfileID returns the typed Gemini GenerateContent profile used by Vertex.
// ProtocolProfileID 返回 Vertex 使用的类型化 Gemini GenerateContent Profile。
func (d *VertexDriver) ProtocolProfileID() string {
	return aistudio.ProfileID
}

// Execute projects one VCP request to the exact Vertex project, location, model, and action path.
// Execute 将一条 VCP 请求投影到精确的 Vertex Project、Location、Model 与 Action 路径。
func (d *VertexDriver) Execute(ctx context.Context, execution provider.ExecutionRequest) (provider.ExecutionResult, error) {
	if d == nil || d.client == nil || d.decoder == nil {
		return provider.ExecutionResult{}, ErrInvalidVertexDriver
	}
	if execution.Binding.Target.ProviderDefinitionID != d.definitionID {
		return provider.ExecutionResult{}, fmt.Errorf("%w: target definition does not belong to this Vertex driver", provider.ErrExecutionBinding)
	}
	if _, errValidate := execution.ValidateForProfile(aistudio.ProfileID, providerconfig.AuthMethodServiceAccount); errValidate != nil {
		return provider.ExecutionResult{}, errValidate
	}
	projectID, location, errScope := vertexExecutionScope(execution)
	if errScope != nil {
		return provider.ExecutionResult{}, errScope
	}
	modelName, errModel := aiStudioModelName(execution.Binding.Target.UpstreamModelID)
	if errModel != nil {
		return provider.ExecutionResult{}, errModel
	}
	if isVertexImageGenerationModel(modelName) {
		return provider.ExecutionResult{}, fmt.Errorf("%w: image-generation model %q requires the future VCP resource-output profile", ErrInvalidVertexDriver, modelName)
	}
	projected, errProject := aistudio.ProjectRequest(execution.Request, execution.Binding.Target, d.capabilities, execution.LineageID, execution.Now)
	if errProject != nil {
		return provider.ExecutionResult{}, errProject
	}
	encodedRequest, errMarshal := json.Marshal(projected.Upstream)
	if errMarshal != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: encode Vertex request: %v", ErrInvalidVertexDriver, errMarshal)
	}
	action := "generateContent"
	if execution.Request.Stream {
		action = "streamGenerateContent"
	}
	path := vertexEndpointPath(projectID, location, modelName, action, execution.Request.Stream)
	outbound := transport.Request{
		Binding: execution.Binding, Method: http.MethodPost, Path: path, Body: encodedRequest,
		Headers:        []transport.Header{{Name: "Content-Type", Value: "application/json"}},
		Authentication: transport.Authentication{Mode: transport.AuthenticationBearer},
		Stream:         execution.Request.Stream, IdempotencyKey: execution.Request.IdempotencyKey,
	}
	if execution.Request.Stream {
		return d.decoder.executeStream(ctx, outbound, projected, execution.Now)
	}
	return d.decoder.executeResponse(ctx, outbound, projected, execution.Now)
}

// CountTokens executes Vertex countTokens against the same immutable project and service-account scope.
// CountTokens 对同一不可变 Project 与服务账号作用域执行 Vertex countTokens。
func (d *VertexDriver) CountTokens(ctx context.Context, execution provider.ExecutionRequest) (aistudio.CountTokensResult, error) {
	if d == nil || d.client == nil {
		return aistudio.CountTokensResult{}, ErrInvalidVertexDriver
	}
	if execution.Binding.Target.ProviderDefinitionID != d.definitionID {
		return aistudio.CountTokensResult{}, fmt.Errorf("%w: target definition does not belong to this Vertex driver", provider.ErrExecutionBinding)
	}
	if _, errValidate := execution.ValidateForProfile(aistudio.ProfileID, providerconfig.AuthMethodServiceAccount); errValidate != nil {
		return aistudio.CountTokensResult{}, errValidate
	}
	projectID, location, errScope := vertexExecutionScope(execution)
	if errScope != nil {
		return aistudio.CountTokensResult{}, errScope
	}
	modelName, errModel := aiStudioModelName(execution.Binding.Target.UpstreamModelID)
	if errModel != nil {
		return aistudio.CountTokensResult{}, errModel
	}
	if isVertexImageGenerationModel(modelName) {
		return aistudio.CountTokensResult{}, fmt.Errorf("%w: image-generation models do not support this countTokens profile", ErrInvalidVertexDriver)
	}
	projected, _, errProject := aistudio.ProjectCountTokensRequest(execution.Request, execution.Binding.Target, d.capabilities, execution.LineageID, execution.Now)
	if errProject != nil {
		return aistudio.CountTokensResult{}, errProject
	}
	// Vertex accepts the GenerateContent body directly, unlike AI Studio's generateContentRequest wrapper.
	// Vertex 直接接受 GenerateContent Body，不使用 AI Studio 的 generateContentRequest 包装。
	encodedRequest, errMarshal := json.Marshal(projected.Upstream)
	if errMarshal != nil {
		return aistudio.CountTokensResult{}, fmt.Errorf("%w: encode Vertex countTokens request: %v", ErrInvalidVertexDriver, errMarshal)
	}
	outbound := transport.Request{
		Binding: execution.Binding, Method: http.MethodPost,
		Path: vertexEndpointPath(projectID, location, modelName, "countTokens", false), Body: encodedRequest,
		Headers:        []transport.Header{{Name: "Content-Type", Value: "application/json"}},
		Authentication: transport.Authentication{Mode: transport.AuthenticationBearer},
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
		return aistudio.CountTokensResult{}, fmt.Errorf("%w: bound Vertex countTokens response: %v", aistudio.ErrInvalidUpstreamResponse, errBound)
	}
	var upstream aistudio.CountTokensResponse
	decoder := json.NewDecoder(boundedBody)
	if errDecode := decoder.Decode(&upstream); errDecode != nil {
		return aistudio.CountTokensResult{}, fmt.Errorf("%w: decode Vertex countTokens response: %v", aistudio.ErrInvalidUpstreamResponse, errDecode)
	}
	if errTrailing := rejectTrailingJSON(decoder); errTrailing != nil {
		return aistudio.CountTokensResult{}, errTrailing
	}
	if upstream.TotalTokens == nil {
		return aistudio.CountTokensResult{}, fmt.Errorf("%w: countTokens response omits totalTokens", aistudio.ErrInvalidUpstreamResponse)
	}
	usage := vcp.UsageObservation{
		InputTokens: upstream.TotalTokens, CacheReadTokens: upstream.CachedContentTokenCount, TotalTokens: upstream.TotalTokens,
		Source: "provider_reported", Aggregation: "snapshot", Phase: "preflight", AccountingBasis: "google_vertex_count_tokens", Final: true,
	}
	report := aistudio.CountTokensReport(projected.Report, usage, upstream)
	return aistudio.CountTokensResult{TotalTokens: upstream.TotalTokens, Usage: usage, Report: report, Projected: projected}, nil
}

// vertexExecutionScope derives and validates the sole project and location owned by one resolved credential endpoint pair.
// vertexExecutionScope 派生并校验一个已解析凭据与端点对拥有的唯一 Project 与 Location。
func vertexExecutionScope(execution provider.ExecutionRequest) (string, string, error) {
	location, errLocation := normalizeVertexLocation(execution.Binding.Endpoint.Region)
	if errLocation != nil || location != execution.Binding.Endpoint.Region {
		return "", "", fmt.Errorf("%w: endpoint region is not one normalized Vertex location", provider.ErrExecutionBinding)
	}
	if execution.Binding.Endpoint.BaseURL != VertexBaseURL(location) {
		return "", "", fmt.Errorf("%w: endpoint origin does not match its Vertex location", provider.ErrExecutionBinding)
	}
	if len(execution.Binding.Credential.ScopeRefs) != 1 || execution.Binding.Credential.ScopeRefs[0].Kind != "project" {
		return "", "", fmt.Errorf("%w: Vertex credential must own exactly one project scope", provider.ErrExecutionBinding)
	}
	projectID := strings.TrimSpace(execution.Binding.Credential.ScopeRefs[0].ID)
	if errProject := validateVertexIdentifier("project_id", projectID); errProject != nil {
		return "", "", fmt.Errorf("%w: %v", provider.ErrExecutionBinding, errProject)
	}
	return projectID, location, nil
}

// vertexEndpointPath builds CLIProxyAPI's exact v1 project, location, publisher, model, and action path.
// vertexEndpointPath 构建 CLIProxyAPI 精确的 v1 Project、Location、Publisher、Model 与 Action 路径。
func vertexEndpointPath(projectID string, location string, modelName string, action string, stream bool) string {
	path := "/" + vertexAPIVersion + "/projects/" + url.PathEscape(projectID) + "/locations/" + url.PathEscape(location) + "/publishers/google/models/" + url.PathEscape(modelName) + ":" + action
	if stream {
		path += "?alt=sse"
	}
	return path
}

// isVertexImageGenerationModel identifies CLIProxyAPI model IDs whose media output cannot yet become a Router-owned resource.
// isVertexImageGenerationModel 标识媒体输出尚无法成为 Router 所有资源的 CLIProxyAPI 模型 ID。
func isVertexImageGenerationModel(modelName string) bool {
	normalized := strings.ToLower(strings.TrimSpace(modelName))
	return strings.Contains(normalized, "imagen") || strings.Contains(normalized, "-image")
}
