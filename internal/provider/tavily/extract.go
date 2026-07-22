package tavily

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strings"

	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

const (
	// ExtractActionBindingID identifies the direct Tavily extraction action.
	// ExtractActionBindingID 标识直接 Tavily 内容提取动作。
	ExtractActionBindingID = "action_tavily_web_extract"
	// ExtractProtocolProfileID identifies the Tavily Extract API contract.
	// ExtractProtocolProfileID 标识 Tavily Extract API 合同。
	ExtractProtocolProfileID = "tavily.extract.v1"
	// extractEndpointPath is the documented Tavily Extract resource path.
	// extractEndpointPath 是文档记录的 Tavily Extract 资源路径。
	extractEndpointPath = "/extract"
)

// ExtractDriver executes one synchronous direct web-content extraction request.
// ExtractDriver 执行一个同步直接网页内容提取请求。
type ExtractDriver struct {
	// definitionID is the sole owning provider definition.
	// definitionID 是唯一拥有的供应商 Definition。
	definitionID string
	// client owns target-bound authenticated transport.
	// client 负责 Target 绑定且经过认证的传输。
	client *transport.Client
}

// NewExtractDriver creates one Tavily direct-extraction driver.
// NewExtractDriver 创建一个 Tavily 直接内容提取 Driver。
func NewExtractDriver(definitionID string, client *transport.Client) (*ExtractDriver, error) {
	if strings.TrimSpace(definitionID) == "" || client == nil {
		return nil, ErrInvalidDriver
	}
	return &ExtractDriver{definitionID: definitionID, client: client}, nil
}

// ProviderDefinitionID returns the sole definition owned by this driver.
// ProviderDefinitionID 返回此 Driver 唯一拥有的 Definition。
func (d *ExtractDriver) ProviderDefinitionID() string { return d.definitionID }

// ActionBindingID returns the sole action owned by this driver.
// ActionBindingID 返回此 Driver 唯一拥有的动作。
func (d *ExtractDriver) ActionBindingID() string { return ExtractActionBindingID }

// tavilyExtractRequest is the exact documented request subset exposed by the system offering.
// tavilyExtractRequest 是系统 Offering 暴露的精确文档请求子集。
type tavilyExtractRequest struct {
	// URLs contains one to twenty exact HTTPS resources.
	// URLs 包含一到二十个精确 HTTPS 资源。
	URLs []string `json:"urls"`
	// Query optionally enables relevance-ranked chunks.
	// Query 可选地启用按相关性排序的片段。
	Query string `json:"query,omitempty"`
	// ChunksPerSource limits relevance-ranked chunks when Query is present.
	// ChunksPerSource 在提供 Query 时限制相关性片段数量。
	ChunksPerSource *int `json:"chunks_per_source,omitempty"`
	// ExtractDepth selects basic or advanced extraction.
	// ExtractDepth 选择 basic 或 advanced 提取。
	ExtractDepth vcp.WebExtractDepth `json:"extract_depth"`
	// IncludeImages requests extracted image URLs.
	// IncludeImages 请求提取图片 URL。
	IncludeImages bool `json:"include_images"`
	// IncludeFavicon requests the page favicon URL.
	// IncludeFavicon 请求页面站点图标 URL。
	IncludeFavicon bool `json:"include_favicon"`
	// Format selects Markdown or plain text output.
	// Format 选择 Markdown 或纯文本输出。
	Format vcp.WebExtractFormat `json:"format"`
	// Timeout optionally bounds provider extraction time in seconds.
	// Timeout 可选地限制供应商提取时间（秒）。
	Timeout *float64 `json:"timeout,omitempty"`
	// IncludeUsage requests provider credit accounting.
	// IncludeUsage 请求供应商 Credit 计量。
	IncludeUsage bool `json:"include_usage"`
}

// tavilyExtractResponse is the exact documented response subset consumed by the Router.
// tavilyExtractResponse 是 Router 消费的精确文档响应子集。
type tavilyExtractResponse struct {
	// Results preserves successful provider order.
	// Results 保留成功结果的供应商顺序。
	Results []tavilyExtractResult `json:"results"`
	// FailedResults preserves provider-reported per-URL failures.
	// FailedResults 保留供应商报告的逐 URL 失败。
	FailedResults []tavilyExtractFailure `json:"failed_results"`
	// ResponseTime is the provider-reported execution duration in seconds.
	// ResponseTime 是供应商报告的执行耗时（秒）。
	ResponseTime float64 `json:"response_time"`
	// Usage contains provider credit consumption.
	// Usage 包含供应商 Credit 消耗。
	Usage tavilyUsage `json:"usage"`
	// RequestID is the provider support identifier.
	// RequestID 是供应商支持标识。
	RequestID string `json:"request_id"`
}

// tavilyExtractResult contains one successful Tavily extraction.
// tavilyExtractResult 包含一个成功的 Tavily 提取结果。
type tavilyExtractResult struct {
	// URL is the extracted resource URL.
	// URL 是被提取资源 URL。
	URL string `json:"url"`
	// RawContent is the requested Markdown or text content.
	// RawContent 是请求的 Markdown 或文本内容。
	RawContent string `json:"raw_content"`
	// Images contains extracted image URLs when requested.
	// Images 包含请求图片时提取到的图片 URL。
	Images []string `json:"images"`
	// Favicon contains the favicon URL when requested.
	// Favicon 包含请求站点图标时返回的图标 URL。
	Favicon string `json:"favicon"`
}

// tavilyExtractFailure contains one documented per-URL provider failure.
// tavilyExtractFailure 包含一个文档记录的逐 URL 供应商失败。
type tavilyExtractFailure struct {
	// URL identifies the resource that could not be processed.
	// URL 标识无法处理的资源。
	URL string `json:"url"`
	// Error is the provider-returned failure description.
	// Error 是供应商返回的失败说明。
	Error string `json:"error"`
}

// Execute validates the immutable service target and maps real provider extraction results.
// Execute 校验不可变服务 Target 并映射真实供应商提取结果。
func (d *ExtractDriver) Execute(ctx context.Context, execution provider.ExecutionRequest) (provider.ExecutionResult, error) {
	if d == nil || d.client == nil {
		return provider.ExecutionResult{}, ErrInvalidDriver
	}
	action, errAction := execution.ValidateForAction(ExtractActionBindingID, providerconfig.AuthMethodAPIKey)
	if errAction != nil {
		return provider.ExecutionResult{}, errAction
	}
	if action.Operation != vcp.OperationWebExtract || execution.Execution.Stream {
		return provider.ExecutionResult{}, fmt.Errorf("%w: Tavily extraction is synchronous only", ErrUnsupportedInput)
	}
	request, errProject := projectExtractRequest(*execution.Execution.Payload.WebExtract)
	if errProject != nil {
		return provider.ExecutionResult{}, errProject
	}
	encoded, errMarshal := json.Marshal(request)
	if errMarshal != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: encode request: %v", ErrInvalidDriver, errMarshal)
	}
	upstream, errRequest := d.client.Do(ctx, transport.Request{Binding: execution.Binding, Method: http.MethodPost, Path: extractEndpointPath, Body: encoded, Headers: []transport.Header{{Name: "Content-Type", Value: "application/json"}}, Authentication: transport.Authentication{Mode: transport.AuthenticationBearer}, IdempotencyKey: execution.Execution.IdempotencyKey})
	if errRequest != nil {
		return provider.ExecutionResult{}, errRequest
	}
	defer func() { _ = transport.DrainAndClose(upstream) }()
	maximumBytes := transport.MaximumNonStreamingResponseBytes
	if execution.Execution.Budget.MaxOutputBytes != nil && *execution.Execution.Budget.MaxOutputBytes < maximumBytes {
		maximumBytes = *execution.Execution.Budget.MaxOutputBytes
	}
	reader, errBound := transport.NewBoundedResponseReader(upstream.Body, maximumBytes)
	if errBound != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: bound response: %v", ErrInvalidResponse, errBound)
	}
	var response tavilyExtractResponse
	decoder := json.NewDecoder(reader)
	if errDecode := decoder.Decode(&response); errDecode != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: decode response: %v", ErrInvalidResponse, errDecode)
	}
	if errTrailing := rejectTrailingJSON(decoder); errTrailing != nil {
		return provider.ExecutionResult{}, errTrailing
	}
	return mapExtractResponse(response)
}

// projectExtractRequest applies documented defaults while preserving every explicit caller option.
// projectExtractRequest 应用文档默认值并保留每个明确的调用方选项。
func projectExtractRequest(operation vcp.WebExtractOperation) (tavilyExtractRequest, error) {
	if errValidate := operation.Validate(); errValidate != nil {
		return tavilyExtractRequest{}, fmt.Errorf("%w: %v", ErrUnsupportedInput, errValidate)
	}
	depth := operation.Depth
	if depth == "" {
		depth = vcp.WebExtractDepthBasic
	}
	format := operation.Format
	if format == "" {
		format = vcp.WebExtractFormatMarkdown
	}
	return tavilyExtractRequest{URLs: append([]string(nil), operation.URLs...), Query: operation.Query, ChunksPerSource: operation.ChunksPerSource, ExtractDepth: depth, IncludeImages: operation.IncludeImages, IncludeFavicon: operation.IncludeFavicon, Format: format, Timeout: operation.TimeoutSeconds, IncludeUsage: true}, nil
}

// mapExtractResponse preserves partial success, provider failures, duration, identity, and credit usage.
// mapExtractResponse 保留部分成功、供应商失败、耗时、身份与 Credit 用量。
func mapExtractResponse(response tavilyExtractResponse) (provider.ExecutionResult, error) {
	if strings.TrimSpace(response.RequestID) == "" || math.IsNaN(response.ResponseTime) || math.IsInf(response.ResponseTime, 0) || response.ResponseTime < 0 || math.IsNaN(response.Usage.Credits) || math.IsInf(response.Usage.Credits, 0) || response.Usage.Credits < 0 || len(response.Results)+len(response.FailedResults) == 0 {
		return provider.ExecutionResult{}, fmt.Errorf("%w: extraction response metadata is invalid", ErrInvalidResponse)
	}
	results := make([]vcp.WebExtractResult, len(response.Results))
	seenURLs := make(map[string]struct{}, len(response.Results)+len(response.FailedResults))
	for index, item := range response.Results {
		if !validExtractResponseURL(item.URL) {
			return provider.ExecutionResult{}, fmt.Errorf("%w: extraction result %d is invalid", ErrInvalidResponse, index)
		}
		if _, exists := seenURLs[item.URL]; exists {
			return provider.ExecutionResult{}, fmt.Errorf("%w: duplicate extraction URL", ErrInvalidResponse)
		}
		seenURLs[item.URL] = struct{}{}
		results[index] = vcp.WebExtractResult{URL: item.URL, RawContent: item.RawContent, Images: append([]string(nil), item.Images...), Favicon: item.Favicon}
	}
	failedResults := make([]vcp.WebExtractFailure, len(response.FailedResults))
	for index, item := range response.FailedResults {
		if !validExtractResponseURL(item.URL) || strings.TrimSpace(item.Error) == "" {
			return provider.ExecutionResult{}, fmt.Errorf("%w: extraction failure %d is invalid", ErrInvalidResponse, index)
		}
		if _, exists := seenURLs[item.URL]; exists {
			return provider.ExecutionResult{}, fmt.Errorf("%w: duplicate extraction URL", ErrInvalidResponse)
		}
		seenURLs[item.URL] = struct{}{}
		failedResults[index] = vcp.WebExtractFailure{URL: item.URL, Error: item.Error}
	}
	credits := response.Usage.Credits
	responseTime := response.ResponseTime
	extract := &vcp.WebExtractResponse{Results: results, FailedResults: failedResults, ProviderRequestID: response.RequestID, ResponseTimeSeconds: &responseTime, Usage: &vcp.UsageObservation{ServiceUnits: &credits, ServiceUnit: "credits", Source: "provider_reported", Aggregation: "snapshot", Phase: "terminal", AccountingBasis: "tavily_api_credits", Final: true}}
	return provider.ExecutionResult{UpstreamResponseID: response.RequestID, Extract: extract}, nil
}

// validExtractResponseURL reports whether a provider result preserves an absolute HTTPS resource identity.
// validExtractResponseURL 报告供应商结果是否保留绝对 HTTPS 资源身份。
func validExtractResponseURL(rawURL string) bool {
	parsed, errParse := url.ParseRequestURI(rawURL)
	return errParse == nil && parsed.Scheme == "https" && parsed.Hostname() != "" && parsed.User == nil
}
