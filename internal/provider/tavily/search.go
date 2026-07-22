// Package tavily implements the exact Tavily Search API boundary.
// Package tavily 实现精确的 Tavily Search API 边界。
package tavily

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

var (
	// ErrInvalidDriver reports an incomplete Tavily action driver.
	// ErrInvalidDriver 表示不完整的 Tavily 动作 Driver。
	ErrInvalidDriver = errors.New("invalid Tavily driver")
	// ErrUnsupportedInput reports a policy outside the documented Tavily offering.
	// ErrUnsupportedInput 表示策略超出已记录的 Tavily Offering。
	ErrUnsupportedInput = errors.New("unsupported Tavily input")
	// ErrInvalidResponse reports a malformed Tavily response.
	// ErrInvalidResponse 表示格式错误的 Tavily 响应。
	ErrInvalidResponse = errors.New("invalid Tavily response")
)

const (
	// ActionBindingID identifies the direct Tavily search action.
	// ActionBindingID 标识直接 Tavily 搜索动作。
	ActionBindingID = "action_tavily_search_web"
	// ProtocolProfileID identifies the Tavily Search API contract.
	// ProtocolProfileID 标识 Tavily Search API 合同。
	ProtocolProfileID = "tavily.search.v1"
	// searchEndpointPath is the documented Tavily Search resource path.
	// searchEndpointPath 是文档记录的 Tavily Search 资源路径。
	searchEndpointPath = "/search"
)

// SearchDriver executes one synchronous direct-search request.
// SearchDriver 执行一个同步直接搜索请求。
type SearchDriver struct {
	// definitionID is the sole owning provider definition.
	// definitionID 是唯一拥有的供应商 Definition。
	definitionID string
	// client owns target-bound authenticated transport.
	// client 负责 Target 绑定且经过认证的传输。
	client *transport.Client
}

// NewSearchDriver creates one Tavily direct-search driver.
// NewSearchDriver 创建一个 Tavily 直接搜索 Driver。
func NewSearchDriver(definitionID string, client *transport.Client) (*SearchDriver, error) {
	if strings.TrimSpace(definitionID) == "" || client == nil {
		return nil, ErrInvalidDriver
	}
	return &SearchDriver{definitionID: definitionID, client: client}, nil
}

// ProviderDefinitionID returns the sole definition owned by this driver.
// ProviderDefinitionID 返回此 Driver 唯一拥有的 Definition。
func (d *SearchDriver) ProviderDefinitionID() string { return d.definitionID }

// ActionBindingID returns the sole action owned by this driver.
// ActionBindingID 返回此 Driver 唯一拥有的动作。
func (d *SearchDriver) ActionBindingID() string { return ActionBindingID }

// tavilySearchRequest is the closed request subset exposed by the system offering.
// tavilySearchRequest 是系统 Offering 暴露的封闭请求子集。
type tavilySearchRequest struct {
	// Query is the exact caller query.
	// Query 是调用方精确查询。
	Query string `json:"query"`
	// SearchDepth fixes predictable basic search behavior and cost.
	// SearchDepth 固定可预测的 basic 搜索行为与成本。
	SearchDepth string `json:"search_depth"`
	// MaxResults is the caller limit when present.
	// MaxResults 是存在时的调用方结果上限。
	MaxResults *int `json:"max_results,omitempty"`
	// IncludeDomains contains exact allowlisted domains.
	// IncludeDomains 包含精确允许域名。
	IncludeDomains []string `json:"include_domains,omitempty"`
	// ExcludeDomains contains exact blocked domains.
	// ExcludeDomains 包含精确阻止域名。
	ExcludeDomains []string `json:"exclude_domains,omitempty"`
	// IncludeAnswer remains false because this offering exposes structured results only.
	// IncludeAnswer 保持 false，因为此 Offering 仅暴露结构化结果。
	IncludeAnswer bool `json:"include_answer"`
	// IncludeRawContent prevents implicit full-page fetching.
	// IncludeRawContent 阻止隐式抓取完整网页。
	IncludeRawContent bool `json:"include_raw_content"`
	// IncludeUsage requests provider credit accounting.
	// IncludeUsage 请求供应商 Credit 计量。
	IncludeUsage bool `json:"include_usage"`
}

// tavilySearchResponse is the exact documented response subset consumed by the Router.
// tavilySearchResponse 是 Router 消费的精确文档响应子集。
type tavilySearchResponse struct {
	// Query is the actual executed query.
	// Query 是实际执行的查询。
	Query string `json:"query"`
	// Results preserves provider order.
	// Results 保留供应商顺序。
	Results []tavilySearchResult `json:"results"`
	// RequestID is the provider support identifier.
	// RequestID 是供应商支持标识。
	RequestID string `json:"request_id"`
	// Usage contains provider credit consumption.
	// Usage 包含供应商 Credit 消耗。
	Usage tavilyUsage `json:"usage"`
}

// tavilySearchResult contains one Tavily structured result.
// tavilySearchResult 包含一个 Tavily 结构化结果。
type tavilySearchResult struct {
	// Title is the provider-returned title.
	// Title 是供应商返回标题。
	Title string `json:"title"`
	// URL is the provider-returned URL.
	// URL 是供应商返回 URL。
	URL string `json:"url"`
	// Content is the provider-returned search snippet.
	// Content 是供应商返回搜索摘要。
	Content string `json:"content"`
	// Score is the raw provider relevance score.
	// Score 是原始供应商相关性分数。
	Score float64 `json:"score"`
}

// tavilyUsage contains provider-reported credit units.
// tavilyUsage 包含供应商报告的 Credit 单位。
type tavilyUsage struct {
	// Credits is the exact consumed credit count.
	// Credits 是精确消耗的 Credit 数量。
	Credits float64 `json:"credits"`
}

// Execute validates the immutable service target and maps real provider results without fetching URLs.
// Execute 校验不可变服务 Target，并在不抓取 URL 的情况下映射真实供应商结果。
func (d *SearchDriver) Execute(ctx context.Context, execution provider.ExecutionRequest) (provider.ExecutionResult, error) {
	if d == nil || d.client == nil {
		return provider.ExecutionResult{}, ErrInvalidDriver
	}
	action, errAction := execution.ValidateForAction(ActionBindingID, providerconfig.AuthMethodAPIKey)
	if errAction != nil {
		return provider.ExecutionResult{}, errAction
	}
	if action.Operation != vcp.OperationSearchWeb || execution.Execution.Stream {
		return provider.ExecutionResult{}, fmt.Errorf("%w: Tavily search is synchronous only", ErrUnsupportedInput)
	}
	request, errProject := projectSearchRequest(*execution.Execution.Payload.SearchWeb)
	if errProject != nil {
		return provider.ExecutionResult{}, errProject
	}
	encoded, errMarshal := json.Marshal(request)
	if errMarshal != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: encode request: %v", ErrInvalidDriver, errMarshal)
	}
	upstream, errRequest := d.client.Do(ctx, transport.Request{Binding: execution.Binding, Method: http.MethodPost, Path: searchEndpointPath, Body: encoded, Headers: []transport.Header{{Name: "Content-Type", Value: "application/json"}}, Authentication: transport.Authentication{Mode: transport.AuthenticationBearer}, IdempotencyKey: execution.Execution.IdempotencyKey})
	if errRequest != nil {
		return provider.ExecutionResult{}, errRequest
	}
	defer func() { _ = transport.DrainAndClose(upstream) }()
	reader, errBound := transport.NewBoundedResponseReader(upstream.Body, transport.MaximumNonStreamingResponseBytes)
	if errBound != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: bound response: %v", ErrInvalidResponse, errBound)
	}
	var response tavilySearchResponse
	decoder := json.NewDecoder(reader)
	if errDecode := decoder.Decode(&response); errDecode != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: decode response: %v", ErrInvalidResponse, errDecode)
	}
	if errTrailing := rejectTrailingJSON(decoder); errTrailing != nil {
		return provider.ExecutionResult{}, errTrailing
	}
	return mapSearchResponse(response)
}

// projectSearchRequest maps only semantically exact Tavily policies.
// projectSearchRequest 仅映射语义精确的 Tavily 策略。
func projectSearchRequest(operation vcp.WebSearchOperation) (tavilySearchRequest, error) {
	if operation.OutputMode != vcp.WebSearchOutputResults || operation.SafeSearch != "" || operation.Locale != (vcp.SearchLocale{}) || operation.Location != (vcp.SearchLocation{}) || operation.Time.PublishedAfter != nil || operation.Time.PublishedBefore != nil {
		return tavilySearchRequest{}, fmt.Errorf("%w: offering supports results, domain filters, and max_results only", ErrUnsupportedInput)
	}
	if operation.MaxResults != nil && *operation.MaxResults > 20 {
		return tavilySearchRequest{}, fmt.Errorf("%w: max_results exceeds 20", ErrUnsupportedInput)
	}
	return tavilySearchRequest{Query: operation.Query, SearchDepth: "basic", MaxResults: operation.MaxResults, IncludeDomains: append([]string(nil), operation.Domains.Allow...), ExcludeDomains: append([]string(nil), operation.Domains.Block...), IncludeAnswer: false, IncludeRawContent: false, IncludeUsage: true}, nil
}

// mapSearchResponse preserves order, URLs, snippets, scores, and provider credit usage.
// mapSearchResponse 保留顺序、URL、摘要、分数和供应商 Credit 用量。
func mapSearchResponse(response tavilySearchResponse) (provider.ExecutionResult, error) {
	if strings.TrimSpace(response.Query) == "" {
		return provider.ExecutionResult{}, fmt.Errorf("%w: response query is required", ErrInvalidResponse)
	}
	results := make([]vcp.WebSearchResult, len(response.Results))
	for index, item := range response.Results {
		parsed, errParse := url.Parse(item.URL)
		if errParse != nil || parsed.Scheme != "https" || parsed.Hostname() == "" {
			return provider.ExecutionResult{}, fmt.Errorf("%w: result %d has invalid HTTPS URL", ErrInvalidResponse, index)
		}
		score := item.Score
		results[index] = vcp.WebSearchResult{ID: fmt.Sprintf("result_%d", index+1), Rank: index + 1, Title: item.Title, URL: item.URL, SourceDomain: strings.ToLower(parsed.Hostname()), Snippet: item.Content, ProviderScore: &score}
	}
	credits := response.Usage.Credits
	search := &vcp.WebSearchResponse{Query: response.Query, Evidence: vcp.SearchExecutionEvidence{Status: vcp.SearchExecutionConfirmed, Kinds: []vcp.SearchEvidenceKind{vcp.SearchEvidenceStructuredResult}}, Results: results, Usage: &vcp.UsageObservation{ServiceUnits: &credits, ServiceUnit: "credits", Source: "provider_reported", Aggregation: "snapshot", Phase: "terminal", AccountingBasis: "tavily_api_credits", Final: true}}
	return provider.ExecutionResult{UpstreamResponseID: response.RequestID, Search: search}, nil
}

// rejectTrailingJSON rejects a second JSON document after the response object.
// rejectTrailingJSON 拒绝响应对象后的第二个 JSON 文档。
func rejectTrailingJSON(decoder *json.Decoder) error {
	var trailing json.RawMessage
	if errDecode := decoder.Decode(&trailing); errDecode == io.EOF {
		return nil
	} else if errDecode != nil {
		return fmt.Errorf("%w: decode trailing response: %v", ErrInvalidResponse, errDecode)
	}
	return fmt.Errorf("%w: trailing JSON document", ErrInvalidResponse)
}
