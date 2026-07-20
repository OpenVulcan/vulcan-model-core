package anthropic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

var (
	// ErrInvalidSearchDriver reports an incomplete Anthropic search driver.
	// ErrInvalidSearchDriver 表示不完整的 Anthropic 搜索 Driver。
	ErrInvalidSearchDriver = errors.New("invalid Anthropic grounded search driver")
	// ErrUnsupportedSearchInput reports a policy outside the pinned Anthropic tool contract.
	// ErrUnsupportedSearchInput 表示超出固定 Anthropic 工具合同的策略。
	ErrUnsupportedSearchInput = errors.New("unsupported Anthropic grounded search input")
	// ErrInvalidSearchResponse reports malformed Anthropic search evidence.
	// ErrInvalidSearchResponse 表示格式错误的 Anthropic 搜索证据。
	ErrInvalidSearchResponse = errors.New("invalid Anthropic grounded search response")
	// ErrSearchNotObserved reports a verified request without a server search call.
	// ErrSearchNotObserved 表示要求验证但没有服务器搜索调用。
	ErrSearchNotObserved = errors.New("search_not_observed")
)

const (
	// SearchActionBindingID identifies the Anthropic native web-search action.
	// SearchActionBindingID 标识 Anthropic 原生网页搜索动作。
	SearchActionBindingID = "action_anthropic_search_web"
	// SearchProtocolProfileID identifies the pinned basic web-search tool.
	// SearchProtocolProfileID 标识固定的基础网页搜索工具。
	SearchProtocolProfileID = "anthropic.messages.web_search.2025_03_05"
	// SearchPromptTemplateID identifies the fixed search instruction.
	// SearchPromptTemplateID 标识固定搜索指令。
	SearchPromptTemplateID = "anthropic.web_search.answer_with_citations"
	// SearchPromptTemplateRevision freezes prompt behavior.
	// SearchPromptTemplateRevision 冻结提示行为。
	SearchPromptTemplateRevision uint64 = 1
	// SearchBackingModelID is the fixed supported Claude model.
	// SearchBackingModelID 是固定支持的 Claude 模型。
	SearchBackingModelID = "claude-sonnet-4-6"
	// SearchBackingModelOfferingID is its deterministic offering identifier.
	// SearchBackingModelOfferingID 是其确定性 Offering 标识。
	SearchBackingModelOfferingID = "offer_claude_sonnet_4_6_anthropic_messages"
	// anthropicSearchPrompt is the immutable provider-facing instruction.
	// anthropicSearchPrompt 是不可变供应商搜索指令。
	anthropicSearchPrompt = "Search the web for the user's query. Answer only from observed web sources and preserve citations."
)

// GroundedSearchDriver executes one fixed Claude model with native web search.
// GroundedSearchDriver 使用原生网页搜索执行固定 Claude 模型。
type GroundedSearchDriver struct {
	// definitionID is the sole owning definition.
	// definitionID 是唯一拥有 Definition。
	definitionID string
	// client owns target-bound transport.
	// client 拥有 Target 绑定传输。
	client *transport.Client
}

// NewGroundedSearchDriver creates an Anthropic API search driver.
// NewGroundedSearchDriver 创建 Anthropic API 搜索 Driver。
func NewGroundedSearchDriver(definitionID string, client *transport.Client) (*GroundedSearchDriver, error) {
	if strings.TrimSpace(definitionID) == "" || client == nil {
		return nil, ErrInvalidSearchDriver
	}
	return &GroundedSearchDriver{definitionID: definitionID, client: client}, nil
}

// ProviderDefinitionID returns the sole owning definition.
// ProviderDefinitionID 返回唯一拥有 Definition。
func (d *GroundedSearchDriver) ProviderDefinitionID() string { return d.definitionID }

// ActionBindingID returns the sole owned action.
// ActionBindingID 返回唯一拥有动作。
func (d *GroundedSearchDriver) ActionBindingID() string { return SearchActionBindingID }

// anthropicSearchRequest is the closed Messages request for unified search.
// anthropicSearchRequest 是统一搜索使用的封闭 Messages 请求。
type anthropicSearchRequest struct {
	// Model is the fixed backing model.
	// Model 是固定后端模型。
	Model string `json:"model"`
	// MaxTokens is a fixed bounded answer ceiling.
	// MaxTokens 是固定受限答案上限。
	MaxTokens int `json:"max_tokens"`
	// System is the immutable search instruction.
	// System 是不可变搜索指令。
	System string `json:"system"`
	// Messages contains the exact caller query.
	// Messages 包含调用方精确查询。
	Messages []anthropicSearchMessage `json:"messages"`
	// Tools contains only the pinned server search tool.
	// Tools 仅包含固定服务器搜索工具。
	Tools []anthropicSearchTool `json:"tools"`
}

// anthropicSearchMessage is one user message.
// anthropicSearchMessage 是一条用户消息。
type anthropicSearchMessage struct {
	// Role is fixed to user.
	// Role 固定为 user。
	Role string `json:"role"`
	// Content is the exact query.
	// Content 是精确查询。
	Content string `json:"content"`
}

// anthropicSearchTool contains documented basic web-search controls.
// anthropicSearchTool 包含文档记录的基础网页搜索控制。
type anthropicSearchTool struct {
	// Type pins the dated basic tool version.
	// Type 固定带日期的基础工具版本。
	Type string `json:"type"`
	// Name is fixed to web_search.
	// Name 固定为 web_search。
	Name string `json:"name"`
	// MaxUses bounds provider search calls.
	// MaxUses 限制供应商搜索调用次数。
	MaxUses int `json:"max_uses"`
	// AllowedDomains contains exact allow filters.
	// AllowedDomains 包含精确允许过滤器。
	AllowedDomains []string `json:"allowed_domains,omitempty"`
	// BlockedDomains contains exact block filters.
	// BlockedDomains 包含精确阻止过滤器。
	BlockedDomains []string `json:"blocked_domains,omitempty"`
	// UserLocation contains optional approximate location.
	// UserLocation 包含可选大致位置。
	UserLocation *anthropicSearchLocation `json:"user_location,omitempty"`
}

// anthropicSearchLocation is the documented approximate location.
// anthropicSearchLocation 是文档记录的大致位置。
type anthropicSearchLocation struct {
	// Type is fixed to approximate.
	// Type 固定为 approximate。
	Type string `json:"type"`
	// City is the caller-authorized city.
	// City 是调用方授权城市。
	City string `json:"city,omitempty"`
	// Region is the caller-authorized region.
	// Region 是调用方授权区域。
	Region string `json:"region,omitempty"`
	// Country is the caller-authorized country.
	// Country 是调用方授权国家。
	Country string `json:"country,omitempty"`
	// Timezone is the caller-authorized timezone.
	// Timezone 是调用方授权时区。
	Timezone string `json:"timezone,omitempty"`
}

// anthropicSearchResponse contains typed server tool and answer blocks.
// anthropicSearchResponse 包含类型化服务器工具与答案块。
type anthropicSearchResponse struct {
	// ID is the provider message identifier.
	// ID 是供应商消息标识。
	ID string `json:"id"`
	// Content contains all server and text blocks.
	// Content 包含所有服务器与文本块。
	Content []anthropicSearchBlock `json:"content"`
	// Usage contains token and search request accounting.
	// Usage 包含 Token 与搜索请求计量。
	Usage anthropicSearchUsage `json:"usage"`
}

// anthropicSearchBlock is one closed response content block.
// anthropicSearchBlock 是一个封闭响应内容块。
type anthropicSearchBlock struct {
	// Type identifies server_tool_use, web_search_tool_result, or text.
	// Type 标识 server_tool_use、web_search_tool_result 或 text。
	Type string `json:"type"`
	// ID is the server tool call identifier.
	// ID 是服务器工具调用标识。
	ID string `json:"id"`
	// Name is the server tool name.
	// Name 是服务器工具名称。
	Name string `json:"name"`
	// Input contains the actual provider query.
	// Input 包含真实供应商查询。
	Input anthropicSearchInput `json:"input"`
	// Content contains raw search results because an error uses a different documented shape.
	// Content 包含原始搜索结果，因为错误使用不同文档形态。
	Content json.RawMessage `json:"content"`
	// Text is the grounded answer.
	// Text 是联网答案。
	Text string `json:"text"`
	// Citations contains answer citations.
	// Citations 包含答案引用。
	Citations []anthropicSearchCitation `json:"citations"`
}

// anthropicSearchInput contains one actual server query.
// anthropicSearchInput 包含一个真实服务器查询。
type anthropicSearchInput struct {
	// Query is generated by Claude.
	// Query 由 Claude 生成。
	Query string `json:"query"`
}

// anthropicSearchResult contains one provider-returned result.
// anthropicSearchResult 包含一个供应商返回结果。
type anthropicSearchResult struct {
	// Type must be web_search_result.
	// Type 必须为 web_search_result。
	Type string `json:"type"`
	// URL is the result URL.
	// URL 是结果 URL。
	URL string `json:"url"`
	// Title is the result title.
	// Title 是结果标题。
	Title string `json:"title"`
	// PageAge is provider-returned update text.
	// PageAge 是供应商返回的更新时间文本。
	PageAge string `json:"page_age"`
}

// anthropicSearchCitation contains one web result relation.
// anthropicSearchCitation 包含一个网页结果关系。
type anthropicSearchCitation struct {
	// Type must be web_search_result_location.
	// Type 必须为 web_search_result_location。
	Type string `json:"type"`
	// URL is the cited source.
	// URL 是引用来源。
	URL string `json:"url"`
	// Title is the cited title.
	// Title 是引用标题。
	Title string `json:"title"`
	// CitedText is the provider-returned excerpt.
	// CitedText 是供应商返回摘录。
	CitedText string `json:"cited_text"`
}

// anthropicSearchUsage contains exact provider accounting.
// anthropicSearchUsage 包含精确供应商计量。
type anthropicSearchUsage struct {
	// InputTokens is the provider input count.
	// InputTokens 是供应商输入计数。
	InputTokens int64 `json:"input_tokens"`
	// OutputTokens is the provider output count.
	// OutputTokens 是供应商输出计数。
	OutputTokens int64 `json:"output_tokens"`
	// ServerToolUse contains search request accounting.
	// ServerToolUse 包含搜索请求计量。
	ServerToolUse anthropicServerToolUsage `json:"server_tool_use"`
}

// anthropicServerToolUsage contains billable web-search calls.
// anthropicServerToolUsage 包含可计费网页搜索调用。
type anthropicServerToolUsage struct {
	// WebSearchRequests is the exact search count.
	// WebSearchRequests 是精确搜索次数。
	WebSearchRequests int64 `json:"web_search_requests"`
}

// Execute invokes Anthropic Messages and preserves queries, results, citations, and usage.
// Execute 调用 Anthropic Messages 并保留查询、结果、引用与用量。
func (d *GroundedSearchDriver) Execute(ctx context.Context, execution provider.ExecutionRequest) (provider.ExecutionResult, error) {
	if d == nil || d.client == nil {
		return provider.ExecutionResult{}, ErrInvalidSearchDriver
	}
	action, errAction := execution.ValidateForAction(SearchActionBindingID, providerconfig.AuthMethodAPIKey)
	if errAction != nil {
		return provider.ExecutionResult{}, errAction
	}
	if action.Operation != vcp.OperationSearchWeb || execution.Execution.Stream {
		return provider.ExecutionResult{}, fmt.Errorf("%w: Anthropic grounded search is synchronous only", ErrUnsupportedSearchInput)
	}
	operation := *execution.Execution.Payload.SearchWeb
	tool, errPolicy := projectAnthropicSearchTool(operation)
	if errPolicy != nil {
		return provider.ExecutionResult{}, errPolicy
	}
	payload := anthropicSearchRequest{Model: SearchBackingModelID, MaxTokens: 4096, System: anthropicSearchPrompt, Messages: []anthropicSearchMessage{{Role: "user", Content: operation.Query}}, Tools: []anthropicSearchTool{tool}}
	encoded, errMarshal := json.Marshal(payload)
	if errMarshal != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: encode request: %v", ErrInvalidSearchDriver, errMarshal)
	}
	upstream, errRequest := d.client.Do(ctx, transport.Request{Binding: execution.Binding, Method: http.MethodPost, Path: "/v1/messages", Body: encoded, Headers: []transport.Header{{Name: "Content-Type", Value: "application/json"}, {Name: "Anthropic-Version", Value: "2023-06-01"}}, Authentication: transport.Authentication{Mode: transport.AuthenticationHeader, HeaderName: "x-api-key"}, IdempotencyKey: execution.Execution.IdempotencyKey})
	if errRequest != nil {
		return provider.ExecutionResult{}, errRequest
	}
	defer func() { _ = transport.DrainAndClose(upstream) }()
	reader, errBound := transport.NewBoundedResponseReader(upstream.Body, transport.MaximumNonStreamingResponseBytes)
	if errBound != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: bound response: %v", ErrInvalidSearchResponse, errBound)
	}
	var response anthropicSearchResponse
	if errDecode := json.NewDecoder(reader).Decode(&response); errDecode != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: decode response: %v", ErrInvalidSearchResponse, errDecode)
	}
	return mapAnthropicSearchResponse(operation, response)
}

// projectAnthropicSearchTool maps the exact documented basic-tool controls.
// projectAnthropicSearchTool 映射精确记录的基础工具控制。
func projectAnthropicSearchTool(operation vcp.WebSearchOperation) (anthropicSearchTool, error) {
	if operation.OutputMode != vcp.WebSearchOutputAnswerWithCitations && operation.OutputMode != vcp.WebSearchOutputResultsAndAnswer || operation.Time.PublishedAfter != nil || operation.Time.PublishedBefore != nil || operation.Locale.Language != "" || operation.Locale.Region != "" || operation.SafeSearch != "" || operation.MaxResults != nil || len(operation.Domains.Allow) > 0 && len(operation.Domains.Block) > 0 {
		return anthropicSearchTool{}, ErrUnsupportedSearchInput
	}
	tool := anthropicSearchTool{Type: "web_search_20250305", Name: "web_search", MaxUses: 5, AllowedDomains: append([]string(nil), operation.Domains.Allow...), BlockedDomains: append([]string(nil), operation.Domains.Block...)}
	if operation.Location.Country != "" || operation.Location.Region != "" || operation.Location.City != "" || operation.Location.Timezone != "" {
		tool.UserLocation = &anthropicSearchLocation{Type: "approximate", Country: operation.Location.Country, Region: operation.Location.Region, City: operation.Location.City, Timezone: operation.Location.Timezone}
	}
	return tool, nil
}

// mapAnthropicSearchResponse maps only actual server-tool observations.
// mapAnthropicSearchResponse 仅映射真实服务器工具观测。
func mapAnthropicSearchResponse(operation vcp.WebSearchOperation, response anthropicSearchResponse) (provider.ExecutionResult, error) {
	search := &vcp.WebSearchResponse{Query: operation.Query, Evidence: vcp.SearchExecutionEvidence{Status: vcp.SearchExecutionRequestedUnverified}}
	for _, block := range response.Content {
		switch block.Type {
		case "server_tool_use":
			if block.Name == "web_search" && strings.TrimSpace(block.Input.Query) != "" {
				search.Queries = append(search.Queries, block.Input.Query)
			}
		case "web_search_tool_result":
			var results []anthropicSearchResult
			if len(block.Content) != 0 && string(block.Content) != "null" {
				if errDecode := json.Unmarshal(block.Content, &results); errDecode != nil {
					return provider.ExecutionResult{}, fmt.Errorf("%w: search tool returned an error shape", ErrInvalidSearchResponse)
				}
			}
			for _, item := range results {
				if item.Type != "web_search_result" || validateAnthropicSearchURL(item.URL) != nil {
					return provider.ExecutionResult{}, ErrInvalidSearchResponse
				}
				parsed, _ := url.Parse(item.URL)
				search.Results = append(search.Results, vcp.WebSearchResult{ID: fmt.Sprintf("result_%d", len(search.Results)+1), Rank: len(search.Results) + 1, Title: item.Title, URL: item.URL, SourceDomain: parsed.Hostname()})
			}
		case "text":
			search.Answer += block.Text
			for _, citation := range block.Citations {
				if citation.Type != "web_search_result_location" || validateAnthropicSearchURL(citation.URL) != nil {
					return provider.ExecutionResult{}, ErrInvalidSearchResponse
				}
				search.Citations = append(search.Citations, vcp.Citation{ID: fmt.Sprintf("citation_%d", len(search.Citations)+1), URL: citation.URL, Title: citation.Title})
			}
		}
	}
	if len(search.Queries) > 0 {
		search.Query = search.Queries[0]
		search.Evidence.Status = vcp.SearchExecutionConfirmed
		search.Evidence.Kinds = []vcp.SearchEvidenceKind{vcp.SearchEvidenceProviderEvent}
		if len(search.Results) > 0 {
			search.Evidence.Kinds = append(search.Evidence.Kinds, vcp.SearchEvidenceStructuredResult)
		}
		if len(search.Citations) > 0 {
			search.Evidence.Kinds = append(search.Evidence.Kinds, vcp.SearchEvidenceCitation)
		}
	}
	if operation.EvidenceRequirement == vcp.SearchEvidenceVerified && search.Evidence.Status != vcp.SearchExecutionConfirmed {
		return provider.ExecutionResult{}, ErrSearchNotObserved
	}
	totalTokens := response.Usage.InputTokens + response.Usage.OutputTokens
	inputTokens := response.Usage.InputTokens
	outputTokens := response.Usage.OutputTokens
	search.Usage = &vcp.UsageObservation{InputTokens: &inputTokens, OutputTokens: &outputTokens, TotalTokens: &totalTokens}
	if response.Usage.ServerToolUse.WebSearchRequests > 0 {
		units := float64(response.Usage.ServerToolUse.WebSearchRequests)
		search.Usage.ServiceUnits = &units
		search.Usage.ServiceUnit = "web_search_requests"
	}
	return provider.ExecutionResult{Search: search, UpstreamResponseID: response.ID}, nil
}

// validateAnthropicSearchURL requires one complete HTTPS result URL.
// validateAnthropicSearchURL 要求一个完整 HTTPS 结果 URL。
func validateAnthropicSearchURL(value string) error {
	parsed, errParse := url.Parse(value)
	if errParse != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return ErrInvalidSearchResponse
	}
	return nil
}
