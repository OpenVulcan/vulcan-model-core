package openai

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
	// ErrInvalidSearchDriver reports an incomplete OpenAI grounded-search action driver.
	// ErrInvalidSearchDriver 表示不完整的 OpenAI 模型联网搜索动作 Driver。
	ErrInvalidSearchDriver = errors.New("invalid OpenAI grounded search driver")
	// ErrUnsupportedSearchInput reports a VCP policy outside the fixed OpenAI offering.
	// ErrUnsupportedSearchInput 表示 VCP 策略超出固定 OpenAI Offering。
	ErrUnsupportedSearchInput = errors.New("unsupported OpenAI grounded search input")
	// ErrInvalidSearchResponse reports malformed provider search evidence.
	// ErrInvalidSearchResponse 表示格式错误的供应商搜索证据。
	ErrInvalidSearchResponse = errors.New("invalid OpenAI grounded search response")
	// ErrSearchNotObserved reports a verified request without observable provider search execution.
	// ErrSearchNotObserved 表示要求验证但未观察到供应商搜索执行。
	ErrSearchNotObserved = errors.New("search_not_observed")
)

const (
	// SearchActionBindingID identifies the fixed OpenAI grounded-search action.
	// SearchActionBindingID 标识固定的 OpenAI 模型联网搜索动作。
	SearchActionBindingID = "action_openai_search_web"
	// SearchProtocolProfileID identifies the pinned Responses web-search tool contract.
	// SearchProtocolProfileID 标识固定版本的 Responses 网页搜索工具合同。
	SearchProtocolProfileID = "openai.responses.web_search.2025_08_26"
	// SearchPromptTemplateID identifies the code-owned instruction used by this offering.
	// SearchPromptTemplateID 标识此 Offering 使用的代码拥有指令。
	SearchPromptTemplateID = "openai.web_search.answer_with_citations"
	// SearchPromptTemplateRevision freezes the search instruction behavior.
	// SearchPromptTemplateRevision 冻结搜索指令行为。
	SearchPromptTemplateRevision uint64 = 1
	// SearchBackingModelID is the exact official snapshot fixed to the service offering.
	// SearchBackingModelID 是固定到 Service Offering 的精确官方快照。
	SearchBackingModelID = "gpt-5.4-nano-2026-03-17"
	// SearchBackingModelOfferingID is the deterministic catalog offering for the fixed model snapshot.
	// SearchBackingModelOfferingID 是固定模型快照的确定性目录 Offering。
	SearchBackingModelOfferingID = "offer_gpt_5_4_nano_2026_03_17_openai_responses"
	// searchPrompt is the immutable provider-facing search instruction.
	// searchPrompt 是不可变的供应商搜索指令。
	searchPrompt = "Search the web for the user's query. Answer only from observed web sources and cite every factual claim."
)

// GroundedSearchDriver executes one fixed model using the pinned native web-search tool.
// GroundedSearchDriver 使用固定模型和固定版本原生网页搜索工具执行搜索。
type GroundedSearchDriver struct {
	// definitionID is the sole owning provider definition.
	// definitionID 是唯一拥有的供应商 Definition。
	definitionID string
	// client owns target-bound authenticated transport.
	// client 负责 Target 绑定且经过认证的传输。
	client *transport.Client
}

// NewGroundedSearchDriver creates an OpenAI model-grounded search driver.
// NewGroundedSearchDriver 创建 OpenAI 模型联网搜索 Driver。
func NewGroundedSearchDriver(definitionID string, client *transport.Client) (*GroundedSearchDriver, error) {
	if strings.TrimSpace(definitionID) == "" || client == nil {
		return nil, ErrInvalidSearchDriver
	}
	return &GroundedSearchDriver{definitionID: definitionID, client: client}, nil
}

// ProviderDefinitionID returns the sole definition owned by this driver.
// ProviderDefinitionID 返回此 Driver 唯一拥有的 Definition。
func (d *GroundedSearchDriver) ProviderDefinitionID() string { return d.definitionID }

// ActionBindingID returns the sole action owned by this driver.
// ActionBindingID 返回此 Driver 唯一拥有的动作。
func (d *GroundedSearchDriver) ActionBindingID() string { return SearchActionBindingID }

// groundedSearchRequest is the closed Responses request used only by unified search.
// groundedSearchRequest 是仅由统一搜索使用的封闭 Responses 请求。
type groundedSearchRequest struct {
	// Model is the immutable backing model from the service offering.
	// Model 是 Service Offering 中不可变的后端模型。
	Model string `json:"model"`
	// Instructions is the versioned code-owned search instruction.
	// Instructions 是版本化的代码拥有搜索指令。
	Instructions string `json:"instructions"`
	// Input is the exact caller query.
	// Input 是调用方精确查询。
	Input string `json:"input"`
	// Tools contains the sole pinned native web-search tool.
	// Tools 包含唯一固定版本的原生网页搜索工具。
	Tools []groundedSearchTool `json:"tools"`
	// Include requests the complete consulted-source list.
	// Include 请求完整的已咨询来源列表。
	Include []string `json:"include"`
}

// groundedSearchTool is the pinned OpenAI web-search tool configuration.
// groundedSearchTool 是固定版本的 OpenAI 网页搜索工具配置。
type groundedSearchTool struct {
	// Type is the exact dated tool version.
	// Type 是精确的带日期工具版本。
	Type string `json:"type"`
	// Filters contains exact allowed-domain filtering.
	// Filters 包含精确允许域名过滤。
	Filters *groundedSearchFilters `json:"filters,omitempty"`
	// UserLocation contains caller-authorized approximate location.
	// UserLocation 包含调用方授权的大致位置。
	UserLocation *groundedSearchLocation `json:"user_location,omitempty"`
}

// groundedSearchFilters contains supported OpenAI web-search filters.
// groundedSearchFilters 包含支持的 OpenAI 网页搜索过滤器。
type groundedSearchFilters struct {
	// AllowedDomains restricts search to exact domains.
	// AllowedDomains 将搜索限制到精确域名。
	AllowedDomains []string `json:"allowed_domains"`
}

// groundedSearchLocation contains the documented approximate user location.
// groundedSearchLocation 包含文档记录的大致用户位置。
type groundedSearchLocation struct {
	// Type is fixed to approximate.
	// Type 固定为 approximate。
	Type string `json:"type"`
	// Country is an ISO country code when supplied.
	// Country 是提供时的 ISO 国家代码。
	Country string `json:"country,omitempty"`
	// Region is the caller-authorized region.
	// Region 是调用方授权区域。
	Region string `json:"region,omitempty"`
	// City is the caller-authorized city.
	// City 是调用方授权城市。
	City string `json:"city,omitempty"`
	// Timezone is the caller-authorized IANA timezone.
	// Timezone 是调用方授权 IANA 时区。
	Timezone string `json:"timezone,omitempty"`
}

// groundedSearchResponse contains only fields needed for unified search and usage.
// groundedSearchResponse 仅包含统一搜索和用量所需字段。
type groundedSearchResponse struct {
	// ID is the provider response identifier.
	// ID 是供应商响应标识。
	ID string `json:"id"`
	// Status is the terminal provider state.
	// Status 是供应商终态。
	Status string `json:"status"`
	// Output contains web-search calls and answer messages.
	// Output 包含网页搜索调用和答案消息。
	Output []groundedSearchOutput `json:"output"`
	// Usage contains provider token accounting.
	// Usage 包含供应商 Token 计量。
	Usage *groundedSearchUsage `json:"usage,omitempty"`
}

// groundedSearchOutput is one closed search-call or message output item.
// groundedSearchOutput 是一个封闭的搜索调用或消息输出项。
type groundedSearchOutput struct {
	// ID is the provider output item identifier.
	// ID 是供应商输出项标识。
	ID string `json:"id"`
	// Type distinguishes web_search_call and message.
	// Type 区分 web_search_call 与 message。
	Type string `json:"type"`
	// Status is the item lifecycle state.
	// Status 是项目生命周期状态。
	Status string `json:"status"`
	// Action contains observed web-search execution details.
	// Action 包含观测到的网页搜索执行详情。
	Action *groundedSearchAction `json:"action,omitempty"`
	// Content contains completed answer text and annotations.
	// Content 包含完成的答案文本和注释。
	Content []groundedSearchContent `json:"content,omitempty"`
}

// groundedSearchAction contains one provider search action and consulted sources.
// groundedSearchAction 包含一个供应商搜索动作和已咨询来源。
type groundedSearchAction struct {
	// Type identifies search, open_page, or find_in_page.
	// Type 标识 search、open_page 或 find_in_page。
	Type string `json:"type"`
	// Query is the actual provider search query.
	// Query 是供应商实际搜索查询。
	Query string `json:"query,omitempty"`
	// Sources contains provider-reported consulted URLs.
	// Sources 包含供应商报告的已咨询 URL。
	Sources []groundedSearchSource `json:"sources,omitempty"`
}

// groundedSearchSource is one consulted provider source.
// groundedSearchSource 是一个供应商已咨询来源。
type groundedSearchSource struct {
	// Type is the provider source kind.
	// Type 是供应商来源类型。
	Type string `json:"type"`
	// URL is the consulted source URL.
	// URL 是已咨询来源 URL。
	URL string `json:"url"`
}

// groundedSearchContent contains answer text and typed URL citations.
// groundedSearchContent 包含答案文本和类型化 URL 引用。
type groundedSearchContent struct {
	// Type is expected to be output_text.
	// Type 预期为 output_text。
	Type string `json:"type"`
	// Text is completed answer text.
	// Text 是完成的答案文本。
	Text string `json:"text"`
	// Annotations contains provider URL citations.
	// Annotations 包含供应商 URL 引用。
	Annotations []groundedSearchAnnotation `json:"annotations,omitempty"`
}

// groundedSearchAnnotation is one exact URL citation annotation.
// groundedSearchAnnotation 是一个精确 URL 引用注释。
type groundedSearchAnnotation struct {
	// Type identifies url_citation.
	// Type 标识 url_citation。
	Type string `json:"type"`
	// URL is the cited source URL.
	// URL 是被引用来源 URL。
	URL string `json:"url"`
	// Title is the provider-returned source title.
	// Title 是供应商返回的来源标题。
	Title string `json:"title"`
	// StartIndex is the inclusive answer character offset.
	// StartIndex 是答案字符的包含端点偏移。
	StartIndex int `json:"start_index"`
	// EndIndex is the exclusive answer character offset.
	// EndIndex 是答案字符的不包含端点偏移。
	EndIndex int `json:"end_index"`
}

// groundedSearchUsage contains provider token usage.
// groundedSearchUsage 包含供应商 Token 用量。
type groundedSearchUsage struct {
	// InputTokens is provider-reported input tokens.
	// InputTokens 是供应商报告的输入 Token。
	InputTokens *int64 `json:"input_tokens,omitempty"`
	// OutputTokens is provider-reported output tokens.
	// OutputTokens 是供应商报告的输出 Token。
	OutputTokens *int64 `json:"output_tokens,omitempty"`
	// TotalTokens is provider-reported total tokens.
	// TotalTokens 是供应商报告的总 Token。
	TotalTokens *int64 `json:"total_tokens,omitempty"`
}

// Execute calls the pinned tool and requires observable search evidence for verified requests.
// Execute 调用固定版本工具，并为验证请求要求可观察搜索证据。
func (d *GroundedSearchDriver) Execute(ctx context.Context, execution provider.ExecutionRequest) (provider.ExecutionResult, error) {
	if d == nil || d.client == nil {
		return provider.ExecutionResult{}, ErrInvalidSearchDriver
	}
	action, errAction := execution.ValidateForAction(SearchActionBindingID, providerconfig.AuthMethodAPIKey)
	if errAction != nil {
		return provider.ExecutionResult{}, errAction
	}
	if action.Operation != vcp.OperationSearchWeb || execution.Execution.Stream {
		return provider.ExecutionResult{}, fmt.Errorf("%w: grounded search is synchronous only", ErrUnsupportedSearchInput)
	}
	operation := *execution.Execution.Payload.SearchWeb
	request, errProject := projectGroundedSearchRequest(execution.Binding.Target.UpstreamServiceID, operation)
	if errProject != nil {
		return provider.ExecutionResult{}, errProject
	}
	encoded, errMarshal := json.Marshal(request)
	if errMarshal != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: encode request: %v", ErrInvalidSearchDriver, errMarshal)
	}
	upstream, errRequest := d.client.Do(ctx, transport.Request{Binding: execution.Binding, Method: http.MethodPost, Path: "/v1/responses", Body: encoded, Headers: []transport.Header{{Name: "Content-Type", Value: "application/json"}}, Authentication: transport.Authentication{Mode: transport.AuthenticationBearer}, IdempotencyKey: execution.Execution.IdempotencyKey})
	if errRequest != nil {
		return provider.ExecutionResult{}, errRequest
	}
	defer func() { _ = transport.DrainAndClose(upstream) }()
	reader, errBound := transport.NewBoundedResponseReader(upstream.Body, transport.MaximumNonStreamingResponseBytes)
	if errBound != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: bound response: %v", ErrInvalidSearchResponse, errBound)
	}
	var response groundedSearchResponse
	decoder := json.NewDecoder(reader)
	if errDecode := decoder.Decode(&response); errDecode != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: decode response: %v", ErrInvalidSearchResponse, errDecode)
	}
	if errTrailing := rejectGroundedSearchTrailingJSON(decoder); errTrailing != nil {
		return provider.ExecutionResult{}, errTrailing
	}
	return mapGroundedSearchResponse(operation, response)
}

// projectGroundedSearchRequest maps only officially evidenced filters and location fields.
// projectGroundedSearchRequest 仅映射官方证据支持的过滤器和位置字段。
func projectGroundedSearchRequest(model string, operation vcp.WebSearchOperation) (groundedSearchRequest, error) {
	if strings.TrimSpace(model) == "" || operation.OutputMode != vcp.WebSearchOutputAnswerWithCitations || len(operation.Domains.Block) != 0 || operation.Time.PublishedAfter != nil || operation.Time.PublishedBefore != nil || operation.Locale != (vcp.SearchLocale{}) || operation.SafeSearch != "" || operation.MaxResults != nil {
		return groundedSearchRequest{}, fmt.Errorf("%w: offering supports answer_with_citations, allowed domains, and approximate location only", ErrUnsupportedSearchInput)
	}
	tool := groundedSearchTool{Type: "web_search_2025_08_26"}
	if len(operation.Domains.Allow) > 0 {
		tool.Filters = &groundedSearchFilters{AllowedDomains: append([]string(nil), operation.Domains.Allow...)}
	}
	if operation.Location != (vcp.SearchLocation{}) {
		tool.UserLocation = &groundedSearchLocation{Type: "approximate", Country: operation.Location.Country, Region: operation.Location.Region, City: operation.Location.City, Timezone: operation.Location.Timezone}
	}
	return groundedSearchRequest{Model: model, Instructions: searchPrompt, Input: operation.Query, Tools: []groundedSearchTool{tool}, Include: []string{"web_search_call.action.sources"}}, nil
}

// mapGroundedSearchResponse preserves all observed queries, sources, answer text, citations, and token usage.
// mapGroundedSearchResponse 保留所有观测到的查询、来源、答案文本、引用和 Token 用量。
func mapGroundedSearchResponse(operation vcp.WebSearchOperation, response groundedSearchResponse) (provider.ExecutionResult, error) {
	if strings.TrimSpace(response.ID) == "" || response.Status != "completed" {
		return provider.ExecutionResult{}, fmt.Errorf("%w: response must be completed with an id", ErrInvalidSearchResponse)
	}
	search := &vcp.WebSearchResponse{Query: operation.Query}
	for _, item := range response.Output {
		switch item.Type {
		case "web_search_call":
			if item.Status != "completed" || item.Action == nil {
				return provider.ExecutionResult{}, fmt.Errorf("%w: incomplete web_search_call", ErrInvalidSearchResponse)
			}
			if item.Action.Type == "search" && strings.TrimSpace(item.Action.Query) != "" {
				search.Queries = append(search.Queries, item.Action.Query)
			}
			for _, source := range item.Action.Sources {
				if errURL := validateGroundedSearchURL(source.URL); errURL != nil {
					return provider.ExecutionResult{}, errURL
				}
				search.Sources = append(search.Sources, vcp.SearchSource{Type: source.Type, URL: source.URL})
			}
		case "message":
			for _, content := range item.Content {
				if content.Type != "output_text" {
					return provider.ExecutionResult{}, fmt.Errorf("%w: unsupported message content %q", ErrInvalidSearchResponse, content.Type)
				}
				search.Answer += content.Text
				for _, annotation := range content.Annotations {
					if annotation.Type != "url_citation" || annotation.StartIndex < 0 || annotation.EndIndex < annotation.StartIndex {
						return provider.ExecutionResult{}, fmt.Errorf("%w: invalid citation annotation", ErrInvalidSearchResponse)
					}
					if errURL := validateGroundedSearchURL(annotation.URL); errURL != nil {
						return provider.ExecutionResult{}, errURL
					}
					start := annotation.StartIndex
					end := annotation.EndIndex
					search.Citations = append(search.Citations, vcp.Citation{ID: fmt.Sprintf("citation_%d", len(search.Citations)+1), URL: annotation.URL, Title: annotation.Title, Location: vcp.CitationLocation{OutputItemID: item.ID, Start: &start, End: &end}})
				}
			}
		default:
			return provider.ExecutionResult{}, fmt.Errorf("%w: unsupported output item %q", ErrInvalidSearchResponse, item.Type)
		}
	}
	if len(search.Queries) == 0 {
		search.Evidence = vcp.SearchExecutionEvidence{Status: vcp.SearchExecutionRequestedUnverified}
		if operation.EvidenceRequirement == vcp.SearchEvidenceVerified {
			return provider.ExecutionResult{}, ErrSearchNotObserved
		}
	} else {
		search.Evidence = vcp.SearchExecutionEvidence{Status: vcp.SearchExecutionConfirmed, Kinds: []vcp.SearchEvidenceKind{vcp.SearchEvidenceProviderEvent, vcp.SearchEvidenceCitation}}
	}
	if response.Usage != nil {
		search.Usage = &vcp.UsageObservation{InputTokens: response.Usage.InputTokens, OutputTokens: response.Usage.OutputTokens, TotalTokens: response.Usage.TotalTokens, Source: "provider_reported", Aggregation: "snapshot", Phase: "terminal", AccountingBasis: "openai_responses", Final: true}
	}
	return provider.ExecutionResult{UpstreamResponseID: response.ID, Search: search}, nil
}

// validateGroundedSearchURL requires one absolute HTTPS provider source URL.
// validateGroundedSearchURL 要求一个绝对 HTTPS 供应商来源 URL。
func validateGroundedSearchURL(value string) error {
	parsed, errParse := url.Parse(value)
	if errParse != nil || parsed.Scheme != "https" || parsed.Hostname() == "" {
		return fmt.Errorf("%w: invalid source URL", ErrInvalidSearchResponse)
	}
	return nil
}

// rejectGroundedSearchTrailingJSON rejects a second JSON document after the response object.
// rejectGroundedSearchTrailingJSON 拒绝响应对象后的第二个 JSON 文档。
func rejectGroundedSearchTrailingJSON(decoder *json.Decoder) error {
	var trailing json.RawMessage
	if errDecode := decoder.Decode(&trailing); errDecode == io.EOF {
		return nil
	} else if errDecode != nil {
		return fmt.Errorf("%w: decode trailing response: %v", ErrInvalidSearchResponse, errDecode)
	}
	return fmt.Errorf("%w: trailing JSON document", ErrInvalidSearchResponse)
}
