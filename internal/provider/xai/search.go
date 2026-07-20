package xai

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
	// ErrInvalidSearchDriver reports an incomplete xAI search driver.
	// ErrInvalidSearchDriver 表示不完整的 xAI 搜索 Driver。
	ErrInvalidSearchDriver = errors.New("invalid xAI grounded search driver")
	// ErrUnsupportedSearchInput reports a policy outside the xAI web-search contract.
	// ErrUnsupportedSearchInput 表示超出 xAI 网页搜索合同的策略。
	ErrUnsupportedSearchInput = errors.New("unsupported xAI grounded search input")
	// ErrInvalidSearchResponse reports malformed xAI citation data.
	// ErrInvalidSearchResponse 表示格式错误的 xAI 引用数据。
	ErrInvalidSearchResponse = errors.New("invalid xAI grounded search response")
	// ErrSearchNotObserved reports a verified request without provider search evidence.
	// ErrSearchNotObserved 表示要求验证但没有供应商搜索证据。
	ErrSearchNotObserved = errors.New("search_not_observed")
)

const (
	// SearchActionBindingID identifies the xAI Responses web-search action.
	// SearchActionBindingID 标识 xAI Responses 网页搜索动作。
	SearchActionBindingID = "action_xai_search_web"
	// SearchProtocolProfileID identifies the native xAI Responses web-search contract.
	// SearchProtocolProfileID 标识原生 xAI Responses 网页搜索合同。
	SearchProtocolProfileID = "xai.responses.web_search.v1"
	// SearchPromptTemplateID identifies the fixed search instruction.
	// SearchPromptTemplateID 标识固定搜索指令。
	SearchPromptTemplateID = "xai.web_search.answer_with_citations"
	// SearchPromptTemplateRevision freezes prompt behavior.
	// SearchPromptTemplateRevision 冻结提示行为。
	SearchPromptTemplateRevision uint64 = 1
	// SearchBackingModelID is the fixed web-search-capable model.
	// SearchBackingModelID 是固定的联网搜索模型。
	SearchBackingModelID = "grok-4.5"
	// SearchBackingModelOfferingID is its deterministic offering identifier.
	// SearchBackingModelOfferingID 是其确定性 Offering 标识。
	SearchBackingModelOfferingID = "offer_grok_4_5_xai_responses"
	// xaiSearchPrompt is the immutable provider-facing instruction.
	// xaiSearchPrompt 是不可变供应商搜索指令。
	xaiSearchPrompt = "Search the web for the user's query. Answer only from observed web sources and preserve inline citations."
)

// GroundedSearchDriver executes a fixed Grok model with native web search.
// GroundedSearchDriver 使用原生网页搜索执行固定 Grok 模型。
type GroundedSearchDriver struct {
	// definitionID is the sole owning definition.
	// definitionID 是唯一拥有 Definition。
	definitionID string
	// client owns target-bound transport.
	// client 拥有 Target 绑定传输。
	client *transport.Client
}

// NewGroundedSearchDriver creates an xAI Responses search driver.
// NewGroundedSearchDriver 创建 xAI Responses 搜索 Driver。
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

// xaiSearchRequest is the closed Responses request used by unified search.
// xaiSearchRequest 是统一搜索使用的封闭 Responses 请求。
type xaiSearchRequest struct {
	// Model is the fixed backing model.
	// Model 是固定后端模型。
	Model string `json:"model"`
	// Instructions is the immutable search instruction.
	// Instructions 是不可变搜索指令。
	Instructions string `json:"instructions"`
	// Input is the exact caller query.
	// Input 是调用方精确查询。
	Input string `json:"input"`
	// Tools contains only native web search.
	// Tools 仅包含原生网页搜索。
	Tools []xaiSearchTool `json:"tools"`
}

// xaiSearchTool contains documented domain controls.
// xaiSearchTool 包含文档记录的域名控制。
type xaiSearchTool struct {
	// Type is fixed to web_search.
	// Type 固定为 web_search。
	Type string `json:"type"`
	// AllowedDomains contains at most five allowlisted domains.
	// AllowedDomains 包含最多五个允许域名。
	AllowedDomains []string `json:"allowed_domains,omitempty"`
	// ExcludedDomains contains at most five blocked domains.
	// ExcludedDomains 包含最多五个阻止域名。
	ExcludedDomains []string `json:"excluded_domains,omitempty"`
}

// xaiSearchResponse contains documented answer and citation fields.
// xaiSearchResponse 包含文档记录的答案和引用字段。
type xaiSearchResponse struct {
	// ID is the provider response identifier.
	// ID 是供应商响应标识。
	ID string `json:"id"`
	// Output contains answer messages.
	// Output 包含答案消息。
	Output []xaiSearchOutput `json:"output"`
	// Citations contains every source encountered by successful tools.
	// Citations 包含成功工具遇到的每个来源。
	Citations []string `json:"citations"`
}

// xaiSearchOutput is one response output item.
// xaiSearchOutput 是一个响应输出项。
type xaiSearchOutput struct {
	// Type identifies message output.
	// Type 标识消息输出。
	Type string `json:"type"`
	// Content contains output text blocks.
	// Content 包含输出文本块。
	Content []xaiSearchContent `json:"content"`
}

// xaiSearchContent contains grounded text and annotations.
// xaiSearchContent 包含联网文本和注释。
type xaiSearchContent struct {
	// Type identifies output_text.
	// Type 标识 output_text。
	Type string `json:"type"`
	// Text is the grounded answer.
	// Text 是联网答案。
	Text string `json:"text"`
	// Annotations contains structured inline citations.
	// Annotations 包含结构化行内引用。
	Annotations []xaiSearchAnnotation `json:"annotations"`
}

// xaiSearchAnnotation contains one exact citation span.
// xaiSearchAnnotation 包含一个精确引用范围。
type xaiSearchAnnotation struct {
	// Type must be url_citation.
	// Type 必须为 url_citation。
	Type string `json:"type"`
	// URL is the source URL.
	// URL 是来源 URL。
	URL string `json:"url"`
	// Title is the provider citation label.
	// Title 是供应商引用标签。
	Title string `json:"title"`
	// StartIndex is the inclusive answer offset.
	// StartIndex 是答案包含端点起始偏移。
	StartIndex int `json:"start_index"`
	// EndIndex is the exclusive answer offset.
	// EndIndex 是答案不包含端点结束偏移。
	EndIndex int `json:"end_index"`
}

// Execute invokes xAI Responses and preserves every actual source and inline citation.
// Execute 调用 xAI Responses 并保留每个真实来源与行内引用。
func (d *GroundedSearchDriver) Execute(ctx context.Context, execution provider.ExecutionRequest) (provider.ExecutionResult, error) {
	if d == nil || d.client == nil {
		return provider.ExecutionResult{}, ErrInvalidSearchDriver
	}
	action, errAction := execution.ValidateForAction(SearchActionBindingID, providerconfig.AuthMethodAPIKey)
	if errAction != nil {
		return provider.ExecutionResult{}, errAction
	}
	if action.Operation != vcp.OperationSearchWeb || execution.Execution.Stream {
		return provider.ExecutionResult{}, fmt.Errorf("%w: xAI grounded search is synchronous only", ErrUnsupportedSearchInput)
	}
	operation := *execution.Execution.Payload.SearchWeb
	tool, errPolicy := projectXAISearchTool(operation)
	if errPolicy != nil {
		return provider.ExecutionResult{}, errPolicy
	}
	payload := xaiSearchRequest{Model: SearchBackingModelID, Instructions: xaiSearchPrompt, Input: operation.Query, Tools: []xaiSearchTool{tool}}
	encoded, errMarshal := json.Marshal(payload)
	if errMarshal != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: encode request: %v", ErrInvalidSearchDriver, errMarshal)
	}
	upstream, errRequest := d.client.Do(ctx, transport.Request{Binding: execution.Binding, Method: http.MethodPost, Path: "/responses", Body: encoded, Headers: []transport.Header{{Name: "Content-Type", Value: "application/json"}}, Authentication: transport.Authentication{Mode: transport.AuthenticationBearer}, IdempotencyKey: execution.Execution.IdempotencyKey})
	if errRequest != nil {
		return provider.ExecutionResult{}, errRequest
	}
	defer func() { _ = transport.DrainAndClose(upstream) }()
	reader, errBound := transport.NewBoundedResponseReader(upstream.Body, transport.MaximumNonStreamingResponseBytes)
	if errBound != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: bound response: %v", ErrInvalidSearchResponse, errBound)
	}
	var response xaiSearchResponse
	if errDecode := json.NewDecoder(reader).Decode(&response); errDecode != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: decode response: %v", ErrInvalidSearchResponse, errDecode)
	}
	return mapXAISearchResponse(operation, response)
}

// projectXAISearchTool maps only the documented domain policy subset.
// projectXAISearchTool 仅映射文档记录的域名策略子集。
func projectXAISearchTool(operation vcp.WebSearchOperation) (xaiSearchTool, error) {
	if operation.OutputMode != vcp.WebSearchOutputAnswerWithCitations || operation.Time.PublishedAfter != nil || operation.Time.PublishedBefore != nil || operation.Locale.Language != "" || operation.Locale.Region != "" || operation.Location.Country != "" || operation.Location.Region != "" || operation.Location.City != "" || operation.Location.Timezone != "" || operation.SafeSearch != "" || operation.MaxResults != nil || len(operation.Domains.Allow) > 5 || len(operation.Domains.Block) > 5 || len(operation.Domains.Allow) > 0 && len(operation.Domains.Block) > 0 {
		return xaiSearchTool{}, ErrUnsupportedSearchInput
	}
	return xaiSearchTool{Type: "web_search", AllowedDomains: append([]string(nil), operation.Domains.Allow...), ExcludedDomains: append([]string(nil), operation.Domains.Block...)}, nil
}

// mapXAISearchResponse maps provider source lists separately from positional citations.
// mapXAISearchResponse 将供应商来源列表与位置引用分别映射。
func mapXAISearchResponse(operation vcp.WebSearchOperation, response xaiSearchResponse) (provider.ExecutionResult, error) {
	search := &vcp.WebSearchResponse{Query: operation.Query, Evidence: vcp.SearchExecutionEvidence{Status: vcp.SearchExecutionRequestedUnverified}}
	for _, sourceURL := range response.Citations {
		if errURL := validateXAISearchURL(sourceURL); errURL != nil {
			return provider.ExecutionResult{}, errURL
		}
		search.Sources = append(search.Sources, vcp.SearchSource{Type: "url", URL: sourceURL})
	}
	for _, output := range response.Output {
		if output.Type != "message" {
			continue
		}
		for _, content := range output.Content {
			if content.Type != "output_text" {
				continue
			}
			search.Answer += content.Text
			for _, annotation := range content.Annotations {
				if annotation.Type != "url_citation" || annotation.StartIndex < 0 || annotation.EndIndex < annotation.StartIndex || annotation.EndIndex > len(content.Text) {
					return provider.ExecutionResult{}, ErrInvalidSearchResponse
				}
				if errURL := validateXAISearchURL(annotation.URL); errURL != nil {
					return provider.ExecutionResult{}, errURL
				}
				start := annotation.StartIndex
				end := annotation.EndIndex
				search.Citations = append(search.Citations, vcp.Citation{ID: fmt.Sprintf("citation_%d", len(search.Citations)+1), URL: annotation.URL, Title: annotation.Title, Location: vcp.CitationLocation{Start: &start, End: &end}})
			}
		}
	}
	if len(search.Sources) > 0 || len(search.Citations) > 0 {
		search.Evidence.Status = vcp.SearchExecutionConfirmed
		search.Evidence.Kinds = []vcp.SearchEvidenceKind{vcp.SearchEvidenceCitation}
	}
	if operation.EvidenceRequirement == vcp.SearchEvidenceVerified && search.Evidence.Status != vcp.SearchExecutionConfirmed {
		return provider.ExecutionResult{}, ErrSearchNotObserved
	}
	return provider.ExecutionResult{Search: search, UpstreamResponseID: response.ID}, nil
}

// validateXAISearchURL requires one complete HTTPS provider source.
// validateXAISearchURL 要求一个完整 HTTPS 供应商来源。
func validateXAISearchURL(value string) error {
	parsed, errParse := url.Parse(value)
	if errParse != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return ErrInvalidSearchResponse
	}
	return nil
}
