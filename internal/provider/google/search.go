package google

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
	// ErrInvalidSearchDriver reports an incomplete Google grounded-search driver.
	// ErrInvalidSearchDriver 表示不完整的 Google 模型联网搜索 Driver。
	ErrInvalidSearchDriver = errors.New("invalid Google grounded search driver")
	// ErrUnsupportedSearchInput reports a policy that Google Interactions does not document.
	// ErrUnsupportedSearchInput 表示 Google Interactions 未记录支持的策略。
	ErrUnsupportedSearchInput = errors.New("unsupported Google grounded search input")
	// ErrInvalidSearchResponse reports malformed Google grounding evidence.
	// ErrInvalidSearchResponse 表示格式错误的 Google 联网证据。
	ErrInvalidSearchResponse = errors.New("invalid Google grounded search response")
	// ErrSearchNotObserved reports a verified request without a Google search call.
	// ErrSearchNotObserved 表示要求验证但没有 Google 搜索调用。
	ErrSearchNotObserved = errors.New("search_not_observed")
)

const (
	// SearchActionBindingID identifies Google Interactions grounded search.
	// SearchActionBindingID 标识 Google Interactions 模型联网搜索。
	SearchActionBindingID = "action_google_search_web"
	// SearchProtocolProfileID identifies the current Interactions Google Search contract.
	// SearchProtocolProfileID 标识当前 Interactions Google Search 合同。
	SearchProtocolProfileID = "google.interactions.google_search.v1beta"
	// SearchPromptTemplateID identifies the fixed search instruction.
	// SearchPromptTemplateID 标识固定搜索指令。
	SearchPromptTemplateID = "google.web_search.answer_with_citations"
	// SearchPromptTemplateRevision freezes prompt behavior.
	// SearchPromptTemplateRevision 冻结提示行为。
	SearchPromptTemplateRevision uint64 = 1
	// SearchBackingModelID is the fixed supported model.
	// SearchBackingModelID 是固定支持模型。
	SearchBackingModelID = "gemini-3.5-flash"
	// SearchBackingModelOfferingID is the deterministic model offering identifier.
	// SearchBackingModelOfferingID 是确定性模型 Offering 标识。
	SearchBackingModelOfferingID = "offer_gemini_3_5_flash_google_interactions"
	// googleSearchPrompt is the immutable provider-facing instruction.
	// googleSearchPrompt 是不可变供应商搜索指令。
	googleSearchPrompt = "Use Google Search for the user's query. Answer only from observed sources and preserve citations."
)

// GroundedSearchDriver executes one fixed Gemini model with Google Search.
// GroundedSearchDriver 使用 Google Search 执行一个固定 Gemini 模型。
type GroundedSearchDriver struct {
	// definitionID is the sole owning definition.
	// definitionID 是唯一拥有 Definition。
	definitionID string
	// client owns target-bound transport.
	// client 拥有 Target 绑定传输。
	client *transport.Client
}

// NewGroundedSearchDriver creates a Google Interactions search driver.
// NewGroundedSearchDriver 创建 Google Interactions 搜索 Driver。
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

// googleSearchRequest is the documented Interactions search request.
// googleSearchRequest 是文档记录的 Interactions 搜索请求。
type googleSearchRequest struct {
	// Model is the fixed backing model.
	// Model 是固定后端模型。
	Model string `json:"model"`
	// Input contains the immutable instruction and caller query.
	// Input 包含不可变指令和调用方查询。
	Input string `json:"input"`
	// Tools enables only Google Search.
	// Tools 仅启用 Google Search。
	Tools []googleSearchTool `json:"tools"`
}

// googleSearchTool identifies the native Interactions tool.
// googleSearchTool 标识原生 Interactions 工具。
type googleSearchTool struct {
	// Type is fixed by the official contract.
	// Type 由官方合同固定。
	Type string `json:"type"`
}

// googleSearchResponse contains the documented grounded response steps.
// googleSearchResponse 包含文档记录的联网响应步骤。
type googleSearchResponse struct {
	// ID is the provider interaction identifier.
	// ID 是供应商交互标识。
	ID string `json:"id"`
	// Steps contains search calls and model output.
	// Steps 包含搜索调用和模型输出。
	Steps []googleSearchStep `json:"steps"`
}

// googleSearchStep is one closed response step consumed by the Router.
// googleSearchStep 是 Router 消费的一个封闭响应步骤。
type googleSearchStep struct {
	// Type distinguishes search calls from model output.
	// Type 区分搜索调用和模型输出。
	Type string `json:"type"`
	// Arguments contains actual generated queries.
	// Arguments 包含实际生成查询。
	Arguments googleSearchArguments `json:"arguments"`
	// Content contains answer blocks.
	// Content 包含答案块。
	Content []googleSearchContent `json:"content"`
}

// googleSearchArguments contains actual provider queries.
// googleSearchArguments 包含真实供应商查询。
type googleSearchArguments struct {
	// Queries preserves execution order.
	// Queries 保留执行顺序。
	Queries []string `json:"queries"`
}

// googleSearchContent contains answer text and URL citations.
// googleSearchContent 包含答案文本与 URL 引用。
type googleSearchContent struct {
	// Type identifies a text block.
	// Type 标识文本块。
	Type string `json:"type"`
	// Text is provider-generated grounded text.
	// Text 是供应商生成的联网文本。
	Text string `json:"text"`
	// Annotations contains provider citations.
	// Annotations 包含供应商引用。
	Annotations []googleSearchAnnotation `json:"annotations"`
}

// googleSearchAnnotation is one URL citation span.
// googleSearchAnnotation 是一个 URL 引用范围。
type googleSearchAnnotation struct {
	// Type must be url_citation.
	// Type 必须为 url_citation。
	Type string `json:"type"`
	// URL is the cited source.
	// URL 是引用来源。
	URL string `json:"url"`
	// Title is the provider source title.
	// Title 是供应商来源标题。
	Title string `json:"title"`
	// StartIndex is the inclusive answer offset.
	// StartIndex 是答案包含端点起始偏移。
	StartIndex int `json:"start_index"`
	// EndIndex is the exclusive answer offset.
	// EndIndex 是答案不包含端点结束偏移。
	EndIndex int `json:"end_index"`
}

// Execute invokes Google Interactions and preserves actual queries and citations.
// Execute 调用 Google Interactions 并保留真实查询与引用。
func (d *GroundedSearchDriver) Execute(ctx context.Context, execution provider.ExecutionRequest) (provider.ExecutionResult, error) {
	if d == nil || d.client == nil {
		return provider.ExecutionResult{}, ErrInvalidSearchDriver
	}
	action, errAction := execution.ValidateForAction(SearchActionBindingID, providerconfig.AuthMethodAPIKey)
	if errAction != nil {
		return provider.ExecutionResult{}, errAction
	}
	if action.Operation != vcp.OperationSearchWeb || execution.Execution.Stream {
		return provider.ExecutionResult{}, fmt.Errorf("%w: Google grounded search is synchronous only", ErrUnsupportedSearchInput)
	}
	operation := *execution.Execution.Payload.SearchWeb
	if errPolicy := validateGoogleSearchPolicy(operation); errPolicy != nil {
		return provider.ExecutionResult{}, errPolicy
	}
	payload := googleSearchRequest{Model: SearchBackingModelID, Input: googleSearchPrompt + "\n\nQuery: " + operation.Query, Tools: []googleSearchTool{{Type: "google_search"}}}
	encoded, errMarshal := json.Marshal(payload)
	if errMarshal != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: encode request: %v", ErrInvalidSearchDriver, errMarshal)
	}
	upstream, errRequest := d.client.Do(ctx, transport.Request{Binding: execution.Binding, Method: http.MethodPost, Path: "/v1beta/interactions", Body: encoded, Headers: []transport.Header{{Name: "Content-Type", Value: "application/json"}, {Name: "Api-Revision", Value: interactionsAPIRevision}}, Authentication: transport.Authentication{Mode: transport.AuthenticationHeader, HeaderName: "X-Goog-Api-Key"}, IdempotencyKey: execution.Execution.IdempotencyKey})
	if errRequest != nil {
		return provider.ExecutionResult{}, errRequest
	}
	defer func() { _ = transport.DrainAndClose(upstream) }()
	reader, errBound := transport.NewBoundedResponseReader(upstream.Body, transport.MaximumNonStreamingResponseBytes)
	if errBound != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: bound response: %v", ErrInvalidSearchResponse, errBound)
	}
	var response googleSearchResponse
	decoder := json.NewDecoder(reader)
	if errDecode := decoder.Decode(&response); errDecode != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: decode response: %v", ErrInvalidSearchResponse, errDecode)
	}
	return mapGoogleSearchResponse(operation, response)
}

// validateGoogleSearchPolicy rejects every VCP option absent from the Interactions contract.
// validateGoogleSearchPolicy 拒绝 Interactions 合同中不存在的每个 VCP 选项。
func validateGoogleSearchPolicy(operation vcp.WebSearchOperation) error {
	if operation.OutputMode != vcp.WebSearchOutputAnswerWithCitations || len(operation.Domains.Allow) != 0 || len(operation.Domains.Block) != 0 || operation.Time.PublishedAfter != nil || operation.Time.PublishedBefore != nil || operation.Locale.Language != "" || operation.Locale.Region != "" || operation.Location.Country != "" || operation.Location.Region != "" || operation.Location.City != "" || operation.Location.Timezone != "" || operation.SafeSearch != "" || operation.MaxResults != nil {
		return ErrUnsupportedSearchInput
	}
	return nil
}

// mapGoogleSearchResponse validates and maps only provider-observed grounding evidence.
// mapGoogleSearchResponse 仅校验并映射供应商观测到的联网证据。
func mapGoogleSearchResponse(operation vcp.WebSearchOperation, response googleSearchResponse) (provider.ExecutionResult, error) {
	search := &vcp.WebSearchResponse{Query: operation.Query, Evidence: vcp.SearchExecutionEvidence{Status: vcp.SearchExecutionRequestedUnverified}}
	for _, step := range response.Steps {
		switch step.Type {
		case "google_search_call":
			for _, query := range step.Arguments.Queries {
				if strings.TrimSpace(query) != "" {
					search.Queries = append(search.Queries, query)
				}
			}
		case "model_output":
			for _, content := range step.Content {
				if content.Type != "text" {
					continue
				}
				search.Answer += content.Text
				for _, annotation := range content.Annotations {
					if annotation.Type != "url_citation" || annotation.StartIndex < 0 || annotation.EndIndex < annotation.StartIndex || annotation.EndIndex > len(content.Text) {
						return provider.ExecutionResult{}, ErrInvalidSearchResponse
					}
					parsed, errParse := url.Parse(annotation.URL)
					if errParse != nil || parsed.Scheme != "https" || parsed.Host == "" {
						return provider.ExecutionResult{}, ErrInvalidSearchResponse
					}
					start := annotation.StartIndex
					end := annotation.EndIndex
					search.Citations = append(search.Citations, vcp.Citation{ID: fmt.Sprintf("citation_%d", len(search.Citations)+1), URL: annotation.URL, Title: annotation.Title, Location: vcp.CitationLocation{Start: &start, End: &end}})
				}
			}
		}
	}
	if len(search.Queries) > 0 {
		search.Query = search.Queries[0]
		search.Evidence = vcp.SearchExecutionEvidence{Status: vcp.SearchExecutionConfirmed, Kinds: []vcp.SearchEvidenceKind{vcp.SearchEvidenceProviderEvent}}
		if len(search.Citations) > 0 {
			search.Evidence.Kinds = append(search.Evidence.Kinds, vcp.SearchEvidenceCitation)
		}
	}
	if operation.EvidenceRequirement == vcp.SearchEvidenceVerified && search.Evidence.Status != vcp.SearchExecutionConfirmed {
		return provider.ExecutionResult{}, ErrSearchNotObserved
	}
	return provider.ExecutionResult{Search: search, UpstreamResponseID: response.ID}, nil
}
