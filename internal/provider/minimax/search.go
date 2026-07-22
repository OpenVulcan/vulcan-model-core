package minimax

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

var (
	// ErrInvalidSearchDriver reports an incomplete MiniMax search driver or response.
	// ErrInvalidSearchDriver 表示不完整的 MiniMax 搜索驱动或响应。
	ErrInvalidSearchDriver = errors.New("invalid MiniMax search driver")
	// ErrUnsupportedSearchInput reports filters that the copied MiniMax endpoint cannot carry.
	// ErrUnsupportedSearchInput 表示复制的 MiniMax 端点无法承载的过滤条件。
	ErrUnsupportedSearchInput = errors.New("unsupported MiniMax search input")
)

const (
	// SearchWebActionBindingID identifies the MiniMax Coding Plan direct search action.
	// SearchWebActionBindingID 标识 MiniMax Coding Plan 直接搜索动作。
	SearchWebActionBindingID = "action_minimax_search_web"
	// SearchWebProtocolProfileID identifies the versioned MiniMax search contract.
	// SearchWebProtocolProfileID 标识版本化 MiniMax 搜索合同。
	SearchWebProtocolProfileID = "minimax.coding_plan.search.v1"
	// searchWebPath is copied from minimax-cli.
	// searchWebPath 从 minimax-cli 复制而来。
	searchWebPath = "/v1/coding_plan/search"
)

// SearchDriver executes MiniMax's synchronous structured search endpoint.
// SearchDriver 执行 MiniMax 的同步结构化搜索端点。
type SearchDriver struct {
	// definitionID fixes one regional provider definition.
	// definitionID 固定一个区域供应商 Definition。
	definitionID string
	// client owns target-bound authenticated transport.
	// client 管理 Target 绑定的认证传输。
	client *transport.Client
}

// searchRequest is MiniMax's exact single-field search request.
// searchRequest 是 MiniMax 精确的单字段搜索请求。
type searchRequest struct {
	// Query is the exact caller search text.
	// Query 是调用方精确搜索文本。
	Query string `json:"q"`
}

// searchResponse contains ordered organic results copied from minimax-cli.
// searchResponse 包含从 minimax-cli 复制的有序自然搜索结果。
type searchResponse struct {
	// Organic contains at most ten provider results.
	// Organic 包含最多十条供应商结果。
	Organic []searchResult `json:"organic"`
}

// searchResult contains one provider-returned result.
// searchResult 包含一条供应商返回结果。
type searchResult struct {
	// Title is the provider-returned title.
	// Title 是供应商返回标题。
	Title string `json:"title"`
	// Link is the provider-returned destination.
	// Link 是供应商返回目标地址。
	Link string `json:"link"`
	// Snippet is the provider-returned excerpt.
	// Snippet 是供应商返回摘要。
	Snippet string `json:"snippet"`
	// Date is retained only for validation evidence because its wire format is undocumented.
	// Date 仅保留作校验证据，因为其 wire 格式未记录。
	Date string `json:"date"`
}

// NewSearchDriver creates one region-fixed MiniMax direct-search driver.
// NewSearchDriver 创建一个区域固定的 MiniMax 直接搜索驱动。
func NewSearchDriver(definitionID string, client *transport.Client) (*SearchDriver, error) {
	if strings.TrimSpace(definitionID) == "" || client == nil {
		return nil, ErrInvalidSearchDriver
	}
	return &SearchDriver{definitionID: definitionID, client: client}, nil
}

// ProviderDefinitionID returns the sole owning definition.
// ProviderDefinitionID 返回唯一归属 Definition。
func (d *SearchDriver) ProviderDefinitionID() string { return d.definitionID }

// ActionBindingID returns the exact search action.
// ActionBindingID 返回精确搜索动作。
func (d *SearchDriver) ActionBindingID() string { return SearchWebActionBindingID }

// Execute maps one filter-free VCP search to the MiniMax endpoint and preserves result order.
// Execute 将一条无过滤条件的 VCP 搜索映射到 MiniMax 端点并保留结果顺序。
func (d *SearchDriver) Execute(ctx context.Context, execution provider.ExecutionRequest) (provider.ExecutionResult, error) {
	if d == nil || d.client == nil {
		return provider.ExecutionResult{}, ErrInvalidSearchDriver
	}
	action, errAction := execution.ValidateForAction(SearchWebActionBindingID, providerconfig.AuthMethodAPIKey, providerconfig.AuthMethodDeviceFlow)
	if errAction != nil {
		return provider.ExecutionResult{}, errAction
	}
	if action.Operation != vcp.OperationSearchWeb || execution.Execution.Stream {
		return provider.ExecutionResult{}, fmt.Errorf("%w: MiniMax search is synchronous only", ErrUnsupportedSearchInput)
	}
	operation := *execution.Execution.Payload.SearchWeb
	if operation.OutputMode != vcp.WebSearchOutputResults || len(operation.Domains.Allow) != 0 || len(operation.Domains.Block) != 0 || operation.Time != (vcp.SearchTimeFilter{}) || operation.Locale != (vcp.SearchLocale{}) || operation.Location != (vcp.SearchLocation{}) || operation.SafeSearch != "" {
		return provider.ExecutionResult{}, fmt.Errorf("%w: MiniMax search supports query and max_results only", ErrUnsupportedSearchInput)
	}
	if operation.MaxResults != nil && (*operation.MaxResults < 1 || *operation.MaxResults > 10) {
		return provider.ExecutionResult{}, fmt.Errorf("%w: max_results must be between one and ten", ErrUnsupportedSearchInput)
	}
	body, errMarshal := json.Marshal(searchRequest{Query: operation.Query})
	if errMarshal != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: encode request: %v", ErrInvalidSearchDriver, errMarshal)
	}
	response, errRequest := d.client.Do(ctx, transport.Request{Binding: execution.Binding, Method: http.MethodPost, Path: searchWebPath, Body: body, Headers: []transport.Header{{Name: "Content-Type", Value: "application/json"}}, Authentication: transport.Authentication{Mode: transport.AuthenticationBearer}, IdempotencyKey: execution.Execution.IdempotencyKey})
	if errRequest != nil {
		return provider.ExecutionResult{}, errRequest
	}
	defer func() { _ = transport.DrainAndClose(response) }()
	reader, errBound := transport.NewBoundedResponseReader(response.Body, transport.MaximumNonStreamingResponseBytes)
	if errBound != nil {
		return provider.ExecutionResult{}, errBound
	}
	var upstream searchResponse
	decoder := json.NewDecoder(reader)
	if errDecode := decoder.Decode(&upstream); errDecode != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: decode response: %v", ErrInvalidSearchDriver, errDecode)
	}
	if errTrailing := rejectTrailingJSON(decoder, ErrInvalidSearchDriver); errTrailing != nil {
		return provider.ExecutionResult{}, errTrailing
	}
	limit := len(upstream.Organic)
	if operation.MaxResults != nil && *operation.MaxResults < limit {
		limit = *operation.MaxResults
	}
	results := make([]vcp.WebSearchResult, limit)
	for index := 0; index < limit; index++ {
		item := upstream.Organic[index]
		parsed, errParse := url.Parse(item.Link)
		if errParse != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil {
			return provider.ExecutionResult{}, fmt.Errorf("%w: result %d has invalid HTTPS URL", ErrInvalidSearchDriver, index)
		}
		publishedAt, errDate := miniMaxSearchPublishedAt(item.Date)
		if errDate != nil {
			return provider.ExecutionResult{}, fmt.Errorf("%w: result %d has an unsupported date", ErrInvalidSearchDriver, index)
		}
		results[index] = vcp.WebSearchResult{ID: fmt.Sprintf("result_%d", index+1), Rank: index + 1, Title: item.Title, URL: item.Link, SourceDomain: strings.ToLower(parsed.Hostname()), Snippet: item.Snippet, PublishedAt: publishedAt}
	}
	search := &vcp.WebSearchResponse{Query: operation.Query, Evidence: vcp.SearchExecutionEvidence{Status: vcp.SearchExecutionConfirmed, Kinds: []vcp.SearchEvidenceKind{vcp.SearchEvidenceStructuredResult}}, Results: results}
	return provider.ExecutionResult{Search: search}, nil
}

// miniMaxSearchPublishedAt normalizes the exact date-only shape proved by the pinned CLI fixture.
// miniMaxSearchPublishedAt 规范化固定 CLI 夹具证明的精确纯日期形态。
func miniMaxSearchPublishedAt(value string) (*time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	parsed, errParse := time.Parse("2006-01-02", value)
	if errParse != nil {
		return nil, errParse
	}
	parsed = parsed.UTC()
	return &parsed, nil
}
