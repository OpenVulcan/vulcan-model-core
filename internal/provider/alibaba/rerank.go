package alibaba

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"

	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

const (
	// RerankActionBindingID identifies Alibaba's OpenAI-compatible qwen3-rerank action.
	// RerankActionBindingID 标识 Alibaba OpenAI 兼容 qwen3-rerank 动作。
	RerankActionBindingID = "action_alibaba_rerank_documents"
	// RerankProtocolProfileID identifies the exact flat qwen3-rerank request and response contract.
	// RerankProtocolProfileID 标识精确的扁平 qwen3-rerank 请求与响应合同。
	RerankProtocolProfileID = "alibaba.qwen3-rerank.v1"
	// rerankEndpointPath is the documented compatible-mode path below a regional Model Studio endpoint.
	// rerankEndpointPath 是区域 Model Studio 入口下文档化的 compatible-mode 路径。
	rerankEndpointPath = "/compatible-mode/v1/reranks"
	// rerankScoreSemantics preserves Alibaba's documented request-relative relevance score meaning.
	// rerankScoreSemantics 保留 Alibaba 文档化的请求内相对相关性分数语义。
	rerankScoreSemantics = "alibaba.request_relative_relevance_score"
)

var (
	// ErrInvalidRerankDriver reports an incomplete or unsupported qwen3-rerank execution.
	// ErrInvalidRerankDriver 表示不完整或不受支持的 qwen3-rerank 执行。
	ErrInvalidRerankDriver = errors.New("invalid Alibaba rerank driver")
	// ErrInvalidRerankResponse reports a malformed qwen3-rerank result.
	// ErrInvalidRerankResponse 表示格式错误的 qwen3-rerank 结果。
	ErrInvalidRerankResponse = errors.New("invalid Alibaba rerank response")
)

// RerankActionDriver executes the text-only qwen3-rerank compatible contract for one immutable provider definition.
// RerankActionDriver 为一个不可变供应商 Definition 执行纯文本 qwen3-rerank 兼容合同。
type RerankActionDriver struct {
	// definitionID is the sole provider definition permitted to use this driver.
	// definitionID 是允许使用此 Driver 的唯一供应商 Definition。
	definitionID string
	// client owns provider-scoped authenticated HTTP execution.
	// client 管理供应商作用域的认证 HTTP 执行。
	client *transport.Client
}

// qwenRerankRequest is the documented flat qwen3-rerank request body.
// qwenRerankRequest 是文档化的扁平 qwen3-rerank 请求体。
type qwenRerankRequest struct {
	// Model is fixed by the resolved catalog target.
	// Model 由解析后的目录目标固定。
	Model string `json:"model"`
	// Query contains one text query.
	// Query 包含一条文本查询。
	Query string `json:"query"`
	// Documents preserves candidate order.
	// Documents 保留候选项顺序。
	Documents []string `json:"documents"`
	// TopN optionally limits returned results.
	// TopN 可选限制返回结果数。
	TopN *int `json:"top_n,omitempty"`
}

// qwenRerankResponse is the documented qwen3-rerank success body.
// qwenRerankResponse 是文档化的 qwen3-rerank 成功响应体。
type qwenRerankResponse struct {
	// Object is fixed to list.
	// Object 固定为 list。
	Object string `json:"object"`
	// Results contains provider-ranked original indexes and scores.
	// Results 包含供应商排序后的原始索引与分数。
	Results []qwenRerankResult `json:"results"`
	// Model reports the actual upstream model.
	// Model 报告实际上游模型。
	Model string `json:"model"`
	// ID is the provider request identifier.
	// ID 是供应商请求标识。
	ID string `json:"id"`
	// Usage contains request token accounting.
	// Usage 包含请求 Token 计量。
	Usage qwenRerankUsage `json:"usage"`
}

// qwenRerankResult contains one request-relative result.
// qwenRerankResult 包含一个请求内相对结果。
type qwenRerankResult struct {
	// Index identifies the original candidate position.
	// Index 标识原始候选项位置。
	Index int `json:"index"`
	// RelevanceScore is the unmodified provider score.
	// RelevanceScore 是未经修改的供应商分数。
	RelevanceScore float64 `json:"relevance_score"`
}

// qwenRerankUsage contains the sole documented usage field.
// qwenRerankUsage 包含唯一文档化的用量字段。
type qwenRerankUsage struct {
	// TotalTokens is the provider-reported request total.
	// TotalTokens 是供应商报告的请求总 Token。
	TotalTokens int64 `json:"total_tokens"`
}

// NewRerankActionDriver creates one Alibaba qwen3-rerank driver.
// NewRerankActionDriver 创建一个 Alibaba qwen3-rerank Driver。
func NewRerankActionDriver(definitionID string, client *transport.Client) (*RerankActionDriver, error) {
	if strings.TrimSpace(definitionID) == "" || client == nil {
		return nil, ErrInvalidRerankDriver
	}
	return &RerankActionDriver{definitionID: definitionID, client: client}, nil
}

// ProviderDefinitionID returns the sole provider definition owned by this driver.
// ProviderDefinitionID 返回此 Driver 拥有的唯一供应商 Definition。
func (d *RerankActionDriver) ProviderDefinitionID() string {
	if d == nil {
		return ""
	}
	return d.definitionID
}

// ActionBindingID returns the exact qwen3-rerank action binding.
// ActionBindingID 返回精确的 qwen3-rerank 动作绑定。
func (d *RerankActionDriver) ActionBindingID() string {
	return RerankActionBindingID
}

// Execute projects one text-only VCP rerank operation and preserves provider order and scores.
// Execute 投影一次纯文本 VCP 重排操作，并保留供应商顺序与分数。
func (d *RerankActionDriver) Execute(ctx context.Context, execution provider.ExecutionRequest) (provider.ExecutionResult, error) {
	if d == nil || d.client == nil || execution.Binding.Target.ProviderDefinitionID != d.definitionID {
		return provider.ExecutionResult{}, ErrInvalidRerankDriver
	}
	action, errAction := execution.ValidateForAction(RerankActionBindingID, providerconfig.AuthMethodAPIKey)
	if errAction != nil {
		return provider.ExecutionResult{}, errAction
	}
	if action.Operation != vcp.OperationRerankDocuments || execution.Execution.Stream || execution.Execution.Payload.RerankDocuments == nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: rerank action must be non-streaming", ErrInvalidRerankDriver)
	}
	operation := *execution.Execution.Payload.RerankDocuments
	request, errProject := projectQwenRerankRequest(execution.Binding.Target.UpstreamModelID, operation)
	if errProject != nil {
		return provider.ExecutionResult{}, errProject
	}
	encoded, errEncode := json.Marshal(request)
	if errEncode != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: encode request: %v", ErrInvalidRerankDriver, errEncode)
	}
	response, errRequest := d.client.Do(ctx, transport.Request{Binding: execution.Binding, Method: http.MethodPost, Path: rerankEndpointPath, Body: encoded, Headers: []transport.Header{{Name: "Content-Type", Value: "application/json"}}, Authentication: transport.Authentication{Mode: transport.AuthenticationBearer}, IdempotencyKey: execution.Execution.IdempotencyKey})
	if errRequest != nil {
		return provider.ExecutionResult{}, errRequest
	}
	defer func() { _ = transport.DrainAndClose(response) }()
	bounded, errBound := transport.NewBoundedResponseReader(response.Body, transport.MaximumNonStreamingResponseBytes)
	if errBound != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: bound response: %v", ErrInvalidRerankResponse, errBound)
	}
	decoder := json.NewDecoder(bounded)
	decoder.DisallowUnknownFields()
	var upstream qwenRerankResponse
	if errDecode := decoder.Decode(&upstream); errDecode != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: decode response: %v", ErrInvalidRerankResponse, errDecode)
	}
	if errTrailing := decoder.Decode(&struct{}{}); !errors.Is(errTrailing, io.EOF) {
		return provider.ExecutionResult{}, fmt.Errorf("%w: trailing response data", ErrInvalidRerankResponse)
	}
	return decodeQwenRerankResponse(execution.Binding.Target.UpstreamModelID, operation, upstream)
}

// projectQwenRerankRequest maps only the official text contract and requires explicit provider truncation semantics.
// projectQwenRerankRequest 仅映射官方纯文本合同，并要求显式使用供应商截断语义。
func projectQwenRerankRequest(model string, operation vcp.RerankOperation) (qwenRerankRequest, error) {
	if strings.TrimSpace(model) != "qwen3-rerank" || operation.Truncation != vcp.RerankTruncationProvider || operation.Query.Content.Text == nil {
		return qwenRerankRequest{}, fmt.Errorf("%w: qwen3-rerank requires text and provider truncation", ErrInvalidRerankDriver)
	}
	request := qwenRerankRequest{Model: model, Query: *operation.Query.Content.Text, Documents: make([]string, len(operation.Candidates)), TopN: operation.TopN}
	for index, candidate := range operation.Candidates {
		if candidate.Content.Text == nil {
			return qwenRerankRequest{}, fmt.Errorf("%w: qwen3-rerank accepts text candidates only", ErrInvalidRerankDriver)
		}
		request.Documents[index] = *candidate.Content.Text
	}
	return request, nil
}

// decodeQwenRerankResponse maps provider-ranked results without score normalization or content trust.
// decodeQwenRerankResponse 映射供应商排序结果，且不归一化分数或信任上游内容。
func decodeQwenRerankResponse(model string, operation vcp.RerankOperation, response qwenRerankResponse) (provider.ExecutionResult, error) {
	if response.Object != "list" || response.Model != model || strings.TrimSpace(response.ID) == "" || len(response.Results) == 0 {
		return provider.ExecutionResult{}, ErrInvalidRerankResponse
	}
	results := make([]vcp.RerankResult, len(response.Results))
	for rank, item := range response.Results {
		if item.Index < 0 || item.Index >= len(operation.Candidates) || math.IsNaN(item.RelevanceScore) || math.IsInf(item.RelevanceScore, 0) || item.RelevanceScore < 0 || item.RelevanceScore > 1 {
			return provider.ExecutionResult{}, ErrInvalidRerankResponse
		}
		candidate := operation.Candidates[item.Index]
		result := vcp.RerankResult{CandidateID: candidate.ID, OriginalIndex: item.Index, Rank: rank + 1, ProviderScore: item.RelevanceScore, ScoreSemantics: rerankScoreSemantics}
		if operation.ReturnContent {
			content := candidate.Content
			result.Content = &content
		}
		results[rank] = result
	}
	if errValidate := operation.ValidateResults(results); errValidate != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: %v", ErrInvalidRerankResponse, errValidate)
	}
	return provider.ExecutionResult{Rerank: results, UpstreamResponseID: response.ID}, nil
}
