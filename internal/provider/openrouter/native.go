// Package openrouter implements OpenRouter-native typed action drivers.
// Package openrouter 实现 OpenRouter 原生类型化动作 Driver。
//
// The endpoint routing behavior is adapted from OpenVulcan/vulcan-model-router
// internal/runtime/executor/openrouter_executor.go. The original implementation forwards
// raw payloads; this adaptation preserves its proven paths and non-streaming behavior while
// enforcing the closed VCP request and result types required by this core.
// 端点路由行为改编自 OpenVulcan/vulcan-model-router 的
// internal/runtime/executor/openrouter_executor.go。原实现透传原始载荷；本适配保留其已验证路径
// 与非流式行为，同时强制执行本核心要求的封闭 VCP 请求和结果类型。
package openrouter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

var (
	// ErrInvalidDriver reports an incomplete OpenRouter native action driver.
	// ErrInvalidDriver 表示 OpenRouter 原生动作 Driver 配置不完整。
	ErrInvalidDriver = errors.New("invalid OpenRouter native action driver")
	// ErrUnsupportedInput reports a valid VCP shape that the selected OpenRouter action cannot project.
	// ErrUnsupportedInput 表示所选 OpenRouter 动作无法投影的合法 VCP 形态。
	ErrUnsupportedInput = errors.New("unsupported OpenRouter native input")
	// ErrInvalidResponse reports malformed or identity-unsafe upstream output.
	// ErrInvalidResponse 表示格式错误或身份不安全的上游输出。
	ErrInvalidResponse = errors.New("invalid OpenRouter native response")
)

const (
	// EmbeddingActionBindingID identifies OpenRouter's native embedding action.
	// EmbeddingActionBindingID 标识 OpenRouter 原生 Embedding 动作。
	EmbeddingActionBindingID = "action_openrouter_embedding_create"
	// RerankActionBindingID identifies OpenRouter's native rerank action.
	// RerankActionBindingID 标识 OpenRouter 原生 Rerank 动作。
	RerankActionBindingID = "action_openrouter_rerank_documents"
	// EmbeddingProtocolProfileID identifies the exact OpenRouter embedding wire contract.
	// EmbeddingProtocolProfileID 标识精确的 OpenRouter Embedding 线路合同。
	EmbeddingProtocolProfileID = "openrouter.embeddings.v1"
	// RerankProtocolProfileID identifies the exact OpenRouter rerank wire contract.
	// RerankProtocolProfileID 标识精确的 OpenRouter Rerank 线路合同。
	RerankProtocolProfileID = "openrouter.rerank.v1"
	// embeddingEndpointPath preserves the source project's native endpoint routing.
	// embeddingEndpointPath 保留来源项目的原生端点路由。
	embeddingEndpointPath = "/v1/embeddings"
	// rerankEndpointPath preserves the source project's native endpoint routing.
	// rerankEndpointPath 保留来源项目的原生端点路由。
	rerankEndpointPath = "/v1/rerank"
	// openRouterScoreSemantics records that scores are unmodified OpenRouter relevance_score values.
	// openRouterScoreSemantics 记录分数为未经修改的 OpenRouter relevance_score 值。
	openRouterScoreSemantics = "openrouter.relevance_score"
)

// NativeActionDriver executes exactly one OpenRouter native synchronous action.
// NativeActionDriver 仅执行一个 OpenRouter 原生同步动作。
type NativeActionDriver struct {
	// definitionID is the sole owning provider definition.
	// definitionID 是唯一拥有的供应商 Definition。
	definitionID string
	// actionBindingID is the sole owned action binding.
	// actionBindingID 是唯一拥有的动作绑定。
	actionBindingID string
	// operation is the exact VCP operation accepted by this instance.
	// operation 是此实例接受的精确 VCP 操作。
	operation vcp.OperationKind
	// client owns target-bound authenticated HTTP execution.
	// client 负责 Target 绑定且经过认证的 HTTP 执行。
	client *transport.Client
}

// NewEmbeddingDriver creates a driver bound to one definition's OpenRouter embedding action.
// NewEmbeddingDriver 创建绑定到一个 Definition 的 OpenRouter Embedding 动作 Driver。
func NewEmbeddingDriver(definitionID string, client *transport.Client) (*NativeActionDriver, error) {
	return newNativeActionDriver(definitionID, EmbeddingActionBindingID, vcp.OperationEmbeddingCreate, client)
}

// NewRerankDriver creates a driver bound to one definition's OpenRouter rerank action.
// NewRerankDriver 创建绑定到一个 Definition 的 OpenRouter Rerank 动作 Driver。
func NewRerankDriver(definitionID string, client *transport.Client) (*NativeActionDriver, error) {
	return newNativeActionDriver(definitionID, RerankActionBindingID, vcp.OperationRerankDocuments, client)
}

// newNativeActionDriver validates one exact action ownership tuple.
// newNativeActionDriver 校验一个精确动作所有权元组。
func newNativeActionDriver(definitionID string, actionBindingID string, operation vcp.OperationKind, client *transport.Client) (*NativeActionDriver, error) {
	if strings.TrimSpace(definitionID) == "" || client == nil {
		return nil, ErrInvalidDriver
	}
	return &NativeActionDriver{definitionID: definitionID, actionBindingID: actionBindingID, operation: operation, client: client}, nil
}

// ProviderDefinitionID returns the sole definition owned by this driver.
// ProviderDefinitionID 返回此 Driver 唯一拥有的 Definition。
func (d *NativeActionDriver) ProviderDefinitionID() string {
	if d == nil {
		return ""
	}
	return d.definitionID
}

// ActionBindingID returns the sole action binding owned by this driver.
// ActionBindingID 返回此 Driver 唯一拥有的动作绑定。
func (d *NativeActionDriver) ActionBindingID() string {
	if d == nil {
		return ""
	}
	return d.actionBindingID
}

// Execute validates immutable ownership, projects a closed request, and decodes typed output.
// Execute 校验不可变所有权、投影封闭请求并解码类型化输出。
func (d *NativeActionDriver) Execute(ctx context.Context, execution provider.ExecutionRequest) (provider.ExecutionResult, error) {
	if d == nil || d.client == nil {
		return provider.ExecutionResult{}, ErrInvalidDriver
	}
	action, errAction := execution.ValidateForAction(d.actionBindingID, providerconfig.AuthMethodAPIKey)
	if errAction != nil {
		return provider.ExecutionResult{}, errAction
	}
	if action.Operation != d.operation || execution.Execution.Stream {
		return provider.ExecutionResult{}, fmt.Errorf("%w: action %q is non-streaming %s", ErrUnsupportedInput, action.ID, d.operation)
	}
	switch d.operation {
	case vcp.OperationEmbeddingCreate:
		return d.executeEmbedding(ctx, execution)
	case vcp.OperationRerankDocuments:
		return d.executeRerank(ctx, execution)
	default:
		return provider.ExecutionResult{}, ErrInvalidDriver
	}
}

// openRouterEmbeddingRequest is the closed supported subset of OpenRouter's embedding request.
// openRouterEmbeddingRequest 是 OpenRouter Embedding 请求中受支持的封闭子集。
type openRouterEmbeddingRequest struct {
	// Model is the exact resolved upstream model.
	// Model 是精确解析的上游模型。
	Model string `json:"model"`
	// Input preserves VCP batch order as text strings.
	// Input 以文本字符串保留 VCP 批次顺序。
	Input []string `json:"input"`
	// Dimensions requests an exact output dimension when present.
	// Dimensions 在存在时请求精确输出维度。
	Dimensions *int `json:"dimensions,omitempty"`
	// EncodingFormat is either float or base64.
	// EncodingFormat 为 float 或 base64。
	EncodingFormat string `json:"encoding_format"`
	// InputType preserves the documented query or document semantic task.
	// InputType 保留文档记录的查询或文档语义任务。
	InputType string `json:"input_type,omitempty"`
}

// openRouterEmbeddingResponse is the typed OpenRouter embedding response subset.
// openRouterEmbeddingResponse 是类型化的 OpenRouter Embedding 响应子集。
type openRouterEmbeddingResponse struct {
	// ID is the optional upstream response identifier.
	// ID 是可选上游响应标识。
	ID string `json:"id"`
	// Model is the provider-reported model.
	// Model 是供应商报告的模型。
	Model string `json:"model"`
	// Data contains indexed vector outputs.
	// Data 包含带索引的向量输出。
	Data []openRouterEmbeddingData `json:"data"`
}

// openRouterEmbeddingData contains one indexed vector union.
// openRouterEmbeddingData 包含一个带索引的向量联合体。
type openRouterEmbeddingData struct {
	// Index maps output to the original ordered input.
	// Index 将输出映射到原始有序输入。
	Index int `json:"index"`
	// Embedding contains exactly one numeric or Base64 representation.
	// Embedding 只包含一种数值或 Base64 表示。
	Embedding openRouterEmbeddingValue `json:"embedding"`
}

// openRouterEmbeddingValue is a closed JSON union of numeric coordinates and Base64 text.
// openRouterEmbeddingValue 是数值坐标与 Base64 文本的封闭 JSON 联合体。
type openRouterEmbeddingValue struct {
	// Values contains numeric coordinates when returned.
	// Values 在返回数值表示时包含坐标。
	Values []float64
	// Base64 contains encoded coordinates when returned.
	// Base64 在返回编码表示时包含坐标。
	Base64 string
}

// UnmarshalJSON decodes exactly one documented OpenRouter embedding representation.
// UnmarshalJSON 仅解码一种文档记录的 OpenRouter Embedding 表示。
func (v *openRouterEmbeddingValue) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("%w: nil embedding value", ErrInvalidResponse)
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '"' {
		return json.Unmarshal(trimmed, &v.Base64)
	}
	return json.Unmarshal(trimmed, &v.Values)
}

// executeEmbedding projects text inputs and preserves the provider index mapping exactly.
// executeEmbedding 投影文本输入并精确保留供应商索引映射。
func (d *NativeActionDriver) executeEmbedding(ctx context.Context, execution provider.ExecutionRequest) (provider.ExecutionResult, error) {
	operation := *execution.Execution.Payload.EmbeddingCreate
	request, errProject := projectEmbeddingRequest(execution.Binding.Target.UpstreamModelID, operation)
	if errProject != nil {
		return provider.ExecutionResult{}, errProject
	}
	var response openRouterEmbeddingResponse
	if errSend := d.sendJSON(ctx, execution, embeddingEndpointPath, request, &response); errSend != nil {
		return provider.ExecutionResult{}, errSend
	}
	if response.Model != "" && response.Model != execution.Binding.Target.UpstreamModelID {
		return provider.ExecutionResult{}, fmt.Errorf("%w: embedding response model differs from immutable target", ErrInvalidResponse)
	}
	if len(response.Data) != len(operation.Inputs) {
		return provider.ExecutionResult{}, fmt.Errorf("%w: embedding output count %d differs from input count %d", ErrInvalidResponse, len(response.Data), len(operation.Inputs))
	}
	sort.Slice(response.Data, func(left int, right int) bool { return response.Data[left].Index < response.Data[right].Index })
	results := make([]vcp.EmbeddingItem, len(response.Data))
	for index, item := range response.Data {
		if item.Index != index {
			return provider.ExecutionResult{}, fmt.Errorf("%w: embedding indexes must cover the complete ordered batch", ErrInvalidResponse)
		}
		dense := &vcp.DenseEmbedding{}
		if operation.Encoding == vcp.EmbeddingEncodingBase64 {
			if operation.Dimensions == nil || item.Embedding.Base64 == "" || len(item.Embedding.Values) != 0 {
				return provider.ExecutionResult{}, fmt.Errorf("%w: Base64 embedding requires requested dimensions and encoded output", ErrInvalidResponse)
			}
			dense.Base64 = item.Embedding.Base64
			dense.Dimensions = *operation.Dimensions
		} else {
			if item.Embedding.Base64 != "" || len(item.Embedding.Values) == 0 {
				return provider.ExecutionResult{}, fmt.Errorf("%w: numeric embedding output is required", ErrInvalidResponse)
			}
			dense.Values = append([]float64(nil), item.Embedding.Values...)
			dense.Dimensions = len(dense.Values)
		}
		results[index] = vcp.EmbeddingItem{InputID: operation.Inputs[index].ID, Kind: vcp.EmbeddingVectorDense, Dense: dense, Encoding: operation.Encoding}
		if errValidate := results[index].Validate(); errValidate != nil {
			return provider.ExecutionResult{}, fmt.Errorf("%w: %v", ErrInvalidResponse, errValidate)
		}
	}
	return provider.ExecutionResult{Embeddings: results, UpstreamResponseID: response.ID}, nil
}

// projectEmbeddingRequest maps only official, model-independent OpenRouter embedding fields.
// projectEmbeddingRequest 仅映射官方且与模型无关的 OpenRouter Embedding 字段。
func projectEmbeddingRequest(model string, operation vcp.EmbeddingOperation) (openRouterEmbeddingRequest, error) {
	if operation.OutputKind != vcp.EmbeddingVectorDense {
		return openRouterEmbeddingRequest{}, fmt.Errorf("%w: OpenRouter supports dense output in this profile", ErrUnsupportedInput)
	}
	request := openRouterEmbeddingRequest{Model: model, Input: make([]string, len(operation.Inputs)), Dimensions: operation.Dimensions}
	switch operation.Encoding {
	case vcp.EmbeddingEncodingFloat:
		request.EncodingFormat = "float"
	case vcp.EmbeddingEncodingBase64:
		if operation.Dimensions == nil {
			return openRouterEmbeddingRequest{}, fmt.Errorf("%w: Base64 output requires explicit dimensions", ErrUnsupportedInput)
		}
		request.EncodingFormat = "base64"
	default:
		return openRouterEmbeddingRequest{}, fmt.Errorf("%w: embedding encoding %q", ErrUnsupportedInput, operation.Encoding)
	}
	switch operation.InputTask {
	case vcp.EmbeddingTaskProviderDefault:
	case vcp.EmbeddingTaskQuery:
		request.InputType = "search_query"
	case vcp.EmbeddingTaskDocument:
		request.InputType = "search_document"
	default:
		return openRouterEmbeddingRequest{}, fmt.Errorf("%w: embedding input task %q", ErrUnsupportedInput, operation.InputTask)
	}
	for index, input := range operation.Inputs {
		if input.Text == nil || input.Resource != nil {
			return openRouterEmbeddingRequest{}, fmt.Errorf("%w: this OpenRouter profile accepts text inputs only", ErrUnsupportedInput)
		}
		request.Input[index] = *input.Text
	}
	return request, nil
}

// openRouterRerankRequest is the closed supported subset of OpenRouter's rerank request.
// openRouterRerankRequest 是 OpenRouter Rerank 请求中受支持的封闭子集。
type openRouterRerankRequest struct {
	// Model is the exact resolved upstream model.
	// Model 是精确解析的上游模型。
	Model string `json:"model"`
	// Query is the sole text query.
	// Query 是唯一文本查询。
	Query string `json:"query"`
	// Documents preserves ordered text candidates.
	// Documents 保留有序文本候选项。
	Documents []string `json:"documents"`
	// TopN optionally bounds returned results.
	// TopN 可选地限制返回结果。
	TopN *int `json:"top_n,omitempty"`
}

// openRouterRerankResponse is the typed OpenRouter rerank response subset.
// openRouterRerankResponse 是类型化的 OpenRouter Rerank 响应子集。
type openRouterRerankResponse struct {
	// ID is the optional upstream response identifier.
	// ID 是可选上游响应标识。
	ID string `json:"id"`
	// Results are already sorted by provider relevance.
	// Results 已按供应商相关性排序。
	Results []openRouterRerankResult `json:"results"`
}

// openRouterRerankResult contains one original index and unmodified score.
// openRouterRerankResult 包含一个原始索引和未经修改的分数。
type openRouterRerankResult struct {
	// Index identifies the original request document.
	// Index 标识原始请求文档。
	Index int `json:"index"`
	// RelevanceScore is the exact provider-reported score.
	// RelevanceScore 是供应商报告的精确分数。
	RelevanceScore float64 `json:"relevance_score"`
}

// executeRerank projects text candidates and maps provider ranks without score normalization.
// executeRerank 投影文本候选项并映射供应商排序且不归一化分数。
func (d *NativeActionDriver) executeRerank(ctx context.Context, execution provider.ExecutionRequest) (provider.ExecutionResult, error) {
	operation := *execution.Execution.Payload.RerankDocuments
	request, errProject := projectRerankRequest(execution.Binding.Target.UpstreamModelID, operation)
	if errProject != nil {
		return provider.ExecutionResult{}, errProject
	}
	var response openRouterRerankResponse
	if errSend := d.sendJSON(ctx, execution, rerankEndpointPath, request, &response); errSend != nil {
		return provider.ExecutionResult{}, errSend
	}
	results := make([]vcp.RerankResult, len(response.Results))
	for index, item := range response.Results {
		if item.Index < 0 || item.Index >= len(operation.Candidates) {
			return provider.ExecutionResult{}, fmt.Errorf("%w: rerank result index %d is outside the candidate batch", ErrInvalidResponse, item.Index)
		}
		candidate := operation.Candidates[item.Index]
		result := vcp.RerankResult{CandidateID: candidate.ID, OriginalIndex: item.Index, Rank: index + 1, ProviderScore: item.RelevanceScore, ScoreSemantics: openRouterScoreSemantics}
		if operation.ReturnContent {
			content := candidate.Content
			result.Content = &content
		}
		results[index] = result
	}
	if errValidate := operation.ValidateResults(results); errValidate != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: %v", ErrInvalidResponse, errValidate)
	}
	return provider.ExecutionResult{Rerank: results, UpstreamResponseID: response.ID}, nil
}

// projectRerankRequest maps the VCP text query and candidates without truncation or multimodal guessing.
// projectRerankRequest 映射 VCP 文本查询与候选项且不猜测截断或多模态行为。
func projectRerankRequest(model string, operation vcp.RerankOperation) (openRouterRerankRequest, error) {
	if operation.Truncation != vcp.RerankTruncationNone {
		return openRouterRerankRequest{}, fmt.Errorf("%w: OpenRouter does not expose a documented rerank truncation switch", ErrUnsupportedInput)
	}
	if operation.Query.Content.Text == nil || operation.Query.Content.Resource != nil {
		return openRouterRerankRequest{}, fmt.Errorf("%w: this OpenRouter profile accepts a text query only", ErrUnsupportedInput)
	}
	request := openRouterRerankRequest{Model: model, Query: *operation.Query.Content.Text, Documents: make([]string, len(operation.Candidates)), TopN: operation.TopN}
	for index, candidate := range operation.Candidates {
		if candidate.Content.Text == nil || candidate.Content.Resource != nil {
			return openRouterRerankRequest{}, fmt.Errorf("%w: this OpenRouter profile accepts text candidates only", ErrUnsupportedInput)
		}
		request.Documents[index] = *candidate.Content.Text
	}
	return request, nil
}

// sendJSON sends one bounded non-streaming request through the immutable provider binding.
// sendJSON 通过不可变供应商绑定发送一个受限非流式请求。
func (d *NativeActionDriver) sendJSON(ctx context.Context, execution provider.ExecutionRequest, path string, requestBody any, responseBody any) error {
	body, errEncode := json.Marshal(requestBody)
	if errEncode != nil {
		return fmt.Errorf("encode OpenRouter request: %w", errEncode)
	}
	response, errDo := d.client.Do(ctx, transport.Request{Binding: execution.Binding, Method: http.MethodPost, Path: path, Body: body, Headers: []transport.Header{{Name: "Content-Type", Value: "application/json"}}, Authentication: transport.Authentication{Mode: transport.AuthenticationBearer}, IdempotencyKey: execution.Execution.IdempotencyKey})
	if errDo != nil {
		return errDo
	}
	defer response.Body.Close()
	boundedBody, errBound := transport.NewBoundedResponseReader(response.Body, transport.MaximumNonStreamingResponseBytes)
	if errBound != nil {
		return errBound
	}
	decoder := json.NewDecoder(boundedBody)
	if errDecode := decoder.Decode(responseBody); errDecode != nil {
		return fmt.Errorf("%w: decode response: %v", ErrInvalidResponse, errDecode)
	}
	if errTrailing := rejectTrailingJSON(decoder); errTrailing != nil {
		return errTrailing
	}
	return nil
}

// rejectTrailingJSON rejects a second JSON value while allowing ordinary trailing whitespace.
// rejectTrailingJSON 拒绝第二个 JSON 值，同时允许普通尾随空白。
func rejectTrailingJSON(decoder *json.Decoder) error {
	var trailing json.RawMessage
	errDecode := decoder.Decode(&trailing)
	if errors.Is(errDecode, io.EOF) {
		return nil
	}
	if errDecode != nil {
		return fmt.Errorf("%w: trailing response data: %v", ErrInvalidResponse, errDecode)
	}
	return fmt.Errorf("%w: multiple JSON response values", ErrInvalidResponse)
}

// compile-time interface assertion keeps action registration behavior explicit.
// 编译期接口断言使动作注册行为保持明确。
var _ provider.ActionExecutionDriver = (*NativeActionDriver)(nil)
