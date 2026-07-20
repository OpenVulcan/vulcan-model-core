package google

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
	// ErrInvalidEmbeddingDriver reports an incomplete Gemini embedding driver.
	// ErrInvalidEmbeddingDriver 表示不完整的 Gemini Embedding Driver。
	ErrInvalidEmbeddingDriver = errors.New("invalid Gemini embedding driver")
	// ErrUnsupportedEmbeddingInput reports input outside the evidence-closed Gemini Profile.
	// ErrUnsupportedEmbeddingInput 表示输入超出证据封闭的 Gemini Profile。
	ErrUnsupportedEmbeddingInput = errors.New("unsupported Gemini embedding input")
	// ErrInvalidEmbeddingResponse reports malformed Gemini embedding output.
	// ErrInvalidEmbeddingResponse 表示格式错误的 Gemini Embedding 输出。
	ErrInvalidEmbeddingResponse = errors.New("invalid Gemini embedding response")
)

const (
	// EmbeddingActionBindingID identifies Google AI Studio batch embedding.
	// EmbeddingActionBindingID 标识 Google AI Studio 批量 Embedding。
	EmbeddingActionBindingID = "action_google_aistudio_embedding_create"
	// EmbeddingProtocolProfileID identifies the Gemini batchEmbedContents wire contract.
	// EmbeddingProtocolProfileID 标识 Gemini batchEmbedContents 线路合同。
	EmbeddingProtocolProfileID = "google.aistudio.embeddings.v1beta"
)

// EmbeddingActionDriver executes Gemini batchEmbedContents for one AI Studio definition.
// EmbeddingActionDriver 为一个 AI Studio Definition 执行 Gemini batchEmbedContents。
type EmbeddingActionDriver struct {
	// definitionID is the sole owning provider definition.
	// definitionID 是唯一拥有的供应商 Definition。
	definitionID string
	// client owns API-key-authenticated target transport.
	// client 负责使用 API Key 认证的 Target 传输。
	client *transport.Client
}

// NewEmbeddingDriver creates an immutable Google AI Studio embedding driver.
// NewEmbeddingDriver 创建不可变的 Google AI Studio Embedding Driver。
func NewEmbeddingDriver(definitionID string, client *transport.Client) (*EmbeddingActionDriver, error) {
	if strings.TrimSpace(definitionID) == "" || client == nil {
		return nil, ErrInvalidEmbeddingDriver
	}
	return &EmbeddingActionDriver{definitionID: definitionID, client: client}, nil
}

// ProviderDefinitionID returns the sole definition owned by this driver.
// ProviderDefinitionID 返回此 Driver 唯一拥有的 Definition。
func (d *EmbeddingActionDriver) ProviderDefinitionID() string {
	if d == nil {
		return ""
	}
	return d.definitionID
}

// ActionBindingID returns the exact AI Studio embedding action.
// ActionBindingID 返回精确的 AI Studio Embedding 动作。
func (d *EmbeddingActionDriver) ActionBindingID() string {
	return EmbeddingActionBindingID
}

// geminiBatchEmbeddingRequest contains independent requests whose output order is provider-guaranteed.
// geminiBatchEmbeddingRequest 包含输出顺序由供应商保证的独立请求。
type geminiBatchEmbeddingRequest struct {
	// Requests preserves VCP input order.
	// Requests 保留 VCP 输入顺序。
	Requests []geminiEmbeddingRequest `json:"requests"`
}

// geminiEmbeddingRequest is the closed text-only EmbedContentRequest subset.
// geminiEmbeddingRequest 是封闭的纯文本 EmbedContentRequest 子集。
type geminiEmbeddingRequest struct {
	// Model repeats the exact path model as required by batchEmbedContents.
	// Model 按 batchEmbedContents 要求重复精确路径模型。
	Model string `json:"model"`
	// Content contains one independent text part.
	// Content 包含一个独立文本 Part。
	Content geminiEmbeddingContent `json:"content"`
	// Config disables silent truncation and carries an optional exact dimension.
	// Config 禁止静默截断并携带可选精确维度。
	Config geminiEmbeddingConfig `json:"embedContentConfig"`
}

// geminiEmbeddingContent contains one ordered Part list.
// geminiEmbeddingContent 包含一个有序 Part 列表。
type geminiEmbeddingContent struct {
	// Parts contains the exact content to embed.
	// Parts 包含待向量化的精确内容。
	Parts []geminiEmbeddingPart `json:"parts"`
}

// geminiEmbeddingPart contains one text input without hidden prompt rewriting.
// geminiEmbeddingPart 包含一个不进行隐藏提示改写的文本输入。
type geminiEmbeddingPart struct {
	// Text is the caller-provided text.
	// Text 是调用方提供的文本。
	Text string `json:"text"`
}

// geminiEmbeddingConfig owns only documented non-transforming controls.
// geminiEmbeddingConfig 仅拥有文档记录且不转换语义的控制项。
type geminiEmbeddingConfig struct {
	// AutoTruncate is always false because Router never permits silent truncation.
	// AutoTruncate 始终为 false，因为 Router 从不允许静默截断。
	AutoTruncate bool `json:"autoTruncate"`
	// OutputDimensionality requests a selected Profile-supported output size.
	// OutputDimensionality 请求所选 Profile 支持的输出维度。
	OutputDimensionality *int `json:"outputDimensionality,omitempty"`
}

// geminiBatchEmbeddingResponse contains embeddings in the documented request order.
// geminiBatchEmbeddingResponse 包含按文档保证的请求顺序返回的 Embedding。
type geminiBatchEmbeddingResponse struct {
	// Embeddings is one dense vector per request.
	// Embeddings 是每个请求对应的一个 Dense 向量。
	Embeddings []geminiContentEmbedding `json:"embeddings"`
}

// geminiContentEmbedding contains Gemini numeric coordinates.
// geminiContentEmbedding 包含 Gemini 数值坐标。
type geminiContentEmbedding struct {
	// Values contains dense coordinates.
	// Values 包含 Dense 坐标。
	Values []float64 `json:"values"`
}

// Execute projects an ordered text batch, explicitly disables truncation, and validates dimensions.
// Execute 投影有序文本批次、显式禁止截断并校验维度。
func (d *EmbeddingActionDriver) Execute(ctx context.Context, execution provider.ExecutionRequest) (provider.ExecutionResult, error) {
	if d == nil || d.client == nil {
		return provider.ExecutionResult{}, ErrInvalidEmbeddingDriver
	}
	action, errAction := execution.ValidateForAction(EmbeddingActionBindingID, providerconfig.AuthMethodAPIKey)
	if errAction != nil {
		return provider.ExecutionResult{}, errAction
	}
	if action.Operation != vcp.OperationEmbeddingCreate || execution.Execution.Stream {
		return provider.ExecutionResult{}, fmt.Errorf("%w: Gemini embedding is synchronous only", ErrUnsupportedEmbeddingInput)
	}
	operation := *execution.Execution.Payload.EmbeddingCreate
	request, modelName, errProject := projectGeminiEmbeddingRequest(execution.Binding.Target.UpstreamModelID, operation)
	if errProject != nil {
		return provider.ExecutionResult{}, errProject
	}
	encoded, errMarshal := json.Marshal(request)
	if errMarshal != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: encode request: %v", ErrInvalidEmbeddingDriver, errMarshal)
	}
	path := "/v1beta/models/" + url.PathEscape(modelName) + ":batchEmbedContents"
	upstream, errRequest := d.client.Do(ctx, transport.Request{
		Binding: execution.Binding, Method: http.MethodPost, Path: path, Body: encoded,
		Headers: []transport.Header{{Name: "Content-Type", Value: "application/json"}}, Authentication: transport.Authentication{Mode: transport.AuthenticationHeader, HeaderName: "X-Goog-Api-Key"},
		IdempotencyKey: execution.Execution.IdempotencyKey,
	})
	if errRequest != nil {
		return provider.ExecutionResult{}, errRequest
	}
	defer func() { _ = transport.DrainAndClose(upstream) }()
	reader, errBound := transport.NewBoundedResponseReader(upstream.Body, transport.MaximumNonStreamingResponseBytes)
	if errBound != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: bound response: %v", ErrInvalidEmbeddingResponse, errBound)
	}
	var response geminiBatchEmbeddingResponse
	decoder := json.NewDecoder(reader)
	if errDecode := decoder.Decode(&response); errDecode != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: decode response: %v", ErrInvalidEmbeddingResponse, errDecode)
	}
	if errTrailing := rejectGeminiEmbeddingTrailingJSON(decoder); errTrailing != nil {
		return provider.ExecutionResult{}, errTrailing
	}
	return mapGeminiEmbeddingResponse(operation, response)
}

// projectGeminiEmbeddingRequest maps provider-default dense float text inputs without implicit task prompts.
// projectGeminiEmbeddingRequest 映射不含隐式任务提示的供应商默认 Dense Float 文本输入。
func projectGeminiEmbeddingRequest(upstreamModelID string, operation vcp.EmbeddingOperation) (geminiBatchEmbeddingRequest, string, error) {
	modelName, errModel := aiStudioModelName(upstreamModelID)
	if errModel != nil {
		return geminiBatchEmbeddingRequest{}, "", errModel
	}
	if operation.InputTask != vcp.EmbeddingTaskProviderDefault || operation.OutputKind != vcp.EmbeddingVectorDense || operation.Encoding != vcp.EmbeddingEncodingFloat {
		return geminiBatchEmbeddingRequest{}, "", fmt.Errorf("%w: only provider-default dense float output is supported", ErrUnsupportedEmbeddingInput)
	}
	request := geminiBatchEmbeddingRequest{Requests: make([]geminiEmbeddingRequest, len(operation.Inputs))}
	for index, input := range operation.Inputs {
		if input.Text == nil || input.Resource != nil {
			return geminiBatchEmbeddingRequest{}, "", fmt.Errorf("%w: initial Gemini Profile accepts text inputs only", ErrUnsupportedEmbeddingInput)
		}
		request.Requests[index] = geminiEmbeddingRequest{
			Model: "models/" + modelName, Content: geminiEmbeddingContent{Parts: []geminiEmbeddingPart{{Text: *input.Text}}}, Config: geminiEmbeddingConfig{AutoTruncate: false, OutputDimensionality: operation.Dimensions},
		}
	}
	return request, modelName, nil
}

// mapGeminiEmbeddingResponse preserves provider-guaranteed order and rejects missing or mismatched dimensions.
// mapGeminiEmbeddingResponse 保留供应商保证的顺序并拒绝缺失或不匹配的维度。
func mapGeminiEmbeddingResponse(operation vcp.EmbeddingOperation, response geminiBatchEmbeddingResponse) (provider.ExecutionResult, error) {
	if len(response.Embeddings) != len(operation.Inputs) {
		return provider.ExecutionResult{}, fmt.Errorf("%w: output count differs from input count", ErrInvalidEmbeddingResponse)
	}
	results := make([]vcp.EmbeddingItem, len(response.Embeddings))
	for index, embedding := range response.Embeddings {
		if len(embedding.Values) == 0 || (operation.Dimensions != nil && len(embedding.Values) != *operation.Dimensions) {
			return provider.ExecutionResult{}, fmt.Errorf("%w: output dimensions differ from request", ErrInvalidEmbeddingResponse)
		}
		results[index] = vcp.EmbeddingItem{InputID: operation.Inputs[index].ID, Kind: vcp.EmbeddingVectorDense, Encoding: vcp.EmbeddingEncodingFloat, Dense: &vcp.DenseEmbedding{Values: append([]float64(nil), embedding.Values...), Dimensions: len(embedding.Values)}}
		if errValidate := results[index].Validate(); errValidate != nil {
			return provider.ExecutionResult{}, fmt.Errorf("%w: %v", ErrInvalidEmbeddingResponse, errValidate)
		}
	}
	return provider.ExecutionResult{Embeddings: results}, nil
}

// rejectGeminiEmbeddingTrailingJSON rejects a second JSON document after the typed response.
// rejectGeminiEmbeddingTrailingJSON 拒绝类型化响应后的第二个 JSON 文档。
func rejectGeminiEmbeddingTrailingJSON(decoder *json.Decoder) error {
	var trailing json.RawMessage
	if errDecode := decoder.Decode(&trailing); !errors.Is(errDecode, io.EOF) {
		if errDecode == nil {
			return fmt.Errorf("%w: trailing JSON document", ErrInvalidEmbeddingResponse)
		}
		return fmt.Errorf("%w: trailing response data: %v", ErrInvalidEmbeddingResponse, errDecode)
	}
	return nil
}
