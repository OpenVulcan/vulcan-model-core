package openai

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
	// ErrInvalidEmbeddingDriver reports an incomplete OpenAI-compatible embedding action driver.
	// ErrInvalidEmbeddingDriver 表示不完整的 OpenAI 兼容 Embedding 动作 Driver。
	ErrInvalidEmbeddingDriver = errors.New("invalid OpenAI-compatible embedding driver")
	// ErrUnsupportedEmbeddingInput reports a VCP input outside the exact compatible wire contract.
	// ErrUnsupportedEmbeddingInput 表示 VCP 输入超出精确兼容线路合同。
	ErrUnsupportedEmbeddingInput = errors.New("unsupported OpenAI-compatible embedding input")
	// ErrInvalidEmbeddingResponse reports malformed or target-inconsistent upstream output.
	// ErrInvalidEmbeddingResponse 表示格式错误或与 Target 不一致的上游输出。
	ErrInvalidEmbeddingResponse = errors.New("invalid OpenAI-compatible embedding response")
)

const (
	// EmbeddingActionBindingID identifies the public OpenAI embedding action.
	// EmbeddingActionBindingID 标识公开 OpenAI Embedding 动作。
	EmbeddingActionBindingID = "action_openai_embedding_create"
	// EmbeddingProtocolProfileID identifies the OpenAI embedding wire contract.
	// EmbeddingProtocolProfileID 标识 OpenAI Embedding 线路合同。
	EmbeddingProtocolProfileID = "openai.embeddings.v1"
	// embeddingEndpointPath is the official OpenAI embedding resource path.
	// embeddingEndpointPath 是 OpenAI 官方 Embedding 资源路径。
	embeddingEndpointPath = "/v1/embeddings"
)

// EmbeddingActionDriver executes one exact synchronous OpenAI-compatible embedding action.
// EmbeddingActionDriver 执行一个精确的同步 OpenAI 兼容 Embedding 动作。
type EmbeddingActionDriver struct {
	// definitionID is the sole owning provider definition.
	// definitionID 是唯一拥有的供应商 Definition。
	definitionID string
	// actionBindingID is the sole action owned by this driver.
	// actionBindingID 是此 Driver 唯一拥有的动作。
	actionBindingID string
	// endpointPath is the evidence-owned compatible embedding path.
	// endpointPath 是证据拥有的兼容 Embedding 路径。
	endpointPath string
	// client owns target-bound authenticated transport.
	// client 负责 Target 绑定且经过认证的传输。
	client *transport.Client
}

// NewEmbeddingDriver creates the public OpenAI embedding driver.
// NewEmbeddingDriver 创建公开 OpenAI Embedding Driver。
func NewEmbeddingDriver(definitionID string, client *transport.Client) (*EmbeddingActionDriver, error) {
	return NewCompatibleEmbeddingDriver(definitionID, EmbeddingActionBindingID, embeddingEndpointPath, client)
}

// NewCompatibleEmbeddingDriver creates a provider-owned driver for an officially documented OpenAI-compatible embedding endpoint.
// NewCompatibleEmbeddingDriver 为官方记录的 OpenAI 兼容 Embedding 入口创建供应商拥有的 Driver。
func NewCompatibleEmbeddingDriver(definitionID string, actionBindingID string, endpointPath string, client *transport.Client) (*EmbeddingActionDriver, error) {
	if strings.TrimSpace(definitionID) == "" || strings.TrimSpace(actionBindingID) == "" || !strings.HasPrefix(endpointPath, "/") || client == nil {
		return nil, ErrInvalidEmbeddingDriver
	}
	return &EmbeddingActionDriver{definitionID: definitionID, actionBindingID: actionBindingID, endpointPath: endpointPath, client: client}, nil
}

// ProviderDefinitionID returns the sole definition owned by this driver.
// ProviderDefinitionID 返回此 Driver 唯一拥有的 Definition。
func (d *EmbeddingActionDriver) ProviderDefinitionID() string {
	if d == nil {
		return ""
	}
	return d.definitionID
}

// ActionBindingID returns the sole action binding owned by this driver.
// ActionBindingID 返回此 Driver 唯一拥有的动作绑定。
func (d *EmbeddingActionDriver) ActionBindingID() string {
	if d == nil {
		return ""
	}
	return d.actionBindingID
}

// compatibleEmbeddingRequest is the closed supported OpenAI-compatible request subset.
// compatibleEmbeddingRequest 是受支持的封闭 OpenAI 兼容请求子集。
type compatibleEmbeddingRequest struct {
	// Model is the exact resolved upstream model.
	// Model 是精确解析的上游模型。
	Model string `json:"model"`
	// Input preserves the original text batch order.
	// Input 保留原始文本批次顺序。
	Input []string `json:"input"`
	// Dimensions requests an exact output size when the selected Profile permits it.
	// Dimensions 在所选 Profile 允许时请求精确输出维度。
	Dimensions *int `json:"dimensions,omitempty"`
	// EncodingFormat selects float or Base64 output.
	// EncodingFormat 选择 Float 或 Base64 输出。
	EncodingFormat string `json:"encoding_format"`
}

// compatibleEmbeddingResponse is the typed response subset shared by documented compatible endpoints.
// compatibleEmbeddingResponse 是文档记录的兼容入口共享的类型化响应子集。
type compatibleEmbeddingResponse struct {
	// ID is the optional provider response identifier.
	// ID 是可选供应商响应标识。
	ID string `json:"id"`
	// Model is the provider-reported model identity.
	// Model 是供应商报告的模型身份。
	Model string `json:"model"`
	// Data contains indexed embedding results.
	// Data 包含带索引的 Embedding 结果。
	Data []compatibleEmbeddingData `json:"data"`
}

// compatibleEmbeddingData contains one indexed embedding value.
// compatibleEmbeddingData 包含一个带索引的 Embedding 值。
type compatibleEmbeddingData struct {
	// Index maps the result to one original input.
	// Index 将结果映射到一个原始输入。
	Index int `json:"index"`
	// Embedding contains exactly one documented representation.
	// Embedding 仅包含一种文档记录的表示。
	Embedding compatibleEmbeddingValue `json:"embedding"`
}

// compatibleEmbeddingValue is a closed numeric-or-Base64 JSON union.
// compatibleEmbeddingValue 是封闭的数值或 Base64 JSON 联合体。
type compatibleEmbeddingValue struct {
	// Values contains numeric vector coordinates.
	// Values 包含数值向量坐标。
	Values []float64
	// Base64 contains provider-encoded vector bytes.
	// Base64 包含供应商编码的向量字节。
	Base64 string
}

// UnmarshalJSON decodes exactly one numeric-array or string representation.
// UnmarshalJSON 仅解码数值数组或字符串中的一种表示。
func (v *compatibleEmbeddingValue) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("%w: nil embedding value", ErrInvalidEmbeddingResponse)
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return fmt.Errorf("%w: empty embedding value", ErrInvalidEmbeddingResponse)
	}
	if trimmed[0] == '"' {
		return json.Unmarshal(trimmed, &v.Base64)
	}
	return json.Unmarshal(trimmed, &v.Values)
}

// Execute validates immutable action ownership, sends one typed request, and preserves batch identity.
// Execute 校验不可变动作所有权、发送类型化请求并保留批次身份。
func (d *EmbeddingActionDriver) Execute(ctx context.Context, execution provider.ExecutionRequest) (provider.ExecutionResult, error) {
	if d == nil || d.client == nil {
		return provider.ExecutionResult{}, ErrInvalidEmbeddingDriver
	}
	action, errAction := execution.ValidateForAction(d.actionBindingID, providerconfig.AuthMethodAPIKey)
	if errAction != nil {
		return provider.ExecutionResult{}, errAction
	}
	if action.Operation != vcp.OperationEmbeddingCreate || execution.Execution.Stream {
		return provider.ExecutionResult{}, fmt.Errorf("%w: embedding action is synchronous only", ErrUnsupportedEmbeddingInput)
	}
	operation := *execution.Execution.Payload.EmbeddingCreate
	request, errProject := projectCompatibleEmbeddingRequest(execution.Binding.Target.UpstreamModelID, operation)
	if errProject != nil {
		return provider.ExecutionResult{}, errProject
	}
	encoded, errMarshal := json.Marshal(request)
	if errMarshal != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: encode request: %v", ErrInvalidEmbeddingDriver, errMarshal)
	}
	upstream, errRequest := d.client.Do(ctx, transport.Request{
		Binding: execution.Binding, Method: http.MethodPost, Path: d.endpointPath, Body: encoded,
		Headers: []transport.Header{{Name: "Content-Type", Value: "application/json"}}, Authentication: transport.Authentication{Mode: transport.AuthenticationBearer},
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
	var response compatibleEmbeddingResponse
	decoder := json.NewDecoder(reader)
	if errDecode := decoder.Decode(&response); errDecode != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: decode response: %v", ErrInvalidEmbeddingResponse, errDecode)
	}
	if errTrailing := rejectCompatibleEmbeddingTrailingJSON(decoder); errTrailing != nil {
		return provider.ExecutionResult{}, errTrailing
	}
	return mapCompatibleEmbeddingResponse(execution.Binding.Target.UpstreamModelID, operation, response)
}

// projectCompatibleEmbeddingRequest maps only fields shared by the documented compatible contract.
// projectCompatibleEmbeddingRequest 仅映射文档记录的兼容合同共享字段。
func projectCompatibleEmbeddingRequest(model string, operation vcp.EmbeddingOperation) (compatibleEmbeddingRequest, error) {
	if operation.InputTask != vcp.EmbeddingTaskProviderDefault || operation.OutputKind != vcp.EmbeddingVectorDense {
		return compatibleEmbeddingRequest{}, fmt.Errorf("%w: only provider-default dense text embedding is supported", ErrUnsupportedEmbeddingInput)
	}
	request := compatibleEmbeddingRequest{Model: model, Input: make([]string, len(operation.Inputs)), Dimensions: operation.Dimensions}
	switch operation.Encoding {
	case vcp.EmbeddingEncodingFloat:
		request.EncodingFormat = "float"
	case vcp.EmbeddingEncodingBase64:
		if operation.Dimensions == nil {
			return compatibleEmbeddingRequest{}, fmt.Errorf("%w: Base64 output requires explicit dimensions", ErrUnsupportedEmbeddingInput)
		}
		request.EncodingFormat = "base64"
	default:
		return compatibleEmbeddingRequest{}, fmt.Errorf("%w: encoding %q", ErrUnsupportedEmbeddingInput, operation.Encoding)
	}
	for index, input := range operation.Inputs {
		if input.Text == nil || input.Resource != nil {
			return compatibleEmbeddingRequest{}, fmt.Errorf("%w: compatible endpoint accepts text inputs only", ErrUnsupportedEmbeddingInput)
		}
		request.Input[index] = *input.Text
	}
	return request, nil
}

// mapCompatibleEmbeddingResponse validates model identity and complete indexed batch correspondence.
// mapCompatibleEmbeddingResponse 校验模型身份与完整带索引批次对应关系。
func mapCompatibleEmbeddingResponse(model string, operation vcp.EmbeddingOperation, response compatibleEmbeddingResponse) (provider.ExecutionResult, error) {
	if response.Model != "" && response.Model != model {
		return provider.ExecutionResult{}, fmt.Errorf("%w: response model differs from immutable target", ErrInvalidEmbeddingResponse)
	}
	if len(response.Data) != len(operation.Inputs) {
		return provider.ExecutionResult{}, fmt.Errorf("%w: output count differs from input count", ErrInvalidEmbeddingResponse)
	}
	sort.Slice(response.Data, func(left int, right int) bool { return response.Data[left].Index < response.Data[right].Index })
	results := make([]vcp.EmbeddingItem, len(response.Data))
	for index, data := range response.Data {
		if data.Index != index {
			return provider.ExecutionResult{}, fmt.Errorf("%w: indexes must cover the ordered batch", ErrInvalidEmbeddingResponse)
		}
		dense := &vcp.DenseEmbedding{}
		if operation.Encoding == vcp.EmbeddingEncodingBase64 {
			if operation.Dimensions == nil || data.Embedding.Base64 == "" || len(data.Embedding.Values) != 0 {
				return provider.ExecutionResult{}, fmt.Errorf("%w: Base64 response representation is invalid", ErrInvalidEmbeddingResponse)
			}
			dense.Base64 = data.Embedding.Base64
			dense.Dimensions = *operation.Dimensions
		} else {
			if data.Embedding.Base64 != "" || len(data.Embedding.Values) == 0 {
				return provider.ExecutionResult{}, fmt.Errorf("%w: numeric response representation is invalid", ErrInvalidEmbeddingResponse)
			}
			dense.Values = append([]float64(nil), data.Embedding.Values...)
			dense.Dimensions = len(dense.Values)
		}
		results[index] = vcp.EmbeddingItem{InputID: operation.Inputs[index].ID, Kind: vcp.EmbeddingVectorDense, Encoding: operation.Encoding, Dense: dense}
		if errValidate := results[index].Validate(); errValidate != nil {
			return provider.ExecutionResult{}, fmt.Errorf("%w: %v", ErrInvalidEmbeddingResponse, errValidate)
		}
	}
	return provider.ExecutionResult{Embeddings: results, UpstreamResponseID: response.ID}, nil
}

// rejectCompatibleEmbeddingTrailingJSON rejects a second JSON document after the response object.
// rejectCompatibleEmbeddingTrailingJSON 拒绝响应对象后的第二个 JSON 文档。
func rejectCompatibleEmbeddingTrailingJSON(decoder *json.Decoder) error {
	var trailing json.RawMessage
	if errDecode := decoder.Decode(&trailing); !errors.Is(errDecode, io.EOF) {
		if errDecode == nil {
			return fmt.Errorf("%w: trailing JSON document", ErrInvalidEmbeddingResponse)
		}
		return fmt.Errorf("%w: trailing response data: %v", ErrInvalidEmbeddingResponse, errDecode)
	}
	return nil
}
