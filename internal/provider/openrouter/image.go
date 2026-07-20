package openrouter

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

const (
	// ImageGenerateActionBindingID identifies the dedicated OpenRouter Image API action.
	// ImageGenerateActionBindingID 标识 OpenRouter 专用 Image API 动作。
	ImageGenerateActionBindingID = "action_openrouter_image_generate"
	// ImageGenerateProtocolProfileID identifies the closed OpenRouter Image API wire contract.
	// ImageGenerateProtocolProfileID 标识封闭的 OpenRouter Image API 线路合同。
	ImageGenerateProtocolProfileID = "openrouter.images.v1"
)

var (
	// ErrInvalidImageDriver reports an incomplete OpenRouter image driver or unsupported request field.
	// ErrInvalidImageDriver 表示 OpenRouter 图片 Driver 不完整或请求字段不受支持。
	ErrInvalidImageDriver = errors.New("invalid OpenRouter image driver")
	// ErrInvalidImageResponse reports malformed image output.
	// ErrInvalidImageResponse 表示图片输出格式错误。
	ErrInvalidImageResponse = errors.New("invalid OpenRouter image response")
)

// ImageDriver executes the dedicated OpenRouter Image API for one immutable definition.
// ImageDriver 为一个不可变 Definition 执行 OpenRouter 专用 Image API。
type ImageDriver struct {
	// definitionID is the sole provider definition owned by this driver.
	// definitionID 是此 Driver 拥有的唯一供应商 Definition。
	definitionID string
	// client owns authenticated provider-scoped HTTP execution.
	// client 负责经过认证的供应商作用域 HTTP 执行。
	client *transport.Client
}

// NewImageDriver creates one definition-bound OpenRouter image driver.
// NewImageDriver 创建一个绑定 Definition 的 OpenRouter 图片 Driver。
func NewImageDriver(definitionID string, client *transport.Client) (*ImageDriver, error) {
	if strings.TrimSpace(definitionID) == "" || client == nil {
		return nil, ErrInvalidImageDriver
	}
	return &ImageDriver{definitionID: definitionID, client: client}, nil
}

// ProviderDefinitionID returns the sole provider definition owned by this driver.
// ProviderDefinitionID 返回此 Driver 拥有的唯一供应商 Definition。
func (d *ImageDriver) ProviderDefinitionID() string {
	if d == nil {
		return ""
	}
	return d.definitionID
}

// ActionBindingID returns the dedicated OpenRouter image action.
// ActionBindingID 返回 OpenRouter 专用图片动作。
func (d *ImageDriver) ActionBindingID() string { return ImageGenerateActionBindingID }

// openRouterImageRequest is the typed dedicated Image API request.
// openRouterImageRequest 是类型化专用 Image API 请求。
type openRouterImageRequest struct {
	// Model is the exact resolved model slug.
	// Model 是精确解析的模型 Slug。
	Model string `json:"model"`
	// Prompt describes the requested image.
	// Prompt 描述请求的图片。
	Prompt string `json:"prompt"`
	// Count requests an exact number of outputs.
	// Count 请求精确输出数量。
	Count int `json:"n,omitempty"`
	// Size is an explicit authoritative pixel size.
	// Size 是显式权威像素尺寸。
	Size string `json:"size,omitempty"`
	// AspectRatio is used only without explicit pixel size.
	// AspectRatio 仅在没有显式像素尺寸时使用。
	AspectRatio string `json:"aspect_ratio,omitempty"`
	// OutputFormat selects png, jpeg, webp, or svg.
	// OutputFormat 选择 png、jpeg、webp 或 svg。
	OutputFormat string `json:"output_format,omitempty"`
	// InputReferences contains ordered URL or Data URL references.
	// InputReferences 包含有序 URL 或 Data URL 参考图。
	InputReferences []openRouterImageReference `json:"input_references,omitempty"`
	// Provider pins one exact upstream provider and disables fallback.
	// Provider 固定唯一上游供应商并关闭回退。
	Provider openRouterImageProvider `json:"provider"`
}

// openRouterImageReference is one typed image_url input reference.
// openRouterImageReference 是一个类型化 image_url 输入参考。
type openRouterImageReference struct {
	// Type is fixed to image_url.
	// Type 固定为 image_url。
	Type string `json:"type"`
	// ImageURL contains the exact URL carrier.
	// ImageURL 包含精确 URL 载体。
	ImageURL openRouterImageURL `json:"image_url"`
}

// openRouterImageURL contains one URL or Data URL.
// openRouterImageURL 包含一个 URL 或 Data URL。
type openRouterImageURL struct {
	// URL is the accepted reference representation.
	// URL 是已接受的参考表示。
	URL string `json:"url"`
}

// openRouterImageProvider fixes OpenRouter routing to one endpoint owner.
// openRouterImageProvider 将 OpenRouter 路由固定到一个端点所有者。
type openRouterImageProvider struct {
	// Only contains the single provider slug proven for this system offering.
	// Only 包含为此系统 Offering 验证的唯一供应商 Slug。
	Only []string `json:"only"`
	// AllowFallbacks is always false to preserve immutable target semantics.
	// AllowFallbacks 始终为 false 以保留不可变 Target 语义。
	AllowFallbacks bool `json:"allow_fallbacks"`
}

// Execute sends one exact OpenRouter image request and returns only private ingestion sources.
// Execute 发送一个精确 OpenRouter 图片请求并仅返回私有导入来源。
func (d *ImageDriver) Execute(ctx context.Context, execution provider.ExecutionRequest) (provider.ExecutionResult, error) {
	if d == nil || d.client == nil || execution.Binding.Target.ProviderDefinitionID != d.definitionID {
		return provider.ExecutionResult{}, ErrInvalidImageDriver
	}
	if _, errValidate := execution.ValidateForAction(ImageGenerateActionBindingID, providerconfig.AuthMethodAPIKey); errValidate != nil {
		return provider.ExecutionResult{}, errValidate
	}
	operation := execution.Execution.Payload.ImageGenerate
	if operation == nil || operation.Seed != nil || strings.TrimSpace(operation.NegativePrompt) != "" {
		return provider.ExecutionResult{}, fmt.Errorf("%w: seed and negative_prompt are not enabled for this endpoint", ErrInvalidImageDriver)
	}
	if operation.Count < 0 || operation.Count > 10 {
		return provider.ExecutionResult{}, fmt.Errorf("%w: image count must be between one and ten when supplied", ErrInvalidImageDriver)
	}
	format := strings.ToLower(strings.TrimSpace(operation.OutputFormat))
	if format != "" && format != "png" && format != "jpeg" && format != "webp" && format != "svg" {
		return provider.ExecutionResult{}, fmt.Errorf("%w: output format %q is unsupported", ErrInvalidImageDriver, operation.OutputFormat)
	}
	body := openRouterImageRequest{Model: execution.Binding.Target.UpstreamModelID, Prompt: operation.Prompt, Count: operation.Count, AspectRatio: operation.AspectRatio, OutputFormat: format, Provider: openRouterImageProvider{Only: []string{"openai"}, AllowFallbacks: false}}
	if operation.Width != 0 || operation.Height != 0 {
		if operation.Width == 0 || operation.Height == 0 || operation.AspectRatio != "" {
			return provider.ExecutionResult{}, fmt.Errorf("%w: explicit size requires width and height without aspect_ratio", ErrInvalidImageDriver)
		}
		body.Size = strconv.Itoa(operation.Width) + "x" + strconv.Itoa(operation.Height)
	}
	materialized := make(map[string]resource.MaterializedInput, len(execution.MaterializedInputs))
	for _, input := range execution.MaterializedInputs {
		materialized[input.InputID] = input
	}
	for _, reference := range operation.References {
		input, exists := materialized[reference.ID]
		if !exists || input.ResourceID != reference.Resource.ResourceID || input.Kind != vcp.MediaImage || input.Role != reference.Role {
			return provider.ExecutionResult{}, fmt.Errorf("%w: reference %q has no exact materialization", ErrInvalidImageDriver, reference.ID)
		}
		url, errURL := openRouterReferenceURL(input)
		if errURL != nil {
			return provider.ExecutionResult{}, errURL
		}
		body.InputReferences = append(body.InputReferences, openRouterImageReference{Type: "image_url", ImageURL: openRouterImageURL{URL: url}})
	}
	encoded, errEncode := json.Marshal(body)
	if errEncode != nil {
		return provider.ExecutionResult{}, errEncode
	}
	response, errRequest := d.client.Do(ctx, transport.Request{Binding: execution.Binding, Method: http.MethodPost, Path: "/v1/images", Body: encoded, Headers: []transport.Header{{Name: "Content-Type", Value: "application/json"}}, Authentication: transport.Authentication{Mode: transport.AuthenticationBearer}, IdempotencyKey: execution.Execution.IdempotencyKey})
	if errRequest != nil {
		return provider.ExecutionResult{}, errRequest
	}
	defer func() { _ = transport.DrainAndClose(response) }()
	bounded, errBound := transport.NewBoundedResponseReader(response.Body, transport.MaximumNonStreamingResponseBytes)
	if errBound != nil {
		return provider.ExecutionResult{}, errBound
	}
	return decodeOpenRouterImages(bounded)
}

// openRouterReferenceURL maps only the two documented dedicated Image API reference carriers.
// openRouterReferenceURL 仅映射专用 Image API 已记录的两种参考载体。
func openRouterReferenceURL(input resource.MaterializedInput) (string, error) {
	switch input.Mode {
	case catalog.MaterializationInlineBase64:
		if strings.TrimSpace(input.InlineBase64) != "" {
			return "data:" + input.MIMEType + ";base64," + input.InlineBase64, nil
		}
	case catalog.MaterializationDirectRemoteURL:
		if strings.TrimSpace(input.RemoteURL) != "" {
			return input.RemoteURL, nil
		}
	}
	return "", fmt.Errorf("%w: reference materialization %q is unsupported", ErrInvalidImageDriver, input.Mode)
}

// openRouterImageResponse is the closed dedicated Image API response.
// openRouterImageResponse 是封闭的专用 Image API 响应。
type openRouterImageResponse struct {
	// Data contains ordered Base64 images.
	// Data 包含有序 Base64 图片。
	Data []openRouterImageData `json:"data"`
}

// openRouterImageData contains one Base64 image and authoritative MIME type.
// openRouterImageData 包含一张 Base64 图片与权威 MIME 类型。
type openRouterImageData struct {
	// Base64JSON contains complete encoded bytes.
	// Base64JSON 包含完整编码字节。
	Base64JSON string `json:"b64_json"`
	// MediaType contains the detected provider MIME type.
	// MediaType 包含供应商检测的 MIME 类型。
	MediaType string `json:"media_type,omitempty"`
}

// decodeOpenRouterImages converts typed Base64 images into Router ingestion sources.
// decodeOpenRouterImages 将类型化 Base64 图片转换为 Router 导入来源。
func decodeOpenRouterImages(reader io.Reader) (provider.ExecutionResult, error) {
	var response openRouterImageResponse
	if errDecode := json.NewDecoder(reader).Decode(&response); errDecode != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: %v", ErrInvalidImageResponse, errDecode)
	}
	if len(response.Data) == 0 {
		return provider.ExecutionResult{}, fmt.Errorf("%w: response contains no images", ErrInvalidImageResponse)
	}
	outputs := make([]provider.GeneratedResource, 0, len(response.Data))
	for index, item := range response.Data {
		decoded, errDecode := base64.StdEncoding.DecodeString(item.Base64JSON)
		if errDecode != nil || len(decoded) == 0 {
			return provider.ExecutionResult{}, fmt.Errorf("%w: image %d has invalid Base64", ErrInvalidImageResponse, index)
		}
		mimeType := strings.TrimSpace(item.MediaType)
		if mimeType == "" {
			mimeType = "application/octet-stream"
		}
		outputs = append(outputs, provider.GeneratedResource{OutputID: "image-" + strconv.Itoa(index), Kind: vcp.MediaImage, MIMEType: mimeType, Data: decoded})
	}
	return provider.ExecutionResult{GeneratedResources: outputs}, nil
}
