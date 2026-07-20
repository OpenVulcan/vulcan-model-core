package openai

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
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
	// ImageGenerateActionBindingID identifies the official OpenAI image generation action.
	// ImageGenerateActionBindingID 标识 OpenAI 官方图片生成动作。
	ImageGenerateActionBindingID = "action_openai_image_generate"
	// ImageEditActionBindingID identifies the official OpenAI image edit action.
	// ImageEditActionBindingID 标识 OpenAI 官方图片编辑动作。
	ImageEditActionBindingID = "action_openai_image_edit"
	// ImageGenerateProtocolProfileID identifies the closed OpenAI image-generation endpoint profile.
	// ImageGenerateProtocolProfileID 标识封闭的 OpenAI 图片生成端点 Profile。
	ImageGenerateProtocolProfileID = "openai.images.generate.v1"
	// ImageEditProtocolProfileID identifies the closed OpenAI image-edit endpoint profile.
	// ImageEditProtocolProfileID 标识封闭的 OpenAI 图片编辑端点 Profile。
	ImageEditProtocolProfileID = "openai.images.edit.v1"
	// maximumOpenAIImageInputBytes is the documented per-image edit input ceiling.
	// maximumOpenAIImageInputBytes 是文档规定的单张编辑输入图片上限。
	maximumOpenAIImageInputBytes = 50 << 20
)

var (
	// ErrInvalidImageDriver reports an incomplete OpenAI Images driver.
	// ErrInvalidImageDriver 表示 OpenAI Images Driver 配置不完整。
	ErrInvalidImageDriver = errors.New("invalid OpenAI Images driver")
	// ErrInvalidImageResponse reports a malformed or unsupported OpenAI Images response.
	// ErrInvalidImageResponse 表示 OpenAI Images 响应格式错误或不受支持。
	ErrInvalidImageResponse = errors.New("invalid OpenAI Images response")
)

// ImageActionDriver executes exactly one OpenAI image action for one immutable provider definition.
// ImageActionDriver 为一个不可变供应商 Definition 执行唯一 OpenAI 图片动作。
type ImageActionDriver struct {
	// definitionID is the sole provider definition permitted to use this driver.
	// definitionID 是允许使用此 Driver 的唯一供应商 Definition。
	definitionID string
	// actionBindingID is the exact generation or edit binding owned by this instance.
	// actionBindingID 是此实例拥有的精确生成或编辑绑定。
	actionBindingID string
	// client owns provider-scoped authenticated HTTP execution.
	// client 负责供应商作用域的认证 HTTP 执行。
	client *transport.Client
}

// NewImageActionDriver creates one OpenAI image generation or edit driver.
// NewImageActionDriver 创建一个 OpenAI 图片生成或编辑 Driver。
func NewImageActionDriver(definitionID string, actionBindingID string, client *transport.Client) (*ImageActionDriver, error) {
	if strings.TrimSpace(definitionID) == "" || client == nil || (actionBindingID != ImageGenerateActionBindingID && actionBindingID != ImageEditActionBindingID) {
		return nil, ErrInvalidImageDriver
	}
	return &ImageActionDriver{definitionID: definitionID, actionBindingID: actionBindingID, client: client}, nil
}

// ProviderDefinitionID returns the sole provider definition owned by this driver.
// ProviderDefinitionID 返回此 Driver 拥有的唯一供应商 Definition。
func (d *ImageActionDriver) ProviderDefinitionID() string {
	if d == nil {
		return ""
	}
	return d.definitionID
}

// ActionBindingID returns the sole action binding owned by this driver.
// ActionBindingID 返回此 Driver 拥有的唯一动作绑定。
func (d *ImageActionDriver) ActionBindingID() string {
	if d == nil {
		return ""
	}
	return d.actionBindingID
}

// Execute projects and executes one official OpenAI Images request.
// Execute 投影并执行一个 OpenAI 官方 Images 请求。
func (d *ImageActionDriver) Execute(ctx context.Context, execution provider.ExecutionRequest) (provider.ExecutionResult, error) {
	if d == nil || d.client == nil {
		return provider.ExecutionResult{}, ErrInvalidImageDriver
	}
	if execution.Binding.Target.ProviderDefinitionID != d.definitionID {
		return provider.ExecutionResult{}, fmt.Errorf("%w: target definition does not belong to this driver", provider.ErrExecutionBinding)
	}
	if _, errValidate := execution.ValidateForAction(d.actionBindingID, providerconfig.AuthMethodAPIKey); errValidate != nil {
		return provider.ExecutionResult{}, errValidate
	}
	var outbound transport.Request
	var errProject error
	switch d.actionBindingID {
	case ImageGenerateActionBindingID:
		outbound, errProject = projectImageGeneration(execution)
	case ImageEditActionBindingID:
		outbound, errProject = projectImageEdit(execution)
	}
	if errProject != nil {
		return provider.ExecutionResult{}, errProject
	}
	response, errRequest := d.client.Do(ctx, outbound)
	if errRequest != nil {
		return provider.ExecutionResult{}, errRequest
	}
	defer func() { _ = transport.DrainAndClose(response) }()
	bounded, errBound := transport.NewBoundedResponseReader(response.Body, transport.MaximumNonStreamingResponseBytes)
	if errBound != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: bound response: %v", ErrInvalidImageResponse, errBound)
	}
	return decodeImageResponse(bounded, execution.Binding.Target.UpstreamModelID, requestedImageMIMEType(execution))
}

// openAIImageRequest is the typed JSON request for image generation.
// openAIImageRequest 是图片生成的类型化 JSON 请求。
type openAIImageRequest struct {
	// Model is the exact resolved upstream image model.
	// Model 是精确解析的上游图片模型。
	Model string `json:"model"`
	// Prompt is the caller-provided image description.
	// Prompt 是调用方提供的图片描述。
	Prompt string `json:"prompt"`
	// Count is the requested number of images.
	// Count 是请求的图片数量。
	Count int `json:"n,omitempty"`
	// Size is the exact width-by-height value when requested.
	// Size 是请求时精确的宽高值。
	Size string `json:"size,omitempty"`
	// OutputFormat is a documented GPT Image output encoding.
	// OutputFormat 是已记录的 GPT Image 输出编码。
	OutputFormat string `json:"output_format,omitempty"`
	// Quality requests one documented GPT Image quality tier.
	// Quality 请求一个文档明确的 GPT Image 质量档位。
	Quality string `json:"quality,omitempty"`
	// Background requests one documented GPT Image background treatment.
	// Background 请求一个文档明确的 GPT Image 背景处理方式。
	Background string `json:"background,omitempty"`
}

// projectImageGeneration maps the closed VCP generation payload to OpenAI JSON.
// projectImageGeneration 将封闭 VCP 生成载荷映射为 OpenAI JSON。
func projectImageGeneration(execution provider.ExecutionRequest) (transport.Request, error) {
	operation := execution.Execution.Payload.ImageGenerate
	if operation == nil || execution.Binding.Target.UpstreamModelID != "gpt-image-2" || len(operation.References) != 0 || strings.TrimSpace(operation.NegativePrompt) != "" || operation.Seed != nil || operation.Resolution != "" || operation.SafetyPolicy != "" {
		return transport.Request{}, fmt.Errorf("%w: generation references, negative_prompt, seed, resolution, and safety_policy have no OpenAI Images carrier", ErrInvalidImageDriver)
	}
	if operation.Count < 0 || operation.Count > 10 {
		return transport.Request{}, fmt.Errorf("%w: image count must be between one and ten when supplied", ErrInvalidImageDriver)
	}
	format, errFormat := openAIImageFormat(operation.OutputFormat)
	if errFormat != nil {
		return transport.Request{}, errFormat
	}
	if !supportedOpenAIImageQuality(operation.Quality) || !supportedOpenAIImageBackground(operation.Background) {
		return transport.Request{}, fmt.Errorf("%w: unsupported quality or background", ErrInvalidImageDriver)
	}
	body := openAIImageRequest{Model: execution.Binding.Target.UpstreamModelID, Prompt: operation.Prompt, Count: operation.Count, OutputFormat: format, Quality: operation.Quality, Background: operation.Background}
	if operation.Width != 0 || operation.Height != 0 {
		if operation.Width == 0 || operation.Height == 0 || operation.AspectRatio != "" {
			return transport.Request{}, fmt.Errorf("%w: width and height must be supplied together without aspect_ratio", ErrInvalidImageDriver)
		}
		body.Size = strconv.Itoa(operation.Width) + "x" + strconv.Itoa(operation.Height)
		if !supportedOpenAIImageDimensions(operation.Width, operation.Height) {
			return transport.Request{}, fmt.Errorf("%w: unsupported image size %q", ErrInvalidImageDriver, body.Size)
		}
	} else if operation.AspectRatio != "" {
		return transport.Request{}, fmt.Errorf("%w: aspect_ratio has no OpenAI Images wire carrier", ErrInvalidImageDriver)
	}
	encoded, errEncode := json.Marshal(body)
	if errEncode != nil {
		return transport.Request{}, fmt.Errorf("%w: encode generation request: %v", ErrInvalidImageDriver, errEncode)
	}
	return transport.Request{Binding: execution.Binding, Method: http.MethodPost, Path: "/v1/images/generations", Body: encoded, Headers: []transport.Header{{Name: "Content-Type", Value: "application/json"}}, Authentication: transport.Authentication{Mode: transport.AuthenticationBearer}, IdempotencyKey: execution.Execution.IdempotencyKey}, nil
}

// projectImageEdit maps exact inline edit sources and mask to OpenAI multipart fields.
// projectImageEdit 将精确内联编辑来源和遮罩映射为 OpenAI Multipart 字段。
func projectImageEdit(execution provider.ExecutionRequest) (transport.Request, error) {
	operation := execution.Execution.Payload.ImageEdit
	if operation == nil || execution.Binding.Target.UpstreamModelID != "gpt-image-2" {
		return transport.Request{}, ErrInvalidImageDriver
	}
	if operation.Count < 0 || operation.Count > 10 {
		return transport.Request{}, fmt.Errorf("%w: image count must be between one and ten when supplied", ErrInvalidImageDriver)
	}
	if operation.Resolution != "" || operation.AspectRatio != "" || !supportedOpenAIImageQuality(operation.Quality) {
		return transport.Request{}, fmt.Errorf("%w: edit resolution and aspect_ratio have no carrier or quality is unsupported", ErrInvalidImageDriver)
	}
	inputs := make(map[string]resource.MaterializedInput, len(execution.MaterializedInputs))
	for _, input := range execution.MaterializedInputs {
		inputs[input.InputID] = input
	}
	firstSourceMIMEType := ""
	for _, source := range operation.Sources {
		if source.Role != vcp.MediaRoleEditSource {
			continue
		}
		input, exists := inputs[source.ID]
		if !exists || input.ResourceID != source.Resource.ResourceID || input.Kind != vcp.MediaImage || input.Role != source.Role || input.Mode != catalog.MaterializationInlineBase64 {
			return transport.Request{}, fmt.Errorf("%w: image edit input %q has no exact inline materialization", ErrInvalidImageDriver, source.ID)
		}
		firstSourceMIMEType = input.MIMEType
		break
	}
	if firstSourceMIMEType == "" {
		return transport.Request{}, fmt.Errorf("%w: image edit requires at least one edit source", ErrInvalidImageDriver)
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if errField := writer.WriteField("model", execution.Binding.Target.UpstreamModelID); errField != nil {
		return transport.Request{}, errField
	}
	if errField := writer.WriteField("prompt", operation.Instruction); errField != nil {
		return transport.Request{}, errField
	}
	if operation.Count > 0 {
		if errField := writer.WriteField("n", strconv.Itoa(operation.Count)); errField != nil {
			return transport.Request{}, errField
		}
	}
	if operation.Width != 0 || operation.Height != 0 {
		if operation.Width == 0 || operation.Height == 0 {
			return transport.Request{}, fmt.Errorf("%w: edit width and height must be supplied together", ErrInvalidImageDriver)
		}
		size := strconv.Itoa(operation.Width) + "x" + strconv.Itoa(operation.Height)
		if !supportedOpenAIImageDimensions(operation.Width, operation.Height) {
			return transport.Request{}, fmt.Errorf("%w: unsupported edit image size %q", ErrInvalidImageDriver, size)
		}
		if errField := writer.WriteField("size", size); errField != nil {
			return transport.Request{}, errField
		}
	}
	if operation.Quality != "" {
		if errField := writer.WriteField("quality", operation.Quality); errField != nil {
			return transport.Request{}, errField
		}
	}
	format, errFormat := openAIImageFormat(operation.OutputFormat)
	if errFormat != nil {
		return transport.Request{}, errFormat
	}
	if format != "" {
		if errField := writer.WriteField("output_format", format); errField != nil {
			return transport.Request{}, errField
		}
	}
	imageIndex := 0
	maskCount := 0
	for _, source := range operation.Sources {
		input, exists := inputs[source.ID]
		if !exists || input.ResourceID != source.Resource.ResourceID || input.Kind != vcp.MediaImage || input.Role != source.Role || input.Mode != catalog.MaterializationInlineBase64 {
			return transport.Request{}, fmt.Errorf("%w: image edit input %q has no exact inline materialization", ErrInvalidImageDriver, source.ID)
		}
		decoded, errDecode := base64.StdEncoding.DecodeString(input.InlineBase64)
		if errDecode != nil || len(decoded) == 0 || len(decoded) > maximumOpenAIImageInputBytes {
			return transport.Request{}, fmt.Errorf("%w: image edit input must contain at most 50 MB of valid Base64 data", ErrInvalidImageDriver)
		}
		fieldName := "image[]"
		fileName := ""
		if source.Role == vcp.MediaRoleMask {
			maskCount++
			if maskCount > 1 || !strings.EqualFold(input.MIMEType, firstSourceMIMEType) {
				return transport.Request{}, fmt.Errorf("%w: mask must use the first edit source's exact format", ErrInvalidImageDriver)
			}
			fieldName = "mask"
			fileName = "mask" + imageExtension(input.MIMEType)
		} else if source.Role == vcp.MediaRoleEditSource {
			imageIndex++
			fileName = "input-" + strconv.Itoa(imageIndex) + imageExtension(input.MIMEType)
		} else {
			return transport.Request{}, fmt.Errorf("%w: unsupported image edit role %q", ErrInvalidImageDriver, source.Role)
		}
		part, errPart := writer.CreateFormFile(fieldName, fileName)
		if errPart != nil {
			return transport.Request{}, errPart
		}
		if _, errWrite := part.Write(decoded); errWrite != nil {
			return transport.Request{}, errWrite
		}
	}
	if errClose := writer.Close(); errClose != nil {
		return transport.Request{}, errClose
	}
	return transport.Request{Binding: execution.Binding, Method: http.MethodPost, Path: "/v1/images/edits", Body: body.Bytes(), Headers: []transport.Header{{Name: "Content-Type", Value: writer.FormDataContentType()}}, Authentication: transport.Authentication{Mode: transport.AuthenticationBearer}, IdempotencyKey: execution.Execution.IdempotencyKey}, nil
}

// openAIImageResponse is the closed successful OpenAI Images response.
// openAIImageResponse 是封闭的 OpenAI Images 成功响应。
type openAIImageResponse struct {
	// Data contains ordered inline images or temporary public URLs.
	// Data 包含有序内联图片或临时公网 URL。
	Data []openAIImageData `json:"data"`
}

// openAIImageData is one exact image acquisition source.
// openAIImageData 是一个精确图片获取来源。
type openAIImageData struct {
	// Base64JSON contains complete image bytes as Base64.
	// Base64JSON 包含 Base64 编码的完整图片字节。
	Base64JSON string `json:"b64_json,omitempty"`
	// URL is a provider-issued temporary public download URL.
	// URL 是供应商签发的临时公网下载 URL。
	URL string `json:"url,omitempty"`
}

// decodeImageResponse converts every provider output into a private Router ingestion source.
// decodeImageResponse 将每个供应商输出转换为私有 Router 导入来源。
func decodeImageResponse(reader io.Reader, upstreamModelID string, mimeType string) (provider.ExecutionResult, error) {
	var response openAIImageResponse
	decoder := json.NewDecoder(reader)
	if errDecode := decoder.Decode(&response); errDecode != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: decode response: %v", ErrInvalidImageResponse, errDecode)
	}
	if len(response.Data) == 0 {
		return provider.ExecutionResult{}, fmt.Errorf("%w: response contains no images", ErrInvalidImageResponse)
	}
	outputs := make([]provider.GeneratedResource, 0, len(response.Data))
	for index, image := range response.Data {
		if (strings.TrimSpace(image.Base64JSON) == "") == (strings.TrimSpace(image.URL) == "") {
			return provider.ExecutionResult{}, fmt.Errorf("%w: image %d requires exactly one acquisition source", ErrInvalidImageResponse, index)
		}
		output := provider.GeneratedResource{OutputID: "image-" + strconv.Itoa(index), Kind: vcp.MediaImage, MIMEType: mimeType, DownloadURL: image.URL}
		if image.Base64JSON != "" {
			decoded, errDecode := base64.StdEncoding.DecodeString(image.Base64JSON)
			if errDecode != nil {
				return provider.ExecutionResult{}, fmt.Errorf("%w: decode image %d: %v", ErrInvalidImageResponse, index, errDecode)
			}
			output.Data = decoded
		}
		outputs = append(outputs, output)
	}
	return provider.ExecutionResult{GeneratedResources: outputs, UpstreamResponseID: upstreamModelID}, nil
}

// requestedImageMIMEType returns the exact output type selected by one VCP image action.
// requestedImageMIMEType 返回一个 VCP 图片动作选择的精确输出类型。
func requestedImageMIMEType(execution provider.ExecutionRequest) string {
	format := ""
	if execution.Execution.Payload.ImageGenerate != nil {
		format = execution.Execution.Payload.ImageGenerate.OutputFormat
	} else if execution.Execution.Payload.ImageEdit != nil {
		format = execution.Execution.Payload.ImageEdit.OutputFormat
	}
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "jpeg", "jpg":
		return "image/jpeg"
	case "webp":
		return "image/webp"
	default:
		return "image/png"
	}
}

// supportedOpenAIImageDimensions reports whether dimensions satisfy the current GPT Image 2 contract.
// supportedOpenAIImageDimensions 报告尺寸是否满足当前 GPT Image 2 合同。
func supportedOpenAIImageDimensions(width int, height int) bool {
	if width <= 0 || height <= 0 || width > 3840 || height > 3840 || width%16 != 0 || height%16 != 0 {
		return false
	}
	pixels := int64(width) * int64(height)
	if pixels < 655360 || pixels > 8294400 {
		return false
	}
	longEdge, shortEdge := width, height
	if longEdge < shortEdge {
		longEdge, shortEdge = shortEdge, longEdge
	}
	return longEdge <= 3*shortEdge
}

// supportedOpenAIImageQuality reports whether GPT Image documents one quality tier.
// supportedOpenAIImageQuality 报告 GPT Image 是否记录了指定质量档位。
func supportedOpenAIImageQuality(quality string) bool {
	switch strings.ToLower(strings.TrimSpace(quality)) {
	case "", "auto", "low", "medium", "high":
		return true
	default:
		return false
	}
}

// supportedOpenAIImageBackground reports whether GPT Image documents one background treatment.
// supportedOpenAIImageBackground 报告 GPT Image 是否记录了指定背景处理方式。
func supportedOpenAIImageBackground(background string) bool {
	switch strings.ToLower(strings.TrimSpace(background)) {
	case "", "auto", "opaque":
		return true
	default:
		return false
	}
}

// openAIImageFormat validates only documented GPT Image output encodings.
// openAIImageFormat 仅校验已记录的 GPT Image 输出编码。
func openAIImageFormat(format string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "png", "jpeg", "webp":
		return strings.ToLower(strings.TrimSpace(format)), nil
	default:
		return "", fmt.Errorf("%w: output format %q is unsupported", ErrInvalidImageDriver, format)
	}
}

// imageExtension returns a safe filename extension for documented OpenAI image inputs.
// imageExtension 返回已记录 OpenAI 图片输入的安全文件扩展名。
func imageExtension(mimeType string) string {
	switch strings.ToLower(strings.TrimSpace(mimeType)) {
	case "image/jpeg":
		return ".jpg"
	case "image/webp":
		return ".webp"
	default:
		return ".png"
	}
}
