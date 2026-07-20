package google

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

const (
	// ImageGenerateActionBindingID identifies the Gemini Interactions image generation action.
	// ImageGenerateActionBindingID 标识 Gemini Interactions 图片生成动作。
	ImageGenerateActionBindingID = "action_google_interactions_image_generate"
	// ImageEditActionBindingID identifies the Gemini Interactions image editing action.
	// ImageEditActionBindingID 标识 Gemini Interactions 图片编辑动作。
	ImageEditActionBindingID = "action_google_interactions_image_edit"
	// ImageGenerateProtocolProfileID identifies the current Gemini Interactions image generation contract.
	// ImageGenerateProtocolProfileID 标识当前 Gemini Interactions 图片生成合同。
	ImageGenerateProtocolProfileID = "google.interactions.image.generate.v1beta"
	// ImageEditProtocolProfileID identifies the current Gemini Interactions image editing contract.
	// ImageEditProtocolProfileID 标识当前 Gemini Interactions 图片编辑合同。
	ImageEditProtocolProfileID = "google.interactions.image.edit.v1beta"
)

var (
	// ErrInvalidInteractionsImageDriver reports an incomplete or unsupported Gemini image request.
	// ErrInvalidInteractionsImageDriver 表示不完整或不受支持的 Gemini 图片请求。
	ErrInvalidInteractionsImageDriver = errors.New("invalid Google Interactions image driver")
	// ErrInvalidInteractionsImageResponse reports a malformed Gemini image response.
	// ErrInvalidInteractionsImageResponse 表示格式错误的 Gemini 图片响应。
	ErrInvalidInteractionsImageResponse = errors.New("invalid Google Interactions image response")
)

// InteractionsImageActionDriver executes one image action for one immutable Google Interactions definition.
// InteractionsImageActionDriver 为一个不可变 Google Interactions Definition 执行一个图片动作。
type InteractionsImageActionDriver struct {
	// definitionID is the sole provider definition permitted to use this driver.
	// definitionID 是允许使用此 Driver 的唯一供应商 Definition。
	definitionID string
	// actionBindingID is the exact generation or edit action owned by this driver.
	// actionBindingID 是此 Driver 拥有的精确生成或编辑动作。
	actionBindingID string
	// client owns provider-scoped authenticated HTTP execution.
	// client 负责供应商作用域的认证 HTTP 执行。
	client *transport.Client
}

// NewInteractionsImageActionDriver creates one Google Interactions image action driver.
// NewInteractionsImageActionDriver 创建一个 Google Interactions 图片动作 Driver。
func NewInteractionsImageActionDriver(definitionID string, actionBindingID string, client *transport.Client) (*InteractionsImageActionDriver, error) {
	if strings.TrimSpace(definitionID) == "" || client == nil || (actionBindingID != ImageGenerateActionBindingID && actionBindingID != ImageEditActionBindingID) {
		return nil, ErrInvalidInteractionsImageDriver
	}
	return &InteractionsImageActionDriver{definitionID: definitionID, actionBindingID: actionBindingID, client: client}, nil
}

// ProviderDefinitionID returns the sole provider definition owned by this driver.
// ProviderDefinitionID 返回此 Driver 拥有的唯一供应商 Definition。
func (d *InteractionsImageActionDriver) ProviderDefinitionID() string {
	if d == nil {
		return ""
	}
	return d.definitionID
}

// ActionBindingID returns the sole action binding owned by this driver.
// ActionBindingID 返回此 Driver 拥有的唯一动作绑定。
func (d *InteractionsImageActionDriver) ActionBindingID() string {
	if d == nil {
		return ""
	}
	return d.actionBindingID
}

// Execute projects and executes one official Gemini Interactions image request.
// Execute 投影并执行一个官方 Gemini Interactions 图片请求。
func (d *InteractionsImageActionDriver) Execute(ctx context.Context, execution provider.ExecutionRequest) (provider.ExecutionResult, error) {
	if d == nil || d.client == nil {
		return provider.ExecutionResult{}, ErrInvalidInteractionsImageDriver
	}
	if execution.Binding.Target.ProviderDefinitionID != d.definitionID {
		return provider.ExecutionResult{}, fmt.Errorf("%w: target definition does not belong to this driver", provider.ErrExecutionBinding)
	}
	if _, errValidate := execution.ValidateForAction(d.actionBindingID, providerconfig.AuthMethodAPIKey, providerconfig.AuthMethodHeaderKey); errValidate != nil {
		return provider.ExecutionResult{}, errValidate
	}
	outbound, errProject := projectInteractionsImageRequest(execution, d.actionBindingID)
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
		return provider.ExecutionResult{}, fmt.Errorf("%w: bound response: %v", ErrInvalidInteractionsImageResponse, errBound)
	}
	return decodeInteractionsImageResponse(bounded)
}

// interactionsImageRequest is the current polymorphic Interactions image request.
// interactionsImageRequest 是当前多态 Interactions 图片请求。
type interactionsImageRequest struct {
	// Model is the exact resolved Gemini image model.
	// Model 是精确解析的 Gemini 图片模型。
	Model string `json:"model"`
	// Input contains text and optional ordered image inputs.
	// Input 包含文本及可选的有序图片输入。
	Input []interactionsImageContent `json:"input"`
	// ResponseFormat requests image-only output with directly represented controls.
	// ResponseFormat 请求仅图片输出并携带可直接表示的控制项。
	ResponseFormat interactionsImageResponseFormat `json:"response_format"`
}

// interactionsImageContent is one typed text or image content block.
// interactionsImageContent 是一个类型化文本或图片内容块。
type interactionsImageContent struct {
	// Type discriminates text from image content.
	// Type 区分文本与图片内容。
	Type string `json:"type"`
	// Text contains one prompt or edit instruction.
	// Text 包含一条提示词或编辑指令。
	Text string `json:"text,omitempty"`
	// Data contains raw Base64 image bytes without a data-URL prefix.
	// Data 包含不带 Data URL 前缀的原始 Base64 图片字节。
	Data string `json:"data,omitempty"`
	// MIMEType declares the exact image media type.
	// MIMEType 声明精确图片媒体类型。
	MIMEType string `json:"mime_type,omitempty"`
	// URI references one directly accessible image.
	// URI 引用一张可直接访问的图片。
	URI string `json:"uri,omitempty"`
}

// interactionsImageResponseFormat contains current image output controls.
// interactionsImageResponseFormat 包含当前图片输出控制项。
type interactionsImageResponseFormat struct {
	// Type is fixed to image.
	// Type 固定为 image。
	Type string `json:"type"`
	// MIMEType requests PNG or JPEG output.
	// MIMEType 请求 PNG 或 JPEG 输出。
	MIMEType string `json:"mime_type,omitempty"`
	// AspectRatio requests one documented Gemini image ratio.
	// AspectRatio 请求一个文档明确的 Gemini 图片长宽比。
	AspectRatio string `json:"aspect_ratio,omitempty"`
	// ImageSize requests one documented Gemini resolution tier.
	// ImageSize 请求一个文档明确的 Gemini 分辨率档位。
	ImageSize string `json:"image_size,omitempty"`
}

// projectInteractionsImageRequest maps one closed VCP image action to the current Interactions API.
// projectInteractionsImageRequest 将一个封闭 VCP 图片动作映射到当前 Interactions API。
func projectInteractionsImageRequest(execution provider.ExecutionRequest, actionBindingID string) (transport.Request, error) {
	input := make([]interactionsImageContent, 0, 15)
	format := interactionsImageResponseFormat{Type: "image"}
	switch actionBindingID {
	case ImageGenerateActionBindingID:
		operation := execution.Execution.Payload.ImageGenerate
		if operation == nil || len(operation.References) != 0 || operation.NegativePrompt != "" || operation.Seed != nil || operation.Width != 0 || operation.Height != 0 || operation.Quality != "" || operation.Background != "" || operation.SafetyPolicy != "" {
			return transport.Request{}, fmt.Errorf("%w: references, negative_prompt, seed, width, height, quality, background, and safety_policy have no exact Interactions image-generation carrier", ErrInvalidInteractionsImageDriver)
		}
		if operation.Count < 0 || operation.Count > 1 {
			return transport.Request{}, fmt.Errorf("%w: Gemini Interactions does not guarantee multiple image outputs", ErrInvalidInteractionsImageDriver)
		}
		input = append(input, interactionsImageContent{Type: "text", Text: operation.Prompt})
		format.AspectRatio = operation.AspectRatio
		format.ImageSize = interactionsImageResolution(operation.Resolution)
		format.MIMEType = interactionsImageOutputMIMEType(operation.OutputFormat)
	case ImageEditActionBindingID:
		operation := execution.Execution.Payload.ImageEdit
		if operation == nil || len(operation.Sources) < 1 || len(operation.Sources) > 14 {
			return transport.Request{}, fmt.Errorf("%w: Gemini image editing requires one to fourteen sources", ErrInvalidInteractionsImageDriver)
		}
		if operation.Count < 0 || operation.Count > 1 {
			return transport.Request{}, fmt.Errorf("%w: Gemini Interactions does not guarantee multiple image outputs", ErrInvalidInteractionsImageDriver)
		}
		if operation.Width != 0 || operation.Height != 0 || operation.Quality != "" {
			return transport.Request{}, fmt.Errorf("%w: edit width, height, and quality have no exact Interactions carrier", ErrInvalidInteractionsImageDriver)
		}
		input = append(input, interactionsImageContent{Type: "text", Text: operation.Instruction})
		materializedByID := make(map[string]resource.MaterializedInput, len(execution.MaterializedInputs))
		for _, materialized := range execution.MaterializedInputs {
			materializedByID[materialized.InputID] = materialized
		}
		for _, source := range operation.Sources {
			if source.Role != vcp.MediaRoleEditSource {
				return transport.Request{}, fmt.Errorf("%w: Gemini image editing accepts edit_source inputs only", ErrInvalidInteractionsImageDriver)
			}
			materialized, exists := materializedByID[source.ID]
			if !exists || materialized.ResourceID != source.Resource.ResourceID || materialized.Kind != vcp.MediaImage || materialized.Role != source.Role {
				return transport.Request{}, fmt.Errorf("%w: image edit input %q has no exact materialization", ErrInvalidInteractionsImageDriver, source.ID)
			}
			content, errContent := interactionsImageMaterialization(materialized)
			if errContent != nil {
				return transport.Request{}, errContent
			}
			input = append(input, content)
		}
		format.MIMEType = interactionsImageOutputMIMEType(operation.OutputFormat)
		format.AspectRatio = operation.AspectRatio
		format.ImageSize = interactionsImageResolution(operation.Resolution)
	default:
		return transport.Request{}, ErrInvalidInteractionsImageDriver
	}
	if format.MIMEType == "invalid" || format.ImageSize == "invalid" || !supportedInteractionsImageAspectRatio(format.AspectRatio) {
		return transport.Request{}, fmt.Errorf("%w: unsupported image output format or aspect ratio", ErrInvalidInteractionsImageDriver)
	}
	body := interactionsImageRequest{Model: execution.Binding.Target.UpstreamModelID, Input: input, ResponseFormat: format}
	encoded, errEncode := json.Marshal(body)
	if errEncode != nil {
		return transport.Request{}, fmt.Errorf("%w: encode request: %v", ErrInvalidInteractionsImageDriver, errEncode)
	}
	return transport.Request{Binding: execution.Binding, Method: http.MethodPost, Path: "/v1beta/interactions", Body: encoded, Headers: []transport.Header{{Name: "Content-Type", Value: "application/json"}}, Authentication: transport.Authentication{Mode: transport.AuthenticationHeader, HeaderName: "X-Goog-Api-Key"}, IdempotencyKey: execution.Execution.IdempotencyKey}, nil
}

// interactionsImageResolution converts one VCP resolution tier to the case-sensitive provider value.
// interactionsImageResolution 将一个 VCP 分辨率档位转换为区分大小写的供应商值。
func interactionsImageResolution(resolution string) string {
	switch strings.ToLower(strings.TrimSpace(resolution)) {
	case "":
		return ""
	case "512", "0.5k":
		return "512"
	case "1k":
		return "1K"
	case "2k":
		return "2K"
	case "4k":
		return "4K"
	default:
		return "invalid"
	}
}

// interactionsImageOutputMIMEType converts the closed VCP format to the official MIME value.
// interactionsImageOutputMIMEType 将封闭 VCP 格式转换为官方 MIME 值。
func interactionsImageOutputMIMEType(format string) string {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "":
		return ""
	case "png":
		return "image/png"
	case "jpg", "jpeg":
		return "image/jpeg"
	default:
		return "invalid"
	}
}

// supportedInteractionsImageAspectRatio reports whether one ratio is documented for Gemini 3.1 Flash Image.
// supportedInteractionsImageAspectRatio 报告某长宽比是否由 Gemini 3.1 Flash Image 文档明确支持。
func supportedInteractionsImageAspectRatio(aspectRatio string) bool {
	switch strings.TrimSpace(aspectRatio) {
	case "", "1:1", "1:4", "1:8", "2:3", "3:2", "3:4", "4:1", "4:3", "4:5", "5:4", "8:1", "9:16", "16:9", "21:9":
		return true
	default:
		return false
	}
}

// interactionsImageMaterialization projects one planned inline or direct-URI image.
// interactionsImageMaterialization 投影一个已规划的内联或直接 URI 图片。
func interactionsImageMaterialization(input resource.MaterializedInput) (interactionsImageContent, error) {
	if !supportedInteractionsImageMIMEType(input.MIMEType) {
		return interactionsImageContent{}, fmt.Errorf("%w: image input MIME type %q is unsupported", ErrInvalidInteractionsImageDriver, input.MIMEType)
	}
	switch input.Mode {
	case catalog.MaterializationInlineBase64:
		decoded, errDecode := base64.StdEncoding.DecodeString(input.InlineBase64)
		if errDecode != nil || len(decoded) == 0 {
			return interactionsImageContent{}, fmt.Errorf("%w: inline image must contain valid Base64 data", ErrInvalidInteractionsImageDriver)
		}
		return interactionsImageContent{Type: "image", Data: input.InlineBase64, MIMEType: input.MIMEType}, nil
	case catalog.MaterializationDirectRemoteURL:
		parsed, errParse := url.ParseRequestURI(input.RemoteURL)
		if errParse != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil {
			return interactionsImageContent{}, fmt.Errorf("%w: direct image URI is invalid", ErrInvalidInteractionsImageDriver)
		}
		return interactionsImageContent{Type: "image", MIMEType: input.MIMEType, URI: input.RemoteURL}, nil
	default:
		return interactionsImageContent{}, fmt.Errorf("%w: Interactions accepts inline Base64 or direct URI image inputs only", ErrInvalidInteractionsImageDriver)
	}
}

// supportedInteractionsImageMIMEType reports whether ImageContent documents one MIME type.
// supportedInteractionsImageMIMEType 报告 ImageContent 是否记录了指定 MIME 类型。
func supportedInteractionsImageMIMEType(mimeType string) bool {
	switch strings.ToLower(strings.TrimSpace(mimeType)) {
	case "image/png", "image/jpeg", "image/webp", "image/gif":
		return true
	default:
		return false
	}
}

// interactionsImageResponse is the raw REST interaction response without SDK convenience fields.
// interactionsImageResponse 是不含 SDK 便捷字段的原始 REST Interaction 响应。
type interactionsImageResponse struct {
	// ID is the provider-issued interaction identifier.
	// ID 是供应商签发的 Interaction 标识。
	ID string `json:"id"`
	// Status is the terminal interaction state.
	// Status 是 Interaction 终态。
	Status string `json:"status"`
	// Steps contains ordered user, tool, and model steps.
	// Steps 包含有序用户、工具及模型步骤。
	Steps []interactionsImageStep `json:"steps"`
}

// interactionsImageStep contains one typed Interactions timeline step.
// interactionsImageStep 包含一个类型化 Interactions 时间线步骤。
type interactionsImageStep struct {
	// Type discriminates model output from other timeline steps.
	// Type 区分模型输出与其他时间线步骤。
	Type string `json:"type"`
	// Content contains ordered model output blocks.
	// Content 包含有序模型输出块。
	Content []interactionsImageContent `json:"content"`
}

// decodeInteractionsImageResponse extracts only raw model-output image content.
// decodeInteractionsImageResponse 仅提取原始模型输出图片内容。
func decodeInteractionsImageResponse(reader io.Reader) (provider.ExecutionResult, error) {
	var response interactionsImageResponse
	if errDecode := json.NewDecoder(reader).Decode(&response); errDecode != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: decode response: %v", ErrInvalidInteractionsImageResponse, errDecode)
	}
	if strings.TrimSpace(response.ID) == "" || (response.Status != "completed" && response.Status != "done") {
		return provider.ExecutionResult{}, fmt.Errorf("%w: interaction is not completed", ErrInvalidInteractionsImageResponse)
	}
	resources := make([]provider.GeneratedResource, 0, 1)
	for stepIndex, step := range response.Steps {
		if step.Type != "model_output" {
			continue
		}
		for contentIndex, content := range step.Content {
			if content.Type != "image" || !supportedInteractionsImageMIMEType(content.MIMEType) || (content.Data == "") == (content.URI == "") {
				continue
			}
			resourceOutput := provider.GeneratedResource{OutputID: fmt.Sprintf("image-%d-%d", stepIndex, contentIndex), Kind: vcp.MediaImage, MIMEType: content.MIMEType}
			if content.Data != "" {
				decoded, errDecode := base64.StdEncoding.DecodeString(content.Data)
				if errDecode != nil || len(decoded) == 0 {
					return provider.ExecutionResult{}, fmt.Errorf("%w: generated image contains invalid Base64 data", ErrInvalidInteractionsImageResponse)
				}
				resourceOutput.Data = decoded
			} else {
				parsed, errParse := url.ParseRequestURI(content.URI)
				if errParse != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil {
					return provider.ExecutionResult{}, fmt.Errorf("%w: generated image URI is invalid", ErrInvalidInteractionsImageResponse)
				}
				resourceOutput.DownloadURL = content.URI
			}
			resources = append(resources, resourceOutput)
		}
	}
	if len(resources) == 0 {
		return provider.ExecutionResult{}, fmt.Errorf("%w: response contains no generated image", ErrInvalidInteractionsImageResponse)
	}
	return provider.ExecutionResult{UpstreamResponseID: response.ID, GeneratedResources: resources}, nil
}
