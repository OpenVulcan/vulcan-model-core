package alibaba

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

const (
	// ImageGenerateActionBindingID identifies the synchronous Qwen image generation action.
	// ImageGenerateActionBindingID 标识同步 Qwen 图片生成动作。
	ImageGenerateActionBindingID = "action_alibaba_qwen_image_generate"
	// ImageEditActionBindingID identifies the synchronous Qwen image editing action.
	// ImageEditActionBindingID 标识同步 Qwen 图片编辑动作。
	ImageEditActionBindingID = "action_alibaba_qwen_image_edit"
	// ImageGenerateProtocolProfileID identifies the closed Qwen image generation profile.
	// ImageGenerateProtocolProfileID 标识封闭的 Qwen 图片生成 Profile。
	ImageGenerateProtocolProfileID = "alibaba.qwen-image.generate.v1"
	// ImageEditProtocolProfileID identifies the closed Qwen image editing profile.
	// ImageEditProtocolProfileID 标识封闭的 Qwen 图片编辑 Profile。
	ImageEditProtocolProfileID = "alibaba.qwen-image.edit.v1"
	// maximumQwenImageInputBytes is the documented per-image edit input ceiling.
	// maximumQwenImageInputBytes 是文档规定的单张编辑输入图片上限。
	maximumQwenImageInputBytes = 10 << 20
)

var (
	// ErrInvalidImageDriver reports an incomplete or unsupported Qwen image request.
	// ErrInvalidImageDriver 表示不完整或不受支持的 Qwen 图片请求。
	ErrInvalidImageDriver = errors.New("invalid Alibaba Qwen image driver")
	// ErrInvalidImageResponse reports a malformed Qwen image response.
	// ErrInvalidImageResponse 表示格式错误的 Qwen 图片响应。
	ErrInvalidImageResponse = errors.New("invalid Alibaba Qwen image response")
)

// ImageActionDriver executes one synchronous Qwen image action for one immutable provider definition.
// ImageActionDriver 为一个不可变供应商 Definition 执行一个同步 Qwen 图片动作。
type ImageActionDriver struct {
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

// NewImageActionDriver creates one Alibaba Qwen image generation or edit driver.
// NewImageActionDriver 创建一个 Alibaba Qwen 图片生成或编辑 Driver。
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

// Execute projects and executes one official synchronous Qwen image request.
// Execute 投影并执行一个官方同步 Qwen 图片请求。
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
	outbound, errProject := projectQwenImageRequest(execution, d.actionBindingID)
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
	return decodeQwenImageResponse(bounded)
}

// qwenImageRequest is the official synchronous MultiModalConversation image request.
// qwenImageRequest 是官方同步 MultiModalConversation 图片请求。
type qwenImageRequest struct {
	// Model is the exact resolved Qwen image model.
	// Model 是精确解析的 Qwen 图片模型。
	Model string `json:"model"`
	// Input contains the required single user message.
	// Input 包含必需的单条用户消息。
	Input qwenImageInput `json:"input"`
	// Parameters contains only documented generation controls represented by VCP.
	// Parameters 仅包含 VCP 可表示且文档明确的生成控制项。
	Parameters qwenImageParameters `json:"parameters,omitempty"`
}

// qwenImageInput contains exactly one synchronous image message.
// qwenImageInput 包含恰好一条同步图片消息。
type qwenImageInput struct {
	// Messages contains the single user message required by the endpoint.
	// Messages 包含端点要求的单条用户消息。
	Messages []qwenImageMessage `json:"messages"`
}

// qwenImageMessage contains ordered image sources followed by one text instruction.
// qwenImageMessage 包含有序图片来源及其后的一条文本指令。
type qwenImageMessage struct {
	// Role is fixed to user by the official single-turn contract.
	// Role 由官方单轮合同固定为 user。
	Role string `json:"role"`
	// Content preserves exact source ordering and one text prompt.
	// Content 保留精确来源顺序及一条文本提示。
	Content []qwenImageContent `json:"content"`
}

// qwenImageContent is an exact-one-of image source or text instruction.
// qwenImageContent 是图片来源或文本指令的精确单选结构。
type qwenImageContent struct {
	// Image contains a public URL or an inline Base64 data URL.
	// Image 包含公网 URL 或内联 Base64 Data URL。
	Image string `json:"image,omitempty"`
	// Text contains the sole generation or editing instruction.
	// Text 包含唯一的生成或编辑指令。
	Text string `json:"text,omitempty"`
}

// qwenImageParameters contains documented Qwen Image 2.0 controls.
// qwenImageParameters 包含文档明确的 Qwen Image 2.0 控制项。
type qwenImageParameters struct {
	// NegativePrompt describes excluded content.
	// NegativePrompt 描述需要排除的内容。
	NegativePrompt string `json:"negative_prompt,omitempty"`
	// Size contains width and height in the provider's width*height form.
	// Size 使用供应商的 width*height 形式包含宽高。
	Size string `json:"size,omitempty"`
	// Count requests between one and six images.
	// Count 请求一至六张图片。
	Count int `json:"n,omitempty"`
	// Seed requests provider-relative deterministic output.
	// Seed 请求供应商相对确定性输出。
	Seed *int64 `json:"seed,omitempty"`
}

// projectQwenImageRequest maps one closed VCP image payload to the official synchronous endpoint.
// projectQwenImageRequest 将一个封闭 VCP 图片载荷映射到官方同步端点。
func projectQwenImageRequest(execution provider.ExecutionRequest, actionBindingID string) (transport.Request, error) {
	contents := make([]qwenImageContent, 0, 4)
	parameters := qwenImageParameters{}
	switch actionBindingID {
	case ImageGenerateActionBindingID:
		operation := execution.Execution.Payload.ImageGenerate
		if operation == nil || len(operation.References) != 0 || operation.AspectRatio != "" || operation.Resolution != "" || operation.Quality != "" || operation.Background != "" || operation.SafetyPolicy != "" {
			return transport.Request{}, fmt.Errorf("%w: generation references, aspect_ratio, resolution, quality, background, and safety_policy have no Qwen Image carrier", ErrInvalidImageDriver)
		}
		if errParameters := validateQwenImageParameters(operation.Count, operation.Width, operation.Height, operation.OutputFormat, operation.NegativePrompt, operation.Seed); errParameters != nil {
			return transport.Request{}, errParameters
		}
		contents = append(contents, qwenImageContent{Text: operation.Prompt})
		parameters = qwenImageParameters{NegativePrompt: operation.NegativePrompt, Count: operation.Count, Seed: operation.Seed}
		if operation.Width != 0 {
			parameters.Size = strconv.Itoa(operation.Width) + "*" + strconv.Itoa(operation.Height)
		}
	case ImageEditActionBindingID:
		operation := execution.Execution.Payload.ImageEdit
		if operation == nil || len(operation.Sources) < 1 || len(operation.Sources) > 3 {
			return transport.Request{}, fmt.Errorf("%w: image editing requires one to three sources", ErrInvalidImageDriver)
		}
		if operation.Width != 0 || operation.Height != 0 || operation.AspectRatio != "" || operation.Resolution != "" || operation.Quality != "" {
			return transport.Request{}, fmt.Errorf("%w: edit width, height, aspect_ratio, resolution, and quality have no Qwen Image carrier", ErrInvalidImageDriver)
		}
		if errParameters := validateQwenImageParameters(operation.Count, 0, 0, operation.OutputFormat, "", nil); errParameters != nil {
			return transport.Request{}, errParameters
		}
		materializedByID := make(map[string]resource.MaterializedInput, len(execution.MaterializedInputs))
		for _, input := range execution.MaterializedInputs {
			materializedByID[input.InputID] = input
		}
		for _, source := range operation.Sources {
			if source.Role != vcp.MediaRoleEditSource {
				return transport.Request{}, fmt.Errorf("%w: Qwen Image editing accepts edit_source inputs only", ErrInvalidImageDriver)
			}
			input, exists := materializedByID[source.ID]
			if !exists || input.ResourceID != source.Resource.ResourceID || input.Kind != vcp.MediaImage || input.Role != source.Role {
				return transport.Request{}, fmt.Errorf("%w: image edit input %q has no exact materialization", ErrInvalidImageDriver, source.ID)
			}
			image, errImage := qwenImageMaterialization(input)
			if errImage != nil {
				return transport.Request{}, errImage
			}
			contents = append(contents, qwenImageContent{Image: image})
		}
		contents = append(contents, qwenImageContent{Text: operation.Instruction})
		parameters.Count = operation.Count
	default:
		return transport.Request{}, ErrInvalidImageDriver
	}
	body := qwenImageRequest{Model: execution.Binding.Target.UpstreamModelID, Input: qwenImageInput{Messages: []qwenImageMessage{{Role: "user", Content: contents}}}, Parameters: parameters}
	encoded, errEncode := json.Marshal(body)
	if errEncode != nil {
		return transport.Request{}, fmt.Errorf("%w: encode request: %v", ErrInvalidImageDriver, errEncode)
	}
	return transport.Request{Binding: execution.Binding, Method: http.MethodPost, Path: "/api/v1/services/aigc/multimodal-generation/generation", Body: encoded, Headers: []transport.Header{{Name: "Content-Type", Value: "application/json"}}, Authentication: transport.Authentication{Mode: transport.AuthenticationBearer}, IdempotencyKey: execution.Execution.IdempotencyKey}, nil
}

// validateQwenImageParameters enforces only limits explicitly documented for Qwen Image 2.0.
// validateQwenImageParameters 仅强制执行 Qwen Image 2.0 文档明确的限制。
func validateQwenImageParameters(count int, width int, height int, format string, negativePrompt string, seed *int64) error {
	if count < 0 || count > 6 {
		return fmt.Errorf("%w: image count must be between one and six when supplied", ErrInvalidImageDriver)
	}
	if (width == 0) != (height == 0) {
		return fmt.Errorf("%w: width and height must be supplied together", ErrInvalidImageDriver)
	}
	if width != 0 {
		pixels := int64(width) * int64(height)
		if width < 1 || height < 1 || pixels < 512*512 || pixels > 2048*2048 {
			return fmt.Errorf("%w: image size exceeds the documented Qwen Image 2.0 pixel range", ErrInvalidImageDriver)
		}
	}
	if normalizedFormat := strings.ToLower(strings.TrimSpace(format)); normalizedFormat != "" && normalizedFormat != "png" {
		return fmt.Errorf("%w: Qwen Image output format is fixed to png", ErrInvalidImageDriver)
	}
	if utf8.RuneCountInString(negativePrompt) > 500 {
		return fmt.Errorf("%w: negative_prompt exceeds 500 characters", ErrInvalidImageDriver)
	}
	if seed != nil && (*seed < 0 || *seed > 2147483647) {
		return fmt.Errorf("%w: seed must be between 0 and 2147483647", ErrInvalidImageDriver)
	}
	return nil
}

// qwenImageMaterialization converts one exact planned image representation to the documented wire value.
// qwenImageMaterialization 将一个精确规划的图片表示转换为文档明确的 Wire 值。
func qwenImageMaterialization(input resource.MaterializedInput) (string, error) {
	switch input.Mode {
	case catalog.MaterializationInlineBase64:
		if !supportedQwenImageMIMEType(input.MIMEType) {
			return "", fmt.Errorf("%w: image input MIME type %q is unsupported", ErrInvalidImageDriver, input.MIMEType)
		}
		decoded, errDecode := base64.StdEncoding.DecodeString(input.InlineBase64)
		if errDecode != nil || len(decoded) == 0 || len(decoded) > maximumQwenImageInputBytes {
			return "", fmt.Errorf("%w: inline image must contain at most 10 MB of valid Base64 data", ErrInvalidImageDriver)
		}
		return "data:" + input.MIMEType + ";base64," + input.InlineBase64, nil
	case catalog.MaterializationDirectRemoteURL:
		parsedURL, errParse := url.ParseRequestURI(input.RemoteURL)
		if errParse != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || parsedURL.Host == "" || parsedURL.User != nil {
			return "", fmt.Errorf("%w: direct image URL is invalid", ErrInvalidImageDriver)
		}
		return input.RemoteURL, nil
	default:
		return "", fmt.Errorf("%w: Qwen Image accepts inline Base64 or direct remote URL inputs only", ErrInvalidImageDriver)
	}
}

// supportedQwenImageMIMEType reports whether the official editing endpoint documents one image format.
// supportedQwenImageMIMEType 报告官方编辑端点是否记录了指定图片格式。
func supportedQwenImageMIMEType(mimeType string) bool {
	switch strings.ToLower(strings.TrimSpace(mimeType)) {
	case "image/jpeg", "image/png", "image/bmp", "image/webp", "image/gif":
		return true
	default:
		return false
	}
}

// qwenImageResponse is the closed successful MultiModalConversation response.
// qwenImageResponse 是封闭的成功 MultiModalConversation 响应。
type qwenImageResponse struct {
	// RequestID is the provider-issued request identifier.
	// RequestID 是供应商签发的请求标识。
	RequestID string `json:"request_id"`
	// Output contains the single assistant choice.
	// Output 包含单个 Assistant Choice。
	Output qwenImageOutput `json:"output"`
}

// qwenImageOutput contains ordered synchronous choices.
// qwenImageOutput 包含有序同步 Choice。
type qwenImageOutput struct {
	// Choices contains the official response choices.
	// Choices 包含官方响应 Choice。
	Choices []qwenImageChoice `json:"choices"`
}

// qwenImageChoice contains one assistant message.
// qwenImageChoice 包含一条 Assistant 消息。
type qwenImageChoice struct {
	// Message contains ordered output image items.
	// Message 包含有序输出图片项。
	Message qwenImageResponseMessage `json:"message"`
}

// qwenImageResponseMessage contains ordered generated image URLs.
// qwenImageResponseMessage 包含有序生成图片 URL。
type qwenImageResponseMessage struct {
	// Content contains generated image URL items.
	// Content 包含生成图片 URL 项。
	Content []qwenImageResponseContent `json:"content"`
}

// qwenImageResponseContent contains one temporary generated image URL.
// qwenImageResponseContent 包含一个临时生成图片 URL。
type qwenImageResponseContent struct {
	// Image is the provider-issued temporary PNG URL.
	// Image 是供应商签发的临时 PNG URL。
	Image string `json:"image"`
}

// decodeQwenImageResponse converts temporary image URLs into private Router ingestion sources.
// decodeQwenImageResponse 将临时图片 URL 转换为私有 Router 导入来源。
func decodeQwenImageResponse(reader io.Reader) (provider.ExecutionResult, error) {
	var response qwenImageResponse
	decoder := json.NewDecoder(reader)
	if errDecode := decoder.Decode(&response); errDecode != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: decode response: %v", ErrInvalidImageResponse, errDecode)
	}
	outputs := make([]provider.GeneratedResource, 0)
	for _, choice := range response.Output.Choices {
		for _, content := range choice.Message.Content {
			parsedURL, errParse := url.ParseRequestURI(content.Image)
			if errParse != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || parsedURL.Host == "" || parsedURL.User != nil {
				return provider.ExecutionResult{}, fmt.Errorf("%w: output image URL is invalid", ErrInvalidImageResponse)
			}
			outputs = append(outputs, provider.GeneratedResource{OutputID: "image-" + strconv.Itoa(len(outputs)), Kind: vcp.MediaImage, MIMEType: "image/png", DownloadURL: content.Image})
		}
	}
	if len(outputs) == 0 {
		return provider.ExecutionResult{}, fmt.Errorf("%w: response contains no images", ErrInvalidImageResponse)
	}
	return provider.ExecutionResult{GeneratedResources: outputs, UpstreamResponseID: response.RequestID}, nil
}
