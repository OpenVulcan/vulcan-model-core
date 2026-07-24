package alibaba

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
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
	// WanImageGenerateActionBindingID identifies the synchronous Wan 2.7 image generation action.
	// WanImageGenerateActionBindingID 标识同步 Wan 2.7 图片生成动作。
	WanImageGenerateActionBindingID = "action_alibaba_wan_image_generate"
	// WanImageEditActionBindingID identifies the synchronous Wan 2.7 image editing action.
	// WanImageEditActionBindingID 标识同步 Wan 2.7 图片编辑动作。
	WanImageEditActionBindingID = "action_alibaba_wan_image_edit"
	// WanImageGenerateProtocolProfileID identifies the closed Wan 2.7 generation profile.
	// WanImageGenerateProtocolProfileID 标识封闭的 Wan 2.7 生成 Profile。
	WanImageGenerateProtocolProfileID = "alibaba.wan-image.generate.v1"
	// WanImageEditProtocolProfileID identifies the closed Wan 2.7 editing profile.
	// WanImageEditProtocolProfileID 标识封闭的 Wan 2.7 编辑 Profile。
	WanImageEditProtocolProfileID = "alibaba.wan-image.edit.v1"
	// maximumWanImageInputBytes is the documented per-image input ceiling.
	// maximumWanImageInputBytes 是文档规定的单张输入图片上限。
	maximumWanImageInputBytes = 20 << 20
)

var (
	// ErrInvalidWanImageDriver reports an incomplete or unsupported Wan image request.
	// ErrInvalidWanImageDriver 表示不完整或不受支持的 Wan 图片请求。
	ErrInvalidWanImageDriver = errors.New("invalid Alibaba Wan image driver")
)

// WanImageActionDriver executes one synchronous Wan 2.7 action for one immutable Alibaba product definition.
// WanImageActionDriver 为一个不可变 Alibaba 产品 Definition 执行一个同步 Wan 2.7 动作。
type WanImageActionDriver struct {
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

// NewWanImageActionDriver creates one synchronous Wan 2.7 generation or edit driver.
// NewWanImageActionDriver 创建一个同步 Wan 2.7 生成或编辑 Driver。
func NewWanImageActionDriver(definitionID string, actionBindingID string, client *transport.Client) (*WanImageActionDriver, error) {
	if strings.TrimSpace(definitionID) == "" || client == nil || (actionBindingID != WanImageGenerateActionBindingID && actionBindingID != WanImageEditActionBindingID) {
		return nil, ErrInvalidWanImageDriver
	}
	return &WanImageActionDriver{definitionID: definitionID, actionBindingID: actionBindingID, client: client}, nil
}

// ProviderDefinitionID returns the sole provider definition owned by this driver.
// ProviderDefinitionID 返回此 Driver 拥有的唯一供应商 Definition。
func (d *WanImageActionDriver) ProviderDefinitionID() string {
	if d == nil {
		return ""
	}
	return d.definitionID
}

// ActionBindingID returns the sole action binding owned by this driver.
// ActionBindingID 返回此 Driver 拥有的唯一动作绑定。
func (d *WanImageActionDriver) ActionBindingID() string {
	if d == nil {
		return ""
	}
	return d.actionBindingID
}

// Execute projects and executes one official synchronous Wan 2.7 image request.
// Execute 投影并执行一个官方同步 Wan 2.7 图片请求。
func (d *WanImageActionDriver) Execute(ctx context.Context, execution provider.ExecutionRequest) (provider.ExecutionResult, error) {
	if d == nil || d.client == nil {
		return provider.ExecutionResult{}, ErrInvalidWanImageDriver
	}
	if execution.Binding.Target.ProviderDefinitionID != d.definitionID {
		return provider.ExecutionResult{}, fmt.Errorf("%w: target definition does not belong to this driver", provider.ErrExecutionBinding)
	}
	if _, errValidate := execution.ValidateForAction(d.actionBindingID, providerconfig.AuthMethodAPIKey); errValidate != nil {
		return provider.ExecutionResult{}, errValidate
	}
	outbound, errProject := projectWanImageRequest(execution, d.actionBindingID)
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

// wanImageRequest is the official synchronous Wan 2.7 multimodal generation request.
// wanImageRequest 是官方同步 Wan 2.7 多模态生成请求。
type wanImageRequest struct {
	// Model is the exact resolved Wan image model.
	// Model 是精确解析的 Wan 图片模型。
	Model string `json:"model"`
	// Input contains the required single user message.
	// Input 包含必需的单条用户消息。
	Input wanImageInput `json:"input"`
	// Parameters contains only documented controls represented by VCP.
	// Parameters 仅包含 VCP 可表示且文档明确的控制项。
	Parameters wanImageParameters `json:"parameters,omitempty"`
}

// wanImageInput contains exactly one synchronous Wan message.
// wanImageInput 包含恰好一条同步 Wan 消息。
type wanImageInput struct {
	// Messages contains the single user message required by the endpoint.
	// Messages 包含端点要求的单条用户消息。
	Messages []wanImageMessage `json:"messages"`
}

// wanImageMessage contains ordered images followed by one text instruction.
// wanImageMessage 包含有序图片及其后的一条文本指令。
type wanImageMessage struct {
	// Role is fixed to user by the official single-turn contract.
	// Role 由官方单轮合同固定为 user。
	Role string `json:"role"`
	// Content preserves exact source ordering and one prompt.
	// Content 保留精确来源顺序及一条提示词。
	Content []wanImageContent `json:"content"`
}

// wanImageContent is an exact-one-of image source or text instruction.
// wanImageContent 是图片来源或文本指令的精确单选结构。
type wanImageContent struct {
	// Image contains a public URL or inline Base64 data URL.
	// Image 包含公网 URL 或内联 Base64 Data URL。
	Image string `json:"image,omitempty"`
	// Text contains the sole generation or editing instruction.
	// Text 包含唯一的生成或编辑指令。
	Text string `json:"text,omitempty"`
}

// wanImageParameters contains the closed Wan controls represented by VCP.
// wanImageParameters 包含 VCP 可表示的封闭 Wan 控制项。
type wanImageParameters struct {
	// NegativePrompt describes content excluded from the generated image.
	// NegativePrompt 描述生成图片中需要排除的内容。
	NegativePrompt string `json:"negative_prompt,omitempty"`
	// Size selects one documented resolution tier.
	// Size 选择一个文档明确的分辨率档位。
	Size string `json:"size,omitempty"`
	// Count requests between one and four images.
	// Count 请求一至四张图片。
	Count int `json:"n,omitempty"`
	// Seed requests provider-relative deterministic output.
	// Seed 请求供应商相对确定性输出。
	Seed *int64 `json:"seed,omitempty"`
	// PromptExtend controls provider-native prompt rewriting.
	// PromptExtend 控制供应商原生提示词改写。
	PromptExtend *bool `json:"prompt_extend,omitempty"`
	// Watermark controls the provider-generated watermark.
	// Watermark 控制供应商生成的水印。
	Watermark *bool `json:"watermark,omitempty"`
}

// projectWanImageRequest maps one closed VCP image payload to the synchronous Wan endpoint.
// projectWanImageRequest 将一个封闭 VCP 图片载荷映射到同步 Wan 端点。
func projectWanImageRequest(execution provider.ExecutionRequest, actionBindingID string) (transport.Request, error) {
	contents := make([]wanImageContent, 0, 10)
	parameters := wanImageParameters{}
	switch actionBindingID {
	case WanImageGenerateActionBindingID:
		operation := execution.Execution.Payload.ImageGenerate
		if operation == nil || len(operation.References) > 9 {
			return transport.Request{}, fmt.Errorf("%w: generation accepts at most nine ordered reference images", ErrInvalidWanImageDriver)
		}
		if operation.Width != 0 || operation.Height != 0 || operation.AspectRatio != "" || operation.Quality != "" || operation.Background != "" || operation.SafetyPolicy != "" {
			return transport.Request{}, fmt.Errorf("%w: dimensions, aspect_ratio, quality, background, and safety_policy have no configured Wan 2.7 carrier", ErrInvalidWanImageDriver)
		}
		if errParameters := validateWanImageParameters(execution.Binding.Target.UpstreamModelID, operation.Prompt, operation.Count, operation.Resolution, operation.OutputFormat, operation.Seed, len(operation.References) != 0); errParameters != nil {
			return transport.Request{}, errParameters
		}
		materialized, errMaterialized := wanImageContents(operation.References, execution.MaterializedInputs, vcp.MediaRoleReference)
		if errMaterialized != nil {
			return transport.Request{}, errMaterialized
		}
		contents = append(contents, materialized...)
		contents = append(contents, wanImageContent{Text: operation.Prompt})
		parameters = wanImageParameters{NegativePrompt: operation.NegativePrompt, Size: wanResolution(operation.Resolution), Count: operation.Count, Seed: operation.Seed, PromptExtend: operation.PromptExtend, Watermark: operation.Watermark}
	case WanImageEditActionBindingID:
		operation := execution.Execution.Payload.ImageEdit
		if operation == nil || len(operation.Sources) < 1 || len(operation.Sources) > 9 {
			return transport.Request{}, fmt.Errorf("%w: image editing requires one to nine sources", ErrInvalidWanImageDriver)
		}
		if operation.Width != 0 || operation.Height != 0 || operation.AspectRatio != "" || operation.Quality != "" {
			return transport.Request{}, fmt.Errorf("%w: edit dimensions, aspect_ratio, and quality have no configured Wan 2.7 carrier", ErrInvalidWanImageDriver)
		}
		if errParameters := validateWanImageParameters(execution.Binding.Target.UpstreamModelID, operation.Instruction, operation.Count, operation.Resolution, operation.OutputFormat, operation.Seed, true); errParameters != nil {
			return transport.Request{}, errParameters
		}
		materialized, errMaterialized := wanImageContents(operation.Sources, execution.MaterializedInputs, vcp.MediaRoleEditSource)
		if errMaterialized != nil {
			return transport.Request{}, errMaterialized
		}
		contents = append(contents, materialized...)
		contents = append(contents, wanImageContent{Text: operation.Instruction})
		parameters = wanImageParameters{NegativePrompt: operation.NegativePrompt, Size: wanResolution(operation.Resolution), Count: operation.Count, Seed: operation.Seed, PromptExtend: operation.PromptExtend, Watermark: operation.Watermark}
	default:
		return transport.Request{}, ErrInvalidWanImageDriver
	}
	body := wanImageRequest{Model: execution.Binding.Target.UpstreamModelID, Input: wanImageInput{Messages: []wanImageMessage{{Role: "user", Content: contents}}}, Parameters: parameters}
	encoded, errEncode := json.Marshal(body)
	if errEncode != nil {
		return transport.Request{}, fmt.Errorf("%w: encode request: %v", ErrInvalidWanImageDriver, errEncode)
	}
	return transport.Request{Binding: execution.Binding, Method: http.MethodPost, Path: "/api/v1/services/aigc/multimodal-generation/generation", Body: encoded, Headers: alibabaJSONHeaders(execution.MaterializedInputs, false), Authentication: transport.Authentication{Mode: transport.AuthenticationBearer}, IdempotencyKey: execution.Execution.IdempotencyKey}, nil
}

// validateWanImageParameters enforces the synchronous Wan 2.7 subset published by the catalog.
// validateWanImageParameters 强制执行目录发布的同步 Wan 2.7 子集。
func validateWanImageParameters(model string, prompt string, count int, resolution string, format string, seed *int64, hasImageInput bool) error {
	if model != "wan2.7-image" && model != "wan2.7-image-pro" {
		return fmt.Errorf("%w: unsupported Wan image model %q", ErrInvalidWanImageDriver, model)
	}
	if utf8.RuneCountInString(prompt) > 5000 {
		return fmt.Errorf("%w: prompt exceeds 5000 characters", ErrInvalidWanImageDriver)
	}
	if count < 0 || count > 4 {
		return fmt.Errorf("%w: image count must be between one and four when supplied", ErrInvalidWanImageDriver)
	}
	normalizedResolution := strings.ToLower(strings.TrimSpace(resolution))
	if normalizedResolution != "" && normalizedResolution != "1k" && normalizedResolution != "2k" && normalizedResolution != "4k" {
		return fmt.Errorf("%w: resolution must be 1k, 2k, or 4k", ErrInvalidWanImageDriver)
	}
	if normalizedResolution == "4k" && (model != "wan2.7-image-pro" || hasImageInput) {
		return fmt.Errorf("%w: 4k is limited to wan2.7-image-pro text-to-image generation", ErrInvalidWanImageDriver)
	}
	if normalizedFormat := strings.ToLower(strings.TrimSpace(format)); normalizedFormat != "" && normalizedFormat != "png" {
		return fmt.Errorf("%w: Wan 2.7 output format is fixed to png", ErrInvalidWanImageDriver)
	}
	if seed != nil && (*seed < 0 || *seed > 2147483647) {
		return fmt.Errorf("%w: seed must be between 0 and 2147483647", ErrInvalidWanImageDriver)
	}
	return nil
}

// wanResolution converts one canonical VCP resolution tier to the case-sensitive wire value.
// wanResolution 将一个规范 VCP 分辨率档位转换为区分大小写的 Wire 值。
func wanResolution(resolution string) string {
	switch strings.ToLower(strings.TrimSpace(resolution)) {
	case "1k":
		return "1K"
	case "2k":
		return "2K"
	case "4k":
		return "4K"
	default:
		return ""
	}
}

// wanImageContents resolves ordered VCP image inputs to exact materialized wire values.
// wanImageContents 将有序 VCP 图片输入解析为精确物化 Wire 值。
func wanImageContents(inputs []vcp.MediaInput, materializedInputs []resource.MaterializedInput, requiredRole vcp.MediaInputRole) ([]wanImageContent, error) {
	materializedByID := make(map[string]resource.MaterializedInput, len(materializedInputs))
	for _, input := range materializedInputs {
		materializedByID[input.InputID] = input
	}
	contents := make([]wanImageContent, 0, len(inputs))
	for _, source := range inputs {
		if source.Role != requiredRole {
			return nil, fmt.Errorf("%w: image input role must be %s", ErrInvalidWanImageDriver, requiredRole)
		}
		input, exists := materializedByID[source.ID]
		if !exists || input.ResourceID != source.Resource.ResourceID || input.Kind != vcp.MediaImage || input.Role != source.Role {
			return nil, fmt.Errorf("%w: image input %q has no exact materialization", ErrInvalidWanImageDriver, source.ID)
		}
		image, errImage := wanImageMaterialization(input)
		if errImage != nil {
			return nil, errImage
		}
		contents = append(contents, wanImageContent{Image: image})
	}
	return contents, nil
}

// wanImageMaterialization converts one planned image representation to the documented wire value.
// wanImageMaterialization 将一个规划图片表示转换为文档明确的 Wire 值。
func wanImageMaterialization(input resource.MaterializedInput) (string, error) {
	switch input.Mode {
	case catalog.MaterializationInlineBase64:
		if !supportedWanImageMIMEType(input.MIMEType) {
			return "", fmt.Errorf("%w: image input MIME type %q is unsupported", ErrInvalidWanImageDriver, input.MIMEType)
		}
		decoded, errDecode := base64.StdEncoding.DecodeString(input.InlineBase64)
		if errDecode != nil || len(decoded) == 0 || len(decoded) > maximumWanImageInputBytes {
			return "", fmt.Errorf("%w: inline image must contain at most 20 MB of valid Base64 data", ErrInvalidWanImageDriver)
		}
		return "data:" + input.MIMEType + ";base64," + input.InlineBase64, nil
	case catalog.MaterializationDirectRemoteURL:
		parsedURL, errParse := url.ParseRequestURI(input.RemoteURL)
		if errParse != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || parsedURL.Host == "" || parsedURL.User != nil {
			return "", fmt.Errorf("%w: direct image URL is invalid", ErrInvalidWanImageDriver)
		}
		return input.RemoteURL, nil
	case catalog.MaterializationProviderObjectURI:
		return alibabaObjectURI(input, ErrInvalidWanImageDriver)
	default:
		return "", fmt.Errorf("%w: Wan accepts inline Base64, direct remote URL, or Alibaba object URI inputs only", ErrInvalidWanImageDriver)
	}
}

// supportedWanImageMIMEType reports whether Wan 2.7 documents one image format.
// supportedWanImageMIMEType 报告 Wan 2.7 是否记录了指定图片格式。
func supportedWanImageMIMEType(mimeType string) bool {
	switch strings.ToLower(strings.TrimSpace(mimeType)) {
	case "image/jpeg", "image/png", "image/bmp", "image/webp":
		return true
	default:
		return false
	}
}
