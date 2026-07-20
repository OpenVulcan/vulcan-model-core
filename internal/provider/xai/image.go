package xai

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
	// ImageGenerateActionBindingID identifies the xAI Imagine image generation action.
	// ImageGenerateActionBindingID 标识 xAI Imagine 图片生成动作。
	ImageGenerateActionBindingID = "action_xai_image_generate"
	// ImageEditActionBindingID identifies the xAI Imagine image editing action.
	// ImageEditActionBindingID 标识 xAI Imagine 图片编辑动作。
	ImageEditActionBindingID = "action_xai_image_edit"
	// ImageGenerateProtocolProfileID identifies the xAI image generation JSON contract.
	// ImageGenerateProtocolProfileID 标识 xAI 图片生成 JSON 合同。
	ImageGenerateProtocolProfileID = "xai.images.generate.v1"
	// ImageEditProtocolProfileID identifies the xAI image editing JSON contract.
	// ImageEditProtocolProfileID 标识 xAI 图片编辑 JSON 合同。
	ImageEditProtocolProfileID = "xai.images.edit.v1"
)

var (
	// ErrInvalidImageDriver reports an incomplete or unsupported xAI image request.
	// ErrInvalidImageDriver 表示不完整或不受支持的 xAI 图片请求。
	ErrInvalidImageDriver = errors.New("invalid xAI image driver")
	// ErrInvalidImageResponse reports a malformed xAI image response.
	// ErrInvalidImageResponse 表示格式错误的 xAI 图片响应。
	ErrInvalidImageResponse = errors.New("invalid xAI image response")
)

// ImageActionDriver executes one xAI Imagine image action for one immutable definition.
// ImageActionDriver 为一个不可变 Definition 执行一个 xAI Imagine 图片动作。
type ImageActionDriver struct {
	// definitionID is the sole provider definition permitted to use this driver.
	// definitionID 是允许使用此 Driver 的唯一供应商 Definition。
	definitionID string
	// actionBindingID is the exact image action owned by this driver.
	// actionBindingID 是此 Driver 拥有的精确图片动作。
	actionBindingID string
	// client owns provider-scoped authenticated HTTP execution.
	// client 负责供应商作用域的认证 HTTP 执行。
	client *transport.Client
}

// NewImageActionDriver creates one xAI image generation or edit driver.
// NewImageActionDriver 创建一个 xAI 图片生成或编辑 Driver。
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

// Execute projects and executes one official xAI Imagine image request.
// Execute 投影并执行一个官方 xAI Imagine 图片请求。
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
	outbound, errProject := projectImageRequest(execution, d.actionBindingID)
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
	return decodeImageResponse(bounded)
}

// imageRequest is the shared xAI JSON request for generation and editing.
// imageRequest 是 xAI 生成与编辑共享的 JSON 请求。
type imageRequest struct {
	// Model is the exact resolved Imagine model.
	// Model 是精确解析的 Imagine 模型。
	Model string `json:"model"`
	// Prompt contains the generation or edit instruction.
	// Prompt 包含生成或编辑指令。
	Prompt string `json:"prompt"`
	// Count requests multiple generation variations.
	// Count 请求多个生成变体。
	Count int `json:"n,omitempty"`
	// AspectRatio requests one documented output ratio.
	// AspectRatio 请求一个文档明确的输出长宽比。
	AspectRatio string `json:"aspect_ratio,omitempty"`
	// Resolution requests the 1k or 2k tier.
	// Resolution 请求 1k 或 2k 档位。
	Resolution string `json:"resolution,omitempty"`
	// ResponseFormat requests inline Base64 output for private Router import.
	// ResponseFormat 请求内联 Base64 输出以供 Router 私有导入。
	ResponseFormat string `json:"response_format"`
	// Image contains the sole source for a one-image edit.
	// Image 包含单图编辑的唯一来源。
	Image *imageSource `json:"image,omitempty"`
	// Images contains ordered sources for a multi-image edit.
	// Images 包含多图编辑的有序来源。
	Images []imageSource `json:"images,omitempty"`
}

// imageSource contains one public or inline xAI image URL.
// imageSource 包含一个公网或内联 xAI 图片 URL。
type imageSource struct {
	// Type declares an image URL carrier.
	// Type 声明图片 URL 载体。
	Type string `json:"type,omitempty"`
	// URL contains a public URL or Base64 data URI.
	// URL 包含公网 URL 或 Base64 Data URI。
	URL string `json:"url"`
}

// projectImageRequest maps one closed VCP image action to xAI JSON.
// projectImageRequest 将一个封闭 VCP 图片动作映射为 xAI JSON。
func projectImageRequest(execution provider.ExecutionRequest, actionBindingID string) (transport.Request, error) {
	body := imageRequest{Model: execution.Binding.Target.UpstreamModelID, ResponseFormat: "b64_json"}
	path := "/v1/images/generations"
	switch actionBindingID {
	case ImageGenerateActionBindingID:
		operation := execution.Execution.Payload.ImageGenerate
		if operation == nil || len(operation.References) != 0 || operation.NegativePrompt != "" || operation.Seed != nil || operation.Width != 0 || operation.Height != 0 || operation.Quality != "" || operation.Background != "" || operation.SafetyPolicy != "" {
			return transport.Request{}, fmt.Errorf("%w: references, negative_prompt, seed, width, height, quality, background, and safety_policy have no xAI generation carrier", ErrInvalidImageDriver)
		}
		if operation.Count < 0 {
			return transport.Request{}, fmt.Errorf("%w: count cannot be negative", ErrInvalidImageDriver)
		}
		body.Prompt, body.Count, body.AspectRatio = operation.Prompt, operation.Count, operation.AspectRatio
		body.Resolution = imageResolution(operation.Resolution)
		if !supportedImageAspectRatio(body.AspectRatio) || body.Resolution == "invalid" || !isJPEGOutputFormat(operation.OutputFormat) {
			return transport.Request{}, fmt.Errorf("%w: unsupported output format, resolution, or aspect ratio", ErrInvalidImageDriver)
		}
	case ImageEditActionBindingID:
		operation := execution.Execution.Payload.ImageEdit
		if operation == nil || len(operation.Sources) < 1 || len(operation.Sources) > 3 {
			return transport.Request{}, fmt.Errorf("%w: xAI image editing requires one to three sources", ErrInvalidImageDriver)
		}
		if operation.Count < 0 || operation.Count > 1 || operation.Width != 0 || operation.Height != 0 || operation.Quality != "" {
			return transport.Request{}, fmt.Errorf("%w: edit count must be one and width, height, and quality have no exact xAI carrier", ErrInvalidImageDriver)
		}
		body.Prompt, body.AspectRatio = operation.Instruction, operation.AspectRatio
		body.Resolution = imageResolution(operation.Resolution)
		if !supportedImageAspectRatio(body.AspectRatio) || body.Resolution == "invalid" || !isJPEGOutputFormat(operation.OutputFormat) {
			return transport.Request{}, fmt.Errorf("%w: unsupported output format, resolution, or aspect ratio", ErrInvalidImageDriver)
		}
		materializedByID := make(map[string]resource.MaterializedInput, len(execution.MaterializedInputs))
		for _, materialized := range execution.MaterializedInputs {
			materializedByID[materialized.InputID] = materialized
		}
		sources := make([]imageSource, 0, len(operation.Sources))
		for _, source := range operation.Sources {
			if source.Role != vcp.MediaRoleEditSource {
				return transport.Request{}, fmt.Errorf("%w: xAI image editing accepts edit_source inputs only", ErrInvalidImageDriver)
			}
			materialized, exists := materializedByID[source.ID]
			if !exists || materialized.ResourceID != source.Resource.ResourceID || materialized.Kind != vcp.MediaImage || materialized.Role != source.Role {
				return transport.Request{}, fmt.Errorf("%w: image edit input %q has no exact materialization", ErrInvalidImageDriver, source.ID)
			}
			projected, errSource := projectImageSource(materialized)
			if errSource != nil {
				return transport.Request{}, errSource
			}
			sources = append(sources, projected)
		}
		if len(sources) == 1 {
			body.Image = &sources[0]
		} else {
			body.Images = sources
		}
		path = "/v1/images/edits"
	default:
		return transport.Request{}, ErrInvalidImageDriver
	}
	encoded, errEncode := json.Marshal(body)
	if errEncode != nil {
		return transport.Request{}, fmt.Errorf("%w: encode request: %v", ErrInvalidImageDriver, errEncode)
	}
	return transport.Request{Binding: execution.Binding, Method: http.MethodPost, Path: path, Body: encoded, Headers: []transport.Header{{Name: "Content-Type", Value: "application/json"}}, Authentication: transport.Authentication{Mode: transport.AuthenticationBearer}, IdempotencyKey: execution.Execution.IdempotencyKey}, nil
}

// projectImageSource converts one exact planned input to an xAI URL carrier.
// projectImageSource 将一个精确规划输入转换为 xAI URL 载体。
func projectImageSource(input resource.MaterializedInput) (imageSource, error) {
	if input.MIMEType != "image/png" && input.MIMEType != "image/jpeg" {
		return imageSource{}, fmt.Errorf("%w: xAI edit image must be PNG or JPEG", ErrInvalidImageDriver)
	}
	switch input.Mode {
	case catalog.MaterializationInlineBase64:
		decoded, errDecode := base64.StdEncoding.DecodeString(input.InlineBase64)
		if errDecode != nil || len(decoded) == 0 {
			return imageSource{}, fmt.Errorf("%w: inline image must contain valid Base64 data", ErrInvalidImageDriver)
		}
		return imageSource{Type: "image_url", URL: "data:" + input.MIMEType + ";base64," + input.InlineBase64}, nil
	case catalog.MaterializationDirectRemoteURL:
		parsed, errParse := url.ParseRequestURI(input.RemoteURL)
		if errParse != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil {
			return imageSource{}, fmt.Errorf("%w: direct image URL is invalid", ErrInvalidImageDriver)
		}
		return imageSource{Type: "image_url", URL: input.RemoteURL}, nil
	default:
		return imageSource{}, fmt.Errorf("%w: xAI editing accepts inline Base64 or direct URL inputs only", ErrInvalidImageDriver)
	}
}

// imageResolution normalizes one xAI resolution tier.
// imageResolution 规范化一个 xAI 分辨率档位。
func imageResolution(resolution string) string {
	switch strings.ToLower(strings.TrimSpace(resolution)) {
	case "", "1k", "2k":
		return strings.ToLower(strings.TrimSpace(resolution))
	default:
		return "invalid"
	}
}

// supportedImageAspectRatio reports whether xAI documents one image ratio.
// supportedImageAspectRatio 报告 xAI 是否记录了指定图片长宽比。
func supportedImageAspectRatio(aspectRatio string) bool {
	switch strings.TrimSpace(aspectRatio) {
	case "", "auto", "1:1", "16:9", "9:16", "4:3", "3:4", "3:2", "2:3", "2:1", "1:2", "19.5:9", "9:19.5", "20:9", "9:20":
		return true
	default:
		return false
	}
}

// isJPEGOutputFormat reports whether the VCP request accepts xAI's fixed JPEG response.
// isJPEGOutputFormat 报告 VCP 请求是否接受 xAI 固定的 JPEG 响应。
func isJPEGOutputFormat(format string) bool {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "jpg", "jpeg":
		return true
	default:
		return false
	}
}

// imageResponse is the official image response subset required for private import.
// imageResponse 是私有导入所需的官方图片响应子集。
type imageResponse struct {
	// Data contains ordered generated image objects.
	// Data 包含有序生成图片对象。
	Data []imageResponseItem `json:"data"`
}

// imageResponseItem contains one inline image and its declared type.
// imageResponseItem 包含一张内联图片及其声明类型。
type imageResponseItem struct {
	// Base64JSON contains raw Base64 generated bytes.
	// Base64JSON 包含原始 Base64 生成字节。
	Base64JSON string `json:"b64_json"`
	// MIMEType declares the generated image type.
	// MIMEType 声明生成图片类型。
	MIMEType string `json:"mime_type"`
}

// decodeImageResponse extracts ordered inline xAI images.
// decodeImageResponse 提取有序内联 xAI 图片。
func decodeImageResponse(reader io.Reader) (provider.ExecutionResult, error) {
	var response imageResponse
	if errDecode := json.NewDecoder(reader).Decode(&response); errDecode != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: decode response: %v", ErrInvalidImageResponse, errDecode)
	}
	if len(response.Data) == 0 {
		return provider.ExecutionResult{}, fmt.Errorf("%w: response contains no generated image", ErrInvalidImageResponse)
	}
	resources := make([]provider.GeneratedResource, 0, len(response.Data))
	for index, item := range response.Data {
		if item.MIMEType != "image/jpeg" || item.Base64JSON == "" {
			return provider.ExecutionResult{}, fmt.Errorf("%w: output %d is not an inline JPEG", ErrInvalidImageResponse, index)
		}
		decoded, errDecode := base64.StdEncoding.DecodeString(item.Base64JSON)
		if errDecode != nil || len(decoded) == 0 {
			return provider.ExecutionResult{}, fmt.Errorf("%w: output %d contains invalid Base64", ErrInvalidImageResponse, index)
		}
		resources = append(resources, provider.GeneratedResource{OutputID: fmt.Sprintf("image-%d", index), Kind: vcp.MediaImage, MIMEType: item.MIMEType, Data: decoded})
	}
	return provider.ExecutionResult{GeneratedResources: resources}, nil
}
