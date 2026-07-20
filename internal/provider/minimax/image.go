package minimax

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
	"unicode/utf8"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

const (
	// ImageGenerateActionBindingID identifies the MiniMax synchronous image generation action.
	// ImageGenerateActionBindingID 标识 MiniMax 同步图片生成动作。
	ImageGenerateActionBindingID = "action_minimax_image_generate"
	// ImageGenerateProtocolProfileID identifies the MiniMax image_generation JSON contract.
	// ImageGenerateProtocolProfileID 标识 MiniMax image_generation JSON 合同。
	ImageGenerateProtocolProfileID = "minimax.image.generate.v1"
)

var (
	// ErrInvalidImageDriver reports an incomplete or unsupported MiniMax image request.
	// ErrInvalidImageDriver 表示不完整或不受支持的 MiniMax 图片请求。
	ErrInvalidImageDriver = errors.New("invalid MiniMax image driver")
	// ErrInvalidImageResponse reports a malformed or failed MiniMax image response.
	// ErrInvalidImageResponse 表示格式错误或执行失败的 MiniMax 图片响应。
	ErrInvalidImageResponse = errors.New("invalid MiniMax image response")
)

// ImageActionDriver executes synchronous MiniMax image generation for one immutable definition.
// ImageActionDriver 为一个不可变 Definition 执行同步 MiniMax 图片生成。
type ImageActionDriver struct {
	// definitionID is the sole provider definition permitted to use this driver.
	// definitionID 是允许使用此 Driver 的唯一供应商 Definition。
	definitionID string
	// client owns provider-scoped authenticated HTTP execution.
	// client 负责供应商作用域的认证 HTTP 执行。
	client *transport.Client
}

// NewImageActionDriver creates one MiniMax image generation driver.
// NewImageActionDriver 创建一个 MiniMax 图片生成 Driver。
func NewImageActionDriver(definitionID string, client *transport.Client) (*ImageActionDriver, error) {
	if strings.TrimSpace(definitionID) == "" || client == nil {
		return nil, ErrInvalidImageDriver
	}
	return &ImageActionDriver{definitionID: definitionID, client: client}, nil
}

// ProviderDefinitionID returns the sole provider definition owned by this driver.
// ProviderDefinitionID 返回此 Driver 拥有的唯一供应商 Definition。
func (d *ImageActionDriver) ProviderDefinitionID() string {
	if d == nil {
		return ""
	}
	return d.definitionID
}

// ActionBindingID returns the MiniMax image generation binding.
// ActionBindingID 返回 MiniMax 图片生成绑定。
func (d *ImageActionDriver) ActionBindingID() string {
	return ImageGenerateActionBindingID
}

// Execute projects and executes one official MiniMax image_generation request.
// Execute 投影并执行一个官方 MiniMax image_generation 请求。
func (d *ImageActionDriver) Execute(ctx context.Context, execution provider.ExecutionRequest) (provider.ExecutionResult, error) {
	if d == nil || d.client == nil {
		return provider.ExecutionResult{}, ErrInvalidImageDriver
	}
	if execution.Binding.Target.ProviderDefinitionID != d.definitionID {
		return provider.ExecutionResult{}, fmt.Errorf("%w: target definition does not belong to this driver", provider.ErrExecutionBinding)
	}
	if _, errValidate := execution.ValidateForAction(ImageGenerateActionBindingID, providerconfig.AuthMethodAPIKey); errValidate != nil {
		return provider.ExecutionResult{}, errValidate
	}
	outbound, errProject := projectImageRequest(execution)
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

// imageRequest is the official MiniMax synchronous image generation request.
// imageRequest 是官方 MiniMax 同步图片生成请求。
type imageRequest struct {
	// Model is fixed by the resolved offering.
	// Model 由已解析 Offering 固定。
	Model string `json:"model"`
	// Prompt describes the generated image.
	// Prompt 描述生成图片。
	Prompt string `json:"prompt"`
	// SubjectReference contains ordered character-preservation references.
	// SubjectReference 包含有序角色保持参考图。
	SubjectReference []subjectReference `json:"subject_reference,omitempty"`
	// AspectRatio requests one documented preset.
	// AspectRatio 请求一个文档明确的预设。
	AspectRatio string `json:"aspect_ratio,omitempty"`
	// Width requests a custom width for image-01.
	// Width 为 image-01 请求自定义宽度。
	Width int `json:"width,omitempty"`
	// Height requests a custom height for image-01.
	// Height 为 image-01 请求自定义高度。
	Height int `json:"height,omitempty"`
	// ResponseFormat is fixed to base64 for private Router import.
	// ResponseFormat 固定为 base64 以供 Router 私有导入。
	ResponseFormat string `json:"response_format"`
	// Seed requests provider-relative deterministic output.
	// Seed 请求供应商相对确定性输出。
	Seed *int64 `json:"seed,omitempty"`
	// Count requests one to nine images.
	// Count 请求一至九张图片。
	Count int `json:"n,omitempty"`
}

// subjectReference is one MiniMax character reference image.
// subjectReference 是一张 MiniMax 角色参考图片。
type subjectReference struct {
	// Type is fixed to character by the official API.
	// Type 由官方 API 固定为 character。
	Type string `json:"type"`
	// ImageFile is one public image URL.
	// ImageFile 是一个公网图片 URL。
	ImageFile string `json:"image_file"`
}

// projectImageRequest maps one closed VCP generation payload to MiniMax JSON.
// projectImageRequest 将一个封闭 VCP 生成载荷映射为 MiniMax JSON。
func projectImageRequest(execution provider.ExecutionRequest) (transport.Request, error) {
	operation := execution.Execution.Payload.ImageGenerate
	if operation == nil || operation.NegativePrompt != "" || operation.Resolution != "" || operation.Quality != "" || operation.Background != "" || operation.SafetyPolicy != "" {
		return transport.Request{}, fmt.Errorf("%w: negative_prompt, resolution, quality, background, and safety_policy have no MiniMax carrier", ErrInvalidImageDriver)
	}
	if utf8.RuneCountInString(operation.Prompt) > 1500 || operation.Count < 0 || operation.Count > 9 {
		return transport.Request{}, fmt.Errorf("%w: prompt exceeds 1500 characters or count exceeds one to nine", ErrInvalidImageDriver)
	}
	if !supportedAspectRatio(operation.AspectRatio) || !isJPEGOutputFormat(operation.OutputFormat) {
		return transport.Request{}, fmt.Errorf("%w: unsupported aspect ratio or output format", ErrInvalidImageDriver)
	}
	if (operation.Width == 0) != (operation.Height == 0) || (operation.Width != 0 && operation.AspectRatio != "") {
		return transport.Request{}, fmt.Errorf("%w: width and height must appear together and cannot be combined with aspect_ratio", ErrInvalidImageDriver)
	}
	if operation.Width != 0 && (operation.Width < 512 || operation.Width > 2048 || operation.Height < 512 || operation.Height > 2048 || operation.Width%8 != 0 || operation.Height%8 != 0) {
		return transport.Request{}, fmt.Errorf("%w: dimensions must be 512 to 2048 and divisible by eight", ErrInvalidImageDriver)
	}
	body := imageRequest{Model: execution.Binding.Target.UpstreamModelID, Prompt: operation.Prompt, AspectRatio: operation.AspectRatio, Width: operation.Width, Height: operation.Height, ResponseFormat: "base64", Seed: operation.Seed, Count: operation.Count}
	materializedByID := make(map[string]resource.MaterializedInput, len(execution.MaterializedInputs))
	for _, materialized := range execution.MaterializedInputs {
		materializedByID[materialized.InputID] = materialized
	}
	for _, reference := range operation.References {
		if reference.Role != vcp.MediaRoleReference {
			return transport.Request{}, fmt.Errorf("%w: MiniMax subject references require the reference role", ErrInvalidImageDriver)
		}
		materialized, exists := materializedByID[reference.ID]
		if !exists || materialized.ResourceID != reference.Resource.ResourceID || materialized.Kind != vcp.MediaImage || materialized.Role != reference.Role || materialized.Mode != catalog.MaterializationDirectRemoteURL {
			return transport.Request{}, fmt.Errorf("%w: reference %q requires one exact direct URL materialization", ErrInvalidImageDriver, reference.ID)
		}
		parsed, errParse := url.ParseRequestURI(materialized.RemoteURL)
		if errParse != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil {
			return transport.Request{}, fmt.Errorf("%w: reference URL is invalid", ErrInvalidImageDriver)
		}
		body.SubjectReference = append(body.SubjectReference, subjectReference{Type: "character", ImageFile: materialized.RemoteURL})
	}
	encoded, errEncode := json.Marshal(body)
	if errEncode != nil {
		return transport.Request{}, fmt.Errorf("%w: encode request: %v", ErrInvalidImageDriver, errEncode)
	}
	return transport.Request{Binding: execution.Binding, Method: http.MethodPost, Path: "/v1/image_generation", Body: encoded, Headers: []transport.Header{{Name: "Content-Type", Value: "application/json"}}, Authentication: transport.Authentication{Mode: transport.AuthenticationBearer}, IdempotencyKey: execution.Execution.IdempotencyKey}, nil
}

// supportedAspectRatio reports whether MiniMax documents one image preset.
// supportedAspectRatio 报告 MiniMax 是否记录了指定图片预设。
func supportedAspectRatio(aspectRatio string) bool {
	switch strings.TrimSpace(aspectRatio) {
	case "", "1:1", "16:9", "4:3", "3:2", "2:3", "3:4", "9:16", "21:9":
		return true
	default:
		return false
	}
}

// isJPEGOutputFormat reports whether the caller accepts MiniMax's JPEG bytes.
// isJPEGOutputFormat 报告调用方是否接受 MiniMax 的 JPEG 字节。
func isJPEGOutputFormat(format string) bool {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "jpg", "jpeg":
		return true
	default:
		return false
	}
}

// imageResponse is the closed successful MiniMax response.
// imageResponse 是封闭的成功 MiniMax 响应。
type imageResponse struct {
	// ID is the provider trace identifier.
	// ID 是供应商追踪标识。
	ID string `json:"id"`
	// Data contains Base64 output images.
	// Data 包含 Base64 输出图片。
	Data imageResponseData `json:"data"`
	// BaseResponse contains the provider application status.
	// BaseResponse 包含供应商应用状态。
	BaseResponse baseResponse `json:"base_resp"`
}

// imageResponseData contains ordered Base64 JPEG strings.
// imageResponseData 包含有序 Base64 JPEG 字符串。
type imageResponseData struct {
	// ImageBase64 contains generated image bytes.
	// ImageBase64 包含生成图片字节。
	ImageBase64 []string `json:"image_base64"`
}

// baseResponse contains the MiniMax application result code.
// baseResponse 包含 MiniMax 应用结果码。
type baseResponse struct {
	// StatusCode is zero only on success.
	// StatusCode 仅在成功时为零。
	StatusCode int `json:"status_code"`
	// StatusMessage is safe provider status text without request content.
	// StatusMessage 是不含请求内容的安全供应商状态文本。
	StatusMessage string `json:"status_msg"`
}

// decodeImageResponse extracts private Base64 JPEG outputs from a successful response.
// decodeImageResponse 从成功响应中提取私有 Base64 JPEG 输出。
func decodeImageResponse(reader io.Reader) (provider.ExecutionResult, error) {
	var response imageResponse
	if errDecode := json.NewDecoder(reader).Decode(&response); errDecode != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: decode response: %v", ErrInvalidImageResponse, errDecode)
	}
	if strings.TrimSpace(response.ID) == "" || response.BaseResponse.StatusCode != 0 || len(response.Data.ImageBase64) == 0 {
		return provider.ExecutionResult{}, fmt.Errorf("%w: provider status %d", ErrInvalidImageResponse, response.BaseResponse.StatusCode)
	}
	resources := make([]provider.GeneratedResource, 0, len(response.Data.ImageBase64))
	for index, encoded := range response.Data.ImageBase64 {
		decoded, errDecode := base64.StdEncoding.DecodeString(encoded)
		if errDecode != nil || len(decoded) == 0 {
			return provider.ExecutionResult{}, fmt.Errorf("%w: output %d contains invalid Base64", ErrInvalidImageResponse, index)
		}
		resources = append(resources, provider.GeneratedResource{OutputID: fmt.Sprintf("image-%d", index), Kind: vcp.MediaImage, MIMEType: "image/jpeg", Data: decoded})
	}
	return provider.ExecutionResult{UpstreamResponseID: response.ID, GeneratedResources: resources}, nil
}
