package openrouter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

const (
	// VideoGenerateActionBindingID identifies OpenRouter's asynchronous video endpoint.
	// VideoGenerateActionBindingID 标识 OpenRouter 异步视频端点。
	VideoGenerateActionBindingID = "action_openrouter_video_generate"
	// VideoGenerateProtocolProfileID identifies OpenRouter's dedicated video JSON contract.
	// VideoGenerateProtocolProfileID 标识 OpenRouter 专用视频 JSON 合同。
	VideoGenerateProtocolProfileID = "openrouter.videos.generate.v1"
	// maximumOpenRouterVideoBytes bounds authenticated content downloads retained in memory before Router ingestion.
	// maximumOpenRouterVideoBytes 限制 Router 导入前保留在内存中的认证视频内容下载大小。
	maximumOpenRouterVideoBytes int64 = 512 << 20
)

var (
	// ErrInvalidVideoDriver reports an unsupported OpenRouter video request.
	// ErrInvalidVideoDriver 表示不受支持的 OpenRouter 视频请求。
	ErrInvalidVideoDriver = errors.New("invalid OpenRouter video driver")
	// ErrInvalidVideoResponse reports a malformed OpenRouter video response.
	// ErrInvalidVideoResponse 表示格式错误的 OpenRouter 视频响应。
	ErrInvalidVideoResponse = errors.New("invalid OpenRouter video response")
)

// VideoTaskDriver owns OpenRouter's dedicated asynchronous video action.
// VideoTaskDriver 拥有 OpenRouter 专用异步视频动作。
type VideoTaskDriver struct {
	// definitionID is the sole provider definition permitted to use this driver.
	// definitionID 是允许使用此 Driver 的唯一供应商 Definition。
	definitionID string
	// client owns provider-scoped authenticated HTTP execution.
	// client 负责供应商作用域的认证 HTTP 执行。
	client *transport.Client
}

// NewVideoTaskDriver creates one OpenRouter asynchronous video driver.
// NewVideoTaskDriver 创建一个 OpenRouter 异步视频 Driver。
func NewVideoTaskDriver(definitionID string, client *transport.Client) (*VideoTaskDriver, error) {
	if strings.TrimSpace(definitionID) == "" || client == nil {
		return nil, ErrInvalidVideoDriver
	}
	return &VideoTaskDriver{definitionID: definitionID, client: client}, nil
}

// ProviderDefinitionID returns the sole provider definition owned by this driver.
// ProviderDefinitionID 返回此 Driver 拥有的唯一供应商 Definition。
func (d *VideoTaskDriver) ProviderDefinitionID() string {
	if d == nil {
		return ""
	}
	return d.definitionID
}

// ActionBindingID returns the dedicated OpenRouter video action.
// ActionBindingID 返回专用 OpenRouter 视频动作。
func (d *VideoTaskDriver) ActionBindingID() string { return VideoGenerateActionBindingID }

// Start submits one dedicated OpenRouter video generation request.
// Start 提交一个专用 OpenRouter 视频生成请求。
func (d *VideoTaskDriver) Start(ctx context.Context, execution provider.ExecutionRequest) (provider.TaskResult, error) {
	if errValidate := d.validateExecution(execution); errValidate != nil {
		return provider.TaskResult{}, errValidate
	}
	outbound, errProject := projectOpenRouterVideo(execution)
	if errProject != nil {
		return provider.TaskResult{}, errProject
	}
	response, errRequest := d.client.Do(ctx, outbound)
	if errRequest != nil {
		return provider.TaskResult{}, errRequest
	}
	defer func() { _ = transport.DrainAndClose(response) }()
	bounded, errBound := transport.NewBoundedResponseReader(response.Body, transport.MaximumNonStreamingResponseBytes)
	if errBound != nil {
		return provider.TaskResult{}, fmt.Errorf("%w: bound start response: %v", ErrInvalidVideoResponse, errBound)
	}
	observation, errDecode := decodeOpenRouterVideoObservation(bounded, "", execution.Now)
	if errDecode != nil {
		return provider.TaskResult{}, errDecode
	}
	if observation.State != provider.TaskQueued {
		return provider.TaskResult{}, fmt.Errorf("%w: start response is not pending", ErrInvalidVideoResponse)
	}
	return observation, nil
}

// Poll observes one exact OpenRouter video job and privately acquires authenticated content when required.
// Poll 观察一个精确 OpenRouter 视频任务并在需要时私下获取认证内容。
func (d *VideoTaskDriver) Poll(ctx context.Context, execution provider.ExecutionRequest, providerTaskID string) (provider.TaskResult, error) {
	if errValidate := d.validateExecution(execution); errValidate != nil {
		return provider.TaskResult{}, errValidate
	}
	if strings.TrimSpace(providerTaskID) == "" {
		return provider.TaskResult{}, fmt.Errorf("%w: provider task identifier is required", ErrInvalidVideoDriver)
	}
	outbound := transport.Request{Binding: execution.Binding, Method: http.MethodGet, Path: "/v1/videos/" + url.PathEscape(providerTaskID), Authentication: transport.Authentication{Mode: transport.AuthenticationBearer}}
	response, errRequest := d.client.Do(ctx, outbound)
	if errRequest != nil {
		return provider.TaskResult{}, errRequest
	}
	defer func() { _ = transport.DrainAndClose(response) }()
	bounded, errBound := transport.NewBoundedResponseReader(response.Body, transport.MaximumNonStreamingResponseBytes)
	if errBound != nil {
		return provider.TaskResult{}, fmt.Errorf("%w: bound poll response: %v", ErrInvalidVideoResponse, errBound)
	}
	observation, errDecode := decodeOpenRouterVideoObservation(bounded, providerTaskID, execution.Now)
	if errDecode != nil || observation.State != provider.TaskSucceeded {
		return observation, errDecode
	}
	for index := range observation.Result.GeneratedResources {
		output := &observation.Result.GeneratedResources[index]
		path, authenticated := authenticatedOpenRouterContentPath(execution.Binding.Endpoint.BaseURL, output.DownloadURL)
		if !authenticated {
			continue
		}
		content, mimeType, errDownload := d.downloadContent(ctx, execution, path)
		if errDownload != nil {
			return provider.TaskResult{}, errDownload
		}
		output.Data, output.DownloadURL = content, ""
		if mimeType != "" {
			output.MIMEType = mimeType
		}
	}
	return observation, nil
}

// Cancel reports that OpenRouter documents terminal cancelled jobs but no public cancellation request endpoint.
// Cancel 报告 OpenRouter 记录了取消终态但未记录公共取消请求端点。
func (d *VideoTaskDriver) Cancel(_ context.Context, execution provider.ExecutionRequest, providerTaskID string) (provider.TaskResult, error) {
	if errValidate := d.validateExecution(execution); errValidate != nil {
		return provider.TaskResult{}, errValidate
	}
	if strings.TrimSpace(providerTaskID) == "" {
		return provider.TaskResult{}, fmt.Errorf("%w: provider task identifier is required", ErrInvalidVideoDriver)
	}
	return provider.TaskResult{}, fmt.Errorf("%w: OpenRouter does not document a video cancellation request endpoint", ErrInvalidVideoDriver)
}

// validateExecution verifies action ownership and API-key authentication.
// validateExecution 校验动作归属和 API Key 认证。
func (d *VideoTaskDriver) validateExecution(execution provider.ExecutionRequest) error {
	if d == nil || d.client == nil || execution.Binding.Target.ProviderDefinitionID != d.definitionID {
		return fmt.Errorf("%w: target definition does not belong to this driver", provider.ErrExecutionBinding)
	}
	_, errValidate := execution.ValidateForAction(VideoGenerateActionBindingID, providerconfig.AuthMethodAPIKey)
	return errValidate
}

// openRouterVideoRequest is the dedicated typed OpenRouter video request.
// openRouterVideoRequest 是专用类型化 OpenRouter 视频请求。
type openRouterVideoRequest struct {
	// Model is the exact resolved video model.
	// Model 是精确解析的视频模型。
	Model string `json:"model"`
	// Prompt describes the requested video.
	// Prompt 描述请求的视频。
	Prompt string `json:"prompt"`
	// Duration is an optional whole-second duration.
	// Duration 是可选整秒时长。
	Duration int `json:"duration,omitempty"`
	// Resolution selects one model-supported tier.
	// Resolution 选择模型支持的一个档位。
	Resolution string `json:"resolution,omitempty"`
	// AspectRatio selects one model-supported ratio.
	// AspectRatio 选择模型支持的一个长宽比。
	AspectRatio string `json:"aspect_ratio,omitempty"`
	// Size requests exact pixel dimensions and excludes tier-plus-ratio controls.
	// Size 请求精确像素尺寸且排斥档位加长宽比控制。
	Size string `json:"size,omitempty"`
	// FrameImages contains first and last frame images.
	// FrameImages 包含首帧和尾帧图片。
	FrameImages []openRouterVideoReference `json:"frame_images,omitempty"`
	// InputReferences contains style or content references.
	// InputReferences 包含风格或内容参考。
	InputReferences []openRouterVideoReference `json:"input_references,omitempty"`
	// Seed requests provider-routed deterministic sampling.
	// Seed 请求供应商路由的确定性采样。
	Seed *int64 `json:"seed,omitempty"`
}

// openRouterVideoReference is one URL-shaped image reference.
// openRouterVideoReference 是一个 URL 形状图片参考。
type openRouterVideoReference struct {
	// Type declares the image URL carrier.
	// Type 声明图片 URL 载体。
	Type string `json:"type"`
	// ImageURL contains a public URL or Base64 data URI.
	// ImageURL 包含公网 URL 或 Base64 Data URI。
	ImageURL openRouterVideoURL `json:"image_url"`
	// FrameType identifies first or last frame when this is a frame input.
	// FrameType 在此项为帧输入时标识首帧或尾帧。
	FrameType string `json:"frame_type,omitempty"`
}

// openRouterVideoURL contains one exact URL carrier.
// openRouterVideoURL 包含一个精确 URL 载体。
type openRouterVideoURL struct {
	// URL is a public URL or Base64 data URI.
	// URL 是公网 URL 或 Base64 Data URI。
	URL string `json:"url"`
}

// openRouterVideoObservation is the shared submit and poll response.
// openRouterVideoObservation 是共享的提交与轮询响应。
type openRouterVideoObservation struct {
	// ID is the private OpenRouter job identifier.
	// ID 是私有 OpenRouter 任务标识。
	ID string `json:"id"`
	// Status is the documented job status.
	// Status 是文档明确的任务状态。
	Status string `json:"status"`
	// UnsignedURLs contains completed content locations.
	// UnsignedURLs 包含已完成内容位置。
	UnsignedURLs []string `json:"unsigned_urls,omitempty"`
	// Error contains only a provider-rendered failure string and is never exposed directly.
	// Error 仅包含供应商渲染的失败字符串且绝不直接公开。
	Error string `json:"error,omitempty"`
}

// projectOpenRouterVideo maps one VCP video generation operation without passthrough options.
// projectOpenRouterVideo 映射一个不含透传选项的 VCP 视频生成操作。
func projectOpenRouterVideo(execution provider.ExecutionRequest) (transport.Request, error) {
	operation := execution.Execution.Payload.VideoGenerate
	if operation == nil || operation.FramesPerSecond != 0 || operation.Watermark != nil || operation.Count > 1 || (operation.OutputFormat != "" && operation.OutputFormat != "mp4") {
		return transport.Request{}, fmt.Errorf("%w: frame rate, watermark, multiple outputs, or non-MP4 output has no OpenRouter carrier", ErrInvalidVideoDriver)
	}
	body := openRouterVideoRequest{Model: execution.Binding.Target.UpstreamModelID, Prompt: operation.Prompt, Resolution: operation.Resolution, AspectRatio: operation.AspectRatio, Seed: operation.Seed}
	if operation.DurationSeconds != 0 {
		body.Duration = int(operation.DurationSeconds)
		if operation.DurationSeconds != float64(body.Duration) || body.Duration < 1 {
			return transport.Request{}, fmt.Errorf("%w: duration must be a positive whole number of seconds", ErrInvalidVideoDriver)
		}
	}
	if operation.Width != 0 || operation.Height != 0 {
		if operation.Width <= 0 || operation.Height <= 0 || operation.Resolution != "" || operation.AspectRatio != "" {
			return transport.Request{}, fmt.Errorf("%w: exact size requires both dimensions and excludes resolution and aspect ratio", ErrInvalidVideoDriver)
		}
		body.Size = strconv.Itoa(operation.Width) + "x" + strconv.Itoa(operation.Height)
	}
	for _, input := range operation.Inputs {
		if input.Kind != vcp.MediaImage {
			return transport.Request{}, fmt.Errorf("%w: initial OpenRouter video profile accepts image inputs only", ErrInvalidVideoDriver)
		}
		mediaURL, errURL := exactOpenRouterMediaURL(input, execution.MaterializedInputs)
		if errURL != nil {
			return transport.Request{}, errURL
		}
		reference := openRouterVideoReference{Type: "image_url", ImageURL: openRouterVideoURL{URL: mediaURL}}
		switch input.Role {
		case vcp.MediaRoleFirstFrame:
			reference.FrameType = "first_frame"
			body.FrameImages = append(body.FrameImages, reference)
		case vcp.MediaRoleLastFrame:
			reference.FrameType = "last_frame"
			body.FrameImages = append(body.FrameImages, reference)
		case vcp.MediaRoleReference:
			body.InputReferences = append(body.InputReferences, reference)
		default:
			return transport.Request{}, fmt.Errorf("%w: unsupported OpenRouter image role %q", ErrInvalidVideoDriver, input.Role)
		}
	}
	if len(body.FrameImages) > 0 && len(body.InputReferences) > 0 {
		return transport.Request{}, fmt.Errorf("%w: frame and reference modes cannot be combined", ErrInvalidVideoDriver)
	}
	encoded, errEncode := json.Marshal(body)
	if errEncode != nil {
		return transport.Request{}, errEncode
	}
	return transport.Request{Binding: execution.Binding, Method: http.MethodPost, Path: "/v1/videos", Body: encoded, Headers: []transport.Header{{Name: "Content-Type", Value: "application/json"}}, Authentication: transport.Authentication{Mode: transport.AuthenticationBearer}, IdempotencyKey: execution.Execution.IdempotencyKey}, nil
}

// exactOpenRouterMediaURL resolves one direct or inline image materialization.
// exactOpenRouterMediaURL 解析一个直接或内联图片物化表示。
func exactOpenRouterMediaURL(input vcp.MediaInput, materialized []resource.MaterializedInput) (string, error) {
	for _, value := range materialized {
		if value.InputID != input.ID {
			continue
		}
		if value.ResourceID != input.Resource.ResourceID || value.Kind != input.Kind || value.Role != input.Role {
			return "", fmt.Errorf("%w: materialized input %q differs from canonical identity", ErrInvalidVideoDriver, input.ID)
		}
		switch value.Mode {
		case catalog.MaterializationDirectRemoteURL:
			if strings.TrimSpace(value.RemoteURL) != "" {
				return value.RemoteURL, nil
			}
		case catalog.MaterializationInlineBase64:
			if strings.TrimSpace(value.InlineBase64) != "" && strings.TrimSpace(value.MIMEType) != "" {
				return "data:" + value.MIMEType + ";base64," + value.InlineBase64, nil
			}
		}
		return "", fmt.Errorf("%w: OpenRouter image materialization must be a URL or Base64 data URI", ErrInvalidVideoDriver)
	}
	return "", fmt.Errorf("%w: media input %q has no exact materialization", ErrInvalidVideoDriver, input.ID)
}

// decodeOpenRouterVideoObservation converts the documented job states into Router task states.
// decodeOpenRouterVideoObservation 将文档明确的任务状态转换为 Router 任务状态。
func decodeOpenRouterVideoObservation(reader io.Reader, expectedID string, now time.Time) (provider.TaskResult, error) {
	var response openRouterVideoObservation
	if errDecode := json.NewDecoder(reader).Decode(&response); errDecode != nil || strings.TrimSpace(response.ID) == "" || (expectedID != "" && response.ID != expectedID) {
		return provider.TaskResult{}, fmt.Errorf("%w: job identity is missing or changed", ErrInvalidVideoResponse)
	}
	switch response.Status {
	case "pending":
		return provider.TaskResult{ProviderTaskID: response.ID, State: provider.TaskQueued, PollAfter: now.UTC().Add(30 * time.Second)}, nil
	case "in_progress":
		return provider.TaskResult{ProviderTaskID: response.ID, State: provider.TaskRunning, PollAfter: now.UTC().Add(30 * time.Second)}, nil
	case "completed":
		if len(response.UnsignedURLs) == 0 {
			return provider.TaskResult{}, fmt.Errorf("%w: completed job has no content URL", ErrInvalidVideoResponse)
		}
		outputs := make([]provider.GeneratedResource, 0, len(response.UnsignedURLs))
		for index, outputURL := range response.UnsignedURLs {
			if strings.TrimSpace(outputURL) == "" {
				return provider.TaskResult{}, fmt.Errorf("%w: completed job contains an empty content URL", ErrInvalidVideoResponse)
			}
			outputs = append(outputs, provider.GeneratedResource{OutputID: "video-" + strconv.Itoa(index), Kind: vcp.MediaVideo, MIMEType: "video/mp4", DownloadURL: outputURL})
		}
		result := provider.ExecutionResult{GeneratedResources: outputs}
		return provider.TaskResult{ProviderTaskID: response.ID, State: provider.TaskSucceeded, Result: &result}, nil
	case "cancelled":
		return provider.TaskResult{ProviderTaskID: response.ID, State: provider.TaskCancelled}, nil
	case "expired":
		return provider.TaskResult{ProviderTaskID: response.ID, State: provider.TaskFailed, ErrorCode: "provider_task_expired"}, nil
	case "failed":
		return provider.TaskResult{ProviderTaskID: response.ID, State: provider.TaskFailed, ErrorCode: "openrouter_video_failed"}, nil
	default:
		return provider.TaskResult{}, fmt.Errorf("%w: unknown job status %q", ErrInvalidVideoResponse, response.Status)
	}
}

// authenticatedOpenRouterContentPath identifies content endpoints that require the selected OpenRouter credential.
// authenticatedOpenRouterContentPath 识别需要选定 OpenRouter 凭据的内容端点。
func authenticatedOpenRouterContentPath(baseURL string, contentURL string) (string, bool) {
	parsedContent, errContent := url.Parse(contentURL)
	if errContent != nil {
		return "", false
	}
	parsedBase, errBase := url.Parse(baseURL)
	if errBase != nil {
		return "", false
	}
	if !parsedContent.IsAbs() {
		return providerRelativeContentPath(parsedBase.Path, parsedContent)
	}
	if !strings.EqualFold(parsedContent.Host, parsedBase.Host) {
		return "", false
	}
	return providerRelativeContentPath(parsedBase.Path, parsedContent)
}

// providerRelativeContentPath removes the configured endpoint base path exactly once before transport reattaches it.
// providerRelativeContentPath 在 Transport 重新附加配置 Endpoint 基础路径前精确移除一次该路径。
func providerRelativeContentPath(basePath string, contentURL *url.URL) (string, bool) {
	path := contentURL.Path
	normalizedBase := strings.TrimRight(basePath, "/")
	if normalizedBase != "" && strings.HasPrefix(path, normalizedBase+"/") {
		path = strings.TrimPrefix(path, normalizedBase)
	}
	if !strings.HasPrefix(path, "/v1/videos/") {
		return "", false
	}
	if contentURL.RawQuery != "" {
		path += "?" + contentURL.RawQuery
	}
	return path, true
}

// downloadContent acquires one authenticated OpenRouter video before public Router ingestion.
// downloadContent 在公开 Router 导入前获取一个经认证的 OpenRouter 视频。
func (d *VideoTaskDriver) downloadContent(ctx context.Context, execution provider.ExecutionRequest, path string) ([]byte, string, error) {
	response, errRequest := d.client.Do(ctx, transport.Request{Binding: execution.Binding, Method: http.MethodGet, Path: path, Authentication: transport.Authentication{Mode: transport.AuthenticationBearer}})
	if errRequest != nil {
		return nil, "", errRequest
	}
	defer func() { _ = transport.DrainAndClose(response) }()
	content, errRead := io.ReadAll(io.LimitReader(response.Body, maximumOpenRouterVideoBytes+1))
	if errRead != nil || len(content) == 0 || int64(len(content)) > maximumOpenRouterVideoBytes {
		return nil, "", fmt.Errorf("%w: authenticated video content is empty or exceeds 512 MB", ErrInvalidVideoResponse)
	}
	mimeType := strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0])
	if mimeType != "" && mimeType != "video/mp4" {
		return nil, "", fmt.Errorf("%w: authenticated content type %q is not MP4", ErrInvalidVideoResponse, mimeType)
	}
	return content, mimeType, nil
}
