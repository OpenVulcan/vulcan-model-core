package xai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
	// VideoGenerateActionBindingID identifies the xAI asynchronous video generation action.
	// VideoGenerateActionBindingID 标识 xAI 异步视频生成动作。
	VideoGenerateActionBindingID = "action_xai_video_generate"
	// VideoEditActionBindingID identifies the xAI asynchronous video editing action.
	// VideoEditActionBindingID 标识 xAI 异步视频编辑动作。
	VideoEditActionBindingID = "action_xai_video_edit"
	// VideoExtendActionBindingID identifies the xAI asynchronous video extension action.
	// VideoExtendActionBindingID 标识 xAI 异步视频延长动作。
	VideoExtendActionBindingID = "action_xai_video_extend"
	// VideoGenerateProtocolProfileID identifies the xAI video generation wire contract.
	// VideoGenerateProtocolProfileID 标识 xAI 视频生成 Wire 合同。
	VideoGenerateProtocolProfileID = "xai.videos.generate.v1"
	// VideoEditProtocolProfileID identifies the xAI video editing wire contract.
	// VideoEditProtocolProfileID 标识 xAI 视频编辑 Wire 合同。
	VideoEditProtocolProfileID = "xai.videos.edit.v1"
	// VideoExtendProtocolProfileID identifies the xAI video extension wire contract.
	// VideoExtendProtocolProfileID 标识 xAI 视频延长 Wire 合同。
	VideoExtendProtocolProfileID = "xai.videos.extend.v1"
)

var (
	// ErrInvalidVideoDriver reports an incomplete or unsupported xAI video request.
	// ErrInvalidVideoDriver 表示不完整或不受支持的 xAI 视频请求。
	ErrInvalidVideoDriver = errors.New("invalid xAI video driver")
	// ErrInvalidVideoResponse reports a malformed xAI asynchronous response.
	// ErrInvalidVideoResponse 表示格式错误的 xAI 异步响应。
	ErrInvalidVideoResponse = errors.New("invalid xAI video response")
)

// VideoTaskDriver owns one xAI asynchronous video action for one immutable definition.
// VideoTaskDriver 为一个不可变 Definition 拥有一个 xAI 异步视频动作。
type VideoTaskDriver struct {
	// definitionID is the sole provider definition permitted to use this driver.
	// definitionID 是允许使用此 Driver 的唯一供应商 Definition。
	definitionID string
	// actionBindingID is the exact video action owned by this driver.
	// actionBindingID 是此 Driver 拥有的精确视频动作。
	actionBindingID string
	// client owns provider-scoped authenticated HTTP execution.
	// client 负责供应商作用域的认证 HTTP 执行。
	client *transport.Client
}

// NewVideoTaskDriver creates one xAI asynchronous video driver.
// NewVideoTaskDriver 创建一个 xAI 异步视频 Driver。
func NewVideoTaskDriver(definitionID string, actionBindingID string, client *transport.Client) (*VideoTaskDriver, error) {
	if strings.TrimSpace(definitionID) == "" || client == nil || !supportedXAIAction(actionBindingID) {
		return nil, ErrInvalidVideoDriver
	}
	return &VideoTaskDriver{definitionID: definitionID, actionBindingID: actionBindingID, client: client}, nil
}

// ProviderDefinitionID returns the sole provider definition owned by this driver.
// ProviderDefinitionID 返回此 Driver 拥有的唯一供应商 Definition。
func (d *VideoTaskDriver) ProviderDefinitionID() string {
	if d == nil {
		return ""
	}
	return d.definitionID
}

// ActionBindingID returns the sole action binding owned by this driver.
// ActionBindingID 返回此 Driver 拥有的唯一动作绑定。
func (d *VideoTaskDriver) ActionBindingID() string {
	if d == nil {
		return ""
	}
	return d.actionBindingID
}

// Start creates one exact xAI video request and returns its private provider task identity.
// Start 创建一个精确的 xAI 视频请求并返回其私有供应商任务标识。
func (d *VideoTaskDriver) Start(ctx context.Context, execution provider.ExecutionRequest) (provider.TaskResult, error) {
	if errValidate := d.validateExecution(execution); errValidate != nil {
		return provider.TaskResult{}, errValidate
	}
	outbound, errProject := projectVideoStart(execution, d.actionBindingID)
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
	return decodeVideoStart(bounded, execution.Now)
}

// Poll observes one exact xAI task without changing its target affinity.
// Poll 在不改变 Target 亲和性的情况下观察一个精确 xAI 任务。
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
	return decodeVideoPoll(bounded, providerTaskID, execution.Now)
}

// Cancel reports the provider's documented lack of a video cancellation endpoint.
// Cancel 报告供应商文档中缺少视频取消端点。
func (d *VideoTaskDriver) Cancel(_ context.Context, execution provider.ExecutionRequest, providerTaskID string) (provider.TaskResult, error) {
	if errValidate := d.validateExecution(execution); errValidate != nil {
		return provider.TaskResult{}, errValidate
	}
	if strings.TrimSpace(providerTaskID) == "" {
		return provider.TaskResult{}, fmt.Errorf("%w: provider task identifier is required", ErrInvalidVideoDriver)
	}
	return provider.TaskResult{}, fmt.Errorf("%w: xAI does not document video task cancellation", ErrInvalidVideoDriver)
}

// validateExecution verifies action ownership and supported API-key authentication.
// validateExecution 校验动作归属和受支持的 API Key 认证。
func (d *VideoTaskDriver) validateExecution(execution provider.ExecutionRequest) error {
	if d == nil || d.client == nil || execution.Binding.Target.ProviderDefinitionID != d.definitionID {
		return fmt.Errorf("%w: target definition does not belong to this driver", provider.ErrExecutionBinding)
	}
	_, errValidate := execution.ValidateForAction(d.actionBindingID, providerconfig.AuthMethodAPIKey)
	return errValidate
}

// videoRequest is the closed xAI request shared by generation, editing, and extension endpoints.
// videoRequest 是 xAI 生成、编辑和延长端点共享的封闭请求。
type videoRequest struct {
	// Model is the exact resolved video model.
	// Model 是精确解析的视频模型。
	Model string `json:"model"`
	// Prompt contains generation, edit, or continuation instructions.
	// Prompt 包含生成、编辑或续接指令。
	Prompt string `json:"prompt"`
	// Duration is the generation or extension duration in whole seconds.
	// Duration 是生成或延长的整秒时长。
	Duration int `json:"duration,omitempty"`
	// AspectRatio is one documented xAI ratio.
	// AspectRatio 是一个文档明确的 xAI 长宽比。
	AspectRatio string `json:"aspect_ratio,omitempty"`
	// Resolution is one documented xAI tier.
	// Resolution 是一个文档明确的 xAI 分辨率档位。
	Resolution string `json:"resolution,omitempty"`
	// Image is the sole first-frame input for image-to-video.
	// Image 是图片转视频的唯一首帧输入。
	Image *videoMediaSource `json:"image,omitempty"`
	// ReferenceImages contains ordered reference-to-video inputs.
	// ReferenceImages 包含有序参考图转视频输入。
	ReferenceImages []videoMediaSource `json:"reference_images,omitempty"`
	// Video is the sole edit or extension source.
	// Video 是唯一编辑或延长来源。
	Video *videoMediaSource `json:"video,omitempty"`
}

// videoMediaSource contains exactly one xAI media carrier.
// videoMediaSource 包含恰好一种 xAI 媒体载体。
type videoMediaSource struct {
	// URL contains a public HTTPS URL or Base64 data URI.
	// URL 包含公网 HTTPS URL 或 Base64 Data URI。
	URL string `json:"url,omitempty"`
	// FileID contains a provider-owned Files API identifier.
	// FileID 包含供应商所有的 Files API 标识。
	FileID string `json:"file_id,omitempty"`
}

// videoStartResponse is the closed xAI start response.
// videoStartResponse 是封闭的 xAI 创建响应。
type videoStartResponse struct {
	// RequestID is the private asynchronous task identifier.
	// RequestID 是私有异步任务标识。
	RequestID string `json:"request_id"`
}

// videoPollResponse is the closed xAI task observation.
// videoPollResponse 是封闭的 xAI 任务观测。
type videoPollResponse struct {
	// Status is pending, done, expired, or failed.
	// Status 为 pending、done、expired 或 failed。
	Status string `json:"status"`
	// Video contains completed output facts.
	// Video 包含已完成输出事实。
	Video *videoOutput `json:"video,omitempty"`
	// Error contains a safe provider classification for failed tasks.
	// Error 包含失败任务的安全供应商分类。
	Error *videoError `json:"error,omitempty"`
}

// videoOutput contains one temporary xAI result URL.
// videoOutput 包含一个临时 xAI 结果 URL。
type videoOutput struct {
	// URL is the temporary MP4 download URL.
	// URL 是临时 MP4 下载 URL。
	URL string `json:"url"`
}

// videoError contains xAI's documented safe error code.
// videoError 包含 xAI 文档明确的安全错误码。
type videoError struct {
	// Code classifies the provider failure without exposing request content.
	// Code 对供应商失败分类且不暴露请求内容。
	Code string `json:"code"`
}

// projectVideoStart maps one closed VCP video action to an xAI JSON request.
// projectVideoStart 将一个封闭 VCP 视频动作映射为 xAI JSON 请求。
func projectVideoStart(execution provider.ExecutionRequest, actionBindingID string) (transport.Request, error) {
	body := videoRequest{Model: execution.Binding.Target.UpstreamModelID}
	path := ""
	switch actionBindingID {
	case VideoGenerateActionBindingID:
		operation := execution.Execution.Payload.VideoGenerate
		if operation == nil {
			return transport.Request{}, ErrInvalidVideoDriver
		}
		if operation.Width != 0 || operation.Height != 0 || operation.FramesPerSecond != 0 || operation.Seed != nil || operation.Watermark != nil || operation.Count > 1 || (operation.OutputFormat != "" && operation.OutputFormat != "mp4") {
			return transport.Request{}, fmt.Errorf("%w: width, height, frame rate, seed, watermark, multiple outputs, or non-MP4 output has no xAI carrier", ErrInvalidVideoDriver)
		}
		duration, errDuration := exactWholeSeconds(operation.DurationSeconds, 1, 15, true)
		if errDuration != nil || !supportedVideoAspectRatio(operation.AspectRatio) || !supportedVideoResolution(operation.Resolution) {
			return transport.Request{}, fmt.Errorf("%w: generation duration, aspect ratio, or resolution is unsupported", ErrInvalidVideoDriver)
		}
		body.Prompt, body.Duration, body.AspectRatio, body.Resolution = operation.Prompt, duration, operation.AspectRatio, operation.Resolution
		if errInputs := projectVideoGenerationInputs(&body, operation.Inputs, execution.MaterializedInputs); errInputs != nil {
			return transport.Request{}, errInputs
		}
		if len(body.ReferenceImages) > 0 && body.Duration > 10 {
			return transport.Request{}, fmt.Errorf("%w: reference-to-video duration cannot exceed ten seconds", ErrInvalidVideoDriver)
		}
		path = "/v1/videos/generations"
	case VideoEditActionBindingID:
		operation := execution.Execution.Payload.VideoEdit
		if operation == nil || len(operation.References) != 0 {
			return transport.Request{}, fmt.Errorf("%w: xAI video editing does not accept reference inputs", ErrInvalidVideoDriver)
		}
		source, errSource := exactVideoMediaSource(operation.Source, execution.MaterializedInputs)
		if errSource != nil {
			return transport.Request{}, errSource
		}
		body.Prompt, body.Video, path = operation.Instruction, &source, "/v1/videos/edits"
	case VideoExtendActionBindingID:
		operation := execution.Execution.Payload.VideoExtend
		if operation == nil {
			return transport.Request{}, ErrInvalidVideoDriver
		}
		duration, errDuration := exactWholeSeconds(operation.AdditionalDurationSeconds, 2, 10, false)
		if errDuration != nil {
			return transport.Request{}, fmt.Errorf("%w: extension duration must be a whole number from two through ten seconds", ErrInvalidVideoDriver)
		}
		source, errSource := exactVideoMediaSource(operation.Source, execution.MaterializedInputs)
		if errSource != nil {
			return transport.Request{}, errSource
		}
		body.Prompt, body.Duration, body.Video, path = operation.Prompt, duration, &source, "/v1/videos/extensions"
	default:
		return transport.Request{}, ErrInvalidVideoDriver
	}
	encoded, errEncode := json.Marshal(body)
	if errEncode != nil {
		return transport.Request{}, errEncode
	}
	return transport.Request{Binding: execution.Binding, Method: http.MethodPost, Path: path, Body: encoded, Headers: []transport.Header{{Name: "Content-Type", Value: "application/json"}}, Authentication: transport.Authentication{Mode: transport.AuthenticationBearer}, IdempotencyKey: execution.Execution.IdempotencyKey}, nil
}

// projectVideoGenerationInputs maps either one first frame or up to seven references without combining modes.
// projectVideoGenerationInputs 映射一个首帧或最多七张参考图且不组合模式。
func projectVideoGenerationInputs(body *videoRequest, inputs []vcp.MediaInput, materialized []resource.MaterializedInput) error {
	for _, input := range inputs {
		source, errSource := exactVideoMediaSource(input, materialized)
		if errSource != nil {
			return errSource
		}
		if input.Kind != vcp.MediaImage {
			return fmt.Errorf("%w: xAI video generation inputs must be images", ErrInvalidVideoDriver)
		}
		switch input.Role {
		case vcp.MediaRoleFirstFrame:
			if body.Image != nil || len(body.ReferenceImages) != 0 {
				return fmt.Errorf("%w: first-frame and reference modes cannot be combined", ErrInvalidVideoDriver)
			}
			body.Image = &source
		case vcp.MediaRoleReference:
			if body.Image != nil || len(body.ReferenceImages) >= 7 {
				return fmt.Errorf("%w: reference mode accepts at most seven images and cannot include a first frame", ErrInvalidVideoDriver)
			}
			body.ReferenceImages = append(body.ReferenceImages, source)
		default:
			return fmt.Errorf("%w: unsupported xAI video input role %q", ErrInvalidVideoDriver, input.Role)
		}
	}
	return nil
}

// exactVideoMediaSource resolves one canonical input to its exact frozen materialization.
// exactVideoMediaSource 将一个规范输入解析为其精确冻结物化表示。
func exactVideoMediaSource(input vcp.MediaInput, materialized []resource.MaterializedInput) (videoMediaSource, error) {
	for _, value := range materialized {
		if value.InputID != input.ID {
			continue
		}
		if value.ResourceID != input.Resource.ResourceID || value.Kind != input.Kind || value.Role != input.Role {
			return videoMediaSource{}, fmt.Errorf("%w: materialized input %q differs from canonical identity", ErrInvalidVideoDriver, input.ID)
		}
		switch value.Mode {
		case catalog.MaterializationDirectRemoteURL:
			if strings.TrimSpace(value.RemoteURL) == "" {
				return videoMediaSource{}, fmt.Errorf("%w: direct URL materialization is empty", ErrInvalidVideoDriver)
			}
			return videoMediaSource{URL: value.RemoteURL}, nil
		case catalog.MaterializationInlineBase64:
			if strings.TrimSpace(value.InlineBase64) == "" || strings.TrimSpace(value.MIMEType) == "" {
				return videoMediaSource{}, fmt.Errorf("%w: inline media materialization is incomplete", ErrInvalidVideoDriver)
			}
			return videoMediaSource{URL: "data:" + value.MIMEType + ";base64," + value.InlineBase64}, nil
		case catalog.MaterializationProviderFileID:
			if strings.TrimSpace(value.ProviderHandle) == "" {
				return videoMediaSource{}, fmt.Errorf("%w: provider file materialization is empty", ErrInvalidVideoDriver)
			}
			return videoMediaSource{FileID: value.ProviderHandle}, nil
		default:
			return videoMediaSource{}, fmt.Errorf("%w: unsupported xAI media materialization %q", ErrInvalidVideoDriver, value.Mode)
		}
	}
	return videoMediaSource{}, fmt.Errorf("%w: media input %q has no exact materialization", ErrInvalidVideoDriver, input.ID)
}

// exactWholeSeconds validates one optional or required integral duration range.
// exactWholeSeconds 校验一个可选或必需的整秒时长范围。
func exactWholeSeconds(value float64, minimum int, maximum int, optional bool) (int, error) {
	if value == 0 && optional {
		return 0, nil
	}
	seconds := int(value)
	if value != float64(seconds) || seconds < minimum || seconds > maximum {
		return 0, ErrInvalidVideoDriver
	}
	return seconds, nil
}

// supportedVideoAspectRatio reports whether one ratio belongs to xAI's documented closed set.
// supportedVideoAspectRatio 报告一个长宽比是否属于 xAI 文档明确的封闭集合。
func supportedVideoAspectRatio(value string) bool {
	switch value {
	case "", "1:1", "16:9", "9:16", "4:3", "3:4", "3:2", "2:3":
		return true
	default:
		return false
	}
}

// supportedVideoResolution reports whether one tier belongs to xAI's documented closed set.
// supportedVideoResolution 报告一个分辨率档位是否属于 xAI 文档明确的封闭集合。
func supportedVideoResolution(value string) bool {
	return value == "" || value == "480p" || value == "720p"
}

// supportedXAIAction reports whether one action identifier is implemented by this driver.
// supportedXAIAction 报告一个动作标识是否由此 Driver 实现。
func supportedXAIAction(value string) bool {
	return value == VideoGenerateActionBindingID || value == VideoEditActionBindingID || value == VideoExtendActionBindingID
}

// decodeVideoStart decodes one private xAI request identifier.
// decodeVideoStart 解码一个私有 xAI 请求标识。
func decodeVideoStart(reader io.Reader, now time.Time) (provider.TaskResult, error) {
	var response videoStartResponse
	if errDecode := json.NewDecoder(reader).Decode(&response); errDecode != nil || strings.TrimSpace(response.RequestID) == "" {
		return provider.TaskResult{}, fmt.Errorf("%w: missing request_id", ErrInvalidVideoResponse)
	}
	return provider.TaskResult{ProviderTaskID: response.RequestID, State: provider.TaskQueued, PollAfter: now.UTC().Add(5 * time.Second)}, nil
}

// decodeVideoPoll converts xAI's documented states into the Router task state machine.
// decodeVideoPoll 将 xAI 文档明确的状态转换为 Router 任务状态机。
func decodeVideoPoll(reader io.Reader, providerTaskID string, now time.Time) (provider.TaskResult, error) {
	var response videoPollResponse
	if errDecode := json.NewDecoder(reader).Decode(&response); errDecode != nil {
		return provider.TaskResult{}, fmt.Errorf("%w: decode task: %v", ErrInvalidVideoResponse, errDecode)
	}
	switch response.Status {
	case "pending":
		return provider.TaskResult{ProviderTaskID: providerTaskID, State: provider.TaskRunning, PollAfter: now.UTC().Add(5 * time.Second)}, nil
	case "done":
		if response.Video == nil || strings.TrimSpace(response.Video.URL) == "" {
			return provider.TaskResult{}, fmt.Errorf("%w: completed task has no video URL", ErrInvalidVideoResponse)
		}
		result := provider.ExecutionResult{GeneratedResources: []provider.GeneratedResource{{OutputID: "video-0", Kind: vcp.MediaVideo, MIMEType: "video/mp4", DownloadURL: response.Video.URL}}}
		return provider.TaskResult{ProviderTaskID: providerTaskID, State: provider.TaskSucceeded, Result: &result}, nil
	case "expired":
		return provider.TaskResult{ProviderTaskID: providerTaskID, State: provider.TaskFailed, ErrorCode: "provider_task_expired"}, nil
	case "failed":
		// retryable is derived only from the documented closed provider classification while the public code remains stable.
		// retryable 仅根据文档明确的封闭供应商分类推导，而公开错误码保持稳定。
		retryable := response.Error != nil && (response.Error.Code == "service_unavailable" || response.Error.Code == "internal_error")
		return provider.TaskResult{ProviderTaskID: providerTaskID, State: provider.TaskFailed, ErrorCode: "xai_video_generation_failed", Retryable: retryable}, nil
	default:
		return provider.TaskResult{}, fmt.Errorf("%w: unknown task status %q", ErrInvalidVideoResponse, response.Status)
	}
}
