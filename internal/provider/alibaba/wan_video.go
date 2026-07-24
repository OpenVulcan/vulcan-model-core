package alibaba

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
	// WanVideoGenerateActionBindingID identifies workspace-scoped Wan 2.7 text-to-video.
	// WanVideoGenerateActionBindingID 标识工作空间作用域的 Wan 2.7 文生视频动作。
	WanVideoGenerateActionBindingID = "action_alibaba_wan_video_generate"
	// WanVideoGenerateProtocolProfileID identifies the Wan 2.7 video wire contract.
	// WanVideoGenerateProtocolProfileID 标识 Wan 2.7 视频 Wire 合同。
	WanVideoGenerateProtocolProfileID = "alibaba.wan.video.generate.v2.7"
)

var (
	// ErrInvalidWanVideoDriver reports an unsupported Wan video request.
	// ErrInvalidWanVideoDriver 表示不受支持的 Wan 视频请求。
	ErrInvalidWanVideoDriver = errors.New("invalid Alibaba Wan video driver")
	// ErrInvalidWanVideoResponse reports malformed Wan task output.
	// ErrInvalidWanVideoResponse 表示格式错误的 Wan 任务输出。
	ErrInvalidWanVideoResponse = errors.New("invalid Alibaba Wan video response")
)

// WanVideoTaskDriver owns the complete Wan asynchronous lifecycle for one workspace definition.
// WanVideoTaskDriver 为一个工作空间 Definition 拥有完整的 Wan 异步生命周期。
type WanVideoTaskDriver struct {
	// definitionID is the immutable workspace provider definition.
	// definitionID 是不可变的工作空间供应商 Definition。
	definitionID string
	// client performs provider-scoped authenticated requests.
	// client 执行供应商作用域的认证请求。
	client *transport.Client
}

// NewWanVideoTaskDriver creates a workspace-scoped Wan 2.7 video driver.
// NewWanVideoTaskDriver 创建工作空间作用域的 Wan 2.7 视频 Driver。
func NewWanVideoTaskDriver(definitionID string, client *transport.Client) (*WanVideoTaskDriver, error) {
	if strings.TrimSpace(definitionID) == "" || client == nil {
		return nil, ErrInvalidWanVideoDriver
	}
	return &WanVideoTaskDriver{definitionID: definitionID, client: client}, nil
}

// ProviderDefinitionID returns the sole provider definition owned by this driver.
// ProviderDefinitionID 返回此 Driver 唯一拥有的供应商 Definition。
func (d *WanVideoTaskDriver) ProviderDefinitionID() string {
	if d == nil {
		return ""
	}
	return d.definitionID
}

// ActionBindingID returns the sole action binding owned by this driver.
// ActionBindingID 返回此 Driver 唯一拥有的动作绑定。
func (d *WanVideoTaskDriver) ActionBindingID() string { return WanVideoGenerateActionBindingID }

// Start submits one Wan task and preserves the private provider task identifier.
// Start 提交一个 Wan 任务并保留私有供应商任务标识。
func (d *WanVideoTaskDriver) Start(ctx context.Context, execution provider.ExecutionRequest) (provider.TaskResult, error) {
	if errValidate := d.validateExecution(execution); errValidate != nil {
		return provider.TaskResult{}, errValidate
	}
	request, errProject := projectWanVideoStart(execution)
	if errProject != nil {
		return provider.TaskResult{}, errProject
	}
	response, errRequest := d.client.Do(ctx, request)
	if errRequest != nil {
		return provider.TaskResult{}, errRequest
	}
	defer func() { _ = transport.DrainAndClose(response) }()
	return decodeWanVideoStart(response.Body, execution.Now)
}

// Poll observes one Wan task through the same immutable target binding.
// Poll 通过同一不可变 Target Binding 观察一个 Wan 任务。
func (d *WanVideoTaskDriver) Poll(ctx context.Context, execution provider.ExecutionRequest, providerTaskID string) (provider.TaskResult, error) {
	if errValidate := d.validateExecution(execution); errValidate != nil {
		return provider.TaskResult{}, errValidate
	}
	if strings.TrimSpace(providerTaskID) == "" || strings.TrimSpace(providerTaskID) != providerTaskID {
		return provider.TaskResult{}, fmt.Errorf("%w: provider task identifier is required", ErrInvalidWanVideoDriver)
	}
	response, errRequest := d.client.Do(ctx, transport.Request{Binding: execution.Binding, Method: http.MethodGet, Path: "/api/v1/tasks/" + url.PathEscape(providerTaskID), Authentication: transport.Authentication{Mode: transport.AuthenticationBearer}})
	if errRequest != nil {
		return provider.TaskResult{}, errRequest
	}
	defer func() { _ = transport.DrainAndClose(response) }()
	return decodeWanVideoPoll(response.Body, providerTaskID, execution.Now)
}

// Cancel cancels a provider-confirmed queued Wan task.
// Cancel 取消供应商确认仍在排队的 Wan 任务。
func (d *WanVideoTaskDriver) Cancel(ctx context.Context, execution provider.ExecutionRequest, providerTaskID string) (provider.TaskResult, error) {
	if errValidate := d.validateExecution(execution); errValidate != nil {
		return provider.TaskResult{}, errValidate
	}
	if strings.TrimSpace(providerTaskID) == "" || strings.TrimSpace(providerTaskID) != providerTaskID {
		return provider.TaskResult{}, fmt.Errorf("%w: provider task identifier is required", ErrInvalidWanVideoDriver)
	}
	response, errRequest := d.client.Do(ctx, transport.Request{Binding: execution.Binding, Method: http.MethodPost, Path: "/api/v1/tasks/" + url.PathEscape(providerTaskID) + "/cancel", Authentication: transport.Authentication{Mode: transport.AuthenticationBearer}})
	if errRequest != nil {
		return provider.TaskResult{}, errRequest
	}
	defer func() { _ = transport.DrainAndClose(response) }()
	var result wanVideoCancelResponse
	if errDecode := decodeAlibabaJSONResponse(response.Body, &result, ErrInvalidWanVideoResponse); errDecode != nil {
		return provider.TaskResult{}, errDecode
	}
	if strings.TrimSpace(result.RequestID) == "" || strings.TrimSpace(result.Code) != "" {
		return provider.TaskResult{}, fmt.Errorf("%w: cancellation was not confirmed", ErrInvalidWanVideoResponse)
	}
	return provider.TaskResult{ProviderTaskID: providerTaskID, State: provider.TaskCancelled}, nil
}

// validateExecution verifies exact definition, action, and API-key ownership.
// validateExecution 校验精确 Definition、动作与 API Key 归属。
func (d *WanVideoTaskDriver) validateExecution(execution provider.ExecutionRequest) error {
	if d == nil || d.client == nil || execution.Binding.Target.ProviderDefinitionID != d.definitionID {
		return fmt.Errorf("%w: target definition does not belong to this driver", provider.ErrExecutionBinding)
	}
	_, errValidate := execution.ValidateForAction(WanVideoGenerateActionBindingID, providerconfig.AuthMethodAPIKey)
	return errValidate
}

// wanVideoRequest is the closed Wan 2.7 text-to-video request.
// wanVideoRequest 是封闭的 Wan 2.7 文生视频请求。
type wanVideoRequest struct {
	// Model is the exact resolved upstream model.
	// Model 是精确解析的上游模型。
	Model string `json:"model"`
	// Input contains text and an optional public audio URL.
	// Input 包含文本和可选的公网音频 URL。
	Input wanVideoInput `json:"input"`
	// Parameters contains only documented generation controls.
	// Parameters 仅包含文档明确的生成控制项。
	Parameters wanVideoParameters `json:"parameters"`
}

// wanVideoInput contains the semantic Wan video inputs.
// wanVideoInput 包含 Wan 视频语义输入。
type wanVideoInput struct {
	// Prompt is the required generation instruction.
	// Prompt 是必需的生成指令。
	Prompt string `json:"prompt"`
	// NegativePrompt describes content to exclude.
	// NegativePrompt 描述应排除的内容。
	NegativePrompt string `json:"negative_prompt,omitempty"`
	// AudioURL is an optional public WAV or MP3 URL.
	// AudioURL 是可选的公网 WAV 或 MP3 URL。
	AudioURL string `json:"audio_url,omitempty"`
	// Media contains the closed Wan 2.7 image-to-video asset combination.
	// Media 包含封闭的 Wan 2.7 图生视频素材组合。
	Media []wanVideoMedia `json:"media,omitempty"`
}

// wanVideoMedia carries one documented image-to-video asset role and URL.
// wanVideoMedia 携带一个文档明确的图生视频素材角色与 URL。
type wanVideoMedia struct {
	// Type is first_frame, last_frame, or driving_audio.
	// Type 为 first_frame、last_frame 或 driving_audio。
	Type string `json:"type"`
	// URL is a public URL or an image data URL where documented.
	// URL 为公网 URL，或在文档允许时为图片 Data URL。
	URL string `json:"url"`
}

// wanVideoParameters contains provider-native bounded controls.
// wanVideoParameters 包含供应商原生且有边界的控制项。
type wanVideoParameters struct {
	// Resolution is 720P or 1080P.
	// Resolution 为 720P 或 1080P。
	Resolution string `json:"resolution,omitempty"`
	// Ratio is one documented output ratio.
	// Ratio 是文档明确的输出比例。
	Ratio string `json:"ratio,omitempty"`
	// Duration is an integral duration from two through fifteen seconds.
	// Duration 是二至十五秒的整数时长。
	Duration int `json:"duration,omitempty"`
	// PromptExtend controls provider-native prompt rewriting.
	// PromptExtend 控制供应商原生提示词改写。
	PromptExtend *bool `json:"prompt_extend,omitempty"`
	// Watermark controls the AI-generated watermark.
	// Watermark 控制 AI 生成水印。
	Watermark *bool `json:"watermark,omitempty"`
	// Seed controls documented pseudo-random initialization.
	// Seed 控制文档明确的伪随机初始化。
	Seed *int64 `json:"seed,omitempty"`
}

// wanVideoTaskEnvelope is the closed start and poll response envelope.
// wanVideoTaskEnvelope 是封闭的创建与轮询响应信封。
type wanVideoTaskEnvelope struct {
	// Output contains task identity, status, output, or safe error code.
	// Output 包含任务标识、状态、输出或安全错误码。
	Output wanVideoTaskOutput `json:"output"`
}

// wanVideoTaskOutput contains one provider task observation.
// wanVideoTaskOutput 包含一次供应商任务观测。
type wanVideoTaskOutput struct {
	// TaskID is the private provider task identifier.
	// TaskID 是私有供应商任务标识。
	TaskID string `json:"task_id"`
	// TaskStatus is the documented uppercase lifecycle state.
	// TaskStatus 是文档明确的大写生命周期状态。
	TaskStatus string `json:"task_status"`
	// VideoURL is the temporary successful MP4 URL.
	// VideoURL 是成功结果的临时 MP4 URL。
	VideoURL string `json:"video_url,omitempty"`
	// Results contains the alternate successful resource envelope used by HappyHorse and some Wan revisions.
	// Results 包含 HappyHorse 与部分 Wan 修订使用的备用成功资源信封。
	Results []wanVideoTaskResource `json:"results,omitempty"`
	// Code is a safe provider failure classification.
	// Code 是安全的供应商失败分类。
	Code string `json:"code,omitempty"`
}

// wanVideoTaskResource contains one alternate provider video result.
// wanVideoTaskResource 包含一个供应商备用视频结果。
type wanVideoTaskResource struct {
	// URL is the temporary successful video URL.
	// URL 是成功结果的临时视频 URL。
	URL string `json:"url"`
}

// wanVideoCancelResponse contains cancellation confirmation metadata.
// wanVideoCancelResponse 包含取消确认元数据。
type wanVideoCancelResponse struct {
	// RequestID confirms the provider accepted the cancellation request.
	// RequestID 确认供应商已接受取消请求。
	RequestID string `json:"request_id"`
	// Code is non-empty when cancellation failed.
	// Code 在取消失败时非空。
	Code string `json:"code,omitempty"`
}

// projectWanVideoStart maps one canonical video request to Wan 2.7.
// projectWanVideoStart 将一个规范视频请求映射到 Wan 2.7。
func projectWanVideoStart(execution provider.ExecutionRequest) (transport.Request, error) {
	operation := execution.Execution.Payload.VideoGenerate
	model := execution.Binding.Target.UpstreamModelID
	if operation == nil || (model != "wan2.7-t2v" && model != "wan2.7-i2v") {
		return transport.Request{}, ErrInvalidWanVideoDriver
	}
	if model == "wan2.7-t2v" && strings.TrimSpace(operation.Prompt) == "" {
		return transport.Request{}, fmt.Errorf("%w: text-to-video requires a prompt", ErrInvalidWanVideoDriver)
	}
	if operation.Width != 0 || operation.Height != 0 || operation.FramesPerSecond != 0 || operation.Count > 1 || (operation.OutputFormat != "" && operation.OutputFormat != "mp4") {
		return transport.Request{}, fmt.Errorf("%w: exact dimensions, frame rate, multiple outputs, or non-MP4 output has no Wan carrier", ErrInvalidWanVideoDriver)
	}
	duration := int(operation.DurationSeconds)
	if operation.DurationSeconds != 0 && (operation.DurationSeconds != float64(duration) || duration < 2 || duration > 15) {
		return transport.Request{}, fmt.Errorf("%w: duration must be a whole number from two through fifteen seconds", ErrInvalidWanVideoDriver)
	}
	resolution := strings.ToUpper(operation.Resolution)
	if resolution != "" && resolution != "720P" && resolution != "1080P" {
		return transport.Request{}, fmt.Errorf("%w: unsupported resolution", ErrInvalidWanVideoDriver)
	}
	if (model == "wan2.7-i2v" && operation.AspectRatio != "") || !supportedWanVideoRatio(operation.AspectRatio) || (operation.Seed != nil && (*operation.Seed < 0 || *operation.Seed > 2147483647)) {
		return transport.Request{}, fmt.Errorf("%w: unsupported ratio or seed", ErrInvalidWanVideoDriver)
	}
	body := wanVideoRequest{Model: execution.Binding.Target.UpstreamModelID, Input: wanVideoInput{Prompt: operation.Prompt, NegativePrompt: operation.NegativePrompt}, Parameters: wanVideoParameters{Resolution: resolution, Ratio: operation.AspectRatio, Duration: duration, PromptExtend: operation.PromptExtend, Watermark: operation.Watermark, Seed: operation.Seed}}
	if model == "wan2.7-i2v" {
		if errMedia := projectWanImageVideoMedia(&body.Input, operation.Inputs, execution.MaterializedInputs); errMedia != nil {
			return transport.Request{}, errMedia
		}
		if len(body.Input.Media) == 0 {
			return transport.Request{}, fmt.Errorf("%w: image-to-video requires a first frame", ErrInvalidWanVideoDriver)
		}
	} else {
		for _, input := range operation.Inputs {
			if input.Kind != vcp.MediaAudio || input.Role != vcp.MediaRoleAudioTrack || body.Input.AudioURL != "" {
				return transport.Request{}, fmt.Errorf("%w: text-to-video accepts at most one audio-track input", ErrInvalidWanVideoDriver)
			}
			audioURL, errAudio := exactWanAudioURL(input, execution.MaterializedInputs)
			if errAudio != nil {
				return transport.Request{}, errAudio
			}
			body.Input.AudioURL = audioURL
		}
	}
	encoded, errEncode := json.Marshal(body)
	if errEncode != nil {
		return transport.Request{}, errEncode
	}
	return transport.Request{Binding: execution.Binding, Method: http.MethodPost, Path: "/api/v1/services/aigc/video-generation/video-synthesis", Headers: alibabaJSONHeaders(execution.MaterializedInputs, true), Body: encoded, Authentication: transport.Authentication{Mode: transport.AuthenticationBearer}, IdempotencyKey: execution.Execution.IdempotencyKey}, nil
}

// projectWanImageVideoMedia maps only documented first-frame, last-frame, and driving-audio combinations.
// projectWanImageVideoMedia 仅映射文档明确的首帧、尾帧与驱动音频组合。
func projectWanImageVideoMedia(target *wanVideoInput, inputs []vcp.MediaInput, materialized []resource.MaterializedInput) error {
	// roles freezes each exact semantic input before provider-canonical ordering.
	// roles 在按供应商规范排序前冻结每个精确语义输入。
	roles := make(map[string]wanVideoMedia, 3)
	for _, input := range inputs {
		mediaType := ""
		switch {
		case input.Kind == vcp.MediaImage && input.Role == vcp.MediaRoleFirstFrame:
			mediaType = "first_frame"
		case input.Kind == vcp.MediaImage && input.Role == vcp.MediaRoleLastFrame:
			mediaType = "last_frame"
		case input.Kind == vcp.MediaAudio && input.Role == vcp.MediaRoleAudioTrack:
			mediaType = "driving_audio"
		default:
			return fmt.Errorf("%w: unsupported image-to-video asset role", ErrInvalidWanVideoDriver)
		}
		if _, exists := roles[mediaType]; exists {
			return fmt.Errorf("%w: image-to-video asset roles must be unique", ErrInvalidWanVideoDriver)
		}
		mediaURL, errMedia := exactWanImageVideoURL(input, materialized)
		if errMedia != nil {
			return errMedia
		}
		roles[mediaType] = wanVideoMedia{Type: mediaType, URL: mediaURL}
	}
	if _, hasFirst := roles["first_frame"]; !hasFirst {
		return fmt.Errorf("%w: image-to-video requires a first frame", ErrInvalidWanVideoDriver)
	}
	for _, mediaType := range []string{"first_frame", "last_frame", "driving_audio"} {
		if media, exists := roles[mediaType]; exists {
			target.Media = append(target.Media, media)
		}
	}
	return nil
}

// exactWanImageVideoURL resolves image data URLs or exact public image/audio URLs.
// exactWanImageVideoURL 解析图片 Data URL 或精确的公网图片、音频 URL。
func exactWanImageVideoURL(input vcp.MediaInput, materialized []resource.MaterializedInput) (string, error) {
	for _, value := range materialized {
		if value.InputID != input.ID {
			continue
		}
		if value.ResourceID != input.Resource.ResourceID || value.Kind != input.Kind || value.Role != input.Role || strings.TrimSpace(value.MIMEType) == "" {
			return "", fmt.Errorf("%w: image-to-video media does not match its exact materialization", ErrInvalidWanVideoDriver)
		}
		if value.Mode == catalog.MaterializationDirectRemoteURL && strings.TrimSpace(value.RemoteURL) != "" {
			return value.RemoteURL, nil
		}
		if value.Mode == catalog.MaterializationProviderObjectURI {
			return alibabaObjectURI(value, ErrInvalidWanVideoDriver)
		}
		if input.Kind == vcp.MediaImage && value.Mode == catalog.MaterializationInlineBase64 && strings.TrimSpace(value.InlineBase64) != "" {
			return "data:" + value.MIMEType + ";base64," + value.InlineBase64, nil
		}
		return "", fmt.Errorf("%w: unsupported image-to-video materialization", ErrInvalidWanVideoDriver)
	}
	return "", fmt.Errorf("%w: image-to-video input has no exact materialization", ErrInvalidWanVideoDriver)
}

// exactWanAudioURL resolves the sole direct public audio materialization.
// exactWanAudioURL 解析唯一的公网音频直接物化结果。
func exactWanAudioURL(input vcp.MediaInput, materialized []resource.MaterializedInput) (string, error) {
	for _, value := range materialized {
		if value.InputID != input.ID {
			continue
		}
		if value.ResourceID != input.Resource.ResourceID || value.Kind != input.Kind || value.Role != input.Role {
			return "", fmt.Errorf("%w: audio input does not match its exact materialization", ErrInvalidWanVideoDriver)
		}
		if value.Mode == catalog.MaterializationProviderObjectURI {
			return alibabaObjectURI(value, ErrInvalidWanVideoDriver)
		}
		if value.Mode != catalog.MaterializationDirectRemoteURL || strings.TrimSpace(value.RemoteURL) == "" {
			return "", fmt.Errorf("%w: audio input requires its exact public URL or Alibaba object materialization", ErrInvalidWanVideoDriver)
		}
		return value.RemoteURL, nil
	}
	return "", fmt.Errorf("%w: audio input has no exact materialization", ErrInvalidWanVideoDriver)
}

// supportedWanVideoRatio reports membership in the documented closed ratio set.
// supportedWanVideoRatio 报告是否属于文档明确的封闭比例集合。
func supportedWanVideoRatio(value string) bool {
	switch value {
	case "", "16:9", "9:16", "1:1", "4:3", "3:4":
		return true
	default:
		return false
	}
}

// decodeWanVideoStart decodes the required queued task identity.
// decodeWanVideoStart 解码必需的排队任务标识。
func decodeWanVideoStart(reader io.Reader, now time.Time) (provider.TaskResult, error) {
	var response wanVideoTaskEnvelope
	if errDecode := decodeAlibabaJSONResponse(reader, &response, ErrInvalidWanVideoResponse); errDecode != nil {
		return provider.TaskResult{}, errDecode
	}
	if response.Output.TaskStatus != "PENDING" || strings.TrimSpace(response.Output.TaskID) == "" || strings.TrimSpace(response.Output.TaskID) != response.Output.TaskID {
		return provider.TaskResult{}, fmt.Errorf("%w: missing queued task", ErrInvalidWanVideoResponse)
	}
	return provider.TaskResult{ProviderTaskID: response.Output.TaskID, State: provider.TaskQueued, PollAfter: now.UTC().Add(15 * time.Second)}, nil
}

// decodeWanVideoPoll maps documented Wan states into Router task states.
// decodeWanVideoPoll 将文档明确的 Wan 状态映射到 Router 任务状态。
func decodeWanVideoPoll(reader io.Reader, providerTaskID string, now time.Time) (provider.TaskResult, error) {
	var response wanVideoTaskEnvelope
	if errDecode := decodeAlibabaJSONResponse(reader, &response, ErrInvalidWanVideoResponse); errDecode != nil {
		return provider.TaskResult{}, errDecode
	}
	if response.Output.TaskID != providerTaskID {
		return provider.TaskResult{}, fmt.Errorf("%w: task response correlation is invalid", ErrInvalidWanVideoResponse)
	}
	switch response.Output.TaskStatus {
	case "PENDING":
		return provider.TaskResult{ProviderTaskID: providerTaskID, State: provider.TaskQueued, PollAfter: now.UTC().Add(15 * time.Second)}, nil
	case "RUNNING":
		return provider.TaskResult{ProviderTaskID: providerTaskID, State: provider.TaskRunning, PollAfter: now.UTC().Add(15 * time.Second)}, nil
	case "SUCCEEDED":
		videoURL := strings.TrimSpace(response.Output.VideoURL)
		if videoURL == "" && len(response.Output.Results) > 0 {
			videoURL = strings.TrimSpace(response.Output.Results[0].URL)
		}
		if videoURL == "" {
			return provider.TaskResult{}, fmt.Errorf("%w: completed task has no video URL", ErrInvalidWanVideoResponse)
		}
		result := provider.ExecutionResult{GeneratedResources: []provider.GeneratedResource{{OutputID: "video-0", Kind: vcp.MediaVideo, MIMEType: "video/mp4", DownloadURL: videoURL}}}
		return provider.TaskResult{ProviderTaskID: providerTaskID, State: provider.TaskSucceeded, Result: &result}, nil
	case "FAILED", "UNKNOWN":
		return provider.TaskResult{ProviderTaskID: providerTaskID, State: provider.TaskFailed, ErrorCode: "alibaba_video_generation_failed"}, nil
	case "CANCELED":
		return provider.TaskResult{ProviderTaskID: providerTaskID, State: provider.TaskCancelled}, nil
	default:
		return provider.TaskResult{}, fmt.Errorf("%w: unknown task status %q", ErrInvalidWanVideoResponse, response.Output.TaskStatus)
	}
}
