package minimax

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
	// VideoGenerateActionBindingID identifies MiniMax asynchronous video generation.
	// VideoGenerateActionBindingID 标识 MiniMax 异步视频生成动作。
	VideoGenerateActionBindingID = "action_minimax_video_generate"
	// VideoGenerateProtocolProfileID identifies the MiniMax video wire contract.
	// VideoGenerateProtocolProfileID 标识 MiniMax 视频 Wire 合同。
	VideoGenerateProtocolProfileID = "minimax.video.generate.v1"
)

var (
	// ErrInvalidVideoDriver reports an unsupported MiniMax video request.
	// ErrInvalidVideoDriver 表示不受支持的 MiniMax 视频请求。
	ErrInvalidVideoDriver = errors.New("invalid MiniMax video driver")
	// ErrInvalidVideoResponse reports malformed MiniMax task output.
	// ErrInvalidVideoResponse 表示格式错误的 MiniMax 任务输出。
	ErrInvalidVideoResponse = errors.New("invalid MiniMax video response")
)

// VideoTaskDriver owns MiniMax video task creation, polling, and file resolution.
// VideoTaskDriver 拥有 MiniMax 视频任务创建、轮询与文件解析。
type VideoTaskDriver struct {
	// definitionID is the sole immutable provider definition.
	// definitionID 是唯一不可变供应商 Definition。
	definitionID string
	// client performs provider-scoped authenticated requests.
	// client 执行供应商作用域的认证请求。
	client *transport.Client
}

// NewVideoTaskDriver creates a MiniMax asynchronous video driver.
// NewVideoTaskDriver 创建 MiniMax 异步视频 Driver。
func NewVideoTaskDriver(definitionID string, client *transport.Client) (*VideoTaskDriver, error) {
	if strings.TrimSpace(definitionID) == "" || client == nil {
		return nil, ErrInvalidVideoDriver
	}
	return &VideoTaskDriver{definitionID: definitionID, client: client}, nil
}

// ProviderDefinitionID returns the sole owning definition.
// ProviderDefinitionID 返回唯一拥有 Definition。
func (d *VideoTaskDriver) ProviderDefinitionID() string { return d.definitionID }

// ActionBindingID returns the sole owning action.
// ActionBindingID 返回唯一拥有动作。
func (d *VideoTaskDriver) ActionBindingID() string { return VideoGenerateActionBindingID }

// Start creates one MiniMax video task.
// Start 创建一个 MiniMax 视频任务。
func (d *VideoTaskDriver) Start(ctx context.Context, execution provider.ExecutionRequest) (provider.TaskResult, error) {
	if errValidate := d.validateExecution(execution); errValidate != nil {
		return provider.TaskResult{}, errValidate
	}
	request, errProject := projectVideoStart(execution)
	if errProject != nil {
		return provider.TaskResult{}, errProject
	}
	response, errRequest := d.client.Do(ctx, request)
	if errRequest != nil {
		return provider.TaskResult{}, errRequest
	}
	defer func() { _ = transport.DrainAndClose(response) }()
	return decodeVideoStart(response.Body, execution.Now)
}

// Poll observes one task and resolves its successful file identifier to a temporary URL.
// Poll 观察一个任务并将其成功文件标识解析为临时 URL。
func (d *VideoTaskDriver) Poll(ctx context.Context, execution provider.ExecutionRequest, providerTaskID string) (provider.TaskResult, error) {
	if errValidate := d.validateExecution(execution); errValidate != nil {
		return provider.TaskResult{}, errValidate
	}
	if strings.TrimSpace(providerTaskID) == "" {
		return provider.TaskResult{}, fmt.Errorf("%w: provider task identifier is required", ErrInvalidVideoDriver)
	}
	response, errRequest := d.client.Do(ctx, transport.Request{Binding: execution.Binding, Method: http.MethodGet, Path: "/v1/query/video_generation?task_id=" + url.QueryEscape(providerTaskID), Authentication: transport.Authentication{Mode: transport.AuthenticationBearer}})
	if errRequest != nil {
		return provider.TaskResult{}, errRequest
	}
	defer func() { _ = transport.DrainAndClose(response) }()
	observation, fileID, errDecode := decodeVideoPoll(response.Body, providerTaskID, execution.Now)
	if errDecode != nil || observation.State != provider.TaskSucceeded || observation.Result != nil {
		return observation, errDecode
	}
	fileResponse, errFile := d.client.Do(ctx, transport.Request{Binding: execution.Binding, Method: http.MethodGet, Path: "/v1/files/retrieve?file_id=" + url.QueryEscape(fileID), Authentication: transport.Authentication{Mode: transport.AuthenticationBearer}})
	if errFile != nil {
		return provider.TaskResult{}, errFile
	}
	defer func() { _ = transport.DrainAndClose(fileResponse) }()
	return decodeVideoFile(fileResponse.Body, providerTaskID)
}

// Cancel reports MiniMax's documented lack of a video task cancellation endpoint.
// Cancel 报告 MiniMax 文档中缺少视频任务取消端点。
func (d *VideoTaskDriver) Cancel(_ context.Context, execution provider.ExecutionRequest, providerTaskID string) (provider.TaskResult, error) {
	if errValidate := d.validateExecution(execution); errValidate != nil {
		return provider.TaskResult{}, errValidate
	}
	if strings.TrimSpace(providerTaskID) == "" {
		return provider.TaskResult{}, fmt.Errorf("%w: provider task identifier is required", ErrInvalidVideoDriver)
	}
	return provider.TaskResult{}, fmt.Errorf("%w: MiniMax does not document video task cancellation", ErrInvalidVideoDriver)
}

// validateExecution verifies exact definition, action, and API-key ownership.
// validateExecution 校验精确 Definition、动作与 API Key 归属。
func (d *VideoTaskDriver) validateExecution(execution provider.ExecutionRequest) error {
	if d == nil || d.client == nil || execution.Binding.Target.ProviderDefinitionID != d.definitionID {
		return fmt.Errorf("%w: target definition does not belong to this driver", provider.ErrExecutionBinding)
	}
	_, errValidate := execution.ValidateForAction(VideoGenerateActionBindingID, providerconfig.AuthMethodAPIKey)
	return errValidate
}

// videoRequest is the closed MiniMax video generation request.
// videoRequest 是封闭的 MiniMax 视频生成请求。
type videoRequest struct {
	// Model is the exact resolved video model.
	// Model 是精确解析的视频模型。
	Model string `json:"model"`
	// Prompt describes the generated motion.
	// Prompt 描述生成的运动。
	Prompt string `json:"prompt"`
	// FirstFrameImage is an optional URL or Base64 data URL.
	// FirstFrameImage 是可选 URL 或 Base64 Data URL。
	FirstFrameImage string `json:"first_frame_image,omitempty"`
	// LastFrameImage is an optional final-frame URL or Base64 data URL.
	// LastFrameImage 是可选末帧 URL 或 Base64 Data URL。
	LastFrameImage string `json:"last_frame_image,omitempty"`
	// Duration is six or ten seconds.
	// Duration 为六秒或十秒。
	Duration int `json:"duration,omitempty"`
	// Resolution is a model-scoped output tier.
	// Resolution 是模型作用域的输出档位。
	Resolution string `json:"resolution,omitempty"`
	// PromptOptimizer controls provider-native prompt optimization.
	// PromptOptimizer 控制供应商原生提示词优化。
	PromptOptimizer *bool `json:"prompt_optimizer,omitempty"`
}

// videoBaseResponse contains MiniMax's stable application status.
// videoBaseResponse 包含 MiniMax 稳定的应用状态。
type videoBaseResponse struct {
	// StatusCode is zero on success.
	// StatusCode 成功时为零。
	StatusCode int `json:"status_code"`
}

// videoStartResponse contains the private task identity.
// videoStartResponse 包含私有任务标识。
type videoStartResponse struct {
	// TaskID is the private provider task identifier.
	// TaskID 是私有供应商任务标识。
	TaskID string `json:"task_id"`
	// BaseResponse records application-level success.
	// BaseResponse 记录应用层成功状态。
	BaseResponse videoBaseResponse `json:"base_resp"`
}

// videoPollResponse contains one documented task observation.
// videoPollResponse 包含一次文档明确的任务观测。
type videoPollResponse struct {
	// Status is Preparing, Queueing, Processing, Success, or Fail.
	// Status 为 Preparing、Queueing、Processing、Success 或 Fail。
	Status string `json:"status"`
	// FileID is returned only after success.
	// FileID 仅在成功后返回。
	FileID string `json:"file_id,omitempty"`
	// BaseResponse records application-level success.
	// BaseResponse 记录应用层成功状态。
	BaseResponse videoBaseResponse `json:"base_resp"`
}

// videoFileResponse contains the temporary generated-file URL.
// videoFileResponse 包含生成文件的临时 URL。
type videoFileResponse struct {
	// File contains resolved file metadata.
	// File 包含解析后的文件元数据。
	File struct {
		// DownloadURL is the temporary provider URL.
		// DownloadURL 是供应商临时 URL。
		DownloadURL string `json:"download_url"`
	} `json:"file"`
	// BaseResponse records application-level success.
	// BaseResponse 记录应用层成功状态。
	BaseResponse videoBaseResponse `json:"base_resp"`
}

// projectVideoStart maps canonical text, first-frame, and last-frame modes.
// projectVideoStart 映射规范文本、首帧与末帧模式。
func projectVideoStart(execution provider.ExecutionRequest) (transport.Request, error) {
	operation := execution.Execution.Payload.VideoGenerate
	if operation == nil || (strings.TrimSpace(operation.Prompt) == "" && len(operation.Inputs) == 0) || len(operation.Prompt) > 2000 || operation.NegativePrompt != "" || operation.AspectRatio != "" || operation.Width != 0 || operation.Height != 0 || operation.FramesPerSecond != 0 || operation.Seed != nil || operation.Watermark != nil || operation.Count > 1 || (operation.OutputFormat != "" && operation.OutputFormat != "mp4") {
		return transport.Request{}, ErrInvalidVideoDriver
	}
	duration := int(operation.DurationSeconds)
	if duration == 0 {
		duration = 6
	}
	if operation.DurationSeconds != 0 && operation.DurationSeconds != float64(duration) {
		return transport.Request{}, fmt.Errorf("%w: duration must be integral", ErrInvalidVideoDriver)
	}
	body := videoRequest{Model: execution.Binding.Target.UpstreamModelID, Prompt: operation.Prompt, Duration: duration, Resolution: strings.ToUpper(operation.Resolution), PromptOptimizer: operation.PromptExtend}
	for _, input := range operation.Inputs {
		if input.Kind != vcp.MediaImage {
			return transport.Request{}, fmt.Errorf("%w: video inputs must be images", ErrInvalidVideoDriver)
		}
		image, errImage := exactVideoImage(input, execution.MaterializedInputs)
		if errImage != nil {
			return transport.Request{}, errImage
		}
		switch input.Role {
		case vcp.MediaRoleFirstFrame:
			if body.FirstFrameImage != "" {
				return transport.Request{}, fmt.Errorf("%w: duplicate first frame", ErrInvalidVideoDriver)
			}
			body.FirstFrameImage = image
		case vcp.MediaRoleLastFrame:
			if body.LastFrameImage != "" {
				return transport.Request{}, fmt.Errorf("%w: duplicate last frame", ErrInvalidVideoDriver)
			}
			body.LastFrameImage = image
		default:
			return transport.Request{}, fmt.Errorf("%w: unsupported image role", ErrInvalidVideoDriver)
		}
	}
	if body.LastFrameImage != "" && body.FirstFrameImage == "" {
		return transport.Request{}, fmt.Errorf("%w: last frame requires first frame", ErrInvalidVideoDriver)
	}
	if errModel := validateVideoModelControls(body); errModel != nil {
		return transport.Request{}, errModel
	}
	encoded, errEncode := json.Marshal(body)
	if errEncode != nil {
		return transport.Request{}, errEncode
	}
	return transport.Request{Binding: execution.Binding, Method: http.MethodPost, Path: "/v1/video_generation", Headers: []transport.Header{{Name: "Content-Type", Value: "application/json"}}, Body: encoded, Authentication: transport.Authentication{Mode: transport.AuthenticationBearer}, IdempotencyKey: execution.Execution.IdempotencyKey}, nil
}

// validateVideoModelControls enforces MiniMax's model-by-mode duration and resolution matrix.
// validateVideoModelControls 强制执行 MiniMax 按模型与模式划分的时长及分辨率矩阵。
func validateVideoModelControls(body videoRequest) error {
	imageMode := body.FirstFrameImage != ""
	switch body.Model {
	case "MiniMax-Hailuo-2.3":
	case "MiniMax-Hailuo-2.3-Fast":
		if !imageMode {
			return fmt.Errorf("%w: fast model requires a first frame", ErrInvalidVideoDriver)
		}
	case "MiniMax-Hailuo-02":
	default:
		return fmt.Errorf("%w: unsupported video model", ErrInvalidVideoDriver)
	}
	if body.LastFrameImage != "" && body.Model != "MiniMax-Hailuo-02" {
		return fmt.Errorf("%w: first-and-last-frame mode requires MiniMax-Hailuo-02", ErrInvalidVideoDriver)
	}
	if body.Duration != 6 && body.Duration != 10 {
		return fmt.Errorf("%w: duration must be six or ten seconds", ErrInvalidVideoDriver)
	}
	if body.Duration == 10 && body.Resolution != "" && body.Resolution != "768P" && !(imageMode && body.Model == "MiniMax-Hailuo-02" && body.Resolution == "512P") {
		return fmt.Errorf("%w: ten-second resolution is unsupported", ErrInvalidVideoDriver)
	}
	if body.Resolution != "" && body.Resolution != "768P" && body.Resolution != "1080P" && !(imageMode && body.Model == "MiniMax-Hailuo-02" && body.Resolution == "512P") {
		return fmt.Errorf("%w: unsupported resolution", ErrInvalidVideoDriver)
	}
	return nil
}

// exactVideoImage resolves one exact public URL or Base64 data URL materialization.
// exactVideoImage 解析一个精确公网 URL 或 Base64 Data URL 物化结果。
func exactVideoImage(input vcp.MediaInput, materialized []resource.MaterializedInput) (string, error) {
	for _, value := range materialized {
		if value.InputID != input.ID {
			continue
		}
		if value.ResourceID != input.Resource.ResourceID || value.Kind != input.Kind || value.Role != input.Role {
			return "", fmt.Errorf("%w: image materialization differs from canonical identity", ErrInvalidVideoDriver)
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
		return "", fmt.Errorf("%w: unsupported image materialization", ErrInvalidVideoDriver)
	}
	return "", fmt.Errorf("%w: image input has no exact materialization", ErrInvalidVideoDriver)
}

// decodeVideoStart decodes one successful task creation.
// decodeVideoStart 解码一次成功任务创建。
func decodeVideoStart(reader io.Reader, now time.Time) (provider.TaskResult, error) {
	var response videoStartResponse
	if errDecode := json.NewDecoder(reader).Decode(&response); errDecode != nil || response.BaseResponse.StatusCode != 0 || strings.TrimSpace(response.TaskID) == "" {
		return provider.TaskResult{}, fmt.Errorf("%w: missing successful task", ErrInvalidVideoResponse)
	}
	return provider.TaskResult{ProviderTaskID: response.TaskID, State: provider.TaskQueued, PollAfter: now.UTC().Add(10 * time.Second)}, nil
}

// decodeVideoPoll maps provider states and returns the private file ID separately.
// decodeVideoPoll 映射供应商状态并单独返回私有文件 ID。
func decodeVideoPoll(reader io.Reader, providerTaskID string, now time.Time) (provider.TaskResult, string, error) {
	var response videoPollResponse
	if errDecode := json.NewDecoder(reader).Decode(&response); errDecode != nil || response.BaseResponse.StatusCode != 0 {
		return provider.TaskResult{}, "", fmt.Errorf("%w: invalid task observation", ErrInvalidVideoResponse)
	}
	switch response.Status {
	case "Preparing", "Queueing":
		return provider.TaskResult{ProviderTaskID: providerTaskID, State: provider.TaskQueued, PollAfter: now.UTC().Add(10 * time.Second)}, "", nil
	case "Processing":
		return provider.TaskResult{ProviderTaskID: providerTaskID, State: provider.TaskRunning, PollAfter: now.UTC().Add(10 * time.Second)}, "", nil
	case "Success":
		if strings.TrimSpace(response.FileID) == "" {
			return provider.TaskResult{}, "", fmt.Errorf("%w: successful task has no file ID", ErrInvalidVideoResponse)
		}
		return provider.TaskResult{ProviderTaskID: providerTaskID, State: provider.TaskSucceeded}, response.FileID, nil
	case "Fail":
		return provider.TaskResult{ProviderTaskID: providerTaskID, State: provider.TaskFailed, ErrorCode: "minimax_video_generation_failed"}, "", nil
	default:
		return provider.TaskResult{}, "", fmt.Errorf("%w: unknown task status %q", ErrInvalidVideoResponse, response.Status)
	}
}

// decodeVideoFile converts a private file lookup into one Router-importable result.
// decodeVideoFile 将私有文件查询转换为一个 Router 可导入结果。
func decodeVideoFile(reader io.Reader, providerTaskID string) (provider.TaskResult, error) {
	var response videoFileResponse
	if errDecode := json.NewDecoder(reader).Decode(&response); errDecode != nil || response.BaseResponse.StatusCode != 0 || strings.TrimSpace(response.File.DownloadURL) == "" {
		return provider.TaskResult{}, fmt.Errorf("%w: missing successful file URL", ErrInvalidVideoResponse)
	}
	result := provider.ExecutionResult{GeneratedResources: []provider.GeneratedResource{{OutputID: "video-0", Kind: vcp.MediaVideo, MIMEType: "video/mp4", DownloadURL: response.File.DownloadURL}}}
	return provider.TaskResult{ProviderTaskID: providerTaskID, State: provider.TaskSucceeded, Result: &result}, nil
}
