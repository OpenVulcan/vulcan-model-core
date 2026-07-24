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
	// HappyHorseVideoGenerateActionBindingID identifies the verified t2v, i2v, and r2v family.
	// HappyHorseVideoGenerateActionBindingID 标识已验证的 t2v、i2v 与 r2v 系列。
	HappyHorseVideoGenerateActionBindingID = "action_alibaba_happyhorse_video_generate"
	// HappyHorseVideoEditActionBindingID identifies the verified video-edit family.
	// HappyHorseVideoEditActionBindingID 标识已验证的视频编辑系列。
	HappyHorseVideoEditActionBindingID = "action_alibaba_happyhorse_video_edit"
	// HappyHorseVideoGenerateProtocolProfileID identifies the HappyHorse generation wire contract.
	// HappyHorseVideoGenerateProtocolProfileID 标识 HappyHorse 生成 Wire 合同。
	HappyHorseVideoGenerateProtocolProfileID = "alibaba.happyhorse.video.generate.v1"
	// HappyHorseVideoEditProtocolProfileID identifies the HappyHorse editing wire contract.
	// HappyHorseVideoEditProtocolProfileID 标识 HappyHorse 编辑 Wire 合同。
	HappyHorseVideoEditProtocolProfileID = "alibaba.happyhorse.video.edit.v1"
)

var (
	// ErrInvalidHappyHorseVideoDriver reports an unsupported HappyHorse request.
	// ErrInvalidHappyHorseVideoDriver 表示不受支持的 HappyHorse 请求。
	ErrInvalidHappyHorseVideoDriver = errors.New("invalid Alibaba HappyHorse video driver")
	// ErrInvalidHappyHorseVideoResponse reports malformed HappyHorse task output.
	// ErrInvalidHappyHorseVideoResponse 表示格式错误的 HappyHorse 任务输出。
	ErrInvalidHappyHorseVideoResponse = errors.New("invalid Alibaba HappyHorse video response")
)

// HappyHorseVideoTaskDriver owns one exact HappyHorse asynchronous action for one CN definition.
// HappyHorseVideoTaskDriver 为一个 CN Definition 拥有一个精确的 HappyHorse 异步动作。
type HappyHorseVideoTaskDriver struct {
	// definitionID is the immutable provider product boundary.
	// definitionID 是不可变供应商产品边界。
	definitionID string
	// actionBindingID selects generation or editing without payload guessing.
	// actionBindingID 在不猜测 Payload 的情况下选择生成或编辑。
	actionBindingID string
	// client performs provider-scoped authenticated requests.
	// client 执行供应商作用域的认证请求。
	client *transport.Client
}

// NewHappyHorseVideoTaskDriver creates one action-specific HappyHorse task driver.
// NewHappyHorseVideoTaskDriver 创建一个动作专属 HappyHorse 任务 Driver。
func NewHappyHorseVideoTaskDriver(definitionID string, actionBindingID string, client *transport.Client) (*HappyHorseVideoTaskDriver, error) {
	if strings.TrimSpace(definitionID) == "" || !isHappyHorseVideoAction(actionBindingID) || client == nil {
		return nil, ErrInvalidHappyHorseVideoDriver
	}
	return &HappyHorseVideoTaskDriver{definitionID: definitionID, actionBindingID: actionBindingID, client: client}, nil
}

// ProviderDefinitionID returns the sole provider definition owned by this driver.
// ProviderDefinitionID 返回此 Driver 唯一拥有的供应商 Definition。
func (d *HappyHorseVideoTaskDriver) ProviderDefinitionID() string {
	if d == nil {
		return ""
	}
	return d.definitionID
}

// ActionBindingID returns the sole action binding owned by this driver.
// ActionBindingID 返回此 Driver 唯一拥有的动作绑定。
func (d *HappyHorseVideoTaskDriver) ActionBindingID() string { return d.actionBindingID }

// Start submits one HappyHorse task and preserves its private provider identifier.
// Start 提交一个 HappyHorse 任务并保留其私有供应商标识。
func (d *HappyHorseVideoTaskDriver) Start(ctx context.Context, execution provider.ExecutionRequest) (provider.TaskResult, error) {
	if errValidate := d.validateExecution(execution); errValidate != nil {
		return provider.TaskResult{}, errValidate
	}
	request, errProject := projectHappyHorseVideoStart(d.actionBindingID, execution)
	if errProject != nil {
		return provider.TaskResult{}, errProject
	}
	response, errRequest := d.client.Do(ctx, request)
	if errRequest != nil {
		return provider.TaskResult{}, errRequest
	}
	defer func() { _ = transport.DrainAndClose(response) }()
	return decodeHappyHorseVideoStart(response.Body, execution.Now)
}

// Poll observes one HappyHorse task through the same immutable action binding.
// Poll 通过同一不可变动作绑定观察一个 HappyHorse 任务。
func (d *HappyHorseVideoTaskDriver) Poll(ctx context.Context, execution provider.ExecutionRequest, providerTaskID string) (provider.TaskResult, error) {
	if errValidate := d.validateExecution(execution); errValidate != nil {
		return provider.TaskResult{}, errValidate
	}
	if strings.TrimSpace(providerTaskID) == "" || strings.TrimSpace(providerTaskID) != providerTaskID {
		return provider.TaskResult{}, fmt.Errorf("%w: provider task identifier is required", ErrInvalidHappyHorseVideoDriver)
	}
	response, errRequest := d.client.Do(ctx, transport.Request{Binding: execution.Binding, Method: http.MethodGet, Path: "/api/v1/tasks/" + url.PathEscape(providerTaskID), Authentication: transport.Authentication{Mode: transport.AuthenticationBearer}})
	if errRequest != nil {
		return provider.TaskResult{}, errRequest
	}
	defer func() { _ = transport.DrainAndClose(response) }()
	return decodeHappyHorseVideoPoll(response.Body, providerTaskID, execution.Now)
}

// Cancel requests cancellation of the same HappyHorse task.
// Cancel 请求取消同一个 HappyHorse 任务。
func (d *HappyHorseVideoTaskDriver) Cancel(ctx context.Context, execution provider.ExecutionRequest, providerTaskID string) (provider.TaskResult, error) {
	if errValidate := d.validateExecution(execution); errValidate != nil {
		return provider.TaskResult{}, errValidate
	}
	if strings.TrimSpace(providerTaskID) == "" || strings.TrimSpace(providerTaskID) != providerTaskID {
		return provider.TaskResult{}, fmt.Errorf("%w: provider task identifier is required", ErrInvalidHappyHorseVideoDriver)
	}
	response, errRequest := d.client.Do(ctx, transport.Request{Binding: execution.Binding, Method: http.MethodPost, Path: "/api/v1/tasks/" + url.PathEscape(providerTaskID) + "/cancel", Authentication: transport.Authentication{Mode: transport.AuthenticationBearer}})
	if errRequest != nil {
		return provider.TaskResult{}, errRequest
	}
	defer func() { _ = transport.DrainAndClose(response) }()
	var result wanVideoCancelResponse
	if errDecode := decodeAlibabaJSONResponse(response.Body, &result, ErrInvalidHappyHorseVideoResponse); errDecode != nil {
		return provider.TaskResult{}, errDecode
	}
	if strings.TrimSpace(result.RequestID) == "" || strings.TrimSpace(result.Code) != "" {
		return provider.TaskResult{}, fmt.Errorf("%w: cancellation was not confirmed", ErrInvalidHappyHorseVideoResponse)
	}
	return provider.TaskResult{ProviderTaskID: providerTaskID, State: provider.TaskCancelled}, nil
}

// validateExecution verifies exact definition, action, and API-key ownership.
// validateExecution 校验精确 Definition、动作与 API Key 归属。
func (d *HappyHorseVideoTaskDriver) validateExecution(execution provider.ExecutionRequest) error {
	if d == nil || d.client == nil || execution.Binding.Target.ProviderDefinitionID != d.definitionID {
		return fmt.Errorf("%w: target definition does not belong to this driver", provider.ErrExecutionBinding)
	}
	_, errValidate := execution.ValidateForAction(d.actionBindingID, providerconfig.AuthMethodAPIKey)
	return errValidate
}

// happyHorseVideoRequest is the closed HappyHorse generation and editing request.
// happyHorseVideoRequest 是封闭的 HappyHorse 生成与编辑请求。
type happyHorseVideoRequest struct {
	// Model is the exact resolved upstream model.
	// Model 是精确解析的上游模型。
	Model string `json:"model"`
	// Input contains the exact semantic prompt and media combination.
	// Input 包含精确语义提示词与媒体组合。
	Input happyHorseVideoInput `json:"input"`
	// Parameters contains only fields copied from the Bailian wire contract.
	// Parameters 仅包含从百炼 Wire 合同复制的字段。
	Parameters happyHorseVideoParameters `json:"parameters"`
}

// happyHorseVideoInput contains one HappyHorse task input.
// happyHorseVideoInput 包含一个 HappyHorse 任务输入。
type happyHorseVideoInput struct {
	// Prompt describes generation or editing and is optional only for video editing.
	// Prompt 描述生成或编辑，仅视频编辑允许省略。
	Prompt string `json:"prompt,omitempty"`
	// NegativePrompt describes content to exclude.
	// NegativePrompt 描述应排除的内容。
	NegativePrompt string `json:"negative_prompt,omitempty"`
	// Media contains provider-ordered first-frame, reference, or edit media.
	// Media 包含供应商排序的首帧、参考或编辑媒体。
	Media []happyHorseVideoMedia `json:"media,omitempty"`
}

// happyHorseVideoMedia contains one exact provider media role.
// happyHorseVideoMedia 包含一个精确供应商媒体角色。
type happyHorseVideoMedia struct {
	// Type is one closed HappyHorse media discriminator.
	// Type 是一种封闭 HappyHorse 媒体判别值。
	Type string `json:"type"`
	// URL is a public URL, Alibaba object URI, or documented image data URL.
	// URL 是公网 URL、Alibaba 对象 URI 或文档明确的图片 Data URL。
	URL string `json:"url"`
	// ReferenceVoice optionally pairs one uploaded voice with this exact reference.
	// ReferenceVoice 可选地将一个上传声音与此精确参考配对。
	ReferenceVoice string `json:"reference_voice,omitempty"`
}

// happyHorseVideoParameters contains the copied HappyHorse parameter shape.
// happyHorseVideoParameters 包含复制的 HappyHorse 参数结构。
type happyHorseVideoParameters struct {
	// Resolution selects the provider resolution tier.
	// Resolution 选择供应商分辨率档位。
	Resolution string `json:"resolution,omitempty"`
	// Ratio selects the provider aspect ratio.
	// Ratio 选择供应商长宽比。
	Ratio string `json:"ratio,omitempty"`
	// Duration is the whole-number output duration in seconds.
	// Duration 是整数秒输出时长。
	Duration int `json:"duration,omitempty"`
	// AudioSetting controls generated or original edit audio.
	// AudioSetting 控制生成音频或保留编辑源音频。
	AudioSetting vcp.VideoAudioMode `json:"audio_setting,omitempty"`
	// PromptExtend controls provider-native prompt rewriting.
	// PromptExtend 控制供应商原生提示词改写。
	PromptExtend *bool `json:"prompt_extend,omitempty"`
	// Watermark controls the AI-generated watermark.
	// Watermark 控制 AI 生成水印。
	Watermark *bool `json:"watermark,omitempty"`
	// Seed controls provider pseudo-random initialization.
	// Seed 控制供应商伪随机初始化。
	Seed *int64 `json:"seed,omitempty"`
}

// projectHappyHorseVideoStart maps one canonical operation to the exact HappyHorse wire shape.
// projectHappyHorseVideoStart 将一个规范操作映射到精确 HappyHorse Wire 结构。
func projectHappyHorseVideoStart(actionBindingID string, execution provider.ExecutionRequest) (transport.Request, error) {
	var body happyHorseVideoRequest
	var errProject error
	switch actionBindingID {
	case HappyHorseVideoGenerateActionBindingID:
		body, errProject = projectHappyHorseGeneration(execution)
	case HappyHorseVideoEditActionBindingID:
		body, errProject = projectHappyHorseEdit(execution)
	default:
		return transport.Request{}, ErrInvalidHappyHorseVideoDriver
	}
	if errProject != nil {
		return transport.Request{}, errProject
	}
	encoded, errEncode := json.Marshal(body)
	if errEncode != nil {
		return transport.Request{}, errEncode
	}
	return transport.Request{Binding: execution.Binding, Method: http.MethodPost, Path: "/api/v1/services/aigc/video-generation/video-synthesis", Headers: alibabaJSONHeaders(execution.MaterializedInputs, true), Body: encoded, Authentication: transport.Authentication{Mode: transport.AuthenticationBearer}, IdempotencyKey: execution.Execution.IdempotencyKey}, nil
}

// projectHappyHorseGeneration maps t2v, i2v, and r2v without positional reference-voice guessing.
// projectHappyHorseGeneration 在不猜测参考语音位置的情况下映射 t2v、i2v 与 r2v。
func projectHappyHorseGeneration(execution provider.ExecutionRequest) (happyHorseVideoRequest, error) {
	operation := execution.Execution.Payload.VideoGenerate
	model := execution.Binding.Target.UpstreamModelID
	if operation == nil || (model != "happyhorse-1.1-t2v" && model != "happyhorse-1.1-i2v" && model != "happyhorse-1.1-r2v") || strings.TrimSpace(operation.Prompt) == "" {
		return happyHorseVideoRequest{}, ErrInvalidHappyHorseVideoDriver
	}
	parameters, errParameters := happyHorseGenerationParameters(*operation)
	if errParameters != nil {
		return happyHorseVideoRequest{}, errParameters
	}
	body := happyHorseVideoRequest{Model: model, Input: happyHorseVideoInput{Prompt: operation.Prompt, NegativePrompt: operation.NegativePrompt}, Parameters: parameters}
	switch model {
	case "happyhorse-1.1-t2v":
		if len(operation.Inputs) != 0 {
			return happyHorseVideoRequest{}, fmt.Errorf("%w: t2v does not accept media input", ErrInvalidHappyHorseVideoDriver)
		}
	case "happyhorse-1.1-i2v":
		if len(operation.Inputs) != 1 || operation.Inputs[0].Kind != vcp.MediaImage || operation.Inputs[0].Role != vcp.MediaRoleFirstFrame {
			return happyHorseVideoRequest{}, fmt.Errorf("%w: i2v requires exactly one first-frame image", ErrInvalidHappyHorseVideoDriver)
		}
		mediaURL, errMedia := exactHappyHorseMediaURL(operation.Inputs[0], execution.MaterializedInputs, true)
		if errMedia != nil {
			return happyHorseVideoRequest{}, errMedia
		}
		body.Input.Media = []happyHorseVideoMedia{{Type: "first_frame", URL: mediaURL}}
	case "happyhorse-1.1-r2v":
		media, errMedia := projectHappyHorseReferences(operation.Inputs, execution.MaterializedInputs)
		if errMedia != nil {
			return happyHorseVideoRequest{}, errMedia
		}
		body.Input.Media = media
	}
	return body, nil
}

// happyHorseGenerationParameters validates only controls proven by the copied CLI contract.
// happyHorseGenerationParameters 仅校验复制的 CLI 合同已证明的控制项。
func happyHorseGenerationParameters(operation vcp.VideoGenerateOperation) (happyHorseVideoParameters, error) {
	if operation.Width != 0 || operation.Height != 0 || operation.FramesPerSecond != 0 || operation.Count > 1 || (operation.OutputFormat != "" && operation.OutputFormat != "mp4") {
		return happyHorseVideoParameters{}, fmt.Errorf("%w: exact dimensions, frame rate, multiple outputs, or non-MP4 output has no HappyHorse carrier", ErrInvalidHappyHorseVideoDriver)
	}
	duration, errDuration := exactHappyHorseDuration(operation.DurationSeconds, 0)
	if errDuration != nil {
		return happyHorseVideoParameters{}, errDuration
	}
	resolution := strings.ToUpper(operation.Resolution)
	if resolution != "" && resolution != "720P" && resolution != "1080P" {
		return happyHorseVideoParameters{}, fmt.Errorf("%w: unsupported resolution", ErrInvalidHappyHorseVideoDriver)
	}
	if !supportedWanVideoRatio(operation.AspectRatio) || (operation.Seed != nil && *operation.Seed < 0) {
		return happyHorseVideoParameters{}, fmt.Errorf("%w: unsupported ratio or seed", ErrInvalidHappyHorseVideoDriver)
	}
	return happyHorseVideoParameters{Resolution: resolution, Ratio: operation.AspectRatio, Duration: duration, PromptExtend: operation.PromptExtend, Watermark: operation.Watermark, Seed: operation.Seed}, nil
}

// projectHappyHorseReferences builds provider order from explicit media relations instead of array positions.
// projectHappyHorseReferences 根据显式媒体关系而不是数组位置构建供应商顺序。
func projectHappyHorseReferences(inputs []vcp.MediaInput, materialized []resource.MaterializedInput) ([]happyHorseVideoMedia, error) {
	// voices freezes the exact related-input mapping before reference ordering.
	// voices 在参考排序前冻结精确的关联输入映射。
	voices := make(map[string]string)
	for _, input := range inputs {
		if input.Role != vcp.MediaRoleReferenceVoice {
			continue
		}
		if _, exists := voices[input.RelatedInputID]; exists {
			return nil, fmt.Errorf("%w: each reference accepts at most one voice", ErrInvalidHappyHorseVideoDriver)
		}
		voiceURL, errVoice := exactHappyHorseMediaURL(input, materialized, false)
		if errVoice != nil {
			return nil, errVoice
		}
		voices[input.RelatedInputID] = voiceURL
	}
	media := make([]happyHorseVideoMedia, 0, len(inputs)-len(voices))
	// referenceImageCount enforces the copied nine-image contract independently of video references and related voices.
	// referenceImageCount 独立于视频参考和关联语音强制执行复制的九张图片合同。
	referenceImageCount := 0
	for _, input := range inputs {
		if input.Role == vcp.MediaRoleReferenceVoice {
			continue
		}
		mediaType := ""
		switch {
		case input.Kind == vcp.MediaImage && input.Role == vcp.MediaRoleReference:
			mediaType = "reference_image"
			referenceImageCount++
		case input.Kind == vcp.MediaVideo && input.Role == vcp.MediaRoleReference:
			mediaType = "reference_video"
		default:
			return nil, fmt.Errorf("%w: r2v accepts only image or video references and explicitly related voices", ErrInvalidHappyHorseVideoDriver)
		}
		mediaURL, errMedia := exactHappyHorseMediaURL(input, materialized, input.Kind == vcp.MediaImage)
		if errMedia != nil {
			return nil, errMedia
		}
		media = append(media, happyHorseVideoMedia{Type: mediaType, URL: mediaURL, ReferenceVoice: voices[input.ID]})
		delete(voices, input.ID)
	}
	if referenceImageCount > 9 {
		return nil, fmt.Errorf("%w: r2v accepts at most nine reference images", ErrInvalidHappyHorseVideoDriver)
	}
	if len(media) == 0 || len(voices) != 0 {
		return nil, fmt.Errorf("%w: r2v requires references and every voice relation must resolve", ErrInvalidHappyHorseVideoDriver)
	}
	return media, nil
}

// projectHappyHorseEdit maps one video source and up to four image references.
// projectHappyHorseEdit 映射一个视频来源与最多四个图片参考。
func projectHappyHorseEdit(execution provider.ExecutionRequest) (happyHorseVideoRequest, error) {
	operation := execution.Execution.Payload.VideoEdit
	if operation == nil || execution.Binding.Target.UpstreamModelID != "happyhorse-1.0-video-edit" || operation.Source.Kind != vcp.MediaVideo || operation.Source.Role != vcp.MediaRoleEditSource || len(operation.References) > 4 {
		return happyHorseVideoRequest{}, ErrInvalidHappyHorseVideoDriver
	}
	if operation.DurationSeconds != 0 && (operation.DurationSeconds < 2 || operation.DurationSeconds > 10) {
		return happyHorseVideoRequest{}, fmt.Errorf("%w: video-edit duration must be from two through ten seconds", ErrInvalidHappyHorseVideoDriver)
	}
	duration, errDuration := exactHappyHorseDuration(operation.DurationSeconds, 10)
	if errDuration != nil {
		return happyHorseVideoRequest{}, errDuration
	}
	resolution := strings.ToUpper(operation.Resolution)
	if resolution != "" && resolution != "720P" && resolution != "1080P" {
		return happyHorseVideoRequest{}, fmt.Errorf("%w: unsupported resolution", ErrInvalidHappyHorseVideoDriver)
	}
	if !supportedWanVideoRatio(operation.AspectRatio) || (operation.Seed != nil && *operation.Seed < 0) {
		return happyHorseVideoRequest{}, fmt.Errorf("%w: unsupported ratio or seed", ErrInvalidHappyHorseVideoDriver)
	}
	sourceURL, errSource := exactHappyHorseMediaURL(operation.Source, execution.MaterializedInputs, false)
	if errSource != nil {
		return happyHorseVideoRequest{}, errSource
	}
	media := []happyHorseVideoMedia{{Type: "video", URL: sourceURL}}
	for _, reference := range operation.References {
		if reference.Kind != vcp.MediaImage || reference.Role != vcp.MediaRoleReference {
			return happyHorseVideoRequest{}, fmt.Errorf("%w: video edit accepts only image references", ErrInvalidHappyHorseVideoDriver)
		}
		referenceURL, errReference := exactHappyHorseMediaURL(reference, execution.MaterializedInputs, true)
		if errReference != nil {
			return happyHorseVideoRequest{}, errReference
		}
		media = append(media, happyHorseVideoMedia{Type: "reference_image", URL: referenceURL})
	}
	return happyHorseVideoRequest{Model: execution.Binding.Target.UpstreamModelID, Input: happyHorseVideoInput{Prompt: operation.Instruction, NegativePrompt: operation.NegativePrompt, Media: media}, Parameters: happyHorseVideoParameters{Resolution: resolution, Ratio: operation.AspectRatio, Duration: duration, AudioSetting: operation.AudioMode, PromptExtend: operation.PromptExtend, Watermark: operation.Watermark, Seed: operation.Seed}}, nil
}

// exactHappyHorseDuration converts only whole positive seconds and optionally enforces a maximum.
// exactHappyHorseDuration 仅转换整数正秒，并可选地强制最大值。
func exactHappyHorseDuration(value float64, maximum int) (int, error) {
	duration := int(value)
	if value != 0 && (value != float64(duration) || duration <= 0 || (maximum > 0 && duration > maximum)) {
		return 0, fmt.Errorf("%w: duration must be a supported whole number of seconds", ErrInvalidHappyHorseVideoDriver)
	}
	return duration, nil
}

// exactHappyHorseMediaURL resolves one exact materialization without cross-input fallback.
// exactHappyHorseMediaURL 在不跨输入兜底的情况下解析一个精确物化结果。
func exactHappyHorseMediaURL(input vcp.MediaInput, materialized []resource.MaterializedInput, allowInlineImage bool) (string, error) {
	for _, value := range materialized {
		if value.InputID != input.ID {
			continue
		}
		if value.ResourceID != input.Resource.ResourceID || value.Kind != input.Kind || value.Role != input.Role || strings.TrimSpace(value.MIMEType) == "" {
			return "", fmt.Errorf("%w: media does not match its exact materialization", ErrInvalidHappyHorseVideoDriver)
		}
		switch value.Mode {
		case catalog.MaterializationDirectRemoteURL:
			if strings.TrimSpace(value.RemoteURL) != "" {
				return value.RemoteURL, nil
			}
		case catalog.MaterializationProviderObjectURI:
			return alibabaObjectURI(value, ErrInvalidHappyHorseVideoDriver)
		case catalog.MaterializationInlineBase64:
			if allowInlineImage && input.Kind == vcp.MediaImage && strings.TrimSpace(value.InlineBase64) != "" {
				return "data:" + value.MIMEType + ";base64," + value.InlineBase64, nil
			}
		}
		return "", fmt.Errorf("%w: unsupported media materialization", ErrInvalidHappyHorseVideoDriver)
	}
	return "", fmt.Errorf("%w: media input has no exact materialization", ErrInvalidHappyHorseVideoDriver)
}

// decodeHappyHorseVideoStart decodes the required queued task identity.
// decodeHappyHorseVideoStart 解码必需的排队任务标识。
func decodeHappyHorseVideoStart(reader io.Reader, now time.Time) (provider.TaskResult, error) {
	var response wanVideoTaskEnvelope
	if errDecode := decodeAlibabaJSONResponse(reader, &response, ErrInvalidHappyHorseVideoResponse); errDecode != nil {
		return provider.TaskResult{}, errDecode
	}
	if response.Output.TaskStatus != "PENDING" || strings.TrimSpace(response.Output.TaskID) == "" || strings.TrimSpace(response.Output.TaskID) != response.Output.TaskID {
		return provider.TaskResult{}, fmt.Errorf("%w: missing queued task", ErrInvalidHappyHorseVideoResponse)
	}
	return provider.TaskResult{ProviderTaskID: response.Output.TaskID, State: provider.TaskQueued, PollAfter: now.UTC().Add(15 * time.Second)}, nil
}

// decodeHappyHorseVideoPoll maps documented task states and both successful URL envelopes.
// decodeHappyHorseVideoPoll 映射文档任务状态与两种成功 URL 信封。
func decodeHappyHorseVideoPoll(reader io.Reader, providerTaskID string, now time.Time) (provider.TaskResult, error) {
	var response wanVideoTaskEnvelope
	if errDecode := decodeAlibabaJSONResponse(reader, &response, ErrInvalidHappyHorseVideoResponse); errDecode != nil {
		return provider.TaskResult{}, errDecode
	}
	if response.Output.TaskID != providerTaskID {
		return provider.TaskResult{}, fmt.Errorf("%w: task response correlation is invalid", ErrInvalidHappyHorseVideoResponse)
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
			return provider.TaskResult{}, fmt.Errorf("%w: completed task has no video URL", ErrInvalidHappyHorseVideoResponse)
		}
		result := provider.ExecutionResult{GeneratedResources: []provider.GeneratedResource{{OutputID: "video-0", Kind: vcp.MediaVideo, MIMEType: "video/mp4", DownloadURL: videoURL}}}
		return provider.TaskResult{ProviderTaskID: providerTaskID, State: provider.TaskSucceeded, Result: &result}, nil
	case "FAILED", "UNKNOWN":
		return provider.TaskResult{ProviderTaskID: providerTaskID, State: provider.TaskFailed, ErrorCode: "alibaba_happyhorse_video_failed"}, nil
	case "CANCELED":
		return provider.TaskResult{ProviderTaskID: providerTaskID, State: provider.TaskCancelled}, nil
	default:
		return provider.TaskResult{}, fmt.Errorf("%w: unknown task status %q", ErrInvalidHappyHorseVideoResponse, response.Output.TaskStatus)
	}
}

// isHappyHorseVideoAction reports membership in the closed HappyHorse action set.
// isHappyHorseVideoAction 报告是否属于封闭 HappyHorse 动作集合。
func isHappyHorseVideoAction(value string) bool {
	return value == HappyHorseVideoGenerateActionBindingID || value == HappyHorseVideoEditActionBindingID
}
