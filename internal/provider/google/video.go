package google

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
	// VideoGenerateActionBindingID identifies Google Veo generation.
	// VideoGenerateActionBindingID 标识 Google Veo 生成动作。
	VideoGenerateActionBindingID = "action_google_video_generate"
	// VideoExtendActionBindingID identifies Google Veo extension.
	// VideoExtendActionBindingID 标识 Google Veo 延长动作。
	VideoExtendActionBindingID = "action_google_video_extend"
	// VideoGenerateProtocolProfileID identifies the Veo long-running generation contract.
	// VideoGenerateProtocolProfileID 标识 Veo 长任务生成合同。
	VideoGenerateProtocolProfileID = "google.veo.generate.v3.1"
	// VideoExtendProtocolProfileID identifies the Veo long-running extension contract.
	// VideoExtendProtocolProfileID 标识 Veo 长任务延长合同。
	VideoExtendProtocolProfileID = "google.veo.extend.v3.1"
	// maximumVeoVideoBytes bounds authenticated result acquisition.
	// maximumVeoVideoBytes 限制认证结果获取大小。
	maximumVeoVideoBytes int64 = 1 << 30
)

var (
	// ErrInvalidVideoDriver reports an unsupported Veo request.
	// ErrInvalidVideoDriver 表示不受支持的 Veo 请求。
	ErrInvalidVideoDriver = errors.New("invalid Google Veo driver")
	// ErrInvalidVideoResponse reports malformed Veo task output.
	// ErrInvalidVideoResponse 表示格式错误的 Veo 任务输出。
	ErrInvalidVideoResponse = errors.New("invalid Google Veo response")
)

// VideoTaskDriver owns one Veo task action for one immutable AI Studio definition.
// VideoTaskDriver 为一个不可变 AI Studio Definition 拥有一个 Veo 任务动作。
type VideoTaskDriver struct {
	// definitionID is the exact owning provider definition.
	// definitionID 是精确拥有供应商 Definition。
	definitionID string
	// actionBindingID is generation or extension.
	// actionBindingID 为生成或延长动作。
	actionBindingID string
	// client performs authenticated provider transport.
	// client 执行认证供应商传输。
	client *transport.Client
}

// NewVideoTaskDriver creates one exact Veo task driver.
// NewVideoTaskDriver 创建一个精确 Veo 任务 Driver。
func NewVideoTaskDriver(definitionID string, actionBindingID string, client *transport.Client) (*VideoTaskDriver, error) {
	if strings.TrimSpace(definitionID) == "" || client == nil || (actionBindingID != VideoGenerateActionBindingID && actionBindingID != VideoExtendActionBindingID) {
		return nil, ErrInvalidVideoDriver
	}
	return &VideoTaskDriver{definitionID: definitionID, actionBindingID: actionBindingID, client: client}, nil
}

// ProviderDefinitionID returns the sole owning definition.
// ProviderDefinitionID 返回唯一拥有 Definition。
func (d *VideoTaskDriver) ProviderDefinitionID() string { return d.definitionID }

// ActionBindingID returns the sole owning action.
// ActionBindingID 返回唯一拥有动作。
func (d *VideoTaskDriver) ActionBindingID() string { return d.actionBindingID }

// Start creates one Veo long-running operation.
// Start 创建一个 Veo 长时间运行操作。
func (d *VideoTaskDriver) Start(ctx context.Context, execution provider.ExecutionRequest) (provider.TaskResult, error) {
	if errValidate := d.validateExecution(execution); errValidate != nil {
		return provider.TaskResult{}, errValidate
	}
	request, errProject := projectVeoStart(execution, d.actionBindingID)
	if errProject != nil {
		return provider.TaskResult{}, errProject
	}
	response, errRequest := d.client.Do(ctx, request)
	if errRequest != nil {
		return provider.TaskResult{}, errRequest
	}
	defer func() { _ = transport.DrainAndClose(response) }()
	return decodeVeoStart(response.Body, execution.Now)
}

// Poll observes one operation and privately downloads authenticated Google output.
// Poll 观察一个操作并私下下载经过认证的 Google 输出。
func (d *VideoTaskDriver) Poll(ctx context.Context, execution provider.ExecutionRequest, providerTaskID string) (provider.TaskResult, error) {
	if errValidate := d.validateExecution(execution); errValidate != nil {
		return provider.TaskResult{}, errValidate
	}
	operationPath, errPath := exactVeoOperationPath(providerTaskID)
	if errPath != nil {
		return provider.TaskResult{}, errPath
	}
	response, errRequest := d.client.Do(ctx, transport.Request{Binding: execution.Binding, Method: http.MethodGet, Path: "/v1beta/" + operationPath, Authentication: googleAPIKeyAuthentication()})
	if errRequest != nil {
		return provider.TaskResult{}, errRequest
	}
	defer func() { _ = transport.DrainAndClose(response) }()
	observation, videoURI, errDecode := decodeVeoPoll(response.Body, providerTaskID, execution.Now)
	if errDecode != nil || observation.State != provider.TaskSucceeded {
		return observation, errDecode
	}
	videoPath, errVideoPath := exactGoogleVideoPath(execution.Binding.Endpoint.BaseURL, videoURI)
	if errVideoPath != nil {
		return provider.TaskResult{}, errVideoPath
	}
	video, errDownload := d.downloadVideo(ctx, execution, videoPath)
	if errDownload != nil {
		return provider.TaskResult{}, errDownload
	}
	result := provider.ExecutionResult{GeneratedResources: []provider.GeneratedResource{{OutputID: "video-0", Kind: vcp.MediaVideo, MIMEType: "video/mp4", Data: video}}}
	observation.Result = &result
	return observation, nil
}

// Cancel reports that the Veo operations guide does not document cancellation.
// Cancel 报告 Veo 操作指南未记录取消能力。
func (d *VideoTaskDriver) Cancel(_ context.Context, execution provider.ExecutionRequest, providerTaskID string) (provider.TaskResult, error) {
	if errValidate := d.validateExecution(execution); errValidate != nil {
		return provider.TaskResult{}, errValidate
	}
	if _, errPath := exactVeoOperationPath(providerTaskID); errPath != nil {
		return provider.TaskResult{}, errPath
	}
	return provider.TaskResult{}, fmt.Errorf("%w: Google does not document Veo operation cancellation", ErrInvalidVideoDriver)
}

// validateExecution verifies exact action, definition, and API-key ownership.
// validateExecution 校验精确动作、Definition 与 API Key 归属。
func (d *VideoTaskDriver) validateExecution(execution provider.ExecutionRequest) error {
	if d == nil || d.client == nil || execution.Binding.Target.ProviderDefinitionID != d.definitionID {
		return fmt.Errorf("%w: target definition does not belong to this driver", provider.ErrExecutionBinding)
	}
	_, errValidate := execution.ValidateForAction(d.actionBindingID, providerconfig.AuthMethodAPIKey)
	return errValidate
}

// googleAPIKeyAuthentication returns the sole AI Studio credential carrier.
// googleAPIKeyAuthentication 返回唯一 AI Studio 凭据载体。
func googleAPIKeyAuthentication() transport.Authentication {
	return transport.Authentication{Mode: transport.AuthenticationHeader, HeaderName: "X-Goog-Api-Key"}
}

// veoRequest is the closed REST predictLongRunning request.
// veoRequest 是封闭的 REST predictLongRunning 请求。
type veoRequest struct {
	// Instances contains exactly one generation instance.
	// Instances 包含恰好一个生成实例。
	Instances []veoInstance `json:"instances"`
	// Parameters contains exact provider controls.
	// Parameters 包含精确供应商控制项。
	Parameters veoParameters `json:"parameters,omitempty"`
}

// veoInstance contains mutually constrained media modes.
// veoInstance 包含互斥约束的媒体模式。
type veoInstance struct {
	// Prompt describes generation or extension.
	// Prompt 描述生成或延长。
	Prompt string `json:"prompt,omitempty"`
	// Image is the optional first frame.
	// Image 是可选首帧。
	Image *veoMedia `json:"image,omitempty"`
	// LastFrame is the optional last frame.
	// LastFrame 是可选末帧。
	LastFrame *veoMedia `json:"lastFrame,omitempty"`
	// ReferenceImages contains up to three asset references.
	// ReferenceImages 包含最多三张资产参考图。
	ReferenceImages []veoReferenceImage `json:"referenceImages,omitempty"`
	// Video is a previous Veo-generated video for extension.
	// Video 是用于延长的先前 Veo 生成视频。
	Video *veoMedia `json:"video,omitempty"`
}

// veoMedia is the exact inline media object.
// veoMedia 是精确内联媒体对象。
type veoMedia struct {
	// InlineData carries MIME and Base64 data.
	// InlineData 携带 MIME 与 Base64 数据。
	InlineData veoInlineData `json:"inlineData"`
}

// veoInlineData contains one Base64 payload.
// veoInlineData 包含一个 Base64 负载。
type veoInlineData struct {
	// MIMEType is the frozen resource media type.
	// MIMEType 是冻结的资源媒体类型。
	MIMEType string `json:"mimeType"`
	// Data is raw Base64 without a data-URL prefix.
	// Data 是不带 Data URL 前缀的原始 Base64。
	Data string `json:"data"`
}

// veoReferenceImage marks one inline image as an asset reference.
// veoReferenceImage 将一张内联图片标记为资产参考。
type veoReferenceImage struct {
	// Image is the inline reference content.
	// Image 是内联参考内容。
	Image veoMedia `json:"image"`
	// ReferenceType is the documented asset mode.
	// ReferenceType 是文档明确的 asset 模式。
	ReferenceType string `json:"referenceType"`
}

// veoParameters contains model-scoped generation controls.
// veoParameters 包含模型作用域的生成控制项。
type veoParameters struct {
	// AspectRatio is 16:9 or 9:16.
	// AspectRatio 为 16:9 或 9:16。
	AspectRatio string `json:"aspectRatio,omitempty"`
	// DurationSeconds is four, six, or eight.
	// DurationSeconds 为四、六或八秒。
	DurationSeconds int `json:"durationSeconds,omitempty"`
	// Resolution is 720p, 1080p, or 4k.
	// Resolution 为 720p、1080p 或 4k。
	Resolution string `json:"resolution,omitempty"`
	// NegativePrompt describes excluded content.
	// NegativePrompt 描述排除内容。
	NegativePrompt string `json:"negativePrompt,omitempty"`
	// NumberOfVideos remains one under the public VCP contract.
	// NumberOfVideos 在公开 VCP 合同下保持为一。
	NumberOfVideos int `json:"numberOfVideos,omitempty"`
}

// veoOperation is one Google long-running operation observation.
// veoOperation 是一次 Google 长时间运行操作观测。
type veoOperation struct {
	// Name is the private operation resource name.
	// Name 是私有操作资源名称。
	Name string `json:"name"`
	// Done reports terminal completion.
	// Done 表示终态完成。
	Done bool `json:"done"`
	// Error contains a safe numeric status code.
	// Error 包含安全数字状态码。
	Error *struct {
		// Code is the canonical Google RPC code.
		// Code 是规范 Google RPC 代码。
		Code int `json:"code"`
	} `json:"error,omitempty"`
	// Response contains successful generated samples.
	// Response 包含成功生成样本。
	Response *struct {
		// GenerateVideoResponse contains the versioned provider result.
		// GenerateVideoResponse 包含版本化供应商结果。
		GenerateVideoResponse struct {
			// GeneratedSamples contains one generated video.
			// GeneratedSamples 包含一个生成视频。
			GeneratedSamples []struct {
				// Video contains the authenticated download URI.
				// Video 包含认证下载 URI。
				Video struct {
					// URI is the temporary Google media URI.
					// URI 是临时 Google 媒体 URI。
					URI string `json:"uri"`
				} `json:"video"`
			} `json:"generatedSamples"`
		} `json:"generateVideoResponse"`
	} `json:"response,omitempty"`
}

// projectVeoStart maps generation or extension to one exact request.
// projectVeoStart 将生成或延长映射为一个精确请求。
func projectVeoStart(execution provider.ExecutionRequest, actionBindingID string) (transport.Request, error) {
	model := execution.Binding.Target.UpstreamModelID
	if !supportedVeoModel(model) {
		return transport.Request{}, fmt.Errorf("%w: unsupported Veo model", ErrInvalidVideoDriver)
	}
	instance := veoInstance{}
	parameters := veoParameters{NumberOfVideos: 1}
	switch actionBindingID {
	case VideoGenerateActionBindingID:
		operation := execution.Execution.Payload.VideoGenerate
		if operation == nil || strings.TrimSpace(operation.Prompt) == "" || operation.Width != 0 || operation.Height != 0 || operation.FramesPerSecond != 0 || operation.Seed != nil || operation.Watermark != nil || operation.PromptExtend != nil || operation.Count > 1 || (operation.OutputFormat != "" && operation.OutputFormat != "mp4") {
			return transport.Request{}, ErrInvalidVideoDriver
		}
		instance.Prompt = operation.Prompt
		parameters.AspectRatio, parameters.Resolution, parameters.NegativePrompt = operation.AspectRatio, strings.ToLower(operation.Resolution), operation.NegativePrompt
		parameters.DurationSeconds = int(operation.DurationSeconds)
		if operation.DurationSeconds != 0 && operation.DurationSeconds != float64(parameters.DurationSeconds) {
			return transport.Request{}, fmt.Errorf("%w: duration must be integral", ErrInvalidVideoDriver)
		}
		if errInputs := projectVeoGenerationInputs(&instance, operation.Inputs, execution.MaterializedInputs); errInputs != nil {
			return transport.Request{}, errInputs
		}
	case VideoExtendActionBindingID:
		operation := execution.Execution.Payload.VideoExtend
		if operation == nil || operation.AdditionalDurationSeconds != 7 {
			return transport.Request{}, fmt.Errorf("%w: Veo extension adds exactly seven seconds", ErrInvalidVideoDriver)
		}
		if errProvenance := validateVeoExtensionProvenance(operation.Source, execution.MaterializedInputs, execution.Binding.Target.ProviderDefinitionID); errProvenance != nil {
			return transport.Request{}, errProvenance
		}
		video, errVideo := exactVeoMedia(operation.Source, execution.MaterializedInputs)
		if errVideo != nil || operation.Source.Kind != vcp.MediaVideo {
			return transport.Request{}, ErrInvalidVideoDriver
		}
		instance.Prompt, instance.Video = operation.Prompt, &video
		parameters.DurationSeconds, parameters.Resolution = 8, "720p"
	default:
		return transport.Request{}, ErrInvalidVideoDriver
	}
	if errControls := validateVeoControls(instance, parameters, model); errControls != nil {
		return transport.Request{}, errControls
	}
	encoded, errEncode := json.Marshal(veoRequest{Instances: []veoInstance{instance}, Parameters: parameters})
	if errEncode != nil {
		return transport.Request{}, errEncode
	}
	return transport.Request{Binding: execution.Binding, Method: http.MethodPost, Path: "/v1beta/models/" + url.PathEscape(model) + ":predictLongRunning", Headers: []transport.Header{{Name: "Content-Type", Value: "application/json"}}, Body: encoded, Authentication: googleAPIKeyAuthentication(), IdempotencyKey: execution.Execution.IdempotencyKey}, nil
}

// validateVeoExtensionProvenance proves the source was produced by a Veo action under the same provider definition.
// validateVeoExtensionProvenance 证明来源由同一供应商 Definition 下的 Veo 动作生成。
func validateVeoExtensionProvenance(input vcp.MediaInput, materialized []resource.MaterializedInput, providerDefinitionID string) error {
	for _, value := range materialized {
		if value.InputID != input.ID {
			continue
		}
		provenance := value.GeneratedBy
		if provenance == nil || provenance.ProviderDefinitionID != providerDefinitionID || !supportedVeoModel(provenance.UpstreamModelID) || (provenance.ActionBindingID != VideoGenerateActionBindingID && provenance.ActionBindingID != VideoExtendActionBindingID) || (provenance.Operation != vcp.OperationVideoGenerate && provenance.Operation != vcp.OperationVideoExtend) {
			return fmt.Errorf("%w: Veo extension requires a Router resource generated by Veo", ErrInvalidVideoDriver)
		}
		return nil
	}
	return fmt.Errorf("%w: Veo extension source has no exact materialization", ErrInvalidVideoDriver)
}

// projectVeoGenerationInputs maps first, last, and reference images without ambiguous combinations.
// projectVeoGenerationInputs 映射首帧、末帧与参考图且不允许含糊组合。
func projectVeoGenerationInputs(instance *veoInstance, inputs []vcp.MediaInput, materialized []resource.MaterializedInput) error {
	for _, input := range inputs {
		if input.Kind != vcp.MediaImage {
			return fmt.Errorf("%w: generation inputs must be images", ErrInvalidVideoDriver)
		}
		media, errMedia := exactVeoMedia(input, materialized)
		if errMedia != nil {
			return errMedia
		}
		switch input.Role {
		case vcp.MediaRoleFirstFrame:
			if instance.Image != nil || len(instance.ReferenceImages) != 0 {
				return fmt.Errorf("%w: first-frame and reference modes cannot be combined", ErrInvalidVideoDriver)
			}
			instance.Image = &media
		case vcp.MediaRoleLastFrame:
			if instance.LastFrame != nil || instance.Image == nil || len(instance.ReferenceImages) != 0 {
				return fmt.Errorf("%w: last frame requires one earlier first frame", ErrInvalidVideoDriver)
			}
			instance.LastFrame = &media
		case vcp.MediaRoleReference:
			if instance.Image != nil || len(instance.ReferenceImages) >= 3 {
				return fmt.Errorf("%w: reference mode accepts at most three images", ErrInvalidVideoDriver)
			}
			instance.ReferenceImages = append(instance.ReferenceImages, veoReferenceImage{Image: media, ReferenceType: "asset"})
		default:
			return fmt.Errorf("%w: unsupported image role", ErrInvalidVideoDriver)
		}
	}
	return nil
}

// exactVeoMedia resolves the required inline Base64 representation.
// exactVeoMedia 解析必需的内联 Base64 表示。
func exactVeoMedia(input vcp.MediaInput, materialized []resource.MaterializedInput) (veoMedia, error) {
	for _, value := range materialized {
		if value.InputID != input.ID {
			continue
		}
		if value.ResourceID != input.Resource.ResourceID || value.Kind != input.Kind || value.Role != input.Role || value.Mode != catalog.MaterializationInlineBase64 || strings.TrimSpace(value.MIMEType) == "" || strings.TrimSpace(value.InlineBase64) == "" {
			return veoMedia{}, fmt.Errorf("%w: Veo media requires its exact inline materialization", ErrInvalidVideoDriver)
		}
		return veoMedia{InlineData: veoInlineData{MIMEType: value.MIMEType, Data: value.InlineBase64}}, nil
	}
	return veoMedia{}, fmt.Errorf("%w: media input has no exact materialization", ErrInvalidVideoDriver)
}

// validateVeoControls enforces the current Veo 3.1 combination matrix.
// validateVeoControls 强制执行当前 Veo 3.1 组合矩阵。
func validateVeoControls(instance veoInstance, parameters veoParameters, model string) error {
	if parameters.AspectRatio != "" && parameters.AspectRatio != "16:9" && parameters.AspectRatio != "9:16" {
		return fmt.Errorf("%w: unsupported aspect ratio", ErrInvalidVideoDriver)
	}
	if parameters.DurationSeconds != 0 && parameters.DurationSeconds != 4 && parameters.DurationSeconds != 6 && parameters.DurationSeconds != 8 {
		return fmt.Errorf("%w: duration must be four, six, or eight seconds", ErrInvalidVideoDriver)
	}
	if parameters.Resolution != "" && parameters.Resolution != "720p" && parameters.Resolution != "1080p" && parameters.Resolution != "4k" {
		return fmt.Errorf("%w: unsupported resolution", ErrInvalidVideoDriver)
	}
	if model == "veo-3.1-lite-generate-preview" && (parameters.Resolution == "4k" || len(instance.ReferenceImages) != 0 || instance.Video != nil) {
		return fmt.Errorf("%w: Veo Lite does not support 4k, references, or extension", ErrInvalidVideoDriver)
	}
	if (parameters.Resolution == "1080p" || parameters.Resolution == "4k" || len(instance.ReferenceImages) != 0 || instance.Video != nil) && parameters.DurationSeconds != 8 {
		return fmt.Errorf("%w: selected mode requires eight-second duration", ErrInvalidVideoDriver)
	}
	return nil
}

// supportedVeoModel reports membership in the current preview model family.
// supportedVeoModel 报告是否属于当前预览模型系列。
func supportedVeoModel(model string) bool {
	return model == "veo-3.1-generate-preview" || model == "veo-3.1-fast-generate-preview" || model == "veo-3.1-lite-generate-preview"
}

// decodeVeoStart decodes one operation resource name.
// decodeVeoStart 解码一个操作资源名称。
func decodeVeoStart(reader io.Reader, now time.Time) (provider.TaskResult, error) {
	var operation veoOperation
	if errDecode := json.NewDecoder(reader).Decode(&operation); errDecode != nil || strings.TrimSpace(operation.Name) == "" || operation.Done {
		return provider.TaskResult{}, fmt.Errorf("%w: missing running operation", ErrInvalidVideoResponse)
	}
	return provider.TaskResult{ProviderTaskID: operation.Name, State: provider.TaskQueued, PollAfter: now.UTC().Add(10 * time.Second)}, nil
}

// decodeVeoPoll maps one long-running operation and returns its private media URI separately.
// decodeVeoPoll 映射一个长时间运行操作并单独返回其私有媒体 URI。
func decodeVeoPoll(reader io.Reader, providerTaskID string, now time.Time) (provider.TaskResult, string, error) {
	var operation veoOperation
	if errDecode := json.NewDecoder(reader).Decode(&operation); errDecode != nil {
		return provider.TaskResult{}, "", fmt.Errorf("%w: decode operation", ErrInvalidVideoResponse)
	}
	if !operation.Done {
		return provider.TaskResult{ProviderTaskID: providerTaskID, State: provider.TaskRunning, PollAfter: now.UTC().Add(10 * time.Second)}, "", nil
	}
	if operation.Error != nil {
		if operation.Error.Code == 1 {
			return provider.TaskResult{ProviderTaskID: providerTaskID, State: provider.TaskCancelled}, "", nil
		}
		return provider.TaskResult{ProviderTaskID: providerTaskID, State: provider.TaskFailed, ErrorCode: "google_video_generation_failed"}, "", nil
	}
	if operation.Response == nil || len(operation.Response.GenerateVideoResponse.GeneratedSamples) != 1 || strings.TrimSpace(operation.Response.GenerateVideoResponse.GeneratedSamples[0].Video.URI) == "" {
		return provider.TaskResult{}, "", fmt.Errorf("%w: completed operation has no single video", ErrInvalidVideoResponse)
	}
	return provider.TaskResult{ProviderTaskID: providerTaskID, State: provider.TaskSucceeded}, operation.Response.GenerateVideoResponse.GeneratedSamples[0].Video.URI, nil
}

// exactVeoOperationPath validates the provider operation name before URL construction.
// exactVeoOperationPath 在构造 URL 前校验供应商操作名称。
func exactVeoOperationPath(value string) (string, error) {
	trimmed := strings.TrimSpace(strings.TrimPrefix(value, "/"))
	segments := strings.Split(trimmed, "/")
	if len(segments) != 4 || segments[0] != "models" || !supportedVeoModel(segments[1]) || segments[2] != "operations" || strings.TrimSpace(segments[3]) == "" || strings.Contains(trimmed, "..") {
		return "", fmt.Errorf("%w: invalid operation name", ErrInvalidVideoDriver)
	}
	return trimmed, nil
}

// exactGoogleVideoPath limits authenticated downloads to the configured Google origin.
// exactGoogleVideoPath 将认证下载限制在已配置的 Google Origin。
func exactGoogleVideoPath(baseURL string, videoURI string) (string, error) {
	base, errBase := url.Parse(baseURL)
	video, errVideo := url.Parse(videoURI)
	if errBase != nil || errVideo != nil || !strings.EqualFold(base.Scheme, video.Scheme) || !strings.EqualFold(base.Host, video.Host) || video.Fragment != "" || !strings.HasPrefix(video.Path, "/upload/v1beta/files/") || (video.RawQuery != "" && video.RawQuery != "alt=media") {
		return "", fmt.Errorf("%w: video URI is outside the configured Google origin", ErrInvalidVideoResponse)
	}
	if video.RawQuery == "" {
		return video.Path, nil
	}
	return video.Path + "?" + video.RawQuery, nil
}

// downloadVideo acquires one authenticated MP4 without exposing its URI.
// downloadVideo 获取一个认证 MP4 且不暴露其 URI。
func (d *VideoTaskDriver) downloadVideo(ctx context.Context, execution provider.ExecutionRequest, path string) ([]byte, error) {
	response, errRequest := d.client.Do(ctx, transport.Request{Binding: execution.Binding, Method: http.MethodGet, Path: path, Authentication: googleAPIKeyAuthentication()})
	if errRequest != nil {
		return nil, errRequest
	}
	defer func() { _ = transport.DrainAndClose(response) }()
	content, errRead := io.ReadAll(io.LimitReader(response.Body, maximumVeoVideoBytes+1))
	if errRead != nil || len(content) == 0 || int64(len(content)) > maximumVeoVideoBytes {
		return nil, fmt.Errorf("%w: downloaded video is empty or exceeds one GiB", ErrInvalidVideoResponse)
	}
	mimeType := strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0])
	if mimeType != "" && mimeType != "video/mp4" {
		return nil, fmt.Errorf("%w: downloaded media is not MP4", ErrInvalidVideoResponse)
	}
	return content, nil
}
