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
	"unicode/utf8"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

const (
	// MusicGenerateActionBindingID identifies MiniMax text-to-music generation.
	// MusicGenerateActionBindingID 标识 MiniMax 文本生成音乐动作。
	MusicGenerateActionBindingID = "action_minimax_music_generate"
	// MusicCoverPrepareActionBindingID identifies MiniMax cover preprocessing.
	// MusicCoverPrepareActionBindingID 标识 MiniMax 翻唱预处理动作。
	MusicCoverPrepareActionBindingID = "action_minimax_music_cover_prepare"
	// MusicCoverActionBindingID identifies MiniMax prepared cover generation.
	// MusicCoverActionBindingID 标识 MiniMax 已准备翻唱生成动作。
	MusicCoverActionBindingID = "action_minimax_music_cover"
	// MusicGenerateProtocolProfileID identifies the MiniMax music generation contract.
	// MusicGenerateProtocolProfileID 标识 MiniMax 音乐生成合同。
	MusicGenerateProtocolProfileID = "minimax.music.generate.v1"
	// MusicCoverPrepareProtocolProfileID identifies the MiniMax cover preprocessing contract.
	// MusicCoverPrepareProtocolProfileID 标识 MiniMax 翻唱预处理合同。
	MusicCoverPrepareProtocolProfileID = "minimax.music.cover.prepare.v1"
	// MusicCoverProtocolProfileID identifies the MiniMax prepared cover contract.
	// MusicCoverProtocolProfileID 标识 MiniMax 已准备翻唱合同。
	MusicCoverProtocolProfileID = "minimax.music.cover.v1"
	// musicCoverHandleLifetime is the provider-documented feature lifetime.
	// musicCoverHandleLifetime 是供应商文档声明的特征有效期。
	musicCoverHandleLifetime = 24 * time.Hour
)

var (
	// ErrInvalidMusicDriver reports an unsupported MiniMax music request.
	// ErrInvalidMusicDriver 表示不受支持的 MiniMax 音乐请求。
	ErrInvalidMusicDriver = errors.New("invalid MiniMax music driver")
	// ErrInvalidMusicResponse reports malformed or failed MiniMax music output.
	// ErrInvalidMusicResponse 表示格式错误或失败的 MiniMax 音乐输出。
	ErrInvalidMusicResponse = errors.New("invalid MiniMax music response")
)

// MusicActionDriver executes one exact synchronous MiniMax music action.
// MusicActionDriver 执行一个精确的同步 MiniMax 音乐动作。
type MusicActionDriver struct {
	// definitionID is the sole provider definition permitted to use this driver.
	// definitionID 是允许使用此 Driver 的唯一供应商 Definition。
	definitionID string
	// actionBindingID is the sole definition-owned action implemented by this instance.
	// actionBindingID 是此实例实现的唯一 Definition 所属动作。
	actionBindingID string
	// client owns provider-scoped authenticated HTTP execution.
	// client 负责供应商作用域的认证 HTTP 执行。
	client *transport.Client
}

// NewMusicActionDriver creates one action-specific MiniMax music driver.
// NewMusicActionDriver 创建一个动作专属 MiniMax 音乐 Driver。
func NewMusicActionDriver(definitionID string, actionBindingID string, client *transport.Client) (*MusicActionDriver, error) {
	if strings.TrimSpace(definitionID) == "" || client == nil {
		return nil, ErrInvalidMusicDriver
	}
	switch actionBindingID {
	case MusicGenerateActionBindingID, MusicCoverPrepareActionBindingID, MusicCoverActionBindingID:
	default:
		return nil, ErrInvalidMusicDriver
	}
	return &MusicActionDriver{definitionID: definitionID, actionBindingID: actionBindingID, client: client}, nil
}

// ProviderDefinitionID returns the sole provider definition owned by this driver.
// ProviderDefinitionID 返回此 Driver 拥有的唯一供应商 Definition。
func (d *MusicActionDriver) ProviderDefinitionID() string {
	if d == nil {
		return ""
	}
	return d.definitionID
}

// ActionBindingID returns the sole MiniMax music action owned by this driver.
// ActionBindingID 返回此 Driver 拥有的唯一 MiniMax 音乐动作。
func (d *MusicActionDriver) ActionBindingID() string {
	if d == nil {
		return ""
	}
	return d.actionBindingID
}

// Execute projects and executes one closed MiniMax music request.
// Execute 投影并执行一个封闭的 MiniMax 音乐请求。
func (d *MusicActionDriver) Execute(ctx context.Context, execution provider.ExecutionRequest) (provider.ExecutionResult, error) {
	if d == nil || d.client == nil {
		return provider.ExecutionResult{}, ErrInvalidMusicDriver
	}
	if execution.Binding.Target.ProviderDefinitionID != d.definitionID {
		return provider.ExecutionResult{}, fmt.Errorf("%w: target definition does not belong to this driver", provider.ErrExecutionBinding)
	}
	if _, errValidate := execution.ValidateForAction(d.actionBindingID, providerconfig.AuthMethodAPIKey, providerconfig.AuthMethodDeviceFlow); errValidate != nil {
		return provider.ExecutionResult{}, errValidate
	}
	var outbound transport.Request
	var errProject error
	switch d.actionBindingID {
	case MusicGenerateActionBindingID:
		outbound, errProject = projectMusicGenerationRequest(execution)
	case MusicCoverPrepareActionBindingID:
		outbound, errProject = projectMusicCoverPreparationRequest(execution)
	case MusicCoverActionBindingID:
		outbound, errProject = projectPreparedMusicCoverRequest(execution)
	}
	if errProject != nil {
		return provider.ExecutionResult{}, errProject
	}
	var (
		response   *http.Response
		errRequest error
	)
	if execution.Execution.Stream && d.actionBindingID != MusicCoverPrepareActionBindingID {
		response, errRequest = d.client.DoStream(ctx, outbound)
	} else {
		response, errRequest = d.client.Do(ctx, outbound)
	}
	if errRequest != nil {
		return provider.ExecutionResult{}, errRequest
	}
	defer func() { _ = transport.DrainAndClose(response) }()
	if execution.Execution.Stream {
		streamed, errStream := decodeMiniMaxAudioHTTPStream(ctx, response, execution.ResourceSink, "music-0", vcp.MediaAudio, musicMIMEType(executionMusicOutputFormat(execution)), execution.Execution.Budget.MaxOutputBytes)
		if errStream != nil {
			return provider.ExecutionResult{}, errStream
		}
		return provider.ExecutionResult{GeneratedResources: []provider.GeneratedResource{{OutputID: "music-0", Kind: vcp.MediaAudio, MIMEType: musicMIMEType(executionMusicOutputFormat(execution)), Data: streamed.Audio}}}, nil
	}
	bounded, errBound := transport.NewBoundedResponseReader(response.Body, transport.MaximumNonStreamingResponseBytes)
	if errBound != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: bound response: %v", ErrInvalidMusicResponse, errBound)
	}
	if d.actionBindingID == MusicCoverPrepareActionBindingID {
		return decodeMusicCoverPreparationResponse(bounded, execution.Now)
	}
	return decodeMusicGenerationResponse(bounded, musicMIMEType(executionMusicOutputFormat(execution)))
}

// musicGenerationRequest is the closed official MiniMax music-generation request.
// musicGenerationRequest 是封闭的官方 MiniMax 音乐生成请求。
type musicGenerationRequest struct {
	// Model is fixed by the resolved offering.
	// Model 由已解析 Offering 固定。
	Model string `json:"model"`
	// Prompt describes style, mood, and scenario.
	// Prompt 描述风格、情绪和场景。
	Prompt string `json:"prompt,omitempty"`
	// Lyrics contains exact lyrics or remains absent for instrumental or optimized generation.
	// Lyrics 包含精确歌词，纯音乐或优化生成时保持缺省。
	Lyrics string `json:"lyrics,omitempty"`
	// Stream follows explicitly selected native audio streaming.
	// Stream 遵循明确选择的原生音频流式输出。
	Stream bool `json:"stream"`
	// OutputFormat is URL so Router can promptly and privately import the result.
	// OutputFormat 为 URL，以便 Router 及时私有导入结果。
	OutputFormat string `json:"output_format"`
	// AudioSetting fixes one documented output encoding.
	// AudioSetting 固定一个文档声明的输出编码。
	AudioSetting musicAudioSetting `json:"audio_setting"`
	// LyricsOptimizer requests provider lyric generation only when VCP omitted lyrics.
	// LyricsOptimizer 仅在 VCP 省略歌词时请求供应商生成歌词。
	LyricsOptimizer bool `json:"lyrics_optimizer,omitempty"`
	// IsInstrumental requests music without vocals.
	// IsInstrumental 请求无声乐的纯音乐。
	IsInstrumental bool `json:"is_instrumental,omitempty"`
	// CoverFeatureID is the private prepared handle for a two-step cover.
	// CoverFeatureID 是两阶段翻唱使用的私有准备句柄。
	CoverFeatureID string `json:"cover_feature_id,omitempty"`
	// AudioURL is one direct public cover source when no lyrics are supplied.
	// AudioURL 是未提供歌词时的一个直接公网翻唱来源。
	AudioURL string `json:"audio_url,omitempty"`
	// AudioBase64 is one direct inline cover source when no lyrics are supplied.
	// AudioBase64 是未提供歌词时的一个直接内联翻唱来源。
	AudioBase64 string `json:"audio_base64,omitempty"`
	// Seed requests provider-relative deterministic sampling.
	// Seed 请求供应商相对确定性采样。
	Seed *int64 `json:"seed,omitempty"`
	// Watermark requests provider AIGC watermarking.
	// Watermark 请求供应商 AIGC 水印。
	Watermark *bool `json:"aigc_watermark,omitempty"`
}

// musicAudioSetting is one documented MiniMax audio encoding.
// musicAudioSetting 是一个文档声明的 MiniMax 音频编码。
type musicAudioSetting struct {
	// SampleRate is the requested audio sample rate.
	// SampleRate 是请求的音频采样率。
	SampleRate int `json:"sample_rate"`
	// Bitrate is the requested encoded bitrate.
	// Bitrate 是请求的编码码率。
	Bitrate int `json:"bitrate"`
	// Format is mp3, wav, or pcm.
	// Format 为 mp3、wav 或 pcm。
	Format string `json:"format"`
	// Channel is the requested channel count when explicitly supplied.
	// Channel 是明确提供时请求的声道数量。
	Channel int `json:"channel,omitempty"`
}

// musicCoverPreparationRequest is the closed official MiniMax preprocessing request.
// musicCoverPreparationRequest 是封闭的官方 MiniMax 预处理请求。
type musicCoverPreparationRequest struct {
	// Model is fixed to the sole model documented by the preprocessing endpoint.
	// Model 固定为预处理端点文档声明的唯一模型。
	Model string `json:"model"`
	// AudioURL carries one direct public reference.
	// AudioURL 承载一个直连公网参考。
	AudioURL string `json:"audio_url,omitempty"`
	// AudioBase64 carries one inline reference.
	// AudioBase64 承载一个内联参考。
	AudioBase64 string `json:"audio_base64,omitempty"`
}

// projectMusicGenerationRequest maps VCP text-to-music input without dropping controls.
// projectMusicGenerationRequest 在不丢弃控制项的前提下映射 VCP 文本生成音乐输入。
func projectMusicGenerationRequest(execution provider.ExecutionRequest) (transport.Request, error) {
	operation := execution.Execution.Payload.MusicGenerate
	if operation == nil || !supportedMiniMaxMusicGenerationModel(execution.Binding.Target.UpstreamModelID) || operation.NegativePrompt != "" || len(operation.References) != 0 || operation.DurationSeconds != 0 || operation.Count > 1 {
		return transport.Request{}, fmt.Errorf("%w: negative_prompt, references, duration_seconds, and multiple outputs have no MiniMax carrier", ErrInvalidMusicDriver)
	}
	promptLength := utf8.RuneCountInString(operation.Prompt)
	lyricsLength := utf8.RuneCountInString(operation.Lyrics)
	if promptLength > 2000 || lyricsLength > 3500 {
		return transport.Request{}, fmt.Errorf("%w: prompt or lyrics exceeds MiniMax limits", ErrInvalidMusicDriver)
	}
	if operation.Instrumental && promptLength == 0 {
		return transport.Request{}, fmt.Errorf("%w: instrumental generation requires a prompt", ErrInvalidMusicDriver)
	}
	if !operation.Instrumental && lyricsLength == 0 && promptLength == 0 {
		return transport.Request{}, fmt.Errorf("%w: automatic lyrics generation requires a prompt", ErrInvalidMusicDriver)
	}
	lyricsOptimizer := false
	if operation.LyricsOptimizer != nil {
		lyricsOptimizer = *operation.LyricsOptimizer
	}
	if lyricsOptimizer && (operation.Instrumental || lyricsLength > 0) || !lyricsOptimizer && !operation.Instrumental && lyricsLength == 0 {
		return transport.Request{}, fmt.Errorf("%w: lyrics_optimizer must match instrumental and explicit lyrics intent", ErrInvalidMusicDriver)
	}
	format, errFormat := normalizeMusicOutputFormat(operation.OutputFormat)
	if errFormat != nil {
		return transport.Request{}, errFormat
	}
	outputFormat := "url"
	if execution.Execution.Stream {
		outputFormat = "hex"
	}
	audioSetting, errAudio := miniMaxMusicAudioSetting(format, operation.SampleRate, operation.Bitrate, operation.Channels)
	if errAudio != nil {
		return transport.Request{}, errAudio
	}
	body := musicGenerationRequest{Model: execution.Binding.Target.UpstreamModelID, Prompt: operation.Prompt, Lyrics: operation.Lyrics, Stream: execution.Execution.Stream, OutputFormat: outputFormat, AudioSetting: audioSetting, LyricsOptimizer: lyricsOptimizer, IsInstrumental: operation.Instrumental, Seed: operation.Seed, Watermark: operation.Watermark}
	return encodeMusicRequest(execution, "/v1/music_generation", body)
}

// projectMusicCoverPreparationRequest maps one exact audio materialization to preprocessing.
// projectMusicCoverPreparationRequest 将一个精确音频物化映射到预处理。
func projectMusicCoverPreparationRequest(execution provider.ExecutionRequest) (transport.Request, error) {
	operation := execution.Execution.Payload.MusicCoverPrepare
	if operation == nil || operation.Source.Kind != vcp.MediaAudio || operation.Source.Role != vcp.MediaRoleCoverReference || operation.Lyrics != "" || len(execution.MaterializedInputs) != 1 {
		return transport.Request{}, fmt.Errorf("%w: cover preprocessing requires one audio cover_reference and cannot carry lyrics", ErrInvalidMusicDriver)
	}
	input := execution.MaterializedInputs[0]
	if input.InputID != operation.Source.ID || input.ResourceID != operation.Source.Resource.ResourceID || input.Kind != vcp.MediaAudio || input.Role != vcp.MediaRoleCoverReference {
		return transport.Request{}, fmt.Errorf("%w: cover source materialization does not match VCP input", ErrInvalidMusicDriver)
	}
	body := musicCoverPreparationRequest{Model: "music-cover"}
	switch input.Mode {
	case catalog.MaterializationDirectRemoteURL:
		if errURL := validatePublicMusicURL(input.RemoteURL); errURL != nil {
			return transport.Request{}, errURL
		}
		body.AudioURL = input.RemoteURL
	case catalog.MaterializationInlineBase64:
		if strings.TrimSpace(input.InlineBase64) == "" {
			return transport.Request{}, fmt.Errorf("%w: inline cover audio is empty", ErrInvalidMusicDriver)
		}
		body.AudioBase64 = input.InlineBase64
	default:
		return transport.Request{}, fmt.Errorf("%w: cover source requires direct URL or inline Base64", ErrInvalidMusicDriver)
	}
	return encodeMusicRequest(execution, "/v1/music_cover_preprocess", body)
}

// projectPreparedMusicCoverRequest maps the exclusive direct-source or Router-prepared cover workflow.
// projectPreparedMusicCoverRequest 映射互斥的直接来源或 Router 已准备翻唱工作流。
func projectPreparedMusicCoverRequest(execution provider.ExecutionRequest) (transport.Request, error) {
	operation := execution.Execution.Payload.MusicCover
	if operation == nil || !supportedMiniMaxMusicCoverModel(execution.Binding.Target.UpstreamModelID) {
		return transport.Request{}, fmt.Errorf("%w: supported MiniMax cover operation is required", ErrInvalidMusicDriver)
	}
	promptLength := utf8.RuneCountInString(operation.Prompt)
	lyricsLength := utf8.RuneCountInString(operation.Lyrics)
	if promptLength < 10 || promptLength > 300 || lyricsLength > 1000 || lyricsLength > 0 && lyricsLength < 10 {
		return transport.Request{}, fmt.Errorf("%w: cover prompt must contain 10-300 characters and lyrics at most 1000 characters", ErrInvalidMusicDriver)
	}
	format, errFormat := normalizeMusicOutputFormat(operation.OutputFormat)
	if errFormat != nil {
		return transport.Request{}, errFormat
	}
	outputFormat := "url"
	if execution.Execution.Stream {
		outputFormat = "hex"
	}
	audioSetting, errAudio := miniMaxMusicAudioSetting(format, operation.SampleRate, operation.Bitrate, operation.Channels)
	if errAudio != nil {
		return transport.Request{}, errAudio
	}
	body := musicGenerationRequest{Model: execution.Binding.Target.UpstreamModelID, Prompt: operation.Prompt, Lyrics: operation.Lyrics, Stream: execution.Execution.Stream, OutputFormat: outputFormat, AudioSetting: audioSetting, Seed: operation.Seed, Watermark: operation.Watermark}
	if operation.Source != nil {
		if execution.PreparedWorkflow != nil || len(execution.MaterializedInputs) != 1 {
			return transport.Request{}, fmt.Errorf("%w: direct cover requires one materialized audio source without preparation", ErrInvalidMusicDriver)
		}
		input := execution.MaterializedInputs[0]
		if input.InputID != operation.Source.ID || input.ResourceID != operation.Source.Resource.ResourceID || input.Kind != vcp.MediaAudio || input.Role != vcp.MediaRoleCoverReference {
			return transport.Request{}, fmt.Errorf("%w: direct cover materialization does not match VCP input", ErrInvalidMusicDriver)
		}
		switch input.Mode {
		case catalog.MaterializationDirectRemoteURL:
			if errURL := validatePublicMusicURL(input.RemoteURL); errURL != nil {
				return transport.Request{}, errURL
			}
			body.AudioURL = input.RemoteURL
		case catalog.MaterializationInlineBase64:
			if strings.TrimSpace(input.InlineBase64) == "" {
				return transport.Request{}, fmt.Errorf("%w: inline cover audio is empty", ErrInvalidMusicDriver)
			}
			body.AudioBase64 = input.InlineBase64
		default:
			return transport.Request{}, fmt.Errorf("%w: direct cover source requires direct URL or inline Base64", ErrInvalidMusicDriver)
		}
	} else {
		prepared := execution.PreparedWorkflow
		if lyricsLength < 10 || prepared == nil || prepared.PreparationID != operation.PreparationID || strings.TrimSpace(prepared.ProviderHandle) == "" || !execution.Now.Before(prepared.ExpiresAt) || len(execution.MaterializedInputs) != 0 {
			return transport.Request{}, fmt.Errorf("%w: valid Router-resolved cover preparation and 10-1000 lyrics characters are required", ErrInvalidMusicDriver)
		}
		body.CoverFeatureID = prepared.ProviderHandle
	}
	return encodeMusicRequest(execution, "/v1/music_generation", body)
}

// supportedMiniMaxMusicGenerationModel applies the exact model enumeration from the pinned MiniMax CLI source.
// supportedMiniMaxMusicGenerationModel 应用固定 MiniMax CLI 源码中的精确模型枚举。
func supportedMiniMaxMusicGenerationModel(model string) bool {
	switch model {
	case "music-3.0", "music-2.6", "music-2.6-free", "music-2.5+", "music-2.5":
		return true
	default:
		return false
	}
}

// supportedMiniMaxMusicCoverModel applies the exact paid and free cover model enumeration.
// supportedMiniMaxMusicCoverModel 应用精确的付费与免费翻唱模型枚举。
func supportedMiniMaxMusicCoverModel(model string) bool {
	return model == "music-cover" || model == "music-cover-free"
}

// encodeMusicRequest serializes one authenticated MiniMax JSON request.
// encodeMusicRequest 序列化一个经过认证的 MiniMax JSON 请求。
func encodeMusicRequest(execution provider.ExecutionRequest, path string, body any) (transport.Request, error) {
	encoded, errEncode := json.Marshal(body)
	if errEncode != nil {
		return transport.Request{}, fmt.Errorf("%w: encode request: %v", ErrInvalidMusicDriver, errEncode)
	}
	return transport.Request{Binding: execution.Binding, Method: http.MethodPost, Path: path, Body: encoded, Headers: []transport.Header{{Name: "Content-Type", Value: "application/json"}}, Authentication: transport.Authentication{Mode: transport.AuthenticationBearer}, IdempotencyKey: execution.Execution.IdempotencyKey}, nil
}

// normalizeMusicOutputFormat resolves the closed MiniMax encoding set.
// normalizeMusicOutputFormat 解析封闭的 MiniMax 编码集合。
func normalizeMusicOutputFormat(format string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(format))
	if normalized == "" {
		normalized = "mp3"
	}
	switch normalized {
	case "mp3", "wav", "pcm":
		return normalized, nil
	default:
		return "", fmt.Errorf("%w: unsupported MiniMax music output format", ErrInvalidMusicDriver)
	}
}

// defaultMusicAudioSetting returns one high-quality documented MiniMax encoding.
// defaultMusicAudioSetting 返回一个高质量且文档声明的 MiniMax 编码。
func defaultMusicAudioSetting(format string) musicAudioSetting {
	return musicAudioSetting{SampleRate: 44100, Bitrate: 256000, Format: format}
}

// miniMaxMusicAudioSetting applies released defaults while preserving explicit positive encoding controls.
// miniMaxMusicAudioSetting 应用已发布默认值并保留明确的正数编码控制。
func miniMaxMusicAudioSetting(format string, sampleRate int, bitrate int, channels int) (musicAudioSetting, error) {
	setting := defaultMusicAudioSetting(format)
	if sampleRate > 0 {
		setting.SampleRate = sampleRate
	}
	if bitrate > 0 {
		setting.Bitrate = bitrate
	}
	if channels > 0 {
		setting.Channel = channels
	}
	if setting.SampleRate <= 0 || setting.Bitrate <= 0 || setting.Channel < 0 || setting.Channel > 2 {
		return musicAudioSetting{}, fmt.Errorf("%w: MiniMax music audio controls are invalid", ErrInvalidMusicDriver)
	}
	return setting, nil
}

// executionMusicOutputFormat returns the exact output format of the active music operation.
// executionMusicOutputFormat 返回当前音乐操作的精确输出格式。
func executionMusicOutputFormat(execution provider.ExecutionRequest) string {
	if execution.Execution.Payload.MusicGenerate != nil {
		return execution.Execution.Payload.MusicGenerate.OutputFormat
	}
	return execution.Execution.Payload.MusicCover.OutputFormat
}

// musicMIMEType maps one validated MiniMax audio format to its media type.
// musicMIMEType 将一个已验证的 MiniMax 音频格式映射到媒体类型。
func musicMIMEType(format string) string {
	normalized, _ := normalizeMusicOutputFormat(format)
	switch normalized {
	case "wav":
		return "audio/wav"
	case "pcm":
		return "audio/L16"
	default:
		return "audio/mpeg"
	}
}

// validatePublicMusicURL verifies one provider-consumable HTTP(S) URL.
// validatePublicMusicURL 校验一个供应商可消费的 HTTP(S) URL。
func validatePublicMusicURL(value string) error {
	parsed, errParse := url.ParseRequestURI(value)
	if errParse != nil || parsed.Host == "" || parsed.User != nil || parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("%w: cover audio URL is invalid", ErrInvalidMusicDriver)
	}
	return nil
}

// musicGenerationResponse is the closed successful MiniMax generation response.
// musicGenerationResponse 是封闭的成功 MiniMax 生成响应。
type musicGenerationResponse struct {
	// Data contains one completed output acquisition value.
	// Data 包含一个已完成输出获取值。
	Data musicGenerationData `json:"data"`
	// TraceID is the provider request identifier.
	// TraceID 是供应商请求标识。
	TraceID string `json:"trace_id"`
	// BaseResponse contains provider application status.
	// BaseResponse 包含供应商应用状态。
	BaseResponse baseResponse `json:"base_resp"`
}

// musicGenerationData contains generated audio and completion status.
// musicGenerationData 包含生成音频与完成状态。
type musicGenerationData struct {
	// AudioURL is the requested temporary result URL.
	// AudioURL 是请求的临时结果 URL。
	AudioURL string `json:"audio_url"`
	// Status is two only when generation completed.
	// Status 仅在生成完成时为二。
	Status int `json:"status"`
}

// decodeMusicGenerationResponse extracts one temporary public audio URL for Router import.
// decodeMusicGenerationResponse 提取一个临时公网音频 URL 供 Router 导入。
func decodeMusicGenerationResponse(reader io.Reader, mimeType string) (provider.ExecutionResult, error) {
	var response musicGenerationResponse
	if errDecode := json.NewDecoder(reader).Decode(&response); errDecode != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: decode response: %v", ErrInvalidMusicResponse, errDecode)
	}
	if response.BaseResponse.StatusCode != 0 || response.Data.Status != 2 || strings.TrimSpace(response.TraceID) == "" || validatePublicMusicURL(response.Data.AudioURL) != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: provider status %d", ErrInvalidMusicResponse, response.BaseResponse.StatusCode)
	}
	return provider.ExecutionResult{UpstreamResponseID: response.TraceID, GeneratedResources: []provider.GeneratedResource{{OutputID: "music-0", Kind: vcp.MediaAudio, MIMEType: mimeType, DownloadURL: response.Data.AudioURL}}}, nil
}

// musicCoverPreparationResponse is the closed successful MiniMax preprocessing response.
// musicCoverPreparationResponse 是封闭的成功 MiniMax 预处理响应。
type musicCoverPreparationResponse struct {
	// CoverFeatureID is the provider-private prepared feature identifier.
	// CoverFeatureID 是供应商私有的已准备特征标识。
	CoverFeatureID string `json:"cover_feature_id"`
	// FormattedLyrics contains editable structured lyrics.
	// FormattedLyrics 包含可编辑的结构化歌词。
	FormattedLyrics string `json:"formatted_lyrics"`
	// StructureResult contains a JSON-encoded song structure.
	// StructureResult 包含 JSON 编码的歌曲结构。
	StructureResult string `json:"structure_result"`
	// AudioDuration contains source duration in seconds.
	// AudioDuration 包含来源时长秒数。
	AudioDuration float64 `json:"audio_duration"`
	// TraceID is the provider request identifier.
	// TraceID 是供应商请求标识。
	TraceID string `json:"trace_id"`
	// BaseResponse contains provider application status.
	// BaseResponse 包含供应商应用状态。
	BaseResponse baseResponse `json:"base_resp"`
}

// musicStructureResult is the provider's nested JSON structure contract.
// musicStructureResult 是供应商嵌套 JSON 结构合同。
type musicStructureResult struct {
	// SegmentCount declares the exact number of returned segments.
	// SegmentCount 声明返回段落的精确数量。
	SegmentCount int `json:"num_segments"`
	// Segments contains ordered song intervals.
	// Segments 包含有序歌曲区间。
	Segments []musicStructureSegment `json:"segments"`
}

// musicStructureSegment is one provider song interval.
// musicStructureSegment 是一个供应商歌曲区间。
type musicStructureSegment struct {
	// Start is the inclusive offset in seconds.
	// Start 是包含端点的秒偏移。
	Start float64 `json:"start"`
	// End is the exclusive offset in seconds.
	// End 是不包含端点的秒偏移。
	End float64 `json:"end"`
	// Label is one documented closed song-section label.
	// Label 是一个文档声明的封闭歌曲段落标签。
	Label string `json:"label"`
}

// decodeMusicCoverPreparationResponse keeps the feature handle private and parses safe structure.
// decodeMusicCoverPreparationResponse 保持特征句柄私有并解析安全结构。
func decodeMusicCoverPreparationResponse(reader io.Reader, now time.Time) (provider.ExecutionResult, error) {
	var response musicCoverPreparationResponse
	if errDecode := json.NewDecoder(reader).Decode(&response); errDecode != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: decode response: %v", ErrInvalidMusicResponse, errDecode)
	}
	if response.BaseResponse.StatusCode != 0 || strings.TrimSpace(response.TraceID) == "" || strings.TrimSpace(response.CoverFeatureID) == "" || strings.TrimSpace(response.FormattedLyrics) == "" || response.AudioDuration <= 0 {
		return provider.ExecutionResult{}, fmt.Errorf("%w: provider status %d", ErrInvalidMusicResponse, response.BaseResponse.StatusCode)
	}
	var structure musicStructureResult
	if errStructure := json.Unmarshal([]byte(response.StructureResult), &structure); errStructure != nil || structure.SegmentCount != len(structure.Segments) || structure.SegmentCount == 0 {
		return provider.ExecutionResult{}, fmt.Errorf("%w: invalid cover structure", ErrInvalidMusicResponse)
	}
	segments := make([]vcp.MusicStructureSegment, 0, len(structure.Segments))
	for _, segment := range structure.Segments {
		canonical := vcp.MusicStructureSegment{Label: segment.Label, StartSeconds: segment.Start, EndSeconds: segment.End}
		if errSegment := canonical.Validate(); errSegment != nil || segment.End > response.AudioDuration {
			return provider.ExecutionResult{}, fmt.Errorf("%w: invalid cover structure segment", ErrInvalidMusicResponse)
		}
		segments = append(segments, canonical)
	}
	preparation := &provider.MusicCoverPreparationResult{ProviderHandle: response.CoverFeatureID, FormattedLyrics: response.FormattedLyrics, Structure: segments, AudioDurationSeconds: response.AudioDuration, ExpiresAt: now.Add(musicCoverHandleLifetime)}
	return provider.ExecutionResult{UpstreamResponseID: response.TraceID, MusicCoverPreparation: preparation}, nil
}
