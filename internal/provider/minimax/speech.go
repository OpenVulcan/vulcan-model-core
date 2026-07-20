package minimax

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

const (
	// SpeechSynthesizeActionBindingID identifies MiniMax synchronous speech synthesis.
	// SpeechSynthesizeActionBindingID 标识 MiniMax 同步语音合成动作。
	SpeechSynthesizeActionBindingID = "action_minimax_speech_synthesize"
	// SpeechSynthesizeAsyncActionBindingID identifies MiniMax long-text asynchronous speech synthesis.
	// SpeechSynthesizeAsyncActionBindingID 标识 MiniMax 长文本异步语音合成动作。
	SpeechSynthesizeAsyncActionBindingID = "action_minimax_speech_synthesize_async"
	// SpeechSynthesizeProtocolProfileID identifies the MiniMax synchronous T2A contract.
	// SpeechSynthesizeProtocolProfileID 标识 MiniMax 同步 T2A 合同。
	SpeechSynthesizeProtocolProfileID = "minimax.speech.t2a.v2"
	// SpeechSynthesizeAsyncProtocolProfileID identifies the MiniMax asynchronous T2A contract.
	// SpeechSynthesizeAsyncProtocolProfileID 标识 MiniMax 异步 T2A 合同。
	SpeechSynthesizeAsyncProtocolProfileID = "minimax.speech.t2a_async.v2"
	// minimaxSpeechPollInterval is the provider task observation interval.
	// minimaxSpeechPollInterval 是供应商任务观察间隔。
	minimaxSpeechPollInterval = 10 * time.Second
)

var (
	// ErrInvalidSpeechDriver reports an incomplete or unsupported MiniMax speech execution.
	// ErrInvalidSpeechDriver 表示 MiniMax 语音执行不完整或不受支持。
	ErrInvalidSpeechDriver = errors.New("invalid MiniMax speech driver")
	// ErrInvalidSpeechResponse reports malformed MiniMax speech output.
	// ErrInvalidSpeechResponse 表示 MiniMax 语音输出格式错误。
	ErrInvalidSpeechResponse = errors.New("invalid MiniMax speech response")
)

// SpeechActionDriver executes MiniMax synchronous non-realtime speech synthesis.
// SpeechActionDriver 执行 MiniMax 同步非实时语音合成。
type SpeechActionDriver struct {
	// definitionID fixes the sole owning provider definition.
	// definitionID 固定唯一所属供应商定义。
	definitionID string
	// client owns authenticated provider-scoped HTTP execution.
	// client 负责经过认证且限定供应商作用域的 HTTP 执行。
	client *transport.Client
}

// NewSpeechActionDriver creates one MiniMax synchronous speech driver.
// NewSpeechActionDriver 创建一个 MiniMax 同步语音驱动。
func NewSpeechActionDriver(definitionID string, client *transport.Client) (*SpeechActionDriver, error) {
	if strings.TrimSpace(definitionID) == "" || client == nil {
		return nil, ErrInvalidSpeechDriver
	}
	return &SpeechActionDriver{definitionID: definitionID, client: client}, nil
}

// ProviderDefinitionID returns the sole provider definition owned by this driver.
// ProviderDefinitionID 返回此驱动唯一所属的供应商定义。
func (d *SpeechActionDriver) ProviderDefinitionID() string {
	if d == nil {
		return ""
	}
	return d.definitionID
}

// ActionBindingID returns the synchronous speech action binding.
// ActionBindingID 返回同步语音动作绑定。
func (d *SpeechActionDriver) ActionBindingID() string { return SpeechSynthesizeActionBindingID }

// Execute sends one synchronous T2A request and imports its hexadecimal audio bytes.
// Execute 发送一个同步 T2A 请求并导入其十六进制音频字节。
func (d *SpeechActionDriver) Execute(ctx context.Context, execution provider.ExecutionRequest) (provider.ExecutionResult, error) {
	if errValidate := validateMiniMaxSpeechExecution(d.definitionID, d.client, SpeechSynthesizeActionBindingID, execution); errValidate != nil {
		return provider.ExecutionResult{}, errValidate
	}
	projection, errProject := projectMiniMaxSpeech(execution, false)
	if errProject != nil {
		return provider.ExecutionResult{}, errProject
	}
	response, errRequest := d.client.Do(ctx, transport.Request{Binding: execution.Binding, Method: http.MethodPost, Path: "/v1/t2a_v2", Body: projection.body, Headers: []transport.Header{{Name: "Content-Type", Value: "application/json"}}, Authentication: transport.Authentication{Mode: transport.AuthenticationBearer}, IdempotencyKey: execution.Execution.IdempotencyKey})
	if errRequest != nil {
		return provider.ExecutionResult{}, errRequest
	}
	defer func() { _ = transport.DrainAndClose(response) }()
	return decodeMiniMaxSpeech(response.Body, projection.mimeType)
}

// SpeechTaskDriver owns MiniMax long-text task creation, polling, and file resolution.
// SpeechTaskDriver 负责 MiniMax 长文本任务创建、轮询与文件解析。
type SpeechTaskDriver struct {
	// definitionID fixes the sole owning provider definition.
	// definitionID 固定唯一所属供应商定义。
	definitionID string
	// client owns authenticated provider-scoped HTTP execution.
	// client 负责经过认证且限定供应商作用域的 HTTP 执行。
	client *transport.Client
}

// NewSpeechTaskDriver creates one MiniMax asynchronous speech driver.
// NewSpeechTaskDriver 创建一个 MiniMax 异步语音驱动。
func NewSpeechTaskDriver(definitionID string, client *transport.Client) (*SpeechTaskDriver, error) {
	if strings.TrimSpace(definitionID) == "" || client == nil {
		return nil, ErrInvalidSpeechDriver
	}
	return &SpeechTaskDriver{definitionID: definitionID, client: client}, nil
}

// ProviderDefinitionID returns the sole provider definition owned by this driver.
// ProviderDefinitionID 返回此驱动唯一所属的供应商定义。
func (d *SpeechTaskDriver) ProviderDefinitionID() string {
	if d == nil {
		return ""
	}
	return d.definitionID
}

// ActionBindingID returns the asynchronous speech action binding.
// ActionBindingID 返回异步语音动作绑定。
func (d *SpeechTaskDriver) ActionBindingID() string { return SpeechSynthesizeAsyncActionBindingID }

// Start creates one MiniMax long-text speech task.
// Start 创建一个 MiniMax 长文本语音任务。
func (d *SpeechTaskDriver) Start(ctx context.Context, execution provider.ExecutionRequest) (provider.TaskResult, error) {
	if errValidate := validateMiniMaxSpeechExecution(d.definitionID, d.client, SpeechSynthesizeAsyncActionBindingID, execution); errValidate != nil {
		return provider.TaskResult{}, errValidate
	}
	projection, errProject := projectMiniMaxSpeech(execution, true)
	if errProject != nil {
		return provider.TaskResult{}, errProject
	}
	response, errRequest := d.client.Do(ctx, transport.Request{Binding: execution.Binding, Method: http.MethodPost, Path: "/v1/t2a_async_v2", Body: projection.body, Headers: []transport.Header{{Name: "Content-Type", Value: "application/json"}}, Authentication: transport.Authentication{Mode: transport.AuthenticationBearer}, IdempotencyKey: execution.Execution.IdempotencyKey})
	if errRequest != nil {
		return provider.TaskResult{}, errRequest
	}
	defer func() { _ = transport.DrainAndClose(response) }()
	return decodeMiniMaxSpeechStart(response.Body, execution.Now)
}

// Poll observes one long-text task and resolves its successful audio file.
// Poll 观察一个长文本任务并解析其成功生成的音频文件。
func (d *SpeechTaskDriver) Poll(ctx context.Context, execution provider.ExecutionRequest, providerTaskID string) (provider.TaskResult, error) {
	if errValidate := validateMiniMaxSpeechExecution(d.definitionID, d.client, SpeechSynthesizeAsyncActionBindingID, execution); errValidate != nil {
		return provider.TaskResult{}, errValidate
	}
	if !isPositiveDecimalIdentifier(providerTaskID) {
		return provider.TaskResult{}, fmt.Errorf("%w: provider task identifier must be a positive decimal integer", ErrInvalidSpeechDriver)
	}
	response, errRequest := d.client.Do(ctx, transport.Request{Binding: execution.Binding, Method: http.MethodGet, Path: "/v1/query/t2a_async_query_v2?task_id=" + url.QueryEscape(providerTaskID), Authentication: transport.Authentication{Mode: transport.AuthenticationBearer}})
	if errRequest != nil {
		return provider.TaskResult{}, errRequest
	}
	defer func() { _ = transport.DrainAndClose(response) }()
	observation, fileID, errDecode := decodeMiniMaxSpeechPoll(response.Body, providerTaskID, execution.Now)
	if errDecode != nil || observation.State != provider.TaskSucceeded || observation.Result != nil {
		return observation, errDecode
	}
	fileResponse, errFile := d.client.Do(ctx, transport.Request{Binding: execution.Binding, Method: http.MethodGet, Path: "/v1/files/retrieve?file_id=" + url.QueryEscape(fileID), Authentication: transport.Authentication{Mode: transport.AuthenticationBearer}})
	if errFile != nil {
		return provider.TaskResult{}, errFile
	}
	defer func() { _ = transport.DrainAndClose(fileResponse) }()
	_, mimeType, errFormat := miniMaxSpeechOutput(execution.Execution.Payload.SpeechSynthesize.OutputFormat)
	if errFormat != nil {
		return provider.TaskResult{}, errFormat
	}
	return decodeMiniMaxSpeechFile(fileResponse.Body, providerTaskID, mimeType)
}

// Cancel reports MiniMax's documented lack of an asynchronous T2A cancellation endpoint.
// Cancel 报告 MiniMax 文档中缺少异步 T2A 取消端点。
func (d *SpeechTaskDriver) Cancel(_ context.Context, execution provider.ExecutionRequest, providerTaskID string) (provider.TaskResult, error) {
	if errValidate := validateMiniMaxSpeechExecution(d.definitionID, d.client, SpeechSynthesizeAsyncActionBindingID, execution); errValidate != nil {
		return provider.TaskResult{}, errValidate
	}
	if !isPositiveDecimalIdentifier(providerTaskID) {
		return provider.TaskResult{}, fmt.Errorf("%w: provider task identifier must be a positive decimal integer", ErrInvalidSpeechDriver)
	}
	return provider.TaskResult{}, fmt.Errorf("%w: MiniMax does not document asynchronous T2A cancellation", ErrInvalidSpeechDriver)
}

// miniMaxSpeechProjection preserves encoded request bytes and verified output media type.
// miniMaxSpeechProjection 保留编码后的请求字节与已验证的输出媒体类型。
type miniMaxSpeechProjection struct {
	// body is the exact provider request body.
	// body 是精确的供应商请求正文。
	body []byte
	// mimeType is the Router-probeable output media type.
	// mimeType 是 Router 可探测的输出媒体类型。
	mimeType string
}

// miniMaxVoiceSetting contains provider-native voice controls.
// miniMaxVoiceSetting 包含供应商原生声音控制。
type miniMaxVoiceSetting struct {
	// VoiceID identifies a built-in or account-owned voice.
	// VoiceID 标识一个内置或账户自有声音。
	VoiceID string `json:"voice_id"`
	// Speed controls speaking speed from 0.5 through 2.0.
	// Speed 控制 0.5 到 2.0 的语速。
	Speed float64 `json:"speed"`
	// Volume controls provider volume from greater than zero through ten.
	// Volume 控制大于零到十的供应商音量。
	Volume float64 `json:"vol"`
	// Pitch controls the integer semitone level from minus twelve through twelve.
	// Pitch 控制负十二到十二的整数半音级别。
	Pitch int `json:"pitch"`
}

// miniMaxSyncAudioSetting contains synchronous audio encoding controls.
// miniMaxSyncAudioSetting 包含同步音频编码控制。
type miniMaxSyncAudioSetting struct {
	// SampleRate is one documented sample rate.
	// SampleRate 是一个文档规定的采样率。
	SampleRate int `json:"sample_rate"`
	// Bitrate is one documented MP3 bitrate.
	// Bitrate 是一个文档规定的 MP3 比特率。
	Bitrate int `json:"bitrate,omitempty"`
	// Format is MP3 or WAV.
	// Format 是 MP3 或 WAV。
	Format string `json:"format"`
	// Channel is mono or stereo.
	// Channel 是单声道或立体声。
	Channel int `json:"channel"`
}

// miniMaxAsyncAudioSetting contains asynchronous audio encoding controls.
// miniMaxAsyncAudioSetting 包含异步音频编码控制。
type miniMaxAsyncAudioSetting struct {
	// SampleRate is one documented asynchronous sample rate.
	// SampleRate 是一个文档规定的异步采样率。
	SampleRate int `json:"audio_sample_rate"`
	// Bitrate is one documented MP3 bitrate.
	// Bitrate 是一个文档规定的 MP3 比特率。
	Bitrate int `json:"bitrate,omitempty"`
	// Format is MP3 or WAV.
	// Format 是 MP3 或 WAV。
	Format string `json:"format"`
	// Channel is mono or stereo.
	// Channel 是单声道或立体声。
	Channel int `json:"channel"`
}

// miniMaxSyncSpeechRequest is the closed synchronous T2A body.
// miniMaxSyncSpeechRequest 是封闭的同步 T2A 正文。
type miniMaxSyncSpeechRequest struct {
	// Model is the resolved upstream speech model.
	// Model 是解析后的上游语音模型。
	Model string `json:"model"`
	// Text is the exact caller text.
	// Text 是调用方的精确文本。
	Text string `json:"text"`
	// Stream explicitly disables provider streaming.
	// Stream 显式关闭供应商流式输出。
	Stream bool `json:"stream"`
	// LanguageBoost is one documented provider language value.
	// LanguageBoost 是一个文档规定的供应商语言值。
	LanguageBoost string `json:"language_boost,omitempty"`
	// OutputFormat requests hexadecimal response audio.
	// OutputFormat 请求十六进制响应音频。
	OutputFormat string `json:"output_format"`
	// VoiceSetting contains exact voice controls.
	// VoiceSetting 包含精确的声音控制。
	VoiceSetting miniMaxVoiceSetting `json:"voice_setting"`
	// AudioSetting contains exact encoding controls.
	// AudioSetting 包含精确的编码控制。
	AudioSetting miniMaxSyncAudioSetting `json:"audio_setting"`
}

// miniMaxAsyncSpeechRequest is the closed direct-text asynchronous T2A body.
// miniMaxAsyncSpeechRequest 是封闭的直接文本异步 T2A 正文。
type miniMaxAsyncSpeechRequest struct {
	// Model is the resolved upstream speech model.
	// Model 是解析后的上游语音模型。
	Model string `json:"model"`
	// Text is the exact caller text.
	// Text 是调用方的精确文本。
	Text string `json:"text"`
	// LanguageBoost is one documented provider language value.
	// LanguageBoost 是一个文档规定的供应商语言值。
	LanguageBoost string `json:"language_boost,omitempty"`
	// VoiceSetting contains exact voice controls.
	// VoiceSetting 包含精确的声音控制。
	VoiceSetting miniMaxVoiceSetting `json:"voice_setting"`
	// AudioSetting contains exact asynchronous encoding controls.
	// AudioSetting 包含精确的异步编码控制。
	AudioSetting miniMaxAsyncAudioSetting `json:"audio_setting"`
}

// miniMaxBaseResponse contains provider application status.
// miniMaxBaseResponse 包含供应商应用状态。
type miniMaxBaseResponse struct {
	// StatusCode is zero on success.
	// StatusCode 成功时为零。
	StatusCode int `json:"status_code"`
}

// miniMaxSpeechResponse contains synchronous hexadecimal audio.
// miniMaxSpeechResponse 包含同步十六进制音频。
type miniMaxSpeechResponse struct {
	// Data may be null when the provider cannot generate audio.
	// Data 在供应商无法生成音频时可能为空。
	Data *struct {
		// Audio is hexadecimal audio content.
		// Audio 是十六进制音频内容。
		Audio string `json:"audio"`
		// Status is two for complete non-streaming output.
		// Status 对完整非流式输出为二。
		Status int `json:"status"`
	} `json:"data"`
	// BaseResponse records application-level success.
	// BaseResponse 记录应用层成功状态。
	BaseResponse miniMaxBaseResponse `json:"base_resp"`
}

// miniMaxSpeechStartResponse contains one private task identity.
// miniMaxSpeechStartResponse 包含一个私有任务标识。
type miniMaxSpeechStartResponse struct {
	// TaskID is the documented numeric task identifier.
	// TaskID 是文档规定的数值任务标识。
	TaskID miniMaxDecimalIdentifier `json:"task_id"`
	// BaseResponse records application-level success.
	// BaseResponse 记录应用层成功状态。
	BaseResponse miniMaxBaseResponse `json:"base_resp"`
}

// miniMaxSpeechPollResponse contains one documented task observation.
// miniMaxSpeechPollResponse 包含一次文档规定的任务观察。
type miniMaxSpeechPollResponse struct {
	// TaskID is the observed numeric task identifier.
	// TaskID 是观察到的数值任务标识。
	TaskID miniMaxDecimalIdentifier `json:"task_id"`
	// Status is processing, success, failed, or expired.
	// Status 是处理中、成功、失败或已过期。
	Status string `json:"status"`
	// FileID identifies generated audio after success.
	// FileID 标识成功后生成的音频。
	FileID miniMaxDecimalIdentifier `json:"file_id"`
	// BaseResponse records application-level success.
	// BaseResponse 记录应用层成功状态。
	BaseResponse miniMaxBaseResponse `json:"base_resp"`
}

// miniMaxDecimalIdentifier preserves the API's documented numeric and example JSON forms.
// miniMaxDecimalIdentifier 保留 API 文档声明与示例中的数值 JSON 形式。
type miniMaxDecimalIdentifier string

// UnmarshalJSON accepts a positive decimal integer encoded as a JSON number or string.
// UnmarshalJSON 接受编码为 JSON 数字或字符串的正十进制整数。
func (i *miniMaxDecimalIdentifier) UnmarshalJSON(data []byte) error {
	var textValue string
	if errText := json.Unmarshal(data, &textValue); errText == nil {
		if !isPositiveDecimalIdentifier(textValue) {
			return ErrInvalidSpeechResponse
		}
		*i = miniMaxDecimalIdentifier(textValue)
		return nil
	}
	var numberValue json.Number
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	if errNumber := decoder.Decode(&numberValue); errNumber != nil || !isPositiveDecimalIdentifier(numberValue.String()) {
		return ErrInvalidSpeechResponse
	}
	*i = miniMaxDecimalIdentifier(numberValue.String())
	return nil
}

// validateMiniMaxSpeechExecution verifies exact definition, action, and API-key ownership.
// validateMiniMaxSpeechExecution 校验精确的定义、动作与 API 密钥归属。
func validateMiniMaxSpeechExecution(definitionID string, client *transport.Client, actionBindingID string, execution provider.ExecutionRequest) error {
	if strings.TrimSpace(definitionID) == "" || client == nil || execution.Binding.Target.ProviderDefinitionID != definitionID {
		return fmt.Errorf("%w: target definition does not belong to this driver", provider.ErrExecutionBinding)
	}
	_, errValidate := execution.ValidateForAction(actionBindingID, providerconfig.AuthMethodAPIKey)
	return errValidate
}

// projectMiniMaxSpeech maps one canonical request into exactly one synchronous or asynchronous carrier.
// projectMiniMaxSpeech 将一个规范请求映射为唯一的同步或异步载体。
func projectMiniMaxSpeech(execution provider.ExecutionRequest, asynchronous bool) (miniMaxSpeechProjection, error) {
	operation := execution.Execution.Payload.SpeechSynthesize
	model := execution.Binding.Target.UpstreamModelID
	if operation == nil || (model != "speech-2.8-hd" && model != "speech-2.8-turbo") || len(operation.Segments) != 0 || operation.Style != "" || operation.Timestamps {
		return miniMaxSpeechProjection{}, fmt.Errorf("%w: model, multi-speaker segments, style, or timestamps are unsupported", ErrInvalidSpeechDriver)
	}
	textLimit := 9999
	if asynchronous {
		textLimit = 50000
	}
	if length := len([]rune(operation.Text)); length == 0 || length > textLimit {
		return miniMaxSpeechProjection{}, fmt.Errorf("%w: text length exceeds the selected execution mode", ErrInvalidSpeechDriver)
	}
	if operation.Language != "" && !supportedMiniMaxLanguage(operation.Language) {
		return miniMaxSpeechProjection{}, fmt.Errorf("%w: unsupported language_boost value %q", ErrInvalidSpeechDriver, operation.Language)
	}
	voice, errVoice := miniMaxVoiceControls(operation)
	if errVoice != nil {
		return miniMaxSpeechProjection{}, errVoice
	}
	format, mimeType, errFormat := miniMaxSpeechOutput(operation.OutputFormat)
	if errFormat != nil {
		return miniMaxSpeechProjection{}, errFormat
	}
	sampleRate, bitrate, channels, errAudio := miniMaxAudioControls(operation, format)
	if errAudio != nil {
		return miniMaxSpeechProjection{}, errAudio
	}
	var body []byte
	var errEncode error
	if asynchronous {
		body, errEncode = json.Marshal(miniMaxAsyncSpeechRequest{Model: model, Text: operation.Text, LanguageBoost: operation.Language, VoiceSetting: voice, AudioSetting: miniMaxAsyncAudioSetting{SampleRate: sampleRate, Bitrate: bitrate, Format: format, Channel: channels}})
	} else {
		body, errEncode = json.Marshal(miniMaxSyncSpeechRequest{Model: model, Text: operation.Text, Stream: false, LanguageBoost: operation.Language, OutputFormat: "hex", VoiceSetting: voice, AudioSetting: miniMaxSyncAudioSetting{SampleRate: sampleRate, Bitrate: bitrate, Format: format, Channel: channels}})
	}
	if errEncode != nil {
		return miniMaxSpeechProjection{}, fmt.Errorf("%w: encode speech request: %v", ErrInvalidSpeechDriver, errEncode)
	}
	return miniMaxSpeechProjection{body: body, mimeType: mimeType}, nil
}

// miniMaxVoiceControls applies documented defaults and exact control ranges.
// miniMaxVoiceControls 应用文档规定的默认值与精确控制范围。
func miniMaxVoiceControls(operation *vcp.SpeechSynthesizeOperation) (miniMaxVoiceSetting, error) {
	speed := 1.0
	volume := 1.0
	pitch := 0.0
	if operation.Speed != nil {
		speed = *operation.Speed
	}
	if operation.Volume != nil {
		volume = *operation.Volume
	}
	if operation.Pitch != nil {
		pitch = *operation.Pitch
	}
	if speed < 0.5 || speed > 2 || volume <= 0 || volume > 10 || pitch < -12 || pitch > 12 || math.Trunc(pitch) != pitch {
		return miniMaxVoiceSetting{}, fmt.Errorf("%w: speed, volume, or integer pitch is outside MiniMax ranges", ErrInvalidSpeechDriver)
	}
	return miniMaxVoiceSetting{VoiceID: operation.VoiceID, Speed: speed, Volume: volume, Pitch: int(pitch)}, nil
}

// miniMaxAudioControls applies documented encoding defaults and closed enumerations.
// miniMaxAudioControls 应用文档规定的编码默认值与封闭枚举。
func miniMaxAudioControls(operation *vcp.SpeechSynthesizeOperation, format string) (int, int, int, error) {
	sampleRate := operation.SampleRate
	if sampleRate == 0 {
		sampleRate = 32000
	}
	if sampleRate != 8000 && sampleRate != 16000 && sampleRate != 22050 && sampleRate != 24000 && sampleRate != 32000 && sampleRate != 44100 {
		return 0, 0, 0, fmt.Errorf("%w: unsupported sample rate", ErrInvalidSpeechDriver)
	}
	channels := operation.Channels
	if channels == 0 {
		channels = 1
	}
	if channels != 1 && channels != 2 {
		return 0, 0, 0, fmt.Errorf("%w: channel count must be one or two", ErrInvalidSpeechDriver)
	}
	bitrate := operation.Bitrate
	if format == "mp3" {
		if bitrate == 0 {
			bitrate = 128000
		}
		if bitrate != 32000 && bitrate != 64000 && bitrate != 128000 && bitrate != 256000 {
			return 0, 0, 0, fmt.Errorf("%w: unsupported MP3 bitrate", ErrInvalidSpeechDriver)
		}
	} else if bitrate != 0 {
		return 0, 0, 0, fmt.Errorf("%w: WAV does not accept an MP3 bitrate", ErrInvalidSpeechDriver)
	}
	return sampleRate, bitrate, channels, nil
}

// miniMaxSpeechOutput resolves only formats the Router can verify and persist.
// miniMaxSpeechOutput 仅解析 Router 能够验证并持久化的格式。
func miniMaxSpeechOutput(format string) (string, string, error) {
	switch format {
	case "", "mp3":
		return "mp3", "audio/mpeg", nil
	case "wav":
		return "wav", "audio/wav", nil
	default:
		return "", "", fmt.Errorf("%w: output format %q is not Router-probeable", ErrInvalidSpeechDriver, format)
	}
}

// supportedMiniMaxLanguage reports the exact current language_boost enumeration.
// supportedMiniMaxLanguage 报告当前精确的 language_boost 枚举。
func supportedMiniMaxLanguage(language string) bool {
	switch language {
	case "Chinese", "Chinese,Yue", "English", "Arabic", "Russian", "Spanish", "French", "Portuguese", "German", "Turkish", "Dutch", "Ukrainian", "Vietnamese", "Indonesian", "Japanese", "Italian", "Korean", "Thai", "Polish", "Romanian", "Greek", "Czech", "Finnish", "Hindi", "Bulgarian", "Danish", "Hebrew", "Malay", "Persian", "Slovak", "Swedish", "Croatian", "Filipino", "Hungarian", "Norwegian", "Slovenian", "Catalan", "Nynorsk", "Tamil", "Afrikaans", "auto":
		return true
	default:
		return false
	}
}

// decodeMiniMaxSpeech imports one successful hexadecimal audio response.
// decodeMiniMaxSpeech 导入一个成功的十六进制音频响应。
func decodeMiniMaxSpeech(reader io.Reader, mimeType string) (provider.ExecutionResult, error) {
	var response miniMaxSpeechResponse
	if errDecode := json.NewDecoder(reader).Decode(&response); errDecode != nil || response.BaseResponse.StatusCode != 0 || response.Data == nil || response.Data.Status != 2 || strings.TrimSpace(response.Data.Audio) == "" {
		return provider.ExecutionResult{}, fmt.Errorf("%w: missing complete hexadecimal audio", ErrInvalidSpeechResponse)
	}
	audio, errHex := hex.DecodeString(response.Data.Audio)
	if errHex != nil || len(audio) == 0 {
		return provider.ExecutionResult{}, fmt.Errorf("%w: invalid hexadecimal audio", ErrInvalidSpeechResponse)
	}
	return provider.ExecutionResult{GeneratedResources: []provider.GeneratedResource{{OutputID: "audio-0", Kind: vcp.MediaAudio, MIMEType: mimeType, Data: audio}}}, nil
}

// decodeMiniMaxSpeechStart decodes one successful asynchronous task creation.
// decodeMiniMaxSpeechStart 解码一次成功的异步任务创建。
func decodeMiniMaxSpeechStart(reader io.Reader, now time.Time) (provider.TaskResult, error) {
	var response miniMaxSpeechStartResponse
	if errDecode := json.NewDecoder(reader).Decode(&response); errDecode != nil || response.BaseResponse.StatusCode != 0 || response.TaskID == "" {
		return provider.TaskResult{}, fmt.Errorf("%w: missing successful task", ErrInvalidSpeechResponse)
	}
	return provider.TaskResult{ProviderTaskID: string(response.TaskID), State: provider.TaskQueued, PollAfter: now.UTC().Add(minimaxSpeechPollInterval)}, nil
}

// decodeMiniMaxSpeechPoll maps the provider's documented casing variants into task states.
// decodeMiniMaxSpeechPoll 将供应商文档中的大小写变体映射为任务状态。
func decodeMiniMaxSpeechPoll(reader io.Reader, providerTaskID string, now time.Time) (provider.TaskResult, string, error) {
	var response miniMaxSpeechPollResponse
	if errDecode := json.NewDecoder(reader).Decode(&response); errDecode != nil || response.BaseResponse.StatusCode != 0 || string(response.TaskID) != providerTaskID {
		return provider.TaskResult{}, "", fmt.Errorf("%w: invalid task observation", ErrInvalidSpeechResponse)
	}
	// MiniMax's prose and example use title case while its schema enum uses lowercase.
	// MiniMax 的说明和示例使用首字母大写，而其 Schema 枚举使用小写。
	switch strings.ToLower(response.Status) {
	case "processing":
		return provider.TaskResult{ProviderTaskID: providerTaskID, State: provider.TaskRunning, PollAfter: now.UTC().Add(minimaxSpeechPollInterval)}, "", nil
	case "success":
		if response.FileID == "" {
			return provider.TaskResult{}, "", fmt.Errorf("%w: successful task has no file ID", ErrInvalidSpeechResponse)
		}
		return provider.TaskResult{ProviderTaskID: providerTaskID, State: provider.TaskSucceeded}, string(response.FileID), nil
	case "failed":
		return provider.TaskResult{ProviderTaskID: providerTaskID, State: provider.TaskFailed, ErrorCode: "minimax_speech_generation_failed"}, "", nil
	case "expired":
		return provider.TaskResult{ProviderTaskID: providerTaskID, State: provider.TaskFailed, ErrorCode: "minimax_speech_generation_expired"}, "", nil
	default:
		return provider.TaskResult{}, "", fmt.Errorf("%w: unknown task status %q", ErrInvalidSpeechResponse, response.Status)
	}
}

// decodeMiniMaxSpeechFile converts a private file lookup into one Router-importable audio result.
// decodeMiniMaxSpeechFile 将私有文件查询转换为一个 Router 可导入的音频结果。
func decodeMiniMaxSpeechFile(reader io.Reader, providerTaskID string, mimeType string) (provider.TaskResult, error) {
	var response videoFileResponse
	if errDecode := json.NewDecoder(reader).Decode(&response); errDecode != nil || response.BaseResponse.StatusCode != 0 || strings.TrimSpace(response.File.DownloadURL) == "" {
		return provider.TaskResult{}, fmt.Errorf("%w: missing successful file URL", ErrInvalidSpeechResponse)
	}
	result := provider.ExecutionResult{GeneratedResources: []provider.GeneratedResource{{OutputID: "audio-0", Kind: vcp.MediaAudio, MIMEType: mimeType, DownloadURL: response.File.DownloadURL}}}
	return provider.TaskResult{ProviderTaskID: providerTaskID, State: provider.TaskSucceeded, Result: &result}, nil
}

// isPositiveDecimalIdentifier reports whether text is one positive base-ten integer without signs or fractions.
// isPositiveDecimalIdentifier 报告文本是否为不含符号和小数部分的正十进制整数。
func isPositiveDecimalIdentifier(value string) bool {
	if strings.TrimSpace(value) != value || value == "" {
		return false
	}
	parsed, errParse := strconv.ParseUint(value, 10, 64)
	return errParse == nil && parsed > 0
}
