package openrouter

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

const (
	// SpeechSynthesizeActionBindingID identifies OpenRouter speech synthesis.
	// SpeechSynthesizeActionBindingID 标识 OpenRouter 语音合成动作。
	SpeechSynthesizeActionBindingID = "action_openrouter_speech_synthesize"
	// SpeechTranscribeActionBindingID identifies OpenRouter transcription.
	// SpeechTranscribeActionBindingID 标识 OpenRouter 语音转写动作。
	SpeechTranscribeActionBindingID = "action_openrouter_speech_transcribe"
	// SpeechSynthesizeProtocolProfileID identifies the OpenRouter speech JSON endpoint.
	// SpeechSynthesizeProtocolProfileID 标识 OpenRouter 语音 JSON 端点。
	SpeechSynthesizeProtocolProfileID = "openrouter.audio.speech.v1"
	// SpeechTranscribeProtocolProfileID identifies the OpenRouter Base64 transcription endpoint.
	// SpeechTranscribeProtocolProfileID 标识 OpenRouter Base64 转写端点。
	SpeechTranscribeProtocolProfileID = "openrouter.audio.transcriptions.v1"
)

var (
	// ErrInvalidAudioDriver reports an invalid OpenRouter audio request boundary.
	// ErrInvalidAudioDriver 表示无效的 OpenRouter 音频请求边界。
	ErrInvalidAudioDriver = errors.New("invalid OpenRouter audio driver")
	// ErrInvalidAudioResponse reports an invalid OpenRouter audio response.
	// ErrInvalidAudioResponse 表示无效的 OpenRouter 音频响应。
	ErrInvalidAudioResponse = errors.New("invalid OpenRouter audio response")
)

// AudioDriver executes one exact OpenRouter TTS or STT action.
// AudioDriver 执行一个精确的 OpenRouter TTS 或 STT 动作。
type AudioDriver struct {
	// definitionID fixes provider ownership.
	// definitionID 固定供应商归属。
	definitionID string
	// actionBindingID fixes the sole wire contract.
	// actionBindingID 固定唯一 wire 合同。
	actionBindingID string
	// client owns authenticated HTTP execution.
	// client 负责认证后的 HTTP 执行。
	client *transport.Client
}

// NewAudioDriver creates one action-bound OpenRouter audio driver.
// NewAudioDriver 创建一个绑定动作的 OpenRouter 音频驱动。
func NewAudioDriver(definitionID string, actionBindingID string, client *transport.Client) (*AudioDriver, error) {
	if strings.TrimSpace(definitionID) == "" || client == nil || (actionBindingID != SpeechSynthesizeActionBindingID && actionBindingID != SpeechTranscribeActionBindingID) {
		return nil, ErrInvalidAudioDriver
	}
	return &AudioDriver{definitionID: definitionID, actionBindingID: actionBindingID, client: client}, nil
}

// ProviderDefinitionID returns the sole provider definition owned by this driver.
// ProviderDefinitionID 返回此驱动唯一拥有的供应商定义。
func (d *AudioDriver) ProviderDefinitionID() string {
	if d == nil {
		return ""
	}
	return d.definitionID
}

// ActionBindingID returns the sole action binding owned by this driver.
// ActionBindingID 返回此驱动唯一拥有的动作绑定。
func (d *AudioDriver) ActionBindingID() string {
	if d == nil {
		return ""
	}
	return d.actionBindingID
}

// Execute projects one closed OpenRouter audio action and decodes its typed result.
// Execute 投影一个封闭的 OpenRouter 音频动作并解码其类型化结果。
func (d *AudioDriver) Execute(ctx context.Context, execution provider.ExecutionRequest) (provider.ExecutionResult, error) {
	if d == nil || d.client == nil || execution.Binding.Target.ProviderDefinitionID != d.definitionID {
		return provider.ExecutionResult{}, ErrInvalidAudioDriver
	}
	if _, errValidate := execution.ValidateForAction(d.actionBindingID, providerconfig.AuthMethodAPIKey); errValidate != nil {
		return provider.ExecutionResult{}, errValidate
	}
	if d.actionBindingID == SpeechSynthesizeActionBindingID {
		return d.executeSpeech(ctx, execution)
	}
	return d.executeTranscription(ctx, execution)
}

// openRouterSpeechRequest is the exact OpenRouter speech JSON carrier.
// openRouterSpeechRequest 是精确的 OpenRouter 语音 JSON 载体。
type openRouterSpeechRequest struct {
	// Input is exact synthesis text.
	// Input 是精确的合成文本。
	Input string `json:"input"`
	// Model is the exact routed TTS model.
	// Model 是精确路由的 TTS 模型。
	Model string `json:"model"`
	// Voice is the provider voice identifier.
	// Voice 是供应商声音标识。
	Voice string `json:"voice"`
	// ResponseFormat requests Router-probeable MP3 bytes.
	// ResponseFormat 请求 Router 可探测的 MP3 字节。
	ResponseFormat string `json:"response_format"`
	// Speed is optional for the selected OpenAI-backed model.
	// Speed 对所选 OpenAI 后端模型是可选的。
	Speed *float64 `json:"speed,omitempty"`
}

// executeSpeech handles the documented OpenAI TTS snapshot through OpenRouter.
// executeSpeech 通过 OpenRouter 处理文档记录的 OpenAI TTS 快照。
func (d *AudioDriver) executeSpeech(ctx context.Context, execution provider.ExecutionRequest) (provider.ExecutionResult, error) {
	operation := execution.Execution.Payload.SpeechSynthesize
	if operation == nil || execution.Binding.Target.UpstreamModelID != "openai/gpt-4o-mini-tts-2025-12-15" || !supportedOpenRouterTTSVoice(operation.VoiceID) || len(operation.Segments) != 0 || operation.Language != "" || operation.Style != "" || operation.Pitch != nil || operation.Volume != nil || operation.SampleRate != 0 || operation.Bitrate != 0 || operation.Channels != 0 || operation.Timestamps || (operation.OutputFormat != "" && operation.OutputFormat != "mp3") {
		return provider.ExecutionResult{}, ErrInvalidAudioDriver
	}
	if operation.Speed != nil && (*operation.Speed < 0.25 || *operation.Speed > 4) {
		return provider.ExecutionResult{}, fmt.Errorf("%w: speed must be between 0.25 and 4", ErrInvalidAudioDriver)
	}
	body := openRouterSpeechRequest{Input: operation.Text, Model: execution.Binding.Target.UpstreamModelID, Voice: operation.VoiceID, ResponseFormat: "mp3", Speed: operation.Speed}
	encoded, errEncode := json.Marshal(body)
	if errEncode != nil {
		return provider.ExecutionResult{}, errEncode
	}
	response, errRequest := d.client.Do(ctx, transport.Request{Binding: execution.Binding, Method: http.MethodPost, Path: "/v1/audio/speech", Body: encoded, Headers: []transport.Header{{Name: "Content-Type", Value: "application/json"}, {Name: "Accept", Value: "audio/mpeg"}}, Authentication: transport.Authentication{Mode: transport.AuthenticationBearer}, IdempotencyKey: execution.Execution.IdempotencyKey})
	if errRequest != nil {
		return provider.ExecutionResult{}, errRequest
	}
	defer func() { _ = transport.DrainAndClose(response) }()
	bounded, errBound := transport.NewBoundedResponseReader(response.Body, transport.MaximumNonStreamingResponseBytes)
	if errBound != nil {
		return provider.ExecutionResult{}, errBound
	}
	audio, errRead := io.ReadAll(bounded)
	if errRead != nil || len(audio) == 0 {
		return provider.ExecutionResult{}, ErrInvalidAudioResponse
	}
	return provider.ExecutionResult{GeneratedResources: []provider.GeneratedResource{{OutputID: "audio-0", Kind: vcp.MediaAudio, MIMEType: "audio/mpeg", Data: audio}}}, nil
}

// supportedOpenRouterTTSVoice reports the documented voices of the fixed OpenAI-backed model.
// supportedOpenRouterTTSVoice 报告固定 OpenAI 后端模型的文档声音。
func supportedOpenRouterTTSVoice(voice string) bool {
	switch voice {
	case "alloy", "ash", "ballad", "coral", "echo", "fable", "onyx", "nova", "sage", "shimmer", "verse", "marin", "cedar":
		return true
	default:
		return false
	}
}

// openRouterTranscriptionRequest is the documented Base64 JSON carrier.
// openRouterTranscriptionRequest 是文档规定的 Base64 JSON 载体。
type openRouterTranscriptionRequest struct {
	// InputAudio contains exact Base64 and format.
	// InputAudio 包含精确的 Base64 与格式。
	InputAudio openRouterInputAudio `json:"input_audio"`
	// Model is the exact transcription model.
	// Model 是精确的转写模型。
	Model string `json:"model"`
	// Language is an optional ISO-639-1 hint.
	// Language 是可选的 ISO-639-1 提示。
	Language string `json:"language,omitempty"`
}

// openRouterInputAudio contains one inline WAV payload.
// openRouterInputAudio 包含一个内联 WAV 载荷。
type openRouterInputAudio struct {
	// Data is Base64 without a data-URL prefix.
	// Data 是不含 Data URL 前缀的 Base64。
	Data string `json:"data"`
	// Format is the exact documented WAV format.
	// Format 是文档规定的精确 WAV 格式。
	Format string `json:"format"`
}

// openRouterTranscriptionResponse contains the guaranteed transcript field only.
// openRouterTranscriptionResponse 仅包含有保证的转写字段。
type openRouterTranscriptionResponse struct {
	// Text is the complete provider-returned transcript.
	// Text 是供应商返回的完整转写文本。
	Text string `json:"text"`
}

// executeTranscription projects one exact WAV source and preserves absent metadata as absent.
// executeTranscription 投影一个精确 WAV 来源并保持缺失元数据仍然缺失。
func (d *AudioDriver) executeTranscription(ctx context.Context, execution provider.ExecutionRequest) (provider.ExecutionResult, error) {
	operation := execution.Execution.Payload.SpeechTranscribe
	if operation == nil || execution.Binding.Target.UpstreamModelID != "openai/whisper-large-v3" || operation.TranslationTarget != "" || operation.Prompt != "" || len(operation.Hotwords) != 0 || operation.Diarization || operation.SegmentTimestamps || operation.WordTimestamps || operation.CandidateCount > 1 {
		return provider.ExecutionResult{}, ErrInvalidAudioDriver
	}
	input, errInput := exactOpenRouterWAVInput(execution.MaterializedInputs, operation.Source)
	if errInput != nil {
		return provider.ExecutionResult{}, errInput
	}
	body := openRouterTranscriptionRequest{InputAudio: openRouterInputAudio{Data: input.InlineBase64, Format: "wav"}, Model: execution.Binding.Target.UpstreamModelID, Language: operation.Language}
	encoded, errEncode := json.Marshal(body)
	if errEncode != nil {
		return provider.ExecutionResult{}, errEncode
	}
	response, errRequest := d.client.Do(ctx, transport.Request{Binding: execution.Binding, Method: http.MethodPost, Path: "/v1/audio/transcriptions", Body: encoded, Headers: []transport.Header{{Name: "Content-Type", Value: "application/json"}}, Authentication: transport.Authentication{Mode: transport.AuthenticationBearer}, IdempotencyKey: execution.Execution.IdempotencyKey})
	if errRequest != nil {
		return provider.ExecutionResult{}, errRequest
	}
	defer func() { _ = transport.DrainAndClose(response) }()
	bounded, errBound := transport.NewBoundedResponseReader(response.Body, transport.MaximumNonStreamingResponseBytes)
	if errBound != nil {
		return provider.ExecutionResult{}, errBound
	}
	var upstream openRouterTranscriptionResponse
	if errDecode := json.NewDecoder(bounded).Decode(&upstream); errDecode != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: %v", ErrInvalidAudioResponse, errDecode)
	}
	transcript := vcp.Transcript{Candidates: []vcp.TranscriptCandidate{{CandidateID: "candidate-0", Text: upstream.Text}}}
	if errValidate := transcript.Validate(); errValidate != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: %v", ErrInvalidAudioResponse, errValidate)
	}
	return provider.ExecutionResult{Transcript: &transcript}, nil
}

// exactOpenRouterWAVInput resolves exactly one accepted inline WAV materialization.
// exactOpenRouterWAVInput 解析唯一已接受的内联 WAV 物化结果。
func exactOpenRouterWAVInput(inputs []resource.MaterializedInput, source vcp.MediaInput) (resource.MaterializedInput, error) {
	for _, input := range inputs {
		if input.InputID != source.ID {
			continue
		}
		if input.ResourceID != source.Resource.ResourceID || input.Kind != vcp.MediaAudio || input.Role != vcp.MediaRoleTranscriptionSource || input.Mode != catalog.MaterializationInlineBase64 || input.MIMEType != "audio/wav" {
			return resource.MaterializedInput{}, ErrInvalidAudioDriver
		}
		decoded, errDecode := base64.StdEncoding.DecodeString(input.InlineBase64)
		if errDecode != nil || len(decoded) == 0 {
			return resource.MaterializedInput{}, ErrInvalidAudioDriver
		}
		return input, nil
	}
	return resource.MaterializedInput{}, ErrInvalidAudioDriver
}
