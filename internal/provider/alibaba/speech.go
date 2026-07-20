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
	"unicode/utf8"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

const (
	// SpeechSynthesizeActionBindingID identifies the synchronous Qwen3-TTS action.
	// SpeechSynthesizeActionBindingID 标识同步 Qwen3-TTS 动作。
	SpeechSynthesizeActionBindingID = "action_alibaba_qwen3_tts_synthesize"
	// SpeechTranscribeActionBindingID identifies the synchronous Qwen3-ASR action.
	// SpeechTranscribeActionBindingID 标识同步 Qwen3-ASR 动作。
	SpeechTranscribeActionBindingID = "action_alibaba_qwen3_asr_transcribe"
	// SpeechSynthesizeProtocolProfileID identifies the closed Qwen3-TTS HTTP profile.
	// SpeechSynthesizeProtocolProfileID 标识封闭的 Qwen3-TTS HTTP Profile。
	SpeechSynthesizeProtocolProfileID = "alibaba.qwen3-tts.synthesize.v1"
	// SpeechTranscribeProtocolProfileID identifies the closed Qwen3-ASR synchronous profile.
	// SpeechTranscribeProtocolProfileID 标识封闭的 Qwen3-ASR 同步 Profile。
	SpeechTranscribeProtocolProfileID = "alibaba.qwen3-asr.transcribe.v1"
	// dashScopeMultimodalGenerationPath is the documented synchronous audio endpoint.
	// dashScopeMultimodalGenerationPath 是文档规定的同步音频端点。
	dashScopeMultimodalGenerationPath = "/api/v1/services/aigc/multimodal-generation/generation"
	// maximumQwen3TTSCharacters is the documented non-realtime text ceiling.
	// maximumQwen3TTSCharacters 是文档规定的非实时文本字符上限。
	maximumQwen3TTSCharacters = 600
)

var (
	// ErrInvalidSpeechDriver reports an incomplete or unsupported Alibaba speech request.
	// ErrInvalidSpeechDriver 表示不完整或不受支持的阿里云语音请求。
	ErrInvalidSpeechDriver = errors.New("invalid Alibaba speech driver")
	// ErrInvalidSpeechResponse reports malformed Alibaba speech output.
	// ErrInvalidSpeechResponse 表示格式错误的阿里云语音输出。
	ErrInvalidSpeechResponse = errors.New("invalid Alibaba speech response")
)

// SpeechActionDriver executes one exact synchronous Alibaba speech action for one immutable definition.
// SpeechActionDriver 为一个不可变 Definition 执行一个精确的同步阿里云语音动作。
type SpeechActionDriver struct {
	// definitionID fixes the sole owning provider definition.
	// definitionID 固定唯一所属供应商 Definition。
	definitionID string
	// actionBindingID fixes synthesis or transcription.
	// actionBindingID 固定合成或转写动作。
	actionBindingID string
	// client owns authenticated provider-scoped HTTP execution.
	// client 负责经过认证且限定供应商作用域的 HTTP 执行。
	client *transport.Client
}

// NewSpeechActionDriver creates one exact synchronous Alibaba speech driver.
// NewSpeechActionDriver 创建一个精确的同步阿里云语音 Driver。
func NewSpeechActionDriver(definitionID string, actionBindingID string, client *transport.Client) (*SpeechActionDriver, error) {
	if strings.TrimSpace(definitionID) == "" || client == nil || (actionBindingID != SpeechSynthesizeActionBindingID && actionBindingID != SpeechTranscribeActionBindingID) {
		return nil, ErrInvalidSpeechDriver
	}
	return &SpeechActionDriver{definitionID: definitionID, actionBindingID: actionBindingID, client: client}, nil
}

// ProviderDefinitionID returns the sole provider definition owned by this driver.
// ProviderDefinitionID 返回此 Driver 唯一所属的供应商 Definition。
func (d *SpeechActionDriver) ProviderDefinitionID() string {
	if d == nil {
		return ""
	}
	return d.definitionID
}

// ActionBindingID returns the exact speech action owned by this driver.
// ActionBindingID 返回此 Driver 拥有的精确语音动作。
func (d *SpeechActionDriver) ActionBindingID() string {
	if d == nil {
		return ""
	}
	return d.actionBindingID
}

// Execute projects and executes one official synchronous Alibaba speech request.
// Execute 投影并执行一个官方同步阿里云语音请求。
func (d *SpeechActionDriver) Execute(ctx context.Context, execution provider.ExecutionRequest) (provider.ExecutionResult, error) {
	if d == nil || d.client == nil || execution.Binding.Target.ProviderDefinitionID != d.definitionID {
		return provider.ExecutionResult{}, fmt.Errorf("%w: target definition does not belong to this driver", provider.ErrExecutionBinding)
	}
	if _, errValidate := execution.ValidateForAction(d.actionBindingID, providerconfig.AuthMethodAPIKey); errValidate != nil {
		return provider.ExecutionResult{}, errValidate
	}
	outbound, errProject := projectAlibabaSpeechRequest(execution, d.actionBindingID)
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
		return provider.ExecutionResult{}, fmt.Errorf("%w: bound response: %v", ErrInvalidSpeechResponse, errBound)
	}
	if d.actionBindingID == SpeechSynthesizeActionBindingID {
		return decodeQwen3TTSResponse(bounded)
	}
	return decodeQwen3ASRResponse(bounded)
}

// qwen3TTSRequest is the official non-streaming Qwen3-TTS request body.
// qwen3TTSRequest 是官方非流式 Qwen3-TTS 请求正文。
type qwen3TTSRequest struct {
	// Model is the exact resolved TTS model.
	// Model 是精确解析的 TTS 模型。
	Model string `json:"model"`
	// Input contains the text, preset voice, and optional language and instructions.
	// Input 包含文本、预设声音及可选语言和指令。
	Input qwen3TTSInput `json:"input"`
}

// qwen3TTSInput contains the documented non-streaming synthesis fields.
// qwen3TTSInput 包含文档规定的非流式合成字段。
type qwen3TTSInput struct {
	// Text is the exact transcript to synthesize.
	// Text 是需要合成的精确逐字稿。
	Text string `json:"text"`
	// Voice is one documented preset system voice.
	// Voice 是文档规定的预设系统声音。
	Voice string `json:"voice"`
	// LanguageType optionally fixes pronunciation language.
	// LanguageType 可选地固定发音语言。
	LanguageType string `json:"language_type,omitempty"`
	// Instructions controls delivery for Qwen3-TTS-Instruct-Flash only.
	// Instructions 仅为 Qwen3-TTS-Instruct-Flash 控制表达方式。
	Instructions string `json:"instructions,omitempty"`
	// OptimizeInstructions requests documented semantic instruction optimization.
	// OptimizeInstructions 请求文档规定的语义指令优化。
	OptimizeInstructions bool `json:"optimize_instructions,omitempty"`
}

// qwen3ASRRequest is the official synchronous DashScope recognition body.
// qwen3ASRRequest 是官方同步 DashScope 识别正文。
type qwen3ASRRequest struct {
	// Model is the exact resolved ASR model.
	// Model 是精确解析的 ASR 模型。
	Model string `json:"model"`
	// Input contains one user audio message.
	// Input 包含一条用户音频消息。
	Input qwen3ASRInput `json:"input"`
	// Parameters requests message output and optional source language.
	// Parameters 请求消息输出及可选源语言。
	Parameters qwen3ASRParameters `json:"parameters"`
}

// qwen3ASRInput contains one ordered message list.
// qwen3ASRInput 包含一个有序消息列表。
type qwen3ASRInput struct {
	// Messages contains exactly one user message.
	// Messages 包含恰好一条用户消息。
	Messages []qwen3ASRMessage `json:"messages"`
}

// qwen3ASRMessage contains one audio content block.
// qwen3ASRMessage 包含一个音频内容块。
type qwen3ASRMessage struct {
	// Role is fixed to user.
	// Role 固定为 user。
	Role string `json:"role"`
	// Content contains exactly one audio item.
	// Content 包含恰好一个音频项。
	Content []qwen3ASRContent `json:"content"`
}

// qwen3ASRContent contains one public URL or Base64 data URL.
// qwen3ASRContent 包含一个公网 URL 或 Base64 Data URL。
type qwen3ASRContent struct {
	// Audio is the documented DashScope audio carrier.
	// Audio 是文档规定的 DashScope 音频载体。
	Audio string `json:"audio"`
}

// qwen3ASRParameters contains exact synchronous recognition controls.
// qwen3ASRParameters 包含精确的同步识别控制项。
type qwen3ASRParameters struct {
	// ResultFormat is fixed to message for typed decoding.
	// ResultFormat 固定为 message 以进行类型化解码。
	ResultFormat string `json:"result_format"`
	// ASROptions contains optional language and fixed ITN behavior.
	// ASROptions 包含可选语言及固定 ITN 行为。
	ASROptions qwen3ASROptions `json:"asr_options"`
}

// qwen3ASROptions contains the documented synchronous ASR options.
// qwen3ASROptions 包含文档规定的同步 ASR 选项。
type qwen3ASROptions struct {
	// Language optionally fixes one documented source language.
	// Language 可选地固定一种文档规定的源语言。
	Language string `json:"language,omitempty"`
	// EnableITN stays false because VCP has no explicit ITN request field.
	// EnableITN 保持 false，因为 VCP 没有明确的 ITN 请求字段。
	EnableITN bool `json:"enable_itn"`
}

// projectAlibabaSpeechRequest maps one closed VCP speech payload to DashScope.
// projectAlibabaSpeechRequest 将一个封闭 VCP 语音载荷映射到 DashScope。
func projectAlibabaSpeechRequest(execution provider.ExecutionRequest, actionBindingID string) (transport.Request, error) {
	var encoded []byte
	var errEncode error
	switch actionBindingID {
	case SpeechSynthesizeActionBindingID:
		projected, errProject := projectQwen3TTSBody(execution)
		if errProject != nil {
			return transport.Request{}, errProject
		}
		encoded, errEncode = json.Marshal(projected)
	case SpeechTranscribeActionBindingID:
		projected, errProject := projectQwen3ASRBody(execution)
		if errProject != nil {
			return transport.Request{}, errProject
		}
		encoded, errEncode = json.Marshal(projected)
	default:
		return transport.Request{}, ErrInvalidSpeechDriver
	}
	if errEncode != nil {
		return transport.Request{}, fmt.Errorf("%w: encode request: %v", ErrInvalidSpeechDriver, errEncode)
	}
	return transport.Request{Binding: execution.Binding, Method: http.MethodPost, Path: dashScopeMultimodalGenerationPath, Body: encoded, Headers: []transport.Header{{Name: "Content-Type", Value: "application/json"}}, Authentication: transport.Authentication{Mode: transport.AuthenticationBearer}, IdempotencyKey: execution.Execution.IdempotencyKey}, nil
}

// projectQwen3TTSBody validates and projects one non-streaming synthesis operation.
// projectQwen3TTSBody 校验并投影一个非流式合成操作。
func projectQwen3TTSBody(execution provider.ExecutionRequest) (qwen3TTSRequest, error) {
	operation := execution.Execution.Payload.SpeechSynthesize
	if operation == nil || strings.TrimSpace(operation.Text) == "" || strings.TrimSpace(operation.VoiceID) == "" {
		return qwen3TTSRequest{}, fmt.Errorf("%w: text and preset voice are required", ErrInvalidSpeechDriver)
	}
	if utf8.RuneCountInString(operation.Text) > maximumQwen3TTSCharacters {
		return qwen3TTSRequest{}, fmt.Errorf("%w: text exceeds 600 characters", ErrInvalidSpeechDriver)
	}
	if len(operation.Segments) != 0 || operation.Speed != nil || operation.Pitch != nil || operation.Volume != nil || operation.SampleRate != 0 || operation.Bitrate != 0 || operation.Channels != 0 || operation.Timestamps {
		return qwen3TTSRequest{}, fmt.Errorf("%w: segments, numeric voice controls, encoding controls, and timestamps have no Qwen3-TTS HTTP carrier", ErrInvalidSpeechDriver)
	}
	if format := strings.ToLower(strings.TrimSpace(operation.OutputFormat)); format != "" && format != "wav" {
		return qwen3TTSRequest{}, fmt.Errorf("%w: non-streaming Qwen3-TTS output is WAV", ErrInvalidSpeechDriver)
	}
	if !supportedQwen3TTSLanguage(operation.Language) {
		return qwen3TTSRequest{}, fmt.Errorf("%w: unsupported Qwen3-TTS language", ErrInvalidSpeechDriver)
	}
	model := execution.Binding.Target.UpstreamModelID
	if operation.Style != "" && model != "qwen3-tts-instruct-flash" && model != "qwen3-tts-instruct-flash-2026-01-26" {
		return qwen3TTSRequest{}, fmt.Errorf("%w: style requires Qwen3-TTS-Instruct-Flash", ErrInvalidSpeechDriver)
	}
	return qwen3TTSRequest{Model: model, Input: qwen3TTSInput{Text: operation.Text, Voice: operation.VoiceID, LanguageType: operation.Language, Instructions: operation.Style, OptimizeInstructions: operation.Style != ""}}, nil
}

// projectQwen3ASRBody validates and projects one synchronous recognition operation.
// projectQwen3ASRBody 校验并投影一个同步识别操作。
func projectQwen3ASRBody(execution provider.ExecutionRequest) (qwen3ASRRequest, error) {
	operation := execution.Execution.Payload.SpeechTranscribe
	if operation == nil || operation.Source.Role != vcp.MediaRoleTranscriptionSource || operation.Source.Resource.ResourceID == "" {
		return qwen3ASRRequest{}, fmt.Errorf("%w: synchronous Qwen3-ASR requires one audio source", ErrInvalidSpeechDriver)
	}
	if operation.TranslationTarget != "" || operation.Prompt != "" || len(operation.Hotwords) != 0 || operation.Diarization || operation.SegmentTimestamps || operation.WordTimestamps || operation.CandidateCount > 1 {
		return qwen3ASRRequest{}, fmt.Errorf("%w: translation, prompt, hotwords, diarization, timestamps, and alternatives have no synchronous Qwen3-ASR carrier", ErrInvalidSpeechDriver)
	}
	if !supportedQwen3ASRLanguage(operation.Language) {
		return qwen3ASRRequest{}, fmt.Errorf("%w: unsupported Qwen3-ASR language", ErrInvalidSpeechDriver)
	}
	if len(execution.MaterializedInputs) != 1 {
		return qwen3ASRRequest{}, fmt.Errorf("%w: Qwen3-ASR requires one exact materialized input", ErrInvalidSpeechDriver)
	}
	input := execution.MaterializedInputs[0]
	if input.InputID != operation.Source.ID || input.ResourceID != operation.Source.Resource.ResourceID || input.Kind != vcp.MediaAudio || input.Role != vcp.MediaRoleTranscriptionSource {
		return qwen3ASRRequest{}, fmt.Errorf("%w: audio source has no exact materialization", ErrInvalidSpeechDriver)
	}
	audio, errAudio := qwen3ASRMaterialization(input)
	if errAudio != nil {
		return qwen3ASRRequest{}, errAudio
	}
	return qwen3ASRRequest{Model: execution.Binding.Target.UpstreamModelID, Input: qwen3ASRInput{Messages: []qwen3ASRMessage{{Role: "user", Content: []qwen3ASRContent{{Audio: audio}}}}}, Parameters: qwen3ASRParameters{ResultFormat: "message", ASROptions: qwen3ASROptions{Language: operation.Language, EnableITN: false}}}, nil
}

// qwen3ASRMaterialization converts one exact planned audio representation to the documented carrier.
// qwen3ASRMaterialization 将一个精确规划的音频表示转换为文档规定的载体。
func qwen3ASRMaterialization(input resource.MaterializedInput) (string, error) {
	if !supportedQwen3ASRMIMEType(input.MIMEType) {
		return "", fmt.Errorf("%w: unsupported Qwen3-ASR audio MIME type", ErrInvalidSpeechDriver)
	}
	switch input.Mode {
	case catalog.MaterializationInlineBase64:
		if input.InlineBase64 == "" {
			return "", fmt.Errorf("%w: inline audio data is empty", ErrInvalidSpeechDriver)
		}
		return "data:" + input.MIMEType + ";base64," + input.InlineBase64, nil
	case catalog.MaterializationDirectRemoteURL:
		parsed, errParse := url.ParseRequestURI(input.RemoteURL)
		if errParse != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil {
			return "", fmt.Errorf("%w: direct audio URL is invalid", ErrInvalidSpeechDriver)
		}
		return input.RemoteURL, nil
	default:
		return "", fmt.Errorf("%w: Qwen3-ASR accepts inline Base64 or direct remote URL only", ErrInvalidSpeechDriver)
	}
}

// supportedQwen3TTSLanguage reports whether one language_type is documented.
// supportedQwen3TTSLanguage 报告一个 language_type 是否有文档依据。
func supportedQwen3TTSLanguage(language string) bool {
	switch language {
	case "", "Auto", "Chinese", "English", "German", "Italian", "Portuguese", "Spanish", "Japanese", "Korean", "French", "Russian":
		return true
	default:
		return false
	}
}

// supportedQwen3ASRLanguage reports whether one source language is documented.
// supportedQwen3ASRLanguage 报告一种源语言是否有文档依据。
func supportedQwen3ASRLanguage(language string) bool {
	switch language {
	case "", "zh", "yue", "en", "ja", "de", "ko", "ru", "fr", "pt", "ar", "it", "es", "hi", "id", "th", "tr", "uk", "vi", "cs", "da", "fil", "fi", "is", "ms", "no", "pl", "sv":
		return true
	default:
		return false
	}
}

// supportedQwen3ASRMIMEType reports whether one documented short-audio input format is accepted.
// supportedQwen3ASRMIMEType 报告一种文档规定的短音频输入格式是否受支持。
func supportedQwen3ASRMIMEType(mimeType string) bool {
	switch strings.ToLower(strings.TrimSpace(mimeType)) {
	case "audio/mpeg", "audio/mp3", "audio/wav", "audio/x-wav", "audio/mp4", "audio/aac", "audio/ogg", "audio/flac", "audio/webm":
		return true
	default:
		return false
	}
}

// qwen3TTSResponse is the closed non-streaming synthesis response.
// qwen3TTSResponse 是封闭的非流式合成响应。
type qwen3TTSResponse struct {
	// StatusCode is the provider-repeated HTTP status.
	// StatusCode 是供应商重复返回的 HTTP 状态。
	StatusCode int `json:"status_code"`
	// RequestID is the provider-issued request identifier.
	// RequestID 是供应商签发的请求标识。
	RequestID string `json:"request_id"`
	// Output contains the terminal audio URL.
	// Output 包含终态音频 URL。
	Output qwen3TTSOutput `json:"output"`
}

// qwen3TTSOutput contains the terminal synthesis state.
// qwen3TTSOutput 包含终态合成状态。
type qwen3TTSOutput struct {
	// FinishReason must be stop for complete output.
	// FinishReason 对完整输出必须为 stop。
	FinishReason string `json:"finish_reason"`
	// Audio contains the temporary complete WAV URL.
	// Audio 包含临时完整 WAV URL。
	Audio qwen3TTSAudio `json:"audio"`
}

// qwen3TTSAudio contains one generated audio locator.
// qwen3TTSAudio 包含一个生成音频定位符。
type qwen3TTSAudio struct {
	// URL is the temporary complete WAV URL.
	// URL 是临时完整 WAV URL。
	URL string `json:"url"`
	// ID is the provider audio identifier retained only as upstream response provenance.
	// ID 是仅作为上游响应来源保留的供应商音频标识。
	ID string `json:"id"`
}

// decodeQwen3TTSResponse validates one complete non-streaming synthesis response.
// decodeQwen3TTSResponse 校验一个完整非流式合成响应。
func decodeQwen3TTSResponse(reader io.Reader) (provider.ExecutionResult, error) {
	var response qwen3TTSResponse
	if errDecode := json.NewDecoder(reader).Decode(&response); errDecode != nil || response.StatusCode != http.StatusOK || response.Output.FinishReason != "stop" || strings.TrimSpace(response.Output.Audio.URL) == "" {
		return provider.ExecutionResult{}, fmt.Errorf("%w: malformed Qwen3-TTS output", ErrInvalidSpeechResponse)
	}
	return provider.ExecutionResult{UpstreamResponseID: response.RequestID, GeneratedResources: []provider.GeneratedResource{{OutputID: "audio-0", Kind: vcp.MediaAudio, MIMEType: "audio/wav", DownloadURL: response.Output.Audio.URL}}}, nil
}

// qwen3ASRResponse is the closed synchronous recognition response.
// qwen3ASRResponse 是封闭的同步识别响应。
type qwen3ASRResponse struct {
	// RequestID is the provider-issued request identifier.
	// RequestID 是供应商签发的请求标识。
	RequestID string `json:"request_id"`
	// Output contains one recognition choice.
	// Output 包含一个识别 Choice。
	Output qwen3ASROutput `json:"output"`
	// Usage contains provider-confirmed source seconds.
	// Usage 包含供应商确认的来源秒数。
	Usage qwen3ASRUsage `json:"usage"`
}

// qwen3ASROutput contains ordered recognition choices.
// qwen3ASROutput 包含有序识别 Choice。
type qwen3ASROutput struct {
	// Choices contains exactly one terminal choice.
	// Choices 包含恰好一个终态 Choice。
	Choices []qwen3ASRChoice `json:"choices"`
}

// qwen3ASRChoice contains one assistant recognition message.
// qwen3ASRChoice 包含一条 Assistant 识别消息。
type qwen3ASRChoice struct {
	// FinishReason must be stop for complete recognition.
	// FinishReason 对完整识别必须为 stop。
	FinishReason string `json:"finish_reason"`
	// Message contains text and provider annotations.
	// Message 包含文本及供应商注解。
	Message qwen3ASRResponseMessage `json:"message"`
}

// qwen3ASRResponseMessage contains recognized text and language annotations.
// qwen3ASRResponseMessage 包含识别文本及语言注解。
type qwen3ASRResponseMessage struct {
	// Role must be assistant.
	// Role 必须为 assistant。
	Role string `json:"role"`
	// Content contains one text item.
	// Content 包含一个文本项。
	Content []qwen3ASRResponseContent `json:"content"`
	// Annotations contains one audio_info item.
	// Annotations 包含一个 audio_info 项。
	Annotations []qwen3ASRAnnotation `json:"annotations"`
}

// qwen3ASRResponseContent contains one recognized text item.
// qwen3ASRResponseContent 包含一个识别文本项。
type qwen3ASRResponseContent struct {
	// Text is the provider-returned complete transcript.
	// Text 是供应商返回的完整转写。
	Text string `json:"text"`
}

// qwen3ASRAnnotation contains provider-confirmed audio metadata.
// qwen3ASRAnnotation 包含供应商确认的音频元数据。
type qwen3ASRAnnotation struct {
	// Type must be audio_info.
	// Type 必须为 audio_info。
	Type string `json:"type"`
	// Language is the provider-confirmed recognition language.
	// Language 是供应商确认的识别语言。
	Language string `json:"language"`
}

// qwen3ASRUsage contains the provider-confirmed audio duration.
// qwen3ASRUsage 包含供应商确认的音频时长。
type qwen3ASRUsage struct {
	// Seconds is the billed audio duration in whole seconds.
	// Seconds 是按整秒计费的音频时长。
	Seconds int64 `json:"seconds"`
}

// decodeQwen3ASRResponse validates typed text without fabricating unavailable segments or confidence.
// decodeQwen3ASRResponse 校验类型化文本且不虚构不可用的分段或置信度。
func decodeQwen3ASRResponse(reader io.Reader) (provider.ExecutionResult, error) {
	var response qwen3ASRResponse
	if errDecode := json.NewDecoder(reader).Decode(&response); errDecode != nil || strings.TrimSpace(response.RequestID) == "" || len(response.Output.Choices) != 1 {
		return provider.ExecutionResult{}, fmt.Errorf("%w: malformed Qwen3-ASR output", ErrInvalidSpeechResponse)
	}
	choice := response.Output.Choices[0]
	if choice.FinishReason != "stop" || choice.Message.Role != "assistant" || len(choice.Message.Content) != 1 || len(choice.Message.Annotations) != 1 || choice.Message.Annotations[0].Type != "audio_info" || response.Usage.Seconds < 0 {
		return provider.ExecutionResult{}, fmt.Errorf("%w: incomplete Qwen3-ASR output", ErrInvalidSpeechResponse)
	}
	duration := response.Usage.Seconds * 1000
	transcript := vcp.Transcript{DurationMilliseconds: &duration, Candidates: []vcp.TranscriptCandidate{{CandidateID: "candidate-0", Text: choice.Message.Content[0].Text, Language: choice.Message.Annotations[0].Language}}}
	if errValidate := transcript.Validate(); errValidate != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: %v", ErrInvalidSpeechResponse, errValidate)
	}
	return provider.ExecutionResult{UpstreamResponseID: response.RequestID, Transcript: &transcript}, nil
}
