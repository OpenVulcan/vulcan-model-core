package google

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

const (
	// SpeechSynthesizeActionBindingID identifies Gemini Interactions non-realtime speech synthesis.
	// SpeechSynthesizeActionBindingID 标识 Gemini Interactions 非实时语音合成。
	SpeechSynthesizeActionBindingID = "action_google_interactions_speech_synthesize"
	// SpeechSynthesizeProtocolProfileID identifies the current Interactions TTS contract.
	// SpeechSynthesizeProtocolProfileID 标识当前 Interactions TTS 合同。
	SpeechSynthesizeProtocolProfileID = "google.interactions.speech.synthesize.v1beta"
)

var (
	// ErrInvalidInteractionsSpeechDriver reports an incomplete or unsupported Gemini TTS request.
	// ErrInvalidInteractionsSpeechDriver 表示 Gemini TTS 请求不完整或不受支持。
	ErrInvalidInteractionsSpeechDriver = errors.New("invalid Google Interactions speech driver")
	// ErrInvalidInteractionsSpeechResponse reports malformed Gemini TTS output.
	// ErrInvalidInteractionsSpeechResponse 表示 Gemini TTS 输出格式错误。
	ErrInvalidInteractionsSpeechResponse = errors.New("invalid Google Interactions speech response")
)

// InteractionsSpeechActionDriver executes non-realtime TTS for one immutable Google Interactions definition.
// InteractionsSpeechActionDriver 为一个不可变 Google Interactions 定义执行非实时 TTS。
type InteractionsSpeechActionDriver struct {
	// definitionID fixes the sole owning provider definition.
	// definitionID 固定唯一所属供应商定义。
	definitionID string
	// client owns authenticated provider-scoped HTTP execution.
	// client 负责经过认证且限定供应商作用域的 HTTP 执行。
	client *transport.Client
}

// NewInteractionsSpeechActionDriver creates one Gemini Interactions speech driver.
// NewInteractionsSpeechActionDriver 创建一个 Gemini Interactions 语音驱动。
func NewInteractionsSpeechActionDriver(definitionID string, client *transport.Client) (*InteractionsSpeechActionDriver, error) {
	if strings.TrimSpace(definitionID) == "" || client == nil {
		return nil, ErrInvalidInteractionsSpeechDriver
	}
	return &InteractionsSpeechActionDriver{definitionID: definitionID, client: client}, nil
}

// ProviderDefinitionID returns the sole provider definition owned by this driver.
// ProviderDefinitionID 返回此驱动唯一所属的供应商定义。
func (d *InteractionsSpeechActionDriver) ProviderDefinitionID() string {
	if d == nil {
		return ""
	}
	return d.definitionID
}

// ActionBindingID returns the Gemini speech action binding.
// ActionBindingID 返回 Gemini 语音动作绑定。
func (d *InteractionsSpeechActionDriver) ActionBindingID() string {
	return SpeechSynthesizeActionBindingID
}

// Execute projects and executes one current Gemini Interactions TTS request.
// Execute 投影并执行一个当前 Gemini Interactions TTS 请求。
func (d *InteractionsSpeechActionDriver) Execute(ctx context.Context, execution provider.ExecutionRequest) (provider.ExecutionResult, error) {
	if d == nil || d.client == nil || execution.Binding.Target.ProviderDefinitionID != d.definitionID {
		return provider.ExecutionResult{}, fmt.Errorf("%w: target definition does not belong to this driver", provider.ErrExecutionBinding)
	}
	if _, errValidate := execution.ValidateForAction(SpeechSynthesizeActionBindingID, providerconfig.AuthMethodAPIKey, providerconfig.AuthMethodHeaderKey); errValidate != nil {
		return provider.ExecutionResult{}, errValidate
	}
	outbound, expectedMIME, errProject := projectInteractionsSpeechRequest(execution)
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
		return provider.ExecutionResult{}, errBound
	}
	return decodeInteractionsSpeechResponse(bounded, expectedMIME)
}

// interactionsSpeechRequest is the current closed Interactions TTS body.
// interactionsSpeechRequest 是当前封闭的 Interactions TTS 正文。
type interactionsSpeechRequest struct {
	// Model is one exact TTS-capable Gemini model.
	// Model 是一个精确支持 TTS 的 Gemini 模型。
	Model string `json:"model"`
	// Input contains exact transcript text or a deterministic multi-speaker prompt.
	// Input 包含精确逐字稿文本或确定性的多说话人提示。
	Input string `json:"input"`
	// ResponseFormat requests one inline Router-probeable audio format.
	// ResponseFormat 请求一种 Router 可探测的内联音频格式。
	ResponseFormat interactionsSpeechResponseFormat `json:"response_format"`
	// GenerationConfig binds one or two preset voices.
	// GenerationConfig 绑定一个或两个预设声音。
	GenerationConfig interactionsSpeechGenerationConfig `json:"generation_config"`
}

// interactionsSpeechResponseFormat contains exact audio delivery controls.
// interactionsSpeechResponseFormat 包含精确音频交付控制。
type interactionsSpeechResponseFormat struct {
	// Type is fixed to audio.
	// Type 固定为 audio。
	Type string `json:"type"`
	// MIMEType requests WAV or MP3.
	// MIMEType 请求 WAV 或 MP3。
	MIMEType string `json:"mime_type"`
	// Delivery keeps generated bytes inline for Router import.
	// Delivery 保持生成字节内联以供 Router 导入。
	Delivery string `json:"delivery"`
	// SampleRate requests the evidenced 24 kHz output rate.
	// SampleRate 请求有证据支持的 24 kHz 输出采样率。
	SampleRate int `json:"sample_rate"`
}

// interactionsSpeechGenerationConfig contains the current speech_config array.
// interactionsSpeechGenerationConfig 包含当前 speech_config 数组。
type interactionsSpeechGenerationConfig struct {
	// SpeechConfig contains one single speaker or two named speakers.
	// SpeechConfig 包含一个单说话人或两个命名说话人。
	SpeechConfig []interactionsSpeakerConfig `json:"speech_config"`
}

// interactionsSpeakerConfig binds one prompt speaker name to one preset voice.
// interactionsSpeakerConfig 将一个提示说话人名称绑定到一个预设声音。
type interactionsSpeakerConfig struct {
	// Speaker is present only for multi-speaker output.
	// Speaker 仅在多说话人输出时存在。
	Speaker string `json:"speaker,omitempty"`
	// Voice is one documented Gemini preset voice.
	// Voice 是一个文档规定的 Gemini 预设声音。
	Voice string `json:"voice"`
}

// interactionsSpeechResponse contains the raw post-migration Interactions step timeline.
// interactionsSpeechResponse 包含迁移后的原始 Interactions 步骤时间线。
type interactionsSpeechResponse struct {
	// ID is the provider-issued interaction identifier.
	// ID 是供应商签发的交互标识。
	ID string `json:"id"`
	// Status is the terminal interaction state.
	// Status 是交互终态。
	Status string `json:"status"`
	// Steps contains ordered model output steps.
	// Steps 包含有序模型输出步骤。
	Steps []interactionsSpeechStep `json:"steps"`
}

// interactionsSpeechStep contains one typed model output step.
// interactionsSpeechStep 包含一个类型化模型输出步骤。
type interactionsSpeechStep struct {
	// Type discriminates model output from other steps.
	// Type 区分模型输出与其他步骤。
	Type string `json:"type"`
	// Content contains ordered audio blocks.
	// Content 包含有序音频块。
	Content []interactionsSpeechContent `json:"content"`
}

// interactionsSpeechContent contains one raw inline audio block.
// interactionsSpeechContent 包含一个原始内联音频块。
type interactionsSpeechContent struct {
	// Type is audio for generated speech.
	// Type 对生成语音为 audio。
	Type string `json:"type"`
	// Data is Base64 audio content.
	// Data 是 Base64 音频内容。
	Data string `json:"data"`
	// MIMEType is the provider-confirmed audio type.
	// MIMEType 是供应商确认的音频类型。
	MIMEType string `json:"mime_type"`
	// URI would violate the requested inline delivery contract.
	// URI 会违反请求的内联交付合同。
	URI string `json:"uri"`
}

// projectInteractionsSpeechRequest maps one canonical single- or two-speaker request.
// projectInteractionsSpeechRequest 映射一个规范的单说话人或双说话人请求。
func projectInteractionsSpeechRequest(execution provider.ExecutionRequest) (transport.Request, string, error) {
	operation := execution.Execution.Payload.SpeechSynthesize
	model := execution.Binding.Target.UpstreamModelID
	if operation == nil || !supportedInteractionsSpeechModel(model) || operation.Language != "" || operation.Speed != nil || operation.Pitch != nil || operation.Volume != nil || operation.Bitrate != 0 || operation.Timestamps || (operation.SampleRate != 0 && operation.SampleRate != 24000) || (operation.Channels != 0 && operation.Channels != 1) {
		return transport.Request{}, "", fmt.Errorf("%w: model, language override, numeric controls, timestamps, sample rate, or channels are unsupported", ErrInvalidInteractionsSpeechDriver)
	}
	mimeType, errFormat := interactionsSpeechMIMEType(operation.OutputFormat)
	if errFormat != nil {
		return transport.Request{}, "", errFormat
	}
	input, speakers, errSpeakers := projectInteractionsSpeechInput(operation)
	if errSpeakers != nil {
		return transport.Request{}, "", errSpeakers
	}
	body := interactionsSpeechRequest{Model: model, Input: input, ResponseFormat: interactionsSpeechResponseFormat{Type: "audio", MIMEType: mimeType, Delivery: "inline", SampleRate: 24000}, GenerationConfig: interactionsSpeechGenerationConfig{SpeechConfig: speakers}}
	encoded, errEncode := json.Marshal(body)
	if errEncode != nil {
		return transport.Request{}, "", fmt.Errorf("%w: encode request: %v", ErrInvalidInteractionsSpeechDriver, errEncode)
	}
	return transport.Request{Binding: execution.Binding, Method: http.MethodPost, Path: "/v1beta/interactions", Body: encoded, Headers: []transport.Header{{Name: "Content-Type", Value: "application/json"}}, Authentication: transport.Authentication{Mode: transport.AuthenticationHeader, HeaderName: "X-Goog-Api-Key"}, IdempotencyKey: execution.Execution.IdempotencyKey}, mimeType, nil
}

// projectInteractionsSpeechInput builds the official speaker-name prompt without ambiguous injected labels.
// projectInteractionsSpeechInput 构建官方说话人名称提示且不允许注入歧义标签。
func projectInteractionsSpeechInput(operation *vcp.SpeechSynthesizeOperation) (string, []interactionsSpeakerConfig, error) {
	stylePrefix := ""
	if operation.Style != "" {
		stylePrefix = "Style instructions:\n" + operation.Style + "\n\n"
	}
	if len(operation.Segments) == 0 {
		if !supportedInteractionsVoice(operation.VoiceID) {
			return "", nil, fmt.Errorf("%w: unsupported preset voice", ErrInvalidInteractionsSpeechDriver)
		}
		if stylePrefix == "" {
			return operation.Text, []interactionsSpeakerConfig{{Voice: operation.VoiceID}}, nil
		}
		return stylePrefix + "Transcript:\n" + operation.Text, []interactionsSpeakerConfig{{Voice: operation.VoiceID}}, nil
	}
	if len(operation.Segments) != 2 {
		return "", nil, fmt.Errorf("%w: Gemini multi-speaker synthesis requires exactly two segments", ErrInvalidInteractionsSpeechDriver)
	}
	for _, segment := range operation.Segments {
		if !supportedInteractionsVoice(segment.VoiceID) || containsInteractionsSpeakerLabel(segment.Text) {
			return "", nil, fmt.Errorf("%w: unsupported voice or ambiguous speaker label in transcript", ErrInvalidInteractionsSpeechDriver)
		}
	}
	input := stylePrefix + "TTS the following conversation between Speaker1 and Speaker2:\nSpeaker1: " + operation.Segments[0].Text + "\nSpeaker2: " + operation.Segments[1].Text
	speakers := []interactionsSpeakerConfig{{Speaker: "Speaker1", Voice: operation.Segments[0].VoiceID}, {Speaker: "Speaker2", Voice: operation.Segments[1].VoiceID}}
	return input, speakers, nil
}

// containsInteractionsSpeakerLabel reports whether transcript text can collide with generated speaker boundaries.
// containsInteractionsSpeakerLabel 报告逐字稿文本是否会与生成的说话人边界冲突。
func containsInteractionsSpeakerLabel(text string) bool {
	return strings.Contains(text, "\nSpeaker1:") || strings.Contains(text, "\nSpeaker2:")
}

// decodeInteractionsSpeechResponse imports exactly one inline audio output.
// decodeInteractionsSpeechResponse 导入唯一一个内联音频输出。
func decodeInteractionsSpeechResponse(reader io.Reader, expectedMIME string) (provider.ExecutionResult, error) {
	var response interactionsSpeechResponse
	if errDecode := json.NewDecoder(reader).Decode(&response); errDecode != nil || strings.TrimSpace(response.ID) == "" || response.Status != "completed" {
		return provider.ExecutionResult{}, fmt.Errorf("%w: interaction is not completed", ErrInvalidInteractionsSpeechResponse)
	}
	var audio *interactionsSpeechContent
	for stepIndex := range response.Steps {
		if response.Steps[stepIndex].Type != "model_output" {
			continue
		}
		for contentIndex := range response.Steps[stepIndex].Content {
			content := &response.Steps[stepIndex].Content[contentIndex]
			if content.Type != "audio" {
				continue
			}
			if audio != nil || content.MIMEType != expectedMIME || strings.TrimSpace(content.Data) == "" || content.URI != "" {
				return provider.ExecutionResult{}, fmt.Errorf("%w: audio output violates the requested inline contract", ErrInvalidInteractionsSpeechResponse)
			}
			audio = content
		}
	}
	if audio == nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: response contains no audio output", ErrInvalidInteractionsSpeechResponse)
	}
	decoded, errDecode := base64.StdEncoding.DecodeString(audio.Data)
	if errDecode != nil || len(decoded) == 0 {
		return provider.ExecutionResult{}, fmt.Errorf("%w: generated audio contains invalid Base64 data", ErrInvalidInteractionsSpeechResponse)
	}
	return provider.ExecutionResult{UpstreamResponseID: response.ID, GeneratedResources: []provider.GeneratedResource{{OutputID: "audio-0", Kind: vcp.MediaAudio, MIMEType: audio.MIMEType, Data: decoded}}}, nil
}

// interactionsSpeechMIMEType resolves only Router-probeable Interactions formats.
// interactionsSpeechMIMEType 仅解析 Router 可探测的 Interactions 格式。
func interactionsSpeechMIMEType(format string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "wav":
		return "audio/wav", nil
	case "mp3":
		return "audio/mp3", nil
	default:
		return "", fmt.Errorf("%w: unsupported output format %q", ErrInvalidInteractionsSpeechDriver, format)
	}
}

// supportedInteractionsSpeechModel reports the current non-realtime Gemini TTS inventory.
// supportedInteractionsSpeechModel 报告当前非实时 Gemini TTS 模型清单。
func supportedInteractionsSpeechModel(model string) bool {
	return model == "gemini-3.1-flash-tts-preview" || model == "gemini-2.5-flash-preview-tts" || model == "gemini-2.5-pro-preview-tts"
}

// supportedInteractionsVoice reports the current thirty prebuilt voice names.
// supportedInteractionsVoice 报告当前三十个预设声音名称。
func supportedInteractionsVoice(voice string) bool {
	switch voice {
	case "Zephyr", "Puck", "Charon", "Kore", "Fenrir", "Leda", "Orus", "Aoede", "Callirrhoe", "Autonoe", "Enceladus", "Iapetus", "Umbriel", "Algieba", "Despina", "Erinome", "Algenib", "Rasalgethi", "Laomedeia", "Achernar", "Alnilam", "Schedar", "Gacrux", "Pulcherrima", "Achird", "Zubenelgenubi", "Vindemiatrix", "Sadachbia", "Sadaltager", "Sulafat":
		return true
	default:
		return false
	}
}
