package openai

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

const (
	// SpeechSynthesizeActionBindingID identifies OpenAI non-realtime speech synthesis.
	// SpeechSynthesizeActionBindingID 标识 OpenAI 非实时语音合成动作。
	SpeechSynthesizeActionBindingID = "action_openai_speech_synthesize"
	// SpeechTranscribeActionBindingID identifies OpenAI non-realtime transcription.
	// SpeechTranscribeActionBindingID 标识 OpenAI 非实时语音转写动作。
	SpeechTranscribeActionBindingID = "action_openai_speech_transcribe"
	// SpeechSynthesizeProtocolProfileID identifies the closed OpenAI speech endpoint contract.
	// SpeechSynthesizeProtocolProfileID 标识封闭的 OpenAI 语音合成端点合同。
	SpeechSynthesizeProtocolProfileID = "openai.audio.speech.v1"
	// SpeechTranscribeProtocolProfileID identifies the closed OpenAI transcription endpoint contract.
	// SpeechTranscribeProtocolProfileID 标识封闭的 OpenAI 语音转写端点合同。
	SpeechTranscribeProtocolProfileID = "openai.audio.transcriptions.v1"
	// maximumOpenAITranscriptionBytes is the documented upload ceiling.
	// maximumOpenAITranscriptionBytes 是文档规定的上传大小上限。
	maximumOpenAITranscriptionBytes = 25 << 20
)

var (
	// ErrInvalidAudioDriver reports an incomplete or unsupported OpenAI audio execution.
	// ErrInvalidAudioDriver 表示 OpenAI 音频执行不完整或不受支持。
	ErrInvalidAudioDriver = errors.New("invalid OpenAI audio driver")
	// ErrInvalidAudioResponse reports a malformed OpenAI audio response.
	// ErrInvalidAudioResponse 表示 OpenAI 音频响应格式错误。
	ErrInvalidAudioResponse = errors.New("invalid OpenAI audio response")
)

// AudioActionDriver executes exactly one OpenAI audio action for one provider definition.
// AudioActionDriver 为一个供应商定义执行唯一的 OpenAI 音频动作。
type AudioActionDriver struct {
	// definitionID fixes the sole owning provider definition.
	// definitionID 固定唯一所属供应商定义。
	definitionID string
	// actionBindingID fixes synthesis or transcription behavior.
	// actionBindingID 固定语音合成或转写行为。
	actionBindingID string
	// client owns authenticated provider-scoped HTTP execution.
	// client 负责经过认证且限定供应商作用域的 HTTP 执行。
	client *transport.Client
}

// NewAudioActionDriver creates one action-bound OpenAI audio driver.
// NewAudioActionDriver 创建一个绑定到动作的 OpenAI 音频驱动。
func NewAudioActionDriver(definitionID string, actionBindingID string, client *transport.Client) (*AudioActionDriver, error) {
	if strings.TrimSpace(definitionID) == "" || client == nil || (actionBindingID != SpeechSynthesizeActionBindingID && actionBindingID != SpeechTranscribeActionBindingID) {
		return nil, ErrInvalidAudioDriver
	}
	return &AudioActionDriver{definitionID: definitionID, actionBindingID: actionBindingID, client: client}, nil
}

// ProviderDefinitionID returns the sole provider definition owned by this driver.
// ProviderDefinitionID 返回此驱动唯一拥有的供应商定义。
func (d *AudioActionDriver) ProviderDefinitionID() string {
	if d == nil {
		return ""
	}
	return d.definitionID
}

// ActionBindingID returns the sole action binding owned by this driver.
// ActionBindingID 返回此驱动唯一拥有的动作绑定。
func (d *AudioActionDriver) ActionBindingID() string {
	if d == nil {
		return ""
	}
	return d.actionBindingID
}

// Execute projects and executes one official OpenAI audio request.
// Execute 投影并执行一个 OpenAI 官方音频请求。
func (d *AudioActionDriver) Execute(ctx context.Context, execution provider.ExecutionRequest) (provider.ExecutionResult, error) {
	if d == nil || d.client == nil {
		return provider.ExecutionResult{}, ErrInvalidAudioDriver
	}
	if execution.Binding.Target.ProviderDefinitionID != d.definitionID {
		return provider.ExecutionResult{}, fmt.Errorf("%w: target definition does not belong to this driver", provider.ErrExecutionBinding)
	}
	if _, errValidate := execution.ValidateForAction(d.actionBindingID, providerconfig.AuthMethodAPIKey); errValidate != nil {
		return provider.ExecutionResult{}, errValidate
	}
	if d.actionBindingID == SpeechSynthesizeActionBindingID {
		return d.executeSynthesis(ctx, execution)
	}
	return d.executeTranscription(ctx, execution)
}

// openAISpeechRequest is the exact JSON shape accepted by tts-1 and tts-1-hd.
// openAISpeechRequest 是 tts-1 与 tts-1-hd 接受的精确 JSON 结构。
type openAISpeechRequest struct {
	// Model is the resolved upstream TTS model.
	// Model 是解析后的上游 TTS 模型。
	Model string `json:"model"`
	// Input is the exact caller text.
	// Input 是调用方提供的精确文本。
	Input string `json:"input"`
	// Voice is one provider-supported built-in voice.
	// Voice 是供应商支持的内置声音。
	Voice string `json:"voice"`
	// ResponseFormat is a Router-probeable audio format.
	// ResponseFormat 是 Router 可探测的音频格式。
	ResponseFormat string `json:"response_format,omitempty"`
	// Speed is emitted only when the caller selected it.
	// Speed 仅在调用方选择时发送。
	Speed *float64 `json:"speed,omitempty"`
}

// executeSynthesis validates the closed tts-1 carrier and imports returned audio bytes.
// executeSynthesis 校验封闭的 tts-1 载体并导入返回的音频字节。
func (d *AudioActionDriver) executeSynthesis(ctx context.Context, execution provider.ExecutionRequest) (provider.ExecutionResult, error) {
	operation := execution.Execution.Payload.SpeechSynthesize
	model := execution.Binding.Target.UpstreamModelID
	if operation == nil || (model != "tts-1" && model != "tts-1-hd") {
		return provider.ExecutionResult{}, ErrInvalidAudioDriver
	}
	if len(operation.Segments) != 0 || operation.Language != "" || operation.Style != "" || operation.Pitch != nil || operation.Volume != nil || operation.SampleRate != 0 || operation.Bitrate != 0 || operation.Channels != 0 || operation.Timestamps {
		return provider.ExecutionResult{}, fmt.Errorf("%w: selected OpenAI TTS models support one voice, text, speed, and output_format only", ErrInvalidAudioDriver)
	}
	if len([]rune(operation.Text)) > 4096 || !supportedOpenAIVoice(operation.VoiceID) {
		return provider.ExecutionResult{}, fmt.Errorf("%w: text exceeds 4096 characters or voice is unsupported", ErrInvalidAudioDriver)
	}
	if operation.Speed != nil && (*operation.Speed < 0.25 || *operation.Speed > 4) {
		return provider.ExecutionResult{}, fmt.Errorf("%w: speed must be between 0.25 and 4.0", ErrInvalidAudioDriver)
	}
	format, mimeType, errFormat := openAIAudioOutputFormat(operation.OutputFormat)
	if errFormat != nil {
		return provider.ExecutionResult{}, errFormat
	}
	body := openAISpeechRequest{Model: model, Input: operation.Text, Voice: operation.VoiceID, ResponseFormat: format, Speed: operation.Speed}
	encoded, errEncode := json.Marshal(body)
	if errEncode != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: encode synthesis request: %v", ErrInvalidAudioDriver, errEncode)
	}
	response, errRequest := d.client.Do(ctx, transport.Request{Binding: execution.Binding, Method: http.MethodPost, Path: "/v1/audio/speech", Body: encoded, Headers: []transport.Header{{Name: "Content-Type", Value: "application/json"}, {Name: "Accept", Value: mimeType}}, Authentication: transport.Authentication{Mode: transport.AuthenticationBearer}, IdempotencyKey: execution.Execution.IdempotencyKey})
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
		return provider.ExecutionResult{}, fmt.Errorf("%w: read generated audio: %v", ErrInvalidAudioResponse, errRead)
	}
	return provider.ExecutionResult{GeneratedResources: []provider.GeneratedResource{{OutputID: "audio-0", Kind: vcp.MediaAudio, MIMEType: mimeType, Data: audio}}}, nil
}

// executeTranscription sends one bounded inline resource as multipart and decodes typed transcript output.
// executeTranscription 将一个有界内联资源作为 multipart 发送并解码类型化转写结果。
func (d *AudioActionDriver) executeTranscription(ctx context.Context, execution provider.ExecutionRequest) (provider.ExecutionResult, error) {
	operation := execution.Execution.Payload.SpeechTranscribe
	if operation == nil {
		return provider.ExecutionResult{}, ErrInvalidAudioDriver
	}
	model := execution.Binding.Target.UpstreamModelID
	if !supportedOpenAITranscriptionModel(model) || operation.CandidateCount > 1 || operation.TranslationTarget != "" || len(operation.Hotwords) != 0 {
		return provider.ExecutionResult{}, fmt.Errorf("%w: model, candidate_count, translation_target, or hotwords are unsupported", ErrInvalidAudioDriver)
	}
	input, errInput := exactOpenAITranscriptionInput(execution.MaterializedInputs, operation.Source)
	if errInput != nil {
		return provider.ExecutionResult{}, errInput
	}
	if model == "gpt-4o-transcribe-diarize" {
		if operation.Prompt != "" || operation.WordTimestamps {
			return provider.ExecutionResult{}, fmt.Errorf("%w: diarize does not accept prompt or word timestamps", ErrInvalidAudioDriver)
		}
	} else if operation.Diarization {
		return provider.ExecutionResult{}, fmt.Errorf("%w: selected transcription model does not support diarization", ErrInvalidAudioDriver)
	}
	if model != "whisper-1" && model != "gpt-4o-transcribe-diarize" && (operation.SegmentTimestamps || operation.WordTimestamps) {
		return provider.ExecutionResult{}, fmt.Errorf("%w: timestamp granularities require whisper-1", ErrInvalidAudioDriver)
	}
	outbound, errProject := projectOpenAITranscription(execution, input)
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
	transcript, errDecode := decodeOpenAITranscript(bounded, model)
	if errDecode != nil {
		return provider.ExecutionResult{}, errDecode
	}
	return provider.ExecutionResult{Transcript: &transcript}, nil
}

// exactOpenAITranscriptionInput resolves the one frozen inline source without fallback paths.
// exactOpenAITranscriptionInput 解析唯一冻结的内联来源且不使用候选兜底路径。
func exactOpenAITranscriptionInput(inputs []resource.MaterializedInput, source vcp.MediaInput) (resource.MaterializedInput, error) {
	for _, input := range inputs {
		if input.InputID != source.ID {
			continue
		}
		if input.ResourceID != source.Resource.ResourceID || input.Kind != source.Kind || input.Role != vcp.MediaRoleTranscriptionSource || input.Mode != catalog.MaterializationInlineBase64 || !supportedOpenAITranscriptionMIME(input.MIMEType) {
			return resource.MaterializedInput{}, fmt.Errorf("%w: transcription source materialization differs from the accepted input plan", ErrInvalidAudioDriver)
		}
		decoded, errDecode := base64.StdEncoding.DecodeString(input.InlineBase64)
		if errDecode != nil || len(decoded) == 0 || len(decoded) > maximumOpenAITranscriptionBytes {
			return resource.MaterializedInput{}, fmt.Errorf("%w: transcription source must contain at most 25 MiB of valid Base64 data", ErrInvalidAudioDriver)
		}
		input.InlineBase64 = base64.StdEncoding.EncodeToString(decoded)
		return input, nil
	}
	return resource.MaterializedInput{}, fmt.Errorf("%w: transcription source has no exact materialized input", ErrInvalidAudioDriver)
}

// projectOpenAITranscription builds the exact multipart fields for the selected model family.
// projectOpenAITranscription 为所选模型系列构建精确的 multipart 字段。
func projectOpenAITranscription(execution provider.ExecutionRequest, input resource.MaterializedInput) (transport.Request, error) {
	operation := execution.Execution.Payload.SpeechTranscribe
	decoded, errDecode := base64.StdEncoding.DecodeString(input.InlineBase64)
	if errDecode != nil {
		return transport.Request{}, ErrInvalidAudioDriver
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if errField := writer.WriteField("model", execution.Binding.Target.UpstreamModelID); errField != nil {
		return transport.Request{}, errField
	}
	responseFormat := "json"
	if execution.Binding.Target.UpstreamModelID == "whisper-1" && (operation.SegmentTimestamps || operation.WordTimestamps) {
		responseFormat = "verbose_json"
	}
	if execution.Binding.Target.UpstreamModelID == "gpt-4o-transcribe-diarize" {
		responseFormat = "diarized_json"
		if errField := writer.WriteField("chunking_strategy", "auto"); errField != nil {
			return transport.Request{}, errField
		}
	}
	if errField := writer.WriteField("response_format", responseFormat); errField != nil {
		return transport.Request{}, errField
	}
	if operation.Language != "" {
		if errField := writer.WriteField("language", operation.Language); errField != nil {
			return transport.Request{}, errField
		}
	}
	if operation.Prompt != "" {
		if errField := writer.WriteField("prompt", operation.Prompt); errField != nil {
			return transport.Request{}, errField
		}
	}
	if operation.SegmentTimestamps {
		if errField := writer.WriteField("timestamp_granularities[]", "segment"); errField != nil {
			return transport.Request{}, errField
		}
	}
	if operation.WordTimestamps {
		if errField := writer.WriteField("timestamp_granularities[]", "word"); errField != nil {
			return transport.Request{}, errField
		}
	}
	part, errPart := writer.CreateFormFile("file", "source"+openAIAudioInputExtension(input.MIMEType))
	if errPart != nil {
		return transport.Request{}, errPart
	}
	if _, errWrite := part.Write(decoded); errWrite != nil {
		return transport.Request{}, errWrite
	}
	if errClose := writer.Close(); errClose != nil {
		return transport.Request{}, errClose
	}
	return transport.Request{Binding: execution.Binding, Method: http.MethodPost, Path: "/v1/audio/transcriptions", Body: body.Bytes(), Headers: []transport.Header{{Name: "Content-Type", Value: writer.FormDataContentType()}}, Authentication: transport.Authentication{Mode: transport.AuthenticationBearer}, IdempotencyKey: execution.Execution.IdempotencyKey}, nil
}

// openAITranscriptionResponse captures plain, verbose, and diarized JSON without untyped maps.
// openAITranscriptionResponse 在不使用无类型映射的情况下承载普通、详细及说话人分离 JSON。
type openAITranscriptionResponse struct {
	// Text is the complete provider transcript.
	// Text 是供应商返回的完整转写文本。
	Text string `json:"text"`
	// Language is present in Whisper verbose JSON.
	// Language 出现在 Whisper 详细 JSON 中。
	Language string `json:"language"`
	// Duration is the provider-confirmed duration in seconds.
	// Duration 是供应商确认的秒级时长。
	Duration *float64 `json:"duration"`
	// Segments contains Whisper or diarized segments.
	// Segments 包含 Whisper 或说话人分离分段。
	Segments []openAITranscriptSegment `json:"segments"`
	// Words contains Whisper word timestamp facts.
	// Words 包含 Whisper 词级时间戳事实。
	Words []openAITranscriptWord `json:"words"`
}

// openAITranscriptSegment is the common typed subset of provider segment variants.
// openAITranscriptSegment 是供应商不同分段结构的共同类型化子集。
type openAITranscriptSegment struct {
	// ID is the provider segment identity in integer or string form.
	// ID 是整数或字符串形式的供应商分段标识。
	ID openAIIdentifier `json:"id"`
	// Start is the inclusive offset in seconds.
	// Start 是包含起点的秒级偏移。
	Start float64 `json:"start"`
	// End is the exclusive offset in seconds.
	// End 是不包含终点的秒级偏移。
	End float64 `json:"end"`
	// Text is the exact segment transcript.
	// Text 是精确的分段转写文本。
	Text string `json:"text"`
	// Speaker is provider-confirmed only for diarized output.
	// Speaker 仅在说话人分离输出中由供应商确认。
	Speaker string `json:"speaker"`
}

// openAITranscriptWord contains one provider-returned word timing pair.
// openAITranscriptWord 包含一个供应商返回的词级时间对。
type openAITranscriptWord struct {
	// Word is the exact recognized token text.
	// Word 是精确识别的词文本。
	Word string `json:"word"`
	// Start is the inclusive offset in seconds.
	// Start 是包含起点的秒级偏移。
	Start float64 `json:"start"`
	// End is the exclusive offset in seconds.
	// End 是不包含终点的秒级偏移。
	End float64 `json:"end"`
}

// openAIIdentifier preserves string and integer provider segment identifiers.
// openAIIdentifier 保留字符串与整数形式的供应商分段标识。
type openAIIdentifier string

// UnmarshalJSON decodes exactly one documented string or integer identifier.
// UnmarshalJSON 仅解码文档规定的字符串或整数标识。
func (i *openAIIdentifier) UnmarshalJSON(data []byte) error {
	var textValue string
	if errString := json.Unmarshal(data, &textValue); errString == nil {
		if strings.TrimSpace(textValue) == "" {
			return ErrInvalidAudioResponse
		}
		*i = openAIIdentifier(textValue)
		return nil
	}
	var integerValue int64
	if errInteger := json.Unmarshal(data, &integerValue); errInteger != nil || integerValue < 0 {
		return ErrInvalidAudioResponse
	}
	*i = openAIIdentifier(strconv.FormatInt(integerValue, 10))
	return nil
}

// decodeOpenAITranscript converts one provider response into the closed VCP transcript contract.
// decodeOpenAITranscript 将一个供应商响应转换为封闭的 VCP 转写合同。
func decodeOpenAITranscript(reader io.Reader, model string) (vcp.Transcript, error) {
	var response openAITranscriptionResponse
	decoder := json.NewDecoder(reader)
	if errDecode := decoder.Decode(&response); errDecode != nil {
		return vcp.Transcript{}, fmt.Errorf("%w: decode transcription: %v", ErrInvalidAudioResponse, errDecode)
	}
	transcript := vcp.Transcript{Candidates: []vcp.TranscriptCandidate{{CandidateID: "candidate-0", Text: response.Text, Language: response.Language}}}
	if response.Duration != nil {
		duration, errDuration := secondsToMilliseconds(*response.Duration)
		if errDuration != nil {
			return vcp.Transcript{}, errDuration
		}
		transcript.DurationMilliseconds = &duration
	}
	segments := make([]vcp.TranscriptSegment, 0, len(response.Segments))
	for index, providerSegment := range response.Segments {
		start, errStart := secondsToMilliseconds(providerSegment.Start)
		end, errEnd := secondsToMilliseconds(providerSegment.End)
		if errStart != nil || errEnd != nil || end < start || strings.TrimSpace(providerSegment.Text) == "" {
			return vcp.Transcript{}, fmt.Errorf("%w: invalid segment timing or text", ErrInvalidAudioResponse)
		}
		segmentID := string(providerSegment.ID)
		if segmentID == "" {
			segmentID = "segment-" + strconv.Itoa(index)
		}
		segments = append(segments, vcp.TranscriptSegment{CandidateID: "candidate-0", SegmentID: segmentID, Text: providerSegment.Text, StartMilliseconds: &start, EndMilliseconds: &end, Speaker: providerSegment.Speaker})
	}
	for _, providerWord := range response.Words {
		start, errStart := secondsToMilliseconds(providerWord.Start)
		end, errEnd := secondsToMilliseconds(providerWord.End)
		if errStart != nil || errEnd != nil || end < start || strings.TrimSpace(providerWord.Word) == "" {
			return vcp.Transcript{}, fmt.Errorf("%w: invalid word timing or text", ErrInvalidAudioResponse)
		}
		assigned := false
		for index := range segments {
			if start >= *segments[index].StartMilliseconds && end <= *segments[index].EndMilliseconds {
				segments[index].Words = append(segments[index].Words, vcp.TranscriptWord{Text: providerWord.Word, StartMilliseconds: &start, EndMilliseconds: &end})
				assigned = true
				break
			}
		}
		if !assigned {
			return vcp.Transcript{}, fmt.Errorf("%w: word timing is outside every provider segment", ErrInvalidAudioResponse)
		}
	}
	transcript.Candidates[0].Segments = segments
	if model == "gpt-4o-transcribe-diarize" && len(segments) == 0 {
		return vcp.Transcript{}, fmt.Errorf("%w: diarized response has no speaker segments", ErrInvalidAudioResponse)
	}
	if errValidate := transcript.Validate(); errValidate != nil {
		return vcp.Transcript{}, fmt.Errorf("%w: %v", ErrInvalidAudioResponse, errValidate)
	}
	return transcript, nil
}

// secondsToMilliseconds converts finite non-negative provider seconds with nearest-millisecond precision.
// secondsToMilliseconds 将有限非负供应商秒数按最接近毫秒精度转换。
func secondsToMilliseconds(seconds float64) (int64, error) {
	if math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds < 0 || seconds > float64(math.MaxInt64)/1000 {
		return 0, ErrInvalidAudioResponse
	}
	return int64(math.Round(seconds * 1000)), nil
}

// supportedOpenAIVoice reports the documented built-in voices accepted by tts-1 models.
// supportedOpenAIVoice 报告 tts-1 模型接受的文档内置声音。
func supportedOpenAIVoice(voice string) bool {
	switch voice {
	case "alloy", "ash", "ballad", "coral", "echo", "fable", "onyx", "nova", "sage", "shimmer", "verse", "marin", "cedar":
		return true
	default:
		return false
	}
}

// openAIAudioOutputFormat resolves only formats the Router can verify and persist.
// openAIAudioOutputFormat 仅解析 Router 能够验证并持久化的格式。
func openAIAudioOutputFormat(format string) (string, string, error) {
	switch format {
	case "", "mp3":
		return "mp3", "audio/mpeg", nil
	case "wav":
		return "wav", "audio/wav", nil
	default:
		return "", "", fmt.Errorf("%w: output format %q is not Router-probeable", ErrInvalidAudioDriver, format)
	}
}

// supportedOpenAITranscriptionModel reports the exact non-realtime models implemented here.
// supportedOpenAITranscriptionModel 报告此处实现的精确非实时模型。
func supportedOpenAITranscriptionModel(model string) bool {
	return model == "gpt-4o-transcribe" || model == "gpt-4o-mini-transcribe" || model == "gpt-4o-transcribe-diarize" || model == "whisper-1"
}

// supportedOpenAITranscriptionMIME reports Router-probeable formats accepted by OpenAI transcription.
// supportedOpenAITranscriptionMIME 报告 OpenAI 转写接受且 Router 可探测的格式。
func supportedOpenAITranscriptionMIME(mimeType string) bool {
	switch strings.ToLower(strings.TrimSpace(mimeType)) {
	case "audio/mpeg", "audio/wav", "video/mp4", "video/webm":
		return true
	default:
		return false
	}
}

// openAIAudioInputExtension returns the exact safe multipart filename extension.
// openAIAudioInputExtension 返回精确且安全的 multipart 文件扩展名。
func openAIAudioInputExtension(mimeType string) string {
	switch strings.ToLower(strings.TrimSpace(mimeType)) {
	case "audio/mpeg":
		return ".mp3"
	case "audio/wav":
		return ".wav"
	case "video/mp4":
		return ".mp4"
	case "video/webm":
		return ".webm"
	default:
		return ""
	}
}
