package alibaba

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

const (
	// CosyVoiceSynthesizeActionBindingID identifies non-realtime CosyVoice synthesis.
	// CosyVoiceSynthesizeActionBindingID 标识非实时 CosyVoice 语音合成。
	CosyVoiceSynthesizeActionBindingID = "action_alibaba_cosyvoice_synthesize"
	// CosyVoiceSynthesizeProtocolProfileID identifies the closed CosyVoice HTTP and SSE contract.
	// CosyVoiceSynthesizeProtocolProfileID 标识封闭的 CosyVoice HTTP 与 SSE 合同。
	CosyVoiceSynthesizeProtocolProfileID = "alibaba.cosyvoice.synthesize.v1"
	// dashScopeCosyVoicePath is the exact path used by the released Bailian CLI.
	// dashScopeCosyVoicePath 是已发布 Bailian CLI 使用的精确路径。
	dashScopeCosyVoicePath = "/api/v1/services/audio/tts/SpeechSynthesizer"
	// maximumCosyVoiceSSELineBytes bounds one independently decoded audio frame.
	// maximumCosyVoiceSSELineBytes 限制一个独立解码音频帧的大小。
	maximumCosyVoiceSSELineBytes = 8 * 1024 * 1024
)

// CosyVoiceActionDriver executes one immutable Alibaba CosyVoice action.
// CosyVoiceActionDriver 执行一个不可变的阿里 CosyVoice 动作。
type CosyVoiceActionDriver struct {
	// definitionID fixes the sole owning provider definition.
	// definitionID 固定唯一所属供应商 Definition。
	definitionID string
	// client owns authenticated provider-scoped HTTP execution.
	// client 负责经过认证且限定供应商作用域的 HTTP 执行。
	client *transport.Client
}

// NewCosyVoiceActionDriver creates one exact CosyVoice synthesis driver.
// NewCosyVoiceActionDriver 创建一个精确的 CosyVoice 合成 Driver。
func NewCosyVoiceActionDriver(definitionID string, client *transport.Client) (*CosyVoiceActionDriver, error) {
	if strings.TrimSpace(definitionID) == "" || client == nil {
		return nil, ErrInvalidSpeechDriver
	}
	return &CosyVoiceActionDriver{definitionID: definitionID, client: client}, nil
}

// ProviderDefinitionID returns the sole provider definition owned by this driver.
// ProviderDefinitionID 返回此 Driver 唯一所属的供应商 Definition。
func (d *CosyVoiceActionDriver) ProviderDefinitionID() string {
	if d == nil {
		return ""
	}
	return d.definitionID
}

// ActionBindingID returns the exact CosyVoice action binding.
// ActionBindingID 返回精确的 CosyVoice 动作绑定。
func (d *CosyVoiceActionDriver) ActionBindingID() string { return CosyVoiceSynthesizeActionBindingID }

// Execute projects and executes one official non-realtime CosyVoice request.
// Execute 投影并执行一个官方非实时 CosyVoice 请求。
func (d *CosyVoiceActionDriver) Execute(ctx context.Context, execution provider.ExecutionRequest) (provider.ExecutionResult, error) {
	if d == nil || d.client == nil || execution.Binding.Target.ProviderDefinitionID != d.definitionID {
		return provider.ExecutionResult{}, fmt.Errorf("%w: target definition does not belong to this driver", provider.ErrExecutionBinding)
	}
	if _, errValidate := execution.ValidateForAction(CosyVoiceSynthesizeActionBindingID, providerconfig.AuthMethodAPIKey); errValidate != nil {
		return provider.ExecutionResult{}, errValidate
	}
	body, format, errProject := projectCosyVoiceRequest(execution)
	if errProject != nil {
		return provider.ExecutionResult{}, errProject
	}
	headers := alibabaJSONHeaders(execution.MaterializedInputs, false)
	outbound := transport.Request{Binding: execution.Binding, Method: http.MethodPost, Path: dashScopeCosyVoicePath, Body: body, Headers: headers, Authentication: transport.Authentication{Mode: transport.AuthenticationBearer}, IdempotencyKey: execution.Execution.IdempotencyKey}
	if execution.Execution.Stream {
		outbound.Headers = append(outbound.Headers, transport.Header{Name: "Accept", Value: "text/event-stream"}, transport.Header{Name: "X-DashScope-SSE", Value: "enable"})
		response, errRequest := d.client.DoStream(ctx, outbound)
		if errRequest != nil {
			return provider.ExecutionResult{}, errRequest
		}
		defer func() { _ = transport.DrainAndClose(response) }()
		audio, errDecode := decodeCosyVoiceSSE(ctx, response.Body, execution.ResourceSink, cosyVoiceMIMEType(format), execution.Execution.Budget.MaxOutputBytes)
		if errDecode != nil {
			return provider.ExecutionResult{}, errDecode
		}
		return provider.ExecutionResult{GeneratedResources: []provider.GeneratedResource{{OutputID: "audio-0", Kind: vcp.MediaAudio, MIMEType: cosyVoiceMIMEType(format), Data: audio}}}, nil
	}
	response, errRequest := d.client.Do(ctx, outbound)
	if errRequest != nil {
		return provider.ExecutionResult{}, errRequest
	}
	defer func() { _ = transport.DrainAndClose(response) }()
	bounded, errBound := transport.NewBoundedResponseReader(response.Body, transport.MaximumNonStreamingResponseBytes)
	if errBound != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: bound CosyVoice response: %v", ErrInvalidSpeechResponse, errBound)
	}
	return decodeCosyVoiceResponse(bounded, cosyVoiceMIMEType(format))
}

// cosyVoiceRequest is the exact released Bailian CLI request envelope.
// cosyVoiceRequest 是已发布 Bailian CLI 的精确请求信封。
type cosyVoiceRequest struct {
	// Model is the resolved upstream CosyVoice model.
	// Model 是已解析的上游 CosyVoice 模型。
	Model string `json:"model"`
	// Input contains the complete non-realtime synthesis controls.
	// Input 包含完整的非实时语音合成控制项。
	Input cosyVoiceInput `json:"input"`
}

// cosyVoiceInput contains every verified non-realtime CosyVoice field.
// cosyVoiceInput 包含每个已验证的非实时 CosyVoice 字段。
type cosyVoiceInput struct {
	// Text is the exact plain text or SSML document.
	// Text 是精确的普通文本或 SSML 文档。
	Text string `json:"text"`
	// Voice selects one system, cloned, or designed voice identifier.
	// Voice 选择一个系统、复刻或设计声音标识。
	Voice string `json:"voice"`
	// Format selects mp3, pcm, wav, or opus.
	// Format 选择 mp3、pcm、wav 或 opus。
	Format string `json:"format,omitempty"`
	// SampleRate optionally requests an output sample rate.
	// SampleRate 可选地请求输出采样率。
	SampleRate int `json:"sample_rate,omitempty"`
	// Volume optionally requests a zero-through-one-hundred level.
	// Volume 可选地请求零至一百的音量级别。
	Volume *float64 `json:"volume,omitempty"`
	// Rate optionally requests a 0.5-through-2.0 speech rate.
	// Rate 可选地请求 0.5 至 2.0 的语速。
	Rate *float64 `json:"rate,omitempty"`
	// Pitch optionally requests a 0.5-through-2.0 pitch multiplier.
	// Pitch 可选地请求 0.5 至 2.0 的音调倍数。
	Pitch *float64 `json:"pitch,omitempty"`
	// Seed optionally requests a zero-through-65535 deterministic seed.
	// Seed 可选地请求零至 65535 的确定性种子。
	Seed *int64 `json:"seed,omitempty"`
	// LanguageHints contains the sole caller-supplied pronunciation hint.
	// LanguageHints 包含调用方提供的唯一发音提示。
	LanguageHints []string `json:"language_hints,omitempty"`
	// Instruction contains one natural-language delivery instruction.
	// Instruction 包含一条自然语言表达指令。
	Instruction string `json:"instruction,omitempty"`
	// EnableSSML enables explicit SSML parsing.
	// EnableSSML 启用显式 SSML 解析。
	EnableSSML bool `json:"enable_ssml,omitempty"`
}

// projectCosyVoiceRequest validates and encodes one exact VCP synthesis operation.
// projectCosyVoiceRequest 校验并编码一个精确 VCP 语音合成操作。
func projectCosyVoiceRequest(execution provider.ExecutionRequest) ([]byte, string, error) {
	operation := execution.Execution.Payload.SpeechSynthesize
	if operation == nil || strings.TrimSpace(operation.Text) == "" || strings.TrimSpace(operation.VoiceID) == "" || len(operation.Segments) != 0 {
		return nil, "", fmt.Errorf("%w: CosyVoice requires text and one voice", ErrInvalidSpeechDriver)
	}
	if len(operation.Pronunciations) != 0 || operation.Bitrate != 0 || operation.Channels != 0 || operation.Timestamps {
		return nil, "", fmt.Errorf("%w: pronunciations, bitrate, channels, and timestamps have no CosyVoice carrier", ErrInvalidSpeechDriver)
	}
	if operation.Speed != nil && (*operation.Speed < 0.5 || *operation.Speed > 2) || operation.Pitch != nil && (*operation.Pitch < 0.5 || *operation.Pitch > 2) || operation.Volume != nil && (*operation.Volume < 0 || *operation.Volume > 100) || operation.Seed != nil && (*operation.Seed < 0 || *operation.Seed > 65535) {
		return nil, "", fmt.Errorf("%w: CosyVoice numeric controls are outside verified ranges", ErrInvalidSpeechDriver)
	}
	format := strings.ToLower(strings.TrimSpace(operation.OutputFormat))
	if format == "" {
		format = "mp3"
	}
	if cosyVoiceMIMEType(format) == "" || operation.SampleRate < 0 {
		return nil, "", fmt.Errorf("%w: unsupported CosyVoice format or sample rate", ErrInvalidSpeechDriver)
	}
	languages := []string(nil)
	if operation.Language != "" {
		if operation.Language != strings.TrimSpace(operation.Language) {
			return nil, "", fmt.Errorf("%w: CosyVoice language hint must be normalized", ErrInvalidSpeechDriver)
		}
		languages = []string{operation.Language}
	}
	request := cosyVoiceRequest{Model: execution.Binding.Target.UpstreamModelID, Input: cosyVoiceInput{Text: operation.Text, Voice: operation.VoiceID, Format: format, SampleRate: operation.SampleRate, Volume: operation.Volume, Rate: operation.Speed, Pitch: operation.Pitch, Seed: operation.Seed, LanguageHints: languages, Instruction: operation.Style, EnableSSML: operation.EnableSSML}}
	encoded, errEncode := json.Marshal(request)
	if errEncode != nil {
		return nil, "", fmt.Errorf("%w: encode CosyVoice request: %v", ErrInvalidSpeechDriver, errEncode)
	}
	return encoded, format, nil
}

// cosyVoiceResponse is the exact terminal non-streaming response envelope.
// cosyVoiceResponse 是精确的终态非流式响应信封。
type cosyVoiceResponse struct {
	// RequestID is the provider-issued diagnostic identifier.
	// RequestID 是供应商签发的诊断标识。
	RequestID string `json:"request_id"`
	// Output contains the terminal audio locator and finish reason.
	// Output 包含终态音频定位符与结束原因。
	Output cosyVoiceOutput `json:"output"`
}

// cosyVoiceOutput contains one terminal or streamed audio observation.
// cosyVoiceOutput 包含一个终态或流式音频观测。
type cosyVoiceOutput struct {
	// Audio contains one URL or one Base64 stream chunk.
	// Audio 包含一个 URL 或一个 Base64 流分片。
	Audio cosyVoiceAudio `json:"audio"`
	// FinishReason equals stop on a terminal stream frame when present.
	// FinishReason 在存在时于终止流帧上等于 stop。
	FinishReason string `json:"finish_reason"`
}

// cosyVoiceAudio contains one verified audio locator or chunk.
// cosyVoiceAudio 包含一个已验证音频定位符或分片。
type cosyVoiceAudio struct {
	// URL is the temporary complete audio URL.
	// URL 是临时完整音频 URL。
	URL string `json:"url"`
	// Data is one independently decodable Base64 audio chunk.
	// Data 是一个可独立解码的 Base64 音频分片。
	Data string `json:"data"`
}

// decodeCosyVoiceResponse converts one complete URL response into a private import source.
// decodeCosyVoiceResponse 将一个完整 URL 响应转换为私有导入来源。
func decodeCosyVoiceResponse(reader io.Reader, mimeType string) (provider.ExecutionResult, error) {
	var response cosyVoiceResponse
	if errDecode := decodeAlibabaJSONResponse(reader, &response, ErrInvalidSpeechResponse); errDecode != nil {
		return provider.ExecutionResult{}, errDecode
	}
	if strings.TrimSpace(response.RequestID) == "" || response.Output.FinishReason != "" && response.Output.FinishReason != "stop" || !validCosyVoiceAudioURL(response.Output.Audio.URL) {
		return provider.ExecutionResult{}, fmt.Errorf("%w: malformed CosyVoice response", ErrInvalidSpeechResponse)
	}
	return provider.ExecutionResult{GeneratedResources: []provider.GeneratedResource{{OutputID: "audio-0", Kind: vcp.MediaAudio, MIMEType: mimeType, DownloadURL: response.Output.Audio.URL}}}, nil
}

// decodeCosyVoiceSSE parses the exact blank-line-delimited Base64 audio stream.
// decodeCosyVoiceSSE 解析精确的空行分隔 Base64 音频流。
func decodeCosyVoiceSSE(ctx context.Context, reader io.Reader, sink provider.ExecutionResourceSink, mimeType string, maximumBytes *int64) ([]byte, error) {
	if reader == nil {
		return nil, fmt.Errorf("%w: CosyVoice stream is required", ErrInvalidSpeechResponse)
	}
	// outputLimit applies the shared 50 MiB safety ceiling unless the VCP request supplied a stricter explicit budget.
	// outputLimit 在 VCP 请求未提供更严格显式预算时应用共享的 50 MiB 安全上限。
	outputLimit := transport.MaximumNonStreamingResponseBytes
	if maximumBytes != nil {
		outputLimit = *maximumBytes
	}
	if outputLimit <= 0 {
		return nil, fmt.Errorf("%w: max_output_bytes must be positive", provider.ErrOutputBudgetExceeded)
	}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), maximumCosyVoiceSSELineBytes)
	dataLines := make([]string, 0, 1)
	var audio []byte
	terminal := false
	dispatch := func() error {
		if len(dataLines) == 0 {
			return nil
		}
		data := strings.Join(dataLines, "\n")
		dataLines = dataLines[:0]
		if data == "[DONE]" {
			terminal = true
			return nil
		}
		var frame cosyVoiceResponse
		if errDecode := json.Unmarshal([]byte(data), &frame); errDecode != nil {
			return fmt.Errorf("%w: decode CosyVoice stream frame: %v", ErrInvalidSpeechResponse, errDecode)
		}
		if frame.Output.Audio.Data != "" {
			chunk, errBase64 := base64.StdEncoding.DecodeString(frame.Output.Audio.Data)
			if errBase64 != nil || len(chunk) == 0 {
				return fmt.Errorf("%w: invalid CosyVoice Base64 audio chunk", ErrInvalidSpeechResponse)
			}
			if int64(len(audio)) > outputLimit-int64(len(chunk)) {
				return fmt.Errorf("%w: streamed output exceeds max_output_bytes", provider.ErrOutputBudgetExceeded)
			}
			audio = append(audio, chunk...)
			if sink != nil {
				if errEmit := sink.EmitResourceProgress(ctx, provider.ResourceProgress{OutputID: "audio-0", Kind: vcp.MediaAudio, MIMEType: mimeType, PartialBytes: int64(len(audio))}); errEmit != nil {
					return errEmit
				}
			}
		}
		if frame.Output.FinishReason != "" {
			if frame.Output.FinishReason != "stop" {
				return fmt.Errorf("%w: unexpected CosyVoice finish reason", ErrInvalidSpeechResponse)
			}
			terminal = true
		}
		return nil
	}
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if errDispatch := dispatch(); errDispatch != nil {
				return nil, errDispatch
			}
			if terminal {
				break
			}
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		field, value, found := strings.Cut(line, ":")
		if !found {
			return nil, fmt.Errorf("%w: malformed CosyVoice SSE field", ErrInvalidSpeechResponse)
		}
		if field == "data" {
			dataLines = append(dataLines, strings.TrimPrefix(value, " "))
		}
	}
	if errScan := scanner.Err(); errScan != nil {
		return nil, fmt.Errorf("%w: read CosyVoice stream: %v", ErrInvalidSpeechResponse, errScan)
	}
	if !terminal {
		if errDispatch := dispatch(); errDispatch != nil {
			return nil, errDispatch
		}
	}
	if !terminal || len(audio) == 0 {
		return nil, fmt.Errorf("%w: CosyVoice stream ended without terminal audio", ErrInvalidSpeechResponse)
	}
	return audio, nil
}

// cosyVoiceMIMEType maps one verified provider format to its output media type.
// cosyVoiceMIMEType 将一个已验证供应商格式映射到其输出媒体类型。
func cosyVoiceMIMEType(format string) string {
	switch format {
	case "mp3":
		return "audio/mpeg"
	case "pcm":
		return "audio/pcm"
	case "wav":
		return "audio/wav"
	case "opus":
		return "audio/opus"
	default:
		return ""
	}
}

// validCosyVoiceAudioURL reports whether one provider locator is an absolute credential-free HTTP URL.
// validCosyVoiceAudioURL 报告一个供应商定位符是否为绝对且不含凭据的 HTTP URL。
func validCosyVoiceAudioURL(rawURL string) bool {
	parsed, errParse := url.ParseRequestURI(strings.TrimSpace(rawURL))
	return errParse == nil && parsed.Host != "" && parsed.User == nil && (parsed.Scheme == "http" || parsed.Scheme == "https")
}
