package alibaba

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/dependency"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

const (
	// SpeechTranscribeAsyncActionBindingID identifies Fun-ASR offline transcription.
	// SpeechTranscribeAsyncActionBindingID 标识 Fun-ASR 离线转写。
	SpeechTranscribeAsyncActionBindingID = "action_alibaba_fun_asr_transcribe"
	// SpeechTranscribeAsyncProtocolProfileID identifies the closed Fun-ASR task contract.
	// SpeechTranscribeAsyncProtocolProfileID 标识封闭的 Fun-ASR 任务合同。
	SpeechTranscribeAsyncProtocolProfileID = "alibaba.fun-asr.transcribe.v1"
	// dashScopeTranscriptionPath is the documented asynchronous submission endpoint.
	// dashScopeTranscriptionPath 是文档规定的异步提交端点。
	dashScopeTranscriptionPath = "/api/v1/services/audio/asr/transcription"
	// funASRPollInterval avoids exceeding the documented query service under normal polling.
	// funASRPollInterval 在正常轮询下避免超过文档规定的查询服务限制。
	funASRPollInterval = 2 * time.Second
	// maximumFunASRResultBytes bounds the provider JSON sidecar independently from media size.
	// maximumFunASRResultBytes 独立于媒体大小限制供应商 JSON Sidecar。
	maximumFunASRResultBytes = 16 << 20
)

// SpeechTaskDriver executes one immutable Fun-ASR asynchronous transcription action.
// SpeechTaskDriver 执行一个不可变的 Fun-ASR 异步转写动作。
type SpeechTaskDriver struct {
	// definitionID fixes the sole owning provider definition.
	// definitionID 固定唯一所属供应商 Definition。
	definitionID string
	// client owns authenticated provider-scoped task requests.
	// client 负责经过认证且限定供应商作用域的任务请求。
	client *transport.Client
	// resultFetcher securely acquires the public result sidecar without credentials.
	// resultFetcher 安全获取公网结果 Sidecar 且不携带凭据。
	resultFetcher resource.PublicDocumentFetcher
}

// NewSpeechTaskDriver creates one Fun-ASR asynchronous transcription driver.
// NewSpeechTaskDriver 创建一个 Fun-ASR 异步转写 Driver。
func NewSpeechTaskDriver(definitionID string, client *transport.Client, resultFetcher resource.PublicDocumentFetcher) (*SpeechTaskDriver, error) {
	if strings.TrimSpace(definitionID) == "" || client == nil || dependency.IsNil(resultFetcher) {
		return nil, ErrInvalidSpeechDriver
	}
	return &SpeechTaskDriver{definitionID: definitionID, client: client, resultFetcher: resultFetcher}, nil
}

// ProviderDefinitionID returns the sole provider definition owned by this driver.
// ProviderDefinitionID 返回此 Driver 唯一所属的供应商 Definition。
func (d *SpeechTaskDriver) ProviderDefinitionID() string {
	if d == nil {
		return ""
	}
	return d.definitionID
}

// ActionBindingID returns the exact Fun-ASR task action.
// ActionBindingID 返回精确的 Fun-ASR 任务动作。
func (d *SpeechTaskDriver) ActionBindingID() string {
	return SpeechTranscribeAsyncActionBindingID
}

// Start submits one exact public audio or video URL to Fun-ASR.
// Start 将一个精确公网音频或视频 URL 提交给 Fun-ASR。
func (d *SpeechTaskDriver) Start(ctx context.Context, execution provider.ExecutionRequest) (provider.TaskResult, error) {
	if errValidate := d.validateExecution(execution); errValidate != nil {
		return provider.TaskResult{}, errValidate
	}
	outbound, errProject := projectFunASRStartRequest(execution)
	if errProject != nil {
		return provider.TaskResult{}, errProject
	}
	response, errRequest := d.client.Do(ctx, outbound)
	if errRequest != nil {
		return provider.TaskResult{}, errRequest
	}
	defer func() { _ = transport.DrainAndClose(response) }()
	bounded, errBound := transport.NewBoundedResponseReader(response.Body, transport.MaximumNonStreamingResponseBytes)
	if errBound != nil {
		return provider.TaskResult{}, fmt.Errorf("%w: bound start response: %v", ErrInvalidSpeechResponse, errBound)
	}
	return decodeFunASRStart(bounded, execution.Now)
}

// Poll observes one exact provider task and securely converts its JSON sidecar to VCP Transcript.
// Poll 观察一个精确供应商任务并安全地将其 JSON Sidecar 转换为 VCP Transcript。
func (d *SpeechTaskDriver) Poll(ctx context.Context, execution provider.ExecutionRequest, providerTaskID string) (provider.TaskResult, error) {
	if errValidate := d.validateExecution(execution); errValidate != nil {
		return provider.TaskResult{}, errValidate
	}
	if strings.TrimSpace(providerTaskID) == "" || strings.TrimSpace(providerTaskID) != providerTaskID {
		return provider.TaskResult{}, fmt.Errorf("%w: provider task identifier is invalid", ErrInvalidSpeechDriver)
	}
	outbound := transport.Request{Binding: execution.Binding, Method: http.MethodGet, Path: "/api/v1/tasks/" + url.PathEscape(providerTaskID), Headers: []transport.Header{{Name: "Content-Type", Value: "application/json"}}, Authentication: transport.Authentication{Mode: transport.AuthenticationBearer}}
	response, errRequest := d.client.Do(ctx, outbound)
	if errRequest != nil {
		return provider.TaskResult{}, errRequest
	}
	defer func() { _ = transport.DrainAndClose(response) }()
	bounded, errBound := transport.NewBoundedResponseReader(response.Body, transport.MaximumNonStreamingResponseBytes)
	if errBound != nil {
		return provider.TaskResult{}, fmt.Errorf("%w: bound poll response: %v", ErrInvalidSpeechResponse, errBound)
	}
	observation, transcriptionURL, errDecode := decodeFunASRPoll(bounded, providerTaskID, execution.Now)
	if errDecode != nil || observation.State != provider.TaskSucceeded {
		return observation, errDecode
	}
	content, errFetch := d.resultFetcher.FetchPublicDocument(ctx, transcriptionURL, maximumFunASRResultBytes)
	if errFetch != nil {
		return provider.TaskResult{}, fmt.Errorf("%w: acquire transcription sidecar: %v", ErrInvalidSpeechResponse, errFetch)
	}
	transcript, errTranscript := decodeFunASRTranscript(bytes.NewReader(content))
	if errTranscript != nil {
		return provider.TaskResult{}, errTranscript
	}
	result := provider.ExecutionResult{Transcript: &transcript}
	observation.Result = &result
	return observation, nil
}

// Cancel reports the documented lack of a Fun-ASR cancellation endpoint.
// Cancel 报告 Fun-ASR 缺少文档化取消端点。
func (d *SpeechTaskDriver) Cancel(context.Context, provider.ExecutionRequest, string) (provider.TaskResult, error) {
	return provider.TaskResult{}, fmt.Errorf("%w: Fun-ASR task cancellation is unsupported", ErrInvalidSpeechDriver)
}

// validateExecution verifies immutable ownership and action binding before network traffic.
// validateExecution 在网络请求前校验不可变归属与动作绑定。
func (d *SpeechTaskDriver) validateExecution(execution provider.ExecutionRequest) error {
	if d == nil || d.client == nil || dependency.IsNil(d.resultFetcher) || execution.Binding.Target.ProviderDefinitionID != d.definitionID {
		return fmt.Errorf("%w: target definition does not belong to this driver", provider.ErrExecutionBinding)
	}
	_, errValidate := execution.ValidateForAction(SpeechTranscribeAsyncActionBindingID, providerconfig.AuthMethodAPIKey)
	return errValidate
}

// funASRRequest is the official asynchronous file transcription body.
// funASRRequest 是官方异步文件转写正文。
type funASRRequest struct {
	// Model is fixed by the resolved offering.
	// Model 由已解析 Offering 固定。
	Model string `json:"model"`
	// Input contains exactly one public file URL.
	// Input 包含恰好一个公网文件 URL。
	Input funASRInput `json:"input"`
	// Parameters contains only VCP-representable documented controls.
	// Parameters 仅包含 VCP 可表示且文档明确的控制项。
	Parameters funASRParameters `json:"parameters"`
}

// funASRInput contains the documented one-element URL array.
// funASRInput 包含文档规定的单元素 URL 数组。
type funASRInput struct {
	// FileURLs contains exactly one public HTTP or HTTPS URL.
	// FileURLs 包含恰好一个公网 HTTP 或 HTTPS URL。
	FileURLs []string `json:"file_urls"`
}

// funASRParameters contains documented offline recognition controls.
// funASRParameters 包含文档规定的离线识别控制项。
type funASRParameters struct {
	// ChannelID fixes recognition to the first channel to preserve one VCP candidate.
	// ChannelID 固定识别第一声道以保留一个 VCP Candidate。
	ChannelID []int `json:"channel_id"`
	// LanguageHints contains at most one source language because the provider ignores extras.
	// LanguageHints 最多包含一种源语言，因为供应商会忽略额外值。
	LanguageHints []string `json:"language_hints,omitempty"`
	// DiarizationEnabled requests provider speaker labels.
	// DiarizationEnabled 请求供应商说话人标签。
	DiarizationEnabled bool `json:"diarization_enabled,omitempty"`
}

// projectFunASRStartRequest maps one closed VCP transcription request to the official task endpoint.
// projectFunASRStartRequest 将一个封闭 VCP 转写请求映射到官方任务端点。
func projectFunASRStartRequest(execution provider.ExecutionRequest) (transport.Request, error) {
	operation := execution.Execution.Payload.SpeechTranscribe
	if operation == nil || operation.Source.Resource.ResourceID == "" || operation.Source.Role != vcp.MediaRoleTranscriptionSource || (operation.Source.Kind != vcp.MediaAudio && operation.Source.Kind != vcp.MediaVideo) {
		return transport.Request{}, fmt.Errorf("%w: Fun-ASR requires one audio or video transcription source", ErrInvalidSpeechDriver)
	}
	if operation.TranslationTarget != "" || operation.Prompt != "" || len(operation.Hotwords) != 0 || operation.CandidateCount > 1 {
		return transport.Request{}, fmt.Errorf("%w: translation, prompt, literal hotwords, and alternatives have no Fun-ASR carrier", ErrInvalidSpeechDriver)
	}
	if !supportedFunASRLanguage(operation.Language) {
		return transport.Request{}, fmt.Errorf("%w: unsupported Fun-ASR language", ErrInvalidSpeechDriver)
	}
	if len(execution.MaterializedInputs) != 1 {
		return transport.Request{}, fmt.Errorf("%w: Fun-ASR requires one exact materialized input", ErrInvalidSpeechDriver)
	}
	input := execution.MaterializedInputs[0]
	if input.InputID != operation.Source.ID || input.ResourceID != operation.Source.Resource.ResourceID || input.Kind != operation.Source.Kind || input.Role != vcp.MediaRoleTranscriptionSource || input.Mode != catalog.MaterializationDirectRemoteURL {
		return transport.Request{}, fmt.Errorf("%w: Fun-ASR requires the exact direct remote URL materialization", ErrInvalidSpeechDriver)
	}
	parsed, errParse := url.ParseRequestURI(input.RemoteURL)
	if errParse != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil {
		return transport.Request{}, fmt.Errorf("%w: Fun-ASR source URL is invalid", ErrInvalidSpeechDriver)
	}
	languages := []string(nil)
	if operation.Language != "" {
		languages = []string{operation.Language}
	}
	body := funASRRequest{Model: execution.Binding.Target.UpstreamModelID, Input: funASRInput{FileURLs: []string{input.RemoteURL}}, Parameters: funASRParameters{ChannelID: []int{0}, LanguageHints: languages, DiarizationEnabled: operation.Diarization}}
	encoded, errEncode := json.Marshal(body)
	if errEncode != nil {
		return transport.Request{}, fmt.Errorf("%w: encode Fun-ASR request: %v", ErrInvalidSpeechDriver, errEncode)
	}
	return transport.Request{Binding: execution.Binding, Method: http.MethodPost, Path: dashScopeTranscriptionPath, Body: encoded, Headers: []transport.Header{{Name: "Content-Type", Value: "application/json"}, {Name: "X-DashScope-Async", Value: "enable"}}, Authentication: transport.Authentication{Mode: transport.AuthenticationBearer}, IdempotencyKey: execution.Execution.IdempotencyKey}, nil
}

// supportedFunASRLanguage reports the current stable Fun-ASR language hints.
// supportedFunASRLanguage 报告当前稳定版 Fun-ASR 的语言提示。
func supportedFunASRLanguage(language string) bool {
	switch language {
	case "", "zh", "en", "ja", "ko", "vi", "th", "id", "ms", "tl", "hi", "ar", "fr", "de", "es", "pt", "ru", "it", "nl", "sv", "da", "fi", "no", "el", "pl", "cs", "hu", "ro", "bg", "hr", "sk":
		return true
	default:
		return false
	}
}

// funASRTaskResponse is the closed common task response envelope.
// funASRTaskResponse 是封闭的通用任务响应信封。
type funASRTaskResponse struct {
	// RequestID is the provider-issued request identifier.
	// RequestID 是供应商签发的请求标识。
	RequestID string `json:"request_id"`
	// Output contains task state and final result URL.
	// Output 包含任务状态及最终结果 URL。
	Output funASRTaskOutput `json:"output"`
}

// funASRTaskOutput contains one provider task observation.
// funASRTaskOutput 包含一个供应商任务观测。
type funASRTaskOutput struct {
	// TaskID is the private provider identifier.
	// TaskID 是私有供应商标识。
	TaskID string `json:"task_id"`
	// TaskStatus is the documented uppercase state.
	// TaskStatus 是文档规定的大写状态。
	TaskStatus string `json:"task_status"`
	// Results contains exactly one file subtask at success.
	// Results 在成功时包含恰好一个文件子任务。
	Results []funASRTaskFile `json:"results"`
}

// funASRTaskFile contains one exact transcription sidecar locator.
// funASRTaskFile 包含一个精确转写 Sidecar 定位符。
type funASRTaskFile struct {
	// SubtaskStatus is the file-level terminal state.
	// SubtaskStatus 是文件级终态。
	SubtaskStatus string `json:"subtask_status"`
	// TranscriptionURL is the temporary public JSON sidecar.
	// TranscriptionURL 是临时公网 JSON Sidecar。
	TranscriptionURL string `json:"transcription_url"`
}

// decodeFunASRStart decodes one successful queued task.
// decodeFunASRStart 解码一个成功排队的任务。
func decodeFunASRStart(reader io.Reader, now time.Time) (provider.TaskResult, error) {
	var response funASRTaskResponse
	if errDecode := json.NewDecoder(reader).Decode(&response); errDecode != nil || strings.TrimSpace(response.Output.TaskID) == "" || response.Output.TaskStatus != "PENDING" {
		return provider.TaskResult{}, fmt.Errorf("%w: malformed Fun-ASR task creation", ErrInvalidSpeechResponse)
	}
	return provider.TaskResult{ProviderTaskID: response.Output.TaskID, State: provider.TaskQueued, PollAfter: now.UTC().Add(funASRPollInterval)}, nil
}

// decodeFunASRPoll maps one documented provider observation without exposing its result URL.
// decodeFunASRPoll 映射一个文档规定的供应商观测且不暴露其结果 URL。
func decodeFunASRPoll(reader io.Reader, providerTaskID string, now time.Time) (provider.TaskResult, string, error) {
	var response funASRTaskResponse
	if errDecode := json.NewDecoder(reader).Decode(&response); errDecode != nil || response.Output.TaskID != providerTaskID {
		return provider.TaskResult{}, "", fmt.Errorf("%w: malformed Fun-ASR task observation", ErrInvalidSpeechResponse)
	}
	switch response.Output.TaskStatus {
	case "PENDING":
		return provider.TaskResult{ProviderTaskID: providerTaskID, State: provider.TaskQueued, PollAfter: now.UTC().Add(funASRPollInterval)}, "", nil
	case "RUNNING":
		return provider.TaskResult{ProviderTaskID: providerTaskID, State: provider.TaskRunning, PollAfter: now.UTC().Add(funASRPollInterval)}, "", nil
	case "FAILED", "UNKNOWN":
		return provider.TaskResult{ProviderTaskID: providerTaskID, State: provider.TaskFailed, ErrorCode: "alibaba_transcription_failed"}, "", nil
	case "SUCCEEDED":
		if len(response.Output.Results) != 1 || response.Output.Results[0].SubtaskStatus != "SUCCEEDED" || strings.TrimSpace(response.Output.Results[0].TranscriptionURL) == "" {
			return provider.TaskResult{ProviderTaskID: providerTaskID, State: provider.TaskFailed, ErrorCode: "alibaba_transcription_failed"}, "", nil
		}
		return provider.TaskResult{ProviderTaskID: providerTaskID, State: provider.TaskSucceeded}, response.Output.Results[0].TranscriptionURL, nil
	default:
		return provider.TaskResult{}, "", fmt.Errorf("%w: unknown Fun-ASR task status %q", ErrInvalidSpeechResponse, response.Output.TaskStatus)
	}
}

// funASRTranscriptDocument is the official downloadable recognition result.
// funASRTranscriptDocument 是官方可下载识别结果。
type funASRTranscriptDocument struct {
	// Properties contains provider-confirmed source metadata.
	// Properties 包含供应商确认的来源元数据。
	Properties funASRProperties `json:"properties"`
	// Transcripts contains the requested first-channel recognition.
	// Transcripts 包含请求的第一声道识别结果。
	Transcripts []funASRTranscript `json:"transcripts"`
}

// funASRProperties contains source duration metadata.
// funASRProperties 包含来源时长元数据。
type funASRProperties struct {
	// OriginalDurationMilliseconds is the exact source duration.
	// OriginalDurationMilliseconds 是精确来源时长。
	OriginalDurationMilliseconds int64 `json:"original_duration_in_milliseconds"`
}

// funASRTranscript contains one requested channel transcript.
// funASRTranscript 包含一个请求声道转写。
type funASRTranscript struct {
	// ChannelID is zero because the request fixes the first channel.
	// ChannelID 为零，因为请求固定第一声道。
	ChannelID int `json:"channel_id"`
	// Text is the complete paragraph-level transcript.
	// Text 是完整段落级转写。
	Text string `json:"text"`
	// Sentences contains ordered provider segments.
	// Sentences 包含有序供应商分段。
	Sentences []funASRSentence `json:"sentences"`
}

// funASRSentence contains one provider-confirmed sentence and timings.
// funASRSentence 包含一个供应商确认的句子及时间。
type funASRSentence struct {
	// SentenceID is the provider sentence sequence.
	// SentenceID 是供应商句子序号。
	SentenceID int `json:"sentence_id"`
	// BeginTime is the inclusive millisecond offset.
	// BeginTime 是包含端点的毫秒偏移。
	BeginTime int64 `json:"begin_time"`
	// EndTime is the exclusive millisecond offset.
	// EndTime 是不包含端点的毫秒偏移。
	EndTime int64 `json:"end_time"`
	// Text is the sentence transcript.
	// Text 是句子转写。
	Text string `json:"text"`
	// SpeakerID is present only when diarization produced a label.
	// SpeakerID 仅在说话人分离产生标签时存在。
	SpeakerID *int `json:"speaker_id,omitempty"`
	// Words contains ordered word-level timings.
	// Words 包含有序词级时间。
	Words []funASRWord `json:"words"`
}

// funASRWord contains one provider-confirmed token and punctuation.
// funASRWord 包含一个供应商确认的词元及标点。
type funASRWord struct {
	// BeginTime is the inclusive millisecond offset.
	// BeginTime 是包含端点的毫秒偏移。
	BeginTime int64 `json:"begin_time"`
	// EndTime is the exclusive millisecond offset.
	// EndTime 是不包含端点的毫秒偏移。
	EndTime int64 `json:"end_time"`
	// Text is the recognized word text.
	// Text 是识别词文本。
	Text string `json:"text"`
	// Punctuation is the provider-predicted suffix.
	// Punctuation 是供应商预测的后缀标点。
	Punctuation string `json:"punctuation"`
}

// decodeFunASRTranscript converts exact provider segments and words without inferring missing facts.
// decodeFunASRTranscript 转换精确供应商分段与词元且不推断缺失事实。
func decodeFunASRTranscript(reader io.Reader) (vcp.Transcript, error) {
	var document funASRTranscriptDocument
	if errDecode := json.NewDecoder(reader).Decode(&document); errDecode != nil || document.Properties.OriginalDurationMilliseconds < 0 || len(document.Transcripts) != 1 || document.Transcripts[0].ChannelID != 0 {
		return vcp.Transcript{}, fmt.Errorf("%w: malformed Fun-ASR result document", ErrInvalidSpeechResponse)
	}
	providerTranscript := document.Transcripts[0]
	segments := make([]vcp.TranscriptSegment, 0, len(providerTranscript.Sentences))
	for _, sentence := range providerTranscript.Sentences {
		start, end := sentence.BeginTime, sentence.EndTime
		segment := vcp.TranscriptSegment{CandidateID: "candidate-0", SegmentID: "segment-" + strconv.Itoa(sentence.SentenceID), Text: sentence.Text, StartMilliseconds: &start, EndMilliseconds: &end}
		if sentence.SpeakerID != nil {
			segment.Speaker = strconv.Itoa(*sentence.SpeakerID)
		}
		segment.Words = make([]vcp.TranscriptWord, 0, len(sentence.Words))
		for _, providerWord := range sentence.Words {
			wordStart, wordEnd := providerWord.BeginTime, providerWord.EndTime
			segment.Words = append(segment.Words, vcp.TranscriptWord{Text: providerWord.Text + providerWord.Punctuation, StartMilliseconds: &wordStart, EndMilliseconds: &wordEnd, Speaker: segment.Speaker})
		}
		segments = append(segments, segment)
	}
	duration := document.Properties.OriginalDurationMilliseconds
	transcript := vcp.Transcript{DurationMilliseconds: &duration, Candidates: []vcp.TranscriptCandidate{{CandidateID: "candidate-0", Text: providerTranscript.Text, Segments: segments}}}
	if errValidate := transcript.Validate(); errValidate != nil {
		return vcp.Transcript{}, fmt.Errorf("%w: %v", ErrInvalidSpeechResponse, errValidate)
	}
	return transcript, nil
}
