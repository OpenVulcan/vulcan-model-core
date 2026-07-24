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

// Start submits one ordered public audio or video batch to Fun-ASR.
// Start 将一个有序公网音频或视频批次提交给 Fun-ASR。
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
	operation := execution.Execution.Payload.SpeechTranscribe
	expectedURLs, errSources := funASRSourceURLs(operation.OrderedSources(), execution.MaterializedInputs)
	if errSources != nil {
		return provider.TaskResult{}, errSources
	}
	files, observation, errDecode := decodeFunASRPoll(bounded, providerTaskID, execution.Now, expectedURLs)
	if errDecode != nil || observation.State != provider.TaskSucceeded {
		return observation, errDecode
	}
	sources := operation.OrderedSources()
	results := make([]vcp.TranscriptionResult, len(sources))
	successCount := 0
	for index := range files {
		results[index] = vcp.TranscriptionResult{InputID: sources[index].ID, ResourceID: sources[index].Resource.ResourceID}
		if files[index].Failed {
			results[index].ErrorCode = "transcription_failed"
			continue
		}
		content, errFetch := d.resultFetcher.FetchPublicDocument(ctx, files[index].TranscriptionURL, maximumFunASRResultBytes)
		if errFetch != nil {
			return provider.TaskResult{}, fmt.Errorf("%w: acquire transcription sidecar %d: %v", ErrInvalidSpeechResponse, index, errFetch)
		}
		transcript, errTranscript := decodeFunASRTranscript(bytes.NewReader(content), effectiveFunASRChannels(operation.ChannelIDs))
		if errTranscript != nil {
			return provider.TaskResult{}, errTranscript
		}
		results[index].Transcript = &transcript
		successCount++
	}
	if successCount == 0 {
		return provider.TaskResult{ProviderTaskID: providerTaskID, State: provider.TaskFailed, ErrorCode: "alibaba_transcription_failed"}, nil
	}
	result := provider.ExecutionResult{}
	if len(results) == 1 {
		result.Transcript = results[0].Transcript
	} else {
		result.Transcriptions = results
	}
	observation.Result = &result
	if successCount != len(results) {
		observation.State = provider.TaskPartiallySucceeded
	}
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
	// Input contains one ordered public file URL batch.
	// Input 包含一个有序公网文件 URL 批次。
	Input funASRInput `json:"input"`
	// Parameters contains only VCP-representable documented controls.
	// Parameters 仅包含 VCP 可表示且文档明确的控制项。
	Parameters funASRParameters `json:"parameters"`
}

// funASRInput contains the documented ordered URL batch.
// funASRInput 包含文档规定的有序 URL 批次。
type funASRInput struct {
	// FileURLs contains one through one hundred public or temporary OSS URLs.
	// FileURLs 包含一至一百个公网或临时 OSS URL。
	FileURLs []string `json:"file_urls"`
}

// funASRParameters contains documented offline recognition controls.
// funASRParameters 包含文档规定的离线识别控制项。
type funASRParameters struct {
	// ChannelID selects the ordered source channels to recognize.
	// ChannelID 选择要识别的有序源声道。
	ChannelID []int `json:"channel_id"`
	// LanguageHints contains at most one source language because the provider ignores extras.
	// LanguageHints 最多包含一种源语言，因为供应商会忽略额外值。
	LanguageHints []string `json:"language_hints,omitempty"`
	// DiarizationEnabled requests provider speaker labels.
	// DiarizationEnabled 请求供应商说话人标签。
	DiarizationEnabled bool `json:"diarization_enabled,omitempty"`
	// SpeakerCount supplies the expected count only with diarization.
	// SpeakerCount 仅在说话人分离时提供预期人数。
	SpeakerCount int `json:"speaker_count,omitempty"`
	// VocabularyID selects one provider-managed vocabulary instead of literal hotwords.
	// VocabularyID 选择一个供应商管理词表而不是字面热词。
	VocabularyID string `json:"vocabulary_id,omitempty"`
}

// projectFunASRStartRequest maps one closed VCP transcription request to the official task endpoint.
// projectFunASRStartRequest 将一个封闭 VCP 转写请求映射到官方任务端点。
func projectFunASRStartRequest(execution provider.ExecutionRequest) (transport.Request, error) {
	operation := execution.Execution.Payload.SpeechTranscribe
	if operation == nil {
		return transport.Request{}, fmt.Errorf("%w: Fun-ASR requires transcription input", ErrInvalidSpeechDriver)
	}
	sources := operation.OrderedSources()
	if len(sources) == 0 || len(sources) > 100 {
		return transport.Request{}, fmt.Errorf("%w: Fun-ASR requires one through 100 transcription sources", ErrInvalidSpeechDriver)
	}
	if operation.TranslationTarget != "" || operation.Prompt != "" || len(operation.Hotwords) != 0 || operation.SegmentTimestamps || operation.WordTimestamps || operation.CandidateCount > 1 {
		return transport.Request{}, fmt.Errorf("%w: translation, prompt, literal hotwords, timestamp switches, and alternatives have no Fun-ASR request carrier", ErrInvalidSpeechDriver)
	}
	if !supportedFunASRLanguage(operation.Language) {
		return transport.Request{}, fmt.Errorf("%w: unsupported Fun-ASR language", ErrInvalidSpeechDriver)
	}
	sourceURLs, errSources := funASRSourceURLs(sources, execution.MaterializedInputs)
	if errSources != nil {
		return transport.Request{}, errSources
	}
	languages := []string(nil)
	if operation.Language != "" {
		languages = []string{operation.Language}
	}
	body := funASRRequest{Model: execution.Binding.Target.UpstreamModelID, Input: funASRInput{FileURLs: sourceURLs}, Parameters: funASRParameters{ChannelID: effectiveFunASRChannels(operation.ChannelIDs), LanguageHints: languages, DiarizationEnabled: operation.Diarization, SpeakerCount: operation.SpeakerCount, VocabularyID: operation.VocabularyID}}
	encoded, errEncode := json.Marshal(body)
	if errEncode != nil {
		return transport.Request{}, fmt.Errorf("%w: encode Fun-ASR request: %v", ErrInvalidSpeechDriver, errEncode)
	}
	return transport.Request{Binding: execution.Binding, Method: http.MethodPost, Path: dashScopeTranscriptionPath, Body: encoded, Headers: alibabaJSONHeaders(execution.MaterializedInputs, true), Authentication: transport.Authentication{Mode: transport.AuthenticationBearer}, IdempotencyKey: execution.Execution.IdempotencyKey}, nil
}

// funASRSourceURLs validates exact input identities and returns unique provider-visible source locators in request order.
// funASRSourceURLs 校验精确输入身份，并按请求顺序返回唯一的供应商可见来源定位符。
func funASRSourceURLs(sources []vcp.MediaInput, materialized []resource.MaterializedInput) ([]string, error) {
	if len(materialized) != len(sources) {
		return nil, fmt.Errorf("%w: Fun-ASR materialized input count differs from sources", ErrInvalidSpeechDriver)
	}
	sourceURLs := make([]string, len(sources))
	seenURLs := make(map[string]struct{}, len(sources))
	for index := range sources {
		input := materialized[index]
		if input.InputID != sources[index].ID || input.ResourceID != sources[index].Resource.ResourceID || input.Kind != sources[index].Kind || input.Role != vcp.MediaRoleTranscriptionSource {
			return nil, fmt.Errorf("%w: Fun-ASR source %d has no exact materialization", ErrInvalidSpeechDriver, index)
		}
		resolvedURL, errResolve := funASRMaterialization(input)
		if errResolve != nil {
			return nil, errResolve
		}
		if _, duplicate := seenURLs[resolvedURL]; duplicate {
			return nil, fmt.Errorf("%w: Fun-ASR cannot correlate duplicate source locator at index %d", ErrInvalidSpeechDriver, index)
		}
		seenURLs[resolvedURL] = struct{}{}
		sourceURLs[index] = resolvedURL
	}
	return sourceURLs, nil
}

// funASRMaterialization converts one exact planned resource into a documented URL carrier.
// funASRMaterialization 将一个精确规划资源转换为文档规定的 URL 载体。
func funASRMaterialization(input resource.MaterializedInput) (string, error) {
	if input.Mode == catalog.MaterializationProviderObjectURI {
		return alibabaObjectURI(input, ErrInvalidSpeechDriver)
	}
	if input.Mode != catalog.MaterializationDirectRemoteURL {
		return "", fmt.Errorf("%w: Fun-ASR requires a direct remote URL or Alibaba object URI", ErrInvalidSpeechDriver)
	}
	parsed, errParse := url.ParseRequestURI(input.RemoteURL)
	if errParse != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil {
		return "", fmt.Errorf("%w: Fun-ASR source URL is invalid", ErrInvalidSpeechDriver)
	}
	return input.RemoteURL, nil
}

// effectiveFunASRChannels applies the provider-documented first-channel default without mutating the request.
// effectiveFunASRChannels 在不修改请求的情况下应用供应商文档规定的第一声道默认值。
func effectiveFunASRChannels(channelIDs []int) []int {
	if len(channelIDs) == 0 {
		return []int{0}
	}
	return append([]int(nil), channelIDs...)
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
	// Results contains one file subtask for every submitted source at success.
	// Results 在成功时为每个已提交来源包含一个文件子任务。
	Results []funASRTaskFile `json:"results"`
}

// funASRTaskFile contains one exact transcription sidecar locator.
// funASRTaskFile 包含一个精确转写 Sidecar 定位符。
type funASRTaskFile struct {
	// FileURL is the provider-echoed source locator used only to confirm a populated result entry.
	// FileURL 是供应商回显的来源定位符，仅用于确认结果条目已填充。
	FileURL string `json:"file_url"`
	// SubtaskStatus is the file-level terminal state.
	// SubtaskStatus 是文件级终态。
	SubtaskStatus string `json:"subtask_status"`
	// TranscriptionURL is the temporary public JSON sidecar.
	// TranscriptionURL 是临时公网 JSON Sidecar。
	TranscriptionURL string `json:"transcription_url"`
	// Code is the provider file-level code retained only for failure classification.
	// Code 是仅用于失败分类的供应商文件级代码。
	Code string `json:"code"`
}

// funASRResolvedFile contains one ordered safe task-sidecar decision.
// funASRResolvedFile 包含一个有序且安全的任务 Sidecar 决策。
type funASRResolvedFile struct {
	// TranscriptionURL is present only for one successful file.
	// TranscriptionURL 仅在一个成功文件上存在。
	TranscriptionURL string
	// Failed records a provider-confirmed file failure without leaking its message.
	// Failed 记录供应商确认的文件失败且不泄露其消息。
	Failed bool
}

// decodeFunASRStart decodes one successful queued task.
// decodeFunASRStart 解码一个成功排队的任务。
func decodeFunASRStart(reader io.Reader, now time.Time) (provider.TaskResult, error) {
	var response funASRTaskResponse
	if errDecode := decodeAlibabaJSONResponse(reader, &response, ErrInvalidSpeechResponse); errDecode != nil {
		return provider.TaskResult{}, errDecode
	}
	if strings.TrimSpace(response.Output.TaskID) == "" || strings.TrimSpace(response.Output.TaskID) != response.Output.TaskID || response.Output.TaskStatus != "PENDING" {
		return provider.TaskResult{}, fmt.Errorf("%w: malformed Fun-ASR task creation", ErrInvalidSpeechResponse)
	}
	return provider.TaskResult{ProviderTaskID: response.Output.TaskID, State: provider.TaskQueued, PollAfter: now.UTC().Add(funASRPollInterval)}, nil
}

// decodeFunASRPoll maps one documented provider observation without exposing its result URL.
// decodeFunASRPoll 映射一个文档规定的供应商观测且不暴露其结果 URL。
func decodeFunASRPoll(reader io.Reader, providerTaskID string, now time.Time, expectedURLs []string) ([]funASRResolvedFile, provider.TaskResult, error) {
	var response funASRTaskResponse
	if errDecode := decodeAlibabaJSONResponse(reader, &response, ErrInvalidSpeechResponse); errDecode != nil {
		return nil, provider.TaskResult{}, errDecode
	}
	if response.Output.TaskID != providerTaskID || len(expectedURLs) == 0 {
		return nil, provider.TaskResult{}, fmt.Errorf("%w: malformed Fun-ASR task observation", ErrInvalidSpeechResponse)
	}
	switch response.Output.TaskStatus {
	case "PENDING":
		return nil, provider.TaskResult{ProviderTaskID: providerTaskID, State: provider.TaskQueued, PollAfter: now.UTC().Add(funASRPollInterval)}, nil
	case "RUNNING":
		return nil, provider.TaskResult{ProviderTaskID: providerTaskID, State: provider.TaskRunning, PollAfter: now.UTC().Add(funASRPollInterval)}, nil
	case "FAILED", "UNKNOWN":
		return nil, provider.TaskResult{ProviderTaskID: providerTaskID, State: provider.TaskFailed, ErrorCode: "alibaba_transcription_failed"}, nil
	case "SUCCEEDED":
		if len(response.Output.Results) != len(expectedURLs) {
			return nil, provider.TaskResult{}, fmt.Errorf("%w: Fun-ASR task result count differs from request", ErrInvalidSpeechResponse)
		}
		expectedIndex := make(map[string]int, len(expectedURLs))
		for index, expectedURL := range expectedURLs {
			if strings.TrimSpace(expectedURL) == "" {
				return nil, provider.TaskResult{}, fmt.Errorf("%w: Fun-ASR expected source locator is empty", ErrInvalidSpeechResponse)
			}
			if _, duplicate := expectedIndex[expectedURL]; duplicate {
				return nil, provider.TaskResult{}, fmt.Errorf("%w: Fun-ASR expected source locator is ambiguous", ErrInvalidSpeechResponse)
			}
			expectedIndex[expectedURL] = index
		}
		resolved := make([]funASRResolvedFile, len(response.Output.Results))
		seenResults := make(map[string]struct{}, len(response.Output.Results))
		for _, file := range response.Output.Results {
			index, expected := expectedIndex[file.FileURL]
			if !expected {
				return nil, provider.TaskResult{}, fmt.Errorf("%w: Fun-ASR returned an unknown source locator", ErrInvalidSpeechResponse)
			}
			if _, duplicate := seenResults[file.FileURL]; duplicate {
				return nil, provider.TaskResult{}, fmt.Errorf("%w: Fun-ASR returned a duplicate source locator", ErrInvalidSpeechResponse)
			}
			seenResults[file.FileURL] = struct{}{}
			switch file.SubtaskStatus {
			case "SUCCEEDED":
				if strings.TrimSpace(file.TranscriptionURL) == "" {
					return nil, provider.TaskResult{}, fmt.Errorf("%w: successful Fun-ASR file lacks transcription URL", ErrInvalidSpeechResponse)
				}
				resolved[index].TranscriptionURL = file.TranscriptionURL
			case "FAILED":
				resolved[index].Failed = true
			default:
				return nil, provider.TaskResult{}, fmt.Errorf("%w: unknown Fun-ASR file status %q", ErrInvalidSpeechResponse, file.SubtaskStatus)
			}
		}
		return resolved, provider.TaskResult{ProviderTaskID: providerTaskID, State: provider.TaskSucceeded}, nil
	default:
		return nil, provider.TaskResult{}, fmt.Errorf("%w: unknown Fun-ASR task status %q", ErrInvalidSpeechResponse, response.Output.TaskStatus)
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
func decodeFunASRTranscript(reader io.Reader, channelIDs []int) (vcp.Transcript, error) {
	var document funASRTranscriptDocument
	if errDecode := decodeAlibabaJSONResponse(reader, &document, ErrInvalidSpeechResponse); errDecode != nil {
		return vcp.Transcript{}, errDecode
	}
	if document.Properties.OriginalDurationMilliseconds < 0 || len(channelIDs) == 0 || len(document.Transcripts) != len(channelIDs) {
		return vcp.Transcript{}, fmt.Errorf("%w: malformed Fun-ASR result document", ErrInvalidSpeechResponse)
	}
	candidates := make([]vcp.TranscriptCandidate, len(document.Transcripts))
	for transcriptIndex, providerTranscript := range document.Transcripts {
		if providerTranscript.ChannelID != channelIDs[transcriptIndex] {
			return vcp.Transcript{}, fmt.Errorf("%w: Fun-ASR result channel order differs from request", ErrInvalidSpeechResponse)
		}
		candidateID := "channel-" + strconv.Itoa(providerTranscript.ChannelID)
		channelID := providerTranscript.ChannelID
		segments := make([]vcp.TranscriptSegment, 0, len(providerTranscript.Sentences))
		for _, sentence := range providerTranscript.Sentences {
			start, end := sentence.BeginTime, sentence.EndTime
			segment := vcp.TranscriptSegment{CandidateID: candidateID, SegmentID: candidateID + "-segment-" + strconv.Itoa(sentence.SentenceID), Text: sentence.Text, StartMilliseconds: &start, EndMilliseconds: &end}
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
		candidates[transcriptIndex] = vcp.TranscriptCandidate{CandidateID: candidateID, ChannelID: &channelID, Text: providerTranscript.Text, Segments: segments}
	}
	duration := document.Properties.OriginalDurationMilliseconds
	transcript := vcp.Transcript{DurationMilliseconds: &duration, Candidates: candidates}
	if errValidate := transcript.Validate(); errValidate != nil {
		return vcp.Transcript{}, fmt.Errorf("%w: %v", ErrInvalidSpeechResponse, errValidate)
	}
	return transcript, nil
}
