package alibaba

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestFunASRTaskLifecyclePreservesTypedTranscript verifies the exact asynchronous request, task identity, and typed result conversion.
// TestFunASRTaskLifecyclePreservesTypedTranscript 验证精确异步请求、任务身份及类型化结果转换。
func TestFunASRTaskLifecyclePreservesTypedTranscript(t *testing.T) {
	fetcher := &recordingPublicDocumentFetcher{content: []byte(`{"properties":{"original_duration_in_milliseconds":1800},"transcripts":[{"channel_id":0,"text":"Hello, Vulcan.","sentences":[{"sentence_id":7,"begin_time":0,"end_time":1800,"text":"Hello, Vulcan.","speaker_id":2,"words":[{"begin_time":0,"end_time":700,"text":"Hello","punctuation":","},{"begin_time":800,"end_time":1800,"text":"Vulcan","punctuation":"."}]}]}]}`)}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodPost && request.URL.Path == dashScopeTranscriptionPath:
			if request.Header.Get("X-DashScope-Async") != "enable" || request.Header.Get("Authorization") != "Bearer test-secret" {
				t.Errorf("start headers = %#v", request.Header)
			}
			var upstream funASRRequest
			if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil {
				t.Errorf("decode start request: %v", errDecode)
			}
			if upstream.Model != "fun-asr" || len(upstream.Input.FileURLs) != 1 || upstream.Input.FileURLs[0] != "https://media.example/source.mp4" || len(upstream.Parameters.ChannelID) != 1 || upstream.Parameters.ChannelID[0] != 0 || len(upstream.Parameters.LanguageHints) != 1 || upstream.Parameters.LanguageHints[0] != "en" || !upstream.Parameters.DiarizationEnabled {
				t.Errorf("start request = %#v", upstream)
			}
			_, _ = io.WriteString(writer, `{"request_id":"request-start","output":{"task_id":"task-123","task_status":"PENDING"}}`)
		case request.Method == http.MethodGet && request.URL.Path == "/api/v1/tasks/task-123":
			_, _ = io.WriteString(writer, `{"request_id":"request-poll","output":{"task_id":"task-123","task_status":"SUCCEEDED","results":[{"file_url":"https://media.example/source.mp4","subtask_status":"SUCCEEDED","transcription_url":"https://results.example/task-123.json"}]}}`)
		default:
			t.Errorf("unexpected request = %s %s", request.Method, request.URL.Path)
			http.Error(writer, "unexpected", http.StatusNotFound)
		}
	}))
	defer server.Close()

	driver, execution := newAlibabaSpeechTaskExecution(t, server.URL, fetcher)
	started, errStart := driver.Start(context.Background(), execution)
	if errStart != nil || started.ProviderTaskID != "task-123" || started.State != provider.TaskQueued {
		t.Fatalf("Start() = %#v, error = %v", started, errStart)
	}
	polled, errPoll := driver.Poll(context.Background(), execution, started.ProviderTaskID)
	if errPoll != nil || polled.State != provider.TaskSucceeded || polled.Result == nil || polled.Result.Transcript == nil {
		t.Fatalf("Poll() = %#v, error = %v", polled, errPoll)
	}
	transcript := polled.Result.Transcript
	if fetcher.requestedURL != "https://results.example/task-123.json" || fetcher.maximumBytes != maximumFunASRResultBytes || transcript.DurationMilliseconds == nil || *transcript.DurationMilliseconds != 1800 || len(transcript.Candidates) != 1 || len(transcript.Candidates[0].Segments) != 1 {
		t.Fatalf("fetcher = %#v, transcript = %#v", fetcher, transcript)
	}
	segment := transcript.Candidates[0].Segments[0]
	if transcript.Candidates[0].ChannelID == nil || *transcript.Candidates[0].ChannelID != 0 || segment.SegmentID != "channel-0-segment-7" || segment.Speaker != "2" || len(segment.Words) != 2 || segment.Words[0].Text != "Hello," || segment.Words[1].Text != "Vulcan." {
		t.Fatalf("segment = %#v", segment)
	}
}

// TestFunASRBatchPreservesInputOwnershipChannelsAndPartialFailure verifies exact request order and typed per-source results.
// TestFunASRBatchPreservesInputOwnershipChannelsAndPartialFailure 验证精确请求顺序及类型化逐来源结果。
func TestFunASRBatchPreservesInputOwnershipChannelsAndPartialFailure(t *testing.T) {
	fetcher := &recordingPublicDocumentFetcher{content: []byte(`{"properties":{"original_duration_in_milliseconds":1800},"transcripts":[{"channel_id":0,"text":"left","sentences":[]},{"channel_id":1,"text":"right","sentences":[]}]}`)}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodPost && request.URL.Path == dashScopeTranscriptionPath:
			var upstream funASRRequest
			if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil {
				t.Errorf("decode start request: %v", errDecode)
			}
			if len(upstream.Input.FileURLs) != 2 || upstream.Input.FileURLs[0] != "https://media.example/first.wav" || upstream.Input.FileURLs[1] != "oss://dashscope-temp/second.wav" || len(upstream.Parameters.ChannelID) != 2 || upstream.Parameters.ChannelID[0] != 0 || upstream.Parameters.ChannelID[1] != 1 || upstream.Parameters.SpeakerCount != 2 || upstream.Parameters.VocabularyID != "vocabulary-1" {
				t.Errorf("start request = %#v", upstream)
			}
			_, _ = io.WriteString(writer, `{"request_id":"request-start","output":{"task_id":"task-batch","task_status":"PENDING"}}`)
		case request.Method == http.MethodGet && request.URL.Path == "/api/v1/tasks/task-batch":
			_, _ = io.WriteString(writer, `{"request_id":"request-poll","output":{"task_id":"task-batch","task_status":"SUCCEEDED","results":[{"file_url":"oss://dashscope-temp/second.wav","subtask_status":"FAILED","code":"provider-private-code"},{"file_url":"https://media.example/first.wav","subtask_status":"SUCCEEDED","transcription_url":"https://results.example/first.json"}]}}`)
		default:
			t.Errorf("unexpected request = %s %s", request.Method, request.URL.Path)
			http.Error(writer, "unexpected", http.StatusNotFound)
		}
	}))
	defer server.Close()
	driver, execution := newAlibabaSpeechTaskExecution(t, server.URL, fetcher)
	execution.Execution.Payload.SpeechTranscribe = &vcp.SpeechTranscribeOperation{
		Sources: []vcp.MediaInput{
			{ID: "first", Kind: vcp.MediaAudio, Role: vcp.MediaRoleTranscriptionSource, Resource: vcp.ResourceReference{ResourceID: "resource-first"}},
			{ID: "second", Kind: vcp.MediaAudio, Role: vcp.MediaRoleTranscriptionSource, Resource: vcp.ResourceReference{ResourceID: "resource-second"}},
		},
		Diarization: true, ChannelIDs: []int{0, 1}, SpeakerCount: 2, VocabularyID: "vocabulary-1",
	}
	execution.MaterializedInputs = []resource.MaterializedInput{
		{InputID: "first", ResourceID: "resource-first", Kind: vcp.MediaAudio, Role: vcp.MediaRoleTranscriptionSource, MIMEType: "audio/wav", Mode: catalog.MaterializationDirectRemoteURL, RemoteURL: "https://media.example/first.wav"},
		{InputID: "second", ResourceID: "resource-second", Kind: vcp.MediaAudio, Role: vcp.MediaRoleTranscriptionSource, MIMEType: "audio/wav", Mode: catalog.MaterializationProviderObjectURI, ProviderHandle: "oss://dashscope-temp/second.wav", ProviderAssetKind: resource.ProviderAssetObject},
	}
	started, errStart := driver.Start(context.Background(), execution)
	if errStart != nil {
		t.Fatalf("Start() error = %v", errStart)
	}
	polled, errPoll := driver.Poll(context.Background(), execution, started.ProviderTaskID)
	if errPoll != nil || polled.State != provider.TaskPartiallySucceeded || polled.Result == nil || len(polled.Result.Transcriptions) != 2 {
		t.Fatalf("Poll() = %#v, error = %v", polled, errPoll)
	}
	first, second := polled.Result.Transcriptions[0], polled.Result.Transcriptions[1]
	if first.InputID != "first" || first.ResourceID != "resource-first" || first.Transcript == nil || len(first.Transcript.Candidates) != 2 || first.Transcript.Candidates[1].ChannelID == nil || *first.Transcript.Candidates[1].ChannelID != 1 || second.InputID != "second" || second.ResourceID != "resource-second" || second.ErrorCode != "transcription_failed" || second.Transcript != nil {
		t.Fatalf("batch results = %#v", polled.Result.Transcriptions)
	}
}

// TestFunASRTaskRejectsUnrepresentableInput verifies unsupported semantics and inline input fail before provider traffic.
// TestFunASRTaskRejectsUnrepresentableInput 验证不受支持语义及内联输入会在供应商流量前失败。
func TestFunASRTaskRejectsUnrepresentableInput(t *testing.T) {
	driver, execution := newAlibabaSpeechTaskExecution(t, "https://dashscope.example", &recordingPublicDocumentFetcher{})
	execution.Execution.Payload.SpeechTranscribe.Hotwords = []string{"Vulcan"}
	if _, errStart := driver.Start(context.Background(), execution); errStart == nil || !strings.Contains(errStart.Error(), "hotwords") {
		t.Fatalf("Start() hotword error = %v", errStart)
	}
	execution.Execution.Payload.SpeechTranscribe.Hotwords = nil
	execution.Execution.Payload.SpeechTranscribe.WordTimestamps = true
	if _, errStart := driver.Start(context.Background(), execution); errStart == nil || !strings.Contains(errStart.Error(), "timestamp switches") {
		t.Fatalf("Start() timestamp error = %v", errStart)
	}
	execution.Execution.Payload.SpeechTranscribe.WordTimestamps = false
	execution.MaterializedInputs[0].Mode = catalog.MaterializationInlineBase64
	execution.MaterializedInputs[0].InlineBase64 = "YXVkaW8="
	execution.MaterializedInputs[0].RemoteURL = ""
	if _, errStart := driver.Start(context.Background(), execution); errStart == nil || !strings.Contains(errStart.Error(), "direct remote URL") {
		t.Fatalf("Start() inline error = %v", errStart)
	}
}

// TestDecodeFunASRPollUsesStableFailureClassification verifies provider-controlled error text never becomes the public failure code.
// TestDecodeFunASRPollUsesStableFailureClassification 验证供应商控制的错误文本绝不会成为公开失败码。
func TestDecodeFunASRPollUsesStableFailureClassification(t *testing.T) {
	files, observation, errDecode := decodeFunASRPoll(strings.NewReader(`{"output":{"task_id":"task-123","task_status":"SUCCEEDED","results":[{"file_url":"https://media.example/source.wav","subtask_status":"FAILED","code":"provider-controlled-secret"}]}}`), "task-123", time.Now(), []string{"https://media.example/source.wav"})
	if errDecode != nil || observation.State != provider.TaskSucceeded || len(files) != 1 || !files[0].Failed {
		t.Fatalf("decodeFunASRPoll() files = %#v, observation = %#v, error = %v", files, observation, errDecode)
	}
}

// TestDecodeFunASRPollRejectsUnknownSource verifies provider result locators cannot be rebound to an unrelated Router input.
// TestDecodeFunASRPollRejectsUnknownSource 验证供应商结果定位符不能重新绑定到无关 Router 输入。
func TestDecodeFunASRPollRejectsUnknownSource(t *testing.T) {
	_, _, errDecode := decodeFunASRPoll(strings.NewReader(`{"output":{"task_id":"task-123","task_status":"SUCCEEDED","results":[{"file_url":"https://media.example/unrelated.wav","subtask_status":"FAILED"}]}}`), "task-123", time.Now(), []string{"https://media.example/source.wav"})
	if errDecode == nil || !strings.Contains(errDecode.Error(), "unknown source locator") {
		t.Fatalf("decodeFunASRPoll() error = %v", errDecode)
	}
}

// recordingPublicDocumentFetcher records one secure public sidecar acquisition.
// recordingPublicDocumentFetcher 记录一次安全公网 Sidecar 获取。
type recordingPublicDocumentFetcher struct {
	// content is the exact deterministic response document.
	// content 是精确确定的响应文档。
	content []byte
	// requestedURL records the sidecar URL passed by the driver.
	// requestedURL 记录 Driver 传入的 Sidecar URL。
	requestedURL string
	// maximumBytes records the bounded read limit.
	// maximumBytes 记录有界读取限制。
	maximumBytes int64
}

// FetchPublicDocument returns the configured deterministic document.
// FetchPublicDocument 返回配置的确定性文档。
func (f *recordingPublicDocumentFetcher) FetchPublicDocument(_ context.Context, rawURL string, maximumBytes int64) ([]byte, error) {
	f.requestedURL = rawURL
	f.maximumBytes = maximumBytes
	return append([]byte(nil), f.content...), nil
}

// newAlibabaSpeechTaskExecution builds one exact Alibaba asynchronous speech execution fixture.
// newAlibabaSpeechTaskExecution 构建一个精确的阿里云异步语音执行夹具。
func newAlibabaSpeechTaskExecution(t *testing.T, baseURL string, fetcher resource.PublicDocumentFetcher) (*SpeechTaskDriver, provider.ExecutionRequest) {
	t.Helper()
	secretStore := secret.NewMemoryStore()
	secretReference, errPut := secretStore.Put(context.Background(), []byte("test-secret"))
	if errPut != nil {
		t.Fatalf("Put() error = %v", errPut)
	}
	client, errClient := transport.NewClient(http.DefaultClient, secretStore, transport.RetryPolicy{})
	if errClient != nil {
		t.Fatalf("NewClient() error = %v", errClient)
	}
	driver, errDriver := NewSpeechTaskDriver("definition-alibaba", client, fetcher)
	if errDriver != nil {
		t.Fatalf("NewSpeechTaskDriver() error = %v", errDriver)
	}
	action := providerconfig.ProviderActionBinding{ID: SpeechTranscribeAsyncActionBindingID, Operation: vcp.OperationSpeechTranscribe, DriverID: "alibaba", DriverVersion: "1", ProtocolProfileID: SpeechTranscribeAsyncProtocolProfileID, EndpointProfileID: "alibaba_speech", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Asynchronous: true, Polling: true}, ResourceMaterialization: []providerconfig.ResourceMaterializationMode{providerconfig.ResourceMaterializationDirectURL}, Revision: 1}
	definition := providerconfig.ProviderDefinition{ID: "definition-alibaba", Kind: providerconfig.DefinitionKindSystem, ProtocolProfileID: EmbeddingProtocolProfileID, AuthMethodIDs: []string{"api_key"}, RuntimeReady: true, AuthMethods: []providerconfig.AuthMethodDefinition{{ID: "api_key", Type: providerconfig.AuthMethodAPIKey}}, ActionBindings: []providerconfig.ProviderActionBinding{action}, Revision: 1}
	target := resolve.Target{SubjectKind: resolve.ExecutionSubjectModel, ProviderDefinitionID: definition.ID, ProviderInstanceID: "instance-alibaba", ChannelID: EmbeddingProtocolProfileID, EndpointID: "endpoint-alibaba", CredentialID: "credential-alibaba", ProviderModelID: "model-fun-asr", OfferingID: "offering-fun-asr", ExecutionProfileID: "profile-fun-asr", UpstreamModelID: "fun-asr", Operation: vcp.OperationSpeechTranscribe, ActionBindingID: SpeechTranscribeAsyncActionBindingID, CatalogRevision: 1}
	request := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request-fun-asr", IdempotencyKey: "idempotency-fun-asr", Target: vcp.TargetSelection{Model: &vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: target.ProviderInstanceID, ProviderModelID: target.ProviderModelID, ExecutionProfileID: target.ExecutionProfileID}}, Operation: vcp.OperationSpeechTranscribe, Payload: vcp.OperationPayload{SpeechTranscribe: &vcp.SpeechTranscribeOperation{Source: vcp.MediaInput{ID: "video-source", Kind: vcp.MediaVideo, Role: vcp.MediaRoleTranscriptionSource, Resource: vcp.ResourceReference{ResourceID: "resource-video"}}, Language: "en", Diarization: true, CandidateCount: 1}}}
	execution := provider.ExecutionRequest{Binding: transport.Binding{Target: target, Endpoint: providerconfig.Endpoint{ID: target.EndpointID, ProviderInstanceID: target.ProviderInstanceID, ChannelID: target.ChannelID, BaseURL: baseURL, Status: providerconfig.EndpointReady}, Credential: providerconfig.Credential{ID: target.CredentialID, ProviderInstanceID: target.ProviderInstanceID, AuthMethodID: "api_key", SecretRef: secretReference, Status: providerconfig.CredentialActive}}, Definition: definition, Execution: &request, MaterializedInputs: []resource.MaterializedInput{{InputID: "video-source", ResourceID: "resource-video", Kind: vcp.MediaVideo, Role: vcp.MediaRoleTranscriptionSource, MIMEType: "video/mp4", Mode: catalog.MaterializationDirectRemoteURL, RemoteURL: "https://media.example/source.mp4"}}, LineageID: "lineage-fun-asr", Now: time.Date(2026, time.July, 20, 0, 0, 0, 0, time.UTC)}
	return driver, execution
}
