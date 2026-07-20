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

	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestQwen3TTSSynthesisUsesNonStreamingHTTPContract verifies exact request fields and temporary WAV acquisition.
// TestQwen3TTSSynthesisUsesNonStreamingHTTPContract 验证精确请求字段及临时 WAV 获取方式。
func TestQwen3TTSSynthesisUsesNonStreamingHTTPContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != dashScopeMultimodalGenerationPath || request.Header.Get("X-DashScope-SSE") != "" {
			t.Errorf("request = %s %s SSE=%q", request.Method, request.URL.Path, request.Header.Get("X-DashScope-SSE"))
		}
		var upstream qwen3TTSRequest
		if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil {
			t.Errorf("decode request: %v", errDecode)
		}
		if upstream.Model != "qwen3-tts-instruct-flash" || upstream.Input.Text != "Hello Vulcan" || upstream.Input.Voice != "Cherry" || upstream.Input.LanguageType != "English" || upstream.Input.Instructions != "Warm and calm" || !upstream.Input.OptimizeInstructions {
			t.Errorf("upstream = %#v", upstream)
		}
		_, _ = io.WriteString(writer, `{"status_code":200,"request_id":"request-tts","output":{"finish_reason":"stop","audio":{"data":"","url":"https://outputs.example/speech.wav?Expires=1","id":"private-audio","expires_at":1}}}`)
	}))
	defer server.Close()
	driver, execution := newAlibabaSpeechExecution(t, server.URL, SpeechSynthesizeActionBindingID, vcp.OperationSpeechSynthesize, "qwen3-tts-instruct-flash")
	execution.Execution.Payload.SpeechSynthesize = &vcp.SpeechSynthesizeOperation{Text: "Hello Vulcan", VoiceID: "Cherry", Language: "English", Style: "Warm and calm", OutputFormat: "wav"}
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if result.UpstreamResponseID != "request-tts" || len(result.GeneratedResources) != 1 || result.GeneratedResources[0].MIMEType != "audio/wav" || result.GeneratedResources[0].DownloadURL != "https://outputs.example/speech.wav?Expires=1" {
		t.Fatalf("result = %#v", result)
	}
}

// TestQwen3ASRTranscriptionPreservesOnlyProviderConfirmedFacts verifies exact Data URL projection and typed transcript decoding.
// TestQwen3ASRTranscriptionPreservesOnlyProviderConfirmedFacts 验证精确 Data URL 投影及类型化转写解码。
func TestQwen3ASRTranscriptionPreservesOnlyProviderConfirmedFacts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var upstream qwen3ASRRequest
		if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil {
			t.Errorf("decode request: %v", errDecode)
		}
		if upstream.Model != "qwen3-asr-flash" || upstream.Parameters.ResultFormat != "message" || upstream.Parameters.ASROptions.Language != "en" || len(upstream.Input.Messages) != 1 || upstream.Input.Messages[0].Content[0].Audio != "data:audio/mpeg;base64,YXVkaW8=" {
			t.Errorf("upstream = %#v", upstream)
		}
		_, _ = io.WriteString(writer, `{"request_id":"request-asr","output":{"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":[{"text":"Welcome to Vulcan."}],"annotations":[{"type":"audio_info","language":"en","emotion":"neutral"}]}}]},"usage":{"seconds":3}}`)
	}))
	defer server.Close()
	driver, execution := newAlibabaSpeechExecution(t, server.URL, SpeechTranscribeActionBindingID, vcp.OperationSpeechTranscribe, "qwen3-asr-flash")
	execution.Execution.Payload.SpeechTranscribe = &vcp.SpeechTranscribeOperation{Source: vcp.MediaInput{ID: "audio-source", Kind: vcp.MediaAudio, Role: vcp.MediaRoleTranscriptionSource, Resource: vcp.ResourceReference{ResourceID: "resource-audio"}}, Language: "en", CandidateCount: 1}
	execution.MaterializedInputs = []resource.MaterializedInput{{InputID: "audio-source", ResourceID: "resource-audio", Kind: vcp.MediaAudio, Role: vcp.MediaRoleTranscriptionSource, MIMEType: "audio/mpeg", Mode: "inline_base64", InlineBase64: "YXVkaW8="}}
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if result.Transcript == nil || result.Transcript.DurationMilliseconds == nil || *result.Transcript.DurationMilliseconds != 3000 || len(result.Transcript.Candidates) != 1 || result.Transcript.Candidates[0].Text != "Welcome to Vulcan." || len(result.Transcript.Candidates[0].Segments) != 0 {
		t.Fatalf("transcript = %#v", result.Transcript)
	}
}

// TestQwen3SpeechRejectsUnsupportedSemantics verifies missing wire carriers fail before network traffic.
// TestQwen3SpeechRejectsUnsupportedSemantics 验证缺少 Wire 载体的语义会在网络请求前失败。
func TestQwen3SpeechRejectsUnsupportedSemantics(t *testing.T) {
	t.Run("tts numeric control", func(t *testing.T) {
		driver, execution := newAlibabaSpeechExecution(t, "https://dashscope.example", SpeechSynthesizeActionBindingID, vcp.OperationSpeechSynthesize, "qwen3-tts-flash")
		speed := 1.2
		execution.Execution.Payload.SpeechSynthesize = &vcp.SpeechSynthesizeOperation{Text: "Hello", VoiceID: "Cherry", Speed: &speed}
		if _, errExecute := driver.Execute(context.Background(), execution); errExecute == nil || !strings.Contains(errExecute.Error(), "numeric voice controls") {
			t.Fatalf("Execute() error = %v", errExecute)
		}
	})
	t.Run("asr timestamps", func(t *testing.T) {
		driver, execution := newAlibabaSpeechExecution(t, "https://dashscope.example", SpeechTranscribeActionBindingID, vcp.OperationSpeechTranscribe, "qwen3-asr-flash")
		execution.Execution.Payload.SpeechTranscribe = &vcp.SpeechTranscribeOperation{Source: vcp.MediaInput{ID: "audio", Kind: vcp.MediaAudio, Role: vcp.MediaRoleTranscriptionSource, Resource: vcp.ResourceReference{ResourceID: "resource"}}, WordTimestamps: true}
		if _, errExecute := driver.Execute(context.Background(), execution); errExecute == nil || !strings.Contains(errExecute.Error(), "timestamps") {
			t.Fatalf("Execute() error = %v", errExecute)
		}
	})
}

// newAlibabaSpeechExecution builds one exact Alibaba synchronous speech execution fixture.
// newAlibabaSpeechExecution 构建一个精确的阿里云同步语音执行夹具。
func newAlibabaSpeechExecution(t *testing.T, baseURL string, actionBindingID string, operation vcp.OperationKind, upstreamModelID string) (*SpeechActionDriver, provider.ExecutionRequest) {
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
	driver, errDriver := NewSpeechActionDriver("definition-alibaba", actionBindingID, client)
	if errDriver != nil {
		t.Fatalf("NewSpeechActionDriver() error = %v", errDriver)
	}
	profileID := SpeechSynthesizeProtocolProfileID
	if operation == vcp.OperationSpeechTranscribe {
		profileID = SpeechTranscribeProtocolProfileID
	}
	action := providerconfig.ProviderActionBinding{ID: actionBindingID, Operation: operation, DriverID: "alibaba", DriverVersion: "1", ProtocolProfileID: profileID, EndpointProfileID: "alibaba_speech", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, ResourceMaterialization: []providerconfig.ResourceMaterializationMode{providerconfig.ResourceMaterializationInline, providerconfig.ResourceMaterializationDirectURL}, Revision: 1}
	definition := providerconfig.ProviderDefinition{ID: "definition-alibaba", Kind: providerconfig.DefinitionKindSystem, ProtocolProfileID: EmbeddingProtocolProfileID, AuthMethodIDs: []string{"api_key"}, RuntimeReady: true, AuthMethods: []providerconfig.AuthMethodDefinition{{ID: "api_key", Type: providerconfig.AuthMethodAPIKey}}, ActionBindings: []providerconfig.ProviderActionBinding{action}, Revision: 1}
	target := resolve.Target{SubjectKind: resolve.ExecutionSubjectModel, ProviderDefinitionID: definition.ID, ProviderInstanceID: "instance-alibaba", ChannelID: EmbeddingProtocolProfileID, EndpointID: "endpoint-alibaba", CredentialID: "credential-alibaba", ProviderModelID: "model-speech", OfferingID: "offering-speech", ExecutionProfileID: "profile-speech", UpstreamModelID: upstreamModelID, Operation: operation, ActionBindingID: actionBindingID, CatalogRevision: 1}
	request := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request-speech", Target: vcp.TargetSelection{Model: &vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: target.ProviderInstanceID, ProviderModelID: target.ProviderModelID, ExecutionProfileID: target.ExecutionProfileID}}, Operation: operation}
	execution := provider.ExecutionRequest{Binding: transport.Binding{Target: target, Endpoint: providerconfig.Endpoint{ID: target.EndpointID, ProviderInstanceID: target.ProviderInstanceID, ChannelID: target.ChannelID, BaseURL: baseURL, Status: providerconfig.EndpointReady}, Credential: providerconfig.Credential{ID: target.CredentialID, ProviderInstanceID: target.ProviderInstanceID, AuthMethodID: "api_key", SecretRef: secretReference, Status: providerconfig.CredentialActive}}, Definition: definition, Execution: &request, LineageID: "lineage-speech", Now: time.Date(2026, time.July, 20, 0, 0, 0, 0, time.UTC)}
	return driver, execution
}
