package openai

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	protocolresponses "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/responses"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestAudioSynthesisProjectsExactClosedRequest verifies unsupported fields cannot leak into OpenAI TTS.
// TestAudioSynthesisProjectsExactClosedRequest 验证不受支持的字段不会泄漏到 OpenAI TTS。
func TestAudioSynthesisProjectsExactClosedRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/audio/speech" || request.Header.Get("Authorization") != "Bearer test-secret" || request.Header.Get("Accept") != "audio/wav" {
			t.Errorf("request path=%q authorization=%q accept=%q", request.URL.Path, request.Header.Get("Authorization"), request.Header.Get("Accept"))
		}
		var body openAISpeechRequest
		if errDecode := json.NewDecoder(request.Body).Decode(&body); errDecode != nil {
			t.Errorf("Decode() error = %v", errDecode)
		}
		if body.Model != "tts-1-hd" || body.Input != "Hello" || body.Voice != "coral" || body.ResponseFormat != "wav" || body.Speed == nil || *body.Speed != 1.25 {
			t.Errorf("body = %#v", body)
		}
		_, _ = writer.Write([]byte("RIFFaudioWAVE"))
	}))
	defer server.Close()

	driver, execution := newOpenAIAudioExecution(t, server.URL, SpeechSynthesizeActionBindingID, vcp.OperationSpeechSynthesize, "tts-1-hd")
	speed := 1.25
	execution.Execution.Payload.SpeechSynthesize = &vcp.SpeechSynthesizeOperation{Text: "Hello", VoiceID: "coral", Speed: &speed, OutputFormat: "wav"}
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if len(result.GeneratedResources) != 1 || result.GeneratedResources[0].MIMEType != "audio/wav" || string(result.GeneratedResources[0].Data) != "RIFFaudioWAVE" {
		t.Fatalf("generated resources = %#v", result.GeneratedResources)
	}
}

// TestAudioTranscriptionPreservesWhisperTimestamps verifies multipart granularities and typed timing output.
// TestAudioTranscriptionPreservesWhisperTimestamps 验证 multipart 粒度字段与类型化时间输出。
func TestAudioTranscriptionPreservesWhisperTimestamps(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if errParse := request.ParseMultipartForm(1 << 20); errParse != nil {
			t.Errorf("ParseMultipartForm() error = %v", errParse)
		}
		if request.FormValue("model") != "whisper-1" || request.FormValue("response_format") != "verbose_json" || request.FormValue("language") != "en" || request.FormValue("prompt") != "Vulcan" {
			t.Errorf("form = %#v", request.MultipartForm.Value)
		}
		granularities := request.MultipartForm.Value["timestamp_granularities[]"]
		if len(granularities) != 2 || granularities[0] != "segment" || granularities[1] != "word" || len(request.MultipartForm.File["file"]) != 1 {
			t.Errorf("multipart = %#v", request.MultipartForm)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"text":"hello world","language":"english","duration":1.25,"segments":[{"id":0,"start":0,"end":1.25,"text":"hello world"}],"words":[{"word":"hello","start":0,"end":0.5},{"word":"world","start":0.5,"end":1.25}]}`)
	}))
	defer server.Close()

	driver, execution := newOpenAIAudioExecution(t, server.URL, SpeechTranscribeActionBindingID, vcp.OperationSpeechTranscribe, "whisper-1")
	source := vcp.MediaInput{ID: "source", Kind: vcp.MediaAudio, Role: vcp.MediaRoleTranscriptionSource, Resource: vcp.ResourceReference{ResourceID: "resource-audio"}}
	execution.Execution.Payload.SpeechTranscribe = &vcp.SpeechTranscribeOperation{Source: source, Language: "en", Prompt: "Vulcan", SegmentTimestamps: true, WordTimestamps: true, CandidateCount: 1}
	execution.MaterializedInputs = []resource.MaterializedInput{{InputID: source.ID, ResourceID: source.Resource.ResourceID, Kind: source.Kind, Role: source.Role, MIMEType: "audio/mpeg", Mode: "inline_base64", InlineBase64: base64.StdEncoding.EncodeToString([]byte("ID3audio"))}}
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if result.Transcript == nil || result.Transcript.DurationMilliseconds == nil || *result.Transcript.DurationMilliseconds != 1250 || len(result.Transcript.Candidates[0].Segments) != 1 || len(result.Transcript.Candidates[0].Segments[0].Words) != 2 {
		t.Fatalf("transcript = %#v", result.Transcript)
	}
}

// TestAudioDiarizationUsesClosedProviderCarrier verifies diarization cannot silently become ordinary transcription.
// TestAudioDiarizationUsesClosedProviderCarrier 验证说话人分离不会静默退化为普通转写。
func TestAudioDiarizationUsesClosedProviderCarrier(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if errParse := request.ParseMultipartForm(1 << 20); errParse != nil {
			t.Errorf("ParseMultipartForm() error = %v", errParse)
		}
		if request.FormValue("response_format") != "diarized_json" || request.FormValue("chunking_strategy") != "auto" {
			t.Errorf("form = %#v", request.MultipartForm.Value)
		}
		_, _ = io.WriteString(writer, `{"text":"hello","duration":1,"segments":[{"id":"seg_001","start":0,"end":1,"text":"hello","speaker":"A"}]}`)
	}))
	defer server.Close()

	driver, execution := newOpenAIAudioExecution(t, server.URL, SpeechTranscribeActionBindingID, vcp.OperationSpeechTranscribe, "gpt-4o-transcribe-diarize")
	source := vcp.MediaInput{ID: "source", Kind: vcp.MediaVideo, Role: vcp.MediaRoleTranscriptionSource, Resource: vcp.ResourceReference{ResourceID: "resource-video"}}
	execution.Execution.Payload.SpeechTranscribe = &vcp.SpeechTranscribeOperation{Source: source, Diarization: true, SegmentTimestamps: true}
	execution.MaterializedInputs = []resource.MaterializedInput{{InputID: source.ID, ResourceID: source.Resource.ResourceID, Kind: source.Kind, Role: source.Role, MIMEType: "video/mp4", Mode: "inline_base64", InlineBase64: base64.StdEncoding.EncodeToString([]byte("video"))}}
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if result.Transcript == nil || result.Transcript.Candidates[0].Segments[0].Speaker != "A" {
		t.Fatalf("transcript = %#v", result.Transcript)
	}
}

// newOpenAIAudioExecution builds one exact action execution fixture.
// newOpenAIAudioExecution 构建一个精确的音频动作执行夹具。
func newOpenAIAudioExecution(t *testing.T, baseURL string, actionBindingID string, operation vcp.OperationKind, model string) (*AudioActionDriver, provider.ExecutionRequest) {
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
	driver, errDriver := NewAudioActionDriver("definition-openai", actionBindingID, client)
	if errDriver != nil {
		t.Fatalf("NewAudioActionDriver() error = %v", errDriver)
	}
	profileID := SpeechSynthesizeProtocolProfileID
	materialization := []providerconfig.ResourceMaterializationMode(nil)
	if operation == vcp.OperationSpeechTranscribe {
		profileID = SpeechTranscribeProtocolProfileID
		materialization = []providerconfig.ResourceMaterializationMode{providerconfig.ResourceMaterializationInline}
	}
	action := providerconfig.ProviderActionBinding{ID: actionBindingID, Operation: operation, DriverID: "openai", DriverVersion: "1", ProtocolProfileID: profileID, EndpointProfileID: "openai_audio", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, ResourceMaterialization: materialization, Revision: 1}
	definition := providerconfig.ProviderDefinition{ID: "definition-openai", Kind: providerconfig.DefinitionKindSystem, ProtocolProfileID: protocolresponses.ProfileID, AuthMethodIDs: []string{"api_key"}, RuntimeReady: true, AuthMethods: []providerconfig.AuthMethodDefinition{{ID: "api_key", Type: providerconfig.AuthMethodAPIKey}}, ActionBindings: []providerconfig.ProviderActionBinding{action}, Revision: 1}
	target := resolve.Target{SubjectKind: resolve.ExecutionSubjectModel, ProviderDefinitionID: definition.ID, ProviderInstanceID: "instance-openai", ChannelID: protocolresponses.ProfileID, EndpointID: "endpoint-openai", CredentialID: "credential-openai", ProviderModelID: "model-" + model, OfferingID: "offering-" + model, ExecutionProfileID: "profile-" + model, UpstreamModelID: model, Operation: operation, ActionBindingID: actionBindingID, CatalogRevision: 1}
	request := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request-audio", Target: vcp.TargetSelection{Model: &vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: target.ProviderInstanceID, ProviderModelID: target.ProviderModelID, ExecutionProfileID: target.ExecutionProfileID}}, Operation: operation}
	execution := provider.ExecutionRequest{Binding: transport.Binding{Target: target, Endpoint: providerconfig.Endpoint{ID: target.EndpointID, ProviderInstanceID: target.ProviderInstanceID, ChannelID: target.ChannelID, BaseURL: baseURL, Status: providerconfig.EndpointReady}, Credential: providerconfig.Credential{ID: target.CredentialID, ProviderInstanceID: target.ProviderInstanceID, AuthMethodID: "api_key", SecretRef: secretReference, Status: providerconfig.CredentialActive}}, Definition: definition, Execution: &request, LineageID: "lineage-audio", Now: time.Date(2026, time.July, 20, 0, 0, 0, 0, time.UTC)}
	return driver, execution
}
