package openrouter

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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

// TestAudioSpeechProjectsExactOpenRouterJSON verifies the fixed model, voice, format, and speed carrier.
// TestAudioSpeechProjectsExactOpenRouterJSON 验证固定模型、声音、格式与语速载体。
func TestAudioSpeechProjectsExactOpenRouterJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var body openRouterSpeechRequest
		if request.URL.Path != "/v1/audio/speech" || json.NewDecoder(request.Body).Decode(&body) != nil || body.Model != "openai/gpt-4o-mini-tts-2025-12-15" || body.ResponseFormat != "mp3" || body.Voice != "nova" {
			t.Errorf("request = %s %#v", request.URL.Path, body)
		}
		_, _ = writer.Write([]byte("ID3audio"))
	}))
	defer server.Close()
	driver, execution := newOpenRouterAudioExecution(t, server.URL, SpeechSynthesizeActionBindingID, vcp.OperationSpeechSynthesize, "openai/gpt-4o-mini-tts-2025-12-15")
	execution.Execution.Payload.SpeechSynthesize = &vcp.SpeechSynthesizeOperation{Text: "Hello", VoiceID: "nova", OutputFormat: "mp3"}
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil || len(result.GeneratedResources) != 1 || string(result.GeneratedResources[0].Data) != "ID3audio" {
		t.Fatalf("result=%#v error=%v", result, errExecute)
	}
}

// TestAudioTranscriptionProjectsExactBase64JSON verifies OpenRouter STT does not fabricate missing metadata.
// TestAudioTranscriptionProjectsExactBase64JSON 验证 OpenRouter STT 不会虚构缺失元数据。
func TestAudioTranscriptionProjectsExactBase64JSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var body openRouterTranscriptionRequest
		if request.URL.Path != "/v1/audio/transcriptions" || json.NewDecoder(request.Body).Decode(&body) != nil || body.Model != "openai/whisper-large-v3" || body.InputAudio.Format != "wav" || body.InputAudio.Data != base64.StdEncoding.EncodeToString([]byte("RIFFaudioWAVE")) || body.Language != "en" {
			t.Errorf("request = %s %#v", request.URL.Path, body)
		}
		_, _ = io.WriteString(writer, `{"text":"hello"}`)
	}))
	defer server.Close()
	driver, execution := newOpenRouterAudioExecution(t, server.URL, SpeechTranscribeActionBindingID, vcp.OperationSpeechTranscribe, "openai/whisper-large-v3")
	source := vcp.MediaInput{ID: "source", Kind: vcp.MediaAudio, Role: vcp.MediaRoleTranscriptionSource, Resource: vcp.ResourceReference{ResourceID: "resource-wav"}}
	execution.Execution.Payload.SpeechTranscribe = &vcp.SpeechTranscribeOperation{Source: source, Language: "en", CandidateCount: 1}
	execution.MaterializedInputs = []resource.MaterializedInput{{InputID: source.ID, ResourceID: source.Resource.ResourceID, Kind: source.Kind, Role: source.Role, MIMEType: "audio/wav", Mode: "inline_base64", InlineBase64: base64.StdEncoding.EncodeToString([]byte("RIFFaudioWAVE"))}}
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil || result.Transcript == nil || result.Transcript.Candidates[0].Text != "hello" || result.Transcript.DurationMilliseconds != nil || len(result.Transcript.Candidates[0].Segments) != 0 {
		t.Fatalf("result=%#v error=%v", result, errExecute)
	}
}

// newOpenRouterAudioExecution builds one exact action execution fixture.
// newOpenRouterAudioExecution 构建一个精确的动作执行夹具。
func newOpenRouterAudioExecution(t *testing.T, baseURL string, actionBindingID string, operation vcp.OperationKind, model string) (*AudioDriver, provider.ExecutionRequest) {
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
	driver, errDriver := NewAudioDriver("definition-openrouter", actionBindingID, client)
	if errDriver != nil {
		t.Fatalf("NewAudioDriver() error = %v", errDriver)
	}
	profileID := SpeechSynthesizeProtocolProfileID
	materialization := []providerconfig.ResourceMaterializationMode(nil)
	if operation == vcp.OperationSpeechTranscribe {
		profileID = SpeechTranscribeProtocolProfileID
		materialization = []providerconfig.ResourceMaterializationMode{providerconfig.ResourceMaterializationInline}
	}
	action := providerconfig.ProviderActionBinding{ID: actionBindingID, Operation: operation, DriverID: "openrouter", DriverVersion: "1", ProtocolProfileID: profileID, EndpointProfileID: "openrouter_audio", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, ResourceMaterialization: materialization, Revision: 1}
	definition := providerconfig.ProviderDefinition{ID: "definition-openrouter", Kind: providerconfig.DefinitionKindSystem, ProtocolProfileID: EmbeddingProtocolProfileID, AuthMethodIDs: []string{"api_key"}, RuntimeReady: true, AuthMethods: []providerconfig.AuthMethodDefinition{{ID: "api_key", Type: providerconfig.AuthMethodAPIKey}}, ActionBindings: []providerconfig.ProviderActionBinding{action}, Revision: 1}
	target := resolve.Target{SubjectKind: resolve.ExecutionSubjectModel, ProviderDefinitionID: definition.ID, ProviderInstanceID: "instance-openrouter", ChannelID: EmbeddingProtocolProfileID, EndpointID: "endpoint-openrouter", CredentialID: "credential-openrouter", ProviderModelID: "model-audio", OfferingID: "offering-audio", ExecutionProfileID: "profile-audio", UpstreamModelID: model, Operation: operation, ActionBindingID: actionBindingID, CatalogRevision: 1}
	request := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request-audio", Target: vcp.TargetSelection{Model: &vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: target.ProviderInstanceID, ProviderModelID: target.ProviderModelID, ExecutionProfileID: target.ExecutionProfileID}}, Operation: operation}
	execution := provider.ExecutionRequest{Binding: transport.Binding{Target: target, Endpoint: providerconfig.Endpoint{ID: target.EndpointID, ProviderInstanceID: target.ProviderInstanceID, ChannelID: target.ChannelID, BaseURL: baseURL, Status: providerconfig.EndpointReady}, Credential: providerconfig.Credential{ID: target.CredentialID, ProviderInstanceID: target.ProviderInstanceID, AuthMethodID: "api_key", SecretRef: secretReference, Status: providerconfig.CredentialActive}}, Definition: definition, Execution: &request, LineageID: "lineage-audio", Now: time.Date(2026, time.July, 20, 0, 0, 0, 0, time.UTC)}
	return driver, execution
}
