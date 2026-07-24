package alibaba

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestCosyVoiceNonStreamingProjectsCompleteVerifiedRequest verifies every copied non-streaming field and private output URL.
// TestCosyVoiceNonStreamingProjectsCompleteVerifiedRequest 验证每个复制的非流式字段及私有输出 URL。
func TestCosyVoiceNonStreamingProjectsCompleteVerifiedRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != dashScopeCosyVoicePath || request.Header.Get("Authorization") != "Bearer test-secret" || request.Header.Get("X-DashScope-SSE") != "" {
			t.Errorf("request = %s %s headers=%#v", request.Method, request.URL.Path, request.Header)
		}
		var upstream cosyVoiceRequest
		if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil {
			t.Errorf("decode request: %v", errDecode)
		}
		if upstream.Model != "cosyvoice-v3.5-flash" || upstream.Input.Text != "<speak>Hello Vulcan</speak>" || upstream.Input.Voice != "voice-clone-1" || upstream.Input.Format != "wav" || upstream.Input.SampleRate != 24000 || upstream.Input.Volume == nil || *upstream.Input.Volume != 60 || upstream.Input.Rate == nil || *upstream.Input.Rate != 1.25 || upstream.Input.Pitch == nil || *upstream.Input.Pitch != 0.75 || upstream.Input.Seed == nil || *upstream.Input.Seed != 7 || !slices.Equal(upstream.Input.LanguageHints, []string{"en"}) || upstream.Input.Instruction != "Warm and calm" || !upstream.Input.EnableSSML {
			t.Errorf("upstream = %#v", upstream)
		}
		_, _ = io.WriteString(writer, `{"request_id":"request-cosy","output":{"audio":{"url":"https://outputs.example/cosy.wav?Expires=1"},"finish_reason":"stop"}}`)
	}))
	defer server.Close()
	driver, execution := newCosyVoiceExecution(t, server.URL)
	volume, speed, pitch, seed := float64(60), float64(1.25), float64(0.75), int64(7)
	execution.Execution.Payload.SpeechSynthesize = &vcp.SpeechSynthesizeOperation{Text: "<speak>Hello Vulcan</speak>", VoiceID: "voice-clone-1", OutputFormat: "wav", SampleRate: 24000, Volume: &volume, Speed: &speed, Pitch: &pitch, Seed: &seed, Language: "en", Style: "Warm and calm", EnableSSML: true}
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if len(result.GeneratedResources) != 1 || result.GeneratedResources[0].MIMEType != "audio/wav" || result.GeneratedResources[0].DownloadURL != "https://outputs.example/cosy.wav?Expires=1" {
		t.Fatalf("result = %#v", result)
	}
}

// TestCosyVoiceStreamingPreservesAudioOrderAndProgress verifies SSE chunks, byte budget, and cumulative progress.
// TestCosyVoiceStreamingPreservesAudioOrderAndProgress 验证 SSE 分片、字节预算及累计进度。
func TestCosyVoiceStreamingPreservesAudioOrderAndProgress(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Accept") != "text/event-stream" || request.Header.Get("X-DashScope-SSE") != "enable" {
			t.Errorf("stream headers = %#v", request.Header)
		}
		writer.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(writer, "data: {\"request_id\":\"request-cosy\",\"output\":{\"audio\":{\"data\":\"YWJj\"}}}\n\n")
		_, _ = io.WriteString(writer, "data: {\"request_id\":\"request-cosy\",\"output\":{\"audio\":{\"data\":\"ZA==\"},\"finish_reason\":\"stop\"}}\n\n")
	}))
	defer server.Close()
	driver, execution := newCosyVoiceExecution(t, server.URL)
	maximumBytes := int64(4)
	sink := &recordingResourceProgressSink{}
	execution.Execution.Stream = true
	execution.Execution.Budget.MaxOutputBytes = &maximumBytes
	execution.Execution.Payload.SpeechSynthesize = &vcp.SpeechSynthesizeOperation{Text: "Hello", VoiceID: "longanyang", OutputFormat: "mp3"}
	execution.ResourceSink = sink
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if len(result.GeneratedResources) != 1 || string(result.GeneratedResources[0].Data) != "abcd" || !slices.Equal(sink.bytes, []int64{3, 4}) {
		t.Fatalf("result = %#v progress = %#v", result, sink.bytes)
	}
	tooSmall := int64(3)
	execution.Execution.Budget.MaxOutputBytes = &tooSmall
	if _, errExecute := driver.Execute(context.Background(), execution); !errors.Is(errExecute, provider.ErrOutputBudgetExceeded) {
		t.Fatalf("Execute() budget error = %v", errExecute)
	}
}

// recordingResourceProgressSink records cumulative generated audio bytes.
// recordingResourceProgressSink 记录生成音频的累计字节数。
type recordingResourceProgressSink struct {
	// bytes contains every strictly increasing progress value.
	// bytes 包含每个严格递增进度值。
	bytes []int64
}

// EmitResourceProgress records one validated provider progress observation.
// EmitResourceProgress 记录一项经过校验的供应商进度观测。
func (s *recordingResourceProgressSink) EmitResourceProgress(_ context.Context, progress provider.ResourceProgress) error {
	s.bytes = append(s.bytes, progress.PartialBytes)
	return nil
}

// newCosyVoiceExecution builds one exact CosyVoice action execution fixture.
// newCosyVoiceExecution 构建一个精确的 CosyVoice 动作执行夹具。
func newCosyVoiceExecution(t *testing.T, baseURL string) (*CosyVoiceActionDriver, provider.ExecutionRequest) {
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
	driver, errDriver := NewCosyVoiceActionDriver("definition-alibaba", client)
	if errDriver != nil {
		t.Fatalf("NewCosyVoiceActionDriver() error = %v", errDriver)
	}
	action := providerconfig.ProviderActionBinding{ID: CosyVoiceSynthesizeActionBindingID, Operation: vcp.OperationSpeechSynthesize, DriverID: "alibaba", DriverVersion: "1", ProtocolProfileID: CosyVoiceSynthesizeProtocolProfileID, EndpointProfileID: "alibaba_cosyvoice", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true, Streaming: true}, Revision: 1}
	definition := providerconfig.ProviderDefinition{ID: "definition-alibaba", Kind: providerconfig.DefinitionKindSystem, ProtocolProfileID: EmbeddingProtocolProfileID, AuthMethodIDs: []string{"api_key"}, RuntimeReady: true, AuthMethods: []providerconfig.AuthMethodDefinition{{ID: "api_key", Type: providerconfig.AuthMethodAPIKey}}, ActionBindings: []providerconfig.ProviderActionBinding{action}, Revision: 1}
	target := resolve.Target{SubjectKind: resolve.ExecutionSubjectModel, ProviderDefinitionID: definition.ID, ProviderInstanceID: "instance-alibaba", ChannelID: CosyVoiceSynthesizeProtocolProfileID, EndpointID: "endpoint-alibaba", CredentialID: "credential-alibaba", ProviderModelID: "model-cosyvoice", OfferingID: "offering-cosyvoice", ExecutionProfileID: "profile-cosyvoice", UpstreamModelID: "cosyvoice-v3.5-flash", Operation: vcp.OperationSpeechSynthesize, ActionBindingID: CosyVoiceSynthesizeActionBindingID, CatalogRevision: 1}
	request := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request-cosyvoice", Target: vcp.TargetSelection{Model: &vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: target.ProviderInstanceID, ProviderModelID: target.ProviderModelID, ExecutionProfileID: target.ExecutionProfileID}}, Operation: vcp.OperationSpeechSynthesize}
	return driver, provider.ExecutionRequest{Binding: transport.Binding{Target: target, Endpoint: providerconfig.Endpoint{ID: target.EndpointID, ProviderInstanceID: target.ProviderInstanceID, ChannelID: target.ChannelID, BaseURL: baseURL, Status: providerconfig.EndpointReady}, Credential: providerconfig.Credential{ID: target.CredentialID, ProviderInstanceID: target.ProviderInstanceID, AuthMethodID: "api_key", SecretRef: secretReference, Status: providerconfig.CredentialActive}}, Definition: definition, Execution: &request, LineageID: "lineage-cosyvoice", Now: time.Date(2026, time.July, 20, 0, 0, 0, 0, time.UTC)}
}
