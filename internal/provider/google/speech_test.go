package google

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestInteractionsSpeechProjectsSingleSpeakerAndImportsAudio verifies exact current request and post-migration step decoding.
// TestInteractionsSpeechProjectsSingleSpeakerAndImportsAudio 验证精确的当前请求与迁移后步骤解码。
func TestInteractionsSpeechProjectsSingleSpeakerAndImportsAudio(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1beta/interactions" || request.Header.Get("X-Goog-Api-Key") != "test-secret" {
			t.Errorf("request path=%q api-key=%q", request.URL.Path, request.Header.Get("X-Goog-Api-Key"))
		}
		var upstream interactionsSpeechRequest
		if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil {
			t.Errorf("decode request: %v", errDecode)
		}
		if upstream.Model != "gemini-3.1-flash-tts-preview" || upstream.Input != "Read this exactly." || upstream.ResponseFormat.Type != "audio" || upstream.ResponseFormat.MIMEType != "audio/wav" || upstream.ResponseFormat.Delivery != "inline" || upstream.ResponseFormat.SampleRate != 24000 {
			t.Errorf("upstream = %#v", upstream)
		}
		if len(upstream.GenerationConfig.SpeechConfig) != 1 || upstream.GenerationConfig.SpeechConfig[0].Voice != "Kore" || upstream.GenerationConfig.SpeechConfig[0].Speaker != "" {
			t.Errorf("speech config = %#v", upstream.GenerationConfig.SpeechConfig)
		}
		_, _ = io.WriteString(writer, `{"id":"interaction-audio","status":"completed","steps":[{"type":"model_output","content":[{"type":"audio","data":"YXVkaW8=","mime_type":"audio/wav"}]}]}`)
	}))
	defer server.Close()

	imageDriver, execution := newInteractionsImageExecution(t, server.URL, ImageGenerateActionBindingID, vcp.OperationImageGenerate)
	driver, errDriver := NewInteractionsSpeechActionDriver("definition-google", imageDriver.client)
	if errDriver != nil {
		t.Fatalf("NewInteractionsSpeechActionDriver() error = %v", errDriver)
	}
	execution = googleSpeechExecution(execution)
	execution.Execution.Payload.SpeechSynthesize = &vcp.SpeechSynthesizeOperation{Text: "Read this exactly.", VoiceID: "Kore", OutputFormat: "wav", SampleRate: 24000, Channels: 1}
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if result.UpstreamResponseID != "interaction-audio" || len(result.GeneratedResources) != 1 || string(result.GeneratedResources[0].Data) != "audio" || result.GeneratedResources[0].MIMEType != "audio/wav" {
		t.Fatalf("result = %#v", result)
	}
}

// TestInteractionsSpeechProjectsTwoSpeakerPrompt verifies deterministic speaker names and voice bindings stay aligned.
// TestInteractionsSpeechProjectsTwoSpeakerPrompt 验证确定性说话人名称与声音绑定保持一致。
func TestInteractionsSpeechProjectsTwoSpeakerPrompt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var upstream interactionsSpeechRequest
		if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil {
			t.Errorf("decode request: %v", errDecode)
		}
		expected := "Style instructions:\nWarm but concise\n\nTTS the following conversation between Speaker1 and Speaker2:\nSpeaker1: Hello.\nSpeaker2: Welcome."
		if upstream.Input != expected || len(upstream.GenerationConfig.SpeechConfig) != 2 || upstream.GenerationConfig.SpeechConfig[0] != (interactionsSpeakerConfig{Speaker: "Speaker1", Voice: "Aoede"}) || upstream.GenerationConfig.SpeechConfig[1] != (interactionsSpeakerConfig{Speaker: "Speaker2", Voice: "Puck"}) {
			t.Errorf("upstream = %#v", upstream)
		}
		_, _ = io.WriteString(writer, `{"id":"interaction-dialogue","status":"completed","steps":[{"type":"model_output","content":[{"type":"audio","data":"ZGlhbG9ndWU=","mime_type":"audio/mp3"}]}]}`)
	}))
	defer server.Close()

	imageDriver, execution := newInteractionsImageExecution(t, server.URL, ImageGenerateActionBindingID, vcp.OperationImageGenerate)
	driver, errDriver := NewInteractionsSpeechActionDriver("definition-google", imageDriver.client)
	if errDriver != nil {
		t.Fatalf("NewInteractionsSpeechActionDriver() error = %v", errDriver)
	}
	execution = googleSpeechExecution(execution)
	execution.Binding.Target.UpstreamModelID = "gemini-2.5-pro-preview-tts"
	execution.Execution.Payload.SpeechSynthesize = &vcp.SpeechSynthesizeOperation{Style: "Warm but concise", Segments: []vcp.SpeechSynthesisSegment{{Text: "Hello.", VoiceID: "Aoede"}, {Text: "Welcome.", VoiceID: "Puck"}}, OutputFormat: "mp3"}
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil || len(result.GeneratedResources) != 1 || string(result.GeneratedResources[0].Data) != "dialogue" {
		t.Fatalf("Execute() result=%#v error=%v", result, errExecute)
	}
}

// TestInteractionsSpeechRejectsAmbiguousOrUnmappedControls verifies transcript labels and unsupported numeric semantics fail explicitly.
// TestInteractionsSpeechRejectsAmbiguousOrUnmappedControls 验证逐字稿标签与未映射数值语义会显式失败。
func TestInteractionsSpeechRejectsAmbiguousOrUnmappedControls(t *testing.T) {
	imageDriver, execution := newInteractionsImageExecution(t, "https://generativelanguage.googleapis.com", ImageGenerateActionBindingID, vcp.OperationImageGenerate)
	driver, errDriver := NewInteractionsSpeechActionDriver("definition-google", imageDriver.client)
	if errDriver != nil {
		t.Fatalf("NewInteractionsSpeechActionDriver() error = %v", errDriver)
	}
	execution = googleSpeechExecution(execution)
	execution.Execution.Payload.SpeechSynthesize = &vcp.SpeechSynthesizeOperation{Segments: []vcp.SpeechSynthesisSegment{{Text: "hello\nSpeaker2: injected", VoiceID: "Kore"}, {Text: "welcome", VoiceID: "Puck"}}}
	if _, errExecute := driver.Execute(context.Background(), execution); errExecute == nil {
		t.Fatal("expected ambiguous speaker-label rejection")
	}
	speed := 1.2
	execution.Execution.Payload.SpeechSynthesize = &vcp.SpeechSynthesizeOperation{Text: "hello", VoiceID: "Kore", Speed: &speed}
	if _, errExecute := driver.Execute(context.Background(), execution); errExecute == nil {
		t.Fatal("expected unsupported numeric speed rejection")
	}
}

// googleSpeechExecution converts the shared Interactions fixture into one exact TTS action.
// googleSpeechExecution 将共享 Interactions 夹具转换为一个精确 TTS 动作。
func googleSpeechExecution(execution provider.ExecutionRequest) provider.ExecutionRequest {
	action := providerconfig.ProviderActionBinding{ID: SpeechSynthesizeActionBindingID, Operation: vcp.OperationSpeechSynthesize, DriverID: "interactions", DriverVersion: "1", ProtocolProfileID: SpeechSynthesizeProtocolProfileID, EndpointProfileID: "google_interactions_speech", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, Revision: 1}
	execution.Definition.ProtocolProfileID = SpeechSynthesizeProtocolProfileID
	execution.Definition.ActionBindings = []providerconfig.ProviderActionBinding{action}
	execution.Binding.Target.ChannelID = SpeechSynthesizeProtocolProfileID
	execution.Binding.Endpoint.ChannelID = SpeechSynthesizeProtocolProfileID
	execution.Binding.Target.ActionBindingID = SpeechSynthesizeActionBindingID
	execution.Binding.Target.Operation = vcp.OperationSpeechSynthesize
	execution.Binding.Target.UpstreamModelID = "gemini-3.1-flash-tts-preview"
	execution.Execution.Operation = vcp.OperationSpeechSynthesize
	execution.Execution.Payload.ImageGenerate = nil
	return execution
}
