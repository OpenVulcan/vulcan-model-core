package minimax

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

// TestMiniMaxSynchronousSpeechProjectsExactControls verifies the closed T2A request and hexadecimal response import.
// TestMiniMaxSynchronousSpeechProjectsExactControls 验证封闭的 T2A 请求与十六进制响应导入。
func TestMiniMaxSynchronousSpeechProjectsExactControls(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/t2a_v2" {
			http.NotFound(writer, request)
			return
		}
		var upstream miniMaxSyncSpeechRequest
		if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil {
			t.Errorf("decode request: %v", errDecode)
		}
		if upstream.Model != "speech-2.8-hd" || upstream.Text != "你好" || upstream.Stream || upstream.LanguageBoost != "Chinese" || upstream.OutputFormat != "hex" {
			t.Errorf("request identity = %#v", upstream)
		}
		if upstream.VoiceSetting.VoiceID != "Chinese (Mandarin)_Gentleman" || upstream.VoiceSetting.Speed != 1.25 || upstream.VoiceSetting.Volume != 2 || upstream.VoiceSetting.Pitch != -2 {
			t.Errorf("voice controls = %#v", upstream.VoiceSetting)
		}
		if upstream.AudioSetting.SampleRate != 44100 || upstream.AudioSetting.Bitrate != 256000 || upstream.AudioSetting.Format != "mp3" || upstream.AudioSetting.Channel != 2 {
			t.Errorf("audio controls = %#v", upstream.AudioSetting)
		}
		_, _ = io.WriteString(writer, `{"data":{"audio":"617564696f","status":2},"base_resp":{"status_code":0}}`)
	}))
	defer server.Close()

	imageDriver, execution := newMiniMaxImageExecution(t, server.URL)
	driver, errDriver := NewSpeechActionDriver("definition-minimax", imageDriver.client)
	if errDriver != nil {
		t.Fatalf("NewSpeechActionDriver() error = %v", errDriver)
	}
	execution = miniMaxSpeechExecution(execution, SpeechSynthesizeActionBindingID, SpeechSynthesizeProtocolProfileID, true)
	speed := 1.25
	volume := 2.0
	pitch := -2.0
	execution.Execution.Payload.SpeechSynthesize = &vcp.SpeechSynthesizeOperation{Text: "你好", VoiceID: "Chinese (Mandarin)_Gentleman", Language: "Chinese", Speed: &speed, Volume: &volume, Pitch: &pitch, SampleRate: 44100, Bitrate: 256000, Channels: 2, OutputFormat: "mp3"}
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if len(result.GeneratedResources) != 1 || result.GeneratedResources[0].MIMEType != "audio/mpeg" || string(result.GeneratedResources[0].Data) != "audio" {
		t.Fatalf("result = %#v", result)
	}
}

// TestMiniMaxAsynchronousSpeechKeepsTaskAndFileIdentifiersPrivate verifies start, poll, and file retrieval use exact upstream identities only internally.
// TestMiniMaxAsynchronousSpeechKeepsTaskAndFileIdentifiersPrivate 验证创建、轮询与文件取回仅在内部使用精确上游标识。
func TestMiniMaxAsynchronousSpeechKeepsTaskAndFileIdentifiersPrivate(t *testing.T) {
	// requests records endpoint order without retaining credentials or text.
	// requests 记录端点顺序且不保留凭据或文本。
	requests := make([]string, 0, 3)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests = append(requests, request.URL.RequestURI())
		switch request.URL.Path {
		case "/v1/t2a_async_v2":
			var upstream miniMaxAsyncSpeechRequest
			if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil {
				t.Errorf("decode request: %v", errDecode)
			}
			if upstream.Model != "speech-2.8-turbo" || upstream.Text != "long text" || upstream.AudioSetting.SampleRate != 32000 || upstream.AudioSetting.Format != "wav" || upstream.AudioSetting.Bitrate != 0 {
				t.Errorf("upstream = %#v", upstream)
			}
			_, _ = io.WriteString(writer, `{"task_id":95157322514444,"file_id":95157322514496,"base_resp":{"status_code":0}}`)
		case "/v1/query/t2a_async_query_v2":
			_, _ = io.WriteString(writer, `{"task_id":95157322514444,"status":"Success","file_id":95157322514496,"base_resp":{"status_code":0}}`)
		case "/v1/files/retrieve":
			_, _ = io.WriteString(writer, `{"file":{"download_url":"https://outputs.example/audio.wav"},"base_resp":{"status_code":0}}`)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	imageDriver, execution := newMiniMaxImageExecution(t, server.URL)
	driver, errDriver := NewSpeechTaskDriver("definition-minimax", imageDriver.client)
	if errDriver != nil {
		t.Fatalf("NewSpeechTaskDriver() error = %v", errDriver)
	}
	execution = miniMaxSpeechExecution(execution, SpeechSynthesizeAsyncActionBindingID, SpeechSynthesizeAsyncProtocolProfileID, false)
	execution.Execution.Payload.SpeechSynthesize = &vcp.SpeechSynthesizeOperation{Text: "long text", VoiceID: "English_expressive_narrator", OutputFormat: "wav"}
	started, errStart := driver.Start(context.Background(), execution)
	if errStart != nil || started.ProviderTaskID != "95157322514444" {
		t.Fatalf("Start() result=%#v error=%v", started, errStart)
	}
	completed, errPoll := driver.Poll(context.Background(), execution, started.ProviderTaskID)
	if errPoll != nil || completed.Result == nil || completed.Result.GeneratedResources[0].DownloadURL != "https://outputs.example/audio.wav" || completed.Result.GeneratedResources[0].MIMEType != "audio/wav" {
		t.Fatalf("Poll() result=%#v error=%v", completed, errPoll)
	}
	if len(requests) != 3 || requests[1] != "/v1/query/t2a_async_query_v2?task_id=95157322514444" || requests[2] != "/v1/files/retrieve?file_id=95157322514496" {
		t.Fatalf("requests = %#v", requests)
	}
}

// TestMiniMaxSpeechRejectsUnrepresentableControls verifies unsupported timestamps and fractional pitch fail explicitly.
// TestMiniMaxSpeechRejectsUnrepresentableControls 验证不受支持的时间戳与小数音高会显式失败。
func TestMiniMaxSpeechRejectsUnrepresentableControls(t *testing.T) {
	imageDriver, execution := newMiniMaxImageExecution(t, "https://api.minimax.io")
	driver, errDriver := NewSpeechActionDriver("definition-minimax", imageDriver.client)
	if errDriver != nil {
		t.Fatalf("NewSpeechActionDriver() error = %v", errDriver)
	}
	execution = miniMaxSpeechExecution(execution, SpeechSynthesizeActionBindingID, SpeechSynthesizeProtocolProfileID, true)
	fractionalPitch := 1.5
	execution.Execution.Payload.SpeechSynthesize = &vcp.SpeechSynthesizeOperation{Text: "hello", VoiceID: "voice", Pitch: &fractionalPitch}
	if _, errExecute := driver.Execute(context.Background(), execution); errExecute == nil {
		t.Fatal("expected fractional pitch rejection")
	}
	execution.Execution.Payload.SpeechSynthesize = &vcp.SpeechSynthesizeOperation{Text: "hello", VoiceID: "voice", Timestamps: true}
	if _, errExecute := driver.Execute(context.Background(), execution); errExecute == nil {
		t.Fatal("expected timestamp rejection")
	}
}

// miniMaxSpeechExecution converts the shared fixture into one exact speech action execution.
// miniMaxSpeechExecution 将共享夹具转换为一个精确的语音动作执行。
func miniMaxSpeechExecution(execution provider.ExecutionRequest, actionBindingID string, profileID string, synchronous bool) provider.ExecutionRequest {
	delivery := providerconfig.ActionDeliveryModes{Asynchronous: !synchronous, Polling: !synchronous, Synchronous: synchronous}
	action := providerconfig.ProviderActionBinding{ID: actionBindingID, Operation: vcp.OperationSpeechSynthesize, DriverID: "minimax", DriverVersion: "1", ProtocolProfileID: profileID, EndpointProfileID: "minimax_speech", AuthMethodIDs: []string{"api_key"}, Delivery: delivery, Revision: 1}
	execution.Definition.ProtocolProfileID = profileID
	execution.Definition.ActionBindings = []providerconfig.ProviderActionBinding{action}
	execution.Binding.Target.ChannelID = profileID
	execution.Binding.Endpoint.ChannelID = profileID
	execution.Binding.Target.ActionBindingID = actionBindingID
	execution.Binding.Target.Operation = vcp.OperationSpeechSynthesize
	execution.Binding.Target.UpstreamModelID = "speech-2.8-hd"
	if !synchronous {
		execution.Binding.Target.UpstreamModelID = "speech-2.8-turbo"
	}
	execution.Execution.Operation = vcp.OperationSpeechSynthesize
	execution.Execution.Payload.ImageGenerate = nil
	return execution
}
