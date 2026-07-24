package alibaba

import (
	"context"
	"encoding/json"
	"errors"
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

// TestWanVideoLifecyclePreservesHeadersPayloadAndTaskIdentity verifies create, poll, and cancellation on the same target.
// TestWanVideoLifecyclePreservesHeadersPayloadAndTaskIdentity 验证同一 Target 上的创建、轮询与取消。
func TestWanVideoLifecyclePreservesHeadersPayloadAndTaskIdentity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer test-secret" {
			t.Errorf("Authorization = %q", request.Header.Get("Authorization"))
		}
		switch request.URL.Path {
		case "/api/v1/services/aigc/video-generation/video-synthesis":
			if request.Method != http.MethodPost || request.Header.Get("X-DashScope-Async") != "enable" {
				t.Errorf("start = %s async=%q", request.Method, request.Header.Get("X-DashScope-Async"))
			}
			var upstream wanVideoRequest
			if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil {
				t.Errorf("decode request: %v", errDecode)
			}
			if upstream.Model != "wan2.7-t2v" || upstream.Input.Prompt != "Neon city" || upstream.Input.AudioURL != "https://inputs.example/track.mp3" || upstream.Parameters.Duration != 8 || upstream.Parameters.Resolution != "1080P" || upstream.Parameters.Ratio != "16:9" {
				t.Errorf("upstream = %#v", upstream)
			}
			_, _ = io.WriteString(writer, `{"output":{"task_id":"task-1","task_status":"PENDING"}}`)
		case "/api/v1/tasks/task-1":
			if request.Method != http.MethodGet {
				t.Errorf("poll method = %s", request.Method)
			}
			_, _ = io.WriteString(writer, `{"output":{"task_id":"task-1","task_status":"SUCCEEDED","video_url":"https://outputs.example/video.mp4"}}`)
		case "/api/v1/tasks/task-1/cancel":
			if request.Method != http.MethodPost {
				t.Errorf("cancel method = %s", request.Method)
			}
			_, _ = io.WriteString(writer, `{"request_id":"request-cancel"}`)
		default:
			t.Errorf("unexpected request = %s %s", request.Method, request.URL.Path)
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	driver, execution := newWanVideoExecution(t, server.URL)
	execution.Execution.Payload.VideoGenerate = &vcp.VideoGenerateOperation{Prompt: "Neon city", Inputs: []vcp.MediaInput{{ID: "audio", Kind: vcp.MediaAudio, Role: vcp.MediaRoleAudioTrack, Resource: vcp.ResourceReference{ResourceID: "resource-audio"}}}, DurationSeconds: 8, AspectRatio: "16:9", Resolution: "1080p", Count: 1, OutputFormat: "mp4"}
	execution.MaterializedInputs = []resource.MaterializedInput{{InputID: "audio", ResourceID: "resource-audio", Kind: vcp.MediaAudio, Role: vcp.MediaRoleAudioTrack, MIMEType: "audio/mpeg", Mode: catalog.MaterializationDirectRemoteURL, RemoteURL: "https://inputs.example/track.mp3"}}
	started, errStart := driver.Start(context.Background(), execution)
	if errStart != nil {
		t.Fatalf("Start() error = %v", errStart)
	}
	if started.ProviderTaskID != "task-1" || started.State != provider.TaskQueued {
		t.Fatalf("started = %#v", started)
	}
	completed, errPoll := driver.Poll(context.Background(), execution, started.ProviderTaskID)
	if errPoll != nil {
		t.Fatalf("Poll() error = %v", errPoll)
	}
	if completed.State != provider.TaskSucceeded || completed.Result == nil || len(completed.Result.GeneratedResources) != 1 || completed.Result.GeneratedResources[0].DownloadURL != "https://outputs.example/video.mp4" {
		t.Fatalf("completed = %#v", completed)
	}
	cancelled, errCancel := driver.Cancel(context.Background(), execution, started.ProviderTaskID)
	if errCancel != nil {
		t.Fatalf("Cancel() error = %v", errCancel)
	}
	if cancelled.State != provider.TaskCancelled || cancelled.ProviderTaskID != "task-1" {
		t.Fatalf("cancelled = %#v", cancelled)
	}
}

// TestWanVideoRejectsFractionalDurationAndInlineAudio verifies unsupported wire forms fail before transport.
// TestWanVideoRejectsFractionalDurationAndInlineAudio 验证不受支持的线路形式在传输前失败。
func TestWanVideoRejectsFractionalDurationAndInlineAudio(t *testing.T) {
	driver, execution := newWanVideoExecution(t, "https://dashscope.aliyuncs.com")
	execution.Execution.Payload.VideoGenerate = &vcp.VideoGenerateOperation{Prompt: "Neon city", DurationSeconds: 2.5}
	if _, errStart := driver.Start(context.Background(), execution); errStart == nil || !strings.Contains(errStart.Error(), "whole number") {
		t.Fatalf("fractional Start() error = %v", errStart)
	}
	execution.Execution.Payload.VideoGenerate = &vcp.VideoGenerateOperation{Prompt: "Neon city", Inputs: []vcp.MediaInput{{ID: "audio", Kind: vcp.MediaAudio, Role: vcp.MediaRoleAudioTrack, Resource: vcp.ResourceReference{ResourceID: "resource-audio"}}}}
	execution.MaterializedInputs = []resource.MaterializedInput{{InputID: "audio", ResourceID: "resource-audio", Kind: vcp.MediaAudio, Role: vcp.MediaRoleAudioTrack, MIMEType: "audio/mpeg", Mode: catalog.MaterializationInlineBase64, InlineBase64: "YXVkaW8="}}
	if _, errStart := driver.Start(context.Background(), execution); errStart == nil || !strings.Contains(errStart.Error(), "public URL") {
		t.Fatalf("inline-audio Start() error = %v", errStart)
	}
}

// TestWanImageVideoProjectsClosedMediaCombination verifies media-only first/last-frame generation and the exact provider role vocabulary.
// TestWanImageVideoProjectsClosedMediaCombination 验证纯媒体首尾帧生成与精确供应商角色词汇。
func TestWanImageVideoProjectsClosedMediaCombination(t *testing.T) {
	_, execution := newWanVideoExecution(t, "https://workspace.ap-southeast-1.maas.aliyuncs.com")
	execution.Binding.Target.UpstreamModelID = "wan2.7-i2v"
	execution.Execution.Payload.VideoGenerate = &vcp.VideoGenerateOperation{Inputs: []vcp.MediaInput{
		{ID: "first", Kind: vcp.MediaImage, Role: vcp.MediaRoleFirstFrame, Resource: vcp.ResourceReference{ResourceID: "resource-first"}},
		{ID: "last", Kind: vcp.MediaImage, Role: vcp.MediaRoleLastFrame, Resource: vcp.ResourceReference{ResourceID: "resource-last"}},
		{ID: "audio", Kind: vcp.MediaAudio, Role: vcp.MediaRoleAudioTrack, Resource: vcp.ResourceReference{ResourceID: "resource-audio"}},
	}, DurationSeconds: 10, Resolution: "720p"}
	execution.MaterializedInputs = []resource.MaterializedInput{
		{InputID: "first", ResourceID: "resource-first", Kind: vcp.MediaImage, Role: vcp.MediaRoleFirstFrame, MIMEType: "image/png", Mode: catalog.MaterializationInlineBase64, InlineBase64: "Zmlyc3Q="},
		{InputID: "last", ResourceID: "resource-last", Kind: vcp.MediaImage, Role: vcp.MediaRoleLastFrame, MIMEType: "image/jpeg", Mode: catalog.MaterializationDirectRemoteURL, RemoteURL: "https://inputs.example/last.jpg"},
		{InputID: "audio", ResourceID: "resource-audio", Kind: vcp.MediaAudio, Role: vcp.MediaRoleAudioTrack, MIMEType: "audio/mpeg", Mode: catalog.MaterializationDirectRemoteURL, RemoteURL: "https://inputs.example/audio.mp3"},
	}
	request, errProject := projectWanVideoStart(execution)
	if errProject != nil {
		t.Fatalf("projectWanVideoStart() error = %v", errProject)
	}
	var upstream wanVideoRequest
	if errDecode := json.Unmarshal(request.Body, &upstream); errDecode != nil {
		t.Fatalf("decode request: %v", errDecode)
	}
	if upstream.Model != "wan2.7-i2v" || upstream.Input.Prompt != "" || upstream.Input.AudioURL != "" || len(upstream.Input.Media) != 3 || upstream.Input.Media[0].Type != "first_frame" || upstream.Input.Media[0].URL != "data:image/png;base64,Zmlyc3Q=" || upstream.Input.Media[1].Type != "last_frame" || upstream.Input.Media[2].Type != "driving_audio" {
		t.Fatalf("upstream = %#v", upstream)
	}
}

// TestDecodeWanVideoPollRejectsMismatchedTask verifies a provider response cannot be rebound to another queued task.
// TestDecodeWanVideoPollRejectsMismatchedTask 验证供应商响应不能重新绑定到另一个排队任务。
func TestDecodeWanVideoPollRejectsMismatchedTask(t *testing.T) {
	_, errDecode := decodeWanVideoPoll(strings.NewReader(`{"output":{"task_id":"task-other","task_status":"SUCCEEDED","video_url":"https://outputs.example/video.mp4"}}`), "task-expected", time.Now())
	if errDecode == nil || !strings.Contains(errDecode.Error(), "correlation") {
		t.Fatalf("decodeWanVideoPoll() error = %v", errDecode)
	}
}

// TestDecodeWanVideoTaskRejectsTrailingJSON verifies task decoders accept exactly one upstream JSON document.
// TestDecodeWanVideoTaskRejectsTrailingJSON 验证任务解码器仅接受一个上游 JSON 文档。
func TestDecodeWanVideoTaskRejectsTrailingJSON(t *testing.T) {
	response := `{"output":{"task_id":"task-one","task_status":"PENDING"}} {}`
	if _, errDecode := decodeWanVideoStart(strings.NewReader(response), time.Now().UTC()); !errors.Is(errDecode, ErrInvalidWanVideoResponse) {
		t.Fatalf("decodeWanVideoStart() error = %v", errDecode)
	}
}

// newWanVideoExecution builds one exact Alibaba workspace video fixture.
// newWanVideoExecution 构建一个精确阿里工作空间视频夹具。
func newWanVideoExecution(t *testing.T, baseURL string) (*WanVideoTaskDriver, provider.ExecutionRequest) {
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
	driver, errDriver := NewWanVideoTaskDriver("definition-alibaba", client)
	if errDriver != nil {
		t.Fatalf("NewWanVideoTaskDriver() error = %v", errDriver)
	}
	action := providerconfig.ProviderActionBinding{ID: WanVideoGenerateActionBindingID, Operation: vcp.OperationVideoGenerate, DriverID: "alibaba.wan.video", DriverVersion: "2.7", ProtocolProfileID: WanVideoGenerateProtocolProfileID, EndpointProfileID: "alibaba_workspace", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Asynchronous: true, Polling: true, Cancellation: true}, ResourceMaterialization: []providerconfig.ResourceMaterializationMode{providerconfig.ResourceMaterializationInline, providerconfig.ResourceMaterializationDirectURL}, Revision: 1}
	definition := providerconfig.ProviderDefinition{ID: "definition-alibaba", Kind: providerconfig.DefinitionKindSystem, ProtocolProfileID: "openai.chat", AuthMethodIDs: []string{"api_key"}, RuntimeReady: true, AuthMethods: []providerconfig.AuthMethodDefinition{{ID: "api_key", Type: providerconfig.AuthMethodAPIKey}}, ActionBindings: []providerconfig.ProviderActionBinding{action}, Revision: 1}
	target := resolve.Target{SubjectKind: resolve.ExecutionSubjectModel, ProviderDefinitionID: definition.ID, ProviderInstanceID: "instance-alibaba", ChannelID: WanVideoGenerateProtocolProfileID, EndpointID: "endpoint-alibaba", CredentialID: "credential-alibaba", ProviderModelID: "model-wan-video", OfferingID: "offering-wan-video", ExecutionProfileID: "profile-wan-video", UpstreamModelID: "wan2.7-t2v", Operation: vcp.OperationVideoGenerate, ActionBindingID: WanVideoGenerateActionBindingID, CatalogRevision: 1}
	request := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request-wan-video", Target: vcp.TargetSelection{Model: &vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: target.ProviderInstanceID, ProviderModelID: target.ProviderModelID, ExecutionProfileID: target.ExecutionProfileID}}, Operation: vcp.OperationVideoGenerate}
	execution := provider.ExecutionRequest{Binding: transport.Binding{Target: target, Endpoint: providerconfig.Endpoint{ID: target.EndpointID, ProviderInstanceID: target.ProviderInstanceID, ChannelID: target.ChannelID, BaseURL: baseURL, Status: providerconfig.EndpointReady}, Credential: providerconfig.Credential{ID: target.CredentialID, ProviderInstanceID: target.ProviderInstanceID, AuthMethodID: "api_key", SecretRef: secretReference, Status: providerconfig.CredentialActive}}, Definition: definition, Execution: &request, LineageID: "lineage-wan-video", Now: time.Date(2026, time.July, 20, 0, 0, 0, 0, time.UTC)}
	return driver, execution
}
