package alibaba

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
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

// TestHappyHorseReferenceVideoUsesExplicitVoiceRelations verifies r2v pairing never depends on input positions.
// TestHappyHorseReferenceVideoUsesExplicitVoiceRelations 验证 r2v 配对绝不依赖输入位置。
func TestHappyHorseReferenceVideoUsesExplicitVoiceRelations(t *testing.T) {
	_, execution := newHappyHorseVideoExecution(t, "https://dashscope.aliyuncs.com", HappyHorseVideoGenerateActionBindingID)
	execution.Binding.Target.UpstreamModelID = "happyhorse-1.1-r2v"
	execution.Execution.Payload.VideoGenerate = &vcp.VideoGenerateOperation{Prompt: "Image 1 speaks, then Video 1 responds", Inputs: []vcp.MediaInput{
		{ID: "voice-video", Kind: vcp.MediaAudio, Role: vcp.MediaRoleReferenceVoice, Resource: vcp.ResourceReference{ResourceID: "resource-voice-video"}, RelatedInputID: "video"},
		{ID: "image", Kind: vcp.MediaImage, Role: vcp.MediaRoleReference, Resource: vcp.ResourceReference{ResourceID: "resource-image"}},
		{ID: "voice-image", Kind: vcp.MediaAudio, Role: vcp.MediaRoleReferenceVoice, Resource: vcp.ResourceReference{ResourceID: "resource-voice-image"}, RelatedInputID: "image"},
		{ID: "video", Kind: vcp.MediaVideo, Role: vcp.MediaRoleReference, Resource: vcp.ResourceReference{ResourceID: "resource-video"}},
	}, DurationSeconds: 5, Resolution: "1080p", AspectRatio: "16:9"}
	execution.MaterializedInputs = []resource.MaterializedInput{
		{InputID: "image", ResourceID: "resource-image", Kind: vcp.MediaImage, Role: vcp.MediaRoleReference, MIMEType: "image/png", Mode: catalog.MaterializationInlineBase64, InlineBase64: "aW1hZ2U="},
		{InputID: "video", ResourceID: "resource-video", Kind: vcp.MediaVideo, Role: vcp.MediaRoleReference, MIMEType: "video/mp4", Mode: catalog.MaterializationProviderObjectURI, ProviderHandle: "oss://bucket/video.mp4", ProviderAssetKind: resource.ProviderAssetObject},
		{InputID: "voice-image", ResourceID: "resource-voice-image", Kind: vcp.MediaAudio, Role: vcp.MediaRoleReferenceVoice, MIMEType: "audio/mpeg", Mode: catalog.MaterializationProviderObjectURI, ProviderHandle: "oss://bucket/image-voice.mp3", ProviderAssetKind: resource.ProviderAssetObject},
		{InputID: "voice-video", ResourceID: "resource-voice-video", Kind: vcp.MediaAudio, Role: vcp.MediaRoleReferenceVoice, MIMEType: "audio/mpeg", Mode: catalog.MaterializationDirectRemoteURL, RemoteURL: "https://inputs.example/video-voice.mp3"},
	}
	request, errProject := projectHappyHorseVideoStart(HappyHorseVideoGenerateActionBindingID, execution)
	if errProject != nil {
		t.Fatalf("projectHappyHorseVideoStart() error = %v", errProject)
	}
	var upstream happyHorseVideoRequest
	if errDecode := json.Unmarshal(request.Body, &upstream); errDecode != nil {
		t.Fatalf("decode request: %v", errDecode)
	}
	// headers projects the typed transport header list for exact assertions.
	// headers 将类型化传输 Header 列表投影为精确断言结构。
	headers := make(map[string]string, len(request.Headers))
	for _, header := range request.Headers {
		headers[header.Name] = header.Value
	}
	if headers["X-DashScope-Async"] != "enable" || headers["X-DashScope-OssResourceResolve"] != "enable" {
		t.Fatalf("headers = %#v", request.Headers)
	}
	if len(upstream.Input.Media) != 2 || upstream.Input.Media[0].Type != "reference_image" || upstream.Input.Media[0].ReferenceVoice != "oss://bucket/image-voice.mp3" || upstream.Input.Media[1].Type != "reference_video" || upstream.Input.Media[1].ReferenceVoice != "https://inputs.example/video-voice.mp3" {
		t.Fatalf("media = %#v", upstream.Input.Media)
	}
}

// TestHappyHorseVideoEditLifecyclePreservesWireShape verifies optional prompt, result fallback, and cancellation.
// TestHappyHorseVideoEditLifecyclePreservesWireShape 验证可选提示词、结果兜底与取消。
func TestHappyHorseVideoEditLifecyclePreservesWireShape(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/v1/services/aigc/video-generation/video-synthesis":
			var upstream happyHorseVideoRequest
			if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil {
				t.Errorf("decode request: %v", errDecode)
			}
			if upstream.Model != "happyhorse-1.0-video-edit" || upstream.Input.Prompt != "" || len(upstream.Input.Media) != 2 || upstream.Input.Media[0].Type != "video" || upstream.Input.Media[1].Type != "reference_image" || upstream.Parameters.AudioSetting != vcp.VideoAudioOrigin || upstream.Parameters.Duration != 8 {
				t.Errorf("upstream = %#v", upstream)
			}
			_, _ = io.WriteString(writer, `{"output":{"task_id":"task-edit","task_status":"PENDING"}}`)
		case "/api/v1/tasks/task-edit":
			_, _ = io.WriteString(writer, `{"output":{"task_id":"task-edit","task_status":"SUCCEEDED","results":[{"url":"https://outputs.example/edited.mp4"}]}}`)
		case "/api/v1/tasks/task-edit/cancel":
			_, _ = io.WriteString(writer, `{"request_id":"request-cancel"}`)
		default:
			t.Errorf("unexpected request = %s %s", request.Method, request.URL.Path)
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	driver, execution := newHappyHorseVideoExecution(t, server.URL, HappyHorseVideoEditActionBindingID)
	execution.Execution.Payload.VideoEdit = &vcp.VideoEditOperation{Source: vcp.MediaInput{ID: "source", Kind: vcp.MediaVideo, Role: vcp.MediaRoleEditSource, Resource: vcp.ResourceReference{ResourceID: "resource-source"}}, References: []vcp.MediaInput{{ID: "reference", Kind: vcp.MediaImage, Role: vcp.MediaRoleReference, Resource: vcp.ResourceReference{ResourceID: "resource-reference"}}}, DurationSeconds: 8, AudioMode: vcp.VideoAudioOrigin}
	execution.MaterializedInputs = []resource.MaterializedInput{
		{InputID: "source", ResourceID: "resource-source", Kind: vcp.MediaVideo, Role: vcp.MediaRoleEditSource, MIMEType: "video/mp4", Mode: catalog.MaterializationDirectRemoteURL, RemoteURL: "https://inputs.example/source.mp4"},
		{InputID: "reference", ResourceID: "resource-reference", Kind: vcp.MediaImage, Role: vcp.MediaRoleReference, MIMEType: "image/png", Mode: catalog.MaterializationDirectRemoteURL, RemoteURL: "https://inputs.example/reference.png"},
	}
	started, errStart := driver.Start(context.Background(), execution)
	if errStart != nil {
		t.Fatalf("Start() error = %v", errStart)
	}
	completed, errPoll := driver.Poll(context.Background(), execution, started.ProviderTaskID)
	if errPoll != nil {
		t.Fatalf("Poll() error = %v", errPoll)
	}
	if completed.Result == nil || len(completed.Result.GeneratedResources) != 1 || completed.Result.GeneratedResources[0].DownloadURL != "https://outputs.example/edited.mp4" {
		t.Fatalf("completed = %#v", completed)
	}
	if _, errCancel := driver.Cancel(context.Background(), execution, started.ProviderTaskID); errCancel != nil {
		t.Fatalf("Cancel() error = %v", errCancel)
	}
}

// TestHappyHorseRejectsUnrelatedVoiceAndFractionalDuration verifies ambiguous provider payloads fail locally.
// TestHappyHorseRejectsUnrelatedVoiceAndFractionalDuration 验证含糊的供应商 Payload 在本地失败。
func TestHappyHorseRejectsUnrelatedVoiceAndFractionalDuration(t *testing.T) {
	_, execution := newHappyHorseVideoExecution(t, "https://dashscope.aliyuncs.com", HappyHorseVideoGenerateActionBindingID)
	execution.Binding.Target.UpstreamModelID = "happyhorse-1.1-r2v"
	execution.Execution.Payload.VideoGenerate = &vcp.VideoGenerateOperation{Prompt: "Speak", DurationSeconds: 2.5, Inputs: []vcp.MediaInput{{ID: "image", Kind: vcp.MediaImage, Role: vcp.MediaRoleReference, Resource: vcp.ResourceReference{ResourceID: "resource-image"}}}}
	if _, errProject := projectHappyHorseVideoStart(HappyHorseVideoGenerateActionBindingID, execution); errProject == nil || !strings.Contains(errProject.Error(), "whole number") {
		t.Fatalf("fractional duration error = %v", errProject)
	}
	execution.Execution.Payload.VideoGenerate.DurationSeconds = 5
	execution.Execution.Payload.VideoGenerate.Inputs = append(execution.Execution.Payload.VideoGenerate.Inputs, vcp.MediaInput{ID: "voice", Kind: vcp.MediaAudio, Role: vcp.MediaRoleReferenceVoice, Resource: vcp.ResourceReference{ResourceID: "resource-voice"}, RelatedInputID: "missing"})
	execution.MaterializedInputs = []resource.MaterializedInput{{InputID: "image", ResourceID: "resource-image", Kind: vcp.MediaImage, Role: vcp.MediaRoleReference, MIMEType: "image/png", Mode: catalog.MaterializationDirectRemoteURL, RemoteURL: "https://inputs.example/image.png"}, {InputID: "voice", ResourceID: "resource-voice", Kind: vcp.MediaAudio, Role: vcp.MediaRoleReferenceVoice, MIMEType: "audio/mpeg", Mode: catalog.MaterializationDirectRemoteURL, RemoteURL: "https://inputs.example/voice.mp3"}}
	if _, errProject := projectHappyHorseVideoStart(HappyHorseVideoGenerateActionBindingID, execution); errProject == nil || !strings.Contains(errProject.Error(), "relation") {
		t.Fatalf("unrelated voice error = %v", errProject)
	}
	// references and materializations construct the first request that exceeds the copied nine-image limit.
	// references 与 materializations 构造第一条超过已复制九图限制的请求。
	references := make([]vcp.MediaInput, 10)
	materializations := make([]resource.MaterializedInput, 10)
	for index := range references {
		identifier := strconv.Itoa(index)
		references[index] = vcp.MediaInput{ID: "image-" + identifier, Kind: vcp.MediaImage, Role: vcp.MediaRoleReference, Resource: vcp.ResourceReference{ResourceID: "resource-image-" + identifier}}
		materializations[index] = resource.MaterializedInput{InputID: "image-" + identifier, ResourceID: "resource-image-" + identifier, Kind: vcp.MediaImage, Role: vcp.MediaRoleReference, MIMEType: "image/png", Mode: catalog.MaterializationDirectRemoteURL, RemoteURL: "https://inputs.example/image-" + identifier + ".png"}
	}
	execution.Execution.Payload.VideoGenerate.Inputs = references
	execution.MaterializedInputs = materializations
	if _, errProject := projectHappyHorseVideoStart(HappyHorseVideoGenerateActionBindingID, execution); errProject == nil || !strings.Contains(errProject.Error(), "at most nine") {
		t.Fatalf("reference image limit error = %v", errProject)
	}
}

// TestDecodeHappyHorseVideoPollRejectsMismatchedTask verifies a provider response cannot be rebound to another queued task.
// TestDecodeHappyHorseVideoPollRejectsMismatchedTask 验证供应商响应不能重新绑定到另一个排队任务。
func TestDecodeHappyHorseVideoPollRejectsMismatchedTask(t *testing.T) {
	_, errDecode := decodeHappyHorseVideoPoll(strings.NewReader(`{"output":{"task_id":"task-other","task_status":"SUCCEEDED","video_url":"https://outputs.example/video.mp4"}}`), "task-expected", time.Now())
	if errDecode == nil || !strings.Contains(errDecode.Error(), "correlation") {
		t.Fatalf("decodeHappyHorseVideoPoll() error = %v", errDecode)
	}
}

// TestDecodeHappyHorseVideoTaskRejectsTrailingJSON verifies task decoders accept exactly one upstream JSON document.
// TestDecodeHappyHorseVideoTaskRejectsTrailingJSON 验证任务解码器仅接受一个上游 JSON 文档。
func TestDecodeHappyHorseVideoTaskRejectsTrailingJSON(t *testing.T) {
	response := `{"output":{"task_id":"task-one","task_status":"PENDING"}} {}`
	if _, errDecode := decodeHappyHorseVideoStart(strings.NewReader(response), time.Now().UTC()); !errors.Is(errDecode, ErrInvalidHappyHorseVideoResponse) {
		t.Fatalf("decodeHappyHorseVideoStart() error = %v", errDecode)
	}
}

// newHappyHorseVideoExecution builds one exact action-specific execution fixture.
// newHappyHorseVideoExecution 构建一个精确动作专属执行夹具。
func newHappyHorseVideoExecution(t *testing.T, baseURL string, actionBindingID string) (*HappyHorseVideoTaskDriver, provider.ExecutionRequest) {
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
	driver, errDriver := NewHappyHorseVideoTaskDriver("definition-alibaba", actionBindingID, client)
	if errDriver != nil {
		t.Fatalf("NewHappyHorseVideoTaskDriver() error = %v", errDriver)
	}
	operation := vcp.OperationVideoGenerate
	protocolProfileID := HappyHorseVideoGenerateProtocolProfileID
	upstreamModelID := "happyhorse-1.1-t2v"
	if actionBindingID == HappyHorseVideoEditActionBindingID {
		operation = vcp.OperationVideoEdit
		protocolProfileID = HappyHorseVideoEditProtocolProfileID
		upstreamModelID = "happyhorse-1.0-video-edit"
	}
	action := providerconfig.ProviderActionBinding{ID: actionBindingID, Operation: operation, DriverID: "alibaba.happyhorse.video", DriverVersion: "1", ProtocolProfileID: protocolProfileID, EndpointProfileID: "alibaba_model_studio", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Asynchronous: true, Polling: true, Cancellation: true}, ResourceMaterialization: []providerconfig.ResourceMaterializationMode{providerconfig.ResourceMaterializationInline, providerconfig.ResourceMaterializationDirectURL, providerconfig.ResourceMaterializationObjectURI}, Revision: 1}
	definition := providerconfig.ProviderDefinition{ID: "definition-alibaba", Kind: providerconfig.DefinitionKindSystem, ProtocolProfileID: "openai.chat", AuthMethodIDs: []string{"api_key"}, RuntimeReady: true, AuthMethods: []providerconfig.AuthMethodDefinition{{ID: "api_key", Type: providerconfig.AuthMethodAPIKey}}, ActionBindings: []providerconfig.ProviderActionBinding{action}, Revision: 1}
	target := resolve.Target{SubjectKind: resolve.ExecutionSubjectModel, ProviderDefinitionID: definition.ID, ProviderInstanceID: "instance-alibaba", ChannelID: protocolProfileID, EndpointID: "endpoint-alibaba", CredentialID: "credential-alibaba", ProviderModelID: "model-happyhorse", OfferingID: "offering-happyhorse", ExecutionProfileID: "profile-happyhorse", UpstreamModelID: upstreamModelID, Operation: operation, ActionBindingID: actionBindingID, CatalogRevision: 1}
	request := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request-happyhorse", Target: vcp.TargetSelection{Model: &vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: target.ProviderInstanceID, ProviderModelID: target.ProviderModelID, ExecutionProfileID: target.ExecutionProfileID}}, Operation: operation}
	execution := provider.ExecutionRequest{Binding: transport.Binding{Target: target, Endpoint: providerconfig.Endpoint{ID: target.EndpointID, ProviderInstanceID: target.ProviderInstanceID, ChannelID: target.ChannelID, BaseURL: baseURL, Status: providerconfig.EndpointReady}, Credential: providerconfig.Credential{ID: target.CredentialID, ProviderInstanceID: target.ProviderInstanceID, AuthMethodID: "api_key", SecretRef: secretReference, Status: providerconfig.CredentialActive}}, Definition: definition, Execution: &request, LineageID: "lineage-happyhorse", Now: time.Date(2026, time.July, 23, 0, 0, 0, 0, time.UTC)}
	return driver, execution
}
