package google

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

// TestVeoGenerateStartPollAndDownload verifies the exact first/last-frame request, long-running poll, and private authenticated download.
// TestVeoGenerateStartPollAndDownload 验证精确首尾帧请求、长任务轮询与私有认证下载。
func TestVeoGenerateStartPollAndDownload(t *testing.T) {
	// serverURL is assigned after server construction so the poll response can point to the same authenticated origin.
	// serverURL 在服务器构造后赋值，使轮询响应能够指向同一认证 Origin。
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("X-Goog-Api-Key") != "test-secret" {
			t.Errorf("X-Goog-Api-Key = %q", request.Header.Get("X-Goog-Api-Key"))
		}
		switch request.URL.RequestURI() {
		case "/v1beta/models/veo-3.1-generate-preview:predictLongRunning":
			if request.Method != http.MethodPost {
				t.Errorf("start method = %s", request.Method)
			}
			var upstream veoRequest
			if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil {
				t.Errorf("decode start request: %v", errDecode)
			}
			if len(upstream.Instances) != 1 || upstream.Instances[0].Prompt != "Ocean sunrise" || upstream.Instances[0].Image == nil || upstream.Instances[0].Image.InlineData.Data != "Zmlyc3Q=" || upstream.Instances[0].LastFrame == nil || upstream.Instances[0].LastFrame.InlineData.Data != "bGFzdA==" {
				t.Errorf("start instance = %#v", upstream.Instances)
			}
			if upstream.Parameters.DurationSeconds != 8 || upstream.Parameters.Resolution != "1080p" || upstream.Parameters.AspectRatio != "16:9" || upstream.Parameters.NumberOfVideos != 1 {
				t.Errorf("start parameters = %#v", upstream.Parameters)
			}
			_, _ = io.WriteString(writer, `{"name":"models/veo-3.1-generate-preview/operations/task-1"}`)
		case "/v1beta/models/veo-3.1-generate-preview/operations/task-1":
			if request.Method != http.MethodGet {
				t.Errorf("poll method = %s", request.Method)
			}
			_, _ = io.WriteString(writer, `{"name":"models/veo-3.1-generate-preview/operations/task-1","done":true,"response":{"generateVideoResponse":{"generatedSamples":[{"video":{"uri":"`+serverURL+`/upload/v1beta/files/video-1?alt=media"}}]}}}`)
		case "/upload/v1beta/files/video-1?alt=media":
			if request.Method != http.MethodGet {
				t.Errorf("download method = %s", request.Method)
			}
			writer.Header().Set("Content-Type", "video/mp4")
			_, _ = writer.Write([]byte("veo-video"))
		default:
			t.Errorf("unexpected request = %s %s", request.Method, request.URL.RequestURI())
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	driver, execution := newVeoExecution(t, server.URL, VideoGenerateActionBindingID, vcp.OperationVideoGenerate)
	execution.Execution.Payload.VideoGenerate = &vcp.VideoGenerateOperation{Prompt: "Ocean sunrise", Inputs: []vcp.MediaInput{
		{ID: "first", Kind: vcp.MediaImage, Role: vcp.MediaRoleFirstFrame, Resource: vcp.ResourceReference{ResourceID: "resource-first"}},
		{ID: "last", Kind: vcp.MediaImage, Role: vcp.MediaRoleLastFrame, Resource: vcp.ResourceReference{ResourceID: "resource-last"}},
	}, DurationSeconds: 8, AspectRatio: "16:9", Resolution: "1080p", Count: 1, OutputFormat: "mp4"}
	execution.MaterializedInputs = []resource.MaterializedInput{
		{InputID: "first", ResourceID: "resource-first", Kind: vcp.MediaImage, Role: vcp.MediaRoleFirstFrame, MIMEType: "image/png", Mode: catalog.MaterializationInlineBase64, InlineBase64: "Zmlyc3Q="},
		{InputID: "last", ResourceID: "resource-last", Kind: vcp.MediaImage, Role: vcp.MediaRoleLastFrame, MIMEType: "image/jpeg", Mode: catalog.MaterializationInlineBase64, InlineBase64: "bGFzdA=="},
	}
	started, errStart := driver.Start(context.Background(), execution)
	if errStart != nil {
		t.Fatalf("Start() error = %v", errStart)
	}
	if started.ProviderTaskID != "models/veo-3.1-generate-preview/operations/task-1" || started.State != provider.TaskQueued {
		t.Fatalf("started = %#v", started)
	}
	completed, errPoll := driver.Poll(context.Background(), execution, started.ProviderTaskID)
	if errPoll != nil {
		t.Fatalf("Poll() error = %v", errPoll)
	}
	if completed.State != provider.TaskSucceeded || completed.Result == nil || len(completed.Result.GeneratedResources) != 1 || string(completed.Result.GeneratedResources[0].Data) != "veo-video" || completed.Result.GeneratedResources[0].DownloadURL != "" {
		t.Fatalf("completed = %#v", completed)
	}
}

// TestVeoExtensionAndOperationPathValidation verifies fixed extension duration and closed operation resource names.
// TestVeoExtensionAndOperationPathValidation 验证固定延长时长与封闭操作资源名称。
func TestVeoExtensionAndOperationPathValidation(t *testing.T) {
	driver, execution := newVeoExecution(t, "https://generativelanguage.googleapis.com", VideoExtendActionBindingID, vcp.OperationVideoExtend)
	execution.Execution.Payload.VideoExtend = &vcp.VideoExtendOperation{Source: vcp.MediaInput{ID: "source", Kind: vcp.MediaVideo, Role: vcp.MediaRoleEditSource, Resource: vcp.ResourceReference{ResourceID: "resource-source"}}, AdditionalDurationSeconds: 6}
	execution.MaterializedInputs = []resource.MaterializedInput{{InputID: "source", ResourceID: "resource-source", Kind: vcp.MediaVideo, Role: vcp.MediaRoleEditSource, MIMEType: "video/mp4", Mode: catalog.MaterializationInlineBase64, InlineBase64: "dmlkZW8="}}
	if _, errStart := driver.Start(context.Background(), execution); errStart == nil || !strings.Contains(errStart.Error(), "exactly seven") {
		t.Fatalf("Start() error = %v", errStart)
	}
	if _, errPath := exactVeoOperationPath("models/veo-3.1-generate-preview/operations/../secret"); errPath == nil {
		t.Fatal("exactVeoOperationPath() accepted traversal")
	}
	execution.Execution.Payload.VideoExtend.AdditionalDurationSeconds = 7
	if _, errProject := projectVeoStart(execution, VideoExtendActionBindingID); errProject == nil || !strings.Contains(errProject.Error(), "generated by Veo") {
		t.Fatalf("extension without provenance error = %v", errProject)
	}
	execution.MaterializedInputs[0].GeneratedBy = &resource.GenerationProvenance{ExecutionID: "execution-source", ProviderDefinitionID: "definition-google", ProviderModelID: "model-veo", UpstreamModelID: "veo-3.1-generate-preview", ActionBindingID: VideoGenerateActionBindingID, Operation: vcp.OperationVideoGenerate}
	request, errProject := projectVeoStart(execution, VideoExtendActionBindingID)
	if errProject != nil {
		t.Fatalf("projectVeoStart() error = %v", errProject)
	}
	var upstream veoRequest
	if errDecode := json.Unmarshal(request.Body, &upstream); errDecode != nil {
		t.Fatalf("decode extension: %v", errDecode)
	}
	if len(upstream.Instances) != 1 || upstream.Instances[0].Video == nil || upstream.Instances[0].Video.InlineData.Data != "dmlkZW8=" || upstream.Parameters.DurationSeconds != 8 || upstream.Parameters.Resolution != "720p" {
		t.Fatalf("extension request = %#v", upstream)
	}
}

// newVeoExecution builds one exact AI Studio Veo task fixture.
// newVeoExecution 构建一个精确 AI Studio Veo 任务夹具。
func newVeoExecution(t *testing.T, baseURL string, actionBindingID string, operation vcp.OperationKind) (*VideoTaskDriver, provider.ExecutionRequest) {
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
	driver, errDriver := NewVideoTaskDriver("definition-google", actionBindingID, client)
	if errDriver != nil {
		t.Fatalf("NewVideoTaskDriver() error = %v", errDriver)
	}
	profileID := VideoGenerateProtocolProfileID
	if operation == vcp.OperationVideoExtend {
		profileID = VideoExtendProtocolProfileID
	}
	action := providerconfig.ProviderActionBinding{ID: actionBindingID, Operation: operation, DriverID: "google.veo", DriverVersion: "3.1", ProtocolProfileID: profileID, EndpointProfileID: "google_ai_studio", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Asynchronous: true, Polling: true}, ResourceMaterialization: []providerconfig.ResourceMaterializationMode{providerconfig.ResourceMaterializationInline}, Revision: 1}
	definition := providerconfig.ProviderDefinition{ID: "definition-google", Kind: providerconfig.DefinitionKindSystem, ProtocolProfileID: "google.aistudio", AuthMethodIDs: []string{"api_key"}, RuntimeReady: true, AuthMethods: []providerconfig.AuthMethodDefinition{{ID: "api_key", Type: providerconfig.AuthMethodAPIKey}}, ActionBindings: []providerconfig.ProviderActionBinding{action}, Revision: 1}
	target := resolve.Target{SubjectKind: resolve.ExecutionSubjectModel, ProviderDefinitionID: definition.ID, ProviderInstanceID: "instance-google", ChannelID: profileID, EndpointID: "endpoint-google", CredentialID: "credential-google", ProviderModelID: "model-veo", OfferingID: "offering-veo", ExecutionProfileID: "profile-veo", UpstreamModelID: "veo-3.1-generate-preview", Operation: operation, ActionBindingID: actionBindingID, CatalogRevision: 1}
	request := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request-veo", Target: vcp.TargetSelection{Model: &vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: target.ProviderInstanceID, ProviderModelID: target.ProviderModelID, ExecutionProfileID: target.ExecutionProfileID}}, Operation: operation}
	execution := provider.ExecutionRequest{Binding: transport.Binding{Target: target, Endpoint: providerconfig.Endpoint{ID: target.EndpointID, ProviderInstanceID: target.ProviderInstanceID, ChannelID: target.ChannelID, BaseURL: baseURL, Status: providerconfig.EndpointReady}, Credential: providerconfig.Credential{ID: target.CredentialID, ProviderInstanceID: target.ProviderInstanceID, AuthMethodID: "api_key", SecretRef: secretReference, Status: providerconfig.CredentialActive}}, Definition: definition, Execution: &request, LineageID: "lineage-veo", Now: time.Date(2026, time.July, 20, 0, 0, 0, 0, time.UTC)}
	return driver, execution
}
