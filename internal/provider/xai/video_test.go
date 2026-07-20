package xai

import (
	"context"
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

// TestVideoTaskDriverPreservesReferenceModeAndImportsCompletedURL verifies exact asynchronous projection and private output acquisition.
// TestVideoTaskDriverPreservesReferenceModeAndImportsCompletedURL 验证精确异步投影和私有输出获取。
func TestVideoTaskDriverPreservesReferenceModeAndImportsCompletedURL(t *testing.T) {
	t.Parallel()
	polls := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer test-secret" {
			t.Errorf("authorization = %q", request.Header.Get("Authorization"))
		}
		switch request.URL.Path {
		case "/v1/videos/generations":
			var upstream videoRequest
			if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil {
				t.Errorf("decode start request: %v", errDecode)
			}
			if upstream.Model != "grok-imagine-video" || upstream.Duration != 10 || upstream.AspectRatio != "16:9" || upstream.Resolution != "720p" || upstream.Image != nil || len(upstream.ReferenceImages) != 2 || upstream.ReferenceImages[0].URL != "https://example.test/reference-1.png" {
				t.Errorf("upstream = %#v", upstream)
			}
			_, _ = io.WriteString(writer, `{"request_id":"request-video-1"}`)
		case "/v1/videos/request-video-1":
			polls++
			_, _ = io.WriteString(writer, `{"status":"done","video":{"url":"https://cdn.example.test/result.mp4","duration":10}}`)
		default:
			t.Errorf("unexpected path = %q", request.URL.Path)
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	driver, execution := newXAIVideoExecution(t, server.URL, VideoGenerateActionBindingID, vcp.OperationVideoGenerate)
	execution.Execution.Payload.VideoGenerate = &vcp.VideoGenerateOperation{Prompt: "Use <IMAGE_1> and <IMAGE_2>", DurationSeconds: 10, AspectRatio: "16:9", Resolution: "720p", OutputFormat: "mp4", Inputs: []vcp.MediaInput{
		{ID: "reference-1", Kind: vcp.MediaImage, Role: vcp.MediaRoleReference, Resource: vcp.ResourceReference{ResourceID: "resource-reference-1"}},
		{ID: "reference-2", Kind: vcp.MediaImage, Role: vcp.MediaRoleReference, Resource: vcp.ResourceReference{ResourceID: "resource-reference-2"}},
	}}
	execution.MaterializedInputs = []resource.MaterializedInput{
		{InputID: "reference-1", ResourceID: "resource-reference-1", Kind: vcp.MediaImage, Role: vcp.MediaRoleReference, MIMEType: "image/png", Mode: "direct_remote_url", RemoteURL: "https://example.test/reference-1.png"},
		{InputID: "reference-2", ResourceID: "resource-reference-2", Kind: vcp.MediaImage, Role: vcp.MediaRoleReference, MIMEType: "image/jpeg", Mode: "inline_base64", InlineBase64: "aW1hZ2U="},
	}
	started, errStart := driver.Start(context.Background(), execution)
	if errStart != nil || started.ProviderTaskID != "request-video-1" || started.State != provider.TaskQueued || started.PollAfter.IsZero() {
		t.Fatalf("Start() = %#v, error=%v", started, errStart)
	}
	completed, errPoll := driver.Poll(context.Background(), execution, started.ProviderTaskID)
	if errPoll != nil || completed.State != provider.TaskSucceeded || completed.Result == nil || len(completed.Result.GeneratedResources) != 1 || completed.Result.GeneratedResources[0].DownloadURL != "https://cdn.example.test/result.mp4" || polls != 1 {
		t.Fatalf("Poll() = %#v, polls=%d, error=%v", completed, polls, errPoll)
	}
}

// TestVideoTaskDriverRejectsFractionalExtensionDuration verifies provider integer-duration semantics are never rounded.
// TestVideoTaskDriverRejectsFractionalExtensionDuration 验证供应商整数时长语义绝不会被舍入。
func TestVideoTaskDriverRejectsFractionalExtensionDuration(t *testing.T) {
	t.Parallel()
	driver, execution := newXAIVideoExecution(t, "https://api.x.ai", VideoExtendActionBindingID, vcp.OperationVideoExtend)
	execution.Execution.Payload.VideoExtend = &vcp.VideoExtendOperation{Source: vcp.MediaInput{ID: "source", Kind: vcp.MediaVideo, Role: vcp.MediaRoleEditSource, Resource: vcp.ResourceReference{ResourceID: "resource-source"}}, Prompt: "Continue", AdditionalDurationSeconds: 2.5}
	execution.MaterializedInputs = []resource.MaterializedInput{{InputID: "source", ResourceID: "resource-source", Kind: vcp.MediaVideo, Role: vcp.MediaRoleEditSource, MIMEType: "video/mp4", Mode: "direct_remote_url", RemoteURL: "https://example.test/source.mp4"}}
	if _, errStart := driver.Start(context.Background(), execution); errStart == nil {
		t.Fatal("Start() accepted fractional extension duration")
	}
}

// newXAIVideoExecution builds one exact asynchronous action fixture.
// newXAIVideoExecution 构建一个精确异步动作夹具。
func newXAIVideoExecution(t *testing.T, baseURL string, actionBindingID string, operation vcp.OperationKind) (*VideoTaskDriver, provider.ExecutionRequest) {
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
	driver, errDriver := NewVideoTaskDriver("definition-xai", actionBindingID, client)
	if errDriver != nil {
		t.Fatalf("NewVideoTaskDriver() error = %v", errDriver)
	}
	profileID := map[vcp.OperationKind]string{vcp.OperationVideoGenerate: VideoGenerateProtocolProfileID, vcp.OperationVideoEdit: VideoEditProtocolProfileID, vcp.OperationVideoExtend: VideoExtendProtocolProfileID}[operation]
	action := providerconfig.ProviderActionBinding{ID: actionBindingID, Operation: operation, DriverID: "xai", DriverVersion: "1", ProtocolProfileID: profileID, EndpointProfileID: "xai_videos", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Asynchronous: true}, Revision: 1}
	definition := providerconfig.ProviderDefinition{ID: "definition-xai", Kind: providerconfig.DefinitionKindSystem, ProtocolProfileID: "xai.responses.v1", AuthMethodIDs: []string{"api_key"}, RuntimeReady: true, AuthMethods: []providerconfig.AuthMethodDefinition{{ID: "api_key", Type: providerconfig.AuthMethodAPIKey}}, ActionBindings: []providerconfig.ProviderActionBinding{action}, Revision: 1}
	target := resolve.Target{SubjectKind: resolve.ExecutionSubjectModel, ProviderDefinitionID: definition.ID, ProviderInstanceID: "instance-xai", ChannelID: "xai.responses.v1", EndpointID: "endpoint-xai", CredentialID: "credential-xai", ProviderModelID: "model-video", OfferingID: "offering-video", ExecutionProfileID: "profile-video", UpstreamModelID: "grok-imagine-video", Operation: operation, ActionBindingID: actionBindingID, CatalogRevision: 1}
	request := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request-video", Target: vcp.TargetSelection{Model: &vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: target.ProviderInstanceID, ProviderModelID: target.ProviderModelID, ExecutionProfileID: target.ExecutionProfileID}}, Operation: operation}
	execution := provider.ExecutionRequest{Binding: transport.Binding{Target: target, Endpoint: providerconfig.Endpoint{ID: target.EndpointID, ProviderInstanceID: target.ProviderInstanceID, ChannelID: target.ChannelID, BaseURL: baseURL, Status: providerconfig.EndpointReady}, Credential: providerconfig.Credential{ID: target.CredentialID, ProviderInstanceID: target.ProviderInstanceID, AuthMethodID: "api_key", SecretRef: secretReference, Status: providerconfig.CredentialActive}}, Definition: definition, Execution: &request, LineageID: "lineage-video", Now: time.Date(2026, time.July, 20, 0, 0, 0, 0, time.UTC)}
	return driver, execution
}
