package openrouter

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

// TestVideoTaskDriverUsesDedicatedAPIAndAuthenticatedContent verifies job affinity and private authenticated content acquisition.
// TestVideoTaskDriverUsesDedicatedAPIAndAuthenticatedContent 验证任务亲和性和私有认证内容获取。
func TestVideoTaskDriverUsesDedicatedAPIAndAuthenticatedContent(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer test-secret" {
			t.Errorf("authorization = %q", request.Header.Get("Authorization"))
		}
		switch request.URL.RequestURI() {
		case "/api/v1/videos":
			var upstream openRouterVideoRequest
			if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil {
				t.Errorf("decode request: %v", errDecode)
			}
			if upstream.Model != "google/veo-3.1" || upstream.Duration != 8 || upstream.Resolution != "720p" || len(upstream.FrameImages) != 1 || upstream.FrameImages[0].FrameType != "first_frame" {
				t.Errorf("upstream = %#v", upstream)
			}
			_, _ = io.WriteString(writer, `{"id":"job-1","polling_url":"/api/v1/videos/job-1","status":"pending"}`)
		case "/api/v1/videos/job-1":
			_, _ = io.WriteString(writer, `{"id":"job-1","status":"completed","unsigned_urls":["/api/v1/videos/job-1/content?index=0"]}`)
		case "/api/v1/videos/job-1/content?index=0":
			writer.Header().Set("Content-Type", "video/mp4")
			_, _ = writer.Write([]byte("video-bytes"))
		default:
			t.Errorf("unexpected request = %s %s", request.Method, request.URL.RequestURI())
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	driver, execution := newOpenRouterVideoExecution(t, server.URL+"/api")
	execution.Execution.Payload.VideoGenerate = &vcp.VideoGenerateOperation{Prompt: "Animate", DurationSeconds: 8, Resolution: "720p", OutputFormat: "mp4", Inputs: []vcp.MediaInput{{ID: "first", Kind: vcp.MediaImage, Role: vcp.MediaRoleFirstFrame, Resource: vcp.ResourceReference{ResourceID: "resource-first"}}}}
	execution.MaterializedInputs = []resource.MaterializedInput{{InputID: "first", ResourceID: "resource-first", Kind: vcp.MediaImage, Role: vcp.MediaRoleFirstFrame, MIMEType: "image/png", Mode: "direct_remote_url", RemoteURL: "https://example.test/first.png"}}
	started, errStart := driver.Start(context.Background(), execution)
	if errStart != nil || started.ProviderTaskID != "job-1" || started.State != provider.TaskQueued {
		t.Fatalf("Start() = %#v, error=%v", started, errStart)
	}
	completed, errPoll := driver.Poll(context.Background(), execution, started.ProviderTaskID)
	if errPoll != nil || completed.State != provider.TaskSucceeded || completed.Result == nil || len(completed.Result.GeneratedResources) != 1 || string(completed.Result.GeneratedResources[0].Data) != "video-bytes" || completed.Result.GeneratedResources[0].DownloadURL != "" {
		t.Fatalf("Poll() = %#v, error=%v", completed, errPoll)
	}
}

// newOpenRouterVideoExecution builds one exact OpenRouter video action fixture.
// newOpenRouterVideoExecution 构建一个精确 OpenRouter 视频动作夹具。
func newOpenRouterVideoExecution(t *testing.T, baseURL string) (*VideoTaskDriver, provider.ExecutionRequest) {
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
	driver, errDriver := NewVideoTaskDriver("definition-openrouter", client)
	if errDriver != nil {
		t.Fatalf("NewVideoTaskDriver() error = %v", errDriver)
	}
	action := providerconfig.ProviderActionBinding{ID: VideoGenerateActionBindingID, Operation: vcp.OperationVideoGenerate, DriverID: "openrouter", DriverVersion: "1", ProtocolProfileID: VideoGenerateProtocolProfileID, EndpointProfileID: "openrouter_videos", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Asynchronous: true}, Revision: 1}
	definition := providerconfig.ProviderDefinition{ID: "definition-openrouter", Kind: providerconfig.DefinitionKindSystem, ProtocolProfileID: EmbeddingProtocolProfileID, AuthMethodIDs: []string{"api_key"}, RuntimeReady: true, AuthMethods: []providerconfig.AuthMethodDefinition{{ID: "api_key", Type: providerconfig.AuthMethodAPIKey}}, ActionBindings: []providerconfig.ProviderActionBinding{action}, Revision: 1}
	target := resolve.Target{SubjectKind: resolve.ExecutionSubjectModel, ProviderDefinitionID: definition.ID, ProviderInstanceID: "instance-openrouter", ChannelID: EmbeddingProtocolProfileID, EndpointID: "endpoint-openrouter", CredentialID: "credential-openrouter", ProviderModelID: "model-veo", OfferingID: "offering-veo", ExecutionProfileID: "profile-veo", UpstreamModelID: "google/veo-3.1", Operation: vcp.OperationVideoGenerate, ActionBindingID: VideoGenerateActionBindingID, CatalogRevision: 1}
	request := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request-video", Target: vcp.TargetSelection{Model: &vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: target.ProviderInstanceID, ProviderModelID: target.ProviderModelID, ExecutionProfileID: target.ExecutionProfileID}}, Operation: vcp.OperationVideoGenerate}
	execution := provider.ExecutionRequest{Binding: transport.Binding{Target: target, Endpoint: providerconfig.Endpoint{ID: target.EndpointID, ProviderInstanceID: target.ProviderInstanceID, ChannelID: target.ChannelID, BaseURL: baseURL, Status: providerconfig.EndpointReady}, Credential: providerconfig.Credential{ID: target.CredentialID, ProviderInstanceID: target.ProviderInstanceID, AuthMethodID: "api_key", SecretRef: secretReference, Status: providerconfig.CredentialActive}}, Definition: definition, Execution: &request, LineageID: "lineage-video", Now: time.Date(2026, time.July, 20, 0, 0, 0, 0, time.UTC)}
	return driver, execution
}
