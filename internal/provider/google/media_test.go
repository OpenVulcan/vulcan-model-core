package google

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	aistudio "github.com/OpenVulcan/vulcan-model-core/internal/protocol/google/aistudio"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestMediaAnalyzeDriverPreservesTaskAndMaterializedInput verifies the versioned instruction and exact media carrier reach Gemini in order.
// TestMediaAnalyzeDriverPreservesTaskAndMaterializedInput 验证版本化指令与精确媒体载体按顺序到达 Gemini。
func TestMediaAnalyzeDriverPreservesTaskAndMaterializedInput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1beta/models/gemini-2.5-flash:generateContent" {
			t.Errorf("request = %s %s", request.Method, request.URL.Path)
		}
		if request.Header.Get("X-Goog-Api-Key") != "test-secret" {
			t.Errorf("X-Goog-Api-Key = %q", request.Header.Get("X-Goog-Api-Key"))
		}
		var upstream aistudio.GenerateContentRequest
		if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil {
			t.Errorf("decode request: %v", errDecode)
		}
		if len(upstream.Contents) != 1 || len(upstream.Contents[0].Parts) != 2 || upstream.Contents[0].Parts[0].Text == "" || upstream.Contents[0].Parts[1].InlineData == nil || upstream.Contents[0].Parts[1].InlineData.Data != "aW1hZ2U=" {
			t.Errorf("upstream request = %#v", upstream)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"responseId":"media-response-1","candidates":[{"index":0,"content":{"role":"model","parts":[{"text":"A blue square."}]},"finishReason":"STOP"}]}`)
	}))
	defer server.Close()

	driver, execution := newMediaAnalyzeExecution(t, server.URL)
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if result.UpstreamResponseID != "media-response-1" || result.Response.Status != vcp.ResponseCompleted || len(result.Response.Items) != 1 || result.Response.Items[0].Content[0].Text != "A blue square." {
		t.Fatalf("result = %#v", result)
	}
	if !containsConversionCode(result.Report.ConversionSummary, "google_aistudio.media_analyze.prompt.v1") {
		t.Fatalf("report = %#v", result.Report)
	}
}

// TestMediaAnalyzeDriverRejectsUnverifiedModerationBeforeNetwork verifies an unproven task cannot be smuggled through a generic prompt.
// TestMediaAnalyzeDriverRejectsUnverifiedModerationBeforeNetwork 验证未经证实的任务不能通过通用提示词夹带执行。
func TestMediaAnalyzeDriverRejectsUnverifiedModerationBeforeNetwork(t *testing.T) {
	driver, execution := newMediaAnalyzeExecution(t, "http://127.0.0.1:1")
	execution.Execution.Payload.MediaAnalyze.Task = vcp.MediaAnalyzeModerate
	if _, errExecute := driver.Execute(context.Background(), execution); !errors.Is(errExecute, ErrUnsupportedMediaAnalyzeInput) {
		t.Fatalf("Execute() error = %v, want ErrUnsupportedMediaAnalyzeInput", errExecute)
	}
}

// newMediaAnalyzeExecution constructs one exact action target with a Router-materialized image.
// newMediaAnalyzeExecution 构建一个带 Router 已物化图片的精确动作 Target。
func newMediaAnalyzeExecution(t *testing.T, baseURL string) (*MediaAnalyzeActionDriver, provider.ExecutionRequest) {
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
	driver, errDriver := NewMediaAnalyzeDriver("definition-google", client)
	if errDriver != nil {
		t.Fatalf("NewMediaAnalyzeDriver() error = %v", errDriver)
	}
	definition := providerconfig.ProviderDefinition{ID: "definition-google", Kind: providerconfig.DefinitionKindSystem, ProtocolProfileID: aistudio.ProfileID, AuthMethodIDs: []string{"api_key"}, RuntimeReady: true, AuthMethods: []providerconfig.AuthMethodDefinition{{ID: "api_key", Type: providerconfig.AuthMethodAPIKey}}, ActionBindings: []providerconfig.ProviderActionBinding{{ID: MediaAnalyzeActionBindingID, Operation: vcp.OperationMediaAnalyze, DriverID: "aistudio", DriverVersion: "1", ProtocolProfileID: MediaAnalyzeProtocolProfileID, EndpointProfileID: "google_ai_studio", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, Revision: 1}}, Revision: 1}
	target := resolve.Target{SubjectKind: resolve.ExecutionSubjectModel, ProviderDefinitionID: definition.ID, ProviderInstanceID: "instance-google", ChannelID: aistudio.ProfileID, EndpointID: "endpoint-google", CredentialID: "credential-google", ProviderModelID: "model-gemini-2-5-flash", OfferingID: "offering-gemini-media", ExecutionProfileID: "profile-gemini-media", UpstreamModelID: "gemini-2.5-flash", Operation: vcp.OperationMediaAnalyze, ActionBindingID: MediaAnalyzeActionBindingID, CatalogRevision: 1}
	request := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request-media", Target: vcp.TargetSelection{Model: &vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: target.ProviderInstanceID, ProviderModelID: target.ProviderModelID, ExecutionProfileID: target.ExecutionProfileID}}, Operation: vcp.OperationMediaAnalyze, Payload: vcp.OperationPayload{MediaAnalyze: &vcp.MediaAnalyzeOperation{Task: vcp.MediaAnalyzeDescribe, Inputs: []vcp.MediaInput{{ID: "image-1", Kind: vcp.MediaImage, Role: vcp.MediaRoleUnderstanding, Resource: vcp.ResourceReference{ResourceID: "resource-image-1"}}}}}}
	execution := provider.ExecutionRequest{Binding: transport.Binding{Target: target, Endpoint: providerconfig.Endpoint{ID: target.EndpointID, ProviderInstanceID: target.ProviderInstanceID, ChannelID: target.ChannelID, BaseURL: baseURL, Status: providerconfig.EndpointReady}, Credential: providerconfig.Credential{ID: target.CredentialID, ProviderInstanceID: target.ProviderInstanceID, AuthMethodID: "api_key", SecretRef: secretReference, Status: providerconfig.CredentialActive}}, Definition: definition, Execution: &request, MaterializedInputs: []resource.MaterializedInput{{InputID: "image-1", ResourceID: "resource-image-1", Kind: vcp.MediaImage, Role: vcp.MediaRoleUnderstanding, MIMEType: "image/png", Mode: "inline_base64", InlineBase64: "aW1hZ2U="}}, LineageID: "lineage-media", Now: time.Date(2026, time.July, 20, 0, 0, 0, 0, time.UTC)}
	return driver, execution
}
