package openai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	protocolresponses "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/responses"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestImageGenerateDriverReturnsPrivateRouterIngestionBytes verifies OpenAI Base64 never enters public protocol output directly.
// TestImageGenerateDriverReturnsPrivateRouterIngestionBytes 验证 OpenAI Base64 不会直接进入公共协议输出。
func TestImageGenerateDriverReturnsPrivateRouterIngestionBytes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/images/generations" || request.Header.Get("Authorization") != "Bearer test-secret" {
			t.Errorf("request = %s %s authorization=%q", request.Method, request.URL.Path, request.Header.Get("Authorization"))
		}
		var upstream openAIImageRequest
		if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil {
			t.Errorf("decode request: %v", errDecode)
		}
		if upstream.Model != "gpt-image-2" || upstream.Prompt != "A blue square" || upstream.Size != "1024x1024" || upstream.OutputFormat != "jpeg" || upstream.Quality != "high" || upstream.Background != "opaque" {
			t.Errorf("upstream = %#v", upstream)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"data":[{"b64_json":"aW1hZ2U="}]}`)
	}))
	defer server.Close()

	driver, execution := newOpenAIImageExecution(t, server.URL, ImageGenerateActionBindingID, vcp.OperationImageGenerate)
	execution.Execution.Payload.ImageGenerate = &vcp.ImageGenerateOperation{Prompt: "A blue square", Count: 1, Width: 1024, Height: 1024, Quality: "high", Background: "opaque", OutputFormat: "jpeg"}
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if len(result.GeneratedResources) != 1 || string(result.GeneratedResources[0].Data) != "image" || result.GeneratedResources[0].DownloadURL != "" || result.GeneratedResources[0].MIMEType != "image/jpeg" {
		t.Fatalf("generated resources = %#v", result.GeneratedResources)
	}
}

// TestImageEditDriverPreservesSourceAndMaskRoles verifies multipart fields follow explicit VCP media roles.
// TestImageEditDriverPreservesSourceAndMaskRoles 验证 Multipart 字段遵循显式 VCP 媒体角色。
func TestImageEditDriverPreservesSourceAndMaskRoles(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/images/edits" {
			t.Errorf("path = %q", request.URL.Path)
		}
		if errParse := request.ParseMultipartForm(1 << 20); errParse != nil {
			t.Errorf("ParseMultipartForm() error = %v", errParse)
		}
		if request.FormValue("model") != "gpt-image-2" || request.FormValue("prompt") != "Remove the background" || request.FormValue("size") != "1024x1536" || request.FormValue("quality") != "medium" || len(request.MultipartForm.File["image[]"]) != 1 || len(request.MultipartForm.File["mask"]) != 1 {
			t.Errorf("multipart form = %#v", request.MultipartForm)
		}
		_, _ = io.WriteString(writer, `{"data":[{"url":"https://cdn.openai.example/output.png"}]}`)
	}))
	defer server.Close()

	driver, execution := newOpenAIImageExecution(t, server.URL, ImageEditActionBindingID, vcp.OperationImageEdit)
	execution.Execution.Payload.ImageEdit = &vcp.ImageEditOperation{Instruction: "Remove the background", Count: 1, Width: 1024, Height: 1536, Quality: "medium", Sources: []vcp.MediaInput{
		{ID: "source", Kind: vcp.MediaImage, Role: vcp.MediaRoleEditSource, Resource: vcp.ResourceReference{ResourceID: "resource-source"}},
		{ID: "mask", Kind: vcp.MediaImage, Role: vcp.MediaRoleMask, Resource: vcp.ResourceReference{ResourceID: "resource-mask"}},
	}}
	execution.MaterializedInputs = []resource.MaterializedInput{
		{InputID: "source", ResourceID: "resource-source", Kind: vcp.MediaImage, Role: vcp.MediaRoleEditSource, MIMEType: "image/png", Mode: "inline_base64", InlineBase64: "c291cmNl"},
		{InputID: "mask", ResourceID: "resource-mask", Kind: vcp.MediaImage, Role: vcp.MediaRoleMask, MIMEType: "image/png", Mode: "inline_base64", InlineBase64: "bWFzaw=="},
	}
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if len(result.GeneratedResources) != 1 || !strings.HasSuffix(result.GeneratedResources[0].DownloadURL, "/output.png") || len(result.GeneratedResources[0].Data) != 0 {
		t.Fatalf("generated resources = %#v", result.GeneratedResources)
	}
}

// newOpenAIImageExecution builds one exact action execution fixture.
// newOpenAIImageExecution 构建一个精确动作执行夹具。
func newOpenAIImageExecution(t *testing.T, baseURL string, actionBindingID string, operation vcp.OperationKind) (*ImageActionDriver, provider.ExecutionRequest) {
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
	driver, errDriver := NewImageActionDriver("definition-openai", actionBindingID, client)
	if errDriver != nil {
		t.Fatalf("NewImageActionDriver() error = %v", errDriver)
	}
	profileID := ImageGenerateProtocolProfileID
	if operation == vcp.OperationImageEdit {
		profileID = ImageEditProtocolProfileID
	}
	action := providerconfig.ProviderActionBinding{ID: actionBindingID, Operation: operation, DriverID: "openai", DriverVersion: "1", ProtocolProfileID: profileID, EndpointProfileID: "openai_images", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, Revision: 1}
	definition := providerconfig.ProviderDefinition{ID: "definition-openai", Kind: providerconfig.DefinitionKindSystem, ProtocolProfileID: protocolresponses.ProfileID, AuthMethodIDs: []string{"api_key"}, RuntimeReady: true, AuthMethods: []providerconfig.AuthMethodDefinition{{ID: "api_key", Type: providerconfig.AuthMethodAPIKey}}, ActionBindings: []providerconfig.ProviderActionBinding{action}, Revision: 1}
	target := resolve.Target{SubjectKind: resolve.ExecutionSubjectModel, ProviderDefinitionID: definition.ID, ProviderInstanceID: "instance-openai", ChannelID: protocolresponses.ProfileID, EndpointID: "endpoint-openai", CredentialID: "credential-openai", ProviderModelID: "model-gpt-image-2", OfferingID: "offering-gpt-image-2", ExecutionProfileID: "profile-gpt-image-2", UpstreamModelID: "gpt-image-2", Operation: operation, ActionBindingID: actionBindingID, CatalogRevision: 1}
	request := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request-image", Target: vcp.TargetSelection{Model: &vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: target.ProviderInstanceID, ProviderModelID: target.ProviderModelID, ExecutionProfileID: target.ExecutionProfileID}}, Operation: operation}
	execution := provider.ExecutionRequest{Binding: transport.Binding{Target: target, Endpoint: providerconfig.Endpoint{ID: target.EndpointID, ProviderInstanceID: target.ProviderInstanceID, ChannelID: target.ChannelID, BaseURL: baseURL, Status: providerconfig.EndpointReady}, Credential: providerconfig.Credential{ID: target.CredentialID, ProviderInstanceID: target.ProviderInstanceID, AuthMethodID: "api_key", SecretRef: secretReference, Status: providerconfig.CredentialActive}}, Definition: definition, Execution: &request, LineageID: "lineage-image", Now: time.Date(2026, time.July, 20, 0, 0, 0, 0, time.UTC)}
	return driver, execution
}
