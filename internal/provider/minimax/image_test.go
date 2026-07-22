package minimax

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

// TestMiniMaxImageGenerationDecodesURLAcquisition verifies the official URL response carrier remains private for Router import.
// TestMiniMaxImageGenerationDecodesURLAcquisition 验证官方 URL 响应载体保持私有并供 Router 导入。
func TestMiniMaxImageGenerationDecodesURLAcquisition(t *testing.T) {
	result, errDecode := decodeImageResponse(strings.NewReader(`{"data":{"task_id":"minimax-url-trace","success_count":1,"failed_count":0,"image_urls":["https://outputs.example/image.jpg"]},"base_resp":{"status_code":0}}`))
	if errDecode != nil {
		t.Fatalf("decodeImageResponse() error = %v", errDecode)
	}
	if result.UpstreamResponseID != "minimax-url-trace" || len(result.GeneratedResources) != 1 || result.GeneratedResources[0].DownloadURL != "https://outputs.example/image.jpg" || len(result.GeneratedResources[0].Data) != 0 {
		t.Fatalf("result = %#v", result)
	}
}

// TestMiniMaxImageGenerationPreservesExactReferenceAndBase64Contract verifies official request and response fields.
// TestMiniMaxImageGenerationPreservesExactReferenceAndBase64Contract 验证官方请求与响应字段。
func TestMiniMaxImageGenerationPreservesExactReferenceAndBase64Contract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/image_generation" || request.Header.Get("Authorization") != "Bearer test-secret" {
			t.Errorf("request path=%q authorization=%q", request.URL.Path, request.Header.Get("Authorization"))
		}
		var upstream imageRequest
		if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil {
			t.Errorf("decode request: %v", errDecode)
		}
		if upstream.Model != "image-01" || upstream.Prompt != "A character in a library" || upstream.AspectRatio != "16:9" || upstream.Count != 2 || upstream.ResponseFormat != "base64" || upstream.PromptOptimizer == nil || !*upstream.PromptOptimizer || upstream.Watermark == nil || !*upstream.Watermark || len(upstream.SubjectReference) != 1 || upstream.SubjectReference[0].Type != "character" || upstream.SubjectReference[0].ImageURL != "https://inputs.example/character.jpg" || upstream.SubjectReference[0].ImageFile != "" {
			t.Errorf("upstream = %#v", upstream)
		}
		_, _ = io.WriteString(writer, `{"data":{"task_id":"minimax-trace","success_count":1,"failed_count":1,"image_base64":["aW1hZ2U="]},"base_resp":{"status_code":0,"status_msg":"success"}}`)
	}))
	defer server.Close()

	driver, execution := newMiniMaxImageExecution(t, server.URL)
	enabled := true
	execution.Execution.Payload.ImageGenerate = &vcp.ImageGenerateOperation{Prompt: "A character in a library", Count: 2, AspectRatio: "16:9", OutputFormat: "jpeg", PromptExtend: &enabled, Watermark: &enabled, References: []vcp.MediaInput{{ID: "character", Kind: vcp.MediaImage, Role: vcp.MediaRoleReference, Resource: vcp.ResourceReference{ResourceID: "resource-character"}}}}
	execution.MaterializedInputs = []resource.MaterializedInput{{InputID: "character", ResourceID: "resource-character", Kind: vcp.MediaImage, Role: vcp.MediaRoleReference, MIMEType: "image/jpeg", Mode: catalog.MaterializationDirectRemoteURL, RemoteURL: "https://inputs.example/character.jpg"}}
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if result.UpstreamResponseID != "minimax-trace" || len(result.GeneratedResources) != 1 || string(result.GeneratedResources[0].Data) != "image" || result.GeneratedResources[0].MIMEType != "image/jpeg" {
		t.Fatalf("result = %#v", result)
	}
}

// TestMiniMaxImageGenerationPreservesInlineSubjectReference verifies minimax-cli's image_file data-URI carrier.
// TestMiniMaxImageGenerationPreservesInlineSubjectReference 验证 minimax-cli 的 image_file Data URI 载体。
func TestMiniMaxImageGenerationPreservesInlineSubjectReference(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var upstream imageRequest
		if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil {
			t.Errorf("decode request: %v", errDecode)
		}
		if len(upstream.SubjectReference) != 1 || upstream.SubjectReference[0].ImageURL != "" || upstream.SubjectReference[0].ImageFile != "data:image/png;base64,aW1hZ2U=" {
			t.Errorf("subject reference = %#v", upstream.SubjectReference)
		}
		_, _ = io.WriteString(writer, `{"data":{"task_id":"minimax-inline-trace","success_count":1,"failed_count":0,"image_base64":["aW1hZ2U="]},"base_resp":{"status_code":0}}`)
	}))
	defer server.Close()

	driver, execution := newMiniMaxImageExecution(t, server.URL)
	execution.Execution.Payload.ImageGenerate = &vcp.ImageGenerateOperation{Prompt: "Keep this character", References: []vcp.MediaInput{{ID: "character", Kind: vcp.MediaImage, Role: vcp.MediaRoleReference, Resource: vcp.ResourceReference{ResourceID: "resource-character"}}}}
	execution.MaterializedInputs = []resource.MaterializedInput{{InputID: "character", ResourceID: "resource-character", Kind: vcp.MediaImage, Role: vcp.MediaRoleReference, MIMEType: "image/png", Mode: catalog.MaterializationInlineBase64, InlineBase64: "aW1hZ2U="}}
	if _, errExecute := driver.Execute(context.Background(), execution); errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
}

// TestMiniMaxImageGenerationDefaultsToOneOutput verifies the pinned CLI n default is projected explicitly.
// TestMiniMaxImageGenerationDefaultsToOneOutput 验证固定 CLI 的 n 默认值会被明确投影。
func TestMiniMaxImageGenerationDefaultsToOneOutput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var upstream imageRequest
		if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil || upstream.Count != 1 {
			t.Errorf("request = %#v, error = %v", upstream, errDecode)
		}
		_, _ = io.WriteString(writer, `{"data":{"task_id":"minimax-default-trace","success_count":1,"failed_count":0,"image_base64":["aW1hZ2U="]},"base_resp":{"status_code":0}}`)
	}))
	defer server.Close()

	driver, execution := newMiniMaxImageExecution(t, server.URL)
	execution.Execution.Payload.ImageGenerate = &vcp.ImageGenerateOperation{Prompt: "One image"}
	if _, errExecute := driver.Execute(context.Background(), execution); errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
}

// newMiniMaxImageExecution builds one exact MiniMax generation fixture.
// newMiniMaxImageExecution 构建一个精确 MiniMax 生成夹具。
func newMiniMaxImageExecution(t *testing.T, baseURL string) (*ImageActionDriver, provider.ExecutionRequest) {
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
	driver, errDriver := NewImageActionDriver("definition-minimax", client)
	if errDriver != nil {
		t.Fatalf("NewImageActionDriver() error = %v", errDriver)
	}
	action := providerconfig.ProviderActionBinding{ID: ImageGenerateActionBindingID, Operation: vcp.OperationImageGenerate, DriverID: "minimax", DriverVersion: "1", ProtocolProfileID: ImageGenerateProtocolProfileID, EndpointProfileID: "minimax_image", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, ResourceMaterialization: []providerconfig.ResourceMaterializationMode{providerconfig.ResourceMaterializationInline, providerconfig.ResourceMaterializationDirectURL}, Revision: 1}
	definition := providerconfig.ProviderDefinition{ID: "definition-minimax", Kind: providerconfig.DefinitionKindSystem, ProtocolProfileID: ImageGenerateProtocolProfileID, AuthMethodIDs: []string{"api_key"}, RuntimeReady: true, AuthMethods: []providerconfig.AuthMethodDefinition{{ID: "api_key", Type: providerconfig.AuthMethodAPIKey}}, ActionBindings: []providerconfig.ProviderActionBinding{action}, Revision: 1}
	target := resolve.Target{SubjectKind: resolve.ExecutionSubjectModel, ProviderDefinitionID: definition.ID, ProviderInstanceID: "instance-minimax", ChannelID: ImageGenerateProtocolProfileID, EndpointID: "endpoint-minimax", CredentialID: "credential-minimax", ProviderModelID: "model-image-01", OfferingID: "offering-image-01", ExecutionProfileID: "profile-image-01", UpstreamModelID: "image-01", Operation: vcp.OperationImageGenerate, ActionBindingID: ImageGenerateActionBindingID, CatalogRevision: 1}
	request := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request-image", Target: vcp.TargetSelection{Model: &vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: target.ProviderInstanceID, ProviderModelID: target.ProviderModelID, ExecutionProfileID: target.ExecutionProfileID}}, Operation: vcp.OperationImageGenerate}
	execution := provider.ExecutionRequest{Binding: transport.Binding{Target: target, Endpoint: providerconfig.Endpoint{ID: target.EndpointID, ProviderInstanceID: target.ProviderInstanceID, ChannelID: target.ChannelID, BaseURL: baseURL, Status: providerconfig.EndpointReady}, Credential: providerconfig.Credential{ID: target.CredentialID, ProviderInstanceID: target.ProviderInstanceID, AuthMethodID: "api_key", SecretRef: secretReference, Status: providerconfig.CredentialActive}}, Definition: definition, Execution: &request, LineageID: "lineage-image", Now: time.Date(2026, time.July, 20, 0, 0, 0, 0, time.UTC)}
	return driver, execution
}
