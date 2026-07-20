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

// TestInteractionsImageGenerationUsesRawRESTTimeline verifies the current request and raw model-output image response.
// TestInteractionsImageGenerationUsesRawRESTTimeline 验证当前请求及原始模型输出图片响应。
func TestInteractionsImageGenerationUsesRawRESTTimeline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1beta/interactions" || request.Header.Get("X-Goog-Api-Key") != "test-secret" {
			t.Errorf("request = %s %s api-key=%q", request.Method, request.URL.Path, request.Header.Get("X-Goog-Api-Key"))
		}
		var upstream interactionsImageRequest
		if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil {
			t.Errorf("decode request: %v", errDecode)
		}
		if upstream.Model != "gemini-3.1-flash-image" || len(upstream.Input) != 1 || upstream.Input[0].Type != "text" || upstream.Input[0].Text != "A coral reef" || upstream.ResponseFormat.Type != "image" || upstream.ResponseFormat.MIMEType != "image/png" || upstream.ResponseFormat.AspectRatio != "16:9" || upstream.ResponseFormat.ImageSize != "2K" {
			t.Errorf("upstream = %#v", upstream)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"id":"interaction-image","status":"completed","steps":[{"type":"model_output","content":[{"type":"text","text":"done"},{"type":"image","mime_type":"image/png","data":"aW1hZ2U="}]}]}`)
	}))
	defer server.Close()

	driver, execution := newInteractionsImageExecution(t, server.URL, ImageGenerateActionBindingID, vcp.OperationImageGenerate)
	execution.Execution.Payload.ImageGenerate = &vcp.ImageGenerateOperation{Prompt: "A coral reef", Count: 1, AspectRatio: "16:9", Resolution: "2k", OutputFormat: "png"}
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if result.UpstreamResponseID != "interaction-image" || len(result.GeneratedResources) != 1 || string(result.GeneratedResources[0].Data) != "image" || result.GeneratedResources[0].MIMEType != "image/png" || result.GeneratedResources[0].DownloadURL != "" {
		t.Fatalf("result = %#v", result)
	}
}

// TestInteractionsImageEditPreservesInlineAndDirectURISources verifies ordered Interactions image inputs.
// TestInteractionsImageEditPreservesInlineAndDirectURISources 验证有序 Interactions 图片输入。
func TestInteractionsImageEditPreservesInlineAndDirectURISources(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var upstream interactionsImageRequest
		if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil {
			t.Errorf("decode request: %v", errDecode)
		}
		if len(upstream.Input) != 3 || upstream.Input[0].Text != "Combine the subjects" || upstream.Input[1].Data != "c291cmNl" || upstream.Input[1].MIMEType != "image/png" || upstream.Input[2].URI != "https://inputs.example/reference.webp" || upstream.Input[2].MIMEType != "image/webp" {
			t.Errorf("input = %#v", upstream.Input)
		}
		_, _ = io.WriteString(writer, `{"id":"interaction-edit","status":"completed","steps":[{"type":"model_output","content":[{"type":"image","mime_type":"image/jpeg","uri":"https://result.example/edit.jpg"}]}]}`)
	}))
	defer server.Close()

	driver, execution := newInteractionsImageExecution(t, server.URL, ImageEditActionBindingID, vcp.OperationImageEdit)
	execution.Execution.Payload.ImageEdit = &vcp.ImageEditOperation{Instruction: "Combine the subjects", Count: 1, OutputFormat: "jpeg", Sources: []vcp.MediaInput{
		{ID: "source-one", Kind: vcp.MediaImage, Role: vcp.MediaRoleEditSource, Resource: vcp.ResourceReference{ResourceID: "resource-one"}},
		{ID: "source-two", Kind: vcp.MediaImage, Role: vcp.MediaRoleEditSource, Resource: vcp.ResourceReference{ResourceID: "resource-two"}},
	}}
	execution.MaterializedInputs = []resource.MaterializedInput{
		{InputID: "source-one", ResourceID: "resource-one", Kind: vcp.MediaImage, Role: vcp.MediaRoleEditSource, MIMEType: "image/png", Mode: catalog.MaterializationInlineBase64, InlineBase64: "c291cmNl"},
		{InputID: "source-two", ResourceID: "resource-two", Kind: vcp.MediaImage, Role: vcp.MediaRoleEditSource, MIMEType: "image/webp", Mode: catalog.MaterializationDirectRemoteURL, RemoteURL: "https://inputs.example/reference.webp"},
	}
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if len(result.GeneratedResources) != 1 || result.GeneratedResources[0].DownloadURL != "https://result.example/edit.jpg" || result.GeneratedResources[0].MIMEType != "image/jpeg" {
		t.Fatalf("generated resources = %#v", result.GeneratedResources)
	}
}

// TestInteractionsImageRejectsUnsupportedMask verifies missing wire semantics fail before execution.
// TestInteractionsImageRejectsUnsupportedMask 验证缺少线路语义时会在执行前失败。
func TestInteractionsImageRejectsUnsupportedMask(t *testing.T) {
	driver, execution := newInteractionsImageExecution(t, "https://generativelanguage.googleapis.com", ImageEditActionBindingID, vcp.OperationImageEdit)
	execution.Execution.Payload.ImageEdit = &vcp.ImageEditOperation{Instruction: "Masked edit", Sources: []vcp.MediaInput{{ID: "mask", Kind: vcp.MediaImage, Role: vcp.MediaRoleMask, Resource: vcp.ResourceReference{ResourceID: "resource-mask"}}}}
	execution.MaterializedInputs = []resource.MaterializedInput{{InputID: "mask", ResourceID: "resource-mask", Kind: vcp.MediaImage, Role: vcp.MediaRoleMask, MIMEType: "image/png", Mode: catalog.MaterializationInlineBase64, InlineBase64: "bWFzaw=="}}
	if _, errExecute := driver.Execute(context.Background(), execution); errExecute == nil || !strings.Contains(errExecute.Error(), "edit_source") {
		t.Fatalf("Execute() error = %v", errExecute)
	}
}

// newInteractionsImageExecution builds one exact Google Interactions image action fixture.
// newInteractionsImageExecution 构建一个精确 Google Interactions 图片动作夹具。
func newInteractionsImageExecution(t *testing.T, baseURL string, actionBindingID string, operation vcp.OperationKind) (*InteractionsImageActionDriver, provider.ExecutionRequest) {
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
	driver, errDriver := NewInteractionsImageActionDriver("definition-google", actionBindingID, client)
	if errDriver != nil {
		t.Fatalf("NewInteractionsImageActionDriver() error = %v", errDriver)
	}
	profileID := ImageGenerateProtocolProfileID
	if operation == vcp.OperationImageEdit {
		profileID = ImageEditProtocolProfileID
	}
	action := providerconfig.ProviderActionBinding{ID: actionBindingID, Operation: operation, DriverID: "interactions", DriverVersion: "1", ProtocolProfileID: profileID, EndpointProfileID: "google_interactions_image", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, ResourceMaterialization: []providerconfig.ResourceMaterializationMode{providerconfig.ResourceMaterializationInline, providerconfig.ResourceMaterializationDirectURL}, Revision: 1}
	definition := providerconfig.ProviderDefinition{ID: "definition-google", Kind: providerconfig.DefinitionKindSystem, ProtocolProfileID: "google.interactions", AuthMethodIDs: []string{"api_key"}, RuntimeReady: true, AuthMethods: []providerconfig.AuthMethodDefinition{{ID: "api_key", Type: providerconfig.AuthMethodAPIKey}}, ActionBindings: []providerconfig.ProviderActionBinding{action}, Revision: 1}
	target := resolve.Target{SubjectKind: resolve.ExecutionSubjectModel, ProviderDefinitionID: definition.ID, ProviderInstanceID: "instance-google", ChannelID: profileID, EndpointID: "endpoint-google", CredentialID: "credential-google", ProviderModelID: "model-gemini-image", OfferingID: "offering-gemini-image", ExecutionProfileID: "profile-gemini-image", UpstreamModelID: "gemini-3.1-flash-image", Operation: operation, ActionBindingID: actionBindingID, CatalogRevision: 1}
	request := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request-image", Target: vcp.TargetSelection{Model: &vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: target.ProviderInstanceID, ProviderModelID: target.ProviderModelID, ExecutionProfileID: target.ExecutionProfileID}}, Operation: operation}
	execution := provider.ExecutionRequest{Binding: transport.Binding{Target: target, Endpoint: providerconfig.Endpoint{ID: target.EndpointID, ProviderInstanceID: target.ProviderInstanceID, ChannelID: target.ChannelID, BaseURL: baseURL, Status: providerconfig.EndpointReady}, Credential: providerconfig.Credential{ID: target.CredentialID, ProviderInstanceID: target.ProviderInstanceID, AuthMethodID: "api_key", SecretRef: secretReference, Status: providerconfig.CredentialActive}}, Definition: definition, Execution: &request, LineageID: "lineage-image", Now: time.Date(2026, time.July, 20, 0, 0, 0, 0, time.UTC)}
	return driver, execution
}
