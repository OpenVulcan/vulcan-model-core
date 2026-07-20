package xai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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

// TestXAIImageGenerationUsesImagineJSON verifies exact batch, ratio, resolution, and Base64 output semantics.
// TestXAIImageGenerationUsesImagineJSON 验证精确批量、长宽比、分辨率及 Base64 输出语义。
func TestXAIImageGenerationUsesImagineJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/images/generations" || request.Header.Get("Authorization") != "Bearer test-secret" {
			t.Errorf("request path=%q authorization=%q", request.URL.Path, request.Header.Get("Authorization"))
		}
		var upstream imageRequest
		if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil {
			t.Errorf("decode request: %v", errDecode)
		}
		if upstream.Model != "grok-imagine-image-quality" || upstream.Prompt != "A city at night" || upstream.Count != 4 || upstream.AspectRatio != "16:9" || upstream.Resolution != "2k" || upstream.ResponseFormat != "b64_json" {
			t.Errorf("upstream = %#v", upstream)
		}
		_, _ = io.WriteString(writer, `{"data":[{"b64_json":"aW1hZ2U=","mime_type":"image/jpeg"}]}`)
	}))
	defer server.Close()

	driver, execution := newXAIImageExecution(t, server.URL, ImageGenerateActionBindingID, vcp.OperationImageGenerate)
	execution.Execution.Payload.ImageGenerate = &vcp.ImageGenerateOperation{Prompt: "A city at night", Count: 4, AspectRatio: "16:9", Resolution: "2k", OutputFormat: "jpeg"}
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if len(result.GeneratedResources) != 1 || string(result.GeneratedResources[0].Data) != "image" || result.GeneratedResources[0].MIMEType != "image/jpeg" {
		t.Fatalf("generated resources = %#v", result.GeneratedResources)
	}
}

// TestXAIImageEditUsesSingularAndPluralJSONCarriers verifies ordered inline and direct image sources.
// TestXAIImageEditUsesSingularAndPluralJSONCarriers 验证有序内联及直连图片来源。
func TestXAIImageEditUsesSingularAndPluralJSONCarriers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/images/edits" {
			t.Errorf("request path = %q", request.URL.Path)
		}
		var upstream imageRequest
		if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil {
			t.Errorf("decode request: %v", errDecode)
		}
		if upstream.Image != nil || len(upstream.Images) != 2 || upstream.Images[0].URL != "data:image/png;base64,c291cmNl" || upstream.Images[1].URL != "https://inputs.example/reference.jpg" || upstream.AspectRatio != "3:2" {
			t.Errorf("upstream = %#v", upstream)
		}
		_, _ = io.WriteString(writer, `{"data":[{"b64_json":"ZWRpdA==","mime_type":"image/jpeg"}]}`)
	}))
	defer server.Close()

	driver, execution := newXAIImageExecution(t, server.URL, ImageEditActionBindingID, vcp.OperationImageEdit)
	execution.Execution.Payload.ImageEdit = &vcp.ImageEditOperation{Instruction: "Combine the subjects", Count: 1, AspectRatio: "3:2", OutputFormat: "jpeg", Sources: []vcp.MediaInput{
		{ID: "source-one", Kind: vcp.MediaImage, Role: vcp.MediaRoleEditSource, Resource: vcp.ResourceReference{ResourceID: "resource-one"}},
		{ID: "source-two", Kind: vcp.MediaImage, Role: vcp.MediaRoleEditSource, Resource: vcp.ResourceReference{ResourceID: "resource-two"}},
	}}
	execution.MaterializedInputs = []resource.MaterializedInput{
		{InputID: "source-one", ResourceID: "resource-one", Kind: vcp.MediaImage, Role: vcp.MediaRoleEditSource, MIMEType: "image/png", Mode: catalog.MaterializationInlineBase64, InlineBase64: "c291cmNl"},
		{InputID: "source-two", ResourceID: "resource-two", Kind: vcp.MediaImage, Role: vcp.MediaRoleEditSource, MIMEType: "image/jpeg", Mode: catalog.MaterializationDirectRemoteURL, RemoteURL: "https://inputs.example/reference.jpg"},
	}
	if _, errExecute := driver.Execute(context.Background(), execution); errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
}

// newXAIImageExecution builds one exact xAI image action fixture.
// newXAIImageExecution 构建一个精确 xAI 图片动作夹具。
func newXAIImageExecution(t *testing.T, baseURL string, actionBindingID string, operation vcp.OperationKind) (*ImageActionDriver, provider.ExecutionRequest) {
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
	driver, errDriver := NewImageActionDriver("definition-xai", actionBindingID, client)
	if errDriver != nil {
		t.Fatalf("NewImageActionDriver() error = %v", errDriver)
	}
	profileID := ImageGenerateProtocolProfileID
	if operation == vcp.OperationImageEdit {
		profileID = ImageEditProtocolProfileID
	}
	action := providerconfig.ProviderActionBinding{ID: actionBindingID, Operation: operation, DriverID: "xai", DriverVersion: "1", ProtocolProfileID: profileID, EndpointProfileID: "xai_images", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, ResourceMaterialization: []providerconfig.ResourceMaterializationMode{providerconfig.ResourceMaterializationInline, providerconfig.ResourceMaterializationDirectURL}, Revision: 1}
	definition := providerconfig.ProviderDefinition{ID: "definition-xai", Kind: providerconfig.DefinitionKindSystem, ProtocolProfileID: "xai.responses", AuthMethodIDs: []string{"api_key"}, RuntimeReady: true, AuthMethods: []providerconfig.AuthMethodDefinition{{ID: "api_key", Type: providerconfig.AuthMethodAPIKey}}, ActionBindings: []providerconfig.ProviderActionBinding{action}, Revision: 1}
	target := resolve.Target{SubjectKind: resolve.ExecutionSubjectModel, ProviderDefinitionID: definition.ID, ProviderInstanceID: "instance-xai", ChannelID: profileID, EndpointID: "endpoint-xai", CredentialID: "credential-xai", ProviderModelID: "model-xai-image", OfferingID: "offering-xai-image", ExecutionProfileID: "profile-xai-image", UpstreamModelID: "grok-imagine-image-quality", Operation: operation, ActionBindingID: actionBindingID, CatalogRevision: 1}
	request := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request-image", Target: vcp.TargetSelection{Model: &vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: target.ProviderInstanceID, ProviderModelID: target.ProviderModelID, ExecutionProfileID: target.ExecutionProfileID}}, Operation: operation}
	execution := provider.ExecutionRequest{Binding: transport.Binding{Target: target, Endpoint: providerconfig.Endpoint{ID: target.EndpointID, ProviderInstanceID: target.ProviderInstanceID, ChannelID: target.ChannelID, BaseURL: baseURL, Status: providerconfig.EndpointReady}, Credential: providerconfig.Credential{ID: target.CredentialID, ProviderInstanceID: target.ProviderInstanceID, AuthMethodID: "api_key", SecretRef: secretReference, Status: providerconfig.CredentialActive}}, Definition: definition, Execution: &request, LineageID: "lineage-image", Now: time.Date(2026, time.July, 20, 0, 0, 0, 0, time.UTC)}
	return driver, execution
}
