package alibaba

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

// TestWanImageGenerationPreservesOrderedReferences verifies the exact synchronous workspace request and private output URL.
// TestWanImageGenerationPreservesOrderedReferences 验证精确同步工作区请求与私有输出 URL。
func TestWanImageGenerationPreservesOrderedReferences(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/api/v1/services/aigc/multimodal-generation/generation" || request.Header.Get("Authorization") != "Bearer test-secret" {
			t.Errorf("request = %s %s authorization=%q", request.Method, request.URL.Path, request.Header.Get("Authorization"))
		}
		var upstream wanImageRequest
		if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil {
			t.Errorf("decode request: %v", errDecode)
		}
		content := upstream.Input.Messages[0].Content
		if upstream.Model != "wan2.7-image-pro" || len(content) != 3 || content[0].Image != "data:image/png;base64,cmVmMQ==" || content[1].Image != "https://inputs.example/reference.webp" || content[2].Text != "Keep both subjects" || upstream.Parameters.Size != "2K" || upstream.Parameters.Count != 2 {
			t.Errorf("upstream = %#v", upstream)
		}
		_, _ = io.WriteString(writer, "{\"request_id\":\"request-wan\",\"output\":{\"choices\":[{\"message\":{\"content\":[{\"type\":\"image\",\"image\":\"https://result.example/wan.png?Expires=1\"}]}}]}}")
	}))
	defer server.Close()

	driver, execution := newAlibabaWanImageExecution(t, server.URL, WanImageGenerateActionBindingID, vcp.OperationImageGenerate, "wan2.7-image-pro")
	execution.Execution.Payload.ImageGenerate = &vcp.ImageGenerateOperation{Prompt: "Keep both subjects", Count: 2, Resolution: "2k", OutputFormat: "png", References: []vcp.MediaInput{
		{ID: "reference-one", Kind: vcp.MediaImage, Role: vcp.MediaRoleReference, Resource: vcp.ResourceReference{ResourceID: "resource-one"}},
		{ID: "reference-two", Kind: vcp.MediaImage, Role: vcp.MediaRoleReference, Resource: vcp.ResourceReference{ResourceID: "resource-two"}},
	}}
	execution.MaterializedInputs = []resource.MaterializedInput{
		{InputID: "reference-one", ResourceID: "resource-one", Kind: vcp.MediaImage, Role: vcp.MediaRoleReference, MIMEType: "image/png", Mode: "inline_base64", InlineBase64: "cmVmMQ=="},
		{InputID: "reference-two", ResourceID: "resource-two", Kind: vcp.MediaImage, Role: vcp.MediaRoleReference, MIMEType: "image/webp", Mode: "direct_remote_url", RemoteURL: "https://inputs.example/reference.webp"},
	}
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if result.UpstreamResponseID != "request-wan" || len(result.GeneratedResources) != 1 || result.GeneratedResources[0].MIMEType != "image/png" || !strings.Contains(result.GeneratedResources[0].DownloadURL, "wan.png") {
		t.Fatalf("result = %#v", result)
	}
}

// TestWanImageEditRejectsFourK verifies the documented image-input resolution restriction.
// TestWanImageEditRejectsFourK 验证文档明确的图片输入分辨率限制。
func TestWanImageEditRejectsFourK(t *testing.T) {
	driver, execution := newAlibabaWanImageExecution(t, "https://workspace.example", WanImageEditActionBindingID, vcp.OperationImageEdit, "wan2.7-image-pro")
	execution.Execution.Payload.ImageEdit = &vcp.ImageEditOperation{Instruction: "Retouch", Resolution: "4k", Sources: []vcp.MediaInput{{ID: "source", Kind: vcp.MediaImage, Role: vcp.MediaRoleEditSource, Resource: vcp.ResourceReference{ResourceID: "resource-source"}}}}
	execution.MaterializedInputs = []resource.MaterializedInput{{InputID: "source", ResourceID: "resource-source", Kind: vcp.MediaImage, Role: vcp.MediaRoleEditSource, MIMEType: "image/png", Mode: "inline_base64", InlineBase64: "c291cmNl"}}
	if _, errExecute := driver.Execute(context.Background(), execution); errExecute == nil || !strings.Contains(errExecute.Error(), "4k") {
		t.Fatalf("Execute() error = %v", errExecute)
	}
}

// newAlibabaWanImageExecution builds one exact Wan image action execution fixture.
// newAlibabaWanImageExecution 构建一个精确 Wan 图片动作执行夹具。
func newAlibabaWanImageExecution(t *testing.T, baseURL string, actionBindingID string, operation vcp.OperationKind, model string) (*WanImageActionDriver, provider.ExecutionRequest) {
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
	driver, errDriver := NewWanImageActionDriver("definition-alibaba", actionBindingID, client)
	if errDriver != nil {
		t.Fatalf("NewWanImageActionDriver() error = %v", errDriver)
	}
	profileID := WanImageGenerateProtocolProfileID
	if operation == vcp.OperationImageEdit {
		profileID = WanImageEditProtocolProfileID
	}
	action := providerconfig.ProviderActionBinding{ID: actionBindingID, Operation: operation, DriverID: "alibaba", DriverVersion: "1", ProtocolProfileID: profileID, EndpointProfileID: "alibaba_wan_image", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, ResourceMaterialization: []providerconfig.ResourceMaterializationMode{providerconfig.ResourceMaterializationInline, providerconfig.ResourceMaterializationDirectURL}, Revision: 1}
	definition := providerconfig.ProviderDefinition{ID: "definition-alibaba", Kind: providerconfig.DefinitionKindSystem, ProtocolProfileID: EmbeddingProtocolProfileID, AuthMethodIDs: []string{"api_key"}, RuntimeReady: true, AuthMethods: []providerconfig.AuthMethodDefinition{{ID: "api_key", Type: providerconfig.AuthMethodAPIKey}}, ActionBindings: []providerconfig.ProviderActionBinding{action}, Revision: 1}
	target := resolve.Target{SubjectKind: resolve.ExecutionSubjectModel, ProviderDefinitionID: definition.ID, ProviderInstanceID: "instance-alibaba", ChannelID: profileID, EndpointID: "endpoint-alibaba", CredentialID: "credential-alibaba", ProviderModelID: "model-wan-image", OfferingID: "offering-wan-image", ExecutionProfileID: "profile-wan-image", UpstreamModelID: model, Operation: operation, ActionBindingID: actionBindingID, CatalogRevision: 1}
	request := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request-wan-image", Target: vcp.TargetSelection{Model: &vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: target.ProviderInstanceID, ProviderModelID: target.ProviderModelID, ExecutionProfileID: target.ExecutionProfileID}}, Operation: operation}
	execution := provider.ExecutionRequest{Binding: transport.Binding{Target: target, Endpoint: providerconfig.Endpoint{ID: target.EndpointID, ProviderInstanceID: target.ProviderInstanceID, ChannelID: target.ChannelID, BaseURL: baseURL, Status: providerconfig.EndpointReady}, Credential: providerconfig.Credential{ID: target.CredentialID, ProviderInstanceID: target.ProviderInstanceID, AuthMethodID: "api_key", SecretRef: secretReference, Status: providerconfig.CredentialActive}}, Definition: definition, Execution: &request, LineageID: "lineage-wan-image", Now: time.Date(2026, time.July, 20, 0, 0, 0, 0, time.UTC)}
	return driver, execution
}
