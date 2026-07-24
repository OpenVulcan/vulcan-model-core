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

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestQwenImageGenerationUsesSynchronousMultimodalContract verifies the exact request shape and private temporary output URL.
// TestQwenImageGenerationUsesSynchronousMultimodalContract 验证精确请求形态与私有临时输出 URL。
func TestQwenImageGenerationUsesSynchronousMultimodalContract(t *testing.T) {
	promptExtend := true
	watermark := false
	seed := int64(42)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/api/v1/services/aigc/multimodal-generation/generation" || request.Header.Get("Authorization") != "Bearer test-secret" {
			t.Errorf("request = %s %s authorization=%q", request.Method, request.URL.Path, request.Header.Get("Authorization"))
		}
		var upstream qwenImageRequest
		if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil {
			t.Errorf("decode request: %v", errDecode)
		}
		if upstream.Model != "qwen-image-2.0-pro" || len(upstream.Input.Messages) != 1 || len(upstream.Input.Messages[0].Content) != 1 || upstream.Input.Messages[0].Content[0].Text != "A blue square" || upstream.Parameters.Size != "1536*1536" || upstream.Parameters.Count != 2 || upstream.Parameters.NegativePrompt != "blur" || upstream.Parameters.Seed == nil || *upstream.Parameters.Seed != seed || upstream.Parameters.PromptExtend == nil || *upstream.Parameters.PromptExtend != promptExtend || upstream.Parameters.Watermark == nil || *upstream.Parameters.Watermark != watermark {
			t.Errorf("upstream = %#v", upstream)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"request_id":"request-qwen","output":{"choices":[{"message":{"content":[{"image":"https://result.example/one.png?Expires=1"},{"image":"https://result.example/two.png?Expires=1"}]}}]}}`)
	}))
	defer server.Close()

	driver, execution := newAlibabaImageExecution(t, server.URL, ImageGenerateActionBindingID, vcp.OperationImageGenerate)
	execution.Execution.Payload.ImageGenerate = &vcp.ImageGenerateOperation{Prompt: "A blue square", NegativePrompt: "blur", Count: 2, Width: 1536, Height: 1536, OutputFormat: "png", Seed: &seed, PromptExtend: &promptExtend, Watermark: &watermark}
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if result.UpstreamResponseID != "request-qwen" || len(result.GeneratedResources) != 2 || !strings.Contains(result.GeneratedResources[0].DownloadURL, "one.png") || result.GeneratedResources[0].MIMEType != "image/png" {
		t.Fatalf("result = %#v", result)
	}
}

// TestQwenImageEditPreservesOrderedInlineAndRemoteSources verifies exact edit roles and both documented materialization modes.
// TestQwenImageEditPreservesOrderedInlineAndRemoteSources 验证精确编辑角色及两种文档明确的物化方式。
func TestQwenImageEditPreservesOrderedInlineAndRemoteSources(t *testing.T) {
	promptExtend := false
	watermark := true
	seed := int64(7)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var upstream qwenImageRequest
		if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil {
			t.Errorf("decode request: %v", errDecode)
		}
		content := upstream.Input.Messages[0].Content
		if len(content) != 3 || content[0].Image != "data:image/png;base64,c291cmNl" || content[1].Image != "https://inputs.example/reference.webp" || content[2].Text != "Combine the subjects" || upstream.Parameters.Count != 1 || upstream.Parameters.NegativePrompt != "duplicate subject" || upstream.Parameters.Seed == nil || *upstream.Parameters.Seed != seed || upstream.Parameters.PromptExtend == nil || *upstream.Parameters.PromptExtend != promptExtend || upstream.Parameters.Watermark == nil || *upstream.Parameters.Watermark != watermark {
			t.Errorf("content = %#v parameters=%#v", content, upstream.Parameters)
		}
		_, _ = io.WriteString(writer, `{"request_id":"request-edit","output":{"choices":[{"message":{"content":[{"image":"https://result.example/edit.png"}]}}]}}`)
	}))
	defer server.Close()

	driver, execution := newAlibabaImageExecution(t, server.URL, ImageEditActionBindingID, vcp.OperationImageEdit)
	execution.Execution.Payload.ImageEdit = &vcp.ImageEditOperation{Instruction: "Combine the subjects", Count: 1, OutputFormat: "png", NegativePrompt: "duplicate subject", Seed: &seed, PromptExtend: &promptExtend, Watermark: &watermark, Sources: []vcp.MediaInput{
		{ID: "source-one", Kind: vcp.MediaImage, Role: vcp.MediaRoleEditSource, Resource: vcp.ResourceReference{ResourceID: "resource-one"}},
		{ID: "source-two", Kind: vcp.MediaImage, Role: vcp.MediaRoleEditSource, Resource: vcp.ResourceReference{ResourceID: "resource-two"}},
	}}
	execution.MaterializedInputs = []resource.MaterializedInput{
		{InputID: "source-one", ResourceID: "resource-one", Kind: vcp.MediaImage, Role: vcp.MediaRoleEditSource, MIMEType: "image/png", Mode: "inline_base64", InlineBase64: "c291cmNl"},
		{InputID: "source-two", ResourceID: "resource-two", Kind: vcp.MediaImage, Role: vcp.MediaRoleEditSource, MIMEType: "image/webp", Mode: "direct_remote_url", RemoteURL: "https://inputs.example/reference.webp"},
	}
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if len(result.GeneratedResources) != 1 || result.GeneratedResources[0].DownloadURL != "https://result.example/edit.png" {
		t.Fatalf("generated resources = %#v", result.GeneratedResources)
	}
}

// TestQwenImageEditAddsOSSResolutionHeader verifies Router-managed object handles activate the copied DashScope header.
// TestQwenImageEditAddsOSSResolutionHeader 验证 Router 管理对象句柄会激活复制的 DashScope Header。
func TestQwenImageEditAddsOSSResolutionHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("X-DashScope-OssResourceResolve") != "enable" {
			t.Errorf("OSS resolution header = %q", request.Header.Get("X-DashScope-OssResourceResolve"))
		}
		var upstream qwenImageRequest
		if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil || len(upstream.Input.Messages) != 1 || upstream.Input.Messages[0].Content[0].Image != "oss://temporary/router/source.png" {
			t.Errorf("upstream = %#v, error = %v", upstream, errDecode)
		}
		_, _ = io.WriteString(writer, `{"request_id":"request-object","output":{"choices":[{"message":{"content":[{"image":"https://result.example/edit.png"}]}}]}}`)
	}))
	defer server.Close()

	driver, execution := newAlibabaImageExecution(t, server.URL, ImageEditActionBindingID, vcp.OperationImageEdit)
	execution.Execution.Payload.ImageEdit = &vcp.ImageEditOperation{Instruction: "Edit", Count: 1, OutputFormat: "png", Sources: []vcp.MediaInput{{ID: "source", Kind: vcp.MediaImage, Role: vcp.MediaRoleEditSource, Resource: vcp.ResourceReference{ResourceID: "resource-source"}}}}
	execution.MaterializedInputs = []resource.MaterializedInput{{InputID: "source", ResourceID: "resource-source", Kind: vcp.MediaImage, Role: vcp.MediaRoleEditSource, MIMEType: "image/png", Mode: catalog.MaterializationProviderObjectURI, ProviderHandle: "oss://temporary/router/source.png", ProviderAssetKind: resource.ProviderAssetObject}}
	if _, errExecute := driver.Execute(context.Background(), execution); errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
}

// TestQwenImageEditRejectsMaskWithoutWireCarrier verifies unsupported semantic roles fail before network traffic.
// TestQwenImageEditRejectsMaskWithoutWireCarrier 验证不受支持的语义角色会在网络请求前明确失败。
func TestQwenImageEditRejectsMaskWithoutWireCarrier(t *testing.T) {
	driver, execution := newAlibabaImageExecution(t, "https://dashscope.example", ImageEditActionBindingID, vcp.OperationImageEdit)
	execution.Execution.Payload.ImageEdit = &vcp.ImageEditOperation{Instruction: "Masked edit", Sources: []vcp.MediaInput{{ID: "mask", Kind: vcp.MediaImage, Role: vcp.MediaRoleMask, Resource: vcp.ResourceReference{ResourceID: "resource-mask"}}}}
	execution.MaterializedInputs = []resource.MaterializedInput{{InputID: "mask", ResourceID: "resource-mask", Kind: vcp.MediaImage, Role: vcp.MediaRoleMask, MIMEType: "image/png", Mode: "inline_base64", InlineBase64: "bWFzaw=="}}
	if _, errExecute := driver.Execute(context.Background(), execution); errExecute == nil || !strings.Contains(errExecute.Error(), "edit_source") {
		t.Fatalf("Execute() error = %v", errExecute)
	}
}

// newAlibabaImageExecution builds one exact Alibaba image action execution fixture.
// newAlibabaImageExecution 构建一个精确 Alibaba 图片动作执行夹具。
func newAlibabaImageExecution(t *testing.T, baseURL string, actionBindingID string, operation vcp.OperationKind) (*ImageActionDriver, provider.ExecutionRequest) {
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
	driver, errDriver := NewImageActionDriver("definition-alibaba", actionBindingID, client)
	if errDriver != nil {
		t.Fatalf("NewImageActionDriver() error = %v", errDriver)
	}
	profileID := ImageGenerateProtocolProfileID
	if operation == vcp.OperationImageEdit {
		profileID = ImageEditProtocolProfileID
	}
	action := providerconfig.ProviderActionBinding{ID: actionBindingID, Operation: operation, DriverID: "alibaba", DriverVersion: "1", ProtocolProfileID: profileID, EndpointProfileID: "alibaba_qwen_image", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, ResourceMaterialization: []providerconfig.ResourceMaterializationMode{providerconfig.ResourceMaterializationInline, providerconfig.ResourceMaterializationDirectURL}, Revision: 1}
	definition := providerconfig.ProviderDefinition{ID: "definition-alibaba", Kind: providerconfig.DefinitionKindSystem, ProtocolProfileID: EmbeddingProtocolProfileID, AuthMethodIDs: []string{"api_key"}, RuntimeReady: true, AuthMethods: []providerconfig.AuthMethodDefinition{{ID: "api_key", Type: providerconfig.AuthMethodAPIKey}}, ActionBindings: []providerconfig.ProviderActionBinding{action}, Revision: 1}
	target := resolve.Target{SubjectKind: resolve.ExecutionSubjectModel, ProviderDefinitionID: definition.ID, ProviderInstanceID: "instance-alibaba", ChannelID: EmbeddingProtocolProfileID, EndpointID: "endpoint-alibaba", CredentialID: "credential-alibaba", ProviderModelID: "model-qwen-image", OfferingID: "offering-qwen-image", ExecutionProfileID: "profile-qwen-image", UpstreamModelID: "qwen-image-2.0-pro", Operation: operation, ActionBindingID: actionBindingID, CatalogRevision: 1}
	request := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request-image", Target: vcp.TargetSelection{Model: &vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: target.ProviderInstanceID, ProviderModelID: target.ProviderModelID, ExecutionProfileID: target.ExecutionProfileID}}, Operation: operation}
	execution := provider.ExecutionRequest{Binding: transport.Binding{Target: target, Endpoint: providerconfig.Endpoint{ID: target.EndpointID, ProviderInstanceID: target.ProviderInstanceID, ChannelID: target.ChannelID, BaseURL: baseURL, Status: providerconfig.EndpointReady}, Credential: providerconfig.Credential{ID: target.CredentialID, ProviderInstanceID: target.ProviderInstanceID, AuthMethodID: "api_key", SecretRef: secretReference, Status: providerconfig.CredentialActive}}, Definition: definition, Execution: &request, LineageID: "lineage-image", Now: time.Date(2026, time.July, 20, 0, 0, 0, 0, time.UTC)}
	return driver, execution
}
