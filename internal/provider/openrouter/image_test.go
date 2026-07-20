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

// TestImageDriverPinsOneProviderAndReturnsPrivateBytes verifies endpoint affinity, references, and Base64 ingestion.
// TestImageDriverPinsOneProviderAndReturnsPrivateBytes 验证端点亲和性、参考图与 Base64 私有导入。
func TestImageDriverPinsOneProviderAndReturnsPrivateBytes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v1/images" || request.Header.Get("Authorization") != "Bearer test-secret" {
			t.Errorf("request path=%q auth=%q", request.URL.Path, request.Header.Get("Authorization"))
		}
		var upstream openRouterImageRequest
		if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil {
			t.Errorf("decode request: %v", errDecode)
		}
		if upstream.Model != "openai/gpt-image-1" || len(upstream.Provider.Only) != 1 || upstream.Provider.Only[0] != "openai" || upstream.Provider.AllowFallbacks || len(upstream.InputReferences) != 1 || upstream.InputReferences[0].ImageURL.URL != "https://inputs.example/reference.png" {
			t.Errorf("upstream = %#v", upstream)
		}
		_, _ = io.WriteString(writer, `{"data":[{"b64_json":"aW1hZ2U=","media_type":"image/png"}]}`)
	}))
	defer server.Close()

	secretStore := secret.NewMemoryStore()
	secretReference, errPut := secretStore.Put(context.Background(), []byte("test-secret"))
	if errPut != nil {
		t.Fatalf("Put() error = %v", errPut)
	}
	client, errClient := transport.NewClient(http.DefaultClient, secretStore, transport.RetryPolicy{})
	if errClient != nil {
		t.Fatalf("NewClient() error = %v", errClient)
	}
	driver, errDriver := NewImageDriver("definition-openrouter", client)
	if errDriver != nil {
		t.Fatalf("NewImageDriver() error = %v", errDriver)
	}
	action := providerconfig.ProviderActionBinding{ID: ImageGenerateActionBindingID, Operation: vcp.OperationImageGenerate, DriverID: "openrouter", DriverVersion: "1", ProtocolProfileID: ImageGenerateProtocolProfileID, EndpointProfileID: "openrouter_images_openai", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, ResourceMaterialization: []providerconfig.ResourceMaterializationMode{providerconfig.ResourceMaterializationDirectURL}, Revision: 1}
	definition := providerconfig.ProviderDefinition{ID: "definition-openrouter", Kind: providerconfig.DefinitionKindSystem, ProtocolProfileID: EmbeddingProtocolProfileID, AuthMethodIDs: []string{"api_key"}, RuntimeReady: true, AuthMethods: []providerconfig.AuthMethodDefinition{{ID: "api_key", Type: providerconfig.AuthMethodAPIKey}}, ActionBindings: []providerconfig.ProviderActionBinding{action}, Revision: 1}
	target := resolve.Target{SubjectKind: resolve.ExecutionSubjectModel, ProviderDefinitionID: definition.ID, ProviderInstanceID: "instance-openrouter", ChannelID: EmbeddingProtocolProfileID, EndpointID: "endpoint-openrouter", CredentialID: "credential-openrouter", ProviderModelID: "model-image", OfferingID: "offering-image", ExecutionProfileID: "profile-image", UpstreamModelID: "openai/gpt-image-1", Operation: vcp.OperationImageGenerate, ActionBindingID: ImageGenerateActionBindingID, CatalogRevision: 1}
	request := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request-image", Target: vcp.TargetSelection{Model: &vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: target.ProviderInstanceID, ProviderModelID: target.ProviderModelID, ExecutionProfileID: target.ExecutionProfileID}}, Operation: vcp.OperationImageGenerate}
	request.Payload.ImageGenerate = &vcp.ImageGenerateOperation{Prompt: "A reference remix", Count: 1, References: []vcp.MediaInput{{ID: "reference", Kind: vcp.MediaImage, Role: vcp.MediaRoleReference, Resource: vcp.ResourceReference{ResourceID: "resource-reference"}}}}
	execution := provider.ExecutionRequest{Binding: transport.Binding{Target: target, Endpoint: providerconfig.Endpoint{ID: target.EndpointID, ProviderInstanceID: target.ProviderInstanceID, ChannelID: target.ChannelID, BaseURL: server.URL + "/api", Status: providerconfig.EndpointReady}, Credential: providerconfig.Credential{ID: target.CredentialID, ProviderInstanceID: target.ProviderInstanceID, AuthMethodID: "api_key", SecretRef: secretReference, Status: providerconfig.CredentialActive}}, Definition: definition, Execution: &request, MaterializedInputs: []resource.MaterializedInput{{InputID: "reference", ResourceID: "resource-reference", Kind: vcp.MediaImage, Role: vcp.MediaRoleReference, MIMEType: "image/png", Mode: "direct_remote_url", RemoteURL: "https://inputs.example/reference.png"}}, LineageID: "lineage-image", Now: time.Date(2026, time.July, 20, 0, 0, 0, 0, time.UTC)}
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if len(result.GeneratedResources) != 1 || string(result.GeneratedResources[0].Data) != "image" || result.GeneratedResources[0].DownloadURL != "" {
		t.Fatalf("generated resources = %#v", result.GeneratedResources)
	}
}
