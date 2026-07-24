package alibaba_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/bootstrap"
	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/management"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/alibaba"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

// TestOSSUploaderCopiesPolicyAndMultipartFlow verifies exact-target authentication, signed fields, bytes, handle, and expiry.
// TestOSSUploaderCopiesPolicyAndMultipartFlow 验证精确 Target 认证、签名字段、字节、句柄及到期时间。
func TestOSSUploaderCopiesPolicyAndMultipartFlow(t *testing.T) {
	content := []byte("image-bytes")
	digest := sha256.Sum256(content)
	digestText := hex.EncodeToString(digest[:])
	fixedNow := time.Date(2026, time.July, 22, 12, 0, 0, 0, time.UTC)
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/api/v1/uploads":
			if request.URL.Query().Get("action") != "getPolicy" || request.URL.Query().Get("model") != "qwen-image-2.0-pro" || request.Header.Get("Authorization") != "Bearer alibaba-key" {
				t.Errorf("policy request = %s authorization=%q", request.URL.String(), request.Header.Get("Authorization"))
			}
			writer.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(writer, `{"data":{"upload_host":%q,"upload_dir":"temporary/router","oss_access_key_id":"temporary-id","signature":"temporary-signature","policy":"temporary-policy","x_oss_object_acl":"private","x_oss_forbid_overwrite":"true"},"request_id":"policy-request"}`, server.URL)
		case request.Method == http.MethodPost && request.URL.Path == "/":
			if request.Header.Get("Authorization") != "" {
				t.Errorf("OSS upload leaked authorization header %q", request.Header.Get("Authorization"))
			}
			if errMultipart := request.ParseMultipartForm(1 << 20); errMultipart != nil {
				t.Errorf("ParseMultipartForm() error = %v", errMultipart)
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			expectedKey := "temporary/router/resource-" + digestText[:16] + ".png"
			if request.FormValue("OSSAccessKeyId") != "temporary-id" || request.FormValue("Signature") != "temporary-signature" || request.FormValue("policy") != "temporary-policy" || request.FormValue("x-oss-object-acl") != "private" || request.FormValue("x-oss-forbid-overwrite") != "true" || request.FormValue("key") != expectedKey || request.FormValue("success_action_status") != "200" {
				t.Errorf("multipart fields = %#v", request.MultipartForm.Value)
			}
			file, header, errFile := request.FormFile("file")
			if errFile != nil {
				t.Errorf("FormFile() error = %v", errFile)
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			defer file.Close()
			uploaded, errRead := io.ReadAll(file)
			if errRead != nil || !bytes.Equal(uploaded, content) || header.Filename != "resource-"+digestText[:16]+".png" {
				t.Errorf("uploaded = %q filename=%q error=%v", uploaded, header.Filename, errRead)
			}
			writer.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected request = %s %s", request.Method, request.URL.Path)
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	protocols := providerconfig.NewProtocolRegistry()
	if errProtocols := bootstrap.RegisterProtocolProfiles(protocols); errProtocols != nil {
		t.Fatalf("RegisterProtocolProfiles() error = %v", errProtocols)
	}
	seedSystems, errSeedSystems := providerconfig.NewSystemRegistry(protocols)
	if errSeedSystems != nil {
		t.Fatalf("NewSystemRegistry() seed error = %v", errSeedSystems)
	}
	if errRegister := bootstrap.RegisterSystemProviders(seedSystems); errRegister != nil {
		t.Fatalf("RegisterSystemProviders() error = %v", errRegister)
	}
	definition, exists := seedSystems.Lookup(bootstrap.AlibabaModelStudioCNDefinitionID)
	if !exists {
		t.Fatal("Alibaba Model Studio CN definition is missing")
	}
	definition.EndpointPresets[0].BaseURL = server.URL
	systems, errSystems := providerconfig.NewSystemRegistry(protocols)
	if errSystems != nil {
		t.Fatalf("NewSystemRegistry() error = %v", errSystems)
	}
	if errGroup := systems.RegisterGroup(providerconfig.ProviderGroup{ID: bootstrap.AlibabaGroupID, DisplayName: "Alibaba", Revision: 1}); errGroup != nil {
		t.Fatalf("RegisterGroup() error = %v", errGroup)
	}
	if errRegister := systems.Register(definition); errRegister != nil {
		t.Fatalf("Register() error = %v", errRegister)
	}
	configurations, errConfigurations := providerconfig.NewMemoryStore(protocols, systems)
	if errConfigurations != nil {
		t.Fatalf("NewMemoryStore() error = %v", errConfigurations)
	}
	secrets := secret.NewMemoryStore()
	commands, errCommands := management.NewService(configurations, secrets, catalog.NewMemoryStore())
	if errCommands != nil {
		t.Fatalf("management.NewService() error = %v", errCommands)
	}
	onboarding, errOnboard := commands.OnboardSystemProvider(context.Background(), management.OnboardSystemProviderInput{DefinitionID: definition.ID, DisplayName: "Alibaba OSS", AuthMethodID: "api_key", Secret: []byte("alibaba-key")})
	if errOnboard != nil {
		t.Fatalf("OnboardSystemProvider() error = %v", errOnboard)
	}
	uploader, errUploader := alibaba.NewOSSUploader(configurations, secrets, server.Client(), []string{definition.ID}, alibaba.OSSUploaderOptions{Now: func() time.Time { return fixedNow }, PolicyBaseURL: server.URL})
	if errUploader != nil {
		t.Fatalf("NewOSSUploader() error = %v", errUploader)
	}
	target := resource.AssetBindingTarget{ProviderDefinitionID: definition.ID, ProviderInstanceID: onboarding.Instance.ID, EndpointID: onboarding.Endpoints[0].ID, Region: onboarding.Endpoints[0].Region, CredentialID: onboarding.Credential.ID, ActionBindingID: alibaba.ImageEditActionBindingID, ProviderModelID: "model-qwen-image", UpstreamModelID: "qwen-image-2.0-pro"}
	result, errUpload := uploader.Upload(context.Background(), resource.AssetUploadRequest{Target: target, ResourceID: "resource-image", SHA256: digestText, Kind: "image", MIMEType: "image/png", SizeBytes: int64(len(content)), Mode: catalog.MaterializationProviderObjectURI, Content: bytes.NewReader(content)})
	if errUpload != nil {
		t.Fatalf("Upload() error = %v", errUpload)
	}
	if !strings.HasPrefix(result.Handle, "oss://temporary/router/resource-") || result.Kind != resource.ProviderAssetObject || result.ExpiresAt == nil || !result.ExpiresAt.Equal(fixedNow.Add(48*time.Hour)) {
		t.Fatalf("Upload() result = %#v", result)
	}
	if errDelete := uploader.Delete(context.Background(), target, result.Kind, result.Handle); errDelete != nil {
		t.Fatalf("Delete() error = %v", errDelete)
	}
}
