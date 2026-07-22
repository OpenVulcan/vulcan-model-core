package minimax_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/OpenVulcan/vulcan-model-core/internal/bootstrap"
	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/management"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/minimax"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

// TestFileUploaderCompletesExactCredentialLifecycle verifies pinned upload, list, retrieve, delete, and protected credential projection.
// TestFileUploaderCompletesExactCredentialLifecycle 验证固定上传、列表、查询、删除与受保护凭据投影。
func TestFileUploaderCompletesExactCredentialLifecycle(t *testing.T) {
	// deleteRequests distinguishes the successful lifecycle deletion from the application-error regression request.
	// deleteRequests 区分成功生命周期删除与应用错误回归请求。
	deleteRequests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer minimax-key" {
			t.Errorf("request authorization=%q", request.Header.Get("Authorization"))
		}
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/v1/files/list":
			_, _ = io.WriteString(writer, `{"base_resp":{"status_code":0,"status_msg":""},"files":[{"file_id":"123456","bytes":2048,"created_at":1700000000,"filename":"vision.png","purpose":"vision"}]}`)
		case request.Method == http.MethodGet && request.URL.Path == "/v1/files/retrieve":
			if request.URL.Query().Get("file_id") != "123456" {
				t.Errorf("retrieve file_id=%q", request.URL.Query().Get("file_id"))
			}
			_, _ = io.WriteString(writer, `{"base_resp":{"status_code":0,"status_msg":""},"file":{"file_id":"123456","bytes":2048,"created_at":1700000000,"filename":"vision.png","purpose":"vision","download_url":"https://temporary.example/private"}}`)
		case request.Method == http.MethodPost && request.URL.Path == "/v1/files/upload":
			if errParse := request.ParseMultipartForm(1 << 20); errParse != nil {
				t.Errorf("ParseMultipartForm() error = %v", errParse)
			}
			file, _, errFile := request.FormFile("file")
			if errFile != nil {
				t.Errorf("FormFile() error = %v", errFile)
				return
			}
			content, _ := io.ReadAll(file)
			_ = file.Close()
			if string(content) != "image-bytes" || request.FormValue("purpose") != "retrieval" {
				t.Errorf("upload content=%q purpose=%q", string(content), request.FormValue("purpose"))
			}
			_, _ = io.WriteString(writer, `{"base_resp":{"status_code":0,"status_msg":""},"file":{"file_id":"123456","bytes":11,"created_at":1700000000,"filename":"resource-image.png","purpose":"retrieval"}}`)
		case request.Method == http.MethodPost && request.URL.Path == "/v1/files/delete":
			deleteRequests++
			var payload struct {
				// FileID is the exact numeric provider identifier.
				// FileID 是精确的供应商数值标识。
				FileID uint64 `json:"file_id"`
			}
			if errDecode := json.NewDecoder(request.Body).Decode(&payload); errDecode != nil || payload.FileID != 123456 {
				t.Errorf("delete payload=%#v error=%v", payload, errDecode)
			}
			if deleteRequests == 1 {
				_, _ = io.WriteString(writer, `{"base_resp":{"status_code":0,"status_msg":""},"file_id":123456}`)
			} else {
				_, _ = io.WriteString(writer, `{"base_resp":{"status_code":1001,"status_msg":"not found"},"file_id":123456}`)
			}
		default:
			t.Errorf("unexpected request method=%q path=%q", request.Method, request.URL.Path)
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	protocols := providerconfig.NewProtocolRegistry()
	if errRegister := bootstrap.RegisterProtocolProfiles(protocols); errRegister != nil {
		t.Fatalf("RegisterProtocolProfiles() error = %v", errRegister)
	}
	seedSystems, errSeedSystems := providerconfig.NewSystemRegistry(protocols)
	if errSeedSystems != nil {
		t.Fatalf("NewSystemRegistry() seed error = %v", errSeedSystems)
	}
	if errRegister := bootstrap.RegisterSystemProviders(seedSystems); errRegister != nil {
		t.Fatalf("RegisterSystemProviders() error = %v", errRegister)
	}
	definition, exists := seedSystems.Lookup(bootstrap.MiniMaxGlobalDefinitionID)
	if !exists {
		t.Fatal("MiniMax Global definition is missing")
	}
	definition.EndpointPresets[0].BaseURL = server.URL
	systems, errSystems := providerconfig.NewSystemRegistry(protocols)
	if errSystems != nil {
		t.Fatalf("NewSystemRegistry() error = %v", errSystems)
	}
	if errGroup := systems.RegisterGroup(providerconfig.ProviderGroup{ID: bootstrap.MiniMaxGroupID, DisplayName: "MiniMax", Revision: 1}); errGroup != nil {
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
	onboarding, errOnboard := commands.OnboardSystemProvider(context.Background(), management.OnboardSystemProviderInput{DefinitionID: definition.ID, DisplayName: "MiniMax Files", AuthMethodID: "api_key", Secret: []byte("minimax-key")})
	if errOnboard != nil {
		t.Fatalf("OnboardSystemProvider() error = %v", errOnboard)
	}
	accessTokens, errAccessTokens := minimax.NewAccessTokenStore(secrets)
	if errAccessTokens != nil {
		t.Fatalf("NewAccessTokenStore() error = %v", errAccessTokens)
	}
	uploader, errUploader := minimax.NewFileUploader(configurations, accessTokens, server.Client())
	if errUploader != nil {
		t.Fatalf("NewFileUploader() error = %v", errUploader)
	}
	files, errList := uploader.ListProviderFiles(context.Background(), onboarding.Instance.ID, onboarding.Endpoints[0].ID, onboarding.Credential.ID)
	if errList != nil {
		t.Fatalf("ListProviderFiles() error = %v", errList)
	}
	if len(files) != 1 || files[0].FileID != "123456" || files[0].Filename != "vision.png" || files[0].Purpose != "vision" || files[0].SizeBytes != 2048 || files[0].CreatedAt.Unix() != 1700000000 {
		t.Fatalf("files = %#v", files)
	}
	retrieved, errRetrieve := uploader.GetProviderFile(context.Background(), onboarding.Instance.ID, onboarding.Endpoints[0].ID, onboarding.Credential.ID, "123456")
	if errRetrieve != nil || retrieved.FileID != "123456" || !retrieved.DownloadAvailable {
		t.Fatalf("GetProviderFile() result=%#v error=%v", retrieved, errRetrieve)
	}
	target := resource.AssetBindingTarget{ProviderDefinitionID: onboarding.Instance.DefinitionID, ProviderInstanceID: onboarding.Instance.ID, EndpointID: onboarding.Endpoints[0].ID, CredentialID: onboarding.Credential.ID, ActionBindingID: minimax.ProviderFileManagementActionBindingID, Region: onboarding.Endpoints[0].Region}
	uploaded, errUpload := uploader.Upload(context.Background(), resource.AssetUploadRequest{Target: target, ResourceID: "resource-image", Kind: "image", MIMEType: "image/png", SizeBytes: 11, Mode: "provider_file_id", Content: bytes.NewReader([]byte("image-bytes"))})
	if errUpload != nil || uploaded.Handle != "123456" || uploaded.Kind != resource.ProviderAssetFile {
		t.Fatalf("Upload() result=%#v error=%v", uploaded, errUpload)
	}
	if errDelete := uploader.Delete(context.Background(), target, uploaded.Kind, uploaded.Handle); errDelete != nil {
		t.Fatalf("Delete() error = %v", errDelete)
	}
	if errDelete := uploader.Delete(context.Background(), target, uploaded.Kind, uploaded.Handle); errDelete == nil {
		t.Fatal("expected application-level deletion failure")
	}
}
