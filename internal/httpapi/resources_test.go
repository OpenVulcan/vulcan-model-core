package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
)

// TestResourceHTTPBase64Lifecycle verifies authenticated import, safe metadata, content, and deletion.
// TestResourceHTTPBase64Lifecycle 验证已认证导入、安全元数据、正文及删除。
func TestResourceHTTPBase64Lifecycle(t *testing.T) {
	t.Parallel()
	server := newResourceHTTPServer(t)
	encoded := base64.StdEncoding.EncodeToString(resourceHTTPPNG(t))
	body := `{"kind":"image","declared_mime":"image/png","retention":"ephemeral","base64":{"encoding":"standard","data":"` + encoded + `"}}`
	create := httptest.NewRequest(http.MethodPost, "/vulcan/v1/resources/import", strings.NewReader(body))
	create.Header.Set("Authorization", "Bearer call-key")
	create.Header.Set("Content-Type", "application/json")
	createdRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(createdRecorder, create)
	if createdRecorder.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body = %s", createdRecorder.Code, createdRecorder.Body.String())
	}
	var created resource.Resource
	if errDecode := json.Unmarshal(createdRecorder.Body.Bytes(), &created); errDecode != nil {
		t.Fatalf("decode created resource: %v", errDecode)
	}
	if created.ID == "" || strings.Contains(createdRecorder.Body.String(), "owner") || strings.Contains(createdRecorder.Body.String(), "object") {
		t.Fatalf("created response is unsafe or incomplete: %s", createdRecorder.Body.String())
	}
	content := httptest.NewRequest(http.MethodGet, "/vulcan/v1/resources/"+created.ID+"/content", nil)
	content.Header.Set("Authorization", "Bearer call-key")
	contentRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(contentRecorder, content)
	if contentRecorder.Code != http.StatusOK || contentRecorder.Header().Get("X-Content-Type-Options") != "nosniff" || !bytes.Equal(contentRecorder.Body.Bytes(), resourceHTTPPNG(t)) {
		t.Fatalf("content status=%d headers=%v bytes=%d", contentRecorder.Code, contentRecorder.Header(), contentRecorder.Body.Len())
	}
	deleteRequest := httptest.NewRequest(http.MethodDelete, "/vulcan/v1/resources/"+created.ID, nil)
	deleteRequest.Header.Set("Authorization", "Bearer call-key")
	deleteRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(deleteRecorder, deleteRequest)
	if deleteRecorder.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d, body = %s", deleteRecorder.Code, deleteRecorder.Body.String())
	}
	getDeleted := httptest.NewRequest(http.MethodGet, "/vulcan/v1/resources/"+created.ID, nil)
	getDeleted.Header.Set("Authorization", "Bearer call-key")
	deletedRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(deletedRecorder, getDeleted)
	if deletedRecorder.Code != http.StatusNotFound {
		t.Fatalf("deleted metadata status = %d", deletedRecorder.Code)
	}
}

// TestResourceHTTPRejectsUnauthenticatedAndAmbiguousImports verifies route auth and exact payload union enforcement.
// TestResourceHTTPRejectsUnauthenticatedAndAmbiguousImports 验证路由认证与精确 Payload 联合体约束。
func TestResourceHTTPRejectsUnauthenticatedAndAmbiguousImports(t *testing.T) {
	t.Parallel()
	server := newResourceHTTPServer(t)
	body := `{"kind":"file","retention":"persistent","url":{"location":"https://example.test/a"},"base64":{"encoding":"standard","data":"YQ=="}}`
	unauthenticated := httptest.NewRequest(http.MethodPost, "/vulcan/v1/resources/import", strings.NewReader(body))
	unauthenticatedRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(unauthenticatedRecorder, unauthenticated)
	if unauthenticatedRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d", unauthenticatedRecorder.Code)
	}
	ambiguous := httptest.NewRequest(http.MethodPost, "/vulcan/v1/resources/import", strings.NewReader(body))
	ambiguous.Header.Set("Authorization", "Bearer call-key")
	ambiguousRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(ambiguousRecorder, ambiguous)
	if ambiguousRecorder.Code != http.StatusBadRequest {
		t.Fatalf("ambiguous status = %d, body = %s", ambiguousRecorder.Code, ambiguousRecorder.Body.String())
	}
}

// newResourceHTTPServer creates one fully authenticated server backed by temporary resource storage.
// newResourceHTTPServer 创建一个由临时资源存储支持的完整认证服务。
func newResourceHTTPServer(t *testing.T) *Server {
	t.Helper()
	service, errService := resource.NewService(resource.NewMemoryStore(), resource.ServiceOptions{Root: t.TempDir(), MaxObjectBytes: 1 << 20, MaxReadyBytes: 4 << 20, DefaultTTL: time.Hour, MaxTTL: 24 * time.Hour})
	if errService != nil {
		t.Fatalf("NewService() error = %v", errService)
	}
	importer, errImporter := resource.NewImporter(service, resource.ImporterOptions{RequestTimeout: time.Second, ResponseHeaderTimeout: time.Second, MaxRedirects: 1})
	if errImporter != nil {
		t.Fatalf("NewImporter() error = %v", errImporter)
	}
	gateway, errGateway := resource.NewGateway(service, importer)
	if errGateway != nil {
		t.Fatalf("NewGateway() error = %v", errGateway)
	}
	access := staticControlAccess{}
	server, errServer := NewWithControlPlane(staticCatalog{}, ControlPlane{Query: staticManagementQuery{}, Commands: staticManagementCommands{}, ModelAccess: staticModelAccessCommands{}, CustomCatalogs: staticCustomCatalogOperations{}, Protocols: staticProtocolProfiles{}, APIKeys: access, Auth: access, Resources: gateway, InputPlans: access, Executions: staticExecutionAccess{}, Targets: access})
	if errServer != nil {
		t.Fatalf("NewWithControlPlane() error = %v", errServer)
	}
	return server
}

// resourceHTTPPNG returns one deterministic one-pixel image fixture.
// resourceHTTPPNG 返回一个确定性单像素图片夹具。
func resourceHTTPPNG(t *testing.T) []byte {
	t.Helper()
	imageValue := image.NewRGBA(image.Rect(0, 0, 1, 1))
	imageValue.Set(0, 0, color.RGBA{R: 0x12, G: 0x34, B: 0x56, A: 0xff})
	buffer := bytes.NewBuffer(nil)
	if errEncode := png.Encode(buffer, imageValue); errEncode != nil {
		t.Fatalf("encode PNG fixture: %v", errEncode)
	}
	return buffer.Bytes()
}
