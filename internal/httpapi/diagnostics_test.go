package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/execution"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// staticResourceDiagnostics returns one deliberately private-rich resource to prove JSON redaction.
// staticResourceDiagnostics 返回一个刻意包含私有字段的资源以证明 JSON 脱敏。
type staticResourceDiagnostics struct{}

// ListDiagnostics returns one safe public metadata view backed by private test fields.
// ListDiagnostics 返回一个由私有测试字段支撑的安全公开元数据视图。
func (staticResourceDiagnostics) ListDiagnostics(context.Context, int) ([]resource.Resource, error) {
	now := time.Date(2026, time.July, 20, 20, 0, 0, 0, time.UTC)
	return []resource.Resource{{ID: "res_0123456789abcdef0123456789abcdef", OwnerAPIKeyID: "api-private-owner", Kind: vcp.MediaFile, MIMEType: "application/pdf", SizeBytes: 10, SHA256: strings.Repeat("a", 64), Source: resource.SourceURLImport, SourceURL: "https://private.example/document.pdf", State: resource.StateReady, Retention: resource.RetentionPersistent, ObjectKey: "private/object/path", CreatedAt: now, UpdatedAt: now, Revision: 1}}, nil
}

// staticExecutionDiagnostics returns one deliberately private-rich execution to prove JSON redaction.
// staticExecutionDiagnostics 返回一个刻意包含私有字段的执行以证明 JSON 脱敏。
type staticExecutionDiagnostics struct{}

// ListDiagnostics returns one lifecycle snapshot containing private in-memory affinity.
// ListDiagnostics 返回一个内存中包含私有亲和性的生命周期快照。
func (staticExecutionDiagnostics) ListDiagnostics(context.Context, int) ([]execution.Record, error) {
	now := time.Date(2026, time.July, 20, 20, 0, 0, 0, time.UTC)
	return []execution.Record{{ID: "exe_diagnostic", OwnerAPIKeyID: "api-private-owner", RequestHash: "private-request-hash", Status: execution.StatusQueued, Operation: vcp.OperationVideoGenerate, ProviderTask: &execution.ProviderTaskSnapshot{ProviderTaskID: "private-provider-task"}, ProviderPreparation: &execution.ProviderPreparationSnapshot{ProviderHandle: "private-provider-feature"}, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour), Revision: 1}}, nil
}

// TestManagementDiagnosticsRequireManagementKeyAndHidePrivateFields verifies the read-only diagnostic boundary.
// TestManagementDiagnosticsRequireManagementKeyAndHidePrivateFields 验证只读诊断边界要求管理密钥并隐藏私有字段。
func TestManagementDiagnosticsRequireManagementKeyAndHidePrivateFields(t *testing.T) {
	access := staticControlAccess{}
	server, errServer := NewWithControlPlane(staticCatalog{}, ControlPlane{Query: staticManagementQuery{}, Commands: staticManagementCommands{}, ModelAccess: staticModelAccessCommands{}, CustomCatalogs: staticCustomCatalogOperations{}, Protocols: staticProtocolProfiles{}, APIKeys: access, Auth: access, Resources: access, InputPlans: access, Executions: staticExecutionAccess{}, Targets: access, ResourceDiagnostics: staticResourceDiagnostics{}, ExecutionDiagnostics: staticExecutionDiagnostics{}})
	if errServer != nil {
		t.Fatalf("NewWithControlPlane() error = %v", errServer)
	}
	for _, path := range []string{"/vulcan/manage/diagnostics/resources", "/vulcan/manage/diagnostics/executions"} {
		unauthorized := httptest.NewRequest(http.MethodGet, path, nil)
		unauthorized.Header.Set("Authorization", "Bearer call-key")
		unauthorizedRecorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(unauthorizedRecorder, unauthorized)
		if unauthorizedRecorder.Code != http.StatusUnauthorized {
			t.Fatalf("%s call-plane status = %d", path, unauthorizedRecorder.Code)
		}
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Header.Set("Authorization", "Bearer manage-key")
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s status = %d body=%s", path, recorder.Code, recorder.Body.String())
		}
		body := recorder.Body.String()
		for _, privateValue := range []string{"api-private-owner", "private.example", "private/object/path", "private-request-hash", "private-provider-task", "private-provider-feature", "sha256", "metadata", "generated_by", "result"} {
			if strings.Contains(body, privateValue) {
				t.Fatalf("%s leaked %q: %s", path, privateValue, body)
			}
		}
	}
}
