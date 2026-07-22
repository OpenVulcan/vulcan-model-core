package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	accesspkg "github.com/OpenVulcan/vulcan-model-core/internal/access"
	"github.com/OpenVulcan/vulcan-model-core/internal/execution"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
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

// staticProviderFileDiagnostics returns one upstream metadata row through the protected management boundary.
// staticProviderFileDiagnostics 通过受保护管理边界返回一条上游元数据。
type staticProviderFileDiagnostics struct{}

// ListProviderFiles verifies the handler forwards the exact instance, endpoint, and credential identifiers.
// ListProviderFiles 验证处理器传递精确实例、入口与凭据标识。
func (staticProviderFileDiagnostics) ListProviderFiles(_ context.Context, instanceID string, endpointID string, credentialID string) ([]provider.ProviderFileDiagnostic, error) {
	if instanceID != "pvi_minimax" || endpointID != "endpoint_minimax" || credentialID != "credential_minimax" {
		return nil, vcp.ErrInvalidRequest
	}
	return []provider.ProviderFileDiagnostic{{FileID: "provider-file-1", Filename: "vision.png", Purpose: "vision", SizeBytes: 42, CreatedAt: time.Date(2026, time.July, 20, 20, 0, 0, 0, time.UTC)}}, nil
}

// GetProviderFile verifies exact protected retrieval coordinates and returns no temporary URL.
// GetProviderFile 验证精确受保护查询坐标并且不返回临时地址。
func (staticProviderFileDiagnostics) GetProviderFile(_ context.Context, instanceID string, endpointID string, credentialID string, fileID string) (provider.ProviderFileDiagnostic, error) {
	if instanceID != "pvi_minimax" || endpointID != "endpoint_minimax" || credentialID != "credential_minimax" || fileID != "provider-file-1" {
		return provider.ProviderFileDiagnostic{}, vcp.ErrInvalidRequest
	}
	return provider.ProviderFileDiagnostic{FileID: fileID, Filename: "vision.png", Purpose: "vision", SizeBytes: 42, CreatedAt: time.Date(2026, time.July, 20, 20, 0, 0, 0, time.UTC), DownloadAvailable: true}, nil
}

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
	accessDiagnostics, errAccessDiagnostics := accesspkg.NewLocalController(accesspkg.Limits{RequestsPerMinute: 10, ConcurrentRequests: 2, AuditEntries: 10})
	if errAccessDiagnostics != nil {
		t.Fatalf("NewLocalController() error = %v", errAccessDiagnostics)
	}
	principal := accesspkg.Principal{SubjectID: "subject-one", TenantID: "tenant-one", ProjectID: "project-one", Roles: []accesspkg.Role{accesspkg.RoleCaller}}
	accessDiagnostics.Record(accesspkg.AuditEvent{Time: time.Date(2026, time.July, 20, 20, 0, 0, 0, time.UTC), Principal: &principal, Outcome: accesspkg.AuditOutcomeAuthorized, Permission: accesspkg.PermissionInvoke, Method: http.MethodPost, Path: "/vulcan/v1/executions", StatusCode: http.StatusAccepted})
	accessDiagnostics.Observe(accesspkg.Observation{ProjectID: "project-one", Permission: accesspkg.PermissionInvoke, StatusCode: http.StatusAccepted, Duration: time.Second})
	server, errServer := NewWithControlPlane(staticCatalog{}, ControlPlane{Query: staticManagementQuery{}, Commands: staticManagementCommands{}, ModelAccess: staticModelAccessCommands{}, CustomCatalogs: staticCustomCatalogOperations{}, Protocols: staticProtocolProfiles{}, APIKeys: access, Auth: access, Resources: access, InputPlans: access, Executions: staticExecutionAccess{}, Targets: access, ResourceDiagnostics: staticResourceDiagnostics{}, ExecutionDiagnostics: staticExecutionDiagnostics{}, ProviderFileDiagnostics: staticProviderFileDiagnostics{}, AccessDiagnostics: accessDiagnostics})
	if errServer != nil {
		t.Fatalf("NewWithControlPlane() error = %v", errServer)
	}
	for _, path := range []string{"/vulcan/manage/diagnostics/resources", "/vulcan/manage/diagnostics/executions", "/vulcan/manage/diagnostics/access"} {
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
	accessRequest := httptest.NewRequest(http.MethodGet, "/vulcan/manage/diagnostics/access", nil)
	accessRequest.Header.Set("Authorization", "Bearer manage-key")
	accessRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(accessRecorder, accessRequest)
	if accessRecorder.Code != http.StatusOK || !strings.Contains(accessRecorder.Body.String(), `"tenant_id":"tenant-one"`) || !strings.Contains(accessRecorder.Body.String(), `"requests":1`) {
		t.Fatalf("access diagnostics status=%d body=%s", accessRecorder.Code, accessRecorder.Body.String())
	}
	providerFilesPath := "/vulcan/manage/provider-instances/pvi_minimax/credentials/credential_minimax/files?endpoint_id=endpoint_minimax"
	unauthorized := httptest.NewRequest(http.MethodGet, providerFilesPath, nil)
	unauthorized.Header.Set("Authorization", "Bearer call-key")
	unauthorizedRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(unauthorizedRecorder, unauthorized)
	if unauthorizedRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("provider files call-plane status = %d", unauthorizedRecorder.Code)
	}
	request := httptest.NewRequest(http.MethodGet, providerFilesPath, nil)
	request.Header.Set("Authorization", "Bearer manage-key")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"file_id":"provider-file-1"`) || !strings.Contains(recorder.Body.String(), `"filename":"vision.png"`) {
		t.Fatalf("provider files status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	retrieveRequest := httptest.NewRequest(http.MethodGet, "/vulcan/manage/provider-instances/pvi_minimax/credentials/credential_minimax/files/provider-file-1?endpoint_id=endpoint_minimax", nil)
	retrieveRequest.Header.Set("Authorization", "Bearer manage-key")
	retrieveRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(retrieveRecorder, retrieveRequest)
	if retrieveRecorder.Code != http.StatusOK || !strings.Contains(retrieveRecorder.Body.String(), `"download_available":true`) || strings.Contains(retrieveRecorder.Body.String(), "download_url") {
		t.Fatalf("provider file retrieve status=%d body=%s", retrieveRecorder.Code, retrieveRecorder.Body.String())
	}
}
