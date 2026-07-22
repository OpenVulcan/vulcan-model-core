package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	accesspkg "github.com/OpenVulcan/vulcan-model-core/internal/access"
	"github.com/OpenVulcan/vulcan-model-core/internal/execution"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// recordingExtractTestExecutions records the exact management extraction request and returns one partial result.
// recordingExtractTestExecutions 记录精确的管理提取请求并返回一个部分成功结果。
type recordingExtractTestExecutions struct {
	// ownerID records the isolated durable execution owner.
	// ownerID 记录隔离的持久化执行所有者。
	ownerID string
	// request records the typed VCP request submitted by the management endpoint.
	// request 记录管理端点提交的类型化 VCP 请求。
	request vcp.ExecutionRequest
}

// Create records and completes one deterministic web-extraction execution.
// Create 记录并完成一个确定性的网页内容提取执行。
func (e *recordingExtractTestExecutions) Create(_ context.Context, ownerID string, request vcp.ExecutionRequest) (execution.Record, bool, error) {
	e.ownerID = ownerID
	e.request = request
	return execution.Record{ID: "exe_extract_test", Status: execution.StatusSucceeded, Operation: vcp.OperationWebExtract, Result: &execution.Result{Extract: &vcp.WebExtractResponse{Results: []vcp.WebExtractResult{{URL: request.Payload.WebExtract.URLs[0], RawContent: "content"}}, FailedResults: []vcp.WebExtractFailure{{URL: request.Payload.WebExtract.URLs[1], Error: "blocked"}}, ProviderRequestID: "req_extract"}}}, false, nil
}

// Get reports no independently fetched fixture execution.
// Get 报告不存在可独立获取的测试执行。
func (*recordingExtractTestExecutions) Get(context.Context, string, string) (execution.Record, error) {
	return execution.Record{}, execution.ErrExecutionNotFound
}

// Events reports no independently streamed fixture events.
// Events 报告不存在可独立流式读取的测试事件。
func (*recordingExtractTestExecutions) Events(context.Context, string, string, uint64) ([]execution.Event, error) {
	return nil, execution.ErrExecutionNotFound
}

// Cancel reports no independently cancellable fixture execution.
// Cancel 报告不存在可独立取消的测试执行。
func (*recordingExtractTestExecutions) Cancel(context.Context, string, string) (execution.Record, error) {
	return execution.Record{}, execution.ErrExecutionNotFound
}

// TestManagementExtractServiceExecutesTypedProfile verifies the exact service profile reaches durable execution.
// TestManagementExtractServiceExecutesTypedProfile 校验精确服务规格到达持久化执行边界。
func TestManagementExtractServiceExecutesTypedProfile(t *testing.T) {
	executions := &recordingExtractTestExecutions{}
	access := staticControlAccess{}
	accessController, errAccessController := accesspkg.NewLocalController(accesspkg.Limits{RequestsPerMinute: 1000, ConcurrentRequests: 10, AuditEntries: 1000})
	if errAccessController != nil {
		t.Fatalf("create access controller: %v", errAccessController)
	}
	server, errServer := NewWithControlPlane(staticCatalog{}, ControlPlane{Query: staticManagementQuery{}, Commands: staticManagementCommands{}, ModelAccess: staticModelAccessCommands{}, CustomCatalogs: staticCustomCatalogOperations{}, Protocols: staticProtocolProfiles{}, APIKeys: access, Auth: access, Access: accessController, Resources: access, InputPlans: access, Executions: executions, Targets: access})
	if errServer != nil {
		t.Fatalf("create server: %v", errServer)
	}
	chunks := 2
	timeout := 15.0
	payload := managementExtractTestRequest{ServiceOfferingID: "service_offer_extract", ExecutionProfileID: "profile_extract", URLs: []string{"https://example.com/a", "https://example.org/b"}, Query: "router", ChunksPerSource: &chunks, Depth: vcp.WebExtractDepthAdvanced, Format: vcp.WebExtractFormatMarkdown, IncludeImages: true, IncludeFavicon: true, TimeoutSeconds: &timeout}
	body, errMarshal := json.Marshal(payload)
	if errMarshal != nil {
		t.Fatalf("marshal request: %v", errMarshal)
	}
	request := httptest.NewRequest(http.MethodPost, "/vulcan/manage/provider-instances/pvi_test/services/service_extract/extract-test", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer manage-key")
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response managementExtractTestResponse
	if errDecode := json.NewDecoder(recorder.Body).Decode(&response); errDecode != nil {
		t.Fatalf("decode response: %v", errDecode)
	}
	if response.ExecutionID != "exe_extract_test" || len(response.Extract.Results) != 1 || len(response.Extract.FailedResults) != 1 {
		t.Fatalf("response=%#v", response)
	}
	if executions.ownerID != managementExtractTestOwnerID || executions.request.Target.Model != nil || executions.request.Target.Service == nil || executions.request.Target.Service.ProviderServiceID != "service_extract" || executions.request.Payload.WebExtract == nil || executions.request.Payload.WebExtract.Query != "router" {
		t.Fatalf("owner=%q request=%#v", executions.ownerID, executions.request)
	}
}
