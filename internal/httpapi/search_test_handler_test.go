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

// recordingSearchTestExecutions records the exact management diagnostic request and returns one provider-confirmed result.
// recordingSearchTestExecutions 记录精确的管理诊断请求并返回一个供应商确认结果。
type recordingSearchTestExecutions struct {
	// ownerID records the isolated durable execution owner.
	// ownerID 记录隔离的持久化执行所有者。
	ownerID string
	// request records the typed VCP request submitted by the management endpoint.
	// request 记录管理端点提交的类型化 VCP 请求。
	request vcp.ExecutionRequest
}

// Create records and completes one deterministic web-search execution.
// Create 记录并完成一个确定性网页搜索执行。
func (e *recordingSearchTestExecutions) Create(_ context.Context, ownerID string, request vcp.ExecutionRequest) (execution.Record, bool, error) {
	e.ownerID = ownerID
	e.request = request
	return execution.Record{ID: "exe_search_test", Status: execution.StatusSucceeded, Operation: vcp.OperationSearchWeb, Result: &execution.Result{Search: &vcp.WebSearchResponse{Query: request.Payload.SearchWeb.Query, Evidence: vcp.SearchExecutionEvidence{Status: vcp.SearchExecutionConfirmed}, Results: []vcp.WebSearchResult{{ID: "result_1", Rank: 1, Title: "OpenVulcan", URL: "https://openvulcan.example", SourceDomain: "openvulcan.example", Snippet: "Unified model routing."}}}}}, false, nil
}

// Get reports no independently fetched fixture execution.
// Get 报告不存在可独立获取的测试执行。
func (*recordingSearchTestExecutions) Get(context.Context, string, string) (execution.Record, error) {
	return execution.Record{}, execution.ErrExecutionNotFound
}

// Events reports no independently streamed fixture events.
// Events 报告不存在可独立流式读取的测试事件。
func (*recordingSearchTestExecutions) Events(context.Context, string, string, uint64) ([]execution.Event, error) {
	return nil, execution.ErrExecutionNotFound
}

// Cancel reports no independently cancellable fixture execution.
// Cancel 报告不存在可独立取消的测试执行。
func (*recordingSearchTestExecutions) Cancel(context.Context, string, string) (execution.Record, error) {
	return execution.Record{}, execution.ErrExecutionNotFound
}

// TestManagementSearchServiceExecutesTypedProfile verifies management auth runs a real service target without model discovery.
// TestManagementSearchServiceExecutesTypedProfile 验证管理认证会运行真实服务目标且不执行模型发现。
func TestManagementSearchServiceExecutesTypedProfile(t *testing.T) {
	// executions captures the exact service-scoped request reaching the durable execution boundary.
	// executions 捕获到达持久执行边界的精确服务作用域请求。
	executions := &recordingSearchTestExecutions{}
	// access supplies deterministic management authentication and the remaining required control dependencies.
	// access 提供确定性管理认证及其余必需控制依赖。
	access := staticControlAccess{}
	accessController, errAccessController := accesspkg.NewLocalController(accesspkg.Limits{RequestsPerMinute: 1000, ConcurrentRequests: 10, AuditEntries: 1000})
	if errAccessController != nil {
		t.Fatalf("create access controller: %v", errAccessController)
	}
	server, errServer := NewWithControlPlane(staticCatalog{}, ControlPlane{Query: staticManagementQuery{}, Commands: staticManagementCommands{}, ModelAccess: staticModelAccessCommands{}, CustomCatalogs: staticCustomCatalogOperations{}, Protocols: staticProtocolProfiles{}, APIKeys: access, Auth: access, Access: accessController, Resources: access, InputPlans: access, Executions: executions, Targets: access})
	if errServer != nil {
		t.Fatalf("create server: %v", errServer)
	}
	payload := managementSearchTestRequest{Query: "OpenVulcan router", ServiceOfferingID: "service_offer_search", ExecutionProfileID: "profile_search", OutputMode: vcp.WebSearchOutputResults, EvidenceRequirement: vcp.SearchEvidenceVerified}
	body, errMarshal := json.Marshal(payload)
	if errMarshal != nil {
		t.Fatalf("marshal request: %v", errMarshal)
	}
	request := httptest.NewRequest(http.MethodPost, "/vulcan/manage/provider-instances/pvi_test/services/service_search/search-test", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer manage-key")
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response managementSearchTestResponse
	if errDecode := json.NewDecoder(recorder.Body).Decode(&response); errDecode != nil {
		t.Fatalf("decode response: %v", errDecode)
	}
	if response.ExecutionID != "exe_search_test" || len(response.Search.Results) != 1 || response.Search.Results[0].URL != "https://openvulcan.example" {
		t.Fatalf("response=%#v", response)
	}
	if executions.ownerID != managementSearchTestOwnerID || executions.request.Target.Model != nil || executions.request.Target.Service == nil || executions.request.Target.Service.ProviderServiceID != "service_search" || executions.request.Payload.SearchWeb == nil || executions.request.Payload.SearchWeb.Query != "OpenVulcan router" {
		t.Fatalf("owner=%q request=%#v", executions.ownerID, executions.request)
	}
}
