package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/execution"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// recordingExecutionService captures authenticated ownership and returns one terminal replayable execution.
// recordingExecutionService 捕获已认证所有权并返回一个终态可回放执行。
type recordingExecutionService struct {
	// owner is the last owner identifier injected by authentication middleware.
	// owner 是认证中间件注入的最后所有者标识。
	owner string
	// record is the deterministic owner-scoped result.
	// record 是确定性所有者作用域结果。
	record execution.Record
	// events is the deterministic durable event log.
	// events 是确定性持久化事件日志。
	events []execution.Event
}

// Create records authenticated ownership and returns the terminal fixture.
// Create 记录已认证所有权并返回终态夹具。
func (s *recordingExecutionService) Create(_ context.Context, owner string, _ vcp.ExecutionRequest) (execution.Record, bool, error) {
	s.owner = owner
	return s.record, false, nil
}

// Get returns the terminal fixture only to its authenticated owner.
// Get 仅向已认证所有者返回终态夹具。
func (s *recordingExecutionService) Get(_ context.Context, owner string, executionID string) (execution.Record, error) {
	if owner != "api_test" || executionID != s.record.ID {
		return execution.Record{}, execution.ErrExecutionNotFound
	}
	return s.record, nil
}

// Events returns durable events strictly after the requested sequence.
// Events 返回请求序号之后的持久化事件。
func (s *recordingExecutionService) Events(_ context.Context, owner string, executionID string, after uint64) ([]execution.Event, error) {
	if owner != "api_test" || executionID != s.record.ID {
		return nil, execution.ErrExecutionNotFound
	}
	if after >= uint64(len(s.events)) {
		return []execution.Event{}, nil
	}
	return append([]execution.Event(nil), s.events[after:]...), nil
}

// Cancel returns the already terminal deterministic fixture.
// Cancel 返回已经终止的确定性夹具。
func (s *recordingExecutionService) Cancel(_ context.Context, owner string, executionID string) (execution.Record, error) {
	return s.Get(context.Background(), owner, executionID)
}

// TestExecutionHTTPInjectsOwnerRedactsPrivateAffinityAndReplaysSSE verifies the complete call-plane boundary.
// TestExecutionHTTPInjectsOwnerRedactsPrivateAffinityAndReplaysSSE 验证完整调用面边界。
func TestExecutionHTTPInjectsOwnerRedactsPrivateAffinityAndReplaysSSE(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	executionID := "exe_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	record := execution.Record{
		ID: executionID, Status: execution.StatusSucceeded, Operation: vcp.OperationConversationRespond,
		Result:       &execution.Result{Conversation: &vcp.Response{ResponseID: "response_test", Status: vcp.ResponseCompleted}},
		ProviderTask: &execution.ProviderTaskSnapshot{ProviderTaskID: "upstream-secret-task", Target: resolve.Target{CredentialID: "credential-secret"}, PollAfter: now},
		CreatedAt:    now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour), Revision: 3,
	}
	events := []execution.Event{
		{ExecutionID: executionID, EventID: "evt_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_1", Sequence: 1, Time: now, Type: execution.EventExecutionAccepted, Lifecycle: &execution.LifecycleEvent{Status: execution.StatusAccepted}},
		{ExecutionID: executionID, EventID: "evt_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_2", Sequence: 2, Time: now, Type: execution.EventExecutionSucceeded, Lifecycle: &execution.LifecycleEvent{Status: execution.StatusSucceeded}},
	}
	executions := &recordingExecutionService{record: record, events: events}
	access := staticControlAccess{}
	server, errServer := NewWithControlPlane(staticCatalog{}, ControlPlane{Query: staticManagementQuery{}, Commands: staticManagementCommands{}, ModelAccess: staticModelAccessCommands{}, CustomCatalogs: staticCustomCatalogOperations{}, Protocols: staticProtocolProfiles{}, APIKeys: access, Auth: access, Resources: access, InputPlans: access, Executions: executions, Targets: access})
	if errServer != nil {
		t.Fatalf("create server: %v", errServer)
	}
	create := httptest.NewRequest(http.MethodPost, "/vulcan/v1/executions", strings.NewReader(`{"protocol_version":"vcp-1","request_id":"request_test","target":{"model":{"target":"exact","provider_instance_id":"pvi_test","provider_model_id":"model_test","execution_profile_id":"profile_test"}},"operation":"conversation.respond","stream":false,"payload":{"conversation":{}},"projection_policy":{},"budget":{}}`))
	create.Header.Set("Authorization", "Bearer call-key")
	createRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(createRecorder, create)
	if createRecorder.Code != http.StatusCreated || executions.owner != "api_test" {
		t.Fatalf("create status=%d owner=%q body=%s", createRecorder.Code, executions.owner, createRecorder.Body.String())
	}
	if strings.Contains(createRecorder.Body.String(), "upstream-secret-task") || strings.Contains(createRecorder.Body.String(), "credential-secret") {
		t.Fatalf("execution response leaked private affinity: %s", createRecorder.Body.String())
	}
	replay := httptest.NewRequest(http.MethodGet, "/vulcan/v1/executions/"+executionID+"/events", nil)
	replay.Header.Set("Authorization", "Bearer call-key")
	replay.Header.Set("Last-Event-ID", events[0].EventID)
	replayRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(replayRecorder, replay)
	if replayRecorder.Code != http.StatusOK || strings.Contains(replayRecorder.Body.String(), events[0].EventID) || !strings.Contains(replayRecorder.Body.String(), events[1].EventID) || !strings.Contains(replayRecorder.Header().Get("Content-Type"), "text/event-stream") {
		t.Fatalf("SSE replay status=%d headers=%v body=%s", replayRecorder.Code, replayRecorder.Header(), replayRecorder.Body.String())
	}
	crossExecution := httptest.NewRequest(http.MethodGet, "/vulcan/v1/executions/"+executionID+"/events", nil)
	crossExecution.Header.Set("Authorization", "Bearer call-key")
	crossExecution.Header.Set("Last-Event-ID", "evt_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb_1")
	crossRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(crossRecorder, crossExecution)
	if crossRecorder.Code != http.StatusBadRequest {
		t.Fatalf("cross-execution Last-Event-ID status=%d body=%s", crossRecorder.Code, crossRecorder.Body.String())
	}
}
