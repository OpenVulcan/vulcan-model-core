package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// staticSelectionAccess combines existing control-plane fixtures with one deterministic safe selection.
// staticSelectionAccess 将既有控制面夹具与一个确定性安全选择组合。
type staticSelectionAccess struct {
	staticControlAccess
}

// Select returns one exact model target and intentionally exposes no endpoint or credential identifiers.
// Select 返回一个精确模型 Target 且有意不暴露入口或凭据标识。
func (staticSelectionAccess) Select(_ context.Context, request vcp.ExecutionSelectionRequest, _ time.Time) (vcp.ExecutionSelection, error) {
	contextTokens := int64(1_048_576)
	return vcp.ExecutionSelection{RequestID: request.RequestID, Target: vcp.TargetSelection{Model: &vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: request.ProviderInstanceID, ProviderModelID: "model_selected", ExecutionProfileID: "profile_selected", RequiredRegion: request.RequiredRegion}}, Operation: request.Operation, EffectiveContextTokens: &contextTokens, CapabilityRevision: 2, CatalogRevision: 3}, nil
}

// TestExecutionSelectionHTTPReturnsOnlySafeExactTarget verifies authenticated capability preselection output.
// TestExecutionSelectionHTTPReturnsOnlySafeExactTarget 验证经过认证的能力预选仅返回安全精确 Target。
func TestExecutionSelectionHTTPReturnsOnlySafeExactTarget(t *testing.T) {
	access := staticControlAccess{}
	server, errServer := NewWithControlPlane(staticCatalog{}, ControlPlane{Query: staticManagementQuery{}, Commands: staticManagementCommands{}, ModelAccess: staticModelAccessCommands{}, CustomCatalogs: staticCustomCatalogOperations{}, Protocols: staticProtocolProfiles{}, APIKeys: access, Auth: access, Resources: access, InputPlans: access, Executions: staticExecutionAccess{}, Targets: staticSelectionAccess{}})
	if errServer != nil {
		t.Fatalf("NewWithControlPlane() error = %v", errServer)
	}
	request := httptest.NewRequest(http.MethodPost, "/vulcan/v1/selections", strings.NewReader(`{"protocol_version":"1.0","request_id":"selection_test","provider_instance_id":"pvi_test","operation":"conversation.respond","required_context_tokens":500000,"required_capabilities":["streaming"],"required_region":"Global"}`))
	request.Header.Set("Authorization", "Bearer call-key")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"provider_model_id":"model_selected"`) || !strings.Contains(recorder.Body.String(), `"required_region":"Global"`) || strings.Contains(recorder.Body.String(), "credential") || strings.Contains(recorder.Body.String(), "endpoint") {
		t.Fatalf("selection status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
