package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/inputplan"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// recordingInputPlans captures the authenticated owner and returns one safe fixture plan.
// recordingInputPlans 捕获已认证所有者并返回一个安全夹具方案。
type recordingInputPlans struct {
	// owner records the authenticated API key identifier.
	// owner 记录已认证 API Key 标识。
	owner string
}

// CreateInputPlan records the server-installed owner and returns one plan with a private target.
// CreateInputPlan 记录服务写入所有者并返回一个带私有 Target 的方案。
func (p *recordingInputPlans) CreateInputPlan(_ context.Context, request inputplan.Request) (inputplan.Plan, error) {
	p.owner = request.OwnerAPIKeyID
	now := time.Date(2026, 7, 20, 14, 0, 0, 0, time.UTC)
	return inputplan.Plan{ID: "ipl_0123456789abcdef0123456789abcdef", OwnerAPIKeyID: request.OwnerAPIKeyID, Accepted: true, Operation: request.Operation, Model: request.Model, Target: resolve.Target{ProviderInstanceID: request.Model.ProviderInstanceID, ProviderModelID: request.Model.ProviderModelID, ExecutionProfileID: request.Model.ExecutionProfileID, CredentialID: "credential_private"}, CapabilityRevision: 1, CatalogRevision: 1, Inputs: []inputplan.PlannedInput{{InputID: "image", ResourceID: "res_0123456789abcdef0123456789abcdef", Kind: vcp.MediaImage, MIMEType: "image/png", SizeBytes: 1, Role: vcp.MediaRoleUnderstanding, ClientStep: inputplan.ClientStepReferenceExisting}}, CreatedAt: now, ExpiresAt: now.Add(time.Minute), Revision: 1}, nil
}

// TestInputPlanHTTPInstallsOwnerAndHidesExecutionTarget verifies call-key ownership and safe plan projection.
// TestInputPlanHTTPInstallsOwnerAndHidesExecutionTarget 验证调用密钥归属与安全方案投影。
func TestInputPlanHTTPInstallsOwnerAndHidesExecutionTarget(t *testing.T) {
	t.Parallel()
	access := staticControlAccess{}
	plans := &recordingInputPlans{}
	server, errServer := NewWithControlPlane(staticCatalog{}, ControlPlane{Query: staticManagementQuery{}, Commands: staticManagementCommands{}, ModelAccess: staticModelAccessCommands{}, CustomCatalogs: staticCustomCatalogOperations{}, Protocols: staticProtocolProfiles{}, APIKeys: access, Auth: access, Resources: access, InputPlans: plans, Executions: staticExecutionAccess{}, Targets: access})
	if errServer != nil {
		t.Fatalf("NewWithControlPlane() error = %v", errServer)
	}
	body := `{"model":{"target":"exact","provider_instance_id":"pvi_1","provider_model_id":"model_1","execution_profile_id":"profile_1"},"operation":"conversation.respond","inputs":[{"input_id":"image","resource_id":"res_0123456789abcdef0123456789abcdef","role":"understanding"}]}`
	request := httptest.NewRequest(http.MethodPost, "/vulcan/v1/input-plans", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer call-key")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated || plans.owner != "api_test" {
		t.Fatalf("status=%d owner=%q body=%s", recorder.Code, plans.owner, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "credential_private") || strings.Contains(recorder.Body.String(), "OwnerAPIKeyID") || strings.Contains(recorder.Body.String(), "Target") {
		t.Fatalf("input plan response leaked private target: %s", recorder.Body.String())
	}
}
