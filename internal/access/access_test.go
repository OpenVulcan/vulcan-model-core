package access

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

// TestLocalControllerEnforcesRoleRateAndConcurrency verifies every local public-service boundary.
// TestLocalControllerEnforcesRoleRateAndConcurrency 验证本地公共服务的每个边界。
func TestLocalControllerEnforcesRoleRateAndConcurrency(t *testing.T) {
	controller, errController := NewLocalController(Limits{RequestsPerMinute: 2, ConcurrentRequests: 1, AuditEntries: 2})
	if errController != nil {
		t.Fatalf("NewLocalController() error = %v", errController)
	}
	principal := Principal{SubjectID: "api_example", TenantID: "tenant_example", ProjectID: "project_example", Roles: []Role{RoleCaller}}
	if errAuthorize := controller.Authorize(context.Background(), principal, PermissionInvoke); errAuthorize != nil {
		t.Fatalf("Authorize() error = %v", errAuthorize)
	}
	if errAuthorize := controller.Authorize(context.Background(), principal, PermissionManage); !errors.Is(errAuthorize, ErrAccessDenied) {
		t.Fatalf("Authorize() error = %v, want ErrAccessDenied", errAuthorize)
	}
	release, errAcquire := controller.Acquire(context.Background(), principal)
	if errAcquire != nil {
		t.Fatalf("Acquire() error = %v", errAcquire)
	}
	if _, errSecond := controller.Acquire(context.Background(), principal); !errors.Is(errSecond, ErrRateLimited) {
		t.Fatalf("concurrent Acquire() error = %v, want ErrRateLimited", errSecond)
	}
	release()
	if _, errThird := controller.Acquire(context.Background(), principal); errThird != nil {
		t.Fatalf("released Acquire() error = %v", errThird)
	}
}

// TestLocalControllerRetainsClosedIsolatedAuditOutcomes verifies unauthenticated events and principal copies remain safe.
// TestLocalControllerRetainsClosedIsolatedAuditOutcomes 验证未认证事件与主体副本保持安全。
func TestLocalControllerRetainsClosedIsolatedAuditOutcomes(t *testing.T) {
	controller, errController := NewLocalController(Limits{RequestsPerMinute: 2, ConcurrentRequests: 1, AuditEntries: 3})
	if errController != nil {
		t.Fatalf("NewLocalController() error = %v", errController)
	}
	principal := Principal{SubjectID: "subject", TenantID: "tenant", ProjectID: "project", Roles: []Role{RoleCaller}}
	controller.Record(AuditEvent{Time: time.Date(2026, time.July, 21, 23, 0, 0, 0, time.UTC), Principal: &principal, Outcome: AuditOutcomeAuthorized, Permission: PermissionInvoke, Method: http.MethodPost, Path: "/vulcan/v1/executions", StatusCode: http.StatusAccepted})
	controller.Record(AuditEvent{Time: time.Date(2026, time.July, 21, 23, 0, 1, 0, time.UTC), Outcome: AuditOutcomeUnauthenticated, Permission: PermissionInvoke, Method: http.MethodPost, Path: "/vulcan/v1/executions", StatusCode: http.StatusUnauthorized})
	controller.Record(AuditEvent{Time: time.Date(2026, time.July, 21, 23, 0, 2, 0, time.UTC), Outcome: AuditOutcome("unknown"), Permission: PermissionInvoke, Method: http.MethodPost, Path: "/vulcan/v1/executions", StatusCode: http.StatusForbidden})
	principal.SubjectID = "mutated"
	principal.Roles[0] = RoleAdministrator
	audit := controller.Audit()
	if len(audit) != 2 || audit[0].Principal == nil || audit[0].Principal.SubjectID != "subject" || audit[0].Principal.Roles[0] != RoleCaller || audit[1].Principal != nil || audit[1].Outcome != AuditOutcomeUnauthenticated {
		t.Fatalf("Audit() = %+v", audit)
	}
	audit[0].Principal.SubjectID = "returned-mutation"
	if retained := controller.Audit(); retained[0].Principal == nil || retained[0].Principal.SubjectID != "subject" {
		t.Fatalf("retained audit was aliased: %+v", retained)
	}
}
