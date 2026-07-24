package execution

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/routertool"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestModelToolValidationReturnsStableErrors verifies exact public codes for profile and dependency failures.
// TestModelToolValidationReturnsStableErrors 校验规格与依赖失败会返回精确公开错误码。
func TestModelToolValidationReturnsStableErrors(t *testing.T) {
	tests := []struct {
		name         string
		operation    vcp.ConversationOperation
		capabilities catalog.ModelCapabilities
		wantCode     vcp.ModelToolErrorCode
		wantToolID   string
	}{
		{
			name:       "native standard unsupported",
			operation:  vcp.ConversationOperation{ModelTools: vcp.ModelToolSelection{Standard: []vcp.StandardModelToolSelection{{Kind: vcp.StandardModelToolWebSearch, Mode: vcp.ModelToolNative}}}},
			wantCode:   vcp.ModelToolNotSupported,
			wantToolID: string(vcp.StandardModelToolWebSearch),
		},
		{
			name:      "standard dependency missing",
			operation: vcp.ConversationOperation{ModelTools: vcp.ModelToolSelection{Standard: []vcp.StandardModelToolSelection{{Kind: vcp.StandardModelToolWebExtractor, Mode: vcp.ModelToolNative}}}},
			capabilities: catalog.ModelCapabilities{StandardTools: []catalog.StandardModelToolCapability{{
				Kind:              vcp.StandardModelToolWebExtractor,
				Native:            true,
				Requires:          []vcp.StandardModelToolKind{vcp.StandardModelToolWebSearch},
				AllowsCallerTools: true,
			}}},
			wantCode:   vcp.ModelToolDependencyMissing,
			wantToolID: string(vcp.StandardModelToolWebExtractor),
		},
		{
			name:       "extra unsupported",
			operation:  vcp.ConversationOperation{ModelTools: vcp.ModelToolSelection{Extra: []string{"code_interpreter"}}},
			wantCode:   vcp.ModelExtraToolNotSupported,
			wantToolID: "code_interpreter",
		},
		{
			name:       "router extension requires tool calling",
			operation:  vcp.ConversationOperation{ModelTools: vcp.ModelToolSelection{RouterExtensions: []vcp.RouterExtensionKind{vcp.RouterExtensionImageUnderstanding}}},
			wantCode:   vcp.ModelToolModeNotSupported,
			wantToolID: "image_understanding",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			errValidate := validateModelToolSelectionAgainstTarget(test.operation, test.capabilities, false)
			var modelToolError *vcp.ModelToolError
			if !errors.As(errValidate, &modelToolError) {
				t.Fatalf("expected model tool error, got %v", errValidate)
			}
			if modelToolError.Code != test.wantCode || modelToolError.ToolID != test.wantToolID || modelToolError.Phase != "validation" || modelToolError.Retryable {
				t.Fatalf("unexpected stable model tool error: %#v", modelToolError)
			}
			if stableFailureCode(errValidate) != string(test.wantCode) {
				t.Fatalf("stable failure code did not preserve model tool code: %s", stableFailureCode(errValidate))
			}
		})
	}
}

// TestModelToolErrorPreservesInvalidRequestClassification verifies compatibility with existing invalid-request handling.
// TestModelToolErrorPreservesInvalidRequestClassification 校验与现有无效请求处理保持兼容。
func TestModelToolErrorPreservesInvalidRequestClassification(t *testing.T) {
	errValue := vcp.NewModelToolError(vcp.RouterToolBindingMissing, string(vcp.StandardModelToolWebSearch), "planning", false)
	if !errors.Is(errValue, vcp.ErrInvalidRequest) {
		t.Fatalf("model tool error did not retain invalid request classification: %v", errValue)
	}
}

// TestRouterBindingErrorCodeSeparatesMissingAndUnavailable verifies public planning errors retain actionable configuration state.
// TestRouterBindingErrorCodeSeparatesMissingAndUnavailable 校验公开规划错误会保留可操作的配置状态。
func TestRouterBindingErrorCodeSeparatesMissingAndUnavailable(t *testing.T) {
	if code := routerBindingErrorCode(routertool.ErrBindingNotFound); code != vcp.RouterToolBindingMissing {
		t.Fatalf("missing binding code = %s", code)
	}
	if code := routerBindingErrorCode(routertool.ErrBindingUnavailable); code != vcp.RouterToolBindingUnavailable {
		t.Fatalf("unavailable binding code = %s", code)
	}
}

// TestResolveModelToolPlanRejectsUnrepresentableToolChoice verifies native and extra tools are never falsely advertised as forceable provider functions.
// TestResolveModelToolPlanRejectsUnrepresentableToolChoice 校验原生及额外工具绝不会被错误声明为可强制选择的供应商函数。
func TestResolveModelToolPlanRejectsUnrepresentableToolChoice(t *testing.T) {
	tests := []struct {
		name      string
		operation vcp.ConversationOperation
		wantTool  string
	}{
		{
			name: "named native standard",
			operation: vcp.ConversationOperation{
				ModelTools: vcp.ModelToolSelection{Standard: []vcp.StandardModelToolSelection{{
					Kind: vcp.StandardModelToolWebSearch,
					Mode: vcp.ModelToolNative,
				}}},
				ToolPolicy: vcp.ToolPolicy{Choice: vcp.ToolChoiceNamed, NamedTool: string(vcp.StandardModelToolWebSearch)},
			},
			wantTool: string(vcp.StandardModelToolWebSearch),
		},
		{
			name: "named provider extra",
			operation: vcp.ConversationOperation{
				ModelTools: vcp.ModelToolSelection{Extra: []string{"code_interpreter"}},
				ToolPolicy: vcp.ToolPolicy{Choice: vcp.ToolChoiceNamed, NamedTool: "code_interpreter"},
			},
			wantTool: "code_interpreter",
		},
		{
			name: "required native only",
			operation: vcp.ConversationOperation{
				ModelTools: vcp.ModelToolSelection{Standard: []vcp.StandardModelToolSelection{{
					Kind: vcp.StandardModelToolWebSearch,
					Mode: vcp.ModelToolNative,
				}}},
				ToolPolicy: vcp.ToolPolicy{Choice: vcp.ToolChoiceRequired},
			},
			wantTool: "tool_policy.required",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := vcp.ExecutionRequest{
				Operation: vcp.OperationConversationRespond,
				Payload:   vcp.OperationPayload{Conversation: &test.operation},
			}
			_, errPlan := (&Service{}).resolveModelToolPlan(context.Background(), request, resolve.Target{CatalogRevision: 1}, time.Unix(1, 0).UTC())
			var modelToolError *vcp.ModelToolError
			if !errors.As(errPlan, &modelToolError) || modelToolError.Code != vcp.ModelToolModeNotSupported || modelToolError.ToolID != test.wantTool || modelToolError.Phase != "planning" {
				t.Fatalf("planning error = %#v, want mode_not_supported for %q", modelToolError, test.wantTool)
			}
		})
	}
}

// TestCanonicalizeLegacyModelToolsMigratesHostedSearchWithDiagnostic verifies the compatibility bridge is explicit and does not mutate caller-owned slices.
// TestCanonicalizeLegacyModelToolsMigratesHostedSearchWithDiagnostic 校验兼容桥接会显式记录且不会修改调用方拥有的切片。
func TestCanonicalizeLegacyModelToolsMigratesHostedSearchWithDiagnostic(t *testing.T) {
	operation := &vcp.ConversationOperation{Tools: []vcp.ToolDefinition{
		{Kind: vcp.ToolNativeWebSearch, Name: "web_search"},
		{Kind: vcp.ToolFunction, Namespace: "caller", Name: "lookup", Parameters: []byte(`{"type":"object","additionalProperties":false}`)},
	}, ToolPolicy: vcp.ToolPolicy{Choice: vcp.ToolChoiceAuto}}
	request := vcp.ExecutionRequest{
		ProtocolVersion: vcp.ProtocolVersion,
		RequestID:       "request_legacy_search",
		Target: vcp.TargetSelection{Model: &vcp.ModelSelection{
			Target:             vcp.ModelTargetExact,
			ProviderInstanceID: "pvi_test",
			ProviderModelID:    "model_test",
			ExecutionProfileID: "profile_test",
		}},
		Operation: vcp.OperationConversationRespond,
		Payload:   vcp.OperationPayload{Conversation: operation},
	}
	canonical, diagnostics, errCanonical := canonicalizeLegacyModelTools(request)
	if errCanonical != nil {
		t.Fatalf("canonicalize legacy tools: %v", errCanonical)
	}
	if len(operation.Tools) != 2 {
		t.Fatalf("caller-owned operation was mutated: %#v", operation.Tools)
	}
	canonicalOperation := canonical.Payload.Conversation
	if canonicalOperation == nil || len(canonicalOperation.Tools) != 1 || canonicalOperation.Tools[0].Kind != vcp.ToolFunction || len(canonicalOperation.ModelTools.Standard) != 1 || canonicalOperation.ModelTools.Standard[0].Kind != vcp.StandardModelToolWebSearch || canonicalOperation.ModelTools.Standard[0].Mode != vcp.ModelToolNative {
		t.Fatalf("canonical operation = %#v", canonicalOperation)
	}
	if len(diagnostics) != 1 || diagnostics[0].Code != vcp.ModelToolDiagnosticLegacyNativeWebSearchMigrated {
		t.Fatalf("compatibility diagnostics = %#v", diagnostics)
	}
}

// TestCanonicalizeLegacyModelToolsRejectsConflictingExplicitMode verifies legacy native intent cannot override an authoritative disabled or Router selection.
// TestCanonicalizeLegacyModelToolsRejectsConflictingExplicitMode 校验旧原生意图不能覆盖权威禁用或 Router 选择。
func TestCanonicalizeLegacyModelToolsRejectsConflictingExplicitMode(t *testing.T) {
	request := vcp.ExecutionRequest{
		Operation: vcp.OperationConversationRespond,
		Payload: vcp.OperationPayload{Conversation: &vcp.ConversationOperation{
			Tools: []vcp.ToolDefinition{{Kind: vcp.ToolNativeWebSearch, Name: "web_search"}},
			ModelTools: vcp.ModelToolSelection{Standard: []vcp.StandardModelToolSelection{{
				Kind: vcp.StandardModelToolWebSearch,
				Mode: vcp.ModelToolRouter,
			}}},
		}},
	}
	_, _, errCanonical := canonicalizeLegacyModelTools(request)
	var modelToolError *vcp.ModelToolError
	if !errors.As(errCanonical, &modelToolError) || modelToolError.Code != vcp.ModelToolModeNotSupported || modelToolError.Phase != "compatibility" {
		t.Fatalf("compatibility conflict = %#v", modelToolError)
	}
}
