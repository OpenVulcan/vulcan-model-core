package chat

import (
	"errors"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestProjectRequestRejectsExactModelSelectionTargetMismatch verifies immutable request-to-target binding.
// TestProjectRequestRejectsExactModelSelectionTargetMismatch 校验不可变的请求到目标绑定。
func TestProjectRequestRejectsExactModelSelectionTargetMismatch(t *testing.T) {
	// mismatchCase defines one exact selection field that must remain bound to the resolved target.
	// mismatchCase 定义一个必须与解析目标保持绑定的精确选择字段。
	type mismatchCase struct {
		// name identifies the exact immutable target field under test.
		// name 标识待测的精确不可变目标字段。
		name string
		// selection contains the deliberately mismatched model selection.
		// selection 包含有意构造的不匹配模型选择。
		selection vcp.ModelSelection
	}

	testCases := []mismatchCase{
		{
			name: "provider instance",
			selection: vcp.ModelSelection{
				Target:             vcp.ModelTargetExact,
				ProviderInstanceID: "pvi_other",
				ProviderModelID:    "mdl_1",
			},
		},
		{
			name: "provider model",
			selection: vcp.ModelSelection{
				Target:             vcp.ModelTargetExact,
				ProviderInstanceID: "pvi_1",
				ProviderModelID:    "mdl_other",
			},
		},
		{
			name: "execution profile",
			selection: vcp.ModelSelection{
				Target:             vcp.ModelTargetExact,
				ProviderInstanceID: "pvi_1",
				ProviderModelID:    "mdl_1",
				ExecutionProfileID: "profile_other",
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			request := chatTestRequest()
			request.ModelSelection = testCase.selection

			_, errProject := ProjectRequest(request, chatTarget(), ProfileCapabilities{}, "lin_boundary", time.Unix(40, 0))
			if !errors.Is(errProject, ErrInvalidTarget) {
				t.Fatalf("ProjectRequest() error = %v, want ErrInvalidTarget", errProject)
			}
		})
	}
}

// TestProjectRequestAcceptsMatchingExactModelSelection verifies all supplied exact fields can match the target.
// TestProjectRequestAcceptsMatchingExactModelSelection 校验所有已提供的精确字段均可与目标匹配。
func TestProjectRequestAcceptsMatchingExactModelSelection(t *testing.T) {
	request := chatTestRequest()
	request.ModelSelection.ExecutionProfileID = "profile_1"

	projected, errProject := ProjectRequest(request, chatTarget(), ProfileCapabilities{}, "lin_boundary_match", time.Unix(41, 0))
	if errProject != nil {
		t.Fatalf("ProjectRequest() error = %v", errProject)
	}
	if projected.Upstream.Model != "gpt-test" {
		t.Fatalf("upstream model = %q, want %q", projected.Upstream.Model, "gpt-test")
	}
}

// TestProjectRequestRejectsInvalidVCPRequest verifies the pure Chat profile enforces the same canonical request validation as executable profiles.
// TestProjectRequestRejectsInvalidVCPRequest 校验纯 Chat Profile 与可执行 Profile 一样强制执行规范请求校验。
func TestProjectRequestRejectsInvalidVCPRequest(t *testing.T) {
	request := chatTestRequest()
	request.ProtocolVersion = "vcp.invalid"

	_, errProject := ProjectRequest(request, chatTarget(), ProfileCapabilities{}, "lin_invalid_vcp", time.Unix(42, 0))
	if !errors.Is(errProject, vcp.ErrInvalidRequest) {
		t.Fatalf("ProjectRequest() error = %v, want ErrInvalidRequest", errProject)
	}
}
