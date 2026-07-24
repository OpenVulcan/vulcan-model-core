package vcp

import (
	"errors"
	"testing"
)

// TestModelToolSelectionValidatesClosedKinds verifies valid explicit modes and stable extension identifiers.
// TestModelToolSelectionValidatesClosedKinds 校验有效显式方式与稳定扩展标识。
func TestModelToolSelectionValidatesClosedKinds(t *testing.T) {
	selection := ModelToolSelection{
		Standard: []StandardModelToolSelection{
			{Kind: StandardModelToolWebSearch, Mode: ModelToolNative},
			{Kind: StandardModelToolWebExtractor, Mode: ModelToolRouter},
		},
		Extra:            []string{"t2i_search", "code_interpreter"},
		RouterExtensions: []RouterExtensionKind{RouterExtensionImageUnderstanding},
	}
	if errValidate := selection.Validate(); errValidate != nil {
		t.Fatalf("validate model tool selection: %v", errValidate)
	}
	if !selection.Enabled() || !selection.ContainsEnabledName("web_search") || !selection.ContainsEnabledName("t2i_search") || !selection.ContainsEnabledName("image_understanding") {
		t.Fatalf("enabled model tools were not discoverable: %#v", selection)
	}
}

// TestModelToolSelectionRejectsDuplicatesAndUnknownValues verifies ambiguous or unregistered declarations fail explicitly.
// TestModelToolSelectionRejectsDuplicatesAndUnknownValues 校验有歧义或未注册的声明会显式失败。
func TestModelToolSelectionRejectsDuplicatesAndUnknownValues(t *testing.T) {
	cases := []ModelToolSelection{
		{Standard: []StandardModelToolSelection{{Kind: "unknown", Mode: ModelToolNative}}},
		{Standard: []StandardModelToolSelection{{Kind: StandardModelToolWebSearch, Mode: "automatic"}}},
		{Standard: []StandardModelToolSelection{{Kind: StandardModelToolWebSearch, Mode: ModelToolNative}, {Kind: StandardModelToolWebSearch, Mode: ModelToolRouter}}},
		{Extra: []string{"Code Interpreter"}},
		{RouterExtensions: []RouterExtensionKind{RouterExtensionImageUnderstanding, RouterExtensionImageUnderstanding}},
	}
	for index, selection := range cases {
		if errValidate := selection.Validate(); !errors.Is(errValidate, ErrInvalidRequest) {
			t.Fatalf("case %d error = %v, want ErrInvalidRequest", index, errValidate)
		}
	}
}

// TestNamedToolPolicyAcceptsEnabledModelTool verifies named selection no longer requires a caller-authored ToolDefinition.
// TestNamedToolPolicyAcceptsEnabledModelTool 校验指定选择不再要求调用方编写 ToolDefinition。
func TestNamedToolPolicyAcceptsEnabledModelTool(t *testing.T) {
	request := testTextRequest()
	request.ModelTools = ModelToolSelection{Standard: []StandardModelToolSelection{{Kind: StandardModelToolWebSearch, Mode: ModelToolNative}}}
	request.ToolPolicy = ToolPolicy{Choice: ToolChoiceNamed, NamedTool: "web_search"}
	if errValidate := request.Validate(); errValidate != nil {
		t.Fatalf("validate named standard model tool: %v", errValidate)
	}
}

// TestNamedToolPolicyRejectsAmbiguousPublicNames verifies one name cannot identify both a caller tool and a model tool.
// TestNamedToolPolicyRejectsAmbiguousPublicNames 校验一个名称不能同时标识调用方工具与模型工具。
func TestNamedToolPolicyRejectsAmbiguousPublicNames(t *testing.T) {
	request := testTextRequest()
	request.Tools = []ToolDefinition{{
		Kind:       ToolFunction,
		Name:       "web_search",
		Parameters: []byte(`{"type":"object"}`),
	}}
	request.ModelTools = ModelToolSelection{Standard: []StandardModelToolSelection{{Kind: StandardModelToolWebSearch, Mode: ModelToolNative}}}
	request.ToolPolicy = ToolPolicy{Choice: ToolChoiceNamed, NamedTool: "web_search"}
	if errValidate := request.Validate(); !errors.Is(errValidate, ErrInvalidRequest) {
		t.Fatalf("validate ambiguous named tool error = %v, want ErrInvalidRequest", errValidate)
	}
}

// TestDisabledStandardToolDoesNotSatisfyRequiredPolicy verifies an explicitly disabled tool is not model-visible.
// TestDisabledStandardToolDoesNotSatisfyRequiredPolicy 校验显式关闭的工具对模型不可见。
func TestDisabledStandardToolDoesNotSatisfyRequiredPolicy(t *testing.T) {
	request := testTextRequest()
	request.ModelTools = ModelToolSelection{Standard: []StandardModelToolSelection{{Kind: StandardModelToolWebSearch, Mode: ModelToolDisabled}}}
	request.ToolPolicy = ToolPolicy{Choice: ToolChoiceRequired}
	if errValidate := request.Validate(); !errors.Is(errValidate, ErrInvalidRequest) {
		t.Fatalf("validate disabled required tool error = %v, want ErrInvalidRequest", errValidate)
	}
}
