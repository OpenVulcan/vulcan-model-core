package catalog

import (
	"testing"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestModelToolCapabilitiesValidateClosedDependencies verifies exact standard and extra-tool dependencies.
// TestModelToolCapabilitiesValidateClosedDependencies 校验精确的标准工具与额外工具依赖。
func TestModelToolCapabilitiesValidateClosedDependencies(t *testing.T) {
	capabilities := ModelCapabilities{
		StandardTools: []StandardModelToolCapability{
			{Kind: vcp.StandardModelToolWebSearch, Native: true, AllowsCallerTools: true},
			{Kind: vcp.StandardModelToolWebExtractor, Native: true, Requires: []vcp.StandardModelToolKind{vcp.StandardModelToolWebSearch}},
		},
		ExtraTools: []ModelExtraToolCapability{{
			ID:                "t2i_search",
			DisplayName:       "Text-to-Image Search",
			Description:       "Searches images from a text query.",
			InputModalities:   []string{"text"},
			OutputModalities:  []string{"image"},
			RequiresStandard:  []vcp.StandardModelToolKind{vcp.StandardModelToolWebSearch},
			AllowsCallerTools: true,
		}},
	}
	if errValidate := validateModelToolCapabilities(capabilities.StandardTools, capabilities.ExtraTools); errValidate != nil {
		t.Fatalf("validate model tool capabilities: %v", errValidate)
	}
}

// TestModelToolCapabilitiesRejectMissingDependencies verifies catalogs cannot infer unpublished tools.
// TestModelToolCapabilitiesRejectMissingDependencies 校验目录不能推断未发布工具。
func TestModelToolCapabilitiesRejectMissingDependencies(t *testing.T) {
	standard := []StandardModelToolCapability{{
		Kind:     vcp.StandardModelToolWebExtractor,
		Native:   true,
		Requires: []vcp.StandardModelToolKind{vcp.StandardModelToolWebSearch},
	}}
	if errValidate := validateModelToolCapabilities(standard, nil); errValidate == nil {
		t.Fatal("missing standard dependency unexpectedly validated")
	}
	extra := []ModelExtraToolCapability{{
		ID:            "code_interpreter",
		DisplayName:   "Code Interpreter",
		Description:   "Runs code in a provider sandbox.",
		RequiresExtra: []string{"missing_tool"},
	}}
	if errValidate := validateModelToolCapabilities(nil, extra); errValidate == nil {
		t.Fatal("missing extra dependency unexpectedly validated")
	}
}

// TestCloneCapabilitiesDeepCopiesModelTools verifies catalog snapshots cannot be mutated through nested slices.
// TestCloneCapabilitiesDeepCopiesModelTools 校验目录快照不能通过嵌套切片被修改。
func TestCloneCapabilitiesDeepCopiesModelTools(t *testing.T) {
	source := ModelCapabilities{
		StandardTools: []StandardModelToolCapability{{Kind: vcp.StandardModelToolWebExtractor, Native: true, Requires: []vcp.StandardModelToolKind{vcp.StandardModelToolWebSearch}}},
		ExtraTools: []ModelExtraToolCapability{{
			ID:               "t2i_search",
			DisplayName:      "Text-to-Image Search",
			Description:      "Searches images.",
			InputModalities:  []string{"text"},
			OutputModalities: []string{"image"},
			RequiresExtra:    []string{"code_interpreter"},
		}},
	}
	cloned := cloneCapabilities(source)
	cloned.StandardTools[0].Requires[0] = vcp.StandardModelToolWebExtractor
	cloned.ExtraTools[0].InputModalities[0] = "video"
	cloned.ExtraTools[0].RequiresExtra[0] = "changed"
	if source.StandardTools[0].Requires[0] != vcp.StandardModelToolWebSearch || source.ExtraTools[0].InputModalities[0] != "text" || source.ExtraTools[0].RequiresExtra[0] != "code_interpreter" {
		t.Fatalf("source model tool capabilities were mutated: %#v", source)
	}
}
