package resource

import (
	"errors"
	"testing"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestIndexMaterializedInputsPreservesSemanticRoles verifies repeated Router resources remain distinct by operation role.
// TestIndexMaterializedInputsPreservesSemanticRoles 验证重复 Router 资源会按操作角色保持区分。
func TestIndexMaterializedInputsPreservesSemanticRoles(t *testing.T) {
	inputs := []MaterializedInput{
		{InputID: "understanding", ResourceID: "resource-shared", Kind: vcp.MediaImage, Role: vcp.MediaRoleUnderstanding, MIMEType: "image/png", Mode: catalog.MaterializationInlineBase64, InlineBase64: "aW1hZ2U="},
		{InputID: "reference", ResourceID: "resource-shared", Kind: vcp.MediaImage, Role: vcp.MediaRoleReference, MIMEType: "image/png", Mode: catalog.MaterializationInlineBase64, InlineBase64: "aW1hZ2U="},
	}
	indexed, errIndex := IndexMaterializedInputs(inputs)
	if errIndex != nil {
		t.Fatalf("IndexMaterializedInputs() error = %v", errIndex)
	}
	if len(indexed) != 2 {
		t.Fatalf("indexed length = %d, want 2", len(indexed))
	}
	if input, exists := indexed.Find("resource-shared", vcp.MediaRoleReference); !exists || input.InputID != "reference" {
		t.Fatalf("reference input = %#v, exists = %v", input, exists)
	}
}

// TestIndexMaterializedInputsAllowsEquivalentOccurrences verifies duplicate input identities may reuse one exact provider representation.
// TestIndexMaterializedInputsAllowsEquivalentOccurrences 验证重复输入身份可以复用同一个精确供应商表示。
func TestIndexMaterializedInputsAllowsEquivalentOccurrences(t *testing.T) {
	first := MaterializedInput{InputID: "first", ResourceID: "resource-shared", Kind: vcp.MediaImage, Role: vcp.MediaRoleUnderstanding, MIMEType: "image/png", Mode: catalog.MaterializationInlineBase64, InlineBase64: "aW1hZ2U="}
	second := first
	second.InputID = "second"
	indexed, errIndex := IndexMaterializedInputs([]MaterializedInput{first, second})
	if errIndex != nil {
		t.Fatalf("IndexMaterializedInputs() error = %v", errIndex)
	}
	if len(indexed) != 1 {
		t.Fatalf("indexed length = %d, want 1", len(indexed))
	}
}

// TestIndexMaterializedInputsRejectsAmbiguousOccurrences verifies one content identity cannot select between different provider representations.
// TestIndexMaterializedInputsRejectsAmbiguousOccurrences 验证同一内容身份不能在不同供应商表示之间进行选择。
func TestIndexMaterializedInputsRejectsAmbiguousOccurrences(t *testing.T) {
	first := MaterializedInput{InputID: "first", ResourceID: "resource-shared", Kind: vcp.MediaImage, Role: vcp.MediaRoleUnderstanding, MIMEType: "image/png", Mode: catalog.MaterializationInlineBase64, InlineBase64: "Zmlyc3Q="}
	second := first
	second.InputID = "second"
	second.InlineBase64 = "c2Vjb25k"
	if _, errIndex := IndexMaterializedInputs([]MaterializedInput{first, second}); !errors.Is(errIndex, ErrMaterializedInputConflict) {
		t.Fatalf("IndexMaterializedInputs() error = %v, want ErrMaterializedInputConflict", errIndex)
	}
}
