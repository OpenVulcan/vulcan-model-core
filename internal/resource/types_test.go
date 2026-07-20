package resource

import (
	"testing"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestGeneratedOperationExcludesMetadataOnlyPreparation verifies preprocessing cannot claim binary provenance.
// TestGeneratedOperationExcludesMetadataOnlyPreparation 验证预处理不能声明二进制来源。
func TestGeneratedOperationExcludesMetadataOnlyPreparation(t *testing.T) {
	if generatedOperation(vcp.OperationMusicCoverPrepare) {
		t.Fatal("music.cover.prepare must not be treated as a generated-resource operation")
	}
	for _, operation := range []vcp.OperationKind{vcp.OperationImageGenerate, vcp.OperationVideoGenerate, vcp.OperationSpeechSynthesize, vcp.OperationMusicGenerate, vcp.OperationMusicCover} {
		if !generatedOperation(operation) {
			t.Fatalf("generated operation %q was rejected", operation)
		}
	}
}
