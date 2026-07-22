package minimax

import (
	"testing"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestProjectVisionRequestUsesOnlyPinnedDataURICarrier verifies VLM never invents a provider file-ID field.
// TestProjectVisionRequestUsesOnlyPinnedDataURICarrier 验证 VLM 绝不虚构供应商文件 ID 字段。
func TestProjectVisionRequestUsesOnlyPinnedDataURICarrier(t *testing.T) {
	source := vcp.MediaInput{ID: "image", Kind: vcp.MediaImage, Role: vcp.MediaRoleUnderstanding, Resource: vcp.ResourceReference{ResourceID: "resource-image"}}
	operation := vcp.MediaAnalyzeOperation{Task: vcp.MediaAnalyzeDescribe, Inputs: []vcp.MediaInput{source}}
	inline := resource.MaterializedInput{InputID: source.ID, ResourceID: source.Resource.ResourceID, Kind: source.Kind, Role: source.Role, MIMEType: "image/png", Mode: catalog.MaterializationInlineBase64, InlineBase64: "aW1hZ2U="}
	projected, errProject := projectVisionRequest(operation, []resource.MaterializedInput{inline})
	if errProject != nil {
		t.Fatalf("projectVisionRequest() error = %v", errProject)
	}
	if projected.ImageURL != "data:image/png;base64,aW1hZ2U=" {
		t.Fatalf("projected = %#v", projected)
	}
	providerFile := inline
	providerFile.Mode = catalog.MaterializationProviderFileID
	providerFile.InlineBase64 = ""
	providerFile.ProviderHandle = "provider-file"
	providerFile.ProviderAssetKind = resource.ProviderAssetFile
	if _, errProject := projectVisionRequest(operation, []resource.MaterializedInput{providerFile}); errProject == nil {
		t.Fatal("projectVisionRequest() accepted an unproved provider file-ID carrier")
	}
}
