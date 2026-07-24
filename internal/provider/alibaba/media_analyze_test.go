package alibaba

import (
	"errors"
	"testing"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestAlibabaMediaAnalyzeRequestPreservesFrozenPromptAndOrderedMedia verifies the action projection neither drops nor reorders declared media.
// TestAlibabaMediaAnalyzeRequestPreservesFrozenPromptAndOrderedMedia 验证动作投影既不丢弃也不重排声明媒体。
func TestAlibabaMediaAnalyzeRequestPreservesFrozenPromptAndOrderedMedia(t *testing.T) {
	image := vcp.MediaInput{ID: "image-input", Kind: vcp.MediaImage, Role: vcp.MediaRoleUnderstanding, Resource: vcp.ResourceReference{ResourceID: "resource-image"}}
	video := vcp.MediaInput{ID: "video-input", Kind: vcp.MediaVideo, Role: vcp.MediaRoleUnderstanding, Resource: vcp.ResourceReference{ResourceID: "resource-video"}}
	operation := vcp.MediaAnalyzeOperation{Task: vcp.MediaAnalyzeQuestionAnswer, Instruction: "What changes over time?", Inputs: []vcp.MediaInput{image, video}}
	materialized := []resource.MaterializedInput{
		{InputID: image.ID, ResourceID: image.Resource.ResourceID, Kind: image.Kind, Role: image.Role, MIMEType: "image/png", Mode: catalog.MaterializationInlineBase64, InlineBase64: "aW1hZ2U="},
		{InputID: video.ID, ResourceID: video.Resource.ResourceID, Kind: video.Kind, Role: video.Role, MIMEType: "video/mp4", Mode: catalog.MaterializationDirectRemoteURL, RemoteURL: "https://media.example/video.mp4"},
	}
	envelope := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request-omni-analysis", Stream: true, Operation: vcp.OperationMediaAnalyze, Payload: vcp.OperationPayload{MediaAnalyze: &operation}}
	request, errRequest := alibabaMediaAnalyzeRequest(envelope, "instance-alibaba", "model-omni", "profile-omni-analysis", operation, materialized)
	if errRequest != nil {
		t.Fatalf("alibabaMediaAnalyzeRequest() error = %v", errRequest)
	}
	if !request.Stream || len(request.Context) != 1 || len(request.Context[0].Content) != 3 {
		t.Fatalf("synthesized request = %#v", request)
	}
	content := request.Context[0].Content
	if content[0].Type != vcp.ContentText || content[0].Text != "Answer this question using only evidence from the supplied media:\nWhat changes over time?" || content[1].ResourceRef != image.Resource.ResourceID || content[2].ResourceRef != video.Resource.ResourceID {
		t.Fatalf("synthesized content = %#v", content)
	}
}

// TestAlibabaMediaAnalyzeRequestRejectsMismatchedMaterialization verifies operation identities cannot be substituted by resource coincidence.
// TestAlibabaMediaAnalyzeRequestRejectsMismatchedMaterialization 验证操作身份不能因资源碰巧相同而被替换。
func TestAlibabaMediaAnalyzeRequestRejectsMismatchedMaterialization(t *testing.T) {
	input := vcp.MediaInput{ID: "audio-input", Kind: vcp.MediaAudio, Role: vcp.MediaRoleUnderstanding, Resource: vcp.ResourceReference{ResourceID: "resource-audio"}}
	operation := vcp.MediaAnalyzeOperation{Task: vcp.MediaAnalyzeDescribe, Inputs: []vcp.MediaInput{input}}
	materialized := []resource.MaterializedInput{{InputID: "different-input", ResourceID: input.Resource.ResourceID, Kind: input.Kind, Role: input.Role, MIMEType: "audio/wav", Mode: catalog.MaterializationInlineBase64, InlineBase64: "YXVkaW8="}}
	envelope := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request-omni-mismatch", Stream: true, Operation: vcp.OperationMediaAnalyze, Payload: vcp.OperationPayload{MediaAnalyze: &operation}}
	if _, errRequest := alibabaMediaAnalyzeRequest(envelope, "instance-alibaba", "model-omni", "profile-omni-analysis", operation, materialized); !errors.Is(errRequest, ErrUnsupportedMediaAnalyzeInput) {
		t.Fatalf("alibabaMediaAnalyzeRequest() error = %v, want ErrUnsupportedMediaAnalyzeInput", errRequest)
	}
}
