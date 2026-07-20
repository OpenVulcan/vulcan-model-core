package minimax

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestMiniMaxVideoTaskResolvesPrivateFileID verifies creation, polling, and file retrieval remain one private lifecycle.
// TestMiniMaxVideoTaskResolvesPrivateFileID 验证创建、轮询与文件取回保持在同一私有生命周期内。
func TestMiniMaxVideoTaskResolvesPrivateFileID(t *testing.T) {
	// requests records the exact endpoint order without retaining credentials or payloads.
	// requests 记录精确端点顺序且不保留凭据或负载。
	requests := make([]string, 0, 3)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests = append(requests, request.URL.RequestURI())
		switch request.URL.Path {
		case "/v1/video_generation":
			var upstream videoRequest
			if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil {
				t.Errorf("decode request: %v", errDecode)
			}
			if upstream.Model != "MiniMax-Hailuo-02" || upstream.FirstFrameImage != "data:image/png;base64,Zmlyc3Q=" || upstream.LastFrameImage != "https://inputs.example/last.webp" || upstream.Duration != 6 || upstream.Resolution != "1080P" {
				t.Errorf("upstream = %#v", upstream)
			}
			_, _ = io.WriteString(writer, `{"task_id":"task-video","base_resp":{"status_code":0}}`)
		case "/v1/query/video_generation":
			_, _ = io.WriteString(writer, `{"status":"Success","file_id":"file-video","base_resp":{"status_code":0}}`)
		case "/v1/files/retrieve":
			_, _ = io.WriteString(writer, `{"file":{"download_url":"https://outputs.example/video.mp4"},"base_resp":{"status_code":0}}`)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	imageDriver, execution := newMiniMaxImageExecution(t, server.URL)
	driver, errDriver := NewVideoTaskDriver("definition-minimax", imageDriver.client)
	if errDriver != nil {
		t.Fatalf("NewVideoTaskDriver() error = %v", errDriver)
	}
	action := providerconfig.ProviderActionBinding{ID: VideoGenerateActionBindingID, Operation: vcp.OperationVideoGenerate, DriverID: "minimax", DriverVersion: "1", ProtocolProfileID: VideoGenerateProtocolProfileID, EndpointProfileID: "minimax_video", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Asynchronous: true, Polling: true}, Revision: 1}
	execution.Definition.ActionBindings = []providerconfig.ProviderActionBinding{action}
	execution.Binding.Target.ActionBindingID = VideoGenerateActionBindingID
	execution.Binding.Target.Operation = vcp.OperationVideoGenerate
	execution.Binding.Target.UpstreamModelID = "MiniMax-Hailuo-02"
	execution.Execution.Operation = vcp.OperationVideoGenerate
	execution.Execution.Payload.ImageGenerate = nil
	execution.Execution.Payload.VideoGenerate = &vcp.VideoGenerateOperation{Prompt: "Grow up", DurationSeconds: 6, Resolution: "1080P", Inputs: []vcp.MediaInput{{ID: "first", Kind: vcp.MediaImage, Role: vcp.MediaRoleFirstFrame, Resource: vcp.ResourceReference{ResourceID: "resource-first"}}, {ID: "last", Kind: vcp.MediaImage, Role: vcp.MediaRoleLastFrame, Resource: vcp.ResourceReference{ResourceID: "resource-last"}}}}
	execution.MaterializedInputs = []resource.MaterializedInput{{InputID: "first", ResourceID: "resource-first", Kind: vcp.MediaImage, Role: vcp.MediaRoleFirstFrame, MIMEType: "image/png", Mode: catalog.MaterializationInlineBase64, InlineBase64: "Zmlyc3Q="}, {InputID: "last", ResourceID: "resource-last", Kind: vcp.MediaImage, Role: vcp.MediaRoleLastFrame, MIMEType: "image/webp", Mode: catalog.MaterializationDirectRemoteURL, RemoteURL: "https://inputs.example/last.webp"}}

	started, errStart := driver.Start(context.Background(), execution)
	if errStart != nil || started.ProviderTaskID != "task-video" {
		t.Fatalf("Start() result=%#v error=%v", started, errStart)
	}
	completed, errPoll := driver.Poll(context.Background(), execution, started.ProviderTaskID)
	if errPoll != nil || completed.Result == nil || completed.Result.GeneratedResources[0].DownloadURL != "https://outputs.example/video.mp4" {
		t.Fatalf("Poll() result=%#v error=%v", completed, errPoll)
	}
	if len(requests) != 3 || requests[1] != "/v1/query/video_generation?task_id=task-video" || requests[2] != "/v1/files/retrieve?file_id=file-video" {
		t.Fatalf("requests = %#v", requests)
	}
}
