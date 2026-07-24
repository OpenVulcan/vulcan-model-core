// Request fixtures cover behavior adapted from CLIProxyAPI commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// 请求夹具覆盖改编自 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66 的行为。
// Source path: internal/translator/openai/openai/responses.
// 来源路径：internal/translator/openai/openai/responses。
// The fixtures verify typed VCP-to-Responses projection without importing CLIProxyAPI translator runtime code.
// 夹具验证类型化 VCP 到 Responses 投影，不导入 CLIProxyAPI Translator 运行时代码。
package responses

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestProjectRequestWithInputsPreservesImageAudioAndFile verifies each supported resource receives its distinct typed carrier.
// TestProjectRequestWithInputsPreservesImageAudioAndFile 验证每种受支持资源获得各自独立的类型化载体。
func TestProjectRequestWithInputsPreservesImageAudioAndFile(t *testing.T) {
	request := responsesTestRequest()
	request.Context[0].Content = []vcp.ContentBlock{
		{Type: vcp.ContentText, Text: "Analyze these"},
		{Type: vcp.ContentImage, ResourceRef: "image-resource", MediaRole: vcp.MediaRoleUnderstanding},
		{Type: vcp.ContentAudio, ResourceRef: "audio-resource", MediaRole: vcp.MediaRoleUnderstanding},
		{Type: vcp.ContentFile, ResourceRef: "file-resource", MediaRole: vcp.MediaRoleUnderstanding},
	}
	inputs := []resource.MaterializedInput{
		{InputID: "image", ResourceID: "image-resource", Kind: vcp.MediaImage, Role: vcp.MediaRoleUnderstanding, MIMEType: "image/png", Mode: catalog.MaterializationInlineBase64, InlineBase64: "aW1hZ2U="},
		{InputID: "audio", ResourceID: "audio-resource", Kind: vcp.MediaAudio, Role: vcp.MediaRoleUnderstanding, MIMEType: "audio/wav", Mode: catalog.MaterializationInlineBase64, InlineBase64: "YXVkaW8="},
		{InputID: "file", ResourceID: "file-resource", Kind: vcp.MediaFile, Role: vcp.MediaRoleUnderstanding, MIMEType: "application/pdf", Mode: catalog.MaterializationProviderFileID, ProviderHandle: "file_123"},
	}
	projected, errProject := ProjectRequestWithInputs(request, responsesTarget(), responsesCapabilities(), "lineage-media", "", responsesNow(), inputs)
	if errProject != nil {
		t.Fatalf("ProjectRequestWithInputs() error = %v", errProject)
	}
	content := projected.Upstream.Input[0].Content
	if len(content) != 4 || content[1].Type != "input_image" || content[1].ImageURL != "data:image/png;base64,aW1hZ2U=" || content[2].InputAudio == nil || content[2].InputAudio.Format != "wav" || content[3].Type != "input_file" || content[3].FileID != "file_123" {
		t.Fatalf("content = %#v", content)
	}
}

// TestProjectRequestWithInputsPreservesRepeatedResourceRoles verifies Responses projection resolves repeated resources by semantic role.
// TestProjectRequestWithInputsPreservesRepeatedResourceRoles 验证 Responses 投影会按语义角色解析重复资源。
func TestProjectRequestWithInputsPreservesRepeatedResourceRoles(t *testing.T) {
	request := responsesTestRequest()
	request.Context[0].Content = []vcp.ContentBlock{
		{Type: vcp.ContentText, Text: "Compare these uses"},
		{Type: vcp.ContentImage, ResourceRef: "image-resource", MediaRole: vcp.MediaRoleUnderstanding},
		{Type: vcp.ContentImage, ResourceRef: "image-resource", MediaRole: vcp.MediaRoleReference},
	}
	inputs := []resource.MaterializedInput{
		{InputID: "understanding", ResourceID: "image-resource", Kind: vcp.MediaImage, Role: vcp.MediaRoleUnderstanding, MIMEType: "image/png", Mode: catalog.MaterializationInlineBase64, InlineBase64: "aW1hZ2U="},
		{InputID: "reference", ResourceID: "image-resource", Kind: vcp.MediaImage, Role: vcp.MediaRoleReference, MIMEType: "image/png", Mode: catalog.MaterializationInlineBase64, InlineBase64: "aW1hZ2U="},
	}
	projected, errProject := ProjectRequestWithInputs(request, responsesTarget(), responsesCapabilities(), "lineage-repeated-roles", "", responsesNow(), inputs)
	if errProject != nil {
		t.Fatalf("ProjectRequestWithInputs() error = %v", errProject)
	}
	content := projected.Upstream.Input[0].Content
	if len(content) != 3 || content[1].ImageURL == "" || content[2].ImageURL == "" {
		t.Fatalf("content = %#v", content)
	}
}

// TestProjectRequestWithInputsRejectsUnverifiedVideo verifies no generic URL field masks absent video support.
// TestProjectRequestWithInputsRejectsUnverifiedVideo 验证通用 URL 字段不会掩盖缺失的视频支持。
func TestProjectRequestWithInputsRejectsUnverifiedVideo(t *testing.T) {
	request := responsesTestRequest()
	request.Context[0].Content = []vcp.ContentBlock{{Type: vcp.ContentText, Text: "Analyze"}, {Type: vcp.ContentVideo, ResourceRef: "video-resource", MediaRole: vcp.MediaRoleUnderstanding}}
	inputs := []resource.MaterializedInput{{InputID: "video", ResourceID: "video-resource", Kind: vcp.MediaVideo, Role: vcp.MediaRoleUnderstanding, MIMEType: "video/mp4", Mode: catalog.MaterializationProviderFileID, ProviderHandle: "file_video"}}
	if _, errProject := ProjectRequestWithInputs(request, responsesTarget(), responsesCapabilities(), "lineage-media", "", responsesNow(), inputs); !errors.Is(errProject, vcp.ErrCapabilityUnavailable) {
		t.Fatalf("ProjectRequestWithInputs() error = %v, want ErrCapabilityUnavailable", errProject)
	}
}

// TestProjectRequestUsesUpstreamToolCallID verifies that replayed tool output retains its actual provider call relation.
// TestProjectRequestUsesUpstreamToolCallID 验证回放工具输出会保留实际 Provider 调用关联。
func TestProjectRequestUsesUpstreamToolCallID(t *testing.T) {
	request := responsesTestRequest()
	request.Tools = []vcp.ToolDefinition{{Kind: vcp.ToolFunction, Name: "lookup", Parameters: json.RawMessage(`{"type":"object"}`)}}
	request.Context = append(request.Context,
		vcp.ContextItem{
			ItemID: "item-call", Sequence: 2, Kind: vcp.ContextToolCall, Authority: vcp.AuthorityAssistant, Actor: vcp.ActorPrimaryAssistant,
			Placement: vcp.PlacementTranscript, Activation: vcp.Activation{Mode: vcp.ActivationRequestStart}, Visibility: vcp.VisibilityModel,
			ToolCall: &vcp.ToolCallItem{ToolCallID: "vcp-call", UpstreamID: "upstream-call", Name: "lookup", Arguments: `{"city":"Shanghai"}`, Status: vcp.ToolCallCompleted},
		},
		vcp.ContextItem{
			ItemID: "item-result", Sequence: 3, Kind: vcp.ContextToolResult, Authority: vcp.AuthorityTool, Actor: vcp.ActorTool,
			Placement: vcp.PlacementTranscript, Activation: vcp.Activation{Mode: vcp.ActivationRequestStart}, Visibility: vcp.VisibilityModel,
			Content: []vcp.ContentBlock{{Type: vcp.ContentText, Text: "Sunny"}}, ToolResult: &vcp.ToolResultItem{ToolCallID: "vcp-call"},
		},
	)
	projected, errProject := ProjectRequest(request, responsesTarget(), responsesCapabilities(), "lineage-1", "", responsesNow())
	if errProject != nil {
		t.Fatalf("ProjectRequest() error = %v", errProject)
	}
	if len(projected.Upstream.Input) != 3 {
		t.Fatalf("input count = %d, want 3", len(projected.Upstream.Input))
	}
	if call := projected.Upstream.Input[1]; call.Type != "function_call" || call.CallID != "upstream-call" {
		t.Fatalf("function call = %#v", call)
	}
	if output := projected.Upstream.Input[2]; output.Type != "function_call_output" || output.CallID != "upstream-call" || output.Output == nil || output.Output.Text == nil || *output.Output.Text != "Sunny" || output.Output.ComputerScreenshot != nil {
		t.Fatalf("function output = %#v", output)
	}
}

// TestProjectRequestRejectsToolCallWithoutUpstreamID verifies Router-owned tool identities are never serialized as Responses call identifiers.
// TestProjectRequestRejectsToolCallWithoutUpstreamID 验证 Router 所有的工具身份绝不会序列化为 Responses 调用标识。
func TestProjectRequestRejectsToolCallWithoutUpstreamID(t *testing.T) {
	request := responsesTestRequest()
	request.Tools = []vcp.ToolDefinition{{Kind: vcp.ToolFunction, Name: "lookup", Parameters: json.RawMessage(`{"type":"object"}`)}}
	request.Context = append(request.Context, vcp.ContextItem{
		ItemID: "item-call-without-upstream", Sequence: 2, Kind: vcp.ContextToolCall, Authority: vcp.AuthorityAssistant, Actor: vcp.ActorPrimaryAssistant,
		Placement: vcp.PlacementTranscript, Activation: vcp.Activation{Mode: vcp.ActivationRequestStart}, Visibility: vcp.VisibilityModel,
		ToolCall: &vcp.ToolCallItem{ToolCallID: "vcp-only-call", Name: "lookup", Arguments: `{}`, Status: vcp.ToolCallCompleted},
	})
	if _, errProject := ProjectRequest(request, responsesTarget(), responsesCapabilities(), "lineage-tool-without-upstream", "", responsesNow()); !errors.Is(errProject, ErrUnsupportedContext) {
		t.Fatalf("ProjectRequest() error = %v, want ErrUnsupportedContext", errProject)
	}
}

// TestProjectRequestProjectsCustomTool verifies that a closed VCP custom tool uses the Responses custom wire type.
// TestProjectRequestProjectsCustomTool 验证封闭 VCP custom 工具使用 Responses custom wire 类型。
func TestProjectRequestProjectsCustomTool(t *testing.T) {
	request := responsesTestRequest()
	request.Tools = []vcp.ToolDefinition{{Kind: vcp.ToolCustom, Name: "apply_patch", Description: "Apply a patch"}}
	projected, errProject := ProjectRequest(request, responsesTarget(), responsesCapabilities(), "lineage-1", "", responsesNow())
	if errProject != nil {
		t.Fatalf("ProjectRequest() error = %v", errProject)
	}
	if len(projected.Upstream.Tools) != 1 || projected.Upstream.Tools[0].Type != "custom" {
		t.Fatalf("tools = %#v", projected.Upstream.Tools)
	}
}

// TestProjectRequestOmitsUnverifiedParallelToolControl verifies an unsupported optional false control is not serialized merely because tools exist.
// TestProjectRequestOmitsUnverifiedParallelToolControl 验证不能仅因存在工具就序列化未经验证的可选 false 并行控制。
func TestProjectRequestOmitsUnverifiedParallelToolControl(t *testing.T) {
	request := responsesTestRequest()
	request.Tools = []vcp.ToolDefinition{{Kind: vcp.ToolFunction, Name: "lookup", Parameters: json.RawMessage(`{"type":"object"}`)}}
	request.ToolPolicy = vcp.ToolPolicy{Choice: vcp.ToolChoiceAuto, Parallel: false}
	capabilities := responsesCapabilities()
	capabilities.ParallelTools = false
	projected, errProject := ProjectRequest(request, responsesTarget(), capabilities, "lineage-tools-without-parallel", "", responsesNow())
	if errProject != nil {
		t.Fatalf("ProjectRequest() error = %v", errProject)
	}
	if projected.Upstream.ParallelToolCalls != nil {
		t.Fatalf("parallel_tool_calls = %#v, want absent", projected.Upstream.ParallelToolCalls)
	}
}

// TestProjectRequestPreservesAssistantHistoryAsEasyInputMessage verifies that canonical assistant history uses the legal input-message carrier.
// TestProjectRequestPreservesAssistantHistoryAsEasyInputMessage 验证规范助手历史使用合法的输入消息载体。
func TestProjectRequestPreservesAssistantHistoryAsEasyInputMessage(t *testing.T) {
	request := responsesTestRequest()
	request.Context = append(request.Context, vcp.ContextItem{
		ItemID: "item-assistant", Sequence: 2, Kind: vcp.ContextMessage, Authority: vcp.AuthorityAssistant, Actor: vcp.ActorPrimaryAssistant,
		Placement: vcp.PlacementTranscript, Activation: vcp.Activation{Mode: vcp.ActivationRequestStart}, Visibility: vcp.VisibilityModel,
		Content: []vcp.ContentBlock{{Type: vcp.ContentText, Text: "Prior answer"}}, Message: &vcp.MessageItem{},
	})
	projected, errProject := ProjectRequest(request, responsesTarget(), responsesCapabilities(), "lineage-1", "", responsesNow())
	if errProject != nil {
		t.Fatalf("ProjectRequest() error = %v", errProject)
	}
	if len(projected.Upstream.Input) != 2 {
		t.Fatalf("input count = %d, want 2", len(projected.Upstream.Input))
	}
	assistant := projected.Upstream.Input[1]
	if assistant.Type != "message" || assistant.Role != "assistant" {
		t.Fatalf("assistant input header = %#v", assistant)
	}
	if len(assistant.Content) != 1 || assistant.Content[0].Type != "input_text" || assistant.Content[0].Text != "Prior answer" {
		t.Fatalf("assistant input content = %#v", assistant.Content)
	}
}

// TestProjectRequestBlocksUnavailableNativeWebSearch verifies required native web search cannot be silently downgraded.
// TestProjectRequestBlocksUnavailableNativeWebSearch 验证必需原生网页搜索不能被静默降级。
func TestProjectRequestBlocksUnavailableNativeWebSearch(t *testing.T) {
	request := responsesTestRequest()
	request.Tools = []vcp.ToolDefinition{{Kind: vcp.ToolNativeWebSearch, Name: "web_search"}}
	capabilities := responsesCapabilities()
	capabilities.NativeWebSearch = false
	_, errProject := ProjectRequest(request, responsesTarget(), capabilities, "lineage-1", "", responsesNow())
	if !errors.Is(errProject, vcp.ErrCapabilityUnavailable) {
		t.Fatalf("ProjectRequest() error = %v, want ErrCapabilityUnavailable", errProject)
	}
}

// TestProjectRequestProjectsNativeWebExtractorFromModelToolSelection verifies the standard capability uses the provider's exact hosted tool type.
// TestProjectRequestProjectsNativeWebExtractorFromModelToolSelection 验证标准能力使用供应商精确的托管工具类型。
func TestProjectRequestProjectsNativeWebExtractorFromModelToolSelection(t *testing.T) {
	request := responsesTestRequest()
	request.ModelTools = vcp.ModelToolSelection{Standard: []vcp.StandardModelToolSelection{{Kind: vcp.StandardModelToolWebExtractor, Mode: vcp.ModelToolNative}}}
	capabilities := responsesCapabilities()
	capabilities.NativeWebExtractor = true
	projected, errProject := ProjectRequest(request, responsesTarget(), capabilities, "lineage-extractor", "", responsesNow())
	if errProject != nil {
		t.Fatalf("ProjectRequest() error = %v", errProject)
	}
	if len(projected.Upstream.Tools) != 1 || projected.Upstream.Tools[0].Type != "web_extractor" || projected.Upstream.ToolChoice == nil || projected.Upstream.ToolChoice.Mode != vcp.ToolChoiceAuto {
		t.Fatalf("projected extractor request = %#v", projected.Upstream)
	}

	capabilities.NativeWebExtractor = false
	_, errProject = ProjectRequest(request, responsesTarget(), capabilities, "lineage-extractor-blocked", "", responsesNow())
	var modelToolError *vcp.ModelToolError
	if !errors.As(errProject, &modelToolError) || modelToolError.Code != vcp.ModelToolNotSupported || modelToolError.ToolID != string(vcp.StandardModelToolWebExtractor) {
		t.Fatalf("blocked extractor error = %v", errProject)
	}
}

// TestProjectRequestProjectsProviderHostedTools verifies each closed VCP hosted-tool configuration reaches its exact Responses wire shape.
// TestProjectRequestProjectsProviderHostedTools 验证每个封闭 VCP 托管工具配置都到达其精确 Responses Wire 形态。
func TestProjectRequestProjectsProviderHostedTools(t *testing.T) {
	// maxResults is the explicit provider retrieval bound used by the fixture.
	// maxResults 是夹具使用的明确供应商检索上限。
	maxResults := 7
	request := responsesTestRequest()
	request.Tools = []vcp.ToolDefinition{
		{Kind: vcp.ToolProviderFileSearch, Name: "file_search", FileSearch: &vcp.ProviderFileSearchTool{StoreIDs: []string{"vs_1", "vs_2"}, MaxResults: &maxResults}},
		{Kind: vcp.ToolProviderCodeInterpreter, Name: "code_interpreter", CodeInterpreter: &vcp.ProviderCodeInterpreterTool{MemoryLimit: "4g"}},
		{Kind: vcp.ToolProviderComputerUse, Name: "computer_use_ga", ComputerUse: &vcp.ProviderComputerUseTool{Mode: vcp.ProviderComputerUseGA}},
		{Kind: vcp.ToolProviderComputerUse, Name: "computer_use_preview", ComputerUse: &vcp.ProviderComputerUseTool{Mode: vcp.ProviderComputerUsePreview, Environment: "browser", DisplayWidth: 1280, DisplayHeight: 720}},
	}
	capabilities := responsesCapabilities()
	capabilities.ProviderFileSearch = true
	capabilities.ProviderCodeInterpreter = true
	capabilities.ProviderComputerUseGA = true
	capabilities.ProviderComputerUsePreview = true
	projected, errProject := ProjectRequest(request, responsesTarget(), capabilities, "lineage-hosted-tools", "", responsesNow())
	if errProject != nil {
		t.Fatalf("ProjectRequest() error = %v", errProject)
	}
	if len(projected.Upstream.Tools) != 4 {
		t.Fatalf("tool count = %d, want 4", len(projected.Upstream.Tools))
	}
	fileSearch := projected.Upstream.Tools[0]
	if fileSearch.Type != "file_search" || len(fileSearch.VectorStoreIDs) != 2 || fileSearch.VectorStoreIDs[1] != "vs_2" || fileSearch.MaxNumResults == nil || *fileSearch.MaxNumResults != 7 {
		t.Fatalf("file search tool = %#v", fileSearch)
	}
	codeInterpreter := projected.Upstream.Tools[1]
	encodedContainer, errMarshal := json.Marshal(codeInterpreter.Container)
	if errMarshal != nil || string(encodedContainer) != `{"type":"auto","memory_limit":"4g"}` {
		t.Fatalf("code interpreter container = %s, error = %v", encodedContainer, errMarshal)
	}
	computerGA := projected.Upstream.Tools[2]
	if computerGA.Type != "computer" || computerGA.Environment != "" || computerGA.DisplayWidth != 0 || computerGA.DisplayHeight != 0 {
		t.Fatalf("computer GA tool = %#v", computerGA)
	}
	computerPreview := projected.Upstream.Tools[3]
	if computerPreview.Type != "computer_use_preview" || computerPreview.Environment != "browser" || computerPreview.DisplayWidth != 1280 || computerPreview.DisplayHeight != 720 {
		t.Fatalf("computer preview tool = %#v", computerPreview)
	}
}

// TestProjectRequestProjectsComputerScreenshotContinuation verifies the caller loop sends only a continued screenshot result.
// TestProjectRequestProjectsComputerScreenshotContinuation 验证调用方循环仅发送续接截图结果。
func TestProjectRequestProjectsComputerScreenshotContinuation(t *testing.T) {
	request := responsesTestRequest()
	request.Tools = []vcp.ToolDefinition{{Kind: vcp.ToolProviderComputerUse, Name: "computer", ComputerUse: &vcp.ProviderComputerUseTool{Mode: vcp.ProviderComputerUseGA}}}
	request.ReasoningPolicy.ContinuationID = "continuation-router"
	request.Context = []vcp.ContextItem{
		vcp.ContextItem{
			ItemID: "computer-call", Sequence: 2, Kind: vcp.ContextToolCall, Authority: vcp.AuthorityAssistant, Actor: vcp.ActorProvider,
			Placement: vcp.PlacementTranscript, Activation: vcp.Activation{Mode: vcp.ActivationRequestStart}, Visibility: vcp.VisibilityModel,
			ToolCall: &vcp.ToolCallItem{ToolCallID: "call-vcp", UpstreamID: "call-upstream", Name: "computer_use", Status: vcp.ToolCallCompleted, ComputerActions: []vcp.ComputerAction{{Type: vcp.ComputerActionScreenshot}}},
		},
		vcp.ContextItem{
			ItemID: "computer-result", Sequence: 3, Kind: vcp.ContextToolResult, Authority: vcp.AuthorityTool, Actor: vcp.ActorTool,
			Placement: vcp.PlacementTranscript, Activation: vcp.Activation{Mode: vcp.ActivationRequestStart}, Visibility: vcp.VisibilityModel,
			ToolResult: &vcp.ToolResultItem{ToolCallID: "call-vcp", ComputerScreenshot: &vcp.ComputerScreenshotResult{ResourceRef: "resource-screenshot", Detail: "original"}},
		},
	}
	capabilities := responsesCapabilities()
	capabilities.ProviderComputerUseGA = true
	inputs := []resource.MaterializedInput{{InputID: "screenshot", ResourceID: "resource-screenshot", Kind: vcp.MediaImage, Role: vcp.MediaRoleUnderstanding, MIMEType: "image/png", Mode: catalog.MaterializationInlineBase64, InlineBase64: "cG5n"}}
	projected, errProject := ProjectRequestWithInputs(request, responsesTarget(), capabilities, "lineage-computer-result", "response-upstream", responsesNow(), inputs)
	if errProject != nil {
		t.Fatalf("ProjectRequestWithInputs() error = %v", errProject)
	}
	if projected.Upstream.PreviousResponseID != "response-upstream" || len(projected.Upstream.Input) != 1 {
		t.Fatalf("upstream request = %#v", projected.Upstream)
	}
	result := projected.Upstream.Input[0]
	if result.Type != "computer_call_output" || result.CallID != "call-upstream" || result.Output == nil || result.Output.ComputerScreenshot == nil || result.Output.Text != nil {
		t.Fatalf("computer result = %#v", result)
	}
	encoded, errEncode := json.Marshal(result)
	if errEncode != nil || string(encoded) != `{"type":"computer_call_output","call_id":"call-upstream","output":{"type":"computer_screenshot","image_url":"data:image/png;base64,cG5n","detail":"original"}}` {
		t.Fatalf("encoded computer result = %s, error = %v", encoded, errEncode)
	}
}

// TestProjectRequestProjectsExplicitCodeInterpreterContainer verifies an authorized provider container remains a string union arm.
// TestProjectRequestProjectsExplicitCodeInterpreterContainer 验证已授权供应商容器保持为字符串联合分支。
func TestProjectRequestProjectsExplicitCodeInterpreterContainer(t *testing.T) {
	request := responsesTestRequest()
	request.Tools = []vcp.ToolDefinition{{Kind: vcp.ToolProviderCodeInterpreter, Name: "code_interpreter", CodeInterpreter: &vcp.ProviderCodeInterpreterTool{ContainerID: "cntr_123"}}}
	capabilities := responsesCapabilities()
	capabilities.ProviderCodeInterpreter = true
	projected, errProject := ProjectRequest(request, responsesTarget(), capabilities, "lineage-explicit-container", "", responsesNow())
	if errProject != nil {
		t.Fatalf("ProjectRequest() error = %v", errProject)
	}
	encodedContainer, errMarshal := json.Marshal(projected.Upstream.Tools[0].Container)
	if errMarshal != nil || string(encodedContainer) != `"cntr_123"` {
		t.Fatalf("code interpreter container = %s, error = %v", encodedContainer, errMarshal)
	}
}

// TestProjectRequestBlocksUnavailableProviderHostedTool verifies transport capability evidence is mandatory even for a valid VCP declaration.
// TestProjectRequestBlocksUnavailableProviderHostedTool 验证即使 VCP 声明有效也必须具有传输能力证据。
func TestProjectRequestBlocksUnavailableProviderHostedTool(t *testing.T) {
	request := responsesTestRequest()
	request.Tools = []vcp.ToolDefinition{{Kind: vcp.ToolProviderFileSearch, Name: "file_search", FileSearch: &vcp.ProviderFileSearchTool{StoreIDs: []string{"vs_1"}}}}
	if _, errProject := ProjectRequest(request, responsesTarget(), responsesCapabilities(), "lineage-unavailable-hosted-tool", "", responsesNow()); !errors.Is(errProject, vcp.ErrCapabilityUnavailable) {
		t.Fatalf("ProjectRequest() error = %v, want ErrCapabilityUnavailable", errProject)
	}
}

// TestProjectRequestRequiresResolvedContinuation verifies that Router-owned continuation IDs never become raw upstream IDs implicitly.
// TestProjectRequestRequiresResolvedContinuation 验证 Router 所有续接 ID 不会被隐式变成原始上游 ID。
func TestProjectRequestRequiresResolvedContinuation(t *testing.T) {
	request := responsesTestRequest()
	request.Context = nil
	request.ReasoningPolicy.ContinuationID = "continuation-1"
	_, errProject := ProjectRequest(request, responsesTarget(), responsesCapabilities(), "lineage-1", "", responsesNow())
	if !errors.Is(errProject, ErrUnsupportedContext) {
		t.Fatalf("ProjectRequest() error = %v, want ErrUnsupportedContext", errProject)
	}
}

// TestProjectRequestRejectsStopSequences verifies Responses requests never silently discard a VCP control with no legal upstream carrier.
// TestProjectRequestRejectsStopSequences 验证 Responses 请求绝不会静默丢弃没有合法上游载体的 VCP 控制。
func TestProjectRequestRejectsStopSequences(t *testing.T) {
	request := responsesTestRequest()
	request.GenerationPolicy.Stop = []string{"<stop>"}

	if _, errProject := ProjectRequest(request, responsesTarget(), responsesCapabilities(), "lineage-stop", "", responsesNow()); !errors.Is(errProject, ErrUnsupportedContext) {
		t.Fatalf("ProjectRequest() error = %v, want ErrUnsupportedContext", errProject)
	}
}

// TestProjectRequestRejectsUnverifiedReasoningSwitchAndBudget verifies unsupported canonical controls cannot be silently omitted by Responses.
// TestProjectRequestRejectsUnverifiedReasoningSwitchAndBudget 验证 Responses 不能静默省略未验证的规范开关与预算控制。
func TestProjectRequestRejectsUnverifiedReasoningSwitchAndBudget(t *testing.T) {
	enabled := true
	budget := int64(4000)
	for _, policy := range []vcp.ReasoningPolicy{{Enabled: &enabled}, {BudgetTokens: &budget}} {
		request := responsesTestRequest()
		request.ReasoningPolicy = policy
		if _, errProject := ProjectRequest(request, responsesTarget(), ProfileCapabilities{Reasoning: true}, "lin_reasoning_control", "", time.Unix(51, 0)); !errors.Is(errProject, ErrUnsupportedContext) {
			t.Fatalf("ProjectRequest() error = %v, want ErrUnsupportedContext", errProject)
		}
	}
}

// TestProjectRequestOmitsNonModelVisibility verifies client and audit-only context never reaches the Responses wire request.
// TestProjectRequestOmitsNonModelVisibility 验证客户端和仅审计上下文永远不会进入 Responses wire 请求。
func TestProjectRequestOmitsNonModelVisibility(t *testing.T) {
	for _, visibility := range []vcp.Visibility{vcp.VisibilityClient, vcp.VisibilityAuditOnly} {
		t.Run(string(visibility), func(t *testing.T) {
			request := responsesTestRequest()
			hidden := vcp.ContextItem{ItemID: "hidden", Sequence: 2, Kind: vcp.ContextMessage, Authority: vcp.AuthorityAssistant, Actor: vcp.ActorPrimaryAssistant, Placement: vcp.PlacementTranscript, Activation: vcp.Activation{Mode: vcp.ActivationRequestStart}, Visibility: visibility, Content: []vcp.ContentBlock{{Type: vcp.ContentText, Text: "must not reach upstream"}}, Message: &vcp.MessageItem{}}
			request.Context = append(request.Context, hidden)

			projected, errProject := ProjectRequest(request, responsesTarget(), responsesCapabilities(), "lineage-visibility", "", responsesNow())
			if errProject != nil {
				t.Fatalf("ProjectRequest() error = %v", errProject)
			}
			if len(projected.Upstream.Input) != 1 || projected.Upstream.Input[0].Content[0].Text != "Hello" {
				t.Fatalf("input = %#v", projected.Upstream.Input)
			}
			entry := projected.Ledger.Entries[1]
			if entry.UpstreamPosition != -1 || entry.ProjectionMode != vcp.CapabilityOmitted || entry.RuleID != "openai_responses.visibility.omitted.v1" {
				t.Fatalf("ledger entry = %#v", entry)
			}
		})
	}
}

// TestProjectRequestRejectsUnresolvedProviderState verifies opaque VCP state cannot be mistaken for a raw Responses continuation identifier.
// TestProjectRequestRejectsUnresolvedProviderState 验证不透明 VCP 状态不会被误认为原始 Responses 续接标识。
func TestProjectRequestRejectsUnresolvedProviderState(t *testing.T) {
	request := responsesTestRequest()
	request.Context[0].ProviderStateRef = "sealed-state"

	if _, errProject := ProjectRequest(request, responsesTarget(), responsesCapabilities(), "lineage-provider-state", "", responsesNow()); !errors.Is(errProject, ErrUnsupportedContext) {
		t.Fatalf("ProjectRequest() error = %v, want ErrUnsupportedContext", errProject)
	}
}

// TestProjectRequestDoesNotEmitEmptyReasoningConfigurationForHistory verifies that replayed summaries do not create an unrequested reasoning control.
// TestProjectRequestDoesNotEmitEmptyReasoningConfigurationForHistory 验证回放摘要不会创建未请求的推理控制。
func TestProjectRequestDoesNotEmitEmptyReasoningConfigurationForHistory(t *testing.T) {
	request := responsesTestRequest()
	request.Context = append(request.Context, vcp.ContextItem{
		ItemID: "item-reasoning", Sequence: 2, Kind: vcp.ContextReasoning, Authority: vcp.AuthorityAssistant, Actor: vcp.ActorPrimaryAssistant,
		Placement: vcp.PlacementTranscript, Activation: vcp.Activation{Mode: vcp.ActivationRequestStart}, Visibility: vcp.VisibilityModel,
		Content: []vcp.ContentBlock{{Type: vcp.ContentText, Text: "Prior visible reasoning"}}, Reasoning: &vcp.ReasoningItem{Summary: true},
	})
	projected, errProject := ProjectRequest(request, responsesTarget(), responsesCapabilities(), "lineage-1", "", responsesNow())
	if errProject != nil {
		t.Fatalf("ProjectRequest() error = %v", errProject)
	}
	if projected.Upstream.Reasoning != nil {
		t.Fatalf("historical reasoning emitted unrequested configuration: %#v", projected.Upstream.Reasoning)
	}
	if len(projected.Upstream.Input) != 2 || projected.Upstream.Input[1].Type != "reasoning" {
		t.Fatalf("historical reasoning input = %#v", projected.Upstream.Input)
	}
}

// responsesTestRequest creates one valid ordinary VCP request for Responses profile tests.
// responsesTestRequest 创建一个用于 Responses Profile 测试的有效普通 VCP 请求。
func responsesTestRequest() vcp.VulcanRequest {
	return vcp.VulcanRequest{
		ProtocolVersion: vcp.ProtocolVersion, RequestID: "request-1",
		ModelSelection: vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: "instance-1", ProviderModelID: "model-1", ExecutionProfileID: "profile-1"},
		Context: []vcp.ContextItem{{
			ItemID: "item-user", Sequence: 1, Kind: vcp.ContextMessage, Authority: vcp.AuthorityUser, Actor: vcp.ActorEndUser,
			Placement: vcp.PlacementTranscript, Activation: vcp.Activation{Mode: vcp.ActivationRequestStart}, Visibility: vcp.VisibilityModel,
			Content: []vcp.ContentBlock{{Type: vcp.ContentText, Text: "Hello"}}, Message: &vcp.MessageItem{},
		}},
		CachePolicy:             vcp.CachePolicy{Strategy: vcp.CacheRegular, OnUnsupported: vcp.CacheUnsupportedReject},
		ContextManagementPolicy: vcp.ContextManagementPolicy{Mode: vcp.ContextManagementRegular},
		CapabilityPolicy:        vcp.CapabilityPolicy{ExecutionMode: vcp.CapabilityMaximize, OptionalOnUnsupported: vcp.OptionalOmit},
	}
}

// responsesTarget creates a complete exact target for Responses profile tests.
// responsesTarget 创建一个用于 Responses Profile 测试的完整精确 Target。
func responsesTarget() resolve.Target {
	return resolve.Target{
		ProviderDefinitionID: "definition-1", ProviderInstanceID: "instance-1", ChannelID: "channel-1", EndpointID: "endpoint-1", CredentialID: "credential-1",
		ProviderModelID: "model-1", OfferingID: "offering-1", ExecutionProfileID: "profile-1", UpstreamModelID: "gpt-test", CatalogRevision: 7,
	}
}

// responsesCapabilities creates a fully verified capability fixture for pure Profile tests.
// responsesCapabilities 创建一个用于纯 Profile 测试的完全验证能力夹具。
func responsesCapabilities() ProfileCapabilities {
	return ProfileCapabilities{
		MediaInputKinds: []vcp.MediaKind{vcp.MediaImage, vcp.MediaAudio, vcp.MediaFile}, MediaMaterializations: []catalog.UpstreamMaterializationMode{catalog.MaterializationInlineBase64, catalog.MaterializationProviderFileID},
		NativeSystemPreamble: true, NativeDeveloper: true, NativeInlineSystem: true, StructuredTools: true, NativeCustomTools: true,
		NativeToolNamespaces: true, ParallelTools: true, StreamingToolArguments: true, StrictJSONSchema: true, Reasoning: true,
		ReasoningContinuation: true, NativeWebSearch: true,
	}
}

// responsesNow returns a fixed time for deterministic projection identities.
// responsesNow 返回用于确定性投影身份的固定时间。
func responsesNow() time.Time {
	return time.Date(2026, time.July, 17, 0, 0, 0, 0, time.UTC)
}
