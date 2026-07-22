// Request fixtures cover behavior adapted from CLIProxyAPI commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// 请求夹具覆盖改编自 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66 的行为。
// Source paths: internal/runtime/executor/xai_executor.go and internal/translator/openai/openai/responses/openai_openai-responses_tools.go.
// 来源路径：internal/runtime/executor/xai_executor.go 和 internal/translator/openai/openai/responses/openai_openai-responses_tools.go。
// The fixtures verify typed xAI request normalization without importing CLIProxyAPI runtime code.
// 夹具验证类型化 xAI 请求归一化，不导入 CLIProxyAPI 运行时代码。
package responses

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestProjectRequestNormalizesNamespaceCustomAndXSearch verifies the selected xAI rules remain typed and auditable.
// TestProjectRequestNormalizesNamespaceCustomAndXSearch 验证选定 xAI 规则保持类型化且可审计。
func TestProjectRequestNormalizesNamespaceCustomAndXSearch(t *testing.T) {
	request := xaiTestRequest()
	request.Tools = []vcp.ToolDefinition{
		{Kind: vcp.ToolFunction, Namespace: "weather", Name: "lookup", Parameters: json.RawMessage(`{"type":"object","properties":{"city":{"type":"string"}}}`)},
		{Kind: vcp.ToolCustom, Namespace: "ops", Name: "run", Description: "Run an operation"},
		{Kind: vcp.ToolNativeWebSearch, Name: "x_search"},
	}
	request.Context = append(request.Context,
		vcp.ContextItem{ItemID: "custom-call", Sequence: 2, Kind: vcp.ContextToolCall, Authority: vcp.AuthorityAssistant, Actor: vcp.ActorPrimaryAssistant, Placement: vcp.PlacementTranscript, Activation: vcp.Activation{Mode: vcp.ActivationRequestStart}, Visibility: vcp.VisibilityModel, ToolCall: &vcp.ToolCallItem{ToolCallID: "call-1", UpstreamID: "upstream-call-1", Namespace: "ops", Name: "run", Arguments: "raw input", Status: vcp.ToolCallCompleted}},
		vcp.ContextItem{ItemID: "custom-result", Sequence: 3, Kind: vcp.ContextToolResult, Authority: vcp.AuthorityTool, Actor: vcp.ActorTool, Placement: vcp.PlacementTranscript, Activation: vcp.Activation{Mode: vcp.ActivationRequestStart}, Visibility: vcp.VisibilityModel, Content: []vcp.ContentBlock{{Type: vcp.ContentText, Text: "done"}}, ToolResult: &vcp.ToolResultItem{ToolCallID: "call-1"}},
	)
	projected, errProject := ProjectRequest(request, xaiTarget(), xaiCapabilities(), "lineage-1", "", xaiNow())
	if errProject != nil {
		t.Fatalf("ProjectRequest() error = %v", errProject)
	}
	if len(projected.Upstream.Tools) != 3 {
		t.Fatalf("tools = %#v", projected.Upstream.Tools)
	}
	if function := projected.Upstream.Tools[0]; function.Type != xaiFunctionType || function.Name != "weather__lookup" {
		t.Fatalf("function tool = %#v", function)
	}
	if custom := projected.Upstream.Tools[1]; custom.Type != xaiFunctionType || custom.Name != "ops__run" || string(custom.Parameters) != string(xaiDefaultFunctionParameters) {
		t.Fatalf("custom tool = %#v", custom)
	}
	if search := projected.Upstream.Tools[2]; search.Type != xaiXSearchType {
		t.Fatalf("search tool = %#v", search)
	}
	if len(projected.Upstream.Input) != 3 || projected.Upstream.Input[1].Type != "function_call" || projected.Upstream.Input[1].CallID != "upstream-call-1" || projected.Upstream.Input[1].Name != "ops__run" || projected.Upstream.Input[1].Arguments != `{"input":"raw input"}` {
		t.Fatalf("input = %#v", projected.Upstream.Input)
	}
	if output := projected.Upstream.Input[2]; output.Type != "function_call_output" || output.Output == nil || output.Output.Text == nil || *output.Output.Text != "done" || output.Output.ComputerScreenshot != nil {
		t.Fatalf("custom output = %#v", output)
	}
	if len(projected.StreamOptions.ToolReferences) != 2 || !projected.StreamOptions.FilterInternalXSearch {
		t.Fatalf("stream options = %#v", projected.StreamOptions)
	}
	entry := projected.Ledger.Entries[1]
	if entry.OriginalItem.ToolCall == nil || entry.OriginalItem.ToolCall.Namespace != "ops" || entry.ProjectionMode != vcp.CapabilityProjected || entry.RuleID != "xai_responses.custom_tool.namespace_function_projected.v1" {
		t.Fatalf("ledger entry = %#v", entry)
	}
}

// TestProjectRequestRejectsUnverifiedReasoningEffort verifies an unsupported model effort is never silently stripped.
// TestProjectRequestRejectsUnverifiedReasoningEffort 验证不受支持的模型强度永远不会被静默移除。
func TestProjectRequestRejectsUnverifiedReasoningEffort(t *testing.T) {
	request := xaiTestRequest()
	request.ReasoningPolicy.Effort = "high"
	capabilities := xaiCapabilities()
	capabilities.ReasoningEffort = false
	_, errProject := ProjectRequest(request, xaiTarget(), capabilities, "lineage-1", "", xaiNow())
	if !errors.Is(errProject, ErrUnsupportedContext) {
		t.Fatalf("ProjectRequest() error = %v, want ErrUnsupportedContext", errProject)
	}
}

// TestProjectRequestRejectsStopSequences verifies xAI Responses does not silently erase a VCP stop-sequence control.
// TestProjectRequestRejectsStopSequences 验证 xAI Responses 不会静默抹除 VCP 停止序列控制。
func TestProjectRequestRejectsStopSequences(t *testing.T) {
	request := xaiTestRequest()
	request.GenerationPolicy.Stop = []string{"<stop>"}

	if _, errProject := ProjectRequest(request, xaiTarget(), xaiCapabilities(), "lineage-stop", "", xaiNow()); !errors.Is(errProject, ErrUnsupportedContext) {
		t.Fatalf("ProjectRequest() error = %v, want ErrUnsupportedContext", errProject)
	}
}

// TestProjectRequestOmitsNonModelVisibility verifies xAI keeps local-only context out of its Responses wire request.
// TestProjectRequestOmitsNonModelVisibility 验证 xAI 会将仅本地上下文排除在其 Responses wire 请求之外。
func TestProjectRequestOmitsNonModelVisibility(t *testing.T) {
	for _, visibility := range []vcp.Visibility{vcp.VisibilityClient, vcp.VisibilityAuditOnly} {
		t.Run(string(visibility), func(t *testing.T) {
			request := xaiTestRequest()
			request.Context = append(request.Context, vcp.ContextItem{ItemID: "hidden", Sequence: 2, Kind: vcp.ContextMessage, Authority: vcp.AuthorityAssistant, Actor: vcp.ActorPrimaryAssistant, Placement: vcp.PlacementTranscript, Activation: vcp.Activation{Mode: vcp.ActivationRequestStart}, Visibility: visibility, Content: []vcp.ContentBlock{{Type: vcp.ContentText, Text: "must not reach upstream"}}, Message: &vcp.MessageItem{}})

			projected, errProject := ProjectRequest(request, xaiTarget(), xaiCapabilities(), "lineage-visibility", "", xaiNow())
			if errProject != nil {
				t.Fatalf("ProjectRequest() error = %v", errProject)
			}
			if len(projected.Upstream.Input) != 1 || projected.Upstream.Input[0].Content[0].Text != "Hello" {
				t.Fatalf("input = %#v", projected.Upstream.Input)
			}
			entry := projected.Ledger.Entries[1]
			if entry.UpstreamPosition != -1 || entry.ProjectionMode != vcp.CapabilityOmitted || entry.RuleID != "xai_responses.visibility.omitted.v1" {
				t.Fatalf("ledger entry = %#v", entry)
			}
		})
	}
}

// TestProjectRequestOmitsHiddenToolCallWithoutDeclaration verifies local-only tool calls never affect xAI tool resolution.
// TestProjectRequestOmitsHiddenToolCallWithoutDeclaration 验证仅本地工具调用绝不会影响 xAI 工具解析。
func TestProjectRequestOmitsHiddenToolCallWithoutDeclaration(t *testing.T) {
	// request carries a client-only tool call whose unregistered identity must remain outside the upstream projection.
	// request 携带一个仅客户端可见的工具调用，其未注册身份必须保留在上游投影之外。
	request := xaiTestRequest()
	request.Context = append(request.Context, vcp.ContextItem{
		ItemID: "hidden-tool-call", Sequence: 2, Kind: vcp.ContextToolCall, Authority: vcp.AuthorityAssistant, Actor: vcp.ActorPrimaryAssistant,
		Placement: vcp.PlacementTranscript, Activation: vcp.Activation{Mode: vcp.ActivationRequestStart}, Visibility: vcp.VisibilityClient,
		ToolCall: &vcp.ToolCallItem{ToolCallID: "call-hidden", Namespace: "private", Name: "unregistered", Status: vcp.ToolCallCompleted},
	})

	// projected records the omitted local-only item without attempting namespace qualification.
	// projected 记录被省略的仅本地项目，且不会尝试命名空间限定。
	projected, errProject := ProjectRequest(request, xaiTarget(), xaiCapabilities(), "lineage-hidden-tool", "", xaiNow())
	if errProject != nil {
		t.Fatalf("ProjectRequest() error = %v", errProject)
	}
	if len(projected.Upstream.Input) != 1 || projected.Upstream.Input[0].Content[0].Text != "Hello" {
		t.Fatalf("input = %#v", projected.Upstream.Input)
	}
	// entry is the ledger record for the client-only tool call.
	// entry 是仅客户端工具调用对应的账本记录。
	entry := projected.Ledger.Entries[1]
	if entry.UpstreamPosition != -1 || entry.ProjectionMode != vcp.CapabilityOmitted || entry.RuleID != "xai_responses.visibility.omitted.v1" {
		t.Fatalf("ledger entry = %#v", entry)
	}
}

// TestProjectRequestRejectsUnresolvedProviderState verifies xAI never receives an opaque Router state as a raw Responses identifier.
// TestProjectRequestRejectsUnresolvedProviderState 验证 xAI 永远不会接收被当作原始 Responses 标识的不透明 Router 状态。
func TestProjectRequestRejectsUnresolvedProviderState(t *testing.T) {
	request := xaiTestRequest()
	request.Context[0].ProviderStateRef = "sealed-state"

	if _, errProject := ProjectRequest(request, xaiTarget(), xaiCapabilities(), "lineage-provider-state", "", xaiNow()); !errors.Is(errProject, ErrUnsupportedContext) {
		t.Fatalf("ProjectRequest() error = %v, want ErrUnsupportedContext", errProject)
	}
}

// TestProjectRequestRejectsCustomApplyPatch verifies the documented xAI incompatibility is explicit at the VCP boundary.
// TestProjectRequestRejectsCustomApplyPatch 验证文档化的 xAI 不兼容性会在 VCP 边界显式返回。
func TestProjectRequestRejectsCustomApplyPatch(t *testing.T) {
	request := xaiTestRequest()
	request.Tools = []vcp.ToolDefinition{{Kind: vcp.ToolCustom, Name: "apply_patch"}}
	_, errProject := ProjectRequest(request, xaiTarget(), xaiCapabilities(), "lineage-1", "", xaiNow())
	if !errors.Is(errProject, ErrUnsupportedContext) {
		t.Fatalf("ProjectRequest() error = %v, want ErrUnsupportedContext", errProject)
	}
}

// TestProjectRequestRejectsStrictRootUnion verifies a strict VCP function schema is never silently downgraded for xAI compatibility.
// TestProjectRequestRejectsStrictRootUnion 验证严格 VCP 函数 Schema 永远不会因 xAI 兼容而被静默降级。
func TestProjectRequestRejectsStrictRootUnion(t *testing.T) {
	request := xaiTestRequest()
	request.Tools = []vcp.ToolDefinition{{Kind: vcp.ToolFunction, Name: "union", Strict: true, Parameters: json.RawMessage(`{"anyOf":[{"type":"object"},{"type":"string"}]}`)}}
	_, errProject := ProjectRequest(request, xaiTarget(), xaiCapabilities(), "lineage-1", "", xaiNow())
	if !errors.Is(errProject, ErrUnsupportedContext) {
		t.Fatalf("ProjectRequest() error = %v, want ErrUnsupportedContext", errProject)
	}
}

// TestProjectRequestSimplifiesNonStrictRootUnion verifies only a non-strict source-evidenced incompatible schema may use the documented xAI fallback.
// TestProjectRequestSimplifiesNonStrictRootUnion 验证只有非严格的来源证实不兼容 Schema 才可使用文档化 xAI 回退。
func TestProjectRequestSimplifiesNonStrictRootUnion(t *testing.T) {
	request := xaiTestRequest()
	request.Tools = []vcp.ToolDefinition{{Kind: vcp.ToolFunction, Name: "union", Parameters: json.RawMessage(`{"anyOf":[{"type":"object"},{"type":"string"}]}`)}}
	projected, errProject := ProjectRequest(request, xaiTarget(), xaiCapabilities(), "lineage-1", "", xaiNow())
	if errProject != nil {
		t.Fatalf("ProjectRequest() error = %v", errProject)
	}
	tool := projected.Upstream.Tools[0]
	if string(tool.Parameters) != string(xaiDefaultFunctionParameters) || tool.Strict {
		t.Fatalf("tool = %#v", tool)
	}
	if !containsSummary(projected.Report.ConversionSummary, "xai_responses.function_schema.simplified") {
		t.Fatalf("report = %#v", projected.Report)
	}
}

// TestProjectRequestMergesAdjacentReasoningSummaries verifies source-evidenced xAI summary coalescing keeps ledger ownership and wire order exact.
// TestProjectRequestMergesAdjacentReasoningSummaries 验证来源证实的 xAI 摘要合并保持账本归属和 wire 顺序精确。
func TestProjectRequestMergesAdjacentReasoningSummaries(t *testing.T) {
	request := xaiTestRequest()
	message := request.Context[0]
	message.ItemID = "user-item-3"
	message.Sequence = 3
	request.Context = []vcp.ContextItem{
		xaiReasoningSummary("reasoning-item-1", 1, "first"),
		xaiReasoningSummary("reasoning-item-2", 2, "second"),
		message,
	}
	projected, errProject := ProjectRequest(request, xaiTarget(), xaiCapabilities(), "lineage-1", "", xaiNow())
	if errProject != nil {
		t.Fatalf("ProjectRequest() error = %v", errProject)
	}
	if len(projected.Upstream.Input) != 2 || projected.Upstream.Input[0].Type != "reasoning" || len(projected.Upstream.Input[0].Summary) != 2 || projected.Upstream.Input[0].Summary[0].Text != "first" || projected.Upstream.Input[0].Summary[1].Text != "second" || projected.Upstream.Input[1].Type != "message" {
		t.Fatalf("upstream input = %#v", projected.Upstream.Input)
	}
	if projected.Ledger.Entries[0].UpstreamPosition != 0 || projected.Ledger.Entries[1].UpstreamPosition != 0 || projected.Ledger.Entries[2].UpstreamPosition != 1 {
		t.Fatalf("ledger positions = %#v", projected.Ledger.Entries)
	}
	restored, errRestore := projected.Ledger.Restore()
	if errRestore != nil || len(restored) != len(request.Context) || restored[0].ItemID != "reasoning-item-1" || restored[1].ItemID != "reasoning-item-2" || restored[2].ItemID != "user-item-3" {
		t.Fatalf("Restore() = %#v, %v", restored, errRestore)
	}
	if !containsSummary(projected.Report.ConversionSummary, "xai_responses.reasoning_summary.merged") {
		t.Fatalf("report = %#v", projected.Report)
	}
}

// TestProjectRequestMarksVerifiedRemoteCompactionNative verifies the xAI-specific compact capability replaces the shared unavailable fact.
// TestProjectRequestMarksVerifiedRemoteCompactionNative 验证 xAI 特定 compact 能力会替换共享的不可用事实。
func TestProjectRequestMarksVerifiedRemoteCompactionNative(t *testing.T) {
	request := xaiTestRequest()
	request.ContextManagementPolicy.Mode = vcp.ContextManagementAuto
	projected, errProject := ProjectRequest(request, xaiTarget(), xaiCapabilities(), "lineage-1", "", xaiNow())
	if errProject != nil {
		t.Fatalf("ProjectRequest() error = %v", errProject)
	}
	if !hasNativeDecision(projected.Report.CapabilityDecisions, vcp.FeatureRemoteCompaction) {
		t.Fatalf("capability decisions = %#v", projected.Report.CapabilityDecisions)
	}
}

// TestProjectCompactRequestUsesResolvedPreviousResponse verifies compact sends only a Router-resolved upstream response identifier.
// TestProjectCompactRequestUsesResolvedPreviousResponse 验证 compact 仅发送 Router 已解析的上游响应标识。
func TestProjectCompactRequestUsesResolvedPreviousResponse(t *testing.T) {
	request := xaiTestRequest()
	request.RemoteCompaction = &vcp.RemoteCompactionRequest{PreviousResponseID: "continuation-1"}
	projected, errProject := ProjectCompactRequest(request, xaiTarget(), xaiCapabilities(), "lineage-1", "upstream-response-1", xaiNow())
	if errProject != nil {
		t.Fatalf("ProjectCompactRequest() error = %v", errProject)
	}
	if projected.Upstream.PreviousResponseID != "upstream-response-1" || projected.Upstream.Stream || len(projected.Upstream.Tools) != 0 || projected.Upstream.ToolChoice != nil || projected.Upstream.ParallelToolCalls != nil {
		t.Fatalf("compact upstream = %#v", projected.Upstream)
	}
	if !hasNativeDecision(projected.Report.CapabilityDecisions, vcp.FeatureRemoteCompaction) || !containsSummary(projected.Report.ConversionSummary, "xai_responses.remote_compaction.native") {
		t.Fatalf("compact report = %#v", projected.Report)
	}
}

// xaiTestRequest creates one valid ordinary VCP request for xAI Responses profile tests.
// xaiTestRequest 创建一个用于 xAI Responses Profile 测试的有效普通 VCP 请求。
func xaiTestRequest() vcp.VulcanRequest {
	return vcp.VulcanRequest{
		ProtocolVersion: vcp.ProtocolVersion, RequestID: "request-1",
		ModelSelection: vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: "instance-1", ProviderModelID: "model-1", ExecutionProfileID: ProfileID},
		Context: []vcp.ContextItem{{
			ItemID: "user-item", Sequence: 1, Kind: vcp.ContextMessage, Authority: vcp.AuthorityUser, Actor: vcp.ActorEndUser,
			Placement: vcp.PlacementTranscript, Activation: vcp.Activation{Mode: vcp.ActivationRequestStart}, Visibility: vcp.VisibilityModel,
			Content: []vcp.ContentBlock{{Type: vcp.ContentText, Text: "Hello"}}, Message: &vcp.MessageItem{},
		}},
		CachePolicy:             vcp.CachePolicy{Strategy: vcp.CacheRegular, OnUnsupported: vcp.CacheUnsupportedReject},
		ContextManagementPolicy: vcp.ContextManagementPolicy{Mode: vcp.ContextManagementRegular},
		CapabilityPolicy:        vcp.CapabilityPolicy{ExecutionMode: vcp.CapabilityMaximize, OptionalOnUnsupported: vcp.OptionalOmit},
	}
}

// xaiReasoningSummary creates one visible canonical reasoning summary item for source-compatibility projection tests.
// xaiReasoningSummary 为来源兼容性投影测试创建一个可见规范推理摘要项目。
func xaiReasoningSummary(itemID string, sequence uint64, text string) vcp.ContextItem {
	return vcp.ContextItem{
		ItemID: itemID, Sequence: sequence, Kind: vcp.ContextReasoning, Authority: vcp.AuthorityAssistant, Actor: vcp.ActorPrimaryAssistant,
		Placement: vcp.PlacementTranscript, Activation: vcp.Activation{Mode: vcp.ActivationRequestStart}, Visibility: vcp.VisibilityModel,
		Content: []vcp.ContentBlock{{Type: vcp.ContentText, Text: text}}, Reasoning: &vcp.ReasoningItem{Summary: true},
	}
}

// xaiTarget creates a complete exact target for xAI Responses profile tests.
// xaiTarget 创建一个用于 xAI Responses Profile 测试的完整精确 Target。
func xaiTarget() resolve.Target {
	return resolve.Target{
		ProviderDefinitionID: "definition-1", ProviderInstanceID: "instance-1", ChannelID: "channel-1", EndpointID: "endpoint-1", CredentialID: "credential-1",
		ProviderModelID: "model-1", OfferingID: "offering-1", ExecutionProfileID: ProfileID, UpstreamModelID: "grok-test", CatalogRevision: 7,
	}
}

// xaiCapabilities creates a fully verified capability fixture for pure xAI Profile tests.
// xaiCapabilities 创建一个用于纯 xAI Profile 测试的完全验证能力夹具。
func xaiCapabilities() ProfileCapabilities {
	return ProfileCapabilities{
		NativeSystemPreamble: true, NativeDeveloper: true, NativeInlineSystem: true, StructuredTools: true, ParallelTools: true,
		StreamingToolArguments: true, StrictJSONSchema: true, Reasoning: true, ReasoningEffort: true, ReasoningContinuation: true,
		NativeXSearch: true, NativeRemoteCompaction: true,
	}
}

// xaiNow returns a fixed time for deterministic xAI projection identities.
// xaiNow 返回用于确定性 xAI 投影身份的固定时间。
func xaiNow() time.Time {
	return time.Date(2026, time.July, 17, 0, 0, 0, 0, time.UTC)
}

// containsSummary reports whether one conversion code exists in a deterministic report summary.
// containsSummary 报告确定性报告摘要中是否存在一个转换代码。
func containsSummary(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// hasNativeDecision reports whether a capability report records the required native selection.
// hasNativeDecision 报告能力报告是否记录所需的原生选择。
func hasNativeDecision(decisions []vcp.CapabilityDecision, feature vcp.CapabilityFeature) bool {
	for _, decision := range decisions {
		if decision.Feature == feature && decision.SelectedMode == vcp.CapabilityNative {
			return true
		}
	}
	return false
}
