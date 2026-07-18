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

	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

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
	if output := projected.Upstream.Input[2]; output.Type != "function_call_output" || output.CallID != "upstream-call" || output.Output != "Sunny" {
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
