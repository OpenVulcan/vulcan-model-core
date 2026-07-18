// Request fixtures cover behavior adapted from CLIProxyAPI commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// 请求夹具覆盖改编自 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66 的行为。
// Source paths: internal/translator/gemini/gemini/gemini_gemini_request.go and internal/translator/gemini/openai/responses/gemini_openai-responses_request.go.
// 来源路径：internal/translator/gemini/gemini/gemini_gemini_request.go 和 internal/translator/gemini/openai/responses/gemini_openai-responses_request.go。
// The fixtures verify typed AI Studio request projection without importing CLIProxyAPI translator runtime code.
// 夹具验证类型化 AI Studio 请求投影，不导入 CLIProxyAPI Translator 运行时代码。
package aistudio

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestProjectRequestMapsSystemToolsAndFunctionAffinity verifies native system, tool, strict-schema, and correlated function-response projection.
// TestProjectRequestMapsSystemToolsAndFunctionAffinity 验证原生系统指令、工具、严格 Schema 与关联函数响应投影。
func TestProjectRequestMapsSystemToolsAndFunctionAffinity(t *testing.T) {
	request := aiStudioTestRequest()
	request.Context = []vcp.ContextItem{
		aiStudioInstruction("system-item", 1, vcp.AuthoritySystem, vcp.PlacementPreamble, "System instruction"),
		aiStudioMessage("user-item", 2, vcp.AuthorityUser, "What is the weather?"),
		aiStudioToolCall("tool-call-item", 3, "call-1", "upstream-call-1", "weather", "lookup", `{"city":"Paris"}`),
		aiStudioToolResult("tool-result-item", 4, "call-1", "sunny"),
	}
	request.Tools = []vcp.ToolDefinition{{Kind: vcp.ToolFunction, Namespace: "weather", Name: "lookup", Description: "Look up weather", Parameters: json.RawMessage(`{"type":"object","properties":{"city":{"type":"string"}},"required":["city"]}`)}}
	request.ToolPolicy = vcp.ToolPolicy{Choice: vcp.ToolChoiceNamed, NamedTool: "lookup", Parallel: true, StreamArguments: true}
	request.GenerationPolicy.StrictJSONSchema = json.RawMessage(`{"type":"object","properties":{"answer":{"type":"string"}},"required":["answer"]}`)

	projected, errProject := ProjectRequest(request, aiStudioTarget(), aiStudioCapabilities(), "lineage-1", aiStudioNow())
	if errProject != nil {
		t.Fatalf("ProjectRequest() error = %v", errProject)
	}
	if projected.Upstream.SystemInstruction == nil || len(projected.Upstream.SystemInstruction.Parts) != 1 || projected.Upstream.SystemInstruction.Parts[0].Text != "System instruction" {
		t.Fatalf("systemInstruction = %#v", projected.Upstream.SystemInstruction)
	}
	if len(projected.Upstream.Contents) != 3 || projected.Upstream.Contents[1].Role != "model" || projected.Upstream.Contents[2].Role != "user" {
		t.Fatalf("contents = %#v", projected.Upstream.Contents)
	}
	functionCall := projected.Upstream.Contents[1].Parts[0].FunctionCall
	functionResponse := projected.Upstream.Contents[2].Parts[0].FunctionResponse
	if functionCall == nil || functionResponse == nil || functionCall.Name != "weather.lookup" || functionResponse.Name != "weather.lookup" || functionResponse.ID != "upstream-call-1" {
		t.Fatalf("function affinity = %#v %#v", functionCall, functionResponse)
	}
	var responseBody struct {
		// Result contains the typed tool-result text.
		// Result 包含类型化工具结果文本。
		Result string `json:"result"`
	}
	if errDecode := json.Unmarshal(functionResponse.Response, &responseBody); errDecode != nil || responseBody.Result != "sunny" {
		t.Fatalf("function response body = %s, error = %v", functionResponse.Response, errDecode)
	}
	if len(projected.Upstream.Tools) != 1 || len(projected.Upstream.Tools[0].FunctionDeclarations) != 1 || projected.Upstream.Tools[0].FunctionDeclarations[0].Name != "weather.lookup" {
		t.Fatalf("tools = %#v", projected.Upstream.Tools)
	}
	if projected.Upstream.ToolConfig == nil || projected.Upstream.ToolConfig.FunctionCallingConfig.Mode != "ANY" || !reflect.DeepEqual(projected.Upstream.ToolConfig.FunctionCallingConfig.AllowedFunctionNames, []string{"weather.lookup"}) {
		t.Fatalf("toolConfig = %#v", projected.Upstream.ToolConfig)
	}
	if projected.Upstream.GenerationConfig == nil || projected.Upstream.GenerationConfig.ResponseMIMEType != "application/json" || string(projected.Upstream.GenerationConfig.ResponseJSONSchema) != string(request.GenerationPolicy.StrictJSONSchema) {
		t.Fatalf("generationConfig = %#v", projected.Upstream.GenerationConfig)
	}
	restored, errRestore := projected.Ledger.Restore()
	if errRestore != nil || !reflect.DeepEqual(restored, request.Context) {
		t.Fatalf("Restore() = %#v, %v", restored, errRestore)
	}
}

// TestProjectRequestDoesNotInventGeminiFunctionCallID verifies the router-owned ToolCallID never becomes a Gemini wire ID.
// TestProjectRequestDoesNotInventGeminiFunctionCallID 验证 Router 所有的 ToolCallID 永远不会成为 Gemini wire ID。
func TestProjectRequestDoesNotInventGeminiFunctionCallID(t *testing.T) {
	request := aiStudioTestRequest()
	request.Context = []vcp.ContextItem{
		aiStudioMessage("user-item", 1, vcp.AuthorityUser, "What is the weather?"),
		aiStudioToolCall("tool-call-item", 2, "router-call-1", "", "weather", "lookup", `{"city":"Paris"}`),
		aiStudioToolResult("tool-result-item", 3, "router-call-1", "sunny"),
	}

	projected, errProject := ProjectRequest(request, aiStudioTarget(), aiStudioCapabilities(), "lineage-no-upstream-call-id", aiStudioNow())
	if errProject != nil {
		t.Fatalf("ProjectRequest() error = %v", errProject)
	}
	functionCall := projected.Upstream.Contents[1].Parts[0].FunctionCall
	functionResponse := projected.Upstream.Contents[2].Parts[0].FunctionResponse
	if functionCall == nil || functionResponse == nil || functionCall.ID != "" || functionResponse.ID != "" {
		t.Fatalf("Gemini function IDs = %#v %#v, want absent upstream IDs", functionCall, functionResponse)
	}
}

// TestProjectRequestOmitsOnlyTrailingPlainModelPrefill verifies the evidenced compatibility omission preserves all other canonical history.
// TestProjectRequestOmitsOnlyTrailingPlainModelPrefill 验证有证据的兼容性省略只移除尾部普通 model 预填，并保留其他规范历史。
func TestProjectRequestOmitsOnlyTrailingPlainModelPrefill(t *testing.T) {
	request := aiStudioTestRequest()
	request.Context = []vcp.ContextItem{
		aiStudioMessage("user-item", 1, vcp.AuthorityUser, "Question"),
		aiStudioMessage("model-prefill", 2, vcp.AuthorityAssistant, "Prefill"),
	}

	projected, errProject := ProjectRequest(request, aiStudioTarget(), aiStudioCapabilities(), "lineage-2", aiStudioNow())
	if errProject != nil {
		t.Fatalf("ProjectRequest() error = %v", errProject)
	}
	if len(projected.Upstream.Contents) != 1 || projected.Upstream.Contents[0].Role != "user" {
		t.Fatalf("contents = %#v", projected.Upstream.Contents)
	}
	if len(projected.Ledger.Entries) != 2 || projected.Ledger.Entries[1].ProjectionMode != vcp.CapabilityOmitted || projected.Ledger.Entries[1].CarrierRoleOrSlot != "omitted:trailing_model_prefill" {
		t.Fatalf("ledger = %#v", projected.Ledger.Entries)
	}
	if !aiStudioContainsSummary(projected.Report.ConversionSummary, "google_aistudio.trailing_model_prefill.omitted") {
		t.Fatalf("report = %#v", projected.Report)
	}
}

// TestToolReferenceSetRejectsLossyNormalizedCollision verifies source-derived name sanitization cannot silently alias two VCP tools.
// TestToolReferenceSetRejectsLossyNormalizedCollision 验证来源派生的名称清理不会静默别名化两个 VCP 工具。
func TestToolReferenceSetRejectsLossyNormalizedCollision(t *testing.T) {
	references := newToolReferenceSet()
	if _, errFirst := references.ensure("", "weather/lookup"); errFirst != nil {
		t.Fatalf("ensure first tool error = %v", errFirst)
	}
	if _, errSecond := references.ensure("", "weather_lookup"); !errors.Is(errSecond, ErrUnsupportedContext) {
		t.Fatalf("ensure second tool error = %v, want ErrUnsupportedContext", errSecond)
	}
}

// TestProjectRequestRejectsStrictFunctionTool verifies AI Studio never silently drops a VCP strict function-schema requirement.
// TestProjectRequestRejectsStrictFunctionTool 验证 AI Studio 永远不会静默丢弃 VCP 严格函数 Schema 要求。
func TestProjectRequestRejectsStrictFunctionTool(t *testing.T) {
	request := aiStudioTestRequest()
	request.Tools = []vcp.ToolDefinition{{Kind: vcp.ToolFunction, Name: "lookup", Strict: true, Parameters: json.RawMessage(`{"type":"object","properties":{}}`)}}

	_, errProject := ProjectRequest(request, aiStudioTarget(), aiStudioCapabilities(), "lineage-strict-tool", aiStudioNow())
	if !errors.Is(errProject, ErrUnsupportedContext) {
		t.Fatalf("ProjectRequest() error = %v, want ErrUnsupportedContext", errProject)
	}
}

// TestProjectCountTokensRequestUsesTypedEnvelope verifies countTokens retains the exact typed generation request without response streaming.
// TestProjectCountTokensRequestUsesTypedEnvelope 验证 countTokens 保留精确类型化生成请求且不携带响应流。
func TestProjectCountTokensRequestUsesTypedEnvelope(t *testing.T) {
	request := aiStudioTestRequest()
	request.Stream = true
	projected, countRequest, errProject := ProjectCountTokensRequest(request, aiStudioTarget(), aiStudioCapabilities(), "lineage-3", aiStudioNow())
	if errProject != nil {
		t.Fatalf("ProjectCountTokensRequest() error = %v", errProject)
	}
	if !reflect.DeepEqual(countRequest.GenerateContentRequest, projected.Upstream) || len(countRequest.GenerateContentRequest.Contents) != 1 || countRequest.GenerateContentRequest.Contents[0].Role != "user" {
		t.Fatalf("count request = %#v, projected = %#v", countRequest, projected)
	}
}

// TestProjectRequestMapsVerifiedThinkingControls verifies VCP reasoning effort and summary become only the target-verified Gemini thinkingConfig fields.
// TestProjectRequestMapsVerifiedThinkingControls 验证 VCP 推理强度和摘要只会变成 Target 已验证的 Gemini thinkingConfig 字段。
func TestProjectRequestMapsVerifiedThinkingControls(t *testing.T) {
	request := aiStudioTestRequest()
	request.ReasoningPolicy = vcp.ReasoningPolicy{Effort: "low", Summary: true}
	capabilities := aiStudioCapabilities()
	capabilities.NativeReasoningSummary = true
	capabilities.ThinkingLevels = []string{"low"}
	projected, errProject := ProjectRequest(request, aiStudioTarget(), capabilities, "lineage-4", aiStudioNow())
	if errProject != nil {
		t.Fatalf("ProjectRequest() error = %v", errProject)
	}
	if projected.Upstream.GenerationConfig == nil || projected.Upstream.GenerationConfig.ThinkingConfig == nil || projected.Upstream.GenerationConfig.ThinkingConfig.ThinkingLevel != "low" || projected.Upstream.GenerationConfig.ThinkingConfig.IncludeThoughts == nil || !*projected.Upstream.GenerationConfig.ThinkingConfig.IncludeThoughts {
		t.Fatalf("generationConfig = %#v", projected.Upstream.GenerationConfig)
	}
}

// TestProjectRequestRejectsUnverifiedThinkingLevel verifies an effort request cannot silently become a different Gemini thinking level.
// TestProjectRequestRejectsUnverifiedThinkingLevel 验证强度请求不能静默变成不同的 Gemini 推理等级。
func TestProjectRequestRejectsUnverifiedThinkingLevel(t *testing.T) {
	request := aiStudioTestRequest()
	request.ReasoningPolicy.Effort = "high"
	capabilities := aiStudioCapabilities()
	capabilities.ThinkingLevels = []string{"low"}
	if _, errProject := ProjectRequest(request, aiStudioTarget(), capabilities, "lineage-5", aiStudioNow()); !errors.Is(errProject, ErrUnsupportedContext) {
		t.Fatalf("ProjectRequest() error = %v, want ErrUnsupportedContext", errProject)
	}
}

// TestProjectRequestRejectsOpaqueReasoningContinuation verifies AI Studio never serializes provider-owned continuation state as visible text.
// TestProjectRequestRejectsOpaqueReasoningContinuation 验证 AI Studio 绝不将 Provider 所有的续接状态序列化为可见文本。
func TestProjectRequestRejectsOpaqueReasoningContinuation(t *testing.T) {
	request := aiStudioTestRequest()
	request.Context = []vcp.ContextItem{
		aiStudioMessage("user-item", 1, vcp.AuthorityUser, "Question"),
		{
			ItemID: "reasoning-item", Sequence: 2, Kind: vcp.ContextReasoning, Authority: vcp.AuthorityAssistant, Actor: vcp.ActorPrimaryAssistant,
			Placement: vcp.PlacementTranscript, Activation: vcp.Activation{Mode: vcp.ActivationRequestStart}, Visibility: vcp.VisibilityModel,
			Content: []vcp.ContentBlock{{Type: vcp.ContentText, Text: "Visible summary"}}, Reasoning: &vcp.ReasoningItem{Summary: true, ContinuationRef: "sealed-continuation"},
		},
	}
	if _, errProject := ProjectRequest(request, aiStudioTarget(), aiStudioCapabilities(), "lineage-opaque-continuation", aiStudioNow()); !errors.Is(errProject, vcp.ErrCapabilityUnavailable) {
		t.Fatalf("ProjectRequest() error = %v, want ErrCapabilityUnavailable", errProject)
	}
}

// aiStudioTestRequest creates one valid ordinary VCP request for pure AI Studio profile tests.
// aiStudioTestRequest 创建一条用于纯 AI Studio Profile 测试的有效普通 VCP 请求。
func aiStudioTestRequest() vcp.VulcanRequest {
	return vcp.VulcanRequest{
		ProtocolVersion: vcp.ProtocolVersion, RequestID: "request-aistudio",
		ModelSelection:          vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: "instance-1", ProviderModelID: "model-1", ExecutionProfileID: ProfileID},
		Context:                 []vcp.ContextItem{aiStudioMessage("user-item", 1, vcp.AuthorityUser, "Hello")},
		CachePolicy:             vcp.CachePolicy{Strategy: vcp.CacheRegular, OnUnsupported: vcp.CacheUnsupportedReject},
		ContextManagementPolicy: vcp.ContextManagementPolicy{Mode: vcp.ContextManagementRegular},
		CapabilityPolicy:        vcp.CapabilityPolicy{ExecutionMode: vcp.CapabilityMaximize, OptionalOnUnsupported: vcp.OptionalOmit},
	}
}

// aiStudioTarget creates one complete immutable target for AI Studio profile tests.
// aiStudioTarget 创建一个用于 AI Studio Profile 测试的完整不可变 Target。
func aiStudioTarget() resolve.Target {
	return resolve.Target{
		ProviderDefinitionID: "definition-1", ProviderInstanceID: "instance-1", ChannelID: "channel-1", EndpointID: "endpoint-1", CredentialID: "credential-1",
		ProviderModelID: "model-1", OfferingID: "offering-1", ExecutionProfileID: ProfileID, UpstreamModelID: "gemini-test", CatalogRevision: 7,
	}
}

// aiStudioCapabilities creates a fully verified capability fixture for AI Studio profile tests.
// aiStudioCapabilities 创建一个用于 AI Studio Profile 测试的完全验证能力夹具。
func aiStudioCapabilities() ProfileCapabilities {
	return ProfileCapabilities{
		NativeSystemInstruction: true, StructuredTools: true, ParallelTools: true, StreamingToolArguments: true, StrictJSONSchema: true, NativeReasoning: true,
	}
}

// aiStudioNow returns one fixed time for deterministic projection and event identities.
// aiStudioNow 返回一个用于确定性投影和事件身份的固定时间。
func aiStudioNow() time.Time {
	return time.Date(2026, time.July, 17, 0, 0, 0, 0, time.UTC)
}

// TestProjectRequestOmitsNonModelVisibility verifies client and audit-only context never reaches the AI Studio wire request.
// TestProjectRequestOmitsNonModelVisibility 验证客户端和仅审计上下文永远不会进入 AI Studio wire 请求。
func TestProjectRequestOmitsNonModelVisibility(t *testing.T) {
	for _, visibility := range []vcp.Visibility{vcp.VisibilityClient, vcp.VisibilityAuditOnly} {
		t.Run(string(visibility), func(t *testing.T) {
			request := aiStudioTestRequest()
			hidden := aiStudioMessage("hidden", 2, vcp.AuthorityAssistant, "must not reach upstream")
			hidden.Visibility = visibility
			request.Context = append(request.Context, hidden)

			projected, errProject := ProjectRequest(request, aiStudioTarget(), aiStudioCapabilities(), "lineage-visibility", aiStudioNow())
			if errProject != nil {
				t.Fatalf("ProjectRequest() error = %v", errProject)
			}
			if len(projected.Upstream.Contents) != 1 || projected.Upstream.Contents[0].Parts[0].Text != "Hello" {
				t.Fatalf("contents = %#v", projected.Upstream.Contents)
			}
			entry := projected.Ledger.Entries[1]
			if entry.UpstreamPosition != -1 || entry.ProjectionMode != vcp.CapabilityOmitted || entry.RuleID != "google_aistudio.visibility.omitted.v1" {
				t.Fatalf("ledger entry = %#v", entry)
			}
		})
	}
}

// TestProjectRequestRejectsUnresolvedProviderState verifies AI Studio cannot receive opaque Router state as a fabricated provider field.
// TestProjectRequestRejectsUnresolvedProviderState 验证 AI Studio 不会把不透明 Router 状态作为伪造 Provider 字段接收。
func TestProjectRequestRejectsUnresolvedProviderState(t *testing.T) {
	request := aiStudioTestRequest()
	request.Context[0].ProviderStateRef = "sealed-state"

	if _, errProject := ProjectRequest(request, aiStudioTarget(), aiStudioCapabilities(), "lineage-provider-state", aiStudioNow()); !errors.Is(errProject, ErrUnsupportedContext) {
		t.Fatalf("ProjectRequest() error = %v, want ErrUnsupportedContext", errProject)
	}
}

// aiStudioInstruction creates one valid VCP instruction context fixture.
// aiStudioInstruction 创建一个有效 VCP 指令上下文夹具。
func aiStudioInstruction(itemID string, sequence uint64, authority vcp.Authority, placement vcp.Placement, text string) vcp.ContextItem {
	return vcp.ContextItem{ItemID: itemID, Sequence: sequence, Kind: vcp.ContextInstruction, Authority: authority, Actor: vcp.ActorApplication, Placement: placement, Activation: vcp.Activation{Mode: vcp.ActivationRequestStart}, Visibility: vcp.VisibilityModel, Content: []vcp.ContentBlock{{Type: vcp.ContentText, Text: text}}, Instruction: &vcp.InstructionItem{}}
}

// aiStudioMessage creates one valid VCP user or assistant message context fixture.
// aiStudioMessage 创建一个有效 VCP 用户或助手消息上下文夹具。
func aiStudioMessage(itemID string, sequence uint64, authority vcp.Authority, text string) vcp.ContextItem {
	actor := vcp.ActorEndUser
	if authority == vcp.AuthorityAssistant {
		actor = vcp.ActorPrimaryAssistant
	}
	return vcp.ContextItem{ItemID: itemID, Sequence: sequence, Kind: vcp.ContextMessage, Authority: authority, Actor: actor, Placement: vcp.PlacementTranscript, Activation: vcp.Activation{Mode: vcp.ActivationRequestStart}, Visibility: vcp.VisibilityModel, Content: []vcp.ContentBlock{{Type: vcp.ContentText, Text: text}}, Message: &vcp.MessageItem{}}
}

// aiStudioToolCall creates one completed VCP tool-call context fixture.
// aiStudioToolCall 创建一个已完成 VCP 工具调用上下文夹具。
func aiStudioToolCall(itemID string, sequence uint64, callID string, upstreamID string, namespace string, name string, arguments string) vcp.ContextItem {
	return vcp.ContextItem{ItemID: itemID, Sequence: sequence, Kind: vcp.ContextToolCall, Authority: vcp.AuthorityAssistant, Actor: vcp.ActorPrimaryAssistant, Placement: vcp.PlacementTranscript, Activation: vcp.Activation{Mode: vcp.ActivationRequestStart}, Visibility: vcp.VisibilityModel, ToolCall: &vcp.ToolCallItem{ToolCallID: callID, UpstreamID: upstreamID, Namespace: namespace, Name: name, Arguments: arguments, Status: vcp.ToolCallCompleted}}
}

// aiStudioToolResult creates one VCP tool-result context fixture tied to an earlier tool call.
// aiStudioToolResult 创建一个关联到更早工具调用的 VCP 工具结果上下文夹具。
func aiStudioToolResult(itemID string, sequence uint64, callID string, text string) vcp.ContextItem {
	return vcp.ContextItem{ItemID: itemID, Sequence: sequence, Kind: vcp.ContextToolResult, Authority: vcp.AuthorityTool, Actor: vcp.ActorTool, Placement: vcp.PlacementTranscript, Activation: vcp.Activation{Mode: vcp.ActivationRequestStart}, Visibility: vcp.VisibilityModel, Content: []vcp.ContentBlock{{Type: vcp.ContentText, Text: text}}, ToolResult: &vcp.ToolResultItem{ToolCallID: callID}}
}

// aiStudioContainsSummary reports whether a stable conversion code exists in a report.
// aiStudioContainsSummary 报告一个稳定转换代码是否存在于报告中。
func aiStudioContainsSummary(codes []string, target string) bool {
	for _, code := range codes {
		if code == target {
			return true
		}
	}
	return false
}
