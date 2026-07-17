package vcp

import (
	"errors"
	"testing"
)

// TestVulcanRequestValidateRejectsNestedClosedEnums verifies nested request payloads cannot carry unregistered enum values.
// TestVulcanRequestValidateRejectsNestedClosedEnums 校验请求嵌套载荷不能携带未注册的枚举值。
func TestVulcanRequestValidateRejectsNestedClosedEnums(t *testing.T) {
	// cases isolate each nested closed-enum boundary so no unrelated validation rule can satisfy the assertion.
	// cases 隔离每个嵌套封闭枚举边界，避免其他无关校验规则满足断言。
	cases := []struct {
		// name identifies the nested enum boundary under validation.
		// name 标识待校验的嵌套枚举边界。
		name string
		// mutate replaces one otherwise valid nested value with an unregistered value.
		// mutate 将一个原本有效的嵌套值替换为未注册值。
		mutate func(*VulcanRequest)
	}{
		{
			name: "authority on tool call",
			mutate: func(request *VulcanRequest) {
				request.Context = []ContextItem{testNestedToolCallItem("item_tool", 1, "call_tool")}
				request.Context[0].Authority = Authority("unregistered_authority")
			},
		},
		{
			name: "delegated result kind",
			mutate: func(request *VulcanRequest) {
				request.Context = []ContextItem{testNestedDelegatedResultItem("item_delegated", 1)}
				request.Context[0].DelegatedResult.ResultKind = DelegatedResultKind("unregistered_result_kind")
			},
		},
		{
			name: "tool call status",
			mutate: func(request *VulcanRequest) {
				request.Context = []ContextItem{testNestedToolCallItem("item_tool", 1, "call_tool")}
				request.Context[0].ToolCall.Status = ToolCallStatus("unregistered_status")
			},
		},
		{
			name: "capability feature",
			mutate: func(request *VulcanRequest) {
				request.CapabilityPolicy.ExplicitDemands = []CapabilityDemand{{
					Feature:       CapabilityFeature("unregistered_feature"),
					Source:        "caller",
					Level:         DemandRequired,
					AcceptedModes: []CapabilityMode{CapabilityNative},
					OnUnavailable: "fail",
				}}
			},
		},
		{
			name: "accepted capability mode",
			mutate: func(request *VulcanRequest) {
				request.CapabilityPolicy.ExplicitDemands = []CapabilityDemand{{
					Feature:       FeatureReasoning,
					Source:        "caller",
					Level:         DemandRequired,
					AcceptedModes: []CapabilityMode{CapabilityMode("unregistered_mode")},
					OnUnavailable: "fail",
				}}
			},
		},
	}

	for _, testCase := range cases {
		// testCase captures the current nested enum scenario for parallel-safe subtest semantics.
		// testCase 捕获当前嵌套枚举场景，以获得并行安全的子测试语义。
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			// request starts valid so the nested mutation is the sole rejection reason.
			// request 初始有效，以确保嵌套变更是唯一拒绝原因。
			request := testTextRequest()
			testCase.mutate(&request)
			if errValidate := request.Validate(); !errors.Is(errValidate, ErrInvalidRequest) {
				t.Fatalf("Validate() error = %v, want ErrInvalidRequest", errValidate)
			}
		})
	}
}

// TestVulcanRequestValidateChecksRemoteCompactionContext verifies stateless compaction input receives full canonical context validation.
// TestVulcanRequestValidateChecksRemoteCompactionContext 校验无状态压缩输入会执行完整的规范上下文校验。
func TestVulcanRequestValidateChecksRemoteCompactionContext(t *testing.T) {
	// request retains valid primary context while only its remote compaction context is malformed.
	// request 保留有效的主上下文，仅让远程压缩上下文格式错误。
	request := testTextRequest()
	// invalidContext violates the canonical positive, globally increasing sequence invariant.
	// invalidContext 违反规范上下文的正数全局递增序列不变量。
	invalidContext := append([]ContextItem(nil), request.Context...)
	invalidContext[0].Sequence = 0
	request.RemoteCompaction = &RemoteCompactionRequest{Context: invalidContext}

	if errValidate := request.Validate(); !errors.Is(errValidate, ErrInvalidRequest) {
		t.Fatalf("Validate() error = %v, want ErrInvalidRequest from remote compaction context", errValidate)
	}
}

// TestVulcanRequestValidateToolResultRequiresPriorToolCall verifies tool results bind only to prior structured calls rather than arbitrary prior items.
// TestVulcanRequestValidateToolResultRequiresPriorToolCall 校验工具结果只能绑定先前结构化调用而不能绑定任意先前项目。
func TestVulcanRequestValidateToolResultRequiresPriorToolCall(t *testing.T) {
	t.Run("prior non-tool item rejected", func(t *testing.T) {
		// request uses a prior message whose item ID matches the requested call ID, proving item existence alone is insufficient.
		// request 使用项目 ID 与目标调用 ID 相同的先前消息，证明仅存在项目不足以建立工具关联。
		request := testTextRequest()
		request.Context[0].ItemID = "call_relation"
		request.Context = append(request.Context, testNestedToolResultItem("item_result", 2, "call_relation"))
		if errValidate := request.Validate(); !errors.Is(errValidate, ErrInvalidRequest) {
			t.Fatalf("Validate() error = %v, want ErrInvalidRequest", errValidate)
		}
	})

	t.Run("prior tool call accepted", func(t *testing.T) {
		// request binds the result to the exact stable ToolCallID of a preceding tool_call item.
		// request 将结果绑定到先前 tool_call 项目的确切稳定 ToolCallID。
		request := testTextRequest()
		request.Context = []ContextItem{
			testNestedToolCallItem("item_tool", 1, "call_relation"),
			testNestedToolResultItem("item_result", 2, "call_relation"),
		}
		if errValidate := request.Validate(); errValidate != nil {
			t.Fatalf("Validate() error = %v, want nil", errValidate)
		}
	})
}

// testNestedToolCallItem returns a valid canonical tool call for nested validation fixtures.
// testNestedToolCallItem 返回用于嵌套校验夹具的有效规范工具调用。
func testNestedToolCallItem(itemID string, sequence uint64, toolCallID string) ContextItem {
	return ContextItem{
		ItemID:    itemID,
		Sequence:  sequence,
		Kind:      ContextToolCall,
		Authority: AuthorityAssistant,
		Actor:     ActorPrimaryAssistant,
		Placement: PlacementTranscript,
		Activation: Activation{
			Mode: ActivationRequestStart,
		},
		Visibility: VisibilityModel,
		ToolCall: &ToolCallItem{
			ToolCallID: toolCallID,
			Name:       "lookup",
			Arguments:  `{}`,
			Status:     ToolCallPending,
		},
	}
}

// testNestedToolResultItem returns a valid canonical tool result targeting one stable call identifier.
// testNestedToolResultItem 返回绑定一个稳定调用标识的有效规范工具结果。
func testNestedToolResultItem(itemID string, sequence uint64, toolCallID string) ContextItem {
	return ContextItem{
		ItemID:    itemID,
		Sequence:  sequence,
		Kind:      ContextToolResult,
		Authority: AuthorityTool,
		Actor:     ActorTool,
		Placement: PlacementTranscript,
		Activation: Activation{
			Mode: ActivationRequestStart,
		},
		Visibility: VisibilityModel,
		Content:    []ContentBlock{{Type: ContentText, Text: "tool result"}},
		ToolResult: &ToolResultItem{
			ToolCallID: toolCallID,
		},
	}
}

// testNestedDelegatedResultItem returns a valid canonical delegated result for nested validation fixtures.
// testNestedDelegatedResultItem 返回用于嵌套校验夹具的有效规范委派结果。
func testNestedDelegatedResultItem(itemID string, sequence uint64) ContextItem {
	return ContextItem{
		ItemID:       itemID,
		Sequence:     sequence,
		Kind:         ContextDelegatedResult,
		Authority:    AuthorityNone,
		Actor:        ActorDelegatedAgent,
		Placement:    PlacementTranscript,
		Activation:   Activation{Mode: ActivationRequestStart},
		Visibility:   VisibilityModel,
		DelegationID: "delegation_one",
		Content:      []ContentBlock{{Type: ContentText, Text: "delegated result"}},
		DelegatedResult: &DelegatedResultItem{
			ResultKind: DelegatedReport,
		},
	}
}
