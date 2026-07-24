package alibaba

import (
	"context"
	"errors"
	"testing"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	chatprofile "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/chat"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestChatAdapterAppliesAlibabaThinkingContract verifies every documented streaming and thinking branch.
// TestChatAdapterAppliesAlibabaThinkingContract 验证每个文档化的流式与思考分支。
func TestChatAdapterAppliesAlibabaThinkingContract(t *testing.T) {
	// reasoningBudget is the catalog-owned default used only for an explicit enabled reasoning request.
	// reasoningBudget 是仅用于明确启用推理请求的目录默认预算。
	reasoningBudget := catalog.OptionalTokenLimit{Known: true, Value: 8192}
	minimumBudget, maximumBudget := int64(1), int64(32768)
	parameters := []catalog.ParameterDescriptor{
		{ID: ReasoningEnabledParameterID, Kind: catalog.ParameterBoolean},
		{ID: ReasoningBudgetParameterID, Kind: catalog.ParameterInteger, IntegerRange: &catalog.IntegerRange{Minimum: &minimumBudget, Maximum: &maximumBudget}},
	}
	tests := []struct {
		name       string
		stream     bool
		profileID  string
		reasoning  catalog.CapabilityLevel
		wantSwitch *bool
		wantBudget int64
	}{
		{name: "non-stream default disables thinking", wantSwitch: boolPointer(false)},
		{name: "stream ordinary profile disables thinking", stream: true, wantSwitch: boolPointer(false)},
		{name: "reasoning profile enables thinking", stream: true, profileID: "profile_qwen" + ReasoningProfileIDSuffix, reasoning: catalog.CapabilityNative, wantSwitch: boolPointer(true), wantBudget: 8192},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := chatprofile.Request{Model: "qwen3.7-plus", Stream: test.stream}
			execution := provider.ExecutionRequest{Binding: transport.Binding{Target: resolve.Target{ExecutionProfileID: test.profileID, ModelCapabilities: catalog.ModelCapabilities{Reasoning: test.reasoning, Parameters: parameters}, TokenRecommendations: catalog.TokenRecommendations{ReasoningTokens: reasoningBudget}}}}
			if _, errAdapt := NewChatAdapter().Adapt(context.Background(), execution, &request); errAdapt != nil {
				t.Fatalf("Adapt() error = %v", errAdapt)
			}
			if request.ReasoningEffort != "" {
				t.Fatalf("reasoning_effort remained %q", request.ReasoningEffort)
			}
			if !equalOptionalBool(request.EnableThinking, test.wantSwitch) {
				t.Fatalf("enable_thinking = %#v, want %#v", request.EnableThinking, test.wantSwitch)
			}
			if test.wantBudget == 0 {
				if request.ThinkingBudget != nil {
					t.Fatalf("thinking_budget = %d, want omitted", *request.ThinkingBudget)
				}
			} else if request.ThinkingBudget == nil || *request.ThinkingBudget != test.wantBudget {
				t.Fatalf("thinking_budget = %#v, want %d", request.ThinkingBudget, test.wantBudget)
			}
		})
	}
}

// TestChatAdapterRejectsExplicitReasoningOnOrdinaryProfile verifies direct execution cannot bypass the selected catalog shape.
// TestChatAdapterRejectsExplicitReasoningOnOrdinaryProfile 验证直接执行不能绕过选定的目录形态。
func TestChatAdapterRejectsExplicitReasoningOnOrdinaryProfile(t *testing.T) {
	enabled := true
	request := chatprofile.Request{Model: "qwen3.7-plus", Stream: true}
	execution := provider.ExecutionRequest{Request: vcp.VulcanRequest{ReasoningPolicy: vcp.ReasoningPolicy{Enabled: &enabled}}, Binding: transport.Binding{Target: resolve.Target{ExecutionProfileID: "profile_qwen", ModelCapabilities: catalog.ModelCapabilities{Reasoning: catalog.CapabilityUnsupported}}}}
	if _, errAdapt := NewChatAdapter().Adapt(context.Background(), execution, &request); !errors.Is(errAdapt, ErrInvalidChatAdapter) {
		t.Fatalf("Adapt() error = %v, want ErrInvalidChatAdapter", errAdapt)
	}
}

// TestChatAdapterRejectsUnevidencedReasoningEffort verifies an arbitrary effort label never collapses into Alibaba's switch semantics.
// TestChatAdapterRejectsUnevidencedReasoningEffort 验证任意强度标签绝不会折叠为 Alibaba 开关语义。
func TestChatAdapterRejectsUnevidencedReasoningEffort(t *testing.T) {
	request := chatprofile.Request{Model: "qwen3.7-plus", ReasoningEffort: "high"}
	execution := provider.ExecutionRequest{Request: vcp.VulcanRequest{ReasoningPolicy: vcp.ReasoningPolicy{Effort: "high"}}, Binding: transport.Binding{Target: resolve.Target{ModelCapabilities: catalog.ModelCapabilities{Reasoning: catalog.CapabilityNative}}}}
	if _, errAdapt := NewChatAdapter().Adapt(context.Background(), execution, &request); !errors.Is(errAdapt, ErrInvalidChatAdapter) {
		t.Fatalf("Adapt() error = %v, want ErrInvalidChatAdapter", errAdapt)
	}
}

// TestChatAdapterMapsCanonicalReasoningSwitch verifies VCP enabled is emitted only through the exact Alibaba switch descriptor.
// TestChatAdapterMapsCanonicalReasoningSwitch 验证 VCP enabled 仅通过精确 Alibaba 开关描述符发出。
func TestChatAdapterMapsCanonicalReasoningSwitch(t *testing.T) {
	enabled := true
	disabled := false
	parameter := catalog.ParameterDescriptor{ID: ReasoningEnabledParameterID, Kind: catalog.ParameterBoolean}
	tests := []struct {
		name      string
		enabled   *bool
		reasoning catalog.CapabilityLevel
		want      bool
	}{
		{name: "enabled", enabled: &enabled, reasoning: catalog.CapabilityNative, want: true},
		{name: "disabled", enabled: &disabled, reasoning: catalog.CapabilityUnsupported, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			execution := provider.ExecutionRequest{Request: vcp.VulcanRequest{ReasoningPolicy: vcp.ReasoningPolicy{Enabled: test.enabled}}, Binding: transport.Binding{Target: resolve.Target{ModelCapabilities: catalog.ModelCapabilities{Reasoning: test.reasoning, Parameters: []catalog.ParameterDescriptor{parameter}}}}}
			request := chatprofile.Request{Model: "qwen3.7-plus"}
			if _, errAdapt := NewChatAdapter().Adapt(context.Background(), execution, &request); errAdapt != nil {
				t.Fatalf("Adapt() error = %v", errAdapt)
			}
			if request.EnableThinking == nil || *request.EnableThinking != test.want {
				t.Fatalf("enable_thinking = %#v, want %t", request.EnableThinking, test.want)
			}
		})
	}
}

// TestChatAdapterValidatesExplicitBudgetAgainstPredictConfig verifies context ceilings never substitute for the model parameter range.
// TestChatAdapterValidatesExplicitBudgetAgainstPredictConfig 验证上下文上限绝不替代模型参数范围。
func TestChatAdapterValidatesExplicitBudgetAgainstPredictConfig(t *testing.T) {
	minimumBudget, maximumBudget := int64(4000), int64(32768)
	validBudget := int64(4000)
	execution := provider.ExecutionRequest{
		Request: vcp.VulcanRequest{ReasoningPolicy: vcp.ReasoningPolicy{BudgetTokens: &validBudget}},
		Binding: transport.Binding{Target: resolve.Target{ModelCapabilities: catalog.ModelCapabilities{Reasoning: catalog.CapabilityNative, Parameters: []catalog.ParameterDescriptor{{ID: ReasoningBudgetParameterID, Kind: catalog.ParameterInteger, IntegerRange: &catalog.IntegerRange{Minimum: &minimumBudget, Maximum: &maximumBudget}}}}}},
	}
	request := chatprofile.Request{Model: "deepseek-v4-pro"}
	if _, errAdapt := NewChatAdapter().Adapt(context.Background(), execution, &request); errAdapt != nil || request.ThinkingBudget == nil || *request.ThinkingBudget != validBudget || request.EnableThinking != nil {
		t.Fatalf("Adapt() request = %#v, error = %v", request, errAdapt)
	}
	invalidBudget := int64(3999)
	execution.Request.ReasoningPolicy.BudgetTokens = &invalidBudget
	request = chatprofile.Request{Model: "deepseek-v4-pro"}
	if _, errAdapt := NewChatAdapter().Adapt(context.Background(), execution, &request); !errors.Is(errAdapt, ErrInvalidChatAdapter) {
		t.Fatalf("out-of-range Adapt() error = %v", errAdapt)
	}
	execution.Binding.Target.ModelCapabilities.Parameters = nil
	execution.Request.ReasoningPolicy.BudgetTokens = &validBudget
	if _, errAdapt := NewChatAdapter().Adapt(context.Background(), execution, &request); !errors.Is(errAdapt, ErrInvalidChatAdapter) {
		t.Fatalf("missing-range Adapt() error = %v", errAdapt)
	}
}

// TestChatAdapterMapsHostedSearchAndDisablesThinkingForAudio verifies Alibaba-only extensions remain target-authorized.
// TestChatAdapterMapsHostedSearchAndDisablesThinkingForAudio 验证阿里云专用扩展始终受 Target 授权约束。
func TestChatAdapterMapsHostedSearchAndDisablesThinkingForAudio(t *testing.T) {
	execution := provider.ExecutionRequest{
		Binding: transport.Binding{Target: resolve.Target{ModelCapabilities: catalog.ModelCapabilities{HostedTools: []vcp.ToolKind{vcp.ToolNativeWebSearch}, OutputModalities: []string{"text", "audio"}}}},
		Request: vcp.VulcanRequest{Tools: []vcp.ToolDefinition{{Kind: vcp.ToolNativeWebSearch, Name: "web_search"}}},
	}
	request := chatprofile.Request{Model: "qwen3.5-omni-plus", Stream: true, Audio: &chatprofile.OutputAudioConfiguration{Voice: "Tina", Format: "wav"}}
	if _, errAdapt := NewChatAdapter().Adapt(context.Background(), execution, &request); errAdapt != nil {
		t.Fatalf("Adapt() error = %v", errAdapt)
	}
	if request.EnableSearch == nil || !*request.EnableSearch || request.EnableThinking == nil || *request.EnableThinking {
		t.Fatalf("adapted request = %#v", request)
	}

	execution.Binding.Target.ModelCapabilities.HostedTools = nil
	if _, errAdapt := NewChatAdapter().Adapt(context.Background(), execution, &request); errAdapt == nil {
		t.Fatal("Adapt() accepted hosted search absent from the selected target")
	}
}

// TestChatAdapterRejectsHostedSearchWithFunctionCalling verifies Alibaba's documented feature exclusion is enforced before network traffic.
// TestChatAdapterRejectsHostedSearchWithFunctionCalling 验证 Alibaba 文档化的功能互斥在网络请求前得到强制执行。
func TestChatAdapterRejectsHostedSearchWithFunctionCalling(t *testing.T) {
	execution := provider.ExecutionRequest{
		Binding: transport.Binding{Target: resolve.Target{ModelCapabilities: catalog.ModelCapabilities{HostedTools: []vcp.ToolKind{vcp.ToolNativeWebSearch}}}},
		Request: vcp.VulcanRequest{Tools: []vcp.ToolDefinition{{Kind: vcp.ToolNativeWebSearch, Name: "web_search"}, {Kind: vcp.ToolFunction, Name: "lookup"}}},
	}
	request := chatprofile.Request{Model: "qwen3.5-omni-plus", Stream: true}
	if _, errAdapt := NewChatAdapter().Adapt(context.Background(), execution, &request); !errors.Is(errAdapt, ErrInvalidChatAdapter) {
		t.Fatalf("Adapt() error = %v, want ErrInvalidChatAdapter", errAdapt)
	}
}

// TestChatAdapterDoesNotImpersonateQwenCode verifies Token Plan Chat requests keep the Router's own transport identity.
// TestChatAdapterDoesNotImpersonateQwenCode 验证 Token Plan Chat 请求保持 Router 自身的传输身份。
func TestChatAdapterDoesNotImpersonateQwenCode(t *testing.T) {
	execution := provider.ExecutionRequest{Binding: transport.Binding{Target: resolve.Target{ProviderDefinitionID: "system_alibaba_token_plan_personal_cn"}}}
	request := chatprofile.Request{Model: "qwen3.7-plus", Stream: true}
	headers, errAdapt := NewChatAdapter().Adapt(context.Background(), execution, &request)
	if errAdapt != nil {
		t.Fatalf("Adapt() error = %v", errAdapt)
	}
	if len(headers) != 0 {
		t.Fatalf("unexpected Token Plan Chat identity headers = %#v", headers)
	}
}

// TestChatAdapterAddsOSSResolutionHeaderOnlyForProviderObjects verifies uploaded conversation media remains resolvable without changing direct requests.
// TestChatAdapterAddsOSSResolutionHeaderOnlyForProviderObjects 验证已上传会话媒体可被解析，同时不改变直接请求。
func TestChatAdapterAddsOSSResolutionHeaderOnlyForProviderObjects(t *testing.T) {
	request := chatprofile.Request{Model: "qwen3.5-omni-plus"}
	directExecution := provider.ExecutionRequest{MaterializedInputs: []resource.MaterializedInput{{InputID: "image", Mode: catalog.MaterializationDirectRemoteURL, RemoteURL: "https://media.example/image.png"}}}
	directHeaders, errDirect := NewChatAdapter().Adapt(context.Background(), directExecution, &request)
	if errDirect != nil || len(directHeaders) != 0 {
		t.Fatalf("direct Adapt() headers = %#v, error = %v", directHeaders, errDirect)
	}
	objectExecution := provider.ExecutionRequest{MaterializedInputs: []resource.MaterializedInput{{InputID: "image", Mode: catalog.MaterializationProviderObjectURI, ProviderHandle: "oss://temporary/image.png"}}}
	objectHeaders, errObject := NewChatAdapter().Adapt(context.Background(), objectExecution, &request)
	if errObject != nil || len(objectHeaders) != 1 || objectHeaders[0].Name != "X-DashScope-OssResourceResolve" || objectHeaders[0].Value != "enable" {
		t.Fatalf("object Adapt() headers = %#v, error = %v", objectHeaders, errObject)
	}
}

// TestChatAdapterAppliesExactToolStreamAndVisionExtensions verifies Alibaba-only wire fields require every documented precondition.
// TestChatAdapterAppliesExactToolStreamAndVisionExtensions 验证 Alibaba 专用 Wire 字段要求满足全部文档化前置条件。
func TestChatAdapterAppliesExactToolStreamAndVisionExtensions(t *testing.T) {
	request := chatprofile.Request{
		Model:  "qwen3.6-plus",
		Stream: true,
		Tools:  []chatprofile.Tool{{Type: "function", Function: chatprofile.FunctionDefinition{Name: "lookup"}}},
	}
	execution := provider.ExecutionRequest{
		Binding: transport.Binding{Target: resolve.Target{UpstreamModelID: "qwen3.6-plus"}},
		MaterializedInputs: []resource.MaterializedInput{{
			InputID: "video",
			Kind:    vcp.MediaVideo,
			Mode:    catalog.MaterializationDirectRemoteURL,
		}},
	}
	if _, errAdapt := NewChatAdapter().Adapt(context.Background(), execution, &request); errAdapt != nil {
		t.Fatalf("Adapt() error = %v", errAdapt)
	}
	if request.ToolStream == nil || !*request.ToolStream || request.VLHighResolutionImages == nil || !*request.VLHighResolutionImages {
		t.Fatalf("adapted request = %#v", request)
	}

	request.Stream = false
	request.Tools = nil
	execution.Binding.Target.UpstreamModelID = "kimi-k2.5"
	if _, errAdapt := NewChatAdapter().Adapt(context.Background(), execution, &request); errAdapt != nil {
		t.Fatalf("unsupported extension Adapt() error = %v", errAdapt)
	}
	if request.ToolStream != nil || request.VLHighResolutionImages != nil {
		t.Fatalf("unsupported model retained Alibaba extensions: %#v", request)
	}
}

// equalOptionalBool compares optional Boolean wire fields without treating nil as false.
// equalOptionalBool 比较可选布尔 wire 字段，且不会把 nil 当作 false。
func equalOptionalBool(left *bool, right *bool) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
