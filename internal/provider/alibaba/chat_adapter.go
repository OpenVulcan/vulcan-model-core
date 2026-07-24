// Portions of this adapter are copied and adapted from bailian-cli packages/commands/src/commands/text/chat.ts at commit 678f60b.
// 本适配器的部分逻辑复制并改编自 bailian-cli 固定提交 678f60b 中的 packages/commands/src/commands/text/chat.ts。
// The copied scope is the documented enable_thinking and thinking_budget behavior; credential and routing ownership remain native Vulcan design.
// 复制范围为文档化的 enable_thinking 与 thinking_budget 行为；凭据和路由所有权仍采用 Vulcan 原生设计。
package alibaba

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	chatprofile "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/chat"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

var (
	// ErrInvalidChatAdapter reports an incomplete Alibaba Chat request adaptation.
	// ErrInvalidChatAdapter 表示 Alibaba Chat 请求适配不完整。
	ErrInvalidChatAdapter = errors.New("invalid Alibaba Chat adapter")
)

const (
	// ReasoningProfileIDSuffix identifies Alibaba execution profiles whose provider-default mode is thinking enabled.
	// ReasoningProfileIDSuffix 标识供应商默认开启思考模式的 Alibaba 执行规格。
	ReasoningProfileIDSuffix = "_reasoning"
	// ReasoningEnabledParameterID identifies exact enable_thinking support in an Alibaba execution profile.
	// ReasoningEnabledParameterID 标识 Alibaba 执行规格对 enable_thinking 的精确支持。
	ReasoningEnabledParameterID = "reasoning_enabled"
	// ReasoningBudgetParameterID identifies an exact model-specific thinking_budget range.
	// ReasoningBudgetParameterID 标识模型专属的精确 thinking_budget 范围。
	ReasoningBudgetParameterID = "reasoning_budget_tokens"
)

// ChatAdapter maps canonical VCP reasoning intent to Alibaba's typed OpenAI-compatible extension.
// ChatAdapter 将规范 VCP 推理意图映射到 Alibaba 类型化 OpenAI 兼容扩展。
type ChatAdapter struct{}

// NewChatAdapter creates one stateless Alibaba Chat request adapter.
// NewChatAdapter 创建一个无状态的 Alibaba Chat 请求适配器。
func NewChatAdapter() *ChatAdapter {
	return &ChatAdapter{}
}

// Adapt applies Alibaba's exact thinking defaults and removes the incompatible generic reasoning_effort carrier.
// Adapt 应用 Alibaba 精确的思考默认值，并移除不兼容的通用 reasoning_effort 载体。
func (a *ChatAdapter) Adapt(_ context.Context, execution provider.ExecutionRequest, request *chatprofile.Request) ([]transport.Header, error) {
	if a == nil || request == nil {
		return nil, ErrInvalidChatAdapter
	}
	nativeSearchCount := 0
	structuredToolCount := 0
	for _, tool := range execution.Request.Tools {
		if tool.Kind == vcp.ToolNativeWebSearch {
			nativeSearchCount++
		} else if tool.Kind == vcp.ToolFunction || tool.Kind == vcp.ToolCustom {
			structuredToolCount++
		}
	}
	nativeSearchSupported := containsAlibabaHostedTool(execution.Binding.Target.ModelCapabilities.HostedTools, vcp.ToolNativeWebSearch) ||
		containsAlibabaStandardTool(execution.Binding.Target.ModelCapabilities.StandardTools, vcp.StandardModelToolWebSearch)
	if nativeSearchCount > 1 || nativeSearchCount == 1 && !nativeSearchSupported {
		return nil, ErrInvalidChatAdapter
	}
	if nativeSearchCount == 1 {
		if structuredToolCount > 0 {
			return nil, fmt.Errorf("%w: Alibaba native web search and function calling are mutually exclusive", ErrInvalidChatAdapter)
		}
		request.EnableSearch = boolPointer(true)
	}
	if request.Audio != nil && (!containsAlibabaModality(execution.Binding.Target.ModelCapabilities.OutputModalities, "audio") || request.Audio.Format != "wav") {
		return nil, ErrInvalidChatAdapter
	}
	if errReasoning := applyAlibabaReasoning(execution, request); errReasoning != nil {
		return nil, errReasoning
	}
	request.ToolStream = nil
	if request.Stream && len(request.Tools) > 0 && supportsAlibabaChatToolStream(execution.Binding.Target.UpstreamModelID) {
		request.ToolStream = boolPointer(true)
	}
	request.VLHighResolutionImages = nil
	if hasAlibabaVisualInput(execution) && requiresAlibabaHighResolutionVision(execution.Binding.Target.UpstreamModelID) {
		request.VLHighResolutionImages = boolPointer(true)
	}
	// headers contains only the OSS resolution signal required by an exact provider-object materialization.
	// headers 仅包含精确 Provider Object 物化所需的 OSS 解析信号。
	headers := []transport.Header(nil)
	for _, input := range execution.MaterializedInputs {
		if input.Mode == catalog.MaterializationProviderObjectURI {
			headers = append(headers, transport.Header{Name: "X-DashScope-OssResourceResolve", Value: "enable"})
			break
		}
	}
	return headers, nil
}

// containsAlibabaStandardTool reports whether one exact Chat profile publishes a native standard model tool.
// containsAlibabaStandardTool 报告一个精确 Chat 规格是否发布原生标准模型工具。
func containsAlibabaStandardTool(values []catalog.StandardModelToolCapability, kind vcp.StandardModelToolKind) bool {
	for _, value := range values {
		if value.Kind == kind && value.Native {
			return true
		}
	}
	return false
}

// supportsAlibabaChatToolStream reports whether exact reviewed Alibaba Chat evidence permits incremental tool arguments for one model.
// supportsAlibabaChatToolStream 报告精确审核的 Alibaba Chat 证据是否允许一个模型使用工具参数增量流。
func supportsAlibabaChatToolStream(modelID string) bool {
	switch modelID {
	case "qwen3.7-max", "qwen3.7-plus", "qwen3.6-plus", "qwen3.6-flash", "qwen3.5-plus",
		"glm-5.2", "glm-5.1", "glm-5", "glm-4.7":
		return true
	default:
		return false
	}
}

// requiresAlibabaHighResolutionVision reports whether Qwen Code's reviewed DashScope adapter enables the exact visual extension for one model.
// requiresAlibabaHighResolutionVision 报告已审核的 Qwen Code DashScope 适配器是否为一个模型启用精确视觉扩展。
func requiresAlibabaHighResolutionVision(modelID string) bool {
	switch modelID {
	case "qwen3.5-plus", "qwen3.6-plus", "qwen3.7-plus":
		return true
	default:
		return false
	}
}

// hasAlibabaVisualInput reports whether the accepted input plan materialized an image or video for this request.
// hasAlibabaVisualInput 报告已接受的输入计划是否为本次请求物化了图片或视频。
func hasAlibabaVisualInput(execution provider.ExecutionRequest) bool {
	for _, input := range execution.MaterializedInputs {
		if input.Kind == vcp.MediaImage || input.Kind == vcp.MediaVideo {
			return true
		}
	}
	return false
}

// applyAlibabaReasoning maps only profile-evidenced switches and model-specific budget ranges.
// applyAlibabaReasoning 仅映射规格证实的开关与模型专属预算范围。
func applyAlibabaReasoning(execution provider.ExecutionRequest, request *chatprofile.Request) error {
	if errEffort := rejectAlibabaReasoningEffort(execution, request); errEffort != nil {
		return errEffort
	}
	policy := execution.Request.ReasoningPolicy
	_, switchSupported := alibabaParameter(execution.Binding.Target.ModelCapabilities.Parameters, ReasoningEnabledParameterID)
	budgetDescriptor, budgetSupported := alibabaParameter(execution.Binding.Target.ModelCapabilities.Parameters, ReasoningBudgetParameterID)
	// explicitlyDisabled and explicitlyEnabled preserve the canonical on/off request independently from provider defaults.
	// explicitlyDisabled 与 explicitlyEnabled 独立于供应商默认值保留规范开关请求。
	explicitlyDisabled := policy.Enabled != nil && !*policy.Enabled
	explicitlyEnabled := policy.Enabled != nil && *policy.Enabled || policy.BudgetTokens != nil
	if request.Audio != nil {
		if explicitlyEnabled {
			return fmt.Errorf("%w: Alibaba conversational audio cannot enable reasoning", ErrInvalidChatAdapter)
		}
		request.EnableThinking = boolPointer(false)
		request.ThinkingBudget = nil
		request.ReasoningEffort = ""
		return nil
	}
	if explicitlyDisabled {
		if callableAlibabaReasoning(execution.Binding.Target.ModelCapabilities.Reasoning) && !switchSupported {
			return fmt.Errorf("%w: selected Alibaba profile cannot disable fixed reasoning", ErrInvalidChatAdapter)
		}
		request.EnableThinking = nil
		if switchSupported {
			request.EnableThinking = boolPointer(false)
		}
		request.ThinkingBudget = nil
		request.ReasoningEffort = ""
		return nil
	}
	profileReasoning := callableAlibabaReasoning(execution.Binding.Target.ModelCapabilities.Reasoning)
	if explicitlyEnabled && !profileReasoning {
		return fmt.Errorf("%w: selected Alibaba profile does not support reasoning", ErrInvalidChatAdapter)
	}
	request.EnableThinking = nil
	if switchSupported {
		// Alibaba switchable ordinary profiles must disable server-default thinking; reasoning profiles enable it.
		// Alibaba 可切换普通规格必须关闭服务端默认思考；推理规格则开启。
		request.EnableThinking = boolPointer(profileReasoning)
	}
	request.ThinkingBudget = nil
	if policy.BudgetTokens != nil {
		if !profileReasoning {
			return fmt.Errorf("%w: reasoning budget requires a reasoning profile", ErrInvalidChatAdapter)
		}
		if !budgetSupported {
			return fmt.Errorf("%w: selected Alibaba profile has no evidenced thinking_budget range", ErrInvalidChatAdapter)
		}
		if errBudget := validateAlibabaReasoningBudget(*policy.BudgetTokens, budgetDescriptor); errBudget != nil {
			return errBudget
		}
		budget := *policy.BudgetTokens
		request.ThinkingBudget = &budget
	} else if profileReasoning && execution.Binding.Target.TokenRecommendations.ReasoningTokens.Known {
		if !budgetSupported {
			return fmt.Errorf("%w: Alibaba reasoning recommendation has no evidenced thinking_budget range", ErrInvalidChatAdapter)
		}
		budget := execution.Binding.Target.TokenRecommendations.ReasoningTokens.Value
		if errBudget := validateAlibabaReasoningBudget(budget, budgetDescriptor); errBudget != nil {
			return errBudget
		}
		request.ThinkingBudget = &budget
	}
	request.ReasoningEffort = ""
	return nil
}

// rejectAlibabaReasoningEffort prevents an unevidenced effort label from collapsing into Alibaba's independent switch and token budget.
// rejectAlibabaReasoningEffort 防止未经证实的强度标签折叠为 Alibaba 相互独立的开关与 Token 预算。
func rejectAlibabaReasoningEffort(execution provider.ExecutionRequest, request *chatprofile.Request) error {
	canonical := strings.TrimSpace(execution.Request.ReasoningPolicy.Effort)
	projected := strings.TrimSpace(request.ReasoningEffort)
	if canonical != "" && projected != "" && canonical != projected {
		return fmt.Errorf("%w: canonical and projected reasoning efforts differ", ErrInvalidChatAdapter)
	}
	if canonical != "" || projected != "" {
		return fmt.Errorf("%w: Alibaba Chat accepts reasoning enabled and budget_tokens, not reasoning effort", ErrInvalidChatAdapter)
	}
	return nil
}

// alibabaParameter returns one exact closed parameter descriptor from the selected profile.
// alibabaParameter 从所选规格返回一个精确的封闭参数描述符。
func alibabaParameter(parameters []catalog.ParameterDescriptor, parameterID string) (catalog.ParameterDescriptor, bool) {
	for _, parameter := range parameters {
		if parameter.ID == parameterID {
			return parameter, true
		}
	}
	return catalog.ParameterDescriptor{}, false
}

// validateAlibabaReasoningBudget enforces the complete inclusive predictConfig range before network traffic.
// validateAlibabaReasoningBudget 在网络请求前强制执行完整且包含端点的 predictConfig 范围。
func validateAlibabaReasoningBudget(budget int64, descriptor catalog.ParameterDescriptor) error {
	if descriptor.Kind != catalog.ParameterInteger || descriptor.IntegerRange == nil || descriptor.IntegerRange.Minimum == nil || descriptor.IntegerRange.Maximum == nil {
		return fmt.Errorf("%w: Alibaba thinking_budget descriptor is incomplete", ErrInvalidChatAdapter)
	}
	if budget < *descriptor.IntegerRange.Minimum || budget > *descriptor.IntegerRange.Maximum {
		return fmt.Errorf("%w: Alibaba thinking_budget %d is outside %d..%d", ErrInvalidChatAdapter, budget, *descriptor.IntegerRange.Minimum, *descriptor.IntegerRange.Maximum)
	}
	return nil
}

// callableAlibabaReasoning reports whether one exact selected profile can accept an explicit reasoning request.
// callableAlibabaReasoning 报告一个精确选定规格是否可以接受显式推理请求。
func callableAlibabaReasoning(level catalog.CapabilityLevel) bool {
	return level == catalog.CapabilityNative || level == catalog.CapabilityEmulated || level == catalog.CapabilityConditional
}

// containsAlibabaHostedTool reports exact target-owned hosted-tool membership.
// containsAlibabaHostedTool 报告精确的 Target 所有托管工具成员关系。
func containsAlibabaHostedTool(values []vcp.ToolKind, target vcp.ToolKind) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// containsAlibabaModality reports exact target-owned output-modality membership.
// containsAlibabaModality 报告精确的 Target 所有输出模态成员关系。
func containsAlibabaModality(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// boolPointer returns an independently owned Boolean pointer for an optional wire field.
// boolPointer 为可选 wire 字段返回独立拥有的布尔指针。
func boolPointer(value bool) *bool {
	return &value
}
