package management

import (
	"encoding/json"
	"fmt"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
)

// defaultReasoningEfforts lists the editable baseline shared by OpenAI-compatible custom protocols.
// defaultReasoningEfforts 列出 OpenAI 兼容自定义协议共享的可编辑默认强度。
var defaultReasoningEfforts = []string{"none", "minimal", "low", "medium", "high", "xhigh", "max"}

// defaultCustomDelivery returns the executable delivery modes guaranteed by every supported custom conversation protocol.
// defaultCustomDelivery 返回每个受支持自定义会话协议保证可执行的交付模式。
func defaultCustomDelivery(protocolProfileID string) (catalog.DeliveryCapabilities, error) {
	switch protocolProfileID {
	case "openai.chat", "openai.responses", "anthropic.messages":
		return catalog.DeliveryCapabilities{Synchronous: true, Streaming: true}, nil
	default:
		return catalog.DeliveryCapabilities{}, fmt.Errorf("custom delivery does not support protocol profile %q", protocolProfileID)
	}
}

// defaultCustomRequestProjection returns an executable editable baseline for one supported custom protocol.
// defaultCustomRequestProjection 为一个受支持的自定义协议返回可执行且可编辑的默认配置。
func defaultCustomRequestProjection(protocolProfileID string) (catalog.RequestProjection, error) {
	switch protocolProfileID {
	case "openai.chat":
		return catalog.RequestProjection{Reasoning: catalog.ReasoningRequestProjection{Effort: scalarEffortRules("reasoning_effort")}}, nil
	case "openai.responses":
		return catalog.RequestProjection{Reasoning: catalog.ReasoningRequestProjection{
			Effort: scalarEffortRules("reasoning.effort"),
			Summary: []catalog.ReasoningParameterRule{
				setRule("auto", "reasoning.summary", "auto"),
				setRule("concise", "reasoning.summary", "concise"),
				setRule("detailed", "reasoning.summary", "detailed"),
			},
		}}, nil
	case "anthropic.messages":
		return catalog.RequestProjection{Reasoning: catalog.ReasoningRequestProjection{Effort: anthropicEffortRules()}}, nil
	default:
		return catalog.RequestProjection{}, fmt.Errorf("custom request projection does not support protocol profile %q", protocolProfileID)
	}
}

// scalarEffortRules maps canonical effort values to one exact scalar upstream field.
// scalarEffortRules 将规范推理强度值映射到一个精确的上游标量字段。
func scalarEffortRules(path string) []catalog.ReasoningParameterRule {
	rules := make([]catalog.ReasoningParameterRule, 0, len(defaultReasoningEfforts))
	for _, effort := range defaultReasoningEfforts {
		rules = append(rules, setRule(effort, path, effort))
	}
	return rules
}

// anthropicEffortRules preserves the copied Anthropic legacy budget mapping as an editable custom-provider baseline.
// anthropicEffortRules 将已复制的 Anthropic 旧版预算映射保留为可编辑的自定义供应商默认配置。
func anthropicEffortRules() []catalog.ReasoningParameterRule {
	return []catalog.ReasoningParameterRule{
		{Value: "none", Set: []catalog.PayloadParameter{jsonParameter("thinking.type", "disabled")}, Delete: []string{"thinking.budget_tokens", "output_config.effort"}},
		{Value: "auto", Set: []catalog.PayloadParameter{jsonParameter("thinking.type", "enabled")}, Delete: []string{"thinking.budget_tokens", "output_config.effort"}},
		{Value: "minimal", Set: []catalog.PayloadParameter{jsonParameter("thinking.type", "enabled"), jsonParameter("thinking.budget_tokens", 512)}, Delete: []string{"output_config.effort"}},
		{Value: "low", Set: []catalog.PayloadParameter{jsonParameter("thinking.type", "enabled"), jsonParameter("thinking.budget_tokens", 1024)}, Delete: []string{"output_config.effort"}},
		{Value: "medium", Set: []catalog.PayloadParameter{jsonParameter("thinking.type", "enabled"), jsonParameter("thinking.budget_tokens", 8192)}, Delete: []string{"output_config.effort"}},
		{Value: "high", Set: []catalog.PayloadParameter{jsonParameter("thinking.type", "enabled"), jsonParameter("thinking.budget_tokens", 24576)}, Delete: []string{"output_config.effort"}},
		{Value: "xhigh", Set: []catalog.PayloadParameter{jsonParameter("thinking.type", "enabled"), jsonParameter("thinking.budget_tokens", 32768)}, Delete: []string{"output_config.effort"}},
		{Value: "max", Set: []catalog.PayloadParameter{jsonParameter("thinking.type", "enabled"), jsonParameter("thinking.budget_tokens", 128000)}, Delete: []string{"output_config.effort"}},
	}
}

// setRule creates one exact scalar reasoning assignment.
// setRule 创建一个精确的标量推理赋值规则。
func setRule(value string, path string, upstreamValue string) catalog.ReasoningParameterRule {
	return catalog.ReasoningParameterRule{Value: value, Set: []catalog.PayloadParameter{jsonParameter(path, upstreamValue)}}
}

// jsonParameter encodes one compile-time default value as valid JSON.
// jsonParameter 将一个编译期默认值编码为有效 JSON。
func jsonParameter(path string, value any) catalog.PayloadParameter {
	encoded, errEncode := json.Marshal(value)
	if errEncode != nil {
		panic(fmt.Sprintf("encode built-in request projection value: %v", errEncode))
	}
	return catalog.PayloadParameter{Path: path, Value: encoded}
}

// reasoningValues returns the exact configured canonical values without inferring unlisted aliases.
// reasoningValues 返回精确配置的规范值，且不推断未列出的别名。
func reasoningValues(rules []catalog.ReasoningParameterRule) []string {
	values := make([]string, 0, len(rules))
	for _, rule := range rules {
		values = append(values, rule.Value)
	}
	return values
}

// validateCustomProjectionForProtocol rejects dual OpenRouter shorthand and nested effort carriers after typed projection.
// validateCustomProjectionForProtocol 拒绝类型化投影后同时存在 OpenRouter 简写与嵌套强度载体。
func validateCustomProjectionForProtocol(protocolProfileID string, projection catalog.RequestProjection) error {
	for _, rule := range projection.Reasoning.Effort {
		switch protocolProfileID {
		case "openai.chat":
			if ruleSetsPath(rule, "reasoning.effort") && !ruleDeletesPath(rule, "reasoning_effort") {
				return fmt.Errorf("reasoning effort rule %q must delete reasoning_effort when it sets reasoning.effort for openai.chat", rule.Value)
			}
		case "openai.responses":
			if ruleSetsPath(rule, "reasoning_effort") && !ruleDeletesPath(rule, "reasoning.effort") {
				return fmt.Errorf("reasoning effort rule %q must delete reasoning.effort when it sets reasoning_effort for openai.responses", rule.Value)
			}
		}
	}
	return nil
}

// ruleSetsPath reports whether one reasoning rule assigns the exact path.
// ruleSetsPath 报告一个推理规则是否赋值精确路径。
func ruleSetsPath(rule catalog.ReasoningParameterRule, path string) bool {
	for _, parameter := range rule.Set {
		if parameter.Path == path {
			return true
		}
	}
	return false
}

// ruleDeletesPath reports whether one reasoning rule removes the exact path.
// ruleDeletesPath 报告一个推理规则是否删除精确路径。
func ruleDeletesPath(rule catalog.ReasoningParameterRule, path string) bool {
	for _, candidate := range rule.Delete {
		if candidate == path {
			return true
		}
	}
	return false
}
