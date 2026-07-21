package provider

import (
	"encoding/json"
	"testing"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
	"github.com/tidwall/gjson"
)

// TestApplyRequestProjectionMapsCompositeReasoning verifies one canonical effort can control multiple upstream fields.
// TestApplyRequestProjectionMapsCompositeReasoning 验证一个规范强度可以控制多个上游字段。
func TestApplyRequestProjectionMapsCompositeReasoning(t *testing.T) {
	projection := catalog.RequestProjection{
		Reasoning: catalog.ReasoningRequestProjection{Effort: []catalog.ReasoningParameterRule{
			{Value: "none", Set: []catalog.PayloadParameter{{Path: "thinking.type", Value: json.RawMessage(`"disabled"`)}}, Delete: []string{"reasoning_effort"}},
			{Value: "high", Set: []catalog.PayloadParameter{{Path: "thinking.type", Value: json.RawMessage(`"enabled"`)}, {Path: "reasoning_effort", Value: json.RawMessage(`"high"`)}}},
		}},
	}
	projected, errProjection := ApplyRequestProjection([]byte(`{"model":"deepseek","reasoning_effort":"medium"}`), projection, vcp.ReasoningPolicy{Effort: "none"})
	if errProjection != nil {
		t.Fatalf("ApplyRequestProjection() error = %v", errProjection)
	}
	if got := gjson.GetBytes(projected, "thinking.type").String(); got != "disabled" {
		t.Fatalf("thinking.type = %q, want disabled", got)
	}
	if gjson.GetBytes(projected, "reasoning_effort").Exists() {
		t.Fatalf("reasoning_effort remained in projected body: %s", projected)
	}
}

// TestApplyRequestProjectionUsesDocumentedPrecedence verifies defaults, reasoning, overrides, and filters apply in order.
// TestApplyRequestProjectionUsesDocumentedPrecedence 验证默认值、推理、覆盖与过滤按文档顺序应用。
func TestApplyRequestProjectionUsesDocumentedPrecedence(t *testing.T) {
	projection := catalog.RequestProjection{
		Reasoning: catalog.ReasoningRequestProjection{Effort: []catalog.ReasoningParameterRule{{Value: "high", Set: []catalog.PayloadParameter{{Path: "reasoning_effort", Value: json.RawMessage(`"high"`)}}}}},
		Additional: catalog.AdditionalPayloadProjection{
			Default:  []catalog.PayloadParameter{{Path: "temperature", Value: json.RawMessage(`0.2`)}, {Path: "top_p", Value: json.RawMessage(`0.8`)}},
			Override: []catalog.PayloadParameter{{Path: "temperature", Value: json.RawMessage(`0.4`)}},
			Filter:   []string{"top_p"},
		},
	}
	projected, errProjection := ApplyRequestProjection([]byte(`{"model":"relay","temperature":0.1}`), projection, vcp.ReasoningPolicy{Effort: "high"})
	if errProjection != nil {
		t.Fatalf("ApplyRequestProjection() error = %v", errProjection)
	}
	if got := gjson.GetBytes(projected, "temperature").Float(); got != 0.4 {
		t.Fatalf("temperature = %v, want 0.4", got)
	}
	if gjson.GetBytes(projected, "top_p").Exists() || gjson.GetBytes(projected, "reasoning_effort").String() != "high" {
		t.Fatalf("projected body = %s", projected)
	}
}

// TestApplyRequestProjectionsLetsModelRulesOverrideProviderDefaults verifies normal inheritance and explicit model exceptions.
// TestApplyRequestProjectionsLetsModelRulesOverrideProviderDefaults 验证普通继承与显式模型例外。
func TestApplyRequestProjectionsLetsModelRulesOverrideProviderDefaults(t *testing.T) {
	providerProjection := catalog.AdditionalPayloadProjection{
		Default:  []catalog.PayloadParameter{{Path: "temperature", Value: json.RawMessage(`0.7`)}, {Path: "provider_options.route", Value: json.RawMessage(`"balanced"`)}},
		Override: []catalog.PayloadParameter{{Path: "top_p", Value: json.RawMessage(`0.9`)}},
		Filter:   []string{"unsupported_parameter"},
	}
	modelProjection := catalog.RequestProjection{Additional: catalog.AdditionalPayloadProjection{
		Override: []catalog.PayloadParameter{{Path: "provider_options.route", Value: json.RawMessage(`"fast"`)}},
	}}
	projected, errProjection := ApplyRequestProjections([]byte(`{"model":"relay","temperature":0.2,"unsupported_parameter":true}`), providerProjection, modelProjection, vcp.ReasoningPolicy{})
	if errProjection != nil {
		t.Fatalf("ApplyRequestProjections() error = %v", errProjection)
	}
	if got := gjson.GetBytes(projected, "temperature").Float(); got != 0.2 {
		t.Fatalf("temperature = %v, want caller value 0.2", got)
	}
	if got := gjson.GetBytes(projected, "provider_options.route").String(); got != "fast" {
		t.Fatalf("provider_options.route = %q, want model override fast", got)
	}
	if got := gjson.GetBytes(projected, "top_p").Float(); got != 0.9 {
		t.Fatalf("top_p = %v, want provider override 0.9", got)
	}
	if gjson.GetBytes(projected, "unsupported_parameter").Exists() {
		t.Fatalf("unsupported_parameter remained in projected body: %s", projected)
	}
}

// TestApplyRequestProjectionRejectsUnconfiguredEffort verifies unknown aliases are not silently guessed.
// TestApplyRequestProjectionRejectsUnconfiguredEffort 验证未知别名不会被静默猜测。
func TestApplyRequestProjectionRejectsUnconfiguredEffort(t *testing.T) {
	projection := catalog.RequestProjection{Reasoning: catalog.ReasoningRequestProjection{Effort: []catalog.ReasoningParameterRule{{Value: "high", Set: []catalog.PayloadParameter{{Path: "reasoning_effort", Value: json.RawMessage(`"high"`)}}}}}}
	if _, errProjection := ApplyRequestProjection([]byte(`{"model":"relay"}`), projection, vcp.ReasoningPolicy{Effort: "medium"}); errProjection == nil {
		t.Fatal("ApplyRequestProjection() accepted an unconfigured effort")
	}
}

// TestApplyRequestProjectionMapsExactSummaryMode verifies concise and detailed modes are not collapsed to auto.
// TestApplyRequestProjectionMapsExactSummaryMode 验证 concise 与 detailed 模式不会被折叠为 auto。
func TestApplyRequestProjectionMapsExactSummaryMode(t *testing.T) {
	projection := catalog.RequestProjection{Reasoning: catalog.ReasoningRequestProjection{Summary: []catalog.ReasoningParameterRule{{Value: "detailed", Set: []catalog.PayloadParameter{{Path: "reasoning.summary", Value: json.RawMessage(`"detailed"`)}}}}}}
	projected, errProjection := ApplyRequestProjection([]byte(`{"model":"relay"}`), projection, vcp.ReasoningPolicy{SummaryMode: "detailed"})
	if errProjection != nil {
		t.Fatalf("ApplyRequestProjection() error = %v", errProjection)
	}
	if got := gjson.GetBytes(projected, "reasoning.summary").String(); got != "detailed" {
		t.Fatalf("reasoning.summary = %q, want detailed", got)
	}
}
