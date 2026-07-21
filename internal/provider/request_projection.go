package provider

import (
	"encoding/json"
	"fmt"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// ApplyRequestProjection applies one validated offering-specific projection to an already typed outbound JSON body.
// ApplyRequestProjection 将一个已校验的产品专属投影应用到已经类型化的出站 JSON Body。
func ApplyRequestProjection(body []byte, projection catalog.RequestProjection, policy vcp.ReasoningPolicy) ([]byte, error) {
	return ApplyRequestProjections(body, catalog.AdditionalPayloadProjection{}, projection, policy)
}

// ApplyRequestProjections applies provider defaults first and model-specific rules second to preserve explicit inheritance.
// ApplyRequestProjections 先应用供应商默认规则，再应用模型专属规则，以保留显式继承关系。
func ApplyRequestProjections(body []byte, providerProjection catalog.AdditionalPayloadProjection, modelProjection catalog.RequestProjection, policy vcp.ReasoningPolicy) ([]byte, error) {
	if !json.Valid(body) || !gjson.ParseBytes(body).IsObject() {
		return nil, fmt.Errorf("%w: outbound request projection requires one JSON object", ErrExecutionBinding)
	}
	if errValidate := providerProjection.Validate(); errValidate != nil {
		return nil, fmt.Errorf("%w: provider additional parameters: %v", ErrExecutionBinding, errValidate)
	}
	if errValidate := modelProjection.Validate(); errValidate != nil {
		return nil, fmt.Errorf("%w: request projection: %v", ErrExecutionBinding, errValidate)
	}
	projected, errProvider := applyAdditionalPayloadProjection(append([]byte(nil), body...), providerProjection)
	if errProvider != nil {
		return nil, errProvider
	}
	var errApply error
	for _, parameter := range modelProjection.Additional.Default {
		if gjson.GetBytes(projected, parameter.Path).Exists() {
			continue
		}
		projected, errApply = sjson.SetRawBytes(projected, parameter.Path, parameter.Value)
		if errApply != nil {
			return nil, fmt.Errorf("%w: apply default parameter %q: %v", ErrExecutionBinding, parameter.Path, errApply)
		}
	}
	if policy.Effort != "" {
		projected, errApply = applyReasoningRule(projected, "effort", policy.Effort, modelProjection.Reasoning.Effort)
		if errApply != nil {
			return nil, errApply
		}
	}
	if summaryMode := policy.RequestedSummaryMode(); summaryMode != "" {
		projected, errApply = applyReasoningRule(projected, "summary", summaryMode, modelProjection.Reasoning.Summary)
		if errApply != nil {
			return nil, errApply
		}
	}
	for _, parameter := range modelProjection.Additional.Override {
		projected, errApply = sjson.SetRawBytes(projected, parameter.Path, parameter.Value)
		if errApply != nil {
			return nil, fmt.Errorf("%w: apply override parameter %q: %v", ErrExecutionBinding, parameter.Path, errApply)
		}
	}
	for _, path := range modelProjection.Additional.Filter {
		projected, errApply = sjson.DeleteBytes(projected, path)
		if errApply != nil {
			return nil, fmt.Errorf("%w: filter parameter %q: %v", ErrExecutionBinding, path, errApply)
		}
	}
	return projected, nil
}

// applyAdditionalPayloadProjection applies one validated default, override, and filter sequence.
// applyAdditionalPayloadProjection 应用一组已校验的默认、覆盖与过滤序列。
func applyAdditionalPayloadProjection(body []byte, projection catalog.AdditionalPayloadProjection) ([]byte, error) {
	projected := body
	for _, parameter := range projection.Default {
		if gjson.GetBytes(projected, parameter.Path).Exists() {
			continue
		}
		updated, errSet := sjson.SetRawBytes(projected, parameter.Path, parameter.Value)
		if errSet != nil {
			return nil, fmt.Errorf("%w: apply default parameter %q: %v", ErrExecutionBinding, parameter.Path, errSet)
		}
		projected = updated
	}
	for _, parameter := range projection.Override {
		updated, errSet := sjson.SetRawBytes(projected, parameter.Path, parameter.Value)
		if errSet != nil {
			return nil, fmt.Errorf("%w: apply override parameter %q: %v", ErrExecutionBinding, parameter.Path, errSet)
		}
		projected = updated
	}
	for _, path := range projection.Filter {
		updated, errDelete := sjson.DeleteBytes(projected, path)
		if errDelete != nil {
			return nil, fmt.Errorf("%w: filter parameter %q: %v", ErrExecutionBinding, path, errDelete)
		}
		projected = updated
	}
	return projected, nil
}

// applyReasoningRule applies the sole rule whose canonical value exactly matches the caller request.
// applyReasoningRule 应用规范值与调用方请求精确匹配的唯一规则。
func applyReasoningRule(body []byte, kind string, requested string, rules []catalog.ReasoningParameterRule) ([]byte, error) {
	for _, rule := range rules {
		if rule.Value != requested {
			continue
		}
		projected := append([]byte(nil), body...)
		for _, parameter := range rule.Set {
			updated, errSet := sjson.SetRawBytes(projected, parameter.Path, parameter.Value)
			if errSet != nil {
				return nil, fmt.Errorf("%w: apply reasoning %s %q path %q: %v", ErrExecutionBinding, kind, requested, parameter.Path, errSet)
			}
			projected = updated
		}
		for _, path := range rule.Delete {
			updated, errDelete := sjson.DeleteBytes(projected, path)
			if errDelete != nil {
				return nil, fmt.Errorf("%w: delete reasoning %s %q path %q: %v", ErrExecutionBinding, kind, requested, path, errDelete)
			}
			projected = updated
		}
		return projected, nil
	}
	return nil, fmt.Errorf("%w: reasoning %s %q has no configured upstream projection", ErrExecutionBinding, kind, requested)
}

// RequestProjectionIsEmpty reports whether an offering carries no runtime mutation rules.
// RequestProjectionIsEmpty 报告一个产品是否未携带任何运行时变更规则。
func RequestProjectionIsEmpty(projection catalog.RequestProjection) bool {
	return len(projection.Reasoning.Effort) == 0 && len(projection.Reasoning.Summary) == 0 && len(projection.Additional.Default) == 0 && len(projection.Additional.Override) == 0 && len(projection.Additional.Filter) == 0
}

// AdditionalPayloadProjectionIsEmpty reports whether provider-wide runtime mutation rules are absent.
// AdditionalPayloadProjectionIsEmpty 报告是否不存在供应商级运行时变更规则。
func AdditionalPayloadProjectionIsEmpty(projection catalog.AdditionalPayloadProjection) bool {
	return len(projection.Default) == 0 && len(projection.Override) == 0 && len(projection.Filter) == 0
}
