package vcp

import (
	"fmt"
	"strings"
)

// ExecutionSelectionRequest asks the Router to choose one model profile inside one immutable provider instance boundary.
// ExecutionSelectionRequest 请求 Router 在一个不可变供应商实例边界内选择一个模型规格。
type ExecutionSelectionRequest struct {
	// ProtocolVersion must equal the sole supported VCP version.
	// ProtocolVersion 必须等于唯一受支持的 VCP 版本。
	ProtocolVersion string `json:"protocol_version"`
	// RequestID correlates selection without becoming provider state.
	// RequestID 关联选择过程且不会成为供应商状态。
	RequestID string `json:"request_id"`
	// ProviderInstanceID fixes the provider boundary and prevents cross-provider fallback.
	// ProviderInstanceID 固定供应商边界并阻止跨供应商降级。
	ProviderInstanceID string `json:"provider_instance_id"`
	// Operation identifies the required closed VCP operation.
	// Operation 标识所需的封闭 VCP 操作。
	Operation OperationKind `json:"operation"`
	// RequiredContextTokens is the minimum shared capacity for input, reasoning, and reserved output.
	// RequiredContextTokens 是输入、推理和预留输出共同所需的最小共享容量。
	RequiredContextTokens int64 `json:"required_context_tokens,omitempty"`
	// RequiredMaxOutputTokens is the minimum independently authoritative output ceiling.
	// RequiredMaxOutputTokens 是最小独立权威输出上限。
	RequiredMaxOutputTokens int64 `json:"required_max_output_tokens,omitempty"`
	// RequiredInputModalities lists every normalized input modality the profile must accept.
	// RequiredInputModalities 列出规格必须接受的全部规范化输入模态。
	RequiredInputModalities []string `json:"required_input_modalities,omitempty"`
	// RequiredOutputModalities lists every normalized output modality the profile must produce.
	// RequiredOutputModalities 列出规格必须生成的全部规范化输出模态。
	RequiredOutputModalities []string `json:"required_output_modalities,omitempty"`
	// RequiredCapabilities contains hard normalized capability identifiers.
	// RequiredCapabilities 包含硬性规范化能力标识。
	RequiredCapabilities []string `json:"required_capabilities,omitempty"`
	// PreferredCapabilities contains soft normalized capability identifiers used only for deterministic ranking.
	// PreferredCapabilities 包含仅用于确定性排序的软性规范化能力标识。
	PreferredCapabilities []string `json:"preferred_capabilities,omitempty"`
	// PreferredModelIDs ranks provider-scoped models in caller order without widening the provider boundary.
	// PreferredModelIDs 按调用方顺序排列供应商作用域模型且不扩大供应商边界。
	PreferredModelIDs []string `json:"preferred_model_ids,omitempty"`
	// RequiredRegion optionally constrains eligible endpoints to one provider-defined region.
	// RequiredRegion 可选地将合格入口限制到一个供应商定义区域。
	RequiredRegion string `json:"required_region,omitempty"`
}

// Validate verifies the provider-scoped selection contract and normalized unique lists.
// Validate 校验供应商作用域选择合同与规范化唯一列表。
func (r ExecutionSelectionRequest) Validate() error {
	if r.ProtocolVersion != ProtocolVersion || strings.TrimSpace(r.RequestID) == "" || strings.TrimSpace(r.ProviderInstanceID) == "" || !r.Operation.Valid() || r.RequiredContextTokens < 0 || r.RequiredMaxOutputTokens < 0 {
		return fmt.Errorf("%w: selection version, identity, provider instance, operation, and context requirement are invalid", ErrInvalidRequest)
	}
	if r.RequiredContextTokens > 0 && r.RequiredMaxOutputTokens > r.RequiredContextTokens {
		return fmt.Errorf("%w: required output ceiling cannot exceed the required shared context capacity", ErrInvalidRequest)
	}
	if errInputs := validateSelectionModalities("required input modality", r.RequiredInputModalities); errInputs != nil {
		return errInputs
	}
	if errOutputs := validateSelectionModalities("required output modality", r.RequiredOutputModalities); errOutputs != nil {
		return errOutputs
	}
	if errRequired := validateSelectionStrings("required capability", r.RequiredCapabilities); errRequired != nil {
		return errRequired
	}
	if errPreferred := validateSelectionStrings("preferred capability", r.PreferredCapabilities); errPreferred != nil {
		return errPreferred
	}
	if errModels := validateSelectionStrings("preferred model", r.PreferredModelIDs); errModels != nil {
		return errModels
	}
	if r.RequiredRegion != strings.TrimSpace(r.RequiredRegion) {
		return fmt.Errorf("%w: required region cannot contain surrounding whitespace", ErrInvalidRequest)
	}
	if (r.Operation == OperationSearchWeb || r.Operation == OperationWebExtract) && (r.RequiredContextTokens != 0 || r.RequiredMaxOutputTokens != 0 || len(r.RequiredInputModalities) != 0 || len(r.RequiredOutputModalities) != 0 || len(r.RequiredCapabilities) != 0 || len(r.PreferredCapabilities) != 0 || len(r.PreferredModelIDs) != 0) {
		return fmt.Errorf("%w: special service selection accepts only provider instance and region constraints", ErrInvalidRequest)
	}
	return nil
}

// validateSelectionModalities rejects unknown, padded, and duplicate modality identifiers.
// validateSelectionModalities 拒绝未知、带首尾空格及重复的模态标识。
func validateSelectionModalities(label string, values []string) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		switch value {
		case "text", "image", "audio", "video", "file":
		default:
			return fmt.Errorf("%w: %s %q is unsupported", ErrInvalidRequest, label, value)
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("%w: duplicate %s %q", ErrInvalidRequest, label, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

// ExecutionSelection contains one safe exact model-or-service target without endpoint or credential identity.
// ExecutionSelection 包含一个不含入口或凭据身份的安全精确模型或服务 Target。
type ExecutionSelection struct {
	// RequestID echoes the selection request identity.
	// RequestID 回显选择请求身份。
	RequestID string `json:"request_id"`
	// Target is the exact closed model-or-service selection to submit with a later execution.
	// Target 是后续执行应提交的精确封闭模型或服务选择。
	Target TargetSelection `json:"target"`
	// Operation is the selected profile operation.
	// Operation 是所选规格的操作。
	Operation OperationKind `json:"operation"`
	// EffectiveContextTokens is present only when the selected account ceiling is authoritative.
	// EffectiveContextTokens 仅在所选账号上限具有权威性时存在。
	EffectiveContextTokens *int64 `json:"effective_context_tokens,omitempty"`
	// CapabilityRevision freezes the selected profile evidence revision for diagnostics.
	// CapabilityRevision 为诊断冻结所选规格证据修订。
	CapabilityRevision uint64 `json:"capability_revision"`
	// CatalogRevision identifies the atomic catalog used by selection.
	// CatalogRevision 标识选择使用的原子目录。
	CatalogRevision uint64 `json:"catalog_revision"`
}

// validateSelectionStrings rejects empty, padded, and duplicate selection identifiers.
// validateSelectionStrings 拒绝空白、带首尾空格及重复的选择标识。
func validateSelectionStrings(label string, values []string) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) == "" || value != strings.TrimSpace(value) {
			return fmt.Errorf("%w: %s values must be normalized", ErrInvalidRequest, label)
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("%w: duplicate %s %q", ErrInvalidRequest, label, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}
