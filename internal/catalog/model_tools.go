package catalog

import (
	"strings"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// StandardModelToolCapability describes one provider-native implementation of a closed Vulcan tool semantic.
// StandardModelToolCapability 描述一个封闭 Vulcan 工具语义的供应商原生实现。
type StandardModelToolCapability struct {
	// Kind identifies the stable Vulcan standard tool.
	// Kind 标识稳定的 Vulcan 标准工具。
	Kind vcp.StandardModelToolKind `json:"kind"`
	// Native reports verified native support in this exact execution profile.
	// Native 报告此精确执行规格中经过验证的原生支持。
	Native bool `json:"native"`
	// Requires lists other standard tools that must be enabled together.
	// Requires 列出必须同时启用的其他标准工具。
	Requires []vcp.StandardModelToolKind `json:"requires,omitempty"`
	// RequiresReasoning reports whether the provider requires reasoning mode.
	// RequiresReasoning 报告供应商是否要求思考模式。
	RequiresReasoning bool `json:"requires_reasoning,omitempty"`
	// RequiresStreaming reports whether the provider requires streaming delivery.
	// RequiresStreaming 报告供应商是否要求流式交付。
	RequiresStreaming bool `json:"requires_streaming,omitempty"`
	// AllowsCallerTools reports whether caller-authored tools may coexist.
	// AllowsCallerTools 报告调用方编写的工具是否可以共存。
	AllowsCallerTools bool `json:"allows_caller_tools"`
}

// ModelExtraToolCapability describes one profile-scoped non-standard provider or model tool.
// ModelExtraToolCapability 描述一个规格作用域的非标准供应商或模型工具。
type ModelExtraToolCapability struct {
	// ID is the stable profile-scoped public identifier.
	// ID 是稳定的规格作用域公开标识。
	ID string `json:"id"`
	// DisplayName is the provider-approved default English label.
	// DisplayName 是供应商认可的默认英文标签。
	DisplayName string `json:"display_name"`
	// Description explains the model-visible behavior without exposing provider wire details.
	// Description 说明模型可见行为且不暴露供应商 Wire 细节。
	Description string `json:"description"`
	// InputModalities lists accepted semantic input kinds.
	// InputModalities 列出接受的语义输入类型。
	InputModalities []string `json:"input_modalities,omitempty"`
	// OutputModalities lists produced semantic output kinds.
	// OutputModalities 列出生成的语义输出类型。
	OutputModalities []string `json:"output_modalities,omitempty"`
	// RequiresStandard lists required Vulcan standard tools.
	// RequiresStandard 列出必需的 Vulcan 标准工具。
	RequiresStandard []vcp.StandardModelToolKind `json:"requires_standard,omitempty"`
	// RequiresExtra lists required extra tools from the same profile.
	// RequiresExtra 列出同一规格中必需的额外工具。
	RequiresExtra []string `json:"requires_extra,omitempty"`
	// RequiresReasoning reports whether the provider requires reasoning mode.
	// RequiresReasoning 报告供应商是否要求思考模式。
	RequiresReasoning bool `json:"requires_reasoning,omitempty"`
	// RequiresStreaming reports whether the provider requires streaming delivery.
	// RequiresStreaming 报告供应商是否要求流式交付。
	RequiresStreaming bool `json:"requires_streaming,omitempty"`
	// AllowsCallerTools reports whether caller-authored tools may coexist.
	// AllowsCallerTools 报告调用方编写的工具是否可以共存。
	AllowsCallerTools bool `json:"allows_caller_tools"`
}

// validateModelToolCapabilities verifies static standard and extra-tool evidence for one exact profile.
// validateModelToolCapabilities 校验一个精确规格的静态标准工具和额外工具证据。
func validateModelToolCapabilities(standard []StandardModelToolCapability, extra []ModelExtraToolCapability) error {
	// standardByKind supports dependency validation without inferring missing tools.
	// standardByKind 支持依赖校验且不推断缺失工具。
	standardByKind := make(map[vcp.StandardModelToolKind]struct{}, len(standard))
	for index, capability := range standard {
		if !capability.Kind.Valid() || !capability.Native {
			return invalid("standard model tool %d must identify one verified native implementation", index)
		}
		if _, exists := standardByKind[capability.Kind]; exists {
			return invalid("standard model tool %q is duplicated", capability.Kind)
		}
		standardByKind[capability.Kind] = struct{}{}
		// seenRequirements rejects duplicated or self-referencing dependencies.
		// seenRequirements 拒绝重复或自引用依赖。
		seenRequirements := make(map[vcp.StandardModelToolKind]struct{}, len(capability.Requires))
		for _, requirement := range capability.Requires {
			if !requirement.Valid() || requirement == capability.Kind {
				return invalid("standard model tool %q has invalid dependency %q", capability.Kind, requirement)
			}
			if _, exists := seenRequirements[requirement]; exists {
				return invalid("standard model tool %q duplicates dependency %q", capability.Kind, requirement)
			}
			seenRequirements[requirement] = struct{}{}
		}
	}
	for _, capability := range standard {
		for _, requirement := range capability.Requires {
			if _, exists := standardByKind[requirement]; !exists {
				return invalid("standard model tool %q requires unpublished tool %q", capability.Kind, requirement)
			}
		}
	}
	// extraByID validates dependencies against the exact same profile.
	// extraByID 针对同一精确规格校验依赖。
	extraByID := make(map[string]struct{}, len(extra))
	for index, capability := range extra {
		if !vcp.ValidModelToolID(capability.ID) || strings.TrimSpace(capability.DisplayName) == "" || strings.TrimSpace(capability.Description) == "" {
			return invalid("extra model tool %d requires a stable id, display name, and description", index)
		}
		if _, exists := extraByID[capability.ID]; exists {
			return invalid("extra model tool %q is duplicated", capability.ID)
		}
		extraByID[capability.ID] = struct{}{}
		if errInputs := validateModelToolModalities(capability.ID, "input", capability.InputModalities); errInputs != nil {
			return errInputs
		}
		if errOutputs := validateModelToolModalities(capability.ID, "output", capability.OutputModalities); errOutputs != nil {
			return errOutputs
		}
	}
	for _, capability := range extra {
		// seenStandard rejects duplicate standard dependencies.
		// seenStandard 拒绝重复的标准工具依赖。
		seenStandard := make(map[vcp.StandardModelToolKind]struct{}, len(capability.RequiresStandard))
		for _, requirement := range capability.RequiresStandard {
			if _, exists := standardByKind[requirement]; !exists {
				return invalid("extra model tool %q requires unpublished standard tool %q", capability.ID, requirement)
			}
			if _, exists := seenStandard[requirement]; exists {
				return invalid("extra model tool %q duplicates standard dependency %q", capability.ID, requirement)
			}
			seenStandard[requirement] = struct{}{}
		}
		// seenExtra rejects duplicate and self-referencing extra dependencies.
		// seenExtra 拒绝重复及自引用额外工具依赖。
		seenExtra := make(map[string]struct{}, len(capability.RequiresExtra))
		for _, requirement := range capability.RequiresExtra {
			if requirement == capability.ID {
				return invalid("extra model tool %q cannot require itself", capability.ID)
			}
			if _, exists := extraByID[requirement]; !exists {
				return invalid("extra model tool %q requires unpublished extra tool %q", capability.ID, requirement)
			}
			if _, exists := seenExtra[requirement]; exists {
				return invalid("extra model tool %q duplicates extra dependency %q", capability.ID, requirement)
			}
			seenExtra[requirement] = struct{}{}
		}
	}
	return nil
}

// validateModelToolModalities verifies one duplicate-free semantic modality list.
// validateModelToolModalities 校验一个无重复的语义模态列表。
func validateModelToolModalities(toolID string, direction string, values []string) error {
	// seen rejects ambiguous repeated modalities.
	// seen 拒绝有歧义的重复模态。
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) == "" || value != strings.TrimSpace(value) {
			return invalid("extra model tool %q has invalid %s modality %q", toolID, direction, value)
		}
		if _, exists := seen[value]; exists {
			return invalid("extra model tool %q duplicates %s modality %q", toolID, direction, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

// cloneStandardModelTools returns mutation-safe standard tool capability values.
// cloneStandardModelTools 返回防止外部修改的标准工具能力值。
func cloneStandardModelTools(values []StandardModelToolCapability) []StandardModelToolCapability {
	cloned := append([]StandardModelToolCapability(nil), values...)
	for index := range cloned {
		cloned[index].Requires = append([]vcp.StandardModelToolKind(nil), cloned[index].Requires...)
	}
	return cloned
}

// cloneExtraModelTools returns mutation-safe extra-tool capability values.
// cloneExtraModelTools 返回防止外部修改的额外工具能力值。
func cloneExtraModelTools(values []ModelExtraToolCapability) []ModelExtraToolCapability {
	cloned := append([]ModelExtraToolCapability(nil), values...)
	for index := range cloned {
		cloned[index].InputModalities = append([]string(nil), cloned[index].InputModalities...)
		cloned[index].OutputModalities = append([]string(nil), cloned[index].OutputModalities...)
		cloned[index].RequiresStandard = append([]vcp.StandardModelToolKind(nil), cloned[index].RequiresStandard...)
		cloned[index].RequiresExtra = append([]string(nil), cloned[index].RequiresExtra...)
	}
	return cloned
}

// SupportsNativeStandardTool reports verified provider-native support in one exact profile.
// SupportsNativeStandardTool 报告一个精确规格中经过验证的供应商原生支持。
func (c ModelCapabilities) SupportsNativeStandardTool(kind vcp.StandardModelToolKind) bool {
	capability, exists := c.StandardTool(kind)
	return exists && capability.Native
}

// StandardTool returns one exact profile-scoped standard tool when it is published.
// StandardTool 返回已发布的一个精确规格作用域标准工具。
func (c ModelCapabilities) StandardTool(kind vcp.StandardModelToolKind) (StandardModelToolCapability, bool) {
	for _, capability := range c.StandardTools {
		if capability.Kind == kind {
			return capability, true
		}
	}
	return StandardModelToolCapability{}, false
}

// ExtraTool returns one exact profile-scoped extra tool when it is published.
// ExtraTool 返回已发布的一个精确规格作用域额外工具。
func (c ModelCapabilities) ExtraTool(id string) (ModelExtraToolCapability, bool) {
	for _, capability := range c.ExtraTools {
		if capability.ID == id {
			return capability, true
		}
	}
	return ModelExtraToolCapability{}, false
}
