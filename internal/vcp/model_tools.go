package vcp

import (
	"errors"
	"fmt"
	"strings"
)

// ModelToolErrorCode identifies one stable public model-tool validation or execution failure.
// ModelToolErrorCode 标识一种稳定公开的模型工具校验或执行失败。
type ModelToolErrorCode string

const (
	// ModelToolNotSupported reports absent native profile support.
	// ModelToolNotSupported 表示原生规格不支持。
	ModelToolNotSupported ModelToolErrorCode = "model_tool_not_supported"
	// ModelToolNotReady reports supported capability that is not executable with current runtime state.
	// ModelToolNotReady 表示已支持能力在当前运行时状态下不可执行。
	ModelToolNotReady ModelToolErrorCode = "model_tool_not_ready"
	// ModelToolModeNotSupported reports an execution mode unavailable to the selected profile.
	// ModelToolModeNotSupported 表示所选规格不支持指定执行方式。
	ModelToolModeNotSupported ModelToolErrorCode = "model_tool_mode_not_supported"
	// ModelToolDependencyMissing reports an unsatisfied standard or extra tool dependency.
	// ModelToolDependencyMissing 表示标准或额外工具依赖未满足。
	ModelToolDependencyMissing ModelToolErrorCode = "model_tool_dependency_missing"
	// ModelExtraToolNotSupported reports an extra tool absent from the exact profile.
	// ModelExtraToolNotSupported 表示精确规格不存在指定额外工具。
	ModelExtraToolNotSupported ModelToolErrorCode = "model_extra_tool_not_supported"
	// ModelExtraToolNotEntitled reports an extra tool excluded by the selected credential entitlement.
	// ModelExtraToolNotEntitled 表示所选凭据权益不包含指定额外工具。
	ModelExtraToolNotEntitled ModelToolErrorCode = "model_extra_tool_not_entitled"
	// RouterToolBindingMissing reports that Router execution has no configured backend.
	// RouterToolBindingMissing 表示 Router 执行没有已配置后端。
	RouterToolBindingMissing ModelToolErrorCode = "router_tool_binding_missing"
	// RouterToolBindingUnavailable reports that a configured backend is not executable now.
	// RouterToolBindingUnavailable 表示已配置后端当前不可执行。
	RouterToolBindingUnavailable ModelToolErrorCode = "router_tool_binding_unavailable"
	// ModelToolStreamingRequired reports a missing required streaming mode.
	// ModelToolStreamingRequired 表示缺少所需流式方式。
	ModelToolStreamingRequired ModelToolErrorCode = "model_tool_streaming_required"
	// ModelToolReasoningRequired reports a missing required reasoning policy.
	// ModelToolReasoningRequired 表示缺少所需推理策略。
	ModelToolReasoningRequired ModelToolErrorCode = "model_tool_reasoning_required"
	// ModelToolConflictsWithCallerTools reports a verified provider coexistence restriction.
	// ModelToolConflictsWithCallerTools 表示已证实的供应商工具共存限制。
	ModelToolConflictsWithCallerTools ModelToolErrorCode = "model_tool_conflicts_with_caller_tools"
	// RouterToolArgumentInvalid reports malformed or policy-violating model-authored arguments.
	// RouterToolArgumentInvalid 表示模型编写参数格式错误或违反策略。
	RouterToolArgumentInvalid ModelToolErrorCode = "router_tool_argument_invalid"
	// RouterToolExecutionFailed reports a failed Router child execution.
	// RouterToolExecutionFailed 表示 Router 子执行失败。
	RouterToolExecutionFailed ModelToolErrorCode = "router_tool_execution_failed"
	// RouterToolResultInvalid reports a malformed or oversized Router child result.
	// RouterToolResultInvalid 表示 Router 子结果格式错误或超限。
	RouterToolResultInvalid ModelToolErrorCode = "router_tool_result_invalid"
	// RouterToolRoundLimitExceeded reports exhaustion of the frozen per-binding call ceiling.
	// RouterToolRoundLimitExceeded 表示冻结的逐绑定调用上限已耗尽。
	RouterToolRoundLimitExceeded ModelToolErrorCode = "router_tool_round_limit_exceeded"
	// RouterToolBudgetExceeded reports exhaustion of an execution or output budget.
	// RouterToolBudgetExceeded 表示执行或输出预算已耗尽。
	RouterToolBudgetExceeded ModelToolErrorCode = "router_tool_budget_exceeded"
	// NativeMediaDisabledByPolicy reports media withheld from a native model by an explicit Router policy.
	// NativeMediaDisabledByPolicy 表示显式 Router 策略禁止向原生模型投递媒体。
	NativeMediaDisabledByPolicy ModelToolErrorCode = "native_media_disabled_by_policy"
)

// ModelToolError carries a stable non-sensitive model-tool failure across HTTP and durable execution boundaries.
// ModelToolError 在 HTTP 与持久执行边界间携带稳定且不敏感的模型工具失败。
type ModelToolError struct {
	// Code is the stable public machine category.
	// Code 是稳定公开机器类别。
	Code ModelToolErrorCode
	// ToolID identifies the standard, extra, or Router extension tool.
	// ToolID 标识标准、额外或 Router 增强工具。
	ToolID string
	// Phase identifies validation, planning, arguments, execution, or result processing.
	// Phase 标识校验、规划、参数、执行或结果处理阶段。
	Phase string
	// Retryable reports whether repeating without configuration changes can succeed.
	// Retryable 表示不改变配置直接重试是否可能成功。
	Retryable bool
}

// Error returns only stable non-sensitive identifiers.
// Error 仅返回稳定且不敏感的标识。
func (e *ModelToolError) Error() string {
	if e == nil {
		return string(ModelToolNotSupported)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.ToolID)
}

// Unwrap preserves invalid-request classification for existing callers.
// Unwrap 为现有调用方保留无效请求分类。
func (e *ModelToolError) Unwrap() error {
	return ErrInvalidRequest
}

// NewModelToolError creates one stable model-tool error without provider or credential details.
// NewModelToolError 创建一个不含供应商或凭据详情的稳定模型工具错误。
func NewModelToolError(code ModelToolErrorCode, toolID string, phase string, retryable bool) error {
	if code == "" || strings.TrimSpace(toolID) == "" || strings.TrimSpace(phase) == "" {
		return errors.New("invalid model tool error")
	}
	return &ModelToolError{Code: code, ToolID: toolID, Phase: phase, Retryable: retryable}
}

// StandardModelToolKind identifies one closed Vulcan model-tool semantic.
// StandardModelToolKind 标识一种封闭的 Vulcan 模型工具语义。
type StandardModelToolKind string

const (
	// StandardModelToolWebSearch searches the public web and returns normalized evidence.
	// StandardModelToolWebSearch 搜索公共网络并返回归一化证据。
	StandardModelToolWebSearch StandardModelToolKind = "web_search"
	// StandardModelToolWebExtractor reads public web pages and returns normalized extracted content.
	// StandardModelToolWebExtractor 读取公共网页并返回归一化提取内容。
	StandardModelToolWebExtractor StandardModelToolKind = "web_extractor"
)

// Valid reports whether the standard model-tool kind belongs to the closed VCP set.
// Valid 报告标准模型工具类型是否属于封闭的 VCP 集合。
func (k StandardModelToolKind) Valid() bool {
	return k == StandardModelToolWebSearch || k == StandardModelToolWebExtractor
}

// ModelToolMode identifies the explicitly selected implementation source for one standard model tool.
// ModelToolMode 标识一个标准模型工具显式选择的实现来源。
type ModelToolMode string

const (
	// ModelToolDisabled keeps the standard model tool unavailable to the model.
	// ModelToolDisabled 使标准模型工具保持对模型不可用。
	ModelToolDisabled ModelToolMode = "disabled"
	// ModelToolNative uses the selected model profile's verified provider-native implementation.
	// ModelToolNative 使用所选模型规格经过验证的供应商原生实现。
	ModelToolNative ModelToolMode = "native"
	// ModelToolRouter uses an explicitly configured Router-owned tool binding.
	// ModelToolRouter 使用显式配置且由 Router 拥有的工具绑定。
	ModelToolRouter ModelToolMode = "router_tool"
)

// Valid reports whether the model-tool mode is one of the closed execution choices.
// Valid 报告模型工具方式是否属于封闭执行选项。
func (m ModelToolMode) Valid() bool {
	return m == ModelToolDisabled || m == ModelToolNative || m == ModelToolRouter
}

// ModelToolDiagnosticCode identifies one closed, safe planning diagnostic attached to a frozen tool plan.
// ModelToolDiagnosticCode 标识一个附加到冻结工具计划的封闭且安全规划诊断。
type ModelToolDiagnosticCode string

const (
	// ModelToolDiagnosticLegacyNativeWebSearchMigrated records canonical migration of the VCP 1.0 legacy hosted-search declaration.
	// ModelToolDiagnosticLegacyNativeWebSearchMigrated 记录 VCP 1.0 旧托管搜索声明的规范迁移。
	ModelToolDiagnosticLegacyNativeWebSearchMigrated ModelToolDiagnosticCode = "legacy_native_web_search_migrated"
)

// Valid reports whether the diagnostic code belongs to the closed VCP model-tool diagnostic set.
// Valid 报告诊断代码是否属于封闭的 VCP 模型工具诊断集合。
func (c ModelToolDiagnosticCode) Valid() bool {
	return c == ModelToolDiagnosticLegacyNativeWebSearchMigrated
}

// ModelToolDiagnostic publishes one safe compatibility or planning fact without request or provider secrets.
// ModelToolDiagnostic 公开一个不含请求或供应商秘密的安全兼容或规划事实。
type ModelToolDiagnostic struct {
	// Code identifies the closed diagnostic fact.
	// Code 标识封闭诊断事实。
	Code ModelToolDiagnosticCode `json:"code"`
}

// RouterExtensionKind identifies one closed operation-backed Router enhancement.
// RouterExtensionKind 标识一种封闭且由操作支持的 Router 增强能力。
type RouterExtensionKind string

const (
	// RouterExtensionImageUnderstanding delegates image analysis to one Router child operation.
	// RouterExtensionImageUnderstanding 将图片分析委托给一个 Router 子操作。
	RouterExtensionImageUnderstanding RouterExtensionKind = "image_understanding"
	// RouterExtensionAudioUnderstanding delegates audio analysis to one Router child operation.
	// RouterExtensionAudioUnderstanding 将音频分析委托给一个 Router 子操作。
	RouterExtensionAudioUnderstanding RouterExtensionKind = "audio_understanding"
	// RouterExtensionVideoUnderstanding delegates video analysis to one Router child operation.
	// RouterExtensionVideoUnderstanding 将视频分析委托给一个 Router 子操作。
	RouterExtensionVideoUnderstanding RouterExtensionKind = "video_understanding"
	// RouterExtensionImageGeneration delegates image generation to one Router child operation.
	// RouterExtensionImageGeneration 将图片生成委托给一个 Router 子操作。
	RouterExtensionImageGeneration RouterExtensionKind = "image_generation"
	// RouterExtensionVideoGeneration delegates video generation to one Router child operation.
	// RouterExtensionVideoGeneration 将视频生成委托给一个 Router 子操作。
	RouterExtensionVideoGeneration RouterExtensionKind = "video_generation"
	// RouterExtensionSpeechGeneration delegates non-realtime speech synthesis to one Router child operation.
	// RouterExtensionSpeechGeneration 将非实时语音合成委托给一个 Router 子操作。
	RouterExtensionSpeechGeneration RouterExtensionKind = "speech_generation"
	// RouterExtensionSpeechTranscription delegates non-realtime speech recognition to one Router child operation.
	// RouterExtensionSpeechTranscription 将非实时语音识别委托给一个 Router 子操作。
	RouterExtensionSpeechTranscription RouterExtensionKind = "speech_transcription"
)

// Valid reports whether the Router extension belongs to the closed operation-backed set.
// Valid 报告 Router 增强能力是否属于封闭的操作支持集合。
func (k RouterExtensionKind) Valid() bool {
	switch k {
	case RouterExtensionImageUnderstanding,
		RouterExtensionAudioUnderstanding,
		RouterExtensionVideoUnderstanding,
		RouterExtensionImageGeneration,
		RouterExtensionVideoGeneration,
		RouterExtensionSpeechGeneration,
		RouterExtensionSpeechTranscription:
		return true
	default:
		return false
	}
}

// Operation returns the exact closed VCP child operation for this Router extension.
// Operation 返回此 Router 增强能力对应的精确封闭 VCP 子操作。
func (k RouterExtensionKind) Operation() OperationKind {
	switch k {
	case RouterExtensionImageUnderstanding, RouterExtensionAudioUnderstanding, RouterExtensionVideoUnderstanding:
		return OperationMediaAnalyze
	case RouterExtensionImageGeneration:
		return OperationImageGenerate
	case RouterExtensionVideoGeneration:
		return OperationVideoGenerate
	case RouterExtensionSpeechGeneration:
		return OperationSpeechSynthesize
	case RouterExtensionSpeechTranscription:
		return OperationSpeechTranscribe
	default:
		return ""
	}
}

// StandardModelToolSelection selects one standard tool and its exact execution source.
// StandardModelToolSelection 选择一个标准工具及其精确执行来源。
type StandardModelToolSelection struct {
	// Kind identifies the stable Vulcan tool semantic.
	// Kind 标识稳定的 Vulcan 工具语义。
	Kind StandardModelToolKind `json:"kind"`
	// Mode explicitly enables the provider-native implementation, a Router binding, or neither.
	// Mode 显式启用供应商原生实现、Router 绑定或均不启用。
	Mode ModelToolMode `json:"mode"`
}

// ModelToolSelection declares all model-visible standard, provider-extra, and Router extension tools.
// ModelToolSelection 声明全部模型可见的标准工具、供应商额外工具和 Router 增强工具。
type ModelToolSelection struct {
	// Standard contains closed Vulcan tools with explicit implementation modes.
	// Standard 包含带显式实现方式的封闭 Vulcan 工具。
	Standard []StandardModelToolSelection `json:"standard,omitempty"`
	// Extra contains profile-declared provider or model extra-tool identifiers.
	// Extra 包含规格声明的供应商或模型额外工具标识。
	Extra []string `json:"extra,omitempty"`
	// RouterExtensions contains explicitly enabled operation-backed Router extension identifiers.
	// RouterExtensions 包含显式启用且由操作支持的 Router 增强工具标识。
	RouterExtensions []RouterExtensionKind `json:"router_extensions,omitempty"`
}

// ModelToolPlanEntry publishes one frozen standard model-tool execution decision without backend secrets.
// ModelToolPlanEntry 公开一项冻结的标准模型工具执行决策且不包含后端秘密。
type ModelToolPlanEntry struct {
	// Kind identifies the standard model tool.
	// Kind 标识标准模型工具。
	Kind StandardModelToolKind `json:"kind"`
	// Mode identifies disabled, native, or Router execution.
	// Mode 标识禁用、原生或 Router 执行。
	Mode ModelToolMode `json:"mode"`
	// RouterBindingID identifies the selected administrator policy without exposing its backend target.
	// RouterBindingID 标识选定的管理员策略且不暴露其后端目标。
	RouterBindingID string `json:"router_binding_id,omitempty"`
	// RouterBindingRevision identifies the frozen policy revision.
	// RouterBindingRevision 标识冻结的策略修订号。
	RouterBindingRevision uint64 `json:"router_binding_revision,omitempty"`
}

// RouterExtensionPlanEntry publishes one frozen operation-backed Router enhancement decision.
// RouterExtensionPlanEntry 公开一项冻结且由操作支持的 Router 增强决策。
type RouterExtensionPlanEntry struct {
	// ID identifies the closed Router enhancement.
	// ID 标识封闭 Router 增强能力。
	ID RouterExtensionKind `json:"id"`
	// RouterBindingID identifies the selected administrator policy without exposing its backend target.
	// RouterBindingID 标识选定的管理员策略且不暴露其后端目标。
	RouterBindingID string `json:"router_binding_id"`
	// RouterBindingRevision identifies the frozen policy revision.
	// RouterBindingRevision 标识冻结的策略修订号。
	RouterBindingRevision uint64 `json:"router_binding_revision"`
}

// ModelToolPlan publishes every frozen model-tool decision accepted for one execution or preflight.
// ModelToolPlan 公开一次执行或预检接收的全部冻结模型工具决策。
type ModelToolPlan struct {
	// CatalogRevision identifies the parent model catalog snapshot used for planning.
	// CatalogRevision 标识用于规划的父模型目录快照。
	CatalogRevision uint64 `json:"catalog_revision"`
	// Standard contains requested standard tools in canonical request order.
	// Standard 按规范请求顺序包含请求的标准工具。
	Standard []ModelToolPlanEntry `json:"standard,omitempty"`
	// Extra contains exact provider-native extra tool identifiers.
	// Extra 包含精确的供应商原生额外工具标识。
	Extra []string `json:"extra,omitempty"`
	// RouterExtensions contains auditable operation-backed Router enhancement decisions.
	// RouterExtensions 包含可审计且由操作支持的 Router 增强决策。
	RouterExtensions []RouterExtensionPlanEntry `json:"router_extensions,omitempty"`
	// Diagnostics contains safe compatibility records produced while canonicalizing the accepted request.
	// Diagnostics 包含规范化已接收请求时生成的安全兼容记录。
	Diagnostics []ModelToolDiagnostic `json:"diagnostics,omitempty"`
}

// Validate verifies the closed standard set and every stable extension identifier.
// Validate 校验封闭标准集合以及每个稳定扩展标识。
func (s ModelToolSelection) Validate() error {
	// seenStandard rejects ambiguous duplicate mode selections.
	// seenStandard 拒绝具有歧义的重复方式选择。
	seenStandard := make(map[StandardModelToolKind]struct{}, len(s.Standard))
	for index, selection := range s.Standard {
		if !selection.Kind.Valid() {
			return fmt.Errorf("%w: model standard tool %d has invalid kind %q", ErrInvalidRequest, index, selection.Kind)
		}
		if !selection.Mode.Valid() {
			return fmt.Errorf("%w: model standard tool %s has invalid mode %q", ErrInvalidRequest, selection.Kind, selection.Mode)
		}
		if _, exists := seenStandard[selection.Kind]; exists {
			return fmt.Errorf("%w: model standard tool %s is duplicated", ErrInvalidRequest, selection.Kind)
		}
		seenStandard[selection.Kind] = struct{}{}
	}
	if errExtra := validateModelToolIDs("model extra tool", s.Extra); errExtra != nil {
		return errExtra
	}
	return validateRouterExtensionKinds(s.RouterExtensions)
}

// Enabled reports whether at least one model tool is explicitly available to the model.
// Enabled 报告是否至少有一个模型工具被显式提供给模型。
func (s ModelToolSelection) Enabled() bool {
	for _, selection := range s.Standard {
		if selection.Mode != ModelToolDisabled {
			return true
		}
	}
	return len(s.Extra) > 0 || len(s.RouterExtensions) > 0
}

// ContainsEnabledName reports whether a named tool policy references an enabled model tool.
// ContainsEnabledName 报告指定工具策略是否引用了已启用的模型工具。
func (s ModelToolSelection) ContainsEnabledName(name string) bool {
	return s.EnabledNameCount(name) > 0
}

// EnabledNameCount returns the number of enabled model-tool declarations with one public name.
// EnabledNameCount 返回具有同一个公开名称的已启用模型工具声明数量。
func (s ModelToolSelection) EnabledNameCount(name string) int {
	count := 0
	for _, selection := range s.Standard {
		if selection.Mode != ModelToolDisabled && string(selection.Kind) == name {
			count++
		}
	}
	for _, candidate := range s.Extra {
		if candidate == name {
			count++
		}
	}
	for _, candidate := range s.RouterExtensions {
		if string(candidate) == name {
			count++
		}
	}
	return count
}

// validateModelToolIDs verifies one duplicate-free list of stable lower-case identifiers.
// validateModelToolIDs 校验一个无重复的稳定小写标识列表。
func validateModelToolIDs(label string, values []string) error {
	// seen rejects duplicate tool declarations without merging caller intent.
	// seen 拒绝重复工具声明且不合并调用方意图。
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		if !validModelToolID(value) {
			return fmt.Errorf("%w: %s %d has invalid identifier %q", ErrInvalidRequest, label, index, value)
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("%w: %s %q is duplicated", ErrInvalidRequest, label, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

// validateRouterExtensionKinds rejects unknown or duplicate operation-backed Router enhancements.
// validateRouterExtensionKinds 拒绝未知或重复的操作支持 Router 增强能力。
func validateRouterExtensionKinds(values []RouterExtensionKind) error {
	seen := make(map[RouterExtensionKind]struct{}, len(values))
	for index, value := range values {
		if !value.Valid() {
			return fmt.Errorf("%w: router extension tool %d has invalid id %q", ErrInvalidRequest, index, value)
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("%w: router extension tool %q is duplicated", ErrInvalidRequest, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

// validModelToolID reports whether one identifier is stable, lower-case, and path-safe.
// validModelToolID 报告一个标识是否稳定、小写且路径安全。
func validModelToolID(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '_' || character == '-' || character == '.' {
			continue
		}
		return false
	}
	return true
}

// ValidModelToolID reports whether one public model-tool identifier satisfies the VCP stability rules.
// ValidModelToolID 报告一个公开模型工具标识是否满足 VCP 稳定性规则。
func ValidModelToolID(value string) bool {
	return validModelToolID(value)
}
