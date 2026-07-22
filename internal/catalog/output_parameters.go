package catalog

import (
	"fmt"
	"strings"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// MediaOutputCapability describes one generated media family and its authoritative limits.
// MediaOutputCapability 描述一种生成媒体类别及其权威限制。
type MediaOutputCapability struct {
	// Kind identifies the generated media family.
	// Kind 标识生成的媒体类别。
	Kind vcp.MediaKind `json:"kind"`
	// Level reports the support form.
	// Level 表示支持形式。
	Level CapabilityLevel `json:"level"`
	// Formats lists exact output formats.
	// Formats 列出精确输出格式。
	Formats []string `json:"formats"`
	// MaxOutputs limits generated resources per execution.
	// MaxOutputs 限制每次执行生成的资源数量。
	MaxOutputs OptionalLimit `json:"max_outputs"`
	// Common contains output byte and count limits.
	// Common 包含输出字节数和数量限制。
	Common CommonMediaLimits `json:"common"`
	// Image contains image-only output limits.
	// Image 包含图片专用输出限制。
	Image *ImageMediaLimits `json:"image,omitempty"`
	// Audio contains audio-only output limits.
	// Audio 包含音频专用输出限制。
	Audio *AudioMediaLimits `json:"audio,omitempty"`
	// Video contains video-only output limits.
	// Video 包含视频专用输出限制。
	Video *VideoMediaLimits `json:"video,omitempty"`
	// Delivery declares real result delivery modes.
	// Delivery 声明真实结果交付模式。
	Delivery DeliveryCapabilities `json:"delivery"`
	// Evidence contains auditable output capability sources.
	// Evidence 包含可审计输出能力来源。
	Evidence []CapabilityEvidence `json:"evidence"`
	// EvidenceRevision freezes the interpreted output contract.
	// EvidenceRevision 冻结解释后的输出合同。
	EvidenceRevision uint64 `json:"evidence_revision"`
}

// ParameterKind identifies one closed operation parameter shape.
// ParameterKind 标识一种封闭操作参数形态。
type ParameterKind string

const (
	// ParameterString represents free text with explicit length bounds.
	// ParameterString 表示具有显式长度边界的自由文本。
	ParameterString ParameterKind = "string"
	// ParameterStringList represents an ordered list of free-text entries with per-entry length bounds.
	// ParameterStringList 表示具有逐项长度边界的有序自由文本列表。
	ParameterStringList ParameterKind = "string_list"
	// ParameterBoolean represents a boolean switch.
	// ParameterBoolean 表示布尔开关。
	ParameterBoolean ParameterKind = "boolean"
	// ParameterInteger represents a bounded integer.
	// ParameterInteger 表示有界整数。
	ParameterInteger ParameterKind = "integer"
	// ParameterFloat represents a bounded floating-point number.
	// ParameterFloat 表示有界浮点数。
	ParameterFloat ParameterKind = "float"
	// ParameterEnum represents one closed string choice.
	// ParameterEnum 表示一个封闭字符串选项。
	ParameterEnum ParameterKind = "enum"
	// ParameterSize represents one provider-defined width and height choice.
	// ParameterSize 表示一个供应商定义的宽高选项。
	ParameterSize ParameterKind = "size"
	// ParameterDuration represents seconds and may express provider-supported fractional durations.
	// ParameterDuration 表示秒并可表达供应商支持的小数时长。
	ParameterDuration ParameterKind = "duration"
	// ParameterFormat represents a closed media format.
	// ParameterFormat 表示封闭媒体格式。
	ParameterFormat ParameterKind = "format"
	// ParameterCount represents a bounded resource count.
	// ParameterCount 表示有界资源数量。
	ParameterCount ParameterKind = "count"
	// ParameterResourceRole represents a closed VCP media input role.
	// ParameterResourceRole 表示封闭 VCP 媒体输入角色。
	ParameterResourceRole ParameterKind = "resource_role"
)

// ParameterDefaultSource identifies who owns one documented default.
// ParameterDefaultSource 标识一个记录默认值的拥有方。
type ParameterDefaultSource string

const (
	// ParameterDefaultProvider is documented by the upstream provider.
	// ParameterDefaultProvider 由上游供应商记录。
	ParameterDefaultProvider ParameterDefaultSource = "provider"
	// ParameterDefaultRouter is defined by the VCP contract.
	// ParameterDefaultRouter 由 VCP 合同定义。
	ParameterDefaultRouter ParameterDefaultSource = "router"
	// ParameterDefaultCaller means no value is supplied automatically.
	// ParameterDefaultCaller 表示不会自动提供值。
	ParameterDefaultCaller ParameterDefaultSource = "caller"
)

// IntegerRange contains optional inclusive integer boundaries.
// IntegerRange 包含可选的包含端点整数边界。
type IntegerRange struct {
	// Minimum is the optional inclusive minimum.
	// Minimum 是可选包含端点最小值。
	Minimum *int64 `json:"minimum,omitempty"`
	// Maximum is the optional inclusive maximum.
	// Maximum 是可选包含端点最大值。
	Maximum *int64 `json:"maximum,omitempty"`
	// MultipleOf requires integer values to be divisible by one positive step.
	// MultipleOf 要求整数值可被一个正步长整除。
	MultipleOf *int64 `json:"multiple_of,omitempty"`
}

// FloatRange contains optional inclusive floating-point boundaries.
// FloatRange 包含可选的包含端点浮点边界。
type FloatRange struct {
	// Minimum is the optional inclusive minimum.
	// Minimum 是可选包含端点最小值。
	Minimum *float64 `json:"minimum,omitempty"`
	// Maximum is the optional inclusive maximum.
	// Maximum 是可选包含端点最大值。
	Maximum *float64 `json:"maximum,omitempty"`
}

// StringRange contains optional inclusive Unicode code-point length boundaries.
// StringRange 包含可选的 Unicode 码点长度包含边界。
type StringRange struct {
	// MinimumLength is the optional inclusive minimum code-point count.
	// MinimumLength 是可选的包含端点最小码点数。
	MinimumLength *int64 `json:"minimum_length,omitempty"`
	// MaximumLength is the optional inclusive maximum code-point count.
	// MaximumLength 是可选的包含端点最大码点数。
	MaximumLength *int64 `json:"maximum_length,omitempty"`
}

// ParameterDefault contains exactly one typed documented default.
// ParameterDefault 包含唯一类型化记录默认值。
type ParameterDefault struct {
	// Source identifies the default owner.
	// Source 标识默认值拥有方。
	Source ParameterDefaultSource `json:"source"`
	// Boolean contains a boolean default.
	// Boolean 包含布尔默认值。
	Boolean *bool `json:"boolean,omitempty"`
	// Integer contains an integer, duration, or count default.
	// Integer 包含整数、时长或数量默认值。
	Integer *int64 `json:"integer,omitempty"`
	// Float contains a floating-point default.
	// Float 包含浮点默认值。
	Float *float64 `json:"float,omitempty"`
	// String contains an enum, format, or size default.
	// String 包含枚举、格式或尺寸默认值。
	String *string `json:"string,omitempty"`
	// ResourceRole contains a media role default.
	// ResourceRole 包含媒体角色默认值。
	ResourceRole *vcp.MediaInputRole `json:"resource_role,omitempty"`
}

// ParameterDescriptor describes one operation parameter without free-form schemas.
// ParameterDescriptor 描述一个操作参数且不使用自由形式 Schema。
type ParameterDescriptor struct {
	// ID is stable within one execution profile.
	// ID 在一个执行 Profile 内保持稳定。
	ID string `json:"id"`
	// Kind identifies the closed parameter shape.
	// Kind 标识封闭参数形态。
	Kind ParameterKind `json:"kind"`
	// Required reports whether callers must supply the parameter.
	// Required 表示调用方是否必须提供此参数。
	Required bool `json:"required"`
	// IntegerRange applies to integer, duration, and count parameters.
	// IntegerRange 适用于整数、时长和数量参数。
	IntegerRange *IntegerRange `json:"integer_range,omitempty"`
	// FloatRange applies only to floating-point parameters.
	// FloatRange 仅适用于浮点参数。
	FloatRange *FloatRange `json:"float_range,omitempty"`
	// StringRange applies only to free-text parameters.
	// StringRange 仅适用于自由文本参数。
	StringRange *StringRange `json:"string_range,omitempty"`
	// AllowedValues lists enum, format, or size choices.
	// AllowedValues 列出枚举、格式或尺寸选项。
	AllowedValues []string `json:"allowed_values,omitempty"`
	// AllowedResourceRoles lists resource-role choices.
	// AllowedResourceRoles 列出资源角色选项。
	AllowedResourceRoles []vcp.MediaInputRole `json:"allowed_resource_roles,omitempty"`
	// Default contains an evidenced default when present.
	// Default 在存在时包含具有证据的默认值。
	Default *ParameterDefault `json:"default,omitempty"`
}

// ParameterRuleKind identifies one closed cross-parameter condition.
// ParameterRuleKind 标识一种封闭跨参数条件。
type ParameterRuleKind string

const (
	// ParameterRuleMutuallyExclusive forbids multiple related parameters together.
	// ParameterRuleMutuallyExclusive 禁止多个相关参数同时出现。
	ParameterRuleMutuallyExclusive ParameterRuleKind = "mutually_exclusive"
	// ParameterRuleRequires requires related parameters when ParameterID is present.
	// ParameterRuleRequires 要求 ParameterID 出现时同时提供相关参数。
	ParameterRuleRequires ParameterRuleKind = "requires"
	// ParameterRuleForbids forbids related parameters when ParameterID is present.
	// ParameterRuleForbids 禁止 ParameterID 出现时提供相关参数。
	ParameterRuleForbids ParameterRuleKind = "forbids"
	// ParameterRuleRequiresWhenEnum requires related parameters for one exact enum value.
	// ParameterRuleRequiresWhenEnum 在一个精确枚举值下要求相关参数。
	ParameterRuleRequiresWhenEnum ParameterRuleKind = "requires_when_enum"
)

// ParameterRule describes one typed relationship between declared parameters.
// ParameterRule 描述已声明参数之间的一条类型化关系。
type ParameterRule struct {
	// Kind identifies the condition semantics.
	// Kind 标识条件语义。
	Kind ParameterRuleKind `json:"kind"`
	// ParameterID identifies the controlling parameter.
	// ParameterID 标识控制参数。
	ParameterID string `json:"parameter_id"`
	// RelatedParameterIDs lists exact affected parameters.
	// RelatedParameterIDs 列出精确受影响参数。
	RelatedParameterIDs []string `json:"related_parameter_ids"`
	// EnumValue contains the trigger only for requires_when_enum.
	// EnumValue 仅为 requires_when_enum 包含触发值。
	EnumValue string `json:"enum_value,omitempty"`
}

// UsageAccuracy identifies whether provider-reported usage is exact, estimated, or unavailable.
// UsageAccuracy 标识供应商报告用量是精确、估算还是不可用。
type UsageAccuracy string

const (
	// UsageExact is reported directly by the provider.
	// UsageExact 由供应商直接报告。
	UsageExact UsageAccuracy = "exact"
	// UsageEstimated is computed by a documented Router rule.
	// UsageEstimated 由记录在案的 Router 规则计算。
	UsageEstimated UsageAccuracy = "estimated"
	// UsageUnknown is not reliably available.
	// UsageUnknown 无法可靠获得。
	UsageUnknown UsageAccuracy = "unknown"
)

// UsageUnit identifies one closed independently reported consumption dimension.
// UsageUnit 标识一个封闭且独立报告的消耗维度。
type UsageUnit string

const (
	// UsageUnitInputTokens counts input tokens.
	// UsageUnitInputTokens 统计输入 Token。
	UsageUnitInputTokens UsageUnit = "input_tokens"
	// UsageUnitOutputTokens counts generated tokens.
	// UsageUnitOutputTokens 统计生成 Token。
	UsageUnitOutputTokens UsageUnit = "output_tokens"
	// UsageUnitReasoningTokens counts reasoning tokens.
	// UsageUnitReasoningTokens 统计推理 Token。
	UsageUnitReasoningTokens UsageUnit = "reasoning_tokens"
	// UsageUnitCharacters counts text characters.
	// UsageUnitCharacters 统计文本字符。
	UsageUnitCharacters UsageUnit = "characters"
	// UsageUnitAudioMilliseconds counts audio duration.
	// UsageUnitAudioMilliseconds 统计音频时长。
	UsageUnitAudioMilliseconds UsageUnit = "audio_milliseconds"
	// UsageUnitVideoMilliseconds counts video duration.
	// UsageUnitVideoMilliseconds 统计视频时长。
	UsageUnitVideoMilliseconds UsageUnit = "video_milliseconds"
	// UsageUnitImages counts image resources.
	// UsageUnitImages 统计图片资源。
	UsageUnitImages UsageUnit = "images"
	// UsageUnitPixels counts processed pixels.
	// UsageUnitPixels 统计处理像素。
	UsageUnitPixels UsageUnit = "pixels"
	// UsageUnitEmbeddingInputs counts vectorized inputs.
	// UsageUnitEmbeddingInputs 统计向量化输入项。
	UsageUnitEmbeddingInputs UsageUnit = "embedding_inputs"
	// UsageUnitVectors counts returned vectors.
	// UsageUnitVectors 统计返回向量。
	UsageUnitVectors UsageUnit = "vectors"
	// UsageUnitRerankCandidates counts ranked candidates.
	// UsageUnitRerankCandidates 统计重排候选项。
	UsageUnitRerankCandidates UsageUnit = "rerank_candidates"
	// UsageUnitSearchQueries counts search queries.
	// UsageUnitSearchQueries 统计搜索 Query。
	UsageUnitSearchQueries UsageUnit = "search_queries"
	// UsageUnitSearchResults counts returned search results.
	// UsageUnitSearchResults 统计返回搜索结果。
	UsageUnitSearchResults UsageUnit = "search_results"
	// UsageUnitProviderTasks counts provider tasks.
	// UsageUnitProviderTasks 统计供应商任务。
	UsageUnitProviderTasks UsageUnit = "provider_tasks"
)

// UsageMetricCapability declares one independently observable usage dimension.
// UsageMetricCapability 声明一个可独立观察的用量维度。
type UsageMetricCapability struct {
	// Unit is a closed VCP usage unit identifier.
	// Unit 是封闭 VCP 用量单位标识。
	Unit UsageUnit `json:"unit"`
	// Accuracy identifies the observation quality.
	// Accuracy 标识观察质量。
	Accuracy UsageAccuracy `json:"accuracy"`
}

// validateOutputAndParameters verifies output, parameter, rule, and usage contracts.
// validateOutputAndParameters 校验输出、参数、规则和用量合同。
func (c ModelCapabilities) validateOutputAndParameters() error {
	seenOutputs := make(map[vcp.MediaKind]struct{}, len(c.MediaOutputs))
	for _, output := range c.MediaOutputs {
		if _, exists := seenOutputs[output.Kind]; exists {
			return fmt.Errorf("%w: duplicate media output capability %q", ErrInvalidCatalog, output.Kind)
		}
		seenOutputs[output.Kind] = struct{}{}
		if errValidate := output.Validate(); errValidate != nil {
			return errValidate
		}
	}
	parameterIDs := make(map[string]ParameterDescriptor, len(c.Parameters))
	for _, parameter := range c.Parameters {
		if _, exists := parameterIDs[parameter.ID]; exists {
			return fmt.Errorf("%w: duplicate parameter %q", ErrInvalidCatalog, parameter.ID)
		}
		if errValidate := parameter.Validate(); errValidate != nil {
			return errValidate
		}
		parameterIDs[parameter.ID] = parameter
	}
	for _, rule := range c.ParameterRules {
		if errValidate := rule.validate(parameterIDs); errValidate != nil {
			return errValidate
		}
	}
	seenUsage := make(map[UsageUnit]struct{}, len(c.UsageMetrics))
	for _, metric := range c.UsageMetrics {
		if !validUsageUnit(metric.Unit) || (metric.Accuracy != UsageExact && metric.Accuracy != UsageEstimated && metric.Accuracy != UsageUnknown) {
			return fmt.Errorf("%w: usage metric is invalid", ErrInvalidCatalog)
		}
		if _, exists := seenUsage[metric.Unit]; exists {
			return fmt.Errorf("%w: duplicate usage metric %q", ErrInvalidCatalog, metric.Unit)
		}
		seenUsage[metric.Unit] = struct{}{}
	}
	return nil
}

// ValidateOperation verifies that one typed model profile exposes exactly the contracts its operation requires.
// ValidateOperation 校验一个类型化模型 Profile 精确公开其操作要求的合同。
func (c ModelCapabilities) ValidateOperation(operation vcp.OperationKind) error {
	if operation == "" {
		return nil
	}
	if errDelivery := validateDeliveryCapabilities(c.Delivery); errDelivery != nil {
		return errDelivery
	}
	if operation != vcp.OperationEmbeddingCreate && c.Embedding != nil {
		return fmt.Errorf("%w: operation %q cannot carry embedding capabilities", ErrInvalidCatalog, operation)
	}
	if operation != vcp.OperationRerankDocuments && c.Rerank != nil {
		return fmt.Errorf("%w: operation %q cannot carry rerank capabilities", ErrInvalidCatalog, operation)
	}
	producesMedia := operation == vcp.OperationImageGenerate || operation == vcp.OperationImageEdit || operation == vcp.OperationVideoGenerate || operation == vcp.OperationVideoEdit || operation == vcp.OperationVideoExtend || operation == vcp.OperationSpeechSynthesize || operation == vcp.OperationMusicGenerate || operation == vcp.OperationMusicCoverPrepare || operation == vcp.OperationMusicCover
	if !producesMedia && len(c.MediaOutputs) != 0 {
		return fmt.Errorf("%w: operation %q cannot carry generated-media capabilities", ErrInvalidCatalog, operation)
	}
	switch operation {
	case vcp.OperationConversationRespond:
		return nil
	case vcp.OperationMediaAnalyze:
		return requireMediaInput(c, "media.analyze")
	case vcp.OperationImageGenerate:
		return requireMediaOutput(c, vcp.MediaImage, operation)
	case vcp.OperationImageEdit:
		if errInput := requireMediaInputKind(c, vcp.MediaImage, operation); errInput != nil {
			return errInput
		}
		return requireMediaOutput(c, vcp.MediaImage, operation)
	case vcp.OperationVideoGenerate:
		return requireMediaOutput(c, vcp.MediaVideo, operation)
	case vcp.OperationVideoEdit, vcp.OperationVideoExtend:
		if errInput := requireMediaInputKind(c, vcp.MediaVideo, operation); errInput != nil {
			return errInput
		}
		return requireMediaOutput(c, vcp.MediaVideo, operation)
	case vcp.OperationSpeechSynthesize:
		return requireMediaOutput(c, vcp.MediaAudio, operation)
	case vcp.OperationSpeechTranscribe:
		return requireMediaInputKind(c, vcp.MediaAudio, operation)
	case vcp.OperationEmbeddingCreate:
		if c.Embedding == nil {
			return fmt.Errorf("%w: embedding.create requires embedding capabilities", ErrInvalidCatalog)
		}
		return nil
	case vcp.OperationRerankDocuments:
		if c.Rerank == nil {
			return fmt.Errorf("%w: rerank.documents requires rerank capabilities", ErrInvalidCatalog)
		}
		return nil
	case vcp.OperationMusicGenerate:
		return requireMediaOutput(c, vcp.MediaAudio, operation)
	case vcp.OperationMusicCoverPrepare:
		return requireMediaInputKind(c, vcp.MediaAudio, operation)
	case vcp.OperationMusicCover:
		return requireMediaOutput(c, vcp.MediaAudio, operation)
	case vcp.OperationSearchWeb, vcp.OperationWebExtract:
		return fmt.Errorf("%w: operation %q requires a service profile", ErrInvalidCatalog, operation)
	default:
		return fmt.Errorf("%w: unsupported model operation %q", ErrInvalidCatalog, operation)
	}
}

// requireMediaInput verifies at least one callable media input contract exists.
// requireMediaInput 校验至少存在一个可调用媒体输入合同。
func requireMediaInput(capabilities ModelCapabilities, operation string) error {
	for _, input := range capabilities.MediaInputs {
		if input.Level == CapabilityNative || input.Level == CapabilityEmulated || input.Level == CapabilityConditional {
			return nil
		}
	}
	return fmt.Errorf("%w: operation %q requires media input capabilities", ErrInvalidCatalog, operation)
}

// requireMediaInputKind verifies one exact callable media input contract exists.
// requireMediaInputKind 校验存在一个精确可调用媒体输入合同。
func requireMediaInputKind(capabilities ModelCapabilities, kind vcp.MediaKind, operation vcp.OperationKind) error {
	for _, input := range capabilities.MediaInputs {
		if input.Kind == kind && (input.Level == CapabilityNative || input.Level == CapabilityEmulated || input.Level == CapabilityConditional) {
			return nil
		}
	}
	return fmt.Errorf("%w: operation %q requires %s input capabilities", ErrInvalidCatalog, operation, kind)
}

// requireMediaOutput verifies one exact callable generated-media contract exists.
// requireMediaOutput 校验存在一个精确可调用生成媒体合同。
func requireMediaOutput(capabilities ModelCapabilities, kind vcp.MediaKind, operation vcp.OperationKind) error {
	for _, output := range capabilities.MediaOutputs {
		if output.Kind == kind && (output.Level == CapabilityNative || output.Level == CapabilityEmulated || output.Level == CapabilityConditional) {
			return nil
		}
	}
	return fmt.Errorf("%w: operation %q requires %s output capabilities", ErrInvalidCatalog, operation, kind)
}

// Validate verifies one generated media contract.
// Validate 校验一个生成媒体合同。
func (c MediaOutputCapability) Validate() error {
	if c.Kind != vcp.MediaImage && c.Kind != vcp.MediaAudio && c.Kind != vcp.MediaVideo {
		return fmt.Errorf("%w: invalid media output kind %q", ErrInvalidCatalog, c.Kind)
	}
	if !validCapabilityLevel(c.Level) || c.Level == CapabilityUnknown || c.EvidenceRevision == 0 || len(c.Formats) == 0 || len(c.Evidence) == 0 {
		return fmt.Errorf("%w: media output requires callable support, formats, and evidence", ErrInvalidCatalog)
	}
	if errFormats := validateUniqueStrings("media output format", c.Formats); errFormats != nil {
		return errFormats
	}
	if errLimit := validateOptionalLimit("media output max outputs", c.MaxOutputs); errLimit != nil {
		return errLimit
	}
	if errCommon := validateCommonMediaLimits(c.Common); errCommon != nil {
		return errCommon
	}
	limits := MediaInputCapability{Kind: c.Kind, Common: c.Common, Image: c.Image, Audio: c.Audio, Video: c.Video}
	if errLimits := validateMediaSpecificLimits(limits); errLimits != nil {
		return errLimits
	}
	if errDelivery := validateDeliveryCapabilities(c.Delivery); errDelivery != nil {
		return errDelivery
	}
	if c.Delivery.PartialResults && !c.Delivery.Streaming && !c.Delivery.Asynchronous {
		return fmt.Errorf("%w: partial media results require streaming or asynchronous delivery", ErrInvalidCatalog)
	}
	for _, evidence := range c.Evidence {
		if !validModelSource(evidence.Source) || strings.TrimSpace(evidence.Reference) == "" || evidence.ObservedAt.IsZero() || evidence.Revision == 0 || (evidence.ExpiresAt != nil && evidence.ExpiresAt.Before(evidence.ObservedAt)) {
			return fmt.Errorf("%w: media output evidence is invalid", ErrInvalidCatalog)
		}
	}
	return nil
}

// validateDeliveryCapabilities verifies async-only polling and cancellation discoverability.
// validateDeliveryCapabilities 校验仅异步任务可公开轮询与取消发现能力。
func validateDeliveryCapabilities(delivery DeliveryCapabilities) error {
	if !delivery.Synchronous && !delivery.Streaming && !delivery.Asynchronous {
		return fmt.Errorf("%w: capability requires a delivery mode", ErrInvalidCatalog)
	}
	if delivery.Polling && !delivery.Asynchronous || delivery.Cancellation && !delivery.Asynchronous && !delivery.Streaming {
		return fmt.Errorf("%w: polling requires asynchronous delivery and cancellation requires asynchronous or streaming delivery", ErrInvalidCatalog)
	}
	return nil
}

// Validate verifies one closed parameter descriptor and typed default.
// Validate 校验一个封闭参数描述及类型化默认值。
func (p ParameterDescriptor) Validate() error {
	if strings.TrimSpace(p.ID) == "" || !validParameterKind(p.Kind) {
		return fmt.Errorf("%w: parameter id and kind are required", ErrInvalidCatalog)
	}
	integerKind := p.Kind == ParameterInteger || p.Kind == ParameterCount
	floatKind := p.Kind == ParameterFloat || p.Kind == ParameterDuration
	stringKind := p.Kind == ParameterString || p.Kind == ParameterStringList
	choiceKind := p.Kind == ParameterEnum || p.Kind == ParameterFormat || p.Kind == ParameterSize
	if (p.IntegerRange != nil) != integerKind || (p.FloatRange != nil) != floatKind || (p.StringRange != nil) != stringKind || (len(p.AllowedValues) > 0) != choiceKind || (len(p.AllowedResourceRoles) > 0) != (p.Kind == ParameterResourceRole) {
		return fmt.Errorf("%w: parameter %q constraint shape does not match kind", ErrInvalidCatalog, p.ID)
	}
	if p.IntegerRange != nil && p.IntegerRange.Minimum != nil && p.IntegerRange.Maximum != nil && *p.IntegerRange.Minimum > *p.IntegerRange.Maximum {
		return fmt.Errorf("%w: parameter %q integer range is inverted", ErrInvalidCatalog, p.ID)
	}
	if p.IntegerRange != nil && p.IntegerRange.MultipleOf != nil && *p.IntegerRange.MultipleOf <= 0 {
		return fmt.Errorf("%w: parameter %q integer multiple_of must be positive", ErrInvalidCatalog, p.ID)
	}
	if p.FloatRange != nil && p.FloatRange.Minimum != nil && p.FloatRange.Maximum != nil && *p.FloatRange.Minimum > *p.FloatRange.Maximum {
		return fmt.Errorf("%w: parameter %q float range is inverted", ErrInvalidCatalog, p.ID)
	}
	if p.StringRange != nil && ((p.StringRange.MinimumLength != nil && *p.StringRange.MinimumLength < 0) || (p.StringRange.MaximumLength != nil && *p.StringRange.MaximumLength < 0) || (p.StringRange.MinimumLength != nil && p.StringRange.MaximumLength != nil && *p.StringRange.MinimumLength > *p.StringRange.MaximumLength)) {
		return fmt.Errorf("%w: parameter %q string range is invalid", ErrInvalidCatalog, p.ID)
	}
	if choiceKind {
		if errChoices := validateUniqueStrings("parameter choice", p.AllowedValues); errChoices != nil {
			return errChoices
		}
	}
	seenRoles := make(map[vcp.MediaInputRole]struct{}, len(p.AllowedResourceRoles))
	for _, role := range p.AllowedResourceRoles {
		if !validMediaRole(role) {
			return fmt.Errorf("%w: parameter %q contains invalid media role %q", ErrInvalidCatalog, p.ID, role)
		}
		if _, exists := seenRoles[role]; exists {
			return fmt.Errorf("%w: parameter %q contains duplicate media role %q", ErrInvalidCatalog, p.ID, role)
		}
		seenRoles[role] = struct{}{}
	}
	if p.Default != nil {
		return p.Default.validate(p)
	}
	return nil
}

// validate verifies exactly one default variant matches its parameter kind and range.
// validate 校验唯一默认值变体匹配参数类型与范围。
func (d ParameterDefault) validate(parameter ParameterDescriptor) error {
	if d.Source != ParameterDefaultProvider && d.Source != ParameterDefaultRouter && d.Source != ParameterDefaultCaller {
		return fmt.Errorf("%w: parameter %q default source is invalid", ErrInvalidCatalog, parameter.ID)
	}
	count := 0
	for _, present := range []bool{d.Boolean != nil, d.Integer != nil, d.Float != nil, d.String != nil, d.ResourceRole != nil} {
		if present {
			count++
		}
	}
	if count != 1 {
		return fmt.Errorf("%w: parameter %q default requires exactly one value", ErrInvalidCatalog, parameter.ID)
	}
	if parameter.Kind == ParameterStringList || (parameter.Kind == ParameterBoolean) != (d.Boolean != nil) || ((parameter.Kind == ParameterInteger || parameter.Kind == ParameterCount) != (d.Integer != nil)) || ((parameter.Kind == ParameterFloat || parameter.Kind == ParameterDuration) != (d.Float != nil)) || ((parameter.Kind == ParameterString || parameter.Kind == ParameterEnum || parameter.Kind == ParameterFormat || parameter.Kind == ParameterSize) != (d.String != nil)) || (parameter.Kind == ParameterResourceRole) != (d.ResourceRole != nil) {
		return fmt.Errorf("%w: parameter %q default type mismatch", ErrInvalidCatalog, parameter.ID)
	}
	if d.Integer != nil && parameter.IntegerRange != nil && ((parameter.IntegerRange.Minimum != nil && *d.Integer < *parameter.IntegerRange.Minimum) || (parameter.IntegerRange.Maximum != nil && *d.Integer > *parameter.IntegerRange.Maximum)) {
		return fmt.Errorf("%w: parameter %q integer default is outside its range", ErrInvalidCatalog, parameter.ID)
	}
	if d.Integer != nil && parameter.IntegerRange != nil && parameter.IntegerRange.MultipleOf != nil && *d.Integer%*parameter.IntegerRange.MultipleOf != 0 {
		return fmt.Errorf("%w: parameter %q integer default violates multiple_of", ErrInvalidCatalog, parameter.ID)
	}
	if d.Float != nil && parameter.FloatRange != nil && ((parameter.FloatRange.Minimum != nil && *d.Float < *parameter.FloatRange.Minimum) || (parameter.FloatRange.Maximum != nil && *d.Float > *parameter.FloatRange.Maximum)) {
		return fmt.Errorf("%w: parameter %q float default is outside its range", ErrInvalidCatalog, parameter.ID)
	}
	if d.String != nil && parameter.Kind == ParameterString && parameter.StringRange != nil {
		length := int64(len([]rune(*d.String)))
		if (parameter.StringRange.MinimumLength != nil && length < *parameter.StringRange.MinimumLength) || (parameter.StringRange.MaximumLength != nil && length > *parameter.StringRange.MaximumLength) {
			return fmt.Errorf("%w: parameter %q string default is outside its length range", ErrInvalidCatalog, parameter.ID)
		}
	}
	if d.String != nil && parameter.Kind != ParameterString && !containsExactString(parameter.AllowedValues, *d.String) {
		return fmt.Errorf("%w: parameter %q string default is not allowed", ErrInvalidCatalog, parameter.ID)
	}
	if d.ResourceRole != nil && !containsMediaRole(parameter.AllowedResourceRoles, *d.ResourceRole) {
		return fmt.Errorf("%w: parameter %q resource-role default is not allowed", ErrInvalidCatalog, parameter.ID)
	}
	return nil
}

// validate verifies one rule references only declared parameters and one valid enum trigger.
// validate 校验一条规则只引用已声明参数和一个有效枚举触发值。
func (r ParameterRule) validate(parameters map[string]ParameterDescriptor) error {
	if r.Kind != ParameterRuleMutuallyExclusive && r.Kind != ParameterRuleRequires && r.Kind != ParameterRuleForbids && r.Kind != ParameterRuleRequiresWhenEnum {
		return fmt.Errorf("%w: invalid parameter rule kind %q", ErrInvalidCatalog, r.Kind)
	}
	controller, exists := parameters[r.ParameterID]
	if !exists || len(r.RelatedParameterIDs) == 0 {
		return fmt.Errorf("%w: parameter rule references an undeclared controller or no related parameters", ErrInvalidCatalog)
	}
	seen := make(map[string]struct{}, len(r.RelatedParameterIDs))
	for _, identifier := range r.RelatedParameterIDs {
		if identifier == r.ParameterID {
			return fmt.Errorf("%w: parameter rule cannot reference itself", ErrInvalidCatalog)
		}
		if _, exists := parameters[identifier]; !exists {
			return fmt.Errorf("%w: parameter rule references undeclared parameter %q", ErrInvalidCatalog, identifier)
		}
		if _, exists := seen[identifier]; exists {
			return fmt.Errorf("%w: parameter rule duplicates related parameter %q", ErrInvalidCatalog, identifier)
		}
		seen[identifier] = struct{}{}
	}
	if r.Kind == ParameterRuleRequiresWhenEnum {
		if controller.Kind != ParameterEnum || strings.TrimSpace(r.EnumValue) == "" || !containsExactString(controller.AllowedValues, r.EnumValue) {
			return fmt.Errorf("%w: conditional parameter rule requires a declared enum value", ErrInvalidCatalog)
		}
	} else if r.EnumValue != "" {
		return fmt.Errorf("%w: unconditional parameter rule cannot carry an enum value", ErrInvalidCatalog)
	}
	return nil
}

// validParameterKind reports whether one parameter kind belongs to the closed contract.
// validParameterKind 报告一个参数类型是否属于封闭合同。
func validParameterKind(kind ParameterKind) bool {
	return kind == ParameterString || kind == ParameterStringList || kind == ParameterBoolean || kind == ParameterInteger || kind == ParameterFloat || kind == ParameterEnum || kind == ParameterSize || kind == ParameterDuration || kind == ParameterFormat || kind == ParameterCount || kind == ParameterResourceRole
}

// containsExactString reports whether a list contains one exact declared value.
// containsExactString 报告列表是否包含一个精确声明值。
func containsExactString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// containsMediaRole reports whether a list contains one exact media role.
// containsMediaRole 报告列表是否包含一个精确媒体角色。
func containsMediaRole(values []vcp.MediaInputRole, target vcp.MediaInputRole) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// validUsageUnit reports whether one unit belongs to the closed accounting set.
// validUsageUnit 报告一个单位是否属于封闭计量集合。
func validUsageUnit(unit UsageUnit) bool {
	switch unit {
	case UsageUnitInputTokens, UsageUnitOutputTokens, UsageUnitReasoningTokens, UsageUnitCharacters, UsageUnitAudioMilliseconds, UsageUnitVideoMilliseconds, UsageUnitImages, UsageUnitPixels, UsageUnitEmbeddingInputs, UsageUnitVectors, UsageUnitRerankCandidates, UsageUnitSearchQueries, UsageUnitSearchResults, UsageUnitProviderTasks:
		return true
	default:
		return false
	}
}
