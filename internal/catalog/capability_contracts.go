package catalog

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// OptionalLimit represents an authoritative non-negative limit or an explicitly unknown value.
// OptionalLimit 表示一个权威非负限制或显式未知值。
type OptionalLimit struct {
	// Known reports whether Value is authoritative.
	// Known 表示 Value 是否具有权威性。
	Known bool `json:"known"`
	// Value is the non-negative limit when Known is true.
	// Value 是 Known 为真时的非负限制。
	Value int64 `json:"value"`
}

// OptionalBool represents an authoritative boolean or an explicitly unknown value.
// OptionalBool 表示一个权威布尔值或显式未知值。
type OptionalBool struct {
	// Known reports whether Value is authoritative.
	// Known 表示 Value 是否具有权威性。
	Known bool `json:"known"`
	// Value is the authoritative boolean when Known is true.
	// Value 是 Known 为真时的权威布尔值。
	Value bool `json:"value"`
}

// MediaInteractionMode identifies one client-visible media interaction shape.
// MediaInteractionMode 标识一种客户端可见媒体交互形态。
type MediaInteractionMode string

const (
	// MediaInteractionMixedConversation combines text and media in a conversation.
	// MediaInteractionMixedConversation 在会话中组合文字与媒体。
	MediaInteractionMixedConversation MediaInteractionMode = "mixed_conversation"
	// MediaInteractionMediaOnlyConversation permits one media-only conversation turn.
	// MediaInteractionMediaOnlyConversation 允许仅含媒体的单轮会话。
	MediaInteractionMediaOnlyConversation MediaInteractionMode = "media_only_conversation"
	// MediaInteractionAnalysis uses the dedicated media analysis operation.
	// MediaInteractionAnalysis 使用专用媒体分析操作。
	MediaInteractionAnalysis MediaInteractionMode = "media_analysis"
	// MediaInteractionOperationInput supplies a resource to a dedicated non-conversation operation.
	// MediaInteractionOperationInput 向专用非会话操作提供资源。
	MediaInteractionOperationInput MediaInteractionMode = "operation_input"
)

// MediaOnlyPolicy identifies how omitted companion text is handled for conversation or dedicated-operation media input.
// MediaOnlyPolicy 标识会话或专用操作媒体输入省略伴随文字时的处理方式。
type MediaOnlyPolicy string

const (
	// MediaOnlyUnsupported forbids media input without companion text.
	// MediaOnlyUnsupported 禁止不带伴随文字的媒体输入。
	MediaOnlyUnsupported MediaOnlyPolicy = "unsupported"
	// MediaOnlyNative permits the upstream's documented implicit media instruction.
	// MediaOnlyNative 允许上游记录的隐式媒体指令。
	MediaOnlyNative MediaOnlyPolicy = "native"
	// MediaOnlyRouterInstruction uses a versioned Router-owned implicit instruction.
	// MediaOnlyRouterInstruction 使用版本化 Router 所有隐式指令。
	MediaOnlyRouterInstruction MediaOnlyPolicy = "router_instruction"
)

// ClientResourceWorkflow identifies how Vulcan creates a Router resource reference.
// ClientResourceWorkflow 标识 Vulcan 如何创建 Router 资源引用。
type ClientResourceWorkflow string

const (
	// ClientWorkflowUploadThenReference uploads bytes before execution.
	// ClientWorkflowUploadThenReference 在执行前上传字节。
	ClientWorkflowUploadThenReference ClientResourceWorkflow = "upload_then_reference"
	// ClientWorkflowImportURLThenReference imports an authorized URL before execution.
	// ClientWorkflowImportURLThenReference 在执行前导入已授权 URL。
	ClientWorkflowImportURLThenReference ClientResourceWorkflow = "import_url_then_reference"
	// ClientWorkflowImportBase64ThenReference imports bounded Base64 before execution.
	// ClientWorkflowImportBase64ThenReference 在执行前导入受限 Base64。
	ClientWorkflowImportBase64ThenReference ClientResourceWorkflow = "import_base64_then_reference"
	// ClientWorkflowResolveInputPlan requires resource-aware planning before execution.
	// ClientWorkflowResolveInputPlan 要求在执行前进行资源感知规划。
	ClientWorkflowResolveInputPlan ClientResourceWorkflow = "resolve_input_plan"
)

// UpstreamMaterializationMode identifies one safe Router-to-provider representation.
// UpstreamMaterializationMode 标识一种安全的 Router 到供应商表示。
type UpstreamMaterializationMode string

const (
	// MaterializationInlineBase64 sends bounded inline Base64.
	// MaterializationInlineBase64 发送受限内联 Base64。
	MaterializationInlineBase64 UpstreamMaterializationMode = "inline_base64"
	// MaterializationDirectRemoteURL sends a validated remote URL.
	// MaterializationDirectRemoteURL 发送已校验远程 URL。
	MaterializationDirectRemoteURL UpstreamMaterializationMode = "direct_remote_url"
	// MaterializationProviderFileID sends a Router-managed provider file identifier.
	// MaterializationProviderFileID 发送 Router 管理的供应商文件标识。
	MaterializationProviderFileID UpstreamMaterializationMode = "provider_file_id"
	// MaterializationProviderAssetID sends a Router-managed provider asset identifier.
	// MaterializationProviderAssetID 发送 Router 管理的供应商资产标识。
	MaterializationProviderAssetID UpstreamMaterializationMode = "provider_asset_id"
	// MaterializationProviderObjectURI sends a provider-authorized object URI.
	// MaterializationProviderObjectURI 发送供应商授权对象 URI。
	MaterializationProviderObjectURI UpstreamMaterializationMode = "provider_object_uri"
	// MaterializationFrameSequence projects video into provider-supported frames.
	// MaterializationFrameSequence 将视频投影为供应商支持的帧序列。
	MaterializationFrameSequence UpstreamMaterializationMode = "frame_sequence_projection"
	// MaterializationAudioTrack projects an embedded audio track.
	// MaterializationAudioTrack 投影内嵌音轨。
	MaterializationAudioTrack UpstreamMaterializationMode = "audio_track_projection"
)

// CommonMediaLimits contains limits shared by all Router resources.
// CommonMediaLimits 包含所有 Router 资源共享的限制。
type CommonMediaLimits struct {
	// MIMETypes lists exact accepted normalized MIME types.
	// MIMETypes 列出精确接受的规范 MIME 类型。
	MIMETypes []string `json:"mime_types"`
	// MaxItemBytes is the maximum bytes per resource.
	// MaxItemBytes 是每个资源的最大字节数。
	MaxItemBytes OptionalLimit `json:"max_item_bytes"`
	// MaxTotalBytes is the maximum bytes for the operation.
	// MaxTotalBytes 是操作的最大总字节数。
	MaxTotalBytes OptionalLimit `json:"max_total_bytes"`
	// MaxItems is the maximum resource count.
	// MaxItems 是最大资源数量。
	MaxItems OptionalLimit `json:"max_items"`
	// AllowsRemoteURL reports whether URL import may remain a direct URL upstream.
	// AllowsRemoteURL 表示 URL 导入是否可在上游保持直接 URL。
	AllowsRemoteURL OptionalBool `json:"allows_remote_url"`
}

// ImageDimensions identifies one exact supported image width and height pair.
// ImageDimensions 标识一个精确支持的图片宽高组合。
type ImageDimensions struct {
	// Width is the exact supported pixel width.
	// Width 是精确支持的像素宽度。
	Width int64 `json:"width"`
	// Height is the exact supported pixel height.
	// Height 是精确支持的像素高度。
	Height int64 `json:"height"`
}

// ImageAspectRatioLimit stores one exact maximum long-edge to short-edge ratio.
// ImageAspectRatioLimit 存储一个精确的最长边与最短边最大比例。
type ImageAspectRatioLimit struct {
	// Known reports whether the ratio is authoritative.
	// Known 表示该比例是否具有权威性。
	Known bool `json:"known"`
	// LongEdge is the ratio numerator when known.
	// LongEdge 是已知比例的分子。
	LongEdge int64 `json:"long_edge,omitempty"`
	// ShortEdge is the ratio denominator when known.
	// ShortEdge 是已知比例的分母。
	ShortEdge int64 `json:"short_edge,omitempty"`
}

// ImageMediaLimits contains authoritative image constraints.
// ImageMediaLimits 包含权威图片约束。
type ImageMediaLimits struct {
	// MinWidth is the minimum pixel width.
	// MinWidth 是最小像素宽度。
	MinWidth OptionalLimit `json:"min_width"`
	// MaxWidth is the maximum pixel width.
	// MaxWidth 是最大像素宽度。
	MaxWidth OptionalLimit `json:"max_width"`
	// MinHeight is the minimum pixel height.
	// MinHeight 是最小像素高度。
	MinHeight OptionalLimit `json:"min_height"`
	// MaxHeight is the maximum pixel height.
	// MaxHeight 是最大像素高度。
	MaxHeight OptionalLimit `json:"max_height"`
	// WidthMultipleOf requires widths to be an exact multiple when known.
	// WidthMultipleOf 在已知时要求宽度为指定值的整数倍。
	WidthMultipleOf OptionalLimit `json:"width_multiple_of"`
	// HeightMultipleOf requires heights to be an exact multiple when known.
	// HeightMultipleOf 在已知时要求高度为指定值的整数倍。
	HeightMultipleOf OptionalLimit `json:"height_multiple_of"`
	// MinPixels is the minimum total pixel count.
	// MinPixels 是最小总像素数。
	MinPixels OptionalLimit `json:"min_pixels"`
	// MaxPixels is the maximum total pixel count.
	// MaxPixels 是最大总像素数。
	MaxPixels OptionalLimit `json:"max_pixels"`
	// MaxLongToShortRatio is the maximum allowed long-edge to short-edge ratio.
	// MaxLongToShortRatio 是允许的最长边与最短边最大比例。
	MaxLongToShortRatio ImageAspectRatioLimit `json:"max_long_to_short_ratio"`
	// AllowedDimensions lists exact supported width and height pairs when the provider exposes a closed size set.
	// AllowedDimensions 在供应商公开封闭尺寸集合时列出精确支持的宽高组合。
	AllowedDimensions []ImageDimensions `json:"allowed_dimensions,omitempty"`
	// Animated reports animated-image support.
	// Animated 表示是否支持动画图片。
	Animated OptionalBool `json:"animated"`
	// Transparency reports alpha-channel support.
	// Transparency 表示是否支持透明通道。
	Transparency OptionalBool `json:"transparency"`
	// RequiresAlpha requires an authoritative alpha channel for every input governed by this capability.
	// RequiresAlpha 要求此能力约束的每个输入都具有权威 Alpha 通道。
	RequiresAlpha bool `json:"requires_alpha,omitempty"`
	// MustMatchFormatAndDimensionsOfRole requires exact format and dimensions equality with the first input of another role.
	// MustMatchFormatAndDimensionsOfRole 要求与另一角色的首个输入具有完全相同的格式和尺寸。
	MustMatchFormatAndDimensionsOfRole vcp.MediaInputRole `json:"must_match_format_and_dimensions_of_role,omitempty"`
}

// AudioMediaLimits contains authoritative audio constraints.
// AudioMediaLimits 包含权威音频约束。
type AudioMediaLimits struct {
	// MaxDurationMilliseconds is the maximum duration.
	// MaxDurationMilliseconds 是最大时长。
	MaxDurationMilliseconds OptionalLimit `json:"max_duration_milliseconds"`
	// MaxSampleRateHz is the maximum sample rate.
	// MaxSampleRateHz 是最大采样率。
	MaxSampleRateHz OptionalLimit `json:"max_sample_rate_hz"`
	// MaxChannels is the maximum channel count.
	// MaxChannels 是最大声道数。
	MaxChannels OptionalLimit `json:"max_channels"`
	// Encodings lists exact accepted codecs or encodings.
	// Encodings 列出精确接受的编码。
	Encodings []string `json:"encodings"`
}

// VideoMediaLimits contains authoritative video constraints.
// VideoMediaLimits 包含权威视频约束。
type VideoMediaLimits struct {
	// MaxDurationMilliseconds is the maximum duration.
	// MaxDurationMilliseconds 是最大时长。
	MaxDurationMilliseconds OptionalLimit `json:"max_duration_milliseconds"`
	// MaxWidth is the maximum frame width.
	// MaxWidth 是最大帧宽度。
	MaxWidth OptionalLimit `json:"max_width"`
	// MaxHeight is the maximum frame height.
	// MaxHeight 是最大帧高度。
	MaxHeight OptionalLimit `json:"max_height"`
	// MaxFrames is the maximum decoded frame count.
	// MaxFrames 是最大解码帧数。
	MaxFrames OptionalLimit `json:"max_frames"`
	// MaxFPS is the maximum frame rate.
	// MaxFPS 是最大帧率。
	MaxFPS OptionalLimit `json:"max_fps"`
	// Codecs lists exact accepted video codecs.
	// Codecs 列出精确接受的视频编码。
	Codecs []string `json:"codecs"`
	// Containers lists exact accepted container formats.
	// Containers 列出精确接受的封装格式。
	Containers []string `json:"containers"`
	// EmbeddedAudio describes whether an embedded audio track is understood.
	// EmbeddedAudio 描述是否理解内嵌音轨。
	EmbeddedAudio OptionalBool `json:"embedded_audio"`
}

// MediaCompatibility declares operation features that may coexist with media input.
// MediaCompatibility 声明可与媒体输入共存的操作特性。
type MediaCompatibility struct {
	// ToolCalling reports tool compatibility.
	// ToolCalling 表示工具兼容性。
	ToolCalling CapabilityLevel `json:"tool_calling"`
	// Streaming reports semantic streaming compatibility.
	// Streaming 表示语义流式兼容性。
	Streaming CapabilityLevel `json:"streaming"`
	// Reasoning reports reasoning compatibility.
	// Reasoning 表示推理兼容性。
	Reasoning CapabilityLevel `json:"reasoning"`
	// StructuredOutput reports structured-output compatibility.
	// StructuredOutput 表示结构化输出兼容性。
	StructuredOutput CapabilityLevel `json:"structured_output"`
	// RequiresText reports whether at least one text block is mandatory.
	// RequiresText 表示是否必须至少提供一个文字块。
	RequiresText bool `json:"requires_text"`
}

// CapabilityEvidence records one auditable capability fact source.
// CapabilityEvidence 记录一个可审计能力事实来源。
type CapabilityEvidence struct {
	// Source identifies system, provider API, discovery, or runtime evidence.
	// Source 标识系统、供应商 API、发现或运行证据。
	Source ModelSource `json:"source"`
	// Reference identifies the official document, fixture, or code-owned evidence record.
	// Reference 标识官方文档、夹具或代码拥有证据记录。
	Reference string `json:"reference"`
	// ObservedAt records when the evidence was checked.
	// ObservedAt 记录证据核对时间。
	ObservedAt time.Time `json:"observed_at"`
	// ExpiresAt optionally records evidence expiry.
	// ExpiresAt 可选地记录证据失效时间。
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// Revision freezes the interpreted evidence.
	// Revision 冻结解释后的证据。
	Revision uint64 `json:"revision"`
}

// GeneratedSourceRequirement declares when an input must originate from a prior Router generation.
// GeneratedSourceRequirement 声明输入何时必须来源于先前的 Router 生成。
type GeneratedSourceRequirement struct {
	// Required reports that imported or uploaded arbitrary bytes are insufficient.
	// Required 表示导入或上传的任意字节不足以满足要求。
	Required bool `json:"required"`
	// SameProviderDefinition requires the code-owned provider boundary to match.
	// SameProviderDefinition 要求代码拥有的供应商边界一致。
	SameProviderDefinition bool `json:"same_provider_definition"`
	// AllowedOperations lists prior canonical operations that may produce the input.
	// AllowedOperations 列出可以产出该输入的先前规范操作。
	AllowedOperations []vcp.OperationKind `json:"allowed_operations"`
	// AllowedUpstreamModels lists exact prior provider model handles.
	// AllowedUpstreamModels 列出精确的先前供应商模型句柄。
	AllowedUpstreamModels []string `json:"allowed_upstream_models"`
}

// Validate verifies one complete closed generated-source constraint.
// Validate 校验一个完整且封闭的生成来源约束。
func (r GeneratedSourceRequirement) Validate() error {
	if !r.Required || !r.SameProviderDefinition || len(r.AllowedOperations) == 0 || len(r.AllowedUpstreamModels) == 0 {
		return fmt.Errorf("%w: generated-source requirement must be complete", ErrInvalidCatalog)
	}
	// seenOperations rejects ambiguous duplicate origin declarations.
	// seenOperations 拒绝含糊的重复来源声明。
	seenOperations := make(map[vcp.OperationKind]struct{}, len(r.AllowedOperations))
	for _, operation := range r.AllowedOperations {
		if operation != vcp.OperationVideoGenerate && operation != vcp.OperationVideoExtend {
			return fmt.Errorf("%w: generated-source operation %q is invalid", ErrInvalidCatalog, operation)
		}
		if _, exists := seenOperations[operation]; exists {
			return fmt.Errorf("%w: duplicate generated-source operation %q", ErrInvalidCatalog, operation)
		}
		seenOperations[operation] = struct{}{}
	}
	return validateUniqueStrings("generated-source upstream model", r.AllowedUpstreamModels)
}

// MediaInputCapability describes one media kind without modality-keyed untyped maps.
// MediaInputCapability 描述一种媒体类型，且不使用按模态键控的无类型映射。
type MediaInputCapability struct {
	// Kind identifies the sole media family.
	// Kind 标识唯一媒体类别。
	Kind vcp.MediaKind `json:"kind"`
	// Roles lists accepted semantic resource roles.
	// Roles 列出接受的语义资源角色。
	Roles []vcp.MediaInputRole `json:"roles"`
	// Level reports native, emulated, conditional, unsupported, or unknown support.
	// Level 表示原生、模拟、条件、不支持或未知支持。
	Level CapabilityLevel `json:"level"`
	// InteractionModes lists accepted conversation and analysis shapes.
	// InteractionModes 列出接受的会话和分析形态。
	InteractionModes []MediaInteractionMode `json:"interaction_modes"`
	// MediaOnlyPolicy controls omitted text in media-only conversation.
	// MediaOnlyPolicy 控制媒体单独会话中省略的文字。
	MediaOnlyPolicy MediaOnlyPolicy `json:"media_only_policy"`
	// AllowedAuthorities lists accepted VCP message authorities.
	// AllowedAuthorities 列出接受的 VCP 消息权限角色。
	AllowedAuthorities []vcp.Authority `json:"allowed_authorities"`
	// AllowedPlacements lists accepted VCP context placements.
	// AllowedPlacements 列出接受的 VCP 上下文位置。
	AllowedPlacements []vcp.Placement `json:"allowed_placements"`
	// ClientWorkflows lists supported Router resource creation workflows.
	// ClientWorkflows 列出支持的 Router 资源创建工作流。
	ClientWorkflows []ClientResourceWorkflow `json:"client_workflows"`
	// MaterializationModes lists safe upstream representations.
	// MaterializationModes 列出安全上游表示。
	MaterializationModes []UpstreamMaterializationMode `json:"materialization_modes"`
	// GeneratedSource constrains inputs that must come from prior Router generation.
	// GeneratedSource 约束必须来自先前 Router 生成的输入。
	GeneratedSource *GeneratedSourceRequirement `json:"generated_source,omitempty"`
	// Common contains cross-media limits.
	// Common 包含跨媒体通用限制。
	Common CommonMediaLimits `json:"common"`
	// Image contains image-only limits when Kind is image.
	// Image 在 Kind 为图片时包含图片专用限制。
	Image *ImageMediaLimits `json:"image,omitempty"`
	// Audio contains audio-only limits when Kind is audio.
	// Audio 在 Kind 为音频时包含音频专用限制。
	Audio *AudioMediaLimits `json:"audio,omitempty"`
	// Video contains video-only limits when Kind is video.
	// Video 在 Kind 为视频时包含视频专用限制。
	Video *VideoMediaLimits `json:"video,omitempty"`
	// Compatibility contains feature-combination rules.
	// Compatibility 包含特性组合规则。
	Compatibility MediaCompatibility `json:"compatibility"`
	// Evidence contains auditable sources for this capability.
	// Evidence 包含此能力的可审计来源。
	Evidence []CapabilityEvidence `json:"evidence"`
	// EvidenceRevision freezes the complete interpreted capability.
	// EvidenceRevision 冻结完整解释后的能力。
	EvidenceRevision uint64 `json:"evidence_revision"`
}

// DeliveryCapabilities declares real execution delivery modes.
// DeliveryCapabilities 声明真实执行交付模式。
type DeliveryCapabilities struct {
	// Synchronous reports immediate completion support.
	// Synchronous 表示支持立即完成。
	Synchronous bool `json:"synchronous"`
	// Streaming reports real semantic event support.
	// Streaming 表示支持真实语义事件。
	Streaming bool `json:"streaming"`
	// Asynchronous reports provider task support.
	// Asynchronous 表示支持供应商任务。
	Asynchronous bool `json:"asynchronous"`
	// Polling reports whether Router exposes task polling for this output.
	// Polling 表示 Router 是否为此输出公开任务轮询。
	Polling bool `json:"polling"`
	// Cancellation reports whether Router can request provider task cancellation.
	// Cancellation 表示 Router 是否可以请求供应商任务取消。
	Cancellation bool `json:"cancellation"`
	// PartialResults reports provider-backed intermediate results.
	// PartialResults 表示支持供应商提供的中间结果。
	PartialResults bool `json:"partial_results"`
}

// EmbeddingCapabilities describes exact vectorization constraints.
// EmbeddingCapabilities 描述精确向量化约束。
type EmbeddingCapabilities struct {
	// InputTasks lists accepted semantic tasks.
	// InputTasks 列出接受的语义任务。
	InputTasks []vcp.EmbeddingInputTask `json:"input_tasks"`
	// OutputKinds lists accepted vector representations.
	// OutputKinds 列出接受的向量表示。
	OutputKinds []vcp.EmbeddingVectorKind `json:"output_kinds"`
	// Encodings lists accepted output encodings.
	// Encodings 列出接受的输出编码。
	Encodings []vcp.EmbeddingEncoding `json:"encodings"`
	// Dimensions lists exact selectable dense dimensions.
	// Dimensions 列出可选择的精确稠密维度。
	Dimensions []int `json:"dimensions"`
	// DefaultDimensions is the provider or Router documented default.
	// DefaultDimensions 是供应商或 Router 记录的默认维度。
	DefaultDimensions OptionalLimit `json:"default_dimensions"`
	// MinDimensions is the minimum selectable dense dimension when a range is documented.
	// MinDimensions 是记录了范围时可选择的最小稠密维度。
	MinDimensions OptionalLimit `json:"min_dimensions"`
	// MaxDimensions is the maximum selectable dense dimension when a range is documented.
	// MaxDimensions 是记录了范围时可选择的最大稠密维度。
	MaxDimensions OptionalLimit `json:"max_dimensions"`
	// MaxBatchItems is the maximum ordered input count.
	// MaxBatchItems 是最大有序输入数量。
	MaxBatchItems OptionalLimit `json:"max_batch_items"`
	// ResourceKinds lists media kinds accepted for multimodal embeddings.
	// ResourceKinds 列出多模态 Embedding 接受的媒体类型。
	ResourceKinds []vcp.MediaKind `json:"resource_kinds"`
	// Normalized reports whether vectors are guaranteed normalized.
	// Normalized 表示是否保证向量已归一化。
	Normalized OptionalBool `json:"normalized"`
}

// RerankCapabilities describes exact candidate and score constraints.
// RerankCapabilities 描述精确候选项与分数约束。
type RerankCapabilities struct {
	// MaxCandidates is the maximum ordered candidate count.
	// MaxCandidates 是最大有序候选项数量。
	MaxCandidates OptionalLimit `json:"max_candidates"`
	// TruncationPolicies lists explicit supported truncation modes.
	// TruncationPolicies 列出明确支持的截断模式。
	TruncationPolicies []vcp.RerankTruncation `json:"truncation_policies"`
	// QueryResourceKinds lists media kinds accepted as queries.
	// QueryResourceKinds 列出可作为 Query 的媒体类型。
	QueryResourceKinds []vcp.MediaKind `json:"query_resource_kinds"`
	// CandidateResourceKinds lists media kinds accepted as candidates.
	// CandidateResourceKinds 列出可作为候选项的媒体类型。
	CandidateResourceKinds []vcp.MediaKind `json:"candidate_resource_kinds"`
	// ReturnContent reports whether results may include original content.
	// ReturnContent 表示结果是否可包含原始内容。
	ReturnContent bool `json:"return_content"`
	// ScoreSemantics preserves the provider-defined score meaning.
	// ScoreSemantics 保留供应商定义的分数含义。
	ScoreSemantics string `json:"score_semantics"`
}

// Validate verifies media, delivery, vector, and rerank contracts.
// Validate 校验媒体、交付、向量和重排契约。
func (c ModelCapabilities) validateExtended() error {
	// mediaRoleKey makes same-kind capabilities independently addressable when they own disjoint semantic roles.
	// mediaRoleKey 使拥有不相交语义角色的同类媒体能力可以独立寻址。
	type mediaRoleKey struct {
		kind vcp.MediaKind
		role vcp.MediaInputRole
	}
	seenMediaRoles := make(map[mediaRoleKey]struct{}, len(c.MediaInputs))
	seenRolelessKinds := make(map[vcp.MediaKind]struct{}, len(c.MediaInputs))
	for _, capability := range c.MediaInputs {
		if errValidate := capability.Validate(); errValidate != nil {
			return errValidate
		}
		if len(capability.Roles) == 0 {
			if _, exists := seenRolelessKinds[capability.Kind]; exists {
				return fmt.Errorf("%w: duplicate roleless media input capability %q", ErrInvalidCatalog, capability.Kind)
			}
			seenRolelessKinds[capability.Kind] = struct{}{}
			continue
		}
		for _, role := range capability.Roles {
			key := mediaRoleKey{kind: capability.Kind, role: role}
			if _, exists := seenMediaRoles[key]; exists {
				return fmt.Errorf("%w: duplicate media input capability %q for role %q", ErrInvalidCatalog, capability.Kind, role)
			}
			seenMediaRoles[key] = struct{}{}
		}
	}
	for _, capability := range c.MediaInputs {
		if capability.Image == nil || capability.Image.MustMatchFormatAndDimensionsOfRole == "" {
			continue
		}
		reference := mediaRoleKey{kind: capability.Kind, role: capability.Image.MustMatchFormatAndDimensionsOfRole}
		if _, exists := seenMediaRoles[reference]; !exists {
			return fmt.Errorf("%w: image matching role %q has no declared capability", ErrInvalidCatalog, capability.Image.MustMatchFormatAndDimensionsOfRole)
		}
	}
	if c.Embedding != nil {
		if errValidate := c.Embedding.Validate(); errValidate != nil {
			return errValidate
		}
	}
	if c.Rerank != nil {
		if errValidate := c.Rerank.Validate(); errValidate != nil {
			return errValidate
		}
	}
	return c.validateOutputAndParameters()
}

// Validate verifies one callable media capability and its explicit unknown limits.
// Validate 校验一个可调用媒体能力及其显式未知限制。
func (c MediaInputCapability) Validate() error {
	if c.Kind != vcp.MediaImage && c.Kind != vcp.MediaAudio && c.Kind != vcp.MediaVideo && c.Kind != vcp.MediaFile {
		return fmt.Errorf("%w: invalid media kind %q", ErrInvalidCatalog, c.Kind)
	}
	if !validCapabilityLevel(c.Level) || c.EvidenceRevision == 0 {
		return fmt.Errorf("%w: media capability level and evidence revision are required", ErrInvalidCatalog)
	}
	if c.Level != CapabilityUnsupported && c.Level != CapabilityUnknown && (len(c.Roles) == 0 || len(c.InteractionModes) == 0 || len(c.ClientWorkflows) == 0 || len(c.MaterializationModes) == 0 || len(c.Evidence) == 0) {
		return fmt.Errorf("%w: callable media capability requires roles, interactions, workflows, materialization, and evidence", ErrInvalidCatalog)
	}
	if errKinds := validateMediaSpecificLimits(c); errKinds != nil {
		return errKinds
	}
	if errLimits := validateCommonMediaLimits(c.Common); errLimits != nil {
		return errLimits
	}
	if errEnums := validateMediaCapabilityEnums(c); errEnums != nil {
		return errEnums
	}
	if c.GeneratedSource != nil {
		if c.Kind != vcp.MediaVideo {
			return fmt.Errorf("%w: generated-source requirements currently apply only to video inputs", ErrInvalidCatalog)
		}
		if errRequirement := c.GeneratedSource.Validate(); errRequirement != nil {
			return errRequirement
		}
	}
	for _, evidence := range c.Evidence {
		if !validModelSource(evidence.Source) || strings.TrimSpace(evidence.Reference) == "" || evidence.ObservedAt.IsZero() || evidence.Revision == 0 || (evidence.ExpiresAt != nil && evidence.ExpiresAt.Before(evidence.ObservedAt)) {
			return fmt.Errorf("%w: media capability evidence is invalid", ErrInvalidCatalog)
		}
	}
	return validateUniqueStrings("media MIME type", c.Common.MIMETypes)
}

// Validate verifies exact embedding options without inventing dimensions or batch limits.
// Validate 校验精确 Embedding 选项，且不虚构维度或批量限制。
func (c EmbeddingCapabilities) Validate() error {
	if len(c.InputTasks) == 0 || len(c.OutputKinds) == 0 || len(c.Encodings) == 0 {
		return fmt.Errorf("%w: embedding tasks, output kinds, and encodings are required", ErrInvalidCatalog)
	}
	if errLimit := validateOptionalLimit("embedding default dimensions", c.DefaultDimensions); errLimit != nil {
		return errLimit
	}
	if errLimit := validateOptionalLimit("embedding minimum dimensions", c.MinDimensions); errLimit != nil {
		return errLimit
	}
	if errLimit := validateOptionalLimit("embedding maximum dimensions", c.MaxDimensions); errLimit != nil {
		return errLimit
	}
	if c.MinDimensions.Known != c.MaxDimensions.Known || c.MinDimensions.Known && c.MinDimensions.Value > c.MaxDimensions.Value {
		return fmt.Errorf("%w: embedding dimension range must be complete and ordered", ErrInvalidCatalog)
	}
	if c.DefaultDimensions.Known && c.MinDimensions.Known && (c.DefaultDimensions.Value < c.MinDimensions.Value || c.DefaultDimensions.Value > c.MaxDimensions.Value) {
		return fmt.Errorf("%w: embedding default dimensions are outside the declared range", ErrInvalidCatalog)
	}
	if errLimit := validateOptionalLimit("embedding max batch items", c.MaxBatchItems); errLimit != nil {
		return errLimit
	}
	dimensions := append([]int(nil), c.Dimensions...)
	sort.Ints(dimensions)
	for index, dimension := range dimensions {
		if dimension <= 0 || (index > 0 && dimension == dimensions[index-1]) {
			return fmt.Errorf("%w: embedding dimensions must be positive and unique", ErrInvalidCatalog)
		}
		if c.MinDimensions.Known && (int64(dimension) < c.MinDimensions.Value || int64(dimension) > c.MaxDimensions.Value) {
			return fmt.Errorf("%w: embedding dimension %d is outside the declared range", ErrInvalidCatalog, dimension)
		}
	}
	if c.DefaultDimensions.Known && len(dimensions) > 0 && !containsInt(dimensions, int(c.DefaultDimensions.Value)) {
		return fmt.Errorf("%w: embedding default dimensions are not selectable", ErrInvalidCatalog)
	}
	if errEnums := validateEmbeddingEnums(c); errEnums != nil {
		return errEnums
	}
	return nil
}

// Validate verifies rerank limits and preserves a non-empty provider score definition.
// Validate 校验重排限制并保留非空供应商分数定义。
func (c RerankCapabilities) Validate() error {
	if errLimit := validateOptionalLimit("rerank max candidates", c.MaxCandidates); errLimit != nil {
		return errLimit
	}
	if strings.TrimSpace(c.ScoreSemantics) == "" || len(c.TruncationPolicies) == 0 {
		return fmt.Errorf("%w: rerank score semantics and truncation policies are required", ErrInvalidCatalog)
	}
	for _, policy := range c.TruncationPolicies {
		if policy != vcp.RerankTruncationNone && policy != vcp.RerankTruncationProvider {
			return fmt.Errorf("%w: invalid rerank truncation policy %q", ErrInvalidCatalog, policy)
		}
	}
	return nil
}

// validateMediaSpecificLimits enforces the exact media-kind limit union.
// validateMediaSpecificLimits 强制精确媒体类型限制联合体。
func validateMediaSpecificLimits(capability MediaInputCapability) error {
	count := 0
	if capability.Image != nil {
		count++
	}
	if capability.Audio != nil {
		count++
	}
	if capability.Video != nil {
		count++
	}
	if capability.Kind == vcp.MediaFile {
		if count != 0 {
			return fmt.Errorf("%w: file media cannot carry image, audio, or video limits", ErrInvalidCatalog)
		}
		return nil
	}
	if count != 1 || (capability.Kind == vcp.MediaImage && capability.Image == nil) || (capability.Kind == vcp.MediaAudio && capability.Audio == nil) || (capability.Kind == vcp.MediaVideo && capability.Video == nil) {
		return fmt.Errorf("%w: media capability requires exactly its matching limit variant", ErrInvalidCatalog)
	}
	if capability.Image != nil {
		for name, limit := range map[string]OptionalLimit{"image min width": capability.Image.MinWidth, "image max width": capability.Image.MaxWidth, "image min height": capability.Image.MinHeight, "image max height": capability.Image.MaxHeight, "image width multiple": capability.Image.WidthMultipleOf, "image height multiple": capability.Image.HeightMultipleOf, "image min pixels": capability.Image.MinPixels, "image max pixels": capability.Image.MaxPixels} {
			if errValidate := validateOptionalLimit(name, limit); errValidate != nil {
				return errValidate
			}
		}
		if capability.Image.MinWidth.Known && capability.Image.MaxWidth.Known && capability.Image.MinWidth.Value > capability.Image.MaxWidth.Value {
			return fmt.Errorf("%w: image minimum width exceeds maximum width", ErrInvalidCatalog)
		}
		if capability.Image.MinHeight.Known && capability.Image.MaxHeight.Known && capability.Image.MinHeight.Value > capability.Image.MaxHeight.Value {
			return fmt.Errorf("%w: image minimum height exceeds maximum height", ErrInvalidCatalog)
		}
		if capability.Image.MinPixels.Known && capability.Image.MaxPixels.Known && capability.Image.MinPixels.Value > capability.Image.MaxPixels.Value {
			return fmt.Errorf("%w: image minimum pixels exceed maximum pixels", ErrInvalidCatalog)
		}
		ratio := capability.Image.MaxLongToShortRatio
		if (ratio.Known && (ratio.LongEdge <= 0 || ratio.ShortEdge <= 0 || ratio.LongEdge < ratio.ShortEdge)) || (!ratio.Known && (ratio.LongEdge != 0 || ratio.ShortEdge != 0)) {
			return fmt.Errorf("%w: image aspect ratio limit must be known-positive or explicitly unknown", ErrInvalidCatalog)
		}
		if capability.Image.MustMatchFormatAndDimensionsOfRole != "" && !validMediaRole(capability.Image.MustMatchFormatAndDimensionsOfRole) {
			return fmt.Errorf("%w: image matching role is invalid", ErrInvalidCatalog)
		}
		seenDimensions := make(map[ImageDimensions]struct{}, len(capability.Image.AllowedDimensions))
		for _, dimensions := range capability.Image.AllowedDimensions {
			if dimensions.Width <= 0 || dimensions.Height <= 0 {
				return fmt.Errorf("%w: allowed image dimensions must be positive", ErrInvalidCatalog)
			}
			if _, exists := seenDimensions[dimensions]; exists {
				return fmt.Errorf("%w: duplicate allowed image dimensions %dx%d", ErrInvalidCatalog, dimensions.Width, dimensions.Height)
			}
			seenDimensions[dimensions] = struct{}{}
		}
	}
	if capability.Audio != nil {
		for name, limit := range map[string]OptionalLimit{"audio max duration": capability.Audio.MaxDurationMilliseconds, "audio max sample rate": capability.Audio.MaxSampleRateHz, "audio max channels": capability.Audio.MaxChannels} {
			if errValidate := validateOptionalLimit(name, limit); errValidate != nil {
				return errValidate
			}
		}
		if errEncodings := validateUniqueStrings("audio encoding", capability.Audio.Encodings); errEncodings != nil {
			return errEncodings
		}
	}
	if capability.Video != nil {
		for name, limit := range map[string]OptionalLimit{"video max duration": capability.Video.MaxDurationMilliseconds, "video max width": capability.Video.MaxWidth, "video max height": capability.Video.MaxHeight, "video max frames": capability.Video.MaxFrames, "video max FPS": capability.Video.MaxFPS} {
			if errValidate := validateOptionalLimit(name, limit); errValidate != nil {
				return errValidate
			}
		}
		if errCodecs := validateUniqueStrings("video codec", capability.Video.Codecs); errCodecs != nil {
			return errCodecs
		}
		if errContainers := validateUniqueStrings("video container", capability.Video.Containers); errContainers != nil {
			return errContainers
		}
	}
	return nil
}

// validateMediaCapabilityEnums verifies closed media lists and rejects duplicate semantic values.
// validateMediaCapabilityEnums 校验封闭媒体列表并拒绝重复语义值。
func validateMediaCapabilityEnums(capability MediaInputCapability) error {
	roles := make(map[vcp.MediaInputRole]struct{}, len(capability.Roles))
	for _, role := range capability.Roles {
		if !validMediaRole(role) {
			return fmt.Errorf("%w: invalid media input role %q", ErrInvalidCatalog, role)
		}
		if _, exists := roles[role]; exists {
			return fmt.Errorf("%w: duplicate media input role %q", ErrInvalidCatalog, role)
		}
		roles[role] = struct{}{}
	}
	interactions := make(map[MediaInteractionMode]struct{}, len(capability.InteractionModes))
	for _, interaction := range capability.InteractionModes {
		if interaction != MediaInteractionMixedConversation && interaction != MediaInteractionMediaOnlyConversation && interaction != MediaInteractionAnalysis && interaction != MediaInteractionOperationInput {
			return fmt.Errorf("%w: invalid media interaction mode %q", ErrInvalidCatalog, interaction)
		}
		if _, exists := interactions[interaction]; exists {
			return fmt.Errorf("%w: duplicate media interaction mode %q", ErrInvalidCatalog, interaction)
		}
		interactions[interaction] = struct{}{}
	}
	if capability.MediaOnlyPolicy != MediaOnlyUnsupported && capability.MediaOnlyPolicy != MediaOnlyNative && capability.MediaOnlyPolicy != MediaOnlyRouterInstruction {
		return fmt.Errorf("%w: invalid media-only policy %q", ErrInvalidCatalog, capability.MediaOnlyPolicy)
	}
	_, allowsMediaOnlyConversation := interactions[MediaInteractionMediaOnlyConversation]
	_, allowsOperationInput := interactions[MediaInteractionOperationInput]
	if !allowsMediaOnlyConversation && !allowsOperationInput && capability.MediaOnlyPolicy != MediaOnlyUnsupported {
		return fmt.Errorf("%w: media-only policy requires media-only interaction support", ErrInvalidCatalog)
	}
	if capability.MediaOnlyPolicy == MediaOnlyRouterInstruction && !allowsMediaOnlyConversation {
		return fmt.Errorf("%w: Router media-only instructions require conversation interaction support", ErrInvalidCatalog)
	}
	for _, authority := range capability.AllowedAuthorities {
		if authority != vcp.AuthoritySystem && authority != vcp.AuthorityDeveloper && authority != vcp.AuthorityUser && authority != vcp.AuthorityAssistant && authority != vcp.AuthorityTool && authority != vcp.AuthorityNone {
			return fmt.Errorf("%w: invalid media authority %q", ErrInvalidCatalog, authority)
		}
	}
	for _, placement := range capability.AllowedPlacements {
		if placement != vcp.PlacementPreamble && placement != vcp.PlacementTranscript {
			return fmt.Errorf("%w: invalid media placement %q", ErrInvalidCatalog, placement)
		}
	}
	for _, workflow := range capability.ClientWorkflows {
		if workflow != ClientWorkflowUploadThenReference && workflow != ClientWorkflowImportURLThenReference && workflow != ClientWorkflowImportBase64ThenReference && workflow != ClientWorkflowResolveInputPlan {
			return fmt.Errorf("%w: invalid client resource workflow %q", ErrInvalidCatalog, workflow)
		}
	}
	for _, mode := range capability.MaterializationModes {
		if mode != MaterializationInlineBase64 && mode != MaterializationDirectRemoteURL && mode != MaterializationProviderFileID && mode != MaterializationProviderAssetID && mode != MaterializationProviderObjectURI && mode != MaterializationFrameSequence && mode != MaterializationAudioTrack {
			return fmt.Errorf("%w: invalid upstream materialization mode %q", ErrInvalidCatalog, mode)
		}
	}
	for _, level := range []CapabilityLevel{capability.Compatibility.ToolCalling, capability.Compatibility.Streaming, capability.Compatibility.Reasoning, capability.Compatibility.StructuredOutput} {
		if !validCapabilityLevel(level) {
			return fmt.Errorf("%w: invalid media compatibility level %q", ErrInvalidCatalog, level)
		}
	}
	return nil
}

// validateEmbeddingEnums verifies every closed embedding option.
// validateEmbeddingEnums 校验每个封闭 Embedding 选项。
func validateEmbeddingEnums(capability EmbeddingCapabilities) error {
	for _, task := range capability.InputTasks {
		switch task {
		case vcp.EmbeddingTaskProviderDefault, vcp.EmbeddingTaskQuery, vcp.EmbeddingTaskDocument, vcp.EmbeddingTaskSemanticSimilarity, vcp.EmbeddingTaskClassification, vcp.EmbeddingTaskClustering, vcp.EmbeddingTaskCodeRetrieval:
		default:
			return fmt.Errorf("%w: invalid embedding input task %q", ErrInvalidCatalog, task)
		}
	}
	for _, kind := range capability.OutputKinds {
		if kind != vcp.EmbeddingVectorDense && kind != vcp.EmbeddingVectorSparse && kind != vcp.EmbeddingVectorMulti {
			return fmt.Errorf("%w: invalid embedding output kind %q", ErrInvalidCatalog, kind)
		}
	}
	for _, encoding := range capability.Encodings {
		if encoding != vcp.EmbeddingEncodingFloat && encoding != vcp.EmbeddingEncodingBase64 {
			return fmt.Errorf("%w: invalid embedding encoding %q", ErrInvalidCatalog, encoding)
		}
	}
	for _, kind := range capability.ResourceKinds {
		if kind != vcp.MediaImage && kind != vcp.MediaAudio && kind != vcp.MediaVideo && kind != vcp.MediaFile {
			return fmt.Errorf("%w: invalid embedding resource kind %q", ErrInvalidCatalog, kind)
		}
	}
	return nil
}

// validMediaRole reports whether one VCP resource role belongs to the closed protocol set.
// validMediaRole 报告一个 VCP 资源角色是否属于封闭协议集合。
func validMediaRole(role vcp.MediaInputRole) bool {
	switch role {
	case vcp.MediaRoleUnderstanding, vcp.MediaRoleReference, vcp.MediaRoleEditSource, vcp.MediaRoleMask, vcp.MediaRoleFirstFrame, vcp.MediaRoleLastFrame, vcp.MediaRoleAudioTrack, vcp.MediaRoleTranscriptionSource, vcp.MediaRoleStyleReference, vcp.MediaRoleCoverReference:
		return true
	default:
		return false
	}
}

// validateCommonMediaLimits verifies known limits are positive and unknown values remain zero.
// validateCommonMediaLimits 校验已知限制为正数且未知值保持为零。
func validateCommonMediaLimits(limits CommonMediaLimits) error {
	for name, limit := range map[string]OptionalLimit{"max item bytes": limits.MaxItemBytes, "max total bytes": limits.MaxTotalBytes, "max items": limits.MaxItems} {
		if errValidate := validateOptionalLimit(name, limit); errValidate != nil {
			return errValidate
		}
	}
	return nil
}

// validateOptionalLimit verifies known-positive and unknown-zero semantics.
// validateOptionalLimit 校验已知正数和未知零值语义。
func validateOptionalLimit(name string, limit OptionalLimit) error {
	if (limit.Known && limit.Value <= 0) || (!limit.Known && limit.Value != 0) {
		return fmt.Errorf("%w: %s must be known-positive or explicitly unknown", ErrInvalidCatalog, name)
	}
	return nil
}

// validateUniqueStrings verifies normalized non-empty list members without duplicates.
// validateUniqueStrings 校验规范非空列表成员且不允许重复。
func validateUniqueStrings(name string, values []string) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		normalized := strings.ToLower(strings.TrimSpace(value))
		if normalized == "" {
			return fmt.Errorf("%w: %s cannot be empty", ErrInvalidCatalog, name)
		}
		if _, exists := seen[normalized]; exists {
			return fmt.Errorf("%w: duplicate %s %q", ErrInvalidCatalog, name, value)
		}
		seen[normalized] = struct{}{}
	}
	return nil
}

// containsInt reports whether one exact integer belongs to a sorted capability list.
// containsInt 报告一个精确整数是否属于已排序能力列表。
func containsInt(values []int, target int) bool {
	index := sort.SearchInts(values, target)
	return index < len(values) && values[index] == target
}
