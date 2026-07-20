package vcp

import (
	"fmt"
	"strings"
)

// OperationKind identifies one closed VCP execution operation.
// OperationKind 标识一种封闭的 VCP 执行操作。
type OperationKind string

const (
	// OperationConversationRespond generates a conversational response.
	// OperationConversationRespond 生成会话响应。
	OperationConversationRespond OperationKind = "conversation.respond"
	// OperationMediaAnalyze analyzes image, audio, video, or file resources.
	// OperationMediaAnalyze 分析图片、音频、视频或文件资源。
	OperationMediaAnalyze OperationKind = "media.analyze"
	// OperationImageGenerate generates images.
	// OperationImageGenerate 生成图片。
	OperationImageGenerate OperationKind = "image.generate"
	// OperationImageEdit edits existing images.
	// OperationImageEdit 编辑现有图片。
	OperationImageEdit OperationKind = "image.edit"
	// OperationVideoGenerate generates videos.
	// OperationVideoGenerate 生成视频。
	OperationVideoGenerate OperationKind = "video.generate"
	// OperationVideoEdit edits existing videos.
	// OperationVideoEdit 编辑现有视频。
	OperationVideoEdit OperationKind = "video.edit"
	// OperationVideoExtend extends an existing video.
	// OperationVideoExtend 延长现有视频。
	OperationVideoExtend OperationKind = "video.extend"
	// OperationSpeechSynthesize converts text to non-realtime speech.
	// OperationSpeechSynthesize 将文本转换为非实时语音。
	OperationSpeechSynthesize OperationKind = "speech.synthesize"
	// OperationSpeechTranscribe converts speech to structured text.
	// OperationSpeechTranscribe 将语音转换为结构化文本。
	OperationSpeechTranscribe OperationKind = "speech.transcribe"
	// OperationEmbeddingCreate creates typed vector representations.
	// OperationEmbeddingCreate 创建类型化向量表示。
	OperationEmbeddingCreate OperationKind = "embedding.create"
	// OperationRerankDocuments ranks candidates against one query.
	// OperationRerankDocuments 根据一个查询重排候选项。
	OperationRerankDocuments OperationKind = "rerank.documents"
	// OperationSearchWeb performs one unified web-search execution.
	// OperationSearchWeb 执行一次统一网页搜索。
	OperationSearchWeb OperationKind = "search.web"
	// OperationMusicGenerate generates music.
	// OperationMusicGenerate 生成音乐。
	OperationMusicGenerate OperationKind = "music.generate"
	// OperationMusicCoverPrepare prepares a provider-owned cover workflow.
	// OperationMusicCoverPrepare 准备供应商拥有的翻唱流程。
	OperationMusicCoverPrepare OperationKind = "music.cover.prepare"
	// OperationMusicCover completes a prepared cover workflow.
	// OperationMusicCover 完成已准备的翻唱流程。
	OperationMusicCover OperationKind = "music.cover"
)

// ServiceSelection identifies one exact provider-scoped special service.
// ServiceSelection 标识一个精确的供应商作用域特殊服务。
type ServiceSelection struct {
	// ProviderInstanceID fixes the immutable provider instance.
	// ProviderInstanceID 固定不可变供应商实例。
	ProviderInstanceID string `json:"provider_instance_id"`
	// ProviderServiceID identifies the provider-owned logical service.
	// ProviderServiceID 标识供应商拥有的逻辑服务。
	ProviderServiceID string `json:"provider_service_id"`
	// ServiceOfferingID selects one exact channel, endpoint, model, or engine binding.
	// ServiceOfferingID 选择一个精确通道、端点、模型或引擎绑定。
	ServiceOfferingID string `json:"service_offering_id"`
	// ExecutionProfileID selects one exact executable capability profile.
	// ExecutionProfileID 选择一个精确可执行能力规格。
	ExecutionProfileID string `json:"execution_profile_id"`
}

// TargetSelection contains exactly one model or service selection.
// TargetSelection 只包含一个模型或服务选择。
type TargetSelection struct {
	// Model selects a model-backed operation.
	// Model 选择模型支持的操作。
	Model *ModelSelection `json:"model,omitempty"`
	// Service selects a special-service operation.
	// Service 选择特殊服务操作。
	Service *ServiceSelection `json:"service,omitempty"`
}

// ConversationOperation contains conversation semantics without envelope metadata.
// ConversationOperation 包含不带信封元数据的会话语义。
type ConversationOperation struct {
	// Context is the canonical ordered truth source.
	// Context 是规范有序真相来源。
	Context []ContextItem `json:"context,omitempty"`
	// Tools contains structured tool declarations.
	// Tools 包含结构化工具声明。
	Tools []ToolDefinition `json:"tools,omitempty"`
	// ToolPolicy controls structured tool behavior.
	// ToolPolicy 控制结构化工具行为。
	ToolPolicy ToolPolicy `json:"tool_policy"`
	// GenerationPolicy controls output generation.
	// GenerationPolicy 控制输出生成。
	GenerationPolicy GenerationPolicy `json:"generation_policy"`
	// ReasoningPolicy controls requested reasoning behavior.
	// ReasoningPolicy 控制请求的推理行为。
	ReasoningPolicy ReasoningPolicy `json:"reasoning_policy"`
	// CachePolicy controls explicit cache intent.
	// CachePolicy 控制显式缓存意图。
	CachePolicy CachePolicy `json:"cache_policy"`
	// ContextManagementPolicy controls compaction triggers.
	// ContextManagementPolicy 控制压缩触发条件。
	ContextManagementPolicy ContextManagementPolicy `json:"context_management_policy"`
	// RemoteCompaction requests a manual remote compaction operation.
	// RemoteCompaction 请求手动远程压缩操作。
	RemoteCompaction *RemoteCompactionRequest `json:"remote_compaction,omitempty"`
	// CapabilityPolicy controls derived demand decisions.
	// CapabilityPolicy 控制推导需求决策。
	CapabilityPolicy CapabilityPolicy `json:"capability_policy"`
	// RegisteredExtensions lists allowed request extension identifiers.
	// RegisteredExtensions 列出允许的请求扩展标识。
	RegisteredExtensions []string `json:"registered_extensions,omitempty"`
	// MediaOnlyMode controls an explicit turn that contains media but no text.
	// MediaOnlyMode 控制明确仅含媒体而不含文字的轮次。
	MediaOnlyMode MediaOnlyConversationMode `json:"media_only_mode,omitempty"`
}

// MediaOnlyConversationMode identifies caller intent for a media-only conversation turn.
// MediaOnlyConversationMode 标识调用方对媒体单独会话轮次的意图。
type MediaOnlyConversationMode string

const (
	// MediaOnlyConversationReject rejects implicit media-only semantics.
	// MediaOnlyConversationReject 拒绝隐式媒体单独语义。
	MediaOnlyConversationReject MediaOnlyConversationMode = "reject"
	// MediaOnlyConversationUseProfilePolicy accepts the selected profile's declared media-only policy.
	// MediaOnlyConversationUseProfilePolicy 接受所选 Profile 声明的媒体单独策略。
	MediaOnlyConversationUseProfilePolicy MediaOnlyConversationMode = "use_profile_policy"
)

// ResourceProjectionPolicy grants specific lossy or provider-shaped media projections.
// ResourceProjectionPolicy 授予特定有损或供应商形态的媒体投影许可。
type ResourceProjectionPolicy struct {
	// AllowFrameSequence permits documented video-to-frame projection.
	// AllowFrameSequence 允许记录在案的视频到帧序列投影。
	AllowFrameSequence bool `json:"allow_frame_sequence"`
	// AllowAudioTrack permits documented extraction of an embedded audio track.
	// AllowAudioTrack 允许记录在案的内嵌音轨提取。
	AllowAudioTrack bool `json:"allow_audio_track"`
	// AllowTranscode permits a loss-accounted media encoding conversion.
	// AllowTranscode 允许记录语义损失的媒体编码转换。
	AllowTranscode bool `json:"allow_transcode"`
}

// OperationBudget contains caller-enforced upper bounds independent of provider defaults.
// OperationBudget 包含独立于供应商默认值的调用方强制上限。
type OperationBudget struct {
	// MaxInputBytes optionally limits all materialized input bytes.
	// MaxInputBytes 可选地限制全部物化输入字节数。
	MaxInputBytes *int64 `json:"max_input_bytes,omitempty"`
	// MaxOutputBytes optionally limits all generated resource bytes.
	// MaxOutputBytes 可选地限制全部生成资源字节数。
	MaxOutputBytes *int64 `json:"max_output_bytes,omitempty"`
	// MaxExecutionMilliseconds optionally limits wall-clock execution time.
	// MaxExecutionMilliseconds 可选地限制执行墙钟时间。
	MaxExecutionMilliseconds *int64 `json:"max_execution_milliseconds,omitempty"`
	// MaxProviderTasks optionally limits provider task creation.
	// MaxProviderTasks 可选地限制供应商任务创建数量。
	MaxProviderTasks *int `json:"max_provider_tasks,omitempty"`
}

// InputPlanResourceAssignment binds one pending planned input to a completed Router resource.
// InputPlanResourceAssignment 将一个待完成规划输入绑定到已完成 Router 资源。
type InputPlanResourceAssignment struct {
	// InputID identifies the exact pending input in the immutable plan.
	// InputID 标识不可变方案中的精确待完成输入。
	InputID string `json:"input_id"`
	// ResourceID identifies the completed owner-scoped Router resource.
	// ResourceID 标识已完成且属于所有者作用域的 Router 资源。
	ResourceID string `json:"resource_id"`
}

// OperationPayload contains exactly one operation-specific payload.
// OperationPayload 只包含一个操作特定载荷。
type OperationPayload struct {
	// Conversation contains conversation response input.
	// Conversation 包含会话响应输入。
	Conversation *ConversationOperation `json:"conversation,omitempty"`
	// MediaAnalyze contains media-analysis input.
	// MediaAnalyze 包含媒体分析输入。
	MediaAnalyze *MediaAnalyzeOperation `json:"media_analyze,omitempty"`
	// ImageGenerate contains image-generation input.
	// ImageGenerate 包含图片生成输入。
	ImageGenerate *ImageGenerateOperation `json:"image_generate,omitempty"`
	// ImageEdit contains image-edit input.
	// ImageEdit 包含图片编辑输入。
	ImageEdit *ImageEditOperation `json:"image_edit,omitempty"`
	// VideoGenerate contains video-generation input.
	// VideoGenerate 包含视频生成输入。
	VideoGenerate *VideoGenerateOperation `json:"video_generate,omitempty"`
	// VideoEdit contains video-edit input.
	// VideoEdit 包含视频编辑输入。
	VideoEdit *VideoEditOperation `json:"video_edit,omitempty"`
	// VideoExtend contains video-extension input.
	// VideoExtend 包含视频延长输入。
	VideoExtend *VideoExtendOperation `json:"video_extend,omitempty"`
	// SpeechSynthesize contains text-to-speech input.
	// SpeechSynthesize 包含文本转语音输入。
	SpeechSynthesize *SpeechSynthesizeOperation `json:"speech_synthesize,omitempty"`
	// SpeechTranscribe contains speech-to-text input.
	// SpeechTranscribe 包含语音转文本输入。
	SpeechTranscribe *SpeechTranscribeOperation `json:"speech_transcribe,omitempty"`
	// EmbeddingCreate contains vectorization input.
	// EmbeddingCreate 包含向量化输入。
	EmbeddingCreate *EmbeddingOperation `json:"embedding_create,omitempty"`
	// RerankDocuments contains reranking input.
	// RerankDocuments 包含重排输入。
	RerankDocuments *RerankOperation `json:"rerank_documents,omitempty"`
	// SearchWeb contains unified web-search input.
	// SearchWeb 包含统一网页搜索输入。
	SearchWeb *WebSearchOperation `json:"search_web,omitempty"`
	// MusicGenerate contains music-generation input.
	// MusicGenerate 包含音乐生成输入。
	MusicGenerate *MusicGenerateOperation `json:"music_generate,omitempty"`
	// MusicCoverPrepare contains cover preparation input.
	// MusicCoverPrepare 包含翻唱准备输入。
	MusicCoverPrepare *MusicCoverPrepareOperation `json:"music_cover_prepare,omitempty"`
	// MusicCover contains final cover input.
	// MusicCover 包含最终翻唱输入。
	MusicCover *MusicCoverOperation `json:"music_cover,omitempty"`
}

// ExecutionRequest is the closed VCP execution envelope.
// ExecutionRequest 是封闭的 VCP 执行信封。
type ExecutionRequest struct {
	// ProtocolVersion must equal ProtocolVersion.
	// ProtocolVersion 必须等于 ProtocolVersion。
	ProtocolVersion string `json:"protocol_version"`
	// RequestID is a stable Router-visible request identifier.
	// RequestID 是稳定的 Router 可见请求标识。
	RequestID string `json:"request_id"`
	// IdempotencyKey optionally protects replayable side effects.
	// IdempotencyKey 可选地保护可重放副作用。
	IdempotencyKey string `json:"idempotency_key,omitempty"`
	// InputPlanID binds conditional media execution to one previously accepted immutable input plan.
	// InputPlanID 将条件媒体执行绑定到一个先前已接受的不可变输入方案。
	InputPlanID string `json:"input_plan_id,omitempty"`
	// InputPlanResources completes pending plan inputs without changing their frozen identities.
	// InputPlanResources 在不改变冻结身份的情况下完成待处理方案输入。
	InputPlanResources []InputPlanResourceAssignment `json:"input_plan_resources,omitempty"`
	// Target contains exactly one model or service selection.
	// Target 只包含一个模型或服务选择。
	Target TargetSelection `json:"target"`
	// Operation identifies the closed payload variant.
	// Operation 标识封闭载荷变体。
	Operation OperationKind `json:"operation"`
	// Stream requests real semantic events when the selected profile supports them.
	// Stream 在所选规格支持时请求真实语义事件。
	Stream bool `json:"stream"`
	// Payload contains exactly one matching operation payload.
	// Payload 只包含一个匹配的操作载荷。
	Payload OperationPayload `json:"payload"`
	// ProjectionPolicy grants exact media projections and defaults to deny.
	// ProjectionPolicy 授予精确媒体投影许可且默认拒绝。
	ProjectionPolicy ResourceProjectionPolicy `json:"projection_policy"`
	// Budget contains caller-enforced operation ceilings.
	// Budget 包含调用方强制操作上限。
	Budget OperationBudget `json:"budget"`
}

// Validate verifies the execution envelope, target, and exact-one payload union.
// Validate 校验执行信封、目标和唯一载荷联合体。
func (r ExecutionRequest) Validate() error {
	if r.ProtocolVersion != ProtocolVersion {
		return fmt.Errorf("%w: unsupported protocol_version %q", ErrInvalidRequest, r.ProtocolVersion)
	}
	if strings.TrimSpace(r.RequestID) == "" {
		return fmt.Errorf("%w: request_id is required", ErrInvalidRequest)
	}
	if errTarget := r.Target.validate(r.Operation); errTarget != nil {
		return errTarget
	}
	if errAssignments := validateInputPlanAssignments(r.InputPlanID, r.InputPlanResources); errAssignments != nil {
		return errAssignments
	}
	if errPayload := r.Payload.validate(r.Operation, r); errPayload != nil {
		return errPayload
	}
	if errBudget := r.Budget.validate(); errBudget != nil {
		return errBudget
	}
	return nil
}

// validateInputPlanAssignments verifies that assignments exist only with a plan and have unique complete identities.
// validateInputPlanAssignments 校验资源指派仅与方案共存且具有唯一完整身份。
func validateInputPlanAssignments(inputPlanID string, assignments []InputPlanResourceAssignment) error {
	if strings.TrimSpace(inputPlanID) == "" && len(assignments) > 0 {
		return fmt.Errorf("%w: input_plan_resources require input_plan_id", ErrInvalidRequest)
	}
	seenInputs := make(map[string]struct{}, len(assignments))
	for _, assignment := range assignments {
		if strings.TrimSpace(assignment.InputID) == "" || strings.TrimSpace(assignment.ResourceID) == "" {
			return fmt.Errorf("%w: input plan resource assignment requires input_id and resource_id", ErrInvalidRequest)
		}
		if _, exists := seenInputs[assignment.InputID]; exists {
			return fmt.Errorf("%w: duplicate input plan resource assignment %q", ErrInvalidRequest, assignment.InputID)
		}
		seenInputs[assignment.InputID] = struct{}{}
	}
	return nil
}

// validate verifies every configured operation budget is positive.
// validate 校验每个已配置操作预算均为正数。
func (b OperationBudget) validate() error {
	if (b.MaxInputBytes != nil && *b.MaxInputBytes <= 0) || (b.MaxOutputBytes != nil && *b.MaxOutputBytes <= 0) || (b.MaxExecutionMilliseconds != nil && *b.MaxExecutionMilliseconds <= 0) || (b.MaxProviderTasks != nil && *b.MaxProviderTasks <= 0) {
		return fmt.Errorf("%w: configured operation budgets must be positive", ErrInvalidRequest)
	}
	return nil
}

// validate verifies exact-one target selection and operation ownership.
// validate 校验唯一目标选择和操作归属。
func (t TargetSelection) validate(operation OperationKind) error {
	if (t.Model == nil) == (t.Service == nil) {
		return fmt.Errorf("%w: target requires exactly one model or service selection", ErrInvalidRequest)
	}
	if operation == OperationSearchWeb {
		if t.Service == nil {
			return fmt.Errorf("%w: search.web requires service selection", ErrInvalidRequest)
		}
		return t.Service.validate()
	}
	if t.Model == nil {
		return fmt.Errorf("%w: operation %q requires model selection", ErrInvalidRequest, operation)
	}
	if !validModelTarget(t.Model.Target) {
		return fmt.Errorf("%w: invalid model target %q", ErrInvalidRequest, t.Model.Target)
	}
	if t.Model.Target == ModelTargetExact && (strings.TrimSpace(t.Model.ProviderInstanceID) == "" || strings.TrimSpace(t.Model.ProviderModelID) == "") {
		return fmt.Errorf("%w: exact model selection requires provider_instance_id and provider_model_id", ErrInvalidRequest)
	}
	return nil
}

// validate verifies the exact service identity required by special-service execution.
// validate 校验特殊服务执行要求的精确服务身份。
func (s ServiceSelection) validate() error {
	if strings.TrimSpace(s.ProviderInstanceID) == "" || strings.TrimSpace(s.ProviderServiceID) == "" || strings.TrimSpace(s.ServiceOfferingID) == "" || strings.TrimSpace(s.ExecutionProfileID) == "" {
		return fmt.Errorf("%w: service selection requires provider_instance_id, provider_service_id, service_offering_id, and execution_profile_id", ErrInvalidRequest)
	}
	return nil
}

// validate verifies the exact-one operation payload and delegates variant validation.
// validate 校验唯一操作载荷并委派变体校验。
func (p OperationPayload) validate(operation OperationKind, envelope ExecutionRequest) error {
	count := 0
	if p.Conversation != nil {
		count++
	}
	if p.MediaAnalyze != nil {
		count++
	}
	if p.ImageGenerate != nil {
		count++
	}
	if p.ImageEdit != nil {
		count++
	}
	if p.VideoGenerate != nil {
		count++
	}
	if p.VideoEdit != nil {
		count++
	}
	if p.VideoExtend != nil {
		count++
	}
	if p.SpeechSynthesize != nil {
		count++
	}
	if p.SpeechTranscribe != nil {
		count++
	}
	if p.EmbeddingCreate != nil {
		count++
	}
	if p.RerankDocuments != nil {
		count++
	}
	if p.SearchWeb != nil {
		count++
	}
	if p.MusicGenerate != nil {
		count++
	}
	if p.MusicCoverPrepare != nil {
		count++
	}
	if p.MusicCover != nil {
		count++
	}
	if count != 1 {
		return fmt.Errorf("%w: payload requires exactly one operation variant", ErrInvalidRequest)
	}
	switch operation {
	case OperationConversationRespond:
		if p.Conversation == nil {
			return payloadMismatch(operation)
		}
		return p.Conversation.validate(envelope)
	case OperationMediaAnalyze:
		if p.MediaAnalyze == nil {
			return payloadMismatch(operation)
		}
		return p.MediaAnalyze.Validate()
	case OperationImageGenerate:
		if p.ImageGenerate == nil {
			return payloadMismatch(operation)
		}
		return p.ImageGenerate.Validate()
	case OperationImageEdit:
		if p.ImageEdit == nil {
			return payloadMismatch(operation)
		}
		return p.ImageEdit.Validate()
	case OperationVideoGenerate:
		if p.VideoGenerate == nil {
			return payloadMismatch(operation)
		}
		return p.VideoGenerate.Validate()
	case OperationVideoEdit:
		if p.VideoEdit == nil {
			return payloadMismatch(operation)
		}
		return p.VideoEdit.Validate()
	case OperationVideoExtend:
		if p.VideoExtend == nil {
			return payloadMismatch(operation)
		}
		return p.VideoExtend.Validate()
	case OperationSpeechSynthesize:
		if p.SpeechSynthesize == nil {
			return payloadMismatch(operation)
		}
		return p.SpeechSynthesize.Validate()
	case OperationSpeechTranscribe:
		if p.SpeechTranscribe == nil {
			return payloadMismatch(operation)
		}
		return p.SpeechTranscribe.Validate()
	case OperationEmbeddingCreate:
		if p.EmbeddingCreate == nil {
			return payloadMismatch(operation)
		}
		return p.EmbeddingCreate.Validate()
	case OperationRerankDocuments:
		if p.RerankDocuments == nil {
			return payloadMismatch(operation)
		}
		return p.RerankDocuments.Validate()
	case OperationSearchWeb:
		if p.SearchWeb == nil {
			return payloadMismatch(operation)
		}
		return p.SearchWeb.Validate()
	case OperationMusicGenerate:
		if p.MusicGenerate == nil {
			return payloadMismatch(operation)
		}
		return p.MusicGenerate.Validate()
	case OperationMusicCoverPrepare:
		if p.MusicCoverPrepare == nil {
			return payloadMismatch(operation)
		}
		return p.MusicCoverPrepare.Validate()
	case OperationMusicCover:
		if p.MusicCover == nil {
			return payloadMismatch(operation)
		}
		return p.MusicCover.Validate()
	default:
		return fmt.Errorf("%w: unsupported operation %q", ErrInvalidRequest, operation)
	}
}

// validate verifies conversation semantics through the established VCP validator.
// validate 通过既有 VCP 校验器校验会话语义。
func (o ConversationOperation) validate(envelope ExecutionRequest) error {
	request := o.vulcanRequest(envelope)
	if errRequest := request.Validate(); errRequest != nil {
		return errRequest
	}
	return o.validateMediaIntent()
}

// ConversationRequest converts one validated conversation action into the established canonical request shape.
// ConversationRequest 将一个已校验会话动作转换为既有规范请求形态。
func (r ExecutionRequest) ConversationRequest() (VulcanRequest, error) {
	if errValidate := r.Validate(); errValidate != nil {
		return VulcanRequest{}, errValidate
	}
	if r.Operation != OperationConversationRespond || r.Payload.Conversation == nil || r.Target.Model == nil {
		return VulcanRequest{}, fmt.Errorf("%w: execution is not a model conversation action", ErrInvalidRequest)
	}
	return r.Payload.Conversation.vulcanRequest(r), nil
}

// vulcanRequest projects the envelope fields without performing a second semantic decision.
// vulcanRequest 投影信封字段且不执行第二次语义决策。
func (o ConversationOperation) vulcanRequest(envelope ExecutionRequest) VulcanRequest {
	return VulcanRequest{
		ProtocolVersion:         envelope.ProtocolVersion,
		RequestID:               envelope.RequestID,
		IdempotencyKey:          envelope.IdempotencyKey,
		ModelSelection:          *envelope.Target.Model,
		Context:                 o.Context,
		Tools:                   o.Tools,
		ToolPolicy:              o.ToolPolicy,
		GenerationPolicy:        o.GenerationPolicy,
		ReasoningPolicy:         o.ReasoningPolicy,
		CachePolicy:             o.CachePolicy,
		ContextManagementPolicy: o.ContextManagementPolicy,
		RemoteCompaction:        o.RemoteCompaction,
		CapabilityPolicy:        o.CapabilityPolicy,
		Stream:                  envelope.Stream,
		RegisteredExtensions:    o.RegisteredExtensions,
	}
}

// validateMediaIntent requires explicit understanding roles and media-only semantics in the new execution envelope.
// validateMediaIntent 在新执行信封中要求明确的理解角色和媒体单独语义。
func (o ConversationOperation) validateMediaIntent() error {
	hasText := false
	hasMedia := false
	for _, item := range o.Context {
		for _, block := range item.Content {
			if block.Type == ContentText && strings.TrimSpace(block.Text) != "" {
				hasText = true
			}
			if block.Type == ContentImage || block.Type == ContentAudio || block.Type == ContentVideo || block.Type == ContentFile {
				hasMedia = true
				if block.MediaRole != MediaRoleUnderstanding {
					return fmt.Errorf("%w: conversation media requires explicit understanding role", ErrInvalidRequest)
				}
			}
		}
	}
	if !hasMedia {
		if o.MediaOnlyMode != "" && o.MediaOnlyMode != MediaOnlyConversationReject {
			return fmt.Errorf("%w: media_only_mode requires media input", ErrInvalidRequest)
		}
		return nil
	}
	if !hasText && o.MediaOnlyMode != MediaOnlyConversationUseProfilePolicy {
		return fmt.Errorf("%w: media-only conversation requires use_profile_policy intent", ErrInvalidRequest)
	}
	if hasText && o.MediaOnlyMode != "" && o.MediaOnlyMode != MediaOnlyConversationReject {
		return fmt.Errorf("%w: mixed conversation cannot request media-only profile policy", ErrInvalidRequest)
	}
	return nil
}

// payloadMismatch creates one stable operation-to-payload mismatch error.
// payloadMismatch 创建一个稳定的操作与载荷不匹配错误。
func payloadMismatch(operation OperationKind) error {
	return fmt.Errorf("%w: payload does not match operation %q", ErrInvalidRequest, operation)
}
