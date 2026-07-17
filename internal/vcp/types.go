// Package vcp defines the typed Vulcan Canonical Protocol 1.0 domain model.
// Package vcp 定义类型化的 Vulcan Canonical Protocol 1.0 领域模型。
package vcp

import (
	"encoding/json"
	"time"
)

// ProtocolVersion is the only VCP version accepted by this implementation.
// ProtocolVersion 是当前实现接受的唯一 VCP 版本。
const ProtocolVersion = "1.0"

// ModelTargetMode identifies how a model selection is resolved.
// ModelTargetMode 标识模型选择的解析方式。
type ModelTargetMode string

const (
	// ModelTargetExact requires an explicitly provider-scoped model.
	// ModelTargetExact 要求显式指定供应商作用域模型。
	ModelTargetExact ModelTargetMode = "exact"
	// ModelTargetAlias resolves a caller-owned stable alias.
	// ModelTargetAlias 解析调用方拥有的稳定别名。
	ModelTargetAlias ModelTargetMode = "alias"
	// ModelTargetAuto permits selection inside the caller-authorized provider boundary.
	// ModelTargetAuto 允许在调用方授权的供应商边界内选择。
	ModelTargetAuto ModelTargetMode = "auto"
)

// ModelSelection describes the requested provider-scoped model target.
// ModelSelection 描述请求的供应商作用域模型目标。
type ModelSelection struct {
	// Target selects exact, alias, or auto resolution.
	// Target 选择精确、别名或自动解析。
	Target ModelTargetMode `json:"target"`
	// ProviderInstanceID optionally fixes the immutable provider instance.
	// ProviderInstanceID 可选地固定不可变供应商实例。
	ProviderInstanceID string `json:"provider_instance_id,omitempty"`
	// ProviderModelID optionally selects one provider-scoped logical model.
	// ProviderModelID 可选地选择一个供应商作用域逻辑模型。
	ProviderModelID string `json:"provider_model_id,omitempty"`
	// ExecutionProfileID optionally selects one client-visible capability profile.
	// ExecutionProfileID 可选地选择一个客户端可见能力规格。
	ExecutionProfileID string `json:"execution_profile_id,omitempty"`
}

// ContextKind identifies one closed canonical context item variant.
// ContextKind 标识一种封闭的规范上下文项目变体。
type ContextKind string

const (
	// ContextInstruction represents a system or developer instruction.
	// ContextInstruction 表示系统或开发者指令。
	ContextInstruction ContextKind = "instruction"
	// ContextMessage represents a user or assistant transcript message.
	// ContextMessage 表示用户或助手会话消息。
	ContextMessage ContextKind = "message"
	// ContextDelegatedResult represents a delegated agent result.
	// ContextDelegatedResult 表示委派代理结果。
	ContextDelegatedResult ContextKind = "delegated_result"
	// ContextToolCall represents a structured tool invocation.
	// ContextToolCall 表示结构化工具调用。
	ContextToolCall ContextKind = "tool_call"
	// ContextToolResult represents the result of one structured tool invocation.
	// ContextToolResult 表示一次结构化工具调用的结果。
	ContextToolResult ContextKind = "tool_result"
	// ContextReasoning represents visible reasoning material or a continuation reference.
	// ContextReasoning 表示可见推理材料或续接引用。
	ContextReasoning ContextKind = "reasoning"
	// ContextRefusal represents an assistant or provider refusal.
	// ContextRefusal 表示助手或供应商拒绝。
	ContextRefusal ContextKind = "refusal"
)

// Authority identifies the original instruction authority independently from the actor.
// Authority 独立于内容生产者标识原始指令权限。
type Authority string

const (
	// AuthoritySystem identifies platform-owned system authority.
	// AuthoritySystem 标识平台拥有的系统权限。
	AuthoritySystem Authority = "system"
	// AuthorityDeveloper identifies application-owned developer authority.
	// AuthorityDeveloper 标识应用拥有的开发者权限。
	AuthorityDeveloper Authority = "developer"
	// AuthorityUser identifies end-user authority.
	// AuthorityUser 标识最终用户权限。
	AuthorityUser Authority = "user"
	// AuthorityAssistant identifies primary assistant authority.
	// AuthorityAssistant 标识主助手权限。
	AuthorityAssistant Authority = "assistant"
	// AuthorityTool identifies tool-produced authority.
	// AuthorityTool 标识工具产生的权限。
	AuthorityTool Authority = "tool"
	// AuthorityNone identifies content without instruction authority.
	// AuthorityNone 标识不具有指令权限的内容。
	AuthorityNone Authority = "none"
)

// Actor identifies who produced a context item independently from its authority.
// Actor 独立于权限标识上下文项目的生产者。
type Actor string

const (
	// ActorPlatform identifies the Vulcan platform.
	// ActorPlatform 标识 Vulcan 平台。
	ActorPlatform Actor = "platform"
	// ActorApplication identifies the calling application.
	// ActorApplication 标识调用应用。
	ActorApplication Actor = "application"
	// ActorEndUser identifies the end user.
	// ActorEndUser 标识最终用户。
	ActorEndUser Actor = "end_user"
	// ActorPrimaryAssistant identifies the primary assistant.
	// ActorPrimaryAssistant 标识主助手。
	ActorPrimaryAssistant Actor = "primary_assistant"
	// ActorDelegatedAgent identifies a delegated agent.
	// ActorDelegatedAgent 标识受委派代理。
	ActorDelegatedAgent Actor = "delegated_agent"
	// ActorTool identifies a tool implementation.
	// ActorTool 标识工具实现。
	ActorTool Actor = "tool"
	// ActorProvider identifies the upstream provider.
	// ActorProvider 标识上游供应商。
	ActorProvider Actor = "provider"
)

// Placement identifies where an item belongs in canonical context.
// Placement 标识项目在规范上下文中的位置类别。
type Placement string

const (
	// PlacementPreamble places an item before transcript history.
	// PlacementPreamble 将项目放在会话历史之前。
	PlacementPreamble Placement = "preamble"
	// PlacementTranscript places an item at its global transcript sequence.
	// PlacementTranscript 将项目放在其全局会话序号处。
	PlacementTranscript Placement = "transcript"
)

// ActivationMode identifies when an instruction becomes active.
// ActivationMode 标识指令何时开始生效。
type ActivationMode string

const (
	// ActivationRequestStart activates at request start.
	// ActivationRequestStart 在请求开始时生效。
	ActivationRequestStart ActivationMode = "request_start"
	// ActivationAfterItem activates after a specific canonical item.
	// ActivationAfterItem 在指定规范项目之后生效。
	ActivationAfterItem ActivationMode = "after_item_id"
)

// Activation describes an instruction activation anchor.
// Activation 描述指令生效锚点。
type Activation struct {
	// Mode selects request start or an item-relative anchor.
	// Mode 选择请求开始或相对项目锚点。
	Mode ActivationMode `json:"mode"`
	// AfterItemID is required when Mode is after_item_id.
	// AfterItemID 在 Mode 为 after_item_id 时必填。
	AfterItemID string `json:"after_item_id,omitempty"`
}

// Visibility identifies which consumer may observe an item.
// Visibility 标识可观察项目的消费者。
type Visibility string

const (
	// VisibilityModel exposes the item to the model.
	// VisibilityModel 向模型暴露项目。
	VisibilityModel Visibility = "model"
	// VisibilityClient exposes the item to the client but not necessarily the model.
	// VisibilityClient 向客户端暴露项目但不一定向模型暴露。
	VisibilityClient Visibility = "client"
	// VisibilityAuditOnly restricts the item to trusted audit storage.
	// VisibilityAuditOnly 将项目限制在受信任审计存储中。
	VisibilityAuditOnly Visibility = "audit_only"
)

// ContentType identifies one registered VCP content block.
// ContentType 标识一种已注册的 VCP 内容块。
type ContentType string

const (
	// ContentText contains UTF-8 text.
	// ContentText 包含 UTF-8 文本。
	ContentText ContentType = "text"
	// ContentImage references image input or output.
	// ContentImage 引用图像输入或输出。
	ContentImage ContentType = "image"
	// ContentAudio references audio input or output.
	// ContentAudio 引用音频输入或输出。
	ContentAudio ContentType = "audio"
	// ContentVideo references video input or output.
	// ContentVideo 引用视频输入或输出。
	ContentVideo ContentType = "video"
	// ContentFile references a file resource.
	// ContentFile 引用文件资源。
	ContentFile ContentType = "file"
	// ContentCitation contains a source citation.
	// ContentCitation 包含来源引用。
	ContentCitation ContentType = "citation"
	// ContentRefusal contains refusal text.
	// ContentRefusal 包含拒绝文本。
	ContentRefusal ContentType = "refusal"
	// ContentRegisteredExtension contains a registered typed extension.
	// ContentRegisteredExtension 包含已注册的类型化扩展。
	ContentRegisteredExtension ContentType = "registered_extension"
)

// ContentBlock contains one typed unit of canonical content.
// ContentBlock 包含一个类型化规范内容单元。
type ContentBlock struct {
	// Type identifies the registered content variant.
	// Type 标识已注册的内容变体。
	Type ContentType `json:"type"`
	// Text contains text, citation, or refusal content when applicable.
	// Text 在适用时包含文本、引用或拒绝内容。
	Text string `json:"text,omitempty"`
	// ResourceRef references a Router-owned media or file resource.
	// ResourceRef 引用 Router 拥有的媒体或文件资源。
	ResourceRef string `json:"resource_ref,omitempty"`
	// MediaType records the authoritative MIME type when known.
	// MediaType 记录已知的权威 MIME 类型。
	MediaType string `json:"media_type,omitempty"`
	// ExtensionID identifies a registered extension schema.
	// ExtensionID 标识已注册扩展 Schema。
	ExtensionID string `json:"extension_id,omitempty"`
	// Extension contains registered extension JSON owned by ExtensionID.
	// Extension 包含由 ExtensionID 约束的已注册扩展 JSON。
	Extension json.RawMessage `json:"extension,omitempty"`
}

// InstructionItem contains instruction-specific canonical data.
// InstructionItem 包含指令特有的规范数据。
type InstructionItem struct {
	// Scope identifies the registered instruction scope.
	// Scope 标识已注册的指令作用域。
	Scope string `json:"scope,omitempty"`
}

// MessageItem contains message-specific canonical data.
// MessageItem 包含消息特有的规范数据。
type MessageItem struct {
	// ReplyToItemID references the message being answered.
	// ReplyToItemID 引用当前消息所回复的消息。
	ReplyToItemID string `json:"reply_to_item_id,omitempty"`
}

// DelegatedResultKind identifies the shape of a delegated result.
// DelegatedResultKind 标识委派结果的形态。
type DelegatedResultKind string

const (
	// DelegatedReport is an analytical delegated report.
	// DelegatedReport 是分析型委派报告。
	DelegatedReport DelegatedResultKind = "report"
	// DelegatedTaskOutput is direct delegated task output.
	// DelegatedTaskOutput 是直接的委派任务输出。
	DelegatedTaskOutput DelegatedResultKind = "task_output"
	// DelegatedToolBackedResult is a delegated result backed by a tool call.
	// DelegatedToolBackedResult 是由工具调用支撑的委派结果。
	DelegatedToolBackedResult DelegatedResultKind = "tool_backed_result"
)

// DelegatedResultItem contains delegation-specific canonical data.
// DelegatedResultItem 包含委派特有的规范数据。
type DelegatedResultItem struct {
	// ResultKind identifies the delegated result shape.
	// ResultKind 标识委派结果形态。
	ResultKind DelegatedResultKind `json:"result_kind"`
}

// ToolCallStatus identifies the lifecycle state of a tool call.
// ToolCallStatus 标识工具调用的生命周期状态。
type ToolCallStatus string

const (
	// ToolCallPending is not yet complete.
	// ToolCallPending 尚未完成。
	ToolCallPending ToolCallStatus = "pending"
	// ToolCallCompleted has a complete name and argument payload.
	// ToolCallCompleted 已具有完整名称和参数载荷。
	ToolCallCompleted ToolCallStatus = "completed"
	// ToolCallIncomplete ended without all required fields.
	// ToolCallIncomplete 在必需字段不完整时结束。
	ToolCallIncomplete ToolCallStatus = "incomplete"
)

// ToolCallItem contains one structured tool invocation.
// ToolCallItem 包含一次结构化工具调用。
type ToolCallItem struct {
	// ToolCallID is the stable VCP tool call identifier.
	// ToolCallID 是稳定的 VCP 工具调用标识。
	ToolCallID string `json:"tool_call_id"`
	// UpstreamID records an upstream identifier when reported.
	// UpstreamID 记录上游报告的标识。
	UpstreamID string `json:"upstream_id,omitempty"`
	// SynthesizedID reports that the Router generated ToolCallID.
	// SynthesizedID 表示 ToolCallID 由 Router 生成。
	SynthesizedID bool `json:"synthesized_id,omitempty"`
	// Namespace identifies the registered tool namespace.
	// Namespace 标识已注册工具命名空间。
	Namespace string `json:"namespace,omitempty"`
	// Name identifies the registered tool.
	// Name 标识已注册工具。
	Name string `json:"name,omitempty"`
	// Arguments contains the exact assembled JSON argument text.
	// Arguments 包含精确归并后的 JSON 参数文本。
	Arguments string `json:"arguments,omitempty"`
	// Status identifies the invocation lifecycle state.
	// Status 标识调用生命周期状态。
	Status ToolCallStatus `json:"status"`
}

// ToolResultItem contains one structured tool result relation.
// ToolResultItem 包含一个结构化工具结果关联。
type ToolResultItem struct {
	// ToolCallID identifies the parent VCP tool call.
	// ToolCallID 标识父级 VCP 工具调用。
	ToolCallID string `json:"tool_call_id"`
}

// ReasoningItem separates visible reasoning from opaque continuation state.
// ReasoningItem 将可见推理与不透明续接状态分开。
type ReasoningItem struct {
	// Summary reports whether content is a client-visible summary.
	// Summary 表示内容是否为客户端可见摘要。
	Summary bool `json:"summary,omitempty"`
	// ContinuationRef references sealed provider-owned continuation state.
	// ContinuationRef 引用密封的供应商所有续接状态。
	ContinuationRef string `json:"continuation_ref,omitempty"`
}

// RefusalItem contains refusal-specific metadata.
// RefusalItem 包含拒绝特有元数据。
type RefusalItem struct {
	// ReasonCode is a safe registered refusal category.
	// ReasonCode 是安全的已注册拒绝类别。
	ReasonCode string `json:"reason_code,omitempty"`
}

// ContextItem is one stable, globally ordered canonical context item.
// ContextItem 是一个稳定且全局有序的规范上下文项目。
type ContextItem struct {
	// ItemID is stable across projection and replay.
	// ItemID 在投影和回放过程中保持稳定。
	ItemID string `json:"item_id"`
	// Sequence is the globally increasing canonical order.
	// Sequence 是全局递增的规范顺序。
	Sequence uint64 `json:"sequence"`
	// Kind identifies the closed item variant.
	// Kind 标识封闭项目变体。
	Kind ContextKind `json:"kind"`
	// Authority records original instruction authority.
	// Authority 记录原始指令权限。
	Authority Authority `json:"authority"`
	// Actor records the content producer.
	// Actor 记录内容生产者。
	Actor Actor `json:"actor"`
	// Placement records preamble or transcript placement.
	// Placement 记录前置或会话内位置。
	Placement Placement `json:"placement"`
	// Activation records the activation anchor.
	// Activation 记录生效锚点。
	Activation Activation `json:"activation"`
	// Visibility records the intended observer.
	// Visibility 记录预期观察者。
	Visibility Visibility `json:"visibility"`
	// ParentItemID records causal parentage.
	// ParentItemID 记录因果父级关系。
	ParentItemID string `json:"parent_item_id,omitempty"`
	// ReplyToItemID records message reply relation.
	// ReplyToItemID 记录消息回复关系。
	ReplyToItemID string `json:"reply_to_item_id,omitempty"`
	// DelegationID records delegated execution identity.
	// DelegationID 记录委派执行身份。
	DelegationID string `json:"delegation_id,omitempty"`
	// OrderingConstraints lists registered item IDs that must precede this item.
	// OrderingConstraints 列出必须先于当前项目的已注册项目 ID。
	OrderingConstraints []string `json:"ordering_constraints,omitempty"`
	// Content contains ordered typed content blocks.
	// Content 包含有序类型化内容块。
	Content []ContentBlock `json:"content,omitempty"`
	// ProviderStateRef references sealed provider-owned state.
	// ProviderStateRef 引用密封的供应商所有状态。
	ProviderStateRef string `json:"provider_state_ref,omitempty"`
	// Instruction is populated only for instruction items.
	// Instruction 仅在指令项目中填充。
	Instruction *InstructionItem `json:"instruction,omitempty"`
	// Message is populated only for message items.
	// Message 仅在消息项目中填充。
	Message *MessageItem `json:"message,omitempty"`
	// DelegatedResult is populated only for delegated result items.
	// DelegatedResult 仅在委派结果项目中填充。
	DelegatedResult *DelegatedResultItem `json:"delegated_result,omitempty"`
	// ToolCall is populated only for tool call items.
	// ToolCall 仅在工具调用项目中填充。
	ToolCall *ToolCallItem `json:"tool_call,omitempty"`
	// ToolResult is populated only for tool result items.
	// ToolResult 仅在工具结果项目中填充。
	ToolResult *ToolResultItem `json:"tool_result,omitempty"`
	// Reasoning is populated only for reasoning items.
	// Reasoning 仅在推理项目中填充。
	Reasoning *ReasoningItem `json:"reasoning,omitempty"`
	// Refusal is populated only for refusal items.
	// Refusal 仅在拒绝项目中填充。
	Refusal *RefusalItem `json:"refusal,omitempty"`
}

// ToolKind identifies a registered tool execution shape.
// ToolKind 标识一种已注册工具执行形态。
type ToolKind string

const (
	// ToolFunction is a caller-executed structured function.
	// ToolFunction 是由调用方执行的结构化函数。
	ToolFunction ToolKind = "function"
	// ToolNativeWebSearch is provider-hosted web search.
	// ToolNativeWebSearch 是供应商托管网页搜索。
	ToolNativeWebSearch ToolKind = "native_web_search"
)

// ToolDefinition declares one typed tool available to the model.
// ToolDefinition 声明一个模型可用的类型化工具。
type ToolDefinition struct {
	// Kind identifies function or provider-hosted behavior.
	// Kind 标识函数或供应商托管行为。
	Kind ToolKind `json:"kind"`
	// Namespace identifies a registered tool namespace.
	// Namespace 标识已注册工具命名空间。
	Namespace string `json:"namespace,omitempty"`
	// Name is the stable tool name.
	// Name 是稳定工具名称。
	Name string `json:"name"`
	// Description is model-visible tool guidance.
	// Description 是模型可见的工具说明。
	Description string `json:"description,omitempty"`
	// Parameters contains the registered JSON Schema payload.
	// Parameters 包含已注册 JSON Schema 载荷。
	Parameters json.RawMessage `json:"parameters,omitempty"`
	// Strict requests verified strict schema enforcement.
	// Strict 请求经过验证的严格 Schema 约束。
	Strict bool `json:"strict,omitempty"`
}

// ToolChoiceMode identifies how the model may select tools.
// ToolChoiceMode 标识模型选择工具的方式。
type ToolChoiceMode string

const (
	// ToolChoiceAuto permits the model to choose.
	// ToolChoiceAuto 允许模型自行选择。
	ToolChoiceAuto ToolChoiceMode = "auto"
	// ToolChoiceNone disables calls while retaining declarations.
	// ToolChoiceNone 在保留声明的同时禁用调用。
	ToolChoiceNone ToolChoiceMode = "none"
	// ToolChoiceRequired requires at least one tool call.
	// ToolChoiceRequired 要求至少一次工具调用。
	ToolChoiceRequired ToolChoiceMode = "required"
	// ToolChoiceNamed requires one named function.
	// ToolChoiceNamed 要求一个指定函数。
	ToolChoiceNamed ToolChoiceMode = "named"
)

// ToolPolicy controls structured tool selection.
// ToolPolicy 控制结构化工具选择。
type ToolPolicy struct {
	// Choice identifies automatic, disabled, required, or named selection.
	// Choice 标识自动、禁用、必需或指定选择。
	Choice ToolChoiceMode `json:"choice,omitempty"`
	// NamedTool identifies the function required by named selection.
	// NamedTool 标识指定选择要求的函数。
	NamedTool string `json:"named_tool,omitempty"`
	// Parallel requests reliable parallel tool calls.
	// Parallel 请求可靠的并行工具调用。
	Parallel bool `json:"parallel,omitempty"`
	// StreamArguments requests real upstream argument deltas.
	// StreamArguments 请求真实上游参数增量。
	StreamArguments bool `json:"stream_arguments,omitempty"`
}

// GenerationPolicy contains protocol-independent generation controls.
// GenerationPolicy 包含协议无关的生成控制。
type GenerationPolicy struct {
	// Temperature controls sampling randomness when supported.
	// Temperature 在支持时控制采样随机性。
	Temperature *float64 `json:"temperature,omitempty"`
	// TopP controls nucleus sampling when supported.
	// TopP 在支持时控制核采样。
	TopP *float64 `json:"top_p,omitempty"`
	// MaxOutputTokens limits generated output.
	// MaxOutputTokens 限制生成输出。
	MaxOutputTokens *int `json:"max_output_tokens,omitempty"`
	// Stop contains explicit stop sequences.
	// Stop 包含显式停止序列。
	Stop []string `json:"stop,omitempty"`
	// StrictJSONSchema contains a required strict output schema.
	// StrictJSONSchema 包含必需的严格输出 Schema。
	StrictJSONSchema json.RawMessage `json:"strict_json_schema,omitempty"`
}

// ReasoningPolicy contains explicitly requested reasoning behavior.
// ReasoningPolicy 包含显式请求的推理行为。
type ReasoningPolicy struct {
	// Effort identifies a registered reasoning effort level.
	// Effort 标识已注册推理强度等级。
	Effort string `json:"effort,omitempty"`
	// Summary requests a visible reasoning summary.
	// Summary 请求可见推理摘要。
	Summary bool `json:"summary,omitempty"`
	// ContinuationID references Router-owned sealed continuation state.
	// ContinuationID 引用 Router 拥有的密封续接状态。
	ContinuationID string `json:"continuation_id,omitempty"`
}

// CacheStrategy identifies explicit cache intent.
// CacheStrategy 标识显式缓存意图。
type CacheStrategy string

const (
	// CacheRegular adds no explicit cache control.
	// CacheRegular 不添加显式缓存控制。
	CacheRegular CacheStrategy = "regular"
	// CacheDisabled requests verified cache disablement.
	// CacheDisabled 请求经过验证的缓存禁用。
	CacheDisabled CacheStrategy = "disabled"
	// CacheStablePrefix requests a stable prefix breakpoint.
	// CacheStablePrefix 请求稳定前缀断点。
	CacheStablePrefix CacheStrategy = "stable_prefix"
	// CacheRollingPerTurn advances a breakpoint per turn.
	// CacheRollingPerTurn 每回合推进缓存断点。
	CacheRollingPerTurn CacheStrategy = "rolling_per_turn"
	// CacheManualBreakpoints uses caller-selected breakpoints.
	// CacheManualBreakpoints 使用调用方选择的断点。
	CacheManualBreakpoints CacheStrategy = "manual_breakpoints"
)

// CacheUnsupportedPolicy controls unsupported explicit cache behavior.
// CacheUnsupportedPolicy 控制不支持显式缓存时的行为。
type CacheUnsupportedPolicy string

const (
	// CacheUnsupportedReject blocks the operation.
	// CacheUnsupportedReject 阻止当前操作。
	CacheUnsupportedReject CacheUnsupportedPolicy = "reject"
	// CacheUnsupportedUseRegular omits explicit control and uses regular behavior.
	// CacheUnsupportedUseRegular 省略显式控制并使用常规行为。
	CacheUnsupportedUseRegular CacheUnsupportedPolicy = "use_regular"
)

// CacheBreakpoint identifies one canonical cache boundary.
// CacheBreakpoint 标识一个规范缓存边界。
type CacheBreakpoint struct {
	// ItemID identifies the canonical item boundary.
	// ItemID 标识规范项目边界。
	ItemID string `json:"item_id"`
	// ContentIndex optionally narrows the boundary to one content block.
	// ContentIndex 可选地将边界缩小到一个内容块。
	ContentIndex *int `json:"content_index,omitempty"`
	// RequestedTTL contains a caller-requested duration.
	// RequestedTTL 包含调用方请求的持续时间。
	RequestedTTL time.Duration `json:"requested_ttl,omitempty"`
}

// CachePolicy separates request intent from provider cache observations.
// CachePolicy 将请求意图与供应商缓存观测分开。
type CachePolicy struct {
	// Strategy identifies regular or explicit cache behavior.
	// Strategy 标识常规或显式缓存行为。
	Strategy CacheStrategy `json:"strategy"`
	// RequestedTTL contains a caller-requested duration.
	// RequestedTTL 包含调用方请求的持续时间。
	RequestedTTL time.Duration `json:"requested_ttl,omitempty"`
	// Breakpoints contains caller-selected canonical boundaries.
	// Breakpoints 包含调用方选择的规范边界。
	Breakpoints []CacheBreakpoint `json:"breakpoints,omitempty"`
	// OnUnsupported determines whether unsupported control blocks or degrades.
	// OnUnsupported 决定不支持控制时阻止还是降级。
	OnUnsupported CacheUnsupportedPolicy `json:"on_unsupported"`
}

// CacheObservation records provider-reported cache facts.
// CacheObservation 记录供应商报告的缓存事实。
type CacheObservation struct {
	// RequestedMode records the VCP cache strategy.
	// RequestedMode 记录 VCP 缓存策略。
	RequestedMode CacheStrategy `json:"requested_mode"`
	// EffectiveMode records implicit, explicit, provider-managed, or unknown behavior.
	// EffectiveMode 记录隐式、显式、供应商托管或未知行为。
	EffectiveMode string `json:"effective_mode"`
	// Outcome records created, read, miss, ineligible, or unknown behavior.
	// Outcome 记录创建、读取、未命中、不符合条件或未知行为。
	Outcome string `json:"outcome"`
	// CreationTokens is nil when the provider did not report the value.
	// CreationTokens 在供应商未报告数值时为 nil。
	CreationTokens *int64 `json:"creation_tokens,omitempty"`
	// ReadTokens is nil when the provider did not report the value.
	// ReadTokens 在供应商未报告数值时为 nil。
	ReadTokens *int64 `json:"read_tokens,omitempty"`
	// Scope records the provider-reported cache isolation scope.
	// Scope 记录供应商报告的缓存隔离作用域。
	Scope string `json:"scope,omitempty"`
	// Source records provider, local, or derived evidence.
	// Source 记录供应商、本地或推导证据。
	Source string `json:"source"`
	// Final reports whether this observation is terminal.
	// Final 表示当前观测是否为终态。
	Final bool `json:"final"`
}

// ContextManagementMode identifies normal or automatic compaction behavior.
// ContextManagementMode 标识常规或自动压缩行为。
type ContextManagementMode string

const (
	// ContextManagementRegular does not request remote compaction.
	// ContextManagementRegular 不请求远程压缩。
	ContextManagementRegular ContextManagementMode = "regular"
	// ContextManagementAuto may request remote compaction at a configured threshold.
	// ContextManagementAuto 可在配置阈值处请求远程压缩。
	ContextManagementAuto ContextManagementMode = "auto"
)

// ContextManagementPolicy controls request-time context management.
// ContextManagementPolicy 控制请求时上下文管理。
type ContextManagementPolicy struct {
	// Mode identifies regular or automatic management.
	// Mode 标识常规或自动管理。
	Mode ContextManagementMode `json:"mode"`
	// ThresholdTokens triggers automatic compaction when positive and reached.
	// ThresholdTokens 为正且达到时触发自动压缩。
	ThresholdTokens int64 `json:"threshold_tokens,omitempty"`
}

// RemoteCompactionRequest models an explicit remote compaction operation.
// RemoteCompactionRequest 建模一次显式远程压缩操作。
type RemoteCompactionRequest struct {
	// PreviousResponseID selects Router-owned lineage input.
	// PreviousResponseID 选择 Router 拥有的谱系输入。
	PreviousResponseID string `json:"previous_response_id,omitempty"`
	// Context supplies stateless canonical input when no previous response is used.
	// Context 在未使用先前响应时提供无状态规范输入。
	Context []ContextItem `json:"context,omitempty"`
}

// CapabilityExecutionMode selects maximum safe behavior or native-only behavior.
// CapabilityExecutionMode 选择最大化安全行为或仅原生行为。
type CapabilityExecutionMode string

const (
	// CapabilityMaximize prefers native and then registered projection.
	// CapabilityMaximize 优先原生，其次已注册投影。
	CapabilityMaximize CapabilityExecutionMode = "maximize"
	// CapabilityNativeOnly rejects projected execution.
	// CapabilityNativeOnly 拒绝投影执行。
	CapabilityNativeOnly CapabilityExecutionMode = "native_only"
)

// OptionalUnsupportedAction controls unsupported preferred capabilities.
// OptionalUnsupportedAction 控制不支持的首选能力。
type OptionalUnsupportedAction string

const (
	// OptionalOmit records an omitted decision.
	// OptionalOmit 记录省略决策。
	OptionalOmit OptionalUnsupportedAction = "omit"
	// OptionalUseRegular permits ordinary execution without the optimization.
	// OptionalUseRegular 允许在没有该优化时常规执行。
	OptionalUseRegular OptionalUnsupportedAction = "use_regular"
	// OptionalFail blocks when a preferred capability is unavailable.
	// OptionalFail 在首选能力不可用时阻止执行。
	OptionalFail OptionalUnsupportedAction = "fail"
)

// CapabilityFeature identifies one request-scoped executable feature.
// CapabilityFeature 标识一个请求作用域可执行能力。
type CapabilityFeature string

const (
	// FeatureOrderedContextProjection preserves special context order and identity.
	// FeatureOrderedContextProjection 保留特殊上下文顺序和身份。
	FeatureOrderedContextProjection CapabilityFeature = "ordered_context_projection"
	// FeatureStructuredToolCalling provides reliable structured tool calls.
	// FeatureStructuredToolCalling 提供可靠结构化工具调用。
	FeatureStructuredToolCalling CapabilityFeature = "structured_tool_calling"
	// FeatureParallelToolCalling provides reliable parallel tool calls.
	// FeatureParallelToolCalling 提供可靠并行工具调用。
	FeatureParallelToolCalling CapabilityFeature = "parallel_tool_calling"
	// FeatureStreamingToolArguments provides real upstream argument deltas.
	// FeatureStreamingToolArguments 提供真实上游参数增量。
	FeatureStreamingToolArguments CapabilityFeature = "streaming_tool_arguments"
	// FeatureStrictSchema provides verified strict JSON schema enforcement.
	// FeatureStrictSchema 提供经过验证的严格 JSON Schema 约束。
	FeatureStrictSchema CapabilityFeature = "strict_schema"
	// FeatureImageInput provides native image input.
	// FeatureImageInput 提供原生图像输入。
	FeatureImageInput CapabilityFeature = "image_input"
	// FeatureAudioInput provides native audio input.
	// FeatureAudioInput 提供原生音频输入。
	FeatureAudioInput CapabilityFeature = "audio_input"
	// FeatureVideoInput provides native video input.
	// FeatureVideoInput 提供原生视频输入。
	FeatureVideoInput CapabilityFeature = "video_input"
	// FeatureFileInput provides native file input.
	// FeatureFileInput 提供原生文件输入。
	FeatureFileInput CapabilityFeature = "file_input"
	// FeatureExplicitPromptCache provides explicit prompt cache control.
	// FeatureExplicitPromptCache 提供显式提示词缓存控制。
	FeatureExplicitPromptCache CapabilityFeature = "explicit_prompt_cache"
	// FeatureRemoteCompaction provides provider-native remote compaction.
	// FeatureRemoteCompaction 提供供应商原生远程压缩。
	FeatureRemoteCompaction CapabilityFeature = "remote_compaction"
	// FeatureNativeWebSearch provides provider-hosted web search.
	// FeatureNativeWebSearch 提供供应商托管网页搜索。
	FeatureNativeWebSearch CapabilityFeature = "native_web_search"
	// FeatureReasoning provides requested reasoning controls or summaries.
	// FeatureReasoning 提供请求的推理控制或摘要。
	FeatureReasoning CapabilityFeature = "reasoning"
	// FeatureReasoningContinuation provides opaque provider continuation.
	// FeatureReasoningContinuation 提供不透明供应商续接。
	FeatureReasoningContinuation CapabilityFeature = "reasoning_continuation"
)

// DemandLevel identifies a hard or preferred request capability.
// DemandLevel 标识硬性或首选请求能力。
type DemandLevel string

const (
	// DemandRequired cannot be silently omitted.
	// DemandRequired 不能被静默省略。
	DemandRequired DemandLevel = "required"
	// DemandPreferred may be omitted according to policy.
	// DemandPreferred 可按策略省略。
	DemandPreferred DemandLevel = "preferred"
)

// CapabilityMode identifies the selected execution representation.
// CapabilityMode 标识选定的执行表示。
type CapabilityMode string

const (
	// CapabilityNative uses a verified direct upstream representation.
	// CapabilityNative 使用经过验证的直接上游表示。
	CapabilityNative CapabilityMode = "native"
	// CapabilityProjected uses a registered reversible representation.
	// CapabilityProjected 使用已注册的可逆表示。
	CapabilityProjected CapabilityMode = "projected"
	// CapabilityOmitted records an unused optional behavior.
	// CapabilityOmitted 记录未使用的可选行为。
	CapabilityOmitted CapabilityMode = "omitted"
	// CapabilityBlocked records an unsafe unavailable hard requirement.
	// CapabilityBlocked 记录无法安全满足的硬需求。
	CapabilityBlocked CapabilityMode = "blocked"
)

// CapabilityDemand describes one payload, policy, or runtime requirement.
// CapabilityDemand 描述一个载荷、策略或运行时需求。
type CapabilityDemand struct {
	// Feature identifies the demanded capability.
	// Feature 标识所需能力。
	Feature CapabilityFeature `json:"feature"`
	// Source identifies payload, policy, or runtime derivation.
	// Source 标识载荷、策略或运行时推导来源。
	Source string `json:"source"`
	// Level identifies required or preferred semantics.
	// Level 标识必需或首选语义。
	Level DemandLevel `json:"level"`
	// AcceptedModes lists native and optionally projected representations.
	// AcceptedModes 列出原生以及可选的投影表示。
	AcceptedModes []CapabilityMode `json:"accepted_modes"`
	// OnUnavailable identifies same-provider reroute or failure behavior.
	// OnUnavailable 标识同供应商重路由或失败行为。
	OnUnavailable string `json:"on_unavailable"`
	// SelectedMode records the frozen planning decision.
	// SelectedMode 记录冻结后的规划决策。
	SelectedMode CapabilityMode `json:"selected_mode,omitempty"`
}

// CapabilityPolicy contains caller overrides for automatically derived demands.
// CapabilityPolicy 包含调用方对自动推导需求的覆盖。
type CapabilityPolicy struct {
	// ExecutionMode selects maximize or native-only behavior.
	// ExecutionMode 选择最大化或仅原生行为。
	ExecutionMode CapabilityExecutionMode `json:"execution_mode"`
	// OptionalOnUnsupported controls unavailable preferred demands.
	// OptionalOnUnsupported 控制不可用的首选需求。
	OptionalOnUnsupported OptionalUnsupportedAction `json:"optional_on_unsupported"`
	// ExplicitDemands supplements or strengthens payload-derived demands.
	// ExplicitDemands 补充或加强载荷推导需求。
	ExplicitDemands []CapabilityDemand `json:"explicit_demands,omitempty"`
	// AllowAdvisoryInstructionProjection permits registered advisory Frames.
	// AllowAdvisoryInstructionProjection 允许已注册的建议性 Frame。
	AllowAdvisoryInstructionProjection bool `json:"allow_advisory_instruction_projection"`
}

// CapabilityAvailability describes verified target support for one feature.
// CapabilityAvailability 描述目标对一个能力的已验证支持。
type CapabilityAvailability struct {
	// Feature identifies the capability.
	// Feature 标识能力。
	Feature CapabilityFeature
	// Native reports a verified direct representation.
	// Native 表示存在经过验证的直接表示。
	Native bool
	// Projected reports a registered reversible representation.
	// Projected 表示存在已注册的可逆表示。
	Projected bool
}

// CapabilityPlan is an immutable per-request capability decision snapshot.
// CapabilityPlan 是不可变的逐请求能力决策快照。
type CapabilityPlan struct {
	// RequestID identifies the VCP request.
	// RequestID 标识 VCP 请求。
	RequestID string `json:"request_id"`
	// CatalogRevision records the capability evidence revision.
	// CatalogRevision 记录能力证据修订号。
	CatalogRevision uint64 `json:"catalog_revision"`
	// Demands contains only actually triggered capabilities.
	// Demands 仅包含实际触发的能力。
	Demands []CapabilityDemand `json:"demands"`
	// TargetConstraints contains safe immutable target identifiers.
	// TargetConstraints 包含安全的不可变目标标识。
	TargetConstraints []string `json:"target_constraints,omitempty"`
	// ProjectionRuleVersions contains frozen rule identifiers.
	// ProjectionRuleVersions 包含冻结的规则标识。
	ProjectionRuleVersions []string `json:"projection_rule_versions,omitempty"`
	// GeneratedAt fixes the plan creation time.
	// GeneratedAt 固定计划生成时间。
	GeneratedAt time.Time `json:"generated_at"`
}

// VulcanRequest is the closed VCP 1.0 request envelope.
// VulcanRequest 是封闭的 VCP 1.0 请求信封。
type VulcanRequest struct {
	// ProtocolVersion must equal ProtocolVersion.
	// ProtocolVersion 必须等于 ProtocolVersion。
	ProtocolVersion string `json:"protocol_version"`
	// RequestID is a stable Router-visible request identifier.
	// RequestID 是稳定的 Router 可见请求标识。
	RequestID string `json:"request_id"`
	// IdempotencyKey optionally protects replayable side effects.
	// IdempotencyKey 可选地保护可重放副作用。
	IdempotencyKey string `json:"idempotency_key,omitempty"`
	// ModelSelection describes provider-scoped model intent.
	// ModelSelection 描述供应商作用域模型意图。
	ModelSelection ModelSelection `json:"model_selection"`
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
	// ReasoningPolicy controls explicitly requested reasoning behavior.
	// ReasoningPolicy 控制显式请求的推理行为。
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
	// Stream requests VCP semantic events.
	// Stream 请求 VCP 语义事件。
	Stream bool `json:"stream"`
	// RegisteredExtensions lists allowed request extension identifiers.
	// RegisteredExtensions 列出允许的请求扩展标识。
	RegisteredExtensions []string `json:"registered_extensions,omitempty"`
}

// ExecutionEquivalence identifies upstream semantic strength.
// ExecutionEquivalence 标识上游语义强度。
type ExecutionEquivalence string

const (
	// EquivalenceEquivalent declares verified equivalent semantics.
	// EquivalenceEquivalent 声明经过验证的等价语义。
	EquivalenceEquivalent ExecutionEquivalence = "equivalent"
	// EquivalenceAdvisory preserves identity without native authority guarantees.
	// EquivalenceAdvisory 保留身份但不保证原生权限。
	EquivalenceAdvisory ExecutionEquivalence = "advisory"
	// EquivalenceNone has no valid execution meaning.
	// EquivalenceNone 不具有有效执行含义。
	EquivalenceNone ExecutionEquivalence = "none"
)

// CapabilityDecision is a client-safe capability execution summary.
// CapabilityDecision 是客户端安全的能力执行摘要。
type CapabilityDecision struct {
	// Feature identifies the decided capability.
	// Feature 标识已决策能力。
	Feature CapabilityFeature `json:"feature"`
	// SelectedMode records native, projected, omitted, or blocked.
	// SelectedMode 记录原生、投影、省略或阻止。
	SelectedMode CapabilityMode `json:"selected_mode"`
	// ExecutionEquivalence records equivalent, advisory, or none.
	// ExecutionEquivalence 记录等价、建议性或无执行含义。
	ExecutionEquivalence ExecutionEquivalence `json:"execution_equivalence"`
	// ReasonCode contains a stable safe explanation.
	// ReasonCode 包含稳定且安全的说明。
	ReasonCode string `json:"reason_code"`
}

// RouteSummary exposes safe target facts without credentials or endpoints.
// RouteSummary 暴露不含凭据或端点的安全目标事实。
type RouteSummary struct {
	// ProviderDefinition identifies the provider integration.
	// ProviderDefinition 标识供应商集成。
	ProviderDefinition string `json:"provider_definition"`
	// Model identifies the provider-scoped logical model.
	// Model 标识供应商作用域逻辑模型。
	Model string `json:"model"`
	// ExecutionProfile identifies the selected capability shape.
	// ExecutionProfile 标识选定能力形态。
	ExecutionProfile string `json:"execution_profile"`
	// Plan identifies a safe commercial plan summary when available.
	// Plan 在可用时标识安全商业套餐摘要。
	Plan string `json:"plan,omitempty"`
}

// ExecutionReport is the client-safe execution and conversion summary.
// ExecutionReport 是客户端安全的执行与转换摘要。
type ExecutionReport struct {
	// ResponseID identifies the logical VCP response.
	// ResponseID 标识逻辑 VCP 响应。
	ResponseID string `json:"response_id"`
	// ExecutionID identifies one immutable execution attempt.
	// ExecutionID 标识一次不可变执行尝试。
	ExecutionID string `json:"execution_id"`
	// CatalogRevision records capability evidence.
	// CatalogRevision 记录能力证据。
	CatalogRevision uint64 `json:"catalog_revision"`
	// Route contains safe provider-scoped target facts.
	// Route 包含安全的供应商作用域目标事实。
	Route RouteSummary `json:"route"`
	// CapabilityDecisions contains request-scoped decisions.
	// CapabilityDecisions 包含请求作用域决策。
	CapabilityDecisions []CapabilityDecision `json:"capability_decisions,omitempty"`
	// ConversionSummary contains safe loss and synthesis notes.
	// ConversionSummary 包含安全的损失与合成说明。
	ConversionSummary []string `json:"conversion_summary,omitempty"`
	// CacheObservation records cache facts without inferring unknown values.
	// CacheObservation 记录缓存事实且不推断未知值。
	CacheObservation *CacheObservation `json:"cache_observation,omitempty"`
	// Usage records provider usage observations.
	// Usage 记录供应商用量观测。
	Usage *UsageObservation `json:"usage,omitempty"`
	// ErrorOrRetryAdvice contains a safe terminal summary.
	// ErrorOrRetryAdvice 包含安全终态摘要。
	ErrorOrRetryAdvice string `json:"error_or_retry_advice,omitempty"`
}

// UsageObservation preserves unknown token values as nil.
// UsageObservation 将未知 Token 数值保留为 nil。
type UsageObservation struct {
	// InputTokens is nil when unknown.
	// InputTokens 在未知时为 nil。
	InputTokens *int64 `json:"input_tokens,omitempty"`
	// OutputTokens is nil when unknown.
	// OutputTokens 在未知时为 nil。
	OutputTokens *int64 `json:"output_tokens,omitempty"`
	// ReasoningTokens is nil when unknown.
	// ReasoningTokens 在未知时为 nil。
	ReasoningTokens *int64 `json:"reasoning_tokens,omitempty"`
	// CacheReadTokens is nil when unknown.
	// CacheReadTokens 在未知时为 nil。
	CacheReadTokens *int64 `json:"cache_read_tokens,omitempty"`
	// CacheCreationTokens is nil when unknown.
	// CacheCreationTokens 在未知时为 nil。
	CacheCreationTokens *int64 `json:"cache_creation_tokens,omitempty"`
	// TotalTokens is nil when unknown.
	// TotalTokens 在未知时为 nil。
	TotalTokens *int64 `json:"total_tokens,omitempty"`
	// Source identifies provider-reported, exact, estimated, or derived values.
	// Source 标识供应商报告、精确、估算或推导数值。
	Source string `json:"source"`
	// Aggregation identifies delta, cumulative, or snapshot semantics.
	// Aggregation 标识增量、累计或快照语义。
	Aggregation string `json:"aggregation"`
	// Phase identifies preflight, streaming, terminal, or billing observation.
	// Phase 标识预检、流式、终态或计费观测。
	Phase string `json:"phase"`
	// AccountingBasis records provider token accounting semantics.
	// AccountingBasis 记录供应商 Token 计量语义。
	AccountingBasis string `json:"accounting_basis"`
	// Final reports whether the observation is terminal.
	// Final 表示当前观测是否为终态。
	Final bool `json:"final"`
}

// Lineage binds logical response state to one immutable provider execution scope.
// Lineage 将逻辑响应状态绑定到一个不可变供应商执行作用域。
type Lineage struct {
	// LineageID identifies the internal lineage record.
	// LineageID 标识内部谱系记录。
	LineageID string `json:"lineage_id"`
	// LogicalResponseID identifies the public VCP response.
	// LogicalResponseID 标识公共 VCP 响应。
	LogicalResponseID string `json:"logical_response_id"`
	// ContinuationID identifies a Router-owned continuation.
	// ContinuationID 标识 Router 拥有的续接。
	ContinuationID string `json:"continuation_id,omitempty"`
	// ProviderDefinitionID fixes provider integration ownership.
	// ProviderDefinitionID 固定供应商集成所有权。
	ProviderDefinitionID string `json:"provider_definition_id"`
	// ProviderInstanceID fixes the provider instance boundary.
	// ProviderInstanceID 固定供应商实例边界。
	ProviderInstanceID string `json:"provider_instance_id"`
	// ChannelID fixes protocol channel ownership.
	// ChannelID 固定协议通道所有权。
	ChannelID string `json:"channel_id"`
	// ProviderModelID fixes the logical model.
	// ProviderModelID 固定逻辑模型。
	ProviderModelID string `json:"provider_model_id"`
	// ExecutionProfileID fixes the capability profile.
	// ExecutionProfileID 固定能力规格。
	ExecutionProfileID string `json:"execution_profile_id"`
	// ProjectionLedgerRefs references persisted projection ledgers.
	// ProjectionLedgerRefs 引用持久化投影账本。
	ProjectionLedgerRefs []string `json:"projection_ledger_refs,omitempty"`
	// OpaqueStateRefs references sealed provider state.
	// OpaqueStateRefs 引用密封供应商状态。
	OpaqueStateRefs []string `json:"opaque_state_refs,omitempty"`
	// ExpiresAt bounds replay and continuation validity.
	// ExpiresAt 限制回放与续接有效期。
	ExpiresAt time.Time `json:"expires_at"`
}

// Continuation is the client-safe reference to Router-owned lineage state.
// Continuation 是指向 Router 所有谱系状态的客户端安全引用。
type Continuation struct {
	// ContinuationID is safe for client replay.
	// ContinuationID 可安全用于客户端回放。
	ContinuationID string `json:"continuation_id"`
	// LogicalResponseID identifies the preceding response.
	// LogicalResponseID 标识前序响应。
	LogicalResponseID string `json:"logical_response_id"`
	// AffinitySummary describes required provider affinity without secrets.
	// AffinitySummary 描述不含秘密的供应商亲和性要求。
	AffinitySummary string `json:"affinity_summary"`
	// ExpiresAt bounds continuation validity.
	// ExpiresAt 限制续接有效期。
	ExpiresAt time.Time `json:"expires_at"`
}
