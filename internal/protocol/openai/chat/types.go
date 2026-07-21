// Package chat implements the VCP 1.0 to OpenAI Chat Completions protocol profile.
// Package chat 实现 VCP 1.0 到 OpenAI Chat Completions 的协议 Profile。
//
// Portions of these typed wire carriers are adapted from CLIProxyAPI commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// 这些类型化 wire 载体的部分逻辑改编自 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66。
// Source paths: sdk/api/handlers/openai/openai_handlers.go and internal/runtime/executor/openai_compat_executor.go.
// 来源路径：sdk/api/handlers/openai/openai_handlers.go 和 internal/runtime/executor/openai_compat_executor.go。
// The adapted scope is closed Chat protocol fields; VCP owns all canonical state.
// 改编范围是封闭 Chat 协议字段；所有规范状态由 VCP 所有。
package chat

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

const (
	// ProfileID is the stable upstream protocol profile identifier for OpenAI Chat Completions.
	// ProfileID 是 OpenAI Chat Completions 的稳定上游协议 Profile 标识。
	ProfileID = "openai.chat"
)

var (
	// ErrInvalidTarget reports an incomplete resolved execution target.
	// ErrInvalidTarget 表示解析后的执行目标不完整。
	ErrInvalidTarget = errors.New("invalid OpenAI Chat execution target")
	// ErrUnsupportedContext reports context that cannot be safely projected.
	// ErrUnsupportedContext 表示无法安全投影的上下文。
	ErrUnsupportedContext = errors.New("unsupported OpenAI Chat context")
	// ErrInvalidUpstreamResponse reports malformed upstream response semantics.
	// ErrInvalidUpstreamResponse 表示上游响应语义格式错误。
	ErrInvalidUpstreamResponse = errors.New("invalid OpenAI Chat response")
)

// ProfileCapabilities contains verified Channel/Profile behavior.
// ProfileCapabilities 包含经过验证的 Channel/Profile 行为。
type ProfileCapabilities struct {
	// MediaInputKinds lists media families represented by this exact provider Profile.
	// MediaInputKinds 列出此精确供应商 Profile 表示的媒体类别。
	MediaInputKinds []vcp.MediaKind
	// MediaMaterializations lists resource representations preserved by this exact provider Profile.
	// MediaMaterializations 列出此精确供应商 Profile 可保真的资源表示方式。
	MediaMaterializations []catalog.UpstreamMaterializationMode
	// NativeSystemPreamble reports verified system message support at the first position.
	// NativeSystemPreamble 表示经过验证的首位 system 消息支持。
	NativeSystemPreamble bool
	// NativeDeveloper reports verified developer role support.
	// NativeDeveloper 表示经过验证的 developer 角色支持。
	NativeDeveloper bool
	// NativeInlineSystem reports verified transcript-position system support.
	// NativeInlineSystem 表示经过验证的会话位置 system 支持。
	NativeInlineSystem bool
	// StructuredTools reports verified function tool support.
	// StructuredTools 表示经过验证的函数工具支持。
	StructuredTools bool
	// ParallelTools reports verified parallel tool call support.
	// ParallelTools 表示经过验证的并行工具调用支持。
	ParallelTools bool
	// StreamingToolArguments reports real upstream argument delta support.
	// StreamingToolArguments 表示真实上游参数增量支持。
	StreamingToolArguments bool
	// StrictJSONSchema reports verified strict response format support.
	// StrictJSONSchema 表示经过验证的严格响应格式支持。
	StrictJSONSchema bool
	// Reasoning reports verified Chat reasoning parameter support.
	// Reasoning 表示经过验证的 Chat 推理参数支持。
	Reasoning bool
	// ReasoningContent reports verified reasoning_content response and replay support.
	// ReasoningContent 表示经过验证的 reasoning_content 响应与回放支持。
	ReasoningContent bool
	// StreamUsage reports verified stream_options.include_usage support.
	// StreamUsage 表示经过验证的 stream_options.include_usage 支持。
	StreamUsage bool
}

// Request is the typed OpenAI Chat Completions request body.
// Request 是类型化的 OpenAI Chat Completions 请求体。
type Request struct {
	// Model is the exact resolved upstream model identifier.
	// Model 是精确解析的上游模型标识。
	Model string `json:"model"`
	// Messages contains ordered upstream transcript carriers.
	// Messages 包含有序上游会话载体。
	Messages []Message `json:"messages"`
	// Stream requests upstream streaming.
	// Stream 请求上游流式传输。
	Stream bool `json:"stream,omitempty"`
	// StreamOptions requests usage only when the profile supports it.
	// StreamOptions 仅在 Profile 支持时请求用量。
	StreamOptions *StreamOptions `json:"stream_options,omitempty"`
	// Temperature maps VCP sampling temperature explicitly.
	// Temperature 显式映射 VCP 采样温度。
	Temperature *float64 `json:"temperature,omitempty"`
	// TopP maps VCP nucleus sampling explicitly.
	// TopP 显式映射 VCP 核采样。
	TopP *float64 `json:"top_p,omitempty"`
	// MaxCompletionTokens maps VCP maximum output tokens.
	// MaxCompletionTokens 映射 VCP 最大输出 Token。
	MaxCompletionTokens *int `json:"max_completion_tokens,omitempty"`
	// Stop maps explicit stop sequences.
	// Stop 映射显式停止序列。
	Stop []string `json:"stop,omitempty"`
	// Tools contains only structured function declarations.
	// Tools 仅包含结构化函数声明。
	Tools []Tool `json:"tools,omitempty"`
	// ToolChoice contains a typed automatic, disabled, required, or named choice.
	// ToolChoice 包含类型化自动、禁用、必需或指定选择。
	ToolChoice *ToolChoice `json:"tool_choice,omitempty"`
	// ParallelToolCalls is absent when tools are empty or parallel controls are not verified for the target.
	// ParallelToolCalls 在 tools 为空或 Target 未验证并行控制时缺失。
	ParallelToolCalls *bool `json:"parallel_tool_calls,omitempty"`
	// ResponseFormat contains a verified strict JSON Schema request.
	// ResponseFormat 包含经过验证的严格 JSON Schema 请求。
	ResponseFormat *ResponseFormat `json:"response_format,omitempty"`
	// ReasoningEffort constrains verified OpenAI Chat reasoning-model effort.
	// ReasoningEffort 约束经过验证的 OpenAI Chat 推理模型强度。
	ReasoningEffort string `json:"reasoning_effort,omitempty"`
	// Thinking carries the typed Moonshot thinking switch only after an explicitly registered provider adapter selects it.
	// Thinking 仅在显式注册的供应商适配器选择后携带类型化 Moonshot 思考开关。
	Thinking *ThinkingConfiguration `json:"thinking,omitempty"`
}

// ThinkingMode identifies one closed Moonshot thinking switch value.
// ThinkingMode 标识一个封闭的 Moonshot 思考开关值。
type ThinkingMode string

const (
	// ThinkingEnabled requests the provider's thinking route.
	// ThinkingEnabled 请求供应商的思考路由。
	ThinkingEnabled ThinkingMode = "enabled"
	// ThinkingDisabled requests the provider's non-thinking route.
	// ThinkingDisabled 请求供应商的非思考路由。
	ThinkingDisabled ThinkingMode = "disabled"
)

// ThinkingConfiguration contains the provider-verified Moonshot thinking extension.
// ThinkingConfiguration 包含供应商已验证的 Moonshot 思考扩展。
type ThinkingConfiguration struct {
	// Type selects the enabled or disabled thinking route.
	// Type 选择启用或禁用思考的路由。
	Type ThinkingMode `json:"type"`
}

// StreamOptions contains OpenAI Chat stream usage options.
// StreamOptions 包含 OpenAI Chat 流用量选项。
type StreamOptions struct {
	// IncludeUsage requests the standard usage-only terminal chunk.
	// IncludeUsage 请求标准的仅用量终态分片。
	IncludeUsage bool `json:"include_usage"`
}

// Message is one typed OpenAI Chat message.
// Message 是一条类型化 OpenAI Chat 消息。
type Message struct {
	// Role identifies system, developer, user, assistant, or tool.
	// Role 标识 system、developer、user、assistant 或 tool。
	Role string `json:"role"`
	// Content contains text when applicable.
	// Content 在适用时包含文本。
	Content string `json:"-"`
	// ContentParts contains an ordered typed user multimodal payload when present.
	// ContentParts 在存在时包含有序的类型化用户多模态载荷。
	ContentParts []ContentPart `json:"-"`
	// ReasoningContent preserves provider-visible reasoning only for profiles with an explicit carrier contract.
	// ReasoningContent 仅为具有显式载体契约的 Profile 保留供应商可见推理。
	ReasoningContent string `json:"reasoning_content,omitempty"`
	// ToolCalls contains historical assistant tool calls.
	// ToolCalls 包含历史助手工具调用。
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`
	// ToolCallID binds a tool result to its call.
	// ToolCallID 将工具结果绑定到其调用。
	ToolCallID string `json:"tool_call_id,omitempty"`
}

// MarshalJSON emits the closed Chat content union as either text or typed parts.
// MarshalJSON 将封闭的 Chat 内容联合编码为文本或类型化内容块。
func (m Message) MarshalJSON() ([]byte, error) {
	if len(m.ContentParts) > 0 {
		return json.Marshal(struct {
			// Role is the upstream Chat role.
			// Role 是上游 Chat 角色。
			Role string `json:"role"`
			// Content contains typed multimodal parts.
			// Content 包含类型化多模态内容块。
			Content []ContentPart `json:"content"`
			// ReasoningContent contains provider-visible reasoning content when supported.
			// ReasoningContent 包含支持时的供应商可见推理内容。
			ReasoningContent string `json:"reasoning_content,omitempty"`
			// ToolCalls contains structured assistant tool calls.
			// ToolCalls 包含结构化助手工具调用。
			ToolCalls []ToolCall `json:"tool_calls,omitempty"`
			// ToolCallID binds a tool result to its call.
			// ToolCallID 将工具结果绑定到其调用。
			ToolCallID string `json:"tool_call_id,omitempty"`
		}{Role: m.Role, Content: m.ContentParts, ReasoningContent: m.ReasoningContent, ToolCalls: m.ToolCalls, ToolCallID: m.ToolCallID})
	}
	return json.Marshal(struct {
		// Role is the upstream Chat role.
		// Role 是上游 Chat 角色。
		Role string `json:"role"`
		// Content contains plain text content.
		// Content 包含纯文本内容。
		Content string `json:"content,omitempty"`
		// ReasoningContent contains provider-visible reasoning content when supported.
		// ReasoningContent 包含支持时的供应商可见推理内容。
		ReasoningContent string `json:"reasoning_content,omitempty"`
		// ToolCalls contains structured assistant tool calls.
		// ToolCalls 包含结构化助手工具调用。
		ToolCalls []ToolCall `json:"tool_calls,omitempty"`
		// ToolCallID binds a tool result to its call.
		// ToolCallID 将工具结果绑定到其调用。
		ToolCallID string `json:"tool_call_id,omitempty"`
	}{Role: m.Role, Content: m.Content, ReasoningContent: m.ReasoningContent, ToolCalls: m.ToolCalls, ToolCallID: m.ToolCallID})
}

// UnmarshalJSON decodes the closed Chat text-or-parts union for exact request fixture inspection.
// UnmarshalJSON 解码封闭的 Chat 文本或内容块联合，以便精确检查请求夹具。
func (m *Message) UnmarshalJSON(data []byte) error {
	if m == nil {
		return errors.New("cannot unmarshal OpenAI Chat message into nil receiver")
	}
	var wire struct {
		// Role is the decoded upstream Chat role.
		// Role 是解码后的上游 Chat 角色。
		Role string `json:"role"`
		// Content preserves the text-or-parts wire union for exact decoding.
		// Content 为精确解码保留文本或内容块 Wire 联合。
		Content json.RawMessage `json:"content"`
		// ReasoningContent contains provider-visible reasoning content when present.
		// ReasoningContent 包含存在时的供应商可见推理内容。
		ReasoningContent string `json:"reasoning_content,omitempty"`
		// ToolCalls contains decoded structured tool calls.
		// ToolCalls 包含解码后的结构化工具调用。
		ToolCalls []ToolCall `json:"tool_calls,omitempty"`
		// ToolCallID binds a decoded tool result to its call.
		// ToolCallID 将解码后的工具结果绑定到其调用。
		ToolCallID string `json:"tool_call_id,omitempty"`
	}
	if errDecode := json.Unmarshal(data, &wire); errDecode != nil {
		return errDecode
	}
	*m = Message{Role: wire.Role, ReasoningContent: wire.ReasoningContent, ToolCalls: wire.ToolCalls, ToolCallID: wire.ToolCallID}
	trimmed := bytes.TrimSpace(wire.Content)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	if trimmed[0] == '"' {
		return json.Unmarshal(trimmed, &m.Content)
	}
	if trimmed[0] == '[' {
		return json.Unmarshal(trimmed, &m.ContentParts)
	}
	return fmt.Errorf("invalid OpenAI Chat message content union")
}

// ContentPart is one evidence-closed OpenAI Chat user content block.
// ContentPart 是一个证据封闭的 OpenAI Chat 用户内容块。
type ContentPart struct {
	// Type selects text, image_url, or input_audio.
	// Type 选择 text、image_url 或 input_audio。
	Type string `json:"type"`
	// Text contains a text block.
	// Text 包含文本块。
	Text string `json:"text,omitempty"`
	// ImageURL contains an image URL or inline data URL.
	// ImageURL 包含图片 URL 或内联 Data URL。
	ImageURL *ImageURL `json:"image_url,omitempty"`
	// InputAudio contains inline audio bytes and their documented encoding.
	// InputAudio 包含内联音频字节及其已记录编码。
	InputAudio *InputAudio `json:"input_audio,omitempty"`
}

// ImageURL is the typed OpenAI Chat image_url payload.
// ImageURL 是类型化 OpenAI Chat image_url 载荷。
type ImageURL struct {
	// URL is a remote or base64 data URL accepted by Chat.
	// URL 是 Chat 接受的远程 URL 或 Base64 Data URL。
	URL string `json:"url"`
}

// InputAudio is the typed OpenAI Chat input_audio payload.
// InputAudio 是类型化 OpenAI Chat input_audio 载荷。
type InputAudio struct {
	// Data contains base64 audio bytes without a data URL prefix.
	// Data 包含不带 Data URL 前缀的 Base64 音频字节。
	Data string `json:"data"`
	// Format is the documented mp3 or wav encoding name.
	// Format 是已记录的 mp3 或 wav 编码名称。
	Format string `json:"format"`
}

// Tool is one OpenAI function tool declaration.
// Tool 是一个 OpenAI 函数工具声明。
type Tool struct {
	// Type is fixed to function.
	// Type 固定为 function。
	Type string `json:"type"`
	// Function contains the typed declaration.
	// Function 包含类型化声明。
	Function FunctionDefinition `json:"function"`
}

// FunctionDefinition is one OpenAI function declaration.
// FunctionDefinition 是一个 OpenAI 函数声明。
type FunctionDefinition struct {
	// Name is the exact VCP tool name.
	// Name 是精确 VCP 工具名称。
	Name string `json:"name"`
	// Description contains model-visible guidance.
	// Description 包含模型可见说明。
	Description string `json:"description,omitempty"`
	// Parameters contains validated JSON Schema.
	// Parameters 包含经过校验的 JSON Schema。
	Parameters json.RawMessage `json:"parameters"`
	// Strict requests verified strict function schema behavior.
	// Strict 请求经过验证的严格函数 Schema 行为。
	Strict bool `json:"strict,omitempty"`
}

// ToolChoice is a typed OpenAI tool choice union.
// ToolChoice 是类型化 OpenAI 工具选择联合。
type ToolChoice struct {
	// Mode identifies auto, none, required, or named.
	// Mode 标识 auto、none、required 或 named。
	Mode vcp.ToolChoiceMode
	// FunctionName is required for named mode.
	// FunctionName 在 named 模式下必填。
	FunctionName string
}

// MarshalJSON emits the exact OpenAI string or named-function shape.
// MarshalJSON 输出精确的 OpenAI 字符串或指定函数形态。
func (c ToolChoice) MarshalJSON() ([]byte, error) {
	if c.Mode != vcp.ToolChoiceNamed {
		return json.Marshal(string(c.Mode))
	}
	// namedChoice is the closed OpenAI named-function representation.
	// namedChoice 是封闭的 OpenAI 指定函数表示。
	namedChoice := struct {
		// Type fixes the named tool choice to a function.
		// Type 将具名工具选择固定为函数。
		Type string `json:"type"`
		// Function contains the exact selected function identity.
		// Function 包含精确选定的函数身份。
		Function struct {
			// Name is the exact selected function name.
			// Name 是精确选定的函数名称。
			Name string `json:"name"`
		} `json:"function"`
	}{Type: "function"}
	namedChoice.Function.Name = c.FunctionName
	return json.Marshal(namedChoice)
}

// ResponseFormat is the typed strict JSON Schema response format.
// ResponseFormat 是类型化严格 JSON Schema 响应格式。
type ResponseFormat struct {
	// Type is fixed to json_schema.
	// Type 固定为 json_schema。
	Type string `json:"type"`
	// JSONSchema contains the complete named strict-schema configuration.
	// JSONSchema 包含完整的具名严格 Schema 配置。
	JSONSchema JSONSchemaConfiguration `json:"json_schema"`
}

// JSONSchemaConfiguration is the closed OpenAI Chat json_schema configuration carrier.
// JSONSchemaConfiguration 是封闭的 OpenAI Chat json_schema 配置载体。
type JSONSchemaConfiguration struct {
	// Name is the stable profile-owned schema name required by OpenAI Chat.
	// Name 是 OpenAI Chat 要求的稳定 Profile 所有 Schema 名称。
	Name string `json:"name"`
	// Schema contains the caller-provided validated JSON Schema.
	// Schema 包含调用方提供且已校验的 JSON Schema。
	Schema json.RawMessage `json:"schema"`
	// Strict requests strict upstream validation for the named schema.
	// Strict 请求上游对具名 Schema 进行严格校验。
	Strict bool `json:"strict"`
}

// ToolCall is one complete OpenAI Chat function call.
// ToolCall 是一个完整 OpenAI Chat 函数调用。
type ToolCall struct {
	// ID is the upstream call identifier when reported.
	// ID 是上游报告的调用标识。
	ID string `json:"id,omitempty"`
	// Type is normally function.
	// Type 通常为 function。
	Type string `json:"type,omitempty"`
	// Function contains the function name and arguments.
	// Function 包含函数名称和参数。
	Function FunctionCall `json:"function"`
}

// FunctionCall contains OpenAI function call data.
// FunctionCall 包含 OpenAI 函数调用数据。
type FunctionCall struct {
	// Name is the function name when reported.
	// Name 是上游报告的函数名称。
	Name string `json:"name,omitempty"`
	// Arguments is the exact assembled JSON text.
	// Arguments 是精确归并后的 JSON 文本。
	Arguments string `json:"arguments,omitempty"`
}

// Response is the typed non-streaming OpenAI Chat response.
// Response 是类型化非流式 OpenAI Chat 响应。
type Response struct {
	// ID is the upstream response identifier.
	// ID 是上游响应标识。
	ID string `json:"id,omitempty"`
	// Object is the documented Chat completion response discriminator.
	// Object 是文档化的 Chat completion 响应判别字段。
	Object string `json:"object,omitempty"`
	// Created is the provider creation timestamp that VCP does not currently carry.
	// Created 是 VCP 当前不承载的 Provider 创建时间戳。
	Created *int64 `json:"created,omitempty"`
	// Model is the upstream model identifier.
	// Model 是上游模型标识。
	Model string `json:"model,omitempty"`
	// Choices contains upstream completion alternatives.
	// Choices 包含上游补全候选。
	Choices []Choice `json:"choices,omitempty"`
	// Usage contains terminal usage when reported.
	// Usage 包含上游报告的终态用量。
	Usage *Usage `json:"usage,omitempty"`
	// ServiceTier is the provider-selected processing tier without a VCP response carrier.
	// ServiceTier 是没有 VCP 响应承载字段的 Provider 所选处理层级。
	ServiceTier string `json:"service_tier,omitempty"`
	// SystemFingerprint is the provider backend fingerprint without a VCP response carrier.
	// SystemFingerprint 是没有 VCP 响应承载字段的 Provider 后端指纹。
	SystemFingerprint string `json:"system_fingerprint,omitempty"`
	// Error contains a structured upstream failure envelope.
	// Error 包含结构化上游失败信封。
	Error *Error `json:"error,omitempty"`
}

// Choice contains one non-streaming or streaming Chat choice.
// Choice 包含一个非流式或流式 Chat 候选。
type Choice struct {
	// Index identifies the upstream choice.
	// Index 标识上游候选。
	Index int `json:"index"`
	// Message contains terminal assistant data when present.
	// Message 在存在时包含终态助手数据。
	Message *AssistantMessage `json:"message,omitempty"`
	// Delta contains streaming assistant data when present.
	// Delta 在存在时包含流式助手数据。
	Delta *Delta `json:"delta,omitempty"`
	// FinishReason records the upstream terminal reason.
	// FinishReason 记录上游终止原因。
	FinishReason string `json:"finish_reason,omitempty"`
	// Logprobs detects token likelihood metadata that this first-phase VCP profile cannot represent.
	// Logprobs 检测到本第一阶段 VCP Profile 无法表示的 Token 概率元数据。
	Logprobs *UnsupportedResponsePayload `json:"logprobs,omitempty"`
}

// AssistantMessage contains OpenAI assistant output.
// AssistantMessage 包含 OpenAI 助手输出。
type AssistantMessage struct {
	// Role is normally assistant.
	// Role 通常为 assistant。
	Role string `json:"role,omitempty"`
	// Content contains assistant text.
	// Content 包含助手文本。
	Content string `json:"content,omitempty"`
	// ReasoningContent contains provider-returned reasoning text when the compatible upstream exposes it.
	// ReasoningContent 包含兼容上游明确返回的推理文本。
	ReasoningContent string `json:"reasoning_content,omitempty"`
	// Refusal contains structured refusal text.
	// Refusal 包含结构化拒绝文本。
	Refusal string `json:"refusal,omitempty"`
	// ToolCalls contains complete function calls.
	// ToolCalls 包含完整函数调用。
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`
	// FunctionCall is the deprecated single-function carrier that remains safely projectable as one VCP tool call.
	// FunctionCall 是已废弃的单函数载体，仍可安全投影为一个 VCP 工具调用。
	FunctionCall *FunctionCall `json:"function_call,omitempty"`
	// Annotations detects citation metadata that this first-phase VCP profile cannot represent.
	// Annotations 检测到本第一阶段 VCP Profile 无法表示的引文元数据。
	Annotations []UnsupportedResponsePayload `json:"annotations,omitempty"`
	// Audio detects an audio response payload outside this text-only first-phase profile.
	// Audio 检测到超出此文本优先第一阶段 Profile 范围的音频响应载荷。
	Audio *UnsupportedResponsePayload `json:"audio,omitempty"`
}

// Delta contains one streaming Chat assistant delta.
// Delta 包含一个流式 Chat 助手增量。
type Delta struct {
	// Role reports the assistant role when present.
	// Role 在存在时报告助手角色。
	Role string `json:"role,omitempty"`
	// Content contains an actual upstream text fragment.
	// Content 包含真实上游文本片段。
	Content string `json:"content,omitempty"`
	// ReasoningContent contains one actual provider reasoning fragment.
	// ReasoningContent 包含一个真实的供应商推理片段。
	ReasoningContent string `json:"reasoning_content,omitempty"`
	// Refusal contains an actual upstream refusal fragment.
	// Refusal 包含真实上游拒绝片段。
	Refusal string `json:"refusal,omitempty"`
	// ToolCalls contains actual upstream tool deltas.
	// ToolCalls 包含真实上游工具增量。
	ToolCalls []ToolCallDelta `json:"tool_calls,omitempty"`
	// FunctionCall is the deprecated single-function delta carrier that remains safely projectable as one VCP tool call.
	// FunctionCall 是已废弃的单函数增量载体，仍可安全投影为一个 VCP 工具调用。
	FunctionCall *FunctionCall `json:"function_call,omitempty"`
	// Audio detects an audio response delta outside this text-only first-phase profile.
	// Audio 检测到超出此文本优先第一阶段 Profile 范围的音频响应增量。
	Audio *UnsupportedResponsePayload `json:"audio,omitempty"`
}

// ToolCallDelta contains one indexed streaming function call delta.
// ToolCallDelta 包含一个带索引的流式函数调用增量。
type ToolCallDelta struct {
	// Index identifies one parallel call inside the choice.
	// Index 标识候选内的一个并行调用。
	Index int `json:"index"`
	// ID contains a possibly delayed upstream identifier.
	// ID 包含可能延迟到达的上游标识。
	ID string `json:"id,omitempty"`
	// Type is normally function.
	// Type 通常为 function。
	Type string `json:"type,omitempty"`
	// Function contains possibly delayed name and argument fragments.
	// Function 包含可能延迟的名称和参数片段。
	Function FunctionCall `json:"function"`
}

// Chunk is one parsed OpenAI Chat streaming object.
// Chunk 是一个解析后的 OpenAI Chat 流对象。
type Chunk struct {
	// ID is the upstream response identifier when reported.
	// ID 是上游报告的响应标识。
	ID string `json:"id,omitempty"`
	// Object is the documented Chat completion chunk discriminator.
	// Object 是文档化的 Chat completion 分片判别字段。
	Object string `json:"object,omitempty"`
	// Created is the provider chunk creation timestamp that VCP does not currently carry.
	// Created 是 VCP 当前不承载的 Provider 分片创建时间戳。
	Created *int64 `json:"created,omitempty"`
	// Model is the upstream model identifier when reported.
	// Model 是上游报告的模型标识。
	Model string `json:"model,omitempty"`
	// Choices contains zero or more semantic deltas.
	// Choices 包含零个或多个语义增量。
	Choices []Choice `json:"choices,omitempty"`
	// Usage supports a standard usage-only chunk.
	// Usage 支持标准的仅用量分片。
	Usage *Usage `json:"usage,omitempty"`
	// ServiceTier is the provider-selected processing tier without a VCP response carrier.
	// ServiceTier 是没有 VCP 响应承载字段的 Provider 所选处理层级。
	ServiceTier string `json:"service_tier,omitempty"`
	// SystemFingerprint is the provider backend fingerprint without a VCP response carrier.
	// SystemFingerprint 是没有 VCP 响应承载字段的 Provider 后端指纹。
	SystemFingerprint string `json:"system_fingerprint,omitempty"`
	// Error contains an in-stream structured failure.
	// Error 包含流内结构化失败。
	Error *Error `json:"error,omitempty"`
}

// Usage contains OpenAI Chat usage fields with pointer-based unknown values.
// Usage 包含使用指针表示未知值的 OpenAI Chat 用量字段。
type Usage struct {
	// PromptTokens is nil when not reported.
	// PromptTokens 在未报告时为 nil。
	PromptTokens *int64 `json:"prompt_tokens,omitempty"`
	// CompletionTokens is nil when not reported.
	// CompletionTokens 在未报告时为 nil。
	CompletionTokens *int64 `json:"completion_tokens,omitempty"`
	// TotalTokens is nil when not reported.
	// TotalTokens 在未报告时为 nil。
	TotalTokens *int64 `json:"total_tokens,omitempty"`
	// PromptDetails contains cache observations when reported.
	// PromptDetails 在报告时包含缓存观测。
	PromptDetails *PromptTokenDetails `json:"prompt_tokens_details,omitempty"`
	// CompletionDetails contains reasoning observations when reported.
	// CompletionDetails 在报告时包含推理观测。
	CompletionDetails *CompletionTokenDetails `json:"completion_tokens_details,omitempty"`
	// CostInUSDTicks is xAI-compatible cost accounting without a VCP billing carrier.
	// CostInUSDTicks 是没有 VCP 计费承载字段的 xAI 兼容成本计量。
	CostInUSDTicks *int64 `json:"cost_in_usd_ticks,omitempty"`
	// NumSourcesUsed is xAI-compatible server-side source accounting without a VCP usage carrier.
	// NumSourcesUsed 是没有 VCP 用量承载字段的 xAI 兼容服务端来源计量。
	NumSourcesUsed *int64 `json:"num_sources_used,omitempty"`
}

// PromptTokenDetails contains OpenAI prompt token details.
// PromptTokenDetails 包含 OpenAI 提示词 Token 明细。
type PromptTokenDetails struct {
	// CachedTokens is nil when not reported.
	// CachedTokens 在未报告时为 nil。
	CachedTokens *int64 `json:"cached_tokens,omitempty"`
	// CacheCreationTokens is nil when not reported by compatible upstreams.
	// CacheCreationTokens 在兼容上游未报告时为 nil。
	CacheCreationTokens *int64 `json:"cache_creation_input_tokens,omitempty"`
	// AudioTokens is the provider-reported audio input accounting without a VCP accounting carrier.
	// AudioTokens 是没有 VCP 计量承载字段的 Provider 音频输入计量。
	AudioTokens *int64 `json:"audio_tokens,omitempty"`
	// TextTokens is xAI-compatible text input accounting without a VCP accounting carrier.
	// TextTokens 是没有 VCP 计量承载字段的 xAI 兼容文本输入计量。
	TextTokens *int64 `json:"text_tokens,omitempty"`
	// ImageTokens is xAI-compatible image input accounting without a VCP accounting carrier.
	// ImageTokens 是没有 VCP 计量承载字段的 xAI 兼容图像输入计量。
	ImageTokens *int64 `json:"image_tokens,omitempty"`
}

// CompletionTokenDetails contains OpenAI completion token details.
// CompletionTokenDetails 包含 OpenAI 补全 Token 明细。
type CompletionTokenDetails struct {
	// ReasoningTokens is nil when not reported.
	// ReasoningTokens 在未报告时为 nil。
	ReasoningTokens *int64 `json:"reasoning_tokens,omitempty"`
	// AudioTokens is the provider-reported generated audio accounting without a VCP accounting carrier.
	// AudioTokens 是没有 VCP 计量承载字段的 Provider 生成音频计量。
	AudioTokens *int64 `json:"audio_tokens,omitempty"`
	// AcceptedPredictionTokens is predicted-output accounting without a VCP accounting carrier.
	// AcceptedPredictionTokens 是没有 VCP 计量承载字段的预测输出接受计量。
	AcceptedPredictionTokens *int64 `json:"accepted_prediction_tokens,omitempty"`
	// RejectedPredictionTokens is predicted-output accounting without a VCP accounting carrier.
	// RejectedPredictionTokens 是没有 VCP 计量承载字段的预测输出拒绝计量。
	RejectedPredictionTokens *int64 `json:"rejected_prediction_tokens,omitempty"`
}

// UnsupportedResponsePayload detects a documented response field without retaining its provider payload.
// UnsupportedResponsePayload 在不保留其 Provider 载荷的前提下检测一个文档化响应字段。
type UnsupportedResponsePayload struct{}

// UnmarshalJSON accepts any documented JSON payload shape while intentionally discarding its contents.
// UnmarshalJSON 接受任何文档化 JSON 载荷形态，同时有意丢弃其内容。
func (*UnsupportedResponsePayload) UnmarshalJSON([]byte) error {
	return nil
}

// Error contains safe upstream error fields.
// Error 包含安全上游错误字段。
type Error struct {
	// Type identifies the upstream error class.
	// Type 标识上游错误类别。
	Type string `json:"type,omitempty"`
	// Code identifies the upstream error code.
	// Code 标识上游错误代码。
	Code string `json:"code,omitempty"`
	// Message is intentionally not copied into ordinary VCP reports.
	// Message 有意不复制到普通 VCP 报告中。
	Message string `json:"message,omitempty"`
}

// ProjectedRequest contains a frozen request, plan, ledger, and safe report.
// ProjectedRequest 包含冻结的请求、计划、账本和安全报告。
type ProjectedRequest struct {
	// Upstream is the typed OpenAI Chat request.
	// Upstream 是类型化 OpenAI Chat 请求。
	Upstream Request
	// CapabilityPlan is frozen before request serialization.
	// CapabilityPlan 在请求序列化前冻结。
	CapabilityPlan vcp.CapabilityPlan
	// ProjectionPlan is frozen before request serialization.
	// ProjectionPlan 在请求序列化前冻结。
	ProjectionPlan vcp.ProjectionPlan
	// Ledger is the authoritative reversible context record.
	// Ledger 是权威的可逆上下文记录。
	Ledger vcp.ProjectionLedger
	// Report is safe for the VCP client.
	// Report 对 VCP 客户端安全。
	Report vcp.ExecutionReport
}
