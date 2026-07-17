// Package chat implements the VCP 1.0 to OpenAI Chat Completions protocol profile.
// Package chat 实现 VCP 1.0 到 OpenAI Chat Completions 的协议 Profile。
package chat

import (
	"encoding/json"
	"errors"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
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
	// ParallelToolCalls is absent when tools are empty.
	// ParallelToolCalls 在 tools 为空时缺失。
	ParallelToolCalls *bool `json:"parallel_tool_calls,omitempty"`
	// ResponseFormat contains a verified strict JSON Schema request.
	// ResponseFormat 包含经过验证的严格 JSON Schema 请求。
	ResponseFormat *ResponseFormat `json:"response_format,omitempty"`
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
	Content string `json:"content,omitempty"`
	// ToolCalls contains historical assistant tool calls.
	// ToolCalls 包含历史助手工具调用。
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`
	// ToolCallID binds a tool result to its call.
	// ToolCallID 将工具结果绑定到其调用。
	ToolCallID string `json:"tool_call_id,omitempty"`
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
		Type     string `json:"type"`
		Function struct {
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
	// JSONSchema contains the caller-provided verified schema.
	// JSONSchema 包含调用方提供且经过验证的 Schema。
	JSONSchema json.RawMessage `json:"json_schema"`
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
	// Model is the upstream model identifier.
	// Model 是上游模型标识。
	Model string `json:"model,omitempty"`
	// Choices contains upstream completion alternatives.
	// Choices 包含上游补全候选。
	Choices []Choice `json:"choices,omitempty"`
	// Usage contains terminal usage when reported.
	// Usage 包含上游报告的终态用量。
	Usage *Usage `json:"usage,omitempty"`
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
	// Refusal contains structured refusal text.
	// Refusal 包含结构化拒绝文本。
	Refusal string `json:"refusal,omitempty"`
	// ToolCalls contains complete function calls.
	// ToolCalls 包含完整函数调用。
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`
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
	// Refusal contains an actual upstream refusal fragment.
	// Refusal 包含真实上游拒绝片段。
	Refusal string `json:"refusal,omitempty"`
	// ToolCalls contains actual upstream tool deltas.
	// ToolCalls 包含真实上游工具增量。
	ToolCalls []ToolCallDelta `json:"tool_calls,omitempty"`
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
	// Model is the upstream model identifier when reported.
	// Model 是上游报告的模型标识。
	Model string `json:"model,omitempty"`
	// Choices contains zero or more semantic deltas.
	// Choices 包含零个或多个语义增量。
	Choices []Choice `json:"choices,omitempty"`
	// Usage supports a standard usage-only chunk.
	// Usage 支持标准的仅用量分片。
	Usage *Usage `json:"usage,omitempty"`
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
}

// CompletionTokenDetails contains OpenAI completion token details.
// CompletionTokenDetails 包含 OpenAI 补全 Token 明细。
type CompletionTokenDetails struct {
	// ReasoningTokens is nil when not reported.
	// ReasoningTokens 在未报告时为 nil。
	ReasoningTokens *int64 `json:"reasoning_tokens,omitempty"`
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
