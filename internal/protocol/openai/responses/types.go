// Package responses implements the VCP 1.0 to OpenAI Responses protocol profile.
// Package responses 实现 VCP 1.0 到 OpenAI Responses 的协议 Profile。
//
// Portions of this package's protocol behavior are adapted from CLIProxyAPI commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// 本包部分协议行为改编自 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66。
// Source paths include sdk/api/handlers/openai/openai_responses_handlers.go and internal/translator/openai/openai/responses.
// 来源路径包括 sdk/api/handlers/openai/openai_responses_handlers.go 和 internal/translator/openai/openai/responses。
// The adapted scope is Responses SSE framing and output-item compatibility rules, with no CLIProxyAPI runtime dependency.
// 改编范围为 Responses SSE 分帧与输出项目兼容规则，且不引入 CLIProxyAPI 运行时依赖。
package responses

import (
	"encoding/json"
	"errors"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

const (
	// ProfileID is the stable upstream protocol profile identifier for OpenAI Responses.
	// ProfileID 是 OpenAI Responses 的稳定上游协议 Profile 标识。
	ProfileID = "openai.responses"
)

var (
	// ErrInvalidTarget reports an incomplete or mismatched resolved execution target.
	// ErrInvalidTarget 表示不完整或不匹配的已解析执行 Target。
	ErrInvalidTarget = errors.New("invalid OpenAI Responses execution target")
	// ErrUnsupportedContext reports canonical data that has no safe Responses representation.
	// ErrUnsupportedContext 表示没有安全 Responses 表示的规范数据。
	ErrUnsupportedContext = errors.New("unsupported OpenAI Responses context")
	// ErrInvalidUpstreamResponse reports malformed Responses response or SSE semantics.
	// ErrInvalidUpstreamResponse 表示格式错误的 Responses 响应或 SSE 语义。
	ErrInvalidUpstreamResponse = errors.New("invalid OpenAI Responses response")
)

// ProfileCapabilities contains verified channel and execution-profile behavior.
// ProfileCapabilities 包含经过验证的 Channel 与执行 Profile 行为。
type ProfileCapabilities struct {
	// NativeSystemPreamble reports direct first-position system instruction support.
	// NativeSystemPreamble 表示直接支持首位 system 指令。
	NativeSystemPreamble bool
	// NativeDeveloper reports direct developer instruction support.
	// NativeDeveloper 表示直接支持 developer 指令。
	NativeDeveloper bool
	// NativeInlineSystem reports direct transcript-position system instruction support.
	// NativeInlineSystem 表示直接支持会话位置 system 指令。
	NativeInlineSystem bool
	// StructuredTools reports verified function tool support.
	// StructuredTools 表示经过验证的函数工具支持。
	StructuredTools bool
	// NativeCustomTools reports verified Responses custom freeform tool support.
	// NativeCustomTools 表示经过验证的 Responses 自由格式 custom tool 支持。
	NativeCustomTools bool
	// NativeToolNamespaces reports verified namespace tool support without flattening.
	// NativeToolNamespaces 表示经过验证的无需扁平化的命名空间工具支持。
	NativeToolNamespaces bool
	// ParallelTools reports verified parallel tool call support.
	// ParallelTools 表示经过验证的并行工具调用支持。
	ParallelTools bool
	// StreamingToolArguments reports actual upstream function argument delta support.
	// StreamingToolArguments 表示真实上游函数参数增量支持。
	StreamingToolArguments bool
	// StrictJSONSchema reports verified strict structured-output support.
	// StrictJSONSchema 表示经过验证的严格结构化输出支持。
	StrictJSONSchema bool
	// Reasoning reports verified reasoning effort or summary support.
	// Reasoning 表示经过验证的推理强度或摘要支持。
	Reasoning bool
	// ReasoningContinuation reports verified previous-response continuation support.
	// ReasoningContinuation 表示经过验证的 previous-response 续接支持。
	ReasoningContinuation bool
	// NativeWebSearch reports verified provider-hosted web search support.
	// NativeWebSearch 表示经过验证的供应商托管网页搜索支持。
	NativeWebSearch bool
}

// Request is the typed OpenAI Responses request body.
// Request 是类型化的 OpenAI Responses 请求体。
type Request struct {
	// Model is the exact resolved upstream model identifier.
	// Model 是精确解析的上游模型标识。
	Model string `json:"model"`
	// Input contains ordered typed historical input items.
	// Input 包含有序类型化历史输入项目。
	Input []InputItem `json:"input,omitempty"`
	// Stream requests upstream SSE events.
	// Stream 请求上游 SSE 事件。
	Stream bool `json:"stream,omitempty"`
	// Temperature maps the VCP temperature control when supported by the selected profile.
	// Temperature 在选定 Profile 支持时映射 VCP 温度控制。
	Temperature *float64 `json:"temperature,omitempty"`
	// TopP maps the VCP nucleus sampling control when supported by the selected profile.
	// TopP 在选定 Profile 支持时映射 VCP 核采样控制。
	TopP *float64 `json:"top_p,omitempty"`
	// MaxOutputTokens maps the VCP maximum output token limit.
	// MaxOutputTokens 映射 VCP 最大输出 Token 限制。
	MaxOutputTokens *int `json:"max_output_tokens,omitempty"`
	// Tools contains typed function, custom, or native web-search declarations.
	// Tools 包含类型化函数、custom 或原生网页搜索声明。
	Tools []Tool `json:"tools,omitempty"`
	// ToolChoice is omitted whenever no tools remain in the wire request.
	// ToolChoice 会在 wire 请求不存在工具时被省略。
	ToolChoice *ToolChoice `json:"tool_choice,omitempty"`
	// ParallelToolCalls is omitted whenever no tools remain or parallel controls are not verified for the target.
	// ParallelToolCalls 会在 wire 请求不存在工具或 Target 未验证并行控制时被省略。
	ParallelToolCalls *bool `json:"parallel_tool_calls,omitempty"`
	// Text contains a strict structured-output format when explicitly requested.
	// Text 在明确请求时包含严格结构化输出格式。
	Text *TextConfiguration `json:"text,omitempty"`
	// Reasoning contains verified effort or visible summary requests.
	// Reasoning 包含经过验证的推理强度或可见摘要请求。
	Reasoning *ReasoningConfiguration `json:"reasoning,omitempty"`
	// PreviousResponseID is emitted only after Router validates same-target continuation affinity.
	// PreviousResponseID 仅在 Router 校验同 Target 续接亲和性后发送。
	PreviousResponseID string `json:"previous_response_id,omitempty"`
}

// InputItem is one closed OpenAI Responses input item representation.
// InputItem 是一种封闭的 OpenAI Responses 输入项目表示。
type InputItem struct {
	// Type identifies message, function_call, function_call_output, custom_tool_call, custom_tool_call_output, or reasoning.
	// Type 标识 message、function_call、function_call_output、custom_tool_call、custom_tool_call_output 或 reasoning。
	Type string `json:"type,omitempty"`
	// Role identifies system, developer, user, or assistant for message items.
	// Role 标识 message 项目的 system、developer、user 或 assistant。
	Role string `json:"role,omitempty"`
	// Content contains typed message content parts.
	// Content 包含类型化消息内容部分。
	Content []InputContent `json:"content,omitempty"`
	// CallID binds a tool output or historical tool call to its stable upstream call identifier.
	// CallID 将工具输出或历史工具调用绑定到稳定上游调用标识。
	CallID string `json:"call_id,omitempty"`
	// Name identifies the tool name for tool-call input items.
	// Name 标识工具调用输入项目的工具名称。
	Name string `json:"name,omitempty"`
	// Arguments contains JSON function arguments for function_call input items.
	// Arguments 包含 function_call 输入项目的 JSON 函数参数。
	Arguments string `json:"arguments,omitempty"`
	// Input contains freeform custom-tool input without JSON wrapping.
	// Input 包含不使用 JSON 包装的自由格式 custom tool 输入。
	Input string `json:"input,omitempty"`
	// Output contains caller-returned tool output text.
	// Output 包含调用方返回的工具输出文本。
	Output string `json:"output,omitempty"`
	// Summary contains visible reasoning summary content only.
	// Summary 仅包含可见推理摘要内容。
	Summary []ReasoningSummary `json:"summary,omitempty"`
}

// InputContent is one closed input_text part for an EasyInputMessage carrier.
// InputContent 是 EasyInputMessage 载体的一种封闭 input_text 内容部分。
type InputContent struct {
	// Type is fixed to input_text for the input-message carrier.
	// Type 对输入消息载体固定为 input_text。
	Type string `json:"type"`
	// Text is the exact text value for the typed content part.
	// Text 是该类型化内容部分的精确文本值。
	Text string `json:"text"`
}

// ReasoningSummary is one visible reasoning summary part.
// ReasoningSummary 是一个可见推理摘要部分。
type ReasoningSummary struct {
	// Type is fixed to summary_text for the current profile.
	// Type 对当前 Profile 固定为 summary_text。
	Type string `json:"type"`
	// Text contains visible summary text only.
	// Text 仅包含可见摘要文本。
	Text string `json:"text"`
}

// Tool is one typed OpenAI Responses tool declaration.
// Tool 是一个类型化 OpenAI Responses 工具声明。
type Tool struct {
	// Type identifies function, custom, or web_search.
	// Type 标识 function、custom 或 web_search。
	Type string `json:"type"`
	// Name identifies function or custom tools.
	// Name 标识 function 或 custom 工具。
	Name string `json:"name,omitempty"`
	// Description contains model-visible guidance when the upstream type accepts it.
	// Description 在上游类型接受时包含模型可见说明。
	Description string `json:"description,omitempty"`
	// Parameters contains a typed function JSON Schema only for function tools.
	// Parameters 仅为 function 工具包含类型化 JSON Schema。
	Parameters json.RawMessage `json:"parameters,omitempty"`
	// Strict requests verified strict function schema behavior.
	// Strict 请求经过验证的严格函数 Schema 行为。
	Strict bool `json:"strict,omitempty"`
}

// ToolChoice is a typed OpenAI Responses tool-choice union.
// ToolChoice 是类型化 OpenAI Responses 工具选择联合。
type ToolChoice struct {
	// Mode identifies auto, none, required, or named selection.
	// Mode 标识 auto、none、required 或指定选择。
	Mode vcp.ToolChoiceMode
	// Type identifies the concrete named tool type.
	// Type 标识具体指定工具类型。
	Type string
	// Name identifies the exact named tool.
	// Name 标识精确指定工具。
	Name string
}

// MarshalJSON emits the exact Responses string or named-tool object representation.
// MarshalJSON 输出精确的 Responses 字符串或指定工具对象表示。
func (c ToolChoice) MarshalJSON() ([]byte, error) {
	if c.Mode != vcp.ToolChoiceNamed {
		return json.Marshal(string(c.Mode))
	}
	// namedChoice is the closed Responses named-tool representation.
	// namedChoice 是封闭的 Responses 指定工具表示。
	namedChoice := struct {
		// Type identifies the exact named tool category.
		// Type 标识精确的具名工具类别。
		Type string `json:"type"`
		// Name identifies the exact selected tool.
		// Name 标识精确选定的工具。
		Name string `json:"name"`
	}{Type: c.Type, Name: c.Name}
	return json.Marshal(namedChoice)
}

// TextConfiguration contains the current strict JSON Schema response format.
// TextConfiguration 包含当前严格 JSON Schema 响应格式。
type TextConfiguration struct {
	// Format contains the exact requested structured-output format.
	// Format 包含精确请求的结构化输出格式。
	Format TextFormat `json:"format"`
}

// TextFormat is the typed OpenAI Responses JSON Schema format shape.
// TextFormat 是类型化 OpenAI Responses JSON Schema 格式形态。
type TextFormat struct {
	// Type is fixed to json_schema.
	// Type 固定为 json_schema。
	Type string `json:"type"`
	// Name is a stable profile-owned schema name.
	// Name 是稳定的 Profile 所有 Schema 名称。
	Name string `json:"name"`
	// Schema contains the caller-provided validated JSON Schema.
	// Schema 包含调用方提供且已经校验的 JSON Schema。
	Schema json.RawMessage `json:"schema"`
	// Strict requests strict validation at the upstream.
	// Strict 请求上游执行严格校验。
	Strict bool `json:"strict"`
}

// ReasoningConfiguration contains verified Responses reasoning controls.
// ReasoningConfiguration 包含经过验证的 Responses 推理控制。
type ReasoningConfiguration struct {
	// Effort contains the registered requested reasoning effort.
	// Effort 包含已注册的请求推理强度。
	Effort string `json:"effort,omitempty"`
	// Summary requests automatic visible reasoning summaries.
	// Summary 请求自动生成可见推理摘要。
	Summary string `json:"summary,omitempty"`
}

// ProjectedRequest is the complete deterministic request projection and audit record.
// ProjectedRequest 是完整确定性请求投影与审计记录。
type ProjectedRequest struct {
	// Upstream is the typed OpenAI Responses wire request.
	// Upstream 是类型化 OpenAI Responses wire 请求。
	Upstream Request
	// CapabilityPlan captures frozen per-request capability decisions.
	// CapabilityPlan 捕获冻结的逐请求能力决策。
	CapabilityPlan vcp.CapabilityPlan
	// ProjectionPlan records every canonical item projection decision.
	// ProjectionPlan 记录每个规范项目投影决策。
	ProjectionPlan vcp.ProjectionPlan
	// Ledger preserves reversible and loss-explicit projection evidence.
	// Ledger 保留可逆且显式损失的投影证据。
	Ledger vcp.ProjectionLedger
	// Report contains the initial client-safe execution report.
	// Report 包含初始客户端安全执行报告。
	Report vcp.ExecutionReport
}

// Response is the typed non-streaming OpenAI Responses response body.
// Response 是类型化非流式 OpenAI Responses 响应体。
type Response struct {
	// ID is the provider response identifier.
	// ID 是供应商响应标识。
	ID string `json:"id"`
	// Object is the documented Responses response discriminator.
	// Object 是文档化的 Responses 响应判别字段。
	Object string `json:"object,omitempty"`
	// CreatedAt is the provider creation timestamp without a VCP response carrier.
	// CreatedAt 是没有 VCP 响应承载字段的 Provider 创建时间戳。
	CreatedAt *int64 `json:"created_at,omitempty"`
	// CompletedAt is the provider completion timestamp without a VCP response carrier.
	// CompletedAt 是没有 VCP 响应承载字段的 Provider 完成时间戳。
	CompletedAt *int64 `json:"completed_at,omitempty"`
	// Status identifies completed, incomplete, failed, or cancelled response state.
	// Status 标识 completed、incomplete、failed 或 cancelled 响应状态。
	Status string `json:"status"`
	// Input detects echoed provider input that must not be copied into output or ordinary reports.
	// Input 检测到不得复制到输出或常规报告中的回显 Provider 输入。
	Input *UnsupportedResponsePayload `json:"input,omitempty"`
	// Instructions detects echoed instructions that must not be copied into output or ordinary reports.
	// Instructions 检测到不得复制到输出或常规报告中的回显指令。
	Instructions *UnsupportedResponsePayload `json:"instructions,omitempty"`
	// MaxOutputTokens is the provider-applied output limit without a VCP response carrier.
	// MaxOutputTokens 是没有 VCP 响应承载字段的 Provider 已应用输出上限。
	MaxOutputTokens *int `json:"max_output_tokens,omitempty"`
	// Model is the provider-selected runtime model without a VCP response carrier.
	// Model 是没有 VCP 响应承载字段的 Provider 选定运行时模型。
	Model string `json:"model,omitempty"`
	// Output contains ordered output items.
	// Output 包含有序输出项目。
	Output []OutputItem `json:"output,omitempty"`
	// PreviousResponseID is echoed continuation metadata without a VCP response carrier.
	// PreviousResponseID 是没有 VCP 响应承载字段的回显续接元数据。
	PreviousResponseID string `json:"previous_response_id,omitempty"`
	// ReasoningEffort is echoed reasoning configuration without a VCP response carrier.
	// ReasoningEffort 是没有 VCP 响应承载字段的回显推理配置。
	ReasoningEffort string `json:"reasoning_effort,omitempty"`
	// Reasoning detects echoed reasoning configuration without retaining provider configuration details.
	// Reasoning 检测回显推理配置，且不保留 Provider 配置明细。
	Reasoning *UnsupportedResponsePayload `json:"reasoning,omitempty"`
	// Store reports provider retention behavior without a VCP response carrier.
	// Store 报告没有 VCP 响应承载字段的 Provider 保留行为。
	Store *bool `json:"store,omitempty"`
	// Temperature is echoed sampling configuration without a VCP response carrier.
	// Temperature 是没有 VCP 响应承载字段的回显采样配置。
	Temperature *float64 `json:"temperature,omitempty"`
	// Text detects echoed text-format configuration without retaining schema details.
	// Text 检测回显文本格式配置，且不保留 Schema 明细。
	Text *UnsupportedResponsePayload `json:"text,omitempty"`
	// ToolChoice detects echoed tool-choice configuration without retaining provider payload details.
	// ToolChoice 检测回显工具选择配置，且不保留 Provider 载荷明细。
	ToolChoice *UnsupportedResponsePayload `json:"tool_choice,omitempty"`
	// Tools detects echoed tool declarations without retaining schemas or descriptions.
	// Tools 检测回显工具声明，且不保留 Schema 或描述。
	Tools *UnsupportedResponsePayload `json:"tools,omitempty"`
	// TopP is echoed nucleus sampling configuration without a VCP response carrier.
	// TopP 是没有 VCP 响应承载字段的回显核采样配置。
	TopP *float64 `json:"top_p,omitempty"`
	// Truncation is echoed context-truncation configuration without a VCP response carrier.
	// Truncation 是没有 VCP 响应承载字段的回显上下文截断配置。
	Truncation string `json:"truncation,omitempty"`
	// TopLogprobs is xAI-compatible top-logprob configuration without a VCP response carrier.
	// TopLogprobs 是没有 VCP 响应承载字段的 xAI 兼容 Top Logprob 配置。
	TopLogprobs *int `json:"top_logprobs,omitempty"`
	// User detects echoed user metadata without retaining its provider value.
	// User 检测回显用户元数据，且不保留其 Provider 值。
	User *UnsupportedResponsePayload `json:"user,omitempty"`
	// Metadata detects echoed metadata without retaining user-provided keys or values.
	// Metadata 检测回显元数据，且不保留用户提供的键或值。
	Metadata *UnsupportedResponsePayload `json:"metadata,omitempty"`
	// ServiceTier is the provider-selected processing tier without a VCP response carrier.
	// ServiceTier 是没有 VCP 响应承载字段的 Provider 所选处理层级。
	ServiceTier string `json:"service_tier,omitempty"`
	// ParallelToolCalls is echoed parallel-tool configuration without a VCP response carrier.
	// ParallelToolCalls 是没有 VCP 响应承载字段的回显并行工具配置。
	ParallelToolCalls *bool `json:"parallel_tool_calls,omitempty"`
	// Background is xAI-compatible background-processing metadata without a VCP response carrier.
	// Background 是没有 VCP 响应承载字段的 xAI 兼容后台处理元数据。
	Background *bool `json:"background,omitempty"`
	// FrequencyPenalty is xAI-compatible penalty metadata without a VCP response carrier.
	// FrequencyPenalty 是没有 VCP 响应承载字段的 xAI 兼容频率惩罚元数据。
	FrequencyPenalty *float64 `json:"frequency_penalty,omitempty"`
	// PresencePenalty is xAI-compatible penalty metadata without a VCP response carrier.
	// PresencePenalty 是没有 VCP 响应承载字段的 xAI 兼容存在惩罚元数据。
	PresencePenalty *float64 `json:"presence_penalty,omitempty"`
	// PromptCacheKey detects echoed cache bucketing metadata without retaining its provider value.
	// PromptCacheKey 检测回显缓存分桶元数据，且不保留其 Provider 值。
	PromptCacheKey *UnsupportedResponsePayload `json:"prompt_cache_key,omitempty"`
	// MaxToolCalls is xAI-compatible server-side tool limit metadata without a VCP response carrier.
	// MaxToolCalls 是没有 VCP 响应承载字段的 xAI 兼容服务端工具上限元数据。
	MaxToolCalls *int `json:"max_tool_calls,omitempty"`
	// SafetyIdentifier detects echoed safety metadata without retaining its provider value.
	// SafetyIdentifier 检测回显安全元数据，且不保留其 Provider 值。
	SafetyIdentifier *UnsupportedResponsePayload `json:"safety_identifier,omitempty"`
	// Citations detects provider-wide citation metadata without retaining source URLs or titles.
	// Citations 检测 Provider 范围引文元数据，且不保留来源 URL 或标题。
	Citations *UnsupportedResponsePayload `json:"citations,omitempty"`
	// InlineCitations detects provider-inline citation metadata without retaining source URLs or positions.
	// InlineCitations 检测 Provider 行内引文元数据，且不保留来源 URL 或位置。
	InlineCitations *UnsupportedResponsePayload `json:"inline_citations,omitempty"`
	// Usage contains provider-reported token usage when available.
	// Usage 包含可用时的供应商报告 Token 用量。
	Usage *Usage `json:"usage,omitempty"`
	// Error contains a structured provider error when present.
	// Error 包含存在时的结构化供应商错误。
	Error *Error `json:"error,omitempty"`
	// IncompleteDetails contains a safe incomplete reason when reported.
	// IncompleteDetails 包含上游报告时的安全不完整原因。
	IncompleteDetails *IncompleteDetails `json:"incomplete_details,omitempty"`
}

// OutputItem is one typed OpenAI Responses output item.
// OutputItem 是一个类型化 OpenAI Responses 输出项目。
type OutputItem struct {
	// ID is the upstream output item identifier.
	// ID 是上游输出项目标识。
	ID string `json:"id"`
	// Type identifies message, function_call, custom_tool_call, or reasoning.
	// Type 标识 message、function_call、custom_tool_call 或 reasoning。
	Type string `json:"type"`
	// Status identifies the upstream item lifecycle state.
	// Status 标识上游项目生命周期状态。
	Status string `json:"status,omitempty"`
	// Role identifies assistant or other valid message roles.
	// Role 标识 assistant 或其他有效消息角色。
	Role string `json:"role,omitempty"`
	// Content contains ordered message content or raw reasoning-content parts according to Type.
	// Content 根据 Type 包含有序消息内容或原始推理内容部分。
	Content []OutputContent `json:"content,omitempty"`
	// CallID is the upstream function or custom tool call identifier.
	// CallID 是上游 function 或 custom tool 调用标识。
	CallID string `json:"call_id,omitempty"`
	// Name is the upstream function or custom tool name.
	// Name 是上游 function 或 custom tool 名称。
	Name string `json:"name,omitempty"`
	// Arguments contains completed JSON function arguments.
	// Arguments 包含已完成的 JSON 函数参数。
	Arguments string `json:"arguments,omitempty"`
	// Input contains completed freeform custom tool input.
	// Input 包含已完成的自由格式 custom tool 输入。
	Input string `json:"input,omitempty"`
	// Summary contains visible reasoning summary parts.
	// Summary 包含可见推理摘要部分。
	Summary []ReasoningSummary `json:"summary,omitempty"`
	// EncryptedContent is sealed provider state and must never be converted to ordinary text.
	// EncryptedContent 是密封供应商状态，绝不能转换为普通文本。
	EncryptedContent string `json:"encrypted_content,omitempty"`
}

// OutputContent is one typed OpenAI Responses output content part.
// OutputContent 是一个类型化 OpenAI Responses 输出内容部分。
type OutputContent struct {
	// Type identifies output_text, refusal, or reasoning_text in a completed output item.
	// Type 标识已完成输出项目中的 output_text、refusal 或 reasoning_text。
	Type string `json:"type"`
	// Text contains normal output text.
	// Text 包含普通输出文本。
	Text string `json:"text,omitempty"`
	// Refusal contains refusal text.
	// Refusal 包含拒绝文本。
	Refusal string `json:"refusal,omitempty"`
	// Annotations records the presence of provider annotations that this VCP profile cannot expose as canonical content.
	// Annotations 记录当前 VCP Profile 无法作为规范内容暴露的 Provider 注释是否存在。
	Annotations []OutputAnnotation `json:"annotations,omitempty"`
	// Logprobs detects token likelihood metadata that this first-phase VCP profile cannot represent.
	// Logprobs 检测到本第一阶段 VCP Profile 无法表示的 Token 概率元数据。
	Logprobs *UnsupportedResponsePayload `json:"logprobs,omitempty"`
}

// OutputAnnotation is the typed presence marker for one OpenAI Responses output annotation.
// OutputAnnotation 是一条 OpenAI Responses 输出注释的类型化存在标记。
type OutputAnnotation struct {
	// Type identifies the provider annotation variant without retaining its opaque detail payload.
	// Type 在不保留其不透明明细载荷的前提下标识 Provider 注释变体。
	Type string `json:"type,omitempty"`
}

// StreamPart is one closed OpenAI Responses SSE part carrier.
// StreamPart 是一个封闭的 OpenAI Responses SSE 部分载体。
type StreamPart struct {
	// Type identifies output_text, refusal, reasoning_text, or summary_text for its owning SSE event.
	// Type 为所属 SSE 事件标识 output_text、refusal、reasoning_text 或 summary_text。
	Type string `json:"type"`
	// Text contains text for output_text, reasoning_text, or summary_text parts.
	// Text 包含 output_text、reasoning_text 或 summary_text 部分的文本。
	Text string `json:"text,omitempty"`
	// Refusal contains refusal text for refusal parts.
	// Refusal 包含 refusal 部分的拒绝文本。
	Refusal string `json:"refusal,omitempty"`
	// Annotations records the presence of provider annotations that this VCP profile cannot expose as canonical content.
	// Annotations 记录当前 VCP Profile 无法作为规范内容暴露的 Provider 注释是否存在。
	Annotations []OutputAnnotation `json:"annotations,omitempty"`
	// Logprobs detects token likelihood metadata that this first-phase VCP profile cannot represent.
	// Logprobs 检测到本第一阶段 VCP Profile 无法表示的 Token 概率元数据。
	Logprobs *UnsupportedResponsePayload `json:"logprobs,omitempty"`
}

// Usage contains typed OpenAI Responses usage fields while preserving unknown values as nil.
// Usage 包含类型化 OpenAI Responses 用量字段，并将未知值保留为 nil。
type Usage struct {
	// InputTokens is the provider-reported input token count.
	// InputTokens 是供应商报告的输入 Token 数。
	InputTokens *int64 `json:"input_tokens,omitempty"`
	// OutputTokens is the provider-reported output token count.
	// OutputTokens 是供应商报告的输出 Token 数。
	OutputTokens *int64 `json:"output_tokens,omitempty"`
	// TotalTokens is the provider-reported total token count.
	// TotalTokens 是供应商报告的总 Token 数。
	TotalTokens *int64 `json:"total_tokens,omitempty"`
	// InputTokensDetails contains cache token details when reported.
	// InputTokensDetails 包含上游报告时的缓存 Token 明细。
	InputTokensDetails *InputTokensDetails `json:"input_tokens_details,omitempty"`
	// OutputTokensDetails contains reasoning token details when reported.
	// OutputTokensDetails 包含上游报告时的推理 Token 明细。
	OutputTokensDetails *OutputTokensDetails `json:"output_tokens_details,omitempty"`
	// CostInUSDTicks is xAI-compatible cost accounting without a VCP billing carrier.
	// CostInUSDTicks 是没有 VCP 计费承载字段的 xAI 兼容成本计量。
	CostInUSDTicks *int64 `json:"cost_in_usd_ticks,omitempty"`
	// NumSourcesUsed is xAI server-side source accounting without a VCP usage carrier.
	// NumSourcesUsed 是没有 VCP 用量承载字段的 xAI 服务端来源计量。
	NumSourcesUsed *int64 `json:"num_sources_used,omitempty"`
	// NumServerSideToolsUsed is xAI server-side tool accounting without a VCP usage carrier.
	// NumServerSideToolsUsed 是没有 VCP 用量承载字段的 xAI 服务端工具计量。
	NumServerSideToolsUsed *int64 `json:"num_server_side_tools_used,omitempty"`
}

// InputTokensDetails contains Responses input token detail fields.
// InputTokensDetails 包含 Responses 输入 Token 明细字段。
type InputTokensDetails struct {
	// CachedTokens is the provider-reported cached input token count.
	// CachedTokens 是供应商报告的缓存输入 Token 数。
	CachedTokens *int64 `json:"cached_tokens,omitempty"`
}

// OutputTokensDetails contains Responses output token detail fields.
// OutputTokensDetails 包含 Responses 输出 Token 明细字段。
type OutputTokensDetails struct {
	// ReasoningTokens is the provider-reported reasoning token count.
	// ReasoningTokens 是供应商报告的推理 Token 数。
	ReasoningTokens *int64 `json:"reasoning_tokens,omitempty"`
}

// UnsupportedResponsePayload detects a documented response field without retaining sensitive provider payload content.
// UnsupportedResponsePayload 在不保留敏感 Provider 载荷内容的前提下检测一个文档化响应字段。
type UnsupportedResponsePayload struct{}

// UnmarshalJSON accepts any documented JSON payload shape while intentionally discarding its contents.
// UnmarshalJSON 接受任何文档化 JSON 载荷形态，同时有意丢弃其内容。
func (*UnsupportedResponsePayload) UnmarshalJSON([]byte) error {
	return nil
}

// Error is a typed safe subset of an OpenAI Responses error object.
// Error 是 OpenAI Responses 错误对象的类型化安全子集。
type Error struct {
	// Code is the provider error code when supplied.
	// Code 是上游提供时的供应商错误码。
	Code string `json:"code,omitempty"`
	// Type is the provider error type when supplied.
	// Type 是上游提供时的供应商错误类型。
	Type string `json:"type,omitempty"`
	// Message is provider diagnostic text that must not enter ordinary VCP reports.
	// Message 是不得进入常规 VCP 报告的 Provider 诊断文本。
	Message string `json:"message,omitempty"`
}

// IncompleteDetails is a typed safe subset of an incomplete response description.
// IncompleteDetails 是不完整响应说明的类型化安全子集。
type IncompleteDetails struct {
	// Reason is the provider incomplete reason when supplied.
	// Reason 是上游提供时的不完整原因。
	Reason string `json:"reason,omitempty"`
}

// StreamEvent is the typed union used by OpenAI Responses SSE payloads.
// StreamEvent 是 OpenAI Responses SSE 载荷使用的类型化联合。
type StreamEvent struct {
	// Type is the authoritative protocol event type.
	// Type 是权威协议事件类型。
	Type string `json:"type"`
	// SequenceNumber is the optional provider stream sequence used to detect reordering or replay.
	// SequenceNumber 是用于检测乱序或重放的可选 Provider 流序列号。
	SequenceNumber *int64 `json:"sequence_number,omitempty"`
	// Response contains lifecycle and terminal response snapshots.
	// Response 包含生命周期和终态响应快照。
	Response *Response `json:"response,omitempty"`
	// Item contains output-item added or completed snapshots.
	// Item 包含输出项目新增或完成快照。
	Item *OutputItem `json:"item,omitempty"`
	// Part contains a content, reasoning, or summary part snapshot for its owning SSE event.
	// Part 包含所属 SSE 事件的内容、推理或摘要部分快照。
	Part *StreamPart `json:"part,omitempty"`
	// OutputIndex identifies the output position when the provider emits it.
	// OutputIndex 标识上游发出时的输出位置。
	OutputIndex *int `json:"output_index,omitempty"`
	// ItemID identifies the upstream output item for delta events.
	// ItemID 标识增量事件的上游输出项目。
	ItemID string `json:"item_id,omitempty"`
	// ContentIndex identifies the content position for content deltas.
	// ContentIndex 标识内容增量的内容位置。
	ContentIndex *int `json:"content_index,omitempty"`
	// SummaryIndex identifies the reasoning summary position for reasoning-summary events.
	// SummaryIndex 标识推理摘要事件的推理摘要位置。
	SummaryIndex *int `json:"summary_index,omitempty"`
	// Delta contains streamed text, refusal, summary, or function argument bytes.
	// Delta 包含流式文本、拒绝、摘要或函数参数字节。
	Delta string `json:"delta,omitempty"`
	// Text contains a finalized text value when the event does not use Delta.
	// Text 包含事件不使用 Delta 时的最终文本值。
	Text string `json:"text,omitempty"`
	// Refusal contains a finalized refusal value when supplied.
	// Refusal 包含上游提供时的最终拒绝值。
	Refusal string `json:"refusal,omitempty"`
	// Name contains a completed function or custom tool name.
	// Name 包含已完成 function 或 custom tool 名称。
	Name string `json:"name,omitempty"`
	// CallID contains a completed function or custom tool call identifier.
	// CallID 包含已完成 function 或 custom tool 调用标识。
	CallID string `json:"call_id,omitempty"`
	// Arguments contains finalized function arguments.
	// Arguments 包含已完成函数参数。
	Arguments string `json:"arguments,omitempty"`
	// Input contains finalized custom tool input.
	// Input 包含已完成 custom tool 输入。
	Input string `json:"input,omitempty"`
	// Error contains a typed error event payload.
	// Error 包含类型化错误事件载荷。
	Error *Error `json:"error,omitempty"`
}

// SSEEnvelope is one parsed SSE frame before JSON event decoding.
// SSEEnvelope 是 JSON 事件解码前的一帧已解析 SSE 数据。
type SSEEnvelope struct {
	// Event is the optional SSE event field.
	// Event 是可选 SSE event 字段。
	Event string
	// Data contains concatenated raw SSE data lines.
	// Data 包含拼接后的原始 SSE data 行。
	Data []byte
}
