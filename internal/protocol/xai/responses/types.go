// Package responses implements the VCP 1.0 to xAI Responses protocol profile.
// Package responses 实现 VCP 1.0 到 xAI Responses 的协议 Profile。
//
// Portions of this package's protocol behavior are adapted from CLIProxyAPI commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// 本包部分协议行为改编自 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66。
// Source paths include internal/runtime/executor/xai_executor.go and internal/translator/openai/openai/responses/openai_openai-responses_tools.go.
// 来源路径包括 internal/runtime/executor/xai_executor.go 和 internal/translator/openai/openai/responses/openai_openai-responses_tools.go。
// The adapted scope is xAI Responses tool normalization, x_search filtering, reasoning normalization, and completed-output repair.
// 改编范围为 xAI Responses 工具归一化、x_search 过滤、推理归一化与完成输出修复。
package responses

import (
	"errors"

	openairesponses "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/responses"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

const (
	// ProfileID is the stable upstream protocol profile identifier for xAI Responses.
	// ProfileID 是 xAI Responses 的稳定上游协议 Profile 标识。
	ProfileID = "xai.responses"
)

var (
	// ErrInvalidTarget reports an incomplete or mismatched resolved xAI execution target.
	// ErrInvalidTarget 表示不完整或不匹配的已解析 xAI 执行 Target。
	ErrInvalidTarget = errors.New("invalid xAI Responses execution target")
	// ErrUnsupportedContext reports canonical data without a verified xAI Responses representation.
	// ErrUnsupportedContext 表示没有经过验证的 xAI Responses 表示的规范数据。
	ErrUnsupportedContext = errors.New("unsupported xAI Responses context")
	// ErrInvalidUpstreamResponse reports malformed xAI Responses response or SSE semantics.
	// ErrInvalidUpstreamResponse 表示格式错误的 xAI Responses 响应或 SSE 语义。
	ErrInvalidUpstreamResponse = errors.New("invalid xAI Responses response")
)

// ProfileCapabilities contains verified target-specific xAI Responses behavior.
// ProfileCapabilities 包含经过验证的 Target 特定 xAI Responses 行为。
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
	// StructuredTools reports verified xAI function tool support.
	// StructuredTools 表示经过验证的 xAI function 工具支持。
	StructuredTools bool
	// ParallelTools reports verified parallel tool call support.
	// ParallelTools 表示经过验证的并行工具调用支持。
	ParallelTools bool
	// StreamingToolArguments reports actual upstream tool argument delta support.
	// StreamingToolArguments 表示真实上游工具参数增量支持。
	StreamingToolArguments bool
	// StrictJSONSchema reports verified strict structured-output support.
	// StrictJSONSchema 表示经过验证的严格结构化输出支持。
	StrictJSONSchema bool
	// Reasoning reports verified visible reasoning summary support.
	// Reasoning 表示经过验证的可见推理摘要支持。
	Reasoning bool
	// ReasoningEffort reports that this exact target model accepts reasoning.effort.
	// ReasoningEffort 表示此精确 Target 模型接受 reasoning.effort。
	ReasoningEffort bool
	// ReasoningContinuation reports verified previous-response continuation support.
	// ReasoningContinuation 表示经过验证的 previous-response 续接支持。
	ReasoningContinuation bool
	// NativeXSearch reports verified provider-hosted x_search support.
	// NativeXSearch 表示经过验证的供应商托管 x_search 支持。
	NativeXSearch bool
	// NativeRemoteCompaction reports verified /responses/compact support on the selected endpoint.
	// NativeRemoteCompaction 表示选定 Endpoint 已验证支持 /responses/compact。
	NativeRemoteCompaction bool
}

// ToolReference binds one xAI wire tool name back to its unique canonical tool identity.
// ToolReference 将一个 xAI wire 工具名称绑定回其唯一规范工具身份。
type ToolReference struct {
	// WireName is the qualified function name sent to xAI.
	// WireName 是发送给 xAI 的限定 function 名称。
	WireName string
	// Namespace is the original canonical tool namespace.
	// Namespace 是原始规范工具命名空间。
	Namespace string
	// Name is the original canonical tool name.
	// Name 是原始规范工具名称。
	Name string
	// Kind is the original closed VCP declaration kind.
	// Kind 是原始封闭 VCP 声明 Kind。
	Kind vcp.ToolKind
}

// StreamOptions contains immutable request-derived facts needed to decode one xAI stream safely.
// StreamOptions 包含安全解码一条 xAI 流所需的不可变请求派生事实。
type StreamOptions struct {
	// ToolReferences restores qualified xAI tool names without guessing a namespace.
	// ToolReferences 在不猜测命名空间的前提下恢复限定 xAI 工具名称。
	ToolReferences []ToolReference
	// FilterInternalXSearch removes only evidenced xAI server-side x_search traces.
	// FilterInternalXSearch 仅移除有证据的 xAI 服务端 x_search 轨迹。
	FilterInternalXSearch bool
}

// ProjectedRequest is the complete deterministic xAI request projection and audit record.
// ProjectedRequest 是完整确定性的 xAI 请求投影与审计记录。
type ProjectedRequest struct {
	// Upstream is the typed xAI Responses wire request.
	// Upstream 是类型化 xAI Responses wire 请求。
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
	// StreamOptions carries the request-bound decode facts for this exact execution.
	// StreamOptions 携带此精确执行的请求绑定解码事实。
	StreamOptions StreamOptions
}

// Request is the typed xAI Responses request wire shape.
// Request 是类型化 xAI Responses 请求 wire 形态。
type Request = openairesponses.Request

// InputItem is one typed xAI Responses historical input item.
// InputItem 是一个类型化 xAI Responses 历史输入项目。
type InputItem = openairesponses.InputItem

// InputContent is one typed xAI Responses input content part.
// InputContent 是一个类型化 xAI Responses 输入内容部分。
type InputContent = openairesponses.InputContent

// ReasoningSummary is one typed xAI Responses visible reasoning summary part.
// ReasoningSummary 是一个类型化 xAI Responses 可见推理摘要部分。
type ReasoningSummary = openairesponses.ReasoningSummary

// Tool is one typed xAI Responses tool declaration.
// Tool 是一个类型化 xAI Responses 工具声明。
type Tool = openairesponses.Tool

// ToolChoice is one typed xAI Responses tool-choice union.
// ToolChoice 是一个类型化 xAI Responses 工具选择联合。
type ToolChoice = openairesponses.ToolChoice

// Response is the typed xAI Responses non-streaming response body.
// Response 是类型化 xAI Responses 非流式响应体。
type Response = openairesponses.Response

// OutputItem is one typed xAI Responses output item.
// OutputItem 是一个类型化 xAI Responses 输出项目。
type OutputItem = openairesponses.OutputItem

// OutputContent is one typed xAI Responses output content part.
// OutputContent 是一个类型化 xAI Responses 输出内容部分。
type OutputContent = openairesponses.OutputContent

// Usage is the typed xAI Responses usage payload.
// Usage 是类型化 xAI Responses 用量载荷。
type Usage = openairesponses.Usage

// Error is the typed safe xAI Responses error payload.
// Error 是类型化安全 xAI Responses 错误载荷。
type Error = openairesponses.Error

// IncompleteDetails is the typed safe xAI Responses incomplete payload.
// IncompleteDetails 是类型化安全 xAI Responses 不完整载荷。
type IncompleteDetails = openairesponses.IncompleteDetails

// StreamEvent is the typed xAI Responses SSE event union.
// StreamEvent 是类型化 xAI Responses SSE 事件联合。
type StreamEvent = openairesponses.StreamEvent

// SSEEnvelope is one parsed xAI SSE frame before JSON event decoding.
// SSEEnvelope 是 JSON 事件解码前的一帧已解析 xAI SSE 数据。
type SSEEnvelope = openairesponses.SSEEnvelope

// baseCapabilities converts xAI target facts into the shared Responses projection capability shape.
// baseCapabilities 将 xAI Target 事实转换为共享 Responses 投影能力形态。
func (c ProfileCapabilities) baseCapabilities() openairesponses.ProfileCapabilities {
	return openairesponses.ProfileCapabilities{
		NativeSystemPreamble: c.NativeSystemPreamble, NativeDeveloper: c.NativeDeveloper, NativeInlineSystem: c.NativeInlineSystem,
		StructuredTools: c.StructuredTools, NativeCustomTools: true, NativeToolNamespaces: true, ParallelTools: c.ParallelTools,
		StreamingToolArguments: c.StreamingToolArguments, StrictJSONSchema: c.StrictJSONSchema, Reasoning: c.Reasoning,
		ReasoningContinuation: c.ReasoningContinuation, NativeWebSearch: c.NativeXSearch,
	}
}
