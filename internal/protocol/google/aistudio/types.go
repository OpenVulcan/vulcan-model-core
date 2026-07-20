// Package aistudio implements the VCP 1.0 to Google AI Studio Gemini protocol profile.
// Package aistudio 实现 VCP 1.0 到 Google AI Studio Gemini 的协议 Profile。
//
// Portions of this package's protocol behavior are adapted from CLIProxyAPI commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// 本包部分协议行为改编自 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66。
// Source paths include internal/runtime/executor/aistudio_executor.go and internal/translator/gemini.
// 来源路径包括 internal/runtime/executor/aistudio_executor.go 和 internal/translator/gemini。
// The adapted scope is AI Studio action routing, function response affinity, and stream completion behavior, with no CLIProxyAPI runtime dependency.
// 改编范围为 AI Studio 动作路由、函数响应亲和性和流完成行为，且不引入 CLIProxyAPI 运行时依赖。
package aistudio

import (
	"encoding/json"
	"errors"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

const (
	// ProfileID is the stable upstream protocol profile identifier for Google AI Studio Gemini.
	// ProfileID 是 Google AI Studio Gemini 的稳定上游协议 Profile 标识。
	ProfileID = "google.aistudio"
)

var (
	// ErrInvalidTarget reports an incomplete or mismatched resolved AI Studio execution target.
	// ErrInvalidTarget 表示不完整或不匹配的已解析 AI Studio 执行 Target。
	ErrInvalidTarget = errors.New("invalid Google AI Studio execution target")
	// ErrUnsupportedContext reports canonical data without a safe typed AI Studio representation.
	// ErrUnsupportedContext 表示没有安全类型化 AI Studio 表示的规范数据。
	ErrUnsupportedContext = errors.New("unsupported Google AI Studio context")
	// ErrInvalidUpstreamResponse reports malformed Gemini response or SSE semantics.
	// ErrInvalidUpstreamResponse 表示格式错误的 Gemini 响应或 SSE 语义。
	ErrInvalidUpstreamResponse = errors.New("invalid Google AI Studio response")
)

// ProfileCapabilities contains verified channel and execution-profile behavior.
// ProfileCapabilities 包含经过验证的 Channel 与执行 Profile 行为。
type ProfileCapabilities struct {
	// MediaInputKinds lists exact media families accepted by this GenerateContent wire implementation.
	// MediaInputKinds 列出此 GenerateContent 线路实现接受的精确媒体类别。
	MediaInputKinds []vcp.MediaKind
	// NativeSystemInstruction reports direct Gemini systemInstruction support.
	// NativeSystemInstruction 表示直接支持 Gemini systemInstruction。
	NativeSystemInstruction bool
	// StructuredTools reports verified Gemini function declaration support.
	// StructuredTools 表示经过验证的 Gemini 函数声明支持。
	StructuredTools bool
	// ParallelTools reports verified parallel function-call support.
	// ParallelTools 表示经过验证的并行函数调用支持。
	ParallelTools bool
	// StreamingToolArguments reports verified upstream function argument delta behavior.
	// StreamingToolArguments 表示经过验证的上游函数参数增量行为。
	StreamingToolArguments bool
	// StrictJSONSchema reports verified responseJsonSchema enforcement.
	// StrictJSONSchema 表示经过验证的 responseJsonSchema 约束支持。
	StrictJSONSchema bool
	// NativeReasoning reports verified Gemini thought-part replay support.
	// NativeReasoning 表示经过验证的 Gemini thought 部分回放支持。
	NativeReasoning bool
	// NativeReasoningSummary reports verified thinkingConfig.includeThoughts support.
	// NativeReasoningSummary 表示经过验证的 thinkingConfig.includeThoughts 支持。
	NativeReasoningSummary bool
	// ThinkingLevels lists exact model-verified thinkingConfig.thinkingLevel values.
	// ThinkingLevels 列出精确模型已验证的 thinkingConfig.thinkingLevel 值。
	ThinkingLevels []string
}

// GenerateContentRequest is the typed Google AI Studio generateContent request body.
// GenerateContentRequest 是类型化的 Google AI Studio generateContent 请求体。
type GenerateContentRequest struct {
	// Contents contains the ordered Gemini conversation turns.
	// Contents 包含有序 Gemini 会话轮次。
	Contents []Content `json:"contents"`
	// Tools contains typed function declaration groups.
	// Tools 包含类型化函数声明分组。
	Tools []Tool `json:"tools,omitempty"`
	// ToolConfig controls the declared function selection mode.
	// ToolConfig 控制已声明函数的选择模式。
	ToolConfig *ToolConfig `json:"toolConfig,omitempty"`
	// SystemInstruction contains directly supported text-only system instructions.
	// SystemInstruction 包含直接支持的仅文本系统指令。
	SystemInstruction *Content `json:"systemInstruction,omitempty"`
	// GenerationConfig contains VCP-compatible generation controls.
	// GenerationConfig 包含与 VCP 兼容的生成控制。
	GenerationConfig *GenerationConfig `json:"generationConfig,omitempty"`
}

// Content is one typed Gemini conversation turn or system instruction carrier.
// Content 是一个类型化 Gemini 会话轮次或系统指令载体。
type Content struct {
	// Role identifies user, model, or the documented function response carrier.
	// Role 标识 user、model 或文档化的函数响应载体。
	Role string `json:"role,omitempty"`
	// Parts contains ordered typed text or function payloads.
	// Parts 包含有序类型化文本或函数载荷。
	Parts []Part `json:"parts"`
}

// Part is one closed Gemini content part represented by this profile.
// Part 是本 Profile 表示的一种封闭 Gemini 内容部分。
type Part struct {
	// Text contains visible textual content.
	// Text 包含可见文本内容。
	Text string `json:"text,omitempty"`
	// Thought identifies visible provider reasoning content.
	// Thought 标识可见 Provider 推理内容。
	Thought bool `json:"thought,omitempty"`
	// ThoughtSignature contains opaque provider-owned reasoning state.
	// ThoughtSignature 包含不透明的 Provider 所有推理状态。
	ThoughtSignature string `json:"thoughtSignature,omitempty"`
	// FunctionCall contains one model-originated function invocation.
	// FunctionCall 包含一次模型发起的函数调用。
	FunctionCall *FunctionCall `json:"functionCall,omitempty"`
	// FunctionResponse contains one caller-returned function result.
	// FunctionResponse 包含一次调用方返回的函数结果。
	FunctionResponse *FunctionResponse `json:"functionResponse,omitempty"`
	// InlineData carries bounded media bytes selected by the immutable input plan.
	// InlineData 承载不可变输入方案选定的受限媒体字节。
	InlineData *InlineData `json:"inlineData,omitempty"`
	// FileData carries one Router-managed provider file or object URI.
	// FileData 承载一个 Router 管理的供应商文件或对象 URI。
	FileData *FileData `json:"fileData,omitempty"`
	// ExecutableCode detects a code-execution payload that this first-phase profile cannot represent.
	// ExecutableCode 检测到本第一阶段 Profile 无法表示的代码执行载荷。
	ExecutableCode *UnsupportedPartPayload `json:"executableCode,omitempty"`
	// CodeExecutionResult detects a code-execution result that this first-phase profile cannot represent.
	// CodeExecutionResult 检测到本第一阶段 Profile 无法表示的代码执行结果。
	CodeExecutionResult *UnsupportedPartPayload `json:"codeExecutionResult,omitempty"`
	// VideoMetadata detects video metadata that this first-phase profile cannot represent.
	// VideoMetadata 检测到本第一阶段 Profile 无法表示的视频元数据。
	VideoMetadata *UnsupportedPartPayload `json:"videoMetadata,omitempty"`
	// unrecognized reports that the provider sent a future part field outside this closed wire carrier.
	// unrecognized 表示 Provider 发送了此封闭 wire 载体之外的未来 Part 字段。
	unrecognized bool
	// empty reports that a decoded wire object contained no part payload field.
	// empty 表示已解码 wire 对象不包含任何 Part 载荷字段。
	empty bool
}

// UnsupportedPartPayload detects one known unsupported Gemini part variant without retaining potentially sensitive media or execution data.
// UnsupportedPartPayload 在不保留潜在敏感媒体或执行数据的前提下检测一种已知不支持的 Gemini Part 变体。
type UnsupportedPartPayload struct{}

// InlineData contains one exact MIME type and standard Base64 payload.
// InlineData 包含一个精确 MIME 类型和标准 Base64 载荷。
type InlineData struct {
	// MIMEType is the authoritative Router-probed media type.
	// MIMEType 是 Router 探测出的权威媒体类型。
	MIMEType string `json:"mimeType"`
	// Data is standard Base64 without a data-URL prefix.
	// Data 是不含 Data URL 前缀的标准 Base64。
	Data string `json:"data"`
}

// FileData contains one provider-authorized URI.
// FileData 包含一个供应商授权 URI。
type FileData struct {
	// MIMEType is the authoritative media type.
	// MIMEType 是权威媒体类型。
	MIMEType string `json:"mimeType"`
	// FileURI is the exact provider file or object URI.
	// FileURI 是精确供应商文件或对象 URI。
	FileURI string `json:"fileUri"`
}

// UnmarshalJSON decodes the closed part fields and marks any future provider field for explicit rejection before VCP reduction.
// UnmarshalJSON 解码封闭 Part 字段，并在 VCP 归并前标记任何未来 Provider 字段以显式拒绝。
func (p *Part) UnmarshalJSON(data []byte) error {
	// plainPart prevents recursive invocation while retaining the exact closed wire shape.
	// plainPart 在保留精确封闭 wire 形态的同时避免递归调用。
	type plainPart Part
	// decoded receives only known typed part fields before future-field detection.
	// decoded 在未来字段检测前仅接收已知的类型化 Part 字段。
	var decoded plainPart
	if errDecode := json.Unmarshal(data, &decoded); errDecode != nil {
		return errDecode
	}
	// fields is boundary-only JSON metadata used solely to detect wire evolution; it never becomes execution state.
	// fields 是仅在边界使用的 JSON 元数据，仅用于检测 wire 演进，绝不成为执行状态。
	var fields map[string]json.RawMessage
	if errDecode := json.Unmarshal(data, &fields); errDecode != nil {
		return errDecode
	}
	if len(fields) == 0 {
		decoded.empty = true
	}
	for fieldName := range fields {
		switch fieldName {
		case "text", "thought", "thoughtSignature", "functionCall", "functionResponse", "inlineData", "fileData", "executableCode", "codeExecutionResult", "videoMetadata":
		default:
			decoded.unrecognized = true
		}
	}
	*p = Part(decoded)
	return nil
}

// hasUnsupportedPayload reports whether a part cannot be safely reduced by the first-phase text-and-function profile.
// hasUnsupportedPayload 表示该 Part 是否无法由第一阶段文本和函数 Profile 安全归并。
func (p Part) hasUnsupportedPayload() bool {
	return p.InlineData != nil || p.FileData != nil || p.ExecutableCode != nil || p.CodeExecutionResult != nil || p.VideoMetadata != nil || p.unrecognized
}

// hasEmptyPayload reports whether a decoded wire object had no content-part field to reduce.
// hasEmptyPayload 表示已解码 wire 对象是否没有可归并的内容 Part 字段。
func (p Part) hasEmptyPayload() bool {
	return p.empty
}

// FunctionCall contains the typed Gemini function-call wire fields.
// FunctionCall 包含类型化 Gemini 函数调用 wire 字段。
type FunctionCall struct {
	// ID is the optional upstream function-call identifier.
	// ID 是可选的上游函数调用标识。
	ID string `json:"id,omitempty"`
	// Name is the exact declared Gemini wire function name.
	// Name 是精确声明的 Gemini wire 函数名称。
	Name string `json:"name,omitempty"`
	// Args contains the exact provider JSON argument object or documented stream fragment.
	// Args 包含精确 Provider JSON 参数对象或文档化流分片。
	Args json.RawMessage `json:"args,omitempty"`
}

// FunctionResponse contains the typed Gemini function-response wire fields.
// FunctionResponse 包含类型化 Gemini 函数响应 wire 字段。
type FunctionResponse struct {
	// ID carries the original upstream function-call identifier when present.
	// ID 在存在时携带原始上游函数调用标识。
	ID string `json:"id,omitempty"`
	// Name is the exact function name associated with the response.
	// Name 是与该响应关联的精确函数名称。
	Name string `json:"name"`
	// Response is the required JSON object supplied to the function-response part.
	// Response 是提供给函数响应部分的必需 JSON 对象。
	Response json.RawMessage `json:"response"`
}

// Tool groups typed Google function declarations.
// Tool 对类型化 Google 函数声明进行分组。
type Tool struct {
	// FunctionDeclarations contains the declarations available to the model.
	// FunctionDeclarations 包含提供给模型的声明。
	FunctionDeclarations []FunctionDeclaration `json:"functionDeclarations,omitempty"`
}

// FunctionDeclaration is one typed Gemini callable function declaration.
// FunctionDeclaration 是一个类型化 Gemini 可调用函数声明。
type FunctionDeclaration struct {
	// Name is the normalized unique Gemini wire function name.
	// Name 是已规范化且唯一的 Gemini wire 函数名称。
	Name string `json:"name"`
	// Description is model-visible function guidance.
	// Description 是模型可见的函数说明。
	Description string `json:"description,omitempty"`
	// ParametersJSONSchema contains the declared VCP JSON Schema without untyped reconstruction.
	// ParametersJSONSchema 包含已声明的 VCP JSON Schema，且不进行未类型化重建。
	ParametersJSONSchema json.RawMessage `json:"parametersJsonSchema,omitempty"`
}

// ToolConfig controls function calling for the declared tools.
// ToolConfig 控制已声明工具的函数调用。
type ToolConfig struct {
	// FunctionCallingConfig is the closed Google function-calling control.
	// FunctionCallingConfig 是封闭的 Google 函数调用控制。
	FunctionCallingConfig FunctionCallingConfig `json:"functionCallingConfig"`
}

// FunctionCallingConfig is the typed mode and exact named-function restriction.
// FunctionCallingConfig 是类型化模式和精确命名函数限制。
type FunctionCallingConfig struct {
	// Mode is AUTO, NONE, or ANY according to the Google AI Studio protocol.
	// Mode 根据 Google AI Studio 协议为 AUTO、NONE 或 ANY。
	Mode string `json:"mode"`
	// AllowedFunctionNames restricts ANY mode to one explicitly selected function.
	// AllowedFunctionNames 将 ANY 模式限制为一个显式选定函数。
	AllowedFunctionNames []string `json:"allowedFunctionNames,omitempty"`
}

// GenerationConfig contains the VCP generation controls representable by AI Studio.
// GenerationConfig 包含 AI Studio 可表示的 VCP 生成控制。
type GenerationConfig struct {
	// Temperature maps VCP sampling temperature.
	// Temperature 映射 VCP 采样温度。
	Temperature *float64 `json:"temperature,omitempty"`
	// TopP maps VCP nucleus sampling.
	// TopP 映射 VCP 核采样。
	TopP *float64 `json:"topP,omitempty"`
	// MaxOutputTokens maps the VCP output token cap.
	// MaxOutputTokens 映射 VCP 输出 Token 上限。
	MaxOutputTokens *int `json:"maxOutputTokens,omitempty"`
	// StopSequences maps explicit VCP stop sequences.
	// StopSequences 映射显式 VCP 停止序列。
	StopSequences []string `json:"stopSequences,omitempty"`
	// ResponseMIMEType is application/json when a strict response schema is requested.
	// ResponseMIMEType 在请求严格响应 Schema 时为 application/json。
	ResponseMIMEType string `json:"responseMimeType,omitempty"`
	// ResponseJSONSchema contains the exact requested JSON Schema.
	// ResponseJSONSchema 包含精确请求的 JSON Schema。
	ResponseJSONSchema json.RawMessage `json:"responseJsonSchema,omitempty"`
	// ThinkingConfig contains only explicitly verified Gemini thinking controls.
	// ThinkingConfig 仅包含显式验证的 Gemini 推理控制。
	ThinkingConfig *ThinkingConfig `json:"thinkingConfig,omitempty"`
}

// ThinkingConfig is the typed Gemini generation thinking configuration represented by VCP.
// ThinkingConfig 是由 VCP 表示的类型化 Gemini 生成推理配置。
type ThinkingConfig struct {
	// ThinkingLevel controls the exact verified model reasoning level.
	// ThinkingLevel 控制精确已验证的模型推理等级。
	ThinkingLevel string `json:"thinkingLevel,omitempty"`
	// IncludeThoughts requests visible Gemini thought summaries.
	// IncludeThoughts 请求可见 Gemini thought 摘要。
	IncludeThoughts *bool `json:"includeThoughts,omitempty"`
}

// ToolReference preserves canonical tool identity across Gemini wire-name normalization.
// ToolReference 在 Gemini wire 名称规范化过程中保留规范工具身份。
type ToolReference struct {
	// WireName is the unique Gemini function declaration name.
	// WireName 是唯一的 Gemini 函数声明名称。
	WireName string
	// Namespace is the original VCP tool namespace.
	// Namespace 是原始 VCP 工具命名空间。
	Namespace string
	// Name is the original VCP tool name.
	// Name 是原始 VCP 工具名称。
	Name string
}

// ProjectedRequest contains immutable wire data and VCP audit state for one AI Studio execution.
// ProjectedRequest 包含一次 AI Studio 执行的不可变 wire 数据和 VCP 审计状态。
type ProjectedRequest struct {
	// Upstream is the exact generateContent or streamGenerateContent request body.
	// Upstream 是精确的 generateContent 或 streamGenerateContent 请求体。
	Upstream GenerateContentRequest
	// CapabilityPlan is the frozen capability decision set.
	// CapabilityPlan 是冻结的能力决策集合。
	CapabilityPlan vcp.CapabilityPlan
	// ProjectionPlan records canonical-to-wire projection decisions.
	// ProjectionPlan 记录规范到 wire 的投影决策。
	ProjectionPlan vcp.ProjectionPlan
	// Ledger retains reversible canonical projection entries.
	// Ledger 保留可逆的规范投影条目。
	Ledger vcp.ProjectionLedger
	// Report contains client-safe execution and conversion facts.
	// Report 包含客户端安全的执行和转换事实。
	Report vcp.ExecutionReport
	// ToolReferences permits exact output function-name restoration.
	// ToolReferences 允许精确恢复输出函数名称。
	ToolReferences []ToolReference
}

// CountTokensRequest is the typed AI Studio countTokens request body.
// CountTokensRequest 是类型化的 AI Studio countTokens 请求体。
type CountTokensRequest struct {
	// GenerateContentRequest carries the same typed generation input whose tokens must be counted.
	// GenerateContentRequest 携带必须统计 Token 的同一类型化生成输入。
	GenerateContentRequest GenerateContentRequest `json:"generateContentRequest"`
}

// CountTokensResponse is the typed AI Studio countTokens response body.
// CountTokensResponse 是类型化的 AI Studio countTokens 响应体。
type CountTokensResponse struct {
	// TotalTokens is the provider-reported input token count.
	// TotalTokens 是 Provider 报告的输入 Token 数。
	TotalTokens *int64 `json:"totalTokens,omitempty"`
	// CachedContentTokenCount is the provider-reported cached input token count.
	// CachedContentTokenCount 是 Provider 报告的缓存输入 Token 数。
	CachedContentTokenCount *int64 `json:"cachedContentTokenCount,omitempty"`
	// PromptTokensDetails contains per-modality prompt accounting that VCP does not currently represent.
	// PromptTokensDetails 包含 VCP 当前不表示的逐模态提示词计量。
	PromptTokensDetails []ModalityTokenCount `json:"promptTokensDetails,omitempty"`
	// CacheTokensDetails contains per-modality cached-content accounting that VCP does not currently represent.
	// CacheTokensDetails 包含 VCP 当前不表示的逐模态缓存内容计量。
	CacheTokensDetails []ModalityTokenCount `json:"cacheTokensDetails,omitempty"`
}

// CountTokensResult contains a typed token-count observation and the projection audit state.
// CountTokensResult 包含类型化 Token 统计观测和投影审计状态。
type CountTokensResult struct {
	// TotalTokens is nil only when the upstream response did not report a count.
	// TotalTokens 仅在上游响应未报告计数时为 nil。
	TotalTokens *int64
	// Usage records the exact provider-reported count as a VCP preflight observation.
	// Usage 将精确 Provider 计数记录为 VCP 预检观测。
	Usage vcp.UsageObservation
	// Report records the client-safe countTokens conversion and provider usage observation.
	// Report 记录客户端安全的 countTokens 转换结果和 Provider 用量观测。
	Report vcp.ExecutionReport
	// Projected contains the immutable request projection used for counting.
	// Projected 包含用于统计的不可变请求投影。
	Projected ProjectedRequest
}

// GenerateContentResponse is the typed subset of Gemini response fields represented by VCP.
// GenerateContentResponse 是由 VCP 表示的 Gemini 响应字段类型化子集。
type GenerateContentResponse struct {
	// Candidates contains provider-generated candidate outputs.
	// Candidates 包含 Provider 生成的候选输出。
	Candidates []Candidate `json:"candidates,omitempty"`
	// PromptFeedback contains a prompt-level block result when no candidate is emitted.
	// PromptFeedback 包含未发出候选时的提示词级阻断结果。
	PromptFeedback *PromptFeedback `json:"promptFeedback,omitempty"`
	// UsageMetadata contains provider-reported token observations.
	// UsageMetadata 包含 Provider 报告的 Token 观测。
	UsageMetadata *UsageMetadata `json:"usageMetadata,omitempty"`
	// ResponseID is the provider response identifier when supplied.
	// ResponseID 是 Provider 提供时的响应标识。
	ResponseID string `json:"responseId,omitempty"`
	// ModelVersion is the provider-selected runtime model version without a VCP response carrier.
	// ModelVersion 是没有 VCP 响应承载字段的 Provider 运行时模型版本。
	ModelVersion string `json:"modelVersion,omitempty"`
	// ModelStatus is provider model-status metadata without a VCP response carrier.
	// ModelStatus 是没有 VCP 响应承载字段的 Provider 模型状态元数据。
	ModelStatus *UnsupportedResponseMetadata `json:"modelStatus,omitempty"`
}

// Candidate is one typed Gemini candidate response.
// Candidate 是一个类型化 Gemini 候选响应。
type Candidate struct {
	// Content contains ordered response parts.
	// Content 包含有序响应部分。
	Content *Content `json:"content,omitempty"`
	// FinishReason contains the documented candidate terminal reason.
	// FinishReason 包含文档化候选终止原因。
	FinishReason string `json:"finishReason,omitempty"`
	// SafetyRatings contains provider safety classifications for this candidate.
	// SafetyRatings 包含该候选的 Provider 安全分类。
	SafetyRatings []SafetyRating `json:"safetyRatings,omitempty"`
	// CitationMetadata detects citation metadata that this first-phase VCP profile does not represent.
	// CitationMetadata 检测到本第一阶段 VCP Profile 不表示的引文元数据。
	CitationMetadata *UnsupportedResponseMetadata `json:"citationMetadata,omitempty"`
	// TokenCount reports per-candidate output accounting that VCP does not currently represent.
	// TokenCount 报告 VCP 当前不表示的逐候选输出计量。
	TokenCount *int64 `json:"tokenCount,omitempty"`
	// GroundingAttributions detects grounding attribution metadata that this first-phase profile does not represent.
	// GroundingAttributions 检测到本第一阶段 Profile 不表示的检索归因元数据。
	GroundingAttributions []UnsupportedResponseMetadata `json:"groundingAttributions,omitempty"`
	// GroundingMetadata detects grounding metadata that this first-phase profile does not represent.
	// GroundingMetadata 检测到本第一阶段 Profile 不表示的检索元数据。
	GroundingMetadata *UnsupportedResponseMetadata `json:"groundingMetadata,omitempty"`
	// AvgLogprobs reports a candidate likelihood summary that VCP does not currently represent.
	// AvgLogprobs 报告 VCP 当前不表示的候选似然摘要。
	AvgLogprobs *float64 `json:"avgLogprobs,omitempty"`
	// LogprobsResult detects detailed token likelihood metadata that this first-phase profile does not represent.
	// LogprobsResult 检测到本第一阶段 Profile 不表示的详细 Token 似然元数据。
	LogprobsResult *UnsupportedResponseMetadata `json:"logprobsResult,omitempty"`
	// URLContextMetadata detects URL retrieval metadata that this first-phase profile does not represent.
	// URLContextMetadata 检测到本第一阶段 Profile 不表示的 URL 检索元数据。
	URLContextMetadata *UnsupportedResponseMetadata `json:"urlContextMetadata,omitempty"`
	// Index identifies the provider candidate index when the upstream response supplies it.
	// Index 在上游响应提供时标识 Provider 候选索引。
	Index *int `json:"index,omitempty"`
	// FinishMessage contains provider diagnostic text that must not enter VCP output or reports.
	// FinishMessage 包含不得进入 VCP 输出或报告的 Provider 诊断文本。
	FinishMessage string `json:"finishMessage,omitempty"`
	// unrecognized reports that the provider sent a future candidate field outside this closed wire carrier.
	// unrecognized 表示 Provider 发送了此封闭 wire 载体之外的未来 Candidate 字段。
	unrecognized bool
}

// UnsupportedResponseMetadata detects a known response metadata object without retaining provider diagnostic contents.
// UnsupportedResponseMetadata 在不保留 Provider 诊断内容的前提下检测一个已知响应元数据对象。
type UnsupportedResponseMetadata struct{}

// UnmarshalJSON decodes the closed candidate fields and marks future provider metadata for explicit audit reporting.
// UnmarshalJSON 解码封闭 Candidate 字段，并标记未来 Provider 元数据以供显式审计报告。
func (c *Candidate) UnmarshalJSON(data []byte) error {
	// plainCandidate prevents recursive invocation while retaining the exact closed wire shape.
	// plainCandidate 在保留精确封闭 wire 形态的同时避免递归调用。
	type plainCandidate Candidate
	// decoded receives only known typed candidate fields before future-field detection.
	// decoded 在未来字段检测前仅接收已知的类型化 Candidate 字段。
	var decoded plainCandidate
	if errDecode := json.Unmarshal(data, &decoded); errDecode != nil {
		return errDecode
	}
	// fields is boundary-only JSON metadata used solely to detect candidate wire evolution; it never becomes execution state.
	// fields 是仅在边界使用的 JSON 元数据，仅用于检测 Candidate wire 演进，绝不成为执行状态。
	var fields map[string]json.RawMessage
	if errDecode := json.Unmarshal(data, &fields); errDecode != nil {
		return errDecode
	}
	for fieldName := range fields {
		switch fieldName {
		case "content", "finishReason", "safetyRatings", "citationMetadata", "tokenCount", "groundingAttributions", "groundingMetadata", "avgLogprobs", "logprobsResult", "urlContextMetadata", "index", "finishMessage":
		default:
			decoded.unrecognized = true
		}
	}
	*c = Candidate(decoded)
	return nil
}

// hasUnrepresentedMetadata reports whether a candidate contains data with no lossless first-phase VCP response carrier.
// hasUnrepresentedMetadata 表示 Candidate 是否包含没有无损第一阶段 VCP 响应承载字段的数据。
func (c Candidate) hasUnrepresentedMetadata() bool {
	return c.CitationMetadata != nil || c.TokenCount != nil || len(c.GroundingAttributions) > 0 || c.GroundingMetadata != nil || c.AvgLogprobs != nil || c.LogprobsResult != nil || c.URLContextMetadata != nil || c.FinishMessage != "" || c.unrecognized
}

// SafetyRating is one typed provider safety classification that has no lossless VCP carrier in the first phase.
// SafetyRating 是一条类型化 Provider 安全分类，第一阶段不存在无损的 VCP 承载字段。
type SafetyRating struct {
	// Category identifies the documented harm category.
	// Category 标识文档化伤害类别。
	Category string `json:"category,omitempty"`
	// Probability identifies the documented harm probability.
	// Probability 标识文档化伤害概率。
	Probability string `json:"probability,omitempty"`
	// Blocked reports whether this exact classification blocked the content.
	// Blocked 表示该精确分类是否阻断了内容。
	Blocked bool `json:"blocked,omitempty"`
}

// PromptFeedback is the typed prompt-level Google safety result.
// PromptFeedback 是类型化的提示词级 Google 安全结果。
type PromptFeedback struct {
	// BlockReason is a safe documented prompt block category.
	// BlockReason 是安全的文档化提示词阻断类别。
	BlockReason string `json:"blockReason,omitempty"`
	// SafetyRatings contains provider safety classifications for the prompt.
	// SafetyRatings 包含提示词的 Provider 安全分类。
	SafetyRatings []SafetyRating `json:"safetyRatings,omitempty"`
}

// UsageMetadata is the typed AI Studio usage subset mapped into VCP observations.
// UsageMetadata 是映射到 VCP 观测的类型化 AI Studio 用量子集。
type UsageMetadata struct {
	// PromptTokenCount reports input tokens.
	// PromptTokenCount 报告输入 Token。
	PromptTokenCount *int64 `json:"promptTokenCount,omitempty"`
	// CandidatesTokenCount reports generated candidate tokens.
	// CandidatesTokenCount 报告生成候选 Token。
	CandidatesTokenCount *int64 `json:"candidatesTokenCount,omitempty"`
	// ToolUsePromptTokenCount reports tokens used in provider tool-use prompts without a VCP-equivalent accounting field.
	// ToolUsePromptTokenCount 报告 Provider 工具使用提示词中的 Token，VCP 没有等价的计量字段。
	ToolUsePromptTokenCount *int64 `json:"toolUsePromptTokenCount,omitempty"`
	// ThoughtsTokenCount reports provider thinking tokens.
	// ThoughtsTokenCount 报告 Provider 思考 Token。
	ThoughtsTokenCount *int64 `json:"thoughtsTokenCount,omitempty"`
	// CachedContentTokenCount reports cached input tokens.
	// CachedContentTokenCount 报告缓存输入 Token。
	CachedContentTokenCount *int64 `json:"cachedContentTokenCount,omitempty"`
	// TotalTokenCount reports the full provider total.
	// TotalTokenCount 报告完整 Provider 总数。
	TotalTokenCount *int64 `json:"totalTokenCount,omitempty"`
	// PromptTokensDetails contains per-modality prompt accounting that VCP does not currently represent.
	// PromptTokensDetails 包含 VCP 当前不表示的逐模态提示词计量。
	PromptTokensDetails []ModalityTokenCount `json:"promptTokensDetails,omitempty"`
	// CacheTokensDetails contains per-modality cached-content accounting that VCP does not currently represent.
	// CacheTokensDetails 包含 VCP 当前不表示的逐模态缓存内容计量。
	CacheTokensDetails []ModalityTokenCount `json:"cacheTokensDetails,omitempty"`
	// CandidatesTokensDetails contains per-modality candidate accounting that VCP does not currently represent.
	// CandidatesTokensDetails 包含 VCP 当前不表示的逐模态候选计量。
	CandidatesTokensDetails []ModalityTokenCount `json:"candidatesTokensDetails,omitempty"`
	// ToolUsePromptTokensDetails contains per-modality tool-use prompt accounting that VCP does not currently represent.
	// ToolUsePromptTokensDetails 包含 VCP 当前不表示的逐模态工具使用提示词计量。
	ToolUsePromptTokensDetails []ModalityTokenCount `json:"toolUsePromptTokensDetails,omitempty"`
	// ServiceTier contains the provider-selected service tier without a VCP response carrier.
	// ServiceTier 包含没有 VCP 响应承载字段的 Provider 所选服务层级。
	ServiceTier string `json:"serviceTier,omitempty"`
}

// ModalityTokenCount is one provider-reported modality-specific token count.
// ModalityTokenCount 是一条 Provider 报告的模态专属 Token 计数。
type ModalityTokenCount struct {
	// Modality identifies the documented content modality.
	// Modality 标识文档化内容模态。
	Modality string `json:"modality,omitempty"`
	// TokenCount reports the token count for this modality when supplied.
	// TokenCount 在提供时报告该模态的 Token 计数。
	TokenCount *int64 `json:"tokenCount,omitempty"`
}

// SSEEnvelope is one complete provider SSE frame before JSON interpretation.
// SSEEnvelope 是 JSON 解释前的一条完整 Provider SSE 帧。
type SSEEnvelope struct {
	// Event is the optional SSE event name.
	// Event 是可选 SSE 事件名称。
	Event string
	// Data contains joined SSE data lines.
	// Data 包含已连接的 SSE data 行。
	Data []byte
}
