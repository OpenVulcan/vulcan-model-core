package execution

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/inputplan"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/routertool"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

const (
	// maximumParallelRouterToolChildren bounds one parent model round independently of model-authored call count.
	// maximumParallelRouterToolChildren 独立于模型生成的调用数量限制单个父模型轮次的并行子执行数。
	maximumParallelRouterToolChildren = 4
	// routerToolNamespace isolates Router-managed functions from caller-owned tools.
	// routerToolNamespace 将 Router 管理函数与调用方工具隔离。
	routerToolNamespace = "vulcan.router"
	// routerWebSearchName is the provider-visible Router search function.
	// routerWebSearchName 是供应商可见的 Router 搜索函数。
	routerWebSearchName = "vulcan_web_search"
	// routerWebExtractorName is the provider-visible Router extraction function.
	// routerWebExtractorName 是供应商可见的 Router 抓取函数。
	routerWebExtractorName = "vulcan_web_extractor"
	// routerImageUnderstandingName is the provider-visible Router image-analysis function.
	// routerImageUnderstandingName 是供应商可见的 Router 图片分析函数。
	routerImageUnderstandingName = "vulcan_image_understanding"
	// routerAudioUnderstandingName is the provider-visible Router audio-analysis function.
	// routerAudioUnderstandingName 是供应商可见的 Router 音频分析函数。
	routerAudioUnderstandingName = "vulcan_audio_understanding"
	// routerVideoUnderstandingName is the provider-visible Router video-analysis function.
	// routerVideoUnderstandingName 是供应商可见的 Router 视频分析函数。
	routerVideoUnderstandingName = "vulcan_video_understanding"
	// routerImageGenerationName is the provider-visible Router image-generation function.
	// routerImageGenerationName 是供应商可见的 Router 图片生成函数。
	routerImageGenerationName = "vulcan_image_generation"
	// routerVideoGenerationName is the provider-visible Router video-generation function.
	// routerVideoGenerationName 是供应商可见的 Router 视频生成函数。
	routerVideoGenerationName = "vulcan_video_generation"
	// routerSpeechGenerationName is the provider-visible Router speech-synthesis function.
	// routerSpeechGenerationName 是供应商可见的 Router 语音合成函数。
	routerSpeechGenerationName = "vulcan_speech_generation"
	// routerSpeechTranscriptionName is the provider-visible Router speech-recognition function.
	// routerSpeechTranscriptionName 是供应商可见的 Router 语音识别函数。
	routerSpeechTranscriptionName = "vulcan_speech_transcription"
)

var (
	// routerWebSearchSchema is the fixed strict input contract for Router search.
	// routerWebSearchSchema 是 Router 搜索的固定严格输入契约。
	routerWebSearchSchema = json.RawMessage(`{"type":"object","properties":{"query":{"type":"string"},"max_results":{"type":"integer","minimum":1}},"required":["query"],"additionalProperties":false}`)
	// routerWebExtractorSchema is the fixed strict input contract for Router extraction.
	// routerWebExtractorSchema 是 Router 抓取的固定严格输入契约。
	routerWebExtractorSchema = json.RawMessage(`{"type":"object","properties":{"urls":{"type":"array","items":{"type":"string","format":"uri"},"minItems":1},"query":{"type":"string"}},"required":["urls"],"additionalProperties":false}`)
	// routerUnderstandingSchema accepts only one authorized parent resource and tasks proved by every implemented media-analysis adapter.
	// routerUnderstandingSchema 仅接受一个父执行已授权资源，以及每个已实现媒体分析适配器均已证明的任务。
	routerUnderstandingSchema = json.RawMessage(`{"type":"object","properties":{"resource_ref":{"type":"string"},"task":{"enum":["describe","summarize","question_answer","extract"]},"instruction":{"type":"string"}},"required":["resource_ref","task"],"additionalProperties":false}`)
	// routerImageGenerationSchema exposes the provider-independent image generation core.
	// routerImageGenerationSchema 公开供应商无关图片生成核心。
	routerImageGenerationSchema = json.RawMessage(`{"type":"object","properties":{"prompt":{"type":"string"},"negative_prompt":{"type":"string"},"count":{"type":"integer","minimum":1},"width":{"type":"integer","minimum":1},"height":{"type":"integer","minimum":1},"aspect_ratio":{"type":"string"}},"required":["prompt"],"additionalProperties":false}`)
	// routerVideoGenerationSchema exposes the provider-independent video generation core.
	// routerVideoGenerationSchema 公开供应商无关视频生成核心。
	routerVideoGenerationSchema = json.RawMessage(`{"type":"object","properties":{"prompt":{"type":"string"},"negative_prompt":{"type":"string"},"duration_seconds":{"type":"number","exclusiveMinimum":0},"aspect_ratio":{"type":"string"},"resolution":{"type":"string"}},"required":["prompt"],"additionalProperties":false}`)
	// routerSpeechGenerationSchema exposes non-realtime synthesis with an explicit voice.
	// routerSpeechGenerationSchema 公开带显式音色的非实时语音合成。
	routerSpeechGenerationSchema = json.RawMessage(`{"type":"object","properties":{"text":{"type":"string"},"voice_id":{"type":"string"},"output_format":{"type":"string"}},"required":["text","voice_id"],"additionalProperties":false}`)
	// routerSpeechTranscriptionSchema accepts only one authorized audio or video resource.
	// routerSpeechTranscriptionSchema 仅接受一个已授权音频或视频资源。
	routerSpeechTranscriptionSchema = json.RawMessage(`{"type":"object","properties":{"resource_ref":{"type":"string"},"language":{"type":"string"},"prompt":{"type":"string"}},"required":["resource_ref"],"additionalProperties":false}`)
)

// routerToolCallPlan freezes one standard tool or Router extension and its exact child target.
// routerToolCallPlan 冻结一个标准工具或 Router 增强能力及其精确子 Target。
type routerToolCallPlan struct {
	// Standard identifies a closed standard tool when this is a standard binding.
	// Standard 在此为标准绑定时标识封闭标准工具。
	Standard vcp.StandardModelToolKind
	// Extension identifies a closed operation-backed enhancement when this is an extension binding.
	// Extension 在此为增强绑定时标识封闭且由操作支持的增强能力。
	Extension vcp.RouterExtensionKind
	// RouterBinding contains the exact immutable policy and child target.
	// RouterBinding 包含精确不可变策略与子 Target。
	RouterBinding *routertool.ResolvedBinding
}

// ToolID returns the sole stable public tool identifier.
// ToolID 返回唯一稳定公开工具标识。
func (p routerToolCallPlan) ToolID() string {
	if p.Standard.Valid() {
		return string(p.Standard)
	}
	return string(p.Extension)
}

// routerToolCall is one completed provider request for a frozen Router-managed tool.
// routerToolCall 是供应商针对冻结 Router 管理工具生成的一个已完成请求。
type routerToolCall struct {
	// Output preserves the provider-decoded call relation.
	// Output 保留供应商解码后的调用关系。
	Output vcp.OutputItem
	// Plan is the exact frozen execution decision.
	// Plan 是精确冻结的执行决策。
	Plan routerToolCallPlan
}

// routerToolCallResult preserves one child result at the exact provider-authored call index.
// routerToolCallResult 在精确的供应商调用索引处保留一个子执行结果。
type routerToolCallResult struct {
	// ModelResult is the bounded normalized payload returned to the parent model.
	// ModelResult 是返回父模型的有界规范化载荷。
	ModelResult string
	// ChildExecutionID links the parent tool result to its durable child.
	// ChildExecutionID 将父工具结果关联到其持久化子执行。
	ChildExecutionID string
	// Err records the exact child failure without reordering sibling results.
	// Err 记录精确的子执行失败且不重排同轮结果。
	Err error
}

// routerToolHistoryEntry identifies the frozen binding and ceiling owned by one provider-visible Router function.
// routerToolHistoryEntry 标识一个供应商可见 Router 函数拥有的冻结绑定与上限。
type routerToolHistoryEntry struct {
	// BindingID identifies the exact frozen administrator policy.
	// BindingID 标识精确冻结的管理员策略。
	BindingID string
	// MaximumCalls is the persisted per-parent ceiling.
	// MaximumCalls 是持久化的逐父执行上限。
	MaximumCalls int
}

// routerSearchArguments contains the only accepted Router search arguments.
// routerSearchArguments 包含 Router 搜索唯一接受的参数。
type routerSearchArguments struct {
	// Query is the exact model-authored search query.
	// Query 是模型编写的精确搜索查询。
	Query string `json:"query"`
	// MaxResults optionally requests a smaller result ceiling.
	// MaxResults 可选地请求更小的结果上限。
	MaxResults *int `json:"max_results,omitempty"`
}

// routerExtractArguments contains the only accepted Router extraction arguments.
// routerExtractArguments 包含 Router 抓取唯一接受的参数。
type routerExtractArguments struct {
	// URLs contains exact public HTTPS resources.
	// URLs 包含精确的公网 HTTPS 资源。
	URLs []string `json:"urls"`
	// Query optionally requests relevance-ranked extraction.
	// Query 可选地请求相关性排序抓取。
	Query string `json:"query,omitempty"`
}

// routerUnderstandingArguments contains one authorized resource analysis request.
// routerUnderstandingArguments 包含一个已授权资源分析请求。
type routerUnderstandingArguments struct {
	// ResourceRef must match one exact parent conversation media block.
	// ResourceRef 必须匹配父会话中的一个精确媒体块。
	ResourceRef string `json:"resource_ref"`
	// Task selects one closed VCP analysis semantic.
	// Task 选择一个封闭 VCP 分析语义。
	Task vcp.MediaAnalyzeTask `json:"task"`
	// Instruction supplies an explicit question or extraction request.
	// Instruction 提供明确问题或提取请求。
	Instruction string `json:"instruction,omitempty"`
}

// routerImageGenerationArguments contains bounded provider-independent image generation input.
// routerImageGenerationArguments 包含有界且供应商无关的图片生成输入。
type routerImageGenerationArguments struct {
	// Prompt describes the requested image.
	// Prompt 描述请求生成的图片。
	Prompt string `json:"prompt"`
	// NegativePrompt describes visual content to exclude.
	// NegativePrompt 描述需要排除的视觉内容。
	NegativePrompt string `json:"negative_prompt,omitempty"`
	// Count requests a positive output count.
	// Count 请求正数输出数量。
	Count int `json:"count,omitempty"`
	// Width requests an exact output width.
	// Width 请求精确输出宽度。
	Width int `json:"width,omitempty"`
	// Height requests an exact output height.
	// Height 请求精确输出高度。
	Height int `json:"height,omitempty"`
	// AspectRatio requests one provider-declared display ratio.
	// AspectRatio 请求一个供应商声明的显示比例。
	AspectRatio string `json:"aspect_ratio,omitempty"`
}

// routerVideoGenerationArguments contains bounded provider-independent video generation input.
// routerVideoGenerationArguments 包含有界且供应商无关的视频生成输入。
type routerVideoGenerationArguments struct {
	// Prompt describes the requested video.
	// Prompt 描述请求生成的视频。
	Prompt string `json:"prompt"`
	// NegativePrompt describes audiovisual content to exclude.
	// NegativePrompt 描述需要排除的视听内容。
	NegativePrompt string `json:"negative_prompt,omitempty"`
	// DurationSeconds requests a positive video duration.
	// DurationSeconds 请求正数视频时长。
	DurationSeconds float64 `json:"duration_seconds,omitempty"`
	// AspectRatio requests one provider-declared display ratio.
	// AspectRatio 请求一个供应商声明的显示比例。
	AspectRatio string `json:"aspect_ratio,omitempty"`
	// Resolution requests one provider-declared output tier.
	// Resolution 请求一个供应商声明的输出档位。
	Resolution string `json:"resolution,omitempty"`
}

// routerSpeechGenerationArguments contains one non-realtime synthesis request.
// routerSpeechGenerationArguments 包含一个非实时语音合成请求。
type routerSpeechGenerationArguments struct {
	// Text is the exact content to synthesize.
	// Text 是需要合成的精确文本。
	Text string `json:"text"`
	// VoiceID selects one provider-supported voice.
	// VoiceID 选择一个供应商支持的音色。
	VoiceID string `json:"voice_id"`
	// OutputFormat requests one provider-supported audio format.
	// OutputFormat 请求一个供应商支持的音频格式。
	OutputFormat string `json:"output_format,omitempty"`
}

// routerSpeechTranscriptionArguments contains one authorized non-realtime recognition request.
// routerSpeechTranscriptionArguments 包含一个已授权非实时语音识别请求。
type routerSpeechTranscriptionArguments struct {
	// ResourceRef must match one authorized parent audio or video block.
	// ResourceRef 必须匹配一个已授权父音频或视频块。
	ResourceRef string `json:"resource_ref"`
	// Language optionally fixes the source language.
	// Language 可选固定源语言。
	Language string `json:"language,omitempty"`
	// Prompt supplies provider-supported recognition context.
	// Prompt 提供供应商支持的识别上下文。
	Prompt string `json:"prompt,omitempty"`
}

// applyRouterToolDefinitions injects only frozen Router functions into the provider-facing request copy.
// applyRouterToolDefinitions 仅将冻结的 Router 函数注入供应商侧请求副本。
func applyRouterToolDefinitions(request *vcp.ExecutionRequest, plan ModelToolPlan) {
	if request == nil || request.Operation != vcp.OperationConversationRespond || request.Payload.Conversation == nil || request.Payload.Conversation.ToolPolicy.Choice == vcp.ToolChoiceNone {
		return
	}
	for _, entry := range plan.Standard {
		if entry.Mode != vcp.ModelToolRouter {
			continue
		}
		switch entry.Kind {
		case vcp.StandardModelToolWebSearch:
			request.Payload.Conversation.Tools = append(request.Payload.Conversation.Tools, vcp.ToolDefinition{Kind: vcp.ToolFunction, Namespace: routerToolNamespace, Name: routerWebSearchName, Description: "Search the public web using the Router-configured service.", Parameters: append(json.RawMessage(nil), routerWebSearchSchema...)})
		case vcp.StandardModelToolWebExtractor:
			request.Payload.Conversation.Tools = append(request.Payload.Conversation.Tools, vcp.ToolDefinition{Kind: vcp.ToolFunction, Namespace: routerToolNamespace, Name: routerWebExtractorName, Description: "Extract content from public HTTPS URLs using the Router-configured service.", Parameters: append(json.RawMessage(nil), routerWebExtractorSchema...)})
		}
	}
	for _, entry := range plan.RouterExtensions {
		name, description, schema := routerExtensionDefinition(entry.ID)
		if name == "" {
			continue
		}
		request.Payload.Conversation.Tools = append(request.Payload.Conversation.Tools, vcp.ToolDefinition{
			Kind:        vcp.ToolFunction,
			Namespace:   routerToolNamespace,
			Name:        name,
			Description: description,
			Parameters:  append(json.RawMessage(nil), schema...),
		})
	}
	policy := &request.Payload.Conversation.ToolPolicy
	if policy.Choice == vcp.ToolChoiceNamed {
		if routerName := routerNamedFunction(plan, policy.NamedTool); routerName != "" {
			policy.NamedTool = routerName
		}
	}
}

// routerNamedFunction returns a provider-visible function only for one exact frozen Router-mode plan entry.
// routerNamedFunction 仅为一个精确冻结的 Router 模式计划项返回供应商可见函数。
func routerNamedFunction(plan ModelToolPlan, publicName string) string {
	for _, entry := range plan.Standard {
		if entry.Mode == vcp.ModelToolRouter && string(entry.Kind) == publicName {
			return routerFunctionName(entry.Kind)
		}
	}
	for _, entry := range plan.RouterExtensions {
		if string(entry.ID) == publicName {
			return routerExtensionFunctionName(entry.ID)
		}
	}
	return ""
}

// routerToolCalls returns only completed reserved calls backed by the frozen plan.
// routerToolCalls 仅返回由冻结计划支持的已完成保留调用。
func routerToolCalls(result provider.ExecutionResult, plan ModelToolPlan) ([]routerToolCall, error) {
	entries := make(map[string]routerToolCallPlan, len(plan.Standard)+len(plan.RouterExtensions))
	for _, entry := range plan.Standard {
		if entry.Mode != vcp.ModelToolRouter {
			continue
		}
		entries[routerFunctionName(entry.Kind)] = routerToolCallPlan{Standard: entry.Kind, RouterBinding: entry.RouterBinding}
	}
	for _, entry := range plan.RouterExtensions {
		entries[routerExtensionFunctionName(entry.ID)] = routerToolCallPlan{Extension: entry.ID, RouterBinding: entry.RouterBinding}
	}
	calls := make([]routerToolCall, 0)
	for _, item := range result.Response.Items {
		if item.Kind != vcp.ContextToolCall || item.ToolCall == nil {
			continue
		}
		entry, managed := entries[item.ToolCall.Name]
		if !managed {
			if reservedRouterToolName(item.ToolCall.Name) {
				return nil, errors.Join(vcp.NewModelToolError(vcp.RouterToolResultInvalid, item.ToolCall.Name, "result", false), ErrInvalidProviderResult)
			}
			continue
		}
		if item.ToolCall.Status != vcp.ToolCallCompleted || strings.TrimSpace(item.ToolCall.ToolCallID) == "" {
			return nil, errors.Join(vcp.NewModelToolError(vcp.RouterToolResultInvalid, entry.ToolID(), "result", false), ErrInvalidProviderResult)
		}
		calls = append(calls, routerToolCall{Output: item, Plan: entry})
	}
	return calls, nil
}

// routerToolHistory restores committed call identifiers and per-binding counts from the durable parent context.
// routerToolHistory 从持久化父上下文恢复已提交调用标识与逐绑定计数。
// Parameters: record contains the frozen plan and every committed Router call/result pair.
// 参数：record 包含冻结计划以及每个已提交 Router 调用/结果对。
// Returns: binding counts, seen call identifiers, and an explicit corruption error.
// 返回：绑定计数、已见调用标识以及明确的损坏错误。
func routerToolHistory(record Record) (map[string]int, map[string]struct{}, error) {
	counts := make(map[string]int)
	seenCalls := make(map[string]struct{})
	if !hasRouterToolPlan(record.ModelToolPlan) {
		return counts, seenCalls, nil
	}
	if record.Request.Payload.Conversation == nil {
		return nil, nil, fmt.Errorf("%w: Router tool history has no parent conversation", ErrInvalidExecution)
	}
	entries := make(map[string]routerToolHistoryEntry, len(record.ModelToolPlan.Standard)+len(record.ModelToolPlan.RouterExtensions))
	for _, entry := range record.ModelToolPlan.Standard {
		if entry.Mode == vcp.ModelToolRouter && entry.RouterBinding != nil {
			entries[routerFunctionName(entry.Kind)] = routerToolHistoryEntry{BindingID: entry.RouterBinding.Binding.ID, MaximumCalls: entry.RouterBinding.Binding.MaximumCalls}
		}
	}
	for _, entry := range record.ModelToolPlan.RouterExtensions {
		if entry.RouterBinding != nil {
			entries[routerExtensionFunctionName(entry.ID)] = routerToolHistoryEntry{BindingID: entry.RouterBinding.Binding.ID, MaximumCalls: entry.RouterBinding.Binding.MaximumCalls}
		}
	}
	internalCalls := make(map[string]vcp.ContextItem)
	for _, item := range record.Request.Payload.Conversation.Context {
		if item.Kind != vcp.ContextToolCall || item.ToolCall == nil {
			continue
		}
		internalNamespace := item.ToolCall.Namespace == routerToolNamespace
		reservedName := reservedRouterToolName(item.ToolCall.Name)
		if !internalNamespace && !reservedName {
			continue
		}
		if !internalNamespace || !reservedName {
			return nil, nil, fmt.Errorf("%w: Router tool history contains an invalid reserved call", ErrInvalidExecution)
		}
		_, exists := entries[item.ToolCall.Name]
		if !exists || item.ToolCall.Status != vcp.ToolCallCompleted || strings.TrimSpace(item.DelegationID) == "" {
			return nil, nil, fmt.Errorf("%w: Router tool history contains an unplanned call", ErrInvalidExecution)
		}
		callID := strings.TrimSpace(item.ToolCall.ToolCallID)
		if callID == "" {
			return nil, nil, fmt.Errorf("%w: Router tool history contains an unidentified call", ErrInvalidExecution)
		}
		if _, duplicate := seenCalls[callID]; duplicate {
			return nil, nil, fmt.Errorf("%w: Router tool history contains a duplicate call", ErrInvalidExecution)
		}
		seenCalls[callID] = struct{}{}
		internalCalls[callID] = item
	}
	results := make(map[string]vcp.ContextItem, len(internalCalls))
	for _, item := range record.Request.Payload.Conversation.Context {
		if item.Kind != vcp.ContextToolResult || item.ToolResult == nil {
			continue
		}
		callID := strings.TrimSpace(item.ToolResult.ToolCallID)
		if _, internal := internalCalls[callID]; !internal {
			continue
		}
		if _, duplicate := results[callID]; duplicate {
			return nil, nil, fmt.Errorf("%w: Router tool history contains duplicate tool results", ErrInvalidExecution)
		}
		results[callID] = item
	}
	for callID, item := range internalCalls {
		entry := entries[item.ToolCall.Name]
		result, paired := results[callID]
		if !paired || result.ParentItemID != item.ItemID || result.DelegationID != item.DelegationID {
			return nil, nil, fmt.Errorf("%w: Router tool history contains an unpaired call", ErrInvalidExecution)
		}
		counts[entry.BindingID]++
		if counts[entry.BindingID] > entry.MaximumCalls {
			return nil, nil, fmt.Errorf("%w: Router tool history exceeds the frozen binding limit", ErrInvalidExecution)
		}
	}
	return counts, seenCalls, nil
}

// routerExtensionDefinition returns the fixed provider-visible definition for one closed Router extension.
// routerExtensionDefinition 返回一个封闭 Router 增强能力的固定供应商可见定义。
func routerExtensionDefinition(extension vcp.RouterExtensionKind) (string, string, json.RawMessage) {
	switch extension {
	case vcp.RouterExtensionImageUnderstanding:
		return routerImageUnderstandingName, "Analyze one authorized image using the Router-configured model.", routerUnderstandingSchema
	case vcp.RouterExtensionAudioUnderstanding:
		return routerAudioUnderstandingName, "Analyze one authorized audio resource using the Router-configured model.", routerUnderstandingSchema
	case vcp.RouterExtensionVideoUnderstanding:
		return routerVideoUnderstandingName, "Analyze one authorized video using the Router-configured model.", routerUnderstandingSchema
	case vcp.RouterExtensionImageGeneration:
		return routerImageGenerationName, "Generate images using the Router-configured model.", routerImageGenerationSchema
	case vcp.RouterExtensionVideoGeneration:
		return routerVideoGenerationName, "Generate video using the Router-configured model.", routerVideoGenerationSchema
	case vcp.RouterExtensionSpeechGeneration:
		return routerSpeechGenerationName, "Synthesize non-realtime speech using the Router-configured model.", routerSpeechGenerationSchema
	case vcp.RouterExtensionSpeechTranscription:
		return routerSpeechTranscriptionName, "Transcribe one authorized audio or video resource using the Router-configured model.", routerSpeechTranscriptionSchema
	default:
		return "", "", nil
	}
}

// routerFunctionName maps a closed standard tool to its reserved provider function.
// routerFunctionName 将封闭标准工具映射到保留的供应商函数。
func routerFunctionName(kind vcp.StandardModelToolKind) string {
	switch kind {
	case vcp.StandardModelToolWebSearch:
		return routerWebSearchName
	case vcp.StandardModelToolWebExtractor:
		return routerWebExtractorName
	default:
		return ""
	}
}

// routerExtensionFunctionName maps a closed Router extension to its reserved provider function.
// routerExtensionFunctionName 将封闭 Router 增强能力映射到保留的供应商函数。
func routerExtensionFunctionName(extension vcp.RouterExtensionKind) string {
	name, _, _ := routerExtensionDefinition(extension)
	return name
}

// maximumRouterToolCalls returns the sum of frozen per-binding call ceilings.
// maximumRouterToolCalls 返回冻结绑定逐项调用上限之和。
func maximumRouterToolCalls(plan ModelToolPlan) int {
	total := 0
	for _, entry := range plan.Standard {
		if entry.Mode == vcp.ModelToolRouter && entry.RouterBinding != nil {
			total += entry.RouterBinding.Binding.MaximumCalls
		}
	}
	for _, entry := range plan.RouterExtensions {
		if entry.RouterBinding != nil {
			total += entry.RouterBinding.Binding.MaximumCalls
		}
	}
	return total
}

// hasRouterToolPlan reports whether provider events must remain buffered across model-tool rounds.
// hasRouterToolPlan 报告供应商事件是否必须跨模型工具轮次保持缓冲。
func hasRouterToolPlan(plan ModelToolPlan) bool {
	return maximumRouterToolCalls(plan) > 0
}

// withholdRouterManagedMedia replaces delegated media with opaque references and removes its materialized bytes from the parent dispatch.
// withholdRouterManagedMedia 用不透明引用替换已委托媒体，并从父分派中移除其物化字节。
func withholdRouterManagedMedia(request *vcp.ExecutionRequest, plan ModelToolPlan, materialized []resource.MaterializedInput) []resource.MaterializedInput {
	if request == nil || request.Payload.Conversation == nil || len(plan.RouterExtensions) == 0 {
		return append([]resource.MaterializedInput(nil), materialized...)
	}
	claimedResources := make(map[string]struct{})
	for itemIndex := range request.Payload.Conversation.Context {
		item := &request.Payload.Conversation.Context[itemIndex]
		for blockIndex, block := range item.Content {
			kind, media := mediaKindForContentType(block.Type)
			if !media || block.ResourceRef == "" || !routerExtensionPlanClaimsMedia(plan.RouterExtensions, kind) {
				continue
			}
			claimedResources[block.ResourceRef] = struct{}{}
			item.Content[blockIndex] = vcp.ContentBlock{
				Type: vcp.ContentText,
				Text: fmt.Sprintf("[Router-managed %s resource_ref=%s]", kind, block.ResourceRef),
			}
		}
	}
	if len(claimedResources) == 0 {
		return append([]resource.MaterializedInput(nil), materialized...)
	}
	filtered := make([]resource.MaterializedInput, 0, len(materialized))
	for _, input := range materialized {
		if _, claimed := claimedResources[input.ResourceID]; claimed {
			continue
		}
		filtered = append(filtered, input)
	}
	return filtered
}

// routerExtensionPlanClaimsMedia reports whether one frozen extension plan owns a media family.
// routerExtensionPlanClaimsMedia 报告一个冻结增强计划是否拥有某种媒体类别。
func routerExtensionPlanClaimsMedia(entries []RouterExtensionPlanEntry, kind vcp.MediaKind) bool {
	for _, entry := range entries {
		if extensionAcceptsMediaKind(entry.ID, kind) {
			return true
		}
	}
	return false
}

// executeRouterToolCall creates one normal VCP child execution and returns a bounded model-visible result.
// executeRouterToolCall 创建一个普通 VCP 子执行并返回有界的模型可见结果。
func (s *Service) executeRouterToolCall(ctx context.Context, parent Record, call routerToolCall, round uint32) (string, string, error) {
	if call.Plan.RouterBinding == nil {
		return "", "", fmt.Errorf("%w: Router tool plan has no frozen binding", ErrInvalidExecution)
	}
	binding := call.Plan.RouterBinding.Binding
	toolID := call.Plan.ToolID()
	childRequest, errRequest := s.routerToolChildRequest(ctx, parent, call, round)
	if errRequest != nil {
		return "", "", errRequest
	}
	lineage := &RouterToolLineage{ParentExecutionID: parent.ID, ParentToolCallID: call.Output.ToolCall.ToolCallID, ParentRound: round, BindingID: binding.ID}
	childContext, cancelChild := context.WithTimeout(ctx, time.Duration(binding.TimeoutMilliseconds)*time.Millisecond)
	defer cancelChild()
	childTarget := call.Plan.RouterBinding.Target
	child, replayed, errChild := s.create(childContext, parent.OwnerAPIKeyID, childRequest, lineage, &childTarget)
	if errChild != nil {
		retryable := errors.Is(errChild, context.DeadlineExceeded)
		return "", "", errors.Join(vcp.NewModelToolError(vcp.RouterToolExecutionFailed, toolID, "execution", retryable), errChild)
	}
	if replayed && child.Status != StatusSucceeded {
		return "", child.ID, vcp.NewModelToolError(vcp.RouterToolExecutionFailed, toolID, "execution", false)
	}
	if child.Status != StatusSucceeded || child.Result == nil {
		failureCode := "router_tool_child_failed"
		if child.Failure != nil && child.Failure.Code != "" {
			failureCode = child.Failure.Code
		}
		modelToolCode := vcp.RouterToolExecutionFailed
		if failureCode == "execution_budget_exceeded" {
			modelToolCode = vcp.RouterToolBudgetExceeded
		}
		return "", child.ID, errors.Join(vcp.NewModelToolError(modelToolCode, toolID, "execution", child.Failure != nil && child.Failure.Retryable), errors.New(failureCode))
	}
	serialized, errSerialize := serializeRouterToolResult(call.Plan, *child.Result, binding.MaximumResultBytes)
	if errSerialize != nil {
		return "", child.ID, errors.Join(vcp.NewModelToolError(vcp.RouterToolResultInvalid, toolID, "result", false), errSerialize)
	}
	return serialized, child.ID, nil
}

// executeRouterToolCalls executes one model-authored batch sequentially unless the caller explicitly authorized parallel tools.
// executeRouterToolCalls 顺序执行一个模型生成批次，除非调用方显式授权并行工具。
// Parameters: ctx propagates cancellation; parent is immutable for the batch; calls preserve provider order; round is the durable semantic round; parallel is caller intent.
// 参数：ctx 传播取消；parent 在批次内不可变；calls 保留供应商顺序；round 是持久语义轮次；parallel 是调用方意图。
// Returns: one result per call in the same order, including explicit per-child errors.
// 返回：按照相同顺序为每个调用返回一个结果，并包含显式逐子执行错误。
func (s *Service) executeRouterToolCalls(ctx context.Context, parent Record, calls []routerToolCall, round uint32, parallel bool) []routerToolCallResult {
	return executeRouterToolCallBatch(calls, parallel, func(index int, call routerToolCall) routerToolCallResult {
		result := routerToolCallResult{}
		result.ModelResult, result.ChildExecutionID, result.Err = s.executeRouterToolCall(ctx, parent, call, round)
		return result
	})
}

// executeRouterToolCallBatch runs a bounded worker pool while preserving exact input order in the returned slice.
// executeRouterToolCallBatch 运行有界工作池，同时在返回切片中保留精确输入顺序。
// Parameters: calls are provider-ordered; parallel authorizes concurrent work; execute performs one indexed child call.
// 参数：calls 按供应商顺序排列；parallel 授权并发工作；execute 执行一个带索引的子调用。
// Returns: one positional result for every input call.
// 返回：为每个输入调用返回一个位置对应的结果。
func executeRouterToolCallBatch(calls []routerToolCall, parallel bool, execute func(int, routerToolCall) routerToolCallResult) []routerToolCallResult {
	results := make([]routerToolCallResult, len(calls))
	if !parallel || len(calls) < 2 {
		for index, call := range calls {
			results[index] = execute(index, call)
		}
		return results
	}
	workers := min(len(calls), maximumParallelRouterToolChildren)
	indices := make(chan int)
	var wait sync.WaitGroup
	wait.Add(workers)
	for range workers {
		go func() {
			defer wait.Done()
			for index := range indices {
				results[index] = execute(index, calls[index])
			}
		}()
	}
	for index := range calls {
		indices <- index
	}
	close(indices)
	wait.Wait()
	return results
}

// routerToolChildRequest builds one exact service or model execution from validated model arguments.
// routerToolChildRequest 根据已校验模型参数构建一个精确服务或模型执行。
func (s *Service) routerToolChildRequest(ctx context.Context, parent Record, call routerToolCall, round uint32) (vcp.ExecutionRequest, error) {
	resolved := call.Plan.RouterBinding
	binding := resolved.Binding
	toolID := call.Plan.ToolID()
	request := vcp.ExecutionRequest{
		ProtocolVersion: vcp.ProtocolVersion,
		RequestID:       routerChildIdentifier("request", parent.ID, call.Output.ToolCall.ToolCallID, round),
		IdempotencyKey:  routerChildIdentifier("idempotency", parent.ID, call.Output.ToolCall.ToolCallID, round),
		DispatchMode:    vcp.DispatchInline,
		Budget:          vcp.OperationBudget{MaxExecutionMilliseconds: &binding.TimeoutMilliseconds},
	}
	if call.Plan.Standard.Valid() {
		request.Target.Service = &vcp.ServiceSelection{ProviderInstanceID: binding.ProviderInstanceID, ProviderServiceID: binding.ProviderServiceID, ServiceOfferingID: binding.ServiceOfferingID, ExecutionProfileID: binding.ExecutionProfileID}
	} else {
		request.Target.Model = &vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: binding.ProviderInstanceID, ProviderModelID: binding.ProviderModelID, ExecutionProfileID: binding.ExecutionProfileID}
	}
	switch call.Plan.Standard {
	case vcp.StandardModelToolWebSearch:
		arguments := routerSearchArguments{}
		if errDecode := decodeRouterToolArguments(call.Output.ToolCall.Arguments, &arguments); errDecode != nil {
			return vcp.ExecutionRequest{}, errors.Join(vcp.NewModelToolError(vcp.RouterToolArgumentInvalid, toolID, "arguments", false), errDecode)
		}
		if strings.TrimSpace(arguments.Query) == "" {
			return vcp.ExecutionRequest{}, vcp.NewModelToolError(vcp.RouterToolArgumentInvalid, toolID, "arguments", false)
		}
		maxResults := binding.MaximumResults
		if arguments.MaxResults != nil {
			if *arguments.MaxResults <= 0 || *arguments.MaxResults > binding.MaximumResults {
				return vcp.ExecutionRequest{}, vcp.NewModelToolError(vcp.RouterToolArgumentInvalid, toolID, "arguments", false)
			}
			maxResults = *arguments.MaxResults
		}
		request.Operation = vcp.OperationSearchWeb
		request.Payload.SearchWeb = &vcp.WebSearchOperation{Query: arguments.Query, MaxResults: &maxResults, OutputMode: vcp.WebSearchOutputResultsAndAnswer, EvidenceRequirement: vcp.SearchEvidenceVerified}
	case vcp.StandardModelToolWebExtractor:
		arguments := routerExtractArguments{}
		if errDecode := decodeRouterToolArguments(call.Output.ToolCall.Arguments, &arguments); errDecode != nil {
			return vcp.ExecutionRequest{}, errors.Join(vcp.NewModelToolError(vcp.RouterToolArgumentInvalid, toolID, "arguments", false), errDecode)
		}
		if len(arguments.URLs) == 0 || len(arguments.URLs) > binding.MaximumURLs {
			return vcp.ExecutionRequest{}, vcp.NewModelToolError(vcp.RouterToolArgumentInvalid, toolID, "arguments", false)
		}
		for _, rawURL := range arguments.URLs {
			if errURL := validatePublicHTTPSURL(ctx, rawURL); errURL != nil {
				return vcp.ExecutionRequest{}, errors.Join(vcp.NewModelToolError(vcp.RouterToolArgumentInvalid, toolID, "arguments", false), errURL)
			}
		}
		request.Operation = vcp.OperationWebExtract
		request.Payload.WebExtract = &vcp.WebExtractOperation{URLs: append([]string(nil), arguments.URLs...), Query: arguments.Query, Depth: vcp.WebExtractDepthBasic, Format: vcp.WebExtractFormatMarkdown}
	}
	if call.Plan.Extension.Valid() {
		if errExtension := s.populateRouterExtensionRequest(ctx, parent, call, &request); errExtension != nil {
			return vcp.ExecutionRequest{}, errExtension
		}
	}
	if request.Operation == "" {
		return vcp.ExecutionRequest{}, vcp.NewModelToolError(vcp.ModelToolNotSupported, toolID, "planning", false)
	}
	if errValidate := request.Validate(); errValidate != nil {
		return vcp.ExecutionRequest{}, errors.Join(vcp.NewModelToolError(vcp.RouterToolArgumentInvalid, toolID, "arguments", false), errValidate)
	}
	return request, nil
}

// populateRouterExtensionRequest validates one extension call and installs its closed VCP payload.
// populateRouterExtensionRequest 校验一个增强调用并安装其封闭 VCP 载荷。
func (s *Service) populateRouterExtensionRequest(ctx context.Context, parent Record, call routerToolCall, request *vcp.ExecutionRequest) error {
	extension := call.Plan.Extension
	toolID := string(extension)
	switch extension {
	case vcp.RouterExtensionImageUnderstanding, vcp.RouterExtensionAudioUnderstanding, vcp.RouterExtensionVideoUnderstanding:
		arguments := routerUnderstandingArguments{}
		if errDecode := decodeRouterToolArguments(call.Output.ToolCall.Arguments, &arguments); errDecode != nil {
			return errors.Join(vcp.NewModelToolError(vcp.RouterToolArgumentInvalid, toolID, "arguments", false), errDecode)
		}
		media, errMedia := authorizedRouterMediaInput(parent, extension, arguments.ResourceRef)
		if errMedia != nil {
			return errors.Join(vcp.NewModelToolError(vcp.RouterToolArgumentInvalid, toolID, "arguments", false), errMedia)
		}
		request.Operation = vcp.OperationMediaAnalyze
		request.Payload.MediaAnalyze = &vcp.MediaAnalyzeOperation{Task: arguments.Task, Instruction: arguments.Instruction, Inputs: []vcp.MediaInput{media}}
		return s.attachRouterMediaInputPlan(ctx, parent, call, request, media)
	case vcp.RouterExtensionImageGeneration:
		arguments := routerImageGenerationArguments{}
		if errDecode := decodeRouterToolArguments(call.Output.ToolCall.Arguments, &arguments); errDecode != nil {
			return errors.Join(vcp.NewModelToolError(vcp.RouterToolArgumentInvalid, toolID, "arguments", false), errDecode)
		}
		request.Operation = vcp.OperationImageGenerate
		request.Payload.ImageGenerate = &vcp.ImageGenerateOperation{Prompt: arguments.Prompt, NegativePrompt: arguments.NegativePrompt, Count: arguments.Count, Width: arguments.Width, Height: arguments.Height, AspectRatio: arguments.AspectRatio}
	case vcp.RouterExtensionVideoGeneration:
		arguments := routerVideoGenerationArguments{}
		if errDecode := decodeRouterToolArguments(call.Output.ToolCall.Arguments, &arguments); errDecode != nil {
			return errors.Join(vcp.NewModelToolError(vcp.RouterToolArgumentInvalid, toolID, "arguments", false), errDecode)
		}
		request.Operation = vcp.OperationVideoGenerate
		request.Payload.VideoGenerate = &vcp.VideoGenerateOperation{Prompt: arguments.Prompt, NegativePrompt: arguments.NegativePrompt, DurationSeconds: arguments.DurationSeconds, AspectRatio: arguments.AspectRatio, Resolution: arguments.Resolution}
	case vcp.RouterExtensionSpeechGeneration:
		arguments := routerSpeechGenerationArguments{}
		if errDecode := decodeRouterToolArguments(call.Output.ToolCall.Arguments, &arguments); errDecode != nil {
			return errors.Join(vcp.NewModelToolError(vcp.RouterToolArgumentInvalid, toolID, "arguments", false), errDecode)
		}
		request.Operation = vcp.OperationSpeechSynthesize
		request.Payload.SpeechSynthesize = &vcp.SpeechSynthesizeOperation{Text: arguments.Text, VoiceID: arguments.VoiceID, OutputFormat: arguments.OutputFormat}
	case vcp.RouterExtensionSpeechTranscription:
		arguments := routerSpeechTranscriptionArguments{}
		if errDecode := decodeRouterToolArguments(call.Output.ToolCall.Arguments, &arguments); errDecode != nil {
			return errors.Join(vcp.NewModelToolError(vcp.RouterToolArgumentInvalid, toolID, "arguments", false), errDecode)
		}
		media, errMedia := authorizedRouterMediaInput(parent, extension, arguments.ResourceRef)
		if errMedia != nil {
			return errors.Join(vcp.NewModelToolError(vcp.RouterToolArgumentInvalid, toolID, "arguments", false), errMedia)
		}
		request.Operation = vcp.OperationSpeechTranscribe
		request.Payload.SpeechTranscribe = &vcp.SpeechTranscribeOperation{Source: media, Language: arguments.Language, Prompt: arguments.Prompt}
		return s.attachRouterMediaInputPlan(ctx, parent, call, request, media)
	default:
		return vcp.NewModelToolError(vcp.ModelToolNotSupported, toolID, "planning", false)
	}
	return nil
}

// authorizedRouterMediaInput binds one extension call to one exact media block already accepted in the parent conversation.
// authorizedRouterMediaInput 将一个增强调用绑定到父会话中已接受的一个精确媒体块。
func authorizedRouterMediaInput(parent Record, extension vcp.RouterExtensionKind, resourceRef string) (vcp.MediaInput, error) {
	if parent.Request.Payload.Conversation == nil || strings.TrimSpace(resourceRef) == "" {
		return vcp.MediaInput{}, fmt.Errorf("%w: parent media reference is unavailable", vcp.ErrInvalidRequest)
	}
	var (
		matchedKind vcp.MediaKind
		matches     int
	)
	for _, item := range parent.Request.Payload.Conversation.Context {
		for _, block := range item.Content {
			if block.ResourceRef != resourceRef {
				continue
			}
			kind, media := mediaKindForContentType(block.Type)
			if !media {
				continue
			}
			// Reusing one immutable resource in multiple message items is valid, but changing its media family is not.
			// 在多个消息项中复用同一个不可变资源是合法的，但改变其媒体类别并不合法。
			if matches > 0 && matchedKind != kind {
				return vcp.MediaInput{}, fmt.Errorf("%w: resource_ref has conflicting parent media kinds", vcp.ErrInvalidRequest)
			}
			matchedKind = kind
			matches++
		}
	}
	if matches == 0 || !extensionAcceptsMediaKind(extension, matchedKind) {
		return vcp.MediaInput{}, fmt.Errorf("%w: resource_ref must identify authorized parent media", vcp.ErrInvalidRequest)
	}
	role := vcp.MediaRoleUnderstanding
	if extension == vcp.RouterExtensionSpeechTranscription {
		role = vcp.MediaRoleTranscriptionSource
	}
	return vcp.MediaInput{ID: "router_media", Kind: matchedKind, Role: role, Resource: vcp.ResourceReference{ResourceID: resourceRef}}, nil
}

// extensionAcceptsMediaKind verifies the closed media family owned by one Router extension.
// extensionAcceptsMediaKind 校验一个 Router 增强能力拥有的封闭媒体类别。
func extensionAcceptsMediaKind(extension vcp.RouterExtensionKind, kind vcp.MediaKind) bool {
	switch extension {
	case vcp.RouterExtensionImageUnderstanding:
		return kind == vcp.MediaImage
	case vcp.RouterExtensionAudioUnderstanding:
		return kind == vcp.MediaAudio
	case vcp.RouterExtensionVideoUnderstanding:
		return kind == vcp.MediaVideo
	case vcp.RouterExtensionSpeechTranscription:
		return kind == vcp.MediaAudio || kind == vcp.MediaVideo
	default:
		return false
	}
}

// attachRouterMediaInputPlan creates and binds one immutable input plan for a media child execution.
// attachRouterMediaInputPlan 为媒体子执行创建并绑定一个不可变输入方案。
func (s *Service) attachRouterMediaInputPlan(ctx context.Context, parent Record, call routerToolCall, request *vcp.ExecutionRequest, media vcp.MediaInput) error {
	creator, supported := s.plans.(InputPlanCreator)
	if !supported {
		return vcp.NewModelToolError(vcp.ModelToolDependencyMissing, call.Plan.ToolID(), "planning", false)
	}
	binding := call.Plan.RouterBinding.Binding
	plan, errPlan := creator.CreateInputPlan(ctx, inputplan.Request{
		OwnerAPIKeyID: parent.OwnerAPIKeyID,
		Model:         *request.Target.Model,
		Operation:     request.Operation,
		Inputs:        []inputplan.Input{{InputID: media.ID, ResourceID: media.Resource.ResourceID, Role: media.Role}},
	})
	if errPlan != nil {
		return errors.Join(vcp.NewModelToolError(vcp.RouterToolExecutionFailed, call.Plan.ToolID(), "planning", false), errPlan)
	}
	if !plan.Accepted {
		return errors.Join(vcp.NewModelToolError(vcp.RouterToolArgumentInvalid, call.Plan.ToolID(), "planning", false), errors.New(plan.ErrorCode))
	}
	target := call.Plan.RouterBinding.Target
	if plan.Target.ProviderInstanceID != target.ProviderInstanceID ||
		plan.Target.ProviderModelID != target.ProviderModelID ||
		plan.Target.OfferingID != target.OfferingID ||
		plan.Target.ExecutionProfileID != target.ExecutionProfileID ||
		plan.Target.EndpointID != target.EndpointID ||
		plan.Target.CredentialID != target.CredentialID ||
		plan.Target.ActionBindingID != target.ActionBindingID ||
		plan.Target.Operation != target.Operation ||
		plan.Target.CapabilityRevision != target.CapabilityRevision ||
		plan.Target.CatalogRevision != target.CatalogRevision {
		return vcp.NewModelToolError(vcp.RouterToolBindingUnavailable, call.Plan.ToolID(), "planning", false)
	}
	if binding.ProviderModelID != plan.Target.ProviderModelID || binding.ExecutionProfileID != plan.Target.ExecutionProfileID {
		return vcp.NewModelToolError(vcp.RouterToolBindingUnavailable, call.Plan.ToolID(), "planning", false)
	}
	request.InputPlanID = plan.ID
	return nil
}

// decodeRouterToolArguments decodes one strict object and rejects unknown or trailing input.
// decodeRouterToolArguments 解码一个严格对象并拒绝未知或尾随输入。
func decodeRouterToolArguments(arguments string, destination any) error {
	decoder := json.NewDecoder(strings.NewReader(arguments))
	decoder.DisallowUnknownFields()
	if errDecode := decoder.Decode(destination); errDecode != nil {
		return fmt.Errorf("%w: invalid Router tool arguments", vcp.ErrInvalidRequest)
	}
	var trailing any
	if errTrailing := decoder.Decode(&trailing); errTrailing != io.EOF {
		return fmt.Errorf("%w: Router tool arguments contain trailing values", vcp.ErrInvalidRequest)
	}
	return nil
}

// validatePublicHTTPSURL enforces the binding's public-HTTPS-only policy for provider-side extraction.
// validatePublicHTTPSURL 为供应商侧抓取强制执行绑定的仅公网 HTTPS 策略。
func validatePublicHTTPSURL(ctx context.Context, rawURL string) error {
	parsed, errParse := url.ParseRequestURI(rawURL)
	if errParse != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil {
		return fmt.Errorf("%w: Router extraction requires a public HTTPS URL", vcp.ErrInvalidRequest)
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") {
		return fmt.Errorf("%w: Router extraction rejects local hosts", vcp.ErrInvalidRequest)
	}
	if address := net.ParseIP(host); address != nil && (address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsUnspecified()) {
		return fmt.Errorf("%w: Router extraction rejects non-public IP addresses", vcp.ErrInvalidRequest)
	}
	if net.ParseIP(host) == nil {
		addresses, errResolve := net.DefaultResolver.LookupIPAddr(ctx, host)
		if errResolve != nil || len(addresses) == 0 {
			return fmt.Errorf("%w: Router extraction host could not be resolved safely", vcp.ErrInvalidRequest)
		}
		for _, resolved := range addresses {
			address := resolved.IP
			if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsUnspecified() {
				return fmt.Errorf("%w: Router extraction host resolves to a non-public address", vcp.ErrInvalidRequest)
			}
		}
	}
	return nil
}

// routerSearchModelResult is the minimal cross-provider search result visible to the parent model.
// routerSearchModelResult 是父模型可见的最小跨供应商搜索结果。
type routerSearchModelResult struct {
	// ExternalContentUntrusted prevents search text from being interpreted as privileged instructions.
	// ExternalContentUntrusted 防止搜索文本被解释为高权限指令。
	ExternalContentUntrusted bool `json:"external_content_untrusted"`
	// Query identifies the provider-executed query.
	// Query 标识供应商执行的查询。
	Query string `json:"query"`
	// Evidence describes observed search execution without provider support identifiers.
	// Evidence 描述已观察到的搜索执行且不包含供应商支持标识。
	Evidence vcp.SearchExecutionEvidence `json:"evidence"`
	// Results contains normalized ordered search results.
	// Results 包含规范化且有序的搜索结果。
	Results []vcp.WebSearchResult `json:"results,omitempty"`
	// Answer contains an optional provider-generated answer.
	// Answer 包含可选的供应商生成答案。
	Answer string `json:"answer,omitempty"`
	// Citations contains normalized provider-returned citations.
	// Citations 包含规范化的供应商返回引用。
	Citations []vcp.Citation `json:"citations,omitempty"`
	// Sources contains normalized consulted-source facts.
	// Sources 包含规范化的已咨询来源事实。
	Sources []vcp.SearchSource `json:"sources,omitempty"`
}

// routerExtractModelResult is the minimal cross-provider extraction result visible to the parent model.
// routerExtractModelResult 是父模型可见的最小跨供应商提取结果。
type routerExtractModelResult struct {
	// ExternalContentUntrusted prevents extracted page text from being interpreted as privileged instructions.
	// ExternalContentUntrusted 防止提取的页面文本被解释为高权限指令。
	ExternalContentUntrusted bool `json:"external_content_untrusted"`
	// Results contains normalized successful page extractions.
	// Results 包含规范化的成功页面提取结果。
	Results []vcp.WebExtractResult `json:"results"`
	// FailedResults contains normalized per-URL failures.
	// FailedResults 包含规范化的逐 URL 失败。
	FailedResults []vcp.WebExtractFailure `json:"failed_results,omitempty"`
}

// routerAnalysisModelResult is the minimal untrusted media-analysis content visible to the parent model.
// routerAnalysisModelResult 是父模型可见的最小不可信媒体分析内容。
type routerAnalysisModelResult struct {
	// ExternalContentUntrusted prevents analyzed media text from becoming privileged instructions.
	// ExternalContentUntrusted 防止已分析媒体文本成为高权限指令。
	ExternalContentUntrusted bool `json:"external_content_untrusted"`
	// Content contains only provider-returned semantic content without child response metadata.
	// Content 仅包含供应商返回的语义内容且不含子响应元数据。
	Content []vcp.ContentBlock `json:"content"`
	// Citations preserves provider-returned citations when present.
	// Citations 在存在时保留供应商返回的引用。
	Citations []vcp.Citation `json:"citations,omitempty"`
}

// routerGeneratedResourceResult exposes only the Router reference and facts needed to consume generated content.
// routerGeneratedResourceResult 仅公开消费生成内容所需的 Router 引用与事实。
type routerGeneratedResourceResult struct {
	// ResourceRef is the opaque Router-owned resource identifier.
	// ResourceRef 是由 Router 所有的不透明资源标识。
	ResourceRef string `json:"resource_ref"`
	// Kind identifies the generated media family.
	// Kind 标识生成媒体类别。
	Kind vcp.MediaKind `json:"kind"`
	// MIMEType is the inspected generated media type.
	// MIMEType 是经过检查的生成媒体类型。
	MIMEType string `json:"mime_type"`
	// SizeBytes is the exact generated object size.
	// SizeBytes 是生成对象的精确字节数。
	SizeBytes int64 `json:"size_bytes"`
}

// routerTranscriptionModelResult marks provider-returned speech text as untrusted media-derived content.
// routerTranscriptionModelResult 将供应商返回的语音文本标记为不可信媒体派生内容。
type routerTranscriptionModelResult struct {
	// ExternalContentUntrusted prevents transcribed speech from becoming privileged instructions.
	// ExternalContentUntrusted 防止转写语音成为高权限指令。
	ExternalContentUntrusted bool `json:"external_content_untrusted"`
	// Transcript contains one complete recognition result when the child operation is singular.
	// Transcript 在子操作为单项时包含一个完整识别结果。
	Transcript *vcp.Transcript `json:"transcript,omitempty"`
	// Transcriptions contains resource-owned batch recognition results.
	// Transcriptions 包含资源归属的批量识别结果。
	Transcriptions []vcp.TranscriptionResult `json:"transcriptions,omitempty"`
}

// serializeRouterToolResult returns a least-privilege typed child response within the frozen byte ceiling.
// serializeRouterToolResult 在冻结字节上限内返回最小权限的类型化子响应。
func serializeRouterToolResult(plan routerToolCallPlan, result Result, maximumBytes int64) (string, error) {
	var value any
	switch plan.Standard {
	case vcp.StandardModelToolWebSearch:
		if result.Search == nil {
			return "", fmt.Errorf("%w: Router search child returned no search result", ErrInvalidProviderResult)
		}
		value = routerSearchModelResult{
			ExternalContentUntrusted: true,
			Query:                    result.Search.Query,
			Evidence:                 result.Search.Evidence,
			Results:                  result.Search.Results,
			Answer:                   result.Search.Answer,
			Citations:                result.Search.Citations,
			Sources:                  result.Search.Sources,
		}
	case vcp.StandardModelToolWebExtractor:
		if result.Extract == nil {
			return "", fmt.Errorf("%w: Router extraction child returned no extraction result", ErrInvalidProviderResult)
		}
		value = routerExtractModelResult{
			ExternalContentUntrusted: true,
			Results:                  result.Extract.Results,
			FailedResults:            result.Extract.FailedResults,
		}
	}
	switch plan.Extension {
	case vcp.RouterExtensionImageUnderstanding, vcp.RouterExtensionAudioUnderstanding, vcp.RouterExtensionVideoUnderstanding:
		if result.Analysis == nil {
			return "", fmt.Errorf("%w: Router media-analysis child returned no analysis", ErrInvalidProviderResult)
		}
		content := make([]vcp.ContentBlock, 0)
		for _, item := range result.Analysis.Items {
			for _, block := range item.Content {
				if block.Type == vcp.ContentText {
					content = append(content, block)
				}
			}
		}
		if len(content) == 0 {
			return "", fmt.Errorf("%w: Router media-analysis child returned no text content", ErrInvalidProviderResult)
		}
		value = routerAnalysisModelResult{ExternalContentUntrusted: true, Content: content, Citations: result.Analysis.Citations}
	case vcp.RouterExtensionImageGeneration, vcp.RouterExtensionVideoGeneration, vcp.RouterExtensionSpeechGeneration:
		if len(result.Resources) == 0 {
			return "", fmt.Errorf("%w: Router generation child returned no resources", ErrInvalidProviderResult)
		}
		resources := make([]routerGeneratedResourceResult, 0, len(result.Resources))
		for _, generated := range result.Resources {
			resources = append(resources, routerGeneratedResourceResult{ResourceRef: generated.ID, Kind: generated.Kind, MIMEType: generated.MIMEType, SizeBytes: generated.SizeBytes})
		}
		value = resources
	case vcp.RouterExtensionSpeechTranscription:
		if result.Transcript != nil {
			value = routerTranscriptionModelResult{ExternalContentUntrusted: true, Transcript: result.Transcript}
		} else if len(result.Transcriptions) != 0 {
			value = routerTranscriptionModelResult{ExternalContentUntrusted: true, Transcriptions: result.Transcriptions}
		} else {
			return "", fmt.Errorf("%w: Router transcription child returned no transcript", ErrInvalidProviderResult)
		}
	}
	if value == nil {
		return "", fmt.Errorf("%w: unsupported Router tool result", ErrInvalidProviderResult)
	}
	serialized, errMarshal := json.Marshal(value)
	if errMarshal != nil {
		return "", fmt.Errorf("marshal Router tool result: %w", errMarshal)
	}
	if int64(len(serialized)) > maximumBytes {
		return "", fmt.Errorf("%w: Router tool result exceeds binding byte limit", ErrInvalidProviderResult)
	}
	return string(serialized), nil
}

// appendRouterToolResult records the assistant call and tool result in canonical model context.
// appendRouterToolResult 将助手调用与工具结果记录到规范模型上下文。
func appendRouterToolResult(record *Record, call routerToolCall, result string, childExecutionID string, round uint32) error {
	if record == nil || record.Request.Payload.Conversation == nil {
		return fmt.Errorf("%w: Router tool parent conversation is unavailable", ErrInvalidExecution)
	}
	conversation := *record.Request.Payload.Conversation
	conversation.Context = append([]vcp.ContextItem(nil), conversation.Context...)
	sequence := uint64(1)
	for _, item := range conversation.Context {
		if item.Sequence >= sequence {
			sequence = item.Sequence + 1
		}
	}
	callID := call.Output.ToolCall.ToolCallID
	callItemID := routerChildIdentifier("call_item", record.ID, callID, round)
	resultItemID := routerChildIdentifier("result_item", record.ID, callID, round)
	conversation.Context = append(conversation.Context,
		vcp.ContextItem{ItemID: callItemID, Sequence: sequence, Kind: vcp.ContextToolCall, Authority: vcp.AuthorityAssistant, Actor: vcp.ActorPrimaryAssistant, Placement: vcp.PlacementTranscript, Activation: vcp.Activation{Mode: vcp.ActivationRequestStart}, Visibility: vcp.VisibilityModel, DelegationID: childExecutionID, ToolCall: &vcp.ToolCallItem{ToolCallID: callID, UpstreamID: call.Output.ToolCall.UpstreamID, SynthesizedID: call.Output.ToolCall.SynthesizedID, Namespace: routerToolNamespace, Name: call.Output.ToolCall.Name, Arguments: call.Output.ToolCall.Arguments, Status: vcp.ToolCallCompleted}},
		vcp.ContextItem{ItemID: resultItemID, Sequence: sequence + 1, Kind: vcp.ContextToolResult, Authority: vcp.AuthorityTool, Actor: vcp.ActorTool, Placement: vcp.PlacementTranscript, Activation: vcp.Activation{Mode: vcp.ActivationRequestStart}, Visibility: vcp.VisibilityModel, ParentItemID: callItemID, DelegationID: childExecutionID, Content: []vcp.ContentBlock{{Type: vcp.ContentText, Text: result}}, ToolResult: &vcp.ToolResultItem{ToolCallID: callID}},
	)
	if conversation.ToolPolicy.Choice == vcp.ToolChoiceRequired || conversation.ToolPolicy.Choice == vcp.ToolChoiceNamed {
		conversation.ToolPolicy.Choice = vcp.ToolChoiceAuto
		conversation.ToolPolicy.NamedTool = ""
	}
	candidate := record.Request
	candidate.Payload.Conversation = &conversation
	if errValidate := candidate.Validate(); errValidate != nil {
		return errValidate
	}
	record.Request = candidate
	return nil
}

// persistRouterToolRound durably freezes parent context, completed attempts, and safe tool events before the next model dispatch.
// persistRouterToolRound 在下一次模型分派前持久冻结父上下文、已完成尝试和安全工具事件。
func (s *Service) persistRouterToolRound(ctx context.Context, record *Record, payloads []ModelToolEvent) error {
	previousRevision := record.Revision
	previousRound := record.CompletedRouterToolRounds
	previousUpdatedAt := record.UpdatedAt
	sequence, errSequence := s.nextEventSequence(ctx, *record)
	if errSequence != nil {
		return errSequence
	}
	record.CompletedRouterToolRounds++
	record.Revision++
	record.UpdatedAt = s.options.Now().UTC()
	events := make([]Event, 0, len(payloads))
	for index := range payloads {
		payload := payloads[index]
		event := Event{ExecutionID: record.ID, EventID: fmt.Sprintf("evt_%s_%d", record.ID[4:], sequence), Sequence: sequence, Time: record.UpdatedAt, Type: EventModelToolLifecycle, ModelTool: &payload}
		if errValidate := event.Validate(); errValidate != nil {
			record.CompletedRouterToolRounds = previousRound
			record.Revision = previousRevision
			record.UpdatedAt = previousUpdatedAt
			return errValidate
		}
		events = append(events, event)
		sequence++
	}
	if errSave := s.store.Save(ctx, *record, previousRevision, events); errSave != nil {
		record.CompletedRouterToolRounds = previousRound
		record.Revision = previousRevision
		record.UpdatedAt = previousUpdatedAt
		return errSave
	}
	return nil
}

// routerChildIdentifier derives a bounded opaque identifier without retaining model-authored call text.
// routerChildIdentifier 派生一个有界不透明标识且不保留模型编写的调用文本。
func routerChildIdentifier(prefix string, executionID string, toolCallID string, round uint32) string {
	digest := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%d", executionID, toolCallID, round)))
	return prefix + "_" + hex.EncodeToString(digest[:16])
}

// hasReservedRouterToolCollision rejects caller declarations that impersonate Router-managed tools.
// hasReservedRouterToolCollision 拒绝冒充 Router 管理工具的调用方声明。
func hasReservedRouterToolCollision(tools []vcp.ToolDefinition) bool {
	for _, tool := range tools {
		if reservedRouterToolName(tool.Name) || tool.Namespace == routerToolNamespace {
			return true
		}
	}
	return false
}

// hasReservedRouterContextCollision rejects caller-authored history that impersonates Router-owned authority.
// hasReservedRouterContextCollision 拒绝冒充 Router 所有权限的调用方历史。
func hasReservedRouterContextCollision(items []vcp.ContextItem) bool {
	for _, item := range items {
		if item.Kind == vcp.ContextToolCall && item.ToolCall != nil && (reservedRouterToolName(item.ToolCall.Name) || item.ToolCall.Namespace == routerToolNamespace) {
			return true
		}
	}
	return false
}

// reservedRouterToolName reports every provider-visible function name owned exclusively by the Router.
// reservedRouterToolName 报告每个由 Router 独占的供应商可见函数名称。
func reservedRouterToolName(name string) bool {
	switch name {
	case routerWebSearchName,
		routerWebExtractorName,
		routerImageUnderstandingName,
		routerAudioUnderstandingName,
		routerVideoUnderstandingName,
		routerImageGenerationName,
		routerVideoGenerationName,
		routerSpeechGenerationName,
		routerSpeechTranscriptionName:
		return true
	default:
		return false
	}
}
