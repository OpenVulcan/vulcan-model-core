// Portions of this xAI request projection are adapted from CLIProxyAPI commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// 本 xAI 请求投影的部分逻辑改编自 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66。
// Source path: internal/runtime/executor/xai_executor.go.
// 来源路径：internal/runtime/executor/xai_executor.go。
// The adapted scope is xAI tool, search, reasoning, and compaction compatibility without a CLIProxyAPI dependency.
// 改编范围为 xAI 工具、搜索、推理和压缩兼容性，不引入 CLIProxyAPI 依赖。
package responses

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	openairesponses "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/responses"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

const (
	// xaiFunctionType is the xAI Responses wire type for every client-callable tool after custom normalization.
	// xaiFunctionType 是 custom 归一化后每个客户端可调用工具使用的 xAI Responses wire 类型。
	xaiFunctionType = "function"
	// xaiCustomType is the OpenAI-compatible custom wire type before xAI normalization.
	// xaiCustomType 是 xAI 归一化前的 OpenAI 兼容 custom wire 类型。
	xaiCustomType = "custom"
	// xaiXSearchType is the xAI provider-hosted search wire type.
	// xaiXSearchType 是 xAI 供应商托管搜索 wire 类型。
	xaiXSearchType = "x_search"
	// xaiWebSearchType is the shared Responses web-search wire type before xAI normalization.
	// xaiWebSearchType 是 xAI 归一化前的共享 Responses 网页搜索 wire 类型。
	xaiWebSearchType = "web_search"
)

var (
	// xaiDefaultFunctionParameters is the minimal object schema evidenced by the xAI compatibility source for converted custom tools.
	// xaiDefaultFunctionParameters 是 xAI 兼容来源为已转换 custom 工具证实的最小对象 Schema。
	xaiDefaultFunctionParameters = json.RawMessage(`{"type":"object","properties":{}}`)
)

// ProjectRequest converts one canonical VCP request into the xAI typed wire request and immutable audit artifacts.
// ProjectRequest 将一条规范 VCP 请求转换为 xAI 类型化 wire 请求与不可变审计产物。
func ProjectRequest(request vcp.VulcanRequest, target resolve.Target, capabilities ProfileCapabilities, lineageID string, previousResponseID string, now time.Time) (ProjectedRequest, error) {
	if request.ReasoningPolicy.Effort != "" && !capabilities.ReasoningEffort {
		return ProjectedRequest{}, fmt.Errorf("%w: selected target does not verify reasoning.effort", ErrUnsupportedContext)
	}
	if request.RemoteCompaction != nil && !capabilities.NativeRemoteCompaction {
		return ProjectedRequest{}, fmt.Errorf("%w: selected target does not verify remote compaction", vcp.ErrCapabilityUnavailable)
	}
	normalized, references, referencesByCanonical, errNormalize := normalizeRequestForXAI(request)
	if errNormalize != nil {
		return ProjectedRequest{}, errNormalize
	}
	// normalized RemoteCompaction is reconciled below because the shared profile has no xAI compact capability fact.
	// normalized RemoteCompaction 会在下方重新协调，因为共享 Profile 没有 xAI compact 能力事实。
	normalized.RemoteCompaction = nil
	baseProjected, errProject := openairesponses.ProjectRequest(normalized, target, capabilities.baseCapabilities(), lineageID, previousResponseID, now)
	if errProject != nil {
		return ProjectedRequest{}, fmt.Errorf("%w: %v", ErrUnsupportedContext, errProject)
	}
	upstream := Request(baseProjected.Upstream)
	transformations, errTransform := normalizeXAIWireRequest(&upstream)
	if errTransform != nil {
		return ProjectedRequest{}, errTransform
	}
	reconcileRemoteCompaction(&baseProjected.CapabilityPlan, &baseProjected.Report, request, capabilities)
	adaptProjectionForXAI(&baseProjected, request, referencesByCanonical, upstream, transformations.inputPositions)
	appendRequestTransformationSummary(&baseProjected.Report, transformations, references)
	return ProjectedRequest{
		Upstream: upstream, CapabilityPlan: baseProjected.CapabilityPlan, ProjectionPlan: baseProjected.ProjectionPlan,
		Ledger: baseProjected.Ledger, Report: baseProjected.Report,
		StreamOptions: StreamOptions{ToolReferences: append([]ToolReference(nil), references...), FilterInternalXSearch: requestUsesNativeXSearch(upstream)},
	}, nil
}

// ProjectCompactRequest projects one explicit VCP remote-compaction operation to xAI /responses/compact without fabricating local compaction output.
// ProjectCompactRequest 将一个显式 VCP 远程压缩操作投影到 xAI /responses/compact，而不伪造本地压缩输出。
func ProjectCompactRequest(request vcp.VulcanRequest, target resolve.Target, capabilities ProfileCapabilities, lineageID string, previousResponseID string, now time.Time) (ProjectedRequest, error) {
	if request.RemoteCompaction == nil {
		return ProjectedRequest{}, fmt.Errorf("%w: remote compaction request is required", ErrUnsupportedContext)
	}
	if !capabilities.NativeRemoteCompaction {
		return ProjectedRequest{}, fmt.Errorf("%w: selected target does not verify remote compaction", vcp.ErrCapabilityUnavailable)
	}
	if request.RemoteCompaction.PreviousResponseID != "" && previousResponseID == "" {
		return ProjectedRequest{}, fmt.Errorf("%w: Router-resolved previous_response_id is required for remote compaction", ErrUnsupportedContext)
	}
	compactRequest := request
	compactRequest.RemoteCompaction = nil
	compactRequest.ContextManagementPolicy = vcp.ContextManagementPolicy{Mode: vcp.ContextManagementRegular}
	compactRequest.Stream = false
	if len(request.RemoteCompaction.Context) > 0 {
		compactRequest.Context = append([]vcp.ContextItem(nil), request.RemoteCompaction.Context...)
	} else {
		compactRequest.Context = nil
	}
	projected, errProject := ProjectRequest(compactRequest, target, capabilities, lineageID, previousResponseID, now)
	if errProject != nil {
		return ProjectedRequest{}, errProject
	}
	projected.Upstream.Stream = false
	projected.Upstream.Tools = nil
	projected.Upstream.ToolChoice = nil
	projected.Upstream.ParallelToolCalls = nil
	if previousResponseID != "" {
		projected.Upstream.PreviousResponseID = previousResponseID
	}
	reconcileRemoteCompaction(&projected.CapabilityPlan, &projected.Report, request, capabilities)
	projected.Report.ConversionSummary = appendUniqueString(projected.Report.ConversionSummary, "xai_responses.remote_compaction.native")
	return projected, nil
}

// normalizeRequestForXAI creates a copy whose namespace-bearing tool identities are flattened before shared projection.
// normalizeRequestForXAI 创建一个副本，在共享投影前将带命名空间的工具身份扁平化。
func normalizeRequestForXAI(request vcp.VulcanRequest) (vcp.VulcanRequest, []ToolReference, map[string]ToolReference, error) {
	normalized := request
	normalized.Tools = append([]vcp.ToolDefinition(nil), request.Tools...)
	normalized.Context = append([]vcp.ContextItem(nil), request.Context...)
	// referencesByCanonical maps exact VCP namespace/name identity to one reversible xAI wire identity.
	// referencesByCanonical 将精确 VCP 命名空间/名称身份映射到一个可逆 xAI wire 身份。
	referencesByCanonical := make(map[string]ToolReference, len(request.Tools))
	// referencesByWire rejects collisions after namespace qualification before an upstream request is built.
	// referencesByWire 在构建上游请求前拒绝命名空间限定后的冲突。
	referencesByWire := make(map[string]ToolReference, len(request.Tools))
	references := make([]ToolReference, 0, len(request.Tools))
	for index := range request.Tools {
		tool := request.Tools[index]
		if tool.Kind == vcp.ToolNativeWebSearch {
			continue
		}
		if tool.Kind != vcp.ToolFunction && tool.Kind != vcp.ToolCustom {
			return vcp.VulcanRequest{}, nil, nil, fmt.Errorf("%w: unsupported tool kind %q", ErrUnsupportedContext, tool.Kind)
		}
		if tool.Kind == vcp.ToolCustom && tool.Name == "apply_patch" {
			return vcp.VulcanRequest{}, nil, nil, fmt.Errorf("%w: custom tool apply_patch is not supported by xAI", ErrUnsupportedContext)
		}
		wireName, errName := qualifyToolName(tool.Namespace, tool.Name)
		if errName != nil {
			return vcp.VulcanRequest{}, nil, nil, errName
		}
		canonicalKey := toolIdentity(tool.Namespace, tool.Name)
		if _, exists := referencesByCanonical[canonicalKey]; exists {
			return vcp.VulcanRequest{}, nil, nil, fmt.Errorf("%w: duplicate tool identity %q", ErrUnsupportedContext, canonicalKey)
		}
		reference := ToolReference{WireName: wireName, Namespace: tool.Namespace, Name: tool.Name, Kind: tool.Kind}
		if existing, exists := referencesByWire[wireName]; exists {
			return vcp.VulcanRequest{}, nil, nil, fmt.Errorf("%w: xAI wire tool name %q conflicts with %q", ErrUnsupportedContext, wireName, toolIdentity(existing.Namespace, existing.Name))
		}
		referencesByCanonical[canonicalKey] = reference
		referencesByWire[wireName] = reference
		references = append(references, reference)
		normalized.Tools[index].Name = wireName
		normalized.Tools[index].Namespace = ""
	}
	for index := range normalized.Context {
		// Local-only context is omitted before projection and must not require an xAI tool declaration.
		// 仅本地上下文会在投影前省略，因此不得要求其拥有 xAI 工具声明。
		if normalized.Context[index].Visibility != vcp.VisibilityModel {
			continue
		}
		if normalized.Context[index].ToolCall == nil {
			continue
		}
		toolCall := *normalized.Context[index].ToolCall
		reference, exists := referencesByCanonical[toolIdentity(toolCall.Namespace, toolCall.Name)]
		if !exists {
			return vcp.VulcanRequest{}, nil, nil, fmt.Errorf("%w: tool call %q has no declared xAI tool", ErrUnsupportedContext, toolCall.ToolCallID)
		}
		toolCall.Name = reference.WireName
		toolCall.Namespace = ""
		normalized.Context[index].ToolCall = &toolCall
	}
	if normalized.ToolPolicy.Choice == vcp.ToolChoiceNamed {
		matchedReference, matchCount := namedToolReference(request.Tools, request.ToolPolicy.NamedTool, referencesByCanonical)
		if matchCount == 1 {
			normalized.ToolPolicy.NamedTool = matchedReference.WireName
		}
	}
	return normalized, references, referencesByCanonical, nil
}

// namedToolReference resolves a VCP named tool only when the original short name has one exact declaration.
// namedToolReference 仅在原始短名称只有一个精确声明时解析 VCP 指定工具。
func namedToolReference(tools []vcp.ToolDefinition, namedTool string, referencesByCanonical map[string]ToolReference) (ToolReference, int) {
	matched := ToolReference{}
	count := 0
	for _, tool := range tools {
		if tool.Name != namedTool {
			continue
		}
		reference, exists := referencesByCanonical[toolIdentity(tool.Namespace, tool.Name)]
		if !exists {
			continue
		}
		matched = reference
		count++
	}
	return matched, count
}

// qualifyToolName applies the xAI evidenced namespace prefix rule without interpreting unknown aliases.
// qualifyToolName 应用已证实的 xAI 命名空间前缀规则，且不解释未知别名。
func qualifyToolName(namespace string, name string) (string, error) {
	trimmedNamespace := strings.TrimSpace(namespace)
	trimmedName := strings.TrimSpace(name)
	if trimmedName == "" {
		return "", fmt.Errorf("%w: tool name is required", ErrUnsupportedContext)
	}
	if trimmedNamespace == "" || strings.HasPrefix(trimmedName, "mcp__") {
		return trimmedName, nil
	}
	prefix := trimmedNamespace
	if !strings.HasSuffix(prefix, "__") {
		prefix += "__"
	}
	if strings.HasPrefix(trimmedName, prefix) {
		return trimmedName, nil
	}
	return prefix + trimmedName, nil
}

// toolIdentity creates a collision-free local identity for a VCP tool declaration.
// toolIdentity 为 VCP 工具声明创建一个无冲突的本地身份。
func toolIdentity(namespace string, name string) string {
	return namespace + "\x00" + name
}

// wireTransformations records xAI wire compatibility transformations for client-safe reporting.
// wireTransformations 记录用于客户端安全报告的 xAI wire 兼容转换。
type wireTransformations struct {
	// customToolsAsFunctions reports converted custom declarations or history items.
	// customToolsAsFunctions 表示已转换的 custom 声明或历史项目。
	customToolsAsFunctions bool
	// nativeXSearch reports converted native web-search declarations.
	// nativeXSearch 表示已转换的原生网页搜索声明。
	nativeXSearch bool
	// simplifiedSchema reports one source-evidenced incompatible function schema simplification.
	// simplifiedSchema 表示一次来源证实的不兼容 function Schema 简化。
	simplifiedSchema bool
	// mergedReasoningSummaries reports source-evidenced coalescing of adjacent pure reasoning summaries.
	// mergedReasoningSummaries 表示来源证实的相邻纯推理摘要合并。
	mergedReasoningSummaries bool
	// inputPositions maps each pre-normalization input position to its final typed wire position.
	// inputPositions 将每个归一化前输入位置映射到最终类型化 wire 位置。
	inputPositions []int
}

// normalizeXAIWireRequest applies typed xAI compatibility transformations after shared canonical projection.
// normalizeXAIWireRequest 在共享规范投影后应用类型化 xAI 兼容转换。
func normalizeXAIWireRequest(upstream *Request) (wireTransformations, error) {
	if upstream == nil {
		return wireTransformations{}, fmt.Errorf("%w: upstream request is required", ErrInvalidTarget)
	}
	transformations := wireTransformations{inputPositions: make([]int, len(upstream.Input))}
	for index := range transformations.inputPositions {
		transformations.inputPositions[index] = index
	}
	for index := range upstream.Tools {
		tool := &upstream.Tools[index]
		switch tool.Type {
		case xaiCustomType:
			if tool.Name == "apply_patch" {
				return wireTransformations{}, fmt.Errorf("%w: custom tool apply_patch is not supported by xAI", ErrUnsupportedContext)
			}
			tool.Type = xaiFunctionType
			tool.Parameters = append(json.RawMessage(nil), xaiDefaultFunctionParameters...)
			tool.Strict = false
			transformations.customToolsAsFunctions = true
		case xaiWebSearchType:
			tool.Type = xaiXSearchType
			transformations.nativeXSearch = true
		}
		if tool.Type == xaiFunctionType {
			simplify, errSchema := requiresXAIParameterSimplification(*tool)
			if errSchema != nil {
				return wireTransformations{}, errSchema
			}
			if simplify {
				if tool.Strict {
					return wireTransformations{}, fmt.Errorf("%w: strict function tool %q requires lossy xAI schema simplification", ErrUnsupportedContext, tool.Name)
				}
				tool.Parameters = append(json.RawMessage(nil), xaiDefaultFunctionParameters...)
				tool.Strict = false
				transformations.simplifiedSchema = true
			}
		}
	}
	if upstream.ToolChoice != nil && upstream.ToolChoice.Type == xaiCustomType {
		upstream.ToolChoice.Type = xaiFunctionType
	}
	for index := range upstream.Input {
		input := &upstream.Input[index]
		switch input.Type {
		case "custom_tool_call":
			arguments, errArguments := customToolCallArguments(input.Input)
			if errArguments != nil {
				return wireTransformations{}, errArguments
			}
			input.Type = "function_call"
			input.Arguments = arguments
			input.Input = ""
			transformations.customToolsAsFunctions = true
		case "custom_tool_call_output":
			input.Type = "function_call_output"
			transformations.customToolsAsFunctions = true
		}
	}
	mergedInput, inputPositions, merged := mergeAdjacentXAIReasoningSummaries(upstream.Input)
	upstream.Input = mergedInput
	transformations.inputPositions = inputPositions
	transformations.mergedReasoningSummaries = merged
	return transformations, nil
}

// mergeAdjacentXAIReasoningSummaries coalesces only source-evidenced adjacent pure summary items and preserves every canonical carrier position.
// mergeAdjacentXAIReasoningSummaries 仅合并来源证实的相邻纯摘要项目，并保留每个规范载体位置。
func mergeAdjacentXAIReasoningSummaries(input []InputItem) ([]InputItem, []int, bool) {
	inputPositions := make([]int, len(input))
	if len(input) == 0 {
		return nil, inputPositions, false
	}
	normalized := make([]InputItem, 0, len(input))
	merged := false
	for sourcePosition, item := range input {
		if len(normalized) > 0 && canMergeXAIReasoningSummary(normalized[len(normalized)-1], item) {
			normalized[len(normalized)-1].Summary = append(normalized[len(normalized)-1].Summary, item.Summary...)
			inputPositions[sourcePosition] = len(normalized) - 1
			merged = true
			continue
		}
		normalized = append(normalized, item)
		inputPositions[sourcePosition] = len(normalized) - 1
	}
	return normalized, inputPositions, merged
}

// canMergeXAIReasoningSummary restricts coalescing to the exact pure visible-summary carrier shape proven by the xAI compatibility source.
// canMergeXAIReasoningSummary 将合并限制为 xAI 兼容来源证实的精确纯可见摘要载体形态。
func canMergeXAIReasoningSummary(previous InputItem, current InputItem) bool {
	return isPureXAIReasoningSummary(previous) && isPureXAIReasoningSummary(current)
}

// isPureXAIReasoningSummary verifies an item has no hidden state, tool relation, or message payload that would make merging non-equivalent.
// isPureXAIReasoningSummary 验证项目不含会使合并不等价的隐藏状态、工具关联或消息载荷。
func isPureXAIReasoningSummary(item InputItem) bool {
	return item.Type == "reasoning" && len(item.Summary) > 0 && item.Role == "" && len(item.Content) == 0 && item.CallID == "" && item.Name == "" && item.Arguments == "" && item.Input == "" && item.Output == ""
}

// customToolCallArguments converts a custom freeform value into the xAI function-call JSON argument contract.
// customToolCallArguments 将 custom 自由格式值转换为 xAI function-call JSON 参数合同。
func customToolCallArguments(input string) (string, error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return "{}", nil
	}
	if json.Valid([]byte(trimmed)) && strings.HasPrefix(trimmed, "{") {
		return trimmed, nil
	}
	encodedInput, errMarshal := json.Marshal(input)
	if errMarshal != nil {
		return "", fmt.Errorf("%w: encode custom tool input: %v", ErrUnsupportedContext, errMarshal)
	}
	return `{"input":` + string(encodedInput) + `}`, nil
}

// xaiSchemaShape is the typed subset needed to identify xAI-incompatible root union schemas.
// xaiSchemaShape 是识别 xAI 不兼容根联合 Schema 所需的类型化子集。
type xaiSchemaShape struct {
	// AnyOf contains root anyOf branches when supplied.
	// AnyOf 包含提供时的根 anyOf 分支。
	AnyOf []xaiSchemaBranch `json:"anyOf"`
	// OneOf contains root oneOf branches when supplied.
	// OneOf 包含提供时的根 oneOf 分支。
	OneOf []xaiSchemaBranch `json:"oneOf"`
}

// xaiSchemaBranch is the typed subset of one root union branch used by the source-evidenced object check.
// xaiSchemaBranch 是来源证实对象检查所使用的一个根联合分支的类型化子集。
type xaiSchemaBranch struct {
	// Type is the JSON Schema type token, which can be a string or an array of strings.
	// Type 是 JSON Schema 类型标记，可以是字符串或字符串数组。
	Type json.RawMessage `json:"type"`
}

// requiresXAIParameterSimplification detects only the schema shapes documented by the xAI compatibility source.
// requiresXAIParameterSimplification 仅检测 xAI 兼容来源文档化的 Schema 形态。
func requiresXAIParameterSimplification(tool Tool) (bool, error) {
	if tool.Name == "codex_app__automation_update" {
		return true, nil
	}
	if len(tool.Parameters) == 0 {
		return false, nil
	}
	var shape xaiSchemaShape
	if errDecode := json.Unmarshal(tool.Parameters, &shape); errDecode != nil {
		return false, fmt.Errorf("%w: function parameters are not valid JSON: %v", ErrUnsupportedContext, errDecode)
	}
	for _, branch := range append(shape.AnyOf, shape.OneOf...) {
		objectOnly, errType := schemaBranchIsObjectOnly(branch.Type)
		if errType != nil {
			return false, errType
		}
		if !objectOnly {
			return true, nil
		}
	}
	return false, nil
}

// schemaBranchIsObjectOnly verifies the exact source rule that every root union branch must explicitly permit only objects.
// schemaBranchIsObjectOnly 校验每个根联合分支必须显式且仅允许对象的精确来源规则。
func schemaBranchIsObjectOnly(rawType json.RawMessage) (bool, error) {
	if len(rawType) == 0 {
		return false, nil
	}
	var single string
	if errSingle := json.Unmarshal(rawType, &single); errSingle == nil {
		return strings.EqualFold(strings.TrimSpace(single), "object"), nil
	}
	var multiple []string
	if errMultiple := json.Unmarshal(rawType, &multiple); errMultiple != nil {
		return false, fmt.Errorf("%w: function parameter branch type is invalid", ErrUnsupportedContext)
	}
	if len(multiple) == 0 {
		return false, nil
	}
	for _, kind := range multiple {
		if !strings.EqualFold(strings.TrimSpace(kind), "object") {
			return false, nil
		}
	}
	return true, nil
}

// adaptProjectionForXAI restores original canonical fields and records xAI-specific reversible transformations in the ledger.
// adaptProjectionForXAI 恢复原始规范字段，并在账本中记录 xAI 特定的可逆转换。
func adaptProjectionForXAI(projected *openairesponses.ProjectedRequest, original vcp.VulcanRequest, referencesByCanonical map[string]ToolReference, upstream Request, inputPositions []int) {
	if projected == nil {
		return
	}
	originalByItemID := make(map[string]vcp.ContextItem, len(original.Context))
	callReferences := make(map[string]ToolReference)
	for _, item := range original.Context {
		originalByItemID[item.ItemID] = item
		if item.ToolCall == nil {
			continue
		}
		if reference, exists := referencesByCanonical[toolIdentity(item.ToolCall.Namespace, item.ToolCall.Name)]; exists {
			callReferences[item.ToolCall.ToolCallID] = reference
		}
	}
	for index := range projected.Ledger.Entries {
		entry := &projected.Ledger.Entries[index]
		originalItem, exists := originalByItemID[entry.CanonicalItemID]
		if !exists {
			continue
		}
		entry.OriginalItem = originalItem
		entry.CarrierProtocol = ProfileID
		if entry.UpstreamPosition >= 0 && entry.UpstreamPosition < len(inputPositions) {
			entry.UpstreamPosition = inputPositions[entry.UpstreamPosition]
		}
		if entry.UpstreamPosition >= 0 && entry.UpstreamPosition < len(upstream.Input) {
			entry.CarrierRoleOrSlot = upstream.Input[entry.UpstreamPosition].Type + ":" + upstream.Input[entry.UpstreamPosition].Role
		}
		entry.RuleID = strings.Replace(entry.RuleID, "openai_responses", "xai_responses", 1)
		if entry.ProjectionMode == vcp.CapabilityOmitted {
			continue
		}
		reference, transformed := xaiReferenceForContextItem(originalItem, callReferences, referencesByCanonical)
		if !transformed {
			continue
		}
		entry.ProjectionMode = vcp.CapabilityProjected
		entry.ExecutionEquivalence = vcp.EquivalenceEquivalent
		if reference.Kind == vcp.ToolCustom && reference.Namespace != "" {
			entry.RuleID = "xai_responses.custom_tool.namespace_function_projected.v1"
		} else if reference.Kind == vcp.ToolCustom {
			entry.RuleID = "xai_responses.custom_tool.function_projected.v1"
		} else {
			entry.RuleID = "xai_responses.namespace_function_projected.v1"
		}
	}
	projected.ProjectionPlan.Entries = append([]vcp.ProjectionEntry(nil), projected.Ledger.Entries...)
}

// xaiReferenceForContextItem returns the associated tool transformation fact for one canonical history item.
// xaiReferenceForContextItem 返回一个规范历史项目关联的工具转换事实。
func xaiReferenceForContextItem(item vcp.ContextItem, callReferences map[string]ToolReference, referencesByCanonical map[string]ToolReference) (ToolReference, bool) {
	switch item.Kind {
	case vcp.ContextToolCall:
		if item.ToolCall == nil {
			return ToolReference{}, false
		}
		reference, exists := referencesByCanonical[toolIdentity(item.ToolCall.Namespace, item.ToolCall.Name)]
		if !exists {
			return ToolReference{}, false
		}
		return reference, reference.Kind == vcp.ToolCustom || reference.Namespace != ""
	case vcp.ContextToolResult:
		if item.ToolResult == nil {
			return ToolReference{}, false
		}
		reference, exists := callReferences[item.ToolResult.ToolCallID]
		if !exists {
			return ToolReference{}, false
		}
		return reference, reference.Kind == vcp.ToolCustom || reference.Namespace != ""
	default:
		return ToolReference{}, false
	}
}

// reconcileRemoteCompaction changes only the xAI-specific remote-compaction capability fact after shared planning.
// reconcileRemoteCompaction 仅在共享规划后变更 xAI 特定的远程压缩能力事实。
func reconcileRemoteCompaction(plan *vcp.CapabilityPlan, report *vcp.ExecutionReport, request vcp.VulcanRequest, capabilities ProfileCapabilities) {
	if plan == nil || report == nil {
		return
	}
	triggered := request.RemoteCompaction != nil || request.ContextManagementPolicy.Mode == vcp.ContextManagementAuto
	if !triggered || !capabilities.NativeRemoteCompaction {
		return
	}
	found := false
	for index := range plan.Demands {
		if plan.Demands[index].Feature != vcp.FeatureRemoteCompaction {
			continue
		}
		plan.Demands[index].SelectedMode = vcp.CapabilityNative
		found = true
	}
	if !found {
		plan.Demands = append(plan.Demands, vcp.CapabilityDemand{Feature: vcp.FeatureRemoteCompaction, Source: "payload", Level: vcp.DemandRequired, AcceptedModes: []vcp.CapabilityMode{vcp.CapabilityNative}, OnUnavailable: "reroute_same_provider", SelectedMode: vcp.CapabilityNative})
	}
	updatedDecision := false
	for index := range report.CapabilityDecisions {
		if report.CapabilityDecisions[index].Feature != vcp.FeatureRemoteCompaction {
			continue
		}
		report.CapabilityDecisions[index] = vcp.CapabilityDecision{Feature: vcp.FeatureRemoteCompaction, SelectedMode: vcp.CapabilityNative, ExecutionEquivalence: vcp.EquivalenceEquivalent, ReasonCode: "capability_plan.native"}
		updatedDecision = true
	}
	if !updatedDecision {
		report.CapabilityDecisions = append(report.CapabilityDecisions, vcp.CapabilityDecision{Feature: vcp.FeatureRemoteCompaction, SelectedMode: vcp.CapabilityNative, ExecutionEquivalence: vcp.EquivalenceEquivalent, ReasonCode: "capability_plan.native"})
	}
	plan.ProjectionRuleVersions = appendUniqueString(plan.ProjectionRuleVersions, "xai_responses.remote_compaction.native.v1")
}

// appendRequestTransformationSummary appends source-evidenced xAI transformation codes without duplicates.
// appendRequestTransformationSummary 追加不重复的来源证实 xAI 转换代码。
func appendRequestTransformationSummary(report *vcp.ExecutionReport, transformations wireTransformations, references []ToolReference) {
	if report == nil {
		return
	}
	for _, reference := range references {
		if reference.Namespace != "" {
			report.ConversionSummary = appendUniqueString(report.ConversionSummary, "xai_responses.namespace_tools.flattened")
			break
		}
	}
	if transformations.customToolsAsFunctions {
		report.ConversionSummary = appendUniqueString(report.ConversionSummary, "xai_responses.custom_tools.function_projected")
	}
	if transformations.nativeXSearch {
		report.ConversionSummary = appendUniqueString(report.ConversionSummary, "xai_responses.native_x_search")
	}
	if transformations.simplifiedSchema {
		report.ConversionSummary = appendUniqueString(report.ConversionSummary, "xai_responses.function_schema.simplified")
	}
	if transformations.mergedReasoningSummaries {
		report.ConversionSummary = appendUniqueString(report.ConversionSummary, "xai_responses.reasoning_summary.merged")
	}
}

// requestUsesNativeXSearch reports whether the final typed wire request explicitly declares xAI x_search.
// requestUsesNativeXSearch 报告最终类型化 wire 请求是否显式声明 xAI x_search。
func requestUsesNativeXSearch(request Request) bool {
	for _, tool := range request.Tools {
		if tool.Type == xaiXSearchType {
			return true
		}
	}
	return false
}

// appendUniqueString appends one stable code only when it is not already present.
// appendUniqueString 仅在尚不存在时追加一个稳定代码。
func appendUniqueString(values []string, target string) []string {
	for _, value := range values {
		if value == target {
			return values
		}
	}
	return append(values, target)
}
