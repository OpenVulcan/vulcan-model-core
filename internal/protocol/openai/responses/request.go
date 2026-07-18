// Portions of this request projection are adapted from CLIProxyAPI commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// 本请求投影的部分逻辑改编自 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66。
// Source path: internal/translator/openai/openai/responses.
// 来源路径：internal/translator/openai/openai/responses。
// The adapted scope is Responses input, tool, and continuation compatibility while VCP remains the sole canonical state.
// 改编范围为 Responses 输入、工具和续接兼容性，同时 VCP 仍是唯一规范状态。
package responses

import (
	"fmt"
	"strings"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// ProjectRequest compiles one VCP request for an exact resolved OpenAI Responses target.
// ProjectRequest 为一个精确解析的 OpenAI Responses Target 编译一条 VCP 请求。
func ProjectRequest(request vcp.VulcanRequest, target resolve.Target, capabilities ProfileCapabilities, lineageID string, previousResponseID string, now time.Time) (ProjectedRequest, error) {
	if errRequest := request.Validate(); errRequest != nil {
		return ProjectedRequest{}, errRequest
	}
	if len(request.GenerationPolicy.Stop) > 0 {
		return ProjectedRequest{}, fmt.Errorf("%w: stop sequences have no OpenAI Responses wire carrier", ErrUnsupportedContext)
	}
	if errTarget := validateTarget(target); errTarget != nil {
		return ProjectedRequest{}, errTarget
	}
	if strings.TrimSpace(lineageID) == "" {
		return ProjectedRequest{}, fmt.Errorf("%w: lineage_id is required", ErrInvalidTarget)
	}
	if errBinding := validateSelectionBinding(request.ModelSelection, target); errBinding != nil {
		return ProjectedRequest{}, errBinding
	}
	availability := capabilityAvailability(request, capabilities)
	plan, errPlan := vcp.PlanCapabilities(request, availability, target.CatalogRevision, now)
	if errPlan != nil {
		return ProjectedRequest{}, errPlan
	}
	if plan.HasBlocked() {
		return ProjectedRequest{}, fmt.Errorf("%w: request has blocked capability demand", vcp.ErrCapabilityUnavailable)
	}
	if request.ReasoningPolicy.ContinuationID != "" && strings.TrimSpace(previousResponseID) == "" {
		return ProjectedRequest{}, fmt.Errorf("%w: Router-resolved previous_response_id is required for continuation", ErrUnsupportedContext)
	}
	// projectionID fixes every ledger entry to this exact provider-scoped execution.
	// projectionID 将每个账本条目固定到这个精确供应商作用域执行。
	projectionID := vcp.DeriveID("prj", request.RequestID, lineageID, target.ProviderInstanceID, target.ChannelID, target.EndpointID, target.CredentialID, target.UpstreamModelID)
	ledger := vcp.ProjectionLedger{LedgerID: vcp.DeriveID("ldg", projectionID), ProjectionID: projectionID, LineageID: lineageID}
	upstream := Request{
		Model: target.UpstreamModelID, Stream: request.Stream,
		Temperature: request.GenerationPolicy.Temperature, TopP: request.GenerationPolicy.TopP, MaxOutputTokens: request.GenerationPolicy.MaxOutputTokens,
	}
	if request.ReasoningPolicy.ContinuationID != "" {
		upstream.PreviousResponseID = previousResponseID
	}
	if len(request.GenerationPolicy.StrictJSONSchema) > 0 {
		upstream.Text = &TextConfiguration{Format: TextFormat{Type: "json_schema", Name: "vulcan_response", Schema: append([]byte(nil), request.GenerationPolicy.StrictJSONSchema...), Strict: true}}
	}
	if capabilitySelected(plan, vcp.FeatureReasoning, vcp.CapabilityNative) && (request.ReasoningPolicy.Effort != "" || request.ReasoningPolicy.Summary) {
		reasoning := ReasoningConfiguration{Effort: request.ReasoningPolicy.Effort}
		if request.ReasoningPolicy.Summary {
			reasoning.Summary = "auto"
		}
		upstream.Reasoning = &reasoning
	}
	toolKinds, errTools := projectTools(&upstream, request, capabilities)
	if errTools != nil {
		return ProjectedRequest{}, errTools
	}
	callProjections := make(map[string]toolCallProjection)
	for _, item := range request.Context {
		if item.Visibility != vcp.VisibilityModel {
			continue
		}
		if item.Kind == vcp.ContextToolCall && item.ToolCall != nil {
			if item.ToolCall.UpstreamID == "" {
				return ProjectedRequest{}, fmt.Errorf("%w: historical tool call %q has no verified upstream call identifier", ErrUnsupportedContext, item.ToolCall.ToolCallID)
			}
			callProjections[item.ToolCall.ToolCallID] = toolCallProjection{Kind: toolKindByIdentity(toolKinds, item.ToolCall.Namespace, item.ToolCall.Name), UpstreamCallID: item.ToolCall.UpstreamID}
		}
	}
	for _, item := range request.Context {
		position := len(upstream.Input)
		input, mode, equivalence, ruleID, frameID, digest, include, errItem := projectItem(item, request, capabilities, lineageID, position, toolKinds, callProjections)
		if errItem != nil {
			return ProjectedRequest{}, errItem
		}
		if include {
			upstream.Input = append(upstream.Input, input)
		} else {
			position = -1
		}
		entry := vcp.ProjectionEntry{
			ProjectionID: projectionID, LineageID: lineageID, CanonicalItemID: item.ItemID, CanonicalSequence: item.Sequence,
			CanonicalKind: item.Kind, SourceAuthority: item.Authority, CarrierProtocol: ProfileID, CarrierRoleOrSlot: input.Type + ":" + input.Role,
			UpstreamPosition: position, ProjectionMode: mode, ExecutionEquivalence: equivalence, RuleID: ruleID, RuleVersion: "1",
			FrameID: frameID, ContentDigest: digest, DecodePolicy: "replay_only", OriginalItem: item, CreatedAt: now, ExpiresAt: now.Add(24 * time.Hour),
		}
		if errAdd := ledger.Add(entry); errAdd != nil {
			return ProjectedRequest{}, errAdd
		}
	}
	projection := vcp.ProjectionPlan{ProjectionID: projectionID, LineageID: lineageID, Entries: append([]vcp.ProjectionEntry(nil), ledger.Entries...)}
	report := vcp.ExecutionReport{
		ResponseID: vcp.DeriveID("resp", request.RequestID), ExecutionID: vcp.DeriveID("exec", projectionID), CatalogRevision: target.CatalogRevision,
		Route:               vcp.RouteSummary{ProviderDefinition: target.ProviderDefinitionID, Model: target.ProviderModelID, ExecutionProfile: target.ExecutionProfileID},
		CapabilityDecisions: plan.ToExecutionDecisions(),
	}
	return ProjectedRequest{Upstream: upstream, CapabilityPlan: plan, ProjectionPlan: projection, Ledger: ledger, Report: report}, nil
}

// validateTarget verifies every exact routing boundary required by the Responses profile.
// validateTarget 校验 Responses Profile 所需的每个精确路由边界。
func validateTarget(target resolve.Target) error {
	if strings.TrimSpace(target.ProviderDefinitionID) == "" || strings.TrimSpace(target.ProviderInstanceID) == "" || strings.TrimSpace(target.ChannelID) == "" || strings.TrimSpace(target.EndpointID) == "" || strings.TrimSpace(target.CredentialID) == "" || strings.TrimSpace(target.ProviderModelID) == "" || strings.TrimSpace(target.ExecutionProfileID) == "" || strings.TrimSpace(target.UpstreamModelID) == "" {
		return fmt.Errorf("%w: provider, channel, endpoint, credential, model, and profile must be exact", ErrInvalidTarget)
	}
	return nil
}

// validateSelectionBinding prevents a resolved target from escaping caller-selected provider boundaries.
// validateSelectionBinding 防止已解析 Target 逸出调用方选择的供应商边界。
func validateSelectionBinding(selection vcp.ModelSelection, target resolve.Target) error {
	if selection.ProviderInstanceID != "" && selection.ProviderInstanceID != target.ProviderInstanceID {
		return fmt.Errorf("%w: provider instance differs from model selection", ErrInvalidTarget)
	}
	if selection.ProviderModelID != "" && selection.ProviderModelID != target.ProviderModelID {
		return fmt.Errorf("%w: provider model differs from model selection", ErrInvalidTarget)
	}
	if selection.ExecutionProfileID != "" && selection.ExecutionProfileID != target.ExecutionProfileID {
		return fmt.Errorf("%w: execution profile differs from model selection", ErrInvalidTarget)
	}
	return nil
}

// capabilityAvailability converts verified Responses behavior into VCP planning evidence.
// capabilityAvailability 将经过验证的 Responses 行为转换为 VCP 规划证据。
func capabilityAvailability(request vcp.VulcanRequest, capabilities ProfileCapabilities) []vcp.CapabilityAvailability {
	projectionNative := true
	projectionTriggered := false
	for _, item := range request.Context {
		switch {
		case item.Kind == vcp.ContextDelegatedResult:
			projectionTriggered = true
			projectionNative = false
		case item.Kind == vcp.ContextInstruction && item.Authority == vcp.AuthoritySystem && item.Placement == vcp.PlacementPreamble:
			projectionTriggered = true
			projectionNative = projectionNative && capabilities.NativeSystemPreamble
		case item.Kind == vcp.ContextInstruction && item.Authority == vcp.AuthorityDeveloper:
			projectionTriggered = true
			projectionNative = projectionNative && capabilities.NativeDeveloper
		case item.Kind == vcp.ContextInstruction && item.Authority == vcp.AuthoritySystem && item.Placement == vcp.PlacementTranscript:
			projectionTriggered = true
			projectionNative = projectionNative && capabilities.NativeInlineSystem
		}
	}
	availability := []vcp.CapabilityAvailability{
		{Feature: vcp.FeatureStructuredToolCalling, Native: capabilities.StructuredTools},
		{Feature: vcp.FeatureParallelToolCalling, Native: capabilities.ParallelTools},
		{Feature: vcp.FeatureStreamingToolArguments, Native: capabilities.StreamingToolArguments},
		{Feature: vcp.FeatureStrictSchema, Native: capabilities.StrictJSONSchema},
		{Feature: vcp.FeatureReasoning, Native: capabilities.Reasoning},
		{Feature: vcp.FeatureReasoningContinuation, Native: capabilities.ReasoningContinuation},
		{Feature: vcp.FeatureExplicitPromptCache, Native: false},
		{Feature: vcp.FeatureRemoteCompaction, Native: false},
		{Feature: vcp.FeatureNativeWebSearch, Native: capabilities.NativeWebSearch},
		{Feature: vcp.FeatureImageInput, Native: false}, {Feature: vcp.FeatureAudioInput, Native: false},
		{Feature: vcp.FeatureVideoInput, Native: false}, {Feature: vcp.FeatureFileInput, Native: false},
	}
	if projectionTriggered {
		availability = append(availability, vcp.CapabilityAvailability{Feature: vcp.FeatureOrderedContextProjection, Native: projectionNative, Projected: request.CapabilityPolicy.AllowAdvisoryInstructionProjection})
	}
	return availability
}

// capabilitySelected reports whether a frozen plan selected one exact capability mode.
// capabilitySelected 报告冻结计划是否选择了一个精确能力模式。
func capabilitySelected(plan vcp.CapabilityPlan, feature vcp.CapabilityFeature, mode vcp.CapabilityMode) bool {
	decision, exists := plan.Decision(feature)
	return exists && decision == mode
}

// projectTools converts VCP declarations while retaining their declared kind for historical tool items.
// projectTools 转换 VCP 声明，同时保留历史工具项目使用的声明 Kind。
func projectTools(upstream *Request, request vcp.VulcanRequest, capabilities ProfileCapabilities) (map[string]vcp.ToolKind, error) {
	// toolKinds maps the exact namespace/name identity to its closed VCP kind.
	// toolKinds 将精确命名空间/名称身份映射到其封闭 VCP Kind。
	toolKinds := make(map[string]vcp.ToolKind)
	if len(request.Tools) == 0 {
		return toolKinds, nil
	}
	upstream.Tools = make([]Tool, 0, len(request.Tools))
	for _, tool := range request.Tools {
		identity := toolIdentity(tool.Namespace, tool.Name)
		if _, exists := toolKinds[identity]; exists {
			return nil, fmt.Errorf("%w: duplicate tool identity %q", ErrUnsupportedContext, identity)
		}
		wireName, errName := wireToolName(tool.Namespace, tool.Name, capabilities.NativeToolNamespaces)
		if errName != nil {
			return nil, errName
		}
		switch tool.Kind {
		case vcp.ToolFunction:
			upstream.Tools = append(upstream.Tools, Tool{Type: "function", Name: wireName, Description: tool.Description, Parameters: append([]byte(nil), tool.Parameters...), Strict: tool.Strict})
		case vcp.ToolCustom:
			if !capabilities.NativeCustomTools {
				return nil, fmt.Errorf("%w: custom tool %q is not supported by this target", ErrUnsupportedContext, tool.Name)
			}
			upstream.Tools = append(upstream.Tools, Tool{Type: "custom", Name: wireName, Description: tool.Description})
		case vcp.ToolNativeWebSearch:
			if tool.Namespace != "" {
				return nil, fmt.Errorf("%w: native web search cannot have a namespace", ErrUnsupportedContext)
			}
			upstream.Tools = append(upstream.Tools, Tool{Type: "web_search"})
		default:
			return nil, fmt.Errorf("%w: tool kind %q", ErrUnsupportedContext, tool.Kind)
		}
		toolKinds[identity] = tool.Kind
	}
	choice := request.ToolPolicy.Choice
	if choice == "" {
		choice = vcp.ToolChoiceAuto
	}
	choiceType := "function"
	if choice == vcp.ToolChoiceNamed {
		matched, count := findNamedTool(request.Tools, request.ToolPolicy.NamedTool)
		if count != 1 {
			return nil, fmt.Errorf("%w: named tool must match exactly one declaration", ErrUnsupportedContext)
		}
		if matched.Kind == vcp.ToolNativeWebSearch {
			return nil, fmt.Errorf("%w: named native web search is not a valid Responses tool choice", ErrUnsupportedContext)
		}
		if matched.Kind == vcp.ToolCustom {
			choiceType = "custom"
		}
		wireName, errName := wireToolName(matched.Namespace, matched.Name, capabilities.NativeToolNamespaces)
		if errName != nil {
			return nil, errName
		}
		upstream.ToolChoice = &ToolChoice{Mode: choice, Type: choiceType, Name: wireName}
	} else {
		upstream.ToolChoice = &ToolChoice{Mode: choice}
	}
	if capabilities.ParallelTools {
		parallel := request.ToolPolicy.Parallel
		upstream.ParallelToolCalls = &parallel
	}
	return toolKinds, nil
}

// findNamedTool finds an exact VCP tool name and returns its count to prevent ambiguous implicit selection.
// findNamedTool 查找精确 VCP 工具名称并返回其数量，以避免模糊隐式选择。
func findNamedTool(tools []vcp.ToolDefinition, name string) (vcp.ToolDefinition, int) {
	matched := vcp.ToolDefinition{}
	count := 0
	for _, tool := range tools {
		if tool.Name == name {
			matched = tool
			count++
		}
	}
	return matched, count
}

// projectItem maps one canonical item to one exact Responses input carrier and ledger decision.
// projectItem 将一个规范项目映射到一个精确 Responses 输入载体和账本决策。
func projectItem(item vcp.ContextItem, request vcp.VulcanRequest, capabilities ProfileCapabilities, lineageID string, position int, toolKinds map[string]vcp.ToolKind, callProjections map[string]toolCallProjection) (InputItem, vcp.CapabilityMode, vcp.ExecutionEquivalence, string, string, string, bool, error) {
	// Client and audit scopes are Router-local, so sending them upstream would violate the VCP visibility boundary.
	// 客户端和审计作用域仅限 Router 本地，因此将其发送上游会违反 VCP 可见性边界。
	if item.Visibility != vcp.VisibilityModel {
		return InputItem{}, vcp.CapabilityOmitted, vcp.EquivalenceNone, "openai_responses.visibility.omitted.v1", "", "", false, nil
	}
	if item.ProviderStateRef != "" {
		return InputItem{}, "", "", "", "", "", false, fmt.Errorf("%w: opaque provider state requires a Router-resolved previous_response_id continuation", ErrUnsupportedContext)
	}
	text, errText := vcp.TextContent(item.Content)
	if errText != nil && item.Kind != vcp.ContextToolCall {
		return InputItem{}, "", "", "", "", "", false, fmt.Errorf("%w: item %q: %v", ErrUnsupportedContext, item.ItemID, errText)
	}
	switch item.Kind {
	case vcp.ContextInstruction:
		if item.Authority == vcp.AuthoritySystem && item.Placement == vcp.PlacementPreamble && capabilities.NativeSystemPreamble {
			return messageInput("system", text), vcp.CapabilityNative, vcp.EquivalenceEquivalent, "openai_responses.system_preamble.native.v1", "", "", true, nil
		}
		if item.Authority == vcp.AuthorityDeveloper && capabilities.NativeDeveloper {
			return messageInput("developer", text), vcp.CapabilityNative, vcp.EquivalenceEquivalent, "openai_responses.developer.native.v1", "", "", true, nil
		}
		if item.Authority == vcp.AuthoritySystem && item.Placement == vcp.PlacementTranscript && capabilities.NativeInlineSystem {
			return messageInput("system", text), vcp.CapabilityNative, vcp.EquivalenceEquivalent, "openai_responses.system_inline.native.v1", "", "", true, nil
		}
		return projectFrame(item, request, lineageID, position)
	case vcp.ContextDelegatedResult:
		return projectFrame(item, request, lineageID, position)
	case vcp.ContextMessage:
		if item.Authority == vcp.AuthorityUser {
			return messageInput("user", vcp.EscapeReservedFrameText(text)), vcp.CapabilityNative, vcp.EquivalenceEquivalent, "openai_responses.user.native.v1", "", "", true, nil
		}
		return messageInput("assistant", text), vcp.CapabilityNative, vcp.EquivalenceEquivalent, "openai_responses.assistant.native.v1", "", "", true, nil
	case vcp.ContextToolCall:
		if item.ToolCall == nil {
			return InputItem{}, "", "", "", "", "", false, fmt.Errorf("%w: missing tool call payload", ErrUnsupportedContext)
		}
		kind := toolKindByIdentity(toolKinds, item.ToolCall.Namespace, item.ToolCall.Name)
		if kind == "" {
			return InputItem{}, "", "", "", "", "", false, fmt.Errorf("%w: tool call %q has no declared tool", ErrUnsupportedContext, item.ToolCall.ToolCallID)
		}
		wireName, errName := wireToolName(item.ToolCall.Namespace, item.ToolCall.Name, capabilities.NativeToolNamespaces)
		if errName != nil {
			return InputItem{}, "", "", "", "", "", false, errName
		}
		if item.ToolCall.UpstreamID == "" {
			return InputItem{}, "", "", "", "", "", false, fmt.Errorf("%w: historical tool call %q has no verified upstream call identifier", ErrUnsupportedContext, item.ToolCall.ToolCallID)
		}
		if kind == vcp.ToolCustom {
			return InputItem{Type: "custom_tool_call", CallID: item.ToolCall.UpstreamID, Name: wireName, Input: item.ToolCall.Arguments}, vcp.CapabilityNative, vcp.EquivalenceEquivalent, "openai_responses.custom_tool_call.native.v1", "", "", true, nil
		}
		if kind != vcp.ToolFunction {
			return InputItem{}, "", "", "", "", "", false, fmt.Errorf("%w: tool call kind %q cannot be historical input", ErrUnsupportedContext, kind)
		}
		return InputItem{Type: "function_call", CallID: item.ToolCall.UpstreamID, Name: wireName, Arguments: item.ToolCall.Arguments}, vcp.CapabilityNative, vcp.EquivalenceEquivalent, "openai_responses.function_call.native.v1", "", "", true, nil
	case vcp.ContextToolResult:
		if item.ToolResult == nil {
			return InputItem{}, "", "", "", "", "", false, fmt.Errorf("%w: missing tool result payload", ErrUnsupportedContext)
		}
		projection, exists := callProjections[item.ToolResult.ToolCallID]
		if !exists || projection.Kind == "" {
			return InputItem{}, "", "", "", "", "", false, fmt.Errorf("%w: tool result %q has no preceding declared tool call", ErrUnsupportedContext, item.ToolResult.ToolCallID)
		}
		if projection.Kind == vcp.ToolCustom {
			return InputItem{Type: "custom_tool_call_output", CallID: projection.UpstreamCallID, Output: text}, vcp.CapabilityNative, vcp.EquivalenceEquivalent, "openai_responses.custom_tool_result.native.v1", "", "", true, nil
		}
		if projection.Kind != vcp.ToolFunction {
			return InputItem{}, "", "", "", "", "", false, fmt.Errorf("%w: tool result kind %q cannot be historical input", ErrUnsupportedContext, projection.Kind)
		}
		return InputItem{Type: "function_call_output", CallID: projection.UpstreamCallID, Output: text}, vcp.CapabilityNative, vcp.EquivalenceEquivalent, "openai_responses.function_tool_result.native.v1", "", "", true, nil
	case vcp.ContextReasoning:
		if item.ProviderStateRef != "" || (item.Reasoning != nil && item.Reasoning.ContinuationRef != "") {
			return InputItem{}, "", "", "", "", "", false, fmt.Errorf("%w: sealed reasoning state requires previous_response_id continuation", ErrUnsupportedContext)
		}
		if capabilities.Reasoning && item.Reasoning != nil && item.Reasoning.Summary {
			return InputItem{Type: "reasoning", Summary: []ReasoningSummary{{Type: "summary_text", Text: text}}}, vcp.CapabilityNative, vcp.EquivalenceEquivalent, "openai_responses.reasoning_summary.native.v1", "", "", true, nil
		}
		return InputItem{}, vcp.CapabilityOmitted, vcp.EquivalenceNone, "openai_responses.reasoning.omitted.v1", "", "", false, nil
	case vcp.ContextRefusal:
		return messageInput("assistant", text), vcp.CapabilityProjected, vcp.EquivalenceAdvisory, "openai_responses.refusal_history.projected.v1", "", "", true, nil
	default:
		return InputItem{}, "", "", "", "", "", false, fmt.Errorf("%w: kind %q", ErrUnsupportedContext, item.Kind)
	}
}

// messageInput builds one typed text message without using string-or-array wire unions.
// messageInput 构建一条类型化文本消息，不使用字符串或数组 wire 联合。
func messageInput(role string, text string) InputItem {
	return InputItem{Type: "message", Role: role, Content: []InputContent{{Type: "input_text", Text: text}}}
}

// projectFrame creates an independent advisory user carrier or an explicit omission.
// projectFrame 创建独立建议性 user 载体或显式省略。
func projectFrame(item vcp.ContextItem, request vcp.VulcanRequest, lineageID string, position int) (InputItem, vcp.CapabilityMode, vcp.ExecutionEquivalence, string, string, string, bool, error) {
	if !request.CapabilityPolicy.AllowAdvisoryInstructionProjection {
		return InputItem{}, vcp.CapabilityOmitted, vcp.EquivalenceNone, "openai_responses.context.omitted.v1", "", "", false, nil
	}
	frameID := vcp.DeriveID("frm", lineageID, item.ItemID, fmt.Sprint(item.Sequence), fmt.Sprint(position))
	encoded, frame, errFrame := vcp.EncodeFrame(item, frameID)
	if errFrame != nil {
		return InputItem{}, "", "", "", "", "", false, errFrame
	}
	ruleID := "openai_responses." + frame.Kind + ".frame.v1"
	return messageInput("user", encoded), vcp.CapabilityProjected, vcp.EquivalenceAdvisory, ruleID, frameID, frame.Digest, true, nil
}

// toolIdentity creates one exact VCP namespace/name key without inferring alternate spellings.
// toolIdentity 创建一个精确 VCP 命名空间/名称键，不推断其他拼写。
func toolIdentity(namespace string, name string) string {
	return namespace + "\x00" + name
}

// toolKindByIdentity looks up one already-declared tool kind exactly.
// toolKindByIdentity 精确查找一个已声明工具的 Kind。
func toolKindByIdentity(toolKinds map[string]vcp.ToolKind, namespace string, name string) vcp.ToolKind {
	return toolKinds[toolIdentity(namespace, name)]
}

// toolCallProjection binds one stable VCP tool call to its exact upstream replay identity and kind.
// toolCallProjection 将一个稳定 VCP 工具调用绑定到其精确上游回放标识和 Kind。
type toolCallProjection struct {
	// Kind is the closed VCP declaration kind used to select the wire call shape.
	// Kind 是用于选择 wire 调用形态的封闭 VCP 声明 Kind。
	Kind vcp.ToolKind
	// UpstreamCallID is the exact identifier required by the provider for a later tool result.
	// UpstreamCallID 是 Provider 后续工具结果所需的精确标识。
	UpstreamCallID string
}

// wireToolName preserves native names or creates the documented namespace-qualified wire name.
// wireToolName 保留原生名称或创建文档规定的命名空间限定 wire 名称。
func wireToolName(namespace string, name string, nativeNamespaces bool) (string, error) {
	if strings.TrimSpace(name) == "" {
		return "", fmt.Errorf("%w: tool name is required", ErrUnsupportedContext)
	}
	if namespace == "" {
		return name, nil
	}
	if !nativeNamespaces {
		return "", fmt.Errorf("%w: tool namespace %q is not supported by this target", ErrUnsupportedContext, namespace)
	}
	if strings.HasPrefix(name, namespace+"__") || strings.HasPrefix(name, "mcp__") {
		return name, nil
	}
	if strings.HasSuffix(namespace, "__") {
		return namespace + name, nil
	}
	return namespace + "__" + name, nil
}
