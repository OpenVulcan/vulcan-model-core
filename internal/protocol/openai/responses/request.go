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

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// ProjectRequest compiles one VCP request for an exact resolved OpenAI Responses target.
// ProjectRequest 为一个精确解析的 OpenAI Responses Target 编译一条 VCP 请求。
func ProjectRequest(request vcp.VulcanRequest, target resolve.Target, capabilities ProfileCapabilities, lineageID string, previousResponseID string, now time.Time) (ProjectedRequest, error) {
	return projectRequest(request, target, capabilities, lineageID, previousResponseID, now, nil)
}

// ProjectRequestWithInputs compiles one Responses request with exact accepted resource materializations.
// ProjectRequestWithInputs 使用精确已接受资源物化结果编译一条 Responses 请求。
func ProjectRequestWithInputs(request vcp.VulcanRequest, target resolve.Target, capabilities ProfileCapabilities, lineageID string, previousResponseID string, now time.Time, inputs []resource.MaterializedInput) (ProjectedRequest, error) {
	materialized, errIndex := resource.IndexMaterializedInputs(inputs)
	if errIndex != nil {
		return ProjectedRequest{}, fmt.Errorf("%w: %v", ErrUnsupportedContext, errIndex)
	}
	return projectRequest(request, target, capabilities, lineageID, previousResponseID, now, materialized)
}

// projectRequest compiles text and optional typed media through one deterministic Responses path.
// projectRequest 通过一条确定性 Responses 路径编译文本和可选类型化媒体。
func projectRequest(request vcp.VulcanRequest, target resolve.Target, capabilities ProfileCapabilities, lineageID string, previousResponseID string, now time.Time, materialized resource.MaterializedInputIndex) (ProjectedRequest, error) {
	if errRequest := request.Validate(); errRequest != nil {
		return ProjectedRequest{}, errRequest
	}
	if request.ReasoningPolicy.Enabled != nil || request.ReasoningPolicy.BudgetTokens != nil {
		return ProjectedRequest{}, fmt.Errorf("%w: Responses has no verified carrier for reasoning enabled or budget_tokens", ErrUnsupportedContext)
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
	if capabilitySelected(plan, vcp.FeatureReasoning, vcp.CapabilityNative) && (request.ReasoningPolicy.Effort != "" || request.ReasoningPolicy.RequestedSummaryMode() != "") {
		reasoning := ReasoningConfiguration{Effort: request.ReasoningPolicy.Effort}
		reasoning.Summary = request.ReasoningPolicy.RequestedSummaryMode()
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
			kind := toolKindByIdentity(toolKinds, item.ToolCall.Namespace, item.ToolCall.Name)
			if len(item.ToolCall.ComputerActions) > 0 {
				if countToolKind(toolKinds, vcp.ToolProviderComputerUse) != 1 {
					return ProjectedRequest{}, fmt.Errorf("%w: computer call requires exactly one declared provider computer tool", ErrUnsupportedContext)
				}
				kind = vcp.ToolProviderComputerUse
			}
			callProjections[item.ToolCall.ToolCallID] = toolCallProjection{Kind: kind, UpstreamCallID: item.ToolCall.UpstreamID}
		}
	}
	for _, item := range request.Context {
		position := len(upstream.Input)
		input, mode, equivalence, ruleID, frameID, digest, include, errItem := projectItem(item, request, capabilities, lineageID, position, toolKinds, callProjections, materialized)
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
		{Feature: vcp.FeatureProviderFileSearch, Native: capabilities.ProviderFileSearch},
		{Feature: vcp.FeatureProviderCodeInterpreter, Native: capabilities.ProviderCodeInterpreter},
		{Feature: vcp.FeatureProviderComputerUse, Native: capabilities.ProviderComputerUsePreview || capabilities.ProviderComputerUseGA},
		{Feature: vcp.FeatureImageInput, Native: capabilities.supportsMediaInput(vcp.MediaImage)}, {Feature: vcp.FeatureAudioInput, Native: capabilities.supportsMediaInput(vcp.MediaAudio)},
		{Feature: vcp.FeatureVideoInput, Native: capabilities.supportsMediaInput(vcp.MediaVideo)}, {Feature: vcp.FeatureFileInput, Native: capabilities.supportsMediaInput(vcp.MediaFile)},
	}
	if projectionTriggered {
		availability = append(availability, vcp.CapabilityAvailability{Feature: vcp.FeatureOrderedContextProjection, Native: projectionNative, Projected: request.CapabilityPolicy.AllowAdvisoryInstructionProjection})
	}
	return availability
}

// supportsMediaInput reports whether this exact Responses projection profile accepts one media family.
// supportsMediaInput 报告此精确 Responses 投影 Profile 是否接受一种媒体类别。
func (c ProfileCapabilities) supportsMediaInput(kind vcp.MediaKind) bool {
	for _, supported := range c.MediaInputKinds {
		if supported == kind {
			return true
		}
	}
	return false
}

// supportsMaterialization reports whether one representation survives the selected provider path.
// supportsMaterialization 报告一种表示是否能完整通过选定供应商路径。
func (c ProfileCapabilities) supportsMaterialization(mode catalog.UpstreamMaterializationMode) bool {
	for _, supported := range c.MediaMaterializations {
		if supported == mode {
			return true
		}
	}
	return false
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
	// nativeExtractorSelected is true only for the closed model-tool decision admitted by the Router.
	// nativeExtractorSelected 仅在 Router 已接收封闭模型工具决策时为真。
	nativeExtractorSelected := selectedNativeStandardModelTool(request.ModelTools, vcp.StandardModelToolWebExtractor)
	if nativeExtractorSelected && !capabilities.NativeWebExtractor {
		return nil, vcp.NewModelToolError(vcp.ModelToolNotSupported, string(vcp.StandardModelToolWebExtractor), "projection", false)
	}
	if len(request.Tools) == 0 && !nativeExtractorSelected {
		return toolKinds, nil
	}
	upstream.Tools = make([]Tool, 0, len(request.Tools)+1)
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
		case vcp.ToolProviderFileSearch:
			if !capabilities.ProviderFileSearch || tool.Namespace != "" || tool.FileSearch == nil {
				return nil, fmt.Errorf("%w: provider file search is unavailable for this Responses profile", ErrUnsupportedContext)
			}
			upstream.Tools = append(upstream.Tools, Tool{Type: "file_search", VectorStoreIDs: append([]string(nil), tool.FileSearch.StoreIDs...), MaxNumResults: tool.FileSearch.MaxResults})
		case vcp.ToolProviderCodeInterpreter:
			if !capabilities.ProviderCodeInterpreter || tool.Namespace != "" || tool.CodeInterpreter == nil {
				return nil, fmt.Errorf("%w: provider code interpreter is unavailable for this Responses profile", ErrUnsupportedContext)
			}
			upstream.Tools = append(upstream.Tools, Tool{Type: "code_interpreter", Container: &CodeInterpreterContainer{ID: tool.CodeInterpreter.ContainerID, MemoryLimit: tool.CodeInterpreter.MemoryLimit}})
		case vcp.ToolProviderComputerUse:
			if tool.Namespace != "" || tool.ComputerUse == nil {
				return nil, fmt.Errorf("%w: provider computer use is unavailable for this Responses profile", ErrUnsupportedContext)
			}
			switch tool.ComputerUse.Mode {
			case vcp.ProviderComputerUseGA:
				if !capabilities.ProviderComputerUseGA {
					return nil, fmt.Errorf("%w: provider computer use GA is unavailable for this Responses profile", ErrUnsupportedContext)
				}
				upstream.Tools = append(upstream.Tools, Tool{Type: "computer"})
			case vcp.ProviderComputerUsePreview:
				if !capabilities.ProviderComputerUsePreview {
					return nil, fmt.Errorf("%w: provider computer use preview is unavailable for this Responses profile", ErrUnsupportedContext)
				}
				upstream.Tools = append(upstream.Tools, Tool{Type: "computer_use_preview", Environment: tool.ComputerUse.Environment, DisplayWidth: tool.ComputerUse.DisplayWidth, DisplayHeight: tool.ComputerUse.DisplayHeight})
			default:
				return nil, fmt.Errorf("%w: provider computer use mode is unsupported", ErrUnsupportedContext)
			}
		default:
			return nil, fmt.Errorf("%w: tool kind %q", ErrUnsupportedContext, tool.Kind)
		}
		toolKinds[identity] = tool.Kind
	}
	if nativeExtractorSelected {
		upstream.Tools = append(upstream.Tools, Tool{Type: "web_extractor"})
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
		if isResponsesHostedTool(matched.Kind) {
			return nil, fmt.Errorf("%w: named provider-hosted tool is not a valid Responses tool choice", ErrUnsupportedContext)
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

// selectedNativeStandardModelTool reports whether one exact standard capability was frozen in native mode.
// selectedNativeStandardModelTool 报告一个精确标准能力是否以原生方式冻结。
func selectedNativeStandardModelTool(selection vcp.ModelToolSelection, kind vcp.StandardModelToolKind) bool {
	for _, standard := range selection.Standard {
		if standard.Kind == kind && standard.Mode == vcp.ModelToolNative {
			return true
		}
	}
	return false
}

// isResponsesHostedTool reports built-ins whose named selection does not use a caller tool name.
// isResponsesHostedTool 报告指定选择不使用调用方工具名的内置工具。
func isResponsesHostedTool(kind vcp.ToolKind) bool {
	return kind == vcp.ToolNativeWebSearch || kind == vcp.ToolProviderFileSearch || kind == vcp.ToolProviderCodeInterpreter || kind == vcp.ToolProviderComputerUse
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
func projectItem(item vcp.ContextItem, request vcp.VulcanRequest, capabilities ProfileCapabilities, lineageID string, position int, toolKinds map[string]vcp.ToolKind, callProjections map[string]toolCallProjection, materialized resource.MaterializedInputIndex) (InputItem, vcp.CapabilityMode, vcp.ExecutionEquivalence, string, string, string, bool, error) {
	// Client and audit scopes are Router-local, so sending them upstream would violate the VCP visibility boundary.
	// 客户端和审计作用域仅限 Router 本地，因此将其发送上游会违反 VCP 可见性边界。
	if item.Visibility != vcp.VisibilityModel {
		return InputItem{}, vcp.CapabilityOmitted, vcp.EquivalenceNone, "openai_responses.visibility.omitted.v1", "", "", false, nil
	}
	if item.ProviderStateRef != "" {
		return InputItem{}, "", "", "", "", "", false, fmt.Errorf("%w: opaque provider state requires a Router-resolved previous_response_id continuation", ErrUnsupportedContext)
	}
	userMediaMessage := item.Kind == vcp.ContextMessage && item.Authority == vcp.AuthorityUser && hasResourceContent(item.Content)
	computerScreenshotResult := item.Kind == vcp.ContextToolResult && item.ToolResult != nil && item.ToolResult.ComputerScreenshot != nil
	text := ""
	var errText error
	if !userMediaMessage && !computerScreenshotResult {
		text, errText = vcp.TextContent(item.Content)
	}
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
			if userMediaMessage {
				input, errMedia := responsesMediaMessage(item.Content, capabilities, materialized)
				if errMedia != nil {
					return InputItem{}, "", "", "", "", "", false, errMedia
				}
				return input, vcp.CapabilityNative, vcp.EquivalenceEquivalent, "openai_responses.user_media.native.v1", "", "", true, nil
			}
			return messageInput("user", vcp.EscapeReservedFrameText(text)), vcp.CapabilityNative, vcp.EquivalenceEquivalent, "openai_responses.user.native.v1", "", "", true, nil
		}
		return messageInput("assistant", text), vcp.CapabilityNative, vcp.EquivalenceEquivalent, "openai_responses.assistant.native.v1", "", "", true, nil
	case vcp.ContextToolCall:
		if item.ToolCall == nil {
			return InputItem{}, "", "", "", "", "", false, fmt.Errorf("%w: missing tool call payload", ErrUnsupportedContext)
		}
		if len(item.ToolCall.ComputerActions) > 0 {
			if request.ReasoningPolicy.ContinuationID == "" {
				return InputItem{}, "", "", "", "", "", false, fmt.Errorf("%w: computer call replay requires Router continuation", ErrUnsupportedContext)
			}
			return InputItem{}, vcp.CapabilityOmitted, vcp.EquivalenceEquivalent, "openai_responses.computer_call.continuation.v1", "", "", false, nil
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
		if item.ToolResult.ComputerScreenshot != nil {
			if projection.Kind != vcp.ToolProviderComputerUse || request.ReasoningPolicy.ContinuationID == "" {
				return InputItem{}, "", "", "", "", "", false, fmt.Errorf("%w: computer screenshot requires a continued provider computer call", ErrUnsupportedContext)
			}
			input, errScreenshot := responsesComputerScreenshot(*item.ToolResult.ComputerScreenshot, projection.UpstreamCallID, materialized)
			if errScreenshot != nil {
				return InputItem{}, "", "", "", "", "", false, errScreenshot
			}
			return input, vcp.CapabilityNative, vcp.EquivalenceEquivalent, "openai_responses.computer_screenshot.native.v1", "", "", true, nil
		}
		if projection.Kind == vcp.ToolCustom {
			return InputItem{Type: "custom_tool_call_output", CallID: projection.UpstreamCallID, Output: textInputItemOutput(text)}, vcp.CapabilityNative, vcp.EquivalenceEquivalent, "openai_responses.custom_tool_result.native.v1", "", "", true, nil
		}
		if projection.Kind != vcp.ToolFunction {
			return InputItem{}, "", "", "", "", "", false, fmt.Errorf("%w: tool result kind %q cannot be historical input", ErrUnsupportedContext, projection.Kind)
		}
		return InputItem{Type: "function_call_output", CallID: projection.UpstreamCallID, Output: textInputItemOutput(text)}, vcp.CapabilityNative, vcp.EquivalenceEquivalent, "openai_responses.function_tool_result.native.v1", "", "", true, nil
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

// countToolKind counts exact declarations of one closed tool kind.
// countToolKind 统计一种封闭工具 Kind 的精确声明数量。
func countToolKind(toolKinds map[string]vcp.ToolKind, target vcp.ToolKind) int {
	count := 0
	for _, kind := range toolKinds {
		if kind == target {
			count++
		}
	}
	return count
}

// textInputItemOutput creates the string arm of the closed Responses output union.
// textInputItemOutput 创建封闭 Responses 输出联合的字符串分支。
func textInputItemOutput(value string) *InputItemOutput {
	return &InputItemOutput{Text: &value}
}

// responsesComputerScreenshot projects one exact PNG materialization into computer_call_output.
// responsesComputerScreenshot 将一个精确 PNG 物化结果投影为 computer_call_output。
func responsesComputerScreenshot(screenshot vcp.ComputerScreenshotResult, upstreamCallID string, materialized resource.MaterializedInputIndex) (InputItem, error) {
	if strings.TrimSpace(upstreamCallID) == "" {
		return InputItem{}, fmt.Errorf("%w: computer screenshot requires an upstream call identifier", ErrUnsupportedContext)
	}
	input, exists := materialized.Find(screenshot.ResourceRef, vcp.MediaRoleUnderstanding)
	if !exists || input.ResourceID != screenshot.ResourceRef {
		return InputItem{}, fmt.Errorf("%w: computer screenshot resource %q has no accepted materialization", ErrUnsupportedContext, screenshot.ResourceRef)
	}
	if input.Kind != vcp.MediaImage || input.Role != vcp.MediaRoleUnderstanding || input.Mode != catalog.MaterializationInlineBase64 || input.MIMEType != "image/png" || strings.TrimSpace(input.InlineBase64) == "" {
		return InputItem{}, fmt.Errorf("%w: computer screenshot requires an inline PNG understanding input", ErrUnsupportedContext)
	}
	output := &InputItemOutput{ComputerScreenshot: &ComputerScreenshotOutput{Type: "computer_screenshot", ImageURL: "data:image/png;base64," + input.InlineBase64, Detail: screenshot.Detail}}
	return InputItem{Type: "computer_call_output", CallID: upstreamCallID, Output: output}, nil
}

// messageInput builds one typed text message without using string-or-array wire unions.
// messageInput 构建一条类型化文本消息，不使用字符串或数组 wire 联合。
func messageInput(role string, text string) InputItem {
	return InputItem{Type: "message", Role: role, Content: []InputContent{{Type: "input_text", Text: text}}}
}

// hasResourceContent reports whether an ordered block list contains a Router resource reference.
// hasResourceContent 报告有序内容块是否包含 Router 资源引用。
func hasResourceContent(blocks []vcp.ContentBlock) bool {
	for _, block := range blocks {
		if block.ResourceRef != "" {
			return true
		}
	}
	return false
}

// responsesMediaMessage preserves mixed content order using only evidence-closed media carriers.
// responsesMediaMessage 仅使用证据封闭的媒体载体保留混合内容顺序。
func responsesMediaMessage(blocks []vcp.ContentBlock, capabilities ProfileCapabilities, materialized resource.MaterializedInputIndex) (InputItem, error) {
	content := make([]InputContent, 0, len(blocks))
	for _, block := range blocks {
		if block.Type == vcp.ContentText {
			content = append(content, InputContent{Type: "input_text", Text: vcp.EscapeReservedFrameText(block.Text)})
			continue
		}
		input, exists := materialized.Find(block.ResourceRef, block.MediaRole)
		if !exists {
			return InputItem{}, fmt.Errorf("%w: resource %q has no matching accepted materialization", ErrUnsupportedContext, block.ResourceRef)
		}
		kind, matches := responsesContentMediaKind(block.Type)
		if !matches || kind != input.Kind || !capabilities.supportsMediaInput(kind) || !capabilities.supportsMaterialization(input.Mode) {
			return InputItem{}, fmt.Errorf("%w: resource %q has no supported Responses media carrier", ErrUnsupportedContext, block.ResourceRef)
		}
		projected, errProject := responsesMediaContent(input)
		if errProject != nil {
			return InputItem{}, errProject
		}
		content = append(content, projected)
	}
	return InputItem{Type: "message", Role: "user", Content: content}, nil
}

// responsesMediaContent projects one exact materialization without silently changing its media family.
// responsesMediaContent 投影一个精确物化结果且不静默改变其媒体类别。
func responsesMediaContent(input resource.MaterializedInput) (InputContent, error) {
	switch input.Kind {
	case vcp.MediaImage:
		switch input.Mode {
		case catalog.MaterializationInlineBase64:
			if strings.TrimSpace(input.InlineBase64) == "" {
				break
			}
			return InputContent{Type: "input_image", ImageURL: "data:" + input.MIMEType + ";base64," + input.InlineBase64}, nil
		case catalog.MaterializationProviderFileID:
			if strings.TrimSpace(input.ProviderHandle) == "" {
				break
			}
			return InputContent{Type: "input_image", FileID: input.ProviderHandle}, nil
		}
	case vcp.MediaAudio:
		if input.Mode == catalog.MaterializationInlineBase64 && strings.TrimSpace(input.InlineBase64) != "" {
			format, errFormat := openAIInputAudioFormat(input.MIMEType)
			if errFormat != nil {
				return InputContent{}, errFormat
			}
			return InputContent{Type: "input_audio", InputAudio: &InputAudio{Data: input.InlineBase64, Format: format}}, nil
		}
	case vcp.MediaFile:
		switch input.Mode {
		case catalog.MaterializationInlineBase64:
			if strings.TrimSpace(input.InlineBase64) == "" {
				break
			}
			return InputContent{Type: "input_file", FileData: "data:" + input.MIMEType + ";base64," + input.InlineBase64, Filename: "resource"}, nil
		case catalog.MaterializationProviderFileID:
			if strings.TrimSpace(input.ProviderHandle) == "" {
				break
			}
			return InputContent{Type: "input_file", FileID: input.ProviderHandle}, nil
		}
	}
	return InputContent{}, fmt.Errorf("%w: media kind %q and materialization %q are not representable", ErrUnsupportedContext, input.Kind, input.Mode)
}

// openAIInputAudioFormat maps only the two documented Chat/Responses audio input encodings.
// openAIInputAudioFormat 仅映射 Chat/Responses 已记录的两种音频输入编码。
func openAIInputAudioFormat(mimeType string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(mimeType)) {
	case "audio/mpeg", "audio/mp3":
		return "mp3", nil
	case "audio/wav", "audio/x-wav":
		return "wav", nil
	default:
		return "", fmt.Errorf("%w: audio MIME type %q has no OpenAI input_audio format", ErrUnsupportedContext, mimeType)
	}
}

// responsesContentMediaKind maps only registered resource-bearing VCP blocks.
// responsesContentMediaKind 仅映射已注册的资源型 VCP 内容块。
func responsesContentMediaKind(contentType vcp.ContentType) (vcp.MediaKind, bool) {
	switch contentType {
	case vcp.ContentImage:
		return vcp.MediaImage, true
	case vcp.ContentAudio:
		return vcp.MediaAudio, true
	case vcp.ContentVideo:
		return vcp.MediaVideo, true
	case vcp.ContentFile:
		return vcp.MediaFile, true
	default:
		return "", false
	}
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
