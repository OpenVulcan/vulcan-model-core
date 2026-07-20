// Portions of this request projection are adapted from CLIProxyAPI commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// 本请求投影的部分逻辑改编自 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66。
// Source paths: internal/translator/gemini/gemini/gemini_gemini_request.go and internal/translator/gemini/openai/responses/gemini_openai-responses_request.go.
// 来源路径：internal/translator/gemini/gemini/gemini_gemini_request.go 和 internal/translator/gemini/openai/responses/gemini_openai-responses_request.go。
// The adapted scope is Gemini function-response affinity and trailing model-prefill protection; VCP remains the sole canonical state.
// 改编范围为 Gemini 函数响应亲和性和尾部模型预填保护；VCP 仍是唯一规范状态。
package aistudio

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// ProjectRequest compiles one VCP request for an exact resolved Google AI Studio target.
// ProjectRequest 为一个精确解析的 Google AI Studio Target 编译一条 VCP 请求。
func ProjectRequest(request vcp.VulcanRequest, target resolve.Target, capabilities ProfileCapabilities, lineageID string, now time.Time) (ProjectedRequest, error) {
	return projectRequest(request, target, capabilities, lineageID, now, nil)
}

// ProjectRequestWithInputs compiles one VCP request with exact input-plan materializations.
// ProjectRequestWithInputs 使用精确输入方案物化结果编译一条 VCP 请求。
func ProjectRequestWithInputs(request vcp.VulcanRequest, target resolve.Target, capabilities ProfileCapabilities, lineageID string, now time.Time, inputs []resource.MaterializedInput) (ProjectedRequest, error) {
	materialized := make(map[string]resource.MaterializedInput, len(inputs))
	for _, input := range inputs {
		if _, exists := materialized[input.ResourceID]; exists {
			return ProjectedRequest{}, fmt.Errorf("%w: duplicate materialized resource %q", ErrUnsupportedContext, input.ResourceID)
		}
		materialized[input.ResourceID] = input
	}
	return projectRequest(request, target, capabilities, lineageID, now, materialized)
}

// projectRequest compiles text and optional materialized media through one deterministic path.
// projectRequest 通过一条确定性路径编译文本和可选物化媒体。
func projectRequest(request vcp.VulcanRequest, target resolve.Target, capabilities ProfileCapabilities, lineageID string, now time.Time, materialized map[string]resource.MaterializedInput) (ProjectedRequest, error) {
	if errRequest := request.Validate(); errRequest != nil {
		return ProjectedRequest{}, errRequest
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
	// projectionID fixes every ledger entry to this exact provider-scoped execution.
	// projectionID 将每个账本条目固定到这个精确供应商作用域执行。
	projectionID := vcp.DeriveID("prj", request.RequestID, lineageID, target.ProviderInstanceID, target.ChannelID, target.EndpointID, target.CredentialID, target.UpstreamModelID)
	ledger := vcp.ProjectionLedger{LedgerID: vcp.DeriveID("ldg", projectionID), ProjectionID: projectionID, LineageID: lineageID}
	// referenceSet preserves every canonical-to-wire function name relation without untyped lookup data.
	// referenceSet 在不使用未类型化查找数据的前提下保留每个规范到 wire 的函数名称关系。
	referenceSet := newToolReferenceSet()
	upstream := GenerateContentRequest{}
	if errTools := projectTools(&upstream, request, referenceSet); errTools != nil {
		return ProjectedRequest{}, errTools
	}
	if errGeneration := projectGeneration(&upstream, request, plan, capabilities); errGeneration != nil {
		return ProjectedRequest{}, errGeneration
	}
	// callNames records only prior canonical tool calls, which VCP validation guarantees are available to later results.
	// callNames 仅记录先前规范工具调用，VCP 校验保证后续结果可使用这些调用。
	callNames := make(map[string]toolCallReference)
	// report gathers safe projection facts before it is returned with the immutable execution route.
	// report 在随不可变执行路由返回前收集安全投影事实。
	report := vcp.ExecutionReport{
		ResponseID: vcp.DeriveID("resp", request.RequestID), ExecutionID: vcp.DeriveID("exec", projectionID), CatalogRevision: target.CatalogRevision,
		Route:               vcp.RouteSummary{ProviderDefinition: target.ProviderDefinitionID, Model: target.ProviderModelID, ExecutionProfile: target.ExecutionProfileID},
		CapabilityDecisions: plan.ToExecutionDecisions(),
	}
	// lastContentEntryIndex tracks the ledger owner of the final actual contents element after visibility and capability projection.
	// lastContentEntryIndex 跟踪经过可见性与能力投影后最终实际 Contents 元素的账本所有者。
	lastContentEntryIndex := -1
	for _, item := range request.Context {
		position := len(upstream.Contents)
		content, carrier, mode, equivalence, ruleID, frameID, digest, include, errItem := projectItem(item, request, plan, capabilities, lineageID, position, referenceSet, callNames, materialized)
		if errItem != nil {
			return ProjectedRequest{}, errItem
		}
		// isSystemInstruction distinguishes a native system carrier from an omitted projection entry.
		// isSystemInstruction 区分原生系统载体和已省略的投影条目。
		isSystemInstruction := carrier == "systemInstruction:parts"
		if isSystemInstruction {
			if upstream.SystemInstruction == nil {
				upstream.SystemInstruction = &Content{}
			}
			position = len(upstream.SystemInstruction.Parts)
			upstream.SystemInstruction.Parts = append(upstream.SystemInstruction.Parts, content.Parts...)
		} else if include {
			upstream.Contents = append(upstream.Contents, content)
		} else {
			position = -1
		}
		if ruleID == "google_aistudio.reasoning.omitted.v1" {
			report.ConversionSummary = appendSafeSummary(report.ConversionSummary, "google_aistudio.reasoning.omitted")
		}
		if ruleID == "google_aistudio.refusal.projected_text.v1" {
			report.ConversionSummary = appendSafeSummary(report.ConversionSummary, "google_aistudio.refusal.projected_text")
		}
		entry := vcp.ProjectionEntry{
			ProjectionID: projectionID, LineageID: lineageID, CanonicalItemID: item.ItemID, CanonicalSequence: item.Sequence,
			CanonicalKind: item.Kind, SourceAuthority: item.Authority, CarrierProtocol: ProfileID, CarrierRoleOrSlot: carrier,
			UpstreamPosition: position, ProjectionMode: mode, ExecutionEquivalence: equivalence, RuleID: ruleID, RuleVersion: "1",
			FrameID: frameID, ContentDigest: digest, DecodePolicy: "replay_only", OriginalItem: item, CreatedAt: now, ExpiresAt: now.Add(24 * time.Hour),
		}
		if errAdd := ledger.Add(entry); errAdd != nil {
			return ProjectedRequest{}, errAdd
		}
		if !isSystemInstruction && include {
			lastContentEntryIndex = len(ledger.Entries) - 1
		}
	}
	if lastContentEntryIndex >= 0 {
		lastContentEntry := &ledger.Entries[lastContentEntryIndex]
		if lastContentEntry.OriginalItem.Kind == vcp.ContextMessage && lastContentEntry.OriginalItem.Authority == vcp.AuthorityAssistant {
			upstream.Contents = upstream.Contents[:len(upstream.Contents)-1]
			lastContentEntry.UpstreamPosition = -1
			lastContentEntry.CarrierRoleOrSlot = "omitted:trailing_model_prefill"
			lastContentEntry.ProjectionMode = vcp.CapabilityOmitted
			lastContentEntry.ExecutionEquivalence = vcp.EquivalenceNone
			lastContentEntry.RuleID = "google_aistudio.trailing_model_prefill.omitted.v1"
			report.ConversionSummary = appendSafeSummary(report.ConversionSummary, "google_aistudio.trailing_model_prefill.omitted")
		}
	}
	if len(upstream.Contents) == 0 {
		return ProjectedRequest{}, fmt.Errorf("%w: generateContent requires at least one remaining content turn", ErrUnsupportedContext)
	}
	if len(referenceSet.references) > 0 {
		report.ConversionSummary = appendSafeSummary(report.ConversionSummary, "google_aistudio.function_name.normalization.tracked")
	}
	projection := vcp.ProjectionPlan{ProjectionID: projectionID, LineageID: lineageID, Entries: append([]vcp.ProjectionEntry(nil), ledger.Entries...)}
	return ProjectedRequest{Upstream: upstream, CapabilityPlan: plan, ProjectionPlan: projection, Ledger: ledger, Report: report, ToolReferences: referenceSet.referencesInOrder()}, nil
}

// ProjectCountTokensRequest compiles the same typed generation input into the documented countTokens envelope.
// ProjectCountTokensRequest 将相同的类型化生成输入编译为文档化的 countTokens 信封。
func ProjectCountTokensRequest(request vcp.VulcanRequest, target resolve.Target, capabilities ProfileCapabilities, lineageID string, now time.Time) (ProjectedRequest, CountTokensRequest, error) {
	// countRequest intentionally disables only response streaming because countTokens has no response stream.
	// countRequest 有意仅禁用响应流，因为 countTokens 没有响应流。
	countRequest := request
	countRequest.Stream = false
	projected, errProject := ProjectRequest(countRequest, target, capabilities, lineageID, now)
	if errProject != nil {
		return ProjectedRequest{}, CountTokensRequest{}, errProject
	}
	return projected, CountTokensRequest{GenerateContentRequest: projected.Upstream}, nil
}

// validateTarget verifies every exact routing boundary required by the AI Studio profile.
// validateTarget 校验 AI Studio Profile 所需的每个精确路由边界。
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

// capabilityAvailability converts verified AI Studio behavior into VCP planning evidence.
// capabilityAvailability 将经过验证的 AI Studio 行为转换为 VCP 规划证据。
func capabilityAvailability(request vcp.VulcanRequest, capabilities ProfileCapabilities) []vcp.CapabilityAvailability {
	// projectionNative reports whether every instruction requiring placement preservation has a native carrier.
	// projectionNative 报告每个需要位置保留的指令是否都有原生载体。
	projectionNative := true
	// projectionTriggered records whether VCP needs to decide ordered context projection at all.
	// projectionTriggered 记录 VCP 是否需要决定有序上下文投影。
	projectionTriggered := false
	for _, item := range request.Context {
		switch {
		case item.Kind == vcp.ContextDelegatedResult:
			projectionTriggered = true
			projectionNative = false
		case item.Kind == vcp.ContextInstruction && item.Authority == vcp.AuthoritySystem && item.Placement == vcp.PlacementPreamble:
			projectionTriggered = true
			projectionNative = projectionNative && capabilities.NativeSystemInstruction
		case item.Kind == vcp.ContextInstruction:
			projectionTriggered = true
			projectionNative = false
		}
	}
	// reasoningNative evaluates the request-specific subset of thinking controls that this exact target has verified.
	// reasoningNative 评估该精确 Target 已验证的请求特定推理控制子集。
	reasoningNative := capabilities.NativeReasoning
	if request.ReasoningPolicy.Summary {
		reasoningNative = reasoningNative && capabilities.NativeReasoningSummary
	}
	if request.ReasoningPolicy.Effort != "" {
		reasoningNative = reasoningNative && capabilities.supportsThinkingLevel(request.ReasoningPolicy.Effort)
	}
	availability := []vcp.CapabilityAvailability{
		{Feature: vcp.FeatureStructuredToolCalling, Native: capabilities.StructuredTools},
		{Feature: vcp.FeatureParallelToolCalling, Native: capabilities.ParallelTools},
		{Feature: vcp.FeatureStreamingToolArguments, Native: capabilities.StreamingToolArguments},
		{Feature: vcp.FeatureStrictSchema, Native: capabilities.StrictJSONSchema},
		{Feature: vcp.FeatureReasoning, Native: reasoningNative},
		{Feature: vcp.FeatureReasoningContinuation, Native: false},
		{Feature: vcp.FeatureExplicitPromptCache, Native: false},
		{Feature: vcp.FeatureRemoteCompaction, Native: false},
		{Feature: vcp.FeatureNativeWebSearch, Native: false},
		{Feature: vcp.FeatureImageInput, Native: capabilities.supportsMediaInput(vcp.MediaImage)}, {Feature: vcp.FeatureAudioInput, Native: capabilities.supportsMediaInput(vcp.MediaAudio)},
		{Feature: vcp.FeatureVideoInput, Native: capabilities.supportsMediaInput(vcp.MediaVideo)}, {Feature: vcp.FeatureFileInput, Native: capabilities.supportsMediaInput(vcp.MediaFile)},
	}
	if projectionTriggered {
		availability = append(availability, vcp.CapabilityAvailability{Feature: vcp.FeatureOrderedContextProjection, Native: projectionNative, Projected: request.CapabilityPolicy.AllowAdvisoryInstructionProjection})
	}
	return availability
}

// supportsMediaInput reports whether the wire profile explicitly accepts one media family.
// supportsMediaInput 报告线路 Profile 是否明确接受一种媒体类别。
func (c ProfileCapabilities) supportsMediaInput(kind vcp.MediaKind) bool {
	for _, supported := range c.MediaInputKinds {
		if supported == kind {
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

// projectGeneration maps the VCP generation controls that the selected capability plan permits.
// projectGeneration 映射已被选定能力计划允许的 VCP 生成控制。
func projectGeneration(upstream *GenerateContentRequest, request vcp.VulcanRequest, plan vcp.CapabilityPlan, capabilities ProfileCapabilities) error {
	if upstream == nil {
		return fmt.Errorf("%w: upstream request is required", ErrUnsupportedContext)
	}
	config := GenerationConfig{
		Temperature:     request.GenerationPolicy.Temperature,
		TopP:            request.GenerationPolicy.TopP,
		MaxOutputTokens: request.GenerationPolicy.MaxOutputTokens,
		StopSequences:   append([]string(nil), request.GenerationPolicy.Stop...),
	}
	if len(request.GenerationPolicy.StrictJSONSchema) > 0 {
		if !capabilitySelected(plan, vcp.FeatureStrictSchema, vcp.CapabilityNative) {
			return fmt.Errorf("%w: strict JSON Schema was not selected natively", ErrUnsupportedContext)
		}
		config.ResponseMIMEType = "application/json"
		config.ResponseJSONSchema = append([]byte(nil), request.GenerationPolicy.StrictJSONSchema...)
	}
	if request.ReasoningPolicy.Effort != "" || request.ReasoningPolicy.Summary {
		if !capabilitySelected(plan, vcp.FeatureReasoning, vcp.CapabilityNative) {
			return fmt.Errorf("%w: requested reasoning controls were not selected natively", ErrUnsupportedContext)
		}
		thinking := ThinkingConfig{}
		if request.ReasoningPolicy.Effort != "" {
			if !capabilities.supportsThinkingLevel(request.ReasoningPolicy.Effort) {
				return fmt.Errorf("%w: thinking level %q is not verified for this target", ErrUnsupportedContext, request.ReasoningPolicy.Effort)
			}
			thinking.ThinkingLevel = request.ReasoningPolicy.Effort
		}
		if request.ReasoningPolicy.Summary {
			if !capabilities.NativeReasoningSummary {
				return fmt.Errorf("%w: visible reasoning summaries are not verified for this target", ErrUnsupportedContext)
			}
			includeThoughts := true
			thinking.IncludeThoughts = &includeThoughts
		}
		config.ThinkingConfig = &thinking
	}
	if config.Temperature != nil || config.TopP != nil || config.MaxOutputTokens != nil || len(config.StopSequences) > 0 || len(config.ResponseJSONSchema) > 0 || config.ThinkingConfig != nil {
		upstream.GenerationConfig = &config
	}
	return nil
}

// supportsThinkingLevel reports whether one exact caller-selected level was verified for the resolved target.
// supportsThinkingLevel 报告一个精确调用方选定等级是否已针对已解析 Target 验证。
func (c ProfileCapabilities) supportsThinkingLevel(level string) bool {
	for _, supported := range c.ThinkingLevels {
		if supported == level {
			return true
		}
	}
	return false
}

// toolReferenceSet maintains exact canonical and normalized wire identities while rejecting lossy collisions.
// toolReferenceSet 在拒绝有损冲突的同时维护精确规范与规范化 wire 身份。
type toolReferenceSet struct {
	// byCanonical maps a namespace/name pair to its unique wire reference.
	// byCanonical 将命名空间/名称对映射到其唯一 wire 引用。
	byCanonical map[string]ToolReference
	// byWire maps a normalized wire name back to exactly one canonical reference.
	// byWire 将规范化 wire 名称映射回唯一规范引用。
	byWire map[string]ToolReference
	// references retains declaration order for deterministic output restoration.
	// references 为确定性输出恢复保留声明顺序。
	references []ToolReference
}

// toolCallReference binds a historical VCP call ID to the exact Gemini function identity.
// toolCallReference 将历史 VCP 调用 ID 绑定到精确 Gemini 函数身份。
type toolCallReference struct {
	// Reference identifies the canonical and wire function names.
	// Reference 标识规范和 wire 函数名称。
	Reference ToolReference
	// UpstreamCallID is the exact correlated provider call identifier when present.
	// UpstreamCallID 是存在时精确关联的 Provider 调用标识。
	UpstreamCallID string
}

// newToolReferenceSet constructs empty typed identity indexes.
// newToolReferenceSet 构建空的类型化身份索引。
func newToolReferenceSet() *toolReferenceSet {
	return &toolReferenceSet{byCanonical: make(map[string]ToolReference), byWire: make(map[string]ToolReference)}
}

// projectTools converts supported VCP function declarations and their exact selection policy.
// projectTools 转换受支持的 VCP 函数声明及其精确选择策略。
func projectTools(upstream *GenerateContentRequest, request vcp.VulcanRequest, references *toolReferenceSet) error {
	if upstream == nil || references == nil {
		return fmt.Errorf("%w: tool projection requires request and identity state", ErrUnsupportedContext)
	}
	if len(request.Tools) == 0 {
		return nil
	}
	declarations := make([]FunctionDeclaration, 0, len(request.Tools))
	for _, tool := range request.Tools {
		if tool.Kind != vcp.ToolFunction {
			return fmt.Errorf("%w: tool %q kind %q has no AI Studio function representation", ErrUnsupportedContext, tool.Name, tool.Kind)
		}
		if tool.Strict {
			return fmt.Errorf("%w: function tool %q requests strict schema but AI Studio has no verified strict function-schema carrier", ErrUnsupportedContext, tool.Name)
		}
		reference, errReference := references.ensure(tool.Namespace, tool.Name)
		if errReference != nil {
			return errReference
		}
		declarations = append(declarations, FunctionDeclaration{Name: reference.WireName, Description: tool.Description, ParametersJSONSchema: append([]byte(nil), tool.Parameters...)})
	}
	upstream.Tools = []Tool{{FunctionDeclarations: declarations}}
	choice := request.ToolPolicy.Choice
	if choice == "" {
		choice = vcp.ToolChoiceAuto
	}
	configuration := FunctionCallingConfig{}
	switch choice {
	case vcp.ToolChoiceAuto:
		configuration.Mode = "AUTO"
	case vcp.ToolChoiceNone:
		configuration.Mode = "NONE"
	case vcp.ToolChoiceRequired:
		configuration.Mode = "ANY"
	case vcp.ToolChoiceNamed:
		// namedReferences resolves only an unambiguous declaration because ToolPolicy has no namespace field.
		// namedReferences 仅解析无歧义声明，因为 ToolPolicy 没有命名空间字段。
		namedReferences := matchingToolReferences(request.Tools, request.ToolPolicy.NamedTool, references)
		if len(namedReferences) != 1 {
			return fmt.Errorf("%w: named tool must match exactly one declaration", ErrUnsupportedContext)
		}
		configuration.Mode = "ANY"
		configuration.AllowedFunctionNames = []string{namedReferences[0].WireName}
	default:
		return fmt.Errorf("%w: unsupported tool choice %q", ErrUnsupportedContext, choice)
	}
	upstream.ToolConfig = &ToolConfig{FunctionCallingConfig: configuration}
	return nil
}

// matchingToolReferences finds every declared exact VCP tool name in deterministic declaration order.
// matchingToolReferences 按确定性声明顺序查找每个已声明的精确 VCP 工具名称。
func matchingToolReferences(tools []vcp.ToolDefinition, name string, references *toolReferenceSet) []ToolReference {
	matched := make([]ToolReference, 0, 1)
	for _, tool := range tools {
		if tool.Name != name {
			continue
		}
		if reference, exists := references.byCanonical[toolIdentity(tool.Namespace, tool.Name)]; exists {
			matched = append(matched, reference)
		}
	}
	return matched
}

// projectItem maps one canonical item to one exact AI Studio carrier and ledger decision.
// projectItem 将一个规范项目映射到一个精确 AI Studio 载体和账本决策。
func projectItem(item vcp.ContextItem, request vcp.VulcanRequest, plan vcp.CapabilityPlan, capabilities ProfileCapabilities, lineageID string, position int, references *toolReferenceSet, calls map[string]toolCallReference, materialized map[string]resource.MaterializedInput) (Content, string, vcp.CapabilityMode, vcp.ExecutionEquivalence, string, string, string, bool, error) {
	// Client and audit scopes are Router-local, so sending them upstream would violate the VCP visibility boundary.
	// 客户端和审计作用域仅限 Router 本地，因此将其发送上游会违反 VCP 可见性边界。
	if item.Visibility != vcp.VisibilityModel {
		return Content{}, "omitted:visibility", vcp.CapabilityOmitted, vcp.EquivalenceNone, "google_aistudio.visibility.omitted.v1", "", "", false, nil
	}
	if item.ProviderStateRef != "" {
		return Content{}, "", "", "", "", "", "", false, fmt.Errorf("%w: opaque provider state has no AI Studio request carrier", ErrUnsupportedContext)
	}
	text, errText := vcp.TextContent(item.Content)
	userMediaMessage := item.Kind == vcp.ContextMessage && item.Authority == vcp.AuthorityUser && hasResourceContent(item.Content)
	if errText != nil && item.Kind != vcp.ContextToolCall && !userMediaMessage {
		return Content{}, "", "", "", "", "", "", false, fmt.Errorf("%w: item %q: %v", ErrUnsupportedContext, item.ItemID, errText)
	}
	switch item.Kind {
	case vcp.ContextInstruction:
		if item.Authority == vcp.AuthoritySystem && item.Placement == vcp.PlacementPreamble && capabilities.NativeSystemInstruction {
			return Content{Parts: []Part{{Text: text}}}, "systemInstruction:parts", vcp.CapabilityNative, vcp.EquivalenceEquivalent, "google_aistudio.system_instruction.native.v1", "", "", false, nil
		}
		return projectFrame(item, request, lineageID, position)
	case vcp.ContextDelegatedResult:
		return projectFrame(item, request, lineageID, position)
	case vcp.ContextMessage:
		if item.Authority == vcp.AuthorityUser {
			parts, errParts := projectUserParts(item.Content, materialized)
			if errParts != nil {
				return Content{}, "", "", "", "", "", "", false, errParts
			}
			return Content{Role: "user", Parts: parts}, "contents:user", vcp.CapabilityNative, vcp.EquivalenceEquivalent, "google_aistudio.user.media.native.v1", "", "", true, nil
		}
		return Content{Role: "model", Parts: []Part{{Text: text}}}, "contents:model", vcp.CapabilityNative, vcp.EquivalenceEquivalent, "google_aistudio.model.native.v1", "", "", true, nil
	case vcp.ContextToolCall:
		if item.ToolCall == nil {
			return Content{}, "", "", "", "", "", "", false, fmt.Errorf("%w: tool call payload is required", ErrUnsupportedContext)
		}
		reference, errReference := references.ensure(item.ToolCall.Namespace, item.ToolCall.Name)
		if errReference != nil {
			return Content{}, "", "", "", "", "", "", false, errReference
		}
		arguments := item.ToolCall.Arguments
		if strings.TrimSpace(arguments) == "" {
			arguments = "{}"
		}
		if !isJSONObject(arguments) {
			return Content{}, "", "", "", "", "", "", false, fmt.Errorf("%w: tool call %q arguments must be a JSON object", ErrUnsupportedContext, item.ToolCall.ToolCallID)
		}
		// upstreamCallID preserves only the provider-issued identifier and remains absent when Gemini supplied none.
		// upstreamCallID 仅保留 Provider 签发的标识；Gemini 未提供时保持缺失。
		upstreamCallID := item.ToolCall.UpstreamID
		calls[item.ToolCall.ToolCallID] = toolCallReference{Reference: reference, UpstreamCallID: upstreamCallID}
		return Content{Role: "model", Parts: []Part{{FunctionCall: &FunctionCall{ID: upstreamCallID, Name: reference.WireName, Args: []byte(arguments)}}}}, "contents:model.functionCall", vcp.CapabilityNative, vcp.EquivalenceEquivalent, "google_aistudio.function_call.native.v1", "", "", true, nil
	case vcp.ContextToolResult:
		if item.ToolResult == nil {
			return Content{}, "", "", "", "", "", "", false, fmt.Errorf("%w: tool result payload is required", ErrUnsupportedContext)
		}
		call, exists := calls[item.ToolResult.ToolCallID]
		if !exists {
			return Content{}, "", "", "", "", "", "", false, fmt.Errorf("%w: tool result %q has no prior exact tool call", ErrUnsupportedContext, item.ItemID)
		}
		responseBody := functionResultBody(text)
		// Google accepts function responses as a user turn after the preceding model call.
		// Google 将函数响应作为紧随前序 model 调用的 user 轮次接收。
		return Content{Role: "user", Parts: []Part{{FunctionResponse: &FunctionResponse{ID: call.UpstreamCallID, Name: call.Reference.WireName, Response: responseBody}}}}, "contents:user.functionResponse", vcp.CapabilityNative, vcp.EquivalenceEquivalent, "google_aistudio.function_response.native.v1", "", "", true, nil
	case vcp.ContextReasoning:
		if item.Reasoning == nil {
			return Content{}, "", "", "", "", "", "", false, fmt.Errorf("%w: reasoning payload is required", ErrUnsupportedContext)
		}
		if item.ProviderStateRef != "" || item.Reasoning.ContinuationRef != "" {
			return Content{}, "", "", "", "", "", "", false, fmt.Errorf("%w: opaque reasoning continuation has no AI Studio continuation carrier", ErrUnsupportedContext)
		}
		if !capabilitySelected(plan, vcp.FeatureReasoning, vcp.CapabilityNative) {
			return Content{}, "omitted:reasoning", vcp.CapabilityOmitted, vcp.EquivalenceNone, "google_aistudio.reasoning.omitted.v1", "", "", false, nil
		}
		return Content{Role: "model", Parts: []Part{{Text: text, Thought: true}}}, "contents:model.thought", vcp.CapabilityNative, vcp.EquivalenceEquivalent, "google_aistudio.reasoning.native.v1", "", "", true, nil
	case vcp.ContextRefusal:
		return Content{Role: "model", Parts: []Part{{Text: text}}}, "contents:model.refusal_text", vcp.CapabilityProjected, vcp.EquivalenceAdvisory, "google_aistudio.refusal.projected_text.v1", "", "", true, nil
	default:
		return Content{}, "", "", "", "", "", "", false, fmt.Errorf("%w: context kind %q", ErrUnsupportedContext, item.Kind)
	}
}

// hasResourceContent reports whether one ordered VCP block list contains media.
// hasResourceContent 报告一个有序 VCP 内容块列表是否包含媒体。
func hasResourceContent(blocks []vcp.ContentBlock) bool {
	for _, block := range blocks {
		if block.ResourceRef != "" {
			return true
		}
	}
	return false
}

// projectUserParts preserves mixed text and media order using only accepted materializations.
// projectUserParts 仅使用已接受物化结果保留混合文本与媒体顺序。
func projectUserParts(blocks []vcp.ContentBlock, materialized map[string]resource.MaterializedInput) ([]Part, error) {
	parts := make([]Part, 0, len(blocks))
	for _, block := range blocks {
		if block.Type == vcp.ContentText {
			parts = append(parts, Part{Text: vcp.EscapeReservedFrameText(block.Text)})
			continue
		}
		input, exists := materialized[block.ResourceRef]
		if !exists {
			return nil, fmt.Errorf("%w: resource %q has no accepted materialization", ErrUnsupportedContext, block.ResourceRef)
		}
		if !contentTypeMatchesMedia(block.Type, input.Kind) {
			return nil, fmt.Errorf("%w: resource %q media kind differs from its content block", ErrUnsupportedContext, block.ResourceRef)
		}
		if block.MediaRole != input.Role {
			return nil, fmt.Errorf("%w: resource %q media role differs from its accepted input plan", ErrUnsupportedContext, block.ResourceRef)
		}
		switch input.Mode {
		case catalog.MaterializationInlineBase64:
			if input.InlineBase64 == "" {
				return nil, fmt.Errorf("%w: inline materialization is empty", ErrUnsupportedContext)
			}
			parts = append(parts, Part{InlineData: &InlineData{MIMEType: input.MIMEType, Data: input.InlineBase64}})
		case catalog.MaterializationProviderFileID, catalog.MaterializationProviderAssetID, catalog.MaterializationProviderObjectURI:
			if input.ProviderHandle == "" {
				return nil, fmt.Errorf("%w: provider materialization handle is empty", ErrUnsupportedContext)
			}
			parts = append(parts, Part{FileData: &FileData{MIMEType: input.MIMEType, FileURI: input.ProviderHandle}})
		default:
			return nil, fmt.Errorf("%w: materialization mode %q has no Gemini content carrier", ErrUnsupportedContext, input.Mode)
		}
	}
	if len(parts) == 0 {
		return nil, fmt.Errorf("%w: user content is empty", ErrUnsupportedContext)
	}
	return parts, nil
}

// contentTypeMatchesMedia verifies the VCP block and planned media kind agree exactly.
// contentTypeMatchesMedia 校验 VCP 内容块与规划媒体类型精确一致。
func contentTypeMatchesMedia(contentType vcp.ContentType, kind vcp.MediaKind) bool {
	switch contentType {
	case vcp.ContentImage:
		return kind == vcp.MediaImage
	case vcp.ContentAudio:
		return kind == vcp.MediaAudio
	case vcp.ContentVideo:
		return kind == vcp.MediaVideo
	case vcp.ContentFile:
		return kind == vcp.MediaFile
	default:
		return false
	}
}

// projectFrame encodes only VCP-registered advisory frame kinds into a user text carrier.
// projectFrame 仅将 VCP 已注册的建议性 Frame 类型编码到 user 文本载体。
func projectFrame(item vcp.ContextItem, request vcp.VulcanRequest, lineageID string, position int) (Content, string, vcp.CapabilityMode, vcp.ExecutionEquivalence, string, string, string, bool, error) {
	if !request.CapabilityPolicy.AllowAdvisoryInstructionProjection {
		return Content{}, "", "", "", "", "", "", false, fmt.Errorf("%w: advisory instruction projection is disabled", ErrUnsupportedContext)
	}
	frameID := vcp.DeriveID("frm", lineageID, item.ItemID)
	encoded, frame, errFrame := vcp.EncodeFrame(item, frameID)
	if errFrame != nil {
		return Content{}, "", "", "", "", "", "", false, fmt.Errorf("%w: item %q: %v", ErrUnsupportedContext, item.ItemID, errFrame)
	}
	return Content{Role: "user", Parts: []Part{{Text: encoded}}}, "contents:user.vulcan_frame", vcp.CapabilityProjected, vcp.EquivalenceAdvisory, "google_aistudio.context_frame.projected.v1", frame.FrameID, frame.Digest, true, nil
}

// toolIdentity returns a collision-free internal key for one canonical namespace and name pair.
// toolIdentity 为一个规范命名空间和名称对返回无冲突的内部键。
func toolIdentity(namespace string, name string) string {
	return namespace + "\x00" + name
}

// ensure returns one existing or newly verified canonical-to-wire function reference.
// ensure 返回一个现有或新验证的规范到 wire 函数引用。
func (s *toolReferenceSet) ensure(namespace string, name string) (ToolReference, error) {
	if s == nil {
		return ToolReference{}, fmt.Errorf("%w: tool identity state is required", ErrUnsupportedContext)
	}
	canonicalKey := toolIdentity(namespace, name)
	if existing, exists := s.byCanonical[canonicalKey]; exists {
		return existing, nil
	}
	wireName, errName := normalizedFunctionName(namespace, name)
	if errName != nil {
		return ToolReference{}, errName
	}
	if existing, exists := s.byWire[wireName]; exists {
		return ToolReference{}, fmt.Errorf("%w: canonical tools %q and %q normalize to the same Gemini function name %q", ErrUnsupportedContext, toolIdentity(existing.Namespace, existing.Name), canonicalKey, wireName)
	}
	reference := ToolReference{WireName: wireName, Namespace: namespace, Name: name}
	s.byCanonical[canonicalKey] = reference
	s.byWire[wireName] = reference
	s.references = append(s.references, reference)
	return reference, nil
}

// referencesInOrder returns an isolated deterministic tool-reference sequence.
// referencesInOrder 返回隔离且确定性的工具引用序列。
func (s *toolReferenceSet) referencesInOrder() []ToolReference {
	if s == nil {
		return nil
	}
	return append([]ToolReference(nil), s.references...)
}

// normalizedFunctionName adapts the source-verified Gemini function-name constraint while preserving an exact reversible reference.
// normalizedFunctionName 在保留精确可逆引用的前提下改编来源已验证的 Gemini 函数名称约束。
func normalizedFunctionName(namespace string, name string) (string, error) {
	if strings.TrimSpace(name) == "" {
		return "", fmt.Errorf("%w: function name is required", ErrUnsupportedContext)
	}
	canonicalName := name
	if namespace != "" {
		canonicalName = namespace + "." + name
	}
	var normalized strings.Builder
	for _, character := range canonicalName {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '_' || character == '.' || character == ':' || character == '-' {
			normalized.WriteRune(character)
			continue
		}
		normalized.WriteByte('_')
	}
	result := normalized.String()
	if result == "" {
		result = "_"
	}
	first, _ := utf8.DecodeRuneInString(result)
	if !((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') || first == '_') {
		result = "_" + result
	}
	if len(result) > 64 {
		result = result[:64]
	}
	return result, nil
}

// isJSONObject verifies the exact JSON object requirement for Gemini function arguments.
// isJSONObject 校验 Gemini 函数参数要求的精确 JSON 对象。
func isJSONObject(value string) bool {
	trimmed := strings.TrimSpace(value)
	return len(trimmed) >= 2 && trimmed[0] == '{' && trimmed[len(trimmed)-1] == '}' && jsonValidObject([]byte(trimmed))
}

// jsonValidObject verifies an object without introducing a generic execution representation.
// jsonValidObject 在不引入通用执行表示的前提下校验对象。
func jsonValidObject(value []byte) bool {
	var object json.RawMessage
	if errDecode := json.Unmarshal(value, &object); errDecode != nil {
		return false
	}
	trimmed := strings.TrimSpace(string(object))
	return len(trimmed) >= 2 && trimmed[0] == '{' && trimmed[len(trimmed)-1] == '}'
}

// functionResultBody wraps the VCP text result in the required typed Gemini function-response object.
// functionResultBody 将 VCP 文本结果包装为必需的类型化 Gemini 函数响应对象。
func functionResultBody(text string) json.RawMessage {
	// resultBody remains a closed local wire type rather than a generic map.
	// resultBody 保持为封闭的本地 wire 类型，而不是通用 map。
	type resultBody struct {
		// Result preserves the exact VCP text payload.
		// Result 保留精确 VCP 文本载荷。
		Result string `json:"result"`
	}
	encoded, _ := json.Marshal(resultBody{Result: text})
	return encoded
}

// appendSafeSummary appends one stable public-safe conversion code at most once.
// appendSafeSummary 至多一次追加一个稳定且公开安全的转换代码。
func appendSafeSummary(summary []string, code string) []string {
	for _, existing := range summary {
		if existing == code {
			return summary
		}
	}
	return append(summary, code)
}
