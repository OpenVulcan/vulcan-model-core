package vcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrInvalidRequest reports a malformed VCP request.
	// ErrInvalidRequest 表示 VCP 请求格式错误。
	ErrInvalidRequest = errors.New("invalid VCP request")
	// ErrCapabilityUnavailable reports a blocked request capability.
	// ErrCapabilityUnavailable 表示请求能力被阻止。
	ErrCapabilityUnavailable = errors.New("capability unavailable")
)

// Validate verifies the closed VCP request and canonical ordering invariants.
// Validate 校验封闭 VCP 请求和规范顺序不变量。
func (r VulcanRequest) Validate() error {
	if r.ProtocolVersion != ProtocolVersion {
		return fmt.Errorf("%w: unsupported protocol_version %q", ErrInvalidRequest, r.ProtocolVersion)
	}
	if strings.TrimSpace(r.RequestID) == "" {
		return fmt.Errorf("%w: request_id is required", ErrInvalidRequest)
	}
	if !validModelTarget(r.ModelSelection.Target) {
		return fmt.Errorf("%w: invalid model target %q", ErrInvalidRequest, r.ModelSelection.Target)
	}
	if r.ModelSelection.Target == ModelTargetExact && (strings.TrimSpace(r.ModelSelection.ProviderInstanceID) == "" || strings.TrimSpace(r.ModelSelection.ProviderModelID) == "") {
		return fmt.Errorf("%w: exact model selection requires provider_instance_id and provider_model_id", ErrInvalidRequest)
	}
	if r.ReasoningPolicy.ContinuationID != "" && len(r.Context) != 0 {
		return fmt.Errorf("%w: continuation and full canonical context are mutually exclusive", ErrInvalidRequest)
	}
	if r.ReasoningPolicy.Summary && strings.TrimSpace(r.ReasoningPolicy.SummaryMode) != "" {
		return fmt.Errorf("%w: reasoning summary and summary_mode are mutually exclusive", ErrInvalidRequest)
	}
	if r.ReasoningPolicy.SummaryMode != strings.TrimSpace(r.ReasoningPolicy.SummaryMode) {
		return fmt.Errorf("%w: reasoning summary_mode cannot contain surrounding whitespace", ErrInvalidRequest)
	}
	switch r.ReasoningPolicy.SummaryMode {
	case "", "auto", "concise", "detailed":
	default:
		return fmt.Errorf("%w: reasoning summary_mode %q is invalid", ErrInvalidRequest, r.ReasoningPolicy.SummaryMode)
	}
	if r.RemoteCompaction != nil && r.RemoteCompaction.PreviousResponseID != "" && len(r.RemoteCompaction.Context) != 0 {
		return fmt.Errorf("%w: remote compaction requires previous_response_id or context, not both", ErrInvalidRequest)
	}
	if r.RemoteCompaction != nil && r.RemoteCompaction.PreviousResponseID == "" && len(r.RemoteCompaction.Context) == 0 {
		return fmt.Errorf("%w: remote compaction requires previous_response_id or context", ErrInvalidRequest)
	}
	if errContext := ValidateContext(r.Context); errContext != nil {
		return errContext
	}
	if r.RemoteCompaction != nil && len(r.RemoteCompaction.Context) > 0 {
		if errContext := ValidateContext(r.RemoteCompaction.Context); errContext != nil {
			return fmt.Errorf("%w: remote compaction context: %v", ErrInvalidRequest, errContext)
		}
	}
	for index := range r.Tools {
		if errTool := validateTool(r.Tools[index]); errTool != nil {
			return fmt.Errorf("%w: tool %d: %v", ErrInvalidRequest, index, errTool)
		}
	}
	if len(r.Tools) == 0 && (r.ToolPolicy.Parallel || r.ToolPolicy.StreamArguments || r.ToolPolicy.Choice == ToolChoiceNamed || r.ToolPolicy.Choice == ToolChoiceRequired) {
		return fmt.Errorf("%w: tool policy requires non-empty tools", ErrInvalidRequest)
	}
	if !validToolChoice(r.ToolPolicy.Choice) {
		return fmt.Errorf("%w: invalid tool choice %q", ErrInvalidRequest, r.ToolPolicy.Choice)
	}
	if r.ToolPolicy.Choice == ToolChoiceNamed && strings.TrimSpace(r.ToolPolicy.NamedTool) == "" {
		return fmt.Errorf("%w: named tool choice requires named_tool", ErrInvalidRequest)
	}
	if r.ToolPolicy.Choice == ToolChoiceNamed {
		matched := false
		for _, tool := range r.Tools {
			if tool.Name == r.ToolPolicy.NamedTool {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("%w: named tool choice does not reference a declared tool", ErrInvalidRequest)
		}
	}
	if r.GenerationPolicy.Temperature != nil && (*r.GenerationPolicy.Temperature < 0 || *r.GenerationPolicy.Temperature > 2) {
		return fmt.Errorf("%w: temperature must be between 0 and 2", ErrInvalidRequest)
	}
	if r.GenerationPolicy.TopP != nil && (*r.GenerationPolicy.TopP <= 0 || *r.GenerationPolicy.TopP > 1) {
		return fmt.Errorf("%w: top_p must be greater than 0 and at most 1", ErrInvalidRequest)
	}
	if r.GenerationPolicy.MaxOutputTokens != nil && *r.GenerationPolicy.MaxOutputTokens <= 0 {
		return fmt.Errorf("%w: max_output_tokens must be positive", ErrInvalidRequest)
	}
	if len(r.GenerationPolicy.StrictJSONSchema) > 0 && !validJSONObject(r.GenerationPolicy.StrictJSONSchema) {
		return fmt.Errorf("%w: strict_json_schema must be a JSON object", ErrInvalidRequest)
	}
	if !validCachePolicy(r.CachePolicy) {
		return fmt.Errorf("%w: invalid cache policy", ErrInvalidRequest)
	}
	if r.ContextManagementPolicy.Mode != "" && r.ContextManagementPolicy.Mode != ContextManagementRegular && r.ContextManagementPolicy.Mode != ContextManagementAuto {
		return fmt.Errorf("%w: invalid context management mode %q", ErrInvalidRequest, r.ContextManagementPolicy.Mode)
	}
	if r.CapabilityPolicy.ExecutionMode != "" && r.CapabilityPolicy.ExecutionMode != CapabilityMaximize && r.CapabilityPolicy.ExecutionMode != CapabilityNativeOnly {
		return fmt.Errorf("%w: invalid capability execution mode %q", ErrInvalidRequest, r.CapabilityPolicy.ExecutionMode)
	}
	if r.CapabilityPolicy.OptionalOnUnsupported != "" && r.CapabilityPolicy.OptionalOnUnsupported != OptionalOmit && r.CapabilityPolicy.OptionalOnUnsupported != OptionalUseRegular && r.CapabilityPolicy.OptionalOnUnsupported != OptionalFail {
		return fmt.Errorf("%w: invalid optional capability policy %q", ErrInvalidRequest, r.CapabilityPolicy.OptionalOnUnsupported)
	}
	for index := range r.CapabilityPolicy.ExplicitDemands {
		if errDemand := validateExplicitCapabilityDemand(r.CapabilityPolicy.ExplicitDemands[index]); errDemand != nil {
			return fmt.Errorf("%w: explicit capability demand %d: %v", ErrInvalidRequest, index, errDemand)
		}
	}
	return nil
}

// validToolChoice reports whether a tool choice is empty-defaulted or registered.
// validToolChoice 报告工具选择是否为空默认值或已注册值。
func validToolChoice(choice ToolChoiceMode) bool {
	return choice == "" || choice == ToolChoiceAuto || choice == ToolChoiceNone || choice == ToolChoiceRequired || choice == ToolChoiceNamed
}

// validCachePolicy reports whether cache strategy and unsupported behavior are registered.
// validCachePolicy 报告缓存策略和不支持行为是否已注册。
func validCachePolicy(policy CachePolicy) bool {
	validStrategy := policy.Strategy == "" || policy.Strategy == CacheRegular || policy.Strategy == CacheDisabled || policy.Strategy == CacheStablePrefix || policy.Strategy == CacheRollingPerTurn || policy.Strategy == CacheManualBreakpoints
	validUnsupported := policy.OnUnsupported == "" || policy.OnUnsupported == CacheUnsupportedReject || policy.OnUnsupported == CacheUnsupportedUseRegular
	return validStrategy && validUnsupported
}

// ValidateContext verifies stable identities, monotonic sequence, variants, and relations.
// ValidateContext 校验稳定身份、单调顺序、变体和关联关系。
func ValidateContext(items []ContextItem) error {
	// seenIDs records canonical identities already available to relation checks.
	// seenIDs 记录已可供关联校验使用的规范身份。
	seenIDs := make(map[string]struct{}, len(items))
	// seenToolCallIDs records prior structured calls available to tool results.
	// seenToolCallIDs 记录可供工具结果关联的先前结构化调用。
	seenToolCallIDs := make(map[string]struct{})
	var previousSequence uint64
	for index := range items {
		// item is the current canonical item under validation.
		// item 是当前正在校验的规范项目。
		item := items[index]
		if strings.TrimSpace(item.ItemID) == "" {
			return fmt.Errorf("%w: context item %d has no item_id", ErrInvalidRequest, index)
		}
		if _, exists := seenIDs[item.ItemID]; exists {
			return fmt.Errorf("%w: duplicate item_id %q", ErrInvalidRequest, item.ItemID)
		}
		if item.Sequence == 0 || (index > 0 && item.Sequence <= previousSequence) {
			return fmt.Errorf("%w: context sequence must be globally increasing", ErrInvalidRequest)
		}
		if errItem := validateContextItem(item); errItem != nil {
			return fmt.Errorf("%w: item %q: %v", ErrInvalidRequest, item.ItemID, errItem)
		}
		if item.Kind == ContextToolResult {
			if _, exists := seenToolCallIDs[item.ToolResult.ToolCallID]; !exists {
				return fmt.Errorf("%w: tool result %q references unavailable prior tool call %q", ErrInvalidRequest, item.ItemID, item.ToolResult.ToolCallID)
			}
		}
		for _, relationID := range append([]string{item.ParentItemID, item.ReplyToItemID, item.Activation.AfterItemID}, item.OrderingConstraints...) {
			if relationID == "" {
				continue
			}
			if _, exists := seenIDs[relationID]; !exists {
				return fmt.Errorf("%w: item %q references unavailable prior item %q", ErrInvalidRequest, item.ItemID, relationID)
			}
		}
		if item.Kind == ContextToolCall {
			if _, exists := seenToolCallIDs[item.ToolCall.ToolCallID]; exists {
				return fmt.Errorf("%w: duplicate tool_call_id %q", ErrInvalidRequest, item.ToolCall.ToolCallID)
			}
			seenToolCallIDs[item.ToolCall.ToolCallID] = struct{}{}
		}
		seenIDs[item.ItemID] = struct{}{}
		previousSequence = item.Sequence
	}
	return nil
}

// validModelTarget reports whether a model target mode is registered.
// validModelTarget 报告模型目标模式是否已注册。
func validModelTarget(mode ModelTargetMode) bool {
	return mode == ModelTargetExact || mode == ModelTargetAlias || mode == ModelTargetAuto
}

// validActor reports whether a context producer is registered by VCP 1.0.
// validActor 报告上下文生产者是否已在 VCP 1.0 中注册。
func validActor(actor Actor) bool {
	return actor == ActorPlatform || actor == ActorApplication || actor == ActorEndUser || actor == ActorPrimaryAssistant || actor == ActorDelegatedAgent || actor == ActorTool || actor == ActorProvider
}

// validAuthority reports whether an instruction authority is registered by VCP 1.0.
// validAuthority 报告指令权限是否已在 VCP 1.0 中注册。
func validAuthority(authority Authority) bool {
	return authority == AuthoritySystem || authority == AuthorityDeveloper || authority == AuthorityUser || authority == AuthorityAssistant || authority == AuthorityTool || authority == AuthorityNone
}

// validDelegatedResultKind reports whether a delegated result shape is registered.
// validDelegatedResultKind 报告委派结果形态是否已注册。
func validDelegatedResultKind(kind DelegatedResultKind) bool {
	return kind == DelegatedReport || kind == DelegatedTaskOutput || kind == DelegatedToolBackedResult
}

// validToolCallStatus reports whether an input tool lifecycle state is empty-defaulted or registered.
// validToolCallStatus 报告输入工具生命周期状态是否为空默认值或已注册值。
func validToolCallStatus(status ToolCallStatus) bool {
	return status == "" || status == ToolCallPending || status == ToolCallCompleted || status == ToolCallIncomplete
}

// validCapabilityFeature reports whether a capability is registered by VCP 1.0.
// validCapabilityFeature 报告能力是否已在 VCP 1.0 中注册。
func validCapabilityFeature(feature CapabilityFeature) bool {
	switch feature {
	case FeatureOrderedContextProjection, FeatureStructuredToolCalling, FeatureParallelToolCalling, FeatureStreamingToolArguments, FeatureStrictSchema, FeatureImageInput, FeatureAudioInput, FeatureVideoInput, FeatureFileInput, FeatureExplicitPromptCache, FeatureRemoteCompaction, FeatureNativeWebSearch, FeatureReasoning, FeatureReasoningContinuation:
		return true
	default:
		return false
	}
}

// validAcceptedCapabilityMode reports whether a demand accepts a selectable execution representation.
// validAcceptedCapabilityMode 报告需求是否接受可选择的执行表示。
func validAcceptedCapabilityMode(mode CapabilityMode) bool {
	return mode == CapabilityNative || mode == CapabilityProjected
}

// validateExplicitCapabilityDemand verifies caller-provided capability strengthening.
// validateExplicitCapabilityDemand 校验调用方提供的能力加强要求。
func validateExplicitCapabilityDemand(demand CapabilityDemand) error {
	if !validCapabilityFeature(demand.Feature) {
		return fmt.Errorf("invalid capability feature %q", demand.Feature)
	}
	if demand.Level != DemandRequired && demand.Level != DemandPreferred {
		return fmt.Errorf("invalid demand level %q", demand.Level)
	}
	for _, mode := range demand.AcceptedModes {
		if !validAcceptedCapabilityMode(mode) {
			return fmt.Errorf("invalid accepted capability mode %q", mode)
		}
	}
	return nil
}

// validateContextItem verifies one closed context item variant.
// validateContextItem 校验一个封闭上下文项目变体。
func validateContextItem(item ContextItem) error {
	if !validAuthority(item.Authority) {
		return fmt.Errorf("invalid authority %q", item.Authority)
	}
	if !validActor(item.Actor) {
		return fmt.Errorf("invalid actor %q", item.Actor)
	}
	if item.Placement != PlacementPreamble && item.Placement != PlacementTranscript {
		return fmt.Errorf("invalid placement %q", item.Placement)
	}
	if item.Activation.Mode != ActivationRequestStart && item.Activation.Mode != ActivationAfterItem {
		return fmt.Errorf("invalid activation %q", item.Activation.Mode)
	}
	if item.Activation.Mode == ActivationAfterItem && item.Activation.AfterItemID == "" {
		return errors.New("after_item_id activation requires an anchor")
	}
	if item.Visibility != VisibilityModel && item.Visibility != VisibilityClient && item.Visibility != VisibilityAuditOnly {
		return fmt.Errorf("invalid visibility %q", item.Visibility)
	}
	for index := range item.Content {
		if errContent := validateContent(item.Content[index]); errContent != nil {
			return fmt.Errorf("content %d: %v", index, errContent)
		}
	}
	// populatedVariants counts tagged-union payloads to enforce exact ownership.
	// populatedVariants 统计带标签联合载荷以强制唯一归属。
	populatedVariants := 0
	for _, populated := range []bool{item.Instruction != nil, item.Message != nil, item.DelegatedResult != nil, item.ToolCall != nil, item.ToolResult != nil, item.Reasoning != nil, item.Refusal != nil} {
		if populated {
			populatedVariants++
		}
	}
	if populatedVariants != 1 {
		return errors.New("exactly one item payload must be populated")
	}
	switch item.Kind {
	case ContextInstruction:
		if item.Instruction == nil || (item.Authority != AuthoritySystem && item.Authority != AuthorityDeveloper) {
			return errors.New("instruction requires instruction payload and system or developer authority")
		}
	case ContextMessage:
		if item.Message == nil || (item.Authority != AuthorityUser && item.Authority != AuthorityAssistant) {
			return errors.New("message requires message payload and user or assistant authority")
		}
	case ContextDelegatedResult:
		if item.DelegatedResult == nil || item.Actor != ActorDelegatedAgent || item.DelegationID == "" {
			return errors.New("delegated_result requires delegated agent actor and delegation_id")
		}
		if !validDelegatedResultKind(item.DelegatedResult.ResultKind) {
			return fmt.Errorf("invalid delegated result kind %q", item.DelegatedResult.ResultKind)
		}
	case ContextToolCall:
		if item.ToolCall == nil || item.ToolCall.ToolCallID == "" {
			return errors.New("tool_call requires a stable tool_call_id")
		}
		if !validToolCallStatus(item.ToolCall.Status) {
			return fmt.Errorf("invalid tool call status %q", item.ToolCall.Status)
		}
	case ContextToolResult:
		if item.ToolResult == nil || item.ToolResult.ToolCallID == "" {
			return errors.New("tool_result requires a parent tool_call_id")
		}
	case ContextReasoning:
		if item.Reasoning == nil {
			return errors.New("reasoning payload is required")
		}
	case ContextRefusal:
		if item.Refusal == nil {
			return errors.New("refusal payload is required")
		}
	default:
		return fmt.Errorf("unknown context kind %q", item.Kind)
	}
	return nil
}

// validateContent verifies one registered content block.
// validateContent 校验一个已注册内容块。
func validateContent(block ContentBlock) error {
	switch block.Type {
	case ContentText, ContentCitation, ContentRefusal:
		if block.Text == "" {
			return errors.New("textual content must not be empty")
		}
	case ContentImage, ContentAudio, ContentVideo, ContentFile:
		if strings.TrimSpace(block.ResourceRef) == "" {
			return errors.New("resource content requires resource_ref")
		}
	case ContentRegisteredExtension:
		if block.ExtensionID == "" || !validJSONObject(block.Extension) {
			return errors.New("registered extension requires extension_id and an object payload")
		}
	default:
		return fmt.Errorf("unknown content type %q", block.Type)
	}
	return nil
}

// validateTool verifies one tool declaration without accepting arbitrary execution fields.
// validateTool 校验工具声明且不接受任意执行字段。
func validateTool(tool ToolDefinition) error {
	if tool.Kind != ToolFunction && tool.Kind != ToolCustom && tool.Kind != ToolNativeWebSearch {
		return fmt.Errorf("unknown tool kind %q", tool.Kind)
	}
	if strings.TrimSpace(tool.Name) == "" {
		return errors.New("name is required")
	}
	if tool.Strict && tool.Kind != ToolFunction {
		return errors.New("strict schema is only supported for function tools")
	}
	if tool.Kind == ToolFunction && !validJSONObject(tool.Parameters) {
		return errors.New("function parameters must be a JSON object")
	}
	return nil
}

// validJSONObject reports whether raw JSON contains exactly one object.
// validJSONObject 报告原始 JSON 是否恰好包含一个对象。
func validJSONObject(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	// object is used only to validate JSON Schema syntax, never as an execution protocol.
	// object 仅用于校验 JSON Schema 语法，绝不作为执行协议。
	var object map[string]json.RawMessage
	if errDecode := json.Unmarshal(raw, &object); errDecode != nil || object == nil {
		return false
	}
	return true
}
