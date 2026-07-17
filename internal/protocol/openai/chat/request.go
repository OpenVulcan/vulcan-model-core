package chat

import (
	"fmt"
	"strings"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// ProjectRequest compiles one VCP request for an exact already-resolved target.
// ProjectRequest 为一个已精确解析的目标编译 VCP 请求。
func ProjectRequest(request vcp.VulcanRequest, target resolve.Target, capabilities ProfileCapabilities, lineageID string, now time.Time) (ProjectedRequest, error) {
	if errTarget := validateTarget(target); errTarget != nil {
		return ProjectedRequest{}, errTarget
	}
	if lineageID == "" {
		return ProjectedRequest{}, fmt.Errorf("%w: lineage_id is required", ErrInvalidTarget)
	}
	availability := capabilityAvailability(request, capabilities)
	plan, errPlan := vcp.PlanCapabilities(request, availability, target.CatalogRevision, now)
	if errPlan != nil {
		return ProjectedRequest{}, errPlan
	}
	if errBinding := validateSelectionBinding(request.ModelSelection, target); errBinding != nil {
		return ProjectedRequest{}, errBinding
	}
	if plan.HasBlocked() {
		return ProjectedRequest{}, fmt.Errorf("%w: request has blocked capability demand", vcp.ErrCapabilityUnavailable)
	}
	projectionID := vcp.DeriveID("prj", request.RequestID, lineageID, target.ProviderInstanceID, target.ChannelID, target.EndpointID, target.CredentialID, target.UpstreamModelID)
	ledger := vcp.ProjectionLedger{LedgerID: vcp.DeriveID("ldg", projectionID), ProjectionID: projectionID, LineageID: lineageID}
	upstream := Request{
		Model: target.UpstreamModelID, Stream: request.Stream,
		Temperature: request.GenerationPolicy.Temperature, TopP: request.GenerationPolicy.TopP,
		MaxCompletionTokens: request.GenerationPolicy.MaxOutputTokens, Stop: append([]string(nil), request.GenerationPolicy.Stop...),
	}
	if request.Stream && capabilities.StreamUsage {
		upstream.StreamOptions = &StreamOptions{IncludeUsage: true}
	}
	if len(request.Tools) > 0 {
		upstream.Tools = make([]Tool, 0, len(request.Tools))
		for _, tool := range request.Tools {
			if tool.Kind != vcp.ToolFunction {
				return ProjectedRequest{}, fmt.Errorf("%w: tool kind %q is not a Chat function", ErrUnsupportedContext, tool.Kind)
			}
			upstream.Tools = append(upstream.Tools, Tool{Type: "function", Function: FunctionDefinition{Name: tool.Name, Description: tool.Description, Parameters: tool.Parameters, Strict: tool.Strict}})
		}
		choice := request.ToolPolicy.Choice
		if choice == "" {
			choice = vcp.ToolChoiceAuto
		}
		upstream.ToolChoice = &ToolChoice{Mode: choice, FunctionName: request.ToolPolicy.NamedTool}
		parallel := request.ToolPolicy.Parallel
		upstream.ParallelToolCalls = &parallel
	}
	if len(request.GenerationPolicy.StrictJSONSchema) > 0 {
		upstream.ResponseFormat = &ResponseFormat{Type: "json_schema", JSONSchema: request.GenerationPolicy.StrictJSONSchema}
	}
	for _, item := range request.Context {
		position := len(upstream.Messages)
		message, mode, equivalence, ruleID, frameID, digest, include, errMessage := projectItem(item, request, capabilities, lineageID, position)
		if errMessage != nil {
			return ProjectedRequest{}, errMessage
		}
		if include {
			upstream.Messages = append(upstream.Messages, message)
		} else {
			position = -1
		}
		entry := vcp.ProjectionEntry{
			ProjectionID: projectionID, LineageID: lineageID, CanonicalItemID: item.ItemID,
			CanonicalSequence: item.Sequence, CanonicalKind: item.Kind, SourceAuthority: item.Authority,
			CarrierProtocol: "openai_chat", CarrierRoleOrSlot: message.Role, UpstreamPosition: position,
			ProjectionMode: mode, ExecutionEquivalence: equivalence, RuleID: ruleID, RuleVersion: "1",
			FrameID: frameID, ContentDigest: digest, DecodePolicy: "replay_only", OriginalItem: item,
			CreatedAt: now, ExpiresAt: now.Add(24 * time.Hour),
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

// validateTarget verifies every exact routing boundary needed by the profile.
// validateTarget 校验 Profile 所需的每个精确路由边界。
func validateTarget(target resolve.Target) error {
	if strings.TrimSpace(target.ProviderDefinitionID) == "" || strings.TrimSpace(target.ProviderInstanceID) == "" || strings.TrimSpace(target.ChannelID) == "" || strings.TrimSpace(target.EndpointID) == "" || strings.TrimSpace(target.CredentialID) == "" || strings.TrimSpace(target.ProviderModelID) == "" || strings.TrimSpace(target.ExecutionProfileID) == "" || strings.TrimSpace(target.UpstreamModelID) == "" {
		return fmt.Errorf("%w: provider, channel, endpoint, credential, model, and profile must be exact", ErrInvalidTarget)
	}
	return nil
}

// validateSelectionBinding prevents a resolved target from escaping caller-selected provider boundaries.
// validateSelectionBinding 防止已解析目标逸出调用方选择的供应商边界。
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

// capabilityAvailability converts verified Profile behavior into request planning evidence.
// capabilityAvailability 将经过验证的 Profile 行为转换为请求规划证据。
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
		{Feature: vcp.FeatureReasoningContinuation, Native: false},
		{Feature: vcp.FeatureExplicitPromptCache, Native: false},
		{Feature: vcp.FeatureRemoteCompaction, Native: false},
		{Feature: vcp.FeatureNativeWebSearch, Native: false},
		{Feature: vcp.FeatureImageInput, Native: false}, {Feature: vcp.FeatureAudioInput, Native: false},
		{Feature: vcp.FeatureVideoInput, Native: false}, {Feature: vcp.FeatureFileInput, Native: false},
	}
	if projectionTriggered {
		availability = append(availability, vcp.CapabilityAvailability{Feature: vcp.FeatureOrderedContextProjection, Native: projectionNative, Projected: request.CapabilityPolicy.AllowAdvisoryInstructionProjection})
	}
	return availability
}

// projectItem maps one canonical item to one exact Chat carrier and ledger decision.
// projectItem 将一个规范项目映射到一个精确 Chat 载体和账本决策。
func projectItem(item vcp.ContextItem, request vcp.VulcanRequest, capabilities ProfileCapabilities, lineageID string, position int) (Message, vcp.CapabilityMode, vcp.ExecutionEquivalence, string, string, string, bool, error) {
	text, errText := vcp.TextContent(item.Content)
	if errText != nil && item.Kind != vcp.ContextToolCall {
		return Message{}, "", "", "", "", "", false, fmt.Errorf("%w: item %q: %v", ErrUnsupportedContext, item.ItemID, errText)
	}
	switch item.Kind {
	case vcp.ContextInstruction:
		if item.Authority == vcp.AuthoritySystem && item.Placement == vcp.PlacementPreamble && capabilities.NativeSystemPreamble {
			return Message{Role: "system", Content: text}, vcp.CapabilityNative, vcp.EquivalenceEquivalent, "openai_chat.system_preamble.native.v1", "", "", true, nil
		}
		if item.Authority == vcp.AuthorityDeveloper && capabilities.NativeDeveloper {
			return Message{Role: "developer", Content: text}, vcp.CapabilityNative, vcp.EquivalenceEquivalent, "openai_chat.developer.native.v1", "", "", true, nil
		}
		if item.Authority == vcp.AuthoritySystem && item.Placement == vcp.PlacementTranscript && capabilities.NativeInlineSystem {
			return Message{Role: "system", Content: text}, vcp.CapabilityNative, vcp.EquivalenceEquivalent, "openai_chat.system_inline.native.v1", "", "", true, nil
		}
		return projectFrame(item, request, lineageID, position)
	case vcp.ContextDelegatedResult:
		return projectFrame(item, request, lineageID, position)
	case vcp.ContextMessage:
		if item.Authority == vcp.AuthorityUser {
			return Message{Role: "user", Content: vcp.EscapeReservedFrameText(text)}, vcp.CapabilityNative, vcp.EquivalenceEquivalent, "openai_chat.user.native.v1", "", "", true, nil
		}
		return Message{Role: "assistant", Content: text}, vcp.CapabilityNative, vcp.EquivalenceEquivalent, "openai_chat.assistant.native.v1", "", "", true, nil
	case vcp.ContextToolCall:
		if item.ToolCall == nil {
			return Message{}, "", "", "", "", "", false, fmt.Errorf("%w: missing tool call payload", ErrUnsupportedContext)
		}
		call := ToolCall{ID: item.ToolCall.ToolCallID, Type: "function", Function: FunctionCall{Name: item.ToolCall.Name, Arguments: item.ToolCall.Arguments}}
		return Message{Role: "assistant", ToolCalls: []ToolCall{call}}, vcp.CapabilityNative, vcp.EquivalenceEquivalent, "openai_chat.tool_call.native.v1", "", "", true, nil
	case vcp.ContextToolResult:
		return Message{Role: "tool", ToolCallID: item.ToolResult.ToolCallID, Content: text}, vcp.CapabilityNative, vcp.EquivalenceEquivalent, "openai_chat.tool_result.native.v1", "", "", true, nil
	case vcp.ContextReasoning:
		if capabilities.Reasoning && item.Reasoning != nil && item.Reasoning.Summary {
			return Message{Role: "assistant", Content: text}, vcp.CapabilityNative, vcp.EquivalenceEquivalent, "openai_chat.reasoning_summary.native.v1", "", "", true, nil
		}
		return Message{}, vcp.CapabilityOmitted, vcp.EquivalenceNone, "openai_chat.reasoning.omitted.v1", "", "", false, nil
	case vcp.ContextRefusal:
		return Message{Role: "assistant", Content: text}, vcp.CapabilityNative, vcp.EquivalenceEquivalent, "openai_chat.refusal_history.native.v1", "", "", true, nil
	default:
		return Message{}, "", "", "", "", "", false, fmt.Errorf("%w: kind %q", ErrUnsupportedContext, item.Kind)
	}
}

// projectFrame creates an independent advisory user carrier or an explicit omission.
// projectFrame 创建独立建议性 user 载体或显式省略。
func projectFrame(item vcp.ContextItem, request vcp.VulcanRequest, lineageID string, position int) (Message, vcp.CapabilityMode, vcp.ExecutionEquivalence, string, string, string, bool, error) {
	if !request.CapabilityPolicy.AllowAdvisoryInstructionProjection {
		return Message{}, vcp.CapabilityOmitted, vcp.EquivalenceNone, "openai_chat.context.omitted.v1", "", "", false, nil
	}
	frameID := vcp.DeriveID("frm", lineageID, item.ItemID, fmt.Sprint(item.Sequence), fmt.Sprint(position))
	encoded, frame, errFrame := vcp.EncodeFrame(item, frameID)
	if errFrame != nil {
		return Message{}, "", "", "", "", "", false, errFrame
	}
	ruleID := "openai_chat." + frame.Kind + ".frame.v1"
	return Message{Role: "user", Content: encoded}, vcp.CapabilityProjected, vcp.EquivalenceAdvisory, ruleID, frameID, frame.Digest, true, nil
}
