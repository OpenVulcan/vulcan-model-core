package vcp

import (
	"sort"
	"time"
)

// PlanCapabilities derives and freezes only capabilities triggered by the request.
// PlanCapabilities 仅推导并冻结请求实际触发的能力。
func PlanCapabilities(request VulcanRequest, availability []CapabilityAvailability, catalogRevision uint64, generatedAt time.Time) (CapabilityPlan, error) {
	if errValidate := request.Validate(); errValidate != nil {
		return CapabilityPlan{}, errValidate
	}
	// demandsByFeature merges payload derivation with explicit policy strengthening.
	// demandsByFeature 将载荷推导与显式策略加强合并。
	demandsByFeature := make(map[CapabilityFeature]CapabilityDemand)
	for _, demand := range deriveDemands(request) {
		demandsByFeature[demand.Feature] = demand
	}
	for _, demand := range request.CapabilityPolicy.ExplicitDemands {
		existing, exists := demandsByFeature[demand.Feature]
		if !exists || demand.Level == DemandRequired || existing.Level != DemandRequired {
			demand.Source = "policy"
			if len(demand.AcceptedModes) == 0 {
				demand.AcceptedModes = []CapabilityMode{CapabilityNative, CapabilityProjected}
			}
			demandsByFeature[demand.Feature] = demand
		}
	}
	// availabilityByFeature provides verified target support without probing unused features.
	// availabilityByFeature 提供经过验证的目标支持且不探测未使用能力。
	availabilityByFeature := make(map[CapabilityFeature]CapabilityAvailability, len(availability))
	for _, supported := range availability {
		availabilityByFeature[supported.Feature] = supported
	}
	features := make([]string, 0, len(demandsByFeature))
	for feature := range demandsByFeature {
		features = append(features, string(feature))
	}
	sort.Strings(features)
	plan := CapabilityPlan{RequestID: request.RequestID, CatalogRevision: catalogRevision, GeneratedAt: generatedAt}
	for _, featureName := range features {
		feature := CapabilityFeature(featureName)
		demand := demandsByFeature[feature]
		supported := availabilityByFeature[feature]
		demand.SelectedMode = selectCapabilityMode(demand, supported, request.CapabilityPolicy)
		plan.Demands = append(plan.Demands, demand)
	}
	return plan, nil
}

// HasBlocked reports whether the frozen plan contains an unavailable hard requirement.
// HasBlocked 报告冻结计划是否包含不可用硬需求。
func (p CapabilityPlan) HasBlocked() bool {
	for _, demand := range p.Demands {
		if demand.SelectedMode == CapabilityBlocked {
			return true
		}
	}
	return false
}

// Decision returns the selected mode for one triggered capability.
// Decision 返回一个已触发能力的选定模式。
func (p CapabilityPlan) Decision(feature CapabilityFeature) (CapabilityMode, bool) {
	for _, demand := range p.Demands {
		if demand.Feature == feature {
			return demand.SelectedMode, true
		}
	}
	return "", false
}

// ToExecutionDecisions converts internal demands into a client-safe summary.
// ToExecutionDecisions 将内部需求转换为客户端安全摘要。
func (p CapabilityPlan) ToExecutionDecisions() []CapabilityDecision {
	decisions := make([]CapabilityDecision, 0, len(p.Demands))
	for _, demand := range p.Demands {
		equivalence := EquivalenceNone
		if demand.SelectedMode == CapabilityNative {
			equivalence = EquivalenceEquivalent
		} else if demand.SelectedMode == CapabilityProjected {
			equivalence = EquivalenceAdvisory
		}
		decisions = append(decisions, CapabilityDecision{
			Feature: demand.Feature, SelectedMode: demand.SelectedMode,
			ExecutionEquivalence: equivalence, ReasonCode: "capability_plan." + string(demand.SelectedMode),
		})
	}
	return decisions
}

// deriveDemands derives capabilities exclusively from active request payload and policy.
// deriveDemands 仅从实际请求载荷与策略推导能力。
func deriveDemands(request VulcanRequest) []CapabilityDemand {
	// demands stores only capabilities that the payload actually uses.
	// demands 仅存储载荷实际使用的能力。
	demands := make([]CapabilityDemand, 0)
	needsProjection := false
	mediaFeatures := make(map[CapabilityFeature]struct{})
	needsReasoning := request.ReasoningPolicy.Effort != "" || request.ReasoningPolicy.Summary
	needsStrictSchema := len(request.GenerationPolicy.StrictJSONSchema) > 0
	needsContinuation := request.ReasoningPolicy.ContinuationID != ""
	for _, item := range request.Context {
		// Non-model items remain in the Router ledger but must never create upstream capability demands.
		// 非模型可见项目保留在 Router 账本中，但绝不能产生上游能力需求。
		if item.Visibility != VisibilityModel {
			continue
		}
		if item.Kind == ContextDelegatedResult || item.Kind == ContextInstruction {
			needsProjection = true
		}
		if item.Kind == ContextReasoning {
			needsReasoning = true
			if item.ProviderStateRef != "" || (item.Reasoning != nil && item.Reasoning.ContinuationRef != "") {
				needsContinuation = true
			}
		}
		for _, block := range item.Content {
			switch block.Type {
			case ContentImage:
				mediaFeatures[FeatureImageInput] = struct{}{}
			case ContentAudio:
				mediaFeatures[FeatureAudioInput] = struct{}{}
			case ContentVideo:
				mediaFeatures[FeatureVideoInput] = struct{}{}
			case ContentFile:
				mediaFeatures[FeatureFileInput] = struct{}{}
			}
		}
	}
	if needsProjection {
		demands = append(demands, preferredDemand(FeatureOrderedContextProjection, true))
	}
	if len(request.Tools) > 0 {
		demands = append(demands, requiredDemand(FeatureStructuredToolCalling, false))
		for _, tool := range request.Tools {
			if tool.Strict {
				needsStrictSchema = true
				break
			}
		}
		if request.ToolPolicy.Parallel {
			demands = append(demands, requiredDemand(FeatureParallelToolCalling, false))
		}
		if request.ToolPolicy.StreamArguments {
			demands = append(demands, requiredDemand(FeatureStreamingToolArguments, false))
		}
	}
	if needsStrictSchema {
		demands = append(demands, requiredDemand(FeatureStrictSchema, false))
	}
	mediaNames := make([]string, 0, len(mediaFeatures))
	for feature := range mediaFeatures {
		mediaNames = append(mediaNames, string(feature))
	}
	sort.Strings(mediaNames)
	for _, featureName := range mediaNames {
		demands = append(demands, requiredDemand(CapabilityFeature(featureName), false))
	}
	if request.CachePolicy.Strategy != "" && request.CachePolicy.Strategy != CacheRegular {
		if request.CachePolicy.OnUnsupported == CacheUnsupportedUseRegular {
			demands = append(demands, preferredDemand(FeatureExplicitPromptCache, false))
		} else {
			demands = append(demands, requiredDemand(FeatureExplicitPromptCache, false))
		}
	}
	if request.RemoteCompaction != nil {
		demands = append(demands, requiredDemand(FeatureRemoteCompaction, false))
	} else if request.ContextManagementPolicy.Mode == ContextManagementAuto {
		demands = append(demands, preferredDemand(FeatureRemoteCompaction, false))
	}
	for _, tool := range request.Tools {
		if tool.Kind == ToolNativeWebSearch {
			demands = append(demands, requiredDemand(FeatureNativeWebSearch, false))
			break
		}
	}
	if needsReasoning {
		demands = append(demands, preferredDemand(FeatureReasoning, false))
	}
	if needsContinuation {
		demands = append(demands, requiredDemand(FeatureReasoningContinuation, false))
	}
	return demands
}

// requiredDemand creates a hard payload-derived capability demand.
// requiredDemand 创建硬性载荷推导能力需求。
func requiredDemand(feature CapabilityFeature, projected bool) CapabilityDemand {
	modes := []CapabilityMode{CapabilityNative}
	if projected {
		modes = append(modes, CapabilityProjected)
	}
	return CapabilityDemand{Feature: feature, Source: "payload", Level: DemandRequired, AcceptedModes: modes, OnUnavailable: "reroute_same_provider"}
}

// preferredDemand creates an optional payload-derived capability demand.
// preferredDemand 创建可选载荷推导能力需求。
func preferredDemand(feature CapabilityFeature, projected bool) CapabilityDemand {
	demand := requiredDemand(feature, projected)
	demand.Level = DemandPreferred
	return demand
}

// selectCapabilityMode applies native, projected, omitted, and blocked ordering.
// selectCapabilityMode 应用原生、投影、省略和阻止顺序。
func selectCapabilityMode(demand CapabilityDemand, supported CapabilityAvailability, policy CapabilityPolicy) CapabilityMode {
	if supported.Native && acceptsMode(demand.AcceptedModes, CapabilityNative) {
		return CapabilityNative
	}
	if policy.ExecutionMode != CapabilityNativeOnly && supported.Projected && acceptsMode(demand.AcceptedModes, CapabilityProjected) {
		return CapabilityProjected
	}
	if demand.Level == DemandPreferred && policy.OptionalOnUnsupported != OptionalFail {
		return CapabilityOmitted
	}
	return CapabilityBlocked
}

// acceptsMode reports whether a demand accepts one execution representation.
// acceptsMode 报告需求是否接受一种执行表示。
func acceptsMode(modes []CapabilityMode, expected CapabilityMode) bool {
	for _, mode := range modes {
		if mode == expected {
			return true
		}
	}
	return false
}
