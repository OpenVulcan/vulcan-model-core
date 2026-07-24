package management

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	provideralibaba "github.com/OpenVulcan/vulcan-model-core/internal/provider/alibaba"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/alibaba/catalogdata"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

const (
	// alibabaCatalogChannelID identifies facts that have not yet been bound to an executable wire contract.
	// alibabaCatalogChannelID 标识尚未绑定到可执行 Wire 合同的事实。
	alibabaCatalogChannelID = "alibaba.catalog"
	// alibabaCatalogEvidenceRevision identifies the first complete CN and Singapore baselines.
	// alibabaCatalogEvidenceRevision 标识首份完整 CN 与 Singapore 基线。
	alibabaCatalogEvidenceRevision = 1
)

// isAlibabaCatalogID reports whether one catalog belongs to the policy-controlled Alibaba family.
// isAlibabaCatalogID 报告一个目录是否属于策略控制的 Alibaba 系列。
func isAlibabaCatalogID(catalogID string) bool {
	return strings.HasPrefix(catalogID, "alibaba_")
}

// alibabaStaticCatalogSourceRevision returns the exact committed content revision for one verified Alibaba catalog.
// alibabaStaticCatalogSourceRevision 返回一个已验证 Alibaba 目录的精确已提交内容修订。
func alibabaStaticCatalogSourceRevision(catalogID string) (string, bool, error) {
	snapshot, verified, errSnapshot := catalogdata.SnapshotForCatalogID(catalogID)
	if errSnapshot != nil {
		return "", false, errSnapshot
	}
	if !verified {
		return "", false, nil
	}
	return snapshot.SourceRevision, true, nil
}

// isAlibabaModelStudioCatalogID reports whether one catalog owns the native Model Studio service APIs.
// isAlibabaModelStudioCatalogID 报告一个目录是否拥有原生 Model Studio 服务 API。
func isAlibabaModelStudioCatalogID(catalogID string) bool {
	switch catalogID {
	case "alibaba_model_studio_cn", "alibaba_model_studio_sg_domestic", "alibaba_model_studio_workspace_sg":
		return true
	default:
		return false
	}
}

// appendAlibabaGeneratedCatalog merges all provider facts while preserving explicit executable templates.
// appendAlibabaGeneratedCatalog 合并全部供应商事实，同时保留显式可执行模板。
func appendAlibabaGeneratedCatalog(snapshot catalog.Snapshot, definition providerconfig.ProviderDefinition) (catalog.Snapshot, error) {
	providerSnapshot, verified, errSnapshot := catalogdata.SnapshotForCatalogID(definition.ModelCatalogID)
	if errSnapshot != nil {
		return catalog.Snapshot{}, fmt.Errorf("load Alibaba generated catalog %q: %w", definition.ModelCatalogID, errSnapshot)
	}
	if !verified {
		return snapshot, nil
	}
	policySet, errPolicies := catalogdata.LoadOperationPolicies()
	if errPolicies != nil {
		return catalog.Snapshot{}, fmt.Errorf("load Alibaba operation policies: %w", errPolicies)
	}
	policyEntries, errPolicyEntries := policySet.EntryMap()
	if errPolicyEntries != nil {
		return catalog.Snapshot{}, fmt.Errorf("index Alibaba operation policies: %w", errPolicyEntries)
	}
	modelIDByUpstream := make(map[string]string, len(snapshot.Models)+len(providerSnapshot.Models))
	for _, model := range snapshot.Models {
		if existingID, exists := modelIDByUpstream[model.UpstreamModelID]; exists && existingID != model.ID {
			return catalog.Snapshot{}, fmt.Errorf("Alibaba catalog contains multiple model records for upstream ID %q", model.UpstreamModelID)
		}
		modelIDByUpstream[model.UpstreamModelID] = model.ID
	}
	policyByModelOperation, errPolicyIndex := indexAlibabaModelOperationPolicies(snapshot.ModelOperationPolicies, snapshot.Offerings, definition.ProtocolProfileID)
	if errPolicyIndex != nil {
		return catalog.Snapshot{}, errPolicyIndex
	}
	offeringIndexByID := make(map[string]int, len(snapshot.Offerings))
	for index, offering := range snapshot.Offerings {
		offeringIndexByID[offering.ID] = index
	}
	for _, fact := range providerSnapshot.Models {
		modelID, exists := modelIDByUpstream[fact.ModelID]
		if !exists {
			modelID = alibabaGeneratedID("model_alibaba_", definition.ModelCatalogID, fact.ModelID)
			snapshot.Models = append(snapshot.Models, catalog.ProviderModel{ID: modelID, ProviderInstanceID: snapshot.ProviderInstanceID, UpstreamModelID: fact.ModelID, DisplayName: fact.DisplayName, Source: catalog.ModelSourceSystem, EntitlementMode: catalog.EntitlementAllBoundCredentials, Revision: 1})
			modelIDByUpstream[fact.ModelID] = modelID
		}
		operations := alibabaCatalogOperations(fact)
		if len(operations) == 0 {
			continue
		}
		for _, operation := range operations {
			policyEntry, policyExists := policyEntries[catalogdata.OperationPolicyKey(definition.ModelCatalogID, fact.ModelID, operation)]
			if !policyExists {
				return catalog.Snapshot{}, fmt.Errorf("Alibaba catalog operation %q/%q/%q has no explicit policy", definition.ModelCatalogID, fact.ModelID, operation)
			}
			modelOperationKey := alibabaModelOperationKey(modelID, operation)
			if policyIndex, supported := policyByModelOperation[modelOperationKey]; supported {
				if policyEntry.Status != catalog.ModelOperationSupported || snapshot.ModelOperationPolicies[policyIndex].Status != catalog.ModelOperationSupported {
					return catalog.Snapshot{}, fmt.Errorf("Alibaba executable operation %q/%q/%q conflicts with policy status %q", definition.ModelCatalogID, fact.ModelID, operation, policyEntry.Status)
				}
				snapshot.ModelOperationPolicies[policyIndex].Reason = policyEntry.Reason
				snapshot.ModelOperationPolicies[policyIndex].EvidenceRevision = policyEntry.EvidenceRevision
				offeringID := snapshot.ModelOperationPolicies[policyIndex].OfferingID
				offeringIndex, offeringExists := offeringIndexByID[offeringID]
				if !offeringExists {
					return catalog.Snapshot{}, fmt.Errorf("Alibaba policy %q references an absent offering", snapshot.ModelOperationPolicies[policyIndex].ID)
				}
				snapshot.Offerings[offeringIndex].Capabilities = mergeAlibabaCatalogCapabilities(snapshot.Offerings[offeringIndex].Capabilities, fact)
				if errProfiles := applyAlibabaExecutableProfileFacts(&snapshot, offeringID, operation, fact); errProfiles != nil {
					return catalog.Snapshot{}, errProfiles
				}
				snapshot.RateLimits = append(snapshot.RateLimits, alibabaRateLimits(snapshot.ProviderInstanceID, offeringID, providerSnapshot, fact)...)
				continue
			}
			if policyEntry.Status == catalog.ModelOperationSupported {
				return catalog.Snapshot{}, fmt.Errorf("Alibaba supported operation %q/%q/%q has no executable system template", definition.ModelCatalogID, fact.ModelID, operation)
			}
			offeringID := alibabaGeneratedID("offer_alibaba_", definition.ModelCatalogID, fact.ModelID, string(operation))
			capabilities := alibabaCatalogCapabilities(fact)
			snapshot.Offerings = append(snapshot.Offerings, catalog.ModelOffering{ID: offeringID, ProviderInstanceID: snapshot.ProviderInstanceID, ProviderModelID: modelID, ChannelID: alibabaCatalogChannelID, UpstreamModelID: fact.ModelID, Capabilities: capabilities, CapabilityRevision: alibabaCatalogEvidenceRevision, Revision: 1})
			offeringIndexByID[offeringID] = len(snapshot.Offerings) - 1
			policy := catalog.ModelOperationPolicy{ID: alibabaGeneratedID("policy_alibaba_", definition.ModelCatalogID, fact.ModelID, string(operation)), ProviderInstanceID: snapshot.ProviderInstanceID, ProviderModelID: modelID, OfferingID: offeringID, Operation: operation, Status: policyEntry.Status, Reason: policyEntry.Reason, Source: catalog.ModelSourceSystem, EvidenceRevision: policyEntry.EvidenceRevision, Revision: 1}
			snapshot.ModelOperationPolicies = append(snapshot.ModelOperationPolicies, policy)
			policyByModelOperation[modelOperationKey] = len(snapshot.ModelOperationPolicies) - 1
			snapshot.RateLimits = append(snapshot.RateLimits, alibabaRateLimits(snapshot.ProviderInstanceID, offeringID, providerSnapshot, fact)...)
		}
	}
	return snapshot, nil
}

// alibabaCatalogOperations classifies every independently proven operation without collapsing multimodal records.
// alibabaCatalogOperations 分类每个独立证明的操作，且不会折叠多模态记录。
func alibabaCatalogOperations(fact catalogdata.ModelFact) []vcp.OperationKind {
	return catalogdata.ClassifiedOperations(fact)
}

// alibabaCatalogCapabilities maps only structured provider facts and leaves missing limits unknown.
// alibabaCatalogCapabilities 仅映射结构化供应商事实，并让缺失限制保持未知。
func alibabaCatalogCapabilities(fact catalogdata.ModelFact) catalog.ModelCapabilities {
	capabilities := catalog.ModelCapabilities{
		ToolCalling: catalog.CapabilityUnknown, ParallelToolCalls: catalog.CapabilityUnknown, StreamingToolArguments: catalog.CapabilityUnknown,
		StrictJSONSchema: catalog.CapabilityUnknown, Reasoning: catalog.CapabilityUnknown,
		InputModalities: append([]string(nil), fact.RequestModalities...), OutputModalities: append([]string(nil), fact.ResponseModalities...),
	}
	if slices.Contains(fact.Features, "function-calling") {
		capabilities.ToolCalling = catalog.CapabilityNative
	}
	if slices.Contains(fact.Features, "structured-outputs") {
		capabilities.StrictJSONSchema = catalog.CapabilityNative
	}
	if slices.Contains(fact.Capabilities, "Reasoning") {
		capabilities.Reasoning = catalog.CapabilityNative
	}
	applyAlibabaTokenFacts(&capabilities, fact)
	return capabilities
}

// mergeAlibabaCatalogCapabilities enriches executable evidence only with same-boundary structured facts.
// mergeAlibabaCatalogCapabilities 仅使用同边界结构化事实增强可执行证据。
func mergeAlibabaCatalogCapabilities(capabilities catalog.ModelCapabilities, fact catalogdata.ModelFact) catalog.ModelCapabilities {
	merged := catalog.CloneModelCapabilities(capabilities)
	// explicitMaximumInput preserves a stricter operation-level input contract than the provider's broader model context fact.
	// explicitMaximumInput 保留比供应商较宽模型上下文事实更严格的操作级输入合同。
	explicitMaximumInput := merged.Tokens.MaxInputTokens
	applyAlibabaTokenFacts(&merged, fact)
	if explicitMaximumInput.Known && (!merged.Tokens.MaxInputTokens.Known || explicitMaximumInput.Value < merged.Tokens.MaxInputTokens.Value) {
		merged.Tokens.MaxInputTokens = explicitMaximumInput
	}
	if len(merged.InputModalities) == 0 {
		merged.InputModalities = append([]string(nil), fact.RequestModalities...)
	}
	if len(merged.OutputModalities) == 0 {
		merged.OutputModalities = append([]string(nil), fact.ResponseModalities...)
	}
	return merged
}

// applyAlibabaTokenFacts assigns independently reported ordinary token ceilings.
// applyAlibabaTokenFacts 赋值独立报告的普通 Token 上限。
func applyAlibabaTokenFacts(capabilities *catalog.ModelCapabilities, fact catalogdata.ModelFact) {
	if fact.ContextWindow != nil && *fact.ContextWindow > 0 {
		capabilities.Tokens.ContextWindow = catalog.OptionalTokenLimit{Known: true, Value: *fact.ContextWindow}
	}
	if fact.MaxInputTokens != nil && *fact.MaxInputTokens > 0 {
		capabilities.Tokens.MaxInputTokens = catalog.OptionalTokenLimit{Known: true, Value: *fact.MaxInputTokens}
	}
	if fact.MaxOutputTokens != nil && *fact.MaxOutputTokens > 0 {
		capabilities.Tokens.MaxOutputTokens = catalog.OptionalTokenLimit{Known: true, Value: *fact.MaxOutputTokens}
	}
	if fact.MaxReasoningTokens != nil && *fact.MaxReasoningTokens > 0 {
		capabilities.Tokens.MaxReasoningTokens = catalog.OptionalTokenLimit{Known: true, Value: *fact.MaxReasoningTokens}
	}
	clampAlibabaTokenLimitsToSharedContext(&capabilities.Tokens)
}

// clampAlibabaTokenLimitsToSharedContext narrows contradictory provider fields to the fixed conservative total-window contract.
// clampAlibabaTokenLimitsToSharedContext 将矛盾的供应商字段收窄到固定的保守总窗口合同。
func clampAlibabaTokenLimitsToSharedContext(limits *catalog.TokenLimits) {
	if limits == nil || !limits.ContextWindow.Known {
		return
	}
	for _, bounded := range []*catalog.OptionalTokenLimit{
		&limits.MaxInputTokens,
		&limits.MaxOutputTokens,
		&limits.MaxReasoningTokens,
	} {
		if bounded.Known && bounded.Value > limits.ContextWindow.Value {
			bounded.Value = limits.ContextWindow.Value
		}
	}
}

// applyAlibabaExecutableProfileFacts enriches executable profiles and splits independently reported ordinary and reasoning token shapes.
// applyAlibabaExecutableProfileFacts 增强可执行规格，并拆分独立报告的普通与思考 Token 形态。
func applyAlibabaExecutableProfileFacts(snapshot *catalog.Snapshot, offeringID string, operation vcp.OperationKind, fact catalogdata.ModelFact) error {
	profileIndexes := make([]int, 0, 1)
	for profileIndex := range snapshot.Profiles {
		profile := snapshot.Profiles[profileIndex]
		if profile.OfferingID == offeringID && profile.Operation == operation {
			profileIndexes = append(profileIndexes, profileIndex)
		}
	}
	if len(profileIndexes) == 0 {
		return fmt.Errorf("Alibaba executable offering %q operation %q has no execution profile", offeringID, operation)
	}
	separateReasoning := operation == vcp.OperationConversationRespond && hasAlibabaReasoningTokenShape(fact)
	alreadySplit := separateReasoning && alibabaProfilesAlreadySplit(snapshot.Profiles, offeringID, operation)
	for _, profileIndex := range profileIndexes {
		profile := snapshot.Profiles[profileIndex]
		merged := mergeAlibabaCatalogCapabilities(profile.Capabilities, fact)
		if alreadySplit {
			if callableAlibabaCatalogReasoning(merged.Reasoning) {
				merged.Tokens.MaxInputTokens = alibabaTokenLimit(fact.ReasoningMaxInputTokens)
				merged.Tokens.MaxOutputTokens = alibabaTokenLimit(fact.ReasoningMaxOutputTokens)
				clampAlibabaTokenLimitsToSharedContext(&merged.Tokens)
			} else {
				merged.Tokens.MaxReasoningTokens = catalog.OptionalTokenLimit{}
				merged.Recommendations.ReasoningTokens = catalog.OptionalTokenLimit{}
				merged.Parameters = removeSystemParameters(merged.Parameters, []string{provideralibaba.ReasoningBudgetParameterID})
			}
			snapshot.Profiles[profileIndex].Capabilities = merged
			continue
		}
		if !separateReasoning || !callableAlibabaCatalogReasoning(merged.Reasoning) {
			snapshot.Profiles[profileIndex].Capabilities = merged
			continue
		}

		normalCapabilities := catalog.CloneModelCapabilities(merged)
		normalCapabilities.Reasoning = catalog.CapabilityUnsupported
		normalCapabilities.ReasoningEfforts = nil
		normalCapabilities.ReasoningSummaryModes = nil
		normalCapabilities.Tokens.MaxReasoningTokens = catalog.OptionalTokenLimit{}
		normalCapabilities.Recommendations.ReasoningTokens = catalog.OptionalTokenLimit{}
		normalCapabilities.Parameters = removeSystemParameters(normalCapabilities.Parameters, []string{provideralibaba.ReasoningBudgetParameterID})
		snapshot.Profiles[profileIndex].Capabilities = normalCapabilities

		reasoningProfileID := profile.ID + provideralibaba.ReasoningProfileIDSuffix
		if alibabaExecutionProfileIDExists(snapshot.Profiles, reasoningProfileID) {
			return fmt.Errorf("Alibaba reasoning execution profile %q is duplicated", reasoningProfileID)
		}
		reasoningCapabilities := catalog.CloneModelCapabilities(merged)
		reasoningCapabilities.Tokens.MaxInputTokens = alibabaTokenLimit(fact.ReasoningMaxInputTokens)
		reasoningCapabilities.Tokens.MaxOutputTokens = alibabaTokenLimit(fact.ReasoningMaxOutputTokens)
		clampAlibabaTokenLimitsToSharedContext(&reasoningCapabilities.Tokens)
		reasoningProfile := profile
		reasoningProfile.ID = reasoningProfileID
		reasoningProfile.DisplayName = profile.DisplayName + " Reasoning"
		reasoningProfile.Default = false
		reasoningProfile.Capabilities = reasoningCapabilities
		reasoningProfile.RequiredEntitlementClasses = append([]string(nil), profile.RequiredEntitlementClasses...)
		snapshot.Profiles = append(snapshot.Profiles, reasoningProfile)
	}
	return nil
}

// alibabaProfilesAlreadySplit reports an exact ordinary/reasoning sibling pair for one operation.
// alibabaProfilesAlreadySplit 报告一个操作是否已有精确的普通与推理同级规格对。
func alibabaProfilesAlreadySplit(profiles []catalog.ExecutionProfile, offeringID string, operation vcp.OperationKind) bool {
	hasOrdinary := false
	hasReasoning := false
	for _, profile := range profiles {
		if profile.OfferingID != offeringID || profile.Operation != operation {
			continue
		}
		if callableAlibabaCatalogReasoning(profile.Capabilities.Reasoning) {
			hasReasoning = true
		} else if profile.Capabilities.Reasoning == catalog.CapabilityUnsupported {
			hasOrdinary = true
		}
	}
	return hasOrdinary && hasReasoning
}

// hasAlibabaReasoningTokenShape reports exact provider evidence for a distinct thinking-mode input or output ceiling.
// hasAlibabaReasoningTokenShape 报告供应商对独立思考模式输入或输出上限的精确证据。
func hasAlibabaReasoningTokenShape(fact catalogdata.ModelFact) bool {
	return fact.ReasoningMaxInputTokens != nil && *fact.ReasoningMaxInputTokens > 0 || fact.ReasoningMaxOutputTokens != nil && *fact.ReasoningMaxOutputTokens > 0
}

// callableAlibabaCatalogReasoning reports whether one catalog capability level can represent a callable reasoning profile.
// callableAlibabaCatalogReasoning 报告一个目录能力等级是否可以表示可调用的推理规格。
func callableAlibabaCatalogReasoning(level catalog.CapabilityLevel) bool {
	return level == catalog.CapabilityNative || level == catalog.CapabilityEmulated || level == catalog.CapabilityConditional
}

// alibabaTokenLimit converts one independently reported positive provider limit without deriving a missing value.
// alibabaTokenLimit 转换一个独立报告的正数供应商上限，且不会推导缺失值。
func alibabaTokenLimit(value *int64) catalog.OptionalTokenLimit {
	if value == nil || *value <= 0 {
		return catalog.OptionalTokenLimit{}
	}
	return catalog.OptionalTokenLimit{Known: true, Value: *value}
}

// alibabaExecutionProfileIDExists reports exact profile-identifier ownership inside one catalog snapshot.
// alibabaExecutionProfileIDExists 报告一个目录快照内精确规格标识的所有权。
func alibabaExecutionProfileIDExists(profiles []catalog.ExecutionProfile, profileID string) bool {
	for _, profile := range profiles {
		if profile.ID == profileID {
			return true
		}
	}
	return false
}

// alibabaRateLimits maps every complete qpmInfo count tuple and preserves duplicate-looking tier IDs independently.
// alibabaRateLimits 映射每个完整 qpmInfo 计数元组，并独立保留看似重复的层级标识。
func alibabaRateLimits(providerInstanceID string, offeringID string, providerSnapshot catalogdata.Snapshot, fact catalogdata.ModelFact) []catalog.RateLimitSnapshot {
	limits := make([]catalog.RateLimitSnapshot, 0, len(fact.RateLimits))
	for _, sourceLimit := range fact.RateLimits {
		if sourceLimit.CountLimit == nil || sourceLimit.CountPeriodSeconds == nil {
			continue
		}
		limits = append(limits, catalog.RateLimitSnapshot{
			ID: alibabaGeneratedID("rate_alibaba_", offeringID, sourceLimit.TierID), ProviderInstanceID: providerInstanceID, Scope: catalog.RateLimitScopeOffering, ScopeID: offeringID,
			TierID: sourceLimit.TierID, CountLimit: *sourceLimit.CountLimit, CountPeriodSeconds: *sourceLimit.CountPeriodSeconds,
			UsageLimit: cloneAlibabaOptionalInt64(sourceLimit.UsageLimit), UsagePeriodSeconds: cloneAlibabaOptionalInt64(sourceLimit.UsagePeriodSeconds), UsageField: sourceLimit.UsageField,
			Source: catalog.ModelSourceProviderAPI, ObservedAt: providerSnapshot.ObservedAt, ExpiresAt: providerSnapshot.ObservedAt.Add(30 * 24 * time.Hour), Revision: 1,
		})
	}
	return limits
}

// cloneAlibabaOptionalInt64 copies one optional generated catalog integer.
// cloneAlibabaOptionalInt64 复制一个可选的生成目录整数。
func cloneAlibabaOptionalInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

// alibabaModelOperationKey creates one non-persisted exact policy lookup key.
// alibabaModelOperationKey 创建一个不持久化的精确策略查找键。
func alibabaModelOperationKey(modelID string, operation vcp.OperationKind) string {
	return modelID + "\x00" + string(operation)
}

// indexAlibabaModelOperationPolicies indexes the sole primary-channel template for generated facts and leaves explicit secondary channels independent.
// indexAlibabaModelOperationPolicies 为生成事实索引唯一主通道模板，并让显式次级通道保持独立。
func indexAlibabaModelOperationPolicies(policies []catalog.ModelOperationPolicy, offerings []catalog.ModelOffering, primaryChannelID string) (map[string]int, error) {
	// indexed stores slice positions so generated evidence can enrich the exact existing policy in place.
	// indexed 保存切片位置，使生成证据可以原位增强精确的既有策略。
	indexed := make(map[string]int, len(policies))
	// channelByOffering binds every policy to the exact wire channel owned by its referenced offering.
	// channelByOffering 把每个策略绑定到其引用 Offering 所拥有的精确 Wire 通道。
	channelByOffering := make(map[string]string, len(offerings))
	for _, offering := range offerings {
		channelByOffering[offering.ID] = offering.ChannelID
	}
	// candidates groups policies by the provider-model operation that generated evidence can describe.
	// candidates 按生成证据可以描述的供应商模型操作对策略分组。
	candidates := make(map[string][]int, len(policies))
	for index, policy := range policies {
		_, exists := channelByOffering[policy.OfferingID]
		if !exists {
			return nil, fmt.Errorf("Alibaba executable policy %q references absent offering %q", policy.ID, policy.OfferingID)
		}
		key := alibabaModelOperationKey(policy.ProviderModelID, policy.Operation)
		candidates[key] = append(candidates[key], index)
	}
	for key, policyIndexes := range candidates {
		if len(policyIndexes) == 1 {
			indexed[key] = policyIndexes[0]
			continue
		}
		selectedIndex := -1
		for _, policyIndex := range policyIndexes {
			if channelByOffering[policies[policyIndex].OfferingID] != primaryChannelID {
				continue
			}
			if selectedIndex >= 0 {
				return nil, fmt.Errorf("Alibaba executable model operation %q is ambiguous between offerings %q and %q", key, policies[selectedIndex].OfferingID, policies[policyIndex].OfferingID)
			}
			selectedIndex = policyIndex
		}
		if selectedIndex < 0 {
			return nil, fmt.Errorf("Alibaba executable model operation %q has no primary-channel offering", key)
		}
		indexed[key] = selectedIndex
	}
	return indexed, nil
}

// alibabaGeneratedID creates a bounded portable identifier from the complete evidence key.
// alibabaGeneratedID 根据完整证据键创建有界且可移植的标识。
func alibabaGeneratedID(prefix string, components ...string) string {
	digest := sha256.Sum256([]byte(strings.Join(components, "\x00")))
	return prefix + hex.EncodeToString(digest[:12])
}
