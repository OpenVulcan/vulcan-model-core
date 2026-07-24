package management

import (
	"slices"
	"testing"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	provideralibaba "github.com/OpenVulcan/vulcan-model-core/internal/provider/alibaba"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/alibaba/catalogdata"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestApplyAlibabaTokenFactsClampsContradictoryIndependentLimits verifies raw provider semantics cannot widen the fixed shared window.
// TestApplyAlibabaTokenFactsClampsContradictoryIndependentLimits 验证原始供应商语义不能放宽固定共享窗口。
func TestApplyAlibabaTokenFactsClampsContradictoryIndependentLimits(t *testing.T) {
	contextWindow := int64(81_920)
	maximumInput := int64(126_976)
	maximumOutput := int64(32_768)
	maximumReasoning := int64(100_000)
	capabilities := catalog.ModelCapabilities{}
	applyAlibabaTokenFacts(&capabilities, catalogdata.ModelFact{
		ContextWindow:      &contextWindow,
		MaxInputTokens:     &maximumInput,
		MaxOutputTokens:    &maximumOutput,
		MaxReasoningTokens: &maximumReasoning,
	})
	if capabilities.Tokens.MaxInputTokens.Value != contextWindow ||
		capabilities.Tokens.MaxReasoningTokens.Value != contextWindow ||
		capabilities.Tokens.MaxOutputTokens.Value != maximumOutput {
		t.Fatalf("normalized Alibaba token limits = %#v", capabilities.Tokens)
	}
	if errValidate := capabilities.Tokens.Validate(); errValidate != nil {
		t.Fatalf("normalized Alibaba token limits are invalid: %v", errValidate)
	}
}

// TestIndexAlibabaModelOperationPoliciesRejectsAmbiguousOfferings verifies generated evidence never selects one of two same-operation channels by insertion order.
// TestIndexAlibabaModelOperationPoliciesRejectsAmbiguousOfferings 验证生成证据绝不会按插入顺序从两个同操作通道中任选其一。
func TestIndexAlibabaModelOperationPoliciesRejectsAmbiguousOfferings(t *testing.T) {
	policies := []catalog.ModelOperationPolicy{
		{ProviderModelID: "model_qwen", OfferingID: "offer_chat", Operation: vcp.OperationConversationRespond},
		{ProviderModelID: "model_qwen", OfferingID: "offer_chat_duplicate", Operation: vcp.OperationConversationRespond},
	}
	offerings := []catalog.ModelOffering{{ID: "offer_chat", ChannelID: "openai.chat"}, {ID: "offer_chat_duplicate", ChannelID: "openai.chat"}}
	if _, errIndex := indexAlibabaModelOperationPolicies(policies, offerings, "openai.chat"); errIndex == nil {
		t.Fatal("indexAlibabaModelOperationPolicies() error = nil, want ambiguous Offering error")
	}
}

// TestIndexAlibabaModelOperationPoliciesLeavesExplicitSecondaryChannelIndependent verifies generated Chat facts do not overwrite a Responses tool profile.
// TestIndexAlibabaModelOperationPoliciesLeavesExplicitSecondaryChannelIndependent 验证生成的 Chat 事实不会覆盖 Responses 工具规格。
func TestIndexAlibabaModelOperationPoliciesLeavesExplicitSecondaryChannelIndependent(t *testing.T) {
	policies := []catalog.ModelOperationPolicy{
		{ProviderModelID: "model_qwen", OfferingID: "offer_chat", Operation: vcp.OperationConversationRespond},
		{ProviderModelID: "model_qwen", OfferingID: "offer_responses", Operation: vcp.OperationConversationRespond},
	}
	offerings := []catalog.ModelOffering{{ID: "offer_chat", ChannelID: "openai.chat"}, {ID: "offer_responses", ChannelID: "openai.responses"}}
	indexed, errIndex := indexAlibabaModelOperationPolicies(policies, offerings, "openai.chat")
	if errIndex != nil {
		t.Fatalf("indexAlibabaModelOperationPolicies() error = %v", errIndex)
	}
	if len(indexed) != 1 || indexed[alibabaModelOperationKey("model_qwen", vcp.OperationConversationRespond)] != 0 {
		t.Fatalf("indexed policies = %#v", indexed)
	}
}

// TestAlibabaCatalogOperationsPreservesEveryProvenOperation verifies multimodal facts are never collapsed by precedence.
// TestAlibabaCatalogOperationsPreservesEveryProvenOperation 验证多模态事实不会因优先级而被折叠。
func TestAlibabaCatalogOperationsPreservesEveryProvenOperation(t *testing.T) {
	// fact represents one provider model whose independent text, vision, speech, and embedding classifications are all proven.
	// fact 表示一个文本、视觉、语音及嵌入分类均已独立证明的供应商模型。
	fact := catalogdata.ModelFact{ModelID: "multi-operation", Capabilities: []string{"TG", "VU", "TTS", "ASR", "ME"}}
	want := []vcp.OperationKind{
		vcp.OperationSpeechSynthesize,
		vcp.OperationSpeechTranscribe,
		vcp.OperationEmbeddingCreate,
		vcp.OperationConversationRespond,
		vcp.OperationMediaAnalyze,
	}
	if got := alibabaCatalogOperations(fact); !slices.Equal(got, want) {
		t.Fatalf("alibabaCatalogOperations() = %#v, want %#v", got, want)
	}
}

// TestAlibabaCatalogOperationsExpandsOmniIntoConversationAndDedicatedAnalysis verifies the provider's aggregate Omni code is not lost or exposed as an invented operation.
// TestAlibabaCatalogOperationsExpandsOmniIntoConversationAndDedicatedAnalysis 验证供应商聚合 Omni 代码不会丢失，也不会暴露为虚构操作。
func TestAlibabaCatalogOperationsExpandsOmniIntoConversationAndDedicatedAnalysis(t *testing.T) {
	want := []vcp.OperationKind{vcp.OperationConversationRespond, vcp.OperationMediaAnalyze}
	got := alibabaCatalogOperations(catalogdata.ModelFact{ModelID: "qwen3.5-omni", Capabilities: []string{"Multimodal-Omni"}})
	if !slices.Equal(got, want) {
		t.Fatalf("alibabaCatalogOperations() = %#v, want %#v", got, want)
	}
}

// TestAlibabaCatalogOperationsSeparatesRerankFromEmbedding verifies the ambiguous provider TR code is resolved only by proven model identity.
// TestAlibabaCatalogOperationsSeparatesRerankFromEmbedding 验证含义有歧义的供应商 TR 代码仅按已证明的模型身份解析。
func TestAlibabaCatalogOperationsSeparatesRerankFromEmbedding(t *testing.T) {
	tests := []struct {
		name  string
		model string
		want  []vcp.OperationKind
	}{
		{name: "rerank", model: "qwen3-rerank", want: []vcp.OperationKind{vcp.OperationRerankDocuments}},
		{name: "embedding", model: "text-embedding-v4", want: []vcp.OperationKind{vcp.OperationEmbeddingCreate}},
		{name: "unproven", model: "future-tr-model", want: nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := alibabaCatalogOperations(catalogdata.ModelFact{ModelID: test.model, Capabilities: []string{"TR"}})
			if !slices.Equal(got, test.want) {
				t.Fatalf("alibabaCatalogOperations(%q) = %#v, want %#v", test.model, got, test.want)
			}
		})
	}
}

// TestApplyAlibabaExecutableProfileFactsSplitsReasoningLimits verifies ordinary and thinking ceilings remain independently queryable.
// TestApplyAlibabaExecutableProfileFactsSplitsReasoningLimits 验证普通与思考上限保持独立且可查询。
func TestApplyAlibabaExecutableProfileFactsSplitsReasoningLimits(t *testing.T) {
	ordinaryInput := int64(991_808)
	ordinaryOutput := int64(65_536)
	reasoningInput := int64(950_000)
	reasoningOutput := int64(32_768)
	reasoningBudget := int64(16_384)
	minimumBudget := int64(1)
	snapshot := catalog.Snapshot{Profiles: []catalog.ExecutionProfile{{
		ID: "profile_qwen", OfferingID: "offer_qwen", Operation: vcp.OperationConversationRespond, DisplayName: "Qwen", Default: true,
		Capabilities: catalog.ModelCapabilities{Reasoning: catalog.CapabilityNative, ReasoningEfforts: []string{"high"}, Recommendations: catalog.TokenRecommendations{ReasoningTokens: catalog.OptionalTokenLimit{Known: true, Value: 8192}}, Parameters: []catalog.ParameterDescriptor{{ID: provideralibaba.ReasoningBudgetParameterID, Kind: catalog.ParameterInteger, IntegerRange: &catalog.IntegerRange{Minimum: &minimumBudget, Maximum: &reasoningBudget}}}},
	}}}
	fact := catalogdata.ModelFact{ModelID: "qwen", MaxInputTokens: &ordinaryInput, MaxOutputTokens: &ordinaryOutput, MaxReasoningTokens: &reasoningBudget, ReasoningMaxInputTokens: &reasoningInput, ReasoningMaxOutputTokens: &reasoningOutput}
	if errApply := applyAlibabaExecutableProfileFacts(&snapshot, "offer_qwen", vcp.OperationConversationRespond, fact); errApply != nil {
		t.Fatalf("applyAlibabaExecutableProfileFacts() error = %v", errApply)
	}
	if len(snapshot.Profiles) != 2 {
		t.Fatalf("profile count = %d, want 2", len(snapshot.Profiles))
	}
	normal := snapshot.Profiles[0]
	reasoning := snapshot.Profiles[1]
	if normal.Capabilities.Reasoning != catalog.CapabilityUnsupported || normal.Capabilities.Tokens.MaxInputTokens.Value != ordinaryInput || normal.Capabilities.Tokens.MaxOutputTokens.Value != ordinaryOutput || normal.Capabilities.Tokens.MaxReasoningTokens.Known || normal.Capabilities.Recommendations.ReasoningTokens.Known || len(normal.Capabilities.Parameters) != 0 {
		t.Fatalf("ordinary profile capabilities = %#v", normal.Capabilities)
	}
	if reasoning.ID != "profile_qwen"+provideralibaba.ReasoningProfileIDSuffix || reasoning.Default || reasoning.Capabilities.Reasoning != catalog.CapabilityNative || reasoning.Capabilities.Tokens.MaxInputTokens.Value != reasoningInput || reasoning.Capabilities.Tokens.MaxOutputTokens.Value != reasoningOutput || reasoning.Capabilities.Tokens.MaxReasoningTokens.Value != reasoningBudget || len(reasoning.Capabilities.Parameters) != 1 {
		t.Fatalf("reasoning profile = %#v", reasoning)
	}
}

// TestApplyAlibabaExecutableProfileFactsPreservesExistingReasoningSiblings verifies static ordinary/reasoning pairs are enriched without a duplicate split.
// TestApplyAlibabaExecutableProfileFactsPreservesExistingReasoningSiblings 验证静态普通与推理同级规格会被增强且不会重复拆分。
func TestApplyAlibabaExecutableProfileFactsPreservesExistingReasoningSiblings(t *testing.T) {
	ordinaryInput := int64(991_808)
	ordinaryOutput := int64(65_536)
	reasoningInput := int64(950_000)
	reasoningOutput := int64(32_768)
	reasoningBudget := int64(16_384)
	minimumBudget := int64(1)
	budgetParameter := catalog.ParameterDescriptor{ID: provideralibaba.ReasoningBudgetParameterID, Kind: catalog.ParameterInteger, IntegerRange: &catalog.IntegerRange{Minimum: &minimumBudget, Maximum: &reasoningBudget}}
	snapshot := catalog.Snapshot{Profiles: []catalog.ExecutionProfile{
		{ID: "profile_qwen_ordinary", OfferingID: "offer_qwen", Operation: vcp.OperationConversationRespond, Default: true, Capabilities: catalog.ModelCapabilities{Reasoning: catalog.CapabilityUnsupported, Parameters: []catalog.ParameterDescriptor{budgetParameter}}},
		{ID: "profile_qwen_reasoning", OfferingID: "offer_qwen", Operation: vcp.OperationConversationRespond, Capabilities: catalog.ModelCapabilities{Reasoning: catalog.CapabilityNative, Recommendations: catalog.TokenRecommendations{ReasoningTokens: catalog.OptionalTokenLimit{Known: true, Value: 4000}}, Parameters: []catalog.ParameterDescriptor{budgetParameter}}},
	}}
	fact := catalogdata.ModelFact{ModelID: "qwen", MaxInputTokens: &ordinaryInput, MaxOutputTokens: &ordinaryOutput, MaxReasoningTokens: &reasoningBudget, ReasoningMaxInputTokens: &reasoningInput, ReasoningMaxOutputTokens: &reasoningOutput}
	if errApply := applyAlibabaExecutableProfileFacts(&snapshot, "offer_qwen", vcp.OperationConversationRespond, fact); errApply != nil {
		t.Fatalf("applyAlibabaExecutableProfileFacts() error = %v", errApply)
	}
	if len(snapshot.Profiles) != 2 {
		t.Fatalf("profile count = %d, want 2", len(snapshot.Profiles))
	}
	ordinary := snapshot.Profiles[0].Capabilities
	reasoning := snapshot.Profiles[1].Capabilities
	if ordinary.Tokens.MaxInputTokens.Value != ordinaryInput || ordinary.Tokens.MaxOutputTokens.Value != ordinaryOutput || ordinary.Tokens.MaxReasoningTokens.Known || ordinary.Recommendations.ReasoningTokens.Known || len(ordinary.Parameters) != 0 {
		t.Fatalf("ordinary capabilities = %#v", ordinary)
	}
	if reasoning.Tokens.MaxInputTokens.Value != reasoningInput || reasoning.Tokens.MaxOutputTokens.Value != reasoningOutput || reasoning.Tokens.MaxReasoningTokens.Value != reasoningBudget || !reasoning.Recommendations.ReasoningTokens.Known || len(reasoning.Parameters) != 1 {
		t.Fatalf("reasoning capabilities = %#v", reasoning)
	}
}

// TestApplyAlibabaExecutableProfileFactsKeepsMissingReasoningLimitUnknown verifies no ordinary ceiling is copied into a missing reasoning field.
// TestApplyAlibabaExecutableProfileFactsKeepsMissingReasoningLimitUnknown 验证普通上限不会被复制到缺失的思考字段。
func TestApplyAlibabaExecutableProfileFactsKeepsMissingReasoningLimitUnknown(t *testing.T) {
	reasoningInput := int64(950_000)
	snapshot := catalog.Snapshot{Profiles: []catalog.ExecutionProfile{{ID: "profile_qwen", OfferingID: "offer_qwen", Operation: vcp.OperationConversationRespond, Default: true, Capabilities: catalog.ModelCapabilities{Reasoning: catalog.CapabilityNative}}}}
	fact := catalogdata.ModelFact{ModelID: "qwen", ReasoningMaxInputTokens: &reasoningInput}
	if errApply := applyAlibabaExecutableProfileFacts(&snapshot, "offer_qwen", vcp.OperationConversationRespond, fact); errApply != nil {
		t.Fatalf("applyAlibabaExecutableProfileFacts() error = %v", errApply)
	}
	if len(snapshot.Profiles) != 2 || snapshot.Profiles[1].Capabilities.Tokens.MaxOutputTokens.Known {
		t.Fatalf("reasoning profiles = %#v", snapshot.Profiles)
	}
}

// TestAlibabaStaticCatalogSourceRevisionExposesOnlyVerifiedEvidence verifies management views receive an immutable version without publishing an unverified boundary.
// TestAlibabaStaticCatalogSourceRevisionExposesOnlyVerifiedEvidence 验证管理视图取得不可变版本且不会发布未验证边界。
func TestAlibabaStaticCatalogSourceRevisionExposesOnlyVerifiedEvidence(t *testing.T) {
	revision, verified, errRevision := alibabaStaticCatalogSourceRevision("alibaba_token_plan_personal_cn")
	if errRevision != nil {
		t.Fatalf("alibabaStaticCatalogSourceRevision() error = %v", errRevision)
	}
	if !verified || len(revision) != 64 {
		t.Fatalf("verified revision = %q, verified = %t", revision, verified)
	}
	unverifiedRevision, unverified, errUnverified := alibabaStaticCatalogSourceRevision("alibaba_token_plan_personal_global")
	if errUnverified != nil {
		t.Fatalf("unverified alibabaStaticCatalogSourceRevision() error = %v", errUnverified)
	}
	if unverified || unverifiedRevision != "" {
		t.Fatalf("unverified revision = %q, verified = %t", unverifiedRevision, unverified)
	}
}
