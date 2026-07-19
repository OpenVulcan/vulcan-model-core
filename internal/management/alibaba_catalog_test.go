package management

import (
	"reflect"
	"testing"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
)

// alibabaCatalogExpectation closes one plan catalog's ordered IDs and exceptional token facts.
// alibabaCatalogExpectation 封闭一个套餐目录的有序 ID 与例外 Token 事实。
type alibabaCatalogExpectation struct {
	// catalogID selects one immutable code-owned plan catalog.
	// catalogID 选择一个不可变代码拥有套餐目录。
	catalogID string
	// modelIDs is the exact official order and set.
	// modelIDs 是精确的官方顺序与集合。
	modelIDs []string
	// contextOverrides records context windows that differ from the common one-million Qwen boundary.
	// contextOverrides 记录不同于通用一百万 Qwen 边界的上下文窗口。
	contextOverrides map[string]int64
	// recommendedReasoning identifies models with a documented plan default.
	// recommendedReasoning 标识具有套餐文档默认值的模型。
	recommendedReasoning int64
	// recommendedReasoningIDs is the exact model subset receiving that documented default.
	// recommendedReasoningIDs 是接收该文档默认值的精确模型子集。
	recommendedReasoningIDs map[string]struct{}
}

// TestAlibabaPlanCatalogsMatchExactRegionalEvidence verifies closed model sets, token semantics, modalities, entitlements, and capability conservatism.
// TestAlibabaPlanCatalogsMatchExactRegionalEvidence 验证封闭模型集合、Token 语义、模态、权益和保守能力声明。
func TestAlibabaPlanCatalogsMatchExactRegionalEvidence(t *testing.T) {
	// expectations distinguishes every commercial product instead of unioning models across plans or regions.
	// expectations 区分每个商业产品，不跨套餐或区域合并模型。
	expectations := []alibabaCatalogExpectation{
		{
			catalogID:               "alibaba_coding_plan_cn",
			modelIDs:                []string{"qwen3.7-plus", "qwen3.6-plus", "qwen3.5-plus", "qwen3-max-2026-01-23", "qwen3-coder-next", "qwen3-coder-plus", "MiniMax-M2.5", "glm-5", "glm-4.7", "kimi-k2.5"},
			contextOverrides:        map[string]int64{"qwen3-max-2026-01-23": 262_144, "qwen3-coder-next": 262_144, "MiniMax-M2.5": 196_608, "glm-5": 202_752, "glm-4.7": 202_752, "kimi-k2.5": 262_144},
			recommendedReasoning:    1_024,
			recommendedReasoningIDs: map[string]struct{}{"qwen3.7-plus": {}, "qwen3.6-plus": {}, "qwen3.5-plus": {}, "glm-5": {}, "kimi-k2.5": {}},
		},
		{
			catalogID:               "alibaba_coding_plan_global",
			modelIDs:                []string{"qwen3.7-plus", "qwen3.6-plus", "qwen3.5-plus", "qwen3-max-2026-01-23", "qwen3-coder-next", "qwen3-coder-plus", "MiniMax-M2.5", "glm-5", "glm-4.7", "kimi-k2.5"},
			contextOverrides:        map[string]int64{"qwen3-max-2026-01-23": 262_144, "qwen3-coder-next": 262_144, "MiniMax-M2.5": 196_608, "glm-5": 202_752, "glm-4.7": 202_752, "kimi-k2.5": 262_144},
			recommendedReasoning:    1_024,
			recommendedReasoningIDs: map[string]struct{}{"qwen3.7-plus": {}, "qwen3.6-plus": {}, "qwen3.5-plus": {}, "glm-5": {}, "kimi-k2.5": {}},
		},
		{
			catalogID:               "alibaba_token_plan_personal_cn",
			modelIDs:                []string{"qwen3.8-max-preview", "qwen3.7-max", "qwen3.7-plus", "qwen3.6-flash", "glm-5.2", "deepseek-v4-pro"},
			contextOverrides:        map[string]int64{"qwen3.8-max-preview": 0},
			recommendedReasoning:    8_192,
			recommendedReasoningIDs: map[string]struct{}{"qwen3.7-max": {}, "qwen3.7-plus": {}, "qwen3.6-flash": {}, "glm-5.2": {}},
		},
		{
			catalogID:               "alibaba_token_plan_team_cn",
			modelIDs:                []string{"qwen3.8-max-preview", "qwen3.7-max", "qwen3.7-plus", "qwen3.6-plus", "qwen3.6-flash", "deepseek-v4-pro", "deepseek-v4-flash", "deepseek-v3.2", "kimi-k2.7-code", "kimi-k2.6", "kimi-k2.5", "glm-5.2", "glm-5.1", "glm-5", "MiniMax-M2.5"},
			contextOverrides:        map[string]int64{"qwen3.8-max-preview": 0, "deepseek-v3.2": 128_000, "kimi-k2.7-code": 256_000, "kimi-k2.6": 256_000, "kimi-k2.5": 256_000, "glm-5.1": 198_000, "glm-5": 198_000, "MiniMax-M2.5": 192_000},
			recommendedReasoning:    8_192,
			recommendedReasoningIDs: map[string]struct{}{"qwen3.7-max": {}, "qwen3.7-plus": {}, "qwen3.6-plus": {}, "qwen3.6-flash": {}, "kimi-k2.7-code": {}, "kimi-k2.6": {}, "kimi-k2.5": {}, "glm-5.2": {}, "glm-5.1": {}, "glm-5": {}},
		},
		{
			catalogID:               "alibaba_token_plan_team_global",
			modelIDs:                []string{"qwen3.7-max", "qwen3.7-plus", "qwen3.6-plus", "qwen3.6-flash", "deepseek-v4-pro", "deepseek-v4-flash", "deepseek-v3.2", "kimi-k2.7-code", "kimi-k2.6", "kimi-k2.5", "glm-5.2", "glm-5.1", "glm-5", "MiniMax-M2.5"},
			contextOverrides:        map[string]int64{"deepseek-v3.2": 128_000, "kimi-k2.7-code": 256_000, "kimi-k2.6": 256_000, "kimi-k2.5": 256_000, "glm-5.2": 198_000, "glm-5.1": 198_000, "glm-5": 198_000, "MiniMax-M2.5": 192_000},
			recommendedReasoning:    8_192,
			recommendedReasoningIDs: map[string]struct{}{"qwen3.7-max": {}, "qwen3.7-plus": {}, "qwen3.6-plus": {}, "qwen3.6-flash": {}, "kimi-k2.7-code": {}, "kimi-k2.6": {}, "kimi-k2.5": {}, "glm-5.2": {}, "glm-5.1": {}, "glm-5": {}},
		},
	}
	for _, expectation := range expectations {
		t.Run(expectation.catalogID, func(t *testing.T) {
			templates, errTemplates := systemModelTemplates(expectation.catalogID)
			if errTemplates != nil {
				t.Fatalf("systemModelTemplates() error = %v", errTemplates)
			}
			actualIDs := make([]string, 0, len(templates))
			for _, template := range templates {
				actualIDs = append(actualIDs, template.upstreamID)
				wantContext := int64(1_000_000)
				if override, exists := expectation.contextOverrides[template.upstreamID]; exists {
					wantContext = override
				}
				if template.contextWindow != wantContext {
					t.Errorf("model %s context = %d, want %d", template.upstreamID, template.contextWindow, wantContext)
				}
				if !reflect.DeepEqual(template.inputModalities, []string{"text"}) || template.reasoning != catalog.CapabilityNative || template.toolCalling != catalog.CapabilityNative || template.parallelTools != catalog.CapabilityUnknown || template.entitlementMode != catalog.EntitlementAllBoundCredentials {
					t.Errorf("model %s common capabilities = %#v", template.upstreamID, template)
				}
				if template.maxInputTokens != 0 || template.maxReasoningTokens != 0 || template.recommendedOutputTokens != 0 {
					t.Errorf("model %s contains unverified token facts = %#v", template.upstreamID, template)
				}
				if template.upstreamID == "qwen3.8-max-preview" && template.maxOutputTokens != 131_072 {
					t.Errorf("qwen3.8 max output = %d", template.maxOutputTokens)
				}
				if template.upstreamID != "qwen3.8-max-preview" && template.maxOutputTokens != 0 {
					t.Errorf("model %s invented max output = %d", template.upstreamID, template.maxOutputTokens)
				}
				_, wantsReasoningRecommendation := expectation.recommendedReasoningIDs[template.upstreamID]
				wantReasoningRecommendation := int64(0)
				if wantsReasoningRecommendation {
					wantReasoningRecommendation = expectation.recommendedReasoning
				}
				if template.recommendedReasoningTokens != wantReasoningRecommendation {
					t.Errorf("model %s recommendation = %d, want %d", template.upstreamID, template.recommendedReasoningTokens, wantReasoningRecommendation)
				}
			}
			if !reflect.DeepEqual(actualIDs, expectation.modelIDs) {
				t.Fatalf("model IDs = %#v, want %#v", actualIDs, expectation.modelIDs)
			}
		})
	}
}
