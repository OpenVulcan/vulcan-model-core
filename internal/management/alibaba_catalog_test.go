package management

import (
	"reflect"
	"strings"
	"testing"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	provideralibaba "github.com/OpenVulcan/vulcan-model-core/internal/provider/alibaba"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/alibaba/catalogdata"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestAlibabaReasoningContractsPreserveExactPredictConfigShapes verifies switches, ranges, and fixed-reasoning models remain distinct.
// TestAlibabaReasoningContractsPreserveExactPredictConfigShapes 验证开关、范围与固定推理模型保持相互独立。
func TestAlibabaReasoningContractsPreserveExactPredictConfigShapes(t *testing.T) {
	tests := []struct {
		modelID      string
		wantSwitch   bool
		wantProfiles int
		wantMinimum  int64
		wantMaximum  int64
		wantDefault  int64
	}{
		{modelID: "qwen3.7-plus", wantSwitch: true, wantProfiles: 2, wantMinimum: 1, wantMaximum: 32768, wantDefault: 4000},
		{modelID: "qwen3.5-flash", wantSwitch: true, wantProfiles: 2, wantMinimum: 1, wantMaximum: 32768, wantDefault: 4000},
		{modelID: "deepseek-v4-pro", wantSwitch: true, wantProfiles: 2, wantMinimum: 4000, wantMaximum: 32768, wantDefault: 4000},
		{modelID: "stepfun/step-3.7-flash", wantSwitch: true, wantProfiles: 2},
		{modelID: "kimi-k2.5", wantSwitch: true, wantProfiles: 2},
		{modelID: "kimi-k2.7-code", wantMinimum: 1, wantMaximum: 32768, wantDefault: 4000},
		{modelID: "MiniMax-M2.5"},
	}
	for _, test := range tests {
		t.Run(test.modelID, func(t *testing.T) {
			template := alibabaModel(test.modelID, test.modelID, 262144, 0, false, false)
			if len(template.profiles) != test.wantProfiles {
				t.Fatalf("profile count = %d, want %d", len(template.profiles), test.wantProfiles)
			}
			switchParameter, hasSwitch := testSystemParameter(template.parameters, provideralibaba.ReasoningEnabledParameterID)
			if hasSwitch != test.wantSwitch || hasSwitch && (switchParameter.Kind != catalog.ParameterBoolean || switchParameter.Default == nil || switchParameter.Default.Boolean == nil) {
				t.Fatalf("switch parameter = %#v, exists = %t", switchParameter, hasSwitch)
			}
			budgetParameter, hasBudget := testSystemParameter(template.parameters, provideralibaba.ReasoningBudgetParameterID)
			if test.wantDefault == 0 {
				if hasBudget || template.recommendedReasoningTokens != 0 {
					t.Fatalf("unexpected budget parameter = %#v, recommendation = %d", budgetParameter, template.recommendedReasoningTokens)
				}
			} else if !hasBudget || budgetParameter.IntegerRange == nil || budgetParameter.IntegerRange.Minimum == nil || *budgetParameter.IntegerRange.Minimum != test.wantMinimum || budgetParameter.IntegerRange.Maximum == nil || *budgetParameter.IntegerRange.Maximum != test.wantMaximum || budgetParameter.Default == nil || budgetParameter.Default.Integer == nil || *budgetParameter.Default.Integer != test.wantDefault || template.recommendedReasoningTokens != test.wantDefault {
				t.Fatalf("budget parameter = %#v, recommendation = %d", budgetParameter, template.recommendedReasoningTokens)
			}
			if test.wantProfiles == 2 {
				baseCapabilities := catalog.ModelCapabilities{Reasoning: catalog.CapabilityNative, Recommendations: catalog.TokenRecommendations{ReasoningTokens: catalog.OptionalTokenLimit{Known: true, Value: template.recommendedReasoningTokens}}, Parameters: template.parameters}
				ordinaryCapabilities := applySystemProfileTemplate(baseCapabilities, template.profiles[0])
				reasoningCapabilities := applySystemProfileTemplate(baseCapabilities, template.profiles[1])
				_, ordinaryHasBudget := testSystemParameter(ordinaryCapabilities.Parameters, provideralibaba.ReasoningBudgetParameterID)
				_, reasoningHasBudget := testSystemParameter(reasoningCapabilities.Parameters, provideralibaba.ReasoningBudgetParameterID)
				if ordinaryCapabilities.Reasoning != catalog.CapabilityUnsupported || ordinaryCapabilities.Recommendations.ReasoningTokens.Known || ordinaryHasBudget || reasoningCapabilities.Reasoning != catalog.CapabilityNative || reasoningHasBudget != hasBudget {
					t.Fatalf("ordinary = %#v, reasoning = %#v", ordinaryCapabilities, reasoningCapabilities)
				}
			}
		})
	}
}

// TestAlibabaModelStudioCNConversationModelsMatchVerifiedAPIContract verifies the curated standard-API models preserve exact text and multimodal boundaries.
// TestAlibabaModelStudioCNConversationModelsMatchVerifiedAPIContract 验证精选标准 API 模型保持精确的文本与多模态边界。
func TestAlibabaModelStudioCNConversationModelsMatchVerifiedAPIContract(t *testing.T) {
	expectations := map[string]struct {
		inputModalities []string
		contextWindow   int64
		maxInputTokens  int64
		maxOutputTokens int64
		maxReasoning    int64
		maximumImages   int64
		nativeSearch    bool
	}{
		"qwen3.5-flash":          {inputModalities: []string{"text", "image", "video"}, contextWindow: 1_000_000, maxInputTokens: 991_808, maxOutputTokens: 65_536, maxReasoning: 81_920, maximumImages: 256, nativeSearch: true},
		"qwen3.5-plus":           {inputModalities: []string{"text", "image", "video"}, contextWindow: 1_000_000, maxInputTokens: 991_808, maxOutputTokens: 65_536, maxReasoning: 81_920, maximumImages: 256, nativeSearch: true},
		"qwen3.6-plus":           {inputModalities: []string{"text", "image", "video"}, contextWindow: 1_000_000, maxInputTokens: 991_808, maxOutputTokens: 65_536, maxReasoning: 81_920, maximumImages: 256, nativeSearch: true},
		"qwen3.7-plus":           {inputModalities: []string{"text", "image", "video"}, contextWindow: 1_000_000, maxOutputTokens: 65_536, maximumImages: 2_048, nativeSearch: true},
		"qwen3.7-max":            {inputModalities: []string{"text"}, contextWindow: 1_000_000, maxOutputTokens: 65_536, nativeSearch: true},
		"qwen3.7-max-2026-06-08": {inputModalities: []string{"text", "image", "video"}, contextWindow: 1_000_000, maxOutputTokens: 65_536, maximumImages: 2_048, nativeSearch: true},
		"glm-5.1":                {inputModalities: []string{"text"}, contextWindow: 202_752, maxOutputTokens: 131_072},
		"glm-5.2-fast-preview":   {inputModalities: []string{"text"}, contextWindow: 1_048_576, maxInputTokens: 1_048_576, maxOutputTokens: 131_072, maxReasoning: 131_072},
		"ZHIPU/GLM-5.2":          {inputModalities: []string{"text"}, contextWindow: 1_048_576, maxInputTokens: 1_048_576, maxOutputTokens: 131_072, maxReasoning: 131_072},
		"kimi/kimi-k3":           {inputModalities: []string{"text", "image", "video"}, contextWindow: 1_048_576, maxInputTokens: 1_048_576, maxOutputTokens: 1_048_576, maxReasoning: 1_048_576},
		"MiniMax/MiniMax-M3":     {inputModalities: []string{"text", "image", "video"}, contextWindow: 1_048_576, maxInputTokens: 1_048_576, maxOutputTokens: 32_768},
		"stepfun/step-3.7-flash": {inputModalities: []string{"text", "image", "video"}, contextWindow: 262_144, maxInputTokens: 262_144, maxOutputTokens: 262_144, maxReasoning: 262_144},
		"xiaomi/mimo-v2.5-pro":   {inputModalities: []string{"text"}, contextWindow: 1_048_576, maxInputTokens: 1_048_576, maxOutputTokens: 131_072, maxReasoning: 131_072},
		"deepseek-v4-pro":        {inputModalities: []string{"text"}, contextWindow: 1_000_000, maxInputTokens: 1_000_000, maxOutputTokens: 393_216, nativeSearch: true},
		"deepseek-v4-flash":      {inputModalities: []string{"text"}, contextWindow: 1_000_000, maxInputTokens: 1_000_000, maxOutputTokens: 393_216, nativeSearch: true},
	}
	models := alibabaModelStudioCNConversationModels()
	if len(models) != len(expectations) {
		t.Fatalf("Model Studio CN conversation model count = %d, want %d", len(models), len(expectations))
	}
	for _, model := range models {
		expectation, exists := expectations[model.upstreamID]
		if !exists {
			t.Fatalf("unexpected Model Studio CN conversation model %q", model.upstreamID)
		}
		if !reflect.DeepEqual(model.inputModalities, expectation.inputModalities) || model.contextWindow != expectation.contextWindow || model.maxInputTokens != expectation.maxInputTokens || model.maxOutputTokens != expectation.maxOutputTokens || model.maxReasoningTokens != expectation.maxReasoning {
			t.Fatalf("model %q capabilities = %#v, want %#v", model.upstreamID, model, expectation)
		}
		hasNativeSearch := len(model.standardTools) == 1 && model.standardTools[0].Kind == vcp.StandardModelToolWebSearch && model.standardTools[0].Native
		if hasNativeSearch != expectation.nativeSearch {
			t.Fatalf("model %q native search = %t, want %t", model.upstreamID, hasNativeSearch, expectation.nativeSearch)
		}
		if reflect.DeepEqual(expectation.inputModalities, []string{"text"}) {
			if len(model.mediaInputs) != 0 {
				t.Fatalf("text-only model %q media inputs = %#v", model.upstreamID, model.mediaInputs)
			}
			continue
		}
		if len(model.mediaInputs) != 2 {
			t.Fatalf("multimodal model %q media input count = %d, want 2", model.upstreamID, len(model.mediaInputs))
		}
		if expectation.maximumImages == 0 {
			continue
		}
		imageInput := model.mediaInputs[0]
		videoInput := model.mediaInputs[1]
		if imageInput.Kind != vcp.MediaImage || !imageInput.Common.MaxItems.Known || imageInput.Common.MaxItems.Value != expectation.maximumImages || !imageInput.Common.MaxItemBytes.Known || imageInput.Common.MaxItemBytes.Value != 20<<20 || imageInput.Image == nil || !imageInput.Image.MaxPixels.Known || imageInput.Image.MaxPixels.Value != 16_000_000 {
			t.Fatalf("model %q image contract = %#v", model.upstreamID, imageInput)
		}
		if videoInput.Kind != vcp.MediaVideo || !videoInput.Common.MaxItems.Known || videoInput.Common.MaxItems.Value != 64 || !videoInput.Common.MaxItemBytes.Known || videoInput.Common.MaxItemBytes.Value != 2<<30 || videoInput.Video == nil || !videoInput.Video.MaxDurationMilliseconds.Known || videoInput.Video.MaxDurationMilliseconds.Value != 2*60*60*1_000 {
			t.Fatalf("model %q video contract = %#v", model.upstreamID, videoInput)
		}
	}
	policies, errPolicies := catalogdata.LoadOperationPolicies()
	if errPolicies != nil {
		t.Fatalf("LoadOperationPolicies() error = %v", errPolicies)
	}
	policyByKey, errIndex := policies.EntryMap()
	if errIndex != nil {
		t.Fatalf("EntryMap() error = %v", errIndex)
	}
	for modelID := range expectations {
		key := catalogdata.OperationPolicyKey("alibaba_model_studio_cn", modelID, vcp.OperationConversationRespond)
		policy, exists := policyByKey[key]
		if !exists || policy.Status != catalog.ModelOperationSupported || policy.Reason != catalog.SupportReasonProviderContractVerified {
			t.Fatalf("model %q conversation policy = %#v, exists = %t", modelID, policy, exists)
		}
	}
}

// TestAlibabaModelStudioSGConversationModelsMatchVerifiedAPIContract verifies Singapore publishes only region-proven executable conversation models.
// TestAlibabaModelStudioSGConversationModelsMatchVerifiedAPIContract 验证新加坡仅发布区域已证实且可执行的会话模型。
func TestAlibabaModelStudioSGConversationModelsMatchVerifiedAPIContract(t *testing.T) {
	expectations := map[string][]string{
		"qwen3.5-flash":        {"text", "image", "video"},
		"qwen3.5-plus":         {"text", "image", "video"},
		"qwen3.6-plus":         {"text", "image", "video"},
		"glm-5.2-fast-preview": {"text"},
		"deepseek-v4-flash":    {"text"},
	}
	models := alibabaModelStudioSGConversationModels()
	if len(models) != len(expectations) {
		t.Fatalf("Model Studio SG conversation model count = %d, want %d", len(models), len(expectations))
	}
	policies, errPolicies := catalogdata.LoadOperationPolicies()
	if errPolicies != nil {
		t.Fatalf("LoadOperationPolicies() error = %v", errPolicies)
	}
	policyByKey, errIndex := policies.EntryMap()
	if errIndex != nil {
		t.Fatalf("EntryMap() error = %v", errIndex)
	}
	for _, model := range models {
		modalities, exists := expectations[model.upstreamID]
		if !exists || !reflect.DeepEqual(model.inputModalities, modalities) {
			t.Fatalf("unexpected Model Studio SG model = %#v", model)
		}
		if model.contextWindow <= 0 || model.maxInputTokens <= 0 || model.maxOutputTokens <= 0 {
			t.Fatalf("Model Studio SG model has incomplete token limits = %#v", model)
		}
		key := catalogdata.OperationPolicyKey("alibaba_model_studio_sg_domestic", model.upstreamID, vcp.OperationConversationRespond)
		policy, exists := policyByKey[key]
		if !exists || policy.Status != catalog.ModelOperationSupported || policy.Reason != catalog.SupportReasonProviderContractVerified {
			t.Fatalf("model %q conversation policy = %#v, exists = %t", model.upstreamID, policy, exists)
		}
	}
}

// TestAlibabaThirdPartyMultimodalLimitsPreserveProviderBoundaries verifies MiniMax and Stepfun do not inherit Qwen media limits.
// TestAlibabaThirdPartyMultimodalLimitsPreserveProviderBoundaries 验证 MiniMax 与阶跃星辰不会继承 Qwen 媒体限制。
func TestAlibabaThirdPartyMultimodalLimitsPreserveProviderBoundaries(t *testing.T) {
	models := map[string]systemModelTemplate{}
	for _, model := range alibabaModelStudioCNConversationModels() {
		models[model.upstreamID] = model
	}
	miniMax := models["MiniMax/MiniMax-M3"]
	if len(miniMax.mediaInputs) != 2 || miniMax.mediaInputs[0].Common.MaxItemBytes.Value != 10<<20 || miniMax.mediaInputs[1].Common.MaxItemBytes.Value != 50<<20 || miniMax.mediaInputs[1].Video == nil || miniMax.mediaInputs[1].Video.MaxDurationMilliseconds.Value != 30*60*1_000 {
		t.Fatalf("MiniMax M3 media limits = %#v", miniMax.mediaInputs)
	}
	stepFun := models["stepfun/step-3.7-flash"]
	if len(stepFun.mediaInputs) != 2 || stepFun.mediaInputs[0].Common.MaxItems.Value != 50 || stepFun.mediaInputs[0].Common.MaxTotalBytes.Value != 20<<20 || stepFun.mediaInputs[1].Common.MaxItemBytes.Value != 128<<20 || stepFun.mediaInputs[1].Video == nil || stepFun.mediaInputs[1].Video.MaxDurationMilliseconds.Value != 5*60*1_000 {
		t.Fatalf("Stepfun 3.7 Flash media limits = %#v", stepFun.mediaInputs)
	}
}

// testSystemParameter returns one exact parameter from an immutable system template fixture.
// testSystemParameter 从不可变系统模板夹具返回一个精确参数。
func testSystemParameter(parameters []catalog.ParameterDescriptor, parameterID string) (catalog.ParameterDescriptor, bool) {
	for _, parameter := range parameters {
		if parameter.ID == parameterID {
			return parameter, true
		}
	}
	return catalog.ParameterDescriptor{}, false
}

// TestAlibabaOmniCatalogPublishesOnlyVerifiedRegionalNonRealtimeActions verifies realtime variants and unverified workspace copies never enter executable templates.
// TestAlibabaOmniCatalogPublishesOnlyVerifiedRegionalNonRealtimeActions 验证实时变体与未经验证的 Workspace 副本绝不会进入可执行模板。
func TestAlibabaOmniCatalogPublishesOnlyVerifiedRegionalNonRealtimeActions(t *testing.T) {
	for _, catalogID := range []string{"alibaba_model_studio_cn", "alibaba_model_studio_sg_domestic"} {
		templates, errTemplates := systemModelTemplates(catalogID)
		if errTemplates != nil {
			t.Fatalf("systemModelTemplates(%q) error = %v", catalogID, errTemplates)
		}
		omniCount := 0
		for _, template := range templates {
			if strings.Contains(template.upstreamID, "realtime") {
				t.Fatalf("catalog %q published realtime template %#v", catalogID, template)
			}
			if template.upstreamID == "qwen3.5-omni-plus" || template.upstreamID == "qwen3.5-omni-flash" {
				omniCount++
				operation := template.operation
				if operation == "" {
					operation = vcp.OperationConversationRespond
				}
				if !template.streamingOnly {
					t.Fatalf("catalog %q Omni template = %#v", catalogID, template)
				}
				if operation == vcp.OperationConversationRespond && !reflect.DeepEqual(template.outputModalities, []string{"text", "audio"}) {
					t.Fatalf("catalog %q conversation Omni output modalities = %#v, want text+audio", catalogID, template.outputModalities)
				}
				if operation == vcp.OperationMediaAnalyze && !reflect.DeepEqual(template.outputModalities, []string{"text"}) {
					t.Fatalf("catalog %q analysis Omni output modalities = %#v, want text", catalogID, template.outputModalities)
				}
			}
		}
		if omniCount != 4 {
			t.Fatalf("catalog %q Omni template count = %d, want 4", catalogID, omniCount)
		}
	}
	workspace, errWorkspace := systemModelTemplates("alibaba_model_studio_workspace_sg")
	if errWorkspace != nil {
		t.Fatalf("workspace templates error = %v", errWorkspace)
	}
	for _, template := range workspace {
		if strings.HasPrefix(template.upstreamID, "qwen3.5-omni-") {
			t.Fatalf("workspace catalog copied unverified Omni template %#v", template)
		}
	}
}

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
	// multimodalModels maps exact conversation model IDs to their documented input modalities.
	// multimodalModels 将精确会话模型 ID 映射到其文档记录的输入模态。
	multimodalModels map[string][]string
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
			recommendedReasoning:    4_000,
			recommendedReasoningIDs: map[string]struct{}{"qwen3.7-plus": {}, "qwen3.6-plus": {}, "qwen3.5-plus": {}, "glm-5": {}, "glm-4.7": {}},
			multimodalModels:        map[string][]string{"qwen3.6-plus": {"text", "image", "video"}, "qwen3.5-plus": {"text", "image", "video"}, "kimi-k2.5": {"text", "image", "video"}},
		},
		{
			catalogID:               "alibaba_coding_plan_global",
			modelIDs:                []string{"qwen3.7-plus", "qwen3.6-plus", "qwen3.5-plus", "qwen3-max-2026-01-23", "qwen3-coder-next", "qwen3-coder-plus", "MiniMax-M2.5", "glm-5", "glm-4.7", "kimi-k2.5"},
			contextOverrides:        map[string]int64{"qwen3-max-2026-01-23": 262_144, "qwen3-coder-next": 262_144, "MiniMax-M2.5": 196_608, "glm-5": 202_752, "glm-4.7": 202_752, "kimi-k2.5": 262_144},
			recommendedReasoning:    4_000,
			recommendedReasoningIDs: map[string]struct{}{"qwen3.7-plus": {}, "qwen3.6-plus": {}, "qwen3.5-plus": {}, "glm-5": {}, "glm-4.7": {}},
			multimodalModels:        map[string][]string{"qwen3.6-plus": {"text", "image", "video"}, "qwen3.5-plus": {"text", "image", "video"}, "kimi-k2.5": {"text", "image", "video"}},
		},
		{
			catalogID:               "alibaba_token_plan_personal_cn",
			modelIDs:                []string{"qwen3.8-max-preview", "qwen3.7-max", "qwen3.7-plus", "qwen3.6-flash", "glm-5.2", "deepseek-v4-pro", "wan2.7-image-pro", "wan2.7-image", "happyhorse-1.1-t2v", "happyhorse-1.1-i2v", "happyhorse-1.1-r2v"},
			contextOverrides:        map[string]int64{},
			recommendedReasoning:    4_000,
			recommendedReasoningIDs: map[string]struct{}{"qwen3.7-max": {}, "qwen3.7-plus": {}, "qwen3.6-flash": {}, "glm-5.2": {}, "deepseek-v4-pro": {}},
			multimodalModels:        map[string][]string{"qwen3.8-max-preview": {"text", "image", "video"}, "qwen3.7-plus": {"text", "image", "video"}, "qwen3.6-flash": {"text", "image"}},
		},
		{
			catalogID:               "alibaba_token_plan_team_cn",
			modelIDs:                []string{"qwen3.8-max-preview", "qwen3.7-max", "qwen3.7-plus", "qwen3.6-plus", "qwen3.6-flash", "deepseek-v4-pro", "deepseek-v4-flash", "deepseek-v3.2", "kimi-k2.7-code", "kimi-k2.6", "kimi-k2.5", "glm-5.2", "glm-5.1", "glm-5", "MiniMax-M2.5", "qwen-image-2.0", "qwen-image-2.0-pro", "wan2.7-image-pro", "wan2.7-image", "happyhorse-1.1-t2v", "happyhorse-1.1-i2v", "happyhorse-1.1-r2v"},
			contextOverrides:        map[string]int64{"deepseek-v3.2": 131_072, "kimi-k2.7-code": 262_144, "kimi-k2.6": 262_144, "kimi-k2.5": 262_144, "glm-5.1": 198_000, "glm-5": 198_000, "MiniMax-M2.5": 196_608},
			recommendedReasoning:    4_000,
			recommendedReasoningIDs: map[string]struct{}{"qwen3.7-max": {}, "qwen3.7-plus": {}, "qwen3.6-plus": {}, "qwen3.6-flash": {}, "deepseek-v4-pro": {}, "deepseek-v4-flash": {}, "deepseek-v3.2": {}, "kimi-k2.7-code": {}, "glm-5.2": {}, "glm-5.1": {}, "glm-5": {}},
			multimodalModels:        map[string][]string{"qwen3.8-max-preview": {"text", "image", "video"}, "qwen3.7-plus": {"text", "image", "video"}, "qwen3.6-plus": {"text", "image", "video"}, "qwen3.6-flash": {"text", "image"}, "kimi-k2.7-code": {"text", "image", "video"}, "kimi-k2.5": {"text", "image", "video"}},
		},
		{
			catalogID:               "alibaba_token_plan_team_global",
			modelIDs:                []string{"qwen3.7-max", "qwen3.7-plus", "qwen3.6-plus", "qwen3.6-flash", "deepseek-v4-pro", "deepseek-v4-flash", "deepseek-v3.2", "kimi-k2.7-code", "kimi-k2.6", "kimi-k2.5", "glm-5.2", "glm-5.1", "glm-5", "MiniMax-M2.5", "qwen-image-2.0", "qwen-image-2.0-pro", "wan2.7-image-pro", "wan2.7-image"},
			contextOverrides:        map[string]int64{"deepseek-v3.2": 128_000, "kimi-k2.7-code": 256_000, "kimi-k2.6": 256_000, "kimi-k2.5": 256_000, "glm-5.2": 198_000, "glm-5.1": 198_000, "glm-5": 198_000, "MiniMax-M2.5": 192_000},
			recommendedReasoning:    4_000,
			recommendedReasoningIDs: map[string]struct{}{"qwen3.7-max": {}, "qwen3.7-plus": {}, "qwen3.6-plus": {}, "qwen3.6-flash": {}, "deepseek-v4-pro": {}, "deepseek-v4-flash": {}, "deepseek-v3.2": {}, "kimi-k2.7-code": {}, "glm-5.2": {}, "glm-5.1": {}, "glm-5": {}},
			multimodalModels:        map[string][]string{"qwen3.7-plus": {"text", "image", "video"}, "qwen3.6-plus": {"text", "image", "video"}, "qwen3.6-flash": {"text", "image"}, "kimi-k2.7-code": {"text", "image", "video"}, "kimi-k2.5": {"text", "image", "video"}},
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
				if template.actionBindingID == provideralibaba.TokenPlanHarnessConversationActionBindingID {
					continue
				}
				actualIDs = append(actualIDs, template.upstreamID)
				if template.operation != "" {
					continue
				}
				wantContext := int64(1_000_000)
				if override, exists := expectation.contextOverrides[template.upstreamID]; exists {
					wantContext = override
				}
				if template.contextWindow != wantContext {
					t.Errorf("model %s context = %d, want %d", template.upstreamID, template.contextWindow, wantContext)
				}
				wantInputModalities := []string{"text"}
				if documentedModalities, exists := expectation.multimodalModels[template.upstreamID]; exists {
					wantInputModalities = documentedModalities
				}
				if !reflect.DeepEqual(template.inputModalities, wantInputModalities) || template.reasoning != catalog.CapabilityNative || template.toolCalling != catalog.CapabilityNative || template.parallelTools != catalog.CapabilityUnknown || template.entitlementMode != catalog.EntitlementAllBoundCredentials {
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

// TestAlibabaTokenPlanPublishesExactAutomaticHarnessTools verifies product, model, and tool scope without inferring support for adjacent Qwen models.
// TestAlibabaTokenPlanPublishesExactAutomaticHarnessTools 校验产品、模型与工具范围，且不为相邻千问模型推断支持。
func TestAlibabaTokenPlanPublishesExactAutomaticHarnessTools(t *testing.T) {
	testCases := []struct {
		name             string
		models           []systemModelTemplate
		wantHarnessCount int
	}{
		{name: "personal-cn", models: alibabaTokenPlanPersonalCNModels(), wantHarnessCount: 3},
		{name: "team-cn", models: alibabaTokenPlanTeamCNModels(), wantHarnessCount: 3},
		{name: "team-global", models: alibabaTokenPlanTeamGlobalModels(), wantHarnessCount: 2},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			harnessCount := 0
			for _, model := range testCase.models {
				if model.actionBindingID != provideralibaba.TokenPlanHarnessConversationActionBindingID {
					if len(model.standardTools) != 0 || len(model.extraTools) != 0 {
						t.Fatalf("ordinary Chat model %s received Harness tools", model.upstreamID)
					}
					continue
				}
				harnessCount++
				if model.upstreamID != "qwen3.8-max-preview" && model.upstreamID != "qwen3.7-max" && model.upstreamID != "qwen3.7-plus" {
					t.Fatalf("model %s received inferred Harness offering", model.upstreamID)
				}
				if model.operation != vcp.OperationConversationRespond || len(model.standardTools) != 2 || len(model.extraTools) != 0 ||
					model.standardTools[0].Kind != vcp.StandardModelToolWebSearch || model.standardTools[1].Kind != vcp.StandardModelToolWebExtractor ||
					model.standardTools[0].AllowsCallerTools || model.standardTools[1].AllowsCallerTools ||
					!reflect.DeepEqual(model.inputModalities, []string{"text"}) || !reflect.DeepEqual(model.outputModalities, []string{"text"}) ||
					model.toolCalling != catalog.CapabilityUnsupported || model.reasoning != catalog.CapabilityUnsupported {
					t.Fatalf("model %s Harness offering = %#v", model.upstreamID, model)
				}
			}
			if harnessCount != testCase.wantHarnessCount {
				t.Fatalf("Harness offering count = %d, want %d", harnessCount, testCase.wantHarnessCount)
			}
		})
	}
	for _, model := range alibabaCodingPlanModels() {
		if len(model.standardTools) != 0 || len(model.extraTools) != 0 {
			t.Fatalf("Coding Plan model %s publishes unsupported Harness tools", model.upstreamID)
		}
	}
}

// TestAlibabaStaticPlanSnapshotsMatchExecutableTemplates verifies every published static plan fact has one exact code-owned executable model.
// TestAlibabaStaticPlanSnapshotsMatchExecutableTemplates 验证每个已发布静态套餐事实都具有一个精确的代码拥有可执行模型。
func TestAlibabaStaticPlanSnapshotsMatchExecutableTemplates(t *testing.T) {
	for _, catalogID := range []string{"alibaba_coding_plan_cn", "alibaba_coding_plan_global", "alibaba_token_plan_personal_cn", "alibaba_token_plan_team_cn", "alibaba_token_plan_team_global"} {
		t.Run(catalogID, func(t *testing.T) {
			providerSnapshot, verified, errSnapshot := catalogdata.SnapshotForCatalogID(catalogID)
			if errSnapshot != nil || !verified {
				t.Fatalf("SnapshotForCatalogID(%q) verified=%v error=%v", catalogID, verified, errSnapshot)
			}
			templates, errTemplates := systemModelTemplates(catalogID)
			if errTemplates != nil {
				t.Fatalf("systemModelTemplates(%q) error=%v", catalogID, errTemplates)
			}
			templateByModelID := make(map[string]systemModelTemplate, len(templates))
			for _, template := range templates {
				if template.actionBindingID == provideralibaba.TokenPlanHarnessConversationActionBindingID {
					continue
				}
				if _, exists := templateByModelID[template.upstreamID]; exists {
					t.Fatalf("catalog %q duplicates executable model %q", catalogID, template.upstreamID)
				}
				templateByModelID[template.upstreamID] = template
			}
			if len(templateByModelID) != len(providerSnapshot.Models) {
				t.Fatalf("catalog %q static/executable model counts = %d/%d", catalogID, len(providerSnapshot.Models), len(templateByModelID))
			}
			for _, fact := range providerSnapshot.Models {
				template, exists := templateByModelID[fact.ModelID]
				if !exists {
					t.Fatalf("catalog %q static model %q has no executable template", catalogID, fact.ModelID)
				}
				if fact.DisplayName != template.displayName || !alibabaModalitiesEqual(fact.RequestModalities, template.inputModalities) {
					t.Fatalf("catalog %q model %q static fact=%#v template=%#v", catalogID, fact.ModelID, fact, template)
				}
				if fact.ContextWindow != nil && *fact.ContextWindow != template.contextWindow {
					t.Fatalf("catalog %q model %q static context=%d template=%d", catalogID, fact.ModelID, *fact.ContextWindow, template.contextWindow)
				}
			}
		})
	}
}

// alibabaModalitiesEqual reports whether two modality lists contain the same unique values regardless of presentation order.
// alibabaModalitiesEqual 报告两个模态列表是否包含相同唯一值且不受展示顺序影响。
func alibabaModalitiesEqual(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	rightValues := make(map[string]struct{}, len(right))
	for _, value := range right {
		rightValues[value] = struct{}{}
	}
	for _, value := range left {
		if _, exists := rightValues[value]; !exists {
			return false
		}
	}
	return len(rightValues) == len(right)
}
