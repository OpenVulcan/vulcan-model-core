package management

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/bootstrap"
	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/alibaba/catalogdata"
	provideropenai "github.com/OpenVulcan/vulcan-model-core/internal/provider/openai"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestOfficialGeminiConversationModelsDeclareTokenLimits verifies every published Google conversation entry carries the official limits.
// TestOfficialGeminiConversationModelsDeclareTokenLimits 验证每个已发布 Google 会话条目都携带官方限制。
func TestOfficialGeminiConversationModelsDeclareTokenLimits(t *testing.T) {
	// testCases covers each Google entry point that publishes the shared Gemini text catalog.
	// testCases 覆盖发布共享 Gemini 文本目录的每个 Google 入口。
	testCases := []struct {
		name          string
		models        []systemModelTemplate
		expectedCount int
	}{
		{name: "AI Studio", models: geminiAIStudioModels(), expectedCount: 6},
		{name: "Interactions", models: geminiInteractionsModels(), expectedCount: 6},
		{name: "Vertex", models: geminiVertexTextModels(), expectedCount: 7},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// conversationCount proves operation-specific media templates are excluded without losing a text model.
			// conversationCount 证明排除操作专属媒体模板时没有丢失文本模型。
			conversationCount := 0
			for _, model := range testCase.models {
				if model.operation != "" && model.operation != vcp.OperationConversationRespond {
					continue
				}
				if model.upstreamID == "gemini-3-pro-preview" || model.upstreamID == "gemini-3.1-flash-lite-preview" {
					t.Fatalf("%s still publishes retired model %q", testCase.name, model.upstreamID)
				}
				conversationCount++
				if model.contextWindow != 1048576 || model.maxInputTokens != 1048576 || model.maxOutputTokens != 65536 {
					t.Fatalf("%s %s token limits = context:%d input:%d output:%d", testCase.name, model.upstreamID, model.contextWindow, model.maxInputTokens, model.maxOutputTokens)
				}
			}
			if conversationCount != testCase.expectedCount {
				t.Fatalf("%s conversation model count = %d, want %d", testCase.name, conversationCount, testCase.expectedCount)
			}
		})
	}
}

// TestDeepSeekCatalogDeclaresExactOfficialModelsAndLimits verifies the public API exposes only the current two models with fixed token semantics.
// TestDeepSeekCatalogDeclaresExactOfficialModelsAndLimits 验证公共 API 仅公开当前两个模型并使用固定 Token 语义。
func TestDeepSeekCatalogDeclaresExactOfficialModelsAndLimits(t *testing.T) {
	models := deepSeekModels()
	expectedIDs := []string{"deepseek-v4-flash", "deepseek-v4-pro"}
	if len(models) != len(expectedIDs) {
		t.Fatalf("DeepSeek model count = %d, want %d", len(models), len(expectedIDs))
	}
	for index, model := range models {
		if model.upstreamID != expectedIDs[index] {
			t.Fatalf("model[%d] ID = %q, want %q", index, model.upstreamID, expectedIDs[index])
		}
		if model.contextWindow != 1000000 || model.maxInputTokens != 840000 || model.maxOutputTokens != 393216 || model.recommendedOutputTokens != 128000 {
			t.Fatalf("model[%d] token limits = context:%d input:%d output:%d recommended:%d", index, model.contextWindow, model.maxInputTokens, model.maxOutputTokens, model.recommendedOutputTokens)
		}
		if model.reasoning != catalog.CapabilityNative || model.toolCalling != catalog.CapabilityNative || len(model.reasoningEfforts) != 2 || model.reasoningEfforts[0] != "high" || model.reasoningEfforts[1] != "max" {
			t.Fatalf("model[%d] capabilities = %#v", index, model)
		}
	}
}

// TestMiniMaxM3DeclaresConservativeOfficialTokenLimits verifies the M3 catalog records its official context and conservative output ceiling.
// TestMiniMaxM3DeclaresConservativeOfficialTokenLimits 验证 M3 目录记录官方上下文与保守输出上限。
func TestMiniMaxM3DeclaresConservativeOfficialTokenLimits(t *testing.T) {
	// models contains the provider's exact published text-model set.
	// models 包含供应商精确发布的文本模型集合。
	models := miniMaxTextModels()
	if len(models) != 1 {
		t.Fatalf("MiniMax text model count = %d, want 1", len(models))
	}
	// model is the only currently published MiniMax conversation model.
	// model 是当前唯一发布的 MiniMax 会话模型。
	model := models[0]
	if model.upstreamID != "MiniMax-M3" || model.contextWindow != 1048576 || model.maxInputTokens != 1048576 || model.maxOutputTokens != 32768 {
		t.Fatalf("MiniMax M3 limits = id:%s context:%d input:%d output:%d", model.upstreamID, model.contextWindow, model.maxInputTokens, model.maxOutputTokens)
	}
}

// TestAlibabaVerifiedFactsAndPoliciesReachTheInternalCatalog verifies publication filtering never drops provider models or classified operation decisions.
// TestAlibabaVerifiedFactsAndPoliciesReachTheInternalCatalog 验证发布过滤绝不会丢弃供应商模型或已分类操作决策。
func TestAlibabaVerifiedFactsAndPoliciesReachTheInternalCatalog(t *testing.T) {
	protocols := providerconfig.NewProtocolRegistry()
	if errProtocols := bootstrap.RegisterProtocolProfiles(protocols); errProtocols != nil {
		t.Fatal(errProtocols)
	}
	systems, errSystems := providerconfig.NewSystemRegistry(protocols)
	if errSystems != nil {
		t.Fatal(errSystems)
	}
	if errProviders := bootstrap.RegisterSystemProviders(systems); errProviders != nil {
		t.Fatal(errProviders)
	}
	definitionIDs := []string{bootstrap.AlibabaModelStudioCNDefinitionID, bootstrap.AlibabaModelStudioGlobalDefinitionID, bootstrap.AlibabaTokenPlanPersonalCNDefinitionID}
	for _, definitionID := range definitionIDs {
		definition, exists := systems.Lookup(definitionID)
		if !exists {
			t.Fatalf("definition %q missing", definitionID)
		}
		source, verified, errSource := catalogdata.SnapshotForCatalogID(definition.ModelCatalogID)
		if errSource != nil || !verified {
			t.Fatalf("source %q verified=%v error=%v", definition.ModelCatalogID, verified, errSource)
		}
		built, errBuild := buildSystemCatalog(providerconfig.SystemOnboarding{Instance: providerconfig.ProviderInstance{ID: "pvi_alibaba_count"}}, definition, time.Date(2026, 7, 23, 5, 0, 0, 0, time.UTC))
		if errBuild != nil {
			t.Fatalf("build %q: %v", definitionID, errBuild)
		}
		models := make(map[string]string, len(built.Models))
		for _, model := range built.Models {
			models[model.UpstreamModelID] = model.ID
		}
		policies := make(map[string]int)
		for _, policy := range built.ModelOperationPolicies {
			policies[policy.ProviderModelID+"\x00"+string(policy.Operation)]++
		}
		for _, fact := range source.Models {
			modelID, exists := models[fact.ModelID]
			if !exists {
				t.Fatalf("catalog %q dropped provider fact %q", definition.ModelCatalogID, fact.ModelID)
			}
			for _, operation := range catalogdata.ClassifiedOperations(fact) {
				if policies[modelID+"\x00"+string(operation)] != 1 {
					t.Fatalf("catalog %q model %q operation %q policy count = %d", definition.ModelCatalogID, fact.ModelID, operation, policies[modelID+"\x00"+string(operation)])
				}
			}
		}
	}
}

// TestAlibabaCatalogSeparatesCompatibleAndNativeEntitlementScopes verifies /models gates only products with a verified listing contract and never removes independently proven native actions.
// TestAlibabaCatalogSeparatesCompatibleAndNativeEntitlementScopes 验证 /models 仅约束拥有已验证列表合同的产品，绝不会移除独立证明的原生操作。
func TestAlibabaCatalogSeparatesCompatibleAndNativeEntitlementScopes(t *testing.T) {
	protocols := providerconfig.NewProtocolRegistry()
	if errProtocols := bootstrap.RegisterProtocolProfiles(protocols); errProtocols != nil {
		t.Fatal(errProtocols)
	}
	systems, errSystems := providerconfig.NewSystemRegistry(protocols)
	if errSystems != nil {
		t.Fatal(errSystems)
	}
	if errProviders := bootstrap.RegisterSystemProviders(systems); errProviders != nil {
		t.Fatal(errProviders)
	}
	definitionIDs := []string{
		bootstrap.AlibabaCodingPlanCNDefinitionID,
		bootstrap.AlibabaModelStudioCNDefinitionID,
		bootstrap.AlibabaModelStudioGlobalDefinitionID,
		bootstrap.AlibabaTokenPlanPersonalCNDefinitionID,
	}
	for _, definitionID := range definitionIDs {
		definition, exists := systems.Lookup(definitionID)
		if !exists {
			t.Fatalf("definition %q missing", definitionID)
		}
		snapshot, errBuild := buildSystemCatalog(providerconfig.SystemOnboarding{Instance: providerconfig.ProviderInstance{ID: "pvi_alibaba_entitlement_" + definitionID}}, definition, time.Date(2026, 7, 23, 5, 0, 0, 0, time.UTC))
		if errBuild != nil {
			t.Fatalf("build %q: %v", definitionID, errBuild)
		}
		modelsByID := make(map[string]catalog.ProviderModel, len(snapshot.Models))
		for _, model := range snapshot.Models {
			modelsByID[model.ID] = model
		}
		offeringsByID := make(map[string]catalog.ModelOffering, len(snapshot.Offerings))
		for _, offering := range snapshot.Offerings {
			offeringsByID[offering.ID] = offering
		}
		for _, profile := range snapshot.Profiles {
			if profile.OfferingID == "" {
				continue
			}
			model := modelsByID[offeringsByID[profile.OfferingID].ProviderModelID]
			if model.EntitlementMode != catalog.EntitlementAllBoundCredentials {
				t.Fatalf("definition %q executable model %q entitlement = %q", definitionID, model.UpstreamModelID, model.EntitlementMode)
			}
			if len(profile.RequiredEntitlementClasses) != 0 {
				t.Fatalf("definition %q static profile %q unexpectedly requires %v", definitionID, profile.ID, profile.RequiredEntitlementClasses)
			}
		}
	}
}

// TestAlibabaStaticPlanCatalogUsesContractEvidence verifies static product templates use committed facts without claiming runtime discovery.
// TestAlibabaStaticPlanCatalogUsesContractEvidence 验证静态产品模板使用已提交事实且不声称运行时发现。
func TestAlibabaStaticPlanCatalogUsesContractEvidence(t *testing.T) {
	protocols := providerconfig.NewProtocolRegistry()
	if errProtocols := bootstrap.RegisterProtocolProfiles(protocols); errProtocols != nil {
		t.Fatal(errProtocols)
	}
	systems, errSystems := providerconfig.NewSystemRegistry(protocols)
	if errSystems != nil {
		t.Fatal(errSystems)
	}
	if errProviders := bootstrap.RegisterSystemProviders(systems); errProviders != nil {
		t.Fatal(errProviders)
	}
	definition, exists := systems.Lookup(bootstrap.AlibabaCodingPlanCNDefinitionID)
	if !exists {
		t.Fatal("Alibaba Coding Plan CN definition is missing")
	}
	providerSnapshot, verified, errSource := catalogdata.SnapshotForCatalogID(definition.ModelCatalogID)
	if errSource != nil || !verified || providerSnapshot.SourceAPI == "/v1/models" || providerSnapshot.SourceAPI == "/compatible-mode/v1/models" {
		t.Fatalf("Coding Plan static catalog verified=%v source=%q error=%v", verified, providerSnapshot.SourceAPI, errSource)
	}
	snapshot, errBuild := buildSystemCatalog(providerconfig.SystemOnboarding{Instance: providerconfig.ProviderInstance{ID: "pvi_alibaba_contract_evidence"}}, definition, time.Date(2026, 7, 23, 5, 0, 0, 0, time.UTC))
	if errBuild != nil {
		t.Fatalf("build Coding Plan catalog: %v", errBuild)
	}
	if len(snapshot.ModelOperationPolicies) == 0 {
		t.Fatal("Coding Plan catalog has no publication policies")
	}
	for _, policy := range snapshot.ModelOperationPolicies {
		if policy.Status != catalog.ModelOperationSupported || policy.Reason != catalog.SupportReasonProviderContractVerified {
			t.Fatalf("Coding Plan policy evidence = %#v", policy)
		}
	}
}

// TestAlibabaUnverifiedBoundariesRemainUnpublished verifies incomplete regional and product evidence cannot create runtime definitions.
// TestAlibabaUnverifiedBoundariesRemainUnpublished 验证不完整的区域与产品证据不能创建运行时定义。
func TestAlibabaUnverifiedBoundariesRemainUnpublished(t *testing.T) {
	protocols := providerconfig.NewProtocolRegistry()
	if errProtocols := bootstrap.RegisterProtocolProfiles(protocols); errProtocols != nil {
		t.Fatal(errProtocols)
	}
	systems, errSystems := providerconfig.NewSystemRegistry(protocols)
	if errSystems != nil {
		t.Fatal(errSystems)
	}
	if errProviders := bootstrap.RegisterSystemProviders(systems); errProviders != nil {
		t.Fatal(errProviders)
	}
	for _, definitionID := range []string{bootstrap.AlibabaModelStudioUSDefinitionID, bootstrap.AlibabaModelStudioWorkspaceGlobalDefinitionID, bootstrap.AlibabaTokenPlanPersonalGlobalDefinitionID} {
		if _, exists := systems.Lookup(definitionID); exists {
			t.Fatalf("unverified Alibaba definition %q was published", definitionID)
		}
	}
	for _, catalogID := range []string{"alibaba_model_studio_hong_kong", "alibaba_model_studio_tokyo", "alibaba_model_studio_frankfurt", "alibaba_model_studio_us", "alibaba_model_studio_workspace_sg", "alibaba_token_plan_personal_global"} {
		_, verified, errSource := catalogdata.SnapshotForCatalogID(catalogID)
		if errSource != nil || verified {
			t.Fatalf("unverified Alibaba catalog %q verified=%v error=%v", catalogID, verified, errSource)
		}
	}
}

// TestEveryRuntimeReadySystemDefinitionOwnsAValidInitialCatalog verifies provider selection never fails after credential acquisition.
// TestEveryRuntimeReadySystemDefinitionOwnsAValidInitialCatalog 验证凭据获取后选择供应商绝不会因目录缺失而失败。
func TestEveryRuntimeReadySystemDefinitionOwnsAValidInitialCatalog(t *testing.T) {
	protocols := providerconfig.NewProtocolRegistry()
	if errProtocols := bootstrap.RegisterProtocolProfiles(protocols); errProtocols != nil {
		t.Fatalf("RegisterProtocolProfiles() error = %v", errProtocols)
	}
	systems, errSystems := providerconfig.NewSystemRegistry(protocols)
	if errSystems != nil {
		t.Fatalf("NewSystemRegistry() error = %v", errSystems)
	}
	if errProviders := bootstrap.RegisterSystemProviders(systems); errProviders != nil {
		t.Fatalf("RegisterSystemProviders() error = %v", errProviders)
	}
	observedAt := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	for index, definition := range systems.List() {
		if !definition.RuntimeReady {
			continue
		}
		snapshot, errCatalog := buildSystemCatalog(providerconfig.SystemOnboarding{Instance: providerconfig.ProviderInstance{ID: fmt.Sprintf("pvi_catalog_%d", index)}}, definition, observedAt)
		if errCatalog != nil {
			t.Errorf("definition %s catalog error = %v", definition.ID, errCatalog)
			continue
		}
		if errValidate := snapshot.Validate(); errValidate != nil {
			t.Errorf("definition %s catalog validation error = %v", definition.ID, errValidate)
		}
		offeringsByID := make(map[string]catalog.ModelOffering, len(snapshot.Offerings))
		for _, offering := range snapshot.Offerings {
			offeringsByID[offering.ID] = offering
		}
		serviceOfferingsByID := make(map[string]catalog.ServiceOffering, len(snapshot.ServiceOfferings))
		for _, offering := range snapshot.ServiceOfferings {
			serviceOfferingsByID[offering.ID] = offering
		}
		for _, profile := range snapshot.Profiles {
			action, errAction := definitionActionByID(definition, profile.ActionBindingID)
			if profile.ServiceOfferingID != "" {
				offering := serviceOfferingsByID[profile.ServiceOfferingID]
				if errAction != nil || profile.ActionBindingID != action.ID || offering.ChannelID != action.ProtocolProfileID || profile.ServiceCapabilities == nil {
					t.Errorf("definition %s service profile action contract = %#v", definition.ID, profile)
				}
				continue
			}
			offering := offeringsByID[profile.OfferingID]
			if errAction != nil || profile.ActionBindingID != action.ID || offering.ChannelID != action.ProtocolProfileID || profile.Capabilities.Delivery.Synchronous && !action.Delivery.Synchronous || profile.Capabilities.Delivery.Streaming && !action.Delivery.Streaming || profile.Capabilities.Delivery.Asynchronous && !action.Delivery.Asynchronous {
				t.Errorf("definition %s profile action contract = %#v", definition.ID, profile)
			}
		}
	}
}

// TestOpenAIAPIInitialCatalogPublishesGroundedSearchAndEmbeddingModels verifies the evidence-closed OpenAI inventory.
// TestOpenAIAPIInitialCatalogPublishesGroundedSearchAndEmbeddingModels 验证证据封闭的 OpenAI 清单。
func TestOpenAIAPIInitialCatalogPublishesGroundedSearchAndEmbeddingModels(t *testing.T) {
	templates, errTemplates := systemModelTemplates("openai_api")
	if errTemplates != nil {
		t.Fatalf("systemModelTemplates() error = %v", errTemplates)
	}
	if len(templates) != 11 || templates[0].upstreamID != provideropenai.SearchBackingModelID || templates[1].upstreamID != "text-embedding-3-small" || templates[2].upstreamID != "text-embedding-3-large" || templates[3].operation != vcp.OperationImageGenerate || templates[4].operation != vcp.OperationImageEdit || templates[5].operation != vcp.OperationSpeechSynthesize || templates[7].operation != vcp.OperationSpeechTranscribe || templates[10].upstreamID != "whisper-1" {
		t.Fatalf("OpenAI API templates = %#v", templates)
	}
	for _, template := range templates[1:3] {
		if template.operation != vcp.OperationEmbeddingCreate || template.embedding == nil || template.embedding.MaxBatchItems.Value != 2048 {
			t.Fatalf("OpenAI embedding template = %#v", template)
		}
	}
}

// TestBuildSystemCatalogSharesTemplatesButIsolatesInstanceOwnership verifies regional reuse and Coding Plan separation.
// TestBuildSystemCatalogSharesTemplatesButIsolatesInstanceOwnership 验证区域模板复用和 Coding Plan 分离。
func TestBuildSystemCatalogSharesTemplatesButIsolatesInstanceOwnership(t *testing.T) {
	protocols := providerconfig.NewProtocolRegistry()
	if errProtocols := bootstrap.RegisterProtocolProfiles(protocols); errProtocols != nil {
		t.Fatalf("RegisterProtocolProfiles() error = %v", errProtocols)
	}
	systems, errSystems := providerconfig.NewSystemRegistry(protocols)
	if errSystems != nil {
		t.Fatalf("NewSystemRegistry() error = %v", errSystems)
	}
	if errProviders := bootstrap.RegisterSystemProviders(systems); errProviders != nil {
		t.Fatalf("RegisterSystemProviders() error = %v", errProviders)
	}
	observedAt := time.Date(2026, 7, 18, 13, 0, 0, 0, time.UTC)
	cnDefinition, _ := systems.Lookup(bootstrap.KimiCNDefinitionID)
	globalDefinition, _ := systems.Lookup(bootstrap.KimiGlobalDefinitionID)
	codingDefinition, _ := systems.Lookup(bootstrap.KimiCodingDefinitionID)
	cn, errCN := buildSystemCatalog(providerconfig.SystemOnboarding{Instance: providerconfig.ProviderInstance{ID: "pvi_cn"}}, cnDefinition, observedAt)
	global, errGlobal := buildSystemCatalog(providerconfig.SystemOnboarding{Instance: providerconfig.ProviderInstance{ID: "pvi_global"}}, globalDefinition, observedAt)
	coding, errCoding := buildSystemCatalog(providerconfig.SystemOnboarding{Instance: providerconfig.ProviderInstance{ID: "pvi_coding"}}, codingDefinition, observedAt)
	if errCN != nil || errGlobal != nil || errCoding != nil {
		t.Fatalf("catalog errors CN=%v Global=%v Coding=%v", errCN, errGlobal, errCoding)
	}
	if len(cn.Models) != 11 || len(global.Models) != 11 || len(coding.Models) != 3 || len(coding.Offerings) != 3 || len(coding.Profiles) != 4 {
		t.Fatalf("catalog sizes CN=%d Global=%d Coding models=%d offerings=%d", len(cn.Models), len(global.Models), len(coding.Models), len(coding.Offerings))
	}
	for index := range cn.Models {
		if cn.Models[index].UpstreamModelID != global.Models[index].UpstreamModelID || cn.Models[index].ProviderInstanceID == global.Models[index].ProviderInstanceID {
			t.Fatalf("regional model ownership CN=%#v Global=%#v", cn.Models[index], global.Models[index])
		}
	}
	modelByUpstreamID := make(map[string]catalog.ProviderModel, len(cn.Models))
	for _, model := range cn.Models {
		modelByUpstreamID[model.UpstreamModelID] = model
	}
	for _, currentModelID := range []string{"kimi-k3", "kimi-k2.7-code", "kimi-k2.7-code-highspeed", "kimi-k2.6"} {
		if _, exists := modelByUpstreamID[currentModelID]; !exists {
			t.Fatalf("current Open Platform model %q is missing", currentModelID)
		}
	}
	for _, restrictedModelID := range []string{"kimi-k2.5", "moonshot-v1-8k", "moonshot-v1-32k", "moonshot-v1-128k"} {
		if modelByUpstreamID[restrictedModelID].EntitlementMode != catalog.EntitlementExplicit {
			t.Fatalf("restricted model %q entitlement = %q", restrictedModelID, modelByUpstreamID[restrictedModelID].EntitlementMode)
		}
	}
	// codingModelIDs is the exact user-confirmed Kimi Coding Plan product set.
	// codingModelIDs 是用户确认的精确 Kimi Coding Plan 产品集合。
	codingModelIDs := []string{"kimi-for-coding", "k3", "kimi-for-coding-highspeed"}
	for index, modelID := range codingModelIDs {
		if coding.Models[index].UpstreamModelID != modelID || coding.Models[index].EntitlementMode != catalog.EntitlementExplicit {
			t.Fatalf("Coding model[%d] = %#v, want upstream %q with explicit entitlement", index, coding.Models[index], modelID)
		}
	}
	for _, snapshot := range []catalog.Snapshot{cn, global, coding} {
		modelIDs := make(map[string]string, len(snapshot.Models))
		for _, model := range snapshot.Models {
			modelIDs[model.ID] = model.UpstreamModelID
		}
		for _, offering := range snapshot.Offerings {
			upstreamID := modelIDs[offering.ProviderModelID]
			if (upstreamID == "kimi-k2.7-code" || upstreamID == "kimi-k2.7-code-highspeed" || upstreamID == "kimi-for-coding" || upstreamID == "kimi-for-coding-highspeed") && offering.Capabilities.Reasoning != catalog.CapabilityNative {
				t.Fatalf("Kimi K2.7 offering %q reasoning = %q, want native", upstreamID, offering.Capabilities.Reasoning)
			}
		}
	}
}

// TestBuildSystemCatalogSeparatesCodexKeyAndAccountEntitlements verifies one shared model union keeps product-specific authorization semantics.
// TestBuildSystemCatalogSeparatesCodexKeyAndAccountEntitlements 验证共享模型并集仍保留产品特定授权语义。
func TestBuildSystemCatalogSeparatesCodexKeyAndAccountEntitlements(t *testing.T) {
	protocols := providerconfig.NewProtocolRegistry()
	if errProtocols := bootstrap.RegisterProtocolProfiles(protocols); errProtocols != nil {
		t.Fatalf("RegisterProtocolProfiles() error = %v", errProtocols)
	}
	systems, errSystems := providerconfig.NewSystemRegistry(protocols)
	if errSystems != nil {
		t.Fatalf("NewSystemRegistry() error = %v", errSystems)
	}
	if errProviders := bootstrap.RegisterSystemProviders(systems); errProviders != nil {
		t.Fatalf("RegisterSystemProviders() error = %v", errProviders)
	}
	apiKeyDefinition, _ := systems.Lookup(bootstrap.OpenAICodexAPIKeyDefinitionID)
	accountDefinition, _ := systems.Lookup(bootstrap.OpenAICodexDefinitionID)
	observedAt := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	apiKeyCatalog, errAPIKey := buildSystemCatalog(providerconfig.SystemOnboarding{Instance: providerconfig.ProviderInstance{ID: "pvi_codex_key"}}, apiKeyDefinition, observedAt)
	accountCatalog, errAccount := buildSystemCatalog(providerconfig.SystemOnboarding{Instance: providerconfig.ProviderInstance{ID: "pvi_codex_account"}}, accountDefinition, observedAt)
	if errAPIKey != nil || errAccount != nil {
		t.Fatalf("Codex catalog errors API key=%v account=%v", errAPIKey, errAccount)
	}
	if len(apiKeyCatalog.Models) != 8 || len(accountCatalog.Models) != 8 {
		t.Fatalf("Codex catalog sizes API key=%d account=%d", len(apiKeyCatalog.Models), len(accountCatalog.Models))
	}
	for index := range apiKeyCatalog.Models {
		if apiKeyCatalog.Models[index].UpstreamModelID != accountCatalog.Models[index].UpstreamModelID {
			t.Fatalf("Codex model identity[%d] API key=%#v account=%#v", index, apiKeyCatalog.Models[index], accountCatalog.Models[index])
		}
		if apiKeyCatalog.Models[index].EntitlementMode != catalog.EntitlementAllBoundCredentials || accountCatalog.Models[index].EntitlementMode != catalog.EntitlementExplicit {
			t.Fatalf("Codex entitlement mode[%d] API key=%q account=%q", index, apiKeyCatalog.Models[index].EntitlementMode, accountCatalog.Models[index].EntitlementMode)
		}
	}
}

// TestOnboardingCompensatesConfigurationAndSecretWhenCatalogFails verifies the cross-store saga boundary.
// TestOnboardingCompensatesConfigurationAndSecretWhenCatalogFails 验证跨存储 Saga 边界。
func TestOnboardingCompensatesConfigurationAndSecretWhenCatalogFails(t *testing.T) {
	ctx := context.Background()
	protocols := providerconfig.NewProtocolRegistry()
	if errProtocols := bootstrap.RegisterProtocolProfiles(protocols); errProtocols != nil {
		t.Fatalf("RegisterProtocolProfiles() error = %v", errProtocols)
	}
	systems, _ := providerconfig.NewSystemRegistry(protocols)
	if errProviders := bootstrap.RegisterSystemProviders(systems); errProviders != nil {
		t.Fatalf("RegisterSystemProviders() error = %v", errProviders)
	}
	configurations, _ := providerconfig.NewMemoryStore(protocols, systems)
	secrets := secret.NewMemoryStore()
	service, errService := NewService(configurations, secrets, failingCatalogStore{})
	if errService != nil {
		t.Fatalf("NewService() error = %v", errService)
	}
	_, errOnboard := service.OnboardSystemProvider(ctx, OnboardSystemProviderInput{DefinitionID: bootstrap.KimiCNDefinitionID, Handle: "catalog-failure", DisplayName: "Failure", AuthMethodID: "api_key", CredentialLabel: "Primary", Secret: []byte("temporary")})
	if errOnboard == nil {
		t.Fatal("OnboardSystemProvider() error = nil, want catalog failure")
	}
	instances, errInstances := configurations.ListInstances(ctx, bootstrap.KimiCNDefinitionID)
	if errInstances != nil || len(instances) != 0 || secrets.Count() != 0 {
		t.Fatalf("compensation instances=%#v error=%v secrets=%d", instances, errInstances, secrets.Count())
	}
}

// TestOnboardingCompensatesAmbiguousCatalogCommit verifies catalog cleanup precedes configuration cleanup after a commit-like error.
// TestOnboardingCompensatesAmbiguousCatalogCommit 验证类似已提交错误发生后目录补偿先于配置补偿。
func TestOnboardingCompensatesAmbiguousCatalogCommit(t *testing.T) {
	ctx := context.Background()
	protocols := providerconfig.NewProtocolRegistry()
	if errProtocols := bootstrap.RegisterProtocolProfiles(protocols); errProtocols != nil {
		t.Fatalf("RegisterProtocolProfiles() error = %v", errProtocols)
	}
	systems, errSystems := providerconfig.NewSystemRegistry(protocols)
	if errSystems != nil {
		t.Fatalf("NewSystemRegistry() error = %v", errSystems)
	}
	if errProviders := bootstrap.RegisterSystemProviders(systems); errProviders != nil {
		t.Fatalf("RegisterSystemProviders() error = %v", errProviders)
	}
	configurations, errConfigurations := providerconfig.NewMemoryStore(protocols, systems)
	if errConfigurations != nil {
		t.Fatalf("NewMemoryStore() error = %v", errConfigurations)
	}
	secrets := secret.NewMemoryStore()
	catalogs := &ambiguousCatalogStore{MemoryStore: catalog.NewMemoryStore()}
	service, errService := NewService(configurations, secrets, catalogs)
	if errService != nil {
		t.Fatalf("NewService() error = %v", errService)
	}
	_, errOnboard := service.OnboardSystemProvider(ctx, OnboardSystemProviderInput{DefinitionID: bootstrap.KimiCNDefinitionID, Handle: "ambiguous-catalog", DisplayName: "Ambiguous", AuthMethodID: "api_key", CredentialLabel: "Primary", Secret: []byte("temporary")})
	if errOnboard == nil {
		t.Fatal("OnboardSystemProvider() error = nil, want ambiguous catalog failure")
	}
	instances, errInstances := configurations.ListInstances(ctx, bootstrap.KimiCNDefinitionID)
	if errInstances != nil || len(instances) != 0 || secrets.Count() != 0 || !catalogs.deleted {
		t.Fatalf("compensation instances=%#v error=%v secrets=%d catalogDeleted=%t", instances, errInstances, secrets.Count(), catalogs.deleted)
	}
}

// failingCatalogStore deterministically rejects catalog persistence for compensation testing.
// failingCatalogStore 为补偿测试确定性拒绝目录持久化。
type failingCatalogStore struct{}

// Save rejects every snapshot.
// Save 拒绝每个快照。
func (failingCatalogStore) Save(context.Context, catalog.Snapshot) error {
	return errors.New("catalog unavailable")
}

// Delete reports that no snapshot was committed.
// Delete 报告没有快照被提交。
func (failingCatalogStore) Delete(context.Context, string) error {
	return catalog.ErrSnapshotNotFound
}

// Get reports no snapshot.
// Get 报告不存在快照。
func (failingCatalogStore) Get(context.Context, string) (catalog.Snapshot, error) {
	return catalog.Snapshot{}, catalog.ErrSnapshotNotFound
}

// ambiguousCatalogStore commits a snapshot and then reports an error to exercise idempotent saga compensation.
// ambiguousCatalogStore 提交快照后再报告错误，以验证幂等 Saga 补偿。
type ambiguousCatalogStore struct {
	// MemoryStore persists the snapshot before the simulated acknowledgement failure.
	// MemoryStore 在模拟确认失败前持久化快照。
	*catalog.MemoryStore
	// deleted records whether saga compensation removed the committed snapshot.
	// deleted 记录 Saga 补偿是否移除了已提交快照。
	deleted bool
}

// Save persists the snapshot before returning a deterministic ambiguous failure.
// Save 先持久化快照再返回确定性的模糊失败。
func (s *ambiguousCatalogStore) Save(ctx context.Context, snapshot catalog.Snapshot) error {
	if errSave := s.MemoryStore.Save(ctx, snapshot); errSave != nil {
		return errSave
	}
	return errors.New("catalog commit acknowledgement lost")
}

// Delete records and delegates exact snapshot cleanup.
// Delete 记录并委托精确快照清理。
func (s *ambiguousCatalogStore) Delete(ctx context.Context, providerInstanceID string) error {
	s.deleted = true
	return s.MemoryStore.Delete(ctx, providerInstanceID)
}
