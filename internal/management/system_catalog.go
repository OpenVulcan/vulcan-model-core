package management

import (
	"fmt"
	"strings"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	provideranthropic "github.com/OpenVulcan/vulcan-model-core/internal/provider/anthropic"
	providergoogle "github.com/OpenVulcan/vulcan-model-core/internal/provider/google"
	provideropenai "github.com/OpenVulcan/vulcan-model-core/internal/provider/openai"
	providerxai "github.com/OpenVulcan/vulcan-model-core/internal/provider/xai"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// systemModelTemplate contains code-owned facts shared across instance-isolated catalog records.
// systemModelTemplate 包含在实例隔离目录记录之间共享的代码拥有事实。
type systemModelTemplate struct {
	// upstreamID is the exact provider model identifier.
	// upstreamID 是精确的供应商模型标识。
	upstreamID string
	// displayName is the operator-facing model name.
	// displayName 是面向操作员的模型名称。
	displayName string
	// contextWindow is the verified maximum input and output context size.
	// contextWindow 是已验证的最大输入输出上下文大小。
	contextWindow int64
	// maxInputTokens is the independently verified input ceiling when known.
	// maxInputTokens 是独立验证且已知时的输入上限。
	maxInputTokens int64
	// maxOutputTokens is the provider-declared maximum completion size when known.
	// maxOutputTokens 是已知时由供应商声明的最大补全大小。
	maxOutputTokens int64
	// maxReasoningTokens is the provider-declared reasoning budget ceiling when known.
	// maxReasoningTokens 是已知时由供应商声明的推理预算上限。
	maxReasoningTokens int64
	// recommendedOutputTokens is the provider-evidenced default output budget when known.
	// recommendedOutputTokens 是供应商证据支持且已知时的默认输出预算。
	recommendedOutputTokens int64
	// recommendedReasoningTokens is the provider-evidenced default reasoning budget when known.
	// recommendedReasoningTokens 是供应商证据支持且已知时的默认推理预算。
	recommendedReasoningTokens int64
	// inputModalities lists the exact accepted resource kinds.
	// inputModalities 列出精确接受的资源类型。
	inputModalities []string
	// reasoning records the verified reasoning capability level.
	// reasoning 记录已验证的推理能力等级。
	reasoning catalog.CapabilityLevel
	// reasoningEfforts lists exact accepted reasoning controls.
	// reasoningEfforts 列出精确接受的推理控制值。
	reasoningEfforts []string
	// toolCalling records the verified tool-call capability level.
	// toolCalling 记录已验证的工具调用能力等级。
	toolCalling catalog.CapabilityLevel
	// parallelTools records verified parallel tool-call support.
	// parallelTools 记录已验证的并行工具调用支持。
	parallelTools catalog.CapabilityLevel
	// streamingTools records verified streamed tool-call support.
	// streamingTools 记录已验证的流式工具调用支持。
	streamingTools catalog.CapabilityLevel
	// strictSchema records verified strict JSON Schema support.
	// strictSchema 记录已验证的严格 JSON Schema 支持。
	strictSchema catalog.CapabilityLevel
	// entitlementMode determines how access is verified for the model.
	// entitlementMode 决定模型访问权的验证方式。
	entitlementMode catalog.EntitlementMode
	// operation identifies the sole callable VCP operation; empty preserves historical conversation templates.
	// operation 标识唯一可调用 VCP 操作；空值保留历史会话模板。
	operation vcp.OperationKind
	// actionBindingID selects one exact internal action when a definition owns multiple actions for the same operation.
	// actionBindingID 在一个定义为同一操作拥有多个动作时选择唯一精确的内部动作。
	actionBindingID string
	// embedding contains exact vectorization facts only for embedding models.
	// embedding 仅为 Embedding 模型包含精确向量化事实。
	embedding *catalog.EmbeddingCapabilities
	// rerank contains exact ranking facts only for rerank models.
	// rerank 仅为 Rerank 模型包含精确排序事实。
	rerank *catalog.RerankCapabilities
	// mediaInputs contains exact per-kind understanding contracts.
	// mediaInputs 包含按媒体类型定义的精确理解合同。
	mediaInputs []catalog.MediaInputCapability
	// mediaOutputs contains exact generated-resource contracts.
	// mediaOutputs 包含精确生成资源合同。
	mediaOutputs []catalog.MediaOutputCapability
	// parameters contains closed operation parameter descriptors.
	// parameters 包含封闭操作参数描述符。
	parameters []catalog.ParameterDescriptor
	// parameterRules contains cross-field validity constraints.
	// parameterRules 包含跨字段有效性约束。
	parameterRules []catalog.ParameterRule
	// usageMetrics contains independently observable billing dimensions.
	// usageMetrics 包含可独立观测的计费维度。
	usageMetrics []catalog.UsageMetricCapability
	// profiles contains explicit capability shapes when one offering has multiple entitlement tiers.
	// profiles 在一个产品具有多个权益档位时包含显式能力形态。
	profiles []systemProfileTemplate
}

// systemProfileTemplate describes one explicit code-owned profile below an offering ceiling.
// systemProfileTemplate 描述一个低于产品能力上限的显式代码拥有规格。
type systemProfileTemplate struct {
	// suffix is appended to the stable profile identifier.
	// suffix 追加到稳定规格标识。
	suffix string
	// displayName is the client-visible capability shape name.
	// displayName 是客户端可见的能力形态名称。
	displayName string
	// contextWindow is the exact total context limit for this profile.
	// contextWindow 是该规格精确的总上下文限制。
	contextWindow int64
	// defaultProfile reports whether clients may omit this profile selection.
	// defaultProfile 表示客户端是否可以省略该规格选择。
	defaultProfile bool
}

// buildSystemCatalog materializes one immutable template into records owned only by the new instance.
// buildSystemCatalog 将一个不可变模板实例化为仅由新实例拥有的记录。
func buildSystemCatalog(onboarding providerconfig.SystemOnboarding, definition providerconfig.ProviderDefinition, observedAt time.Time) (catalog.Snapshot, error) {
	templates, errTemplates := systemModelTemplates(definition.ModelCatalogID)
	if errTemplates != nil {
		return catalog.Snapshot{}, errTemplates
	}
	snapshot := catalog.Snapshot{ProviderInstanceID: onboarding.Instance.ID, Revision: 1, ObservedAt: observedAt}
	for _, template := range templates {
		operation := template.operation
		if operation == "" {
			operation = vcp.OperationConversationRespond
		}
		action, errAction := definitionActionForTemplate(definition, template, operation)
		if errAction != nil {
			return catalog.Snapshot{}, errAction
		}
		modelSuffix := catalogIdentifier(template.upstreamID)
		modelID := "model_" + modelSuffix
		if !snapshotHasModel(snapshot, modelID) {
			snapshot.Models = append(snapshot.Models, catalog.ProviderModel{ID: modelID, ProviderInstanceID: onboarding.Instance.ID, UpstreamModelID: template.upstreamID, DisplayName: template.displayName, Source: catalog.ModelSourceSystem, EntitlementMode: template.entitlementMode, Revision: 1})
		}
		protocolSuffix := catalogIdentifier(action.ProtocolProfileID)
		offeringID := "offer_" + modelSuffix + "_" + protocolSuffix
		capabilities := systemModelCapabilities(template, action.Delivery)
		snapshot.Offerings = append(snapshot.Offerings, catalog.ModelOffering{ID: offeringID, ProviderInstanceID: onboarding.Instance.ID, ProviderModelID: modelID, ChannelID: action.ProtocolProfileID, UpstreamModelID: template.upstreamID, Capabilities: capabilities, CapabilityRevision: 1, Revision: 1})
		if len(template.profiles) == 0 {
			snapshot.Profiles = append(snapshot.Profiles, catalog.ExecutionProfile{ID: "profile_" + modelSuffix + "_" + protocolSuffix, ProviderInstanceID: onboarding.Instance.ID, OfferingID: offeringID, Operation: operation, ActionBindingID: action.ID, DisplayName: template.displayName, Default: true, Capabilities: capabilities, SwitchPolicy: catalog.ProfileSwitchReplayRequired, PoolPolicy: catalog.PoolPreferSmallestSufficient, CapabilityRevision: 1, Revision: 1})
			continue
		}
		for _, profileTemplate := range template.profiles {
			profileCapabilities := catalog.CloneModelCapabilities(capabilities)
			profileCapabilities.Tokens.ContextWindow = catalog.OptionalTokenLimit{Known: true, Value: profileTemplate.contextWindow}
			snapshot.Profiles = append(snapshot.Profiles, catalog.ExecutionProfile{ID: "profile_" + modelSuffix + "_" + profileTemplate.suffix + "_" + protocolSuffix, ProviderInstanceID: onboarding.Instance.ID, OfferingID: offeringID, Operation: operation, ActionBindingID: action.ID, DisplayName: profileTemplate.displayName, Default: profileTemplate.defaultProfile, Capabilities: profileCapabilities, SwitchPolicy: catalog.ProfileSwitchReplayRequired, PoolPolicy: catalog.PoolStrictProfile, CapabilityRevision: 1, Revision: 1})
		}
	}
	if definition.ModelCatalogID == "tavily_search_api" {
		action, errAction := definitionActionForOperation(definition, vcp.OperationSearchWeb)
		if errAction != nil {
			return catalog.Snapshot{}, errAction
		}
		capabilities := catalog.ServiceCapabilities{WebSearch: &catalog.WebSearchCapabilities{
			BackendKind: vcp.SearchBackendDirectAPI, InvocationMode: catalog.SearchInvocationDirectRequest,
			OutputModes: []vcp.WebSearchOutputMode{vcp.WebSearchOutputResults}, EvidenceKinds: []vcp.SearchEvidenceKind{vcp.SearchEvidenceStructuredResult}, EvidenceRequirements: []vcp.SearchEvidenceRequirement{vcp.SearchEvidenceBestEffort, vcp.SearchEvidenceVerified},
			Filters: catalog.SearchFilterCapabilities{DomainAllow: catalog.CapabilityNative, DomainBlock: catalog.CapabilityNative, PublicationTime: catalog.CapabilityUnsupported, Language: catalog.CapabilityUnsupported, Region: catalog.CapabilityUnsupported, Location: catalog.CapabilityUnsupported, SafeSearch: catalog.CapabilityUnsupported}, MaxResults: catalog.OptionalCountLimit{Known: true, Value: 20},
		}}
		snapshot.Services = append(snapshot.Services, catalog.ProviderService{ID: "service_web_search", ProviderInstanceID: onboarding.Instance.ID, DisplayName: "Tavily Web Search", Operation: vcp.OperationSearchWeb, Source: catalog.ModelSourceSystem, EntitlementMode: catalog.EntitlementAllBoundCredentials, Revision: 1})
		snapshot.ServiceOfferings = append(snapshot.ServiceOfferings, catalog.ServiceOffering{ID: "service_offer_tavily_search", ProviderInstanceID: onboarding.Instance.ID, ProviderServiceID: "service_web_search", ChannelID: action.ProtocolProfileID, UpstreamServiceID: "tavily-search", Capabilities: capabilities, CapabilityRevision: 1, Revision: 1})
		snapshot.Profiles = append(snapshot.Profiles, catalog.ExecutionProfile{ID: "profile_tavily_search", ProviderInstanceID: onboarding.Instance.ID, ServiceOfferingID: "service_offer_tavily_search", Operation: vcp.OperationSearchWeb, ActionBindingID: action.ID, DisplayName: "Tavily Results", Default: true, ServiceCapabilities: &capabilities, SwitchPolicy: catalog.ProfileSwitchReplayRequired, PoolPolicy: catalog.PoolPreferSmallestSufficient, CapabilityRevision: 1, Revision: 1})
	}
	if definition.ModelCatalogID == "openai_api" {
		action, errAction := definitionActionForOperation(definition, vcp.OperationSearchWeb)
		if errAction != nil {
			return catalog.Snapshot{}, errAction
		}
		capabilities := catalog.ServiceCapabilities{WebSearch: &catalog.WebSearchCapabilities{
			BackendKind: vcp.SearchBackendGroundedModel, InvocationMode: catalog.SearchInvocationNativeToolAndPrompt, BackingModelOfferingID: provideropenai.SearchBackingModelOfferingID, PromptTemplateID: provideropenai.SearchPromptTemplateID, PromptTemplateRevision: provideropenai.SearchPromptTemplateRevision,
			OutputModes: []vcp.WebSearchOutputMode{vcp.WebSearchOutputAnswerWithCitations}, EvidenceKinds: []vcp.SearchEvidenceKind{vcp.SearchEvidenceProviderEvent, vcp.SearchEvidenceCitation}, EvidenceRequirements: []vcp.SearchEvidenceRequirement{vcp.SearchEvidenceBestEffort, vcp.SearchEvidenceVerified},
			Filters: catalog.SearchFilterCapabilities{DomainAllow: catalog.CapabilityNative, DomainBlock: catalog.CapabilityUnsupported, PublicationTime: catalog.CapabilityUnsupported, Language: catalog.CapabilityUnsupported, Region: catalog.CapabilityUnsupported, Location: catalog.CapabilityNative, SafeSearch: catalog.CapabilityUnsupported}, MaxResults: catalog.OptionalCountLimit{},
		}}
		snapshot.Services = append(snapshot.Services, catalog.ProviderService{ID: "service_web_search", ProviderInstanceID: onboarding.Instance.ID, DisplayName: "OpenAI Grounded Web Search", Operation: vcp.OperationSearchWeb, Source: catalog.ModelSourceSystem, EntitlementMode: catalog.EntitlementAllBoundCredentials, Revision: 1})
		snapshot.ServiceOfferings = append(snapshot.ServiceOfferings, catalog.ServiceOffering{ID: "service_offer_openai_grounded_search", ProviderInstanceID: onboarding.Instance.ID, ProviderServiceID: "service_web_search", ChannelID: action.ProtocolProfileID, UpstreamServiceID: provideropenai.SearchBackingModelID, Capabilities: capabilities, CapabilityRevision: 1, Revision: 1})
		snapshot.Profiles = append(snapshot.Profiles, catalog.ExecutionProfile{ID: "profile_openai_grounded_search", ProviderInstanceID: onboarding.Instance.ID, ServiceOfferingID: "service_offer_openai_grounded_search", Operation: vcp.OperationSearchWeb, ActionBindingID: action.ID, DisplayName: "OpenAI Answer with Citations", Default: true, ServiceCapabilities: &capabilities, SwitchPolicy: catalog.ProfileSwitchReplayRequired, PoolPolicy: catalog.PoolPreferSmallestSufficient, CapabilityRevision: 1, Revision: 1})
	}
	if definition.ModelCatalogID == "anthropic_api" {
		action, errAction := definitionActionForOperation(definition, vcp.OperationSearchWeb)
		if errAction != nil {
			return catalog.Snapshot{}, errAction
		}
		capabilities := catalog.ServiceCapabilities{WebSearch: &catalog.WebSearchCapabilities{
			BackendKind: vcp.SearchBackendGroundedModel, InvocationMode: catalog.SearchInvocationNativeToolAndPrompt, BackingModelOfferingID: provideranthropic.SearchBackingModelOfferingID, PromptTemplateID: provideranthropic.SearchPromptTemplateID, PromptTemplateRevision: provideranthropic.SearchPromptTemplateRevision,
			OutputModes: []vcp.WebSearchOutputMode{vcp.WebSearchOutputAnswerWithCitations, vcp.WebSearchOutputResultsAndAnswer}, EvidenceKinds: []vcp.SearchEvidenceKind{vcp.SearchEvidenceProviderEvent, vcp.SearchEvidenceStructuredResult, vcp.SearchEvidenceCitation}, EvidenceRequirements: []vcp.SearchEvidenceRequirement{vcp.SearchEvidenceBestEffort, vcp.SearchEvidenceVerified},
			Filters: catalog.SearchFilterCapabilities{DomainAllow: catalog.CapabilityNative, DomainBlock: catalog.CapabilityNative, PublicationTime: catalog.CapabilityUnsupported, Language: catalog.CapabilityUnsupported, Region: catalog.CapabilityUnsupported, Location: catalog.CapabilityNative, SafeSearch: catalog.CapabilityUnsupported},
		}}
		snapshot.Services = append(snapshot.Services, catalog.ProviderService{ID: "service_web_search", ProviderInstanceID: onboarding.Instance.ID, DisplayName: "Anthropic Grounded Web Search", Operation: vcp.OperationSearchWeb, Source: catalog.ModelSourceSystem, EntitlementMode: catalog.EntitlementAllBoundCredentials, Revision: 1})
		snapshot.ServiceOfferings = append(snapshot.ServiceOfferings, catalog.ServiceOffering{ID: "service_offer_anthropic_grounded_search", ProviderInstanceID: onboarding.Instance.ID, ProviderServiceID: "service_web_search", ChannelID: action.ProtocolProfileID, UpstreamServiceID: provideranthropic.SearchBackingModelID, Capabilities: capabilities, CapabilityRevision: 1, Revision: 1})
		snapshot.Profiles = append(snapshot.Profiles, catalog.ExecutionProfile{ID: "profile_anthropic_grounded_search", ProviderInstanceID: onboarding.Instance.ID, ServiceOfferingID: "service_offer_anthropic_grounded_search", Operation: vcp.OperationSearchWeb, ActionBindingID: action.ID, DisplayName: "Anthropic Answer with Citations", Default: true, ServiceCapabilities: &capabilities, SwitchPolicy: catalog.ProfileSwitchReplayRequired, PoolPolicy: catalog.PoolPreferSmallestSufficient, CapabilityRevision: 1, Revision: 1})
	}
	if definition.ModelCatalogID == "google_interactions" {
		action, errAction := definitionActionForOperation(definition, vcp.OperationSearchWeb)
		if errAction != nil {
			return catalog.Snapshot{}, errAction
		}
		capabilities := catalog.ServiceCapabilities{WebSearch: &catalog.WebSearchCapabilities{
			BackendKind: vcp.SearchBackendGroundedModel, InvocationMode: catalog.SearchInvocationNativeToolAndPrompt, BackingModelOfferingID: providergoogle.SearchBackingModelOfferingID, PromptTemplateID: providergoogle.SearchPromptTemplateID, PromptTemplateRevision: providergoogle.SearchPromptTemplateRevision,
			OutputModes: []vcp.WebSearchOutputMode{vcp.WebSearchOutputAnswerWithCitations}, EvidenceKinds: []vcp.SearchEvidenceKind{vcp.SearchEvidenceProviderEvent, vcp.SearchEvidenceCitation}, EvidenceRequirements: []vcp.SearchEvidenceRequirement{vcp.SearchEvidenceBestEffort, vcp.SearchEvidenceVerified},
			Filters: catalog.SearchFilterCapabilities{DomainAllow: catalog.CapabilityUnsupported, DomainBlock: catalog.CapabilityUnsupported, PublicationTime: catalog.CapabilityUnsupported, Language: catalog.CapabilityUnsupported, Region: catalog.CapabilityUnsupported, Location: catalog.CapabilityUnsupported, SafeSearch: catalog.CapabilityUnsupported},
		}}
		snapshot.Services = append(snapshot.Services, catalog.ProviderService{ID: "service_web_search", ProviderInstanceID: onboarding.Instance.ID, DisplayName: "Google Grounded Web Search", Operation: vcp.OperationSearchWeb, Source: catalog.ModelSourceSystem, EntitlementMode: catalog.EntitlementAllBoundCredentials, Revision: 1})
		snapshot.ServiceOfferings = append(snapshot.ServiceOfferings, catalog.ServiceOffering{ID: "service_offer_google_grounded_search", ProviderInstanceID: onboarding.Instance.ID, ProviderServiceID: "service_web_search", ChannelID: action.ProtocolProfileID, UpstreamServiceID: providergoogle.SearchBackingModelID, Capabilities: capabilities, CapabilityRevision: 1, Revision: 1})
		snapshot.Profiles = append(snapshot.Profiles, catalog.ExecutionProfile{ID: "profile_google_grounded_search", ProviderInstanceID: onboarding.Instance.ID, ServiceOfferingID: "service_offer_google_grounded_search", Operation: vcp.OperationSearchWeb, ActionBindingID: action.ID, DisplayName: "Google Answer with Citations", Default: true, ServiceCapabilities: &capabilities, SwitchPolicy: catalog.ProfileSwitchReplayRequired, PoolPolicy: catalog.PoolPreferSmallestSufficient, CapabilityRevision: 1, Revision: 1})
	}
	if definition.ModelCatalogID == "xai_api" {
		action, errAction := definitionActionForOperation(definition, vcp.OperationSearchWeb)
		if errAction != nil {
			return catalog.Snapshot{}, errAction
		}
		capabilities := catalog.ServiceCapabilities{WebSearch: &catalog.WebSearchCapabilities{
			BackendKind: vcp.SearchBackendGroundedModel, InvocationMode: catalog.SearchInvocationNativeToolAndPrompt, BackingModelOfferingID: providerxai.SearchBackingModelOfferingID, PromptTemplateID: providerxai.SearchPromptTemplateID, PromptTemplateRevision: providerxai.SearchPromptTemplateRevision,
			OutputModes: []vcp.WebSearchOutputMode{vcp.WebSearchOutputAnswerWithCitations}, EvidenceKinds: []vcp.SearchEvidenceKind{vcp.SearchEvidenceCitation}, EvidenceRequirements: []vcp.SearchEvidenceRequirement{vcp.SearchEvidenceBestEffort, vcp.SearchEvidenceVerified},
			Filters: catalog.SearchFilterCapabilities{DomainAllow: catalog.CapabilityNative, DomainBlock: catalog.CapabilityNative, PublicationTime: catalog.CapabilityUnsupported, Language: catalog.CapabilityUnsupported, Region: catalog.CapabilityUnsupported, Location: catalog.CapabilityUnsupported, SafeSearch: catalog.CapabilityUnsupported},
		}}
		snapshot.Services = append(snapshot.Services, catalog.ProviderService{ID: "service_web_search", ProviderInstanceID: onboarding.Instance.ID, DisplayName: "xAI Grounded Web Search", Operation: vcp.OperationSearchWeb, Source: catalog.ModelSourceSystem, EntitlementMode: catalog.EntitlementAllBoundCredentials, Revision: 1})
		snapshot.ServiceOfferings = append(snapshot.ServiceOfferings, catalog.ServiceOffering{ID: "service_offer_xai_grounded_search", ProviderInstanceID: onboarding.Instance.ID, ProviderServiceID: "service_web_search", ChannelID: action.ProtocolProfileID, UpstreamServiceID: providerxai.SearchBackingModelID, Capabilities: capabilities, CapabilityRevision: 1, Revision: 1})
		snapshot.Profiles = append(snapshot.Profiles, catalog.ExecutionProfile{ID: "profile_xai_grounded_search", ProviderInstanceID: onboarding.Instance.ID, ServiceOfferingID: "service_offer_xai_grounded_search", Operation: vcp.OperationSearchWeb, ActionBindingID: action.ID, DisplayName: "xAI Answer with Citations", Default: true, ServiceCapabilities: &capabilities, SwitchPolicy: catalog.ProfileSwitchReplayRequired, PoolPolicy: catalog.PoolPreferSmallestSufficient, CapabilityRevision: 1, Revision: 1})
	}
	if errValidate := snapshot.Validate(); errValidate != nil {
		return catalog.Snapshot{}, fmt.Errorf("validate system provider catalog: %w", errValidate)
	}
	return snapshot, nil
}

// definitionActionForTemplate resolves the exact code-owned action declared by one model template.
// definitionActionForTemplate 解析一个模型模板声明的精确代码拥有动作。
func definitionActionForTemplate(definition providerconfig.ProviderDefinition, template systemModelTemplate, operation vcp.OperationKind) (providerconfig.ProviderActionBinding, error) {
	if template.actionBindingID == "" {
		return definitionActionForOperation(definition, operation)
	}
	action, errAction := definitionActionByID(definition, template.actionBindingID)
	if errAction != nil {
		return providerconfig.ProviderActionBinding{}, errAction
	}
	if action.Operation != operation {
		return providerconfig.ProviderActionBinding{}, fmt.Errorf("provider definition %s action binding %s owns operation %s, not %s", definition.ID, action.ID, action.Operation, operation)
	}
	return action, nil
}

// definitionActionByID resolves one exact code-owned action by its immutable identifier.
// definitionActionByID 按不可变标识解析一个精确代码拥有动作。
func definitionActionByID(definition providerconfig.ProviderDefinition, actionBindingID string) (providerconfig.ProviderActionBinding, error) {
	for _, action := range definition.ActionBindings {
		if action.ID == actionBindingID {
			return action, nil
		}
	}
	return providerconfig.ProviderActionBinding{}, fmt.Errorf("provider definition %s does not own declared action binding %s", definition.ID, actionBindingID)
}

// definitionActionForOperation resolves one exact code-owned action without guessing protocol aliases.
// definitionActionForOperation 解析一个精确代码拥有动作且不猜测协议别名。
func definitionActionForOperation(definition providerconfig.ProviderDefinition, operation vcp.OperationKind) (providerconfig.ProviderActionBinding, error) {
	var resolved providerconfig.ProviderActionBinding
	found := false
	for _, action := range definition.ActionBindings {
		if action.Operation != operation {
			continue
		}
		if found {
			return providerconfig.ProviderActionBinding{}, fmt.Errorf("provider definition %s declares duplicate %s actions", definition.ID, operation)
		}
		resolved = action
		found = true
	}
	if !found {
		return providerconfig.ProviderActionBinding{}, fmt.Errorf("provider definition %s does not declare %s action", definition.ID, operation)
	}
	return resolved, nil
}

// snapshotHasModel reports whether a model identity was already materialized for another operation.
// snapshotHasModel 报告模型身份是否已为另一操作实例化。
func snapshotHasModel(snapshot catalog.Snapshot, modelID string) bool {
	for _, model := range snapshot.Models {
		if model.ID == modelID {
			return true
		}
	}
	return false
}

// systemModelTemplates returns the exact current code-owned model set for one registered catalog identifier.
// systemModelTemplates 返回一个已注册目录标识的精确当前代码拥有模型集合。
func systemModelTemplates(catalogID string) ([]systemModelTemplate, error) {
	switch catalogID {
	case "kimi_open_platform":
		return kimiOpenPlatformModels(), nil
	case "kimi_coding":
		return kimiCodingModels(), nil
	case "alibaba_coding_plan_cn":
		return alibabaCodingPlanModels(), nil
	case "alibaba_coding_plan_global":
		return alibabaCodingPlanModels(), nil
	case "alibaba_token_plan_personal_cn":
		return alibabaTokenPlanPersonalCNModels(), nil
	case "alibaba_token_plan_team_cn":
		return alibabaTokenPlanTeamCNModels(), nil
	case "alibaba_token_plan_team_global":
		return alibabaTokenPlanTeamGlobalModels(), nil
	case "alibaba_model_studio_cn", "alibaba_model_studio_global":
		return alibabaModelStudioModels(false), nil
	case "alibaba_model_studio_workspace_global":
		return alibabaModelStudioModels(true), nil
	case "openai_api":
		return openAIAPIModels(), nil
	case "openrouter_api":
		return openRouterNativeModels(), nil
	case "minimax_api":
		return miniMaxModels(), nil
	case "tavily_search_api":
		return nil, nil
	case "openai_codex_api_key":
		return codexSystemModels(catalog.EntitlementAllBoundCredentials), nil
	case "openai_codex_account":
		return codexSystemModels(catalog.EntitlementExplicit), nil
	case "anthropic_api", "anthropic_claude_code":
		return anthropicModels(), nil
	case "google_ai_studio":
		return geminiAIStudioModels(), nil
	case "google_interactions":
		return geminiInteractionsModels(), nil
	case "google_vertex":
		// VCP 1.0 has no durable Router-owned output resource store, so media-output Imagen and Gemini Image products are not advertised as executable text models.
		// VCP 1.0 尚无持久 Router 所有输出资源存储，因此不将媒体输出 Imagen 与 Gemini Image 产品声明为可执行文本模型。
		return copiedTextModels("vertex", []systemModelIdentity{{"gemini-2.5-pro", "Gemini 2.5 Pro", 0}, {"gemini-2.5-flash", "Gemini 2.5 Flash", 0}, {"gemini-2.5-flash-lite", "Gemini 2.5 Flash Lite", 0}, {"gemini-3-pro-preview", "Gemini 3 Pro Preview", 0}, {"gemini-3-flash-preview", "Gemini 3 Flash Preview", 0}, {"gemini-3.1-pro-preview", "Gemini 3.1 Pro Preview", 0}, {"gemini-3.1-flash-lite", "Gemini 3.1 Flash Lite", 0}, {"gemini-3.5-flash", "Gemini 3.5 Flash", 0}}), nil
	case "google_antigravity":
		return copiedTextModels("antigravity", []systemModelIdentity{{"claude-opus-4-6-thinking", "Claude Opus 4.6 (Thinking)", 200000}, {"claude-sonnet-4-6", "Claude Sonnet 4.6 (Thinking)", 200000}, {"gemini-3-flash", "Gemini 3 Flash", 1048576}, {"gemini-3-flash-agent", "Gemini 3.5 Flash (High)", 1048576}, {"gemini-pro-agent", "Gemini 3.1 Pro (High)", 1048576}, {"gemini-3.1-pro-low", "Gemini 3.1 Pro (Low)", 1048576}, {"gpt-oss-120b-medium", "GPT-OSS 120B (Medium)", 114000}, {"gemini-3.1-flash-lite", "Gemini 3.1 Flash Lite", 1048576}, {"gemini-3.5-flash-low", "Gemini 3.5 Flash (Medium)", 1048576}, {"gemini-3.5-flash-extra-low", "Gemini 3.5 Flash (Low)", 1048576}}), nil
	case "xai_api":
		return xaiAPIModels(), nil
	case "xai_account":
		return copiedTextModels("xai", []systemModelIdentity{{"grok-build-0.1", "Grok Build 0.1", 256000}, {"grok-4.5", "Grok 4.5", 500000}, {"grok-4.3", "Grok 4.3", 1000000}, {"grok-4.20-0309-reasoning", "Grok 4.20 0309 Reasoning", 2000000}, {"grok-4.20-0309-non-reasoning", "Grok 4.20 0309 Non Reasoning", 2000000}, {"grok-4.20-multi-agent-0309", "Grok 4.20 Multi Agent 0309", 2000000}, {"grok-3-mini", "Grok 3 Mini", 131072}, {"grok-3-mini-fast", "Grok 3 Mini Fast", 131072}, {"grok-composer-2.5-fast", "Composer 2.5 Fast", 200000}}), nil
	default:
		return nil, fmt.Errorf("system provider model catalog %q is not registered", catalogID)
	}
}

// codexSystemModels maps the shared CLIProxyAPI Codex catalog to one product-specific entitlement boundary.
// codexSystemModels 将共享 CLIProxyAPI Codex 目录映射到一个产品特定授权边界。
func codexSystemModels(entitlementMode catalog.EntitlementMode) []systemModelTemplate {
	models := provideropenai.CodexCatalogModels()
	templates := make([]systemModelTemplate, 0, len(models))
	for _, model := range models {
		templates = append(templates, systemModelTemplate{upstreamID: model.UpstreamID, displayName: model.DisplayName, contextWindow: model.ContextWindow, maxOutputTokens: model.MaxOutputTokens, inputModalities: []string{"text"}, reasoning: model.Reasoning, toolCalling: model.ToolCalling, parallelTools: catalog.CapabilityUnknown, streamingTools: catalog.CapabilityUnknown, strictSchema: catalog.CapabilityUnknown, entitlementMode: entitlementMode})
	}
	return templates
}

// systemModelIdentity contains the exact identity and context facts copied from CLIProxyAPI's models.json.
// systemModelIdentity 包含从 CLIProxyAPI models.json 精确复制的身份与上下文事实。
type systemModelIdentity struct {
	// upstreamID is the provider model identifier.
	// upstreamID 是供应商模型标识。
	upstreamID string
	// displayName is the copied user-facing model name.
	// displayName 是复制的用户可见模型名称。
	displayName string
	// contextWindow is the copied context limit, or zero when CLIProxyAPI does not declare one.
	// contextWindow 是复制的上下文限制；CLIProxyAPI 未声明时为零。
	contextWindow int64
}

// copiedTextModels converts copied CLIProxyAPI identities and structured model evidence into conservative templates.
// copiedTextModels 将复制的 CLIProxyAPI 身份与结构化模型证据转换为保守模板。
func copiedTextModels(sourceCatalogID string, identities []systemModelIdentity) []systemModelTemplate {
	templates := make([]systemModelTemplate, 0, len(identities))
	for _, identity := range identities {
		evidence := copiedModelEvidenceFor(sourceCatalogID, identity.upstreamID)
		templates = append(templates, systemModelTemplate{upstreamID: identity.upstreamID, displayName: identity.displayName, contextWindow: identity.contextWindow, maxOutputTokens: evidence.maxOutputTokens, maxReasoningTokens: evidence.maxReasoningTokens, inputModalities: []string{"text"}, reasoning: evidence.reasoning, toolCalling: evidence.toolCalling, parallelTools: catalog.CapabilityUnknown, streamingTools: catalog.CapabilityUnknown, strictSchema: catalog.CapabilityUnknown, entitlementMode: catalog.EntitlementAllBoundCredentials})
	}
	return templates
}

// geminiAPITextModels returns CLIProxyAPI's official Gemini API-key catalog while excluding image-output products that VCP cannot persist yet.
// geminiAPITextModels 返回 CLIProxyAPI 官方 Gemini API Key 目录，并排除 VCP 当前尚不能持久化的图像输出产品。
func geminiAPITextModels() []systemModelTemplate {
	return copiedTextModels("gemini", []systemModelIdentity{{"gemini-2.5-pro", "Gemini 2.5 Pro", 0}, {"gemini-2.5-flash", "Gemini 2.5 Flash", 0}, {"gemini-2.5-flash-lite", "Gemini 2.5 Flash Lite", 0}, {"gemini-3-pro-preview", "Gemini 3 Pro Preview", 0}, {"gemini-3.1-pro-preview", "Gemini 3.1 Pro Preview", 0}, {"gemini-3-flash-preview", "Gemini 3 Flash Preview", 0}, {"gemini-3.1-flash-lite-preview", "Gemini 3.1 Flash Lite Preview", 0}, {"gemini-3.5-flash", "Gemini 3.5 Flash", 0}})
}

// geminiInteractionsModels returns text models plus current native Gemini image actions.
// geminiInteractionsModels 返回文本模型及当前原生 Gemini 图片动作。
func geminiInteractionsModels() []systemModelTemplate {
	models := geminiAPITextModels()
	models = append(models, googleInteractionsSpeechModels()...)
	return append(models, googleInteractionsImageModels()...)
}

// gemini25FlashMediaInputs returns official image, audio, and video understanding contracts.
// gemini25FlashMediaInputs 返回官方图片、音频与视频理解合同。
func gemini25FlashMediaInputs() []catalog.MediaInputCapability {
	// observedAt freezes the date on which the official capability pages were verified.
	// observedAt 固定官方能力页面完成核验的日期。
	observedAt := time.Date(2026, time.July, 20, 0, 0, 0, 0, time.UTC)
	// common builds only the cross-media facts shared by all three documented input families.
	// common 仅构建三种已记录输入类别共享的跨媒体事实。
	common := func(kind vcp.MediaKind, mimeTypes []string) catalog.MediaInputCapability {
		return catalog.MediaInputCapability{Kind: kind, Roles: []vcp.MediaInputRole{vcp.MediaRoleUnderstanding}, Level: catalog.CapabilityNative, InteractionModes: []catalog.MediaInteractionMode{catalog.MediaInteractionMixedConversation, catalog.MediaInteractionMediaOnlyConversation, catalog.MediaInteractionAnalysis}, MediaOnlyPolicy: catalog.MediaOnlyRouterInstruction, AllowedAuthorities: []vcp.Authority{vcp.AuthorityUser}, AllowedPlacements: []vcp.Placement{vcp.PlacementTranscript}, ClientWorkflows: []catalog.ClientResourceWorkflow{catalog.ClientWorkflowUploadThenReference, catalog.ClientWorkflowImportURLThenReference, catalog.ClientWorkflowImportBase64ThenReference, catalog.ClientWorkflowResolveInputPlan}, MaterializationModes: []catalog.UpstreamMaterializationMode{catalog.MaterializationInlineBase64, catalog.MaterializationProviderFileID}, Common: catalog.CommonMediaLimits{MIMETypes: mimeTypes}, Compatibility: catalog.MediaCompatibility{ToolCalling: catalog.CapabilityNative, Streaming: catalog.CapabilityNative, Reasoning: catalog.CapabilityNative, StructuredOutput: catalog.CapabilityNative}, Evidence: []catalog.CapabilityEvidence{{Source: catalog.ModelSourceProviderAPI, Reference: "https://ai.google.dev/gemini-api/docs/models/gemini-2.5-flash", ObservedAt: observedAt, Revision: 1}}, EvidenceRevision: 1}
	}
	image := common(vcp.MediaImage, []string{"image/jpeg", "image/png", "image/webp"})
	image.Image = &catalog.ImageMediaLimits{}
	audio := common(vcp.MediaAudio, []string{"audio/aac", "audio/flac", "audio/mp3", "audio/mpeg", "audio/mp4", "audio/ogg", "audio/pcm", "audio/wav", "audio/webm"})
	audio.Audio = &catalog.AudioMediaLimits{MaxDurationMilliseconds: catalog.OptionalLimit{Known: true, Value: 34200000}}
	video := common(vcp.MediaVideo, []string{"video/mp4", "video/mpeg", "video/mov", "video/avi", "video/x-flv", "video/mpg", "video/webm", "video/wmv", "video/3gpp"})
	video.Video = &catalog.VideoMediaLimits{EmbeddedAudio: catalog.OptionalBool{Known: true, Value: true}}
	return []catalog.MediaInputCapability{image, audio, video}
}

// kimiOpenPlatformModels returns current non-retired models documented by the Kimi API Open Platform.
// kimiOpenPlatformModels 返回 Kimi API 开放平台当前记录且未退役的模型。
func kimiOpenPlatformModels() []systemModelTemplate {
	allBound := catalog.EntitlementAllBoundCredentials
	return []systemModelTemplate{
		{upstreamID: "kimi-k3", displayName: "Kimi K3", contextWindow: 1048576, inputModalities: []string{"text", "image", "video"}, reasoning: catalog.CapabilityNative, toolCalling: catalog.CapabilityNative, parallelTools: catalog.CapabilityNative, streamingTools: catalog.CapabilityNative, strictSchema: catalog.CapabilityNative, entitlementMode: allBound},
		{upstreamID: "kimi-k2.7-code", displayName: "Kimi K2.7 Code", contextWindow: 262144, inputModalities: []string{"text", "image", "video"}, reasoning: catalog.CapabilityUnknown, toolCalling: catalog.CapabilityNative, parallelTools: catalog.CapabilityNative, streamingTools: catalog.CapabilityNative, strictSchema: catalog.CapabilityUnknown, entitlementMode: allBound},
		{upstreamID: "kimi-k2.7-code-highspeed", displayName: "Kimi K2.7 Code HighSpeed", contextWindow: 262144, inputModalities: []string{"text", "image", "video"}, reasoning: catalog.CapabilityUnknown, toolCalling: catalog.CapabilityNative, parallelTools: catalog.CapabilityNative, streamingTools: catalog.CapabilityNative, strictSchema: catalog.CapabilityUnknown, entitlementMode: allBound},
		{upstreamID: "kimi-k2.6", displayName: "Kimi K2.6", contextWindow: 262144, inputModalities: []string{"text", "image"}, reasoning: catalog.CapabilityUnknown, toolCalling: catalog.CapabilityNative, parallelTools: catalog.CapabilityNative, streamingTools: catalog.CapabilityNative, strictSchema: catalog.CapabilityUnknown, entitlementMode: allBound},
		{upstreamID: "kimi-k2.5", displayName: "Kimi K2.5", contextWindow: 262144, inputModalities: []string{"text", "image"}, reasoning: catalog.CapabilityUnknown, toolCalling: catalog.CapabilityNative, parallelTools: catalog.CapabilityNative, streamingTools: catalog.CapabilityNative, strictSchema: catalog.CapabilityUnknown, entitlementMode: catalog.EntitlementExplicit},
		{upstreamID: "moonshot-v1-8k", displayName: "Moonshot V1 8K", contextWindow: 8192, inputModalities: []string{"text"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnknown, parallelTools: catalog.CapabilityUnknown, streamingTools: catalog.CapabilityUnknown, strictSchema: catalog.CapabilityUnknown, entitlementMode: catalog.EntitlementExplicit},
		{upstreamID: "moonshot-v1-32k", displayName: "Moonshot V1 32K", contextWindow: 32768, inputModalities: []string{"text"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnknown, parallelTools: catalog.CapabilityUnknown, streamingTools: catalog.CapabilityUnknown, strictSchema: catalog.CapabilityUnknown, entitlementMode: catalog.EntitlementExplicit},
		{upstreamID: "moonshot-v1-128k", displayName: "Moonshot V1 128K", contextWindow: 131072, inputModalities: []string{"text"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnknown, parallelTools: catalog.CapabilityUnknown, streamingTools: catalog.CapabilityUnknown, strictSchema: catalog.CapabilityUnknown, entitlementMode: catalog.EntitlementExplicit},
		{upstreamID: "moonshot-v1-8k-vision-preview", displayName: "Moonshot V1 8K Vision", contextWindow: 8192, inputModalities: []string{"text", "image"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnknown, parallelTools: catalog.CapabilityUnknown, streamingTools: catalog.CapabilityUnknown, strictSchema: catalog.CapabilityUnknown, entitlementMode: catalog.EntitlementExplicit},
		{upstreamID: "moonshot-v1-32k-vision-preview", displayName: "Moonshot V1 32K Vision", contextWindow: 32768, inputModalities: []string{"text", "image"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnknown, parallelTools: catalog.CapabilityUnknown, streamingTools: catalog.CapabilityUnknown, strictSchema: catalog.CapabilityUnknown, entitlementMode: catalog.EntitlementExplicit},
		{upstreamID: "moonshot-v1-128k-vision-preview", displayName: "Moonshot V1 128K Vision", contextWindow: 131072, inputModalities: []string{"text", "image"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnknown, parallelTools: catalog.CapabilityUnknown, streamingTools: catalog.CapabilityUnknown, strictSchema: catalog.CapabilityUnknown, entitlementMode: catalog.EntitlementExplicit},
	}
}

// kimiCodingModels returns CLIProxyAPI's exact Kimi executor model set at the pinned source baseline.
// kimiCodingModels 返回 CLIProxyAPI 在固定源码基线上的精确 Kimi Executor 模型集合。
func kimiCodingModels() []systemModelTemplate {
	common := systemModelTemplate{inputModalities: []string{"text"}, reasoning: catalog.CapabilityUnknown, toolCalling: catalog.CapabilityNative, parallelTools: catalog.CapabilityNative, streamingTools: catalog.CapabilityNative, strictSchema: catalog.CapabilityUnknown, entitlementMode: catalog.EntitlementExplicit}
	k27 := common
	k27.upstreamID = "kimi-for-coding"
	k27.displayName = "Kimi K2.7 Code"
	k27.contextWindow = 262144
	highSpeed := common
	highSpeed.upstreamID = "kimi-for-coding-highspeed"
	highSpeed.displayName = "Kimi K2.7 Code HighSpeed"
	highSpeed.contextWindow = 262144
	k3 := common
	k3.upstreamID = "k3"
	k3.displayName = "Kimi K3"
	k3.contextWindow = 1048576
	k3.reasoning = catalog.CapabilityNative
	k3.reasoningEfforts = []string{"low", "high", "max"}
	k3.strictSchema = catalog.CapabilityNative
	k3.profiles = []systemProfileTemplate{{suffix: "256k", displayName: "Kimi K3 256K", contextWindow: 262144, defaultProfile: true}, {suffix: "1m", displayName: "Kimi K3 1M", contextWindow: 1048576}}
	return []systemModelTemplate{k27, k3, highSpeed}
}

// systemModelCapabilities constructs one closed capability set without inferring undocumented output limits.
// systemModelCapabilities 构建一组封闭能力且不推断未记录输出限制。
func systemModelCapabilities(template systemModelTemplate, delivery providerconfig.ActionDeliveryModes) catalog.ModelCapabilities {
	contextWindow := catalog.OptionalTokenLimit{}
	if template.contextWindow > 0 {
		contextWindow = catalog.OptionalTokenLimit{Known: true, Value: template.contextWindow}
	}
	maxInputTokens := catalog.OptionalTokenLimit{}
	if template.maxInputTokens > 0 {
		maxInputTokens = catalog.OptionalTokenLimit{Known: true, Value: template.maxInputTokens}
	}
	maxOutputTokens := catalog.OptionalTokenLimit{}
	if template.maxOutputTokens > 0 {
		maxOutputTokens = catalog.OptionalTokenLimit{Known: true, Value: template.maxOutputTokens}
	}
	maxReasoningTokens := catalog.OptionalTokenLimit{}
	if template.maxReasoningTokens > 0 {
		maxReasoningTokens = catalog.OptionalTokenLimit{Known: true, Value: template.maxReasoningTokens}
	}
	recommendedOutputTokens := catalog.OptionalTokenLimit{}
	if template.recommendedOutputTokens > 0 {
		recommendedOutputTokens = catalog.OptionalTokenLimit{Known: true, Value: template.recommendedOutputTokens}
	}
	recommendedReasoningTokens := catalog.OptionalTokenLimit{}
	if template.recommendedReasoningTokens > 0 {
		recommendedReasoningTokens = catalog.OptionalTokenLimit{Known: true, Value: template.recommendedReasoningTokens}
	}
	return catalog.ModelCapabilities{
		Tokens:                 catalog.TokenLimits{ContextWindow: contextWindow, MaxInputTokens: maxInputTokens, MaxOutputTokens: maxOutputTokens, MaxReasoningTokens: maxReasoningTokens},
		Recommendations:        catalog.TokenRecommendations{OutputTokens: recommendedOutputTokens, ReasoningTokens: recommendedReasoningTokens},
		ToolCalling:            template.toolCalling,
		ParallelToolCalls:      template.parallelTools,
		StreamingToolArguments: template.streamingTools,
		StrictJSONSchema:       template.strictSchema,
		Reasoning:              template.reasoning,
		ReasoningEfforts:       append([]string(nil), template.reasoningEfforts...),
		InputModalities:        append([]string(nil), template.inputModalities...),
		OutputModalities:       systemOutputModalities(template),
		Delivery:               catalog.DeliveryCapabilities{Synchronous: delivery.Synchronous, Streaming: delivery.Streaming, Asynchronous: delivery.Asynchronous},
		Embedding:              template.embedding,
		Rerank:                 template.rerank,
		MediaInputs:            append([]catalog.MediaInputCapability(nil), template.mediaInputs...),
		MediaOutputs:           append([]catalog.MediaOutputCapability(nil), template.mediaOutputs...),
		Parameters:             append([]catalog.ParameterDescriptor(nil), template.parameters...),
		ParameterRules:         append([]catalog.ParameterRule(nil), template.parameterRules...),
		UsageMetrics:           append([]catalog.UsageMetricCapability(nil), template.usageMetrics...),
	}
}

// systemOutputModalities returns the operation-specific closed output modality list.
// systemOutputModalities 返回操作专属的封闭输出模态列表。
func systemOutputModalities(template systemModelTemplate) []string {
	switch template.operation {
	case vcp.OperationImageGenerate, vcp.OperationImageEdit:
		return []string{"image"}
	case vcp.OperationVideoGenerate, vcp.OperationVideoEdit, vcp.OperationVideoExtend:
		return []string{"video"}
	case vcp.OperationSpeechSynthesize, vcp.OperationMusicGenerate, vcp.OperationMusicCoverPrepare, vcp.OperationMusicCover:
		return []string{"audio"}
	case vcp.OperationSpeechTranscribe, vcp.OperationMediaAnalyze:
		return []string{"text"}
	case vcp.OperationEmbeddingCreate:
		return []string{"embedding"}
	case vcp.OperationRerankDocuments:
		return []string{"ranking"}
	default:
		return []string{"text"}
	}
}

// catalogIdentifier converts one trusted upstream model identifier to the portable catalog identifier alphabet.
// catalogIdentifier 将一个受信任上游模型标识转换为可移植目录标识字母表。
func catalogIdentifier(value string) string {
	return strings.ToLower(strings.NewReplacer("-", "_", ".", "_", "/", "_").Replace(value))
}
