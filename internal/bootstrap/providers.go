// Package bootstrap registers process-wide immutable provider catalog metadata.
// Package bootstrap 注册进程范围内不可变的供应商目录元数据。
package bootstrap

import (
	"fmt"

	"github.com/OpenVulcan/vulcan-model-core/internal/dependency"
	protocolchat "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/chat"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	providerkimi "github.com/OpenVulcan/vulcan-model-core/internal/provider/kimi"
	provideropenai "github.com/OpenVulcan/vulcan-model-core/internal/provider/openai"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

const (
	// KimiGroupID identifies the Kimi provider family.
	// KimiGroupID 标识 Kimi 供应商系列。
	KimiGroupID = "kimi"
	// KimiCNDefinitionID identifies the Kimi Open Platform CN site.
	// KimiCNDefinitionID 标识 Kimi 开放平台 CN 站点。
	KimiCNDefinitionID = "system_kimi_cn"
	// KimiGlobalDefinitionID identifies the Kimi Open Platform Global site.
	// KimiGlobalDefinitionID 标识 Kimi 开放平台 Global 站点。
	KimiGlobalDefinitionID = "system_kimi_global"
	// KimiCodingDefinitionID identifies the separate Kimi Coding Plan product.
	// KimiCodingDefinitionID 标识独立的 Kimi Coding Plan 产品。
	KimiCodingDefinitionID = "system_kimi_coding_plan"
)

// RegisterSystemProviders registers code-owned provider groups and exact selectable provider variants.
// RegisterSystemProviders 注册代码拥有的供应商分组及精确可选择的供应商变体。
func RegisterSystemProviders(registry *providerconfig.SystemRegistry) error {
	if registry == nil {
		return fmt.Errorf("system provider registry is required")
	}
	if errProviders := registerCLIProxyProviderCatalog(registry); errProviders != nil {
		return errProviders
	}
	if errAlibaba := registerAlibabaProviderCatalog(registry); errAlibaba != nil {
		return errAlibaba
	}
	if errOpenRouter := registerOpenRouterProviderCatalog(registry); errOpenRouter != nil {
		return errOpenRouter
	}
	if errMiniMax := registerMiniMaxProviderCatalog(registry); errMiniMax != nil {
		return errMiniMax
	}
	if errTavily := registerTavilyProviderCatalog(registry); errTavily != nil {
		return errTavily
	}
	if errGroup := registry.RegisterGroup(providerconfig.ProviderGroup{
		ID:             KimiGroupID,
		DisplayName:    "Kimi",
		Description:    "Moonshot AI services across regional Open Platform sites and the separate Coding Plan.",
		DescriptionKey: "providers.kimi.description",
		SortOrder:      10,
		Revision:       1,
	}); errGroup != nil {
		return fmt.Errorf("register Kimi provider group: %w", errGroup)
	}
	for _, definition := range kimiProviderDefinitions() {
		definitionWithAction, errAction := withConversationAction(definition)
		if errAction != nil {
			return errAction
		}
		if errRegister := registry.Register(definitionWithAction); errRegister != nil {
			return fmt.Errorf("register Kimi provider definition %s: %w", definition.ID, errRegister)
		}
	}
	return nil
}

// RegisterKimiExecutionDrivers binds every runtime-ready Kimi definition to its sole OpenAI Chat execution driver.
// RegisterKimiExecutionDrivers 将每个运行时就绪的 Kimi 定义绑定到其唯一的 OpenAI Chat 执行 Driver。
func RegisterKimiExecutionDrivers(registry *provider.ExecutionRegistry, openPlatformClient *transport.Client, codingClient *transport.Client, secrets secret.Store) error {
	if registry == nil || openPlatformClient == nil || codingClient == nil || dependency.IsNil(secrets) {
		return fmt.Errorf("Kimi execution registry, transport clients, and protected secret store are required")
	}
	for _, definitionID := range []string{KimiCNDefinitionID, KimiGlobalDefinitionID} {
		driver, errDriver := provideropenai.NewChatDriver(definitionID, protocolchat.ProfileID, openPlatformClient, kimiChatCapabilities())
		if errDriver != nil {
			return fmt.Errorf("create Kimi Chat driver %s: %w", definitionID, errDriver)
		}
		if errRegister := registerConversationDriver(registry, driver); errRegister != nil {
			return fmt.Errorf("register Kimi Chat driver %s: %w", definitionID, errRegister)
		}
	}
	// codingAdapter owns only the Kimi Coding model-name and non-secret device-header wire adaptation.
	// codingAdapter 仅负责 Kimi Coding 模型名及非秘密设备请求头的 wire 适配。
	codingAdapter, errCodingAdapter := providerkimi.NewCodingChatAdapter(secrets)
	if errCodingAdapter != nil {
		return fmt.Errorf("create Kimi Coding request adapter: %w", errCodingAdapter)
	}
	codingChat, errCodingChat := provideropenai.NewBearerChatDriverWithRequestAdapter(KimiCodingDefinitionID, protocolchat.ProfileID, codingClient, kimiChatCapabilities(), []providerconfig.AuthMethodType{providerconfig.AuthMethodAPIKey, providerconfig.AuthMethodDeviceFlow}, codingAdapter)
	if errCodingChat != nil {
		return fmt.Errorf("create Kimi Coding Chat driver: %w", errCodingChat)
	}
	if errRegister := registerConversationDriver(registry, codingChat); errRegister != nil {
		return fmt.Errorf("register Kimi Coding Chat driver: %w", errRegister)
	}
	return nil
}

// kimiChatCapabilities returns provider-documented Chat transport features; model-level availability remains catalog-owned.
// kimiChatCapabilities 返回供应商文档记录的 Chat 传输能力；模型级可用性仍由目录拥有。
func kimiChatCapabilities() protocolchat.ProfileCapabilities {
	return protocolchat.ProfileCapabilities{NativeSystemPreamble: true, NativeInlineSystem: true, StructuredTools: true, ParallelTools: true, StreamingToolArguments: true, StrictJSONSchema: true, Reasoning: true, ReasoningContent: true}
}

// kimiProviderDefinitions returns the three immutable Kimi commercial and regional access boundaries.
// kimiProviderDefinitions 返回三个不可变的 Kimi 商业及区域接入边界。
func kimiProviderDefinitions() []providerconfig.ProviderDefinition {
	// apiKey is shared as immutable value input across the returned definitions.
	// apiKey 作为不可变值输入在返回的定义之间共享。
	apiKey := providerconfig.AuthMethodDefinition{ID: "api_key", Type: providerconfig.AuthMethodAPIKey, MultipleCredentials: true, PlanAcquisition: providerconfig.PlanAcquisitionUnavailable}
	// codingAPIKey requires an explicit membership tier because Kimi cannot derive it from a static key.
	// codingAPIKey 要求显式选择会员档位，因为 Kimi 无法从静态密钥推导该档位。
	codingAPIKey := providerconfig.AuthMethodDefinition{ID: "api_key", Type: providerconfig.AuthMethodAPIKey, MultipleCredentials: true, PlanAcquisition: providerconfig.PlanAcquisitionManualRequired}
	// deviceFlow describes the refreshable Coding Plan authorization lifecycle copied from the proven Kimi integration.
	// deviceFlow 描述从已验证 Kimi 集成复制而来的可刷新 Coding Plan 授权生命周期。
	deviceFlow := providerconfig.AuthMethodDefinition{ID: "device_flow", Type: providerconfig.AuthMethodDeviceFlow, Refreshable: true, MultipleCredentials: true, PlanAcquisition: providerconfig.PlanAcquisitionProviderDetected}
	// codingPlans freezes the user-confirmed Kimi membership vocabulary and exact provider codes.
	// codingPlans 固化用户确认的 Kimi 会员词汇表与精确供应商代码。
	codingPlans := []providerconfig.PlanOptionDefinition{
		{ID: "kimi_andante", DisplayName: "Andante", DisplayNameKey: "providers.kimi.plans.andante", AuthMethodIDs: []string{"api_key", "device_flow"}, ManuallySelectable: true, ProviderPlanCodes: []string{"andante"}, SortOrder: 10, Revision: 1, EvidenceRevision: 1},
		{ID: "kimi_moderato", DisplayName: "Moderato", DisplayNameKey: "providers.kimi.plans.moderato", AuthMethodIDs: []string{"api_key", "device_flow"}, ManuallySelectable: true, ProviderPlanCodes: []string{"moderato"}, SortOrder: 20, Revision: 1, EvidenceRevision: 1},
		{ID: "kimi_allegretto", DisplayName: "Allegretto", DisplayNameKey: "providers.kimi.plans.allegretto", AuthMethodIDs: []string{"api_key", "device_flow"}, ManuallySelectable: true, ProviderPlanCodes: []string{"allegretto"}, SortOrder: 30, Revision: 1, EvidenceRevision: 1},
		{ID: "kimi_allegro", DisplayName: "Allegro", DisplayNameKey: "providers.kimi.plans.allegro", AuthMethodIDs: []string{"api_key", "device_flow"}, ManuallySelectable: true, ProviderPlanCodes: []string{"allegro"}, SortOrder: 40, Revision: 1, EvidenceRevision: 1},
	}
	// unsupportedFeatures explicitly records management capabilities that do not yet have trusted implementations.
	// unsupportedFeatures 显式记录尚无受信任实现的管理能力。
	unsupportedFeatures := providerconfig.ProviderFeatureSet{
		ModelDiscovery:    providerconfig.SupportUnsupported,
		PlanReader:        providerconfig.SupportUnsupported,
		EntitlementReader: providerconfig.SupportUnsupported,
		AllowanceReader:   providerconfig.SupportUnsupported,
	}
	// codingFeatures expose the account API's proven plan, entitlement, and usage observation.
	// codingFeatures 暴露账号接口已验证的套餐、授权与用量观测能力。
	codingFeatures := unsupportedFeatures
	codingFeatures.PlanReader = providerconfig.SupportSupported
	codingFeatures.EntitlementReader = providerconfig.SupportSupported
	codingFeatures.AllowanceReader = providerconfig.SupportSupported
	return []providerconfig.ProviderDefinition{
		{
			ID: KimiCNDefinitionID, Kind: providerconfig.DefinitionKindSystem, DisplayName: "Kimi CN",
			GroupID: KimiGroupID, VariantName: "CN", VariantDescription: "Kimi Open Platform service hosted at the CN API site.", VariantDescriptionKey: "providers.kimi.cnDescription", ModelCatalogID: "kimi_open_platform", SortOrder: 10,
			DriverID: "kimi", DriverVersion: "1", ConfigSchemaVersion: "1", ProtocolProfileID: protocolchat.ProfileID, EndpointProfileID: "kimi_chat", AuthMethodIDs: []string{"api_key"}, Priority: 10, RuntimeReady: true, AuthMethods: []providerconfig.AuthMethodDefinition{apiKey},
			EndpointPresets: []providerconfig.EndpointPreset{{ID: "cn_chat", BaseURL: "https://api.moonshot.cn", Region: "CN", UserEditable: false}},
			Features:        unsupportedFeatures, Revision: 1,
		},
		{
			ID: KimiGlobalDefinitionID, Kind: providerconfig.DefinitionKindSystem, DisplayName: "Kimi Global",
			GroupID: KimiGroupID, VariantName: "Global", VariantDescription: "Kimi Open Platform service hosted at the Global API site.", VariantDescriptionKey: "providers.kimi.globalDescription", ModelCatalogID: "kimi_open_platform", SortOrder: 20,
			DriverID: "kimi", DriverVersion: "1", ConfigSchemaVersion: "1", ProtocolProfileID: protocolchat.ProfileID, EndpointProfileID: "kimi_chat", AuthMethodIDs: []string{"api_key"}, Priority: 10, RuntimeReady: true, AuthMethods: []providerconfig.AuthMethodDefinition{apiKey},
			EndpointPresets: []providerconfig.EndpointPreset{{ID: "global_chat", BaseURL: "https://api.moonshot.ai", Region: "Global", UserEditable: false}},
			Features:        unsupportedFeatures, Revision: 1,
		},
		{
			ID: KimiCodingDefinitionID, Kind: providerconfig.DefinitionKindSystem, DisplayName: "Kimi Coding Plan",
			GroupID: KimiGroupID, VariantName: "Coding Plan", VariantDescription: "Membership-based coding service with dedicated models and credentials.", VariantDescriptionKey: "providers.kimi.codingDescription", ModelCatalogID: "kimi_coding", SortOrder: 30,
			DriverID: "kimi", DriverVersion: "1", ConfigSchemaVersion: "1",
			ProtocolProfileID: protocolchat.ProfileID, EndpointProfileID: "kimi_coding_chat", AuthMethodIDs: []string{"api_key", "device_flow"}, Priority: 10, RuntimeReady: true,
			AuthMethods:     []providerconfig.AuthMethodDefinition{codingAPIKey, deviceFlow},
			PlanOptions:     codingPlans,
			EndpointPresets: []providerconfig.EndpointPreset{{ID: "coding_chat", BaseURL: "https://api.kimi.com/coding", Region: "Coding Plan", UserEditable: false}},
			Features:        codingFeatures, Revision: 1,
		},
	}
}
