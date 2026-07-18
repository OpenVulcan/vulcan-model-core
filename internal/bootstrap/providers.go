// Package bootstrap registers process-wide immutable provider catalog metadata.
// Package bootstrap 注册进程范围内不可变的供应商目录元数据。
package bootstrap

import (
	"fmt"

	protocolchat "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/chat"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	provideropenai "github.com/OpenVulcan/vulcan-model-core/internal/provider/openai"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
)

const (
	// KimiGroupID identifies the management-only Kimi provider family.
	// KimiGroupID 标识仅供管理使用的 Kimi 供应商系列。
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
		if errRegister := registry.Register(definition); errRegister != nil {
			return fmt.Errorf("register Kimi provider definition %s: %w", definition.ID, errRegister)
		}
	}
	return nil
}

// RegisterKimiExecutionDrivers binds every runtime-ready Kimi definition to its sole OpenAI Chat execution driver.
// RegisterKimiExecutionDrivers 将每个运行时就绪的 Kimi 定义绑定到其唯一的 OpenAI Chat 执行 Driver。
func RegisterKimiExecutionDrivers(registry *provider.ExecutionRegistry, openPlatformClient *transport.Client, codingClient *transport.Client) error {
	if registry == nil || openPlatformClient == nil || codingClient == nil {
		return fmt.Errorf("Kimi execution registry and transport clients are required")
	}
	for _, definitionID := range []string{KimiCNDefinitionID, KimiGlobalDefinitionID} {
		driver, errDriver := provideropenai.NewChatDriver(definitionID, protocolchat.ProfileID, openPlatformClient, kimiChatCapabilities())
		if errDriver != nil {
			return fmt.Errorf("create Kimi Chat driver %s: %w", definitionID, errDriver)
		}
		if errRegister := registry.Register(driver); errRegister != nil {
			return fmt.Errorf("register Kimi Chat driver %s: %w", definitionID, errRegister)
		}
	}
	codingChat, errCodingChat := provideropenai.NewBearerChatDriver(KimiCodingDefinitionID, protocolchat.ProfileID, codingClient, kimiChatCapabilities(), []providerconfig.AuthMethodType{providerconfig.AuthMethodAPIKey, providerconfig.AuthMethodDeviceFlow})
	if errCodingChat != nil {
		return fmt.Errorf("create Kimi Coding Chat driver: %w", errCodingChat)
	}
	if errRegister := registry.Register(codingChat); errRegister != nil {
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
	apiKey := providerconfig.AuthMethodDefinition{ID: "api_key", Type: providerconfig.AuthMethodAPIKey, MultipleCredentials: true}
	// deviceFlow describes the refreshable Coding Plan authorization lifecycle copied from the proven Kimi integration.
	// deviceFlow 描述从已验证 Kimi 集成复制而来的可刷新 Coding Plan 授权生命周期。
	deviceFlow := providerconfig.AuthMethodDefinition{ID: "device_flow", Type: providerconfig.AuthMethodDeviceFlow, Refreshable: true, MultipleCredentials: true}
	// unsupportedFeatures explicitly records management capabilities that do not yet have trusted implementations.
	// unsupportedFeatures 显式记录尚无受信任实现的管理能力。
	unsupportedFeatures := providerconfig.ProviderFeatureSet{
		ModelDiscovery:    providerconfig.SupportUnsupported,
		PlanReader:        providerconfig.SupportUnsupported,
		EntitlementReader: providerconfig.SupportUnsupported,
		AllowanceReader:   providerconfig.SupportUnsupported,
	}
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
			AuthMethods:     []providerconfig.AuthMethodDefinition{apiKey, deviceFlow},
			EndpointPresets: []providerconfig.EndpointPreset{{ID: "coding_chat", BaseURL: "https://api.kimi.com/coding", Region: "Coding Plan", UserEditable: false}},
			Features:        unsupportedFeatures, Revision: 1,
		},
	}
}
