package bootstrap

import (
	"fmt"

	protocolmessages "github.com/OpenVulcan/vulcan-model-core/internal/protocol/anthropic/messages"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	provideralibaba "github.com/OpenVulcan/vulcan-model-core/internal/provider/alibaba"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
)

const (
	// AlibabaGroupID identifies the Alibaba Cloud Model Studio provider family.
	// AlibabaGroupID 标识 Alibaba Cloud Model Studio 供应商系列。
	AlibabaGroupID = "alibaba"
	// AlibabaCodingPlanCNDefinitionID identifies the China Coding Plan product.
	// AlibabaCodingPlanCNDefinitionID 标识中国站 Coding Plan 产品。
	AlibabaCodingPlanCNDefinitionID = "system_alibaba_coding_plan_cn"
	// AlibabaCodingPlanGlobalDefinitionID identifies the global Coding Plan product.
	// AlibabaCodingPlanGlobalDefinitionID 标识国际站 Coding Plan 产品。
	AlibabaCodingPlanGlobalDefinitionID = "system_alibaba_coding_plan_global"
	// AlibabaTokenPlanPersonalCNDefinitionID identifies the China Token Plan Personal product.
	// AlibabaTokenPlanPersonalCNDefinitionID 标识中国站 Token Plan Personal 产品。
	AlibabaTokenPlanPersonalCNDefinitionID = "system_alibaba_token_plan_personal_cn"
	// AlibabaTokenPlanTeamCNDefinitionID identifies the China Token Plan Team product.
	// AlibabaTokenPlanTeamCNDefinitionID 标识中国站 Token Plan Team 产品。
	AlibabaTokenPlanTeamCNDefinitionID = "system_alibaba_token_plan_team_cn"
	// AlibabaTokenPlanTeamGlobalDefinitionID identifies the global Token Plan Team product.
	// AlibabaTokenPlanTeamGlobalDefinitionID 标识国际站 Token Plan Team 产品。
	AlibabaTokenPlanTeamGlobalDefinitionID = "system_alibaba_token_plan_team_global"
)

// registerAlibabaProviderCatalog registers Alibaba's immutable plan products and exact regional boundaries.
// registerAlibabaProviderCatalog 注册阿里云不可变套餐产品及精确区域边界。
func registerAlibabaProviderCatalog(registry *providerconfig.SystemRegistry) error {
	if errGroup := registry.RegisterGroup(providerconfig.ProviderGroup{
		ID:             AlibabaGroupID,
		DisplayName:    "Alibaba Cloud Model Studio",
		Description:    "Alibaba Cloud Model Studio coding subscriptions across CN and Global sites.",
		DescriptionKey: "providers.alibaba.description",
		SortOrder:      60,
		Revision:       1,
	}); errGroup != nil {
		return fmt.Errorf("register Alibaba provider group: %w", errGroup)
	}
	for _, definition := range alibabaProviderDefinitions() {
		if errRegister := registry.Register(definition); errRegister != nil {
			return fmt.Errorf("register Alibaba provider definition %s: %w", definition.ID, errRegister)
		}
	}
	return nil
}

// RegisterAlibabaExecutionDrivers binds every Alibaba plan definition to its sole Anthropic-compatible Messages driver.
// RegisterAlibabaExecutionDrivers 将每个阿里云套餐定义绑定到其唯一的 Anthropic 兼容 Messages 驱动。
func RegisterAlibabaExecutionDrivers(registry *provider.ExecutionRegistry, client *transport.Client) error {
	if registry == nil || client == nil {
		return fmt.Errorf("Alibaba execution registry and transport client are required")
	}
	for _, definitionID := range []string{
		AlibabaCodingPlanCNDefinitionID,
		AlibabaCodingPlanGlobalDefinitionID,
		AlibabaTokenPlanPersonalCNDefinitionID,
		AlibabaTokenPlanTeamCNDefinitionID,
		AlibabaTokenPlanTeamGlobalDefinitionID,
	} {
		driver, errDriver := provideralibaba.NewMessagesDriver(definitionID, client, responsesCapabilities())
		if errDriver != nil {
			return fmt.Errorf("create Alibaba Messages driver %s: %w", definitionID, errDriver)
		}
		if errRegister := registry.Register(driver); errRegister != nil {
			return fmt.Errorf("register Alibaba Messages driver %s: %w", definitionID, errRegister)
		}
	}
	return nil
}

// alibabaProviderDefinitions returns five immutable subscription and region boundaries.
// alibabaProviderDefinitions 返回五个不可变订阅产品及区域边界。
func alibabaProviderDefinitions() []providerconfig.ProviderDefinition {
	// apiKey is the only documented credential mechanism for Alibaba coding plans.
	// apiKey 是阿里云编码套餐唯一有文档依据的凭据机制。
	apiKey := providerconfig.AuthMethodDefinition{ID: "api_key", Type: providerconfig.AuthMethodAPIKey, MultipleCredentials: true}
	// unsupportedFeatures prevents unimplemented console-only metadata from appearing available.
	// unsupportedFeatures 防止尚未实现的控制台专属元数据被声明为可用。
	unsupportedFeatures := providerconfig.ProviderFeatureSet{
		ModelDiscovery:    providerconfig.SupportUnsupported,
		PlanReader:        providerconfig.SupportUnsupported,
		EntitlementReader: providerconfig.SupportUnsupported,
		AllowanceReader:   providerconfig.SupportUnsupported,
	}
	return []providerconfig.ProviderDefinition{
		alibabaProviderDefinition(AlibabaCodingPlanCNDefinitionID, "Alibaba Coding Plan CN", "Coding Plan CN", "Alibaba Coding Plan service hosted at the CN site.", "providers.alibaba.codingPlanCNDescription", "alibaba_coding_plan_cn", "coding_plan_cn", "https://coding.dashscope.aliyuncs.com/apps/anthropic/v1", "CN", 10, apiKey, unsupportedFeatures),
		alibabaProviderDefinition(AlibabaCodingPlanGlobalDefinitionID, "Alibaba Coding Plan Global", "Coding Plan Global", "Alibaba Coding Plan service hosted at the Global site.", "providers.alibaba.codingPlanGlobalDescription", "alibaba_coding_plan_global", "coding_plan_global", "https://coding-intl.dashscope.aliyuncs.com/apps/anthropic/v1", "Global", 20, apiKey, unsupportedFeatures),
		alibabaProviderDefinition(AlibabaTokenPlanPersonalCNDefinitionID, "Alibaba Token Plan Personal CN", "Token Plan Personal CN", "Personal Token Plan service hosted at the CN site.", "providers.alibaba.tokenPlanPersonalCNDescription", "alibaba_token_plan_personal_cn", "token_plan_personal_cn", "https://token-plan.cn-beijing.maas.aliyuncs.com/apps/anthropic/v1", "CN", 30, apiKey, unsupportedFeatures),
		alibabaProviderDefinition(AlibabaTokenPlanTeamCNDefinitionID, "Alibaba Token Plan Team CN", "Token Plan Team CN", "Team Token Plan service hosted at the CN site.", "providers.alibaba.tokenPlanTeamCNDescription", "alibaba_token_plan_team_cn", "token_plan_team_cn", "https://token-plan.cn-beijing.maas.aliyuncs.com/apps/anthropic/v1", "CN", 40, apiKey, unsupportedFeatures),
		alibabaProviderDefinition(AlibabaTokenPlanTeamGlobalDefinitionID, "Alibaba Token Plan Team Global", "Token Plan Team Global", "Team Token Plan service hosted at the Global site.", "providers.alibaba.tokenPlanTeamGlobalDescription", "alibaba_token_plan_team_global", "token_plan_team_global", "https://token-plan.ap-southeast-1.maas.aliyuncs.com/apps/anthropic/v1", "Global", 50, apiKey, unsupportedFeatures),
	}
}

// alibabaProviderDefinition builds one closed single-protocol system definition from explicit product facts.
// alibabaProviderDefinition 根据明确产品事实构建一个封闭的单协议系统定义。
func alibabaProviderDefinition(definitionID string, displayName string, variantName string, description string, descriptionKey string, catalogID string, endpointID string, baseURL string, region string, sortOrder int, apiKey providerconfig.AuthMethodDefinition, features providerconfig.ProviderFeatureSet) providerconfig.ProviderDefinition {
	return providerconfig.ProviderDefinition{
		ID: definitionID, Kind: providerconfig.DefinitionKindSystem, DisplayName: displayName,
		GroupID: AlibabaGroupID, VariantName: variantName, VariantDescription: description, VariantDescriptionKey: descriptionKey, ModelCatalogID: catalogID, SortOrder: sortOrder,
		DriverID: "alibaba", DriverVersion: "1", ConfigSchemaVersion: "1", ProtocolProfileID: protocolmessages.ProfileID, EndpointProfileID: "alibaba_messages", AuthMethodIDs: []string{"api_key"}, Priority: 10, RuntimeReady: true,
		AuthMethods:     []providerconfig.AuthMethodDefinition{apiKey},
		EndpointPresets: []providerconfig.EndpointPreset{{ID: endpointID, BaseURL: baseURL, Region: region, UserEditable: false}},
		Features:        features, Revision: 1,
	}
}
