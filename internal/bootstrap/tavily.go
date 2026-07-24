package bootstrap

import (
	"fmt"

	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	providertavily "github.com/OpenVulcan/vulcan-model-core/internal/provider/tavily"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

const (
	// TavilyGroupID identifies the Tavily search provider family.
	// TavilyGroupID 标识 Tavily 搜索供应商系列。
	TavilyGroupID = "tavily"
	// TavilySearchDefinitionID identifies the public Tavily Search API product.
	// TavilySearchDefinitionID 标识公开 Tavily Search API 产品。
	TavilySearchDefinitionID = "system_tavily_search_api"
)

// registerTavilyProviderCatalog registers Tavily search, extraction, and account metadata contracts.
// registerTavilyProviderCatalog 注册 Tavily 搜索、提取与账号元数据合同。
func registerTavilyProviderCatalog(registry *providerconfig.SystemRegistry) error {
	if errGroup := registry.RegisterGroup(providerconfig.ProviderGroup{ID: TavilyGroupID, DisplayName: "Tavily", Description: "Tavily structured web search and content extraction API.", DescriptionKey: "providers.tavily.description", SortOrder: 80, Revision: 1}); errGroup != nil {
		return fmt.Errorf("register Tavily provider group: %w", errGroup)
	}
	auth := providerconfig.AuthMethodDefinition{ID: "api_key", Type: providerconfig.AuthMethodAPIKey, MultipleCredentials: true, BillingMode: providerconfig.BillingModeSubscription}
	features := providerconfig.ProviderFeatureSet{PlanReader: providerconfig.SupportSupported, EntitlementReader: providerconfig.SupportUnsupported, AllowanceReader: providerconfig.SupportSupported}
	searchAction := providerconfig.ProviderActionBinding{ID: providertavily.ActionBindingID, Operation: vcp.OperationSearchWeb, DriverID: "tavily", DriverVersion: "1", ProtocolProfileID: providertavily.ProtocolProfileID, EndpointProfileID: "tavily_search", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, Search: &providerconfig.SearchActionBinding{BackendKind: vcp.SearchBackendDirectAPI}, Revision: 1}
	extractAction := providerconfig.ProviderActionBinding{ID: providertavily.ExtractActionBindingID, Operation: vcp.OperationWebExtract, DriverID: "tavily", DriverVersion: "1", ProtocolProfileID: providertavily.ExtractProtocolProfileID, EndpointProfileID: "tavily_search", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, Revision: 1}
	definition := providerconfig.ProviderDefinition{
		ID: TavilySearchDefinitionID, Kind: providerconfig.DefinitionKindSystem, DisplayName: "Tavily API", GroupID: TavilyGroupID, VariantName: "API", VariantDescription: "Tavily structured web search and direct content extraction.", VariantDescriptionKey: "providers.tavily.searchDescription", ModelCatalogID: "tavily_search_api", SortOrder: 10,
		DriverID: "tavily", DriverVersion: "1", ConfigSchemaVersion: "1", ProtocolProfileID: providertavily.ProtocolProfileID, EndpointProfileID: "tavily_search", AuthMethodIDs: []string{"api_key"}, Priority: 10, RuntimeReady: true,
		AuthMethods: []providerconfig.AuthMethodDefinition{auth}, EndpointPresets: []providerconfig.EndpointPreset{{ID: "search_api", BaseURL: "https://api.tavily.com", Region: "Global", UserEditable: false}}, Features: features, ActionBindings: []providerconfig.ProviderActionBinding{searchAction, extractAction}, Revision: 1,
	}
	if errRegister := registry.Register(definition); errRegister != nil {
		return fmt.Errorf("register Tavily provider definition: %w", errRegister)
	}
	return nil
}

// RegisterTavilyExecutionDrivers binds exact Tavily search and extraction actions.
// RegisterTavilyExecutionDrivers 绑定精确的 Tavily 搜索与提取动作。
func RegisterTavilyExecutionDrivers(registry *provider.ExecutionRegistry, client *transport.Client) error {
	if registry == nil || client == nil {
		return fmt.Errorf("Tavily execution registry and transport client are required")
	}
	driver, errDriver := providertavily.NewSearchDriver(TavilySearchDefinitionID, client)
	if errDriver != nil {
		return fmt.Errorf("create Tavily search driver: %w", errDriver)
	}
	if errRegister := registry.RegisterAction(driver); errRegister != nil {
		return fmt.Errorf("register Tavily search driver: %w", errRegister)
	}
	extractDriver, errExtractDriver := providertavily.NewExtractDriver(TavilySearchDefinitionID, client)
	if errExtractDriver != nil {
		return fmt.Errorf("create Tavily extraction driver: %w", errExtractDriver)
	}
	if errRegister := registry.RegisterAction(extractDriver); errRegister != nil {
		return fmt.Errorf("register Tavily extraction driver: %w", errRegister)
	}
	return nil
}
