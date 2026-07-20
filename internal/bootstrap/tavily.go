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

// registerTavilyProviderCatalog registers the direct-search-only Tavily system product.
// registerTavilyProviderCatalog 注册仅提供直接搜索的 Tavily 系统产品。
func registerTavilyProviderCatalog(registry *providerconfig.SystemRegistry) error {
	if errGroup := registry.RegisterGroup(providerconfig.ProviderGroup{ID: TavilyGroupID, DisplayName: "Tavily", Description: "Tavily structured web search API.", DescriptionKey: "providers.tavily.description", SortOrder: 80, Revision: 1}); errGroup != nil {
		return fmt.Errorf("register Tavily provider group: %w", errGroup)
	}
	auth := providerconfig.AuthMethodDefinition{ID: "api_key", Type: providerconfig.AuthMethodAPIKey, MultipleCredentials: true}
	features := providerconfig.ProviderFeatureSet{ModelDiscovery: providerconfig.SupportUnsupported, PlanReader: providerconfig.SupportUnsupported, EntitlementReader: providerconfig.SupportUnsupported, AllowanceReader: providerconfig.SupportUnsupported}
	action := providerconfig.ProviderActionBinding{ID: providertavily.ActionBindingID, Operation: vcp.OperationSearchWeb, DriverID: "tavily", DriverVersion: "1", ProtocolProfileID: providertavily.ProtocolProfileID, EndpointProfileID: "tavily_search", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, Search: &providerconfig.SearchActionBinding{BackendKind: vcp.SearchBackendDirectAPI}, Revision: 1}
	definition := providerconfig.ProviderDefinition{
		ID: TavilySearchDefinitionID, Kind: providerconfig.DefinitionKindSystem, DisplayName: "Tavily Search API", GroupID: TavilyGroupID, VariantName: "Search API", VariantDescription: "Tavily structured direct web search.", VariantDescriptionKey: "providers.tavily.searchDescription", ModelCatalogID: "tavily_search_api", SortOrder: 10,
		DriverID: "tavily", DriverVersion: "1", ConfigSchemaVersion: "1", ProtocolProfileID: providertavily.ProtocolProfileID, EndpointProfileID: "tavily_search", AuthMethodIDs: []string{"api_key"}, Priority: 10, RuntimeReady: true,
		AuthMethods: []providerconfig.AuthMethodDefinition{auth}, EndpointPresets: []providerconfig.EndpointPreset{{ID: "search_api", BaseURL: "https://api.tavily.com", Region: "Global", UserEditable: false}}, Features: features, ActionBindings: []providerconfig.ProviderActionBinding{action}, Revision: 1,
	}
	if errRegister := registry.Register(definition); errRegister != nil {
		return fmt.Errorf("register Tavily provider definition: %w", errRegister)
	}
	return nil
}

// RegisterTavilyExecutionDrivers binds the exact Tavily direct-search action.
// RegisterTavilyExecutionDrivers 绑定精确的 Tavily 直接搜索动作。
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
	return nil
}
