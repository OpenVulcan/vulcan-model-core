package bootstrap

import (
	"fmt"

	protocolchat "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/chat"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	providerdeepseek "github.com/OpenVulcan/vulcan-model-core/internal/provider/deepseek"
	provideropenai "github.com/OpenVulcan/vulcan-model-core/internal/provider/openai"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
)

const (
	// DeepSeekGroupID identifies the official DeepSeek provider family.
	// DeepSeekGroupID 标识 DeepSeek 官方供应商系列。
	DeepSeekGroupID = "deepseek"
	// DeepSeekAPIDefinitionID identifies the official DeepSeek public API product.
	// DeepSeekAPIDefinitionID 标识 DeepSeek 官方公共 API 产品。
	DeepSeekAPIDefinitionID = "system_deepseek_api"
)

// registerDeepSeekProviderCatalog registers the official DeepSeek API as one immutable system product.
// registerDeepSeekProviderCatalog 将 DeepSeek 官方 API 注册为一个不可变系统产品。
func registerDeepSeekProviderCatalog(registry *providerconfig.SystemRegistry) error {
	if registry == nil {
		return fmt.Errorf("DeepSeek system provider registry is required")
	}
	if errGroup := registry.RegisterGroup(providerconfig.ProviderGroup{
		ID:             DeepSeekGroupID,
		DisplayName:    "DeepSeek",
		Description:    "Official DeepSeek API with dual thinking modes and account balance queries.",
		DescriptionKey: "providers.deepseek.description",
		SortOrder:      55,
		Revision:       1,
	}); errGroup != nil {
		return fmt.Errorf("register DeepSeek provider group: %w", errGroup)
	}
	// apiKey is the sole credential type documented for the official public API.
	// apiKey 是官方公共 API 文档记录的唯一凭据类型。
	apiKey := providerconfig.AuthMethodDefinition{
		ID:                  "api_key",
		Type:                providerconfig.AuthMethodAPIKey,
		MultipleCredentials: true,
		PlanAcquisition:     providerconfig.PlanAcquisitionUnavailable,
		BillingMode:         providerconfig.BillingModeUsage,
	}
	// features exposes only the provider capabilities backed by official endpoints.
	// features 仅公开由官方端点支撑的供应商能力。
	features := providerconfig.ProviderFeatureSet{
		PlanReader:        providerconfig.SupportUnsupported,
		EntitlementReader: providerconfig.SupportUnsupported,
		AllowanceReader:   providerconfig.SupportSupported,
	}
	definition := providerDefinition(
		DeepSeekAPIDefinitionID,
		"DeepSeek API",
		DeepSeekGroupID,
		"API",
		"Official DeepSeek API using OpenAI Chat Completions and provider-native balance queries.",
		"providers.deepseek.apiDescription",
		"deepseek_api",
		10,
		"deepseek",
		protocolchat.ProfileID,
		"deepseek_chat",
		"https://api.deepseek.com",
		true,
		[]providerconfig.AuthMethodDefinition{apiKey},
		features,
	)
	definitionWithAction, errAction := withConversationAction(definition)
	if errAction != nil {
		return errAction
	}
	if errRegister := registry.Register(definitionWithAction); errRegister != nil {
		return fmt.Errorf("register DeepSeek provider definition: %w", errRegister)
	}
	return nil
}

// RegisterDeepSeekExecutionDrivers binds the official DeepSeek product to its typed Chat driver.
// RegisterDeepSeekExecutionDrivers 将 DeepSeek 官方产品绑定到其类型化 Chat Driver。
func RegisterDeepSeekExecutionDrivers(registry *provider.ExecutionRegistry, client *transport.Client) error {
	if registry == nil || client == nil {
		return fmt.Errorf("DeepSeek execution registry and transport client are required")
	}
	driver, errDriver := provideropenai.NewBearerChatDriverWithRequestAdapter(
		DeepSeekAPIDefinitionID,
		protocolchat.ProfileID,
		client,
		deepSeekChatCapabilities(),
		[]providerconfig.AuthMethodType{providerconfig.AuthMethodAPIKey},
		providerdeepseek.NewChatAdapter(),
	)
	if errDriver != nil {
		return fmt.Errorf("create DeepSeek Chat driver: %w", errDriver)
	}
	if errRegister := registerConversationDriver(registry, driver); errRegister != nil {
		return fmt.Errorf("register DeepSeek Chat driver: %w", errRegister)
	}
	return nil
}

// deepSeekChatCapabilities returns only officially documented Chat transport features.
// deepSeekChatCapabilities 仅返回官方文档记录的 Chat 传输能力。
func deepSeekChatCapabilities() protocolchat.ProfileCapabilities {
	return protocolchat.ProfileCapabilities{
		NativeSystemPreamble:           true,
		StructuredTools:                true,
		Reasoning:                      true,
		ProviderReasoningSwitchAdapter: true,
		ReasoningContent:               true,
	}
}
