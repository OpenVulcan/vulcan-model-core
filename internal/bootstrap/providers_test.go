package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	protocolchat "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/chat"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	provideralibaba "github.com/OpenVulcan/vulcan-model-core/internal/provider/alibaba"
	providerkimi "github.com/OpenVulcan/vulcan-model-core/internal/provider/kimi"
	providerminimax "github.com/OpenVulcan/vulcan-model-core/internal/provider/minimax"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestRegisterSystemProvidersBuildsKimiGroup verifies exact variants, shared catalogs, endpoints, and protocols.
// TestRegisterSystemProvidersBuildsKimiGroup 验证精确变体、共享目录、端点和协议。
func TestRegisterSystemProvidersBuildsKimiGroup(t *testing.T) {
	protocols := providerconfig.NewProtocolRegistry()
	if errProtocols := RegisterProtocolProfiles(protocols); errProtocols != nil {
		t.Fatalf("RegisterProtocolProfiles() error = %v", errProtocols)
	}
	systems, errSystems := providerconfig.NewSystemRegistry(protocols)
	if errSystems != nil {
		t.Fatalf("NewSystemRegistry() error = %v", errSystems)
	}
	if errRegister := RegisterSystemProviders(systems); errRegister != nil {
		t.Fatalf("RegisterSystemProviders() error = %v", errRegister)
	}
	groups := systems.ListGroups()
	if len(groups) != 9 || groups[0].ID != KimiGroupID || groups[0].DisplayName != "Kimi" || groups[5].ID != AlibabaGroupID || groups[6].ID != OpenRouterGroupID || groups[7].ID != MiniMaxGroupID || groups[8].ID != TavilyGroupID {
		t.Fatalf("groups = %#v", groups)
	}
	definitions := systems.List()
	if len(definitions) != 25 {
		t.Fatalf("definition count = %d", len(definitions))
	}
	for _, definition := range definitions {
		if definition.ID == TavilySearchDefinitionID {
			if len(definition.ActionBindings) != 1 || definition.ActionBindings[0].Operation != vcp.OperationSearchWeb || definition.ActionBindings[0].Search == nil || definition.ActionBindings[0].Search.BackendKind != vcp.SearchBackendDirectAPI {
				t.Fatalf("definition %q Tavily actions = %#v", definition.ID, definition.ActionBindings)
			}
			continue
		}
		if definition.ID == AlibabaModelStudioWorkspaceGlobalDefinitionID {
			if len(definition.ActionBindings) != 9 || definition.ActionBindings[0].Operation != vcp.OperationEmbeddingCreate || definition.ActionBindings[1].ID != provideralibaba.SpeechSynthesizeActionBindingID || definition.ActionBindings[2].ID != provideralibaba.SpeechTranscribeActionBindingID || definition.ActionBindings[3].ID != provideralibaba.SpeechTranscribeAsyncActionBindingID || definition.ActionBindings[4].Operation != vcp.OperationImageGenerate || definition.ActionBindings[5].Operation != vcp.OperationImageEdit || definition.ActionBindings[6].Operation != vcp.OperationImageGenerate || definition.ActionBindings[7].Operation != vcp.OperationImageEdit || definition.ActionBindings[8].Operation != vcp.OperationVideoGenerate {
				t.Fatalf("definition %q Alibaba workspace Model Studio actions = %#v", definition.ID, definition.ActionBindings)
			}
			continue
		}
		if definition.ID == AlibabaModelStudioCNDefinitionID || definition.ID == AlibabaModelStudioGlobalDefinitionID {
			if len(definition.ActionBindings) != 6 || definition.ActionBindings[0].Operation != vcp.OperationEmbeddingCreate || definition.ActionBindings[1].ID != provideralibaba.SpeechSynthesizeActionBindingID || definition.ActionBindings[2].ID != provideralibaba.SpeechTranscribeActionBindingID || definition.ActionBindings[3].ID != provideralibaba.SpeechTranscribeAsyncActionBindingID || definition.ActionBindings[4].Operation != vcp.OperationImageGenerate || definition.ActionBindings[5].Operation != vcp.OperationImageEdit {
				t.Fatalf("definition %q Alibaba Model Studio actions = %#v", definition.ID, definition.ActionBindings)
			}
			continue
		}
		if definition.ID == OpenRouterAPIDefinitionID {
			if len(definition.ActionBindings) != 6 || definition.ActionBindings[0].Operation != vcp.OperationEmbeddingCreate || definition.ActionBindings[1].Operation != vcp.OperationRerankDocuments || definition.ActionBindings[2].Operation != vcp.OperationImageGenerate || definition.ActionBindings[3].Operation != vcp.OperationVideoGenerate || definition.ActionBindings[4].Operation != vcp.OperationSpeechSynthesize || definition.ActionBindings[5].Operation != vcp.OperationSpeechTranscribe {
				t.Fatalf("definition %q native actions = %#v", definition.ID, definition.ActionBindings)
			}
			continue
		}
		if definition.ID == MiniMaxAPIDefinitionID {
			if len(definition.ActionBindings) != 7 || definition.ActionBindings[0].Operation != vcp.OperationImageGenerate || definition.ActionBindings[1].Operation != vcp.OperationVideoGenerate || definition.ActionBindings[2].ID != providerminimax.SpeechSynthesizeActionBindingID || definition.ActionBindings[3].ID != providerminimax.SpeechSynthesizeAsyncActionBindingID || definition.ActionBindings[4].ID != providerminimax.MusicGenerateActionBindingID || definition.ActionBindings[5].ID != providerminimax.MusicCoverPrepareActionBindingID || definition.ActionBindings[6].ID != providerminimax.MusicCoverActionBindingID {
				t.Fatalf("definition %q MiniMax actions = %#v", definition.ID, definition.ActionBindings)
			}
			continue
		}
		if definition.ID == OpenAIAPIDefinitionID {
			if len(definition.ActionBindings) != 7 || definition.ActionBindings[0].Operation != vcp.OperationEmbeddingCreate || definition.ActionBindings[1].Operation != vcp.OperationSearchWeb || definition.ActionBindings[1].Search == nil || definition.ActionBindings[1].Search.BackendKind != vcp.SearchBackendGroundedModel || definition.ActionBindings[2].Operation != vcp.OperationImageGenerate || definition.ActionBindings[3].Operation != vcp.OperationImageEdit || definition.ActionBindings[4].Operation != vcp.OperationSpeechSynthesize || definition.ActionBindings[5].Operation != vcp.OperationSpeechTranscribe || definition.ActionBindings[6].ID != ConversationActionBindingID || definition.ActionBindings[6].Operation != vcp.OperationConversationRespond {
				t.Fatalf("definition %q OpenAI actions = %#v", definition.ID, definition.ActionBindings)
			}
			continue
		}
		if definition.ID == AnthropicAPIDefinitionID {
			if len(definition.ActionBindings) != 2 || definition.ActionBindings[0].Operation != vcp.OperationSearchWeb || definition.ActionBindings[0].Search == nil || definition.ActionBindings[1].Operation != vcp.OperationConversationRespond {
				t.Fatalf("definition %q Anthropic API actions = %#v", definition.ID, definition.ActionBindings)
			}
			continue
		}
		if definition.ID == GoogleAIStudioDefinitionID {
			if len(definition.ActionBindings) != 5 || definition.ActionBindings[0].Operation != vcp.OperationEmbeddingCreate || definition.ActionBindings[1].Operation != vcp.OperationMediaAnalyze || definition.ActionBindings[2].Operation != vcp.OperationVideoGenerate || definition.ActionBindings[3].Operation != vcp.OperationVideoExtend || definition.ActionBindings[4].ID != ConversationActionBindingID || definition.ActionBindings[4].Operation != vcp.OperationConversationRespond {
				t.Fatalf("definition %q Google AI Studio actions = %#v", definition.ID, definition.ActionBindings)
			}
			continue
		}
		if definition.ID == GoogleInteractionsDefinitionID {
			if len(definition.ActionBindings) != 5 || definition.ActionBindings[0].Operation != vcp.OperationSearchWeb || definition.ActionBindings[0].Search == nil || definition.ActionBindings[1].Operation != vcp.OperationImageGenerate || definition.ActionBindings[2].Operation != vcp.OperationImageEdit || definition.ActionBindings[3].Operation != vcp.OperationSpeechSynthesize || definition.ActionBindings[4].Operation != vcp.OperationConversationRespond {
				t.Fatalf("definition %q Google Interactions actions = %#v", definition.ID, definition.ActionBindings)
			}
			continue
		}
		if definition.ID == XAIAPIDefinitionID {
			if len(definition.ActionBindings) != 7 || definition.ActionBindings[0].Operation != vcp.OperationSearchWeb || definition.ActionBindings[0].Search == nil || definition.ActionBindings[1].Operation != vcp.OperationImageGenerate || definition.ActionBindings[2].Operation != vcp.OperationImageEdit || definition.ActionBindings[3].Operation != vcp.OperationVideoGenerate || definition.ActionBindings[4].Operation != vcp.OperationVideoEdit || definition.ActionBindings[5].Operation != vcp.OperationVideoExtend || definition.ActionBindings[6].Operation != vcp.OperationConversationRespond {
				t.Fatalf("definition %q xAI API actions = %#v", definition.ID, definition.ActionBindings)
			}
			continue
		}
		if len(definition.ActionBindings) != 1 || definition.ActionBindings[0].ID != ConversationActionBindingID || definition.ActionBindings[0].Operation != vcp.OperationConversationRespond || definition.ActionBindings[0].ProtocolProfileID != definition.ProtocolProfileID || definition.ActionBindings[0].EndpointProfileID != definition.EndpointProfileID {
			t.Fatalf("definition %q conversation action = %#v", definition.ID, definition.ActionBindings)
		}
	}
	cn, existsCN := systems.Lookup(KimiCNDefinitionID)
	global, existsGlobal := systems.Lookup(KimiGlobalDefinitionID)
	coding, existsCoding := systems.Lookup(KimiCodingDefinitionID)
	if !existsCN || !existsGlobal || !existsCoding {
		t.Fatalf("definition existence = CN:%t Global:%t Coding:%t", existsCN, existsGlobal, existsCoding)
	}
	if cn.ModelCatalogID != global.ModelCatalogID || cn.EndpointPresets[0].BaseURL != "https://api.moonshot.cn" || global.EndpointPresets[0].BaseURL != "https://api.moonshot.ai" {
		t.Fatalf("Open Platform definitions = CN:%#v Global:%#v", cn, global)
	}
	if coding.ProtocolProfileID != protocolchat.ProfileID || len(coding.EndpointPresets) != 1 || coding.VariantName != "Coding Plan" || coding.EndpointPresets[0].BaseURL != "https://api.kimi.com/coding" {
		t.Fatalf("Coding definition = %#v", coding)
	}
	if len(coding.AuthMethods) != 2 || coding.AuthMethods[0].Type != providerconfig.AuthMethodAPIKey || coding.AuthMethods[1].Type != providerconfig.AuthMethodDeviceFlow || !coding.AuthMethods[1].Refreshable {
		t.Fatalf("Coding authentication = %#v", coding.AuthMethods)
	}
	if coding.Features.PlanReader != providerconfig.SupportSupported || coding.Features.EntitlementReader != providerconfig.SupportSupported || coding.Features.AllowanceReader != providerconfig.SupportSupported {
		t.Fatalf("Coding metadata features = %#v", coding.Features)
	}
	if !coding.RuntimeReady {
		t.Fatal("Coding protocol is not runtime ready after its driver implementation was added")
	}
}

// TestRegisterSystemProvidersBuildsAlibabaGroup verifies the five immutable plan products, exact endpoints, and sole protocol/authentication boundary.
// TestRegisterSystemProvidersBuildsAlibabaGroup 验证五个不可变套餐产品、精确端点和唯一协议及认证边界。
func TestRegisterSystemProvidersBuildsAlibabaGroup(t *testing.T) {
	protocols := providerconfig.NewProtocolRegistry()
	if errProtocols := RegisterProtocolProfiles(protocols); errProtocols != nil {
		t.Fatalf("RegisterProtocolProfiles() error = %v", errProtocols)
	}
	systems, errSystems := providerconfig.NewSystemRegistry(protocols)
	if errSystems != nil {
		t.Fatalf("NewSystemRegistry() error = %v", errSystems)
	}
	if errRegister := RegisterSystemProviders(systems); errRegister != nil {
		t.Fatalf("RegisterSystemProviders() error = %v", errRegister)
	}
	// expected closes the product set and endpoint ownership for the Alibaba group.
	// expected 封闭 Alibaba 分组的产品集合与端点归属。
	expected := []struct {
		// definitionID is the immutable product identity.
		// definitionID 是不可变产品身份。
		definitionID string
		// variantName is the concise management label.
		// variantName 是简洁的管理标签。
		variantName string
		// baseURL is the exact fixed regional Messages base address.
		// baseURL 是精确固定的区域 Messages 基础地址。
		baseURL string
	}{
		{AlibabaCodingPlanCNDefinitionID, "Coding Plan CN", "https://coding.dashscope.aliyuncs.com/apps/anthropic/v1"},
		{AlibabaCodingPlanGlobalDefinitionID, "Coding Plan Global", "https://coding-intl.dashscope.aliyuncs.com/apps/anthropic/v1"},
		{AlibabaTokenPlanPersonalCNDefinitionID, "Token Plan Personal CN", "https://token-plan.cn-beijing.maas.aliyuncs.com/apps/anthropic/v1"},
		{AlibabaTokenPlanTeamCNDefinitionID, "Token Plan Team CN", "https://token-plan.cn-beijing.maas.aliyuncs.com/apps/anthropic/v1"},
		{AlibabaTokenPlanTeamGlobalDefinitionID, "Token Plan Team Global", "https://token-plan.ap-southeast-1.maas.aliyuncs.com/apps/anthropic/v1"},
	}
	for index, want := range expected {
		definition, exists := systems.Lookup(want.definitionID)
		if !exists {
			t.Errorf("definition %q is missing", want.definitionID)
			continue
		}
		if definition.GroupID != AlibabaGroupID || definition.SortOrder != (index+1)*10 || definition.VariantName != want.variantName {
			t.Errorf("definition identity %q = %#v", want.definitionID, definition)
		}
		if definition.ProtocolProfileID != "anthropic.messages" || len(definition.EndpointPresets) != 1 || definition.EndpointPresets[0].BaseURL != want.baseURL || definition.EndpointPresets[0].UserEditable {
			t.Errorf("definition boundary %q = %#v", want.definitionID, definition)
		}
		if len(definition.AuthMethods) != 1 || definition.AuthMethods[0].ID != "api_key" || definition.AuthMethods[0].Type != providerconfig.AuthMethodAPIKey || !definition.RuntimeReady {
			t.Errorf("definition authentication/runtime %q = %#v", want.definitionID, definition)
		}
	}
}

// TestRegisterSystemProvidersIncludesAdaptedProducts verifies copied CLIProxyAPI products and independently evidenced Alibaba products form one closed system set.
// TestRegisterSystemProvidersIncludesAdaptedProducts 验证复制的 CLIProxyAPI 产品与独立取证的 Alibaba 产品共同形成封闭系统集合。
func TestRegisterSystemProvidersIncludesAdaptedProducts(t *testing.T) {
	protocols := providerconfig.NewProtocolRegistry()
	if errProtocols := RegisterProtocolProfiles(protocols); errProtocols != nil {
		t.Fatalf("RegisterProtocolProfiles() error = %v", errProtocols)
	}
	systems, errSystems := providerconfig.NewSystemRegistry(protocols)
	if errSystems != nil {
		t.Fatalf("NewSystemRegistry() error = %v", errSystems)
	}
	if errRegister := RegisterSystemProviders(systems); errRegister != nil {
		t.Fatalf("RegisterSystemProviders() error = %v", errRegister)
	}
	// expected records the exact non-Kimi products evidenced by CLIProxyAPI's executor registry.
	// expected 记录由 CLIProxyAPI 执行器注册表验证的精确非 Kimi 产品。
	expected := map[string]struct {
		// groupID is the exact system provider group.
		// groupID 是精确的系统供应商分组。
		groupID string
		// baseURL is the copied default provider origin.
		// baseURL 是复制的默认供应商 Origin。
		baseURL string
		// runtimeReady reports whether execution wiring is complete.
		// runtimeReady 表示执行接线是否完整。
		runtimeReady bool
	}{
		OpenAIAPIDefinitionID:           {groupID: OpenAIGroupID, baseURL: "https://api.openai.com", runtimeReady: true},
		OpenAICodexAPIKeyDefinitionID:   {groupID: OpenAIGroupID, baseURL: "https://chatgpt.com/backend-api/codex", runtimeReady: true},
		OpenAICodexDefinitionID:         {groupID: OpenAIGroupID, baseURL: "https://chatgpt.com/backend-api/codex", runtimeReady: true},
		AnthropicAPIDefinitionID:        {groupID: AnthropicGroupID, baseURL: "https://api.anthropic.com", runtimeReady: true},
		AnthropicClaudeCodeDefinitionID: {groupID: AnthropicGroupID, baseURL: "https://api.anthropic.com", runtimeReady: true},
		GoogleAIStudioDefinitionID:      {groupID: GoogleGroupID, baseURL: "https://generativelanguage.googleapis.com", runtimeReady: true},
		GoogleInteractionsDefinitionID:  {groupID: GoogleGroupID, baseURL: "https://generativelanguage.googleapis.com", runtimeReady: true},
		GoogleVertexDefinitionID:        {groupID: GoogleGroupID, baseURL: "https://us-central1-aiplatform.googleapis.com", runtimeReady: true},
		GoogleAntigravityDefinitionID:   {groupID: GoogleGroupID, baseURL: "https://cloudcode-pa.googleapis.com", runtimeReady: true},
		XAIAPIDefinitionID:              {groupID: XAIGroupID, baseURL: "https://api.x.ai/v1", runtimeReady: true},
		XAIOAuthDefinitionID:            {groupID: XAIGroupID, baseURL: "https://cli-chat-proxy.grok.com/v1", runtimeReady: true},
		OpenRouterAPIDefinitionID:       {groupID: OpenRouterGroupID, baseURL: "https://openrouter.ai/api", runtimeReady: true},
		MiniMaxAPIDefinitionID:          {groupID: MiniMaxGroupID, baseURL: "https://api.minimax.io", runtimeReady: true},
	}
	for definitionID, want := range expected {
		definition, exists := systems.Lookup(definitionID)
		if !exists {
			t.Errorf("definition %s is missing", definitionID)
			continue
		}
		if definition.GroupID != want.groupID || len(definition.EndpointPresets) != 1 || definition.EndpointPresets[0].BaseURL != want.baseURL || definition.RuntimeReady != want.runtimeReady {
			t.Errorf("definition %s = %#v", definitionID, definition)
		}
		if definitionID == OpenAICodexDefinitionID {
			if len(definition.AuthMethodIDs) != 2 || len(definition.AuthMethods) != 2 || definition.AuthMethodIDs[0] != "oauth" || definition.AuthMethodIDs[1] != "device_flow" || definition.AuthMethods[0].Type != providerconfig.AuthMethodOAuth || definition.AuthMethods[1].Type != providerconfig.AuthMethodDeviceFlow {
				t.Errorf("Codex auth methods = %#v / %#v", definition.AuthMethodIDs, definition.AuthMethods)
			}
			if definition.ModelCatalogID != "openai_codex_account" || definition.Features.PlanReader != providerconfig.SupportSupported || definition.Features.EntitlementReader != providerconfig.SupportSupported {
				t.Errorf("Codex account catalog/features = %q / %#v", definition.ModelCatalogID, definition.Features)
			}
		} else if definitionID == OpenAICodexAPIKeyDefinitionID {
			if definition.ModelCatalogID != "openai_codex_api_key" || definition.Features.PlanReader != providerconfig.SupportUnsupported || definition.Features.EntitlementReader != providerconfig.SupportUnsupported {
				t.Errorf("Codex API-key catalog/features = %q / %#v", definition.ModelCatalogID, definition.Features)
			}
		} else if len(definition.AuthMethodIDs) != 1 || len(definition.AuthMethods) != 1 || definition.AuthMethodIDs[0] != definition.AuthMethods[0].ID {
			t.Errorf("definition %s auth methods = %#v / %#v", definitionID, definition.AuthMethodIDs, definition.AuthMethods)
		}
	}
	// expectedDefinitionIDs closes the system-product set so plugin-only, relay-only, or custom compatibility providers cannot appear accidentally.
	// expectedDefinitionIDs 封闭系统产品全集，防止仅插件、仅中继或自定义兼容供应商被意外注册。
	expectedDefinitionIDs := map[string]struct{}{
		KimiCNDefinitionID: {}, KimiGlobalDefinitionID: {}, KimiCodingDefinitionID: {},
		OpenAIAPIDefinitionID: {}, OpenAICodexAPIKeyDefinitionID: {}, OpenAICodexDefinitionID: {},
		AnthropicAPIDefinitionID: {}, AnthropicClaudeCodeDefinitionID: {},
		GoogleAIStudioDefinitionID: {}, GoogleInteractionsDefinitionID: {}, GoogleVertexDefinitionID: {}, GoogleAntigravityDefinitionID: {},
		XAIAPIDefinitionID: {}, XAIOAuthDefinitionID: {},
		AlibabaCodingPlanCNDefinitionID: {}, AlibabaCodingPlanGlobalDefinitionID: {},
		AlibabaTokenPlanPersonalCNDefinitionID: {}, AlibabaTokenPlanTeamCNDefinitionID: {}, AlibabaTokenPlanTeamGlobalDefinitionID: {},
		AlibabaModelStudioCNDefinitionID: {}, AlibabaModelStudioGlobalDefinitionID: {},
		AlibabaModelStudioWorkspaceGlobalDefinitionID: {},
		OpenRouterAPIDefinitionID:                     {},
		MiniMaxAPIDefinitionID:                        {},
		TavilySearchDefinitionID:                      {},
	}
	definitions := systems.List()
	if len(definitions) != len(expectedDefinitionIDs) {
		t.Fatalf("system definition count = %d, want exact adapted set %d", len(definitions), len(expectedDefinitionIDs))
	}
	for _, definition := range definitions {
		if _, exists := expectedDefinitionIDs[definition.ID]; !exists {
			t.Errorf("unexpected system definition %q", definition.ID)
		}
	}
}

// TestRegisterCLIProxyExecutionDriversIncludesCodexKeyAndAccount verifies both Codex credential products own exact drivers.
// TestRegisterCLIProxyExecutionDriversIncludesCodexKeyAndAccount 验证两个 Codex 凭据产品都拥有精确 Driver。
func TestRegisterCLIProxyExecutionDriversIncludesCodexKeyAndAccount(t *testing.T) {
	secrets := secret.NewMemoryStore()
	client, errClient := transport.NewClient(http.DefaultClient, secrets, transport.RetryPolicy{})
	if errClient != nil {
		t.Fatalf("NewClient() error = %v", errClient)
	}
	registry := provider.NewExecutionRegistry()
	if errRegister := RegisterCLIProxyExecutionDrivers(registry, client, client, client, client, client, client); errRegister != nil {
		t.Fatalf("RegisterCLIProxyExecutionDrivers() error = %v", errRegister)
	}
	registered := make(map[string]struct{})
	for _, definitionID := range registry.ProviderIDs() {
		registered[definitionID] = struct{}{}
	}
	// expectedDriverIDs is the exact non-Kimi system Driver set owned by this registration function.
	// expectedDriverIDs 是该注册函数拥有的精确非 Kimi 系统 Driver 全集。
	expectedDriverIDs := []string{
		OpenAIAPIDefinitionID,
		OpenAICodexAPIKeyDefinitionID,
		OpenAICodexDefinitionID,
		AnthropicAPIDefinitionID,
		AnthropicClaudeCodeDefinitionID,
		GoogleAIStudioDefinitionID,
		GoogleInteractionsDefinitionID,
		GoogleVertexDefinitionID,
		GoogleAntigravityDefinitionID,
		XAIAPIDefinitionID,
		XAIOAuthDefinitionID,
	}
	if len(registered) != len(expectedDriverIDs) {
		t.Fatalf("registered Driver count = %d, want %d", len(registered), len(expectedDriverIDs))
	}
	for _, definitionID := range expectedDriverIDs {
		if _, exists := registered[definitionID]; !exists {
			t.Errorf("execution driver %s is missing", definitionID)
		}
	}
}

// TestRegisterAlibabaExecutionDriversOwnsExactSevenDefinitions verifies the Alibaba registrar owns every plan and fixed API product.
// TestRegisterAlibabaExecutionDriversOwnsExactSevenDefinitions 验证 Alibaba 注册器拥有每个套餐和固定 API 产品。
func TestRegisterAlibabaExecutionDriversOwnsExactSevenDefinitions(t *testing.T) {
	secrets := secret.NewMemoryStore()
	client, errClient := transport.NewClient(http.DefaultClient, secrets, transport.RetryPolicy{})
	if errClient != nil {
		t.Fatalf("NewClient() error = %v", errClient)
	}
	registry := provider.NewExecutionRegistry()
	if errRegister := RegisterAlibabaExecutionDrivers(registry, client, bootstrapDocumentFetcher{}); errRegister != nil {
		t.Fatalf("RegisterAlibabaExecutionDrivers() error = %v", errRegister)
	}
	expectedDriverIDs := []string{AlibabaCodingPlanCNDefinitionID, AlibabaCodingPlanGlobalDefinitionID, AlibabaModelStudioCNDefinitionID, AlibabaModelStudioGlobalDefinitionID, AlibabaModelStudioWorkspaceGlobalDefinitionID, AlibabaTokenPlanPersonalCNDefinitionID, AlibabaTokenPlanTeamCNDefinitionID, AlibabaTokenPlanTeamGlobalDefinitionID}
	registeredDriverIDs := registry.ProviderIDs()
	if len(registeredDriverIDs) != len(expectedDriverIDs) {
		t.Fatalf("registered Driver IDs = %#v", registeredDriverIDs)
	}
	for index, definitionID := range expectedDriverIDs {
		if registeredDriverIDs[index] != definitionID {
			t.Fatalf("registered Driver[%d] = %q, want %q", index, registeredDriverIDs[index], definitionID)
		}
	}
}

// bootstrapDocumentFetcher is a registration-only public document fetcher fixture.
// bootstrapDocumentFetcher 是仅用于注册测试的公网文档获取夹具。
type bootstrapDocumentFetcher struct{}

// FetchPublicDocument reports an unexpected execution from registration-only tests.
// FetchPublicDocument 报告仅注册测试中的意外执行。
func (bootstrapDocumentFetcher) FetchPublicDocument(context.Context, string, int64) ([]byte, error) {
	return nil, fmt.Errorf("registration-only document fetcher was executed")
}

// TestXAIProviderCapabilitiesKeepCompactOnOfficialAPI verifies endpoint-specific compact support is not overclaimed.
// TestXAIProviderCapabilitiesKeepCompactOnOfficialAPI 验证不会跨入口夸大 Compact 支持。
func TestXAIProviderCapabilitiesKeepCompactOnOfficialAPI(t *testing.T) {
	if !xaiAPIResponsesCapabilities().NativeRemoteCompaction {
		t.Fatal("official xAI API remote compaction = false")
	}
	if xaiAccountResponsesCapabilities().NativeRemoteCompaction {
		t.Fatal("xAI account chat-proxy remote compaction = true")
	}
}

// TestKimiExecutionDriversUseExactDefinitionPathsAndBearerAuthentication verifies every runtime-ready Kimi channel end to end.
// TestKimiExecutionDriversUseExactDefinitionPathsAndBearerAuthentication 端到端验证每个运行时就绪的 Kimi 通道。
func TestKimiExecutionDriversUseExactDefinitionPathsAndBearerAuthentication(t *testing.T) {
	expectedPath := ""
	expectedAuthorization := "Bearer kimi-test-key"
	expectedModel := ""
	expectedKimiHeaders := false
	expectedDeviceID := ""
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != expectedPath {
			t.Errorf("request path = %q, want %q", request.URL.Path, expectedPath)
		}
		if authorization := request.Header.Get("Authorization"); authorization != expectedAuthorization {
			t.Errorf("Authorization = %q", authorization)
		}
		// payload captures only the typed model field needed to verify Kimi's wire projection.
		// payload 仅捕获验证 Kimi wire 投影所需的类型化模型字段。
		payload := struct {
			// Model is the provider-facing model identifier sent on the wire.
			// Model 是发送到 wire 上的供应商侧模型标识。
			Model string `json:"model"`
		}{}
		if errDecode := json.NewDecoder(request.Body).Decode(&payload); errDecode != nil {
			t.Errorf("decode request body: %v", errDecode)
		} else if payload.Model != expectedModel {
			t.Errorf("model = %q, want %q", payload.Model, expectedModel)
		}
		if expectedKimiHeaders {
			if request.Header.Get("User-Agent") != "CLIProxyAPI/dev" || request.Header.Get("X-Msh-Platform") != "CLIProxyAPI" || request.Header.Get("X-Msh-Version") != "dev" || request.Header.Get("X-Msh-Device-Id") == "" {
				t.Errorf("Kimi execution headers = %#v", request.Header)
			}
			if expectedDeviceID != "" && request.Header.Get("X-Msh-Device-Id") != expectedDeviceID {
				t.Errorf("X-Msh-Device-Id = %q, want %q", request.Header.Get("X-Msh-Device-Id"), expectedDeviceID)
			}
		} else if request.Header.Get("X-Msh-Platform") != "" || request.Header.Get("X-Msh-Device-Id") != "" {
			t.Errorf("Open Platform request leaked Coding headers = %#v", request.Header)
		}
		if strings.HasSuffix(expectedPath, "/messages") {
			writer.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(writer, "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_kimi\",\"usage\":{\"input_tokens\":1,\"output_tokens\":0}}}\n"+
				"data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n"+
				"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"ok\"}}\n"+
				"data: {\"type\":\"content_block_stop\",\"index\":0}\n"+
				"data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":1}}\n"+
				"data: {\"type\":\"message_stop\"}\n")
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"id":"chat_kimi","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`)
	}))
	defer server.Close()

	secretStore := secret.NewMemoryStore()
	secretReference, errSecret := secretStore.Put(context.Background(), []byte("kimi-test-key"))
	if errSecret != nil {
		t.Fatalf("Put() error = %v", errSecret)
	}
	encodedDeviceToken, errDeviceToken := providerkimi.MarshalToken(providerkimi.Token{AccessToken: "kimi-device-access", RefreshToken: "kimi-device-refresh", DeviceID: "device-test", Type: "kimi"})
	if errDeviceToken != nil {
		t.Fatalf("MarshalToken() error = %v", errDeviceToken)
	}
	deviceTokenReference, errPutDeviceToken := secretStore.Put(context.Background(), encodedDeviceToken)
	if errPutDeviceToken != nil {
		t.Fatalf("Put(device token) error = %v", errPutDeviceToken)
	}
	openPlatformClient, errOpenClient := transport.NewClient(server.Client(), secretStore, transport.RetryPolicy{})
	if errOpenClient != nil {
		t.Fatalf("NewClient(open platform) error = %v", errOpenClient)
	}
	accessTokens, errAccessTokens := providerkimi.NewAccessTokenStore(secretStore)
	if errAccessTokens != nil {
		t.Fatalf("NewAccessTokenStore() error = %v", errAccessTokens)
	}
	codingClient, errCodingClient := transport.NewClient(server.Client(), accessTokens, transport.RetryPolicy{})
	if errCodingClient != nil {
		t.Fatalf("NewClient(coding) error = %v", errCodingClient)
	}
	registry := provider.NewExecutionRegistry()
	if errRegister := RegisterKimiExecutionDrivers(registry, openPlatformClient, codingClient, secretStore); errRegister != nil {
		t.Fatalf("RegisterKimiExecutionDrivers() error = %v", errRegister)
	}
	definitions := kimiDefinitionsByID()
	testCases := []struct {
		// name labels the isolated execution case.
		// name 标记隔离执行用例。
		name string
		// definitionID selects one immutable Kimi product.
		// definitionID 选择一个不可变 Kimi 产品。
		definitionID string
		// channelID selects the configured protocol channel.
		// channelID 选择已配置协议通道。
		channelID string
		// profileID is the expected execution profile.
		// profileID 是预期执行 Profile。
		profileID string
		// path is the exact expected upstream request path.
		// path 是预期的精确上游请求路径。
		path string
		// authMethodID selects API-key or device-flow metadata.
		// authMethodID 选择 API Key 或设备授权元数据。
		authMethodID string
		// secretRef identifies the protected test credential.
		// secretRef 标识受保护测试凭据。
		secretRef string
		// authorization is the expected projected bearer header.
		// authorization 是预期投影后的 Bearer Header。
		authorization string
		// upstreamModel is the catalog-owned immutable model identifier before wire adaptation.
		// upstreamModel 是 wire 适配前由目录拥有的不可变模型标识。
		upstreamModel string
		// projectedModel is the exact provider-facing model identifier.
		// projectedModel 是精确的供应商侧模型标识。
		projectedModel string
		// kimiHeaders reports whether Kimi Coding CLI identity headers are required.
		// kimiHeaders 表示是否需要 Kimi Coding CLI 身份请求头。
		kimiHeaders bool
		// deviceID is the exact device-flow identity when deterministic.
		// deviceID 是可确定时的精确设备授权身份。
		deviceID string
	}{
		{name: "CN Chat", definitionID: KimiCNDefinitionID, channelID: protocolchat.ProfileID, profileID: protocolchat.ProfileID, path: "/v1/chat/completions", authMethodID: "api_key", secretRef: secretReference, authorization: "Bearer kimi-test-key", upstreamModel: "kimi-k2.5", projectedModel: "kimi-k2.5"},
		{name: "Global Chat", definitionID: KimiGlobalDefinitionID, channelID: protocolchat.ProfileID, profileID: protocolchat.ProfileID, path: "/v1/chat/completions", authMethodID: "api_key", secretRef: secretReference, authorization: "Bearer kimi-test-key", upstreamModel: "kimi-k2.5", projectedModel: "kimi-k2.5"},
		{name: "Coding Chat API Key", definitionID: KimiCodingDefinitionID, channelID: protocolchat.ProfileID, profileID: protocolchat.ProfileID, path: "/coding/v1/chat/completions", authMethodID: "api_key", secretRef: secretReference, authorization: "Bearer kimi-test-key", upstreamModel: "kimi-k2.5", projectedModel: "k2.5", kimiHeaders: true},
		{name: "Coding Chat Device Flow", definitionID: KimiCodingDefinitionID, channelID: protocolchat.ProfileID, profileID: protocolchat.ProfileID, path: "/coding/v1/chat/completions", authMethodID: "device_flow", secretRef: deviceTokenReference, authorization: "Bearer kimi-device-access", upstreamModel: "kimi-k2.5", projectedModel: "k2.5", kimiHeaders: true, deviceID: "device-test"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			definition := definitions[testCase.definitionID]
			preset := kimiEndpointPreset(t, definition, testCase.channelID)
			upstreamURL, errURL := url.Parse(preset.BaseURL)
			if errURL != nil {
				t.Fatalf("Parse(%q) error = %v", preset.BaseURL, errURL)
			}
			expectedPath = testCase.path
			expectedAuthorization = testCase.authorization
			expectedModel = testCase.projectedModel
			expectedKimiHeaders = testCase.kimiHeaders
			expectedDeviceID = testCase.deviceID
			execution := kimiExecutionRequest(definition, testCase.channelID, testCase.profileID, server.URL+upstreamURL.Path, testCase.authMethodID, testCase.secretRef, testCase.upstreamModel)
			result, errExecute := registry.Execute(context.Background(), execution)
			if errExecute != nil {
				t.Fatalf("Execute() error = %v", errExecute)
			}
			if result.Response.Status != vcp.ResponseCompleted || len(result.Response.Items) == 0 || result.Response.Items[0].Content[0].Text != "ok" {
				t.Fatalf("result = %#v", result)
			}
		})
	}
}

// kimiDefinitionsByID indexes immutable Kimi definitions by their exact identifier for runtime tests.
// kimiDefinitionsByID 按精确标识索引不可变 Kimi 定义以供运行时测试。
func kimiDefinitionsByID() map[string]providerconfig.ProviderDefinition {
	definitions := make(map[string]providerconfig.ProviderDefinition)
	for _, definition := range kimiProviderDefinitions() {
		definitions[definition.ID] = definition
	}
	return definitions
}

// kimiEndpointPreset returns the one exact channel preset from a validated immutable definition.
// kimiEndpointPreset 从已校验的不可变定义返回一个精确通道预设。
func kimiEndpointPreset(t *testing.T, definition providerconfig.ProviderDefinition, channelID string) providerconfig.EndpointPreset {
	t.Helper()
	if len(definition.EndpointPresets) == 1 && channelID == definition.ProtocolProfileID {
		return definition.EndpointPresets[0]
	}
	t.Fatalf("definition %q has no endpoint preset for channel %q", definition.ID, channelID)
	return providerconfig.EndpointPreset{}
}

// kimiExecutionRequest builds one exact-target VCP execution from a code-owned definition and endpoint preset.
// kimiExecutionRequest 从代码拥有的定义和端点预设构建一条精确目标 VCP 执行。
func kimiExecutionRequest(definition providerconfig.ProviderDefinition, channelID string, profileID string, baseURL string, authMethodID string, secretReference string, upstreamModelID string) provider.ExecutionRequest {
	instanceID := "instance-" + definition.ID
	endpointID := "endpoint-" + channelID
	credentialID := "credential-" + authMethodID
	return provider.ExecutionRequest{
		Binding: transport.Binding{
			Target:     resolve.Target{ProviderDefinitionID: definition.ID, ProviderInstanceID: instanceID, ChannelID: channelID, EndpointID: endpointID, CredentialID: credentialID, ProviderModelID: "model-kimi", OfferingID: "offering-kimi", ExecutionProfileID: profileID, UpstreamModelID: upstreamModelID, CatalogRevision: 1},
			Endpoint:   providerconfig.Endpoint{ID: endpointID, ProviderInstanceID: instanceID, ChannelID: channelID, BaseURL: baseURL, Status: providerconfig.EndpointReady},
			Credential: providerconfig.Credential{ID: credentialID, ProviderInstanceID: instanceID, AuthMethodID: authMethodID, SecretRef: secretReference, Status: providerconfig.CredentialActive},
		},
		Definition: definition,
		Request: vcp.VulcanRequest{
			ProtocolVersion: vcp.ProtocolVersion,
			RequestID:       "request-kimi",
			ModelSelection:  vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: instanceID, ProviderModelID: "model-kimi", ExecutionProfileID: profileID},
			Context:         []vcp.ContextItem{{ItemID: "user-kimi", Sequence: 1, Kind: vcp.ContextMessage, Authority: vcp.AuthorityUser, Actor: vcp.ActorEndUser, Placement: vcp.PlacementTranscript, Activation: vcp.Activation{Mode: vcp.ActivationRequestStart}, Visibility: vcp.VisibilityModel, Content: []vcp.ContentBlock{{Type: vcp.ContentText, Text: "Hello"}}, Message: &vcp.MessageItem{}}},
			CachePolicy:     vcp.CachePolicy{Strategy: vcp.CacheRegular, OnUnsupported: vcp.CacheUnsupportedReject}, ContextManagementPolicy: vcp.ContextManagementPolicy{Mode: vcp.ContextManagementRegular}, CapabilityPolicy: vcp.CapabilityPolicy{ExecutionMode: vcp.CapabilityMaximize, OptionalOnUnsupported: vcp.OptionalOmit},
		},
		LineageID: "lineage-kimi",
		Now:       time.Date(2026, time.July, 18, 0, 0, 0, 0, time.UTC),
	}
}
