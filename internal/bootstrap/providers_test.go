package bootstrap

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	protocolmessages "github.com/OpenVulcan/vulcan-model-core/internal/protocol/anthropic/messages"
	protocolchat "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/chat"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	providerkimi "github.com/OpenVulcan/vulcan-model-core/internal/provider/kimi"
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
	if len(groups) != 1 || groups[0].ID != KimiGroupID || groups[0].DisplayName != "Kimi" {
		t.Fatalf("groups = %#v", groups)
	}
	definitions := systems.List()
	if len(definitions) != 3 {
		t.Fatalf("definition count = %d", len(definitions))
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
	if len(coding.Channels) != 2 || len(coding.EndpointPresets) != 2 || coding.VariantName != "Coding Plan" || coding.EndpointPresets[0].BaseURL != "https://api.kimi.com/coding" {
		t.Fatalf("Coding definition = %#v", coding)
	}
	if len(coding.AuthMethods) != 2 || coding.AuthMethods[0].Type != providerconfig.AuthMethodAPIKey || coding.AuthMethods[1].Type != providerconfig.AuthMethodDeviceFlow || !coding.AuthMethods[1].Refreshable {
		t.Fatalf("Coding authentication = %#v", coding.AuthMethods)
	}
	for _, channel := range coding.Channels {
		if !channel.RuntimeReady {
			t.Fatalf("Coding channel %q is not runtime ready after its driver implementation was added", channel.ID)
		}
	}
}

// TestKimiExecutionDriversUseExactDefinitionPathsAndBearerAuthentication verifies every runtime-ready Kimi channel end to end.
// TestKimiExecutionDriversUseExactDefinitionPathsAndBearerAuthentication 端到端验证每个运行时就绪的 Kimi 通道。
func TestKimiExecutionDriversUseExactDefinitionPathsAndBearerAuthentication(t *testing.T) {
	expectedPath := ""
	expectedAuthorization := "Bearer kimi-test-key"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != expectedPath {
			t.Errorf("request path = %q, want %q", request.URL.Path, expectedPath)
		}
		if authorization := request.Header.Get("Authorization"); authorization != expectedAuthorization {
			t.Errorf("Authorization = %q", authorization)
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
	if errRegister := RegisterKimiExecutionDrivers(registry, openPlatformClient, codingClient); errRegister != nil {
		t.Fatalf("RegisterKimiExecutionDrivers() error = %v", errRegister)
	}
	definitions := kimiDefinitionsByID()
	testCases := []struct {
		name          string
		definitionID  string
		channelID     string
		profileID     string
		path          string
		authMethodID  string
		secretRef     string
		authorization string
	}{
		{name: "CN Chat", definitionID: KimiCNDefinitionID, channelID: "chat", profileID: protocolchat.ProfileID, path: "/v1/chat/completions", authMethodID: "api_key", secretRef: secretReference, authorization: "Bearer kimi-test-key"},
		{name: "Global Chat", definitionID: KimiGlobalDefinitionID, channelID: "chat", profileID: protocolchat.ProfileID, path: "/v1/chat/completions", authMethodID: "api_key", secretRef: secretReference, authorization: "Bearer kimi-test-key"},
		{name: "Coding Chat API Key", definitionID: KimiCodingDefinitionID, channelID: "chat", profileID: protocolchat.ProfileID, path: "/coding/v1/chat/completions", authMethodID: "api_key", secretRef: secretReference, authorization: "Bearer kimi-test-key"},
		{name: "Coding Chat Device Flow", definitionID: KimiCodingDefinitionID, channelID: "chat", profileID: protocolchat.ProfileID, path: "/coding/v1/chat/completions", authMethodID: "device_flow", secretRef: deviceTokenReference, authorization: "Bearer kimi-device-access"},
		{name: "Coding Anthropic", definitionID: KimiCodingDefinitionID, channelID: "anthropic", profileID: protocolmessages.ProfileID, path: "/coding/v1/messages", authMethodID: "api_key", secretRef: secretReference, authorization: "Bearer kimi-test-key"},
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
			execution := kimiExecutionRequest(definition, testCase.channelID, testCase.profileID, server.URL+upstreamURL.Path, testCase.authMethodID, testCase.secretRef)
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
	for _, preset := range definition.EndpointPresets {
		if preset.ChannelID == channelID {
			return preset
		}
	}
	t.Fatalf("definition %q has no endpoint preset for channel %q", definition.ID, channelID)
	return providerconfig.EndpointPreset{}
}

// kimiExecutionRequest builds one exact-target VCP execution from a code-owned definition and endpoint preset.
// kimiExecutionRequest 从代码拥有的定义和端点预设构建一条精确目标 VCP 执行。
func kimiExecutionRequest(definition providerconfig.ProviderDefinition, channelID string, profileID string, baseURL string, authMethodID string, secretReference string) provider.ExecutionRequest {
	instanceID := "instance-" + definition.ID
	endpointID := "endpoint-" + channelID
	credentialID := "credential-" + authMethodID
	return provider.ExecutionRequest{
		Binding: transport.Binding{
			Target:     resolve.Target{ProviderDefinitionID: definition.ID, ProviderInstanceID: instanceID, ChannelID: channelID, EndpointID: endpointID, CredentialID: credentialID, ProviderModelID: "model-kimi", OfferingID: "offering-kimi", ExecutionProfileID: profileID, UpstreamModelID: "kimi-for-coding", CatalogRevision: 1},
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
