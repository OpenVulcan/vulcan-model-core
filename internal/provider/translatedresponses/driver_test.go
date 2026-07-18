package translatedresponses_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/protocol/anthropic/messages"
	"github.com/OpenVulcan/vulcan-model-core/internal/protocol/google/antigravity"
	"github.com/OpenVulcan/vulcan-model-core/internal/protocol/google/interactions"
	"github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/codex"
	openairesponses "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/responses"
	protocolbridge "github.com/OpenVulcan/vulcan-model-core/internal/protocol/translatedresponses"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	translateddriver "github.com/OpenVulcan/vulcan-model-core/internal/provider/translatedresponses"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
	"github.com/tidwall/gjson"
)

// TestDriverExecutesAllCopiedNonStreamProtocols verifies network execution preserves each copied response path.
// TestDriverExecutesAllCopiedNonStreamProtocols 验证网络执行保留每个复制响应路径。
func TestDriverExecutesAllCopiedNonStreamProtocols(t *testing.T) {
	// cases defines the exact request and response behavior inherited from each upstream executor.
	// cases 定义从每个上游执行器继承的精确请求和响应行为。
	cases := []struct {
		name                   string
		profile                protocolCase
		response               string
		contentType            string
		forceTranslationStream bool
		forceUpstreamStream    bool
		wantText               string
		wantStatus             vcp.ResponseStatus
	}{
		{
			name: "claude", profile: protocolCase{id: messages.ProfileID, descriptor: messages.Profile(), requestField: "stream", requestValue: "true"},
			forceTranslationStream: true, wantText: "ok", wantStatus: vcp.ResponseCompleted, contentType: "text/event-stream",
			response: "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"usage\":{\"input_tokens\":1,\"output_tokens\":0}}}\n" +
				"data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n" +
				"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"ok\"}}\n" +
				"data: {\"type\":\"content_block_stop\",\"index\":0}\n" +
				"data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":1}}\n" +
				"data: {\"type\":\"message_stop\"}\n",
		},
		{
			name: "codex", profile: protocolCase{id: codex.ProfileID, descriptor: codex.Profile(), requestField: "store", requestValue: "false"},
			forceTranslationStream: true, forceUpstreamStream: true, wantStatus: vcp.ResponseCompleted, contentType: "text/event-stream",
			response: "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"status\":\"completed\",\"output\":[]}}\n\n",
		},
		{
			name: "interactions", profile: protocolCase{id: interactions.ProfileID, descriptor: interactions.Profile(), requestField: "input.0.type", requestValue: "user_input"},
			wantText: "ok", wantStatus: vcp.ResponseCompleted, contentType: "application/json",
			response: `{"id":"interaction_1","object":"interaction","status":"completed","steps":[{"type":"model_output","content":[{"text":"ok"}]}],"usage":{"input_tokens":1,"output_tokens":2,"total_tokens":3}}`,
		},
		{
			name: "antigravity", profile: protocolCase{id: antigravity.ProfileID, descriptor: antigravity.Profile(), requestField: "project", requestValue: ""},
			wantText: "ok", wantStatus: vcp.ResponseCompleted, contentType: "application/json",
			response: `{"response":{"responseId":"response_1","candidates":[{"content":{"role":"model","parts":[{"text":"ok"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":1,"candidatesTokenCount":1,"totalTokenCount":2}}}`,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			// server validates copied request output before returning the matching upstream fixture.
			// server 在返回对应上游夹具前校验复制请求输出。
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				rawRequest, errRead := io.ReadAll(request.Body)
				if errRead != nil {
					t.Errorf("read request: %v", errRead)
				}
				if authorization := request.Header.Get("Authorization"); authorization != "Bearer test-secret" {
					t.Errorf("Authorization = %q", authorization)
				}
				if got := gjson.GetBytes(rawRequest, testCase.profile.requestField).String(); got != testCase.profile.requestValue {
					t.Errorf("request %s = %q, want %q: %s", testCase.profile.requestField, got, testCase.profile.requestValue, rawRequest)
				}
				writer.Header().Set("Content-Type", testCase.contentType)
				_, _ = io.WriteString(writer, testCase.response)
			}))
			defer server.Close()

			// client resolves the fixture secret through the same production transport boundary.
			// client 通过相同生产传输边界解析夹具 Secret。
			client, secretReference := translatedTestClient(t)
			// driver uses a shared path because the table validates protocol translation rather than provider URL selection.
			// driver 使用共享路径，因为表格验证协议转换而不是供应商 URL 选择。
			driver, errDriver := translateddriver.NewDriver(translateddriver.Configuration{
				DefinitionID: "definition-1", Profile: testCase.profile.descriptor, Client: client, Capabilities: translatedCapabilities(),
				Path: "/execute", StreamPath: "/execute", Headers: []transport.Header{{Name: "Content-Type", Value: "application/json"}},
				Authentication: transport.Authentication{Mode: transport.AuthenticationBearer}, AllowedAuthMethods: []providerconfig.AuthMethodType{providerconfig.AuthMethodAPIKey},
				StreamInputMode: translateddriver.StreamInputLine, ForceTranslationStream: testCase.forceTranslationStream, ForceUpstreamStream: testCase.forceUpstreamStream,
			})
			if errDriver != nil {
				t.Fatalf("NewDriver() error = %v", errDriver)
			}
			// execution binds the request to the exact table profile and test server endpoint.
			// execution 将请求绑定到精确表格 Profile 和测试服务器 Endpoint。
			execution := translatedExecution(server.URL, secretReference, testCase.profile.id, false)
			result, errExecute := driver.Execute(context.Background(), execution)
			if errExecute != nil {
				t.Fatalf("Execute() error = %v", errExecute)
			}
			if result.Response.Status != testCase.wantStatus {
				t.Fatalf("response status = %q, want %q", result.Response.Status, testCase.wantStatus)
			}
			if testCase.wantText != "" && (len(result.Response.Items) == 0 || len(result.Response.Items[0].Content) == 0 || result.Response.Items[0].Content[0].Text != testCase.wantText) {
				t.Fatalf("response = %#v, want text %q", result.Response, testCase.wantText)
			}
		})
	}
}

// protocolCase contains the stable descriptor and one copied request assertion.
// protocolCase 包含稳定描述符及一项复制请求断言。
type protocolCase struct {
	// id is the stable Vulcan protocol profile identifier.
	// id 是稳定的 Vulcan 协议 Profile 标识。
	id string
	// descriptor selects the exact copied CLIProxyAPI translator.
	// descriptor 选择精确的复制 CLIProxyAPI 转换器。
	descriptor protocolbridge.Profile
	// requestField is the copied request field inspected by the test.
	// requestField 是测试检查的复制请求字段。
	requestField string
	// requestValue is the exact expected copied wire value.
	// requestValue 是精确预期的复制 wire 值。
	requestValue string
}

// translatedTestClient creates the production transport and one stored test secret.
// translatedTestClient 创建生产传输和一个已存储测试 Secret。
func translatedTestClient(t *testing.T) (*transport.Client, string) {
	t.Helper()
	// secretStore owns the isolated plaintext fixture behind the production resolver interface.
	// secretStore 在生产解析器接口后管理隔离的明文夹具。
	secretStore := secret.NewMemoryStore()
	secretReference, errPut := secretStore.Put(context.Background(), []byte("test-secret"))
	if errPut != nil {
		t.Fatalf("Put() error = %v", errPut)
	}
	client, errClient := transport.NewClient(http.DefaultClient, secretStore, transport.RetryPolicy{})
	if errClient != nil {
		t.Fatalf("NewClient() error = %v", errClient)
	}
	return client, secretReference
}

// translatedExecution returns one complete immutable execution fixture for the supplied profile.
// translatedExecution 返回给定 Profile 对应的完整不可变执行夹具。
func translatedExecution(baseURL string, secretReference string, profileID string, stream bool) provider.ExecutionRequest {
	// now is shared across projection and response event generation.
	// now 在投影和响应事件生成之间共享。
	now := time.Date(2026, time.July, 18, 0, 0, 0, 0, time.UTC)
	return provider.ExecutionRequest{
		Binding: transport.Binding{
			Target: resolve.Target{
				ProviderDefinitionID: "definition-1", ProviderInstanceID: "instance-1", ChannelID: "channel-1", EndpointID: "endpoint-1", CredentialID: "credential-1",
				ProviderModelID: "model-1", OfferingID: "offering-1", ExecutionProfileID: profileID, UpstreamModelID: "model-test", CatalogRevision: 1,
			},
			Endpoint:   providerconfig.Endpoint{ID: "endpoint-1", ProviderInstanceID: "instance-1", ChannelID: "channel-1", BaseURL: baseURL, Status: providerconfig.EndpointReady},
			Credential: providerconfig.Credential{ID: "credential-1", ProviderInstanceID: "instance-1", AuthMethodID: "api-key", SecretRef: secretReference, Status: providerconfig.CredentialActive},
		},
		Definition: providerconfig.ProviderDefinition{ID: "definition-1", Kind: providerconfig.DefinitionKindSystem, AuthMethods: []providerconfig.AuthMethodDefinition{{ID: "api-key", Type: providerconfig.AuthMethodAPIKey}}, Channels: []providerconfig.ProviderChannel{{ID: "channel-1", ProtocolProfileID: profileID, AuthMethodIDs: []string{"api-key"}, RuntimeReady: true}}},
		Request: vcp.VulcanRequest{
			ProtocolVersion: vcp.ProtocolVersion, RequestID: "request-1", Stream: stream,
			ModelSelection: vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: "instance-1", ProviderModelID: "model-1", ExecutionProfileID: profileID},
			Context: []vcp.ContextItem{{
				ItemID: "user-item-1", Sequence: 1, Kind: vcp.ContextMessage, Authority: vcp.AuthorityUser, Actor: vcp.ActorEndUser,
				Placement: vcp.PlacementTranscript, Activation: vcp.Activation{Mode: vcp.ActivationRequestStart}, Visibility: vcp.VisibilityModel,
				Content: []vcp.ContentBlock{{Type: vcp.ContentText, Text: "Hello"}}, Message: &vcp.MessageItem{},
			}},
			CachePolicy:             vcp.CachePolicy{Strategy: vcp.CacheRegular, OnUnsupported: vcp.CacheUnsupportedReject},
			ContextManagementPolicy: vcp.ContextManagementPolicy{Mode: vcp.ContextManagementRegular},
			CapabilityPolicy:        vcp.CapabilityPolicy{ExecutionMode: vcp.CapabilityMaximize, OptionalOnUnsupported: vcp.OptionalOmit},
		},
		LineageID: "lineage-1", Now: now,
	}
}

// translatedCapabilities returns the verified capability fixture shared by protocol driver tests.
// translatedCapabilities 返回协议驱动测试共享的已验证能力夹具。
func translatedCapabilities() openairesponses.ProfileCapabilities {
	return openairesponses.ProfileCapabilities{
		NativeSystemPreamble: true, NativeDeveloper: true, NativeInlineSystem: true, StructuredTools: true, NativeCustomTools: true,
		NativeToolNamespaces: true, ParallelTools: true, StreamingToolArguments: true, StrictJSONSchema: true, Reasoning: true,
		ReasoningContinuation: true, NativeWebSearch: true,
	}
}
