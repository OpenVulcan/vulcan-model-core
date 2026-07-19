package anthropic

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	protocolmessages "github.com/OpenVulcan/vulcan-model-core/internal/protocol/anthropic/messages"
	openairesponses "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/responses"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
	"github.com/tidwall/gjson"
)

// TestMessagesDriverPreservesCopiedClaudeExecutionBoundary verifies forced SSE aggregation, beta headers, and API-key injection.
// TestMessagesDriverPreservesCopiedClaudeExecutionBoundary 验证强制 SSE 聚合、Beta Header 和 API Key 注入。
func TestMessagesDriverPreservesCopiedClaudeExecutionBoundary(t *testing.T) {
	// server validates the exact copied Claude endpoint and upstream stream request.
	// server 校验精确的复制 Claude 端点和上游流式请求。
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/messages" || request.URL.Query().Get("beta") != "true" {
			t.Errorf("request URL = %s", request.URL.String())
		}
		if key := request.Header.Get("x-api-key"); key != "test-secret" {
			t.Errorf("x-api-key = %q", key)
		}
		if version := request.Header.Get("Anthropic-Version"); version != "2023-06-01" {
			t.Errorf("Anthropic-Version = %q", version)
		}
		if betas := request.Header.Get("Anthropic-Beta"); betas != anthropicDefaultBetas {
			t.Errorf("Anthropic-Beta = %q", betas)
		}
		if request.Header.Get("X-Claude-Code-Session-Id") == "" || request.Header.Get("x-client-request-id") == "" {
			t.Errorf("Claude identity headers are incomplete: %v", request.Header)
		}
		if runtime := request.Header.Get("X-Stainless-Runtime"); runtime != "node" {
			t.Errorf("X-Stainless-Runtime = %q", runtime)
		}
		if dangerous := request.Header.Get("Anthropic-Dangerous-Direct-Browser-Access"); dangerous != "true" {
			t.Errorf("Anthropic-Dangerous-Direct-Browser-Access = %q", dangerous)
		}
		rawRequest, errRead := io.ReadAll(request.Body)
		if errRead != nil {
			t.Errorf("read request: %v", errRead)
		}
		if !gjson.GetBytes(rawRequest, "stream").Bool() {
			t.Errorf("Claude translated request must force stream: %s", rawRequest)
		}
		writer.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(writer,
			"data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"usage\":{\"input_tokens\":1,\"output_tokens\":0}}}\n"+
				"data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n"+
				"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"ok\"}}\n"+
				"data: {\"type\":\"content_block_stop\",\"index\":0}\n"+
				"data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":1}}\n"+
				"data: {\"type\":\"message_stop\"}\n")
	}))
	defer server.Close()
	// secretStore owns the isolated API-key fixture behind the production secret resolver.
	// secretStore 在生产 Secret 解析器后管理隔离 API Key 夹具。
	secretStore := secret.NewMemoryStore()
	secretReference, errPut := secretStore.Put(context.Background(), []byte("test-secret"))
	if errPut != nil {
		t.Fatalf("Put() error = %v", errPut)
	}
	client, errClient := transport.NewClient(http.DefaultClient, secretStore, transport.RetryPolicy{})
	if errClient != nil {
		t.Fatalf("NewClient() error = %v", errClient)
	}
	driver, errDriver := NewMessagesDriver("definition-1", client, anthropicTestCapabilities())
	if errDriver != nil {
		t.Fatalf("NewMessagesDriver() error = %v", errDriver)
	}
	// execution is a non-stream VCP request that must still use Claude SSE upstream.
	// execution 是一条仍必须在 Claude 上游使用 SSE 的非流式 VCP 请求。
	execution := anthropicTestExecution(server.URL, secretReference)
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if result.Response.Status != vcp.ResponseCompleted || len(result.Response.Items) == 0 || result.Response.Items[0].Content[0].Text != "ok" {
		t.Fatalf("result = %#v", result)
	}
}

// TestAdaptClaudeRequestHeadersKeepsBrowserHeaderAPIKeyOnly verifies Claude Code OAuth does not impersonate browser API-key mode.
// TestAdaptClaudeRequestHeadersKeepsBrowserHeaderAPIKeyOnly 验证 Claude Code OAuth 不会伪装成浏览器 API Key 模式。
func TestAdaptClaudeRequestHeadersKeepsBrowserHeaderAPIKeyOnly(t *testing.T) {
	execution := anthropicTestExecution("https://api.anthropic.com", "secret-reference")
	apiKeyRequest, errAPIKey := adaptClaudeRequestHeaders(execution, transport.Request{})
	if errAPIKey != nil {
		t.Fatalf("adaptClaudeRequestHeaders(API key) error = %v", errAPIKey)
	}
	if !requestHeaderEquals(apiKeyRequest.Headers, "Anthropic-Dangerous-Direct-Browser-Access", "true") {
		t.Fatalf("API-key headers = %#v", apiKeyRequest.Headers)
	}
	execution.Definition.AuthMethods[0].Type = providerconfig.AuthMethodOAuth
	oauthRequest, errOAuth := adaptClaudeRequestHeaders(execution, transport.Request{})
	if errOAuth != nil {
		t.Fatalf("adaptClaudeRequestHeaders(OAuth) error = %v", errOAuth)
	}
	if requestHeaderEquals(oauthRequest.Headers, "Anthropic-Dangerous-Direct-Browser-Access", "true") {
		t.Fatalf("OAuth headers = %#v", oauthRequest.Headers)
	}
}

// requestHeaderEquals reports whether one exact transport header has the expected value.
// requestHeaderEquals 判断一个精确 Transport Header 是否具有预期值。
func requestHeaderEquals(headers []transport.Header, name string, value string) bool {
	for _, header := range headers {
		if header.Name == name && header.Value == value {
			return true
		}
	}
	return false
}

// anthropicTestExecution returns one complete exact Anthropic execution fixture.
// anthropicTestExecution 返回一条完整精确的 Anthropic 执行夹具。
func anthropicTestExecution(baseURL string, secretReference string) provider.ExecutionRequest {
	return provider.ExecutionRequest{
		Binding: transport.Binding{
			Target: resolve.Target{
				ProviderDefinitionID: "definition-1", ProviderInstanceID: "instance-1", ChannelID: "channel-1", EndpointID: "endpoint-1", CredentialID: "credential-1",
				ProviderModelID: "model-1", OfferingID: "offering-1", ExecutionProfileID: protocolmessages.ProfileID, UpstreamModelID: "claude-test", CatalogRevision: 1,
			},
			Endpoint:   providerconfig.Endpoint{ID: "endpoint-1", ProviderInstanceID: "instance-1", ChannelID: "channel-1", BaseURL: baseURL, Status: providerconfig.EndpointReady},
			Credential: providerconfig.Credential{ID: "credential-1", ProviderInstanceID: "instance-1", AuthMethodID: "api-key", SecretRef: secretReference, Status: providerconfig.CredentialActive},
		},
		Definition: providerconfig.ProviderDefinition{ID: "definition-1", Kind: providerconfig.DefinitionKindSystem, ProtocolProfileID: protocolmessages.ProfileID, AuthMethodIDs: []string{"api-key"}, RuntimeReady: true, AuthMethods: []providerconfig.AuthMethodDefinition{{ID: "api-key", Type: providerconfig.AuthMethodAPIKey}}},
		Request: vcp.VulcanRequest{
			ProtocolVersion: vcp.ProtocolVersion, RequestID: "request-1",
			ModelSelection: vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: "instance-1", ProviderModelID: "model-1", ExecutionProfileID: protocolmessages.ProfileID},
			Context: []vcp.ContextItem{{
				ItemID: "user-item-1", Sequence: 1, Kind: vcp.ContextMessage, Authority: vcp.AuthorityUser, Actor: vcp.ActorEndUser,
				Placement: vcp.PlacementTranscript, Activation: vcp.Activation{Mode: vcp.ActivationRequestStart}, Visibility: vcp.VisibilityModel,
				Content: []vcp.ContentBlock{{Type: vcp.ContentText, Text: "Hello"}}, Message: &vcp.MessageItem{},
			}},
			CachePolicy:             vcp.CachePolicy{Strategy: vcp.CacheRegular, OnUnsupported: vcp.CacheUnsupportedReject},
			ContextManagementPolicy: vcp.ContextManagementPolicy{Mode: vcp.ContextManagementRegular},
			CapabilityPolicy:        vcp.CapabilityPolicy{ExecutionMode: vcp.CapabilityMaximize, OptionalOnUnsupported: vcp.OptionalOmit},
		},
		LineageID: "lineage-1", Now: time.Date(2026, time.July, 18, 0, 0, 0, 0, time.UTC),
	}
}

// anthropicTestCapabilities returns verified capabilities used by the isolated Anthropic driver test.
// anthropicTestCapabilities 返回隔离 Anthropic 驱动测试使用的已验证能力。
func anthropicTestCapabilities() openairesponses.ProfileCapabilities {
	return openairesponses.ProfileCapabilities{NativeSystemPreamble: true, StructuredTools: true, ParallelTools: true, StreamingToolArguments: true, StrictJSONSchema: true, Reasoning: true}
}
