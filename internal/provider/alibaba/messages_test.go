package alibaba

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	protocolmessages "github.com/OpenVulcan/vulcan-model-core/internal/protocol/anthropic/messages"
	openairesponses "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/responses"
	protocolbridge "github.com/OpenVulcan/vulcan-model-core/internal/protocol/translatedresponses"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
	"github.com/tidwall/gjson"
)

// TestAdaptMessagesBodyAppliesDocumentedAlibabaControls verifies recommendation defaults, explicit-limit rejection, and the closed tool-stream model set.
// TestAdaptMessagesBodyAppliesDocumentedAlibabaControls 验证推荐默认值、显式上限拒绝和封闭的工具流模型集合。
func TestAdaptMessagesBodyAppliesDocumentedAlibabaControls(t *testing.T) {
	execution := alibabaTestExecution("https://example.invalid/apps/anthropic/v1", "secret-reference")
	execution.Request.Stream = true
	execution.Request.Tools = []vcp.ToolDefinition{{Kind: vcp.ToolFunction, Name: "lookup", Parameters: json.RawMessage(`{"type":"object"}`)}}
	execution.Binding.Target.UpstreamModelID = "qwen3.7-plus"
	execution.Binding.Target.TokenLimits.MaxOutputTokens = catalog.OptionalTokenLimit{Known: true, Value: 16_384}
	execution.Binding.Target.TokenRecommendations.OutputTokens = catalog.OptionalTokenLimit{Known: true, Value: 8_192}

	adapted, errAdapt := adaptMessagesBody(execution, protocolbridge.ProjectedRequest{UpstreamJSON: []byte(`{"stream":true,"max_tokens":32000}`)})
	if errAdapt != nil {
		t.Fatalf("adaptMessagesBody() error = %v", errAdapt)
	}
	if got := gjson.GetBytes(adapted, "max_tokens").Int(); got != 8_192 {
		t.Fatalf("max_tokens = %d, want recommended 8192", got)
	}
	if !gjson.GetBytes(adapted, "tool_stream").Bool() {
		t.Fatalf("tool_stream was not enabled: %s", adapted)
	}

	execution.Request.Stream = false
	withoutStream, errWithoutStream := adaptMessagesBody(execution, protocolbridge.ProjectedRequest{UpstreamJSON: []byte(`{"stream":false,"max_tokens":32000}`)})
	if errWithoutStream != nil {
		t.Fatalf("adaptMessagesBody(non-stream) error = %v", errWithoutStream)
	}
	if gjson.GetBytes(withoutStream, "tool_stream").Exists() {
		t.Fatalf("non-stream body contains tool_stream: %s", withoutStream)
	}

	execution.Request.Stream = true
	execution.Request.Tools = nil
	withoutTools, errWithoutTools := adaptMessagesBody(execution, protocolbridge.ProjectedRequest{UpstreamJSON: []byte(`{"stream":true,"max_tokens":32000}`)})
	if errWithoutTools != nil {
		t.Fatalf("adaptMessagesBody(without tools) error = %v", errWithoutTools)
	}
	if gjson.GetBytes(withoutTools, "tool_stream").Exists() {
		t.Fatalf("tool-free body contains tool_stream: %s", withoutTools)
	}

	execution.Request.Tools = []vcp.ToolDefinition{{Kind: vcp.ToolFunction, Name: "lookup", Parameters: json.RawMessage(`{"type":"object"}`)}}
	execution.Binding.Target.UpstreamModelID = "kimi-k2.5"
	unsupported, errUnsupported := adaptMessagesBody(execution, protocolbridge.ProjectedRequest{UpstreamJSON: []byte(`{"stream":true,"max_tokens":32000}`)})
	if errUnsupported != nil {
		t.Fatalf("adaptMessagesBody(unsupported model) error = %v", errUnsupported)
	}
	if gjson.GetBytes(unsupported, "tool_stream").Exists() {
		t.Fatalf("unsupported model body contains tool_stream: %s", unsupported)
	}

	explicit := 12_000
	execution.Request.GenerationPolicy.MaxOutputTokens = &explicit
	preservedExplicit, errExplicit := adaptMessagesBody(execution, protocolbridge.ProjectedRequest{UpstreamJSON: []byte(`{"max_tokens":12000}`)})
	if errExplicit != nil {
		t.Fatalf("adaptMessagesBody(explicit output) error = %v", errExplicit)
	}
	if got := gjson.GetBytes(preservedExplicit, "max_tokens").Int(); got != 12_000 {
		t.Fatalf("explicit max_tokens = %d, want 12000", got)
	}
	explicit = 20_000
	if _, errLimit := adaptMessagesBody(execution, protocolbridge.ProjectedRequest{UpstreamJSON: []byte(`{"max_tokens":20000}`)}); errLimit == nil {
		t.Fatal("adaptMessagesBody() accepted explicit output tokens above the model maximum")
	}
}

// TestSupportsStreamingToolArgumentsUsesClosedOfficialAllowlist verifies every documented model and representative unsupported families.
// TestSupportsStreamingToolArgumentsUsesClosedOfficialAllowlist 验证每个已记录模型及代表性不支持模型族。
func TestSupportsStreamingToolArgumentsUsesClosedOfficialAllowlist(t *testing.T) {
	// expectations is deliberately exhaustive for the centralized provider allowlist.
	// expectations 对集中式供应商白名单进行刻意穷举。
	expectations := map[string]bool{
		"qwen3.7-max": true, "qwen3.7-plus": true, "qwen3.6-plus": true, "qwen3.6-flash": true, "qwen3.5-plus": true,
		"glm-5.2": true, "glm-5.1": true, "glm-5": true, "glm-4.7": true,
		"qwen3.8-max-preview": false, "deepseek-v4-pro": false, "kimi-k2.5": false, "MiniMax-M2.5": false,
	}
	for modelID, expected := range expectations {
		if actual := supportsStreamingToolArguments(modelID); actual != expected {
			t.Errorf("supportsStreamingToolArguments(%q) = %t, want %t", modelID, actual, expected)
		}
	}
}

// TestMessagesDriverUsesAlibabaBoundaryAndPreservesToolDeltas verifies the final path, minimal headers, API-key injection, and real upstream argument fragmentation.
// TestMessagesDriverUsesAlibabaBoundaryAndPreservesToolDeltas 验证最终路径、最小 Header、API Key 注入和真实上游参数分片。
func TestMessagesDriverUsesAlibabaBoundaryAndPreservesToolDeltas(t *testing.T) {
	// server captures the exact Alibaba-compatible request before returning two tool-argument deltas.
	// server 在返回两个工具参数增量前捕获精确的阿里云兼容请求。
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/apps/anthropic/v1/messages" {
			t.Errorf("request path = %q", request.URL.Path)
		}
		if key := request.Header.Get("x-api-key"); key != "test-secret" {
			t.Errorf("x-api-key = %q", key)
		}
		for _, forbidden := range []string{"Anthropic-Beta", "X-Claude-Code-Session-Id", "x-client-request-id", "X-Stainless-Runtime", "Anthropic-Dangerous-Direct-Browser-Access"} {
			if value := request.Header.Get(forbidden); value != "" {
				t.Errorf("forbidden header %s = %q", forbidden, value)
			}
		}
		rawRequest, errRead := io.ReadAll(request.Body)
		if errRead != nil {
			t.Errorf("read request: %v", errRead)
		}
		if !gjson.GetBytes(rawRequest, "stream").Bool() || !gjson.GetBytes(rawRequest, "tool_stream").Bool() {
			t.Errorf("stream controls = %s", rawRequest)
		}
		writer.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(writer,
			"data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"usage\":{\"input_tokens\":1,\"output_tokens\":0}}}\n"+
				"data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"tool_1\",\"name\":\"lookup\",\"input\":{}}}\n"+
				"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"city\\\":\"}}\n"+
				"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"\\\"Hangzhou\\\"}\"}}\n"+
				"data: {\"type\":\"content_block_stop\",\"index\":0}\n"+
				"data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":4}}\n"+
				"data: {\"type\":\"message_stop\"}\n")
	}))
	defer server.Close()

	secretStore := secret.NewMemoryStore()
	secretReference, errPut := secretStore.Put(context.Background(), []byte("test-secret"))
	if errPut != nil {
		t.Fatalf("Put() error = %v", errPut)
	}
	client, errClient := transport.NewClient(http.DefaultClient, secretStore, transport.RetryPolicy{})
	if errClient != nil {
		t.Fatalf("NewClient() error = %v", errClient)
	}
	driver, errDriver := NewMessagesDriver("definition-1", client, alibabaTestCapabilities())
	if errDriver != nil {
		t.Fatalf("NewMessagesDriver() error = %v", errDriver)
	}
	execution := alibabaTestExecution(server.URL+"/apps/anthropic/v1", secretReference)
	execution.Request.Stream = true
	execution.Request.Tools = []vcp.ToolDefinition{{Kind: vcp.ToolFunction, Name: "lookup", Parameters: json.RawMessage(`{"type":"object"}`)}}
	execution.Binding.Target.UpstreamModelID = "qwen3.7-plus"
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	argumentDeltas := 0
	for _, event := range result.Events {
		if event.Type == vcp.EventToolArgumentsDelta {
			argumentDeltas++
		}
	}
	if argumentDeltas != 2 {
		t.Fatalf("tool argument delta count = %d, want 2; events = %#v", argumentDeltas, result.Events)
	}
}

// alibabaTestExecution returns one isolated Alibaba execution fixture using the sole API-key method.
// alibabaTestExecution 返回仅使用 API Key 方式的一条隔离 Alibaba 执行夹具。
func alibabaTestExecution(baseURL string, secretReference string) provider.ExecutionRequest {
	return provider.ExecutionRequest{
		Binding: transport.Binding{
			Target: resolve.Target{
				ProviderDefinitionID: "definition-1", ProviderInstanceID: "instance-1", ChannelID: "channel-1", EndpointID: "endpoint-1", CredentialID: "credential-1",
				ProviderModelID: "model-1", OfferingID: "offering-1", ExecutionProfileID: protocolmessages.ProfileID, UpstreamModelID: "qwen3.7-plus", CatalogRevision: 1,
			},
			Endpoint:   providerconfig.Endpoint{ID: "endpoint-1", ProviderInstanceID: "instance-1", ChannelID: "channel-1", BaseURL: baseURL, Status: providerconfig.EndpointReady},
			Credential: providerconfig.Credential{ID: "credential-1", ProviderInstanceID: "instance-1", AuthMethodID: "api_key", SecretRef: secretReference, Status: providerconfig.CredentialActive},
		},
		Definition: providerconfig.ProviderDefinition{ID: "definition-1", Kind: providerconfig.DefinitionKindSystem, ProtocolProfileID: protocolmessages.ProfileID, AuthMethodIDs: []string{"api_key"}, RuntimeReady: true, AuthMethods: []providerconfig.AuthMethodDefinition{{ID: "api_key", Type: providerconfig.AuthMethodAPIKey}}},
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
		LineageID: "lineage-1", Now: time.Date(2026, time.July, 19, 0, 0, 0, 0, time.UTC),
	}
}

// alibabaTestCapabilities returns the documented translated Messages feature surface used by tests.
// alibabaTestCapabilities 返回测试使用且有文档依据的 Messages 转换能力面。
func alibabaTestCapabilities() openairesponses.ProfileCapabilities {
	return openairesponses.ProfileCapabilities{NativeSystemPreamble: true, StructuredTools: true, ParallelTools: true, StreamingToolArguments: true, StrictJSONSchema: true, Reasoning: true}
}
