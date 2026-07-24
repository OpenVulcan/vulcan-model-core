package alibaba

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestWebSearchActionDriverCopiesMCPFlow verifies the exact copied initialization, session, notification, and tool-call sequence.
// TestWebSearchActionDriverCopiesMCPFlow 验证精确复制的初始化、会话、通知及工具调用顺序。
func TestWebSearchActionDriverCopiesMCPFlow(t *testing.T) {
	var requestCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		currentRequest := requestCount.Add(1)
		if request.Method != http.MethodPost || request.URL.Path != webSearchMCPPath || request.Header.Get("Authorization") != "Bearer test-secret" || request.Header.Get("Accept") != "application/json, text/event-stream" {
			t.Errorf("request %d = %s %s authorization=%q accept=%q", currentRequest, request.Method, request.URL.Path, request.Header.Get("Authorization"), request.Header.Get("Accept"))
		}
		switch currentRequest {
		case 1:
			var initialize mcpInitializeRequest
			if errDecode := json.NewDecoder(request.Body).Decode(&initialize); errDecode != nil || initialize.JSONRPC != "2.0" || initialize.ID != 1 || initialize.Method != "initialize" || initialize.Params.ProtocolVersion != webSearchMCPProtocolVersion || initialize.Params.ClientInfo.Name != "VulcanModelRouter" {
				t.Errorf("initialize = %#v, error = %v", initialize, errDecode)
			}
			writer.Header().Set("Mcp-Session-Id", "session-one")
			writer.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(writer, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","capabilities":{},"serverInfo":{"name":"WebSearch","version":"1"}}}`)
		case 2:
			if request.Header.Get("Mcp-Session-Id") != "session-one" {
				t.Errorf("notification session = %q", request.Header.Get("Mcp-Session-Id"))
			}
			var notification mcpInitializedNotification
			if errDecode := json.NewDecoder(request.Body).Decode(&notification); errDecode != nil || notification.JSONRPC != "2.0" || notification.Method != "notifications/initialized" {
				t.Errorf("notification = %#v, error = %v", notification, errDecode)
			}
			writer.WriteHeader(http.StatusAccepted)
		case 3:
			if request.Header.Get("Mcp-Session-Id") != "session-one" {
				t.Errorf("tool session = %q", request.Header.Get("Mcp-Session-Id"))
			}
			var call mcpToolCallRequest
			if errDecode := json.NewDecoder(request.Body).Decode(&call); errDecode != nil || call.JSONRPC != "2.0" || call.ID != 2 || call.Method != "tools/call" || call.Params.Name != webSearchMCPToolName || call.Params.Arguments.Query != "Vulcan" || call.Params.Arguments.Count == nil || *call.Params.Arguments.Count != 1 {
				t.Errorf("call = %#v, error = %v", call, errDecode)
			}
			writer.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(writer, `{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"{\"pages\":[{\"title\":\"First\",\"url\":\"https://Example.com/first\",\"snippet\":\"one\",\"hostname\":\"untrusted.example\"},{\"title\":\"Second\",\"url\":\"https://second.example/result\",\"snippet\":\"two\"}]}"}]}}`)
		default:
			t.Errorf("unexpected request %d", currentRequest)
			writer.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	driver, execution := newAlibabaWebSearchExecution(t, server.URL)
	maximumResults := 1
	execution.Execution.Payload.SearchWeb.MaxResults = &maximumResults
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if requestCount.Load() != 3 || result.Search == nil || result.Search.Query != "Vulcan" || result.Search.Evidence.Status != vcp.SearchExecutionConfirmed || len(result.Search.Results) != 1 || result.Search.Results[0].URL != "https://Example.com/first" || result.Search.Results[0].SourceDomain != "example.com" || result.Search.Results[0].Rank != 1 {
		t.Fatalf("request count = %d, result = %#v", requestCount.Load(), result)
	}
}

// TestWebSearchActionDriverRejectsUnsupportedFiltersBeforeNetwork verifies MCP never receives unsupported policy fields.
// TestWebSearchActionDriverRejectsUnsupportedFiltersBeforeNetwork 验证 MCP 绝不会收到不受支持的策略字段。
func TestWebSearchActionDriverRejectsUnsupportedFiltersBeforeNetwork(t *testing.T) {
	var requestCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requestCount.Add(1)
		writer.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	driver, execution := newAlibabaWebSearchExecution(t, server.URL)
	execution.Execution.Payload.SearchWeb.Domains.Allow = []string{"example.com"}
	if _, errExecute := driver.Execute(context.Background(), execution); errExecute == nil || !strings.Contains(errExecute.Error(), "supports query and max_results only") {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if requestCount.Load() != 0 {
		t.Fatalf("network request count = %d, want 0", requestCount.Load())
	}
}

// TestDecodeWebSearchToolResultRejectsInvalidProviderURL verifies untrusted MCP page URLs cannot escape the resource boundary.
// TestDecodeWebSearchToolResultRejectsInvalidProviderURL 验证不可信 MCP 页面 URL 无法越过资源边界。
func TestDecodeWebSearchToolResultRejectsInvalidProviderURL(t *testing.T) {
	operation := vcp.WebSearchOperation{Query: "Vulcan", OutputMode: vcp.WebSearchOutputResults, EvidenceRequirement: vcp.SearchEvidenceVerified}
	payload := json.RawMessage(`{"content":[{"type":"text","text":"{\"pages\":[{\"title\":\"Bad\",\"url\":\"file:///etc/passwd\"}]}"}]}`)
	if _, errDecode := decodeWebSearchToolResult(operation, payload); errDecode == nil || !strings.Contains(errDecode.Error(), "invalid HTTP URL") {
		t.Fatalf("decodeWebSearchToolResult() error = %v", errDecode)
	}
}

// newAlibabaWebSearchExecution builds one exact Alibaba service-search execution fixture.
// newAlibabaWebSearchExecution 构建一个精确 Alibaba 服务搜索执行夹具。
func newAlibabaWebSearchExecution(t *testing.T, baseURL string) (*WebSearchActionDriver, provider.ExecutionRequest) {
	t.Helper()
	secretStore := secret.NewMemoryStore()
	secretReference, errPut := secretStore.Put(context.Background(), []byte("test-secret"))
	if errPut != nil {
		t.Fatalf("Put() error = %v", errPut)
	}
	client, errClient := transport.NewClient(http.DefaultClient, secretStore, transport.RetryPolicy{})
	if errClient != nil {
		t.Fatalf("NewClient() error = %v", errClient)
	}
	driver, errDriver := NewWebSearchActionDriver("definition-alibaba", client)
	if errDriver != nil {
		t.Fatalf("NewWebSearchActionDriver() error = %v", errDriver)
	}
	action := providerconfig.ProviderActionBinding{ID: SearchWebActionBindingID, Operation: vcp.OperationSearchWeb, DriverID: "alibaba", DriverVersion: "1", ProtocolProfileID: SearchWebProtocolProfileID, EndpointProfileID: "alibaba_web_search_mcp", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, Search: &providerconfig.SearchActionBinding{BackendKind: vcp.SearchBackendDirectAPI}, Revision: 1}
	definition := providerconfig.ProviderDefinition{ID: "definition-alibaba", Kind: providerconfig.DefinitionKindSystem, ProtocolProfileID: SearchWebProtocolProfileID, AuthMethodIDs: []string{"api_key"}, RuntimeReady: true, AuthMethods: []providerconfig.AuthMethodDefinition{{ID: "api_key", Type: providerconfig.AuthMethodAPIKey}}, ActionBindings: []providerconfig.ProviderActionBinding{action}, Revision: 1}
	target := resolve.Target{SubjectKind: resolve.ExecutionSubjectService, ProviderDefinitionID: definition.ID, ProviderInstanceID: "instance-alibaba", ChannelID: SearchWebProtocolProfileID, EndpointID: "endpoint-alibaba", CredentialID: "credential-alibaba", ProviderServiceID: "service-web-search", ServiceOfferingID: "offering-alibaba-search", ExecutionProfileID: "profile-alibaba-search", UpstreamServiceID: webSearchMCPToolName, Operation: vcp.OperationSearchWeb, ActionBindingID: SearchWebActionBindingID, CatalogRevision: 1}
	request := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request-alibaba-search", Target: vcp.TargetSelection{Service: &vcp.ServiceSelection{ProviderInstanceID: target.ProviderInstanceID, ProviderServiceID: target.ProviderServiceID, ServiceOfferingID: target.ServiceOfferingID, ExecutionProfileID: target.ExecutionProfileID}}, Operation: vcp.OperationSearchWeb, Payload: vcp.OperationPayload{SearchWeb: &vcp.WebSearchOperation{Query: "Vulcan", OutputMode: vcp.WebSearchOutputResults, EvidenceRequirement: vcp.SearchEvidenceVerified}}}
	execution := provider.ExecutionRequest{Binding: transport.Binding{Target: target, Endpoint: providerconfig.Endpoint{ID: target.EndpointID, ProviderInstanceID: target.ProviderInstanceID, ChannelID: target.ChannelID, BaseURL: baseURL, Status: providerconfig.EndpointReady}, Credential: providerconfig.Credential{ID: target.CredentialID, ProviderInstanceID: target.ProviderInstanceID, AuthMethodID: "api_key", SecretRef: secretReference, Status: providerconfig.CredentialActive}}, Definition: definition, Execution: &request, LineageID: "lineage-alibaba-search", Now: time.Date(2026, time.July, 22, 0, 0, 0, 0, time.UTC)}
	return driver, execution
}
