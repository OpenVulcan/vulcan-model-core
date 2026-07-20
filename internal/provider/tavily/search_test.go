package tavily

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestSearchDriverPreservesStructuredResults verifies endpoint, authentication, filters, order, score, and usage.
// TestSearchDriverPreservesStructuredResults 验证入口、认证、过滤器、顺序、分数和用量。
func TestSearchDriverPreservesStructuredResults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/search" || request.Header.Get("Authorization") != "Bearer test-secret" {
			t.Errorf("request = %s %s authorization=%q", request.Method, request.URL.Path, request.Header.Get("Authorization"))
		}
		var upstream tavilySearchRequest
		if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil {
			t.Errorf("decode request: %v", errDecode)
		}
		if upstream.Query != "Vulcan" || upstream.SearchDepth != "basic" || upstream.MaxResults == nil || *upstream.MaxResults != 2 || len(upstream.IncludeDomains) != 1 || upstream.IncludeDomains[0] != "example.com" || upstream.IncludeAnswer || upstream.IncludeRawContent || !upstream.IncludeUsage {
			t.Errorf("upstream request = %#v", upstream)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"query":"Vulcan","request_id":"req-search","results":[{"title":"First","url":"https://example.com/first","content":"one","score":0.91},{"title":"Second","url":"https://docs.example.org/second","content":"two","score":0.72}],"usage":{"credits":1}}`)
	}))
	defer server.Close()

	maxResults := 2
	execution := tavilyExecution(t, server.URL)
	execution.Execution.Payload.SearchWeb = &vcp.WebSearchOperation{Query: "Vulcan", Domains: vcp.DomainFilter{Allow: []string{"example.com"}}, MaxResults: &maxResults, OutputMode: vcp.WebSearchOutputResults, EvidenceRequirement: vcp.SearchEvidenceVerified}
	client, secretReference := tavilyTransportClient(t)
	execution.Binding.Credential.SecretRef = secretReference
	driver, errDriver := NewSearchDriver("definition-tavily", client)
	if errDriver != nil {
		t.Fatalf("NewSearchDriver() error = %v", errDriver)
	}
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if result.UpstreamResponseID != "req-search" || result.Search == nil || result.Search.Evidence.Status != vcp.SearchExecutionConfirmed || len(result.Search.Results) != 2 || result.Search.Results[0].Rank != 1 || result.Search.Results[0].SourceDomain != "example.com" || result.Search.Results[0].ProviderScore == nil || *result.Search.Results[0].ProviderScore != 0.91 || result.Search.Usage == nil || result.Search.Usage.ServiceUnits == nil || *result.Search.Usage.ServiceUnits != 1 || result.Search.Usage.ServiceUnit != "credits" {
		t.Fatalf("result = %#v", result)
	}
}

// tavilyTransportClient creates a target-bound client with a protected fixture key.
// tavilyTransportClient 使用受保护夹具 Key 创建 Target 绑定客户端。
func tavilyTransportClient(t *testing.T) (*transport.Client, string) {
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
	return client, secretReference
}

// tavilyExecution creates one exact service action request with immutable provider ownership.
// tavilyExecution 创建一个具有不可变供应商所有权的精确服务动作请求。
func tavilyExecution(t *testing.T, baseURL string) provider.ExecutionRequest {
	t.Helper()
	now := time.Date(2026, time.July, 20, 0, 0, 0, 0, time.UTC)
	action := providerconfig.ProviderActionBinding{ID: ActionBindingID, Operation: vcp.OperationSearchWeb, DriverID: "tavily", DriverVersion: "1", ProtocolProfileID: ProtocolProfileID, EndpointProfileID: "tavily_search", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, Search: &providerconfig.SearchActionBinding{BackendKind: vcp.SearchBackendDirectAPI}, Revision: 1}
	definition := providerconfig.ProviderDefinition{ID: "definition-tavily", Kind: providerconfig.DefinitionKindSystem, ProtocolProfileID: ProtocolProfileID, AuthMethodIDs: []string{"api_key"}, RuntimeReady: true, AuthMethods: []providerconfig.AuthMethodDefinition{{ID: "api_key", Type: providerconfig.AuthMethodAPIKey}}, ActionBindings: []providerconfig.ProviderActionBinding{action}, Revision: 1}
	target := resolve.Target{SubjectKind: resolve.ExecutionSubjectService, ProviderDefinitionID: definition.ID, ProviderInstanceID: "instance-tavily", ChannelID: ProtocolProfileID, EndpointID: "endpoint-tavily", CredentialID: "credential-tavily", ProviderServiceID: "service-web-search", ServiceOfferingID: "offering-tavily", ExecutionProfileID: "profile-tavily", UpstreamServiceID: "tavily-search", Operation: vcp.OperationSearchWeb, ActionBindingID: ActionBindingID, CatalogRevision: 1}
	request := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request-tavily", Target: vcp.TargetSelection{Service: &vcp.ServiceSelection{ProviderInstanceID: target.ProviderInstanceID, ProviderServiceID: target.ProviderServiceID, ServiceOfferingID: target.ServiceOfferingID, ExecutionProfileID: target.ExecutionProfileID}}, Operation: vcp.OperationSearchWeb, Payload: vcp.OperationPayload{}}
	return provider.ExecutionRequest{Binding: transport.Binding{Target: target, Endpoint: providerconfig.Endpoint{ID: target.EndpointID, ProviderInstanceID: target.ProviderInstanceID, ChannelID: target.ChannelID, BaseURL: baseURL, Status: providerconfig.EndpointReady}, Credential: providerconfig.Credential{ID: target.CredentialID, ProviderInstanceID: target.ProviderInstanceID, AuthMethodID: "api_key", SecretRef: "secret-reference", Status: providerconfig.CredentialActive}}, Definition: definition, Execution: &request, LineageID: "lineage-tavily", Now: now}
}
