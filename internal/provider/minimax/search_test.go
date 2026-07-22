package minimax

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

// TestSearchDriverAcceptsProviderDatetimeMetadata verifies the live MiniMax date shape cannot invalidate otherwise successful results.
// TestSearchDriverAcceptsProviderDatetimeMetadata 验证 MiniMax 真实日期形态不会使其他方面成功的结果失效。
func TestSearchDriverAcceptsProviderDatetimeMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/coding_plan/search" || request.Header.Get("Authorization") != "Bearer test-secret" {
			t.Errorf("request = %s %s authorization=%q", request.Method, request.URL.Path, request.Header.Get("Authorization"))
		}
		var upstream searchRequest
		if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil || upstream.Query != "Vulcan" {
			t.Errorf("upstream request = %#v, error = %v", upstream, errDecode)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"organic":[{"title":"First","link":"https://example.com/first","snippet":"one","date":"2026-07-21 11:51:10"},{"title":"Legacy HTTP","link":"http://legacy.example.org/result","snippet":"two","date":"2026-07-21 10:00:00"}],"base_resp":{"status_code":0,"status_msg":"success"}}`)
	}))
	defer server.Close()

	driver, execution := newMiniMaxSearchExecution(t, server.URL)
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if result.Search == nil || len(result.Search.Results) != 2 || result.Search.Results[0].URL != "https://example.com/first" || result.Search.Results[0].PublishedAt != nil || result.Search.Results[1].URL != "http://legacy.example.org/result" || result.Search.Results[1].SourceDomain != "legacy.example.org" {
		t.Fatalf("result = %#v", result)
	}
}

// TestSearchDriverRejectsProviderApplicationFailure verifies HTTP success cannot hide a MiniMax application error.
// TestSearchDriverRejectsProviderApplicationFailure 验证 HTTP 成功不能掩盖 MiniMax 应用层错误。
func TestSearchDriverRejectsProviderApplicationFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"organic":[],"base_resp":{"status_code":1004,"status_msg":"invalid request"}}`)
	}))
	defer server.Close()

	driver, execution := newMiniMaxSearchExecution(t, server.URL)
	if _, errExecute := driver.Execute(context.Background(), execution); errExecute == nil {
		t.Fatal("expected provider application failure")
	}
}

// newMiniMaxSearchExecution builds one exact MiniMax service-search execution fixture.
// newMiniMaxSearchExecution 构建一个精确的 MiniMax 服务搜索执行夹具。
func newMiniMaxSearchExecution(t *testing.T, baseURL string) (*SearchDriver, provider.ExecutionRequest) {
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
	driver, errDriver := NewSearchDriver("definition-minimax", client)
	if errDriver != nil {
		t.Fatalf("NewSearchDriver() error = %v", errDriver)
	}
	action := providerconfig.ProviderActionBinding{ID: SearchWebActionBindingID, Operation: vcp.OperationSearchWeb, DriverID: "minimax", DriverVersion: "1", ProtocolProfileID: SearchWebProtocolProfileID, EndpointProfileID: "minimax_search", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, Search: &providerconfig.SearchActionBinding{BackendKind: vcp.SearchBackendDirectAPI}, Revision: 1}
	definition := providerconfig.ProviderDefinition{ID: "definition-minimax", Kind: providerconfig.DefinitionKindSystem, ProtocolProfileID: SearchWebProtocolProfileID, AuthMethodIDs: []string{"api_key"}, RuntimeReady: true, AuthMethods: []providerconfig.AuthMethodDefinition{{ID: "api_key", Type: providerconfig.AuthMethodAPIKey}}, ActionBindings: []providerconfig.ProviderActionBinding{action}, Revision: 1}
	target := resolve.Target{SubjectKind: resolve.ExecutionSubjectService, ProviderDefinitionID: definition.ID, ProviderInstanceID: "instance-minimax", ChannelID: SearchWebProtocolProfileID, EndpointID: "endpoint-minimax", CredentialID: "credential-minimax", ProviderServiceID: "service-web-search", ServiceOfferingID: "offering-minimax-search", ExecutionProfileID: "profile-minimax-search", UpstreamServiceID: "minimax-coding-plan-search", Operation: vcp.OperationSearchWeb, ActionBindingID: SearchWebActionBindingID, CatalogRevision: 1}
	request := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request-minimax-search", Target: vcp.TargetSelection{Service: &vcp.ServiceSelection{ProviderInstanceID: target.ProviderInstanceID, ProviderServiceID: target.ProviderServiceID, ServiceOfferingID: target.ServiceOfferingID, ExecutionProfileID: target.ExecutionProfileID}}, Operation: vcp.OperationSearchWeb, Payload: vcp.OperationPayload{SearchWeb: &vcp.WebSearchOperation{Query: "Vulcan", OutputMode: vcp.WebSearchOutputResults, EvidenceRequirement: vcp.SearchEvidenceVerified}}}
	execution := provider.ExecutionRequest{Binding: transport.Binding{Target: target, Endpoint: providerconfig.Endpoint{ID: target.EndpointID, ProviderInstanceID: target.ProviderInstanceID, ChannelID: target.ChannelID, BaseURL: baseURL, Status: providerconfig.EndpointReady}, Credential: providerconfig.Credential{ID: target.CredentialID, ProviderInstanceID: target.ProviderInstanceID, AuthMethodID: "api_key", SecretRef: secretReference, Status: providerconfig.CredentialActive}}, Definition: definition, Execution: &request, LineageID: "lineage-minimax-search", Now: time.Date(2026, time.July, 22, 0, 0, 0, 0, time.UTC)}
	return driver, execution
}
