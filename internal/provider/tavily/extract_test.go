package tavily

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestExtractDriverPreservesPartialResultsAndUsage verifies the documented request and complete typed response projection.
// TestExtractDriverPreservesPartialResultsAndUsage 校验文档化请求与完整类型化响应投影。
func TestExtractDriverPreservesPartialResultsAndUsage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/extract" || request.Header.Get("Authorization") != "Bearer test-secret" {
			t.Errorf("request = %s %s authorization=%q", request.Method, request.URL.Path, request.Header.Get("Authorization"))
		}
		var upstream tavilyExtractRequest
		if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil {
			t.Errorf("decode request: %v", errDecode)
		}
		if len(upstream.URLs) != 2 || upstream.Query != "router" || upstream.ChunksPerSource == nil || *upstream.ChunksPerSource != 2 || upstream.ExtractDepth != vcp.WebExtractDepthAdvanced || upstream.Format != vcp.WebExtractFormatText || !upstream.IncludeImages || !upstream.IncludeFavicon || upstream.Timeout == nil || *upstream.Timeout != 15 || !upstream.IncludeUsage {
			t.Errorf("upstream request = %#v", upstream)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"results":[{"url":"https://example.com/a","raw_content":"content","images":["https://example.com/image.png"],"favicon":"https://example.com/favicon.ico"}],"failed_results":[{"url":"https://example.org/b","error":"blocked"}],"response_time":1.25,"usage":{"credits":2},"request_id":"req-extract"}`)
	}))
	defer server.Close()

	execution := tavilyExecution(t, server.URL)
	execution.Binding.Target.Operation = vcp.OperationWebExtract
	execution.Binding.Target.ActionBindingID = ExtractActionBindingID
	execution.Binding.Target.ProviderServiceID = "service-web-extract"
	execution.Binding.Target.ServiceOfferingID = "offering-extract"
	execution.Binding.Target.ExecutionProfileID = "profile-extract"
	execution.Binding.Target.UpstreamServiceID = "tavily-extract"
	execution.Binding.Target.ChannelID = ExtractProtocolProfileID
	execution.Binding.Endpoint.ChannelID = ExtractProtocolProfileID
	execution.Definition.ProtocolProfileID = ProtocolProfileID
	execution.Definition.ActionBindings = []providerconfig.ProviderActionBinding{{ID: ExtractActionBindingID, Operation: vcp.OperationWebExtract, DriverID: "tavily", DriverVersion: "1", ProtocolProfileID: ExtractProtocolProfileID, EndpointProfileID: "tavily_search", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, Revision: 1}}
	execution.Execution.Operation = vcp.OperationWebExtract
	execution.Execution.Target.Service.ProviderServiceID = "service-web-extract"
	execution.Execution.Target.Service.ServiceOfferingID = "offering-extract"
	execution.Execution.Target.Service.ExecutionProfileID = "profile-extract"
	chunks := 2
	timeout := 15.0
	execution.Execution.Payload = vcp.OperationPayload{WebExtract: &vcp.WebExtractOperation{URLs: []string{"https://example.com/a", "https://example.org/b"}, Query: "router", ChunksPerSource: &chunks, Depth: vcp.WebExtractDepthAdvanced, Format: vcp.WebExtractFormatText, IncludeImages: true, IncludeFavicon: true, TimeoutSeconds: &timeout}}
	client, secretReference := tavilyTransportClient(t)
	execution.Binding.Credential.SecretRef = secretReference
	driver, errDriver := NewExtractDriver("definition-tavily", client)
	if errDriver != nil {
		t.Fatalf("NewExtractDriver() error = %v", errDriver)
	}
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if result.UpstreamResponseID != "req-extract" || result.Extract == nil || len(result.Extract.Results) != 1 || result.Extract.Results[0].RawContent != "content" || len(result.Extract.FailedResults) != 1 || result.Extract.FailedResults[0].Error != "blocked" || result.Extract.ResponseTimeSeconds == nil || *result.Extract.ResponseTimeSeconds != 1.25 || result.Extract.Usage == nil || result.Extract.Usage.ServiceUnits == nil || *result.Extract.Usage.ServiceUnits != 2 {
		t.Fatalf("result = %#v", result)
	}
}

// TestProjectExtractRequestAppliesDocumentedDefaults verifies omitted options have one deterministic upstream shape.
// TestProjectExtractRequestAppliesDocumentedDefaults 校验省略选项具有唯一确定的上游形态。
func TestProjectExtractRequestAppliesDocumentedDefaults(t *testing.T) {
	request, errProject := projectExtractRequest(vcp.WebExtractOperation{URLs: []string{"https://example.com"}})
	if errProject != nil {
		t.Fatalf("projectExtractRequest() error = %v", errProject)
	}
	if request.ExtractDepth != vcp.WebExtractDepthBasic || request.Format != vcp.WebExtractFormatMarkdown || !request.IncludeUsage {
		t.Fatalf("request = %#v", request)
	}
}
