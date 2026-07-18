package openai

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	protocolcodex "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/codex"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
	"github.com/tidwall/gjson"
)

// TestCodexDriverPreservesAlwaysStreamingExecution verifies copied Codex path, headers, and mandatory stream request behavior.
// TestCodexDriverPreservesAlwaysStreamingExecution 验证复制的 Codex 路径、Header 和强制流式请求行为。
func TestCodexDriverPreservesAlwaysStreamingExecution(t *testing.T) {
	// server validates that a non-stream VCP request still reaches Codex as Responses SSE.
	// server 校验非流式 VCP 请求仍以 Responses SSE 形式到达 Codex。
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/responses" {
			t.Errorf("path = %q", request.URL.Path)
		}
		if originator := request.Header.Get("Originator"); originator != "codex-tui" {
			t.Errorf("Originator = %q", originator)
		}
		if authorization := request.Header.Get("Authorization"); authorization != "Bearer test-secret" {
			t.Errorf("Authorization = %q", authorization)
		}
		rawRequest, errRead := io.ReadAll(request.Body)
		if errRead != nil {
			t.Errorf("read request: %v", errRead)
		}
		if !gjson.GetBytes(rawRequest, "stream").Bool() || gjson.GetBytes(rawRequest, "store").Bool() {
			t.Errorf("Codex request = %s", rawRequest)
		}
		writer.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(writer, "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"status\":\"completed\",\"output\":[]}}\n\n")
	}))
	defer server.Close()
	// fixtureDriver supplies the production transport bound to the shared test secret.
	// fixtureDriver 提供绑定共享测试 Secret 的生产传输。
	fixtureDriver, execution := newResponsesDriverExecution(t, server.URL, false)
	driver, errDriver := NewCodexDriver("definition-1", fixtureDriver.client, openAIResponsesCapabilities())
	if errDriver != nil {
		t.Fatalf("NewCodexDriver() error = %v", errDriver)
	}
	execution.Binding.Target.ExecutionProfileID = protocolcodex.ProfileID
	execution.Request.ModelSelection.ExecutionProfileID = protocolcodex.ProfileID
	execution.Definition.ProtocolProfileID = protocolcodex.ProfileID
	execution.Definition.AuthMethods[0].Type = providerconfig.AuthMethodAPIKey
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if result.Response.Status != vcp.ResponseCompleted || result.UpstreamResponseID != "resp_1" {
		t.Fatalf("result = %#v", result)
	}
}

// TestAdaptCodexRequestHeadersRequiresUniqueOAuthAccount verifies the copied non-API-key account boundary.
// TestAdaptCodexRequestHeadersRequiresUniqueOAuthAccount 验证复制的非 API Key 账号边界。
func TestAdaptCodexRequestHeadersRequiresUniqueOAuthAccount(t *testing.T) {
	// execution is the exact shared fixture retargeted to OAuth authentication.
	// execution 是重新绑定到 OAuth 认证的精确共享夹具。
	_, execution := newResponsesDriverExecution(t, "https://example.invalid", false)
	execution.Definition.AuthMethods[0].Type = providerconfig.AuthMethodOAuth
	execution.Binding.Credential.ScopeRefs = []providerconfig.ScopeReference{{Kind: "account", ID: "account-1"}}
	adapted, errAdapt := adaptCodexRequestHeaders(execution, transport.Request{})
	if errAdapt != nil {
		t.Fatalf("adaptCodexRequestHeaders() error = %v", errAdapt)
	}
	// accountHeader records the exact ChatGPT account header emitted by the adapter.
	// accountHeader 记录适配器发出的精确 ChatGPT 账号 Header。
	accountHeader := ""
	for _, header := range adapted.Headers {
		if header.Name == "Chatgpt-Account-Id" {
			accountHeader = header.Value
		}
	}
	if accountHeader != "account-1" {
		t.Fatalf("Chatgpt-Account-Id = %q", accountHeader)
	}
	execution.Binding.Credential.ScopeRefs = nil
	if _, errMissing := adaptCodexRequestHeaders(execution, transport.Request{}); errMissing == nil {
		t.Fatal("adaptCodexRequestHeaders() missing account error = nil")
	}
}
