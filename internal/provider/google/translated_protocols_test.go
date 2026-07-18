package google

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	protocolantigravity "github.com/OpenVulcan/vulcan-model-core/internal/protocol/google/antigravity"
	protocolinteractions "github.com/OpenVulcan/vulcan-model-core/internal/protocol/google/interactions"
	openairesponses "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/responses"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
	"github.com/tidwall/gjson"
)

// TestInteractionsDriverUsesNativeEndpointAndRevision verifies copied Gemini executor endpoint and revision behavior.
// TestInteractionsDriverUsesNativeEndpointAndRevision 验证复制的 Gemini 执行器端点和修订版本行为。
func TestInteractionsDriverUsesNativeEndpointAndRevision(t *testing.T) {
	// server validates the exact native Interactions request boundary.
	// server 校验精确的原生 Interactions 请求边界。
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1beta/interactions" {
			t.Errorf("path = %q", request.URL.Path)
		}
		if revision := request.Header.Get("Api-Revision"); revision != interactionsAPIRevision {
			t.Errorf("Api-Revision = %q", revision)
		}
		if key := request.Header.Get("X-Goog-Api-Key"); key != "test-secret" {
			t.Errorf("X-Goog-Api-Key = %q", key)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"id":"interaction_1","object":"interaction","status":"completed","steps":[{"type":"model_output","content":[{"text":"ok"}]}]}`)
	}))
	defer server.Close()
	// fixtureDriver supplies the production transport already bound to the test secret store.
	// fixtureDriver 提供已经绑定测试 Secret 存储的生产传输。
	fixtureDriver, execution := newAIStudioDriverExecution(t, server.URL, false)
	driver, errDriver := NewInteractionsDriver("definition-1", fixtureDriver.client, translatedGoogleCapabilities())
	if errDriver != nil {
		t.Fatalf("NewInteractionsDriver() error = %v", errDriver)
	}
	setGoogleTranslatedProfile(&execution, protocolinteractions.ProfileID, providerconfig.AuthMethodAPIKey)
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if result.Response.Status != vcp.ResponseCompleted || len(result.Response.Items) == 0 || result.Response.Items[0].Content[0].Text != "ok" {
		t.Fatalf("result = %#v", result)
	}
}

// TestAntigravityDriverSetsProjectEnvelope verifies the copied internal endpoint receives the unique credential project scope.
// TestAntigravityDriverSetsProjectEnvelope 验证复制的内部端点接收唯一凭据项目作用域。
func TestAntigravityDriverSetsProjectEnvelope(t *testing.T) {
	// server validates the Antigravity project and model envelope without inspecting canonical prompt data.
	// server 校验 Antigravity 项目与模型信封且不检查规范 Prompt 数据。
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1internal:generateContent" {
			t.Errorf("path = %q", request.URL.Path)
		}
		if authorization := request.Header.Get("Authorization"); authorization != "Bearer test-secret" {
			t.Errorf("Authorization = %q", authorization)
		}
		if userAgent := request.Header.Get("User-Agent"); userAgent != "antigravity/hub/2.2.1 darwin/arm64" {
			t.Errorf("User-Agent = %q", userAgent)
		}
		rawRequest, errRead := io.ReadAll(request.Body)
		if errRead != nil {
			t.Errorf("read request: %v", errRead)
		}
		if projectID := gjson.GetBytes(rawRequest, "project").String(); projectID != "project-1" {
			t.Errorf("project = %q; request=%s", projectID, rawRequest)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"response":{"responseId":"response_1","candidates":[{"content":{"role":"model","parts":[{"text":"ok"}]},"finishReason":"STOP"}]}}`)
	}))
	defer server.Close()
	// fixtureDriver supplies the production transport already bound to the test secret store.
	// fixtureDriver 提供已经绑定测试 Secret 存储的生产传输。
	fixtureDriver, execution := newAIStudioDriverExecution(t, server.URL, false)
	driver, errDriver := NewAntigravityDriver("definition-1", fixtureDriver.client, translatedGoogleCapabilities())
	if errDriver != nil {
		t.Fatalf("NewAntigravityDriver() error = %v", errDriver)
	}
	setGoogleTranslatedProfile(&execution, protocolantigravity.ProfileID, providerconfig.AuthMethodBearer)
	execution.Binding.Credential.ScopeRefs = []providerconfig.ScopeReference{{Kind: "project", ID: "project-1"}}
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if result.Response.Status != vcp.ResponseCompleted {
		t.Fatalf("result = %#v", result)
	}
}

// setGoogleTranslatedProfile retargets the shared exact fixture to one translated Google protocol.
// setGoogleTranslatedProfile 将共享精确夹具重新绑定到一个转换 Google 协议。
func setGoogleTranslatedProfile(execution *provider.ExecutionRequest, profileID string, authType providerconfig.AuthMethodType) {
	execution.Binding.Target.ExecutionProfileID = profileID
	execution.Request.ModelSelection.ExecutionProfileID = profileID
	execution.Definition.AuthMethods[0].Type = authType
	execution.Definition.ProtocolProfileID = profileID
}

// translatedGoogleCapabilities returns verified capabilities used only by isolated driver tests.
// translatedGoogleCapabilities 返回仅供隔离驱动测试使用的已验证能力。
func translatedGoogleCapabilities() openairesponses.ProfileCapabilities {
	return openairesponses.ProfileCapabilities{NativeSystemPreamble: true, NativeDeveloper: true, StructuredTools: true, ParallelTools: true, StreamingToolArguments: true, StrictJSONSchema: true, Reasoning: true}
}
