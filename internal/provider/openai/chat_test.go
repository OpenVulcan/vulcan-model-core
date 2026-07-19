// Chat Driver fixtures cover target-bound HTTP/SSE behavior adapted from CLIProxyAPI commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// Chat Driver 夹具覆盖改编自 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66 的 Target 绑定 HTTP/SSE 行为。
// Source path: internal/runtime/executor/openai_compat_executor.go.
// 来源路径：internal/runtime/executor/openai_compat_executor.go。
// The fixtures verify the target-bound adaptation boundary without importing CLIProxyAPI runtime code.
// 夹具验证 Target 绑定的改编边界，不导入 CLIProxyAPI 运行时代码。
package openai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	chatprofile "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/chat"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

const (
	// chatTestProfileID is the exact registered profile fixture used for Chat driver binding tests.
	// chatTestProfileID 是 Chat Driver 绑定测试使用的精确已注册 Profile 夹具。
	chatTestProfileID = "openai.chat.test.v1"
)

// TestChatDriverExecutesBoundNonStreamingRequest verifies the selected target alone receives the typed Chat request and bearer credential.
// TestChatDriverExecutesBoundNonStreamingRequest 验证仅选定 Target 接收类型化 Chat 请求和 Bearer 凭据。
func TestChatDriverExecutesBoundNonStreamingRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/chat/completions" || request.URL.RawQuery != "" {
			t.Errorf("request = %s %s?%s", request.Method, request.URL.Path, request.URL.RawQuery)
		}
		if authorization := request.Header.Get("Authorization"); authorization != "Bearer test-secret" {
			t.Errorf("Authorization = %q", authorization)
		}
		var upstream chatprofile.Request
		if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil {
			t.Errorf("decode request: %v", errDecode)
		}
		if len(upstream.Messages) != 1 || upstream.Messages[0].Role != "user" || upstream.Messages[0].Content != "Hello" {
			t.Errorf("upstream request = %#v", upstream)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"id":"chat-upstream-1","choices":[{"index":0,"message":{"role":"assistant","content":"Hello"},"finish_reason":"stop"}]}`)
	}))
	defer server.Close()

	driver, execution := newChatDriverExecution(t, server.URL, false)
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if result.UpstreamResponseID != "chat-upstream-1" || result.Response.Status != vcp.ResponseCompleted || len(result.Response.Items) != 1 || result.Response.Items[0].Content[0].Text != "Hello" {
		t.Fatalf("result = %#v", result)
	}
}

// TestChatDriverExecutesBoundStream verifies typed Chat SSE stays target-bound and exposes the stable upstream response identifier.
// TestChatDriverExecutesBoundStream 验证类型化 Chat SSE 保持 Target 绑定，并暴露稳定的上游响应标识。
func TestChatDriverExecutesBoundStream(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/chat/completions" || request.Header.Get("Accept") != "text/event-stream" {
			t.Errorf("request = %s %s accept=%q", request.Method, request.URL.Path, request.Header.Get("Accept"))
		}
		writer.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(writer, "data: {\"id\":\"chat-upstream-2\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
	}))
	defer server.Close()

	driver, execution := newChatDriverExecution(t, server.URL, true)
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if result.UpstreamResponseID != "chat-upstream-2" || result.Response.Status != vcp.ResponseCompleted || len(result.Response.Items) != 1 || result.Response.Items[0].Content[0].Text != "Hello" {
		t.Fatalf("result = %#v", result)
	}
}

// TestOpenAICompatibilityDriverPreservesVersionedBaseURL verifies CLIProxyAPI's /chat/completions suffix does not duplicate /v1.
// TestOpenAICompatibilityDriverPreservesVersionedBaseURL 验证 CLIProxyAPI 的 /chat/completions 后缀不会重复 /v1。
func TestOpenAICompatibilityDriverPreservesVersionedBaseURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/gateway/v1/chat/completions" {
			t.Errorf("request path = %q", request.URL.Path)
		}
		if authorization := request.Header.Get("Authorization"); authorization != "Bearer test-secret" {
			t.Errorf("Authorization = %q", authorization)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"id":"chat-compat-1","choices":[{"index":0,"message":{"role":"assistant","content":"Hello"},"finish_reason":"stop"}]}`)
	}))
	defer server.Close()

	baseDriver, execution := newChatDriverExecution(t, server.URL+"/gateway/v1", false)
	driver, errDriver := NewOpenAICompatibilityDriver("definition-1", baseDriver.client, chatDriverCapabilities())
	if errDriver != nil {
		t.Fatalf("NewOpenAICompatibilityDriver() error = %v", errDriver)
	}
	execution.Binding.Target.ExecutionProfileID = chatprofile.ProfileID
	execution.Binding.Credential.AuthMethodID = "default"
	execution.Definition = providerconfig.ProviderDefinition{
		ID: "definition-1", Kind: providerconfig.DefinitionKindCustom, ProtocolProfileID: chatprofile.ProfileID,
		EndpointProfileID: providerconfig.CustomEndpointProfileOpenAICompatibility, AuthMethodIDs: []string{"default"}, RuntimeReady: true,
		AuthMethods: []providerconfig.AuthMethodDefinition{{ID: "default", Type: providerconfig.AuthMethodBearer}}, Revision: 1,
	}
	execution.Request.ModelSelection.ExecutionProfileID = chatprofile.ProfileID
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if result.UpstreamResponseID != "chat-compat-1" {
		t.Fatalf("result = %#v", result)
	}
}

// TestChatDriverRejectsNonAPIKeyCredentialBeforeNetwork verifies a bearer wire request cannot be created from a differently typed credential.
// TestChatDriverRejectsNonAPIKeyCredentialBeforeNetwork 验证不能使用类型不同的凭据创建 Bearer wire 请求。
func TestChatDriverRejectsNonAPIKeyCredentialBeforeNetwork(t *testing.T) {
	var networkReached atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		networkReached.Store(true)
		writer.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	driver, execution := newChatDriverExecution(t, server.URL, false)
	execution.Definition.AuthMethods[0].Type = providerconfig.AuthMethodBearer
	if _, errExecute := driver.Execute(context.Background(), execution); !errors.Is(errExecute, provider.ErrExecutionBinding) {
		t.Fatalf("Execute() error = %v, want ErrExecutionBinding", errExecute)
	}
	if networkReached.Load() {
		t.Fatal("unexpected network execution")
	}
}

// newChatDriverExecution creates one Chat driver and immutable exact-target execution fixture for local HTTP tests.
// newChatDriverExecution 为本地 HTTP 测试创建一个 Chat Driver 和不可变精确 Target 执行夹具。
func newChatDriverExecution(t *testing.T, baseURL string, stream bool) (*ChatDriver, provider.ExecutionRequest) {
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
	driver, errDriver := NewChatDriver("definition-1", chatTestProfileID, client, chatDriverCapabilities())
	if errDriver != nil {
		t.Fatalf("NewChatDriver() error = %v", errDriver)
	}
	now := time.Date(2026, time.July, 17, 0, 0, 0, 0, time.UTC)
	execution := provider.ExecutionRequest{
		Binding: transport.Binding{
			Target:     resolve.Target{ProviderDefinitionID: "definition-1", ProviderInstanceID: "instance-1", ChannelID: "channel-1", EndpointID: "endpoint-1", CredentialID: "credential-1", ProviderModelID: "model-1", OfferingID: "offering-1", ExecutionProfileID: chatTestProfileID, UpstreamModelID: "gpt-test", CatalogRevision: 1},
			Endpoint:   providerconfig.Endpoint{ID: "endpoint-1", ProviderInstanceID: "instance-1", ChannelID: "channel-1", BaseURL: baseURL, Status: providerconfig.EndpointReady},
			Credential: providerconfig.Credential{ID: "credential-1", ProviderInstanceID: "instance-1", AuthMethodID: "api-key", SecretRef: secretReference, Status: providerconfig.CredentialActive},
		},
		Definition: providerconfig.ProviderDefinition{ID: "definition-1", Kind: providerconfig.DefinitionKindSystem, ProtocolProfileID: chatTestProfileID, AuthMethodIDs: []string{"api-key"}, RuntimeReady: true, AuthMethods: []providerconfig.AuthMethodDefinition{{ID: "api-key", Type: providerconfig.AuthMethodAPIKey}}},
		Request: vcp.VulcanRequest{
			ProtocolVersion: vcp.ProtocolVersion, RequestID: "request-1", Stream: stream,
			ModelSelection: vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: "instance-1", ProviderModelID: "model-1", ExecutionProfileID: chatTestProfileID},
			Context:        []vcp.ContextItem{{ItemID: "user-item-1", Sequence: 1, Kind: vcp.ContextMessage, Authority: vcp.AuthorityUser, Actor: vcp.ActorEndUser, Placement: vcp.PlacementTranscript, Activation: vcp.Activation{Mode: vcp.ActivationRequestStart}, Visibility: vcp.VisibilityModel, Content: []vcp.ContentBlock{{Type: vcp.ContentText, Text: "Hello"}}, Message: &vcp.MessageItem{}}},
			CachePolicy:    vcp.CachePolicy{Strategy: vcp.CacheRegular, OnUnsupported: vcp.CacheUnsupportedReject}, ContextManagementPolicy: vcp.ContextManagementPolicy{Mode: vcp.ContextManagementRegular}, CapabilityPolicy: vcp.CapabilityPolicy{ExecutionMode: vcp.CapabilityMaximize, OptionalOnUnsupported: vcp.OptionalOmit},
		},
		LineageID: "lineage-1", Now: now,
	}
	return driver, execution
}

// chatDriverCapabilities returns verified ordinary Chat behavior used by isolated local driver tests.
// chatDriverCapabilities 返回隔离本地 Driver 测试使用的已验证普通 Chat 行为。
func chatDriverCapabilities() chatprofile.ProfileCapabilities {
	return chatprofile.ProfileCapabilities{NativeSystemPreamble: true, NativeDeveloper: true, NativeInlineSystem: true, StructuredTools: true, ParallelTools: true, StreamingToolArguments: true, StrictJSONSchema: true, Reasoning: true, StreamUsage: true}
}
