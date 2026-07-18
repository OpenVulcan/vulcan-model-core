// Driver fixtures cover behavior adapted from CLIProxyAPI commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// Driver 夹具覆盖改编自 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66 的行为。
// Source path: internal/runtime/executor/openai_compat_executor.go.
// 来源路径：internal/runtime/executor/openai_compat_executor.go。
// The fixtures verify the target-bound Responses execution boundary without importing CLIProxyAPI runtime code.
// 夹具验证 Target 绑定的 Responses 执行边界，不导入 CLIProxyAPI 运行时代码。
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

	responsesprofile "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/responses"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestResponsesDriverExecutesBoundNonStreamingRequest verifies the driver keeps an exact target and decodes a typed completed payload.
// TestResponsesDriverExecutesBoundNonStreamingRequest 验证 Driver 保持精确 Target 并解码类型化完成载荷。
func TestResponsesDriverExecutesBoundNonStreamingRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/responses" {
			t.Errorf("request = %s %s", request.Method, request.URL.Path)
		}
		if authorization := request.Header.Get("Authorization"); authorization != "Bearer test-secret" {
			t.Errorf("Authorization = %q", authorization)
		}
		var upstream responsesprofile.Request
		if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil {
			t.Errorf("decode request: %v", errDecode)
		}
		if upstream.Model != "gpt-test" || upstream.Stream {
			t.Errorf("upstream request = %#v", upstream)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"id":"upstream-response-1","status":"completed","output":[{"id":"message-item-1","type":"message","content":[{"type":"output_text","text":"Hello"}]}]}`)
	}))
	defer server.Close()
	driver, execution := newResponsesDriverExecution(t, server.URL, false)
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if result.UpstreamResponseID != "upstream-response-1" || result.Response.Status != vcp.ResponseCompleted || len(result.Response.Items) != 1 || result.Response.Items[0].Content[0].Text != "Hello" {
		t.Fatalf("result = %#v", result)
	}
	if result.Report.Route.ExecutionProfile != responsesprofile.ProfileID || result.Report.Usage != nil {
		t.Fatalf("report = %#v", result.Report)
	}
}

// TestResponsesDriverExecutesBoundStream verifies the stream path requests SSE and yields the same VCP completion semantics.
// TestResponsesDriverExecutesBoundStream 验证流式路径请求 SSE 并产生相同的 VCP 完成语义。
func TestResponsesDriverExecutesBoundStream(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if accept := request.Header.Get("Accept"); accept != "text/event-stream" {
			t.Errorf("Accept = %q", accept)
		}
		var upstream responsesprofile.Request
		if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil {
			t.Errorf("decode request: %v", errDecode)
		}
		if !upstream.Stream {
			t.Errorf("stream request = %#v", upstream)
		}
		writer.Header().Set("Content-Type", "text/event-stream")
		outputIndex := 0
		contentIndex := 0
		writeResponsesSSE(t, writer, responsesprofile.StreamEvent{Type: "response.output_item.added", OutputIndex: &outputIndex, Item: &responsesprofile.OutputItem{ID: "message-item-2", Type: "message"}})
		writeResponsesSSE(t, writer, responsesprofile.StreamEvent{Type: "response.output_text.delta", ItemID: "message-item-2", OutputIndex: &outputIndex, ContentIndex: &contentIndex, Delta: "Hello"})
		writeResponsesSSE(t, writer, responsesprofile.StreamEvent{Type: "response.completed", Response: &responsesprofile.Response{ID: "upstream-response-2", Status: "completed", Output: []responsesprofile.OutputItem{{ID: "message-item-2", Type: "message", Content: []responsesprofile.OutputContent{{Type: "output_text", Text: "Hello"}}}}}})
	}))
	defer server.Close()
	driver, execution := newResponsesDriverExecution(t, server.URL, true)
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if result.UpstreamResponseID != "upstream-response-2" || result.Response.Status != vcp.ResponseCompleted || len(result.Response.Items) != 1 || result.Response.Items[0].Content[0].Text != "Hello" {
		t.Fatalf("result = %#v", result)
	}
}

// TestResponsesDriverRejectsNonAPIKeyCredentialBeforeNetwork verifies a Responses bearer wire request cannot be created from a differently typed credential.
// TestResponsesDriverRejectsNonAPIKeyCredentialBeforeNetwork 验证不能使用类型不同的凭据创建 Responses Bearer wire 请求。
func TestResponsesDriverRejectsNonAPIKeyCredentialBeforeNetwork(t *testing.T) {
	var networkReached atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		networkReached.Store(true)
		writer.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	driver, execution := newResponsesDriverExecution(t, server.URL, false)
	execution.Definition.AuthMethods[0].Type = providerconfig.AuthMethodBearer
	if _, errExecute := driver.Execute(context.Background(), execution); !errors.Is(errExecute, provider.ErrExecutionBinding) {
		t.Fatalf("Execute() error = %v, want ErrExecutionBinding", errExecute)
	}
	if networkReached.Load() {
		t.Fatal("unexpected network execution")
	}
}

// writeResponsesSSE writes one valid typed Responses stream event using the SSE framing consumed by the driver.
// writeResponsesSSE 使用 Driver 消费的 SSE 分帧写入一个有效类型化 Responses 流事件。
func writeResponsesSSE(t *testing.T, writer io.Writer, event responsesprofile.StreamEvent) {
	t.Helper()
	payload, errMarshal := json.Marshal(event)
	if errMarshal != nil {
		t.Errorf("Marshal() error = %v", errMarshal)
		return
	}
	if _, errWrite := fmt.Fprintf(writer, "event: %s\ndata: %s\n\n", event.Type, payload); errWrite != nil {
		t.Errorf("write SSE event: %v", errWrite)
	}
}

// newResponsesDriverExecution creates one driver and exact execution fixture sharing the supplied test server endpoint.
// newResponsesDriverExecution 创建一个共享给定测试服务器 Endpoint 的 Driver 与精确执行夹具。
func newResponsesDriverExecution(t *testing.T, baseURL string, stream bool) (*ResponsesDriver, provider.ExecutionRequest) {
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
	driver, errDriver := NewResponsesDriver("definition-1", client, openAIResponsesCapabilities())
	if errDriver != nil {
		t.Fatalf("NewResponsesDriver() error = %v", errDriver)
	}
	now := time.Date(2026, time.July, 17, 0, 0, 0, 0, time.UTC)
	execution := provider.ExecutionRequest{
		Binding: transport.Binding{
			Target: resolve.Target{
				ProviderDefinitionID: "definition-1", ProviderInstanceID: "instance-1", ChannelID: "channel-1", EndpointID: "endpoint-1", CredentialID: "credential-1",
				ProviderModelID: "model-1", OfferingID: "offering-1", ExecutionProfileID: responsesprofile.ProfileID, UpstreamModelID: "gpt-test", CatalogRevision: 1,
			},
			Endpoint:   providerconfig.Endpoint{ID: "endpoint-1", ProviderInstanceID: "instance-1", ChannelID: "channel-1", BaseURL: baseURL, Status: providerconfig.EndpointReady},
			Credential: providerconfig.Credential{ID: "credential-1", ProviderInstanceID: "instance-1", AuthMethodID: "api-key", SecretRef: secretReference, Status: providerconfig.CredentialActive},
		},
		Definition: providerconfig.ProviderDefinition{ID: "definition-1", Kind: providerconfig.DefinitionKindSystem, AuthMethods: []providerconfig.AuthMethodDefinition{{ID: "api-key", Type: providerconfig.AuthMethodAPIKey}}, Channels: []providerconfig.ProviderChannel{{ID: "channel-1", ProtocolProfileID: responsesprofile.ProfileID, AuthMethodIDs: []string{"api-key"}, RuntimeReady: true}}},
		Request: vcp.VulcanRequest{
			ProtocolVersion: vcp.ProtocolVersion, RequestID: "request-1", Stream: stream,
			ModelSelection: vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: "instance-1", ProviderModelID: "model-1", ExecutionProfileID: responsesprofile.ProfileID},
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
	return driver, execution
}

// openAIResponsesCapabilities returns the verified capability fixture used by the isolated driver tests.
// openAIResponsesCapabilities 返回隔离 Driver 测试使用的已验证能力夹具。
func openAIResponsesCapabilities() responsesprofile.ProfileCapabilities {
	return responsesprofile.ProfileCapabilities{
		NativeSystemPreamble: true, NativeDeveloper: true, NativeInlineSystem: true, StructuredTools: true, NativeCustomTools: true,
		NativeToolNamespaces: true, ParallelTools: true, StreamingToolArguments: true, StrictJSONSchema: true, Reasoning: true,
		ReasoningContinuation: true, NativeWebSearch: true,
	}
}
