// Driver fixtures cover behavior adapted from CLIProxyAPI commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// Driver 夹具覆盖改编自 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66 的行为。
// Source path: internal/runtime/executor/xai_executor.go.
// 来源路径：internal/runtime/executor/xai_executor.go。
// The fixtures verify the target-bound xAI action boundary without importing CLIProxyAPI runtime code.
// 夹具验证 Target 绑定的 xAI 动作边界，不导入 CLIProxyAPI 运行时代码。
package xai

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

	xairesponses "github.com/OpenVulcan/vulcan-model-core/internal/protocol/xai/responses"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestResponsesDriverExecutesBoundNonStreamingRequest verifies xAI requests remain within the endpoint-selected /v1 scope.
// TestResponsesDriverExecutesBoundNonStreamingRequest 验证 xAI 请求保持在 Endpoint 选定的 /v1 作用域内。
func TestResponsesDriverExecutesBoundNonStreamingRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/responses" {
			t.Errorf("request = %s %s", request.Method, request.URL.Path)
		}
		if authorization := request.Header.Get("Authorization"); authorization != "Bearer test-secret" {
			t.Errorf("Authorization = %q", authorization)
		}
		var upstream xairesponses.Request
		if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil {
			t.Errorf("decode request: %v", errDecode)
		}
		if upstream.Model != "grok-test" || upstream.Stream {
			t.Errorf("upstream request = %#v", upstream)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"id":"upstream-xai-1","status":"completed","output":[{"id":"message-item","type":"message","content":[{"type":"output_text","text":"Hello"}]}]}`)
	}))
	defer server.Close()
	driver, execution := newXAIResponsesDriverExecution(t, server.URL+"/v1", server.Client(), false)
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if result.UpstreamResponseID != "upstream-xai-1" || result.Response.Status != vcp.ResponseCompleted || len(result.Response.Items) != 1 || result.Response.Items[0].Content[0].Text != "Hello" {
		t.Fatalf("result = %#v", result)
	}
}

// TestResponsesDriverExecutesCompactWithResolvedContinuation verifies compact uses the same target endpoint and never sends the Router identifier.
// TestResponsesDriverExecutesCompactWithResolvedContinuation 验证 compact 使用相同 Target Endpoint 且绝不发送 Router 标识。
func TestResponsesDriverExecutesCompactWithResolvedContinuation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/responses/compact" {
			t.Errorf("request = %s %s", request.Method, request.URL.Path)
		}
		var upstream xairesponses.Request
		if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil {
			t.Errorf("decode compact request: %v", errDecode)
		}
		if upstream.PreviousResponseID != "upstream-seed" || upstream.Stream || len(upstream.Tools) != 0 || upstream.ToolChoice != nil || upstream.ParallelToolCalls != nil {
			t.Errorf("compact upstream = %#v", upstream)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"id":"upstream-compact","status":"completed","output":[{"id":"compact-item","type":"compaction"}]}`)
	}))
	defer server.Close()
	driver, execution := newXAIResponsesDriverExecution(t, server.URL+"/v1", server.Client(), false)
	execution.Request.RemoteCompaction = &vcp.RemoteCompactionRequest{PreviousResponseID: "continuation-1"}
	execution.Continuation = &provider.ContinuationBinding{
		ContinuationID: "continuation-1", ProviderDefinitionID: "definition-1", ProviderInstanceID: "instance-1", ChannelID: "channel-1",
		EndpointID: "endpoint-1", CredentialID: "credential-1", ProviderModelID: "model-1", UpstreamModelID: "grok-test", ExecutionProfileID: xairesponses.ProfileID, UpstreamResponseID: "upstream-seed",
	}
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if result.UpstreamResponseID != "upstream-compact" || result.Response.Status != vcp.ResponseCompleted || len(result.Response.Items) != 0 || !containsSummaryCode(result.Report.ConversionSummary, "xai_responses.compaction.provider_state_retained_by_response_id") {
		t.Fatalf("result = %#v", result)
	}
}

// TestResponsesDriverExecutesBoundStream verifies xAI SSE requests use the same target and normalize the terminal event sequence.
// TestResponsesDriverExecutesBoundStream 验证 xAI SSE 请求使用相同 Target 并归一化终态事件序列。
func TestResponsesDriverExecutesBoundStream(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/responses" || request.Header.Get("Accept") != "text/event-stream" {
			t.Errorf("stream request = %s %q", request.URL.Path, request.Header.Get("Accept"))
		}
		writer.Header().Set("Content-Type", "text/event-stream")
		outputIndex := 0
		contentIndex := 0
		writeXAISSE(t, writer, xairesponses.StreamEvent{Type: "response.output_item.added", OutputIndex: &outputIndex, Item: &xairesponses.OutputItem{ID: "message-item", Type: "message"}})
		writeXAISSE(t, writer, xairesponses.StreamEvent{Type: "response.output_text.delta", ItemID: "message-item", OutputIndex: &outputIndex, ContentIndex: &contentIndex, Delta: "Hello"})
		writeXAISSE(t, writer, xairesponses.StreamEvent{Type: "response.completed", Response: &xairesponses.Response{ID: "upstream-xai-2", Status: "completed", Output: []xairesponses.OutputItem{{ID: "message-item", Type: "message", Content: []xairesponses.OutputContent{{Type: "output_text", Text: "Hello"}}}}}})
	}))
	defer server.Close()
	driver, execution := newXAIResponsesDriverExecution(t, server.URL+"/v1", server.Client(), true)
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if result.UpstreamResponseID != "upstream-xai-2" || result.Response.Status != vcp.ResponseCompleted || len(result.Response.Items) != 1 || result.Response.Items[0].Content[0].Text != "Hello" {
		t.Fatalf("result = %#v", result)
	}
}

// TestResponsesDriverRejectsNonAPIKeyCredentialBeforeNetwork verifies an xAI bearer wire request cannot be created from a differently typed credential.
// TestResponsesDriverRejectsNonAPIKeyCredentialBeforeNetwork 验证不能使用类型不同的凭据创建 xAI Bearer wire 请求。
func TestResponsesDriverRejectsNonAPIKeyCredentialBeforeNetwork(t *testing.T) {
	var networkReached atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		networkReached.Store(true)
		writer.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	driver, execution := newXAIResponsesDriverExecution(t, server.URL+"/v1", server.Client(), false)
	execution.Definition.AuthMethods[0].Type = providerconfig.AuthMethodBearer
	if _, errExecute := driver.Execute(context.Background(), execution); !errors.Is(errExecute, provider.ErrExecutionBinding) {
		t.Fatalf("Execute() error = %v, want ErrExecutionBinding", errExecute)
	}
	if networkReached.Load() {
		t.Fatal("unexpected network execution")
	}
}

// writeXAISSE writes one valid typed xAI stream event using the SSE framing consumed by the driver.
// writeXAISSE 使用 Driver 消费的 SSE 分帧写入一个有效类型化 xAI 流事件。
func writeXAISSE(t *testing.T, writer io.Writer, event xairesponses.StreamEvent) {
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

// newXAIResponsesDriverExecution creates one xAI driver and exact execution fixture sharing the supplied endpoint and HTTP client.
// newXAIResponsesDriverExecution 创建一个共享给定 Endpoint 与 HTTP 客户端的 xAI Driver 和精确执行夹具。
func newXAIResponsesDriverExecution(t *testing.T, baseURL string, httpClient *http.Client, stream bool) (*ResponsesDriver, provider.ExecutionRequest) {
	t.Helper()
	secretStore := secret.NewMemoryStore()
	secretReference, errPut := secretStore.Put(context.Background(), []byte("test-secret"))
	if errPut != nil {
		t.Fatalf("Put() error = %v", errPut)
	}
	client, errClient := transport.NewClient(httpClient, secretStore, transport.RetryPolicy{})
	if errClient != nil {
		t.Fatalf("NewClient() error = %v", errClient)
	}
	driver, errDriver := NewResponsesDriver("definition-1", client, xaiDriverCapabilities())
	if errDriver != nil {
		t.Fatalf("NewResponsesDriver() error = %v", errDriver)
	}
	now := time.Date(2026, time.July, 17, 0, 0, 0, 0, time.UTC)
	execution := provider.ExecutionRequest{
		Binding: transport.Binding{
			Target: resolve.Target{
				ProviderDefinitionID: "definition-1", ProviderInstanceID: "instance-1", ChannelID: "channel-1", EndpointID: "endpoint-1", CredentialID: "credential-1",
				ProviderModelID: "model-1", OfferingID: "offering-1", ExecutionProfileID: xairesponses.ProfileID, UpstreamModelID: "grok-test", CatalogRevision: 1,
			},
			Endpoint:   providerconfig.Endpoint{ID: "endpoint-1", ProviderInstanceID: "instance-1", ChannelID: "channel-1", BaseURL: baseURL, Status: providerconfig.EndpointReady},
			Credential: providerconfig.Credential{ID: "credential-1", ProviderInstanceID: "instance-1", AuthMethodID: "api-key", SecretRef: secretReference, Status: providerconfig.CredentialActive},
		},
		Definition: providerconfig.ProviderDefinition{ID: "definition-1", Kind: providerconfig.DefinitionKindSystem, AuthMethods: []providerconfig.AuthMethodDefinition{{ID: "api-key", Type: providerconfig.AuthMethodAPIKey}}, Channels: []providerconfig.ProviderChannel{{ID: "channel-1", ProtocolProfileID: xairesponses.ProfileID, AuthMethodIDs: []string{"api-key"}, RuntimeReady: true}}},
		Request: vcp.VulcanRequest{
			ProtocolVersion: vcp.ProtocolVersion, RequestID: "request-1", Stream: stream,
			ModelSelection: vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: "instance-1", ProviderModelID: "model-1", ExecutionProfileID: xairesponses.ProfileID},
			Context: []vcp.ContextItem{{
				ItemID: "user-item", Sequence: 1, Kind: vcp.ContextMessage, Authority: vcp.AuthorityUser, Actor: vcp.ActorEndUser,
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

// xaiDriverCapabilities returns the fully verified capability fixture used by the isolated xAI driver tests.
// xaiDriverCapabilities 返回隔离 xAI Driver 测试使用的完全验证能力夹具。
func xaiDriverCapabilities() xairesponses.ProfileCapabilities {
	return xairesponses.ProfileCapabilities{
		NativeSystemPreamble: true, NativeDeveloper: true, NativeInlineSystem: true, StructuredTools: true, ParallelTools: true,
		StreamingToolArguments: true, StrictJSONSchema: true, Reasoning: true, ReasoningEffort: true, ReasoningContinuation: true,
		NativeXSearch: true, NativeRemoteCompaction: true,
	}
}

// containsSummaryCode reports whether one stable conversion code appears in a driver result report.
// containsSummaryCode 报告一个稳定转换代码是否出现在 Driver 结果报告中。
func containsSummaryCode(codes []string, target string) bool {
	for _, code := range codes {
		if code == target {
			return true
		}
	}
	return false
}
