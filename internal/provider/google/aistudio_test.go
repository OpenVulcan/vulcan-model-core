// Driver fixtures cover AI Studio action routing adapted from CLIProxyAPI commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// Driver 夹具覆盖改编自 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66 的 AI Studio 动作路由。
// Source path: internal/runtime/executor/aistudio_executor.go.
// 来源路径：internal/runtime/executor/aistudio_executor.go。
// The fixtures verify typed AI Studio action routing without importing CLIProxyAPI runtime code.
// 夹具验证类型化 AI Studio 动作路由，不导入 CLIProxyAPI 运行时代码。
package google

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

	aistudio "github.com/OpenVulcan/vulcan-model-core/internal/protocol/google/aistudio"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestAIStudioDriverExecutesBoundNonStreamingRequest verifies the exact selected target receives a typed generateContent request and API-key authentication.
// TestAIStudioDriverExecutesBoundNonStreamingRequest 验证精确选定的 Target 接收类型化 generateContent 请求和 API Key 认证。
func TestAIStudioDriverExecutesBoundNonStreamingRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1beta/models/gemini-test:generateContent" || request.URL.RawQuery != "" {
			t.Errorf("request = %s %s?%s", request.Method, request.URL.Path, request.URL.RawQuery)
		}
		if apiKey := request.Header.Get("X-Goog-Api-Key"); apiKey != "test-secret" {
			t.Errorf("X-Goog-Api-Key = %q", apiKey)
		}
		var upstream aistudio.GenerateContentRequest
		if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil {
			t.Errorf("decode request: %v", errDecode)
		}
		if len(upstream.Contents) != 1 || upstream.Contents[0].Role != "user" || upstream.Contents[0].Parts[0].Text != "Hello" {
			t.Errorf("upstream request = %#v", upstream)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"responseId":"upstream-response-1","candidates":[{"index":0,"content":{"role":"model","parts":[{"text":"Hello"}]},"finishReason":"STOP"}]}`)
	}))
	defer server.Close()

	driver, execution := newAIStudioDriverExecution(t, server.URL, false)
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if result.UpstreamResponseID != "upstream-response-1" || result.Response.Status != vcp.ResponseCompleted || len(result.Response.Items) != 1 || result.Response.Items[0].Content[0].Text != "Hello" {
		t.Fatalf("result = %#v", result)
	}
	if result.Report.Route.ExecutionProfile != aistudio.ProfileID || result.Report.Usage != nil {
		t.Fatalf("report = %#v", result.Report)
	}
}

// TestAIStudioDriverExecutesBoundStream verifies the stream action, SSE query syntax, and VCP reduction remain bound to the same target.
// TestAIStudioDriverExecutesBoundStream 验证流动作、SSE 查询语法和 VCP 归并始终绑定到同一 Target。
func TestAIStudioDriverExecutesBoundStream(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1beta/models/gemini-test:streamGenerateContent" || request.URL.Query().Get("alt") != "sse" {
			t.Errorf("request = %s %s?%s", request.Method, request.URL.Path, request.URL.RawQuery)
		}
		if accept := request.Header.Get("Accept"); accept != "text/event-stream" {
			t.Errorf("Accept = %q", accept)
		}
		if apiKey := request.Header.Get("X-Goog-Api-Key"); apiKey != "test-secret" {
			t.Errorf("X-Goog-Api-Key = %q", apiKey)
		}
		var upstream aistudio.GenerateContentRequest
		if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil {
			t.Errorf("decode request: %v", errDecode)
		}
		if len(upstream.Contents) != 1 || upstream.Contents[0].Role != "user" {
			t.Errorf("upstream request = %#v", upstream)
		}
		writer.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(writer, "data: {\"responseId\":\"upstream-response-2\",\"candidates\":[{\"index\":0,\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"Hello\"}]},\"finishReason\":\"STOP\"}]}\n\n")
	}))
	defer server.Close()

	driver, execution := newAIStudioDriverExecution(t, server.URL, true)
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if result.UpstreamResponseID != "upstream-response-2" || result.Response.Status != vcp.ResponseCompleted || len(result.Response.Items) != 1 || result.Response.Items[0].Content[0].Text != "Hello" {
		t.Fatalf("result = %#v", result)
	}
}

// TestAIStudioDriverRejectsNonAPIKeyCredentialBeforeNetwork verifies the fixed X-Goog-Api-Key carrier is only built from a provider API key credential.
// TestAIStudioDriverRejectsNonAPIKeyCredentialBeforeNetwork 验证固定的 X-Goog-Api-Key 载体只会由供应商 API Key 凭据构造。
func TestAIStudioDriverRejectsNonAPIKeyCredentialBeforeNetwork(t *testing.T) {
	var networkReached atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		networkReached.Store(true)
		writer.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	driver, execution := newAIStudioDriverExecution(t, server.URL, false)
	execution.Definition.AuthMethods[0].Type = providerconfig.AuthMethodHeaderKey
	if _, errExecute := driver.Execute(context.Background(), execution); !errors.Is(errExecute, provider.ErrExecutionBinding) {
		t.Fatalf("Execute() error = %v, want ErrExecutionBinding", errExecute)
	}
	if networkReached.Load() {
		t.Fatal("unexpected network execution")
	}
}

// TestAIStudioDriverCountTokensUsesTypedEnvelope verifies countTokens calls its own action and accepts the documented zero-token response.
// TestAIStudioDriverCountTokensUsesTypedEnvelope 验证 countTokens 调用自身动作并接受文档化的零 Token 响应。
func TestAIStudioDriverCountTokensUsesTypedEnvelope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1beta/models/gemini-test:countTokens" || request.URL.RawQuery != "" {
			t.Errorf("request = %s %s?%s", request.Method, request.URL.Path, request.URL.RawQuery)
		}
		if apiKey := request.Header.Get("X-Goog-Api-Key"); apiKey != "test-secret" {
			t.Errorf("X-Goog-Api-Key = %q", apiKey)
		}
		var upstream aistudio.CountTokensRequest
		if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil {
			t.Errorf("decode count request: %v", errDecode)
		}
		if len(upstream.GenerateContentRequest.Contents) != 1 || upstream.GenerateContentRequest.Contents[0].Role != "user" {
			t.Errorf("count request = %#v", upstream)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"totalTokens":0,"cachedContentTokenCount":0,"promptTokensDetails":[{"modality":"TEXT","tokenCount":0}],"cacheTokensDetails":[{"modality":"TEXT","tokenCount":0}]}`)
	}))
	defer server.Close()

	driver, execution := newAIStudioDriverExecution(t, server.URL, false)
	result, errCount := driver.CountTokens(context.Background(), execution)
	if errCount != nil {
		t.Fatalf("CountTokens() error = %v", errCount)
	}
	if result.TotalTokens == nil || *result.TotalTokens != 0 || result.Usage.TotalTokens == nil || *result.Usage.TotalTokens != 0 || result.Usage.Phase != "preflight" {
		t.Fatalf("result = %#v", result)
	}
	if result.Report.Usage == nil || result.Report.Usage.TotalTokens == nil || *result.Report.Usage.TotalTokens != 0 || !containsConversionCode(result.Report.ConversionSummary, "google_aistudio.count_tokens.modality_details.omitted") {
		t.Fatalf("countTokens report = %#v", result.Report)
	}
}

// TestAIStudioEndpointPathAcceptsDocumentedModelResource verifies a configured models/{id} resource has one unambiguous action path.
// TestAIStudioEndpointPathAcceptsDocumentedModelResource 验证配置的 models/{id} 资源具有唯一明确的动作路径。
func TestAIStudioEndpointPathAcceptsDocumentedModelResource(t *testing.T) {
	path, errPath := aiStudioEndpointPath("models/gemini-test", "streamGenerateContent", true)
	if errPath != nil {
		t.Fatalf("aiStudioEndpointPath() error = %v", errPath)
	}
	if path != "/v1beta/models/gemini-test:streamGenerateContent?alt=sse" {
		t.Fatalf("path = %q", path)
	}
}

// TestAIStudioDriverCopiesThinkingLevelCapabilities verifies caller mutation cannot alter the driver's verified target facts.
// TestAIStudioDriverCopiesThinkingLevelCapabilities 验证调用方修改不会改变 Driver 已验证的 Target 能力事实。
func TestAIStudioDriverCopiesThinkingLevelCapabilities(t *testing.T) {
	capabilities := aiStudioDriverCapabilities()
	capabilities.ThinkingLevels = []string{"high"}
	client, errClient := transport.NewClient(http.DefaultClient, secret.NewMemoryStore(), transport.RetryPolicy{})
	if errClient != nil {
		t.Fatalf("NewClient() error = %v", errClient)
	}
	driver, errDriver := NewAIStudioDriver("definition-1", client, capabilities)
	if errDriver != nil {
		t.Fatalf("NewAIStudioDriver() error = %v", errDriver)
	}
	capabilities.ThinkingLevels[0] = "low"
	if len(driver.capabilities.ThinkingLevels) != 1 || driver.capabilities.ThinkingLevels[0] != "high" {
		t.Fatalf("driver capabilities = %#v", driver.capabilities)
	}
}

// newAIStudioDriverExecution creates one driver and immutable execution fixture sharing a supplied local upstream endpoint.
// newAIStudioDriverExecution 创建一个共享给定本地上游 Endpoint 的 Driver 和不可变执行夹具。
func newAIStudioDriverExecution(t *testing.T, baseURL string, stream bool) (*AIStudioDriver, provider.ExecutionRequest) {
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
	driver, errDriver := NewAIStudioDriver("definition-1", client, aiStudioDriverCapabilities())
	if errDriver != nil {
		t.Fatalf("NewAIStudioDriver() error = %v", errDriver)
	}
	now := time.Date(2026, time.July, 17, 0, 0, 0, 0, time.UTC)
	execution := provider.ExecutionRequest{
		Binding: transport.Binding{
			Target: resolve.Target{
				ProviderDefinitionID: "definition-1", ProviderInstanceID: "instance-1", ChannelID: "channel-1", EndpointID: "endpoint-1", CredentialID: "credential-1",
				ProviderModelID: "model-1", OfferingID: "offering-1", ExecutionProfileID: aistudio.ProfileID, UpstreamModelID: "gemini-test", CatalogRevision: 1,
			},
			Endpoint:   providerconfig.Endpoint{ID: "endpoint-1", ProviderInstanceID: "instance-1", ChannelID: "channel-1", BaseURL: baseURL, Status: providerconfig.EndpointReady},
			Credential: providerconfig.Credential{ID: "credential-1", ProviderInstanceID: "instance-1", AuthMethodID: "api-key", SecretRef: secretReference, Status: providerconfig.CredentialActive},
		},
		Definition: providerconfig.ProviderDefinition{ID: "definition-1", Kind: providerconfig.DefinitionKindSystem, AuthMethods: []providerconfig.AuthMethodDefinition{{ID: "api-key", Type: providerconfig.AuthMethodAPIKey}}, Channels: []providerconfig.ProviderChannel{{ID: "channel-1", ProtocolProfileID: aistudio.ProfileID, AuthMethodIDs: []string{"api-key"}, RuntimeReady: true}}},
		Request: vcp.VulcanRequest{
			ProtocolVersion: vcp.ProtocolVersion, RequestID: "request-1", Stream: stream,
			ModelSelection: vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: "instance-1", ProviderModelID: "model-1", ExecutionProfileID: aistudio.ProfileID},
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

// aiStudioDriverCapabilities returns the verified profile facts used by isolated local driver tests.
// aiStudioDriverCapabilities 返回隔离本地 Driver 测试使用的已验证 Profile 事实。
func aiStudioDriverCapabilities() aistudio.ProfileCapabilities {
	return aistudio.ProfileCapabilities{NativeSystemInstruction: true, StructuredTools: true, ParallelTools: true, StreamingToolArguments: true, StrictJSONSchema: true, NativeReasoning: true}
}
