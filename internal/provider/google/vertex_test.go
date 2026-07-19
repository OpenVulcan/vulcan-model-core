// Driver fixtures cover Vertex action routing copied from CLIProxyAPI commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// Driver 夹具覆盖从 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66 复制的 Vertex 动作路由。
package google

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
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

// TestVertexDriverExecutesExactRegionalActions verifies non-stream, stream, and countTokens wire paths and authentication.
// TestVertexDriverExecutesExactRegionalActions 校验非流式、流式与 countTokens Wire 路径及认证。
func TestVertexDriverExecutesExactRegionalActions(t *testing.T) {
	t.Run("generateContent", func(t *testing.T) {
		driver, execution := newVertexDriverExecution(t, false, func(request *http.Request) (*http.Response, error) {
			verifyVertexExecutionRequest(t, request, "/v1/projects/vertex-project/locations/europe-west1/publishers/google/models/gemini-test:generateContent", "")
			return vertexHTTPResponse(request, http.StatusOK, "application/json", `{"responseId":"vertex-response-1","candidates":[{"index":0,"content":{"role":"model","parts":[{"text":"Hello"}]},"finishReason":"STOP"}]}`), nil
		})
		result, errExecute := driver.Execute(context.Background(), execution)
		if errExecute != nil {
			t.Fatalf("Execute() error = %v", errExecute)
		}
		if result.UpstreamResponseID != "vertex-response-1" || result.Response.Status != vcp.ResponseCompleted || result.Response.Items[0].Content[0].Text != "Hello" {
			t.Fatalf("unexpected Vertex result: %#v", result)
		}
	})

	t.Run("streamGenerateContent", func(t *testing.T) {
		driver, execution := newVertexDriverExecution(t, true, func(request *http.Request) (*http.Response, error) {
			verifyVertexExecutionRequest(t, request, "/v1/projects/vertex-project/locations/europe-west1/publishers/google/models/gemini-test:streamGenerateContent", "alt=sse")
			if request.Header.Get("Accept") != "text/event-stream" {
				t.Errorf("unexpected stream Accept header %q", request.Header.Get("Accept"))
			}
			body := "data: {\"responseId\":\"vertex-response-2\",\"candidates\":[{\"index\":0,\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"Hello\"}]},\"finishReason\":\"STOP\"}]}\n\n"
			return vertexHTTPResponse(request, http.StatusOK, "text/event-stream", body), nil
		})
		result, errExecute := driver.Execute(context.Background(), execution)
		if errExecute != nil {
			t.Fatalf("Execute() error = %v", errExecute)
		}
		if result.UpstreamResponseID != "vertex-response-2" || result.Response.Status != vcp.ResponseCompleted {
			t.Fatalf("unexpected Vertex stream result: %#v", result)
		}
	})

	t.Run("countTokens", func(t *testing.T) {
		driver, execution := newVertexDriverExecution(t, false, func(request *http.Request) (*http.Response, error) {
			verifyVertexExecutionRequest(t, request, "/v1/projects/vertex-project/locations/europe-west1/publishers/google/models/gemini-test:countTokens", "")
			body, errRead := io.ReadAll(request.Body)
			if errRead != nil {
				t.Errorf("read countTokens body: %v", errRead)
			}
			if strings.Contains(string(body), "generateContentRequest") {
				t.Errorf("Vertex countTokens body used the AI Studio wrapper: %s", body)
			}
			var upstream aistudio.GenerateContentRequest
			if errDecode := json.Unmarshal(body, &upstream); errDecode != nil || len(upstream.Contents) != 1 {
				t.Errorf("decode direct Vertex countTokens body: request=%#v error=%v", upstream, errDecode)
			}
			return vertexHTTPResponse(request, http.StatusOK, "application/json", `{"totalTokens":12,"cachedContentTokenCount":3}`), nil
		})
		result, errCount := driver.CountTokens(context.Background(), execution)
		if errCount != nil {
			t.Fatalf("CountTokens() error = %v", errCount)
		}
		if result.TotalTokens == nil || *result.TotalTokens != 12 || result.Usage.CacheReadTokens == nil || *result.Usage.CacheReadTokens != 3 || result.Usage.AccountingBasis != "google_vertex_count_tokens" {
			t.Fatalf("unexpected Vertex token count: %#v", result)
		}
	})
}

// TestVertexDriverRejectsMissingTotalTokenCount verifies a successful countTokens payload cannot omit its required result.
// TestVertexDriverRejectsMissingTotalTokenCount 验证成功的 countTokens 载荷不能省略必需结果。
func TestVertexDriverRejectsMissingTotalTokenCount(t *testing.T) {
	driver, execution := newVertexDriverExecution(t, false, func(request *http.Request) (*http.Response, error) {
		return vertexHTTPResponse(request, http.StatusOK, "application/json", `{}`), nil
	})
	if _, errCount := driver.CountTokens(context.Background(), execution); !errors.Is(errCount, aistudio.ErrInvalidUpstreamResponse) {
		t.Fatalf("CountTokens() error = %v, want ErrInvalidUpstreamResponse", errCount)
	}
}

// TestVertexDriverRejectsScopeDriftAndImageGeneration verifies no network call can escape persisted Vertex scope or unsupported VCP media output.
// TestVertexDriverRejectsScopeDriftAndImageGeneration 校验网络调用无法逸出持久化 Vertex 作用域或进入不支持的 VCP 媒体输出。
func TestVertexDriverRejectsScopeDriftAndImageGeneration(t *testing.T) {
	var networkReached atomic.Bool
	driver, execution := newVertexDriverExecution(t, false, func(request *http.Request) (*http.Response, error) {
		networkReached.Store(true)
		return nil, errors.New("unexpected network request")
	})
	execution.Binding.Endpoint.BaseURL = "https://us-central1-aiplatform.googleapis.com"
	if _, errExecute := driver.Execute(context.Background(), execution); !errors.Is(errExecute, provider.ErrExecutionBinding) {
		t.Fatalf("scope-drift Execute() error = %v, want ErrExecutionBinding", errExecute)
	}
	execution.Binding.Endpoint.BaseURL = VertexBaseURL("europe-west1")
	execution.Binding.Target.UpstreamModelID = "imagen-4.0-generate-001"
	if _, errExecute := driver.Execute(context.Background(), execution); !errors.Is(errExecute, ErrInvalidVertexDriver) {
		t.Fatalf("Imagen Execute() error = %v, want ErrInvalidVertexDriver", errExecute)
	}
	if networkReached.Load() {
		t.Fatalf("Vertex preflight rejection reached the network")
	}
}

// newVertexDriverExecution creates one service-account driver and immutable regional execution fixture.
// newVertexDriverExecution 创建一个服务账号 Driver 与不可变区域执行 Fixture。
func newVertexDriverExecution(t *testing.T, stream bool, roundTrip vertexRoundTripFunc) (*VertexDriver, provider.ExecutionRequest) {
	t.Helper()
	secretStore := secret.NewMemoryStore()
	secretReference, errPut := secretStore.Put(context.Background(), []byte("vertex-access-token"))
	if errPut != nil {
		t.Fatalf("store projected Vertex token: %v", errPut)
	}
	client, errClient := transport.NewClient(&http.Client{Transport: roundTrip}, secretStore, transport.RetryPolicy{})
	if errClient != nil {
		t.Fatalf("create Vertex transport: %v", errClient)
	}
	driver, errDriver := NewVertexDriver("definition-vertex", client, aiStudioDriverCapabilities())
	if errDriver != nil {
		t.Fatalf("create Vertex driver: %v", errDriver)
	}
	execution := provider.ExecutionRequest{
		Binding: transport.Binding{
			Target: resolve.Target{
				ProviderDefinitionID: "definition-vertex", ProviderInstanceID: "instance-vertex", ChannelID: aistudio.ProfileID,
				EndpointID: "endpoint-vertex", CredentialID: "credential-vertex", ProviderModelID: "model-vertex",
				OfferingID: "offering-vertex", ExecutionProfileID: aistudio.ProfileID, UpstreamModelID: "gemini-test", CatalogRevision: 1,
			},
			Endpoint: providerconfig.Endpoint{
				ID: "endpoint-vertex", ProviderInstanceID: "instance-vertex", ChannelID: aistudio.ProfileID,
				BaseURL: VertexBaseURL("europe-west1"), Region: "europe-west1", Status: providerconfig.EndpointReady, Revision: 1,
			},
			Credential: providerconfig.Credential{
				ID: "credential-vertex", ProviderInstanceID: "instance-vertex", AuthMethodID: "service_account",
				SecretRef: secretReference, Status: providerconfig.CredentialActive,
				ScopeRefs: []providerconfig.ScopeReference{{Kind: "project", ID: "vertex-project"}}, Revision: 1,
			},
		},
		Definition: providerconfig.ProviderDefinition{
			ID: "definition-vertex", Kind: providerconfig.DefinitionKindSystem, ProtocolProfileID: aistudio.ProfileID,
			AuthMethodIDs: []string{"service_account"}, RuntimeReady: true,
			AuthMethods: []providerconfig.AuthMethodDefinition{{ID: "service_account", Type: providerconfig.AuthMethodServiceAccount}},
		},
		Request: vcp.VulcanRequest{
			ProtocolVersion: vcp.ProtocolVersion, RequestID: "request-vertex", Stream: stream,
			ModelSelection: vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: "instance-vertex", ProviderModelID: "model-vertex", ExecutionProfileID: aistudio.ProfileID},
			Context: []vcp.ContextItem{{
				ItemID: "item-vertex", Sequence: 1, Kind: vcp.ContextMessage, Authority: vcp.AuthorityUser, Actor: vcp.ActorEndUser,
				Placement: vcp.PlacementTranscript, Activation: vcp.Activation{Mode: vcp.ActivationRequestStart}, Visibility: vcp.VisibilityModel,
				Content: []vcp.ContentBlock{{Type: vcp.ContentText, Text: "Hello"}}, Message: &vcp.MessageItem{},
			}},
			CachePolicy:             vcp.CachePolicy{Strategy: vcp.CacheRegular, OnUnsupported: vcp.CacheUnsupportedReject},
			ContextManagementPolicy: vcp.ContextManagementPolicy{Mode: vcp.ContextManagementRegular},
			CapabilityPolicy:        vcp.CapabilityPolicy{ExecutionMode: vcp.CapabilityMaximize, OptionalOnUnsupported: vcp.OptionalOmit},
		},
		LineageID: "lineage-vertex", Now: time.Date(2026, time.July, 19, 0, 0, 0, 0, time.UTC),
	}
	return driver, execution
}

// verifyVertexExecutionRequest validates the copied endpoint shape and bearer-only authentication.
// verifyVertexExecutionRequest 校验复制的入口形态与仅 Bearer 认证。
func verifyVertexExecutionRequest(t *testing.T, request *http.Request, expectedPath string, expectedQuery string) {
	t.Helper()
	if request.Method != http.MethodPost || request.URL.Scheme != "https" || request.URL.Host != "europe-west1-aiplatform.googleapis.com" || request.URL.Path != expectedPath || request.URL.RawQuery != expectedQuery {
		t.Errorf("unexpected Vertex request: %s %s", request.Method, request.URL.String())
	}
	if request.Header.Get("Authorization") != "Bearer vertex-access-token" || request.Header.Get("X-Goog-Api-Key") != "" {
		t.Errorf("unexpected Vertex authentication headers: %#v", request.Header)
	}
}

// vertexHTTPResponse creates one isolated successful or failed upstream response.
// vertexHTTPResponse 创建一个隔离的成功或失败上游响应。
func vertexHTTPResponse(request *http.Request, statusCode int, contentType string, body string) *http.Response {
	header := make(http.Header)
	header.Set("Content-Type", contentType)
	return &http.Response{StatusCode: statusCode, Header: header, Body: io.NopCloser(strings.NewReader(body)), Request: request}
}
