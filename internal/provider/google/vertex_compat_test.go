// Driver fixtures cover Vertex-compatible API-key routing copied from CLIProxyAPI commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// Driver 夹具覆盖从 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66 复制的 Vertex 兼容 API Key 路由。
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

	aistudio "github.com/OpenVulcan/vulcan-model-core/internal/protocol/google/aistudio"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestVertexCompatDriverExecutesExactAPIKeyActions verifies non-stream, stream, and countTokens paths copied from CLIProxyAPI.
// TestVertexCompatDriverExecutesExactAPIKeyActions 校验从 CLIProxyAPI 复制的非流式、流式与 countTokens 路径。
func TestVertexCompatDriverExecutesExactAPIKeyActions(t *testing.T) {
	t.Run("generateContent", func(t *testing.T) {
		driver, execution := newVertexCompatDriverExecution(t, false, func(request *http.Request) (*http.Response, error) {
			verifyVertexCompatExecutionRequest(t, request, "/compat-root/v1/publishers/google/models/gemini-test:generateContent", "")
			return vertexHTTPResponse(request, http.StatusOK, "application/json", `{"responseId":"vertex-compat-1","candidates":[{"index":0,"content":{"role":"model","parts":[{"text":"Hello"}]},"finishReason":"STOP"}]}`), nil
		})
		result, errExecute := driver.Execute(context.Background(), execution)
		if errExecute != nil {
			t.Fatalf("Execute() error = %v", errExecute)
		}
		if result.UpstreamResponseID != "vertex-compat-1" || result.Response.Status != vcp.ResponseCompleted {
			t.Fatalf("unexpected Vertex-compatible result: %#v", result)
		}
	})

	t.Run("streamGenerateContent", func(t *testing.T) {
		driver, execution := newVertexCompatDriverExecution(t, true, func(request *http.Request) (*http.Response, error) {
			verifyVertexCompatExecutionRequest(t, request, "/compat-root/v1/publishers/google/models/gemini-test:streamGenerateContent", "alt=sse")
			if request.Header.Get("Accept") != "text/event-stream" {
				t.Errorf("unexpected stream Accept header %q", request.Header.Get("Accept"))
			}
			body := "data: {\"responseId\":\"vertex-compat-2\",\"candidates\":[{\"index\":0,\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"Hello\"}]},\"finishReason\":\"STOP\"}]}\n\n"
			return vertexHTTPResponse(request, http.StatusOK, "text/event-stream", body), nil
		})
		result, errExecute := driver.Execute(context.Background(), execution)
		if errExecute != nil {
			t.Fatalf("Execute() error = %v", errExecute)
		}
		if result.UpstreamResponseID != "vertex-compat-2" || result.Response.Status != vcp.ResponseCompleted {
			t.Fatalf("unexpected Vertex-compatible stream result: %#v", result)
		}
	})

	t.Run("countTokens", func(t *testing.T) {
		driver, execution := newVertexCompatDriverExecution(t, false, func(request *http.Request) (*http.Response, error) {
			verifyVertexCompatExecutionRequest(t, request, "/compat-root/v1/publishers/google/models/gemini-test:countTokens", "")
			body, errRead := io.ReadAll(request.Body)
			if errRead != nil {
				t.Errorf("read countTokens body: %v", errRead)
			}
			if strings.Contains(string(body), "generateContentRequest") {
				t.Errorf("Vertex-compatible countTokens body used the AI Studio wrapper: %s", body)
			}
			var upstream aistudio.GenerateContentRequest
			if errDecode := json.Unmarshal(body, &upstream); errDecode != nil || len(upstream.Contents) != 1 {
				t.Errorf("decode direct Vertex-compatible body: request=%#v error=%v", upstream, errDecode)
			}
			return vertexHTTPResponse(request, http.StatusOK, "application/json", `{"totalTokens":19,"cachedContentTokenCount":4}`), nil
		})
		result, errCount := driver.CountTokens(context.Background(), execution)
		if errCount != nil {
			t.Fatalf("CountTokens() error = %v", errCount)
		}
		if result.TotalTokens == nil || *result.TotalTokens != 19 || result.Usage.CacheReadTokens == nil || *result.Usage.CacheReadTokens != 4 || result.Usage.AccountingBasis != "vertex_compat_count_tokens" {
			t.Fatalf("unexpected Vertex-compatible token count: %#v", result)
		}
	})
}

// TestVertexCompatDriverRejectsWrongAuthAndImageOutput verifies the fixed header carrier and VCP resource boundary are enforced before network traffic.
// TestVertexCompatDriverRejectsWrongAuthAndImageOutput 验证固定 Header 载体与 VCP 资源边界会在网络流量前被强制执行。
func TestVertexCompatDriverRejectsWrongAuthAndImageOutput(t *testing.T) {
	var networkReached atomic.Bool
	driver, execution := newVertexCompatDriverExecution(t, false, func(_ *http.Request) (*http.Response, error) {
		networkReached.Store(true)
		return nil, errors.New("unexpected network request")
	})
	execution.Definition.AuthMethods[0].Type = providerconfig.AuthMethodBearer
	if _, errExecute := driver.Execute(context.Background(), execution); !errors.Is(errExecute, provider.ErrExecutionBinding) {
		t.Fatalf("wrong-auth Execute() error = %v, want ErrExecutionBinding", errExecute)
	}
	execution.Definition.AuthMethods[0].Type = providerconfig.AuthMethodHeaderKey
	execution.Binding.Target.UpstreamModelID = "imagen-4.0-generate-001"
	if _, errExecute := driver.Execute(context.Background(), execution); !errors.Is(errExecute, ErrInvalidVertexCompatDriver) {
		t.Fatalf("image Execute() error = %v, want ErrInvalidVertexCompatDriver", errExecute)
	}
	if networkReached.Load() {
		t.Fatal("Vertex-compatible preflight rejection reached the network")
	}
}

// newVertexCompatDriverExecution creates one custom API-key Driver and immutable exact-target execution fixture.
// newVertexCompatDriverExecution 创建一个自定义 API Key Driver 与不可变精确 Target 执行 Fixture。
func newVertexCompatDriverExecution(t *testing.T, stream bool, roundTrip vertexRoundTripFunc) (*VertexCompatDriver, provider.ExecutionRequest) {
	t.Helper()
	baseDriver, execution := newVertexDriverExecution(t, stream, roundTrip)
	driver, errDriver := NewVertexCompatDriver("definition-vertex", baseDriver.client, aiStudioDriverCapabilities())
	if errDriver != nil {
		t.Fatalf("create Vertex-compatible driver: %v", errDriver)
	}
	execution.Binding.Endpoint.BaseURL = "https://vertex-compat.example/compat-root"
	execution.Binding.Endpoint.Region = ""
	execution.Binding.Credential.AuthMethodID = "default"
	execution.Binding.Credential.ScopeRefs = nil
	execution.Definition = providerconfig.ProviderDefinition{
		ID: "definition-vertex", Kind: providerconfig.DefinitionKindCustom, ProtocolProfileID: aistudio.ProfileID,
		EndpointProfileID: providerconfig.CustomEndpointProfileVertexCompatibility, AuthMethodIDs: []string{"default"}, RuntimeReady: true,
		AuthMethods: []providerconfig.AuthMethodDefinition{{ID: "default", Type: providerconfig.AuthMethodHeaderKey}}, Revision: 1,
	}
	return driver, execution
}

// verifyVertexCompatExecutionRequest validates CLIProxyAPI's exact custom base-path and x-goog-api-key behavior.
// verifyVertexCompatExecutionRequest 校验 CLIProxyAPI 精确的自定义 Base Path 与 x-goog-api-key 行为。
func verifyVertexCompatExecutionRequest(t *testing.T, request *http.Request, expectedPath string, expectedQuery string) {
	t.Helper()
	if request.Method != http.MethodPost || request.URL.Scheme != "https" || request.URL.Host != "vertex-compat.example" || request.URL.Path != expectedPath || request.URL.RawQuery != expectedQuery {
		t.Errorf("unexpected Vertex-compatible request: %s %s", request.Method, request.URL.String())
	}
	if request.Header.Get("X-Goog-Api-Key") != "vertex-access-token" || request.Header.Get("Authorization") != "" {
		t.Errorf("unexpected Vertex-compatible authentication headers: %#v", request.Header)
	}
}
