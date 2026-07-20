// OpenRouter native fixtures preserve source-project endpoint and authentication behavior.
// OpenRouter 原生夹具保留来源项目的端点与认证行为。
// Source: D:/openvulcan/vulcan-model-router/internal/runtime/executor/openrouter_executor.go.
// 来源：D:/openvulcan/vulcan-model-router/internal/runtime/executor/openrouter_executor.go。
package openrouter

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestEmbeddingDriverPreservesBatchIdentity verifies the source path, bearer authentication, typed fields, and reordered indexes.
// TestEmbeddingDriverPreservesBatchIdentity 验证来源路径、Bearer 认证、类型化字段及重排索引。
func TestEmbeddingDriverPreservesBatchIdentity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/embeddings" || request.Header.Get("Authorization") != "Bearer test-secret" {
			t.Errorf("request = %s %s authorization=%q", request.Method, request.URL.Path, request.Header.Get("Authorization"))
		}
		var upstream openRouterEmbeddingRequest
		if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil {
			t.Errorf("decode request: %v", errDecode)
		}
		if upstream.Model != "openai/text-embedding-3-small" || upstream.EncodingFormat != "float" || upstream.InputType != "search_document" || len(upstream.Input) != 2 || upstream.Input[0] != "first" || upstream.Input[1] != "second" {
			t.Errorf("upstream request = %#v", upstream)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"id":"embed-1","model":"openai/text-embedding-3-small","data":[{"index":1,"embedding":[3,4]},{"index":0,"embedding":[1,2]}]}`)
	}))
	defer server.Close()

	execution := newNativeExecution(t, server.URL, EmbeddingActionBindingID, EmbeddingProtocolProfileID, vcp.OperationEmbeddingCreate)
	first := "first"
	second := "second"
	execution.Execution.Payload.EmbeddingCreate = &vcp.EmbeddingOperation{Inputs: []vcp.EmbeddingInput{{ID: "input-first", Text: &first}, {ID: "input-second", Text: &second}}, InputTask: vcp.EmbeddingTaskDocument, OutputKind: vcp.EmbeddingVectorDense, Encoding: vcp.EmbeddingEncodingFloat}
	client, secretReference := nativeTransportClient(t)
	execution.Binding.Credential.SecretRef = secretReference
	driver, errDriver := NewEmbeddingDriver("definition-openrouter", client)
	if errDriver != nil {
		t.Fatalf("NewEmbeddingDriver() error = %v", errDriver)
	}
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if result.UpstreamResponseID != "embed-1" || len(result.Embeddings) != 2 || result.Embeddings[0].InputID != "input-first" || result.Embeddings[0].Dense.Values[0] != 1 || result.Embeddings[1].InputID != "input-second" || result.Embeddings[1].Dense.Values[0] != 3 {
		t.Fatalf("result = %#v", result)
	}
}

// TestRerankDriverPreservesRawScores verifies the source path and maps provider rank to immutable candidate identities.
// TestRerankDriverPreservesRawScores 验证来源路径并将供应商排序映射到不可变候选身份。
func TestRerankDriverPreservesRawScores(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/rerank" || request.Header.Get("Authorization") != "Bearer test-secret" {
			t.Errorf("request = %s %s authorization=%q", request.Method, request.URL.Path, request.Header.Get("Authorization"))
		}
		var upstream openRouterRerankRequest
		if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil {
			t.Errorf("decode request: %v", errDecode)
		}
		if upstream.Model != "cohere/rerank-v3.5" || upstream.Query != "capital" || len(upstream.Documents) != 2 || upstream.TopN == nil || *upstream.TopN != 1 {
			t.Errorf("upstream request = %#v", upstream)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"id":"rerank-1","results":[{"index":1,"relevance_score":0.987654321}]}`)
	}))
	defer server.Close()

	execution := newNativeExecution(t, server.URL, RerankActionBindingID, RerankProtocolProfileID, vcp.OperationRerankDocuments)
	query := "capital"
	first := "Berlin"
	second := "Paris"
	topN := 1
	execution.Execution.Payload.RerankDocuments = &vcp.RerankOperation{Query: vcp.RerankQuery{ID: "query-1", Content: vcp.RerankContent{Text: &query}}, Candidates: []vcp.RerankCandidate{{ID: "candidate-berlin", Content: vcp.RerankContent{Text: &first}}, {ID: "candidate-paris", Content: vcp.RerankContent{Text: &second}}}, TopN: &topN, Truncation: vcp.RerankTruncationNone}
	execution.Binding.Target.UpstreamModelID = "cohere/rerank-v3.5"
	client, secretReference := nativeTransportClient(t)
	execution.Binding.Credential.SecretRef = secretReference
	driver, errDriver := NewRerankDriver("definition-openrouter", client)
	if errDriver != nil {
		t.Fatalf("NewRerankDriver() error = %v", errDriver)
	}
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if result.UpstreamResponseID != "rerank-1" || len(result.Rerank) != 1 || result.Rerank[0].CandidateID != "candidate-paris" || result.Rerank[0].OriginalIndex != 1 || result.Rerank[0].Rank != 1 || result.Rerank[0].ProviderScore != 0.987654321 || result.Rerank[0].ScoreSemantics != openRouterScoreSemantics {
		t.Fatalf("result = %#v", result)
	}
}

// TestNativeDriverRejectsStreamingBeforeNetwork verifies source-proven non-streaming behavior remains explicit.
// TestNativeDriverRejectsStreamingBeforeNetwork 验证来源已证明的非流式行为保持显式。
func TestNativeDriverRejectsStreamingBeforeNetwork(t *testing.T) {
	var reached atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached.Store(true) }))
	defer server.Close()
	execution := newNativeExecution(t, server.URL, EmbeddingActionBindingID, EmbeddingProtocolProfileID, vcp.OperationEmbeddingCreate)
	text := "hello"
	execution.Execution.Stream = true
	execution.Execution.Payload.EmbeddingCreate = &vcp.EmbeddingOperation{Inputs: []vcp.EmbeddingInput{{ID: "input-1", Text: &text}}, InputTask: vcp.EmbeddingTaskProviderDefault, OutputKind: vcp.EmbeddingVectorDense, Encoding: vcp.EmbeddingEncodingFloat}
	client, secretReference := nativeTransportClient(t)
	execution.Binding.Credential.SecretRef = secretReference
	driver, errDriver := NewEmbeddingDriver("definition-openrouter", client)
	if errDriver != nil {
		t.Fatalf("NewEmbeddingDriver() error = %v", errDriver)
	}
	if _, errExecute := driver.Execute(context.Background(), execution); !errors.Is(errExecute, ErrUnsupportedInput) {
		t.Fatalf("Execute() error = %v, want ErrUnsupportedInput", errExecute)
	}
	if reached.Load() {
		t.Fatal("unexpected network request")
	}
}

// nativeTransportClient creates a target-bound client using the same secret reference as native fixtures.
// nativeTransportClient 使用与原生夹具相同的 Secret 引用创建 Target 绑定客户端。
func nativeTransportClient(t *testing.T) (*transport.Client, string) {
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
	return client, secretReference
}

// newNativeExecution creates one exact model action request with immutable provider ownership.
// newNativeExecution 创建一个具有不可变供应商所有权的精确模型动作请求。
func newNativeExecution(t *testing.T, baseURL string, actionID string, protocolProfileID string, operation vcp.OperationKind) provider.ExecutionRequest {
	t.Helper()
	now := time.Date(2026, time.July, 20, 0, 0, 0, 0, time.UTC)
	definition := providerconfig.ProviderDefinition{ID: "definition-openrouter", Kind: providerconfig.DefinitionKindSystem, ProtocolProfileID: "openai.chat.v1", AuthMethodIDs: []string{"api_key"}, RuntimeReady: true, AuthMethods: []providerconfig.AuthMethodDefinition{{ID: "api_key", Type: providerconfig.AuthMethodAPIKey}}, ActionBindings: []providerconfig.ProviderActionBinding{{ID: actionID, Operation: operation, DriverID: "openrouter", DriverVersion: "1", ProtocolProfileID: protocolProfileID, EndpointProfileID: "openrouter_native", AuthMethodIDs: []string{"api_key"}, Delivery: providerconfig.ActionDeliveryModes{Synchronous: true}, Revision: 1}}, Revision: 1}
	target := resolve.Target{SubjectKind: resolve.ExecutionSubjectModel, ProviderDefinitionID: definition.ID, ProviderInstanceID: "instance-openrouter", ChannelID: "openai.chat.v1", EndpointID: "endpoint-openrouter", CredentialID: "credential-openrouter", ProviderModelID: "model-openrouter", OfferingID: "offering-openrouter", ExecutionProfileID: "profile-openrouter", UpstreamModelID: "openai/text-embedding-3-small", Operation: operation, ActionBindingID: actionID, CatalogRevision: 1}
	request := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request-openrouter", Target: vcp.TargetSelection{Model: &vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: target.ProviderInstanceID, ProviderModelID: target.ProviderModelID, ExecutionProfileID: target.ExecutionProfileID}}, Operation: operation, Payload: vcp.OperationPayload{}}
	return provider.ExecutionRequest{Binding: transport.Binding{Target: target, Endpoint: providerconfig.Endpoint{ID: target.EndpointID, ProviderInstanceID: target.ProviderInstanceID, ChannelID: target.ChannelID, BaseURL: baseURL, Status: providerconfig.EndpointReady}, Credential: providerconfig.Credential{ID: target.CredentialID, ProviderInstanceID: target.ProviderInstanceID, AuthMethodID: "api_key", SecretRef: "secret-reference", Status: providerconfig.CredentialActive}}, Definition: definition, Execution: &request, LineageID: "lineage-openrouter", Now: now}
}
