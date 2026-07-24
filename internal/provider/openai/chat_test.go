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

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	chatprofile "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/chat"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
	"github.com/tidwall/gjson"
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

// TestChatDriverAppliesOfferingRequestProjection verifies configured reasoning mutations reach the final outbound wire body.
// TestChatDriverAppliesOfferingRequestProjection 验证已配置的推理变更会到达最终出站 Wire Body。
func TestChatDriverAppliesOfferingRequestProjection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, errRead := io.ReadAll(request.Body)
		if errRead != nil {
			t.Errorf("read request: %v", errRead)
		}
		if gjson.GetBytes(body, "thinking.type").String() != "enabled" || gjson.GetBytes(body, "reasoning_effort").String() != "high" {
			t.Errorf("projected request = %s", body)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"id":"chat-projected","choices":[{"index":0,"message":{"role":"assistant","content":"Hello"},"finish_reason":"stop"}]}`)
	}))
	defer server.Close()

	driver, execution := newChatDriverExecution(t, server.URL, false)
	execution.Request.ReasoningPolicy.Effort = "high"
	execution.Binding.Target.ModelCapabilities = catalog.ModelCapabilities{Reasoning: catalog.CapabilityNative, ReasoningEfforts: []string{"high"}}
	execution.Binding.Target.RequestProjection = catalog.RequestProjection{Reasoning: catalog.ReasoningRequestProjection{Effort: []catalog.ReasoningParameterRule{{
		Value: "high", Set: []catalog.PayloadParameter{{Path: "thinking.type", Value: json.RawMessage(`"enabled"`)}, {Path: "reasoning_effort", Value: json.RawMessage(`"high"`)}},
	}}}}
	if _, errExecute := driver.Execute(context.Background(), execution); errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
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
	sink := &chatRecordingEventSink{}
	execution.EventSink = sink
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if result.UpstreamResponseID != "chat-upstream-2" || result.Response.Status != vcp.ResponseCompleted || len(result.Response.Items) != 1 || result.Response.Items[0].Content[0].Text != "Hello" {
		t.Fatalf("result = %#v", result)
	}
	if len(sink.events) == 0 || sink.events[0].Type != vcp.EventResponseStarted || sink.events[len(sink.events)-1].Type != vcp.EventResponseCompleted {
		t.Fatalf("stream event order = %#v", sink.events)
	}
	startedCount := 0
	for _, event := range sink.events {
		if event.Type == vcp.EventResponseStarted {
			startedCount++
		}
	}
	if startedCount != 1 {
		t.Fatalf("response.started count = %d, want 1", startedCount)
	}
}

// TestChatDriverStreamsMixedAudioOutput verifies the reviewed Alibaba PCM chunks become one bounded Router-owned WAV resource.
// TestChatDriverStreamsMixedAudioOutput 验证已审核的阿里云 PCM 分片会成为一个有界且由 Router 所有的 WAV 资源。
func TestChatDriverStreamsMixedAudioOutput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var upstream chatprofile.Request
		if errDecode := json.NewDecoder(request.Body).Decode(&upstream); errDecode != nil {
			t.Errorf("decode request: %v", errDecode)
		}
		if !upstream.Stream || len(upstream.Modalities) != 2 || upstream.Modalities[0] != "text" || upstream.Modalities[1] != "audio" || upstream.Audio == nil || upstream.Audio.Voice != "Tina" || upstream.Audio.Format != "wav" {
			t.Errorf("upstream request = %#v", upstream)
		}
		writer.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(writer, "data: {\"id\":\"chat-omni\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello\",\"audio\":{\"data\":\"YWJj\"}}}]}\n\ndata: {\"id\":\"chat-omni\",\"choices\":[{\"index\":0,\"delta\":{\"audio\":{\"data\":\"ZA==\"}},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
	}))
	defer server.Close()

	driver, execution := newChatDriverExecution(t, server.URL, true)
	driver.capabilities.MixedAudioOutput = true
	execution.Request.GenerationPolicy.OutputModalities = []string{"text", "audio"}
	execution.Request.GenerationPolicy.AudioOutput = &vcp.ConversationAudioOutput{VoiceID: "Tina", OutputFormat: "wav"}
	sink := &chatRecordingResourceSink{}
	execution.ResourceSink = sink
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if len(result.GeneratedResources) != 1 || result.GeneratedResources[0].MIMEType != "audio/wav" || string(result.GeneratedResources[0].Data[:4]) != "RIFF" || string(result.GeneratedResources[0].Data[8:12]) != "WAVE" || string(result.GeneratedResources[0].Data[44:]) != "abcd" {
		t.Fatalf("generated resources = %#v", result.GeneratedResources)
	}
	if len(sink.progress) != 2 || sink.progress[0].PartialBytes != 3 || sink.progress[1].PartialBytes != 4 {
		t.Fatalf("resource progress = %#v", sink.progress)
	}
}

// TestChatAudioAccumulatorEnforcesCompleteWAVBudget verifies the header participates in the caller's hard byte ceiling.
// TestChatAudioAccumulatorEnforcesCompleteWAVBudget 验证 WAV 头参与调用方的硬字节上限。
func TestChatAudioAccumulatorEnforcesCompleteWAVBudget(t *testing.T) {
	maximumBytes := int64(47)
	accumulator, errNew := newChatAudioAccumulator(&maximumBytes, nil)
	if errNew != nil {
		t.Fatalf("newChatAudioAccumulator() error = %v", errNew)
	}
	if errPush := accumulator.Push(context.Background(), &chatprofile.AudioOutputDelta{Data: "YWJjZA=="}); !errors.Is(errPush, provider.ErrOutputBudgetExceeded) {
		t.Fatalf("Push() error = %v, want ErrOutputBudgetExceeded", errPush)
	}
}

// TestPushChatChoiceAudioRejectsUnevidencedCarriers verifies mixed audio cannot concatenate multiple choices or a terminal message payload.
// TestPushChatChoiceAudioRejectsUnevidencedCarriers 验证混合音频不能拼接多个候选或终态消息载荷。
func TestPushChatChoiceAudioRejectsUnevidencedCarriers(t *testing.T) {
	for _, choices := range [][]chatprofile.Choice{
		{{Index: 1, Delta: &chatprofile.Delta{Audio: &chatprofile.AudioOutputDelta{Data: "YQ=="}}}},
		{{Index: 0, Message: &chatprofile.AssistantMessage{Audio: &chatprofile.AudioOutputDelta{Data: "YQ=="}}}},
	} {
		accumulator, errNew := newChatAudioAccumulator(nil, nil)
		if errNew != nil {
			t.Fatalf("newChatAudioAccumulator() error = %v", errNew)
		}
		if errPush := pushChatChoiceAudio(context.Background(), accumulator, choices); !errors.Is(errPush, chatprofile.ErrInvalidUpstreamResponse) {
			t.Fatalf("pushChatChoiceAudio() error = %v, want ErrInvalidUpstreamResponse", errPush)
		}
	}
}

// chatRecordingResourceSink records exact streaming byte observations.
// chatRecordingResourceSink 记录精确的流式字节观测。
type chatRecordingResourceSink struct {
	// progress preserves observations in causal order.
	// progress 按因果顺序保留观测。
	progress []provider.ResourceProgress
}

// chatRecordingEventSink records provider semantic events in exact delivery order.
// chatRecordingEventSink 按精确交付顺序记录供应商语义事件。
type chatRecordingEventSink struct {
	// events preserves every emitted semantic event.
	// events 保留每个已发出的语义事件。
	events []vcp.Event
}

// Emit records one provider semantic event without changing its fields.
// Emit 记录一个供应商语义事件且不修改其字段。
func (s *chatRecordingEventSink) Emit(_ context.Context, event vcp.Event) error {
	s.events = append(s.events, event)
	return nil
}

// EmitResourceProgress records one streaming byte observation.
// EmitResourceProgress 记录一项流式字节观测。
func (s *chatRecordingResourceSink) EmitResourceProgress(_ context.Context, progress provider.ResourceProgress) error {
	s.progress = append(s.progress, progress)
	return nil
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

// TestBearerChatDriverAtPathExecutesProviderOwnedPath verifies a provider-owned normalized Chat path is preserved exactly.
// TestBearerChatDriverAtPathExecutesProviderOwnedPath 验证供应商拥有的规范化 Chat 路径会被精确保留。
func TestBearerChatDriverAtPathExecutesProviderOwnedPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/compatible-mode/v1/chat/completions" {
			t.Errorf("request path = %q", request.URL.Path)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"id":"chat-custom-path","choices":[{"index":0,"message":{"role":"assistant","content":"Hello"},"finish_reason":"stop"}]}`)
	}))
	defer server.Close()

	baseDriver, execution := newChatDriverExecution(t, server.URL, false)
	driver, errDriver := NewBearerChatDriverAtPath("definition-1", chatTestProfileID, baseDriver.client, chatDriverCapabilities(), []providerconfig.AuthMethodType{providerconfig.AuthMethodAPIKey}, "/compatible-mode/v1/chat/completions")
	if errDriver != nil {
		t.Fatalf("NewBearerChatDriverAtPath() error = %v", errDriver)
	}
	result, errExecute := driver.Execute(context.Background(), execution)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if result.UpstreamResponseID != "chat-custom-path" {
		t.Fatalf("result = %#v", result)
	}
}

// TestBearerChatDriverAtPathRejectsUnnormalizedPaths verifies query strings, parent traversal, and non-Chat paths are rejected.
// TestBearerChatDriverAtPathRejectsUnnormalizedPaths 验证查询字符串、父级跳转和非 Chat 路径会被拒绝。
func TestBearerChatDriverAtPathRejectsUnnormalizedPaths(t *testing.T) {
	baseDriver, _ := newChatDriverExecution(t, "https://example.invalid", false)
	for _, endpointPath := range []string{"compatible-mode/v1/chat/completions", "/compatible-mode/../v1/chat/completions", "/v1/chat/completions?trace=true", "/v1/responses"} {
		if _, errDriver := NewBearerChatDriverAtPath("definition-1", chatTestProfileID, baseDriver.client, chatDriverCapabilities(), []providerconfig.AuthMethodType{providerconfig.AuthMethodAPIKey}, endpointPath); !errors.Is(errDriver, ErrInvalidChatDriver) {
			t.Errorf("endpoint path %q error = %v, want ErrInvalidChatDriver", endpointPath, errDriver)
		}
	}
}

// TestBearerChatDriverRejectsReasoningAdapterCapabilityWithoutAdapter verifies construction cannot publish a provider mutation that has no wire consumer.
// TestBearerChatDriverRejectsReasoningAdapterCapabilityWithoutAdapter 验证构造阶段不能发布没有线路消费者的供应商变更能力。
func TestBearerChatDriverRejectsReasoningAdapterCapabilityWithoutAdapter(t *testing.T) {
	baseDriver, _ := newChatDriverExecution(t, "https://example.invalid", false)
	for _, capabilities := range []chatprofile.ProfileCapabilities{
		{Reasoning: true, ProviderReasoningSwitchAdapter: true},
		{Reasoning: true, ProviderReasoningBudgetAdapter: true},
	} {
		if _, errDriver := NewBearerChatDriver("definition-1", chatTestProfileID, baseDriver.client, capabilities, []providerconfig.AuthMethodType{providerconfig.AuthMethodAPIKey}); !errors.Is(errDriver, ErrInvalidChatDriver) {
			t.Fatalf("NewBearerChatDriver() error = %v, want ErrInvalidChatDriver", errDriver)
		}
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
