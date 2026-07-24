package kimi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	chatprofile "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/chat"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

// TestCodingChatAdapterPreservesOfficialModelsAndForcesK27Thinking verifies both Coding aliases remain exact and cannot silently route back to K2.6.
// TestCodingChatAdapterPreservesOfficialModelsAndForcesK27Thinking 验证两个 Coding 别名保持精确且不会静默回退到 K2.6。
func TestCodingChatAdapterPreservesOfficialModelsAndForcesK27Thinking(t *testing.T) {
	adapter, errAdapter := NewCodingChatAdapter(secret.NewMemoryStore())
	if errAdapter != nil {
		t.Fatalf("NewCodingChatAdapter() error = %v", errAdapter)
	}
	execution := provider.ExecutionRequest{Definition: providerconfig.ProviderDefinition{AuthMethods: []providerconfig.AuthMethodDefinition{{ID: "api_key", Type: providerconfig.AuthMethodAPIKey}}}}
	execution.Binding.Credential.AuthMethodID = "api_key"
	for _, modelID := range []string{"kimi-for-coding", "kimi-for-coding-highspeed"} {
		request := chatprofile.Request{Model: modelID, ReasoningEffort: "high"}
		if _, errAdapt := adapter.Adapt(context.Background(), execution, &request); errAdapt != nil {
			t.Fatalf("Adapt(%s) error = %v", modelID, errAdapt)
		}
		if request.Model != modelID || request.ReasoningEffort != "" || request.Thinking == nil || request.Thinking.Type != chatprofile.ThinkingEnabled {
			t.Fatalf("Adapt(%s) request = %#v", modelID, request)
		}
		encoded, errMarshal := json.Marshal(request)
		if errMarshal != nil {
			t.Fatalf("Marshal(%s) error = %v", modelID, errMarshal)
		}
		if strings.Contains(string(encoded), "reasoning_effort") || !strings.Contains(string(encoded), `"thinking":{"type":"enabled"}`) {
			t.Fatalf("Adapt(%s) JSON = %s", modelID, encoded)
		}
	}
}

// TestKimiThinkingAdaptersUseCurrentContract verifies K3 and Open Platform requests translate explicit reasoning without inventing a default.
// TestKimiThinkingAdaptersUseCurrentContract 验证 K3 与开放平台请求会转换显式推理且不会臆造默认行为。
func TestKimiThinkingAdaptersUseCurrentContract(t *testing.T) {
	openPlatform := NewOpenPlatformChatAdapter()
	request := chatprofile.Request{Model: "kimi-k2.7-code", ReasoningEffort: "low"}
	if _, errAdapt := openPlatform.Adapt(context.Background(), provider.ExecutionRequest{}, &request); errAdapt != nil {
		t.Fatalf("Open Platform Adapt() error = %v", errAdapt)
	}
	if request.ReasoningEffort != "" || request.Thinking == nil || request.Thinking.Type != chatprofile.ThinkingEnabled {
		t.Fatalf("Open Platform request = %#v", request)
	}
	k3 := chatprofile.Request{Model: "k3"}
	applyKimiThinking(&k3)
	if k3.Thinking != nil || k3.ReasoningEffort != "" {
		t.Fatalf("implicit K3 request = %#v", k3)
	}
}

// TestCodingChatAdapterClassifiesOnlyExactAccessTermination verifies Kimi's exhausted-cycle identity is not generalized to every forbidden response.
// TestCodingChatAdapterClassifiesOnlyExactAccessTermination 验证 Kimi 周期额度耗尽身份不会被泛化到每个禁止访问响应。
func TestCodingChatAdapterClassifiesOnlyExactAccessTermination(t *testing.T) {
	adapter, errAdapter := NewCodingChatAdapter(secret.NewMemoryStore())
	if errAdapter != nil {
		t.Fatalf("NewCodingChatAdapter() error = %v", errAdapter)
	}
	now := time.Date(2026, 7, 24, 5, 0, 0, 0, time.UTC)
	classified, matched := adapter.ClassifyChatError(transport.StatusError{StatusCode: http.StatusForbidden, ProviderType: codingAccessTerminatedErrorType}, resolve.Target{}, now)
	if !matched || classified.Category != "quota_exhausted" || classified.Scope != provider.ErrorScopeCredential || classified.Action != provider.RetryOtherCredential || classified.RuleID != "kimi_access_terminated_error" || classified.RetryAt == nil || !classified.RetryAt.Equal(now.Add(codingAccessTerminatedCooldown)) {
		t.Fatalf("Kimi access termination classification = %#v matched=%t", classified, matched)
	}
	if generic, genericMatched := adapter.ClassifyChatError(transport.StatusError{StatusCode: http.StatusForbidden, ProviderType: "permission_denied"}, resolve.Target{}, now); genericMatched || generic != (provider.ClassifiedError{}) {
		t.Fatalf("generic forbidden classification = %#v matched=%t", generic, genericMatched)
	}
}
