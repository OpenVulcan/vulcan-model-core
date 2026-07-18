package translatedresponses_test

import (
	"context"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/protocol/anthropic/messages"
	"github.com/OpenVulcan/vulcan-model-core/internal/protocol/google/antigravity"
	"github.com/OpenVulcan/vulcan-model-core/internal/protocol/google/interactions"
	"github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/codex"
	openairesponses "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/responses"
	translatedresponses "github.com/OpenVulcan/vulcan-model-core/internal/protocol/translatedresponses"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
	"github.com/tidwall/gjson"
)

// TestProjectRequestUsesCopiedProtocolTransformers verifies every missing profile crosses the copied request implementation.
// TestProjectRequestUsesCopiedProtocolTransformers 验证每个缺失 Profile 都经过复制的请求实现。
func TestProjectRequestUsesCopiedProtocolTransformers(t *testing.T) {
	// cases defines copied wire facts that uniquely identify each target transformer.
	// cases 定义能够唯一标识每个目标转换器的复制 wire 事实。
	cases := []struct {
		name        string
		profile     translatedresponses.Profile
		assertField string
		assertValue string
	}{
		{name: "claude", profile: messages.Profile(), assertField: "messages.0.role", assertValue: "user"},
		{name: "codex", profile: codex.Profile(), assertField: "store", assertValue: "false"},
		{name: "interactions", profile: interactions.Profile(), assertField: "input.0.type", assertValue: "user_input"},
		{name: "antigravity", profile: antigravity.Profile(), assertField: "project", assertValue: ""},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			// projected is the exact copied translator output for a shared canonical request.
			// projected 是共享规范请求对应的精确复制转换器输出。
			projected, errProject := translatedresponses.ProjectRequest(testCase.profile, bridgeRequest(false), bridgeTarget(testCase.profile.ID), bridgeCapabilities(), "lineage-1", "", false, bridgeNow())
			if errProject != nil {
				t.Fatalf("ProjectRequest() error = %v", errProject)
			}
			// field is the unique copied wire field selected by the table case.
			// field 是表格用例选定的唯一复制 wire 字段。
			field := gjson.GetBytes(projected.UpstreamJSON, testCase.assertField)
			if !field.Exists() && testCase.assertField != "project" {
				t.Fatalf("translated request missing %q: %s", testCase.assertField, projected.UpstreamJSON)
			}
			if field.String() != testCase.assertValue {
				t.Fatalf("translated request %s = %q, want %q: %s", testCase.assertField, field.String(), testCase.assertValue, projected.UpstreamJSON)
			}
		})
	}
}

// TestDecodeNonStreamUsesCopiedProtocolTransformers verifies all four upstream response schemas return canonical terminal state.
// TestDecodeNonStreamUsesCopiedProtocolTransformers 验证四种上游响应 Schema 均返回规范终态。
func TestDecodeNonStreamUsesCopiedProtocolTransformers(t *testing.T) {
	// cases preserves upstream response fixtures shaped exactly like copied translator regression inputs.
	// cases 保留与复制转换器回归输入形态完全一致的上游响应夹具。
	cases := []struct {
		name       string
		profile    translatedresponses.Profile
		raw        string
		wantStatus vcp.ResponseStatus
		wantText   string
	}{
		{
			name: "claude", profile: messages.Profile(), wantStatus: vcp.ResponseCompleted, wantText: "ok",
			raw: "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"usage\":{\"input_tokens\":1,\"output_tokens\":0}}}\n" +
				"data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n" +
				"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"ok\"}}\n" +
				"data: {\"type\":\"content_block_stop\",\"index\":0}\n" +
				"data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":1}}\n" +
				"data: {\"type\":\"message_stop\"}",
		},
		{
			name: "codex", profile: codex.Profile(), wantStatus: vcp.ResponseIncomplete,
			raw: `{"type":"response.incomplete","response":{"id":"resp_1","status":"incomplete","incomplete_details":{"reason":"max_output_tokens"},"output":[],"usage":{"input_tokens":1,"output_tokens":2,"total_tokens":3}}}`,
		},
		{
			name: "interactions", profile: interactions.Profile(), wantStatus: vcp.ResponseCompleted, wantText: "ok",
			raw: `{"id":"interaction_1","object":"interaction","status":"completed","steps":[{"type":"model_output","content":[{"text":"ok"}]}],"usage":{"input_tokens":1,"output_tokens":2,"total_tokens":3}}`,
		},
		{
			name: "antigravity", profile: antigravity.Profile(), wantStatus: vcp.ResponseCompleted, wantText: "ok",
			raw: `{"response":{"responseId":"response_1","candidates":[{"content":{"role":"model","parts":[{"text":"ok"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":1,"candidatesTokenCount":1,"totalTokenCount":2}}}`,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			// projected supplies the original and translated requests needed by stateful upstream converters.
			// projected 提供有状态上游转换器所需的原始请求和转换后请求。
			projected, errProject := translatedresponses.ProjectRequest(testCase.profile, bridgeRequest(false), bridgeTarget(testCase.profile.ID), bridgeCapabilities(), "lineage-1", "", testCase.profile.Format.String() == "claude", bridgeNow())
			if errProject != nil {
				t.Fatalf("ProjectRequest() error = %v", errProject)
			}
			// decoded is the canonical result after copied response translation.
			// decoded 是复制响应转换后的规范结果。
			decoded, errDecode := translatedresponses.DecodeNonStream(context.Background(), testCase.profile, projected, []byte(testCase.raw), projected.Base.Report.ResponseID, bridgeTarget(testCase.profile.ID).UpstreamModelID, bridgeNow())
			if errDecode != nil {
				t.Fatalf("DecodeNonStream() error = %v", errDecode)
			}
			if decoded.Response.Status != testCase.wantStatus {
				t.Fatalf("response status = %q, want %q", decoded.Response.Status, testCase.wantStatus)
			}
			if testCase.wantText != "" {
				if len(decoded.Response.Items) == 0 || len(decoded.Response.Items[0].Content) == 0 || decoded.Response.Items[0].Content[0].Text != testCase.wantText {
					t.Fatalf("decoded response = %#v, want text %q", decoded.Response, testCase.wantText)
				}
			}
		})
	}
}

// bridgeNow returns the deterministic timestamp shared by bridge tests.
// bridgeNow 返回桥接测试共享的确定性时间戳。
func bridgeNow() time.Time {
	return time.Date(2026, time.July, 18, 0, 0, 0, 0, time.UTC)
}

// bridgeTarget returns one complete immutable target for the supplied translated profile.
// bridgeTarget 返回给定转换 Profile 对应的完整不可变 Target。
func bridgeTarget(profileID string) resolve.Target {
	return resolve.Target{
		ProviderDefinitionID: "definition-1", ProviderInstanceID: "instance-1", ChannelID: "channel-1", EndpointID: "endpoint-1", CredentialID: "credential-1",
		ProviderModelID: "model-1", OfferingID: "offering-1", ExecutionProfileID: profileID, UpstreamModelID: "model-test", CatalogRevision: 1,
	}
}

// bridgeRequest returns one valid canonical text request for translated protocol tests.
// bridgeRequest 返回转换协议测试使用的一条有效规范文本请求。
func bridgeRequest(stream bool) vcp.VulcanRequest {
	return vcp.VulcanRequest{
		ProtocolVersion: vcp.ProtocolVersion, RequestID: "request-1", Stream: stream,
		ModelSelection: vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: "instance-1", ProviderModelID: "model-1"},
		Context: []vcp.ContextItem{{
			ItemID: "user-item-1", Sequence: 1, Kind: vcp.ContextMessage, Authority: vcp.AuthorityUser, Actor: vcp.ActorEndUser,
			Placement: vcp.PlacementTranscript, Activation: vcp.Activation{Mode: vcp.ActivationRequestStart}, Visibility: vcp.VisibilityModel,
			Content: []vcp.ContentBlock{{Type: vcp.ContentText, Text: "Hello"}}, Message: &vcp.MessageItem{},
		}},
		CachePolicy:             vcp.CachePolicy{Strategy: vcp.CacheRegular, OnUnsupported: vcp.CacheUnsupportedReject},
		ContextManagementPolicy: vcp.ContextManagementPolicy{Mode: vcp.ContextManagementRegular},
		CapabilityPolicy:        vcp.CapabilityPolicy{ExecutionMode: vcp.CapabilityMaximize, OptionalOnUnsupported: vcp.OptionalOmit},
	}
}

// bridgeCapabilities returns the complete verified capability fixture used by copied translator tests.
// bridgeCapabilities 返回复制转换器测试使用的完整已验证能力夹具。
func bridgeCapabilities() openairesponses.ProfileCapabilities {
	return openairesponses.ProfileCapabilities{
		NativeSystemPreamble: true, NativeDeveloper: true, NativeInlineSystem: true, StructuredTools: true, NativeCustomTools: true,
		NativeToolNamespaces: true, ParallelTools: true, StreamingToolArguments: true, StrictJSONSchema: true, Reasoning: true,
		ReasoningContinuation: true, NativeWebSearch: true,
	}
}
