// Stream fixtures cover behavior adapted from CLIProxyAPI commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// 流式夹具覆盖改编自 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66 的行为。
// Source path: internal/translator/gemini/claude/gemini_claude_response.go.
// 来源路径：internal/translator/gemini/claude/gemini_claude_response.go。
// The fixtures verify typed AI Studio SSE reconstruction without importing CLIProxyAPI translator runtime code.
// 夹具验证类型化 AI Studio SSE 重建，不导入 CLIProxyAPI Translator 运行时代码。
package aistudio

import (
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestStreamDecoderAccumulatesNameLessFunctionArguments verifies a named Gemini call can receive its complete argument object in a later name-less part.
// TestStreamDecoderAccumulatesNameLessFunctionArguments 验证具名 Gemini 调用可在后续无名称部分接收完整参数对象。
func TestStreamDecoderAccumulatesNameLessFunctionArguments(t *testing.T) {
	decoder, errNew := NewStreamDecoder("response-1", aiStudioNow(), []ToolReference{{WireName: "weather.lookup", Namespace: "weather", Name: "lookup"}})
	if errNew != nil {
		t.Fatalf("NewStreamDecoder() error = %v", errNew)
	}
	first := GenerateContentResponse{
		ResponseID: "upstream-response-1",
		Candidates: []Candidate{{
			Index: aiStudioInt(0), Content: &Content{Role: "model", Parts: []Part{{Text: "Hello "}, {FunctionCall: &FunctionCall{ID: "upstream-call-1", Name: "weather.lookup"}}}},
		}},
	}
	if _, errPush := decoder.Push(first); errPush != nil {
		t.Fatalf("Push(first) error = %v", errPush)
	}
	second := GenerateContentResponse{
		Candidates: []Candidate{{
			Index: aiStudioInt(0), Content: &Content{Role: "model", Parts: []Part{{FunctionCall: &FunctionCall{Args: []byte(`{"city":"Paris"}`)}}}}, FinishReason: "STOP",
		}},
		UsageMetadata: &UsageMetadata{PromptTokenCount: aiStudioInt64(5), CandidatesTokenCount: aiStudioInt64(3), TotalTokenCount: aiStudioInt64(8)},
	}
	if _, errPush := decoder.Push(second); errPush != nil {
		t.Fatalf("Push(second) error = %v", errPush)
	}
	response := decoder.Response()
	if response.Status != vcp.ResponseCompleted || response.FinishReason != "stop" || response.Usage == nil || response.Usage.TotalTokens == nil || *response.Usage.TotalTokens != 8 {
		t.Fatalf("response = %#v", response)
	}
	if decoder.UpstreamResponseID() != "upstream-response-1" {
		t.Fatalf("UpstreamResponseID() = %q", decoder.UpstreamResponseID())
	}
	if len(response.Items) != 2 || response.Items[0].Kind != vcp.ContextMessage || response.Items[0].Content[0].Text != "Hello " {
		t.Fatalf("text items = %#v", response.Items)
	}
	tool := response.Items[1]
	if tool.Kind != vcp.ContextToolCall || tool.ToolCall == nil || tool.ToolCall.Namespace != "weather" || tool.ToolCall.Name != "lookup" || tool.ToolCall.UpstreamID != "upstream-call-1" || tool.ToolCall.Arguments != `{"city":"Paris"}` || tool.ToolCall.Status != vcp.ToolCallCompleted {
		t.Fatalf("tool item = %#v", tool)
	}
	events := decoder.Events()
	if len(events) == 0 || events[len(events)-1].Type != vcp.EventResponseCompleted {
		t.Fatalf("events = %#v", events)
	}
}

// TestStreamDecoderReportsThoughtSignatureWithoutLeakingIt verifies opaque provider thought state is not emitted as normal content or continuation state.
// TestStreamDecoderReportsThoughtSignatureWithoutLeakingIt 验证不透明 Provider thought 状态不会作为普通内容或续接状态发出。
func TestStreamDecoderReportsThoughtSignatureWithoutLeakingIt(t *testing.T) {
	decoder, errNew := NewStreamDecoder("response-2", aiStudioNow(), nil)
	if errNew != nil {
		t.Fatalf("NewStreamDecoder() error = %v", errNew)
	}
	response := GenerateContentResponse{Candidates: []Candidate{{Content: &Content{Role: "model", Parts: []Part{{Text: "Reason", Thought: true, ThoughtSignature: "opaque-provider-state"}}}, FinishReason: "STOP"}}}
	if _, errPush := decoder.Push(response); errPush != nil {
		t.Fatalf("Push() error = %v", errPush)
	}
	snapshot := decoder.Response()
	if snapshot.Status != vcp.ResponseCompleted || len(snapshot.Items) != 1 || snapshot.Items[0].Kind != vcp.ContextReasoning || snapshot.Items[0].Content[0].Text != "Reason" {
		t.Fatalf("response = %#v", snapshot)
	}
	if !aiStudioContainsSummary(decoder.Report().ConversionSummary, "google_aistudio.thought_signature.provider_state_unavailable") {
		t.Fatalf("report = %#v", decoder.Report())
	}
}

// TestStreamDecoderIgnoresSignatureOnlyParts verifies a signature-only Gemini part cannot create a phantom empty VCP output item.
// TestStreamDecoderIgnoresSignatureOnlyParts 验证仅含签名的 Gemini Part 不会创建虚假的空 VCP 输出项。
func TestStreamDecoderIgnoresSignatureOnlyParts(t *testing.T) {
	decoder, errNew := NewStreamDecoder("response-signature-only", aiStudioNow(), nil)
	if errNew != nil {
		t.Fatalf("NewStreamDecoder() error = %v", errNew)
	}
	response := GenerateContentResponse{
		Candidates: []Candidate{{
			Content:      &Content{Role: "model", Parts: []Part{{ThoughtSignature: "opaque-provider-state"}}},
			FinishReason: "STOP",
		}},
	}
	if _, errPush := decoder.Push(response); errPush != nil {
		t.Fatalf("Push() error = %v", errPush)
	}
	snapshot := decoder.Response()
	if snapshot.Status != vcp.ResponseCompleted || len(snapshot.Items) != 0 {
		t.Fatalf("response = %#v", snapshot)
	}
	if !aiStudioContainsSummary(decoder.Report().ConversionSummary, "google_aistudio.thought_signature.provider_state_unavailable") {
		t.Fatalf("report = %#v", decoder.Report())
	}
}

// TestStreamDecoderRejectsNonModelCandidateContent verifies a provider candidate cannot silently project user-originated content as model output.
// TestStreamDecoderRejectsNonModelCandidateContent 验证 Provider 候选不能将 user 来源内容静默投影为模型输出。
func TestStreamDecoderRejectsNonModelCandidateContent(t *testing.T) {
	decoder, errNew := NewStreamDecoder("response-invalid-candidate-role", aiStudioNow(), nil)
	if errNew != nil {
		t.Fatalf("NewStreamDecoder() error = %v", errNew)
	}
	_, errPush := decoder.Push(GenerateContentResponse{Candidates: []Candidate{{Content: &Content{Role: "user", Parts: []Part{{Text: "must not become output"}}}, FinishReason: "STOP"}}})
	if !errors.Is(errPush, ErrInvalidUpstreamResponse) {
		t.Fatalf("Push() error = %v, want ErrInvalidUpstreamResponse", errPush)
	}
}

// TestStreamDecoderReportsUnrepresentedSafetyAndUsage verifies documented AI Studio response metadata is explicitly reported instead of silently discarded.
// TestStreamDecoderReportsUnrepresentedSafetyAndUsage 验证文档化 AI Studio 响应元数据会被显式报告，而不是被静默丢弃。
func TestStreamDecoderReportsUnrepresentedSafetyAndUsage(t *testing.T) {
	decoder, errNew := NewStreamDecoder("response-unrepresented-metadata", aiStudioNow(), nil)
	if errNew != nil {
		t.Fatalf("NewStreamDecoder() error = %v", errNew)
	}
	response := GenerateContentResponse{
		Candidates: []Candidate{{
			Content:       &Content{Role: "model", Parts: []Part{{Text: "Safe output"}}},
			FinishReason:  "STOP",
			SafetyRatings: []SafetyRating{{Category: "HARM_CATEGORY_DANGEROUS_CONTENT", Probability: "LOW"}},
		}},
		PromptFeedback: &PromptFeedback{SafetyRatings: []SafetyRating{{Category: "HARM_CATEGORY_HARASSMENT", Probability: "NEGLIGIBLE"}}},
		UsageMetadata: &UsageMetadata{
			ToolUsePromptTokenCount:    aiStudioInt64(2),
			PromptTokensDetails:        []ModalityTokenCount{{Modality: "TEXT", TokenCount: aiStudioInt64(4)}},
			ToolUsePromptTokensDetails: []ModalityTokenCount{{Modality: "TEXT", TokenCount: aiStudioInt64(2)}},
			ServiceTier:                "priority",
		},
	}
	if _, errPush := decoder.Push(response); errPush != nil {
		t.Fatalf("Push() error = %v", errPush)
	}
	// summaryCodes enumerate the safe audit records required for every unrepresentable documented metadata group in the fixture.
	// summaryCodes 枚举该夹具中每组不可表示文档化元数据所必需的安全审计记录。
	summaryCodes := []string{
		"google_aistudio.prompt_safety_ratings.omitted",
		"google_aistudio.candidate_safety_ratings.omitted",
		"google_aistudio.usage.tool_use_prompt_tokens.omitted",
		"google_aistudio.usage.modality_details.omitted",
		"google_aistudio.usage.service_tier.omitted",
	}
	for _, summaryCode := range summaryCodes {
		if !aiStudioContainsSummary(decoder.Report().ConversionSummary, summaryCode) {
			t.Fatalf("report = %#v, missing summary %q", decoder.Report(), summaryCode)
		}
	}
}

// TestStreamDecoderReportsUnrepresentedResponseMetadata verifies all documented response metadata without a VCP carrier is visible as a safe audit code.
// TestStreamDecoderReportsUnrepresentedResponseMetadata 验证所有没有 VCP 承载字段的文档化响应元数据都会作为安全审计代码可见。
func TestStreamDecoderReportsUnrepresentedResponseMetadata(t *testing.T) {
	// upstreamJSON contains each unsupported documented metadata group and one future candidate field without placing diagnostic content in the expected report.
	// upstreamJSON 包含每组不受支持的文档化元数据和一个未来 Candidate 字段，且不会将诊断内容放入预期报告。
	upstreamJSON := []byte(`{"modelVersion":"runtime-version","modelStatus":{},"candidates":[{"content":{"role":"model","parts":[{"text":"Visible text"}]},"finishReason":"STOP","citationMetadata":{},"tokenCount":3,"groundingAttributions":[{}],"groundingMetadata":{},"avgLogprobs":-0.25,"logprobsResult":{},"urlContextMetadata":{},"finishMessage":"provider diagnostic","futureCandidateMetadata":{}}]}`)
	var upstream GenerateContentResponse
	if errDecode := json.Unmarshal(upstreamJSON, &upstream); errDecode != nil {
		t.Fatalf("json.Unmarshal() error = %v", errDecode)
	}
	decoder, errNew := NewStreamDecoder("response-unrepresented-response-metadata", aiStudioNow(), nil)
	if errNew != nil {
		t.Fatalf("NewStreamDecoder() error = %v", errNew)
	}
	if _, errPush := decoder.Push(upstream); errPush != nil {
		t.Fatalf("Push() error = %v", errPush)
	}
	// summaryCodes enumerate every response metadata group whose values must not leak but whose omission must be auditable.
	// summaryCodes 枚举每组值不得泄露但其省略必须可审计的响应元数据。
	summaryCodes := []string{
		"google_aistudio.model_version.omitted",
		"google_aistudio.model_status.omitted",
		"google_aistudio.candidate_citation_metadata.omitted",
		"google_aistudio.candidate_token_count.omitted",
		"google_aistudio.candidate_grounding_metadata.omitted",
		"google_aistudio.candidate_logprobs.omitted",
		"google_aistudio.candidate_url_context_metadata.omitted",
		"google_aistudio.candidate_finish_message.omitted",
		"google_aistudio.candidate_future_metadata.omitted",
	}
	for _, summaryCode := range summaryCodes {
		if !aiStudioContainsSummary(decoder.Report().ConversionSummary, summaryCode) {
			t.Fatalf("report = %#v, missing summary %q", decoder.Report(), summaryCode)
		}
	}
}

// TestStreamDecoderRejectsUnsupportedOrFutureParts verifies AI Studio media, code, and future part variants cannot be silently reduced as empty text.
// TestStreamDecoderRejectsUnsupportedOrFutureParts 验证 AI Studio 媒体、代码和未来 Part 变体不能被静默归并为空文本。
func TestStreamDecoderRejectsUnsupportedOrFutureParts(t *testing.T) {
	// partPayloads cover every documented first-phase-excluded part carrier and one future-field boundary.
	// partPayloads 覆盖每个文档化的第一阶段排除 Part 载体及一个未来字段边界。
	partPayloads := []string{
		`{}`,
		`{"inlineData":{"mimeType":"image/png","data":"opaque"}}`,
		`{"fileData":{"mimeType":"application/pdf","fileUri":"files/example"}}`,
		`{"executableCode":{"language":"PYTHON","code":"print(1)"}}`,
		`{"codeExecutionResult":{"outcome":"OUTCOME_OK","output":"1"}}`,
		`{"videoMetadata":{"startOffset":"1s"}}`,
		`{"futureProviderPart":{"opaque":"value"}}`,
	}
	for index, partPayload := range partPayloads {
		t.Run(partPayload, func(t *testing.T) {
			// upstreamJSON uses raw wire data to exercise Part.UnmarshalJSON rather than only manually-built test values.
			// upstreamJSON 使用原始 wire 数据来覆盖 Part.UnmarshalJSON，而不是只使用手工构建的测试值。
			upstreamJSON := []byte(`{"candidates":[{"content":{"role":"model","parts":[` + partPayload + `]},"finishReason":"STOP"}]}`)
			var upstream GenerateContentResponse
			if errDecode := json.Unmarshal(upstreamJSON, &upstream); errDecode != nil {
				t.Fatalf("json.Unmarshal() error = %v", errDecode)
			}
			decoder, errNew := NewStreamDecoder("response-unsupported-part-"+strconv.Itoa(index), aiStudioNow(), nil)
			if errNew != nil {
				t.Fatalf("NewStreamDecoder() error = %v", errNew)
			}
			if _, errPush := decoder.Push(upstream); !errors.Is(errPush, ErrInvalidUpstreamResponse) {
				t.Fatalf("Push() error = %v, want ErrInvalidUpstreamResponse", errPush)
			}
		})
	}
}

// TestStreamDecoderRejectsModelFunctionResponse verifies an input-only Gemini functionResponse part cannot be silently discarded from a model candidate.
// TestStreamDecoderRejectsModelFunctionResponse 验证仅输入可用的 Gemini functionResponse 部分不会从模型候选中被静默丢弃。
func TestStreamDecoderRejectsModelFunctionResponse(t *testing.T) {
	decoder, errNew := NewStreamDecoder("response-function-response", aiStudioNow(), nil)
	if errNew != nil {
		t.Fatalf("NewStreamDecoder() error = %v", errNew)
	}
	response := GenerateContentResponse{Candidates: []Candidate{{Content: &Content{Role: "model", Parts: []Part{{FunctionResponse: &FunctionResponse{Name: "lookup", Response: []byte(`{"result":"unexpected"}`)}}}}}}}

	if _, errPush := decoder.Push(response); !errors.Is(errPush, ErrInvalidUpstreamResponse) {
		t.Fatalf("Push() error = %v, want ErrInvalidUpstreamResponse", errPush)
	}
}

// TestStreamDecoderMarksEOFWithoutFinishIncomplete verifies an SSE EOF cannot be misreported as successful completion.
// TestStreamDecoderMarksEOFWithoutFinishIncomplete 验证 SSE EOF 不会被误报为成功完成。
func TestStreamDecoderMarksEOFWithoutFinishIncomplete(t *testing.T) {
	decoder, errNew := NewStreamDecoder("response-3", aiStudioNow(), nil)
	if errNew != nil {
		t.Fatalf("NewStreamDecoder() error = %v", errNew)
	}
	if _, errPush := decoder.Push(GenerateContentResponse{Candidates: []Candidate{{Content: &Content{Role: "model", Parts: []Part{{Text: "Partial"}}}}}}); errPush != nil {
		t.Fatalf("Push() error = %v", errPush)
	}
	if _, errClose := decoder.Close(nil); errClose != nil {
		t.Fatalf("Close() error = %v", errClose)
	}
	response := decoder.Response()
	if response.Status != vcp.ResponseIncomplete || response.FinishReason != "eof_without_finish_reason" || len(response.Items) != 1 || response.Items[0].Status != vcp.OutputItemIncomplete {
		t.Fatalf("response = %#v", response)
	}
}

// TestStreamDecoderMapsDocumentedTerminalFailures verifies each first-phase Gemini terminal failure has a stable VCP-safe code.
// TestStreamDecoderMapsDocumentedTerminalFailures 验证每个第一阶段 Gemini 终态失败都具有稳定且 VCP 安全的代码。
func TestStreamDecoderMapsDocumentedTerminalFailures(t *testing.T) {
	// testCases enumerate the official finish reasons whose distinct semantics must not collapse into an unrecognized fallback.
	// testCases 枚举正式 finish reason，其不同语义绝不能折叠为未识别兜底。
	testCases := []struct {
		// finishReason is the documented Gemini candidate terminal value.
		// finishReason 是文档化的 Gemini 候选终态值。
		finishReason string
		// errorCode is the safe VCP terminal code expected for that exact condition.
		// errorCode 是该精确条件预期的安全 VCP 终态代码。
		errorCode string
		// refusal reports whether the upstream condition is a safety-like content refusal.
		// refusal 表示该上游条件是否属于类似安全拦截的内容拒绝。
		refusal bool
	}{
		{finishReason: "IMAGE_PROHIBITED_CONTENT", errorCode: "google_aistudio.candidate_blocked", refusal: true},
		{finishReason: "IMAGE_RECITATION", errorCode: "google_aistudio.candidate_blocked", refusal: true},
		{finishReason: "IMAGE_OTHER", errorCode: "google_aistudio.image_other"},
		{finishReason: "NO_IMAGE", errorCode: "google_aistudio.no_image"},
		{finishReason: "UNEXPECTED_TOOL_CALL", errorCode: "google_aistudio.unexpected_tool_call"},
		{finishReason: "TOO_MANY_TOOL_CALLS", errorCode: "google_aistudio.too_many_tool_calls"},
		{finishReason: "MISSING_THOUGHT_SIGNATURE", errorCode: "google_aistudio.missing_thought_signature"},
		{finishReason: "MALFORMED_RESPONSE", errorCode: "google_aistudio.malformed_response"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.finishReason, func(t *testing.T) {
			// decoder receives one terminal candidate without exposing provider diagnostic text.
			// decoder 接收一个终态候选，且不暴露 Provider 诊断文本。
			decoder, errNew := NewStreamDecoder("response-terminal-"+testCase.finishReason, aiStudioNow(), nil)
			if errNew != nil {
				t.Fatalf("NewStreamDecoder() error = %v", errNew)
			}
			if _, errPush := decoder.Push(GenerateContentResponse{Candidates: []Candidate{{FinishReason: testCase.finishReason}}}); errPush != nil {
				t.Fatalf("Push() error = %v", errPush)
			}
			// response is terminally failed with the exact safe code, and safety-like reasons retain a refusal item.
			// response 以精确安全代码终态失败，且类似安全的原因会保留拒绝项目。
			response := decoder.Response()
			if response.Status != vcp.ResponseFailed || response.ErrorCode != testCase.errorCode {
				t.Fatalf("response = %#v", response)
			}
			if testCase.refusal && len(response.Items) != 1 || !testCase.refusal && len(response.Items) != 0 {
				t.Fatalf("response items = %#v", response.Items)
			}
		})
	}
}

// TestReadSSEParsesMultilineFrames verifies transport-independent parsing preserves event names and joins SSE data lines once.
// TestReadSSEParsesMultilineFrames 验证独立于传输的解析保留事件名称并且只连接一次 SSE 数据行。
func TestReadSSEParsesMultilineFrames(t *testing.T) {
	var envelopes []SSEEnvelope
	errRead := ReadSSE(strings.NewReader(": keepalive\nevent: chunk\ndata: first\ndata: second\n\n"), func(envelope SSEEnvelope) error {
		envelopes = append(envelopes, envelope)
		return nil
	})
	if errRead != nil {
		t.Fatalf("ReadSSE() error = %v", errRead)
	}
	want := []SSEEnvelope{{Event: "chunk", Data: []byte("first\nsecond")}}
	if !reflect.DeepEqual(envelopes, want) {
		t.Fatalf("envelopes = %#v, want %#v", envelopes, want)
	}
}

// TestReadSSERejectsOversizedMultilineFrame verifies individually valid lines cannot create an unbounded aggregate payload.
// TestReadSSERejectsOversizedMultilineFrame 验证单独有效的行不能创建无界聚合载荷。
func TestReadSSERejectsOversizedMultilineFrame(t *testing.T) {
	dataLine := "data: " + strings.Repeat("x", maximumSSELineBytes/2+1) + "\n"
	errRead := ReadSSE(strings.NewReader(dataLine+dataLine+"\n"), func(SSEEnvelope) error { return nil })
	if !errors.Is(errRead, ErrInvalidUpstreamResponse) {
		t.Fatalf("ReadSSE() error = %v, want ErrInvalidUpstreamResponse", errRead)
	}
}

// aiStudioInt returns an isolated integer pointer for typed Gemini response fixtures.
// aiStudioInt 为类型化 Gemini 响应夹具返回一个隔离整数指针。
func aiStudioInt(value int) *int {
	return &value
}

// aiStudioInt64 returns an isolated int64 pointer for typed Gemini usage fixtures.
// aiStudioInt64 为类型化 Gemini 用量夹具返回一个隔离 int64 指针。
func aiStudioInt64(value int64) *int64 {
	return &value
}
