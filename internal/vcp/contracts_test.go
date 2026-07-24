package vcp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

// publishedSchemaPaths enumerates every independently published VCP JSON Schema document.
// publishedSchemaPaths 枚举每个独立发布的 VCP JSON Schema 文档。
var publishedSchemaPaths = []string{
	"execution-request.schema.json", "operation-payload.schema.json", "selection-request.schema.json", "selection-response.schema.json", "usage-preflight-request.schema.json", "usage-preflight-response.schema.json", "execution-record.schema.json", "execution-result.schema.json", "result-components.schema.json", "execution-event.schema.json", "failure.schema.json", "error.schema.json", "information-request.schema.json", "information-response.schema.json", "input-plan-request.schema.json", "input-plan.schema.json", "resource.schema.json", "resource-import-request.schema.json", "continuation.schema.json", "usage-observation.schema.json", "retry-state.schema.json",
}

// TestPublishedVCPContractsMatchRuntime verifies version, routes, schemas, Rust source, and golden request remain aligned.
// TestPublishedVCPContractsMatchRuntime 验证版本、路由、Schema、Rust 源与 Golden 请求保持一致。
func TestPublishedVCPContractsMatchRuntime(t *testing.T) {
	contractRoot := filepath.Join("..", "..", "api", "vcp")
	openAPI := readContractFile(t, filepath.Join(contractRoot, "openapi.yaml"))
	for _, required := range []string{"version: \"" + ProtocolVersion + "\"", "/vulcan/v1/info:", "/vulcan/v1/selections:", "/vulcan/v1/preflight:", "/vulcan/v1/executions:", "/vulcan/v1/input-plans:", "/vulcan/v1/resources:"} {
		if !strings.Contains(openAPI, required) {
			t.Fatalf("OpenAPI contract is missing %q", required)
		}
	}
	validatePublishedOpenAPI(t, filepath.Join(contractRoot, "openapi.yaml"))
	for _, schemaPath := range publishedSchemaPaths {
		relativePath := filepath.Join("schemas", schemaPath)
		content := readContractFile(t, filepath.Join(contractRoot, relativePath))
		var document any
		if errDecode := json.Unmarshal([]byte(content), &document); errDecode != nil {
			t.Fatalf("decode %s: %v", relativePath, errDecode)
		}
		if !strings.Contains(content, ProtocolVersion) && relativePath != "schemas/selection-response.schema.json" && relativePath != "schemas/failure.schema.json" && relativePath != "schemas/execution-event.schema.json" && relativePath != "schemas/execution-record.schema.json" && relativePath != "schemas/result-components.schema.json" {
			t.Fatalf("schema %s does not declare protocol version %s", relativePath, ProtocolVersion)
		}
	}
	validatePublishedSchemaFixtures(t, contractRoot)
	executionSchema := readContractFile(t, filepath.Join(contractRoot, "schemas", "execution-request.schema.json"))
	if !strings.Contains(executionSchema, `"$ref": "./operation-payload.schema.json"`) {
		t.Fatal("execution request schema must reference the closed typed operation payload schema")
	}
	operationSchema := readContractFile(t, filepath.Join(contractRoot, "schemas", "operation-payload.schema.json"))
	for _, member := range []string{"conversation", "media_analyze", "image_generate", "image_edit", "video_generate", "video_edit", "video_extend", "speech_synthesize", "speech_transcribe", "embedding_create", "rerank_documents", "search_web", "web_extract", "music_generate", "music_cover_prepare", "music_cover"} {
		if !strings.Contains(operationSchema, `"`+member+`"`) {
			t.Fatalf("closed operation payload schema is missing %q", member)
		}
	}
	rustSource := readContractFile(t, filepath.Join(contractRoot, "rust", "vcp_v1.rs"))
	for _, rustContract := range []string{"PROTOCOL_VERSION: &str = \"" + ProtocolVersion + "\"", "pub enum OperationKind", "#[serde(rename = \"web.extract\")]", "TWebExtract", "WebExtract(TWebExtract)", "pub enum OperationPayload", "pub struct ExecutionRequest", "pub struct ExecutionSelectionRequest", "pub struct ExecutionSelectionResponse", "pub enum ComputerAction", "pub struct ComputerScreenshotResult", "pub struct RetryPolicy", "pub struct RetryState", "pub struct ExecutionFailure", "pub struct ExecutionRecord", "pub enum ExecutionEvent", "execution.cancellation.requested", "pub struct Continuation", "pub struct UsageObservation", "pub enum PreflightAccuracy", "pub struct PreflightMetric", "pub struct InformationRequest", "pub struct CatalogChange", "pub enum InformationResponse", "pub struct Resource"} {
		if !strings.Contains(rustSource, rustContract) {
			t.Fatalf("Rust generation source is missing %q", rustContract)
		}
	}
	fixture := readContractFile(t, filepath.Join(contractRoot, "fixtures", "execution-request.json"))
	var request ExecutionRequest
	if errDecode := json.Unmarshal([]byte(fixture), &request); errDecode != nil {
		t.Fatalf("decode execution fixture: %v", errDecode)
	}
	if errValidate := request.Validate(); errValidate != nil {
		t.Fatalf("validate execution fixture: %v", errValidate)
	}
	preflightFixture := readContractFile(t, filepath.Join(contractRoot, "fixtures", "usage-preflight-request.json"))
	var preflight UsagePreflightRequest
	if errDecode := json.Unmarshal([]byte(preflightFixture), &preflight); errDecode != nil {
		t.Fatalf("decode usage preflight fixture: %v", errDecode)
	}
	if errValidate := preflight.Validate(); errValidate != nil {
		t.Fatalf("validate usage preflight fixture: %v", errValidate)
	}
	for _, fixturePath := range []string{"fixtures/error.json", "fixtures/resource.json", "fixtures/continuation.json", "fixtures/computer-loop.json", "fixtures/usage-observation.json", "fixtures/retry-state.json", "fixtures/usage-preflight-response.json", "fixtures/selection-request.json", "fixtures/selection-model-response.json", "fixtures/selection-service-response.json", "fixtures/execution-event.json", "fixtures/execution-record.json", "fixtures/information-request.json", "fixtures/information-instances-response.json", "fixtures/information-models-response.json", "fixtures/information-accounts-response.json", "fixtures/information-services-response.json", "fixtures/information-usage-response.json", "fixtures/information-catalog-response.json"} {
		content := readContractFile(t, filepath.Join(contractRoot, fixturePath))
		var document any
		if errDecode := json.Unmarshal([]byte(content), &document); errDecode != nil {
			t.Fatalf("decode %s: %v", fixturePath, errDecode)
		}
	}
}

// validatePublishedOpenAPI resolves every local reference and validates the complete OpenAPI document semantically.
// validatePublishedOpenAPI 解析每个本地引用并对完整 OpenAPI 文档执行语义校验。
func validatePublishedOpenAPI(t *testing.T, contractPath string) {
	t.Helper()
	loader := openapi3.NewLoader()
	// Local schema files are external documents in OpenAPI terminology; the repository controls the exact contract root.
	// 本地 Schema 文件在 OpenAPI 术语中属于外部文档；Repository 控制精确的契约根目录。
	loader.IsExternalRefsAllowed = true
	document, errLoad := loader.LoadFromFile(contractPath)
	if errLoad != nil {
		t.Fatalf("load OpenAPI contract: %v", errLoad)
	}
	if errValidate := document.Validate(context.Background()); errValidate != nil {
		t.Fatalf("validate OpenAPI contract: %v", errValidate)
	}
}

// validatePublishedSchemaFixtures compiles every published schema with all local references and validates every golden fixture.
// validatePublishedSchemaFixtures 编译全部已发布 Schema 及其本地引用，并验证所有 Golden Fixture。
func validatePublishedSchemaFixtures(t *testing.T, contractRoot string) {
	t.Helper()
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	schemaIDs := make(map[string]string, len(publishedSchemaPaths))
	for _, schemaPath := range publishedSchemaPaths {
		content := readContractFile(t, filepath.Join(contractRoot, "schemas", schemaPath))
		var document map[string]any
		if errDecode := json.Unmarshal([]byte(content), &document); errDecode != nil {
			t.Fatalf("decode schema %s: %v", schemaPath, errDecode)
		}
		schemaID, validID := document["$id"].(string)
		if !validID || strings.TrimSpace(schemaID) == "" {
			t.Fatalf("schema %s has no absolute identifier", schemaPath)
		}
		if errAdd := compiler.AddResource(schemaID, document); errAdd != nil {
			t.Fatalf("add schema %s: %v", schemaPath, errAdd)
		}
		schemaIDs[schemaPath] = schemaID
	}
	compiled := make(map[string]*jsonschema.Schema, len(schemaIDs))
	for schemaPath, schemaID := range schemaIDs {
		schema, errCompile := compiler.Compile(schemaID)
		if errCompile != nil {
			t.Fatalf("compile schema %s: %v", schemaPath, errCompile)
		}
		compiled[schemaPath] = schema
	}
	fixtures := map[string]string{
		"execution-request.json":              "execution-request.schema.json",
		"selection-request.json":              "selection-request.schema.json",
		"selection-model-response.json":       "selection-response.schema.json",
		"selection-service-response.json":     "selection-response.schema.json",
		"usage-preflight-request.json":        "usage-preflight-request.schema.json",
		"usage-preflight-response.json":       "usage-preflight-response.schema.json",
		"error.json":                          "error.schema.json",
		"resource.json":                       "resource.schema.json",
		"continuation.json":                   "continuation.schema.json",
		"usage-observation.json":              "usage-observation.schema.json",
		"retry-state.json":                    "retry-state.schema.json",
		"execution-event.json":                "execution-event.schema.json",
		"execution-record.json":               "execution-record.schema.json",
		"information-request.json":            "information-request.schema.json",
		"information-instances-response.json": "information-response.schema.json",
		"information-models-response.json":    "information-response.schema.json",
		"information-accounts-response.json":  "information-response.schema.json",
		"information-services-response.json":  "information-response.schema.json",
		"information-usage-response.json":     "information-response.schema.json",
		"information-catalog-response.json":   "information-response.schema.json",
	}
	for fixturePath, schemaPath := range fixtures {
		content := readContractFile(t, filepath.Join(contractRoot, "fixtures", fixturePath))
		var document any
		if errDecode := json.Unmarshal([]byte(content), &document); errDecode != nil {
			t.Fatalf("decode fixture %s: %v", fixturePath, errDecode)
		}
		if errValidate := compiled[schemaPath].Validate(document); errValidate != nil {
			t.Fatalf("validate fixture %s with %s: %v", fixturePath, schemaPath, errValidate)
		}
	}
	validatePublishedSchemaRejections(t, compiled)
}

// validatePublishedSchemaRejections proves cross-field and exact-union invariants reject structurally plausible invalid documents.
// validatePublishedSchemaRejections 证明跨字段与唯一联合不变量会拒绝结构上看似合理的无效文档。
func validatePublishedSchemaRejections(t *testing.T, compiled map[string]*jsonschema.Schema) {
	t.Helper()
	validReasoningPolicy := map[string]any{"conversation": map[string]any{"reasoning_policy": map[string]any{"enabled": true, "budget_tokens": float64(4000)}}}
	if errValidate := compiled["operation-payload.schema.json"].Validate(validReasoningPolicy); errValidate != nil {
		t.Fatalf("reasoning switch and budget operation payload is invalid: %v", errValidate)
	}
	invalidReasoningBudget := cloneContractDocument(t, validReasoningPolicy)
	invalidReasoningBudget["conversation"].(map[string]any)["reasoning_policy"].(map[string]any)["budget_tokens"] = float64(0)
	assertPublishedSchemaRejects(t, compiled["operation-payload.schema.json"], invalidReasoningBudget, "reasoning policy with a zero budget")
	invalidReasoningSwitch := cloneContractDocument(t, validReasoningPolicy)
	invalidReasoningSwitch["conversation"].(map[string]any)["reasoning_policy"].(map[string]any)["enabled"] = "true"
	assertPublishedSchemaRejects(t, compiled["operation-payload.schema.json"], invalidReasoningSwitch, "reasoning policy with a string switch")
	unknownReasoningMember := cloneContractDocument(t, validReasoningPolicy)
	unknownReasoningMember["conversation"].(map[string]any)["reasoning_policy"].(map[string]any)["thinking"] = true
	assertPublishedSchemaRejects(t, compiled["operation-payload.schema.json"], unknownReasoningMember, "reasoning policy with an unknown member")
	// validConversationAudio proves the published request can carry the closed text-plus-audio shape.
	// validConversationAudio 证明已发布请求可以携带封闭的文字加音频形态。
	validConversationAudio := map[string]any{"conversation": map[string]any{"generation_policy": map[string]any{"output_modalities": []any{"text", "audio"}, "audio_output": map[string]any{"voice_id": "Tina", "output_format": "wav"}}}}
	assertPublishedSchemaAccepts(t, compiled["operation-payload.schema.json"], validConversationAudio, "conversation audio output")
	invalidConversationAudio := cloneContractDocument(t, validConversationAudio)
	invalidConversationAudio["conversation"].(map[string]any)["generation_policy"].(map[string]any)["output_modalities"] = []any{"audio"}
	assertPublishedSchemaRejects(t, compiled["operation-payload.schema.json"], invalidConversationAudio, "conversation audio output without text")
	// validReferenceVideo proves reference voices retain their exact related visual input.
	// validReferenceVideo 证明参考声音保留其精确关联的视觉输入。
	validReferenceVideo := map[string]any{"video_generate": map[string]any{"inputs": []any{
		map[string]any{"id": "visual-1", "kind": "image", "role": "reference", "resource": map[string]any{"resource_id": "resource-visual"}},
		map[string]any{"id": "voice-1", "kind": "audio", "role": "reference_voice", "resource": map[string]any{"resource_id": "resource-voice"}, "related_input_id": "visual-1"},
	}}}
	assertPublishedSchemaAccepts(t, compiled["operation-payload.schema.json"], validReferenceVideo, "reference-only video generation")
	invalidReferenceVideo := cloneContractDocument(t, validReferenceVideo)
	invalidReferenceVideo["video_generate"].(map[string]any)["inputs"].([]any)[1].(map[string]any)["kind"] = "image"
	assertPublishedSchemaRejects(t, compiled["operation-payload.schema.json"], invalidReferenceVideo, "non-audio reference voice")
	// validVideoEdit proves provider-verified reference-only edits and all newly typed controls remain public.
	// validVideoEdit 证明供应商已验证的纯参考编辑及全部新增强类型控制保持公开。
	validVideoEdit := map[string]any{"video_edit": map[string]any{"source": map[string]any{"id": "video-1", "kind": "video", "role": "edit_source", "resource": map[string]any{"resource_id": "resource-video"}}, "negative_prompt": "blur", "duration_seconds": float64(5), "resolution": "720p", "aspect_ratio": "16:9", "audio_mode": "origin", "prompt_extend": true, "watermark": false, "seed": float64(7)}}
	assertPublishedSchemaAccepts(t, compiled["operation-payload.schema.json"], validVideoEdit, "reference-only video edit")
	invalidVideoEdit := cloneContractDocument(t, validVideoEdit)
	invalidVideoEdit["video_edit"].(map[string]any)["audio_mode"] = "replace"
	assertPublishedSchemaRejects(t, compiled["operation-payload.schema.json"], invalidVideoEdit, "video edit with an unknown audio mode")
	// validSegmentSpeech proves multi-speaker synthesis is an alternative to top-level text and voice fields.
	// validSegmentSpeech 证明多说话人合成是顶层文字和声音字段的替代形态。
	validSegmentSpeech := map[string]any{"speech_synthesize": map[string]any{"segments": []any{map[string]any{"text": "Hello", "voice_id": "Tina"}, map[string]any{"text": "World", "voice_id": "Chelsie"}}, "pitch": float64(-1), "volume": float64(0), "seed": float64(9), "enable_ssml": true}}
	assertPublishedSchemaAccepts(t, compiled["operation-payload.schema.json"], validSegmentSpeech, "multi-speaker speech synthesis")
	invalidSegmentSpeech := cloneContractDocument(t, validSegmentSpeech)
	invalidSegmentSpeech["speech_synthesize"].(map[string]any)["text"] = "duplicate mode"
	invalidSegmentSpeech["speech_synthesize"].(map[string]any)["voice_id"] = "Tina"
	assertPublishedSchemaRejects(t, compiled["operation-payload.schema.json"], invalidSegmentSpeech, "speech synthesis with both input modes")
	// validBatchTranscription freezes ordered source, channel, diarization, and vocabulary fields.
	// validBatchTranscription 冻结有序来源、声道、说话人分离与词表字段。
	validBatchTranscription := map[string]any{"speech_transcribe": map[string]any{"sources": []any{
		map[string]any{"id": "audio-1", "kind": "audio", "role": "transcription_source", "resource": map[string]any{"resource_id": "resource-audio-1"}},
		map[string]any{"id": "audio-2", "kind": "audio", "role": "transcription_source", "resource": map[string]any{"resource_id": "resource-audio-2"}},
	}, "candidate_count": float64(0), "channel_ids": []any{float64(0), float64(1)}, "diarization": true, "speaker_count": float64(2), "vocabulary_id": "vocabulary-1"}}
	assertPublishedSchemaAccepts(t, compiled["operation-payload.schema.json"], validBatchTranscription, "batch speech transcription")
	invalidBatchTranscription := cloneContractDocument(t, validBatchTranscription)
	invalidBatchTranscription["speech_transcribe"].(map[string]any)["source"] = map[string]any{"id": "audio-3", "kind": "audio", "role": "transcription_source", "resource": map[string]any{"resource_id": "resource-audio-3"}}
	assertPublishedSchemaRejects(t, compiled["operation-payload.schema.json"], invalidBatchTranscription, "transcription with both source modes")
	// validWebExtract proves the committed special service is present in payload and envelope contracts.
	// validWebExtract 证明已提交的特殊服务存在于载荷与信封契约中。
	validWebExtract := map[string]any{"web_extract": map[string]any{"urls": []any{"https://example.com/a"}, "query": "router", "chunks_per_source": float64(3), "depth": "advanced", "format": "markdown", "include_images": true, "include_favicon": true, "timeout_seconds": float64(30)}}
	assertPublishedSchemaAccepts(t, compiled["operation-payload.schema.json"], validWebExtract, "web extraction payload")
	validWebExtractExecution := map[string]any{"protocol_version": ProtocolVersion, "request_id": "request-extract", "target": map[string]any{"service": map[string]any{"provider_instance_id": "pvi_extract", "provider_service_id": "service_extract"}}, "operation": "web.extract", "stream": false, "payload": validWebExtract, "projection_policy": map[string]any{}, "budget": map[string]any{}}
	assertPublishedSchemaAccepts(t, compiled["execution-request.schema.json"], validWebExtractExecution, "web extraction execution")
	validWebExtractSelection := map[string]any{"protocol_version": ProtocolVersion, "request_id": "selection-extract", "provider_instance_id": "pvi_extract", "operation": "web.extract"}
	assertPublishedSchemaAccepts(t, compiled["selection-request.schema.json"], validWebExtractSelection, "web extraction selection")
	invalidWebExtractSelection := cloneContractDocument(t, validWebExtractSelection)
	invalidWebExtractSelection["required_context_tokens"] = float64(100)
	assertPublishedSchemaRejects(t, compiled["selection-request.schema.json"], invalidWebExtractSelection, "web extraction selection with model requirements")
	// validTypedResults proves both direct extraction and resource-owned batch transcription remain serializable.
	// validTypedResults 证明直接提取与资源归属批量转写均保持可序列化。
	validExtractResult := map[string]any{"extract": map[string]any{"results": []any{map[string]any{"url": "https://example.com/a", "raw_content": "content"}}, "failed_results": []any{map[string]any{"url": "https://example.com/b", "error": "blocked"}}, "response_time_seconds": float64(1)}}
	assertPublishedSchemaAccepts(t, compiled["execution-result.schema.json"], validExtractResult, "web extraction result")
	validTranscriptionResult := map[string]any{"transcriptions": []any{map[string]any{"input_id": "audio-1", "resource_id": "resource-audio-1", "transcript": map[string]any{"candidates": []any{map[string]any{"candidate_id": "candidate-1", "channel_id": float64(0), "text": "hello"}}}}}}
	assertPublishedSchemaAccepts(t, compiled["execution-result.schema.json"], validTranscriptionResult, "batch transcription result")
	invalidTranscriptionResult := cloneContractDocument(t, validTranscriptionResult)
	invalidTranscriptionResult["transcriptions"].([]any)[0].(map[string]any)["error_code"] = "transcription_failed"
	assertPublishedSchemaRejects(t, compiled["execution-result.schema.json"], invalidTranscriptionResult, "batch transcription item with success and failure")
	// extractCapabilities is reused verbatim by the service offering and execution profile branches.
	// extractCapabilities 由服务 Offering 与执行规格分支原样复用。
	extractCapabilities := map[string]any{"web_extract": map[string]any{"max_urls": float64(20), "depths": []any{"basic", "advanced"}, "formats": []any{"markdown", "text"}, "query_relevance": true, "minimum_chunks_per_source": float64(1), "maximum_chunks_per_source": float64(5), "include_images": true, "include_favicon": true, "minimum_timeout_seconds": float64(1), "maximum_timeout_seconds": float64(60)}}
	validExtractInformation := map[string]any{"get": "services", "services": []any{map[string]any{"provider_instance_id": "pvi_extract", "provider_handle": "extract", "provider_definition_id": "definition_extract", "service": map[string]any{"id": "service_extract", "display_name": "Extract", "operation": "web.extract", "entitlement_mode": "all_bound_credentials", "enabled": true, "authorization_status": "authorized", "offerings": []any{map[string]any{"id": "service_offer_extract", "upstream_service_id": "extract", "capabilities": extractCapabilities, "profiles": []any{map[string]any{"id": "profile_extract", "display_name": "Extract", "default": true, "operation": "web.extract", "action_binding_id": "action_extract", "capabilities": extractCapabilities}}}}}}}}
	assertPublishedSchemaAccepts(t, compiled["information-response.schema.json"], validExtractInformation, "web extraction information response")
	// Closed operation documents prove response and input-plan schemas cannot drift back to arbitrary strings.
	// 封闭操作文档证明响应与输入方案 Schema 不会退化为任意字符串。
	validSelectionResponse := map[string]any{"request_id": "selection-closed", "target": map[string]any{"model": map[string]any{"target": "exact", "provider_instance_id": "pvi_closed", "provider_model_id": "model_closed", "execution_profile_id": "profile_closed"}}, "operation": "conversation.respond", "capability_revision": float64(1), "catalog_revision": float64(1)}
	assertPublishedSchemaAccepts(t, compiled["selection-response.schema.json"], validSelectionResponse, "selection response with a registered operation")
	unknownSelectionResponse := cloneContractDocument(t, validSelectionResponse)
	unknownSelectionResponse["operation"] = "unknown.operation"
	assertPublishedSchemaRejects(t, compiled["selection-response.schema.json"], unknownSelectionResponse, "selection response with an unknown operation")
	validInputPlanRequest := map[string]any{"model": map[string]any{"target": "exact", "provider_instance_id": "pvi_closed", "provider_model_id": "model_closed", "execution_profile_id": "profile_closed"}, "operation": "conversation.respond", "inputs": []any{map[string]any{}}}
	assertPublishedSchemaAccepts(t, compiled["input-plan-request.schema.json"], validInputPlanRequest, "input plan request with a registered operation")
	unknownInputPlanRequest := cloneContractDocument(t, validInputPlanRequest)
	unknownInputPlanRequest["operation"] = "unknown.operation"
	assertPublishedSchemaRejects(t, compiled["input-plan-request.schema.json"], unknownInputPlanRequest, "input plan request with an unknown operation")
	validInputPlan := map[string]any{"input_plan_id": "ipl_0123456789abcdef0123456789abcdef", "accepted": true, "operation": "conversation.respond", "model": map[string]any{}, "capability_revision": float64(1), "catalog_revision": float64(1), "inputs": []any{map[string]any{}}, "requires_provider_preparation": false, "asynchronous_preparation": false, "created_at": "2026-07-21T00:00:00Z", "expires_at": "2026-07-21T00:01:00Z", "revision": float64(1)}
	assertPublishedSchemaAccepts(t, compiled["input-plan.schema.json"], validInputPlan, "input plan with a registered operation")
	unknownInputPlan := cloneContractDocument(t, validInputPlan)
	unknownInputPlan["operation"] = "unknown.operation"
	assertPublishedSchemaRejects(t, compiled["input-plan.schema.json"], unknownInputPlan, "input plan with an unknown operation")
	baseEvent := map[string]any{"execution_id": "exe_0123456789abcdef0123456789abcdef", "event_id": "evt_0123456789abcdef0123456789abcdef_8", "sequence": float64(8), "time": "2026-07-21T00:00:00Z"}
	duplicatePayload := cloneContractDocument(t, baseEvent)
	duplicatePayload["type"] = "execution.running"
	duplicatePayload["lifecycle"] = map[string]any{"status": "running"}
	duplicatePayload["retry"] = map[string]any{"attempt": float64(2)}
	assertPublishedSchemaRejects(t, compiled["execution-event.schema.json"], duplicatePayload, "execution event with two payloads")
	mismatchedLifecycle := cloneContractDocument(t, baseEvent)
	mismatchedLifecycle["type"] = "execution.succeeded"
	mismatchedLifecycle["lifecycle"] = map[string]any{"status": "running"}
	assertPublishedSchemaRejects(t, compiled["execution-event.schema.json"], mismatchedLifecycle, "execution event with mismatched lifecycle")
	invalidRetry := cloneContractDocument(t, baseEvent)
	invalidRetry["type"] = "retry.started"
	invalidRetry["retry"] = map[string]any{"attempt": float64(2), "next_retry_at": "2026-07-21T00:00:05Z"}
	assertPublishedSchemaRejects(t, compiled["execution-event.schema.json"], invalidRetry, "started retry with a scheduled timestamp")
	validModelToolEvent := cloneContractDocument(t, baseEvent)
	validModelToolEvent["type"] = "model_tool.lifecycle"
	validModelToolEvent["model_tool"] = map[string]any{"tool_id": "web_search", "stage": "enabled", "mode": "native"}
	assertPublishedSchemaAccepts(t, compiled["execution-event.schema.json"], validModelToolEvent, "model tool admission event")
	invalidAdmissionModelToolEvent := cloneContractDocument(t, validModelToolEvent)
	invalidAdmissionModelToolEvent["model_tool"].(map[string]any)["tool_call_id"] = "call-must-not-leak"
	assertPublishedSchemaRejects(t, compiled["execution-event.schema.json"], invalidAdmissionModelToolEvent, "model tool admission event with call-scoped state")
	validModelTools := map[string]any{"conversation": map[string]any{"model_tools": map[string]any{"standard": []any{map[string]any{"kind": "web_search", "mode": "native"}}}}}
	assertPublishedSchemaAccepts(t, compiled["operation-payload.schema.json"], validModelTools, "one standard model tool selection")
	duplicateStandardSelection := cloneContractDocument(t, validModelTools)
	duplicateStandardSelection["conversation"].(map[string]any)["model_tools"].(map[string]any)["standard"] = []any{
		map[string]any{"kind": "web_search", "mode": "native"},
		map[string]any{"kind": "web_search", "mode": "router_tool"},
	}
	assertPublishedSchemaRejects(t, compiled["operation-payload.schema.json"], duplicateStandardSelection, "duplicate standard model tool kind with different modes")
	validRecord := map[string]any{"id": "exe_0123456789abcdef0123456789abcdef", "status": "succeeded", "operation": "search.web", "model_tool_plan": map[string]any{"catalog_revision": float64(0)}, "result": map[string]any{"search": map[string]any{"query": "valid", "evidence": map[string]any{"status": "confirmed", "kinds": []any{}}}}, "created_at": "2026-07-21T00:00:00Z", "updated_at": "2026-07-21T00:00:01Z", "expires_at": "2026-07-22T00:00:00Z", "revision": float64(2)}
	if errValidate := compiled["execution-record.schema.json"].Validate(validRecord); errValidate != nil {
		t.Fatalf("baseline execution record is invalid: %v", errValidate)
	}
	validDiagnosticRecord := cloneContractDocument(t, validRecord)
	validDiagnosticRecord["model_tool_plan"].(map[string]any)["diagnostics"] = []any{map[string]any{"code": "legacy_native_web_search_migrated"}}
	assertPublishedSchemaAccepts(t, compiled["execution-record.schema.json"], validDiagnosticRecord, "execution record with a closed compatibility diagnostic")
	invalidDiagnosticRecord := cloneContractDocument(t, validDiagnosticRecord)
	invalidDiagnosticRecord["model_tool_plan"].(map[string]any)["diagnostics"].([]any)[0].(map[string]any)["code"] = "unknown_migration"
	assertPublishedSchemaRejects(t, compiled["execution-record.schema.json"], invalidDiagnosticRecord, "execution record with an unknown compatibility diagnostic")
	duplicateExtensionPlan := cloneContractDocument(t, validRecord)
	duplicateExtensionPlan["model_tool_plan"].(map[string]any)["router_extensions"] = []any{
		map[string]any{"id": "image_generation", "router_binding_id": "rtb_first", "router_binding_revision": float64(1)},
		map[string]any{"id": "image_generation", "router_binding_id": "rtb_second", "router_binding_revision": float64(2)},
	}
	assertPublishedSchemaRejects(t, compiled["execution-record.schema.json"], duplicateExtensionPlan, "duplicate Router extension plan id with different bindings")
	invalidRecord := cloneContractDocument(t, validRecord)
	invalidRecord["status"] = "failed"
	assertPublishedSchemaRejects(t, compiled["execution-record.schema.json"], invalidRecord, "failed execution with a success result")
	validComputerEvent := map[string]any{
		"response_id": "response-computer", "event_id": "event-computer-1", "sequence": float64(1), "time": "2026-07-21T00:00:00Z", "replayable": true,
		"type": "item.started", "item_id": "computer-item", "item": map[string]any{
			"item_id": "computer-item", "kind": "tool_call", "status": "in_progress", "tool_call": map[string]any{
				"tool_call_id": "computer-call", "upstream_id": "computer-call", "name": "computer_use", "status": "completed", "computer_actions": []any{map[string]any{"type": "screenshot"}},
			},
		},
	}
	validComputerExecutionEvent := map[string]any{"execution_id": "exe_0123456789abcdef0123456789abcdef", "event_id": "evt_0123456789abcdef0123456789abcdef_9", "sequence": float64(9), "time": "2026-07-21T00:00:00Z", "type": "provider.semantic", "provider_event": validComputerEvent}
	if errValidate := compiled["execution-event.schema.json"].Validate(validComputerExecutionEvent); errValidate != nil {
		t.Fatalf("baseline computer provider event is invalid: %v", errValidate)
	}
	invalidComputerExecutionEvent := cloneContractDocument(t, validComputerExecutionEvent)
	invalidComputerEvent := invalidComputerExecutionEvent["provider_event"].(map[string]any)
	invalidItem := invalidComputerEvent["item"].(map[string]any)
	invalidCall := invalidItem["tool_call"].(map[string]any)
	invalidCall["computer_actions"] = []any{map[string]any{"type": "screenshot", "x": float64(10)}}
	assertPublishedSchemaRejects(t, compiled["execution-event.schema.json"], invalidComputerExecutionEvent, "computer screenshot action with click coordinates")
}

// assertPublishedSchemaAccepts fails when one intentionally valid contract document is rejected.
// assertPublishedSchemaAccepts 在故意构造的有效契约文档被拒绝时使测试失败。
func assertPublishedSchemaAccepts(t *testing.T, schema *jsonschema.Schema, document any, description string) {
	t.Helper()
	if errValidate := schema.Validate(document); errValidate != nil {
		t.Fatalf("schema rejected %s: %v", description, errValidate)
	}
}

// cloneContractDocument copies one JSON-compatible object for isolated negative-schema mutation.
// cloneContractDocument 复制一个 JSON 兼容对象用于隔离的负向 Schema 修改。
func cloneContractDocument(t *testing.T, source map[string]any) map[string]any {
	t.Helper()
	encoded, errEncode := json.Marshal(source)
	if errEncode != nil {
		t.Fatalf("encode contract document: %v", errEncode)
	}
	var cloned map[string]any
	if errDecode := json.Unmarshal(encoded, &cloned); errDecode != nil {
		t.Fatalf("decode contract document: %v", errDecode)
	}
	return cloned
}

// assertPublishedSchemaRejects fails when one intentionally invalid contract document is accepted.
// assertPublishedSchemaRejects 在故意构造的无效契约文档被接受时使测试失败。
func assertPublishedSchemaRejects(t *testing.T, schema *jsonschema.Schema, document any, description string) {
	t.Helper()
	if errValidate := schema.Validate(document); errValidate == nil {
		t.Fatalf("schema accepted %s", description)
	}
}

// readContractFile loads one repository contract fixture or fails the current test.
// readContractFile 加载一个 Repository 契约夹具，失败时终止当前测试。
func readContractFile(t *testing.T, path string) string {
	t.Helper()
	content, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatalf("read contract %s: %v", path, errRead)
	}
	return string(content)
}
