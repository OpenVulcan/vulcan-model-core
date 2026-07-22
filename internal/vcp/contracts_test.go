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
	for _, member := range []string{"conversation", "media_analyze", "image_generate", "image_edit", "video_generate", "video_edit", "video_extend", "speech_synthesize", "speech_transcribe", "embedding_create", "rerank_documents", "search_web", "music_generate", "music_cover_prepare", "music_cover"} {
		if !strings.Contains(operationSchema, `"`+member+`"`) {
			t.Fatalf("closed operation payload schema is missing %q", member)
		}
	}
	rustSource := readContractFile(t, filepath.Join(contractRoot, "rust", "vcp_v1.rs"))
	for _, rustContract := range []string{"PROTOCOL_VERSION: &str = \"" + ProtocolVersion + "\"", "pub enum OperationKind", "pub enum OperationPayload", "pub struct ExecutionRequest", "pub struct ExecutionSelectionRequest", "pub struct ExecutionSelectionResponse", "pub enum ComputerAction", "pub struct ComputerScreenshotResult", "pub struct RetryPolicy", "pub struct RetryState", "pub struct ExecutionFailure", "pub struct ExecutionRecord", "pub enum ExecutionEvent", "execution.cancellation.requested", "pub struct Continuation", "pub struct UsageObservation", "pub enum PreflightAccuracy", "pub struct PreflightMetric", "pub struct InformationRequest", "pub struct CatalogChange", "pub enum InformationResponse", "pub struct Resource"} {
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
	validRecord := map[string]any{"id": "exe_0123456789abcdef0123456789abcdef", "status": "succeeded", "operation": "search.web", "result": map[string]any{"search": map[string]any{"query": "valid", "evidence": map[string]any{"status": "confirmed", "kinds": []any{}}}}, "created_at": "2026-07-21T00:00:00Z", "updated_at": "2026-07-21T00:00:01Z", "expires_at": "2026-07-22T00:00:00Z", "revision": float64(2)}
	if errValidate := compiled["execution-record.schema.json"].Validate(validRecord); errValidate != nil {
		t.Fatalf("baseline execution record is invalid: %v", errValidate)
	}
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
