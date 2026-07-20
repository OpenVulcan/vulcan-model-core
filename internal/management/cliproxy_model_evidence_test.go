package management

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// copiedModelsDocument is the typed subset of the verbatim CLIProxyAPI models.json used by catalog parity tests.
// copiedModelsDocument 是目录一致性测试使用的原样 CLIProxyAPI models.json 类型化子集。
type copiedModelsDocument map[string][]copiedModelRecord

// copiedModelRecord contains every upstream model field projected into Vulcan capabilities.
// copiedModelRecord 包含投影到 Vulcan 能力的全部上游模型字段。
type copiedModelRecord struct {
	// ID is the exact upstream model identifier.
	// ID 是精确上游模型标识。
	ID string `json:"id"`
	// DisplayName is the upstream operator-facing label.
	// DisplayName 是上游面向操作员的标签。
	DisplayName string `json:"display_name"`
	// ContextLength is the upstream total context limit.
	// ContextLength 是上游总上下文限制。
	ContextLength int64 `json:"context_length"`
	// MaxCompletionTokens is the upstream output ceiling.
	// MaxCompletionTokens 是上游输出上限。
	MaxCompletionTokens int64 `json:"max_completion_tokens"`
	// SupportedParameters lists explicit source-catalog request capabilities.
	// SupportedParameters 列出源码目录明确声明的请求能力。
	SupportedParameters []string `json:"supported_parameters"`
	// Thinking contains structured reasoning support when declared.
	// Thinking 包含声明时的结构化推理支持。
	Thinking *copiedThinkingRecord `json:"thinking"`
}

// copiedThinkingRecord contains the numeric reasoning ceiling used by Vulcan's capability projection.
// copiedThinkingRecord 包含 Vulcan 能力投影使用的数值推理上限。
type copiedThinkingRecord struct {
	// Max is the maximum provider reasoning budget when positive.
	// Max 是为正数时的供应商最大推理预算。
	Max int64 `json:"max"`
}

// copiedCatalogParityCase binds one Vulcan model catalog to its exact CLIProxyAPI source list and intentional exclusions.
// copiedCatalogParityCase 将一个 Vulcan 模型目录绑定到其精确 CLIProxyAPI 源列表与有意排除项。
type copiedCatalogParityCase struct {
	// modelCatalogID selects the Vulcan system catalog adaptation.
	// modelCatalogID 选择 Vulcan 系统目录适配。
	modelCatalogID string
	// sourceCatalogID selects the verbatim models.json array.
	// sourceCatalogID 选择原样 models.json 数组。
	sourceCatalogID string
	// excludedModelIDs lists media-output products that VCP cannot yet persist safely.
	// excludedModelIDs 列出 VCP 当前尚不能安全持久化的媒体输出产品。
	excludedModelIDs []string
	// additionalModelIDs lists models added from newer provider-official evidence rather than the pinned CLIProxyAPI snapshot.
	// additionalModelIDs 列出来自更新供应商官方证据而非固定 CLIProxyAPI 快照的模型。
	additionalModelIDs []string
	// additionalOperationCount counts action-specific templates that reuse an already verified provider model.
	// additionalOperationCount 统计复用已验证供应商模型的动作专属模板。
	additionalOperationCount int
}

// TestSystemModelTemplatesMatchCopiedCLIProxyModels verifies every adapted record directly against the verbatim pinned JSON file.
// TestSystemModelTemplatesMatchCopiedCLIProxyModels 直接对照原样固定 JSON 文件校验每条适配记录。
func TestSystemModelTemplatesMatchCopiedCLIProxyModels(t *testing.T) {
	document := readCopiedModelsDocument(t)
	testCases := []copiedCatalogParityCase{
		{modelCatalogID: "openai_codex_api_key", sourceCatalogID: "codex-pro"},
		{modelCatalogID: "openai_codex_account", sourceCatalogID: "codex-pro"},
		{modelCatalogID: "anthropic_api", sourceCatalogID: "claude"},
		{modelCatalogID: "anthropic_claude_code", sourceCatalogID: "claude"},
		{modelCatalogID: "google_ai_studio", sourceCatalogID: "gemini", excludedModelIDs: []string{"gemini-3.1-flash-image-preview", "gemini-3-pro-image-preview"}, additionalModelIDs: []string{"gemini-embedding-2"}, additionalOperationCount: 6},
		{modelCatalogID: "google_interactions", sourceCatalogID: "gemini", excludedModelIDs: []string{"gemini-3.1-flash-image-preview", "gemini-3-pro-image-preview"}, additionalModelIDs: []string{"gemini-3.1-flash-tts-preview", "gemini-2.5-flash-preview-tts", "gemini-2.5-pro-preview-tts"}, additionalOperationCount: 2},
		{modelCatalogID: "google_vertex", sourceCatalogID: "vertex", excludedModelIDs: []string{"gemini-2.5-flash-image", "gemini-3.1-flash-image-preview", "gemini-3-pro-image-preview", "imagen-4.0-generate-001", "imagen-4.0-ultra-generate-001", "imagen-3.0-generate-002", "imagen-3.0-fast-generate-001", "imagen-4.0-fast-generate-001"}},
		{modelCatalogID: "google_antigravity", sourceCatalogID: "antigravity", excludedModelIDs: []string{"gemini-3.1-flash-image"}},
		{modelCatalogID: "xai_api", sourceCatalogID: "xai", additionalOperationCount: 7},
		{modelCatalogID: "xai_account", sourceCatalogID: "xai"},
		{modelCatalogID: "kimi_coding", sourceCatalogID: "kimi"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.modelCatalogID, func(t *testing.T) {
			templates, errTemplates := systemModelTemplates(testCase.modelCatalogID)
			if errTemplates != nil {
				t.Fatalf("systemModelTemplates() error = %v", errTemplates)
			}
			expected := includedCopiedModels(document[testCase.sourceCatalogID], testCase.excludedModelIDs)
			if len(templates) != len(expected)+len(testCase.additionalModelIDs)+testCase.additionalOperationCount {
				t.Fatalf("template count = %d, want %d", len(templates), len(expected)+len(testCase.additionalModelIDs)+testCase.additionalOperationCount)
			}
			for index, record := range expected {
				assertCopiedModelTemplate(t, testCase.modelCatalogID, index, templates[index], record)
			}
			for index, modelID := range testCase.additionalModelIDs {
				if templates[len(expected)+index].upstreamID != modelID {
					t.Fatalf("additional template[%d] = %q, want %q", index, templates[len(expected)+index].upstreamID, modelID)
				}
			}
			if testCase.modelCatalogID == "google_ai_studio" {
				operationTemplate := templates[len(expected)+len(testCase.additionalModelIDs)]
				if operationTemplate.upstreamID != "gemini-2.5-flash" || operationTemplate.operation != vcp.OperationMediaAnalyze {
					t.Fatalf("media analysis template = %#v", operationTemplate)
				}
			}
			if testCase.additionalOperationCount == 2 {
				generateTemplate := templates[len(templates)-2]
				editTemplate := templates[len(templates)-1]
				if generateTemplate.upstreamID != "gemini-3.1-flash-image" || generateTemplate.operation != vcp.OperationImageGenerate || editTemplate.upstreamID != "gemini-3.1-flash-image" || editTemplate.operation != vcp.OperationImageEdit {
					t.Fatalf("image operation templates = generate:%#v edit:%#v", generateTemplate, editTemplate)
				}
			}
			if testCase.additionalOperationCount == 4 {
				operations := templates[len(templates)-4:]
				if operations[0].upstreamID != "grok-imagine-image" || operations[0].operation != vcp.OperationImageGenerate || operations[1].operation != vcp.OperationImageEdit || operations[2].upstreamID != "grok-imagine-image-quality" || operations[2].operation != vcp.OperationImageGenerate || operations[3].operation != vcp.OperationImageEdit {
					t.Fatalf("xAI image operation templates = %#v", operations)
				}
			}
		})
	}
}

// readCopiedModelsDocument loads the repository's byte-for-byte CLIProxyAPI model catalog copy.
// readCopiedModelsDocument 读取仓库中逐字节复制的 CLIProxyAPI 模型目录。
func readCopiedModelsDocument(t *testing.T) copiedModelsDocument {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	modelsPath := filepath.Join(filepath.Dir(sourceFile), "..", "thirdparty", "cliproxyapi", "internal", "registry", "models", "models.json")
	value, errRead := os.ReadFile(modelsPath)
	if errRead != nil {
		t.Fatalf("read copied CLIProxyAPI models.json: %v", errRead)
	}
	var document copiedModelsDocument
	if errDecode := json.Unmarshal(value, &document); errDecode != nil {
		t.Fatalf("decode copied CLIProxyAPI models.json: %v", errDecode)
	}
	return document
}

// includedCopiedModels filters only the explicitly unsupported media-output products while preserving source order.
// includedCopiedModels 仅过滤明确不受支持的媒体输出产品并保留源码顺序。
func includedCopiedModels(records []copiedModelRecord, excludedModelIDs []string) []copiedModelRecord {
	included := make([]copiedModelRecord, 0, len(records))
	for _, record := range records {
		if slices.Contains(excludedModelIDs, record.ID) {
			continue
		}
		included = append(included, record)
	}
	return included
}

// assertCopiedModelTemplate compares one adapted template with every structured fact owned by the source record.
// assertCopiedModelTemplate 将一条适配模板与源码记录拥有的每个结构化事实进行比较。
func assertCopiedModelTemplate(t *testing.T, modelCatalogID string, index int, template systemModelTemplate, record copiedModelRecord) {
	t.Helper()
	expectedReasoning := catalog.CapabilityUnknown
	if record.Thinking != nil {
		expectedReasoning = catalog.CapabilityNative
	} else if record.ID == "grok-4.20-0309-non-reasoning" {
		expectedReasoning = catalog.CapabilityUnsupported
	}
	expectedMaxReasoningTokens := int64(0)
	if record.Thinking != nil {
		expectedMaxReasoningTokens = record.Thinking.Max
	}
	expectedToolCalling := catalog.CapabilityUnknown
	if slices.Contains(record.SupportedParameters, "tools") {
		expectedToolCalling = catalog.CapabilityNative
	}
	expectedContextWindow := record.ContextLength
	expectedMaxOutputTokens := record.MaxCompletionTokens
	if modelCatalogID == "google_ai_studio" && record.ID == "gemini-2.5-flash" {
		expectedContextWindow = 1048576
		expectedMaxOutputTokens = 65536
	}
	if template.upstreamID != record.ID || template.displayName != record.DisplayName || template.contextWindow != expectedContextWindow || template.maxOutputTokens != expectedMaxOutputTokens || template.maxReasoningTokens != expectedMaxReasoningTokens || template.reasoning != expectedReasoning || template.toolCalling != expectedToolCalling {
		t.Fatalf("template[%d] = %#v, source = %#v", index, template, record)
	}
}
