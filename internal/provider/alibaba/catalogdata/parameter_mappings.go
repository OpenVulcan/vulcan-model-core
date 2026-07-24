package catalogdata

import (
	"errors"
	"fmt"
	"strings"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

const (
	// ParameterMappingSchemaVersion is the current reviewed Alibaba wire-mapping schema.
	// ParameterMappingSchemaVersion 是当前已审核 Alibaba Wire 映射 Schema 版本。
	ParameterMappingSchemaVersion = 1
	// parameterMappingFilename is the embedded reviewed mapping filename.
	// parameterMappingFilename 是内嵌已审核映射文件名。
	parameterMappingFilename = "parameter-mappings.json"
)

// ParameterMappingSet stores only C-level mappings whose VCP source and exact outbound path are both implemented.
// ParameterMappingSet 仅保存 VCP 来源与精确出站路径均已实现的 C 级映射。
type ParameterMappingSet struct {
	// SchemaVersion identifies the document schema.
	// SchemaVersion 标识文档 Schema。
	SchemaVersion int `json:"schema_version"`
	// Entries contains mappings in unique identifier order.
	// Entries 按唯一标识顺序包含映射。
	Entries []ParameterMappingEntry `json:"entries"`
}

// ParameterMappingEntry binds one canonical VCP field to one exact provider action and JSON path.
// ParameterMappingEntry 将一个规范 VCP 字段绑定到一个精确供应商动作与 JSON Path。
type ParameterMappingEntry struct {
	// ID is the immutable mapping identifier.
	// ID 是不可变映射标识。
	ID string `json:"id"`
	// ActionBindingID selects one exact implemented driver contract.
	// ActionBindingID 选择一个精确已实现驱动合同。
	ActionBindingID string `json:"action_binding_id"`
	// Operation is the exact VCP operation.
	// Operation 是精确 VCP 操作。
	Operation vcp.OperationKind `json:"operation"`
	// VCPField is the canonical semantic source path.
	// VCPField 是规范语义来源路径。
	VCPField string `json:"vcp_field"`
	// OutboundJSONPath is the exact provider request path.
	// OutboundJSONPath 是精确供应商请求路径。
	OutboundJSONPath string `json:"outbound_json_path"`
	// Transform identifies a closed non-identity projection when required.
	// Transform 标识需要时的封闭非恒等投影。
	Transform string `json:"transform,omitempty"`
	// EvidenceRevision identifies the reviewed wire evidence.
	// EvidenceRevision 标识已审核 Wire 证据。
	EvidenceRevision uint64 `json:"evidence_revision"`
	// Evidence records the exact code or upstream contract boundary.
	// Evidence 记录精确代码或上游合同边界。
	Evidence string `json:"evidence"`
}

// LoadParameterMappings decodes and validates the embedded reviewed mapping set.
// LoadParameterMappings 解码并校验内嵌已审核映射集合。
func LoadParameterMappings() (ParameterMappingSet, error) {
	encoded, errRead := embeddedCatalogs.ReadFile(parameterMappingFilename)
	if errRead != nil {
		return ParameterMappingSet{}, fmt.Errorf("read Alibaba parameter mappings: %w", errRead)
	}
	var mappings ParameterMappingSet
	if errDecode := decodeStrictEmbeddedJSON(encoded, &mappings); errDecode != nil {
		return ParameterMappingSet{}, fmt.Errorf("decode Alibaba parameter mappings: %w", errDecode)
	}
	if errValidate := mappings.Validate(); errValidate != nil {
		return ParameterMappingSet{}, errValidate
	}
	return mappings, nil
}

// Validate verifies one mapping set is complete, uniquely sorted, and restricted to reviewed transforms.
// Validate 校验一个映射集合完整、唯一排序且仅使用已审核转换。
func (m ParameterMappingSet) Validate() error {
	if m.SchemaVersion != ParameterMappingSchemaVersion || len(m.Entries) == 0 {
		return errors.New("Alibaba parameter mapping schema or entries are invalid")
	}
	previousID := ""
	for _, entry := range m.Entries {
		if errEntry := entry.Validate(); errEntry != nil {
			return errEntry
		}
		if previousID != "" && entry.ID <= previousID {
			return errors.New("Alibaba parameter mappings must be uniquely sorted by ID")
		}
		previousID = entry.ID
	}
	return nil
}

// Validate verifies one mapping owns an exact action, semantic source, provider path, and evidence revision.
// Validate 校验一个映射拥有精确动作、语义来源、供应商路径与证据修订。
func (m ParameterMappingEntry) Validate() error {
	if !canonicalNonEmptyString(m.ID) || !strings.HasPrefix(m.ID, "alibaba.") || !canonicalNonEmptyString(m.ActionBindingID) || !strings.HasPrefix(m.ActionBindingID, "action_") || !validParameterMappingOperation(m.Operation) || !canonicalNonEmptyString(m.VCPField) || !canonicalNonEmptyString(m.OutboundJSONPath) || m.EvidenceRevision == 0 || !canonicalNonEmptyString(m.Evidence) || m.Transform != strings.TrimSpace(m.Transform) {
		return fmt.Errorf("Alibaba parameter mapping %q is incomplete", m.ID)
	}
	switch m.Transform {
	case "", "width_height_product", "singleton_array", "media_relation", "boolean_presence", "format_default", "resolution_uppercase":
		return nil
	default:
		return fmt.Errorf("Alibaba parameter mapping %q uses unreviewed transform %q", m.ID, m.Transform)
	}
}

// validParameterMappingOperation accepts only model operations implemented by Alibaba parameter projectors.
// validParameterMappingOperation 仅接受 Alibaba 参数投影器已实现的模型操作。
func validParameterMappingOperation(operation vcp.OperationKind) bool {
	switch operation {
	case vcp.OperationConversationRespond, vcp.OperationMediaAnalyze, vcp.OperationImageGenerate, vcp.OperationImageEdit, vcp.OperationVideoGenerate, vcp.OperationVideoEdit, vcp.OperationSpeechSynthesize, vcp.OperationSpeechTranscribe, vcp.OperationEmbeddingCreate, vcp.OperationRerankDocuments:
		return true
	default:
		return false
	}
}
