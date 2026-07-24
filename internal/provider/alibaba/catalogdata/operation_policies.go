package catalogdata

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

const (
	// OperationPolicySchemaVersion is the current Alibaba publication-policy file schema.
	// OperationPolicySchemaVersion 是当前 Alibaba 发布策略文件 Schema 版本。
	OperationPolicySchemaVersion = 1
	// operationPolicyFilename is the immutable embedded policy filename.
	// operationPolicyFilename 是不可变的内嵌策略文件名。
	operationPolicyFilename = "model-operation-policies.json"
)

// OperationPolicySet stores the complete reviewed decision set for every classified operation in verified Alibaba snapshots.
// OperationPolicySet 保存 Alibaba 已验证快照中每个已分类操作的完整审核决策集合。
type OperationPolicySet struct {
	// SchemaVersion identifies the policy document schema.
	// SchemaVersion 标识策略文档 Schema。
	SchemaVersion int `json:"schema_version"`
	// Entries contains exact catalog, model, and operation decisions in canonical order.
	// Entries 按规范顺序包含精确的目录、模型与操作决策。
	Entries []OperationPolicyEntry `json:"entries"`
}

// OperationPolicyEntry records one evidence-bound Router publication decision without runtime identifiers.
// OperationPolicyEntry 记录一个绑定证据且不含运行时标识的 Router 发布决策。
type OperationPolicyEntry struct {
	// CatalogID fixes one product, site, region, and channel boundary.
	// CatalogID 固定一个产品、站点、区域与通道边界。
	CatalogID string `json:"catalog_id"`
	// ModelID is the exact upstream model identifier in that catalog.
	// ModelID 是该目录中的精确上游模型标识。
	ModelID string `json:"model_id"`
	// Operation is the independently classified VCP operation.
	// Operation 是独立分类的 VCP 操作。
	Operation vcp.OperationKind `json:"operation"`
	// Status controls publication while retaining all provider facts.
	// Status 在保留全部供应商事实的同时控制发布。
	Status catalog.ModelOperationSupportStatus `json:"status"`
	// Reason is the closed evidence-backed decision reason.
	// Reason 是由证据支持的封闭决策原因。
	Reason catalog.ModelOperationSupportReason `json:"reason"`
	// EvidenceRevision identifies the reviewed evidence revision.
	// EvidenceRevision 标识已审核证据修订号。
	EvidenceRevision uint64 `json:"evidence_revision"`
	// SourceRevision binds the decision to one normalized provider snapshot revision.
	// SourceRevision 将决策绑定到一个规范化供应商快照修订。
	SourceRevision string `json:"source_revision"`
	// Evidence explains the non-secret basis for this decision.
	// Evidence 说明该决策的不含秘密依据。
	Evidence string `json:"evidence"`
}

// LoadOperationPolicies decodes and fully validates the embedded Alibaba publication policy set.
// LoadOperationPolicies 解码并完整校验内嵌 Alibaba 发布策略集合。
func LoadOperationPolicies() (OperationPolicySet, error) {
	encoded, errRead := embeddedCatalogs.ReadFile(operationPolicyFilename)
	if errRead != nil {
		return OperationPolicySet{}, fmt.Errorf("read Alibaba operation policies: %w", errRead)
	}
	var policies OperationPolicySet
	if errDecode := decodeStrictEmbeddedJSON(encoded, &policies); errDecode != nil {
		return OperationPolicySet{}, fmt.Errorf("decode Alibaba operation policies: %w", errDecode)
	}
	if errValidate := policies.Validate(); errValidate != nil {
		return OperationPolicySet{}, errValidate
	}
	if errCoverage := policies.ValidateEmbeddedCoverage(); errCoverage != nil {
		return OperationPolicySet{}, errCoverage
	}
	return policies, nil
}

// Validate verifies canonical ordering, unique keys, closed status semantics, and evidence identity.
// Validate 校验规范排序、唯一键、封闭状态语义与证据身份。
func (p OperationPolicySet) Validate() error {
	if p.SchemaVersion != OperationPolicySchemaVersion || len(p.Entries) == 0 {
		return errors.New("Alibaba operation policy schema or entries are invalid")
	}
	previousKey := ""
	for _, entry := range p.Entries {
		if errEntry := entry.Validate(); errEntry != nil {
			return errEntry
		}
		key := entry.Key()
		if previousKey != "" && key <= previousKey {
			return errors.New("Alibaba operation policies must be uniquely sorted by catalog, model, and operation")
		}
		previousKey = key
	}
	return nil
}

// Validate verifies one operation policy uses a closed operation, decision, reason, and evidence revision.
// Validate 校验一个操作策略使用封闭的操作、决策、原因与证据修订。
func (p OperationPolicyEntry) Validate() error {
	_, errRevision := hex.DecodeString(p.SourceRevision)
	if !canonicalNonEmptyString(p.CatalogID) || !canonicalNonEmptyString(p.ModelID) || !validClassifiedOperation(p.Operation) || p.EvidenceRevision == 0 || len(p.SourceRevision) != 64 || errRevision != nil || !canonicalNonEmptyString(p.Evidence) {
		return fmt.Errorf("Alibaba operation policy %q is incomplete", p.Key())
	}
	if !validPolicyDecision(p.Status, p.Reason) {
		return fmt.Errorf("Alibaba operation policy %q has incompatible status %q and reason %q", p.Key(), p.Status, p.Reason)
	}
	return nil
}

// Key returns the canonical non-persisted identity for one policy entry.
// Key 返回一个策略条目的规范非持久化身份。
func (p OperationPolicyEntry) Key() string {
	return OperationPolicyKey(p.CatalogID, p.ModelID, p.Operation)
}

// OperationPolicyKey creates the exact catalog, model, and operation lookup key.
// OperationPolicyKey 创建精确的目录、模型与操作查找键。
func OperationPolicyKey(catalogID string, modelID string, operation vcp.OperationKind) string {
	return catalogID + "\x00" + modelID + "\x00" + string(operation)
}

// EntryMap returns a mutation-safe exact-key lookup after validating the policy set.
// EntryMap 在校验策略集合后返回一个可安全变更的精确键查找表。
func (p OperationPolicySet) EntryMap() (map[string]OperationPolicyEntry, error) {
	if errValidate := p.Validate(); errValidate != nil {
		return nil, errValidate
	}
	entries := make(map[string]OperationPolicyEntry, len(p.Entries))
	for _, entry := range p.Entries {
		entries[entry.Key()] = entry
	}
	return entries, nil
}

// ValidateEmbeddedCoverage proves every classified operation has exactly one decision and no decision crosses an evidence boundary.
// ValidateEmbeddedCoverage 证明每个已分类操作恰有一个决策，且没有决策跨越证据边界。
func (p OperationPolicySet) ValidateEmbeddedCoverage() error {
	entries, errEntries := p.EntryMap()
	if errEntries != nil {
		return errEntries
	}
	manifest, errManifest := LoadManifest()
	if errManifest != nil {
		return errManifest
	}
	expected := make(map[string]struct{})
	for _, manifestEntry := range manifest.Entries {
		if manifestEntry.Status != VerificationVerified {
			continue
		}
		snapshot, errSnapshot := LoadSnapshot(manifestEntry.Filename)
		if errSnapshot != nil {
			return errSnapshot
		}
		for _, model := range snapshot.Models {
			for _, operation := range ClassifiedOperations(model) {
				key := OperationPolicyKey(manifestEntry.CatalogID, model.ModelID, operation)
				expected[key] = struct{}{}
				entry, exists := entries[key]
				if !exists {
					return fmt.Errorf("Alibaba classified operation %q has no explicit policy", key)
				}
				if entry.SourceRevision != snapshot.SourceRevision {
					return fmt.Errorf("Alibaba operation policy %q targets stale source revision", key)
				}
			}
		}
	}
	for key := range entries {
		if _, exists := expected[key]; !exists {
			return fmt.Errorf("Alibaba operation policy %q has no classified embedded operation", key)
		}
	}
	return nil
}

// ValidateStableDecisions rejects pending entries from a release baseline while leaving the runtime schema capable of representing review work.
// ValidateStableDecisions 拒绝发布基线中的待审核条目，同时保留运行时 Schema 表示审核工作的能力。
func (p OperationPolicySet) ValidateStableDecisions() error {
	if errValidate := p.ValidateEmbeddedCoverage(); errValidate != nil {
		return errValidate
	}
	for _, entry := range p.Entries {
		if entry.Status == catalog.ModelOperationPendingReview {
			return fmt.Errorf("Alibaba operation policy %q is still pending review", entry.Key())
		}
	}
	return nil
}

// SortOperationPolicyEntries returns a canonical copy suitable for deterministic generation.
// SortOperationPolicyEntries 返回适用于确定性生成的规范副本。
func SortOperationPolicyEntries(entries []OperationPolicyEntry) []OperationPolicyEntry {
	ordered := append([]OperationPolicyEntry(nil), entries...)
	sort.Slice(ordered, func(left int, right int) bool { return ordered[left].Key() < ordered[right].Key() })
	return ordered
}

// validPolicyDecision enforces the closed relationship between publication state and evidence reason.
// validPolicyDecision 强制发布状态与证据原因之间的封闭关系。
func validPolicyDecision(status catalog.ModelOperationSupportStatus, reason catalog.ModelOperationSupportReason) bool {
	switch status {
	case catalog.ModelOperationSupported:
		return reason == catalog.SupportReasonRuntimeVerified || reason == catalog.SupportReasonProviderContractVerified
	case catalog.ModelOperationPendingReview:
		return reason == catalog.SupportReasonNewCatalogEntry || reason == catalog.SupportReasonMissingProtocolEvidence || reason == catalog.SupportReasonMissingParameterMapping || reason == catalog.SupportReasonMissingExecutionFixture
	case catalog.ModelOperationUnsupported:
		switch reason {
		case catalog.SupportReasonProviderInferenceDisabled, catalog.SupportReasonOperationNotImplemented, catalog.SupportReasonCodingCapabilityInsufficient, catalog.SupportReasonDeprecatedOrSuperseded, catalog.SupportReasonOutOfScopeRealtime, catalog.SupportReasonOutOfScopeProduct:
			return true
		default:
			return false
		}
	default:
		return false
	}
}

// validClassifiedOperation accepts only operation families the Alibaba catalog classifier can produce.
// validClassifiedOperation 仅接受 Alibaba 目录分类器可以产生的操作系列。
func validClassifiedOperation(operation vcp.OperationKind) bool {
	switch operation {
	case vcp.OperationConversationRespond, vcp.OperationMediaAnalyze, vcp.OperationImageGenerate, vcp.OperationVideoGenerate, vcp.OperationSpeechSynthesize, vcp.OperationSpeechTranscribe, vcp.OperationEmbeddingCreate, vcp.OperationRerankDocuments:
		return true
	default:
		return false
	}
}
