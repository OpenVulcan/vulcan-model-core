package catalogdata

import (
	"testing"
)

// TestEmbeddedVerifiedCatalogBaselinesPreserveCompleteCounts verifies committed provider observations cannot be silently truncated.
// TestEmbeddedVerifiedCatalogBaselinesPreserveCompleteCounts 验证已提交的供应商观测不会被静默截断。
func TestEmbeddedVerifiedCatalogBaselinesPreserveCompleteCounts(t *testing.T) {
	t.Parallel()
	// expectedBaselines freezes the reviewed full-pagination observations; a later refresh must update this evidence deliberately.
	// expectedBaselines 冻结已审核的完整分页观测；后续刷新必须显式更新该证据。
	expectedBaselines := []struct {
		// catalogID identifies one immutable product and region boundary.
		// catalogID 标识一个不可变的产品与区域边界。
		catalogID string
		// familyTotal is the provider-reported unique source-family count.
		// familyTotal 是供应商报告的唯一来源族数量。
		familyTotal int
		// recordTotal is the complete normalized concrete-model count.
		// recordTotal 是完整规范化具体模型数量。
		recordTotal int
	}{
		{catalogID: "alibaba_model_studio_cn", familyTotal: 171, recordTotal: 471},
		{catalogID: "alibaba_model_studio_sg_domestic", familyTotal: 90, recordTotal: 225},
		{catalogID: "alibaba_coding_plan_cn", familyTotal: 10, recordTotal: 10},
		{catalogID: "alibaba_coding_plan_global", familyTotal: 10, recordTotal: 10},
		{catalogID: "alibaba_token_plan_personal_cn", familyTotal: 11, recordTotal: 11},
		{catalogID: "alibaba_token_plan_team_cn", familyTotal: 22, recordTotal: 22},
		{catalogID: "alibaba_token_plan_team_global", familyTotal: 18, recordTotal: 18},
	}
	for _, expected := range expectedBaselines {
		snapshot, verified, errSnapshot := SnapshotForCatalogID(expected.catalogID)
		if errSnapshot != nil || !verified {
			t.Fatalf("SnapshotForCatalogID(%q) verified=%v error=%v", expected.catalogID, verified, errSnapshot)
		}
		if snapshot.FamilyTotal != expected.familyTotal || snapshot.RecordTotal != expected.recordTotal || len(snapshot.Models) != expected.recordTotal {
			t.Fatalf("catalog %q counts families=%d records=%d models=%d, want %d/%d/%d", expected.catalogID, snapshot.FamilyTotal, snapshot.RecordTotal, len(snapshot.Models), expected.familyTotal, expected.recordTotal, expected.recordTotal)
		}
	}
}

// TestCatalogEvidenceRejectsNonCanonicalIdentities verifies generated snapshots cannot contain whitespace-aliased keys or list facts.
// TestCatalogEvidenceRejectsNonCanonicalIdentities 验证生成快照不能包含空白别名键或列表事实。
func TestCatalogEvidenceRejectsNonCanonicalIdentities(t *testing.T) {
	base, verified, errSnapshot := SnapshotForCatalogID("alibaba_token_plan_personal_cn")
	if errSnapshot != nil || !verified {
		t.Fatalf("SnapshotForCatalogID() verified=%v error=%v", verified, errSnapshot)
	}
	snapshotTests := []struct {
		// name identifies the exact normalization boundary.
		// name 标识精确的规范化边界。
		name string
		// mutate introduces one invalid alias without changing unrelated facts.
		// mutate 引入一个无效别名且不修改无关事实。
		mutate func(*Snapshot)
	}{
		{name: "source API", mutate: func(snapshot *Snapshot) { snapshot.SourceAPI += " " }},
	}
	for _, test := range snapshotTests {
		t.Run(test.name, func(t *testing.T) {
			candidate := base
			candidate.Models = append([]ModelFact(nil), base.Models...)
			test.mutate(&candidate)
			revision, errRevision := candidate.ContentRevision()
			if errRevision != nil {
				t.Fatalf("ContentRevision() error = %v", errRevision)
			}
			candidate.SourceRevision = revision
			if errValidate := candidate.Validate(); errValidate == nil {
				t.Fatal("Validate() accepted a non-canonical catalog identity")
			}
		})
	}
	modelTests := []ModelFact{
		{ModelID: "model ", DisplayName: "Model", SourceFamilyID: "family"},
		{ModelID: "model", DisplayName: "Model ", SourceFamilyID: "family"},
		{ModelID: "model", DisplayName: "Model", SourceFamilyID: "family ", Capabilities: []string{"text"}},
		{ModelID: "model", DisplayName: "Model", SourceFamilyID: "family", ModelAlias: "alias "},
		{ModelID: "model", DisplayName: "Model", SourceFamilyID: "family", Capabilities: []string{" "}},
	}
	for _, model := range modelTests {
		if errValidate := model.Validate(); errValidate == nil {
			t.Fatalf("Validate() accepted non-canonical model fact %#v", model)
		}
	}
}

// TestRateLimitFactRejectsNonCanonicalIdentity verifies rate-limit lookup keys and provider metric names are exact.
// TestRateLimitFactRejectsNonCanonicalIdentity 验证速率限制查找键与供应商指标名称保持精确。
func TestRateLimitFactRejectsNonCanonicalIdentity(t *testing.T) {
	count := int64(10)
	period := int64(60)
	usage := int64(1000)
	for _, limit := range []RateLimitFact{
		{TierID: "tier ", CountLimit: &count, CountPeriodSeconds: &period},
		{TierID: "tier", TierType: "default ", CountLimit: &count, CountPeriodSeconds: &period},
		{TierID: "tier", UsageLimit: &usage, UsagePeriodSeconds: &period, UsageField: "tokens "},
	} {
		if errValidate := limit.Validate(); errValidate == nil {
			t.Fatalf("Validate() accepted non-canonical rate limit %#v", limit)
		}
	}
}

// TestDecodeStrictEmbeddedJSONRejectsSchemaDrift verifies versioned artifacts cannot silently accept new fields or extra documents.
// TestDecodeStrictEmbeddedJSONRejectsSchemaDrift 验证版本化产物不能静默接受新字段或额外文档。
func TestDecodeStrictEmbeddedJSONRejectsSchemaDrift(t *testing.T) {
	for _, encoded := range []string{
		`{"schema_version":1,"entries":[],"unexpected":true}`,
		`{"schema_version":1,"entries":[]} {"schema_version":1,"entries":[]}`,
	} {
		var manifest Manifest
		if errDecode := decodeStrictEmbeddedJSON([]byte(encoded), &manifest); errDecode == nil {
			t.Fatalf("decodeStrictEmbeddedJSON(%q) error = nil", encoded)
		}
	}
}

// TestManifestRequiresTheClosedProductMatrix verifies missing or cross-region boundaries cannot pass validation.
// TestManifestRequiresTheClosedProductMatrix 验证缺失或跨区域边界不能通过校验。
func TestManifestRequiresTheClosedProductMatrix(t *testing.T) {
	manifest, errManifest := LoadManifest()
	if errManifest != nil {
		t.Fatalf("LoadManifest() error = %v", errManifest)
	}
	missing := manifest
	missing.Entries = append([]ManifestEntry(nil), manifest.Entries[1:]...)
	if errValidate := missing.Validate(); errValidate == nil {
		t.Fatal("Validate() accepted a missing product boundary")
	}
	crossed := manifest
	crossed.Entries = append([]ManifestEntry(nil), manifest.Entries...)
	crossed.Entries[0].Region = RegionSingapore
	if errValidate := crossed.Validate(); errValidate == nil {
		t.Fatal("Validate() accepted a cross-region product boundary")
	}
}

// TestSnapshotRequiresTheClosedProductMatrix verifies individually valid enums cannot form an undeclared product boundary.
// TestSnapshotRequiresTheClosedProductMatrix 验证各自有效的枚举不能组成未声明的产品边界。
func TestSnapshotRequiresTheClosedProductMatrix(t *testing.T) {
	snapshot, verified, errSnapshot := SnapshotForCatalogID("alibaba_token_plan_personal_cn")
	if errSnapshot != nil || !verified {
		t.Fatalf("SnapshotForCatalogID() verified=%v error=%v", verified, errSnapshot)
	}
	snapshot.ConsoleSite = ConsoleSiteNotApplicable
	revision, errRevision := snapshot.ContentRevision()
	if errRevision != nil {
		t.Fatalf("ContentRevision() error = %v", errRevision)
	}
	snapshot.SourceRevision = revision
	if errValidate := snapshot.Validate(); errValidate == nil {
		t.Fatal("Validate() accepted an undeclared product boundary")
	}
}
