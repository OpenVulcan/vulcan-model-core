package catalogdata

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"path"
)

// embeddedCatalogs contains only checked-in, credential-free Alibaba catalog JSON files.
// embeddedCatalogs 仅包含已提交且不含凭据的 Alibaba 目录 JSON 文件。
//
//go:embed *.json
var embeddedCatalogs embed.FS

// LoadManifest decodes and validates the embedded product and region matrix.
// LoadManifest 解码并校验内嵌产品与区域矩阵。
func LoadManifest() (Manifest, error) {
	encoded, errRead := embeddedCatalogs.ReadFile("manifest.json")
	if errRead != nil {
		return Manifest{}, fmt.Errorf("read Alibaba catalog manifest: %w", errRead)
	}
	var manifest Manifest
	if errDecode := decodeStrictEmbeddedJSON(encoded, &manifest); errDecode != nil {
		return Manifest{}, fmt.Errorf("decode Alibaba catalog manifest: %w", errDecode)
	}
	if errValidate := manifest.Validate(); errValidate != nil {
		return Manifest{}, errValidate
	}
	return manifest, nil
}

// LoadSnapshot decodes one verified embedded snapshot by manifest filename.
// LoadSnapshot 按 Manifest 文件名解码一份已验证的内嵌快照。
func LoadSnapshot(filename string) (Snapshot, error) {
	if filename == "" || path.Base(filename) != filename {
		return Snapshot{}, fmt.Errorf("Alibaba catalog filename %q is invalid", filename)
	}
	encoded, errRead := embeddedCatalogs.ReadFile(filename)
	if errRead != nil {
		return Snapshot{}, fmt.Errorf("read Alibaba catalog snapshot %q: %w", filename, errRead)
	}
	var snapshot Snapshot
	if errDecode := decodeStrictEmbeddedJSON(encoded, &snapshot); errDecode != nil {
		return Snapshot{}, fmt.Errorf("decode Alibaba catalog snapshot %q: %w", filename, errDecode)
	}
	if errValidate := snapshot.Validate(); errValidate != nil {
		return Snapshot{}, fmt.Errorf("validate Alibaba catalog snapshot %q: %w", filename, errValidate)
	}
	return snapshot, nil
}

// decodeStrictEmbeddedJSON rejects unknown fields and trailing JSON in one versioned catalog artifact.
// decodeStrictEmbeddedJSON 拒绝一个版本化目录产物中的未知字段与尾随 JSON。
func decodeStrictEmbeddedJSON(encoded []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if errDecode := decoder.Decode(destination); errDecode != nil {
		return errDecode
	}
	if errTrailing := decoder.Decode(&struct{}{}); errTrailing != io.EOF {
		if errTrailing == nil {
			return fmt.Errorf("catalog artifact contains trailing JSON")
		}
		return fmt.Errorf("decode trailing catalog JSON: %w", errTrailing)
	}
	return nil
}

// SnapshotForCatalogID returns one verified snapshot without crossing product or region boundaries.
// SnapshotForCatalogID 返回一份已验证快照且不跨越产品或区域边界。
func SnapshotForCatalogID(catalogID string) (Snapshot, bool, error) {
	manifest, errManifest := LoadManifest()
	if errManifest != nil {
		return Snapshot{}, false, errManifest
	}
	for _, entry := range manifest.Entries {
		if entry.CatalogID != catalogID {
			continue
		}
		if entry.Status != VerificationVerified {
			return Snapshot{}, false, nil
		}
		snapshot, errSnapshot := LoadSnapshot(entry.Filename)
		if errSnapshot != nil {
			return Snapshot{}, false, errSnapshot
		}
		if snapshot.Product != entry.Product || snapshot.ConsoleSite != entry.ConsoleSite || snapshot.Region != entry.Region || snapshot.Channel != entry.Channel {
			return Snapshot{}, false, fmt.Errorf("Alibaba catalog %q snapshot crosses its manifest boundary", catalogID)
		}
		if snapshot.SourceRevision != entry.ContentRevision {
			return Snapshot{}, false, fmt.Errorf("Alibaba catalog %q manifest targets a stale content revision", catalogID)
		}
		return snapshot, true, nil
	}
	return Snapshot{}, false, fmt.Errorf("Alibaba catalog ID %q is not declared", catalogID)
}

// VerifyEmbedded validates every verified snapshot and every explicit unverified boundary.
// VerifyEmbedded 校验每份已验证快照及每个显式未验证边界。
func VerifyEmbedded() error {
	manifest, errManifest := LoadManifest()
	if errManifest != nil {
		return errManifest
	}
	for _, entry := range manifest.Entries {
		if entry.Status != VerificationVerified {
			continue
		}
		snapshot, errSnapshot := LoadSnapshot(entry.Filename)
		if errSnapshot != nil {
			return errSnapshot
		}
		if snapshot.SourceRevision != entry.ContentRevision {
			return fmt.Errorf("Alibaba catalog %q manifest targets a stale content revision", entry.CatalogID)
		}
	}
	policies, errPolicies := LoadOperationPolicies()
	if errPolicies != nil {
		return errPolicies
	}
	if errStable := policies.ValidateStableDecisions(); errStable != nil {
		return errStable
	}
	_, errMappings := LoadParameterMappings()
	return errMappings
}
