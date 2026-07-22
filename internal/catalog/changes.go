package catalog

import (
	"context"
	"errors"
	"strings"
	"time"
)

// ChangeType identifies one atomic provider-catalog invalidation fact.
// ChangeType 标识一个原子供应商目录失效事实。
type ChangeType string

const (
	// ChangeSnapshotUpsert reports one validated provider snapshot replacement.
	// ChangeSnapshotUpsert 报告一次经过校验的供应商快照替换。
	ChangeSnapshotUpsert ChangeType = "snapshot_upsert"
	// ChangeSnapshotDelete reports removal of one entire provider snapshot.
	// ChangeSnapshotDelete 报告一个完整供应商快照被删除。
	ChangeSnapshotDelete ChangeType = "snapshot_delete"
)

// Change records one globally ordered catalog invalidation without duplicating the full provider snapshot.
// Change 记录一个全局有序目录失效事实，且不复制完整供应商快照。
type Change struct {
	// GlobalRevision is the monotonically increasing Router-wide catalog revision.
	// GlobalRevision 是 Router 全局单调递增目录修订号。
	GlobalRevision uint64 `json:"global_revision"`
	// ProviderInstanceID identifies the exact invalidated provider snapshot.
	// ProviderInstanceID 标识精确失效的供应商快照。
	ProviderInstanceID string `json:"provider_instance_id"`
	// ProviderRevision is the provider-scoped snapshot revision written or removed.
	// ProviderRevision 是写入或移除的供应商作用域快照修订号。
	ProviderRevision uint64 `json:"provider_revision"`
	// Type identifies replacement or complete removal.
	// Type 标识替换或完整移除。
	Type ChangeType `json:"type"`
	// ObservedAt is the authoritative snapshot observation time.
	// ObservedAt 是权威快照观测时间。
	ObservedAt time.Time `json:"observed_at"`
	// SourceRevision is the trusted dynamic-source revision when available.
	// SourceRevision 是可用时的受信任动态来源修订。
	SourceRevision string `json:"source_revision,omitempty"`
	// ETag is the dynamic conditional validator when available.
	// ETag 是可用时的动态条件校验值。
	ETag string `json:"etag,omitempty"`
	// RefreshStatus is the dynamic refresh state when available.
	// RefreshStatus 是可用时的动态刷新状态。
	RefreshStatus CatalogRefreshStatus `json:"refresh_status,omitempty"`
	// Tombstones contain authoritative entity removals from the replacement snapshot.
	// Tombstones 包含替换快照中的权威实体删除记录。
	Tombstones []CatalogTombstone `json:"tombstones,omitempty"`
}

// ChangePage returns an ordered incremental page and the latest committed global revision.
// ChangePage 返回有序增量页及最新已提交全局修订。
type ChangePage struct {
	// CurrentRevision is the latest committed catalog revision at query time.
	// CurrentRevision 是查询时最新已提交目录修订。
	CurrentRevision uint64 `json:"current_revision"`
	// Changes contains revisions strictly after the caller cursor.
	// Changes 包含严格晚于调用方游标的修订。
	Changes []Change `json:"changes"`
}

// ChangeStore exposes globally ordered incremental catalog invalidations.
// ChangeStore 暴露全局有序增量目录失效事实。
type ChangeStore interface {
	// ListChanges returns at most limit changes strictly after one global revision.
	// ListChanges 返回严格晚于一个全局修订且最多 limit 条的变更。
	ListChanges(context.Context, uint64, int) (ChangePage, error)
}

// Validate verifies one closed catalog change before persistence or publication.
// Validate 在持久化或发布前校验一个封闭目录变更。
func (c Change) Validate() error {
	if c.GlobalRevision == 0 || strings.TrimSpace(c.ProviderInstanceID) == "" || c.ProviderInstanceID != strings.TrimSpace(c.ProviderInstanceID) || c.ProviderRevision == 0 || c.ObservedAt.IsZero() || c.Type != ChangeSnapshotUpsert && c.Type != ChangeSnapshotDelete {
		return errors.New("catalog change identity is invalid")
	}
	if c.Type == ChangeSnapshotDelete && (c.SourceRevision != "" || c.ETag != "" || c.RefreshStatus != "" || len(c.Tombstones) != 0) {
		return errors.New("catalog deletion cannot contain replacement metadata")
	}
	for _, tombstone := range c.Tombstones {
		if tombstone.Kind != "model" && tombstone.Kind != "service" || strings.TrimSpace(tombstone.ID) == "" || tombstone.RemovedAt.IsZero() {
			return errors.New("catalog change tombstone is invalid")
		}
	}
	return nil
}

// ChangeFromSnapshot creates one public invalidation fact from a validated snapshot.
// ChangeFromSnapshot 从一个已校验快照创建公开失效事实。
func ChangeFromSnapshot(snapshot Snapshot) Change {
	change := Change{ProviderInstanceID: snapshot.ProviderInstanceID, ProviderRevision: snapshot.Revision, Type: ChangeSnapshotUpsert, ObservedAt: snapshot.ObservedAt.UTC()}
	if snapshot.Dynamic != nil {
		change.SourceRevision = snapshot.Dynamic.SourceRevision
		change.ETag = snapshot.Dynamic.ETag
		change.RefreshStatus = snapshot.Dynamic.Status
		change.Tombstones = append([]CatalogTombstone(nil), snapshot.Dynamic.Tombstones...)
	}
	return change
}
