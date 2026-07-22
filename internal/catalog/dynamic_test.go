package catalog

import (
	"context"
	"testing"
	"time"
)

// TestApplyDynamicRefreshPreservesLastGoodAndTombstones verifies atomic replacement, deletion evidence, and safe failure retention.
// TestApplyDynamicRefreshPreservesLastGoodAndTombstones 验证原子替换、删除证据与安全失败保留。
func TestApplyDynamicRefreshPreservesLastGoodAndTombstones(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	now := time.Date(2026, 7, 21, 18, 0, 0, 0, time.UTC)
	initial := testCatalogSnapshot()
	initial.ProviderInstanceID = "pvi_kimi"
	fresh, errFresh := ApplyDynamicRefresh(ctx, store, DynamicRefresh{ProviderInstanceID: initial.ProviderInstanceID, Authority: CatalogAuthorityProvider, SourceRevision: "provider-1", ETag: "etag-1", RefreshedAt: now, ExpiresAt: now.Add(time.Hour), Candidate: &initial})
	if errFresh != nil || fresh.Dynamic == nil || fresh.Dynamic.Status != CatalogRefreshFresh || len(fresh.Models) != 1 {
		t.Fatalf("initial refresh=%+v error=%v", fresh.Dynamic, errFresh)
	}
	empty := Snapshot{ProviderInstanceID: initial.ProviderInstanceID}
	removedAt := now.Add(time.Minute)
	removed, errRemoved := ApplyDynamicRefresh(ctx, store, DynamicRefresh{ProviderInstanceID: initial.ProviderInstanceID, Authority: CatalogAuthorityProvider, SourceRevision: "provider-2", ETag: "etag-2", RefreshedAt: removedAt, ExpiresAt: removedAt.Add(time.Hour), Candidate: &empty})
	if errRemoved != nil || len(removed.Models) != 0 || removed.Dynamic == nil || len(removed.Dynamic.Tombstones) != 1 || removed.Dynamic.Tombstones[0].Kind != "model" || removed.Dynamic.Tombstones[0].ID != "model_kimi_k3" {
		t.Fatalf("removed refresh=%+v error=%v", removed, errRemoved)
	}
	failedAt := removedAt.Add(time.Minute)
	stale, errStale := ApplyDynamicRefresh(ctx, store, DynamicRefresh{ProviderInstanceID: initial.ProviderInstanceID, Authority: CatalogAuthorityProvider, RefreshedAt: failedAt, FailureCode: "provider_unreachable"})
	if errStale != nil || stale.Dynamic == nil || stale.Dynamic.Status != CatalogRefreshStale || stale.Dynamic.FailureCode != "provider_unreachable" || len(stale.Dynamic.Tombstones) != 1 || stale.Revision != removed.Revision+1 || !stale.ObservedAt.Equal(removed.ObservedAt) || !stale.Dynamic.RefreshedAt.Equal(failedAt) {
		t.Fatalf("stale refresh=%+v error=%v", stale.Dynamic, errStale)
	}
}

// TestMemoryStorePublishesGlobalCatalogChanges verifies snapshot replacements and deletion share one monotonic change log.
// TestMemoryStorePublishesGlobalCatalogChanges 验证快照替换与删除共享一个单调变更日志。
func TestMemoryStorePublishesGlobalCatalogChanges(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	now := time.Date(2026, 7, 22, 7, 0, 0, 0, time.UTC)
	first := testCatalogSnapshot()
	first.ObservedAt = now
	if errSave := store.Save(ctx, first); errSave != nil {
		t.Fatalf("Save() first error = %v", errSave)
	}
	second := first
	second.Revision = 2
	second.ObservedAt = now.Add(time.Minute)
	if errSave := store.Save(ctx, second); errSave != nil {
		t.Fatalf("Save() second error = %v", errSave)
	}
	if errDelete := store.Delete(ctx, first.ProviderInstanceID); errDelete != nil {
		t.Fatalf("Delete() error = %v", errDelete)
	}
	page, errChanges := store.ListChanges(ctx, 1, 10)
	if errChanges != nil || page.CurrentRevision != 3 || len(page.Changes) != 2 || page.Changes[0].GlobalRevision != 2 || page.Changes[0].Type != ChangeSnapshotUpsert || page.Changes[1].GlobalRevision != 3 || page.Changes[1].Type != ChangeSnapshotDelete {
		t.Fatalf("ListChanges() = (%+v, %v)", page, errChanges)
	}
}
