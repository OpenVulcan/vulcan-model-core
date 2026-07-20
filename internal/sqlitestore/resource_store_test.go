package sqlitestore

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestResourceStorePersistsLifecycleAndQuota verifies durable private fields, quota, and optimistic transitions.
// TestResourceStorePersistsLifecycleAndQuota 验证持久私有字段、配额及乐观状态迁移。
func TestResourceStorePersistsLifecycleAndQuota(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, errDatabase := Open(ctx, filepath.Join(t.TempDir(), "resources.db"))
	if errDatabase != nil {
		t.Fatalf("Open() error = %v", errDatabase)
	}
	t.Cleanup(func() { _ = database.Close() })
	store, errStore := NewResourceStore(database)
	if errStore != nil {
		t.Fatalf("NewResourceStore() error = %v", errStore)
	}
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	first := receivingResource("res_00000000000000000000000000000001", now)
	if errCreate := store.CreateReceiving(ctx, first); errCreate != nil {
		t.Fatalf("CreateReceiving() error = %v", errCreate)
	}
	ready := readyResource(first, 8, now.Add(time.Minute))
	if errReady := store.CommitReady(ctx, ready, 10); errReady != nil {
		t.Fatalf("CommitReady() error = %v", errReady)
	}
	persisted, errGet := store.Get(ctx, first.ID)
	if errGet != nil || persisted.OwnerAPIKeyID != first.OwnerAPIKeyID || persisted.ObjectKey != ready.ObjectKey || persisted.SourceURL != first.SourceURL {
		t.Fatalf("Get() = %#v, error = %v", persisted, errGet)
	}
	second := receivingResource("res_00000000000000000000000000000002", now)
	if errCreate := store.CreateReceiving(ctx, second); errCreate != nil {
		t.Fatalf("CreateReceiving(second) error = %v", errCreate)
	}
	if errReady := store.CommitReady(ctx, readyResource(second, 3, now.Add(time.Minute)), 10); !errors.Is(errReady, resource.ErrResourceQuotaExceeded) {
		t.Fatalf("CommitReady(second) error = %v, want quota", errReady)
	}
	expired, errExpired := store.MarkExpired(ctx, first.ID, ready.Revision, now.Add(2*time.Hour))
	if errExpired != nil || expired.State != resource.StateExpired {
		t.Fatalf("MarkExpired() = %#v, error = %v", expired, errExpired)
	}
	deleting, errDelete := store.BeginDelete(ctx, first.ID, expired.Revision, now.Add(2*time.Hour))
	if errDelete != nil || deleting.State != resource.StateDeleting {
		t.Fatalf("BeginDelete() = %#v, error = %v", deleting, errDelete)
	}
	if errFinish := store.FinishDelete(ctx, first.ID, deleting.Revision, now.Add(2*time.Hour)); errFinish != nil {
		t.Fatalf("FinishDelete() error = %v", errFinish)
	}
}

// TestResourceStorePersistsGenerationProvenance verifies provider origin survives durable recovery.
// TestResourceStorePersistsGenerationProvenance 验证供应商来源在持久恢复后保持不变。
func TestResourceStorePersistsGenerationProvenance(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, errDatabase := Open(ctx, filepath.Join(t.TempDir(), "generated-resource.db"))
	if errDatabase != nil {
		t.Fatalf("Open() error = %v", errDatabase)
	}
	t.Cleanup(func() { _ = database.Close() })
	store, errStore := NewResourceStore(database)
	if errStore != nil {
		t.Fatalf("NewResourceStore() error = %v", errStore)
	}
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	expiresAt := now.Add(time.Hour)
	provenance := &resource.GenerationProvenance{ExecutionID: "execution-veo", ProviderDefinitionID: "definition-google", ProviderModelID: "model-veo", UpstreamModelID: "veo-3.1-generate-preview", ActionBindingID: "action_google_video_generate", Operation: vcp.OperationVideoGenerate}
	value := resource.Resource{ID: "res_00000000000000000000000000000003", OwnerAPIKeyID: "key_1", Kind: vcp.MediaVideo, Source: resource.SourceGenerated, GeneratedBy: provenance, State: resource.StateReceiving, Retention: resource.RetentionEphemeral, CreatedAt: now, UpdatedAt: now, ExpiresAt: &expiresAt, Revision: 1}
	if errCreate := store.CreateReceiving(ctx, value); errCreate != nil {
		t.Fatalf("CreateReceiving() error = %v", errCreate)
	}
	persisted, errGet := store.Get(ctx, value.ID)
	if errGet != nil || persisted.GeneratedBy == nil || *persisted.GeneratedBy != *provenance {
		t.Fatalf("Get() = %#v, error = %v", persisted, errGet)
	}
}

// receivingResource creates one valid URL-import reservation fixture.
// receivingResource 创建一个有效 URL 导入预留夹具。
func receivingResource(identifier string, now time.Time) resource.Resource {
	expiresAt := now.Add(time.Hour)
	return resource.Resource{ID: identifier, OwnerAPIKeyID: "key_1", Kind: vcp.MediaFile, Source: resource.SourceURLImport, SourceURL: "https://example.test/private-source", State: resource.StateReceiving, Retention: resource.RetentionEphemeral, CreatedAt: now, UpdatedAt: now, ExpiresAt: &expiresAt, Revision: 1}
}

// readyResource completes one reserved file fixture with exact immutable facts.
// readyResource 使用精确不可变事实完成一个预留文件夹具。
func readyResource(receiving resource.Resource, size int64, updatedAt time.Time) resource.Resource {
	receiving.State = resource.StateReady
	receiving.MIMEType = "application/pdf"
	receiving.SizeBytes = size
	receiving.SHA256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	receiving.ObjectKey = receiving.ID[:6] + "/" + receiving.ID
	receiving.UpdatedAt = updatedAt
	receiving.Revision++
	return receiving
}
