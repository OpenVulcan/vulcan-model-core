package resource

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestResourcePublicJSONOmitsOwnershipAndInternalLocations verifies public metadata cannot leak authorization or origin details.
// TestResourcePublicJSONOmitsOwnershipAndInternalLocations 验证公开元数据不会泄露授权或来源详情。
func TestResourcePublicJSONOmitsOwnershipAndInternalLocations(t *testing.T) {
	value := Resource{ID: "res_0123456789abcdef0123456789abcdef", OwnerAPIKeyID: "key-secret-scope", SourceURL: "https://origin.example/private", ObjectKey: "objects/private", Kind: vcp.MediaFile, Source: SourceURLImport, State: StateDeleted, Retention: RetentionPersistent, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(), Revision: 2}
	payload, errMarshal := json.Marshal(value)
	if errMarshal != nil {
		t.Fatalf("json.Marshal() error = %v", errMarshal)
	}
	text := string(payload)
	if strings.Contains(text, "key-secret-scope") || strings.Contains(text, "origin.example") || strings.Contains(text, "objects/private") {
		t.Fatalf("public JSON leaked private fields: %s", text)
	}
}

// TestMemoryStoreCommitsReadyResourceWithAtomicQuota verifies state ownership and byte ceilings.
// TestMemoryStoreCommitsReadyResourceWithAtomicQuota 验证状态归属和字节上限。
func TestMemoryStoreCommitsReadyResourceWithAtomicQuota(t *testing.T) {
	store := NewMemoryStore()
	receiving := testReceivingResource("res_11111111111111111111111111111111")
	if errCreate := store.CreateReceiving(context.Background(), receiving); errCreate != nil {
		t.Fatalf("CreateReceiving() error = %v", errCreate)
	}
	ready := testReadyResource(receiving, 8)
	if errCommit := store.CommitReady(context.Background(), ready, 10); errCommit != nil {
		t.Fatalf("CommitReady() error = %v", errCommit)
	}

	second := testReceivingResource("res_22222222222222222222222222222222")
	if errCreate := store.CreateReceiving(context.Background(), second); errCreate != nil {
		t.Fatalf("CreateReceiving(second) error = %v", errCreate)
	}
	if errCommit := store.CommitReady(context.Background(), testReadyResource(second, 3), 10); !errors.Is(errCommit, ErrResourceQuotaExceeded) {
		t.Fatalf("CommitReady(second) error = %v, want ErrResourceQuotaExceeded", errCommit)
	}
}

// TestMemoryStoreExpiryDeleteLifecycle verifies expired objects remain blocked until deterministic cleanup.
// TestMemoryStoreExpiryDeleteLifecycle 验证过期对象保持阻断直到确定性清理。
func TestMemoryStoreExpiryDeleteLifecycle(t *testing.T) {
	store := NewMemoryStore()
	receiving := testReceivingResource("res_33333333333333333333333333333333")
	if errCreate := store.CreateReceiving(context.Background(), receiving); errCreate != nil {
		t.Fatalf("CreateReceiving() error = %v", errCreate)
	}
	ready := testReadyResource(receiving, 5)
	if errCommit := store.CommitReady(context.Background(), ready, 100); errCommit != nil {
		t.Fatalf("CommitReady() error = %v", errCommit)
	}
	expired, errExpire := store.MarkExpired(context.Background(), ready.ID, ready.Revision, *ready.ExpiresAt)
	if errExpire != nil || expired.State != StateExpired {
		t.Fatalf("MarkExpired() resource = %#v, error = %v", expired, errExpire)
	}
	deleting, errDelete := store.BeginDelete(context.Background(), expired.ID, expired.Revision, expired.UpdatedAt.Add(time.Second))
	if errDelete != nil {
		t.Fatalf("BeginDelete() error = %v", errDelete)
	}
	if errFinish := store.FinishDelete(context.Background(), deleting.ID, deleting.Revision, deleting.UpdatedAt.Add(time.Second)); errFinish != nil {
		t.Fatalf("FinishDelete() error = %v", errFinish)
	}
	tombstone, errGet := store.Get(context.Background(), deleting.ID)
	if errGet != nil || tombstone.State != StateDeleted || tombstone.ObjectKey != "" || tombstone.SHA256 != "" {
		t.Fatalf("deleted tombstone = %#v, error = %v", tombstone, errGet)
	}
}

// TestResourceValidationRejectsMetadataKindDrift verifies media metadata cannot cross resource kinds.
// TestResourceValidationRejectsMetadataKindDrift 验证媒体元数据不能跨越资源类型。
func TestResourceValidationRejectsMetadataKindDrift(t *testing.T) {
	resource := testReadyResource(testReceivingResource("res_44444444444444444444444444444444"), 5)
	resource.Metadata = Metadata{Audio: &AudioMetadata{Encoding: "pcm"}}
	if errValidate := resource.Validate(); !errors.Is(errValidate, ErrInvalidResource) {
		t.Fatalf("Validate() error = %v, want ErrInvalidResource", errValidate)
	}
}

// testReceivingResource creates one valid reserved image resource.
// testReceivingResource 创建一个有效已保留图片资源。
func testReceivingResource(identifier string) Resource {
	createdAt := time.Date(2026, time.July, 20, 12, 0, 0, 0, time.UTC)
	expiresAt := createdAt.Add(time.Hour)
	return Resource{ID: identifier, OwnerAPIKeyID: "key_test", Kind: vcp.MediaImage, Source: SourceMultipart, State: StateReceiving, Retention: RetentionEphemeral, CreatedAt: createdAt, UpdatedAt: createdAt, ExpiresAt: &expiresAt, Revision: 1}
}

// testReadyResource completes one reserved image resource with exact facts.
// testReadyResource 使用精确事实完成一个已保留图片资源。
func testReadyResource(receiving Resource, size int64) Resource {
	receiving.State = StateReady
	receiving.MIMEType = "image/png"
	receiving.SizeBytes = size
	receiving.SHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	receiving.ObjectKey = "objects/" + receiving.ID
	receiving.Metadata = Metadata{Image: &ImageMetadata{Width: 1, Height: 1}}
	receiving.UpdatedAt = receiving.UpdatedAt.Add(time.Second)
	receiving.Revision++
	return receiving
}
