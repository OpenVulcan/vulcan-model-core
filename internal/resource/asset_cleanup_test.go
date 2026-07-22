package resource

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

// cleanupAssetUploader records exact provider deletions and can preserve one transient failure.
// cleanupAssetUploader 记录精确供应商删除并可保留一次暂时失败。
type cleanupAssetUploader struct {
	// deletes contains upstream handles in attempted order.
	// deletes 按尝试顺序包含上游句柄。
	deletes []string
	// failure is returned without mutating durable binding state.
	// failure 在不修改持久绑定状态的情况下返回。
	failure error
}

// Upload is unused by cleanup-only tests.
// Upload 不被仅清理测试使用。
func (u *cleanupAssetUploader) Upload(context.Context, AssetUploadRequest) (AssetUploadResult, error) {
	return AssetUploadResult{}, errors.New("upload is not expected")
}

// Delete records one exact protected handle and returns the configured outcome.
// Delete 记录一个精确受保护句柄并返回配置结果。
func (u *cleanupAssetUploader) Delete(_ context.Context, _ AssetBindingTarget, _ ProviderAssetKind, handle string) error {
	u.deletes = append(u.deletes, handle)
	return u.failure
}

// TestAssetBindingCleanerDeletesUpstreamBeforeBinding verifies Router resource deletion cannot orphan a live provider file.
// TestAssetBindingCleanerDeletesUpstreamBeforeBinding 验证 Router 资源删除不会遗留有效供应商文件。
func TestAssetBindingCleanerDeletesUpstreamBeforeBinding(t *testing.T) {
	ctx := context.Background()
	bindings := NewMemoryAssetBindingStore()
	secrets := secret.NewMemoryStore()
	secretReference, errSecret := secrets.Put(ctx, []byte("95157322514496"))
	if errSecret != nil {
		t.Fatalf("secret Put() error = %v", errSecret)
	}
	binding := cleanupBindingFixture(secretReference)
	if errSave := bindings.Save(ctx, binding); errSave != nil {
		t.Fatalf("Save() error = %v", errSave)
	}
	uploader := &cleanupAssetUploader{}
	cleaner, errCleaner := NewAssetBindingCleaner(bindings, secrets, uploader)
	if errCleaner != nil {
		t.Fatalf("NewAssetBindingCleaner() error = %v", errCleaner)
	}
	if errCleanup := cleaner.CleanupResourceBindings(ctx, binding.ResourceID); errCleanup != nil {
		t.Fatalf("CleanupResourceBindings() error = %v", errCleanup)
	}
	remaining, errList := bindings.ListByResource(ctx, binding.ResourceID)
	if errList != nil || len(remaining) != 0 || len(uploader.deletes) != 1 || uploader.deletes[0] != "95157322514496" {
		t.Fatalf("remaining=%#v deletes=%#v error=%v", remaining, uploader.deletes, errList)
	}
	if _, errGet := secrets.Get(ctx, secretReference); errGet == nil {
		t.Fatal("protected provider handle remained after successful cleanup")
	}
}

// TestAssetBindingCleanerRetainsFailedUpstreamWork verifies transient deletion errors remain retryable.
// TestAssetBindingCleanerRetainsFailedUpstreamWork 验证暂时删除错误会保留可重试任务。
func TestAssetBindingCleanerRetainsFailedUpstreamWork(t *testing.T) {
	ctx := context.Background()
	bindings := NewMemoryAssetBindingStore()
	secrets := secret.NewMemoryStore()
	secretReference, errSecret := secrets.Put(ctx, []byte("95157322514496"))
	if errSecret != nil {
		t.Fatalf("secret Put() error = %v", errSecret)
	}
	binding := cleanupBindingFixture(secretReference)
	if errSave := bindings.Save(ctx, binding); errSave != nil {
		t.Fatalf("Save() error = %v", errSave)
	}
	uploader := &cleanupAssetUploader{failure: errors.New("temporary provider failure")}
	cleaner, errCleaner := NewAssetBindingCleaner(bindings, secrets, uploader)
	if errCleaner != nil {
		t.Fatalf("NewAssetBindingCleaner() error = %v", errCleaner)
	}
	if errCleanup := cleaner.CleanupResourceBindings(ctx, binding.ResourceID); errCleanup == nil {
		t.Fatal("CleanupResourceBindings() error = nil, want transient failure")
	}
	remaining, errList := bindings.ListByResource(ctx, binding.ResourceID)
	if errList != nil || len(remaining) != 1 {
		t.Fatalf("failed cleanup did not retain binding: remaining=%#v error=%v", remaining, errList)
	}
	if value, errGet := secrets.Get(ctx, secretReference); errGet != nil || string(value) != "95157322514496" {
		t.Fatalf("failed cleanup did not retain protected handle: value=%q error=%v", value, errGet)
	}
}

// cleanupBindingFixture returns one complete exact-target MiniMax provider-file binding.
// cleanupBindingFixture 返回一个完整精确 Target 的 MiniMax 供应商文件绑定。
func cleanupBindingFixture(secretReference string) ProviderAssetBinding {
	createdAt := time.Date(2026, time.July, 21, 19, 0, 0, 0, time.UTC)
	expiresAt := createdAt.Add(time.Hour)
	return ProviderAssetBinding{
		ID: "pab_0123456789abcdef0123456789abcdef", ResourceID: "res_0123456789abcdef0123456789abcdef", ResourceSHA256: strings.Repeat("a", 64),
		Target:          AssetBindingTarget{ProviderDefinitionID: "system_minimax_api", ProviderInstanceID: "pvi_minimax", EndpointID: "endpoint_minimax", Region: "Global", CredentialID: "credential_minimax", ActionBindingID: "action_minimax_media_analyze", ProviderModelID: "model_minimax", UpstreamModelID: "MiniMax-VL-01"},
		Materialization: catalog.MaterializationProviderFileID, Kind: ProviderAssetFile, ProtectedHandleRef: secretReference, CreatedAt: createdAt, ExpiresAt: &expiresAt, Revision: 1,
	}
}
