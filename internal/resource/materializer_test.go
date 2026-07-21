package resource

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// recordingAssetUploader records exact-target uploads and returns deterministic sensitive handles.
// recordingAssetUploader 记录精确 Target 上传并返回确定性敏感句柄。
type recordingAssetUploader struct {
	// uploads counts exact-target provider uploads.
	// uploads 统计精确 Target 供应商上传次数。
	uploads int
}

// Upload consumes the exact stream and returns one provider file handle.
// Upload 消费精确流并返回一个供应商文件句柄。
func (u *recordingAssetUploader) Upload(_ context.Context, request AssetUploadRequest) (AssetUploadResult, error) {
	content, errRead := io.ReadAll(request.Content)
	if errRead != nil || int64(len(content)) != request.SizeBytes {
		return AssetUploadResult{}, ErrMaterializationFailed
	}
	u.uploads++
	return AssetUploadResult{Handle: fmt.Sprintf("provider-file-%d", u.uploads), Kind: ProviderAssetFile}, nil
}

// Delete accepts compensation for the deterministic fixture.
// Delete 接受确定性夹具的补偿删除。
func (*recordingAssetUploader) Delete(context.Context, AssetBindingTarget, ProviderAssetKind, string) error {
	return nil
}

// TestMaterializerReusesOnlyExactTargetBinding verifies protected handle reuse and credential isolation.
// TestMaterializerReusesOnlyExactTargetBinding 验证受保护句柄复用与凭据隔离。
func TestMaterializerReusesOnlyExactTargetBinding(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 20, 15, 0, 0, 0, time.UTC)
	service, errService := NewService(NewMemoryStore(), ServiceOptions{Root: t.TempDir(), MaxObjectBytes: 1 << 20, MaxReadyBytes: 2 << 20, DefaultTTL: time.Hour, MaxTTL: 24 * time.Hour, Now: func() time.Time { return now }, NewID: func() (string, error) { return "res_0123456789abcdef0123456789abcdef", nil }})
	if errService != nil {
		t.Fatalf("NewService() error = %v", errService)
	}
	created, errCreate := service.Create(context.Background(), CreateInput{OwnerAPIKeyID: "api_owner", Kind: vcp.MediaImage, Source: SourceMultipart, Retention: RetentionEphemeral, Reader: bytesReader(testPNG(t, 1, 1))})
	if errCreate != nil {
		t.Fatalf("Create() error = %v", errCreate)
	}
	uploader := &recordingAssetUploader{}
	bindings := NewMemoryAssetBindingStore()
	materializer, errMaterializer := NewMaterializer(service, bindings, secret.NewMemoryStore(), uploader, MaterializerOptions{Now: func() time.Time { return now }, NewBindingID: func() (string, error) { return fmt.Sprintf("pab_%032x", uploader.uploads), nil }})
	if errMaterializer != nil {
		t.Fatalf("NewMaterializer() error = %v", errMaterializer)
	}
	plan := frozenProviderFilePlan(now, created)
	first, errFirst := materializer.Materialize(context.Background(), "api_owner", plan, nil)
	if errFirst != nil || len(first) != 1 || first[0].ProviderHandle != "provider-file-1" || uploader.uploads != 1 {
		t.Fatalf("first materialization = %#v, uploads=%d, error=%v", first, uploader.uploads, errFirst)
	}
	second, errSecond := materializer.Materialize(context.Background(), "api_owner", plan, nil)
	if errSecond != nil || second[0].ProviderHandle != "provider-file-1" || uploader.uploads != 1 {
		t.Fatalf("reused materialization = %#v, uploads=%d, error=%v", second, uploader.uploads, errSecond)
	}
	plan.Target.CredentialID = "credential_2"
	third, errThird := materializer.Materialize(context.Background(), "api_owner", plan, nil)
	if errThird != nil || third[0].ProviderHandle != "provider-file-2" || uploader.uploads != 2 {
		t.Fatalf("isolated materialization = %#v, uploads=%d, error=%v", third, uploader.uploads, errThird)
	}
}

// TestMaterializerRejectsAssignmentsOutsidePendingPlanInputs verifies assignments form the exact pending-input set and cannot override frozen resources.
// TestMaterializerRejectsAssignmentsOutsidePendingPlanInputs 验证 Assignment 必须精确对应待绑定输入且不能覆盖已冻结资源。
func TestMaterializerRejectsAssignmentsOutsidePendingPlanInputs(t *testing.T) {
	now := time.Date(2026, time.July, 20, 0, 0, 0, 0, time.UTC)
	service, errService := NewService(NewMemoryStore(), ServiceOptions{Root: t.TempDir(), MaxObjectBytes: 1 << 20, MaxReadyBytes: 2 << 20, DefaultTTL: time.Hour, MaxTTL: 24 * time.Hour, Now: func() time.Time { return now }, NewID: func() (string, error) { return "res_0123456789abcdef0123456789abcdef", nil }})
	if errService != nil {
		t.Fatalf("NewService() error = %v", errService)
	}
	created, errCreate := service.Create(context.Background(), CreateInput{OwnerAPIKeyID: "key_test", Kind: vcp.MediaImage, Source: SourceMultipart, Reader: bytesReader(testPNG(t, 1, 1)), Retention: RetentionEphemeral})
	if errCreate != nil {
		t.Fatalf("Create() error = %v", errCreate)
	}
	materializer, errMaterializer := NewMaterializer(service, NewMemoryAssetBindingStore(), secret.NewMemoryStore(), &recordingAssetUploader{}, MaterializerOptions{Now: func() time.Time { return now }})
	if errMaterializer != nil {
		t.Fatalf("NewMaterializer() error = %v", errMaterializer)
	}
	plan := frozenProviderFilePlan(now, created)
	if _, errMaterialize := materializer.Materialize(context.Background(), "key_test", plan, []ResourceAssignment{{InputID: plan.Inputs[0].InputID, ResourceID: created.ID}}); errMaterialize != ErrMaterializationFailed {
		t.Fatalf("Materialize() frozen override error = %v, want ErrMaterializationFailed", errMaterialize)
	}
	if _, errMaterialize := materializer.Materialize(context.Background(), "key_test", plan, []ResourceAssignment{{InputID: "unknown-input", ResourceID: created.ID}}); errMaterialize != ErrMaterializationFailed {
		t.Fatalf("Materialize() unknown assignment error = %v, want ErrMaterializationFailed", errMaterialize)
	}
}

// bytesReader returns one immutable byte reader without introducing test-global state.
// bytesReader 返回一个不可变字节 Reader 且不引入测试全局状态。
func bytesReader(value []byte) io.Reader { return bytes.NewReader(value) }

// frozenProviderFilePlan returns one accepted exact-target plan fixture.
// frozenProviderFilePlan 返回一个已接受精确 Target 方案夹具。
func frozenProviderFilePlan(now time.Time, value Resource) FrozenMaterializationPlan {
	return FrozenMaterializationPlan{OwnerAPIKeyID: "api_owner", Accepted: true, ExpiresAt: now.Add(time.Minute), Target: resolve.Target{ProviderDefinitionID: "provider_1", ProviderInstanceID: "pvi_1", EndpointID: "endpoint_1", EndpointRegion: "region_1", CredentialID: "credential_1", ProviderModelID: "model_1", ActionBindingID: "action_upload", UpstreamModelID: "upstream_1"}, Inputs: []FrozenMaterializationInput{{InputID: "image", ResourceID: value.ID, SHA256: value.SHA256, Kind: value.Kind, MIMEType: value.MIMEType, SizeBytes: value.SizeBytes, Role: vcp.MediaRoleUnderstanding, ImageWidth: value.Metadata.Image.Width, ImageHeight: value.Metadata.Image.Height, ImageHasAlpha: value.Metadata.Image.HasAlpha, Materialization: catalog.MaterializationProviderFileID}}}
}
