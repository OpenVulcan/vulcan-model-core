package resource

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/color"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestServiceCreatesAndReadsVerifiedImage verifies bytes become visible only after hash, magic, metadata, and quota commit.
// TestServiceCreatesAndReadsVerifiedImage 验证字节仅在 Hash、魔数、元数据和配额提交后可见。
func TestServiceCreatesAndReadsVerifiedImage(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, time.July, 20, 13, 0, 0, 0, time.UTC)
	service := newTestService(t, store, &now, "res_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil, 1<<20)
	content := testPNG(t, 3, 2)
	created, errCreate := service.Create(context.Background(), CreateInput{
		OwnerAPIKeyID: "key_owner", Kind: vcp.MediaImage, DeclaredMIME: "image/png", Source: SourceMultipart, Retention: RetentionEphemeral, Reader: bytes.NewReader(content),
	})
	if errCreate != nil {
		t.Fatalf("Create() error = %v", errCreate)
	}
	if created.State != StateReady || created.MIMEType != "image/png" || created.Metadata.Image == nil || created.Metadata.Image.Width != 3 || created.Metadata.Image.Height != 2 || len(created.SHA256) != 64 {
		t.Fatalf("created resource = %#v", created)
	}
	if _, _, errOpen := service.OpenContent(context.Background(), "key_foreign", created.ID); !errors.Is(errOpen, ErrResourceAccessDenied) {
		t.Fatalf("foreign OpenContent() error = %v, want ErrResourceAccessDenied", errOpen)
	}
	metadata, reader, errOpen := service.OpenContent(context.Background(), "key_owner", created.ID)
	if errOpen != nil {
		t.Fatalf("OpenContent() error = %v", errOpen)
	}
	read, errRead := io.ReadAll(reader)
	errClose := reader.Close()
	if errRead != nil || errClose != nil || !bytes.Equal(read, content) || metadata.ID != created.ID {
		t.Fatalf("content read=%d error=%v close=%v metadata=%#v", len(read), errRead, errClose, metadata)
	}
}

// TestServiceRejectsMIMEConflictAndRemovesTemporaryFile verifies failed validation cannot leave a usable or orphan object.
// TestServiceRejectsMIMEConflictAndRemovesTemporaryFile 验证校验失败不能留下可用资源或孤立对象。
func TestServiceRejectsMIMEConflictAndRemovesTemporaryFile(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, time.July, 20, 13, 0, 0, 0, time.UTC)
	root := t.TempDir()
	service := newTestServiceAtRoot(t, store, &now, "res_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", nil, 1<<20, root)
	_, errCreate := service.Create(context.Background(), CreateInput{
		OwnerAPIKeyID: "key_owner", Kind: vcp.MediaImage, DeclaredMIME: "image/jpeg", Source: SourceMultipart, Retention: RetentionEphemeral, Reader: bytes.NewReader(testPNG(t, 1, 1)),
	})
	if !errors.Is(errCreate, ErrMIMEConflict) {
		t.Fatalf("Create() error = %v, want ErrMIMEConflict", errCreate)
	}
	failed, errGet := store.Get(context.Background(), "res_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	if errGet != nil || failed.State != StateFailed || failed.ErrorCode != "mime_mismatch" {
		t.Fatalf("failed resource = %#v, error = %v", failed, errGet)
	}
	entries, errWalk := os.ReadDir(filepath.Join(root, "tmp"))
	if errWalk != nil || len(entries) != 0 {
		t.Fatalf("temporary entries = %v, error = %v", entries, errWalk)
	}
}

// TestServiceDeleteRetriesBindingCleanup verifies a transient upstream cleanup failure leaves a resumable deleting state.
// TestServiceDeleteRetriesBindingCleanup 验证暂时上游清理失败留下可恢复的删除中状态。
func TestServiceDeleteRetriesBindingCleanup(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, time.July, 20, 13, 0, 0, 0, time.UTC)
	cleaner := &testBindingCleaner{failuresRemaining: 1}
	service := newTestService(t, store, &now, "res_cccccccccccccccccccccccccccccccc", cleaner, 1<<20)
	created, errCreate := service.Create(context.Background(), CreateInput{OwnerAPIKeyID: "key_owner", Kind: vcp.MediaImage, Source: SourceMultipart, Retention: RetentionEphemeral, Reader: bytes.NewReader(testPNG(t, 1, 1))})
	if errCreate != nil {
		t.Fatalf("Create() error = %v", errCreate)
	}
	if errDelete := service.Delete(context.Background(), "key_owner", created.ID); errDelete == nil {
		t.Fatal("first Delete() error = nil, want cleanup failure")
	}
	deleting, errGet := store.Get(context.Background(), created.ID)
	if errGet != nil || deleting.State != StateDeleting {
		t.Fatalf("deleting resource = %#v, error = %v", deleting, errGet)
	}
	if errDelete := service.Delete(context.Background(), "key_owner", created.ID); errDelete != nil {
		t.Fatalf("retry Delete() error = %v", errDelete)
	}
	deleted, errGet := store.Get(context.Background(), created.ID)
	if errGet != nil || deleted.State != StateDeleted || cleaner.calls != 2 {
		t.Fatalf("deleted resource = %#v, cleaner calls = %d, error = %v", deleted, cleaner.calls, errGet)
	}
}

// testBindingCleaner records cleanup calls and controlled transient failures.
// testBindingCleaner 记录清理调用及受控暂时失败。
type testBindingCleaner struct {
	// failuresRemaining is decremented for each injected failure.
	// failuresRemaining 在每次注入失败时递减。
	failuresRemaining int
	// calls records all cleanup attempts.
	// calls 记录全部清理尝试。
	calls int
}

// CleanupResourceBindings records one exact resource cleanup.
// CleanupResourceBindings 记录一次精确资源清理。
func (c *testBindingCleaner) CleanupResourceBindings(_ context.Context, _ string) error {
	c.calls++
	if c.failuresRemaining > 0 {
		c.failuresRemaining--
		return errors.New("temporary cleanup failure")
	}
	return nil
}

// newTestService creates a deterministic resource service in one temporary root.
// newTestService 在一个临时根目录中创建确定性资源服务。
func newTestService(t *testing.T, store Store, now *time.Time, identifier string, cleaner BindingCleaner, maxObjectBytes int64) *Service {
	t.Helper()
	return newTestServiceAtRoot(t, store, now, identifier, cleaner, maxObjectBytes, t.TempDir())
}

// newTestServiceAtRoot creates a deterministic resource service in the supplied root.
// newTestServiceAtRoot 在提供的根目录中创建确定性资源服务。
func newTestServiceAtRoot(t *testing.T, store Store, now *time.Time, identifier string, cleaner BindingCleaner, maxObjectBytes int64, root string) *Service {
	t.Helper()
	service, errService := NewService(store, ServiceOptions{
		Root: root, MaxObjectBytes: maxObjectBytes, MaxReadyBytes: 4 << 20, DefaultTTL: time.Hour, MaxTTL: 24 * time.Hour,
		Now: func() time.Time { return *now }, NewID: func() (string, error) { return identifier, nil }, Probe: StandardProbe{}, BindingCleaner: cleaner,
	})
	if errService != nil {
		t.Fatalf("NewService() error = %v", errService)
	}
	return service
}

// testPNG encodes one deterministic opaque PNG fixture.
// testPNG 编码一个确定性不透明 PNG 夹具。
func testPNG(t *testing.T, width int, height int) []byte {
	t.Helper()
	imageValue := image.NewRGBA(image.Rect(0, 0, width, height))
	imageValue.Set(0, 0, color.RGBA{R: 255, A: 255})
	buffer := &bytes.Buffer{}
	if errEncode := png.Encode(buffer, imageValue); errEncode != nil {
		t.Fatalf("encode PNG fixture: %v", errEncode)
	}
	return buffer.Bytes()
}
