package resource

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/dependency"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// BindingCleaner removes provider-owned resource handles before local deletion completes.
// BindingCleaner 在本地删除完成前移除供应商拥有的资源句柄。
type BindingCleaner interface {
	// CleanupResourceBindings removes every exact binding owned by one Router resource.
	// CleanupResourceBindings 移除一个 Router 资源拥有的每个精确绑定。
	CleanupResourceBindings(context.Context, string) error
}

// ServiceOptions configures bounded object storage and deterministic time and identity dependencies.
// ServiceOptions 配置受限对象存储及确定性时间与身份依赖。
type ServiceOptions struct {
	// Root is the absolute resource directory containing objects and temporary files.
	// Root 是包含对象与临时文件的绝对资源目录。
	Root string
	// MaxObjectBytes is the hard per-object decoded byte limit.
	// MaxObjectBytes 是每个对象的硬解码字节上限。
	MaxObjectBytes int64
	// MaxReadyBytes is the hard total ready-object byte limit.
	// MaxReadyBytes 是全部就绪对象的硬总字节上限。
	MaxReadyBytes int64
	// DefaultTTL is applied to ephemeral resources.
	// DefaultTTL 应用于临时资源。
	DefaultTTL time.Duration
	// MaxTTL limits explicit expiry.
	// MaxTTL 限制明确过期时间。
	MaxTTL time.Duration
	// Now returns deterministic current time.
	// Now 返回确定性的当前时间。
	Now func() time.Time
	// NewID returns one unpredictable Router resource identifier.
	// NewID 返回一个不可预测 Router 资源标识。
	NewID func() (string, error)
	// Probe inspects magic and metadata after bytes are complete.
	// Probe 在字节完成后检查魔数与元数据。
	Probe Probe
	// BindingCleaner removes upstream handles during deletion.
	// BindingCleaner 在删除期间移除上游句柄。
	BindingCleaner BindingCleaner
}

// Service owns resource ingestion, authorization, content access, and cleanup.
// Service 拥有资源接收、授权、内容访问和清理。
type Service struct {
	// store owns durable metadata and atomic quotas.
	// store 拥有持久元数据与原子配额。
	store Store
	// options contains validated immutable service dependencies.
	// options 包含已校验不可变服务依赖。
	options ServiceOptions
	// objectsRoot is the resolved object directory.
	// objectsRoot 是已解析对象目录。
	objectsRoot string
	// temporaryRoot is the resolved temporary directory.
	// temporaryRoot 是已解析临时目录。
	temporaryRoot string
}

// ListDiagnostics returns bounded management-safe resource metadata when the durable store supports diagnostics.
// ListDiagnostics 在持久化存储支持诊断时返回有界且管理安全的资源元数据。
func (s *Service) ListDiagnostics(ctx context.Context, limit int) ([]Resource, error) {
	store, supported := s.store.(DiagnosticStore)
	if !supported {
		return nil, fmt.Errorf("%w: resource diagnostics are unavailable", ErrInvalidResource)
	}
	return store.ListDiagnostics(ctx, limit)
}

// CreateInput describes one already-authorized binary ingestion stream.
// CreateInput 描述一个已授权二进制接收流。
type CreateInput struct {
	// OwnerAPIKeyID is the non-secret authenticated call-key identifier.
	// OwnerAPIKeyID 是非秘密已认证调用密钥标识。
	OwnerAPIKeyID string
	// Kind is the caller-declared closed resource family checked against magic.
	// Kind 是调用方声明且将与魔数核对的封闭资源类别。
	Kind vcp.MediaKind
	// DeclaredMIME is optional but must match magic when present.
	// DeclaredMIME 可选但在提供时必须匹配魔数。
	DeclaredMIME string
	// Source identifies the authorized ingestion workflow.
	// Source 标识已授权接收工作流。
	Source Source
	// SourceURL is the final validated public URL for URL imports.
	// SourceURL 是 URL 导入的最终已校验公网 URL。
	SourceURL string
	// GeneratedBy records safe execution provenance when Source is generated.
	// GeneratedBy 在 Source 为生成资源时记录安全执行来源。
	GeneratedBy *GenerationProvenance
	// Retention selects ephemeral, explicit expiry, or persistent storage.
	// Retention 选择临时、明确过期或持久存储。
	Retention RetentionPolicy
	// ExpiresAt is required only for explicit expiry.
	// ExpiresAt 仅在明确过期时必填。
	ExpiresAt *time.Time
	// Reader streams decoded bytes and remains caller-owned.
	// Reader 流式提供解码字节且仍由调用方拥有。
	Reader io.Reader
}

// NewService validates directories and creates a bounded resource service.
// NewService 校验目录并创建受限资源服务。
func NewService(store Store, options ServiceOptions) (*Service, error) {
	if dependency.IsNil(store) || strings.TrimSpace(options.Root) == "" || options.MaxObjectBytes <= 0 || options.MaxReadyBytes <= 0 || options.DefaultTTL <= 0 || options.MaxTTL < options.DefaultTTL {
		return nil, fmt.Errorf("%w: store, root, positive quotas, and valid TTLs are required", ErrInvalidResource)
	}
	root, errAbsolute := filepath.Abs(options.Root)
	if errAbsolute != nil {
		return nil, fmt.Errorf("resolve resource root: %w", errAbsolute)
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.NewID == nil {
		options.NewID = randomResourceID
	}
	if dependency.IsNil(options.Probe) {
		options.Probe = StandardProbe{}
	}
	objectsRoot := filepath.Join(root, "objects")
	temporaryRoot := filepath.Join(root, "tmp")
	if errCreate := os.MkdirAll(objectsRoot, 0o700); errCreate != nil {
		return nil, fmt.Errorf("create resource object directory: %w", errCreate)
	}
	if errCreate := os.MkdirAll(temporaryRoot, 0o700); errCreate != nil {
		return nil, fmt.Errorf("create resource temporary directory: %w", errCreate)
	}
	options.Root = root
	return &Service{store: store, options: options, objectsRoot: objectsRoot, temporaryRoot: temporaryRoot}, nil
}

// Create streams, hashes, probes, atomically moves, and quota-commits one resource.
// Create 流式写入、计算 Hash、探测、原子移动并按配额提交一个资源。
func (s *Service) Create(ctx context.Context, input CreateInput) (Resource, error) {
	if s == nil || dependency.IsNil(input.Reader) || strings.TrimSpace(input.OwnerAPIKeyID) == "" || !validKind(input.Kind) || !validSource(input.Source) || !validRetention(input.Retention) {
		return Resource{}, ErrInvalidResource
	}
	if input.Source == SourceURLImport && strings.TrimSpace(input.SourceURL) == "" {
		return Resource{}, fmt.Errorf("%w: URL import requires final source URL", ErrInvalidResource)
	}
	now := s.options.Now().UTC()
	expiresAt, errExpiry := s.resolveExpiry(now, input.Retention, input.ExpiresAt)
	if errExpiry != nil {
		return Resource{}, errExpiry
	}
	resourceID, errID := s.options.NewID()
	if errID != nil || !validResourceID(resourceID) {
		return Resource{}, fmt.Errorf("create resource identifier: %w", errID)
	}
	receiving := Resource{ID: resourceID, OwnerAPIKeyID: input.OwnerAPIKeyID, Kind: input.Kind, Source: input.Source, SourceURL: input.SourceURL, GeneratedBy: input.GeneratedBy, State: StateReceiving, Retention: input.Retention, CreatedAt: now, UpdatedAt: now, ExpiresAt: expiresAt, Revision: 1}
	if errCreate := s.store.CreateReceiving(ctx, receiving); errCreate != nil {
		return Resource{}, errCreate
	}
	temporary, errTemporary := os.CreateTemp(s.temporaryRoot, ".resource-")
	if errTemporary != nil {
		s.fail(ctx, resourceID, "temporary_create_failed")
		return Resource{}, fmt.Errorf("create resource temporary file: %w", errTemporary)
	}
	temporaryPath := temporary.Name()
	temporaryClosed := false
	defer func() {
		if !temporaryClosed {
			_ = temporary.Close()
		}
		_ = os.Remove(temporaryPath)
	}()
	hash := sha256.New()
	written, errCopy := io.Copy(io.MultiWriter(temporary, hash), io.LimitReader(input.Reader, s.options.MaxObjectBytes+1))
	if errCopy != nil {
		s.fail(ctx, resourceID, "read_failed")
		return Resource{}, fmt.Errorf("stream resource bytes: %w", errCopy)
	}
	if written == 0 {
		s.fail(ctx, resourceID, "empty_resource")
		return Resource{}, fmt.Errorf("%w: resource is empty", ErrInvalidResource)
	}
	if written > s.options.MaxObjectBytes {
		s.fail(ctx, resourceID, "object_too_large")
		return Resource{}, ErrResourceQuotaExceeded
	}
	if errSync := temporary.Sync(); errSync != nil {
		s.fail(ctx, resourceID, "temporary_sync_failed")
		return Resource{}, fmt.Errorf("sync resource temporary file: %w", errSync)
	}
	if errClose := temporary.Close(); errClose != nil {
		temporaryClosed = true
		s.fail(ctx, resourceID, "temporary_close_failed")
		return Resource{}, fmt.Errorf("close resource temporary file: %w", errClose)
	}
	temporaryClosed = true
	mimeType, metadata, errProbe := s.options.Probe.Inspect(temporaryPath, input.Kind, input.DeclaredMIME)
	if errProbe != nil {
		errorCode := "metadata_invalid"
		if errors.Is(errProbe, ErrMIMEConflict) {
			errorCode = "mime_mismatch"
		}
		s.fail(ctx, resourceID, errorCode)
		return Resource{}, errProbe
	}
	objectDirectory := filepath.Join(s.objectsRoot, resourceID[4:6])
	if errCreate := os.MkdirAll(objectDirectory, 0o700); errCreate != nil {
		s.fail(ctx, resourceID, "object_directory_failed")
		return Resource{}, fmt.Errorf("create resource object shard: %w", errCreate)
	}
	objectPath := filepath.Join(objectDirectory, resourceID+".bin")
	if _, errStat := os.Stat(objectPath); errStat == nil || !errors.Is(errStat, os.ErrNotExist) {
		s.fail(ctx, resourceID, "object_conflict")
		return Resource{}, ErrResourceConflict
	}
	if errRename := os.Rename(temporaryPath, objectPath); errRename != nil {
		s.fail(ctx, resourceID, "object_move_failed")
		return Resource{}, fmt.Errorf("publish resource object: %w", errRename)
	}
	ready := receiving
	ready.MIMEType = mimeType
	ready.SizeBytes = written
	ready.SHA256 = hex.EncodeToString(hash.Sum(nil))
	ready.Metadata = metadata
	ready.State = StateReady
	ready.ObjectKey = filepath.ToSlash(filepath.Join("objects", resourceID[4:6], resourceID+".bin"))
	ready.UpdatedAt = s.options.Now().UTC()
	ready.Revision++
	if errCommit := s.store.CommitReady(ctx, ready, s.options.MaxReadyBytes); errCommit != nil {
		_ = os.Remove(objectPath)
		s.fail(ctx, resourceID, failureCode(errCommit))
		return Resource{}, errCommit
	}
	return ready, nil
}

// Get returns safe metadata only when the authenticated call key owns the resource.
// Get 仅在已认证调用密钥拥有资源时返回安全元数据。
func (s *Service) Get(ctx context.Context, ownerAPIKeyID string, resourceID string) (Resource, error) {
	resource, errGet := s.store.Get(ctx, resourceID)
	if errGet != nil {
		return Resource{}, errGet
	}
	if ownerAPIKeyID == "" || resource.OwnerAPIKeyID != ownerAPIKeyID {
		return Resource{}, ErrResourceAccessDenied
	}
	return resource, nil
}

// OpenContent opens one ready, unexpired, owner-authorized local object.
// OpenContent 打开一个就绪、未过期且所有者已授权的本地对象。
func (s *Service) OpenContent(ctx context.Context, ownerAPIKeyID string, resourceID string) (Resource, io.ReadCloser, error) {
	resource, errGet := s.Get(ctx, ownerAPIKeyID, resourceID)
	if errGet != nil {
		return Resource{}, nil, errGet
	}
	if resource.State != StateReady || (resource.ExpiresAt != nil && !resource.ExpiresAt.After(s.options.Now().UTC())) {
		return Resource{}, nil, ErrResourceNotFound
	}
	path, errPath := s.objectPath(resource.ObjectKey)
	if errPath != nil {
		return Resource{}, nil, errPath
	}
	content, errOpen := os.Open(path)
	if errOpen != nil {
		return Resource{}, nil, fmt.Errorf("open resource content: %w", errOpen)
	}
	return resource, content, nil
}

// Delete removes provider bindings, local bytes, and leaves a metadata-safe tombstone.
// Delete 移除供应商绑定、本地字节并留下元数据安全墓碑。
func (s *Service) Delete(ctx context.Context, ownerAPIKeyID string, resourceID string) error {
	resource, errGet := s.Get(ctx, ownerAPIKeyID, resourceID)
	if errGet != nil {
		return errGet
	}
	deleting := resource
	if resource.State != StateDeleting {
		var errBegin error
		deleting, errBegin = s.store.BeginDelete(ctx, resource.ID, resource.Revision, s.options.Now().UTC())
		if errBegin != nil {
			return errBegin
		}
	}
	if !dependency.IsNil(s.options.BindingCleaner) {
		if errCleanup := s.options.BindingCleaner.CleanupResourceBindings(ctx, resource.ID); errCleanup != nil {
			return fmt.Errorf("cleanup provider resource bindings: %w", errCleanup)
		}
	}
	path, errPath := s.objectPath(deleting.ObjectKey)
	if errPath != nil {
		return errPath
	}
	if errRemove := os.Remove(path); errRemove != nil && !errors.Is(errRemove, os.ErrNotExist) {
		return fmt.Errorf("remove resource object: %w", errRemove)
	}
	return s.store.FinishDelete(ctx, deleting.ID, deleting.Revision, s.options.Now().UTC())
}

// CleanupExpired marks and deletes a bounded stable batch of expired resources.
// CleanupExpired 标记并删除一批受限稳定过期资源。
func (s *Service) CleanupExpired(ctx context.Context, limit int) (int, error) {
	now := s.options.Now().UTC()
	resources, errList := s.store.ListExpired(ctx, now, limit)
	if errList != nil {
		return 0, errList
	}
	cleaned := 0
	for _, resource := range resources {
		expired := resource
		if resource.State == StateReady {
			var errExpire error
			expired, errExpire = s.store.MarkExpired(ctx, resource.ID, resource.Revision, now)
			if errExpire != nil {
				return cleaned, errExpire
			}
		}
		deleting := expired
		if expired.State != StateDeleting {
			var errDelete error
			deleting, errDelete = s.store.BeginDelete(ctx, expired.ID, expired.Revision, now)
			if errDelete != nil {
				return cleaned, errDelete
			}
		}
		if !dependency.IsNil(s.options.BindingCleaner) {
			if errBindings := s.options.BindingCleaner.CleanupResourceBindings(ctx, resource.ID); errBindings != nil {
				return cleaned, errBindings
			}
		}
		path, errPath := s.objectPath(deleting.ObjectKey)
		if errPath != nil {
			return cleaned, errPath
		}
		if errRemove := os.Remove(path); errRemove != nil && !errors.Is(errRemove, os.ErrNotExist) {
			return cleaned, errRemove
		}
		if errFinish := s.store.FinishDelete(ctx, deleting.ID, deleting.Revision, now); errFinish != nil {
			return cleaned, errFinish
		}
		cleaned++
	}
	return cleaned, nil
}

// resolveExpiry validates retention-specific expiry without silently shortening caller intent.
// resolveExpiry 校验保留策略特定过期时间且不静默缩短调用方意图。
func (s *Service) resolveExpiry(now time.Time, retention RetentionPolicy, requested *time.Time) (*time.Time, error) {
	if retention == RetentionPersistent {
		if requested != nil {
			return nil, fmt.Errorf("%w: persistent retention cannot include expiry", ErrInvalidResource)
		}
		return nil, nil
	}
	if retention == RetentionEphemeral {
		if requested != nil {
			return nil, fmt.Errorf("%w: ephemeral retention uses the Router default TTL", ErrInvalidResource)
		}
		expiresAt := now.Add(s.options.DefaultTTL)
		return &expiresAt, nil
	}
	if requested == nil || !requested.After(now) || requested.After(now.Add(s.options.MaxTTL)) {
		return nil, fmt.Errorf("%w: explicit expiry must be in the future and within maximum TTL", ErrInvalidResource)
	}
	expiresAt := requested.UTC()
	return &expiresAt, nil
}

// objectPath resolves one internal object key and rejects path escape.
// objectPath 解析一个内部对象键并拒绝路径逸出。
func (s *Service) objectPath(objectKey string) (string, error) {
	cleanKey := filepath.Clean(filepath.FromSlash(objectKey))
	path := filepath.Join(s.options.Root, cleanKey)
	relative, errRelative := filepath.Rel(s.options.Root, path)
	if errRelative != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return "", fmt.Errorf("%w: object key escapes resource root", ErrInvalidResource)
	}
	return path, nil
}

// fail records a safe terminal code while preserving the original operation error.
// fail 记录安全终态代码且保留原始操作错误。
func (s *Service) fail(ctx context.Context, resourceID string, errorCode string) {
	_ = s.store.MarkFailed(context.WithoutCancel(ctx), resourceID, errorCode, s.options.Now().UTC())
}

// failureCode maps internal quota conflicts to stable non-secret resource codes.
// failureCode 将内部配额冲突映射到稳定非秘密资源代码。
func failureCode(err error) string {
	if errors.Is(err, ErrResourceQuotaExceeded) {
		return "total_quota_exceeded"
	}
	return "metadata_commit_failed"
}

// randomResourceID returns 128 bits of cryptographic entropy as a portable identifier.
// randomResourceID 返回 128 位加密随机熵作为可移植标识。
func randomResourceID() (string, error) {
	buffer := make([]byte, 16)
	if _, errRead := rand.Read(buffer); errRead != nil {
		return "", errRead
	}
	return "res_" + hex.EncodeToString(buffer), nil
}
