package resource

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/dependency"
)

// Store persists resource metadata and owns atomic quota-aware state transitions.
// Store 持久化资源元数据并拥有原子配额感知状态迁移。
type Store interface {
	// CreateReceiving reserves one immutable resource identity.
	// CreateReceiving 保留一个不可变资源身份。
	CreateReceiving(context.Context, Resource) error
	// CommitReady atomically checks total ready bytes and publishes one completed resource.
	// CommitReady 原子检查就绪总字节数并发布一个已完成资源。
	CommitReady(context.Context, Resource, int64) error
	// MarkFailed changes one receiving resource to a safe failed terminal record.
	// MarkFailed 将一个接收中资源变更为安全失败终态记录。
	MarkFailed(context.Context, string, string, time.Time) error
	// BeginDelete changes one ready or expired resource to deleting.
	// BeginDelete 将一个就绪或已过期资源变更为删除中。
	BeginDelete(context.Context, string, uint64, time.Time) (Resource, error)
	// FinishDelete replaces one deleting resource with a tombstone.
	// FinishDelete 将一个删除中资源替换为墓碑记录。
	FinishDelete(context.Context, string, uint64, time.Time) error
	// MarkExpired changes one elapsed ready resource to expired.
	// MarkExpired 将一个已到期就绪资源变更为已过期。
	MarkExpired(context.Context, string, uint64, time.Time) (Resource, error)
	// Get returns one mutation-safe metadata snapshot.
	// Get 返回一个防外部修改的元数据快照。
	Get(context.Context, string) (Resource, error)
	// ListExpired returns ready resources whose expiry is at or before the boundary.
	// ListExpired 返回过期时间不晚于边界的就绪资源。
	ListExpired(context.Context, time.Time, int) ([]Resource, error)
}

// DiagnosticStore lists bounded management-safe resource metadata across call-plane owners.
// DiagnosticStore 跨调用面所有者列出有界且管理安全的资源元数据。
type DiagnosticStore interface {
	// ListDiagnostics returns newest resources without object paths, source URLs, or owner credentials in JSON.
	// ListDiagnostics 返回最新资源，且 JSON 中不包含对象路径、来源 URL 或所有者凭据。
	ListDiagnostics(context.Context, int) ([]Resource, error)
}

// MemoryStore is an atomic in-memory resource metadata repository.
// MemoryStore 是原子内存资源元数据仓库。
type MemoryStore struct {
	// mu protects resource values and quota computation.
	// mu 保护资源值及配额计算。
	mu sync.RWMutex
	// resources owns immutable identifiers and mutable lifecycle snapshots.
	// resources 拥有不可变标识及可变生命周期快照。
	resources map[string]Resource
}

// NewMemoryStore creates an empty resource metadata store.
// NewMemoryStore 创建一个空资源元数据仓库。
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{resources: make(map[string]Resource)}
}

// ListDiagnostics returns the newest bounded mutation-safe resource snapshots.
// ListDiagnostics 返回最新的有界防变异资源快照。
func (s *MemoryStore) ListDiagnostics(ctx context.Context, limit int) ([]Resource, error) {
	if errContext := contextError(ctx); errContext != nil {
		return nil, errContext
	}
	if limit <= 0 || limit > 500 {
		return nil, ErrInvalidResource
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	values := make([]Resource, 0, len(s.resources))
	for _, value := range s.resources {
		values = append(values, cloneResource(value))
	}
	sort.Slice(values, func(first int, second int) bool {
		if values[first].CreatedAt.Equal(values[second].CreatedAt) {
			return values[first].ID > values[second].ID
		}
		return values[first].CreatedAt.After(values[second].CreatedAt)
	})
	if len(values) > limit {
		values = values[:limit]
	}
	return values, nil
}

// CreateReceiving reserves one validated receiving resource.
// CreateReceiving 保留一个已校验接收中资源。
func (s *MemoryStore) CreateReceiving(ctx context.Context, resource Resource) error {
	if errContext := contextError(ctx); errContext != nil {
		return errContext
	}
	if s == nil || resource.State != StateReceiving {
		return ErrInvalidResource
	}
	if errValidate := resource.Validate(); errValidate != nil {
		return errValidate
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.resources[resource.ID]; exists {
		return ErrResourceConflict
	}
	s.resources[resource.ID] = cloneResource(resource)
	return nil
}

// CommitReady atomically verifies reservation identity, revision, and the total byte quota.
// CommitReady 原子校验保留身份、修订号及总字节配额。
func (s *MemoryStore) CommitReady(ctx context.Context, resource Resource, maxReadyBytes int64) error {
	if errContext := contextError(ctx); errContext != nil {
		return errContext
	}
	if s == nil || resource.State != StateReady || maxReadyBytes <= 0 {
		return ErrInvalidResource
	}
	if errValidate := resource.Validate(); errValidate != nil {
		return errValidate
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.resources[resource.ID]
	if !exists {
		return ErrResourceNotFound
	}
	if current.State != StateReceiving || resource.Revision != current.Revision+1 || resource.OwnerAPIKeyID != current.OwnerAPIKeyID || resource.Kind != current.Kind || resource.Source != current.Source || resource.CreatedAt != current.CreatedAt {
		return ErrResourceConflict
	}
	readyBytes := int64(0)
	for _, candidate := range s.resources {
		if candidate.State == StateReady {
			readyBytes += candidate.SizeBytes
		}
	}
	if resource.SizeBytes > maxReadyBytes-readyBytes {
		return ErrResourceQuotaExceeded
	}
	s.resources[resource.ID] = cloneResource(resource)
	return nil
}

// MarkFailed records one safe failure only from receiving state.
// MarkFailed 仅从接收中状态记录一个安全失败。
func (s *MemoryStore) MarkFailed(ctx context.Context, resourceID string, errorCode string, now time.Time) error {
	if errContext := contextError(ctx); errContext != nil {
		return errContext
	}
	if s == nil || errorCode == "" || now.IsZero() {
		return ErrInvalidResource
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.resources[resourceID]
	if !exists {
		return ErrResourceNotFound
	}
	if current.State != StateReceiving {
		return ErrResourceConflict
	}
	current.State = StateFailed
	current.ErrorCode = errorCode
	current.UpdatedAt = now
	current.Revision++
	s.resources[resourceID] = cloneResource(current)
	return nil
}

// BeginDelete moves one ready or expired resource into deleting with optimistic revision control.
// BeginDelete 通过乐观修订控制将一个就绪或已过期资源移入删除中。
func (s *MemoryStore) BeginDelete(ctx context.Context, resourceID string, revision uint64, now time.Time) (Resource, error) {
	if errContext := contextError(ctx); errContext != nil {
		return Resource{}, errContext
	}
	if s == nil || now.IsZero() {
		return Resource{}, ErrInvalidResource
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.resources[resourceID]
	if !exists {
		return Resource{}, ErrResourceNotFound
	}
	if (current.State != StateReady && current.State != StateExpired) || current.Revision != revision {
		return Resource{}, ErrResourceConflict
	}
	current.State = StateDeleting
	current.UpdatedAt = now
	current.Revision++
	s.resources[resourceID] = cloneResource(current)
	return cloneResource(current), nil
}

// FinishDelete replaces a deleting record with a metadata-safe tombstone.
// FinishDelete 将删除中记录替换为元数据安全墓碑。
func (s *MemoryStore) FinishDelete(ctx context.Context, resourceID string, revision uint64, now time.Time) error {
	if errContext := contextError(ctx); errContext != nil {
		return errContext
	}
	if s == nil || now.IsZero() {
		return ErrInvalidResource
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.resources[resourceID]
	if !exists {
		return ErrResourceNotFound
	}
	if current.State != StateDeleting || current.Revision != revision {
		return ErrResourceConflict
	}
	current.State = StateDeleted
	current.MIMEType = ""
	current.SizeBytes = 0
	current.SHA256 = ""
	current.Metadata = Metadata{}
	current.ObjectKey = ""
	current.SourceURL = ""
	current.UpdatedAt = now
	current.Revision++
	s.resources[resourceID] = cloneResource(current)
	return nil
}

// MarkExpired changes one elapsed ready resource to expired.
// MarkExpired 将一个已到期就绪资源变更为已过期。
func (s *MemoryStore) MarkExpired(ctx context.Context, resourceID string, revision uint64, now time.Time) (Resource, error) {
	if errContext := contextError(ctx); errContext != nil {
		return Resource{}, errContext
	}
	if s == nil || now.IsZero() {
		return Resource{}, ErrInvalidResource
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.resources[resourceID]
	if !exists {
		return Resource{}, ErrResourceNotFound
	}
	if current.State != StateReady || current.Revision != revision || current.ExpiresAt == nil || current.ExpiresAt.After(now) {
		return Resource{}, ErrResourceConflict
	}
	current.State = StateExpired
	current.UpdatedAt = now
	current.Revision++
	s.resources[resourceID] = cloneResource(current)
	return cloneResource(current), nil
}

// Get returns one mutation-safe resource snapshot.
// Get 返回一个防外部修改的资源快照。
func (s *MemoryStore) Get(ctx context.Context, resourceID string) (Resource, error) {
	if errContext := contextError(ctx); errContext != nil {
		return Resource{}, errContext
	}
	if s == nil {
		return Resource{}, ErrResourceNotFound
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	resource, exists := s.resources[resourceID]
	if !exists {
		return Resource{}, ErrResourceNotFound
	}
	return cloneResource(resource), nil
}

// ListExpired returns stable ready-resource snapshots at or before one expiry boundary.
// ListExpired 返回不晚于一个过期边界的稳定就绪资源快照。
func (s *MemoryStore) ListExpired(ctx context.Context, boundary time.Time, limit int) ([]Resource, error) {
	if errContext := contextError(ctx); errContext != nil {
		return nil, errContext
	}
	if s == nil || boundary.IsZero() || limit <= 0 {
		return nil, ErrInvalidResource
	}
	s.mu.RLock()
	resources := make([]Resource, 0)
	for _, resource := range s.resources {
		if (resource.State == StateReady || resource.State == StateExpired || resource.State == StateDeleting) && resource.ExpiresAt != nil && !resource.ExpiresAt.After(boundary) {
			resources = append(resources, cloneResource(resource))
		}
	}
	s.mu.RUnlock()
	sort.Slice(resources, func(left int, right int) bool {
		if resources[left].ExpiresAt.Equal(*resources[right].ExpiresAt) {
			return resources[left].ID < resources[right].ID
		}
		return resources[left].ExpiresAt.Before(*resources[right].ExpiresAt)
	})
	if len(resources) > limit {
		resources = resources[:limit]
	}
	return resources, nil
}

// cloneResource returns one mutation-safe resource including optional metadata pointers.
// cloneResource 返回一个包含可选元数据指针的防外部修改资源。
func cloneResource(resource Resource) Resource {
	if resource.ExpiresAt != nil {
		expiresAt := *resource.ExpiresAt
		resource.ExpiresAt = &expiresAt
	}
	if resource.Metadata.Image != nil {
		image := *resource.Metadata.Image
		resource.Metadata.Image = &image
	}
	if resource.Metadata.Audio != nil {
		audio := *resource.Metadata.Audio
		resource.Metadata.Audio = &audio
	}
	if resource.Metadata.Video != nil {
		video := *resource.Metadata.Video
		if video.HasAudio != nil {
			hasAudio := *video.HasAudio
			video.HasAudio = &hasAudio
		}
		resource.Metadata.Video = &video
	}
	return resource
}

// contextError returns cancellation without hiding it behind domain errors.
// contextError 返回取消错误且不以领域错误掩盖。
func contextError(ctx context.Context) error {
	if dependency.IsNil(ctx) {
		return errors.New("context is required")
	}
	return ctx.Err()
}
