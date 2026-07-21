package execution

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// Store persists executions, idempotency ownership, and ordered events atomically.
// Store 原子持久化执行、幂等所有权与有序事件。
type Store interface {
	// LookupIdempotency returns an exact owner-key replay before mutable target resolution.
	// LookupIdempotency 在可变 Target 解析前返回精确所有者键重放。
	LookupIdempotency(context.Context, string, string, string) (Record, bool, error)
	// Create admits one execution or returns an exact idempotent replay.
	// Create 接收一个执行或返回精确幂等重放。
	Create(context.Context, Record, Event) (Record, bool, error)
	// Get returns one owner-scoped execution.
	// Get 返回一个所有者作用域执行。
	Get(context.Context, string, string) (Record, error)
	// Save atomically applies one compare-and-swap record update and appends ordered events.
	// Save 原子应用一个比较并交换记录更新并追加有序事件。
	Save(context.Context, Record, uint64, []Event) error
	// ListEvents returns events strictly after one sequence in stable order.
	// ListEvents 以稳定顺序返回指定序号之后的事件。
	ListEvents(context.Context, string, string, uint64) ([]Event, error)
	// ListRecoverable returns all non-terminal records for restart recovery.
	// ListRecoverable 返回所有用于重启恢复的非终态记录。
	ListRecoverable(context.Context) ([]Record, error)
}

// DiagnosticStore lists bounded management-safe executions across call-plane owners.
// DiagnosticStore 跨调用面所有者列出有界且管理安全的执行记录。
type DiagnosticStore interface {
	// ListDiagnostics returns newest execution snapshots without private requests, targets, tasks, or preparations in JSON.
	// ListDiagnostics 返回最新执行快照，且 JSON 中不包含私有请求、目标、任务或准备状态。
	ListDiagnostics(context.Context, int) ([]Record, error)
}

// MemoryStore is a deterministic concurrency-safe execution repository for tests and embedded use.
// MemoryStore 是用于测试和嵌入使用的确定性并发安全执行 Repository。
type MemoryStore struct {
	// mu protects all records, idempotency bindings, and event sequences.
	// mu 保护全部记录、幂等绑定和事件序列。
	mu sync.RWMutex
	// records stores executions by immutable identifier.
	// records 按不可变标识保存执行。
	records map[string]Record
	// idempotency maps owner and key to exactly one execution identifier.
	// idempotency 将所有者与键映射到唯一执行标识。
	idempotency map[string]string
	// events stores ordered event logs by execution identifier.
	// events 按执行标识保存有序事件日志。
	events map[string][]Event
}

// NewMemoryStore creates an empty execution repository.
// NewMemoryStore 创建一个空执行 Repository。
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{records: make(map[string]Record), idempotency: make(map[string]string), events: make(map[string][]Event)}
}

// LookupIdempotency returns an exact owner-key replay before mutable target resolution.
// LookupIdempotency 在可变 Target 解析前返回精确所有者键重放。
func (s *MemoryStore) LookupIdempotency(ctx context.Context, ownerAPIKeyID string, idempotencyKey string, requestHash string) (Record, bool, error) {
	if errContext := contextError(ctx); errContext != nil {
		return Record{}, false, errContext
	}
	if idempotencyKey == "" {
		return Record{}, false, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	executionID, exists := s.idempotency[idempotencyStoreKey(ownerAPIKeyID, idempotencyKey)]
	if !exists {
		return Record{}, false, nil
	}
	record := s.records[executionID]
	if record.RequestHash != requestHash {
		return Record{}, false, ErrIdempotencyConflict
	}
	return cloneRecord(record), true, nil
}

// Create admits one execution or returns an exact idempotent replay.
// Create 接收一个执行或返回精确幂等重放。
func (s *MemoryStore) Create(ctx context.Context, record Record, accepted Event) (Record, bool, error) {
	if errContext := contextError(ctx); errContext != nil {
		return Record{}, false, errContext
	}
	if errRecord := record.Validate(); errRecord != nil {
		return Record{}, false, errRecord
	}
	if errEvent := accepted.Validate(); errEvent != nil || accepted.ExecutionID != record.ID || accepted.Sequence != 1 {
		return Record{}, false, fmt.Errorf("%w: accepted event does not start the execution log", ErrInvalidExecution)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if record.IdempotencyKey != "" {
		key := idempotencyStoreKey(record.OwnerAPIKeyID, record.IdempotencyKey)
		if existingID, exists := s.idempotency[key]; exists {
			existing := s.records[existingID]
			if existing.RequestHash != record.RequestHash {
				return Record{}, false, ErrIdempotencyConflict
			}
			return cloneRecord(existing), true, nil
		}
		s.idempotency[key] = record.ID
	}
	if _, exists := s.records[record.ID]; exists {
		return Record{}, false, fmt.Errorf("%w: duplicate execution identifier", ErrInvalidExecution)
	}
	s.records[record.ID] = cloneRecord(record)
	s.events[record.ID] = []Event{accepted}
	return cloneRecord(record), false, nil
}

// Get returns one owner-scoped execution.
// Get 返回一个所有者作用域执行。
func (s *MemoryStore) Get(ctx context.Context, ownerAPIKeyID string, executionID string) (Record, error) {
	if errContext := contextError(ctx); errContext != nil {
		return Record{}, errContext
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, exists := s.records[executionID]
	if !exists || record.OwnerAPIKeyID != ownerAPIKeyID {
		return Record{}, ErrExecutionNotFound
	}
	return cloneRecord(record), nil
}

// Save atomically applies one compare-and-swap record update and appends ordered events.
// Save 原子应用一个比较并交换记录更新并追加有序事件。
func (s *MemoryStore) Save(ctx context.Context, record Record, expectedRevision uint64, appended []Event) error {
	if errContext := contextError(ctx); errContext != nil {
		return errContext
	}
	if errRecord := record.Validate(); errRecord != nil {
		return errRecord
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.records[record.ID]
	if !exists || current.OwnerAPIKeyID != record.OwnerAPIKeyID {
		return ErrExecutionNotFound
	}
	if current.Revision != expectedRevision || record.Revision != expectedRevision+1 {
		return ErrRevisionConflict
	}
	if current.Status != record.Status {
		if errTransition := ValidateTransition(current.Status, record.Status); errTransition != nil {
			return errTransition
		}
	}
	currentEvents := s.events[record.ID]
	nextSequence := uint64(len(currentEvents) + 1)
	for index, event := range appended {
		if errEvent := event.Validate(); errEvent != nil {
			return fmt.Errorf("%w: appended event at index %d is invalid: %v", ErrInvalidExecution, index, errEvent)
		}
		if event.ExecutionID != record.ID || event.Sequence != nextSequence+uint64(index) {
			return fmt.Errorf("%w: appended event at index %d has a non-contiguous identity or sequence: got %d, want %d", ErrInvalidExecution, index, event.Sequence, nextSequence+uint64(index))
		}
	}
	s.records[record.ID] = cloneRecord(record)
	s.events[record.ID] = append(currentEvents, appended...)
	return nil
}

// ListEvents returns events strictly after one sequence in stable order.
// ListEvents 以稳定顺序返回指定序号之后的事件。
func (s *MemoryStore) ListEvents(ctx context.Context, ownerAPIKeyID string, executionID string, afterSequence uint64) ([]Event, error) {
	if _, errRecord := s.Get(ctx, ownerAPIKeyID, executionID); errRecord != nil {
		return nil, errRecord
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	values := s.events[executionID]
	if afterSequence >= uint64(len(values)) {
		return []Event{}, nil
	}
	return append([]Event(nil), values[afterSequence:]...), nil
}

// ListRecoverable returns all non-terminal records in stable creation order.
// ListRecoverable 以稳定创建顺序返回所有非终态记录。
func (s *MemoryStore) ListRecoverable(ctx context.Context) ([]Record, error) {
	if errContext := contextError(ctx); errContext != nil {
		return nil, errContext
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	records := make([]Record, 0)
	for _, record := range s.records {
		if !record.Status.IsTerminal() {
			records = append(records, cloneRecord(record))
		}
	}
	sort.Slice(records, func(first int, second int) bool {
		if records[first].CreatedAt.Equal(records[second].CreatedAt) {
			return records[first].ID < records[second].ID
		}
		return records[first].CreatedAt.Before(records[second].CreatedAt)
	})
	return records, nil
}

// ListDiagnostics returns the newest bounded mutation-safe execution snapshots.
// ListDiagnostics 返回最新的有界防变异执行快照。
func (s *MemoryStore) ListDiagnostics(ctx context.Context, limit int) ([]Record, error) {
	if errContext := contextError(ctx); errContext != nil {
		return nil, errContext
	}
	if limit <= 0 || limit > 500 {
		return nil, ErrInvalidExecution
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	records := make([]Record, 0, len(s.records))
	for _, record := range s.records {
		records = append(records, cloneRecord(record))
	}
	sort.Slice(records, func(first int, second int) bool {
		if records[first].CreatedAt.Equal(records[second].CreatedAt) {
			return records[first].ID > records[second].ID
		}
		return records[first].CreatedAt.After(records[second].CreatedAt)
	})
	if len(records) > limit {
		records = records[:limit]
	}
	return records, nil
}

// contextError returns an explicit error for nil or cancelled contexts.
// contextError 为 nil 或已取消 Context 返回明确错误。
func contextError(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: context is required", ErrInvalidExecution)
	}
	return ctx.Err()
}

// idempotencyStoreKey builds one collision-free in-memory composite key.
// idempotencyStoreKey 构建一个无冲突的内存复合键。
func idempotencyStoreKey(ownerAPIKeyID string, idempotencyKey string) string {
	return ownerAPIKeyID + "\x00" + idempotencyKey
}

// cloneRecord copies mutable slices and pointers that may cross repository boundaries.
// cloneRecord 复制可能跨越 Repository 边界的可变切片与指针。
func cloneRecord(record Record) Record {
	record.Attempts = append([]Attempt(nil), record.Attempts...)
	if record.Result != nil {
		result := *record.Result
		result.Embeddings = append([]vcp.EmbeddingItem(nil), record.Result.Embeddings...)
		result.Rerank = append([]vcp.RerankResult(nil), record.Result.Rerank...)
		result.Resources = append([]resource.Resource(nil), record.Result.Resources...)
		if record.Result.MusicCoverPreparation != nil {
			preparation := *record.Result.MusicCoverPreparation
			preparation.Structure = append([]vcp.MusicStructureSegment(nil), record.Result.MusicCoverPreparation.Structure...)
			result.MusicCoverPreparation = &preparation
		}
		record.Result = &result
	}
	if record.Failure != nil {
		failure := *record.Failure
		record.Failure = &failure
	}
	if record.ProviderTask != nil {
		providerTask := *record.ProviderTask
		record.ProviderTask = &providerTask
	}
	if record.ProviderPreparation != nil {
		providerPreparation := *record.ProviderPreparation
		record.ProviderPreparation = &providerPreparation
	}
	return record
}
