package execution

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

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

// LeaseStore coordinates one active recovery owner per execution across service instances.
// LeaseStore 跨服务实例协调每个执行唯一的活动恢复所有者。
type LeaseStore interface {
	// AcquireLease creates or takes an expired lease for one exact worker.
	// AcquireLease 为一个精确 Worker 创建或接管已过期租约。
	AcquireLease(context.Context, string, string, time.Time, time.Time) (bool, error)
	// RenewLease extends only the current worker's unexpired lease.
	// RenewLease 仅延长当前 Worker 的未过期租约。
	RenewLease(context.Context, string, string, time.Time, time.Time) (bool, error)
	// ReleaseLease removes only the current worker's lease.
	// ReleaseLease 仅移除当前 Worker 的租约。
	ReleaseLease(context.Context, string, string) error
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
	cloned, errClone := cloneRecord(record)
	return cloned, true, errClone
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
	if errEvent := accepted.Validate(); errEvent != nil || accepted.ExecutionID != record.ID || accepted.Sequence != 1 || accepted.Type != EventExecutionAccepted || accepted.Lifecycle == nil || accepted.Lifecycle.Status != StatusAccepted {
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
			cloned, errClone := cloneRecord(existing)
			return cloned, true, errClone
		}
		s.idempotency[key] = record.ID
	}
	if _, exists := s.records[record.ID]; exists {
		return Record{}, false, fmt.Errorf("%w: duplicate execution identifier", ErrInvalidExecution)
	}
	stored, errClone := cloneRecord(record)
	if errClone != nil {
		return Record{}, false, errClone
	}
	s.records[record.ID] = stored
	s.events[record.ID] = []Event{accepted}
	returned, errReturnClone := cloneRecord(record)
	return returned, false, errReturnClone
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
	return cloneRecord(record)
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
	stored, errClone := cloneRecord(record)
	if errClone != nil {
		return errClone
	}
	s.records[record.ID] = stored
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
			cloned, errClone := cloneRecord(record)
			if errClone != nil {
				return nil, errClone
			}
			records = append(records, cloned)
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
		cloned, errClone := cloneRecord(record)
		if errClone != nil {
			return nil, errClone
		}
		records = append(records, cloned)
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
func cloneRecord(record Record) (Record, error) {
	request, errRequest := vcp.CloneExecutionRequest(record.Request)
	if errRequest != nil {
		return Record{}, fmt.Errorf("%w: clone private execution request: %v", ErrInvalidExecution, errRequest)
	}
	record.Request = request
	record.Attempts = append([]Attempt(nil), record.Attempts...)
	for index := range record.Attempts {
		record.Attempts[index].Usage = cloneUsageObservation(record.Attempts[index].Usage)
	}
	if record.Result != nil {
		result := *record.Result
		if record.Result.Conversation != nil {
			conversation := vcp.CloneResponse(*record.Result.Conversation)
			result.Conversation = &conversation
		}
		if record.Result.Analysis != nil {
			analysis := vcp.CloneResponse(*record.Result.Analysis)
			result.Analysis = &analysis
		}
		result.Embeddings = cloneEmbeddingItems(record.Result.Embeddings)
		result.Rerank = cloneRerankResults(record.Result.Rerank)
		result.Search = cloneWebSearchResponse(record.Result.Search)
		result.Transcript = cloneTranscript(record.Result.Transcript)
		result.Resources = cloneResources(record.Result.Resources)
		result.Usage = cloneUsageObservation(record.Result.Usage)
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
	if record.Retry != nil {
		retry := *record.Retry
		if retry.MaxAttempts != nil {
			maximum := *retry.MaxAttempts
			retry.MaxAttempts = &maximum
		}
		record.Retry = &retry
	}
	if record.ProviderTask != nil {
		providerTask := *record.ProviderTask
		record.ProviderTask = &providerTask
	}
	if record.ProviderPreparation != nil {
		providerPreparation := *record.ProviderPreparation
		record.ProviderPreparation = &providerPreparation
	}
	if record.ProviderContinuation != nil {
		providerContinuation := *record.ProviderContinuation
		record.ProviderContinuation = &providerContinuation
	}
	if record.Result != nil && record.Result.Continuation != nil {
		continuation := *record.Result.Continuation
		record.Result.Continuation = &continuation
	}
	return record, nil
}

// cloneEmbeddingItems deep-copies every mutable embedding representation.
// cloneEmbeddingItems 深拷贝每个可变的向量表示。
func cloneEmbeddingItems(source []vcp.EmbeddingItem) []vcp.EmbeddingItem {
	cloned := append([]vcp.EmbeddingItem(nil), source...)
	for index := range cloned {
		if source[index].Dense != nil {
			dense := *source[index].Dense
			dense.Values = append([]float64(nil), source[index].Dense.Values...)
			if source[index].Dense.Normalized != nil {
				normalized := *source[index].Dense.Normalized
				dense.Normalized = &normalized
			}
			cloned[index].Dense = &dense
		}
		cloned[index].Sparse = append([]vcp.SparseEmbeddingEntry(nil), source[index].Sparse...)
		cloned[index].MultiVector = append([]vcp.MultiEmbeddingVector(nil), source[index].MultiVector...)
		for vectorIndex := range cloned[index].MultiVector {
			cloned[index].MultiVector[vectorIndex].Values = append([]float64(nil), source[index].MultiVector[vectorIndex].Values...)
		}
	}
	return cloned
}

// cloneRerankResults deep-copies optional returned candidate content.
// cloneRerankResults 深拷贝可选的返回候选内容。
func cloneRerankResults(source []vcp.RerankResult) []vcp.RerankResult {
	cloned := append([]vcp.RerankResult(nil), source...)
	for index := range cloned {
		if source[index].Content == nil {
			continue
		}
		content := *source[index].Content
		if content.Text != nil {
			text := *content.Text
			content.Text = &text
		}
		if content.Resource != nil {
			resourceReference := *content.Resource
			content.Resource = &resourceReference
		}
		cloned[index].Content = &content
	}
	return cloned
}

// cloneWebSearchResponse deep-copies one optional search result and all optional measurements.
// cloneWebSearchResponse 深拷贝一个可选搜索结果及其全部可选测量值。
func cloneWebSearchResponse(source *vcp.WebSearchResponse) *vcp.WebSearchResponse {
	if source == nil {
		return nil
	}
	cloned := *source
	cloned.Queries = append([]string(nil), source.Queries...)
	cloned.Evidence.Kinds = append([]vcp.SearchEvidenceKind(nil), source.Evidence.Kinds...)
	cloned.Results = append([]vcp.WebSearchResult(nil), source.Results...)
	for index := range cloned.Results {
		if source.Results[index].PublishedAt != nil {
			publishedAt := *source.Results[index].PublishedAt
			cloned.Results[index].PublishedAt = &publishedAt
		}
		if source.Results[index].UpdatedAt != nil {
			updatedAt := *source.Results[index].UpdatedAt
			cloned.Results[index].UpdatedAt = &updatedAt
		}
		if source.Results[index].ProviderScore != nil {
			providerScore := *source.Results[index].ProviderScore
			cloned.Results[index].ProviderScore = &providerScore
		}
	}
	cloned.Citations = append([]vcp.Citation(nil), source.Citations...)
	for index := range cloned.Citations {
		cloned.Citations[index].Location.Start = cloneIntPointer(source.Citations[index].Location.Start)
		cloned.Citations[index].Location.End = cloneIntPointer(source.Citations[index].Location.End)
	}
	cloned.Sources = append([]vcp.SearchSource(nil), source.Sources...)
	cloned.Usage = cloneUsageObservation(source.Usage)
	return &cloned
}

// cloneTranscript deep-copies one optional non-realtime transcript tree.
// cloneTranscript 深拷贝一个可选的非实时转写树。
func cloneTranscript(source *vcp.Transcript) *vcp.Transcript {
	if source == nil {
		return nil
	}
	cloned := *source
	cloned.DurationMilliseconds = cloneInt64Pointer(source.DurationMilliseconds)
	cloned.Candidates = append([]vcp.TranscriptCandidate(nil), source.Candidates...)
	for candidateIndex := range cloned.Candidates {
		candidate := &cloned.Candidates[candidateIndex]
		candidate.Confidence = cloneFloat64Pointer(source.Candidates[candidateIndex].Confidence)
		candidate.Segments = append([]vcp.TranscriptSegment(nil), source.Candidates[candidateIndex].Segments...)
		for segmentIndex := range candidate.Segments {
			segment := &candidate.Segments[segmentIndex]
			sourceSegment := source.Candidates[candidateIndex].Segments[segmentIndex]
			segment.StartMilliseconds = cloneInt64Pointer(sourceSegment.StartMilliseconds)
			segment.EndMilliseconds = cloneInt64Pointer(sourceSegment.EndMilliseconds)
			segment.Confidence = cloneFloat64Pointer(sourceSegment.Confidence)
			segment.Words = append([]vcp.TranscriptWord(nil), sourceSegment.Words...)
			for wordIndex := range segment.Words {
				sourceWord := sourceSegment.Words[wordIndex]
				segment.Words[wordIndex].StartMilliseconds = cloneInt64Pointer(sourceWord.StartMilliseconds)
				segment.Words[wordIndex].EndMilliseconds = cloneInt64Pointer(sourceWord.EndMilliseconds)
				segment.Words[wordIndex].Confidence = cloneFloat64Pointer(sourceWord.Confidence)
			}
		}
	}
	return &cloned
}

// cloneResources deep-copies Router resources including private pointers retained by repositories.
// cloneResources 深拷贝 Router 资源，包括 Repository 保留的私有指针。
func cloneResources(source []resource.Resource) []resource.Resource {
	cloned := append([]resource.Resource(nil), source...)
	for index := range cloned {
		cloned[index].ExpiresAt = cloneTimePointer(source[index].ExpiresAt)
		if source[index].GeneratedBy != nil {
			generatedBy := *source[index].GeneratedBy
			cloned[index].GeneratedBy = &generatedBy
		}
		if source[index].Metadata.Image != nil {
			image := *source[index].Metadata.Image
			cloned[index].Metadata.Image = &image
		}
		if source[index].Metadata.Audio != nil {
			audio := *source[index].Metadata.Audio
			cloned[index].Metadata.Audio = &audio
		}
		if source[index].Metadata.Video != nil {
			video := *source[index].Metadata.Video
			if video.HasAudio != nil {
				hasAudio := *video.HasAudio
				video.HasAudio = &hasAudio
			}
			cloned[index].Metadata.Video = &video
		}
	}
	return cloned
}

// cloneUsageObservation deep-copies one optional observation and every optional numeric dimension.
// cloneUsageObservation 深拷贝一个可选观测及其每个可选数值维度。
func cloneUsageObservation(source *vcp.UsageObservation) *vcp.UsageObservation {
	if source == nil {
		return nil
	}
	copy := *source
	if source.ServiceUnits != nil {
		value := *source.ServiceUnits
		copy.ServiceUnits = &value
	}
	copy.InputTokens = cloneInt64Pointer(source.InputTokens)
	copy.OutputTokens = cloneInt64Pointer(source.OutputTokens)
	copy.ReasoningTokens = cloneInt64Pointer(source.ReasoningTokens)
	copy.CacheReadTokens = cloneInt64Pointer(source.CacheReadTokens)
	copy.CacheCreationTokens = cloneInt64Pointer(source.CacheCreationTokens)
	copy.TotalTokens = cloneInt64Pointer(source.TotalTokens)
	return &copy
}

// cloneInt64Pointer returns an independent optional integer value.
// cloneInt64Pointer 返回一个独立的可选整数值。
func cloneInt64Pointer(source *int64) *int64 {
	if source == nil {
		return nil
	}
	value := *source
	return &value
}

// cloneIntPointer returns an independent optional integer value.
// cloneIntPointer 返回独立的可选整数值。
func cloneIntPointer(source *int) *int {
	if source == nil {
		return nil
	}
	value := *source
	return &value
}

// cloneFloat64Pointer returns an independent optional floating-point value.
// cloneFloat64Pointer 返回独立的可选浮点值。
func cloneFloat64Pointer(source *float64) *float64 {
	if source == nil {
		return nil
	}
	value := *source
	return &value
}

// cloneTimePointer returns an independent optional time value.
// cloneTimePointer 返回独立的可选时间值。
func cloneTimePointer(source *time.Time) *time.Time {
	if source == nil {
		return nil
	}
	value := *source
	return &value
}
