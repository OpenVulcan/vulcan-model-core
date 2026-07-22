package execution

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// durableProviderEventSink validates and commits provider semantic events while an upstream stream remains active.
// durableProviderEventSink 在上游流保持活跃时校验并提交供应商语义事件。
type durableProviderEventSink struct {
	// mu serializes reducer state and compare-and-swap event commits.
	// mu 串行化 Reducer 状态与比较交换事件提交。
	mu sync.Mutex
	// service owns the durable execution store and deterministic clock.
	// service 拥有持久执行存储与确定性时钟。
	service *Service
	// ownerAPIKeyID isolates the execution event stream.
	// ownerAPIKeyID 隔离执行事件流。
	ownerAPIKeyID string
	// executionID identifies the durable execution receiving events.
	// executionID 标识接收事件的持久执行。
	executionID string
	// reducer validates one response-local causal event sequence before publication.
	// reducer 在发布前校验一个响应内的因果事件序列。
	reducer *vcp.Reducer
	// responseID fixes the first observed response identity.
	// responseID 固定首次观测到的响应身份。
	responseID string
	// lastSequence tracks the latest durable Router event sequence.
	// lastSequence 跟踪最新持久 Router 事件序号。
	lastSequence uint64
	// initialized reports whether the existing durable log has been observed.
	// initialized 表示是否已经观察现有持久事件日志。
	initialized bool
	// emittedProviderEventIDs deduplicates exact provider replay events and supports terminal batch filtering.
	// emittedProviderEventIDs 对精确供应商重放事件去重，并支持终态批次过滤。
	emittedProviderEventIDs map[string]struct{}
	// partialBytes records the latest cumulative observation for each provider output.
	// partialBytes 记录每个供应商输出最新的累计观测。
	partialBytes map[string]int64
	// emittedResourceEvents counts durable native resource progress observations.
	// emittedResourceEvents 统计持久化原生资源进度观测。
	emittedResourceEvents int
}

// newDurableProviderEventSink creates one execution-scoped real-time semantic event sink.
// newDurableProviderEventSink 创建一个执行作用域实时语义事件 Sink。
func newDurableProviderEventSink(service *Service, record Record) *durableProviderEventSink {
	return &durableProviderEventSink{service: service, ownerAPIKeyID: record.OwnerAPIKeyID, executionID: record.ID, emittedProviderEventIDs: make(map[string]struct{}), partialBytes: make(map[string]int64)}
}

// EmitResourceProgress validates and durably commits one native cumulative resource observation.
// EmitResourceProgress 校验并持久提交一个原生累计资源观测。
func (s *durableProviderEventSink) EmitResourceProgress(ctx context.Context, progress provider.ResourceProgress) error {
	if errContext := ctx.Err(); errContext != nil {
		return errContext
	}
	if progress.PartialBytes <= 0 || progress.OutputID == "" || progress.MIMEType == "" || !validGeneratedMediaKind(progress.Kind) {
		return fmt.Errorf("%w: provider resource progress is invalid", ErrInvalidProviderResult)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if previous := s.partialBytes[progress.OutputID]; progress.PartialBytes <= previous {
		return fmt.Errorf("%w: provider resource progress must increase", ErrInvalidProviderResult)
	}
	if errInitialize := s.initializeSequence(ctx); errInitialize != nil {
		return errInitialize
	}
	for {
		record, errGet := s.service.store.Get(ctx, s.ownerAPIKeyID, s.executionID)
		if errGet != nil {
			return errGet
		}
		if record.Status.IsTerminal() {
			return provider.ErrExecutionEventSinkClosed
		}
		expectedRevision := record.Revision
		record.UpdatedAt = s.service.options.Now().UTC()
		record.Revision++
		sequence := s.lastSequence + 1
		partialBytes := progress.PartialBytes
		event := Event{ExecutionID: record.ID, EventID: fmt.Sprintf("evt_%s_%d", record.ID[4:], sequence), Sequence: sequence, Time: record.UpdatedAt, Type: EventResourcePartial, Resource: &ResourceEvent{OutputID: progress.OutputID, Kind: progress.Kind, MIMEType: progress.MIMEType, PartialBytes: &partialBytes}}
		if errSave := s.service.store.Save(ctx, record, expectedRevision, []Event{event}); errSave != nil {
			if !errors.Is(errSave, ErrRevisionConflict) {
				return errSave
			}
			if errRefresh := s.refreshSequence(ctx); errRefresh != nil {
				return errRefresh
			}
			continue
		}
		s.lastSequence = sequence
		s.partialBytes[progress.OutputID] = progress.PartialBytes
		s.emittedResourceEvents++
		return nil
	}
}

// Emit validates, deduplicates, and durably commits one provider event before upstream reading continues.
// Emit 在继续读取上游前校验、去重并持久提交一个供应商事件。
func (s *durableProviderEventSink) Emit(ctx context.Context, providerEvent vcp.Event) error {
	if errContext := ctx.Err(); errContext != nil {
		return errContext
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, duplicate := s.emittedProviderEventIDs[providerEvent.EventID]; duplicate {
		return nil
	}
	if s.reducer == nil {
		if providerEvent.ResponseID == "" {
			return fmt.Errorf("%w: provider event response identifier is required", ErrInvalidProviderResult)
		}
		s.responseID = providerEvent.ResponseID
		s.reducer = vcp.NewReducer(providerEvent.ResponseID)
	}
	if providerEvent.ResponseID != s.responseID {
		return fmt.Errorf("%w: provider event changed response identity", ErrInvalidProviderResult)
	}
	if errApply := s.reducer.Apply(providerEvent); errApply != nil {
		return fmt.Errorf("%w: provider semantic event: %v", ErrInvalidProviderResult, errApply)
	}
	if errInitialize := s.initializeSequence(ctx); errInitialize != nil {
		return errInitialize
	}
	for {
		record, errGet := s.service.store.Get(ctx, s.ownerAPIKeyID, s.executionID)
		if errGet != nil {
			return errGet
		}
		if record.Status.IsTerminal() {
			return provider.ErrExecutionEventSinkClosed
		}
		expectedRevision := record.Revision
		record.UpdatedAt = s.service.options.Now().UTC()
		record.Revision++
		sequence := s.lastSequence + 1
		eventCopy := providerEvent
		durableEvent := Event{ExecutionID: record.ID, EventID: fmt.Sprintf("evt_%s_%d", record.ID[4:], sequence), Sequence: sequence, Time: record.UpdatedAt, Type: EventProviderSemantic, ProviderEvent: &eventCopy}
		if errSave := s.service.store.Save(ctx, record, expectedRevision, []Event{durableEvent}); errSave != nil {
			if !errors.Is(errSave, ErrRevisionConflict) {
				return errSave
			}
			if errRefresh := s.refreshSequence(ctx); errRefresh != nil {
				return errRefresh
			}
			continue
		}
		s.lastSequence = sequence
		s.emittedProviderEventIDs[providerEvent.EventID] = struct{}{}
		return nil
	}
}

// initializeSequence loads the existing durable event boundary exactly once.
// initializeSequence 仅加载一次现有持久事件边界。
func (s *durableProviderEventSink) initializeSequence(ctx context.Context) error {
	if s.initialized {
		return nil
	}
	if errRefresh := s.refreshSequence(ctx); errRefresh != nil {
		return errRefresh
	}
	s.initialized = true
	return nil
}

// refreshSequence reloads the latest durable sequence after a concurrent lifecycle update.
// refreshSequence 在并发生命周期更新后重新加载最新持久序号。
func (s *durableProviderEventSink) refreshSequence(ctx context.Context) error {
	events, errEvents := s.service.store.ListEvents(ctx, s.ownerAPIKeyID, s.executionID, 0)
	if errEvents != nil {
		return errEvents
	}
	if len(events) == 0 {
		return fmt.Errorf("%w: execution event log is empty", ErrInvalidExecution)
	}
	s.lastSequence = events[len(events)-1].Sequence
	return nil
}

// emittedCount reports how many semantic events reached durable storage during the active dispatch.
// emittedCount 报告活动分派期间有多少语义事件进入持久存储。
func (s *durableProviderEventSink) emittedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.emittedProviderEventIDs) + s.emittedResourceEvents
}

// filterPending returns only provider events that were not already durably streamed.
// filterPending 仅返回尚未实时持久化的供应商事件。
func (s *durableProviderEventSink) filterPending(events []vcp.Event) []vcp.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	pending := make([]vcp.Event, 0, len(events))
	for _, event := range events {
		if _, emitted := s.emittedProviderEventIDs[event.EventID]; !emitted {
			pending = append(pending, event)
		}
	}
	return pending
}
