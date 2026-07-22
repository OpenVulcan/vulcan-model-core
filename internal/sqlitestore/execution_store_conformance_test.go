package sqlitestore

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/execution"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// executionStoreConformanceCase describes one execution repository implementation under the shared behavioral contract.
// executionStoreConformanceCase 描述共享行为契约下的一个执行 Repository 实现。
type executionStoreConformanceCase struct {
	// name identifies the implementation in subtest output.
	// name 在子测试输出中标识具体实现。
	name string
	// open creates one isolated Store and registers any required cleanup with the test.
	// open 创建一个隔离 Store，并向测试注册所需清理逻辑。
	open func(*testing.T) execution.Store
}

// TestExecutionStoreConformance verifies memory and durable repositories obey one transactional contract.
// TestExecutionStoreConformance 验证内存与持久 Repository 遵循同一事务契约。
func TestExecutionStoreConformance(t *testing.T) {
	testCases := []executionStoreConformanceCase{
		{
			name: "memory",
			open: func(*testing.T) execution.Store {
				return execution.NewMemoryStore()
			},
		},
		{
			name: "sqlite",
			open: func(t *testing.T) execution.Store {
				database, errOpen := Open(context.Background(), filepath.Join(t.TempDir(), "conformance.db"))
				if errOpen != nil {
					t.Fatalf("Open() error = %v", errOpen)
				}
				t.Cleanup(func() {
					if errClose := database.Close(); errClose != nil {
						t.Errorf("Close() error = %v", errClose)
					}
				})
				store, errStore := NewExecutionStore(database, secret.NewMemoryStore())
				if errStore != nil {
					t.Fatalf("NewExecutionStore() error = %v", errStore)
				}
				return store
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			runExecutionStoreConformance(t, testCase.open(t))
		})
	}
}

// runExecutionStoreConformance verifies admission, replay, atomic CAS, ordered events, recovery, and ownership.
// runExecutionStoreConformance 验证接收、重放、原子 CAS、有序事件、恢复与所有权。
func runExecutionStoreConformance(t *testing.T, store execution.Store) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, time.July, 21, 22, 0, 0, 0, time.UTC)
	record := sqliteExecutionRecord(now)
	accepted := sqliteLifecycleEvent(record.ID, 1, now, execution.EventExecutionAccepted, execution.StatusAccepted)

	created, replayed, errCreate := store.Create(ctx, record, accepted)
	if errCreate != nil || replayed || created.Revision != 1 {
		t.Fatalf("Create() record=%+v replayed=%t error=%v", created, replayed, errCreate)
	}
	lookup, found, errLookup := store.LookupIdempotency(ctx, record.OwnerAPIKeyID, record.IdempotencyKey, record.RequestHash)
	if errLookup != nil || !found || lookup.ID != record.ID {
		t.Fatalf("LookupIdempotency() record=%+v found=%t error=%v", lookup, found, errLookup)
	}
	if _, errForeignGet := store.Get(ctx, "another-owner", record.ID); !errors.Is(errForeignGet, execution.ErrExecutionNotFound) {
		t.Fatalf("foreign Get() error=%v", errForeignGet)
	}
	if _, replayed, errReplay := store.Create(ctx, record, accepted); errReplay != nil || !replayed {
		t.Fatalf("replayed Create() replayed=%t error=%v", replayed, errReplay)
	}
	conflict := record
	conflict.ID = "exe_cccccccccccccccccccccccccccccccc"
	conflict.RequestHash = "different-request-hash"
	conflictingAccepted := sqliteLifecycleEvent(conflict.ID, 1, now, execution.EventExecutionAccepted, execution.StatusAccepted)
	if _, _, errConflict := store.Create(ctx, conflict, conflictingAccepted); !errors.Is(errConflict, execution.ErrIdempotencyConflict) {
		t.Fatalf("conflicting Create() error=%v", errConflict)
	}

	queued := record
	queued.Status = execution.StatusQueued
	queued.UpdatedAt = now.Add(time.Second)
	queued.Revision = 2
	queuedEvent := sqliteLifecycleEvent(record.ID, 2, queued.UpdatedAt, execution.EventExecutionQueued, execution.StatusQueued)
	if errSave := store.Save(ctx, queued, 1, []execution.Event{queuedEvent}); errSave != nil {
		t.Fatalf("Save(queued) error=%v", errSave)
	}
	if errStale := store.Save(ctx, queued, 1, nil); !errors.Is(errStale, execution.ErrRevisionConflict) {
		t.Fatalf("stale Save() error=%v", errStale)
	}

	running := queued
	running.Status = execution.StatusRunning
	running.UpdatedAt = now.Add(2 * time.Second)
	running.Revision = 3
	invalidEvent := sqliteLifecycleEvent(record.ID, 4, running.UpdatedAt, execution.EventExecutionRunning, execution.StatusRunning)
	if errInvalid := store.Save(ctx, running, 2, []execution.Event{invalidEvent}); !errors.Is(errInvalid, execution.ErrInvalidExecution) {
		t.Fatalf("non-contiguous Save() error=%v", errInvalid)
	}
	unchanged, errUnchanged := store.Get(ctx, record.OwnerAPIKeyID, record.ID)
	eventsAfterRollback, errEventsAfterRollback := store.ListEvents(ctx, record.OwnerAPIKeyID, record.ID, 0)
	if errUnchanged != nil || errEventsAfterRollback != nil || unchanged.Revision != 2 || unchanged.Status != execution.StatusQueued || len(eventsAfterRollback) != 2 {
		t.Fatalf("failed Save() was not atomic: record=%+v events=%+v get_error=%v events_error=%v", unchanged, eventsAfterRollback, errUnchanged, errEventsAfterRollback)
	}
	runningEvent := sqliteLifecycleEvent(record.ID, 3, running.UpdatedAt, execution.EventExecutionRunning, execution.StatusRunning)
	if errSave := store.Save(ctx, running, 2, []execution.Event{runningEvent}); errSave != nil {
		t.Fatalf("Save(running) error=%v", errSave)
	}
	events, errEvents := store.ListEvents(ctx, record.OwnerAPIKeyID, record.ID, 1)
	if errEvents != nil || len(events) != 2 || events[0].Sequence != 2 || events[1].Sequence != 3 {
		t.Fatalf("ListEvents() events=%+v error=%v", events, errEvents)
	}
	recoverable, errRecoverable := store.ListRecoverable(ctx)
	if errRecoverable != nil || len(recoverable) != 1 || recoverable[0].ID != record.ID || recoverable[0].Revision != 3 {
		t.Fatalf("ListRecoverable() records=%+v error=%v", recoverable, errRecoverable)
	}

	succeeded := running
	succeeded.Status = execution.StatusSucceeded
	succeeded.UpdatedAt = now.Add(3 * time.Second)
	succeeded.Revision = 4
	succeeded.Result = &execution.Result{Conversation: &vcp.Response{ResponseID: "response-conformance", Status: vcp.ResponseCompleted}}
	succeededEvent := sqliteLifecycleEvent(record.ID, 4, succeeded.UpdatedAt, execution.EventExecutionSucceeded, execution.StatusSucceeded)
	if errSave := store.Save(ctx, succeeded, 3, []execution.Event{succeededEvent}); errSave != nil {
		t.Fatalf("Save(succeeded) error=%v", errSave)
	}
	recoverable, errRecoverable = store.ListRecoverable(ctx)
	if errRecoverable != nil || len(recoverable) != 0 {
		t.Fatalf("terminal ListRecoverable() records=%+v error=%v", recoverable, errRecoverable)
	}

	cancelledContext, cancel := context.WithCancel(ctx)
	cancel()
	if _, errCancelled := store.Get(cancelledContext, record.OwnerAPIKeyID, record.ID); !errors.Is(errCancelled, context.Canceled) {
		t.Fatalf("cancelled Get() error=%v", errCancelled)
	}
}

// TestExecutionLeaseStoreConformance verifies the durable multi-instance lease contract independently from execution data.
// TestExecutionLeaseStoreConformance 独立于执行数据验证持久化多实例租约契约。
func TestExecutionLeaseStoreConformance(t *testing.T) {
	ctx := context.Background()
	database, errOpen := Open(ctx, filepath.Join(t.TempDir(), "lease-conformance.db"))
	if errOpen != nil {
		t.Fatalf("Open() error = %v", errOpen)
	}
	t.Cleanup(func() {
		if errClose := database.Close(); errClose != nil {
			t.Errorf("Close() error = %v", errClose)
		}
	})
	store, errStore := NewExecutionStore(database, secret.NewMemoryStore())
	if errStore != nil {
		t.Fatalf("NewExecutionStore() error = %v", errStore)
	}
	now := time.Date(2026, time.July, 21, 23, 0, 0, 0, time.UTC)
	record := sqliteExecutionRecord(now)
	accepted := sqliteLifecycleEvent(record.ID, 1, now, execution.EventExecutionAccepted, execution.StatusAccepted)
	if _, _, errCreate := store.Create(ctx, record, accepted); errCreate != nil {
		t.Fatalf("Create() error = %v", errCreate)
	}
	runExecutionLeaseStoreConformance(t, store, record.ID, now)
}

// runExecutionLeaseStoreConformance verifies exclusive ownership, renewal, exact release, and expiry takeover.
// runExecutionLeaseStoreConformance 验证排他所有权、续约、精确释放与过期接管。
func runExecutionLeaseStoreConformance(t *testing.T, store execution.LeaseStore, executionID string, now time.Time) {
	t.Helper()
	ctx := context.Background()
	firstOwner := "worker-first"
	secondOwner := "worker-second"
	acquired, errAcquire := store.AcquireLease(ctx, executionID, firstOwner, now, now.Add(30*time.Second))
	if errAcquire != nil || !acquired {
		t.Fatalf("first AcquireLease() acquired=%t error=%v", acquired, errAcquire)
	}
	blocked, errBlocked := store.AcquireLease(ctx, executionID, secondOwner, now.Add(time.Second), now.Add(31*time.Second))
	if errBlocked != nil || blocked {
		t.Fatalf("competing AcquireLease() acquired=%t error=%v", blocked, errBlocked)
	}
	if renewed, errRenew := store.RenewLease(ctx, executionID, firstOwner, now.Add(2*time.Second), now.Add(40*time.Second)); errRenew != nil || !renewed {
		t.Fatalf("RenewLease() renewed=%t error=%v", renewed, errRenew)
	}
	if errRelease := store.ReleaseLease(ctx, executionID, secondOwner); errRelease != nil {
		t.Fatalf("non-owner ReleaseLease() error=%v", errRelease)
	}
	if renewed, errRenew := store.RenewLease(ctx, executionID, firstOwner, now.Add(3*time.Second), now.Add(41*time.Second)); errRenew != nil || !renewed {
		t.Fatalf("lease disappeared after non-owner release: renewed=%t error=%v", renewed, errRenew)
	}
	taken, errTakeover := store.AcquireLease(ctx, executionID, secondOwner, now.Add(42*time.Second), now.Add(72*time.Second))
	if errTakeover != nil || !taken {
		t.Fatalf("expired takeover acquired=%t error=%v", taken, errTakeover)
	}
	if renewed, errRenew := store.RenewLease(ctx, executionID, firstOwner, now.Add(43*time.Second), now.Add(73*time.Second)); errRenew != nil || renewed {
		t.Fatalf("previous owner RenewLease() renewed=%t error=%v", renewed, errRenew)
	}
	if errRelease := store.ReleaseLease(ctx, executionID, secondOwner); errRelease != nil {
		t.Fatalf("owner ReleaseLease() error=%v", errRelease)
	}
	if acquired, errAcquire := store.AcquireLease(ctx, executionID, firstOwner, now.Add(44*time.Second), now.Add(74*time.Second)); errAcquire != nil || !acquired {
		t.Fatalf("AcquireLease() after release acquired=%t error=%v", acquired, errAcquire)
	}
}
