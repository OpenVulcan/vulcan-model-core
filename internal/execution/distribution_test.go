package execution

import (
	"context"
	"testing"
	"time"
)

// TestPollingEventDistributorObservesDurableEvents verifies cross-instance-style visibility uses only the shared Store contract.
// TestPollingEventDistributorObservesDurableEvents 验证跨实例式可见性只依赖共享 Store 合同。
func TestPollingEventDistributorObservesDurableEvents(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 7, 22, 5, 0, 0, 0, time.UTC)
	record := validTestRecord(now)
	accepted := lifecycleEvent(record.ID, 1, now, EventExecutionAccepted, StatusAccepted, nil)
	if _, _, errCreate := store.Create(context.Background(), record, accepted); errCreate != nil {
		t.Fatalf("Create() error = %v", errCreate)
	}
	distributor, errDistributor := NewPollingEventDistributor(store, 10*time.Millisecond)
	if errDistributor != nil {
		t.Fatalf("NewPollingEventDistributor() error = %v", errDistributor)
	}
	result := make(chan []Event, 1)
	errors := make(chan error, 1)
	go func() {
		events, errWait := distributor.Wait(context.Background(), record.OwnerAPIKeyID, record.ID, 1, time.Second)
		result <- events
		errors <- errWait
	}()
	time.Sleep(25 * time.Millisecond)
	running := record
	running.Status = StatusRunning
	running.UpdatedAt = now.Add(time.Second)
	running.Revision = 2
	runningEvent := lifecycleEvent(record.ID, 2, running.UpdatedAt, EventExecutionRunning, StatusRunning, nil)
	if errSave := store.Save(context.Background(), running, 1, []Event{runningEvent}); errSave != nil {
		t.Fatalf("Save() error = %v", errSave)
	}
	select {
	case events := <-result:
		if errWait := <-errors; errWait != nil || len(events) != 1 || events[0].Sequence != 2 {
			t.Fatalf("Wait() = (%+v, %v)", events, errWait)
		}
	case <-time.After(time.Second):
		t.Fatal("Wait() did not observe the durable event")
	}
}

// TestPollingEventDistributorTimesOutWithoutInventingEvents verifies idle waits return an explicit empty durable batch.
// TestPollingEventDistributorTimesOutWithoutInventingEvents 验证空闲等待返回明确的空持久事件批次且不虚构事件。
func TestPollingEventDistributorTimesOutWithoutInventingEvents(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 7, 22, 5, 30, 0, 0, time.UTC)
	record := validTestRecord(now)
	accepted := lifecycleEvent(record.ID, 1, now, EventExecutionAccepted, StatusAccepted, nil)
	if _, _, errCreate := store.Create(context.Background(), record, accepted); errCreate != nil {
		t.Fatalf("Create() error = %v", errCreate)
	}
	distributor, errDistributor := NewPollingEventDistributor(store, 10*time.Millisecond)
	if errDistributor != nil {
		t.Fatalf("NewPollingEventDistributor() error = %v", errDistributor)
	}
	events, errWait := distributor.Wait(context.Background(), record.OwnerAPIKeyID, record.ID, 1, 30*time.Millisecond)
	if errWait != nil || len(events) != 0 {
		t.Fatalf("Wait() = (%+v, %v), want empty timeout", events, errWait)
	}
}
