package execution

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// EventDistributor waits for durable event visibility without owning event truth or ordering.
// EventDistributor 等待持久事件可见性，但不拥有事件事实或排序。
type EventDistributor interface {
	// Wait returns durable events after one sequence or an empty slice when maxWait elapses.
	// Wait 返回指定序号后的持久事件，或在 maxWait 到期时返回空切片。
	Wait(context.Context, string, string, uint64, time.Duration) ([]Event, error)
}

// PollingEventDistributor provides a shared-database-safe baseline that can be replaced by database notifications or a bus.
// PollingEventDistributor 提供可用于共享数据库的基线，可由数据库通知或事件总线替换。
type PollingEventDistributor struct {
	// store remains the only authoritative durable event source.
	// store 始终是唯一权威持久事件来源。
	store Store
	// interval bounds visibility latency and shared-database read pressure.
	// interval 限制可见延迟与共享数据库读取压力。
	interval time.Duration
}

// NewPollingEventDistributor creates one cross-process-compatible durable event waiter.
// NewPollingEventDistributor 创建一个兼容跨进程持久事件等待器。
func NewPollingEventDistributor(store Store, interval time.Duration) (*PollingEventDistributor, error) {
	if store == nil {
		return nil, errors.New("execution event store is required")
	}
	if interval == 0 {
		interval = 250 * time.Millisecond
	}
	if interval < 10*time.Millisecond || interval > 10*time.Second {
		return nil, errors.New("execution event polling interval is outside the allowed boundary")
	}
	return &PollingEventDistributor{store: store, interval: interval}, nil
}

// Wait checks durable truth immediately and then at a bounded cadence until events, cancellation, or timeout.
// Wait 立即检查持久事实，随后按受限频率等待事件、取消或超时。
func (d *PollingEventDistributor) Wait(ctx context.Context, ownerAPIKeyID string, executionID string, afterSequence uint64, maxWait time.Duration) ([]Event, error) {
	if d == nil || d.store == nil || ctx == nil || ownerAPIKeyID == "" || executionID == "" || maxWait <= 0 || maxWait > time.Minute {
		return nil, fmt.Errorf("%w: event distribution request is invalid", ErrInvalidExecution)
	}
	events, errEvents := d.store.ListEvents(ctx, ownerAPIKeyID, executionID, afterSequence)
	if errEvents != nil || len(events) > 0 {
		return events, errEvents
	}
	ticker := time.NewTicker(d.interval)
	defer ticker.Stop()
	timeout := time.NewTimer(maxWait)
	defer timeout.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timeout.C:
			return []Event{}, nil
		case <-ticker.C:
			events, errEvents = d.store.ListEvents(ctx, ownerAPIKeyID, executionID, afterSequence)
			if errEvents != nil || len(events) > 0 {
				return events, errEvents
			}
		}
	}
}
