package refresh

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
)

// coordinatorInstanceLister returns one stable test instance set.
// coordinatorInstanceLister 返回一组稳定测试实例。
type coordinatorInstanceLister struct {
	// instances contains the exact configured test instances.
	// instances 包含精确配置的测试实例。
	instances []providerconfig.ProviderInstance
}

// ListInstances returns isolated instance snapshots.
// ListInstances 返回隔离的实例快照。
func (l coordinatorInstanceLister) ListInstances(context.Context, string) ([]providerconfig.ProviderInstance, error) {
	return append([]providerconfig.ProviderInstance(nil), l.instances...), nil
}

// blockingMetadataRefresher records calls and waits for release or timeout.
// blockingMetadataRefresher 记录调用并等待释放或超时。
type blockingMetadataRefresher struct {
	// calls receives each exact instance identifier.
	// calls 接收每个精确实例标识。
	calls chan string
	// release allows a successful refresh return when non-nil.
	// release 非空时允许刷新成功返回。
	release chan struct{}
	// mu protects observed context errors.
	// mu 保护已观测 Context 错误。
	mu sync.Mutex
	// contextErrors records timeout or shutdown cancellation.
	// contextErrors 记录超时或关闭取消。
	contextErrors []error
}

// Refresh records one call and obeys its exact caller timeout.
// Refresh 记录一次调用并遵守精确调用方超时。
func (r *blockingMetadataRefresher) Refresh(ctx context.Context, instanceID string, _ time.Time) (catalog.Snapshot, error) {
	r.calls <- instanceID
	if r.release != nil {
		select {
		case <-r.release:
			return catalog.Snapshot{ProviderInstanceID: instanceID}, nil
		case <-ctx.Done():
			r.recordContextError(ctx.Err())
			return catalog.Snapshot{}, ctx.Err()
		}
	}
	<-ctx.Done()
	r.recordContextError(ctx.Err())
	return catalog.Snapshot{}, ctx.Err()
}

// recordContextError appends one observed cancellation under lock.
// recordContextError 在锁保护下追加一个已观测取消。
func (r *blockingMetadataRefresher) recordContextError(errValue error) {
	r.mu.Lock()
	r.contextErrors = append(r.contextErrors, errValue)
	r.mu.Unlock()
}

// TestCoordinatorDeduplicatesImmediateTriggers verifies queued and in-flight refreshes share one key.
// TestCoordinatorDeduplicatesImmediateTriggers 验证已排队与执行中的刷新共享一个去重键。
func TestCoordinatorDeduplicatesImmediateTriggers(t *testing.T) {
	refresher := &blockingMetadataRefresher{calls: make(chan string, 2), release: make(chan struct{})}
	coordinator, errCoordinator := NewCoordinator(coordinatorInstanceLister{}, refresher, CoordinatorOptions{Interval: time.Hour, Jitter: time.Nanosecond, Timeout: time.Second, Workers: 1, Now: func() time.Time { return time.Date(2026, 7, 20, 18, 0, 0, 0, time.UTC) }})
	if errCoordinator != nil {
		t.Fatalf("create coordinator: %v", errCoordinator)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = coordinator.Run(ctx) }()
	if !coordinator.Trigger("pvi_test") || coordinator.Trigger("pvi_test") {
		t.Fatal("immediate trigger was not deduplicated")
	}
	select {
	case instanceID := <-refresher.calls:
		if instanceID != "pvi_test" {
			t.Fatalf("refresh instance=%q", instanceID)
		}
	case <-time.After(time.Second):
		t.Fatal("refresh was not dispatched")
	}
	if coordinator.Trigger("pvi_test") {
		t.Fatal("in-flight trigger was not deduplicated")
	}
	close(refresher.release)
	deadline := time.Now().Add(time.Second)
	for !coordinator.Trigger("pvi_test") {
		if time.Now().After(deadline) {
			t.Fatal("completed refresh key was not released")
		}
		time.Sleep(time.Millisecond)
	}
}

// TestCoordinatorBoundsRefreshTimeout verifies an unresponsive provider cannot occupy a worker forever.
// TestCoordinatorBoundsRefreshTimeout 验证无响应供应商不能永久占用 Worker。
func TestCoordinatorBoundsRefreshTimeout(t *testing.T) {
	refresher := &blockingMetadataRefresher{calls: make(chan string, 1)}
	coordinator, errCoordinator := NewCoordinator(coordinatorInstanceLister{}, refresher, CoordinatorOptions{Interval: time.Hour, Jitter: time.Nanosecond, Timeout: 10 * time.Millisecond, Workers: 1})
	if errCoordinator != nil {
		t.Fatalf("create coordinator: %v", errCoordinator)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = coordinator.Run(ctx) }()
	if !coordinator.Trigger("pvi_timeout") {
		t.Fatal("timeout trigger was rejected")
	}
	select {
	case <-refresher.calls:
	case <-time.After(time.Second):
		t.Fatal("timeout refresh was not dispatched")
	}
	deadline := time.Now().Add(time.Second)
	for {
		refresher.mu.Lock()
		observed := len(refresher.contextErrors) > 0
		refresher.mu.Unlock()
		if observed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("refresh timeout was not observed")
		}
		time.Sleep(time.Millisecond)
	}
}

// TestStableRefreshJitterIsDeterministicAndBounded verifies restart-stable scheduling.
// TestStableRefreshJitterIsDeterministicAndBounded 验证重启稳定调度。
func TestStableRefreshJitterIsDeterministicAndBounded(t *testing.T) {
	maximum := 30 * time.Second
	first := stableRefreshJitter("pvi_stable", maximum)
	second := stableRefreshJitter("pvi_stable", maximum)
	if first != second || first < 0 || first >= maximum {
		t.Fatalf("stable jitter first=%s second=%s maximum=%s", first, second, maximum)
	}
}

// TestCoordinatorDefaultsRefreshBeforeProviderEvidenceExpires verifies scheduling cannot create routine authorization-unknown gaps.
// TestCoordinatorDefaultsRefreshBeforeProviderEvidenceExpires 验证默认调度不会产生常规的授权未知时间缺口。
func TestCoordinatorDefaultsRefreshBeforeProviderEvidenceExpires(t *testing.T) {
	refresher := &blockingMetadataRefresher{calls: make(chan string, 1)}
	coordinator, errCoordinator := NewCoordinator(coordinatorInstanceLister{}, refresher, CoordinatorOptions{})
	if errCoordinator != nil {
		t.Fatalf("create coordinator: %v", errCoordinator)
	}
	if coordinator.options.Interval+coordinator.options.Jitter+coordinator.options.Timeout >= 5*time.Minute {
		t.Fatalf("default refresh envelope=%s, want below provider evidence lifetime", coordinator.options.Interval+coordinator.options.Jitter+coordinator.options.Timeout)
	}
}
