package refresh

import (
	"context"
	"errors"
	"hash/fnv"
	"strings"
	"sync"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/dependency"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
)

// InstanceLister returns the provider instances eligible for periodic metadata refresh.
// InstanceLister 返回可参与周期元数据刷新的供应商实例。
type InstanceLister interface {
	// ListInstances returns stable instance snapshots, optionally filtered by definition.
	// ListInstances 返回稳定实例快照，并可按 Definition 过滤。
	ListInstances(context.Context, string) ([]providerconfig.ProviderInstance, error)
}

// MetadataRefresher atomically refreshes one provider instance.
// MetadataRefresher 原子刷新一个供应商实例。
type MetadataRefresher interface {
	// Refresh replaces current metadata using one fixed evaluation time.
	// Refresh 使用一个固定评估时间替换当前元数据。
	Refresh(context.Context, string, time.Time) (catalog.Snapshot, error)
}

// CoordinatorOptions controls bounded background refresh scheduling.
// CoordinatorOptions 控制有界后台刷新调度。
type CoordinatorOptions struct {
	// Interval is the period between complete instance scans.
	// Interval 是完整实例扫描之间的周期。
	Interval time.Duration
	// Jitter spreads each periodic scan by a stable per-instance delay.
	// Jitter 使用稳定的实例级延迟分散每次周期扫描。
	Jitter time.Duration
	// Timeout bounds one upstream instance refresh.
	// Timeout 限制一次上游实例刷新时长。
	Timeout time.Duration
	// Workers bounds concurrent provider refresh traffic.
	// Workers 限制并发供应商刷新流量。
	Workers int
	// Now supplies deterministic UTC evaluation time.
	// Now 提供确定性的 UTC 评估时间。
	Now func() time.Time
}

// Coordinator deduplicates immediate triggers and periodically refreshes every configured instance.
// Coordinator 对即时触发进行去重，并周期刷新每个已配置实例。
type Coordinator struct {
	// instances supplies the current provider-instance set.
	// instances 提供当前供应商实例集合。
	instances InstanceLister
	// refresher owns atomic provider metadata replacement.
	// refresher 管理原子供应商元数据替换。
	refresher MetadataRefresher
	// options contains validated scheduling limits.
	// options 包含已校验的调度限制。
	options CoordinatorOptions
	// queue carries deduplicated instance identifiers to bounded workers.
	// queue 将去重后的实例标识传递给有界 Worker。
	queue chan string
	// mu protects pending across HTTP triggers, scans, and workers.
	// mu 在 HTTP 触发、扫描和 Worker 之间保护 pending。
	mu sync.Mutex
	// pending contains queued or currently refreshing instance identifiers.
	// pending 包含已排队或正在刷新的实例标识。
	pending map[string]struct{}
}

// NewCoordinator creates one bounded metadata refresh scheduler.
// NewCoordinator 创建一个有界元数据刷新调度器。
func NewCoordinator(instances InstanceLister, refresher MetadataRefresher, options CoordinatorOptions) (*Coordinator, error) {
	if dependency.IsNil(instances) || dependency.IsNil(refresher) {
		return nil, errors.New("provider instance lister and metadata refresher are required")
	}
	if options.Interval <= 0 {
		// The default scan stays below the five-minute provider metadata freshness window, including jitter and timeout.
		// 默认扫描周期连同抖动与超时仍低于五分钟供应商元数据新鲜度窗口。
		options.Interval = 4 * time.Minute
	}
	if options.Jitter < 0 {
		return nil, errors.New("metadata refresh jitter cannot be negative")
	}
	if options.Jitter == 0 {
		options.Jitter = 15 * time.Second
	}
	if options.Timeout <= 0 {
		options.Timeout = 30 * time.Second
	}
	if options.Workers <= 0 {
		options.Workers = 4
	}
	if options.Workers > 32 {
		return nil, errors.New("metadata refresh workers cannot exceed 32")
	}
	if options.Now == nil {
		options.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Coordinator{instances: instances, refresher: refresher, options: options, queue: make(chan string, 1024), pending: make(map[string]struct{})}, nil
}

// Refresh performs one caller-owned synchronous refresh through the wrapped service.
// Refresh 通过包装服务执行一次由调用方拥有的同步刷新。
func (c *Coordinator) Refresh(ctx context.Context, instanceID string, now time.Time) (catalog.Snapshot, error) {
	return c.refresher.Refresh(ctx, instanceID, now)
}

// Trigger enqueues one immediate refresh unless that instance is already queued or running.
// Trigger 将一次即时刷新入队，除非该实例已经排队或正在运行。
func (c *Coordinator) Trigger(instanceID string) bool {
	instanceID = strings.TrimSpace(instanceID)
	if instanceID == "" {
		return false
	}
	c.mu.Lock()
	if _, exists := c.pending[instanceID]; exists {
		c.mu.Unlock()
		return false
	}
	c.pending[instanceID] = struct{}{}
	c.mu.Unlock()
	select {
	case c.queue <- instanceID:
		return true
	default:
		c.finish(instanceID)
		return false
	}
}

// Run starts bounded workers and periodic jittered scans until cancellation.
// Run 启动有界 Worker 与带抖动的周期扫描，直到取消。
func (c *Coordinator) Run(ctx context.Context) error {
	if ctx == nil {
		return errors.New("metadata refresh context is required")
	}
	for workerIndex := 0; workerIndex < c.options.Workers; workerIndex++ {
		go c.runWorker(ctx)
	}
	c.scheduleAll(ctx)
	ticker := time.NewTicker(c.options.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			c.scheduleAll(ctx)
		}
	}
}

// runWorker executes queued refreshes with one independent timeout each.
// runWorker 使用独立超时执行每个已排队刷新。
func (c *Coordinator) runWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case instanceID := <-c.queue:
			refreshContext, cancelRefresh := context.WithTimeout(ctx, c.options.Timeout)
			_, _ = c.refresher.Refresh(refreshContext, instanceID, c.options.Now().UTC())
			cancelRefresh()
			c.finish(instanceID)
		}
	}
}

// scheduleAll lists instances once and schedules each with stable jitter.
// scheduleAll 读取一次实例列表，并使用稳定抖动调度每个实例。
func (c *Coordinator) scheduleAll(ctx context.Context) {
	instances, errInstances := c.instances.ListInstances(ctx, "")
	if errInstances != nil {
		return
	}
	for _, instance := range instances {
		instanceID := instance.ID
		delay := stableRefreshJitter(instanceID, c.options.Jitter)
		go func() {
			timer := time.NewTimer(delay)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				c.Trigger(instanceID)
			}
		}()
	}
}

// finish removes one completed or rejected queue item from the deduplication set.
// finish 从去重集合移除一个已完成或被队列拒绝的项目。
func (c *Coordinator) finish(instanceID string) {
	c.mu.Lock()
	delete(c.pending, instanceID)
	c.mu.Unlock()
}

// stableRefreshJitter derives a restart-stable bounded delay without global random state.
// stableRefreshJitter 在不使用全局随机状态的情况下派生重启稳定的有界延迟。
func stableRefreshJitter(instanceID string, maximum time.Duration) time.Duration {
	if maximum <= 0 {
		return 0
	}
	hasher := fnv.New64a()
	_, _ = hasher.Write([]byte(instanceID))
	return time.Duration(hasher.Sum64() % uint64(maximum))
}
