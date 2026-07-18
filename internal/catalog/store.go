package catalog

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

var (
	// ErrSnapshotNotFound reports a missing provider catalog snapshot.
	// ErrSnapshotNotFound 表示供应商目录快照不存在。
	ErrSnapshotNotFound = errors.New("provider catalog snapshot not found")
)

// Store persists atomic provider-scoped catalog snapshots.
// Store 持久化原子的供应商作用域目录快照。
type Store interface {
	// Save creates or replaces one provider snapshot with a newer revision.
	// Save 使用更高修订号创建或替换一个供应商快照。
	Save(context.Context, Snapshot) error
	// Delete removes one provider snapshot and reports ErrSnapshotNotFound when it does not exist.
	// Delete 删除一个供应商快照，目标不存在时返回 ErrSnapshotNotFound。
	Delete(context.Context, string) error
	// Get returns one mutation-safe provider snapshot.
	// Get 返回一个防止外部修改的供应商快照。
	Get(context.Context, string) (Snapshot, error)
}

// MemoryStore is a thread-safe atomic catalog store for tests and framework bootstrap.
// MemoryStore 是用于测试和框架启动的线程安全原子目录存储。
type MemoryStore struct {
	// mu protects atomic snapshot replacement and reads.
	// mu 保护原子快照替换和读取。
	mu sync.RWMutex
	// snapshots stores one latest catalog per provider instance.
	// snapshots 为每个供应商实例存储一个最新目录。
	snapshots map[string]Snapshot
}

// NewMemoryStore creates an empty atomic provider catalog store.
// NewMemoryStore 创建一个空的原子供应商目录存储。
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{snapshots: make(map[string]Snapshot)}
}

// Save validates and atomically stores a newer provider catalog revision.
// Save 校验并原子存储一个更新的供应商目录修订。
func (s *MemoryStore) Save(ctx context.Context, snapshot Snapshot) error {
	if ctx == nil {
		return errors.New("context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := snapshot.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if current, exists := s.snapshots[snapshot.ProviderInstanceID]; exists && snapshot.Revision <= current.Revision {
		return fmt.Errorf("%w: catalog revision must increase", ErrInvalidCatalog)
	}
	s.snapshots[snapshot.ProviderInstanceID] = cloneSnapshot(snapshot)
	return nil
}

// Delete removes one provider snapshot atomically.
// Delete 原子删除一个供应商快照。
func (s *MemoryStore) Delete(ctx context.Context, providerInstanceID string) error {
	if ctx == nil {
		return errors.New("context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.snapshots[providerInstanceID]; !exists {
		return fmt.Errorf("%w: %s", ErrSnapshotNotFound, providerInstanceID)
	}
	delete(s.snapshots, providerInstanceID)
	return nil
}

// Get returns one mutation-safe atomic provider catalog snapshot.
// Get 返回一个防止外部修改的原子供应商目录快照。
func (s *MemoryStore) Get(ctx context.Context, providerInstanceID string) (Snapshot, error) {
	if ctx == nil {
		return Snapshot{}, errors.New("context is required")
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	snapshot, exists := s.snapshots[providerInstanceID]
	if !exists {
		return Snapshot{}, fmt.Errorf("%w: %s", ErrSnapshotNotFound, providerInstanceID)
	}
	return cloneSnapshot(snapshot), nil
}

// cloneSnapshot returns a deep-enough immutable catalog value for all slice and pointer fields.
// cloneSnapshot 为全部切片和指针字段返回足够深度的不可变目录值。
func cloneSnapshot(snapshot Snapshot) Snapshot {
	snapshot.Models = append([]ProviderModel(nil), snapshot.Models...)
	snapshot.Offerings = append([]ModelOffering(nil), snapshot.Offerings...)
	for index := range snapshot.Offerings {
		snapshot.Offerings[index].Capabilities = cloneCapabilities(snapshot.Offerings[index].Capabilities)
	}
	snapshot.Profiles = append([]ExecutionProfile(nil), snapshot.Profiles...)
	for index := range snapshot.Profiles {
		snapshot.Profiles[index].Capabilities = cloneCapabilities(snapshot.Profiles[index].Capabilities)
		snapshot.Profiles[index].RequiredEntitlementClasses = append([]string(nil), snapshot.Profiles[index].RequiredEntitlementClasses...)
	}
	snapshot.Entitlements = append([]ModelEntitlement(nil), snapshot.Entitlements...)
	for index := range snapshot.Entitlements {
		snapshot.Entitlements[index].AllowedProfileIDs = append([]string(nil), snapshot.Entitlements[index].AllowedProfileIDs...)
	}
	snapshot.Plans = append([]PlanSnapshot(nil), snapshot.Plans...)
	snapshot.Allowances = append([]AllowanceSnapshot(nil), snapshot.Allowances...)
	for index := range snapshot.Allowances {
		snapshot.Allowances[index] = cloneAllowance(snapshot.Allowances[index])
	}
	snapshot.Pools = append([]PoolSummary(nil), snapshot.Pools...)
	for index := range snapshot.Pools {
		snapshot.Pools[index].BlockingAllowanceKinds = append([]AllowanceKind(nil), snapshot.Pools[index].BlockingAllowanceKinds...)
		if snapshot.Pools[index].EarliestResetAt != nil {
			resetAt := *snapshot.Pools[index].EarliestResetAt
			snapshot.Pools[index].EarliestResetAt = &resetAt
		}
	}
	return snapshot
}

// cloneCapabilities returns one mutation-safe model capability value.
// cloneCapabilities 返回一个防止外部修改的模型能力值。
func cloneCapabilities(capabilities ModelCapabilities) ModelCapabilities {
	capabilities.InputModalities = append([]string(nil), capabilities.InputModalities...)
	capabilities.OutputModalities = append([]string(nil), capabilities.OutputModalities...)
	return capabilities
}

// cloneAllowance returns one mutation-safe allowance value.
// cloneAllowance 返回一个防止外部修改的资源值。
func cloneAllowance(allowance AllowanceSnapshot) AllowanceSnapshot {
	allowance.Limit = cloneStringPointer(allowance.Limit)
	allowance.Used = cloneStringPointer(allowance.Used)
	allowance.Remaining = cloneStringPointer(allowance.Remaining)
	if allowance.RemainingRatio != nil {
		remainingRatio := *allowance.RemainingRatio
		allowance.RemainingRatio = &remainingRatio
	}
	if allowance.Window != nil {
		window := *allowance.Window
		if window.ResetAt != nil {
			resetAt := *window.ResetAt
			window.ResetAt = &resetAt
		}
		allowance.Window = &window
	}
	return allowance
}

// cloneStringPointer copies one optional immutable decimal string.
// cloneStringPointer 复制一个可选的不可变十进制字符串。
func cloneStringPointer(value *string) *string {
	if value == nil {
		return nil
	}
	clonedValue := *value
	return &clonedValue
}
