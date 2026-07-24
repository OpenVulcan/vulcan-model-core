// Package catalogruntime separates code-owned runtime catalogs from user-owned persisted catalogs.
// Package catalogruntime 将代码拥有的运行时目录与用户拥有的持久化目录分离。
package catalogruntime

import (
	"context"
	"errors"
	"fmt"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/dependency"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
)

// OwnershipStore exposes the exact configuration facts required to route catalog ownership.
// OwnershipStore 暴露路由目录所有权所需的精确配置事实。
type OwnershipStore interface {
	// GetDefinition returns the immutable owner definition for one provider instance.
	// GetDefinition 返回一个供应商实例对应的不可变所有者定义。
	GetDefinition(context.Context, string) (providerconfig.ProviderDefinition, error)
	// GetInstance returns one persisted provider instance.
	// GetInstance 返回一个持久化供应商实例。
	GetInstance(context.Context, string) (providerconfig.ProviderInstance, error)
	// ListInstances returns provider instances, optionally filtered by definition.
	// ListInstances 返回供应商实例，并可按定义筛选。
	ListInstances(context.Context, string) ([]providerconfig.ProviderInstance, error)
}

// PersistentPurger removes historical rows that no longer belong in durable catalog storage.
// PersistentPurger 删除不再属于持久化目录存储的历史记录。
type PersistentPurger interface {
	// Purge removes exact provider catalog snapshots and their historical change records.
	// Purge 删除精确供应商目录快照及其历史变更记录。
	Purge(context.Context, []string) (int, error)
}

// Store routes system catalogs to volatile memory and custom catalogs to durable storage.
// Store 将系统目录路由到易失内存，并将自定义目录路由到持久化存储。
type Store struct {
	// ownership resolves the immutable system-or-custom definition boundary.
	// ownership 解析不可变的系统或自定义定义边界。
	ownership OwnershipStore
	// runtime owns every in-process snapshot and the process-local global change sequence.
	// runtime 拥有每个进程内快照以及进程本地的全局变更序列。
	runtime *catalog.MemoryStore
	// persistent owns only user-created custom-provider snapshots.
	// persistent 仅拥有用户创建的自定义供应商快照。
	persistent catalog.Store
}

// New creates an ownership-aware runtime catalog store.
// New 创建一个感知所有权的运行时目录存储。
func New(ownership OwnershipStore, persistent catalog.Store) (*Store, error) {
	if dependency.IsNil(ownership) || dependency.IsNil(persistent) {
		return nil, errors.New("catalog ownership and persistent stores are required")
	}
	return &Store{ownership: ownership, runtime: catalog.NewMemoryStore(), persistent: persistent}, nil
}

// Save stores system snapshots only in memory and durably stores custom snapshots.
// Save 仅在内存中保存系统快照，并持久化保存自定义快照。
func (s *Store) Save(ctx context.Context, snapshot catalog.Snapshot) error {
	systemOwned, errOwnership := s.systemOwned(ctx, snapshot.ProviderInstanceID)
	if errOwnership != nil {
		return errOwnership
	}
	if systemOwned {
		return s.runtime.Save(ctx, snapshot)
	}
	if errValidate := snapshot.Validate(); errValidate != nil {
		return errValidate
	}
	current, errCurrent := s.runtime.Get(ctx, snapshot.ProviderInstanceID)
	if errCurrent == nil && snapshot.Revision <= current.Revision {
		return fmt.Errorf("%w: runtime catalog revision must increase", catalog.ErrInvalidCatalog)
	}
	if errCurrent != nil && !errors.Is(errCurrent, catalog.ErrSnapshotNotFound) {
		return errCurrent
	}
	if errPersist := s.persistent.Save(ctx, snapshot); errPersist != nil {
		return errPersist
	}
	return s.runtime.Save(ctx, snapshot)
}

// Delete removes a system snapshot from memory or a custom snapshot from both durable and runtime stores.
// Delete 从内存删除系统快照，或从持久化与运行时存储中同时删除自定义快照。
func (s *Store) Delete(ctx context.Context, providerInstanceID string) error {
	systemOwned, errOwnership := s.systemOwned(ctx, providerInstanceID)
	if errOwnership != nil {
		return errOwnership
	}
	if systemOwned {
		return s.runtime.Delete(ctx, providerInstanceID)
	}
	snapshot, errSnapshot := s.persistent.Get(ctx, providerInstanceID)
	if errSnapshot != nil {
		return errSnapshot
	}
	if errDelete := s.persistent.Delete(ctx, providerInstanceID); errDelete != nil {
		return errDelete
	}
	if errMirror := s.mirrorRuntime(ctx, snapshot); errMirror != nil {
		return fmt.Errorf("mirror custom catalog before runtime deletion: %w", errMirror)
	}
	return s.runtime.Delete(ctx, providerInstanceID)
}

// ListChanges returns one process-local globally ordered catalog change page.
// ListChanges 返回一个进程本地全局有序的目录变更页。
func (s *Store) ListChanges(ctx context.Context, afterRevision uint64, limit int) (catalog.ChangePage, error) {
	return s.runtime.ListChanges(ctx, afterRevision, limit)
}

// Get returns the runtime system snapshot or the authoritative durable custom snapshot without turning reads into change events.
// Get 返回运行时系统快照或权威持久化自定义快照，且不会把读取转换为变更事件。
func (s *Store) Get(ctx context.Context, providerInstanceID string) (catalog.Snapshot, error) {
	systemOwned, errOwnership := s.systemOwned(ctx, providerInstanceID)
	if errOwnership != nil {
		return catalog.Snapshot{}, errOwnership
	}
	if systemOwned {
		return s.runtime.Get(ctx, providerInstanceID)
	}
	snapshot, errSnapshot := s.persistent.Get(ctx, providerInstanceID)
	if errSnapshot != nil {
		return catalog.Snapshot{}, errSnapshot
	}
	return snapshot, nil
}

// systemOwned resolves the unique definition ownership for one provider instance.
// systemOwned 解析一个供应商实例的唯一所有权定义。
func (s *Store) systemOwned(ctx context.Context, providerInstanceID string) (bool, error) {
	instance, errInstance := s.ownership.GetInstance(ctx, providerInstanceID)
	if errInstance != nil {
		return false, fmt.Errorf("get provider instance %s for catalog ownership: %w", providerInstanceID, errInstance)
	}
	definition, errDefinition := s.ownership.GetDefinition(ctx, instance.DefinitionID)
	if errDefinition != nil {
		return false, fmt.Errorf("get provider definition %s for catalog ownership: %w", instance.DefinitionID, errDefinition)
	}
	switch definition.Kind {
	case providerconfig.DefinitionKindSystem:
		return true, nil
	case providerconfig.DefinitionKindCustom:
		return false, nil
	default:
		return false, fmt.Errorf("provider definition %s has unsupported catalog ownership %q", definition.ID, definition.Kind)
	}
}

// mirrorRuntime publishes one durable custom snapshot into the process-local change stream exactly once per revision.
// mirrorRuntime 将一个持久化自定义快照按每个修订仅一次发布到进程本地变更流。
func (s *Store) mirrorRuntime(ctx context.Context, snapshot catalog.Snapshot) error {
	current, errCurrent := s.runtime.Get(ctx, snapshot.ProviderInstanceID)
	if errors.Is(errCurrent, catalog.ErrSnapshotNotFound) {
		return s.runtime.Save(ctx, snapshot)
	}
	if errCurrent != nil {
		return errCurrent
	}
	if current.Revision > snapshot.Revision {
		return fmt.Errorf("%w: runtime custom catalog is newer than durable catalog", catalog.ErrInvalidCatalog)
	}
	if current.Revision == snapshot.Revision {
		return nil
	}
	return s.runtime.Save(ctx, snapshot)
}

// PurgePersistedSystemCatalogs removes every code-owned system catalog from durable storage.
// PurgePersistedSystemCatalogs 从持久化存储中删除所有代码拥有的系统目录。
func PurgePersistedSystemCatalogs(ctx context.Context, ownership OwnershipStore, persistent PersistentPurger) (int, error) {
	if ctx == nil {
		return 0, errors.New("context is required")
	}
	if dependency.IsNil(ownership) || dependency.IsNil(persistent) {
		return 0, errors.New("catalog ownership and purge stores are required")
	}
	instances, errInstances := ownership.ListInstances(ctx, "")
	if errInstances != nil {
		return 0, fmt.Errorf("list provider instances for system catalog purge: %w", errInstances)
	}
	systemInstanceIDs := make([]string, 0, len(instances))
	for _, instance := range instances {
		definition, errDefinition := ownership.GetDefinition(ctx, instance.DefinitionID)
		if errDefinition != nil {
			return 0, fmt.Errorf("get provider definition %s for system catalog purge: %w", instance.DefinitionID, errDefinition)
		}
		if definition.Kind == providerconfig.DefinitionKindSystem {
			systemInstanceIDs = append(systemInstanceIDs, instance.ID)
		}
	}
	return persistent.Purge(ctx, systemInstanceIDs)
}
