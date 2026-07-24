package catalogruntime

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
)

// ownershipFixture supplies exact provider ownership records to runtime-store tests.
// ownershipFixture 为运行时存储测试提供精确的供应商所有权记录。
type ownershipFixture struct {
	// instances indexes provider instances by immutable identifier.
	// instances 按不可变标识索引供应商实例。
	instances map[string]providerconfig.ProviderInstance
	// definitions indexes provider definitions by immutable identifier.
	// definitions 按不可变标识索引供应商定义。
	definitions map[string]providerconfig.ProviderDefinition
}

// GetDefinition returns one exact fixture definition.
// GetDefinition 返回一条精确夹具定义。
func (f ownershipFixture) GetDefinition(_ context.Context, definitionID string) (providerconfig.ProviderDefinition, error) {
	definition, exists := f.definitions[definitionID]
	if !exists {
		return providerconfig.ProviderDefinition{}, errors.New("definition not found")
	}
	return definition, nil
}

// GetInstance returns one exact fixture instance.
// GetInstance 返回一条精确夹具实例。
func (f ownershipFixture) GetInstance(_ context.Context, instanceID string) (providerconfig.ProviderInstance, error) {
	instance, exists := f.instances[instanceID]
	if !exists {
		return providerconfig.ProviderInstance{}, errors.New("instance not found")
	}
	return instance, nil
}

// ListInstances returns every fixture instance or the exact requested definition subset.
// ListInstances 返回全部夹具实例或精确请求的定义子集。
func (f ownershipFixture) ListInstances(_ context.Context, definitionID string) ([]providerconfig.ProviderInstance, error) {
	instances := make([]providerconfig.ProviderInstance, 0, len(f.instances))
	for _, instance := range f.instances {
		if definitionID == "" || instance.DefinitionID == definitionID {
			instances = append(instances, instance)
		}
	}
	return instances, nil
}

// purgeFixture records exact purge ownership while deleting matching memory snapshots.
// purgeFixture 记录精确清理所有权，同时删除匹配的内存快照。
type purgeFixture struct {
	// MemoryStore provides validated catalog persistence behavior.
	// MemoryStore 提供经过校验的目录持久化行为。
	*catalog.MemoryStore
	// providerInstanceIDs records the exact purge request.
	// providerInstanceIDs 记录精确的清理请求。
	providerInstanceIDs []string
}

// Purge records and removes the exact requested provider catalogs.
// Purge 记录并删除精确请求的供应商目录。
func (f *purgeFixture) Purge(ctx context.Context, providerInstanceIDs []string) (int, error) {
	f.providerInstanceIDs = append([]string(nil), providerInstanceIDs...)
	purged := 0
	for _, providerInstanceID := range providerInstanceIDs {
		if _, errGet := f.Get(ctx, providerInstanceID); errors.Is(errGet, catalog.ErrSnapshotNotFound) {
			continue
		} else if errGet != nil {
			return 0, errGet
		}
		if errDelete := f.Delete(ctx, providerInstanceID); errDelete != nil {
			return 0, errDelete
		}
		purged++
	}
	return purged, nil
}

// TestStorePersistsOnlyCustomCatalogs verifies the system/custom durability boundary and unified runtime change stream.
// TestStorePersistsOnlyCustomCatalogs 验证系统与自定义目录的持久化边界及统一运行时变更流。
func TestStorePersistsOnlyCustomCatalogs(t *testing.T) {
	ctx := context.Background()
	ownership := testOwnershipFixture()
	persistent := catalog.NewMemoryStore()
	store, errStore := New(ownership, persistent)
	if errStore != nil {
		t.Fatalf("New() error = %v", errStore)
	}
	observedAt := time.Date(2026, 7, 24, 7, 30, 0, 0, time.UTC)
	systemSnapshot := catalog.Snapshot{ProviderInstanceID: "pvi_system", Revision: 1, ObservedAt: observedAt}
	customSnapshot := catalog.Snapshot{ProviderInstanceID: "pvi_custom", Revision: 1, ObservedAt: observedAt}
	if errSave := store.Save(ctx, systemSnapshot); errSave != nil {
		t.Fatalf("save system snapshot: %v", errSave)
	}
	if _, errPersistedSystem := persistent.Get(ctx, systemSnapshot.ProviderInstanceID); !errors.Is(errPersistedSystem, catalog.ErrSnapshotNotFound) {
		t.Fatalf("persisted system snapshot error = %v", errPersistedSystem)
	}
	if errSave := store.Save(ctx, customSnapshot); errSave != nil {
		t.Fatalf("save custom snapshot: %v", errSave)
	}
	if _, errPersistedCustom := persistent.Get(ctx, customSnapshot.ProviderInstanceID); errPersistedCustom != nil {
		t.Fatalf("get persisted custom snapshot: %v", errPersistedCustom)
	}
	page, errChanges := store.ListChanges(ctx, 0, 10)
	if errChanges != nil {
		t.Fatalf("list runtime catalog changes: %v", errChanges)
	}
	if len(page.Changes) != 2 {
		t.Fatalf("runtime catalog changes = %d, want 2", len(page.Changes))
	}
}

// TestStoreCustomReadDoesNotPublishChange verifies durable reads cannot create synthetic runtime catalog mutations.
// TestStoreCustomReadDoesNotPublishChange 验证持久化读取不会创建虚假的运行时目录变更。
func TestStoreCustomReadDoesNotPublishChange(t *testing.T) {
	ctx := context.Background()
	persistent := catalog.NewMemoryStore()
	observedAt := time.Date(2026, 7, 24, 7, 40, 0, 0, time.UTC)
	snapshot := catalog.Snapshot{ProviderInstanceID: "pvi_custom", Revision: 1, ObservedAt: observedAt}
	if errSave := persistent.Save(ctx, snapshot); errSave != nil {
		t.Fatalf("seed durable custom snapshot: %v", errSave)
	}
	store, errStore := New(testOwnershipFixture(), persistent)
	if errStore != nil {
		t.Fatalf("New() error = %v", errStore)
	}
	if _, errGet := store.Get(ctx, snapshot.ProviderInstanceID); errGet != nil {
		t.Fatalf("get durable custom snapshot: %v", errGet)
	}
	page, errChanges := store.ListChanges(ctx, 0, 10)
	if errChanges != nil {
		t.Fatalf("list runtime changes after custom read: %v", errChanges)
	}
	if len(page.Changes) != 0 || page.CurrentRevision != 0 {
		t.Fatalf("custom read published runtime changes: %#v", page)
	}
}

// TestPurgePersistedSystemCatalogsPreservesCustomCatalogs verifies legacy cleanup never removes user-owned model data.
// TestPurgePersistedSystemCatalogsPreservesCustomCatalogs 验证历史清理绝不会删除用户拥有的模型数据。
func TestPurgePersistedSystemCatalogsPreservesCustomCatalogs(t *testing.T) {
	ctx := context.Background()
	ownership := testOwnershipFixture()
	persistent := &purgeFixture{MemoryStore: catalog.NewMemoryStore()}
	observedAt := time.Date(2026, 7, 24, 7, 45, 0, 0, time.UTC)
	for _, providerInstanceID := range []string{"pvi_system", "pvi_custom"} {
		if errSave := persistent.Save(ctx, catalog.Snapshot{ProviderInstanceID: providerInstanceID, Revision: 1, ObservedAt: observedAt}); errSave != nil {
			t.Fatalf("seed snapshot %s: %v", providerInstanceID, errSave)
		}
	}
	purged, errPurge := PurgePersistedSystemCatalogs(ctx, ownership, persistent)
	if errPurge != nil || purged != 1 {
		t.Fatalf("PurgePersistedSystemCatalogs() purged=%d error=%v", purged, errPurge)
	}
	if len(persistent.providerInstanceIDs) != 1 || persistent.providerInstanceIDs[0] != "pvi_system" {
		t.Fatalf("purge IDs = %#v", persistent.providerInstanceIDs)
	}
	if _, errSystem := persistent.Get(ctx, "pvi_system"); !errors.Is(errSystem, catalog.ErrSnapshotNotFound) {
		t.Fatalf("system snapshot remains: %v", errSystem)
	}
	if _, errCustom := persistent.Get(ctx, "pvi_custom"); errCustom != nil {
		t.Fatalf("custom snapshot was removed: %v", errCustom)
	}
}

// testOwnershipFixture builds one system and one custom provider ownership graph.
// testOwnershipFixture 构建一个系统与一个自定义供应商所有权图。
func testOwnershipFixture() ownershipFixture {
	return ownershipFixture{
		instances: map[string]providerconfig.ProviderInstance{
			"pvi_system": {ID: "pvi_system", DefinitionID: "system_test"},
			"pvi_custom": {ID: "pvi_custom", DefinitionID: "custom_test"},
		},
		definitions: map[string]providerconfig.ProviderDefinition{
			"system_test": {ID: "system_test", Kind: providerconfig.DefinitionKindSystem},
			"custom_test": {ID: "custom_test", Kind: providerconfig.DefinitionKindCustom},
		},
	}
}
