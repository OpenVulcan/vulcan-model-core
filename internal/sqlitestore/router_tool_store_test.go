package sqlitestore

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/routertool"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestRouterToolStorePersistsRevisionAndSelectionOrder verifies schema migration, round-trip, and optimistic updates.
// TestRouterToolStorePersistsRevisionAndSelectionOrder 验证 Schema 迁移、往返读取与乐观更新。
func TestRouterToolStorePersistsRevisionAndSelectionOrder(t *testing.T) {
	ctx := context.Background()
	database, errOpen := Open(ctx, filepath.Join(t.TempDir(), "router-tools.db"))
	if errOpen != nil {
		t.Fatalf("Open() error = %v", errOpen)
	}
	t.Cleanup(func() { _ = database.Close() })
	if _, errInstance := database.sql.ExecContext(ctx, `INSERT INTO provider_instances(id, definition_id, handle, status, revision, payload) VALUES (?, ?, ?, ?, ?, ?)`, "pvi_router_backend", "system_tavily", "tavily", "ready", 1, []byte(`{}`)); errInstance != nil {
		t.Fatalf("insert provider instance fixture: %v", errInstance)
	}
	store, errStore := NewRouterToolStore(database)
	if errStore != nil {
		t.Fatalf("NewRouterToolStore() error = %v", errStore)
	}
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	search := sqliteRouterToolBinding("rtb_search", vcp.StandardModelToolWebSearch, 2, now)
	extract := sqliteRouterToolBinding("rtb_extract", vcp.StandardModelToolWebExtractor, 1, now)
	if errSave := store.Save(ctx, search); errSave != nil {
		t.Fatalf("Save(search) error = %v", errSave)
	}
	if errSave := store.Save(ctx, extract); errSave != nil {
		t.Fatalf("Save(extract) error = %v", errSave)
	}
	values, errList := store.List(ctx)
	if errList != nil || len(values) != 2 || values[0].ID != extract.ID || values[1].ID != search.ID {
		t.Fatalf("List() = %#v, error = %v", values, errList)
	}
	search.Revision = 2
	search.Priority = 0
	search.UpdatedAt = now.Add(time.Minute)
	if errSave := store.Save(ctx, search); errSave != nil {
		t.Fatalf("Save(update) error = %v", errSave)
	}
	search.Revision = 3
	search.CreatedAt = now.Add(time.Second)
	search.UpdatedAt = now.Add(2 * time.Minute)
	if errSave := store.Save(ctx, search); !errors.Is(errSave, routertool.ErrInvalidBinding) {
		t.Fatalf("Save(mutated creation time) error = %v", errSave)
	}
	search.CreatedAt = now
	search.Revision = 4
	if errSave := store.Save(ctx, search); !errors.Is(errSave, routertool.ErrInvalidBinding) {
		t.Fatalf("Save(conflict) error = %v", errSave)
	}
	if errDelete := store.Delete(ctx, extract.ID); errDelete != nil {
		t.Fatalf("Delete() error = %v", errDelete)
	}
	if _, errGet := store.Get(ctx, extract.ID); !errors.Is(errGet, routertool.ErrBindingNotFound) {
		t.Fatalf("Get(deleted) error = %v", errGet)
	}
}

// TestRouterToolStoreAllowsOnlyOneConcurrentRevisionWinner verifies database-level optimistic locking rejects sibling replacements.
// TestRouterToolStoreAllowsOnlyOneConcurrentRevisionWinner 验证数据库级乐观锁会拒绝同级并发替换。
func TestRouterToolStoreAllowsOnlyOneConcurrentRevisionWinner(t *testing.T) {
	ctx := context.Background()
	database, errOpen := Open(ctx, filepath.Join(t.TempDir(), "router-tools-concurrent.db"))
	if errOpen != nil {
		t.Fatalf("open database: %v", errOpen)
	}
	t.Cleanup(func() { _ = database.Close() })
	if _, errInstance := database.sql.ExecContext(ctx, `INSERT INTO provider_instances(id, definition_id, handle, status, revision, payload) VALUES (?, ?, ?, ?, ?, ?)`, "pvi_router_backend", "system_tavily", "tavily", "ready", 1, []byte(`{}`)); errInstance != nil {
		t.Fatalf("insert provider instance fixture: %v", errInstance)
	}
	store, errStore := NewRouterToolStore(database)
	if errStore != nil {
		t.Fatalf("create Router tool store: %v", errStore)
	}
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	original := sqliteRouterToolBinding("rtb_concurrent", vcp.StandardModelToolWebSearch, 0, now)
	if errSave := store.Save(ctx, original); errSave != nil {
		t.Fatalf("save original binding: %v", errSave)
	}
	const contenders = 8
	var winners atomic.Int32
	var wait sync.WaitGroup
	wait.Add(contenders)
	for priority := range contenders {
		go func() {
			defer wait.Done()
			replacement := original
			replacement.Revision = 2
			replacement.Priority = priority
			replacement.UpdatedAt = now.Add(time.Minute)
			if errSave := store.Save(ctx, replacement); errSave == nil {
				winners.Add(1)
			}
		}()
	}
	wait.Wait()
	if winners.Load() != 1 {
		t.Fatalf("concurrent revision winners = %d, want 1", winners.Load())
	}
	loaded, errGet := store.Get(ctx, original.ID)
	if errGet != nil || loaded.Revision != 2 {
		t.Fatalf("load winning revision = %+v, error = %v", loaded, errGet)
	}
}

// TestRouterToolStoreRoundTripsExtensionModelTarget verifies the indexed tool identifier does not erase the model-backed family.
// TestRouterToolStoreRoundTripsExtensionModelTarget 校验索引工具标识不会抹除由模型支持的绑定类别。
func TestRouterToolStoreRoundTripsExtensionModelTarget(t *testing.T) {
	ctx := context.Background()
	database, errOpen := Open(ctx, filepath.Join(t.TempDir(), "router-extension.db"))
	if errOpen != nil {
		t.Fatalf("open database: %v", errOpen)
	}
	t.Cleanup(func() { _ = database.Close() })
	if _, errInstance := database.sql.ExecContext(ctx, `INSERT INTO provider_instances(id, definition_id, handle, status, revision, payload) VALUES (?, ?, ?, ?, ?, ?)`, "pvi_image_backend", "system_minimax", "minimax", "ready", 1, []byte(`{}`)); errInstance != nil {
		t.Fatalf("insert provider instance fixture: %v", errInstance)
	}
	store, errStore := NewRouterToolStore(database)
	if errStore != nil {
		t.Fatalf("create Router tool store: %v", errStore)
	}
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	binding := routertool.Binding{
		ID:                  "rtb_image_generation",
		Extension:           vcp.RouterExtensionImageGeneration,
		ProviderInstanceID:  "pvi_image_backend",
		ProviderModelID:     "model_image",
		OfferingID:          "offering_image",
		ExecutionProfileID:  "profile_image",
		Enabled:             true,
		TimeoutMilliseconds: 30_000,
		MaximumCalls:        2,
		MaximumResultBytes:  64 * 1024,
		SafetyPolicy:        routertool.SafetyPublicHTTPSOnly,
		Revision:            1,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	if errSave := store.Save(ctx, binding); errSave != nil {
		t.Fatalf("save extension binding: %v", errSave)
	}
	loaded, errGet := store.Get(ctx, binding.ID)
	if errGet != nil {
		t.Fatalf("load extension binding: %v", errGet)
	}
	if loaded.Extension != binding.Extension || loaded.Kind != "" || loaded.ProviderModelID != binding.ProviderModelID || loaded.OfferingID != binding.OfferingID || loaded.ProviderServiceID != "" || loaded.ServiceOfferingID != "" {
		t.Fatalf("loaded extension binding = %+v", loaded)
	}
}

// TestRouterToolMigration16PreservesStandardBindings verifies the table rebuild keeps every version-15 policy row.
// TestRouterToolMigration16PreservesStandardBindings 校验表重建会保留每一条版本 15 策略记录。
func TestRouterToolMigration16PreservesStandardBindings(t *testing.T) {
	ctx := context.Background()
	databasePath := filepath.Join(t.TempDir(), "router-migration.db")
	database, errOpen := Open(ctx, databasePath)
	if errOpen != nil {
		t.Fatalf("open current database: %v", errOpen)
	}
	if _, errInstance := database.sql.ExecContext(ctx, `INSERT INTO provider_instances(id, definition_id, handle, status, revision, payload) VALUES (?, ?, ?, ?, ?, ?)`, "pvi_migration_backend", "system_tavily", "tavily-migration", "ready", 1, []byte(`{}`)); errInstance != nil {
		t.Fatalf("insert migration provider instance: %v", errInstance)
	}
	store, errStore := NewRouterToolStore(database)
	if errStore != nil {
		t.Fatalf("create current Router tool store: %v", errStore)
	}
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	binding := sqliteRouterToolBinding("rtb_preserved", vcp.StandardModelToolWebSearch, 0, now)
	binding.ProviderInstanceID = "pvi_migration_backend"
	if errSave := store.Save(ctx, binding); errSave != nil {
		t.Fatalf("save standard binding before migration replay: %v", errSave)
	}
	// downgradeStatements reconstruct the exact version-15 table so reopening must apply migration 16.
	// downgradeStatements 重建精确的版本 15 表，使重新打开数据库时必须应用迁移 16。
	downgradeStatements := []string{
		`ALTER TABLE router_tool_bindings RENAME TO router_tool_bindings_v16`,
		`DROP INDEX router_tool_bindings_selection_idx`,
		`DROP INDEX router_tool_bindings_instance_idx`,
		`CREATE TABLE router_tool_bindings (
			id TEXT PRIMARY KEY,
			kind TEXT NOT NULL CHECK (kind IN ('web_search', 'web_extractor')),
			provider_instance_id TEXT NOT NULL REFERENCES provider_instances(id) ON DELETE CASCADE,
			priority INTEGER NOT NULL CHECK (priority >= 0),
			enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
			revision INTEGER NOT NULL CHECK (revision > 0),
			payload BLOB NOT NULL
		)`,
		`INSERT INTO router_tool_bindings(id, kind, provider_instance_id, priority, enabled, revision, payload)
		 SELECT id, kind, provider_instance_id, priority, enabled, revision, payload FROM router_tool_bindings_v16`,
		`DROP TABLE router_tool_bindings_v16`,
		`CREATE INDEX router_tool_bindings_selection_idx ON router_tool_bindings(kind, enabled, priority, id)`,
		`CREATE INDEX router_tool_bindings_instance_idx ON router_tool_bindings(provider_instance_id, id)`,
		`DELETE FROM schema_migrations WHERE version = 16`,
	}
	for _, statement := range downgradeStatements {
		if _, errExec := database.sql.ExecContext(ctx, statement); errExec != nil {
			t.Fatalf("reconstruct version-15 schema: %v", errExec)
		}
	}
	if errClose := database.Close(); errClose != nil {
		t.Fatalf("close version-15 database: %v", errClose)
	}
	migrated, errReopen := Open(ctx, databasePath)
	if errReopen != nil {
		t.Fatalf("reopen and migrate database: %v", errReopen)
	}
	t.Cleanup(func() { _ = migrated.Close() })
	migratedStore, errMigratedStore := NewRouterToolStore(migrated)
	if errMigratedStore != nil {
		t.Fatalf("create migrated Router tool store: %v", errMigratedStore)
	}
	loaded, errGet := migratedStore.Get(ctx, binding.ID)
	if errGet != nil || loaded.Kind != binding.Kind || loaded.ProviderInstanceID != binding.ProviderInstanceID || loaded.Revision != binding.Revision {
		t.Fatalf("preserved binding = %+v, error = %v", loaded, errGet)
	}
}

// sqliteRouterToolBinding creates one complete persisted test binding.
// sqliteRouterToolBinding 创建一个完整持久化测试绑定。
func sqliteRouterToolBinding(id string, kind vcp.StandardModelToolKind, priority int, now time.Time) routertool.Binding {
	return routertool.Binding{
		ID: id, Kind: kind, ProviderInstanceID: "pvi_router_backend",
		ProviderServiceID: "service_backend", ServiceOfferingID: "offering_backend",
		ExecutionProfileID: "profile_backend", Priority: priority, Enabled: true,
		TimeoutMilliseconds: 30_000, MaximumCalls: 3, MaximumResults: 5, MaximumURLs: 5,
		MaximumResultBytes: 64 * 1024, SafetyPolicy: routertool.SafetyPublicHTTPSOnly,
		Revision: 1, CreatedAt: now, UpdatedAt: now,
	}
}
