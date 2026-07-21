package sqlitestore

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/routingstate"
)

// TestRoutingStateStorePersistsSettingsAndCredentialModelState verifies schema-nine durability and revision protection.
// TestRoutingStateStorePersistsSettingsAndCredentialModelState 验证第九版 Schema 的持久性与修订保护。
func TestRoutingStateStorePersistsSettingsAndCredentialModelState(t *testing.T) {
	ctx := context.Background()
	databasePath := filepath.Join(t.TempDir(), "routing-state.db")
	database, errOpen := Open(ctx, databasePath)
	if errOpen != nil {
		t.Fatalf("Open() error = %v", errOpen)
	}
	store, errStore := NewRoutingStateStore(database)
	if errStore != nil {
		t.Fatalf("NewRoutingStateStore() error = %v", errStore)
	}
	initial, errInitial := store.GetSettings(ctx)
	if errInitial != nil || initial.DefaultRoutingStrategy != providerconfig.RoutingRoundRobin || initial.Revision != 1 {
		t.Fatalf("initial settings = %#v, error = %v", initial, errInitial)
	}
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	updated := routingstate.Settings{DefaultRoutingStrategy: providerconfig.RoutingFillFirst, Revision: 2, UpdatedAt: now}
	if errSave := store.SaveSettings(ctx, updated); errSave != nil {
		t.Fatalf("SaveSettings() error = %v", errSave)
	}
	if errStale := store.SaveSettings(ctx, updated); !errors.Is(errStale, routingstate.ErrRevisionConflict) {
		t.Fatalf("stale SaveSettings() error = %v", errStale)
	}
	insertRoutingStateOwners(t, database)
	coolingUntil := now.Add(5 * time.Minute)
	state := routingstate.CredentialModelState{ProviderInstanceID: "pvi_runtime", CredentialID: "cred_runtime", ProviderModelID: "model_k3", Status: routingstate.ModelCooling, FailureCategory: "quota", RuleID: "kimi_quota", QuotaExhausted: true, CoolingUntil: &coolingUntil, BackoffLevel: 2, LastFailureAt: &now, Revision: 1}
	if errState := store.SaveCredentialModelState(ctx, state); errState != nil {
		t.Fatalf("SaveCredentialModelState() error = %v", errState)
	}
	scopeState := routingstate.RuntimeScopeState{ProviderInstanceID: "pvi_runtime", Scope: routingstate.ScopeEndpoint, ScopeID: "endpoint_runtime", Status: routingstate.ModelCooling, FailureCategory: "transient", RuleID: "http_503", CoolingUntil: &coolingUntil, LastFailureAt: &now, Revision: 1}
	if errScope := store.SaveRuntimeScopeState(ctx, scopeState); errScope != nil {
		t.Fatalf("SaveRuntimeScopeState() error = %v", errScope)
	}
	if errClose := database.Close(); errClose != nil {
		t.Fatalf("Close() error = %v", errClose)
	}
	reopened, errReopen := Open(ctx, databasePath)
	if errReopen != nil {
		t.Fatalf("reopen database error = %v", errReopen)
	}
	defer reopened.Close()
	reopenedStore, _ := NewRoutingStateStore(reopened)
	restoredSettings, errSettings := reopenedStore.GetSettings(ctx)
	restoredState, errState := reopenedStore.GetCredentialModelState(ctx, state.ProviderInstanceID, state.CredentialID, state.ProviderModelID)
	restoredScope, errScope := reopenedStore.GetRuntimeScopeState(ctx, scopeState.ProviderInstanceID, scopeState.Scope, scopeState.ScopeID)
	if errSettings != nil || restoredSettings.DefaultRoutingStrategy != providerconfig.RoutingFillFirst || restoredSettings.Revision != 2 {
		t.Fatalf("restored settings = %#v, error = %v", restoredSettings, errSettings)
	}
	if errState != nil || restoredState.Status != routingstate.ModelCooling || restoredState.BackoffLevel != 2 || restoredState.CoolingUntil == nil || !restoredState.CoolingUntil.Equal(coolingUntil) {
		t.Fatalf("restored state = %#v, error = %v", restoredState, errState)
	}
	if errScope != nil || restoredScope.Status != routingstate.ModelCooling || restoredScope.CoolingUntil == nil || !restoredScope.CoolingUntil.Equal(coolingUntil) {
		t.Fatalf("restored scope state = %#v, error = %v", restoredScope, errScope)
	}
}

// insertRoutingStateOwners creates the exact foreign-key owners required by the focused repository test.
// insertRoutingStateOwners 创建聚焦仓库测试所需的精确外键所有者。
func insertRoutingStateOwners(t *testing.T, database *Database) {
	t.Helper()
	if _, errInsert := database.sql.Exec(`INSERT INTO provider_instances(id, definition_id, handle, status, revision, payload) VALUES ('pvi_runtime', 'system_runtime', 'runtime', 'ready', 1, '{}')`); errInsert != nil {
		t.Fatalf("insert provider instance owner: %v", errInsert)
	}
	if _, errInsert := database.sql.Exec(`INSERT INTO provider_credentials(id, provider_instance_id, auth_method_id, principal_key, fingerprint, status, revision, payload) VALUES ('cred_runtime', 'pvi_runtime', 'api_key', '', 'runtime-fingerprint', 'active', 1, '{}')`); errInsert != nil {
		t.Fatalf("insert credential owner: %v", errInsert)
	}
}
