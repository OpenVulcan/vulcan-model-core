package sqlitestore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/routingstate"
)

// RoutingStateStore persists global routing settings and model-specific account state.
// RoutingStateStore 持久化全局路由设置与模型专属账号状态。
type RoutingStateStore struct {
	// database owns the migrated SQLite pool.
	// database 拥有已迁移 SQLite 连接池。
	database *Database
}

// NewRoutingStateStore creates a repository over schema version seven or newer.
// NewRoutingStateStore 基于第七版或更新 Schema 创建仓库。
func NewRoutingStateStore(database *Database) (*RoutingStateStore, error) {
	if database == nil || database.sql == nil {
		return nil, errors.New("sqlite database is required")
	}
	return &RoutingStateStore{database: database}, nil
}

// GetSettings returns the singleton Router settings row.
// GetSettings 返回单例 Router 设置记录。
func (s *RoutingStateStore) GetSettings(ctx context.Context) (routingstate.Settings, error) {
	var strategy string
	var revision uint64
	var updatedAtText string
	if errScan := s.database.sql.QueryRowContext(ctx, `SELECT default_routing_strategy, revision, updated_at FROM router_settings WHERE id = 1`).Scan(&strategy, &revision, &updatedAtText); errScan != nil {
		if errors.Is(errScan, sql.ErrNoRows) {
			return routingstate.Settings{}, routingstate.ErrNotFound
		}
		return routingstate.Settings{}, fmt.Errorf("read router settings: %w", errScan)
	}
	updatedAt, errTime := parseSQLiteTime(updatedAtText)
	if errTime != nil {
		return routingstate.Settings{}, fmt.Errorf("parse router settings time: %w", errTime)
	}
	return routingstate.Settings{DefaultRoutingStrategy: providerconfig.RoutingStrategy(strategy), Revision: revision, UpdatedAt: updatedAt}, nil
}

// SaveSettings persists a strictly newer settings revision.
// SaveSettings 持久化严格更新的设置修订号。
func (s *RoutingStateStore) SaveSettings(ctx context.Context, settings routingstate.Settings) error {
	if errValidate := settings.Validate(); errValidate != nil {
		return errValidate
	}
	result, errExec := s.database.sql.ExecContext(ctx, `UPDATE router_settings SET default_routing_strategy = ?, revision = ?, updated_at = ? WHERE id = 1 AND revision < ?`, settings.DefaultRoutingStrategy, settings.Revision, settings.UpdatedAt.UTC().Format(time.RFC3339Nano), settings.Revision)
	if errExec != nil {
		return fmt.Errorf("save router settings: %w", errExec)
	}
	rows, errRows := result.RowsAffected()
	if errRows != nil {
		return fmt.Errorf("read router settings result: %w", errRows)
	}
	if rows != 1 {
		return routingstate.ErrRevisionConflict
	}
	return nil
}

// GetCredentialModelState returns one exact persisted runtime state.
// GetCredentialModelState 返回一个精确持久化运行状态。
func (s *RoutingStateStore) GetCredentialModelState(ctx context.Context, instanceID string, credentialID string, modelID string) (routingstate.CredentialModelState, error) {
	var payload []byte
	errQuery := s.database.sql.QueryRowContext(ctx, `SELECT payload FROM credential_model_states WHERE provider_instance_id = ? AND credential_id = ? AND provider_model_id = ?`, instanceID, credentialID, modelID).Scan(&payload)
	if errors.Is(errQuery, sql.ErrNoRows) {
		return routingstate.CredentialModelState{}, routingstate.ErrNotFound
	}
	if errQuery != nil {
		return routingstate.CredentialModelState{}, fmt.Errorf("read credential model state: %w", errQuery)
	}
	return decodeCredentialModelState(payload)
}

// ListCredentialModelStates returns stable ordered states for one provider instance.
// ListCredentialModelStates 返回一个供应商实例的稳定排序状态。
func (s *RoutingStateStore) ListCredentialModelStates(ctx context.Context, instanceID string) ([]routingstate.CredentialModelState, error) {
	rows, errQuery := s.database.sql.QueryContext(ctx, `SELECT payload FROM credential_model_states WHERE provider_instance_id = ? ORDER BY credential_id, provider_model_id`, instanceID)
	if errQuery != nil {
		return nil, fmt.Errorf("list credential model states: %w", errQuery)
	}
	defer rows.Close()
	states := make([]routingstate.CredentialModelState, 0)
	for rows.Next() {
		var payload []byte
		if errScan := rows.Scan(&payload); errScan != nil {
			return nil, fmt.Errorf("scan credential model state: %w", errScan)
		}
		state, errDecode := decodeCredentialModelState(payload)
		if errDecode != nil {
			return nil, errDecode
		}
		states = append(states, state)
	}
	if errRows := rows.Err(); errRows != nil {
		return nil, fmt.Errorf("iterate credential model states: %w", errRows)
	}
	return states, nil
}

// SaveCredentialModelState persists a strictly newer exact state.
// SaveCredentialModelState 持久化严格更新的精确状态。
func (s *RoutingStateStore) SaveCredentialModelState(ctx context.Context, state routingstate.CredentialModelState) error {
	if errValidate := state.Validate(); errValidate != nil {
		return errValidate
	}
	payload, errMarshal := json.Marshal(state)
	if errMarshal != nil {
		return fmt.Errorf("encode credential model state: %w", errMarshal)
	}
	result, errExec := s.database.sql.ExecContext(ctx, `
		INSERT INTO credential_model_states(provider_instance_id, credential_id, provider_model_id, status, revision, payload)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(provider_instance_id, credential_id, provider_model_id) DO UPDATE SET status = excluded.status, revision = excluded.revision, payload = excluded.payload
		WHERE excluded.revision > credential_model_states.revision`, state.ProviderInstanceID, state.CredentialID, state.ProviderModelID, state.Status, state.Revision, payload)
	if errExec != nil {
		return fmt.Errorf("save credential model state: %w", errExec)
	}
	rows, errRows := result.RowsAffected()
	if errRows != nil {
		return fmt.Errorf("read credential model state result: %w", errRows)
	}
	if rows != 1 {
		return routingstate.ErrRevisionConflict
	}
	return nil
}

// GetRuntimeScopeState returns one exact persisted non-model state.
// GetRuntimeScopeState 返回一个精确持久化非模型状态。
func (s *RoutingStateStore) GetRuntimeScopeState(ctx context.Context, instanceID string, scope routingstate.RuntimeScope, scopeID string) (routingstate.RuntimeScopeState, error) {
	var payload []byte
	errQuery := s.database.sql.QueryRowContext(ctx, `SELECT payload FROM runtime_scope_states WHERE provider_instance_id = ? AND scope = ? AND scope_id = ?`, instanceID, scope, scopeID).Scan(&payload)
	if errors.Is(errQuery, sql.ErrNoRows) {
		return routingstate.RuntimeScopeState{}, routingstate.ErrNotFound
	}
	if errQuery != nil {
		return routingstate.RuntimeScopeState{}, fmt.Errorf("read runtime scope state: %w", errQuery)
	}
	return decodeRuntimeScopeState(payload)
}

// ListRuntimeScopeStates returns stable ordered non-model states for one provider instance.
// ListRuntimeScopeStates 返回一个供应商实例的稳定排序非模型状态。
func (s *RoutingStateStore) ListRuntimeScopeStates(ctx context.Context, instanceID string) ([]routingstate.RuntimeScopeState, error) {
	rows, errQuery := s.database.sql.QueryContext(ctx, `SELECT payload FROM runtime_scope_states WHERE provider_instance_id = ? ORDER BY scope, scope_id`, instanceID)
	if errQuery != nil {
		return nil, fmt.Errorf("list runtime scope states: %w", errQuery)
	}
	defer rows.Close()
	states := make([]routingstate.RuntimeScopeState, 0)
	for rows.Next() {
		var payload []byte
		if errScan := rows.Scan(&payload); errScan != nil {
			return nil, fmt.Errorf("scan runtime scope state: %w", errScan)
		}
		state, errDecode := decodeRuntimeScopeState(payload)
		if errDecode != nil {
			return nil, errDecode
		}
		states = append(states, state)
	}
	if errRows := rows.Err(); errRows != nil {
		return nil, fmt.Errorf("iterate runtime scope states: %w", errRows)
	}
	return states, nil
}

// SaveRuntimeScopeState persists a strictly newer exact non-model state.
// SaveRuntimeScopeState 持久化严格更新的精确非模型状态。
func (s *RoutingStateStore) SaveRuntimeScopeState(ctx context.Context, state routingstate.RuntimeScopeState) error {
	if errValidate := state.Validate(); errValidate != nil {
		return errValidate
	}
	payload, errMarshal := json.Marshal(state)
	if errMarshal != nil {
		return fmt.Errorf("encode runtime scope state: %w", errMarshal)
	}
	result, errExec := s.database.sql.ExecContext(ctx, `
		INSERT INTO runtime_scope_states(provider_instance_id, scope, scope_id, status, revision, payload)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(provider_instance_id, scope, scope_id) DO UPDATE SET status = excluded.status, revision = excluded.revision, payload = excluded.payload
		WHERE excluded.revision > runtime_scope_states.revision`, state.ProviderInstanceID, state.Scope, state.ScopeID, state.Status, state.Revision, payload)
	if errExec != nil {
		return fmt.Errorf("save runtime scope state: %w", errExec)
	}
	rows, errRows := result.RowsAffected()
	if errRows != nil {
		return fmt.Errorf("read runtime scope state result: %w", errRows)
	}
	if rows != 1 {
		return routingstate.ErrRevisionConflict
	}
	return nil
}

// decodeCredentialModelState validates one persisted payload before returning it.
// decodeCredentialModelState 在返回前校验一个持久化 Payload。
func decodeCredentialModelState(payload []byte) (routingstate.CredentialModelState, error) {
	var state routingstate.CredentialModelState
	if errDecode := json.Unmarshal(payload, &state); errDecode != nil {
		return routingstate.CredentialModelState{}, fmt.Errorf("decode credential model state: %w", errDecode)
	}
	if errValidate := state.Validate(); errValidate != nil {
		return routingstate.CredentialModelState{}, fmt.Errorf("validate credential model state: %w", errValidate)
	}
	return state, nil
}

// decodeRuntimeScopeState validates one persisted non-model payload before returning it.
// decodeRuntimeScopeState 在返回前校验一个持久化非模型 Payload。
func decodeRuntimeScopeState(payload []byte) (routingstate.RuntimeScopeState, error) {
	var state routingstate.RuntimeScopeState
	if errDecode := json.Unmarshal(payload, &state); errDecode != nil {
		return routingstate.RuntimeScopeState{}, fmt.Errorf("decode runtime scope state: %w", errDecode)
	}
	if errValidate := state.Validate(); errValidate != nil {
		return routingstate.RuntimeScopeState{}, fmt.Errorf("validate runtime scope state: %w", errValidate)
	}
	return state, nil
}

// parseSQLiteTime accepts RFC3339 writes and SQLite's initial CURRENT_TIMESTAMP format.
// parseSQLiteTime 接受 RFC3339 写入值与 SQLite 初始 CURRENT_TIMESTAMP 格式。
func parseSQLiteTime(value string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05"} {
		parsed, errParse := time.Parse(layout, value)
		if errParse == nil {
			return parsed.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unsupported SQLite timestamp %q", value)
}
