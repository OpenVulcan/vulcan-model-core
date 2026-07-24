package sqlitestore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/OpenVulcan/vulcan-model-core/internal/routertool"
)

// RouterToolStore persists explicit Router model-tool bindings.
// RouterToolStore 持久化显式 Router 模型工具绑定。
type RouterToolStore struct {
	// database owns the migrated SQLite connection pool.
	// database 拥有已迁移 SQLite 连接池。
	database *Database
}

// NewRouterToolStore creates a SQLite-backed Router tool binding repository.
// NewRouterToolStore 创建 SQLite 支持的 Router 工具绑定仓库。
func NewRouterToolStore(database *Database) (*RouterToolStore, error) {
	if database == nil || database.sql == nil {
		return nil, errors.New("sqlite database is required")
	}
	return &RouterToolStore{database: database}, nil
}

// Save validates and atomically creates or advances one binding revision.
// Save 校验并原子创建或推进一个绑定修订。
func (s *RouterToolStore) Save(ctx context.Context, binding routertool.Binding) error {
	if errValidate := binding.Validate(); errValidate != nil {
		return errValidate
	}
	payload, errMarshal := json.Marshal(binding)
	if errMarshal != nil {
		return fmt.Errorf("encode router tool binding: %w", errMarshal)
	}
	transaction, errBegin := s.database.sql.BeginTx(ctx, nil)
	if errBegin != nil {
		return fmt.Errorf("begin router tool binding save: %w", errBegin)
	}
	defer func() {
		_ = transaction.Rollback()
	}()
	var currentRevision uint64
	var currentPayload []byte
	errCurrent := transaction.QueryRowContext(ctx, `SELECT revision, payload FROM router_tool_bindings WHERE id = ?`, binding.ID).Scan(&currentRevision, &currentPayload)
	exists := errCurrent == nil
	switch {
	case errors.Is(errCurrent, sql.ErrNoRows) && binding.Revision != 1:
		return fmt.Errorf("%w: new binding revision must be one", routertool.ErrInvalidBinding)
	case errCurrent == nil:
		current, errDecode := decodeRouterToolBinding(currentPayload)
		if errDecode != nil {
			return errDecode
		}
		if current.Revision != currentRevision {
			return fmt.Errorf("%w: indexed revision differs from payload", routertool.ErrInvalidBinding)
		}
		if errReplacement := binding.ValidateReplacement(current); errReplacement != nil {
			return errReplacement
		}
	case errCurrent != nil && !errors.Is(errCurrent, sql.ErrNoRows):
		return fmt.Errorf("read router tool binding revision: %w", errCurrent)
	}
	if !exists {
		if _, errInsert := transaction.ExecContext(ctx, `
			INSERT INTO router_tool_bindings(id, kind, provider_instance_id, priority, enabled, revision, payload)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`, binding.ID, binding.ToolID(), binding.ProviderInstanceID, binding.Priority, binding.Enabled, binding.Revision, payload); errInsert != nil {
			return fmt.Errorf("create router tool binding: %w", errInsert)
		}
	} else {
		result, errUpdate := transaction.ExecContext(ctx, `
			UPDATE router_tool_bindings
			SET kind = ?, provider_instance_id = ?, priority = ?, enabled = ?, revision = ?, payload = ?
			WHERE id = ? AND revision = ?
		`, binding.ToolID(), binding.ProviderInstanceID, binding.Priority, binding.Enabled, binding.Revision, payload, binding.ID, currentRevision)
		if errUpdate != nil {
			return fmt.Errorf("update router tool binding: %w", errUpdate)
		}
		affected, errAffected := result.RowsAffected()
		if errAffected != nil {
			return fmt.Errorf("read router tool binding update count: %w", errAffected)
		}
		if affected != 1 {
			return fmt.Errorf("%w: revision conflict", routertool.ErrInvalidBinding)
		}
	}
	if errCommit := transaction.Commit(); errCommit != nil {
		return fmt.Errorf("commit router tool binding: %w", errCommit)
	}
	return nil
}

// Get returns one decoded binding.
// Get 返回一个解码后的绑定。
func (s *RouterToolStore) Get(ctx context.Context, id string) (routertool.Binding, error) {
	var payload []byte
	if errQuery := s.database.sql.QueryRowContext(ctx, `SELECT payload FROM router_tool_bindings WHERE id = ?`, id).Scan(&payload); errQuery != nil {
		if errors.Is(errQuery, sql.ErrNoRows) {
			return routertool.Binding{}, fmt.Errorf("%w: %s", routertool.ErrBindingNotFound, id)
		}
		return routertool.Binding{}, fmt.Errorf("read router tool binding: %w", errQuery)
	}
	return decodeRouterToolBinding(payload)
}

// List returns all decoded bindings in deterministic runtime selection order.
// List 按确定性运行时选择顺序返回全部解码绑定。
func (s *RouterToolStore) List(ctx context.Context) ([]routertool.Binding, error) {
	rows, errQuery := s.database.sql.QueryContext(ctx, `SELECT payload FROM router_tool_bindings ORDER BY priority, id`)
	if errQuery != nil {
		return nil, fmt.Errorf("list router tool bindings: %w", errQuery)
	}
	defer rows.Close()
	values := make([]routertool.Binding, 0)
	for rows.Next() {
		var payload []byte
		if errScan := rows.Scan(&payload); errScan != nil {
			return nil, fmt.Errorf("scan router tool binding: %w", errScan)
		}
		binding, errDecode := decodeRouterToolBinding(payload)
		if errDecode != nil {
			return nil, errDecode
		}
		values = append(values, binding)
	}
	if errRows := rows.Err(); errRows != nil {
		return nil, fmt.Errorf("iterate router tool bindings: %w", errRows)
	}
	sort.Slice(values, func(left int, right int) bool {
		if values[left].Priority == values[right].Priority {
			return values[left].ID < values[right].ID
		}
		return values[left].Priority < values[right].Priority
	})
	return values, nil
}

// Delete removes one exact binding.
// Delete 删除一个精确绑定。
func (s *RouterToolStore) Delete(ctx context.Context, id string) error {
	result, errDelete := s.database.sql.ExecContext(ctx, `DELETE FROM router_tool_bindings WHERE id = ?`, id)
	if errDelete != nil {
		return fmt.Errorf("delete router tool binding: %w", errDelete)
	}
	affected, errAffected := result.RowsAffected()
	if errAffected != nil {
		return fmt.Errorf("read router tool binding delete count: %w", errAffected)
	}
	if affected == 0 {
		return fmt.Errorf("%w: %s", routertool.ErrBindingNotFound, id)
	}
	return nil
}

// decodeRouterToolBinding decodes and validates one persisted binding payload.
// decodeRouterToolBinding 解码并校验一个持久化绑定载荷。
func decodeRouterToolBinding(payload []byte) (routertool.Binding, error) {
	var binding routertool.Binding
	if errDecode := json.Unmarshal(payload, &binding); errDecode != nil {
		return routertool.Binding{}, fmt.Errorf("decode router tool binding: %w", errDecode)
	}
	if errValidate := binding.Validate(); errValidate != nil {
		return routertool.Binding{}, errValidate
	}
	return binding, nil
}
