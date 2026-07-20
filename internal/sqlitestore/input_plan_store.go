package sqlitestore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/OpenVulcan/vulcan-model-core/internal/inputplan"
)

// InputPlanStore persists immutable conditional media plans.
// InputPlanStore 持久化不可变条件媒体方案。
type InputPlanStore struct {
	// database owns the shared migrated SQLite connection pool.
	// database 管理共享且已迁移的 SQLite 连接池。
	database *Database
}

// NewInputPlanStore creates a SQLite-backed input-plan repository.
// NewInputPlanStore 创建一个由 SQLite 支持的输入方案仓库。
func NewInputPlanStore(database *Database) (*InputPlanStore, error) {
	if database == nil || database.sql == nil {
		return nil, errors.New("sqlite database is required")
	}
	return &InputPlanStore{database: database}, nil
}

// Save creates one validated immutable plan.
// Save 创建一个已校验不可变方案。
func (s *InputPlanStore) Save(ctx context.Context, plan inputplan.Plan) error {
	if errContext := validateContext(ctx); errContext != nil {
		return errContext
	}
	if errValidate := plan.Validate(); errValidate != nil {
		return errValidate
	}
	payload, errPayload := marshalPayload(plan)
	if errPayload != nil {
		return errPayload
	}
	targetPayload, errTargetPayload := marshalPayload(plan.Target)
	if errTargetPayload != nil {
		return errTargetPayload
	}
	if _, errExec := s.database.sql.ExecContext(ctx, `INSERT INTO input_plans(id, owner_api_key_id, expires_at, target_payload, payload) VALUES (?, ?, ?, ?, ?)`, plan.ID, plan.OwnerAPIKeyID, plan.ExpiresAt.UTC().Format(sqliteTimeLayout), targetPayload, payload); errExec != nil {
		return fmt.Errorf("%w: save immutable input plan", inputplan.ErrInvalidPlan)
	}
	return nil
}

// Get returns one validated plan with its private owner restored.
// Get 返回一个恢复私有所有者且经过校验的方案。
func (s *InputPlanStore) Get(ctx context.Context, identifier string) (inputplan.Plan, error) {
	if errContext := validateContext(ctx); errContext != nil {
		return inputplan.Plan{}, errContext
	}
	var ownerAPIKeyID string
	var targetPayload []byte
	var payload []byte
	errQuery := s.database.sql.QueryRowContext(ctx, `SELECT owner_api_key_id, target_payload, payload FROM input_plans WHERE id = ?`, identifier).Scan(&ownerAPIKeyID, &targetPayload, &payload)
	if errors.Is(errQuery, sql.ErrNoRows) {
		return inputplan.Plan{}, inputplan.ErrPlanNotFound
	}
	if errQuery != nil {
		return inputplan.Plan{}, fmt.Errorf("query input plan: %w", errQuery)
	}
	var plan inputplan.Plan
	if errDecode := unmarshalPayload(payload, &plan); errDecode != nil {
		return inputplan.Plan{}, errDecode
	}
	plan.OwnerAPIKeyID = ownerAPIKeyID
	if errDecode := unmarshalPayload(targetPayload, &plan.Target); errDecode != nil {
		return inputplan.Plan{}, errDecode
	}
	if errValidate := plan.Validate(); errValidate != nil {
		return inputplan.Plan{}, fmt.Errorf("validate persisted input plan: %w", errValidate)
	}
	return plan, nil
}
