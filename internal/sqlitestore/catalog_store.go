package sqlitestore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
)

// CatalogStore persists one atomic model and runtime snapshot per provider instance.
// CatalogStore 为每个供应商实例持久化一个原子模型与运行时快照。
type CatalogStore struct {
	// database owns the shared migrated SQLite connection pool.
	// database 管理共享且已经迁移的 SQLite 连接池。
	database *Database
}

// NewCatalogStore creates a SQLite-backed atomic catalog repository.
// NewCatalogStore 创建一个 SQLite 支持的原子目录 Repository。
func NewCatalogStore(database *Database) (*CatalogStore, error) {
	if database == nil || database.sql == nil {
		return nil, errors.New("sqlite database is required")
	}
	return &CatalogStore{database: database}, nil
}

// Save validates and atomically replaces one provider catalog with a newer revision.
// Save 校验并使用更高修订号原子替换一个供应商目录。
func (s *CatalogStore) Save(ctx context.Context, snapshot catalog.Snapshot) error {
	if err := validateContext(ctx); err != nil {
		return err
	}
	if err := snapshot.Validate(); err != nil {
		return err
	}
	if snapshot.Revision > math.MaxInt64 {
		return fmt.Errorf("%w: catalog revision exceeds SQLite integer range", catalog.ErrInvalidCatalog)
	}
	payload, errPayload := marshalPayload(snapshot)
	if errPayload != nil {
		return errPayload
	}
	result, errExec := s.database.sql.ExecContext(ctx, `
		INSERT INTO catalog_snapshots(provider_instance_id, revision, observed_at, payload) VALUES (?, ?, ?, ?)
		ON CONFLICT(provider_instance_id) DO UPDATE SET revision = excluded.revision,
		observed_at = excluded.observed_at, payload = excluded.payload
		WHERE excluded.revision > catalog_snapshots.revision`, snapshot.ProviderInstanceID, int64(snapshot.Revision), snapshot.ObservedAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"), payload)
	if errExec != nil {
		return fmt.Errorf("save provider catalog snapshot: %w", errExec)
	}
	rowsAffected, errRows := result.RowsAffected()
	if errRows != nil {
		return fmt.Errorf("read provider catalog write result: %w", errRows)
	}
	if rowsAffected != 1 {
		return fmt.Errorf("%w: catalog revision must increase", catalog.ErrInvalidCatalog)
	}
	return nil
}

// Delete removes one provider catalog snapshot.
// Delete 删除一个供应商目录快照。
func (s *CatalogStore) Delete(ctx context.Context, providerInstanceID string) error {
	if err := validateContext(ctx); err != nil {
		return err
	}
	result, errExec := s.database.sql.ExecContext(ctx, `DELETE FROM catalog_snapshots WHERE provider_instance_id = ?`, providerInstanceID)
	if errExec != nil {
		return fmt.Errorf("delete provider catalog snapshot: %w", errExec)
	}
	rowsAffected, errRows := result.RowsAffected()
	if errRows != nil {
		return fmt.Errorf("read provider catalog delete result: %w", errRows)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("%w: %s", catalog.ErrSnapshotNotFound, providerInstanceID)
	}
	return nil
}

// Get returns one validated mutation-safe provider catalog snapshot.
// Get 返回一个经过校验且防止外部修改的供应商目录快照。
func (s *CatalogStore) Get(ctx context.Context, providerInstanceID string) (catalog.Snapshot, error) {
	if err := validateContext(ctx); err != nil {
		return catalog.Snapshot{}, err
	}
	var payload []byte
	errQuery := s.database.sql.QueryRowContext(ctx, `SELECT payload FROM catalog_snapshots WHERE provider_instance_id = ?`, providerInstanceID).Scan(&payload)
	if errors.Is(errQuery, sql.ErrNoRows) {
		return catalog.Snapshot{}, fmt.Errorf("%w: %s", catalog.ErrSnapshotNotFound, providerInstanceID)
	}
	if errQuery != nil {
		return catalog.Snapshot{}, fmt.Errorf("query provider catalog snapshot: %w", errQuery)
	}
	var snapshot catalog.Snapshot
	if errDecode := unmarshalPayload(payload, &snapshot); errDecode != nil {
		return catalog.Snapshot{}, errDecode
	}
	if errValidate := snapshot.Validate(); errValidate != nil {
		return catalog.Snapshot{}, fmt.Errorf("validate persisted provider catalog snapshot: %w", errValidate)
	}
	return snapshot, nil
}
