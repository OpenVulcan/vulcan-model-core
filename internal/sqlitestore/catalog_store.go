package sqlitestore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

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
	transaction, errBegin := s.database.sql.BeginTx(ctx, nil)
	if errBegin != nil {
		return fmt.Errorf("begin provider catalog save: %w", errBegin)
	}
	defer func() { _ = transaction.Rollback() }()
	result, errExec := transaction.ExecContext(ctx, `
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
	if errChange := insertCatalogChange(ctx, transaction, catalog.ChangeFromSnapshot(snapshot)); errChange != nil {
		return errChange
	}
	if errCommit := transaction.Commit(); errCommit != nil {
		return fmt.Errorf("commit provider catalog save: %w", errCommit)
	}
	return nil
}

// Delete removes one provider catalog snapshot.
// Delete 删除一个供应商目录快照。
func (s *CatalogStore) Delete(ctx context.Context, providerInstanceID string) error {
	if err := validateContext(ctx); err != nil {
		return err
	}
	transaction, errBegin := s.database.sql.BeginTx(ctx, nil)
	if errBegin != nil {
		return fmt.Errorf("begin provider catalog delete: %w", errBegin)
	}
	defer func() { _ = transaction.Rollback() }()
	var providerRevision int64
	var observedAtEncoded string
	if errRead := transaction.QueryRowContext(ctx, `SELECT revision, observed_at FROM catalog_snapshots WHERE provider_instance_id = ?`, providerInstanceID).Scan(&providerRevision, &observedAtEncoded); errors.Is(errRead, sql.ErrNoRows) {
		return fmt.Errorf("%w: %s", catalog.ErrSnapshotNotFound, providerInstanceID)
	} else if errRead != nil {
		return fmt.Errorf("read provider catalog before deletion: %w", errRead)
	}
	observedAt, errObservedAt := time.Parse("2006-01-02T15:04:05.999999999Z07:00", observedAtEncoded)
	if errObservedAt != nil {
		return fmt.Errorf("decode provider catalog deletion metadata: %w", errObservedAt)
	}
	if providerRevision <= 0 {
		return errors.New("persisted provider catalog revision is invalid")
	}
	result, errExec := transaction.ExecContext(ctx, `DELETE FROM catalog_snapshots WHERE provider_instance_id = ?`, providerInstanceID)
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
	change := catalog.Change{ProviderInstanceID: providerInstanceID, ProviderRevision: uint64(providerRevision), Type: catalog.ChangeSnapshotDelete, ObservedAt: observedAt.UTC()}
	if errChange := insertCatalogChange(ctx, transaction, change); errChange != nil {
		return errChange
	}
	if errCommit := transaction.Commit(); errCommit != nil {
		return fmt.Errorf("commit provider catalog delete: %w", errCommit)
	}
	return nil
}

// Purge removes catalog snapshots and historical catalog-change rows for the exact provider instances without publishing runtime tombstones.
// Purge 删除精确供应商实例的目录快照与历史目录变更记录，且不发布运行时墓碑。
func (s *CatalogStore) Purge(ctx context.Context, providerInstanceIDs []string) (int, error) {
	if err := validateContext(ctx); err != nil {
		return 0, err
	}
	if len(providerInstanceIDs) == 0 {
		return 0, nil
	}
	transaction, errBegin := s.database.sql.BeginTx(ctx, nil)
	if errBegin != nil {
		return 0, fmt.Errorf("begin provider catalog purge: %w", errBegin)
	}
	defer func() { _ = transaction.Rollback() }()
	purgedSnapshots := 0
	for _, providerInstanceID := range providerInstanceIDs {
		if providerInstanceID == "" {
			return 0, errors.New("provider instance ID is required for catalog purge")
		}
		if _, errDeleteChanges := transaction.ExecContext(ctx, `DELETE FROM catalog_changes WHERE provider_instance_id = ?`, providerInstanceID); errDeleteChanges != nil {
			return 0, fmt.Errorf("purge provider catalog changes %s: %w", providerInstanceID, errDeleteChanges)
		}
		result, errDeleteSnapshot := transaction.ExecContext(ctx, `DELETE FROM catalog_snapshots WHERE provider_instance_id = ?`, providerInstanceID)
		if errDeleteSnapshot != nil {
			return 0, fmt.Errorf("purge provider catalog snapshot %s: %w", providerInstanceID, errDeleteSnapshot)
		}
		rowsAffected, errRows := result.RowsAffected()
		if errRows != nil {
			return 0, fmt.Errorf("read provider catalog purge result %s: %w", providerInstanceID, errRows)
		}
		purgedSnapshots += int(rowsAffected)
	}
	if errCommit := transaction.Commit(); errCommit != nil {
		return 0, fmt.Errorf("commit provider catalog purge: %w", errCommit)
	}
	return purgedSnapshots, nil
}

// ListChanges returns one globally ordered mutation-safe incremental catalog page.
// ListChanges 返回一个全局有序且防止外部修改的增量目录页。
func (s *CatalogStore) ListChanges(ctx context.Context, afterRevision uint64, limit int) (catalog.ChangePage, error) {
	if errContext := validateContext(ctx); errContext != nil {
		return catalog.ChangePage{}, errContext
	}
	if afterRevision > math.MaxInt64 || limit <= 0 || limit > 1000 {
		return catalog.ChangePage{}, fmt.Errorf("%w: catalog change cursor or limit is outside the allowed boundary", catalog.ErrInvalidCatalog)
	}
	var currentRevision int64
	if errCurrent := s.database.sql.QueryRowContext(ctx, `SELECT COALESCE(MAX(global_revision), 0) FROM catalog_changes`).Scan(&currentRevision); errCurrent != nil {
		return catalog.ChangePage{}, fmt.Errorf("read current catalog revision: %w", errCurrent)
	}
	rows, errQuery := s.database.sql.QueryContext(ctx, `SELECT global_revision, provider_instance_id, provider_revision, change_type, observed_at, source_revision, etag, refresh_status, tombstones_payload FROM catalog_changes WHERE global_revision > ? ORDER BY global_revision LIMIT ?`, int64(afterRevision), limit)
	if errQuery != nil {
		return catalog.ChangePage{}, fmt.Errorf("query catalog changes: %w", errQuery)
	}
	defer rows.Close()
	page := catalog.ChangePage{CurrentRevision: uint64(currentRevision), Changes: make([]catalog.Change, 0, limit)}
	for rows.Next() {
		var globalRevision int64
		var providerRevision int64
		var observedAtEncoded string
		var tombstonesPayload []byte
		var change catalog.Change
		if errScan := rows.Scan(&globalRevision, &change.ProviderInstanceID, &providerRevision, &change.Type, &observedAtEncoded, &change.SourceRevision, &change.ETag, &change.RefreshStatus, &tombstonesPayload); errScan != nil {
			return catalog.ChangePage{}, fmt.Errorf("scan catalog change: %w", errScan)
		}
		observedAt, errObservedAt := time.Parse("2006-01-02T15:04:05.999999999Z07:00", observedAtEncoded)
		if errObservedAt != nil || globalRevision <= 0 || providerRevision <= 0 {
			return catalog.ChangePage{}, errors.New("persisted catalog change metadata is invalid")
		}
		change.GlobalRevision = uint64(globalRevision)
		change.ProviderRevision = uint64(providerRevision)
		change.ObservedAt = observedAt.UTC()
		if errDecode := json.Unmarshal(tombstonesPayload, &change.Tombstones); errDecode != nil {
			return catalog.ChangePage{}, fmt.Errorf("decode catalog change tombstones: %w", errDecode)
		}
		if errValidate := change.Validate(); errValidate != nil {
			return catalog.ChangePage{}, fmt.Errorf("validate persisted catalog change: %w", errValidate)
		}
		page.Changes = append(page.Changes, change)
	}
	if errRows := rows.Err(); errRows != nil {
		return catalog.ChangePage{}, fmt.Errorf("iterate catalog changes: %w", errRows)
	}
	return page, nil
}

// insertCatalogChange appends one invalidation fact in the same transaction as its snapshot mutation.
// insertCatalogChange 在快照变更的同一事务中追加一个失效事实。
func insertCatalogChange(ctx context.Context, transaction *sql.Tx, change catalog.Change) error {
	tombstonesPayload, errPayload := json.Marshal(change.Tombstones)
	if errPayload != nil {
		return fmt.Errorf("encode catalog change tombstones: %w", errPayload)
	}
	if _, errInsert := transaction.ExecContext(ctx, `INSERT INTO catalog_changes(provider_instance_id, provider_revision, change_type, observed_at, source_revision, etag, refresh_status, tombstones_payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, change.ProviderInstanceID, int64(change.ProviderRevision), change.Type, change.ObservedAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"), change.SourceRevision, change.ETag, change.RefreshStatus, tombstonesPayload); errInsert != nil {
		return fmt.Errorf("append catalog change: %w", errInsert)
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
