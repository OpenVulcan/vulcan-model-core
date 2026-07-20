package sqlitestore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
)

const (
	// sqliteTimeLayout is the canonical sortable timestamp representation used by resource indexes.
	// sqliteTimeLayout 是资源索引使用的规范可排序时间戳表示。
	sqliteTimeLayout = "2006-01-02T15:04:05.999999999Z07:00"
)

// ResourceStore persists Router resource metadata while object bytes remain on the filesystem.
// ResourceStore 持久化 Router 资源元数据，而对象字节仍保留在文件系统中。
type ResourceStore struct {
	// database owns the shared migrated SQLite connection pool.
	// database 管理共享且已迁移的 SQLite 连接池。
	database *Database
}

// NewResourceStore creates a SQLite-backed resource metadata repository.
// NewResourceStore 创建一个由 SQLite 支持的资源元数据仓库。
func NewResourceStore(database *Database) (*ResourceStore, error) {
	if database == nil || database.sql == nil {
		return nil, errors.New("sqlite database is required")
	}
	return &ResourceStore{database: database}, nil
}

// CreateReceiving reserves one validated resource identity.
// CreateReceiving 保留一个已校验资源身份。
func (s *ResourceStore) CreateReceiving(ctx context.Context, value resource.Resource) error {
	if errContext := validateContext(ctx); errContext != nil {
		return errContext
	}
	if value.State != resource.StateReceiving {
		return resource.ErrInvalidResource
	}
	if errValidate := value.Validate(); errValidate != nil {
		return errValidate
	}
	payload, errPayload := marshalPayload(value)
	if errPayload != nil {
		return errPayload
	}
	_, errExec := s.database.sql.ExecContext(ctx, `INSERT INTO router_resources(id, owner_api_key_id, kind, state, size_bytes, revision, expires_at, object_key, source_url, payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, value.ID, value.OwnerAPIKeyID, value.Kind, value.State, value.SizeBytes, int64(value.Revision), nullableTime(value.ExpiresAt), value.ObjectKey, value.SourceURL, payload)
	if errExec != nil {
		return fmt.Errorf("%w: reserve resource metadata", resource.ErrResourceConflict)
	}
	return nil
}

// CommitReady atomically locks quota accounting, verifies identity, and publishes one ready resource.
// CommitReady 原子锁定配额核算、校验身份并发布一个就绪资源。
func (s *ResourceStore) CommitReady(ctx context.Context, value resource.Resource, maxReadyBytes int64) error {
	if errContext := validateContext(ctx); errContext != nil {
		return errContext
	}
	if value.State != resource.StateReady || maxReadyBytes <= 0 || value.Revision > math.MaxInt64 {
		return resource.ErrInvalidResource
	}
	if errValidate := value.Validate(); errValidate != nil {
		return errValidate
	}
	payload, errPayload := marshalPayload(value)
	if errPayload != nil {
		return errPayload
	}
	transaction, errBegin := s.database.sql.BeginTx(ctx, nil)
	if errBegin != nil {
		return fmt.Errorf("begin resource commit: %w", errBegin)
	}
	defer func() { _ = transaction.Rollback() }()
	if _, errLock := transaction.ExecContext(ctx, `UPDATE resource_quota_lock SET revision = revision + 1 WHERE id = 1`); errLock != nil {
		return fmt.Errorf("lock resource quota: %w", errLock)
	}
	var readyBytes int64
	if errSum := transaction.QueryRowContext(ctx, `SELECT COALESCE(SUM(size_bytes), 0) FROM router_resources WHERE state = ?`, resource.StateReady).Scan(&readyBytes); errSum != nil {
		return fmt.Errorf("sum ready resource bytes: %w", errSum)
	}
	if value.SizeBytes > maxReadyBytes-readyBytes {
		return resource.ErrResourceQuotaExceeded
	}
	result, errUpdate := transaction.ExecContext(ctx, `UPDATE router_resources SET state = ?, size_bytes = ?, revision = ?, expires_at = ?, object_key = ?, source_url = ?, payload = ? WHERE id = ? AND state = ? AND revision = ? AND owner_api_key_id = ? AND kind = ?`, value.State, value.SizeBytes, int64(value.Revision), nullableTime(value.ExpiresAt), value.ObjectKey, value.SourceURL, payload, value.ID, resource.StateReceiving, int64(value.Revision-1), value.OwnerAPIKeyID, value.Kind)
	if errUpdate != nil {
		return fmt.Errorf("publish ready resource: %w", errUpdate)
	}
	if errAffected := requireOneResourceRow(result); errAffected != nil {
		return errAffected
	}
	if errCommit := transaction.Commit(); errCommit != nil {
		return fmt.Errorf("commit ready resource: %w", errCommit)
	}
	return nil
}

// MarkFailed records one safe failure from receiving state.
// MarkFailed 从接收中状态记录一个安全失败。
func (s *ResourceStore) MarkFailed(ctx context.Context, resourceID string, errorCode string, now time.Time) error {
	return s.transitionPayload(ctx, resourceID, resource.StateReceiving, 0, func(current *resource.Resource) error {
		if errorCode == "" || now.IsZero() {
			return resource.ErrInvalidResource
		}
		current.State = resource.StateFailed
		current.ErrorCode = errorCode
		current.UpdatedAt = now.UTC()
		current.Revision++
		return nil
	})
}

// BeginDelete moves one ready or expired resource to deleting using optimistic revision control.
// BeginDelete 使用乐观修订控制将一个就绪或已过期资源移至删除中。
func (s *ResourceStore) BeginDelete(ctx context.Context, resourceID string, revision uint64, now time.Time) (resource.Resource, error) {
	var updated resource.Resource
	errTransition := s.transitionPayload(ctx, resourceID, "", revision, func(current *resource.Resource) error {
		if (current.State != resource.StateReady && current.State != resource.StateExpired) || now.IsZero() {
			return resource.ErrResourceConflict
		}
		current.State = resource.StateDeleting
		current.UpdatedAt = now.UTC()
		current.Revision++
		updated = *current
		return nil
	})
	return updated, errTransition
}

// FinishDelete replaces one deleting record with a metadata-safe tombstone.
// FinishDelete 将一个删除中记录替换为元数据安全墓碑。
func (s *ResourceStore) FinishDelete(ctx context.Context, resourceID string, revision uint64, now time.Time) error {
	return s.transitionPayload(ctx, resourceID, resource.StateDeleting, revision, func(current *resource.Resource) error {
		if now.IsZero() {
			return resource.ErrInvalidResource
		}
		current.State = resource.StateDeleted
		current.MIMEType = ""
		current.SizeBytes = 0
		current.SHA256 = ""
		current.Metadata = resource.Metadata{}
		current.ObjectKey = ""
		current.SourceURL = ""
		current.UpdatedAt = now.UTC()
		current.Revision++
		return nil
	})
}

// MarkExpired moves an elapsed ready resource to expired.
// MarkExpired 将一个已到期就绪资源移至已过期状态。
func (s *ResourceStore) MarkExpired(ctx context.Context, resourceID string, revision uint64, now time.Time) (resource.Resource, error) {
	var updated resource.Resource
	errTransition := s.transitionPayload(ctx, resourceID, resource.StateReady, revision, func(current *resource.Resource) error {
		if now.IsZero() || current.ExpiresAt == nil || current.ExpiresAt.After(now) {
			return resource.ErrResourceConflict
		}
		current.State = resource.StateExpired
		current.UpdatedAt = now.UTC()
		current.Revision++
		updated = *current
		return nil
	})
	return updated, errTransition
}

// Get returns one validated resource metadata snapshot.
// Get 返回一个经过校验的资源元数据快照。
func (s *ResourceStore) Get(ctx context.Context, resourceID string) (resource.Resource, error) {
	if errContext := validateContext(ctx); errContext != nil {
		return resource.Resource{}, errContext
	}
	return scanResource(s.database.sql.QueryRowContext(ctx, `SELECT owner_api_key_id, object_key, source_url, payload FROM router_resources WHERE id = ?`, resourceID))
}

// ListExpired returns cleanup candidates in deterministic expiry and identifier order.
// ListExpired 按确定性的过期时间与标识顺序返回清理候选项。
func (s *ResourceStore) ListExpired(ctx context.Context, before time.Time, limit int) ([]resource.Resource, error) {
	if errContext := validateContext(ctx); errContext != nil {
		return nil, errContext
	}
	if before.IsZero() || limit <= 0 {
		return nil, resource.ErrInvalidResource
	}
	rows, errQuery := s.database.sql.QueryContext(ctx, `SELECT owner_api_key_id, object_key, source_url, payload FROM router_resources WHERE (state IN (?, ?) AND expires_at IS NOT NULL AND expires_at <= ?) OR state = ? ORDER BY COALESCE(expires_at, ''), id LIMIT ?`, resource.StateReady, resource.StateExpired, before.UTC().Format(sqliteTimeLayout), resource.StateDeleting, limit)
	if errQuery != nil {
		return nil, fmt.Errorf("list expired resources: %w", errQuery)
	}
	defer rows.Close()
	values := make([]resource.Resource, 0)
	for rows.Next() {
		value, errScan := scanResource(rows)
		if errScan != nil {
			return nil, errScan
		}
		values = append(values, value)
	}
	if errRows := rows.Err(); errRows != nil {
		return nil, fmt.Errorf("iterate expired resources: %w", errRows)
	}
	return values, nil
}

// ListDiagnostics returns the newest bounded resource metadata for management diagnostics.
// ListDiagnostics 返回供管理诊断使用的最新有界资源元数据。
func (s *ResourceStore) ListDiagnostics(ctx context.Context, limit int) ([]resource.Resource, error) {
	if errContext := validateContext(ctx); errContext != nil {
		return nil, errContext
	}
	if limit <= 0 || limit > 500 {
		return nil, resource.ErrInvalidResource
	}
	rows, errQuery := s.database.sql.QueryContext(ctx, `SELECT owner_api_key_id, object_key, source_url, payload FROM router_resources ORDER BY created_at DESC, id DESC LIMIT ?`, limit)
	if errQuery != nil {
		return nil, fmt.Errorf("list resource diagnostics: %w", errQuery)
	}
	defer rows.Close()
	values := make([]resource.Resource, 0)
	for rows.Next() {
		value, errScan := scanResource(rows)
		if errScan != nil {
			return nil, errScan
		}
		values = append(values, value)
	}
	if errRows := rows.Err(); errRows != nil {
		return nil, fmt.Errorf("iterate resource diagnostics: %w", errRows)
	}
	return values, nil
}

// transitionPayload serializes one optimistic metadata transition in a database transaction.
// transitionPayload 在数据库事务中串行化一个乐观元数据迁移。
func (s *ResourceStore) transitionPayload(ctx context.Context, resourceID string, expectedState resource.State, expectedRevision uint64, mutate func(*resource.Resource) error) error {
	if errContext := validateContext(ctx); errContext != nil {
		return errContext
	}
	transaction, errBegin := s.database.sql.BeginTx(ctx, nil)
	if errBegin != nil {
		return fmt.Errorf("begin resource transition: %w", errBegin)
	}
	defer func() { _ = transaction.Rollback() }()
	current, errCurrent := scanResource(transaction.QueryRowContext(ctx, `SELECT owner_api_key_id, object_key, source_url, payload FROM router_resources WHERE id = ?`, resourceID))
	if errCurrent != nil {
		return errCurrent
	}
	if expectedState != "" && current.State != expectedState {
		return resource.ErrResourceConflict
	}
	if expectedRevision != 0 && current.Revision != expectedRevision {
		return resource.ErrResourceConflict
	}
	previousRevision := current.Revision
	if errMutate := mutate(&current); errMutate != nil {
		return errMutate
	}
	payload, errPayload := marshalPayload(current)
	if errPayload != nil {
		return errPayload
	}
	result, errUpdate := transaction.ExecContext(ctx, `UPDATE router_resources SET state = ?, size_bytes = ?, revision = ?, expires_at = ?, object_key = ?, source_url = ?, payload = ? WHERE id = ? AND revision = ?`, current.State, current.SizeBytes, int64(current.Revision), nullableTime(current.ExpiresAt), current.ObjectKey, current.SourceURL, payload, current.ID, int64(previousRevision))
	if errUpdate != nil {
		return fmt.Errorf("update resource transition: %w", errUpdate)
	}
	if errAffected := requireOneResourceRow(result); errAffected != nil {
		return errAffected
	}
	if errCommit := transaction.Commit(); errCommit != nil {
		return fmt.Errorf("commit resource transition: %w", errCommit)
	}
	return nil
}

// resourceScanner is implemented by both sql.Row and sql.Rows.
// resourceScanner 由 sql.Row 与 sql.Rows 共同实现。
type resourceScanner interface {
	// Scan copies the current row into destinations.
	// Scan 将当前行复制到目标值。
	Scan(...any) error
}

// scanResource restores private persistence columns and validates one payload.
// scanResource 恢复私有持久化列并校验一个 Payload。
func scanResource(scanner resourceScanner) (resource.Resource, error) {
	var ownerAPIKeyID string
	var objectKey string
	var sourceURL string
	var payload []byte
	if errScan := scanner.Scan(&ownerAPIKeyID, &objectKey, &sourceURL, &payload); errors.Is(errScan, sql.ErrNoRows) {
		return resource.Resource{}, resource.ErrResourceNotFound
	} else if errScan != nil {
		return resource.Resource{}, fmt.Errorf("scan resource metadata: %w", errScan)
	}
	var value resource.Resource
	if errDecode := unmarshalPayload(payload, &value); errDecode != nil {
		return resource.Resource{}, errDecode
	}
	value.OwnerAPIKeyID = ownerAPIKeyID
	value.ObjectKey = objectKey
	value.SourceURL = sourceURL
	if errValidate := value.Validate(); errValidate != nil {
		return resource.Resource{}, fmt.Errorf("validate persisted resource: %w", errValidate)
	}
	return value, nil
}

// requireOneResourceRow maps an optimistic update miss to a resource conflict.
// requireOneResourceRow 将乐观更新未命中映射为资源冲突。
func requireOneResourceRow(result sql.Result) error {
	rowsAffected, errRows := result.RowsAffected()
	if errRows != nil {
		return fmt.Errorf("read resource write result: %w", errRows)
	}
	if rowsAffected != 1 {
		return resource.ErrResourceConflict
	}
	return nil
}

// nullableTime projects an optional UTC timestamp into SQLite.
// nullableTime 将可选 UTC 时间戳投影到 SQLite。
func nullableTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.UTC().Format(sqliteTimeLayout)
}
