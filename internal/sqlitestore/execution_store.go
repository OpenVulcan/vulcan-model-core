package sqlitestore

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/execution"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

// ExecutionStore persists durable execution records and event logs in SQLite.
// ExecutionStore 在 SQLite 中持久化执行记录与事件日志。
type ExecutionStore struct {
	// database owns the migrated SQLite connection pool.
	// database 拥有已迁移 SQLite 连接池。
	database *Database
	// secrets protects upstream task and prepared-workflow handles outside SQLite.
	// secrets 在 SQLite 之外保护上游任务与准备工作流句柄。
	secrets secret.Store
}

// formatExecutionTime encodes one UTC timestamp using the repository-wide SQLite layout.
// formatExecutionTime 使用 Repository 统一 SQLite 格式编码一个 UTC 时间戳。
func formatExecutionTime(value time.Time) string {
	return value.UTC().Format(sqliteTimeLayout)
}

// parseExecutionTime decodes one timestamp written by formatExecutionTime.
// parseExecutionTime 解码一个由 formatExecutionTime 写入的时间戳。
func parseExecutionTime(value string) (time.Time, error) {
	return time.Parse(sqliteTimeLayout, value)
}

// NewExecutionStore creates one SQLite-backed execution repository.
// NewExecutionStore 创建一个 SQLite 支持的执行 Repository。
func NewExecutionStore(database *Database, secrets secret.Store) (*ExecutionStore, error) {
	if database == nil || database.sql == nil {
		return nil, errors.New("sqlite database is required")
	}
	if secrets == nil {
		return nil, errors.New("execution secret store is required")
	}
	store := &ExecutionStore{database: database, secrets: secrets}
	if errMigrate := store.migrateLegacyProviderHandles(context.Background()); errMigrate != nil {
		return nil, errMigrate
	}
	return store, nil
}

// legacyExecutionProviderTaskPayload is the exact schema-version-5 plaintext task shape.
// legacyExecutionProviderTaskPayload 是 Schema 版本 5 的精确明文任务结构。
type legacyExecutionProviderTaskPayload struct {
	// ProviderTaskID is the legacy plaintext upstream task identifier.
	// ProviderTaskID 是旧版明文上游任务标识。
	ProviderTaskID string `json:"provider_task_id"`
	// Target is the exact immutable provider affinity.
	// Target 是精确不可变供应商亲和性。
	Target resolve.Target `json:"target"`
	// Definition is the immutable provider driver definition snapshot.
	// Definition 是不可变供应商 Driver Definition 快照。
	Definition providerconfig.ProviderDefinition `json:"definition"`
	// Endpoint is the immutable provider endpoint snapshot.
	// Endpoint 是不可变供应商 Endpoint 快照。
	Endpoint providerconfig.Endpoint `json:"endpoint"`
	// Credential is the immutable non-secret credential snapshot.
	// Credential 是不可变非秘密 Credential 快照。
	Credential providerconfig.Credential `json:"credential"`
	// PollAfter is the earliest permitted poll.
	// PollAfter 是最早允许轮询时间。
	PollAfter time.Time `json:"poll_after"`
	// PollAttempts counts completed bounded polls.
	// PollAttempts 统计已完成有界轮询次数。
	PollAttempts uint32 `json:"poll_attempts"`
}

// legacyExecutionProviderPreparationPayload is the exact schema-version-5 plaintext preparation shape.
// legacyExecutionProviderPreparationPayload 是 Schema 版本 5 的精确明文准备结构。
type legacyExecutionProviderPreparationPayload struct {
	// ProviderHandle is the legacy plaintext prepared-workflow handle.
	// ProviderHandle 是旧版明文准备工作流句柄。
	ProviderHandle string `json:"provider_handle"`
	// Target is the immutable provider affinity that created the handle.
	// Target 是创建句柄的不可变供应商亲和性。
	Target resolve.Target `json:"target"`
	// ExpiresAt is the provider-confirmed handle expiry.
	// ExpiresAt 是供应商确认的句柄到期时间。
	ExpiresAt time.Time `json:"expires_at"`
}

// legacyExecutionHandleRow contains one candidate row for protected-handle migration.
// legacyExecutionHandleRow 包含一个受保护句柄迁移候选行。
type legacyExecutionHandleRow struct {
	// id is the exact execution row identifier.
	// id 是精确执行行标识。
	id string
	// taskPayload is the existing task snapshot payload.
	// taskPayload 是现有任务快照载荷。
	taskPayload []byte
	// preparationPayload is the existing prepared-workflow snapshot payload.
	// preparationPayload 是现有准备工作流快照载荷。
	preparationPayload []byte
	// taskSecretRef is the already protected task reference when present.
	// taskSecretRef 是存在时已受保护的任务引用。
	taskSecretRef sql.NullString
	// preparationSecretRef is the already protected preparation reference when present.
	// preparationSecretRef 是存在时已受保护的准备引用。
	preparationSecretRef sql.NullString
}

// migrateLegacyProviderHandles protects every schema-version-5 plaintext handle before the repository becomes usable.
// migrateLegacyProviderHandles 在 Repository 可用前保护每个 Schema 版本 5 的明文句柄。
func (s *ExecutionStore) migrateLegacyProviderHandles(ctx context.Context) error {
	transaction, errBegin := s.database.sql.BeginTx(ctx, nil)
	if errBegin != nil {
		return fmt.Errorf("begin execution handle migration: %w", errBegin)
	}
	defer func() { _ = transaction.Rollback() }()
	rows, errQuery := transaction.QueryContext(ctx, `SELECT id, provider_task_payload, provider_preparation_payload, provider_task_secret_ref, provider_preparation_secret_ref FROM executions WHERE provider_task_payload IS NOT NULL OR provider_preparation_payload IS NOT NULL`)
	if errQuery != nil {
		return fmt.Errorf("query legacy execution handles: %w", errQuery)
	}
	// candidates isolates all rows before updates begin on the same transaction.
	// candidates 在同一事务开始更新前隔离全部行。
	candidates := make([]legacyExecutionHandleRow, 0)
	for rows.Next() {
		var candidate legacyExecutionHandleRow
		if errScan := rows.Scan(&candidate.id, &candidate.taskPayload, &candidate.preparationPayload, &candidate.taskSecretRef, &candidate.preparationSecretRef); errScan != nil {
			_ = rows.Close()
			return fmt.Errorf("scan legacy execution handles: %w", errScan)
		}
		candidates = append(candidates, candidate)
	}
	if errRows := rows.Err(); errRows != nil {
		_ = rows.Close()
		return fmt.Errorf("iterate legacy execution handles: %w", errRows)
	}
	if errClose := rows.Close(); errClose != nil {
		return fmt.Errorf("close legacy execution handles: %w", errClose)
	}
	// createdReferences are removed if any migration row cannot be committed.
	// createdReferences 会在任一迁移行无法提交时被删除。
	createdReferences := make([]string, 0)
	committed := false
	defer func() {
		if !committed {
			cleanupCreatedExecutionSecrets(ctx, s.secrets, createdReferences)
		}
	}()
	for _, candidate := range candidates {
		taskPayload := candidate.taskPayload
		taskSecretRef := candidate.taskSecretRef.String
		preparationPayload := candidate.preparationPayload
		preparationSecretRef := candidate.preparationSecretRef.String
		changed := false
		if len(taskPayload) > 0 {
			var legacyTask legacyExecutionProviderTaskPayload
			if errDecode := json.Unmarshal(taskPayload, &legacyTask); errDecode != nil {
				return fmt.Errorf("decode legacy execution task %s: %w", candidate.id, errDecode)
			}
			if legacyTask.ProviderTaskID != "" {
				protectedReference, created, errProtect := ensureExecutionSecret(ctx, s.secrets, taskSecretRef, legacyTask.ProviderTaskID)
				if errProtect != nil {
					return fmt.Errorf("protect legacy execution task %s: %w", candidate.id, errProtect)
				}
				taskSecretRef = protectedReference
				if created {
					createdReferences = append(createdReferences, protectedReference)
				}
				var errEncode error
				taskPayload, errEncode = json.Marshal(executionProviderTaskPayload{Target: legacyTask.Target, Definition: legacyTask.Definition, Endpoint: legacyTask.Endpoint, Credential: legacyTask.Credential, PollAfter: legacyTask.PollAfter, PollAttempts: legacyTask.PollAttempts})
				if errEncode != nil {
					return fmt.Errorf("rewrite legacy execution task %s: %w", candidate.id, errEncode)
				}
				changed = true
			} else if taskSecretRef == "" {
				return fmt.Errorf("migrate execution task %s: protected reference is missing", candidate.id)
			}
		}
		if len(preparationPayload) > 0 {
			var legacyPreparation legacyExecutionProviderPreparationPayload
			if errDecode := json.Unmarshal(preparationPayload, &legacyPreparation); errDecode != nil {
				return fmt.Errorf("decode legacy execution preparation %s: %w", candidate.id, errDecode)
			}
			if legacyPreparation.ProviderHandle != "" {
				protectedReference, created, errProtect := ensureExecutionSecret(ctx, s.secrets, preparationSecretRef, legacyPreparation.ProviderHandle)
				if errProtect != nil {
					return fmt.Errorf("protect legacy execution preparation %s: %w", candidate.id, errProtect)
				}
				preparationSecretRef = protectedReference
				if created {
					createdReferences = append(createdReferences, protectedReference)
				}
				var errEncode error
				preparationPayload, errEncode = json.Marshal(executionProviderPreparationPayload{Target: legacyPreparation.Target, ExpiresAt: legacyPreparation.ExpiresAt})
				if errEncode != nil {
					return fmt.Errorf("rewrite legacy execution preparation %s: %w", candidate.id, errEncode)
				}
				changed = true
			} else if preparationSecretRef == "" {
				return fmt.Errorf("migrate execution preparation %s: protected reference is missing", candidate.id)
			}
		}
		if changed {
			if _, errUpdate := transaction.ExecContext(ctx, `UPDATE executions SET provider_task_payload = ?, provider_preparation_payload = ?, provider_task_secret_ref = ?, provider_preparation_secret_ref = ? WHERE id = ?`, taskPayload, preparationPayload, nullString(taskSecretRef), nullString(preparationSecretRef), candidate.id); errUpdate != nil {
				return fmt.Errorf("persist protected execution handles %s: %w", candidate.id, errUpdate)
			}
		}
	}
	if errCommit := transaction.Commit(); errCommit != nil {
		return fmt.Errorf("commit execution handle migration: %w", errCommit)
	}
	committed = true
	return nil
}

// LookupIdempotency returns an exact owner-key replay before mutable target resolution.
// LookupIdempotency 在可变 Target 解析前返回精确所有者键重放。
func (s *ExecutionStore) LookupIdempotency(ctx context.Context, ownerAPIKeyID string, idempotencyKey string, requestHash string) (execution.Record, bool, error) {
	if idempotencyKey == "" {
		return execution.Record{}, false, nil
	}
	record, errScan := scanExecution(ctx, s.secrets, s.database.sql.QueryRowContext(ctx, executionSelect+` WHERE owner_api_key_id = ? AND idempotency_key = ?`, ownerAPIKeyID, idempotencyKey))
	if errors.Is(errScan, sql.ErrNoRows) {
		return execution.Record{}, false, nil
	}
	if errScan != nil {
		return execution.Record{}, false, fmt.Errorf("read idempotent execution: %w", errScan)
	}
	if record.RequestHash != requestHash {
		return execution.Record{}, false, execution.ErrIdempotencyConflict
	}
	return record, true, nil
}

// Create admits one execution or returns an exact idempotent replay in one transaction.
// Create 在一个事务中接收执行或返回精确幂等重放。
func (s *ExecutionStore) Create(ctx context.Context, record execution.Record, accepted execution.Event) (execution.Record, bool, error) {
	if errRecord := record.Validate(); errRecord != nil {
		return execution.Record{}, false, errRecord
	}
	if errEvent := accepted.Validate(); errEvent != nil || accepted.ExecutionID != record.ID || accepted.Sequence != 1 {
		return execution.Record{}, false, fmt.Errorf("%w: invalid accepted event", execution.ErrInvalidExecution)
	}
	transaction, errBegin := s.database.sql.BeginTx(ctx, nil)
	if errBegin != nil {
		return execution.Record{}, false, fmt.Errorf("begin execution creation: %w", errBegin)
	}
	defer func() { _ = transaction.Rollback() }()
	if record.IdempotencyKey != "" {
		existing, found, errExisting := getExecutionByIdempotency(ctx, s.secrets, transaction, record.OwnerAPIKeyID, record.IdempotencyKey)
		if errExisting != nil {
			return execution.Record{}, false, errExisting
		}
		if found {
			if existing.RequestHash != record.RequestHash {
				return execution.Record{}, false, execution.ErrIdempotencyConflict
			}
			return existing, true, nil
		}
	}
	encoded, errEncode := encodeExecutionRecord(ctx, s.secrets, record)
	if errEncode != nil {
		return execution.Record{}, false, errEncode
	}
	// committed prevents cleanup from deleting newly referenced secrets after a successful transaction.
	// committed 防止清理逻辑在事务成功后删除新引用的 Secret。
	committed := false
	defer func() {
		if !committed {
			cleanupCreatedExecutionSecrets(ctx, s.secrets, encoded.createdSecretRefs)
		}
	}()
	if _, errInsert := transaction.ExecContext(ctx, `INSERT INTO executions(id, owner_api_key_id, request_hash, idempotency_key, status, operation, revision, created_at, updated_at, expires_at, request_payload, target_payload, result_payload, failure_payload, provider_task_payload, provider_preparation_payload, provider_task_secret_ref, provider_preparation_secret_ref) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, record.ID, record.OwnerAPIKeyID, record.RequestHash, record.IdempotencyKey, record.Status, record.Operation, record.Revision, formatExecutionTime(record.CreatedAt), formatExecutionTime(record.UpdatedAt), formatExecutionTime(record.ExpiresAt), encoded.request, encoded.target, encoded.result, encoded.failure, encoded.providerTask, encoded.providerPreparation, nullString(encoded.providerTaskSecretRef), nullString(encoded.providerPreparationSecretRef)); errInsert != nil {
		if record.IdempotencyKey != "" {
			existing, found, errExisting := getExecutionByIdempotency(ctx, s.secrets, transaction, record.OwnerAPIKeyID, record.IdempotencyKey)
			if errExisting == nil && found {
				if existing.RequestHash != record.RequestHash {
					return execution.Record{}, false, execution.ErrIdempotencyConflict
				}
				return existing, true, nil
			}
		}
		return execution.Record{}, false, fmt.Errorf("insert execution: %w", errInsert)
	}
	if errEvents := insertExecutionEvents(ctx, transaction, []execution.Event{accepted}); errEvents != nil {
		return execution.Record{}, false, errEvents
	}
	if errCommit := transaction.Commit(); errCommit != nil {
		return execution.Record{}, false, fmt.Errorf("commit execution creation: %w", errCommit)
	}
	committed = true
	assignExecutionSecretRefs(&record, encoded)
	return record, false, nil
}

// Get returns one owner-scoped execution.
// Get 返回一个所有者作用域执行。
func (s *ExecutionStore) Get(ctx context.Context, ownerAPIKeyID string, executionID string) (execution.Record, error) {
	row := s.database.sql.QueryRowContext(ctx, executionSelect+` WHERE owner_api_key_id = ? AND id = ?`, ownerAPIKeyID, executionID)
	record, errScan := scanExecution(ctx, s.secrets, row)
	if errors.Is(errScan, sql.ErrNoRows) {
		return execution.Record{}, execution.ErrExecutionNotFound
	}
	return record, errScan
}

// Save atomically applies one compare-and-swap update and appends ordered events.
// Save 原子应用一个比较并交换更新并追加有序事件。
func (s *ExecutionStore) Save(ctx context.Context, record execution.Record, expectedRevision uint64, appended []execution.Event) error {
	if errRecord := record.Validate(); errRecord != nil {
		return errRecord
	}
	transaction, errBegin := s.database.sql.BeginTx(ctx, nil)
	if errBegin != nil {
		return fmt.Errorf("begin execution update: %w", errBegin)
	}
	defer func() { _ = transaction.Rollback() }()
	var currentStatus execution.Status
	var currentRevision uint64
	var maximumSequence uint64
	// previousTaskSecretRef and previousPreparationSecretRef identify protected values replaced by this commit.
	// previousTaskSecretRef 与 previousPreparationSecretRef 标识被本次提交替换的受保护值。
	var previousTaskSecretRef sql.NullString
	var previousPreparationSecretRef sql.NullString
	errCurrent := transaction.QueryRowContext(ctx, `SELECT status, revision, COALESCE((SELECT MAX(sequence) FROM execution_events WHERE execution_id = executions.id), 0), provider_task_secret_ref, provider_preparation_secret_ref FROM executions WHERE owner_api_key_id = ? AND id = ?`, record.OwnerAPIKeyID, record.ID).Scan(&currentStatus, &currentRevision, &maximumSequence, &previousTaskSecretRef, &previousPreparationSecretRef)
	if errors.Is(errCurrent, sql.ErrNoRows) {
		return execution.ErrExecutionNotFound
	}
	if errCurrent != nil {
		return fmt.Errorf("read current execution: %w", errCurrent)
	}
	if currentRevision != expectedRevision || record.Revision != expectedRevision+1 {
		return execution.ErrRevisionConflict
	}
	if currentStatus != record.Status {
		if errTransition := execution.ValidateTransition(currentStatus, record.Status); errTransition != nil {
			return errTransition
		}
	}
	for index, event := range appended {
		if errEvent := event.Validate(); errEvent != nil || event.ExecutionID != record.ID || event.Sequence != maximumSequence+1+uint64(index) {
			return fmt.Errorf("%w: appended event sequence is invalid", execution.ErrInvalidExecution)
		}
	}
	encoded, errEncode := encodeExecutionRecord(ctx, s.secrets, record)
	if errEncode != nil {
		return errEncode
	}
	// committed prevents rollback cleanup from deleting values referenced by a successful update.
	// committed 防止回滚清理删除成功更新所引用的值。
	committed := false
	defer func() {
		if !committed {
			cleanupCreatedExecutionSecrets(ctx, s.secrets, encoded.createdSecretRefs)
		}
	}()
	result, errUpdate := transaction.ExecContext(ctx, `UPDATE executions SET status = ?, revision = ?, updated_at = ?, expires_at = ?, result_payload = ?, failure_payload = ?, provider_task_payload = ?, provider_preparation_payload = ?, provider_task_secret_ref = ?, provider_preparation_secret_ref = ? WHERE id = ? AND owner_api_key_id = ? AND revision = ?`, record.Status, record.Revision, formatExecutionTime(record.UpdatedAt), formatExecutionTime(record.ExpiresAt), encoded.result, encoded.failure, encoded.providerTask, encoded.providerPreparation, nullString(encoded.providerTaskSecretRef), nullString(encoded.providerPreparationSecretRef), record.ID, record.OwnerAPIKeyID, expectedRevision)
	if errUpdate != nil {
		return fmt.Errorf("update execution: %w", errUpdate)
	}
	rowsAffected, errRows := result.RowsAffected()
	if errRows != nil {
		return fmt.Errorf("read execution update count: %w", errRows)
	}
	if rowsAffected != 1 {
		return execution.ErrRevisionConflict
	}
	if errEvents := insertExecutionEvents(ctx, transaction, appended); errEvents != nil {
		return errEvents
	}
	if errCommit := transaction.Commit(); errCommit != nil {
		return fmt.Errorf("commit execution update: %w", errCommit)
	}
	committed = true
	assignExecutionSecretRefs(&record, encoded)
	deleteReplacedExecutionSecret(ctx, s.secrets, previousTaskSecretRef.String, encoded.providerTaskSecretRef)
	deleteReplacedExecutionSecret(ctx, s.secrets, previousPreparationSecretRef.String, encoded.providerPreparationSecretRef)
	return nil
}

// ListEvents returns events strictly after one sequence in stable order.
// ListEvents 以稳定顺序返回指定序号之后的事件。
func (s *ExecutionStore) ListEvents(ctx context.Context, ownerAPIKeyID string, executionID string, afterSequence uint64) ([]execution.Event, error) {
	if _, errRecord := s.Get(ctx, ownerAPIKeyID, executionID); errRecord != nil {
		return nil, errRecord
	}
	rows, errQuery := s.database.sql.QueryContext(ctx, `SELECT payload FROM execution_events WHERE execution_id = ? AND sequence > ? ORDER BY sequence`, executionID, afterSequence)
	if errQuery != nil {
		return nil, fmt.Errorf("list execution events: %w", errQuery)
	}
	defer rows.Close()
	events := make([]execution.Event, 0)
	for rows.Next() {
		var payload []byte
		if errScan := rows.Scan(&payload); errScan != nil {
			return nil, fmt.Errorf("scan execution event: %w", errScan)
		}
		var event execution.Event
		if errDecode := json.Unmarshal(payload, &event); errDecode != nil {
			return nil, fmt.Errorf("decode execution event: %w", errDecode)
		}
		events = append(events, event)
	}
	if errRows := rows.Err(); errRows != nil {
		return nil, fmt.Errorf("iterate execution events: %w", errRows)
	}
	return events, nil
}

// ListRecoverable returns all non-terminal records in stable creation order.
// ListRecoverable 以稳定创建顺序返回所有非终态记录。
func (s *ExecutionStore) ListRecoverable(ctx context.Context) ([]execution.Record, error) {
	rows, errQuery := s.database.sql.QueryContext(ctx, executionSelect+` WHERE status NOT IN (?, ?, ?, ?, ?) ORDER BY created_at, id`, execution.StatusSucceeded, execution.StatusPartiallySucceeded, execution.StatusFailed, execution.StatusCancelled, execution.StatusExpired)
	if errQuery != nil {
		return nil, fmt.Errorf("list recoverable executions: %w", errQuery)
	}
	defer rows.Close()
	records := make([]execution.Record, 0)
	for rows.Next() {
		record, errScan := scanExecution(ctx, s.secrets, rows)
		if errScan != nil {
			return nil, errScan
		}
		records = append(records, record)
	}
	if errRows := rows.Err(); errRows != nil {
		return nil, fmt.Errorf("iterate recoverable executions: %w", errRows)
	}
	return records, nil
}

// ListDiagnostics returns the newest bounded execution snapshots for management diagnostics.
// ListDiagnostics 返回供管理诊断使用的最新有界执行快照。
func (s *ExecutionStore) ListDiagnostics(ctx context.Context, limit int) ([]execution.Record, error) {
	if errContext := validateContext(ctx); errContext != nil {
		return nil, errContext
	}
	if limit <= 0 || limit > 500 {
		return nil, execution.ErrInvalidExecution
	}
	rows, errQuery := s.database.sql.QueryContext(ctx, executionSelect+` ORDER BY created_at DESC, id DESC LIMIT ?`, limit)
	if errQuery != nil {
		return nil, fmt.Errorf("list execution diagnostics: %w", errQuery)
	}
	defer rows.Close()
	records := make([]execution.Record, 0)
	for rows.Next() {
		record, errScan := scanExecution(ctx, s.secrets, rows)
		if errScan != nil {
			return nil, errScan
		}
		records = append(records, record)
	}
	if errRows := rows.Err(); errRows != nil {
		return nil, fmt.Errorf("iterate execution diagnostics: %w", errRows)
	}
	return records, nil
}

// executionEncodedRecord contains exact JSON columns for one durable record.
// executionEncodedRecord 包含一个持久化记录的精确 JSON 列。
type executionEncodedRecord struct {
	// request stores the private canonical VCP request.
	// request 保存私有规范 VCP 请求。
	request []byte
	// target stores immutable provider affinity.
	// target 保存不可变供应商亲和性。
	target []byte
	// result stores optional typed output.
	// result 保存可选类型化输出。
	result []byte
	// failure stores optional safe failure facts.
	// failure 保存可选安全错误事实。
	failure []byte
	// providerTask stores optional private asynchronous recovery facts.
	// providerTask 保存可选私有异步恢复事实。
	providerTask []byte
	// providerPreparation stores optional private multi-step workflow affinity.
	// providerPreparation 保存可选私有多步骤工作流亲和性。
	providerPreparation []byte
	// providerTaskSecretRef points to the protected upstream task identifier.
	// providerTaskSecretRef 指向受保护的上游任务标识。
	providerTaskSecretRef string
	// providerPreparationSecretRef points to the protected prepared-workflow handle.
	// providerPreparationSecretRef 指向受保护的准备工作流句柄。
	providerPreparationSecretRef string
	// createdSecretRefs contains values that must be removed if the SQL transaction fails.
	// createdSecretRefs 包含 SQL 事务失败时必须删除的值。
	createdSecretRefs []string
}

// executionSelect is the sole column order accepted by scanExecution.
// executionSelect 是 scanExecution 接受的唯一列顺序。
const executionSelect = `SELECT id, owner_api_key_id, request_hash, idempotency_key, status, operation, revision, created_at, updated_at, expires_at, request_payload, target_payload, result_payload, failure_payload, provider_task_payload, provider_preparation_payload, provider_task_secret_ref, provider_preparation_secret_ref FROM executions`

// rowScanner abstracts QueryRow and Rows without weakening typed record decoding.
// rowScanner 在不削弱类型化记录解码的情况下抽象 QueryRow 与 Rows。
type rowScanner interface {
	// Scan copies the exact selected columns into typed destinations.
	// Scan 将精确选中列复制到类型化目标。
	Scan(...any) error
}

// scanExecution decodes one exact executionSelect row.
// scanExecution 解码一行精确 executionSelect 结果。
func scanExecution(ctx context.Context, secrets secret.Store, scanner rowScanner) (execution.Record, error) {
	var record execution.Record
	var createdAt string
	var updatedAt string
	var expiresAt string
	var requestPayload []byte
	var targetPayload []byte
	var resultPayload []byte
	var failurePayload []byte
	var providerTaskPayload []byte
	var providerPreparationPayload []byte
	var providerTaskSecretRef sql.NullString
	var providerPreparationSecretRef sql.NullString
	errScan := scanner.Scan(&record.ID, &record.OwnerAPIKeyID, &record.RequestHash, &record.IdempotencyKey, &record.Status, &record.Operation, &record.Revision, &createdAt, &updatedAt, &expiresAt, &requestPayload, &targetPayload, &resultPayload, &failurePayload, &providerTaskPayload, &providerPreparationPayload, &providerTaskSecretRef, &providerPreparationSecretRef)
	if errScan != nil {
		return execution.Record{}, errScan
	}
	var errDecode error
	if record.CreatedAt, errDecode = parseExecutionTime(createdAt); errDecode != nil {
		return execution.Record{}, fmt.Errorf("decode execution created_at: %w", errDecode)
	}
	if record.UpdatedAt, errDecode = parseExecutionTime(updatedAt); errDecode != nil {
		return execution.Record{}, fmt.Errorf("decode execution updated_at: %w", errDecode)
	}
	if record.ExpiresAt, errDecode = parseExecutionTime(expiresAt); errDecode != nil {
		return execution.Record{}, fmt.Errorf("decode execution expires_at: %w", errDecode)
	}
	if errDecode = json.Unmarshal(requestPayload, &record.Request); errDecode != nil {
		return execution.Record{}, fmt.Errorf("decode execution request: %w", errDecode)
	}
	if errDecode = json.Unmarshal(targetPayload, &record.Target); errDecode != nil {
		return execution.Record{}, fmt.Errorf("decode execution target: %w", errDecode)
	}
	if len(resultPayload) > 0 {
		record.Result = &execution.Result{}
		if errDecode = json.Unmarshal(resultPayload, record.Result); errDecode != nil {
			return execution.Record{}, fmt.Errorf("decode execution result: %w", errDecode)
		}
	}
	if len(failurePayload) > 0 {
		record.Failure = &execution.Failure{}
		if errDecode = json.Unmarshal(failurePayload, record.Failure); errDecode != nil {
			return execution.Record{}, fmt.Errorf("decode execution failure: %w", errDecode)
		}
	}
	if len(providerTaskPayload) > 0 {
		var persistedTask executionProviderTaskPayload
		if errDecode = json.Unmarshal(providerTaskPayload, &persistedTask); errDecode != nil {
			return execution.Record{}, fmt.Errorf("decode execution provider task: %w", errDecode)
		}
		providerTaskID, errSecret := readExecutionSecret(ctx, secrets, providerTaskSecretRef.String, "provider task")
		if errSecret != nil {
			return execution.Record{}, errSecret
		}
		record.ProviderTask = &execution.ProviderTaskSnapshot{ProviderTaskID: providerTaskID, ProtectedTaskIDRef: providerTaskSecretRef.String, Target: persistedTask.Target, Definition: persistedTask.Definition, Endpoint: persistedTask.Endpoint, Credential: persistedTask.Credential, PollAfter: persistedTask.PollAfter, PollAttempts: persistedTask.PollAttempts}
	}
	if len(providerPreparationPayload) > 0 {
		var persistedPreparation executionProviderPreparationPayload
		if errDecode = json.Unmarshal(providerPreparationPayload, &persistedPreparation); errDecode != nil {
			return execution.Record{}, fmt.Errorf("decode execution provider preparation: %w", errDecode)
		}
		providerHandle, errSecret := readExecutionSecret(ctx, secrets, providerPreparationSecretRef.String, "provider preparation")
		if errSecret != nil {
			return execution.Record{}, errSecret
		}
		record.ProviderPreparation = &execution.ProviderPreparationSnapshot{ProviderHandle: providerHandle, ProtectedHandleRef: providerPreparationSecretRef.String, Target: persistedPreparation.Target, ExpiresAt: persistedPreparation.ExpiresAt}
	}
	return record, nil
}

// encodeExecutionRecord serializes only closed typed columns.
// encodeExecutionRecord 仅序列化封闭类型化列。
func encodeExecutionRecord(ctx context.Context, secrets secret.Store, record execution.Record) (executionEncodedRecord, error) {
	requestPayload, errRequest := json.Marshal(record.Request)
	if errRequest != nil {
		return executionEncodedRecord{}, fmt.Errorf("encode execution request: %w", errRequest)
	}
	targetPayload, errTarget := json.Marshal(record.Target)
	if errTarget != nil {
		return executionEncodedRecord{}, fmt.Errorf("encode execution target: %w", errTarget)
	}
	resultPayload, errResult := marshalOptional(record.Result)
	if errResult != nil {
		return executionEncodedRecord{}, fmt.Errorf("encode execution result: %w", errResult)
	}
	failurePayload, errFailure := marshalOptional(record.Failure)
	if errFailure != nil {
		return executionEncodedRecord{}, fmt.Errorf("encode execution failure: %w", errFailure)
	}
	providerTaskPayload, providerTaskSecretRef, taskSecretCreated, errTask := marshalProviderTask(ctx, secrets, record.ProviderTask)
	if errTask != nil {
		return executionEncodedRecord{}, fmt.Errorf("encode execution provider task: %w", errTask)
	}
	providerPreparationPayload, providerPreparationSecretRef, preparationSecretCreated, errPreparation := marshalProviderPreparation(ctx, secrets, record.ProviderPreparation)
	if errPreparation != nil {
		if taskSecretCreated {
			cleanupCreatedExecutionSecrets(ctx, secrets, []string{providerTaskSecretRef})
		}
		return executionEncodedRecord{}, fmt.Errorf("encode execution provider preparation: %w", errPreparation)
	}
	createdSecretRefs := make([]string, 0, 2)
	if taskSecretCreated {
		createdSecretRefs = append(createdSecretRefs, providerTaskSecretRef)
	}
	if preparationSecretCreated {
		createdSecretRefs = append(createdSecretRefs, providerPreparationSecretRef)
	}
	return executionEncodedRecord{request: requestPayload, target: targetPayload, result: resultPayload, failure: failurePayload, providerTask: providerTaskPayload, providerPreparation: providerPreparationPayload, providerTaskSecretRef: providerTaskSecretRef, providerPreparationSecretRef: providerPreparationSecretRef, createdSecretRefs: createdSecretRefs}, nil
}

// executionProviderTaskPayload is the private persisted asynchronous affinity shape.
// executionProviderTaskPayload 是私有持久化异步亲和性结构。
type executionProviderTaskPayload struct {
	// Target is the exact immutable provider affinity.
	// Target 是精确不可变供应商亲和性。
	Target resolve.Target `json:"target"`
	// Definition is the immutable provider driver definition snapshot.
	// Definition 是不可变供应商 Driver Definition 快照。
	Definition providerconfig.ProviderDefinition `json:"definition"`
	// Endpoint is the immutable provider endpoint snapshot.
	// Endpoint 是不可变供应商 Endpoint 快照。
	Endpoint providerconfig.Endpoint `json:"endpoint"`
	// Credential is the immutable non-secret credential snapshot.
	// Credential 是不可变非秘密 Credential 快照。
	Credential providerconfig.Credential `json:"credential"`
	// PollAfter is the earliest permitted poll.
	// PollAfter 是最早允许轮询时间。
	PollAfter time.Time `json:"poll_after"`
	// PollAttempts counts completed bounded polls.
	// PollAttempts 统计已完成有界轮询次数。
	PollAttempts uint32 `json:"poll_attempts"`
}

// executionProviderPreparationPayload is the private persisted prepared-workflow affinity shape.
// executionProviderPreparationPayload 是私有持久化准备工作流亲和性结构。
type executionProviderPreparationPayload struct {
	// Target is the immutable provider affinity that created the handle.
	// Target 是创建此句柄的不可变供应商亲和性。
	Target resolve.Target `json:"target"`
	// ExpiresAt is the provider-confirmed handle expiry.
	// ExpiresAt 是供应商确认的句柄过期时间。
	ExpiresAt time.Time `json:"expires_at"`
}

// marshalProviderTask preserves private task affinity while the public record hides upstream identifiers.
// marshalProviderTask 在公开记录隐藏上游标识的同时保留私有任务亲和性。
func marshalProviderTask(ctx context.Context, secrets secret.Store, task *execution.ProviderTaskSnapshot) ([]byte, string, bool, error) {
	if task == nil {
		return nil, "", false, nil
	}
	secretRef, created, errProtect := ensureExecutionSecret(ctx, secrets, task.ProtectedTaskIDRef, task.ProviderTaskID)
	if errProtect != nil {
		return nil, "", false, errProtect
	}
	payload, errMarshal := json.Marshal(executionProviderTaskPayload{Target: task.Target, Definition: task.Definition, Endpoint: task.Endpoint, Credential: task.Credential, PollAfter: task.PollAfter, PollAttempts: task.PollAttempts})
	if errMarshal != nil && created {
		cleanupCreatedExecutionSecrets(ctx, secrets, []string{secretRef})
	}
	return payload, secretRef, created, errMarshal
}

// marshalProviderPreparation preserves private prepared-workflow affinity while public results expose only Router identifiers.
// marshalProviderPreparation 在公开结果仅暴露 Router 标识的同时保留私有准备工作流亲和性。
func marshalProviderPreparation(ctx context.Context, secrets secret.Store, preparation *execution.ProviderPreparationSnapshot) ([]byte, string, bool, error) {
	if preparation == nil {
		return nil, "", false, nil
	}
	secretRef, created, errProtect := ensureExecutionSecret(ctx, secrets, preparation.ProtectedHandleRef, preparation.ProviderHandle)
	if errProtect != nil {
		return nil, "", false, errProtect
	}
	payload, errMarshal := json.Marshal(executionProviderPreparationPayload{Target: preparation.Target, ExpiresAt: preparation.ExpiresAt})
	if errMarshal != nil && created {
		cleanupCreatedExecutionSecrets(ctx, secrets, []string{secretRef})
	}
	return payload, secretRef, created, errMarshal
}

// ensureExecutionSecret reuses an exact protected reference or creates one for a new private handle.
// ensureExecutionSecret 复用精确受保护引用，或为新的私有句柄创建引用。
func ensureExecutionSecret(ctx context.Context, secrets secret.Store, existingReference string, plaintext string) (string, bool, error) {
	if plaintext == "" {
		return "", false, errors.New("execution provider handle is required")
	}
	if existingReference == "" {
		// plaintextBytes isolates the immutable string before SecretStore takes ownership of a copy.
		// plaintextBytes 在 SecretStore 获取副本所有权前隔离不可变字符串。
		plaintextBytes := []byte(plaintext)
		defer clear(plaintextBytes)
		reference, errPut := secrets.Put(ctx, plaintextBytes)
		if errPut != nil {
			return "", false, errPut
		}
		return reference, true, nil
	}
	protectedValue, errGet := secrets.Get(ctx, existingReference)
	defer clear(protectedValue)
	if errGet != nil {
		return "", false, errGet
	}
	// expectedValue is cleared after comparison so the immutable string does not create a retained byte slice.
	// expectedValue 会在比较后清理，避免不可变字符串产生被保留的字节切片。
	expectedValue := []byte(plaintext)
	defer clear(expectedValue)
	if !bytes.Equal(protectedValue, expectedValue) {
		return "", false, errors.New("execution provider handle changed for an existing protected reference")
	}
	return existingReference, false, nil
}

// readExecutionSecret resolves one required protected handle and clears the temporary byte buffer.
// readExecutionSecret 解析一个必需的受保护句柄并清理临时字节缓冲区。
func readExecutionSecret(ctx context.Context, secrets secret.Store, reference string, field string) (string, error) {
	if reference == "" {
		return "", fmt.Errorf("decode execution %s: protected reference is required", field)
	}
	value, errGet := secrets.Get(ctx, reference)
	defer clear(value)
	if errGet != nil {
		return "", fmt.Errorf("decode execution %s: %w", field, errGet)
	}
	if len(value) == 0 {
		return "", fmt.Errorf("decode execution %s: protected value is empty", field)
	}
	return string(value), nil
}

// assignExecutionSecretRefs retains repository-created references on the caller-visible in-memory snapshots.
// assignExecutionSecretRefs 在调用方可见的内存快照上保留 Repository 创建的引用。
func assignExecutionSecretRefs(record *execution.Record, encoded executionEncodedRecord) {
	if record.ProviderTask != nil {
		record.ProviderTask.ProtectedTaskIDRef = encoded.providerTaskSecretRef
	}
	if record.ProviderPreparation != nil {
		record.ProviderPreparation.ProtectedHandleRef = encoded.providerPreparationSecretRef
	}
}

// cleanupCreatedExecutionSecrets removes transaction-local values after a failed SQL write.
// cleanupCreatedExecutionSecrets 在 SQL 写入失败后删除事务局部值。
func cleanupCreatedExecutionSecrets(ctx context.Context, secrets secret.Store, references []string) {
	// cleanupContext must survive request cancellation after an SQL failure so no orphaned handle remains.
	// cleanupContext 必须在 SQL 失败后的请求取消中继续存活，避免遗留孤立句柄。
	cleanupContext := context.WithoutCancel(ctx)
	for _, reference := range references {
		if reference != "" {
			_ = secrets.Delete(cleanupContext, reference)
		}
	}
}

// deleteReplacedExecutionSecret removes an old protected value only after its SQL reference was committed away.
// deleteReplacedExecutionSecret 仅在 SQL 引用提交移除后删除旧受保护值。
func deleteReplacedExecutionSecret(ctx context.Context, secrets secret.Store, previousReference string, currentReference string) {
	if previousReference != "" && previousReference != currentReference {
		_ = secrets.Delete(context.WithoutCancel(ctx), previousReference)
	}
}

// nullString stores absent protected references as SQL NULL instead of ambiguous empty strings.
// nullString 将不存在的受保护引用保存为 SQL NULL，而非含糊的空字符串。
func nullString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

// marshalOptional preserves SQL NULL for absent typed payloads.
// marshalOptional 为不存在的类型化载荷保留 SQL NULL。
func marshalOptional(value any) ([]byte, error) {
	if value == nil {
		return nil, nil
	}
	return json.Marshal(value)
}

// insertExecutionEvents appends prevalidated ordered events inside the caller transaction.
// insertExecutionEvents 在调用方事务中追加已预校验有序事件。
func insertExecutionEvents(ctx context.Context, transaction *sql.Tx, events []execution.Event) error {
	for _, event := range events {
		payload, errEncode := json.Marshal(event)
		if errEncode != nil {
			return fmt.Errorf("encode execution event: %w", errEncode)
		}
		if _, errInsert := transaction.ExecContext(ctx, `INSERT INTO execution_events(execution_id, sequence, event_id, payload) VALUES (?, ?, ?, ?)`, event.ExecutionID, event.Sequence, event.EventID, payload); errInsert != nil {
			return fmt.Errorf("insert execution event: %w", errInsert)
		}
	}
	return nil
}

// getExecutionByIdempotency reads one exact owner-key binding inside a transaction.
// getExecutionByIdempotency 在事务内读取一个精确所有者键绑定。
func getExecutionByIdempotency(ctx context.Context, secrets secret.Store, transaction *sql.Tx, ownerAPIKeyID string, idempotencyKey string) (execution.Record, bool, error) {
	record, errScan := scanExecution(ctx, secrets, transaction.QueryRowContext(ctx, executionSelect+` WHERE owner_api_key_id = ? AND idempotency_key = ?`, ownerAPIKeyID, idempotencyKey))
	if errors.Is(errScan, sql.ErrNoRows) {
		return execution.Record{}, false, nil
	}
	if errScan != nil {
		return execution.Record{}, false, fmt.Errorf("read idempotent execution: %w", errScan)
	}
	return record, true, nil
}
