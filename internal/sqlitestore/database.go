// Package sqlitestore provides SQLite-backed configuration and catalog repositories.
// sqlitestore 包提供 SQLite 支持的配置与目录 Repository。
package sqlitestore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

const (
	// currentSchemaVersion is the latest schema migration understood by this binary.
	// currentSchemaVersion 是当前程序理解的最新 Schema 迁移版本。
	currentSchemaVersion = 1
)

var (
	// ErrSchemaTooNew reports a database created by a newer incompatible binary.
	// ErrSchemaTooNew 表示数据库由更新且不兼容的程序创建。
	ErrSchemaTooNew = errors.New("sqlite schema is newer than this binary")
)

// Database owns one migrated SQLite connection pool shared by repositories.
// Database 管理一个由多个 Repository 共享且已经迁移的 SQLite 连接池。
type Database struct {
	// sql is the initialized standard-library database handle.
	// sql 是已经初始化的标准库数据库句柄。
	sql *sql.DB
}

// Open creates or opens one SQLite file and applies all pending migrations.
// Open 创建或打开一个 SQLite 文件并应用全部待执行迁移。
func Open(ctx context.Context, path string) (*Database, error) {
	if ctx == nil {
		return nil, errors.New("context is required")
	}
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("sqlite path is required")
	}
	absolutePath, errAbsolute := filepath.Abs(path)
	if errAbsolute != nil {
		return nil, fmt.Errorf("resolve sqlite path: %w", errAbsolute)
	}
	if errMkdir := os.MkdirAll(filepath.Dir(absolutePath), 0o700); errMkdir != nil {
		return nil, fmt.Errorf("create sqlite parent directory: %w", errMkdir)
	}
	dsn := sqliteDSN(absolutePath)
	database, errOpen := sql.Open("sqlite", dsn)
	if errOpen != nil {
		return nil, fmt.Errorf("open sqlite database: %w", errOpen)
	}
	database.SetMaxOpenConns(4)
	database.SetMaxIdleConns(4)
	if errPing := database.PingContext(ctx); errPing != nil {
		_ = database.Close()
		return nil, fmt.Errorf("ping sqlite database: %w", errPing)
	}
	if _, errWAL := database.ExecContext(ctx, `PRAGMA journal_mode = WAL`); errWAL != nil {
		_ = database.Close()
		return nil, fmt.Errorf("enable sqlite WAL: %w", errWAL)
	}
	if errMigrate := migrate(ctx, database); errMigrate != nil {
		_ = database.Close()
		return nil, errMigrate
	}
	return &Database{sql: database}, nil
}

// Close releases the underlying SQLite connection pool.
// Close 释放底层 SQLite 连接池。
func (d *Database) Close() error {
	if d == nil || d.sql == nil {
		return nil
	}
	return d.sql.Close()
}

// SchemaVersion returns the applied schema migration version.
// SchemaVersion 返回已经应用的 Schema 迁移版本。
func (d *Database) SchemaVersion(ctx context.Context) (int, error) {
	if d == nil || d.sql == nil {
		return 0, errors.New("sqlite database is required")
	}
	if ctx == nil {
		return 0, errors.New("context is required")
	}
	var version int
	errQuery := d.sql.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&version)
	if errQuery != nil {
		return 0, fmt.Errorf("read sqlite schema version: %w", errQuery)
	}
	return version, nil
}

// sqliteDSN returns a file URI that configures every pooled connection consistently.
// sqliteDSN 返回一个为每个池化连接提供一致配置的文件 URI。
func sqliteDSN(absolutePath string) string {
	query := url.Values{}
	query.Add("_pragma", "busy_timeout(5000)")
	query.Add("_pragma", "foreign_keys(1)")
	query.Add("_dqs", "0")
	return "file:" + filepath.ToSlash(absolutePath) + "?" + query.Encode()
}

// migrate applies every missing schema version in one transaction.
// migrate 在一个事务中应用全部缺失的 Schema 版本。
func migrate(ctx context.Context, database *sql.DB) error {
	transaction, errBegin := database.BeginTx(ctx, nil)
	if errBegin != nil {
		return fmt.Errorf("begin sqlite migration: %w", errBegin)
	}
	defer func() {
		_ = transaction.Rollback()
	}()
	if _, errCreate := transaction.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at TEXT NOT NULL
		)`); errCreate != nil {
		return fmt.Errorf("create schema migration table: %w", errCreate)
	}
	var version int
	if errVersion := transaction.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&version); errVersion != nil {
		return fmt.Errorf("read current schema version: %w", errVersion)
	}
	if version > currentSchemaVersion {
		return fmt.Errorf("%w: database=%d binary=%d", ErrSchemaTooNew, version, currentSchemaVersion)
	}
	for nextVersion := version + 1; nextVersion <= currentSchemaVersion; nextVersion++ {
		if errMigration := applyMigration(ctx, transaction, nextVersion); errMigration != nil {
			return errMigration
		}
		if _, errRecord := transaction.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at) VALUES (?, CURRENT_TIMESTAMP)`, nextVersion); errRecord != nil {
			return fmt.Errorf("record schema migration %d: %w", nextVersion, errRecord)
		}
	}
	if errCommit := transaction.Commit(); errCommit != nil {
		return fmt.Errorf("commit sqlite migration: %w", errCommit)
	}
	return nil
}

// applyMigration executes one exact schema migration version.
// applyMigration 执行一个精确版本的 Schema 迁移。
func applyMigration(ctx context.Context, transaction *sql.Tx, version int) error {
	if version != 1 {
		return fmt.Errorf("unknown sqlite migration version %d", version)
	}
	statements := []string{
		`CREATE TABLE custom_provider_definitions (
			id TEXT PRIMARY KEY,
			revision INTEGER NOT NULL CHECK (revision > 0),
			payload BLOB NOT NULL
		)`,
		`CREATE TABLE provider_instances (
			id TEXT PRIMARY KEY,
			definition_id TEXT NOT NULL,
			handle TEXT NOT NULL UNIQUE,
			status TEXT NOT NULL,
			revision INTEGER NOT NULL CHECK (revision > 0),
			payload BLOB NOT NULL
		)`,
		`CREATE INDEX provider_instances_definition_idx ON provider_instances(definition_id)`,
		`CREATE TABLE provider_endpoints (
			id TEXT PRIMARY KEY,
			provider_instance_id TEXT NOT NULL REFERENCES provider_instances(id) ON DELETE RESTRICT,
			channel_id TEXT NOT NULL,
			status TEXT NOT NULL,
			revision INTEGER NOT NULL CHECK (revision > 0),
			payload BLOB NOT NULL
		)`,
		`CREATE INDEX provider_endpoints_instance_idx ON provider_endpoints(provider_instance_id)`,
		`CREATE TABLE provider_credentials (
			id TEXT PRIMARY KEY,
			provider_instance_id TEXT NOT NULL REFERENCES provider_instances(id) ON DELETE RESTRICT,
			auth_method_id TEXT NOT NULL,
			principal_key TEXT NOT NULL,
			fingerprint TEXT NOT NULL,
			status TEXT NOT NULL,
			revision INTEGER NOT NULL CHECK (revision > 0),
			payload BLOB NOT NULL,
			UNIQUE(provider_instance_id, fingerprint)
		)`,
		`CREATE UNIQUE INDEX provider_credentials_principal_idx ON provider_credentials(provider_instance_id, principal_key) WHERE principal_key <> ''`,
		`CREATE INDEX provider_credentials_instance_idx ON provider_credentials(provider_instance_id)`,
		`CREATE TABLE access_bindings (
			id TEXT PRIMARY KEY,
			provider_instance_id TEXT NOT NULL REFERENCES provider_instances(id) ON DELETE RESTRICT,
			channel_id TEXT NOT NULL,
			endpoint_id TEXT NOT NULL REFERENCES provider_endpoints(id) ON DELETE RESTRICT,
			credential_id TEXT NOT NULL REFERENCES provider_credentials(id) ON DELETE RESTRICT,
			priority INTEGER NOT NULL,
			enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
			revision INTEGER NOT NULL CHECK (revision > 0),
			payload BLOB NOT NULL
		)`,
		`CREATE INDEX access_bindings_instance_idx ON access_bindings(provider_instance_id, priority, id)`,
		`CREATE TABLE catalog_snapshots (
			provider_instance_id TEXT PRIMARY KEY REFERENCES provider_instances(id) ON DELETE RESTRICT,
			revision INTEGER NOT NULL CHECK (revision > 0),
			observed_at TEXT NOT NULL,
			payload BLOB NOT NULL
		)`,
	}
	for _, statement := range statements {
		if _, errExec := transaction.ExecContext(ctx, statement); errExec != nil {
			return fmt.Errorf("apply sqlite migration %d: %w", version, errExec)
		}
	}
	return nil
}
