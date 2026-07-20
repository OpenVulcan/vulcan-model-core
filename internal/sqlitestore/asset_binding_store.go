package sqlitestore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
)

// AssetBindingStore persists exact-target provider asset bindings without upstream handles.
// AssetBindingStore 持久化不含上游句柄的精确 Target 供应商资产绑定。
type AssetBindingStore struct {
	// database owns the shared migrated SQLite connection pool.
	// database 管理共享且已迁移的 SQLite 连接池。
	database *Database
}

// NewAssetBindingStore creates a SQLite-backed asset-binding repository.
// NewAssetBindingStore 创建一个由 SQLite 支持的资产绑定仓库。
func NewAssetBindingStore(database *Database) (*AssetBindingStore, error) {
	if database == nil || database.sql == nil {
		return nil, errors.New("sqlite database is required")
	}
	return &AssetBindingStore{database: database}, nil
}

// Save creates one validated immutable provider asset binding.
// Save 创建一个已校验不可变供应商资产绑定。
func (s *AssetBindingStore) Save(ctx context.Context, binding resource.ProviderAssetBinding) error {
	if errContext := validateContext(ctx); errContext != nil {
		return errContext
	}
	if errValidate := binding.Validate(); errValidate != nil {
		return errValidate
	}
	payload, errPayload := marshalPayload(binding)
	if errPayload != nil {
		return errPayload
	}
	target := binding.Target
	_, errExec := s.database.sql.ExecContext(ctx, `INSERT INTO provider_asset_bindings(id, resource_id, resource_sha256, provider_definition_id, provider_instance_id, endpoint_id, region, credential_id, action_binding_id, provider_model_id, upstream_model_id, materialization, expires_at, payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, binding.ID, binding.ResourceID, binding.ResourceSHA256, target.ProviderDefinitionID, target.ProviderInstanceID, target.EndpointID, target.Region, target.CredentialID, target.ActionBindingID, target.ProviderModelID, target.UpstreamModelID, binding.Materialization, nullableTime(binding.ExpiresAt), payload)
	if errExec != nil {
		return fmt.Errorf("%w: save provider asset binding", resource.ErrInvalidAssetBinding)
	}
	return nil
}

// FindExact returns the newest live binding for every exact target identity.
// FindExact 为每项精确 Target 身份返回最新有效绑定。
func (s *AssetBindingStore) FindExact(ctx context.Context, resourceID string, resourceHash string, target resource.AssetBindingTarget, mode catalog.UpstreamMaterializationMode, now time.Time) (resource.ProviderAssetBinding, error) {
	if errContext := validateContext(ctx); errContext != nil {
		return resource.ProviderAssetBinding{}, errContext
	}
	var payload []byte
	errQuery := s.database.sql.QueryRowContext(ctx, `SELECT payload FROM provider_asset_bindings WHERE resource_id = ? AND resource_sha256 = ? AND provider_definition_id = ? AND provider_instance_id = ? AND endpoint_id = ? AND region = ? AND credential_id = ? AND action_binding_id = ? AND provider_model_id = ? AND upstream_model_id = ? AND materialization = ? AND (expires_at IS NULL OR expires_at > ?) ORDER BY id LIMIT 1`, resourceID, resourceHash, target.ProviderDefinitionID, target.ProviderInstanceID, target.EndpointID, target.Region, target.CredentialID, target.ActionBindingID, target.ProviderModelID, target.UpstreamModelID, mode, now.UTC().Format(sqliteTimeLayout)).Scan(&payload)
	if errors.Is(errQuery, sql.ErrNoRows) {
		return resource.ProviderAssetBinding{}, resource.ErrAssetBindingNotFound
	}
	if errQuery != nil {
		return resource.ProviderAssetBinding{}, fmt.Errorf("query exact provider asset binding: %w", errQuery)
	}
	var binding resource.ProviderAssetBinding
	if errDecode := unmarshalPayload(payload, &binding); errDecode != nil {
		return resource.ProviderAssetBinding{}, errDecode
	}
	if errValidate := binding.Validate(); errValidate != nil {
		return resource.ProviderAssetBinding{}, fmt.Errorf("validate persisted asset binding: %w", errValidate)
	}
	return binding, nil
}

// DeleteByResource removes every provider binding for one Router resource.
// DeleteByResource 移除一个 Router 资源的每个供应商绑定。
func (s *AssetBindingStore) DeleteByResource(ctx context.Context, resourceID string) error {
	if errContext := validateContext(ctx); errContext != nil {
		return errContext
	}
	if _, errExec := s.database.sql.ExecContext(ctx, `DELETE FROM provider_asset_bindings WHERE resource_id = ?`, resourceID); errExec != nil {
		return fmt.Errorf("delete provider asset bindings: %w", errExec)
	}
	return nil
}

// CleanupResourceBindings satisfies resource lifecycle cleanup.
// CleanupResourceBindings 满足资源生命周期清理。
func (s *AssetBindingStore) CleanupResourceBindings(ctx context.Context, resourceID string) error {
	return s.DeleteByResource(ctx, resourceID)
}
