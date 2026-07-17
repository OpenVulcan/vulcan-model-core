package sqlitestore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"

	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
)

// ConfigurationStore persists provider configuration while resolving system definitions from code.
// ConfigurationStore 持久化供应商配置，同时从代码解析系统定义。
type ConfigurationStore struct {
	// database owns the shared migrated SQLite connection pool.
	// database 管理共享且已经迁移的 SQLite 连接池。
	database *Database
	// protocols validates custom definitions against executable protocol metadata.
	// protocols 根据可执行协议元数据校验自定义定义。
	protocols *providerconfig.ProtocolRegistry
	// systems resolves immutable code-owned system provider definitions.
	// systems 解析代码拥有的不可变系统供应商定义。
	systems *providerconfig.SystemRegistry
}

// NewConfigurationStore creates a SQLite-backed provider configuration repository.
// NewConfigurationStore 创建一个 SQLite 支持的供应商配置 Repository。
func NewConfigurationStore(database *Database, protocols *providerconfig.ProtocolRegistry, systems *providerconfig.SystemRegistry) (*ConfigurationStore, error) {
	if database == nil || database.sql == nil || protocols == nil || systems == nil {
		return nil, errors.New("sqlite database and provider registries are required")
	}
	return &ConfigurationStore{database: database, protocols: protocols, systems: systems}, nil
}

// SaveCustomDefinition creates or updates one validated custom provider definition.
// SaveCustomDefinition 创建或更新一个经过校验的自定义供应商定义。
func (s *ConfigurationStore) SaveCustomDefinition(ctx context.Context, definition providerconfig.ProviderDefinition) error {
	if err := validateContext(ctx); err != nil {
		return err
	}
	if err := providerconfig.ValidateCustomDefinition(definition, s.protocols); err != nil {
		return err
	}
	payload, errPayload := marshalPayload(definition)
	if errPayload != nil {
		return errPayload
	}
	return s.saveRevisioned(ctx, `
		INSERT INTO custom_provider_definitions(id, revision, payload) VALUES (?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET revision = excluded.revision, payload = excluded.payload
		WHERE excluded.revision > custom_provider_definitions.revision`, definition.ID, definition.Revision, "custom provider definition", payload)
}

// GetDefinition resolves one immutable system or persisted custom provider definition.
// GetDefinition 解析一个不可变系统或已持久化自定义供应商定义。
func (s *ConfigurationStore) GetDefinition(ctx context.Context, definitionID string) (providerconfig.ProviderDefinition, error) {
	if err := validateContext(ctx); err != nil {
		return providerconfig.ProviderDefinition{}, err
	}
	if definition, exists := s.systems.Lookup(definitionID); exists {
		return definition, nil
	}
	var payload []byte
	errQuery := s.database.sql.QueryRowContext(ctx, `SELECT payload FROM custom_provider_definitions WHERE id = ?`, definitionID).Scan(&payload)
	if errors.Is(errQuery, sql.ErrNoRows) {
		return providerconfig.ProviderDefinition{}, fmt.Errorf("%w: provider definition %s", providerconfig.ErrNotFound, definitionID)
	}
	if errQuery != nil {
		return providerconfig.ProviderDefinition{}, fmt.Errorf("query provider definition: %w", errQuery)
	}
	var definition providerconfig.ProviderDefinition
	if errDecode := unmarshalPayload(payload, &definition); errDecode != nil {
		return providerconfig.ProviderDefinition{}, errDecode
	}
	if errValidate := providerconfig.ValidateCustomDefinition(definition, s.protocols); errValidate != nil {
		return providerconfig.ProviderDefinition{}, fmt.Errorf("validate persisted custom provider definition: %w", errValidate)
	}
	return definition, nil
}

// ListDefinitions returns stable system and custom provider definition snapshots.
// ListDefinitions 返回稳定的系统与自定义供应商定义快照。
func (s *ConfigurationStore) ListDefinitions(ctx context.Context) ([]providerconfig.ProviderDefinition, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	definitions := s.systems.List()
	rows, errQuery := s.database.sql.QueryContext(ctx, `SELECT payload FROM custom_provider_definitions ORDER BY id`)
	if errQuery != nil {
		return nil, fmt.Errorf("list custom provider definitions: %w", errQuery)
	}
	defer closeRows(rows)
	for rows.Next() {
		var payload []byte
		if errScan := rows.Scan(&payload); errScan != nil {
			return nil, fmt.Errorf("scan custom provider definition: %w", errScan)
		}
		var definition providerconfig.ProviderDefinition
		if errDecode := unmarshalPayload(payload, &definition); errDecode != nil {
			return nil, errDecode
		}
		if errValidate := providerconfig.ValidateCustomDefinition(definition, s.protocols); errValidate != nil {
			return nil, fmt.Errorf("validate persisted custom provider definition: %w", errValidate)
		}
		definitions = append(definitions, definition)
	}
	if errRows := rows.Err(); errRows != nil {
		return nil, fmt.Errorf("iterate custom provider definitions: %w", errRows)
	}
	sort.Slice(definitions, func(left int, right int) bool {
		return definitions[left].ID < definitions[right].ID
	})
	return definitions, nil
}

// SaveInstance creates or updates one provider instance with revision and handle checks.
// SaveInstance 使用修订号和 Handle 校验创建或更新供应商实例。
func (s *ConfigurationStore) SaveInstance(ctx context.Context, instance providerconfig.ProviderInstance) error {
	if err := validateContext(ctx); err != nil {
		return err
	}
	if err := instance.Validate(); err != nil {
		return err
	}
	definition, errDefinition := s.GetDefinition(ctx, instance.DefinitionID)
	if errDefinition != nil {
		return errDefinition
	}
	if instance.DefinitionRevision != definition.Revision {
		return invalidConfiguration("provider instance definition revision does not match current definition")
	}
	var conflictingID string
	errConflict := s.database.sql.QueryRowContext(ctx, `SELECT id FROM provider_instances WHERE handle = ? AND id <> ?`, instance.Handle, instance.ID).Scan(&conflictingID)
	if errConflict == nil {
		return fmt.Errorf("%w: provider handle %s", providerconfig.ErrAlreadyRegistered, instance.Handle)
	}
	if !errors.Is(errConflict, sql.ErrNoRows) {
		return fmt.Errorf("check provider handle: %w", errConflict)
	}
	payload, errPayload := marshalPayload(instance)
	if errPayload != nil {
		return errPayload
	}
	return s.saveRevisioned(ctx, `
		INSERT INTO provider_instances(id, definition_id, handle, status, revision, payload) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET definition_id = excluded.definition_id, handle = excluded.handle,
		status = excluded.status, revision = excluded.revision, payload = excluded.payload
		WHERE excluded.revision > provider_instances.revision`, instance.ID, instance.Revision, "provider instance", payload, instance.DefinitionID, instance.Handle, instance.Status)
}

// GetInstance returns one persisted provider instance.
// GetInstance 返回一个已经持久化的供应商实例。
func (s *ConfigurationStore) GetInstance(ctx context.Context, instanceID string) (providerconfig.ProviderInstance, error) {
	var instance providerconfig.ProviderInstance
	errGet := s.getPayload(ctx, `SELECT payload FROM provider_instances WHERE id = ?`, instanceID, &instance)
	if errors.Is(errGet, sql.ErrNoRows) {
		return providerconfig.ProviderInstance{}, fmt.Errorf("%w: provider instance %s", providerconfig.ErrNotFound, instanceID)
	}
	if errGet != nil {
		return providerconfig.ProviderInstance{}, fmt.Errorf("query provider instance: %w", errGet)
	}
	if errValidate := instance.Validate(); errValidate != nil {
		return providerconfig.ProviderInstance{}, fmt.Errorf("validate persisted provider instance: %w", errValidate)
	}
	return instance, nil
}

// ListInstances returns stable provider instance snapshots with an optional definition filter.
// ListInstances 返回稳定的供应商实例快照，并可选择按定义筛选。
func (s *ConfigurationStore) ListInstances(ctx context.Context, definitionID string) ([]providerconfig.ProviderInstance, error) {
	query := `SELECT payload FROM provider_instances ORDER BY id`
	arguments := []any(nil)
	if definitionID != "" {
		query = `SELECT payload FROM provider_instances WHERE definition_id = ? ORDER BY id`
		arguments = []any{definitionID}
	}
	return listPayloads[providerconfig.ProviderInstance](ctx, s.database.sql, query, arguments, func(instance providerconfig.ProviderInstance) error {
		return instance.Validate()
	})
}

// SaveEndpoint creates or updates one endpoint owned by an existing provider channel.
// SaveEndpoint 创建或更新一个由现有供应商通道拥有的端点。
func (s *ConfigurationStore) SaveEndpoint(ctx context.Context, endpoint providerconfig.Endpoint) error {
	if err := validateContext(ctx); err != nil {
		return err
	}
	if err := endpoint.Validate(); err != nil {
		return err
	}
	instance, definition, errOwner := s.instanceDefinition(ctx, endpoint.ProviderInstanceID)
	if errOwner != nil {
		return errOwner
	}
	if instance.ID == "" || !definition.HasChannel(endpoint.ChannelID) {
		return invalidConfiguration("endpoint references channel outside its provider definition")
	}
	payload, errPayload := marshalPayload(endpoint)
	if errPayload != nil {
		return errPayload
	}
	return s.saveRevisioned(ctx, `
		INSERT INTO provider_endpoints(id, provider_instance_id, channel_id, status, revision, payload) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET provider_instance_id = excluded.provider_instance_id, channel_id = excluded.channel_id,
		status = excluded.status, revision = excluded.revision, payload = excluded.payload
		WHERE excluded.revision > provider_endpoints.revision`, endpoint.ID, endpoint.Revision, "provider endpoint", payload, endpoint.ProviderInstanceID, endpoint.ChannelID, endpoint.Status)
}

// ListEndpoints returns stable endpoint snapshots for one provider instance.
// ListEndpoints 返回一个供应商实例的稳定端点快照。
func (s *ConfigurationStore) ListEndpoints(ctx context.Context, instanceID string) ([]providerconfig.Endpoint, error) {
	return listPayloads[providerconfig.Endpoint](ctx, s.database.sql, `SELECT payload FROM provider_endpoints WHERE provider_instance_id = ? ORDER BY id`, []any{instanceID}, func(endpoint providerconfig.Endpoint) error {
		return endpoint.Validate()
	})
}

// SaveCredential creates or updates non-secret credential metadata with duplicate checks.
// SaveCredential 使用排重校验创建或更新非秘密凭据元数据。
func (s *ConfigurationStore) SaveCredential(ctx context.Context, credential providerconfig.Credential) error {
	if err := validateContext(ctx); err != nil {
		return err
	}
	if err := credential.Validate(); err != nil {
		return err
	}
	_, definition, errOwner := s.instanceDefinition(ctx, credential.ProviderInstanceID)
	if errOwner != nil {
		return errOwner
	}
	if !definition.HasAuthMethod(credential.AuthMethodID) {
		return invalidConfiguration("credential references auth method outside its provider definition")
	}
	if errDuplicate := s.checkCredentialDuplicate(ctx, credential); errDuplicate != nil {
		return errDuplicate
	}
	payload, errPayload := marshalPayload(credential)
	if errPayload != nil {
		return errPayload
	}
	return s.saveRevisioned(ctx, `
		INSERT INTO provider_credentials(id, provider_instance_id, auth_method_id, principal_key, fingerprint, status, revision, payload)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET provider_instance_id = excluded.provider_instance_id, auth_method_id = excluded.auth_method_id,
		principal_key = excluded.principal_key, fingerprint = excluded.fingerprint, status = excluded.status,
		revision = excluded.revision, payload = excluded.payload
		WHERE excluded.revision > provider_credentials.revision`, credential.ID, credential.Revision, "provider credential", payload,
		credential.ProviderInstanceID, credential.AuthMethodID, credential.PrincipalKey, credential.Fingerprint, credential.Status)
}

// ListCredentials returns stable non-secret credential snapshots for one provider instance.
// ListCredentials 返回一个供应商实例稳定的非秘密凭据快照。
func (s *ConfigurationStore) ListCredentials(ctx context.Context, instanceID string) ([]providerconfig.Credential, error) {
	return listPayloads[providerconfig.Credential](ctx, s.database.sql, `SELECT payload FROM provider_credentials WHERE provider_instance_id = ? ORDER BY id`, []any{instanceID}, func(credential providerconfig.Credential) error {
		return credential.Validate()
	})
}

// SaveBinding creates or updates one same-instance endpoint and credential binding.
// SaveBinding 创建或更新一个同实例端点与凭据绑定。
func (s *ConfigurationStore) SaveBinding(ctx context.Context, binding providerconfig.AccessBinding) error {
	if err := validateContext(ctx); err != nil {
		return err
	}
	if err := binding.Validate(); err != nil {
		return err
	}
	_, definition, errOwner := s.instanceDefinition(ctx, binding.ProviderInstanceID)
	if errOwner != nil {
		return errOwner
	}
	if !definition.HasChannel(binding.ChannelID) {
		return invalidConfiguration("access binding references channel outside its provider definition")
	}
	endpoint, errEndpoint := s.getEndpoint(ctx, binding.EndpointID)
	if errEndpoint != nil {
		return errEndpoint
	}
	credential, errCredential := s.getCredential(ctx, binding.CredentialID)
	if errCredential != nil {
		return errCredential
	}
	if endpoint.ProviderInstanceID != binding.ProviderInstanceID || credential.ProviderInstanceID != binding.ProviderInstanceID {
		return invalidConfiguration("access binding cannot cross provider instances")
	}
	if endpoint.ChannelID != binding.ChannelID || !definition.ChannelAllowsAuth(binding.ChannelID, credential.AuthMethodID) {
		return invalidConfiguration("access binding channel is incompatible with endpoint or credential auth method")
	}
	payload, errPayload := marshalPayload(binding)
	if errPayload != nil {
		return errPayload
	}
	enabled := 0
	if binding.Enabled {
		enabled = 1
	}
	return s.saveRevisioned(ctx, `
		INSERT INTO access_bindings(id, provider_instance_id, channel_id, endpoint_id, credential_id, priority, enabled, revision, payload)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET provider_instance_id = excluded.provider_instance_id, channel_id = excluded.channel_id,
		endpoint_id = excluded.endpoint_id, credential_id = excluded.credential_id, priority = excluded.priority,
		enabled = excluded.enabled, revision = excluded.revision, payload = excluded.payload
		WHERE excluded.revision > access_bindings.revision`, binding.ID, binding.Revision, "access binding", payload,
		binding.ProviderInstanceID, binding.ChannelID, binding.EndpointID, binding.CredentialID, binding.Priority, enabled)
}

// ListBindings returns stable access binding snapshots for one provider instance.
// ListBindings 返回一个供应商实例的稳定访问绑定快照。
func (s *ConfigurationStore) ListBindings(ctx context.Context, instanceID string) ([]providerconfig.AccessBinding, error) {
	return listPayloads[providerconfig.AccessBinding](ctx, s.database.sql, `SELECT payload FROM access_bindings WHERE provider_instance_id = ? ORDER BY priority, id`, []any{instanceID}, func(binding providerconfig.AccessBinding) error {
		return binding.Validate()
	})
}

// instanceDefinition resolves the exact persisted instance and its current definition.
// instanceDefinition 解析精确持久化实例及其当前定义。
func (s *ConfigurationStore) instanceDefinition(ctx context.Context, instanceID string) (providerconfig.ProviderInstance, providerconfig.ProviderDefinition, error) {
	instance, errInstance := s.GetInstance(ctx, instanceID)
	if errInstance != nil {
		return providerconfig.ProviderInstance{}, providerconfig.ProviderDefinition{}, errInstance
	}
	definition, errDefinition := s.GetDefinition(ctx, instance.DefinitionID)
	if errDefinition != nil {
		return providerconfig.ProviderInstance{}, providerconfig.ProviderDefinition{}, errDefinition
	}
	return instance, definition, nil
}

// checkCredentialDuplicate enforces instance-scoped fingerprint and principal uniqueness.
// checkCredentialDuplicate 强制执行实例作用域的指纹与账号身份唯一性。
func (s *ConfigurationStore) checkCredentialDuplicate(ctx context.Context, credential providerconfig.Credential) error {
	var conflictingID string
	errFingerprint := s.database.sql.QueryRowContext(ctx, `
		SELECT id FROM provider_credentials WHERE provider_instance_id = ? AND fingerprint = ? AND id <> ?`,
		credential.ProviderInstanceID, credential.Fingerprint, credential.ID).Scan(&conflictingID)
	if errFingerprint == nil {
		return fmt.Errorf("%w: credential fingerprint", providerconfig.ErrAlreadyRegistered)
	}
	if !errors.Is(errFingerprint, sql.ErrNoRows) {
		return fmt.Errorf("check credential fingerprint: %w", errFingerprint)
	}
	if credential.PrincipalKey == "" {
		return nil
	}
	errPrincipal := s.database.sql.QueryRowContext(ctx, `
		SELECT id FROM provider_credentials WHERE provider_instance_id = ? AND principal_key = ? AND id <> ?`,
		credential.ProviderInstanceID, credential.PrincipalKey, credential.ID).Scan(&conflictingID)
	if errPrincipal == nil {
		return fmt.Errorf("%w: credential principal", providerconfig.ErrAlreadyRegistered)
	}
	if !errors.Is(errPrincipal, sql.ErrNoRows) {
		return fmt.Errorf("check credential principal: %w", errPrincipal)
	}
	return nil
}

// getEndpoint returns one validated endpoint by identifier.
// getEndpoint 按标识返回一个经过校验的端点。
func (s *ConfigurationStore) getEndpoint(ctx context.Context, endpointID string) (providerconfig.Endpoint, error) {
	var endpoint providerconfig.Endpoint
	errGet := s.getPayload(ctx, `SELECT payload FROM provider_endpoints WHERE id = ?`, endpointID, &endpoint)
	if errors.Is(errGet, sql.ErrNoRows) {
		return providerconfig.Endpoint{}, fmt.Errorf("%w: provider endpoint %s", providerconfig.ErrNotFound, endpointID)
	}
	if errGet != nil {
		return providerconfig.Endpoint{}, fmt.Errorf("query provider endpoint: %w", errGet)
	}
	if errValidate := endpoint.Validate(); errValidate != nil {
		return providerconfig.Endpoint{}, fmt.Errorf("validate persisted provider endpoint: %w", errValidate)
	}
	return endpoint, nil
}

// getCredential returns one validated non-secret credential by identifier.
// getCredential 按标识返回一个经过校验的非秘密凭据。
func (s *ConfigurationStore) getCredential(ctx context.Context, credentialID string) (providerconfig.Credential, error) {
	var credential providerconfig.Credential
	errGet := s.getPayload(ctx, `SELECT payload FROM provider_credentials WHERE id = ?`, credentialID, &credential)
	if errors.Is(errGet, sql.ErrNoRows) {
		return providerconfig.Credential{}, fmt.Errorf("%w: provider credential %s", providerconfig.ErrNotFound, credentialID)
	}
	if errGet != nil {
		return providerconfig.Credential{}, fmt.Errorf("query provider credential: %w", errGet)
	}
	if errValidate := credential.Validate(); errValidate != nil {
		return providerconfig.Credential{}, fmt.Errorf("validate persisted provider credential: %w", errValidate)
	}
	return credential, nil
}

// getPayload reads and decodes one typed JSON payload.
// getPayload 读取并解码一个强类型 JSON Payload。
func (s *ConfigurationStore) getPayload(ctx context.Context, query string, identifier string, destination any) error {
	if err := validateContext(ctx); err != nil {
		return err
	}
	var payload []byte
	if errQuery := s.database.sql.QueryRowContext(ctx, query, identifier).Scan(&payload); errQuery != nil {
		return errQuery
	}
	return unmarshalPayload(payload, destination)
}

// saveRevisioned executes one optimistic revision upsert and rejects stale writes.
// saveRevisioned 执行一次乐观修订号 Upsert 并拒绝过期写入。
func (s *ConfigurationStore) saveRevisioned(ctx context.Context, query string, identifier string, revision uint64, entityName string, payload []byte, valuesBeforeRevision ...any) error {
	if revision > math.MaxInt64 {
		return invalidConfiguration("revision exceeds SQLite integer range")
	}
	if entityName == "" {
		return errors.New("revisioned save entity name is required")
	}
	queryArguments := make([]any, 0, len(valuesBeforeRevision)+3)
	queryArguments = append(queryArguments, identifier)
	queryArguments = append(queryArguments, valuesBeforeRevision...)
	queryArguments = append(queryArguments, int64(revision), payload)
	result, errExec := s.database.sql.ExecContext(ctx, query, queryArguments...)
	if errExec != nil {
		return fmt.Errorf("save %s: %w", entityName, errExec)
	}
	rowsAffected, errRows := result.RowsAffected()
	if errRows != nil {
		return fmt.Errorf("read %s write result: %w", entityName, errRows)
	}
	if rowsAffected != 1 {
		return invalidConfiguration("%s revision must increase", entityName)
	}
	return nil
}

// listPayloads reads, validates, and returns stable typed payloads.
// listPayloads 读取、校验并返回稳定的强类型 Payload。
func listPayloads[T any](ctx context.Context, database *sql.DB, query string, arguments []any, validate func(T) error) ([]T, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	rows, errQuery := database.QueryContext(ctx, query, arguments...)
	if errQuery != nil {
		return nil, fmt.Errorf("list persisted records: %w", errQuery)
	}
	defer closeRows(rows)
	records := make([]T, 0)
	for rows.Next() {
		var payload []byte
		if errScan := rows.Scan(&payload); errScan != nil {
			return nil, fmt.Errorf("scan persisted record: %w", errScan)
		}
		var record T
		if errDecode := unmarshalPayload(payload, &record); errDecode != nil {
			return nil, errDecode
		}
		if errValidate := validate(record); errValidate != nil {
			return nil, fmt.Errorf("validate persisted record: %w", errValidate)
		}
		records = append(records, record)
	}
	if errRows := rows.Err(); errRows != nil {
		return nil, fmt.Errorf("iterate persisted records: %w", errRows)
	}
	return records, nil
}

// marshalPayload encodes one validated domain value for durable storage.
// marshalPayload 编码一个经过校验的领域值以便持久化。
func marshalPayload(value any) ([]byte, error) {
	payload, errMarshal := json.Marshal(value)
	if errMarshal != nil {
		return nil, fmt.Errorf("encode sqlite payload: %w", errMarshal)
	}
	return payload, nil
}

// unmarshalPayload decodes one persisted typed domain value.
// unmarshalPayload 解码一个已经持久化的强类型领域值。
func unmarshalPayload(payload []byte, destination any) error {
	if errDecode := json.Unmarshal(payload, destination); errDecode != nil {
		return fmt.Errorf("decode sqlite payload: %w", errDecode)
	}
	return nil
}

// validateContext rejects absent or already-cancelled operation contexts.
// validateContext 拒绝缺失或已经取消的操作 Context。
func validateContext(ctx context.Context) error {
	if ctx == nil {
		return errors.New("context is required")
	}
	return ctx.Err()
}

// invalidConfiguration creates one provider configuration validation error.
// invalidConfiguration 创建一个供应商配置校验错误。
func invalidConfiguration(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", providerconfig.ErrInvalidConfiguration, fmt.Sprintf(format, arguments...))
}

// closeRows closes query rows without hiding a primary operation error.
// closeRows 关闭查询结果且不隐藏主要操作错误。
func closeRows(rows *sql.Rows) {
	_ = rows.Close()
}
