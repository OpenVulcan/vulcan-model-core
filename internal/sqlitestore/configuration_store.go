package sqlitestore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
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

// ListProviderGroups returns immutable code-owned management groups without querying SQLite.
// ListProviderGroups 返回不可变的代码拥有管理分组，且不查询 SQLite。
func (s *ConfigurationStore) ListProviderGroups(ctx context.Context) ([]providerconfig.ProviderGroup, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	return s.systems.ListGroups(), nil
}

// NewConfigurationStore creates a SQLite-backed provider configuration repository.
// NewConfigurationStore 创建一个 SQLite 支持的供应商配置 Repository。
func NewConfigurationStore(database *Database, protocols *providerconfig.ProtocolRegistry, systems *providerconfig.SystemRegistry) (*ConfigurationStore, error) {
	if database == nil || database.sql == nil || protocols == nil || systems == nil {
		return nil, errors.New("sqlite database and provider registries are required")
	}
	return &ConfigurationStore{database: database, protocols: protocols, systems: systems}, nil
}

// SaveCustomDefinition creates one validated custom provider definition; replacements require an atomic migration.
// SaveCustomDefinition 创建一个经过校验的自定义供应商定义；替换必须使用原子迁移。
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
	if definition.Revision > math.MaxInt64 {
		return invalidConfiguration("custom provider definition revision exceeds SQLite integer range")
	}
	result, errInsert := s.database.sql.ExecContext(ctx, `
		INSERT INTO custom_provider_definitions(id, revision, payload) VALUES (?, ?, ?)
		ON CONFLICT(id) DO NOTHING`, definition.ID, int64(definition.Revision), payload)
	if errInsert != nil {
		return fmt.Errorf("save custom provider definition: %w", errInsert)
	}
	rowsAffected, errRows := result.RowsAffected()
	if errRows != nil {
		return fmt.Errorf("read custom provider definition write result: %w", errRows)
	}
	if rowsAffected != 1 {
		return fmt.Errorf("%w: provider definition %s", providerconfig.ErrAlreadyRegistered, definition.ID)
	}
	return nil
}

// SaveCustomDefinitionMigration atomically replaces one custom definition and transitions every owned instance in SQLite.
// SaveCustomDefinitionMigration 在 SQLite 中原子替换一个自定义定义并转换其拥有的全部实例。
func (s *ConfigurationStore) SaveCustomDefinitionMigration(ctx context.Context, migration providerconfig.CustomDefinitionMigration) error {
	if err := validateContext(ctx); err != nil {
		return err
	}
	currentDefinition, errDefinition := s.GetDefinition(ctx, migration.Definition.ID)
	if errDefinition != nil {
		return errDefinition
	}
	currentInstances, errInstances := s.ListInstances(ctx, migration.Definition.ID)
	if errInstances != nil {
		return errInstances
	}
	if errMigration := providerconfig.ValidateCustomDefinitionMigration(migration, currentDefinition, currentInstances, s.protocols); errMigration != nil {
		return errMigration
	}
	if migration.Definition.Revision > math.MaxInt64 {
		return invalidConfiguration("custom provider definition revision exceeds SQLite integer range")
	}
	definitionPayload, errPayload := marshalPayload(migration.Definition)
	if errPayload != nil {
		return errPayload
	}
	// instancePayloads and currentRevisions preserve validated values across the transaction boundary.
	// instancePayloads 与 currentRevisions 跨事务边界保留经过校验的值。
	instancePayloads := make(map[string][]byte, len(migration.Instances))
	currentRevisions := make(map[string]uint64, len(currentInstances))
	for _, current := range currentInstances {
		currentRevisions[current.ID] = current.Revision
	}
	for _, instance := range migration.Instances {
		if instance.Revision > math.MaxInt64 {
			return invalidConfiguration("provider instance revision exceeds SQLite integer range")
		}
		payload, errInstancePayload := marshalPayload(instance)
		if errInstancePayload != nil {
			return errInstancePayload
		}
		instancePayloads[instance.ID] = payload
	}
	transaction, errTransaction := s.database.sql.BeginTx(ctx, nil)
	if errTransaction != nil {
		return fmt.Errorf("begin custom definition migration transaction: %w", errTransaction)
	}
	defer func() { _ = transaction.Rollback() }()
	definitionResult, errDefinitionUpdate := transaction.ExecContext(ctx, `
		UPDATE custom_provider_definitions SET revision = ?, payload = ?
		WHERE id = ? AND revision = ?`, int64(migration.Definition.Revision), definitionPayload, migration.Definition.ID, int64(currentDefinition.Revision))
	if errDefinitionUpdate != nil {
		return fmt.Errorf("update custom provider definition migration: %w", errDefinitionUpdate)
	}
	if errResult := requireSingleMutation(definitionResult, "custom provider definition migration"); errResult != nil {
		return errResult
	}
	var persistedInstanceCount int
	if errCount := transaction.QueryRowContext(ctx, `SELECT COUNT(*) FROM provider_instances WHERE definition_id = ?`, migration.Definition.ID).Scan(&persistedInstanceCount); errCount != nil {
		return fmt.Errorf("count custom definition migration instances: %w", errCount)
	}
	if persistedInstanceCount != len(migration.Instances) {
		return invalidConfiguration("custom definition migration instance set changed concurrently")
	}
	for _, instance := range migration.Instances {
		instanceResult, errInstanceUpdate := transaction.ExecContext(ctx, `
			UPDATE provider_instances SET handle = ?, status = ?, revision = ?, payload = ?
			WHERE id = ? AND definition_id = ? AND revision = ?`, instance.Handle, instance.Status, int64(instance.Revision), instancePayloads[instance.ID], instance.ID, migration.Definition.ID, int64(currentRevisions[instance.ID]))
		if errInstanceUpdate != nil {
			return fmt.Errorf("update custom definition migration instance %s: %w", instance.ID, errInstanceUpdate)
		}
		if errResult := requireSingleMutation(instanceResult, "custom definition migration instance "+instance.ID); errResult != nil {
			return errResult
		}
	}
	if errCommit := transaction.Commit(); errCommit != nil {
		return fmt.Errorf("commit custom definition migration transaction: %w", errCommit)
	}
	return nil
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

// SaveProviderConfiguration atomically inserts one credential-independent provider instance and endpoint graph.
// SaveProviderConfiguration 原子插入一个独立于凭据的供应商实例与入口图。
func (s *ConfigurationStore) SaveProviderConfiguration(ctx context.Context, configuration providerconfig.ProviderConfiguration) error {
	if err := validateContext(ctx); err != nil {
		return err
	}
	definition, errDefinition := s.GetDefinition(ctx, configuration.Instance.DefinitionID)
	if errDefinition != nil {
		return errDefinition
	}
	if errValidate := providerconfig.ValidateProviderConfiguration(configuration, definition); errValidate != nil {
		return errValidate
	}
	transaction, errTransaction := s.database.sql.BeginTx(ctx, nil)
	if errTransaction != nil {
		return fmt.Errorf("begin provider configuration transaction: %w", errTransaction)
	}
	defer func() { _ = transaction.Rollback() }()
	if definition.Kind == providerconfig.DefinitionKindCustom {
		var matchingDefinition int
		if errMatch := transaction.QueryRowContext(ctx, `SELECT COUNT(*) FROM custom_provider_definitions WHERE id = ? AND revision = ?`, definition.ID, configuration.Instance.DefinitionRevision).Scan(&matchingDefinition); errMatch != nil {
			return fmt.Errorf("check provider configuration custom definition revision: %w", errMatch)
		}
		if matchingDefinition != 1 {
			return invalidConfiguration("provider configuration custom definition changed concurrently")
		}
	}
	if errInsert := insertOnboardingInstance(ctx, transaction, configuration.Instance); errInsert != nil {
		return errInsert
	}
	for _, endpoint := range configuration.Endpoints {
		if errInsert := insertOnboardingEndpoint(ctx, transaction, endpoint); errInsert != nil {
			return errInsert
		}
	}
	if errCommit := transaction.Commit(); errCommit != nil {
		return fmt.Errorf("commit provider configuration transaction: %w", errCommit)
	}
	return nil
}

// DeleteProviderConfiguration removes one exact unchanged provider configuration in one compensation transaction.
// DeleteProviderConfiguration 在一个补偿事务中删除一个精确且未变化的供应商配置。
func (s *ConfigurationStore) DeleteProviderConfiguration(ctx context.Context, configuration providerconfig.ProviderConfiguration) error {
	if err := validateContext(ctx); err != nil {
		return err
	}
	transaction, errTransaction := s.database.sql.BeginTx(ctx, nil)
	if errTransaction != nil {
		return fmt.Errorf("begin provider configuration compensation: %w", errTransaction)
	}
	defer func() { _ = transaction.Rollback() }()
	var endpointCount int
	if errCount := transaction.QueryRowContext(ctx, `SELECT COUNT(*) FROM provider_endpoints WHERE provider_instance_id = ?`, configuration.Instance.ID).Scan(&endpointCount); errCount != nil {
		return fmt.Errorf("count provider configuration endpoints: %w", errCount)
	}
	var credentialCount int
	if errCount := transaction.QueryRowContext(ctx, `SELECT COUNT(*) FROM provider_credentials WHERE provider_instance_id = ?`, configuration.Instance.ID).Scan(&credentialCount); errCount != nil {
		return fmt.Errorf("count provider configuration credentials: %w", errCount)
	}
	var bindingCount int
	if errCount := transaction.QueryRowContext(ctx, `SELECT COUNT(*) FROM access_bindings WHERE provider_instance_id = ?`, configuration.Instance.ID).Scan(&bindingCount); errCount != nil {
		return fmt.Errorf("count provider configuration bindings: %w", errCount)
	}
	if endpointCount != len(configuration.Endpoints) || credentialCount != 0 || bindingCount != 0 {
		return fmt.Errorf("provider configuration compensation target changed")
	}
	for _, endpoint := range configuration.Endpoints {
		if errDelete := deleteCompensationRow(ctx, transaction, "provider endpoint", `DELETE FROM provider_endpoints WHERE id = ? AND provider_instance_id = ? AND revision = ?`, endpoint.ID, configuration.Instance.ID, endpoint.Revision); errDelete != nil {
			return errDelete
		}
	}
	if errDelete := deleteCompensationRow(ctx, transaction, "provider instance", `DELETE FROM provider_instances WHERE id = ? AND definition_id = ? AND revision = ?`, configuration.Instance.ID, configuration.Instance.DefinitionID, configuration.Instance.Revision); errDelete != nil {
		return errDelete
	}
	if errCommit := transaction.Commit(); errCommit != nil {
		return fmt.Errorf("commit provider configuration compensation: %w", errCommit)
	}
	return nil
}

// SaveSystemOnboarding atomically inserts one complete system-provider configuration in SQLite.
// SaveSystemOnboarding 在 SQLite 中原子插入一份完整的系统供应商配置。
func (s *ConfigurationStore) SaveSystemOnboarding(ctx context.Context, onboarding providerconfig.SystemOnboarding) error {
	if err := validateContext(ctx); err != nil {
		return err
	}
	definition, errDefinition := s.GetDefinition(ctx, onboarding.Instance.DefinitionID)
	if errDefinition != nil {
		return errDefinition
	}
	if errValidate := providerconfig.ValidateSystemOnboarding(onboarding, definition); errValidate != nil {
		return errValidate
	}
	transaction, errTransaction := s.database.sql.BeginTx(ctx, nil)
	if errTransaction != nil {
		return fmt.Errorf("begin system provider onboarding transaction: %w", errTransaction)
	}
	defer func() {
		_ = transaction.Rollback()
	}()
	if errInsert := insertOnboardingInstance(ctx, transaction, onboarding.Instance); errInsert != nil {
		return errInsert
	}
	for _, endpoint := range onboarding.Endpoints {
		if errInsert := insertOnboardingEndpoint(ctx, transaction, endpoint); errInsert != nil {
			return errInsert
		}
	}
	if errInsert := insertOnboardingCredential(ctx, transaction, onboarding.Credential); errInsert != nil {
		return errInsert
	}
	for _, binding := range onboarding.Bindings {
		if errInsert := insertOnboardingBinding(ctx, transaction, binding); errInsert != nil {
			return errInsert
		}
	}
	if errCommit := transaction.Commit(); errCommit != nil {
		return fmt.Errorf("commit system provider onboarding transaction: %w", errCommit)
	}
	return nil
}

// DeleteSystemOnboarding removes one complete new instance graph in a single compensation transaction.
// DeleteSystemOnboarding 在一个补偿事务中删除完整的新实例图。
func (s *ConfigurationStore) DeleteSystemOnboarding(ctx context.Context, onboarding providerconfig.SystemOnboarding) error {
	if err := validateContext(ctx); err != nil {
		return err
	}
	transaction, errTransaction := s.database.sql.BeginTx(ctx, nil)
	if errTransaction != nil {
		return fmt.Errorf("begin system onboarding compensation: %w", errTransaction)
	}
	defer func() { _ = transaction.Rollback() }()
	for _, binding := range onboarding.Bindings {
		if errDelete := deleteCompensationRow(ctx, transaction, "access binding", `DELETE FROM access_bindings WHERE id = ? AND provider_instance_id = ? AND revision = ?`, binding.ID, onboarding.Instance.ID, binding.Revision); errDelete != nil {
			return errDelete
		}
	}
	if errDelete := deleteCompensationRow(ctx, transaction, "credential", `DELETE FROM provider_credentials WHERE id = ? AND provider_instance_id = ? AND revision = ?`, onboarding.Credential.ID, onboarding.Instance.ID, onboarding.Credential.Revision); errDelete != nil {
		return errDelete
	}
	for _, endpoint := range onboarding.Endpoints {
		if errDelete := deleteCompensationRow(ctx, transaction, "endpoint", `DELETE FROM provider_endpoints WHERE id = ? AND provider_instance_id = ? AND revision = ?`, endpoint.ID, onboarding.Instance.ID, endpoint.Revision); errDelete != nil {
			return errDelete
		}
	}
	if errDelete := deleteCompensationRow(ctx, transaction, "provider instance", `DELETE FROM provider_instances WHERE id = ? AND definition_id = ? AND revision = ?`, onboarding.Instance.ID, onboarding.Instance.DefinitionID, onboarding.Instance.Revision); errDelete != nil {
		return errDelete
	}
	if errCommit := transaction.Commit(); errCommit != nil {
		return fmt.Errorf("commit system onboarding compensation: %w", errCommit)
	}
	return nil
}

// SaveCustomOnboarding atomically inserts one custom definition and its complete executable graph in SQLite.
// SaveCustomOnboarding 在 SQLite 中原子插入一个自定义 Definition 及其完整可执行图。
func (s *ConfigurationStore) SaveCustomOnboarding(ctx context.Context, onboarding providerconfig.CustomOnboarding) error {
	if err := validateContext(ctx); err != nil {
		return err
	}
	if errDefinition := providerconfig.ValidateCustomDefinition(onboarding.Definition, s.protocols); errDefinition != nil {
		return errDefinition
	}
	if errValidate := providerconfig.ValidateCustomOnboarding(onboarding); errValidate != nil {
		return errValidate
	}
	definitionPayload, errPayload := marshalPayload(onboarding.Definition)
	if errPayload != nil {
		return errPayload
	}
	transaction, errTransaction := s.database.sql.BeginTx(ctx, nil)
	if errTransaction != nil {
		return fmt.Errorf("begin custom provider onboarding transaction: %w", errTransaction)
	}
	defer func() { _ = transaction.Rollback() }()
	if _, errInsert := transaction.ExecContext(ctx, `INSERT INTO custom_provider_definitions(id, revision, payload) VALUES (?, ?, ?)`, onboarding.Definition.ID, onboarding.Definition.Revision, definitionPayload); errInsert != nil {
		return fmt.Errorf("insert custom provider definition: %w", errInsert)
	}
	if errInsert := insertOnboardingInstance(ctx, transaction, onboarding.Instance); errInsert != nil {
		return errInsert
	}
	if errInsert := insertOnboardingEndpoint(ctx, transaction, onboarding.Endpoint); errInsert != nil {
		return errInsert
	}
	if errInsert := insertOnboardingCredential(ctx, transaction, onboarding.Credential); errInsert != nil {
		return errInsert
	}
	if errInsert := insertOnboardingBinding(ctx, transaction, onboarding.Binding); errInsert != nil {
		return errInsert
	}
	if errCommit := transaction.Commit(); errCommit != nil {
		return fmt.Errorf("commit custom provider onboarding transaction: %w", errCommit)
	}
	return nil
}

// DeleteCustomOnboarding removes one exact unchanged custom definition and instance graph in a compensation transaction.
// DeleteCustomOnboarding 在一个补偿事务中删除精确且未变化的自定义 Definition 与实例图。
func (s *ConfigurationStore) DeleteCustomOnboarding(ctx context.Context, onboarding providerconfig.CustomOnboarding) error {
	if err := validateContext(ctx); err != nil {
		return err
	}
	definitionPayload, errPayload := marshalPayload(onboarding.Definition)
	if errPayload != nil {
		return errPayload
	}
	transaction, errTransaction := s.database.sql.BeginTx(ctx, nil)
	if errTransaction != nil {
		return fmt.Errorf("begin custom onboarding compensation: %w", errTransaction)
	}
	defer func() { _ = transaction.Rollback() }()
	if errDelete := deleteCompensationRow(ctx, transaction, "access binding", `DELETE FROM access_bindings WHERE id = ? AND provider_instance_id = ? AND revision = ?`, onboarding.Binding.ID, onboarding.Instance.ID, onboarding.Binding.Revision); errDelete != nil {
		return errDelete
	}
	if errDelete := deleteCompensationRow(ctx, transaction, "credential", `DELETE FROM provider_credentials WHERE id = ? AND provider_instance_id = ? AND revision = ?`, onboarding.Credential.ID, onboarding.Instance.ID, onboarding.Credential.Revision); errDelete != nil {
		return errDelete
	}
	if errDelete := deleteCompensationRow(ctx, transaction, "endpoint", `DELETE FROM provider_endpoints WHERE id = ? AND provider_instance_id = ? AND revision = ?`, onboarding.Endpoint.ID, onboarding.Instance.ID, onboarding.Endpoint.Revision); errDelete != nil {
		return errDelete
	}
	if errDelete := deleteCompensationRow(ctx, transaction, "provider instance", `DELETE FROM provider_instances WHERE id = ? AND definition_id = ? AND revision = ?`, onboarding.Instance.ID, onboarding.Definition.ID, onboarding.Instance.Revision); errDelete != nil {
		return errDelete
	}
	if errDelete := deleteCompensationRow(ctx, transaction, "custom provider definition", `DELETE FROM custom_provider_definitions WHERE id = ? AND revision = ? AND payload = ?`, onboarding.Definition.ID, onboarding.Definition.Revision, definitionPayload); errDelete != nil {
		return errDelete
	}
	if errCommit := transaction.Commit(); errCommit != nil {
		return fmt.Errorf("commit custom onboarding compensation: %w", errCommit)
	}
	return nil
}

// deleteCompensationRow deletes exactly one unchanged onboarding row inside the caller-owned transaction.
// deleteCompensationRow 在调用方事务内精确删除一条未变化的录入记录。
func deleteCompensationRow(ctx context.Context, transaction *sql.Tx, entityName string, statement string, arguments ...any) error {
	result, errExec := transaction.ExecContext(ctx, statement, arguments...)
	if errExec != nil {
		return fmt.Errorf("compensate system onboarding %s: %w", entityName, errExec)
	}
	rowsAffected, errRows := result.RowsAffected()
	if errRows != nil {
		return fmt.Errorf("read system onboarding %s compensation result: %w", entityName, errRows)
	}
	if rowsAffected != 1 {
		return fmt.Errorf("system onboarding compensation %s changed", entityName)
	}
	return nil
}

// insertOnboardingInstance inserts the new instance inside the caller-owned transaction.
// insertOnboardingInstance 在调用方拥有的事务内插入新实例。
func insertOnboardingInstance(ctx context.Context, transaction *sql.Tx, instance providerconfig.ProviderInstance) error {
	payload, errPayload := marshalPayload(instance)
	if errPayload != nil {
		return errPayload
	}
	if _, errExec := transaction.ExecContext(ctx, `INSERT INTO provider_instances(id, definition_id, handle, status, revision, payload) VALUES (?, ?, ?, ?, ?, ?)`, instance.ID, instance.DefinitionID, instance.Handle, instance.Status, instance.Revision, payload); errExec != nil {
		return fmt.Errorf("insert onboarding provider instance: %w", errExec)
	}
	return nil
}

// insertOnboardingEndpoint inserts one fixed endpoint inside the caller-owned transaction.
// insertOnboardingEndpoint 在调用方拥有的事务内插入一个固定端点。
func insertOnboardingEndpoint(ctx context.Context, transaction *sql.Tx, endpoint providerconfig.Endpoint) error {
	payload, errPayload := marshalPayload(endpoint)
	if errPayload != nil {
		return errPayload
	}
	if _, errExec := transaction.ExecContext(ctx, `INSERT INTO provider_endpoints(id, provider_instance_id, channel_id, status, revision, payload) VALUES (?, ?, ?, ?, ?, ?)`, endpoint.ID, endpoint.ProviderInstanceID, endpoint.ChannelID, endpoint.Status, endpoint.Revision, payload); errExec != nil {
		return fmt.Errorf("insert onboarding provider endpoint: %w", errExec)
	}
	return nil
}

// insertOnboardingCredential inserts one non-secret credential record inside the caller-owned transaction.
// insertOnboardingCredential 在调用方拥有的事务内插入一个非秘密凭据记录。
func insertOnboardingCredential(ctx context.Context, transaction *sql.Tx, credential providerconfig.Credential) error {
	payload, errPayload := marshalPayload(credential)
	if errPayload != nil {
		return errPayload
	}
	if _, errExec := transaction.ExecContext(ctx, `INSERT INTO provider_credentials(id, provider_instance_id, auth_method_id, principal_key, fingerprint, status, revision, payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, credential.ID, credential.ProviderInstanceID, credential.AuthMethodID, credential.PrincipalKey, credential.Fingerprint, credential.Status, credential.Revision, payload); errExec != nil {
		return fmt.Errorf("insert onboarding provider credential: %w", errExec)
	}
	return nil
}

// insertOnboardingBinding inserts one closed access path inside the caller-owned transaction.
// insertOnboardingBinding 在调用方拥有的事务内插入一条闭合访问路径。
func insertOnboardingBinding(ctx context.Context, transaction *sql.Tx, binding providerconfig.AccessBinding) error {
	payload, errPayload := marshalPayload(binding)
	if errPayload != nil {
		return errPayload
	}
	if _, errExec := transaction.ExecContext(ctx, `INSERT INTO access_bindings(id, provider_instance_id, channel_id, endpoint_id, credential_id, priority, enabled, revision, payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, binding.ID, binding.ProviderInstanceID, binding.ChannelID, binding.EndpointID, binding.CredentialID, binding.Priority, binding.Enabled, binding.Revision, payload); errExec != nil {
		return fmt.Errorf("insert onboarding access binding: %w", errExec)
	}
	return nil
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
	current, errCurrent := s.GetInstance(ctx, instance.ID)
	if errCurrent == nil {
		if errMutation := current.ValidateMutation(instance); errMutation != nil {
			return errMutation
		}
	} else if !errors.Is(errCurrent, providerconfig.ErrNotFound) {
		return errCurrent
	}
	definition, systemDefinition := s.systems.Lookup(instance.DefinitionID)
	if !systemDefinition {
		var errDefinition error
		definition, errDefinition = s.GetDefinition(ctx, instance.DefinitionID)
		if errDefinition != nil {
			return errDefinition
		}
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
	if systemDefinition {
		return s.saveRevisioned(ctx, `
			INSERT INTO provider_instances(id, definition_id, handle, status, revision, payload) VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT(id) DO UPDATE SET definition_id = excluded.definition_id, handle = excluded.handle,
			status = excluded.status, revision = excluded.revision, payload = excluded.payload
			WHERE excluded.revision > provider_instances.revision
			AND excluded.definition_id = provider_instances.definition_id`, instance.ID, instance.Revision, "provider instance", payload, instance.DefinitionID, instance.Handle, instance.Status)
	}
	return s.saveCustomInstanceRevisioned(ctx, instance, payload)
}

// saveCustomInstanceRevisioned persists one custom instance only while its exact definition revision remains current.
// saveCustomInstanceRevisioned 仅在其精确的定义修订仍为当前版本时持久化一个自定义实例。
func (s *ConfigurationStore) saveCustomInstanceRevisioned(ctx context.Context, instance providerconfig.ProviderInstance, payload []byte) error {
	if instance.Revision > math.MaxInt64 || instance.DefinitionRevision > math.MaxInt64 {
		return invalidConfiguration("provider instance revision exceeds SQLite integer range")
	}
	result, errExec := s.database.sql.ExecContext(ctx, `
		INSERT INTO provider_instances(id, definition_id, handle, status, revision, payload)
		SELECT ?, ?, ?, ?, ?, ?
		WHERE EXISTS (
			SELECT 1 FROM custom_provider_definitions WHERE id = ? AND revision = ?
		)
		ON CONFLICT(id) DO UPDATE SET definition_id = excluded.definition_id, handle = excluded.handle,
		status = excluded.status, revision = excluded.revision, payload = excluded.payload
		WHERE excluded.revision > provider_instances.revision
		AND excluded.definition_id = provider_instances.definition_id`,
		instance.ID, instance.DefinitionID, instance.Handle, instance.Status, int64(instance.Revision), payload,
		instance.DefinitionID, int64(instance.DefinitionRevision))
	if errExec != nil {
		return fmt.Errorf("save provider instance: %w", errExec)
	}
	rowsAffected, errRows := result.RowsAffected()
	if errRows != nil {
		return fmt.Errorf("read provider instance write result: %w", errRows)
	}
	if rowsAffected != 1 {
		return invalidConfiguration("provider instance revision or custom definition changed concurrently")
	}
	return nil
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
	if errPreset := definition.ValidateEndpointPreset(endpoint); errPreset != nil {
		return errPreset
	}
	current, errCurrent := s.getEndpoint(ctx, endpoint.ID)
	if errCurrent == nil {
		if errMutation := definition.ValidateEndpointMutation(current, endpoint); errMutation != nil {
			return errMutation
		}
	} else if !errors.Is(errCurrent, providerconfig.ErrNotFound) {
		return errCurrent
	}
	payload, errPayload := marshalPayload(endpoint)
	if errPayload != nil {
		return errPayload
	}
	return s.saveRevisioned(ctx, `
		INSERT INTO provider_endpoints(id, provider_instance_id, channel_id, status, revision, payload) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET provider_instance_id = excluded.provider_instance_id, channel_id = excluded.channel_id,
		status = excluded.status, revision = excluded.revision, payload = excluded.payload
		WHERE excluded.revision > provider_endpoints.revision
		AND excluded.provider_instance_id = provider_endpoints.provider_instance_id
		AND excluded.channel_id = provider_endpoints.channel_id`, endpoint.ID, endpoint.Revision, "provider endpoint", payload, endpoint.ProviderInstanceID, endpoint.ChannelID, endpoint.Status)
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
	current, errCurrent := s.getCredential(ctx, credential.ID)
	if errCurrent == nil {
		if errMutation := current.ValidateMutation(credential); errMutation != nil {
			return errMutation
		}
	} else if !errors.Is(errCurrent, providerconfig.ErrNotFound) {
		return errCurrent
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
		WHERE excluded.revision > provider_credentials.revision
		AND excluded.provider_instance_id = provider_credentials.provider_instance_id
		AND excluded.auth_method_id = provider_credentials.auth_method_id`, credential.ID, credential.Revision, "provider credential", payload,
		credential.ProviderInstanceID, credential.AuthMethodID, credential.PrincipalKey, credential.Fingerprint, credential.Status)
}

// SaveCredentialAndCatalog atomically commits one credential mutation and its exact derived catalog revision.
// SaveCredentialAndCatalog 原子提交一次凭据变更及其精确派生目录修订。
func (s *ConfigurationStore) SaveCredentialAndCatalog(ctx context.Context, credential providerconfig.Credential, snapshot catalog.Snapshot) error {
	if err := validateContext(ctx); err != nil {
		return err
	}
	if errCredential := credential.Validate(); errCredential != nil {
		return errCredential
	}
	if errSnapshot := snapshot.Validate(); errSnapshot != nil {
		return errSnapshot
	}
	if snapshot.ProviderInstanceID != credential.ProviderInstanceID {
		return invalidConfiguration("credential and catalog provider instances do not match")
	}
	if credential.Revision > math.MaxInt64 || snapshot.Revision > math.MaxInt64 {
		return invalidConfiguration("credential or catalog revision exceeds SQLite integer range")
	}
	_, definition, errOwner := s.instanceDefinition(ctx, credential.ProviderInstanceID)
	if errOwner != nil {
		return errOwner
	}
	if !definition.HasAuthMethod(credential.AuthMethodID) {
		return invalidConfiguration("credential references auth method outside its provider definition")
	}
	credentialPayload, errCredentialPayload := marshalPayload(credential)
	if errCredentialPayload != nil {
		return errCredentialPayload
	}
	catalogPayload, errCatalogPayload := marshalPayload(snapshot)
	if errCatalogPayload != nil {
		return errCatalogPayload
	}
	transaction, errBegin := s.database.sql.BeginTx(ctx, nil)
	if errBegin != nil {
		return fmt.Errorf("begin credential plan transaction: %w", errBegin)
	}
	defer transaction.Rollback()
	var currentPayload []byte
	if errQuery := transaction.QueryRowContext(ctx, `SELECT payload FROM provider_credentials WHERE id = ?`, credential.ID).Scan(&currentPayload); errors.Is(errQuery, sql.ErrNoRows) {
		return fmt.Errorf("%w: provider credential %s", providerconfig.ErrNotFound, credential.ID)
	} else if errQuery != nil {
		return fmt.Errorf("query credential for plan transaction: %w", errQuery)
	}
	var current providerconfig.Credential
	if errDecode := unmarshalPayload(currentPayload, &current); errDecode != nil {
		return errDecode
	}
	if errMutation := current.ValidateMutation(credential); errMutation != nil {
		return errMutation
	}
	if errDuplicate := checkCredentialDuplicateInTransaction(ctx, transaction, credential); errDuplicate != nil {
		return errDuplicate
	}
	credentialResult, errCredentialWrite := transaction.ExecContext(ctx, `
		UPDATE provider_credentials SET principal_key = ?, fingerprint = ?, status = ?, revision = ?, payload = ?
		WHERE id = ? AND provider_instance_id = ? AND auth_method_id = ? AND revision < ?`,
		credential.PrincipalKey, credential.Fingerprint, credential.Status, int64(credential.Revision), credentialPayload,
		credential.ID, credential.ProviderInstanceID, credential.AuthMethodID, int64(credential.Revision))
	if errCredentialWrite != nil {
		return fmt.Errorf("save provider credential plan: %w", errCredentialWrite)
	}
	if errRows := requireSingleMutation(credentialResult, "provider credential plan"); errRows != nil {
		return errRows
	}
	catalogResult, errCatalogWrite := transaction.ExecContext(ctx, `
		UPDATE catalog_snapshots SET revision = ?, observed_at = ?, payload = ?
		WHERE provider_instance_id = ? AND revision < ?`,
		int64(snapshot.Revision), snapshot.ObservedAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"), catalogPayload,
		snapshot.ProviderInstanceID, int64(snapshot.Revision))
	if errCatalogWrite != nil {
		return fmt.Errorf("save provider credential plan catalog: %w", errCatalogWrite)
	}
	if errRows := requireSingleMutation(catalogResult, "provider credential plan catalog"); errRows != nil {
		return errRows
	}
	if errCommit := transaction.Commit(); errCommit != nil {
		return fmt.Errorf("commit credential plan transaction: %w", errCommit)
	}
	return nil
}

// checkCredentialDuplicateInTransaction enforces account uniqueness inside the atomic plan mutation.
// checkCredentialDuplicateInTransaction 在原子套餐变更内强制执行账号唯一性。
func checkCredentialDuplicateInTransaction(ctx context.Context, transaction *sql.Tx, credential providerconfig.Credential) error {
	var conflictingID string
	errFingerprint := transaction.QueryRowContext(ctx, `SELECT id FROM provider_credentials WHERE provider_instance_id = ? AND fingerprint = ? AND id <> ?`, credential.ProviderInstanceID, credential.Fingerprint, credential.ID).Scan(&conflictingID)
	if errFingerprint == nil {
		return fmt.Errorf("%w: credential fingerprint", providerconfig.ErrAlreadyRegistered)
	}
	if !errors.Is(errFingerprint, sql.ErrNoRows) {
		return fmt.Errorf("check credential fingerprint: %w", errFingerprint)
	}
	if credential.PrincipalKey == "" {
		return nil
	}
	errPrincipal := transaction.QueryRowContext(ctx, `SELECT id FROM provider_credentials WHERE provider_instance_id = ? AND principal_key = ? AND id <> ?`, credential.ProviderInstanceID, credential.PrincipalKey, credential.ID).Scan(&conflictingID)
	if errPrincipal == nil {
		return fmt.Errorf("%w: credential principal", providerconfig.ErrAlreadyRegistered)
	}
	if !errors.Is(errPrincipal, sql.ErrNoRows) {
		return fmt.Errorf("check credential principal: %w", errPrincipal)
	}
	return nil
}

// ListCredentials returns stable non-secret credential snapshots for one provider instance.
// ListCredentials 返回一个供应商实例稳定的非秘密凭据快照。
func (s *ConfigurationStore) ListCredentials(ctx context.Context, instanceID string) ([]providerconfig.Credential, error) {
	return listPayloads[providerconfig.Credential](ctx, s.database.sql, `SELECT payload FROM provider_credentials WHERE provider_instance_id = ? ORDER BY id`, []any{instanceID}, func(credential providerconfig.Credential) error {
		return credential.Validate()
	})
}

// DeleteCredentialGraph atomically removes one credential and its bindings while retaining an empty provider configuration as draft.
// DeleteCredentialGraph 原子删除一个凭据及其绑定，并将失去全部凭据的供应商配置保留为草稿。
func (s *ConfigurationStore) DeleteCredentialGraph(ctx context.Context, instanceID string, credentialID string) (providerconfig.CredentialDeletion, error) {
	if err := validateContext(ctx); err != nil {
		return providerconfig.CredentialDeletion{}, err
	}
	credential, errCredential := s.getCredential(ctx, credentialID)
	if errCredential != nil {
		return providerconfig.CredentialDeletion{}, errCredential
	}
	if credential.ProviderInstanceID != instanceID {
		return providerconfig.CredentialDeletion{}, fmt.Errorf("%w: provider credential %s", providerconfig.ErrNotFound, credentialID)
	}
	instance, errInstance := s.GetInstance(ctx, instanceID)
	if errInstance != nil {
		return providerconfig.CredentialDeletion{}, errInstance
	}
	transaction, errTransaction := s.database.sql.BeginTx(ctx, nil)
	if errTransaction != nil {
		return providerconfig.CredentialDeletion{}, fmt.Errorf("begin credential deletion: %w", errTransaction)
	}
	defer func() { _ = transaction.Rollback() }()
	if _, errBindings := transaction.ExecContext(ctx, `DELETE FROM access_bindings WHERE provider_instance_id = ? AND credential_id = ?`, instanceID, credentialID); errBindings != nil {
		return providerconfig.CredentialDeletion{}, fmt.Errorf("delete credential bindings: %w", errBindings)
	}
	credentialResult, errDeleteCredential := transaction.ExecContext(ctx, `DELETE FROM provider_credentials WHERE id = ? AND provider_instance_id = ? AND revision = ?`, credentialID, instanceID, credential.Revision)
	if errDeleteCredential != nil {
		return providerconfig.CredentialDeletion{}, fmt.Errorf("delete provider credential: %w", errDeleteCredential)
	}
	if errRows := requireSingleMutation(credentialResult, "provider credential deletion"); errRows != nil {
		return providerconfig.CredentialDeletion{}, errRows
	}
	var remainingCredentials int
	if errCount := transaction.QueryRowContext(ctx, `SELECT COUNT(*) FROM provider_credentials WHERE provider_instance_id = ?`, instanceID).Scan(&remainingCredentials); errCount != nil {
		return providerconfig.CredentialDeletion{}, fmt.Errorf("count remaining provider credentials: %w", errCount)
	}
	deletion := providerconfig.CredentialDeletion{Credential: credential}
	if remainingCredentials == 0 {
		instance.Status = providerconfig.LifecycleDraft
		instance.Revision++
		instance.UpdatedAt = time.Now().UTC()
		payload, errPayload := marshalPayload(instance)
		if errPayload != nil {
			return providerconfig.CredentialDeletion{}, errPayload
		}
		instanceResult, errUpdateInstance := transaction.ExecContext(ctx, `UPDATE provider_instances SET status = ?, revision = ?, payload = ? WHERE id = ? AND definition_id = ? AND revision = ?`, instance.Status, instance.Revision, payload, instance.ID, instance.DefinitionID, instance.Revision-1)
		if errUpdateInstance != nil {
			return providerconfig.CredentialDeletion{}, fmt.Errorf("draft empty provider instance: %w", errUpdateInstance)
		}
		if errRows := requireSingleMutation(instanceResult, "empty provider instance draft transition"); errRows != nil {
			return providerconfig.CredentialDeletion{}, errRows
		}
		deletion.InstanceDrafted = true
	}
	if errCommit := transaction.Commit(); errCommit != nil {
		return providerconfig.CredentialDeletion{}, fmt.Errorf("commit credential deletion: %w", errCommit)
	}
	return deletion, nil
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
	current, errCurrent := s.getBinding(ctx, binding.ID)
	if errCurrent == nil {
		if errMutation := current.ValidateMutation(binding); errMutation != nil {
			return errMutation
		}
	} else if !errors.Is(errCurrent, providerconfig.ErrNotFound) {
		return errCurrent
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
		WHERE excluded.revision > access_bindings.revision
		AND excluded.provider_instance_id = access_bindings.provider_instance_id
		AND excluded.channel_id = access_bindings.channel_id`, binding.ID, binding.Revision, "access binding", payload,
		binding.ProviderInstanceID, binding.ChannelID, binding.EndpointID, binding.CredentialID, binding.Priority, enabled)
}

// ListBindings returns stable access binding snapshots for one provider instance.
// ListBindings 返回一个供应商实例的稳定访问绑定快照。
func (s *ConfigurationStore) ListBindings(ctx context.Context, instanceID string) ([]providerconfig.AccessBinding, error) {
	return listPayloads[providerconfig.AccessBinding](ctx, s.database.sql, `SELECT payload FROM access_bindings WHERE provider_instance_id = ? ORDER BY priority, id`, []any{instanceID}, func(binding providerconfig.AccessBinding) error {
		return binding.Validate()
	})
}

// ReplaceAccessGraph atomically replaces one instance's complete endpoint and binding graph after exact-state comparison.
// ReplaceAccessGraph 在精确状态比对后原子替换一个实例的完整入口与 Binding 图。
func (s *ConfigurationStore) ReplaceAccessGraph(ctx context.Context, replacement providerconfig.AccessGraphReplacement) error {
	if err := validateContext(ctx); err != nil {
		return err
	}
	instance, definition, errOwner := s.instanceDefinition(ctx, replacement.ProviderInstanceID)
	if errOwner != nil {
		return errOwner
	}
	if instance.ID == "" {
		return invalidConfiguration("access graph provider instance is required")
	}
	credentials, errCredentials := s.ListCredentials(ctx, replacement.ProviderInstanceID)
	if errCredentials != nil {
		return errCredentials
	}
	if errValidate := providerconfig.ValidateAccessGraphReplacement(replacement, definition, credentials); errValidate != nil {
		return errValidate
	}
	transaction, errBegin := s.database.sql.BeginTx(ctx, nil)
	if errBegin != nil {
		return fmt.Errorf("begin access graph replacement: %w", errBegin)
	}
	defer transaction.Rollback()
	currentEndpoints, errEndpoints := listTransactionPayloads[providerconfig.Endpoint](ctx, transaction, `SELECT payload FROM provider_endpoints WHERE provider_instance_id = ? ORDER BY id`, replacement.ProviderInstanceID)
	if errEndpoints != nil {
		return fmt.Errorf("read current endpoints for access graph replacement: %w", errEndpoints)
	}
	currentBindings, errBindings := listTransactionPayloads[providerconfig.AccessBinding](ctx, transaction, `SELECT payload FROM access_bindings WHERE provider_instance_id = ? ORDER BY id`, replacement.ProviderInstanceID)
	if errBindings != nil {
		return fmt.Errorf("read current bindings for access graph replacement: %w", errBindings)
	}
	if !equalPersistedAccessGraphs(currentEndpoints, currentBindings, replacement.ExpectedEndpoints, replacement.ExpectedBindings) {
		return invalidConfiguration("provider access graph changed before replacement")
	}
	if _, errDeleteBindings := transaction.ExecContext(ctx, `DELETE FROM access_bindings WHERE provider_instance_id = ?`, replacement.ProviderInstanceID); errDeleteBindings != nil {
		return fmt.Errorf("delete replaced access bindings: %w", errDeleteBindings)
	}
	if _, errDeleteEndpoints := transaction.ExecContext(ctx, `DELETE FROM provider_endpoints WHERE provider_instance_id = ?`, replacement.ProviderInstanceID); errDeleteEndpoints != nil {
		return fmt.Errorf("delete replaced provider endpoints: %w", errDeleteEndpoints)
	}
	for _, endpoint := range replacement.Endpoints {
		if errInsert := insertOnboardingEndpoint(ctx, transaction, endpoint); errInsert != nil {
			return fmt.Errorf("insert replacement endpoint: %w", errInsert)
		}
	}
	for _, binding := range replacement.Bindings {
		if errInsert := insertOnboardingBinding(ctx, transaction, binding); errInsert != nil {
			return fmt.Errorf("insert replacement binding: %w", errInsert)
		}
	}
	if errCommit := transaction.Commit(); errCommit != nil {
		return fmt.Errorf("commit access graph replacement: %w", errCommit)
	}
	return nil
}

// listTransactionPayloads reads typed JSON payloads through one caller-owned transaction.
// listTransactionPayloads 通过一个由调用方拥有的事务读取强类型 JSON 载荷。
func listTransactionPayloads[T any](ctx context.Context, transaction *sql.Tx, query string, arguments ...any) ([]T, error) {
	rows, errQuery := transaction.QueryContext(ctx, query, arguments...)
	if errQuery != nil {
		return nil, errQuery
	}
	defer rows.Close()
	values := make([]T, 0)
	for rows.Next() {
		var payload []byte
		if errScan := rows.Scan(&payload); errScan != nil {
			return nil, errScan
		}
		var value T
		if errDecode := unmarshalPayload(payload, &value); errDecode != nil {
			return nil, errDecode
		}
		values = append(values, value)
	}
	if errRows := rows.Err(); errRows != nil {
		return nil, errRows
	}
	return values, nil
}

// equalPersistedAccessGraphs compares complete endpoint and binding sets in deterministic identifier order.
// equalPersistedAccessGraphs 按确定性标识顺序比较完整入口与 Binding 集合。
func equalPersistedAccessGraphs(leftEndpoints []providerconfig.Endpoint, leftBindings []providerconfig.AccessBinding, rightEndpoints []providerconfig.Endpoint, rightBindings []providerconfig.AccessBinding) bool {
	leftEndpoints = append([]providerconfig.Endpoint(nil), leftEndpoints...)
	rightEndpoints = append([]providerconfig.Endpoint(nil), rightEndpoints...)
	leftBindings = append([]providerconfig.AccessBinding(nil), leftBindings...)
	rightBindings = append([]providerconfig.AccessBinding(nil), rightBindings...)
	sort.Slice(leftEndpoints, func(left int, right int) bool { return leftEndpoints[left].ID < leftEndpoints[right].ID })
	sort.Slice(rightEndpoints, func(left int, right int) bool { return rightEndpoints[left].ID < rightEndpoints[right].ID })
	sort.Slice(leftBindings, func(left int, right int) bool { return leftBindings[left].ID < leftBindings[right].ID })
	sort.Slice(rightBindings, func(left int, right int) bool { return rightBindings[left].ID < rightBindings[right].ID })
	return reflect.DeepEqual(leftEndpoints, rightEndpoints) && reflect.DeepEqual(leftBindings, rightBindings)
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

// getBinding returns one validated access binding by identifier.
// getBinding 按标识返回一个经过校验的访问绑定。
func (s *ConfigurationStore) getBinding(ctx context.Context, bindingID string) (providerconfig.AccessBinding, error) {
	var binding providerconfig.AccessBinding
	errGet := s.getPayload(ctx, `SELECT payload FROM access_bindings WHERE id = ?`, bindingID, &binding)
	if errors.Is(errGet, sql.ErrNoRows) {
		return providerconfig.AccessBinding{}, fmt.Errorf("%w: access binding %s", providerconfig.ErrNotFound, bindingID)
	}
	if errGet != nil {
		return providerconfig.AccessBinding{}, fmt.Errorf("query access binding: %w", errGet)
	}
	if errValidate := binding.Validate(); errValidate != nil {
		return providerconfig.AccessBinding{}, fmt.Errorf("validate persisted access binding: %w", errValidate)
	}
	return binding, nil
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
// requireSingleMutation verifies one compare-and-swap statement changed exactly one persisted record.
// requireSingleMutation 校验一条比较交换语句恰好变更了一条持久化记录。
func requireSingleMutation(result sql.Result, entityName string) error {
	rowsAffected, errRows := result.RowsAffected()
	if errRows != nil {
		return fmt.Errorf("read %s write result: %w", entityName, errRows)
	}
	if rowsAffected != 1 {
		return invalidConfiguration("%s changed concurrently", entityName)
	}
	return nil
}

// saveRevisioned inserts or updates one payload only when its revision advances.
// saveRevisioned 仅在修订号推进时插入或更新一个 Payload。
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
