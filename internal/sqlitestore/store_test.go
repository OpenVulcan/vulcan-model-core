package sqlitestore

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/management"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestDatabaseMigratesVersionSixToRoutingAndAttemptState verifies append-only upgrades preserve an existing database.
// TestDatabaseMigratesVersionSixToRoutingAndAttemptState 验证追加式升级会保留现有数据库。
func TestDatabaseMigratesVersionSixToRoutingAndAttemptState(t *testing.T) {
	ctx := context.Background()
	databasePath := filepath.Join(t.TempDir(), "version-six.db")
	absolutePath, errAbsolute := filepath.Abs(databasePath)
	if errAbsolute != nil {
		t.Fatalf("filepath.Abs() error = %v", errAbsolute)
	}
	rawDatabase, errOpen := sql.Open("sqlite", sqliteDSN(absolutePath))
	if errOpen != nil {
		t.Fatalf("sql.Open() error = %v", errOpen)
	}
	if _, errSchema := rawDatabase.ExecContext(ctx, `CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); errSchema != nil {
		t.Fatalf("create schema migrations: %v", errSchema)
	}
	transaction, errBegin := rawDatabase.BeginTx(ctx, nil)
	if errBegin != nil {
		t.Fatalf("BeginTx() error = %v", errBegin)
	}
	for version := 1; version <= 6; version++ {
		if errMigration := applyMigration(ctx, transaction, version); errMigration != nil {
			t.Fatalf("apply migration %d: %v", version, errMigration)
		}
		if _, errRecord := transaction.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at) VALUES (?, CURRENT_TIMESTAMP)`, version); errRecord != nil {
			t.Fatalf("record migration %d: %v", version, errRecord)
		}
	}
	if errCommit := transaction.Commit(); errCommit != nil {
		t.Fatalf("commit version-six fixture: %v", errCommit)
	}
	if errClose := rawDatabase.Close(); errClose != nil {
		t.Fatalf("close version-six fixture: %v", errClose)
	}
	database, errDatabase := Open(ctx, databasePath)
	if errDatabase != nil {
		t.Fatalf("Open() migrated database error = %v", errDatabase)
	}
	defer database.Close()
	version, errVersion := database.SchemaVersion(ctx)
	if errVersion != nil || version != currentSchemaVersion {
		t.Fatalf("schema version=%d error=%v", version, errVersion)
	}
	var strategy string
	if errSettings := database.sql.QueryRowContext(ctx, `SELECT default_routing_strategy FROM router_settings WHERE id = 1`).Scan(&strategy); errSettings != nil || strategy != "round_robin" {
		t.Fatalf("routing strategy=%q error=%v", strategy, errSettings)
	}
	var attemptsColumnCount int
	if errColumn := database.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM pragma_table_info('executions') WHERE name = 'attempts_payload'`).Scan(&attemptsColumnCount); errColumn != nil || attemptsColumnCount != 1 {
		t.Fatalf("attempts column count=%d error=%v", attemptsColumnCount, errColumn)
	}
	var modelStateTableCount int
	if errTable := database.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'credential_model_states'`).Scan(&modelStateTableCount); errTable != nil || modelStateTableCount != 1 {
		t.Fatalf("model state table count=%d error=%v", modelStateTableCount, errTable)
	}
	// runtimeScopeStateTableCount proves the version-nine non-model cooldown migration was applied.
	// runtimeScopeStateTableCount 证明版本九的非模型冷却迁移已应用。
	var runtimeScopeStateTableCount int
	if errTable := database.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'runtime_scope_states'`).Scan(&runtimeScopeStateTableCount); errTable != nil || runtimeScopeStateTableCount != 1 {
		t.Fatalf("runtime scope state table count=%d error=%v", runtimeScopeStateTableCount, errTable)
	}
}

// TestDatabaseMigratesVersionThirteenToManagementAuthorizationSchema verifies Schema 14 survives every later additive migration.
// TestDatabaseMigratesVersionThirteenToManagementAuthorizationSchema 校验 Schema 14 可安全通过全部后续追加迁移。
func TestDatabaseMigratesVersionThirteenToManagementAuthorizationSchema(t *testing.T) {
	ctx := context.Background()
	databasePath := filepath.Join(t.TempDir(), "version-thirteen.db")
	absolutePath, errAbsolute := filepath.Abs(databasePath)
	if errAbsolute != nil {
		t.Fatalf("filepath.Abs() error = %v", errAbsolute)
	}
	rawDatabase, errOpen := sql.Open("sqlite", sqliteDSN(absolutePath))
	if errOpen != nil {
		t.Fatalf("sql.Open() error = %v", errOpen)
	}
	if _, errSchema := rawDatabase.ExecContext(ctx, `CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); errSchema != nil {
		t.Fatalf("create schema migrations: %v", errSchema)
	}
	transaction, errBegin := rawDatabase.BeginTx(ctx, nil)
	if errBegin != nil {
		t.Fatalf("BeginTx() error = %v", errBegin)
	}
	for version := 1; version <= 13; version++ {
		if errMigration := applyMigration(ctx, transaction, version); errMigration != nil {
			t.Fatalf("apply migration %d: %v", version, errMigration)
		}
		if _, errRecord := transaction.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at) VALUES (?, CURRENT_TIMESTAMP)`, version); errRecord != nil {
			t.Fatalf("record migration %d: %v", version, errRecord)
		}
	}
	if errCommit := transaction.Commit(); errCommit != nil {
		t.Fatalf("commit version-thirteen fixture: %v", errCommit)
	}
	if errClose := rawDatabase.Close(); errClose != nil {
		t.Fatalf("close version-thirteen fixture: %v", errClose)
	}
	database, errDatabase := Open(ctx, databasePath)
	if errDatabase != nil {
		t.Fatalf("Open() migrated database error = %v", errDatabase)
	}
	defer database.Close()
	version, errVersion := database.SchemaVersion(ctx)
	if errVersion != nil || version != currentSchemaVersion {
		t.Fatalf("schema version = %d, error = %v", version, errVersion)
	}
	for _, table := range []string{
		"provider_management_authorizations",
		"provider_management_authorization_links",
		"provider_management_snapshots",
	} {
		var tableCount int
		if errTable := database.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&tableCount); errTable != nil || tableCount != 1 {
			t.Fatalf("table %s count = %d, error = %v", table, tableCount, errTable)
		}
	}
}

// sqliteTestRegistries returns executable protocol metadata and one system definition.
// sqliteTestRegistries 返回可执行协议元数据与一个系统定义。
func sqliteTestRegistries(t *testing.T) (*providerconfig.ProtocolRegistry, *providerconfig.SystemRegistry) {
	t.Helper()
	protocols := providerconfig.NewProtocolRegistry()
	if err := protocols.Register(providerconfig.ProtocolProfile{
		ID:                         "openai.chat",
		Version:                    "1",
		DisplayName:                "OpenAI Chat Completions",
		UserConfigurable:           true,
		CustomDefinitionCompatible: true,
		RuntimeReady:               true,
		AllowedAuthMethods:         []providerconfig.AuthMethodType{providerconfig.AuthMethodBearer},
	}); err != nil {
		t.Fatalf("register protocol profile: %v", err)
	}
	systems, errSystems := providerconfig.NewSystemRegistry(protocols)
	if errSystems != nil {
		t.Fatalf("create system registry: %v", errSystems)
	}
	if err := systems.Register(providerconfig.ProviderDefinition{
		ID:                  "system_sqlite_test",
		Kind:                providerconfig.DefinitionKindSystem,
		DisplayName:         "SQLite Test",
		DriverID:            "sqlite-test",
		DriverVersion:       "1.0.0",
		ConfigSchemaVersion: "1",
		ProtocolProfileID:   "openai.chat",
		EndpointProfileID:   "default",
		AuthMethodIDs:       []string{"bearer"},
		RuntimeReady:        true,
		AuthMethods: []providerconfig.AuthMethodDefinition{{
			ID:                  "bearer",
			Type:                providerconfig.AuthMethodBearer,
			MultipleCredentials: true,
		}},
		Features: providerconfig.ProviderFeatureSet{
			PlanReader:        providerconfig.SupportUnsupported,
			EntitlementReader: providerconfig.SupportUnsupported,
			AllowanceReader:   providerconfig.SupportUnsupported,
		},
		Revision: 1,
	}); err != nil {
		t.Fatalf("register system definition: %v", err)
	}
	return protocols, systems
}

// sqliteTestCapabilities returns one explicit text model capability fixture.
// sqliteTestCapabilities 返回一个显式文本模型能力测试夹具。
func sqliteTestCapabilities() catalog.ModelCapabilities {
	// minimum and maximum freeze one persisted integer parameter range.
	// minimum 和 maximum 固定一个持久化整数参数范围。
	minimum, maximum := int64(1), int64(4096)
	// dimensionsDefault freezes one evidenced selectable vector dimension.
	// dimensionsDefault 固定一个具有证据的可选向量维度。
	dimensionsDefault := int64(1024)
	return catalog.ModelCapabilities{
		Tokens:                 catalog.TokenLimits{ContextWindow: catalog.OptionalTokenLimit{Known: true, Value: 262144}, MaxOutputTokens: catalog.OptionalTokenLimit{Known: true, Value: 16384}},
		Recommendations:        catalog.TokenRecommendations{OutputTokens: catalog.OptionalTokenLimit{Known: true, Value: 8192}},
		ToolCalling:            catalog.CapabilityNative,
		ParallelToolCalls:      catalog.CapabilityNative,
		StreamingToolArguments: catalog.CapabilityNative,
		StrictJSONSchema:       catalog.CapabilityConditional,
		Reasoning:              catalog.CapabilityNative,
		InputModalities:        []string{"text"},
		OutputModalities:       []string{"text"},
		Delivery:               catalog.DeliveryCapabilities{Synchronous: true},
		Embedding: &catalog.EmbeddingCapabilities{
			InputTasks: []vcp.EmbeddingInputTask{vcp.EmbeddingTaskDocument}, OutputKinds: []vcp.EmbeddingVectorKind{vcp.EmbeddingVectorDense}, Encodings: []vcp.EmbeddingEncoding{vcp.EmbeddingEncodingFloat},
			Dimensions: []int{1024}, DefaultDimensions: catalog.OptionalLimit{Known: true, Value: dimensionsDefault}, MaxBatchItems: catalog.OptionalLimit{Known: true, Value: 32},
		},
		Parameters:   []catalog.ParameterDescriptor{{ID: "dimensions", Kind: catalog.ParameterInteger, IntegerRange: &catalog.IntegerRange{Minimum: &minimum, Maximum: &maximum}}},
		UsageMetrics: []catalog.UsageMetricCapability{{Unit: catalog.UsageUnitEmbeddingInputs, Accuracy: catalog.UsageExact}},
	}
}

// sqliteTestSnapshot returns one minimal valid provider catalog.
// sqliteTestSnapshot 返回一个最小有效供应商目录。
func sqliteTestSnapshot(observedAt time.Time) catalog.Snapshot {
	// resetAt fixes one calendar allowance boundary for persistence round-trip coverage.
	// resetAt 固定一个日历额度边界以覆盖持久化往返。
	resetAt := observedAt.Add(24 * time.Hour)
	// remaining preserves an exact fractional credit amount without floating-point conversion.
	// remaining 在不经过浮点转换的情况下保留精确小数 Credit 数量。
	remaining := "125.5"
	// usageLimit fixes one provider-reported token ceiling for persistence coverage.
	// usageLimit 固定一个供应商报告的 Token 上限以覆盖持久化。
	usageLimit := int64(1_000_000)
	// usagePeriod fixes the provider-reported usage window paired with usageLimit.
	// usagePeriod 固定与 usageLimit 配对的供应商用量窗口。
	usagePeriod := int64(60)
	return catalog.Snapshot{
		ProviderInstanceID: "pvi_sqlite",
		Models: []catalog.ProviderModel{{
			ID:                 "model_sqlite",
			ProviderInstanceID: "pvi_sqlite",
			UpstreamModelID:    "sqlite-model",
			DisplayName:        "SQLite Model",
			Source:             catalog.ModelSourceSystem,
			EntitlementMode:    catalog.EntitlementAllBoundCredentials,
			Revision:           1,
		}},
		Offerings: []catalog.ModelOffering{{
			ID:                 "offer_sqlite",
			ProviderInstanceID: "pvi_sqlite",
			ProviderModelID:    "model_sqlite",
			ChannelID:          "anthropic.messages.v1",
			UpstreamModelID:    "sqlite-model",
			Capabilities:       sqliteTestCapabilities(),
			CapabilityRevision: 1,
			Revision:           1,
		}},
		Profiles: []catalog.ExecutionProfile{{
			ID:                 "profile_sqlite_default",
			ProviderInstanceID: "pvi_sqlite",
			OfferingID:         "offer_sqlite",
			Operation:          vcp.OperationEmbeddingCreate,
			ActionBindingID:    "action_sqlite_embedding",
			DisplayName:        "Default",
			Default:            true,
			Capabilities:       sqliteTestCapabilities(),
			SwitchPolicy:       catalog.ProfileSwitchSeamless,
			PoolPolicy:         catalog.PoolStrictProfile,
			CapabilityRevision: 1,
			Revision:           1,
		}},
		ModelOperationPolicies: []catalog.ModelOperationPolicy{{
			ID:                 "policy_sqlite_embedding",
			ProviderInstanceID: "pvi_sqlite",
			ProviderModelID:    "model_sqlite",
			OfferingID:         "offer_sqlite",
			Operation:          vcp.OperationEmbeddingCreate,
			Status:             catalog.ModelOperationSupported,
			Reason:             catalog.SupportReasonRuntimeVerified,
			Source:             catalog.ModelSourceRuntimeEvidence,
			EvidenceRevision:   1,
			Revision:           1,
		}},
		Plans: []catalog.PlanSnapshot{{
			ID:                 "plan_sqlite_account",
			ProviderInstanceID: "pvi_sqlite",
			CredentialID:       "cred_sqlite",
			PlanCode:           "pro",
			PlanName:           "Pro",
			Status:             "active",
			ObservedAt:         observedAt,
			ExpiresAt:          observedAt.Add(5 * time.Minute),
			Revision:           1,
		}},
		Allowances: []catalog.AllowanceSnapshot{{
			ID:                 "allow_sqlite_monthly",
			ProviderInstanceID: "pvi_sqlite",
			Kind:               catalog.AllowanceWindowQuota,
			Scope:              catalog.ScopeCredential,
			ScopeID:            "cred_sqlite",
			Metric:             "monthly_credits",
			Unit:               catalog.UnitProviderCredits,
			Remaining:          &remaining,
			Status:             catalog.AllowanceAvailable,
			Mandatory:          true,
			Window: &catalog.AllowanceWindow{
				Kind:         catalog.WindowCalendar,
				CalendarUnit: "month",
				TimeZone:     "Asia/Shanghai",
				ResetAt:      &resetAt,
			},
			Source:     catalog.ModelSourceProviderAPI,
			ObservedAt: observedAt,
			ExpiresAt:  observedAt.Add(5 * time.Minute),
			Revision:   1,
		}},
		RateLimits: []catalog.RateLimitSnapshot{{
			ID:                 "rate_sqlite_chat",
			ProviderInstanceID: "pvi_sqlite",
			Scope:              catalog.RateLimitScopeOffering,
			ScopeID:            "offer_sqlite",
			TierID:             "default",
			CountLimit:         120,
			CountPeriodSeconds: 60,
			UsageLimit:         &usageLimit,
			UsagePeriodSeconds: &usagePeriod,
			UsageField:         "tokens",
			Source:             catalog.ModelSourceProviderAPI,
			ObservedAt:         observedAt,
			ExpiresAt:          observedAt.Add(time.Hour),
			Revision:           1,
		}},
		Revision:   1,
		ObservedAt: observedAt,
	}
}

// TestCatalogStoreReadsLegacySnapshotWithoutPoliciesOrRateLimits verifies additive catalog fields preserve historical payload compatibility.
// TestCatalogStoreReadsLegacySnapshotWithoutPoliciesOrRateLimits 验证目录新增字段保持历史载荷兼容性。
func TestCatalogStoreReadsLegacySnapshotWithoutPoliciesOrRateLimits(t *testing.T) {
	// ctx owns the isolated SQLite operations performed by this compatibility test.
	// ctx 管理此兼容性测试执行的隔离 SQLite 操作。
	ctx := context.Background()
	// database stores one raw historical snapshot that predates both additive fields.
	// database 保存一个早于两个新增字段的原始历史快照。
	database, errDatabase := Open(ctx, filepath.Join(t.TempDir(), "legacy-catalog.db"))
	if errDatabase != nil {
		t.Fatalf("open legacy catalog database: %v", errDatabase)
	}
	defer func() {
		if errClose := database.Close(); errClose != nil {
			t.Errorf("close legacy catalog database: %v", errClose)
		}
	}()
	store, errStore := NewCatalogStore(database)
	if errStore != nil {
		t.Fatalf("create legacy catalog store: %v", errStore)
	}
	// protocols and systems provide the immutable definition required by the catalog owner foreign key.
	// protocols 和 systems 提供目录所有者外键所需的不可变定义。
	protocols, systems := sqliteTestRegistries(t)
	configurationStore, errConfigurationStore := NewConfigurationStore(database, protocols, systems)
	if errConfigurationStore != nil {
		t.Fatalf("create legacy configuration store: %v", errConfigurationStore)
	}
	managementService, errManagementService := management.NewService(configurationStore, secret.NewMemoryStore(), store)
	if errManagementService != nil {
		t.Fatalf("create legacy management service: %v", errManagementService)
	}
	if _, errInstance := managementService.CreateInstance(ctx, management.CreateInstanceInput{ID: "pvi_sqlite", DefinitionID: "system_sqlite_test", Handle: "legacy-sqlite", DisplayName: "Legacy SQLite"}); errInstance != nil {
		t.Fatalf("create legacy catalog owner: %v", errInstance)
	}
	// observedAt fixes the persisted SQL metadata and JSON evidence timestamp.
	// observedAt 固定持久化 SQL 元数据与 JSON 证据时间戳。
	observedAt := time.Date(2026, 7, 17, 14, 0, 0, 0, time.UTC)
	// legacySnapshot starts from a valid snapshot before removing additive fields from the encoded object.
	// legacySnapshot 从有效快照开始，再从编码对象删除新增字段。
	legacySnapshot := sqliteTestSnapshot(observedAt)
	legacySnapshot.ModelOperationPolicies = nil
	legacySnapshot.RateLimits = nil
	encodedSnapshot, errEncode := json.Marshal(legacySnapshot)
	if errEncode != nil {
		t.Fatalf("encode legacy catalog fixture: %v", errEncode)
	}
	// legacyObject permits exact removal of fields that did not exist in the historical payload schema.
	// legacyObject 允许精确删除历史载荷 Schema 中不存在的字段。
	legacyObject := make(map[string]json.RawMessage)
	if errDecode := json.Unmarshal(encodedSnapshot, &legacyObject); errDecode != nil {
		t.Fatalf("decode legacy catalog fixture object: %v", errDecode)
	}
	delete(legacyObject, "ModelOperationPolicies")
	delete(legacyObject, "RateLimits")
	legacyPayload, errLegacyPayload := json.Marshal(legacyObject)
	if errLegacyPayload != nil {
		t.Fatalf("encode field-omitted legacy catalog fixture: %v", errLegacyPayload)
	}
	if _, errInsert := database.sql.ExecContext(ctx, `INSERT INTO catalog_snapshots(provider_instance_id, revision, observed_at, payload) VALUES (?, ?, ?, ?)`, legacySnapshot.ProviderInstanceID, int64(legacySnapshot.Revision), observedAt.Format(time.RFC3339Nano), legacyPayload); errInsert != nil {
		t.Fatalf("insert legacy catalog fixture: %v", errInsert)
	}
	restored, errRestore := store.Get(ctx, legacySnapshot.ProviderInstanceID)
	if errRestore != nil {
		t.Fatalf("restore field-omitted legacy catalog: %v", errRestore)
	}
	if len(restored.ModelOperationPolicies) != 0 || len(restored.RateLimits) != 0 {
		t.Fatalf("legacy additive fields policies=%#v rate_limits=%#v", restored.ModelOperationPolicies, restored.RateLimits)
	}
}

// TestDatabaseConfiguresSQLiteAndPersistsRepositories verifies migration and restart recovery.
// TestDatabaseConfiguresSQLiteAndPersistsRepositories 校验迁移与重启恢复。
func TestDatabaseConfiguresSQLiteAndPersistsRepositories(t *testing.T) {
	ctx := context.Background()
	databasePath := filepath.Join(t.TempDir(), "model-core.db")
	protocols, systems := sqliteTestRegistries(t)
	database, errDatabase := Open(ctx, databasePath)
	if errDatabase != nil {
		t.Fatalf("open sqlite database: %v", errDatabase)
	}
	var journalMode string
	if err := database.sql.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&journalMode); err != nil {
		t.Fatalf("query journal mode: %v", err)
	}
	if journalMode != "wal" {
		t.Fatalf("journal mode = %s, want wal", journalMode)
	}
	var foreignKeys int
	if err := database.sql.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&foreignKeys); err != nil {
		t.Fatalf("query foreign keys: %v", err)
	}
	if foreignKeys != 1 {
		t.Fatalf("foreign keys = %d, want 1", foreignKeys)
	}
	var busyTimeout int
	if err := database.sql.QueryRowContext(ctx, `PRAGMA busy_timeout`).Scan(&busyTimeout); err != nil {
		t.Fatalf("query busy timeout: %v", err)
	}
	if busyTimeout != 5000 {
		t.Fatalf("busy timeout = %d, want 5000", busyTimeout)
	}
	version, errVersion := database.SchemaVersion(ctx)
	if errVersion != nil || version != currentSchemaVersion {
		t.Fatalf("schema version = %d, error = %v", version, errVersion)
	}
	configurations, errConfigurations := NewConfigurationStore(database, protocols, systems)
	if errConfigurations != nil {
		t.Fatalf("create configuration store: %v", errConfigurations)
	}
	catalogs, errCatalogs := NewCatalogStore(database)
	if errCatalogs != nil {
		t.Fatalf("create catalog store: %v", errCatalogs)
	}
	secrets := secret.NewMemoryStore()
	service, errService := management.NewService(configurations, secrets, catalogs)
	if errService != nil {
		t.Fatalf("create management service: %v", errService)
	}
	customDefinition, errCustomDefinition := service.CreateCustomDefinition(ctx, management.CreateCustomDefinitionInput{
		ID: "custom_sqlite", DisplayName: "SQLite Custom", ProtocolProfileID: "openai.chat", AuthMethod: providerconfig.AuthMethodBearer,
	})
	if errCustomDefinition != nil {
		t.Fatalf("create custom provider definition: %v", errCustomDefinition)
	}
	instance, errInstance := service.CreateInstance(ctx, management.CreateInstanceInput{
		ID: "pvi_sqlite", DefinitionID: "system_sqlite_test", Handle: "sqlite", DisplayName: "SQLite",
	})
	if errInstance != nil {
		t.Fatalf("create provider instance: %v", errInstance)
	}
	endpoint, errEndpoint := service.AddEndpoint(ctx, management.AddEndpointInput{
		ID: "ep_sqlite", ProviderInstanceID: instance.ID, BaseURL: "https://sqlite.example/v1",
	})
	if errEndpoint != nil {
		t.Fatalf("add endpoint: %v", errEndpoint)
	}
	secretValue := []byte("super-secret-token-must-not-enter-sqlite")
	credential, errCredential := service.AddCredential(ctx, management.AddCredentialInput{
		ID: "cred_sqlite", ProviderInstanceID: instance.ID, AuthMethodID: "bearer", Label: "Account",
		PrincipalKey: "account-sqlite", Secret: secretValue,
	})
	if errCredential != nil {
		t.Fatalf("add credential: %v", errCredential)
	}
	if _, errBinding := service.AddBinding(ctx, management.AddBindingInput{
		ID: "bind_sqlite", ProviderInstanceID: instance.ID, EndpointID: endpoint.ID, CredentialID: credential.ID,
	}); errBinding != nil {
		t.Fatalf("add binding: %v", errBinding)
	}
	if _, errActivate := service.ActivateInstance(ctx, instance.ID); errActivate != nil {
		t.Fatalf("activate instance: %v", errActivate)
	}
	if errSave := catalogs.Save(ctx, sqliteTestSnapshot(time.Date(2026, 7, 17, 14, 0, 0, 0, time.UTC))); errSave != nil {
		t.Fatalf("save catalog snapshot: %v", errSave)
	}
	if errClose := database.Close(); errClose != nil {
		t.Fatalf("close sqlite database: %v", errClose)
	}
	databaseBytes, errRead := os.ReadFile(databasePath)
	if errRead != nil {
		t.Fatalf("read sqlite database: %v", errRead)
	}
	if bytes.Contains(databaseBytes, secretValue) {
		t.Fatal("plain secret leaked into SQLite business database")
	}
	reopened, errReopen := Open(ctx, databasePath)
	if errReopen != nil {
		t.Fatalf("reopen sqlite database: %v", errReopen)
	}
	defer func() {
		if errClose := reopened.Close(); errClose != nil {
			t.Errorf("close reopened database: %v", errClose)
		}
	}()
	reopenedConfigurations, errReopenedConfigurations := NewConfigurationStore(reopened, protocols, systems)
	if errReopenedConfigurations != nil {
		t.Fatalf("create reopened configuration store: %v", errReopenedConfigurations)
	}
	reopenedCatalogs, errReopenedCatalogs := NewCatalogStore(reopened)
	if errReopenedCatalogs != nil {
		t.Fatalf("create reopened catalog store: %v", errReopenedCatalogs)
	}
	restoredInstance, errRestoredInstance := reopenedConfigurations.GetInstance(ctx, instance.ID)
	if errRestoredInstance != nil {
		t.Fatalf("restore provider instance: %v", errRestoredInstance)
	}
	if restoredInstance.Status != providerconfig.LifecycleReady || restoredInstance.Revision != 2 {
		t.Fatalf("restored instance status=%s revision=%d", restoredInstance.Status, restoredInstance.Revision)
	}
	restoredCustomDefinition, errRestoredCustomDefinition := reopenedConfigurations.GetDefinition(ctx, customDefinition.ID)
	if errRestoredCustomDefinition != nil || restoredCustomDefinition.Kind != providerconfig.DefinitionKindCustom {
		t.Fatalf("restore custom definition kind=%s error=%v", restoredCustomDefinition.Kind, errRestoredCustomDefinition)
	}
	restoredCredentials, errRestoredCredentials := reopenedConfigurations.ListCredentials(ctx, instance.ID)
	if errRestoredCredentials != nil || len(restoredCredentials) != 1 {
		t.Fatalf("restore credentials count=%d error=%v", len(restoredCredentials), errRestoredCredentials)
	}
	if string(restoredCredentials[0].SecretRef) == string(secretValue) {
		t.Fatal("credential stored a plain secret instead of a reference")
	}
	restoredSnapshot, errRestoredSnapshot := reopenedCatalogs.Get(ctx, instance.ID)
	if errRestoredSnapshot != nil || restoredSnapshot.Revision != 1 {
		t.Fatalf("restore catalog revision=%d error=%v", restoredSnapshot.Revision, errRestoredSnapshot)
	}
	if len(restoredSnapshot.Plans) != 1 || restoredSnapshot.Plans[0].PlanCode != "pro" {
		t.Fatalf("restored plans = %#v", restoredSnapshot.Plans)
	}
	if len(restoredSnapshot.Allowances) != 1 || restoredSnapshot.Allowances[0].Window == nil || restoredSnapshot.Allowances[0].Window.TimeZone != "Asia/Shanghai" {
		t.Fatalf("restored allowances = %#v", restoredSnapshot.Allowances)
	}
	if restoredSnapshot.Allowances[0].Remaining == nil || *restoredSnapshot.Allowances[0].Remaining != "125.5" {
		t.Fatalf("restored exact remaining amount = %#v", restoredSnapshot.Allowances[0].Remaining)
	}
	if len(restoredSnapshot.Profiles) != 1 || restoredSnapshot.Profiles[0].Capabilities.Embedding == nil || restoredSnapshot.Profiles[0].Capabilities.Embedding.DefaultDimensions.Value != 1024 || len(restoredSnapshot.Profiles[0].Capabilities.Parameters) != 1 || restoredSnapshot.Profiles[0].Capabilities.Parameters[0].IntegerRange == nil || *restoredSnapshot.Profiles[0].Capabilities.Parameters[0].IntegerRange.Maximum != 4096 || len(restoredSnapshot.Profiles[0].Capabilities.UsageMetrics) != 1 {
		t.Fatalf("restored extended capabilities = %#v", restoredSnapshot.Profiles)
	}
	if len(restoredSnapshot.Offerings) != 1 || !restoredSnapshot.Offerings[0].Capabilities.Recommendations.OutputTokens.Known || restoredSnapshot.Offerings[0].Capabilities.Recommendations.OutputTokens.Value != 8192 {
		t.Fatalf("restored token recommendations = %#v", restoredSnapshot.Offerings)
	}
	if len(restoredSnapshot.ModelOperationPolicies) != 1 || restoredSnapshot.ModelOperationPolicies[0].Status != catalog.ModelOperationSupported || restoredSnapshot.ModelOperationPolicies[0].Reason != catalog.SupportReasonRuntimeVerified {
		t.Fatalf("restored operation policies = %#v", restoredSnapshot.ModelOperationPolicies)
	}
	if len(restoredSnapshot.RateLimits) != 1 || restoredSnapshot.RateLimits[0].UsageLimit == nil || *restoredSnapshot.RateLimits[0].UsageLimit != 1_000_000 || restoredSnapshot.RateLimits[0].UsagePeriodSeconds == nil || *restoredSnapshot.RateLimits[0].UsagePeriodSeconds != 60 {
		t.Fatalf("restored rate limits = %#v", restoredSnapshot.RateLimits)
	}
	firstChanges, errFirstChanges := reopenedCatalogs.ListChanges(ctx, 0, 10)
	if errFirstChanges != nil || firstChanges.CurrentRevision != 1 || len(firstChanges.Changes) != 1 || firstChanges.Changes[0].ProviderInstanceID != instance.ID || firstChanges.Changes[0].Type != catalog.ChangeSnapshotUpsert {
		t.Fatalf("first catalog changes = %+v error=%v", firstChanges, errFirstChanges)
	}
	updatedSnapshot := restoredSnapshot
	updatedSnapshot.Revision = 2
	updatedSnapshot.ObservedAt = restoredSnapshot.ObservedAt.Add(time.Minute)
	if errSave := reopenedCatalogs.Save(ctx, updatedSnapshot); errSave != nil {
		t.Fatalf("save updated catalog snapshot: %v", errSave)
	}
	if errDelete := reopenedCatalogs.Delete(ctx, instance.ID); errDelete != nil {
		t.Fatalf("delete catalog snapshot: %v", errDelete)
	}
	incremental, errIncremental := reopenedCatalogs.ListChanges(ctx, 1, 10)
	if errIncremental != nil || incremental.CurrentRevision != 3 || len(incremental.Changes) != 2 || incremental.Changes[0].Type != catalog.ChangeSnapshotUpsert || incremental.Changes[1].Type != catalog.ChangeSnapshotDelete {
		t.Fatalf("incremental catalog changes = %+v error=%v", incremental, errIncremental)
	}
}
