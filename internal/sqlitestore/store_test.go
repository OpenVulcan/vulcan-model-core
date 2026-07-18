package sqlitestore

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/management"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

// sqliteTestRegistries returns executable protocol metadata and one system definition.
// sqliteTestRegistries 返回可执行协议元数据与一个系统定义。
func sqliteTestRegistries(t *testing.T) (*providerconfig.ProtocolRegistry, *providerconfig.SystemRegistry) {
	t.Helper()
	protocols := providerconfig.NewProtocolRegistry()
	if err := protocols.Register(providerconfig.ProtocolProfile{
		ID:                 "anthropic.messages.v1",
		Version:            "1",
		DisplayName:        "Anthropic Messages",
		UserConfigurable:   true,
		RuntimeReady:       true,
		ModelDiscovery:     providerconfig.SupportUnsupported,
		AllowedAuthMethods: []providerconfig.AuthMethodType{providerconfig.AuthMethodBearer},
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
		Channels: []providerconfig.ProviderChannel{{
			ID:                "anthropic",
			ProtocolProfileID: "anthropic.messages.v1",
			EndpointProfileID: "default",
			AuthMethodIDs:     []string{"bearer"},
			RuntimeReady:      true,
		}},
		AuthMethods: []providerconfig.AuthMethodDefinition{{
			ID:                  "bearer",
			Type:                providerconfig.AuthMethodBearer,
			MultipleCredentials: true,
		}},
		Features: providerconfig.ProviderFeatureSet{
			ModelDiscovery:    providerconfig.SupportUnsupported,
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
	return catalog.ModelCapabilities{
		Tokens:                 catalog.TokenLimits{ContextWindow: catalog.OptionalTokenLimit{Known: true, Value: 262144}},
		ToolCalling:            catalog.CapabilityNative,
		ParallelToolCalls:      catalog.CapabilityNative,
		StreamingToolArguments: catalog.CapabilityNative,
		StrictJSONSchema:       catalog.CapabilityConditional,
		Reasoning:              catalog.CapabilityNative,
		InputModalities:        []string{"text"},
		OutputModalities:       []string{"text"},
	}
}

// sqliteTestSnapshot returns one minimal valid provider catalog.
// sqliteTestSnapshot 返回一个最小有效供应商目录。
func sqliteTestSnapshot(observedAt time.Time) catalog.Snapshot {
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
			ChannelID:          "anthropic",
			UpstreamModelID:    "sqlite-model",
			Capabilities:       sqliteTestCapabilities(),
			CapabilityRevision: 1,
			Revision:           1,
		}},
		Profiles: []catalog.ExecutionProfile{{
			ID:                 "profile_sqlite_default",
			ProviderInstanceID: "pvi_sqlite",
			OfferingID:         "offer_sqlite",
			DisplayName:        "Default",
			Default:            true,
			Capabilities:       sqliteTestCapabilities(),
			SwitchPolicy:       catalog.ProfileSwitchSeamless,
			PoolPolicy:         catalog.PoolStrictProfile,
			CapabilityRevision: 1,
			Revision:           1,
		}},
		Revision:   1,
		ObservedAt: observedAt,
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
		ID: "custom_sqlite", DisplayName: "SQLite Custom", ProtocolProfileID: "anthropic.messages.v1", AuthMethod: providerconfig.AuthMethodBearer,
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
		ID: "ep_sqlite", ProviderInstanceID: instance.ID, ChannelID: "anthropic", BaseURL: "https://sqlite.example/v1",
	})
	if errEndpoint != nil {
		t.Fatalf("add endpoint: %v", errEndpoint)
	}
	secretValue := []byte("super-secret-token-must-not-enter-sqlite")
	credential, errCredential := service.AddCredential(ctx, management.AddCredentialInput{
		ID: "cred_sqlite", ProviderInstanceID: instance.ID, AuthMethodID: "bearer", Label: "Account",
		PrincipalKey: "account-sqlite", Fingerprint: "fingerprint-sqlite", Secret: secretValue,
	})
	if errCredential != nil {
		t.Fatalf("add credential: %v", errCredential)
	}
	if _, errBinding := service.AddBinding(ctx, management.AddBindingInput{
		ID: "bind_sqlite", ProviderInstanceID: instance.ID, ChannelID: "anthropic", EndpointID: endpoint.ID, CredentialID: credential.ID,
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
}
