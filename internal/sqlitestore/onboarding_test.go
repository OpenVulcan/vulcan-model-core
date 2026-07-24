package sqlitestore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/bootstrap"
	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	protocolchat "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/chat"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
)

// TestSaveSystemOnboardingRollsBackEveryRowOnLateConflict verifies the SQLite transaction remains all-or-nothing.
// TestSaveSystemOnboardingRollsBackEveryRowOnLateConflict 验证 SQLite 事务始终保持全有或全无。
func TestSaveSystemOnboardingRollsBackEveryRowOnLateConflict(t *testing.T) {
	ctx := context.Background()
	database, errDatabase := Open(ctx, filepath.Join(t.TempDir(), "onboarding.db"))
	if errDatabase != nil {
		t.Fatalf("Open() error = %v", errDatabase)
	}
	defer database.Close()
	protocols := providerconfig.NewProtocolRegistry()
	if errProtocols := bootstrap.RegisterProtocolProfiles(protocols); errProtocols != nil {
		t.Fatalf("RegisterProtocolProfiles() error = %v", errProtocols)
	}
	systems, errSystems := providerconfig.NewSystemRegistry(protocols)
	if errSystems != nil {
		t.Fatalf("NewSystemRegistry() error = %v", errSystems)
	}
	if errProviders := bootstrap.RegisterSystemProviders(systems); errProviders != nil {
		t.Fatalf("RegisterSystemProviders() error = %v", errProviders)
	}
	store, errStore := NewConfigurationStore(database, protocols, systems)
	if errStore != nil {
		t.Fatalf("NewConfigurationStore() error = %v", errStore)
	}
	first := sqliteKimiOnboarding("pvi_first", "kimi-first", "ep_first", "cred_first", "bind_shared")
	if errSave := store.SaveSystemOnboarding(ctx, first); errSave != nil {
		t.Fatalf("first SaveSystemOnboarding() error = %v", errSave)
	}
	second := sqliteKimiOnboarding("pvi_second", "kimi-second", "ep_second", "cred_second", "bind_shared")
	if errSave := store.SaveSystemOnboarding(ctx, second); errSave == nil {
		t.Fatal("second SaveSystemOnboarding() error = nil, want binding conflict")
	}
	if _, errInstance := store.GetInstance(ctx, second.Instance.ID); !errors.Is(errInstance, providerconfig.ErrNotFound) {
		t.Fatalf("rolled-back instance error = %v, want ErrNotFound", errInstance)
	}
	endpoints, errEndpoints := store.ListEndpoints(ctx, second.Instance.ID)
	if errEndpoints != nil || len(endpoints) != 0 {
		t.Fatalf("rolled-back endpoints=%#v error=%v", endpoints, errEndpoints)
	}
	credentials, errCredentials := store.ListCredentials(ctx, second.Instance.ID)
	if errCredentials != nil || len(credentials) != 0 {
		t.Fatalf("rolled-back credentials=%#v error=%v", credentials, errCredentials)
	}
}

// TestDeleteCredentialGraphRetainsFinalSQLiteInstance verifies production persistence keeps provider configuration after its last credential is removed.
// TestDeleteCredentialGraphRetainsFinalSQLiteInstance 验证生产持久化会在删除最后凭据后保留供应商配置。
func TestDeleteCredentialGraphRetainsFinalSQLiteInstance(t *testing.T) {
	ctx := context.Background()
	database, errDatabase := Open(ctx, filepath.Join(t.TempDir(), "delete-credential.db"))
	if errDatabase != nil {
		t.Fatalf("Open() error = %v", errDatabase)
	}
	defer database.Close()
	protocols := providerconfig.NewProtocolRegistry()
	if errProtocols := bootstrap.RegisterProtocolProfiles(protocols); errProtocols != nil {
		t.Fatalf("RegisterProtocolProfiles() error = %v", errProtocols)
	}
	systems, errSystems := providerconfig.NewSystemRegistry(protocols)
	if errSystems != nil {
		t.Fatalf("NewSystemRegistry() error = %v", errSystems)
	}
	if errProviders := bootstrap.RegisterSystemProviders(systems); errProviders != nil {
		t.Fatalf("RegisterSystemProviders() error = %v", errProviders)
	}
	store, errStore := NewConfigurationStore(database, protocols, systems)
	if errStore != nil {
		t.Fatalf("NewConfigurationStore() error = %v", errStore)
	}
	onboarding := sqliteKimiOnboarding("pvi_delete", "kimi-delete", "ep_delete", "cred_delete", "bind_delete")
	if errSave := store.SaveSystemOnboarding(ctx, onboarding); errSave != nil {
		t.Fatalf("SaveSystemOnboarding() error = %v", errSave)
	}
	deletion, errDelete := store.DeleteCredentialGraph(ctx, onboarding.Instance.ID, onboarding.Credential.ID)
	if errDelete != nil || deletion.InstanceDeleted || !deletion.InstanceDrafted {
		t.Fatalf("DeleteCredentialGraph() deletion=%#v error=%v", deletion, errDelete)
	}
	retainedInstance, errInstance := store.GetInstance(ctx, onboarding.Instance.ID)
	if errInstance != nil || retainedInstance.Status != providerconfig.LifecycleDraft {
		t.Fatalf("retained instance=%#v error=%v", retainedInstance, errInstance)
	}
	bindings, errBindings := store.ListBindings(ctx, onboarding.Instance.ID)
	if errBindings != nil || len(bindings) != 0 {
		t.Fatalf("deleted bindings=%#v error=%v", bindings, errBindings)
	}
	endpoints, errEndpoints := store.ListEndpoints(ctx, onboarding.Instance.ID)
	if errEndpoints != nil || len(endpoints) != 1 || endpoints[0].ID != onboarding.Endpoints[0].ID {
		t.Fatalf("retained endpoints=%#v error=%v", endpoints, errEndpoints)
	}
}

// TestProviderConfigurationLifecycleIsCredentialIndependent verifies SQLite atomically creates and compensates an instance-endpoint graph without accounts.
// TestProviderConfigurationLifecycleIsCredentialIndependent 验证 SQLite 原子创建并补偿不含账号的实例入口图。
func TestProviderConfigurationLifecycleIsCredentialIndependent(t *testing.T) {
	ctx := context.Background()
	database, errDatabase := Open(ctx, filepath.Join(t.TempDir(), "provider-configuration.db"))
	if errDatabase != nil {
		t.Fatalf("Open() error = %v", errDatabase)
	}
	defer database.Close()
	protocols := providerconfig.NewProtocolRegistry()
	if errProtocols := bootstrap.RegisterProtocolProfiles(protocols); errProtocols != nil {
		t.Fatalf("RegisterProtocolProfiles() error = %v", errProtocols)
	}
	systems, errSystems := providerconfig.NewSystemRegistry(protocols)
	if errSystems != nil {
		t.Fatalf("NewSystemRegistry() error = %v", errSystems)
	}
	if errProviders := bootstrap.RegisterSystemProviders(systems); errProviders != nil {
		t.Fatalf("RegisterSystemProviders() error = %v", errProviders)
	}
	store, errStore := NewConfigurationStore(database, protocols, systems)
	if errStore != nil {
		t.Fatalf("NewConfigurationStore() error = %v", errStore)
	}
	onboarding := sqliteKimiOnboarding("pvi_configuration", "kimi-configuration", "ep_configuration", "cred_unused", "bind_unused")
	onboarding.Instance.Status = providerconfig.LifecycleDraft
	configuration := providerconfig.ProviderConfiguration{Instance: onboarding.Instance, Endpoints: onboarding.Endpoints}
	if errSave := store.SaveProviderConfiguration(ctx, configuration); errSave != nil {
		t.Fatalf("SaveProviderConfiguration() error = %v", errSave)
	}
	credentials, errCredentials := store.ListCredentials(ctx, configuration.Instance.ID)
	if errCredentials != nil || len(credentials) != 0 {
		t.Fatalf("credential-independent configuration credentials=%#v error=%v", credentials, errCredentials)
	}
	if errDelete := store.DeleteProviderConfiguration(ctx, configuration); errDelete != nil {
		t.Fatalf("DeleteProviderConfiguration() error = %v", errDelete)
	}
	if _, errInstance := store.GetInstance(ctx, configuration.Instance.ID); !errors.Is(errInstance, providerconfig.ErrNotFound) {
		t.Fatalf("compensated provider instance error = %v", errInstance)
	}
}

// TestDeleteCustomDefinitionRequiresAllSQLiteInstancesRemoved verifies the definition compare-and-delete boundary rejects referenced rows.
// TestDeleteCustomDefinitionRequiresAllSQLiteInstancesRemoved 验证定义比较删除边界会拒绝仍被实例引用的记录。
func TestDeleteCustomDefinitionRequiresAllSQLiteInstancesRemoved(t *testing.T) {
	ctx := context.Background()
	database, errDatabase := Open(ctx, filepath.Join(t.TempDir(), "custom-definition-deletion.db"))
	if errDatabase != nil {
		t.Fatalf("Open() error = %v", errDatabase)
	}
	defer database.Close()
	protocols := providerconfig.NewProtocolRegistry()
	if errProtocols := bootstrap.RegisterProtocolProfiles(protocols); errProtocols != nil {
		t.Fatalf("RegisterProtocolProfiles() error = %v", errProtocols)
	}
	systems, errSystems := providerconfig.NewSystemRegistry(protocols)
	if errSystems != nil {
		t.Fatalf("NewSystemRegistry() error = %v", errSystems)
	}
	if errProviders := bootstrap.RegisterSystemProviders(systems); errProviders != nil {
		t.Fatalf("RegisterSystemProviders() error = %v", errProviders)
	}
	store, errStore := NewConfigurationStore(database, protocols, systems)
	if errStore != nil {
		t.Fatalf("NewConfigurationStore() error = %v", errStore)
	}
	onboarding := sqliteCustomOnboarding("custom_delete", "pvi_custom_delete", "custom-delete", "ep_custom_delete", "cred_unused", "bind_unused")
	if errDefinition := store.SaveCustomDefinition(ctx, onboarding.Definition); errDefinition != nil {
		t.Fatalf("SaveCustomDefinition() error = %v", errDefinition)
	}
	onboarding.Instance.Status = providerconfig.LifecycleDraft
	configuration := providerconfig.ProviderConfiguration{Instance: onboarding.Instance, Endpoints: []providerconfig.Endpoint{onboarding.Endpoint}}
	if errConfiguration := store.SaveProviderConfiguration(ctx, configuration); errConfiguration != nil {
		t.Fatalf("SaveProviderConfiguration() error = %v", errConfiguration)
	}
	if errReferencedDelete := store.DeleteCustomDefinition(ctx, onboarding.Definition); errReferencedDelete == nil {
		t.Fatal("DeleteCustomDefinition() with an instance error = nil, want rejection")
	}
	if errConfigurationDelete := store.DeleteProviderConfiguration(ctx, configuration); errConfigurationDelete != nil {
		t.Fatalf("DeleteProviderConfiguration() error = %v", errConfigurationDelete)
	}
	// persistedPayload captures the exact historical JSON bytes so the test can preserve semantics while changing serialization.
	// persistedPayload 捕获历史 JSON 的精确字节，以便测试在保持语义不变的同时改变序列化形式。
	var persistedPayload []byte
	if errPayload := database.sql.QueryRowContext(
		ctx,
		`SELECT payload FROM custom_provider_definitions WHERE id = ?`,
		onboarding.Definition.ID,
	).Scan(&persistedPayload); errPayload != nil {
		t.Fatalf("read custom definition payload: %v", errPayload)
	}
	// indentedPayload represents legacy semantically equivalent JSON that must not invalidate revision-based deletion.
	// indentedPayload 表示语义等价的历史 JSON，不得导致基于修订号的删除失效。
	var indentedPayload bytes.Buffer
	if errIndent := json.Indent(&indentedPayload, persistedPayload, "", "  "); errIndent != nil {
		t.Fatalf("indent custom definition payload: %v", errIndent)
	}
	if _, errUpdate := database.sql.ExecContext(
		ctx,
		`UPDATE custom_provider_definitions SET payload = ? WHERE id = ?`,
		indentedPayload.Bytes(),
		onboarding.Definition.ID,
	); errUpdate != nil {
		t.Fatalf("rewrite custom definition payload: %v", errUpdate)
	}
	if errDefinitionDelete := store.DeleteCustomDefinition(ctx, onboarding.Definition); errDefinitionDelete != nil {
		t.Fatalf("DeleteCustomDefinition() error = %v", errDefinitionDelete)
	}
	if _, errDefinition := store.GetDefinition(ctx, onboarding.Definition.ID); !errors.Is(errDefinition, providerconfig.ErrNotFound) {
		t.Fatalf("GetDefinition() after deletion error = %v, want ErrNotFound", errDefinition)
	}
}

// TestSaveCredentialAndCatalogRollsBackBothRevisions verifies manual plan changes cannot split configuration from catalog state.
// TestSaveCredentialAndCatalogRollsBackBothRevisions 验证人工套餐变更不能使配置与目录状态分裂。
func TestSaveCredentialAndCatalogRollsBackBothRevisions(t *testing.T) {
	ctx := context.Background()
	database, errDatabase := Open(ctx, filepath.Join(t.TempDir(), "credential-plan.db"))
	if errDatabase != nil {
		t.Fatalf("Open() error = %v", errDatabase)
	}
	defer database.Close()
	protocols := providerconfig.NewProtocolRegistry()
	if errProtocols := bootstrap.RegisterProtocolProfiles(protocols); errProtocols != nil {
		t.Fatalf("RegisterProtocolProfiles() error = %v", errProtocols)
	}
	systems, errSystems := providerconfig.NewSystemRegistry(protocols)
	if errSystems != nil {
		t.Fatalf("NewSystemRegistry() error = %v", errSystems)
	}
	if errProviders := bootstrap.RegisterSystemProviders(systems); errProviders != nil {
		t.Fatalf("RegisterSystemProviders() error = %v", errProviders)
	}
	configurations, errConfigurations := NewConfigurationStore(database, protocols, systems)
	if errConfigurations != nil {
		t.Fatalf("NewConfigurationStore() error = %v", errConfigurations)
	}
	catalogs, errCatalogs := NewCatalogStore(database)
	if errCatalogs != nil {
		t.Fatalf("NewCatalogStore() error = %v", errCatalogs)
	}
	onboarding := sqliteKimiOnboarding("pvi_plan", "kimi-plan", "ep_plan", "cred_plan", "bind_plan")
	if errSave := configurations.SaveSystemOnboarding(ctx, onboarding); errSave != nil {
		t.Fatalf("SaveSystemOnboarding() error = %v", errSave)
	}
	observedAt := time.Date(2026, 7, 20, 19, 0, 0, 0, time.UTC)
	currentSnapshot := catalog.Snapshot{ProviderInstanceID: onboarding.Instance.ID, Revision: 2, ObservedAt: observedAt}
	if errSave := catalogs.Save(ctx, currentSnapshot); errSave != nil {
		t.Fatalf("save current catalog: %v", errSave)
	}
	updatedCredential := onboarding.Credential
	updatedCredential.Label = "Updated Plan"
	updatedCredential.Revision = 2
	conflictingSnapshot := currentSnapshot
	if errAtomic := configurations.SaveCredentialAndCatalog(ctx, updatedCredential, conflictingSnapshot); errAtomic == nil {
		t.Fatal("SaveCredentialAndCatalog() error = nil, want catalog revision conflict")
	}
	credentials, errCredentials := configurations.ListCredentials(ctx, onboarding.Instance.ID)
	if errCredentials != nil || len(credentials) != 1 || credentials[0].Revision != 1 || credentials[0].Label != onboarding.Credential.Label {
		t.Fatalf("rolled-back credentials=%+v error=%v", credentials, errCredentials)
	}
	updatedSnapshot := currentSnapshot
	updatedSnapshot.Revision = 3
	updatedSnapshot.ObservedAt = observedAt.Add(time.Minute)
	if errAtomic := configurations.SaveCredentialAndCatalog(ctx, updatedCredential, updatedSnapshot); errAtomic != nil {
		t.Fatalf("SaveCredentialAndCatalog() success error = %v", errAtomic)
	}
	credentials, errCredentials = configurations.ListCredentials(ctx, onboarding.Instance.ID)
	persistedSnapshot, errSnapshot := catalogs.Get(ctx, onboarding.Instance.ID)
	if errCredentials != nil || errSnapshot != nil || credentials[0].Revision != 2 || credentials[0].Label != updatedCredential.Label || persistedSnapshot.Revision != 3 {
		t.Fatalf("credentials=%+v catalog=%+v credential_error=%v catalog_error=%v", credentials, persistedSnapshot, errCredentials, errSnapshot)
	}
}

// TestDeleteSystemOnboardingRequiresExactUnchangedGraph verifies compensation deletes only the graph created by the failed operation.
// TestDeleteSystemOnboardingRequiresExactUnchangedGraph 验证补偿仅删除失败操作创建且未变化的配置图。
func TestDeleteSystemOnboardingRequiresExactUnchangedGraph(t *testing.T) {
	ctx := context.Background()
	// newStore creates one isolated SQLite configuration store for each ownership scenario.
	// newStore 为每个所有权场景创建一个隔离的 SQLite 配置存储。
	newStore := func(t *testing.T) *ConfigurationStore {
		t.Helper()
		database, errDatabase := Open(ctx, filepath.Join(t.TempDir(), "compensation.db"))
		if errDatabase != nil {
			t.Fatalf("Open() error = %v", errDatabase)
		}
		t.Cleanup(func() { _ = database.Close() })
		protocols := providerconfig.NewProtocolRegistry()
		if errProtocols := bootstrap.RegisterProtocolProfiles(protocols); errProtocols != nil {
			t.Fatalf("RegisterProtocolProfiles() error = %v", errProtocols)
		}
		systems, errSystems := providerconfig.NewSystemRegistry(protocols)
		if errSystems != nil {
			t.Fatalf("NewSystemRegistry() error = %v", errSystems)
		}
		if errProviders := bootstrap.RegisterSystemProviders(systems); errProviders != nil {
			t.Fatalf("RegisterSystemProviders() error = %v", errProviders)
		}
		store, errStore := NewConfigurationStore(database, protocols, systems)
		if errStore != nil {
			t.Fatalf("NewConfigurationStore() error = %v", errStore)
		}
		return store
	}

	t.Run("unchanged graph", func(t *testing.T) {
		store := newStore(t)
		onboarding := sqliteKimiOnboarding("pvi_delete", "kimi-delete", "ep_delete", "cred_delete", "bind_delete")
		if errSave := store.SaveSystemOnboarding(ctx, onboarding); errSave != nil {
			t.Fatalf("SaveSystemOnboarding() error = %v", errSave)
		}
		if errDelete := store.DeleteSystemOnboarding(ctx, onboarding); errDelete != nil {
			t.Fatalf("DeleteSystemOnboarding() error = %v", errDelete)
		}
		if _, errInstance := store.GetInstance(ctx, onboarding.Instance.ID); !errors.Is(errInstance, providerconfig.ErrNotFound) {
			t.Fatalf("deleted instance error = %v, want ErrNotFound", errInstance)
		}
	})

	t.Run("changed graph", func(t *testing.T) {
		store := newStore(t)
		onboarding := sqliteKimiOnboarding("pvi_changed", "kimi-changed", "ep_changed", "cred_changed", "bind_changed")
		if errSave := store.SaveSystemOnboarding(ctx, onboarding); errSave != nil {
			t.Fatalf("SaveSystemOnboarding() error = %v", errSave)
		}
		changedEndpoint := onboarding.Endpoints[0]
		changedEndpoint.Status = providerconfig.EndpointDisabled
		changedEndpoint.Revision++
		if errEndpoint := store.SaveEndpoint(ctx, changedEndpoint); errEndpoint != nil {
			t.Fatalf("SaveEndpoint() error = %v", errEndpoint)
		}
		if errDelete := store.DeleteSystemOnboarding(ctx, onboarding); errDelete == nil {
			t.Fatal("DeleteSystemOnboarding() error = nil, want changed-graph rejection")
		}
		if _, errInstance := store.GetInstance(ctx, onboarding.Instance.ID); errInstance != nil {
			t.Fatalf("GetInstance() error = %v, want transaction rollback", errInstance)
		}
		endpoints, errEndpoints := store.ListEndpoints(ctx, onboarding.Instance.ID)
		if errEndpoints != nil || len(endpoints) != 1 || endpoints[0].Revision != 2 {
			t.Fatalf("endpoints=%#v error=%v", endpoints, errEndpoints)
		}
	})
}

// TestSaveAndDeleteCustomOnboardingAreAtomic verifies definition and graph rows share one SQLite transaction and compensation boundary.
// TestSaveAndDeleteCustomOnboardingAreAtomic 验证 Definition 与访问图行共享一个 SQLite 事务和补偿边界。
func TestSaveAndDeleteCustomOnboardingAreAtomic(t *testing.T) {
	ctx := context.Background()
	database, errDatabase := Open(ctx, filepath.Join(t.TempDir(), "custom-onboarding.db"))
	if errDatabase != nil {
		t.Fatalf("Open() error = %v", errDatabase)
	}
	defer database.Close()
	protocols := providerconfig.NewProtocolRegistry()
	if errProtocols := bootstrap.RegisterProtocolProfiles(protocols); errProtocols != nil {
		t.Fatalf("RegisterProtocolProfiles() error = %v", errProtocols)
	}
	systems, errSystems := providerconfig.NewSystemRegistry(protocols)
	if errSystems != nil {
		t.Fatalf("NewSystemRegistry() error = %v", errSystems)
	}
	if errProviders := bootstrap.RegisterSystemProviders(systems); errProviders != nil {
		t.Fatalf("RegisterSystemProviders() error = %v", errProviders)
	}
	store, errStore := NewConfigurationStore(database, protocols, systems)
	if errStore != nil {
		t.Fatalf("NewConfigurationStore() error = %v", errStore)
	}
	first := sqliteCustomOnboarding("custom_first", "pvi_custom_first", "custom-first", "ep_custom_first", "cred_custom_first", "bind_custom_shared")
	if errSave := store.SaveCustomOnboarding(ctx, first); errSave != nil {
		t.Fatalf("first SaveCustomOnboarding() error = %v", errSave)
	}
	second := sqliteCustomOnboarding("custom_second", "pvi_custom_second", "custom-second", "ep_custom_second", "cred_custom_second", "bind_custom_shared")
	if errSave := store.SaveCustomOnboarding(ctx, second); errSave == nil {
		t.Fatal("second SaveCustomOnboarding() error = nil, want binding conflict")
	}
	if _, errDefinition := store.GetDefinition(ctx, second.Definition.ID); !errors.Is(errDefinition, providerconfig.ErrNotFound) {
		t.Fatalf("rolled-back definition error = %v, want ErrNotFound", errDefinition)
	}
	if _, errInstance := store.GetInstance(ctx, second.Instance.ID); !errors.Is(errInstance, providerconfig.ErrNotFound) {
		t.Fatalf("rolled-back instance error = %v, want ErrNotFound", errInstance)
	}
	if errDelete := store.DeleteCustomOnboarding(ctx, first); errDelete != nil {
		t.Fatalf("DeleteCustomOnboarding() error = %v", errDelete)
	}
	if _, errDefinition := store.GetDefinition(ctx, first.Definition.ID); !errors.Is(errDefinition, providerconfig.ErrNotFound) {
		t.Fatalf("deleted definition error = %v, want ErrNotFound", errDefinition)
	}
}

// TestConfigurationStoreRejectsStableOwnershipReassignment verifies SQLite upserts cannot move existing identifiers across provider graphs.
// TestConfigurationStoreRejectsStableOwnershipReassignment 验证 SQLite Upsert 不能跨供应商配置图迁移现有标识。
func TestConfigurationStoreRejectsStableOwnershipReassignment(t *testing.T) {
	ctx := context.Background()
	database, errDatabase := Open(ctx, filepath.Join(t.TempDir(), "immutable-ownership.db"))
	if errDatabase != nil {
		t.Fatalf("Open() error = %v", errDatabase)
	}
	defer database.Close()
	protocols := providerconfig.NewProtocolRegistry()
	if errProtocols := bootstrap.RegisterProtocolProfiles(protocols); errProtocols != nil {
		t.Fatalf("RegisterProtocolProfiles() error = %v", errProtocols)
	}
	systems, errSystems := providerconfig.NewSystemRegistry(protocols)
	if errSystems != nil {
		t.Fatalf("NewSystemRegistry() error = %v", errSystems)
	}
	if errProviders := bootstrap.RegisterSystemProviders(systems); errProviders != nil {
		t.Fatalf("RegisterSystemProviders() error = %v", errProviders)
	}
	store, errStore := NewConfigurationStore(database, protocols, systems)
	if errStore != nil {
		t.Fatalf("NewConfigurationStore() error = %v", errStore)
	}
	first := sqliteKimiOnboarding("pvi_owner_first", "kimi-owner-first", "ep_owner_first", "cred_owner_first", "bind_owner_first")
	second := sqliteKimiOnboarding("pvi_owner_second", "kimi-owner-second", "ep_owner_second", "cred_owner_second", "bind_owner_second")
	if errSave := store.SaveSystemOnboarding(ctx, first); errSave != nil {
		t.Fatalf("save first onboarding: %v", errSave)
	}
	if errSave := store.SaveSystemOnboarding(ctx, second); errSave != nil {
		t.Fatalf("save second onboarding: %v", errSave)
	}

	reassignedInstance := first.Instance
	reassignedInstance.DefinitionID = bootstrap.KimiGlobalDefinitionID
	reassignedInstance.Revision++
	reassignedInstance.UpdatedAt = reassignedInstance.UpdatedAt.Add(time.Minute)
	if errSave := store.SaveInstance(ctx, reassignedInstance); errSave == nil {
		t.Fatal("SaveInstance() accepted definition ownership reassignment")
	}
	reassignedEndpoint := first.Endpoints[0]
	reassignedEndpoint.ProviderInstanceID = second.Instance.ID
	reassignedEndpoint.Revision++
	if errSave := store.SaveEndpoint(ctx, reassignedEndpoint); errSave == nil {
		t.Fatal("SaveEndpoint() accepted provider ownership reassignment")
	}
	reassignedCredential := first.Credential
	reassignedCredential.ProviderInstanceID = second.Instance.ID
	reassignedCredential.Revision++
	if errSave := store.SaveCredential(ctx, reassignedCredential); errSave == nil {
		t.Fatal("SaveCredential() accepted provider ownership reassignment")
	}
	reassignedBinding := first.Bindings[0]
	reassignedBinding.ProviderInstanceID = second.Instance.ID
	reassignedBinding.EndpointID = second.Endpoints[0].ID
	reassignedBinding.CredentialID = second.Credential.ID
	reassignedBinding.Revision++
	if errSave := store.SaveBinding(ctx, reassignedBinding); errSave == nil {
		t.Fatal("SaveBinding() accepted provider ownership reassignment")
	}
}

// TestSaveCustomDefinitionMigrationRollsBackEveryRow verifies a late SQLite instance failure preserves the prior definition graph.
// TestSaveCustomDefinitionMigrationRollsBackEveryRow 验证后期 SQLite 实例失败会保留先前定义图。
func TestSaveCustomDefinitionMigrationRollsBackEveryRow(t *testing.T) {
	ctx := context.Background()
	database, errDatabase := Open(ctx, filepath.Join(t.TempDir(), "custom-migration.db"))
	if errDatabase != nil {
		t.Fatalf("Open() error = %v", errDatabase)
	}
	defer database.Close()
	protocols := providerconfig.NewProtocolRegistry()
	if errProtocols := bootstrap.RegisterProtocolProfiles(protocols); errProtocols != nil {
		t.Fatalf("RegisterProtocolProfiles() error = %v", errProtocols)
	}
	systems, errSystems := providerconfig.NewSystemRegistry(protocols)
	if errSystems != nil {
		t.Fatalf("NewSystemRegistry() error = %v", errSystems)
	}
	if errProviders := bootstrap.RegisterSystemProviders(systems); errProviders != nil {
		t.Fatalf("RegisterSystemProviders() error = %v", errProviders)
	}
	store, errStore := NewConfigurationStore(database, protocols, systems)
	if errStore != nil {
		t.Fatalf("NewConfigurationStore() error = %v", errStore)
	}
	onboarding := sqliteCustomOnboarding("custom_migration", "pvi_custom_migration_first", "custom-migration-first", "ep_custom_migration", "cred_custom_migration", "bind_custom_migration")
	if errSave := store.SaveCustomOnboarding(ctx, onboarding); errSave != nil {
		t.Fatalf("SaveCustomOnboarding() error = %v", errSave)
	}
	second := onboarding.Instance
	second.ID = "pvi_custom_migration_second"
	second.Handle = "custom-migration-second"
	second.DisplayName = "custom-migration-second"
	if errSave := store.SaveInstance(ctx, second); errSave != nil {
		t.Fatalf("SaveInstance() error = %v", errSave)
	}
	directReplacement := onboarding.Definition
	directReplacement.DisplayName = "Unsafe direct replacement"
	directReplacement.Revision++
	if errSave := store.SaveCustomDefinition(ctx, directReplacement); !errors.Is(errSave, providerconfig.ErrAlreadyRegistered) {
		t.Fatalf("direct custom definition replacement error = %v, want ErrAlreadyRegistered", errSave)
	}
	storedBeforeMigration, errStoredBeforeMigration := store.GetDefinition(ctx, onboarding.Definition.ID)
	if errStoredBeforeMigration != nil || storedBeforeMigration.Revision != onboarding.Definition.Revision {
		t.Fatalf("definition after direct replacement = %+v, error = %v", storedBeforeMigration, errStoredBeforeMigration)
	}
	updatedDefinition := onboarding.Definition
	updatedDefinition.DisplayName = "Migrated custom provider"
	updatedDefinition.Revision++
	migrationTime := onboarding.Instance.UpdatedAt.Add(time.Minute)
	migratedFirst := onboarding.Instance
	migratedFirst.Status = providerconfig.LifecycleMigrationRequired
	migratedFirst.DefinitionRevision = updatedDefinition.Revision
	migratedFirst.Revision++
	migratedFirst.UpdatedAt = migrationTime
	migratedSecond := second
	migratedSecond.Status = providerconfig.LifecycleMigrationRequired
	migratedSecond.DefinitionRevision = updatedDefinition.Revision
	migratedSecond.Revision++
	migratedSecond.UpdatedAt = migrationTime
	if _, errTrigger := database.sql.ExecContext(ctx, `
		CREATE TRIGGER fail_second_custom_migration
		BEFORE UPDATE ON provider_instances
		WHEN NEW.id = 'pvi_custom_migration_second'
		BEGIN SELECT RAISE(ABORT, 'forced migration failure'); END`); errTrigger != nil {
		t.Fatalf("create migration failure trigger: %v", errTrigger)
	}
	errMigration := store.SaveCustomDefinitionMigration(ctx, providerconfig.CustomDefinitionMigration{
		Definition: updatedDefinition,
		Instances:  []providerconfig.ProviderInstance{migratedFirst, migratedSecond},
	})
	if errMigration == nil {
		t.Fatal("SaveCustomDefinitionMigration() error = nil, want forced failure")
	}
	storedDefinition, errDefinition := store.GetDefinition(ctx, onboarding.Definition.ID)
	storedFirst, errFirst := store.GetInstance(ctx, onboarding.Instance.ID)
	storedSecond, errSecond := store.GetInstance(ctx, second.ID)
	if errDefinition != nil || errFirst != nil || errSecond != nil || storedDefinition.Revision != onboarding.Definition.Revision || storedFirst.Revision != onboarding.Instance.Revision || storedSecond.Revision != second.Revision || storedFirst.Status != providerconfig.LifecycleReady || storedSecond.Status != providerconfig.LifecycleReady {
		t.Fatalf("rolled-back migration definition=%+v instances=%+v/%+v errors=%v/%v/%v", storedDefinition, storedFirst, storedSecond, errDefinition, errFirst, errSecond)
	}
}

// TestSQLiteReplaceAccessGraphCommitsCompleteReplacement verifies durable graph replacement and stale-state rejection.
// TestSQLiteReplaceAccessGraphCommitsCompleteReplacement 验证持久图的完整替换与过期状态拒绝。
func TestSQLiteReplaceAccessGraphCommitsCompleteReplacement(t *testing.T) {
	ctx := context.Background()
	database, errDatabase := Open(ctx, filepath.Join(t.TempDir(), "access-graph.db"))
	if errDatabase != nil {
		t.Fatalf("Open() error = %v", errDatabase)
	}
	defer database.Close()
	protocols := providerconfig.NewProtocolRegistry()
	if errProtocols := bootstrap.RegisterProtocolProfiles(protocols); errProtocols != nil {
		t.Fatalf("RegisterProtocolProfiles() error = %v", errProtocols)
	}
	systems, errSystems := providerconfig.NewSystemRegistry(protocols)
	if errSystems != nil {
		t.Fatalf("NewSystemRegistry() error = %v", errSystems)
	}
	if errProviders := bootstrap.RegisterSystemProviders(systems); errProviders != nil {
		t.Fatalf("RegisterSystemProviders() error = %v", errProviders)
	}
	store, errStore := NewConfigurationStore(database, protocols, systems)
	if errStore != nil {
		t.Fatalf("NewConfigurationStore() error = %v", errStore)
	}
	onboarding := sqliteKimiOnboarding("pvi_access_graph", "kimi-access-graph", "ep_access_legacy", "cred_access_graph", "bind_access_legacy")
	if errSave := store.SaveSystemOnboarding(ctx, onboarding); errSave != nil {
		t.Fatalf("SaveSystemOnboarding() error = %v", errSave)
	}
	replacementEndpoint := onboarding.Endpoints[0]
	replacementEndpoint.ID = "ep_access_current"
	replacementBinding := onboarding.Bindings[0]
	replacementBinding.ID = "bind_access_current"
	replacementBinding.EndpointID = replacementEndpoint.ID
	replacement := providerconfig.AccessGraphReplacement{ProviderInstanceID: onboarding.Instance.ID, ExpectedEndpoints: onboarding.Endpoints, ExpectedBindings: onboarding.Bindings, Endpoints: []providerconfig.Endpoint{replacementEndpoint}, Bindings: []providerconfig.AccessBinding{replacementBinding}}
	if errReplace := store.ReplaceAccessGraph(ctx, replacement); errReplace != nil {
		t.Fatalf("ReplaceAccessGraph() error = %v", errReplace)
	}
	endpoints, errEndpoints := store.ListEndpoints(ctx, onboarding.Instance.ID)
	bindings, errBindings := store.ListBindings(ctx, onboarding.Instance.ID)
	if errEndpoints != nil || errBindings != nil || len(endpoints) != 1 || endpoints[0].ID != replacementEndpoint.ID || len(bindings) != 1 || bindings[0].ID != replacementBinding.ID {
		t.Fatalf("replaced endpoints=%#v bindings=%#v errors=%v/%v", endpoints, bindings, errEndpoints, errBindings)
	}
	if errReplace := store.ReplaceAccessGraph(ctx, replacement); errReplace == nil {
		t.Fatal("ReplaceAccessGraph() accepted stale expected graph")
	}
}

// sqliteKimiOnboarding builds one valid fixed CN configuration with caller-controlled collision identifiers.
// sqliteKimiOnboarding 使用调用方控制的冲突标识构建一份有效固定 CN 配置。
func sqliteKimiOnboarding(instanceID string, handle string, endpointID string, credentialID string, bindingID string) providerconfig.SystemOnboarding {
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	return providerconfig.SystemOnboarding{
		Instance:   providerconfig.ProviderInstance{ID: instanceID, DefinitionID: bootstrap.KimiCNDefinitionID, Handle: handle, DisplayName: handle, Status: providerconfig.LifecycleReady, Revision: 1, DefinitionRevision: 1, CreatedAt: now, UpdatedAt: now},
		Endpoints:  []providerconfig.Endpoint{{ID: endpointID, ProviderInstanceID: instanceID, ChannelID: "openai.chat", BaseURL: "https://api.moonshot.cn", Region: "CN", Status: providerconfig.EndpointReady, Revision: 1}},
		Credential: providerconfig.Credential{ID: credentialID, ProviderInstanceID: instanceID, AuthMethodID: "api_key", Label: "Primary", SecretRef: "secret-reference", Fingerprint: credentialID, Status: providerconfig.CredentialActive, Revision: 1},
		Bindings:   []providerconfig.AccessBinding{{ID: bindingID, ProviderInstanceID: instanceID, ChannelID: "openai.chat", EndpointID: endpointID, CredentialID: credentialID, Priority: 10, Enabled: true, Revision: 1}},
	}
}

// sqliteCustomOnboarding builds one exact OpenAICompatibility definition and ready access graph.
// sqliteCustomOnboarding 构建一个精确 OpenAICompatibility Definition 与就绪访问图。
func sqliteCustomOnboarding(definitionID string, instanceID string, handle string, endpointID string, credentialID string, bindingID string) providerconfig.CustomOnboarding {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	definition := providerconfig.ProviderDefinition{
		ID: definitionID, Kind: providerconfig.DefinitionKindCustom, DisplayName: handle, ConfigSchemaVersion: "1",
		ProtocolProfileID: protocolchat.ProfileID, EndpointProfileID: providerconfig.CustomEndpointProfileOpenAICompatibility,
		AuthMethodIDs: []string{"default"}, RuntimeReady: true,
		AuthMethods: []providerconfig.AuthMethodDefinition{{ID: "default", Type: providerconfig.AuthMethodBearer, MultipleCredentials: true}}, Revision: 1,
		Features: providerconfig.ProviderFeatureSet{
			PlanReader:        providerconfig.SupportUnsupported,
			EntitlementReader: providerconfig.SupportUnsupported,
			AllowanceReader:   providerconfig.SupportUnsupported,
		},
	}
	return providerconfig.CustomOnboarding{
		Definition: definition,
		Instance:   providerconfig.ProviderInstance{ID: instanceID, DefinitionID: definitionID, Handle: handle, DisplayName: handle, Status: providerconfig.LifecycleReady, Revision: 1, DefinitionRevision: 1, CreatedAt: now, UpdatedAt: now},
		Endpoint:   providerconfig.Endpoint{ID: endpointID, ProviderInstanceID: instanceID, ChannelID: protocolchat.ProfileID, BaseURL: "https://custom.example/v1", Status: providerconfig.EndpointReady, Revision: 1},
		Credential: providerconfig.Credential{ID: credentialID, ProviderInstanceID: instanceID, AuthMethodID: "default", Label: handle, SecretRef: "secret-reference", Fingerprint: credentialID, Status: providerconfig.CredentialActive, Revision: 1},
		Binding:    providerconfig.AccessBinding{ID: bindingID, ProviderInstanceID: instanceID, ChannelID: protocolchat.ProfileID, EndpointID: endpointID, CredentialID: credentialID, Priority: 10, Enabled: true, Revision: 1},
	}
}
