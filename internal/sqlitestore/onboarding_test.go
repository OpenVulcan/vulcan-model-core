package sqlitestore

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/bootstrap"
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

// sqliteKimiOnboarding builds one valid fixed CN configuration with caller-controlled collision identifiers.
// sqliteKimiOnboarding 使用调用方控制的冲突标识构建一份有效固定 CN 配置。
func sqliteKimiOnboarding(instanceID string, handle string, endpointID string, credentialID string, bindingID string) providerconfig.SystemOnboarding {
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	return providerconfig.SystemOnboarding{
		Instance:   providerconfig.ProviderInstance{ID: instanceID, DefinitionID: bootstrap.KimiCNDefinitionID, Handle: handle, DisplayName: handle, Status: providerconfig.LifecycleReady, Revision: 1, DefinitionRevision: 1, CreatedAt: now, UpdatedAt: now},
		Endpoints:  []providerconfig.Endpoint{{ID: endpointID, ProviderInstanceID: instanceID, ChannelID: "chat", BaseURL: "https://api.moonshot.cn", Region: "CN", Status: providerconfig.EndpointReady, Revision: 1}},
		Credential: providerconfig.Credential{ID: credentialID, ProviderInstanceID: instanceID, AuthMethodID: "api_key", Label: "Primary", SecretRef: "secret-reference", Fingerprint: credentialID, Status: providerconfig.CredentialActive, Revision: 1},
		Bindings:   []providerconfig.AccessBinding{{ID: bindingID, ProviderInstanceID: instanceID, ChannelID: "chat", EndpointID: endpointID, CredentialID: credentialID, Priority: 10, Enabled: true, Revision: 1}},
	}
}
