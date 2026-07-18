package management

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/bootstrap"
	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

// TestBuildSystemCatalogSharesTemplatesButIsolatesInstanceOwnership verifies regional reuse and Coding Plan separation.
// TestBuildSystemCatalogSharesTemplatesButIsolatesInstanceOwnership 验证区域模板复用和 Coding Plan 分离。
func TestBuildSystemCatalogSharesTemplatesButIsolatesInstanceOwnership(t *testing.T) {
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
	observedAt := time.Date(2026, 7, 18, 13, 0, 0, 0, time.UTC)
	cnDefinition, _ := systems.Lookup(bootstrap.KimiCNDefinitionID)
	globalDefinition, _ := systems.Lookup(bootstrap.KimiGlobalDefinitionID)
	codingDefinition, _ := systems.Lookup(bootstrap.KimiCodingDefinitionID)
	cn, errCN := buildSystemCatalog(providerconfig.SystemOnboarding{Instance: providerconfig.ProviderInstance{ID: "pvi_cn"}}, cnDefinition, observedAt)
	global, errGlobal := buildSystemCatalog(providerconfig.SystemOnboarding{Instance: providerconfig.ProviderInstance{ID: "pvi_global"}}, globalDefinition, observedAt)
	coding, errCoding := buildSystemCatalog(providerconfig.SystemOnboarding{Instance: providerconfig.ProviderInstance{ID: "pvi_coding"}}, codingDefinition, observedAt)
	if errCN != nil || errGlobal != nil || errCoding != nil {
		t.Fatalf("catalog errors CN=%v Global=%v Coding=%v", errCN, errGlobal, errCoding)
	}
	if len(cn.Models) != 11 || len(global.Models) != 11 || len(coding.Models) != 3 || len(coding.Offerings) != 6 {
		t.Fatalf("catalog sizes CN=%d Global=%d Coding models=%d offerings=%d", len(cn.Models), len(global.Models), len(coding.Models), len(coding.Offerings))
	}
	for index := range cn.Models {
		if cn.Models[index].UpstreamModelID != global.Models[index].UpstreamModelID || cn.Models[index].ProviderInstanceID == global.Models[index].ProviderInstanceID {
			t.Fatalf("regional model ownership CN=%#v Global=%#v", cn.Models[index], global.Models[index])
		}
	}
	modelByUpstreamID := make(map[string]catalog.ProviderModel, len(cn.Models))
	for _, model := range cn.Models {
		modelByUpstreamID[model.UpstreamModelID] = model
	}
	for _, currentModelID := range []string{"kimi-k3", "kimi-k2.7-code", "kimi-k2.7-code-highspeed", "kimi-k2.6"} {
		if _, exists := modelByUpstreamID[currentModelID]; !exists {
			t.Fatalf("current Open Platform model %q is missing", currentModelID)
		}
	}
	for _, restrictedModelID := range []string{"kimi-k2.5", "moonshot-v1-8k", "moonshot-v1-32k", "moonshot-v1-128k"} {
		if modelByUpstreamID[restrictedModelID].EntitlementMode != catalog.EntitlementExplicit {
			t.Fatalf("restricted model %q entitlement = %q", restrictedModelID, modelByUpstreamID[restrictedModelID].EntitlementMode)
		}
	}
}

// TestOnboardingCompensatesConfigurationAndSecretWhenCatalogFails verifies the cross-store saga boundary.
// TestOnboardingCompensatesConfigurationAndSecretWhenCatalogFails 验证跨存储 Saga 边界。
func TestOnboardingCompensatesConfigurationAndSecretWhenCatalogFails(t *testing.T) {
	ctx := context.Background()
	protocols := providerconfig.NewProtocolRegistry()
	if errProtocols := bootstrap.RegisterProtocolProfiles(protocols); errProtocols != nil {
		t.Fatalf("RegisterProtocolProfiles() error = %v", errProtocols)
	}
	systems, _ := providerconfig.NewSystemRegistry(protocols)
	if errProviders := bootstrap.RegisterSystemProviders(systems); errProviders != nil {
		t.Fatalf("RegisterSystemProviders() error = %v", errProviders)
	}
	configurations, _ := providerconfig.NewMemoryStore(protocols, systems)
	secrets := secret.NewMemoryStore()
	service, errService := NewService(configurations, secrets, failingCatalogStore{})
	if errService != nil {
		t.Fatalf("NewService() error = %v", errService)
	}
	_, errOnboard := service.OnboardSystemProvider(ctx, OnboardSystemProviderInput{DefinitionID: bootstrap.KimiCNDefinitionID, Handle: "catalog-failure", DisplayName: "Failure", AuthMethodID: "api_key", CredentialLabel: "Primary", Secret: []byte("temporary")})
	if errOnboard == nil {
		t.Fatal("OnboardSystemProvider() error = nil, want catalog failure")
	}
	instances, errInstances := configurations.ListInstances(ctx, bootstrap.KimiCNDefinitionID)
	if errInstances != nil || len(instances) != 0 || secrets.Count() != 0 {
		t.Fatalf("compensation instances=%#v error=%v secrets=%d", instances, errInstances, secrets.Count())
	}
}

// TestOnboardingCompensatesAmbiguousCatalogCommit verifies catalog cleanup precedes configuration cleanup after a commit-like error.
// TestOnboardingCompensatesAmbiguousCatalogCommit 验证类似已提交错误发生后目录补偿先于配置补偿。
func TestOnboardingCompensatesAmbiguousCatalogCommit(t *testing.T) {
	ctx := context.Background()
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
	configurations, errConfigurations := providerconfig.NewMemoryStore(protocols, systems)
	if errConfigurations != nil {
		t.Fatalf("NewMemoryStore() error = %v", errConfigurations)
	}
	secrets := secret.NewMemoryStore()
	catalogs := &ambiguousCatalogStore{MemoryStore: catalog.NewMemoryStore()}
	service, errService := NewService(configurations, secrets, catalogs)
	if errService != nil {
		t.Fatalf("NewService() error = %v", errService)
	}
	_, errOnboard := service.OnboardSystemProvider(ctx, OnboardSystemProviderInput{DefinitionID: bootstrap.KimiCNDefinitionID, Handle: "ambiguous-catalog", DisplayName: "Ambiguous", AuthMethodID: "api_key", CredentialLabel: "Primary", Secret: []byte("temporary")})
	if errOnboard == nil {
		t.Fatal("OnboardSystemProvider() error = nil, want ambiguous catalog failure")
	}
	instances, errInstances := configurations.ListInstances(ctx, bootstrap.KimiCNDefinitionID)
	if errInstances != nil || len(instances) != 0 || secrets.Count() != 0 || !catalogs.deleted {
		t.Fatalf("compensation instances=%#v error=%v secrets=%d catalogDeleted=%t", instances, errInstances, secrets.Count(), catalogs.deleted)
	}
}

// failingCatalogStore deterministically rejects catalog persistence for compensation testing.
// failingCatalogStore 为补偿测试确定性拒绝目录持久化。
type failingCatalogStore struct{}

// Save rejects every snapshot.
// Save 拒绝每个快照。
func (failingCatalogStore) Save(context.Context, catalog.Snapshot) error {
	return errors.New("catalog unavailable")
}

// Delete reports that no snapshot was committed.
// Delete 报告没有快照被提交。
func (failingCatalogStore) Delete(context.Context, string) error {
	return catalog.ErrSnapshotNotFound
}

// Get reports no snapshot.
// Get 报告不存在快照。
func (failingCatalogStore) Get(context.Context, string) (catalog.Snapshot, error) {
	return catalog.Snapshot{}, catalog.ErrSnapshotNotFound
}

// ambiguousCatalogStore commits a snapshot and then reports an error to exercise idempotent saga compensation.
// ambiguousCatalogStore 提交快照后再报告错误，以验证幂等 Saga 补偿。
type ambiguousCatalogStore struct {
	*catalog.MemoryStore
	deleted bool
}

// Save persists the snapshot before returning a deterministic ambiguous failure.
// Save 先持久化快照再返回确定性的模糊失败。
func (s *ambiguousCatalogStore) Save(ctx context.Context, snapshot catalog.Snapshot) error {
	if errSave := s.MemoryStore.Save(ctx, snapshot); errSave != nil {
		return errSave
	}
	return errors.New("catalog commit acknowledgement lost")
}

// Delete records and delegates exact snapshot cleanup.
// Delete 记录并委托精确快照清理。
func (s *ambiguousCatalogStore) Delete(ctx context.Context, providerInstanceID string) error {
	s.deleted = true
	return s.MemoryStore.Delete(ctx, providerInstanceID)
}
