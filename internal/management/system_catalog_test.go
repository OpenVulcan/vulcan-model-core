package management

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/bootstrap"
	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	provideropenai "github.com/OpenVulcan/vulcan-model-core/internal/provider/openai"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestEveryRuntimeReadySystemDefinitionOwnsAValidInitialCatalog verifies provider selection never fails after credential acquisition.
// TestEveryRuntimeReadySystemDefinitionOwnsAValidInitialCatalog 验证凭据获取后选择供应商绝不会因目录缺失而失败。
func TestEveryRuntimeReadySystemDefinitionOwnsAValidInitialCatalog(t *testing.T) {
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
	observedAt := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	for index, definition := range systems.List() {
		if !definition.RuntimeReady {
			continue
		}
		snapshot, errCatalog := buildSystemCatalog(providerconfig.SystemOnboarding{Instance: providerconfig.ProviderInstance{ID: fmt.Sprintf("pvi_catalog_%d", index)}}, definition, observedAt)
		if errCatalog != nil {
			t.Errorf("definition %s catalog error = %v", definition.ID, errCatalog)
			continue
		}
		if errValidate := snapshot.Validate(); errValidate != nil {
			t.Errorf("definition %s catalog validation error = %v", definition.ID, errValidate)
		}
		offeringsByID := make(map[string]catalog.ModelOffering, len(snapshot.Offerings))
		for _, offering := range snapshot.Offerings {
			offeringsByID[offering.ID] = offering
		}
		serviceOfferingsByID := make(map[string]catalog.ServiceOffering, len(snapshot.ServiceOfferings))
		for _, offering := range snapshot.ServiceOfferings {
			serviceOfferingsByID[offering.ID] = offering
		}
		for _, profile := range snapshot.Profiles {
			action, errAction := definitionActionByID(definition, profile.ActionBindingID)
			if profile.ServiceOfferingID != "" {
				offering := serviceOfferingsByID[profile.ServiceOfferingID]
				if errAction != nil || profile.ActionBindingID != action.ID || offering.ChannelID != action.ProtocolProfileID || profile.ServiceCapabilities == nil {
					t.Errorf("definition %s service profile action contract = %#v", definition.ID, profile)
				}
				continue
			}
			offering := offeringsByID[profile.OfferingID]
			if errAction != nil || profile.ActionBindingID != action.ID || offering.ChannelID != action.ProtocolProfileID || profile.Capabilities.Delivery.Synchronous != action.Delivery.Synchronous || profile.Capabilities.Delivery.Streaming != action.Delivery.Streaming || profile.Capabilities.Delivery.Asynchronous != action.Delivery.Asynchronous {
				t.Errorf("definition %s profile action contract = %#v", definition.ID, profile)
			}
		}
	}
}

// TestOpenAIAPIInitialCatalogPublishesGroundedSearchAndEmbeddingModels verifies the evidence-closed OpenAI inventory.
// TestOpenAIAPIInitialCatalogPublishesGroundedSearchAndEmbeddingModels 验证证据封闭的 OpenAI 清单。
func TestOpenAIAPIInitialCatalogPublishesGroundedSearchAndEmbeddingModels(t *testing.T) {
	templates, errTemplates := systemModelTemplates("openai_api")
	if errTemplates != nil {
		t.Fatalf("systemModelTemplates() error = %v", errTemplates)
	}
	if len(templates) != 11 || templates[0].upstreamID != provideropenai.SearchBackingModelID || templates[1].upstreamID != "text-embedding-3-small" || templates[2].upstreamID != "text-embedding-3-large" || templates[3].operation != vcp.OperationImageGenerate || templates[4].operation != vcp.OperationImageEdit || templates[5].operation != vcp.OperationSpeechSynthesize || templates[7].operation != vcp.OperationSpeechTranscribe || templates[10].upstreamID != "whisper-1" {
		t.Fatalf("OpenAI API templates = %#v", templates)
	}
	for _, template := range templates[1:3] {
		if template.operation != vcp.OperationEmbeddingCreate || template.embedding == nil || template.embedding.MaxBatchItems.Value != 2048 {
			t.Fatalf("OpenAI embedding template = %#v", template)
		}
	}
}

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
	if len(cn.Models) != 11 || len(global.Models) != 11 || len(coding.Models) != 3 || len(coding.Offerings) != 3 || len(coding.Profiles) != 4 {
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
	// codingModelIDs is the exact user-confirmed Kimi Coding Plan product set.
	// codingModelIDs 是用户确认的精确 Kimi Coding Plan 产品集合。
	codingModelIDs := []string{"kimi-for-coding", "k3", "kimi-for-coding-highspeed"}
	for index, modelID := range codingModelIDs {
		if coding.Models[index].UpstreamModelID != modelID || coding.Models[index].EntitlementMode != catalog.EntitlementExplicit {
			t.Fatalf("Coding model[%d] = %#v, want upstream %q with explicit entitlement", index, coding.Models[index], modelID)
		}
	}
}

// TestBuildSystemCatalogSeparatesCodexKeyAndAccountEntitlements verifies one shared model union keeps product-specific authorization semantics.
// TestBuildSystemCatalogSeparatesCodexKeyAndAccountEntitlements 验证共享模型并集仍保留产品特定授权语义。
func TestBuildSystemCatalogSeparatesCodexKeyAndAccountEntitlements(t *testing.T) {
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
	apiKeyDefinition, _ := systems.Lookup(bootstrap.OpenAICodexAPIKeyDefinitionID)
	accountDefinition, _ := systems.Lookup(bootstrap.OpenAICodexDefinitionID)
	observedAt := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	apiKeyCatalog, errAPIKey := buildSystemCatalog(providerconfig.SystemOnboarding{Instance: providerconfig.ProviderInstance{ID: "pvi_codex_key"}}, apiKeyDefinition, observedAt)
	accountCatalog, errAccount := buildSystemCatalog(providerconfig.SystemOnboarding{Instance: providerconfig.ProviderInstance{ID: "pvi_codex_account"}}, accountDefinition, observedAt)
	if errAPIKey != nil || errAccount != nil {
		t.Fatalf("Codex catalog errors API key=%v account=%v", errAPIKey, errAccount)
	}
	if len(apiKeyCatalog.Models) != 8 || len(accountCatalog.Models) != 8 {
		t.Fatalf("Codex catalog sizes API key=%d account=%d", len(apiKeyCatalog.Models), len(accountCatalog.Models))
	}
	for index := range apiKeyCatalog.Models {
		if apiKeyCatalog.Models[index].UpstreamModelID != accountCatalog.Models[index].UpstreamModelID {
			t.Fatalf("Codex model identity[%d] API key=%#v account=%#v", index, apiKeyCatalog.Models[index], accountCatalog.Models[index])
		}
		if apiKeyCatalog.Models[index].EntitlementMode != catalog.EntitlementAllBoundCredentials || accountCatalog.Models[index].EntitlementMode != catalog.EntitlementExplicit {
			t.Fatalf("Codex entitlement mode[%d] API key=%q account=%q", index, apiKeyCatalog.Models[index].EntitlementMode, accountCatalog.Models[index].EntitlementMode)
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
	// MemoryStore persists the snapshot before the simulated acknowledgement failure.
	// MemoryStore 在模拟确认失败前持久化快照。
	*catalog.MemoryStore
	// deleted records whether saga compensation removed the committed snapshot.
	// deleted 记录 Saga 补偿是否移除了已提交快照。
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
