package management

import (
	"context"
	"testing"

	"github.com/OpenVulcan/vulcan-model-core/internal/bootstrap"
	providergoogle "github.com/OpenVulcan/vulcan-model-core/internal/provider/google"
	providerxai "github.com/OpenVulcan/vulcan-model-core/internal/provider/xai"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
)

// TestReauthorizeCredentialPreservesProviderAccountIdentity verifies replacement cannot silently switch accounts.
// TestReauthorizeCredentialPreservesProviderAccountIdentity 验证替换操作不能静默切换账号。
func TestReauthorizeCredentialPreservesProviderAccountIdentity(t *testing.T) {
	ctx := context.Background()
	service, _, secrets := newKimiOnboardingService(t)
	original, errOriginal := providerxai.MarshalToken(providerxai.Token{AccessToken: "old-access", RefreshToken: "old-refresh", TokenEndpoint: "https://auth.x.ai/oauth/token", Subject: "subject-one", Email: "one@example.com", Type: "xai"})
	if errOriginal != nil {
		t.Fatalf("MarshalToken() original error = %v", errOriginal)
	}
	onboarding, errOnboard := service.OnboardXAIDeviceProvider(ctx, OnboardSystemProviderInput{DefinitionID: bootstrap.XAIOAuthDefinitionID, AuthMethodID: "device_flow", Secret: original})
	if errOnboard != nil {
		t.Fatalf("OnboardXAIDeviceProvider() error = %v", errOnboard)
	}
	replacement, errReplacement := providerxai.MarshalToken(providerxai.Token{AccessToken: "new-access", RefreshToken: "new-refresh", TokenEndpoint: "https://auth.x.ai/oauth/token", Subject: "subject-one", Email: "one@example.com", Type: "xai"})
	if errReplacement != nil {
		t.Fatalf("MarshalToken() replacement error = %v", errReplacement)
	}
	updated, errReauthorize := service.ReauthorizeCredential(ctx, ReauthorizeCredentialInput{ProviderInstanceID: onboarding.Instance.ID, CredentialID: onboarding.Credential.ID, AuthMethodID: "device_flow", Secret: replacement})
	if errReauthorize != nil || updated.Revision != onboarding.Credential.Revision+1 {
		t.Fatalf("ReauthorizeCredential() credential=%#v error=%v", updated, errReauthorize)
	}
	protected, errProtected := secrets.Get(ctx, updated.SecretRef)
	if errProtected != nil {
		t.Fatalf("Get() replacement secret error = %v", errProtected)
	}
	token, errToken := providerxai.UnmarshalToken(protected)
	clear(protected)
	if errToken != nil || token.AccessToken != "new-access" {
		t.Fatalf("replacement token=%#v error=%v", token, errToken)
	}
	foreign, errForeign := providerxai.MarshalToken(providerxai.Token{AccessToken: "foreign-access", RefreshToken: "foreign-refresh", TokenEndpoint: "https://auth.x.ai/oauth/token", Subject: "subject-two", Email: "two@example.com", Type: "xai"})
	if errForeign != nil {
		t.Fatalf("MarshalToken() foreign error = %v", errForeign)
	}
	if _, errReauthorize = service.ReauthorizeCredential(ctx, ReauthorizeCredentialInput{ProviderInstanceID: onboarding.Instance.ID, CredentialID: onboarding.Credential.ID, AuthMethodID: "device_flow", Secret: foreign}); errReauthorize == nil {
		t.Fatal("ReauthorizeCredential() foreign account error = nil")
	}
}

// TestReauthorizeVertexCredentialPreservesAccountProjectAndLocation verifies service-account rotation cannot change routing ownership.
// TestReauthorizeVertexCredentialPreservesAccountProjectAndLocation 验证服务账号轮换不能改变路由归属。
func TestReauthorizeVertexCredentialPreservesAccountProjectAndLocation(t *testing.T) {
	ctx := context.Background()
	service, _, secrets := newKimiOnboardingService(t)
	original := vertexServiceAccountFixture(t)
	onboarding, errOnboard := service.OnboardVertexServiceAccountProvider(ctx, OnboardSystemProviderInput{DefinitionID: bootstrap.GoogleVertexDefinitionID, AuthMethodID: "service_account", Secret: original}, "europe-west1")
	if errOnboard != nil {
		t.Fatalf("OnboardVertexServiceAccountProvider() error = %v", errOnboard)
	}
	replacementCredential, errParse := providergoogle.ParseVertexCredential(vertexServiceAccountFixture(t), "europe-west1")
	if errParse != nil {
		t.Fatalf("ParseVertexCredential() error = %v", errParse)
	}
	replacement, errMarshal := providergoogle.MarshalVertexCredential(replacementCredential)
	if errMarshal != nil {
		t.Fatalf("MarshalVertexCredential() error = %v", errMarshal)
	}
	updated, errReauthorize := service.ReauthorizeCredential(ctx, ReauthorizeCredentialInput{ProviderInstanceID: onboarding.Instance.ID, CredentialID: onboarding.Credential.ID, AuthMethodID: "service_account", Secret: replacement})
	if errReauthorize != nil || updated.Revision != onboarding.Credential.Revision+1 {
		t.Fatalf("ReauthorizeCredential() credential=%#v error=%v", updated, errReauthorize)
	}
	protected, errProtected := secrets.Get(ctx, updated.SecretRef)
	if errProtected != nil {
		t.Fatalf("Get() replacement secret error = %v", errProtected)
	}
	stored, errStored := providergoogle.UnmarshalVertexCredential(protected)
	clear(protected)
	if errStored != nil || stored.Location != "europe-west1" || stored.ProjectID != "vertex-project" {
		t.Fatalf("stored Vertex credential=%#v error=%v", stored, errStored)
	}
	wrongLocationCredential, errWrongLocation := providergoogle.ParseVertexCredential(vertexServiceAccountFixture(t), "asia-east1")
	if errWrongLocation != nil {
		t.Fatalf("ParseVertexCredential() wrong location error = %v", errWrongLocation)
	}
	wrongLocation, errWrongMarshal := providergoogle.MarshalVertexCredential(wrongLocationCredential)
	if errWrongMarshal != nil {
		t.Fatalf("MarshalVertexCredential() wrong location error = %v", errWrongMarshal)
	}
	locationPreserved, errReauthorizeLocation := service.ReauthorizeCredential(ctx, ReauthorizeCredentialInput{ProviderInstanceID: onboarding.Instance.ID, CredentialID: onboarding.Credential.ID, AuthMethodID: "service_account", Secret: wrongLocation})
	if errReauthorizeLocation != nil {
		t.Fatalf("ReauthorizeCredential() alternate submitted location error = %v", errReauthorizeLocation)
	}
	preservedProtected, errPreservedProtected := secrets.Get(ctx, locationPreserved.SecretRef)
	if errPreservedProtected != nil {
		t.Fatalf("Get() location-preserved secret error = %v", errPreservedProtected)
	}
	preserved, errPreserved := providergoogle.UnmarshalVertexCredential(preservedProtected)
	clear(preservedProtected)
	if errPreserved != nil || preserved.Location != "europe-west1" {
		t.Fatalf("location-preserved Vertex credential=%#v error=%v", preserved, errPreserved)
	}
}

// TestDeleteCredentialRetainsFinalInstanceCatalogAndRemovesSecret verifies credential lifecycle does not own provider configuration.
// TestDeleteCredentialRetainsFinalInstanceCatalogAndRemovesSecret 验证凭据生命周期不拥有供应商配置。
func TestDeleteCredentialRetainsFinalInstanceCatalogAndRemovesSecret(t *testing.T) {
	ctx := context.Background()
	service, configurations, secrets := newKimiOnboardingService(t)
	onboarding, errOnboard := service.OnboardSystemProvider(ctx, OnboardSystemProviderInput{DefinitionID: bootstrap.KimiCNDefinitionID, DisplayName: "Kimi", AuthMethodID: "api_key", Secret: []byte("secret-key")})
	if errOnboard != nil {
		t.Fatalf("OnboardSystemProvider() error = %v", errOnboard)
	}
	deletion, errDelete := service.DeleteCredential(ctx, onboarding.Instance.ID, onboarding.Credential.ID)
	if errDelete != nil || deletion.InstanceDeleted || !deletion.InstanceDrafted {
		t.Fatalf("DeleteCredential() deletion=%#v error=%v", deletion, errDelete)
	}
	instance, errInstance := configurations.GetInstance(ctx, onboarding.Instance.ID)
	if errInstance != nil || instance.Status != providerconfig.LifecycleDraft {
		t.Fatalf("retained instance=%#v error=%v", instance, errInstance)
	}
	if _, errSecret := secrets.Get(ctx, onboarding.Credential.SecretRef); errSecret == nil {
		t.Fatal("deleted credential secret remains readable")
	}
	if _, errCatalog := service.catalogs.Get(ctx, onboarding.Instance.ID); errCatalog != nil {
		t.Fatalf("retained provider catalog error = %v", errCatalog)
	}
	endpoints, errEndpoints := configurations.ListEndpoints(ctx, onboarding.Instance.ID)
	if errEndpoints != nil || len(endpoints) == 0 {
		t.Fatalf("retained endpoints=%#v error=%v", endpoints, errEndpoints)
	}
}

// TestConfigureSystemProviderWithoutCredentialBuildsDraftCatalog verifies native providers no longer require account creation for configuration.
// TestConfigureSystemProviderWithoutCredentialBuildsDraftCatalog 验证原生供应商配置不再要求同时创建账号。
func TestConfigureSystemProviderWithoutCredentialBuildsDraftCatalog(t *testing.T) {
	ctx := context.Background()
	service, configurations, _ := newKimiOnboardingService(t)
	configured, errConfigure := service.ConfigureProvider(ctx, ConfigureProviderInput{
		DefinitionID: bootstrap.KimiCNDefinitionID, Handle: "kimi-cn-draft", DisplayName: "Kimi CN Draft",
	})
	if errConfigure != nil {
		t.Fatalf("ConfigureProvider() error = %v", errConfigure)
	}
	if configured.Configuration.Instance.Status != providerconfig.LifecycleDraft || len(configured.Configuration.Endpoints) != 1 || len(configured.Catalog.Models) == 0 {
		t.Fatalf("configured system provider=%#v catalog=%#v", configured.Configuration, configured.Catalog)
	}
	credentials, errCredentials := configurations.ListCredentials(ctx, configured.Configuration.Instance.ID)
	if errCredentials != nil || len(credentials) != 0 {
		t.Fatalf("system provider credentials=%#v error=%v", credentials, errCredentials)
	}
}

// TestConfigureVertexProviderMaterializesSelectedRegion verifies provider configuration owns the regional endpoint before service-account attachment.
// TestConfigureVertexProviderMaterializesSelectedRegion 验证供应商配置会在附加服务账号前拥有所选区域入口。
func TestConfigureVertexProviderMaterializesSelectedRegion(t *testing.T) {
	ctx := context.Background()
	service, _, _ := newKimiOnboardingService(t)
	configured, errConfigure := service.ConfigureProvider(ctx, ConfigureProviderInput{
		DefinitionID: bootstrap.GoogleVertexDefinitionID, Handle: "vertex-europe", DisplayName: "Vertex Europe", Region: "europe-west1",
	})
	if errConfigure != nil {
		t.Fatalf("ConfigureProvider() Vertex error = %v", errConfigure)
	}
	if len(configured.Configuration.Endpoints) != 1 || configured.Configuration.Endpoints[0].Region != "europe-west1" || configured.Configuration.Endpoints[0].BaseURL != providergoogle.VertexBaseURL("europe-west1") {
		t.Fatalf("configured Vertex endpoints = %#v", configured.Configuration.Endpoints)
	}
}

// TestDeleteCredentialPreservesInstanceWithAnotherAccount verifies removing one pool member does not remove shared provider routing.
// TestDeleteCredentialPreservesInstanceWithAnotherAccount 验证删除账号池中的一个成员不会删除共享供应商路由。
func TestDeleteCredentialPreservesInstanceWithAnotherAccount(t *testing.T) {
	ctx := context.Background()
	service, configurations, secrets := newKimiOnboardingService(t)
	onboarding, errOnboard := service.OnboardSystemProvider(ctx, OnboardSystemProviderInput{DefinitionID: bootstrap.KimiCNDefinitionID, DisplayName: "Kimi Primary", AuthMethodID: "api_key", Secret: []byte("primary-key")})
	if errOnboard != nil {
		t.Fatalf("OnboardSystemProvider() error = %v", errOnboard)
	}
	secondary, errSecondary := service.AddCredential(ctx, AddCredentialInput{ProviderInstanceID: onboarding.Instance.ID, AuthMethodID: "api_key", Label: "Kimi Secondary", Secret: []byte("secondary-key")})
	if errSecondary != nil {
		t.Fatalf("AddCredential() error = %v", errSecondary)
	}
	deletion, errDelete := service.DeleteCredential(ctx, onboarding.Instance.ID, secondary.ID)
	if errDelete != nil || deletion.InstanceDeleted {
		t.Fatalf("DeleteCredential() deletion=%#v error=%v", deletion, errDelete)
	}
	if _, errInstance := configurations.GetInstance(ctx, onboarding.Instance.ID); errInstance != nil {
		t.Fatalf("preserved instance error = %v", errInstance)
	}
	credentials, errCredentials := configurations.ListCredentials(ctx, onboarding.Instance.ID)
	if errCredentials != nil || len(credentials) != 1 || credentials[0].ID != onboarding.Credential.ID {
		t.Fatalf("remaining credentials=%#v error=%v", credentials, errCredentials)
	}
	if _, errSecret := secrets.Get(ctx, secondary.SecretRef); errSecret == nil {
		t.Fatal("deleted secondary secret remains readable")
	}
	if _, errCatalog := service.catalogs.Get(ctx, onboarding.Instance.ID); errCatalog != nil {
		t.Fatalf("preserved provider catalog error = %v", errCatalog)
	}
}
