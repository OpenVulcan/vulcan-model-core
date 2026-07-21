package management

import (
	"context"
	"slices"
	"testing"

	"github.com/OpenVulcan/vulcan-model-core/internal/bootstrap"
	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	providerkimi "github.com/OpenVulcan/vulcan-model-core/internal/provider/kimi"
)

// TestKimiDeclaredMembershipMatrix verifies every user-confirmed tier grants only its exact model profiles.
// TestKimiDeclaredMembershipMatrix 验证每个用户确认档位仅授予其精确模型规格。
func TestKimiDeclaredMembershipMatrix(t *testing.T) {
	testCases := []struct {
		// name labels the membership test case.
		// name 标记会员测试场景。
		name string
		// planOptionID selects the exact code-owned tier.
		// planOptionID 选择精确代码拥有档位。
		planOptionID string
		// allowedContexts maps upstream models to allowed context profiles.
		// allowedContexts 将上游模型映射到允许的上下文规格。
		allowedContexts map[string][]int64
	}{
		{name: "Andante", planOptionID: providerkimi.PlanOptionAndante, allowedContexts: map[string][]int64{"kimi-for-coding": {262144}}},
		{name: "Moderato", planOptionID: providerkimi.PlanOptionModerato, allowedContexts: map[string][]int64{"kimi-for-coding": {262144}, "k3": {262144}}},
		{name: "Allegretto", planOptionID: providerkimi.PlanOptionAllegretto, allowedContexts: map[string][]int64{"kimi-for-coding": {262144}, "k3": {262144, 1048576}, "kimi-for-coding-highspeed": {262144}}},
		{name: "Allegro", planOptionID: providerkimi.PlanOptionAllegro, allowedContexts: map[string][]int64{"kimi-for-coding": {262144}, "k3": {262144, 1048576}, "kimi-for-coding-highspeed": {262144}}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			service, _, _ := newKimiOnboardingService(t)
			onboarding, errOnboard := service.OnboardSystemProvider(context.Background(), OnboardSystemProviderInput{DefinitionID: bootstrap.KimiCodingDefinitionID, DisplayName: testCase.name, AuthMethodID: "api_key", CredentialLabel: testCase.name, Secret: []byte("test-key-" + testCase.name), PlanOptionID: testCase.planOptionID})
			if errOnboard != nil {
				t.Fatalf("OnboardSystemProvider() error = %v", errOnboard)
			}
			snapshot, errSnapshot := service.catalogs.Get(context.Background(), onboarding.Instance.ID)
			if errSnapshot != nil {
				t.Fatalf("Get() catalog error = %v", errSnapshot)
			}
			assertKimiMembershipSnapshot(t, snapshot, testCase.allowedContexts)
		})
	}
}

// TestKimiAPIKeyRequiresDeclaredMembership verifies a static key cannot gain inferred maximum-plan access.
// TestKimiAPIKeyRequiresDeclaredMembership 验证静态密钥不能获得推断出的最高套餐访问权。
func TestKimiAPIKeyRequiresDeclaredMembership(t *testing.T) {
	service, _, _ := newKimiOnboardingService(t)
	_, errOnboard := service.OnboardSystemProvider(context.Background(), OnboardSystemProviderInput{DefinitionID: bootstrap.KimiCodingDefinitionID, DisplayName: "Unknown", AuthMethodID: "api_key", CredentialLabel: "Unknown", Secret: []byte("test-key")})
	if errOnboard == nil {
		t.Fatal("OnboardSystemProvider() accepted a Kimi Coding API key without membership")
	}
}

// assertKimiMembershipSnapshot compares one catalog to exact allowed context windows per upstream model.
// assertKimiMembershipSnapshot 将一个目录与每个上游模型精确允许的上下文窗口进行比较。
func assertKimiMembershipSnapshot(t *testing.T, snapshot catalog.Snapshot, expected map[string][]int64) {
	t.Helper()
	modelByID := make(map[string]catalog.ProviderModel, len(snapshot.Models))
	for _, model := range snapshot.Models {
		modelByID[model.ID] = model
	}
	offeringModel := make(map[string]string, len(snapshot.Offerings))
	for _, offering := range snapshot.Offerings {
		offeringModel[offering.ID] = modelByID[offering.ProviderModelID].UpstreamModelID
	}
	profileContext := make(map[string]int64, len(snapshot.Profiles))
	for _, profile := range snapshot.Profiles {
		profileContext[profile.ID] = profile.Capabilities.Tokens.ContextWindow.Value
		if offeringModel[profile.OfferingID] == "k3" && !slices.Equal(profile.Capabilities.ReasoningEfforts, []string{"low", "high", "max"}) {
			t.Fatalf("K3 reasoning efforts = %#v", profile.Capabilities.ReasoningEfforts)
		}
	}
	for _, entitlement := range snapshot.Entitlements {
		upstreamModelID := modelByID[entitlement.ProviderModelID].UpstreamModelID
		contexts := make([]int64, 0, len(entitlement.AllowedProfileIDs))
		for _, profileID := range entitlement.AllowedProfileIDs {
			contexts = append(contexts, profileContext[profileID])
		}
		if !slices.Equal(contexts, expected[upstreamModelID]) {
			t.Fatalf("model %s contexts = %v, want %v", upstreamModelID, contexts, expected[upstreamModelID])
		}
		wantAvailability := catalog.AvailabilityDenied
		if len(expected[upstreamModelID]) > 0 {
			wantAvailability = catalog.AvailabilityAllowed
		}
		if entitlement.Availability != wantAvailability || entitlement.EvidenceSource != catalog.MetadataEvidenceOperatorDeclared {
			t.Fatalf("model %s entitlement = %#v", upstreamModelID, entitlement)
		}
	}
}
