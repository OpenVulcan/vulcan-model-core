package management

import (
	"context"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/bootstrap"
	providerkimi "github.com/OpenVulcan/vulcan-model-core/internal/provider/kimi"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/routingstate"
)

// TestRoutingServicePersistsPolicyPriorityAndKimiPlan verifies every management mutation against exact durable records.
// TestRoutingServicePersistsPolicyPriorityAndKimiPlan 验证每项管理变更对应的精确持久化记录。
func TestRoutingServicePersistsPolicyPriorityAndKimiPlan(t *testing.T) {
	ctx := context.Background()
	commands, configurations, _ := newKimiOnboardingService(t)
	onboarding, errOnboard := commands.OnboardSystemProvider(ctx, OnboardSystemProviderInput{DefinitionID: bootstrap.KimiCodingDefinitionID, DisplayName: "Kimi Account", AuthMethodID: "api_key", CredentialLabel: "Kimi Account", Secret: []byte("test-key"), PlanOptionID: providerkimi.PlanOptionAllegro})
	if errOnboard != nil {
		t.Fatalf("OnboardSystemProvider() error = %v", errOnboard)
	}
	states := routingstate.NewMemoryStore(time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC))
	service, errService := NewRoutingService(configurations, commands.catalogs, states)
	if errService != nil {
		t.Fatalf("NewRoutingService() error = %v", errService)
	}
	mutationTime := time.Date(2026, 7, 21, 13, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return mutationTime }
	settings, errSettings := service.SetDefaultRoutingStrategy(ctx, providerconfig.RoutingFillFirst)
	if errSettings != nil || settings.DefaultRoutingStrategy != providerconfig.RoutingFillFirst || settings.Revision != 2 {
		t.Fatalf("updated settings = %#v, error = %v", settings, errSettings)
	}
	instance, errInstance := service.SetInstanceRoutingStrategy(ctx, onboarding.Instance.ID, providerconfig.RoutingRoundRobin)
	if errInstance != nil || instance.RoutingStrategy != providerconfig.RoutingRoundRobin {
		t.Fatalf("updated instance = %#v, error = %v", instance, errInstance)
	}
	credential, errPriority := service.SetCredentialPriority(ctx, onboarding.Instance.ID, onboarding.Credential.ID, 7)
	if errPriority != nil || credential.Priority != 7 {
		t.Fatalf("updated priority credential = %#v, error = %v", credential, errPriority)
	}
	credential, errPlan := service.SetCredentialPlan(ctx, onboarding.Instance.ID, onboarding.Credential.ID, providerkimi.PlanOptionAndante)
	if errPlan != nil || credential.DeclaredPlan == nil || credential.DeclaredPlan.PlanOptionID != providerkimi.PlanOptionAndante {
		t.Fatalf("updated plan credential = %#v, error = %v", credential, errPlan)
	}
	snapshot, errSnapshot := commands.catalogs.Get(ctx, onboarding.Instance.ID)
	if errSnapshot != nil {
		t.Fatalf("Get() updated catalog error = %v", errSnapshot)
	}
	allowedModels := 0
	for _, entitlement := range snapshot.Entitlements {
		if entitlement.Availability == "allowed" {
			allowedModels++
		}
	}
	if allowedModels != 1 || len(snapshot.Plans) != 1 || snapshot.Plans[0].PlanCode != providerkimi.PlanOptionAndante || len(snapshot.Pools) != 4 {
		t.Fatalf("updated Kimi catalog plans=%#v entitlements=%#v pools=%#v", snapshot.Plans, snapshot.Entitlements, snapshot.Pools)
	}
}
