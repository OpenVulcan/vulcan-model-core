package management

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
)

// TestSetModelEnabledPersistsOnlyCatalogOwnedModelPolicy verifies local model policy cannot target fabricated model identifiers.
// TestSetModelEnabledPersistsOnlyCatalogOwnedModelPolicy 验证本地模型策略不能指向伪造的模型标识。
func TestSetModelEnabledPersistsOnlyCatalogOwnedModelPolicy(t *testing.T) {
	// ctx fixes the operation scope for configuration and catalog access.
	// ctx 为配置和目录访问固定操作范围。
	ctx := context.Background()
	// commands and configurations share the memory-backed provider configuration state.
	// commands 和 configurations 共享内存后端供应商配置状态。
	commands, configurations, _ := managementTestService(t)
	instance, errInstance := commands.CreateInstance(ctx, CreateInstanceInput{
		ID: "pvi_model_policy", DefinitionID: "system_management_test", Handle: "model-policy", DisplayName: "Model Policy",
	})
	if errInstance != nil {
		t.Fatalf("create provider instance: %v", errInstance)
	}
	// catalogs contains the atomic model ownership fact used by the policy service.
	// catalogs 包含策略服务使用的原子模型归属事实。
	catalogs := catalog.NewMemoryStore()
	if errSave := catalogs.Save(ctx, catalog.Snapshot{
		ProviderInstanceID: instance.ID,
		Models: []catalog.ProviderModel{{
			ID: "model_policy_target", ProviderInstanceID: instance.ID, UpstreamModelID: "target-model", DisplayName: "Target Model",
			Source: catalog.ModelSourceSystem, EntitlementMode: catalog.EntitlementAllBoundCredentials, Revision: 1,
		}},
		Revision: 1, ObservedAt: time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC),
	}); errSave != nil {
		t.Fatalf("save provider catalog: %v", errSave)
	}
	access, errAccess := NewModelAccessService(configurations, catalogs)
	if errAccess != nil {
		t.Fatalf("create model access service: %v", errAccess)
	}
	disabled, errDisable := access.SetModelEnabled(ctx, SetModelEnabledInput{
		ProviderInstanceID: instance.ID, ProviderModelID: "model_policy_target", Enabled: false,
	})
	if errDisable != nil {
		t.Fatalf("disable catalog model: %v", errDisable)
	}
	if len(disabled.DisabledModelIDs) != 1 || disabled.DisabledModelIDs[0] != "model_policy_target" || disabled.Revision != instance.Revision+1 {
		t.Fatalf("disabled instance = %+v", disabled)
	}
	repeated, errRepeat := access.SetModelEnabled(ctx, SetModelEnabledInput{
		ProviderInstanceID: instance.ID, ProviderModelID: "model_policy_target", Enabled: false,
	})
	if errRepeat != nil {
		t.Fatalf("repeat disable catalog model: %v", errRepeat)
	}
	if repeated.Revision != disabled.Revision {
		t.Fatalf("repeated disable revision = %d, want %d", repeated.Revision, disabled.Revision)
	}
	enabled, errEnable := access.SetModelEnabled(ctx, SetModelEnabledInput{
		ProviderInstanceID: instance.ID, ProviderModelID: "model_policy_target", Enabled: true,
	})
	if errEnable != nil {
		t.Fatalf("enable catalog model: %v", errEnable)
	}
	if len(enabled.DisabledModelIDs) != 0 || enabled.Revision != disabled.Revision+1 {
		t.Fatalf("enabled instance = %+v", enabled)
	}
	_, errMissing := access.SetModelEnabled(ctx, SetModelEnabledInput{
		ProviderInstanceID: instance.ID, ProviderModelID: "model_unknown", Enabled: false,
	})
	if !errors.Is(errMissing, ErrProviderModelNotFound) {
		t.Fatalf("unknown model error = %v, want ErrProviderModelNotFound", errMissing)
	}
}
