package sqlitestore

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/inputplan"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestInputPlanAndAssetBindingStoresPersistPrivateTargetOwnership verifies plan and binding restart-safe identities.
// TestInputPlanAndAssetBindingStoresPersistPrivateTargetOwnership 验证方案与绑定可跨重启保存私有 Target 归属。
func TestInputPlanAndAssetBindingStoresPersistPrivateTargetOwnership(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, errDatabase := Open(ctx, filepath.Join(t.TempDir(), "plans.db"))
	if errDatabase != nil {
		t.Fatalf("Open() error = %v", errDatabase)
	}
	t.Cleanup(func() { _ = database.Close() })
	planStore, errPlanStore := NewInputPlanStore(database)
	if errPlanStore != nil {
		t.Fatalf("NewInputPlanStore() error = %v", errPlanStore)
	}
	now := time.Date(2026, 7, 20, 13, 0, 0, 0, time.UTC)
	model := vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: "pvi_1", ProviderModelID: "model_1", ExecutionProfileID: "profile_1"}
	target := resolve.Target{ProviderDefinitionID: "provider_1", ProviderInstanceID: "pvi_1", EndpointID: "endpoint_1", CredentialID: "credential_1", ProviderModelID: "model_1", OfferingID: "offering_1", ActionBindingID: "action_1", ExecutionProfileID: "profile_1", UpstreamModelID: "upstream_1", CapabilityRevision: 2, CatalogRevision: 3}
	plan := inputplan.Plan{ID: "ipl_0123456789abcdef0123456789abcdef", OwnerAPIKeyID: "api_owner", Accepted: true, Operation: vcp.OperationConversationRespond, Model: model, Target: target, CapabilityRevision: 2, CatalogRevision: 3, Inputs: []inputplan.PlannedInput{{InputID: "image", ResourceID: "res_0123456789abcdef0123456789abcdef", SHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", Kind: vcp.MediaImage, MIMEType: "image/png", SizeBytes: 8, Role: vcp.MediaRoleUnderstanding, ClientStep: inputplan.ClientStepReferenceExisting, Materialization: catalog.MaterializationProviderFileID}}, CreatedAt: now, ExpiresAt: now.Add(time.Hour), Revision: 1}
	if errSave := planStore.Save(ctx, plan); errSave != nil {
		t.Fatalf("Save(plan) error = %v", errSave)
	}
	persistedPlan, errGet := planStore.Get(ctx, plan.ID)
	if errGet != nil || persistedPlan.OwnerAPIKeyID != plan.OwnerAPIKeyID || persistedPlan.Target.CredentialID != target.CredentialID {
		t.Fatalf("Get(plan) = %#v, error = %v", persistedPlan, errGet)
	}
	resourceStore, errResourceStore := NewResourceStore(database)
	if errResourceStore != nil {
		t.Fatalf("NewResourceStore() error = %v", errResourceStore)
	}
	receiving := receivingResource(plan.Inputs[0].ResourceID, now)
	if errCreate := resourceStore.CreateReceiving(ctx, receiving); errCreate != nil {
		t.Fatalf("CreateReceiving() error = %v", errCreate)
	}
	ready := readyResource(receiving, 8, now.Add(time.Minute))
	if errReady := resourceStore.CommitReady(ctx, ready, 100); errReady != nil {
		t.Fatalf("CommitReady() error = %v", errReady)
	}
	bindingStore, errBindingStore := NewAssetBindingStore(database)
	if errBindingStore != nil {
		t.Fatalf("NewAssetBindingStore() error = %v", errBindingStore)
	}
	bindingTarget := resource.AssetBindingTarget{ProviderDefinitionID: target.ProviderDefinitionID, ProviderInstanceID: target.ProviderInstanceID, EndpointID: target.EndpointID, CredentialID: target.CredentialID, ActionBindingID: target.ActionBindingID, ProviderModelID: target.ProviderModelID, UpstreamModelID: target.UpstreamModelID}
	expiresAt := now.Add(time.Hour)
	binding := resource.ProviderAssetBinding{ID: "pab_0123456789abcdef0123456789abcdef", ResourceID: ready.ID, ResourceSHA256: ready.SHA256, Target: bindingTarget, Materialization: catalog.MaterializationProviderFileID, Kind: resource.ProviderAssetFile, ProtectedHandleRef: "secret_provider_asset_1", CreatedAt: now, ExpiresAt: &expiresAt, Revision: 1}
	if errSave := bindingStore.Save(ctx, binding); errSave != nil {
		t.Fatalf("Save(binding) error = %v", errSave)
	}
	persistedBinding, errFind := bindingStore.FindExact(ctx, ready.ID, ready.SHA256, bindingTarget, catalog.MaterializationProviderFileID, now.Add(time.Minute))
	if errFind != nil || persistedBinding.ProtectedHandleRef != binding.ProtectedHandleRef {
		t.Fatalf("FindExact() = %#v, error = %v", persistedBinding, errFind)
	}
	if errDelete := bindingStore.DeleteByResource(ctx, ready.ID); errDelete != nil {
		t.Fatalf("DeleteByResource() error = %v", errDelete)
	}
	if _, errFind := bindingStore.FindExact(ctx, ready.ID, ready.SHA256, bindingTarget, catalog.MaterializationProviderFileID, now.Add(time.Minute)); errFind != resource.ErrAssetBindingNotFound {
		t.Fatalf("FindExact(after delete) error = %v", errFind)
	}
}
