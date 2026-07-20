package inputplan

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	routerresource "github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// fixedResolver returns one mutable fixture target for planning and drift tests.
// fixedResolver 为规划与漂移测试返回一个可变夹具 Target。
type fixedResolver struct{ target resolve.Target }

// Resolve returns the exact fixture target.
// Resolve 返回精确夹具 Target。
func (r *fixedResolver) Resolve(context.Context, resolve.Request) (resolve.Target, resolve.Diagnostics, error) {
	return r.target, resolve.Diagnostics{ReadyCandidates: 1}, nil
}

// fixedResourceReader returns one owner-scoped fixture resource.
// fixedResourceReader 返回一个所有者作用域夹具资源。
type fixedResourceReader struct{ value routerresource.Resource }

// Get returns the fixture only for its exact owner and identifier.
// Get 仅为精确所有者与标识返回夹具。
func (r fixedResourceReader) Get(_ context.Context, owner string, identifier string) (routerresource.Resource, error) {
	if owner != r.value.OwnerAPIKeyID || identifier != r.value.ID {
		return routerresource.Resource{}, routerresource.ErrResourceNotFound
	}
	return r.value, nil
}

// TestServiceFreezesMaterializationAndDetectsCapabilityDrift verifies deterministic planning and revalidation.
// TestServiceFreezesMaterializationAndDetectsCapabilityDrift 验证确定性规划与重新校验。
func TestServiceFreezesMaterializationAndDetectsCapabilityDrift(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC)
	resolver := &fixedResolver{target: inputPlanTarget()}
	reader := fixedResourceReader{value: inputPlanResource(now)}
	service, errService := NewService(resolver, reader, NewMemoryStore(), ServiceOptions{TTL: 10 * time.Minute, Now: func() time.Time { return now }, NewID: func() (string, error) { return "ipl_0123456789abcdef0123456789abcdef", nil }})
	if errService != nil {
		t.Fatalf("NewService() error = %v", errService)
	}
	plan, errCreate := service.Create(context.Background(), Request{OwnerAPIKeyID: "api_owner", Model: vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: "pvi_1", ProviderModelID: "model_1", ExecutionProfileID: "profile_1"}, Operation: vcp.OperationConversationRespond, Inputs: []Input{{InputID: "image_1", ResourceID: reader.value.ID, Role: vcp.MediaRoleUnderstanding}}})
	if errCreate != nil {
		t.Fatalf("Create() error = %v", errCreate)
	}
	if !plan.Accepted || len(plan.Inputs) != 1 || plan.Inputs[0].Materialization != catalog.MaterializationInlineBase64 || plan.RequiresProviderPreparation {
		t.Fatalf("plan = %#v", plan)
	}
	if _, errValidate := service.Revalidate(context.Background(), "api_owner", plan.ID); errValidate != nil {
		t.Fatalf("Revalidate() error = %v", errValidate)
	}
	resolver.target.CapabilityRevision++
	if _, errValidate := service.Revalidate(context.Background(), "api_owner", plan.ID); !errors.Is(errValidate, ErrCapabilityChanged) {
		t.Fatalf("Revalidate() error = %v, want capability changed", errValidate)
	}
}

// TestServiceRejectsPendingWorkflowOutsideCapability verifies client acquisition is contract-bound.
// TestServiceRejectsPendingWorkflowOutsideCapability 验证客户端获取方式受契约约束。
func TestServiceRejectsPendingWorkflowOutsideCapability(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC)
	service, errService := NewService(&fixedResolver{target: inputPlanTarget()}, fixedResourceReader{value: inputPlanResource(now)}, NewMemoryStore(), ServiceOptions{TTL: time.Minute, Now: func() time.Time { return now }, NewID: func() (string, error) { return "ipl_fedcba9876543210fedcba9876543210", nil }})
	if errService != nil {
		t.Fatalf("NewService() error = %v", errService)
	}
	plan, errCreate := service.Create(context.Background(), Request{OwnerAPIKeyID: "api_owner", Model: vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: "pvi_1", ProviderModelID: "model_1", ExecutionProfileID: "profile_1"}, Operation: vcp.OperationConversationRespond, Inputs: []Input{{InputID: "pending", Role: vcp.MediaRoleUnderstanding, Pending: &PendingResource{Kind: vcp.MediaImage, MIMEType: "image/png", SizeBytes: 10, Workflow: catalog.ClientWorkflowImportURLThenReference}}}})
	if errCreate != nil {
		t.Fatalf("Create() error = %v", errCreate)
	}
	if plan.Accepted || plan.ErrorCode != "media_capability_rejected" {
		t.Fatalf("rejected plan = %#v", plan)
	}
}

// TestServiceEnforcesGeneratedSourceRequirement verifies arbitrary uploaded bytes cannot enter a provider-generated-only workflow.
// TestServiceEnforcesGeneratedSourceRequirement 验证任意上传字节不能进入仅允许供应商生成来源的工作流。
func TestServiceEnforcesGeneratedSourceRequirement(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC)
	target := resolve.Target{ProviderDefinitionID: "definition-google", ProviderInstanceID: "instance-google", ChannelID: "google.veo.extend.v3.1", EndpointID: "endpoint-google", CredentialID: "credential-google", SubjectKind: resolve.ExecutionSubjectModel, ProviderModelID: "model-veo-extension", OfferingID: "offering-veo-extension", Operation: vcp.OperationVideoExtend, ActionBindingID: "action_google_video_extend", ExecutionProfileID: "profile-veo-extension", UpstreamModelID: "veo-3.1-generate-preview", CapabilityRevision: 1, ProviderConfigRevision: 1, CatalogRevision: 1, ModelCapabilities: catalog.ModelCapabilities{MediaInputs: []catalog.MediaInputCapability{{Kind: vcp.MediaVideo, Roles: []vcp.MediaInputRole{vcp.MediaRoleEditSource}, Level: catalog.CapabilityNative, InteractionModes: []catalog.MediaInteractionMode{catalog.MediaInteractionOperationInput}, ClientWorkflows: []catalog.ClientResourceWorkflow{catalog.ClientWorkflowResolveInputPlan}, MaterializationModes: []catalog.UpstreamMaterializationMode{catalog.MaterializationInlineBase64}, GeneratedSource: &catalog.GeneratedSourceRequirement{Required: true, SameProviderDefinition: true, AllowedOperations: []vcp.OperationKind{vcp.OperationVideoGenerate}, AllowedUpstreamModels: []string{"veo-3.1-generate-preview"}}, Common: catalog.CommonMediaLimits{MIMETypes: []string{"video/mp4"}}, Video: &catalog.VideoMediaLimits{}, EvidenceRevision: 1}}}}
	expiresAt := now.Add(time.Hour)
	video := routerresource.Resource{ID: "res_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", OwnerAPIKeyID: "api_owner", Kind: vcp.MediaVideo, MIMEType: "video/mp4", SizeBytes: 10, SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Metadata: routerresource.Metadata{Video: &routerresource.VideoMetadata{}}, Source: routerresource.SourceGenerated, GeneratedBy: &routerresource.GenerationProvenance{ExecutionID: "execution-veo", ProviderDefinitionID: "definition-google", ProviderModelID: "model-veo", UpstreamModelID: "veo-3.1-generate-preview", ActionBindingID: "action_google_video_generate", Operation: vcp.OperationVideoGenerate}, State: routerresource.StateReady, Retention: routerresource.RetentionEphemeral, ObjectKey: "objects/video", CreatedAt: now, UpdatedAt: now, ExpiresAt: &expiresAt, Revision: 2}
	reader := fixedResourceReader{value: video}
	service, errService := NewService(&fixedResolver{target: target}, reader, NewMemoryStore(), ServiceOptions{TTL: time.Minute, Now: func() time.Time { return now }, NewID: func() (string, error) { return "ipl_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil }})
	if errService != nil {
		t.Fatalf("NewService() error = %v", errService)
	}
	request := Request{OwnerAPIKeyID: "api_owner", Model: vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: target.ProviderInstanceID, ProviderModelID: target.ProviderModelID, ExecutionProfileID: target.ExecutionProfileID}, Operation: vcp.OperationVideoExtend, Inputs: []Input{{InputID: "source", ResourceID: video.ID, Role: vcp.MediaRoleEditSource}}}
	plan, errCreate := service.Create(context.Background(), request)
	if errCreate != nil || !plan.Accepted || plan.Inputs[0].GeneratedBy == nil {
		t.Fatalf("Create() = %#v, error = %v", plan, errCreate)
	}
	video.GeneratedBy.ProviderDefinitionID = "definition-other"
	rejectedService, errRejectedService := NewService(&fixedResolver{target: target}, fixedResourceReader{value: video}, NewMemoryStore(), ServiceOptions{TTL: time.Minute, Now: func() time.Time { return now }, NewID: func() (string, error) { return "ipl_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", nil }})
	if errRejectedService != nil {
		t.Fatalf("NewService(rejected) error = %v", errRejectedService)
	}
	rejected, errRejected := rejectedService.Create(context.Background(), request)
	if errRejected != nil || rejected.Accepted || rejected.ErrorCode != "media_capability_rejected" {
		t.Fatalf("rejected Create() = %#v, error = %v", rejected, errRejected)
	}
}

// inputPlanTarget returns one exact model target with an image contract.
// inputPlanTarget 返回一个带图片契约的精确模型 Target。
func inputPlanTarget() resolve.Target {
	return resolve.Target{ProviderDefinitionID: "provider_1", ProviderInstanceID: "pvi_1", ChannelID: "channel_1", EndpointID: "endpoint_1", CredentialID: "credential_1", SubjectKind: resolve.ExecutionSubjectModel, ProviderModelID: "model_1", OfferingID: "offering_1", Operation: vcp.OperationConversationRespond, ActionBindingID: "action_1", ExecutionProfileID: "profile_1", UpstreamModelID: "upstream_1", CapabilityRevision: 3, ProviderConfigRevision: 2, CatalogRevision: 7, ModelCapabilities: catalog.ModelCapabilities{MediaInputs: []catalog.MediaInputCapability{{Kind: vcp.MediaImage, Roles: []vcp.MediaInputRole{vcp.MediaRoleUnderstanding}, Level: catalog.CapabilityNative, InteractionModes: []catalog.MediaInteractionMode{catalog.MediaInteractionMixedConversation}, MediaOnlyPolicy: catalog.MediaOnlyUnsupported, ClientWorkflows: []catalog.ClientResourceWorkflow{catalog.ClientWorkflowUploadThenReference}, MaterializationModes: []catalog.UpstreamMaterializationMode{catalog.MaterializationInlineBase64}, Common: catalog.CommonMediaLimits{MIMETypes: []string{"image/png"}, MaxItemBytes: catalog.OptionalLimit{Known: true, Value: 1024}}, Image: &catalog.ImageMediaLimits{}, EvidenceRevision: 1}}}}
}

// inputPlanResource returns one authoritative ready image fixture.
// inputPlanResource 返回一个权威就绪图片夹具。
func inputPlanResource(now time.Time) routerresource.Resource {
	expiresAt := now.Add(time.Hour)
	return routerresource.Resource{ID: "res_0123456789abcdef0123456789abcdef", OwnerAPIKeyID: "api_owner", Kind: vcp.MediaImage, MIMEType: "image/png", SizeBytes: 10, SHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", Metadata: routerresource.Metadata{Image: &routerresource.ImageMetadata{Width: 1, Height: 1}}, Source: routerresource.SourceMultipart, State: routerresource.StateReady, Retention: routerresource.RetentionEphemeral, ObjectKey: "objects/value", CreatedAt: now, UpdatedAt: now, ExpiresAt: &expiresAt, Revision: 2}
}
