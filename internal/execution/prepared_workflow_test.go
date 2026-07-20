package execution

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestMusicCoverPreparationPublishesOnlyRouterIdentity verifies private provider handles never enter public JSON.
// TestMusicCoverPreparationPublishesOnlyRouterIdentity 验证私有供应商句柄绝不进入公开 JSON。
func TestMusicCoverPreparationPublishesOnlyRouterIdentity(t *testing.T) {
	now := time.Date(2026, time.July, 20, 16, 0, 0, 0, time.UTC)
	store := NewMemoryStore()
	service := &Service{store: store, options: ServiceOptions{Now: func() time.Time { return now }}}
	record := musicCoverPreparationRecord(now, StatusRunning, nil, nil)
	accepted := lifecycleEvent(record.ID, 1, now, EventExecutionAccepted, StatusAccepted, nil)
	if _, _, errCreate := store.Create(context.Background(), record, accepted); errCreate != nil {
		t.Fatalf("Create() error = %v", errCreate)
	}
	providerResult := provider.ExecutionResult{MusicCoverPreparation: &provider.MusicCoverPreparationResult{ProviderHandle: "provider-feature-secret", FormattedLyrics: "[Verse]\nPrepared lyrics", Structure: []vcp.MusicStructureSegment{{Label: "verse", StartSeconds: 0, EndSeconds: 10}}, AudioDurationSeconds: 10, ExpiresAt: now.Add(24 * time.Hour)}}
	completed, _, errSucceed := service.succeedWithStatus(context.Background(), record, providerResult, nil, StatusSucceeded, EventExecutionSucceeded)
	if errSucceed != nil {
		t.Fatalf("succeedWithStatus() error = %v", errSucceed)
	}
	if completed.Result == nil || completed.Result.MusicCoverPreparation == nil || completed.Result.MusicCoverPreparation.PreparationID != record.ID || completed.ProviderPreparation == nil || completed.ProviderPreparation.ProviderHandle != "provider-feature-secret" {
		t.Fatalf("completed = %#v", completed)
	}
	encoded, errEncode := json.Marshal(completed)
	if errEncode != nil {
		t.Fatalf("json.Marshal() error = %v", errEncode)
	}
	if strings.Contains(string(encoded), "provider-feature-secret") || strings.Contains(string(encoded), "provider_preparation") || strings.Contains(string(encoded), "provider_task") {
		t.Fatalf("public execution leaked private affinity: %s", encoded)
	}
}

// TestResolvePreparedWorkflowEnforcesOwnerExpiryAndImmutableAffinity verifies every reuse boundary.
// TestResolvePreparedWorkflowEnforcesOwnerExpiryAndImmutableAffinity 验证每个复用边界。
func TestResolvePreparedWorkflowEnforcesOwnerExpiryAndImmutableAffinity(t *testing.T) {
	now := time.Date(2026, time.July, 20, 17, 0, 0, 0, time.UTC)
	store := NewMemoryStore()
	prepared := musicCoverPreparationRecord(now, StatusSucceeded, &Result{MusicCoverPreparation: &vcp.MusicCoverPreparation{PreparationID: "exe_preparation", FormattedLyrics: "[Verse]\nPrepared lyrics", Structure: []vcp.MusicStructureSegment{{Label: "verse", StartSeconds: 0, EndSeconds: 10}}, AudioDurationSeconds: 10, ExpiresAt: now.Add(24 * time.Hour)}}, &ProviderPreparationSnapshot{ProviderHandle: "provider-feature-secret", Target: musicCoverTarget(vcp.OperationMusicCoverPrepare), ExpiresAt: now.Add(24 * time.Hour)})
	if _, _, errCreate := store.Create(context.Background(), prepared, lifecycleEvent(prepared.ID, 1, now, EventExecutionAccepted, StatusAccepted, nil)); errCreate != nil {
		t.Fatalf("Create() error = %v", errCreate)
	}
	serviceNow := now.Add(time.Hour)
	service := &Service{store: store, options: ServiceOptions{Now: func() time.Time { return serviceNow }}}
	cover := musicCoverExecutionRecord(now, "owner-music", musicCoverTarget(vcp.OperationMusicCover))
	binding, errResolve := service.resolvePreparedWorkflow(context.Background(), cover)
	if errResolve != nil || binding == nil || binding.PreparationID != prepared.ID || binding.ProviderHandle != "provider-feature-secret" {
		t.Fatalf("binding=%#v error=%v", binding, errResolve)
	}

	otherOwner := cover
	otherOwner.OwnerAPIKeyID = "owner-other"
	if _, errResolve := service.resolvePreparedWorkflow(context.Background(), otherOwner); !errors.Is(errResolve, vcp.ErrInvalidRequest) {
		t.Fatalf("cross-owner error = %v", errResolve)
	}
	otherCredential := cover
	otherCredential.Target.CredentialID = "credential-other"
	if _, errResolve := service.resolvePreparedWorkflow(context.Background(), otherCredential); !errors.Is(errResolve, vcp.ErrInvalidRequest) {
		t.Fatalf("cross-target error = %v", errResolve)
	}
	serviceNow = now.Add(24 * time.Hour)
	if _, errResolve := service.resolvePreparedWorkflow(context.Background(), cover); !errors.Is(errResolve, vcp.ErrInvalidRequest) {
		t.Fatalf("expired error = %v", errResolve)
	}
}

// TestMemoryStoreClonesPreparedWorkflowState verifies mutable public slices and private pointers cannot alias storage.
// TestMemoryStoreClonesPreparedWorkflowState 验证可变公开切片与私有指针不能与存储形成别名。
func TestMemoryStoreClonesPreparedWorkflowState(t *testing.T) {
	now := time.Date(2026, time.July, 20, 18, 0, 0, 0, time.UTC)
	store := NewMemoryStore()
	record := musicCoverPreparationRecord(now, StatusSucceeded, &Result{MusicCoverPreparation: &vcp.MusicCoverPreparation{PreparationID: "exe_preparation", FormattedLyrics: "lyrics", Structure: []vcp.MusicStructureSegment{{Label: "verse", StartSeconds: 0, EndSeconds: 10}}, AudioDurationSeconds: 10, ExpiresAt: now.Add(time.Hour)}}, &ProviderPreparationSnapshot{ProviderHandle: "provider-feature-secret", Target: musicCoverTarget(vcp.OperationMusicCoverPrepare), ExpiresAt: now.Add(time.Hour)})
	if _, _, errCreate := store.Create(context.Background(), record, lifecycleEvent(record.ID, 1, now, EventExecutionAccepted, StatusAccepted, nil)); errCreate != nil {
		t.Fatalf("Create() error = %v", errCreate)
	}
	read, errGet := store.Get(context.Background(), record.OwnerAPIKeyID, record.ID)
	if errGet != nil {
		t.Fatalf("Get() error = %v", errGet)
	}
	read.Result.MusicCoverPreparation.Structure[0].Label = "intro"
	read.ProviderPreparation.ProviderHandle = "mutated"
	again, errGet := store.Get(context.Background(), record.OwnerAPIKeyID, record.ID)
	if errGet != nil || again.Result.MusicCoverPreparation.Structure[0].Label != "verse" || again.ProviderPreparation.ProviderHandle != "provider-feature-secret" {
		t.Fatalf("stored record aliased caller mutation: %#v error=%v", again, errGet)
	}
}

// musicCoverPreparationRecord builds one valid preparation lifecycle record.
// musicCoverPreparationRecord 构建一个有效的准备生命周期记录。
func musicCoverPreparationRecord(now time.Time, status Status, result *Result, preparation *ProviderPreparationSnapshot) Record {
	target := musicCoverTarget(vcp.OperationMusicCoverPrepare)
	request := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request-prepare", Target: vcp.TargetSelection{Model: &vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: target.ProviderInstanceID, ProviderModelID: target.ProviderModelID, ExecutionProfileID: target.ExecutionProfileID}}, Operation: vcp.OperationMusicCoverPrepare, Payload: vcp.OperationPayload{MusicCoverPrepare: &vcp.MusicCoverPrepareOperation{Source: vcp.MediaInput{ID: "cover-source", Kind: vcp.MediaAudio, Role: vcp.MediaRoleCoverReference, Resource: vcp.ResourceReference{ResourceID: "resource-cover"}}}}}
	return Record{ID: "exe_preparation", OwnerAPIKeyID: "owner-music", RequestHash: "request-hash", Request: request, Target: target, Status: status, Operation: request.Operation, Result: result, ProviderPreparation: preparation, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(48 * time.Hour), Revision: 1}
}

// musicCoverExecutionRecord builds one valid final-cover lookup record.
// musicCoverExecutionRecord 构建一个有效的最终翻唱查找记录。
func musicCoverExecutionRecord(now time.Time, ownerAPIKeyID string, target resolve.Target) Record {
	request := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request-cover", Target: vcp.TargetSelection{Model: &vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: target.ProviderInstanceID, ProviderModelID: target.ProviderModelID, ExecutionProfileID: target.ExecutionProfileID}}, Operation: vcp.OperationMusicCover, Payload: vcp.OperationPayload{MusicCover: &vcp.MusicCoverOperation{PreparationID: "exe_preparation", Prompt: "Gentle acoustic cover", Lyrics: "Prepared final lyrics"}}}
	return Record{ID: "exe_cover", OwnerAPIKeyID: ownerAPIKeyID, RequestHash: "cover-hash", Request: request, Target: target, Status: StatusAccepted, Operation: request.Operation, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(48 * time.Hour), Revision: 1}
}

// musicCoverTarget builds one phase-specific target with shared immutable provider affinity.
// musicCoverTarget 构建一个阶段专属且共享不可变供应商亲和性的 Target。
func musicCoverTarget(operation vcp.OperationKind) resolve.Target {
	actionBindingID := "action-cover-prepare"
	executionProfileID := "profile-cover-prepare"
	offeringID := "offering-cover-prepare"
	if operation == vcp.OperationMusicCover {
		actionBindingID = "action-cover"
		executionProfileID = "profile-cover"
		offeringID = "offering-cover"
	}
	return resolve.Target{ProviderDefinitionID: "definition-minimax", ProviderInstanceID: "instance-minimax", ChannelID: "minimax-music", EndpointID: "endpoint-minimax", EndpointRegion: "global", CredentialID: "credential-minimax", SubjectKind: resolve.ExecutionSubjectModel, ProviderModelID: "model-music-cover", OfferingID: offeringID, Operation: operation, ActionBindingID: actionBindingID, ExecutionProfileID: executionProfileID, UpstreamModelID: "music-cover", CapabilityRevision: 1, ProviderConfigRevision: 1, CatalogRevision: 1}
}
