package execution

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestValidateTransitionRejectsTerminalRollbackAndPhaseSkips verifies the closed lifecycle graph.
// TestValidateTransitionRejectsTerminalRollbackAndPhaseSkips 验证封闭生命周期图。
func TestValidateTransitionRejectsTerminalRollbackAndPhaseSkips(t *testing.T) {
	if errTransition := ValidateTransition(StatusAccepted, StatusPartiallySucceeded); !errors.Is(errTransition, ErrInvalidExecution) {
		t.Fatalf("accepted to partial transition error=%v, want invalid execution", errTransition)
	}
	if errTransition := ValidateTransition(StatusSucceeded, StatusRunning); !errors.Is(errTransition, ErrInvalidExecution) {
		t.Fatalf("terminal rollback error=%v, want invalid execution", errTransition)
	}
	if errTransition := ValidateTransition(StatusQueued, StatusRunning); errTransition != nil {
		t.Fatalf("queued to running transition failed: %v", errTransition)
	}
}

// TestMemoryStoreEnforcesIdempotencyCASAndReplaySequence verifies the repository's atomic invariants.
// TestMemoryStoreEnforcesIdempotencyCASAndReplaySequence 验证 Repository 原子不变量。
func TestMemoryStoreEnforcesIdempotencyCASAndReplaySequence(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	record := validTestRecord(now)
	accepted := lifecycleEvent(record.ID, 1, now, EventExecutionAccepted, StatusAccepted, nil)
	created, replayed, errCreate := store.Create(context.Background(), record, accepted)
	if errCreate != nil || replayed || created.ID != record.ID {
		t.Fatalf("create=(%+v,%t,%v)", created, replayed, errCreate)
	}
	replayedRecord, replayed, errReplay := store.Create(context.Background(), record, accepted)
	if errReplay != nil || !replayed || replayedRecord.ID != record.ID {
		t.Fatalf("idempotent replay=(%+v,%t,%v)", replayedRecord, replayed, errReplay)
	}
	conflict := record
	conflict.ID = "exe_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	conflict.RequestHash = "different"
	conflictEvent := lifecycleEvent(conflict.ID, 1, now, EventExecutionAccepted, StatusAccepted, nil)
	if _, _, errConflict := store.Create(context.Background(), conflict, conflictEvent); !errors.Is(errConflict, ErrIdempotencyConflict) {
		t.Fatalf("idempotency conflict error=%v", errConflict)
	}
	running := record
	running.Status = StatusRunning
	running.UpdatedAt = now.Add(time.Second)
	running.Revision = 2
	runningEvent := lifecycleEvent(record.ID, 2, running.UpdatedAt, EventExecutionRunning, StatusRunning, nil)
	if errSave := store.Save(context.Background(), running, 1, []Event{runningEvent}); errSave != nil {
		t.Fatalf("save running: %v", errSave)
	}
	if errStale := store.Save(context.Background(), running, 1, nil); !errors.Is(errStale, ErrRevisionConflict) {
		t.Fatalf("stale save error=%v", errStale)
	}
	events, errEvents := store.ListEvents(context.Background(), record.OwnerAPIKeyID, record.ID, 1)
	if errEvents != nil || len(events) != 1 || events[0].Sequence != 2 {
		t.Fatalf("events=%+v error=%v", events, errEvents)
	}
}

// TestMemoryStoreDeepCopiesTypedResults verifies callers cannot mutate nested stored outputs or usage pointers.
// TestMemoryStoreDeepCopiesTypedResults 验证调用方不能修改嵌套的已存输出或用量指针。
func TestMemoryStoreDeepCopiesTypedResults(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 7, 21, 23, 0, 0, 0, time.UTC)
	record := validTestRecord(now)
	record.Request.Payload.Conversation.GenerationPolicy.Stop = []string{"END"}
	record.Request.Payload.Conversation.RegisteredExtensions = []string{"extension.test"}
	inputTokens := int64(7)
	text := "stored"
	accepted := lifecycleEvent(record.ID, 1, now, EventExecutionAccepted, StatusAccepted, nil)
	if _, _, errCreate := store.Create(context.Background(), record, accepted); errCreate != nil {
		t.Fatalf("create result fixture: %v", errCreate)
	}
	record.Status = StatusRunning
	record.UpdatedAt = now.Add(time.Second)
	record.Revision = 2
	if errSave := store.Save(context.Background(), record, 1, []Event{lifecycleEvent(record.ID, 2, record.UpdatedAt, EventExecutionRunning, StatusRunning, nil)}); errSave != nil {
		t.Fatalf("save running result fixture: %v", errSave)
	}
	record.Status = StatusSucceeded
	record.UpdatedAt = now.Add(2 * time.Second)
	record.Revision = 3
	record.Result = &Result{
		Conversation: &vcp.Response{ResponseID: "response_test", Status: vcp.ResponseCompleted, Items: []vcp.OutputItem{{ItemID: "item_test", Kind: vcp.ContextMessage, Status: vcp.OutputItemCompleted, Content: []vcp.ContentBlock{{Type: vcp.ContentText, Text: text}}}}},
		Usage:        &vcp.UsageObservation{InputTokens: &inputTokens, Source: "provider_reported", Aggregation: "snapshot", Phase: "terminal", AccountingBasis: "test", Final: true},
	}
	if errSave := store.Save(context.Background(), record, 2, []Event{lifecycleEvent(record.ID, 3, record.UpdatedAt, EventExecutionSucceeded, StatusSucceeded, nil)}); errSave != nil {
		t.Fatalf("save result fixture: %v", errSave)
	}
	created, errCreated := store.Get(context.Background(), record.OwnerAPIKeyID, record.ID)
	if errCreated != nil {
		t.Fatalf("get result fixture: %v", errCreated)
	}
	record.Result.Conversation.Items[0].Content[0].Text = "caller-mutated"
	*record.Result.Usage.InputTokens = 99
	record.Request.Payload.Conversation.GenerationPolicy.Stop[0] = "caller-mutated"
	record.Request.Payload.Conversation.RegisteredExtensions[0] = "caller-mutated"
	created.Result.Conversation.Items[0].Content[0].Text = "returned-mutated"
	*created.Result.Usage.InputTokens = 88
	created.Request.Payload.Conversation.GenerationPolicy.Stop[0] = "returned-mutated"
	stored, errGet := store.Get(context.Background(), record.OwnerAPIKeyID, record.ID)
	if errGet != nil || stored.Result == nil || stored.Result.Conversation.Items[0].Content[0].Text != text || stored.Result.Usage == nil || *stored.Result.Usage.InputTokens != 7 || stored.Request.Payload.Conversation.GenerationPolicy.Stop[0] != "END" || stored.Request.Payload.Conversation.RegisteredExtensions[0] != "extension.test" {
		t.Fatalf("stored nested result was aliased: result=%#v error=%v", stored.Result, errGet)
	}
}

// TestFailureValidateEnforcesTrustedClassificationTuple verifies partial or unknown provider metadata is rejected.
// TestFailureValidateEnforcesTrustedClassificationTuple 验证不完整或未知的供应商元数据会被拒绝。
func TestFailureValidateEnforcesTrustedClassificationTuple(t *testing.T) {
	failure := Failure{Code: "provider_failed", Retryable: true, Attempt: 1, RouterRequestID: "request_test", TargetSummary: "instance=pvi_test"}
	if errFailure := failure.Validate(); errFailure != nil {
		t.Fatalf("unclassified failure should be valid: %v", errFailure)
	}
	failure.Category = "transient_upstream"
	if errFailure := failure.Validate(); !errors.Is(errFailure, ErrInvalidExecution) {
		t.Fatalf("partial classification error=%v, want invalid execution", errFailure)
	}
	failure.Scope = provider.ErrorScopeSubscription
	failure.RetryAction = provider.RetryAfterReset
	if errFailure := failure.Validate(); errFailure != nil {
		t.Fatalf("complete classification should be valid: %v", errFailure)
	}
	failure.Scope = provider.ErrorScope("unknown")
	if errFailure := failure.Validate(); !errors.Is(errFailure, ErrInvalidExecution) {
		t.Fatalf("unknown classification error=%v, want invalid execution", errFailure)
	}
}

// TestRecordAndLifecycleRejectFailureOutsideFailedState verifies durable and event unions share the failure invariant.
// TestRecordAndLifecycleRejectFailureOutsideFailedState 验证持久记录和事件联合体共享失败不变量。
func TestRecordAndLifecycleRejectFailureOutsideFailedState(t *testing.T) {
	now := time.Date(2026, 7, 21, 23, 30, 0, 0, time.UTC)
	record := validTestRecord(now)
	record.Failure = &Failure{Code: "unexpected", RouterRequestID: record.Request.RequestID, TargetSummary: "instance=pvi_test"}
	if errRecord := record.Validate(); !errors.Is(errRecord, ErrInvalidExecution) {
		t.Fatalf("nonfailed record failure error=%v, want invalid execution", errRecord)
	}
	invalidFailure := &Failure{Code: "provider_failed", Category: "transient_upstream", RouterRequestID: record.Request.RequestID, TargetSummary: "instance=pvi_test"}
	event := lifecycleEvent(record.ID, 2, now, EventExecutionFailed, StatusFailed, invalidFailure)
	if errEvent := event.Validate(); !errors.Is(errEvent, ErrInvalidExecution) {
		t.Fatalf("invalid lifecycle failure error=%v, want invalid execution", errEvent)
	}
}

// validTestRecord returns one minimal valid accepted execution fixture.
// validTestRecord 返回一个最小有效已接收执行夹具。
func validTestRecord(now time.Time) Record {
	request := vcp.ExecutionRequest{
		ProtocolVersion: vcp.ProtocolVersion,
		RequestID:       "request_test",
		IdempotencyKey:  "idem_test",
		Target: vcp.TargetSelection{Model: &vcp.ModelSelection{
			Target:             vcp.ModelTargetExact,
			ProviderInstanceID: "pvi_test",
			ProviderModelID:    "model_test",
			ExecutionProfileID: "profile_test",
		}},
		Operation: vcp.OperationConversationRespond,
		Payload:   vcp.OperationPayload{Conversation: &vcp.ConversationOperation{}},
	}
	return Record{
		ID:             "exe_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		OwnerAPIKeyID:  "key_test",
		RequestHash:    "hash_test",
		IdempotencyKey: request.IdempotencyKey,
		Request:        request,
		Target: resolve.Target{
			ProviderDefinitionID: "definition_test", ProviderInstanceID: "pvi_test", ChannelID: "channel_test", EndpointID: "endpoint_test", CredentialID: "credential_test",
			SubjectKind: resolve.ExecutionSubjectModel, ProviderModelID: "model_test", OfferingID: "offering_test", Operation: vcp.OperationConversationRespond, ActionBindingID: "action_test", ExecutionProfileID: "profile_test", UpstreamModelID: "upstream_test",
		},
		Status: StatusAccepted, Operation: vcp.OperationConversationRespond, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour), Revision: 1,
	}
}
