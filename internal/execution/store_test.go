package execution

import (
	"context"
	"errors"
	"testing"
	"time"

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
