package sqlitestore

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/execution"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/routertool"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestExecutionStoreProtectsProviderContinuation verifies only the Router identifier and safe affinity summary are publicly serializable.
// TestExecutionStoreProtectsProviderContinuation 验证仅 Router 标识与安全亲和摘要可公开序列化。
func TestExecutionStoreProtectsProviderContinuation(t *testing.T) {
	ctx := context.Background()
	database, errDatabase := Open(ctx, filepath.Join(t.TempDir(), "continuation.db"))
	if errDatabase != nil {
		t.Fatalf("Open() error = %v", errDatabase)
	}
	defer func() { _ = database.Close() }()
	secrets := secret.NewMemoryStore()
	store, errStore := NewExecutionStore(database, secrets)
	if errStore != nil {
		t.Fatalf("NewExecutionStore() error = %v", errStore)
	}
	now := time.Date(2026, time.July, 21, 14, 0, 0, 0, time.UTC)
	record := sqliteExecutionRecord(now)
	record.Status = execution.StatusSucceeded
	record.Result = &execution.Result{Conversation: &vcp.Response{ResponseID: "response-public", Status: vcp.ResponseCompleted}, Continuation: &vcp.Continuation{ContinuationID: record.ID, LogicalResponseID: "response-public", AffinitySummary: "provider=definition_test", ExpiresAt: record.ExpiresAt}}
	record.ProviderContinuation = &execution.ProviderContinuationSnapshot{ContinuationID: record.ID, UpstreamResponseID: "upstream-private-response", Target: record.Target, LogicalResponseID: "response-public", CreatedAt: record.UpdatedAt, LastUsedAt: record.UpdatedAt, ExpiresAt: record.ExpiresAt, InvalidatedAt: record.UpdatedAt, InvalidationReason: execution.ContinuationInvalidatedProviderRejected}
	if _, _, errCreate := store.Create(ctx, record, sqliteLifecycleEvent(record.ID, 1, now, execution.EventExecutionAccepted, execution.StatusAccepted)); errCreate != nil {
		t.Fatalf("Create() error = %v", errCreate)
	}
	reopened, errGet := store.Get(ctx, record.OwnerAPIKeyID, record.ID)
	if errGet != nil || reopened.ProviderContinuation == nil || reopened.ProviderContinuation.UpstreamResponseID != "upstream-private-response" || !reopened.ProviderContinuation.LastUsedAt.Equal(now) || reopened.ProviderContinuation.InvalidationReason != execution.ContinuationInvalidatedProviderRejected || reopened.Result == nil || reopened.Result.Continuation == nil || reopened.Result.Continuation.ContinuationID != record.ID {
		t.Fatalf("reopened continuation=%+v result=%+v error=%v", reopened.ProviderContinuation, reopened.Result, errGet)
	}
	publicJSON, errJSON := json.Marshal(reopened)
	if errJSON != nil {
		t.Fatalf("json.Marshal() error = %v", errJSON)
	}
	if strings.Contains(string(publicJSON), "upstream-private-response") || strings.Contains(string(publicJSON), record.Target.CredentialID) {
		t.Fatalf("public execution leaked private continuation: %s", publicJSON)
	}
	var persistedPayload []byte
	var protectedReference string
	if errQuery := database.sql.QueryRowContext(ctx, `SELECT provider_continuation_payload, provider_continuation_secret_ref FROM executions WHERE id = ?`, record.ID).Scan(&persistedPayload, &protectedReference); errQuery != nil {
		t.Fatalf("read continuation columns: %v", errQuery)
	}
	if strings.Contains(string(persistedPayload), "upstream-private-response") || protectedReference == "" || secrets.Count() != 1 {
		t.Fatalf("continuation was not protected: payload=%s reference=%q secrets=%d", persistedPayload, protectedReference, secrets.Count())
	}
}

// TestExecutionStorePersistsPrivateMusicPreparationWithoutPublicDisclosure verifies durable two-step cover state.
// TestExecutionStorePersistsPrivateMusicPreparationWithoutPublicDisclosure 验证持久化两阶段翻唱状态不会公开泄露。
func TestExecutionStorePersistsPrivateMusicPreparationWithoutPublicDisclosure(t *testing.T) {
	ctx := context.Background()
	database, errDatabase := Open(ctx, filepath.Join(t.TempDir(), "music-preparation.db"))
	if errDatabase != nil {
		t.Fatalf("Open() error = %v", errDatabase)
	}
	defer func() { _ = database.Close() }()
	secrets := secret.NewMemoryStore()
	store, errStore := NewExecutionStore(database, secrets)
	if errStore != nil {
		t.Fatalf("NewExecutionStore() error = %v", errStore)
	}
	now := time.Date(2026, time.July, 20, 16, 0, 0, 0, time.UTC)
	target := resolve.Target{ProviderDefinitionID: "definition-minimax", ProviderInstanceID: "instance-minimax", ChannelID: "minimax-music", EndpointID: "endpoint-minimax", EndpointRegion: "global", CredentialID: "credential-minimax", SubjectKind: resolve.ExecutionSubjectModel, ProviderModelID: "model-music-cover", OfferingID: "offering-cover-prepare", Operation: vcp.OperationMusicCoverPrepare, ActionBindingID: "action-cover-prepare", ExecutionProfileID: "profile-cover-prepare", UpstreamModelID: "music-cover", CapabilityRevision: 1, ProviderConfigRevision: 1, CatalogRevision: 1}
	request := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request-prepare", Target: vcp.TargetSelection{Model: &vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: target.ProviderInstanceID, ProviderModelID: target.ProviderModelID, ExecutionProfileID: target.ExecutionProfileID}}, Operation: vcp.OperationMusicCoverPrepare, Payload: vcp.OperationPayload{MusicCoverPrepare: &vcp.MusicCoverPrepareOperation{Source: vcp.MediaInput{ID: "cover-source", Kind: vcp.MediaAudio, Role: vcp.MediaRoleCoverReference, Resource: vcp.ResourceReference{ResourceID: "resource-cover"}}}}}
	expiresAt := now.Add(24 * time.Hour)
	record := execution.Record{ID: "exe_music_preparation", OwnerAPIKeyID: "owner-music", RequestHash: "request-hash", Request: request, Target: target, Status: execution.StatusSucceeded, Operation: request.Operation, Result: &execution.Result{MusicCoverPreparation: &vcp.MusicCoverPreparation{PreparationID: "exe_music_preparation", FormattedLyrics: "[Verse]\nPrepared lyrics", Structure: []vcp.MusicStructureSegment{{Label: "verse", StartSeconds: 0, EndSeconds: 10}}, AudioDurationSeconds: 10, ExpiresAt: expiresAt}}, ProviderPreparation: &execution.ProviderPreparationSnapshot{ProviderHandle: "provider-feature-secret", Target: target, ExpiresAt: expiresAt}, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(48 * time.Hour), Revision: 1}
	if _, _, errCreate := store.Create(ctx, record, sqliteLifecycleEvent(record.ID, 1, now, execution.EventExecutionAccepted, execution.StatusAccepted)); errCreate != nil {
		t.Fatalf("Create() error = %v", errCreate)
	}
	reopened, errGet := store.Get(ctx, record.OwnerAPIKeyID, record.ID)
	if errGet != nil || reopened.ProviderPreparation == nil || reopened.ProviderPreparation.ProviderHandle != "provider-feature-secret" || reopened.Result == nil || reopened.Result.MusicCoverPreparation == nil || reopened.Result.MusicCoverPreparation.PreparationID != record.ID {
		t.Fatalf("reopened = %#v error=%v", reopened, errGet)
	}
	encoded, errEncode := json.Marshal(reopened)
	if errEncode != nil {
		t.Fatalf("json.Marshal() error = %v", errEncode)
	}
	if strings.Contains(string(encoded), "provider-feature-secret") {
		t.Fatalf("public execution leaked provider handle: %s", encoded)
	}
	var persistedPreparation []byte
	var protectedReference string
	if errQuery := database.sql.QueryRowContext(ctx, `SELECT provider_preparation_payload, provider_preparation_secret_ref FROM executions WHERE id = ?`, record.ID).Scan(&persistedPreparation, &protectedReference); errQuery != nil {
		t.Fatalf("read protected preparation columns: %v", errQuery)
	}
	if strings.Contains(string(persistedPreparation), "provider-feature-secret") || strings.Contains(string(persistedPreparation), "provider_handle") || protectedReference == "" || secrets.Count() != 1 {
		t.Fatalf("preparation handle was not isolated: payload=%s reference=%q secrets=%d", persistedPreparation, protectedReference, secrets.Count())
	}
	legacyPayload, errLegacy := json.Marshal(legacyExecutionProviderPreparationPayload{ProviderHandle: "legacy-provider-feature-secret", Target: target, ExpiresAt: expiresAt})
	if errLegacy != nil {
		t.Fatalf("marshal legacy preparation: %v", errLegacy)
	}
	if _, errUpdate := database.sql.ExecContext(ctx, `UPDATE executions SET provider_preparation_payload = ?, provider_preparation_secret_ref = NULL WHERE id = ?`, legacyPayload, record.ID); errUpdate != nil {
		t.Fatalf("install legacy preparation fixture: %v", errUpdate)
	}
	if errDelete := secrets.Delete(ctx, protectedReference); errDelete != nil {
		t.Fatalf("delete replaced protected fixture: %v", errDelete)
	}
	migratedStore, errMigratedStore := NewExecutionStore(database, secrets)
	if errMigratedStore != nil {
		t.Fatalf("migrate legacy preparation: %v", errMigratedStore)
	}
	migrated, errMigratedGet := migratedStore.Get(ctx, record.OwnerAPIKeyID, record.ID)
	if errMigratedGet != nil || migrated.ProviderPreparation == nil || migrated.ProviderPreparation.ProviderHandle != "legacy-provider-feature-secret" {
		t.Fatalf("migrated preparation=%+v error=%v", migrated.ProviderPreparation, errMigratedGet)
	}
	if errQuery := database.sql.QueryRowContext(ctx, `SELECT provider_preparation_payload, provider_preparation_secret_ref FROM executions WHERE id = ?`, record.ID).Scan(&persistedPreparation, &protectedReference); errQuery != nil {
		t.Fatalf("read migrated preparation columns: %v", errQuery)
	}
	if strings.Contains(string(persistedPreparation), "legacy-provider-feature-secret") || strings.Contains(string(persistedPreparation), "provider_handle") || protectedReference == "" || secrets.Count() != 1 {
		t.Fatalf("legacy preparation was not protected: payload=%s reference=%q secrets=%d", persistedPreparation, protectedReference, secrets.Count())
	}
}

// TestExecutionStorePersistsIdempotencyEventsAndPrivateTaskAffinity verifies durable replay and restart facts.
// TestExecutionStorePersistsIdempotencyEventsAndPrivateTaskAffinity 验证持久化重放与重启事实。
func TestExecutionStorePersistsIdempotencyEventsAndPrivateTaskAffinity(t *testing.T) {
	ctx := context.Background()
	database, errOpen := Open(ctx, filepath.Join(t.TempDir(), "execution.db"))
	if errOpen != nil {
		t.Fatalf("open database: %v", errOpen)
	}
	defer database.Close()
	secrets := secret.NewMemoryStore()
	store, errStore := NewExecutionStore(database, secrets)
	if errStore != nil {
		t.Fatalf("create execution store: %v", errStore)
	}
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	record := sqliteExecutionRecord(now)
	accepted := sqliteLifecycleEvent(record.ID, 1, now, execution.EventExecutionAccepted, execution.StatusAccepted)
	if _, replayed, errCreate := store.Create(ctx, record, accepted); errCreate != nil || replayed {
		t.Fatalf("create replayed=%t error=%v", replayed, errCreate)
	}
	if _, replayed, errReplay := store.Create(ctx, record, accepted); errReplay != nil || !replayed {
		t.Fatalf("replay replayed=%t error=%v", replayed, errReplay)
	}
	conflict := record
	conflict.ID = "exe_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	conflict.RequestHash = "different"
	if _, _, errConflict := store.Create(ctx, conflict, sqliteLifecycleEvent(conflict.ID, 1, now, execution.EventExecutionAccepted, execution.StatusAccepted)); !errors.Is(errConflict, execution.ErrIdempotencyConflict) {
		t.Fatalf("idempotency conflict error=%v", errConflict)
	}
	queued := record
	queued.Status = execution.StatusQueued
	queued.UpdatedAt = now.Add(time.Second)
	queued.Revision = 2
	queued.Attempts = []execution.Attempt{{Sequence: 1, Target: record.Target, StartedAt: now, EndedAt: now.Add(time.Second), Succeeded: true, SemanticOutput: true}}
	// cancellationRequestedAt freezes the durable intent timestamp verified after decoding.
	// cancellationRequestedAt 冻结解码后要验证的持久化意图时间戳。
	cancellationRequestedAt := now.Add(500 * time.Millisecond)
	queued.ProviderTask = &execution.ProviderTaskSnapshot{
		ProviderTaskID: "upstream-secret-task", Target: record.Target,
		Definition: providerconfig.ProviderDefinition{ID: record.Target.ProviderDefinitionID},
		Endpoint:   providerconfig.Endpoint{ID: record.Target.EndpointID, ProviderInstanceID: record.Target.ProviderInstanceID},
		Credential: providerconfig.Credential{ID: record.Target.CredentialID, ProviderInstanceID: record.Target.ProviderInstanceID},
		PollAfter:  now.Add(time.Minute), PollAttempts: 2,
		CancellationRequestedAt: &cancellationRequestedAt,
		CancellationAfter:       now.Add(3 * time.Second), CancellationAttempts: 1,
	}
	if errSave := store.Save(ctx, queued, 1, []execution.Event{sqliteLifecycleEvent(record.ID, 2, queued.UpdatedAt, execution.EventExecutionQueued, execution.StatusQueued)}); errSave != nil {
		t.Fatalf("save queued task: %v", errSave)
	}
	reopened, errGet := store.Get(ctx, record.OwnerAPIKeyID, record.ID)
	if errGet != nil || reopened.ProviderTask == nil || reopened.ProviderTask.ProviderTaskID != "upstream-secret-task" || reopened.ProviderTask.Target.CredentialID != record.Target.CredentialID || reopened.ProviderTask.CancellationRequestedAt == nil || *reopened.ProviderTask.CancellationRequestedAt != now.Add(500*time.Millisecond) || reopened.ProviderTask.CancellationAfter != now.Add(3*time.Second) || reopened.ProviderTask.CancellationAttempts != 1 || len(reopened.Attempts) != 1 || !reopened.Attempts[0].Succeeded {
		t.Fatalf("reopened task=%+v error=%v", reopened.ProviderTask, errGet)
	}
	if reopened.Result != nil {
		t.Fatalf("queued execution decoded a spurious result: %+v", reopened.Result)
	}
	publicJSON, errJSON := json.Marshal(reopened)
	if errJSON != nil {
		t.Fatalf("marshal public record: %v", errJSON)
	}
	if strings.Contains(string(publicJSON), "upstream-secret-task") || strings.Contains(string(publicJSON), record.Target.CredentialID) {
		t.Fatalf("public record leaked private task affinity: %s", publicJSON)
	}
	var persistedTask []byte
	var taskSecretReference string
	if errQuery := database.sql.QueryRowContext(ctx, `SELECT provider_task_payload, provider_task_secret_ref FROM executions WHERE id = ?`, record.ID).Scan(&persistedTask, &taskSecretReference); errQuery != nil {
		t.Fatalf("read protected task columns: %v", errQuery)
	}
	if strings.Contains(string(persistedTask), "upstream-secret-task") || strings.Contains(string(persistedTask), "provider_task_id") || taskSecretReference == "" || secrets.Count() != 1 {
		t.Fatalf("task handle was not isolated: payload=%s reference=%q secrets=%d", persistedTask, taskSecretReference, secrets.Count())
	}
	events, errEvents := store.ListEvents(ctx, record.OwnerAPIKeyID, record.ID, 1)
	if errEvents != nil || len(events) != 1 || events[0].Sequence != 2 {
		t.Fatalf("events=%+v error=%v", events, errEvents)
	}
	recoverable, errRecoverable := store.ListRecoverable(ctx)
	if errRecoverable != nil || len(recoverable) != 1 || recoverable[0].ID != record.ID {
		t.Fatalf("recoverable=%+v error=%v", recoverable, errRecoverable)
	}
	failed := reopened
	failed.Status = execution.StatusFailed
	failed.Failure = &execution.Failure{Code: "provider_failed", Retryable: false, RouterRequestID: failed.Request.RequestID, TargetSummary: "instance=" + failed.Target.ProviderInstanceID}
	failed.Result = nil
	failed.ProviderTask = nil
	failed.UpdatedAt = now.Add(2 * time.Minute)
	failed.Revision = 3
	// failedEvent carries the exact safe failure required by a terminal failure transition.
	// failedEvent 携带终态失败转换要求的精确安全失败信息。
	failedEvent := sqliteLifecycleEvent(record.ID, 3, failed.UpdatedAt, execution.EventExecutionFailed, execution.StatusFailed)
	failedEvent.Lifecycle.Failure = failed.Failure
	if errSave := store.Save(ctx, failed, 2, []execution.Event{failedEvent}); errSave != nil {
		t.Fatalf("save terminal task cleanup: %v", errSave)
	}
	if secrets.Count() != 0 {
		t.Fatalf("terminal task retained %d protected handles", secrets.Count())
	}
}

// TestExecutionStoreLeaseEnforcesOwnerAndExpiry verifies exclusive ownership, renewal, and crash takeover.
// TestExecutionStoreLeaseEnforcesOwnerAndExpiry 验证排他所有权、续约与崩溃接管。
func TestExecutionStoreLeaseEnforcesOwnerAndExpiry(t *testing.T) {
	ctx := context.Background()
	database, errDatabase := Open(ctx, filepath.Join(t.TempDir(), "lease.db"))
	if errDatabase != nil {
		t.Fatalf("Open() error = %v", errDatabase)
	}
	defer database.Close()
	store, errStore := NewExecutionStore(database, secret.NewMemoryStore())
	if errStore != nil {
		t.Fatalf("NewExecutionStore() error = %v", errStore)
	}
	now := time.Date(2026, 7, 21, 20, 0, 0, 0, time.UTC)
	record := sqliteExecutionRecord(now)
	accepted := sqliteLifecycleEvent(record.ID, 1, now, execution.EventExecutionAccepted, execution.StatusAccepted)
	if _, _, errCreate := store.Create(ctx, record, accepted); errCreate != nil {
		t.Fatalf("Create() error = %v", errCreate)
	}
	acquired, errAcquire := store.AcquireLease(ctx, record.ID, "worker_a", now, now.Add(30*time.Second))
	if errAcquire != nil || !acquired {
		t.Fatalf("first acquire=%t error=%v", acquired, errAcquire)
	}
	blocked, errBlocked := store.AcquireLease(ctx, record.ID, "worker_b", now.Add(time.Second), now.Add(31*time.Second))
	if errBlocked != nil || blocked {
		t.Fatalf("competing acquire=%t error=%v", blocked, errBlocked)
	}
	renewed, errRenew := store.RenewLease(ctx, record.ID, "worker_a", now.Add(2*time.Second), now.Add(40*time.Second))
	if errRenew != nil || !renewed {
		t.Fatalf("renew=%t error=%v", renewed, errRenew)
	}
	taken, errTakeover := store.AcquireLease(ctx, record.ID, "worker_b", now.Add(41*time.Second), now.Add(71*time.Second))
	if errTakeover != nil || !taken {
		t.Fatalf("takeover=%t error=%v", taken, errTakeover)
	}
	if errRelease := store.ReleaseLease(ctx, record.ID, "worker_a"); errRelease != nil {
		t.Fatalf("non-owner release error=%v", errRelease)
	}
	stillOwned, errStillOwned := store.RenewLease(ctx, record.ID, "worker_b", now.Add(42*time.Second), now.Add(72*time.Second))
	if errStillOwned != nil || !stillOwned {
		t.Fatalf("owner lease disappeared=%t error=%v", stillOwned, errStillOwned)
	}
}

// TestExecutionStorePersistsAttemptAndResultUsage verifies both private attempt accounting and public logical accounting survive restart reads.
// TestExecutionStorePersistsAttemptAndResultUsage 验证私有尝试计量和公共逻辑计量均可在重启读取后保留。
func TestExecutionStorePersistsAttemptAndResultUsage(t *testing.T) {
	ctx := context.Background()
	database, errDatabase := Open(ctx, filepath.Join(t.TempDir(), "usage.db"))
	if errDatabase != nil {
		t.Fatalf("Open() error = %v", errDatabase)
	}
	defer database.Close()
	store, errStore := NewExecutionStore(database, secret.NewMemoryStore())
	if errStore != nil {
		t.Fatalf("NewExecutionStore() error = %v", errStore)
	}
	now := time.Date(2026, 7, 21, 23, 15, 0, 0, time.UTC)
	record := sqliteExecutionRecord(now)
	if _, _, errCreate := store.Create(ctx, record, sqliteLifecycleEvent(record.ID, 1, now, execution.EventExecutionAccepted, execution.StatusAccepted)); errCreate != nil {
		t.Fatalf("Create() error = %v", errCreate)
	}
	running := record
	running.Status = execution.StatusRunning
	running.UpdatedAt = now.Add(time.Second)
	running.Revision = 2
	if errSave := store.Save(ctx, running, 1, []execution.Event{sqliteLifecycleEvent(record.ID, 2, running.UpdatedAt, execution.EventExecutionRunning, execution.StatusRunning)}); errSave != nil {
		t.Fatalf("save running: %v", errSave)
	}
	inputTokens := int64(12)
	outputTokens := int64(4)
	usage := &vcp.UsageObservation{InputTokens: &inputTokens, OutputTokens: &outputTokens, Source: "provider_reported", Aggregation: "snapshot", Phase: "terminal", AccountingBasis: "provider_usage", Final: true}
	succeeded := running
	succeeded.Status = execution.StatusSucceeded
	succeeded.UpdatedAt = now.Add(2 * time.Second)
	succeeded.Revision = 3
	succeeded.Attempts = []execution.Attempt{{Sequence: 1, Target: record.Target, StartedAt: running.UpdatedAt, EndedAt: succeeded.UpdatedAt, Succeeded: true, SemanticOutput: true, Usage: usage}}
	succeeded.Result = &execution.Result{Conversation: &vcp.Response{ResponseID: "response_usage", Status: vcp.ResponseCompleted}, Usage: usage}
	if errSave := store.Save(ctx, succeeded, 2, []execution.Event{sqliteLifecycleEvent(record.ID, 3, succeeded.UpdatedAt, execution.EventExecutionSucceeded, execution.StatusSucceeded)}); errSave != nil {
		t.Fatalf("save succeeded usage: %v", errSave)
	}
	reopened, errGet := store.Get(ctx, record.OwnerAPIKeyID, record.ID)
	if errGet != nil || len(reopened.Attempts) != 1 || reopened.Attempts[0].Usage == nil || reopened.Result == nil || reopened.Result.Usage == nil || *reopened.Attempts[0].Usage.InputTokens != 12 || *reopened.Result.Usage.OutputTokens != 4 {
		t.Fatalf("reopened usage attempt=%#v result=%#v error=%v", reopened.Attempts, reopened.Result, errGet)
	}
}

// TestExecutionStorePersistsPrivateRouterToolPlan verifies restart recovery retains the child target without public disclosure.
// TestExecutionStorePersistsPrivateRouterToolPlan 验证重启恢复保留子 Target 且不公开披露。
func TestExecutionStorePersistsPrivateRouterToolPlan(t *testing.T) {
	ctx := context.Background()
	database, errDatabase := Open(ctx, filepath.Join(t.TempDir(), "router-tool-plan.db"))
	if errDatabase != nil {
		t.Fatalf("Open() error = %v", errDatabase)
	}
	defer func() { _ = database.Close() }()
	store, errStore := NewExecutionStore(database, secret.NewMemoryStore())
	if errStore != nil {
		t.Fatalf("NewExecutionStore() error = %v", errStore)
	}
	now := time.Date(2026, time.July, 23, 15, 0, 0, 0, time.UTC)
	record := sqliteExecutionRecord(now)
	record.Request.Payload.Conversation.ModelTools.Standard = []vcp.StandardModelToolSelection{{Kind: vcp.StandardModelToolWebSearch, Mode: vcp.ModelToolRouter}}
	record.CompletedRouterToolRounds = 2
	childTarget := resolve.Target{ProviderDefinitionID: "definition_search_private", ProviderInstanceID: "pvi_search_private", ChannelID: "channel_search_private", EndpointID: "endpoint_search_private", CredentialID: "credential_search_private", SubjectKind: resolve.ExecutionSubjectService, ProviderServiceID: "search.web", ServiceOfferingID: "offering_search", Operation: vcp.OperationSearchWeb, ExecutionProfileID: "profile_search", CatalogRevision: 2}
	binding := routertool.Binding{ID: "rtb_search", Kind: vcp.StandardModelToolWebSearch, ProviderInstanceID: childTarget.ProviderInstanceID, ProviderServiceID: childTarget.ProviderServiceID, ServiceOfferingID: childTarget.ServiceOfferingID, ExecutionProfileID: childTarget.ExecutionProfileID, Enabled: true, TimeoutMilliseconds: 5000, MaximumCalls: 2, MaximumResults: 5, MaximumURLs: 1, MaximumResultBytes: 65536, SafetyPolicy: routertool.SafetyPublicHTTPSOnly, Revision: 1, CreatedAt: now, UpdatedAt: now}
	record.ModelToolPlan = execution.ModelToolPlan{
		CatalogRevision: record.Target.CatalogRevision,
		Standard:        []execution.ModelToolPlanEntry{{Kind: binding.Kind, Mode: vcp.ModelToolRouter, RouterBindingID: binding.ID, RouterBindingRevision: binding.Revision, RouterBinding: &routertool.ResolvedBinding{Binding: binding, Target: childTarget}}},
		Diagnostics:     []vcp.ModelToolDiagnostic{{Code: vcp.ModelToolDiagnosticLegacyNativeWebSearchMigrated}},
	}
	if _, _, errCreate := store.Create(ctx, record, sqliteLifecycleEvent(record.ID, 1, now, execution.EventExecutionAccepted, execution.StatusAccepted)); errCreate != nil {
		t.Fatalf("Create() error = %v", errCreate)
	}
	reopened, errGet := store.Get(ctx, record.OwnerAPIKeyID, record.ID)
	if errGet != nil || reopened.CompletedRouterToolRounds != 2 || len(reopened.ModelToolPlan.Standard) != 1 || reopened.ModelToolPlan.Standard[0].RouterBinding == nil || reopened.ModelToolPlan.Standard[0].RouterBinding.Target.CredentialID != childTarget.CredentialID || len(reopened.ModelToolPlan.Diagnostics) != 1 || reopened.ModelToolPlan.Diagnostics[0].Code != vcp.ModelToolDiagnosticLegacyNativeWebSearchMigrated {
		t.Fatalf("reopened plan=%+v error=%v", reopened.ModelToolPlan, errGet)
	}
	publicPayload, errMarshal := json.Marshal(reopened)
	if errMarshal != nil {
		t.Fatalf("marshal public record: %v", errMarshal)
	}
	if strings.Contains(string(publicPayload), childTarget.CredentialID) || strings.Contains(string(publicPayload), childTarget.EndpointID) {
		t.Fatalf("public record exposed private Router child target: %s", publicPayload)
	}
}

// sqliteExecutionRecord returns one minimal valid accepted persistence fixture.
// sqliteExecutionRecord 返回一个最小有效已接收持久化夹具。
func sqliteExecutionRecord(now time.Time) execution.Record {
	request := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request_sqlite", IdempotencyKey: "idem_sqlite", Target: vcp.TargetSelection{Model: &vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: "pvi_test", ProviderModelID: "model_test", ExecutionProfileID: "profile_test"}}, Operation: vcp.OperationConversationRespond, Payload: vcp.OperationPayload{Conversation: &vcp.ConversationOperation{}}}
	target := resolve.Target{ProviderDefinitionID: "definition_test", ProviderInstanceID: "pvi_test", ChannelID: "channel_test", EndpointID: "endpoint_test", EndpointRegion: "region_test", CredentialID: "credential_test", SubjectKind: resolve.ExecutionSubjectModel, ProviderModelID: "model_test", OfferingID: "offering_test", Operation: vcp.OperationConversationRespond, ActionBindingID: "action_test", ExecutionProfileID: "profile_test", UpstreamModelID: "upstream_test", CapabilityRevision: 1, ProviderConfigRevision: 1, CatalogRevision: 1}
	return execution.Record{ID: "exe_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", OwnerAPIKeyID: "key_test", RequestHash: "hash_sqlite", IdempotencyKey: request.IdempotencyKey, Request: request, Target: target, Status: execution.StatusAccepted, Operation: request.Operation, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour), Revision: 1}
}

// sqliteLifecycleEvent returns one valid Router-owned lifecycle event fixture.
// sqliteLifecycleEvent 返回一个有效 Router 所有生命周期事件夹具。
func sqliteLifecycleEvent(executionID string, sequence uint64, at time.Time, eventType execution.EventType, status execution.Status) execution.Event {
	return execution.Event{ExecutionID: executionID, EventID: "evt_" + executionID[4:] + "_" + strconv.FormatUint(sequence, 10), Sequence: sequence, Time: at, Type: eventType, Lifecycle: &execution.LifecycleEvent{Status: status}}
}
