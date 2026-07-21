package runtimefeedback

import (
	"context"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/routingstate"
)

// TestControllerQuotaBackoffOncePerWindow mirrors CLIProxyAPI's copied cooldown regression cases.
// TestControllerQuotaBackoffOncePerWindow 镜像 CLIProxyAPI 复制的冷却回归场景。
func TestControllerQuotaBackoffOncePerWindow(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	store := routingstate.NewMemoryStore(now)
	controller, _ := NewController(store)
	target := resolve.Target{ProviderInstanceID: "pvi_test", CredentialID: "cred_test", ProviderModelID: "model_test"}
	request := provider.ExecutionRequest{Binding: transport.Binding{Target: target, Credential: providerconfig.Credential{ID: target.CredentialID, ProviderInstanceID: target.ProviderInstanceID}}}
	classified := provider.ClassifiedError{Category: "quota_exhausted", Scope: provider.ErrorScopeModel, Action: provider.RetryOtherCredential, RuleID: "status_429"}
	if errFailure := controller.RecordFailure(context.Background(), request, classified, now); errFailure != nil {
		t.Fatalf("RecordFailure() error = %v", errFailure)
	}
	first, _ := store.GetCredentialModelState(context.Background(), target.ProviderInstanceID, target.CredentialID, target.ProviderModelID)
	if first.BackoffLevel != 1 || first.CoolingUntil == nil || !first.CoolingUntil.Equal(now.Add(time.Second)) {
		t.Fatalf("first quota state = %#v", first)
	}
	if errFailure := controller.RecordFailure(context.Background(), request, classified, now.Add(100*time.Millisecond)); errFailure != nil {
		t.Fatalf("in-window RecordFailure() error = %v", errFailure)
	}
	second, _ := store.GetCredentialModelState(context.Background(), target.ProviderInstanceID, target.CredentialID, target.ProviderModelID)
	if second.BackoffLevel != 1 || !second.CoolingUntil.Equal(*first.CoolingUntil) {
		t.Fatalf("in-window quota state = %#v", second)
	}
	if errFailure := controller.RecordFailure(context.Background(), request, classified, now.Add(2*time.Second)); errFailure != nil {
		t.Fatalf("post-window RecordFailure() error = %v", errFailure)
	}
	third, _ := store.GetCredentialModelState(context.Background(), target.ProviderInstanceID, target.CredentialID, target.ProviderModelID)
	if third.BackoffLevel != 2 || !third.CoolingUntil.Equal(now.Add(4*time.Second)) {
		t.Fatalf("post-window quota state = %#v", third)
	}
	if errSuccess := controller.RecordSuccess(context.Background(), request, now.Add(5*time.Second)); errSuccess != nil {
		t.Fatalf("RecordSuccess() error = %v", errSuccess)
	}
	ready, _ := store.GetCredentialModelState(context.Background(), target.ProviderInstanceID, target.CredentialID, target.ProviderModelID)
	if ready.Status != routingstate.ModelReady || ready.BackoffLevel != 0 || ready.CoolingUntil != nil || ready.QuotaExhausted {
		t.Fatalf("successful state = %#v", ready)
	}
}

// TestControllerPersistsExactCredentialEndpointAndSharedScopes verifies non-model failures use their sole evidence-backed identity.
// TestControllerPersistsExactCredentialEndpointAndSharedScopes 验证非模型失败使用其唯一有证据支持的身份。
func TestControllerPersistsExactCredentialEndpointAndSharedScopes(t *testing.T) {
	now := time.Date(2026, 7, 20, 13, 0, 0, 0, time.UTC)
	store := routingstate.NewMemoryStore(now)
	controller, _ := NewController(store)
	target := resolve.Target{ProviderInstanceID: "pvi_scope", CredentialID: "cred_scope", EndpointID: "ep_scope", ProviderModelID: "model_scope"}
	credential := providerconfig.Credential{ID: target.CredentialID, ProviderInstanceID: target.ProviderInstanceID, ScopeRefs: []providerconfig.ScopeReference{{Kind: "subscription", ID: "sub_scope"}, {Kind: "billing_account", ID: "billing_scope"}}}
	request := provider.ExecutionRequest{Binding: transport.Binding{Target: target, Credential: credential}}
	testCases := []struct {
		// providerScope is the classifier-owned failure boundary.
		// providerScope 是分类器拥有的失败边界。
		providerScope provider.ErrorScope
		// stateScope is the corresponding persistent routing boundary.
		// stateScope 是对应的持久化路由边界。
		stateScope routingstate.RuntimeScope
		// scopeID is the exact affected resource identifier.
		// scopeID 是受影响资源的精确标识。
		scopeID string
	}{
		{provider.ErrorScopeCredential, routingstate.ScopeCredential, target.CredentialID},
		{provider.ErrorScopeEndpoint, routingstate.ScopeEndpoint, target.EndpointID},
		{provider.ErrorScopeProvider, routingstate.ScopeProvider, target.ProviderInstanceID},
		{provider.ErrorScopeSubscription, routingstate.ScopeSubscription, "sub_scope"},
		{provider.ErrorScopeBillingAccount, routingstate.ScopeBillingAccount, "billing_scope"},
	}
	for index, testCase := range testCases {
		classified := provider.ClassifiedError{Category: "transient", Scope: testCase.providerScope, Action: provider.RetryOtherCredential, RuleID: "scope_test"}
		if errFailure := controller.RecordFailure(context.Background(), request, classified, now.Add(time.Duration(index)*time.Second)); errFailure != nil {
			t.Fatalf("RecordFailure(%s) error = %v", testCase.providerScope, errFailure)
		}
		state, errState := store.GetRuntimeScopeState(context.Background(), target.ProviderInstanceID, testCase.stateScope, testCase.scopeID)
		if errState != nil || state.Status != routingstate.ModelCooling || state.CoolingUntil == nil {
			t.Fatalf("scope=%s state=%+v error=%v", testCase.providerScope, state, errState)
		}
	}
	if errSuccess := controller.RecordSuccess(context.Background(), request, now.Add(time.Minute)); errSuccess != nil {
		t.Fatalf("RecordSuccess() error = %v", errSuccess)
	}
	for _, identity := range []scopeIdentity{{routingstate.ScopeCredential, target.CredentialID}, {routingstate.ScopeEndpoint, target.EndpointID}, {routingstate.ScopeProvider, target.ProviderInstanceID}} {
		state, errState := store.GetRuntimeScopeState(context.Background(), target.ProviderInstanceID, identity.scope, identity.scopeID)
		if errState != nil || state.Status != routingstate.ModelReady {
			t.Fatalf("successful scope=%s state=%+v error=%v", identity.scope, state, errState)
		}
	}
}
