package routertool

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// stubTargetResolver records exact service requests and can reject selected providers.
// stubTargetResolver 记录精确服务请求并可拒绝选定供应商。
type stubTargetResolver struct {
	// requests contains every attempted exact service resolution.
	// requests 包含每次尝试的精确服务解析。
	requests []resolve.Request
	// rejectedInstances identifies unavailable test backends.
	// rejectedInstances 标识测试中不可用的后端。
	rejectedInstances map[string]struct{}
	// failure is one operational error that must never be classified as normal unavailability.
	// failure 是绝不能被归类为普通不可用的操作错误。
	failure error
}

// Resolve returns one service target unless its exact provider instance is rejected.
// Resolve 返回一个服务 Target，除非其精确供应商实例被拒绝。
func (s *stubTargetResolver) Resolve(_ context.Context, request resolve.Request) (resolve.Target, resolve.Diagnostics, error) {
	s.requests = append(s.requests, request)
	if s.failure != nil {
		return resolve.Target{}, resolve.Diagnostics{}, s.failure
	}
	if _, rejected := s.rejectedInstances[request.ProviderInstanceID]; rejected {
		return resolve.Target{}, resolve.Diagnostics{}, resolve.ErrNoEligibleTarget
	}
	target := resolve.Target{
		ProviderInstanceID: request.ProviderInstanceID,
		ExecutionProfileID: request.ExecutionProfileID,
		Operation:          request.Operation,
	}
	if request.ProviderModelID != "" {
		target.SubjectKind = resolve.ExecutionSubjectModel
		target.ProviderModelID = request.ProviderModelID
		target.OfferingID = request.OfferingID
	} else {
		target.SubjectKind = resolve.ExecutionSubjectService
		target.ProviderServiceID = request.ProviderServiceID
		target.ServiceOfferingID = request.ServiceOfferingID
	}
	return target, resolve.Diagnostics{ReadyCandidates: 1}, nil
}

// TestResolverPropagatesOperationalTargetFailure verifies cancellation and storage failures never masquerade as unavailable bindings.
// TestResolverPropagatesOperationalTargetFailure 验证取消与存储失败绝不会伪装成绑定不可用。
func TestResolverPropagatesOperationalTargetFailure(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	store := NewMemoryStore()
	if errSave := store.Save(context.Background(), validBinding("rtb_failure", "pvi_failure", 0, now)); errSave != nil {
		t.Fatalf("save binding: %v", errSave)
	}
	resolver, errNew := NewResolver(store, &stubTargetResolver{failure: context.Canceled})
	if errNew != nil {
		t.Fatalf("NewResolver() error = %v", errNew)
	}
	parent := resolve.Target{SubjectKind: resolve.ExecutionSubjectModel, ProviderInstanceID: "pvi_parent", ProviderModelID: "model_parent", ExecutionProfileID: "profile_parent"}
	if _, errResolve := resolver.Resolve(context.Background(), parent, vcp.StandardModelToolWebSearch, now); !errors.Is(errResolve, context.Canceled) {
		t.Fatalf("Resolve() error = %v, want context.Canceled", errResolve)
	}
	if _, errAvailability := resolver.Availability(context.Background(), parent, vcp.StandardModelToolWebSearch, now); !errors.Is(errAvailability, context.Canceled) {
		t.Fatalf("Availability() error = %v, want context.Canceled", errAvailability)
	}
}

// TestBindingValidateRejectsUnsafeLimits verifies every administrator-authored execution ceiling is bounded in the domain.
// TestBindingValidateRejectsUnsafeLimits 验证每个管理员编写的执行上限都在领域层受到约束。
func TestBindingValidateRejectsUnsafeLimits(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		mutate func(*Binding)
	}{
		{name: "negative unused URL limit", mutate: func(binding *Binding) { binding.MaximumURLs = -1 }},
		{name: "untrimmed identity", mutate: func(binding *Binding) { binding.ProviderInstanceID = " pvi_limit" }},
		{name: "reversed audit timestamps", mutate: func(binding *Binding) { binding.CreatedAt = binding.UpdatedAt.Add(time.Second) }},
		{name: "timeout too large", mutate: func(binding *Binding) { binding.TimeoutMilliseconds = MaximumTimeoutMilliseconds + 1 }},
		{name: "call count too large", mutate: func(binding *Binding) { binding.MaximumCalls = MaximumCallsPerParent + 1 }},
		{name: "search results too large", mutate: func(binding *Binding) { binding.MaximumResults = MaximumSearchResults + 1 }},
		{name: "serialized result too large", mutate: func(binding *Binding) { binding.MaximumResultBytes = MaximumSerializedResultBytes + 1 }},
		{name: "scope too large", mutate: func(binding *Binding) {
			binding.AllowedProviderModelIDs = make([]string, MaximumScopeIdentifiers+1)
			for index := range binding.AllowedProviderModelIDs {
				binding.AllowedProviderModelIDs[index] = fmt.Sprintf("model_%d", index)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			binding := validBinding("rtb_limit", "pvi_limit", 0, now)
			test.mutate(&binding)
			if errValidate := binding.Validate(); !errors.Is(errValidate, ErrInvalidBinding) {
				t.Fatalf("Validate() error = %v, want ErrInvalidBinding", errValidate)
			}
		})
	}
}

// TestMemoryStoreRejectsReplacementAuditMutation verifies optimistic replacement cannot rewrite creation history.
// TestMemoryStoreRejectsReplacementAuditMutation 校验乐观替换无法改写创建历史。
func TestMemoryStoreRejectsReplacementAuditMutation(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	store := NewMemoryStore()
	binding := validBinding("rtb_audit", "pvi_audit", 0, now)
	if errSave := store.Save(context.Background(), binding); errSave != nil {
		t.Fatalf("Save(initial) error = %v", errSave)
	}
	binding.Revision++
	binding.CreatedAt = now.Add(time.Second)
	binding.UpdatedAt = now.Add(time.Second)
	if errSave := store.Save(context.Background(), binding); !errors.Is(errSave, ErrInvalidBinding) {
		t.Fatalf("Save(mutated audit) error = %v, want ErrInvalidBinding", errSave)
	}
}

// TestResolverUsesPriorityScopeAndRuntimeReadiness verifies selection never guesses across unavailable exact backends.
// TestResolverUsesPriorityScopeAndRuntimeReadiness 验证选择绝不会在不可用精确后端之间进行猜测。
func TestResolverUsesPriorityScopeAndRuntimeReadiness(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	store := NewMemoryStore()
	first := validBinding("rtb_first", "pvi_unavailable", 0, now)
	second := validBinding("rtb_second", "pvi_ready", 1, now)
	second.AllowedProviderModelIDs = []string{"model_parent"}
	if errSave := store.Save(context.Background(), first); errSave != nil {
		t.Fatalf("save first binding: %v", errSave)
	}
	if errSave := store.Save(context.Background(), second); errSave != nil {
		t.Fatalf("save second binding: %v", errSave)
	}
	targets := &stubTargetResolver{rejectedInstances: map[string]struct{}{"pvi_unavailable": {}}}
	resolver, errNew := NewResolver(store, targets)
	if errNew != nil {
		t.Fatalf("NewResolver() error = %v", errNew)
	}
	resolved, errResolve := resolver.Resolve(context.Background(), resolve.Target{SubjectKind: resolve.ExecutionSubjectModel, ProviderInstanceID: "pvi_parent", ProviderModelID: "model_parent", ExecutionProfileID: "profile_parent"}, vcp.StandardModelToolWebSearch, now)
	if errResolve != nil {
		t.Fatalf("Resolve() error = %v", errResolve)
	}
	if resolved.Binding.ID != second.ID || resolved.Target.ProviderInstanceID != second.ProviderInstanceID || len(targets.requests) != 2 {
		t.Fatalf("resolved = %#v, requests = %#v", resolved, targets.requests)
	}
}

// TestResolverRejectsOutOfScopeBinding verifies empty inference never broadens explicit parent allowlists and reports no scoped policy.
// TestResolverRejectsOutOfScopeBinding 验证空推断绝不会扩大显式父级允许列表并报告作用域内无策略。
func TestResolverRejectsOutOfScopeBinding(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	store := NewMemoryStore()
	binding := validBinding("rtb_scoped", "pvi_ready", 0, now)
	binding.AllowedProviderModelIDs = []string{"another_model"}
	if errSave := store.Save(context.Background(), binding); errSave != nil {
		t.Fatalf("save binding: %v", errSave)
	}
	resolver, errNew := NewResolver(store, &stubTargetResolver{})
	if errNew != nil {
		t.Fatalf("NewResolver() error = %v", errNew)
	}
	_, errResolve := resolver.Resolve(context.Background(), resolve.Target{SubjectKind: resolve.ExecutionSubjectModel, ProviderModelID: "model_parent"}, vcp.StandardModelToolWebSearch, now)
	if !errors.Is(errResolve, ErrBindingNotFound) {
		t.Fatalf("Resolve() error = %v, want ErrBindingNotFound", errResolve)
	}
}

// TestResolverAvailabilitySeparatesSupportAndReadiness verifies missing, disabled, unavailable, and ready states remain distinct.
// TestResolverAvailabilitySeparatesSupportAndReadiness 验证缺失、关闭、不可用与就绪状态保持区分。
func TestResolverAvailabilitySeparatesSupportAndReadiness(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	store := NewMemoryStore()
	targets := &stubTargetResolver{rejectedInstances: map[string]struct{}{"pvi_unavailable": {}}}
	resolver, errNew := NewResolver(store, targets)
	if errNew != nil {
		t.Fatalf("NewResolver() error = %v", errNew)
	}
	parent := resolve.Target{SubjectKind: resolve.ExecutionSubjectModel, ProviderInstanceID: "pvi_parent", ProviderModelID: "model_parent", ExecutionProfileID: "profile_parent"}
	missing, errMissing := resolver.Availability(context.Background(), parent, vcp.StandardModelToolWebSearch, now)
	if errMissing != nil || missing.Supported || missing.Ready || missing.UnavailableReason != AvailabilityReasonBindingMissing {
		t.Fatalf("missing availability = %#v, error = %v", missing, errMissing)
	}
	disabledBinding := validBinding("rtb_disabled", "pvi_ready", 0, now)
	disabledBinding.Enabled = false
	if errSave := store.Save(context.Background(), disabledBinding); errSave != nil {
		t.Fatalf("save disabled binding: %v", errSave)
	}
	disabled, errDisabled := resolver.Availability(context.Background(), parent, vcp.StandardModelToolWebSearch, now)
	if errDisabled != nil || !disabled.Supported || disabled.Ready || disabled.UnavailableReason != AvailabilityReasonBindingDisabled {
		t.Fatalf("disabled availability = %#v, error = %v", disabled, errDisabled)
	}
	unavailableBinding := validBinding("rtb_unavailable", "pvi_unavailable", 1, now)
	if errSave := store.Save(context.Background(), unavailableBinding); errSave != nil {
		t.Fatalf("save unavailable binding: %v", errSave)
	}
	unavailable, errUnavailable := resolver.Availability(context.Background(), parent, vcp.StandardModelToolWebSearch, now)
	if errUnavailable != nil || !unavailable.Supported || unavailable.Ready || unavailable.UnavailableReason != AvailabilityReasonBindingUnavailable {
		t.Fatalf("unavailable availability = %#v, error = %v", unavailable, errUnavailable)
	}
	readyBinding := validBinding("rtb_ready", "pvi_ready", 2, now)
	if errSave := store.Save(context.Background(), readyBinding); errSave != nil {
		t.Fatalf("save ready binding: %v", errSave)
	}
	ready, errReady := resolver.Availability(context.Background(), parent, vcp.StandardModelToolWebSearch, now)
	if errReady != nil || !ready.Supported || !ready.Ready || ready.UnavailableReason != "" {
		t.Fatalf("ready availability = %#v, error = %v", ready, errReady)
	}
}

// TestResolverExtensionUsesExactModelTarget verifies operation-backed enhancements never resolve through a special-service path.
// TestResolverExtensionUsesExactModelTarget 校验由操作支持的增强能力绝不会通过特殊服务路径解析。
func TestResolverExtensionUsesExactModelTarget(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	store := NewMemoryStore()
	binding := Binding{
		ID:                  "rtb_image",
		Extension:           vcp.RouterExtensionImageGeneration,
		ProviderInstanceID:  "pvi_image",
		ProviderModelID:     "model_image",
		OfferingID:          "offering_image",
		ExecutionProfileID:  "profile_image",
		Enabled:             true,
		TimeoutMilliseconds: 30_000,
		MaximumCalls:        2,
		MaximumResultBytes:  64 * 1024,
		SafetyPolicy:        SafetyPublicHTTPSOnly,
		Revision:            1,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	if errSave := store.Save(context.Background(), binding); errSave != nil {
		t.Fatalf("save extension binding: %v", errSave)
	}
	targets := &stubTargetResolver{}
	resolver, errNew := NewResolver(store, targets)
	if errNew != nil {
		t.Fatalf("create resolver: %v", errNew)
	}
	parent := resolve.Target{SubjectKind: resolve.ExecutionSubjectModel, ProviderInstanceID: "pvi_parent", ProviderModelID: "model_parent", ExecutionProfileID: "profile_parent"}
	resolved, errResolve := resolver.ResolveExtension(context.Background(), parent, vcp.RouterExtensionImageGeneration, now)
	if errResolve != nil {
		t.Fatalf("resolve extension: %v", errResolve)
	}
	if resolved.Target.SubjectKind != resolve.ExecutionSubjectModel || resolved.Target.ProviderModelID != binding.ProviderModelID || resolved.Target.OfferingID != binding.OfferingID || resolved.Target.Operation != vcp.OperationImageGenerate || len(targets.requests) != 1 || targets.requests[0].ProviderServiceID != "" || targets.requests[0].OfferingID != binding.OfferingID {
		t.Fatalf("resolved=%+v requests=%+v", resolved, targets.requests)
	}
}

// TestProbeBindingSeparatesDisabledUnavailableAndReady verifies management tests use real exact-target resolution.
// TestProbeBindingSeparatesDisabledUnavailableAndReady 校验管理测试使用真实精确 Target 解析并区分停用、不可用与就绪。
func TestProbeBindingSeparatesDisabledUnavailableAndReady(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	store := NewMemoryStore()
	disabled := validBinding("rtb_disabled_probe", "pvi_disabled", 0, now)
	disabled.Enabled = false
	unavailable := validBinding("rtb_unavailable_probe", "pvi_unavailable", 1, now)
	ready := validBinding("rtb_ready_probe", "pvi_ready", 2, now)
	for _, binding := range []Binding{disabled, unavailable, ready} {
		if errSave := store.Save(context.Background(), binding); errSave != nil {
			t.Fatalf("save %s: %v", binding.ID, errSave)
		}
	}
	resolver, errNew := NewResolver(store, &stubTargetResolver{rejectedInstances: map[string]struct{}{"pvi_unavailable": {}}})
	if errNew != nil {
		t.Fatalf("create resolver: %v", errNew)
	}
	disabledProbe, errDisabled := resolver.ProbeBinding(context.Background(), disabled.ID, now)
	if errDisabled != nil || disabledProbe.Ready || disabledProbe.UnavailableReason != AvailabilityReasonBindingDisabled {
		t.Fatalf("disabled probe = %+v, error = %v", disabledProbe, errDisabled)
	}
	unavailableProbe, errUnavailable := resolver.ProbeBinding(context.Background(), unavailable.ID, now)
	if errUnavailable != nil || unavailableProbe.Ready || unavailableProbe.UnavailableReason != AvailabilityReasonBindingUnavailable {
		t.Fatalf("unavailable probe = %+v, error = %v", unavailableProbe, errUnavailable)
	}
	readyProbe, errReady := resolver.ProbeBinding(context.Background(), ready.ID, now)
	if errReady != nil || !readyProbe.Ready || readyProbe.ToolID != string(vcp.StandardModelToolWebSearch) || readyProbe.Operation != vcp.OperationSearchWeb {
		t.Fatalf("ready probe = %+v, error = %v", readyProbe, errReady)
	}
}

// TestResolvedBindingRejectsTargetDrift verifies persisted execution plans cannot rewrite an exact child offering.
// TestResolvedBindingRejectsTargetDrift 校验持久化执行计划不能改写精确子产品。
func TestResolvedBindingRejectsTargetDrift(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	binding := validBinding("rtb_drift", "pvi_service", 0, now)
	resolved := ResolvedBinding{
		Binding: binding,
		Target: resolve.Target{
			SubjectKind:        resolve.ExecutionSubjectService,
			ProviderInstanceID: binding.ProviderInstanceID,
			ProviderServiceID:  binding.ProviderServiceID,
			ServiceOfferingID:  "service_offering_other",
			ExecutionProfileID: binding.ExecutionProfileID,
			Operation:          binding.Operation(),
		},
	}
	if errValidate := resolved.Validate(); !errors.Is(errValidate, ErrInvalidBinding) {
		t.Fatalf("drifted target error = %v, want ErrInvalidBinding", errValidate)
	}
}

// validBinding creates one complete explicit test binding.
// validBinding 创建一个完整显式测试绑定。
func validBinding(id string, instanceID string, priority int, now time.Time) Binding {
	return Binding{
		ID: id, Kind: vcp.StandardModelToolWebSearch,
		ProviderInstanceID: instanceID, ProviderServiceID: "service_search",
		ServiceOfferingID: "offering_search", ExecutionProfileID: "profile_search",
		Priority: priority, Enabled: true, TimeoutMilliseconds: 30_000,
		MaximumCalls: 3, MaximumResults: 5, MaximumURLs: 1,
		MaximumResultBytes: 64 * 1024, SafetyPolicy: SafetyPublicHTTPSOnly,
		Revision: 1, CreatedAt: now, UpdatedAt: now,
	}
}
