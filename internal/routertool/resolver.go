package routertool

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TargetResolver resolves one exact service target through normal credential and allowance policy.
// TargetResolver 通过常规凭据与额度策略解析一个精确服务 Target。
type TargetResolver interface {
	// Resolve returns one immutable execution target and safe diagnostics.
	// Resolve 返回一个不可变执行 Target 与安全诊断。
	Resolve(context.Context, resolve.Request) (resolve.Target, resolve.Diagnostics, error)
}

// ResolvedBinding freezes one binding and its independently resolved child target.
// ResolvedBinding 冻结一个绑定及其独立解析的子 Target。
type ResolvedBinding struct {
	// Binding is the selected immutable administrator policy.
	// Binding 是选定的不可变管理员策略。
	Binding Binding
	// Target is the exact child execution target.
	// Target 是精确的子执行 Target。
	Target resolve.Target
}

// Validate verifies that one frozen target exactly belongs to its persisted binding.
// Validate 校验一个冻结 Target 精确属于其持久化绑定。
func (r ResolvedBinding) Validate() error {
	if errBinding := r.Binding.Validate(); errBinding != nil {
		return errBinding
	}
	if !bindingOwnsResolvedTarget(r.Binding, r.Target) {
		return fmt.Errorf("%w: resolved target differs from binding %s", ErrInvalidBinding, r.Binding.ID)
	}
	return nil
}

// Resolver deterministically selects one ready Router tool backend.
// Resolver 确定性选择一个就绪的 Router 工具后端。
type Resolver struct {
	// bindings supplies administrator-authored policies.
	// bindings 提供管理员编写的策略。
	bindings Store
	// targets applies normal provider-owned service resolution.
	// targets 应用常规供应商所属服务解析。
	targets TargetResolver
}

// NewResolver creates a Router tool resolver.
// NewResolver 创建 Router 工具解析器。
func NewResolver(bindings Store, targets TargetResolver) (*Resolver, error) {
	if bindings == nil || targets == nil {
		return nil, fmt.Errorf("%w: binding store and target resolver are required", ErrInvalidBinding)
	}
	return &Resolver{bindings: bindings, targets: targets}, nil
}

// Resolve selects the first enabled, in-scope, currently executable binding.
// Resolve 选择首个已启用、范围匹配且当前可执行的绑定。
func (r *Resolver) Resolve(ctx context.Context, parent resolve.Target, kind vcp.StandardModelToolKind, now time.Time) (ResolvedBinding, error) {
	if ctx == nil || parent.SubjectKind != resolve.ExecutionSubjectModel || !kind.Valid() || now.IsZero() {
		return ResolvedBinding{}, fmt.Errorf("%w: parent model, tool kind, and time are required", ErrInvalidBinding)
	}
	return r.resolve(ctx, parent, string(kind), kind, "", vcp.OperationKind(""), now)
}

// ResolveExtension selects the first ready binding for one closed operation-backed Router enhancement.
// ResolveExtension 为一个封闭且由操作支持的 Router 增强能力选择首个就绪绑定。
func (r *Resolver) ResolveExtension(ctx context.Context, parent resolve.Target, extension vcp.RouterExtensionKind, now time.Time) (ResolvedBinding, error) {
	if ctx == nil || parent.SubjectKind != resolve.ExecutionSubjectModel || !extension.Valid() || now.IsZero() {
		return ResolvedBinding{}, fmt.Errorf("%w: parent model, Router extension, and time are required", ErrInvalidBinding)
	}
	return r.resolve(ctx, parent, string(extension), "", extension, extension.Operation(), now)
}

// resolve selects one exact binding family without inferring a service operation from provider names.
// resolve 在不根据供应商名称推断服务操作的情况下选择一个精确绑定族。
func (r *Resolver) resolve(ctx context.Context, parent resolve.Target, toolID string, kind vcp.StandardModelToolKind, extension vcp.RouterExtensionKind, operation vcp.OperationKind, now time.Time) (ResolvedBinding, error) {
	bindings, errList := r.bindings.List(ctx)
	if errList != nil {
		return ResolvedBinding{}, errList
	}
	matched := false
	for _, binding := range bindings {
		if binding.Kind != kind || binding.Extension != extension || !bindingMatchesParent(binding, parent) {
			continue
		}
		matched = true
		if !binding.Enabled {
			continue
		}
		childOperation := operation
		if kind.Valid() {
			childOperation = binding.Operation()
		}
		target, _, errResolve := r.targets.Resolve(ctx, bindingResolveRequest(binding, childOperation, now))
		if errResolve != nil {
			if bindingTargetUnavailable(errResolve) {
				continue
			}
			return ResolvedBinding{}, errResolve
		}
		resolved := ResolvedBinding{Binding: cloneBinding(binding), Target: target}
		if errResolved := resolved.Validate(); errResolved != nil {
			return ResolvedBinding{}, errResolved
		}
		return resolved, nil
	}
	if !matched {
		return ResolvedBinding{}, fmt.Errorf("%w: %s", ErrBindingNotFound, toolID)
	}
	return ResolvedBinding{}, fmt.Errorf("%w: %s", ErrBindingUnavailable, toolID)
}

// Availability reports configured support and current readiness without exposing backend identity.
// Availability 报告已配置支持与当前就绪状态且不暴露后端身份。
func (r *Resolver) Availability(ctx context.Context, parent resolve.Target, kind vcp.StandardModelToolKind, now time.Time) (Availability, error) {
	if ctx == nil || parent.SubjectKind != resolve.ExecutionSubjectModel || !kind.Valid() || now.IsZero() {
		return Availability{}, fmt.Errorf("%w: parent model, tool kind, and time are required", ErrInvalidBinding)
	}
	return r.availability(ctx, parent, kind, "", now)
}

// AvailabilityExtension reports configured support and current readiness for one closed Router enhancement.
// AvailabilityExtension 报告一个封闭 Router 增强能力的已配置支持与当前就绪状态。
func (r *Resolver) AvailabilityExtension(ctx context.Context, parent resolve.Target, extension vcp.RouterExtensionKind, now time.Time) (Availability, error) {
	if ctx == nil || parent.SubjectKind != resolve.ExecutionSubjectModel || !extension.Valid() || now.IsZero() {
		return Availability{}, fmt.Errorf("%w: parent model, Router extension, and time are required", ErrInvalidBinding)
	}
	return r.availability(ctx, parent, "", extension, now)
}

// availability evaluates one exact binding family and its independently resolved child operation.
// availability 评估一个精确绑定族及其独立解析的子操作。
func (r *Resolver) availability(ctx context.Context, parent resolve.Target, kind vcp.StandardModelToolKind, extension vcp.RouterExtensionKind, now time.Time) (Availability, error) {
	bindings, errList := r.bindings.List(ctx)
	if errList != nil {
		return Availability{}, errList
	}
	availability := Availability{UnavailableReason: AvailabilityReasonBindingMissing}
	for _, binding := range bindings {
		if binding.Kind != kind || binding.Extension != extension || !bindingMatchesParent(binding, parent) {
			continue
		}
		availability.Supported = true
		if !binding.Enabled {
			if availability.UnavailableReason == AvailabilityReasonBindingMissing {
				availability.UnavailableReason = AvailabilityReasonBindingDisabled
			}
			continue
		}
		availability.UnavailableReason = AvailabilityReasonBindingUnavailable
		if target, _, errResolve := r.targets.Resolve(ctx, bindingResolveRequest(binding, binding.Operation(), now)); errResolve == nil {
			if !bindingOwnsResolvedTarget(binding, target) {
				return Availability{}, fmt.Errorf("%w: resolved target differs from binding %s", ErrInvalidBinding, binding.ID)
			}
			availability.Ready = true
			availability.UnavailableReason = ""
			return availability, nil
		} else if !bindingTargetUnavailable(errResolve) {
			return Availability{}, errResolve
		}
	}
	return availability, nil
}

// ProbeBinding tests one persisted binding's exact backend resolution without requiring a parent-model scope.
// ProbeBinding 在不要求父模型范围的情况下测试一个持久化绑定的精确后端解析。
func (r *Resolver) ProbeBinding(ctx context.Context, bindingID string, now time.Time) (BindingProbe, error) {
	if ctx == nil || bindingID == "" || now.IsZero() {
		return BindingProbe{}, fmt.Errorf("%w: binding identifier, context, and time are required", ErrInvalidBinding)
	}
	binding, errBinding := r.bindings.Get(ctx, bindingID)
	if errBinding != nil {
		return BindingProbe{}, errBinding
	}
	probe := BindingProbe{
		BindingID: binding.ID,
		Revision:  binding.Revision,
		ToolID:    binding.ToolID(),
		Operation: binding.Operation(),
	}
	if !binding.Enabled {
		probe.UnavailableReason = AvailabilityReasonBindingDisabled
		return probe, nil
	}
	target, _, errResolve := r.targets.Resolve(ctx, bindingResolveRequest(binding, binding.Operation(), now))
	if errResolve != nil {
		if bindingTargetUnavailable(errResolve) {
			probe.UnavailableReason = AvailabilityReasonBindingUnavailable
			return probe, nil
		}
		return BindingProbe{}, errResolve
	}
	if !bindingOwnsResolvedTarget(binding, target) {
		return BindingProbe{}, fmt.Errorf("%w: resolved target differs from binding %s", ErrInvalidBinding, binding.ID)
	}
	probe.Ready = true
	return probe, nil
}

// bindingTargetUnavailable reports only closed resolver outcomes that permit trying another configured backend.
// bindingTargetUnavailable 仅报告允许继续尝试其他已配置后端的封闭解析结果。
func bindingTargetUnavailable(errValue error) bool {
	return errors.Is(errValue, resolve.ErrInstanceNotExecutable) ||
		errors.Is(errValue, resolve.ErrModelNotFound) ||
		errors.Is(errValue, resolve.ErrModelDisabled) ||
		errors.Is(errValue, resolve.ErrServiceNotFound) ||
		errors.Is(errValue, resolve.ErrServiceDisabled) ||
		errors.Is(errValue, resolve.ErrProfileNotFound) ||
		errors.Is(errValue, resolve.ErrProfilePolicyMismatch) ||
		errors.Is(errValue, resolve.ErrNoEligibleTarget)
}

// bindingResolveRequest projects the exact binding target family without cross-family fallback.
// bindingResolveRequest 投影精确绑定目标族且不进行跨目标族回退。
func bindingResolveRequest(binding Binding, operation vcp.OperationKind, now time.Time) resolve.Request {
	request := resolve.Request{
		ProviderInstanceID: binding.ProviderInstanceID,
		ExecutionProfileID: binding.ExecutionProfileID,
		Operation:          operation,
		Now:                now,
	}
	if binding.Kind.Valid() {
		request.ProviderServiceID = binding.ProviderServiceID
		request.ServiceOfferingID = binding.ServiceOfferingID
	} else {
		request.ProviderModelID = binding.ProviderModelID
		request.OfferingID = binding.OfferingID
	}
	return request
}

// bindingOwnsResolvedTarget verifies every persisted identity against the immutable child target.
// bindingOwnsResolvedTarget 根据不可变子 Target 校验每个持久化身份。
func bindingOwnsResolvedTarget(binding Binding, target resolve.Target) bool {
	if target.ProviderInstanceID != binding.ProviderInstanceID ||
		target.ExecutionProfileID != binding.ExecutionProfileID ||
		target.Operation != binding.Operation() {
		return false
	}
	if binding.Kind.Valid() {
		return target.SubjectKind == resolve.ExecutionSubjectService &&
			target.ProviderServiceID == binding.ProviderServiceID &&
			target.ServiceOfferingID == binding.ServiceOfferingID
	}
	return target.SubjectKind == resolve.ExecutionSubjectModel &&
		target.ProviderModelID == binding.ProviderModelID &&
		target.OfferingID == binding.OfferingID
}

// bindingMatchesParent applies only administrator-authored exact allowlists.
// bindingMatchesParent 仅应用管理员编写的精确允许列表。
func bindingMatchesParent(binding Binding, parent resolve.Target) bool {
	return containsScope(binding.AllowedProviderInstanceIDs, parent.ProviderInstanceID) &&
		containsScope(binding.AllowedProviderModelIDs, parent.ProviderModelID) &&
		containsScope(binding.AllowedExecutionProfileIDs, parent.ExecutionProfileID)
}

// containsScope treats an empty allowlist as unrestricted and never normalizes aliases.
// containsScope 将空允许列表视为不限制且绝不规范化别名。
func containsScope(values []string, target string) bool {
	if len(values) == 0 {
		return true
	}
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
