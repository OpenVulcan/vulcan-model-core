package httpapi

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/management"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/routertool"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// selectiveTargetAvailability resolves only the explicitly admitted profile identifiers.
// selectiveTargetAvailability 仅解析被明确允许的规格标识。
type selectiveTargetAvailability struct {
	// profiles contains the exact currently executable profile set.
	// profiles 包含当前精确可执行规格集合。
	profiles map[string]struct{}
	// offerings optionally fixes the exact offering owned by each admitted profile.
	// offerings 可选地固定每个已允许规格所属的精确产品。
	offerings map[string]string
}

// Resolve returns a target only for an admitted exact profile.
// Resolve 仅为允许的精确规格返回 Target。
// Parameters: ctx carries cancellation; request identifies the exact profile.
// 参数：ctx 携带取消信号；request 标识精确规格。
// Returns: an immutable target and diagnostics, or an explicit ineligibility error.
// 返回：不可变 Target 与诊断信息，或明确的不合格错误。
func (a selectiveTargetAvailability) Resolve(ctx context.Context, request resolve.Request) (resolve.Target, resolve.Diagnostics, error) {
	if errContext := ctx.Err(); errContext != nil {
		return resolve.Target{}, resolve.Diagnostics{}, errContext
	}
	if _, exists := a.profiles[request.ExecutionProfileID]; !exists {
		return resolve.Target{}, resolve.Diagnostics{}, resolve.ErrNoEligibleTarget
	}
	if offeringID, constrained := a.offerings[request.ExecutionProfileID]; constrained && request.OfferingID != offeringID {
		return resolve.Target{}, resolve.Diagnostics{}, resolve.ErrNoEligibleTarget
	}
	return resolve.Target{ExecutionProfileID: request.ExecutionProfileID}, resolve.Diagnostics{ReadyCandidates: 1}, nil
}

// TestCallModelToolViewsRetainsStaticSupportWithoutReadyCredential verifies static facts remain visible while readiness is false.
// TestCallModelToolViewsRetainsStaticSupportWithoutReadyCredential 验证没有就绪凭据时仍公开静态事实且就绪状态为假。
func TestCallModelToolViewsRetainsStaticSupportWithoutReadyCredential(t *testing.T) {
	server := &Server{control: &ControlPlane{Targets: selectiveTargetAvailability{profiles: map[string]struct{}{}}}}
	model := management.ModelView{
		ID: "model_static",
		Offerings: []management.OfferingView{{
			ID: "offering_static",
			Profiles: []management.ExecutionProfileView{{
				ID:        "profile_static",
				Operation: vcp.OperationConversationRespond,
				Capabilities: management.CapabilityView{
					StandardTools: []catalog.StandardModelToolCapability{{
						Kind:              vcp.StandardModelToolWebSearch,
						Native:            true,
						AllowsCallerTools: true,
					}},
					ExtraTools: []catalog.ModelExtraToolCapability{{
						ID:                "code_interpreter",
						DisplayName:       "Code Interpreter",
						Description:       "Provider-managed code execution.",
						AllowsCallerTools: true,
					}},
				},
			}},
		}},
	}
	views, errViews := server.callModelToolViews(context.Background(), "pvi_static", model, time.Now())
	if errViews != nil {
		t.Fatalf("callModelToolViews() error = %v", errViews)
	}
	if len(views) != 1 ||
		len(views[0].Standard) != 2 ||
		!views[0].Standard[0].NativeSupported ||
		views[0].Standard[0].NativeReady ||
		views[0].Standard[0].NativeUnavailableReason != callModelToolUnavailableReasonParentTargetUnavailable ||
		views[0].Standard[0].RouterToolUnavailableReason != callModelToolUnavailableReason(routertool.AvailabilityReasonBindingMissing) ||
		len(views[0].Extra) != 1 ||
		views[0].Extra[0].Ready ||
		views[0].Extra[0].UnavailableReason != callModelToolUnavailableReasonParentTargetUnavailable {
		t.Fatalf("static model-tool view = %#v", views)
	}
}

// TestEffectiveRouterToolAvailabilityRequiresExecutableParent verifies a ready binding cannot make an unavailable parent executable.
// TestEffectiveRouterToolAvailabilityRequiresExecutableParent 验证就绪绑定不能让不可用的父模型变为可执行。
func TestEffectiveRouterToolAvailabilityRequiresExecutableParent(t *testing.T) {
	ready, reason := effectiveRouterToolAvailability(false, routertool.Availability{Supported: true, Ready: true})
	if ready || reason != callModelToolUnavailableReasonParentTargetUnavailable {
		t.Fatalf("effectiveRouterToolAvailability(false, ready) = (%t, %q)", ready, reason)
	}
	ready, reason = effectiveRouterToolAvailability(true, routertool.Availability{
		Supported:         true,
		Ready:             false,
		UnavailableReason: routertool.AvailabilityReasonBindingUnavailable,
	})
	if ready || reason != callModelToolUnavailableReason(routertool.AvailabilityReasonBindingUnavailable) {
		t.Fatalf("effectiveRouterToolAvailability(true, unavailable) = (%t, %q)", ready, reason)
	}
}

// TestCallModelToolViewsResolvesExactOffering verifies readiness never drops the product identity selected by the view.
// TestCallModelToolViewsResolvesExactOffering 验证就绪度计算绝不丢失视图选定的产品身份。
func TestCallModelToolViewsResolvesExactOffering(t *testing.T) {
	server := &Server{control: &ControlPlane{Targets: selectiveTargetAvailability{
		profiles:  map[string]struct{}{"profile_exact": {}},
		offerings: map[string]string{"profile_exact": "offering_exact"},
	}}}
	model := management.ModelView{ID: "model_exact", Offerings: []management.OfferingView{{
		ID: "offering_exact",
		Profiles: []management.ExecutionProfileView{{
			ID:        "profile_exact",
			Operation: vcp.OperationConversationRespond,
			Capabilities: management.CapabilityView{StandardTools: []catalog.StandardModelToolCapability{{
				Kind:              vcp.StandardModelToolWebSearch,
				Native:            true,
				AllowsCallerTools: true,
			}}},
		}},
	}}}
	views, errViews := server.callModelToolViews(context.Background(), "pvi_exact", model, time.Now())
	if errViews != nil {
		t.Fatalf("callModelToolViews() error = %v", errViews)
	}
	if len(views) != 1 || !views[0].Standard[0].NativeReady {
		t.Fatalf("exact offering model-tool view = %#v", views)
	}
}

// TestExecutableServiceViewRemovesUnavailableProfiles verifies service discovery prunes blocked offerings and profiles independently.
// TestExecutableServiceViewRemovesUnavailableProfiles 验证服务发现独立裁剪被阻塞的产品与规格。
func TestExecutableServiceViewRemovesUnavailableProfiles(t *testing.T) {
	server := &Server{control: &ControlPlane{Targets: selectiveTargetAvailability{profiles: map[string]struct{}{"profile_search_ready": {}}}}}
	service := management.ServiceView{ID: "service_search", Operation: vcp.OperationSearchWeb, Offerings: []management.ServiceOfferingView{
		{ID: "service_offer_ready", Capabilities: catalog.ServiceCapabilities{}, Profiles: []management.ServiceExecutionProfileView{{ID: "profile_search_ready", Operation: vcp.OperationSearchWeb}, {ID: "profile_search_blocked", Operation: vcp.OperationSearchWeb}}},
		{ID: "service_offer_blocked", Capabilities: catalog.ServiceCapabilities{}, Profiles: []management.ServiceExecutionProfileView{{ID: "profile_search_other", Operation: vcp.OperationSearchWeb}}},
	}}

	filtered, executable, errFilter := server.executableServiceView(context.Background(), "pvi_test", service, time.Now())
	if errFilter != nil {
		t.Fatalf("executableServiceView() error = %v", errFilter)
	}
	if !executable || len(filtered.Offerings) != 1 || len(filtered.Offerings[0].Profiles) != 1 || filtered.Offerings[0].Profiles[0].ID != "profile_search_ready" {
		t.Fatalf("executableServiceView() = %#v, executable=%t", filtered, executable)
	}
	if len(service.Offerings[0].Profiles) != 2 {
		t.Fatal("executableServiceView() mutated the management service view")
	}
}

// TestExecutableDiscoveryPropagatesOperationalFailure verifies repository and cancellation errors cannot masquerade as unavailable profiles.
// TestExecutableDiscoveryPropagatesOperationalFailure 验证存储与取消错误不能伪装成不可用规格。
func TestExecutableDiscoveryPropagatesOperationalFailure(t *testing.T) {
	server := &Server{control: &ControlPlane{Targets: failingTargetAvailability{err: context.Canceled}}}
	model := management.ModelView{ID: "model_test", Offerings: []management.OfferingView{{ID: "offer_test", Profiles: []management.ExecutionProfileView{{ID: "profile_test", Operation: vcp.OperationImageGenerate}}}}}
	if _, errViews := server.callModelToolViews(context.Background(), "pvi_test", model, time.Now()); !errors.Is(errViews, context.Canceled) {
		t.Fatalf("callModelToolViews() error = %v, want context.Canceled", errViews)
	}
}

// failingTargetAvailability returns one deterministic operational failure.
// failingTargetAvailability 返回一个确定的操作失败。
type failingTargetAvailability struct {
	// err is the exact failure returned by Resolve.
	// err 是 Resolve 返回的精确失败。
	err error
}

// Resolve returns the configured operational error without classifying it as profile ineligibility.
// Resolve 返回配置的操作错误且不把它分类为规格不可用。
// Parameters: context and request are accepted to satisfy the exact availability boundary.
// 参数：接收 context 与 request 以满足精确可用性边界。
// Returns: empty target facts and the configured error.
// 返回：空 Target 事实与配置的错误。
func (a failingTargetAvailability) Resolve(context.Context, resolve.Request) (resolve.Target, resolve.Diagnostics, error) {
	return resolve.Target{}, resolve.Diagnostics{}, a.err
}
