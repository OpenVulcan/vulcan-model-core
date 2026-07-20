package httpapi

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/management"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// selectiveTargetAvailability resolves only the explicitly admitted profile identifiers.
// selectiveTargetAvailability 仅解析被明确允许的规格标识。
type selectiveTargetAvailability struct {
	// profiles contains the exact currently executable profile set.
	// profiles 包含当前精确可执行规格集合。
	profiles map[string]struct{}
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
	return resolve.Target{ExecutionProfileID: request.ExecutionProfileID}, resolve.Diagnostics{ReadyCandidates: 1}, nil
}

// TestExecutableModelViewRemovesUnavailableProfiles verifies discovery never publishes a profile that exact resolution rejects.
// TestExecutableModelViewRemovesUnavailableProfiles 验证发现接口绝不发布精确解析拒绝的规格。
func TestExecutableModelViewRemovesUnavailableProfiles(t *testing.T) {
	server := &Server{control: &ControlPlane{Targets: selectiveTargetAvailability{profiles: map[string]struct{}{"profile_ready": {}}}}}
	model := management.ModelView{ID: "model_test", Offerings: []management.OfferingView{
		{ID: "offer_ready", Profiles: []management.ExecutionProfileView{{ID: "profile_ready", Operation: vcp.OperationImageGenerate}, {ID: "profile_blocked", Operation: vcp.OperationImageEdit}}},
		{ID: "offer_blocked", Profiles: []management.ExecutionProfileView{{ID: "profile_other", Operation: vcp.OperationVideoGenerate}}},
	}}

	filtered, executable, errFilter := server.executableModelView(context.Background(), "pvi_test", model, time.Now())
	if errFilter != nil {
		t.Fatalf("executableModelView() error = %v", errFilter)
	}
	if !executable || len(filtered.Offerings) != 1 || len(filtered.Offerings[0].Profiles) != 1 || filtered.Offerings[0].Profiles[0].ID != "profile_ready" {
		t.Fatalf("executableModelView() = %#v, executable=%t", filtered, executable)
	}
	if len(model.Offerings[0].Profiles) != 2 {
		t.Fatal("executableModelView() mutated the management model view")
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
	if _, _, errFilter := server.executableModelView(context.Background(), "pvi_test", model, time.Now()); !errors.Is(errFilter, context.Canceled) {
		t.Fatalf("executableModelView() error = %v, want context.Canceled", errFilter)
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
