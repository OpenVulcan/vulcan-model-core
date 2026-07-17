package core

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
)

// recordingAdapter records executions for one test provider.
// recordingAdapter 记录一个测试供应商的执行次数。
type recordingAdapter struct {
	// providerID is the exact provider identifier owned by the adapter.
	// providerID 是适配器所属的精确供应商标识。
	providerID string
	// calls counts adapter executions.
	// calls 统计适配器执行次数。
	calls atomic.Int32
}

// ProviderID returns the test adapter provider identifier.
// ProviderID 返回测试适配器的供应商标识。
func (a *recordingAdapter) ProviderID() string {
	return a.providerID
}

// Execute records one execution and echoes the request payload.
// Execute 记录一次执行并回显请求载荷。
func (a *recordingAdapter) Execute(_ context.Context, request Request) (Response, error) {
	a.calls.Add(1)
	return Response{Payload: append([]byte(nil), request.Payload...)}, nil
}

// TestRegistryRejectsDuplicateProvider verifies unambiguous provider ownership.
// TestRegistryRejectsDuplicateProvider 验证供应商归属不存在歧义。
func TestRegistryRejectsDuplicateProvider(t *testing.T) {
	// registry is the isolated registry under test.
	// registry 是待测试的隔离注册表。
	registry := NewRegistry()
	if errRegister := registry.Register(&recordingAdapter{providerID: "anthropic"}); errRegister != nil {
		t.Fatalf("register first adapter: %v", errRegister)
	}
	if errRegister := registry.Register(&recordingAdapter{providerID: "anthropic"}); !errors.Is(errRegister, ErrDuplicateProvider) {
		t.Fatalf("duplicate registration error = %v, want %v", errRegister, ErrDuplicateProvider)
	}
}

// TestRegistryProviderIDsAreStable verifies deterministic provider metadata.
// TestRegistryProviderIDsAreStable 验证供应商元数据具有确定性。
func TestRegistryProviderIDsAreStable(t *testing.T) {
	// registry is populated out of order to verify sorting.
	// registry 以乱序填充以验证排序。
	registry := NewRegistry()
	for _, providerID := range []string{"openai", "anthropic", "gemini"} {
		if errRegister := registry.Register(&recordingAdapter{providerID: providerID}); errRegister != nil {
			t.Fatalf("register %s: %v", providerID, errRegister)
		}
	}
	// expected is the stable provider ordering returned to callers.
	// expected 是返回给调用方的稳定供应商顺序。
	expected := []string{"anthropic", "gemini", "openai"}
	if actual := registry.ProviderIDs(); !reflect.DeepEqual(actual, expected) {
		t.Fatalf("provider ids = %v, want %v", actual, expected)
	}
}

// TestRouterUsesOnlyRequestedProvider verifies the no-fusion routing invariant.
// TestRouterUsesOnlyRequestedProvider 验证禁止供应商融合的路由不变量。
func TestRouterUsesOnlyRequestedProvider(t *testing.T) {
	// anthropic is the requested provider adapter.
	// anthropic 是请求指定的供应商适配器。
	anthropic := &recordingAdapter{providerID: "anthropic"}
	// openai is a registered but unrequested provider adapter.
	// openai 是已注册但未被请求的供应商适配器。
	openai := &recordingAdapter{providerID: "openai"}
	// registry stores both providers without combining them.
	// registry 存储两个供应商但不会将其融合。
	registry := NewRegistry()
	for _, adapter := range []Adapter{anthropic, openai} {
		if errRegister := registry.Register(adapter); errRegister != nil {
			t.Fatalf("register adapter: %v", errRegister)
		}
	}
	// router dispatches through the exact provider key.
	// router 通过精确供应商键进行分派。
	router, errRouter := NewRouter(registry)
	if errRouter != nil {
		t.Fatalf("create router: %v", errRouter)
	}
	// request targets Anthropic and contains an opaque Vulcan payload.
	// request 指向 Anthropic 并包含不透明的 Vulcan 载荷。
	request := Request{Target: Target{Provider: "anthropic", Model: "claude-test"}, Payload: []byte(`{"input":"hello"}`)}
	if _, errExecute := router.Execute(context.Background(), request); errExecute != nil {
		t.Fatalf("execute request: %v", errExecute)
	}
	if actual := anthropic.calls.Load(); actual != 1 {
		t.Fatalf("anthropic calls = %d, want 1", actual)
	}
	if actual := openai.calls.Load(); actual != 0 {
		t.Fatalf("openai calls = %d, want 0", actual)
	}
}

// TestRouterRejectsUnknownProvider verifies that failures do not cross providers.
// TestRouterRejectsUnknownProvider 验证失败不会跨越供应商边界。
func TestRouterRejectsUnknownProvider(t *testing.T) {
	// registry intentionally contains only a different provider.
	// registry 故意只包含另一个供应商。
	registry := NewRegistry()
	if errRegister := registry.Register(&recordingAdapter{providerID: "openai"}); errRegister != nil {
		t.Fatalf("register adapter: %v", errRegister)
	}
	// router must fail instead of selecting the registered provider.
	// router 必须失败而不是选择已注册的供应商。
	router, errRouter := NewRouter(registry)
	if errRouter != nil {
		t.Fatalf("create router: %v", errRouter)
	}
	// request targets an unavailable provider.
	// request 指向一个不可用供应商。
	request := Request{Target: Target{Provider: "anthropic", Model: "claude-test"}}
	if _, errExecute := router.Execute(context.Background(), request); !errors.Is(errExecute, ErrAdapterNotFound) {
		t.Fatalf("execute error = %v, want %v", errExecute, ErrAdapterNotFound)
	}
}
