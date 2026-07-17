// Package core defines the provider-scoped execution boundary for Vulcan Model Core.
// core 包定义 Vulcan Model Core 以供应商为边界的执行核心。
package core

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

var (
	// ErrInvalidTarget identifies an incomplete provider-scoped execution target.
	// ErrInvalidTarget 标识不完整的供应商作用域执行目标。
	ErrInvalidTarget = errors.New("invalid execution target")
	// ErrAdapterNotFound identifies a provider without a registered adapter.
	// ErrAdapterNotFound 标识没有注册适配器的供应商。
	ErrAdapterNotFound = errors.New("provider adapter not found")
	// ErrDuplicateProvider identifies a duplicate provider registration.
	// ErrDuplicateProvider 标识重复的供应商注册。
	ErrDuplicateProvider = errors.New("provider adapter already registered")
	// ErrAdapterRequired identifies an empty adapter registration.
	// ErrAdapterRequired 标识空适配器注册。
	ErrAdapterRequired = errors.New("provider adapter is required")
	// ErrRegistryRequired identifies a missing provider registry.
	// ErrRegistryRequired 标识缺失的供应商注册表。
	ErrRegistryRequired = errors.New("provider registry is required")
)

// Target identifies one immutable provider-scoped execution destination.
// Target 标识一个不可变的供应商作用域执行目标。
type Target struct {
	// Provider identifies the provider boundary that must not change during execution.
	// Provider 标识执行期间不得改变的供应商边界。
	Provider string
	// Model identifies the provider-native model or provider-scoped alias.
	// Model 标识供应商原生模型或供应商作用域别名。
	Model string
	// Plan optionally constrains execution to one plan within the provider.
	// Plan 可选地将执行限制在供应商内部的一个套餐。
	Plan string
}

// Validate verifies that the immutable provider and model boundary is explicit.
// Validate 校验不可变的供应商和模型边界是否明确。
func (t Target) Validate() error {
	if strings.TrimSpace(t.Provider) == "" {
		return fmt.Errorf("%w: provider is required", ErrInvalidTarget)
	}
	if strings.TrimSpace(t.Model) == "" {
		return fmt.Errorf("%w: model is required", ErrInvalidTarget)
	}
	return nil
}

// Request carries one Vulcan protocol payload to an exact provider target.
// Request 将一个 Vulcan 协议载荷传递给精确的供应商目标。
type Request struct {
	// Target is the immutable destination selected before execution starts.
	// Target 是执行开始前选定的不可变目标。
	Target Target
	// Payload contains protocol-owned bytes that the core must not reinterpret.
	// Payload 包含核心不得重新解释的协议所属字节。
	Payload []byte
}

// Response carries provider output normalized to the Vulcan protocol boundary.
// Response 携带已归一化到 Vulcan 协议边界的供应商输出。
type Response struct {
	// Payload contains protocol-owned Vulcan response bytes.
	// Payload 包含协议所属的 Vulcan 响应字节。
	Payload []byte
}

// Adapter executes requests for exactly one provider.
// Adapter 仅为一个精确供应商执行请求。
type Adapter interface {
	// ProviderID returns the unique provider identifier owned by this adapter.
	// ProviderID 返回该适配器所属的唯一供应商标识。
	ProviderID() string
	// Execute sends one request without changing its provider boundary.
	// Execute 在不改变供应商边界的前提下发送一次请求。
	Execute(ctx context.Context, request Request) (Response, error)
}

// Registry stores provider adapters by exact provider identifier.
// Registry 按精确供应商标识存储供应商适配器。
type Registry struct {
	// mu protects adapters during concurrent registration and lookup.
	// mu 在并发注册和查询期间保护适配器集合。
	mu sync.RWMutex
	// adapters maps one provider identifier to exactly one adapter.
	// adapters 将一个供应商标识映射到唯一适配器。
	adapters map[string]Adapter
}

// NewRegistry creates an empty provider-scoped adapter registry.
// NewRegistry 创建一个空的供应商作用域适配器注册表。
func NewRegistry() *Registry {
	return &Registry{adapters: make(map[string]Adapter)}
}

// Register adds one adapter and rejects ambiguous provider ownership.
// Register 添加一个适配器并拒绝存在歧义的供应商归属。
func (r *Registry) Register(adapter Adapter) error {
	if adapter == nil {
		return ErrAdapterRequired
	}
	// providerID is the normalized identifier used as the registry key.
	// providerID 是用作注册表键的规范化标识。
	providerID := strings.TrimSpace(adapter.ProviderID())
	if providerID == "" {
		return fmt.Errorf("%w: provider identifier is required", ErrInvalidTarget)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.adapters[providerID]; exists {
		return fmt.Errorf("%w: %s", ErrDuplicateProvider, providerID)
	}
	r.adapters[providerID] = adapter
	return nil
}

// Lookup returns the adapter registered for an exact provider identifier.
// Lookup 返回为精确供应商标识注册的适配器。
func (r *Registry) Lookup(providerID string) (Adapter, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	// adapter is the exact provider adapter stored in the registry.
	// adapter 是注册表中存储的精确供应商适配器。
	adapter, exists := r.adapters[strings.TrimSpace(providerID)]
	return adapter, exists
}

// ProviderIDs returns a stable sorted snapshot of registered providers.
// ProviderIDs 返回已注册供应商的稳定排序快照。
func (r *Registry) ProviderIDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	// providerIDs stores an isolated provider identifier snapshot.
	// providerIDs 存储隔离后的供应商标识快照。
	providerIDs := make([]string, 0, len(r.adapters))
	for providerID := range r.adapters {
		providerIDs = append(providerIDs, providerID)
	}
	sort.Strings(providerIDs)
	return providerIDs
}

// Count returns the number of registered provider adapters.
// Count 返回已注册供应商适配器的数量。
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.adapters)
}

// Router dispatches each request to its explicitly selected provider only.
// Router 仅将每个请求分派给其明确选择的供应商。
type Router struct {
	// registry resolves one exact provider without cross-provider candidates.
	// registry 解析一个精确供应商且不接受跨供应商候选。
	registry *Registry
}

// NewRouter creates a provider-scoped router.
// NewRouter 创建一个供应商作用域路由器。
func NewRouter(registry *Registry) (*Router, error) {
	if registry == nil {
		return nil, ErrRegistryRequired
	}
	return &Router{registry: registry}, nil
}

// Execute validates the target and invokes only its exact provider adapter.
// Execute 校验目标并仅调用其精确供应商适配器。
func (r *Router) Execute(ctx context.Context, request Request) (Response, error) {
	if errValidate := request.Target.Validate(); errValidate != nil {
		return Response{}, errValidate
	}
	// adapter is resolved only from the immutable request provider.
	// adapter 仅根据不可变的请求供应商进行解析。
	adapter, exists := r.registry.Lookup(request.Target.Provider)
	if !exists {
		return Response{}, fmt.Errorf("%w: %s", ErrAdapterNotFound, request.Target.Provider)
	}
	return adapter.Execute(ctx, request)
}
