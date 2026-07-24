package routertool

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// Store persists Router model-tool bindings.
// Store 持久化 Router 模型工具绑定。
type Store interface {
	// Save creates or replaces one binding using optimistic revision rules.
	// Save 使用乐观修订规则创建或替换一个绑定。
	Save(context.Context, Binding) error
	// Get returns one mutation-safe binding.
	// Get 返回一个防止外部修改的绑定。
	Get(context.Context, string) (Binding, error)
	// List returns all bindings in deterministic selection order.
	// List 按确定性选择顺序返回全部绑定。
	List(context.Context) ([]Binding, error)
	// Delete removes one exact binding.
	// Delete 删除一个精确绑定。
	Delete(context.Context, string) error
}

// MemoryStore is a thread-safe Router model-tool binding store.
// MemoryStore 是线程安全的 Router 模型工具绑定存储。
type MemoryStore struct {
	// mu protects bindings.
	// mu 保护绑定数据。
	mu sync.RWMutex
	// bindings stores values by stable identifier.
	// bindings 按稳定标识存储值。
	bindings map[string]Binding
}

// NewMemoryStore creates an empty Router model-tool binding store.
// NewMemoryStore 创建空的 Router 模型工具绑定存储。
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{bindings: make(map[string]Binding)}
}

// Save validates and atomically stores one binding.
// Save 校验并原子存储一个绑定。
func (s *MemoryStore) Save(ctx context.Context, binding Binding) error {
	if ctx == nil {
		return fmt.Errorf("%w: context is required", ErrInvalidBinding)
	}
	if errContext := ctx.Err(); errContext != nil {
		return errContext
	}
	if errValidate := binding.Validate(); errValidate != nil {
		return errValidate
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.bindings[binding.ID]
	if exists {
		if errReplacement := binding.ValidateReplacement(current); errReplacement != nil {
			return errReplacement
		}
	} else if binding.Revision != 1 {
		return fmt.Errorf("%w: revision conflict", ErrInvalidBinding)
	}
	s.bindings[binding.ID] = cloneBinding(binding)
	return nil
}

// Get returns one mutation-safe binding.
// Get 返回一个防止外部修改的绑定。
func (s *MemoryStore) Get(ctx context.Context, id string) (Binding, error) {
	if ctx == nil {
		return Binding{}, fmt.Errorf("%w: context is required", ErrInvalidBinding)
	}
	if errContext := ctx.Err(); errContext != nil {
		return Binding{}, errContext
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	binding, exists := s.bindings[id]
	if !exists {
		return Binding{}, fmt.Errorf("%w: %s", ErrBindingNotFound, id)
	}
	return cloneBinding(binding), nil
}

// List returns all bindings by priority and identifier.
// List 按优先级和标识返回全部绑定。
func (s *MemoryStore) List(ctx context.Context) ([]Binding, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context is required", ErrInvalidBinding)
	}
	if errContext := ctx.Err(); errContext != nil {
		return nil, errContext
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	values := make([]Binding, 0, len(s.bindings))
	for _, binding := range s.bindings {
		values = append(values, cloneBinding(binding))
	}
	sortBindings(values)
	return values, nil
}

// Delete removes one exact binding.
// Delete 删除一个精确绑定。
func (s *MemoryStore) Delete(ctx context.Context, id string) error {
	if ctx == nil {
		return fmt.Errorf("%w: context is required", ErrInvalidBinding)
	}
	if errContext := ctx.Err(); errContext != nil {
		return errContext
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.bindings[id]; !exists {
		return fmt.Errorf("%w: %s", ErrBindingNotFound, id)
	}
	delete(s.bindings, id)
	return nil
}

// sortBindings orders bindings exactly as runtime selection.
// sortBindings 按运行时选择顺序排列绑定。
func sortBindings(values []Binding) {
	sort.Slice(values, func(left int, right int) bool {
		if values[left].Priority == values[right].Priority {
			return values[left].ID < values[right].ID
		}
		return values[left].Priority < values[right].Priority
	})
}

// cloneBinding returns a mutation-safe binding.
// cloneBinding 返回一个防止外部修改的绑定。
func cloneBinding(binding Binding) Binding {
	binding.AllowedProviderInstanceIDs = append([]string(nil), binding.AllowedProviderInstanceIDs...)
	binding.AllowedProviderModelIDs = append([]string(nil), binding.AllowedProviderModelIDs...)
	binding.AllowedExecutionProfileIDs = append([]string(nil), binding.AllowedExecutionProfileIDs...)
	return binding
}
