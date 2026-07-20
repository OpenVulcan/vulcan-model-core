package inputplan

import (
	"context"
	"sync"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
)

// Store persists immutable input plans until retention cleanup.
// Store 持久化不可变输入方案直到保留清理。
type Store interface {
	// Save creates one plan and rejects identifier reuse.
	// Save 创建一个方案并拒绝标识复用。
	Save(context.Context, Plan) error
	// Get returns one mutation-safe plan snapshot.
	// Get 返回一个防止外部修改的方案快照。
	Get(context.Context, string) (Plan, error)
}

// MemoryStore is an in-memory input-plan repository for tests and isolated use.
// MemoryStore 是用于测试与隔离使用的内存输入方案仓库。
type MemoryStore struct {
	// mu protects the immutable plan map.
	// mu 保护不可变方案映射。
	mu sync.RWMutex
	// plans owns plan snapshots by identifier.
	// plans 按标识拥有方案快照。
	plans map[string]Plan
}

// NewMemoryStore creates an empty input-plan repository.
// NewMemoryStore 创建一个空输入方案仓库。
func NewMemoryStore() *MemoryStore { return &MemoryStore{plans: make(map[string]Plan)} }

// Save creates one validated immutable plan.
// Save 创建一个已校验不可变方案。
func (s *MemoryStore) Save(ctx context.Context, plan Plan) error {
	if ctx == nil {
		return ErrInvalidPlan
	}
	if errContext := ctx.Err(); errContext != nil {
		return errContext
	}
	if s == nil {
		return ErrInvalidPlan
	}
	if errValidate := plan.Validate(); errValidate != nil {
		return errValidate
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.plans[plan.ID]; exists {
		return ErrInvalidPlan
	}
	s.plans[plan.ID] = clonePlan(plan)
	return nil
}

// Get returns one mutation-safe plan snapshot.
// Get 返回一个防止外部修改的方案快照。
func (s *MemoryStore) Get(ctx context.Context, identifier string) (Plan, error) {
	if ctx == nil {
		return Plan{}, ErrInvalidPlan
	}
	if errContext := ctx.Err(); errContext != nil {
		return Plan{}, errContext
	}
	if s == nil {
		return Plan{}, ErrInvalidPlan
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	plan, exists := s.plans[identifier]
	if !exists {
		return Plan{}, ErrPlanNotFound
	}
	return clonePlan(plan), nil
}

// clonePlan isolates mutable slices and nested capability contracts.
// clonePlan 隔离可变切片与嵌套能力契约。
func clonePlan(plan Plan) Plan {
	plan.Inputs = append([]PlannedInput(nil), plan.Inputs...)
	plan.Target.ModelCapabilities = catalog.CloneModelCapabilities(plan.Target.ModelCapabilities)
	if plan.Target.ServiceCapabilities != nil {
		capabilities := *plan.Target.ServiceCapabilities
		plan.Target.ServiceCapabilities = &capabilities
	}
	return plan
}
