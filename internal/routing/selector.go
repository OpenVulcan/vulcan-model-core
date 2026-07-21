// Portions of this file are copied and adapted from CLIProxyAPI sdk/cliproxy/auth/selector.go and scheduler.go at commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// 本文件部分逻辑复制并改编自 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66 中的 sdk/cliproxy/auth/selector.go 与 scheduler.go。
// Package routing adapts CLIProxyAPI's proven credential selectors to provider-instance-owned Vulcan candidates.
// routing 包将 CLIProxyAPI 已验证的凭据选择器适配为供应商实例所有的 Vulcan 候选。
package routing

import (
	"errors"
	"sort"
	"sync"

	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
)

const (
	// defaultMaximumCursorKeys preserves CLIProxyAPI's bounded cursor-map behavior.
	// defaultMaximumCursorKeys 保留 CLIProxyAPI 的有界游标 Map 行为。
	defaultMaximumCursorKeys = 4096
	// maximumSafeCursorValue resets before an int cursor approaches overflow.
	// maximumSafeCursorValue 在 int 游标接近溢出前执行重置。
	maximumSafeCursorValue = 2_147_483_640
)

var (
	// ErrNoCandidate reports an empty eligible credential pool.
	// ErrNoCandidate 表示合格凭据池为空。
	ErrNoCandidate = errors.New("no eligible routing candidate")
)

// Candidate contains only safe selection facts after Resolver eligibility filtering.
// Candidate 仅包含 Resolver 资格过滤后的安全选择事实。
type Candidate struct {
	// ID is the immutable credential identifier returned after selection.
	// ID 是选择后返回的不可变凭据标识。
	ID string
	// Priority forms deterministic preference buckets; lower values win.
	// Priority 形成确定性偏好桶；较小值优先。
	Priority int
	// CapacityKnown reports whether Capacity is an authoritative account ceiling.
	// CapacityKnown 表示 Capacity 是否为权威账号上限。
	CapacityKnown bool
	// Capacity is used only to preserve the smallest sufficient account class.
	// Capacity 仅用于保护满足要求的最小账号等级。
	Capacity int64
}

// SelectionOptions contains exact per-profile selection behavior.
// SelectionOptions 包含精确的逐 Profile 选择行为。
type SelectionOptions struct {
	// Strategy selects balanced rotation or first-account exhaustion.
	// Strategy 选择均衡轮换或首账号优先消耗。
	Strategy providerconfig.RoutingStrategy
	// PreferSmallestSufficient keeps scarce high-capacity accounts outside a lower-capacity bucket.
	// PreferSmallestSufficient 将稀缺高容量账号排除在低容量桶之外。
	PreferSmallestSufficient bool
}

// Selector is CLIProxyAPI's bounded provider-and-model-scoped round-robin cursor adapted to Vulcan ownership keys.
// Selector 是从 CLIProxyAPI 适配而来的有界供应商模型作用域轮询游标，并使用 Vulcan 所有权键。
type Selector struct {
	// mu protects cursor initialization, selection, and bounded reset.
	// mu 保护游标初始化、选择与有界重置。
	mu sync.Mutex
	// cursors stores the next balanced index for each exact pool key.
	// cursors 为每个精确账号池键保存下一均衡索引。
	cursors map[string]int
	// maxKeys overrides the copied 4096-key limit in focused tests.
	// maxKeys 在聚焦测试中覆盖复制的 4096 Key 上限。
	maxKeys int
}

// NewSelector creates one process-local thread-safe selector.
// NewSelector 创建一个进程本地线程安全选择器。
func NewSelector() *Selector {
	return &Selector{cursors: make(map[string]int)}
}

// Pick selects one candidate after priority and optional capacity bucketing.
// Pick 在优先级与可选容量分桶后选择一个候选。
func (s *Selector) Pick(key string, options SelectionOptions, candidates []Candidate) (Candidate, error) {
	if s == nil || key == "" || len(candidates) == 0 {
		return Candidate{}, ErrNoCandidate
	}
	available := preferredBucket(candidates, options.PreferSmallestSufficient)
	if len(available) == 0 {
		return Candidate{}, ErrNoCandidate
	}
	if options.Strategy == providerconfig.RoutingFillFirst {
		return available[0], nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cursors == nil {
		s.cursors = make(map[string]int)
	}
	limit := s.maxKeys
	if limit <= 0 {
		limit = defaultMaximumCursorKeys
	}
	s.ensureCursorKey(key, limit)
	index := s.cursors[key]
	if index >= maximumSafeCursorValue {
		index = 0
	}
	s.cursors[key] = index + 1
	return available[index%len(available)], nil
}

// ensureCursorKey preserves CLIProxyAPI's bounded reset when a new pool would exceed the cursor-key limit.
// ensureCursorKey 保留 CLIProxyAPI 在新账号池超过游标 Key 上限时执行的有界重置。
func (s *Selector) ensureCursorKey(key string, limit int) {
	if _, exists := s.cursors[key]; !exists && len(s.cursors) >= limit {
		s.cursors = make(map[string]int)
	}
}

// preferredBucket copies CLIProxyAPI's priority-bucket selection and adds Vulcan's profile-capacity conservation.
// preferredBucket 复制 CLIProxyAPI 的优先级桶选择，并增加 Vulcan 的 Profile 容量保护。
func preferredBucket(candidates []Candidate, preferSmallestSufficient bool) []Candidate {
	ordered := append([]Candidate(nil), candidates...)
	sort.Slice(ordered, func(left int, right int) bool {
		if ordered[left].Priority != ordered[right].Priority {
			return ordered[left].Priority < ordered[right].Priority
		}
		if preferSmallestSufficient {
			if ordered[left].CapacityKnown != ordered[right].CapacityKnown {
				return ordered[left].CapacityKnown
			}
			if ordered[left].CapacityKnown && ordered[left].Capacity != ordered[right].Capacity {
				return ordered[left].Capacity < ordered[right].Capacity
			}
		}
		return ordered[left].ID < ordered[right].ID
	})
	bestPriority := ordered[0].Priority
	bestCapacityKnown := ordered[0].CapacityKnown
	bestCapacity := ordered[0].Capacity
	end := 0
	for end < len(ordered) {
		candidate := ordered[end]
		if candidate.Priority != bestPriority {
			break
		}
		if preferSmallestSufficient && (candidate.CapacityKnown != bestCapacityKnown || (bestCapacityKnown && candidate.Capacity != bestCapacity)) {
			break
		}
		end++
	}
	return ordered[:end]
}
