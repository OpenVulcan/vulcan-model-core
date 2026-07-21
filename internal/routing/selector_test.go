// Test cases in this file are copied and adapted from CLIProxyAPI sdk/cliproxy/auth/selector_test.go and scheduler_test.go at commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// 本文件测试场景复制并改编自 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66 中的 sdk/cliproxy/auth/selector_test.go 与 scheduler_test.go。
package routing

import (
	"sync"
	"testing"

	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
)

// TestRoundRobinSelectorCyclesDeterministically adapts CLIProxyAPI's stable cycle test.
// TestRoundRobinSelectorCyclesDeterministically 适配 CLIProxyAPI 的稳定循环测试。
func TestRoundRobinSelectorCyclesDeterministically(t *testing.T) {
	selector := NewSelector()
	candidates := []Candidate{{ID: "cred_b"}, {ID: "cred_a"}}
	want := []string{"cred_a", "cred_b", "cred_a"}
	for index, expected := range want {
		selected, errSelect := selector.Pick("pvi:model:profile", SelectionOptions{Strategy: providerconfig.RoutingRoundRobin}, candidates)
		if errSelect != nil || selected.ID != expected {
			t.Fatalf("Pick() #%d = %q, error = %v, want %q", index, selected.ID, errSelect, expected)
		}
	}
}

// TestFillFirstSelectorUsesFirstAvailable adapts CLIProxyAPI's deterministic first-account test.
// TestFillFirstSelectorUsesFirstAvailable 适配 CLIProxyAPI 的确定性首账号测试。
func TestFillFirstSelectorUsesFirstAvailable(t *testing.T) {
	selector := NewSelector()
	for index := 0; index < 3; index++ {
		selected, errSelect := selector.Pick("pvi:model:profile", SelectionOptions{Strategy: providerconfig.RoutingFillFirst}, []Candidate{{ID: "cred_b"}, {ID: "cred_a"}})
		if errSelect != nil || selected.ID != "cred_a" {
			t.Fatalf("Pick() #%d = %q, error = %v", index, selected.ID, errSelect)
		}
	}
}

// TestSelectorUsesPriorityThenSmallestCapacity verifies explicit account preference precedes scarce-capacity conservation.
// TestSelectorUsesPriorityThenSmallestCapacity 验证明示账号偏好先于稀缺容量保护。
func TestSelectorUsesPriorityThenSmallestCapacity(t *testing.T) {
	selector := NewSelector()
	candidates := []Candidate{
		{ID: "cred_low_capacity", Priority: 10, CapacityKnown: true, Capacity: 262144},
		{ID: "cred_preferred_high_capacity", Priority: 1, CapacityKnown: true, Capacity: 1048576},
		{ID: "cred_preferred_low_capacity", Priority: 1, CapacityKnown: true, Capacity: 262144},
	}
	selected, errSelect := selector.Pick("pvi:model:profile", SelectionOptions{Strategy: providerconfig.RoutingFillFirst, PreferSmallestSufficient: true}, candidates)
	if errSelect != nil || selected.ID != "cred_preferred_low_capacity" {
		t.Fatalf("Pick() = %q, error = %v", selected.ID, errSelect)
	}
}

// TestRoundRobinSelectorSeparatesModelKeys verifies one model never advances another model's cursor.
// TestRoundRobinSelectorSeparatesModelKeys 验证一个模型绝不会推进另一个模型的游标。
func TestRoundRobinSelectorSeparatesModelKeys(t *testing.T) {
	selector := NewSelector()
	candidates := []Candidate{{ID: "cred_a"}, {ID: "cred_b"}}
	firstA, _ := selector.Pick("pvi:model_a:profile", SelectionOptions{}, candidates)
	firstB, _ := selector.Pick("pvi:model_b:profile", SelectionOptions{}, candidates)
	secondA, _ := selector.Pick("pvi:model_a:profile", SelectionOptions{}, candidates)
	if firstA.ID != "cred_a" || firstB.ID != "cred_a" || secondA.ID != "cred_b" {
		t.Fatalf("model-scoped picks = %q, %q, %q", firstA.ID, firstB.ID, secondA.ID)
	}
}

// TestRoundRobinSelectorIsConcurrent verifies copied cursor locking never loses or duplicates pool membership.
// TestRoundRobinSelectorIsConcurrent 验证复制的游标锁不会丢失或复制账号池成员。
func TestRoundRobinSelectorIsConcurrent(t *testing.T) {
	selector := NewSelector()
	candidates := []Candidate{{ID: "cred_a"}, {ID: "cred_b"}}
	counts := map[string]int{"cred_a": 0, "cred_b": 0}
	var countsMu sync.Mutex
	var wait sync.WaitGroup
	for index := 0; index < 200; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			selected, errSelect := selector.Pick("pvi:model:profile", SelectionOptions{}, candidates)
			if errSelect != nil {
				t.Errorf("Pick() error = %v", errSelect)
				return
			}
			countsMu.Lock()
			counts[selected.ID]++
			countsMu.Unlock()
		}()
	}
	wait.Wait()
	if counts["cred_a"] != 100 || counts["cred_b"] != 100 {
		t.Fatalf("concurrent counts = %#v", counts)
	}
}

// TestRoundRobinSelectorBoundsCursorKeys verifies CLIProxyAPI's map reset prevents unbounded keys.
// TestRoundRobinSelectorBoundsCursorKeys 验证 CLIProxyAPI 的 Map 重置可以阻止 Key 无界增长。
func TestRoundRobinSelectorBoundsCursorKeys(t *testing.T) {
	selector := &Selector{cursors: make(map[string]int), maxKeys: 2}
	candidates := []Candidate{{ID: "cred_a"}}
	_, _ = selector.Pick("one", SelectionOptions{}, candidates)
	_, _ = selector.Pick("two", SelectionOptions{}, candidates)
	_, _ = selector.Pick("three", SelectionOptions{}, candidates)
	if len(selector.cursors) != 1 {
		t.Fatalf("cursor key count = %d, want 1", len(selector.cursors))
	}
}
