package dependency

import "testing"

// TestIsNilCoversTypedReferenceValues verifies constructor guards reject every nil-capable dynamic representation.
// TestIsNilCoversTypedReferenceValues 验证构造器守卫会拒绝全部可为 nil 的动态表示。
func TestIsNilCoversTypedReferenceValues(t *testing.T) {
	var pointer *int
	var mapping map[string]string
	var values []string
	var channel chan struct{}
	var callback func()
	testCases := []struct {
		// name identifies the dynamic representation under test.
		// name 标识待测试的动态表示。
		name string
		// dependency is the boxed constructor input.
		// dependency 是装箱后的构造器输入。
		dependency any
		// want is the expected nil result.
		// want 是预期的 nil 判定结果。
		want bool
	}{
		{name: "nil interface", dependency: nil, want: true},
		{name: "typed pointer", dependency: pointer, want: true},
		{name: "typed map", dependency: mapping, want: true},
		{name: "typed slice", dependency: values, want: true},
		{name: "typed channel", dependency: channel, want: true},
		{name: "typed function", dependency: callback, want: true},
		{name: "concrete value", dependency: 1},
		{name: "non-nil pointer", dependency: new(int)},
		{name: "non-nil map", dependency: map[string]string{}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := IsNil(testCase.dependency); got != testCase.want {
				t.Fatalf("IsNil() = %t, want %t", got, testCase.want)
			}
		})
	}
}
