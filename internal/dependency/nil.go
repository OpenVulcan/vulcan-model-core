// Package dependency validates constructor dependencies before extension-owned interface methods are invoked.
// dependency 包在调用扩展所有的接口方法前校验构造器依赖。
package dependency

import "reflect"

// IsNil reports whether a dependency is nil or contains a typed nil reference value.
// IsNil 返回依赖是否为 nil 或包含带类型的 nil 引用值。
func IsNil(dependency any) bool {
	if dependency == nil {
		return true
	}
	// value exposes the dynamic kind required to inspect every nil-capable reference representation.
	// value 暴露检查全部可为 nil 的引用表示所需的动态类型。
	value := reflect.ValueOf(dependency)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice, reflect.UnsafePointer:
		return value.IsNil()
	default:
		return false
	}
}
