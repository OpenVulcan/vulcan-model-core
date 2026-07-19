// This setup extends Vitest assertions for React DOM page checks.
// 此初始化为 React DOM 页面检查扩展 Vitest 断言。
import "@testing-library/jest-dom/vitest"
import { cleanup } from "@testing-library/react"
import { afterEach } from "vitest"

// clearRenderedPage removes each test's DOM tree before the next authentication or sidebar assertion.
// clearRenderedPage 会在下一项认证或侧栏断言前移除每项测试的 DOM 树。
afterEach(() => {
  cleanup()
})

// createMediaQueryList supplies the responsive listener contract required by the sidebar in jsdom.
// createMediaQueryList 在 jsdom 中提供侧栏所需的响应式监听器约定。
function createMediaQueryList(query: string): MediaQueryList {
  return {
    matches: false,
    media: query,
    onchange: null,
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
    addListener: () => undefined,
    removeListener: () => undefined,
    dispatchEvent: () => false,
  }
}

// matchMedia is installed before component tests because jsdom does not implement it.
// matchMedia 会在组件测试前安装，因为 jsdom 未实现该浏览器 API。
Object.defineProperty(window, "matchMedia", {
  writable: true,
  value: createMediaQueryList,
})
