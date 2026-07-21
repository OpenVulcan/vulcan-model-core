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

// createTestStorage supplies deterministic browser storage when the active Node runtime reserves an unavailable global implementation.
// createTestStorage 在当前 Node 运行时保留不可用全局实现时提供确定性的浏览器存储。
function createTestStorage(): Storage {
  // values owns exact string keys and values for one isolated Vitest worker.
  // values 为一个隔离 Vitest Worker 保存精确字符串键值。
  const values = new Map<string, string>()
  return {
    get length() {
      return values.size
    },
    clear: () => values.clear(),
    getItem: (key) => values.get(key) ?? null,
    key: (index) => Array.from(values.keys())[index] ?? null,
    removeItem: (key) => {
      values.delete(key)
    },
    setItem: (key, value) => {
      values.set(key, String(value))
    },
  }
}

// localStorage is installed explicitly because Node 26 may expose an unavailable experimental global ahead of jsdom.
// localStorage 被显式安装，因为 Node 26 可能在 jsdom 之前暴露一个不可用的实验性全局对象。
Object.defineProperty(window, "localStorage", {
  configurable: true,
  value: createTestStorage(),
})
