import { afterEach, describe, expect, it } from "vitest"
import { fireEvent, render, screen } from "@testing-library/react"

import { LanguageToggle } from "@/components/language-toggle"
import { SiteHeader } from "@/components/site-header"
import { SidebarProvider } from "@/components/ui/sidebar"
import {
  detectBrowserLocale,
  I18nProvider,
  isChineseLanguageTag,
} from "@/i18n"

// originalBrowserLanguage preserves the jsdom language value after each browser-language test.
// originalBrowserLanguage 在每个浏览器语言测试后保留 jsdom 原始语言值。
const originalBrowserLanguage = navigator.language

// setBrowserLanguage updates the browser-language value used by the locale detector during a test.
// setBrowserLanguage 更新测试期间语言检测器使用的浏览器语言值。
// languageTag is the complete browser language tag to expose.
// languageTag 是要暴露的完整浏览器语言标签。
function setBrowserLanguage(languageTag: string) {
  Object.defineProperty(navigator, "language", {
    configurable: true,
    value: languageTag,
  })
}

// i18n suite verifies Chinese tag normalization and the only manual two-language toggle.
// i18n 测试套件验证中文标签归一化与唯一的手动双语切换。
describe("i18n", () => {
  // restoreBrowserLanguage keeps every test independent from a previous language override.
  // restoreBrowserLanguage 使每个测试都不受先前语言覆盖的影响。
  afterEach(() => {
    setBrowserLanguage(originalBrowserLanguage)
  })

  // Chinese browser language test treats simplified and traditional Chinese tags as simplified Chinese content.
  // 中文浏览器语言测试会将简体和繁体中文标签统一视为简体中文内容。
  it("uses simplified Chinese for every Chinese browser language tag", () => {
    // chineseLanguageTags enumerates representative simplified, traditional, and generic Chinese browser tags.
    // chineseLanguageTags 枚举有代表性的简体、繁体及通用中文浏览器标签。
    const chineseLanguageTags = ["zh-CN", "zh-Hans", "zh-TW", "zh-Hant-TW", "zh"]

    for (const languageTag of chineseLanguageTags) {
      setBrowserLanguage(languageTag)
      expect(isChineseLanguageTag(languageTag)).toBe(true)
      expect(detectBrowserLocale()).toBe("zh")
    }

    setBrowserLanguage("en-US")
    expect(isChineseLanguageTag("en-US")).toBe(false)
    expect(detectBrowserLocale()).toBe("en")
  })

  // Manual language toggle test confirms the document language and accessible action change together.
  // 手动语言切换测试确认文档语言和可访问操作会一起变化。
  it("switches the management page between English and simplified Chinese", () => {
    setBrowserLanguage("en-US")

    render(
      <I18nProvider>
        <LanguageToggle />
      </I18nProvider>,
    )

    fireEvent.click(
      screen.getByRole("button", { name: "Switch to Chinese" }),
    )

    expect(document.documentElement).toHaveAttribute("lang", "zh-CN")
    expect(
      screen.getByRole("button", { name: "切换到英文" }),
    ).toBeInTheDocument()
  })

  // Dashboard language control test verifies the homepage header exposes the same top-right manual toggle.
  // 仪表盘语言控件测试验证主页页头提供相同的右上角手动切换。
  it("places the manual language control in the router overview header", () => {
    setBrowserLanguage("en-US")

    render(
      <I18nProvider>
        <SidebarProvider>
          <SiteHeader />
        </SidebarProvider>
      </I18nProvider>,
    )

    expect(
      screen.getByRole("heading", { name: "Model Router overview" }),
    ).toBeInTheDocument()
    fireEvent.click(
      screen.getByRole("button", { name: "Switch to Chinese" }),
    )
    expect(
      screen.getByRole("heading", { name: "模型路由概览" }),
    ).toBeInTheDocument()
  })
})
