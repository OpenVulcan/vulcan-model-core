import { createElement } from "react";
import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ProviderIcon, resolveProviderIconKey } from "@/lib/provider-icons";

// The provider icon library prioritizes exact product artwork over its provider-family default.
// 供应商图标库优先使用精确产品图标，而不是供应商系列默认图标。
describe("resolveProviderIconKey", () => {
  // Exact product bindings preserve distinct Codex, Vertex, and Antigravity artwork.
  // 精确产品绑定保留不同的 Codex、Vertex 与 Antigravity 图标。
  it("uses exact system product artwork before the family artwork", () => {
    expect(resolveProviderIconKey({ definitionID: "system_openai_codex", groupID: "openai" })).toBe("codex");
    expect(resolveProviderIconKey({ definitionID: "system_google_vertex", groupID: "google" })).toBe("vertex");
    expect(resolveProviderIconKey({ definitionID: "system_google_antigravity", groupID: "google" })).toBe("antigravity");
  });

  // Family bindings cover every current native provider with artwork available in CLIProxyAPI management.html.
  // 系列绑定覆盖当前所有在 CLIProxyAPI management.html 中存在图标的原生供应商。
  it("uses the configured family artwork for native providers", () => {
    expect(resolveProviderIconKey({ groupID: "anthropic" })).toBe("claude");
    expect(resolveProviderIconKey({ groupID: "google" })).toBe("gemini");
    expect(resolveProviderIconKey({ groupID: "xai" })).toBe("grok");
    expect(resolveProviderIconKey({ groupID: "kimi" })).toBe("kimi");
    expect(resolveProviderIconKey({ groupID: "alibaba" })).toBe("qwen");
    expect(resolveProviderIconKey({ groupID: "minimax" })).toBe("minimax");
  });

  // Compatibility services and unknown future providers share CLIProxyAPI's authored compatibility icon.
  // 兼容服务与未知的未来供应商共用 CLIProxyAPI 编写的兼容图标。
  it("falls back to the CLIProxyAPI compatibility artwork", () => {
    expect(resolveProviderIconKey({ groupID: "openrouter" })).toBe("compatibility");
    expect(resolveProviderIconKey({ groupID: "tavily" })).toBe("compatibility");
    expect(resolveProviderIconKey({ definitionID: "custom_operator_owned" })).toBe("compatibility");
    expect(resolveProviderIconKey({ groupID: "future-provider" })).toBe("compatibility");
  });

  // Kimi keeps CLIProxyAPI's framed 26-pixel surface and separate theme artwork instead of stretching the raw SVG.
  // Kimi 保留 CLIProxyAPI 的 26 像素外框与独立主题图标，而不是拉伸原始 SVG。
  it("renders the authored Kimi theme surface", () => {
    // rendered contains the exact decorative provider element used by every management page.
    // rendered 包含每个管理页面使用的精确装饰性供应商元素。
    const rendered = render(createElement(ProviderIcon, { groupID: "kimi" }));
    // icon is the shared framed container rather than either internal SVG image.
    // icon 是共享外框容器，而不是任一内部 SVG 图像。
    const icon = rendered.container.querySelector('[data-provider-icon="kimi"]');
    expect(icon).toHaveClass("size-[26px]", "bg-black", "p-[5px]", "dark:bg-white");
    expect(icon?.querySelectorAll("img")).toHaveLength(2);
  });
});
