import { type ReactElement } from "react";

import antigravityIcon from "@/assets/provider-antigravity.svg";
import claudeIcon from "@/assets/provider-claude.svg";
import codexIcon from "@/assets/provider-codex.svg";
import deepSeekIcon from "@/assets/provider-deepseek.svg";
import geminiIcon from "@/assets/provider-gemini.svg";
import grokDarkIcon from "@/assets/provider-grok-dark.svg";
import grokLightIcon from "@/assets/provider-grok-light.svg";
import kimiDarkIcon from "@/assets/provider-kimi-dark.svg";
import kimiLightIcon from "@/assets/provider-kimi-light.svg";
import miniMaxIcon from "@/assets/provider-minimax.svg";
import openAICompatibilityDarkIcon from "@/assets/provider-openai-compat-dark.svg";
import openAICompatibilityLightIcon from "@/assets/provider-openai-compat-light.svg";
import qwenIcon from "@/assets/provider-qwen.svg";
import vertexIcon from "@/assets/provider-vertex.svg";
import zhipuIcon from "@/assets/provider-zhipu.svg";
import { cn } from "@/lib/utils";

// ProviderIconKey is the closed set of CLIProxyAPI provider artwork retained by the management frontend.
// ProviderIconKey 是管理前端保留的 CLIProxyAPI 供应商图标闭集。
export type ProviderIconKey =
  | "antigravity"
  | "claude"
  | "codex"
  | "compatibility"
  | "deepseek"
  | "gemini"
  | "grok"
  | "kimi"
  | "minimax"
  | "qwen"
  | "vertex"
  | "zhipu";

// ProviderIconAsset stores one light asset and an optional dark-theme counterpart copied from CLIProxyAPI management.html.
// ProviderIconAsset 保存从 CLIProxyAPI management.html 复制的亮色资源与可选暗色资源。
interface ProviderIconAsset {
  // light is rendered in the default theme.
  // light 在默认主题中渲染。
  light: string;
  // dark replaces the light asset only when CLIProxyAPI defines an explicit dark variant.
  // dark 仅在 CLIProxyAPI 定义明确暗色变体时替换亮色资源。
  dark?: string;
  // themeSurface reproduces CLIProxyAPI's framed provider treatment instead of stretching the raw SVG.
  // themeSurface 复刻 CLIProxyAPI 的供应商外框处理，而不是拉伸原始 SVG。
  themeSurface?: boolean;
  // transparent removes the standard tertiary icon tile used by CLIProxyAPI.
  // transparent 移除 CLIProxyAPI 使用的标准第三级图标底板。
  transparent?: boolean;
}

// providerIconLibrary is the frontend-owned artwork library extracted from CLIProxyAPI management.html.
// providerIconLibrary 是从 CLIProxyAPI management.html 提取且由前端拥有的图标库。
const providerIconLibrary: Readonly<Record<ProviderIconKey, ProviderIconAsset>> = {
  antigravity: { light: antigravityIcon },
  claude: { light: claudeIcon },
  codex: { light: codexIcon },
  compatibility: { light: openAICompatibilityLightIcon, dark: openAICompatibilityDarkIcon, transparent: true },
  deepseek: { light: deepSeekIcon },
  gemini: { light: geminiIcon },
  grok: { light: grokLightIcon, dark: grokDarkIcon, transparent: true },
  kimi: { light: kimiLightIcon, dark: kimiDarkIcon, themeSurface: true, transparent: true },
  minimax: { light: miniMaxIcon },
  qwen: { light: qwenIcon },
  vertex: { light: vertexIcon },
  zhipu: { light: zhipuIcon },
};

// providerGroupIconMap binds stable provider-family identifiers to their corresponding CLIProxyAPI artwork.
// providerGroupIconMap 将稳定供应商系列标识绑定到对应的 CLIProxyAPI 图标。
const providerGroupIconMap: Readonly<Record<string, ProviderIconKey>> = {
  alibaba: "qwen",
  anthropic: "claude",
  claude: "claude",
  deepseek: "deepseek",
  glm: "zhipu",
  google: "gemini",
  kimi: "kimi",
  minimax: "minimax",
  openai: "compatibility",
  openrouter: "compatibility",
  qwen: "qwen",
  tavily: "compatibility",
  xai: "grok",
  zhipu: "zhipu",
};

// providerDefinitionIconMap overrides a family icon only when one exact system product has distinct CLIProxyAPI artwork.
// providerDefinitionIconMap 仅在某个精确系统产品具有独立 CLIProxyAPI 图标时覆盖系列图标。
const providerDefinitionIconMap: Readonly<Record<string, ProviderIconKey>> = {
  system_google_ai_studio: "gemini",
  system_google_antigravity: "antigravity",
  system_google_interactions: "gemini",
  system_google_vertex: "vertex",
  system_openai_codex: "codex",
  system_openai_codex_api_key: "codex",
};

// ProviderIconIdentity contains the stable frontend lookup keys supplied by provider management responses.
// ProviderIconIdentity 包含供应商管理响应提供的稳定前端查询键。
export interface ProviderIconIdentity {
  // definitionID identifies one exact provider product when available.
  // definitionID 在可用时标识一个精确供应商产品。
  definitionID?: string;
  // groupID identifies the provider family when available.
  // groupID 在可用时标识供应商系列。
  groupID?: string;
}

// resolveProviderIconKey selects an exact product icon, then a family icon, and finally CLIProxyAPI's compatibility icon.
// resolveProviderIconKey 依次选择精确产品图标、系列图标，最后回退到 CLIProxyAPI 兼容图标。
export function resolveProviderIconKey({
  definitionID,
  groupID,
}: ProviderIconIdentity): ProviderIconKey {
  if (definitionID && providerDefinitionIconMap[definitionID]) {
    return providerDefinitionIconMap[definitionID];
  }
  if (groupID && providerGroupIconMap[groupID]) {
    return providerGroupIconMap[groupID];
  }
  return "compatibility";
}

// ProviderIconProps configures one decorative provider logo without moving provider identity into backend data.
// ProviderIconProps 配置一个装饰性供应商 Logo，且不把供应商图标身份移入后端数据。
interface ProviderIconProps extends ProviderIconIdentity {
  // className controls the square display box used by the caller.
  // className 控制调用方使用的方形显示框。
  className?: string;
}

// ProviderIcon renders the resolved CLIProxyAPI artwork and preserves its authored light and dark variants.
// ProviderIcon 渲染解析后的 CLIProxyAPI 图标并保留其原始亮色与暗色变体。
export function ProviderIcon({
  definitionID,
  groupID,
  className,
}: ProviderIconProps): ReactElement {
  // iconKey is resolved only from server-authored stable identifiers.
  // iconKey 仅从服务端编写的稳定标识解析。
  const iconKey = resolveProviderIconKey({ definitionID, groupID });
  // asset is the complete theme-aware artwork entry for the resolved provider.
  // asset 是已解析供应商的完整主题感知图标项。
  const asset = providerIconLibrary[iconKey];

  return (
    <span
      aria-hidden="true"
      data-provider-icon={iconKey}
      className={cn(
        "inline-flex size-[26px] shrink-0 items-center justify-center rounded-md bg-muted p-0.5",
        asset.transparent ? "bg-transparent" : "",
        asset.themeSurface ? "box-border rounded-md bg-black p-[5px] dark:bg-white" : "",
        className,
      )}
    >
      <img
        src={asset.light}
        alt=""
        draggable={false}
        className={cn("size-full object-contain", asset.dark ? "dark:hidden" : "")}
      />
      {asset.dark ? (
        <img
          src={asset.dark}
          alt=""
          draggable={false}
          className="hidden size-full object-contain dark:block"
        />
      ) : null}
    </span>
  );
}
