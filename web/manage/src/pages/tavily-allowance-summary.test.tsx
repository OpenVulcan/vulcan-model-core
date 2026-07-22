import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { TranslationKey } from "@/i18n";
import type { ProviderAllowance } from "@/lib/provider-groups";
import { TavilyAllowanceSummary } from "@/pages/provider-management-page";

// tavilyAllowance creates one exact credential-scoped Tavily counter for compact-summary verification.
// tavilyAllowance 创建一个精确的凭据作用域 Tavily 计数器，用于紧凑摘要验证。
function tavilyAllowance(
  metric: string,
  used: string,
  options: Partial<ProviderAllowance> = {},
): ProviderAllowance {
  return {
    credential_id: "cred_tavily",
    kind: "provider_defined",
    scope: "credential",
    metric,
    unit: "provider_credits",
    used,
    status: "unknown_sufficiency",
    mandatory: false,
    observed_at: "2026-07-22T12:00:00Z",
    expires_at: "2026-07-22T12:05:00Z",
    ...options,
  };
}

// tavilyTranslations contains only the labels exercised by the provider-specific compact layout.
// tavilyTranslations 仅包含供应商专属紧凑布局所使用的标签。
const tavilyTranslations: Partial<Record<TranslationKey, string>> = {
  "providers.allowanceMetrics.tavilyPlan": "Plan",
  "providers.allowanceMetrics.tavilyPaygo": "Pay-as-you-go",
  "providers.used": "Used",
};

// translateTavily returns deterministic labels for this isolated component test.
// translateTavily 为此隔离组件测试返回确定性标签。
function translateTavily(key: TranslationKey): string {
  return tavilyTranslations[key] ?? key;
}

describe("TavilyAllowanceSummary", () => {
  // This test verifies compact display keeps dynamic plan consumption while omitting configurable PAYGO and detailed product counters.
  // 此测试验证紧凑展示保留动态套餐消费，同时省略可配置的 PAYGO 与产品详细计数器。
  it("displays only dynamic Tavily plan consumption", () => {
    render(
      <TavilyAllowanceSummary
        summary={{
          accountPlan: tavilyAllowance("tavily.account.plan", "2", {
            kind: "balance",
            limit: "1000",
            remaining: "998",
            remaining_ratio: 0.998,
            status: "available",
          }),
        }}
        t={translateTavily}
      />,
    );

    expect(screen.getByText("Used 2 / 1000")).toBeInTheDocument();
    expect(screen.queryByText("Pay-as-you-go")).not.toBeInTheDocument();
    expect(screen.queryByText(/API key/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Account breakdown/)).not.toBeInTheDocument();
    expect(screen.queryByText("+4")).not.toBeInTheDocument();
  });
});
