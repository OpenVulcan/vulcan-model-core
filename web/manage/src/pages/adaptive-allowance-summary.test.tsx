import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { TranslationKey } from "@/i18n";
import type { ProviderAllowance } from "@/lib/provider-groups";
import {
  AdaptiveAllowanceSummary,
  AdaptiveBalanceSummary,
} from "@/pages/provider-management-page";

// deepSeekBalance creates one exact credential-scoped DeepSeek balance observation.
// deepSeekBalance 创建一个精确凭据作用域的 DeepSeek 余额观测。
function deepSeekBalance(
  metric: string,
  remaining: string,
): ProviderAllowance {
  return {
    credential_id: "cred_deepseek",
    kind: "balance",
    scope: "credential",
    metric,
    unit: "minor_currency_units",
    currency: "CNY",
    remaining,
    status: "available",
    mandatory: false,
    observed_at: "2026-07-24T08:00:00Z",
    expires_at: "2026-07-24T08:05:00Z",
  };
}

// allowanceTranslations contains the deterministic labels exercised by adaptive balance rendering.
// allowanceTranslations 包含自适应余额渲染所使用的确定性标签。
const allowanceTranslations: Partial<Record<TranslationKey, string>> = {
  "providers.allowanceMetrics.deepseekTotal": "Available balance",
  "providers.allowanceMetrics.deepseekGranted": "Granted balance",
  "providers.sharedUsage": "Shared",
  "providers.unlimited": "Unlimited",
  "providers.unknownAmount": "Unknown",
};

// translateAllowance returns deterministic labels for isolated adaptive-panel tests.
// translateAllowance 为隔离的自适应面板测试返回确定性标签。
function translateAllowance(key: TranslationKey): string {
  return allowanceTranslations[key] ?? key;
}

describe("adaptive allowance summary", () => {
  // This test verifies DeepSeek balance is excluded from usage and rendered only in the independent balance field.
  // 此测试验证 DeepSeek 余额从用量中排除，并且只在独立余额字段中渲染。
  it("separates DeepSeek balance from usage", () => {
    const allowances = [
      deepSeekBalance("deepseek.balance.total", "39861"),
      deepSeekBalance("deepseek.balance.granted", "19861"),
    ];
    const usageView = render(
      <AdaptiveAllowanceSummary
        allowances={allowances}
        credentialID="cred_deepseek"
        includeSharedAllowances
        t={translateAllowance}
      />,
    );
    expect(screen.getByText("providers.noUsage")).toBeInTheDocument();
    expect(screen.queryByText(/398\.61/)).not.toBeInTheDocument();
    usageView.unmount();

    render(
      <AdaptiveBalanceSummary
        allowances={allowances}
        credentialID="cred_deepseek"
        includeSharedAllowances
        t={translateAllowance}
      />,
    );

    const balanceValue = screen.getByText(/398\.61/);
    expect(balanceValue.parentElement).toHaveClass("text-sm", "leading-5");
    expect(screen.queryByText("Available balance")).not.toBeInTheDocument();
    expect(screen.queryByText("Granted balance")).not.toBeInTheDocument();
    expect(screen.queryByText("+1")).not.toBeInTheDocument();
  });

  // This test verifies providers without a proven balance reader render the explicit unsupported placeholder.
  // 此测试验证没有已证实余额读取器的供应商渲染明确的不支持占位符。
  it("renders a double dash when no balance is available", () => {
    render(
      <AdaptiveBalanceSummary
        allowances={[]}
        credentialID="cred_api"
        includeSharedAllowances
        t={translateAllowance}
      />,
    );
    expect(screen.getByText("--")).toBeInTheDocument();
  });
});
