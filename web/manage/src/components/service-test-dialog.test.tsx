import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import {
  ServiceTestDialog,
  type ServiceTestTarget,
} from "@/components/service-test-dialog";
import { searchSnippetText } from "@/components/search-service-test-dialog";
import { I18nProvider } from "@/i18n";

// combinedTarget mirrors one Tavily provider exposing both Search and Extract diagnostics.
// combinedTarget 镜像一个同时公开搜索与提取诊断的 Tavily 供应商。
const combinedTarget: ServiceTestTarget = {
  providerName: "Tavily Search API",
  search: {
    ready: true,
    target: {
      providerInstanceID: "pvi_tavily",
      providerName: "Tavily Search API",
      providerServiceID: "service_web_search",
      serviceName: "Tavily Web Search",
      serviceOfferingID: "service_offer_tavily_search",
      executionProfileID: "profile_tavily_search",
      outputMode: "results",
      evidenceRequirement: "verified",
    },
  },
  extract: {
    ready: true,
    target: {
      providerInstanceID: "pvi_tavily",
      providerName: "Tavily Search API",
      providerServiceID: "service_web_extract",
      serviceName: "Tavily Web Extract",
      serviceOfferingID: "service_offer_tavily_extract",
      executionProfileID: "profile_tavily_extract",
      maxURLs: 20,
      depths: ["basic", "advanced"],
      formats: ["markdown", "text"],
      queryRelevance: true,
      minimumChunksPerSource: 1,
      maximumChunksPerSource: 5,
      includeImages: true,
      includeFavicon: true,
      minimumTimeoutSeconds: 1,
      maximumTimeoutSeconds: 60,
    },
  },
};

describe("ServiceTestDialog", () => {
  // This test verifies one generic Test entry exposes both provider capabilities and returns to the selector.
  // 此测试验证一个通用“测试”入口会公开供应商的两种能力并可返回选择器。
  it("selects Search and Extract inside one diagnostic flow", () => {
    const onClose = vi.fn();
    render(
      <I18nProvider>
        <ServiceTestDialog
          managementAuthToken="management-token"
          target={combinedTarget}
          onClose={onClose}
        />
      </I18nProvider>,
    );

    const serviceHeading = screen.getByRole("heading", {
      name: "Service test",
    });
    expect(serviceHeading).toBeInTheDocument();
    expect(serviceHeading.parentElement).toHaveClass("grid");
    expect(screen.queryByRole("button", { name: "Cancel" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Close test" })).toHaveClass(
      "text-destructive",
    );
    const searchOption = screen.getByRole("button", { name: /Search/ });
    const extractOption = screen.getByRole("button", { name: /Extract/ });
    expect(searchOption).toBeEnabled();
    expect(searchOption).toHaveClass("h-12", "w-full", "justify-between");
    expect(extractOption).toBeEnabled();
    expect(extractOption).toHaveClass("h-12", "w-full", "justify-between");

    fireEvent.click(extractOption);
    expect(
      screen.getByRole("heading", { name: "Content extraction test" }),
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Close test" }));

    expect(
      screen.getByRole("heading", { name: "Service test" }),
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Search/ }));
    expect(
      screen.getByRole("heading", { name: "Search test" }),
    ).toBeInTheDocument();
    expect(screen.getByRole("textbox").tagName).toBe("INPUT");
    expect(screen.getByRole("dialog")).toHaveClass("overflow-hidden");
    expect(screen.queryByRole("button", { name: "Cancel" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Close test" })).toHaveClass(
      "text-destructive",
    );
    expect(onClose).not.toHaveBeenCalled();
  });

  // This test verifies provider HTML fragments become compact plain text before result rendering.
  // 此测试验证供应商 HTML 片段在结果渲染前转换为紧凑纯文本。
  it("normalizes provider result snippets", () => {
    expect(
      searchSnippetText("<p>First&nbsp;part</p><p>Second part</p>"),
    ).toBe("First partSecond part");
  });
});
