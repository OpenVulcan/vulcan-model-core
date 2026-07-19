import { afterEach, describe, expect, it, vi } from "vitest";

import {
  ProviderCredentialRefreshError,
  ProviderMetadataRefreshError,
  refreshProviderCredential,
  refreshProviderMetadata,
  startKimiDeviceFlow,
} from "@/lib/provider-groups";

describe("provider metadata transport", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  // This test verifies malformed provider metadata is never mislabeled as a network outage.
  // 此测试验证格式错误的供应商元数据绝不会被误标为网络故障。
  it("classifies a malformed successful response explicitly", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ provider_instance_id: "instance-1" }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      ),
    );

    await expect(
      refreshProviderMetadata("management-token", "instance-1"),
    ).rejects.toEqual(
      expect.objectContaining<Partial<ProviderMetadataRefreshError>>({
        code: "provider_metadata_invalid_response",
        status: 200,
      }),
    );
  });

  // This test verifies metadata from another provider instance cannot be attached to the requested card.
  // 此测试验证另一个供应商实例的元数据不能挂到当前请求卡片。
  it("rejects a mismatched provider metadata owner", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            provider_instance_id: "instance-other",
            models: [],
            plans: [],
            allowances: [],
            revision: 1,
            observed_at: "2026-07-19T12:00:00Z",
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json" },
          },
        ),
      ),
    );

    await expect(
      refreshProviderMetadata("management-token", "instance-1"),
    ).rejects.toEqual(
      expect.objectContaining<Partial<ProviderMetadataRefreshError>>({
        code: "provider_metadata_invalid_response",
        status: 200,
      }),
    );
  });

  // This test verifies every client-safe allowance window node survives strict response validation.
  // 此测试验证每个客户端安全的额度窗口节点都能通过严格响应校验并完整保留。
  it("preserves validated allowance window semantics", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            provider_instance_id: "instance-1",
            models: [],
            plans: [],
            allowances: [
              {
                kind: "window_quota",
                scope: "credential",
                metric: "monthly_requests",
                unit: "requests",
                remaining: "1.25e2",
                remaining_ratio: 0.5,
                status: "available",
                mandatory: true,
                window: {
                  kind: "calendar",
                  duration: "0",
                  calendar_unit: "month",
                  time_zone: "Asia/Shanghai",
                  reset_at: "2026-08-01T00:00:00+08:00",
                },
                observed_at: "2026-07-19T12:00:00Z",
                expires_at: "2026-07-19T12:10:00Z",
              },
              {
                kind: "window_quota",
                scope: "credential",
                metric: "annual_requests",
                unit: "requests",
                remaining: "42",
                status: "available",
                mandatory: true,
                window: {
                  kind: "rolling",
                  duration: "31536000000000000",
                },
                observed_at: "2026-07-19T12:00:00Z",
                expires_at: "2026-07-19T12:10:00Z",
              },
            ],
            revision: 2,
            observed_at: "2026-07-19T12:00:00Z",
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json" },
          },
        ),
      ),
    );

    // metadata is the exact validated management payload returned to page state.
    // metadata 是返回页面状态的精确已校验管理载荷。
    const metadata = await refreshProviderMetadata(
      "management-token",
      "instance-1",
    );
    expect(metadata.allowances[0]?.window).toEqual({
      kind: "calendar",
      duration: "0",
      calendar_unit: "month",
      time_zone: "Asia/Shanghai",
      reset_at: "2026-08-01T00:00:00+08:00",
    });
    expect(metadata.allowances[0]?.remaining).toBe("1.25e2");
    expect(metadata.allowances[1]?.window?.duration).toBe("31536000000000000");
  });

  // This test verifies non-decimal amount syntax and unknown normalized enum values cannot enter UI state.
  // 此测试验证非十进制数量语法和未知规范化枚举值不能进入 UI 状态。
  it("rejects invalid allowance contracts", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            provider_instance_id: "instance-1",
            models: [],
            plans: [],
            allowances: [
              {
                kind: "credit",
                scope: "credential",
                metric: "credits",
                unit: "provider_credits",
                remaining: "1/2",
                status: "available",
                mandatory: false,
                observed_at: "2026-07-19T12:00:00Z",
                expires_at: "2026-07-19T12:10:00Z",
              },
            ],
            revision: 2,
            observed_at: "2026-07-19T12:00:00Z",
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json" },
          },
        ),
      ),
    );

    await expect(
      refreshProviderMetadata("management-token", "instance-1"),
    ).rejects.toEqual(
      expect.objectContaining<Partial<ProviderMetadataRefreshError>>({
        code: "provider_metadata_invalid_response",
        status: 200,
      }),
    );
  });

  // This test verifies the credential transport preserves only the stable management authentication category.
  // 此测试验证凭据传输层只保留稳定的管理认证分类。
  it("preserves a server-authored credential rejection", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({ error: "provider_authentication_rejected" }),
          {
            status: 424,
            headers: { "Content-Type": "application/json" },
          },
        ),
      ),
    );

    await expect(
      refreshProviderCredential(
        "management-token",
        "instance-1",
        "credential-1",
      ),
    ).rejects.toEqual(
      expect.objectContaining<Partial<ProviderCredentialRefreshError>>({
        code: "provider_authentication_rejected",
        status: 424,
      }),
    );
  });

  // This test verifies malformed successful credential envelopes are not mistaken for connectivity failures.
  // 此测试验证格式错误的凭据成功信封不会被误判为连接故障。
  it("classifies a malformed credential success response explicitly", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({}), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      ),
    );

    await expect(
      refreshProviderCredential(
        "management-token",
        "instance-1",
        "credential-1",
      ),
    ).rejects.toEqual(
      expect.objectContaining<Partial<ProviderCredentialRefreshError>>({
        code: "provider_authentication_invalid_response",
        status: 200,
      }),
    );
  });

  // This test verifies a successful refresh response must identify the exact credential requested by the administrator.
  // 此测试验证成功刷新响应必须标识管理员请求的精确凭据。
  it("rejects a mismatched refreshed credential identity", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ id: "credential-other" }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      ),
    );

    await expect(
      refreshProviderCredential(
        "management-token",
        "instance-1",
        "credential-1",
      ),
    ).rejects.toEqual(
      expect.objectContaining<Partial<ProviderCredentialRefreshError>>({
        code: "provider_authentication_invalid_response",
        status: 200,
      }),
    );
  });
});

describe("provider authorization transport", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  // This test verifies provider-controlled device links cannot inject a non-HTTP browser scheme.
  // 此测试验证供应商控制的设备链接不能注入非 HTTP 浏览器 Scheme。
  it("rejects a non-HTTP device verification URL", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            id: "flow-unsafe",
            user_code: "ABCD-EFGH",
            verification_uri: "javascript:alert(1)",
            verification_uri_complete: "",
            expires_at: "2026-07-19T12:10:00Z",
            poll_interval_seconds: 5,
          }),
          {
            status: 201,
            headers: { "Content-Type": "application/json" },
          },
        ),
      ),
    );

    await expect(startKimiDeviceFlow("management-token")).rejects.toThrow();
  });
});
