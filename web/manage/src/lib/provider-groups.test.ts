import { afterEach, describe, expect, it, vi } from "vitest";

import {
  ProviderCredentialRefreshError,
  ProviderMetadataRefreshError,
  fetchProviderFiles,
  parseAdditionalPayloadProjectionJSON,
  parseRequestProjectionJSON,
  refreshProviderCredential,
  refreshProviderMetadata,
  startKimiDeviceFlow,
  updateProviderEndpoint,
} from "@/lib/provider-groups";

describe("custom request projection validation", () => {
  // This test verifies provider-wide non-reasoning rules use the same protected-path boundary.
  // 此测试验证供应商级非推理规则使用相同的受保护路径边界。
  it("validates provider-wide additional parameters independently", () => {
    const projection = parseAdditionalPayloadProjectionJSON(JSON.stringify({
      default: [{ path: "temperature", value: 0.7 }],
      override: [{ path: "provider_options.route", value: "fast" }],
      filter: ["unsupported_parameter"],
    }));
    expect(projection.override?.[0].value).toBe("fast");
    expect(() => parseAdditionalPayloadProjectionJSON(JSON.stringify({ override: [{ path: "model", value: "other" }] }))).toThrow(/protocol or authentication boundary/);
  });

  // This test verifies a composite DeepSeek-style reasoning rule remains configurable.
  // 此测试验证 DeepSeek 风格的组合推理规则保持可配置。
  it("accepts one effort that controls multiple upstream fields", () => {
    const projection = parseRequestProjectionJSON(JSON.stringify({
      reasoning: {
        effort: [{
          value: "high",
          set: [
            { path: "thinking.type", value: "enabled" },
            { path: "reasoning_effort", value: "high" },
          ],
        }],
      },
      additional: {},
    }), "openai.chat");
    expect(projection.reasoning.effort).toHaveLength(1);
  });

  // This test verifies additional request parameters remain valid without reasoning rules.
  // 此测试验证没有推理规则时额外请求参数仍然有效。
  it("accepts additional parameters for a non-reasoning model", () => {
    const projection = parseRequestProjectionJSON(JSON.stringify({
      reasoning: {},
      additional: { override: [{ path: "temperature", value: 0.2 }] },
    }), "openai.chat");
    expect(projection.additional.override?.[0].value).toBe(0.2);
  });

  // This test verifies OpenRouter nested effort cannot coexist with the Chat shorthand emitted by typed projection.
  // 此测试验证 OpenRouter 嵌套强度不能与类型化投影生成的 Chat 简写同时存在。
  it("requires deleting the Chat shorthand when nested effort is configured", () => {
    expect(() => parseRequestProjectionJSON(JSON.stringify({
      reasoning: { effort: [{ value: "high", set: [{ path: "reasoning.effort", value: "high" }] }] },
      additional: {},
    }), "openai.chat")).toThrow(/delete reasoning_effort/);
  });

  // This test verifies advanced parameters cannot replace model identity or prompt content.
  // 此测试验证高级参数不能替换模型身份或提示内容。
  it("rejects protocol-owned paths", () => {
    expect(() => parseRequestProjectionJSON(JSON.stringify({
      reasoning: { effort: [{ value: "high", set: [{ path: "model", value: "other" }] }] },
      additional: {},
    }), "openai.chat")).toThrow(/protocol or authentication boundary/);
  });
});

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
                metric: "minimax.general.weekly",
                unit: "requests",
                status: "unlimited",
                mandatory: false,
                window: {
                  kind: "calendar",
                  duration: "0",
                  calendar_unit: "week",
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
    // annualAllowance selects the exact rolling-window fixture independently of array insertion order.
    // annualAllowance 独立于数组插入顺序选择精确的滚动窗口夹具。
    const annualAllowance = metadata.allowances.find(
      (allowance) => allowance.metric === "annual_requests",
    );
    // unlimitedAllowance selects the explicit canonical unlimited-state fixture.
    // unlimitedAllowance 选择明确的规范无限状态夹具。
    const unlimitedAllowance = metadata.allowances.find(
      (allowance) => allowance.metric === "minimax.general.weekly",
    );
    expect(annualAllowance?.window?.duration).toBe("31536000000000000");
    expect(unlimitedAllowance?.status).toBe("unlimited");
  });

  // This test verifies the one proven legacy null representation for an empty MiniMax voice description list is normalized at the Web boundary.
  // 此测试验证 MiniMax 空声音说明列表唯一已证实的旧版 null 表示会在 Web 边界被规范化。
  it("normalizes legacy empty MiniMax voice descriptions", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            provider_instance_id: "instance-1",
            models: [],
            plans: [],
            allowances: [],
            voices: [
              {
                voice_id: "voice-empty-description",
                display_name: "Voice",
                descriptions: null,
                credential_id: "credential-1",
                credential_label: "MiniMax",
                observed_at: "2026-07-22T01:00:00Z",
                expires_at: "2026-07-22T01:30:00Z",
              },
            ],
            revision: 2,
            observed_at: "2026-07-22T01:00:00Z",
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json" },
          },
        ),
      ),
    );

    // metadata is the normalized catalog returned to the provider management page.
    // metadata 是返回供应商管理页面的规范化目录。
    const metadata = await refreshProviderMetadata(
      "management-token",
      "instance-1",
    );
    expect(metadata.voices[0]?.descriptions).toEqual([]);
  });

  // This test verifies the protected file list stays scoped to the requested instance, endpoint, and credential.
  // 此测试验证受保护的文件列表始终限定在所请求的实例、端点和凭据范围内。
  it("loads credential-scoped provider file metadata", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          files: [
            {
              file_id: "minimax-file-1",
              filename: "reference.png",
              purpose: "vision",
              size_bytes: 2048,
              created_at: "2026-07-22T03:00:00Z",
              download_available: true,
            },
          ],
        }),
        {
          status: 200,
          headers: { "Content-Type": "application/json" },
        },
      ),
    );
    vi.stubGlobal("fetch", fetchMock);

    const files = await fetchProviderFiles(
      "management-token",
      "pvi_minimax",
      "endpoint_minimax",
      "credential_minimax",
    );

    expect(files).toEqual([
      {
        file_id: "minimax-file-1",
        filename: "reference.png",
        purpose: "vision",
        size_bytes: 2048,
        created_at: "2026-07-22T03:00:00Z",
        download_available: true,
      },
    ]);
    expect(fetchMock).toHaveBeenCalledWith(
      "/vulcan/manage/provider-instances/pvi_minimax/credentials/credential_minimax/files?endpoint_id=endpoint_minimax",
      expect.objectContaining({
        method: "GET",
        headers: { Authorization: "Bearer management-token" },
      }),
    );
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

describe("provider settings transport", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  // This test verifies editing a custom provider API sends the complete retained endpoint contract.
  // 此测试验证编辑自定义供应商 API 时发送完整的保留入口合同。
  it("updates the provider API base URL", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ id: "ep_custom" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await updateProviderEndpoint("management-token", "pvi_custom", {
      id: "ep_custom",
      base_url: "https://api.example.com/v1",
      region: "global",
      status: "ready",
    });

    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/vulcan/manage/provider-instances/pvi_custom/endpoints/ep_custom");
    expect(init.method).toBe("PUT");
    expect(JSON.parse(String(init.body))).toEqual({
      base_url: "https://api.example.com/v1",
      region: "global",
      status: "ready",
    });
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
