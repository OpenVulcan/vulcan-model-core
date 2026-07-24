import { afterEach, describe, expect, it, vi } from "vitest";

import {
  capabilityLevelSchema,
  formatKnownLimit,
  isCatalogRateLimitExpired,
  modelCapabilitiesSchema,
  modelCatalogSchema,
  selectProfileRateLimits,
  testExtractService,
  testSearchService,
} from "@/lib/model-capabilities";

// createCapabilitiesFixture returns one complete capability contract with explicit unknown and conditional facts.
// createCapabilitiesFixture 返回一个包含明确未知与条件事实的完整能力合同。
function createCapabilitiesFixture() {
  return {
    context_window: { known: true, value: 128000 },
    max_input_tokens: { known: false },
    max_output_tokens: { known: true, value: 8192 },
    max_reasoning_tokens: { known: false },
    recommended_output_tokens: { known: true, value: 4096 },
    recommended_reasoning_tokens: { known: false },
    tool_calling: "native",
    parallel_tool_calls: "conditional",
    streaming_tool_arguments: "emulated",
    strict_json_schema: "unsupported",
    reasoning: "unknown",
    input_modalities: ["text", "image"],
    output_modalities: ["text"],
    delivery: {
      synchronous: true,
      streaming: true,
      asynchronous: false,
      polling: false,
      cancellation: false,
      partial_results: false,
    },
    media_inputs: [
      {
        kind: "image",
        level: "conditional",
        client_workflows: ["resource_ref"],
        evidence: [
          {
            source: "official_docs",
            reference: "fixture",
            observed_at: "2026-07-20T00:00:00Z",
            revision: 1,
          },
        ],
        evidence_revision: 1,
      },
    ],
    media_outputs: [],
    parameters: [],
    parameter_rules: [],
    usage_metrics: [{ unit: "input_tokens", accuracy: "exact" }],
    standard_tools: [{ kind: "web_search", native: true, requires: [] }],
    extra_tools: [{
      id: "code_interpreter",
      display_name: "Code Interpreter",
      description: "Executes provider-hosted code.",
      input_modalities: ["text"],
      output_modalities: ["text", "file"],
      requires_standard: [],
      requires_extra: [],
    }],
    hosted_tools: ["native_web_search"],
  } as const;
}

describe("model capability schema", () => {
  it("preserves conditional and unknown capability facts", () => {
    const parsed = modelCapabilitiesSchema.parse(createCapabilitiesFixture());
    expect(parsed.parallel_tool_calls).toBe("conditional");
    expect(parsed.reasoning).toBe("unknown");
    expect(parsed.max_input_tokens).toEqual({ known: false });
    expect(parsed.media_inputs[0]?.level).toBe("conditional");
    expect(parsed.standard_tools[0]?.kind).toBe("web_search");
    expect(parsed.extra_tools[0]?.id).toBe("code_interpreter");
    expect(parsed.hosted_tools).toEqual(["native_web_search"]);
  });

  it("rejects contradictory known-limit objects", () => {
    expect(() =>
      modelCapabilitiesSchema.parse({
        ...createCapabilitiesFixture(),
        max_input_tokens: { known: false, value: 1000 },
      }),
    ).toThrow();
    expect(formatKnownLimit({ known: false }, "Unknown")).toBe("Unknown");
  });

  it("rejects unrecognized support levels", () => {
    expect(() => capabilityLevelSchema.parse("assumed")).toThrow();
  });

  it("rejects caller-owned tool kinds in the legacy hosted-tool compatibility field", () => {
    expect(() =>
      modelCapabilitiesSchema.parse({
        ...createCapabilitiesFixture(),
        hosted_tools: ["function"],
      }),
    ).toThrow();
    expect(() =>
      modelCapabilitiesSchema.parse({
        ...createCapabilitiesFixture(),
        hosted_tools: ["custom"],
      }),
    ).toThrow();
  });

  // This test reproduces current Go DTO omission, nil-slice, embedding, rerank, and pool encodings.
  // 此测试复现当前 Go DTO 的省略字段、nil Slice、Embedding、Rerank 与 Pool 编码。
  it("parses and normalizes the current catalog DTO", () => {
    // baseCapabilities contains the exact fields shared by every current model capability response.
    // baseCapabilities 包含当前每个模型能力响应共用的精确字段。
    const baseCapabilities = {
      context_window: { known: false },
      max_input_tokens: { known: false },
      max_output_tokens: { known: false },
      max_reasoning_tokens: { known: false },
      recommended_output_tokens: { known: false },
      recommended_reasoning_tokens: { known: false },
      tool_calling: "unsupported",
      parallel_tool_calls: "unsupported",
      streaming_tool_arguments: "unsupported",
      strict_json_schema: "unsupported",
      reasoning: "unsupported",
      input_modalities: null,
      output_modalities: null,
      delivery: {
        synchronous: true,
        streaming: false,
        asynchronous: false,
        polling: false,
        cancellation: false,
        partial_results: false,
      },
    };
    const parsed = modelCatalogSchema.parse({
      provider_instance_id: "pvi_capabilities",
      models: [
        {
          id: "model_capabilities",
          upstream_model_id: "model-capabilities",
          display_name: "Capability Model",
          entitlement_mode: "all_bound_credentials",
          enabled: true,
          authorization_status: "authorized",
          offerings: [
            {
              id: "offering_capabilities",
              upstream_model_id: "model-capabilities",
              profiles: [
                {
                  id: "profile_embedding",
                  display_name: "Embedding",
                  default: true,
                  operation: "embedding.create",
                  action_binding_id: "action_embedding",
                  capabilities: {
                    ...baseCapabilities,
                    embedding: {
                      input_tasks: ["provider_default", "query", "document"],
                      output_kinds: ["dense", "sparse"],
                      encodings: ["float"],
                      dimensions: null,
                      default_dimensions: { known: false, value: 0 },
                      min_dimensions: { known: false, value: 0 },
                      max_dimensions: { known: false, value: 0 },
                      max_batch_items: { known: true, value: 10 },
                      resource_kinds: null,
                      normalized: { known: false, value: false },
                    },
                  },
                  pool: {
                    configured_credentials: 1,
                    entitled_credentials: 1,
                    ready_credentials: 1,
                    cooling_credentials: 0,
                    exhausted_credentials: 0,
                    invalid_credentials: 0,
                    blocking_allowance_kinds: null,
                  },
                },
                {
                  id: "profile_rerank",
                  display_name: "Rerank",
                  default: false,
                  operation: "rerank.documents",
                  action_binding_id: "action_rerank",
                  capabilities: {
                    ...baseCapabilities,
                    rerank: {
                      max_candidates: { known: true, value: 100 },
                      truncation_policies: null,
                      query_resource_kinds: null,
                      candidate_resource_kinds: null,
                      return_content: true,
                      score_semantics: "provider_relevance",
                    },
                  },
                },
                {
                  id: "profile_legacy_conversation",
                  display_name: "Legacy Conversation",
                  default: false,
                  capabilities: baseCapabilities,
                },
              ],
            },
          ],
        },
      ],
      services: [],
      rate_limits: [
        {
          id: "rate_provider",
          scope: "provider_instance",
          scope_id: "pvi_capabilities",
          tier_id: "provider-default",
          count_limit: 1000,
          count_period_seconds: 60,
          observed_at: "2026-07-20T00:00:00Z",
          expires_at: "2026-07-21T00:00:00Z",
        },
        {
          id: "rate_offering",
          scope: "offering",
          scope_id: "offering_capabilities",
          tier_id: "offering-default",
          count_limit: 100,
          count_period_seconds: 60,
          usage_limit: 100000,
          usage_period_seconds: 60,
          usage_field: "tokens",
          observed_at: "2026-07-20T00:00:00Z",
          expires_at: "2026-07-21T00:00:00Z",
        },
        {
          id: "rate_profile",
          scope: "execution_profile",
          scope_id: "profile_embedding",
          tier_id: "embedding-default",
          count_limit: 10,
          count_period_seconds: 60,
          observed_at: "2026-07-20T00:00:00Z",
          expires_at: "2026-07-21T00:00:00Z",
        },
        {
          id: "rate_credential",
          scope: "credential",
          scope_id: "credential_hidden",
          tier_id: "credential-private",
          count_limit: 5,
          count_period_seconds: 60,
          observed_at: "2026-07-20T00:00:00Z",
          expires_at: "2026-07-21T00:00:00Z",
        },
      ],
      revision: 1,
      observed_at: "2026-07-20T00:00:00Z",
    });

    const embeddingProfile = parsed.models[0]?.offerings[0]?.profiles[0];
    expect(embeddingProfile?.capabilities.media_inputs).toEqual([]);
    expect(embeddingProfile?.capabilities.parameters).toEqual([]);
    expect(embeddingProfile?.capabilities.embedding?.output_kinds).toEqual([
      "dense",
      "sparse",
    ]);
    expect(
      embeddingProfile?.capabilities.embedding?.default_dimensions,
    ).toEqual({
      known: false,
    });
    expect(embeddingProfile?.pool?.blocking_allowance_kinds).toEqual([]);
    expect(
      parsed.models[0]?.offerings[0]?.profiles[1]?.capabilities.rerank
        ?.truncation_policies,
    ).toEqual([]);
    expect(parsed.models[0]?.offerings[0]?.profiles[2]?.operation).toBe("");
    expect(parsed.models[0]?.offerings[0]?.profiles[2]?.action_binding_id).toBe(
      "",
    );
    expect(
      selectProfileRateLimits(
        parsed.rate_limits,
        parsed.provider_instance_id,
        "offering_capabilities",
        "profile_embedding",
      ).map((limit) => limit.id),
    ).toEqual(["rate_provider", "rate_offering", "rate_profile"]);
    expect(
      isCatalogRateLimitExpired(
        parsed.rate_limits[0],
        Date.parse("2026-07-20T23:59:59Z"),
      ),
    ).toBe(false);
    expect(
      isCatalogRateLimitExpired(
        parsed.rate_limits[0],
        Date.parse("2026-07-21T00:00:00Z"),
      ),
    ).toBe(true);

    // incompleteUsageTuple proves the browser rejects an ambiguous provider metric instead of hiding missing fields.
    // incompleteUsageTuple 证明浏览器会拒绝歧义供应商指标，而不是隐藏缺失字段。
    const incompleteUsageTuple = {
      ...parsed,
      rate_limits: [
        {
          ...parsed.rate_limits[0],
          usage_limit: 1,
        },
      ],
    };
    expect(() => modelCatalogSchema.parse(incompleteUsageTuple)).toThrow(
      "rate-limit usage fields must be all present or all absent",
    );
  });
});

describe("search service diagnostics", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  // This test verifies one exact typed search target is sent to the management diagnostic endpoint and parsed strictly.
  // 此测试验证一个精确的类型化搜索目标会发送到管理诊断端点并被严格解析。
  it("executes a provider-backed search without model discovery", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          execution_id: "exec-search",
          search: {
            query: "Vulcan",
            queries: ["Vulcan"],
            evidence: { status: "confirmed", kinds: ["url"] },
            results: [
              {
                id: "result-1",
                rank: 1,
                title: "Vulcan",
                url: "https://example.com/vulcan",
              },
            ],
            citations: null,
            sources: null,
          },
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );
    vi.stubGlobal("fetch", fetchMock);

    const result = await testSearchService("management-token", {
      providerInstanceID: "provider-search",
      providerServiceID: "service-search",
      serviceOfferingID: "offering-search",
      executionProfileID: "profile-search",
      query: "Vulcan",
      outputMode: "results",
      evidenceRequirement: "verified",
    });

    expect(result.search.results[0]?.title).toBe("Vulcan");
    expect(result.search.citations).toEqual([]);
    expect(fetchMock).toHaveBeenCalledWith(
      "/vulcan/manage/provider-instances/provider-search/services/service-search/search-test",
      expect.objectContaining({
        method: "POST",
        headers: {
          Authorization: "Bearer management-token",
          "Content-Type": "application/json",
        },
      }),
    );
  });
});

describe("extract service diagnostics", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  // This test verifies one exact typed extraction target and partial provider result survive strict validation.
  // 此测试验证一个精确类型化提取目标与供应商部分成功结果能通过严格校验。
  it("executes provider-backed extraction without model discovery", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          execution_id: "exec-extract",
          extract: {
            results: [
              {
                url: "https://example.com/a",
                raw_content: "content",
                images: ["https://example.com/image.png"],
              },
            ],
            failed_results: [
              { url: "https://example.org/b", error: "blocked" },
            ],
            provider_request_id: "req-extract",
            response_time_seconds: 1.25,
            usage: {
              service_units: 2,
              service_unit: "credits",
              source: "provider_reported",
              aggregation: "snapshot",
              phase: "terminal",
              accounting_basis: "tavily_api_credits",
              final: true,
            },
          },
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );
    vi.stubGlobal("fetch", fetchMock);

    const result = await testExtractService("management-token", {
      providerInstanceID: "provider-extract",
      providerServiceID: "service-extract",
      serviceOfferingID: "offering-extract",
      executionProfileID: "profile-extract",
      urls: ["https://example.com/a", "https://example.org/b"],
      query: "router",
      chunksPerSource: 2,
      depth: "advanced",
      format: "markdown",
      includeImages: true,
      includeFavicon: false,
      timeoutSeconds: 15,
    });

    expect(result.extract.results[0]?.raw_content).toBe("content");
    expect(result.extract.failed_results[0]?.error).toBe("blocked");
    expect(fetchMock).toHaveBeenCalledWith(
      "/vulcan/manage/provider-instances/provider-extract/services/service-extract/extract-test",
      expect.objectContaining({
        method: "POST",
        headers: {
          Authorization: "Bearer management-token",
          "Content-Type": "application/json",
        },
      }),
    );
  });
});
