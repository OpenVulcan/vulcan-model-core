import { describe, expect, it } from "vitest"

import { capabilityLevelSchema, formatKnownLimit, modelCapabilitiesSchema, modelCatalogSchema } from "@/lib/model-capabilities"

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
    delivery: { synchronous: true, streaming: true, asynchronous: false, polling: false, cancellation: false, partial_results: false },
    media_inputs: [{ kind: "image", level: "conditional", client_workflows: ["resource_ref"], evidence: [{ source: "official_docs", reference: "fixture", observed_at: "2026-07-20T00:00:00Z", revision: 1 }], evidence_revision: 1 }],
    media_outputs: [],
    parameters: [],
    parameter_rules: [],
    usage_metrics: [{ unit: "input_tokens", accuracy: "exact" }],
  } as const
}

describe("model capability schema", () => {
  it("preserves conditional and unknown capability facts", () => {
    const parsed = modelCapabilitiesSchema.parse(createCapabilitiesFixture())
    expect(parsed.parallel_tool_calls).toBe("conditional")
    expect(parsed.reasoning).toBe("unknown")
    expect(parsed.max_input_tokens).toEqual({ known: false })
    expect(parsed.media_inputs[0]?.level).toBe("conditional")
  })

  it("rejects contradictory known-limit objects", () => {
    expect(() => modelCapabilitiesSchema.parse({ ...createCapabilitiesFixture(), max_input_tokens: { known: false, value: 1000 } })).toThrow()
    expect(formatKnownLimit({ known: false }, "Unknown")).toBe("Unknown")
  })

  it("rejects unrecognized support levels", () => {
    expect(() => capabilityLevelSchema.parse("assumed")).toThrow()
  })

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
    }
    const parsed = modelCatalogSchema.parse({
      provider_instance_id: "pvi_capabilities",
      models: [
        {
          id: "model_capabilities",
          upstream_model_id: "model-capabilities",
          display_name: "Capability Model",
          entitlement_mode: "all_bound_credentials",
          enabled: true,
          provider_authorized: true,
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
      revision: 1,
      observed_at: "2026-07-20T00:00:00Z",
    })

    const embeddingProfile = parsed.models[0]?.offerings[0]?.profiles[0]
    expect(embeddingProfile?.capabilities.media_inputs).toEqual([])
    expect(embeddingProfile?.capabilities.parameters).toEqual([])
    expect(embeddingProfile?.capabilities.embedding?.output_kinds).toEqual([
      "dense",
      "sparse",
    ])
    expect(embeddingProfile?.capabilities.embedding?.default_dimensions).toEqual({
      known: false,
    })
    expect(embeddingProfile?.pool?.blocking_allowance_kinds).toEqual([])
    expect(
      parsed.models[0]?.offerings[0]?.profiles[1]?.capabilities.rerank
        ?.truncation_policies,
    ).toEqual([])
    expect(parsed.models[0]?.offerings[0]?.profiles[2]?.operation).toBe("")
    expect(parsed.models[0]?.offerings[0]?.profiles[2]?.action_binding_id).toBe(
      "",
    )
  })
})
