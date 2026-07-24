import { afterEach, describe, expect, it, vi } from "vitest"

import {
  createRouterToolBinding,
  fetchModelToolAvailability,
  fetchRouterToolBindings,
  probeRouterToolBinding,
  type RouterToolBindingInput,
  updateRouterToolBinding,
} from "@/lib/router-tool-bindings"

// bindingFixture returns one complete management-safe Router binding.
// bindingFixture 返回一个完整且管理安全的 Router 绑定。
function bindingFixture() {
  return {
    id: "rtb_fixture",
    kind: "web_search",
    provider_instance_id: "pvi_tavily",
    provider_service_id: "service_web_search",
    service_offering_id: "service_offer_tavily_search",
    execution_profile_id: "profile_tavily_search",
    priority: 0,
    enabled: true,
    allowed_provider_instance_ids: null,
    allowed_provider_model_ids: null,
    allowed_execution_profile_ids: null,
    timeout_milliseconds: 30000,
    maximum_calls: 4,
    maximum_results: 8,
    maximum_urls: 0,
    maximum_result_bytes: 65536,
    safety_policy: "public_https_only",
    revision: 1,
    created_at: "2026-07-23T00:00:00Z",
    updated_at: "2026-07-23T00:00:00Z",
  }
}

// bindingInput returns the exact operator-authored mutation contract.
// bindingInput 返回精确的操作员变更合同。
function bindingInput(): RouterToolBindingInput {
  return {
    kind: "web_search",
    providerInstanceID: "pvi_tavily",
    providerServiceID: "service_web_search",
    serviceOfferingID: "service_offer_tavily_search",
    executionProfileID: "profile_tavily_search",
    priority: 0,
    enabled: true,
    timeoutMilliseconds: 30000,
    maximumCalls: 4,
    maximumResults: 8,
    maximumURLs: 0,
    maximumResultBytes: 65536,
  }
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe("Router tool binding client", () => {
  it("normalizes optional scopes and preserves exact backend identifiers", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({
      router_tool_bindings: [bindingFixture()],
    }), { status: 200, headers: { "Content-Type": "application/json" } })))

    const bindings = await fetchRouterToolBindings("management-token")

    expect(bindings).toHaveLength(1)
    expect(bindings[0]?.allowed_provider_instance_ids).toEqual([])
    expect(bindings[0]?.execution_profile_id).toBe("profile_tavily_search")
  })

  it("parses native and Router readiness independently", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({
      models: [{
        provider_instance_id: "pvi_model",
        provider_handle: "model",
        provider_definition_id: "system_model",
        model: { id: "model_one", display_name: "Model One", upstream_model_id: "model-one" },
        model_tools: [{
          offering_id: "offer_one",
          execution_profile_id: "profile_one",
          standard: [{
            kind: "web_search",
            native_supported: false,
            native_ready: false,
            router_tool_supported: true,
            router_tool_ready: true,
            available_modes: ["disabled", "router_tool"],
            requires: [],
          }],
          extra: [],
          router_extensions: [],
        }],
      }],
    }), { status: 200, headers: { "Content-Type": "application/json" } })))

    const availability = await fetchModelToolAvailability("management-token")

    expect(availability.models[0]?.model_tools[0]?.standard[0]).toMatchObject({
      native_ready: false,
      router_tool_ready: true,
    })
  })

  it("writes exact create and optimistic update payloads", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(bindingFixture()), { status: 201, headers: { "Content-Type": "application/json" } }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ ...bindingFixture(), revision: 2 }), { status: 200, headers: { "Content-Type": "application/json" } }))
    vi.stubGlobal("fetch", fetchMock)

    await createRouterToolBinding("management-token", bindingInput())
    await updateRouterToolBinding("management-token", "rtb_fixture", 1, bindingInput())

    const createPayload = JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body))
    const updatePayload = JSON.parse(String(fetchMock.mock.calls[1]?.[1]?.body))
    expect(createPayload).toMatchObject({
      kind: "web_search",
      provider_instance_id: "pvi_tavily",
      safety_policy: "public_https_only",
      maximum_results: 8,
    })
    expect(createPayload.revision).toBeUndefined()
    expect(updatePayload.revision).toBe(1)
  })

  it("tests one exact binding without accepting credential fields", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      binding_id: "rtb_fixture",
      revision: 1,
      tool_id: "web_search",
      operation: "search.web",
      ready: true,
    }), { status: 200, headers: { "Content-Type": "application/json" } }))
    vi.stubGlobal("fetch", fetchMock)

    const probe = await probeRouterToolBinding("management-token", "rtb_fixture")

    expect(probe).toMatchObject({ binding_id: "rtb_fixture", ready: true })
    expect(fetchMock).toHaveBeenCalledWith(
      "/vulcan/manage/router-tool-bindings/rtb_fixture/test",
      expect.objectContaining({ method: "POST" }),
    )
  })
})
