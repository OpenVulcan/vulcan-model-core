import { afterEach, describe, expect, it, vi } from "vitest";

import { ManagementClient, type BindingRequest, type EndpointRequest } from "./api";
import type { CustomCatalogDocument } from "./types";

// jsonResponse returns one minimal successful identifier response for client payload tests.
// jsonResponse 返回一个用于客户端载荷测试的最小成功标识响应。
function jsonResponse(identifier: string): Response {
  return new Response(JSON.stringify({ id: identifier }), { status: 201, headers: { "Content-Type": "application/json" } });
}

// describe verifies the browser client removes editor-only fields before strict server JSON decoding.
// describe 验证浏览器客户端在严格服务端 JSON 解码前移除仅编辑器字段。
describe("ManagementClient", () => {
  // fetchMock captures exact outbound management request bodies.
  // fetchMock 捕获精确的出站管理请求正文。
  const fetchMock = vi.fn();

  afterEach(() => {
    vi.unstubAllGlobals();
    fetchMock.mockReset();
  });

  // it verifies create endpoint payloads never contain UI-only status or editing fields.
  // it 验证创建端点载荷绝不包含仅 UI 使用的状态或编辑字段。
  it("serializes only backend-declared endpoint creation fields", async () => {
    fetchMock.mockResolvedValue(jsonResponse("ep_test"));
    vi.stubGlobal("fetch", fetchMock);
    const client = new ManagementClient("manage-key");
    const payload = {
      id: "ep_test",
      channel_id: "default",
      base_url: "https://gateway.example/v1",
      region: "local",
      status: "ready",
      editing_id: "ui-only"
    } as EndpointRequest & { editing_id: string };

    await client.createEndpoint("pvi_test", payload);

    const options = fetchMock.mock.calls[0]?.[1] as RequestInit;
    expect(JSON.parse(String(options.body))).toEqual({
      id: "ep_test",
      channel_id: "default",
      base_url: "https://gateway.example/v1",
      region: "local"
    });
  });

  // it verifies update binding payloads retain only the strict server contract and explicit enabled state.
  // it 验证更新绑定载荷仅保留严格服务端合同和显式启用状态。
  it("serializes only backend-declared binding update fields", async () => {
    fetchMock.mockResolvedValue(jsonResponse("bind_test"));
    vi.stubGlobal("fetch", fetchMock);
    const client = new ManagementClient("manage-key");
    const payload = {
      id: "bind_test",
      channel_id: "default",
      endpoint_id: "ep_test",
      credential_id: "cred_test",
      allowed_model_ids: ["model_test"],
      priority: 7,
      enabled: false,
      editing_id: "ui-only",
      allowed_models_text: "model_test"
    } as BindingRequest & { editing_id: string; allowed_models_text: string };

    await client.updateBinding("pvi_test", "bind_test", payload);

    const options = fetchMock.mock.calls[0]?.[1] as RequestInit;
    expect(JSON.parse(String(options.body))).toEqual({
      channel_id: "default",
      endpoint_id: "ep_test",
      credential_id: "cred_test",
      allowed_model_ids: ["model_test"],
      priority: 7,
      enabled: false
    });
  });

  // it verifies complete custom catalog documents use the custom-provider-only management route.
  // it 验证完整自定义目录文档使用仅限自定义供应商的管理路由。
  it("saves a typed custom catalog through the exact custom-only path", async () => {
    const document: CustomCatalogDocument = { models: [], offerings: [], profiles: [] };
    fetchMock.mockResolvedValue(new Response(JSON.stringify(document), { status: 200, headers: { "Content-Type": "application/json" } }));
    vi.stubGlobal("fetch", fetchMock);
    const client = new ManagementClient("manage-key");

    const saved = await client.saveCustomCatalog("pvi_custom", document);

    expect(saved).toEqual(document);
    expect(fetchMock.mock.calls[0]?.[0]).toBe("/vulcan/manage/provider-instances/pvi_custom/custom-catalog");
    const options = fetchMock.mock.calls[0]?.[1] as RequestInit;
    expect(options.method).toBe("PUT");
    expect(JSON.parse(String(options.body))).toEqual(document);
  });
});
