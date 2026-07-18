import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import App from "./App";

// jsonResponse returns one deterministic successful JSON fetch response.
// jsonResponse 返回一个确定性的成功 JSON Fetch 响应。
function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
}

// describe verifies the memory-only management login and first safe data refresh.
// describe 验证仅内存管理登录和首次安全数据刷新。
describe("App", () => {
  // fetchMock captures browser management API calls without opening a real local connection.
  // fetchMock 捕获浏览器管理 API 调用且不打开真实本地连接。
  const fetchMock = vi.fn();

  beforeEach(() => {
    fetchMock.mockImplementation((input: string | URL | Request) => {
      const path = String(input);
      if (path === "/vulcan/manage/protocol-profiles") {
        return Promise.resolve(jsonResponse({
          protocol_profiles: [{ id: "openai.responses", version: "1", display_name: "OpenAI Responses", user_configurable: true, runtime_ready: true, model_discovery: "unsupported", capabilities: [], allowed_auth_methods: ["bearer"] }]
        }));
      }
      if (path === "/vulcan/manage/provider-definitions") {
        return Promise.resolve(jsonResponse({ provider_definitions: [] }));
      }
      if (path === "/vulcan/manage/provider-instances") {
        return Promise.resolve(jsonResponse({ provider_instances: [] }));
      }
      if (path === "/vulcan/manage/api-keys") {
        return Promise.resolve(jsonResponse({ api_keys: [] }));
      }
      return Promise.resolve(jsonResponse({ endpoints: [], credentials: [], bindings: [] }));
    });
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    fetchMock.mockReset();
  });

  // it verifies management authentication remains memory-only and is sent only as a Bearer header.
  // it 验证管理认证保持仅内存状态且仅作为 Bearer 头发送。
  it("connects with a memory-only management key and loads management metadata", async () => {
    render(<App />);
    const keyInput = screen.getByLabelText("管理密钥");
    fireEvent.change(keyInput, { target: { value: "manage-test-key" } });
    fireEvent.click(screen.getByRole("button", { name: "进入管理端" }));

    await waitFor(() => expect(screen.getByRole("option", { name: "OpenAI Responses (openai.responses)" })).toBeInTheDocument());
    expect(fetchMock).toHaveBeenCalledWith("/vulcan/manage/protocol-profiles", expect.objectContaining({
      headers: expect.objectContaining({ Authorization: "Bearer manage-test-key" })
    }));
    expect(window.localStorage.getItem("management-key")).toBeNull();
  });

  // it verifies a selected custom provider loads its complete typed catalog into the non-secret editor.
  // it 验证所选自定义供应商会将完整类型化目录加载到非秘密编辑器。
  it("loads the custom catalog editor only for a custom provider instance", async () => {
    fetchMock.mockImplementation((input: string | URL | Request) => {
      const path = String(input);
      if (path === "/vulcan/manage/protocol-profiles") {
        return Promise.resolve(jsonResponse({ protocol_profiles: [] }));
      }
      if (path === "/vulcan/manage/provider-definitions") {
        return Promise.resolve(jsonResponse({ provider_definitions: [{ id: "custom_test", kind: "custom", display_name: "Custom Test", channels: [{ id: "default", protocol_profile_id: "openai.responses", runtime_ready: true }], auth_methods: [{ id: "default", type: "bearer" }], revision: 1 }] }));
      }
      if (path === "/vulcan/manage/provider-instances") {
        return Promise.resolve(jsonResponse({ provider_instances: [{ id: "pvi_custom_test", definition_id: "custom_test", handle: "custom-test", display_name: "Custom Test", status: "draft", disabled_model_ids: [], endpoint_count: 0, credential_count: 0, binding_count: 0, revision: 1 }] }));
      }
      if (path === "/vulcan/manage/api-keys") {
        return Promise.resolve(jsonResponse({ api_keys: [] }));
      }
      if (path === "/vulcan/manage/provider-instances/pvi_custom_test/custom-catalog") {
        return Promise.resolve(jsonResponse({ models: [{ id: "model_example", upstream_model_id: "example-model", display_name: "Example Model" }], offerings: [], profiles: [] }));
      }
      if (path === "/vulcan/manage/provider-instances/pvi_custom_test/catalog") {
        return Promise.resolve(jsonResponse({ provider_instance_id: "pvi_custom_test", models: [], allowances: [], plans: [], revision: 1, observed_at: "2026-07-18T00:00:00Z" }));
      }
      if (path.endsWith("/endpoints")) {
        return Promise.resolve(jsonResponse({ endpoints: [] }));
      }
      if (path.endsWith("/credentials")) {
        return Promise.resolve(jsonResponse({ credentials: [] }));
      }
      if (path.endsWith("/bindings")) {
        return Promise.resolve(jsonResponse({ bindings: [] }));
      }
      throw new Error(`unexpected path ${path}`);
    });

    render(<App />);
    fireEvent.change(screen.getByLabelText("管理密钥"), { target: { value: "manage-test-key" } });
    fireEvent.click(screen.getByRole("button", { name: "进入管理端" }));

    const editor = await screen.findByLabelText("自定义模型目录 JSON");
    await waitFor(() => expect((editor as HTMLTextAreaElement).value).toContain("model_example"));
    expect(fetchMock).toHaveBeenCalledWith("/vulcan/manage/provider-instances/pvi_custom_test/custom-catalog", expect.objectContaining({
      headers: expect.objectContaining({ Authorization: "Bearer manage-test-key" })
    }));
  });
});
