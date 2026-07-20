import { afterEach, describe, expect, it, vi } from "vitest"

import { executionDiagnosticSchema, fetchExecutionDiagnostics, resourceDiagnosticSchema } from "@/lib/diagnostics"

afterEach(() => {
  vi.unstubAllGlobals()
})

describe("management diagnostic schemas", () => {
  it("strips fields outside the metadata-only resource contract", () => {
    const parsed = resourceDiagnosticSchema.parse({ id: "res_1", kind: "image", mime_type: "image/png", size_bytes: 10, source: "multipart", state: "ready", created_at: "2026-07-20T00:00:00Z", updated_at: "2026-07-20T00:00:01Z", revision: 1, sha256: "private-content-digest", source_url: "https://private.example" })
    expect(parsed).not.toHaveProperty("sha256")
    expect(parsed).not.toHaveProperty("source_url")
  })

  it("strips provider state and result content from execution rows", () => {
    const parsed = executionDiagnosticSchema.parse({ id: "exe_1", status: "succeeded", operation: "conversation.respond", result: { text: "private output" }, provider_task_id: "private-task", created_at: "2026-07-20T00:00:00Z", updated_at: "2026-07-20T00:00:01Z", expires_at: "2026-07-21T00:00:00Z", revision: 2 })
    expect(parsed).not.toHaveProperty("result")
    expect(parsed).not.toHaveProperty("provider_task_id")
  })

  it("loads a bounded public execution status envelope", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ executions: [{ id: "exe_1", status: "running", operation: "video.generate", created_at: "2026-07-20T00:00:00Z", updated_at: "2026-07-20T00:00:01Z", expires_at: "2026-07-21T00:00:00Z", revision: 3 }] }), { status: 200 }))
    vi.stubGlobal("fetch", fetchMock)
    const rows = await fetchExecutionDiagnostics("manage-token")
    expect(rows[0]?.status).toBe("running")
    expect(fetchMock).toHaveBeenCalledWith("/vulcan/manage/diagnostics/executions", expect.objectContaining({ headers: { Authorization: "Bearer manage-token" } }))
  })
})
