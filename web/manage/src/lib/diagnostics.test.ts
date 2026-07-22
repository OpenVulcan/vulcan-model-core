import { afterEach, describe, expect, it, vi } from "vitest"

import { executionDiagnosticSchema, fetchAccessDiagnostics, fetchExecutionDiagnostics, resourceDiagnosticSchema } from "@/lib/diagnostics"

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

  it("loads the redacted access audit and aggregate counters", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ audit: [{ time: "2026-07-21T00:00:00Z", principal: { subject_id: "api_local", tenant_id: "tenant_local", project_id: "project_local", roles: ["caller"] }, outcome: "authorized", permission: "invoke", method: "POST", path: "/vulcan/v1/executions", status_code: 201 }], metrics: { requests: 1, failures: 0, total_duration_nanoseconds: 2500000 } }), { status: 200 }))
    vi.stubGlobal("fetch", fetchMock)
    const value = await fetchAccessDiagnostics("manage-token")
    expect(value.audit[0]?.principal?.subject_id).toBe("api_local")
    expect(value.metrics.total_duration_nanoseconds).toBe(2500000)
    expect(fetchMock).toHaveBeenCalledWith("/vulcan/manage/diagnostics/access", expect.objectContaining({ headers: { Authorization: "Bearer manage-token" } }))
  })
})
