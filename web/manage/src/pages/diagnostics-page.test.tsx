import { render, screen, waitFor } from "@testing-library/react"
import { afterEach, describe, expect, it, vi } from "vitest"

import { I18nProvider } from "@/i18n"
import { DiagnosticsPage } from "@/pages/diagnostics-page"

afterEach(() => {
  vi.unstubAllGlobals()
})

describe("DiagnosticsPage", () => {
  it("renders the exact execution status and safe failure classification", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ executions: [{ id: "exe_visible", status: "failed", operation: "audio.transcribe", failure: { code: "provider_rejected", retryable: false }, created_at: "2026-07-20T00:00:00Z", updated_at: "2026-07-20T00:00:01Z", expires_at: "2026-07-21T00:00:00Z", revision: 2 }] }), { status: 200 })))

    render(<I18nProvider><DiagnosticsPage kind="executions" managementAuthToken="manage-token" /></I18nProvider>)

    await waitFor(() => expect(screen.getByText("exe_visible")).toBeInTheDocument())
    expect(screen.getByText("failed")).toBeInTheDocument()
    expect(screen.getByText("provider_rejected")).toBeInTheDocument()
    expect(screen.queryByText("private-provider-task")).not.toBeInTheDocument()
  })

  it("renders aggregate access metrics and redacted principal identifiers", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ audit: [{ time: "2026-07-21T00:00:00Z", principal: { subject_id: "api_local", tenant_id: "tenant_local", project_id: "project_local", roles: ["caller"] }, outcome: "authorized", permission: "invoke", method: "POST", path: "/vulcan/v1/info", status_code: 200 }], metrics: { requests: 4, failures: 1, total_duration_nanoseconds: 2000000 } }), { status: 200 })))

    render(<I18nProvider><DiagnosticsPage kind="access" managementAuthToken="manage-token" /></I18nProvider>)

    await waitFor(() => expect(screen.getByText("api_local")).toBeInTheDocument())
    expect(screen.getByText("tenant_local / project_local")).toBeInTheDocument()
    expect(screen.getByText("/vulcan/v1/info")).toBeInTheDocument()
  })
})
