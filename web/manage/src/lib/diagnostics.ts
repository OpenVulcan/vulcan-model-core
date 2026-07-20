import { z } from "zod"

// resourceDiagnosticSchema validates metadata-only Router resource rows.
// resourceDiagnosticSchema 校验仅含元数据的 Router 资源行。
export const resourceDiagnosticSchema = z.object({ id: z.string().min(1), kind: z.string().min(1), mime_type: z.string(), size_bytes: z.number().nonnegative(), source: z.string().min(1), state: z.string().min(1), error_code: z.string().optional(), created_at: z.string().min(1), updated_at: z.string().min(1), expires_at: z.string().optional(), revision: z.number().int().positive() })

// executionDiagnosticSchema validates public execution lifecycle rows without private request or provider state.
// executionDiagnosticSchema 校验不含私有请求或供应商状态的公开执行生命周期行。
export const executionDiagnosticSchema = z.object({ id: z.string().min(1), status: z.string().min(1), operation: z.string().min(1), failure: z.object({ code: z.string().min(1), retryable: z.boolean() }).optional(), created_at: z.string().min(1), updated_at: z.string().min(1), expires_at: z.string().min(1), revision: z.number().int().positive() })

// ResourceDiagnostic is one parsed management-safe resource row.
// ResourceDiagnostic 是一个已解析的管理安全资源行。
export type ResourceDiagnostic = z.infer<typeof resourceDiagnosticSchema>

// ExecutionDiagnostic is one parsed management-safe execution row.
// ExecutionDiagnostic 是一个已解析的管理安全执行行。
export type ExecutionDiagnostic = z.infer<typeof executionDiagnosticSchema>

// fetchResourceDiagnostics loads the bounded metadata-only resource history.
// fetchResourceDiagnostics 加载有界且仅含元数据的资源历史。
export async function fetchResourceDiagnostics(managementAuthToken: string, signal?: AbortSignal): Promise<ResourceDiagnostic[]> {
  const response = await fetch("/vulcan/manage/diagnostics/resources", { headers: { Authorization: `Bearer ${managementAuthToken}` }, signal })
  if (!response.ok) throw new Error(`resource diagnostics request failed with status ${response.status}`)
  return z.object({ resources: z.array(resourceDiagnosticSchema) }).parse(await response.json()).resources
}

// fetchExecutionDiagnostics loads the bounded public execution lifecycle history.
// fetchExecutionDiagnostics 加载有界的公开执行生命周期历史。
export async function fetchExecutionDiagnostics(managementAuthToken: string, signal?: AbortSignal): Promise<ExecutionDiagnostic[]> {
  const response = await fetch("/vulcan/manage/diagnostics/executions", { headers: { Authorization: `Bearer ${managementAuthToken}` }, signal })
  if (!response.ok) throw new Error(`execution diagnostics request failed with status ${response.status}`)
  return z.object({ executions: z.array(executionDiagnosticSchema) }).parse(await response.json()).executions
}
