# ADR 0007：CLIProxyAPI 上游协议源码迁移与 VCP 适配

## 状态

已实施，已通过逐文件五轮审计门禁。

## 背景

Vulcan Model Core 已将 VCP 作为唯一内部协议真相，但尚未拥有 OpenAI Responses、xAI Responses 与 Google AI Studio 的完整上游协议执行实现。CLIProxyAPI 已在对应协议上积累大量 wire、SSE、工具与异常兼容修复。用户已授权按 MIT 许可证选择性迁入这些经过验证的行为。

来源固定为 `https://github.com/router-for-me/CLIProxyAPI` 的提交 `9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66`。许可证文本与版权声明见仓库根目录 `THIRD_PARTY_NOTICES.md`。

## 决策

1. 迁入对象必须是上游协议的确定性 wire 行为、SSE 生命周期、端点构造、已证实的字段归一化或对应无密钥回归夹具。
2. 每个迁入或实质改编的 Go 文件保留来源头注释；本 ADR 的来源矩阵将源文件和函数节点逐项绑定到本项目落点与测试。
3. 不复制或依赖 Gin Handler、Translator 注册矩阵、配置中心、账号池、OAuth 文件、调度、插件、日志运行时和跨 Provider 回退。它们与本项目的 VCP/Provider 边界冲突。
4. 对源代码中依赖 `map[string]any`、`gjson`、`sjson` 的处理，采用等价的封闭 Go wire 类型重写；`[]byte` 仅存在于 HTTP/SSE 边界，绝不作为内部执行真相。
5. 正式厂商 API 文档决定 wire 合法性，CLIProxyAPI 代码和测试决定历史兼容行为。若两者冲突，采用正式协议并记录差异，不静默沿用历史行为。

## 来源矩阵

| 来源文件与节点 | 证据用途 | 本项目目标 | 迁移方式 | 状态 |
| --- | --- | --- | --- | --- |
| `sdk/api/handlers/openai/openai_handlers.go`：`ChatCompletions`、流/非流分发 | OpenAI Chat 端点和 SSE 行为证据 | `internal/protocol/openai/chat`、`internal/provider/openai/chat.go` | 仅行为证据；公共 Handler 不迁入 | 已完成；只迁入出站 Driver，不新增公共入口 |
| `internal/runtime/executor/openai_compat_executor.go`：`PrepareRequest`、`HttpRequest`、状态错误 | Bearer 认证、HTTP/SSE 与状态错误边界 | `internal/provider/transport`、`internal/provider/openai/chat.go`、`internal/provider/openai/responses.go` | 实质改编 | 已完成；同 Target Transport 替代全局 Executor |
| `internal/runtime/executor/openai_compat_executor.go`：`CountTokens` | CLIProxyAPI 本地 tokenizer 估算 | 不迁入 | 明确排除 | 本项目当前没有 OpenAI 本地估算 VCP 操作；不得伪造 Provider 返回或引入其 tokenizer 依赖 |
| `sdk/api/handlers/openai/openai_responses_handlers.go`：`responsesSSEFramer`、`repairCompletedPayload` | 拆包 SSE、晚到完整输出与完成事件修复 | `internal/protocol/openai/responses/stream.go` | 实质改编 | 已完成 |
| `internal/translator/openai/openai/responses/openai_openai-responses_response.go`：Responses 输出状态机 | output item、文本、function call、reasoning、completed/incomplete 的事件语义 | `internal/protocol/openai/responses/response.go`、`stream.go` | 行为提取与测试夹具 | 已完成 |
| `internal/translator/openai/openai/responses/openai_openai-responses_tools.go`：命名空间/自定义工具 | function/custom/namespace 工具名称和参数规则 | `internal/protocol/xai/responses/request.go` | 实质改编 | 已完成 |
| `internal/runtime/executor/xai_executor.go`：`sanitizeXAIResponsesBody`、`normalizeXAITools`、`normalizeXAIInputReasoningItems`、`mergeAdjacentXAIInputReasoningSummaries` | xAI 推理、工具、无效字段与相邻摘要兼容 | `internal/protocol/xai/responses/request.go` | 实质改编 | 已完成；相邻纯摘要会类型化合并并重映射账本位置 |
| `internal/runtime/executor/xai_executor.go`：`ensureXAINativeXSearchTool`、`ensureXAINativeXSearchAllowedTools`、`pruneXAIOrphanedToolChoice`、`normalizeXAIToolChoiceForTools` | 隐式搜索注入与失配工具控制清理 | `internal/protocol/openai/responses/request.go`、`internal/protocol/xai/responses/request.go` | 有界改编 | 已完成；VCP 只投影调用方显式声明且 Target 已验证的 `ToolNativeWebSearch`，无工具时不发送 `tool_choice`/并行控制；不复制 CLIProxyAPI 的隐式注入 |
| `internal/runtime/executor/xai_executor.go`：`normalizeXAIInputCustomToolCalls`、`normalizeXAIInputNamespaceToolCalls`、`restoreXAINamespaceToolCalls` | custom 调用历史和 namespace 名称的双向归一 | `internal/protocol/xai/responses/request.go`、`internal/protocol/xai/responses/stream.go` | 实质改编 | 已完成；custom 仅在类型化 VCP 工具声明存在时转换为 function，限定名称只按请求声明恢复 |
| `internal/runtime/executor/xai_executor.go`：`xaiSupportsReasoningEffort` | 未支持模型的 reasoning effort 清理 | `internal/protocol/xai/responses/request.go` | 正式协议优先差异 | 已完成；VCP 需求不可静默重写，Target 未声明该能力时显式拒绝 |
| `internal/runtime/executor/xai_executor.go`：`sanitizeXAIInputEncryptedContent` | 原始 `encrypted_content` 签名净化 | 不迁入 wire 净化器 | 明确排除 | VCP 不接收该原始字段；密封续接只能由 Router 以同 Target continuation 绑定提供，无法验证时显式拒绝 |
| `internal/runtime/executor/xai_executor.go`：`newXAIInternalXSearchResponseFilter`、`compactOutputIndex`、`xaiPatchCompletedOutput` | 内部 x_search 过滤、输出索引紧凑与完成补丁 | `internal/protocol/xai/responses/stream.go` | 实质改编 | 已完成 |
| `internal/runtime/executor/xai_executor.go`：`CountTokens` | CLIProxyAPI 本地 `cl100k_base` 估算 | 不迁入 | 明确排除 | 当前 VCP 没有 xAI 本地估算操作；不得以本地估算冒充 xAI 上游协议结果 |
| `internal/runtime/executor/aistudio_executor.go`：`translateRequest`、`buildEndpoint`、`CountTokens` | AI Studio 动作选择、`alt=sse` 端点与 Token 统计边界 | `internal/protocol/google/aistudio`、`internal/provider/google/aistudio.go` | 实质改编 | 已完成；CountTokens 按正式文档使用类型化信封 |
| `internal/runtime/executor/aistudio_executor.go`：`PrepareRequest`、`HttpRequest` | Auth Attributes 自定义头与 CLIProxyAPI WebSocket relay | 不迁入 | 明确排除 | Target 只允许已建模的认证和 Driver 固定头；本项目直接使用同 Target HTTP，不复制 Relay、账号身份或任意 Attribute 头 |
| `sdk/api/handlers/gemini/gemini_handlers.go`：`handleGenerateContent`、`handleStreamGenerateContent`、`handleCountTokens` | AI Studio 三个 API 动作与流转证据 | `internal/protocol/google/aistudio`、`internal/provider/google/aistudio.go` | 仅行为证据 | 已完成；仅出站 Profile/Driver，不迁入公共 Handler |
| `internal/translator/gemini/gemini/gemini_gemini_request.go`：`backfillEmptyFunctionResponseNames` | Gemini 历史 functionResponse 缺名修复 | `internal/protocol/google/aistudio/request.go` | 实质改编 | 已完成；通过 VCP 先行 ToolCall 精确关联，无法确定时拒绝 |
| `internal/translator/gemini/gemini/gemini_gemini_request.go`：角色补全、字段重命名、thought signature 清理、默认 safety | 原始 JSON 的事后兼容改写 | 不迁入通用改写器 | 明确排除 | 已完成；typed Projection 只发正式 `user`/`model` 与正式字段名，opaque state 显式处理，VCP 未声明安全策略时不注入默认值 |
| `internal/translator/gemini/claude/gemini_claude_response.go`：无名称 functionCall 参数续接、签名单独分片、终态 usage | Gemini 分段工具参数与终态事件顺序 | `internal/protocol/google/aistudio/stream.go` | 实质改编 | 已完成；签名单独分片不会生成空 VCP 输出项，opaque 签名只记录安全转换事实 |
| `internal/translator/gemini/openai/responses/gemini_openai-responses_request.go`：systemInstruction、函数关联、尾部 model prefill | Gemini Responses 历史输入兼容 | `internal/protocol/google/aistudio/request.go` | 实质改编 | 已完成；函数结果改用正式 `user` 角色 |
| `internal/util/gemini_schema.go`：`CleanJSONSchemaForGemini` | 历史 JSON Schema 破坏性清理 | 不迁入 | 仅行为证据 | 明确不迁入；缺少可逆 VCP 规则，禁止静默改写调用方 Schema |
| `internal/translator/gemini/common`：默认 safetySettings 注入 | 配置驱动默认安全策略 | 不迁入 | 明确排除 | VCP 尚无调用方安全策略字段，禁止擅自注入 Provider 默认值 |
| 本项目原生：`providerconfig.ProtocolProfile.Capabilities` | 静态 Profile 能力事实 | `internal/providerconfig` | 本项目原生设计 | 已完成；禁止按真实请求探测未声明能力 |

## 可迁入的协议行为

### OpenAI Chat 与 Responses

- OpenAI Chat 的已有 VCP Profile 继续保持纯转换；真正网络行为放在同 Provider 的 Driver/Transport。
- Responses 支持封闭 input/output item、function call/output、reasoning、refusal、usage、非流和 SSE；输出项必须先拥有稳定 ID 后才允许进入 VCP 事件。
- 流式完成事件中缺失 output 时，只能由已经记录且有序的 output item 回填；没有证据的 item 不得伪造。

### xAI Responses

- 没有可用工具时不发送 `tool_choice` 或并行工具控制；命名空间函数以稳定限定名传输并在回读时恢复。
- `x_search` 仅在已解析的 xAI Target 明确支持时才投影；Provider 内部产生、但不属于调用方声明函数的搜索轨迹必须在输出中删除并紧凑索引。
- 加密推理内容不作为普通文本回放；只可作为 sealed provider continuation/state 处理。目标未声明 reasoning effort 时必须以显式错误拒绝请求。

### Google AI Studio

- 支持 `generateContent`、`streamGenerateContent`、`countTokens` 三个动作，stream 动作使用 `alt=sse`。
- Gemini 的 `contents`、`parts`、`systemInstruction`、`functionCall`、`functionResponse`、safety 与 usage 映射到 VCP 的封闭类型。
- functionResponse 只有在同一有序 VCP 上下文中找到唯一先行 ToolCall 时才可回填 function 名称；无法确定时拒绝投影，不能猜测。
- `thinkingConfig.thinkingLevel` 与 `includeThoughts` 仅在目标 Capabilities 明确列出对应等级和摘要支持时发送；未验证控制返回显式错误。

## 正式协议优先的差异记录

1. CLIProxyAPI 的 `AIStudioExecutor.CountTokens` 从已翻译请求中删除 generationConfig、tools 和 safetySettings 后直接调用 `countTokens`。本实现遵循 [Google CountTokens API](https://ai.google.dev/api/tokens) 的正式 `generateContentRequest` 信封，以封闭类型保留同一份请求投影；本地 mock 覆盖该 wire 形状和零 Token 响应。
2. CLIProxyAPI Responses 转换器先构造 `role: "function"`，再依赖 Gemini 请求归一化器重写非 `user`/`model` 角色。正式 [Gemini function calling 文档](https://ai.google.dev/gemini-api/docs/generate-content/function-calling) 要求函数结果作为 `user` 轮次；本实现直接发送该合法角色，避免二次隐式改写。
3. CLIProxyAPI 的通用 Schema 清理器会把 `$ref`、联合、枚举与约束重写为描述提示。该过程无法通过当前 VCP Projection Ledger 可逆表达，因此本实现保留调用方的类型化 JSON Schema，遇到不支持的严格控制时显式拒绝，而不伪造兼容。
4. CLIProxyAPI 的 OpenAI/xAI `CountTokens` 是其运行时本地 tokenizer 估算，不是相应 Provider 的上游 wire 操作。本实现仅为 Google AI Studio 迁入其已定义的 `countTokens` 出站协议；其他两者明确不伪造为 Provider 计数结果。
5. CLIProxyAPI 的 OpenAI Chat Handler 透传外部请求，不能作为 VCP 字段投影的唯一 wire 定义。本实现遵循 [OpenAI Chat Completions API](https://platform.openai.com/docs/api-reference/chat/create) 直接发送 `reasoning_effort`，并使用包含 `name`、`schema` 与 `strict` 的 `response_format.json_schema` 配置；Chat 没有可见推理摘要的同等请求控制，因此该需求会按 Capability Policy 显式 omitted 或 blocked，绝不伪造为原生支持。
6. VCP 的 `ToolCallID` 是 Router 稳定身份，OpenAI Chat 的 `tool_call_id` 是上游 wire 关系。历史回放优先发送已记录的 `UpstreamID`，并要求 ToolResult 只关联有序前置 ToolCall；不得把 Router 标识伪装成 Provider 标识。

## 被明确排除的内容

- 面向客户端的 OpenAI、Gemini、xAI、Claude、Codex 兼容 HTTP 端点。
- CLIProxyAPI 的 Translator 配对注册和任意协议 A 到协议 B 的运行时转换路径。
- OAuth、API Key 文件、账号池、全局重试调度、日志插件、WebSocket、媒体 API、跨 Provider 故障转移。
- 未经可复现测试证明的实时、媒体、Vertex AI 或专有身份认证行为。

## 安全与不变量

1. `resolve.Target`、ProviderDefinition、Channel、Endpoint、Credential 和 Model 必须一一校验；Driver 不得替换它们。
2. Secret 仅由 Transport 在请求创建时读取，不能进入日志、错误、ExecutionReport 或 Profile。
3. 重试最多重试同一不可变 Target；不自动改用其他 Provider、Credential、Endpoint 或 Model。
4. 所有 Profile 可在无真实密钥的本地 mock upstream 上验证请求、SSE、错误和取消。

## 后果

该决策以可审计的局部代码复用换取历史协议兼容性，同时保留 VCP 的单一真相与 Provider-scoped 执行约束。后续新增任何源文件或协议节点，必须先更新本矩阵和许可证清单，再进入实现。
