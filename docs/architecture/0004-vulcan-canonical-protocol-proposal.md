# ADR 0004：Vulcan 规范协议与流式语义提案

- 状态：部分替代；协议规则以 ADR 0006 为准，本文保留分析证据与历史提案内容
- 日期：2026-07-17
- 参考基线：CLIProxyAPI `main`，提交 `9f4f53ca`，`v7.2.74-24-g9f4f53ca`
- 分析范围：协议转换、工具调用、流式输出、用量、推理上下文、终态与错误语义
- 非分析范围：不对比当前 Vulcan Model Core 的实现缺口，不直接实现任何供应商协议

## 背景

CLIProxyAPI 已从本地 `v7.2.16` 快进更新 245 个提交到上述基线。最新代码注册了 OpenAI Chat Completions、OpenAI Responses、Claude、Gemini、Codex、Antigravity 和 Interactions 等格式之间的大量成对转换，并在供应商执行器中继续修正协议之外的行为差异。

这些代码最有价值的部分不是现成抽象，而是长期积累的失败样本：工具调用 ID 可能缺失或延迟出现，终态可能不带完整输出，usage 可能只出现在空内容分片中，推理签名不能跨供应商复用，429 也可能分别表示瞬时限流、套餐耗尽或模型繁忙。

Vulcan Model Core 不需要继续维护任意协议之间的互转。需要从这些失败样本中提炼一个只面向 Vulcan 工具的规范协议，使每个供应商只实现“供应商协议与 Vulcan 规范语义”之间的双向适配。

## 基线更新结果

更新前：

- 分支：`main`
- 提交：`dd49a520`
- 标签：`v7.2.16`
- 状态：落后 `origin/main` 245 个提交，工作树干净

执行 `git pull --ff-only origin main` 后：

- 提交：`9f4f53ca`
- 描述：`v7.2.74-24-g9f4f53ca`
- 状态：与 `origin/main` 一致，工作树干净
- 更新规模：458 个文件，约新增 60973 行、删除 12213 行

## CLIProxyAPI 当前协议架构

### 成对转换注册表

`sdk/translator/registry.go` 使用以下结构注册转换器：

```text
source format -> target format -> request transform
target format -> source format -> response transform
```

请求和响应主体仍是原始 JSON 字节。流式转换器通过 `param *any` 保存自己的可变状态，并返回若干原始字节分片。`internal/translator/init.go` 通过匿名导入注册完整的协议对。

该结构适合兼容代理，但不适合 Vulcan 内核：

1. 新增协议会扩大成对转换矩阵。
2. 同一语义在多个转换器里重复实现。
3. 状态类型不透明，无法统一验证流式不变量。
4. 缺少转换器时可能直接返回原始载荷，存在静默错误协议透传。
5. 语义损失没有统一报告方式。

### 转换器之外的执行器修复

协议稳定性还依赖执行器：

- Codex 在 `response.completed.response.output` 为空时，用此前的 `response.output_item.done` 重建最终输出。
- Codex 将 `response.failed`、`response.incomplete`、上下文超限、套餐用量耗尽和模型容量不足分别处理。
- OpenAI 风格流可能使用只有 usage、没有 choices 的末尾分片。
- WebSocket 的 `message_too_big` 需要转换成结构化错误。
- Codex、xAI、Antigravity 分别维护受模型、会话和供应商约束的推理回放缓存。
- `parallel_tool_calls` 在没有 tools 时必须移除，否则上游可能拒绝请求。
- 某些终态只补充工具名称、调用 ID 或最终参数，转换器必须水合此前未完成的调用。

因此，协议适配不能只定义 JSON 字段映射。它必须覆盖请求规范化、流式状态机、终态归并、供应商延续状态和错误分类。

## 各协议的真正共同点

不同协议的字段名称不同，但都可归纳为以下语义。

### 执行描述

- 模型或模型规格选择；
- 系统、开发者和用户指令；
- 采样、推理、最大输出和结构化输出参数；
- 可用工具及工具选择策略；
- 流式或非流式传输偏好；
- 缓存、服务等级和供应商扩展。

### 有序上下文

- 上下文是有序项目序列，不只是字符串消息数组；
- 一个项目可以包含多个内容块；
- 内容块至少包括文本、图像、音频、视频、文件、推理、拒绝、引用和供应商扩展；
- 系统、开发者、用户、助手的角色不能随意合并；
- 工具调用与工具结果存在显式因果关系和邻接约束；
- 某些供应商要求保留推理签名或加密延续数据。

### 工具生命周期

- 工具声明；
- 工具调用开始；
- 工具名称和调用 ID；
- 参数增量；
- 参数完成；
- 工具执行结果；
- 并行或交错的多个调用；
- 内置工具、自定义工具和带命名空间工具。

### 输出生命周期

- 响应开始；
- 输出项目开始；
- 内容块开始；
- 内容或参数增量；
- 内容块完成；
- 输出项目完成；
- usage 更新；
- 响应完成、不完整、失败或取消。

### 用量与限制

- 输入 token；
- 输出 token；
- 推理 token；
- 缓存读取 token；
- 缓存写入 token；
- 总 token；
- 供应商报告、Core 本地计算或估算；
- 流中间检查点或仅终态汇总。

### 终止与错误

- 正常结束；
- 达到输出上限；
- 工具调用；
- 内容过滤；
- 上下文超限；
- 套餐、余额或时间窗口耗尽；
- 瞬时限流；
- 模型容量不足；
- 认证、授权、签名和传输失败。

## 从最新代码确认的高风险失败模式

### 工具调用

最新测试和提交覆盖了以下情况：

- 流式工具调用的 ID 可能缺失、为空或晚于参数出现；
- 名称可能为空、为 null、重复发送或在终态才出现；
- 多个工具调用可以并行、交错或分多个批次出现；
- 工具调用只有参数而没有有效名称时不能伪造完整调用；
- 工具调用 ID 可能超过目标协议限制，需要映射并保持反向可恢复；
- 工具结果必须匹配正确调用，不能只依赖“最后一次调用”；
- 某些 Gemini 转换只能使用 FIFO 推断缺失的调用 ID；
- 只有工具调用、没有自然语言内容的响应仍是有效响应；
- 终态可能负责补全此前未决的工具调用；
- 自定义工具、内置工具和命名空间工具不能仅靠显示名称区分。

结论：Vulcan 必须为工具调用提供稳定身份、显式因果关系和映射来源。FIFO 只能是带诊断信息的兼容降级，不能是不可见的默认语义。

### 流式输出

最新实现表明：

- 网络分片、SSE 行、SSE 事件和语义事件不是同一层；
- 一个上游事件可能产生零个、一个或多个 Vulcan 事件；
- 终态可能不包含之前已经流出的完整内容；
- `output_item.done` 可能比 `response.completed` 更完整；
- 流在已经产生内容后仍可能收到结构化失败；
- 没有合法终态的 EOF 必须视为不完整流；
- 完成事件之后的传输错误不应推翻已经确认的完成；
- `response.incomplete` 不是普通成功，也不等同于网络错误；
- 大事件需要明确上限，CLIProxyAPI 多处将 Scanner 上限提高到 50 MB；
- WebSocket 和 SSE 应共享语义状态机，而不是共享原始分片格式。

结论：Vulcan 必须定义可归并的事件日志和确定性 reducer。最终响应应由语义事件归并得到，不能假设终态载荷始终自包含。

### 上下文与推理

最新实现表明：

- OpenAI Responses reasoning item、Claude thinking block 和 Gemini thought/signature 不能直接等价；
- 推理签名可能与供应商、模型族、会话和具体调用块绑定；
- 外来或失效签名需要删除，错误签名还可能导致缓存失效；
- 签名可能只在早期、增量或最终 done 事件中出现；
- 纯推理历史、推理后跟助手内容、推理后跟工具调用都需要保持顺序；
- 某些 Gemini 上游不接受末尾 assistant prefill，但删除它会改变上下文语义；
- Claude 的 message-level system 在目标协议不支持时会被模拟成 `<system-reminder>` 用户内容；这属于有损仿真，不应静默发生；
- cache control 可能附着在消息或具体内容块，块级配置优先；
- 工具调用与工具结果的邻接关系会影响供应商是否接受上下文。

结论：不能把上下文转换定义为角色和文本的简单复制。每个上下文项目必须保留顺序、身份、来源、约束和转换结果。

### usage 与 token 检查

最新实现表明：

- usage 可能位于 `usage`、`response.usage`、`interaction.usage`、`metadata.usage`、`usageMetadata` 等不同位置；
- OpenAI、Claude 和 Gemini 对缓存 token 是否包含在 input/total 中的口径不同；
- Anthropic 将 `cache_creation_input_tokens`、`cache_read_input_tokens` 与断点后的普通 `input_tokens` 分开报告，三者相加才是该请求处理的总输入；
- Anthropic 还可能在 `cache_creation` 中按 5 分钟和 1 小时 TTL 细分创建 token；
- 百炼的 Qwen 模型同时存在显式缓存和隐式缓存，显式缓存可在同一轮既读取旧缓存又创建新的增长前缀；
- 百炼 OpenAI 兼容接口使用 `prompt_tokens_details.cache_creation_input_tokens` 和 `cached_tokens`，Anthropic 兼容接口则使用 `cache_creation_input_tokens` 和 `cache_read_input_tokens`；
- 百炼明确说明 `input_tokens` 不一定等于缓存创建、缓存命中和普通输入的简单和，因为服务端可能追加缓存断点之后的 token；
- 流式 usage 可能是累计值，只应保留最后一个有效观测；
- usage 为 null、全零、仅服务等级或只有缓存字段都需要区分；
- 某些协议支持专用 count tokens 接口，另一些只能本地估算；
- CLIProxyAPI 的一个 Claude→Responses 转换会用推理文本字节长度除以 4 估算 reasoning token，但输出中没有表达“估算”来源。

结论：缓存创建不是普通 input token 的别名，也不只是内部性能指标，而是独立的用量和计费类别。未知、零、估算、推导和供应商精确报告必须是不同状态。token 检查点和最终计费 usage 也必须分离。

### 错误与重试

最新实现明确区分：

- `usage_limit_reached`：套餐或窗口耗尽，可携带 `resets_at` 或 `resets_in_seconds`；
- `rate_limit_error`：瞬时限流，不应等同于套餐耗尽；
- `model at capacity`：模型容量不足；
- `context_length_exceeded`：请求上下文需要缩减或切换规格；
- `thinking_signature_invalid`：供应商延续状态失效；
- HTTP 成功后的 `response.failed`：流内失败；
- transport EOF：只有在没有合法终态时才是不完整流。

结论：HTTP 状态码不能直接决定容灾。供应商驱动必须输出结构化错误类别、作用域、恢复时间和允许的下一动作。

## 协议选择结论

### 不直接采用任何现有供应商协议

不建议将 OpenAI Chat Completions、OpenAI Responses、Claude Messages、Gemini GenerateContent 或 Google Interactions 中的任意一个直接作为 Vulcan 内部真相模型。

- Chat Completions 的消息和 delta 结构不足以稳定表达完整项目生命周期。
- Claude 的 content block、thinking signature 和 cache control 很强，但其角色、工具和媒体语义仍是供应商特定结构。
- Gemini 的 parts 适合多模态，但函数调用 ID、角色和 thought signature 行为具有供应商约束。
- Interactions 的 step 结构接近规范项目，但现有适配中仍会把某些音频降级成文本描述，说明它也不能成为无损公共基准。
- OpenAI Responses 的 item 与事件模型最接近需求，但仍包含 OpenAI/Codex 特有字段、存储语义和推理延续语义。

### 推荐方案

采用 Vulcan 自有规范协议：

> 请求使用“有序项目 + 类型化内容块”，响应使用“类型化语义事件 + 确定性 reducer”。OpenAI Responses 仅作为线协议外形和事件命名的参考，不作为内部领域模型或兼容承诺。

这样每种上游协议只需要两条路径：

```text
Vulcan request -> provider request
provider events/response -> Vulcan events/response
```

转换复杂度随供应商和协议通道线性增长，不再形成任意协议之间的互转矩阵。

## 建议的规范结构

以下是语义结构，不是最终 Go 字段定义。

### 请求信封

```text
VulcanRequest
├── protocol_version
├── request_id
├── provider_instance_id
├── model_selection
│   ├── provider_model_id
│   └── execution_profile_id
├── items[]
├── tools[]
├── tool_policy
├── generation_policy
├── reasoning_policy
├── cache_policy
├── output_policy
└── extension_refs[]
```

`provider_instance_id` 在一次执行内不可变。模型和规格使用供应商作用域 ID，不按全局模型名称融合。

### 上下文项目

建议使用封闭的 tagged union：

- `instruction`：带明确权限、位置和生效范围的系统或开发者指令；
- `message`：用户、主助手或其他消息生产者的会话消息，包含有序内容块；
- `delegated_result`：子代理或委派任务的独立结果，保留委派父级和可见性；
- `reasoning`：可见摘要和不可见延续状态分离；
- `tool_call`：调用身份、工具身份、参数和状态；
- `tool_result`：显式引用 `tool_call_id`；
- `refusal`：拒绝内容及可公开原因；
- `provider_extension`：通过注册的类型、所有者和版本引用，不能使用无约束 `map[string]any`。

每个项目至少预留：

- `item_id`；
- `origin`；
- `created_by`；
- `ordering_constraints`；
- `conversion_status`；
- `provider_state_ref`。

### 角色、指令权限与委派消息

不能把任一供应商的 `role` 字符串直接当作 Vulcan 的领域模型。`system`、`developer`、`user`、`assistant`、`tool` 既可能表示指令优先级，也可能表示内容生产者或线协议中的序列位置；“子代理消息”还额外表达委派关系。把这些含义压缩成一个枚举，会在协议投影时丢失安全边界或时序。

每个上下文项目应将以下维度分开保存：

```text
ContextItemSemantics
├── kind: instruction | message | delegated_result | reasoning | tool_call | tool_result | refusal
├── authority: system | developer | user | assistant | tool | none
├── actor: platform | application | end_user | primary_assistant | delegated_agent | tool | provider
├── placement: preamble | transcript
├── activation: request_start | after_item_id
├── visibility: model | client | audit_only
├── parent_item_id: OptionalItemID
├── delegation_id: OptionalDelegationID
├── ordering_constraints[]
├── origin
└── source_role_reference
```

- `authority` 表示内容在源会话中声明的指令权限，不能在转换后被静默提升；不同目标的实际优先级由对应 Execution Profile 明确声明，Core 不假定所有供应商对 `system` 与 `developer` 的优先级相同。
- `actor` 表示内容由谁产生。它与权限不同：子代理可以产生重要报告，但其输出不是系统或开发者指令。
- `placement` 与 `activation` 表示指令何时开始生效。第二个或中途的 system 指令不能与首个顶层 system 合并后仍宣称等价，因为其作用时机已改变。
- `parent_item_id`、`delegation_id` 与 `ordering_constraints` 保存工具、委派和会话项目之间的因果关系；这些关系不能用文本标签代替。
- `source_role_reference` 仅用于审计和同源精确回放，不能成为跨协议执行时的唯一判断依据。

`instruction`、`message` 与 `delegated_result` 应分别有明确语义：

```text
InstructionItem
├── authority: system | developer
├── placement: preamble | transcript
├── activation
├── content[]
└── instruction_scope

MessageItem
├── authority: user | assistant
├── actor: end_user | primary_assistant | delegated_agent
├── content[]
└── reply_to_item_id: OptionalItemID

DelegatedResultItem
├── delegation_id
├── parent_item_id
├── producer: delegated_agent
├── result_kind: report | task_output | tool_backed_result
├── visibility
└── content[]
```

`delegated_result` 是对“子代理反馈”的规范表达，不能先假定某个 OpenAI 公共 API 存在同名 `role`。在拿到真实请求/响应样本或官方协议定义前，适配器不得把未证实字段硬编码为 `subagent` role；如目标协议有精确类型，则注册为该类型的原生投影，否则按下述策略做显式降级。

#### 角色投影规则

每个 Provider Channel 必须发布 `RoleProjectionCapability`，而不是只发布“支持哪些 role”：

```text
RoleProjectionCapability
├── accepted_authorities[]
├── accepted_placements[]: preamble | transcript
├── multiple_instruction_segments
├── preserves_instruction_order
├── authority_precedence
├── delegated_result_projection: native | tool_result | message | unsupported
├── instruction_projections[]
│   ├── source_authority
│   ├── source_placement
│   ├── target_representation
│   ├── conversion_status
│   └── explicit_opt_in_required
└── reserved_marker_escaping
```

适配器只能选择已声明的投影，且必须满足以下规则：

1. 只有权限、位置、生效时机和因果关系均保持时，才能记录为 `preserved` 或 `normalized`。
2. 目标可原生表示顶层 system/developer 时，首个或同为前置范围的指令可以原生投影；是否可保留多个指令段及其顺序由能力声明决定。
3. 目标只接受顶层 system、而源会话在中途出现 system/developer 时，默认 `rejected`。可选的 `emulate_as_user_reminder` 只能在客户端明确授权后启用，并必须记录为 `emulated`；它不能用于依赖真实高权限边界的安全策略。
4. `hoist_to_preamble` 会扩大指令的生效范围或改变时序，也只能显式授权并记录为 `emulated`，不得作为默认优化。
5. 对以用户文本承载的 reminder，保留标记必须进行保留标记转义，并且不得让该标记在下一次转换时被误识别为真实 system/developer 项目。
6. `delegated_result` 优先投影为目标的原生委派结果；仅当其与某工具调用具有明确父级关系时，才可以按声明投影为 tool result；投影为普通消息同样是 `emulated`。
7. 无论投影到何种目标表示，子代理、工具和供应商产生的内容都不得提升为 system 或 developer 权限。

OpenAI Chat 形态可在其目标通道确实支持时原生承载会话内的 system/developer 消息；但“GPT 兼容”并不等于完整支持，必须由该自定义供应商通道声明。OpenAI Responses 使用类型化 input/output item，不能把 `instructions` 误当作完整历史消息转录；它是当前 response 范围的指令，是否能够替代某一规范项目必须由该通道的请求生命周期声明。Anthropic Messages 的顶层 `system` 可承载前置指令，但会话中途的高权限指令不能因此被宣称为原生等价；CLIProxyAPI 当前把这类内容包装为 `<system-reminder>` 用户内容，正是本提案定义的显式有损仿真，而不是可复用的默认事实。

角色投影计划必须在缓存断点和请求签名计算前冻结。缓存身份至少包含项目种类、权限、位置、生效锚点、父级关系、目标投影规则版本和实际目标表示；不能只按拼接后的文本复用缓存，否则不同权限或时序的提示词可能发生错误共享。

### 内容块

建议支持：

- text；
- image；
- audio；
- video；
- file/document；
- citation/annotation；
- refusal；
- registered extension。

媒体内容应使用资源引用，保留 MIME、尺寸、文件名、来源和完整性摘要。不得通过构造文本描述来冒充原媒体内容。

### 工具调用

建议的稳定字段包括：

- Vulcan 生成的稳定 `tool_call_id`；
- 上游原始 ID 和 ID 来源；
- 工具定义 ID、显示名称、上游名称、命名空间；
- 工具种类：function、custom、provider_builtin；
- 参数编码：JSON、text 或注册编码；
- 原始参数增量字节和最终解析结果；
- 状态：pending、streaming、completed、invalid、cancelled；
- 与 tool result 的显式引用；
- ID 或名称映射记录。

如果上游缺少 ID，可以合成 Vulcan ID，但必须标记 `id_origin = synthesized`。如果只能用 FIFO 推断关系，必须生成降级诊断，供日志、测试和客户端策略判断。

### 流式事件

建议的基础事件：

- `response.started`；
- `item.started`；
- `content.started`；
- `content.delta`；
- `content.completed`；
- `item.completed`；
- `usage.updated`；
- `warning.raised`；
- `response.completed`；
- `response.incomplete`；
- `response.failed`；
- `response.cancelled`。

每个事件至少包含：

- 协议版本；
- response ID；
- 全局单调 sequence；
- event ID；
- item ID 和 item index；
- content index；
- 事件时间；
- 是否为可重放事件；
- 可选供应商事件指纹。

事件 reducer 必须满足：

1. 同一合法事件序列总能得到相同最终响应。
2. 完成的项目不会被后续重复 done 破坏。
3. 终态缺少 aggregate output 时仍可由项目事件重建。
4. 缺少终态时输出 `response.incomplete`，不能伪装成功。
5. 终态后传输关闭不改变已确认终态。
6. 重复事件可根据 event ID 或供应商指纹去重。

### usage 观测

建议将每个 token 数表示为“可知值”，不能用零替代未知：

```text
UsageObservation
├── input_tokens: OptionalInt
├── output_tokens: OptionalInt
├── reasoning_tokens: OptionalInt
├── cache_read_tokens: OptionalInt
├── cache_creation_tokens: OptionalInt
├── cache_creation_breakdown[]
├── total_tokens: OptionalInt
├── source: provider_reported | local_exact | local_estimate | derived
├── aggregation: delta | cumulative | snapshot
├── phase: preflight | streaming | terminal | billing
├── final
├── accounting_basis
└── provider_scope
```

其中 `accounting_basis` 必须描述供应商的输入口径，例如：

- input_excludes_cache_read_and_creation；
- input_includes_cache_read；
- input_includes_all_prompt_tokens；
- provider_defined；
- unknown。

Core 只有在口径已知时才能推导总输入。不得假设：

```text
input_tokens = uncached_tokens + cache_creation_tokens + cache_read_tokens
```

`cache_creation_breakdown` 用于保留 TTL 或计费等级，例如 Anthropic 的 5 分钟与 1 小时缓存创建 token。`cache_write_tokens` 只可作为上游字段别名映射到 `cache_creation_tokens`，不作为 Vulcan 公共名称。

专用 token count 应返回独立的 `TokenCountResult`，包括：

- 是否支持；
- 精确或估算；
- tokenizer/供应商来源；
- 输入计数；
- 计算时间；
- 对应的模型和执行规格；
- 不确定性或失败原因。

流中 token checkpoint 也是 usage observation，但 `final = false`。不支持 checkpoint 的供应商应明确发布“不支持”，而不是持续返回零。

### 上下文缓存策略与观测

缓存能力声明、请求侧缓存意图和响应侧缓存事实必须分开建模。

#### 模型与执行规格声明

缓存能力不是全局协议能力，必须发布在供应商作用域的模型和执行规格上。最终能力由 Provider Definition、Channel、Provider Model、Execution Profile 和账号授权共同解析：

```text
ContextCacheCapability
├── availability: supported | unsupported | conditional | unknown
├── default_behavior: none | implicit | provider_managed | unknown
├── disable_supported
├── request_strategies[]
│   ├── regular
│   ├── disabled
│   ├── stable_prefix
│   ├── rolling_per_turn
│   └── manual_breakpoints
├── breakpoint_granularity[]: request | message | content_block
├── max_breakpoints: OptionalInt
├── ttl_options[]
├── min_cacheable_tokens: OptionalInt
├── cacheable_content_types[]
├── isolation_scope
├── usage_reporting
│   ├── creation_tokens
│   ├── read_tokens
│   └── ttl_breakdown
└── conditions[]
```

`conditions` 可引用模型版本、执行规格、套餐、账号授权、区域和协议通道。不能因为同名模型在另一个供应商或另一个套餐支持缓存，就把能力合并到当前模型。

能力查询 API 应返回 `available_strategies`、`default_strategy` 和每种策略的可用性。如果同一供应商账号池中只有部分凭据支持某种缓存策略，应返回 `conditional` 以及可用凭据数量，不应简单取全集或交集。请求指定策略后，凭据选择器先按该策略过滤，再在同一供应商的合法凭据中容灾。

#### VulcanCode 请求策略

建议请求侧使用：

```text
CachePolicy
├── strategy: regular | disabled | stable_prefix | rolling_per_turn | manual_breakpoints
├── requested_ttl: OptionalDuration
├── breakpoints[]
│   ├── item_id
│   ├── content_index
│   └── requested_ttl
├── on_unsupported: reject | use_regular
└── loss_policy
```

公共 API 不使用 `cache_enabled` 和 `create_every_turn` 两个布尔值，因为它们可以产生互相矛盾的组合。`strategy` 的语义为：

- `regular`：常规调用。Vulcan 不主动添加显式缓存标记，允许供应商执行默认或隐式缓存。这是 API 字段缺省时的默认值。
- `disabled`：要求不使用缓存。只有能力声明 `disable_supported = true` 时才合法；它与 `regular` 不同。
- `stable_prefix`：Vulcan 在稳定前缀边界请求显式缓存，适合固定 system、tools、项目说明或长文档。后续请求继续使用同一逻辑边界。
- `rolling_per_turn`：每次请求都在最新一个完整会话回合之后放置或推进缓存断点，使可缓存前缀随会话增长。这对应 VulcanCode 的“每回合创建缓存”选项。
- `manual_breakpoints`：VulcanCode 显式指定一个或多个项目/内容块断点，只在模型声明支持的粒度和数量内生效。

“每回合创建”表示每回合都向上游请求创建或推进缓存，并不保证供应商一定创建成功。真实结果仍以 `CacheObservation.creation_tokens` 为准。可能出现只命中、创建并命中、未达到最小长度或供应商没有报告结果等情况。

`on_unsupported` 默认必须是 `reject`。只有 VulcanCode 明确选择 `use_regular` 时，Core 才能把不支持的显式策略降级为常规调用，并在 `ConversionReport` 中记录降级。

百炼部分模型的隐式缓存自动启用且不能关闭，因此如果客户端要求 `disabled`，而目标通道无法满足，适配器必须返回 capability conflict，不能假装已经关闭。选择 `regular` 时则可以继续使用供应商隐式缓存。

缓存策略应随每个请求完整发送。VulcanCode 可以在会话设置中保存用户默认选择，但 Core 不依赖未声明的会话级隐式状态。这样请求重放、审计和容灾时可以确定当时实际要求的缓存策略。

API 示例：

```json
{
  "cache": {
    "strategy": "regular"
  }
}
```

```json
{
  "cache": {
    "strategy": "rolling_per_turn",
    "requested_ttl": "5m",
    "on_unsupported": "reject"
  }
}
```

```json
{
  "cache": {
    "strategy": "disabled",
    "on_unsupported": "reject"
  }
}
```

#### 响应观测

建议响应侧使用：

```text
CacheObservation
├── requested_mode
├── effective_mode: implicit | explicit | provider_managed | unknown
├── outcome: created | read | created_and_read | miss | not_eligible | unknown
├── creation_tokens: OptionalInt
├── read_tokens: OptionalInt
├── creation_breakdown[]
│   ├── ttl
│   ├── billing_class
│   └── tokens
├── scope: account | workspace | organization | model | provider_defined
├── expires_in: OptionalDuration
├── source
└── final
```

一次请求中 `creation_tokens > 0` 和 `read_tokens > 0` 可以同时成立，前端应同时显示“命中已有缓存”和“创建新缓存”，不能把它压缩成单一 hit/miss 布尔值。

当供应商只返回 token 统计但不返回真实 TTL、scope 或创建完成时间时，对应字段保持 unknown。Core 不应根据配置中的 TTL 推断上游一定成功创建了缓存。

流式协议可通过 `usage.updated.cache` 携带 `CacheObservation`。如果供应商在流开始事件中报告缓存用量，应保留其 phase；最终 usage 到达后再发布 `final = true` 的观测。这样 VulcanCode 可以实时展示“本轮正在使用/创建缓存”，同时以最终观测作为计费依据。

### 推理延续状态

reasoning 文本或摘要与供应商延续状态必须分离。延续状态应使用不可解释的 sealed reference：

```text
ProviderContinuation
├── owner_provider
├── channel
├── model_family
├── scope_policy
├── session_scope_hash
├── schema_version
├── expires_at
└── encrypted_payload_ref
```

具体凭据是否属于 scope 由 Provider Driver 明确定义。Core 不应默认跨凭据共享，也不应默认永不共享。签名不兼容、过期或上游声明无效时，Driver 必须返回明确的失效原因并清理对应状态。

### 错误信封与重试建议

建议错误类别至少包括：

- authentication；
- permission；
- model_not_found；
- model_not_entitled；
- account_balance_exhausted；
- plan_window_exhausted；
- transient_rate_limit；
- provider_capacity；
- context_length_exceeded；
- invalid_request；
- invalid_tool_schema；
- invalid_continuation；
- content_policy；
- upstream_protocol；
- transport；
- cancelled；
- unknown。

错误信封还需要：

- HTTP/上游原始状态；
- 供应商代码和安全摘要；
- 分类规则版本和命中证据；
- 作用域：request、model、credential、plan、endpoint、provider；
- 恢复时间或 reset window；
- 是否已经向客户端提交语义输出；
- 建议动作。

建议动作使用封闭枚举：

- retry_same_credential；
- try_other_credential_same_provider；
- try_other_endpoint_same_provider；
- try_other_plan_same_provider；
- retry_after；
- compact_context；
- choose_other_profile；
- refresh_auth；
- do_not_retry。

不得出现跨供应商建议。已经提交工具调用或可见内容后，除非协议具备幂等恢复依据，否则不能自动重放整个请求。

## 必须预留的能力描述

供应商、模型和执行规格需要发布可协商能力，至少包括：

### 工具能力

- 是否支持 function/custom/provider built-in tools；
- 是否支持并行调用；
- 最大工具数和最大参数大小；
- JSON Schema 支持子集；
- 是否保证原生调用 ID；
- 是否支持流式参数；
- 工具结果允许的内容块类型。

### 流式能力

- SSE、WebSocket 或非流式；
- 是否提供 item/content 生命周期；
- 是否提供 usage checkpoint；
- usage 是 delta 还是 cumulative；
- 是否保证合法终态；
- 最大单事件大小；
- 是否支持取消、续传或幂等请求键。

### 上下文能力

- 支持的输入角色、权限等级及其目标侧优先级；
- 指令可放置的位置：仅前置、会话内或两者；
- 是否支持多个指令段、是否保持它们的相对顺序和生效范围；
- system/developer 投影的精确保真级别及允许的降级方式；
- 是否原生支持委派结果、可投影为工具结果还是只能模拟为普通消息；
- 支持的内容块；
- assistant prefill 支持；
- 工具调用与结果的邻接要求；
- cache control 粒度；
- 缓存模式：隐式、显式、供应商自动或不可关闭；
- 缓存断点粒度：请求、消息或内容块；
- 最大断点数、可选 TTL、最小可缓存 token 和可缓存内容类型；
- 缓存隔离作用域和模型间是否共享；
- 是否报告创建、读取和 TTL 细分用量；
- 推理历史和签名要求；
- 结构化输出；
- compaction；
- 模型规格对应的上下文上限。

### 能力不是布尔值

建议采用：

- supported；
- unsupported；
- emulated；
- conditional；
- unknown。

`conditional` 必须附带条件，例如套餐、账号授权、模型规格、通道或区域。这样才能表达 Kimi K3 不同套餐对应不同模型授权和上下文上限，也能表达 Codex 特定账号不下发某些模型。

## 无损转换与降级策略

每次请求适配应产生内部 `ConversionReport`：

- preserved：语义完整保留；
- normalized：只做等价规范化；
- emulated：通过提示词或其他结构模拟；
- dropped：目标不支持而删除；
- rejected：为避免语义错误而拒绝；
- synthesized：生成了 ID 或默认值；
- ambiguous：只能通过顺序或启发式推断。

对 `emulated`、`dropped`、`rejected` 或 `ambiguous` 的角色投影，报告还必须记录源项目种类、源权限、源位置与生效锚点、目标表示、规则版本和产生的语义差异；不得只输出“role converted”之类无法审计的摘要。

默认策略应为：

1. 工具身份、工具因果关系、指令权限与生效时机、媒体内容和供应商延续状态发生不可接受损失时拒绝请求。
2. 只有客户端或 Provider Driver 明确允许时才执行 emulated/dropped/ambiguous。
3. 所有降级都可观测，但日志默认不得包含提示词、工具参数、签名和媒体内容。
4. 不允许在缺少转换器时原样透传未知协议。

## 传输层预留

Vulcan 语义事件应独立于具体传输。SSE 解码器需要处理：

- 任意网络分片边界；
- `LF` 和 `CRLF`；
- 多行 data；
- event、id、retry 和注释行；
- UTF-8 字符跨分片；
- 最大帧限制；
- 背压与取消；
- EOF 前未完成事件；
- `[DONE]` 和供应商自定义终止标记。

WebSocket 解码器负责帧和连接语义，但产出同一组 Vulcan 事件。HTTP 连接建立后的读取策略由供应商通道控制，不能为了整齐而给长推理输出增加固定总超时。

## 不应复制的 CLIProxyAPI 结构

1. 不复制任意协议之间的成对转换矩阵。
2. 不使用原始 JSON 字节作为内部唯一真相。
3. 不使用 `param *any` 保存流式状态。
4. 不在缺失转换器时静默原样透传。
5. 不把系统指令模拟成用户文本而不报告损失。
6. 不把合成调用 ID、FIFO 配对或名称重写隐藏起来。
7. 不把估算 token 当作供应商精确 usage。
8. 不让每个转换器自行发明一套 start/delta/done 状态机。
9. 不把供应商推理签名当作跨供应商通用字段。
10. 不把 HTTP 429 直接等同于某一种容灾策略。

## 应转换成回归夹具的历史问题

首批规范测试应覆盖：

### 工具

- ID 缺失、延迟、过长和重复；
- 名称缺失、延迟、null 和命名空间冲突；
- 多调用并行、交错和多批次；
- 参数跨任意分片；
- 只有工具调用的响应；
- 终态补全未决调用；
- 调用与结果不匹配；
- tool schema 子集不兼容；
- custom 和 provider built-in 工具。

### 流

- 文本、推理和工具交错；
- usage-only 分片；
- 空终态 output 的项目重建；
- incomplete 和 failed；
- 未收到终态的 EOF；
- 完成后的 transport error；
- 重复 done；
- 超大事件和 WebSocket message too big；
- SSE 多行 data、CRLF 和 UTF-8 跨分片。

### 上下文

- 首个、多个及会话中途出现的 system/developer 指令；
- 指令前置提升、用户 reminder 仿真和严格拒绝三条路径；
- 同文本但不同权限、位置或生效锚点不得共享缓存；
- 子代理委派结果的父级关联、可见性和禁止权限提升；
- 用户文本伪造 reminder 保留标记时的转义与回转；
- reasoning-only 历史；
- reasoning 与助手输出合并顺序；
- 工具调用与结果邻接；
- assistant prefill；
- 内容块级 cache control；
- 图像、音频、视频和文件；
- 供应商签名兼容、过期和失效。

### usage 与错误

- unknown、零、null、估算和精确值；
- delta 与 cumulative；
- cache creation/read 口径；
- 同一轮既命中旧缓存又创建新缓存；
- 显式、隐式、供应商自动和不可关闭缓存；
- `regular`、`disabled`、`stable_prefix`、`rolling_per_turn` 和手动断点策略；
- 账号池只有部分凭据支持指定缓存策略；
- 不支持策略时严格拒绝和客户端授权降级两条路径；
- 缓存创建按 TTL 或计费类别拆分；
- Anthropic 与百炼不同的 input token 归集公式；
- 套餐窗口耗尽、余额不足、瞬时限流和容量不足；
- 上下文超限；
- 流内错误和 HTTP 错误；
- 输出提交前后不同的重试边界。

## 分阶段落地建议

### 阶段一：冻结语义，不接供应商

1. 确认本提案的协议方向。
2. 编写 Vulcan request、item、权限/角色投影、content、tool、event、usage、error 的正式规范。
3. 定义未知字段、扩展注册、版本协商和降级规则。
4. 定义 reducer 不变量和测试夹具格式。

### 阶段二：实现纯协议内核

1. 实现类型化 Go 领域对象。
2. 实现事件 validator 和 reducer。
3. 实现 SSE/WebSocket 传输解码边界。
4. 实现 ConversionReport、UsageObservation 和 ErrorEnvelope。
5. 使用人工夹具完成属性测试和乱序/分片测试。

### 阶段三：单协议纵向验证

先选择一个供应商通道，只实现：

```text
Vulcan request -> upstream request
upstream stream -> Vulcan events -> final response
```

验证工具、上下文、reasoning、usage、错误和取消后，再接入第二种协议。第二个协议的目标是证明规范模型确实消除了成对转换，而不是快速增加供应商数量。

### 阶段四：供应商语义

在规范协议稳定后接入 Provider Driver 的：

- 套餐和模型授权；
- 多凭据与同供应商容灾；
- 额度窗口和余额；
- 错误分类与 RetryAdvisor；
- 模型规格和上下文能力发布。

## 待确认决策

进入实现前需要确认：

1. 接受“Vulcan 自有规范协议，Responses-like 但不兼容 OpenAI Responses”这一方向。
2. 接受“流式事件日志是最终响应的权威来源，终态 aggregate 只是快照”这一方向。
3. 接受“默认拒绝关键语义损失，降级必须显式报告”这一方向。
4. 接受“usage 的未知、估算、推导、供应商报告分别建模”这一方向。
5. 接受“推理延续状态由 Provider Driver 封装和定作用域，不作为通用可移植内容”这一方向。
6. 接受“缓存创建、缓存读取和普通输入分别建模，并保留供应商计费口径与 TTL 明细”这一方向。
7. 接受“缓存策略由模型/执行规格声明，VulcanCode 每个请求显式选择，账号池按策略先过滤凭据”这一方向。
8. 接受“角色拆分为项目种类、指令权限、内容生产者、位置/生效时机和因果关系，而不是单一 role 枚举”这一方向。
9. 接受“中途高权限指令与子代理结果默认不静默降级；前置提升、用户 reminder 与普通消息投影均须显式授权并记录转换损失”这一方向。

确认后再创建正式协议 Schema 和 Go 类型，避免在核心协议层提前固化错误假设。

## 外部协议依据

- Anthropic Prompt Caching：<https://platform.claude.com/docs/en/build-with-claude/prompt-caching>
- Anthropic Tool Use with Prompt Caching：<https://platform.claude.com/docs/en/agents-and-tools/tool-use/tool-use-with-prompt-caching>
- Anthropic Messages API：<https://platform.claude.com/docs/en/api/messages>
- OpenAI Responses 迁移指南（message 与类型化 item）：<https://developers.openai.com/api/docs/guides/migrate-to-responses#2-map-messages-to-items>
- OpenAI 消息角色与指令优先级：<https://developers.openai.com/api/docs/guides/text#message-roles-and-instruction-following>
- 阿里云百炼 Context Cache：<https://help.aliyun.com/zh/model-studio/context-cache>
- 阿里云百炼显式缓存最佳实践：<https://help.aliyun.com/zh/model-studio/explicit-cache-guide>

## 分析验证记录

本次分析完成后，针对关键结论执行了 CLIProxyAPI 当前基线的聚焦回归测试：

- `go test ./internal/translator/openai/openai/responses`：34 项通过；
- `go test ./internal/translator/claude/openai/responses`：16 项通过；
- `go test ./internal/translator/codex/claude`：70 项通过；
- Codex 空终态输出重建、incomplete、缺失终态和流式重建聚焦测试：4 项通过。

这些测试验证了本文引用的工具调用事件链、Claude→Responses 状态归并、Codex→Claude 未决工具水合和 Codex 终态处理行为确实存在于最新基线中。
