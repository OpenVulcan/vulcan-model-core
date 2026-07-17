# CLIProxyAPI `system-reminder` 与提示词角色转换审计记录

## 审计结论

CLIProxyAPI 中显式的 `<system-reminder>` 只有一条公共构造链：一个 helper、四个协议转换调用点，以及 Claude 执行器中的一条运行时 cloaking 注入路径。但“把高权限提示词改写为较低权限文本”并不只发生在这个标签上；当前基线还存在无标签的 user 降权、顶层前置合并、`system` 到 `developer` 的角色投影、固定系统指令注入、连续响应时删除 instructions、敏感词字符级改写，以及按角色决定推理回放位置等行为。

因此，`<system-reminder>` 不能被当成一个可孤立复制的格式技巧。它是多种有损提示词投影中的一种，必须和权限、位置、生效时机、来源以及工具/委派关系一起审计。

本记录只陈述已从源码确认的当前行为，不把这些行为认定为 Vulcan Core 的目标设计。

## 审计范围与基线

- 上游仓库：`D:\openvulcan\third_git\CLIProxyAPI`
- 审计基线：`9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66`
- 基线描述：`v7.2.74-24-g9f4f53ca`
- 审计日期：2026-07-17
- 检索范围：`internal/translator/**` 与 `internal/runtime/executor/**` 的生产 Go 代码；相关测试仅作为行为证据。
- 检索维度：`system-reminder`、提醒 XML 标签、`system/developer` 角色条件、`instructions` / `systemInstruction` / `system_instruction` 字段、前置/合并/重建逻辑、固定系统指令注入、敏感词改写、缓存断点注入、连续响应的 instructions 删除，以及 `subagent` / `delegation` 等委派词汇。

以下分类用于避免混淆：

- **原生投影**：目标存在相应的顶层或等价角色结构；仍需由目标协议能力确认优先级是否等价。
- **前置合并**：保留文本但把会话内指令搬到请求前置位置，必然改变生效时机。
- **文本仿真**：用普通 user 内容和标签提示模型把文本当作系统上下文，权限不再由协议保证。
- **直接降权**：改为 user/user_input 而不加提醒包装。
- **运行时 cloaking**：为上游识别、计费或指纹规避而改写请求，不是协议语义转换。

## 一、显式 `<system-reminder>` 链

### 1. 公共构造 helper

文件：`internal/translator/common/claude_system.go`

- `ClaudeMessageSystemReminderText`（第 15 行）接收 Claude 会话 `messages[]` 中 `role=system` 的内容。
- 仅保留字符串内容或数组中 `type=text` 的内容块；非文本块被忽略。
- `util.IsClaudeCodeAttributionSystemText` 判定为 Claude Code attribution 的文本会被忽略。
- 非空文本被拼接为：

```text
<system-reminder>
{text}
</system-reminder>
```

- 该 helper 不返回来源角色、原始位置、丢弃内容、转换原因或损失等级。
- 未发现保留标签转义或反转义逻辑。用户文本本身含有同名标签时，系统没有可验证的来源区分。

### 2. 四个调用点

#### 2.1 Claude → OpenAI Chat

文件：`internal/translator/openai/claude/openai_claude_request.go`

- `ConvertClaudeRequestToOpenAI` 在第 145–151 行识别会话内 `role=system`。
- 调用公共 helper 后，创建 `role=user` 的 OpenAI Chat 消息。
- 顶层 Claude `system` 则在第 132–138 行投影为顶层/首个 Chat `system` 消息。
- 分类：会话内 system 为**文本仿真**；顶层 system 为原生形态投影。

测试证据：`internal/translator/openai/claude/openai_claude_request_test.go` 第 360 行的 `TestConvertClaudeRequestToOpenAI_MessageSystemRoleWrapsAsUserReminder`。

#### 2.2 Claude → Gemini

文件：`internal/translator/gemini/claude/gemini_claude_request.go`

- 顶层 Claude `system` 在第 39–63 行进入 Gemini `system_instruction`。
- 会话内 `role=system` 在第 75–90 行先改为 Gemini `role=user`，再写入 `<system-reminder>` 文本。
- 分类：会话内 system 为**文本仿真**。

测试证据：`internal/translator/gemini/claude/gemini_claude_request_test.go` 第 110 行的 `TestConvertClaudeRequestToGemini_ConvertsMessageSystemRoleToUserContent`。

#### 2.3 Claude → Codex / Responses 形态

文件：`internal/translator/codex/claude/codex_claude_request.go`

- 顶层 Claude `system` 在第 50–80 行被创建为 Codex input 中的 `role=developer` 消息。
- 会话内 `role=system` 在第 91–97 行被创建为 `role=user` 的 `<system-reminder>` input。
- 分类：顶层 system 为 system→developer 投影；会话内 system 为**文本仿真**。

测试证据：`internal/translator/codex/claude/codex_claude_request_test.go` 第 105 行的 `TestConvertClaudeRequestToCodex_MessageSystemRoleWrapsAsUserReminder`。

#### 2.4 Claude → Antigravity

文件：`internal/translator/antigravity/claude/antigravity_claude_request.go`

- 顶层 Claude `system` 在第 318–345 行进入 `request.systemInstruction`。
- 会话内 `role=system` 在第 365–383 行变为 `request.contents[]` 的 `role=user`，文本由 helper 包装。
- 分类：会话内 system 为**文本仿真**。

测试证据：`internal/translator/antigravity/claude/antigravity_claude_request_test.go` 第 137 行的 `TestConvertClaudeRequestToAntigravity_ConvertsMessageSystemRoleToUserContent`。

### 3. 标签语义提示文本

文件：`internal/runtime/executor/helps/claude_system_prompt.go`

- 实际被 Claude cloaking 静态 prompt 使用的 `ClaudeCodeSystem`（第 15–20 行）说明：tool result 与 user message 中可能出现 `<system-reminder>`，且该标签携带系统信息。
- `ClaudeCodeSystemReminderSection`（第 63–65 行）包含相似文本，但当前只发现其定义，未发现生产调用点。
- 这说明上游通过提示词让模型“理解”标签，但标签不改变协议层的 role 或权限。

## 二、Claude 执行器的运行时改写

### 1. Cloaking：顶层 system → 首个 user 的标签文本

文件：`internal/runtime/executor/claude_executor.go`

- `checkSystemInstructionsWithSigningMode`（第 1878 行起）先保存原始顶层 `system`，然后把请求顶层 system 覆盖为 billing header、agent identifier 和 Claude Code 静态 prompt 三个块。
- 非 strict 模式下，第 1930–1955 行收集原始顶层 system 的文本并调用 `prependToFirstUserMessage`。
- `prependToFirstUserMessage`（第 1993–2042 行）把文本包进 `<system-reminder>`，插到**第一个** user message 的起始位置。
- OAuth 模式下，`sanitizeForwardedSystemPrompt`（第 1961–1972 行）不保留原始 system 内容，而是替换成固定的三行中性软件工程提醒。
- strict 模式不会把原始顶层 system 转发到 user；因此原始内容在该路径中不会继续作为用户提示词出现。

这是**运行时 cloaking**，目的在源码注释中明确为避免 OAuth 代理请求中的额外 usage billing 及第三方客户端识别；它不应被视为协议转换的通用方案。

调用位置：

- 普通请求：`Execute` 第 229–235 行，经 `applyCloaking` 触发；
- 流式请求：`ExecuteStream` 第 422–428 行，经 `applyCloaking` 触发；
- token 计数：`CountTokens` 第 709–715 行直接调用 `checkSystemInstructions`。

测试证据：`internal/runtime/executor/claude_executor_test.go` 第 2404、2438、2468、2486 行的 `TestCheckSystemInstructionsWithMode_*`。

### 2. 可选重建：会话内 system → 顶层 system

文件：`internal/runtime/executor/claude_executor.go`

- `rebuildMidSystemMessagesToTopLevel`（第 1195–1226 行）扫描全部 `messages[]`。
- 每个 `role=system` 的文本内容被从原位置移除，并追加到顶层 `system` 的末尾。
- 原消息的相对位置、生效时机和与相邻工具/助手回合的关系不再保留；非文本内容也不会作为同等语义转移。
- 该行为只在 `rebuildMidSystemMessageEnabled` 返回 true 时启用；配置字段为 `rebuild-mid-system-message`，属性开关为 `rebuild_mid_system_message=true`。
- 三条执行路径均在协议翻译后、cloaking 前调用：普通请求第 229–230 行、流式请求第 422–423 行、token 计数第 709–710 行。

分类：**前置合并**，且是显式 opt-in；默认关闭。

测试证据：`internal/runtime/executor/claude_executor_test.go` 第 2588 行的默认关闭测试，以及第 2629 行的 opt-in 重建测试。

### 3. Cloaking 敏感词改写：system 与消息文本的字节变化

文件：

- `internal/runtime/executor/claude_executor.go` 第 2044–2114 行；
- `internal/runtime/executor/helps/cloak_obfuscate.go` 第 13–160 行。

- `applyCloaking` 仅在 Cloak 模式生效后执行；凭据属性 `cloak_sensitive_words` 或 Claude Key 的 `sensitive-words` 配置会提供词表，并触发 `ObfuscateSensitiveWords`。
- 该 helper 同时遍历顶层 `system` 和 `messages[]` 中可处理的文本内容。每个命中的敏感词会在第一个 Unicode rune 之后插入零宽空格（`U+200B`），因此上游收到的文本字节与用户原始输入不同。
- 这不是角色转换，也不是安全隔离；它是供应商规避用途的内容改写。原始文本、改写文本和改写规则版本若不被明确记录，后续重试、请求签名、缓存命中和审计都会失去可比性。

分类：**运行时内容改写**。Vulcan Core 不应把它作为通用协议能力；若未来某个 Provider Driver 必须提供，必须显式声明、可关闭，并把应用后的表示作为独立执行产物。

测试证据：`internal/runtime/executor/claude_executor_test.go` 第 2685 行的 `TestApplyCloaking_PreservesConfiguredStrictModeAndSensitiveWordsWhenModeOmitted` 确认消息文本会出现零宽空格。

### 4. 自动 cache_control：不改文本，但会改写内容结构与缓存边界

文件：`internal/runtime/executor/claude_executor.go` 第 2117–2633 行。

- 在 cloaking 后，若请求中不存在任何 `cache_control`，`ensureCacheControl` 会依次为最后一个工具、最后一个顶层 system 元素和倒数第二个 user 回合注入 ephemeral 缓存断点。
- 当顶层 `system` 或目标 user 消息原本是字符串时，代码会把它改写成带有 `type=text` 与 `cache_control` 的内容块数组；文本与 role 不变，但 JSON 结构和缓存作用范围发生变化。
- 随后的 `enforceCacheControlLimit` 会把总断点限制为四个，`normalizeCacheControlTTL` 会按评估顺序调整不合法的 TTL 组合。因此缓存策略不是一个可脱离内容位置的布尔开关。

分类：**结构性缓存投影**。它不属于 `<system-reminder>`，但会改变 prompt cache 的前缀边界；Vulcan 的缓存指纹必须在角色投影、文本仿真和缓存断点策略全部确定后再计算。

## 三、无标签但同类的角色转换

### 1. OpenAI Chat → Claude：所有 system 前置化

文件：`internal/translator/claude/openai/chat-completions/claude_openai_request.go`

- `ConvertOpenAIRequestToClaude` 在第 171–202 行将每一个 Chat `role=system` 追加到 Claude 顶层 `system`。
- 不区分该 system 在会话中的原始位置，因此中途 system 也会前置化。
- `developer` 未在该 `switch` 中处理；该函数不会把它投影为 Claude 的明确高权限结构。

分类：system 为**前置合并**；developer 行为需要单独的兼容策略，不能假定与 system 等价。

### 2. OpenAI Chat → Gemini / Antigravity：system 与 developer 前置合并

文件：

- `internal/translator/gemini/openai/chat-completions/gemini_openai_request.go` 第 157–176 行；
- `internal/translator/antigravity/openai/chat-completions/antigravity_openai_request.go` 第 156–176 行。

行为：

- 当 Chat 消息数大于一时，所有 `system` 与 `developer` 的文本都按遍历顺序追加到目标 `systemInstruction`。
- 当只有一条 system/developer 消息时，代码把它当作普通 `role=user` 内容，而不是顶层 system instruction。
- 会话内出现的位置和每段指令的边界均不再可恢复。

分类：多消息场景为**前置合并**；单消息场景为**直接降权**。

### 3. OpenAI Chat → Interactions：system 与 developer 合并为一个顶层字符串

文件：`internal/translator/openai/interactions/chat-completions/openai_interactions_request.go`

- `appendOpenAIMessagesToInteractions`（第 33–56 行）收集所有 system/developer 文本，以换行拼接后写入 `system_instruction`。
- 原有位置、消息边界和内容块级元数据均不保留。

分类：**前置合并**。

### 4. OpenAI Responses → Gemini：system、developer 与 instructions 全部进入顶层 systemInstruction

文件：`internal/translator/gemini/openai/responses/gemini_openai-responses_request.go`

- 顶层 `instructions` 在第 29–34 行写入 `systemInstruction`。
- 每个 input `message` 的 `role=system` 或 `role=developer` 在第 124–149 行被追加到同一 `systemInstruction`。
- 这会将中途出现的高权限消息移动到请求前置位置。

分类：**前置合并**。

### 5. OpenAI Responses → Claude：instructions 或首个 system 变为 leading user

文件：`internal/translator/claude/openai/responses/claude_openai-responses_request.go`

- 顶层 `instructions` 在第 130–140 行直接写为 Claude `role=user` 的首条消息，未使用 `<system-reminder>`。
- 当 `instructions` 为空时，第 142–170 行会从 input 中提取首个 `role=system`，同样写为 leading user；后续 input 遍历会跳过 system 项目。
- 当前分支没有把这条降权写入 `ConversionReport`，也没有记录该 system 原本位于何处。

分类：**直接降权**。该函数对 developer 的处理没有明确的高权限投影分支，后续实现前必须以样本和测试确认其精确行为。

### 6. OpenAI Responses → Interactions：非 assistant message 默认成为 user_input

文件：`internal/translator/openai/interactions/responses/interactions_openai_responses_request.go`

- 顶层 `instructions` 在第 17–19 行写入 `system_instruction`。
- `appendResponsesInputItemToInteractions`（第 177–187 行）只把 assistant/model 识别成 `model_output`；其他 `message` role（包含 system/developer）使用 `user_input`。

分类：会话内 system/developer 为**直接降权**。

### 7. OpenAI Responses → OpenAI Chat：developer 变为 user

文件：`internal/translator/openai/openai/responses/openai_openai-responses_request.go`

- 顶层 `instructions` 在第 51–56 行成为 Chat `role=system`。
- input message 的 `role=developer` 在第 149–152 行被重写为 `role=user`；system 则不在该分支中改写。

分类：developer 为**直接降权**。

### 8. Gemini → Claude：顶层 system_instruction 变为 user

文件：`internal/translator/claude/gemini/claude_gemini_request.go`

- `system_instruction` 在第 227–247 行被创建成 Claude `role=user` 消息，而不是 Claude 顶层 `system` 字段。

分类：**直接降权**。

### 9. Claude / Interactions 的通用消息路径：未知高权限角色落到 user

文件：

- `internal/translator/interactions/claude/interactions_claude_request.go` 第 125–183 行；
- `internal/translator/claude/interactions/interactions_claude_request.go` 第 177–180 行；
- `internal/translator/gemini/interactions/interactions_gemini_common.go` 第 795–805 行；
- `internal/translator/antigravity/interactions/interactions_antigravity_request.go` 第 633–643 行。

行为：

- 这些通用消息/步骤转换器只对 assistant/model 和 user 做显式角色映射。
- 如果把 system/developer 放入其普通会话项目而非专用顶层 `system_instruction`，默认分支会生成 user/user_input 内容。
- 这不是显式 `<system-reminder>` 仿真，也没有转换损失记录。

分类：**直接降权**。这类路径是否属于各协议允许的输入，需要在 Vulcan 实现前用真实样本确认；无论是否常见，都不能把默认分支当作高权限语义保留。

## 四、专用运行模式中的强制提示词处理

这些路径不是通用 role 投影；它们只在特定功能、上游连接形态或模型能力条件下改变有效提示词，必须由 Provider Driver 的专用能力声明控制。

### 1. Claude → Antigravity：工具与思考同时启用时附加 interleaved-thinking 指令

文件：`internal/translator/antigravity/claude/antigravity_claude_request.go` 第 707–733 行。

- 当请求同时存在工具、已启用 thinking，且目标被识别为 Claude thinking 模型时，转换器会创建一段固定的 `interleavedHint`。
- 若已有 `request.systemInstruction`，该文本块被追加到最后；否则转换器会新建一个 `systemInstruction`。
- 该提示要求模型在工具调用之间和工具结果之后继续思考，并要求不要提及这一约束。它不是来自用户的 system、developer 或 user 内容。

分类：**供应商特定的系统指令注入**。Vulcan 必须将其记录为 driver 注入项，不能把它混入用户 system prompt，也不能在协议转换层默认启用。

### 2. Claude → Antigravity 原生 Web Search：以固定系统指令替换普通会话转换

文件：

- `internal/translator/antigravity/claude/antigravity_claude_request.go` 第 310–315 行；
- `internal/translator/antigravity/claude/web_search.go` 第 27、94–114 行。

- 仅当模型声明支持原生 Google Search、工具集合只含 Claude typed web-search，且 `tool_choice` 允许时，`ConvertClaudeRequestToAntigravity` 会提前返回独立的 `requestType=web_search` 请求。
- 该分支只从最后一个可用 user 消息提取 query，并注入固定的“search engine bot” `request.systemInstruction`。因为提前返回，普通转换路径中的顶层 `system`、会话内容和工具结构不会继续被投影到这个搜索请求。
- 这是把 Claude 工具调用改造成供应商检索 API 的专用请求，而不是将原会话无损转换为另一协议。

分类：**专用功能请求重建**。Vulcan 应把它建模为独立的 WebSearch execution mode，并向调用方报告原会话哪些字段未参与该上游请求。

测试证据：`internal/translator/antigravity/claude/antigravity_claude_request_test.go` 第 184 行的 `TestConvertClaudeRequestToAntigravity_MapsTypedWebSearchToIndependentSearchRequest`。

### 3. xAI Responses WebSocket：存在 previous_response_id 时删除 instructions

文件：`internal/runtime/executor/xai_websockets_executor.go` 第 1181–1194 行。

- `buildXAIWebsocketRequestBody` 在克隆请求、设置 `type=response.create` 与 `store=true` 后，若 `previous_response_id` 非空，会无条件删除 `instructions`。
- 这不是文本包装或角色改写，而是有状态的字段删除；下游请求中的顶层指令不会随该 WebSocket 上游请求发送。
- 上游测试将此行为作为兼容性要求验证，但该删除函数本身不保留“原 instructions 是否应由 previous response 继承”的语义证据。

分类：**连续响应的状态性指令删除**。Vulcan 必须把“沿用 previous response 上下文”与“本回合新 instructions 被拒绝/忽略”区分为显式策略，禁止静默丢弃。

测试证据：`internal/runtime/executor/xai_websockets_executor_test.go` 第 992 行的 `TestBuildXAIWebsocketRequestBodySetsStoreAndKeepsPromptCacheKey`。

## 五、相对保留的顶层投影

以下路径没有发现 `<system-reminder>` 或 user 降权，但仍需要供应商级能力声明来确认真实优先级：

- Claude 顶层 `system` → OpenAI Chat `system`、Gemini `system_instruction`、Antigravity `request.systemInstruction`、Codex `developer`、Interactions `system_instruction`；
- Gemini `systemInstruction` / `system_instruction` → OpenAI Chat `system`、Codex `developer`、Antigravity 的同义顶层字段；
- Interactions `system_instruction` → Claude 顶层 `system`、Codex `instructions`、Gemini/Antigravity `systemInstruction`、OpenAI Chat `system`、OpenAI Responses `instructions`；
- OpenAI Chat → Codex：`system` 在第 173–177 行变为 `developer`，保留在 input 序列中的位置；
- OpenAI Responses → Codex：`convertSystemRoleToDeveloper`（`internal/translator/codex/openai/responses/codex_openai-responses_request.go` 第 66–107 行）将 system message 就地改为 developer；
- Interactions → Codex：`interactionsCodexDefaultRole`（第 631–644 行）把 system/developer 显式映射为 developer。

“相对保留”不等于自动无损：不同供应商的 developer/system 真实优先级、多个指令段支持和 request-scoped instructions 生命周期仍必须由 Execution Profile 明确声明。

## 六、角色敏感但不直接改写文本的路径

文件：`internal/runtime/executor/codex_executor.go`

- `shouldInsertCodexReasoningReplayBefore`（第 671–681 行）遇到 developer/system 时禁止在其前插入 reasoning replay。
- 这不是 role 转换，但它证明角色会影响流式/重放后的项目顺序；因此内部模型不能把 role 仅作为显示字段。

## 七、明确排除项

- `internal/runtime/executor/antigravity_executor.go` 中曾出现 systemInstruction 注入片段，但目前全部是注释，不是可执行路径。
- `internal/runtime/executor/claude_executor_test.go` 中的 `<system-reminder>` cache-control 用例只是字节保真测试，不负责生成或投影提示词。
- `internal/runtime/executor/codex_executor.go` 的 `normalizeCodexInstructions` 只在 `instructions` 缺失或为 null 时补写空字符串；`codex_openai_images.go` 也只在内部图像请求模板中初始化空 `instructions`。二者都不改写已有用户指令。
- OpenAI Responses 的多个响应转换器会把原请求中的 `instructions` 回显到响应对象；它们不负责向上游投影或改写该指令，因此不列为有效 prompt 的变更路径。
- 在生产 Go 代码中未发现除 `<system-reminder>` 外的其他 reminder XML 标签生成器。
- 针对 `subagent`、`sub-agent`、`delegation`、`delegated`、`agent_result` 和 `child_agent` 的生产代码检索没有命中。当前 CLIProxyAPI 没有可复用的子代理/委派消息协议实现，不能据此推断任何通用 `subagent` role。

## 八、验证记录

对显式 reminder 链和 Claude 执行器路径执行了聚焦测试：

```text
go test ./internal/translator/openai/claude \
        ./internal/translator/gemini/claude \
        ./internal/translator/codex/claude \
        ./internal/translator/antigravity/claude \
        ./internal/runtime/executor
```

结果：`754 passed in 5 packages`。

## 九、对 Vulcan Core 的可继承结论

1. 不继承“看到 system 就改为 user”的隐式默认路径。
2. 不继承 cloaking；它属于供应商特定、凭据特定的运行时行为，且可能主动替换原始提示词。
3. `system-reminder` 只能是 Provider Driver 声明的显式 `emulated` 投影，不能是 Core 的默认转换规则。
4. 每次角色投影必须记录源权限、源位置、生效锚点、目标表示、规则版本和损失等级。
5. 中途 system/developer 的可选策略应为 `reject`、`emulate_as_user_reminder`、`hoist_to_preamble`；后两者必须由调用方显式授权。
6. 子代理输出应采用 `delegated_result` 等独立项目类型；不得因为目标不支持而静默降为 developer/system，也不得把子代理文本升级为高权限内容。
7. 角色投影完成后才计算缓存断点和请求签名；缓存身份必须包含权限、位置和投影规则版本。
8. Driver 注入的固定系统指令、敏感词改写、原生工具请求重建和连续响应字段删除都必须是显式 Execution Profile 策略，并在执行报告中写明触发条件、被替换/未转发字段及规则版本。
