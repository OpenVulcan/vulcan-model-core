# CLIProxyAPI 协议迁移与 VCP 适配完整方案

## 一、任务目标

在保持 VCP 为唯一规范真相、一次执行只绑定一个 Provider、禁止跨 Provider 自动降级的前提下，将 CLIProxyAPI 中已经经过长期验证的上游协议实现，以可追溯的本地代码迁移方式引入本项目。

本阶段的目标不是复制 CLIProxyAPI 的成对 Translator 矩阵，也不是新增 OpenAI、Gemini 或 xAI 的公共兼容 HTTP 入口；目标是建设下列上游 Profile 与 Provider 执行能力：

1. 完善既有 OpenAI Chat Completions Profile 的请求、非流式和 SSE 适配边界。
2. 新增 OpenAI Responses Profile。
3. 新增 xAI Responses Profile，并保留 xAI 特有工具、推理、搜索和压缩兼容行为。
4. 新增 Google AI Studio Gemini Profile，覆盖 generateContent、streamGenerateContent 与 countTokens。
5. 将每个 Profile 接入 Provider-scoped 执行链，使 VCP 请求只能在已解析的同 Provider Target 内执行。

## 二、已确认事实与约束

1. CLIProxyAPI 的 `LICENSE` 为 MIT License，允许复制、修改、分发和再许可，但所有复制或实质部分必须保留原版权与许可证声明；本次盘点固定来源 commit 为 `9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66`。
2. 本仓库的架构规则明确禁止将 CLIProxyAPI 作为 Go Module 或运行时依赖；因此只能迁入经过选择的本地源码，不能导入其 module、配置中心、服务端、认证管理器或 Translator 注册机制。
3. 本仓库已有 `internal/core` 的单 Provider Router、`internal/resolve.Target` 的精确 Target、`internal/providerconfig.ProtocolProfile` 的协议元数据边界，以及 VCP 与 OpenAI Chat 的纯转换层。
4. CLIProxyAPI 的协议能力分散在公共 Handler、成对 Translator、Provider Executor、认证和 WebSocket 代码中。它的 Handler/Translator 依赖 Gin、配置、认证、调度和原始 JSON 真相模型，不能整包搬入。
5. CLIProxyAPI 的关键参考位置已经确认：
   - OpenAI Chat/Responses Handler：`sdk/api/handlers/openai/`。
   - Google AI Studio Handler：`sdk/api/handlers/gemini/gemini_handlers.go`。
   - OpenAI-compatible、xAI、AI Studio Executor：`internal/runtime/executor/`。
   - 历史协议兼容与转换测试：`internal/translator/`、`internal/signature/`、对应 Executor 测试。

## 三、重大架构决策

### 3.1 复制策略：选择性源码迁移，不复制成对转换矩阵

允许直接复制的对象必须满足以下全部条件：

1. 它直接表达目标上游协议的 wire 格式、SSE 事件语法、端点构造、字段归一化或已证实的兼容缺陷修复。
2. 它的依赖闭包可被剥离为标准库、本项目既有类型或少量本地重写的辅助函数。
3. 它不要求 CLIProxyAPI 的全局配置、Gin、账号池、调度器、日志、插件、成对 Translator 注册或跨 Provider 回退。
4. 迁入后仍能由 VCP 的 Projection Ledger、Capability Plan、Lineage 和 ExecutionReport 表达其行为。

不得直接复制的对象：

1. `internal/translator/<协议A>/<协议B>` 的注册和路由层；它们会重新引入协议 A 到协议 B 的成对转换架构。
2. 公共 OpenAI、Gemini、Claude、Codex 兼容 Handler；本项目的公共 HTTP API 仍只能由 Vulcan 协议套件拥有。
3. CLIProxyAPI 的 OAuth、Token 文件、账号池、调度、重试、全局配置、日志和插件运行时；这些职责已有或应由本项目的 Provider、Credential、Secret、Resolve 与未来执行层拥有。
4. 使用未类型化 `map[string]any` 或任意 JSON 作为内部执行真相的状态机；迁入时必须落到 VCP 或某个 Profile 的封闭类型。

### 3.2 许可证与可追溯性

每次迁入必须同时完成：

1. 在仓库根目录新增或更新 `THIRD_PARTY_NOTICES.md`，保留 CLIProxyAPI 的完整 MIT 许可证文本、版权信息、来源仓库、固定 commit、迁入日期和文件清单。
2. 每个直接复制或实质改编的 Go 文件保留来源注释，说明来源路径、来源 commit、改编范围和本项目责任边界。
3. 在 `docs/architecture/` 新增迁移 ADR，记录“复制了什么、为何可以复制、剥离了哪些依赖、哪些行为仍仅作为测试证据”。
4. 为每个迁入文件建立来源清单，禁止无来源的大段复制。

### 3.3 VCP 与 Provider 的职责分割

```text
Vulcan Public API
        ↓
VCP Request / Capability Plan / Projection Ledger
        ↓
Protocol Profile（OpenAI Chat、Responses、xAI Responses、AI Studio）
        ↓
Provider-scoped Execution Driver
        ↓
Resolved Target（同 Provider 的 Channel / Endpoint / Credential / Model / Profile）
        ↓
Upstream HTTP、SSE 或 WebSocket
```

职责必须固定：

1. VCP 负责唯一真相、能力决策、可逆投影、Lineage、统一语义事件与客户端安全报告。
2. Protocol Profile 负责 VCP 与一个上游协议之间的 typed wire 编解码，不能查询凭据或选择其他 Provider。
3. Provider Driver 负责同 Provider 内的认证准备、端点调用、协议 Profile 选择、状态码分类和允许的同 Provider 重试。
4. Resolve 先产出不可变 Target；Profile 和 Driver 只能消费它，不能替换其 Provider Instance、Channel、Endpoint、Credential、Provider Model 或 Execution Profile。
5. 真实 HTTP、SSE 和 WebSocket 仅在 Driver/Transport 层发生；Profile 单元测试必须保持纯转换。

## 四、协议范围与迁移优先级

| 优先级 | 上游 Profile | 主要来源证据 | 首批能力 | 暂不纳入首批 |
| --- | --- | --- | --- | --- |
| P0 | OpenAI Chat Completions | OpenAI Handler、OpenAI Compat Executor、Chat 相关 Translator/测试 | 完善现有映射、SSE、工具、usage、结构化输出 | 图像/视频与公共兼容入口 |
| P0 | OpenAI Responses | Responses Handler、Responses Translator、Responses 相关签名与 SSE 测试 | input/output item、function call/output、reasoning、SSE、compact 能力模型 | WebSocket realtime、图像/视频生成 |
| P1 | xAI Responses | `xai_executor.go`、xAI 测试、xAI reasoning replay | function/custom tool、x_search、reasoning summary、同 Provider compact、SSE | xAI 图像/视频、WebSocket 会话 |
| P1 | Google AI Studio Gemini | Gemini Handler、`aistudio_executor.go`、Gemini Translator/测试 | generateContent、streamGenerateContent、countTokens、function call、safety、usage | Vertex AI、浏览器/WebSocket 专有认证路径 |
| P2 | Google Vertex、xAI WebSocket、OpenAI Realtime、媒体 API | 对应 Executor 与测试 | 仅在前四个 Profile 稳定后评审 | 不提前实现 |

## 五、完整实施阶段

### 阶段 A：来源冻结与兼容行为提取

1. 固定 CLIProxyAPI 的 Git commit，并生成协议来源矩阵：源文件、测试文件、依赖、字段、失败模式、目标 Profile、迁移方式。
2. 对每个候选源文件标记为“直接复制”“改编复制”“仅提取测试夹具”“仅作行为证据”。
3. 从现有测试和代码抽取兼容规则，不以猜测补全：工具 ID、延迟字段、SSE ordering、usage-only、finish_reason、reasoning signature、缓存、compaction、搜索、错误状态和重试边界。
4. 为每条规则标记证据等级：上游正式协议、CLIProxyAPI 测试、CLIProxyAPI 实现观察、待真实互操作验证。

验收：来源清单完整、许可证文件完整、每个目标 Profile 有字段/事件/失败模式矩阵。

### 阶段 B：建立可执行 Profile 与 Transport 边界

1. 在现有 `internal/protocol` 下定义只面向 VCP 的 Profile 编解码契约；不让 Profile 持有 Credential 或 HTTP Client。
2. 在 `internal/provider` 扩展同 Provider 执行契约，明确非流、流、取消、重试分类和安全日志边界。
3. 为 `providerconfig.ProtocolProfile` 补充可声明的 Profile 能力事实，禁止以实际请求探测未使用能力。
4. 建立 Target 到 Profile/Driver 的显式绑定表，拒绝 Provider、Channel、Profile 或 Model 不匹配。
5. 将现有 OpenAI Chat Profile 迁移到该契约，并保持全部第一阶段测试通过。

验收：单 Provider 不变量、Target 绑定、纯 Profile 测试、Transport mock 测试和错误分类测试全部通过。

### 阶段 C：OpenAI Chat 完整兼容收口

1. 以迁入或改编的 CLIProxyAPI 测试补齐 Chat 的历史兼容用例：系统提示词、developer 降级、工具 ID、并行工具、strict schema、usage-only、异常终态、SSE 字段缺失。
2. 对可安全表达的行为保留 native/projected/omitted/blocked 决策；不能安全表达的硬控制必须 blocked。
3. 仅在 Driver 中实现官方 OpenAI-compatible HTTP/SSE Transport；不新增对外 OpenAI HTTP 入口。

验收：与来源夹具的 golden 输出对齐；每个降级均体现在 Projection Ledger 或 ExecutionReport。

### 阶段 D：OpenAI Responses Profile

1. 新建 `internal/protocol/openai/responses`，使用封闭 input/output item、function call、function output、reasoning、refusal、usage 和 SSE event 类型。
2. 将 Responses 的 item 语义映射到 VCP ContextItem 和 Event，不能把 opaque reasoning/continuation 降为普通文本。
3. 抽取并改编 Responses 的关键逻辑：输出项状态机、晚到 usage、function call 参数累积、completed/incomplete/error、reasoning signature 校验。
4. `compact` 只先建立 CapabilityDemand 与同 Provider Driver 接口；没有经证实的 native 支持时必须 blocked，不伪造本地压缩。

验收：非流和流均可回放为确定 VCP Event 序列；历史输出不会被普通文本或伪造 Frame 提权。

### 阶段 E：xAI Responses Profile

1. 新建 `internal/protocol/xai/responses` 和 `internal/provider/xai` 的同 Provider Driver 实现。
2. 迁入并类型化 xAI 的工具兼容逻辑：无工具时移除 tool_choice/parallel_tool_calls、namespace function 名称、custom tool、内部 x_search 过滤、输出索引紧凑化。
3. 迁入并类型化 reasoning summary、reasoning effort、encrypted reasoning 输入清理、延迟 output item 和 SSE 完成补丁逻辑。
4. 只在已解析的 xAI Target 支持时暴露 native x_search 与 remote compaction；其他 Target 进入 omitted 或 blocked，绝不跨 Provider 替代。

验收：xAI 特有工具、推理、搜索和 compact 规则都能映射到 Capability Plan、Projection Ledger 和 ExecutionReport。

### 阶段 F：Google AI Studio Gemini Profile

1. 新建 `internal/protocol/google/aistudio` 和 `internal/provider/google` 的 AI Studio Driver。
2. 迁入并类型化 generateContent、streamGenerateContent、countTokens 的端点、请求、响应和 SSE 行为；将 contents、parts、systemInstruction、functionCall/functionResponse、safety 和 usage 映射到 VCP。
3. AI Studio 的 WebSocket、认证或请求格式兼容仅在有可复现来源测试时迁入；未证实部分必须保留为未实现能力。
4. Google AI Studio 与 Vertex AI 保持独立 Channel/Profile，禁止混用端点、凭据或身份语义。

验收：三种 API 动作均可通过 mock Transport 运行；安全拦截、函数调用、用量和流事件可确定归并。

### 阶段 G：差分验证与发布门禁

1. 将可公开且无密钥的 CLIProxyAPI 测试夹具转为本项目的 fixtures；保留来源注释，不引入 CLIProxyAPI 包依赖。
2. 对每个 Profile 建立同输入下的差分测试：请求 wire JSON、SSE 事件顺序、输出语义、CapabilityDecision、Projection Ledger 和安全错误码。
3. 建立最小 mock upstream 服务用于 HTTP/SSE，不进行真实 API Key、OAuth 或线上探测测试。
4. 每个 Profile 独立运行 `gofmt -w .`、`go test ./...`、`go vet ./...`、`go build -o test-output ./cmd/vulcan-model-core`。

## 六、兼容与推理反推方法

1. 先以正式协议文档定义 wire 合法性，再用 CLIProxyAPI 代码和测试补齐真实兼容行为；两者冲突时记录 ADR，不静默沿用历史 workaround。
2. 每个上游字段都建立四列表：来源字段、VCP 唯一归属、能力等级、失败策略。
3. 每个“反推”结论必须附带可执行证据：最小 fixture、来源测试名或上游文档；没有证据时标记为待确认，不能写 fallback 代码。
4. 将兼容规则分类为：协议必要、Provider 特有、历史 bug 防护、可选增强。只有前三类进入默认实现。
5. 对无法可逆恢复的上游专有字段，使用 VCP 的 provider_state_ref、Lineage 或显式 omitted/blocked；禁止伪装为普通文本成功。

## 七、风险与防护

1. 许可证风险：所有复制文件必须保留 MIT 归属；来源 commit 变更后必须重新审查。
2. 架构回退风险：禁止复制 Translator 注册矩阵和公共 Handler；CI 增加 import-boundary 测试，禁止 `internal/protocol` 导入 CLIProxyAPI 或其替代模块。
3. 凭据泄露风险：迁入 Executor 前先替换日志、错误和 header 处理；默认禁止记录 Token、prompt、工具参数和资源内容。
4. 协议漂移风险：每个 Profile 的能力通过 Catalog/ProtocolProfile 显式发布，不以运行时猜测支持度。
5. 规模风险：按 Profile 独立合并；任何一个 Profile 不得阻塞其他 Profile 的纯转换测试。

## 八、验收标准

1. 每个迁入文件均可追溯到 CLIProxyAPI 固定 commit，且许可证与来源通知完整。
2. VCP 仍是唯一内部真相，不存在协议 A 到协议 B 的运行时转换路径。
3. 每次执行的 Provider、Channel、Endpoint、Credential、Model、Profile 都不可变且可审计。
4. OpenAI Chat、OpenAI Responses、xAI Responses、Google AI Studio 的 Profile 均有纯转换、mock Transport、SSE 和失败模式测试。
5. 所有历史兼容行为都具有明确 native/projected/omitted/blocked 结果，不存在静默伪造。
6. 不新增公共兼容端点、不引入 CLIProxyAPI module/runtime dependency、不实现跨 Provider 自动降级。

## 九、需用户确认的重大事项

1. “对外访问协议”在本方案中按“对上游 Provider 的出站协议”理解，而不是新增面向客户端的 OpenAI/Gemini/xAI 兼容 HTTP 入口。若你希望后者，必须单独确认，因为它改变现有公共 API 架构约束。
2. 是否批准按上述 MIT 合规流程直接迁入和改编 CLIProxyAPI 的选定源码与测试夹具。
3. 是否批准优先级：OpenAI Responses → xAI Responses → Google AI Studio，并先建设 Profile/Driver 执行边界。
4. 是否批准将真实 HTTP/SSE Transport、认证注入和同 Provider 重试纳入下一阶段；这会改变当前“纯转换、无网络”的阶段边界。

在上述重大事项确认前，仅完成来源盘点、方案、ADR 草案和测试矩阵，不复制生产源码、不新增网络行为。
