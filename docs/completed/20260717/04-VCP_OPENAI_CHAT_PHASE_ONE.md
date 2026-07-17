# VCP 1.0 与 OpenAI Chat Completions 第一阶段协议实现计划

## 任务目标

在不改变既有 Provider、Catalog、Resolve、Credential 所有权边界的前提下，实现 VCP 1.0 的类型化协议基层，以及 VCP 与 OpenAI Chat Completions Profile 之间的纯请求、非流式响应和流事件转换。实现仅负责协议编解码、能力规划、精确执行目标桥接和确定性归并，不发起真实 HTTP 请求，不新增公共兼容端点，不引入跨供应商路由。

## 已确认源码边界

1. `internal/core` 当前只负责按不可变 Provider 标识分派协议所属字节，不解释协议字段。
2. `internal/resolve.Target` 已表达 Provider Definition、Provider Instance、Channel、Endpoint、Credential、Provider Model、Execution Profile 和 Upstream Model 的精确执行目标。
3. `internal/catalog.ModelCapabilities` 已表达工具、并行工具、流式工具参数、严格 JSON、推理和模态能力，但不承担 VCP 请求级能力决策。
4. `internal/providerconfig.ProtocolProfile` 与 `ProviderChannel` 已表达共享协议 Profile 和供应商通道边界。
5. 新实现应以独立 VCP 包承载规范真相，以 OpenAI Chat Profile 包承载协议差异，通过显式目标类型连接现有 Resolve 边界。

## 技术选型

1. 使用 Go 1.26 与标准库；不新增第三方依赖。
2. 使用封闭枚举和显式结构体表达协议，不使用 `map[string]any` 作为执行协议。
3. 使用 SHA-256、XML 标准转义和固定属性顺序实现 Vulcan Frame。
4. 使用 Projection Ledger 作为可逆恢复依据，不扫描普通模型输出提升权限。
5. 使用类型化 OpenAI Chat 结构体和 `encoding/json` 处理请求、响应与模拟流分片。
6. 使用确定性 ID 派生规则保证相同输入产生稳定 item、event 和合成 tool call ID。
7. 使用纯单元测试、黄金映射测试、模拟分片测试和 reducer 测试验证，不访问网络。

## 详细执行步骤

### 一、VCP 1.0 领域模型与校验

1. 新增 VCP 请求、模型选择、生成策略、工具策略、能力策略与能力需求类型。
2. 新增 Canonical ContextItem 及 instruction、message、delegated_result、tool_call、tool_result、reasoning、refusal 载荷。
3. 将 kind、authority、actor、placement、activation、visibility、稳定 item ID、全局 sequence、父级/回复/委派关系、内容和 provider state reference 分开建模。
4. 新增 CachePolicy、CacheObservation、Remote Compaction、Lineage、Continuation 的最小领域模型。
5. 实现协议版本、封闭枚举、上下文顺序、内容块、关联关系和请求冲突校验。

### 二、按需能力规划

1. 从实际 payload 推导 ordered context projection、结构化工具、并行工具、流式工具参数、严格 Schema、媒体、显式缓存、远程压缩、网页搜索和 reasoning 需求。
2. 实现 native → projected → omitted → blocked 的确定性决策。
3. 保证 required、preferred、unused 语义明确，未触发能力不进入计划。
4. 输出客户端安全的 ExecutionReport 能力决策摘要。

### 三、Frame、Projection Plan 与 Ledger

1. 实现固定格式的 Vulcan Frame 编码、解析、摘要和保留标签转义。
2. 限制 Frame 仅承载已注册的纯文本 context 语义。
3. 实现 ProjectionPlan、ProjectionLedger、ProjectionEntry 及唯一性、lineage、位置、carrier、digest 校验。
4. 实现 `Restore(Project(X).Ledger) == X` 的恢复路径。
5. 实现跨模拟 chunk 的 Frame 扫描；验证失败时按普通文本返回。

### 四、VCP 语义事件与 reducer

1. 实现基础语义事件、稳定 event ID、全局单调 sequence 和生命周期校验。
2. 实现文本、工具参数、usage、完成、失败、不完整和取消归并。
3. 保证合法终态水合未完成工具调用，EOF 无终态产生 incomplete，completed 后传输错误不推翻完成。
4. 保证 usage-only 事件不产生虚构内容，重复完成事件不覆盖已完成项目。

### 五、OpenAI Chat Completions Profile

1. 实现 VCP 文本上下文到 Chat messages 的明确映射。
2. 支持原生 system preamble、可配置的原生 developer，以及 developer/system inline/delegated_result 的独立 Frame carrier。
3. 保留 canonical sequence，转义用户伪造 Frame，不与真实 user 文本拼接。
4. 映射 model、stream、生成参数、tools、tool_choice、parallel_tool_calls；tools 为空时不发送 parallel_tool_calls。
5. 对 optional 不支持能力生成 omitted，对 required 不支持能力生成 blocked。
6. 解码非流式 assistant content、tool_calls、finish_reason、usage、refusal和错误，并报告字段缺失、合成 ID 与降级。
7. 解码模拟流中的文本、并行/交错工具调用、延迟 ID/名称/参数、usage-only、finish_reason、终态补全、EOF 和传输错误。
8. 不伪造上游不存在的逐字符工具参数流。

### 六、现有边界桥接

1. 定义从 `resolve.Target` 到 OpenAI Chat Profile 精确执行目标的无损转换。
2. 保持 Provider Instance、Channel、Endpoint、Credential、Model 和 Profile 全部不可变。
3. 不实现 HTTP、认证、凭据读取、端点探测或跨供应商候选。

### 七、测试与闭环验证

1. 覆盖纯文本请求在未声明工具、缓存、压缩和媒体能力时仍可执行。
2. 覆盖原生 system、developer 原生与 Frame fallback、system inline、delegated_result、伪造 Frame、Ledger 恢复。
3. 覆盖空 tools 移除 parallel_tool_calls。
4. 覆盖单工具、多工具、并行/交错、ID/名称/参数延迟、usage-only 和终态水合。
5. 覆盖 completed、failed、incomplete reducer 规则及 completed 后错误。
6. 覆盖 Frame 跨 chunk。
7. 覆盖 required、preferred、unused 能力决策，以及普通文本不受 remote compaction、prompt cache、网页搜索缺失影响。
8. 执行 `gofmt -w .`、`go test ./...`、`go build -o test-output ./cmd/vulcan-model-core`。
9. 对照本计划逐项复核；修正所有未满足项。
10. 在本文件末尾追加结构化“执行变更总结”，再迁移至 `docs/completed/20260717/04-VCP_OPENAI_CHAT_PHASE_ONE.md`。

## 验收标准

1. 所有要求的 VCP 基础概念均有类型化 Go 定义和校验。
2. Frame 编解码、Ledger 恢复和伪造防护满足 ADR 0006。
3. Capability Plan 只评估实际触发能力，并正确区分 native、projected、omitted、blocked。
4. OpenAI Chat Profile 完成纯请求、非流式响应和模拟流双向语义转换。
5. 流事件 sequence 单调、ID 稳定、reducer 确定，异常终态符合规则。
6. 不新增其他供应商协议、不发网络请求、不增加公开兼容 API、不改变供应商边界。
7. 所有新增 Go 类型、接口、函数、方法和非直观变量均具有英文第一行、中文第二行注释。
8. 全量测试和命令构建通过。

## 执行变更总结

### 1. 核心修复与调整概述

1. 新增 VCP 1.0 类型化协议基层，完整表达模型选择、生成策略、工具策略、能力策略、Canonical ContextItem、缓存、远程压缩、谱系、续传、执行报告与用量观测等第一阶段领域概念。
2. 新增请求与上下文校验，封闭协议枚举和载荷变体，校验稳定标识、全局顺序、关联关系、内容块、工具定义及策略冲突，避免使用任意 `map[string]any` 承载执行协议。
3. 新增按请求实际载荷推导的能力规划，仅评估已触发能力，并确定性区分 `native`、`projected`、`omitted`、`blocked`；同时生成不泄露凭据和端点的客户端安全决策摘要。
4. 新增 Vulcan Frame、Projection Plan 与 Projection Ledger，采用固定属性顺序、标准 XML 转义、SHA-256 摘要和确定性标识，支持可信投影恢复、跨分片扫描与伪造 Frame 防护。
5. 新增 VCP 语义事件及确定性 reducer，覆盖文本、拒绝、工具参数、用量和响应终态，保证事件序号单调、标识稳定、合法终态水合未完成工具调用，并正确处理 EOF、失败及完成后传输错误。
6. 新增 OpenAI Chat Completions Profile 的类型化请求投影、非流式响应解码与模拟流解码；保持已解析 Provider 目标不可变，并通过独立 Frame carrier 承载需要投影的上下文语义。
7. 最终闭环验证结果为：`gofmt -w .` 成功、`go test ./...` 成功、`go vet ./...` 成功、`go build -o test-output ./cmd/vulcan-model-core` 成功。

### 2. 📂 文件变更清单

#### 新增

- `internal/vcp/capability.go`
- `internal/vcp/capability_test.go`
- `internal/vcp/events.go`
- `internal/vcp/events_snapshot_test.go`
- `internal/vcp/events_test.go`
- `internal/vcp/projection.go`
- `internal/vcp/types.go`
- `internal/vcp/validation.go`
- `internal/vcp/validation_additional_test.go`
- `internal/vcp/validation_nested_test.go`
- `internal/protocol/openai/chat/request.go`
- `internal/protocol/openai/chat/request_boundary_test.go`
- `internal/protocol/openai/chat/request_test.go`
- `internal/protocol/openai/chat/response.go`
- `internal/protocol/openai/chat/response_boundary_test.go`
- `internal/protocol/openai/chat/response_test.go`
- `internal/protocol/openai/chat/stream.go`
- `internal/protocol/openai/chat/stream_additional_test.go`
- `internal/protocol/openai/chat/stream_event_history_test.go`
- `internal/protocol/openai/chat/stream_event_isolation_test.go`
- `internal/protocol/openai/chat/stream_test.go`
- `internal/protocol/openai/chat/types.go`

#### 修改

- `docs/completed/20260717/04-VCP_OPENAI_CHAT_PHASE_ONE.md`：归档计划、验收结果与本次执行变更总结。

#### 删除

- 无。

#### 追加回归测试结果

- `internal/vcp/validation_additional_test.go` 覆盖 15 个封闭枚举边界、远程压缩输入互斥、Frame 规范编码、原文降级及 Ledger 各项信任绑定；补测发现并推动修复了未知 `Actor` 未被拒绝的问题。
- `internal/protocol/openai/chat/stream_additional_test.go` 覆盖重复工具调用标识告警、终态工具名称水合、形似 Frame 的助手普通文本、结束原因后的用量分片和无合法终态 EOF。
- `internal/vcp/validation_nested_test.go` 覆盖嵌套权限、委派结果、工具状态、能力特性、能力模式、远程压缩上下文及工具结果前序调用关联。
- `internal/vcp/events_snapshot_test.go`、`internal/protocol/openai/chat/stream_event_isolation_test.go` 与 `stream_event_history_test.go` 覆盖 reducer 快照、流回放返回值和历史事件载荷的深隔离与不可变性。
- `internal/protocol/openai/chat/request_boundary_test.go` 与 `response_boundary_test.go` 覆盖 VCP 模型选择到精确 Target 的绑定，以及缺失消息或结束原因时的非流式不完整终态。

### 3. 💻 关键代码调整详情

1. `VulcanRequest.Validate`、`ValidateContext` 及各载荷校验函数建立封闭请求校验链，明确拒绝无效协议版本、模型目标、嵌套封闭枚举、远程压缩上下文、工具结果前序关联、内容、工具 Schema 与策略冲突。
2. `PlanCapabilities` 从实际请求载荷和显式策略推导需求，按能力可用性选择原生、投影、省略或阻止模式；普通纯文本请求不会因未使用的缓存、远程压缩、网页搜索或媒体能力缺失而被阻止。
3. `EncodeFrame`、`ParseFrame`、`FrameScanner` 与 `ProjectionLedger.Add/Restore/RestoreFrame` 实现固定格式 Frame、跨分片组装、唯一性与谱系校验，以及不依赖上游请求回显的可信 Canonical ContextItem 恢复。
4. `Reducer.Apply` 实现统一事件生命周期与终态约束，并深拷贝事件初始载荷与响应快照；完成、失败、不完整和取消均显式归并，历史事件不会被后续水合反向修改。
5. `ProjectRequest` 将 VCP 请求编译到精确的 `resolve.Target`，逐项核验 Provider Instance、Provider Model 和显式 Execution Profile 绑定；按 Profile 能力选择原生 system/developer 或独立 Frame carrier，并在 tools 为空时不发送 `parallel_tool_calls`。
6. `DecodeResponse` 将非流式 assistant 文本、拒绝、工具调用、结束原因、用量和结构化错误转换为稳定 VCP 事件；缺失消息或结束原因产生 `response.incomplete`，诊断代码经过有界标识校验且不复制提示词或供应商消息。
7. `StreamDecoder.Push/Close` 支持文本、拒绝、并行及交错工具调用、延迟 ID/名称/参数、usage-only 分片、终态水合、EOF 和传输错误；回放日志深隔离，仅转发上游实际提供的工具参数增量。
8. 单元测试覆盖按需能力决策、封闭及嵌套枚举校验、Frame/Ledger 往返与伪造防护、精确目标绑定、原生及投影上下文、非流式缺失终态、流式交错工具调用、历史事件不可变性和 reducer 终态规则。

### 4. ⚠️ 遗留问题与注意事项

1. 本阶段仅实现协议类型、校验、能力规划、投影、恢复和语义归并，不实现真实 HTTP 请求、OAuth 授权、API Key 读取或注入、端点探测及网络重试。
2. 本阶段不实现其他供应商协议，不新增 OpenAI Chat Completions、Claude、Gemini、Codex 或其他公共兼容端点，也不改变由 Vulcan 协议套件拥有公共 HTTP API 的架构边界。
3. 不存在跨供应商候选列表或自动降级；一次执行的 Provider 标识保持不可变，后续故障转移仍只能发生在同一 Provider 所属的计划、端点、区域和凭据之间。
4. CLIProxyAPI 仅作为历史行为与兼容问题的证据来源，未引入为 Go Module 或运行时依赖。
5. 后续接入真实传输、认证或其他协议前，应另行制定计划并重新确认架构、凭据安全、日志脱敏与供应商边界；不得在本协议层追加投机性兼容路径。
