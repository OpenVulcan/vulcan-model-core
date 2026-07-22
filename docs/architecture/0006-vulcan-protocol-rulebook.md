# ADR 0006：Vulcan 协议规则集——按需能力执行与可逆投影

- 状态：已采纳
- 日期：2026-07-17
- 适用版本：Vulcan Canonical Protocol 1.0，简称 VCP 1.0
- 取代范围：本 ADR 取代 ADR 0004 中“以全量能力是否保真决定模型可用性”以及“关键语义默认拒绝”的规则；ADR 0004 中关于工具、流、usage、缓存、错误和供应商状态的证据与问题清单仍然有效。
- 相关文档：
  - ADR 0002：供应商、Channel、Credential、Execution Profile、Catalog 与 Resolve 的领域边界。
  - ADR 0004：CLIProxyAPI 协议失败模式、事件 reducer、缓存和错误分析。
  - ADR 0005：system-reminder、角色降权、前置合并和提示词改写审计。

## 1. 决策

Vulcan 系列工具只面向 VCP 1.0 编程。每个上游供应商、协议通道和模型只实现：

~~~text
VCP 请求与上下文  -> 上游请求
上游响应与事件    -> VCP 响应与事件
~~~

VCP 不要求任何供应商实现全部 VCP 能力。模型是否可用由当前请求实际需要的能力决定，而不是由该模型是否拥有全部高级 API 功能决定。

每次执行都遵守以下优先级：

~~~text
原生高级能力
  > 已注册的可逆投影
  > 未使用能力不参与判断
  > 可选能力按策略省略
  > 仅当当前请求的硬需求无法安全完成时才改路由或失败
~~~

因此，缺少显式缓存、远程压缩、原生网页搜索、并行工具或某个未来 API 的模型，仍可承担不依赖这些能力的文本、代码、上下文和普通 Agent 请求。

## 2. 规范性用语

本文中的用语含义如下：

- 必须：违反后不得执行或不得声称满足该规则。
- 应当：默认要求；只有有记录、可测试的理由时才可偏离。
- 可以：可选实现，不构成互操作承诺。
- 原生：上游协议存在经 Driver 验证的直接表示和执行路径。
- 投影：Router 以已注册的 carrier 表示 VCP 语义项，并保存反向恢复信息。
- 可逆：Router 能从自己的投影账本和受控回放输入恢复原 VCP 语义项、顺序和关联。
- 等价：上游协议对该语义提供同等执行保证。
- 建议性：上游可以读取承载内容，但协议不保证与原权限或控制语义同等。
- 硬需求：当前请求若缺失该能力，结果将不符合调用方明确要求。
- 可选能力：缺失时仍可执行，只是少了优化、性能或额外体验。

可逆投影不等于上游语义等价。把 developer 指令放进 user carrier 可以保证 VCP 侧身份、顺序和回放可恢复，但不能声称该上游模型一定赋予它原生 developer 的优先级。

## 3. 目标与非目标

### 3.1 目标

1. 让 Vulcan Code 和其他 Vulcan 工具只理解一份稳定、类型化、有时序的协议。
2. 尽可能利用每个上游的高级原生能力，而不是永远降到最低公共能力。
3. 让未使用的高级能力不影响模型可用性。
4. 对角色、子代理结果、工具、缓存、压缩、推理状态和流事件建立可审计的映射。
5. 防止“发送 A、内部变成不可识别的 B、后续回放无法恢复”的协议漂移。
6. 保持一次执行的供应商边界不可变；容灾只发生在同一供应商拥有的账号、端点、区域或套餐候选之间。

### 3.2 非目标

1. 不实现任意供应商协议之间的成对转换矩阵。
2. 不要求 Router 支持每个供应商新发布但 Vulcan 工具尚未使用的 API。
3. 不把供应商的原始 JSON、签名、response ID 或密钥暴露给 Vulcan 客户端。
4. 不用文本标签伪造可靠的结构化工具调用、图像能力、远程压缩或权限隔离。
5. 不在核心 Router 中自动跨供应商融合或跨供应商故障转移。
6. 不以无约束的通用 execute map 承载未知功能。

## 4. VCP 的协议面

VCP 1.0 使用 JSON 请求、JSON 非流式响应和 SSE 流式响应。Responses 风格的生命周期和命名可以复用，但 VCP 的类型、能力规则和扩展字段才是权威定义。

VCP 1.0 的唯一公开协议面如下；OpenAI、Anthropic、Google、xAI 等兼容协议只允许作为内部上游 Adapter，不得增加同名公开入口：

~~~text
POST   /vulcan/v1/info
POST   /vulcan/v1/selections
POST   /vulcan/v1/preflight
POST   /vulcan/v1/resources
POST   /vulcan/v1/resources/import
GET    /vulcan/v1/resources/{resource_id}
GET    /vulcan/v1/resources/{resource_id}/content
DELETE /vulcan/v1/resources/{resource_id}
POST   /vulcan/v1/input-plans
POST   /vulcan/v1/executions
GET    /vulcan/v1/executions/{execution_id}
GET    /vulcan/v1/executions/{execution_id}/events
POST   /vulcan/v1/executions/{execution_id}/cancel
~~~

`info` 使用请求体中的封闭 `get` 判别字段返回实例、模型、账号、服务、用量或目录增量；`selections` 只在调用方固定的 Provider Instance 内选择精确模型或服务 Target。图片、音频、文件和视频输入先进入统一 Resource 与 InputPlan 生命周期；文本、多模态、搜索和异步媒体操作统一通过强类型 `executions` 信封提交，不另建供应商兼容协议面。

请求必须携带 protocol_version。服务端仅在已声明兼容范围内接受版本；未知顶层字段、未知 item 类型和未注册扩展必须明确报错，不能原样透传给上游。

## 5. 基本执行不变量

### 5.1 供应商边界

一次 Response Execution 在开始前选择一个精确 Provider Instance。执行中可以在该实例拥有的 Credential、Endpoint、Region 和 Plan 候选之间容灾；不得自动换到另一个 Provider Instance。

### 5.2 上下文真相来源

VCP Canonical Context 与 Projection Ledger 是上下文真相来源。上游不回显请求时，Router 也必须能够恢复此前投影出去的 VCP 项目；不得依赖上游会把原始输入完整返回。

### 5.3 逐请求能力判定

模型的基础可执行性与当前请求的能力可执行性分开：

~~~text
base_executable
  表示该 Channel、Credential、Model 与基础文本链路可以工作。

operation_eligible
  表示该模型能够完成当前请求实际触发的硬需求。
~~~

任何未被当前请求触发的能力都不得参与 operation_eligible 判断。

### 5.4 不能静默伪造

当某能力不可投影且当前请求将其声明为硬需求时，Router 必须：

1. 在同一 Provider Instance 内寻找满足要求的 Model、Execution Profile、Credential 或 Endpoint；
2. 若不存在，返回结构化 capability_unavailable；
3. 不得把普通文本回答伪造成工具调用、远程压缩、严格 JSON、媒体处理或原生权限执行。

## 6. 请求信封

VCP 请求是封闭结构，逻辑字段如下：

~~~text
VulcanRequest
├── protocol_version
├── request_id
├── idempotency_key
├── model_selection
│   ├── target: exact | alias | auto
│   ├── provider_instance_id: optional
│   ├── provider_model_id: optional
│   └── execution_profile_id: auto | explicit
├── context[]
├── tools[]
├── tool_policy
├── generation_policy
├── reasoning_policy
├── cache_policy
├── context_management_policy
├── capability_policy
├── stream
├── metadata
└── registered_extensions[]
~~~

### 6.1 model_selection

精确目标固定供应商边界；alias 和 auto 只能在调用方允许的供应商范围内解析。解析结果必须在 Response 开始事件中返回安全的路由摘要，不得暴露 Credential ID、Base URL 或上游密钥。

execution_profile 是客户端可选择的能力形态。例如同一 Kimi K3 模型可以拥有 256K 与 1M 两个 Execution Profile；最终可用 Profile 由账号 entitlement、套餐与上下文上限共同决定。

### 6.2 capability_policy

Capability Policy 不要求客户端手工列出所有未来能力。Router 先从请求实体自动推导需求，客户端只补充更严格或更宽松的业务要求。

~~~text
CapabilityPolicy
├── execution_mode: maximize | native_only
├── optional_on_unsupported: omit | use_regular | fail
├── explicit_demands[]
│   ├── feature
│   ├── level: required | preferred
│   ├── accepted_modes: native | projected
│   └── on_unavailable: reroute_same_provider | fail
└── allow_advisory_instruction_projection
~~~

默认 execution_mode 是 maximize：

- 优先 native；
- native 不存在但已注册 projected 规则时使用 projected；
- 未触发的能力直接跳过；
- preferred 能力可按策略省略；
- required 能力不能被静默省略。

native_only 仅用于确实需要上游原生执行保证的场景，例如安全边界、可靠工具执行、供应商原生 continuation 或明确要求的远程压缩。

### 6.3 自动推导需求

下列条件至少应自动产生对应 Capability Demand：

| 请求内容 | 推导能力 | 默认级别 |
| --- | --- | --- |
| developer、system_inline 或 delegated_result | ordered_context_projection | preferred，允许 projected |
| tools 非空 | structured_tool_calling | required |
| parallel tool policy | parallel_tool_calling | required |
| 流式工具参数被要求 | streaming_tool_arguments | required |
| strict JSON schema | strict_schema | required |
| image、audio、video 或 file block | 对应输入模态 | required |
| 明确 cache strategy 非 regular | explicit_prompt_cache | 由 on_unsupported 决定 |
| compact 端点调用 | remote_compaction | required |
| normal request 的 auto compaction | remote_compaction | preferred |
| 供应商托管网页搜索 | native_web_search | required 或 preferred，取决于调用方策略 |

纯文本请求没有 tools、媒体、缓存和压缩需求时，不得因为目标模型不支持这些能力而被拒绝。

## 7. Canonical Context

### 7.1 统一项目模型

上下文必须是带稳定身份和全局顺序的封闭项目序列，而不是未约束的消息数组。

~~~text
ContextItem
├── item_id
├── sequence
├── kind
├── authority
├── actor
├── placement
├── activation
├── visibility
├── content[]
├── parent_item_id
├── reply_to_item_id
├── delegation_id
├── ordering_constraints[]
├── origin
└── provider_state_ref
~~~

字段含义：

- kind：instruction、message、delegated_result、reasoning、tool_call、tool_result、refusal。
- authority：system、developer、user、assistant、tool、none。
- actor：platform、application、end_user、primary_assistant、delegated_agent、tool、provider。
- placement：preamble 或 transcript。
- activation：request_start 或 after_item_id。
- visibility：model、client、audit_only。

authority 表示原会话中的指令权限；actor 表示谁产生了内容。两者不得合并成单一 role 字符串。

### 7.2 主系统提示词与会话内指令

主系统提示词必须表示为：

~~~text
kind=instruction
authority=system
placement=preamble
activation=request_start
~~~

它是当前请求中最先投影的 Canonical Item。若目标原生支持主 system，Adapter 直接投影；若不支持，Adapter 必须生成独立的首条 synthetic carrier，并记录该 carrier 仍对应 system preamble，不能与真实 user 文本拼接。

会话中途加入的 system 或 developer 指令必须保留原 sequence、placement=transcript 和 activation anchor。不能因为目标只有顶层 system 就默认把它们前置；优先使用在原位置插入的 Framed Carrier。只有调用方明确允许 hoist_to_preamble 时才可以前置，并且该执行必须标记为 advisory。

### 7.3 delegated_result

delegated_result 是子代理、子任务或受委派执行产生的独立项目类型：

~~~text
DelegatedResult
├── item_id
├── delegation_id
├── parent_item_id
├── producer=delegated_agent
├── result_kind=report | task_output | tool_backed_result
├── visibility
└── content[]
~~~

它绝不能被提升成 system 或 developer。若上游没有原生委派结果类型，优先使用 registered Framed Carrier；只有与明确 tool_call 存在父级关系时，Driver 才可声明投影为 tool_result。

### 7.4 内容块

VCP 1.0 支持以下已注册内容块：

- text；
- image；
- audio；
- video；
- file；
- citation；
- refusal；
- registered_extension。

Framed Carrier 只能承载明确允许的文本项目。目标不支持的媒体不能通过“文本描述”伪装为原媒体输入；该媒体是当前请求硬需求时应重新解析目标或失败。

## 8. 可逆投影合同

### 8.1 三条 Adapter 路径

每个 Protocol Profile 必须实现以下语义合同：

~~~text
Project(CanonicalContext, CapabilityPlan)
  -> UpstreamRequest, ProjectionLedger

Decode(UpstreamEventOrResponse, ProjectionLedger)
  -> CanonicalEvent

Restore(ProjectionLedger)
  -> CanonicalContext
~~~

必须满足：

~~~text
Restore(Project(X).ledger) == X
~~~

该等式针对 Router 自己投影出的上下文、顺序、关联和 carrier 信息。它不要求上游把原请求回显，也不把上游新生成的 assistant 文本误当作原输入。

### 8.2 每项投影的结果

每个 Canonical Item 的 Projection Result 必须是下列之一：

| 模式 | 含义 |
| --- | --- |
| native | 目标有直接、已验证的表示 |
| projected | 使用已注册 Frame 或其他可逆 carrier |
| omitted | 当前可选能力未启用或策略允许省略 |
| blocked | 当前硬需求无法安全完成 |

每个 native 或 projected 项还必须记录 execution_equivalence：

| 值 | 含义 |
| --- | --- |
| equivalent | 上游协议声明具有同等执行语义 |
| advisory | 内容与 VCP 身份可恢复，但权限、优先级或控制效果不保证等价 |
| none | 不存在有效执行含义；不得用于 required 需求 |

### 8.3 Projection Ledger

Projection Ledger 是 Router 内部持久化记录，不直接暴露给客户端：

~~~text
ProjectionEntry
├── projection_id
├── lineage_id
├── canonical_item_id
├── canonical_sequence
├── canonical_kind
├── source_authority
├── carrier_protocol
├── carrier_role_or_slot
├── upstream_position
├── projection_mode
├── execution_equivalence
├── rule_id
├── rule_version
├── frame_id
├── content_digest
├── decode_policy
├── created_at
└── expires_at
~~~

同一 Canonical Item 在一次上游尝试中只能有一个有效 Projection Entry。因重试选择另一个同供应商 Target 时，必须重新编译新的 Projection Plan，不能复用旧 Target 的上游 ID、Frame 或 opaque state。

### 8.4 角色的默认投影决策

| VCP 项目 | 原生优先 | 无原生表示时的默认处理 |
| --- | --- | --- |
| system preamble | 顶层 system、instructions 或等价槽位 | 首条独立 Framed Carrier |
| system inline | 原位置 system item | 原位置独立 Framed Carrier |
| developer | 原生 developer 或等价声明 | 原位置独立 Framed Carrier |
| user / assistant message | 原生 message | Profile 必须有直接消息规则，否则 blocked |
| delegated_result | 原生委派类型 | Framed Carrier；有明确父级时可声明 tool_result |
| tool_call | 原生结构化 tool call | blocked，不能只用文本标签伪造 |
| tool_result | 原生 tool result | 仅在 Driver 注册明确上下文规则时允许 carrier |
| reasoning continuation | Owner 原生 continuation | blocked，不能跨 owner Frame 化 |
| image / audio / video / file | 原生模态或注册资源转换 | blocked，不能伪装成描述文字 |

该表只规定默认。Provider Driver 可以在更窄的 Channel、Model、Execution Profile 条件下发布更精确的规则。

## 9. Framed Carrier 规则

### 9.1 适用范围

Framed Carrier 解决的是“目标协议没有对应 role 或 item，但可以把受控文本作为上下文交给模型”的问题。它不赋予目标协议不存在的原生权限，也不允许承载结构化控制操作。

可承载的 VCP 项目必须同时满足：

1. 内容全部是允许的 text block；
2. 已存在 Profile 注册的 carrier role、位置和规则；
3. 请求的 Capability Demand 接受 projected；
4. 没有被标记为 native_only；
5. 该规则的 execution_equivalence 至少为 advisory。

### 9.2 线协议格式

Framed Carrier 使用保留的 Vulcan Frame 格式。为了让模型能够阅读正文，正文是经 XML 文本转义后的明文；为了让 Router 能验证来源，Frame 包含稳定 ID、版本和摘要。

~~~xml
<vulcan-frame
  version="1"
  frame-id="frm_01J..."
  kind="developer"
  sequence="12"
  digest="sha256:..."
  purpose="context-carrier">
请始终以简洁、可执行的方式回答。
</vulcan-frame>
~~~

规则：

1. 属性顺序、编码和 digest 输入必须由 VCP 规范固定，不能由各 Adapter 自行拼接。
2. frame-id 必须在当前 Projection Ledger 中存在。
3. 真实用户文本中出现的类似标签必须转义，不能被解释为 Frame。
4. carrier 必须是独立 synthetic message 或已声明的独立内容块；不得把 Frame 与真实 user 文本无边界拼接。
5. 只允许 Router 产生、登记并发送的 Frame 参与反向恢复。
6. 不得将密钥、Credential ID、上游 response ID、推理签名或内部路径写入 Frame。

### 9.3 示例：developer 到 Chat carrier

VCP 输入：

~~~text
sequence=12
kind=instruction
authority=developer
placement=transcript
content="优先给出可运行代码。"
~~~

目标 Chat 没有 developer 时，投影为：

~~~text
role=user
content=<vulcan-frame ... kind="developer" sequence="12">优先给出可运行代码。</vulcan-frame>
~~~

Ledger 记录该 user carrier 的真实 VCP 身份仍为 developer。后续会话重放、请求恢复或受控回传时，Router 恢复为 sequence=12 的 developer instruction，而不是把它永久变成 user。

### 9.4 示例：subagent_result

VCP 输入：

~~~text
kind=delegated_result
delegation_id=dlg_...
parent_item_id=itm_...
content="已完成依赖分析，发现两个冲突。"
~~~

若目标不支持原生委派结果，投影为：

~~~xml
<vulcan-frame
  version="1"
  frame-id="frm_..."
  kind="delegated_result"
  sequence="18"
  digest="sha256:..."
  purpose="context-carrier">
已完成依赖分析，发现两个冲突。
</vulcan-frame>
~~~

它恢复后仍是 delegated_result，且保留 delegation_id 与 parent_item_id；不得恢复为 developer 或 system。

### 9.5 反向解析与伪造防护

Router 不得扫描任意 assistant 输出并把看起来像 Frame 的文本自动升级为高权限项目。反向恢复必须同时满足：

1. Frame 来自当前 Lineage 已登记的 Projection Entry；
2. frame-id、digest、kind、sequence 与 Ledger 一致；
3. Frame 出现在该 Entry 允许的 upstream carrier 位置；
4. decode_policy 明确允许恢复；
5. 当前处理的是受控回放、输入恢复或受信任内部执行通道。

默认 decode_policy 是 replay_only。模型在普通 assistant 文本中复制或伪造标签时，按普通文本输出，不得改变 VCP 上下文权限或项目类型。

## 10. Protocol Profile 与 Provider Driver

### 10.1 Profile 的职责

Protocol Profile 负责协议族的通用编解码与 Frame carrier 规则，例如：

- openai_chat；
- openai_responses；
- anthropic_messages；
- gemini_generate_content；
- codex_responses；
- 其他已注册协议族。

Profile 不得根据供应商名称硬编码套餐、错误关键词、模型白名单或私有 API 地址。

### 10.2 Driver 的职责

Provider Driver 负责系统供应商的事实与差异：

- Provider Definition、Channel、认证方式；
- 模型发现、套餐、授权、额度；
- 精确能力条件；
- 供应商错误分类；
- Provider 专属 Frame 或 native projection 覆盖；
- prompt cache、remote compaction、reasoning continuation 的支持条件；
- 上游请求和响应的专用适配。

Driver 覆盖 Profile 通用规则时，必须给出 rule_id、版本、适用条件和合同测试。

### 10.3 系统供应商与自定义供应商

system_ 前缀的 Definition 由受信任 Driver 拥有，可声明并实现高级能力。

custom_ 前缀的 Definition 只能选择标记为 UserConfigurable 的 Protocol Profile、配置端点、模型和认证方式。自定义供应商默认可使用基础文本、已注册的通用 Framed Carrier 和模型发现；它不得仅凭用户配置声称拥有以下高级能力：

- 原生 remote compaction；
- provider opaque continuation；
- 原生 reasoning signature；
- 显式 prompt cache 创建；
- 供应商托管工具；
- 账号套餐、余额和专属错误分类。

这些能力只有在受信任 Driver、明确探测规则和合同测试存在后才能发布为 native 或 projected。

## 11. 按需能力规划

### 11.1 Capability Plan

Router 在请求解析后、选择 Credential 前生成一次不可变 Capability Plan：

~~~text
CapabilityPlan
├── request_id
├── catalog_revision
├── demands[]
│   ├── feature
│   ├── source: payload | policy | runtime
│   ├── level: required | preferred
│   ├── accepted_modes
│   └── selected_mode: native | projected | omitted | blocked
├── target_constraints
├── projection_rule_versions[]
└── generated_at
~~~

Plan 必须在缓存断点、请求签名、Projection Ledger 和上游请求体生成之前冻结。

### 11.2 选择规则

对每个当前请求实际触发的需求，按下列顺序选择：

1. 目标支持 native：选择 native。
2. 目标不支持 native，但已注册且允许 projected：选择 projected。
3. 需求是 preferred，且策略允许省略：选择 omitted。
4. 需求是 required：在同一 Provider Instance 内重解析 Target。
5. 同一 Provider Instance 不存在可行 Target：选择 blocked 并返回 capability_unavailable。

未触发的能力不进入 Plan，也不触发探测、请求字段、错误或模型淘汰。

### 11.3 高级能力调用原则

Router 应在当前请求有价值时优先使用高级原生 API：

- 有稳定前缀缓存策略且目标支持显式缓存时，发送原生 cache control；
- 发生压缩需求且目标支持原生压缩时，调用原生 compact；
- 调用方要求托管网页搜索且目标支持时，使用原生工具；
- 请求要求 reasoning 强度且目标支持时，传递原生 reasoning 参数；
- 请求要求并行工具与流式参数且目标支持时，保持原生事件链。

Router 不得仅因为上游支持某功能就擅自调用它。未被 VCP 请求、策略或运行时阈值触发的功能必须保持未调用。

### 11.4 新上游 API 的准入

新增供应商 API 只有满足至少一项时才需要实现：

1. Vulcan 工具已经产生对应 VCP 需求；
2. 它能改善现有 VCP 操作的正确性、能力或成本；
3. 它影响当前错误、额度、缓存、续接或安全行为。

否则该 API 不在当前协议范围内；它既不阻止模型使用，也不应被通用 passthrough 盲目发送。

## 12. 流式时序与事件规则

### 12.1 执行状态机

每次执行必须按以下语义阶段推进：

~~~text
RequestAccepted
  -> Canonicalized
  -> TargetResolved
  -> CapabilityPlanned
  -> ProjectionPlanned
  -> LedgerPersisted
  -> UpstreamStarted
  -> Streaming
  -> Terminal
  -> LineageCommitted
~~~

规则：

1. LedgerPersisted 必须发生在任何上游字节发出之前。
2. 只有在尚未向客户端发送可见语义事件前，Router 才可按同供应商容灾策略更换 Target。
3. 一旦发送了可见输出、工具调用或完成事件，除非协议声明可恢复并能保证幂等，否则不得静默重放到另一个 Target。
4. 任何未收到合法终态的 EOF 都必须产生 response.incomplete。
5. 一旦 response.completed 已确认，后续传输错误不得推翻该终态。

### 12.2 VCP 语义事件

基础事件集：

~~~text
response.started
route.resolved
item.started
content.started
content.delta
content.completed
tool.arguments.delta
tool.arguments.completed
item.completed
usage.updated
warning.raised
response.completed
response.incomplete
response.failed
response.cancelled
~~~

每个事件必须有 response_id、event_id、全局单调 sequence、时间、可重放标记，以及适用时的 item_id、content_index、tool_call_id。

上游网络分片、SSE 行、WebSocket 帧与 VCP 语义事件不是同一层。Adapter 可以把一个上游事件展开成多个 VCP 事件，也可以合并多个上游事件后再产生一个 VCP 事件，但不得改变 Canonical Item 的因果顺序。

### 12.3 流式 Frame 扫描

当 Profile 的受控通道需要识别 Framed Carrier 时，扫描器必须：

1. 支持 Frame 跨网络分片、SSE data 行或 WebSocket 帧；
2. 在 Frame 验证完成前缓冲可能构成保留标记的字节；
3. 验证失败后按原字节作为普通文本输出；
4. 只在第 9.5 节的受控条件满足时反向恢复；
5. 不将模型生成的普通标签文本升级为 VCP 指令或 delegated_result。

### 12.4 终态 reducer

最终 Response 必须由 VCP 事件 reducer 归并得出。上游终态对象只是一个观测，不得假设它必然自包含全部输出、工具参数或 usage。

Reducer 必须保证：

- 相同合法事件序列得到相同最终 Response；
- 已完成 item 不会被重复 done 覆盖；
- 工具名称、调用 ID 或最终参数可以由合法终态水合；
- response.failed 与 response.incomplete 不得伪装为成功；
- usage-only 分片可更新 usage，但不能虚构文本内容。

## 13. 续接、谱系与远程压缩

### 13.1 Logical Response 与 Lineage

VCP response_id 是 Router 生成的逻辑 ID。它与上游 response ID、会话 token、reasoning signature 和 compaction token 不同。

Lineage 至少保存：

~~~text
Lineage
├── logical_response_id
├── continuation_id
├── provider_definition_id
├── provider_instance_id
├── channel_id
├── endpoint_id
├── credential_id
├── provider_model_id
├── upstream_model_id
├── execution_profile_id
├── adapter_version
├── projection_ledger_refs[]
├── opaque_state_refs[]
├── affinity_policy
└── expires_at
~~~

客户端只获得安全的 response_id、continuation_id、有效期和亲和性摘要；不得获得 Credential ID 或 opaque state。

### 13.2 previous_response_id

previous_response_id 只接受 VCP 逻辑 response_id。Router 通过 Lineage 找到对应状态并决定是否可以续接。

若请求同时给出完整 Canonical Context 与 previous_response_id，必须由协议明确选择一种模式；VCP 1.0 默认拒绝二者同时存在，防止两份历史发生隐式拼接。

### 13.3 亲和性

Affinity Policy 必须由 Driver 声明：

| 状态 | 默认亲和性 |
| --- | --- |
| 无 opaque state、可完整重放的 Canonical Context | 同 Provider Instance、同模型或声明兼容模型 |
| 上游 response state、reasoning signature | 由 Driver 声明，默认同 Credential |
| 原生 compaction 输出 | 默认同 Credential、同 Channel、同模型 |
| 供应商明确声明可跨 Credential continuation | 按声明的 ScopeReference 范围 |

失去亲和性时返回 context_affinity_lost 或 invalid_continuation；不得把 opaque 状态发送给另一个供应商，或无记录地切换模型。

### 13.4 remote compaction

普通请求不因为目标缺少 remote compaction 而不可用。只有以下情形才触发该能力：

- 客户端调用 compact 端点；
- context_management_policy=auto 且达到预设上下文阈值；
- Driver 因上游协议要求请求 compaction。

compact 请求必须二选一：

1. 传入 previous_response_id，由 Router 从 Lineage 获取受控历史；
2. 传入完整 Canonical Context，作为无状态压缩输入。

上游成功压缩后，Router 必须原子完成：

1. 保存新的 opaque compaction state；
2. 创建新的 continuation_id；
3. 用压缩后的 Canonical Context 或 state reference 替换旧 Lineage 的续接状态；
4. 清理或失效旧 reasoning replay；
5. 记录实际 Target、压缩规则和亲和性。

不得将本地摘要伪装为 remote compaction。目标不支持 remote compaction 时：

- 手动 compact 请求返回 capability_unavailable；
- auto compaction 按 context_management_policy 决定继续保留历史、请求客户端行动或使用调用方明确许可的 local_summary；
- 正常对话请求不受该缺失影响。

## 14. 缓存规则

缓存能力、缓存请求意图和缓存实际结果必须分开。

### 14.1 Cache Policy

~~~text
CachePolicy
├── strategy: regular | disabled | stable_prefix | rolling_per_turn | manual_breakpoints
├── requested_ttl
├── breakpoints[]
├── on_unsupported: reject | use_regular
└── scope_preference
~~~

regular 是默认值：Router 不主动添加显式 cache control，但允许供应商自身的常规或隐式缓存。没有显式缓存需求的请求不得检查或调用显式缓存 API。

rolling_per_turn 表示每回合请求创建或推进缓存断点，不保证上游一定创建成功。实际结果仅以响应中的 Cache Observation 为准。

### 14.2 Capability Plan 中的缓存

- strategy=regular：explicit_prompt_cache 不进入必需需求。
- strategy=disabled：目标不支持关闭缓存时，按 on_unsupported 明确失败或继续常规调用；不得假装关闭成功。
- stable_prefix、rolling_per_turn、manual_breakpoints：目标支持时优先 native；目标不支持且 on_unsupported=use_regular 时记录 omitted，否则 blocked。

Projection、角色顺序和 Frame 编译必须先于缓存断点与请求签名。缓存键必须包含 Canonical Item 身份、authority、placement、activation、投影规则版本和实际 Target，不能只按拼接文本共享。

### 14.3 Cache Observation

响应必须分别观测：

- creation_tokens；
- read_tokens；
- effective_mode；
- outcome；
- TTL 或 billing breakdown；
- scope；
- source；
- final。

unknown、零、估算、推导和供应商精确报告必须区分。一次请求可以同时读取旧缓存并创建新缓存。

## 15. 工具与结构化输出规则

### 15.1 工具

工具调用是控制语义，不是普通文本内容。当前请求存在 tools 时，结构化 tool_calling 是 required。

Adapter 必须保留：

- 稳定 Vulcan tool_call_id；
- 原生 ID 或 synthesized 标记；
- 工具名称、命名空间和种类；
- 参数原始增量与最终值；
- tool_result 对应的 parent tool_call_id；
- 并行、交错和完成状态。

目标没有原生结构化工具调用时，Router 不得用提示词让模型输出 JSON 后宣称拥有可靠工具能力。该模型仍可处理不含 tools 的文本请求。

### 15.2 流式参数

当调用方要求 streaming_tool_arguments 时，Adapter 只有在上游真实提供增量参数时才能发出 tool.arguments.delta。上游只提供完整参数时：

- 若该需求是 required，当前 Target 不可用；
- 若该需求是 preferred，等待完整参数并在 Capability Decision 中记录未使用流式参数；
- 不得伪造逐字符流。

### 15.3 严格 JSON

strict schema 必须仅在上游具备已验证的原生约束或 Driver 注册的可靠实现时发布为 native。普通文本“请输出 JSON”是建议性提示，不是 strict schema 能力。

## 16. 推理与不透明状态

可见 reasoning summary 与不可见 Provider Continuation 必须分离。

Provider Continuation 是 sealed reference，至少绑定：

~~~text
owner_provider
channel
model_family
credential_or_scope_policy
session_scope_hash
schema_version
expires_at
encrypted_payload_ref
~~~

它不能被转换成另一个供应商的 reasoning、Frame 或普通文本。失效、签名错误、模型变化或 scope 不匹配时必须返回明确错误并清理无效状态。

若当前请求没有 reasoning continuation、推理强度或 reasoning summary 需求，目标是否支持高级 reasoning API 不得影响模型使用。

## 17. usage、错误、取消与恢复

### 17.1 Usage

Usage Observation 对每个 token 量使用“已知或未知”的值，至少区分：

- input_tokens；
- output_tokens；
- reasoning_tokens；
- cache_read_tokens；
- cache_creation_tokens；
- total_tokens；
- source；
- aggregation；
- phase；
- accounting_basis；
- final。

Provider 未报告的细分值必须为 unknown，不得填零。流中累计 usage 必须按 Provider 声明处理为 delta、cumulative 或 snapshot。

### 17.2 Error

错误必须具有稳定的 category、scope、retry action、retry time、provider request ID 和 Router request ID。至少区分：

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
- capability_unavailable；
- context_affinity_lost；
- upstream_protocol；
- transport；
- cancelled。

404 或“接口不支持”必须先由 Driver 判断其 scope。它可能表示当前操作不支持，不能自动把整个 Credential 或 Provider Instance 标记为失效。

### 17.3 重试与容灾

在未向客户端提交可见语义事件前，Router 可以按 Driver 的 Retry Advice：

- retry_same_credential；
- try_other_credential_same_provider；
- try_other_endpoint_same_provider；
- try_other_plan_same_provider；
- retry_after；
- choose_other_profile；
- compact_context；
- refresh_auth；
- do_not_retry。

不得出现自动跨供应商 retry。已经提交工具调用、内容或终态后，没有幂等恢复依据时不得重新发起完整请求。

### 17.4 取消与恢复

cancel 必须传播到实际上游请求。SSE 恢复使用 VCP response_id、event_id 与 Last-Event-ID；不支持恢复时返回明确错误，不得静默重新执行模型调用。

有副作用的媒体或工具任务若没有 idempotency_key，不得自动重放。

## 18. Catalog 规则

Catalog 是运行时协议选择依据，不是“模型是否具备全部功能”的展示页。

每个 Model Offering 与 Execution Profile 必须发布：

~~~text
ProtocolCapability
├── base_executable
├── protocol_profile
├── supported_transport
├── context_projection_rules[]
│   ├── semantic_kind
│   ├── native | projected | unsupported
│   ├── execution_equivalence
│   ├── carrier_rule_id
│   └── conditions
├── tool_capability
├── stream_capability
├── media_capability
├── cache_capability
├── remote_compaction_capability
├── reasoning_continuation_capability
├── cancellation_and_recovery
├── token_limits
├── profile_version
└── evidence_revision
~~~

base_executable=true 只要求基础链路和对应合同测试可工作。当前请求会根据 Capability Plan 再计算 operation_eligible。

同名模型在不同 Provider、Channel、Plan、Credential 或 Execution Profile 下的能力不能合并。Kimi K3 的不同上下文规格、Codex 的账号差异、套餐窗口和余额均必须以 Catalog 与 Entitlement 的实际快照为准。

## 19. 客户端可见执行报告

VCP 响应和 SSE 应提供安全的执行摘要，而非泄露内部账本：

~~~text
ExecutionReport
├── response_id
├── execution_id
├── catalog_revision
├── route
│   ├── provider_definition
│   ├── model
│   ├── execution_profile
│   └── plan
├── capability_decisions[]
│   ├── feature
│   ├── selected_mode
│   ├── execution_equivalence
│   └── reason_code
├── conversion_summary
├── cache_observation
├── continuation_summary
├── usage
└── error_or_retry_advice
~~~

建议性投影必须可见，例如：

~~~text
feature=developer_instruction
selected_mode=projected
execution_equivalence=advisory
rule_id=openai_chat.developer.frame.v1
~~~

这让 Vulcan Code 可以在普通请求中接受投影，而在安全或严格任务中要求 native_only。

## 20. 安全与隐私

1. Projection Ledger、Lineage、Provider Continuation 和原始上游请求默认不写入普通日志。
2. Frame 不得包含密钥、账号、签名、内部路径或不必要的 provider metadata。
3. 用户文本中的保留标记必须转义；模型输出中的相似文本默认只是文本。
4. 任何 Driver 注入的固定提示词、内容改写、cloaking、工具请求重建或字段删除都必须有显式规则、触发条件、版本和执行报告。
5. 缓存、请求签名和幂等键计算必须在 Projection Plan 冻结后进行。
6. Provider 的 opaque state 永远不跨 Provider Instance 传递。

## 21. 合同测试与验收

每个正式启用的 Protocol Profile 和系统 Provider Driver 必须有脱敏黄金夹具：

~~~text
VCP Request
  -> Capability Plan
  -> Projection Plan / Ledger
  -> Upstream Request
  -> Upstream Events
  -> VCP Events
  -> Final Response / Lineage
~~~

至少覆盖：

1. 纯文本请求不因未使用工具、缓存、压缩或媒体能力失败。
2. system preamble、developer、system inline 和 delegated_result 的 native 与 Frame 投影。
3. Frame 用户伪造、模型复制、跨分片、回放恢复和 Ledger 不匹配。
4. 主系统提示词作为原生槽位或首条 synthetic carrier 的时序恢复。
5. 工具 ID 缺失、延迟、并行、交错、终态水合和 tool result 邻接。
6. 文本、reasoning、工具和 usage 的流式交错；EOF、failed、incomplete 与重复 done。
7. 缓存 regular、disabled、stable_prefix、rolling_per_turn、manual_breakpoints 与不支持策略。
8. remote compaction 成功、失败、状态替换、亲和性丢失和不支持时的普通对话。
9. Kimi 等多 Execution Profile、套餐授权、上下文限制和多凭据池。
10. 401、403、429、套餐耗尽、容量不足、context 超限、无效 continuation 与同供应商容灾。

base_executable 或某项 native/projected capability 只有在相应合同测试通过后才能发布。

## 22. 实施顺序

1. 冻结 VCP 1.0 的 request、context item、event、Capability Plan、Projection Ledger 和 Execution Report Schema。
2. 实现纯协议内核：校验器、事件 reducer、Frame 编解码、Ledger 与 Lineage 接口。
3. 扩展 Catalog：区分 base_executable、operation_eligible、native、projected、advisory 与 blocked。
4. 实现一个基础 Profile 的端到端纵向路径，优先验证普通文本、developer Frame、主 system 时序和流。
5. 接入原生工具、缓存、reasoning continuation 与 remote compaction 的系统 Provider Driver。
6. 接入自定义 OpenAI Chat / Responses Profile，默认只开放经验证的通用能力。
7. 最后接入媒体协议、恢复、Sidecar 与公共服务治理。

## 23. 最终规则摘要

1. 所有模型默认按基础能力可用，不因未使用的高级功能被整体禁用。
2. 每次请求按实际 payload 生成 Capability Plan。
3. 当前需要的能力优先 native，其次 registered projected。
4. Frame 保证 Router 的身份、顺序、来源和回放可恢复；不虚构上游原生权限。
5. 当前未用到的上游 API 不检查、不调用、不实现。
6. 硬控制能力不能用文本标签伪造；仅在本次请求确实需要时阻止路由。
7. 上游请求、流事件、最终响应和后续回放必须共享同一个 Projection Ledger 与时序模型。
8. 远程压缩、reasoning state 和 opaque continuation 必须遵守 Provider、Model、Channel 与 Credential 亲和性。
9. 高级能力缺失应影响当前操作的执行方式，不应否定模型的基础可用性。
10. 任何降级、投影、省略、失败或同供应商容灾都必须可观察、可测试、可审计。
