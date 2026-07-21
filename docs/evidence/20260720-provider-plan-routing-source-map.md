# 供应商套餐、账号调度与运行状态来源映射

## 固定来源

- 来源仓库：`D:/openvulcan/third_git/CLIProxyAPI`
- 固定提交：`9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66`
- 许可证边界：CLIProxyAPI 仅作为固定源码副本和行为证据，不成为 Core 的 Go Module 或运行时依赖。

## 源文件哈希

| 来源文件 | SHA-256 |
| --- | --- |
| `sdk/cliproxy/auth/selector.go` | `D774517C8668A0ECE683B978DB28BEE82553FEE0969413942CF8763D8FEF809F` |
| `sdk/cliproxy/auth/selector_test.go` | `D71AFA1BB4A4B2D92385BDB99209C90429E4E5B573954B17915237B673C522FB` |
| `sdk/cliproxy/auth/scheduler.go` | `801C4A479D9B7F692A8B19754893F7A7A53A8D8C55271A7AAE5557627FEB388D` |
| `sdk/cliproxy/auth/types.go` | `A30F30D0405892574F39DB8076F21BAC2FA642D65B2D6B3298FA0795D36AE985` |
| `sdk/cliproxy/auth/cooldown_state.go` | `E3C78D954350BCA975C04448880CB22A800FF89E1F1FBDCF6851461A52137A04` |
| `sdk/cliproxy/auth/conductor.go` | `7B4BEB3AB586A57D313FBA8916A28C49A6B95793DC2C34905CBB9A4E47A2AFA8` |

## 复制与适配映射

| CLIProxyAPI 节点 | Vulcan 落点 | 保留行为 | Vulcan 必要差异 |
| --- | --- | --- | --- |
| `RoundRobinSelector.Pick`、`ensureCursorKey` | `internal/routing/selector.go` | 并发锁、按模型游标、4096 Key 上限、稳定轮询 | 候选已由 Resolver 完成套餐、权益、额度与运行状态过滤；键固定包含 Provider Instance 与 Profile |
| `FillFirstSelector.Pick` | `internal/routing/selector.go` | 优先级内稳定选择首账号 | 不支持跨供应商 Mixed 调度 |
| `authPriority`、Scheduler tried 排除 | `internal/routing/selector.go`、`internal/resolve`、`internal/execution` | 优先级桶、一次执行内不重复账号 | Credential Priority 与 Binding Priority 分离；执行的 Provider Instance 永不改变 |
| `QuotaState`、`ModelState`、Cooldown Store | `internal/routingstate`、`internal/sqlitestore/routing_state_store.go` | 模型级冷却、持久恢复、Revision 防覆盖 | 增加凭据、订阅、计费账号、入口和 Provider 精确作用域，不保存 CLIProxyAPI 任意 Auth Metadata |
| `applyAuthFailureState`、`quotaCooldownAfterFailure` | `internal/runtimefeedback/controller.go` | 每个冷却窗口只升级一次、1 秒指数退避、30 分钟上限、`Retry-After` 优先 | 输入仅接受已分类且不含响应正文的强类型错误；状态严格属于一个 Provider Instance |
| Selector、Scheduler、Cooldown 聚焦测试 | `internal/routing/selector_test.go`、`internal/runtimefeedback/controller_test.go`、Resolver/Execution 测试 | Round Robin、Fill First、优先级、并发、游标上限、冷却与 tried 集合 | 删除跨供应商候选测试，增加权益档位、语义输出后禁重放和任务 ID 后亲和冻结测试 |

当前目标文件哈希仅用于本次审计快照，后续合法修改应同步更新本表：

| 目标文件 | SHA-256 |
| --- | --- |
| `internal/routing/selector.go` | `0358C94500842EE03C82681339309406257ABECC5B147F1DB0EEF5E6FDD6F27E` |
| `internal/routing/selector_test.go` | `C1A647A958368BDB47E9174F15B04197DB649F2D4D3803A0F9245ADA5A3DBB35` |
| `internal/runtimefeedback/controller.go` | `12F3E87DDC9DA82DCB86A0D89378A92DB7DA259A718DA2595AF30D0B5D00CB95` |
| `internal/routingstate/store.go` | `61436A8D132A3FCA82554BA1502689F41D8F9A8FE04E0D6E502D82F6AB53DDF3` |

## 账号套餐与用量审计结论

| 产品 | 自动套餐证据 | 模型权益证据 | 用量或余额证据 | 当前处理 |
| --- | --- | --- | --- | --- |
| OpenAI Codex Account | ID Token `chatgpt_plan_type` | 固定提交中的 Free、Team/Business/Go、Plus、Pro 模型集合 | 固定提交未发现实时剩余额度接口 | Token Claim 生成 Plan 与 Entitlement；未知套餐不生成任何权益；启动迁移会删除历史未知套餐的 Pro 权益 |
| Google Antigravity | `loadCodeAssist.paidTier.id` | 固定目录；当前 Tier 未证明改变模型集合 | `paidTier.availableCredits` 的 `GOOGLE_ONE_AI` | Provider API 证据生成 Plan 与非强制 Credit；不把 Credit 耗尽扩大成全部模型禁用 |
| Kimi Coding Plan API Key | 上游固定提交无查询接口；管理员选择 | 用户确认的四档三模型矩阵 | 固定提交无 `/usages` 或余额读取器 | Operator Declared；Andante/Moderato/Allegretto/Allegro 精确生成 allowed/denied Entitlement |
| Kimi Coding Plan Device | 固定提交只有设备授权、Token 刷新和设备头 | 固定提交没有会员档位接口 | 固定提交无用量接口 | 认证成功与商业权益分离；在取得 Kimi TUI 或官方接口证据前保持 Unknown |
| Claude Code | Token 交换提供账号与组织身份 | 固定提交没有套餐到模型集合映射 | 固定提交无实时余额接口 | Plan、Entitlement、Allowance 明确不可用；不从 OAuth 成功推测套餐 |
| xAI Account | ID Token 提供 Subject 与邮箱 | 固定提交只有静态产品目录，没有套餐分支 | 固定提交无实时余额接口 | Plan、Entitlement、Allowance 明确不可用；运行时结构化错误可形成临时状态 |
| Google Vertex Service Account | Project、Service Account、Location | 固定静态 Vertex 目录 | 固定提交无通用余额接口 | 商业套餐不可用；Project/Location 只作为强类型作用域和入口事实 |
| 普通 OpenAI、Anthropic、Google AI Studio、xAI、Kimi CN/Global API Key | 无 | 代码拥有目录或调用时供应商响应 | 只有单次请求 Usage，不等于账号剩余额度 | 不声称存在商业套餐；没有 Credential 时能力授权显示 Unknown，有凭据且目录为 all-bound 时才可执行 |

## 明确不复制的节点

1. Session Affinity、客户端 Prompt Hash、任意 Header、任意 Auth Metadata 与跨供应商 Mixed 调度不进入 Core。
2. CLIProxyAPI 对未知 Codex 套餐回退 Pro 的行为被安全测试明确反转为 Unknown。
3. 不解析供应商错误正文猜测套餐、余额或共享 Scope；Subscription 与 Billing Account 状态只有在 Credential 恰好拥有一个对应强类型 ScopeRef 时才能记录。
4. 已产生文本、推理、工具、媒体、Response ID 或 Provider Task ID 后，不允许更换凭据或入口重放。
5. Kimi 会员查询 URL、Header 与字段路径在固定源码中不存在，因此没有实现候选路径轮询或模糊字段兼容。
