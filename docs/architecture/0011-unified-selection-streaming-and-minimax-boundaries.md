# 0011：统一选择、实时事件与 MiniMax 区域边界

- 状态：已接受
- 日期：2026-07-21
- 适用版本：VCP 1.0

## 背景

Vulcan Code 需要按能力需求选择唯一执行目标，并在执行期间实时接收语义事件和媒体进度。MiniMax 同时存在 CN 与 Global 两套固定入口，并提供文本、视觉、文件、图片、视频、语音、音乐、搜索、OAuth 与额度接口。若选择、续接、重试、资源和区域边界不明确，Router 会出现跨供应商重放、跨区域探测、上游文件标识外泄或伪流式等问题。

## 决策

### 执行前选择

1. `ExecutionSelectionRequest` 可以从经过完整校验的原子目录快照中选择一个精确 Target。
2. Target 包含唯一的 Provider Definition、Instance、Channel、Endpoint、Credential、Model/Service、Upstream ID 与 Execution Profile。
3. Target 一旦写入执行记录即不可变。重试只能在该 Provider Instance 所属的入口和凭据池内发生，不允许跨供应商故障转移。
4. Resolver 只公开被选 Target 与安全的选择证据，不公开候选供应商列表。

### 实时事件

1. Provider Driver 在解析到每个上游语义帧时立即写入 `EventSink`，由 Sink 分配 Router 事件序号并持久化。
2. `tool.arguments.delta` 保留原始增量；媒体流只公开稳定 `output_id`、累计字节数、MIME 与媒体类型，不公开正文。
3. `resource.partial` 的 `output_id` 是执行期间稳定的逻辑输出标识；只有资源被 Router Object Store 完整接收并校验后，`resource.completed` 才携带公开 `resource_id`。
4. 客户端断开不会取消执行。客户端通过 `Last-Event-ID` 重放持久事件后继续跟随。

### 重试、取消和续接

1. 延迟重试状态持久化，默认初始间隔 5 秒、最大间隔 30 分钟；最大次数省略时持续到执行过期或用户取消。
2. 已产生语义输出后，不自动重放没有幂等证据的请求。
3. 取消意图先持久化，再取消进程内 Context；上游任务存在取消接口时再执行同 Target 取消。
4. Router continuation ID 映射到受保护的上游响应 ID，并绑定完整 Target 亲和信息。调用方不能直接提交上游响应 ID。
5. Continuation 私有状态与产生它的执行记录在同一事务边界内持久化；SQLite 载荷保存创建、最后使用、到期、失效时间与原因，上游 ID 不进入公开 JSON。该实现不使用独立表，避免执行成功与 Continuation 创建出现双写分裂，但其生命周期仍由 Router 单独校验和更新。
6. 每次使用通过 CAS 更新最后使用时间；到期、配置或目录删除、精确 Target 不再可用以及供应商明确拒绝分别持久化为封闭失效原因。观察事件追加不会借用执行记录修订号作为事件序号。

### 供应商托管工具

1. `file_search` 与 `code_interpreter` 是供应商内部完成的托管工具；Router 只保留不含结果正文的安全轨迹提示，最终答案仍通过普通输出事件返回。
2. `computer_use` 不是可忽略轨迹。OpenAI Responses 当前 GA 的 `computer_call.actions[]` 与旧版 Preview 的单个 `action` 分别解码为同一组封闭 VCP 计算机动作，但两种 Wire 载体不得混用。
3. Vulcan Code 必须按顺序执行动作并导入 PNG 截图；下一轮通过 Router continuation 提交精确配对的计算机调用与截图结果。Router 仅向上游发送 `computer_call_output`，截图必须由输入计划物化为原始 PNG Data URL，不允许调用方提交上游响应 ID 或任意外部图片 URL。
4. 计算机动作只允许点击、双击、拖动、移动、滚动、按键、输入、等待与截图的强类型字段组合；未知动作或跨变体字段会关闭失败。

### MiniMax 区域与认证

1. MiniMax Global 固定使用 `https://api.minimax.io` 与 `https://account.minimax.io`。
2. MiniMax CN 固定使用 `https://api.minimaxi.com` 与 `https://account.minimaxi.com`。
3. 区域由用户选择的系统变体确定。API Key 和 OAuth 均不得自动探测、回退或切换到另一区域。
4. Messages 使用经证据确认的 `x-api-key`；媒体、文件、声音、额度与 Coding Plan 接口使用 Bearer。认证头由具体 Driver 封闭拥有。
5. 上游文件 ID、任务 ID、OAuth Token 和 `resource_url` 均是 Provider 私有状态，不作为公开 VCP 资源标识返回。

### 多模态与文件

1. 公开输入只接受强类型 URL、Base64/Data URI 或 Router Resource ID，并先经过输入规划与安全物化。
2. Provider File 只作为绑定到精确 Provider、Endpoint、Credential、用途和过期时间的内部物化结果。
3. 供应商源码只证明某一媒体类型或用途时，目录只声明该已证明组合；不因上传接口通用而推测模型能消费其他媒体。
4. 临时 Provider File 在物化失败时补偿删除，在 Router Resource 删除或过期时通过绑定清理器删除。

### 部署与安全

1. 管理面与调用面保持不同凭据域和路由前缀。
2. Secret、对象存储、目录、执行、事件、Continuation 与租约均由接口隔离；本地默认实现不构成公共部署的明文降级许可。
3. 租户、项目、RBAC/OIDC、速率、并发、审计和指标边界必须保持强类型，日志和公开错误不得包含 Secret、Prompt、工具参数、生成正文或私有上游标识。

## 后果

1. 新 Provider 必须先声明精确能力和物化方式，再注册 Driver。
2. 不支持精确用量预检的 Provider 必须返回 `estimated` 或 `unknown`，不得伪装为 `exact`。
3. MiniMax 新增能力必须逐文件对照固定的 `minimax-cli` 证据提交，并将已修复边界转为回归测试。
4. 任何跨供应商执行期回退、区域自动探测或通用无类型 Payload 都违反本决策。
