# 统一能力执行协议与调用流程

## 目标与边界

Vulcan Model Router 对外只暴露 Vulcan 协议。调用方先从模型或特殊服务目录选择一个精确的供应商实例与执行规格；一次执行的供应商身份随后不可改变。Endpoint、Region、Credential 与 Plan 只允许在该供应商实例内部按已发布规则解析，Core 不接受供应商候选列表，也不执行跨供应商自动回退。

本阶段支持以下封闭操作：

| 类别 | Operation |
| --- | --- |
| 会话与理解 | `conversation.respond`、`media.analyze` |
| 图片 | `image.generate`、`image.edit` |
| 视频 | `video.generate`、`video.edit`、`video.extend` |
| 非实时语音 | `speech.synthesize`、`speech.transcribe` |
| 音乐 | `music.generate`、`music.cover.prepare`、`music.cover` |
| 向量与重排 | `embedding.create`、`rerank.documents` |
| 特殊服务 | `search.web` |

实时语音、WebRTC、语音克隆、向量数据库、自动文档分块、跨供应商搜索加生成、3D、Avatar、口型同步、超分与音频特效不属于本阶段。

## 发现与选择

1. 使用调用面 API Key 请求 `POST /vulcan/v1/info`，并用请求体 `{"get":"instances"}`、`{"get":"models"}` 或 `{"get":"services"}` 选择唯一信息投影。
2. `get` 是封闭枚举，当前只接受 `instances | models | accounts | services | usage`；不为每个信息层级增加独立 HTTP GET 路径。
3. 只选择目录中实际返回的 Profile。模型目录包含 Operation、输入与输出模态、媒体角色、客户端工作流、上游物化方式、限制、参数、交付模式、用量精度和能力修订。
4. `known: false` 表示供应商限制未知，不能当作无限；`conditional` 表示必须按目录中的工作流或兼容条件调用。
5. `Pool.ready_credentials` 为零时该 Profile 不可立即执行；管理目录仍保留已停用、未授权、冷却、额度耗尽或无效凭据等聚合原因。
6. 使用 `{"get":"accounts","provider_instance_id":"...","provider_model_id":"..."}` 获取一个精确模型的全部上下文规格，以及每个规格下已授权的具体本地账号、套餐、有效上下文上限和当前运行状态。
7. 使用 `{"get":"usage","provider_instance_id":"...","provider_model_id":"...","credential_id":"..."}` 查询一个精确模型账号组合的当前目录用量。响应只返回适用于该账号与模型规格交集的当前额度，并保留观测时间与失效时间；共享套餐、组织或计费账号的上游标识不会公开。

模型 Target 使用 `provider_instance_id + provider_model_id + execution_profile_id`。特殊服务 Target 使用 `provider_instance_id + provider_service_id + service_offering_id + execution_profile_id`。两种 Target 不能同时出现。

## 资源与多模态输入

执行 Payload 只引用 Router `resource_id`，不直接携带 URL、Base64 或供应商文件 ID：

1. Multipart 文件使用 `POST /vulcan/v1/resources`。
2. URL 或 Base64 使用 `POST /vulcan/v1/resources/import`。
3. 使用 `GET /vulcan/v1/resources/{resource_id}` 检查安全元数据。
4. 当能力为条件路径或客户端需要确认具体传输方式时，调用 `POST /vulcan/v1/input-plans`。
5. 将返回的 Router `input_plan_id` 与相同 ResourceRef 放入执行请求。目录修订、资源事实或 Target 发生变化时，旧计划会被明确拒绝。

URL 导入在读取正文前校验 Scheme、DNS、IP 与重定向；禁止 Loopback、私网、Link-local、保留地址及 DNS Rebinding。文件经过大小、MIME 魔数与媒体元数据校验，二进制正文位于 `~/.vulcan/router/resources/`，不写入 SQLite。

### 媒体理解示例

```json
{
  "protocol_version": "1.0",
  "request_id": "req_media_01",
  "target": {
    "model": {
      "target": "exact",
      "provider_instance_id": "pvi_google",
      "provider_model_id": "model_gemini",
      "execution_profile_id": "profile_media_analyze"
    }
  },
  "operation": "media.analyze",
  "payload": {
    "media_analyze": {
      "task": "question_answer",
      "instruction": "概括图片中的主要内容",
      "inputs": [
        {
          "id": "image_1",
          "kind": "image",
          "role": "understanding",
          "resource": { "resource_id": "res_0123456789abcdef0123456789abcdef" }
        }
      ]
    }
  }
}
```

同一多模态模型的混合会话使用 `conversation.respond`，把媒体块放在规范上下文中；媒体单轮理解使用 `media.analyze`。图片、音频、视频都遵守相同的 Router ResourceRef 原则，但各自的角色、MIME、数量、大小、时长、尺寸与媒体单独策略必须取自所选 Profile。

## 执行与事件

使用 `POST /vulcan/v1/executions` 创建执行。请求信封中的 `idempotency_key` 与规范请求 Hash 一起绑定到调用面主体；相同键与相同请求返回原执行，相同键与不同请求返回冲突。

状态机为：

```text
accepted -> preparing_inputs -> queued -> running
accepted/preparing_inputs/queued/running -> failed | cancelled | expired
running -> succeeded | partially_succeeded
```

同步 Driver 可以从 `running` 直接进入终态；异步 Driver 持久化精确 Target 后按供应商建议间隔轮询。`GET /vulcan/v1/executions/{id}/events` 支持 `Last-Event-ID` 重放，事件序号单调递增。没有供应商真实进度时不会生成虚假百分比。

调用 `POST /vulcan/v1/executions/{id}/cancel` 只在供应商合同真实支持取消时确认取消；不支持取消会返回显式错误。终态不可逆。

供应商 Task ID、准备句柄与 Provider Asset Handle 均只保存在平台保护的 SecretStore 中，SQLite 只保存不透明引用。公开执行、事件、资源与管理诊断只返回 Router ID。

## 两阶段音乐翻唱

MiniMax 翻唱使用两个不可跳过的执行：

1. `music.cover.prepare` 接收一个 `cover_reference` 音频 ResourceRef，返回 Router 所有的 `preparation_id`、格式化歌词、结构与过期时间。
2. `music.cover` 引用该 `preparation_id`。Core 校验所有者、有效期、供应商定义、实例、Endpoint、Region、Credential 与上游模型亲和性，再把受保护的供应商句柄交给同一 Driver。

调用方永远不会看到上游 Feature ID。

## Embedding、Rerank 与 Web Search

- `embedding.create` 保留输入 ID 与顺序，响应分别使用 Dense、Sparse 或 Multi-vector 类型。维度、归一化、距离度量与用量均来自供应商事实；Core 不保存向量。
- `rerank.documents` 保留 Candidate ID、OriginalIndex、Rank 与供应商原始 Score 语义，不自动分块、截断、归一化或跨模型比较。
- 对外只有 `search.web`。所选 ServiceOffering 在代码中固定为 `direct_search_api` 或 `model_grounded_search`；公共请求和响应不因后端类型变化。
- 联网模型必须返回可观察搜索证据。仅请求了搜索但没有可观察证据时使用 `requested_unverified`；严格证据模式会失败为 `search_not_observed`。
- Core 不在两种搜索后端之间自动降级，也不把搜索结果自动交给第二个供应商模型总结。

## 错误合同

HTTP 错误使用不含 Prompt、Transcript、URL、Base64、凭据或上游句柄的安全字符串。常见分类如下：

| HTTP | 错误 | 含义 |
| --- | --- | --- |
| `400` | `invalid execution request`、`invalid input plan request`、`invalid resource request` | 请求形态、未知字段、枚举或参数不合法 |
| `401` | `unauthorized` | 管理密钥或调用面 API Key 不匹配；两个命名空间不能互换 |
| `404` | `execution not found`、`resource not found` | 资源不存在或不属于当前调用主体 |
| `409` | `idempotency conflict`、`execution changed concurrently`、`capability changed`、`resource conflict` | 幂等、修订或生命周期冲突 |
| `413` | `resource limit exceeded` | 单项、总量或正文大小超过已发布上限 |
| `422` | `no eligible target`、`input plan unavailable` | 没有满足供应商、能力、资源与凭据交集的精确路径 |
| `502` | `resource import failed`、`provider_invalid_response` | 上游响应或资源导入违反已确认合同 |
| `500` | `execution failed`、`resource operation failed` | 已脱敏的内部失败 |

执行进入失败终态时，`failure.code` 使用当前封闭机器码：`capability_changed`、`cancelled`、`deadline_exceeded`、`provider_action_unavailable`、`provider_invalid_response` 或 `provider_execution_failed`；`retryable` 只在当前错误事实明确为超时时为真。供应商返回的异步安全错误码只在 Task Driver 已验证其不含敏感内容后原值保留。

## 管理诊断

管理 Web 提供模型能力、特殊服务能力、Resource 与 Execution 四个只读页面。资源诊断不返回正文、摘要、对象路径、来源 URL 或所有者；执行诊断不返回请求、结果正文、Provider Task 或准备句柄。管理 API Key 不能调用调用面，调用面 API Key 也不能读取管理诊断。

## 验证

```powershell
gofmt -w .
go test ./...
go build -o test-output ./cmd/vulcan-model-core
Set-Location web/manage
npm test
```

管理端不执行生产构建；开发服务器已运行时不重复启动。
