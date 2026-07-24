# Alibaba Cloud Model Studio 与编程套餐静态证据边界

## 1. 文档目的

本文固定 VulcanModelRouter 对 Alibaba Cloud Model Studio、Coding Plan 与 Token Plan 的静态目录、区域隔离、协议及凭据边界。当前基线审核日期为 2026-07-23。

系统不在运行期调用 `bl`、Bailian CLI 或上游模型列表接口，不允许用某个凭据返回的模型集合修改系统目录。模型更新只能通过提交新的独立静态快照、证据修订与审核结论完成。

## 2. 证据来源与裁决规则

| 事实 | 证据 |
| --- | --- |
| Coding Plan、Token Plan 产品模型集合 | Alibaba 官方套餐产品页 |
| API 入口、协议与推荐 Coding 模型 | Qwen Code 官方源码及 Alibaba 官方接入文档 |
| Qwen Code 精确源码基线 | `819cd4ab4a335f04228c161cf89616c2cc88ef28` |
| Model Studio CN / Singapore 完整目录 | 已脱敏并提交的 `listFoundationModels` 完整分页快照 |
| `tool_stream` 与高分辨率视觉参数 | Alibaba 官方协议说明与 Qwen Code `dashscope.ts` |

冲突裁决顺序：

1. 套餐产品页决定套餐的精确模型集合。
2. 相同商业产品下的独立区域证据决定区域能力和限制。
3. Qwen Code 源码决定其已验证的推荐模型、模态与请求扩展行为。
4. 缺少独立证据的产品或区域保持不可发布，不从其他区域、套餐或账号复制事实。

## 3. 可执行产品与协议

| Definition | 产品 | 固定 Base URL | Chat 路径 | 唯一会话协议 |
| --- | --- | --- | --- | --- |
| `system_alibaba_coding_plan_cn` | Coding Plan CN | `https://coding.dashscope.aliyuncs.com` | `/v1/chat/completions` | OpenAI Chat |
| `system_alibaba_coding_plan_global` | Coding Plan Global | `https://coding-intl.dashscope.aliyuncs.com` | `/v1/chat/completions` | OpenAI Chat |
| `system_alibaba_token_plan_personal_cn` | Token Plan Personal CN | `https://token-plan.cn-beijing.maas.aliyuncs.com` | `/compatible-mode/v1/chat/completions` | OpenAI Chat |
| `system_alibaba_token_plan_team_cn` | Token Plan Team CN | `https://token-plan.cn-beijing.maas.aliyuncs.com` | `/compatible-mode/v1/chat/completions` | OpenAI Chat |
| `system_alibaba_token_plan_team_global` | Token Plan Team Global | `https://token-plan.ap-southeast-1.maas.aliyuncs.com` | `/compatible-mode/v1/chat/completions` | OpenAI Chat |
| `system_alibaba_model_studio_cn` | Model Studio CN | `https://dashscope.aliyuncs.com` | `/compatible-mode/v1/chat/completions` | OpenAI Chat |
| `system_alibaba_model_studio_global` | Model Studio Singapore | `https://dashscope-intl.aliyuncs.com` | `/compatible-mode/v1/chat/completions` | OpenAI Chat |

所有产品只使用一个 API Key 凭据，不读取或保存 Bailian CLI Auth、AccessKey/SecretKey 管理凭据，也不为同一个供应商建立 Anthropic 双协议配置。

## 4. 静态目录文件

每个已发布产品必须拥有独立 JSON 快照，Manifest 同时固定：

- 产品、控制台站点、区域和协议通道；
- 证据类型与证据观测时间；
- 快照文件名和 SHA-256 内容修订；
- 已验证或未验证状态。

当前已发布文件：

| Catalog | 静态文件 | 记录数 |
| --- | --- | ---: |
| Coding Plan CN | `coding-plan-cn.json` | 10 |
| Coding Plan Global | `coding-plan-global.json` | 10 |
| Token Plan Personal CN | `token-plan-personal-cn-static.json` | 11 |
| Token Plan Team CN | `token-plan-team-cn.json` | 22 |
| Token Plan Team Global | `token-plan-team-global.json` | 18 |
| Model Studio CN | `model-studio-cn.json` | 471 |
| Model Studio Singapore | `model-studio-sg-domestic.json` | 225 |

历史动态目录来源、动态模型权益与服务权益不会在迁移后保留。套餐模型及静态 Model Studio 模型统一使用“全部已绑定凭据”归属；最终可用性仍要求实例、入口、凭据和访问绑定均有效。

## 5. 套餐模型集合

### 5.1 Coding Plan CN / Global

10 个会话模型：

`qwen3.7-plus`、`qwen3.6-plus`、`qwen3.5-plus`、`qwen3-max-2026-01-23`、`qwen3-coder-next`、`qwen3-coder-plus`、`MiniMax-M2.5`、`glm-5`、`glm-4.7`、`kimi-k2.5`。

### 5.2 Token Plan Personal CN

- 6 个会话模型：`qwen3.8-max-preview`、`qwen3.7-max`、`qwen3.7-plus`、`qwen3.6-flash`、`glm-5.2`、`deepseek-v4-pro`。
- 2 个图像生成模型：`wan2.7-image`、`wan2.7-image-pro`。
- 3 个视频生成模型：`happyhorse-1.1-t2v`、`happyhorse-1.1-i2v`、`happyhorse-1.1-r2v`。
- 不发布 `happyhorse-1.0-video-edit`。

### 5.3 Token Plan Team CN

- 15 个会话模型：`qwen3.8-max-preview`、`qwen3.7-max`、`qwen3.7-plus`、`qwen3.6-plus`、`qwen3.6-flash`、`deepseek-v4-pro`、`deepseek-v4-flash`、`deepseek-v3.2`、`kimi-k2.7-code`、`kimi-k2.6`、`kimi-k2.5`、`glm-5.2`、`glm-5.1`、`glm-5`、`MiniMax-M2.5`。
- 4 个图像生成模型：`qwen-image-2.0`、`qwen-image-2.0-pro`、`wan2.7-image`、`wan2.7-image-pro`。
- 3 个 HappyHorse 视频生成模型，与 Personal CN 相同。

### 5.4 Token Plan Team Global

- 14 个会话模型，不含 `qwen3.8-max-preview`。
- 4 个图像生成模型，与 Team CN 相同。
- 不发布 HappyHorse。
- Global 的上下文限制只使用 Global 独立证据，不继承 CN 数值。

## 6. 多模态和请求扩展

会话模型的图片、视频理解以模型级静态能力声明为准。内联 Base64、远程 URL 和上游对象引用必须通过 VCP 资源计划转换，不能把媒体输入猜测为普通文本。

`tool_stream=true` 仅在以下三个条件同时满足时写入：

1. VCP 请求为流式；
2. 请求确实包含工具；
3. 模型位于精确白名单。

白名单为：

`qwen3.7-max`、`qwen3.7-plus`、`qwen3.6-plus`、`qwen3.6-flash`、`qwen3.5-plus`、`glm-5.2`、`glm-5.1`、`glm-5`、`glm-4.7`。

`vl_high_resolution_images=true` 仅在请求实际包含图片或视频且模型为 `qwen3.5-plus`、`qwen3.6-plus` 或 `qwen3.7-plus` 时写入。其他模型和纯文本请求不得注入。

## 7. Token Plan Harness 工具证据边界

Token Plan 产品页可以证明 `web_search`、`web_extractor`、`t2i_search`、`i2i_search` 与 `code_interpreter` 这些 Harness 工具名称存在。Qwen Code 官方源码进一步证明联网搜索通过独立的 Responses 请求启用 `web_search` 与 `web_extractor`，而不是通过普通 OpenAI Chat 请求字段启用。

当前实现因此只在精确 Token Plan Responses Profile 中发布固定标准工具 `web_search` 与 `web_extractor`，并通过可重复脱敏实测确认请求投影、流式事件和结果归一可用。普通 Chat Profile 不发布这些能力，也不得静默丢弃相应选择。

`t2i_search`、`i2i_search` 与 `code_interpreter` 仍缺少官方源码或可重复脱敏实测所证明的精确 Responses Wire、输入输出事件及结果结构，因此保持未发布。后续只有在证据补齐后，才能按“产品 + 区域 + 模型 + 协议”白名单作为模型额外工具发布，并同时补齐请求投影、响应归一、流式事件和用量测试。

## 8. 未发布边界

以下边界记录在 Manifest 中，但没有 RuntimeReady Definition、入口、驱动或 UI 新建项：

- Token Plan Personal Global；
- Model Studio Hong Kong；
- Model Studio Tokyo；
- Model Studio Frankfurt；
- Model Studio Virginia；
- Model Studio Workspace Singapore。

它们必须在获得独立的完整模型、能力、参数和实际执行证据后，才可通过新的静态快照发布。

## 9. 管理、执行与迁移隔离

- 一次执行只绑定一个不可变 Alibaba Definition。
- CN、Global、Personal、Team、Coding Plan 与 Model Studio 之间不自动回退。
- 凭据新增、替换、删除只修改既有实例的凭据与绑定，不克隆供应商。
- 启动迁移保留实例、入口、凭据、绑定、操作员附加参数、当前套餐、额度及声音缓存。
- 启动迁移清除历史动态目录来源、动态模型权益和动态服务权益，并重建静态模型、操作、规格与账号池。
