# Alibaba Cloud Model Studio 套餐供应商证据快照

## 1. 文档目的

本文固定 VulcanModelRouter 第一阶段 Alibaba Cloud Model Studio 编程套餐接入的事实边界。检索日期为 2026-07-19。代码只发布本文有官方证据支持的套餐、入口、模型和能力；按量 API、Workspace、图像、音频与视频能力留待第二阶段。

## 2. 官方来源

| 事实 | 官方来源 |
| --- | --- |
| CN OpenCode 套餐、Base URL、模型 ID 与推荐配置 | <https://help.aliyun.com/zh/model-studio/opencode> |
| Global OpenCode 套餐、Base URL 与模型 ID | <https://www.alibabacloud.com/help/en/model-studio/opencode> |
| Coding Plan 上下文窗口 | <https://help.aliyun.com/zh/model-studio/coding-plan-faq> |
| CN 模型上下文与能力 | <https://help.aliyun.com/zh/model-studio/text-generation-model> |
| Global 模型上下文与能力 | <https://www.alibabacloud.com/help/en/model-studio/text-generation-model/> |
| Anthropic Messages 请求、鉴权与流事件 | <https://help.aliyun.com/zh/model-studio/anthropic-api-messages> |
| Qwen `tool_stream` 行为 | <https://help.aliyun.com/zh/model-studio/qwen-api-via-openai-chat-completions> |
| GLM Anthropic 工具流行为 | <https://help.aliyun.com/zh/model-studio/glm> |
| OpenCode 配置字段语义 | <https://opencode.ai/docs/providers> |

冲突裁决顺序为：套餐产品页决定模型集合，区域模型页决定固有能力，OpenCode 示例决定入口、协议与推荐参数。其他区域或同名模型的数据不能跨目录补全未知字段。

## 3. 产品与入口矩阵

| Definition | 产品 | Region | 固定 Base URL | 唯一协议 | 鉴权 |
| --- | --- | --- | --- | --- | --- |
| `system_alibaba_coding_plan_cn` | Coding Plan CN | CN | `https://coding.dashscope.aliyuncs.com/apps/anthropic/v1` | `anthropic.messages` | API Key |
| `system_alibaba_coding_plan_global` | Coding Plan Global | Global | `https://coding-intl.dashscope.aliyuncs.com/apps/anthropic/v1` | `anthropic.messages` | API Key |
| `system_alibaba_token_plan_personal_cn` | Token Plan Personal CN | CN | `https://token-plan.cn-beijing.maas.aliyuncs.com/apps/anthropic/v1` | `anthropic.messages` | API Key |
| `system_alibaba_token_plan_team_cn` | Token Plan Team CN | CN | `https://token-plan.cn-beijing.maas.aliyuncs.com/apps/anthropic/v1` | `anthropic.messages` | API Key |
| `system_alibaba_token_plan_team_global` | Token Plan Team Global | Global | `https://token-plan.ap-southeast-1.maas.aliyuncs.com/apps/anthropic/v1` | `anthropic.messages` | API Key |

Driver 只追加 `/messages`，因此最终请求地址为 `<Base URL>/messages`。鉴权 Header 是 `x-api-key`；不会发送 Claude Code Beta、Session、Stainless 或浏览器指纹 Header。

## 4. 模型目录边界

| Catalog | 精确模型集合 |
| --- | --- |
| Coding Plan CN / Global | `qwen3.7-plus`, `qwen3.6-plus`, `qwen3.5-plus`, `qwen3-max-2026-01-23`, `qwen3-coder-next`, `qwen3-coder-plus`, `MiniMax-M2.5`, `glm-5`, `glm-4.7`, `kimi-k2.5` |
| Token Plan Personal CN | `qwen3.8-max-preview`, `qwen3.7-max`, `qwen3.7-plus`, `qwen3.6-flash`, `glm-5.2`, `deepseek-v4-pro` |
| Token Plan Team CN | `qwen3.8-max-preview`, `qwen3.7-max`, `qwen3.7-plus`, `qwen3.6-plus`, `qwen3.6-flash`, `deepseek-v4-pro`, `deepseek-v4-flash`, `deepseek-v3.2`, `kimi-k2.7-code`, `kimi-k2.6`, `kimi-k2.5`, `glm-5.2`, `glm-5.1`, `glm-5`, `MiniMax-M2.5` |
| Token Plan Team Global | 与 Team CN 相同，但不含 `qwen3.8-max-preview`；Global 的 `glm-5.2` 上下文为 198,000，不继承 CN 的 1,000,000。 |

所有模型在本阶段仅发布 `text -> text`。即使上游模型具备多模态能力，也不会在 VCP 目录中提前声明未实现的资源执行链路。

## 5. Token 字段语义

- `ContextWindow`：输入、推理和输出共享的总上下文容量。
- `MaxInputTokens`：独立可证明时记录的输入硬上限，不能由总上下文反推。
- `MaxOutputTokens`：独立可证明时记录的输出硬上限。
- `MaxReasoningTokens`：独立可证明时记录的推理硬上限。
- `RecommendedOutputTokens`：供应商建议的默认输出预算，不是硬上限。
- `RecommendedReasoningTokens`：供应商或 OpenCode 配置建议的默认推理预算，不是硬上限。

Coding Plan 的 `1024` 和 Token Plan 的 `8192` 是推荐推理预算。qwen3.8 OpenCode 示例同时出现 `contextWindow=983616`、`maxOutputTokens=131072`、`budgetTokens=262144`；现有资料不足以证明 `983616` 是总上下文，因此代码仅记录已明确的最大输出 131,072，不把配置字段相加、互换或反推为硬上限。

## 6. 流式工具行为

Alibaba 的 `tool_stream` 默认关闭。只有同时满足以下条件才写入 `tool_stream=true`：VCP 请求要求流式输出、请求包含工具、目标模型位于官方明确支持的 Qwen/GLM 白名单。

当前白名单为 `qwen3.7-max`、`qwen3.7-plus`、`qwen3.6-plus`、`qwen3.6-flash`、`qwen3.5-plus`、`glm-5.2`、`glm-5.1`、`glm-5`、`glm-4.7`。未确认的 qwen3.8 以及 DeepSeek、Kimi、MiniMax 不注入该扩展字段。

上游 `input_json_delta.partial_json` 必须逐块转换为 VCP `tool.arguments.delta`，不能在工具块结束时合并为一个伪增量。驱动回归测试同时保护最终 URL、Header 白名单、自动参数和真实分片数量。

## 7. 管理与执行隔离

`alibaba` 仅是管理端分组。五个 Definition 分别拥有 Endpoint、模型目录、实例、凭据与执行 Driver；一次执行绑定一个不可变 Definition，不在 CN/Global、Coding Plan/Token Plan、Personal/Team 之间自动回退，也不增加公开 Anthropic 兼容入口。
