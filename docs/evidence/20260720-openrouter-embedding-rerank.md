# OpenRouter Embedding 与 Rerank 证据基线

## 核验信息

- 核验日期：2026-07-20
- 官方 Embedding 创建接口：`https://openrouter.ai/docs/api/api-reference/embeddings/create-embeddings`
- 官方 Embedding 模型列表接口：`https://openrouter.ai/docs/api/api-reference/embeddings/list-embeddings-models`
- 官方 Rerank 接口：`https://openrouter.ai/docs/api/api-reference/rerank/create-rerank`
- 来源项目：`D:/openvulcan/vulcan-model-router`
- 来源文件：`internal/runtime/executor/openrouter_executor.go`
- 来源回归文件：`internal/runtime/executor/openrouter_executor_test.go`

## 已确认事实

1. Embedding 使用 `POST /api/v1/embeddings`，Bearer API Key 认证，不支持流式输出。
2. Embedding 请求包含必需的 `model`、`input`，并可包含 `dimensions`、`encoding_format`、`input_type`。
3. `encoding_format` 的官方枚举为 `float` 与 `base64`；VCP 不虚构 `float32` 或 `float64` 精度。
4. Embedding 响应通过 `data[].index` 对应原始批量输入，Router 必须验证索引完整、唯一且顺序稳定。
5. 官方 Embedding 模型列表示例确认 `openai/text-embedding-3-small`、文本输入、8192 上下文；OpenRouter 接口允许传入正整数 `dimensions`，但当前可直接核验的逐模型资料没有同时给出该路由模型的默认维度与精确上下界，因此初始目录不发布维度范围。
6. Rerank 使用 `POST /api/v1/rerank`，Bearer API Key 认证，不支持流式输出。
7. Rerank 请求包含必需的 `model`、`query`、`documents`，可选 `top_n`。
8. Rerank 响应按相关性排序，以 `index` 指向原始候选，并返回 `relevance_score`；Router 必须原值保留该分数，不做归一化或跨模型比较。
9. 官方示例确认 `cohere/rerank-v3.5` 可通过该接口调用。
10. 来源项目已验证 `/embeddings`、`/rerank` 原生路径、Bearer 认证和原生动作拒绝流式输出；新实现保留这些行为，但将原始 JSON 透传替换为封闭 VCP 投影与类型化响应校验。

## 保守边界

- 初始 OpenRouter Embedding Profile 只公开文本、Dense、`float` 与 `provider_default`，不把模型相关 `input_type`、Base64、维度范围、多模态输入或未知批量上限当作通用能力。
- Driver 保留官方接口定义的 Base64 解析能力，供未来存在逐模型维度证据的 Profile 使用；Base64 结果没有自描述维度，Router 不按字节长度猜测元素精度。
- 初始 Rerank Profile 只公开文本 Query 与文本 Candidate；官方虽定义结构化图文文档联合体，但在逐模型限制证据完成前不发布多模态 Rerank。
- 不公开供应商路由候选、跨供应商回退、静默截断、静默分块或 Score 改写。
