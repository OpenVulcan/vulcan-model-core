# Google Gemini Embedding 证据基线

## 核验信息

- 核验日期：2026-07-20
- 官方指南：`https://ai.google.dev/gemini-api/docs/embeddings`
- 官方 API Reference：`https://ai.google.dev/api/embeddings`

## 已确认事实

1. Google AI Studio 使用 `POST /v1beta/models/{model}:embedContent` 或同步批量 `batchEmbedContents`，通过 `X-Goog-Api-Key` 认证且不流式输出。
2. `batchEmbedContents` 要求每个内部请求的 `models/{model}` 与路径模型一致，并按请求顺序返回 `embeddings[]`。
3. `gemini-embedding-2` 是稳定的多模态 Embedding 模型，输入上限 8192 Token，支持文本、图片、视频、音频与 PDF，维度范围为 128 至 3072，推荐 768、1536 或 3072，默认 3072。
4. `gemini-embedding-2` 的默认及缩短维度输出由供应商自动归一化；其向量空间与 `gemini-embedding-001` 不兼容。
5. `gemini-embedding-2` 不接受旧版 `taskType`，官方对查询与文档任务采用显式文本前缀；Router 不隐藏改写调用方内容，因此初始 Profile 只发布 `provider_default`。
6. `EmbedContentConfig.autoTruncate` 是显式字段；Driver 始终发送 `false`，不允许供应商静默截断。

## 保守边界

- 初始执行 Profile 仅启用文本批次、Dense Float 与 `provider_default`；媒体输入将在资源物化和逐 MIME 限制接入阶段启用，不因为模型总览声明多模态就提前发布。
- 不自动追加查询或文档提示前缀，不把多个输入聚合成一个向量，也不跨 `gemini-embedding-001` 与 `gemini-embedding-2` 比较。
- 不接入高吞吐异步 Batch API；当前 VCP 同步批次使用同步 `batchEmbedContents`。
