# 统一能力协议供应商证据与回归矩阵

## 冻结基线

- 核验日期：2026-07-20
- Core 实施起点：`ecfd3071646eff51a422ed57c443faada5895fde`
- Vulcan Model Router 来源提交：`9f7b5a5f61e7076538950d50a4e6867ce6abad20`
- CLIProxyAPI 来源提交：`9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66`
- 来源项目只提供行为证据与历史缺陷夹具，不是 Go Module 或运行时依赖。

## 供应商能力矩阵

| 供应商 | 已实现动作 | 官方证据入口 | 固定实现与回归位置 |
| --- | --- | --- | --- |
| OpenAI | 图片生成/编辑、TTS、STT、Embedding、联网搜索、会话媒体理解 | `developers.openai.com/api/docs/guides/image-generation`、`platform.openai.com/docs/api-reference/audio`、`developers.openai.com/api/reference/resources/embeddings/methods/create`、`developers.openai.com/api/docs/guides/tools-web-search` | `internal/provider/openai/`、`internal/management/media_catalog.go`、`openai_audio_catalog.go`、`openai_embedding_catalog.go` |
| Anthropic | 联网模型 `search.web`、会话媒体理解 | `docs.anthropic.com/en/docs/agents-and-tools/tool-use/web-search-tool`、Anthropic Messages 官方媒体合同 | `internal/provider/anthropic/search.go`、`internal/management/system_catalog.go` |
| Google AI Studio / Interactions / Vertex | 图片生成/编辑、Veo 视频生成/延长、TTS、Embedding、联网搜索、图片/音频/视频理解 | `ai.google.dev/gemini-api/docs/image-generation`、`ai.google.dev/gemini-api/docs/video`、`ai.google.dev/gemini-api/docs/speech-generation`、`ai.google.dev/gemini-api/docs/embeddings`、Google Search grounding 官方指南 | `internal/provider/google/`、`internal/management/google_*_catalog.go`、`system_catalog.go` |
| xAI | 图片生成/编辑、视频生成/编辑/延长、联网搜索、媒体理解 | `docs.x.ai/developers/rest-api-reference/inference/images`、`docs.x.ai/developers/model-capabilities/video/generation`、xAI Search Tools 官方文档 | `internal/provider/xai/`、`internal/management/xai_image_catalog.go` |
| Alibaba Model Studio | Qwen/Wan 图片生成与编辑、Wan 视频生成、Qwen TTS/STT、Fun-ASR 异步转写、Embedding | `alibabacloud.com/help/en/model-studio/qwen-image-api`、`wan-image-generation-and-editing-api-reference`、Wan 视频 API、`qwen-tts-api`、`qwen-asr-api-reference`、DashScope Embedding 文档 | `internal/provider/alibaba/`、`internal/management/alibaba_*_catalog.go` |
| OpenRouter | 图片生成、视频生成、TTS/STT、Embedding、Rerank | `openrouter.ai/docs/guides/overview/multimodal/image-generation`、`openrouter.ai/docs/api/api-reference/video-generation/list-videos-models`、`openrouter.ai/docs/api/api-reference/embeddings/create-embeddings`、`openrouter.ai/docs/api/api-reference/rerank/create-rerank` | `internal/provider/openrouter/`、`internal/management/openrouter_*_catalog.go` |
| MiniMax | 图片生成、视频生成、同步/异步 TTS、音乐生成、两阶段翻唱 | `platform.minimax.io/docs/api-reference/image-generation-t2i`、MiniMax 视频与 TTS API Reference、`platform.minimax.io/docs/api-reference/music-generation`、`music-cover-preprocess` | `internal/provider/minimax/`、`internal/management/minimax_*_catalog.go` |
| Tavily | 独立搜索 API `search.web` | `docs.tavily.com/documentation/api-reference/endpoint/search` | `internal/provider/tavily/`、`internal/bootstrap/tavily.go` |

目录只发布代码、官方证据、Endpoint/地区、凭据资格与运行状态的交集。矩阵中“供应商支持”不等于所有站点、套餐、模型或 Endpoint 均可调用。

## 来源项目问题到固定回归的映射

| 已知风险 | Core 固定行为 | 回归位置 |
| --- | --- | --- |
| OpenAI Chat / Responses 流式工具参数分片、终态 Usage 与结束原因丢失 | 使用封闭语义事件、增量参数合并及终态 Reducer | `internal/protocol/openai/chat/*_test.go`、`internal/protocol/openai/responses/*_test.go` |
| Gemini 多模态 Part 顺序或工具结果角色改写 | 保留规范上下文顺序并通过 ActionBinding 做确定性投影 | `internal/protocol/google/aistudio/request_test.go`、`internal/provider/google/media_test.go` |
| 聚合平台把同名模型能力做并集 | Target 固定 ProviderInstance、Offering、Endpoint 与 Profile；能力按交集收窄 | `internal/resolve/resolver_test.go`、`internal/management/system_catalog_test.go` |
| Base64 Embedding 精度/维度被猜测 | 只有 Profile 明确发布的编码与维度可调用；否则显式拒绝 | `internal/provider/openai/embedding_test.go`、`internal/provider/openrouter/native_test.go` |
| Rerank Score 被归一化或 Candidate 顺序丢失 | 保留 ProviderScore、ScoreSemantics、OriginalIndex 与稳定 Rank | `internal/provider/openrouter/native_test.go`、`internal/vcp/rerank_result_test.go` |
| 联网模型仅收到搜索提示但未实际搜索 | 区分可观察证据、`requested_unverified` 与严格 `search_not_observed` | `internal/provider/openai/search_test.go`、`internal/provider/anthropic/search_test.go`、`internal/provider/google/search_test.go`、`internal/provider/xai/search_test.go` |
| 异步任务轮询后切换供应商、Endpoint、Credential 或 Model | Provider Task 持久化不可变 Target，恢复时只使用原亲和性 | `internal/execution/service_test.go`、`internal/sqlitestore/execution_store_test.go` |
| 供应商 Task ID、Feature ID 或下载 URL 进入公开 JSON/SQLite 明文 | 公开合同只返回 Router ID；持久化句柄进入平台保护 SecretStore | `internal/httpapi/diagnostics_test.go`、`internal/execution/prepared_workflow_test.go`、`internal/sqlitestore/execution_store_test.go` |
| URL 导入 SSRF、重定向绕过、流式超限与临时文件残留 | 每跳重新解析与拒绝非公网地址，边读边限额并清理临时对象 | `internal/resource/importer_test.go`、`internal/resource/service_test.go` |
| 多阶段翻唱跳过准备、复用过期 Feature 或跨凭据复用 | `preparation_id` 是 Router Execution ID，并校验所有者、期限与完整亲和性 | `internal/provider/minimax/music_test.go`、`internal/execution/prepared_workflow_test.go` |

## 保守发布边界

1. 未找到当前官方字段或限制证据时使用 `unknown`，不填猜测值。
2. 不支持的媒体角色、MIME、数量、尺寸、时长、参数组合或交付模式在网络调用前失败。
3. 上游上传、对象 URI、文件 ID、Task ID、Feature ID 与临时下载 URL 不进入调用面、管理面或普通日志。
4. 图片、音频、视频理解都允许混合会话与媒体单轮理解，但必须由精确 Profile 分别声明；Core 不自动抽帧或抽取音轨冒充原生能力。
5. Web Search 对外只有 `search.web`，独立搜索 API 与联网模型不能在一次执行中自动切换或组合。
6. Embedding 与 Rerank 不扩展成向量数据库、索引、集合、相似度查询或跨模型 Score 比较。
7. MiniMax 官方同步音乐接口没有已确认取消合同，因此目录不虚构取消能力。

## 审核入口

- 能力模型：`internal/catalog/capability_contracts.go`、`service_offerings.go`、`output_parameters.go`
- 公共协议：`internal/vcp/media.go`、`operations.go`、`embedding.go`、`rerank.go`、`search.go`、`transcript.go`、`music.go`
- 资源与物化：`internal/resource/`、`internal/inputplan/`
- 执行与持久化：`internal/execution/`、`internal/sqlitestore/execution_store.go`
- 管理与调用发现：`internal/management/query.go`、`internal/httpapi/`
- 前端 Schema 与页面：`web/manage/src/lib/model-capabilities.ts`、`diagnostics.ts`、`web/manage/src/pages/`
