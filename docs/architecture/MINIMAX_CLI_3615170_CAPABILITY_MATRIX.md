# MiniMax CLI 固定提交能力证据矩阵

## 证据边界

- 来源仓库：`D:/openvulcan/third_git/minimax-cli`
- 固定提交：`3615170a2e26ec6003c4550cd1324b55ec8ad677`
- 路由实现：Go 原生适配，不引入 Bun、TypeScript 或该仓库的运行时依赖。
- 区域策略：固定提交包含区域配置能力，但 VulcanModelRouter 只使用操作员明确选择的 CN 或 Global Definition，不执行 API Key 跨区探测。
- 零猜测策略：只有固定提交源码、固定测试或代码中已登记的供应商文档证据能够进入可调用目录；存在独立文件接口不等于模型接口接受文件 ID。

## 逐文件来源清单

| 固定来源文件 | 已证实上游接口 | 已证实行为 | Router 实现与限制 |
|---|---|---|---|
| `src/sdk/text/index.ts`、`src/types/api.ts` | `/anthropic/v1/messages` | `x-api-key`；非流式与 SSE；文本、Thinking、工具、工具结果；默认 `MiniMax-M3` | `conversation.respond`；保持 Messages 类型化转换与实时事件；固定源码没有图片 Content Block，因此目录只声明文本输入 |
| `src/sdk/vision/index.ts` | `/v1/coding_plan/vlm` | 请求仅含 `prompt` 与 `image_url`；本地图片转换为 Data URI；响应为 `content` | `media.analyze`；只接受一个图片的内联 Base64/Data URI 物化；不发送未经证实的 `file_id` |
| `src/sdk/search/index.ts`、`test/sdk/search.test.ts` | `/v1/coding_plan/search` | 请求 `{q}`；响应 `organic[]` 含 title/link/snippet/date；固定测试证明日期为 `YYYY-MM-DD` | `search.web`；直接搜索 API Offering；日期规范化为 UTC 当日零点；不虚构分页、日期格式或额外过滤字段 |
| `src/sdk/file/index.ts`、`src/client/endpoints.ts` | `/v1/files/upload`、`/v1/files/list`、`/v1/files/delete`、`/v1/files/retrieve` | `purpose=retrieval` 的 Multipart 上传；元数据列表；数字删除 ID；删除仍检查 `base_resp`；元数据与临时下载 URL 查询 | 独立 `minimax.files.manage` Provider File 管理动作与受保护的列表、单文件查询、删除诊断；上游 ID 与临时下载 URL 均不进入公共 VCP；文件接口存在不代表 VLM 或其他模型消费其 ID |
| `src/sdk/image/index.ts`、`src/types/api.ts` | `/v1/image_generation` | 默认 `image-01` 与 `n=1`；宽高必须同时出现、512–2048、8 的倍数；比例；Seed；Prompt Optimizer；Watermark；URL/Base64；`data.task_id` 与成功/失败计数；Subject Reference 的 URL 或 `image_file` Data URI | `image.generate`；两种互斥响应载体统一导入 Router Resource；Subject Reference 支持直接 HTTPS URL 与内联 Base64，模型和参数使用封闭枚举 |
| `src/sdk/video/index.ts`、`src/types/api.ts` | `/v1/video_generation`、`/v1/query/video_generation`、`/v1/files/retrieve` | 所有模式必须有 Prompt；默认模型按首尾帧与 Subject Reference 决定；Fast 必须首帧；尾帧必须同时有首帧；尾帧与 Subject Reference 互斥；失败终态为 `Failed`；异步任务、可选 Callback 字段与文件取回 | `video.generate` Provider Task；Router 不接收或转发 Callback URL，以持久轮询作为唯一状态事实；任务、文件 ID 和下载 URL 保持私有；重启后按持久任务亲和性继续轮询 |
| `src/sdk/speech/index.ts`、`src/types/api.ts` | `/v1/t2a_v2`、`/v1/get_voice` | 默认 `speech-2.8-hd`；Voice、Speed、Volume、Pitch、Audio Setting、Language Boost、Pronunciation、Subtitle；Hex 非流式与 SSE 流式音频；系统声音目录 | `speech.synthesize`；真实音频分片事件；输出统一导入资源；声音目录按凭据缓存；不从该来源推断 STT |
| `src/sdk/music/index.ts` | `/v1/music_generation`、`/v1/music_cover_preprocess` | 已登记音乐模型；歌词/纯音乐/显式 `lyrics_optimizer` 互斥；Hex/URL 输出；流式不能 URL；直接 URL/Base64 来源允许可选 Lyrics，`cover_feature_id` 路径要求 Lyrics | `music.generate`、`music.cover.prepare`、`music.cover`；不得自动开启 `lyrics_optimizer`；准备句柄不公开；直接与准备两条路径分别测试；真实音频流事件 |
| `src/sdk/quota/index.ts`、`src/types/api.ts`、`src/output/quota-table.ts` | `/v1/token_plan/remains` | 当前周期与周周期、状态、起止时间、剩余时间、Weekly Boost；固定表格实现与测试把误命名的 `current_interval_usage_count` 与 `current_weekly_usage_count` 当作剩余次数 | 凭据作用域 Allowance；由剩余次数反算已用次数；状态 1/2/3 与“两个状态均为 3 且总量为零”的未包含语义分别处理；缓存与单飞刷新 |
| `src/auth/oauth.ts`、`src/auth/refresh.ts` | 区域账号 OAuth 接口 | PKCE 设备授权、轮询、刷新、Resource URL | CN/Global 固定 Origin 白名单；Token 文档受保护；过期前刷新；不利用 Resource URL 切换区域 |

## 独立官方文档证据

以下能力不属于固定 CLI 提交，不能标成源码复制；它们由代码中登记的 MiniMax 官方 API 文档单独约束：

| 官方证据 | 上游接口 | Router 实现与限制 |
|---|---|---|
| `https://platform.minimax.io/docs/api-reference/speech-t2a-async-create` | `/v1/t2a_async_v2`、`/v1/query/t2a_async_query_v2`、`/v1/files/retrieve` | 长文本 `speech.synthesize` Provider Task；只登记文档证明的模型、MP3/WAV、任务状态和文件取回；不把该能力归因于固定 CLI |

## 明确不宣称支持的项目

1. 固定 TextSDK 的 Content Block 没有图片、音频或视频块，因此 `MiniMax-M3` 不声明多模态会话输入。
2. VisionSDK 请求没有 `file_id` 字段，因此 MiniMax VLM 不声明 Provider File ID 物化；Router 文件接口仍可独立用于生命周期诊断和后续有证据的模型载体。
3. 固定提交没有语音转文本实现，因此不为 MiniMax 注册 `speech.transcribe`。
4. 固定提交没有实时语音或 WebRTC，因此本阶段不注册实时语音能力。
5. 固定源码未提供明确套餐名称与模型权益映射；额度可以存在，但不据额度名称推导授权模型。
6. 固定源码包含视频 Callback URL 字段，但 Router 不开放该外部回调能力；外部回调会新增 SSRF、回调鉴权和双重状态源，当前实现统一使用可恢复的任务轮询。

## 回归测试索引

- 区域与额度：`internal/provider/minimax/allowance_test.go`
- OAuth 与刷新：`internal/provider/minimax/oauth_test.go`
- VLM 载体：`internal/provider/minimax/vision_test.go`
- 文件上传、列表、单文件查询与删除：`internal/provider/minimax/files_external_test.go`
- 图片：`internal/provider/minimax/image_test.go`
- 视频：`internal/provider/minimax/video_test.go`
- TTS 与流式音频：`internal/provider/minimax/speech_test.go`
- 声音目录：`internal/provider/minimax/voices_test.go`
- 音乐与两种翻唱路径：`internal/provider/minimax/music_test.go`
