# CLIProxyAPI 供应商认证与账号能力事实矩阵

## 固定基线与判定方法

- 源码目录：`D:/openvulcan/third_git/CLIProxyAPI`。
- 固定提交：`9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66`。
- 协议副本：`internal/thirdparty/cliproxyapi`。上游文件只允许模块导入前缀机械替换；目录内唯一的本地文件是由 `tools/cliproxy_register.go.txt` 逐字生成的注册垫片，仅用于满足 Go `internal` 包可见性，所有 Vulcan 业务适配仍位于副本目录之外。
- 账号认证源码范围：协议实现位于 `internal/auth/antigravity`、`claude`、`codex`、`kimi`、`vertex`、`xai`，登录编排、Codex 设备授权与文件存储边界位于 `sdk/auth`。两处源码必须同时逐文件闭环，固定基线中没有其他内置账号认证系列。
- 配置事实来源：`internal/config/config.go`、`internal/config/vertex_compat.go`、`internal/watcher/synthesizer/config.go` 与 `internal/watcher/clients.go`。
- 模型事实来源：`internal/registry/models/models.json` 与 `internal/registry/models/codex_client_models.json`。Vulcan 的对照测试直接读取仓库中的逐字节副本，不通过手写期望值掩盖遗漏。
- “请求 Token 统计”只表示一次推理请求的输入、输出、缓存与推理 Token 计数，不等同于账号套餐、余额或周期用量。

## 执行器与模型目录的重要区分

1. 公开 Gemini API Key 由 CLIProxyAPI 的 `GeminiExecutor` 执行，模型目录键是 `gemini`。Vulcan 的 Google AI Studio 与 Google Interactions 系统产品因此使用 `gemini` 模型目录。
2. CLIProxyAPI 的原生 `aistudio` 执行器是 WebSocket 中继实现，不是公开 Gemini API Key 产品。它的模型目录不能用于证明 Google AI Studio API Key 的模型集合。
3. 固定基线中的 `gemini-cli` 认证、解析和执行由插件宿主提供；主仓库只有插件协议与测试，没有可复制的内置认证实现。因此它不注册为 Vulcan 系统供应商。
4. CLIProxyAPI 固定基线没有静态公开 OpenAI API 模型目录。Vulcan 保留 OpenAI API 系统产品与 Responses Driver，但初始目录为空，不虚构模型清单。
5. `OpenAICompatibility` 与 `VertexCompatKey` 是用户配置的兼容供应商，不是 OpenAI、Google 官方账号产品；Vulcan 将它们落到自定义供应商执行白名单。

## 系统供应商能力矩阵

| 系统供应商产品 | 唯一优势协议 | 默认入口 | CLIProxyAPI 认证证据 | 账号、套餐与授权证据 | 用量或余额证据 | Vulcan 结论 |
| --- | --- | --- | --- | --- | --- | --- |
| OpenAI API | OpenAI Responses | `https://api.openai.com` | API Key | 无静态公开模型清单 | 仅请求 Token 统计 | 已注册系统配置与 Driver；账号读取显式不支持；初始模型目录保持为空 |
| OpenAI Codex API Key | OpenAI Codex | `https://chatgpt.com/backend-api/codex` | `CodexKey` Bearer API Key | `codex-pro` 静态目录 | 仅请求 Token 统计 | 已注册独立系统配置、原始 API Key Driver 与完整静态目录 |
| OpenAI Codex Account | OpenAI Codex | `https://chatgpt.com/backend-api/codex` | 浏览器 OAuth、设备授权、Refresh Token | ID Token 的账号 ID、邮箱、`chatgpt_plan_type`；`free`、`team/business/go`、`plus`、`pro` 精确模型集合 | 未发现实时剩余额度接口 | 已实现两种授权、刷新、身份不变校验、套餐读取与模型授权读取 |
| Anthropic API | Anthropic Messages | `https://api.anthropic.com` | `ClaudeKey` API Key | `claude` 静态目录 | 仅请求 Token 统计 | 已注册系统配置、Messages Driver 与静态目录；账号读取显式不支持 |
| Claude Code | Anthropic Messages | `https://api.anthropic.com` | OAuth、PKCE、Refresh Token、Chrome TLS 指纹兼容传输 | Token 交换返回组织、账号 UUID 与邮箱 | 未发现套餐或实时额度查询 | 已实现 OAuth、线性重试、429 重放阻断、单飞刷新、uTLS 与身份不变校验；套餐和额度显式不支持 |
| Google AI Studio | Gemini GenerateContent | `https://generativelanguage.googleapis.com` | `GeminiKey`、`x-goog-api-key` | `gemini` 静态目录，排除当前无法持久化的图像输出产品 | 仅请求 Token 统计 | 已注册系统配置、GenerateContent Driver 与文本执行目录；账号读取显式不支持 |
| Google Interactions | Google Interactions | `https://generativelanguage.googleapis.com` | `InteractionsKey`，结构复用 `GeminiKey` | `gemini` 静态目录，排除当前无法持久化的图像输出产品 | 仅请求 Token 统计 | 已注册系统配置、Interactions Driver 与文本执行目录；账号读取显式不支持 |
| Google Vertex AI | Vertex GenerateContent | 区域化 `https://{region}-aiplatform.googleapis.com` | 官方 Service Account；CLIProxyAPI 另有第三方 `VertexCompatKey` | Project、Service Account 邮箱、Location 与 `vertex` 静态目录 | 未发现通用余额查询 | 已实现 Service Account JSON 修复、RSA JWT、Token 交换、Project/Location 强类型作用域与区域入口；第三方兼容入口归入自定义供应商 |
| Google Antigravity | Antigravity | `https://cloudcode-pa.googleapis.com` | Google OAuth、Refresh Token | 邮箱、Project、`loadCodeAssist.paidTier.id` | `paidTier.availableCredits` 中的 `GOOGLE_ONE_AI` | 已实现 OAuth、刷新、动态客户端版本、HTTP/1.1 边界、套餐与积分读取；积分是非强制、模型选择相关观测，不会阻塞该凭据的全部模型 |
| Kimi CN | OpenAI Chat | `https://api.moonshot.cn` | API Key | Kimi Open Platform 代码拥有目录 | 固定基线未发现账号或用量读取 | 已注册独立区域产品与唯一 Chat 协议；账号读取显式不支持 |
| Kimi Global | OpenAI Chat | `https://api.moonshot.ai` | API Key | 与 CN 共用模型事实，入口不同 | 固定基线未发现账号或用量读取 | 已注册独立区域产品与唯一 Chat 协议；账号读取显式不支持 |
| Kimi Coding Plan | OpenAI Chat | `https://api.kimi.com/coding` | 设备授权、API Key、Refresh Token、TUI 风格设备头 | `kimi` 静态目录 | 固定基线没有 `/usages`、余额或周期用量读取器 | 已实现设备授权、刷新、设备身份、模型前缀移除与精确七模型目录；协议路径追加 `/v1/chat/completions`，用量显式不支持 |
| Alibaba Coding Plan CN / Global | Anthropic Messages | 区域固定 `/apps/anthropic/v1` 入口 | 阿里云官方 API Key、`x-api-key` | 区域产品页与 Coding Plan 上下文表 | 未发现稳定公开账号或额度 Reader | 已注册两个区域产品、独立 Driver 与隔离目录；流式工具请求按 Qwen/GLM 白名单自动开启 `tool_stream` |
| Alibaba Token Plan Personal CN | Anthropic Messages | `https://token-plan.cn-beijing.maas.aliyuncs.com/apps/anthropic/v1` | 阿里云官方 API Key、`x-api-key` | CN Personal 精确模型集合 | 未发现稳定公开账号或额度 Reader | 已注册个人版产品与独立目录；不虚构 Personal Global |
| Alibaba Token Plan Team CN / Global | Anthropic Messages | CN / Global 区域固定 `/apps/anthropic/v1` 入口 | 阿里云官方 API Key、`x-api-key` | 区域 Team 精确模型集合与上下文差异 | 未发现稳定公开账号或额度 Reader | 已注册两个区域团队版产品与隔离目录；CN/Global 不跨区域合并或回退 |
| xAI API | xAI Responses | `https://api.x.ai/v1` | `XAIKey` Bearer API Key | `xai` 静态目录 | 仅请求 Token 统计 | 已注册系统配置、Responses/Compact Driver 与静态目录；账号读取显式不支持 |
| xAI Account | xAI Responses | `https://cli-chat-proxy.grok.com/v1` | OIDC 发现、RFC 8628 设备授权、Refresh Token | ID Token 中的邮箱与 Subject；`xai` 静态目录 | 未发现套餐或实时额度查询 | 已实现发现、设备授权、刷新、身份不变校验与账号专用请求头；账号入口不声明 Compact |

## 认证刷新与错误语义

所有可刷新账号产品均只在加密 Secret Store 中保存完整 Token 文档。管理端刷新使用不可变 `provider_instance_id + credential_id` 定位凭据，先完成上游交换和账号身份校验，再创建替代 Secret 并持久化新凭据；上游失败不会覆盖旧 Secret。

管理 API 与 Web 使用以下稳定且不含供应商响应正文的分类：

| 分类 | 管理错误码 | HTTP 状态 | Web 行为 |
| --- | --- | --- | --- |
| Refresh Token 或凭据被拒绝 | `provider_authentication_rejected` | 424 | 提示重新授权 |
| 上游限流、5xx、网络或读取失败 | `provider_authentication_unavailable` | 503 | 提示可重试，并明确已保存凭据未改变 |
| 上游状态、JSON、必填字段、过期值或账号身份异常 | `provider_authentication_invalid_response` | 502 | 提示供应商认证响应无法解析，并明确已保存凭据未改变 |
| 浏览器到本地管理 API 的网络失败 | `provider_authentication_network_failed` | 无服务端状态 | 与临时不可用使用相同的安全重试提示 |

Codex 保留三次刷新与一秒、两秒线性等待，并对 `refresh_token_reused` 立即停止；Claude 保留三次线性重试、`Retry-After` 与 429 重放阻断；Kimi、xAI 与 Antigravity 保留各自精确 Grant、请求头与 Token 保留规则。并发管理刷新按同一不可变凭据合并，刷新后的账号 Subject、Account ID、邮箱回退身份或 Project 发生变化时，按无效认证响应拒绝持久化。

## CLIProxyAPI 认证目录逐文件结论

| 上游文件 | 核心事实 | Vulcan 落点或明确排除 |
| --- | --- | --- |
| `internal/auth/models.go` | 通用 TokenStorage 接口 | 由 `internal/secret` 与强类型 Token 文档替代，不引入文件 Token Store |
| `internal/auth/antigravity/auth.go` | Auth URL、Code 交换、用户信息、Project、Onboard | `provider/google/antigravity_oauth.go` 与聚焦测试 |
| `internal/auth/antigravity/auth_test.go` | 授权参数、Project 与 Tier 回归 | `antigravity_oauth_test.go` 的等价边界测试 |
| `internal/auth/antigravity/constants.go` | Client ID、Secret、Scope 与入口 | 原值复制到 Antigravity OAuth 实现 |
| `internal/auth/antigravity/filename.go` | 文件名派生 | 不复制；Vulcan 使用服务端生成不可变 ID 与 Secret 引用 |
| `internal/auth/claude/anthropic.go` | PKCE、Token、账号与组织字段 | `provider/anthropic/claude_oauth.go`、`claude_token.go` |
| `internal/auth/claude/anthropic_auth.go` | OAuth、刷新、重试、429 阻断与单飞 | 原行为适配到 Claude OAuth Client 与管理刷新服务 |
| `internal/auth/claude/anthropic_auth_proxy_test.go` | Proxy 覆盖 | 当前任务不实现代理配置管理器；在边界章节显式记录 |
| `internal/auth/claude/anthropic_auth_test.go` | 授权参数与刷新回归 | `claude_oauth_test.go` 的等价回归 |
| `internal/auth/claude/errors.go` | OAuth 与认证错误类型 | 对外收敛为稳定管理错误码，不透出响应正文 |
| `internal/auth/claude/html_templates.go` | 本地回调 HTML | 不复制；Vulcan 管理 Dialog 展示授权 URL 并提交回调 |
| `internal/auth/claude/oauth_server.go` | 本地回调会话 | 适配为有界、服务端拥有、可取消的内存流程 |
| `internal/auth/claude/pkce.go` | 96 字节 Verifier 与 S256 | 原行为复制并测试 |
| `internal/auth/claude/token.go` | Token 持久字段 | 适配为加密 Secret Store 强类型文档 |
| `internal/auth/claude/utls_transport.go` | Chrome 指纹、HTTP/2 连接与代理边界 | uTLS/HTTP2 行为复制；用户级代理管理器仍显式未实现 |
| `internal/auth/codex/errors.go` | OAuth 与认证错误类型 | 对外收敛为稳定管理错误码 |
| `internal/auth/codex/filename.go` | 邮箱派生文件名 | 不复制；显示名称由身份派生，内部 ID 由服务端生成 |
| `internal/auth/codex/filename_test.go` | 文件名冲突回归 | 文件存储模型不适用 |
| `internal/auth/codex/html_templates.go` | 本地回调 HTML | 不复制；由管理 Dialog 承担交互 |
| `internal/auth/codex/jwt_parser.go` | 邮箱、Account ID 与套餐声明路径 | `provider/openai/codex_token.go`、`codex_catalog.go` |
| `internal/auth/codex/oauth_server.go` | 本地浏览器回调会话 | 适配为有界、服务端拥有、可取消的 OAuth 流程 |
| `internal/auth/codex/openai.go` | PKCE 与 Token Bundle | 适配为强类型 Codex Token 文档 |
| `internal/auth/codex/openai_auth.go` | 浏览器 OAuth、刷新单飞与三次重试 | `codex_oauth.go`、`codex_device_flow.go` 与管理刷新服务 |
| `internal/auth/codex/openai_auth_test.go` | 授权、交换与刷新回归 | Codex OAuth、设备授权和刷新测试覆盖等价边界 |
| `internal/auth/codex/pkce.go` | PKCE 生成 | 原行为复制并测试 |
| `internal/auth/codex/token.go` | Token 持久字段 | 适配为加密 Secret Store 强类型文档 |
| `internal/auth/empty/token.go` | 空 Token Store | 不属于供应商能力，不复制 |
| `internal/auth/kimi/kimi.go` | 设备授权、轮询、设备头、刷新单飞 | `provider/kimi/device_flow.go` 与管理刷新服务 |
| `internal/auth/kimi/kimi_proxy_test.go` | Proxy 覆盖 | 当前任务不实现代理配置管理器 |
| `internal/auth/kimi/kimi_refresh_test.go` | Refresh Grant 与并发去重 | Kimi 刷新和管理单飞测试覆盖等价边界 |
| `internal/auth/kimi/token.go` | Access、Refresh、设备 ID 与过期时间 | 适配为加密 Secret Store 强类型文档 |
| `internal/auth/vertex/keyutil.go` | ANSI、换行、损坏 PEM、PKCS#1/PKCS#8 RSA 修复 | `provider/google/vertex_service_account.go` 原行为适配并测试 |
| `internal/auth/vertex/vertex_credentials.go` | Project、Location 与 Service Account 字段 | Vertex 强类型凭据、Scope 与区域入口 |
| `internal/auth/xai/token.go` | Access、Refresh、ID Token、邮箱、Subject、Token Endpoint | `provider/xai/device_flow.go` 与 `token_store.go` |
| `internal/auth/xai/types.go` | OIDC、设备码与 Token 响应结构 | xAI 强类型响应结构 |
| `internal/auth/xai/xai.go` | 发现、RFC 8628、刷新与 JWT 身份 | xAI DeviceFlow Client、管理刷新与身份不变校验 |
| `internal/auth/xai/xai_auth_test.go` | 入口限制、表单、轮询与刷新回归 | xAI 聚焦测试覆盖等价边界 |

## CLIProxyAPI SDK 认证目录逐文件结论

| 上游文件 | 核心事实 | Vulcan 落点或明确排除 |
| --- | --- | --- |
| `sdk/auth/antigravity.go` | 本地回调、手动粘贴回调、Project 录入与五分钟提前刷新 | `provider/google/antigravity_oauth.go` 的服务端有界流程、`management/onboarding.go` 与刷新服务；不启动独占回调端口 |
| `sdk/auth/claude.go` | 本地回调、手动回调、PKCE、账号录入与四小时提前刷新 | `provider/anthropic/claude_oauth.go` 的服务端有界流程、`management/onboarding.go` 与刷新服务；不复制授权码或 State 日志 |
| `sdk/auth/codex.go` | 浏览器 OAuth、手动回调、设备模式分派与账号记录构建 | `provider/openai/codex_oauth.go`、Codex Flow Manager 与统一原子录入 |
| `sdk/auth/codex_device.go` | User Code、轮询、字符串或数字间隔、设备回调 Redirect URI 与授权码交换 | `provider/openai/codex_device_flow.go` 原行为适配并由设备授权聚焦测试锁定 |
| `sdk/auth/errors.go` | 需要用户提供邮箱或别名的交互错误 | Vulcan 从供应商身份派生唯一名称，不要求管理员重复填写邮箱；该交互错误不适用 |
| `sdk/auth/filestore.go` | 多供应商 JSON 文件落盘、插件多凭据展开、禁用标记与路径解析 | 由加密 `internal/secret`、`providerconfig` 强类型对象和服务端生成 ID 替代，不引入明文认证文件 |
| `sdk/auth/filestore_disabled_test.go` | 禁用状态持久化回归 | `providerconfig` Credential 状态与 SQLite/内存 Store 测试覆盖对应领域行为 |
| `sdk/auth/filestore_test.go` | 文件列表、插件多凭据展开、禁用继承与内置解析抑制 | 文件与插件认证模型不适用；系统/自定义供应商边界由 Definition、Instance、Credential 测试覆盖 |
| `sdk/auth/interfaces.go` | 通用登录选项、认证器接口与 RefreshLead | 由强类型管理命令、供应商专属 Flow Manager 和 Credential `ExpiresAt` 替代，不引入通用 Metadata 登录参数 |
| `sdk/auth/kimi.go` | Kimi 设备授权交互、五分钟提前刷新、设备 ID 与 Token 文档 | `provider/kimi/device_flow.go`、Kimi 原子录入与管理刷新服务 |
| `sdk/auth/manager.go` | 按供应商注册认证器并保存 Auth 记录 | 由系统 Definition 固定分派、供应商专属管理服务、加密 Secret Store 与原子录入替代 |
| `sdk/auth/refresh_registry.go` | Codex、Claude、Antigravity、Kimi、xAI 的刷新提前量注册 | 由 Credential `ExpiresAt`、供应商刷新客户端与管理刷新服务承载；当前阶段仅提供显式管理刷新，不伪装后台自动刷新 |
| `sdk/auth/store_registry.go` | 全局 Token Store 注册与默认文件存储 | 使用显式依赖注入的 Secret Store，不引入全局可变认证存储 |
| `sdk/auth/xai.go` | xAI 设备授权、身份文件名与 RefreshLead | `provider/xai/device_flow.go`、服务端身份派生、原子录入与管理刷新服务 |
| `sdk/auth/xai_test.go` | xAI Provider ID 与刷新提前量回归 | xAI Definition、设备授权和刷新聚焦测试覆盖对应边界 |

## 配置对象到 Vulcan 领域模型的映射

| CLIProxyAPI 配置 | Vulcan 映射 |
| --- | --- |
| `ClaudeKey` | Anthropic API 系统 Definition；API Key 进入 Secret Store，固定官方入口进入 Endpoint，静态模型进入实例目录 |
| `CodexKey` | OpenAI Codex API Key 系统 Definition；Bearer 凭据、固定 Codex 入口与 `codex-pro` 目录 |
| `XAIKey` | xAI API 系统 Definition；Bearer 凭据、官方 xAI 入口与 `xai` 目录 |
| `GeminiKey` | Google AI Studio 系统 Definition；`x-goog-api-key`、官方 Gemini 入口与 `gemini` 目录 |
| `InteractionsKey` | Google Interactions 系统 Definition；认证结构复用 `GeminiKey`，协议固定为 Interactions |
| `OpenAICompatibility` | 自定义供应商 `openai.chat` + `openai_compatibility` Endpoint Profile + Bearer 白名单 |
| `VertexCompatKey` | 自定义供应商 `google.aistudio` + `vertex_compatibility` Endpoint Profile + `x-goog-api-key` 白名单 |
| Vertex Service Account 文件 | Google Vertex AI 系统 Definition；Project、Location、Email、RSA Key 与区域入口均为强类型事实 |

共同字段按 Vulcan 自身领域拆分：多 API Key 对应多个 Credential；Priority 对应 AccessBinding Priority；Base URL 对应 Endpoint；模型 Name、Alias 与 DisplayName 对应 ProviderModel 与 Offering；Excluded Models 对应 ProviderInstance DisabledModelIDs；账号、组织、Project 与 Location 对应 Credential ScopeRefs 或强类型受保护文档。系统产品只使用代码拥有的官方入口，非官方 Base URL 不会悄悄改变系统供应商身份。

## 明确未伪装为已同步的能力

1. `ProxyURL` 只有 `ProviderInstance.ProxyRef` 架构承载位，当前没有用户级代理配置管理器。
2. 任意 `Headers` 不进入管理录入接口，避免将认证秘密或未知协议行为变成无约束透传。
3. `Prefix` 在 Vulcan 中由实例隔离的模型 ID 与显示名承担，不复制 CLIProxyAPI 的客户端模型名前缀调度。
4. `ForceMapping`、`DisableCooling`、Codex/xAI WebSocket、Claude Cloak/Strict/Rebuild、敏感词改写属于 CLIProxyAPI 客户端兼容或调度策略，不是供应商认证、账号套餐或余额事实。
5. Kimi 固定基线没有 `/usages` 实现；Codex、Claude 与 xAI 固定基线没有实时账号余额接口；这些能力保持显式 `unsupported`。
6. 媒体输出模型在 VCP 1.0 缺少 Router 所有的持久输出资源存储，因此从可执行文本目录中显式排除，并由逐字节模型对照测试锁定排除清单。
