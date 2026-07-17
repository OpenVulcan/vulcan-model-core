# ADR 0003：SQLite、Secret 与管理查询边界

- 状态：已接受
- 日期：2026-07-17
- 范围：配置持久化、目录持久化、Secret 隔离、应用服务和 VulcanCode 只读查询
- 非范围：供应商协议编解码、真实 OAuth 网络流程、供应商模型拉取和上游执行

## 决策

Vulcan Model Core 的首个持久化实现使用 SQLite。Go 代码通过 `database/sql` 与无 CGO 的 `modernc.org/sqlite` 驱动访问数据库。

数据库必须启用 WAL、外键约束和 Busy Timeout。Schema 迁移使用单调递增版本，并在事务中完成。关系列负责标识、Revision、唯一性、所有权与常用筛选；完整领域对象保存为强类型 JSON Payload，读取后必须重新执行领域校验，不能将 JSON 当作跳过约束的通用数据结构。

系统 Provider Definition 仍然只来自代码注册表，不写入业务数据库。数据库只保存用户自定义 Provider Definition、Provider Instance、Endpoint、Credential 非秘密元数据、Access Binding 和原子 Catalog Snapshot。

## Secret 边界

业务数据库禁止保存明文 API Key、Access Token、Refresh Token 和 OAuth Secret。Credential 只保存不可解析的 `SecretRef`。Secret 的写入、读取和删除由独立 `SecretStore` 合同承担。

配置应用服务负责 Secret 与 Credential 元数据之间的顺序：先写 Secret，再保存只包含引用的 Credential；若元数据保存失败，必须删除刚写入的 Secret。SecretStore 的生产级加密文件或系统密钥环实现将在独立安全设计中确定，本阶段提供合同和内存实现以验证边界。

## 应用服务边界

Repository 负责单个聚合的校验与持久化，应用服务负责跨 Repository 工作流、状态流转和补偿。HTTP Handler 不直接组合数据库操作。

Provider Instance 进入 `ready` 前必须至少拥有一个 Ready Endpoint、一个 Active Credential 和一个引用二者的 Enabled Access Binding。该校验不代表上游网络可用，只代表本地配置闭合。

## VulcanCode 查询边界

只读查询 API 使用 Vulcan 自有路径和显式 DTO。它可以返回供应商定义、实例状态、模型、Execution Profile、上下文上限、能力、Pool Summary 和 Allowance，但不得返回 SecretRef、Fingerprint、PrincipalKey 或其他账号级敏感标识。

客户端选择模型时继续使用 `provider_instance_id + provider_model_id + execution_profile_id`，不得使用跨供应商候选列表或同名模型融合。

## 后果

- 本地部署获得事务、迁移和崩溃恢复能力，无需外部数据库或 CGO。
- Catalog 仍以供应商实例为原子快照更新，避免模型、授权和额度出现半更新状态。
- Secret 的生产级持久化实现仍需后续安全专项，但业务 Schema 不会因此被明文 Secret 污染。
- 若未来增加 PostgreSQL，只需实现既有 Store 合同和迁移，不改变领域结构与客户端查询合同。
