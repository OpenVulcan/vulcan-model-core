# VCP 兼容矩阵

| Wire 版本 | Go 运行时 | Rust 生成源 | 兼容规则 |
|---|---|---|---|
| `1.0` | 当前版本 | `rust/vcp_v1.rs` | 当前唯一支持版本；未知字段和未知枚举必须拒绝 |

服务在所有 HTTP 响应中返回 `Vulcan-Protocol-Min` 与 `Vulcan-Protocol-Max`。当前两者均为 `1.0`。客户端不得把 `vcp-1`、`1` 或其他历史写法静默改写为 `1.0`。

`POST /vulcan/v1/selections` 只返回一个已选择的供应商作用域 Target，不返回候选供应商、入口或凭据。执行创建后供应商实例不可改变。
