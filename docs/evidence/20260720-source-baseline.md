# 统一能力协议来源与测试基线

## 冻结信息

- 观测日期：2026-07-20
- 当前 Core 提交：`ecfd3071646eff51a422ed57c443faada5895fde`
- Vulcan Model Router 来源提交：`9f7b5a5f61e7076538950d50a4e6867ce6abad20`
- CLIProxyAPI 来源提交：`9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66`
- Go 工具链：`go1.26.1 windows/amd64`

## 基线验证

- `go test ./...`：通过，共 57 个包、780 个测试。
- `npm test`（`web/manage`）：通过，共 6 个测试文件、40 个测试。
- 工作区状态：`main` 与 `origin/main` 对齐，实施开始前无未提交修改。

## 使用边界

- Vulcan Model Router 与 CLIProxyAPI 仅作为已经验证过的供应商行为、协议节点和历史缺陷证据。
- CLIProxyAPI 不得成为 Core 的 Go Module 或运行时依赖。
- 复制协议行为前必须先建立聚焦回归测试，再投影到 VCP 封闭类型。
- 供应商能力、模型范围、地区、端点、限制和响应节点必须继续以当前官方文档与实际夹具确认；本文件中的提交哈希不能替代官方事实。
