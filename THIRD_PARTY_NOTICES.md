# 第三方软件声明

## CLIProxyAPI 协议实现迁移

- 来源仓库：`https://github.com/router-for-me/CLIProxyAPI`
- 固定来源提交：`9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66`
- 迁入日期：2026-07-17
- 迁入方式：仅选择性复制或实质改编上游协议的 wire、SSE、端点构造、字段归一化与回归测试行为；不引入该仓库的 Go module、运行时依赖、公共 Handler、Translator 注册表、认证池、调度器或跨 Provider 回退。
- 详细来源节点、目标文件与迁入状态见 `docs/architecture/0007-cliproxyapi-protocol-source-migration.md`。

本项目中所有直接复制或实质改编自 CLIProxyAPI 的 Go 文件均保留来源路径、固定提交和改编边界的文件头注释。

### 迁入与实质改编文件清单

生产实现：

- `internal/provider/transport/transport.go`
- `internal/provider/openai/chat.go`
- `internal/provider/openai/responses.go`
- `internal/provider/xai/responses.go`
- `internal/provider/google/aistudio.go`
- `internal/protocol/openai/chat/types.go`
- `internal/protocol/openai/chat/request.go`
- `internal/protocol/openai/chat/response.go`
- `internal/protocol/openai/chat/stream.go`
- `internal/protocol/openai/chat/sse.go`
- `internal/protocol/openai/responses/types.go`
- `internal/protocol/openai/responses/request.go`
- `internal/protocol/openai/responses/response.go`
- `internal/protocol/openai/responses/stream.go`
- `internal/protocol/xai/responses/types.go`
- `internal/protocol/xai/responses/request.go`
- `internal/protocol/xai/responses/stream.go`
- `internal/protocol/google/aistudio/types.go`
- `internal/protocol/google/aistudio/request.go`
- `internal/protocol/google/aistudio/response.go`
- `internal/protocol/google/aistudio/stream.go`

无密钥回归夹具：

- `internal/provider/transport/transport_test.go`
- `internal/provider/openai/chat_test.go`
- `internal/provider/openai/responses_test.go`
- `internal/provider/xai/responses_test.go`
- `internal/provider/google/aistudio_test.go`
- `internal/protocol/openai/chat/request_test.go`
- `internal/protocol/openai/chat/response_test.go`
- `internal/protocol/openai/chat/stream_test.go`
- `internal/protocol/openai/chat/stream_additional_test.go`
- `internal/protocol/openai/chat/sse_test.go`
- `internal/protocol/openai/chat/stream_identity_test.go`
- `internal/protocol/openai/responses/request_test.go`
- `internal/protocol/openai/responses/response_test.go`
- `internal/protocol/openai/responses/stream_test.go`
- `internal/protocol/xai/responses/request_test.go`
- `internal/protocol/xai/responses/stream_test.go`
- `internal/protocol/google/aistudio/request_test.go`
- `internal/protocol/google/aistudio/response_test.go`
- `internal/protocol/google/aistudio/stream_test.go`

### MIT License

Copyright (c) 2025-2005.9 Luis Pater

Copyright (c) 2025.9-present Router-For.ME

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
