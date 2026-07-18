# CLIProxyAPI 协议源码副本

## 来源

- 仓库：`D:/openvulcan/third_git/CLIProxyAPI`
- 固定提交：`9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66`
- 许可证：MIT，许可证原文保存在同目录 `LICENSE`

## 迁移原则

本目录保存 CLIProxyAPI 已验证协议实现的源码副本。上游 Go 文件仅允许进行模块导入前缀机械替换：

`github.com/router-for-me/CLIProxyAPI/v7/`

替换为：

`github.com/OpenVulcan/vulcan-model-core/internal/thirdparty/cliproxyapi/`

不得在本目录直接重写、合并或简化上游协议逻辑。Vulcan 特定适配必须位于本目录之外。

## 同步范围

同步范围是 Anthropic Messages、OpenAI Codex、Google Interactions、Google Antigravity 四个 Responses 转换器的完整构建依赖闭包，包括 translator registry、签名兼容、thinking、schema 清理、工具调用处理和模型辅助代码。四个目标转换包及 translator registry 的上游回归测试一并保留。

## 维护命令

```powershell
pwsh -NoProfile -File tools/sync_cliproxy_protocols.ps1
pwsh -NoProfile -File tools/compare_cliproxy_protocols.ps1
```

同步后必须执行复制层测试、Vulcan 全量测试和逐文件差异审查。
