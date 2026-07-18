// Package register activates the selected copied CLIProxyAPI protocol translators.
// Package register 激活选定的复制 CLIProxyAPI 协议转换器。
package register

import (
	_ "github.com/OpenVulcan/vulcan-model-core/internal/thirdparty/cliproxyapi/internal/translator/antigravity/openai/responses"
	_ "github.com/OpenVulcan/vulcan-model-core/internal/thirdparty/cliproxyapi/internal/translator/claude/openai/responses"
	_ "github.com/OpenVulcan/vulcan-model-core/internal/thirdparty/cliproxyapi/internal/translator/codex/openai/responses"
	_ "github.com/OpenVulcan/vulcan-model-core/internal/thirdparty/cliproxyapi/internal/translator/openai/interactions/responses"
)
