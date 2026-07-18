// Package codex exposes the OpenAI Codex profile backed by copied CLIProxyAPI behavior.
// Package codex 暴露由复制 CLIProxyAPI 行为支持的 OpenAI Codex Profile。
package codex

import (
	"github.com/OpenVulcan/vulcan-model-core/internal/protocol/translatedresponses"
	sdktranslator "github.com/OpenVulcan/vulcan-model-core/internal/thirdparty/cliproxyapi/sdk/translator"
)

const (
	// ProfileID is the stable OpenAI Codex protocol profile identifier.
	// ProfileID 是稳定的 OpenAI Codex 协议 Profile 标识。
	ProfileID = "openai.codex"
)

// Profile returns the immutable bridge descriptor for OpenAI Codex.
// Profile 返回 OpenAI Codex 的不可变桥接描述符。
func Profile() translatedresponses.Profile {
	return translatedresponses.Profile{ID: ProfileID, Format: sdktranslator.FormatCodex}
}
