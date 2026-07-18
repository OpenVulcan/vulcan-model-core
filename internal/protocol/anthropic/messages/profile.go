// Package messages exposes the Anthropic Messages profile backed by copied CLIProxyAPI behavior.
// Package messages 暴露由复制 CLIProxyAPI 行为支持的 Anthropic Messages Profile。
package messages

import (
	"github.com/OpenVulcan/vulcan-model-core/internal/protocol/translatedresponses"
	sdktranslator "github.com/OpenVulcan/vulcan-model-core/internal/thirdparty/cliproxyapi/sdk/translator"
)

const (
	// ProfileID is the stable Anthropic Messages protocol profile identifier.
	// ProfileID 是稳定的 Anthropic Messages 协议 Profile 标识。
	ProfileID = "anthropic.messages"
)

// Profile returns the immutable bridge descriptor for Anthropic Messages.
// Profile 返回 Anthropic Messages 的不可变桥接描述符。
func Profile() translatedresponses.Profile {
	return translatedresponses.Profile{ID: ProfileID, Format: sdktranslator.FormatClaude}
}
