// Package antigravity exposes the Google Antigravity profile backed by copied CLIProxyAPI behavior.
// Package antigravity 暴露由复制 CLIProxyAPI 行为支持的 Google Antigravity Profile。
package antigravity

import (
	"github.com/OpenVulcan/vulcan-model-core/internal/protocol/translatedresponses"
	sdktranslator "github.com/OpenVulcan/vulcan-model-core/internal/thirdparty/cliproxyapi/sdk/translator"
)

const (
	// ProfileID is the stable Google Antigravity protocol profile identifier.
	// ProfileID 是稳定的 Google Antigravity 协议 Profile 标识。
	ProfileID = "google.antigravity"
)

// Profile returns the immutable bridge descriptor for Google Antigravity.
// Profile 返回 Google Antigravity 的不可变桥接描述符。
func Profile() translatedresponses.Profile {
	return translatedresponses.Profile{ID: ProfileID, Format: sdktranslator.FormatAntigravity}
}
