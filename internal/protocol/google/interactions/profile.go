// Package interactions exposes the Google Interactions profile backed by copied CLIProxyAPI behavior.
// Package interactions 暴露由复制 CLIProxyAPI 行为支持的 Google Interactions Profile。
package interactions

import (
	"github.com/OpenVulcan/vulcan-model-core/internal/protocol/translatedresponses"
	sdktranslator "github.com/OpenVulcan/vulcan-model-core/internal/thirdparty/cliproxyapi/sdk/translator"
)

const (
	// ProfileID is the stable Google Interactions protocol profile identifier.
	// ProfileID 是稳定的 Google Interactions 协议 Profile 标识。
	ProfileID = "google.interactions"
)

// Profile returns the immutable bridge descriptor for Google Interactions.
// Profile 返回 Google Interactions 的不可变桥接描述符。
func Profile() translatedresponses.Profile {
	return translatedresponses.Profile{ID: ProfileID, Format: sdktranslator.FormatInteractions}
}
