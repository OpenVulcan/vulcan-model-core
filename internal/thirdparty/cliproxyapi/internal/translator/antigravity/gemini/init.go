package gemini

import (
	. "github.com/OpenVulcan/vulcan-model-core/internal/thirdparty/cliproxyapi/internal/constant"
	"github.com/OpenVulcan/vulcan-model-core/internal/thirdparty/cliproxyapi/internal/interfaces"
	"github.com/OpenVulcan/vulcan-model-core/internal/thirdparty/cliproxyapi/internal/translator/translator"
)

func init() {
	translator.Register(
		Gemini,
		Antigravity,
		ConvertGeminiRequestToAntigravity,
		interfaces.TranslateResponse{
			Stream:     ConvertAntigravityResponseToGemini,
			NonStream:  ConvertAntigravityResponseToGeminiNonStream,
			TokenCount: GeminiTokenCount,
		},
	)
}
