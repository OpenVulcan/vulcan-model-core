package responses

import (
	. "github.com/OpenVulcan/vulcan-model-core/internal/thirdparty/cliproxyapi/internal/constant"
	"github.com/OpenVulcan/vulcan-model-core/internal/thirdparty/cliproxyapi/internal/interfaces"
	"github.com/OpenVulcan/vulcan-model-core/internal/thirdparty/cliproxyapi/internal/translator/translator"
)

func init() {
	translator.Register(
		OpenaiResponse,
		Antigravity,
		ConvertOpenAIResponsesRequestToAntigravity,
		interfaces.TranslateResponse{
			Stream:    ConvertAntigravityResponseToOpenAIResponses,
			NonStream: ConvertAntigravityResponseToOpenAIResponsesNonStream,
		},
	)
}
