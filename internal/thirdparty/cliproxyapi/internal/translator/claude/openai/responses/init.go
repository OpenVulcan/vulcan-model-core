package responses

import (
	. "github.com/OpenVulcan/vulcan-model-core/internal/thirdparty/cliproxyapi/internal/constant"
	"github.com/OpenVulcan/vulcan-model-core/internal/thirdparty/cliproxyapi/internal/interfaces"
	"github.com/OpenVulcan/vulcan-model-core/internal/thirdparty/cliproxyapi/internal/translator/translator"
)

func init() {
	translator.Register(
		OpenaiResponse,
		Claude,
		ConvertOpenAIResponsesRequestToClaude,
		interfaces.TranslateResponse{
			Stream:    ConvertClaudeResponseToOpenAIResponses,
			NonStream: ConvertClaudeResponseToOpenAIResponsesNonStream,
		},
	)
}
