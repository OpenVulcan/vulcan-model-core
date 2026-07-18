package responses

import (
	. "github.com/OpenVulcan/vulcan-model-core/internal/thirdparty/cliproxyapi/internal/constant"
	"github.com/OpenVulcan/vulcan-model-core/internal/thirdparty/cliproxyapi/internal/interfaces"
	"github.com/OpenVulcan/vulcan-model-core/internal/thirdparty/cliproxyapi/internal/translator/translator"
)

func init() {
	translator.Register(
		OpenaiResponse,
		Interactions,
		ConvertOpenAIResponsesRequestToInteractions,
		interfaces.TranslateResponse{
			Stream:    ConvertInteractionsResponseToOpenAIResponses,
			NonStream: ConvertInteractionsResponseToOpenAIResponsesNonStream,
		},
	)
	translator.Register(
		Interactions,
		OpenaiResponse,
		ConvertInteractionsRequestToOpenAIResponses,
		interfaces.TranslateResponse{
			Stream:    ConvertOpenAIResponsesResponseToInteractions,
			NonStream: ConvertOpenAIResponsesResponseToInteractionsNonStream,
		},
	)
}
