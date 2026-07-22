package vcp

import (
	"errors"
	"testing"
)

// TestExecutionRequestRejectsTargetAndPayloadAmbiguity verifies the closed execution union.
// TestExecutionRequestRejectsTargetAndPayloadAmbiguity 校验封闭执行联合体。
func TestExecutionRequestRejectsTargetAndPayloadAmbiguity(t *testing.T) {
	validSearch := validSearchExecutionRequest()
	if errValidate := validSearch.Validate(); errValidate != nil {
		t.Fatalf("valid search execution failed validation: %v", errValidate)
	}

	modelSearch := validSearch
	modelSearch.Target = TargetSelection{Model: &ModelSelection{
		Target:             ModelTargetExact,
		ProviderInstanceID: "provider-instance",
		ProviderModelID:    "provider-model",
	}}
	if errValidate := modelSearch.Validate(); !errors.Is(errValidate, ErrInvalidRequest) {
		t.Fatalf("model-targeted search error = %v, want ErrInvalidRequest", errValidate)
	}

	ambiguousPayload := validSearch
	ambiguousPayload.Payload.EmbeddingCreate = &EmbeddingOperation{}
	if errValidate := ambiguousPayload.Validate(); !errors.Is(errValidate, ErrInvalidRequest) {
		t.Fatalf("ambiguous payload error = %v, want ErrInvalidRequest", errValidate)
	}
}

// TestEmbeddingOperationPreservesExactOneOrderedInputs verifies input identity and union rules.
// TestEmbeddingOperationPreservesExactOneOrderedInputs 校验输入身份和唯一联合体规则。
func TestEmbeddingOperationPreservesExactOneOrderedInputs(t *testing.T) {
	first := "first document"
	second := "second document"
	operation := EmbeddingOperation{
		Inputs: []EmbeddingInput{
			{ID: "first", Text: &first},
			{ID: "second", Text: &second},
		},
		InputTask:  EmbeddingTaskDocument,
		OutputKind: EmbeddingVectorDense,
		Encoding:   EmbeddingEncodingFloat,
	}
	if errValidate := operation.Validate(); errValidate != nil {
		t.Fatalf("valid embedding operation failed validation: %v", errValidate)
	}

	resource := ResourceReference{ResourceID: "resource-1"}
	operation.Inputs[1].Resource = &resource
	if errValidate := operation.Validate(); !errors.Is(errValidate, ErrInvalidRequest) {
		t.Fatalf("ambiguous embedding input error = %v, want ErrInvalidRequest", errValidate)
	}
}

// TestRerankOperationRejectsInvalidTopNAndDuplicateCandidates verifies stable candidate rules.
// TestRerankOperationRejectsInvalidTopNAndDuplicateCandidates 校验稳定候选项规则。
func TestRerankOperationRejectsInvalidTopNAndDuplicateCandidates(t *testing.T) {
	query := "router"
	first := "first"
	second := "second"
	topN := 2
	operation := RerankOperation{
		Query: RerankQuery{ID: "query", Content: RerankContent{Text: &query}},
		Candidates: []RerankCandidate{
			{ID: "first", Content: RerankContent{Text: &first}},
			{ID: "second", Content: RerankContent{Text: &second}},
		},
		TopN:       &topN,
		Truncation: RerankTruncationNone,
	}
	if errValidate := operation.Validate(); errValidate != nil {
		t.Fatalf("valid rerank operation failed validation: %v", errValidate)
	}

	operation.Candidates[1].ID = "first"
	if errValidate := operation.Validate(); !errors.Is(errValidate, ErrInvalidRequest) {
		t.Fatalf("duplicate rerank candidate error = %v, want ErrInvalidRequest", errValidate)
	}
}

// TestWebSearchOperationValidatesPolicies verifies the single public search payload.
// TestWebSearchOperationValidatesPolicies 校验唯一公开搜索载荷。
func TestWebSearchOperationValidatesPolicies(t *testing.T) {
	operation := validSearchExecutionRequest().Payload.SearchWeb
	if errValidate := operation.Validate(); errValidate != nil {
		t.Fatalf("valid web search operation failed validation: %v", errValidate)
	}

	operation.Domains = DomainFilter{Allow: []string{"example.com"}, Block: []string{"EXAMPLE.COM"}}
	if errValidate := operation.Validate(); !errors.Is(errValidate, ErrInvalidRequest) {
		t.Fatalf("duplicate domain error = %v, want ErrInvalidRequest", errValidate)
	}
}

// TestMediaOperationRequiresExplicitTaskInput verifies media-only task semantics.
// TestMediaOperationRequiresExplicitTaskInput 校验仅媒体任务语义。
func TestMediaOperationRequiresExplicitTaskInput(t *testing.T) {
	operation := MediaAnalyzeOperation{
		Task: MediaAnalyzeQuestionAnswer,
		Inputs: []MediaInput{{
			ID:   "image",
			Kind: MediaImage,
			Role: MediaRoleUnderstanding,
			Resource: ResourceReference{
				ResourceID: "resource-image",
			},
		}},
	}
	if errValidate := operation.Validate(); !errors.Is(errValidate, ErrInvalidRequest) {
		t.Fatalf("missing media question error = %v, want ErrInvalidRequest", errValidate)
	}

	operation.Instruction = "What is shown?"
	if errValidate := operation.Validate(); errValidate != nil {
		t.Fatalf("valid media operation failed validation: %v", errValidate)
	}
}

// TestConversationOperationRequiresExplicitMediaRoleAndMediaOnlyIntent verifies new envelopes never infer media semantics.
// TestConversationOperationRequiresExplicitMediaRoleAndMediaOnlyIntent 验证新信封绝不推断媒体语义。
func TestConversationOperationRequiresExplicitMediaRoleAndMediaOnlyIntent(t *testing.T) {
	request := validConversationExecutionRequest()
	request.Payload.Conversation.Context[0].Content = []ContentBlock{{Type: ContentVideo, ResourceRef: "resource-video"}}
	if errValidate := request.Validate(); !errors.Is(errValidate, ErrInvalidRequest) {
		t.Fatalf("missing media role error = %v, want ErrInvalidRequest", errValidate)
	}

	request.Payload.Conversation.Context[0].Content[0].MediaRole = MediaRoleUnderstanding
	if errValidate := request.Validate(); !errors.Is(errValidate, ErrInvalidRequest) {
		t.Fatalf("implicit media-only error = %v, want ErrInvalidRequest", errValidate)
	}

	request.Payload.Conversation.MediaOnlyMode = MediaOnlyConversationUseProfilePolicy
	if errValidate := request.Validate(); errValidate != nil {
		t.Fatalf("explicit media-only request failed validation: %v", errValidate)
	}
}

// TestExecutionRequestRejectsNonPositiveOperationBudget verifies configured ceilings fail before routing.
// TestExecutionRequestRejectsNonPositiveOperationBudget 验证已配置非正数上限在路由前失败。
func TestExecutionRequestRejectsNonPositiveOperationBudget(t *testing.T) {
	request := validSearchExecutionRequest()
	invalidBudget := int64(0)
	request.Budget.MaxExecutionMilliseconds = &invalidBudget
	if errValidate := request.Validate(); !errors.Is(errValidate, ErrInvalidRequest) {
		t.Fatalf("invalid operation budget error = %v, want ErrInvalidRequest", errValidate)
	}
}

// TestEveryOperationAcceptsOnlyItsOwnPayload verifies the complete public operation union with one valid and one mismatched case per operation.
// TestEveryOperationAcceptsOnlyItsOwnPayload 使用每种操作的一个合法与一个错配用例校验完整公开操作联合体。
func TestEveryOperationAcceptsOnlyItsOwnPayload(t *testing.T) {
	imageUnderstanding := MediaInput{ID: "image-understanding", Kind: MediaImage, Role: MediaRoleUnderstanding, Resource: ResourceReference{ResourceID: "resource-image"}}
	imageEdit := MediaInput{ID: "image-edit", Kind: MediaImage, Role: MediaRoleEditSource, Resource: ResourceReference{ResourceID: "resource-image-edit"}}
	videoEdit := MediaInput{ID: "video-edit", Kind: MediaVideo, Role: MediaRoleEditSource, Resource: ResourceReference{ResourceID: "resource-video-edit"}}
	audioTranscription := MediaInput{ID: "audio-transcription", Kind: MediaAudio, Role: MediaRoleTranscriptionSource, Resource: ResourceReference{ResourceID: "resource-audio"}}
	audioCover := MediaInput{ID: "audio-cover", Kind: MediaAudio, Role: MediaRoleCoverReference, Resource: ResourceReference{ResourceID: "resource-cover"}}
	embeddingText := "embedding input"
	rerankQuery := "router"
	rerankCandidate := "candidate"

	conversation := validConversationExecutionRequest().Payload.Conversation
	search := validSearchExecutionRequest().Payload.SearchWeb
	cases := []struct {
		// name labels the closed operation test case.
		// name 标记封闭操作测试场景。
		name string
		// operation is the exact operation discriminator.
		// operation 是精确操作判别值。
		operation OperationKind
		// payload contains the matching typed union member.
		// payload 包含匹配的类型化联合成员。
		payload OperationPayload
	}{
		{name: "conversation", operation: OperationConversationRespond, payload: OperationPayload{Conversation: conversation}},
		{name: "media analyze", operation: OperationMediaAnalyze, payload: OperationPayload{MediaAnalyze: &MediaAnalyzeOperation{Task: MediaAnalyzeDescribe, Inputs: []MediaInput{imageUnderstanding}}}},
		{name: "image generate", operation: OperationImageGenerate, payload: OperationPayload{ImageGenerate: &ImageGenerateOperation{Prompt: "draw a router"}}},
		{name: "image edit", operation: OperationImageEdit, payload: OperationPayload{ImageEdit: &ImageEditOperation{Instruction: "add a label", Sources: []MediaInput{imageEdit}}}},
		{name: "video generate", operation: OperationVideoGenerate, payload: OperationPayload{VideoGenerate: &VideoGenerateOperation{Prompt: "animate a router"}}},
		{name: "video edit", operation: OperationVideoEdit, payload: OperationPayload{VideoEdit: &VideoEditOperation{Instruction: "trim the opening", Source: videoEdit}}},
		{name: "video extend", operation: OperationVideoExtend, payload: OperationPayload{VideoExtend: &VideoExtendOperation{Source: videoEdit, AdditionalDurationSeconds: 2}}},
		{name: "speech synthesize", operation: OperationSpeechSynthesize, payload: OperationPayload{SpeechSynthesize: &SpeechSynthesizeOperation{Text: "hello", VoiceID: "voice"}}},
		{name: "speech transcribe", operation: OperationSpeechTranscribe, payload: OperationPayload{SpeechTranscribe: &SpeechTranscribeOperation{Source: audioTranscription}}},
		{name: "embedding create", operation: OperationEmbeddingCreate, payload: OperationPayload{EmbeddingCreate: &EmbeddingOperation{Inputs: []EmbeddingInput{{ID: "embedding", Text: &embeddingText}}, InputTask: EmbeddingTaskDocument, OutputKind: EmbeddingVectorDense, Encoding: EmbeddingEncodingFloat}}},
		{name: "rerank documents", operation: OperationRerankDocuments, payload: OperationPayload{RerankDocuments: &RerankOperation{Query: RerankQuery{ID: "query", Content: RerankContent{Text: &rerankQuery}}, Candidates: []RerankCandidate{{ID: "candidate", Content: RerankContent{Text: &rerankCandidate}}}, Truncation: RerankTruncationNone}}},
		{name: "search web", operation: OperationSearchWeb, payload: OperationPayload{SearchWeb: search}},
		{name: "music generate", operation: OperationMusicGenerate, payload: OperationPayload{MusicGenerate: &MusicGenerateOperation{Prompt: "ambient music"}}},
		{name: "music cover prepare", operation: OperationMusicCoverPrepare, payload: OperationPayload{MusicCoverPrepare: &MusicCoverPrepareOperation{Source: audioCover}}},
		{name: "music cover", operation: OperationMusicCover, payload: OperationPayload{MusicCover: &MusicCoverOperation{PreparationID: "execution-preparation", Prompt: "jazz cover", Lyrics: "prepared lyrics"}}},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			request := validConversationExecutionRequest()
			request.Operation = testCase.operation
			request.Payload = testCase.payload
			if testCase.operation == OperationSearchWeb {
				request.Target = validSearchExecutionRequest().Target
			}
			if errValidate := request.Validate(); errValidate != nil {
				t.Fatalf("ExecutionRequest.Validate() valid operation error = %v", errValidate)
			}

			request.Payload = OperationPayload{ImageGenerate: &ImageGenerateOperation{Prompt: "foreign payload"}}
			if testCase.operation == OperationImageGenerate {
				request.Payload = OperationPayload{MusicGenerate: &MusicGenerateOperation{Prompt: "foreign payload"}}
			}
			if errValidate := request.Validate(); !errors.Is(errValidate, ErrInvalidRequest) {
				t.Fatalf("ExecutionRequest.Validate() mismatched payload error = %v, want ErrInvalidRequest", errValidate)
			}
		})
	}
}

// validConversationExecutionRequest converts the established canonical conversation fixture into the new envelope.
// validConversationExecutionRequest 将既有规范会话夹具转换为新信封。
func validConversationExecutionRequest() ExecutionRequest {
	legacy := testTextRequest()
	return ExecutionRequest{
		ProtocolVersion: legacy.ProtocolVersion,
		RequestID:       legacy.RequestID,
		Target:          TargetSelection{Model: &legacy.ModelSelection},
		Operation:       OperationConversationRespond,
		Stream:          legacy.Stream,
		Payload: OperationPayload{Conversation: &ConversationOperation{
			Context: legacy.Context, Tools: legacy.Tools, ToolPolicy: legacy.ToolPolicy, GenerationPolicy: legacy.GenerationPolicy,
			ReasoningPolicy: legacy.ReasoningPolicy, CachePolicy: legacy.CachePolicy, ContextManagementPolicy: legacy.ContextManagementPolicy,
			RemoteCompaction: legacy.RemoteCompaction, CapabilityPolicy: legacy.CapabilityPolicy, RegisteredExtensions: legacy.RegisteredExtensions,
		}},
	}
}

// validSearchExecutionRequest creates one fully explicit service-targeted search request.
// validSearchExecutionRequest 创建一个完整显式的服务目标搜索请求。
func validSearchExecutionRequest() ExecutionRequest {
	maxResults := 5
	return ExecutionRequest{
		ProtocolVersion: ProtocolVersion,
		RequestID:       "request-search",
		Target: TargetSelection{Service: &ServiceSelection{
			ProviderInstanceID: "provider-instance",
			ProviderServiceID:  "provider-service",
			ServiceOfferingID:  "service-offering",
			ExecutionProfileID: "execution-profile",
		}},
		Operation: OperationSearchWeb,
		Payload: OperationPayload{SearchWeb: &WebSearchOperation{
			Query:               "latest Vulcan release",
			MaxResults:          &maxResults,
			OutputMode:          WebSearchOutputResults,
			EvidenceRequirement: SearchEvidenceVerified,
		}},
	}
}
