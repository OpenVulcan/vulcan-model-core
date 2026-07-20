package catalog

import (
	"errors"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestExtendedModelCapabilitiesValidateTypedMediaAndEmbedding verifies callable contracts remain fully typed and evidenced.
// TestExtendedModelCapabilitiesValidateTypedMediaAndEmbedding 验证可调用合同保持完整类型化且具有证据。
func TestExtendedModelCapabilitiesValidateTypedMediaAndEmbedding(t *testing.T) {
	capabilities := validExtendedCapabilities()
	if errValidate := capabilities.Validate(); errValidate != nil {
		t.Fatalf("Validate() error = %v", errValidate)
	}
}

// TestMediaCapabilityRejectsMismatchedLimitVariant verifies media limit unions cannot describe another modality.
// TestMediaCapabilityRejectsMismatchedLimitVariant 验证媒体限制联合体不能描述其他模态。
func TestMediaCapabilityRejectsMismatchedLimitVariant(t *testing.T) {
	capabilities := validExtendedCapabilities()
	capabilities.MediaInputs[0].Image = nil
	capabilities.MediaInputs[0].Audio = &AudioMediaLimits{}
	if errValidate := capabilities.Validate(); !errors.Is(errValidate, ErrInvalidCatalog) {
		t.Fatalf("Validate() error = %v, want ErrInvalidCatalog", errValidate)
	}
}

// TestImageCapabilityValidatesClosedDimensionPairs verifies exact sizes are positive and unique.
// TestImageCapabilityValidatesClosedDimensionPairs 验证精确尺寸均为正数且不重复。
func TestImageCapabilityValidatesClosedDimensionPairs(t *testing.T) {
	capabilities := validExtendedCapabilities()
	capabilities.MediaOutputs[0].Image.AllowedDimensions = []ImageDimensions{{Width: 1024, Height: 1024}, {Width: 1536, Height: 1024}}
	if errValidate := capabilities.Validate(); errValidate != nil {
		t.Fatalf("Validate() error = %v", errValidate)
	}
	capabilities.MediaOutputs[0].Image.AllowedDimensions = append(capabilities.MediaOutputs[0].Image.AllowedDimensions, ImageDimensions{Width: 1024, Height: 1024})
	if errValidate := capabilities.Validate(); !errors.Is(errValidate, ErrInvalidCatalog) {
		t.Fatalf("Validate() duplicate dimensions error = %v, want ErrInvalidCatalog", errValidate)
	}
}

// TestCloneCapabilitiesDeepCopiesExtendedContracts verifies callers cannot mutate nested catalog facts.
// TestCloneCapabilitiesDeepCopiesExtendedContracts 验证调用方不能修改嵌套目录事实。
func TestCloneCapabilitiesDeepCopiesExtendedContracts(t *testing.T) {
	original := validExtendedCapabilities()
	cloned := cloneCapabilities(original)
	cloned.MediaInputs[0].Roles[0] = vcp.MediaRoleMask
	cloned.MediaInputs[0].Common.MIMETypes[0] = "image/gif"
	cloned.MediaInputs[0].Evidence[0].Reference = "changed"
	cloned.Embedding.Dimensions[0] = 1
	cloned.MediaOutputs[0].Formats[0] = "gif"
	cloned.Parameters[0].AllowedValues[0] = "changed"
	cloned.ParameterRules[0].RelatedParameterIDs[0] = "changed"
	if original.MediaInputs[0].Roles[0] != vcp.MediaRoleUnderstanding || original.MediaInputs[0].Common.MIMETypes[0] != "image/png" || original.MediaInputs[0].Evidence[0].Reference != "official-image-doc" || original.Embedding.Dimensions[0] != 768 || original.MediaOutputs[0].Formats[0] != "png" || original.Parameters[0].AllowedValues[0] != "creative" || original.ParameterRules[0].RelatedParameterIDs[0] != "seed" {
		t.Fatalf("original capabilities were mutated: %#v", original)
	}
}

// TestParameterContractRejectsOutOfRangeDefault verifies defaults cannot escape declared capability ceilings.
// TestParameterContractRejectsOutOfRangeDefault 验证默认值不能逸出声明的能力上限。
func TestParameterContractRejectsOutOfRangeDefault(t *testing.T) {
	capabilities := validExtendedCapabilities()
	invalidDefault := int64(101)
	capabilities.Parameters[1].Default.Integer = &invalidDefault
	if errValidate := capabilities.Validate(); !errors.Is(errValidate, ErrInvalidCatalog) {
		t.Fatalf("Validate() error = %v, want ErrInvalidCatalog", errValidate)
	}
}

// TestModelCapabilitiesValidateOperationRequiresExactContracts verifies typed profiles cannot advertise unrelated capability unions.
// TestModelCapabilitiesValidateOperationRequiresExactContracts 验证类型化 Profile 不能发布无关能力联合体。
func TestModelCapabilitiesValidateOperationRequiresExactContracts(t *testing.T) {
	imageCapabilities := validExtendedCapabilities()
	imageCapabilities.Embedding = nil
	if errValidate := imageCapabilities.ValidateOperation(vcp.OperationImageGenerate); errValidate != nil {
		t.Fatalf("image generation contract error = %v", errValidate)
	}
	imageCapabilities.MediaOutputs = nil
	if errValidate := imageCapabilities.ValidateOperation(vcp.OperationImageGenerate); !errors.Is(errValidate, ErrInvalidCatalog) {
		t.Fatalf("missing image output error = %v, want ErrInvalidCatalog", errValidate)
	}

	embeddingCapabilities := validExtendedCapabilities()
	embeddingCapabilities.MediaOutputs = nil
	if errValidate := embeddingCapabilities.ValidateOperation(vcp.OperationEmbeddingCreate); errValidate != nil {
		t.Fatalf("embedding contract error = %v", errValidate)
	}
}

// validExtendedCapabilities creates a fully evidenced image and embedding capability fixture.
// validExtendedCapabilities 创建完整证据化的图片与 Embedding 能力夹具。
func validExtendedCapabilities() ModelCapabilities {
	defaultMode := "creative"
	minimumSeed := int64(0)
	maximumSeed := int64(100)
	defaultSeed := int64(42)
	observedAt := time.Date(2026, time.July, 20, 0, 0, 0, 0, time.UTC)
	return ModelCapabilities{
		Tokens:                 TokenLimits{ContextWindow: OptionalTokenLimit{Known: true, Value: 32768}},
		ToolCalling:            CapabilityNative,
		ParallelToolCalls:      CapabilityUnsupported,
		StreamingToolArguments: CapabilityUnsupported,
		StrictJSONSchema:       CapabilityUnsupported,
		Reasoning:              CapabilityUnsupported,
		InputModalities:        []string{"text", "image"},
		OutputModalities:       []string{"text"},
		Delivery:               DeliveryCapabilities{Synchronous: true, Streaming: true},
		MediaInputs: []MediaInputCapability{{
			Kind: vcp.MediaImage, Roles: []vcp.MediaInputRole{vcp.MediaRoleUnderstanding}, Level: CapabilityNative,
			InteractionModes: []MediaInteractionMode{MediaInteractionMixedConversation, MediaInteractionMediaOnlyConversation, MediaInteractionAnalysis}, MediaOnlyPolicy: MediaOnlyNative,
			AllowedAuthorities: []vcp.Authority{vcp.AuthorityUser}, AllowedPlacements: []vcp.Placement{vcp.PlacementTranscript},
			ClientWorkflows: []ClientResourceWorkflow{ClientWorkflowUploadThenReference, ClientWorkflowImportURLThenReference}, MaterializationModes: []UpstreamMaterializationMode{MaterializationInlineBase64},
			Common:        CommonMediaLimits{MIMETypes: []string{"image/png", "image/jpeg"}, MaxItemBytes: OptionalLimit{Known: true, Value: 10_000_000}, MaxItems: OptionalLimit{Known: true, Value: 4}},
			Image:         &ImageMediaLimits{MaxWidth: OptionalLimit{Known: true, Value: 4096}, MaxHeight: OptionalLimit{Known: true, Value: 4096}},
			Compatibility: MediaCompatibility{ToolCalling: CapabilityNative, Streaming: CapabilityNative, Reasoning: CapabilityUnsupported, StructuredOutput: CapabilityNative},
			Evidence:      []CapabilityEvidence{{Source: ModelSourceSystem, Reference: "official-image-doc", ObservedAt: time.Date(2026, time.July, 20, 0, 0, 0, 0, time.UTC), Revision: 1}}, EvidenceRevision: 1,
		}},
		Embedding: &EmbeddingCapabilities{
			InputTasks: []vcp.EmbeddingInputTask{vcp.EmbeddingTaskQuery, vcp.EmbeddingTaskDocument}, OutputKinds: []vcp.EmbeddingVectorKind{vcp.EmbeddingVectorDense}, Encodings: []vcp.EmbeddingEncoding{vcp.EmbeddingEncodingFloat},
			Dimensions: []int{768, 1024}, DefaultDimensions: OptionalLimit{Known: true, Value: 768}, MaxBatchItems: OptionalLimit{Known: true, Value: 32}, Normalized: OptionalBool{Known: true, Value: true},
		},
		MediaOutputs: []MediaOutputCapability{{
			Kind: vcp.MediaImage, Level: CapabilityNative, Formats: []string{"png", "jpeg"}, MaxOutputs: OptionalLimit{Known: true, Value: 4},
			Image:    &ImageMediaLimits{MaxWidth: OptionalLimit{Known: true, Value: 4096}, MaxHeight: OptionalLimit{Known: true, Value: 4096}},
			Delivery: DeliveryCapabilities{Synchronous: true}, Evidence: []CapabilityEvidence{{Source: ModelSourceSystem, Reference: "official-image-output-doc", ObservedAt: observedAt, Revision: 1}}, EvidenceRevision: 1,
		}},
		Parameters: []ParameterDescriptor{
			{ID: "mode", Kind: ParameterEnum, AllowedValues: []string{"creative", "deterministic"}, Default: &ParameterDefault{Source: ParameterDefaultProvider, String: &defaultMode}},
			{ID: "seed", Kind: ParameterInteger, IntegerRange: &IntegerRange{Minimum: &minimumSeed, Maximum: &maximumSeed}, Default: &ParameterDefault{Source: ParameterDefaultProvider, Integer: &defaultSeed}},
		},
		ParameterRules: []ParameterRule{{Kind: ParameterRuleRequiresWhenEnum, ParameterID: "mode", RelatedParameterIDs: []string{"seed"}, EnumValue: "deterministic"}},
		UsageMetrics:   []UsageMetricCapability{{Unit: UsageUnitImages, Accuracy: UsageExact}, {Unit: UsageUnitPixels, Accuracy: UsageEstimated}},
	}
}
