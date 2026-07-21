package management

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
)

// TestDefaultCustomRequestProjectionProvidesEditableReasoning verifies every supported custom protocol has an executable baseline.
// TestDefaultCustomRequestProjectionProvidesEditableReasoning 验证每个受支持的自定义协议都有可执行默认配置。
func TestDefaultCustomRequestProjectionProvidesEditableReasoning(t *testing.T) {
	for _, protocolProfileID := range []string{"openai.chat", "openai.responses", "anthropic.messages"} {
		projection, errProjection := defaultCustomRequestProjection(protocolProfileID)
		if errProjection != nil {
			t.Fatalf("defaultCustomRequestProjection(%q) error = %v", protocolProfileID, errProjection)
		}
		if len(projection.Reasoning.Effort) == 0 {
			t.Fatalf("defaultCustomRequestProjection(%q) has no effort rules", protocolProfileID)
		}
		if errValidate := projection.Validate(); errValidate != nil {
			t.Fatalf("defaultCustomRequestProjection(%q).Validate() error = %v", protocolProfileID, errValidate)
		}
	}
}

// TestUnsupportedReasoningStillAllowsAdditionalParameters verifies extra payload rules are independent from reasoning capability.
// TestUnsupportedReasoningStillAllowsAdditionalParameters 验证额外载荷规则独立于推理能力。
func TestUnsupportedReasoningStillAllowsAdditionalParameters(t *testing.T) {
	projection := catalog.RequestProjection{Additional: catalog.AdditionalPayloadProjection{Override: []catalog.PayloadParameter{{Path: "temperature", Value: json.RawMessage(`0.2`)}}}}
	instance := providerconfig.ProviderInstance{ID: "pvi_custom_projection", DefinitionID: "custom_projection", Handle: "projection", DisplayName: "Projection", Status: providerconfig.LifecycleReady, Revision: 1}
	input := InitialProviderModelInput{UpstreamModelID: "model", DisplayName: "Model", ToolCalling: catalog.CapabilityNative, Reasoning: catalog.CapabilityUnsupported, RequestProjection: &projection}
	if _, errBuild := buildInitialProviderCatalog(instance, "openai.chat", input, time.Now().UTC()); errBuild != nil {
		t.Fatalf("buildInitialProviderCatalog() additional-only error = %v", errBuild)
	}
	projection.Reasoning.Effort = []catalog.ReasoningParameterRule{{Value: "high", Set: []catalog.PayloadParameter{{Path: "reasoning_effort", Value: json.RawMessage(`"high"`)}}}}
	if _, errBuild := buildInitialProviderCatalog(instance, "openai.chat", input, time.Now().UTC()); errBuild == nil {
		t.Fatal("buildInitialProviderCatalog() accepted reasoning rules for an unsupported model")
	}
}

// TestValidateCustomProjectionForProtocolRejectsDualOpenRouterCarriers verifies shorthand and nested effort cannot disagree.
// TestValidateCustomProjectionForProtocolRejectsDualOpenRouterCarriers 验证简写与嵌套强度载体不能产生分歧。
func TestValidateCustomProjectionForProtocolRejectsDualOpenRouterCarriers(t *testing.T) {
	projection := catalog.RequestProjection{Reasoning: catalog.ReasoningRequestProjection{Effort: []catalog.ReasoningParameterRule{{
		Value: "high", Set: []catalog.PayloadParameter{{Path: "reasoning.effort", Value: json.RawMessage(`"high"`)}},
	}}}}
	if errValidate := validateCustomProjectionForProtocol("openai.chat", projection); errValidate == nil {
		t.Fatal("validateCustomProjectionForProtocol() accepted nested effort without deleting the Chat shorthand")
	}
	projection.Reasoning.Effort[0].Delete = []string{"reasoning_effort"}
	if errValidate := validateCustomProjectionForProtocol("openai.chat", projection); errValidate != nil {
		t.Fatalf("validateCustomProjectionForProtocol() valid override error = %v", errValidate)
	}
}
