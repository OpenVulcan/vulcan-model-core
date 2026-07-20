package providerconfig

import (
	"errors"
	"testing"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestProviderActionBindingValidatesSearchBackends verifies fixed search implementation rules.
// TestProviderActionBindingValidatesSearchBackends 校验固定搜索实现规则。
func TestProviderActionBindingValidatesSearchBackends(t *testing.T) {
	direct := ProviderActionBinding{
		ID:                "action_search",
		Operation:         vcp.OperationSearchWeb,
		DriverID:          "search_driver",
		DriverVersion:     "1",
		ProtocolProfileID: "search.protocol.v1",
		EndpointProfileID: "search_endpoint",
		AuthMethodIDs:     []string{"api_key"},
		Delivery:          ActionDeliveryModes{Synchronous: true},
		Search:            &SearchActionBinding{BackendKind: vcp.SearchBackendDirectAPI},
		Revision:          1,
	}
	if errValidate := direct.Validate(); errValidate != nil {
		t.Fatalf("valid direct search binding failed validation: %v", errValidate)
	}

	model := direct
	model.Search = &SearchActionBinding{
		BackendKind:            vcp.SearchBackendGroundedModel,
		BackingModelOfferingID: "offer_grounded_model",
		PromptTemplateID:       "search_prompt",
		PromptTemplateRevision: 1,
	}
	if errValidate := model.Validate(); errValidate != nil {
		t.Fatalf("valid model-grounded search binding failed validation: %v", errValidate)
	}

	model.Search.PromptTemplateRevision = 0
	if errValidate := model.Validate(); !errors.Is(errValidate, ErrInvalidConfiguration) {
		t.Fatalf("incomplete prompt binding error = %v, want ErrInvalidConfiguration", errValidate)
	}
}

// TestCustomProviderDefinitionRejectsSystemActionBindings preserves single-protocol customization.
// TestCustomProviderDefinitionRejectsSystemActionBindings 保持自定义供应商单协议约束。
func TestCustomProviderDefinitionRejectsSystemActionBindings(t *testing.T) {
	definition := testCustomDefinition()
	definition.ActionBindings = []ProviderActionBinding{{
		ID:                "action_conversation",
		Operation:         vcp.OperationConversationRespond,
		DriverID:          "trusted_driver",
		DriverVersion:     "1",
		ProtocolProfileID: definition.ProtocolProfileID,
		EndpointProfileID: definition.EndpointProfileID,
		AuthMethodIDs:     append([]string(nil), definition.AuthMethodIDs...),
		Delivery:          ActionDeliveryModes{Synchronous: true},
		Revision:          1,
	}}
	if errValidate := definition.Validate(); !errors.Is(errValidate, ErrInvalidConfiguration) {
		t.Fatalf("custom action binding error = %v, want ErrInvalidConfiguration", errValidate)
	}
}

// TestProviderActionBindingRejectsTaskControlsWithoutAsync verifies task controls cannot be advertised for non-task actions.
// TestProviderActionBindingRejectsTaskControlsWithoutAsync 验证非任务动作不能公开任务控制能力。
func TestProviderActionBindingRejectsTaskControlsWithoutAsync(t *testing.T) {
	binding := ProviderActionBinding{ID: "action_image", Operation: vcp.OperationImageGenerate, DriverID: "image_driver", DriverVersion: "1", ProtocolProfileID: "image.protocol.v1", EndpointProfileID: "image_endpoint", AuthMethodIDs: []string{"api_key"}, Delivery: ActionDeliveryModes{Synchronous: true, Polling: true}, Revision: 1}
	if errValidate := binding.Validate(); !errors.Is(errValidate, ErrInvalidConfiguration) {
		t.Fatalf("polling without async error = %v, want ErrInvalidConfiguration", errValidate)
	}
	binding.Delivery = ActionDeliveryModes{Synchronous: true, Cancellation: true}
	if errValidate := binding.Validate(); !errors.Is(errValidate, ErrInvalidConfiguration) {
		t.Fatalf("cancellation without async error = %v, want ErrInvalidConfiguration", errValidate)
	}
}
