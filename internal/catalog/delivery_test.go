package catalog

import (
	"errors"
	"testing"
)

// TestValidateDeliveryCapabilitiesRejectsTaskControlsWithoutAsync verifies catalog task controls match executable lifecycle semantics.
// TestValidateDeliveryCapabilitiesRejectsTaskControlsWithoutAsync 验证目录任务控制与可执行生命周期语义一致。
func TestValidateDeliveryCapabilitiesRejectsTaskControlsWithoutAsync(t *testing.T) {
	for _, delivery := range []DeliveryCapabilities{{Synchronous: true, Polling: true}, {Synchronous: true, Cancellation: true}} {
		if errValidate := validateDeliveryCapabilities(delivery); !errors.Is(errValidate, ErrInvalidCatalog) {
			t.Fatalf("validateDeliveryCapabilities(%#v) error = %v, want ErrInvalidCatalog", delivery, errValidate)
		}
	}
	if errValidate := validateDeliveryCapabilities(DeliveryCapabilities{Asynchronous: true, Polling: true, Cancellation: true}); errValidate != nil {
		t.Fatalf("valid async delivery error = %v", errValidate)
	}
	if errValidate := validateDeliveryCapabilities(DeliveryCapabilities{Streaming: true, Cancellation: true}); errValidate != nil {
		t.Fatalf("valid cancellable stream delivery error = %v", errValidate)
	}
}
