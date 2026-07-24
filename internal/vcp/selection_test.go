package vcp

import (
	"errors"
	"testing"
)

// TestExecutionSelectionRequestUsesSharedContextSemantics verifies reserved output cannot exceed the requested total window.
// TestExecutionSelectionRequestUsesSharedContextSemantics 验证预留输出不能超过请求的总窗口。
func TestExecutionSelectionRequestUsesSharedContextSemantics(t *testing.T) {
	valid := ExecutionSelectionRequest{
		ProtocolVersion:         ProtocolVersion,
		RequestID:               "selection-shared-context",
		ProviderInstanceID:      "pvi_test",
		Operation:               OperationConversationRespond,
		RequiredContextTokens:   131_072,
		RequiredMaxOutputTokens: 65_536,
	}
	if errValidate := valid.Validate(); errValidate != nil {
		t.Fatalf("Validate() rejected a valid shared context request: %v", errValidate)
	}
	invalid := valid
	invalid.RequiredMaxOutputTokens = 131_073
	if errValidate := invalid.Validate(); !errors.Is(errValidate, ErrInvalidRequest) {
		t.Fatalf("Validate() error = %v, want ErrInvalidRequest", errValidate)
	}
}
