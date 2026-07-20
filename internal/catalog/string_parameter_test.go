package catalog

import "testing"

// TestStringParameterValidatesUnicodeLengthAndConstraintShape verifies free-text parameters remain typed and bounded without enum misuse.
// TestStringParameterValidatesUnicodeLengthAndConstraintShape 验证自由文本参数保持类型化与有界且不误用枚举。
func TestStringParameterValidatesUnicodeLengthAndConstraintShape(t *testing.T) {
	minimum, maximum := int64(1), int64(2)
	validDefault := "中文"
	parameter := ParameterDescriptor{ID: "text", Kind: ParameterString, StringRange: &StringRange{MinimumLength: &minimum, MaximumLength: &maximum}, Default: &ParameterDefault{Source: ParameterDefaultProvider, String: &validDefault}}
	if errValidate := parameter.Validate(); errValidate != nil {
		t.Fatalf("expected Unicode code-point range to validate: %v", errValidate)
	}
	invalidDefault := "三个字"
	parameter.Default.String = &invalidDefault
	if errValidate := parameter.Validate(); errValidate == nil {
		t.Fatal("expected overlong string default rejection")
	}
	parameter.Default = nil
	parameter.AllowedValues = []string{"not-a-free-text-choice"}
	if errValidate := parameter.Validate(); errValidate == nil {
		t.Fatal("expected string parameter enum-shape rejection")
	}
}
