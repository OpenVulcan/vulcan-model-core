package vcp

import (
	"math"
	"testing"
)

// TestSpeechSynthesizeValidationSeparatesCanonicalAndProviderRanges verifies that canonical validation permits provider-defined pitch and volume levels.
// TestSpeechSynthesizeValidationSeparatesCanonicalAndProviderRanges 验证规范校验允许由供应商定义音高与音量级别范围。
func TestSpeechSynthesizeValidationSeparatesCanonicalAndProviderRanges(t *testing.T) {
	negativePitch := -12.0
	zeroVolume := 0.0
	operation := SpeechSynthesizeOperation{Text: "hello", VoiceID: "voice", Pitch: &negativePitch, Volume: &zeroVolume}
	if errValidate := operation.Validate(); errValidate != nil {
		t.Fatalf("expected provider-scoped pitch and volume levels to remain structurally valid: %v", errValidate)
	}
}

// TestSpeechSynthesizeValidationRejectsNonFiniteControls verifies that canonical numeric controls cannot contain NaN or infinity.
// TestSpeechSynthesizeValidationRejectsNonFiniteControls 验证规范数值控制不得包含非数或无穷值。
func TestSpeechSynthesizeValidationRejectsNonFiniteControls(t *testing.T) {
	nan := math.NaN()
	infinity := math.Inf(1)
	tests := []SpeechSynthesizeOperation{
		{Text: "hello", VoiceID: "voice", Speed: &nan},
		{Text: "hello", VoiceID: "voice", Pitch: &infinity},
		{Text: "hello", VoiceID: "voice", Volume: &nan},
	}
	for index := range tests {
		if errValidate := tests[index].Validate(); errValidate == nil {
			t.Fatalf("expected non-finite control at index %d to fail", index)
		}
	}
}
