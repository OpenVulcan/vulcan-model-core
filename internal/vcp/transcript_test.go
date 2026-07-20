package vcp

import (
	"errors"
	"testing"
)

// TestTranscriptValidatesOptionalFactsWithoutInventingThem verifies complete and absent timing shapes.
// TestTranscriptValidatesOptionalFactsWithoutInventingThem 验证完整与缺失时间事实的形态。
func TestTranscriptValidatesOptionalFactsWithoutInventingThem(t *testing.T) {
	start, middle, end := int64(0), int64(500), int64(1000)
	confidence := 0.9
	transcript := Transcript{Candidates: []TranscriptCandidate{{CandidateID: "candidate-0", Text: "hello world", Confidence: &confidence, Segments: []TranscriptSegment{{CandidateID: "candidate-0", SegmentID: "segment-0", Text: "hello world", StartMilliseconds: &start, EndMilliseconds: &end, Words: []TranscriptWord{{Text: "hello", StartMilliseconds: &start, EndMilliseconds: &middle}, {Text: "world", StartMilliseconds: &middle, EndMilliseconds: &end}}}}}}}
	if errValidate := transcript.Validate(); errValidate != nil {
		t.Fatalf("Validate() error = %v", errValidate)
	}
	silent := Transcript{Candidates: []TranscriptCandidate{{CandidateID: "candidate-0", Text: ""}}}
	if errValidate := silent.Validate(); errValidate != nil {
		t.Fatalf("silent Validate() error = %v", errValidate)
	}
}

// TestTranscriptRejectsPartialTimingAndDuplicateIdentity verifies replay facts remain unambiguous.
// TestTranscriptRejectsPartialTimingAndDuplicateIdentity 验证回放事实保持无歧义。
func TestTranscriptRejectsPartialTimingAndDuplicateIdentity(t *testing.T) {
	start := int64(0)
	partial := Transcript{Candidates: []TranscriptCandidate{{CandidateID: "candidate-0", Segments: []TranscriptSegment{{CandidateID: "candidate-0", SegmentID: "segment-0", Text: "hello", StartMilliseconds: &start}}}}}
	if errValidate := partial.Validate(); !errors.Is(errValidate, ErrInvalidRequest) {
		t.Fatalf("partial timing error = %v, want ErrInvalidRequest", errValidate)
	}
	duplicate := Transcript{Candidates: []TranscriptCandidate{{CandidateID: "candidate-0"}, {CandidateID: "candidate-0"}}}
	if errValidate := duplicate.Validate(); !errors.Is(errValidate, ErrInvalidRequest) {
		t.Fatalf("duplicate identity error = %v, want ErrInvalidRequest", errValidate)
	}
}
