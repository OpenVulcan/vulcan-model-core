package execution

import (
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestValidateProviderTranscriptAndEmitSegments verifies the final union and replay segment projection.
// TestValidateProviderTranscriptAndEmitSegments 验证最终结果联合体与回放分段投影。
func TestValidateProviderTranscriptAndEmitSegments(t *testing.T) {
	start, end := int64(0), int64(1000)
	transcript := &vcp.Transcript{Candidates: []vcp.TranscriptCandidate{{CandidateID: "candidate-0", Text: "hello", Segments: []vcp.TranscriptSegment{{CandidateID: "candidate-0", SegmentID: "segment-0", Text: "hello", StartMilliseconds: &start, EndMilliseconds: &end}}}}}
	request := vcp.ExecutionRequest{Operation: vcp.OperationSpeechTranscribe, Payload: vcp.OperationPayload{SpeechTranscribe: &vcp.SpeechTranscribeOperation{CandidateCount: 1}}}
	result := provider.ExecutionResult{Transcript: transcript}
	if errValidate := validateProviderResult(request, result, true); errValidate != nil {
		t.Fatalf("validateProviderResult() error = %v", errValidate)
	}
	events := typedResultEvents("exec_0123456789abcdef0123456789abcdef", 2, time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC), result, nil)
	if len(events) != 1 || events[0].Type != EventTranscriptSegment || events[0].Transcript == nil || events[0].Transcript.CandidateID != "candidate-0" {
		t.Fatalf("events = %#v", events)
	}
	if errValidate := events[0].Validate(); errValidate != nil {
		t.Fatalf("event Validate() error = %v", errValidate)
	}
}

// TestValidateProviderTranscriptRejectsMissingAndExcessCandidates verifies speech results cannot use another union shape.
// TestValidateProviderTranscriptRejectsMissingAndExcessCandidates 验证语音结果不能使用其他联合体形态。
func TestValidateProviderTranscriptRejectsMissingAndExcessCandidates(t *testing.T) {
	request := vcp.ExecutionRequest{Operation: vcp.OperationSpeechTranscribe, Payload: vcp.OperationPayload{SpeechTranscribe: &vcp.SpeechTranscribeOperation{CandidateCount: 1}}}
	if errValidate := validateProviderResult(request, provider.ExecutionResult{}, true); errValidate == nil {
		t.Fatal("validateProviderResult() accepted missing transcript")
	}
	result := provider.ExecutionResult{Transcript: &vcp.Transcript{Candidates: []vcp.TranscriptCandidate{{CandidateID: "candidate-0"}, {CandidateID: "candidate-1"}}}}
	if errValidate := validateProviderResult(request, result, true); errValidate == nil {
		t.Fatal("validateProviderResult() accepted excess candidates")
	}
}
