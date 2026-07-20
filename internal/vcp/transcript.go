package vcp

import (
	"fmt"
	"math"
	"strings"
)

// Transcript contains one or more ordered non-realtime recognition candidates.
// Transcript 包含一个或多个有序的非实时识别候选。
type Transcript struct {
	// DurationMilliseconds is the provider-confirmed source duration when available.
	// DurationMilliseconds 是可用时供应商确认的源时长。
	DurationMilliseconds *int64 `json:"duration_milliseconds,omitempty"`
	// Candidates contains the primary recognition followed by provider alternatives.
	// Candidates 包含主要识别结果及其后的供应商候选结果。
	Candidates []TranscriptCandidate `json:"candidates"`
}

// TranscriptCandidate contains one complete recognition hypothesis.
// TranscriptCandidate 包含一个完整识别假设。
type TranscriptCandidate struct {
	// CandidateID is stable and unique within one transcript.
	// CandidateID 在一个转写结果内稳定且唯一。
	CandidateID string `json:"candidate_id"`
	// Text is the complete provider-returned transcript and may be empty for silence.
	// Text 是供应商返回的完整转写，静音时可以为空。
	Text string `json:"text"`
	// Language is the provider-confirmed language when available.
	// Language 是可用时供应商确认的语言。
	Language string `json:"language,omitempty"`
	// Confidence is the provider-confirmed candidate confidence in the closed zero-to-one range.
	// Confidence 是供应商确认且处于零至一封闭区间的候选置信度。
	Confidence *float64 `json:"confidence,omitempty"`
	// Segments contains ordered provider-returned segments when available.
	// Segments 包含可用时供应商返回的有序分段。
	Segments []TranscriptSegment `json:"segments,omitempty"`
}

// TranscriptSegment contains one typed segment without fabricating unavailable timing or speaker facts.
// TranscriptSegment 包含一个类型化分段，且不虚构不可用的时间或说话人事实。
type TranscriptSegment struct {
	// CandidateID identifies the owning recognition candidate.
	// CandidateID 标识所属识别候选。
	CandidateID string `json:"candidate_id"`
	// SegmentID is stable and unique within one transcript.
	// SegmentID 在一个转写结果内稳定且唯一。
	SegmentID string `json:"segment_id"`
	// Text is the actual provider-returned segment text.
	// Text 是供应商实际返回的分段文字。
	Text string `json:"text"`
	// StartMilliseconds is the inclusive media offset when available.
	// StartMilliseconds 是可用时包含端点的媒体偏移。
	StartMilliseconds *int64 `json:"start_milliseconds,omitempty"`
	// EndMilliseconds is the exclusive media offset when available.
	// EndMilliseconds 是可用时不包含端点的媒体偏移。
	EndMilliseconds *int64 `json:"end_milliseconds,omitempty"`
	// Speaker is a provider-confirmed speaker label when available.
	// Speaker 是可用时供应商确认的说话人标签。
	Speaker string `json:"speaker,omitempty"`
	// Confidence is the provider-confirmed segment confidence when available.
	// Confidence 是可用时供应商确认的分段置信度。
	Confidence *float64 `json:"confidence,omitempty"`
	// Words contains ordered provider-returned word facts when available.
	// Words 包含可用时供应商返回的有序词级事实。
	Words []TranscriptWord `json:"words,omitempty"`
}

// TranscriptWord contains one word and only the provider-confirmed optional facts.
// TranscriptWord 包含一个词以及仅由供应商确认的可选事实。
type TranscriptWord struct {
	// Text is the actual transcribed word.
	// Text 是实际转写词。
	Text string `json:"text"`
	// StartMilliseconds is the inclusive media offset when available.
	// StartMilliseconds 是可用时包含端点的媒体偏移。
	StartMilliseconds *int64 `json:"start_milliseconds,omitempty"`
	// EndMilliseconds is the exclusive media offset when available.
	// EndMilliseconds 是可用时不包含端点的媒体偏移。
	EndMilliseconds *int64 `json:"end_milliseconds,omitempty"`
	// Speaker is a provider-confirmed word-level speaker label when available.
	// Speaker 是可用时供应商确认的词级说话人标签。
	Speaker string `json:"speaker,omitempty"`
	// Confidence is the provider-confirmed word confidence when available.
	// Confidence 是可用时供应商确认的词级置信度。
	Confidence *float64 `json:"confidence,omitempty"`
}

// Validate verifies candidate identity, ordering, optional timing pairs, and confidence ranges.
// Validate 校验候选身份、顺序、可选时间对与置信度范围。
func (t Transcript) Validate() error {
	if t.DurationMilliseconds != nil && *t.DurationMilliseconds < 0 || len(t.Candidates) == 0 {
		return fmt.Errorf("%w: transcript requires candidates and a non-negative optional duration", ErrInvalidRequest)
	}
	// candidateIDs and segmentIDs enforce stable replay identities across the complete transcript.
	// candidateIDs 与 segmentIDs 在完整转写内强制稳定的回放身份。
	candidateIDs := make(map[string]struct{}, len(t.Candidates))
	segmentIDs := make(map[string]struct{})
	for _, candidate := range t.Candidates {
		if strings.TrimSpace(candidate.CandidateID) == "" || invalidConfidence(candidate.Confidence) {
			return fmt.Errorf("%w: transcript candidate identity or confidence is invalid", ErrInvalidRequest)
		}
		if _, exists := candidateIDs[candidate.CandidateID]; exists {
			return fmt.Errorf("%w: duplicate transcript candidate identifier", ErrInvalidRequest)
		}
		candidateIDs[candidate.CandidateID] = struct{}{}
		var previousEnd *int64
		for _, segment := range candidate.Segments {
			if errSegment := segment.Validate(); errSegment != nil || segment.CandidateID != candidate.CandidateID {
				return fmt.Errorf("%w: transcript segment differs from its candidate", ErrInvalidRequest)
			}
			if _, exists := segmentIDs[segment.SegmentID]; exists {
				return fmt.Errorf("%w: duplicate transcript segment identifier", ErrInvalidRequest)
			}
			segmentIDs[segment.SegmentID] = struct{}{}
			if previousEnd != nil && segment.StartMilliseconds != nil && *segment.StartMilliseconds < *previousEnd {
				return fmt.Errorf("%w: transcript segments are not ordered", ErrInvalidRequest)
			}
			previousEnd = segment.EndMilliseconds
		}
	}
	return nil
}

// Validate verifies one segment and its ordered optional word timing.
// Validate 校验一个分段及其有序可选词级时间。
func (s TranscriptSegment) Validate() error {
	if strings.TrimSpace(s.CandidateID) == "" || strings.TrimSpace(s.SegmentID) == "" || strings.TrimSpace(s.Text) == "" || !validTimestampPair(s.StartMilliseconds, s.EndMilliseconds) || invalidConfidence(s.Confidence) {
		return fmt.Errorf("%w: transcript segment is invalid", ErrInvalidRequest)
	}
	var previousEnd *int64
	for _, word := range s.Words {
		if errWord := word.Validate(); errWord != nil {
			return errWord
		}
		if previousEnd != nil && word.StartMilliseconds != nil && *word.StartMilliseconds < *previousEnd {
			return fmt.Errorf("%w: transcript words are not ordered", ErrInvalidRequest)
		}
		if s.StartMilliseconds != nil && word.StartMilliseconds != nil && (*word.StartMilliseconds < *s.StartMilliseconds || *word.EndMilliseconds > *s.EndMilliseconds) {
			return fmt.Errorf("%w: transcript word is outside its segment", ErrInvalidRequest)
		}
		previousEnd = word.EndMilliseconds
	}
	return nil
}

// Validate verifies one non-empty word and its optional provider facts.
// Validate 校验一个非空词及其可选供应商事实。
func (w TranscriptWord) Validate() error {
	if strings.TrimSpace(w.Text) == "" || !validTimestampPair(w.StartMilliseconds, w.EndMilliseconds) || invalidConfidence(w.Confidence) {
		return fmt.Errorf("%w: transcript word is invalid", ErrInvalidRequest)
	}
	return nil
}

// validTimestampPair accepts an absent pair or one non-negative increasing interval.
// validTimestampPair 接受缺失时间对或一个非负递增区间。
func validTimestampPair(start *int64, end *int64) bool {
	if start == nil || end == nil {
		return start == nil && end == nil
	}
	return *start >= 0 && *end >= *start
}

// invalidConfidence reports values outside the closed zero-to-one range or non-finite values.
// invalidConfidence 报告超出零至一封闭区间或非有限的值。
func invalidConfidence(value *float64) bool {
	return value != nil && (math.IsNaN(*value) || math.IsInf(*value, 0) || *value < 0 || *value > 1)
}
