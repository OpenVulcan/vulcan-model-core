package vcp

import (
	"fmt"
	"strings"
	"time"
)

// MusicCoverPreparation is the Router-owned public result of one cover preprocessing execution.
// MusicCoverPreparation 是一次翻唱预处理执行产生的 Router 所有公开结果。
type MusicCoverPreparation struct {
	// PreparationID is the opaque Router execution identifier consumed by music.cover.
	// PreparationID 是供 music.cover 使用的不透明 Router 执行标识。
	PreparationID string `json:"preparation_id"`
	// FormattedLyrics contains provider-extracted editable structured lyrics.
	// FormattedLyrics 包含供应商提取且可编辑的结构化歌词。
	FormattedLyrics string `json:"formatted_lyrics"`
	// Structure contains typed provider-confirmed song sections.
	// Structure 包含类型化且由供应商确认的歌曲段落。
	Structure []MusicStructureSegment `json:"structure"`
	// AudioDurationSeconds is the provider-confirmed reference duration.
	// AudioDurationSeconds 是供应商确认的参考音频时长。
	AudioDurationSeconds float64 `json:"audio_duration_seconds"`
	// ExpiresAt is the last instant at which the preparation may be consumed.
	// ExpiresAt 是此准备结果可被消费的最晚时刻。
	ExpiresAt time.Time `json:"expires_at"`
}

// MusicStructureSegment contains one provider-confirmed cover structure interval.
// MusicStructureSegment 包含一个供应商确认的翻唱结构区间。
type MusicStructureSegment struct {
	// Label is the provider-confirmed closed section label.
	// Label 是供应商确认的封闭段落标签。
	Label string `json:"label"`
	// StartSeconds is the inclusive section offset.
	// StartSeconds 是包含端点的段落偏移。
	StartSeconds float64 `json:"start_seconds"`
	// EndSeconds is the exclusive section offset.
	// EndSeconds 是不包含端点的段落偏移。
	EndSeconds float64 `json:"end_seconds"`
}

// Validate verifies public identity, expiry, duration, and ordered typed structure.
// Validate 校验公开身份、过期时间、时长与有序类型化结构。
func (p MusicCoverPreparation) Validate() error {
	if strings.TrimSpace(p.PreparationID) == "" || strings.TrimSpace(p.FormattedLyrics) == "" || p.AudioDurationSeconds <= 0 || p.ExpiresAt.IsZero() || len(p.Structure) == 0 {
		return fmt.Errorf("%w: music cover preparation is incomplete", ErrInvalidRequest)
	}
	previousEnd := float64(0)
	for index, segment := range p.Structure {
		if errSegment := segment.Validate(); errSegment != nil || index > 0 && segment.StartSeconds < previousEnd || segment.EndSeconds > p.AudioDurationSeconds {
			return fmt.Errorf("%w: music cover structure is invalid", ErrInvalidRequest)
		}
		previousEnd = segment.EndSeconds
	}
	return nil
}

// Validate verifies one known non-negative increasing music section interval.
// Validate 校验一个已知、非负且递增的音乐段落区间。
func (s MusicStructureSegment) Validate() error {
	switch s.Label {
	case "intro", "verse", "chorus", "bridge", "outro", "inst", "silence":
	default:
		return fmt.Errorf("%w: music structure label is invalid", ErrInvalidRequest)
	}
	if s.StartSeconds < 0 || s.EndSeconds <= s.StartSeconds {
		return fmt.Errorf("%w: music structure interval is invalid", ErrInvalidRequest)
	}
	return nil
}
