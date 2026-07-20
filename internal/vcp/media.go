package vcp

import (
	"fmt"
	"math"
	"strings"
)

// MediaKind identifies one binary media family.
// MediaKind 标识一种二进制媒体类别。
type MediaKind string

const (
	// MediaImage identifies image resources.
	// MediaImage 标识图片资源。
	MediaImage MediaKind = "image"
	// MediaAudio identifies audio resources.
	// MediaAudio 标识音频资源。
	MediaAudio MediaKind = "audio"
	// MediaVideo identifies video resources.
	// MediaVideo 标识视频资源。
	MediaVideo MediaKind = "video"
	// MediaFile identifies non-media file resources.
	// MediaFile 标识非媒体文件资源。
	MediaFile MediaKind = "file"
)

// MediaInputRole identifies the semantic role of one resource.
// MediaInputRole 标识一个资源的语义角色。
type MediaInputRole string

const (
	// MediaRoleUnderstanding requests semantic understanding.
	// MediaRoleUnderstanding 请求语义理解。
	MediaRoleUnderstanding MediaInputRole = "understanding"
	// MediaRoleReference supplies a generation reference.
	// MediaRoleReference 提供生成参考。
	MediaRoleReference MediaInputRole = "reference"
	// MediaRoleEditSource supplies an editable source.
	// MediaRoleEditSource 提供可编辑来源。
	MediaRoleEditSource MediaInputRole = "edit_source"
	// MediaRoleMask supplies an image mask.
	// MediaRoleMask 提供图片遮罩。
	MediaRoleMask MediaInputRole = "mask"
	// MediaRoleFirstFrame supplies the first video frame.
	// MediaRoleFirstFrame 提供视频首帧。
	MediaRoleFirstFrame MediaInputRole = "first_frame"
	// MediaRoleLastFrame supplies the last video frame.
	// MediaRoleLastFrame 提供视频尾帧。
	MediaRoleLastFrame MediaInputRole = "last_frame"
	// MediaRoleAudioTrack supplies a video audio track.
	// MediaRoleAudioTrack 提供视频音轨。
	MediaRoleAudioTrack MediaInputRole = "audio_track"
	// MediaRoleTranscriptionSource supplies audio or an audio-bearing video for speech recognition.
	// MediaRoleTranscriptionSource 为语音识别提供音频或含音轨视频。
	MediaRoleTranscriptionSource MediaInputRole = "transcription_source"
	// MediaRoleStyleReference supplies a style reference.
	// MediaRoleStyleReference 提供风格参考。
	MediaRoleStyleReference MediaInputRole = "style_reference"
	// MediaRoleCoverReference supplies a music-cover reference.
	// MediaRoleCoverReference 提供翻唱参考。
	MediaRoleCoverReference MediaInputRole = "cover_reference"
)

// ResourceReference identifies one Router-owned immutable resource.
// ResourceReference 标识一个 Router 拥有的不可变资源。
type ResourceReference struct {
	// ResourceID is the Router-owned resource identifier.
	// ResourceID 是 Router 拥有的资源标识。
	ResourceID string `json:"resource_id"`
	// Revision optionally freezes a specific immutable resource revision.
	// Revision 可选地冻结一个特定不可变资源修订。
	Revision string `json:"revision,omitempty"`
}

// MediaInput binds one Router resource to a media kind and semantic role.
// MediaInput 将一个 Router 资源绑定到媒体类型和语义角色。
type MediaInput struct {
	// ID is stable within the request.
	// ID 在请求内保持稳定。
	ID string `json:"id"`
	// Kind identifies image, audio, video, or file content.
	// Kind 标识图片、音频、视频或文件内容。
	Kind MediaKind `json:"kind"`
	// Role identifies how the operation consumes the resource.
	// Role 标识操作如何消费资源。
	Role MediaInputRole `json:"role"`
	// Resource references the Router-owned content.
	// Resource 引用 Router 拥有的内容。
	Resource ResourceReference `json:"resource"`
}

// MediaAnalyzeTask identifies the requested analysis semantics.
// MediaAnalyzeTask 标识请求的分析语义。
type MediaAnalyzeTask string

const (
	// MediaAnalyzeDescribe requests a description.
	// MediaAnalyzeDescribe 请求描述。
	MediaAnalyzeDescribe MediaAnalyzeTask = "describe"
	// MediaAnalyzeSummarize requests a summary.
	// MediaAnalyzeSummarize 请求摘要。
	MediaAnalyzeSummarize MediaAnalyzeTask = "summarize"
	// MediaAnalyzeQuestionAnswer requests an answer to an explicit question.
	// MediaAnalyzeQuestionAnswer 请求回答一个明确问题。
	MediaAnalyzeQuestionAnswer MediaAnalyzeTask = "question_answer"
	// MediaAnalyzeExtract requests structured extraction.
	// MediaAnalyzeExtract 请求结构化提取。
	MediaAnalyzeExtract MediaAnalyzeTask = "extract"
	// MediaAnalyzeModerate requests content moderation analysis.
	// MediaAnalyzeModerate 请求内容审核分析。
	MediaAnalyzeModerate MediaAnalyzeTask = "moderate"
)

// MediaAnalyzeOperation analyzes one or more ordered media resources.
// MediaAnalyzeOperation 分析一个或多个有序媒体资源。
type MediaAnalyzeOperation struct {
	// Task identifies the requested analysis.
	// Task 标识请求的分析任务。
	Task MediaAnalyzeTask `json:"task"`
	// Instruction contains an explicit question or extraction instruction.
	// Instruction 包含明确问题或提取指令。
	Instruction string `json:"instruction,omitempty"`
	// Inputs contains ordered media resources.
	// Inputs 包含有序媒体资源。
	Inputs []MediaInput `json:"inputs"`
}

// ImageGenerateOperation contains provider-independent image generation input.
// ImageGenerateOperation 包含供应商无关的图片生成输入。
type ImageGenerateOperation struct {
	// Prompt describes the desired image.
	// Prompt 描述期望图片。
	Prompt string `json:"prompt"`
	// NegativePrompt describes excluded visual properties.
	// NegativePrompt 描述需要排除的视觉属性。
	NegativePrompt string `json:"negative_prompt,omitempty"`
	// References contains ordered reference resources.
	// References 包含有序参考资源。
	References []MediaInput `json:"references,omitempty"`
	// Count requests a positive output count.
	// Count 请求正数输出数量。
	Count int `json:"count,omitempty"`
	// Width requests an exact output width when supported.
	// Width 在支持时请求精确输出宽度。
	Width int `json:"width,omitempty"`
	// Height requests an exact output height when supported.
	// Height 在支持时请求精确输出高度。
	Height int `json:"height,omitempty"`
	// AspectRatio requests a registered aspect ratio.
	// AspectRatio 请求一个已注册长宽比。
	AspectRatio string `json:"aspect_ratio,omitempty"`
	// Resolution requests a registered provider-independent resolution tier.
	// Resolution 请求一个已注册的供应商无关分辨率档位。
	Resolution string `json:"resolution,omitempty"`
	// Quality requests a registered image quality tier.
	// Quality 请求一个已注册图片质量档位。
	Quality string `json:"quality,omitempty"`
	// Background requests a registered background treatment.
	// Background 请求一个已注册背景处理方式。
	Background string `json:"background,omitempty"`
	// OutputFormat requests a registered image format.
	// OutputFormat 请求一个已注册图片格式。
	OutputFormat string `json:"output_format,omitempty"`
	// SafetyPolicy selects one registered provider-independent safety policy.
	// SafetyPolicy 选择一个已注册的供应商无关安全策略。
	SafetyPolicy string `json:"safety_policy,omitempty"`
	// Seed requests a deterministic provider seed when supported.
	// Seed 在支持时请求确定性供应商种子。
	Seed *int64 `json:"seed,omitempty"`
}

// ImageEditOperation edits one or more source images.
// ImageEditOperation 编辑一个或多个来源图片。
type ImageEditOperation struct {
	// Instruction describes the requested edit.
	// Instruction 描述请求的编辑。
	Instruction string `json:"instruction"`
	// Sources contains ordered edit sources and an optional mask.
	// Sources 包含有序编辑来源和可选遮罩。
	Sources []MediaInput `json:"sources"`
	// Count requests a positive output count.
	// Count 请求正数输出数量。
	Count int `json:"count,omitempty"`
	// Width requests an exact output width when supported.
	// Width 在支持时请求精确输出宽度。
	Width int `json:"width,omitempty"`
	// Height requests an exact output height when supported.
	// Height 在支持时请求精确输出高度。
	Height int `json:"height,omitempty"`
	// AspectRatio requests a registered output aspect ratio.
	// AspectRatio 请求一个已注册输出长宽比。
	AspectRatio string `json:"aspect_ratio,omitempty"`
	// Resolution requests a registered output resolution tier.
	// Resolution 请求一个已注册输出分辨率档位。
	Resolution string `json:"resolution,omitempty"`
	// Quality requests a registered image quality tier.
	// Quality 请求一个已注册图片质量档位。
	Quality string `json:"quality,omitempty"`
	// OutputFormat requests a registered image format.
	// OutputFormat 请求一个已注册图片格式。
	OutputFormat string `json:"output_format,omitempty"`
}

// VideoGenerateOperation contains provider-independent video generation input.
// VideoGenerateOperation 包含供应商无关的视频生成输入。
type VideoGenerateOperation struct {
	// Prompt describes the desired video.
	// Prompt 描述期望视频。
	Prompt string `json:"prompt"`
	// NegativePrompt describes visual or acoustic content that should be excluded.
	// NegativePrompt 描述应排除的视觉或声音内容。
	NegativePrompt string `json:"negative_prompt,omitempty"`
	// Inputs contains ordered reference, frame, or audio resources.
	// Inputs 包含有序参考、帧或音轨资源。
	Inputs []MediaInput `json:"inputs,omitempty"`
	// DurationSeconds requests a supported duration.
	// DurationSeconds 请求一个受支持时长。
	DurationSeconds float64 `json:"duration_seconds,omitempty"`
	// Width requests an exact output width when supported.
	// Width 在支持时请求精确输出宽度。
	Width int `json:"width,omitempty"`
	// Height requests an exact output height when supported.
	// Height 在支持时请求精确输出高度。
	Height int `json:"height,omitempty"`
	// Resolution requests one provider-declared resolution tier.
	// Resolution 请求供应商声明的分辨率档位。
	Resolution string `json:"resolution,omitempty"`
	// AspectRatio requests one provider-declared display ratio.
	// AspectRatio 请求供应商声明的显示长宽比。
	AspectRatio string `json:"aspect_ratio,omitempty"`
	// FramesPerSecond requests a supported frame rate.
	// FramesPerSecond 请求一个受支持帧率。
	FramesPerSecond float64 `json:"frames_per_second,omitempty"`
	// OutputFormat requests a registered video format.
	// OutputFormat 请求一个已注册视频格式。
	OutputFormat string `json:"output_format,omitempty"`
	// Seed requests a deterministic provider seed when supported.
	// Seed 在支持时请求确定性供应商种子。
	Seed *int64 `json:"seed,omitempty"`
	// Count requests a supported number of independent outputs.
	// Count 请求受支持数量的独立输出。
	Count int `json:"count,omitempty"`
	// Watermark requests an explicit provider-supported watermark preference.
	// Watermark 请求明确且供应商支持的水印偏好。
	Watermark *bool `json:"watermark,omitempty"`
	// PromptExtend requests provider-native prompt rewriting when the model exposes it.
	// PromptExtend 在模型公开该能力时请求供应商原生提示词改写。
	PromptExtend *bool `json:"prompt_extend,omitempty"`
}

// VideoEditOperation edits one existing video.
// VideoEditOperation 编辑一个现有视频。
type VideoEditOperation struct {
	// Instruction describes the requested edit.
	// Instruction 描述请求的编辑。
	Instruction string `json:"instruction"`
	// Source is the single video edit source.
	// Source 是唯一视频编辑来源。
	Source MediaInput `json:"source"`
	// References contains optional ordered references.
	// References 包含可选有序参考资源。
	References []MediaInput `json:"references,omitempty"`
}

// VideoExtendOperation extends one existing video.
// VideoExtendOperation 延长一个现有视频。
type VideoExtendOperation struct {
	// Source is the single video extension source.
	// Source 是唯一视频延长来源。
	Source MediaInput `json:"source"`
	// Prompt describes the desired continuation.
	// Prompt 描述期望续接内容。
	Prompt string `json:"prompt,omitempty"`
	// AdditionalDurationSeconds requests a supported extension duration.
	// AdditionalDurationSeconds 请求一个受支持延长时长。
	AdditionalDurationSeconds float64 `json:"additional_duration_seconds"`
}

// SpeechSynthesizeOperation contains non-realtime text-to-speech input.
// SpeechSynthesizeOperation 包含非实时文本转语音输入。
type SpeechSynthesizeOperation struct {
	// Text is the exact text to synthesize.
	// Text 是需要合成的精确文本。
	Text string `json:"text"`
	// Segments contains ordered multi-speaker text when the selected profile supports it.
	// Segments 在选定 Profile 支持时包含有序多说话人文本。
	Segments []SpeechSynthesisSegment `json:"segments,omitempty"`
	// VoiceID selects a provider-supported preset voice.
	// VoiceID 选择供应商支持的预设声音。
	VoiceID string `json:"voice_id"`
	// Language optionally declares the requested language.
	// Language 可选地声明请求语言。
	Language string `json:"language,omitempty"`
	// Style requests one provider-declared speaking style.
	// Style 请求供应商声明的说话风格。
	Style string `json:"style,omitempty"`
	// Speed optionally requests a supported speech rate.
	// Speed 可选地请求受支持语速。
	Speed *float64 `json:"speed,omitempty"`
	// Pitch optionally requests a provider-supported pitch multiplier or level.
	// Pitch 可选地请求供应商支持的音调倍数或级别。
	Pitch *float64 `json:"pitch,omitempty"`
	// Volume optionally requests a provider-supported volume multiplier or level.
	// Volume 可选地请求供应商支持的音量倍数或级别。
	Volume *float64 `json:"volume,omitempty"`
	// OutputFormat requests a registered audio format.
	// OutputFormat 请求一个已注册音频格式。
	OutputFormat string `json:"output_format,omitempty"`
	// SampleRate requests a supported sample rate.
	// SampleRate 请求一个受支持采样率。
	SampleRate int `json:"sample_rate,omitempty"`
	// Bitrate requests a supported encoded bitrate in bits per second.
	// Bitrate 请求受支持的编码码率，单位为比特每秒。
	Bitrate int `json:"bitrate,omitempty"`
	// Channels requests a supported channel count.
	// Channels 请求受支持的声道数量。
	Channels int `json:"channels,omitempty"`
	// Timestamps requests provider-confirmed timing metadata when available.
	// Timestamps 请求供应商确认且可用的时间元数据。
	Timestamps bool `json:"timestamps,omitempty"`
}

// SpeechSynthesisSegment binds one text span to one preset voice.
// SpeechSynthesisSegment 将一段文本绑定到一个预设声音。
type SpeechSynthesisSegment struct {
	// Text is the exact segment text.
	// Text 是精确的片段文本。
	Text string `json:"text"`
	// VoiceID selects the segment's provider-supported preset voice.
	// VoiceID 选择片段的供应商支持预设声音。
	VoiceID string `json:"voice_id"`
}

// SpeechTranscribeOperation contains non-realtime speech-to-text input.
// SpeechTranscribeOperation 包含非实时语音转文本输入。
type SpeechTranscribeOperation struct {
	// Source is an audio resource or a video resource with an audio track.
	// Source 是音频资源或包含音轨的视频资源。
	Source MediaInput `json:"source"`
	// Language optionally fixes the source language.
	// Language 可选地固定源语言。
	Language string `json:"language,omitempty"`
	// TranslationTarget optionally requests transcription translated into one target language.
	// TranslationTarget 可选地请求将转写翻译为一种目标语言。
	TranslationTarget string `json:"translation_target,omitempty"`
	// Prompt supplies provider-supported transcription context.
	// Prompt 提供供应商支持的转写上下文。
	Prompt string `json:"prompt,omitempty"`
	// Hotwords contains ordered provider-supported recognition hints.
	// Hotwords 包含有序的供应商支持识别提示词。
	Hotwords []string `json:"hotwords,omitempty"`
	// Diarization requests speaker separation.
	// Diarization 请求说话人分离。
	Diarization bool `json:"diarization,omitempty"`
	// SegmentTimestamps requests segment-level timestamps.
	// SegmentTimestamps 请求分段级时间戳。
	SegmentTimestamps bool `json:"segment_timestamps,omitempty"`
	// WordTimestamps requests word-level timestamps.
	// WordTimestamps 请求词级时间戳。
	WordTimestamps bool `json:"word_timestamps,omitempty"`
	// CandidateCount requests a supported number of recognition alternatives.
	// CandidateCount 请求受支持数量的识别候选。
	CandidateCount int `json:"candidate_count,omitempty"`
}

// MusicGenerateOperation contains music-generation input.
// MusicGenerateOperation 包含音乐生成输入。
type MusicGenerateOperation struct {
	// Prompt describes the desired music.
	// Prompt 描述期望音乐。
	Prompt string `json:"prompt"`
	// NegativePrompt describes musical properties to avoid when supported.
	// NegativePrompt 描述支持时应避免的音乐属性。
	NegativePrompt string `json:"negative_prompt,omitempty"`
	// Lyrics optionally supplies exact lyrics.
	// Lyrics 可选地提供精确歌词。
	Lyrics string `json:"lyrics,omitempty"`
	// Instrumental requests music without vocals.
	// Instrumental 请求纯音乐。
	Instrumental bool `json:"instrumental,omitempty"`
	// References contains optional style or audio references.
	// References 包含可选风格或音频参考。
	References []MediaInput `json:"references,omitempty"`
	// DurationSeconds requests a supported duration.
	// DurationSeconds 请求一个受支持时长。
	DurationSeconds float64 `json:"duration_seconds,omitempty"`
	// OutputFormat requests a registered audio format.
	// OutputFormat 请求一个已注册音频格式。
	OutputFormat string `json:"output_format,omitempty"`
	// Seed requests deterministic provider sampling when supported.
	// Seed 请求供应商支持时的确定性采样。
	Seed *int64 `json:"seed,omitempty"`
	// Count requests a supported number of outputs.
	// Count 请求受支持数量的输出。
	Count int `json:"count,omitempty"`
}

// MusicCoverPrepareOperation prepares one provider-specific cover workflow.
// MusicCoverPrepareOperation 准备一个供应商特定翻唱流程。
type MusicCoverPrepareOperation struct {
	// Source is the cover source audio.
	// Source 是翻唱来源音频。
	Source MediaInput `json:"source"`
	// Lyrics optionally supplies editable lyrics.
	// Lyrics 可选地提供可编辑歌词。
	Lyrics string `json:"lyrics,omitempty"`
}

// MusicCoverOperation completes one prepared cover workflow.
// MusicCoverOperation 完成一个已准备翻唱流程。
type MusicCoverOperation struct {
	// PreparationID references one Router-owned prepared workflow result.
	// PreparationID 引用一个 Router 拥有的准备流程结果。
	PreparationID string `json:"preparation_id"`
	// Prompt describes the target cover style.
	// Prompt 描述目标翻唱风格。
	Prompt string `json:"prompt"`
	// Lyrics contains the confirmed final lyrics.
	// Lyrics 包含已确认最终歌词。
	Lyrics string `json:"lyrics,omitempty"`
	// OutputFormat requests a registered audio format.
	// OutputFormat 请求一个已注册音频格式。
	OutputFormat string `json:"output_format,omitempty"`
}

// Validate verifies media-analysis task and ordered inputs.
// Validate 校验媒体分析任务和有序输入。
func (o MediaAnalyzeOperation) Validate() error {
	if o.Task != MediaAnalyzeDescribe && o.Task != MediaAnalyzeSummarize && o.Task != MediaAnalyzeQuestionAnswer && o.Task != MediaAnalyzeExtract && o.Task != MediaAnalyzeModerate {
		return fmt.Errorf("%w: invalid media analysis task %q", ErrInvalidRequest, o.Task)
	}
	if o.Task == MediaAnalyzeQuestionAnswer && strings.TrimSpace(o.Instruction) == "" {
		return fmt.Errorf("%w: question_answer requires instruction", ErrInvalidRequest)
	}
	return validateMediaInputs(o.Inputs, true)
}

// Validate verifies image-generation required fields and ranges.
// Validate 校验图片生成必填字段和范围。
func (o ImageGenerateOperation) Validate() error {
	if strings.TrimSpace(o.Prompt) == "" {
		return fmt.Errorf("%w: image prompt is required", ErrInvalidRequest)
	}
	if o.Count < 0 || o.Width < 0 || o.Height < 0 {
		return fmt.Errorf("%w: image count and dimensions cannot be negative", ErrInvalidRequest)
	}
	return validateMediaInputs(o.References, false)
}

// Validate verifies image-edit required fields and source roles.
// Validate 校验图片编辑必填字段和来源角色。
func (o ImageEditOperation) Validate() error {
	if strings.TrimSpace(o.Instruction) == "" {
		return fmt.Errorf("%w: image edit instruction is required", ErrInvalidRequest)
	}
	if o.Count < 0 || o.Width < 0 || o.Height < 0 {
		return fmt.Errorf("%w: image edit count and dimensions cannot be negative", ErrInvalidRequest)
	}
	return validateMediaInputs(o.Sources, true)
}

// Validate verifies video-generation required fields and ranges.
// Validate 校验视频生成必填字段和范围。
func (o VideoGenerateOperation) Validate() error {
	if strings.TrimSpace(o.Prompt) == "" && len(o.Inputs) == 0 {
		return fmt.Errorf("%w: video prompt or media input is required", ErrInvalidRequest)
	}
	if o.DurationSeconds < 0 || o.Width < 0 || o.Height < 0 || o.FramesPerSecond < 0 || o.Count < 0 {
		return fmt.Errorf("%w: video numeric fields cannot be negative", ErrInvalidRequest)
	}
	return validateMediaInputs(o.Inputs, false)
}

// Validate verifies video-edit source identity and instruction.
// Validate 校验视频编辑来源身份和指令。
func (o VideoEditOperation) Validate() error {
	if strings.TrimSpace(o.Instruction) == "" {
		return fmt.Errorf("%w: video edit instruction is required", ErrInvalidRequest)
	}
	if errSource := validateMediaInput(o.Source); errSource != nil {
		return errSource
	}
	return validateMediaInputs(o.References, false)
}

// Validate verifies video-extension source and positive duration.
// Validate 校验视频延长来源和正数时长。
func (o VideoExtendOperation) Validate() error {
	if errSource := validateMediaInput(o.Source); errSource != nil {
		return errSource
	}
	if o.AdditionalDurationSeconds <= 0 {
		return fmt.Errorf("%w: additional_duration_seconds must be positive", ErrInvalidRequest)
	}
	return nil
}

// Validate verifies non-realtime text-to-speech input.
// Validate 校验非实时文本转语音输入。
func (o SpeechSynthesizeOperation) Validate() error {
	usesSingleVoice := strings.TrimSpace(o.Text) != "" && strings.TrimSpace(o.VoiceID) != "" && len(o.Segments) == 0
	usesSegments := strings.TrimSpace(o.Text) == "" && strings.TrimSpace(o.VoiceID) == "" && len(o.Segments) > 0
	if !usesSingleVoice && !usesSegments {
		return fmt.Errorf("%w: speech synthesis requires either text plus voice_id or multi-speaker segments", ErrInvalidRequest)
	}
	for _, segment := range o.Segments {
		if strings.TrimSpace(segment.Text) == "" || strings.TrimSpace(segment.VoiceID) == "" {
			return fmt.Errorf("%w: speech segment text and voice_id are required", ErrInvalidRequest)
		}
	}
	if o.Speed != nil && (math.IsNaN(*o.Speed) || math.IsInf(*o.Speed, 0) || *o.Speed <= 0) {
		return fmt.Errorf("%w: speech speed must be finite and positive", ErrInvalidRequest)
	}
	if o.Pitch != nil && (math.IsNaN(*o.Pitch) || math.IsInf(*o.Pitch, 0)) {
		return fmt.Errorf("%w: speech pitch must be finite", ErrInvalidRequest)
	}
	if o.Volume != nil && (math.IsNaN(*o.Volume) || math.IsInf(*o.Volume, 0)) {
		return fmt.Errorf("%w: speech volume must be finite", ErrInvalidRequest)
	}
	if o.SampleRate < 0 || o.Bitrate < 0 || o.Channels < 0 {
		return fmt.Errorf("%w: speech encoding fields cannot be negative", ErrInvalidRequest)
	}
	return nil
}

// Validate verifies non-realtime speech-to-text input.
// Validate 校验非实时语音转文本输入。
func (o SpeechTranscribeOperation) Validate() error {
	if o.CandidateCount < 0 || (o.Source.Kind != MediaAudio && o.Source.Kind != MediaVideo) || o.Source.Role != MediaRoleTranscriptionSource {
		return fmt.Errorf("%w: transcription requires an audio or video transcription_source and a non-negative candidate_count", ErrInvalidRequest)
	}
	for _, hotword := range o.Hotwords {
		if strings.TrimSpace(hotword) == "" {
			return fmt.Errorf("%w: transcription hotwords cannot be empty", ErrInvalidRequest)
		}
	}
	return validateMediaInput(o.Source)
}

// Validate verifies music-generation input and mutually exclusive lyrics intent.
// Validate 校验音乐生成输入和互斥歌词意图。
func (o MusicGenerateOperation) Validate() error {
	if strings.TrimSpace(o.Prompt) == "" && strings.TrimSpace(o.Lyrics) == "" {
		return fmt.Errorf("%w: music prompt or lyrics are required", ErrInvalidRequest)
	}
	if o.Instrumental && strings.TrimSpace(o.Lyrics) != "" {
		return fmt.Errorf("%w: instrumental music cannot include lyrics", ErrInvalidRequest)
	}
	if o.DurationSeconds < 0 || o.Count < 0 {
		return fmt.Errorf("%w: music duration and count cannot be negative", ErrInvalidRequest)
	}
	return validateMediaInputs(o.References, false)
}

// Validate verifies music-cover preparation source identity.
// Validate 校验翻唱准备来源身份。
func (o MusicCoverPrepareOperation) Validate() error {
	return validateMediaInput(o.Source)
}

// Validate verifies final music-cover preparation identity.
// Validate 校验最终翻唱准备身份。
func (o MusicCoverOperation) Validate() error {
	if strings.TrimSpace(o.PreparationID) == "" || strings.TrimSpace(o.Prompt) == "" {
		return fmt.Errorf("%w: preparation_id and prompt are required", ErrInvalidRequest)
	}
	return nil
}

// validateMediaInputs verifies ordered uniqueness and optionally requires one item.
// validateMediaInputs 校验有序唯一性并可选要求至少一项。
func validateMediaInputs(inputs []MediaInput, required bool) error {
	if required && len(inputs) == 0 {
		return fmt.Errorf("%w: at least one media input is required", ErrInvalidRequest)
	}
	seen := make(map[string]struct{}, len(inputs))
	for index := range inputs {
		if errInput := validateMediaInput(inputs[index]); errInput != nil {
			return fmt.Errorf("%w: media input %d: %v", ErrInvalidRequest, index, errInput)
		}
		if _, exists := seen[inputs[index].ID]; exists {
			return fmt.Errorf("%w: duplicate media input id %q", ErrInvalidRequest, inputs[index].ID)
		}
		seen[inputs[index].ID] = struct{}{}
	}
	return nil
}

// validateMediaInput verifies one closed media reference.
// validateMediaInput 校验一个封闭媒体引用。
func validateMediaInput(input MediaInput) error {
	if strings.TrimSpace(input.ID) == "" || strings.TrimSpace(input.Resource.ResourceID) == "" {
		return fmt.Errorf("%w: media input id and resource_id are required", ErrInvalidRequest)
	}
	if input.Kind != MediaImage && input.Kind != MediaAudio && input.Kind != MediaVideo && input.Kind != MediaFile {
		return fmt.Errorf("%w: invalid media kind %q", ErrInvalidRequest, input.Kind)
	}
	switch input.Role {
	case MediaRoleUnderstanding, MediaRoleReference, MediaRoleEditSource, MediaRoleMask, MediaRoleFirstFrame, MediaRoleLastFrame, MediaRoleAudioTrack, MediaRoleTranscriptionSource, MediaRoleStyleReference, MediaRoleCoverReference:
		return nil
	default:
		return fmt.Errorf("%w: invalid media role %q", ErrInvalidRequest, input.Role)
	}
}
