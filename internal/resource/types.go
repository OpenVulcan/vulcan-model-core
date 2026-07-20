// Package resource owns Router-local binary resources and safe provider asset bindings.
// Package resource 拥有 Router 本地二进制资源及安全供应商资产绑定。
package resource

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

var (
	// ErrInvalidResource reports malformed metadata or an invalid state transition.
	// ErrInvalidResource 表示元数据格式错误或状态迁移无效。
	ErrInvalidResource = errors.New("invalid Router resource")
	// ErrResourceNotFound reports an unknown Router resource identifier.
	// ErrResourceNotFound 表示未知 Router 资源标识。
	ErrResourceNotFound = errors.New("Router resource not found")
	// ErrResourceConflict reports an immutable identifier or revision conflict.
	// ErrResourceConflict 表示不可变标识或修订冲突。
	ErrResourceConflict = errors.New("Router resource conflict")
	// ErrResourceQuotaExceeded reports that a configured byte ceiling would be exceeded.
	// ErrResourceQuotaExceeded 表示将超过已配置字节上限。
	ErrResourceQuotaExceeded = errors.New("Router resource quota exceeded")
	// ErrResourceAccessDenied reports owner-key scope mismatch without revealing another resource.
	// ErrResourceAccessDenied 表示所有者密钥作用域不匹配且不泄露其他资源。
	ErrResourceAccessDenied = errors.New("Router resource access denied")
)

// State identifies one durable resource lifecycle state.
// State 标识一种持久资源生命周期状态。
type State string

const (
	// StateReceiving reserves metadata while bytes are being verified.
	// StateReceiving 在字节校验期间保留元数据。
	StateReceiving State = "receiving"
	// StateReady permits authorized execution and download.
	// StateReady 允许已授权执行与下载。
	StateReady State = "ready"
	// StateFailed records a safe terminal ingestion failure.
	// StateFailed 记录安全终态接收失败。
	StateFailed State = "failed"
	// StateDeleting blocks new use while bindings and objects are removed.
	// StateDeleting 在清理绑定与对象期间阻止新使用。
	StateDeleting State = "deleting"
	// StateDeleted is a retained tombstone.
	// StateDeleted 是保留的墓碑记录。
	StateDeleted State = "deleted"
	// StateExpired marks a resource whose retention deadline elapsed.
	// StateExpired 标记保留期限已过的资源。
	StateExpired State = "expired"
)

// Source identifies how Router obtained the bytes.
// Source 标识 Router 如何获得字节。
type Source string

const (
	// SourceMultipart identifies a call-plane multipart upload.
	// SourceMultipart 标识调用面 Multipart 上传。
	SourceMultipart Source = "multipart"
	// SourceURLImport identifies a Router-fetched public URL.
	// SourceURLImport 标识 Router 获取的公网 URL。
	SourceURLImport Source = "url_import"
	// SourceBase64Import identifies a bounded Base64 import.
	// SourceBase64Import 标识受限 Base64 导入。
	SourceBase64Import Source = "base64_import"
	// SourceGenerated identifies a provider-generated result copied into Router storage.
	// SourceGenerated 标识复制到 Router 存储的供应商生成结果。
	SourceGenerated Source = "generated"
)

// RetentionPolicy identifies who controls resource expiry.
// RetentionPolicy 标识谁控制资源过期。
type RetentionPolicy string

const (
	// RetentionEphemeral uses the Router default short lifetime.
	// RetentionEphemeral 使用 Router 默认短生命周期。
	RetentionEphemeral RetentionPolicy = "ephemeral"
	// RetentionExplicitExpiry uses a caller-authorized explicit deadline.
	// RetentionExplicitExpiry 使用调用方授权的明确期限。
	RetentionExplicitExpiry RetentionPolicy = "explicit_expiry"
	// RetentionPersistent remains until explicit deletion.
	// RetentionPersistent 保留到显式删除。
	RetentionPersistent RetentionPolicy = "persistent"
)

// OptionalInt64 represents an authoritative non-negative measurement or an unknown value.
// OptionalInt64 表示一个权威非负测量值或未知值。
type OptionalInt64 struct {
	// Known reports whether Value was parsed authoritatively.
	// Known 表示 Value 是否经过权威解析。
	Known bool `json:"known"`
	// Value contains the non-negative measurement when Known is true.
	// Value 在 Known 为真时包含非负测量值。
	Value int64 `json:"value,omitempty"`
}

// OptionalFloat64 represents an authoritative non-negative measurement or an unknown value.
// OptionalFloat64 表示一个权威非负浮点测量值或未知值。
type OptionalFloat64 struct {
	// Known reports whether Value was parsed authoritatively.
	// Known 表示 Value 是否经过权威解析。
	Known bool `json:"known"`
	// Value contains the non-negative measurement when Known is true.
	// Value 在 Known 为真时包含非负测量值。
	Value float64 `json:"value,omitempty"`
}

// ImageMetadata contains parsed image dimensions.
// ImageMetadata 包含已解析图片尺寸。
type ImageMetadata struct {
	// Width is the decoded pixel width.
	// Width 是解码后的像素宽度。
	Width int `json:"width"`
	// Height is the decoded pixel height.
	// Height 是解码后的像素高度。
	Height int `json:"height"`
	// Animated reports whether multiple frames were observed.
	// Animated 表示是否观察到多帧。
	Animated bool `json:"animated"`
	// HasAlpha reports whether the decoded image format contains an alpha channel or transparent palette entry.
	// HasAlpha 表示解码后的图片格式是否包含 Alpha 通道或透明调色板项。
	HasAlpha bool `json:"has_alpha"`
}

// AudioMetadata contains parsed audio measurements without guessed values.
// AudioMetadata 包含已解析音频测量值且不包含猜测值。
type AudioMetadata struct {
	// DurationMilliseconds is authoritative when parsed from the container.
	// DurationMilliseconds 在从容器解析后具有权威性。
	DurationMilliseconds OptionalInt64 `json:"duration_milliseconds"`
	// SampleRateHz is authoritative when parsed from the stream.
	// SampleRateHz 在从流中解析后具有权威性。
	SampleRateHz OptionalInt64 `json:"sample_rate_hz"`
	// Channels is authoritative when parsed from the stream.
	// Channels 在从流中解析后具有权威性。
	Channels OptionalInt64 `json:"channels"`
	// Encoding is the parsed codec or encoding identifier.
	// Encoding 是已解析编解码或编码标识。
	Encoding string `json:"encoding,omitempty"`
}

// VideoMetadata contains parsed video measurements without guessed values.
// VideoMetadata 包含已解析视频测量值且不包含猜测值。
type VideoMetadata struct {
	// DurationMilliseconds is authoritative when parsed from the container.
	// DurationMilliseconds 在从容器解析后具有权威性。
	DurationMilliseconds OptionalInt64 `json:"duration_milliseconds"`
	// Width is authoritative when parsed from a video track.
	// Width 在从视频轨道解析后具有权威性。
	Width OptionalInt64 `json:"width"`
	// Height is authoritative when parsed from a video track.
	// Height 在从视频轨道解析后具有权威性。
	Height OptionalInt64 `json:"height"`
	// FrameCount is authoritative only when the container provides it.
	// FrameCount 仅在容器提供时具有权威性。
	FrameCount OptionalInt64 `json:"frame_count"`
	// FramesPerSecond is authoritative only when parsed.
	// FramesPerSecond 仅在解析后具有权威性。
	FramesPerSecond OptionalFloat64 `json:"frames_per_second"`
	// Codec is the parsed video codec.
	// Codec 是已解析视频编码。
	Codec string `json:"codec,omitempty"`
	// Container is the parsed container identifier.
	// Container 是已解析封装标识。
	Container string `json:"container,omitempty"`
	// HasAudio is authoritative only when an audio track was parsed.
	// HasAudio 仅在解析到音轨时具有权威性。
	HasAudio *bool `json:"has_audio,omitempty"`
}

// Metadata contains exactly the variant matching Resource.Kind when applicable.
// Metadata 在适用时只包含与 Resource.Kind 匹配的变体。
type Metadata struct {
	// Image contains image-only facts.
	// Image 包含图片专用事实。
	Image *ImageMetadata `json:"image,omitempty"`
	// Audio contains audio-only facts.
	// Audio 包含音频专用事实。
	Audio *AudioMetadata `json:"audio,omitempty"`
	// Video contains video-only facts.
	// Video 包含视频专用事实。
	Video *VideoMetadata `json:"video,omitempty"`
}

// GenerationProvenance records the safe immutable execution origin of a generated resource.
// GenerationProvenance 记录生成资源安全且不可变的执行来源。
type GenerationProvenance struct {
	// ExecutionID identifies the Router execution that produced the bytes.
	// ExecutionID 标识产出这些字节的 Router 执行。
	ExecutionID string `json:"execution_id"`
	// ProviderDefinitionID identifies the code-owned provider boundary.
	// ProviderDefinitionID 标识代码拥有的供应商边界。
	ProviderDefinitionID string `json:"provider_definition_id"`
	// ProviderModelID identifies the Router catalog model.
	// ProviderModelID 标识 Router 目录模型。
	ProviderModelID string `json:"provider_model_id"`
	// UpstreamModelID identifies the exact provider model handle.
	// UpstreamModelID 标识精确的供应商模型句柄。
	UpstreamModelID string `json:"upstream_model_id"`
	// ActionBindingID identifies the code-owned generating action.
	// ActionBindingID 标识代码拥有的生成动作。
	ActionBindingID string `json:"action_binding_id"`
	// Operation identifies the canonical generation operation.
	// Operation 标识规范生成操作。
	Operation vcp.OperationKind `json:"operation"`
}

// Validate verifies complete safe generation ownership.
// Validate 校验完整且安全的生成归属。
func (p GenerationProvenance) Validate() error {
	if strings.TrimSpace(p.ExecutionID) == "" || strings.TrimSpace(p.ProviderDefinitionID) == "" || strings.TrimSpace(p.ProviderModelID) == "" || strings.TrimSpace(p.UpstreamModelID) == "" || strings.TrimSpace(p.ActionBindingID) == "" || !generatedOperation(p.Operation) {
		return fmt.Errorf("%w: generated resource provenance is incomplete", ErrInvalidResource)
	}
	return nil
}

// Resource is one immutable Router-owned binary identity and mutable lifecycle record.
// Resource 是一个不可变 Router 所有二进制身份及可变生命周期记录。
type Resource struct {
	// ID is the opaque Router resource identifier.
	// ID 是不透明 Router 资源标识。
	ID string `json:"id"`
	// OwnerAPIKeyID is a non-secret call-key identifier used for authorization and audit.
	// OwnerAPIKeyID 是用于授权与审计的非秘密调用密钥标识。
	OwnerAPIKeyID string `json:"-"`
	// Kind identifies image, audio, video, or file.
	// Kind 标识图片、音频、视频或文件。
	Kind vcp.MediaKind `json:"kind"`
	// MIMEType is authoritative after magic inspection.
	// MIMEType 在魔数检查后具有权威性。
	MIMEType string `json:"mime_type"`
	// SizeBytes is the exact object size.
	// SizeBytes 是精确对象大小。
	SizeBytes int64 `json:"size_bytes"`
	// SHA256 is the lowercase hexadecimal content digest.
	// SHA256 是小写十六进制内容摘要。
	SHA256 string `json:"sha256"`
	// Metadata contains parsed media facts.
	// Metadata 包含已解析媒体事实。
	Metadata Metadata `json:"metadata"`
	// Source records how Router obtained the bytes.
	// Source 记录 Router 如何获得字节。
	Source Source `json:"source"`
	// SourceURL records the final public URL only for URL imports.
	// SourceURL 仅为 URL 导入记录最终公网 URL。
	SourceURL string `json:"-"`
	// GeneratedBy records safe provider and execution provenance only for generated resources.
	// GeneratedBy 仅为生成资源记录安全的供应商与执行来源。
	GeneratedBy *GenerationProvenance `json:"generated_by,omitempty"`
	// State controls execution and content access.
	// State 控制执行与内容访问。
	State State `json:"state"`
	// Retention controls expiration semantics.
	// Retention 控制过期语义。
	Retention RetentionPolicy `json:"retention"`
	// ObjectKey is an internal relative object path and is never serialized publicly.
	// ObjectKey 是内部相对对象路径且绝不公开序列化。
	ObjectKey string `json:"-"`
	// ErrorCode is a stable non-secret ingestion failure code.
	// ErrorCode 是稳定非秘密接收失败码。
	ErrorCode string `json:"error_code,omitempty"`
	// CreatedAt is the initial reservation time.
	// CreatedAt 是初始保留时间。
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is the latest state transition time.
	// UpdatedAt 是最近状态迁移时间。
	UpdatedAt time.Time `json:"updated_at"`
	// ExpiresAt is required unless retention is persistent.
	// ExpiresAt 除持久保留外均为必填。
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// Revision is the optimistic concurrency revision.
	// Revision 是乐观并发修订号。
	Revision uint64 `json:"revision"`
}

// Validate verifies immutable facts, lifecycle shape, and exact metadata union.
// Validate 校验不可变事实、生命周期形态和精确元数据联合体。
func (r Resource) Validate() error {
	if !validResourceID(r.ID) || strings.TrimSpace(r.OwnerAPIKeyID) == "" || !validKind(r.Kind) || !validSource(r.Source) || !validState(r.State) || !validRetention(r.Retention) || r.CreatedAt.IsZero() || r.UpdatedAt.IsZero() || r.UpdatedAt.Before(r.CreatedAt) || r.Revision == 0 {
		return fmt.Errorf("%w: identity, owner, enums, timestamps, and revision are required", ErrInvalidResource)
	}
	if r.Retention == RetentionPersistent {
		if r.ExpiresAt != nil {
			return fmt.Errorf("%w: persistent resource cannot expire", ErrInvalidResource)
		}
	} else if r.ExpiresAt == nil || !r.ExpiresAt.After(r.CreatedAt) {
		return fmt.Errorf("%w: non-persistent resource requires a future expiry", ErrInvalidResource)
	}
	readyFacts := strings.TrimSpace(r.MIMEType) != "" && r.SizeBytes > 0 && len(r.SHA256) == 64 && strings.TrimSpace(r.ObjectKey) != ""
	if r.State == StateReady && !readyFacts {
		return fmt.Errorf("%w: ready resource requires MIME, size, hash, and object key", ErrInvalidResource)
	}
	if r.State == StateReceiving && (r.SizeBytes != 0 || r.SHA256 != "" || r.ObjectKey != "" || r.ErrorCode != "") {
		return fmt.Errorf("%w: receiving resource cannot carry completed facts", ErrInvalidResource)
	}
	if r.State == StateFailed && strings.TrimSpace(r.ErrorCode) == "" {
		return fmt.Errorf("%w: failed resource requires a safe error code", ErrInvalidResource)
	}
	if r.Source == SourceGenerated {
		if r.GeneratedBy == nil {
			return fmt.Errorf("%w: generated resource requires provenance", ErrInvalidResource)
		}
		if errProvenance := r.GeneratedBy.Validate(); errProvenance != nil {
			return errProvenance
		}
	} else if r.GeneratedBy != nil {
		return fmt.Errorf("%w: imported resource cannot carry generation provenance", ErrInvalidResource)
	}
	return validateMetadata(r.Kind, r.Metadata, r.State == StateReady)
}

// generatedOperation reports whether one operation can produce Router-owned bytes.
// generatedOperation 报告一个操作是否能够产出 Router 所有字节。
func generatedOperation(operation vcp.OperationKind) bool {
	switch operation {
	case vcp.OperationImageGenerate, vcp.OperationImageEdit, vcp.OperationVideoGenerate, vcp.OperationVideoEdit, vcp.OperationVideoExtend, vcp.OperationSpeechSynthesize, vcp.OperationMusicGenerate, vcp.OperationMusicCover:
		return true
	default:
		return false
	}
}

// validResourceID verifies the exact cryptographically generated identifier shape.
// validResourceID 校验精确加密生成标识形态。
func validResourceID(identifier string) bool {
	if len(identifier) != 36 || !strings.HasPrefix(identifier, "res_") {
		return false
	}
	decoded, errDecode := hex.DecodeString(identifier[4:])
	return errDecode == nil && len(decoded) == 16
}

// validateMetadata verifies exactly the media-specific variant required by kind.
// validateMetadata 校验媒体类型要求的精确专用变体。
func validateMetadata(kind vcp.MediaKind, metadata Metadata, ready bool) error {
	count := 0
	if metadata.Image != nil {
		count++
	}
	if metadata.Audio != nil {
		count++
	}
	if metadata.Video != nil {
		count++
	}
	if !ready {
		if count != 0 {
			return fmt.Errorf("%w: incomplete resource cannot carry parsed metadata", ErrInvalidResource)
		}
		return nil
	}
	if kind == vcp.MediaFile {
		if count != 0 {
			return fmt.Errorf("%w: file resource cannot carry media metadata", ErrInvalidResource)
		}
		return nil
	}
	if count != 1 || (kind == vcp.MediaImage && metadata.Image == nil) || (kind == vcp.MediaAudio && metadata.Audio == nil) || (kind == vcp.MediaVideo && metadata.Video == nil) {
		return fmt.Errorf("%w: ready media resource requires exactly its matching metadata", ErrInvalidResource)
	}
	if metadata.Image != nil && (metadata.Image.Width <= 0 || metadata.Image.Height <= 0) {
		return fmt.Errorf("%w: image dimensions must be positive", ErrInvalidResource)
	}
	return nil
}

// validKind reports whether one resource kind is registered.
// validKind 报告一种资源类型是否已注册。
func validKind(kind vcp.MediaKind) bool {
	return kind == vcp.MediaImage || kind == vcp.MediaAudio || kind == vcp.MediaVideo || kind == vcp.MediaFile
}

// validSource reports whether one ingestion source is registered.
// validSource 报告一种接收来源是否已注册。
func validSource(source Source) bool {
	return source == SourceMultipart || source == SourceURLImport || source == SourceBase64Import || source == SourceGenerated
}

// validState reports whether one lifecycle state is registered.
// validState 报告一种生命周期状态是否已注册。
func validState(state State) bool {
	return state == StateReceiving || state == StateReady || state == StateFailed || state == StateDeleting || state == StateDeleted || state == StateExpired
}

// validRetention reports whether one retention policy is registered.
// validRetention 报告一种保留策略是否已注册。
func validRetention(retention RetentionPolicy) bool {
	return retention == RetentionEphemeral || retention == RetentionExplicitExpiry || retention == RetentionPersistent
}
