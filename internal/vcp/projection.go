package vcp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	// FrameVersion is the canonical Vulcan Frame wire version.
	// FrameVersion 是规范 Vulcan Frame 线协议版本。
	FrameVersion = "1"
	// FramePurpose is the only registered Frame purpose in VCP 1.0.
	// FramePurpose 是 VCP 1.0 唯一注册的 Frame 用途。
	FramePurpose = "context-carrier"
)

var (
	// ErrInvalidFrame reports malformed or untrusted Frame data.
	// ErrInvalidFrame 表示 Frame 数据格式错误或不可信。
	ErrInvalidFrame = errors.New("invalid Vulcan Frame")
	// ErrProjectionMismatch reports a Frame that does not match its ledger entry.
	// ErrProjectionMismatch 表示 Frame 与账本条目不匹配。
	ErrProjectionMismatch = errors.New("projection ledger mismatch")
)

// ProjectionPlan contains frozen upstream projection decisions.
// ProjectionPlan 包含冻结后的上游投影决策。
type ProjectionPlan struct {
	// ProjectionID identifies one immutable upstream attempt projection.
	// ProjectionID 标识一次不可变上游尝试投影。
	ProjectionID string `json:"projection_id"`
	// LineageID binds the projection to Router-owned lineage.
	// LineageID 将投影绑定到 Router 拥有的谱系。
	LineageID string `json:"lineage_id"`
	// Entries contains one decision for every projected canonical item.
	// Entries 包含每个已投影规范项目的唯一决策。
	Entries []ProjectionEntry `json:"entries"`
}

// ProjectionLedger is the authoritative reversible projection record.
// ProjectionLedger 是权威的可逆投影记录。
type ProjectionLedger struct {
	// LedgerID identifies the persisted ledger.
	// LedgerID 标识持久化账本。
	LedgerID string `json:"ledger_id"`
	// ProjectionID identifies the upstream attempt projection.
	// ProjectionID 标识上游尝试投影。
	ProjectionID string `json:"projection_id"`
	// LineageID binds every entry to one lineage.
	// LineageID 将每个条目绑定到一个谱系。
	LineageID string `json:"lineage_id"`
	// Entries contains one entry per canonical item.
	// Entries 包含每个规范项目的唯一条目。
	Entries []ProjectionEntry `json:"entries"`
}

// ProjectionEntry records one canonical-to-upstream mapping.
// ProjectionEntry 记录一个规范项目到上游的映射。
type ProjectionEntry struct {
	// ProjectionID identifies the owning projection attempt.
	// ProjectionID 标识所属投影尝试。
	ProjectionID string `json:"projection_id"`
	// LineageID identifies the owning lineage.
	// LineageID 标识所属谱系。
	LineageID string `json:"lineage_id"`
	// CanonicalItemID identifies the original VCP item.
	// CanonicalItemID 标识原始 VCP 项目。
	CanonicalItemID string `json:"canonical_item_id"`
	// CanonicalSequence records the original global order.
	// CanonicalSequence 记录原始全局顺序。
	CanonicalSequence uint64 `json:"canonical_sequence"`
	// CanonicalKind records the original item kind.
	// CanonicalKind 记录原始项目种类。
	CanonicalKind ContextKind `json:"canonical_kind"`
	// SourceAuthority records the original authority.
	// SourceAuthority 记录原始权限。
	SourceAuthority Authority `json:"source_authority"`
	// CarrierProtocol identifies the upstream protocol profile.
	// CarrierProtocol 标识上游协议 Profile。
	CarrierProtocol string `json:"carrier_protocol"`
	// CarrierRoleOrSlot identifies the exact upstream carrier.
	// CarrierRoleOrSlot 标识精确上游载体。
	CarrierRoleOrSlot string `json:"carrier_role_or_slot"`
	// UpstreamPosition identifies the exact zero-based carrier position.
	// UpstreamPosition 标识精确的零基载体位置。
	UpstreamPosition int `json:"upstream_position"`
	// ProjectionMode records native, projected, omitted, or blocked.
	// ProjectionMode 记录原生、投影、省略或阻止。
	ProjectionMode CapabilityMode `json:"projection_mode"`
	// ExecutionEquivalence records semantic strength.
	// ExecutionEquivalence 记录语义强度。
	ExecutionEquivalence ExecutionEquivalence `json:"execution_equivalence"`
	// RuleID identifies the registered mapping rule.
	// RuleID 标识已注册映射规则。
	RuleID string `json:"rule_id"`
	// RuleVersion identifies the mapping behavior version.
	// RuleVersion 标识映射行为版本。
	RuleVersion string `json:"rule_version"`
	// FrameID identifies a projected Frame when used.
	// FrameID 在使用投影 Frame 时标识该 Frame。
	FrameID string `json:"frame_id,omitempty"`
	// ContentDigest verifies Frame plaintext content.
	// ContentDigest 校验 Frame 明文内容。
	ContentDigest string `json:"content_digest,omitempty"`
	// DecodePolicy restricts restoration to trusted replay paths.
	// DecodePolicy 将恢复限制在受信任回放路径。
	DecodePolicy string `json:"decode_policy"`
	// OriginalItem preserves the canonical truth independently of upstream echo.
	// OriginalItem 独立于上游回显保存规范真相。
	OriginalItem ContextItem `json:"original_item"`
	// CreatedAt records ledger creation time.
	// CreatedAt 记录账本创建时间。
	CreatedAt time.Time `json:"created_at"`
	// ExpiresAt bounds restoration validity.
	// ExpiresAt 限制恢复有效期。
	ExpiresAt time.Time `json:"expires_at"`
}

// Frame is the parsed canonical Vulcan Frame representation.
// Frame 是解析后的规范 Vulcan Frame 表示。
type Frame struct {
	// Version identifies the Frame schema.
	// Version 标识 Frame Schema。
	Version string
	// FrameID identifies the ledger entry.
	// FrameID 标识账本条目。
	FrameID string
	// Kind identifies developer, system_inline, system_preamble, or delegated_result.
	// Kind 标识 developer、system_inline、system_preamble 或 delegated_result。
	Kind string
	// Sequence records canonical global order.
	// Sequence 记录规范全局顺序。
	Sequence uint64
	// Digest verifies plaintext content.
	// Digest 校验明文内容。
	Digest string
	// Purpose must equal context-carrier.
	// Purpose 必须等于 context-carrier。
	Purpose string
	// Content contains decoded plaintext.
	// Content 包含解码后的明文。
	Content string
}

// EncodeFrame encodes one registered text-only canonical item using fixed attribute order.
// EncodeFrame 使用固定属性顺序编码一个已注册的纯文本规范项目。
func EncodeFrame(item ContextItem, frameID string) (string, Frame, error) {
	if strings.TrimSpace(frameID) == "" {
		return "", Frame{}, fmt.Errorf("%w: frame-id is required", ErrInvalidFrame)
	}
	kind, errKind := frameKind(item)
	if errKind != nil {
		return "", Frame{}, errKind
	}
	content, errContent := TextContent(item.Content)
	if errContent != nil {
		return "", Frame{}, errContent
	}
	digest := DigestText(content)
	frame := Frame{Version: FrameVersion, FrameID: frameID, Kind: kind, Sequence: item.Sequence, Digest: digest, Purpose: FramePurpose, Content: content}
	return encodeFrameValue(frame), frame, nil
}

// ParseFrame parses exactly one complete canonical Vulcan Frame.
// ParseFrame 解析且仅解析一个完整规范 Vulcan Frame。
func ParseFrame(encoded string) (Frame, error) {
	// wireFrame is the strict XML representation accepted by the parser.
	// wireFrame 是解析器接受的严格 XML 表示。
	type wireFrame struct {
		// XMLName fixes the only accepted root element.
		// XMLName 固定唯一接受的根元素。
		XMLName xml.Name `xml:"vulcan-frame"`
		// Version is the canonical frame protocol version.
		// Version 是规范 Frame 协议版本。
		Version string `xml:"version,attr"`
		// FrameID is the immutable frame identifier.
		// FrameID 是不可变 Frame 标识。
		FrameID string `xml:"frame-id,attr"`
		// Kind is the registered frame content category.
		// Kind 是已注册的 Frame 内容类别。
		Kind string `xml:"kind,attr"`
		// Sequence is the canonical decimal event sequence.
		// Sequence 是规范十进制事件序号。
		Sequence string `xml:"sequence,attr"`
		// Digest authenticates the canonical text content.
		// Digest 认证规范文本内容。
		Digest string `xml:"digest,attr"`
		// Purpose fixes the frame interpretation boundary.
		// Purpose 固定 Frame 解释边界。
		Purpose string `xml:"purpose,attr"`
		// Content is the exact canonical frame character data.
		// Content 是精确的规范 Frame 字符数据。
		Content string `xml:",chardata"`
	}
	var wire wireFrame
	decoder := xml.NewDecoder(strings.NewReader(encoded))
	if errDecode := decoder.Decode(&wire); errDecode != nil {
		return Frame{}, fmt.Errorf("%w: %v", ErrInvalidFrame, errDecode)
	}
	sequence, errSequence := strconv.ParseUint(wire.Sequence, 10, 64)
	if errSequence != nil || sequence == 0 {
		return Frame{}, fmt.Errorf("%w: invalid sequence", ErrInvalidFrame)
	}
	frame := Frame{Version: wire.Version, FrameID: wire.FrameID, Kind: wire.Kind, Sequence: sequence, Digest: wire.Digest, Purpose: wire.Purpose, Content: wire.Content}
	if frame.Version != FrameVersion || frame.Purpose != FramePurpose || frame.FrameID == "" || !registeredFrameKind(frame.Kind) || frame.Digest != DigestText(frame.Content) {
		return Frame{}, fmt.Errorf("%w: attributes or digest do not match", ErrInvalidFrame)
	}
	if encoded != encodeFrameValue(frame) {
		return Frame{}, fmt.Errorf("%w: non-canonical attribute order or encoding", ErrInvalidFrame)
	}
	return frame, nil
}

// encodeFrameValue renders one already-validated Frame in canonical wire order.
// encodeFrameValue 以规范线协议顺序渲染一个已校验 Frame。
func encodeFrameValue(frame Frame) string {
	var encoded bytes.Buffer
	encoded.WriteString(`<vulcan-frame version="`)
	encoded.WriteString(frame.Version)
	encoded.WriteString(`" frame-id="`)
	encoded.WriteString(escapeXML(frame.FrameID))
	encoded.WriteString(`" kind="`)
	encoded.WriteString(frame.Kind)
	encoded.WriteString(`" sequence="`)
	encoded.WriteString(strconv.FormatUint(frame.Sequence, 10))
	encoded.WriteString(`" digest="`)
	encoded.WriteString(frame.Digest)
	encoded.WriteString(`" purpose="`)
	encoded.WriteString(frame.Purpose)
	encoded.WriteString(`">`)
	encoded.WriteString(escapeXML(frame.Content))
	encoded.WriteString(`</vulcan-frame>`)
	return encoded.String()
}

// TextContent joins text blocks and rejects non-text carrier content.
// TextContent 拼接文本块并拒绝非文本载体内容。
func TextContent(blocks []ContentBlock) (string, error) {
	if len(blocks) == 0 {
		return "", fmt.Errorf("%w: carrier content is empty", ErrInvalidFrame)
	}
	parts := make([]string, 0, len(blocks))
	for _, block := range blocks {
		if block.Type != ContentText && block.Type != ContentRefusal {
			return "", fmt.Errorf("%w: content type %q is not text-carriable", ErrInvalidFrame, block.Type)
		}
		parts = append(parts, block.Text)
	}
	return strings.Join(parts, "\n"), nil
}

// DigestText returns the fixed lowercase SHA-256 content digest.
// DigestText 返回固定的小写 SHA-256 内容摘要。
func DigestText(content string) string {
	digest := sha256.Sum256([]byte(content))
	return "sha256:" + hex.EncodeToString(digest[:])
}

// DeriveID deterministically derives a safe opaque identifier from stable parts.
// DeriveID 从稳定组成部分确定性派生安全不透明标识。
func DeriveID(prefix string, parts ...string) string {
	digest := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return prefix + "_" + hex.EncodeToString(digest[:12])
}

// EscapeReservedFrameText prevents user text from being interpreted as a Router Frame.
// EscapeReservedFrameText 防止用户文本被解释为 Router Frame。
func EscapeReservedFrameText(text string) string {
	escaped := strings.ReplaceAll(text, "<vulcan-frame", "&lt;vulcan-frame")
	return strings.ReplaceAll(escaped, "</vulcan-frame", "&lt;/vulcan-frame")
}

// FrameScanner accumulates a controlled Frame across arbitrary chunks.
// FrameScanner 跨任意分片累积受控 Frame。
type FrameScanner struct {
	// buffer stores bytes until the caller declares the controlled carrier complete.
	// buffer 在调用方声明受控载体完成前存储字节。
	buffer strings.Builder
}

// Feed appends one arbitrary carrier chunk.
// Feed 追加一个任意载体分片。
func (s *FrameScanner) Feed(chunk string) {
	s.buffer.WriteString(chunk)
}

// Complete validates the accumulated controlled carrier as one Frame.
// Complete 将累积的受控载体校验为一个 Frame。
func (s *FrameScanner) Complete() (Frame, error) {
	return ParseFrame(s.buffer.String())
}

// CompleteOrText restores a valid controlled Frame or returns the exact bytes as ordinary text.
// CompleteOrText 恢复有效受控 Frame，或将精确字节作为普通文本返回。
func (s *FrameScanner) CompleteOrText() (Frame, string, bool) {
	raw := s.buffer.String()
	frame, errFrame := ParseFrame(raw)
	if errFrame != nil {
		return Frame{}, raw, false
	}
	return frame, "", true
}

// Add appends one projection entry while enforcing lineage and item uniqueness.
// Add 追加一个投影条目并强制谱系和项目唯一性。
func (l *ProjectionLedger) Add(entry ProjectionEntry) error {
	if entry.LineageID != l.LineageID || entry.ProjectionID != l.ProjectionID {
		return fmt.Errorf("%w: entry ownership differs", ErrProjectionMismatch)
	}
	for _, existing := range l.Entries {
		if existing.CanonicalItemID == entry.CanonicalItemID {
			return fmt.Errorf("%w: duplicate canonical item %q", ErrProjectionMismatch, entry.CanonicalItemID)
		}
		if entry.FrameID != "" && existing.FrameID == entry.FrameID {
			return fmt.Errorf("%w: duplicate frame_id %q", ErrProjectionMismatch, entry.FrameID)
		}
	}
	l.Entries = append(l.Entries, entry)
	return nil
}

// Restore reconstructs canonical context without relying on upstream request echo.
// Restore 在不依赖上游请求回显的情况下重建规范上下文。
func (l ProjectionLedger) Restore() ([]ContextItem, error) {
	items := make([]ContextItem, 0, len(l.Entries))
	for _, entry := range l.Entries {
		if entry.LineageID != l.LineageID || entry.ProjectionID != l.ProjectionID || entry.OriginalItem.ItemID != entry.CanonicalItemID || entry.OriginalItem.Sequence != entry.CanonicalSequence {
			return nil, fmt.Errorf("%w: invalid entry ownership", ErrProjectionMismatch)
		}
		items = append(items, entry.OriginalItem)
	}
	sort.Slice(items, func(left, right int) bool { return items[left].Sequence < items[right].Sequence })
	if errValidate := ValidateContext(items); errValidate != nil {
		return nil, errValidate
	}
	return items, nil
}

// RestoreFrame validates lineage, carrier, position, identity, and digest before restoration.
// RestoreFrame 在恢复前校验谱系、载体、位置、身份和摘要。
func (l ProjectionLedger) RestoreFrame(frame Frame, lineageID string, carrier string, position int, now time.Time) (ContextItem, error) {
	if lineageID != l.LineageID {
		return ContextItem{}, fmt.Errorf("%w: lineage differs", ErrProjectionMismatch)
	}
	for _, entry := range l.Entries {
		if entry.FrameID != frame.FrameID {
			continue
		}
		if entry.DecodePolicy != "replay_only" || entry.CarrierRoleOrSlot != carrier || entry.UpstreamPosition != position || now.After(entry.ExpiresAt) || entry.ContentDigest != frame.Digest || entry.CanonicalSequence != frame.Sequence || frame.Kind != entryFrameKind(entry) {
			return ContextItem{}, fmt.Errorf("%w: frame constraints differ", ErrProjectionMismatch)
		}
		return entry.OriginalItem, nil
	}
	return ContextItem{}, fmt.Errorf("%w: frame_id is not registered", ErrProjectionMismatch)
}

// frameKind maps a canonical item to one registered Frame kind.
// frameKind 将规范项目映射到一个已注册 Frame 种类。
func frameKind(item ContextItem) (string, error) {
	if item.Kind == ContextDelegatedResult {
		return "delegated_result", nil
	}
	if item.Kind != ContextInstruction {
		return "", fmt.Errorf("%w: kind %q is not frame-carriable", ErrInvalidFrame, item.Kind)
	}
	if item.Authority == AuthorityDeveloper {
		return "developer", nil
	}
	if item.Authority == AuthoritySystem && item.Placement == PlacementPreamble {
		return "system_preamble", nil
	}
	if item.Authority == AuthoritySystem && item.Placement == PlacementTranscript {
		return "system_inline", nil
	}
	return "", fmt.Errorf("%w: instruction is not registered for a Frame", ErrInvalidFrame)
}

// entryFrameKind returns the registered Frame kind represented by an entry.
// entryFrameKind 返回条目表示的已注册 Frame 种类。
func entryFrameKind(entry ProjectionEntry) string {
	kind, errKind := frameKind(entry.OriginalItem)
	if errKind != nil {
		return ""
	}
	return kind
}

// registeredFrameKind reports whether a Frame kind is registered in VCP 1.0.
// registeredFrameKind 报告 Frame 种类是否已在 VCP 1.0 注册。
func registeredFrameKind(kind string) bool {
	return kind == "developer" || kind == "system_inline" || kind == "system_preamble" || kind == "delegated_result"
}

// escapeXML returns canonical XML text escaping without adding tags.
// escapeXML 返回不添加标签的规范 XML 文本转义。
func escapeXML(value string) string {
	var escaped bytes.Buffer
	if errEscape := xml.EscapeText(&escaped, []byte(value)); errEscape != nil {
		return ""
	}
	return escaped.String()
}
