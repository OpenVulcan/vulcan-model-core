package resource

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"mime"
	"os"
	"strings"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// ErrMIMEConflict reports disagreement between declared and magic-derived MIME.
// ErrMIMEConflict 表示声明 MIME 与魔数推导 MIME 不一致。
var ErrMIMEConflict = errors.New("declared MIME does not match resource bytes")

// Probe inspects one completed temporary object without trusting its extension.
// Probe 检查一个已完成临时对象且不信任其扩展名。
type Probe interface {
	// Inspect returns authoritative MIME and parsed metadata for the exact declared resource kind.
	// Inspect 为精确声明资源类型返回权威 MIME 与已解析元数据。
	Inspect(string, vcp.MediaKind, string) (string, Metadata, error)
}

// StandardProbe implements bounded standard-library magic and metadata inspection.
// StandardProbe 实现受限标准库魔数与元数据检查。
type StandardProbe struct{}

// Inspect derives MIME from magic, verifies kind ownership, and parses supported metadata.
// Inspect 根据魔数推导 MIME、校验类型归属并解析受支持元数据。
func (StandardProbe) Inspect(path string, kind vcp.MediaKind, declaredMIME string) (string, Metadata, error) {
	file, errOpen := os.Open(path)
	if errOpen != nil {
		return "", Metadata{}, fmt.Errorf("open resource for inspection: %w", errOpen)
	}
	defer file.Close()
	header := make([]byte, 512)
	read, errRead := io.ReadFull(file, header)
	if errRead != nil && !errors.Is(errRead, io.ErrUnexpectedEOF) {
		return "", Metadata{}, fmt.Errorf("read resource magic: %w", errRead)
	}
	header = header[:read]
	detectedMIME, detectedKind := detectMagic(header)
	if detectedKind != kind {
		return "", Metadata{}, fmt.Errorf("%w: declared kind %q differs from detected kind %q", ErrMIMEConflict, kind, detectedKind)
	}
	declaredBase, _, errMIME := mime.ParseMediaType(strings.TrimSpace(declaredMIME))
	if declaredMIME != "" && (errMIME != nil || !strings.EqualFold(declaredBase, detectedMIME)) {
		return "", Metadata{}, fmt.Errorf("%w: declared %q, detected %q", ErrMIMEConflict, declaredMIME, detectedMIME)
	}
	if _, errSeek := file.Seek(0, io.SeekStart); errSeek != nil {
		return "", Metadata{}, fmt.Errorf("rewind resource for metadata: %w", errSeek)
	}
	switch kind {
	case vcp.MediaImage:
		return inspectImage(file, path, detectedMIME)
	case vcp.MediaAudio:
		return inspectAudio(file, detectedMIME)
	case vcp.MediaVideo:
		return detectedMIME, Metadata{Video: &VideoMetadata{Container: videoContainer(detectedMIME)}}, nil
	case vcp.MediaFile:
		return detectedMIME, Metadata{}, nil
	default:
		return "", Metadata{}, ErrInvalidResource
	}
}

// detectMagic returns one closed MIME and media kind from verified leading bytes.
// detectMagic 根据已校验前导字节返回一个封闭 MIME 和媒体类型。
func detectMagic(header []byte) (string, vcp.MediaKind) {
	switch {
	case len(header) >= 8 && bytes.Equal(header[:8], []byte("\x89PNG\r\n\x1a\n")):
		return "image/png", vcp.MediaImage
	case len(header) >= 3 && header[0] == 0xff && header[1] == 0xd8 && header[2] == 0xff:
		return "image/jpeg", vcp.MediaImage
	case len(header) >= 6 && (bytes.Equal(header[:6], []byte("GIF87a")) || bytes.Equal(header[:6], []byte("GIF89a"))):
		return "image/gif", vcp.MediaImage
	case len(header) >= 12 && bytes.Equal(header[:4], []byte("RIFF")) && bytes.Equal(header[8:12], []byte("WEBP")):
		return "image/webp", vcp.MediaImage
	case len(header) >= 2 && bytes.Equal(header[:2], []byte("BM")):
		return "image/bmp", vcp.MediaImage
	case len(header) >= 12 && bytes.Equal(header[:4], []byte("RIFF")) && bytes.Equal(header[8:12], []byte("WAVE")):
		return "audio/wav", vcp.MediaAudio
	case len(header) >= 3 && bytes.Equal(header[:3], []byte("ID3")):
		return "audio/mpeg", vcp.MediaAudio
	case len(header) >= 2 && header[0] == 0xff && header[1]&0xe0 == 0xe0:
		return "audio/mpeg", vcp.MediaAudio
	case len(header) >= 12 && bytes.Equal(header[4:8], []byte("ftyp")):
		return "video/mp4", vcp.MediaVideo
	case len(header) >= 4 && bytes.Equal(header[:4], []byte{0x1a, 0x45, 0xdf, 0xa3}):
		return "video/webm", vcp.MediaVideo
	case len(header) >= 5 && bytes.Equal(header[:5], []byte("%PDF-")):
		return "application/pdf", vcp.MediaFile
	default:
		return "application/octet-stream", vcp.MediaFile
	}
}

// inspectImage decodes authoritative dimensions and GIF animation state.
// inspectImage 解码权威尺寸及 GIF 动画状态。
func inspectImage(file *os.File, path string, detectedMIME string) (string, Metadata, error) {
	if detectedMIME == "image/webp" {
		return inspectWebP(file, detectedMIME)
	}
	if detectedMIME == "image/bmp" {
		return inspectBMP(file, detectedMIME)
	}
	configuration, _, errDecode := image.DecodeConfig(file)
	if errDecode != nil || configuration.Width <= 0 || configuration.Height <= 0 {
		return "", Metadata{}, fmt.Errorf("decode image metadata: %w", errDecode)
	}
	animated := false
	if detectedMIME == "image/gif" {
		gifFile, errOpen := os.Open(path)
		if errOpen != nil {
			return "", Metadata{}, fmt.Errorf("open GIF metadata: %w", errOpen)
		}
		decoded, errGIF := gif.DecodeAll(gifFile)
		errClose := gifFile.Close()
		if errGIF != nil {
			return "", Metadata{}, fmt.Errorf("decode GIF metadata: %w", errGIF)
		}
		if errClose != nil {
			return "", Metadata{}, fmt.Errorf("close GIF metadata: %w", errClose)
		}
		animated = len(decoded.Image) > 1
	}
	return detectedMIME, Metadata{Image: &ImageMetadata{Width: configuration.Width, Height: configuration.Height, Animated: animated, HasAlpha: imageColorModelHasAlpha(configuration.ColorModel)}}, nil
}

// imageColorModelHasAlpha reports structural alpha support from one decoded standard-library color model.
// imageColorModelHasAlpha 根据一个已解码标准库颜色模型报告结构化 Alpha 支持。
func imageColorModelHasAlpha(model color.Model) bool {
	if model == color.AlphaModel || model == color.Alpha16Model || model == color.RGBAModel || model == color.RGBA64Model || model == color.NRGBAModel || model == color.NRGBA64Model {
		return true
	}
	palette, paletteModel := model.(color.Palette)
	if !paletteModel {
		return false
	}
	for _, value := range palette {
		_, _, _, alpha := value.RGBA()
		if alpha != 0xffff {
			return true
		}
	}
	return false
}

// inspectWebP parses the three standardized WebP image headers without adding a runtime codec dependency.
// inspectWebP 在不增加运行时编解码依赖的情况下解析三种标准 WebP 图片头。
func inspectWebP(file *os.File, detectedMIME string) (string, Metadata, error) {
	header := make([]byte, 32)
	read, errRead := io.ReadFull(file, header)
	if errRead != nil && !errors.Is(errRead, io.ErrUnexpectedEOF) {
		return "", Metadata{}, fmt.Errorf("read WebP metadata: %w", errRead)
	}
	header = header[:read]
	width, height, hasAlpha := 0, 0, false
	switch {
	case len(header) >= 30 && bytes.Equal(header[12:16], []byte("VP8X")):
		hasAlpha = header[20]&0x10 != 0
		width = 1 + int(header[24]) + int(header[25])<<8 + int(header[26])<<16
		height = 1 + int(header[27]) + int(header[28])<<8 + int(header[29])<<16
	case len(header) >= 30 && bytes.Equal(header[12:16], []byte("VP8 ")) && bytes.Equal(header[23:26], []byte{0x9d, 0x01, 0x2a}):
		width = int(binary.LittleEndian.Uint16(header[26:28]) & 0x3fff)
		height = int(binary.LittleEndian.Uint16(header[28:30]) & 0x3fff)
	case len(header) >= 25 && bytes.Equal(header[12:16], []byte("VP8L")) && header[20] == 0x2f:
		bits := binary.LittleEndian.Uint32(header[21:25])
		width = 1 + int(bits&0x3fff)
		height = 1 + int((bits>>14)&0x3fff)
		hasAlpha = true
	default:
		return "", Metadata{}, fmt.Errorf("decode WebP metadata: %w", ErrInvalidResource)
	}
	if width <= 0 || height <= 0 {
		return "", Metadata{}, fmt.Errorf("decode WebP dimensions: %w", ErrInvalidResource)
	}
	return detectedMIME, Metadata{Image: &ImageMetadata{Width: width, Height: height, HasAlpha: hasAlpha}}, nil
}

// inspectBMP parses authoritative dimensions from the standard BITMAPINFOHEADER family.
// inspectBMP 从标准 BITMAPINFOHEADER 系列解析权威尺寸。
func inspectBMP(file *os.File, detectedMIME string) (string, Metadata, error) {
	header := make([]byte, 30)
	if _, errRead := io.ReadFull(file, header); errRead != nil {
		return "", Metadata{}, fmt.Errorf("read BMP metadata: %w", errRead)
	}
	if !bytes.Equal(header[:2], []byte("BM")) || binary.LittleEndian.Uint32(header[14:18]) < 40 {
		return "", Metadata{}, fmt.Errorf("decode BMP metadata: %w", ErrInvalidResource)
	}
	width := int(int32(binary.LittleEndian.Uint32(header[18:22])))
	height := int(int32(binary.LittleEndian.Uint32(header[22:26])))
	if height < 0 {
		height = -height
	}
	if width <= 0 || height <= 0 {
		return "", Metadata{}, fmt.Errorf("decode BMP dimensions: %w", ErrInvalidResource)
	}
	return detectedMIME, Metadata{Image: &ImageMetadata{Width: width, Height: height}}, nil
}

// inspectAudio parses authoritative WAV measurements and keeps unsupported MP3 values unknown.
// inspectAudio 解析权威 WAV 测量值并保持不支持的 MP3 值未知。
func inspectAudio(file *os.File, detectedMIME string) (string, Metadata, error) {
	if detectedMIME != "audio/wav" {
		return detectedMIME, Metadata{Audio: &AudioMetadata{Encoding: "mp3"}}, nil
	}
	metadata, errWAV := inspectWAV(file)
	if errWAV != nil {
		return "", Metadata{}, errWAV
	}
	return detectedMIME, Metadata{Audio: &metadata}, nil
}

// inspectWAV scans RIFF chunks for format and data facts without assuming a fixed 44-byte header.
// inspectWAV 扫描 RIFF Chunk 获取格式和数据事实且不假定固定 44 字节 Header。
func inspectWAV(file *os.File) (AudioMetadata, error) {
	header := make([]byte, 12)
	if _, errRead := io.ReadFull(file, header); errRead != nil || !bytes.Equal(header[:4], []byte("RIFF")) || !bytes.Equal(header[8:12], []byte("WAVE")) {
		return AudioMetadata{}, fmt.Errorf("decode WAV header: %w", ErrInvalidResource)
	}
	var channels uint16
	var sampleRate uint32
	var byteRate uint32
	var dataBytes uint32
	for {
		chunkHeader := make([]byte, 8)
		if _, errRead := io.ReadFull(file, chunkHeader); errRead != nil {
			if errors.Is(errRead, io.EOF) || errors.Is(errRead, io.ErrUnexpectedEOF) {
				break
			}
			return AudioMetadata{}, fmt.Errorf("read WAV chunk: %w", errRead)
		}
		chunkSize := binary.LittleEndian.Uint32(chunkHeader[4:8])
		switch string(chunkHeader[:4]) {
		case "fmt ":
			if chunkSize < 16 || chunkSize > 1<<20 {
				return AudioMetadata{}, fmt.Errorf("invalid WAV format chunk: %w", ErrInvalidResource)
			}
			format := make([]byte, chunkSize)
			if _, errRead := io.ReadFull(file, format); errRead != nil {
				return AudioMetadata{}, fmt.Errorf("read WAV format chunk: %w", errRead)
			}
			channels = binary.LittleEndian.Uint16(format[2:4])
			sampleRate = binary.LittleEndian.Uint32(format[4:8])
			byteRate = binary.LittleEndian.Uint32(format[8:12])
		case "data":
			dataBytes = chunkSize
			if _, errSeek := file.Seek(int64(chunkSize), io.SeekCurrent); errSeek != nil {
				return AudioMetadata{}, fmt.Errorf("skip WAV data: %w", errSeek)
			}
		default:
			if _, errSeek := file.Seek(int64(chunkSize), io.SeekCurrent); errSeek != nil {
				return AudioMetadata{}, fmt.Errorf("skip WAV chunk: %w", errSeek)
			}
		}
		if chunkSize%2 == 1 {
			if _, errSeek := file.Seek(1, io.SeekCurrent); errSeek != nil {
				return AudioMetadata{}, fmt.Errorf("skip WAV padding: %w", errSeek)
			}
		}
	}
	if channels == 0 || sampleRate == 0 || byteRate == 0 || dataBytes == 0 {
		return AudioMetadata{}, fmt.Errorf("WAV format or data chunk is missing: %w", ErrInvalidResource)
	}
	durationMilliseconds := int64(dataBytes) * 1000 / int64(byteRate)
	return AudioMetadata{
		DurationMilliseconds: OptionalInt64{Known: true, Value: durationMilliseconds},
		SampleRateHz:         OptionalInt64{Known: true, Value: int64(sampleRate)},
		Channels:             OptionalInt64{Known: true, Value: int64(channels)},
		Encoding:             "pcm",
	}, nil
}

// videoContainer maps one verified MIME to its closed container identifier.
// videoContainer 将一个已验证 MIME 映射到其封闭容器标识。
func videoContainer(mimeType string) string {
	if mimeType == "video/mp4" {
		return "mp4"
	}
	return "webm"
}
