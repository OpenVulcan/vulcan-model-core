package minimax

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

const (
	// maximumMiniMaxAudioSSELineBytes bounds one provider audio frame without limiting the complete output.
	// maximumMiniMaxAudioSSELineBytes 限制单个供应商音频帧且不限制完整输出。
	maximumMiniMaxAudioSSELineBytes = 8 * 1024 * 1024
)

// miniMaxAudioStreamPayload mirrors the common streamed speech and music audio envelope.
// miniMaxAudioStreamPayload 镜像语音与音乐共用的流式音频信封。
type miniMaxAudioStreamPayload struct {
	// Data contains one optional hexadecimal audio chunk and provider stream state.
	// Data 包含一个可选十六进制音频分片与供应商流状态。
	Data *struct {
		// Audio contains one independently decodable hexadecimal byte chunk.
		// Audio 包含一个可独立解码的十六进制字节分片。
		Audio string `json:"audio"`
		// Status equals two on the provider's terminal frame.
		// Status 在供应商终止帧上等于二。
		Status int `json:"status"`
		// SubtitleFile is the temporary subtitle timing JSON URL when requested for T2A.
		// SubtitleFile 是 T2A 请求字幕时返回的临时字幕计时 JSON URL。
		SubtitleFile string `json:"subtitle_file"`
	} `json:"data"`
	// BaseResponse records provider application-level success.
	// BaseResponse 记录供应商应用层成功状态。
	BaseResponse miniMaxBaseResponse `json:"base_resp"`
}

// miniMaxDecodedAudio contains complete streamed bytes and an optional terminal subtitle URL.
// miniMaxDecodedAudio 包含完整流式字节与可选终态字幕 URL。
type miniMaxDecodedAudio struct {
	// Audio contains complete decoded output bytes.
	// Audio 包含完整解码输出字节。
	Audio []byte
	// SubtitleURL contains a provider-returned temporary timing document URL.
	// SubtitleURL 包含供应商返回的临时计时文档 URL。
	SubtitleURL string
}

// decodeMiniMaxAudioHTTPStream decodes JSON fallback or SSE audio exactly as released minimax-cli does.
// decodeMiniMaxAudioHTTPStream 按已发布 minimax-cli 的行为精确解码 JSON 降级或 SSE 音频。
func decodeMiniMaxAudioHTTPStream(ctx context.Context, response *http.Response, sink provider.ExecutionResourceSink, outputID string, kind vcp.MediaKind, mimeType string, maximumBytes *int64) (miniMaxDecodedAudio, error) {
	if response == nil || response.Body == nil {
		return miniMaxDecodedAudio{}, fmt.Errorf("%w: audio response body is required", ErrInvalidSpeechResponse)
	}
	mediaType, _, errMediaType := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if errMediaType == nil && strings.EqualFold(mediaType, "text/event-stream") {
		return decodeMiniMaxAudioSSE(ctx, response.Body, sink, outputID, kind, mimeType, maximumBytes)
	}
	bounded, errBound := transport.NewBoundedResponseReader(response.Body, transport.MaximumNonStreamingResponseBytes)
	if errBound != nil {
		return miniMaxDecodedAudio{}, fmt.Errorf("%w: bound audio response: %v", ErrInvalidSpeechResponse, errBound)
	}
	var payload miniMaxAudioStreamPayload
	if errDecode := json.NewDecoder(bounded).Decode(&payload); errDecode != nil {
		return miniMaxDecodedAudio{}, fmt.Errorf("%w: expected SSE or JSON audio: %v", ErrInvalidSpeechResponse, errDecode)
	}
	audio, errAppend := appendMiniMaxAudioChunk(ctx, nil, payload, sink, outputID, kind, mimeType, maximumBytes)
	if errAppend != nil {
		return miniMaxDecodedAudio{}, errAppend
	}
	if len(audio) == 0 {
		return miniMaxDecodedAudio{}, fmt.Errorf("%w: response ended without audio data", ErrInvalidSpeechResponse)
	}
	return miniMaxDecodedAudio{Audio: audio, SubtitleURL: miniMaxSubtitleURL(payload)}, nil
}

// decodeMiniMaxAudioSSE parses blank-line-delimited data frames and retains only decoded output bytes.
// decodeMiniMaxAudioSSE 解析空行分隔的数据帧且仅保留解码后的输出字节。
func decodeMiniMaxAudioSSE(ctx context.Context, reader io.Reader, sink provider.ExecutionResourceSink, outputID string, kind vcp.MediaKind, mimeType string, maximumBytes *int64) (miniMaxDecodedAudio, error) {
	if reader == nil {
		return miniMaxDecodedAudio{}, fmt.Errorf("%w: audio stream reader is required", ErrInvalidSpeechResponse)
	}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), maximumMiniMaxAudioSSELineBytes)
	// dataLines preserves one syntactically complete SSE frame before semantic decoding.
	// dataLines 在语义解码前保存一条语法完整的 SSE 帧。
	dataLines := make([]string, 0, 1)
	var audio []byte
	subtitleURL := ""
	terminal := false
	dispatch := func() error {
		if len(dataLines) == 0 {
			return nil
		}
		data := strings.Join(dataLines, "\n")
		dataLines = dataLines[:0]
		if data == "[DONE]" {
			terminal = true
			return nil
		}
		var payload miniMaxAudioStreamPayload
		if errDecode := json.Unmarshal([]byte(data), &payload); errDecode != nil {
			return fmt.Errorf("%w: decode audio stream frame: %v", ErrInvalidSpeechResponse, errDecode)
		}
		updated, errAppend := appendMiniMaxAudioChunk(ctx, audio, payload, sink, outputID, kind, mimeType, maximumBytes)
		if errAppend != nil {
			return errAppend
		}
		audio = updated
		if observedSubtitleURL := miniMaxSubtitleURL(payload); observedSubtitleURL != "" {
			subtitleURL = observedSubtitleURL
		}
		if payload.Data != nil && payload.Data.Status == 2 {
			terminal = true
		}
		return nil
	}
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if errDispatch := dispatch(); errDispatch != nil {
				return miniMaxDecodedAudio{}, errDispatch
			}
			if terminal {
				break
			}
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		field, value, found := strings.Cut(line, ":")
		if !found {
			return miniMaxDecodedAudio{}, fmt.Errorf("%w: malformed audio SSE field", ErrInvalidSpeechResponse)
		}
		if field == "data" {
			dataLines = append(dataLines, strings.TrimPrefix(value, " "))
		}
	}
	if errScan := scanner.Err(); errScan != nil {
		return miniMaxDecodedAudio{}, fmt.Errorf("%w: read audio stream: %v", ErrInvalidSpeechResponse, errScan)
	}
	if !terminal {
		if errDispatch := dispatch(); errDispatch != nil {
			return miniMaxDecodedAudio{}, errDispatch
		}
	}
	if len(audio) == 0 {
		return miniMaxDecodedAudio{}, fmt.Errorf("%w: stream ended without audio data", ErrInvalidSpeechResponse)
	}
	return miniMaxDecodedAudio{Audio: audio, SubtitleURL: subtitleURL}, nil
}

// miniMaxSubtitleURL extracts only a syntactically valid provider-returned HTTP(S) subtitle URL.
// miniMaxSubtitleURL 仅提取语法有效的供应商返回 HTTP(S) 字幕 URL。
func miniMaxSubtitleURL(payload miniMaxAudioStreamPayload) string {
	if payload.Data == nil || validatePublicMusicURL(payload.Data.SubtitleFile) != nil {
		return ""
	}
	return strings.TrimSpace(payload.Data.SubtitleFile)
}

// appendMiniMaxAudioChunk validates one provider envelope, enforces budget, and emits cumulative progress.
// appendMiniMaxAudioChunk 校验一个供应商信封、强制预算并发送累计进度。
func appendMiniMaxAudioChunk(ctx context.Context, audio []byte, payload miniMaxAudioStreamPayload, sink provider.ExecutionResourceSink, outputID string, kind vcp.MediaKind, mimeType string, maximumBytes *int64) ([]byte, error) {
	if payload.BaseResponse.StatusCode != 0 {
		return nil, fmt.Errorf("%w: provider status %d", ErrInvalidSpeechResponse, payload.BaseResponse.StatusCode)
	}
	if payload.Data == nil || strings.TrimSpace(payload.Data.Audio) == "" {
		if payload.Data != nil && payload.Data.Status == 2 && len(audio) > 0 {
			return audio, nil
		}
		return audio, nil
	}
	chunk, errHex := hex.DecodeString(payload.Data.Audio)
	if errHex != nil || len(chunk) == 0 {
		return nil, fmt.Errorf("%w: invalid hexadecimal audio chunk", ErrInvalidSpeechResponse)
	}
	if maximumBytes != nil && int64(len(audio)) > *maximumBytes-int64(len(chunk)) {
		return nil, fmt.Errorf("%w: streamed output exceeds max_output_bytes", provider.ErrOutputBudgetExceeded)
	}
	audio = append(audio, chunk...)
	if sink != nil {
		progress := provider.ResourceProgress{OutputID: outputID, Kind: kind, MIMEType: mimeType, PartialBytes: int64(len(audio))}
		if errEmit := sink.EmitResourceProgress(ctx, progress); errEmit != nil {
			return nil, errEmit
		}
	}
	return audio, nil
}
