package openai

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"

	chatprofile "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/chat"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

const (
	// chatPCMHeaderBytes is the exact standard WAV header length copied from Bailian CLI's reviewed Omni implementation.
	// chatPCMHeaderBytes 是从已审核 Bailian CLI Omni 实现复制的标准 WAV 头精确长度。
	chatPCMHeaderBytes int64 = 44
	// chatPCMSampleRate is Alibaba Omni's documented raw PCM sample rate.
	// chatPCMSampleRate 是阿里云 Omni 文档化的原始 PCM 采样率。
	chatPCMSampleRate uint32 = 24_000
)

// chatAudioAccumulator incrementally decodes one verified Base64 PCM stream under a hard byte ceiling.
// chatAudioAccumulator 在硬字节上限内增量解码一条经过验证的 Base64 PCM 流。
type chatAudioAccumulator struct {
	// pcm stores only decoded provider PCM bytes until the final WAV header is constructed.
	// pcm 在最终构建 WAV 头之前仅存储已解码的供应商 PCM 字节。
	pcm bytes.Buffer
	// remainder preserves fewer than four Base64 characters between provider fragments.
	// remainder 在供应商分片之间保留少于四个 Base64 字符。
	remainder string
	// maximumBytes is the complete generated WAV ceiling including its header.
	// maximumBytes 是包含 WAV 头在内的完整生成资源上限。
	maximumBytes int64
	// sealed reports that padded Base64 termination has already been observed.
	// sealed 表示已经观察到带填充的 Base64 终止。
	sealed bool
	// sink receives exact cumulative decoded PCM progress.
	// sink 接收精确的累计已解码 PCM 进度。
	sink provider.ExecutionResourceSink
}

// newChatAudioAccumulator creates one bounded decoder before provider bytes are read.
// newChatAudioAccumulator 在读取供应商字节前创建一个有界解码器。
func newChatAudioAccumulator(maximumOutputBytes *int64, sink provider.ExecutionResourceSink) (*chatAudioAccumulator, error) {
	maximumBytes := transport.MaximumNonStreamingResponseBytes
	if maximumOutputBytes != nil {
		maximumBytes = *maximumOutputBytes
	}
	if maximumBytes <= chatPCMHeaderBytes {
		return nil, fmt.Errorf("%w: max_output_bytes cannot contain a WAV header", provider.ErrOutputBudgetExceeded)
	}
	return &chatAudioAccumulator{maximumBytes: maximumBytes, sink: sink}, nil
}

// Push decodes all complete Base64 groups from one documented audio fragment.
// Push 从一个文档化音频分片中解码全部完整 Base64 分组。
func (a *chatAudioAccumulator) Push(ctx context.Context, audio *chatprofile.AudioOutputDelta) error {
	if a == nil || audio == nil || audio.Data == "" {
		return nil
	}
	if a.sealed {
		return fmt.Errorf("%w: audio data followed padded Base64 termination", chatprofile.ErrInvalidUpstreamResponse)
	}
	combined := a.remainder + audio.Data
	completeLength := len(combined) / 4 * 4
	if completeLength == 0 {
		a.remainder = combined
		return nil
	}
	complete := combined[:completeLength]
	a.remainder = combined[completeLength:]
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(complete)))
	decodedLength, errDecode := base64.StdEncoding.Decode(decoded, []byte(complete))
	if errDecode != nil {
		return fmt.Errorf("%w: decode streamed audio: %v", chatprofile.ErrInvalidUpstreamResponse, errDecode)
	}
	if strings.Contains(complete, "=") {
		if a.remainder != "" {
			return fmt.Errorf("%w: padded Base64 audio has trailing data", chatprofile.ErrInvalidUpstreamResponse)
		}
		a.sealed = true
	}
	return a.appendDecoded(ctx, decoded[:decodedLength])
}

// Finalize decodes the final raw Base64 suffix and constructs one PCM 16-bit mono 24 kHz WAV resource.
// Finalize 解码最终无填充 Base64 后缀，并构建一个 PCM 16 位单声道 24 kHz WAV 资源。
func (a *chatAudioAccumulator) Finalize(ctx context.Context) (provider.GeneratedResource, error) {
	if a == nil {
		return provider.GeneratedResource{}, fmt.Errorf("%w: audio accumulator is required", chatprofile.ErrInvalidUpstreamResponse)
	}
	if a.remainder != "" {
		if len(a.remainder) == 1 {
			return provider.GeneratedResource{}, fmt.Errorf("%w: incomplete Base64 audio suffix", chatprofile.ErrInvalidUpstreamResponse)
		}
		decoded := make([]byte, base64.RawStdEncoding.DecodedLen(len(a.remainder)))
		decodedLength, errDecode := base64.RawStdEncoding.Decode(decoded, []byte(a.remainder))
		if errDecode != nil {
			return provider.GeneratedResource{}, fmt.Errorf("%w: decode final streamed audio: %v", chatprofile.ErrInvalidUpstreamResponse, errDecode)
		}
		if errAppend := a.appendDecoded(ctx, decoded[:decodedLength]); errAppend != nil {
			return provider.GeneratedResource{}, errAppend
		}
		a.remainder = ""
	}
	if a.pcm.Len() == 0 {
		return provider.GeneratedResource{}, fmt.Errorf("%w: requested mixed audio output is missing", chatprofile.ErrInvalidUpstreamResponse)
	}
	header, errHeader := chatPCMToWAVHeader(a.pcm.Len())
	if errHeader != nil {
		return provider.GeneratedResource{}, errHeader
	}
	wav := make([]byte, 0, len(header)+a.pcm.Len())
	wav = append(wav, header...)
	wav = append(wav, a.pcm.Bytes()...)
	return provider.GeneratedResource{OutputID: "audio-0", Kind: vcp.MediaAudio, MIMEType: "audio/wav", Data: wav}, nil
}

// appendDecoded enforces the complete resource ceiling before retaining or reporting decoded PCM bytes.
// appendDecoded 在保留或报告已解码 PCM 字节前强制执行完整资源上限。
func (a *chatAudioAccumulator) appendDecoded(ctx context.Context, decoded []byte) error {
	if len(decoded) == 0 {
		return nil
	}
	if int64(a.pcm.Len()) > a.maximumBytes-chatPCMHeaderBytes-int64(len(decoded)) {
		return fmt.Errorf("%w: streamed audio exceeds max_output_bytes", provider.ErrOutputBudgetExceeded)
	}
	if _, errWrite := a.pcm.Write(decoded); errWrite != nil {
		return fmt.Errorf("%w: retain streamed audio: %v", chatprofile.ErrInvalidUpstreamResponse, errWrite)
	}
	if a.sink != nil {
		progress := provider.ResourceProgress{OutputID: "audio-0", Kind: vcp.MediaAudio, MIMEType: "audio/wav", PartialBytes: int64(a.pcm.Len())}
		if errEmit := a.sink.EmitResourceProgress(ctx, progress); errEmit != nil {
			return errEmit
		}
	}
	return nil
}

// chatPCMToWAVHeader builds Bailian CLI's exact PCM 16-bit mono 24 kHz WAV header.
// chatPCMToWAVHeader 构建 Bailian CLI 精确的 PCM 16 位单声道 24 kHz WAV 头。
func chatPCMToWAVHeader(dataLength int) ([]byte, error) {
	if dataLength <= 0 || uint64(dataLength) > uint64(^uint32(0))-36 {
		return nil, fmt.Errorf("%w: PCM audio length cannot be represented by WAV", chatprofile.ErrInvalidUpstreamResponse)
	}
	header := make([]byte, chatPCMHeaderBytes)
	copy(header[0:4], "RIFF")
	binary.LittleEndian.PutUint32(header[4:8], uint32(36+dataLength))
	copy(header[8:12], "WAVE")
	copy(header[12:16], "fmt ")
	binary.LittleEndian.PutUint32(header[16:20], 16)
	binary.LittleEndian.PutUint16(header[20:22], 1)
	binary.LittleEndian.PutUint16(header[22:24], 1)
	binary.LittleEndian.PutUint32(header[24:28], chatPCMSampleRate)
	binary.LittleEndian.PutUint32(header[28:32], chatPCMSampleRate*2)
	binary.LittleEndian.PutUint16(header[32:34], 2)
	binary.LittleEndian.PutUint16(header[34:36], 16)
	copy(header[36:40], "data")
	binary.LittleEndian.PutUint32(header[40:44], uint32(dataLength))
	return header, nil
}

// pushChatChoiceAudio accepts only the single choice-zero delta carrier verified by Alibaba's streaming Omni contract.
// pushChatChoiceAudio 仅接受 Alibaba 流式 Omni 合同已验证的单一零号候选增量载体。
func pushChatChoiceAudio(ctx context.Context, accumulator *chatAudioAccumulator, choices []chatprofile.Choice) error {
	if accumulator == nil {
		return nil
	}
	for _, choice := range choices {
		if choice.Message != nil && choice.Message.Audio != nil {
			return fmt.Errorf("%w: streamed audio must use the delta carrier", chatprofile.ErrInvalidUpstreamResponse)
		}
		if choice.Delta == nil || choice.Delta.Audio == nil {
			continue
		}
		if choice.Index != 0 {
			return fmt.Errorf("%w: streamed audio must belong to choice zero", chatprofile.ErrInvalidUpstreamResponse)
		}
		if errPush := accumulator.Push(ctx, choice.Delta.Audio); errPush != nil {
			return errPush
		}
	}
	return nil
}
