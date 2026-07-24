package alibaba

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// TestAlibabaTypedDecodersRejectTrailingJSON verifies every Alibaba response family changed by this integration accepts one JSON document only.
// TestAlibabaTypedDecodersRejectTrailingJSON 验证本次集成修改的每个阿里响应系列都只接受一个 JSON 文档。
func TestAlibabaTypedDecodersRejectTrailingJSON(t *testing.T) {
	// testCase owns one valid first document followed by a forbidden second document and its exact decoder assertion.
	// testCase 保存一个有效首文档、一个禁止的第二文档及其精确解码断言。
	type testCase struct {
		name          string
		invalidError  error
		decode        func(string) error
		validDocument string
	}
	tests := []testCase{
		{name: "Qwen image", invalidError: ErrInvalidImageResponse, validDocument: `{"request_id":"request-image","output":{"choices":[{"message":{"content":[{"image":"https://outputs.example/image.png"}]}}]}}`, decode: func(value string) error {
			_, errDecode := decodeQwenImageResponse(strings.NewReader(value))
			return errDecode
		}},
		{name: "CosyVoice", invalidError: ErrInvalidSpeechResponse, validDocument: `{"request_id":"request-cosy","output":{"audio":{"url":"https://outputs.example/cosy.wav"},"finish_reason":"stop"}}`, decode: func(value string) error {
			_, errDecode := decodeCosyVoiceResponse(strings.NewReader(value), "audio/wav")
			return errDecode
		}},
		{name: "Qwen TTS", invalidError: ErrInvalidSpeechResponse, validDocument: `{"status_code":200,"request_id":"request-tts","output":{"finish_reason":"stop","audio":{"url":"https://outputs.example/tts.wav"}}}`, decode: func(value string) error {
			_, errDecode := decodeQwen3TTSResponse(strings.NewReader(value))
			return errDecode
		}},
		{name: "Qwen ASR", invalidError: ErrInvalidSpeechResponse, validDocument: `{"request_id":"request-asr","output":{"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":[{"text":"hello"}],"annotations":[{"type":"audio_info","language":"en"}]}}]},"usage":{"seconds":1}}`, decode: func(value string) error {
			_, errDecode := decodeQwen3ASRResponse(strings.NewReader(value))
			return errDecode
		}},
		{name: "Fun ASR start", invalidError: ErrInvalidSpeechResponse, validDocument: `{"output":{"task_id":"task-one","task_status":"PENDING"}}`, decode: func(value string) error {
			_, errDecode := decodeFunASRStart(strings.NewReader(value), time.Now().UTC())
			return errDecode
		}},
		{name: "Fun ASR poll", invalidError: ErrInvalidSpeechResponse, validDocument: `{"output":{"task_id":"task-one","task_status":"PENDING"}}`, decode: func(value string) error {
			_, _, errDecode := decodeFunASRPoll(strings.NewReader(value), "task-one", time.Now().UTC(), []string{"https://inputs.example/source.wav"})
			return errDecode
		}},
		{name: "Fun ASR transcript", invalidError: ErrInvalidSpeechResponse, validDocument: `{"properties":{"original_duration_in_milliseconds":1},"transcripts":[{"channel_id":0,"text":"hello","sentences":[]}]}`, decode: func(value string) error {
			_, errDecode := decodeFunASRTranscript(strings.NewReader(value), []int{0})
			return errDecode
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if errDecode := test.decode(test.validDocument + ` {}`); !errors.Is(errDecode, test.invalidError) || !strings.Contains(errDecode.Error(), "trailing response data") {
				t.Fatalf("decoder error = %v", errDecode)
			}
		})
	}
}

// TestDecodeFunASRStartRejectsNonCanonicalTaskID verifies provider task identities cannot change after trimming.
// TestDecodeFunASRStartRejectsNonCanonicalTaskID 验证供应商任务标识不能在去除空格后发生变化。
func TestDecodeFunASRStartRejectsNonCanonicalTaskID(t *testing.T) {
	response := `{"output":{"task_id":" task-one ","task_status":"PENDING"}}`
	if _, errDecode := decodeFunASRStart(strings.NewReader(response), time.Now().UTC()); !errors.Is(errDecode, ErrInvalidSpeechResponse) {
		t.Fatalf("decodeFunASRStart() error = %v", errDecode)
	}
}
