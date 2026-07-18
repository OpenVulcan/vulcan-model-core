// Stream fixtures cover behavior adapted from CLIProxyAPI commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// 流式夹具覆盖改编自 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66 的行为。
// Source paths: sdk/api/handlers/openai/openai_handlers.go and internal/runtime/executor/openai_compat_executor.go.
// 来源路径：sdk/api/handlers/openai/openai_handlers.go 和 internal/runtime/executor/openai_compat_executor.go。
// The fixtures verify Router and upstream identifier separation without importing CLIProxyAPI runtime code.
// 夹具验证 Router 与上游标识分离，不导入 CLIProxyAPI 运行时代码。
package chat

import (
	"errors"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestStreamDecoderRecordsOneStableUpstreamResponseID verifies the decoder exposes one provider response identity and rejects contradictory chunks.
// TestStreamDecoderRecordsOneStableUpstreamResponseID 验证解码器公开一个 Provider 响应身份并拒绝相互矛盾的分片。
func TestStreamDecoderRecordsOneStableUpstreamResponseID(t *testing.T) {
	decoder, errNew := NewStreamDecoder("response-1", time.Date(2026, time.July, 17, 0, 0, 0, 0, time.UTC))
	if errNew != nil {
		t.Fatalf("NewStreamDecoder() error = %v", errNew)
	}
	if _, errPush := decoder.Push(Chunk{ID: "upstream-1"}); errPush != nil {
		t.Fatalf("Push() error = %v", errPush)
	}
	if decoder.UpstreamResponseID() != "upstream-1" {
		t.Fatalf("UpstreamResponseID() = %q", decoder.UpstreamResponseID())
	}
	if _, errPush := decoder.Push(Chunk{ID: "upstream-2"}); !errors.Is(errPush, ErrInvalidUpstreamResponse) {
		t.Fatalf("Push() error = %v, want ErrInvalidUpstreamResponse", errPush)
	}
}

// TestStreamDecoderReportsActualUsageAndWarnings verifies stream-only observations reach the client-safe execution report.
// TestStreamDecoderReportsActualUsageAndWarnings 验证仅流式观测会进入客户端安全执行报告。
func TestStreamDecoderReportsActualUsageAndWarnings(t *testing.T) {
	decoder, errNew := NewStreamDecoder("response-1", time.Date(2026, time.July, 17, 0, 0, 0, 0, time.UTC))
	if errNew != nil {
		t.Fatalf("NewStreamDecoder() error = %v", errNew)
	}
	tokens := int64(3)
	if _, errPush := decoder.Push(Chunk{Usage: &Usage{TotalTokens: &tokens}}); errPush != nil {
		t.Fatalf("Push() usage error = %v", errPush)
	}
	warning := decoder.emitter.event(vcp.EventWarningRaised)
	warning.WarningCode = "openai_chat.test_warning"
	if errEmit := decoder.emit(warning, nil); errEmit != nil {
		t.Fatalf("emit() error = %v", errEmit)
	}
	report := decoder.Report()
	if report.Usage == nil || report.Usage.TotalTokens == nil || *report.Usage.TotalTokens != 3 || len(report.ConversionSummary) != 1 || report.ConversionSummary[0] != "openai_chat.test_warning" {
		t.Fatalf("report = %#v", report)
	}
}
