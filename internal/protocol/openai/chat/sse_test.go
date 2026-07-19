// SSE fixtures cover behavior adapted from CLIProxyAPI commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// SSE 夹具覆盖改编自 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66 的行为。
// Source path: sdk/api/handlers/openai/openai_handlers.go.
// 来源路径：sdk/api/handlers/openai/openai_handlers.go。
// The fixtures verify typed upstream SSE framing without importing CLIProxyAPI public handler runtime code.
// 夹具验证类型化上游 SSE 分帧，不导入 CLIProxyAPI 公共 Handler 运行时代码。
package chat

import (
	"errors"
	"strings"
	"testing"
)

// TestReadSSEPreservesEventAndMultilineData verifies Chat framing preserves one syntactic event name and joined data fields.
// TestReadSSEPreservesEventAndMultilineData 验证 Chat 分帧保留一条语法事件名称和连接后的 data 字段。
func TestReadSSEPreservesEventAndMultilineData(t *testing.T) {
	envelopes := make([]SSEEnvelope, 0)
	errRead := ReadSSE(strings.NewReader("event: chat.chunk\ndata: first\ndata: second\n\n: keepalive\n\ndata: [DONE]\n\n"), func(envelope SSEEnvelope) error {
		envelopes = append(envelopes, envelope)
		return nil
	})
	if errRead != nil {
		t.Fatalf("ReadSSE() error = %v", errRead)
	}
	if len(envelopes) != 2 || envelopes[0].Event != "chat.chunk" || string(envelopes[0].Data) != "first\nsecond" || string(envelopes[1].Data) != "[DONE]" {
		t.Fatalf("envelopes = %#v", envelopes)
	}
}

// TestReadSSERejectsOversizedMultilineFrame verifies many valid lines cannot bypass the aggregate frame limit.
// TestReadSSERejectsOversizedMultilineFrame 验证多条有效行不能绕过聚合帧上限。
func TestReadSSERejectsOversizedMultilineFrame(t *testing.T) {
	dataLine := "data: " + strings.Repeat("x", maximumSSELineBytes/2+1) + "\n"
	errRead := ReadSSE(strings.NewReader(dataLine+dataLine+"\n"), func(SSEEnvelope) error { return nil })
	if !errors.Is(errRead, ErrInvalidUpstreamResponse) {
		t.Fatalf("ReadSSE() error = %v, want ErrInvalidUpstreamResponse", errRead)
	}
}
