package translatedresponses

import (
	"errors"
	"strings"
	"testing"

	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
)

// TestReadUpstreamStreamRejectsOversizedAggregateFrame verifies valid individual lines cannot bypass the complete-frame budget.
// TestReadUpstreamStreamRejectsOversizedAggregateFrame 验证单独有效的行不能绕过完整帧预算。
func TestReadUpstreamStreamRejectsOversizedAggregateFrame(t *testing.T) {
	stream := strings.NewReader("data: 12345678\ndata: 12345678\n\n")
	errRead := readUpstreamStreamBounded(stream, StreamInputFrame, 24, func([]byte) error { return nil })
	if !errors.Is(errRead, transport.ErrResponseTooLarge) {
		t.Fatalf("readUpstreamStreamBounded() error = %v, want ErrResponseTooLarge", errRead)
	}
}
