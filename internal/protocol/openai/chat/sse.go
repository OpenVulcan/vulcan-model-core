// Portions of this SSE framing are adapted from CLIProxyAPI commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// 本 SSE 分帧的部分逻辑改编自 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66。
// Source path: sdk/api/handlers/openai/openai_handlers.go.
// 来源路径：sdk/api/handlers/openai/openai_handlers.go。
// The adapted scope is syntactic upstream SSE framing without the CLIProxyAPI public handler runtime.
// 改编范围是语法层上游 SSE 分帧，不包含 CLIProxyAPI 公共 Handler 运行时。
package chat

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

const (
	// maximumSSELineBytes bounds one upstream SSE field without retaining an unbounded payload.
	// maximumSSELineBytes 限制单个上游 SSE 字段，避免保留无界载荷。
	maximumSSELineBytes = 4 * 1024 * 1024
)

// SSEEnvelope is one complete syntactic SSE frame that remains independent of Chat JSON semantics.
// SSEEnvelope 是一条完整的语法 SSE 帧，并保持独立于 Chat JSON 语义。
type SSEEnvelope struct {
	// Event contains the optional SSE event name.
	// Event 包含可选的 SSE 事件名称。
	Event string
	// Data contains joined data fields from one complete SSE frame.
	// Data 包含一条完整 SSE 帧中连接后的 data 字段。
	Data []byte
}

// ReadSSE parses a Chat SSE byte stream into complete frames without interpreting provider JSON values.
// ReadSSE 将 Chat SSE 字节流解析为完整帧，但不解释 Provider JSON 值。
func ReadSSE(reader io.Reader, consume func(SSEEnvelope) error) error {
	if reader == nil || consume == nil {
		return fmt.Errorf("%w: SSE reader and consumer are required", ErrInvalidUpstreamResponse)
	}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), maximumSSELineBytes)
	// eventName and dataLines preserve the current frame until its required blank-line separator.
	// eventName 和 dataLines 在必需的空行分隔符出现前保存当前帧。
	eventName := ""
	dataLines := make([]string, 0)
	dispatch := func() error {
		if len(dataLines) == 0 {
			eventName = ""
			return nil
		}
		envelope := SSEEnvelope{Event: eventName, Data: []byte(strings.Join(dataLines, "\n"))}
		eventName = ""
		dataLines = dataLines[:0]
		return consume(envelope)
	}
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if errDispatch := dispatch(); errDispatch != nil {
				return errDispatch
			}
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		field, value, found := strings.Cut(line, ":")
		if !found {
			return fmt.Errorf("%w: malformed SSE field", ErrInvalidUpstreamResponse)
		}
		value = strings.TrimPrefix(value, " ")
		switch field {
		case "event":
			eventName = value
		case "data":
			dataLines = append(dataLines, value)
		}
	}
	if errScan := scanner.Err(); errScan != nil {
		return errScan
	}
	return dispatch()
}
