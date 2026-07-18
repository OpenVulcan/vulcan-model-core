// Portions of this response adapter are adapted from CLIProxyAPI commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// 本响应适配器的部分逻辑改编自 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66。
// Source path: internal/translator/openai/openai/responses/openai_openai-responses_response.go.
// 来源路径：internal/translator/openai/openai/responses/openai_openai-responses_response.go。
// The adapted scope is terminal Responses output-state handling without CLIProxyAPI runtime dependencies.
// 改编范围为终态 Responses 输出状态处理，不引入 CLIProxyAPI 运行时依赖。
package responses

import (
	"fmt"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// DecodeResponse converts one complete terminal OpenAI Responses payload into VCP state, replay events, and a safe report.
// DecodeResponse 将一个完整终态 OpenAI Responses 载荷转换为 VCP 状态、回放事件和安全报告。
func DecodeResponse(responseID string, upstream Response, now time.Time) (vcp.Response, []vcp.Event, vcp.ExecutionReport, error) {
	if upstream.ID == "" {
		return vcp.Response{}, nil, vcp.ExecutionReport{}, fmt.Errorf("%w: upstream response id is required", ErrInvalidUpstreamResponse)
	}
	decoder, errDecoder := NewStreamDecoder(responseID, now)
	if errDecoder != nil {
		return vcp.Response{}, nil, vcp.ExecutionReport{}, errDecoder
	}
	terminalType, errTerminal := responseTerminalType(upstream.Status)
	if errTerminal != nil {
		return vcp.Response{}, nil, vcp.ExecutionReport{}, errTerminal
	}
	if errDecode := decoder.terminate(&upstream, terminalType, nil); errDecode != nil {
		return vcp.Response{}, nil, vcp.ExecutionReport{}, errDecode
	}
	return decoder.Response(), decoder.Events(), decoder.Report(), nil
}

// responseTerminalType maps the closed synchronous Responses terminal status set to VCP terminal events.
// responseTerminalType 将封闭的同步 Responses 终态集合映射为 VCP 终态事件。
func responseTerminalType(status string) (vcp.EventType, error) {
	switch status {
	case "completed":
		return vcp.EventResponseCompleted, nil
	case "incomplete":
		return vcp.EventResponseIncomplete, nil
	case "failed":
		return vcp.EventResponseFailed, nil
	case "cancelled":
		return vcp.EventResponseCancelled, nil
	default:
		return "", fmt.Errorf("%w: response status is not a supported terminal status", ErrInvalidUpstreamResponse)
	}
}
