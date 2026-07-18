// Portions of this response adapter are adapted from CLIProxyAPI commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// 本响应适配器的部分逻辑改编自 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66。
// Source path: internal/translator/gemini/claude/gemini_claude_response.go.
// 来源路径：internal/translator/gemini/claude/gemini_claude_response.go。
// The adapted scope is sharing one Gemini stream-state reduction path for complete and streamed responses.
// 改编范围为完整和流式响应共用一条 Gemini 流状态归并路径。
package aistudio

import (
	"fmt"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// DecodeResponse converts one complete non-stream Gemini response through the same deterministic stream reducer.
// DecodeResponse 通过相同的确定性流 reducer 转换一条完整非流 Gemini 响应。
func DecodeResponse(responseID string, upstream GenerateContentResponse, references []ToolReference, now time.Time) (vcp.Response, []vcp.Event, vcp.ExecutionReport, error) {
	decoder, errNew := NewStreamDecoder(responseID, now, references)
	if errNew != nil {
		return vcp.Response{}, nil, vcp.ExecutionReport{}, errNew
	}
	if _, errPush := decoder.Push(upstream); errPush != nil {
		return vcp.Response{}, nil, vcp.ExecutionReport{}, errPush
	}
	if _, errClose := decoder.Close(nil); errClose != nil {
		return vcp.Response{}, nil, vcp.ExecutionReport{}, errClose
	}
	response := decoder.Response()
	if response.Status == vcp.ResponseInProgress {
		return vcp.Response{}, nil, vcp.ExecutionReport{}, fmt.Errorf("%w: non-stream response has no terminal", ErrInvalidUpstreamResponse)
	}
	return response, decoder.Events(), decoder.Report(), nil
}

// CountTokensReport merges immutable projection facts with one exact countTokens observation and explicitly records unsupported detailed accounting.
// CountTokensReport 合并不可变投影事实与一条精确 countTokens 观测，并显式记录不受支持的详细计量。
func CountTokensReport(projected vcp.ExecutionReport, usage vcp.UsageObservation, upstream CountTokensResponse) vcp.ExecutionReport {
	// report starts with immutable request-projection facts and only adds data supplied by this provider response.
	// report 从不可变请求投影事实开始，并且只添加本条 Provider 响应提供的数据。
	report := projected
	// observedUsage prevents callers from mutating the report through the result's value-owned usage field.
	// observedUsage 防止调用方通过结果中按值持有的用量字段修改报告。
	observedUsage := usage
	report.Usage = &observedUsage
	if len(upstream.PromptTokensDetails) > 0 || len(upstream.CacheTokensDetails) > 0 {
		report.ConversionSummary = appendSafeSummary(report.ConversionSummary, "google_aistudio.count_tokens.modality_details.omitted")
	}
	return report
}
