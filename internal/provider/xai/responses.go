// Package xai contains provider-scoped xAI execution drivers.
// Package xai 包含供应商作用域的 xAI 执行 Driver。
//
// Portions of this driver are adapted from CLIProxyAPI internal/runtime/executor/xai_executor.go at commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// 本 Driver 的部分逻辑改编自 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66 中的 internal/runtime/executor/xai_executor.go。
// Source path: internal/runtime/executor/xai_executor.go.
// 来源路径：internal/runtime/executor/xai_executor.go。
// The adapted scope is provider-bound xAI Responses and compact action execution without CLIProxyAPI runtime dependencies.
// 改编范围为 Provider 绑定 xAI Responses 和 compact 动作执行，不引入 CLIProxyAPI 运行时依赖。
package xai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	xairesponses "github.com/OpenVulcan/vulcan-model-core/internal/protocol/xai/responses"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

var (
	// ErrInvalidResponsesDriver reports an unconfigured xAI Responses execution driver.
	// ErrInvalidResponsesDriver 表示未配置的 xAI Responses 执行 Driver。
	ErrInvalidResponsesDriver = errors.New("invalid xAI Responses execution driver")
)

// ResponsesDriver executes the one registered xAI Responses profile for one immutable provider definition.
// ResponsesDriver 为一个不可变 Provider Definition 执行唯一已注册的 xAI Responses Profile。
type ResponsesDriver struct {
	// definitionID is the sole provider definition permitted to use this driver.
	// definitionID 是允许使用此 Driver 的唯一 Provider Definition。
	definitionID string
	// client owns provider-scoped HTTP and SSE execution.
	// client 负责供应商作用域的 HTTP 与 SSE 执行。
	client *transport.Client
	// capabilities records the verified target behavior selected for this driver instance.
	// capabilities 记录为此 Driver 实例选定的已验证 Target 行为。
	capabilities xairesponses.ProfileCapabilities
}

// NewResponsesDriver creates a driver permanently bound to one provider definition and transport client.
// NewResponsesDriver 创建一个永久绑定到一个 Provider Definition 与传输客户端的 Driver。
func NewResponsesDriver(definitionID string, client *transport.Client, capabilities xairesponses.ProfileCapabilities) (*ResponsesDriver, error) {
	if strings.TrimSpace(definitionID) == "" || client == nil {
		return nil, ErrInvalidResponsesDriver
	}
	return &ResponsesDriver{definitionID: definitionID, client: client, capabilities: capabilities}, nil
}

// ProviderDefinitionID returns the exact definition that owns this xAI Responses driver.
// ProviderDefinitionID 返回拥有此 xAI Responses Driver 的精确 Definition。
func (d *ResponsesDriver) ProviderDefinitionID() string {
	if d == nil {
		return ""
	}
	return d.definitionID
}

// ProtocolProfileID returns the one xAI Responses protocol profile implemented by this driver.
// ProtocolProfileID 返回此 Driver 实现的唯一 xAI Responses 协议 Profile。
func (d *ResponsesDriver) ProtocolProfileID() string {
	return xairesponses.ProfileID
}

// Execute projects and sends one xAI request only to the immutable selected target, including the target-owned compact endpoint when requested.
// Execute 仅向不可变选定 Target 投影并发送一条 xAI 请求，包含请求时 Target 所有的 compact Endpoint。
func (d *ResponsesDriver) Execute(ctx context.Context, execution provider.ExecutionRequest) (provider.ExecutionResult, error) {
	if d == nil || d.client == nil {
		return provider.ExecutionResult{}, ErrInvalidResponsesDriver
	}
	if execution.Binding.Target.ProviderDefinitionID != d.definitionID {
		return provider.ExecutionResult{}, fmt.Errorf("%w: target definition does not belong to this driver", provider.ErrExecutionBinding)
	}
	if _, errValidate := execution.ValidateForProfile(xairesponses.ProfileID, providerconfig.AuthMethodAPIKey); errValidate != nil {
		return provider.ExecutionResult{}, errValidate
	}
	previousResponseID := ""
	if execution.Continuation != nil {
		previousResponseID = execution.Continuation.UpstreamResponseID
	}
	if execution.Request.RemoteCompaction != nil {
		projected, errProject := xairesponses.ProjectCompactRequest(execution.Request, execution.Binding.Target, d.capabilities, execution.LineageID, previousResponseID, execution.Now)
		if errProject != nil {
			return provider.ExecutionResult{}, errProject
		}
		return d.executeResponse(ctx, "/responses/compact", projected, execution.Now, execution)
	}
	projected, errProject := xairesponses.ProjectRequest(execution.Request, execution.Binding.Target, d.capabilities, execution.LineageID, previousResponseID, execution.Now)
	if errProject != nil {
		return provider.ExecutionResult{}, errProject
	}
	if projected.Upstream.Stream {
		return d.executeStream(ctx, "/responses", projected, execution.Now, execution)
	}
	return d.executeResponse(ctx, "/responses", projected, execution.Now, execution)
}

// executeResponse executes one typed non-streaming xAI endpoint and rejects trailing untyped JSON values.
// executeResponse 执行一个类型化非流式 xAI Endpoint 并拒绝尾随的未类型化 JSON 值。
func (d *ResponsesDriver) executeResponse(ctx context.Context, path string, projected xairesponses.ProjectedRequest, now time.Time, execution provider.ExecutionRequest) (provider.ExecutionResult, error) {
	outbound, errRequest := xaiTransportRequest(path, projected.Upstream, execution)
	if errRequest != nil {
		return provider.ExecutionResult{}, errRequest
	}
	upstreamResponse, errDo := d.client.Do(ctx, outbound)
	if errDo != nil {
		return provider.ExecutionResult{}, errDo
	}
	defer func() {
		_ = transport.DrainAndClose(upstreamResponse)
	}()
	var upstream xairesponses.Response
	decoder := json.NewDecoder(upstreamResponse.Body)
	if errDecode := decoder.Decode(&upstream); errDecode != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: decode response: %v", xairesponses.ErrInvalidUpstreamResponse, errDecode)
	}
	var trailing json.RawMessage
	if errTrailing := decoder.Decode(&trailing); !errors.Is(errTrailing, io.EOF) {
		if errTrailing == nil {
			return provider.ExecutionResult{}, fmt.Errorf("%w: response contains trailing JSON value", xairesponses.ErrInvalidUpstreamResponse)
		}
		return provider.ExecutionResult{}, fmt.Errorf("%w: decode trailing response data: %v", xairesponses.ErrInvalidUpstreamResponse, errTrailing)
	}
	response, events, decodedReport, errDecode := xairesponses.DecodeResponse(projected.Report.ResponseID, upstream, now, projected.StreamOptions)
	if errDecode != nil {
		return provider.ExecutionResult{}, errDecode
	}
	return provider.ExecutionResult{Response: response, Events: events, Report: mergeReports(projected.Report, decodedReport), UpstreamResponseID: upstream.ID}, nil
}

// executeStream executes one typed xAI SSE endpoint and yields xAI-normalized VCP replay events.
// executeStream 执行一个类型化 xAI SSE Endpoint 并产生 xAI 归一化 VCP 回放事件。
func (d *ResponsesDriver) executeStream(ctx context.Context, path string, projected xairesponses.ProjectedRequest, now time.Time, execution provider.ExecutionRequest) (provider.ExecutionResult, error) {
	outbound, errRequest := xaiTransportRequest(path, projected.Upstream, execution)
	if errRequest != nil {
		return provider.ExecutionResult{}, errRequest
	}
	upstreamResponse, errDo := d.client.DoStream(ctx, outbound)
	if errDo != nil {
		return provider.ExecutionResult{}, errDo
	}
	defer func() {
		_ = transport.DrainAndClose(upstreamResponse)
	}()
	decoder, errNew := xairesponses.NewStreamDecoder(projected.Report.ResponseID, now, projected.StreamOptions)
	if errNew != nil {
		return provider.ExecutionResult{}, errNew
	}
	errRead := xairesponses.ReadSSE(upstreamResponse.Body, func(envelope xairesponses.SSEEnvelope) error {
		_, errPush := decoder.PushSSE(envelope)
		return errPush
	})
	if errRead != nil {
		_, _ = decoder.Close(errRead)
		return provider.ExecutionResult{}, errRead
	}
	if _, errClose := decoder.Close(nil); errClose != nil {
		return provider.ExecutionResult{}, errClose
	}
	return provider.ExecutionResult{Response: decoder.Response(), Events: decoder.Events(), Report: mergeReports(projected.Report, decoder.Report()), UpstreamResponseID: decoder.UpstreamResponseID()}, nil
}

// xaiTransportRequest encodes one projected xAI request at the target-bound transport boundary.
// xaiTransportRequest 在 Target 绑定传输边界编码一条已投影 xAI 请求。
func xaiTransportRequest(path string, upstream xairesponses.Request, execution provider.ExecutionRequest) (transport.Request, error) {
	encoded, errMarshal := json.Marshal(upstream)
	if errMarshal != nil {
		return transport.Request{}, fmt.Errorf("%w: encode request: %v", ErrInvalidResponsesDriver, errMarshal)
	}
	return transport.Request{
		Binding: execution.Binding, Method: http.MethodPost, Path: path, Body: encoded,
		Headers:        []transport.Header{{Name: "Content-Type", Value: "application/json"}},
		Authentication: transport.Authentication{Mode: transport.AuthenticationBearer},
		Stream:         upstream.Stream, IdempotencyKey: execution.Request.IdempotencyKey,
	}, nil
}

// mergeReports combines xAI projection-owned route facts with decoder-owned provider observations without inferring unknown values.
// mergeReports 组合 xAI 投影拥有的路由事实与解码器拥有的 Provider 观测，且不推断未知值。
func mergeReports(projected vcp.ExecutionReport, decoded vcp.ExecutionReport) vcp.ExecutionReport {
	merged := projected
	if decoded.Usage != nil {
		usage := *decoded.Usage
		merged.Usage = &usage
	}
	if decoded.ErrorOrRetryAdvice != "" {
		merged.ErrorOrRetryAdvice = decoded.ErrorOrRetryAdvice
	}
	for _, code := range decoded.ConversionSummary {
		if !containsConversionCode(merged.ConversionSummary, code) {
			merged.ConversionSummary = append(merged.ConversionSummary, code)
		}
	}
	return merged
}

// containsConversionCode reports whether a stable conversion code has already been recorded.
// containsConversionCode 报告是否已经记录了一个稳定转换代码。
func containsConversionCode(codes []string, target string) bool {
	for _, code := range codes {
		if code == target {
			return true
		}
	}
	return false
}
