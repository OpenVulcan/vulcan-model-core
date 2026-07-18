// Package translatedresponses executes protocols translated from the typed OpenAI Responses projection.
// Package translatedresponses 执行由类型化 OpenAI Responses 投影转换而来的协议。
package translatedresponses

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	openairesponses "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/responses"
	protocolbridge "github.com/OpenVulcan/vulcan-model-core/internal/protocol/translatedresponses"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

const (
	// maximumUpstreamStreamLineBytes matches the copied CLIProxyAPI executor scanner limit.
	// maximumUpstreamStreamLineBytes 与复制的 CLIProxyAPI 执行器扫描限制一致。
	maximumUpstreamStreamLineBytes = 52_428_800
)

var (
	// ErrInvalidDriver reports an incomplete translated provider driver configuration.
	// ErrInvalidDriver 表示转换供应商驱动配置不完整。
	ErrInvalidDriver = errors.New("invalid translated Responses provider driver")
)

// StreamInputMode identifies the exact unit passed from an upstream SSE stream to the copied translator.
// StreamInputMode 标识从上游 SSE 流传递给复制转换器的精确单元。
type StreamInputMode string

const (
	// StreamInputLine passes each scanner line exactly as used by Claude and Codex executors.
	// StreamInputLine 按 Claude 和 Codex 执行器的方式逐行传递扫描结果。
	StreamInputLine StreamInputMode = "line"
	// StreamInputFrame passes complete blank-line-delimited SSE frames.
	// StreamInputFrame 传递由空行分隔的完整 SSE 帧。
	StreamInputFrame StreamInputMode = "frame"
	// StreamInputPayload extracts and joins data fields before invoking the copied translator.
	// StreamInputPayload 在调用复制转换器前提取并连接 data 字段。
	StreamInputPayload StreamInputMode = "payload"
)

// BodyAdapter applies provider-specific envelope fields after copied protocol translation.
// BodyAdapter 在复制协议转换后应用供应商特定信封字段。
type BodyAdapter func(execution provider.ExecutionRequest, projected protocolbridge.ProjectedRequest) ([]byte, error)

// RequestAdapter applies provider-specific non-secret headers after the typed transport request is constructed.
// RequestAdapter 在类型化传输请求构造后应用供应商特定非秘密 Header。
type RequestAdapter func(execution provider.ExecutionRequest, outbound transport.Request) (transport.Request, error)

// Configuration fixes every provider-specific wire decision used by a translated driver.
// Configuration 固定转换驱动使用的每项供应商特定 wire 决策。
type Configuration struct {
	// DefinitionID is the immutable provider definition owned by this driver.
	// DefinitionID 是此驱动拥有的不可变供应商定义。
	DefinitionID string
	// Profile selects the copied protocol translation and stable profile identifier.
	// Profile 选择复制协议转换和稳定 Profile 标识。
	Profile protocolbridge.Profile
	// Client executes requests within the selected endpoint and credential binding.
	// Client 在选定 Endpoint 与 Credential 绑定内执行请求。
	Client *transport.Client
	// Capabilities freezes verified typed Responses projection behavior.
	// Capabilities 固定经过验证的类型化 Responses 投影行为。
	Capabilities openairesponses.ProfileCapabilities
	// Path is the relative non-stream endpoint path.
	// Path 是非流式相对端点路径。
	Path string
	// StreamPath is the relative streaming endpoint path.
	// StreamPath 是流式相对端点路径。
	StreamPath string
	// Headers contains immutable non-secret protocol headers.
	// Headers 包含不可变非秘密协议 Header。
	Headers []transport.Header
	// Authentication defines exact secret injection behavior.
	// Authentication 定义精确的 Secret 注入行为。
	Authentication transport.Authentication
	// AllowedAuthMethods lists the exact credential metadata accepted by execution validation.
	// AllowedAuthMethods 列出执行校验接受的精确凭据元数据。
	AllowedAuthMethods []providerconfig.AuthMethodType
	// StreamInputMode selects copied executor-compatible upstream stream framing.
	// StreamInputMode 选择与复制执行器兼容的上游流分帧方式。
	StreamInputMode StreamInputMode
	// SendDonePayload reports whether the copied translator requires a terminal [DONE] payload.
	// SendDonePayload 表示复制转换器是否需要终止 `[DONE]` 载荷。
	SendDonePayload bool
	// ForceUpstreamStream preserves providers such as Codex that always return Responses SSE.
	// ForceUpstreamStream 保留 Codex 等始终返回 Responses SSE 的供应商行为。
	ForceUpstreamStream bool
	// ForceTranslationStream preserves copied translators that aggregate an upstream SSE response for non-stream callers.
	// ForceTranslationStream 保留为非流式调用方聚合上游 SSE 响应的复制转换器行为。
	ForceTranslationStream bool
	// AdaptBody optionally applies a provider envelope without modifying copied translation logic.
	// AdaptBody 可选地应用供应商信封且不修改复制转换逻辑。
	AdaptBody BodyAdapter
	// AdaptRequest optionally applies provider-specific request metadata without accessing the resolved secret.
	// AdaptRequest 可选地应用供应商特定请求元数据且不访问已解析 Secret。
	AdaptRequest RequestAdapter
}

// Driver executes one immutable provider definition through copied protocol translation.
// Driver 通过复制协议转换执行一个不可变供应商定义。
type Driver struct {
	// configuration contains all immutable provider-specific execution decisions.
	// configuration 包含全部不可变供应商特定执行决策。
	configuration Configuration
}

// NewDriver validates and constructs one translated provider driver.
// NewDriver 校验并构造一个转换供应商驱动。
func NewDriver(configuration Configuration) (*Driver, error) {
	if strings.TrimSpace(configuration.DefinitionID) == "" || configuration.Client == nil || strings.TrimSpace(configuration.Path) == "" || strings.TrimSpace(configuration.StreamPath) == "" {
		return nil, fmt.Errorf("%w: definition, client, and endpoint paths are required", ErrInvalidDriver)
	}
	if errProfile := configuration.Profile.Validate(); errProfile != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidDriver, errProfile)
	}
	if len(configuration.AllowedAuthMethods) == 0 {
		return nil, fmt.Errorf("%w: at least one auth method is required", ErrInvalidDriver)
	}
	switch configuration.StreamInputMode {
	case StreamInputLine, StreamInputFrame, StreamInputPayload:
	default:
		return nil, fmt.Errorf("%w: unsupported stream input mode %q", ErrInvalidDriver, configuration.StreamInputMode)
	}
	return &Driver{configuration: configuration}, nil
}

// ProviderDefinitionID returns the immutable provider definition owned by this driver.
// ProviderDefinitionID 返回此驱动拥有的不可变供应商定义。
func (d *Driver) ProviderDefinitionID() string {
	if d == nil {
		return ""
	}
	return d.configuration.DefinitionID
}

// ProtocolProfileID returns the exact translated protocol profile handled by this driver.
// ProtocolProfileID 返回此驱动处理的精确转换协议 Profile。
func (d *Driver) ProtocolProfileID() string {
	if d == nil {
		return ""
	}
	return d.configuration.Profile.ID
}

// Execute projects one VCP request, applies copied translation, and decodes the same provider response.
// Execute 投影一条 VCP 请求、应用复制转换并解码同一供应商响应。
func (d *Driver) Execute(ctx context.Context, execution provider.ExecutionRequest) (provider.ExecutionResult, error) {
	if d == nil || d.configuration.Client == nil {
		return provider.ExecutionResult{}, ErrInvalidDriver
	}
	if execution.Binding.Target.ProviderDefinitionID != d.configuration.DefinitionID {
		return provider.ExecutionResult{}, fmt.Errorf("%w: target definition does not belong to this driver", provider.ErrExecutionBinding)
	}
	if _, errValidate := execution.ValidateForProfile(d.configuration.Profile.ID, d.configuration.AllowedAuthMethods...); errValidate != nil {
		return provider.ExecutionResult{}, errValidate
	}
	previousResponseID := ""
	if execution.Continuation != nil {
		previousResponseID = execution.Continuation.UpstreamResponseID
	}
	translationStream := execution.Request.Stream || d.configuration.ForceTranslationStream
	projected, errProject := protocolbridge.ProjectRequest(d.configuration.Profile, execution.Request, execution.Binding.Target, d.configuration.Capabilities, execution.LineageID, previousResponseID, translationStream, execution.Now)
	if errProject != nil {
		return provider.ExecutionResult{}, errProject
	}
	body := projected.UpstreamJSON
	if d.configuration.AdaptBody != nil {
		adaptedBody, errAdapt := d.configuration.AdaptBody(execution, projected)
		if errAdapt != nil {
			return provider.ExecutionResult{}, errAdapt
		}
		body = adaptedBody
		projected.UpstreamJSON = append([]byte(nil), adaptedBody...)
	}
	upstreamStream := projected.Base.Upstream.Stream || d.configuration.ForceUpstreamStream
	path := d.configuration.Path
	if upstreamStream {
		path = d.configuration.StreamPath
	}
	outbound := transport.Request{
		Binding: execution.Binding, Method: http.MethodPost, Path: path, Body: body,
		Headers: append([]transport.Header(nil), d.configuration.Headers...), Authentication: d.configuration.Authentication,
		Stream: upstreamStream, IdempotencyKey: execution.Request.IdempotencyKey,
	}
	if d.configuration.AdaptRequest != nil {
		adaptedRequest, errAdaptRequest := d.configuration.AdaptRequest(execution, outbound)
		if errAdaptRequest != nil {
			return provider.ExecutionResult{}, errAdaptRequest
		}
		outbound = adaptedRequest
	}
	if upstreamStream {
		return d.executeStream(ctx, execution, outbound, projected)
	}
	return d.executeResponse(ctx, execution, outbound, projected)
}

// executeResponse executes and translates one complete non-stream response.
// executeResponse 执行并转换一个完整非流式响应。
func (d *Driver) executeResponse(ctx context.Context, execution provider.ExecutionRequest, outbound transport.Request, projected protocolbridge.ProjectedRequest) (provider.ExecutionResult, error) {
	upstreamResponse, errRequest := d.configuration.Client.Do(ctx, outbound)
	if errRequest != nil {
		return provider.ExecutionResult{}, errRequest
	}
	defer func() {
		_ = transport.DrainAndClose(upstreamResponse)
	}()
	rawResponse, errRead := io.ReadAll(upstreamResponse.Body)
	if errRead != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: read upstream response: %v", ErrInvalidDriver, errRead)
	}
	decoded, errDecode := protocolbridge.DecodeNonStream(ctx, d.configuration.Profile, projected, rawResponse, projected.Base.Report.ResponseID, execution.Binding.Target.UpstreamModelID, execution.Now)
	if errDecode != nil {
		return provider.ExecutionResult{}, errDecode
	}
	return provider.ExecutionResult{Response: decoded.Response, Events: decoded.Events, Report: mergeReports(projected.Base.Report, decoded.Report), UpstreamResponseID: decoded.UpstreamResponseID}, nil
}

// executeStream executes, frames, translates, and decodes one provider SSE response.
// executeStream 执行、分帧、转换并解码一个供应商 SSE 响应。
func (d *Driver) executeStream(ctx context.Context, execution provider.ExecutionRequest, outbound transport.Request, projected protocolbridge.ProjectedRequest) (provider.ExecutionResult, error) {
	upstreamResponse, errRequest := d.configuration.Client.DoStream(ctx, outbound)
	if errRequest != nil {
		return provider.ExecutionResult{}, errRequest
	}
	defer func() {
		_ = transport.DrainAndClose(upstreamResponse)
	}()
	translator, errTranslator := protocolbridge.NewStreamTranslator(d.configuration.Profile, execution.Binding.Target.UpstreamModelID, projected)
	if errTranslator != nil {
		return provider.ExecutionResult{}, errTranslator
	}
	decoder, errDecoder := openairesponses.NewStreamDecoder(projected.Base.Report.ResponseID, execution.Now)
	if errDecoder != nil {
		return provider.ExecutionResult{}, errDecoder
	}
	consume := func(raw []byte) error {
		translatedChunks, errTranslate := translator.Translate(ctx, raw)
		if errTranslate != nil {
			return errTranslate
		}
		for _, translatedChunk := range translatedChunks {
			trimmed := bytes.TrimSpace(translatedChunk)
			if bytes.Equal(trimmed, []byte("[DONE]")) || bytes.Equal(trimmed, []byte("data: [DONE]")) {
				continue
			}
			if errRead := openairesponses.ReadSSE(bytes.NewReader(translatedChunk), func(envelope openairesponses.SSEEnvelope) error {
				_, errPush := decoder.PushSSE(envelope)
				return errPush
			}); errRead != nil {
				return errRead
			}
		}
		return nil
	}
	if errRead := readUpstreamStream(upstreamResponse.Body, d.configuration.StreamInputMode, consume); errRead != nil {
		_, _ = decoder.Close(errRead)
		return provider.ExecutionResult{}, errRead
	}
	if d.configuration.SendDonePayload {
		if errDone := consume([]byte("[DONE]")); errDone != nil {
			_, _ = decoder.Close(errDone)
			return provider.ExecutionResult{}, errDone
		}
	}
	if _, errClose := decoder.Close(nil); errClose != nil {
		return provider.ExecutionResult{}, errClose
	}
	return provider.ExecutionResult{Response: decoder.Response(), Events: decoder.Events(), Report: mergeReports(projected.Base.Report, decoder.Report()), UpstreamResponseID: decoder.UpstreamResponseID()}, nil
}

// readUpstreamStream preserves the copied executor's line, frame, or payload feeding behavior.
// readUpstreamStream 保留复制执行器逐行、逐帧或逐载荷的传递行为。
func readUpstreamStream(reader io.Reader, mode StreamInputMode, consume func([]byte) error) error {
	if reader == nil || consume == nil {
		return fmt.Errorf("%w: stream reader and consumer are required", ErrInvalidDriver)
	}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(nil, maximumUpstreamStreamLineBytes)
	if mode == StreamInputLine {
		for scanner.Scan() {
			if errConsume := consume(bytes.Clone(scanner.Bytes())); errConsume != nil {
				return errConsume
			}
		}
		return scanner.Err()
	}
	frame := make([]byte, 0)
	emitFrame := func() error {
		if len(bytes.TrimSpace(frame)) == 0 {
			frame = frame[:0]
			return nil
		}
		input := bytes.Clone(frame)
		frame = frame[:0]
		if mode == StreamInputPayload {
			input = ssePayload(input)
			if len(input) == 0 {
				return nil
			}
		}
		return consume(input)
	}
	for scanner.Scan() {
		line := scanner.Bytes()
		frame = append(frame, line...)
		frame = append(frame, '\n')
		if len(bytes.TrimSpace(line)) == 0 {
			if errEmit := emitFrame(); errEmit != nil {
				return errEmit
			}
		}
	}
	if errScan := scanner.Err(); errScan != nil {
		return errScan
	}
	return emitFrame()
}

// ssePayload extracts ordered data fields from one complete SSE frame.
// ssePayload 从一个完整 SSE 帧中提取有序 data 字段。
func ssePayload(frame []byte) []byte {
	var dataLines [][]byte
	for _, line := range bytes.Split(frame, []byte("\n")) {
		trimmed := bytes.TrimSpace(line)
		if bytes.HasPrefix(trimmed, []byte("data:")) {
			dataLines = append(dataLines, bytes.TrimSpace(trimmed[len("data:"):]))
		}
	}
	return bytes.Join(dataLines, []byte("\n"))
}

// mergeReports combines projection facts with translated provider observations without duplicating codes.
// mergeReports 组合投影事实和转换后的供应商观测且不重复转换代码。
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
		if !containsString(merged.ConversionSummary, code) {
			merged.ConversionSummary = append(merged.ConversionSummary, code)
		}
	}
	return merged
}

// containsString reports whether one exact value is already present.
// containsString 表示一个精确值是否已经存在。
func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
