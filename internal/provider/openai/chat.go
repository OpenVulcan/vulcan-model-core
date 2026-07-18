// Portions of this driver are adapted from CLIProxyAPI internal/runtime/executor/openai_compat_executor.go at commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// 本 Driver 的部分逻辑改编自 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66 中的 internal/runtime/executor/openai_compat_executor.go。
// Source path: internal/runtime/executor/openai_compat_executor.go.
// 来源路径：internal/runtime/executor/openai_compat_executor.go。
// The adapted scope is target-bound OpenAI-compatible Chat HTTP/SSE execution without CLIProxyAPI configuration, logs, or runtime dependencies.
// 改编范围为 Target 绑定的 OpenAI 兼容 Chat HTTP/SSE 执行，不引入 CLIProxyAPI 配置、日志或运行时依赖。
package openai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	chatprofile "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/chat"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
)

var (
	// ErrInvalidChatDriver reports an unconfigured OpenAI Chat execution driver.
	// ErrInvalidChatDriver 表示未配置的 OpenAI Chat 执行 Driver。
	ErrInvalidChatDriver = errors.New("invalid OpenAI Chat execution driver")
)

// ChatDriver executes one explicitly registered OpenAI Chat protocol profile for one immutable provider definition.
// ChatDriver 为一个不可变 Provider Definition 执行一个显式注册的 OpenAI Chat 协议 Profile。
type ChatDriver struct {
	// definitionID is the sole provider definition permitted to use this driver.
	// definitionID 是允许使用此 Driver 的唯一 Provider Definition。
	definitionID string
	// profileID is the exact configured Chat protocol profile owned by this driver.
	// profileID 是由此 Driver 拥有的精确已配置 Chat 协议 Profile。
	profileID string
	// client owns provider-scoped HTTP and SSE execution.
	// client 负责供应商作用域的 HTTP 与 SSE 执行。
	client *transport.Client
	// capabilities records the verified protocol behavior selected for this driver instance.
	// capabilities 记录为此 Driver 实例选定的已验证协议行为。
	capabilities chatprofile.ProfileCapabilities
}

// NewChatDriver creates a driver permanently bound to one provider definition, registered Chat profile, and transport client.
// NewChatDriver 创建一个永久绑定到一个 Provider Definition、已注册 Chat Profile 与传输客户端的 Driver。
func NewChatDriver(definitionID string, profileID string, client *transport.Client, capabilities chatprofile.ProfileCapabilities) (*ChatDriver, error) {
	if strings.TrimSpace(definitionID) == "" || strings.TrimSpace(profileID) == "" || client == nil {
		return nil, ErrInvalidChatDriver
	}
	return &ChatDriver{definitionID: definitionID, profileID: profileID, client: client, capabilities: capabilities}, nil
}

// ProviderDefinitionID returns the exact definition that owns this Chat driver.
// ProviderDefinitionID 返回拥有此 Chat Driver 的精确 Definition。
func (d *ChatDriver) ProviderDefinitionID() string {
	if d == nil {
		return ""
	}
	return d.definitionID
}

// ProtocolProfileID returns the one explicitly registered Chat protocol profile implemented by this driver.
// ProtocolProfileID 返回此 Driver 实现的唯一显式注册 Chat 协议 Profile。
func (d *ChatDriver) ProtocolProfileID() string {
	if d == nil {
		return ""
	}
	return d.profileID
}

// Execute projects one VCP request, sends it only to the immutable target, and decodes exactly that OpenAI Chat response.
// Execute 投影一条 VCP 请求，仅将其发送到不可变 Target，并解码该 OpenAI Chat 的精确响应。
func (d *ChatDriver) Execute(ctx context.Context, execution provider.ExecutionRequest) (provider.ExecutionResult, error) {
	if d == nil || d.client == nil {
		return provider.ExecutionResult{}, ErrInvalidChatDriver
	}
	if execution.Binding.Target.ProviderDefinitionID != d.definitionID {
		return provider.ExecutionResult{}, fmt.Errorf("%w: target definition does not belong to this driver", provider.ErrExecutionBinding)
	}
	if _, errValidate := execution.ValidateForProfile(d.profileID, providerconfig.AuthMethodAPIKey); errValidate != nil {
		return provider.ExecutionResult{}, errValidate
	}
	projected, errProject := chatprofile.ProjectRequest(execution.Request, execution.Binding.Target, d.capabilities, execution.LineageID, execution.Now)
	if errProject != nil {
		return provider.ExecutionResult{}, errProject
	}
	encodedRequest, errMarshal := json.Marshal(projected.Upstream)
	if errMarshal != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: encode request: %v", ErrInvalidChatDriver, errMarshal)
	}
	outbound := transport.Request{
		Binding: execution.Binding, Method: http.MethodPost, Path: "/v1/chat/completions", Body: encodedRequest,
		Headers:        []transport.Header{{Name: "Content-Type", Value: "application/json"}},
		Authentication: transport.Authentication{Mode: transport.AuthenticationBearer},
		Stream:         projected.Upstream.Stream, IdempotencyKey: execution.Request.IdempotencyKey,
	}
	if projected.Upstream.Stream {
		return d.executeStream(ctx, outbound, projected, execution.Now)
	}
	return d.executeResponse(ctx, outbound, projected, execution.Now)
}

// executeResponse executes one non-streaming Chat request and rejects trailing untyped JSON values.
// executeResponse 执行一条非流式 Chat 请求并拒绝尾随的未类型化 JSON 值。
func (d *ChatDriver) executeResponse(ctx context.Context, outbound transport.Request, projected chatprofile.ProjectedRequest, now time.Time) (provider.ExecutionResult, error) {
	upstreamResponse, errRequest := d.client.Do(ctx, outbound)
	if errRequest != nil {
		return provider.ExecutionResult{}, errRequest
	}
	defer func() {
		_ = transport.DrainAndClose(upstreamResponse)
	}()
	var upstream chatprofile.Response
	decoder := json.NewDecoder(upstreamResponse.Body)
	if errDecode := decoder.Decode(&upstream); errDecode != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: decode response: %v", chatprofile.ErrInvalidUpstreamResponse, errDecode)
	}
	if errTrailing := rejectTrailingChatJSON(decoder); errTrailing != nil {
		return provider.ExecutionResult{}, errTrailing
	}
	response, events, decodedReport, errDecode := chatprofile.DecodeResponse(projected.Report.ResponseID, upstream, now)
	if errDecode != nil {
		return provider.ExecutionResult{}, errDecode
	}
	return provider.ExecutionResult{Response: response, Events: events, Report: mergeReports(projected.Report, decodedReport), UpstreamResponseID: upstream.ID}, nil
}

// executeStream executes one Chat SSE request and converts each syntactically complete upstream frame into VCP replay events.
// executeStream 执行一条 Chat SSE 请求，并将每个语法完整的上游帧转换为 VCP 回放事件。
func (d *ChatDriver) executeStream(ctx context.Context, outbound transport.Request, projected chatprofile.ProjectedRequest, now time.Time) (provider.ExecutionResult, error) {
	upstreamResponse, errRequest := d.client.DoStream(ctx, outbound)
	if errRequest != nil {
		return provider.ExecutionResult{}, errRequest
	}
	defer func() {
		_ = transport.DrainAndClose(upstreamResponse)
	}()
	decoder, errNew := chatprofile.NewStreamDecoder(projected.Report.ResponseID, now)
	if errNew != nil {
		return provider.ExecutionResult{}, errNew
	}
	errRead := chatprofile.ReadSSE(upstreamResponse.Body, func(envelope chatprofile.SSEEnvelope) error {
		if bytes.Equal(bytes.TrimSpace(envelope.Data), []byte("[DONE]")) {
			return nil
		}
		var chunk chatprofile.Chunk
		if errDecode := json.Unmarshal(envelope.Data, &chunk); errDecode != nil {
			return fmt.Errorf("%w: SSE JSON: %v", chatprofile.ErrInvalidUpstreamResponse, errDecode)
		}
		_, errPush := decoder.Push(chunk)
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

// rejectTrailingChatJSON rejects a second JSON value so the typed response decoder never silently accepts an ambiguous payload.
// rejectTrailingChatJSON 拒绝第二个 JSON 值，确保类型化响应解码器不会静默接受含糊载荷。
func rejectTrailingChatJSON(decoder *json.Decoder) error {
	var trailing json.RawMessage
	if errTrailing := decoder.Decode(&trailing); !errors.Is(errTrailing, io.EOF) {
		if errTrailing == nil {
			return fmt.Errorf("%w: response contains trailing JSON value", chatprofile.ErrInvalidUpstreamResponse)
		}
		return fmt.Errorf("%w: decode trailing response data: %v", chatprofile.ErrInvalidUpstreamResponse, errTrailing)
	}
	return nil
}
