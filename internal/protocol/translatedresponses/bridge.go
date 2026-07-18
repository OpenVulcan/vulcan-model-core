// Package translatedresponses adapts VCP through the copied CLIProxyAPI Responses translators.
// Package translatedresponses 通过复制的 CLIProxyAPI Responses 转换器适配 VCP。
package translatedresponses

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	openairesponses "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/responses"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	_ "github.com/OpenVulcan/vulcan-model-core/internal/thirdparty/cliproxyapi/register"
	sdktranslator "github.com/OpenVulcan/vulcan-model-core/internal/thirdparty/cliproxyapi/sdk/translator"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

var (
	// ErrInvalidProfile reports a translated protocol descriptor outside the closed migrated format set.
	// ErrInvalidProfile 表示转换协议描述符不属于封闭的迁移格式集合。
	ErrInvalidProfile = errors.New("invalid translated Responses protocol profile")
	// ErrInvalidTranslation reports malformed or unavailable copied upstream translation behavior.
	// ErrInvalidTranslation 表示复制的上游转换行为格式错误或不可用。
	ErrInvalidTranslation = errors.New("invalid CLIProxyAPI protocol translation")
)

// Profile identifies one Vulcan protocol profile and its exact copied CLIProxyAPI wire format.
// Profile 标识一个 Vulcan 协议 Profile 及其精确的 CLIProxyAPI wire 格式。
type Profile struct {
	// ID is the stable Vulcan protocol profile identifier.
	// ID 是稳定的 Vulcan 协议 Profile 标识。
	ID string
	// Format is the copied CLIProxyAPI target format.
	// Format 是复制的 CLIProxyAPI 目标格式。
	Format sdktranslator.Format
}

// Validate verifies that the descriptor selects exactly one migrated protocol implementation.
// Validate 校验描述符精确选择一个已迁移协议实现。
func (p Profile) Validate() error {
	if p.ID == "" {
		return fmt.Errorf("%w: profile id is required", ErrInvalidProfile)
	}
	switch p.Format {
	case sdktranslator.FormatClaude, sdktranslator.FormatCodex, sdktranslator.FormatInteractions, sdktranslator.FormatAntigravity:
		return nil
	default:
		return fmt.Errorf("%w: unsupported format %q", ErrInvalidProfile, p.Format)
	}
}

// ProjectedRequest preserves the typed VCP projection and both sides of the copied request translation.
// ProjectedRequest 保留类型化 VCP 投影及复制请求转换的两端载荷。
type ProjectedRequest struct {
	// Base is the typed OpenAI Responses projection used as the copied translator source schema.
	// Base 是作为复制转换器源 Schema 的类型化 OpenAI Responses 投影。
	Base openairesponses.ProjectedRequest
	// SourceJSON is the encoded typed Responses request before copied translation.
	// SourceJSON 是复制转换前编码的类型化 Responses 请求。
	SourceJSON []byte
	// UpstreamJSON is the exact copied translator output sent to the selected provider.
	// UpstreamJSON 是发送给选定供应商的精确复制转换器输出。
	UpstreamJSON []byte
}

// ProjectRequest projects VCP to typed Responses and then invokes the copied upstream request transformer unchanged.
// ProjectRequest 将 VCP 投影为类型化 Responses，随后原样调用复制的上游请求转换器。
func ProjectRequest(profile Profile, request vcp.VulcanRequest, target resolve.Target, capabilities openairesponses.ProfileCapabilities, lineageID string, previousResponseID string, translationStream bool, now time.Time) (ProjectedRequest, error) {
	if errProfile := profile.Validate(); errProfile != nil {
		return ProjectedRequest{}, errProfile
	}
	if !sdktranslator.HasRequestTransformer(sdktranslator.FormatOpenAIResponse, profile.Format) {
		return ProjectedRequest{}, fmt.Errorf("%w: request transformer %q -> %q is not registered", ErrInvalidTranslation, sdktranslator.FormatOpenAIResponse, profile.Format)
	}
	base, errProject := openairesponses.ProjectRequest(request, target, capabilities, lineageID, previousResponseID, now)
	if errProject != nil {
		return ProjectedRequest{}, errProject
	}
	sourceJSON, errMarshal := json.Marshal(base.Upstream)
	if errMarshal != nil {
		return ProjectedRequest{}, fmt.Errorf("%w: encode typed Responses source: %v", ErrInvalidTranslation, errMarshal)
	}
	upstreamJSON := sdktranslator.TranslateRequest(sdktranslator.FormatOpenAIResponse, profile.Format, target.UpstreamModelID, sourceJSON, translationStream)
	if !json.Valid(upstreamJSON) {
		return ProjectedRequest{}, fmt.Errorf("%w: copied request transformer returned invalid JSON", ErrInvalidTranslation)
	}
	return ProjectedRequest{Base: base, SourceJSON: sourceJSON, UpstreamJSON: upstreamJSON}, nil
}

// DecodedResponse contains the VCP terminal state produced after copied response translation.
// DecodedResponse 包含复制响应转换后生成的 VCP 终态。
type DecodedResponse struct {
	// Response is the canonical terminal response.
	// Response 是规范终态响应。
	Response vcp.Response
	// Events is the canonical replay event sequence.
	// Events 是规范回放事件序列。
	Events []vcp.Event
	// Report contains provider observations decoded from the translated Responses payload.
	// Report 包含从转换后 Responses 载荷解码的供应商观测。
	Report vcp.ExecutionReport
	// UpstreamResponseID is the translated provider response identifier.
	// UpstreamResponseID 是转换后的供应商响应标识。
	UpstreamResponseID string
}

// DecodeNonStream invokes the copied upstream response transformer before the existing typed Responses decoder.
// DecodeNonStream 在现有类型化 Responses 解码器之前调用复制的上游响应转换器。
func DecodeNonStream(ctx context.Context, profile Profile, projected ProjectedRequest, rawResponse []byte, responseID string, model string, now time.Time) (DecodedResponse, error) {
	if errProfile := profile.Validate(); errProfile != nil {
		return DecodedResponse{}, errProfile
	}
	if !sdktranslator.HasNonStreamResponseTransformer(sdktranslator.FormatOpenAIResponse, profile.Format) {
		return DecodedResponse{}, fmt.Errorf("%w: non-stream response transformer %q -> %q is not registered", ErrInvalidTranslation, profile.Format, sdktranslator.FormatOpenAIResponse)
	}
	var state any
	translated := sdktranslator.TranslateNonStream(ctx, profile.Format, sdktranslator.FormatOpenAIResponse, model, projected.SourceJSON, projected.UpstreamJSON, rawResponse, &state)
	if !json.Valid(translated) {
		return DecodedResponse{}, fmt.Errorf("%w: copied non-stream response transformer returned invalid JSON", ErrInvalidTranslation)
	}
	var upstream openairesponses.Response
	if errUnmarshal := json.Unmarshal(translated, &upstream); errUnmarshal != nil {
		return DecodedResponse{}, fmt.Errorf("%w: decode translated Responses payload: %v", ErrInvalidTranslation, errUnmarshal)
	}
	response, events, report, errDecode := openairesponses.DecodeResponse(responseID, upstream, now)
	if errDecode != nil {
		return DecodedResponse{}, errDecode
	}
	return DecodedResponse{Response: response, Events: events, Report: report, UpstreamResponseID: upstream.ID}, nil
}

// StreamTranslator owns the exact copied state parameter for one immutable upstream stream.
// StreamTranslator 管理一个不可变上游流对应的精确复制状态参数。
type StreamTranslator struct {
	// mutex serializes access to the copied translator's mutable stream state.
	// mutex 串行化对复制转换器可变流状态的访问。
	mutex sync.Mutex
	// profile fixes the upstream format for the lifetime of this stream.
	// profile 在流的整个生命周期内固定上游格式。
	profile Profile
	// model fixes the exact resolved upstream model name.
	// model 固定精确解析的上游模型名称。
	model string
	// sourceJSON preserves the pre-translation typed request.
	// sourceJSON 保留转换前的类型化请求。
	sourceJSON []byte
	// upstreamJSON preserves the actual translated wire request.
	// upstreamJSON 保留实际转换后的 wire 请求。
	upstreamJSON []byte
	// state is owned and interpreted exclusively by the copied translator.
	// state 仅由复制的转换器拥有并解释。
	state any
}

// NewStreamTranslator constructs one request-scoped copied stream translator.
// NewStreamTranslator 构造一个请求作用域的复制流转换器。
func NewStreamTranslator(profile Profile, model string, projected ProjectedRequest) (*StreamTranslator, error) {
	if errProfile := profile.Validate(); errProfile != nil {
		return nil, errProfile
	}
	if !sdktranslator.HasStreamResponseTransformer(sdktranslator.FormatOpenAIResponse, profile.Format) {
		return nil, fmt.Errorf("%w: stream response transformer %q -> %q is not registered", ErrInvalidTranslation, profile.Format, sdktranslator.FormatOpenAIResponse)
	}
	return &StreamTranslator{profile: profile, model: model, sourceJSON: append([]byte(nil), projected.SourceJSON...), upstreamJSON: append([]byte(nil), projected.UpstreamJSON...)}, nil
}

// Translate applies the copied stateful stream transformer to exactly one upstream line or payload.
// Translate 将复制的有状态流转换器应用于恰好一条上游行或载荷。
func (t *StreamTranslator) Translate(ctx context.Context, raw []byte) ([][]byte, error) {
	if t == nil {
		return nil, fmt.Errorf("%w: stream translator is nil", ErrInvalidTranslation)
	}
	t.mutex.Lock()
	defer t.mutex.Unlock()
	outputs := sdktranslator.TranslateStream(ctx, t.profile.Format, sdktranslator.FormatOpenAIResponse, t.model, t.sourceJSON, t.upstreamJSON, raw, &t.state)
	// filtered preserves upstream suppression semantics while removing empty scanner delimiters.
	// filtered 保留上游抑制语义，同时移除空扫描分隔项。
	filtered := make([][]byte, 0, len(outputs))
	for _, output := range outputs {
		if len(output) != 0 {
			filtered = append(filtered, output)
		}
	}
	return filtered, nil
}
