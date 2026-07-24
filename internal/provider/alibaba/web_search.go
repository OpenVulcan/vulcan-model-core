package alibaba

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

var (
	// ErrInvalidWebSearchDriver reports an incomplete Alibaba WebSearch MCP driver or response.
	// ErrInvalidWebSearchDriver 表示不完整的 Alibaba WebSearch MCP 驱动或响应。
	ErrInvalidWebSearchDriver = errors.New("invalid Alibaba WebSearch driver")
	// ErrUnsupportedWebSearchInput reports VCP filters that Alibaba WebSearch MCP cannot carry.
	// ErrUnsupportedWebSearchInput 表示 Alibaba WebSearch MCP 无法承载的 VCP 过滤条件。
	ErrUnsupportedWebSearchInput = errors.New("unsupported Alibaba WebSearch input")
)

const (
	// SearchWebActionBindingID identifies the Alibaba Model Studio WebSearch MCP action.
	// SearchWebActionBindingID 标识 Alibaba Model Studio WebSearch MCP 动作。
	SearchWebActionBindingID = "action_alibaba_search_web"
	// SearchWebProtocolProfileID identifies the copied Alibaba WebSearch MCP wire contract.
	// SearchWebProtocolProfileID 标识复制的 Alibaba WebSearch MCP 线协议合同。
	SearchWebProtocolProfileID = "alibaba.web_search_mcp.v1"
	// webSearchMCPPath is copied from bailian-cli's mcpWebSearchPath implementation.
	// webSearchMCPPath 从 bailian-cli 的 mcpWebSearchPath 实现复制而来。
	webSearchMCPPath = "/api/v1/mcps/WebSearch/mcp"
	// webSearchMCPProtocolVersion is the exact streamable HTTP protocol version used by bailian-cli.
	// webSearchMCPProtocolVersion 是 bailian-cli 使用的精确可流式 HTTP 协议版本。
	webSearchMCPProtocolVersion = "2025-03-26"
	// webSearchMCPToolName is the exact server tool invoked by bailian-cli.
	// webSearchMCPToolName 是 bailian-cli 调用的精确服务端工具名称。
	webSearchMCPToolName = "bailian_web_search"
)

// WebSearchActionDriver executes Alibaba Model Studio's MCP WebSearch service.
// WebSearchActionDriver 执行 Alibaba Model Studio 的 MCP WebSearch 服务。
type WebSearchActionDriver struct {
	// definitionID fixes one Alibaba Model Studio regional definition.
	// definitionID 固定一个 Alibaba Model Studio 区域定义。
	definitionID string
	// client owns target-bound authenticated transport.
	// client 管理目标绑定的认证传输。
	client *transport.Client
}

// mcpInitializeRequest is the exact JSON-RPC initialize envelope copied from bailian-cli.
// mcpInitializeRequest 是从 bailian-cli 复制的精确 JSON-RPC 初始化信封。
type mcpInitializeRequest struct {
	// JSONRPC fixes the JSON-RPC protocol version.
	// JSONRPC 固定 JSON-RPC 协议版本。
	JSONRPC string `json:"jsonrpc"`
	// ID correlates the initialization response.
	// ID 关联初始化响应。
	ID int `json:"id"`
	// Method identifies the MCP initialization method.
	// Method 标识 MCP 初始化方法。
	Method string `json:"method"`
	// Params carries the closed initialization parameters.
	// Params 携带封闭的初始化参数。
	Params mcpInitializeParams `json:"params"`
}

// mcpInitializeParams contains the protocol and client identity declared by the Router.
// mcpInitializeParams 包含 Router 声明的协议与客户端身份。
type mcpInitializeParams struct {
	// ProtocolVersion is the negotiated MCP streamable HTTP revision.
	// ProtocolVersion 是协商的 MCP 可流式 HTTP 修订版本。
	ProtocolVersion string `json:"protocolVersion"`
	// Capabilities intentionally declares no optional MCP client capabilities.
	// Capabilities 有意声明不具备可选 MCP 客户端能力。
	Capabilities mcpClientCapabilities `json:"capabilities"`
	// ClientInfo identifies this implementation without user or credential data.
	// ClientInfo 标识本实现且不包含用户或凭据数据。
	ClientInfo mcpClientInfo `json:"clientInfo"`
}

// mcpClientCapabilities is the closed empty capability object required by MCP initialize.
// mcpClientCapabilities 是 MCP 初始化要求的封闭空能力对象。
type mcpClientCapabilities struct{}

// mcpClientInfo contains the stable non-sensitive Router client identity.
// mcpClientInfo 包含稳定且不敏感的 Router 客户端身份。
type mcpClientInfo struct {
	// Name is the stable client product name.
	// Name 是稳定的客户端产品名称。
	Name string `json:"name"`
	// Version is the integration contract version, not a user-controlled value.
	// Version 是集成合同版本而非用户控制值。
	Version string `json:"version"`
}

// mcpInitializedNotification is the exact notification sent after successful initialization.
// mcpInitializedNotification 是成功初始化后发送的精确通知。
type mcpInitializedNotification struct {
	// JSONRPC fixes the JSON-RPC protocol version.
	// JSONRPC 固定 JSON-RPC 协议版本。
	JSONRPC string `json:"jsonrpc"`
	// Method identifies the initialized notification and deliberately has no request ID.
	// Method 标识 initialized 通知并有意不携带请求 ID。
	Method string `json:"method"`
}

// mcpToolCallRequest is the exact JSON-RPC tools/call envelope copied from bailian-cli.
// mcpToolCallRequest 是从 bailian-cli 复制的精确 JSON-RPC tools/call 信封。
type mcpToolCallRequest struct {
	// JSONRPC fixes the JSON-RPC protocol version.
	// JSONRPC 固定 JSON-RPC 协议版本。
	JSONRPC string `json:"jsonrpc"`
	// ID correlates the tool-call response.
	// ID 关联工具调用响应。
	ID int `json:"id"`
	// Method identifies the MCP tool-call method.
	// Method 标识 MCP 工具调用方法。
	Method string `json:"method"`
	// Params carries the closed WebSearch tool invocation.
	// Params 携带封闭的 WebSearch 工具调用。
	Params mcpToolCallParams `json:"params"`
}

// mcpToolCallParams selects one MCP tool and its strongly typed arguments.
// mcpToolCallParams 选择一个 MCP 工具及其强类型参数。
type mcpToolCallParams struct {
	// Name is the exact Alibaba WebSearch tool name.
	// Name 是精确的 Alibaba WebSearch 工具名称。
	Name string `json:"name"`
	// Arguments contains only the parameters proven by bailian-cli.
	// Arguments 仅包含 bailian-cli 已证明的参数。
	Arguments mcpWebSearchArguments `json:"arguments"`
}

// mcpWebSearchArguments contains the query and optional result count accepted by Alibaba WebSearch.
// mcpWebSearchArguments 包含 Alibaba WebSearch 接受的查询及可选结果数量。
type mcpWebSearchArguments struct {
	// Query is the exact caller search text.
	// Query 是调用方精确搜索文本。
	Query string `json:"query"`
	// Count is omitted when the caller accepts the provider default.
	// Count 在调用方接受供应商默认值时省略。
	Count *int `json:"count,omitempty"`
}

// mcpJSONRPCResponse contains one typed JSON-RPC response envelope.
// mcpJSONRPCResponse 包含一个类型化 JSON-RPC 响应信封。
type mcpJSONRPCResponse struct {
	// JSONRPC is the returned protocol version.
	// JSONRPC 是返回的协议版本。
	JSONRPC string `json:"jsonrpc"`
	// ID correlates the response with the request.
	// ID 将响应与请求关联。
	ID int `json:"id"`
	// Result retains a typed response boundary until the method-specific decoder runs.
	// Result 在方法专属解码器运行前保留类型化响应边界。
	Result json.RawMessage `json:"result"`
	// Error contains a provider JSON-RPC error without exposing untrusted details to clients.
	// Error 包含供应商 JSON-RPC 错误且不会向客户端暴露不可信详情。
	Error *mcpJSONRPCError `json:"error,omitempty"`
}

// mcpJSONRPCError contains the stable JSON-RPC error code and untrusted provider message.
// mcpJSONRPCError 包含稳定的 JSON-RPC 错误码与不可信供应商消息。
type mcpJSONRPCError struct {
	// Code is the provider JSON-RPC error code.
	// Code 是供应商 JSON-RPC 错误码。
	Code int `json:"code"`
	// Message is decoded for wire compatibility but is never returned in Router errors.
	// Message 为线协议兼容而解码，但绝不会进入 Router 错误。
	Message string `json:"message"`
}

// mcpToolResult contains the closed content result returned by tools/call.
// mcpToolResult 包含 tools/call 返回的封闭内容结果。
type mcpToolResult struct {
	// Content contains ordered MCP content items.
	// Content 包含有序 MCP 内容项。
	Content []mcpContentItem `json:"content"`
	// IsError marks an application-level tool error.
	// IsError 标记应用层工具错误。
	IsError bool `json:"isError,omitempty"`
}

// mcpContentItem contains one MCP content item shape copied from bailian-cli.
// mcpContentItem 包含从 bailian-cli 复制的一个 MCP 内容项形态。
type mcpContentItem struct {
	// Type identifies text or another MCP content kind.
	// Type 标识文本或其他 MCP 内容类型。
	Type string `json:"type"`
	// Text contains JSON-encoded WebSearch pages for text content.
	// Text 为文本内容携带 JSON 编码的 WebSearch 页面。
	Text string `json:"text,omitempty"`
	// Data is decoded for wire compatibility with non-text MCP content.
	// Data 为非文本 MCP 内容的线协议兼容而解码。
	Data string `json:"data,omitempty"`
	// MIMEType is decoded for wire compatibility with non-text MCP content.
	// MIMEType 为非文本 MCP 内容的线协议兼容而解码。
	MIMEType string `json:"mimeType,omitempty"`
}

// mcpWebSearchPages contains the structured page list encoded inside MCP text content.
// mcpWebSearchPages 包含编码在 MCP 文本内容内的结构化页面列表。
type mcpWebSearchPages struct {
	// Pages preserves the provider result order.
	// Pages 保留供应商结果顺序。
	Pages []mcpWebSearchPage `json:"pages"`
}

// mcpWebSearchPage contains one provider-returned WebSearch page.
// mcpWebSearchPage 包含一个供应商返回的 WebSearch 页面。
type mcpWebSearchPage struct {
	// Title is the provider-returned page title.
	// Title 是供应商返回的页面标题。
	Title string `json:"title,omitempty"`
	// URL is the provider-returned destination.
	// URL 是供应商返回的目标地址。
	URL string `json:"url,omitempty"`
	// Snippet is the provider-returned excerpt.
	// Snippet 是供应商返回的摘要。
	Snippet string `json:"snippet,omitempty"`
	// Hostname is decoded for source compatibility; Router derives the canonical host from URL.
	// Hostname 为来源兼容而解码；Router 从 URL 派生规范主机名。
	Hostname string `json:"hostname,omitempty"`
}

// NewWebSearchActionDriver creates one region-fixed Alibaba WebSearch MCP driver.
// NewWebSearchActionDriver 创建一个区域固定的 Alibaba WebSearch MCP 驱动。
func NewWebSearchActionDriver(definitionID string, client *transport.Client) (*WebSearchActionDriver, error) {
	if strings.TrimSpace(definitionID) == "" || client == nil {
		return nil, ErrInvalidWebSearchDriver
	}
	return &WebSearchActionDriver{definitionID: definitionID, client: client}, nil
}

// ProviderDefinitionID returns the sole owning definition.
// ProviderDefinitionID 返回唯一归属定义。
func (d *WebSearchActionDriver) ProviderDefinitionID() string { return d.definitionID }

// ActionBindingID returns the exact WebSearch action.
// ActionBindingID 返回精确 WebSearch 动作。
func (d *WebSearchActionDriver) ActionBindingID() string { return SearchWebActionBindingID }

// Execute maps one filter-free VCP search through Alibaba's copied MCP session flow.
// Execute 将一次无过滤 VCP 搜索映射到复制的 Alibaba MCP 会话流程。
func (d *WebSearchActionDriver) Execute(ctx context.Context, execution provider.ExecutionRequest) (provider.ExecutionResult, error) {
	if d == nil || d.client == nil {
		return provider.ExecutionResult{}, ErrInvalidWebSearchDriver
	}
	action, errAction := execution.ValidateForAction(SearchWebActionBindingID, providerconfig.AuthMethodAPIKey)
	if errAction != nil {
		return provider.ExecutionResult{}, errAction
	}
	if action.Operation != vcp.OperationSearchWeb || execution.Execution.Stream {
		return provider.ExecutionResult{}, fmt.Errorf("%w: Alibaba WebSearch is synchronous only", ErrUnsupportedWebSearchInput)
	}
	operation := *execution.Execution.Payload.SearchWeb
	if operation.OutputMode != vcp.WebSearchOutputResults || len(operation.Domains.Allow) != 0 || len(operation.Domains.Block) != 0 || operation.Time != (vcp.SearchTimeFilter{}) || operation.Locale != (vcp.SearchLocale{}) || operation.Location != (vcp.SearchLocation{}) || operation.SafeSearch != "" {
		return provider.ExecutionResult{}, fmt.Errorf("%w: Alibaba WebSearch supports query and max_results only", ErrUnsupportedWebSearchInput)
	}

	initializeBody, errInitializeMarshal := json.Marshal(mcpInitializeRequest{JSONRPC: "2.0", ID: 1, Method: "initialize", Params: mcpInitializeParams{ProtocolVersion: webSearchMCPProtocolVersion, Capabilities: mcpClientCapabilities{}, ClientInfo: mcpClientInfo{Name: "VulcanModelRouter", Version: "1"}}})
	if errInitializeMarshal != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: encode initialize request: %v", ErrInvalidWebSearchDriver, errInitializeMarshal)
	}
	initializeResponse, sessionID, errInitialize := d.postMCP(ctx, execution, initializeBody, "")
	if errInitialize != nil {
		return provider.ExecutionResult{}, errInitialize
	}
	if _, errDecodeInitialize := decodeMCPResponse(initializeResponse, 1); errDecodeInitialize != nil {
		return provider.ExecutionResult{}, errDecodeInitialize
	}

	notificationBody, errNotificationMarshal := json.Marshal(mcpInitializedNotification{JSONRPC: "2.0", Method: "notifications/initialized"})
	if errNotificationMarshal != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: encode initialized notification: %v", ErrInvalidWebSearchDriver, errNotificationMarshal)
	}
	notificationResponse, refreshedSessionID, errNotification := d.postMCP(ctx, execution, notificationBody, sessionID)
	if errNotification != nil {
		return provider.ExecutionResult{}, errNotification
	}
	if errDrain := transport.DrainAndClose(notificationResponse); errDrain != nil {
		return provider.ExecutionResult{}, errDrain
	}
	if refreshedSessionID != "" {
		sessionID = refreshedSessionID
	}

	callBody, errCallMarshal := json.Marshal(mcpToolCallRequest{JSONRPC: "2.0", ID: 2, Method: "tools/call", Params: mcpToolCallParams{Name: webSearchMCPToolName, Arguments: mcpWebSearchArguments{Query: operation.Query, Count: operation.MaxResults}}})
	if errCallMarshal != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: encode tool request: %v", ErrInvalidWebSearchDriver, errCallMarshal)
	}
	callResponse, _, errCall := d.postMCP(ctx, execution, callBody, sessionID)
	if errCall != nil {
		return provider.ExecutionResult{}, errCall
	}
	resultPayload, errDecodeCall := decodeMCPResponse(callResponse, 2)
	if errDecodeCall != nil {
		return provider.ExecutionResult{}, errDecodeCall
	}
	return decodeWebSearchToolResult(operation, resultPayload)
}

// postMCP sends one exact MCP request and returns any refreshed session identifier.
// postMCP 发送一个精确 MCP 请求并返回可能刷新的会话标识。
func (d *WebSearchActionDriver) postMCP(ctx context.Context, execution provider.ExecutionRequest, body []byte, sessionID string) (*http.Response, string, error) {
	headers := []transport.Header{{Name: "Content-Type", Value: "application/json"}, {Name: "Accept", Value: "application/json, text/event-stream"}}
	if sessionID != "" {
		headers = append(headers, transport.Header{Name: "Mcp-Session-Id", Value: sessionID})
	}
	response, errRequest := d.client.Do(ctx, transport.Request{Binding: execution.Binding, Method: http.MethodPost, Path: webSearchMCPPath, Body: body, Headers: headers, Authentication: transport.Authentication{Mode: transport.AuthenticationBearer}})
	if errRequest != nil {
		return nil, "", errRequest
	}
	return response, strings.TrimSpace(response.Header.Get("Mcp-Session-Id")), nil
}

// decodeMCPResponse decodes one bounded JSON-RPC response and closes its body.
// decodeMCPResponse 解码一个有界 JSON-RPC 响应并关闭其正文。
func decodeMCPResponse(response *http.Response, expectedID int) (json.RawMessage, error) {
	if response == nil || response.Body == nil {
		return nil, ErrInvalidWebSearchDriver
	}
	defer func() { _ = response.Body.Close() }()
	reader, errBound := transport.NewBoundedResponseReader(response.Body, transport.MaximumNonStreamingResponseBytes)
	if errBound != nil {
		return nil, errBound
	}
	var envelope mcpJSONRPCResponse
	decoder := json.NewDecoder(reader)
	if errDecode := decoder.Decode(&envelope); errDecode != nil {
		return nil, fmt.Errorf("%w: decode MCP response: %v", ErrInvalidWebSearchDriver, errDecode)
	}
	if errTrailing := decoder.Decode(&struct{}{}); !errors.Is(errTrailing, io.EOF) {
		return nil, fmt.Errorf("%w: trailing MCP response data", ErrInvalidWebSearchDriver)
	}
	if envelope.JSONRPC != "2.0" || envelope.ID != expectedID {
		return nil, fmt.Errorf("%w: MCP response correlation is invalid", ErrInvalidWebSearchDriver)
	}
	if envelope.Error != nil {
		return nil, fmt.Errorf("%w: MCP JSON-RPC error code %d", ErrInvalidWebSearchDriver, envelope.Error.Code)
	}
	if len(envelope.Result) == 0 || string(envelope.Result) == "null" {
		return nil, fmt.Errorf("%w: MCP response result is missing", ErrInvalidWebSearchDriver)
	}
	return append(json.RawMessage(nil), envelope.Result...), nil
}

// decodeWebSearchToolResult converts MCP text pages into canonical ordered VCP results.
// decodeWebSearchToolResult 将 MCP 文本页面转换为规范有序 VCP 结果。
func decodeWebSearchToolResult(operation vcp.WebSearchOperation, payload json.RawMessage) (provider.ExecutionResult, error) {
	var toolResult mcpToolResult
	if errDecode := json.Unmarshal(payload, &toolResult); errDecode != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: decode tool result: %v", ErrInvalidWebSearchDriver, errDecode)
	}
	if toolResult.IsError {
		return provider.ExecutionResult{}, fmt.Errorf("%w: MCP tool reported failure", ErrInvalidWebSearchDriver)
	}
	pages := make([]mcpWebSearchPage, 0)
	for _, content := range toolResult.Content {
		if content.Type != "text" || strings.TrimSpace(content.Text) == "" {
			continue
		}
		var pageEnvelope mcpWebSearchPages
		decoder := json.NewDecoder(strings.NewReader(content.Text))
		if errDecode := decoder.Decode(&pageEnvelope); errDecode != nil {
			return provider.ExecutionResult{}, fmt.Errorf("%w: decode WebSearch pages: %v", ErrInvalidWebSearchDriver, errDecode)
		}
		if errTrailing := decoder.Decode(&struct{}{}); !errors.Is(errTrailing, io.EOF) {
			return provider.ExecutionResult{}, fmt.Errorf("%w: trailing WebSearch page data", ErrInvalidWebSearchDriver)
		}
		pages = append(pages, pageEnvelope.Pages...)
	}
	if len(pages) == 0 {
		return provider.ExecutionResult{}, fmt.Errorf("%w: MCP tool returned no structured pages", ErrInvalidWebSearchDriver)
	}
	if operation.MaxResults != nil && len(pages) > *operation.MaxResults {
		pages = pages[:*operation.MaxResults]
	}
	results := make([]vcp.WebSearchResult, len(pages))
	for index, page := range pages {
		normalizedURL, errURL := transport.ValidateAbsoluteHTTPURL(page.URL)
		if errURL != nil {
			return provider.ExecutionResult{}, fmt.Errorf("%w: result %d has invalid HTTP URL", ErrInvalidWebSearchDriver, index)
		}
		parsedURL, errParse := url.Parse(normalizedURL)
		if errParse != nil {
			return provider.ExecutionResult{}, fmt.Errorf("%w: result %d URL cannot be parsed", ErrInvalidWebSearchDriver, index)
		}
		results[index] = vcp.WebSearchResult{ID: fmt.Sprintf("result_%d", index+1), Rank: index + 1, Title: page.Title, URL: normalizedURL, SourceDomain: strings.ToLower(parsedURL.Hostname()), Snippet: page.Snippet}
	}
	search := &vcp.WebSearchResponse{Query: operation.Query, Evidence: vcp.SearchExecutionEvidence{Status: vcp.SearchExecutionConfirmed, Kinds: []vcp.SearchEvidenceKind{vcp.SearchEvidenceStructuredResult}}, Results: results}
	return provider.ExecutionResult{Search: search}, nil
}
