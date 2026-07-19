package google

import (
	"fmt"
	"strings"

	protocolantigravity "github.com/OpenVulcan/vulcan-model-core/internal/protocol/google/antigravity"
	openairesponses "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/responses"
	protocolbridge "github.com/OpenVulcan/vulcan-model-core/internal/protocol/translatedresponses"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	translateddriver "github.com/OpenVulcan/vulcan-model-core/internal/provider/translatedresponses"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/tidwall/sjson"
)

// AntigravityDriver executes Google's Antigravity agent backend through copied CLIProxyAPI behavior.
// AntigravityDriver 通过复制的 CLIProxyAPI 行为执行 Google Antigravity Agent 后端。
type AntigravityDriver struct {
	// Driver owns shared immutable translated-response execution mechanics.
	// Driver 管理共享的不可变转换响应执行机制。
	*translateddriver.Driver
}

// NewAntigravityDriver constructs an Antigravity driver with its project envelope and internal endpoints.
// NewAntigravityDriver 使用项目信封和内部端点构造 Antigravity 驱动。
func NewAntigravityDriver(definitionID string, client *transport.Client, capabilities openairesponses.ProfileCapabilities) (*AntigravityDriver, error) {
	driver, errDriver := translateddriver.NewDriver(translateddriver.Configuration{
		DefinitionID: definitionID,
		Profile:      protocolantigravity.Profile(),
		Client:       client,
		Capabilities: capabilities,
		Path:         "/v1internal:generateContent",
		StreamPath:   "/v1internal:streamGenerateContent?alt=sse",
		Headers: []transport.Header{
			{Name: "Content-Type", Value: "application/json"},
		},
		Authentication:     transport.Authentication{Mode: transport.AuthenticationBearer},
		AllowedAuthMethods: []providerconfig.AuthMethodType{providerconfig.AuthMethodOAuth, providerconfig.AuthMethodBearer},
		StreamInputMode:    translateddriver.StreamInputPayload,
		SendDonePayload:    true,
		AdaptBody:          adaptAntigravityProject,
		AdaptRequest:       adaptAntigravityRequest,
	})
	if errDriver != nil {
		return nil, errDriver
	}
	return &AntigravityDriver{Driver: driver}, nil
}

// adaptAntigravityRequest applies CLIProxyAPI's dynamically refreshed short Hub User-Agent.
// adaptAntigravityRequest 应用 CLIProxyAPI 动态刷新的简短 Hub User-Agent。
func adaptAntigravityRequest(_ provider.ExecutionRequest, outbound transport.Request) (transport.Request, error) {
	outbound.Headers = append(outbound.Headers, transport.Header{Name: "User-Agent", Value: AntigravityRequestUserAgent("")})
	return outbound, nil
}

// adaptAntigravityProject sets the unique project scope required by the copied Antigravity envelope.
// adaptAntigravityProject 设置复制 Antigravity 信封要求的唯一项目作用域。
func adaptAntigravityProject(execution provider.ExecutionRequest, projected protocolbridge.ProjectedRequest) ([]byte, error) {
	projectID := ""
	for _, scope := range execution.Binding.Credential.ScopeRefs {
		if scope.Kind != "project" {
			continue
		}
		if strings.TrimSpace(scope.ID) == "" {
			return nil, fmt.Errorf("%w: Antigravity project scope id is empty", translateddriver.ErrInvalidDriver)
		}
		if projectID != "" {
			return nil, fmt.Errorf("%w: Antigravity requires exactly one project scope", translateddriver.ErrInvalidDriver)
		}
		projectID = scope.ID
	}
	if projectID == "" {
		return nil, fmt.Errorf("%w: Antigravity project scope is required", translateddriver.ErrInvalidDriver)
	}
	adapted, errSet := sjson.SetBytes(projected.UpstreamJSON, "project", projectID)
	if errSet != nil {
		return nil, fmt.Errorf("%w: set Antigravity project envelope: %v", translateddriver.ErrInvalidDriver, errSet)
	}
	adapted, errModel := sjson.SetBytes(adapted, "model", execution.Binding.Target.UpstreamModelID)
	if errModel != nil {
		return nil, fmt.Errorf("%w: set Antigravity model envelope: %v", translateddriver.ErrInvalidDriver, errModel)
	}
	return adapted, nil
}
