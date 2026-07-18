package google

import (
	protocolinteractions "github.com/OpenVulcan/vulcan-model-core/internal/protocol/google/interactions"
	openairesponses "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/responses"
	translateddriver "github.com/OpenVulcan/vulcan-model-core/internal/provider/translatedresponses"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
)

const (
	// interactionsAPIRevision is copied from CLIProxyAPI's native Interactions executor.
	// interactionsAPIRevision 从 CLIProxyAPI 原生 Interactions 执行器复制而来。
	interactionsAPIRevision = "2026-05-20"
)

// InteractionsDriver executes Google's native Interactions API through copied CLIProxyAPI behavior.
// InteractionsDriver 通过复制的 CLIProxyAPI 行为执行 Google 原生 Interactions API。
type InteractionsDriver struct {
	// Driver owns shared immutable translated-response execution mechanics.
	// Driver 管理共享的不可变转换响应执行机制。
	*translateddriver.Driver
}

// NewInteractionsDriver constructs a Google Interactions driver.
// NewInteractionsDriver 构造 Google Interactions 驱动。
func NewInteractionsDriver(definitionID string, client *transport.Client, capabilities openairesponses.ProfileCapabilities) (*InteractionsDriver, error) {
	driver, errDriver := translateddriver.NewDriver(translateddriver.Configuration{
		DefinitionID: definitionID,
		Profile:      protocolinteractions.Profile(),
		Client:       client,
		Capabilities: capabilities,
		Path:         "/v1beta/interactions",
		StreamPath:   "/v1beta/interactions",
		Headers: []transport.Header{
			{Name: "Content-Type", Value: "application/json"},
			{Name: "Api-Revision", Value: interactionsAPIRevision},
		},
		Authentication:     transport.Authentication{Mode: transport.AuthenticationHeader, HeaderName: "X-Goog-Api-Key"},
		AllowedAuthMethods: []providerconfig.AuthMethodType{providerconfig.AuthMethodAPIKey, providerconfig.AuthMethodHeaderKey},
		StreamInputMode:    translateddriver.StreamInputPayload,
	})
	if errDriver != nil {
		return nil, errDriver
	}
	return &InteractionsDriver{Driver: driver}, nil
}
