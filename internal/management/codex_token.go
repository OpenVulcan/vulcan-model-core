package management

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/OpenVulcan/vulcan-model-core/internal/bootstrap"
	"github.com/OpenVulcan/vulcan-model-core/internal/dependency"
	coreprovider "github.com/OpenVulcan/vulcan-model-core/internal/provider"
	provideropenai "github.com/OpenVulcan/vulcan-model-core/internal/provider/openai"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

// CodexTokenClient refreshes one complete Codex token without owning persistence.
// CodexTokenClient 刷新一个完整 Codex Token 且不拥有持久化。
type CodexTokenClient interface {
	// Refresh exchanges one refresh token for a replacement Codex document.
	// Refresh 使用一个 Refresh Token 交换替代 Codex 文档。
	Refresh(context.Context, provideropenai.CodexToken) (provideropenai.CodexToken, error)
}

// CodexTokenService coordinates protected Codex token replacement.
// CodexTokenService 协调受保护 Codex Token 替换。
type CodexTokenService struct {
	// configurations owns non-secret credential metadata.
	// configurations 管理非秘密凭据元数据。
	configurations providerconfig.Store
	// secrets owns protected token documents.
	// secrets 管理受保护 Token 文档。
	secrets secret.Store
	// client performs provider refresh exchanges.
	// client 执行供应商刷新交换。
	client CodexTokenClient
	// refreshMu protects the in-flight registry.
	// refreshMu 保护进行中刷新注册表。
	refreshMu sync.Mutex
	// refreshCalls stores one shared call per credential.
	// refreshCalls 按凭据存储一个共享调用。
	refreshCalls map[string]*codexRefreshCall
}

// codexRefreshCall shares one credential refresh result with concurrent requests.
// codexRefreshCall 与并发请求共享一个凭据刷新结果。
type codexRefreshCall struct {
	// done closes after the result becomes immutable.
	// done 在结果不可变后关闭。
	done chan struct{}
	// credential is the persisted replacement.
	// credential 是已持久化的替代凭据。
	credential providerconfig.Credential
	// err is the shared refresh result.
	// err 是共享刷新结果。
	err error
}

// NewCodexTokenService creates one protected refresh coordinator.
// NewCodexTokenService 创建一个受保护刷新协调器。
func NewCodexTokenService(configurations providerconfig.Store, secrets secret.Store, client CodexTokenClient) (*CodexTokenService, error) {
	if dependency.IsNil(configurations) || dependency.IsNil(secrets) || dependency.IsNil(client) {
		return nil, errors.New("Codex token configuration, secret store, and client are required")
	}
	return &CodexTokenService{configurations: configurations, secrets: secrets, client: client, refreshCalls: make(map[string]*codexRefreshCall)}, nil
}

// RefreshCredential replaces one exact Codex device-flow credential.
// RefreshCredential 替换一个精确 Codex 设备授权凭据。
func (s *CodexTokenService) RefreshCredential(ctx context.Context, instanceID string, credentialID string) (providerconfig.Credential, error) {
	refreshKey := instanceID + "\x00" + credentialID
	s.refreshMu.Lock()
	if existing, found := s.refreshCalls[refreshKey]; found {
		s.refreshMu.Unlock()
		select {
		case <-existing.done:
			return existing.credential, existing.err
		case <-ctx.Done():
			return providerconfig.Credential{}, ctx.Err()
		}
	}
	call := &codexRefreshCall{done: make(chan struct{})}
	s.refreshCalls[refreshKey] = call
	s.refreshMu.Unlock()
	// The shared leader outlives the initiating HTTP request exactly like CLIProxyAPI's Codex single-flight refresh.
	// 共享主刷新严格按照 CLIProxyAPI 的 Codex 单飞刷新行为，不随发起它的 HTTP 请求结束。
	call.credential, call.err = s.refreshCredential(context.WithoutCancel(ctx), instanceID, credentialID)
	s.refreshMu.Lock()
	delete(s.refreshCalls, refreshKey)
	close(call.done)
	s.refreshMu.Unlock()
	return call.credential, call.err
}

// refreshCredential performs one leader-owned Codex exchange and durable replacement.
// refreshCredential 执行一次主请求拥有的 Codex 交换与持久替换。
func (s *CodexTokenService) refreshCredential(ctx context.Context, instanceID string, credentialID string) (providerconfig.Credential, error) {
	instance, errInstance := s.configurations.GetInstance(ctx, instanceID)
	if errInstance != nil {
		return providerconfig.Credential{}, errInstance
	}
	definition, errDefinition := s.configurations.GetDefinition(ctx, instance.DefinitionID)
	if errDefinition != nil {
		return providerconfig.Credential{}, errDefinition
	}
	if definition.ID != bootstrap.OpenAICodexDefinitionID || definition.Kind != providerconfig.DefinitionKindSystem {
		return providerconfig.Credential{}, errors.New("Codex token refresh requires the exact system OpenAI Codex definition")
	}
	credentials, errCredentials := s.configurations.ListCredentials(ctx, instanceID)
	if errCredentials != nil {
		return providerconfig.Credential{}, errCredentials
	}
	var credential providerconfig.Credential
	for _, candidate := range credentials {
		if candidate.ID == credentialID {
			credential = candidate
			break
		}
	}
	if credential.ID == "" {
		return providerconfig.Credential{}, fmt.Errorf("%w: provider credential %s", providerconfig.ErrNotFound, credentialID)
	}
	if credential.AuthMethodID != "device_flow" && credential.AuthMethodID != "oauth" {
		return providerconfig.Credential{}, errors.New("provider credential is not a refreshable Codex account credential")
	}
	protectedValue, errSecret := s.secrets.Get(ctx, credential.SecretRef)
	if errSecret != nil {
		return providerconfig.Credential{}, errSecret
	}
	token, errToken := provideropenai.UnmarshalCodexToken(protectedValue)
	clear(protectedValue)
	if errToken != nil {
		return providerconfig.Credential{}, errToken
	}
	refreshed, errRefresh := s.client.Refresh(ctx, token)
	if errRefresh != nil {
		return providerconfig.Credential{}, errRefresh
	}
	if refreshed.AccountID != token.AccountID {
		return providerconfig.Credential{}, fmt.Errorf("%w: Codex token refresh returned a different account identity", coreprovider.ErrAuthenticationResponseInvalid)
	}
	encoded, errEncode := provideropenai.MarshalCodexToken(refreshed)
	if errEncode != nil {
		return providerconfig.Credential{}, errEncode
	}
	defer clear(encoded)
	expiresAt := refreshed.ExpiresAt.UTC()
	credential.ExpiresAt = &expiresAt
	return persistCredentialSecretReplacement(ctx, s.configurations, s.secrets, credential, encoded)
}
