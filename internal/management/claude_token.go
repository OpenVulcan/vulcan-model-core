package management

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/bootstrap"
	"github.com/OpenVulcan/vulcan-model-core/internal/dependency"
	coreprovider "github.com/OpenVulcan/vulcan-model-core/internal/provider"
	provideranthropic "github.com/OpenVulcan/vulcan-model-core/internal/provider/anthropic"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

// ClaudeTokenClient refreshes one complete Claude Code token without owning persistence.
// ClaudeTokenClient 刷新一个完整 Claude Code Token 且不拥有持久化。
type ClaudeTokenClient interface {
	// Refresh exchanges one protected refresh token through the copied Claude OAuth behavior.
	// Refresh 通过复制的 Claude OAuth 行为交换一个受保护 Refresh Token。
	Refresh(context.Context, provideranthropic.ClaudeToken) (provideranthropic.ClaudeToken, error)
}

// ClaudeTokenService coordinates protected Claude Code token replacement.
// ClaudeTokenService 协调受保护 Claude Code Token 替换。
type ClaudeTokenService struct {
	// configurations owns non-secret credential metadata.
	// configurations 管理非秘密凭据元数据。
	configurations providerconfig.Store
	// secrets owns protected Claude token documents.
	// secrets 管理受保护 Claude Token 文档。
	secrets secret.Store
	// client performs provider refresh exchanges.
	// client 执行供应商刷新交换。
	client ClaudeTokenClient
	// refreshMu protects the in-flight registry.
	// refreshMu 保护进行中刷新注册表。
	refreshMu sync.Mutex
	// refreshCalls stores one shared call per immutable credential.
	// refreshCalls 按不可变凭据存储一个共享调用。
	refreshCalls map[string]*claudeRefreshCall
}

// claudeRefreshCall shares one persisted credential result with concurrent management requests.
// claudeRefreshCall 与并发管理请求共享一个已持久化凭据结果。
type claudeRefreshCall struct {
	// done closes after credential and err become immutable.
	// done 在 credential 与 err 不可变后关闭。
	done chan struct{}
	// credential is the persisted replacement metadata.
	// credential 是已持久化替代凭据元数据。
	credential providerconfig.Credential
	// err is the shared refresh result.
	// err 是共享刷新结果。
	err error
}

// NewClaudeTokenService creates one protected Claude refresh coordinator.
// NewClaudeTokenService 创建一个受保护 Claude 刷新协调器。
func NewClaudeTokenService(configurations providerconfig.Store, secrets secret.Store, client ClaudeTokenClient) (*ClaudeTokenService, error) {
	if dependency.IsNil(configurations) || dependency.IsNil(secrets) || dependency.IsNil(client) {
		return nil, errors.New("Claude token configuration, secret store, and client are required")
	}
	return &ClaudeTokenService{configurations: configurations, secrets: secrets, client: client, refreshCalls: make(map[string]*claudeRefreshCall)}, nil
}

// RefreshCredential replaces one exact Claude Code OAuth credential.
// RefreshCredential 替换一个精确 Claude Code OAuth 凭据。
func (s *ClaudeTokenService) RefreshCredential(ctx context.Context, instanceID string, credentialID string) (providerconfig.Credential, error) {
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
	call := &claudeRefreshCall{done: make(chan struct{})}
	s.refreshCalls[refreshKey] = call
	s.refreshMu.Unlock()
	// The shared leader outlives the initiating HTTP request exactly like CLIProxyAPI's account refresh.
	// 共享主刷新严格按照 CLIProxyAPI 的账号刷新行为，不随发起它的 HTTP 请求结束。
	call.credential, call.err = s.refreshCredential(context.WithoutCancel(ctx), instanceID, credentialID)
	s.refreshMu.Lock()
	delete(s.refreshCalls, refreshKey)
	close(call.done)
	s.refreshMu.Unlock()
	return call.credential, call.err
}

// refreshCredential performs one leader-owned Claude exchange and durable secret replacement.
// refreshCredential 执行一次主请求拥有的 Claude 交换与持久 Secret 替换。
func (s *ClaudeTokenService) refreshCredential(ctx context.Context, instanceID string, credentialID string) (providerconfig.Credential, error) {
	instance, errInstance := s.configurations.GetInstance(ctx, instanceID)
	if errInstance != nil {
		return providerconfig.Credential{}, errInstance
	}
	definition, errDefinition := s.configurations.GetDefinition(ctx, instance.DefinitionID)
	if errDefinition != nil {
		return providerconfig.Credential{}, errDefinition
	}
	if definition.ID != bootstrap.AnthropicClaudeCodeDefinitionID || definition.Kind != providerconfig.DefinitionKindSystem {
		return providerconfig.Credential{}, errors.New("Claude token refresh requires the exact system Claude Code definition")
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
	if credential.AuthMethodID != "oauth" {
		return providerconfig.Credential{}, errors.New("provider credential is not a refreshable Claude OAuth credential")
	}
	protectedValue, errSecret := s.secrets.Get(ctx, credential.SecretRef)
	if errSecret != nil {
		return providerconfig.Credential{}, errSecret
	}
	token, errToken := provideranthropic.UnmarshalClaudeToken(protectedValue)
	clear(protectedValue)
	if errToken != nil {
		return providerconfig.Credential{}, errToken
	}
	refreshed, errRefresh := s.client.Refresh(ctx, token)
	if errRefresh != nil {
		return providerconfig.Credential{}, errRefresh
	}
	if token.AccountID != "" && refreshed.AccountID != token.AccountID {
		return providerconfig.Credential{}, fmt.Errorf("%w: Claude token refresh returned a different account identity", coreprovider.ErrAuthenticationResponseInvalid)
	}
	if token.AccountID == "" && token.Email != "" && refreshed.Email != token.Email {
		return providerconfig.Credential{}, fmt.Errorf("%w: Claude token refresh returned a different account email", coreprovider.ErrAuthenticationResponseInvalid)
	}
	if token.OrganizationID != "" && refreshed.OrganizationID != token.OrganizationID {
		return providerconfig.Credential{}, fmt.Errorf("%w: Claude token refresh returned a different organization identity", coreprovider.ErrAuthenticationResponseInvalid)
	}
	encoded, errEncode := provideranthropic.MarshalClaudeToken(refreshed)
	if errEncode != nil {
		return providerconfig.Credential{}, errEncode
	}
	defer clear(encoded)
	expiresAt := time.Unix(refreshed.ExpiresAt, 0).UTC()
	credential.ExpiresAt = &expiresAt
	return persistCredentialSecretReplacement(ctx, s.configurations, s.secrets, credential, encoded)
}
