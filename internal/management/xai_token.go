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
	providerxai "github.com/OpenVulcan/vulcan-model-core/internal/provider/xai"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

// XAITokenClient refreshes one complete xAI token without owning persistence.
// XAITokenClient 刷新一个完整 xAI Token 且不拥有持久化。
type XAITokenClient interface {
	// Refresh exchanges one refresh token for a replacement document.
	// Refresh 使用一个 Refresh Token 交换替代文档。
	Refresh(context.Context, providerxai.Token) (providerxai.Token, error)
}

// XAITokenService coordinates protected xAI token replacement.
// XAITokenService 协调受保护 xAI Token 替换。
type XAITokenService struct {
	// configurations owns non-secret credential metadata.
	// configurations 管理非秘密凭据元数据。
	configurations providerconfig.Store
	// secrets owns protected token documents.
	// secrets 管理受保护 Token 文档。
	secrets secret.Store
	// client performs provider refresh exchanges.
	// client 执行供应商刷新交换。
	client XAITokenClient
	// refreshMu protects the in-flight registry.
	// refreshMu 保护进行中刷新注册表。
	refreshMu sync.Mutex
	// refreshCalls stores one shared call per credential.
	// refreshCalls 按凭据存储一个共享调用。
	refreshCalls map[string]*xaiRefreshCall
}

// xaiRefreshCall shares one credential refresh result with concurrent requests.
// xaiRefreshCall 与并发请求共享一个凭据刷新结果。
type xaiRefreshCall struct {
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

// NewXAITokenService creates one protected refresh coordinator.
// NewXAITokenService 创建一个受保护刷新协调器。
func NewXAITokenService(configurations providerconfig.Store, secrets secret.Store, client XAITokenClient) (*XAITokenService, error) {
	if dependency.IsNil(configurations) || dependency.IsNil(secrets) || dependency.IsNil(client) {
		return nil, errors.New("xAI token configuration, secret store, and client are required")
	}
	return &XAITokenService{configurations: configurations, secrets: secrets, client: client, refreshCalls: make(map[string]*xaiRefreshCall)}, nil
}

// RefreshCredential replaces one exact xAI device-flow credential.
// RefreshCredential 替换一个精确 xAI 设备授权凭据。
func (s *XAITokenService) RefreshCredential(ctx context.Context, instanceID string, credentialID string) (providerconfig.Credential, error) {
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
	call := &xaiRefreshCall{done: make(chan struct{})}
	s.refreshCalls[refreshKey] = call
	s.refreshMu.Unlock()
	// The shared leader outlives the initiating HTTP request so concurrent refresh callers observe one durable result.
	// 共享主刷新不随发起它的 HTTP 请求结束，使并发刷新调用方观察同一个持久结果。
	call.credential, call.err = s.refreshCredential(context.WithoutCancel(ctx), instanceID, credentialID)
	s.refreshMu.Lock()
	delete(s.refreshCalls, refreshKey)
	close(call.done)
	s.refreshMu.Unlock()
	return call.credential, call.err
}

// refreshCredential performs one leader-owned provider exchange and durable replacement.
// refreshCredential 执行一次主请求拥有的供应商交换与持久替换。
func (s *XAITokenService) refreshCredential(ctx context.Context, instanceID string, credentialID string) (providerconfig.Credential, error) {
	instance, errInstance := s.configurations.GetInstance(ctx, instanceID)
	if errInstance != nil {
		return providerconfig.Credential{}, errInstance
	}
	definition, errDefinition := s.configurations.GetDefinition(ctx, instance.DefinitionID)
	if errDefinition != nil {
		return providerconfig.Credential{}, errDefinition
	}
	if definition.ID != bootstrap.XAIOAuthDefinitionID || definition.Kind != providerconfig.DefinitionKindSystem {
		return providerconfig.Credential{}, errors.New("xAI token refresh requires the exact system xAI Account definition")
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
	if credential.AuthMethodID != "device_flow" {
		return providerconfig.Credential{}, errors.New("provider credential is not a refreshable xAI device-flow credential")
	}
	protectedValue, errSecret := s.secrets.Get(ctx, credential.SecretRef)
	if errSecret != nil {
		return providerconfig.Credential{}, errSecret
	}
	token, errToken := providerxai.UnmarshalToken(protectedValue)
	clear(protectedValue)
	if errToken != nil {
		return providerconfig.Credential{}, errToken
	}
	refreshed, errRefresh := s.client.Refresh(ctx, token)
	if errRefresh != nil {
		return providerconfig.Credential{}, errRefresh
	}
	if token.Subject != "" && refreshed.Subject != token.Subject {
		return providerconfig.Credential{}, fmt.Errorf("%w: xAI token refresh returned a different account subject", coreprovider.ErrAuthenticationResponseInvalid)
	}
	if token.Subject == "" && token.Email != "" && refreshed.Email != token.Email {
		return providerconfig.Credential{}, fmt.Errorf("%w: xAI token refresh returned a different account email", coreprovider.ErrAuthenticationResponseInvalid)
	}
	encoded, errEncode := providerxai.MarshalToken(refreshed)
	if errEncode != nil {
		return providerconfig.Credential{}, errEncode
	}
	defer clear(encoded)
	if refreshed.ExpiresAt > 0 {
		expiresAt := time.Unix(refreshed.ExpiresAt, 0).UTC()
		credential.ExpiresAt = &expiresAt
	}
	return persistCredentialSecretReplacement(ctx, s.configurations, s.secrets, credential, encoded)
}
