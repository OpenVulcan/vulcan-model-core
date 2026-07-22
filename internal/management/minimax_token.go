package management

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/OpenVulcan/vulcan-model-core/internal/bootstrap"
	"github.com/OpenVulcan/vulcan-model-core/internal/dependency"
	coreprovider "github.com/OpenVulcan/vulcan-model-core/internal/provider"
	providerminimax "github.com/OpenVulcan/vulcan-model-core/internal/provider/minimax"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

// MiniMaxTokenClient refreshes one complete region-bound MiniMax token without owning persistence.
// MiniMaxTokenClient 刷新一个完整且绑定区域的 MiniMax Token，但不管理持久化。
type MiniMaxTokenClient interface {
	// Refresh exchanges one refresh token against its document-declared regional Origin.
	// Refresh 针对 Token 文档声明的区域 Origin 交换一个 Refresh Token。
	Refresh(context.Context, providerminimax.Token) (providerminimax.Token, error)
}

// MiniMaxTokenService coordinates protected regional token replacement.
// MiniMaxTokenService 协调受保护区域 Token 的替换。
type MiniMaxTokenService struct {
	// configurations owns non-secret credential metadata.
	// configurations 管理非秘密凭据元数据。
	configurations providerconfig.Store
	// secrets owns protected complete token documents.
	// secrets 管理受保护的完整 Token 文档。
	secrets secret.Store
	// client dispatches refresh to the token-declared region.
	// client 将刷新分派到 Token 声明的区域。
	client MiniMaxTokenClient
	// refreshMu protects the in-flight registry.
	// refreshMu 保护进行中刷新注册表。
	refreshMu sync.Mutex
	// refreshCalls stores one shared operation per exact credential.
	// refreshCalls 为每个精确凭据存储一个共享操作。
	refreshCalls map[string]*miniMaxRefreshCall
}

// miniMaxRefreshCall shares one persisted refresh result with concurrent callers.
// miniMaxRefreshCall 与并发调用方共享一个已持久化刷新结果。
type miniMaxRefreshCall struct {
	// done closes after the result becomes immutable.
	// done 在结果不可变后关闭。
	done chan struct{}
	// credential is the persisted replacement metadata.
	// credential 是已持久化的替换元数据。
	credential providerconfig.Credential
	// err is the shared operation result.
	// err 是共享操作结果。
	err error
}

// NewMiniMaxTokenService creates one exact-region protected refresh coordinator.
// NewMiniMaxTokenService 创建一个精确区域的受保护刷新协调器。
func NewMiniMaxTokenService(configurations providerconfig.Store, secrets secret.Store, client MiniMaxTokenClient) (*MiniMaxTokenService, error) {
	if dependency.IsNil(configurations) || dependency.IsNil(secrets) || dependency.IsNil(client) {
		return nil, errors.New("MiniMax token configuration, secret store, and client are required")
	}
	return &MiniMaxTokenService{configurations: configurations, secrets: secrets, client: client, refreshCalls: make(map[string]*miniMaxRefreshCall)}, nil
}

// RefreshCredential refreshes one exact MiniMax device-flow credential with request coalescing.
// RefreshCredential 使用请求合并刷新一个精确的 MiniMax 设备授权凭据。
func (s *MiniMaxTokenService) RefreshCredential(ctx context.Context, instanceID string, credentialID string) (providerconfig.Credential, error) {
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
	call := &miniMaxRefreshCall{done: make(chan struct{})}
	s.refreshCalls[refreshKey] = call
	s.refreshMu.Unlock()
	// The leader survives an initiating request cancellation so every waiter observes one durable result.
	// 主刷新不随发起请求取消，使所有等待方观察同一个持久结果。
	call.credential, call.err = s.refreshCredential(context.WithoutCancel(ctx), instanceID, credentialID)
	s.refreshMu.Lock()
	delete(s.refreshCalls, refreshKey)
	close(call.done)
	s.refreshMu.Unlock()
	return call.credential, call.err
}

// refreshCredential validates immutable definition-region ownership and replaces one complete protected token.
// refreshCredential 校验不可变的定义区域归属并替换一个完整受保护 Token。
func (s *MiniMaxTokenService) refreshCredential(ctx context.Context, instanceID string, credentialID string) (providerconfig.Credential, error) {
	instance, errInstance := s.configurations.GetInstance(ctx, instanceID)
	if errInstance != nil {
		return providerconfig.Credential{}, errInstance
	}
	definition, errDefinition := s.configurations.GetDefinition(ctx, instance.DefinitionID)
	if errDefinition != nil {
		return providerconfig.Credential{}, errDefinition
	}
	if definition.Kind != providerconfig.DefinitionKindSystem || (definition.ID != bootstrap.MiniMaxGlobalDefinitionID && definition.ID != bootstrap.MiniMaxCNDefinitionID) {
		return providerconfig.Credential{}, errors.New("MiniMax token refresh requires an exact system MiniMax regional definition")
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
		return providerconfig.Credential{}, errors.New("provider credential is not a refreshable MiniMax device-flow credential")
	}
	protectedValue, errSecret := s.secrets.Get(ctx, credential.SecretRef)
	if errSecret != nil {
		return providerconfig.Credential{}, errSecret
	}
	token, errToken := providerminimax.UnmarshalToken(protectedValue)
	clear(protectedValue)
	if errToken != nil {
		return providerconfig.Credential{}, errToken
	}
	expectedRegion := "global"
	if definition.ID == bootstrap.MiniMaxCNDefinitionID {
		expectedRegion = "cn"
	}
	if token.Region != expectedRegion {
		return providerconfig.Credential{}, fmt.Errorf("%w: MiniMax token region does not match its provider definition", coreprovider.ErrAuthenticationResponseInvalid)
	}
	refreshed, errRefresh := s.client.Refresh(ctx, token)
	if errRefresh != nil {
		return providerconfig.Credential{}, errRefresh
	}
	if refreshed.Region != token.Region || refreshed.ResourceURL != token.ResourceURL {
		return providerconfig.Credential{}, fmt.Errorf("%w: MiniMax refresh changed immutable regional resource ownership", coreprovider.ErrAuthenticationResponseInvalid)
	}
	encoded, errEncode := providerminimax.MarshalToken(refreshed)
	if errEncode != nil {
		return providerconfig.Credential{}, errEncode
	}
	defer clear(encoded)
	expiresAt := refreshed.ExpiresAt.UTC()
	credential.ExpiresAt = &expiresAt
	return persistCredentialSecretReplacement(ctx, s.configurations, s.secrets, credential, encoded)
}
