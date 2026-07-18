package management

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/bootstrap"
	providerkimi "github.com/OpenVulcan/vulcan-model-core/internal/provider/kimi"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

// KimiTokenClient refreshes one complete provider token without owning persistence.
// KimiTokenClient 刷新一个完整供应商令牌且不拥有持久化。
type KimiTokenClient interface {
	// Refresh exchanges one refresh token for a replacement token document.
	// Refresh 使用一个 Refresh Token 交换替换令牌文档。
	Refresh(context.Context, providerkimi.Token) (providerkimi.Token, error)
}

// KimiTokenService coordinates protected token replacement and credential metadata revision.
// KimiTokenService 协调受保护令牌替换和凭据元数据修订。
type KimiTokenService struct {
	// configurations owns non-secret credential metadata.
	// configurations 管理非秘密凭据元数据。
	configurations providerconfig.Store
	// secrets owns protected token documents.
	// secrets 管理受保护令牌文档。
	secrets secret.Store
	// client performs the provider exchange.
	// client 执行供应商交换。
	client KimiTokenClient
	// refreshMu protects the per-credential in-flight registry.
	// refreshMu 保护按凭据划分的进行中刷新注册表。
	refreshMu sync.Mutex
	// refreshCalls contains only currently running refresh operations.
	// refreshCalls 仅包含当前正在运行的刷新操作。
	refreshCalls map[string]*kimiRefreshCall
}

// kimiRefreshCall shares one exact credential refresh result with concurrent management requests.
// kimiRefreshCall 与并发管理请求共享一个精确凭据刷新结果。
type kimiRefreshCall struct {
	// done closes after the shared result is immutable.
	// done 在共享结果不可变后关闭。
	done chan struct{}
	// credential is the exact persisted replacement returned to every waiter.
	// credential 是返回给所有等待者的精确持久化替换凭据。
	credential providerconfig.Credential
	// err is the leader result shared without exposing provider response bodies.
	// err 是共享且不暴露供应商响应正文的主请求结果。
	err error
	// waiters counts concurrent callers joined to this exact operation.
	// waiters 统计加入此精确操作的并发调用方。
	waiters int
}

// NewKimiTokenService creates one refresh coordinator with explicit persistence boundaries.
// NewKimiTokenService 创建一个具有显式持久化边界的刷新协调器。
func NewKimiTokenService(configurations providerconfig.Store, secrets secret.Store, client KimiTokenClient) (*KimiTokenService, error) {
	if configurations == nil || secrets == nil || client == nil {
		return nil, errors.New("Kimi token configuration, secret store, and client are required")
	}
	return &KimiTokenService{configurations: configurations, secrets: secrets, client: client, refreshCalls: make(map[string]*kimiRefreshCall)}, nil
}

// RefreshCredential replaces one exact device-flow credential and compensates failed metadata persistence.
// RefreshCredential 替换一个精确设备授权凭据并补偿失败的元数据持久化。
func (s *KimiTokenService) RefreshCredential(ctx context.Context, instanceID string, credentialID string) (providerconfig.Credential, error) {
	refreshKey := instanceID + "\x00" + credentialID
	s.refreshMu.Lock()
	if existing, found := s.refreshCalls[refreshKey]; found {
		existing.waiters++
		s.refreshMu.Unlock()
		select {
		case <-existing.done:
			return existing.credential, existing.err
		case <-ctx.Done():
			return providerconfig.Credential{}, ctx.Err()
		}
	}
	call := &kimiRefreshCall{done: make(chan struct{})}
	s.refreshCalls[refreshKey] = call
	s.refreshMu.Unlock()

	call.credential, call.err = s.refreshCredential(ctx, instanceID, credentialID)
	s.refreshMu.Lock()
	delete(s.refreshCalls, refreshKey)
	close(call.done)
	s.refreshMu.Unlock()
	return call.credential, call.err
}

// refreshCredential performs one leader-owned refresh and durable secret replacement.
// refreshCredential 执行一次由主请求拥有的刷新与持久秘密替换。
func (s *KimiTokenService) refreshCredential(ctx context.Context, instanceID string, credentialID string) (providerconfig.Credential, error) {
	instance, errInstance := s.configurations.GetInstance(ctx, instanceID)
	if errInstance != nil {
		return providerconfig.Credential{}, errInstance
	}
	definition, errDefinition := s.configurations.GetDefinition(ctx, instance.DefinitionID)
	if errDefinition != nil {
		return providerconfig.Credential{}, errDefinition
	}
	if definition.ID != bootstrap.KimiCodingDefinitionID || definition.Kind != providerconfig.DefinitionKindSystem {
		return providerconfig.Credential{}, errors.New("Kimi token refresh requires the exact system Kimi Coding Plan definition")
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
	authMethodIsDeviceFlow := false
	for _, authMethod := range definition.AuthMethods {
		if authMethod.ID == credential.AuthMethodID && authMethod.Type == providerconfig.AuthMethodDeviceFlow && authMethod.Refreshable {
			authMethodIsDeviceFlow = true
			break
		}
	}
	if !authMethodIsDeviceFlow {
		return providerconfig.Credential{}, errors.New("provider credential is not a refreshable Kimi device-flow credential")
	}
	protectedValue, errSecret := s.secrets.Get(ctx, credential.SecretRef)
	if errSecret != nil {
		return providerconfig.Credential{}, errSecret
	}
	token, errToken := providerkimi.UnmarshalToken(protectedValue)
	if errToken != nil {
		return providerconfig.Credential{}, errToken
	}
	refreshed, errRefresh := s.client.Refresh(ctx, token)
	if errRefresh != nil {
		return providerconfig.Credential{}, errRefresh
	}
	encoded, errEncode := providerkimi.MarshalToken(refreshed)
	if errEncode != nil {
		return providerconfig.Credential{}, errEncode
	}
	replacementReference, errPut := s.secrets.Put(ctx, encoded)
	if errPut != nil {
		return providerconfig.Credential{}, errPut
	}
	previousReference := credential.SecretRef
	fingerprint := sha256.Sum256(encoded)
	credential.SecretRef = replacementReference
	credential.Fingerprint = hex.EncodeToString(fingerprint[:])
	credential.Revision++
	if refreshed.ExpiresAt > 0 {
		expiresAt := time.Unix(refreshed.ExpiresAt, 0).UTC()
		credential.ExpiresAt = &expiresAt
	}
	if errSave := s.configurations.SaveCredential(ctx, credential); errSave != nil {
		_ = s.secrets.Delete(context.WithoutCancel(ctx), replacementReference)
		return providerconfig.Credential{}, errSave
	}
	if errDelete := s.secrets.Delete(context.WithoutCancel(ctx), previousReference); errDelete != nil {
		return providerconfig.Credential{}, fmt.Errorf("delete superseded Kimi token: %w", errDelete)
	}
	return credential, nil
}
