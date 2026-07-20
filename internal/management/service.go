// Package management coordinates provider configuration workflows and safe client queries.
// management 包协调供应商配置工作流与客户端安全查询。
package management

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/dependency"
	protocolaistudio "github.com/OpenVulcan/vulcan-model-core/internal/protocol/google/aistudio"
	protocolchat "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/chat"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	provideranthropic "github.com/OpenVulcan/vulcan-model-core/internal/provider/anthropic"
	providergoogle "github.com/OpenVulcan/vulcan-model-core/internal/provider/google"
	providerkimi "github.com/OpenVulcan/vulcan-model-core/internal/provider/kimi"
	provideropenai "github.com/OpenVulcan/vulcan-model-core/internal/provider/openai"
	providerxai "github.com/OpenVulcan/vulcan-model-core/internal/provider/xai"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

// OnboardSystemProviderInput contains the only operator-authored fields for one atomic system-provider onboarding.
// OnboardSystemProviderInput 包含一次原子系统供应商录入仅由操作员填写的字段。
type OnboardSystemProviderInput struct {
	// DefinitionID selects one exact code-owned provider variant.
	// DefinitionID 选择一个精确的代码拥有供应商变体。
	DefinitionID string
	// Handle optionally carries an internal routing alias; atomic management onboarding leaves it empty for server generation.
	// Handle 可选携带内部路由别名；原子管理录入会将其留空并由服务端生成。
	Handle string
	// DisplayName is the sole operator-authored name when provider identity cannot supply one.
	// DisplayName 是供应商身份无法提供名称时唯一由操作员填写的名称。
	DisplayName string
	// AuthMethodID selects one authentication method declared by the definition.
	// AuthMethodID 选择定义声明的一种认证方式。
	AuthMethodID string
	// CredentialLabel is derived from DisplayName or provider-issued identity metadata.
	// CredentialLabel 由 DisplayName 或供应商签发的身份元数据派生。
	CredentialLabel string
	// PrincipalKey is the provider-reported stable account identity when available.
	// PrincipalKey 是可用时供应商报告的稳定账号身份。
	PrincipalKey string
	// Secret contains transient credential material and is never written to SQLite.
	// Secret 包含临时凭据材料且绝不写入 SQLite。
	Secret []byte
	// ScopeRefs contains only provider-reported scopes established by a server-owned authorization flow.
	// ScopeRefs 仅包含由服务端拥有授权流程建立的供应商报告作用域。
	ScopeRefs []providerconfig.ScopeReference
	// EndpointParameters contains non-secret values declared by the selected system endpoint preset.
	// EndpointParameters 包含所选系统端点预设声明的非秘密值。
	EndpointParameters []providerconfig.EndpointParameterValue
	// endpointBaseURL is set only by a provider-owned onboarding workflow after validating uploaded credentials.
	// endpointBaseURL 仅由供应商专属录入流程在校验上传凭据后设置。
	endpointBaseURL string
	// endpointRegion is set only by a provider-owned onboarding workflow after normalizing its location.
	// endpointRegion 仅由供应商专属录入流程在规范化区域后设置。
	endpointRegion string
	// credentialExpiresAt is set only from provider-issued token metadata.
	// credentialExpiresAt 仅根据供应商签发的 Token 元数据设置。
	credentialExpiresAt *time.Time
}

// applyResolvedProviderName fills the instance and credential labels from one exact provider identity when the caller supplied no name.
// applyResolvedProviderName 在调用方未提供名称时，使用一个精确的供应商身份填充实例与凭据标签。
func applyResolvedProviderName(input *OnboardSystemProviderInput, providerIdentity string) {
	input.DisplayName = strings.TrimSpace(input.DisplayName)
	input.CredentialLabel = strings.TrimSpace(input.CredentialLabel)
	resolvedIdentity := strings.TrimSpace(providerIdentity)
	if input.DisplayName == "" {
		input.DisplayName = resolvedIdentity
	}
	if input.CredentialLabel == "" {
		input.CredentialLabel = resolvedIdentity
		if input.CredentialLabel == "" {
			input.CredentialLabel = input.DisplayName
		}
	}
}

// OnboardSystemProvider atomically creates one complete system-provider access path with secret compensation.
// OnboardSystemProvider 通过秘密补偿原子创建一条完整系统供应商访问路径。
func (s *Service) OnboardSystemProvider(ctx context.Context, input OnboardSystemProviderInput) (providerconfig.SystemOnboarding, error) {
	return s.onboardSystemProvider(ctx, input, "")
}

// OnboardKimiDeviceProvider atomically stores one server-acquired and format-validated Kimi device credential.
// OnboardKimiDeviceProvider 原子存储一个由服务端获取且格式已校验的 Kimi 设备凭据。
func (s *Service) OnboardKimiDeviceProvider(ctx context.Context, input OnboardSystemProviderInput) (providerconfig.SystemOnboarding, error) {
	token, errToken := providerkimi.UnmarshalToken(input.Secret)
	if errToken != nil {
		return providerconfig.SystemOnboarding{}, errToken
	}
	input.PrincipalKey = ""
	input.ScopeRefs = nil
	input.credentialExpiresAt = providerTokenExpiry(token.ExpiresAt)
	applyResolvedProviderName(&input, "")
	return s.onboardSystemProvider(ctx, input, "kimi")
}

// OnboardXAIDeviceProvider atomically stores one server-acquired and validated xAI device credential.
// OnboardXAIDeviceProvider 原子存储一个由服务端获取且已校验的 xAI 设备凭据。
func (s *Service) OnboardXAIDeviceProvider(ctx context.Context, input OnboardSystemProviderInput) (providerconfig.SystemOnboarding, error) {
	token, errToken := providerxai.UnmarshalToken(input.Secret)
	if errToken != nil {
		return providerconfig.SystemOnboarding{}, errToken
	}
	input.PrincipalKey = token.Subject
	if input.PrincipalKey == "" {
		input.PrincipalKey = token.Email
	}
	input.ScopeRefs = nil
	identityLabel := token.Email
	if identityLabel == "" {
		identityLabel = token.Subject
	}
	applyResolvedProviderName(&input, identityLabel)
	input.credentialExpiresAt = providerTokenExpiry(token.ExpiresAt)
	return s.onboardSystemProvider(ctx, input, "xai")
}

// OnboardCodexDeviceProvider atomically stores one server-acquired and validated Codex device credential.
// OnboardCodexDeviceProvider 原子存储一个由服务端获取且已校验的 Codex 设备凭据。
func (s *Service) OnboardCodexDeviceProvider(ctx context.Context, input OnboardSystemProviderInput) (providerconfig.SystemOnboarding, error) {
	if input.AuthMethodID != "device_flow" {
		return providerconfig.SystemOnboarding{}, errors.New("Codex device onboarding requires the exact device_flow authentication method")
	}
	return s.onboardCodexProvider(ctx, input)
}

// OnboardCodexOAuthProvider atomically stores one server-acquired and validated Codex browser OAuth credential.
// OnboardCodexOAuthProvider 原子存储一个由服务端获取且已校验的 Codex 浏览器 OAuth 凭据。
func (s *Service) OnboardCodexOAuthProvider(ctx context.Context, input OnboardSystemProviderInput) (providerconfig.SystemOnboarding, error) {
	if input.AuthMethodID != "oauth" {
		return providerconfig.SystemOnboarding{}, errors.New("Codex browser onboarding requires the exact oauth authentication method")
	}
	return s.onboardCodexProvider(ctx, input)
}

// onboardCodexProvider derives immutable account metadata from one protected token document.
// onboardCodexProvider 从一个受保护 Token 文档派生不可变账号元数据。
func (s *Service) onboardCodexProvider(ctx context.Context, input OnboardSystemProviderInput) (providerconfig.SystemOnboarding, error) {
	token, errToken := provideropenai.UnmarshalCodexToken(input.Secret)
	if errToken != nil {
		return providerconfig.SystemOnboarding{}, errToken
	}
	if strings.TrimSpace(token.AccountID) == "" {
		return providerconfig.SystemOnboarding{}, errors.New("Codex account onboarding requires the provider-reported ChatGPT account ID")
	}
	input.PrincipalKey = token.AccountID
	input.ScopeRefs = []providerconfig.ScopeReference{{Kind: "account", ID: token.AccountID}}
	identityLabel := token.Email
	if identityLabel == "" {
		identityLabel = token.AccountID
	}
	applyResolvedProviderName(&input, identityLabel)
	input.credentialExpiresAt = providerTokenExpiry(token.ExpiresAt.Unix())
	return s.onboardSystemProvider(ctx, input, "codex")
}

// OnboardClaudeOAuthProvider atomically stores one server-acquired and validated Claude Code OAuth credential.
// OnboardClaudeOAuthProvider 原子存储一个由服务端获取且已校验的 Claude Code OAuth 凭据。
func (s *Service) OnboardClaudeOAuthProvider(ctx context.Context, input OnboardSystemProviderInput) (providerconfig.SystemOnboarding, error) {
	token, errToken := provideranthropic.UnmarshalClaudeToken(input.Secret)
	if errToken != nil {
		return providerconfig.SystemOnboarding{}, errToken
	}
	input.PrincipalKey = token.AccountID
	if input.PrincipalKey == "" {
		input.PrincipalKey = token.Email
	}
	input.ScopeRefs = nil
	if token.OrganizationID != "" {
		input.ScopeRefs = []providerconfig.ScopeReference{{Kind: string(catalog.ScopeOrganization), ID: token.OrganizationID}}
	}
	identityLabel := token.Email
	if identityLabel == "" {
		identityLabel = token.AccountID
	}
	applyResolvedProviderName(&input, identityLabel)
	input.credentialExpiresAt = providerTokenExpiry(token.ExpiresAt)
	return s.onboardSystemProvider(ctx, input, "claude")
}

// OnboardAntigravityOAuthProvider atomically stores one server-acquired and validated Antigravity OAuth credential.
// OnboardAntigravityOAuthProvider 原子存储一个由服务端获取且已校验的 Antigravity OAuth 凭据。
func (s *Service) OnboardAntigravityOAuthProvider(ctx context.Context, input OnboardSystemProviderInput) (providerconfig.SystemOnboarding, error) {
	token, errToken := providergoogle.UnmarshalAntigravityToken(input.Secret)
	if errToken != nil {
		return providerconfig.SystemOnboarding{}, errToken
	}
	input.PrincipalKey = token.Email
	input.ScopeRefs = []providerconfig.ScopeReference{{Kind: "project", ID: token.ProjectID}}
	input.credentialExpiresAt = providerTokenExpiry(token.ExpiresAt)
	applyResolvedProviderName(&input, token.Email)
	return s.onboardSystemProvider(ctx, input, "antigravity")
}

// OnboardVertexServiceAccountProvider normalizes uploaded JSON and derives all identity, project, and endpoint facts server-side.
// OnboardVertexServiceAccountProvider 在服务端规范化上传 JSON 并派生全部身份、Project 与 Endpoint 事实。
func (s *Service) OnboardVertexServiceAccountProvider(ctx context.Context, input OnboardSystemProviderInput, location string) (providerconfig.SystemOnboarding, error) {
	defer clear(input.Secret)
	credential, errCredential := providergoogle.ParseVertexCredential(input.Secret, location)
	if errCredential != nil {
		return providerconfig.SystemOnboarding{}, errCredential
	}
	protected, errProtected := providergoogle.MarshalVertexCredential(credential)
	if errProtected != nil {
		return providerconfig.SystemOnboarding{}, errProtected
	}
	defer clear(protected)
	input.Secret = protected
	input.PrincipalKey = credential.Email
	input.ScopeRefs = []providerconfig.ScopeReference{{Kind: "project", ID: credential.ProjectID}}
	input.endpointBaseURL = providergoogle.VertexBaseURL(credential.Location)
	input.endpointRegion = credential.Location
	applyResolvedProviderName(&input, credential.Email)
	return s.onboardSystemProvider(ctx, input, "vertex")
}

// onboardSystemProvider enforces the acquisition boundary before committing one complete provider graph.
// onboardSystemProvider 在提交完整供应商图之前强制执行凭据获取边界。
func (s *Service) onboardSystemProvider(ctx context.Context, input OnboardSystemProviderInput, serverAcquiredProvider string) (providerconfig.SystemOnboarding, error) {
	input.Handle = strings.TrimSpace(input.Handle)
	applyResolvedProviderName(&input, "")
	input.PrincipalKey = strings.TrimSpace(input.PrincipalKey)
	definition, errDefinition := s.configurations.GetDefinition(ctx, input.DefinitionID)
	if errDefinition != nil {
		return providerconfig.SystemOnboarding{}, errDefinition
	}
	authMethod, authMethodExists := definition.AuthMethod(input.AuthMethodID)
	if definition.Kind != providerconfig.DefinitionKindSystem || !authMethodExists {
		return providerconfig.SystemOnboarding{}, fmt.Errorf("system provider onboarding requires an exact system definition and authentication method")
	}
	if serverAcquiredProvider != "" {
		expectedAuthType := providerconfig.AuthMethodDeviceFlow
		switch serverAcquiredProvider {
		case "antigravity", "claude":
			expectedAuthType = providerconfig.AuthMethodOAuth
		case "vertex":
			expectedAuthType = providerconfig.AuthMethodServiceAccount
		}
		if definition.DriverID != serverAcquiredProvider {
			return providerconfig.SystemOnboarding{}, fmt.Errorf("server-acquired onboarding requires the exact %s %s definition", serverAcquiredProvider, expectedAuthType)
		}
		if serverAcquiredProvider == "codex" {
			if authMethod.Type != providerconfig.AuthMethodDeviceFlow && authMethod.Type != providerconfig.AuthMethodOAuth {
				return providerconfig.SystemOnboarding{}, errors.New("server-acquired Codex onboarding requires device_flow or oauth authentication")
			}
		} else if authMethod.Type != expectedAuthType {
			return providerconfig.SystemOnboarding{}, fmt.Errorf("server-acquired onboarding requires the exact %s %s definition", serverAcquiredProvider, expectedAuthType)
		}
		switch serverAcquiredProvider {
		case "kimi":
			if _, errToken := providerkimi.UnmarshalToken(input.Secret); errToken != nil {
				return providerconfig.SystemOnboarding{}, errToken
			}
			if input.PrincipalKey != "" || len(input.ScopeRefs) != 0 {
				return providerconfig.SystemOnboarding{}, errors.New("Kimi onboarding does not accept caller-authored account identity or scopes")
			}
		case "xai":
			token, errToken := providerxai.UnmarshalToken(input.Secret)
			if errToken != nil {
				return providerconfig.SystemOnboarding{}, errToken
			}
			principalKey := token.Subject
			if principalKey == "" {
				principalKey = token.Email
			}
			if input.PrincipalKey != principalKey || len(input.ScopeRefs) != 0 {
				return providerconfig.SystemOnboarding{}, errors.New("xAI onboarding requires the exact provider-reported account identity without caller-authored scopes")
			}
		case "codex":
			token, errToken := provideropenai.UnmarshalCodexToken(input.Secret)
			if errToken != nil {
				return providerconfig.SystemOnboarding{}, errToken
			}
			if input.PrincipalKey != token.AccountID || len(input.ScopeRefs) != 1 || input.ScopeRefs[0] != (providerconfig.ScopeReference{Kind: "account", ID: token.AccountID}) {
				return providerconfig.SystemOnboarding{}, errors.New("Codex onboarding requires the exact provider-reported account scope")
			}
		case "claude":
			token, errToken := provideranthropic.UnmarshalClaudeToken(input.Secret)
			if errToken != nil {
				return providerconfig.SystemOnboarding{}, errToken
			}
			principalKey := token.AccountID
			if principalKey == "" {
				principalKey = token.Email
			}
			expectedScopes := []providerconfig.ScopeReference(nil)
			if token.OrganizationID != "" {
				expectedScopes = []providerconfig.ScopeReference{{Kind: string(catalog.ScopeOrganization), ID: token.OrganizationID}}
			}
			if input.PrincipalKey != principalKey || !slices.Equal(input.ScopeRefs, expectedScopes) {
				return providerconfig.SystemOnboarding{}, errors.New("Claude onboarding requires the exact provider-reported account and organization identity")
			}
		case "antigravity":
			token, errToken := providergoogle.UnmarshalAntigravityToken(input.Secret)
			if errToken != nil {
				return providerconfig.SystemOnboarding{}, errToken
			}
			if input.PrincipalKey != token.Email || len(input.ScopeRefs) != 1 || input.ScopeRefs[0].Kind != "project" || input.ScopeRefs[0].ID != token.ProjectID {
				return providerconfig.SystemOnboarding{}, errors.New("Antigravity onboarding requires the exact provider-reported account and project identity")
			}
		case "vertex":
			credential, errCredential := providergoogle.UnmarshalVertexCredential(input.Secret)
			if errCredential != nil {
				return providerconfig.SystemOnboarding{}, errCredential
			}
			if input.PrincipalKey != credential.Email || len(input.ScopeRefs) != 1 || input.ScopeRefs[0] != (providerconfig.ScopeReference{Kind: "project", ID: credential.ProjectID}) {
				return providerconfig.SystemOnboarding{}, errors.New("Vertex onboarding requires the exact service-account identity and project scope")
			}
			if input.endpointRegion != credential.Location || input.endpointBaseURL != providergoogle.VertexBaseURL(credential.Location) {
				return providerconfig.SystemOnboarding{}, errors.New("Vertex onboarding requires the exact normalized regional endpoint")
			}
		default:
			return providerconfig.SystemOnboarding{}, fmt.Errorf("server-acquired provider %s is unsupported", serverAcquiredProvider)
		}
	} else if authMethod.Type == providerconfig.AuthMethodDeviceFlow || authMethod.Type == providerconfig.AuthMethodOAuth || authMethod.Type == providerconfig.AuthMethodServiceAccount {
		return providerconfig.SystemOnboarding{}, fmt.Errorf("specialized provider credentials require their server-owned authorization workflow")
	}
	if len(input.Secret) == 0 {
		return providerconfig.SystemOnboarding{}, fmt.Errorf("system provider onboarding secret is required")
	}
	secretReference, errSecret := s.secrets.Put(ctx, input.Secret)
	if errSecret != nil {
		return providerconfig.SystemOnboarding{}, errSecret
	}
	onboarding, errBuild := s.buildSystemOnboarding(definition, input, secretReference)
	if errBuild != nil {
		if errDelete := s.secrets.Delete(context.WithoutCancel(ctx), secretReference); errDelete != nil {
			return providerconfig.SystemOnboarding{}, fmt.Errorf("build system provider onboarding: %w; compensate secret: %w", errBuild, errDelete)
		}
		return providerconfig.SystemOnboarding{}, errBuild
	}
	if errSave := s.configurations.SaveSystemOnboarding(ctx, onboarding); errSave != nil {
		if errDelete := s.secrets.Delete(context.WithoutCancel(ctx), secretReference); errDelete != nil {
			return providerconfig.SystemOnboarding{}, fmt.Errorf("save system provider onboarding: %w; compensate secret: %v", errSave, errDelete)
		}
		return providerconfig.SystemOnboarding{}, errSave
	}
	snapshot, errCatalog := buildSystemCatalog(onboarding, definition, s.now().UTC())
	if errCatalog == nil && serverAcquiredProvider == "codex" {
		snapshot, errCatalog = appendInitialCodexMetadata(snapshot, onboarding, input.Secret)
	}
	if errCatalog == nil {
		errCatalog = s.catalogs.Save(ctx, snapshot)
	}
	if errCatalog != nil {
		compensationContext := context.WithoutCancel(ctx)
		errCatalogCleanup := s.catalogs.Delete(compensationContext, onboarding.Instance.ID)
		if errors.Is(errCatalogCleanup, catalog.ErrSnapshotNotFound) {
			errCatalogCleanup = nil
		}
		errConfigurationCleanup := s.configurations.DeleteSystemOnboarding(compensationContext, onboarding)
		errSecretCleanup := s.secrets.Delete(compensationContext, secretReference)
		if errCatalogCleanup != nil || errConfigurationCleanup != nil || errSecretCleanup != nil {
			return providerconfig.SystemOnboarding{}, fmt.Errorf("save system provider catalog: %w; compensate catalog: %v; compensate configuration: %v; compensate secret: %v", errCatalog, errCatalogCleanup, errConfigurationCleanup, errSecretCleanup)
		}
		return providerconfig.SystemOnboarding{}, errCatalog
	}
	return onboarding, nil
}

// appendInitialCodexMetadata atomically adds the token's current plan and exact allowed-model set to a new account catalog.
// appendInitialCodexMetadata 将 Token 当前套餐与精确允许模型集合原子添加到新账号目录。
func appendInitialCodexMetadata(snapshot catalog.Snapshot, onboarding providerconfig.SystemOnboarding, protectedToken []byte) (catalog.Snapshot, error) {
	metadata, errMetadata := provideropenai.CodexCredentialMetadataFromToken(protectedToken, onboarding.Instance, onboarding.Credential, snapshot.ObservedAt)
	if errMetadata != nil {
		return catalog.Snapshot{}, errMetadata
	}
	if metadata.Plan == nil {
		return catalog.Snapshot{}, fmt.Errorf("%w: initial Codex metadata omitted its plan", provider.ErrMetadataResponseInvalid)
	}
	snapshot.Plans = append(snapshot.Plans, *metadata.Plan)
	snapshot.Entitlements = append(snapshot.Entitlements, metadata.Entitlements...)
	if errValidate := snapshot.Validate(); errValidate != nil {
		return catalog.Snapshot{}, fmt.Errorf("validate initial Codex metadata: %w", errValidate)
	}
	return snapshot, nil
}

// buildSystemOnboarding constructs server-owned identifiers, fixed endpoints, and bindings for one definition.
// buildSystemOnboarding 为一个定义构建服务端拥有的标识、固定端点和绑定。
func (s *Service) buildSystemOnboarding(definition providerconfig.ProviderDefinition, input OnboardSystemProviderInput, secretReference string) (providerconfig.SystemOnboarding, error) {
	instanceID, errInstanceID := generateID("pvi_")
	if errInstanceID != nil {
		return providerconfig.SystemOnboarding{}, errInstanceID
	}
	credentialID, errCredentialID := generateID("cred_")
	if errCredentialID != nil {
		return providerconfig.SystemOnboarding{}, errCredentialID
	}
	now := s.now().UTC()
	handle := input.Handle
	if handle == "" {
		handle = "provider-" + strings.TrimPrefix(instanceID, "pvi_")
	}
	onboarding := providerconfig.SystemOnboarding{
		Instance:   providerconfig.ProviderInstance{ID: instanceID, DefinitionID: definition.ID, Handle: handle, DisplayName: input.DisplayName, Status: providerconfig.LifecycleReady, Revision: 1, DefinitionRevision: definition.Revision, CreatedAt: now, UpdatedAt: now},
		Credential: providerconfig.Credential{ID: credentialID, ProviderInstanceID: instanceID, AuthMethodID: input.AuthMethodID, Label: input.CredentialLabel, PrincipalKey: input.PrincipalKey, SecretRef: secretReference, Fingerprint: credentialFingerprint(input.Secret), Status: providerconfig.CredentialActive, ScopeRefs: append([]providerconfig.ScopeReference(nil), input.ScopeRefs...), ExpiresAt: input.credentialExpiresAt, Revision: 1},
	}
	if len(definition.EndpointPresets) != 1 {
		return providerconfig.SystemOnboarding{}, fmt.Errorf("provider definition requires exactly one onboarding endpoint preset")
	}
	if !slices.Contains(definition.AuthMethodIDs, input.AuthMethodID) {
		return providerconfig.SystemOnboarding{}, fmt.Errorf("provider protocol does not allow authentication method %q", input.AuthMethodID)
	}
	preset := definition.EndpointPresets[0]
	baseURL := preset.BaseURL
	region := preset.Region
	endpointParameters := []providerconfig.EndpointParameterValue(nil)
	if preset.BaseURLTemplate != "" {
		var errMaterialize error
		baseURL, errMaterialize = preset.MaterializeBaseURL(input.EndpointParameters)
		if errMaterialize != nil {
			return providerconfig.SystemOnboarding{}, errMaterialize
		}
		// valuesByID canonicalizes persisted parameters into code-owned schema order.
		// valuesByID 将持久化参数规范为代码拥有的 Schema 顺序。
		valuesByID := make(map[string]string, len(input.EndpointParameters))
		for _, parameter := range input.EndpointParameters {
			valuesByID[parameter.ID] = parameter.Value
		}
		endpointParameters = make([]providerconfig.EndpointParameterValue, 0, len(preset.Parameters))
		for _, definition := range preset.Parameters {
			endpointParameters = append(endpointParameters, providerconfig.EndpointParameterValue{ID: definition.ID, Value: valuesByID[definition.ID]})
		}
	} else if len(input.EndpointParameters) != 0 {
		return providerconfig.SystemOnboarding{}, errors.New("selected provider endpoint does not accept parameters")
	}
	if input.endpointBaseURL != "" || input.endpointRegion != "" {
		if len(input.EndpointParameters) != 0 {
			return providerconfig.SystemOnboarding{}, errors.New("provider-owned endpoint override cannot combine endpoint parameters")
		}
		if input.endpointBaseURL == "" || input.endpointRegion == "" {
			return providerconfig.SystemOnboarding{}, errors.New("provider-owned endpoint override requires both base URL and region")
		}
		baseURL = input.endpointBaseURL
		region = input.endpointRegion
	}
	for _, channelID := range definition.ChannelIDs() {
		endpointID, errEndpointID := generateID("ep_")
		if errEndpointID != nil {
			return providerconfig.SystemOnboarding{}, errEndpointID
		}
		bindingID, errBindingID := generateID("bind_")
		if errBindingID != nil {
			return providerconfig.SystemOnboarding{}, errBindingID
		}
		onboarding.Endpoints = append(onboarding.Endpoints, providerconfig.Endpoint{ID: endpointID, ProviderInstanceID: instanceID, ChannelID: channelID, BaseURL: baseURL, Region: region, Parameters: append([]providerconfig.EndpointParameterValue(nil), endpointParameters...), Status: providerconfig.EndpointReady, Revision: 1})
		onboarding.Bindings = append(onboarding.Bindings, providerconfig.AccessBinding{ID: bindingID, ProviderInstanceID: instanceID, ChannelID: channelID, EndpointID: endpointID, CredentialID: credentialID, Priority: definition.Priority, Enabled: true, Revision: 1})
	}
	return onboarding, nil
}

var (
	// ErrConfigurationIncomplete reports an instance that cannot enter ready state.
	// ErrConfigurationIncomplete 表示供应商实例无法进入 Ready 状态。
	ErrConfigurationIncomplete = errors.New("provider configuration is incomplete")
	// ErrSystemDefinitionImmutable reports a management mutation attempted against a code-owned system definition.
	// ErrSystemDefinitionImmutable 表示管理变更尝试作用于代码拥有的系统定义。
	ErrSystemDefinitionImmutable = errors.New("system provider definition is immutable")
	// ErrCustomCatalogRequiresCustomProvider reports a user-declared catalog operation attempted against a system provider.
	// ErrCustomCatalogRequiresCustomProvider 表示用户声明目录操作尝试作用于系统供应商。
	ErrCustomCatalogRequiresCustomProvider = errors.New("user-declared catalogs are allowed only for custom providers")
)

// Service coordinates configuration persistence, secret compensation, and lifecycle rules.
// Service 协调配置持久化、Secret 补偿和生命周期规则。
type Service struct {
	// configurations persists non-secret provider configuration.
	// configurations 持久化非秘密供应商配置。
	configurations providerconfig.Store
	// secrets persists opaque credential bytes outside business storage.
	// secrets 在业务存储之外持久化不透明凭据字节。
	secrets secret.Store
	// catalogs persists instance-isolated system model metadata created during onboarding.
	// catalogs 持久化录入期间创建的实例隔离系统模型元数据。
	catalogs catalog.Store
	// now returns the authoritative lifecycle timestamp.
	// now 返回权威生命周期时间戳。
	now func() time.Time
}

// NewService creates one provider configuration application service.
// NewService 创建一个供应商配置应用服务。
func NewService(configurations providerconfig.Store, secrets secret.Store, catalogs catalog.Store) (*Service, error) {
	if dependency.IsNil(configurations) || dependency.IsNil(secrets) || dependency.IsNil(catalogs) {
		return nil, errors.New("provider configuration, secret, and catalog stores are required")
	}
	return &Service{configurations: configurations, secrets: secrets, catalogs: catalogs, now: time.Now}, nil
}

// CreateCustomDefinitionInput contains the editable portion of one generic custom provider.
// CreateCustomDefinitionInput 包含一个通用自定义供应商的可编辑部分。
type CreateCustomDefinitionInput struct {
	// ID optionally supplies an externally allocated custom_ identifier.
	// ID 可选地提供一个外部分配的 custom_ 标识。
	ID string
	// DisplayName is the management-facing provider name.
	// DisplayName 是管理界面显示的供应商名称。
	DisplayName string
	// ProtocolProfileID selects one user-configurable executable standard protocol.
	// ProtocolProfileID 选择一个用户可配置且可执行的标准协议。
	ProtocolProfileID string
	// AuthMethod selects one generic custom-provider authentication mechanism.
	// AuthMethod 选择一种通用自定义供应商认证机制。
	AuthMethod providerconfig.AuthMethodType
}

// OnboardCustomProviderInput contains the sole initial configuration for one executable compatibility provider.
// OnboardCustomProviderInput 包含一个可执行兼容供应商的唯一初始配置。
type OnboardCustomProviderInput struct {
	// DisplayName is reused as the provider, instance, and credential label so users enter one visible name.
	// DisplayName 同时作为供应商、实例与凭据标签，使用户只需输入一个可见名称。
	DisplayName string
	// Handle is the stable workspace-visible routing identifier.
	// Handle 是工作区可见的稳定路由标识。
	Handle string
	// ProtocolProfileID selects one exact custom execution factory profile.
	// ProtocolProfileID 选择一个精确的自定义执行 Factory Profile。
	ProtocolProfileID string
	// BaseURL is the operator-owned versioned compatibility endpoint.
	// BaseURL 是操作员拥有的带版本兼容 Endpoint。
	BaseURL string
	// Secret contains one transient Bearer or header API key and is never persisted outside Secret Store.
	// Secret 包含一个临时 Bearer 或 Header API Key，且绝不在 Secret Store 之外持久化。
	Secret []byte
	// UpstreamModelID is the exact wire model identifier exposed by this endpoint.
	// UpstreamModelID 是此 Endpoint 暴露的精确 Wire 模型标识。
	UpstreamModelID string
	// ModelDisplayName is the optional management-facing model label.
	// ModelDisplayName 是可选的管理界面模型标签。
	ModelDisplayName string
}

// CustomProviderOnboardingResult contains the committed custom graph and its initial user-declared catalog.
// CustomProviderOnboardingResult 包含已提交的自定义图与初始用户声明目录。
type CustomProviderOnboardingResult struct {
	// Configuration is the atomically persisted custom definition and access graph.
	// Configuration 是原子持久化的自定义 Definition 与访问图。
	Configuration providerconfig.CustomOnboarding
	// Catalog is the initial one-model catalog committed after configuration persistence.
	// Catalog 是配置持久化后提交的初始单模型目录。
	Catalog catalog.Snapshot
	// ProviderModelID is the server-allocated identifier of the sole initial model.
	// ProviderModelID 是服务端为唯一初始模型分配的标识。
	ProviderModelID string
}

// OnboardCustomProvider atomically creates one whitelisted compatibility definition, access path, secret, and model catalog.
// OnboardCustomProvider 原子创建一个白名单兼容 Definition、访问路径、Secret 与模型目录。
func (s *Service) OnboardCustomProvider(ctx context.Context, input OnboardCustomProviderInput) (CustomProviderOnboardingResult, error) {
	if s == nil {
		return CustomProviderOnboardingResult{}, errors.New("provider management service is required")
	}
	input.DisplayName = strings.TrimSpace(input.DisplayName)
	input.Handle = strings.TrimSpace(input.Handle)
	input.ProtocolProfileID = strings.TrimSpace(input.ProtocolProfileID)
	input.BaseURL = strings.TrimSpace(input.BaseURL)
	input.UpstreamModelID = strings.TrimSpace(input.UpstreamModelID)
	input.ModelDisplayName = strings.TrimSpace(input.ModelDisplayName)
	if input.DisplayName == "" || input.Handle == "" || input.BaseURL == "" || input.UpstreamModelID == "" || len(input.Secret) == 0 {
		return CustomProviderOnboardingResult{}, errors.New("custom provider name, handle, endpoint, secret, and upstream model are required")
	}
	if input.ModelDisplayName == "" {
		input.ModelDisplayName = input.UpstreamModelID
	}
	authMethod, errAuthMethod := customProviderAuthMethod(input.ProtocolProfileID)
	if errAuthMethod != nil {
		return CustomProviderOnboardingResult{}, errAuthMethod
	}
	identifiers, errIdentifiers := generateCustomOnboardingIdentifiers()
	if errIdentifiers != nil {
		return CustomProviderOnboardingResult{}, errIdentifiers
	}
	definition := customDefinition(identifiers.definitionID, 1, CreateCustomDefinitionInput{DisplayName: input.DisplayName, ProtocolProfileID: input.ProtocolProfileID, AuthMethod: authMethod})
	secretReference, errSecret := s.secrets.Put(ctx, input.Secret)
	if errSecret != nil {
		return CustomProviderOnboardingResult{}, errSecret
	}
	// operationTime keeps every record created by this logical operation on one authoritative timestamp.
	// operationTime 使本次逻辑操作创建的全部记录共享一个权威时间戳。
	operationTime := s.now().UTC()
	onboarding := buildCustomOnboarding(definition, identifiers, input, secretReference, operationTime)
	if errSave := s.configurations.SaveCustomOnboarding(ctx, onboarding); errSave != nil {
		if errDelete := s.secrets.Delete(context.WithoutCancel(ctx), secretReference); errDelete != nil {
			return CustomProviderOnboardingResult{}, fmt.Errorf("save custom provider onboarding: %w; compensate secret: %v", errSave, errDelete)
		}
		return CustomProviderOnboardingResult{}, errSave
	}
	catalogService, errCatalogService := NewCustomCatalogService(s.configurations, s.catalogs)
	if errCatalogService != nil {
		return CustomProviderOnboardingResult{}, compensateCustomOnboarding(ctx, s, onboarding, secretReference, errCatalogService)
	}
	snapshot, errCatalog := catalogService.SaveCustomCatalog(ctx, initialCustomCatalogInput(onboarding, identifiers, input, operationTime))
	if errCatalog != nil {
		return CustomProviderOnboardingResult{}, compensateCustomOnboarding(ctx, s, onboarding, secretReference, errCatalog)
	}
	return CustomProviderOnboardingResult{Configuration: onboarding, Catalog: snapshot, ProviderModelID: identifiers.modelID}, nil
}

// customOnboardingIdentifiers contains server-owned identifiers for one new custom provider graph and model catalog.
// customOnboardingIdentifiers 包含一个新自定义供应商图与模型目录的服务端所有标识。
type customOnboardingIdentifiers struct {
	// definitionID identifies the custom provider definition.
	// definitionID 标识自定义供应商 Definition。
	definitionID string
	// instanceID identifies the initial provider instance.
	// instanceID 标识初始供应商实例。
	instanceID string
	// endpointID identifies the compatibility endpoint.
	// endpointID 标识兼容 Endpoint。
	endpointID string
	// credentialID identifies the protected credential metadata.
	// credentialID 标识受保护凭据元数据。
	credentialID string
	// bindingID identifies the executable access binding.
	// bindingID 标识可执行访问绑定。
	bindingID string
	// modelID identifies the initial provider model.
	// modelID 标识初始供应商模型。
	modelID string
	// offeringID identifies the initial model offering.
	// offeringID 标识初始模型 Offering。
	offeringID string
	// profileID identifies the default execution profile.
	// profileID 标识默认执行 Profile。
	profileID string
}

// generateCustomOnboardingIdentifiers allocates every identity before any secret or configuration mutation.
// generateCustomOnboardingIdentifiers 在任何 Secret 或配置变更前分配全部身份。
func generateCustomOnboardingIdentifiers() (customOnboardingIdentifiers, error) {
	identifiers := customOnboardingIdentifiers{}
	// targets binds each domain prefix to its exact destination field before persistence starts.
	// targets 在持久化开始前将每个领域前缀绑定到其精确目标字段。
	targets := []struct {
		// prefix is the domain-specific identifier prefix.
		// prefix 是领域专用标识前缀。
		prefix string
		// value receives the generated identifier.
		// value 接收生成的标识。
		value *string
	}{
		{prefix: "custom_", value: &identifiers.definitionID},
		{prefix: "pvi_", value: &identifiers.instanceID},
		{prefix: "ep_", value: &identifiers.endpointID},
		{prefix: "cred_", value: &identifiers.credentialID},
		{prefix: "bind_", value: &identifiers.bindingID},
		{prefix: "model_", value: &identifiers.modelID},
		{prefix: "offer_", value: &identifiers.offeringID},
		{prefix: "profile_", value: &identifiers.profileID},
	}
	for _, target := range targets {
		identifier, errIdentifier := generateID(target.prefix)
		if errIdentifier != nil {
			return customOnboardingIdentifiers{}, errIdentifier
		}
		*target.value = identifier
	}
	return identifiers, nil
}

// customProviderAuthMethod returns the one fixed secret carrier implemented for a whitelisted custom protocol.
// customProviderAuthMethod 返回白名单自定义协议实现的唯一固定 Secret 载体。
func customProviderAuthMethod(protocolProfileID string) (providerconfig.AuthMethodType, error) {
	switch protocolProfileID {
	case protocolchat.ProfileID:
		return providerconfig.AuthMethodBearer, nil
	case protocolaistudio.ProfileID:
		return providerconfig.AuthMethodHeaderKey, nil
	default:
		return "", fmt.Errorf("custom provider protocol profile %q has no registered execution factory", protocolProfileID)
	}
}

// buildCustomOnboarding constructs one exact ready graph after the secret has entered protected storage.
// buildCustomOnboarding 在 Secret 进入受保护存储后构建一个精确就绪图。
func buildCustomOnboarding(definition providerconfig.ProviderDefinition, identifiers customOnboardingIdentifiers, input OnboardCustomProviderInput, secretReference string, now time.Time) providerconfig.CustomOnboarding {
	return providerconfig.CustomOnboarding{
		Definition: definition,
		Instance:   providerconfig.ProviderInstance{ID: identifiers.instanceID, DefinitionID: definition.ID, Handle: input.Handle, DisplayName: input.DisplayName, Status: providerconfig.LifecycleReady, Revision: 1, DefinitionRevision: definition.Revision, CreatedAt: now, UpdatedAt: now},
		Endpoint:   providerconfig.Endpoint{ID: identifiers.endpointID, ProviderInstanceID: identifiers.instanceID, ChannelID: definition.ProtocolProfileID, BaseURL: input.BaseURL, Status: providerconfig.EndpointReady, Revision: 1},
		Credential: providerconfig.Credential{ID: identifiers.credentialID, ProviderInstanceID: identifiers.instanceID, AuthMethodID: "default", Label: input.DisplayName, SecretRef: secretReference, Fingerprint: credentialFingerprint(input.Secret), Status: providerconfig.CredentialActive, Revision: 1},
		Binding:    providerconfig.AccessBinding{ID: identifiers.bindingID, ProviderInstanceID: identifiers.instanceID, ChannelID: definition.ProtocolProfileID, EndpointID: identifiers.endpointID, CredentialID: identifiers.credentialID, Priority: 10, Enabled: true, Revision: 1},
	}
}

// initialCustomCatalogInput builds one evidence-honest text model whose unknown capabilities remain explicit.
// initialCustomCatalogInput 构建一个证据诚实的文本模型，并显式保留未知能力。
func initialCustomCatalogInput(onboarding providerconfig.CustomOnboarding, identifiers customOnboardingIdentifiers, input OnboardCustomProviderInput, observedAt time.Time) SaveCustomCatalogInput {
	// capabilities explicitly preserve the absence of upstream capability evidence.
	// capabilities 显式保留缺少上游能力证据这一事实。
	capabilities := catalog.ModelCapabilities{
		ToolCalling: catalog.CapabilityUnknown, ParallelToolCalls: catalog.CapabilityUnknown,
		StreamingToolArguments: catalog.CapabilityUnknown, StrictJSONSchema: catalog.CapabilityUnknown,
		Reasoning: catalog.CapabilityUnknown, InputModalities: []string{"text"}, OutputModalities: []string{"text"},
	}
	return SaveCustomCatalogInput{
		ProviderInstanceID: onboarding.Instance.ID,
		Models:             []catalog.ProviderModel{{ID: identifiers.modelID, ProviderInstanceID: onboarding.Instance.ID, UpstreamModelID: input.UpstreamModelID, DisplayName: input.ModelDisplayName, Source: catalog.ModelSourceUserDeclared, EntitlementMode: catalog.EntitlementAllBoundCredentials, Revision: 1}},
		Offerings:          []catalog.ModelOffering{{ID: identifiers.offeringID, ProviderInstanceID: onboarding.Instance.ID, ProviderModelID: identifiers.modelID, UpstreamModelID: input.UpstreamModelID, Capabilities: capabilities, CapabilityRevision: 1, Revision: 1}},
		Profiles:           []catalog.ExecutionProfile{{ID: identifiers.profileID, ProviderInstanceID: onboarding.Instance.ID, OfferingID: identifiers.offeringID, DisplayName: "Default", Default: true, Capabilities: capabilities, SwitchPolicy: catalog.ProfileSwitchSeamless, PoolPolicy: catalog.PoolStrictProfile, CapabilityRevision: 1, Revision: 1}},
		ObservedAt:         observedAt,
	}
}

// compensateCustomOnboarding removes catalog, configuration, and secret state after any post-configuration failure.
// compensateCustomOnboarding 在配置后的任意失败后删除目录、配置与 Secret 状态。
func compensateCustomOnboarding(ctx context.Context, service *Service, onboarding providerconfig.CustomOnboarding, secretReference string, cause error) error {
	compensationContext := context.WithoutCancel(ctx)
	errCatalogCleanup := service.catalogs.Delete(compensationContext, onboarding.Instance.ID)
	if errors.Is(errCatalogCleanup, catalog.ErrSnapshotNotFound) {
		errCatalogCleanup = nil
	}
	errConfigurationCleanup := service.configurations.DeleteCustomOnboarding(compensationContext, onboarding)
	errSecretCleanup := service.secrets.Delete(compensationContext, secretReference)
	if errCatalogCleanup != nil || errConfigurationCleanup != nil || errSecretCleanup != nil {
		return fmt.Errorf("save custom provider catalog: %w; compensate catalog: %v; compensate configuration: %v; compensate secret: %v", cause, errCatalogCleanup, errConfigurationCleanup, errSecretCleanup)
	}
	return cause
}

// CreateCustomDefinition builds and persists one constrained custom provider definition.
// CreateCustomDefinition 构建并持久化一个受约束的自定义供应商定义。
func (s *Service) CreateCustomDefinition(ctx context.Context, input CreateCustomDefinitionInput) (providerconfig.ProviderDefinition, error) {
	definitionID := input.ID
	if definitionID == "" {
		generatedID, errID := generateID("custom_")
		if errID != nil {
			return providerconfig.ProviderDefinition{}, errID
		}
		definitionID = generatedID
	}
	definition := customDefinition(definitionID, 1, input)
	if errSave := s.configurations.SaveCustomDefinition(ctx, definition); errSave != nil {
		return providerconfig.ProviderDefinition{}, errSave
	}
	return definition, nil
}

// UpdateCustomDefinitionInput contains every editable field of one existing custom provider definition.
// UpdateCustomDefinitionInput 包含一个既有自定义供应商定义的全部可编辑字段。
type UpdateCustomDefinitionInput struct {
	// DefinitionID identifies the exact custom definition to replace.
	// DefinitionID 标识要替换的精确自定义定义。
	DefinitionID string
	// DisplayName is the replacement management-facing provider name.
	// DisplayName 是替换后的管理界面供应商名称。
	DisplayName string
	// ProtocolProfileID selects the replacement executable protocol profile.
	// ProtocolProfileID 选择替换后的可执行协议规格。
	ProtocolProfileID string
	// AuthMethod selects the replacement custom-provider authentication mechanism.
	// AuthMethod 选择替换后的自定义供应商认证机制。
	AuthMethod providerconfig.AuthMethodType
}

// UpdateCustomDefinition replaces one custom definition and marks its existing instances as migration-required.
// UpdateCustomDefinition 替换一个自定义定义并将其既有实例标记为需要迁移。
func (s *Service) UpdateCustomDefinition(ctx context.Context, input UpdateCustomDefinitionInput) (providerconfig.ProviderDefinition, error) {
	current, errCurrent := s.configurations.GetDefinition(ctx, input.DefinitionID)
	if errCurrent != nil {
		return providerconfig.ProviderDefinition{}, errCurrent
	}
	if current.Kind != providerconfig.DefinitionKindCustom {
		return providerconfig.ProviderDefinition{}, fmt.Errorf("%w: %s", ErrSystemDefinitionImmutable, current.ID)
	}
	// updated rebuilds the constrained one-channel custom shape rather than preserving incompatible stale fields.
	// updated 重建受约束的单通道自定义形态，而不是保留可能不兼容的旧字段。
	updated := customDefinition(current.ID, current.Revision+1, CreateCustomDefinitionInput{
		DisplayName:       input.DisplayName,
		ProtocolProfileID: input.ProtocolProfileID,
		AuthMethod:        input.AuthMethod,
	})
	instances, errInstances := s.configurations.ListInstances(ctx, current.ID)
	if errInstances != nil {
		return providerconfig.ProviderDefinition{}, errInstances
	}
	// migrationTime is shared so all transitioned instances form one management operation snapshot.
	// migrationTime 被共享，使全部转换实例形成一次管理操作快照。
	migrationTime := s.now().UTC()
	for index := range instances {
		instances[index].DefinitionRevision = updated.Revision
		instances[index].Status = providerconfig.LifecycleMigrationRequired
		instances[index].Revision++
		instances[index].UpdatedAt = migrationTime
	}
	if errSave := s.configurations.SaveCustomDefinitionMigration(ctx, providerconfig.CustomDefinitionMigration{Definition: updated, Instances: instances}); errSave != nil {
		return providerconfig.ProviderDefinition{}, errSave
	}
	return updated, nil
}

// customDefinition builds the sole supported generic custom provider shape from explicit management input.
// customDefinition 根据显式管理输入构建唯一受支持的通用自定义供应商形态。
func customDefinition(definitionID string, revision uint64, input CreateCustomDefinitionInput) providerconfig.ProviderDefinition {
	return providerconfig.ProviderDefinition{
		ID:                  definitionID,
		Kind:                providerconfig.DefinitionKindCustom,
		DisplayName:         input.DisplayName,
		ConfigSchemaVersion: "1",
		ProtocolProfileID:   input.ProtocolProfileID,
		EndpointProfileID:   customEndpointProfileID(input.ProtocolProfileID),
		AuthMethodIDs:       []string{"default"},
		RuntimeReady:        true,
		AuthMethods: []providerconfig.AuthMethodDefinition{{
			ID:                  "default",
			Type:                input.AuthMethod,
			MultipleCredentials: true,
		}},
		Features: providerconfig.ProviderFeatureSet{
			ModelDiscovery:    providerconfig.SupportUnsupported,
			PlanReader:        providerconfig.SupportUnsupported,
			EntitlementReader: providerconfig.SupportUnsupported,
			AllowanceReader:   providerconfig.SupportUnsupported,
		},
		Revision: revision,
	}
}

// customEndpointProfileID maps the complete executable custom protocol whitelist to one exact endpoint shape.
// customEndpointProfileID 将完整可执行自定义协议白名单映射到一个精确 Endpoint 形态。
func customEndpointProfileID(protocolProfileID string) string {
	switch protocolProfileID {
	case protocolchat.ProfileID:
		return providerconfig.CustomEndpointProfileOpenAICompatibility
	case protocolaistudio.ProfileID:
		return providerconfig.CustomEndpointProfileVertexCompatibility
	default:
		return ""
	}
}

// CreateInstanceInput contains initial provider instance configuration.
// CreateInstanceInput 包含供应商实例初始配置。
type CreateInstanceInput struct {
	// ID optionally supplies an externally allocated pvi_ identifier.
	// ID 可选地提供一个外部分配的 pvi_ 标识。
	ID string
	// DefinitionID selects one system or custom provider definition.
	// DefinitionID 选择一个系统或自定义供应商定义。
	DefinitionID string
	// Handle is the stable workspace routing alias.
	// Handle 是稳定的工作区路由别名。
	Handle string
	// DisplayName is the editable management-facing instance name.
	// DisplayName 是管理界面可编辑的实例名称。
	DisplayName string
}

// CreateInstance persists one provider instance in draft state.
// CreateInstance 以 Draft 状态持久化一个供应商实例。
func (s *Service) CreateInstance(ctx context.Context, input CreateInstanceInput) (providerconfig.ProviderInstance, error) {
	definition, errDefinition := s.configurations.GetDefinition(ctx, input.DefinitionID)
	if errDefinition != nil {
		return providerconfig.ProviderInstance{}, errDefinition
	}
	instanceID := input.ID
	if instanceID == "" {
		generatedID, errID := generateID("pvi_")
		if errID != nil {
			return providerconfig.ProviderInstance{}, errID
		}
		instanceID = generatedID
	}
	now := s.now().UTC()
	instance := providerconfig.ProviderInstance{
		ID:                 instanceID,
		DefinitionID:       definition.ID,
		Handle:             input.Handle,
		DisplayName:        input.DisplayName,
		Status:             providerconfig.LifecycleDraft,
		Revision:           1,
		DefinitionRevision: definition.Revision,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	if errSave := s.configurations.SaveInstance(ctx, instance); errSave != nil {
		return providerconfig.ProviderInstance{}, errSave
	}
	return instance, nil
}

// UpdateInstanceInput contains editable identity fields of one existing provider instance.
// UpdateInstanceInput 包含一个既有供应商实例的可编辑身份字段。
type UpdateInstanceInput struct {
	// ProviderInstanceID identifies the exact instance to update.
	// ProviderInstanceID 标识要更新的精确实例。
	ProviderInstanceID string
	// Handle is the replacement stable workspace routing alias.
	// Handle 是替换后的稳定工作区路由别名。
	Handle string
	// DisplayName is the replacement management-facing instance name.
	// DisplayName 是替换后的管理界面实例名称。
	DisplayName string
}

// UpdateInstance replaces editable instance identity fields without altering provider ownership or lifecycle.
// UpdateInstance 替换可编辑实例身份字段且不改变供应商归属或生命周期。
func (s *Service) UpdateInstance(ctx context.Context, input UpdateInstanceInput) (providerconfig.ProviderInstance, error) {
	instance, errInstance := s.configurations.GetInstance(ctx, input.ProviderInstanceID)
	if errInstance != nil {
		return providerconfig.ProviderInstance{}, errInstance
	}
	instance.Handle = input.Handle
	instance.DisplayName = input.DisplayName
	instance.Revision++
	instance.UpdatedAt = s.now().UTC()
	if errSave := s.configurations.SaveInstance(ctx, instance); errSave != nil {
		return providerconfig.ProviderInstance{}, errSave
	}
	return instance, nil
}

// SetInstanceEnabled transitions one instance to disabled or validates it back into ready state.
// SetInstanceEnabled 将一个实例转换为禁用状态或校验后恢复为就绪状态。
func (s *Service) SetInstanceEnabled(ctx context.Context, instanceID string, enabled bool) (providerconfig.ProviderInstance, error) {
	if enabled {
		return s.ActivateInstance(ctx, instanceID)
	}
	instance, errInstance := s.configurations.GetInstance(ctx, instanceID)
	if errInstance != nil {
		return providerconfig.ProviderInstance{}, errInstance
	}
	if instance.Status == providerconfig.LifecycleDisabled {
		return instance, nil
	}
	instance.Status = providerconfig.LifecycleDisabled
	instance.Revision++
	instance.UpdatedAt = s.now().UTC()
	if errSave := s.configurations.SaveInstance(ctx, instance); errSave != nil {
		return providerconfig.ProviderInstance{}, errSave
	}
	return instance, nil
}

// AddEndpointInput contains one concrete upstream endpoint configuration.
// AddEndpointInput 包含一个具体上游端点配置。
type AddEndpointInput struct {
	// ID optionally supplies an externally allocated ep_ identifier.
	// ID 可选地提供一个外部分配的 ep_ 标识。
	ID string
	// ProviderInstanceID owns the endpoint.
	// ProviderInstanceID 是端点所属供应商实例。
	ProviderInstanceID string
	// BaseURL is the validated upstream base URL.
	// BaseURL 是经过校验的上游基础 URL。
	BaseURL string
	// Region is an optional provider-defined region.
	// Region 是可选的供应商定义区域。
	Region string
}

// AddEndpoint creates one ready local endpoint record without probing the network.
// AddEndpoint 创建一个本地 Ready 端点记录且不探测网络。
func (s *Service) AddEndpoint(ctx context.Context, input AddEndpointInput) (providerconfig.Endpoint, error) {
	protocolProfileID, errProtocol := s.providerProtocolProfileID(ctx, input.ProviderInstanceID)
	if errProtocol != nil {
		return providerconfig.Endpoint{}, errProtocol
	}
	endpointID := input.ID
	if endpointID == "" {
		generatedID, errID := generateID("ep_")
		if errID != nil {
			return providerconfig.Endpoint{}, errID
		}
		endpointID = generatedID
	}
	endpoint := providerconfig.Endpoint{
		ID:                 endpointID,
		ProviderInstanceID: input.ProviderInstanceID,
		ChannelID:          protocolProfileID,
		BaseURL:            input.BaseURL,
		Region:             input.Region,
		Status:             providerconfig.EndpointReady,
		Revision:           1,
	}
	if errSave := s.configurations.SaveEndpoint(ctx, endpoint); errSave != nil {
		return providerconfig.Endpoint{}, errSave
	}
	return endpoint, nil
}

// UpdateEndpointInput contains every editable field of one existing endpoint.
// UpdateEndpointInput 包含一个既有端点的全部可编辑字段。
type UpdateEndpointInput struct {
	// ProviderInstanceID owns the endpoint and prevents cross-instance updates.
	// ProviderInstanceID 拥有该端点并阻止跨实例更新。
	ProviderInstanceID string
	// EndpointID identifies the exact endpoint to replace.
	// EndpointID 标识要替换的精确端点。
	EndpointID string
	// BaseURL is the replacement validated upstream base URL.
	// BaseURL 是替换后的已校验上游基础 URL。
	BaseURL string
	// Region is the replacement optional provider-defined region.
	// Region 是替换后的可选供应商定义区域。
	Region string
	// Status is the replacement endpoint availability state.
	// Status 是替换后的端点可用性状态。
	Status providerconfig.EndpointStatus
}

// UpdateEndpoint replaces one same-instance endpoint while preserving its immutable identifier.
// UpdateEndpoint 替换一个同实例端点，同时保留其不可变标识。
func (s *Service) UpdateEndpoint(ctx context.Context, input UpdateEndpointInput) (providerconfig.Endpoint, error) {
	endpoint, errEndpoint := s.endpoint(ctx, input.ProviderInstanceID, input.EndpointID)
	if errEndpoint != nil {
		return providerconfig.Endpoint{}, errEndpoint
	}
	endpoint.BaseURL = input.BaseURL
	endpoint.Region = input.Region
	endpoint.Status = input.Status
	endpoint.Revision++
	if errSave := s.configurations.SaveEndpoint(ctx, endpoint); errSave != nil {
		return providerconfig.Endpoint{}, errSave
	}
	return endpoint, nil
}

// AddCredentialInput contains non-secret metadata and transient secret bytes.
// AddCredentialInput 包含非秘密元数据和临时 Secret 字节。
type AddCredentialInput struct {
	// ID optionally supplies an externally allocated cred_ identifier.
	// ID 可选地提供一个外部分配的 cred_ 标识。
	ID string
	// ProviderInstanceID owns the credential.
	// ProviderInstanceID 是凭据所属供应商实例。
	ProviderInstanceID string
	// AuthMethodID selects one definition-owned authentication method.
	// AuthMethodID 选择一个定义拥有的认证方式。
	AuthMethodID string
	// Label is the editable management-facing account name.
	// Label 是管理界面可编辑的账号名称。
	Label string
	// PrincipalKey is the stable upstream account identity when known.
	// PrincipalKey 是已知时稳定的上游账号身份。
	PrincipalKey string
	// ScopeRefs lists shared commercial and organizational scopes.
	// ScopeRefs 列出共享商业与组织作用域。
	ScopeRefs []providerconfig.ScopeReference
	// Secret contains transient credential bytes and is never persisted in configuration storage.
	// Secret 包含临时凭据字节且绝不持久化到配置存储。
	Secret []byte
}

// AddCredential stores a secret first and compensates it if metadata persistence fails.
// AddCredential 先保存 Secret，并在元数据持久化失败时进行补偿删除。
func (s *Service) AddCredential(ctx context.Context, input AddCredentialInput) (providerconfig.Credential, error) {
	if errAuth := s.validateDirectSecretAuthMethod(ctx, input.ProviderInstanceID, input.AuthMethodID); errAuth != nil {
		return providerconfig.Credential{}, errAuth
	}
	if len(input.Secret) == 0 {
		return providerconfig.Credential{}, fmt.Errorf("provider credential secret is required")
	}
	credentialID := input.ID
	if credentialID == "" {
		generatedID, errID := generateID("cred_")
		if errID != nil {
			return providerconfig.Credential{}, errID
		}
		credentialID = generatedID
	}
	secretReference, errSecret := s.secrets.Put(ctx, input.Secret)
	if errSecret != nil {
		return providerconfig.Credential{}, errSecret
	}
	credential := providerconfig.Credential{
		ID:                 credentialID,
		ProviderInstanceID: input.ProviderInstanceID,
		AuthMethodID:       input.AuthMethodID,
		Label:              input.Label,
		PrincipalKey:       input.PrincipalKey,
		SecretRef:          secretReference,
		Fingerprint:        credentialFingerprint(input.Secret),
		Status:             providerconfig.CredentialActive,
		ScopeRefs:          append([]providerconfig.ScopeReference(nil), input.ScopeRefs...),
		Revision:           1,
	}
	if errSave := s.configurations.SaveCredential(ctx, credential); errSave != nil {
		if errDelete := s.secrets.Delete(context.WithoutCancel(ctx), secretReference); errDelete != nil {
			return providerconfig.Credential{}, fmt.Errorf("save credential metadata: %v; compensate secret: %w", errSave, errDelete)
		}
		return providerconfig.Credential{}, errSave
	}
	return credential, nil
}

// UpdateCredentialInput contains editable non-secret fields of one existing credential.
// UpdateCredentialInput 包含一个既有凭据的可编辑非秘密字段。
type UpdateCredentialInput struct {
	// ProviderInstanceID owns the credential and prevents cross-instance updates.
	// ProviderInstanceID 拥有该凭据并阻止跨实例更新。
	ProviderInstanceID string
	// CredentialID identifies the exact credential to update.
	// CredentialID 标识要更新的精确凭据。
	CredentialID string
	// Label is the replacement management-facing credential label.
	// Label 是替换后的管理界面凭据标签。
	Label string
	// PrincipalKey replaces operator-owned account metadata and may only echo or omit provider-derived identity.
	// PrincipalKey 替换操作员拥有的账号元数据；对供应商派生身份只能原样回传或省略。
	PrincipalKey string
	// ScopeRefs replaces operator-owned scopes and may only echo or omit provider-derived scopes.
	// ScopeRefs 替换操作员拥有的作用域；对供应商派生作用域只能原样回传或省略。
	ScopeRefs []providerconfig.ScopeReference
}

// UpdateCredential replaces operator-owned metadata while preserving provider-derived identity and scope facts.
// UpdateCredential 替换操作员拥有的元数据，同时保留供应商派生的身份与作用域事实。
func (s *Service) UpdateCredential(ctx context.Context, input UpdateCredentialInput) (providerconfig.Credential, error) {
	credential, errCredential := s.credential(ctx, input.ProviderInstanceID, input.CredentialID)
	if errCredential != nil {
		return providerconfig.Credential{}, errCredential
	}
	instance, errInstance := s.configurations.GetInstance(ctx, input.ProviderInstanceID)
	if errInstance != nil {
		return providerconfig.Credential{}, errInstance
	}
	definition, errDefinition := s.configurations.GetDefinition(ctx, instance.DefinitionID)
	if errDefinition != nil {
		return providerconfig.Credential{}, errDefinition
	}
	authMethod, exists := definition.AuthMethod(credential.AuthMethodID)
	if !exists {
		return providerconfig.Credential{}, errors.New("provider credential references an unknown authentication method")
	}
	credential.Label = input.Label
	if providerOwnsCredentialMaterial(authMethod.Type) {
		// Empty values mean the caller omitted immutable fields; non-empty conflicting values are explicit tampering.
		// 空值表示调用方省略不可变字段；非空冲突值则是显式篡改。
		if input.PrincipalKey != "" && input.PrincipalKey != credential.PrincipalKey {
			return providerconfig.Credential{}, errors.New("provider-derived credential identity is immutable")
		}
		if input.ScopeRefs != nil && !slices.Equal(input.ScopeRefs, credential.ScopeRefs) {
			return providerconfig.Credential{}, errors.New("provider-derived credential scopes are immutable")
		}
	} else {
		credential.PrincipalKey = input.PrincipalKey
		credential.ScopeRefs = append([]providerconfig.ScopeReference(nil), input.ScopeRefs...)
	}
	credential.Revision++
	if errSave := s.configurations.SaveCredential(ctx, credential); errSave != nil {
		return providerconfig.Credential{}, errSave
	}
	return credential, nil
}

// RotateCredentialSecretInput contains the only fields needed to replace credential secret bytes safely.
// RotateCredentialSecretInput 包含安全替换凭据 Secret 字节所需的唯一字段。
type RotateCredentialSecretInput struct {
	// ProviderInstanceID owns the credential and prevents cross-instance rotation.
	// ProviderInstanceID 拥有该凭据并阻止跨实例轮换。
	ProviderInstanceID string
	// CredentialID identifies the exact credential whose secret changes.
	// CredentialID 标识其 Secret 发生变化的精确凭据。
	CredentialID string
	// Secret contains the transient replacement credential bytes.
	// Secret 包含临时替换凭据字节。
	Secret []byte
}

// RotateCredentialSecret writes a replacement secret before changing metadata and cleans up the old secret afterwards.
// RotateCredentialSecret 在变更元数据前写入替换 Secret，并在之后清理旧 Secret。
func (s *Service) RotateCredentialSecret(ctx context.Context, input RotateCredentialSecretInput) (providerconfig.Credential, error) {
	credential, errCredential := s.credential(ctx, input.ProviderInstanceID, input.CredentialID)
	if errCredential != nil {
		return providerconfig.Credential{}, errCredential
	}
	if errAuth := s.validateDirectSecretAuthMethod(ctx, input.ProviderInstanceID, credential.AuthMethodID); errAuth != nil {
		return providerconfig.Credential{}, errAuth
	}
	if len(input.Secret) == 0 {
		return providerconfig.Credential{}, fmt.Errorf("replacement provider credential secret is required")
	}
	return persistCredentialSecretReplacement(ctx, s.configurations, s.secrets, credential, input.Secret)
}

// validateDirectSecretAuthMethod permits operator-supplied bytes only for operator-managed authentication methods declared by the exact instance definition.
// validateDirectSecretAuthMethod 仅允许精确实例定义声明的操作员管理认证方式接收操作员提供的字节。
func (s *Service) validateDirectSecretAuthMethod(ctx context.Context, instanceID string, authMethodID string) error {
	instance, errInstance := s.configurations.GetInstance(ctx, instanceID)
	if errInstance != nil {
		return errInstance
	}
	definition, errDefinition := s.configurations.GetDefinition(ctx, instance.DefinitionID)
	if errDefinition != nil {
		return errDefinition
	}
	authMethod, exists := definition.AuthMethod(authMethodID)
	if !exists {
		return fmt.Errorf("provider credential requires an exact definition-owned authentication method")
	}
	if providerOwnsCredentialMaterial(authMethod.Type) {
		return fmt.Errorf("provider-owned credentials require their server-owned authorization workflow")
	}
	return nil
}

// providerOwnsCredentialMaterial reports authentication types whose bytes, identity, and scopes must be derived by a specialized provider workflow.
// providerOwnsCredentialMaterial 报告必须由供应商专用流程派生字节、身份与作用域的认证类型。
func providerOwnsCredentialMaterial(authMethodType providerconfig.AuthMethodType) bool {
	return authMethodType == providerconfig.AuthMethodDeviceFlow || authMethodType == providerconfig.AuthMethodOAuth || authMethodType == providerconfig.AuthMethodServiceAccount
}

// AddBindingInput contains one endpoint-to-credential access relationship.
// AddBindingInput 包含一个端点到凭据的访问关系。
type AddBindingInput struct {
	// ID optionally supplies an externally allocated bind_ identifier.
	// ID 可选地提供一个外部分配的 bind_ 标识。
	ID string
	// ProviderInstanceID owns every referenced record.
	// ProviderInstanceID 是全部被引用记录所属实例。
	ProviderInstanceID string
	// EndpointID references one endpoint in the same instance.
	// EndpointID 引用同一实例中的一个端点。
	EndpointID string
	// CredentialID references one credential in the same instance.
	// CredentialID 引用同一实例中的一个凭据。
	CredentialID string
	// AllowedModelIDs optionally restricts the binding to explicit models.
	// AllowedModelIDs 可选地将绑定限制到明确模型。
	AllowedModelIDs []string
	// Priority is the deterministic same-pool order.
	// Priority 是同一账号池内的确定性顺序。
	Priority int
}

// AddBinding persists one enabled same-instance access binding.
// AddBinding 持久化一个启用的同实例访问绑定。
func (s *Service) AddBinding(ctx context.Context, input AddBindingInput) (providerconfig.AccessBinding, error) {
	protocolProfileID, errProtocol := s.providerProtocolProfileID(ctx, input.ProviderInstanceID)
	if errProtocol != nil {
		return providerconfig.AccessBinding{}, errProtocol
	}
	bindingID := input.ID
	if bindingID == "" {
		generatedID, errID := generateID("bind_")
		if errID != nil {
			return providerconfig.AccessBinding{}, errID
		}
		bindingID = generatedID
	}
	binding := providerconfig.AccessBinding{
		ID:                 bindingID,
		ProviderInstanceID: input.ProviderInstanceID,
		ChannelID:          protocolProfileID,
		EndpointID:         input.EndpointID,
		CredentialID:       input.CredentialID,
		AllowedModelIDs:    append([]string(nil), input.AllowedModelIDs...),
		Priority:           input.Priority,
		Enabled:            true,
		Revision:           1,
	}
	if errSave := s.configurations.SaveBinding(ctx, binding); errSave != nil {
		return providerconfig.AccessBinding{}, errSave
	}
	return binding, nil
}

// UpdateBindingInput contains every editable field of one existing access binding.
// UpdateBindingInput 包含一个既有访问绑定的全部可编辑字段。
type UpdateBindingInput struct {
	// ProviderInstanceID owns all referenced records and prevents cross-instance updates.
	// ProviderInstanceID 拥有全部引用记录并阻止跨实例更新。
	ProviderInstanceID string
	// BindingID identifies the exact binding to replace.
	// BindingID 标识要替换的精确绑定。
	BindingID string
	// EndpointID references the replacement same-instance endpoint.
	// EndpointID 引用替换后的同实例端点。
	EndpointID string
	// CredentialID references the replacement same-instance credential.
	// CredentialID 引用替换后的同实例凭据。
	CredentialID string
	// AllowedModelIDs restricts the replacement binding to explicit models when non-empty.
	// AllowedModelIDs 非空时将替换绑定限制到明确模型。
	AllowedModelIDs []string
	// Priority is the replacement deterministic same-pool order.
	// Priority 是替换后的确定性同账号池顺序。
	Priority int
	// Enabled controls whether the binding participates in resolution.
	// Enabled 控制绑定是否参与解析。
	Enabled bool
}

// UpdateBinding replaces one same-instance access binding while preserving its immutable identifier.
// UpdateBinding 替换一个同实例访问绑定，同时保留其不可变标识。
func (s *Service) UpdateBinding(ctx context.Context, input UpdateBindingInput) (providerconfig.AccessBinding, error) {
	binding, errBinding := s.binding(ctx, input.ProviderInstanceID, input.BindingID)
	if errBinding != nil {
		return providerconfig.AccessBinding{}, errBinding
	}
	binding.EndpointID = input.EndpointID
	binding.CredentialID = input.CredentialID
	binding.AllowedModelIDs = append([]string(nil), input.AllowedModelIDs...)
	binding.Priority = input.Priority
	binding.Enabled = input.Enabled
	binding.Revision++
	if errSave := s.configurations.SaveBinding(ctx, binding); errSave != nil {
		return providerconfig.AccessBinding{}, errSave
	}
	return binding, nil
}

// ActivateInstance verifies a locally closed access path and transitions the instance to ready.
// ActivateInstance 校验本地闭合访问路径并将实例转换为 Ready。
func (s *Service) ActivateInstance(ctx context.Context, instanceID string) (providerconfig.ProviderInstance, error) {
	instance, errInstance := s.configurations.GetInstance(ctx, instanceID)
	if errInstance != nil {
		return providerconfig.ProviderInstance{}, errInstance
	}
	endpoints, errEndpoints := s.configurations.ListEndpoints(ctx, instanceID)
	if errEndpoints != nil {
		return providerconfig.ProviderInstance{}, errEndpoints
	}
	credentials, errCredentials := s.configurations.ListCredentials(ctx, instanceID)
	if errCredentials != nil {
		return providerconfig.ProviderInstance{}, errCredentials
	}
	bindings, errBindings := s.configurations.ListBindings(ctx, instanceID)
	if errBindings != nil {
		return providerconfig.ProviderInstance{}, errBindings
	}
	readyEndpoints := make(map[string]struct{})
	for _, endpoint := range endpoints {
		if endpoint.Status == providerconfig.EndpointReady {
			readyEndpoints[endpoint.ID] = struct{}{}
		}
	}
	activeCredentials := make(map[string]struct{})
	for _, credential := range credentials {
		if credential.Status == providerconfig.CredentialActive {
			activeCredentials[credential.ID] = struct{}{}
		}
	}
	configurationClosed := false
	for _, binding := range bindings {
		if !binding.Enabled {
			continue
		}
		_, endpointReady := readyEndpoints[binding.EndpointID]
		_, credentialActive := activeCredentials[binding.CredentialID]
		if endpointReady && credentialActive {
			configurationClosed = true
			break
		}
	}
	if !configurationClosed {
		return providerconfig.ProviderInstance{}, fmt.Errorf("%w: ready endpoint, active credential, and enabled binding are required", ErrConfigurationIncomplete)
	}
	if instance.Status == providerconfig.LifecycleReady {
		return instance, nil
	}
	instance.Status = providerconfig.LifecycleReady
	instance.Revision++
	instance.UpdatedAt = s.now().UTC()
	if errSave := s.configurations.SaveInstance(ctx, instance); errSave != nil {
		return providerconfig.ProviderInstance{}, errSave
	}
	return instance, nil
}

// SetCredentialStatusInput contains one explicit credential lifecycle transition.
// SetCredentialStatusInput 包含一次显式凭据生命周期转换。
type SetCredentialStatusInput struct {
	// ProviderInstanceID owns the credential and prevents cross-instance lookup.
	// ProviderInstanceID 是凭据所属实例并阻止跨实例查询。
	ProviderInstanceID string
	// CredentialID identifies the exact credential to update.
	// CredentialID 标识需要更新的精确凭据。
	CredentialID string
	// Status is the new explicit credential state.
	// Status 是新的显式凭据状态。
	Status providerconfig.CredentialStatus
	// CoolingUntil is required only when Status is cooling.
	// CoolingUntil 仅在 Status 为 Cooling 时必填。
	CoolingUntil *time.Time
}

// SetCredentialStatus updates one credential without reading or rewriting its secret.
// SetCredentialStatus 更新一个凭据且不读取或重写其 Secret。
func (s *Service) SetCredentialStatus(ctx context.Context, input SetCredentialStatusInput) (providerconfig.Credential, error) {
	credentials, errCredentials := s.configurations.ListCredentials(ctx, input.ProviderInstanceID)
	if errCredentials != nil {
		return providerconfig.Credential{}, errCredentials
	}
	var selected providerconfig.Credential
	found := false
	for _, credential := range credentials {
		if credential.ID == input.CredentialID {
			selected = credential
			found = true
			break
		}
	}
	if !found {
		return providerconfig.Credential{}, fmt.Errorf("%w: provider credential %s", providerconfig.ErrNotFound, input.CredentialID)
	}
	selected.Status = input.Status
	selected.CoolingUntil = nil
	if input.Status == providerconfig.CredentialCooling {
		selected.CoolingUntil = cloneTimePointer(input.CoolingUntil)
	}
	selected.Revision++
	if errSave := s.configurations.SaveCredential(ctx, selected); errSave != nil {
		return providerconfig.Credential{}, errSave
	}
	return selected, nil
}

// providerProtocolProfileID resolves the immutable direct protocol reference owned by one provider instance.
// providerProtocolProfileID 解析一个供应商实例拥有的不可变直接协议引用。
func (s *Service) providerProtocolProfileID(ctx context.Context, instanceID string) (string, error) {
	instance, errInstance := s.configurations.GetInstance(ctx, instanceID)
	if errInstance != nil {
		return "", errInstance
	}
	definition, errDefinition := s.configurations.GetDefinition(ctx, instance.DefinitionID)
	if errDefinition != nil {
		return "", errDefinition
	}
	return definition.ProtocolProfileID, nil
}

// endpoint returns one endpoint only when it belongs to the requested provider instance.
// endpoint 仅在端点属于请求的供应商实例时返回该端点。
func (s *Service) endpoint(ctx context.Context, instanceID string, endpointID string) (providerconfig.Endpoint, error) {
	endpoints, errEndpoints := s.configurations.ListEndpoints(ctx, instanceID)
	if errEndpoints != nil {
		return providerconfig.Endpoint{}, errEndpoints
	}
	for _, endpoint := range endpoints {
		if endpoint.ID == endpointID {
			return endpoint, nil
		}
	}
	return providerconfig.Endpoint{}, fmt.Errorf("%w: provider endpoint %s", providerconfig.ErrNotFound, endpointID)
}

// credential returns one credential only when it belongs to the requested provider instance.
// credential 仅在凭据属于请求的供应商实例时返回该凭据。
func (s *Service) credential(ctx context.Context, instanceID string, credentialID string) (providerconfig.Credential, error) {
	credentials, errCredentials := s.configurations.ListCredentials(ctx, instanceID)
	if errCredentials != nil {
		return providerconfig.Credential{}, errCredentials
	}
	for _, credential := range credentials {
		if credential.ID == credentialID {
			return credential, nil
		}
	}
	return providerconfig.Credential{}, fmt.Errorf("%w: provider credential %s", providerconfig.ErrNotFound, credentialID)
}

// binding returns one access binding only when it belongs to the requested provider instance.
// binding 仅在访问绑定属于请求的供应商实例时返回该绑定。
func (s *Service) binding(ctx context.Context, instanceID string, bindingID string) (providerconfig.AccessBinding, error) {
	bindings, errBindings := s.configurations.ListBindings(ctx, instanceID)
	if errBindings != nil {
		return providerconfig.AccessBinding{}, errBindings
	}
	for _, binding := range bindings {
		if binding.ID == bindingID {
			return binding, nil
		}
	}
	return providerconfig.AccessBinding{}, fmt.Errorf("%w: access binding %s", providerconfig.ErrNotFound, bindingID)
}

// CustomCatalogService persists user-declared models without system-provider commercial metadata.
// CustomCatalogService 持久化用户声明模型且不包含系统供应商商业元数据。
type CustomCatalogService struct {
	// configurations verifies custom provider ownership and builds local pools.
	// configurations 校验自定义供应商所有权并构建本地账号池。
	configurations providerconfig.Store
	// catalogs atomically persists the user-declared model catalog.
	// catalogs 原子持久化用户声明模型目录。
	catalogs catalog.Store
	// resolver derives client-safe account pool summaries.
	// resolver 派生客户端安全账号池摘要。
	resolver *resolve.Resolver
}

// NewCustomCatalogService creates one user-declared model catalog manager.
// NewCustomCatalogService 创建一个用户声明模型目录管理器。
func NewCustomCatalogService(configurations providerconfig.Store, catalogs catalog.Store) (*CustomCatalogService, error) {
	if dependency.IsNil(configurations) || dependency.IsNil(catalogs) {
		return nil, errors.New("provider configuration and catalog stores are required")
	}
	targetResolver, errResolver := resolve.New(configurations, catalogs)
	if errResolver != nil {
		return nil, errResolver
	}
	return &CustomCatalogService{configurations: configurations, catalogs: catalogs, resolver: targetResolver}, nil
}

// SaveCustomCatalogInput contains one complete user-declared model catalog revision.
// SaveCustomCatalogInput 包含一份完整用户声明模型目录修订。
type SaveCustomCatalogInput struct {
	// ProviderInstanceID owns every supplied model record.
	// ProviderInstanceID 是全部传入模型记录的所有者。
	ProviderInstanceID string
	// Models contains logical user-declared models.
	// Models 包含逻辑用户声明模型。
	Models []catalog.ProviderModel
	// Offerings binds models to the provider's immutable direct protocol reference.
	// Offerings 将模型绑定到供应商不可变的直接协议引用。
	Offerings []catalog.ModelOffering
	// Profiles contains client-selectable context and capability shapes.
	// Profiles 包含客户端可选上下文与能力形态。
	Profiles []catalog.ExecutionProfile
	// ObservedAt records when the user configuration was accepted.
	// ObservedAt 记录用户配置被接受的时间。
	ObservedAt time.Time
}

// SaveCustomCatalog validates custom ownership, derives pools, and atomically saves the catalog.
// SaveCustomCatalog 校验自定义所有权、派生账号池并原子保存目录。
func (s *CustomCatalogService) SaveCustomCatalog(ctx context.Context, input SaveCustomCatalogInput) (catalog.Snapshot, error) {
	instance, errInstance := s.customInstance(ctx, input.ProviderInstanceID)
	if errInstance != nil {
		return catalog.Snapshot{}, errInstance
	}
	definition, errDefinition := s.configurations.GetDefinition(ctx, instance.DefinitionID)
	if errDefinition != nil {
		return catalog.Snapshot{}, errDefinition
	}
	for _, model := range input.Models {
		if model.Source != catalog.ModelSourceUserDeclared || model.EntitlementMode != catalog.EntitlementAllBoundCredentials {
			return catalog.Snapshot{}, errors.New("custom provider models must be user-declared and available to all bound credentials")
		}
	}
	revision := uint64(1)
	current, errCurrent := s.catalogs.Get(ctx, instance.ID)
	if errCurrent == nil {
		revision = current.Revision + 1
	} else if !errors.Is(errCurrent, catalog.ErrSnapshotNotFound) {
		return catalog.Snapshot{}, errCurrent
	}
	// models copies caller data before the service owns the catalog revision metadata.
	// models 在服务接管目录修订元数据前复制调用方数据。
	models := append([]catalog.ProviderModel(nil), input.Models...)
	for index := range models {
		models[index].Revision = revision
	}
	// offerings copies caller data before assigning the authoritative catalog and capability revisions.
	// offerings 在分配权威目录和能力修订前复制调用方数据。
	offerings := append([]catalog.ModelOffering(nil), input.Offerings...)
	for index := range offerings {
		offerings[index].ChannelID = definition.ProtocolProfileID
		offerings[index].CapabilityRevision = revision
		offerings[index].Revision = revision
	}
	// profiles copies caller data before assigning the authoritative catalog and capability revisions.
	// profiles 在分配权威目录和能力修订前复制调用方数据。
	profiles := append([]catalog.ExecutionProfile(nil), input.Profiles...)
	for index := range profiles {
		profiles[index].CapabilityRevision = revision
		profiles[index].Revision = revision
	}
	snapshot := catalog.Snapshot{
		ProviderInstanceID: instance.ID,
		Models:             models,
		Offerings:          offerings,
		Profiles:           profiles,
		Revision:           revision,
		ObservedAt:         input.ObservedAt,
	}
	if errValidate := snapshot.Validate(); errValidate != nil {
		return catalog.Snapshot{}, errValidate
	}
	pools, errPools := s.resolver.SummarizeSnapshot(ctx, snapshot, input.ObservedAt, revision)
	if errPools != nil {
		return catalog.Snapshot{}, errPools
	}
	snapshot.Pools = pools
	if errSave := s.catalogs.Save(ctx, snapshot); errSave != nil {
		return catalog.Snapshot{}, errSave
	}
	return snapshot, nil
}

// GetCustomCatalog returns the current user-declared catalog only for a custom provider instance.
// GetCustomCatalog 仅为自定义供应商实例返回当前用户声明的目录。
func (s *CustomCatalogService) GetCustomCatalog(ctx context.Context, providerInstanceID string) (catalog.Snapshot, error) {
	instance, errInstance := s.customInstance(ctx, providerInstanceID)
	if errInstance != nil {
		return catalog.Snapshot{}, errInstance
	}
	return s.catalogs.Get(ctx, instance.ID)
}

// customInstance verifies that one instance is owned by a user-editable custom provider definition.
// customInstance 校验一个实例由可编辑的自定义供应商定义拥有。
func (s *CustomCatalogService) customInstance(ctx context.Context, providerInstanceID string) (providerconfig.ProviderInstance, error) {
	instance, errInstance := s.configurations.GetInstance(ctx, providerInstanceID)
	if errInstance != nil {
		return providerconfig.ProviderInstance{}, errInstance
	}
	definition, errDefinition := s.configurations.GetDefinition(ctx, instance.DefinitionID)
	if errDefinition != nil {
		return providerconfig.ProviderInstance{}, errDefinition
	}
	if definition.Kind != providerconfig.DefinitionKindCustom {
		return providerconfig.ProviderInstance{}, fmt.Errorf("%w: %s", ErrCustomCatalogRequiresCustomProvider, instance.ID)
	}
	return instance, nil
}

// providerTokenExpiry converts one provider-issued Unix expiry into isolated credential metadata.
// providerTokenExpiry 将一个供应商签发的 Unix 到期时间转换为隔离凭据元数据。
func providerTokenExpiry(expiresAt int64) *time.Time {
	if expiresAt <= 0 {
		return nil
	}
	value := time.Unix(expiresAt, 0).UTC()
	return &value
}

// cloneTimePointer copies one optional lifecycle timestamp.
// cloneTimePointer 复制一个可选生命周期时间戳。
func cloneTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

// generateID creates one portable lowercase random domain identifier.
// generateID 创建一个可移植的小写随机领域标识。
func generateID(prefix string) (string, error) {
	randomBytes := make([]byte, 12)
	if _, errRandom := rand.Read(randomBytes); errRandom != nil {
		return "", fmt.Errorf("generate %s identifier: %w", prefix, errRandom)
	}
	return prefix + hex.EncodeToString(randomBytes), nil
}
