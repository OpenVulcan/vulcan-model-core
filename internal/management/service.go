// Package management coordinates provider configuration workflows and safe client queries.
// management 包协调供应商配置工作流与客户端安全查询。
package management

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/dependency"
	protocolmessages "github.com/OpenVulcan/vulcan-model-core/internal/protocol/anthropic/messages"
	protocolchat "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/chat"
	protocolresponses "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/responses"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	provideranthropic "github.com/OpenVulcan/vulcan-model-core/internal/provider/anthropic"
	providergoogle "github.com/OpenVulcan/vulcan-model-core/internal/provider/google"
	providerkimi "github.com/OpenVulcan/vulcan-model-core/internal/provider/kimi"
	providerminimax "github.com/OpenVulcan/vulcan-model-core/internal/provider/minimax"
	provideropenai "github.com/OpenVulcan/vulcan-model-core/internal/provider/openai"
	providerxai "github.com/OpenVulcan/vulcan-model-core/internal/provider/xai"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

const (
	// customModelDiscoveryTTL bounds freshness of a provider-owned standard model listing before explicit refresh.
	// customModelDiscoveryTTL 限制供应商标准模型清单在显式刷新前的有效期。
	customModelDiscoveryTTL = 15 * time.Minute
	// maximumCustomModelDiscoveryBytes bounds untrusted standard model-list responses.
	// maximumCustomModelDiscoveryBytes 限制不受信任的标准模型清单响应大小。
	maximumCustomModelDiscoveryBytes = 1 << 20
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
	// CredentialPriority orders this account within the provider instance; lower values win.
	// CredentialPriority 在供应商实例内排列该账号；较小值优先。
	CredentialPriority int
	// PlanOptionID selects one code-owned manual plan when the authentication method requires it.
	// PlanOptionID 在认证方式要求时选择一个代码拥有的人工套餐。
	PlanOptionID string
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

// OnboardMiniMaxDeviceProvider atomically stores one server-acquired region-bound MiniMax OAuth credential.
// OnboardMiniMaxDeviceProvider 原子存储一个由服务端获取且绑定区域的 MiniMax OAuth 凭据。
func (s *Service) OnboardMiniMaxDeviceProvider(ctx context.Context, input OnboardSystemProviderInput) (providerconfig.SystemOnboarding, error) {
	token, errToken := providerminimax.UnmarshalToken(input.Secret)
	if errToken != nil {
		return providerconfig.SystemOnboarding{}, errToken
	}
	regionMatches := (input.DefinitionID == "system_minimax_api" && token.Region == "global") || (input.DefinitionID == "system_minimax_cn" && token.Region == "cn")
	if input.AuthMethodID != "device_flow" || !regionMatches {
		return providerconfig.SystemOnboarding{}, errors.New("MiniMax device credential does not match the selected regional provider")
	}
	input.PrincipalKey = ""
	input.ScopeRefs = nil
	input.credentialExpiresAt = providerTokenExpiry(token.ExpiresAt.Unix())
	applyResolvedProviderName(&input, "")
	return s.onboardSystemProvider(ctx, input, "minimax")
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
		case "minimax":
			if _, errToken := providerminimax.UnmarshalToken(input.Secret); errToken != nil {
				return providerconfig.SystemOnboarding{}, errToken
			}
			if input.PrincipalKey != "" || len(input.ScopeRefs) != 0 {
				return providerconfig.SystemOnboarding{}, errors.New("MiniMax onboarding does not accept caller-authored account identity or scopes")
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
	if errCatalog == nil && definition.ID == "system_kimi_coding_plan" && onboarding.Credential.DeclaredPlan != nil {
		snapshot, errCatalog = providerkimi.ApplyDeclaredMembership(snapshot, onboarding.Credential)
	}
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
	// declaredPlan preserves the exact operator choice separately from provider-reported metadata.
	// declaredPlan 将精确的操作员选择与供应商报告的元数据分开保存。
	var declaredPlan *providerconfig.DeclaredPlanSelection
	if input.PlanOptionID != "" {
		declaredPlan = &providerconfig.DeclaredPlanSelection{PlanOptionID: input.PlanOptionID, DeclaredAt: now, Revision: 1}
	}
	onboarding := providerconfig.SystemOnboarding{
		Instance:   providerconfig.ProviderInstance{ID: instanceID, DefinitionID: definition.ID, Handle: handle, DisplayName: input.DisplayName, Status: providerconfig.LifecycleReady, Revision: 1, DefinitionRevision: definition.Revision, CreatedAt: now, UpdatedAt: now},
		Credential: providerconfig.Credential{ID: credentialID, ProviderInstanceID: instanceID, AuthMethodID: input.AuthMethodID, Label: input.CredentialLabel, PrincipalKey: input.PrincipalKey, SecretRef: secretReference, Fingerprint: credentialFingerprint(input.Secret), Status: providerconfig.CredentialActive, ScopeRefs: append([]providerconfig.ScopeReference(nil), input.ScopeRefs...), ExpiresAt: input.credentialExpiresAt, Priority: input.CredentialPriority, DeclaredPlan: declaredPlan, Revision: 1},
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
	endpointID, errEndpointID := generateID("ep_")
	if errEndpointID != nil {
		return providerconfig.SystemOnboarding{}, errEndpointID
	}
	onboarding.Endpoints = append(onboarding.Endpoints, providerconfig.Endpoint{ID: endpointID, ProviderInstanceID: instanceID, ChannelID: definition.ProtocolProfileID, BaseURL: baseURL, Region: region, Parameters: append([]providerconfig.EndpointParameterValue(nil), endpointParameters...), Status: providerconfig.EndpointReady, Revision: 1})
	for _, channelID := range definition.ChannelIDs() {
		bindingID, errBindingID := generateID("bind_")
		if errBindingID != nil {
			return providerconfig.SystemOnboarding{}, errBindingID
		}
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
	// httpClient performs bounded custom-provider model discovery without forwarding redirects.
	// httpClient 执行有界自定义供应商模型发现且不转发重定向。
	httpClient *http.Client
}

// NewService creates one provider configuration application service.
// NewService 创建一个供应商配置应用服务。
func NewService(configurations providerconfig.Store, secrets secret.Store, catalogs catalog.Store) (*Service, error) {
	if dependency.IsNil(configurations) || dependency.IsNil(secrets) || dependency.IsNil(catalogs) {
		return nil, errors.New("provider configuration, secret, and catalog stores are required")
	}
	return &Service{
		configurations: configurations,
		secrets:        secrets,
		catalogs:       catalogs,
		now:            time.Now,
		httpClient: &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}},
	}, nil
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
	case protocolchat.ProfileID, protocolresponses.ProfileID:
		return providerconfig.AuthMethodBearer, nil
	case protocolmessages.ProfileID:
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
	// Legacy Vertex definitions remain editable only when the protocol and code-owned endpoint shape stay unchanged.
	// 旧版 Vertex 定义仅在协议与代码拥有的 Endpoint 形态保持不变时继续允许编辑。
	if input.ProtocolProfileID == current.ProtocolProfileID && current.EndpointProfileID == providerconfig.CustomEndpointProfileVertexCompatibility {
		updated.EndpointProfileID = current.EndpointProfileID
	}
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
	case protocolresponses.ProfileID:
		return providerconfig.CustomEndpointProfileOpenAIResponsesCompatibility
	case protocolmessages.ProfileID:
		return providerconfig.CustomEndpointProfileAnthropicMessagesCompatibility
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

// ConfigureProviderInput contains one credential-independent provider configuration request.
// ConfigureProviderInput 包含一个独立于凭据的供应商配置请求。
type ConfigureProviderInput struct {
	// DefinitionID selects one exact system or custom provider definition.
	// DefinitionID 选择一个精确的系统或自定义供应商定义。
	DefinitionID string
	// Handle is the stable workspace-visible routing identifier.
	// Handle 是工作区可见的稳定路由标识。
	Handle string
	// DisplayName is the management-facing provider instance name.
	// DisplayName 是管理界面显示的供应商实例名称。
	DisplayName string
	// BaseURL supplies the operator-owned endpoint only for custom definitions.
	// BaseURL 仅为自定义定义提供操作员拥有的入口地址。
	BaseURL string
	// Region supplies optional custom-provider regional metadata.
	// Region 提供可选的自定义供应商区域元数据。
	Region string
	// EndpointParameters contains exact non-secret values declared by a system endpoint preset.
	// EndpointParameters 包含系统入口预设声明的精确非秘密参数值。
	EndpointParameters []providerconfig.EndpointParameterValue
	// InitialModel optionally declares one evidence-honest custom-provider model.
	// InitialModel 可选声明一个证据诚实的自定义供应商模型。
	InitialModel *InitialProviderModelInput
}

// InitialProviderModelInput contains one user-declared custom model and its known capability limits.
// InitialProviderModelInput 包含一个用户声明的自定义模型及其已知能力限制。
type InitialProviderModelInput struct {
	// UpstreamModelID is the exact model identifier sent to the provider.
	// UpstreamModelID 是发送给供应商的精确模型标识。
	UpstreamModelID string
	// DisplayName is the management-facing model name.
	// DisplayName 是管理界面显示的模型名称。
	DisplayName string
	// ContextWindow is zero only when the total context limit is unknown.
	// ContextWindow 仅在总上下文限制未知时为零。
	ContextWindow int64
	// MaxOutputTokens is zero only when the output limit is unknown.
	// MaxOutputTokens 仅在输出限制未知时为零。
	MaxOutputTokens int64
	// ToolCalling is an explicit user-declared capability level.
	// ToolCalling 是显式的用户声明能力级别。
	ToolCalling catalog.CapabilityLevel
	// Reasoning is an explicit user-declared capability level.
	// Reasoning 是显式的用户声明能力级别。
	Reasoning catalog.CapabilityLevel
	// RequestProjection optionally replaces the protocol-specific default outbound parameter mapping.
	// RequestProjection 可选替换协议专属的默认出站参数映射。
	RequestProjection *catalog.RequestProjection
}

// ProviderConfigurationResult contains the committed provider configuration and its credential-independent catalog.
// ProviderConfigurationResult 包含已提交的供应商配置及其独立于凭据的目录。
type ProviderConfigurationResult struct {
	// Configuration is the atomically persisted instance and endpoint graph.
	// Configuration 是原子持久化的实例与入口图。
	Configuration providerconfig.ProviderConfiguration
	// Catalog is the initial system or empty custom provider catalog.
	// Catalog 是初始系统目录或空的自定义供应商目录。
	Catalog catalog.Snapshot
}

// ConfigureProvider creates one provider instance, its endpoints, and its catalog without accepting a credential.
// ConfigureProvider 创建一个供应商实例、入口及目录，且不接收凭据。
func (s *Service) ConfigureProvider(ctx context.Context, input ConfigureProviderInput) (ProviderConfigurationResult, error) {
	definition, errDefinition := s.configurations.GetDefinition(ctx, strings.TrimSpace(input.DefinitionID))
	if errDefinition != nil {
		return ProviderConfigurationResult{}, errDefinition
	}
	configuration, errConfiguration := s.buildProviderConfiguration(definition, input)
	if errConfiguration != nil {
		return ProviderConfigurationResult{}, errConfiguration
	}
	if errSave := s.configurations.SaveProviderConfiguration(ctx, configuration); errSave != nil {
		return ProviderConfigurationResult{}, errSave
	}
	observedAt := s.now().UTC()
	snapshot := catalog.Snapshot{ProviderInstanceID: configuration.Instance.ID, Revision: 1, ObservedAt: observedAt}
	var errCatalog error
	if definition.Kind == providerconfig.DefinitionKindSystem {
		snapshot, errCatalog = buildSystemCatalog(providerconfig.SystemOnboarding{Instance: configuration.Instance, Endpoints: configuration.Endpoints}, definition, observedAt)
	} else if input.InitialModel != nil {
		snapshot, errCatalog = buildInitialProviderCatalog(configuration.Instance, definition.ProtocolProfileID, *input.InitialModel, observedAt)
	}
	if errCatalog == nil {
		errCatalog = s.catalogs.Save(ctx, snapshot)
	}
	if errCatalog != nil {
		compensationContext := context.WithoutCancel(ctx)
		errConfigurationCleanup := s.configurations.DeleteProviderConfiguration(compensationContext, configuration)
		if errConfigurationCleanup != nil {
			return ProviderConfigurationResult{}, fmt.Errorf("save provider configuration catalog: %w; compensate configuration: %v", errCatalog, errConfigurationCleanup)
		}
		return ProviderConfigurationResult{}, errCatalog
	}
	return ProviderConfigurationResult{Configuration: configuration, Catalog: snapshot}, nil
}

// buildInitialProviderCatalog builds one user-declared text model while preserving every unknown capability explicitly.
// buildInitialProviderCatalog 构建一个用户声明文本模型，同时显式保留每个未知能力。
func buildInitialProviderCatalog(instance providerconfig.ProviderInstance, channelID string, input InitialProviderModelInput, observedAt time.Time) (catalog.Snapshot, error) {
	input.UpstreamModelID = strings.TrimSpace(input.UpstreamModelID)
	input.DisplayName = strings.TrimSpace(input.DisplayName)
	if input.UpstreamModelID == "" {
		return catalog.Snapshot{}, errors.New("initial custom-provider model ID is required")
	}
	if input.DisplayName == "" {
		input.DisplayName = input.UpstreamModelID
	}
	if input.ContextWindow < 0 || input.MaxOutputTokens < 0 {
		return catalog.Snapshot{}, errors.New("initial custom-provider token limits cannot be negative")
	}
	if input.ToolCalling == "" {
		input.ToolCalling = catalog.CapabilityNative
	}
	if input.Reasoning == "" {
		input.Reasoning = catalog.CapabilityNative
	}
	if input.ToolCalling != catalog.CapabilityNative && input.ToolCalling != catalog.CapabilityUnsupported {
		return catalog.Snapshot{}, errors.New("custom-provider tool calling must be native or unsupported")
	}
	if input.Reasoning != catalog.CapabilityNative && input.Reasoning != catalog.CapabilityUnsupported {
		return catalog.Snapshot{}, errors.New("custom-provider reasoning must be native or unsupported")
	}
	requestProjection := catalog.RequestProjection{}
	if input.Reasoning == catalog.CapabilityNative {
		var errProjection error
		requestProjection, errProjection = defaultCustomRequestProjection(channelID)
		if errProjection != nil {
			return catalog.Snapshot{}, errProjection
		}
	}
	if input.RequestProjection != nil {
		requestProjection = catalog.CloneRequestProjection(*input.RequestProjection)
	}
	if errProjection := requestProjection.Validate(); errProjection != nil {
		return catalog.Snapshot{}, errProjection
	}
	if input.Reasoning == catalog.CapabilityNative && len(requestProjection.Reasoning.Effort) == 0 {
		return catalog.Snapshot{}, errors.New("callable custom-provider reasoning requires at least one effort projection rule")
	}
	if input.Reasoning == catalog.CapabilityUnsupported && (len(requestProjection.Reasoning.Effort) > 0 || len(requestProjection.Reasoning.Summary) > 0) {
		return catalog.Snapshot{}, errors.New("unsupported custom-provider reasoning cannot carry effort or summary projection rules")
	}
	if errProjection := validateCustomProjectionForProtocol(channelID, requestProjection); errProjection != nil {
		return catalog.Snapshot{}, errProjection
	}
	identifiers := make([]string, 3)
	for index, prefix := range []string{"model_", "offer_", "profile_"} {
		identifier, errIdentifier := generateID(prefix)
		if errIdentifier != nil {
			return catalog.Snapshot{}, errIdentifier
		}
		identifiers[index] = identifier
	}
	capabilities := catalog.ModelCapabilities{
		ToolCalling: input.ToolCalling, ParallelToolCalls: catalog.CapabilityUnknown,
		StreamingToolArguments: catalog.CapabilityUnknown, StrictJSONSchema: catalog.CapabilityUnknown,
		Reasoning: input.Reasoning, ReasoningEfforts: reasoningValues(requestProjection.Reasoning.Effort),
		ReasoningSummaryModes: reasoningValues(requestProjection.Reasoning.Summary),
		InputModalities:       []string{"text"}, OutputModalities: []string{"text"},
	}
	if input.ContextWindow > 0 {
		capabilities.Tokens.ContextWindow = catalog.OptionalTokenLimit{Known: true, Value: input.ContextWindow}
	}
	if input.MaxOutputTokens > 0 {
		capabilities.Tokens.MaxOutputTokens = catalog.OptionalTokenLimit{Known: true, Value: input.MaxOutputTokens}
	}
	snapshot := catalog.Snapshot{
		ProviderInstanceID: instance.ID,
		Models:             []catalog.ProviderModel{{ID: identifiers[0], ProviderInstanceID: instance.ID, UpstreamModelID: input.UpstreamModelID, DisplayName: input.DisplayName, Source: catalog.ModelSourceUserDeclared, EntitlementMode: catalog.EntitlementAllBoundCredentials, Revision: 1}},
		Offerings:          []catalog.ModelOffering{{ID: identifiers[1], ProviderInstanceID: instance.ID, ProviderModelID: identifiers[0], ChannelID: channelID, UpstreamModelID: input.UpstreamModelID, Capabilities: capabilities, RequestProjection: requestProjection, CapabilityRevision: 1, Revision: 1}},
		Profiles:           []catalog.ExecutionProfile{{ID: identifiers[2], ProviderInstanceID: instance.ID, OfferingID: identifiers[1], DisplayName: "Default", Default: true, Capabilities: capabilities, SwitchPolicy: catalog.ProfileSwitchSeamless, PoolPolicy: catalog.PoolStrictProfile, CapabilityRevision: 1, Revision: 1}},
		Revision:           1, ObservedAt: observedAt,
	}
	if errValidate := snapshot.Validate(); errValidate != nil {
		return catalog.Snapshot{}, errValidate
	}
	return snapshot, nil
}

// DiscoverCustomProviderModels reads a standard OpenAI-compatible model list with one explicit same-instance credential.
// DiscoverCustomProviderModels 使用一个显式同实例凭据读取标准 OpenAI 兼容模型清单。
func (s *Service) DiscoverCustomProviderModels(ctx context.Context, providerInstanceID string, credentialID string) (catalog.Snapshot, error) {
	instance, errInstance := s.configurations.GetInstance(ctx, providerInstanceID)
	if errInstance != nil {
		return catalog.Snapshot{}, errInstance
	}
	definition, errDefinition := s.configurations.GetDefinition(ctx, instance.DefinitionID)
	if errDefinition != nil {
		return catalog.Snapshot{}, errDefinition
	}
	if definition.Kind != providerconfig.DefinitionKindCustom || (definition.ProtocolProfileID != protocolchat.ProfileID && definition.ProtocolProfileID != protocolresponses.ProfileID) {
		return catalog.Snapshot{}, errors.New("standard model discovery is supported only for custom OpenAI Chat or Responses providers")
	}
	endpoints, errEndpoints := s.configurations.ListEndpoints(ctx, instance.ID)
	if errEndpoints != nil {
		return catalog.Snapshot{}, errEndpoints
	}
	if len(endpoints) != 1 || endpoints[0].Status != providerconfig.EndpointReady {
		return catalog.Snapshot{}, errors.New("custom model discovery requires exactly one ready endpoint")
	}
	credential, errCredential := s.credential(ctx, instance.ID, credentialID)
	if errCredential != nil {
		return catalog.Snapshot{}, errCredential
	}
	authMethod, authExists := definition.AuthMethod(credential.AuthMethodID)
	if !authExists || authMethod.Type != providerconfig.AuthMethodBearer || credential.Status != providerconfig.CredentialActive {
		return catalog.Snapshot{}, errors.New("custom model discovery requires one active Bearer credential")
	}
	protectedSecret, errSecret := s.secrets.Get(ctx, credential.SecretRef)
	if errSecret != nil {
		return catalog.Snapshot{}, errSecret
	}
	defer clear(protectedSecret)
	request, errRequest := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(endpoints[0].BaseURL, "/")+"/models", nil)
	if errRequest != nil {
		return catalog.Snapshot{}, errRequest
	}
	request.Header.Set("Authorization", "Bearer "+string(protectedSecret))
	request.Header.Set("Accept", "application/json")
	current, errCurrent := s.catalogs.Get(ctx, instance.ID)
	if errCurrent != nil {
		return catalog.Snapshot{}, errCurrent
	}
	if current.Dynamic != nil && strings.TrimSpace(current.Dynamic.ETag) != "" {
		request.Header.Set("If-None-Match", current.Dynamic.ETag)
	}
	response, errDo := s.httpClient.Do(request)
	if errDo != nil {
		discoveryError := fmt.Errorf("discover custom provider models: %w", errDo)
		return catalog.Snapshot{}, s.failCustomModelDiscovery(ctx, current, "provider_discovery_unavailable", discoveryError)
	}
	defer response.Body.Close()
	observedAt := s.now().UTC()
	expiresAt := observedAt.Add(customModelDiscoveryTTL)
	if response.StatusCode == http.StatusNotModified {
		if current.Dynamic == nil {
			return catalog.Snapshot{}, errors.New("custom provider returned not-modified without a last-good dynamic catalog")
		}
		return catalog.ApplyDynamicRefresh(ctx, s.catalogs, catalog.DynamicRefresh{ProviderInstanceID: instance.ID, Authority: catalog.CatalogAuthorityProvider, ETag: response.Header.Get("ETag"), RefreshedAt: observedAt, ExpiresAt: expiresAt, NotModified: true})
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		discoveryError := fmt.Errorf("custom provider model discovery returned status %d", response.StatusCode)
		return catalog.Snapshot{}, s.failCustomModelDiscovery(ctx, current, "provider_discovery_rejected", discoveryError)
	}
	// modelListPayload intentionally decodes only the standard data[].id contract and ignores provider extensions.
	// modelListPayload 有意仅解码标准 data[].id 合同并忽略供应商扩展。
	var modelListPayload struct {
		// Data contains standard OpenAI-compatible model objects.
		// Data 包含标准 OpenAI 兼容模型对象。
		Data []struct {
			// ID is the exact upstream wire model identifier.
			// ID 是精确的上游 Wire 模型标识。
			ID string `json:"id"`
		} `json:"data"`
	}
	encodedResponse, errRead := io.ReadAll(io.LimitReader(response.Body, maximumCustomModelDiscoveryBytes+1))
	if errRead != nil || len(encodedResponse) > maximumCustomModelDiscoveryBytes {
		discoveryError := errors.New("custom provider model list exceeds the allowed boundary")
		return catalog.Snapshot{}, s.failCustomModelDiscovery(ctx, current, "provider_discovery_invalid_response", discoveryError)
	}
	if errDecode := json.Unmarshal(encodedResponse, &modelListPayload); errDecode != nil {
		discoveryError := errors.New("custom provider returned an invalid model list")
		return catalog.Snapshot{}, s.failCustomModelDiscovery(ctx, current, "provider_discovery_invalid_response", discoveryError)
	}
	if modelListPayload.Data == nil {
		discoveryError := errors.New("custom provider model list omitted the standard data array")
		return catalog.Snapshot{}, s.failCustomModelDiscovery(ctx, current, "provider_discovery_invalid_response", discoveryError)
	}
	modelsByUpstreamID := make(map[string]catalog.ProviderModel, len(current.Models))
	for _, model := range current.Models {
		modelsByUpstreamID[model.UpstreamModelID] = model
	}
	offeringsByModelID := make(map[string][]catalog.ModelOffering, len(current.Models))
	for _, offering := range current.Offerings {
		offeringsByModelID[offering.ProviderModelID] = append(offeringsByModelID[offering.ProviderModelID], offering)
	}
	profilesByOfferingID := make(map[string][]catalog.ExecutionProfile, len(current.Offerings))
	for _, profile := range current.Profiles {
		profilesByOfferingID[profile.OfferingID] = append(profilesByOfferingID[profile.OfferingID], profile)
	}
	updated := catalog.Snapshot{
		ProviderInstanceID: instance.ID, Plans: current.Plans, Entitlements: current.Entitlements,
		ServiceEntitlements: current.ServiceEntitlements, Allowances: current.Allowances, Voices: current.Voices,
		DefaultAdditionalParameters: catalog.CloneAdditionalPayloadProjection(current.DefaultAdditionalParameters),
		Revision:                    current.Revision + 1, ObservedAt: observedAt,
	}
	seen := make(map[string]struct{}, len(modelListPayload.Data))
	discoveredModelIDs := make([]string, 0, len(modelListPayload.Data))
	for _, discovered := range modelListPayload.Data {
		upstreamModelID := strings.TrimSpace(discovered.ID)
		if upstreamModelID == "" {
			discoveryError := errors.New("custom provider model list contains an empty model ID")
			return catalog.Snapshot{}, s.failCustomModelDiscovery(ctx, current, "provider_discovery_invalid_response", discoveryError)
		}
		if _, duplicate := seen[upstreamModelID]; duplicate {
			discoveryError := errors.New("custom provider model list contains duplicate model IDs")
			return catalog.Snapshot{}, s.failCustomModelDiscovery(ctx, current, "provider_discovery_invalid_response", discoveryError)
		}
		seen[upstreamModelID] = struct{}{}
		discoveredModelIDs = append(discoveredModelIDs, upstreamModelID)
		if existing, exists := modelsByUpstreamID[upstreamModelID]; exists {
			updated.Models = append(updated.Models, existing)
			for _, offering := range offeringsByModelID[existing.ID] {
				updated.Offerings = append(updated.Offerings, offering)
				updated.Profiles = append(updated.Profiles, profilesByOfferingID[offering.ID]...)
			}
			continue
		}
		initial, errInitial := buildInitialProviderCatalog(instance, definition.ProtocolProfileID, InitialProviderModelInput{UpstreamModelID: upstreamModelID, DisplayName: upstreamModelID}, updated.ObservedAt)
		if errInitial != nil {
			return catalog.Snapshot{}, errInitial
		}
		initial.Models[0].Source = catalog.ModelSourceProviderAPI
		updated.Models = append(updated.Models, initial.Models[0])
		updated.Offerings = append(updated.Offerings, initial.Offerings[0])
		updated.Profiles = append(updated.Profiles, initial.Profiles[0])
	}
	resolver, errResolver := resolve.New(s.configurations, s.catalogs)
	if errResolver != nil {
		return catalog.Snapshot{}, errResolver
	}
	updated.Pools, errResolver = resolver.SummarizeSnapshot(ctx, updated, updated.ObservedAt, updated.Revision)
	if errResolver != nil {
		return catalog.Snapshot{}, errResolver
	}
	slices.Sort(discoveredModelIDs)
	sourceRevision := customModelDiscoveryRevision(discoveredModelIDs)
	return catalog.ApplyDynamicRefresh(ctx, s.catalogs, catalog.DynamicRefresh{ProviderInstanceID: instance.ID, Authority: catalog.CatalogAuthorityProvider, SourceRevision: sourceRevision, ETag: response.Header.Get("ETag"), RefreshedAt: observedAt, ExpiresAt: expiresAt, Candidate: &updated})
}

// failCustomModelDiscovery preserves the provider failure and joins any durable failure-recording error.
// failCustomModelDiscovery 保留供应商失败，并合并任何持久失败记录错误。
func (s *Service) failCustomModelDiscovery(ctx context.Context, current catalog.Snapshot, failureCode string, discoveryError error) error {
	errRecord := s.recordCustomModelDiscoveryFailure(ctx, current, failureCode)
	if errRecord == nil {
		return discoveryError
	}
	return errors.Join(discoveryError, fmt.Errorf("record custom model discovery failure: %w", errRecord))
}

// recordCustomModelDiscoveryFailure marks a prior dynamic snapshot stale while preserving every last-good catalog entity.
// recordCustomModelDiscoveryFailure 在保留全部最后有效目录实体的同时将既有动态快照标记为过期。
func (s *Service) recordCustomModelDiscoveryFailure(ctx context.Context, current catalog.Snapshot, failureCode string) error {
	if current.Dynamic == nil {
		return nil
	}
	_, errRefresh := catalog.ApplyDynamicRefresh(context.WithoutCancel(ctx), s.catalogs, catalog.DynamicRefresh{ProviderInstanceID: current.ProviderInstanceID, Authority: catalog.CatalogAuthorityProvider, RefreshedAt: s.now().UTC(), FailureCode: failureCode})
	return errRefresh
}

// customModelDiscoveryRevision derives a stable order-independent source revision when the provider omits an ETag.
// customModelDiscoveryRevision 在供应商省略 ETag 时派生稳定且与顺序无关的来源修订。
func customModelDiscoveryRevision(modelIDs []string) string {
	digest := sha256.New()
	for _, modelID := range modelIDs {
		_, _ = digest.Write([]byte(modelID))
		_, _ = digest.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil))
}

// SaveCustomProviderModels replaces a custom provider's simplified model set with explicit user-declared capabilities.
// SaveCustomProviderModels 使用显式用户声明能力替换自定义供应商的简化模型集合。
func (s *Service) SaveCustomProviderModels(ctx context.Context, providerInstanceID string, inputs []InitialProviderModelInput) (catalog.Snapshot, error) {
	instance, errInstance := s.configurations.GetInstance(ctx, providerInstanceID)
	if errInstance != nil {
		return catalog.Snapshot{}, errInstance
	}
	definition, errDefinition := s.configurations.GetDefinition(ctx, instance.DefinitionID)
	if errDefinition != nil {
		return catalog.Snapshot{}, errDefinition
	}
	if definition.Kind != providerconfig.DefinitionKindCustom {
		return catalog.Snapshot{}, errors.New("simplified model editing is supported only for custom providers")
	}
	current, errCurrent := s.catalogs.Get(ctx, instance.ID)
	if errCurrent != nil {
		return catalog.Snapshot{}, errCurrent
	}
	existingModels := make(map[string]catalog.ProviderModel, len(current.Models))
	existingOfferings := make(map[string]catalog.ModelOffering, len(current.Models))
	existingProfiles := make(map[string]catalog.ExecutionProfile, len(current.Models))
	for _, model := range current.Models {
		existingModels[model.UpstreamModelID] = model
	}
	for _, offering := range current.Offerings {
		model, exists := existingModelsByID(current.Models, offering.ProviderModelID)
		if exists {
			existingOfferings[model.UpstreamModelID] = offering
		}
	}
	for _, profile := range current.Profiles {
		for upstreamModelID, offering := range existingOfferings {
			if profile.OfferingID == offering.ID && (profile.Default || existingProfiles[upstreamModelID].ID == "") {
				existingProfiles[upstreamModelID] = profile
			}
		}
	}
	updated := catalog.Snapshot{
		ProviderInstanceID: instance.ID, Plans: current.Plans, Entitlements: current.Entitlements,
		ServiceEntitlements: current.ServiceEntitlements, Allowances: current.Allowances, Voices: current.Voices,
		DefaultAdditionalParameters: catalog.CloneAdditionalPayloadProjection(current.DefaultAdditionalParameters),
		Revision:                    current.Revision + 1, ObservedAt: s.now().UTC(),
	}
	seen := make(map[string]struct{}, len(inputs))
	for _, input := range inputs {
		input.UpstreamModelID = strings.TrimSpace(input.UpstreamModelID)
		if _, duplicate := seen[input.UpstreamModelID]; input.UpstreamModelID != "" && duplicate {
			return catalog.Snapshot{}, errors.New("custom provider model editor contains duplicate upstream model IDs")
		}
		seen[input.UpstreamModelID] = struct{}{}
		modelSnapshot, errModel := buildInitialProviderCatalog(instance, definition.ProtocolProfileID, input, updated.ObservedAt)
		if errModel != nil {
			return catalog.Snapshot{}, errModel
		}
		if existing, exists := existingModels[input.UpstreamModelID]; exists {
			modelSnapshot.Models[0].ID = existing.ID
			modelSnapshot.Models[0].Revision = existing.Revision + 1
			if offering, offeringExists := existingOfferings[input.UpstreamModelID]; offeringExists {
				modelSnapshot.Offerings[0].ID = offering.ID
				modelSnapshot.Offerings[0].ProviderModelID = existing.ID
				modelSnapshot.Offerings[0].Revision = offering.Revision + 1
				modelSnapshot.Offerings[0].CapabilityRevision = offering.CapabilityRevision + 1
				modelSnapshot.Profiles[0].OfferingID = offering.ID
				if profile, profileExists := existingProfiles[input.UpstreamModelID]; profileExists {
					modelSnapshot.Profiles[0].ID = profile.ID
					modelSnapshot.Profiles[0].Revision = profile.Revision + 1
					modelSnapshot.Profiles[0].CapabilityRevision = profile.CapabilityRevision + 1
				}
			}
		}
		updated.Models = append(updated.Models, modelSnapshot.Models[0])
		updated.Offerings = append(updated.Offerings, modelSnapshot.Offerings[0])
		updated.Profiles = append(updated.Profiles, modelSnapshot.Profiles[0])
	}
	resolver, errResolver := resolve.New(s.configurations, s.catalogs)
	if errResolver != nil {
		return catalog.Snapshot{}, errResolver
	}
	updated.Pools, errResolver = resolver.SummarizeSnapshot(ctx, updated, updated.ObservedAt, updated.Revision)
	if errResolver != nil {
		return catalog.Snapshot{}, errResolver
	}
	if errSave := s.catalogs.Save(ctx, updated); errSave != nil {
		return catalog.Snapshot{}, errSave
	}
	return updated, nil
}

// SaveCustomProviderAdditionalParameters replaces provider-wide additional request rules for one custom provider.
// SaveCustomProviderAdditionalParameters 替换一个自定义供应商的供应商级附加请求规则。
func (s *Service) SaveCustomProviderAdditionalParameters(ctx context.Context, providerInstanceID string, parameters catalog.AdditionalPayloadProjection) (catalog.Snapshot, error) {
	instance, errInstance := s.configurations.GetInstance(ctx, strings.TrimSpace(providerInstanceID))
	if errInstance != nil {
		return catalog.Snapshot{}, errInstance
	}
	definition, errDefinition := s.configurations.GetDefinition(ctx, instance.DefinitionID)
	if errDefinition != nil {
		return catalog.Snapshot{}, errDefinition
	}
	if definition.Kind != providerconfig.DefinitionKindCustom {
		return catalog.Snapshot{}, errors.New("provider additional parameter editing is supported only for custom providers")
	}
	if errValidate := parameters.Validate(); errValidate != nil {
		return catalog.Snapshot{}, errValidate
	}
	updated, errCurrent := s.catalogs.Get(ctx, instance.ID)
	if errCurrent != nil {
		return catalog.Snapshot{}, errCurrent
	}
	updated.DefaultAdditionalParameters = catalog.CloneAdditionalPayloadProjection(parameters)
	updated.Revision++
	updated.ObservedAt = s.now().UTC()
	if errValidate := updated.Validate(); errValidate != nil {
		return catalog.Snapshot{}, errValidate
	}
	targetResolver, errResolver := resolve.New(s.configurations, s.catalogs)
	if errResolver != nil {
		return catalog.Snapshot{}, errResolver
	}
	updated.Pools, errResolver = targetResolver.SummarizeSnapshot(ctx, updated, updated.ObservedAt, updated.Revision)
	if errResolver != nil {
		return catalog.Snapshot{}, errResolver
	}
	if errSave := s.catalogs.Save(ctx, updated); errSave != nil {
		return catalog.Snapshot{}, errSave
	}
	return updated, nil
}

// existingModelsByID resolves one exact model identifier from a complete custom model slice.
// existingModelsByID 从完整自定义模型切片中解析一个精确模型标识。
func existingModelsByID(models []catalog.ProviderModel, modelID string) (catalog.ProviderModel, bool) {
	for _, model := range models {
		if model.ID == modelID {
			return model, true
		}
	}
	return catalog.ProviderModel{}, false
}

// DeleteProviderConfiguration removes one provider configuration only when it owns no credentials or bindings.
// DeleteProviderConfiguration 仅在供应商配置不拥有凭据或绑定时删除该配置。
func (s *Service) DeleteProviderConfiguration(ctx context.Context, providerInstanceID string) error {
	instance, errInstance := s.configurations.GetInstance(ctx, providerInstanceID)
	if errInstance != nil {
		return errInstance
	}
	credentials, errCredentials := s.configurations.ListCredentials(ctx, instance.ID)
	if errCredentials != nil {
		return errCredentials
	}
	bindings, errBindings := s.configurations.ListBindings(ctx, instance.ID)
	if errBindings != nil {
		return errBindings
	}
	if len(credentials) != 0 || len(bindings) != 0 {
		return errors.New("provider configuration must not contain credentials or bindings before deletion")
	}
	endpoints, errEndpoints := s.configurations.ListEndpoints(ctx, instance.ID)
	if errEndpoints != nil {
		return errEndpoints
	}
	snapshot, errSnapshot := s.catalogs.Get(ctx, instance.ID)
	if errSnapshot != nil {
		return errSnapshot
	}
	if errDeleteCatalog := s.catalogs.Delete(ctx, instance.ID); errDeleteCatalog != nil {
		return errDeleteCatalog
	}
	configuration := providerconfig.ProviderConfiguration{Instance: instance, Endpoints: endpoints}
	if errDeleteConfiguration := s.configurations.DeleteProviderConfiguration(ctx, configuration); errDeleteConfiguration != nil {
		if errRestore := s.catalogs.Save(context.WithoutCancel(ctx), snapshot); errRestore != nil {
			return fmt.Errorf("delete provider configuration: %v; restore catalog: %w", errDeleteConfiguration, errRestore)
		}
		return errDeleteConfiguration
	}
	return nil
}

// buildProviderConfiguration materializes one network Origin that definition-owned channels may share through bindings.
// buildProviderConfiguration 实例化一个可由定义拥有通道通过绑定共享的网络 Origin。
func (s *Service) buildProviderConfiguration(definition providerconfig.ProviderDefinition, input ConfigureProviderInput) (providerconfig.ProviderConfiguration, error) {
	input.Handle = strings.TrimSpace(input.Handle)
	input.DisplayName = strings.TrimSpace(input.DisplayName)
	input.BaseURL = strings.TrimSpace(input.BaseURL)
	input.Region = strings.TrimSpace(input.Region)
	if input.Handle == "" || input.DisplayName == "" {
		return providerconfig.ProviderConfiguration{}, errors.New("provider handle and display name are required")
	}
	instanceID, errInstanceID := generateID("pvi_")
	if errInstanceID != nil {
		return providerconfig.ProviderConfiguration{}, errInstanceID
	}
	baseURL := input.BaseURL
	region := input.Region
	parameters := []providerconfig.EndpointParameterValue(nil)
	if definition.Kind == providerconfig.DefinitionKindSystem {
		if input.BaseURL != "" {
			return providerconfig.ProviderConfiguration{}, errors.New("system provider endpoint addresses are code-owned and cannot be overridden")
		}
		if len(definition.EndpointPresets) != 1 {
			return providerconfig.ProviderConfiguration{}, errors.New("provider definition requires exactly one endpoint preset")
		}
		preset := definition.EndpointPresets[0]
		baseURL = preset.BaseURL
		region = preset.Region
		if input.Region != "" {
			materialized, errMaterialize := preset.MaterializeRegionalBaseURL(input.Region)
			if errMaterialize != nil {
				return providerconfig.ProviderConfiguration{}, errMaterialize
			}
			baseURL = materialized
			region = input.Region
		}
		if preset.BaseURLTemplate != "" {
			if input.Region != "" {
				return providerconfig.ProviderConfiguration{}, errors.New("parameterized system endpoint cannot also select a region")
			}
			materialized, errMaterialize := preset.MaterializeBaseURL(input.EndpointParameters)
			if errMaterialize != nil {
				return providerconfig.ProviderConfiguration{}, errMaterialize
			}
			baseURL = materialized
			valuesByID := make(map[string]string, len(input.EndpointParameters))
			for _, parameter := range input.EndpointParameters {
				valuesByID[parameter.ID] = parameter.Value
			}
			for _, parameter := range preset.Parameters {
				parameters = append(parameters, providerconfig.EndpointParameterValue{ID: parameter.ID, Value: valuesByID[parameter.ID]})
			}
		} else if len(input.EndpointParameters) != 0 {
			return providerconfig.ProviderConfiguration{}, errors.New("selected provider endpoint does not accept parameters")
		}
	} else {
		if input.BaseURL == "" || len(input.EndpointParameters) != 0 {
			return providerconfig.ProviderConfiguration{}, errors.New("custom provider base URL is required and endpoint parameters are unsupported")
		}
	}
	now := s.now().UTC()
	configuration := providerconfig.ProviderConfiguration{Instance: providerconfig.ProviderInstance{
		ID: instanceID, DefinitionID: definition.ID, Handle: input.Handle, DisplayName: input.DisplayName,
		Status: providerconfig.LifecycleDraft, Revision: 1, DefinitionRevision: definition.Revision, CreatedAt: now, UpdatedAt: now,
	}}
	endpointID, errEndpointID := generateID("ep_")
	if errEndpointID != nil {
		return providerconfig.ProviderConfiguration{}, errEndpointID
	}
	configuration.Endpoints = append(configuration.Endpoints, providerconfig.Endpoint{
		ID: endpointID, ProviderInstanceID: instanceID, ChannelID: definition.ProtocolProfileID, BaseURL: baseURL,
		Region: region, Parameters: append([]providerconfig.EndpointParameterValue(nil), parameters...), Status: providerconfig.EndpointReady, Revision: 1,
	})
	if errValidate := providerconfig.ValidateProviderConfiguration(configuration, definition); errValidate != nil {
		return providerconfig.ProviderConfiguration{}, errValidate
	}
	return configuration, nil
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
	// Priority orders this account within the provider instance.
	// Priority 在供应商实例内排列该账号。
	Priority int
	// PlanOptionID selects one code-owned manual plan when the authentication method requires it.
	// PlanOptionID 在认证方式要求时选择一个代码拥有的人工套餐。
	PlanOptionID string
	// ExpiresAt is accepted only from a server-owned provider authorization workflow.
	// ExpiresAt 仅接受由服务端拥有的供应商授权流程提供的值。
	ExpiresAt *time.Time
	// Secret contains transient credential bytes and is never persisted in configuration storage.
	// Secret 包含临时凭据字节且绝不持久化到配置存储。
	Secret []byte
}

// AddCredential stores a secret first and compensates it if metadata persistence fails.
// AddCredential 先保存 Secret，并在元数据持久化失败时进行补偿删除。
func (s *Service) AddCredential(ctx context.Context, input AddCredentialInput) (providerconfig.Credential, error) {
	return s.addCredential(ctx, input, false)
}

// addCredential persists credential metadata after enforcing either direct or provider-owned acquisition boundaries.
// addCredential 在强制执行直接或供应商拥有的获取边界后持久化凭据元数据。
func (s *Service) addCredential(ctx context.Context, input AddCredentialInput, providerOwned bool) (providerconfig.Credential, error) {
	if !providerOwned {
		if input.ExpiresAt != nil {
			return providerconfig.Credential{}, errors.New("direct credentials cannot declare provider-owned expiry metadata")
		}
		if errAuth := s.validateDirectSecretAuthMethod(ctx, input.ProviderInstanceID, input.AuthMethodID); errAuth != nil {
			return providerconfig.Credential{}, errAuth
		}
	} else if errAuth := s.validateProviderOwnedAuthMethod(ctx, input.ProviderInstanceID, input.AuthMethodID); errAuth != nil {
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
	declaredPlan, errPlan := s.declaredPlanForCredential(ctx, input.ProviderInstanceID, input.AuthMethodID, input.PlanOptionID)
	if errPlan != nil {
		if errDelete := s.secrets.Delete(context.WithoutCancel(ctx), secretReference); errDelete != nil {
			return providerconfig.Credential{}, fmt.Errorf("validate credential plan: %v; compensate secret: %w", errPlan, errDelete)
		}
		return providerconfig.Credential{}, errPlan
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
		Priority:           input.Priority,
		DeclaredPlan:       declaredPlan,
		ExpiresAt:          input.ExpiresAt,
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

// CredentialAttachment contains one newly attached credential and every generated endpoint binding.
// CredentialAttachment 包含一个新附加的凭据及其全部生成的入口绑定。
type CredentialAttachment struct {
	// Credential is the newly persisted non-secret credential metadata.
	// Credential 是新持久化的非秘密凭据元数据。
	Credential providerconfig.Credential
	// Bindings closes every definition-authorized endpoint path for the credential.
	// Bindings 为该凭据闭合全部定义允许的入口路径。
	Bindings []providerconfig.AccessBinding
}

// AttachCredential adds one direct-secret credential to an existing provider configuration and activates its access graph.
// AttachCredential 向既有供应商配置添加一个直接 Secret 凭据并激活其访问图。
func (s *Service) AttachCredential(ctx context.Context, input AddCredentialInput) (CredentialAttachment, error) {
	return s.attachCredential(ctx, input, false)
}

// attachCredential closes one credential access graph after its acquisition boundary has been selected explicitly.
// attachCredential 在显式选择凭据获取边界后闭合一个凭据访问图。
func (s *Service) attachCredential(ctx context.Context, input AddCredentialInput, providerOwned bool) (CredentialAttachment, error) {
	instance, errInstance := s.configurations.GetInstance(ctx, input.ProviderInstanceID)
	if errInstance != nil {
		return CredentialAttachment{}, errInstance
	}
	definition, errDefinition := s.configurations.GetDefinition(ctx, instance.DefinitionID)
	if errDefinition != nil {
		return CredentialAttachment{}, errDefinition
	}
	endpoints, errEndpoints := s.configurations.ListEndpoints(ctx, instance.ID)
	if errEndpoints != nil {
		return CredentialAttachment{}, errEndpoints
	}
	if len(endpoints) == 0 {
		return CredentialAttachment{}, fmt.Errorf("%w: provider configuration has no endpoint", ErrConfigurationIncomplete)
	}
	expectedBindings, errBindings := s.configurations.ListBindings(ctx, instance.ID)
	if errBindings != nil {
		return CredentialAttachment{}, errBindings
	}
	originalSnapshot, errSnapshot := s.catalogs.Get(ctx, instance.ID)
	if errSnapshot != nil {
		return CredentialAttachment{}, errSnapshot
	}
	credential, errCredential := s.addCredential(ctx, input, providerOwned)
	if errCredential != nil {
		return CredentialAttachment{}, errCredential
	}
	channels := definition.ChannelIDs()
	bindings := make([]providerconfig.AccessBinding, 0, len(channels))
	for _, channelID := range channels {
		if !definition.ChannelAllowsAuth(channelID, credential.AuthMethodID) {
			continue
		}
		endpoint, errEndpoint := endpointForChannel(endpoints, channelID)
		if errEndpoint != nil {
			return CredentialAttachment{}, s.compensateCredentialAttachment(ctx, instance, credential, originalSnapshot, errEndpoint)
		}
		bindingID, errBindingID := generateID("bind_")
		if errBindingID != nil {
			return CredentialAttachment{}, s.compensateCredentialAttachment(ctx, instance, credential, originalSnapshot, errBindingID)
		}
		bindings = append(bindings, providerconfig.AccessBinding{
			ID: bindingID, ProviderInstanceID: instance.ID, ChannelID: channelID, EndpointID: endpoint.ID,
			CredentialID: credential.ID, Priority: definition.Priority, Enabled: true, Revision: 1,
		})
	}
	if len(bindings) == 0 {
		return CredentialAttachment{}, s.compensateCredentialAttachment(ctx, instance, credential, originalSnapshot, errors.New("credential authentication method is not allowed by any configured channel"))
	}
	replacement := providerconfig.AccessGraphReplacement{
		ProviderInstanceID: instance.ID, ExpectedEndpoints: endpoints, ExpectedBindings: expectedBindings,
		Endpoints: endpoints, Bindings: append(append([]providerconfig.AccessBinding(nil), expectedBindings...), bindings...),
	}
	if errReplace := s.configurations.ReplaceAccessGraph(ctx, replacement); errReplace != nil {
		return CredentialAttachment{}, s.compensateCredentialAttachment(ctx, instance, credential, originalSnapshot, errReplace)
	}
	updatedSnapshot, errUpdatedSnapshot := s.catalogs.Get(ctx, instance.ID)
	if errUpdatedSnapshot != nil {
		return CredentialAttachment{}, s.compensateCredentialAttachment(ctx, instance, credential, originalSnapshot, errUpdatedSnapshot)
	}
	mutationTime := s.now().UTC()
	updatedSnapshot.Revision++
	updatedSnapshot.ObservedAt = mutationTime
	updatedSnapshot.Pools = nil
	if definition.ID == "system_kimi_coding_plan" && credential.DeclaredPlan != nil {
		updatedSnapshot, errUpdatedSnapshot = providerkimi.ApplyDeclaredMembership(updatedSnapshot, credential)
		if errUpdatedSnapshot != nil {
			return CredentialAttachment{}, s.compensateCredentialAttachment(ctx, instance, credential, originalSnapshot, errUpdatedSnapshot)
		}
	}
	if definition.DriverID == "codex" && providerOwned {
		metadata, errMetadata := provideropenai.CodexCredentialMetadataFromToken(input.Secret, instance, credential, mutationTime)
		if errMetadata != nil {
			return CredentialAttachment{}, s.compensateCredentialAttachment(ctx, instance, credential, originalSnapshot, errMetadata)
		}
		if metadata.Plan == nil {
			return CredentialAttachment{}, s.compensateCredentialAttachment(ctx, instance, credential, originalSnapshot, errors.New("Codex credential metadata omitted its plan"))
		}
		updatedSnapshot.Plans = append(updatedSnapshot.Plans, *metadata.Plan)
		updatedSnapshot.Entitlements = append(updatedSnapshot.Entitlements, metadata.Entitlements...)
	}
	resolver, errResolver := resolve.New(s.configurations, s.catalogs)
	if errResolver != nil {
		return CredentialAttachment{}, s.compensateCredentialAttachment(ctx, instance, credential, originalSnapshot, errResolver)
	}
	pools, errPools := resolver.SummarizeSnapshot(ctx, updatedSnapshot, mutationTime, updatedSnapshot.Revision)
	if errPools != nil {
		return CredentialAttachment{}, s.compensateCredentialAttachment(ctx, instance, credential, originalSnapshot, errPools)
	}
	updatedSnapshot.Pools = pools
	if errSaveCatalog := s.catalogs.Save(ctx, updatedSnapshot); errSaveCatalog != nil {
		return CredentialAttachment{}, s.compensateCredentialAttachment(ctx, instance, credential, originalSnapshot, errSaveCatalog)
	}
	if _, errActivate := s.ActivateInstance(ctx, instance.ID); errActivate != nil {
		return CredentialAttachment{}, s.compensateCredentialAttachment(ctx, instance, credential, originalSnapshot, errActivate)
	}
	return CredentialAttachment{Credential: credential, Bindings: bindings}, nil
}

// endpointForChannel selects an exact legacy channel endpoint or the sole shared Origin endpoint.
// endpointForChannel 选择精确的旧通道端点或唯一的共享 Origin 端点。
func endpointForChannel(endpoints []providerconfig.Endpoint, channelID string) (providerconfig.Endpoint, error) {
	for _, endpoint := range endpoints {
		if endpoint.ChannelID == channelID {
			return endpoint, nil
		}
	}
	if len(endpoints) == 1 {
		return endpoints[0], nil
	}
	return providerconfig.Endpoint{}, fmt.Errorf("provider configuration has no unambiguous endpoint for channel %q", channelID)
}

// AttachAcquiredCredentialInput contains provider-owned credential material and its exact existing instance target.
// AttachAcquiredCredentialInput 包含供应商拥有的凭据材料及其精确既有实例目标。
type AttachAcquiredCredentialInput struct {
	// ProviderInstanceID identifies the existing provider configuration.
	// ProviderInstanceID 标识既有供应商配置。
	ProviderInstanceID string
	// AuthMethodID identifies the completed definition-owned authorization method.
	// AuthMethodID 标识已完成的定义拥有授权方式。
	AuthMethodID string
	// Label is used only when the provider does not expose a safe account label.
	// Label 仅在供应商不提供安全账号标签时使用。
	Label string
	// Secret contains transient server-acquired credential material.
	// Secret 包含临时的服务端获取凭据材料。
	Secret []byte
}

// AttachAcquiredCredential derives provider identity from protected material and attaches it to an existing instance.
// AttachAcquiredCredential 从受保护材料派生供应商身份并将其附加到既有实例。
func (s *Service) AttachAcquiredCredential(ctx context.Context, input AttachAcquiredCredentialInput) (CredentialAttachment, error) {
	instance, errInstance := s.configurations.GetInstance(ctx, input.ProviderInstanceID)
	if errInstance != nil {
		return CredentialAttachment{}, errInstance
	}
	definition, errDefinition := s.configurations.GetDefinition(ctx, instance.DefinitionID)
	if errDefinition != nil {
		return CredentialAttachment{}, errDefinition
	}
	credentialInput := AddCredentialInput{ProviderInstanceID: instance.ID, AuthMethodID: input.AuthMethodID, Label: strings.TrimSpace(input.Label), Secret: input.Secret}
	switch definition.DriverID {
	case "kimi":
		token, errToken := providerkimi.UnmarshalToken(input.Secret)
		if errToken != nil {
			return CredentialAttachment{}, errToken
		}
		credentialInput.ExpiresAt = providerTokenExpiry(token.ExpiresAt)
	case "minimax":
		if input.AuthMethodID != "device_flow" {
			return CredentialAttachment{}, errors.New("MiniMax provider-owned credential attachment requires device_flow")
		}
		token, errToken := providerminimax.UnmarshalToken(input.Secret)
		if errToken != nil {
			return CredentialAttachment{}, errToken
		}
		regionMatches := (definition.ID == "system_minimax_api" && token.Region == "global") || (definition.ID == "system_minimax_cn" && token.Region == "cn")
		if !regionMatches {
			return CredentialAttachment{}, errors.New("MiniMax token region does not match the selected provider definition")
		}
		credentialInput.ExpiresAt = providerTokenExpiry(token.ExpiresAt.Unix())
	case "xai":
		token, errToken := providerxai.UnmarshalToken(input.Secret)
		if errToken != nil {
			return CredentialAttachment{}, errToken
		}
		credentialInput.PrincipalKey = token.Subject
		if credentialInput.PrincipalKey == "" {
			credentialInput.PrincipalKey = token.Email
		}
		if token.Email != "" {
			credentialInput.Label = token.Email
		} else if credentialInput.Label == "" {
			credentialInput.Label = token.Subject
		}
		credentialInput.ExpiresAt = providerTokenExpiry(token.ExpiresAt)
	case "codex":
		token, errToken := provideropenai.UnmarshalCodexToken(input.Secret)
		if errToken != nil {
			return CredentialAttachment{}, errToken
		}
		if strings.TrimSpace(token.AccountID) == "" {
			return CredentialAttachment{}, errors.New("Codex account credential requires the provider-reported account ID")
		}
		credentialInput.PrincipalKey = token.AccountID
		credentialInput.ScopeRefs = []providerconfig.ScopeReference{{Kind: "account", ID: token.AccountID}}
		credentialInput.Label = token.Email
		if credentialInput.Label == "" {
			credentialInput.Label = token.AccountID
		}
		credentialInput.ExpiresAt = providerTokenExpiry(token.ExpiresAt.Unix())
	case "claude":
		token, errToken := provideranthropic.UnmarshalClaudeToken(input.Secret)
		if errToken != nil {
			return CredentialAttachment{}, errToken
		}
		credentialInput.PrincipalKey = token.AccountID
		if credentialInput.PrincipalKey == "" {
			credentialInput.PrincipalKey = token.Email
		}
		if token.OrganizationID != "" {
			credentialInput.ScopeRefs = []providerconfig.ScopeReference{{Kind: string(catalog.ScopeOrganization), ID: token.OrganizationID}}
		}
		credentialInput.Label = token.Email
		if credentialInput.Label == "" {
			credentialInput.Label = token.AccountID
		}
		credentialInput.ExpiresAt = providerTokenExpiry(token.ExpiresAt)
	case "antigravity":
		token, errToken := providergoogle.UnmarshalAntigravityToken(input.Secret)
		if errToken != nil {
			return CredentialAttachment{}, errToken
		}
		credentialInput.PrincipalKey = token.Email
		credentialInput.ScopeRefs = []providerconfig.ScopeReference{{Kind: "project", ID: token.ProjectID}}
		credentialInput.Label = token.Email
		credentialInput.ExpiresAt = providerTokenExpiry(token.ExpiresAt)
	case "vertex":
		credential, errCredential := providergoogle.UnmarshalVertexCredential(input.Secret)
		if errCredential != nil {
			return CredentialAttachment{}, errCredential
		}
		endpoints, errEndpoints := s.configurations.ListEndpoints(ctx, instance.ID)
		if errEndpoints != nil {
			return CredentialAttachment{}, errEndpoints
		}
		if len(endpoints) != 1 || endpoints[0].Region != credential.Location || endpoints[0].BaseURL != providergoogle.VertexBaseURL(credential.Location) {
			return CredentialAttachment{}, errors.New("Vertex credential location does not match the configured provider endpoint")
		}
		credentialInput.PrincipalKey = credential.Email
		credentialInput.ScopeRefs = []providerconfig.ScopeReference{{Kind: "project", ID: credential.ProjectID}}
		credentialInput.Label = credential.Email
	default:
		return CredentialAttachment{}, errors.New("provider-owned credential attachment is not registered for this provider")
	}
	if strings.TrimSpace(credentialInput.Label) == "" {
		credentialInput.Label = instance.DisplayName
	}
	return s.attachCredential(ctx, credentialInput, true)
}

// declaredPlanForCredential validates one manual plan selection against the exact instance authentication method.
// declaredPlanForCredential 根据精确实例认证方式校验一个人工套餐选择。
func (s *Service) declaredPlanForCredential(ctx context.Context, instanceID string, authMethodID string, planOptionID string) (*providerconfig.DeclaredPlanSelection, error) {
	instance, errInstance := s.configurations.GetInstance(ctx, instanceID)
	if errInstance != nil {
		return nil, errInstance
	}
	definition, errDefinition := s.configurations.GetDefinition(ctx, instance.DefinitionID)
	if errDefinition != nil {
		return nil, errDefinition
	}
	authMethod, exists := definition.AuthMethod(authMethodID)
	if !exists {
		return nil, errors.New("credential authentication method is not declared by its provider definition")
	}
	acquisition := authMethod.PlanAcquisition
	if acquisition == "" {
		acquisition = providerconfig.PlanAcquisitionUnavailable
	}
	planOptionID = strings.TrimSpace(planOptionID)
	if planOptionID == "" {
		if acquisition == providerconfig.PlanAcquisitionManualRequired {
			return nil, errors.New("credential authentication method requires a manual plan selection")
		}
		return nil, nil
	}
	if acquisition != providerconfig.PlanAcquisitionManualRequired && acquisition != providerconfig.PlanAcquisitionManualOptional {
		return nil, errors.New("credential authentication method does not accept a manual plan selection")
	}
	planOption, planExists := definition.PlanOption(planOptionID)
	if !planExists || !planOption.ManuallySelectable || !definition.AuthMethodAllowsPlan(authMethod.ID, planOptionID) {
		return nil, errors.New("credential plan option is not valid for its authentication method")
	}
	return &providerconfig.DeclaredPlanSelection{PlanOptionID: planOptionID, DeclaredAt: s.now().UTC(), Revision: 1}, nil
}

// compensateCredentialAttachment removes a partially attached credential and restores the previous catalog content at a newer revision.
// compensateCredentialAttachment 删除部分附加的凭据，并以更高修订恢复先前目录内容。
func (s *Service) compensateCredentialAttachment(ctx context.Context, instance providerconfig.ProviderInstance, credential providerconfig.Credential, originalSnapshot catalog.Snapshot, cause error) error {
	compensationContext := context.WithoutCancel(ctx)
	_, errDelete := s.DeleteCredential(compensationContext, instance.ID, credential.ID)
	currentSnapshot, errCurrent := s.catalogs.Get(compensationContext, instance.ID)
	var errCatalog error
	if errCurrent == nil && currentSnapshot.Revision > originalSnapshot.Revision {
		originalSnapshot.Revision = currentSnapshot.Revision + 1
		originalSnapshot.ObservedAt = s.now().UTC()
		errCatalog = s.catalogs.Save(compensationContext, originalSnapshot)
	}
	if errDelete != nil || (errCurrent != nil && !errors.Is(errCurrent, catalog.ErrSnapshotNotFound)) || errCatalog != nil {
		return fmt.Errorf("attach credential: %w; compensate credential: %v; inspect catalog: %v; compensate catalog: %v", cause, errDelete, errCurrent, errCatalog)
	}
	return cause
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

// ReauthorizeCredentialInput contains one server-acquired replacement token and its exact acquisition method.
// ReauthorizeCredentialInput 包含一个服务端获取的替代 Token 及其精确获取方式。
type ReauthorizeCredentialInput struct {
	// ProviderInstanceID owns the existing credential.
	// ProviderInstanceID 拥有既有凭据。
	ProviderInstanceID string
	// CredentialID identifies the credential whose secret is replaced.
	// CredentialID 标识需要替换 Secret 的凭据。
	CredentialID string
	// AuthMethodID binds the completed flow to the original credential method.
	// AuthMethodID 将已完成流程绑定到原始凭据方式。
	AuthMethodID string
	// Secret is the validated provider-issued protected document.
	// Secret 是经过校验的供应商签发受保护文档。
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

// ReauthorizeCredential replaces one provider-owned token only after immutable account identity validation.
// ReauthorizeCredential 仅在不可变账号身份校验后替换一个供应商拥有的 Token。
func (s *Service) ReauthorizeCredential(ctx context.Context, input ReauthorizeCredentialInput) (providerconfig.Credential, error) {
	credential, errCredential := s.credential(ctx, input.ProviderInstanceID, input.CredentialID)
	if errCredential != nil {
		return providerconfig.Credential{}, errCredential
	}
	if credential.AuthMethodID != input.AuthMethodID {
		return providerconfig.Credential{}, errors.New("reauthorization method does not match the existing credential")
	}
	instance, errInstance := s.configurations.GetInstance(ctx, input.ProviderInstanceID)
	if errInstance != nil {
		return providerconfig.Credential{}, errInstance
	}
	if len(input.Secret) == 0 {
		return providerconfig.Credential{}, errors.New("reauthorization credential is required")
	}
	var expiresAt *time.Time
	switch instance.DefinitionID {
	case "system_kimi_coding_plan":
		if input.AuthMethodID != "device_flow" {
			return providerconfig.Credential{}, errors.New("Kimi reauthorization requires device_flow")
		}
		token, errToken := providerkimi.UnmarshalToken(input.Secret)
		if errToken != nil {
			return providerconfig.Credential{}, errToken
		}
		if credential.PrincipalKey != "" || len(credential.ScopeRefs) != 0 {
			return providerconfig.Credential{}, errors.New("Kimi credential identity is inconsistent")
		}
		expiresAt = providerTokenExpiry(token.ExpiresAt)
	case "system_minimax_api", "system_minimax_cn":
		if input.AuthMethodID != "device_flow" {
			return providerconfig.Credential{}, errors.New("MiniMax reauthorization requires device_flow")
		}
		token, errToken := providerminimax.UnmarshalToken(input.Secret)
		if errToken != nil {
			return providerconfig.Credential{}, errToken
		}
		regionMatches := (instance.DefinitionID == "system_minimax_api" && token.Region == "global") || (instance.DefinitionID == "system_minimax_cn" && token.Region == "cn")
		if !regionMatches {
			return providerconfig.Credential{}, errors.New("MiniMax replacement token region does not match the existing provider definition")
		}
		if credential.PrincipalKey != "" || len(credential.ScopeRefs) != 0 {
			return providerconfig.Credential{}, errors.New("MiniMax credential identity is inconsistent")
		}
		expiresAt = providerTokenExpiry(token.ExpiresAt.Unix())
	case "system_xai_oauth":
		token, errToken := providerxai.UnmarshalToken(input.Secret)
		if errToken != nil {
			return providerconfig.Credential{}, errToken
		}
		principal := token.Subject
		if principal == "" {
			principal = token.Email
		}
		if principal == "" || principal != credential.PrincipalKey {
			return providerconfig.Credential{}, errors.New("xAI reauthorization account does not match the existing credential")
		}
		expiresAt = providerTokenExpiry(token.ExpiresAt)
	case "system_openai_codex":
		token, errToken := provideropenai.UnmarshalCodexToken(input.Secret)
		if errToken != nil {
			return providerconfig.Credential{}, errToken
		}
		if token.AccountID == "" || token.AccountID != credential.PrincipalKey {
			return providerconfig.Credential{}, errors.New("Codex reauthorization account does not match the existing credential")
		}
		expiresAt = providerTokenExpiry(token.ExpiresAt.Unix())
	case "system_anthropic_claude_code":
		token, errToken := provideranthropic.UnmarshalClaudeToken(input.Secret)
		if errToken != nil {
			return providerconfig.Credential{}, errToken
		}
		principal := token.AccountID
		if principal == "" {
			principal = token.Email
		}
		if principal == "" || principal != credential.PrincipalKey {
			return providerconfig.Credential{}, errors.New("Claude reauthorization account does not match the existing credential")
		}
		expectedScopes := []providerconfig.ScopeReference(nil)
		if token.OrganizationID != "" {
			expectedScopes = []providerconfig.ScopeReference{{Kind: "organization", ID: token.OrganizationID}}
		}
		if !slices.Equal(expectedScopes, credential.ScopeRefs) {
			return providerconfig.Credential{}, errors.New("Claude reauthorization organization does not match the existing credential")
		}
		expiresAt = providerTokenExpiry(token.ExpiresAt)
	case "system_google_antigravity":
		token, errToken := providergoogle.UnmarshalAntigravityToken(input.Secret)
		if errToken != nil {
			return providerconfig.Credential{}, errToken
		}
		expectedScopes := []providerconfig.ScopeReference{{Kind: "project", ID: token.ProjectID}}
		if token.Email == "" || token.Email != credential.PrincipalKey || !slices.Equal(expectedScopes, credential.ScopeRefs) {
			return providerconfig.Credential{}, errors.New("Antigravity reauthorization account or project does not match the existing credential")
		}
		expiresAt = providerTokenExpiry(token.ExpiresAt)
	case "system_google_vertex":
		if input.AuthMethodID != "service_account" {
			return providerconfig.Credential{}, errors.New("Vertex reauthorization requires service_account")
		}
		vertexCredential, errToken := providergoogle.UnmarshalVertexCredential(input.Secret)
		if errToken != nil {
			return providerconfig.Credential{}, errToken
		}
		currentProtectedValue, errCurrentSecret := s.secrets.Get(ctx, credential.SecretRef)
		if errCurrentSecret != nil {
			return providerconfig.Credential{}, errCurrentSecret
		}
		currentVertexCredential, errCurrentCredential := providergoogle.UnmarshalVertexCredential(currentProtectedValue)
		clear(currentProtectedValue)
		if errCurrentCredential != nil {
			return providerconfig.Credential{}, errCurrentCredential
		}
		expectedScopes := []providerconfig.ScopeReference{{Kind: "project", ID: vertexCredential.ProjectID}}
		if vertexCredential.Email == "" || vertexCredential.Email != credential.PrincipalKey || !slices.Equal(expectedScopes, credential.ScopeRefs) {
			return providerconfig.Credential{}, errors.New("Vertex replacement account or project does not match the existing credential")
		}
		// The endpoint region belongs to the immutable instance route, so credential rotation preserves the verified current location.
		// 入口区域属于不可变实例路由，因此凭据轮换保留已验证的当前区域。
		vertexCredential.Location = currentVertexCredential.Location
		normalizedReplacement, errReplacement := providergoogle.MarshalVertexCredential(vertexCredential)
		if errReplacement != nil {
			return providerconfig.Credential{}, errReplacement
		}
		defer clear(normalizedReplacement)
		input.Secret = normalizedReplacement
	default:
		return providerconfig.Credential{}, errors.New("provider credential does not support server-owned reauthorization")
	}
	credential.ExpiresAt = expiresAt
	credential.Status = providerconfig.CredentialActive
	credential.CoolingUntil = nil
	return persistCredentialSecretReplacement(ctx, s.configurations, s.secrets, credential, input.Secret)
}

// DeleteCredential removes one credential graph and its protected secret while retaining provider configuration and catalog state.
// DeleteCredential 删除一个凭据图及其受保护 Secret，同时保留供应商配置与目录状态。
func (s *Service) DeleteCredential(ctx context.Context, providerInstanceID string, credentialID string) (providerconfig.CredentialDeletion, error) {
	instance, errInstance := s.configurations.GetInstance(ctx, providerInstanceID)
	if errInstance != nil {
		return providerconfig.CredentialDeletion{}, errInstance
	}
	bindings, errBindings := s.configurations.ListBindings(ctx, providerInstanceID)
	if errBindings != nil {
		return providerconfig.CredentialDeletion{}, errBindings
	}
	credentialBindings := make([]providerconfig.AccessBinding, 0)
	for _, binding := range bindings {
		if binding.CredentialID == credentialID {
			credentialBindings = append(credentialBindings, binding)
		}
	}
	snapshot, errSnapshot := s.catalogs.Get(ctx, providerInstanceID)
	if errSnapshot != nil && !errors.Is(errSnapshot, catalog.ErrSnapshotNotFound) {
		return providerconfig.CredentialDeletion{}, errSnapshot
	}
	deletion, errDelete := s.configurations.DeleteCredentialGraph(ctx, providerInstanceID, credentialID)
	if errDelete != nil {
		return providerconfig.CredentialDeletion{}, errDelete
	}
	if errSnapshot == nil {
		mutationTime := s.now().UTC()
		updatedSnapshot := removeCredentialCommercialMetadata(snapshot, credentialID)
		updatedSnapshot.Revision++
		updatedSnapshot.ObservedAt = mutationTime
		updatedSnapshot.Pools = nil
		resolver, errResolver := resolve.New(s.configurations, s.catalogs)
		if errResolver == nil {
			updatedSnapshot.Pools, errResolver = resolver.SummarizeSnapshot(ctx, updatedSnapshot, mutationTime, updatedSnapshot.Revision)
		}
		if errResolver == nil {
			errResolver = s.catalogs.Save(ctx, updatedSnapshot)
		}
		if errResolver != nil {
			errRestore := s.restoreDeletedCredentialConfiguration(context.WithoutCancel(ctx), instance, deletion.Credential, credentialBindings)
			if errRestore != nil {
				return deletion, fmt.Errorf("update credential-deletion catalog: %v; restore configuration: %w", errResolver, errRestore)
			}
			return deletion, errResolver
		}
	}
	cleanupContext := context.WithoutCancel(ctx)
	if errSecret := s.secrets.Delete(cleanupContext, deletion.Credential.SecretRef); errSecret != nil {
		return deletion, fmt.Errorf("deleted credential configuration but could not delete protected secret: %w", errSecret)
	}
	return deletion, nil
}

// restoreDeletedCredentialConfiguration restores one credential graph after catalog mutation failure.
// restoreDeletedCredentialConfiguration 在目录变更失败后恢复一个凭据图。
func (s *Service) restoreDeletedCredentialConfiguration(ctx context.Context, originalInstance providerconfig.ProviderInstance, credential providerconfig.Credential, bindings []providerconfig.AccessBinding) error {
	currentInstance, errCurrent := s.configurations.GetInstance(ctx, originalInstance.ID)
	if errCurrent != nil {
		return errCurrent
	}
	if errCredential := s.configurations.SaveCredential(ctx, credential); errCredential != nil {
		return errCredential
	}
	for _, binding := range bindings {
		if errBinding := s.configurations.SaveBinding(ctx, binding); errBinding != nil {
			return errBinding
		}
	}
	if currentInstance.Status != originalInstance.Status {
		originalInstance.Revision = currentInstance.Revision + 1
		originalInstance.UpdatedAt = s.now().UTC()
		if errInstance := s.configurations.SaveInstance(ctx, originalInstance); errInstance != nil {
			return errInstance
		}
	}
	return nil
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

// validateProviderOwnedAuthMethod permits only interactive or service-account methods completed by server-owned workflows.
// validateProviderOwnedAuthMethod 仅允许由服务端拥有流程完成的交互式或服务账号认证方式。
func (s *Service) validateProviderOwnedAuthMethod(ctx context.Context, instanceID string, authMethodID string) error {
	instance, errInstance := s.configurations.GetInstance(ctx, instanceID)
	if errInstance != nil {
		return errInstance
	}
	definition, errDefinition := s.configurations.GetDefinition(ctx, instance.DefinitionID)
	if errDefinition != nil {
		return errDefinition
	}
	authMethod, exists := definition.AuthMethod(authMethodID)
	if !exists || !providerOwnsCredentialMaterial(authMethod.Type) {
		return errors.New("provider-owned credential requires a definition-owned interactive or service-account authentication method")
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
	// DefaultAdditionalParameters contains provider-wide request mutations inherited by every model.
	// DefaultAdditionalParameters 包含由每个模型继承的供应商级请求变更。
	DefaultAdditionalParameters catalog.AdditionalPayloadProjection
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
		ProviderInstanceID:          instance.ID,
		DefaultAdditionalParameters: catalog.CloneAdditionalPayloadProjection(input.DefaultAdditionalParameters),
		Models:                      models,
		Offerings:                   offerings,
		Profiles:                    profiles,
		Revision:                    revision,
		ObservedAt:                  input.ObservedAt,
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
