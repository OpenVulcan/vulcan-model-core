package providerconfig

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

var (
	// ErrInvalidConfiguration reports a structurally invalid domain record.
	// ErrInvalidConfiguration 表示领域记录结构无效。
	ErrInvalidConfiguration = errors.New("invalid provider configuration")
	// stableIdentifierPattern restricts persisted identifiers to portable lowercase values.
	// stableIdentifierPattern 将持久化标识限制为可移植的小写值。
	stableIdentifierPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
)

// Validate verifies one protocol profile without assuming a concrete adapter implementation.
// Validate 校验一个协议 Profile 且不假设具体 Adapter 实现。
func (p ProtocolProfile) Validate() error {
	if err := validateIdentifier("protocol profile id", p.ID); err != nil {
		return err
	}
	if strings.TrimSpace(p.Version) == "" {
		return invalid("protocol profile version is required")
	}
	if strings.TrimSpace(p.DisplayName) == "" {
		return invalid("protocol profile display name is required")
	}
	if !validSupportStatus(p.ModelDiscovery) {
		return invalid("protocol profile model discovery status is invalid")
	}
	for _, authMethod := range p.AllowedAuthMethods {
		if !validAuthMethodType(authMethod) {
			return invalid("protocol profile auth method %q is invalid", authMethod)
		}
	}
	return nil
}

// Validate verifies one provider definition and its internally owned identifiers.
// Validate 校验一个供应商定义及其内部拥有的标识。
func (d ProviderDefinition) Validate() error {
	if err := validateIdentifier("provider definition id", d.ID); err != nil {
		return err
	}
	switch d.Kind {
	case DefinitionKindSystem:
		if !strings.HasPrefix(d.ID, "system_") {
			return invalid("system provider definition id must start with system_")
		}
		if strings.TrimSpace(d.DriverID) == "" || strings.TrimSpace(d.DriverVersion) == "" {
			return invalid("system provider definition requires driver id and version")
		}
	case DefinitionKindCustom:
		if !strings.HasPrefix(d.ID, "custom_") {
			return invalid("custom provider definition id must start with custom_")
		}
		if d.DriverID != "" || d.DriverVersion != "" {
			return invalid("custom provider definition cannot register a trusted driver")
		}
		if len(d.Channels) != 1 {
			return invalid("custom provider definition requires exactly one channel")
		}
	default:
		return invalid("provider definition kind %q is invalid", d.Kind)
	}
	if strings.TrimSpace(d.DisplayName) == "" || strings.TrimSpace(d.ConfigSchemaVersion) == "" {
		return invalid("provider definition display name and config schema version are required")
	}
	if d.Revision == 0 {
		return invalid("provider definition revision must be positive")
	}
	if len(d.Channels) == 0 || len(d.AuthMethods) == 0 {
		return invalid("provider definition requires at least one channel and auth method")
	}
	authMethods := make(map[string]struct{}, len(d.AuthMethods))
	for _, authMethod := range d.AuthMethods {
		if err := authMethod.Validate(); err != nil {
			return err
		}
		if _, exists := authMethods[authMethod.ID]; exists {
			return invalid("duplicate auth method id %q", authMethod.ID)
		}
		authMethods[authMethod.ID] = struct{}{}
	}
	channels := make(map[string]struct{}, len(d.Channels))
	for _, channel := range d.Channels {
		if err := channel.Validate(); err != nil {
			return err
		}
		if _, exists := channels[channel.ID]; exists {
			return invalid("duplicate provider channel id %q", channel.ID)
		}
		channels[channel.ID] = struct{}{}
		for _, authMethodID := range channel.AuthMethodIDs {
			if _, exists := authMethods[authMethodID]; !exists {
				return invalid("provider channel %q references unknown auth method %q", channel.ID, authMethodID)
			}
		}
	}
	if err := d.Features.Validate(); err != nil {
		return err
	}
	return nil
}

// Validate verifies one optional provider feature set.
// Validate 校验一组可选供应商能力。
func (f ProviderFeatureSet) Validate() error {
	statuses := []SupportStatus{f.ModelDiscovery, f.PlanReader, f.EntitlementReader, f.AllowanceReader}
	for _, status := range statuses {
		if !validSupportStatus(status) {
			return invalid("provider feature status %q is invalid", status)
		}
	}
	return nil
}

// Validate verifies one provider authentication method definition.
// Validate 校验一个供应商认证方式定义。
func (a AuthMethodDefinition) Validate() error {
	if err := validateIdentifier("auth method id", a.ID); err != nil {
		return err
	}
	if !validAuthMethodType(a.Type) {
		return invalid("auth method type %q is invalid", a.Type)
	}
	return nil
}

// Validate verifies one provider channel definition.
// Validate 校验一个供应商通道定义。
func (c ProviderChannel) Validate() error {
	if err := validateIdentifier("provider channel id", c.ID); err != nil {
		return err
	}
	if err := validateIdentifier("protocol profile id", c.ProtocolProfileID); err != nil {
		return err
	}
	if strings.TrimSpace(c.EndpointProfileID) == "" {
		return invalid("provider channel endpoint profile id is required")
	}
	if len(c.AuthMethodIDs) == 0 {
		return invalid("provider channel requires at least one auth method")
	}
	for _, authMethodID := range c.AuthMethodIDs {
		if err := validateIdentifier("provider channel auth method id", authMethodID); err != nil {
			return err
		}
	}
	return nil
}

// Validate verifies one persisted provider instance.
// Validate 校验一个持久化供应商实例。
func (i ProviderInstance) Validate() error {
	if err := validatePrefixedIdentifier("provider instance id", i.ID, "pvi_"); err != nil {
		return err
	}
	if !strings.HasPrefix(i.DefinitionID, "system_") && !strings.HasPrefix(i.DefinitionID, "custom_") {
		return invalid("provider instance definition id must start with system_ or custom_")
	}
	if err := validateIdentifier("provider instance handle", i.Handle); err != nil {
		return err
	}
	if strings.TrimSpace(i.DisplayName) == "" || !validLifecycleStatus(i.Status) {
		return invalid("provider instance display name or lifecycle status is invalid")
	}
	if i.Revision == 0 || i.DefinitionRevision == 0 {
		return invalid("provider instance revisions must be positive")
	}
	if i.CreatedAt.IsZero() || i.UpdatedAt.IsZero() || i.UpdatedAt.Before(i.CreatedAt) {
		return invalid("provider instance timestamps are invalid")
	}
	return nil
}

// Validate verifies one concrete endpoint record.
// Validate 校验一个具体端点记录。
func (e Endpoint) Validate() error {
	if err := validatePrefixedIdentifier("endpoint id", e.ID, "ep_"); err != nil {
		return err
	}
	if err := validatePrefixedIdentifier("endpoint provider instance id", e.ProviderInstanceID, "pvi_"); err != nil {
		return err
	}
	if err := validateIdentifier("endpoint channel id", e.ChannelID); err != nil {
		return err
	}
	parsedURL, errParse := url.ParseRequestURI(e.BaseURL)
	if errParse != nil || parsedURL.Host == "" || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		return invalid("endpoint base url must be an absolute http or https url")
	}
	if !validEndpointStatus(e.Status) || e.Revision == 0 {
		return invalid("endpoint status or revision is invalid")
	}
	return nil
}

// Validate verifies one non-secret credential record.
// Validate 校验一个非秘密凭据记录。
func (c Credential) Validate() error {
	if err := validatePrefixedIdentifier("credential id", c.ID, "cred_"); err != nil {
		return err
	}
	if err := validatePrefixedIdentifier("credential provider instance id", c.ProviderInstanceID, "pvi_"); err != nil {
		return err
	}
	if err := validateIdentifier("credential auth method id", c.AuthMethodID); err != nil {
		return err
	}
	if strings.TrimSpace(c.Label) == "" || strings.TrimSpace(c.SecretRef) == "" || strings.TrimSpace(c.Fingerprint) == "" {
		return invalid("credential label, secret reference, and fingerprint are required")
	}
	if !validCredentialStatus(c.Status) || c.Revision == 0 {
		return invalid("credential status or revision is invalid")
	}
	if c.Status == CredentialCooling && c.CoolingUntil == nil {
		return invalid("cooling credential requires a recovery time")
	}
	seenScopes := make(map[string]struct{}, len(c.ScopeRefs))
	for _, scopeRef := range c.ScopeRefs {
		if err := scopeRef.Validate(); err != nil {
			return err
		}
		scopeKey := scopeRef.Kind + "\x00" + scopeRef.ID
		if _, exists := seenScopes[scopeKey]; exists {
			return invalid("duplicate credential scope reference %q", scopeRef.Kind)
		}
		seenScopes[scopeKey] = struct{}{}
	}
	return nil
}

// Validate verifies one credential commercial scope reference.
// Validate 校验一个凭据商业作用域引用。
func (s ScopeReference) Validate() error {
	if err := validateIdentifier("scope reference kind", s.Kind); err != nil {
		return err
	}
	if strings.TrimSpace(s.ID) == "" {
		return invalid("scope reference id is required")
	}
	return nil
}

// Validate verifies one access binding without resolving external references.
// Validate 校验一个访问绑定但不解析外部引用。
func (b AccessBinding) Validate() error {
	if err := validatePrefixedIdentifier("access binding id", b.ID, "bind_"); err != nil {
		return err
	}
	if err := validatePrefixedIdentifier("access binding provider instance id", b.ProviderInstanceID, "pvi_"); err != nil {
		return err
	}
	if err := validateIdentifier("access binding channel id", b.ChannelID); err != nil {
		return err
	}
	if err := validatePrefixedIdentifier("access binding endpoint id", b.EndpointID, "ep_"); err != nil {
		return err
	}
	if err := validatePrefixedIdentifier("access binding credential id", b.CredentialID, "cred_"); err != nil {
		return err
	}
	if b.Revision == 0 {
		return invalid("access binding revision must be positive")
	}
	for _, modelID := range b.AllowedModelIDs {
		if err := validateIdentifier("access binding model id", modelID); err != nil {
			return err
		}
	}
	return nil
}

// HasChannel reports whether a provider definition owns one channel identifier.
// HasChannel 返回供应商定义是否拥有指定通道标识。
func (d ProviderDefinition) HasChannel(channelID string) bool {
	for _, channel := range d.Channels {
		if channel.ID == channelID {
			return true
		}
	}
	return false
}

// HasAuthMethod reports whether a provider definition owns one authentication method.
// HasAuthMethod 返回供应商定义是否拥有指定认证方式。
func (d ProviderDefinition) HasAuthMethod(authMethodID string) bool {
	for _, authMethod := range d.AuthMethods {
		if authMethod.ID == authMethodID {
			return true
		}
	}
	return false
}

// ChannelAllowsAuth reports whether a channel accepts one provider authentication method.
// ChannelAllowsAuth 返回通道是否接受指定供应商认证方式。
func (d ProviderDefinition) ChannelAllowsAuth(channelID string, authMethodID string) bool {
	for _, channel := range d.Channels {
		if channel.ID != channelID {
			continue
		}
		for _, allowedAuthMethodID := range channel.AuthMethodIDs {
			if allowedAuthMethodID == authMethodID {
				return true
			}
		}
	}
	return false
}

// validSupportStatus reports whether a support state is explicitly defined.
// validSupportStatus 返回支持状态是否已显式定义。
func validSupportStatus(status SupportStatus) bool {
	return status == SupportSupported || status == SupportUnsupported || status == SupportTemporarilyUnavailable
}

// validAuthMethodType reports whether an authentication method type is explicitly defined.
// validAuthMethodType 返回认证方式类型是否已显式定义。
func validAuthMethodType(authMethod AuthMethodType) bool {
	switch authMethod {
	case AuthMethodOAuth, AuthMethodDeviceFlow, AuthMethodAPIKey, AuthMethodBearer, AuthMethodHeaderKey, AuthMethodQueryKey, AuthMethodNone:
		return true
	default:
		return false
	}
}

// validLifecycleStatus reports whether a provider lifecycle state is explicitly defined.
// validLifecycleStatus 返回供应商生命周期状态是否已显式定义。
func validLifecycleStatus(status LifecycleStatus) bool {
	switch status {
	case LifecycleDraft, LifecycleValidating, LifecycleReady, LifecycleDegraded, LifecycleDisabled, LifecycleMigrationRequired, LifecycleDeleting:
		return true
	default:
		return false
	}
}

// validCredentialStatus reports whether a credential state is explicitly defined.
// validCredentialStatus 返回凭据状态是否已显式定义。
func validCredentialStatus(status CredentialStatus) bool {
	switch status {
	case CredentialActive, CredentialDisabled, CredentialExpired, CredentialInvalid, CredentialCooling:
		return true
	default:
		return false
	}
}

// validEndpointStatus reports whether an endpoint state is explicitly defined.
// validEndpointStatus 返回端点状态是否已显式定义。
func validEndpointStatus(status EndpointStatus) bool {
	return status == EndpointReady || status == EndpointUnavailable || status == EndpointDisabled
}

// validateIdentifier verifies one portable stable identifier.
// validateIdentifier 校验一个可移植的稳定标识。
func validateIdentifier(field string, value string) error {
	if !stableIdentifierPattern.MatchString(value) {
		return invalid("%s %q is invalid", field, value)
	}
	return nil
}

// validatePrefixedIdentifier verifies one portable identifier with a required namespace prefix.
// validatePrefixedIdentifier 校验一个带必需命名空间前缀的可移植标识。
func validatePrefixedIdentifier(field string, value string, prefix string) error {
	if !strings.HasPrefix(value, prefix) {
		return invalid("%s must start with %s", field, prefix)
	}
	return validateIdentifier(field, value)
}

// invalid wraps one provider configuration validation failure.
// invalid 包装一个供应商配置校验失败。
func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidConfiguration, fmt.Sprintf(format, args...))
}
