package providerconfig

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
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
	// capabilities ensures each declarable behavior has one explicit verified status rather than runtime probing.
	// capabilities 确保每个可声明行为拥有一个显式验证状态，而不是在运行时探测。
	capabilities := make(map[ProtocolCapability]struct{}, len(p.Capabilities))
	for _, fact := range p.Capabilities {
		if !validProtocolCapability(fact.Capability) {
			return invalid("protocol profile capability %q is invalid", fact.Capability)
		}
		if !validSupportStatus(fact.Status) {
			return invalid("protocol profile capability %q status is invalid", fact.Capability)
		}
		if _, exists := capabilities[fact.Capability]; exists {
			return invalid("protocol profile capability %q is duplicated", fact.Capability)
		}
		capabilities[fact.Capability] = struct{}{}
	}
	// allowedAuthMethods prevents one protocol profile from declaring the same authentication contract twice.
	// allowedAuthMethods 防止一个协议 Profile 重复声明同一认证契约。
	allowedAuthMethods := make(map[AuthMethodType]struct{}, len(p.AllowedAuthMethods))
	for _, authMethod := range p.AllowedAuthMethods {
		if !validAuthMethodType(authMethod) {
			return invalid("protocol profile auth method %q is invalid", authMethod)
		}
		if _, exists := allowedAuthMethods[authMethod]; exists {
			return invalid("protocol profile auth method %q is duplicated", authMethod)
		}
		allowedAuthMethods[authMethod] = struct{}{}
	}
	if p.UserConfigurable && !p.CustomDefinitionCompatible {
		return invalid("user-configurable protocol profile must be custom-definition compatible")
	}
	if p.CustomDefinitionCompatible && len(p.AllowedAuthMethods) == 0 {
		return invalid("custom-definition compatible protocol profile requires an authentication method")
	}
	return nil
}

// validProtocolCapability reports whether one declarable protocol behavior belongs to the closed configuration vocabulary.
// validProtocolCapability 报告一个可声明协议行为是否属于封闭配置词汇表。
func validProtocolCapability(capability ProtocolCapability) bool {
	switch capability {
	case ProtocolCapabilitySystemInstruction, ProtocolCapabilityStructuredTools, ProtocolCapabilityParallelTools, ProtocolCapabilityStreamingToolArguments, ProtocolCapabilityStrictJSONSchema, ProtocolCapabilityReasoning, ProtocolCapabilityReasoningContinuation, ProtocolCapabilityRemoteCompaction, ProtocolCapabilityNativeWebSearch, ProtocolCapabilityTokenCounting:
		return true
	default:
		return false
	}
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
		if d.GroupID != "" {
			if err := validateIdentifier("provider group id", d.GroupID); err != nil {
				return err
			}
			if strings.TrimSpace(d.VariantName) == "" {
				return invalid("grouped system provider definition requires a variant name")
			}
		} else if d.VariantName != "" || d.VariantDescription != "" || d.VariantDescriptionKey != "" || d.SortOrder != 0 {
			return invalid("ungrouped system provider definition cannot register grouped variant metadata")
		}
		if d.ModelCatalogID != "" {
			if err := validateIdentifier("provider model catalog id", d.ModelCatalogID); err != nil {
				return err
			}
		}
	case DefinitionKindCustom:
		if !strings.HasPrefix(d.ID, "custom_") {
			return invalid("custom provider definition id must start with custom_")
		}
		if d.DriverID != "" || d.DriverVersion != "" {
			return invalid("custom provider definition cannot register a trusted driver")
		}
		if d.GroupID != "" || d.VariantName != "" || d.VariantDescription != "" || d.VariantDescriptionKey != "" || d.ModelCatalogID != "" || d.SortOrder != 0 || len(d.EndpointPresets) != 0 {
			return invalid("custom provider definition cannot register system grouping or endpoint preset metadata")
		}
		if len(d.ActionBindings) != 0 {
			return invalid("custom provider definition cannot register system action bindings")
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
	if d.SortOrder < 0 {
		return invalid("provider definition sort order cannot be negative")
	}
	if err := validateIdentifier("provider protocol profile id", d.ProtocolProfileID); err != nil {
		return err
	}
	if strings.TrimSpace(d.EndpointProfileID) == "" {
		return invalid("provider definition endpoint profile id is required")
	}
	if len(d.AuthMethodIDs) == 0 {
		return invalid("provider definition protocol requires at least one auth method")
	}
	if !d.RuntimeReady {
		return invalid("provider definition protocol must be runtime ready")
	}
	if len(d.AuthMethods) == 0 {
		return invalid("provider definition requires at least one auth method")
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
	planOptions := make(map[string]struct{}, len(d.PlanOptions))
	for _, option := range d.PlanOptions {
		if d.Kind != DefinitionKindSystem {
			return invalid("custom provider definition cannot register plan options")
		}
		if errOption := option.Validate(authMethods); errOption != nil {
			return errOption
		}
		if _, exists := planOptions[option.ID]; exists {
			return invalid("provider plan option %q is duplicated", option.ID)
		}
		planOptions[option.ID] = struct{}{}
	}
	for _, authMethod := range d.AuthMethods {
		if authMethod.PlanAcquisition != PlanAcquisitionManualRequired {
			continue
		}
		foundOption := false
		for _, option := range d.PlanOptions {
			if option.ManuallySelectable && slices.Contains(option.AuthMethodIDs, authMethod.ID) {
				foundOption = true
				break
			}
		}
		if !foundOption {
			return invalid("manual-required auth method %q requires at least one plan option", authMethod.ID)
		}
	}
	// protocolAuthMethods prevents duplicated references from changing protocol authentication semantics.
	// protocolAuthMethods 防止重复引用改变协议认证语义。
	protocolAuthMethods := make(map[string]struct{}, len(d.AuthMethodIDs))
	for _, authMethodID := range d.AuthMethodIDs {
		if err := validateIdentifier("provider protocol auth method id", authMethodID); err != nil {
			return err
		}
		if _, exists := protocolAuthMethods[authMethodID]; exists {
			return invalid("provider protocol auth method %q is duplicated", authMethodID)
		}
		protocolAuthMethods[authMethodID] = struct{}{}
		if _, exists := authMethods[authMethodID]; !exists {
			return invalid("provider protocol references unknown auth method %q", authMethodID)
		}
	}
	actionBindings := make(map[string]struct{}, len(d.ActionBindings))
	for _, binding := range d.ActionBindings {
		if errBinding := binding.Validate(); errBinding != nil {
			return errBinding
		}
		if _, exists := actionBindings[binding.ID]; exists {
			return invalid("provider action binding %q is duplicated", binding.ID)
		}
		actionBindings[binding.ID] = struct{}{}
		for _, authMethodID := range binding.AuthMethodIDs {
			if _, exists := authMethods[authMethodID]; !exists {
				return invalid("provider action binding %q references unknown auth method %q", binding.ID, authMethodID)
			}
		}
	}
	presets := make(map[string]struct{}, len(d.EndpointPresets))
	for _, preset := range d.EndpointPresets {
		if err := preset.Validate(); err != nil {
			return err
		}
		if _, exists := presets[preset.ID]; exists {
			return invalid("duplicate endpoint preset id %q", preset.ID)
		}
		presets[preset.ID] = struct{}{}
	}
	if err := d.Features.Validate(); err != nil {
		return err
	}
	return nil
}

// Validate verifies one code-owned provider management group without granting it routing semantics.
// Validate 校验一个代码拥有的供应商管理分组，且不赋予其路由语义。
func (g ProviderGroup) Validate() error {
	if err := validateIdentifier("provider group id", g.ID); err != nil {
		return err
	}
	if strings.TrimSpace(g.DisplayName) == "" || g.Revision == 0 {
		return invalid("provider group display name and positive revision are required")
	}
	if g.SortOrder < 0 {
		return invalid("provider group sort order cannot be negative")
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
	if a.PlanAcquisition != "" && !validPlanAcquisitionMode(a.PlanAcquisition) {
		return invalid("auth method plan acquisition mode %q is invalid", a.PlanAcquisition)
	}
	return nil
}

// Validate verifies one immutable provider plan choice against the owning auth-method set.
// Validate 根据所属认证方式集合校验一个不可变供应商套餐选项。
func (p PlanOptionDefinition) Validate(authMethods map[string]struct{}) error {
	if errID := validateIdentifier("provider plan option id", p.ID); errID != nil {
		return errID
	}
	if strings.TrimSpace(p.DisplayName) == "" || p.SortOrder < 0 || p.Revision == 0 || p.EvidenceRevision == 0 || len(p.AuthMethodIDs) == 0 {
		return invalid("provider plan option display name, auth methods, sort order, and revision are invalid")
	}
	seenAuthMethods := make(map[string]struct{}, len(p.AuthMethodIDs))
	for _, authMethodID := range p.AuthMethodIDs {
		if _, exists := authMethods[authMethodID]; !exists {
			return invalid("provider plan option %q references unknown auth method %q", p.ID, authMethodID)
		}
		if _, exists := seenAuthMethods[authMethodID]; exists {
			return invalid("provider plan option %q duplicates auth method %q", p.ID, authMethodID)
		}
		seenAuthMethods[authMethodID] = struct{}{}
	}
	seenCodes := make(map[string]struct{}, len(p.ProviderPlanCodes))
	for _, providerPlanCode := range p.ProviderPlanCodes {
		if errCode := validateIdentifier("provider plan code", providerPlanCode); errCode != nil {
			return errCode
		}
		if _, exists := seenCodes[providerPlanCode]; exists {
			return invalid("duplicate provider plan code %q", providerPlanCode)
		}
		seenCodes[providerPlanCode] = struct{}{}
	}
	return nil
}

// Validate verifies one system-provider endpoint preset independently from persisted instance endpoints.
// Validate 独立于持久化实例端点校验一个系统供应商端点预设。
func (p EndpointPreset) Validate() error {
	if err := validateIdentifier("endpoint preset id", p.ID); err != nil {
		return err
	}
	if p.BaseURLTemplate != "" || len(p.Parameters) != 0 {
		if p.BaseURLTemplate == "" || len(p.Parameters) == 0 {
			return invalid("parameterized endpoint preset requires a base url template and parameter definitions")
		}
		if p.BaseURL != "" || p.RegionalBaseURLTemplate != "" || p.GlobalBaseURL != "" || p.UserEditable {
			return invalid("parameterized endpoint preset cannot combine fixed, regional, global, or editable endpoint fields")
		}
		if strings.TrimSpace(p.Region) == "" {
			return invalid("endpoint preset region is required")
		}
		// materializedTemplate validates the template structure with safe representative labels.
		// materializedTemplate 使用安全的代表性标签校验模板结构。
		materializedTemplate := p.BaseURLTemplate
		seenParameterIDs := make(map[string]struct{}, len(p.Parameters))
		for _, parameter := range p.Parameters {
			if errParameter := parameter.Validate(); errParameter != nil {
				return errParameter
			}
			if _, exists := seenParameterIDs[parameter.ID]; exists {
				return invalid("duplicate endpoint parameter definition %q", parameter.ID)
			}
			seenParameterIDs[parameter.ID] = struct{}{}
			placeholder := "{" + parameter.ID + "}"
			if strings.Count(materializedTemplate, placeholder) != 1 {
				return invalid("endpoint parameter %q must occur exactly once in the base url template", parameter.ID)
			}
			materializedTemplate = strings.Replace(materializedTemplate, placeholder, "example", 1)
		}
		if strings.ContainsAny(materializedTemplate, "{}") {
			return invalid("endpoint base url template contains an undeclared or malformed placeholder")
		}
		return validateDerivedHTTPSBaseURL("parameterized endpoint base url template", materializedTemplate)
	}
	if errBaseURL := validateBaseURL("endpoint preset base url", p.BaseURL); errBaseURL != nil {
		return errBaseURL
	}
	if strings.TrimSpace(p.Region) == "" {
		return invalid("endpoint preset region is required")
	}
	if p.RegionalBaseURLTemplate == "" {
		if p.GlobalBaseURL != "" {
			return invalid("endpoint preset global base url requires a regional template")
		}
		return nil
	}
	if p.UserEditable || strings.Count(p.RegionalBaseURLTemplate, "{region}") != 1 {
		return invalid("derived endpoint preset requires one non-editable {region} placeholder")
	}
	if errRegion := validateEndpointRegion(p.Region); errRegion != nil {
		return errRegion
	}
	derivedBaseURL, errDerived := p.derivedBaseURL(p.Region)
	if errDerived != nil {
		return errDerived
	}
	if derivedBaseURL != p.BaseURL {
		return invalid("endpoint preset base url must match its default derived region")
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
	if i.RoutingStrategy != "" && !validRoutingStrategy(i.RoutingStrategy) {
		return invalid("provider instance routing strategy %q is invalid", i.RoutingStrategy)
	}
	if i.Revision == 0 || i.DefinitionRevision == 0 {
		return invalid("provider instance revisions must be positive")
	}
	if i.CreatedAt.IsZero() || i.UpdatedAt.IsZero() || i.UpdatedAt.Before(i.CreatedAt) {
		return invalid("provider instance timestamps are invalid")
	}
	// disabledModels prevents one model policy from containing duplicate or non-portable identifiers.
	// disabledModels 防止一个模型策略包含重复或不可移植标识。
	disabledModels := make(map[string]struct{}, len(i.DisabledModelIDs))
	for _, modelID := range i.DisabledModelIDs {
		if errModelID := validateIdentifier("provider instance disabled model id", modelID); errModelID != nil {
			return errModelID
		}
		if _, exists := disabledModels[modelID]; exists {
			return invalid("duplicate provider instance disabled model id %q", modelID)
		}
		disabledModels[modelID] = struct{}{}
	}
	disabledServices := make(map[string]struct{}, len(i.DisabledServiceIDs))
	for _, serviceID := range i.DisabledServiceIDs {
		if errService := validateIdentifier("provider instance disabled service id", serviceID); errService != nil {
			return errService
		}
		if _, exists := disabledServices[serviceID]; exists {
			return invalid("provider instance disabled service id %q is duplicated", serviceID)
		}
		disabledServices[serviceID] = struct{}{}
	}
	return nil
}

// ValidateMutation verifies an existing provider instance keeps its definition ownership and creation time.
// ValidateMutation 校验现有供应商实例保持其定义所有权与创建时间不变。
func (i ProviderInstance) ValidateMutation(next ProviderInstance) error {
	if i.ID == "" || i.ID != next.ID {
		return invalid("provider instance mutation requires matching identifiers")
	}
	if i.DefinitionID != next.DefinitionID {
		return invalid("provider instance definition ownership is immutable")
	}
	if !i.CreatedAt.Equal(next.CreatedAt) {
		return invalid("provider instance creation time is immutable")
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
	if errBaseURL := validateBaseURL("endpoint base url", e.BaseURL); errBaseURL != nil {
		return errBaseURL
	}
	seenParameterIDs := make(map[string]struct{}, len(e.Parameters))
	for _, parameter := range e.Parameters {
		if errParameterID := validateIdentifier("endpoint parameter id", parameter.ID); errParameterID != nil {
			return errParameterID
		}
		if parameter.Value == "" || parameter.Value != strings.TrimSpace(parameter.Value) {
			return invalid("endpoint parameter %q value must be non-empty and normalized", parameter.ID)
		}
		if _, exists := seenParameterIDs[parameter.ID]; exists {
			return invalid("duplicate endpoint parameter value %q", parameter.ID)
		}
		seenParameterIDs[parameter.ID] = struct{}{}
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
	if c.Priority < 0 {
		return invalid("credential priority cannot be negative")
	}
	if c.DeclaredPlan != nil {
		if errPlan := validateIdentifier("credential declared plan option id", c.DeclaredPlan.PlanOptionID); errPlan != nil {
			return errPlan
		}
		if c.DeclaredPlan.DeclaredAt.IsZero() || c.DeclaredPlan.Revision == 0 {
			return invalid("credential declared plan time and revision are required")
		}
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

// RuntimeEligibleAt reports whether this credential may participate in upstream work at the evaluation time.
// RuntimeEligibleAt 表示该凭据在评估时刻是否可以参与上游工作。
func (c Credential) RuntimeEligibleAt(now time.Time) bool {
	if c.ExpiresAt != nil && !c.ExpiresAt.After(now) {
		return false
	}
	switch c.Status {
	case CredentialActive:
		return true
	case CredentialCooling:
		return c.CoolingUntil != nil && !c.CoolingUntil.After(now)
	default:
		return false
	}
}

// ValidateMutation verifies an existing credential keeps its provider and authentication ownership.
// ValidateMutation 校验现有凭据保持其供应商与认证方式所有权不变。
func (c Credential) ValidateMutation(next Credential) error {
	if c.ID == "" || c.ID != next.ID {
		return invalid("credential mutation requires matching identifiers")
	}
	if c.ProviderInstanceID != next.ProviderInstanceID || c.AuthMethodID != next.AuthMethodID {
		return invalid("credential provider and authentication ownership are immutable")
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
	// allowedModels keeps one binding policy canonical and prevents duplicate model rules.
	// allowedModels 保持绑定策略规范化并防止重复模型规则。
	allowedModels := make(map[string]struct{}, len(b.AllowedModelIDs))
	for _, modelID := range b.AllowedModelIDs {
		if err := validateIdentifier("access binding model id", modelID); err != nil {
			return err
		}
		if _, exists := allowedModels[modelID]; exists {
			return invalid("access binding model id %q is duplicated", modelID)
		}
		allowedModels[modelID] = struct{}{}
	}
	allowedServices := make(map[string]struct{}, len(b.AllowedServiceIDs))
	for _, serviceID := range b.AllowedServiceIDs {
		if errService := validateIdentifier("access binding service id", serviceID); errService != nil {
			return errService
		}
		if _, exists := allowedServices[serviceID]; exists {
			return invalid("access binding service id %q is duplicated", serviceID)
		}
		allowedServices[serviceID] = struct{}{}
	}
	return nil
}

// ValidateMutation verifies an existing binding keeps its provider and protocol-channel ownership.
// ValidateMutation 校验现有绑定保持其供应商与协议通道所有权不变。
func (b AccessBinding) ValidateMutation(next AccessBinding) error {
	if b.ID == "" || b.ID != next.ID {
		return invalid("access binding mutation requires matching identifiers")
	}
	if b.ProviderInstanceID != next.ProviderInstanceID || b.ChannelID != next.ChannelID {
		return invalid("access binding provider and channel ownership are immutable")
	}
	return nil
}

// ValidateAccessGraphReplacement verifies one complete replacement graph against current provider and credential ownership.
// ValidateAccessGraphReplacement 校验一个完整替换图的当前供应商与凭据归属。
func ValidateAccessGraphReplacement(replacement AccessGraphReplacement, definition ProviderDefinition, credentials []Credential) error {
	if errInstanceID := validatePrefixedIdentifier("access graph provider instance id", replacement.ProviderInstanceID, "pvi_"); errInstanceID != nil {
		return errInstanceID
	}
	for _, endpoint := range replacement.ExpectedEndpoints {
		if errEndpoint := endpoint.Validate(); errEndpoint != nil || endpoint.ProviderInstanceID != replacement.ProviderInstanceID {
			return invalid("expected endpoint is invalid or belongs to another provider instance")
		}
	}
	for _, binding := range replacement.ExpectedBindings {
		if errBinding := binding.Validate(); errBinding != nil || binding.ProviderInstanceID != replacement.ProviderInstanceID {
			return invalid("expected binding is invalid or belongs to another provider instance")
		}
	}
	credentialByID := make(map[string]Credential, len(credentials))
	for _, credential := range credentials {
		if credential.ProviderInstanceID == replacement.ProviderInstanceID {
			credentialByID[credential.ID] = credential
		}
	}
	endpointByID := make(map[string]Endpoint, len(replacement.Endpoints))
	for _, endpoint := range replacement.Endpoints {
		if errEndpoint := endpoint.Validate(); errEndpoint != nil {
			return errEndpoint
		}
		if endpoint.ProviderInstanceID != replacement.ProviderInstanceID || !definition.HasChannel(endpoint.ChannelID) {
			return invalid("replacement endpoint is outside provider ownership")
		}
		if errPreset := definition.ValidateEndpointPreset(endpoint); errPreset != nil {
			return errPreset
		}
		if _, duplicate := endpointByID[endpoint.ID]; duplicate {
			return invalid("replacement endpoint id %q is duplicated", endpoint.ID)
		}
		endpointByID[endpoint.ID] = endpoint
	}
	seenBindings := make(map[string]struct{}, len(replacement.Bindings))
	for _, binding := range replacement.Bindings {
		if errBinding := binding.Validate(); errBinding != nil {
			return errBinding
		}
		_, endpointExists := endpointByID[binding.EndpointID]
		credential, credentialExists := credentialByID[binding.CredentialID]
		if binding.ProviderInstanceID != replacement.ProviderInstanceID || !endpointExists || !credentialExists {
			return invalid("replacement binding references resources outside provider ownership")
		}
		if !definition.ChannelAllowsAuth(binding.ChannelID, credential.AuthMethodID) {
			return invalid("replacement binding channel is incompatible with endpoint or credential auth method")
		}
		if _, duplicate := seenBindings[binding.ID]; duplicate {
			return invalid("replacement binding id %q is duplicated", binding.ID)
		}
		seenBindings[binding.ID] = struct{}{}
	}
	return nil
}

// validateBaseURL verifies a credential-free absolute HTTP(S) base URL while preserving provider-owned paths.
// validateBaseURL 校验不含凭据的绝对 HTTP(S) 基础 URL，同时保留供应商自有路径。
func validateBaseURL(field string, value string) error {
	parsedURL, errParse := url.Parse(value)
	if errParse != nil || !parsedURL.IsAbs() || parsedURL.Host == "" || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		return invalid("%s must be an absolute http or https url", field)
	}
	if parsedURL.User != nil || parsedURL.ForceQuery || parsedURL.RawQuery != "" || parsedURL.Fragment != "" || strings.Contains(value, "#") {
		return invalid("%s cannot contain user information, query, or fragment", field)
	}
	return nil
}

// HasChannel reports whether a provider definition owns one channel identifier.
// HasChannel 返回供应商定义是否拥有指定通道标识。
func (d ProviderDefinition) HasChannel(channelID string) bool {
	for _, ownedChannelID := range d.ChannelIDs() {
		if ownedChannelID == channelID {
			return true
		}
	}
	return false
}

// ChannelIDs returns the primary protocol and every action-specific protocol exactly once in stable declaration order.
// ChannelIDs 以稳定声明顺序返回主协议及每个动作专属协议且不重复。
func (d ProviderDefinition) ChannelIDs() []string {
	seen := make(map[string]struct{}, len(d.ActionBindings)+1)
	channels := make([]string, 0, len(d.ActionBindings)+1)
	appendChannel := func(channelID string) {
		if _, exists := seen[channelID]; exists {
			return
		}
		seen[channelID] = struct{}{}
		channels = append(channels, channelID)
	}
	appendChannel(d.ProtocolProfileID)
	for _, action := range d.ActionBindings {
		appendChannel(action.ProtocolProfileID)
	}
	return channels
}

// HasAuthMethod reports whether a provider definition owns one authentication method.
// HasAuthMethod 返回供应商定义是否拥有指定认证方式。
func (d ProviderDefinition) HasAuthMethod(authMethodID string) bool {
	_, exists := d.AuthMethod(authMethodID)
	return exists
}

// AuthMethod returns one definition-owned authentication method by exact identifier.
// AuthMethod 按精确标识返回一个由定义拥有的认证方式。
func (d ProviderDefinition) AuthMethod(authMethodID string) (AuthMethodDefinition, bool) {
	for _, authMethod := range d.AuthMethods {
		if authMethod.ID == authMethodID {
			return authMethod, true
		}
	}
	return AuthMethodDefinition{}, false
}

// PlanOption returns one code-owned commercial plan by exact identifier.
// PlanOption 按精确标识返回一个代码拥有的商业套餐。
func (d ProviderDefinition) PlanOption(planOptionID string) (PlanOptionDefinition, bool) {
	for _, option := range d.PlanOptions {
		if option.ID == planOptionID {
			return option, true
		}
	}
	return PlanOptionDefinition{}, false
}

// AuthMethodAllowsPlan reports whether one exact manual plan belongs to the selected authentication method.
// AuthMethodAllowsPlan 报告一个精确人工套餐是否属于所选认证方式。
func (d ProviderDefinition) AuthMethodAllowsPlan(authMethodID string, planOptionID string) bool {
	option, exists := d.PlanOption(planOptionID)
	return exists && slices.Contains(option.AuthMethodIDs, authMethodID)
}

// ChannelAllowsAuth reports whether a channel accepts one provider authentication method.
// ChannelAllowsAuth 返回通道是否接受指定供应商认证方式。
func (d ProviderDefinition) ChannelAllowsAuth(channelID string, authMethodID string) bool {
	if channelID == d.ProtocolProfileID {
		for _, allowedAuthMethodID := range d.AuthMethodIDs {
			if allowedAuthMethodID == authMethodID {
				return true
			}
		}
	}
	for _, action := range d.ActionBindings {
		if action.ProtocolProfileID != channelID {
			continue
		}
		for _, allowedAuthMethodID := range action.AuthMethodIDs {
			if allowedAuthMethodID == authMethodID {
				return true
			}
		}
	}
	return false
}

// ValidateEndpointPreset enforces code-owned fixed endpoint boundaries for one concrete endpoint.
// ValidateEndpointPreset 为一个具体端点强制执行代码拥有的固定端点边界。
func (d ProviderDefinition) ValidateEndpointPreset(endpoint Endpoint) error {
	if d.Kind != DefinitionKindSystem || len(d.EndpointPresets) == 0 {
		return nil
	}
	// hasEditablePreset records the explicit exception that permits a management-provided address.
	// hasEditablePreset 记录允许管理端提供地址的显式例外。
	hasEditablePreset := false
	for _, preset := range d.EndpointPresets {
		if preset.BaseURL == endpoint.BaseURL && preset.Region == endpoint.Region && len(endpoint.Parameters) == 0 {
			return nil
		}
		if preset.RegionalBaseURLTemplate != "" && len(endpoint.Parameters) == 0 {
			derivedBaseURL, errDerived := preset.derivedBaseURL(endpoint.Region)
			if errDerived == nil && derivedBaseURL == endpoint.BaseURL {
				return nil
			}
		}
		if preset.BaseURLTemplate != "" && preset.Region == endpoint.Region {
			derivedBaseURL, errDerived := preset.MaterializeBaseURL(endpoint.Parameters)
			if errDerived == nil && derivedBaseURL == endpoint.BaseURL {
				return nil
			}
		}
		if preset.UserEditable {
			hasEditablePreset = true
		}
	}
	if !hasEditablePreset {
		return invalid("endpoint must exactly match one fixed system provider preset")
	}
	return nil
}

// ValidateEndpointMutation prevents a provider-derived system origin from changing after credential-bound onboarding.
// ValidateEndpointMutation 防止供应商派生的系统 Origin 在凭据绑定录入后发生变化。
func (d ProviderDefinition) ValidateEndpointMutation(current Endpoint, next Endpoint) error {
	if current.ID == "" || current.ID != next.ID {
		return invalid("endpoint mutation requires matching identifiers")
	}
	if current.ProviderInstanceID != next.ProviderInstanceID || current.ChannelID != next.ChannelID {
		return invalid("endpoint provider and channel ownership are immutable")
	}
	if d.Kind != DefinitionKindSystem {
		return nil
	}
	for _, preset := range d.EndpointPresets {
		if preset.RegionalBaseURLTemplate != "" {
			currentBaseURL, errCurrent := preset.derivedBaseURL(current.Region)
			if errCurrent == nil && currentBaseURL == current.BaseURL && (current.BaseURL != next.BaseURL || current.Region != next.Region || !slices.Equal(current.Parameters, next.Parameters)) {
				return invalid("provider-derived system endpoint origin, region, and parameters are immutable after onboarding")
			}
		}
		if preset.BaseURLTemplate != "" && preset.Region == current.Region {
			currentBaseURL, errCurrent := preset.MaterializeBaseURL(current.Parameters)
			if errCurrent == nil && currentBaseURL == current.BaseURL && (current.BaseURL != next.BaseURL || current.Region != next.Region || !slices.Equal(current.Parameters, next.Parameters)) {
				return invalid("provider-derived system endpoint origin, region, and parameters are immutable after onboarding")
			}
		}
	}
	return nil
}

// derivedBaseURL materializes one safe provider-owned regional origin from a closed preset template.
// derivedBaseURL 从封闭预设模板实例化一个安全的供应商所有区域 Origin。
func (p EndpointPreset) derivedBaseURL(region string) (string, error) {
	if errRegion := validateEndpointRegion(region); errRegion != nil {
		return "", errRegion
	}
	baseURL := strings.Replace(p.RegionalBaseURLTemplate, "{region}", region, 1)
	if region == "global" && p.GlobalBaseURL != "" {
		baseURL = p.GlobalBaseURL
	}
	if errBaseURL := validateDerivedHTTPSBaseURL("derived endpoint base url", baseURL); errBaseURL != nil {
		return "", errBaseURL
	}
	return baseURL, nil
}

// MaterializeRegionalBaseURL derives one provider-owned regional origin only for a declared regional preset.
// MaterializeRegionalBaseURL 仅为已声明的区域预设派生一个供应商拥有的区域 Origin。
func (p EndpointPreset) MaterializeRegionalBaseURL(region string) (string, error) {
	if p.RegionalBaseURLTemplate == "" {
		return "", invalid("endpoint preset does not accept a region")
	}
	return p.derivedBaseURL(region)
}

// Validate verifies one closed endpoint parameter definition.
// Validate 校验一个封闭的端点参数定义。
func (p EndpointParameterDefinition) Validate() error {
	if errID := validateIdentifier("endpoint parameter definition id", p.ID); errID != nil {
		return errID
	}
	if p.Kind != EndpointParameterHostnameLabel {
		return invalid("endpoint parameter %q has unsupported kind %q", p.ID, p.Kind)
	}
	if !p.Required {
		return invalid("endpoint template parameter %q must be required", p.ID)
	}
	return nil
}

// MaterializeBaseURL derives one exact HTTPS base URL from declared non-secret parameter values.
// MaterializeBaseURL 根据已声明的非秘密参数值派生一个精确的 HTTPS 基础 URL。
func (p EndpointPreset) MaterializeBaseURL(values []EndpointParameterValue) (string, error) {
	if p.BaseURLTemplate == "" || len(values) != len(p.Parameters) {
		return "", invalid("endpoint parameter values must exactly match the preset schema")
	}
	valuesByID := make(map[string]string, len(values))
	for _, value := range values {
		if _, exists := valuesByID[value.ID]; exists {
			return "", invalid("duplicate endpoint parameter value %q", value.ID)
		}
		valuesByID[value.ID] = value.Value
	}
	baseURL := p.BaseURLTemplate
	for _, definition := range p.Parameters {
		value, exists := valuesByID[definition.ID]
		if !exists {
			return "", invalid("endpoint parameter %q is required", definition.ID)
		}
		if errValue := validateEndpointParameterValue(definition, value); errValue != nil {
			return "", errValue
		}
		baseURL = strings.Replace(baseURL, "{"+definition.ID+"}", value, 1)
	}
	if errBaseURL := validateDerivedHTTPSBaseURL("parameterized endpoint base url", baseURL); errBaseURL != nil {
		return "", errBaseURL
	}
	return baseURL, nil
}

// validateEndpointParameterValue applies the exact closed validation rule declared by one endpoint parameter.
// validateEndpointParameterValue 应用一个端点参数声明的精确封闭校验规则。
func validateEndpointParameterValue(definition EndpointParameterDefinition, value string) error {
	switch definition.Kind {
	case EndpointParameterHostnameLabel:
		if len(value) == 0 || len(value) > 63 || value != strings.ToLower(strings.TrimSpace(value)) || strings.HasPrefix(value, "-") || strings.HasSuffix(value, "-") {
			return invalid("endpoint parameter %q must be a normalized DNS hostname label", definition.ID)
		}
		for _, character := range value {
			if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' {
				continue
			}
			return invalid("endpoint parameter %q must be a normalized DNS hostname label", definition.ID)
		}
		return nil
	default:
		return invalid("endpoint parameter %q has unsupported kind %q", definition.ID, definition.Kind)
	}
}

// validateDerivedHTTPSBaseURL verifies a provider-owned materialized HTTPS URL without request components.
// validateDerivedHTTPSBaseURL 校验不含请求组件的供应商所有已实例化 HTTPS URL。
func validateDerivedHTTPSBaseURL(field string, value string) error {
	parsedURL, errParse := url.ParseRequestURI(value)
	if errParse != nil || parsedURL.Scheme != "https" || parsedURL.Host == "" || parsedURL.User != nil || parsedURL.RawQuery != "" || parsedURL.Fragment != "" {
		return invalid("%s must be an absolute credential-free HTTPS url", field)
	}
	return nil
}

// validateEndpointRegion accepts only normalized host- and path-safe provider region identifiers.
// validateEndpointRegion 仅接受规范化且对 Host 与 Path 安全的供应商区域标识。
func validateEndpointRegion(region string) error {
	if region == "" || region != strings.ToLower(strings.TrimSpace(region)) {
		return invalid("derived endpoint region must be normalized")
	}
	for _, character := range region {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' {
			continue
		}
		return invalid("derived endpoint region contains unsupported characters")
	}
	return nil
}

// ValidateProviderConfiguration verifies a credential-independent instance and its complete endpoint graph.
// ValidateProviderConfiguration 校验一个独立于凭据的实例及其完整入口图。
func ValidateProviderConfiguration(configuration ProviderConfiguration, definition ProviderDefinition) error {
	if configuration.Instance.DefinitionID != definition.ID {
		return invalid("provider configuration requires its exact provider definition")
	}
	if errInstance := configuration.Instance.Validate(); errInstance != nil {
		return errInstance
	}
	if configuration.Instance.DefinitionRevision != definition.Revision || configuration.Instance.Status != LifecycleDraft {
		return invalid("credential-independent provider configuration must be draft and match the definition revision")
	}
	if len(configuration.Endpoints) == 0 {
		return invalid("provider configuration requires at least one endpoint")
	}
	channels := make(map[string]struct{}, len(configuration.Endpoints))
	for _, endpoint := range configuration.Endpoints {
		if errEndpoint := endpoint.Validate(); errEndpoint != nil {
			return errEndpoint
		}
		if endpoint.ProviderInstanceID != configuration.Instance.ID || !definition.HasChannel(endpoint.ChannelID) {
			return invalid("provider configuration endpoint is outside its provider definition")
		}
		if definition.Kind == DefinitionKindSystem {
			if errPreset := definition.ValidateEndpointPreset(endpoint); errPreset != nil {
				return errPreset
			}
		}
		if _, exists := channels[endpoint.ChannelID]; exists {
			return invalid("duplicate provider configuration channel %q", endpoint.ChannelID)
		}
		channels[endpoint.ChannelID] = struct{}{}
	}
	return nil
}

// ValidateSystemOnboarding verifies one complete new system-provider configuration before persistence.
// ValidateSystemOnboarding 在持久化前校验一份完整的新系统供应商配置。
func ValidateSystemOnboarding(onboarding SystemOnboarding, definition ProviderDefinition) error {
	if definition.Kind != DefinitionKindSystem || onboarding.Instance.DefinitionID != definition.ID {
		return invalid("system onboarding requires its exact system provider definition")
	}
	if errInstance := onboarding.Instance.Validate(); errInstance != nil {
		return errInstance
	}
	if onboarding.Instance.DefinitionRevision != definition.Revision {
		return invalid("system onboarding definition revision does not match current definition")
	}
	if onboarding.Instance.Status != LifecycleReady {
		return invalid("complete system onboarding instance must be ready")
	}
	if errCredential := onboarding.Credential.Validate(); errCredential != nil {
		return errCredential
	}
	if onboarding.Credential.ProviderInstanceID != onboarding.Instance.ID || !definition.HasAuthMethod(onboarding.Credential.AuthMethodID) {
		return invalid("system onboarding credential is outside its provider definition")
	}
	authMethod, _ := definition.AuthMethod(onboarding.Credential.AuthMethodID)
	planAcquisition := authMethod.PlanAcquisition
	if planAcquisition == "" {
		planAcquisition = PlanAcquisitionUnavailable
	}
	switch planAcquisition {
	case PlanAcquisitionManualRequired:
		if onboarding.Credential.DeclaredPlan == nil {
			return invalid("system onboarding credential requires one valid declared plan option")
		}
		planOption, exists := definition.PlanOption(onboarding.Credential.DeclaredPlan.PlanOptionID)
		if !exists || !planOption.ManuallySelectable || !definition.AuthMethodAllowsPlan(authMethod.ID, onboarding.Credential.DeclaredPlan.PlanOptionID) {
			return invalid("system onboarding credential requires one manually selectable declared plan option")
		}
	case PlanAcquisitionManualOptional:
		if onboarding.Credential.DeclaredPlan != nil {
			planOption, exists := definition.PlanOption(onboarding.Credential.DeclaredPlan.PlanOptionID)
			if !exists || !planOption.ManuallySelectable || !definition.AuthMethodAllowsPlan(authMethod.ID, onboarding.Credential.DeclaredPlan.PlanOptionID) {
				return invalid("system onboarding credential declared plan option is not manually selectable")
			}
		}
	case PlanAcquisitionProviderDetected, PlanAcquisitionUnavailable:
		if onboarding.Credential.DeclaredPlan != nil {
			return invalid("system onboarding credential cannot declare a plan for this auth method")
		}
	default:
		return invalid("system onboarding credential plan acquisition mode is invalid")
	}
	// endpoints indexes exact onboarding endpoints for binding ownership validation.
	// endpoints 为绑定所有权校验索引精确的录入端点。
	endpoints := make(map[string]Endpoint, len(onboarding.Endpoints))
	for _, endpoint := range onboarding.Endpoints {
		if errEndpoint := endpoint.Validate(); errEndpoint != nil {
			return errEndpoint
		}
		if endpoint.ProviderInstanceID != onboarding.Instance.ID || !definition.HasChannel(endpoint.ChannelID) {
			return invalid("system onboarding endpoint is outside its provider definition")
		}
		if errPreset := definition.ValidateEndpointPreset(endpoint); errPreset != nil {
			return errPreset
		}
		if _, exists := endpoints[endpoint.ID]; exists {
			return invalid("duplicate system onboarding endpoint id %q", endpoint.ID)
		}
		endpoints[endpoint.ID] = endpoint
	}
	// boundChannels ensures every runtime-ready selected channel has exactly one closed access path.
	// boundChannels 确保每个运行时就绪的已选通道都恰有一条闭合访问路径。
	boundChannels := make(map[string]struct{}, len(onboarding.Bindings))
	for _, binding := range onboarding.Bindings {
		if errBinding := binding.Validate(); errBinding != nil {
			return errBinding
		}
		_, endpointExists := endpoints[binding.EndpointID]
		if !endpointExists || binding.ProviderInstanceID != onboarding.Instance.ID || binding.CredentialID != onboarding.Credential.ID || !definition.ChannelAllowsAuth(binding.ChannelID, onboarding.Credential.AuthMethodID) {
			return invalid("system onboarding binding does not close one exact provider channel")
		}
		if _, exists := boundChannels[binding.ChannelID]; exists {
			return invalid("duplicate system onboarding channel binding %q", binding.ChannelID)
		}
		boundChannels[binding.ChannelID] = struct{}{}
	}
	if len(onboarding.Endpoints) == 0 || len(onboarding.Bindings) == 0 {
		return invalid("system onboarding requires endpoints and bindings")
	}
	for _, channelID := range definition.ChannelIDs() {
		if _, exists := boundChannels[channelID]; !exists {
			return invalid("system onboarding is missing provider channel binding %q", channelID)
		}
	}
	return nil
}

// ValidateCustomOnboarding verifies one complete single-protocol custom definition and initial executable graph before persistence.
// ValidateCustomOnboarding 在持久化前校验一个完整单协议自定义 Definition 与初始可执行图。
func ValidateCustomOnboarding(onboarding CustomOnboarding) error {
	definition := onboarding.Definition
	if definition.Kind != DefinitionKindCustom || onboarding.Instance.DefinitionID != definition.ID {
		return invalid("custom onboarding requires its exact custom provider definition")
	}
	if errDefinition := definition.Validate(); errDefinition != nil {
		return errDefinition
	}
	if len(definition.EndpointPresets) != 0 || len(definition.AuthMethodIDs) != 1 || definition.AuthMethodIDs[0] != "default" || len(definition.AuthMethods) != 1 || definition.AuthMethods[0].ID != "default" {
		return invalid("custom onboarding requires one default authentication method and no code-owned endpoint presets")
	}
	// expectedAuthType is fixed by the selected execution factory rather than supplied independently by users.
	// expectedAuthType 由所选执行 Factory 固定，而不是由用户独立提供。
	expectedAuthType := AuthMethodType("")
	switch definition.EndpointProfileID {
	case CustomEndpointProfileOpenAICompatibility:
		expectedAuthType = AuthMethodBearer
	case CustomEndpointProfileOpenAIResponsesCompatibility:
		expectedAuthType = AuthMethodBearer
	case CustomEndpointProfileAnthropicMessagesCompatibility:
		expectedAuthType = AuthMethodHeaderKey
	case CustomEndpointProfileVertexCompatibility:
		expectedAuthType = AuthMethodHeaderKey
	default:
		return invalid("custom onboarding endpoint profile %q has no execution factory", definition.EndpointProfileID)
	}
	if definition.AuthMethods[0].Type != expectedAuthType {
		return invalid("custom onboarding authentication does not match endpoint profile %q", definition.EndpointProfileID)
	}
	if errInstance := onboarding.Instance.Validate(); errInstance != nil {
		return errInstance
	}
	if onboarding.Instance.DefinitionRevision != definition.Revision || onboarding.Instance.Status != LifecycleReady {
		return invalid("custom onboarding instance must be ready and match the definition revision")
	}
	if errEndpoint := onboarding.Endpoint.Validate(); errEndpoint != nil {
		return errEndpoint
	}
	if onboarding.Endpoint.ProviderInstanceID != onboarding.Instance.ID || onboarding.Endpoint.ChannelID != definition.ProtocolProfileID || onboarding.Endpoint.Status != EndpointReady {
		return invalid("custom onboarding endpoint is outside its exact protocol channel")
	}
	if errCredential := onboarding.Credential.Validate(); errCredential != nil {
		return errCredential
	}
	if onboarding.Credential.ProviderInstanceID != onboarding.Instance.ID || onboarding.Credential.AuthMethodID != "default" || onboarding.Credential.Status != CredentialActive {
		return invalid("custom onboarding credential is outside its exact authentication method")
	}
	if errBinding := onboarding.Binding.Validate(); errBinding != nil {
		return errBinding
	}
	if onboarding.Binding.ProviderInstanceID != onboarding.Instance.ID || onboarding.Binding.ChannelID != definition.ProtocolProfileID || onboarding.Binding.EndpointID != onboarding.Endpoint.ID || onboarding.Binding.CredentialID != onboarding.Credential.ID || !onboarding.Binding.Enabled {
		return invalid("custom onboarding binding does not close the exact protocol access path")
	}
	return nil
}

// ValidateCustomDefinitionMigration verifies one replacement definition and the complete, otherwise unchanged instance transition.
// ValidateCustomDefinitionMigration 校验一个替换定义及完整且除此之外未变化的实例转换。
func ValidateCustomDefinitionMigration(migration CustomDefinitionMigration, currentDefinition ProviderDefinition, currentInstances []ProviderInstance, protocols *ProtocolRegistry) error {
	if errDefinition := ValidateCustomDefinition(migration.Definition, protocols); errDefinition != nil {
		return errDefinition
	}
	if currentDefinition.Kind != DefinitionKindCustom || migration.Definition.ID != currentDefinition.ID {
		return invalid("custom definition migration requires its exact current custom definition")
	}
	if migration.Definition.Revision != currentDefinition.Revision+1 {
		return invalid("custom definition migration revision must increase exactly once")
	}
	if len(migration.Instances) != len(currentInstances) {
		return invalid("custom definition migration must contain every existing provider instance")
	}
	// currentByID proves the migration neither omits nor invents definition-owned instances.
	// currentByID 证明迁移既不遗漏也不虚构该定义拥有的实例。
	currentByID := make(map[string]ProviderInstance, len(currentInstances))
	for _, current := range currentInstances {
		if current.DefinitionID != currentDefinition.ID {
			return invalid("custom definition migration current instance ownership is invalid")
		}
		if _, exists := currentByID[current.ID]; exists {
			return invalid("duplicate current custom definition instance %q", current.ID)
		}
		currentByID[current.ID] = current
	}
	for _, next := range migration.Instances {
		current, exists := currentByID[next.ID]
		if !exists {
			return invalid("custom definition migration contains an unknown provider instance %q", next.ID)
		}
		if errInstance := next.Validate(); errInstance != nil {
			return errInstance
		}
		if errMutation := current.ValidateMutation(next); errMutation != nil {
			return errMutation
		}
		if next.DefinitionRevision != migration.Definition.Revision || next.Status != LifecycleMigrationRequired || next.Revision != current.Revision+1 {
			return invalid("custom definition migration instance state or revision is invalid")
		}
		if next.Handle != current.Handle || next.DisplayName != current.DisplayName || next.ProxyRef != current.ProxyRef || !slices.Equal(next.DisabledModelIDs, current.DisabledModelIDs) || !slices.Equal(next.DisabledServiceIDs, current.DisabledServiceIDs) {
			return invalid("custom definition migration may only change migration state and revisions")
		}
		delete(currentByID, next.ID)
	}
	if len(currentByID) != 0 {
		return invalid("custom definition migration omitted existing provider instances")
	}
	return nil
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
	case AuthMethodOAuth, AuthMethodDeviceFlow, AuthMethodAPIKey, AuthMethodBearer, AuthMethodHeaderKey, AuthMethodQueryKey, AuthMethodServiceAccount, AuthMethodNone:
		return true
	default:
		return false
	}
}

// validPlanAcquisitionMode reports whether one plan source belongs to the closed vocabulary.
// validPlanAcquisitionMode 报告一个套餐来源是否属于封闭词汇表。
func validPlanAcquisitionMode(mode PlanAcquisitionMode) bool {
	switch mode {
	case PlanAcquisitionUnavailable, PlanAcquisitionProviderDetected, PlanAcquisitionManualRequired, PlanAcquisitionManualOptional:
		return true
	default:
		return false
	}
}

// validRoutingStrategy reports whether one persisted credential strategy is supported.
// validRoutingStrategy 报告一个持久化凭据策略是否受支持。
func validRoutingStrategy(strategy RoutingStrategy) bool {
	return strategy == RoutingRoundRobin || strategy == RoutingFillFirst
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
