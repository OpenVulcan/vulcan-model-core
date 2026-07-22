package catalog

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

var (
	// ErrInvalidCatalog reports invalid provider-scoped model metadata.
	// ErrInvalidCatalog 表示供应商作用域模型元数据无效。
	ErrInvalidCatalog = errors.New("invalid provider catalog")
	// catalogIdentifierPattern restricts internal catalog identifiers to portable lowercase values.
	// catalogIdentifierPattern 将内部目录标识限制为可移植的小写值。
	catalogIdentifierPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	// currencyCodePattern restricts monetary allowances to normalized ISO-style currency codes.
	// currencyCodePattern 将货币资源限制为规范化的 ISO 风格货币代码。
	currencyCodePattern = regexp.MustCompile(`^[A-Z]{3}$`)
	// nonNegativeDecimalPattern accepts only JSON-compatible non-negative decimal notation.
	// nonNegativeDecimalPattern 仅接受与 JSON 兼容的非负十进制表示法。
	nonNegativeDecimalPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$`)
	// payloadPathPattern accepts explicit object paths while rejecting array selectors and ambiguous sjson syntax.
	// payloadPathPattern 接受显式对象路径，同时拒绝数组选择器与有歧义的 sjson 语法。
	payloadPathPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*(\.[A-Za-z_][A-Za-z0-9_-]*)*$`)
)

// Validate verifies one atomic provider-scoped catalog and all cross references.
// Validate 校验一个原子供应商作用域目录及其全部交叉引用。
func (s Snapshot) Validate() error {
	if err := validatePrefixedID("catalog provider instance id", s.ProviderInstanceID, "pvi_"); err != nil {
		return err
	}
	if s.Revision == 0 || s.ObservedAt.IsZero() {
		return invalid("catalog revision and observed time are required")
	}
	if s.Dynamic != nil {
		if errDynamic := s.Dynamic.Validate(); errDynamic != nil {
			return errDynamic
		}
	}
	if errAdditional := s.DefaultAdditionalParameters.Validate(); errAdditional != nil {
		return fmt.Errorf("provider default additional parameters: %w", errAdditional)
	}
	providerAdditionalPaths := additionalProjectionPaths(s.DefaultAdditionalParameters)
	models := make(map[string]ProviderModel, len(s.Models))
	for _, model := range s.Models {
		if err := model.Validate(); err != nil {
			return err
		}
		if model.ProviderInstanceID != s.ProviderInstanceID {
			return invalid("model %q crosses provider instances", model.ID)
		}
		if _, exists := models[model.ID]; exists {
			return invalid("duplicate model id %q", model.ID)
		}
		models[model.ID] = model
	}
	offerings := make(map[string]ModelOffering, len(s.Offerings))
	for _, offering := range s.Offerings {
		if err := offering.Validate(); err != nil {
			return err
		}
		for reasoningPath := range reasoningProjectionPaths(offering.RequestProjection.Reasoning) {
			if pathConflictsWithSet(reasoningPath, providerAdditionalPaths) {
				return invalid("offering %q reasoning path %q conflicts with provider default additional parameters", offering.ID, reasoningPath)
			}
		}
		if offering.ProviderInstanceID != s.ProviderInstanceID {
			return invalid("offering %q crosses provider instances", offering.ID)
		}
		if _, exists := models[offering.ProviderModelID]; !exists {
			return invalid("offering %q references unknown model %q", offering.ID, offering.ProviderModelID)
		}
		if _, exists := offerings[offering.ID]; exists {
			return invalid("duplicate offering id %q", offering.ID)
		}
		offerings[offering.ID] = offering
	}
	services := make(map[string]ProviderService, len(s.Services))
	for _, service := range s.Services {
		if errService := service.Validate(); errService != nil {
			return errService
		}
		if service.ProviderInstanceID != s.ProviderInstanceID {
			return invalid("service %q crosses provider instances", service.ID)
		}
		if _, exists := services[service.ID]; exists {
			return invalid("duplicate service id %q", service.ID)
		}
		services[service.ID] = service
	}
	serviceOfferings := make(map[string]ServiceOffering, len(s.ServiceOfferings))
	for _, offering := range s.ServiceOfferings {
		service, exists := services[offering.ProviderServiceID]
		if !exists {
			return invalid("service offering %q references unknown service %q", offering.ID, offering.ProviderServiceID)
		}
		if errOffering := offering.Validate(service.Operation); errOffering != nil {
			return errOffering
		}
		if offering.Capabilities.WebSearch != nil && offering.Capabilities.WebSearch.BackendKind == vcp.SearchBackendGroundedModel {
			if _, exists := offerings[offering.Capabilities.WebSearch.BackingModelOfferingID]; !exists {
				return invalid("service offering %q references unknown backing model offering %q", offering.ID, offering.Capabilities.WebSearch.BackingModelOfferingID)
			}
		}
		if offering.ProviderInstanceID != s.ProviderInstanceID {
			return invalid("service offering %q crosses provider instances", offering.ID)
		}
		if _, exists := serviceOfferings[offering.ID]; exists {
			return invalid("duplicate service offering id %q", offering.ID)
		}
		serviceOfferings[offering.ID] = offering
	}
	profiles := make(map[string]ExecutionProfile, len(s.Profiles))
	profileModels := make(map[string]string, len(s.Profiles))
	profileServices := make(map[string]string, len(s.Profiles))
	defaultProfiles := make(map[string]string)
	for _, profile := range s.Profiles {
		if err := profile.Validate(); err != nil {
			return err
		}
		if profile.ProviderInstanceID != s.ProviderInstanceID {
			return invalid("profile %q crosses provider instances", profile.ID)
		}
		profileSubject := ""
		if profile.OfferingID != "" {
			offering, exists := offerings[profile.OfferingID]
			if !exists {
				return invalid("profile %q references unknown offering %q", profile.ID, profile.OfferingID)
			}
			profileSubject = "model\x00" + profile.OfferingID
			profileModels[profile.ID] = offering.ProviderModelID
		} else {
			offering, exists := serviceOfferings[profile.ServiceOfferingID]
			if !exists {
				return invalid("profile %q references unknown service offering %q", profile.ID, profile.ServiceOfferingID)
			}
			service := services[offering.ProviderServiceID]
			if profile.Operation != service.Operation {
				return invalid("profile %q operation does not match service %q", profile.ID, service.ID)
			}
			profileSubject = "service\x00" + profile.ServiceOfferingID
			profileServices[profile.ID] = offering.ProviderServiceID
		}
		if _, exists := profiles[profile.ID]; exists {
			return invalid("duplicate profile id %q", profile.ID)
		}
		if profile.Default {
			if existingProfileID, exists := defaultProfiles[profileSubject]; exists {
				return invalid("offering %q has multiple default profiles %q and %q", profileSubject, existingProfileID, profile.ID)
			}
			defaultProfiles[profileSubject] = profile.ID
		}
		profiles[profile.ID] = profile
	}
	for offeringID := range offerings {
		if _, exists := defaultProfiles["model\x00"+offeringID]; !exists {
			return invalid("offering %q requires exactly one default profile", offeringID)
		}
	}
	for offeringID := range serviceOfferings {
		if _, exists := defaultProfiles["service\x00"+offeringID]; !exists {
			return invalid("service offering %q requires exactly one default profile", offeringID)
		}
	}
	entitlementIDs := make(map[string]struct{}, len(s.Entitlements))
	entitlementSubjects := make(map[string]string, len(s.Entitlements))
	for _, entitlement := range s.Entitlements {
		if err := entitlement.Validate(); err != nil {
			return err
		}
		if entitlement.ProviderInstanceID != s.ProviderInstanceID {
			return invalid("entitlement %q crosses provider instances", entitlement.ID)
		}
		if _, exists := models[entitlement.ProviderModelID]; !exists {
			return invalid("entitlement %q references unknown model %q", entitlement.ID, entitlement.ProviderModelID)
		}
		if _, exists := entitlementIDs[entitlement.ID]; exists {
			return invalid("duplicate entitlement id %q", entitlement.ID)
		}
		entitlementIDs[entitlement.ID] = struct{}{}
		entitlementSubject := entitlement.CredentialID + "\x00" + entitlement.ProviderModelID
		if existingEntitlementID, exists := entitlementSubjects[entitlementSubject]; exists {
			return invalid("credential %q and model %q have multiple entitlements %q and %q", entitlement.CredentialID, entitlement.ProviderModelID, existingEntitlementID, entitlement.ID)
		}
		entitlementSubjects[entitlementSubject] = entitlement.ID
		for _, profileID := range entitlement.AllowedProfileIDs {
			if _, exists := profiles[profileID]; !exists {
				return invalid("entitlement %q references unknown profile %q", entitlement.ID, profileID)
			}
			if profileModels[profileID] != entitlement.ProviderModelID {
				return invalid("entitlement %q references profile %q from another model", entitlement.ID, profileID)
			}
		}
	}
	serviceEntitlementIDs := make(map[string]struct{}, len(s.ServiceEntitlements))
	serviceEntitlementSubjects := make(map[string]string, len(s.ServiceEntitlements))
	for _, entitlement := range s.ServiceEntitlements {
		if errEntitlement := entitlement.Validate(); errEntitlement != nil {
			return errEntitlement
		}
		if entitlement.ProviderInstanceID != s.ProviderInstanceID {
			return invalid("service entitlement %q crosses provider instances", entitlement.ID)
		}
		if _, exists := services[entitlement.ProviderServiceID]; !exists {
			return invalid("service entitlement %q references unknown service %q", entitlement.ID, entitlement.ProviderServiceID)
		}
		if _, exists := serviceEntitlementIDs[entitlement.ID]; exists {
			return invalid("duplicate service entitlement id %q", entitlement.ID)
		}
		serviceEntitlementIDs[entitlement.ID] = struct{}{}
		entitlementSubject := entitlement.CredentialID + "\x00" + entitlement.ProviderServiceID
		if existingEntitlementID, exists := serviceEntitlementSubjects[entitlementSubject]; exists {
			return invalid("credential %q and service %q have multiple entitlements %q and %q", entitlement.CredentialID, entitlement.ProviderServiceID, existingEntitlementID, entitlement.ID)
		}
		serviceEntitlementSubjects[entitlementSubject] = entitlement.ID
		for _, profileID := range entitlement.AllowedProfileIDs {
			if _, exists := profiles[profileID]; !exists {
				return invalid("service entitlement %q references unknown profile %q", entitlement.ID, profileID)
			}
			if profileServices[profileID] != entitlement.ProviderServiceID {
				return invalid("service entitlement %q references profile %q from another service", entitlement.ID, profileID)
			}
		}
	}
	planIDs := make(map[string]struct{}, len(s.Plans))
	// planSubjects enforces the singular current-plan contract for each exact credential.
	// planSubjects 为每个精确凭据强制执行单一当前套餐合同。
	planSubjects := make(map[string]string, len(s.Plans))
	for _, plan := range s.Plans {
		if err := plan.Validate(); err != nil {
			return err
		}
		if plan.ProviderInstanceID != s.ProviderInstanceID {
			return invalid("plan snapshot %q crosses provider instances", plan.ID)
		}
		if _, exists := planIDs[plan.ID]; exists {
			return invalid("duplicate plan snapshot id %q", plan.ID)
		}
		planIDs[plan.ID] = struct{}{}
		if existingPlanID, exists := planSubjects[plan.CredentialID]; exists {
			return invalid("credential %q has multiple plan snapshots %q and %q", plan.CredentialID, existingPlanID, plan.ID)
		}
		planSubjects[plan.CredentialID] = plan.ID
	}
	allowanceIDs := make(map[string]struct{}, len(s.Allowances))
	for _, allowance := range s.Allowances {
		if err := allowance.Validate(); err != nil {
			return err
		}
		if allowance.ProviderInstanceID != s.ProviderInstanceID {
			return invalid("allowance %q crosses provider instances", allowance.ID)
		}
		if _, exists := allowanceIDs[allowance.ID]; exists {
			return invalid("duplicate allowance snapshot id %q", allowance.ID)
		}
		allowanceIDs[allowance.ID] = struct{}{}
		if allowance.Scope == ScopeProviderModel {
			if _, exists := models[allowance.ScopeID]; !exists {
				return invalid("allowance %q references unknown model %q", allowance.ID, allowance.ScopeID)
			}
		}
		if allowance.Scope == ScopeExecutionProfile {
			if _, exists := profiles[allowance.ScopeID]; !exists {
				return invalid("allowance %q references unknown profile %q", allowance.ID, allowance.ScopeID)
			}
		}
	}
	voiceIDs := make(map[string]struct{}, len(s.Voices))
	voiceSubjects := make(map[string]string, len(s.Voices))
	for _, voice := range s.Voices {
		if errVoice := voice.Validate(); errVoice != nil {
			return errVoice
		}
		if voice.ProviderInstanceID != s.ProviderInstanceID {
			return invalid("voice %q crosses provider instances", voice.ID)
		}
		if _, exists := voiceIDs[voice.ID]; exists {
			return invalid("duplicate voice id %q", voice.ID)
		}
		voiceIDs[voice.ID] = struct{}{}
		subject := voice.CredentialID + "\x00" + voice.VoiceID
		if existingID, exists := voiceSubjects[subject]; exists {
			return invalid("credential %q and provider voice %q have multiple records %q and %q", voice.CredentialID, voice.VoiceID, existingID, voice.ID)
		}
		voiceSubjects[subject] = voice.ID
	}
	poolProfiles := make(map[string]struct{}, len(s.Pools))
	for _, pool := range s.Pools {
		if err := pool.Validate(); err != nil {
			return err
		}
		if pool.ProviderInstanceID != s.ProviderInstanceID {
			return invalid("pool %q crosses provider instances", pool.ExecutionProfileID)
		}
		if _, exists := profiles[pool.ExecutionProfileID]; !exists {
			return invalid("pool references unknown profile %q", pool.ExecutionProfileID)
		}
		if _, exists := poolProfiles[pool.ExecutionProfileID]; exists {
			return invalid("duplicate pool summary for profile %q", pool.ExecutionProfileID)
		}
		poolProfiles[pool.ExecutionProfileID] = struct{}{}
	}
	return nil
}

// Validate verifies one credential-scoped voice observation and its cache boundary.
// Validate 校验一个凭据作用域声音观测及其缓存边界。
func (v VoiceSnapshot) Validate() error {
	if errID := validatePrefixedID("voice id", v.ID, "voice_"); errID != nil {
		return errID
	}
	if errInstance := validatePrefixedID("voice provider instance id", v.ProviderInstanceID, "pvi_"); errInstance != nil {
		return errInstance
	}
	if errCredential := validatePrefixedID("voice credential id", v.CredentialID, "cred_"); errCredential != nil {
		return errCredential
	}
	if strings.TrimSpace(v.VoiceID) == "" || v.VoiceID != strings.TrimSpace(v.VoiceID) || strings.TrimSpace(v.DisplayName) == "" || v.DisplayName != strings.TrimSpace(v.DisplayName) || !validModelSource(v.Source) || v.ObservedAt.IsZero() || !v.ExpiresAt.After(v.ObservedAt) || v.Revision == 0 {
		return invalid("voice identity, source, freshness, and revision are required")
	}
	descriptions := make(map[string]struct{}, len(v.Descriptions))
	for _, description := range v.Descriptions {
		if strings.TrimSpace(description) == "" || description != strings.TrimSpace(description) {
			return invalid("voice %q contains an empty or unnormalized description", v.ID)
		}
		if _, exists := descriptions[description]; exists {
			return invalid("voice %q contains duplicate description %q", v.ID, description)
		}
		descriptions[description] = struct{}{}
	}
	return nil
}

// Validate verifies dynamic source, freshness, failure, and tombstone facts.
// Validate 校验动态来源、新鲜度、失败与墓碑事实。
func (m DynamicCatalogMetadata) Validate() error {
	if m.Authority != CatalogAuthorityProvider && m.Authority != CatalogAuthoritySignedRemote && m.Authority != CatalogAuthorityUser {
		return invalid("dynamic catalog authority is invalid")
	}
	if strings.TrimSpace(m.SourceRevision) == "" || m.SourceRevision != strings.TrimSpace(m.SourceRevision) || m.RefreshedAt.IsZero() || m.ExpiresAt.IsZero() || m.Status == CatalogRefreshFresh && !m.ExpiresAt.After(m.RefreshedAt) {
		return invalid("dynamic catalog revision and refresh interval are required")
	}
	if m.ETag != strings.TrimSpace(m.ETag) || m.FailureCode != strings.TrimSpace(m.FailureCode) {
		return invalid("dynamic catalog etag and failure code must be normalized")
	}
	if m.Status == CatalogRefreshFresh && m.FailureCode != "" || m.Status == CatalogRefreshStale && m.FailureCode == "" || m.Status != CatalogRefreshFresh && m.Status != CatalogRefreshStale {
		return invalid("dynamic catalog refresh status and failure code do not match")
	}
	seen := make(map[string]struct{}, len(m.Tombstones))
	for _, tombstone := range m.Tombstones {
		if tombstone.Kind != "model" && tombstone.Kind != "service" || strings.TrimSpace(tombstone.ID) == "" || tombstone.ID != strings.TrimSpace(tombstone.ID) || tombstone.RemovedAt.IsZero() {
			return invalid("dynamic catalog tombstone is invalid")
		}
		key := tombstone.Kind + "\x00" + tombstone.ID
		if _, exists := seen[key]; exists {
			return invalid("duplicate dynamic catalog tombstone %q", tombstone.ID)
		}
		seen[key] = struct{}{}
	}
	return nil
}

// Validate verifies one provider-scoped logical model.
// Validate 校验一个供应商作用域逻辑模型。
func (m ProviderModel) Validate() error {
	if err := validatePrefixedID("provider model id", m.ID, "model_"); err != nil {
		return err
	}
	if err := validatePrefixedID("provider model instance id", m.ProviderInstanceID, "pvi_"); err != nil {
		return err
	}
	if strings.TrimSpace(m.UpstreamModelID) == "" || strings.TrimSpace(m.DisplayName) == "" {
		return invalid("provider model upstream id and display name are required")
	}
	if !validModelSource(m.Source) || !validEntitlementMode(m.EntitlementMode) || m.Revision == 0 {
		return invalid("provider model source, entitlement mode, or revision is invalid")
	}
	return nil
}

// Validate verifies one channel-specific model offering.
// Validate 校验一个通道特定模型产品。
func (o ModelOffering) Validate() error {
	if err := validatePrefixedID("model offering id", o.ID, "offer_"); err != nil {
		return err
	}
	if err := validatePrefixedID("model offering instance id", o.ProviderInstanceID, "pvi_"); err != nil {
		return err
	}
	if err := validatePrefixedID("model offering model id", o.ProviderModelID, "model_"); err != nil {
		return err
	}
	if err := validateID("model offering channel id", o.ChannelID); err != nil {
		return err
	}
	if strings.TrimSpace(o.UpstreamModelID) == "" || o.CapabilityRevision == 0 || o.Revision == 0 {
		return invalid("model offering upstream id and revisions are required")
	}
	if errCapabilities := o.Capabilities.Validate(); errCapabilities != nil {
		return errCapabilities
	}
	return o.RequestProjection.Validate()
}

// Validate verifies one client-selectable execution profile.
// Validate 校验一个客户端可选择执行规格。
func (p ExecutionProfile) Validate() error {
	if err := validatePrefixedID("execution profile id", p.ID, "profile_"); err != nil {
		return err
	}
	if err := validatePrefixedID("execution profile instance id", p.ProviderInstanceID, "pvi_"); err != nil {
		return err
	}
	if (p.OfferingID == "") == (p.ServiceOfferingID == "") {
		return invalid("execution profile requires exactly one model or service offering")
	}
	if p.OfferingID != "" {
		if errOffering := validatePrefixedID("execution profile offering id", p.OfferingID, "offer_"); errOffering != nil {
			return errOffering
		}
		if p.ServiceCapabilities != nil {
			return invalid("model execution profile cannot carry service capabilities")
		}
		if p.Operation == vcp.OperationSearchWeb || p.Operation == vcp.OperationWebExtract {
			return invalid("operation %q requires a service execution profile", p.Operation)
		}
		if p.Operation != "" && p.ActionBindingID == "" {
			return invalid("typed model execution profile requires action binding id")
		}
	} else {
		if errOffering := validatePrefixedID("execution profile service offering id", p.ServiceOfferingID, "service_offer_"); errOffering != nil {
			return errOffering
		}
		if p.Operation == "" || p.ServiceCapabilities == nil {
			return invalid("service execution profile requires operation and service capabilities")
		}
		if errAction := validatePrefixedID("execution profile action binding id", p.ActionBindingID, "action_"); errAction != nil {
			return errAction
		}
	}
	if strings.TrimSpace(p.DisplayName) == "" || p.CapabilityRevision == 0 || p.Revision == 0 {
		return invalid("execution profile display name and revisions are required")
	}
	if !validSwitchPolicy(p.SwitchPolicy) || !validPoolPolicy(p.PoolPolicy) {
		return invalid("execution profile switch or pool policy is invalid")
	}
	for _, entitlementClass := range p.RequiredEntitlementClasses {
		if err := validateID("execution profile entitlement class", entitlementClass); err != nil {
			return err
		}
	}
	if p.OfferingID != "" {
		if errCapabilities := p.Capabilities.Validate(); errCapabilities != nil {
			return errCapabilities
		}
		return p.Capabilities.ValidateOperation(p.Operation)
	}
	return p.ServiceCapabilities.Validate(p.Operation)
}

// Validate verifies one credential-specific model entitlement.
// Validate 校验一个凭据特定模型授权。
func (e ModelEntitlement) Validate() error {
	if err := validatePrefixedID("model entitlement id", e.ID, "ent_"); err != nil {
		return err
	}
	if err := validatePrefixedID("model entitlement instance id", e.ProviderInstanceID, "pvi_"); err != nil {
		return err
	}
	if err := validatePrefixedID("model entitlement credential id", e.CredentialID, "cred_"); err != nil {
		return err
	}
	if err := validatePrefixedID("model entitlement model id", e.ProviderModelID, "model_"); err != nil {
		return err
	}
	if !validAvailability(e.Availability) || !validModelSource(e.Source) || e.Revision == 0 {
		return invalid("model entitlement availability, source, or revision is invalid")
	}
	if e.EntitlementClass != "" {
		if err := validateID("model entitlement class", e.EntitlementClass); err != nil {
			return err
		}
	}
	for _, profileID := range e.AllowedProfileIDs {
		if err := validatePrefixedID("model entitlement profile id", profileID, "profile_"); err != nil {
			return err
		}
	}
	if errEvidence := validateMetadataEvidence(e.EvidenceSource, e.ObservedAt, e.ExpiresAt); errEvidence != nil {
		return fmt.Errorf("model entitlement evidence: %w", errEvidence)
	}
	return e.LimitOverrides.Validate()
}

// Validate verifies one commercial plan snapshot.
// Validate 校验一个商业套餐快照。
func (p PlanSnapshot) Validate() error {
	if err := validatePrefixedID("plan snapshot id", p.ID, "plan_"); err != nil {
		return err
	}
	if err := validatePrefixedID("plan snapshot instance id", p.ProviderInstanceID, "pvi_"); err != nil {
		return err
	}
	if err := validatePrefixedID("plan snapshot credential id", p.CredentialID, "cred_"); err != nil {
		return err
	}
	if strings.TrimSpace(p.PlanCode) == "" || strings.TrimSpace(p.PlanName) == "" || strings.TrimSpace(p.Status) == "" || p.Revision == 0 {
		return invalid("plan snapshot code, name, status, and revision are required")
	}
	if errEvidence := validateMetadataEvidence(p.EvidenceSource, p.ObservedAt, p.ExpiresAt); errEvidence != nil {
		return fmt.Errorf("plan snapshot evidence: %w", errEvidence)
	}
	return nil
}

// Validate verifies one arbitrary quota, balance, or credit snapshot.
// Validate 校验一个任意额度、余额或 Credit 快照。
func (a AllowanceSnapshot) Validate() error {
	if err := validatePrefixedID("allowance snapshot id", a.ID, "allow_"); err != nil {
		return err
	}
	if err := validatePrefixedID("allowance snapshot instance id", a.ProviderInstanceID, "pvi_"); err != nil {
		return err
	}
	if !validAllowanceKind(a.Kind) || !validAllowanceScope(a.Scope) || !validAllowanceUnit(a.Unit) || !validAllowanceStatus(a.Status) {
		return invalid("allowance kind, scope, unit, or status is invalid")
	}
	if strings.TrimSpace(a.ScopeID) == "" || strings.TrimSpace(a.Metric) == "" || !validModelSource(a.Source) || a.Revision == 0 {
		return invalid("allowance scope id, metric, source, and revision are required")
	}
	if a.Scope == ScopeCredential {
		if err := validatePrefixedID("credential allowance scope id", a.ScopeID, "cred_"); err != nil {
			return err
		}
	}
	if a.Unit == UnitMinorCurrency && !currencyCodePattern.MatchString(a.Currency) {
		return invalid("minor currency allowance requires an ISO currency code")
	}
	if a.Unit != UnitMinorCurrency && a.Currency != "" {
		return invalid("allowance currency is only valid for minor currency units")
	}
	for field, value := range map[string]*string{"limit": a.Limit, "used": a.Used, "remaining": a.Remaining} {
		if value != nil && !validNonNegativeDecimal(*value) {
			return invalid("allowance %s must be a non-negative decimal string", field)
		}
	}
	if a.RemainingRatio != nil && (math.IsNaN(*a.RemainingRatio) || *a.RemainingRatio < 0 || *a.RemainingRatio > 1) {
		return invalid("allowance remaining ratio must be between zero and one")
	}
	if a.DisplayMultiplierPermille != nil && *a.DisplayMultiplierPermille < 0 {
		return invalid("allowance display multiplier must be non-negative")
	}
	if a.Kind == AllowanceWindowQuota {
		if a.Window == nil {
			return invalid("window quota requires window metadata")
		}
		if err := a.Window.Validate(); err != nil {
			return err
		}
	} else if a.Window != nil {
		return invalid("non-window allowance cannot contain quota window metadata")
	}
	if errEvidence := validateMetadataEvidence(a.EvidenceSource, a.ObservedAt, a.ExpiresAt); errEvidence != nil {
		return fmt.Errorf("allowance evidence: %w", errEvidence)
	}
	return nil
}

// Validate verifies one quota window definition.
// Validate 校验一个额度窗口定义。
func (w AllowanceWindow) Validate() error {
	if w.StartAt != nil && w.ResetAt != nil && !w.StartAt.Before(*w.ResetAt) {
		return invalid("allowance window start must precede reset")
	}
	switch w.Kind {
	case WindowRolling:
		if w.Duration <= 0 || w.CalendarUnit != "" {
			return invalid("rolling allowance window requires a positive duration only")
		}
	case WindowCalendar:
		if strings.TrimSpace(w.CalendarUnit) == "" || w.Duration != 0 {
			return invalid("calendar allowance window requires a calendar unit only")
		}
	case WindowProviderDefined:
		if w.Duration != 0 || w.CalendarUnit != "" {
			return invalid("provider-defined allowance window cannot invent duration or calendar semantics")
		}
	default:
		return invalid("allowance window kind %q is invalid", w.Kind)
	}
	return nil
}

// Validate verifies one model capability set.
// Validate 校验一组模型能力。
func (c ModelCapabilities) Validate() error {
	if err := c.Tokens.Validate(); err != nil {
		return err
	}
	if err := c.Recommendations.Validate(c.Tokens); err != nil {
		return err
	}
	levels := []CapabilityLevel{c.ToolCalling, c.ParallelToolCalls, c.StreamingToolArguments, c.StrictJSONSchema, c.Reasoning}
	for _, level := range levels {
		if !validCapabilityLevel(level) {
			return invalid("model capability level %q is invalid", level)
		}
	}
	for _, modality := range append(append([]string(nil), c.InputModalities...), c.OutputModalities...) {
		if err := validateID("model modality", modality); err != nil {
			return err
		}
	}
	if errEfforts := validateUniqueStrings("reasoning effort", c.ReasoningEfforts); errEfforts != nil {
		return errEfforts
	}
	if errSummaries := validateUniqueStrings("reasoning summary mode", c.ReasoningSummaryModes); errSummaries != nil {
		return errSummaries
	}
	if len(c.ReasoningEfforts) > 0 && c.Reasoning != CapabilityNative && c.Reasoning != CapabilityEmulated && c.Reasoning != CapabilityConditional {
		return invalid("reasoning efforts require callable reasoning capability")
	}
	if len(c.ReasoningSummaryModes) > 0 && c.Reasoning != CapabilityNative && c.Reasoning != CapabilityEmulated && c.Reasoning != CapabilityConditional {
		return invalid("reasoning summary modes require callable reasoning capability")
	}
	seenHostedTools := make(map[vcp.ToolKind]struct{}, len(c.HostedTools))
	for _, toolKind := range c.HostedTools {
		if toolKind != vcp.ToolNativeWebSearch && toolKind != vcp.ToolProviderFileSearch && toolKind != vcp.ToolProviderCodeInterpreter && toolKind != vcp.ToolProviderComputerUse {
			return invalid("hosted tool kind %q is invalid", toolKind)
		}
		if _, exists := seenHostedTools[toolKind]; exists {
			return invalid("hosted tool kind %q is duplicated", toolKind)
		}
		seenHostedTools[toolKind] = struct{}{}
	}
	return c.validateExtended()
}

// Validate verifies model-offering request rules without interpreting untyped execution payloads.
// Validate 校验模型产品请求规则，且不解释无类型执行载荷。
func (p RequestProjection) Validate() error {
	effortPaths := make(map[string]struct{})
	if errEffort := validateReasoningParameterRules("reasoning effort", p.Reasoning.Effort, effortPaths); errEffort != nil {
		return errEffort
	}
	summaryPaths := make(map[string]struct{})
	if errSummary := validateReasoningParameterRules("reasoning summary", p.Reasoning.Summary, summaryPaths); errSummary != nil {
		return errSummary
	}
	reasoningPaths := make(map[string]struct{}, len(effortPaths)+len(summaryPaths))
	for path := range effortPaths {
		reasoningPaths[path] = struct{}{}
	}
	for path := range summaryPaths {
		if pathConflictsWithSet(path, effortPaths) {
			return invalid("reasoning summary path %q conflicts with an effort rule", path)
		}
		reasoningPaths[path] = struct{}{}
	}
	if errDefault := validatePayloadParameters("additional default", p.Additional.Default, reasoningPaths, true); errDefault != nil {
		return errDefault
	}
	if errOverride := validatePayloadParameters("additional override", p.Additional.Override, reasoningPaths, true); errOverride != nil {
		return errOverride
	}
	seenFilters := make(map[string]struct{}, len(p.Additional.Filter))
	for _, path := range p.Additional.Filter {
		originalPath := path
		path = strings.TrimSpace(path)
		if originalPath != path {
			return invalid("additional filter path %q must not contain surrounding whitespace", originalPath)
		}
		if errPath := validatePayloadPath("additional filter", path, true); errPath != nil {
			return errPath
		}
		if pathConflictsWithSet(path, reasoningPaths) {
			return invalid("additional filter path %q conflicts with a reasoning rule", path)
		}
		if pathConflictsWithSet(path, seenFilters) {
			return invalid("additional filter path %q is duplicated", path)
		}
		seenFilters[path] = struct{}{}
	}
	return nil
}

// Validate verifies provider-level additional payload mutations without interpreting an execution payload.
// Validate 校验供应商级附加载荷变更，且不解释执行载荷。
func (p AdditionalPayloadProjection) Validate() error {
	return (RequestProjection{Additional: p}).Validate()
}

// reasoningProjectionPaths returns every path owned by model-level reasoning mappings.
// reasoningProjectionPaths 返回模型级推理映射拥有的全部路径。
func reasoningProjectionPaths(projection ReasoningRequestProjection) map[string]struct{} {
	paths := make(map[string]struct{})
	for _, rules := range [][]ReasoningParameterRule{projection.Effort, projection.Summary} {
		for _, rule := range rules {
			for _, parameter := range rule.Set {
				paths[parameter.Path] = struct{}{}
			}
			for _, path := range rule.Delete {
				paths[path] = struct{}{}
			}
		}
	}
	return paths
}

// additionalProjectionPaths returns every path mutated or removed by provider-level additional rules.
// additionalProjectionPaths 返回供应商级附加规则变更或删除的全部路径。
func additionalProjectionPaths(projection AdditionalPayloadProjection) map[string]struct{} {
	paths := make(map[string]struct{}, len(projection.Default)+len(projection.Override)+len(projection.Filter))
	for _, parameters := range [][]PayloadParameter{projection.Default, projection.Override} {
		for _, parameter := range parameters {
			paths[parameter.Path] = struct{}{}
		}
	}
	for _, path := range projection.Filter {
		paths[path] = struct{}{}
	}
	return paths
}

// validateReasoningParameterRules verifies a closed value-to-mutation rule set and records every owned path.
// validateReasoningParameterRules 校验封闭的值到变更规则集合，并记录其拥有的每个路径。
func validateReasoningParameterRules(label string, rules []ReasoningParameterRule, ownedPaths map[string]struct{}) error {
	seenValues := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		value := strings.TrimSpace(rule.Value)
		if value == "" {
			return invalid("%s rule value is required", label)
		}
		if value != rule.Value {
			return invalid("%s rule value %q must not contain surrounding whitespace", label, rule.Value)
		}
		if _, duplicate := seenValues[value]; duplicate {
			return invalid("%s rule value %q is duplicated", label, value)
		}
		seenValues[value] = struct{}{}
		if len(rule.Set) == 0 && len(rule.Delete) == 0 {
			return invalid("%s rule %q requires at least one mutation", label, value)
		}
		rulePaths := make(map[string]struct{}, len(rule.Set)+len(rule.Delete))
		if errSet := validatePayloadParameters(label+" set", rule.Set, nil, true); errSet != nil {
			return errSet
		}
		for _, parameter := range rule.Set {
			path := strings.TrimSpace(parameter.Path)
			if pathConflictsWithSet(path, rulePaths) {
				return invalid("%s rule %q mutates path %q more than once", label, value, path)
			}
			rulePaths[path] = struct{}{}
			ownedPaths[path] = struct{}{}
		}
		for _, path := range rule.Delete {
			originalPath := path
			path = strings.TrimSpace(path)
			if originalPath != path {
				return invalid("%s delete path %q must not contain surrounding whitespace", label, originalPath)
			}
			if errPath := validatePayloadPath(label+" delete", path, true); errPath != nil {
				return errPath
			}
			if pathConflictsWithSet(path, rulePaths) {
				return invalid("%s rule %q mutates path %q more than once", label, value, path)
			}
			rulePaths[path] = struct{}{}
			ownedPaths[path] = struct{}{}
		}
	}
	return nil
}

// validatePayloadParameters verifies exact JSON assignments and optional conflicts with reasoning-owned paths.
// validatePayloadParameters 校验精确 JSON 赋值及其与推理拥有路径的可选冲突。
func validatePayloadParameters(label string, parameters []PayloadParameter, reasoningPaths map[string]struct{}, rejectProtected bool) error {
	seen := make(map[string]struct{}, len(parameters))
	for _, parameter := range parameters {
		path := strings.TrimSpace(parameter.Path)
		if path != parameter.Path {
			return invalid("%s path %q must not contain surrounding whitespace", label, parameter.Path)
		}
		if errPath := validatePayloadPath(label, path, rejectProtected); errPath != nil {
			return errPath
		}
		if !json.Valid(parameter.Value) {
			return invalid("%s path %q requires one valid JSON value", label, path)
		}
		if pathConflictsWithSet(path, seen) {
			return invalid("%s path %q is duplicated", label, path)
		}
		if pathConflictsWithSet(path, reasoningPaths) {
			return invalid("%s path %q conflicts with a reasoning rule", label, path)
		}
		seen[path] = struct{}{}
	}
	return nil
}

// pathConflictsWithSet reports exact or parent-child overlap that would make mutation order observable.
// pathConflictsWithSet 报告会使变更顺序可观察的精确或父子路径重叠。
func pathConflictsWithSet(path string, existing map[string]struct{}) bool {
	for candidate := range existing {
		if path == candidate || strings.HasPrefix(path, candidate+".") || strings.HasPrefix(candidate, path+".") {
			return true
		}
	}
	return false
}

// validatePayloadPath accepts only explicit object paths and protects protocol-owned request identity and content.
// validatePayloadPath 仅接受显式对象路径，并保护协议拥有的请求身份与内容。
func validatePayloadPath(label string, path string, rejectProtected bool) error {
	path = strings.TrimSpace(path)
	if !payloadPathPattern.MatchString(path) {
		return invalid("%s path %q is not a supported object path", label, path)
	}
	if !rejectProtected {
		return nil
	}
	root := strings.SplitN(path, ".", 2)[0]
	normalizedRoot := strings.ReplaceAll(strings.ToLower(root), "-", "_")
	switch normalizedRoot {
	case "model", "messages", "input", "instructions", "system", "tools", "tool_choice", "stream", "previous_response_id", "authorization", "proxy_authorization", "api_key", "apikey", "x_api_key", "access_token", "auth_token", "token", "secret", "client_secret", "password", "credential", "cookie", "set_cookie":
		return invalid("%s path %q is owned by the protocol or authentication boundary", label, path)
	default:
		return nil
	}
}

// Validate verifies token recommendations and their relationship to independently known hard ceilings.
// Validate 校验 Token 推荐值及其与独立已知硬上限之间的关系。
func (r TokenRecommendations) Validate(limits TokenLimits) error {
	recommendations := []OptionalTokenLimit{r.OutputTokens, r.ReasoningTokens}
	for _, recommendation := range recommendations {
		if recommendation.Known && recommendation.Value <= 0 {
			return invalid("known token recommendation must be positive")
		}
		if !recommendation.Known && recommendation.Value != 0 {
			return invalid("unknown token recommendation cannot carry a value")
		}
	}
	if r.OutputTokens.Known && limits.MaxOutputTokens.Known && r.OutputTokens.Value > limits.MaxOutputTokens.Value {
		return invalid("recommended output tokens exceed the known maximum output")
	}
	if r.ReasoningTokens.Known && limits.MaxReasoningTokens.Known && r.ReasoningTokens.Value > limits.MaxReasoningTokens.Value {
		return invalid("recommended reasoning tokens exceed the known maximum reasoning budget")
	}
	if r.OutputTokens.Known && limits.ContextWindow.Known && r.OutputTokens.Value > limits.ContextWindow.Value {
		return invalid("recommended output tokens exceed the known context window")
	}
	if r.ReasoningTokens.Known && limits.ContextWindow.Known && r.ReasoningTokens.Value > limits.ContextWindow.Value {
		return invalid("recommended reasoning tokens exceed the known context window")
	}
	if r.OutputTokens.Known && r.ReasoningTokens.Known && r.ReasoningTokens.Value > r.OutputTokens.Value {
		return invalid("recommended reasoning tokens exceed the recommended output budget")
	}
	return nil
}

// Validate verifies independently known token limits without deriving missing values.
// Validate 校验独立已知的 Token 限制且不推导缺失值。
func (l TokenLimits) Validate() error {
	limits := []OptionalTokenLimit{l.ContextWindow, l.MaxInputTokens, l.MaxOutputTokens, l.MaxReasoningTokens}
	for _, limit := range limits {
		if limit.Known && limit.Value <= 0 {
			return invalid("known token limit must be positive")
		}
		if !limit.Known && limit.Value != 0 {
			return invalid("unknown token limit cannot carry a value")
		}
	}
	return nil
}

// Validate verifies one client-safe pool summary.
// Validate 校验一个客户端安全账号池摘要。
func (p PoolSummary) Validate() error {
	if err := validatePrefixedID("pool provider instance id", p.ProviderInstanceID, "pvi_"); err != nil {
		return err
	}
	if err := validatePrefixedID("pool execution profile id", p.ExecutionProfileID, "profile_"); err != nil {
		return err
	}
	counts := []int{p.ConfiguredCredentials, p.EntitledCredentials, p.ReadyCredentials, p.CoolingCredentials, p.ExhaustedCredentials, p.InvalidCredentials}
	for _, count := range counts {
		if count < 0 {
			return invalid("pool counts cannot be negative")
		}
	}
	// classifiedCredentials counts mutually exclusive runtime outcome classes beneath the entitled pool.
	// classifiedCredentials 统计已授权账号池下互斥的运行时结果分类。
	classifiedCredentials := p.ReadyCredentials + p.CoolingCredentials + p.ExhaustedCredentials + p.InvalidCredentials
	if p.EntitledCredentials > p.ConfiguredCredentials || p.ReadyCredentials > p.EntitledCredentials || p.CoolingCredentials > p.EntitledCredentials || p.ExhaustedCredentials > p.EntitledCredentials || p.InvalidCredentials > p.EntitledCredentials || classifiedCredentials > p.EntitledCredentials || p.Revision == 0 || p.ObservedAt.IsZero() {
		return invalid("pool count relationships, revision, or observed time are invalid")
	}
	if p.ExhaustedCredentials == 0 && (len(p.BlockingAllowanceKinds) > 0 || p.EarliestResetAt != nil) {
		return invalid("pool blocking allowances require an exhausted credential")
	}
	// seenAllowanceKinds prevents duplicated diagnostic categories in one pool summary.
	// seenAllowanceKinds 防止一个账号池摘要中出现重复诊断类别。
	seenAllowanceKinds := make(map[AllowanceKind]struct{}, len(p.BlockingAllowanceKinds))
	for _, allowanceKind := range p.BlockingAllowanceKinds {
		if !validAllowanceKind(allowanceKind) {
			return invalid("pool blocking allowance kind %q is invalid", allowanceKind)
		}
		if _, exists := seenAllowanceKinds[allowanceKind]; exists {
			return invalid("pool blocking allowance kind %q is duplicated", allowanceKind)
		}
		seenAllowanceKinds[allowanceKind] = struct{}{}
	}
	return nil
}

// validNonNegativeDecimal reports whether one string is an exact non-negative decimal.
// validNonNegativeDecimal 返回字符串是否是精确非负十进制数。
func validNonNegativeDecimal(value string) bool {
	return nonNegativeDecimalPattern.MatchString(value)
}

// validCapabilityLevel reports whether a capability level is explicitly defined.
// validCapabilityLevel 返回能力等级是否已显式定义。
func validCapabilityLevel(level CapabilityLevel) bool {
	switch level {
	case CapabilityNative, CapabilityEmulated, CapabilityUnsupported, CapabilityConditional, CapabilityUnknown:
		return true
	default:
		return false
	}
}

// validAvailability reports whether an availability state is explicitly defined.
// validAvailability 返回可用状态是否已显式定义。
func validAvailability(status AvailabilityStatus) bool {
	switch status {
	case AvailabilityAllowed, AvailabilityDenied, AvailabilityConditional, AvailabilityUnknown, AvailabilityTemporarilyUnavailable:
		return true
	default:
		return false
	}
}

// validModelSource reports whether a model evidence source is explicitly defined.
// validModelSource 返回模型证据来源是否已显式定义。
func validModelSource(source ModelSource) bool {
	switch source {
	case ModelSourceSystem, ModelSourceProviderAPI, ModelSourceCredentialDiscovery, ModelSourceRuntimeEvidence, ModelSourceUserDeclared:
		return true
	default:
		return false
	}
}

// validateMetadataEvidence verifies one commercial fact's authority and optional validity window.
// validateMetadataEvidence 校验一个商业事实的权威来源与可选有效期窗口。
func validateMetadataEvidence(source MetadataEvidenceSource, observedAt time.Time, expiresAt time.Time) error {
	if observedAt.IsZero() {
		return invalid("observed time is required")
	}
	if source == "" {
		if expiresAt.IsZero() || expiresAt.Before(observedAt) {
			return invalid("legacy evidence requires a valid expiry time")
		}
		return nil
	}
	if !validMetadataEvidenceSource(source) {
		return invalid("metadata evidence source %q is invalid", source)
	}
	if expiresAt.IsZero() {
		if source != MetadataEvidenceOperatorDeclared && source != MetadataEvidenceSystemRule {
			return invalid("expiring provider evidence requires an expiry time")
		}
		return nil
	}
	if expiresAt.Before(observedAt) {
		return invalid("expiry time precedes observation time")
	}
	return nil
}

// validMetadataEvidenceSource reports whether one commercial fact source is registered.
// validMetadataEvidenceSource 报告一个商业事实来源是否已注册。
func validMetadataEvidenceSource(source MetadataEvidenceSource) bool {
	switch source {
	case MetadataEvidenceProviderAPI, MetadataEvidenceProtectedTokenClaim, MetadataEvidenceOperatorDeclared, MetadataEvidenceSystemRule, MetadataEvidenceRuntimeObservation:
		return true
	default:
		return false
	}
}

// validEntitlementMode reports whether a model entitlement mode is explicitly defined.
// validEntitlementMode 返回模型授权模式是否已显式定义。
func validEntitlementMode(mode EntitlementMode) bool {
	return mode == EntitlementAllBoundCredentials || mode == EntitlementExplicit
}

// validSwitchPolicy reports whether a profile switch policy is explicitly defined.
// validSwitchPolicy 返回规格切换策略是否已显式定义。
func validSwitchPolicy(policy ProfileSwitchPolicy) bool {
	switch policy {
	case ProfileSwitchSeamless, ProfileSwitchReplayRequired, ProfileSwitchNewSession, ProfileSwitchUnsupported:
		return true
	default:
		return false
	}
}

// validPoolPolicy reports whether a profile pool policy is explicitly defined.
// validPoolPolicy 返回规格账号池策略是否已显式定义。
func validPoolPolicy(policy PoolPolicy) bool {
	return policy == PoolPreferSmallestSufficient || policy == PoolStrictProfile
}

// validAllowanceKind reports whether an allowance kind is explicitly defined.
// validAllowanceKind 返回资源形态是否已显式定义。
func validAllowanceKind(kind AllowanceKind) bool {
	switch kind {
	case AllowanceWindowQuota, AllowanceBalance, AllowanceCreditGrant, AllowanceProviderDefined:
		return true
	default:
		return false
	}
}

// validAllowanceScope reports whether an allowance scope is explicitly defined.
// validAllowanceScope 返回资源作用域是否已显式定义。
func validAllowanceScope(scope AllowanceScope) bool {
	switch scope {
	case ScopeCredential, ScopeSubscription, ScopeOrganization, ScopeProject, ScopeBillingAccount, ScopeProviderModel, ScopeExecutionProfile, ScopeCapability:
		return true
	default:
		return false
	}
}

// validAllowanceStatus reports whether an allowance state is explicitly defined.
// validAllowanceStatus 返回资源状态是否已显式定义。
func validAllowanceStatus(status AllowanceStatus) bool {
	switch status {
	case AllowanceAvailable, AllowanceUnlimited, AllowanceLow, AllowanceExhausted, AllowanceUnknownSufficiency, AllowanceUnavailable, AllowanceNotIncluded:
		return true
	default:
		return false
	}
}

// validAllowanceUnit reports whether an allowance unit is explicitly defined.
// validAllowanceUnit 返回资源计量单位是否已显式定义。
func validAllowanceUnit(unit AllowanceUnit) bool {
	switch unit {
	case UnitTokens, UnitRequests, UnitWeightedTokens, UnitProviderCredits, UnitMinorCurrency, UnitPercentage, UnitProviderDefined:
		return true
	default:
		return false
	}
}

// validateID verifies one portable catalog identifier.
// validateID 校验一个可移植目录标识。
func validateID(field string, value string) error {
	if !catalogIdentifierPattern.MatchString(value) {
		return invalid("%s %q is invalid", field, value)
	}
	return nil
}

// validatePrefixedID verifies one portable catalog identifier with a namespace prefix.
// validatePrefixedID 校验一个带命名空间前缀的可移植目录标识。
func validatePrefixedID(field string, value string, prefix string) error {
	if !strings.HasPrefix(value, prefix) {
		return invalid("%s must start with %s", field, prefix)
	}
	return validateID(field, value)
}

// invalid wraps one provider catalog validation failure.
// invalid 包装一个供应商目录校验失败。
func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidCatalog, fmt.Sprintf(format, args...))
}
