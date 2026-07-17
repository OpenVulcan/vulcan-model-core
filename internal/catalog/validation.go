package catalog

import (
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
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
	profiles := make(map[string]ExecutionProfile, len(s.Profiles))
	profileModels := make(map[string]string, len(s.Profiles))
	defaultProfiles := make(map[string]string)
	for _, profile := range s.Profiles {
		if err := profile.Validate(); err != nil {
			return err
		}
		if profile.ProviderInstanceID != s.ProviderInstanceID {
			return invalid("profile %q crosses provider instances", profile.ID)
		}
		if _, exists := offerings[profile.OfferingID]; !exists {
			return invalid("profile %q references unknown offering %q", profile.ID, profile.OfferingID)
		}
		if _, exists := profiles[profile.ID]; exists {
			return invalid("duplicate profile id %q", profile.ID)
		}
		if profile.Default {
			if existingProfileID, exists := defaultProfiles[profile.OfferingID]; exists {
				return invalid("offering %q has multiple default profiles %q and %q", profile.OfferingID, existingProfileID, profile.ID)
			}
			defaultProfiles[profile.OfferingID] = profile.ID
		}
		profiles[profile.ID] = profile
		profileModels[profile.ID] = offerings[profile.OfferingID].ProviderModelID
	}
	for offeringID := range offerings {
		if _, exists := defaultProfiles[offeringID]; !exists {
			return invalid("offering %q requires exactly one default profile", offeringID)
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
	planIDs := make(map[string]struct{}, len(s.Plans))
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
	return o.Capabilities.Validate()
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
	if err := validatePrefixedID("execution profile offering id", p.OfferingID, "offer_"); err != nil {
		return err
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
	return p.Capabilities.Validate()
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
	if e.ObservedAt.IsZero() || e.ExpiresAt.IsZero() || e.ExpiresAt.Before(e.ObservedAt) {
		return invalid("model entitlement timestamps are invalid")
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
	if p.ObservedAt.IsZero() || p.ExpiresAt.IsZero() || p.ExpiresAt.Before(p.ObservedAt) {
		return invalid("plan snapshot timestamps are invalid")
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
	if a.RemainingRatio != nil && (*a.RemainingRatio < 0 || *a.RemainingRatio > 1) {
		return invalid("allowance remaining ratio must be between zero and one")
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
	if a.ObservedAt.IsZero() || a.ExpiresAt.IsZero() || a.ExpiresAt.Before(a.ObservedAt) {
		return invalid("allowance timestamps are invalid")
	}
	return nil
}

// Validate verifies one quota window definition.
// Validate 校验一个额度窗口定义。
func (w AllowanceWindow) Validate() error {
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
	if p.EntitledCredentials > p.ConfiguredCredentials || p.ReadyCredentials > p.EntitledCredentials || p.Revision == 0 || p.ObservedAt.IsZero() {
		return invalid("pool count relationships, revision, or observed time are invalid")
	}
	for _, allowanceKind := range p.BlockingAllowanceKinds {
		if !validAllowanceKind(allowanceKind) {
			return invalid("pool blocking allowance kind %q is invalid", allowanceKind)
		}
	}
	return nil
}

// validNonNegativeDecimal reports whether one string is an exact non-negative decimal.
// validNonNegativeDecimal 返回字符串是否是精确非负十进制数。
func validNonNegativeDecimal(value string) bool {
	if strings.TrimSpace(value) != value || value == "" {
		return false
	}
	rational, valid := new(big.Rat).SetString(value)
	return valid && rational.Sign() >= 0
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
	case AllowanceAvailable, AllowanceLow, AllowanceExhausted, AllowanceUnknownSufficiency, AllowanceUnavailable:
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
