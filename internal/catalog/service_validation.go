package catalog

import (
	"strings"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// Validate verifies one provider-scoped logical special service.
// Validate 校验一个供应商作用域逻辑特殊服务。
func (s ProviderService) Validate() error {
	if errID := validatePrefixedID("provider service id", s.ID, "service_"); errID != nil {
		return errID
	}
	if errInstance := validatePrefixedID("provider service instance id", s.ProviderInstanceID, "pvi_"); errInstance != nil {
		return errInstance
	}
	if strings.TrimSpace(s.DisplayName) == "" || s.Operation != vcp.OperationSearchWeb {
		return invalid("provider service display name and supported operation are required")
	}
	if !validModelSource(s.Source) || !validEntitlementMode(s.EntitlementMode) || s.Revision == 0 {
		return invalid("provider service source, entitlement mode, or revision is invalid")
	}
	return nil
}

// Validate verifies one channel-specific special-service offering.
// Validate 校验一个通道特定特殊服务产品。
func (o ServiceOffering) Validate(operation vcp.OperationKind) error {
	if errID := validatePrefixedID("service offering id", o.ID, "service_offer_"); errID != nil {
		return errID
	}
	if errInstance := validatePrefixedID("service offering instance id", o.ProviderInstanceID, "pvi_"); errInstance != nil {
		return errInstance
	}
	if errService := validatePrefixedID("service offering service id", o.ProviderServiceID, "service_"); errService != nil {
		return errService
	}
	if errChannel := validateID("service offering channel id", o.ChannelID); errChannel != nil {
		return errChannel
	}
	if strings.TrimSpace(o.UpstreamServiceID) == "" || o.CapabilityRevision == 0 || o.Revision == 0 {
		return invalid("service offering upstream id and revisions are required")
	}
	return o.Capabilities.Validate(operation)
}

// Validate verifies one closed special-service capability variant.
// Validate 校验一个封闭特殊服务能力变体。
func (c ServiceCapabilities) Validate(operation vcp.OperationKind) error {
	if operation != vcp.OperationSearchWeb || c.WebSearch == nil {
		return invalid("service capabilities must match search.web")
	}
	return c.WebSearch.Validate()
}

// Validate verifies one exact unified web-search capability profile.
// Validate 校验一个精确统一网页搜索能力规格。
func (c WebSearchCapabilities) Validate() error {
	if c.BackendKind != vcp.SearchBackendDirectAPI && c.BackendKind != vcp.SearchBackendGroundedModel {
		return invalid("web search backend kind %q is invalid", c.BackendKind)
	}
	if !validSearchInvocationMode(c.InvocationMode) {
		return invalid("web search invocation mode %q is invalid", c.InvocationMode)
	}
	if c.BackendKind == vcp.SearchBackendDirectAPI {
		if c.InvocationMode != SearchInvocationDirectRequest || c.BackingModelOfferingID != "" || c.PromptTemplateID != "" || c.PromptTemplateRevision != 0 {
			return invalid("direct search API cannot carry model or prompt binding")
		}
	} else {
		if errModel := validatePrefixedID("web search backing model offering id", c.BackingModelOfferingID, "offer_"); errModel != nil {
			return errModel
		}
		if c.InvocationMode == SearchInvocationDirectRequest {
			return invalid("model-grounded search cannot use direct invocation")
		}
		promptRequired := c.InvocationMode == SearchInvocationPrompt || c.InvocationMode == SearchInvocationNativeToolAndPrompt
		if promptRequired && (strings.TrimSpace(c.PromptTemplateID) == "" || c.PromptTemplateRevision == 0) {
			return invalid("prompt-backed search requires prompt template id and revision")
		}
		if !promptRequired && (c.PromptTemplateID != "" || c.PromptTemplateRevision != 0) {
			return invalid("search prompt metadata requires a prompt-backed invocation mode")
		}
	}
	if c.MaxResults.Known && c.MaxResults.Value <= 0 {
		return invalid("known web search max results must be positive")
	}
	if !c.MaxResults.Known && c.MaxResults.Value != 0 {
		return invalid("unknown web search max results cannot carry a value")
	}
	if errOutputs := validateSearchOutputModes(c.OutputModes); errOutputs != nil {
		return errOutputs
	}
	if errEvidence := validateSearchEvidence(c.EvidenceKinds, c.EvidenceRequirements); errEvidence != nil {
		return errEvidence
	}
	levels := []CapabilityLevel{c.Filters.DomainAllow, c.Filters.DomainBlock, c.Filters.PublicationTime, c.Filters.Language, c.Filters.Region, c.Filters.Location, c.Filters.SafeSearch}
	for _, level := range levels {
		if !validCapabilityLevel(level) {
			return invalid("web search filter capability level %q is invalid", level)
		}
	}
	return nil
}

// Validate verifies one credential-specific special-service entitlement.
// Validate 校验一个凭据特定特殊服务授权。
func (e ServiceEntitlement) Validate() error {
	if errID := validatePrefixedID("service entitlement id", e.ID, "service_ent_"); errID != nil {
		return errID
	}
	if errInstance := validatePrefixedID("service entitlement instance id", e.ProviderInstanceID, "pvi_"); errInstance != nil {
		return errInstance
	}
	if errCredential := validatePrefixedID("service entitlement credential id", e.CredentialID, "cred_"); errCredential != nil {
		return errCredential
	}
	if errService := validatePrefixedID("service entitlement service id", e.ProviderServiceID, "service_"); errService != nil {
		return errService
	}
	if !validAvailability(e.Availability) || !validModelSource(e.Source) || e.Revision == 0 {
		return invalid("service entitlement availability, source, or revision is invalid")
	}
	for _, profileID := range e.AllowedProfileIDs {
		if errProfile := validatePrefixedID("service entitlement profile id", profileID, "profile_"); errProfile != nil {
			return errProfile
		}
	}
	if e.ObservedAt.IsZero() || e.ExpiresAt.IsZero() || e.ExpiresAt.Before(e.ObservedAt) {
		return invalid("service entitlement timestamps are invalid")
	}
	return nil
}

// validSearchInvocationMode reports whether one invocation mode is registered.
// validSearchInvocationMode 报告一个触发方式是否已注册。
func validSearchInvocationMode(mode SearchInvocationMode) bool {
	switch mode {
	case SearchInvocationDirectRequest, SearchInvocationAlwaysOn, SearchInvocationNativeTool, SearchInvocationPrompt, SearchInvocationNativeToolAndPrompt:
		return true
	default:
		return false
	}
}

// validateSearchOutputModes verifies non-empty stable unique response shapes.
// validateSearchOutputModes 校验非空稳定唯一响应形态。
func validateSearchOutputModes(modes []vcp.WebSearchOutputMode) error {
	if len(modes) == 0 {
		return invalid("web search output modes are required")
	}
	seen := make(map[vcp.WebSearchOutputMode]struct{}, len(modes))
	for _, mode := range modes {
		if mode != vcp.WebSearchOutputResults && mode != vcp.WebSearchOutputAnswerWithCitations && mode != vcp.WebSearchOutputResultsAndAnswer {
			return invalid("web search output mode %q is invalid", mode)
		}
		if _, exists := seen[mode]; exists {
			return invalid("duplicate web search output mode %q", mode)
		}
		seen[mode] = struct{}{}
	}
	return nil
}

// validateSearchEvidence verifies evidence kinds and accepted verification requirements.
// validateSearchEvidence 校验证据类型和接受的验证要求。
func validateSearchEvidence(kinds []vcp.SearchEvidenceKind, requirements []vcp.SearchEvidenceRequirement) error {
	if len(kinds) == 0 || len(requirements) == 0 {
		return invalid("web search evidence kinds and requirements are required")
	}
	observable := false
	kindSet := make(map[vcp.SearchEvidenceKind]struct{}, len(kinds))
	for _, kind := range kinds {
		switch kind {
		case vcp.SearchEvidenceProviderEvent, vcp.SearchEvidenceStructuredResult, vcp.SearchEvidenceCitation:
			observable = true
		case vcp.SearchEvidenceProviderContract:
		default:
			return invalid("web search evidence kind %q is invalid", kind)
		}
		if _, exists := kindSet[kind]; exists {
			return invalid("duplicate web search evidence kind %q", kind)
		}
		kindSet[kind] = struct{}{}
	}
	requirementSet := make(map[vcp.SearchEvidenceRequirement]struct{}, len(requirements))
	for _, requirement := range requirements {
		if requirement != vcp.SearchEvidenceBestEffort && requirement != vcp.SearchEvidenceVerified {
			return invalid("web search evidence requirement %q is invalid", requirement)
		}
		if requirement == vcp.SearchEvidenceVerified && !observable {
			return invalid("verified web search requires observable provider evidence")
		}
		if _, exists := requirementSet[requirement]; exists {
			return invalid("duplicate web search evidence requirement %q", requirement)
		}
		requirementSet[requirement] = struct{}{}
	}
	return nil
}
