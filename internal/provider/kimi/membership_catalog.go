package kimi

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
)

// MembershipTier identifies one ordered Kimi Coding Plan membership level.
// MembershipTier 标识一个有序的 Kimi Coding Plan 会员档位。
type MembershipTier int

const (
	// MembershipAndante is the base Kimi Coding Plan membership.
	// MembershipAndante 是基础 Kimi Coding Plan 会员档位。
	MembershipAndante MembershipTier = iota + 1
	// MembershipModerato unlocks Kimi K3 with the 256K profile.
	// MembershipModerato 解锁 Kimi K3 的 256K 规格。
	MembershipModerato
	// MembershipAllegretto unlocks K3 1M and K2.7 HighSpeed.
	// MembershipAllegretto 解锁 K3 1M 与 K2.7 HighSpeed。
	MembershipAllegretto
	// MembershipAllegro is retained independently for future allowance differences.
	// MembershipAllegro 为未来额度差异保留为独立档位。
	MembershipAllegro
)

const (
	// PlanOptionAndante is the immutable system plan option identifier.
	// PlanOptionAndante 是不可变的系统套餐选项标识。
	PlanOptionAndante = "kimi_andante"
	// PlanOptionModerato is the immutable system plan option identifier.
	// PlanOptionModerato 是不可变的系统套餐选项标识。
	PlanOptionModerato = "kimi_moderato"
	// PlanOptionAllegretto is the immutable system plan option identifier.
	// PlanOptionAllegretto 是不可变的系统套餐选项标识。
	PlanOptionAllegretto = "kimi_allegretto"
	// PlanOptionAllegro is the immutable system plan option identifier.
	// PlanOptionAllegro 是不可变的系统套餐选项标识。
	PlanOptionAllegro = "kimi_allegro"
)

const (
	// ProviderMembershipAndante is Kimi's exact account API value for Andante.
	// ProviderMembershipAndante 是 Kimi 账号接口中 Andante 的精确值。
	ProviderMembershipAndante = "LEVEL_TRIAL"
	// ProviderMembershipModerato is Kimi's exact account API value for Moderato.
	// ProviderMembershipModerato 是 Kimi 账号接口中 Moderato 的精确值。
	ProviderMembershipModerato = "LEVEL_BASIC"
	// ProviderMembershipAllegretto is Kimi's exact account API value for Allegretto.
	// ProviderMembershipAllegretto 是 Kimi 账号接口中 Allegretto 的精确值。
	ProviderMembershipAllegretto = "LEVEL_INTERMEDIATE"
	// ProviderMembershipAllegro is Kimi's exact account API value for Allegro.
	// ProviderMembershipAllegro 是 Kimi 账号接口中 Allegro 的精确值。
	ProviderMembershipAllegro = "LEVEL_ADVANCED"
)

const (
	// ModelK27ID is the stable system catalog identifier for Kimi K2.7 Code.
	// ModelK27ID 是 Kimi K2.7 Code 的稳定系统目录标识。
	ModelK27ID = "model_kimi_for_coding"
	// ModelK3ID is the stable system catalog identifier for Kimi K3.
	// ModelK3ID 是 Kimi K3 的稳定系统目录标识。
	ModelK3ID = "model_k3"
	// ModelK27HighSpeedID is the stable system catalog identifier for Kimi K2.7 Code HighSpeed.
	// ModelK27HighSpeedID 是 Kimi K2.7 Code HighSpeed 的稳定系统目录标识。
	ModelK27HighSpeedID = "model_kimi_for_coding_highspeed"
	// ProfileK27ID is the stable OpenAI Chat profile for Kimi K2.7 Code.
	// ProfileK27ID 是 Kimi K2.7 Code 的稳定 OpenAI Chat 规格标识。
	ProfileK27ID = "profile_kimi_for_coding_openai_chat"
	// ProfileK3256KID is the stable Kimi K3 256K OpenAI Chat profile.
	// ProfileK3256KID 是稳定的 Kimi K3 256K OpenAI Chat 规格标识。
	ProfileK3256KID = "profile_k3_256k_openai_chat"
	// ProfileK31MID is the stable Kimi K3 1M OpenAI Chat profile.
	// ProfileK31MID 是稳定的 Kimi K3 1M OpenAI Chat 规格标识。
	ProfileK31MID = "profile_k3_1m_openai_chat"
	// ProfileK27HighSpeedID is the stable OpenAI Chat profile for Kimi K2.7 Code HighSpeed.
	// ProfileK27HighSpeedID 是 Kimi K2.7 Code HighSpeed 的稳定 OpenAI Chat 规格标识。
	ProfileK27HighSpeedID = "profile_kimi_for_coding_highspeed_openai_chat"
)

// ApplyDeclaredMembership adds an operator-declared plan and the exact Kimi model entitlement matrix.
// ApplyDeclaredMembership 添加操作员声明套餐与精确的 Kimi 模型权益矩阵。
func ApplyDeclaredMembership(snapshot catalog.Snapshot, credential providerconfig.Credential) (catalog.Snapshot, error) {
	if credential.DeclaredPlan == nil {
		return catalog.Snapshot{}, errors.New("Kimi declared membership is required")
	}
	tier, _, errTier := membershipFromPlanOption(credential.DeclaredPlan.PlanOptionID)
	if errTier != nil {
		return catalog.Snapshot{}, errTier
	}
	if credential.ProviderInstanceID != snapshot.ProviderInstanceID {
		return catalog.Snapshot{}, errors.New("Kimi credential and catalog ownership differ")
	}
	plan, entitlements, errMetadata := membershipMetadata(snapshot.ProviderInstanceID, credential.ID, tier, catalog.MetadataEvidenceOperatorDeclared, credential.DeclaredPlan.DeclaredAt, time.Time{}, credential.DeclaredPlan.Revision)
	if errMetadata != nil {
		return catalog.Snapshot{}, errMetadata
	}
	snapshot.Plans = append(snapshot.Plans, plan)
	snapshot.Entitlements = append(snapshot.Entitlements, entitlements...)
	if errValidate := snapshot.Validate(); errValidate != nil {
		return catalog.Snapshot{}, fmt.Errorf("validate Kimi declared membership catalog: %w", errValidate)
	}
	return snapshot, nil
}

// MembershipMetadataFromProvider converts one exact Kimi account API level into current plan and model authorization evidence.
// MembershipMetadataFromProvider 将一个精确的 Kimi 账号接口等级转换为当前套餐与模型授权证据。
func MembershipMetadataFromProvider(instanceID string, credentialID string, providerLevel string, observedAt time.Time) (catalog.PlanSnapshot, []catalog.ModelEntitlement, error) {
	tier, errTier := membershipFromProviderLevel(providerLevel)
	if errTier != nil {
		return catalog.PlanSnapshot{}, nil, errTier
	}
	return membershipMetadata(instanceID, credentialID, tier, catalog.MetadataEvidenceProviderAPI, observedAt, observedAt.Add(5*time.Minute), 1)
}

// membershipFromProviderLevel maps only Kimi's confirmed account API values to code-owned tiers.
// membershipFromProviderLevel 仅将 Kimi 已确认的账号接口值映射到代码拥有的档位。
func membershipFromProviderLevel(providerLevel string) (MembershipTier, error) {
	switch strings.TrimSpace(providerLevel) {
	case ProviderMembershipAndante:
		return MembershipAndante, nil
	case ProviderMembershipModerato:
		return MembershipModerato, nil
	case ProviderMembershipAllegretto:
		return MembershipAllegretto, nil
	case ProviderMembershipAllegro:
		return MembershipAllegro, nil
	default:
		return 0, fmt.Errorf("unknown Kimi provider membership level %q", providerLevel)
	}
}

// membershipMetadata builds the complete code-owned Kimi plan and authorization matrix for one evidence observation.
// membershipMetadata 为一次证据观测构建完整的代码拥有 Kimi 套餐与授权矩阵。
func membershipMetadata(instanceID string, credentialID string, tier MembershipTier, evidence catalog.MetadataEvidenceSource, observedAt time.Time, expiresAt time.Time, revision uint64) (catalog.PlanSnapshot, []catalog.ModelEntitlement, error) {
	planCode, planName, errPlan := membershipPlan(tier)
	if errPlan != nil {
		return catalog.PlanSnapshot{}, nil, errPlan
	}
	plan := catalog.PlanSnapshot{ID: "plan_" + strings.TrimPrefix(credentialID, "cred_"), ProviderInstanceID: instanceID, CredentialID: credentialID, PlanCode: planCode, PlanName: planName, Status: "active", EvidenceSource: evidence, ObservedAt: observedAt, ExpiresAt: expiresAt, Revision: revision}
	// records freezes Kimi's confirmed tier matrix; every model receives explicit allow or deny evidence.
	// records 固化 Kimi 已确认的档位矩阵；每个模型都会获得显式允许或拒绝证据。
	records := []struct {
		// modelID identifies the exact Kimi model receiving entitlement evidence.
		// modelID 标识接收权益证据的精确 Kimi 模型。
		modelID string
		// availability is the explicit tier-derived authorization state.
		// availability 是从档位显式派生的授权状态。
		availability catalog.AvailabilityStatus
		// profiles lists the exact execution profiles authorized by the tier.
		// profiles 列出该档位授权的精确执行规格。
		profiles []string
	}{
		{modelID: ModelK27ID, availability: catalog.AvailabilityAllowed, profiles: []string{ProfileK27ID}},
		{modelID: ModelK3ID, availability: availabilityFor(tier >= MembershipModerato), profiles: k3ProfilesForTier(tier)},
		{modelID: ModelK27HighSpeedID, availability: availabilityFor(tier >= MembershipAllegretto), profiles: profilesWhen(tier >= MembershipAllegretto, ProfileK27HighSpeedID)},
	}
	entitlements := make([]catalog.ModelEntitlement, 0, len(records))
	for _, record := range records {
		entitlement := catalog.ModelEntitlement{ID: "ent_" + strings.TrimPrefix(credentialID, "cred_") + "_" + strings.TrimPrefix(record.modelID, "model_"), ProviderInstanceID: instanceID, CredentialID: credentialID, ProviderModelID: record.modelID, Availability: record.availability, EntitlementClass: strings.TrimPrefix(planCode, "kimi_"), AllowedProfileIDs: record.profiles, Source: catalog.ModelSourceSystem, EvidenceSource: evidence, ObservedAt: observedAt, ExpiresAt: expiresAt, Revision: revision}
		if errValidate := entitlement.Validate(); errValidate != nil {
			return catalog.PlanSnapshot{}, nil, fmt.Errorf("validate Kimi model entitlement: %w", errValidate)
		}
		entitlements = append(entitlements, entitlement)
	}
	if errValidate := plan.Validate(); errValidate != nil {
		return catalog.PlanSnapshot{}, nil, fmt.Errorf("validate Kimi plan snapshot: %w", errValidate)
	}
	return plan, entitlements, nil
}

// membershipPlan returns the code-owned plan identifier and display name for one tier.
// membershipPlan 返回一个档位对应的代码拥有套餐标识和显示名称。
func membershipPlan(tier MembershipTier) (string, string, error) {
	switch tier {
	case MembershipAndante:
		return PlanOptionAndante, "Andante", nil
	case MembershipModerato:
		return PlanOptionModerato, "Moderato", nil
	case MembershipAllegretto:
		return PlanOptionAllegretto, "Allegretto", nil
	case MembershipAllegro:
		return PlanOptionAllegro, "Allegro", nil
	default:
		return "", "", fmt.Errorf("unknown Kimi membership tier %d", tier)
	}
}

// availabilityFor converts one confirmed access rule into explicit catalog evidence.
// availabilityFor 将一条已确认访问规则转换为显式目录证据。
func availabilityFor(allowed bool) catalog.AvailabilityStatus {
	if allowed {
		return catalog.AvailabilityAllowed
	}
	return catalog.AvailabilityDenied
}

// profilesWhen returns an isolated profile list only when the confirmed access rule allows it.
// profilesWhen 仅在已确认访问规则允许时返回隔离的规格列表。
func profilesWhen(allowed bool, profiles ...string) []string {
	if !allowed {
		return nil
	}
	return append([]string(nil), profiles...)
}

// k3ProfilesForTier returns the exact K3 context profiles unlocked by one membership tier.
// k3ProfilesForTier 返回一个会员档位精确解锁的 K3 上下文规格。
func k3ProfilesForTier(tier MembershipTier) []string {
	if tier < MembershipModerato {
		return nil
	}
	if tier >= MembershipAllegretto {
		return []string{ProfileK3256KID, ProfileK31MID}
	}
	return []string{ProfileK3256KID}
}

// membershipFromPlanOption maps only exact code-owned identifiers to ordered membership levels.
// membershipFromPlanOption 仅将精确的代码拥有标识映射到有序会员档位。
func membershipFromPlanOption(planOptionID string) (MembershipTier, string, error) {
	for _, tier := range []MembershipTier{MembershipAndante, MembershipModerato, MembershipAllegretto, MembershipAllegro} {
		code, name, errPlan := membershipPlan(tier)
		if errPlan == nil && planOptionID == code {
			return tier, name, nil
		}
	}
	return 0, "", fmt.Errorf("unknown Kimi membership plan option %q", planOptionID)
}
