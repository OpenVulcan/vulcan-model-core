package management

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/bootstrap"
	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/dependency"
	providerkimi "github.com/OpenVulcan/vulcan-model-core/internal/provider/kimi"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/routingstate"
)

// RoutingService manages persisted scheduling policy, credential priority, and manual commercial plans.
// RoutingService 管理持久化调度策略、凭据优先级与人工商业套餐。
type RoutingService struct {
	// configurations owns provider instances and credentials.
	// configurations 拥有供应商实例与凭据。
	configurations providerconfig.Store
	// catalogs owns atomic model and entitlement snapshots.
	// catalogs 拥有原子模型与权益快照。
	catalogs catalog.Store
	// states owns Router-wide scheduling defaults.
	// states 拥有 Router 全局调度默认值。
	states routingstate.Store
	// resolver rebuilds client-safe pool aggregates after plan changes.
	// resolver 在套餐变更后重建客户端安全账号池聚合。
	resolver *resolve.Resolver
	// now returns authoritative mutation timestamps.
	// now 返回权威变更时间戳。
	now func() time.Time
	// atomicPlanMutations commits credential and catalog revisions together when the durable store supports it.
	// atomicPlanMutations 在持久存储支持时共同提交凭据与目录修订。
	atomicPlanMutations credentialPlanMutationStore
}

// credentialPlanMutationStore atomically persists one manual-plan configuration and its derived catalog.
// credentialPlanMutationStore 原子持久化一次人工套餐配置及其派生目录。
type credentialPlanMutationStore interface {
	// SaveCredentialAndCatalog commits both revisions or neither revision.
	// SaveCredentialAndCatalog 同时提交两个修订，或两个都不提交。
	SaveCredentialAndCatalog(context.Context, providerconfig.Credential, catalog.Snapshot) error
}

// NewRoutingService creates one management boundary for routing and entitlement configuration.
// NewRoutingService 创建一个路由与权益配置管理边界。
func NewRoutingService(configurations providerconfig.Store, catalogs catalog.Store, states routingstate.Store) (*RoutingService, error) {
	if dependency.IsNil(configurations) || dependency.IsNil(catalogs) || dependency.IsNil(states) {
		return nil, errors.New("provider configuration, catalog, and routing state stores are required")
	}
	resolver, errResolver := resolve.NewWithRuntimeState(configurations, catalogs, states)
	if errResolver != nil {
		return nil, errResolver
	}
	atomicPlanMutations, _ := configurations.(credentialPlanMutationStore)
	return &RoutingService{configurations: configurations, catalogs: catalogs, states: states, resolver: resolver, now: time.Now, atomicPlanMutations: atomicPlanMutations}, nil
}

// GetSettings returns Router-wide scheduling settings.
// GetSettings 返回 Router 全局调度设置。
func (s *RoutingService) GetSettings(ctx context.Context) (routingstate.Settings, error) {
	return s.states.GetSettings(ctx)
}

// SetDefaultRoutingStrategy changes the inherited scheduling strategy through a revisioned write.
// SetDefaultRoutingStrategy 通过带修订号写入修改继承的调度策略。
func (s *RoutingService) SetDefaultRoutingStrategy(ctx context.Context, strategy providerconfig.RoutingStrategy) (routingstate.Settings, error) {
	current, errCurrent := s.states.GetSettings(ctx)
	if errCurrent != nil {
		return routingstate.Settings{}, errCurrent
	}
	updated := routingstate.Settings{DefaultRoutingStrategy: strategy, Revision: current.Revision + 1, UpdatedAt: s.now().UTC()}
	if errSave := s.states.SaveSettings(ctx, updated); errSave != nil {
		return routingstate.Settings{}, errSave
	}
	return updated, nil
}

// SetInstanceRoutingStrategy sets or clears one provider-instance override.
// SetInstanceRoutingStrategy 设置或清除一个供应商实例覆盖策略。
func (s *RoutingService) SetInstanceRoutingStrategy(ctx context.Context, instanceID string, strategy providerconfig.RoutingStrategy) (providerconfig.ProviderInstance, error) {
	if strategy != "" && strategy != providerconfig.RoutingRoundRobin && strategy != providerconfig.RoutingFillFirst {
		return providerconfig.ProviderInstance{}, errors.New("provider routing strategy is invalid")
	}
	instance, errInstance := s.configurations.GetInstance(ctx, instanceID)
	if errInstance != nil {
		return providerconfig.ProviderInstance{}, errInstance
	}
	instance.RoutingStrategy = strategy
	instance.UpdatedAt = s.now().UTC()
	instance.Revision++
	if errSave := s.configurations.SaveInstance(ctx, instance); errSave != nil {
		return providerconfig.ProviderInstance{}, errSave
	}
	return instance, nil
}

// SetCredentialPriority updates account ordering independently from endpoint binding priority.
// SetCredentialPriority 独立于入口 Binding 优先级更新账号顺序。
func (s *RoutingService) SetCredentialPriority(ctx context.Context, instanceID string, credentialID string, priority int) (providerconfig.Credential, error) {
	if priority < 0 {
		return providerconfig.Credential{}, errors.New("credential priority cannot be negative")
	}
	credential, errCredential := findOwnedCredential(ctx, s.configurations, instanceID, credentialID)
	if errCredential != nil {
		return providerconfig.Credential{}, errCredential
	}
	credential.Priority = priority
	credential.Revision++
	if errSave := s.configurations.SaveCredential(ctx, credential); errSave != nil {
		return providerconfig.Credential{}, errSave
	}
	return credential, nil
}

// SetCredentialPlan replaces one manual code-owned plan and rebuilds exact account entitlements.
// SetCredentialPlan 替换一个人工代码拥有套餐并重建精确账号权益。
func (s *RoutingService) SetCredentialPlan(ctx context.Context, instanceID string, credentialID string, planOptionID string) (providerconfig.Credential, error) {
	instance, errInstance := s.configurations.GetInstance(ctx, instanceID)
	if errInstance != nil {
		return providerconfig.Credential{}, errInstance
	}
	definition, errDefinition := s.configurations.GetDefinition(ctx, instance.DefinitionID)
	if errDefinition != nil {
		return providerconfig.Credential{}, errDefinition
	}
	credential, errCredential := findOwnedCredential(ctx, s.configurations, instanceID, credentialID)
	if errCredential != nil {
		return providerconfig.Credential{}, errCredential
	}
	authMethod, authMethodExists := definition.AuthMethod(credential.AuthMethodID)
	planOption, planOptionExists := definition.PlanOption(planOptionID)
	manualPlan := authMethodExists && (authMethod.PlanAcquisition == providerconfig.PlanAcquisitionManualRequired || authMethod.PlanAcquisition == providerconfig.PlanAcquisitionManualOptional)
	if !manualPlan || !planOptionExists || !planOption.ManuallySelectable || !definition.AuthMethodAllowsPlan(authMethod.ID, planOptionID) {
		return providerconfig.Credential{}, errors.New("credential plan option is not valid for its authentication method")
	}
	if definition.ID != bootstrap.KimiCodingDefinitionID {
		return providerconfig.Credential{}, errors.New("manual entitlement synthesis is not registered for this provider")
	}
	currentSnapshot, errSnapshot := s.catalogs.Get(ctx, instanceID)
	if errSnapshot != nil {
		return providerconfig.Credential{}, errSnapshot
	}
	previousCredential := credential
	declarationRevision := uint64(1)
	if credential.DeclaredPlan != nil {
		declarationRevision = credential.DeclaredPlan.Revision + 1
	}
	mutationTime := s.now().UTC()
	credential.DeclaredPlan = &providerconfig.DeclaredPlanSelection{PlanOptionID: planOptionID, DeclaredAt: mutationTime, Revision: declarationRevision}
	credential.Revision++
	updatedSnapshot := removeCredentialCommercialMetadata(currentSnapshot, credentialID)
	updatedSnapshot.Revision++
	updatedSnapshot.ObservedAt = mutationTime
	updatedSnapshot.Pools = nil
	updatedSnapshot, errApply := providerkimi.ApplyDeclaredMembership(updatedSnapshot, credential)
	if errApply != nil {
		return providerconfig.Credential{}, errApply
	}
	pools, errPools := s.resolver.SummarizeSnapshot(ctx, updatedSnapshot, mutationTime, updatedSnapshot.Revision)
	if errPools != nil {
		return providerconfig.Credential{}, errPools
	}
	updatedSnapshot.Pools = pools
	if s.atomicPlanMutations != nil {
		if errAtomicSave := s.atomicPlanMutations.SaveCredentialAndCatalog(ctx, credential, updatedSnapshot); errAtomicSave != nil {
			return providerconfig.Credential{}, errAtomicSave
		}
		return credential, nil
	}
	if errSaveCredential := s.configurations.SaveCredential(ctx, credential); errSaveCredential != nil {
		return providerconfig.Credential{}, errSaveCredential
	}
	if errSaveCatalog := s.catalogs.Save(ctx, updatedSnapshot); errSaveCatalog != nil {
		previousCredential.Revision = credential.Revision + 1
		if errCompensate := s.configurations.SaveCredential(context.WithoutCancel(ctx), previousCredential); errCompensate != nil {
			return providerconfig.Credential{}, fmt.Errorf("save credential plan catalog: %v; compensate credential: %w", errSaveCatalog, errCompensate)
		}
		return providerconfig.Credential{}, errSaveCatalog
	}
	return credential, nil
}

// findOwnedCredential returns one exact credential without accepting cross-instance identifiers.
// findOwnedCredential 返回一个精确凭据且不接受跨实例标识。
func findOwnedCredential(ctx context.Context, configurations providerconfig.Store, instanceID string, credentialID string) (providerconfig.Credential, error) {
	credentials, errCredentials := configurations.ListCredentials(ctx, instanceID)
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

// removeCredentialCommercialMetadata removes only one account's replaceable plan and model entitlement records.
// removeCredentialCommercialMetadata 仅删除一个账号可替换的套餐与模型权益记录。
func removeCredentialCommercialMetadata(snapshot catalog.Snapshot, credentialID string) catalog.Snapshot {
	plans := make([]catalog.PlanSnapshot, 0, len(snapshot.Plans))
	for _, plan := range snapshot.Plans {
		if plan.CredentialID != credentialID {
			plans = append(plans, plan)
		}
	}
	entitlements := make([]catalog.ModelEntitlement, 0, len(snapshot.Entitlements))
	for _, entitlement := range snapshot.Entitlements {
		if entitlement.CredentialID != credentialID {
			entitlements = append(entitlements, entitlement)
		}
	}
	snapshot.Plans = plans
	snapshot.Entitlements = entitlements
	return snapshot
}
