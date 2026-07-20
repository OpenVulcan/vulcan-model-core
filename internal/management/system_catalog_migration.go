package management

import (
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/OpenVulcan/vulcan-model-core/internal/bootstrap"
	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/dependency"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

const (
	// legacyKimiChatChannelID is the exact Chat channel persisted by the pre-profile Kimi catalog implementation.
	// legacyKimiChatChannelID 是旧版 Kimi 目录实现在引入 Profile 前持久化的精确 Chat 通道标识。
	legacyKimiChatChannelID = "chat"
)

// ReconcileKimiSystemCatalogs migrates persisted Kimi catalogs to the current single Chat protocol contract and returns the changed instance count.
// ReconcileKimiSystemCatalogs 将持久化的 Kimi 目录迁移到当前唯一 Chat 协议合同，并返回发生变更的实例数量。
func ReconcileKimiSystemCatalogs(ctx context.Context, configurations providerconfig.Store, catalogs catalog.Store) (int, error) {
	if ctx == nil {
		return 0, errors.New("context is required")
	}
	if dependency.IsNil(configurations) || dependency.IsNil(catalogs) {
		return 0, errors.New("provider configuration and catalog stores are required")
	}
	instances, errInstances := configurations.ListInstances(ctx, "")
	if errInstances != nil {
		return 0, fmt.Errorf("list provider instances for Kimi catalog reconciliation: %w", errInstances)
	}
	changedInstances := 0
	for _, instance := range instances {
		if !isKimiSystemDefinition(instance.DefinitionID) {
			continue
		}
		definition, errDefinition := configurations.GetDefinition(ctx, instance.DefinitionID)
		if errDefinition != nil {
			return changedInstances, fmt.Errorf("get Kimi definition %s: %w", instance.DefinitionID, errDefinition)
		}
		action, errAction := definitionActionForOperation(definition, vcp.OperationConversationRespond)
		if errAction != nil {
			return changedInstances, fmt.Errorf("resolve Kimi Chat action %s: %w", instance.DefinitionID, errAction)
		}
		current, errCatalog := catalogs.Get(ctx, instance.ID)
		if errors.Is(errCatalog, catalog.ErrSnapshotNotFound) {
			continue
		}
		if errCatalog != nil {
			return changedInstances, fmt.Errorf("get Kimi catalog %s: %w", instance.ID, errCatalog)
		}
		migrated, changed, errMigrate := migrateKimiCatalogToChat(current, action)
		if errMigrate != nil {
			return changedInstances, fmt.Errorf("migrate Kimi catalog %s: %w", instance.ID, errMigrate)
		}
		if !changed {
			continue
		}
		if errSave := catalogs.Save(ctx, migrated); errSave != nil {
			return changedInstances, fmt.Errorf("save migrated Kimi catalog %s: %w", instance.ID, errSave)
		}
		changedInstances++
	}
	return changedInstances, nil
}

// isKimiSystemDefinition reports whether one immutable definition belongs to the three built-in Kimi products.
// isKimiSystemDefinition 判断一个不可变定义是否属于三个内置 Kimi 产品之一。
func isKimiSystemDefinition(definitionID string) bool {
	switch definitionID {
	case bootstrap.KimiCNDefinitionID, bootstrap.KimiGlobalDefinitionID, bootstrap.KimiCodingDefinitionID:
		return true
	default:
		return false
	}
}

// migrateKimiCatalogToChat removes non-Chat products while preserving account metadata that still references the retained Chat profiles.
// migrateKimiCatalogToChat 删除非 Chat 产品，同时保留仍引用保留 Chat Profile 的账号元数据。
func migrateKimiCatalogToChat(current catalog.Snapshot, action providerconfig.ProviderActionBinding) (catalog.Snapshot, bool, error) {
	if action.Operation != vcp.OperationConversationRespond || action.ProtocolProfileID == "" {
		return catalog.Snapshot{}, false, errors.New("Kimi migration requires one concrete Chat conversation action")
	}
	retainedModelIDs := make(map[string]struct{})
	staleOfferingIDs := make(map[string]struct{})
	for _, offering := range current.Offerings {
		if offering.ChannelID == action.ProtocolProfileID || offering.ChannelID == legacyKimiChatChannelID {
			retainedModelIDs[offering.ProviderModelID] = struct{}{}
			continue
		}
		staleOfferingIDs[offering.ID] = struct{}{}
	}
	for _, offering := range current.Offerings {
		if _, stale := staleOfferingIDs[offering.ID]; !stale {
			continue
		}
		if _, retained := retainedModelIDs[offering.ProviderModelID]; !retained {
			return catalog.Snapshot{}, false, fmt.Errorf("model %s has no retained Chat offering", offering.ProviderModelID)
		}
	}
	migrated := current
	migrated.Offerings = make([]catalog.ModelOffering, 0, len(current.Offerings)-len(staleOfferingIDs))
	changed := len(staleOfferingIDs) > 0
	expectedDelivery := catalog.DeliveryCapabilities{Synchronous: action.Delivery.Synchronous, Streaming: action.Delivery.Streaming, Asynchronous: action.Delivery.Asynchronous}
	for _, offering := range current.Offerings {
		if _, stale := staleOfferingIDs[offering.ID]; stale {
			continue
		}
		offeringChanged := false
		if offering.ChannelID == legacyKimiChatChannelID {
			offering.ChannelID = action.ProtocolProfileID
			offeringChanged = true
		}
		if offering.Capabilities.Delivery != expectedDelivery {
			offering.Capabilities.Delivery = expectedDelivery
			offering.CapabilityRevision = incrementCatalogRevision(offering.CapabilityRevision)
			offeringChanged = true
		}
		if offeringChanged {
			offering.Revision = incrementCatalogRevision(offering.Revision)
			changed = true
		}
		migrated.Offerings = append(migrated.Offerings, offering)
	}
	retainedProfileIDs := make(map[string]struct{})
	staleProfileIDs := make(map[string]struct{})
	migrated.Profiles = make([]catalog.ExecutionProfile, 0, len(current.Profiles))
	for _, profile := range current.Profiles {
		if _, stale := staleOfferingIDs[profile.OfferingID]; stale {
			staleProfileIDs[profile.ID] = struct{}{}
			changed = true
			continue
		}
		if profile.OfferingID != "" {
			retainedProfileIDs[profile.ID] = struct{}{}
			profileChanged := false
			if profile.Operation != action.Operation || profile.ActionBindingID != action.ID {
				profile.Operation = action.Operation
				profile.ActionBindingID = action.ID
				profileChanged = true
			}
			if profile.Capabilities.Delivery != expectedDelivery {
				profile.Capabilities.Delivery = expectedDelivery
				profile.CapabilityRevision = incrementCatalogRevision(profile.CapabilityRevision)
				profileChanged = true
			}
			if profileChanged {
				profile.Revision = incrementCatalogRevision(profile.Revision)
				changed = true
			}
		}
		migrated.Profiles = append(migrated.Profiles, profile)
	}
	migrated.Entitlements = make([]catalog.ModelEntitlement, 0, len(current.Entitlements))
	for _, entitlement := range current.Entitlements {
		if len(entitlement.AllowedProfileIDs) == 0 {
			migrated.Entitlements = append(migrated.Entitlements, entitlement)
			continue
		}
		allowedProfileIDs := make([]string, 0, len(entitlement.AllowedProfileIDs))
		for _, profileID := range entitlement.AllowedProfileIDs {
			if _, retained := retainedProfileIDs[profileID]; retained {
				allowedProfileIDs = append(allowedProfileIDs, profileID)
			}
		}
		if len(allowedProfileIDs) == 0 {
			changed = true
			continue
		}
		if len(allowedProfileIDs) != len(entitlement.AllowedProfileIDs) {
			entitlement.AllowedProfileIDs = allowedProfileIDs
			entitlement.Revision = incrementCatalogRevision(entitlement.Revision)
			changed = true
		}
		migrated.Entitlements = append(migrated.Entitlements, entitlement)
	}
	migrated.Allowances = make([]catalog.AllowanceSnapshot, 0, len(current.Allowances))
	for _, allowance := range current.Allowances {
		if allowance.Scope == catalog.ScopeExecutionProfile {
			if _, stale := staleProfileIDs[allowance.ScopeID]; stale {
				changed = true
				continue
			}
		}
		migrated.Allowances = append(migrated.Allowances, allowance)
	}
	migrated.Pools = make([]catalog.PoolSummary, 0, len(current.Pools))
	for _, pool := range current.Pools {
		if _, stale := staleProfileIDs[pool.ExecutionProfileID]; stale {
			changed = true
			continue
		}
		migrated.Pools = append(migrated.Pools, pool)
	}
	if !changed {
		return current, false, nil
	}
	if current.Revision == math.MaxUint64 {
		return catalog.Snapshot{}, false, errors.New("Kimi catalog revision is exhausted")
	}
	migrated.Revision = current.Revision + 1
	if errValidate := migrated.Validate(); errValidate != nil {
		return catalog.Snapshot{}, false, errValidate
	}
	return migrated, true, nil
}

// incrementCatalogRevision advances a record revision while leaving exhaustion to snapshot validation as an explicit invalid state.
// incrementCatalogRevision 推进记录修订号，并将耗尽状态作为显式无效状态交由快照校验处理。
func incrementCatalogRevision(revision uint64) uint64 {
	if revision == math.MaxUint64 {
		return 0
	}
	return revision + 1
}
