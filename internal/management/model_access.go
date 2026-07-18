package management

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
)

var (
	// ErrProviderModelNotFound reports a model absent from the selected provider instance catalog.
	// ErrProviderModelNotFound 表示所选供应商实例目录中不存在的模型。
	ErrProviderModelNotFound = errors.New("provider model not found")
)

// ModelAccessService coordinates instance-level model enablement against atomic catalog facts.
// ModelAccessService 根据原子目录事实协调实例级模型启停。
type ModelAccessService struct {
	// configurations persists the instance-level disabled-model policy.
	// configurations 持久化实例级禁用模型策略。
	configurations providerconfig.Store
	// catalogs verifies every policy target exists in the selected instance catalog.
	// catalogs 校验每个策略目标均存在于所选实例目录中。
	catalogs catalog.Store
	// now provides the authoritative timestamp for persisted instance revisions.
	// now 为持久化实例修订提供权威时间戳。
	now func() time.Time
}

// SetModelEnabledInput identifies one exact model and the desired instance-level availability state.
// SetModelEnabledInput 标识一个精确模型及期望的实例级可用性状态。
type SetModelEnabledInput struct {
	// ProviderInstanceID identifies the exact provider instance owning the policy.
	// ProviderInstanceID 标识拥有该策略的精确供应商实例。
	ProviderInstanceID string
	// ProviderModelID identifies the exact provider-scoped catalog model.
	// ProviderModelID 标识精确供应商作用域目录模型。
	ProviderModelID string
	// Enabled controls whether call-plane resolution may select the model.
	// Enabled 控制调用面解析是否可以选择该模型。
	Enabled bool
}

// NewModelAccessService creates one instance model-access application service.
// NewModelAccessService 创建一个实例模型访问应用服务。
func NewModelAccessService(configurations providerconfig.Store, catalogs catalog.Store) (*ModelAccessService, error) {
	if configurations == nil || catalogs == nil {
		return nil, errors.New("provider configuration and catalog stores are required")
	}
	return &ModelAccessService{configurations: configurations, catalogs: catalogs, now: time.Now}, nil
}

// SetModelEnabled updates one explicit model policy only after confirming the catalog owns that model.
// SetModelEnabled 仅在确认目录拥有该模型后更新一个显式模型策略。
func (s *ModelAccessService) SetModelEnabled(ctx context.Context, input SetModelEnabledInput) (providerconfig.ProviderInstance, error) {
	instance, errInstance := s.configurations.GetInstance(ctx, input.ProviderInstanceID)
	if errInstance != nil {
		return providerconfig.ProviderInstance{}, errInstance
	}
	snapshot, errSnapshot := s.catalogs.Get(ctx, input.ProviderInstanceID)
	if errSnapshot != nil {
		return providerconfig.ProviderInstance{}, errSnapshot
	}
	if !catalogContainsModel(snapshot.Models, input.ProviderModelID) {
		return providerconfig.ProviderInstance{}, fmt.Errorf("%w: %s", ErrProviderModelNotFound, input.ProviderModelID)
	}
	// disabledModelIDs is copied because a no-op request must not leak a mutable store slice.
	// disabledModelIDs 被复制，因为无操作请求不得泄露可变存储切片。
	disabledModelIDs := append([]string(nil), instance.DisabledModelIDs...)
	if input.Enabled {
		disabledModelIDs = removeModelID(disabledModelIDs, input.ProviderModelID)
	} else if !containsModelID(disabledModelIDs, input.ProviderModelID) {
		disabledModelIDs = append(disabledModelIDs, input.ProviderModelID)
	}
	sort.Strings(disabledModelIDs)
	if equalModelIDs(instance.DisabledModelIDs, disabledModelIDs) {
		return instance, nil
	}
	instance.DisabledModelIDs = disabledModelIDs
	instance.Revision++
	instance.UpdatedAt = s.now().UTC()
	if errSave := s.configurations.SaveInstance(ctx, instance); errSave != nil {
		return providerconfig.ProviderInstance{}, errSave
	}
	return instance, nil
}

// catalogContainsModel reports whether one atomic catalog contains an exact provider model identifier.
// catalogContainsModel 返回一个原子目录是否包含精确供应商模型标识。
func catalogContainsModel(models []catalog.ProviderModel, modelID string) bool {
	for _, model := range models {
		if model.ID == modelID {
			return true
		}
	}
	return false
}

// containsModelID reports whether one model policy contains an exact identifier.
// containsModelID 返回一个模型策略是否包含精确标识。
func containsModelID(modelIDs []string, modelID string) bool {
	for _, candidate := range modelIDs {
		if candidate == modelID {
			return true
		}
	}
	return false
}

// removeModelID returns a copied policy without one exact model identifier.
// removeModelID 返回一个不含精确模型标识的复制策略。
func removeModelID(modelIDs []string, modelID string) []string {
	// remaining has independent backing storage so callers never mutate the input slice.
	// remaining 拥有独立底层存储，因此调用方绝不修改输入切片。
	remaining := make([]string, 0, len(modelIDs))
	for _, candidate := range modelIDs {
		if candidate != modelID {
			remaining = append(remaining, candidate)
		}
	}
	return remaining
}

// equalModelIDs reports exact ordered policy equality after deterministic sorting.
// equalModelIDs 在确定性排序后报告精确策略相等性。
func equalModelIDs(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
