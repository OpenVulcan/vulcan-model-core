package resource

import (
	"errors"
	"strings"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

var (
	// ErrMaterializedInputConflict reports two input identities that require different representations for the same canonical resource role.
	// ErrMaterializedInputConflict 表示两个输入身份为同一规范资源角色要求了不同表示。
	ErrMaterializedInputConflict = errors.New("conflicting materialized input representation")
)

// MaterializedInputReference identifies the projection-visible identity of one resource input.
// MaterializedInputReference 标识一个资源输入在投影阶段可见的身份。
type MaterializedInputReference struct {
	// ResourceID identifies the immutable Router resource.
	// ResourceID 标识不可变的 Router 资源。
	ResourceID string
	// Role identifies the exact operation semantics for that resource occurrence.
	// Role 标识该资源出现位置的精确操作语义。
	Role vcp.MediaInputRole
}

// MaterializedInputIndex resolves projection-visible references without collapsing distinct semantic roles.
// MaterializedInputIndex 在不折叠不同语义角色的情况下解析投影可见引用。
type MaterializedInputIndex map[MaterializedInputReference]MaterializedInput

// IndexMaterializedInputs creates one deterministic projection index and rejects ambiguous duplicate representations.
// IndexMaterializedInputs 创建确定性的投影索引，并拒绝含糊的重复表示。
func IndexMaterializedInputs(inputs []MaterializedInput) (MaterializedInputIndex, error) {
	indexed := make(MaterializedInputIndex, len(inputs))
	for _, input := range inputs {
		if strings.TrimSpace(input.ResourceID) == "" || strings.TrimSpace(string(input.Role)) == "" {
			return nil, ErrMaterializedInputConflict
		}
		reference := MaterializedInputReference{ResourceID: input.ResourceID, Role: input.Role}
		if existing, exists := indexed[reference]; exists {
			if !sameMaterializedRepresentation(existing, input) {
				return nil, ErrMaterializedInputConflict
			}
			continue
		}
		indexed[reference] = input
	}
	return indexed, nil
}

// Find returns the one unambiguous representation for an exact Router resource and semantic role.
// Find 返回精确 Router 资源与语义角色对应的唯一无歧义表示。
func (i MaterializedInputIndex) Find(resourceID string, role vcp.MediaInputRole) (MaterializedInput, bool) {
	input, exists := i[MaterializedInputReference{ResourceID: resourceID, Role: role}]
	return input, exists
}

// sameMaterializedRepresentation compares all provider-visible facts while intentionally excluding per-occurrence InputID.
// sameMaterializedRepresentation 比较所有供应商可见事实，同时有意排除每次出现独有的 InputID。
func sameMaterializedRepresentation(left MaterializedInput, right MaterializedInput) bool {
	if left.ResourceID != right.ResourceID || left.Kind != right.Kind || left.Role != right.Role || left.MIMEType != right.MIMEType || left.SizeBytes != right.SizeBytes || left.Mode != right.Mode || left.InlineBase64 != right.InlineBase64 || left.RemoteURL != right.RemoteURL || left.ProviderHandle != right.ProviderHandle || left.ProviderAssetKind != right.ProviderAssetKind {
		return false
	}
	if left.GeneratedBy == nil || right.GeneratedBy == nil {
		return left.GeneratedBy == nil && right.GeneratedBy == nil
	}
	return *left.GeneratedBy == *right.GeneratedBy
}
