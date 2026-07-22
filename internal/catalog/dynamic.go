package catalog

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// DynamicRefresh contains one complete authoritative discovery outcome.
// DynamicRefresh 包含一次完整权威发现结果。
type DynamicRefresh struct {
	// ProviderInstanceID owns the existing and replacement snapshots.
	// ProviderInstanceID 拥有现有与替换快照。
	ProviderInstanceID string
	// Authority identifies the trusted discovery source.
	// Authority 标识可信发现来源。
	Authority CatalogAuthority
	// SourceRevision is the upstream or signed-manifest revision.
	// SourceRevision 是上游或签名清单修订。
	SourceRevision string
	// ETag is the new opaque conditional validator.
	// ETag 是新的不透明条件校验值。
	ETag string
	// RefreshedAt records this exact attempt.
	// RefreshedAt 记录本次精确尝试时间。
	RefreshedAt time.Time
	// ExpiresAt defines the next freshness boundary after success or not-modified.
	// ExpiresAt 定义成功或未修改后的下一新鲜度边界。
	ExpiresAt time.Time
	// Candidate is the complete replacement after successful discovery.
	// Candidate 是成功发现后的完整替换快照。
	Candidate *Snapshot
	// NotModified confirms the current last-good payload remains authoritative.
	// NotModified 确认当前最后有效载荷仍具权威性。
	NotModified bool
	// FailureCode is a safe explicit failure classification.
	// FailureCode 是安全明确的失败分类。
	FailureCode string
}

// ApplyDynamicRefresh atomically keeps last-good content, records failures, and creates deletion tombstones.
// ApplyDynamicRefresh 原子保留最后有效内容、记录失败并创建删除墓碑。
func ApplyDynamicRefresh(ctx context.Context, store Store, refresh DynamicRefresh) (Snapshot, error) {
	if store == nil || strings.TrimSpace(refresh.ProviderInstanceID) == "" || refresh.RefreshedAt.IsZero() || refresh.Authority == CatalogAuthorityCode {
		return Snapshot{}, fmt.Errorf("%w: dynamic refresh identity, source, and time are required", ErrInvalidCatalog)
	}
	current, errCurrent := store.Get(ctx, refresh.ProviderInstanceID)
	currentExists := errCurrent == nil
	if errCurrent != nil && !errors.Is(errCurrent, ErrSnapshotNotFound) {
		return Snapshot{}, errCurrent
	}
	outcomes := 0
	if refresh.Candidate != nil {
		outcomes++
	}
	if refresh.NotModified {
		outcomes++
	}
	if strings.TrimSpace(refresh.FailureCode) != "" {
		outcomes++
	}
	if outcomes != 1 {
		return Snapshot{}, fmt.Errorf("%w: dynamic refresh requires exactly one outcome", ErrInvalidCatalog)
	}
	if refresh.NotModified || refresh.FailureCode != "" {
		if !currentExists || current.Dynamic == nil {
			return Snapshot{}, fmt.Errorf("%w: dynamic refresh has no last-good snapshot", ErrSnapshotNotFound)
		}
		updated := cloneSnapshot(current)
		updated.Revision++
		updated.Dynamic.RefreshedAt = refresh.RefreshedAt.UTC()
		if refresh.NotModified {
			updated.ObservedAt = refresh.RefreshedAt.UTC()
			updated.Dynamic.Status = CatalogRefreshFresh
			updated.Dynamic.FailureCode = ""
			updated.Dynamic.ExpiresAt = refresh.ExpiresAt.UTC()
			if strings.TrimSpace(refresh.ETag) != "" {
				updated.Dynamic.ETag = strings.TrimSpace(refresh.ETag)
			}
		} else {
			updated.Dynamic.Status = CatalogRefreshStale
			updated.Dynamic.FailureCode = strings.TrimSpace(refresh.FailureCode)
		}
		if errSave := store.Save(ctx, updated); errSave != nil {
			return Snapshot{}, errSave
		}
		return updated, nil
	}
	candidate := cloneSnapshot(*refresh.Candidate)
	if candidate.ProviderInstanceID != refresh.ProviderInstanceID || strings.TrimSpace(refresh.SourceRevision) == "" || !refresh.ExpiresAt.After(refresh.RefreshedAt) {
		return Snapshot{}, fmt.Errorf("%w: successful dynamic refresh metadata is incomplete", ErrInvalidCatalog)
	}
	if currentExists {
		candidate.Revision = current.Revision + 1
	} else {
		candidate.Revision = 1
	}
	candidate.ObservedAt = refresh.RefreshedAt.UTC()
	tombstones := dynamicTombstones(current, candidate, refresh.RefreshedAt.UTC())
	candidate.Dynamic = &DynamicCatalogMetadata{Authority: refresh.Authority, SourceRevision: strings.TrimSpace(refresh.SourceRevision), ETag: strings.TrimSpace(refresh.ETag), RefreshedAt: refresh.RefreshedAt.UTC(), ExpiresAt: refresh.ExpiresAt.UTC(), Status: CatalogRefreshFresh, Tombstones: tombstones}
	if errValidate := candidate.Validate(); errValidate != nil {
		return Snapshot{}, errValidate
	}
	if errSave := store.Save(ctx, candidate); errSave != nil {
		return Snapshot{}, errSave
	}
	return candidate, nil
}

// dynamicTombstones merges prior removals and identifiers removed by the new complete snapshot.
// dynamicTombstones 合并既有删除记录与新完整快照移除的标识。
func dynamicTombstones(previous Snapshot, next Snapshot, removedAt time.Time) []CatalogTombstone {
	tombstones := make([]CatalogTombstone, 0)
	seen := make(map[string]struct{})
	if previous.Dynamic != nil {
		for _, tombstone := range previous.Dynamic.Tombstones {
			key := tombstone.Kind + "\x00" + tombstone.ID
			seen[key] = struct{}{}
			tombstones = append(tombstones, tombstone)
		}
	}
	nextModels := make(map[string]struct{}, len(next.Models))
	for _, model := range next.Models {
		nextModels[model.ID] = struct{}{}
	}
	for _, model := range previous.Models {
		if _, exists := nextModels[model.ID]; !exists {
			tombstones = appendDynamicTombstone(tombstones, seen, CatalogTombstone{Kind: "model", ID: model.ID, RemovedAt: removedAt})
		}
	}
	nextServices := make(map[string]struct{}, len(next.Services))
	for _, service := range next.Services {
		nextServices[service.ID] = struct{}{}
	}
	for _, service := range previous.Services {
		if _, exists := nextServices[service.ID]; !exists {
			tombstones = appendDynamicTombstone(tombstones, seen, CatalogTombstone{Kind: "service", ID: service.ID, RemovedAt: removedAt})
		}
	}
	return tombstones
}

// appendDynamicTombstone appends one unique authoritative deletion.
// appendDynamicTombstone 追加一条唯一权威删除记录。
func appendDynamicTombstone(values []CatalogTombstone, seen map[string]struct{}, value CatalogTombstone) []CatalogTombstone {
	key := value.Kind + "\x00" + value.ID
	if _, exists := seen[key]; exists {
		return values
	}
	seen[key] = struct{}{}
	return append(values, value)
}
