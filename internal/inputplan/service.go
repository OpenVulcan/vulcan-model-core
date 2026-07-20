package inputplan

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/dependency"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	routerresource "github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TargetResolver resolves one exact immutable provider target.
// TargetResolver 解析一个精确不可变供应商目标。
type TargetResolver interface {
	// Resolve selects one same-provider destination without fallback.
	// Resolve 在不降级的情况下选择一个同供应商目的地。
	Resolve(context.Context, resolve.Request) (resolve.Target, resolve.Diagnostics, error)
}

// ResourceReader returns owner-scoped Router resource facts.
// ResourceReader 返回所有者作用域 Router 资源事实。
type ResourceReader interface {
	// Get returns one owner-authorized resource.
	// Get 返回一个所有者授权资源。
	Get(context.Context, string, string) (routerresource.Resource, error)
}

// ServiceOptions configures deterministic identity, time, and plan lifetime.
// ServiceOptions 配置确定性身份、时间与方案生命周期。
type ServiceOptions struct {
	// TTL limits capability and resource snapshot reuse.
	// TTL 限制能力与资源快照复用时间。
	TTL time.Duration
	// Now returns current time.
	// Now 返回当前时间。
	Now func() time.Time
	// NewID returns one unpredictable plan identifier.
	// NewID 返回一个不可预测方案标识。
	NewID func() (string, error)
}

// Service resolves, validates, freezes, and later revalidates input plans.
// Service 解析、校验、冻结并在之后重新校验输入方案。
type Service struct {
	// resolver owns exact provider target selection.
	// resolver 拥有精确供应商 Target 选择。
	resolver TargetResolver
	// resources supplies authoritative resource facts.
	// resources 提供权威资源事实。
	resources ResourceReader
	// store owns immutable plans.
	// store 拥有不可变方案。
	store Store
	// options contains validated deterministic dependencies.
	// options 包含已校验确定性依赖。
	options ServiceOptions
}

// NewService creates one complete conditional input planner.
// NewService 创建一个完整条件输入规划器。
func NewService(resolver TargetResolver, resources ResourceReader, store Store, options ServiceOptions) (*Service, error) {
	if dependency.IsNil(resolver) || dependency.IsNil(resources) || dependency.IsNil(store) || options.TTL <= 0 {
		return nil, ErrInvalidPlan
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.NewID == nil {
		options.NewID = randomPlanID
	}
	return &Service{resolver: resolver, resources: resources, store: store, options: options}, nil
}

// Create resolves one exact target and freezes a deterministic input path for every item.
// Create 解析一个精确 Target 并为每个项目冻结确定性输入路径。
func (s *Service) Create(ctx context.Context, request Request) (Plan, error) {
	if s == nil || ctx == nil || strings.TrimSpace(request.OwnerAPIKeyID) == "" || request.Model.Target != vcp.ModelTargetExact || request.Model.ProviderInstanceID == "" || request.Model.ProviderModelID == "" || request.Model.ExecutionProfileID == "" || request.Operation == "" || len(request.Inputs) == 0 {
		return Plan{}, ErrInvalidPlan
	}
	now := s.options.Now().UTC()
	target, _, errResolve := s.resolver.Resolve(ctx, resolve.Request{ProviderInstanceID: request.Model.ProviderInstanceID, ProviderModelID: request.Model.ProviderModelID, Operation: request.Operation, ExecutionProfileID: request.Model.ExecutionProfileID, RequiredCapabilities: capabilityFeatureStrings(request.RequiredFeatures), Now: now})
	if errResolve != nil {
		return Plan{}, errResolve
	}
	identifier, errID := s.options.NewID()
	if errID != nil || !validPlanID(identifier) {
		return Plan{}, fmt.Errorf("create input plan identifier: %w", errID)
	}
	plan := Plan{ID: identifier, OwnerAPIKeyID: request.OwnerAPIKeyID, Accepted: true, Operation: request.Operation, Model: request.Model, Target: target, CapabilityRevision: target.CapabilityRevision, CatalogRevision: target.CatalogRevision, CreatedAt: now, ExpiresAt: now.Add(s.options.TTL), Revision: 1}
	seenInputs := make(map[string]struct{}, len(request.Inputs))
	// aggregateKey isolates limits owned by distinct semantic-role capabilities of the same media kind.
	// aggregateKey 隔离同一媒体类型下由不同语义角色能力拥有的限制。
	type aggregateKey struct {
		kind vcp.MediaKind
		role vcp.MediaInputRole
	}
	totalBytes := make(map[aggregateKey]int64)
	itemCounts := make(map[aggregateKey]int64)
	for _, input := range request.Inputs {
		if strings.TrimSpace(input.InputID) == "" {
			return Plan{}, ErrInvalidPlan
		}
		if _, exists := seenInputs[input.InputID]; exists {
			return Plan{}, fmt.Errorf("%w: duplicate input identifier", ErrInvalidPlan)
		}
		seenInputs[input.InputID] = struct{}{}
		planned, capability, errInput := s.planInput(ctx, request, target, input)
		if errInput != nil {
			plan.Accepted = false
			plan.ErrorCode = stableInputError(errInput)
			plan.Inputs = nil
			break
		}
		key := aggregateKey{kind: planned.Kind, role: planned.Role}
		totalBytes[key] += planned.SizeBytes
		itemCounts[key]++
		if exceedsKnown(capability.Common.MaxTotalBytes, totalBytes[key]) || exceedsKnown(capability.Common.MaxItems, itemCounts[key]) {
			plan.Accepted = false
			plan.ErrorCode = "media_aggregate_limit_exceeded"
			plan.Inputs = nil
			break
		}
		plan.Inputs = append(plan.Inputs, planned)
		if requiresProviderPreparation(planned.Materialization) {
			plan.RequiresProviderPreparation = true
		}
		if planned.Materialization == catalog.MaterializationProviderAssetID || planned.Materialization == catalog.MaterializationProviderObjectURI {
			plan.AsynchronousPreparation = true
		}
	}
	if plan.Accepted {
		if errRelationship := validateImageInputRelationships(target.ModelCapabilities.MediaInputs, plan.Inputs); errRelationship != nil {
			plan.Accepted = false
			plan.ErrorCode = "image_mask_contract_mismatch"
			plan.Inputs = nil
		}
	}
	if errSave := s.store.Save(ctx, plan); errSave != nil {
		return Plan{}, errSave
	}
	return clonePlan(plan), nil
}

// CreateInputPlan exposes Create under an unambiguous cross-boundary method name.
// CreateInputPlan 以无歧义跨边界方法名暴露 Create。
func (s *Service) CreateInputPlan(ctx context.Context, request Request) (Plan, error) {
	return s.Create(ctx, request)
}

// Get returns one live owner-scoped plan.
// Get 返回一个有效所有者作用域方案。
func (s *Service) Get(ctx context.Context, ownerAPIKeyID string, planID string) (Plan, error) {
	plan, errGet := s.store.Get(ctx, planID)
	if errGet != nil {
		return Plan{}, errGet
	}
	if ownerAPIKeyID == "" || plan.OwnerAPIKeyID != ownerAPIKeyID || !plan.ExpiresAt.After(s.options.Now().UTC()) {
		return Plan{}, ErrPlanNotFound
	}
	return plan, nil
}

// Revalidate resolves the target again and verifies catalog, capability, provider, and resource hashes.
// Revalidate 重新解析 Target 并校验目录、能力、供应商及资源 Hash。
func (s *Service) Revalidate(ctx context.Context, ownerAPIKeyID string, planID string) (Plan, error) {
	plan, errGet := s.Get(ctx, ownerAPIKeyID, planID)
	if errGet != nil {
		return Plan{}, errGet
	}
	if !plan.Accepted {
		return Plan{}, ErrInputRejected
	}
	target, _, errResolve := s.resolver.Resolve(ctx, resolve.Request{ProviderInstanceID: plan.Target.ProviderInstanceID, ProviderModelID: plan.Target.ProviderModelID, Operation: plan.Operation, ExecutionProfileID: plan.Target.ExecutionProfileID, Now: s.options.Now().UTC()})
	if errResolve != nil || !sameFrozenTarget(plan.Target, target) || target.CatalogRevision != plan.CatalogRevision || target.CapabilityRevision != plan.CapabilityRevision {
		return Plan{}, ErrCapabilityChanged
	}
	for _, input := range plan.Inputs {
		if input.ResourceID == "" {
			continue
		}
		value, errResource := s.resources.Get(ctx, ownerAPIKeyID, input.ResourceID)
		if errResource != nil || value.SHA256 != input.SHA256 || value.Kind != input.Kind || value.MIMEType != input.MIMEType || value.SizeBytes != input.SizeBytes || !samePlannedImageMetadata(input, value.Metadata) || !sameGenerationProvenance(input.GeneratedBy, value.GeneratedBy) {
			return Plan{}, ErrCapabilityChanged
		}
	}
	return plan, nil
}

// planInput validates one resource or pending descriptor against one exact media capability.
// planInput 根据一个精确媒体能力校验一个资源或待创建描述符。
func (s *Service) planInput(ctx context.Context, request Request, target resolve.Target, input Input) (PlannedInput, catalog.MediaInputCapability, error) {
	if (input.ResourceID == "") == (input.Pending == nil) {
		return PlannedInput{}, catalog.MediaInputCapability{}, ErrInvalidPlan
	}
	planned := PlannedInput{InputID: input.InputID, ResourceID: input.ResourceID, Role: input.Role}
	var sourceURLAvailable bool
	var workflow catalog.ClientResourceWorkflow
	var metadata routerresource.Metadata
	var generatedBy *routerresource.GenerationProvenance
	if input.ResourceID != "" {
		value, errGet := s.resources.Get(ctx, request.OwnerAPIKeyID, input.ResourceID)
		if errGet != nil {
			return PlannedInput{}, catalog.MediaInputCapability{}, errGet
		}
		planned.Kind, planned.MIMEType, planned.SizeBytes, planned.SHA256 = value.Kind, value.MIMEType, value.SizeBytes, value.SHA256
		planned.ClientStep = ClientStepReferenceExisting
		metadata = value.Metadata
		generatedBy = value.GeneratedBy
		sourceURLAvailable = value.Source == routerresource.SourceURLImport && value.SourceURL != ""
	} else {
		if input.Pending.SizeBytes <= 0 || strings.TrimSpace(input.Pending.MIMEType) == "" {
			return PlannedInput{}, catalog.MediaInputCapability{}, ErrInvalidPlan
		}
		planned.Kind, planned.MIMEType, planned.SizeBytes = input.Pending.Kind, input.Pending.MIMEType, input.Pending.SizeBytes
		workflow = input.Pending.Workflow
		planned.ClientStep = clientStepForWorkflow(workflow)
		metadata = input.Pending.Metadata
	}
	capability, exists := targetMediaCapability(target, planned.Kind, input.Role)
	if !exists || !containsRole(capability.Roles, input.Role) || (input.Pending != nil && !containsWorkflow(capability.ClientWorkflows, workflow)) {
		return PlannedInput{}, catalog.MediaInputCapability{}, ErrInputRejected
	}
	if errGenerated := validateGeneratedSourceRequirement(capability.GeneratedSource, generatedBy, target); errGenerated != nil {
		return PlannedInput{}, catalog.MediaInputCapability{}, errGenerated
	}
	planned.GeneratedBy = generatedBy
	if errLimits := validateMediaFacts(capability, planned, metadata); errLimits != nil {
		return PlannedInput{}, catalog.MediaInputCapability{}, errLimits
	}
	materialization, errMaterialization := selectMaterialization(capability, planned, sourceURLAvailable, request.AllowProjection)
	if errMaterialization != nil {
		return PlannedInput{}, catalog.MediaInputCapability{}, errMaterialization
	}
	planned.Materialization = materialization
	if planned.Kind == vcp.MediaImage && metadata.Image != nil {
		planned.ImageWidth = metadata.Image.Width
		planned.ImageHeight = metadata.Image.Height
		planned.ImageHasAlpha = metadata.Image.HasAlpha
	}
	return planned, capability, nil
}

// validateGeneratedSourceRequirement verifies a prior generation against the catalog's closed origin set.
// validateGeneratedSourceRequirement 根据目录的封闭来源集合校验先前生成。
func validateGeneratedSourceRequirement(requirement *catalog.GeneratedSourceRequirement, provenance *routerresource.GenerationProvenance, target resolve.Target) error {
	if requirement == nil {
		return nil
	}
	if provenance == nil || (requirement.SameProviderDefinition && provenance.ProviderDefinitionID != target.ProviderDefinitionID) || !containsOperation(requirement.AllowedOperations, provenance.Operation) || !containsString(requirement.AllowedUpstreamModels, provenance.UpstreamModelID) {
		return ErrInputRejected
	}
	return nil
}

// sameGenerationProvenance verifies the immutable safe origin snapshot did not change.
// sameGenerationProvenance 校验不可变安全来源快照未发生变化。
func sameGenerationProvenance(expected *routerresource.GenerationProvenance, actual *routerresource.GenerationProvenance) bool {
	if expected == nil || actual == nil {
		return expected == nil && actual == nil
	}
	return *expected == *actual
}

// targetMediaCapability finds one exact callable media contract.
// targetMediaCapability 查找一个精确可调用媒体契约。
func targetMediaCapability(target resolve.Target, kind vcp.MediaKind, role vcp.MediaInputRole) (catalog.MediaInputCapability, bool) {
	for _, capability := range target.ModelCapabilities.MediaInputs {
		if capability.Kind == kind && containsRole(capability.Roles, role) && capability.Level != catalog.CapabilityUnsupported && capability.Level != catalog.CapabilityUnknown {
			return capability, true
		}
	}
	return catalog.MediaInputCapability{}, false
}

// validateImageInputRelationships enforces capability-declared alpha and cross-role requirements before dispatch.
// validateImageInputRelationships 在分派前强制执行能力声明的 Alpha 与跨角色要求。
func validateImageInputRelationships(capabilities []catalog.MediaInputCapability, inputs []PlannedInput) error {
	for index := range inputs {
		input := &inputs[index]
		if input.Kind != vcp.MediaImage {
			continue
		}
		capability, exists := mediaCapabilityForInput(capabilities, input.Kind, input.Role)
		if !exists || capability.Image == nil {
			return ErrInputRejected
		}
		if capability.Image.RequiresAlpha && !input.ImageHasAlpha {
			return ErrInputRejected
		}
		matchingRole := capability.Image.MustMatchFormatAndDimensionsOfRole
		if matchingRole == "" {
			continue
		}
		var matching *PlannedInput
		for relatedIndex := range inputs {
			if inputs[relatedIndex].Kind == input.Kind && inputs[relatedIndex].Role == matchingRole {
				matching = &inputs[relatedIndex]
				break
			}
		}
		if matching == nil || !strings.EqualFold(input.MIMEType, matching.MIMEType) || input.ImageWidth <= 0 || input.ImageHeight <= 0 || input.ImageWidth != matching.ImageWidth || input.ImageHeight != matching.ImageHeight {
			return ErrInputRejected
		}
	}
	return nil
}

// mediaCapabilityForInput returns the exact media capability that owns one semantic role.
// mediaCapabilityForInput 返回拥有一个语义角色的精确媒体能力。
func mediaCapabilityForInput(capabilities []catalog.MediaInputCapability, kind vcp.MediaKind, role vcp.MediaInputRole) (catalog.MediaInputCapability, bool) {
	for _, capability := range capabilities {
		if capability.Kind == kind && containsRole(capability.Roles, role) {
			return capability, true
		}
	}
	return catalog.MediaInputCapability{}, false
}

// samePlannedImageMetadata verifies resource measurements still match a frozen plan.
// samePlannedImageMetadata 验证资源测量值仍与冻结方案一致。
func samePlannedImageMetadata(planned PlannedInput, metadata routerresource.Metadata) bool {
	if planned.Kind != vcp.MediaImage {
		return true
	}
	return metadata.Image != nil && metadata.Image.Width == planned.ImageWidth && metadata.Image.Height == planned.ImageHeight && metadata.Image.HasAlpha == planned.ImageHasAlpha
}

// randomPlanID returns a 128-bit opaque plan identifier.
// randomPlanID 返回一个 128 位不透明方案标识。
func randomPlanID() (string, error) {
	bytes := make([]byte, 16)
	if _, errRead := rand.Read(bytes); errRead != nil {
		return "", errRead
	}
	return "ipl_" + hex.EncodeToString(bytes), nil
}

// capabilityFeatureStrings projects closed feature values for target resolution.
// capabilityFeatureStrings 为 Target 解析投影封闭特性值。
func capabilityFeatureStrings(features []vcp.CapabilityFeature) []string {
	values := make([]string, len(features))
	for index, feature := range features {
		values[index] = string(feature)
	}
	return values
}

// stableInputError maps internal rejection reasons to one content-safe code.
// stableInputError 将内部拒绝原因映射为内容安全码。
func stableInputError(errValue error) string {
	if errors.Is(errValue, ErrInputRejected) {
		return "media_capability_rejected"
	}
	if errors.Is(errValue, routerresource.ErrResourceNotFound) || errors.Is(errValue, routerresource.ErrResourceAccessDenied) {
		return "resource_unavailable"
	}
	return "invalid_input"
}

// clientStepForWorkflow maps one acquisition contract to one exact client action.
// clientStepForWorkflow 将一个获取契约映射为一项精确客户端动作。
func clientStepForWorkflow(workflow catalog.ClientResourceWorkflow) ClientStepKind {
	switch workflow {
	case catalog.ClientWorkflowUploadThenReference:
		return ClientStepUploadMultipart
	case catalog.ClientWorkflowImportURLThenReference:
		return ClientStepImportURL
	case catalog.ClientWorkflowImportBase64ThenReference:
		return ClientStepImportBase64
	default:
		return ""
	}
}

// selectMaterialization selects the first declared feasible mode without probing provider endpoints.
// selectMaterialization 在不探测供应商端点的情况下选择首个已声明可行模式。
func selectMaterialization(capability catalog.MediaInputCapability, input PlannedInput, sourceURLAvailable bool, allowProjection bool) (catalog.UpstreamMaterializationMode, error) {
	for _, mode := range capability.MaterializationModes {
		switch mode {
		case catalog.MaterializationInlineBase64:
			if !exceedsKnown(capability.Common.MaxItemBytes, input.SizeBytes) {
				return mode, nil
			}
		case catalog.MaterializationDirectRemoteURL:
			if sourceURLAvailable && capability.Common.AllowsRemoteURL.Known && capability.Common.AllowsRemoteURL.Value {
				return mode, nil
			}
		case catalog.MaterializationProviderFileID, catalog.MaterializationProviderAssetID, catalog.MaterializationProviderObjectURI:
			return mode, nil
		case catalog.MaterializationFrameSequence, catalog.MaterializationAudioTrack:
			if allowProjection && capability.Level == catalog.CapabilityEmulated {
				return mode, nil
			}
		}
	}
	return "", ErrInputRejected
}

// validateMediaFacts checks exact MIME, bytes, and parsed kind-specific ceilings.
// validateMediaFacts 校验精确 MIME、字节及已解析类型专用上限。
func validateMediaFacts(capability catalog.MediaInputCapability, input PlannedInput, metadata routerresource.Metadata) error {
	if len(capability.Common.MIMETypes) > 0 && !containsString(capability.Common.MIMETypes, input.MIMEType) {
		return ErrInputRejected
	}
	if exceedsKnown(capability.Common.MaxItemBytes, input.SizeBytes) {
		return ErrInputRejected
	}
	if input.Kind == vcp.MediaImage && metadata.Image != nil && capability.Image != nil && (exceedsKnown(capability.Image.MaxWidth, int64(metadata.Image.Width)) || exceedsKnown(capability.Image.MaxHeight, int64(metadata.Image.Height)) || exceedsKnown(capability.Image.MaxPixels, int64(metadata.Image.Width)*int64(metadata.Image.Height))) {
		return ErrInputRejected
	}
	if input.Kind == vcp.MediaAudio && metadata.Audio != nil && capability.Audio != nil && metadata.Audio.DurationMilliseconds.Known && exceedsKnown(capability.Audio.MaxDurationMilliseconds, metadata.Audio.DurationMilliseconds.Value) {
		return ErrInputRejected
	}
	if input.Kind == vcp.MediaVideo && metadata.Video != nil && capability.Video != nil && metadata.Video.DurationMilliseconds.Known && exceedsKnown(capability.Video.MaxDurationMilliseconds, metadata.Video.DurationMilliseconds.Value) {
		return ErrInputRejected
	}
	return nil
}

// exceedsKnown reports an authoritative ceiling violation.
// exceedsKnown 报告权威上限违规。
func exceedsKnown(limit catalog.OptionalLimit, value int64) bool {
	return limit.Known && value > limit.Value
}

// requiresProviderPreparation identifies materializations that create provider-owned handles.
// requiresProviderPreparation 标识会创建供应商拥有句柄的物化方式。
func requiresProviderPreparation(mode catalog.UpstreamMaterializationMode) bool {
	return mode == catalog.MaterializationProviderFileID || mode == catalog.MaterializationProviderAssetID || mode == catalog.MaterializationProviderObjectURI
}

// containsRole reports exact role membership.
// containsRole 报告精确角色成员关系。
func containsRole(values []vcp.MediaInputRole, expected vcp.MediaInputRole) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

// containsWorkflow reports exact workflow membership.
// containsWorkflow 报告精确工作流成员关系。
func containsWorkflow(values []catalog.ClientResourceWorkflow, expected catalog.ClientResourceWorkflow) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

// containsString reports exact string membership.
// containsString 报告精确字符串成员关系。
func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

// containsOperation reports exact operation membership.
// containsOperation 报告精确操作成员关系。
func containsOperation(values []vcp.OperationKind, expected vcp.OperationKind) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

// sameFrozenTarget compares every identity that constrains provider asset ownership and execution.
// sameFrozenTarget 比较约束供应商资产归属与执行的每项身份。
func sameFrozenTarget(first resolve.Target, second resolve.Target) bool {
	return first.ProviderDefinitionID == second.ProviderDefinitionID && first.ProviderInstanceID == second.ProviderInstanceID && first.EndpointID == second.EndpointID && first.EndpointRegion == second.EndpointRegion && first.CredentialID == second.CredentialID && first.ProviderModelID == second.ProviderModelID && first.OfferingID == second.OfferingID && first.ActionBindingID == second.ActionBindingID && first.ExecutionProfileID == second.ExecutionProfileID && first.UpstreamModelID == second.UpstreamModelID
}
