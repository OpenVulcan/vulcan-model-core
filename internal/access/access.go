// Package access defines tenant identity, authorization, isolation, audit, and request accounting boundaries.
// access 包定义租户身份、授权、隔离、审计和请求计量边界。
package access

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

var (
	// ErrAccessDenied reports an authenticated identity without the required permission.
	// ErrAccessDenied 表示已认证身份缺少所需权限。
	ErrAccessDenied = errors.New("access denied")
	// ErrRateLimited reports an exhausted tenant request or concurrency allowance.
	// ErrRateLimited 表示租户请求或并发额度已经耗尽。
	ErrRateLimited = errors.New("tenant rate limit exceeded")
)

// Role identifies one closed Router authorization role.
// Role 标识一种封闭 Router 授权角色。
type Role string

const (
	// RoleAdministrator grants management-plane operations.
	// RoleAdministrator 授予管理面操作权限。
	RoleAdministrator Role = "administrator"
	// RoleCaller grants VCP call-plane operations.
	// RoleCaller 授予 VCP 调用面操作权限。
	RoleCaller Role = "caller"
)

// Permission identifies one route-domain permission.
// Permission 标识一种路由域权限。
type Permission string

const (
	// PermissionManage controls management-plane access.
	// PermissionManage 控制管理面访问。
	PermissionManage Permission = "manage"
	// PermissionInvoke controls VCP call-plane access.
	// PermissionInvoke 控制 VCP 调用面访问。
	PermissionInvoke Permission = "invoke"
)

// AuditOutcome identifies one closed authentication or authorization result.
// AuditOutcome 标识一种封闭的认证或授权结果。
type AuditOutcome string

const (
	// AuditOutcomeAuthorized records an admitted authenticated request.
	// AuditOutcomeAuthorized 记录一个已接收的认证请求。
	AuditOutcomeAuthorized AuditOutcome = "authorized"
	// AuditOutcomeUnauthenticated records rejection before an identity was established.
	// AuditOutcomeUnauthenticated 记录建立身份前的拒绝。
	AuditOutcomeUnauthenticated AuditOutcome = "unauthenticated"
	// AuditOutcomeForbidden records a validated identity without permission.
	// AuditOutcomeForbidden 记录经过验证但没有权限的身份。
	AuditOutcomeForbidden AuditOutcome = "forbidden"
	// AuditOutcomeRateLimited records an authorized identity rejected by traffic policy.
	// AuditOutcomeRateLimited 记录被流量策略拒绝的已授权身份。
	AuditOutcomeRateLimited AuditOutcome = "rate_limited"
)

// Principal is one authenticated organization, tenant, project, and subject identity.
// Principal 是一个已认证组织、租户、项目和主体身份。
type Principal struct {
	// SubjectID is the stable non-secret human or machine identity.
	// SubjectID 是稳定的非秘密人员或机器身份。
	SubjectID string `json:"subject_id"`
	// OrganizationID is the optional top-level administrative owner.
	// OrganizationID 是可选顶层管理所有者。
	OrganizationID string `json:"organization_id,omitempty"`
	// TenantID is the mandatory isolation and accounting boundary.
	// TenantID 是必填隔离与计量边界。
	TenantID string `json:"tenant_id"`
	// ProjectID is the mandatory workload and budget boundary.
	// ProjectID 是必填工作负载与预算边界。
	ProjectID string `json:"project_id"`
	// Roles contains explicit closed permissions assigned by the identity source.
	// Roles 包含身份源分配的明确封闭权限。
	Roles []Role `json:"roles"`
}

// Validate verifies complete stable identity and at least one recognized role.
// Validate 校验完整稳定身份以及至少一个已识别角色。
func (p Principal) Validate() error {
	if strings.TrimSpace(p.SubjectID) == "" || strings.TrimSpace(p.TenantID) == "" || strings.TrimSpace(p.ProjectID) == "" || len(p.Roles) == 0 {
		return ErrAccessDenied
	}
	for _, role := range p.Roles {
		if role != RoleAdministrator && role != RoleCaller {
			return ErrAccessDenied
		}
	}
	return nil
}

// IdentityVerifier verifies an external OIDC token into one validated Router principal.
// IdentityVerifier 将外部 OIDC Token 校验为一个已验证 Router 主体。
type IdentityVerifier interface {
	// Verify validates issuer, audience, signature, expiry, and required claims without returning raw claims.
	// Verify 校验颁发者、受众、签名、有效期和必需声明且不返回原始声明。
	Verify(context.Context, string) (Principal, error)
}

// Controller enforces authorization, per-project traffic, safe audit, and metric accounting.
// Controller 强制执行授权、逐项目流量、安全审计和指标计量。
type Controller interface {
	// Authorize verifies one explicit permission.
	// Authorize 校验一项明确权限。
	Authorize(context.Context, Principal, Permission) error
	// Acquire reserves one request and concurrency slot and returns an idempotent release function.
	// Acquire 保留一个请求与并发槽并返回幂等释放函数。
	Acquire(context.Context, Principal) (func(), error)
	// Record appends one redacted audit event.
	// Record 追加一条脱敏审计事件。
	Record(AuditEvent)
	// Observe records one non-sensitive request metric.
	// Observe 记录一项非敏感请求指标。
	Observe(Observation)
}

// Limits configures a local project-scoped fixed-window and concurrency guard.
// Limits 配置本地项目作用域固定窗口与并发保护器。
type Limits struct {
	// RequestsPerMinute bounds admitted requests per project.
	// RequestsPerMinute 限制每个项目每分钟接收请求数。
	RequestsPerMinute int
	// ConcurrentRequests bounds active requests per project.
	// ConcurrentRequests 限制每个项目活动请求数。
	ConcurrentRequests int
	// AuditEntries bounds retained redacted local audit events.
	// AuditEntries 限制保留的本地脱敏审计事件数。
	AuditEntries int
}

// AuditEvent contains only safe request metadata and authorization outcome.
// AuditEvent 仅包含安全请求元数据与授权结果。
type AuditEvent struct {
	// Time is the completed request time.
	// Time 是请求完成时间。
	Time time.Time `json:"time"`
	// Principal is the validated non-secret identity and is absent before authentication succeeds.
	// Principal 是经过校验的非秘密身份，在认证成功前不存在。
	Principal *Principal `json:"principal,omitempty"`
	// Outcome is the closed authentication or authorization result.
	// Outcome 是封闭的认证或授权结果。
	Outcome AuditOutcome `json:"outcome"`
	// Permission is the checked route-domain permission.
	// Permission 是已检查的路由域权限。
	Permission Permission `json:"permission"`
	// Method is the HTTP method without body or query data.
	// Method 是不含正文或查询数据的 HTTP 方法。
	Method string `json:"method"`
	// Path is the URL path without query data.
	// Path 是不含查询数据的 URL 路径。
	Path string `json:"path"`
	// StatusCode is the final HTTP status.
	// StatusCode 是最终 HTTP 状态码。
	StatusCode int `json:"status_code"`
}

// Observation contains one safe aggregate metric input.
// Observation 包含一项安全聚合指标输入。
type Observation struct {
	// ProjectID is the metric isolation key.
	// ProjectID 是指标隔离键。
	ProjectID string
	// Permission is the request domain.
	// Permission 是请求域。
	Permission Permission
	// StatusCode is the final HTTP status.
	// StatusCode 是最终 HTTP 状态码。
	StatusCode int
	// Duration is the wall-clock handler duration.
	// Duration 是处理器墙钟耗时。
	Duration time.Duration
}

// Snapshot is a redacted local observability snapshot.
// Snapshot 是一份脱敏本地可观测快照。
type Snapshot struct {
	// Requests is the total observed request count.
	// Requests 是观测到的请求总数。
	Requests uint64 `json:"requests"`
	// Failures is the total response count at or above HTTP 400.
	// Failures 是 HTTP 400 及以上响应总数。
	Failures uint64 `json:"failures"`
	// TotalDuration is the aggregate request duration.
	// TotalDuration 是聚合请求耗时。
	TotalDuration time.Duration `json:"total_duration_nanoseconds"`
}

// localProjectState owns one fixed-window and concurrency counter.
// localProjectState 管理一个固定窗口与并发计数器。
type localProjectState struct {
	// windowStart is the beginning of the current fixed request window.
	// windowStart 是当前固定请求窗口的开始时间。
	windowStart time.Time
	// requests counts admissions within the current window.
	// requests 统计当前窗口内的接收次数。
	requests int
	// active counts currently reserved concurrency slots.
	// active 统计当前保留的并发槽位。
	active int
}

// LocalController is the single-process default and an interface-compatible shared-service reference.
// LocalController 是单进程默认实现，也是接口兼容共享服务的参考实现。
type LocalController struct {
	// mu serializes project counters, audit retention, and aggregate metrics.
	// mu 串行化项目计数器、审计保留与聚合指标。
	mu sync.Mutex
	// limits contains validated local guard ceilings.
	// limits 包含经过校验的本地保护上限。
	limits Limits
	// now supplies the current time for deterministic windows.
	// now 为确定性窗口提供当前时间。
	now func() time.Time
	// projects contains per-project fixed-window and concurrency state.
	// projects 包含逐项目固定窗口与并发状态。
	projects map[string]localProjectState
	// audit retains bounded redacted management events.
	// audit 保留受限且已脱敏的管理事件。
	audit []AuditEvent
	// metrics aggregates content-free request observations.
	// metrics 聚合不含内容的请求观测。
	metrics Snapshot
}

// NewLocalController creates one bounded in-process access controller.
// NewLocalController 创建一个受限进程内访问控制器。
func NewLocalController(limits Limits) (*LocalController, error) {
	if limits.RequestsPerMinute <= 0 || limits.ConcurrentRequests <= 0 || limits.AuditEntries <= 0 {
		return nil, errors.New("positive access limits are required")
	}
	return &LocalController{limits: limits, now: func() time.Time { return time.Now().UTC() }, projects: make(map[string]localProjectState)}, nil
}

// Authorize permits only explicit administrator-management and caller-invocation pairs.
// Authorize 仅允许明确的管理员管理与调用者调用组合。
func (c *LocalController) Authorize(ctx context.Context, principal Principal, permission Permission) error {
	if ctx == nil || ctx.Err() != nil || principal.Validate() != nil {
		return ErrAccessDenied
	}
	required := RoleCaller
	if permission == PermissionManage {
		required = RoleAdministrator
	} else if permission != PermissionInvoke {
		return ErrAccessDenied
	}
	for _, role := range principal.Roles {
		if role == required {
			return nil
		}
	}
	return ErrAccessDenied
}

// Acquire applies one atomic project-scoped request and concurrency decision.
// Acquire 应用一次原子项目作用域请求与并发决策。
func (c *LocalController) Acquire(ctx context.Context, principal Principal) (func(), error) {
	if ctx == nil || ctx.Err() != nil || principal.Validate() != nil {
		return nil, ErrAccessDenied
	}
	now := c.now().UTC()
	c.mu.Lock()
	state := c.projects[principal.ProjectID]
	if state.windowStart.IsZero() || !now.Before(state.windowStart.Add(time.Minute)) {
		state.windowStart = now
		state.requests = 0
	}
	if state.requests >= c.limits.RequestsPerMinute || state.active >= c.limits.ConcurrentRequests {
		c.mu.Unlock()
		return nil, ErrRateLimited
	}
	state.requests++
	state.active++
	c.projects[principal.ProjectID] = state
	c.mu.Unlock()
	var releaseOnce sync.Once
	return func() {
		releaseOnce.Do(func() {
			c.mu.Lock()
			current := c.projects[principal.ProjectID]
			if current.active > 0 {
				current.active--
			}
			c.projects[principal.ProjectID] = current
			c.mu.Unlock()
		})
	}, nil
}

// Record retains one bounded redacted audit event.
// Record 保留一条受限脱敏审计事件。
func (c *LocalController) Record(event AuditEvent) {
	if event.Outcome != AuditOutcomeAuthorized && event.Outcome != AuditOutcomeUnauthenticated && event.Outcome != AuditOutcomeForbidden && event.Outcome != AuditOutcomeRateLimited {
		return
	}
	if event.Principal != nil {
		principal := *event.Principal
		principal.Roles = append([]Role(nil), event.Principal.Roles...)
		event.Principal = &principal
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.audit = append(c.audit, event)
	if len(c.audit) > c.limits.AuditEntries {
		c.audit = append([]AuditEvent(nil), c.audit[len(c.audit)-c.limits.AuditEntries:]...)
	}
}

// Observe aggregates request count, failures, and duration without labels containing user data.
// Observe 聚合请求数、失败数与耗时且标签不包含用户数据。
func (c *LocalController) Observe(observation Observation) {
	c.mu.Lock()
	c.metrics.Requests++
	if observation.StatusCode >= 400 {
		c.metrics.Failures++
	}
	c.metrics.TotalDuration += observation.Duration
	c.mu.Unlock()
}

// Audit returns an isolated bounded audit snapshot for tests or a protected management adapter.
// Audit 为测试或受保护管理适配器返回隔离的受限审计快照。
func (c *LocalController) Audit() []AuditEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	audit := append([]AuditEvent(nil), c.audit...)
	for index := range audit {
		if audit[index].Principal != nil {
			principal := *audit[index].Principal
			principal.Roles = append([]Role(nil), audit[index].Principal.Roles...)
			audit[index].Principal = &principal
		}
	}
	return audit
}

// Metrics returns the current non-sensitive aggregate snapshot.
// Metrics 返回当前非敏感聚合快照。
func (c *LocalController) Metrics() Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.metrics
}
