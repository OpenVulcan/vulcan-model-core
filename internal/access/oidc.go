package access

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// maximumOIDCTokenBytes bounds attacker-controlled bearer parsing before signature verification.
	// maximumOIDCTokenBytes 在签名校验前限制攻击者控制的 Bearer 解析大小。
	maximumOIDCTokenBytes = 64 << 10
	// maximumOIDCMetadataBytes bounds discovery and key-set documents.
	// maximumOIDCMetadataBytes 限制发现文档和密钥集文档大小。
	maximumOIDCMetadataBytes = 1 << 20
	// maximumOIDCSigningKeys bounds CPU and memory consumed by one remotely supplied key set.
	// maximumOIDCSigningKeys 限制一个远程密钥集消耗的 CPU 与内存。
	maximumOIDCSigningKeys = 64
	// minimumOIDCRefreshInterval prevents attacker-selected key identifiers from causing metadata request storms.
	// minimumOIDCRefreshInterval 防止攻击者选择的密钥标识引发元数据请求风暴。
	minimumOIDCRefreshInterval = time.Minute
)

// OIDCVerifierConfig configures one issuer-owned RS256 identity boundary.
// OIDCVerifierConfig 配置一个由颁发者拥有的 RS256 身份边界。
type OIDCVerifierConfig struct {
	// Issuer is the exact expected iss claim and discovery origin.
	// Issuer 是预期的精确 iss 声明与发现源站。
	Issuer string
	// Audience is the exact required aud member.
	// Audience 是 aud 中必须存在的精确成员。
	Audience string
	// JWKSURL optionally bypasses discovery with one explicitly configured key-set URL.
	// JWKSURL 可选地使用显式配置的密钥集 URL 跳过发现。
	JWKSURL string
	// HTTPClient performs bounded metadata reads and should enforce deployment proxy policy.
	// HTTPClient 执行受限元数据读取，并应实施部署代理策略。
	HTTPClient *http.Client
	// CacheTTL bounds reuse of one successfully validated key set.
	// CacheTTL 限制一次成功校验密钥集的复用时间。
	CacheTTL time.Duration
	// ClockSkew permits a small deployment clock difference for time claims.
	// ClockSkew 允许时间声明存在少量部署时钟差异。
	ClockSkew time.Duration
	// Now supplies deterministic UTC time for tests.
	// Now 为测试提供确定性 UTC 时间。
	Now func() time.Time
}

// OIDCVerifier validates one configured issuer and never returns raw claims or token material.
// OIDCVerifier 校验一个已配置颁发者，且绝不返回原始声明或 Token 材料。
type OIDCVerifier struct {
	// issuer is the normalized exact claim value.
	// issuer 是规范化后的精确声明值。
	issuer string
	// audience is the required audience member.
	// audience 是必需的受众成员。
	audience string
	// configuredJWKSURL is an optional operator-owned key-set location.
	// configuredJWKSURL 是可选的操作员拥有密钥集地址。
	configuredJWKSURL string
	// client performs bounded remote reads.
	// client 执行受限远程读取。
	client *http.Client
	// cacheTTL bounds validated key reuse.
	// cacheTTL 限制已校验密钥复用。
	cacheTTL time.Duration
	// clockSkew is the accepted claim clock difference.
	// clockSkew 是接受的声明时钟差异。
	clockSkew time.Duration
	// now provides the current UTC time.
	// now 提供当前 UTC 时间。
	now func() time.Time
	// mu serializes discovery, key rotation, and cache publication.
	// mu 串行化发现、密钥轮换与缓存发布。
	mu sync.Mutex
	// discoveredJWKSURL is the issuer-validated discovery result.
	// discoveredJWKSURL 是经过颁发者校验的发现结果。
	discoveredJWKSURL string
	// keys contains currently trusted signing keys by kid.
	// keys 按 kid 保存当前可信签名密钥。
	keys map[string]*rsa.PublicKey
	// keysExpireAt is the local refresh boundary.
	// keysExpireAt 是本地刷新边界。
	keysExpireAt time.Time
	// lastRefreshAttempt rate-limits successful and failed remote refreshes equally.
	// lastRefreshAttempt 对成功与失败的远程刷新采用相同限流。
	lastRefreshAttempt time.Time
}

// oidcJWTHeader contains only fields required to select and constrain a signing key.
// oidcJWTHeader 仅包含选择并约束签名密钥所需字段。
type oidcJWTHeader struct {
	// Algorithm must be RS256.
	// Algorithm 必须是 RS256。
	Algorithm string `json:"alg"`
	// KeyID selects one key in the issuer JWKS.
	// KeyID 选择颁发者 JWKS 中的一个密钥。
	KeyID string `json:"kid"`
	// Type may be JWT when supplied.
	// Type 在提供时可以是 JWT。
	Type string `json:"typ,omitempty"`
}

// oidcAudience accepts the two audience representations defined by JWT.
// oidcAudience 接受 JWT 定义的两种受众表示。
type oidcAudience []string

// UnmarshalJSON decodes one string or an ordered string array without accepting another JSON shape.
// UnmarshalJSON 解码一个字符串或有序字符串数组，且不接受其他 JSON 形态。
func (a *oidcAudience) UnmarshalJSON(data []byte) error {
	var single string
	if errSingle := json.Unmarshal(data, &single); errSingle == nil {
		*a = oidcAudience{single}
		return nil
	}
	var multiple []string
	if errMultiple := json.Unmarshal(data, &multiple); errMultiple != nil || len(multiple) == 0 {
		return errors.New("OIDC audience must be a string or non-empty string array")
	}
	*a = oidcAudience(multiple)
	return nil
}

// oidcClaims contains only the closed identity mapping accepted by the Router.
// oidcClaims 仅包含 Router 接受的封闭身份映射。
type oidcClaims struct {
	// Issuer must exactly match the configured issuer.
	// Issuer 必须与配置的颁发者精确匹配。
	Issuer string `json:"iss"`
	// Subject is the stable external identity.
	// Subject 是稳定外部身份。
	Subject string `json:"sub"`
	// Audience must contain the configured Router audience.
	// Audience 必须包含配置的 Router 受众。
	Audience oidcAudience `json:"aud"`
	// ExpiresAt is the mandatory JWT expiry in Unix seconds.
	// ExpiresAt 是必填 JWT Unix 秒到期时间。
	ExpiresAt float64 `json:"exp"`
	// NotBefore is the optional earliest acceptance time.
	// NotBefore 是可选最早接受时间。
	NotBefore float64 `json:"nbf,omitempty"`
	// IssuedAt is the optional issuance time.
	// IssuedAt 是可选签发时间。
	IssuedAt float64 `json:"iat,omitempty"`
	// OrganizationID is the optional administrative owner claim.
	// OrganizationID 是可选管理所有者声明。
	OrganizationID string `json:"organization_id,omitempty"`
	// TenantID is the mandatory isolation claim.
	// TenantID 是必填隔离声明。
	TenantID string `json:"tenant_id"`
	// ProjectID is the mandatory workload claim.
	// ProjectID 是必填工作负载声明。
	ProjectID string `json:"project_id"`
	// Roles contains only Router role identifiers.
	// Roles 仅包含 Router 角色标识。
	Roles []string `json:"roles"`
}

// oidcDiscovery contains the security-critical subset of an OpenID Provider Configuration response.
// oidcDiscovery 包含 OpenID Provider Configuration 响应中安全关键的子集。
type oidcDiscovery struct {
	// Issuer must exactly match the configured issuer.
	// Issuer 必须与配置的颁发者精确匹配。
	Issuer string `json:"issuer"`
	// JWKSURI is the advertised signing-key document.
	// JWKSURI 是公布的签名密钥文档。
	JWKSURI string `json:"jwks_uri"`
}

// oidcJWKS contains one issuer signing-key set.
// oidcJWKS 包含一个颁发者签名密钥集。
type oidcJWKS struct {
	// Keys contains independently validated RSA keys.
	// Keys 包含独立校验的 RSA 密钥。
	Keys []oidcJWK `json:"keys"`
}

// oidcJWK contains the exact RSA key fields needed by RS256.
// oidcJWK 包含 RS256 所需的精确 RSA 密钥字段。
type oidcJWK struct {
	// KeyType must be RSA.
	// KeyType 必须是 RSA。
	KeyType string `json:"kty"`
	// KeyID is the unique non-empty lookup identifier.
	// KeyID 是唯一非空查找标识。
	KeyID string `json:"kid"`
	// Use, when present, must be sig.
	// Use 在存在时必须是 sig。
	Use string `json:"use,omitempty"`
	// Algorithm, when present, must be RS256.
	// Algorithm 在存在时必须是 RS256。
	Algorithm string `json:"alg,omitempty"`
	// Modulus is the base64url RSA modulus.
	// Modulus 是 Base64URL RSA 模数。
	Modulus string `json:"n"`
	// Exponent is the base64url RSA exponent.
	// Exponent 是 Base64URL RSA 指数。
	Exponent string `json:"e"`
}

// NewOIDCVerifier creates one strict issuer and audience verifier with bounded key rotation.
// NewOIDCVerifier 创建一个具有受限密钥轮换的严格颁发者与受众校验器。
func NewOIDCVerifier(config OIDCVerifierConfig) (*OIDCVerifier, error) {
	issuer, errIssuer := validateOIDCURL(config.Issuer)
	if errIssuer != nil {
		return nil, fmt.Errorf("invalid OIDC issuer: %w", errIssuer)
	}
	if strings.TrimSpace(config.Audience) == "" {
		return nil, errors.New("OIDC audience is required")
	}
	configuredJWKSURL := ""
	if strings.TrimSpace(config.JWKSURL) != "" {
		jwksURL, errJWKSURL := validateOIDCURL(config.JWKSURL)
		if errJWKSURL != nil {
			return nil, fmt.Errorf("invalid OIDC JWKS URL: %w", errJWKSURL)
		}
		configuredJWKSURL = jwksURL
	}
	cacheTTL := config.CacheTTL
	if cacheTTL == 0 {
		cacheTTL = 15 * time.Minute
	}
	clockSkew := config.ClockSkew
	if clockSkew == 0 {
		clockSkew = time.Minute
	}
	if cacheTTL < time.Minute || cacheTTL > 24*time.Hour || clockSkew < 0 || clockSkew > 5*time.Minute {
		return nil, errors.New("OIDC cache TTL or clock skew is outside the allowed boundary")
	}
	client := &http.Client{}
	if config.HTTPClient != nil {
		*client = *config.HTTPClient
	}
	if client.Timeout == 0 {
		client.Timeout = 10 * time.Second
	}
	// CheckRedirect is owned by the verifier and cannot be weakened by an injected client.
	// CheckRedirect 由校验器拥有，且不能被注入客户端削弱。
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	now := config.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &OIDCVerifier{issuer: issuer, audience: strings.TrimSpace(config.Audience), configuredJWKSURL: configuredJWKSURL, client: client, cacheTTL: cacheTTL, clockSkew: clockSkew, now: now, keys: make(map[string]*rsa.PublicKey)}, nil
}

// Verify validates signature and claims before constructing one closed Router principal.
// Verify 在构造一个封闭 Router 主体前校验签名与声明。
func (v *OIDCVerifier) Verify(ctx context.Context, token string) (Principal, error) {
	if ctx == nil || ctx.Err() != nil || len(token) == 0 || len(token) > maximumOIDCTokenBytes {
		return Principal{}, ErrAccessDenied
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return Principal{}, ErrAccessDenied
	}
	headerBytes, errHeaderBytes := base64.RawURLEncoding.DecodeString(parts[0])
	if errHeaderBytes != nil {
		return Principal{}, ErrAccessDenied
	}
	var header oidcJWTHeader
	if errHeader := json.Unmarshal(headerBytes, &header); errHeader != nil || header.Algorithm != "RS256" || strings.TrimSpace(header.KeyID) == "" || header.Type != "" && !strings.EqualFold(header.Type, "JWT") {
		return Principal{}, ErrAccessDenied
	}
	signature, errSignature := base64.RawURLEncoding.DecodeString(parts[2])
	if errSignature != nil {
		return Principal{}, ErrAccessDenied
	}
	signed := []byte(parts[0] + "." + parts[1])
	digest := sha256.Sum256(signed)
	key, errKey := v.signingKey(ctx, header.KeyID, false)
	if errKey != nil || rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) != nil {
		key, errKey = v.signingKey(ctx, header.KeyID, true)
		if errKey != nil || rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) != nil {
			return Principal{}, ErrAccessDenied
		}
	}
	claimsBytes, errClaimsBytes := base64.RawURLEncoding.DecodeString(parts[1])
	if errClaimsBytes != nil {
		return Principal{}, ErrAccessDenied
	}
	var claims oidcClaims
	if errClaims := json.Unmarshal(claimsBytes, &claims); errClaims != nil || !v.validClaims(claims) {
		return Principal{}, ErrAccessDenied
	}
	roles := make([]Role, len(claims.Roles))
	for index, role := range claims.Roles {
		roles[index] = Role(role)
	}
	principal := Principal{SubjectID: strings.TrimSpace(claims.Subject), OrganizationID: strings.TrimSpace(claims.OrganizationID), TenantID: strings.TrimSpace(claims.TenantID), ProjectID: strings.TrimSpace(claims.ProjectID), Roles: roles}
	if errPrincipal := principal.Validate(); errPrincipal != nil {
		return Principal{}, ErrAccessDenied
	}
	return principal, nil
}

// validClaims checks exact issuer, audience, time, and non-empty identity fields.
// validClaims 校验精确颁发者、受众、时间与非空身份字段。
func (v *OIDCVerifier) validClaims(claims oidcClaims) bool {
	if claims.Issuer != v.issuer || strings.TrimSpace(claims.Subject) == "" || strings.TrimSpace(claims.TenantID) == "" || strings.TrimSpace(claims.ProjectID) == "" || len(claims.Roles) == 0 || claims.ExpiresAt <= 0 {
		return false
	}
	audienceFound := false
	for _, audience := range claims.Audience {
		if audience == v.audience {
			audienceFound = true
			break
		}
	}
	if !audienceFound {
		return false
	}
	nowSeconds := float64(v.now().UTC().UnixNano()) / float64(time.Second)
	skewSeconds := v.clockSkew.Seconds()
	return claims.ExpiresAt > nowSeconds-skewSeconds && (claims.NotBefore == 0 || claims.NotBefore <= nowSeconds+skewSeconds) && (claims.IssuedAt == 0 || claims.IssuedAt <= nowSeconds+skewSeconds)
}

// signingKey returns one cached key and performs at most one serialized refresh for a request.
// signingKey 返回一个缓存密钥，并为一次请求最多执行一次串行刷新。
func (v *OIDCVerifier) signingKey(ctx context.Context, keyID string, forceRefresh bool) (*rsa.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	now := v.now().UTC()
	key := v.keys[keyID]
	if !forceRefresh && now.Before(v.keysExpireAt) && key != nil {
		return key, nil
	}
	if !v.lastRefreshAttempt.IsZero() && now.Sub(v.lastRefreshAttempt) < minimumOIDCRefreshInterval {
		if key != nil {
			return key, nil
		}
		return nil, errors.New("OIDC signing key refresh is cooling down")
	}
	v.lastRefreshAttempt = now
	if errRefresh := v.refreshKeysLocked(ctx, now); errRefresh != nil {
		return nil, errRefresh
	}
	key = v.keys[keyID]
	if key == nil {
		return nil, errors.New("OIDC signing key is unavailable")
	}
	return key, nil
}

// refreshKeysLocked discovers and atomically replaces one validated RSA key set while mu is held.
// refreshKeysLocked 在持有 mu 时发现并原子替换一个已校验 RSA 密钥集。
func (v *OIDCVerifier) refreshKeysLocked(ctx context.Context, now time.Time) error {
	jwksURL := v.configuredJWKSURL
	if jwksURL == "" {
		if v.discoveredJWKSURL == "" {
			discoveryURL := strings.TrimSuffix(v.issuer, "/") + "/.well-known/openid-configuration"
			var discovery oidcDiscovery
			if errRead := v.readJSON(ctx, discoveryURL, &discovery); errRead != nil {
				return errRead
			}
			if discovery.Issuer != v.issuer {
				return errors.New("OIDC discovery issuer mismatch")
			}
			validatedJWKSURL, errJWKSURL := validateOIDCURL(discovery.JWKSURI)
			if errJWKSURL != nil {
				return fmt.Errorf("invalid discovered OIDC JWKS URL: %w", errJWKSURL)
			}
			if !sameOIDCOrigin(v.issuer, validatedJWKSURL) {
				return errors.New("discovered OIDC JWKS URL must share the issuer origin")
			}
			v.discoveredJWKSURL = validatedJWKSURL
		}
		jwksURL = v.discoveredJWKSURL
	}
	var document oidcJWKS
	if errRead := v.readJSON(ctx, jwksURL, &document); errRead != nil {
		return errRead
	}
	if len(document.Keys) == 0 || len(document.Keys) > maximumOIDCSigningKeys {
		return errors.New("OIDC JWKS key count is outside the allowed boundary")
	}
	keys := make(map[string]*rsa.PublicKey)
	for _, candidate := range document.Keys {
		key, errCandidate := candidate.publicKey()
		if errCandidate != nil {
			return errCandidate
		}
		if _, duplicate := keys[candidate.KeyID]; duplicate {
			return errors.New("OIDC JWKS contains a duplicate key identifier")
		}
		keys[candidate.KeyID] = key
	}
	v.keys = keys
	v.keysExpireAt = now.Add(v.cacheTTL)
	return nil
}

// readJSON performs one successful bounded JSON metadata request without following redirects.
// readJSON 执行一次成功且受限的 JSON 元数据请求，并且不跟随重定向。
func (v *OIDCVerifier) readJSON(ctx context.Context, target string, destination any) error {
	request, errRequest := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if errRequest != nil {
		return errors.New("create OIDC metadata request")
	}
	request.Header.Set("Accept", "application/json")
	response, errDo := v.client.Do(request)
	if errDo != nil {
		return errors.New("read OIDC metadata")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("OIDC metadata endpoint returned a non-success status")
	}
	limited := io.LimitReader(response.Body, maximumOIDCMetadataBytes+1)
	encoded, errRead := io.ReadAll(limited)
	if errRead != nil || len(encoded) > maximumOIDCMetadataBytes {
		return errors.New("OIDC metadata exceeds the allowed boundary")
	}
	if errDecode := json.Unmarshal(encoded, destination); errDecode != nil {
		return errors.New("OIDC metadata is invalid JSON")
	}
	return nil
}

// publicKey validates and decodes one RSA signing JWK.
// publicKey 校验并解码一个 RSA 签名 JWK。
func (k oidcJWK) publicKey() (*rsa.PublicKey, error) {
	if k.KeyType != "RSA" || strings.TrimSpace(k.KeyID) == "" || k.Use != "" && k.Use != "sig" || k.Algorithm != "" && k.Algorithm != "RS256" {
		return nil, errors.New("OIDC JWKS contains an unsupported key")
	}
	modulusBytes, errModulus := base64.RawURLEncoding.DecodeString(k.Modulus)
	exponentBytes, errExponent := base64.RawURLEncoding.DecodeString(k.Exponent)
	if errModulus != nil || errExponent != nil || len(modulusBytes) < 256 || len(exponentBytes) == 0 || len(exponentBytes) > 4 {
		return nil, errors.New("OIDC JWKS contains invalid RSA material")
	}
	exponent := 0
	for _, value := range exponentBytes {
		exponent = exponent<<8 | int(value)
	}
	if exponent < 3 || exponent%2 == 0 {
		return nil, errors.New("OIDC JWKS contains an invalid RSA exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(modulusBytes), E: exponent}, nil
}

// validateOIDCURL accepts HTTPS or explicit loopback HTTP without query, fragment, or user information.
// validateOIDCURL 接受 HTTPS 或显式环回 HTTP，且不允许查询、片段或用户信息。
func validateOIDCURL(rawURL string) (string, error) {
	parsed, errParse := url.Parse(strings.TrimSpace(rawURL))
	if errParse != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("absolute metadata URL without credentials, query, or fragment is required")
	}
	if parsed.Scheme != "https" {
		host := parsed.Hostname()
		address := net.ParseIP(host)
		if parsed.Scheme != "http" || host != "localhost" && (address == nil || !address.IsLoopback()) {
			return "", errors.New("metadata URL must use HTTPS outside loopback")
		}
	}
	// The issuer claim is an exact identifier. Preserve a configured trailing slash instead of silently rewriting it.
	// 颁发者声明是精确标识符；保留配置中的尾随斜杠，不进行静默改写。
	return parsed.String(), nil
}

// sameOIDCOrigin compares normalized scheme and authority for discovery-owned metadata.
// sameOIDCOrigin 比较发现所拥有元数据的规范化协议与 Authority。
func sameOIDCOrigin(first string, second string) bool {
	firstURL, errFirst := url.Parse(first)
	secondURL, errSecond := url.Parse(second)
	return errFirst == nil && errSecond == nil && strings.EqualFold(firstURL.Scheme, secondURL.Scheme) && strings.EqualFold(firstURL.Host, secondURL.Host)
}
